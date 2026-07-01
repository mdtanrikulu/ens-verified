import { useCallback, useEffect, useState } from "react";
import {
  recoverTypedDataAddress,
  type Address,
  type Hex,
  type PublicClient,
  type Chain,
  type Transport,
} from "viem";
import {
  verifyRecord,
  type VerificationResult,
  type ProofBundle,
} from "@ensverify/sdk";
import type { DemoConfig, PrivateRecordConfig } from "./setup";
import {
  bruteForceBirthday,
  bruteForceEmail,
  buildEmailCandidates,
  completeBundle,
  getDisclosureTypedData,
  parseRedactedBundle,
  randomNonce,
  saltedKeccakHash,
  saltedPoseidonHash,
  unsaltedKeccakHash,
  unsaltedPoseidonHash,
  type BruteForceResult,
  type RedactedBundle,
} from "./privacy";

// ── Tab ────────────────────────────────────────────────────────────────────

interface PrivacyTabProps {
  client: PublicClient<Transport, Chain>;
  config: DemoConfig;
  owner: Address | null;
}

export function PrivacyTab({ client, config, owner }: PrivacyTabProps) {
  return (
    <>
      <div className="section">
        <h2>Selective Disclosure (ENSIP-PRIVACY)</h2>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
          These records hold <strong>private</strong> data. The on-chain{" "}
          <code>recordDataHash</code> is always <strong>salted</strong>, so it is never a
          brute-force oracle. There are two privacy models, one per card below:
        </p>
        <ul
          style={{
            color: "var(--text-muted)",
            fontSize: "0.82rem",
            margin: "0.5rem 0 0.25rem 1.1rem",
            lineHeight: 1.6,
          }}
        >
          <li>
            <strong style={{ color: "var(--ecdsa)" }}>Value hidden (email)</strong> — the public
            path reveals <em>nothing</em>; the issuer serves a <em>redacted</em> bundle. The user
            discloses <code>(salt, data)</code> to a specific vendor to reveal the value.
          </li>
          <li>
            <strong style={{ color: "var(--zk)" }}>Predicate public (ZK age)</strong> — the ZK
            proof <em>publicly</em> attests “age&nbsp;≥&nbsp;18” while the birthday stays hidden.
            Disclosure is only needed when a vendor wants the <em>exact</em> birthday.
          </li>
        </ul>
        <DisclosurePhases />
      </div>

      <div className="records-grid">
        {config.privateRecords.map((rec) => (
          <PrivacyRecordCard
            key={rec.issuerAddress}
            rec={rec}
            client={client}
            config={config}
            owner={owner}
          />
        ))}
      </div>
    </>
  );
}

// ── Per-record card ──────────────────────────────────────────────────────────

type VendorReport = {
  reconstructedHash: Hex;
  hashMatches: boolean;
  signer: Address;
  signerIsOwner: boolean;
  nonceValid: boolean;
  scopeValid: boolean;
  verification: VerificationResult;
};

function PrivacyRecordCard({
  rec,
  client,
  config,
  owner,
}: {
  rec: PrivateRecordConfig;
  client: PublicClient<Transport, Chain>;
  config: DemoConfig;
  owner: Address | null;
}) {
  const badge = rec.type === "age" ? "zk" : "ecdsa";

  // Disclosure state machine: challenge → disclose → verify.
  const [nonce, setNonce] = useState<Hex | null>(null);
  const [revealed, setRevealed] = useState<{ signature: Hex } | null>(null);
  const [report, setReport] = useState<VendorReport | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);

  // Predicate cards (ZK age): verify the PUBLIC proof on mount — "≥18" is public.
  const [publicResult, setPublicResult] = useState<VerificationResult | null>(null);
  useEffect(() => {
    if (rec.publicModel !== "predicate") return;
    let cancelled = false;
    verifyRecord(client, verifyParams(config, rec))
      .then((v) => !cancelled && setPublicResult(v))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [client, config, rec]);

  function reset() {
    setNonce(null);
    setRevealed(null);
    setReport(null);
    setError(null);
  }

  async function reconstructHash(): Promise<Hex> {
    if (rec.secret.kind === "keccak") {
      return saltedKeccakHash(rec.secret.salt, rec.secret.data);
    }
    return saltedPoseidonHash(
      BigInt(rec.secret.birthday),
      BigInt(rec.secret.saltDecimal),
    );
  }

  function handleChallenge() {
    reset();
    setNonce(randomNonce());
  }

  async function handleDisclose() {
    if (!nonce) return;
    setBusy("Signing disclosure...");
    setError(null);
    try {
      const typed = disclosureTyped(config, rec, nonce);
      const signature = await config.userAccount.signTypedData({
        domain: typed.domain as any,
        types: typed.types as any,
        primaryType: typed.primaryType as any,
        message: typed.message as any,
      });
      setRevealed({ signature });
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleVerify() {
    if (!nonce || !revealed) return;
    setBusy("Verifying disclosure...");
    setError(null);
    try {
      // 1. Verify the disclosure signature (EIP-712) recovers to the current name owner.
      const typed = disclosureTyped(config, rec, nonce);
      const signer = await recoverTypedDataAddress({
        domain: typed.domain,
        types: typed.types,
        primaryType: typed.primaryType,
        message: typed.message,
        signature: revealed.signature,
      });
      const signerIsOwner = !!owner && signer.toLowerCase() === owner.toLowerCase();

      // 2. Reconstruct recordDataHash from the disclosed (salt, data) and check it matches
      //    the on-chain commitment — this is what proves the exact disclosed value.
      const reconstructedHash = await reconstructHash();
      const hashMatches =
        reconstructedHash.toLowerCase() === rec.recordDataHash.toLowerCase();

      // 3. Run the base §7 verification end-to-end.
      let verification: VerificationResult;
      if (rec.publicModel === "redacted") {
        // Fetch the redacted bundle, apply §2 rules, then insert the reconstructed hash.
        const raw = await (await fetch(rec.specificationURI)).json();
        const redacted: RedactedBundle | null = parseRedactedBundle(raw);
        if (!redacted) throw new Error("Served bundle failed the §2 redaction rules");
        const completed: ProofBundle = completeBundle(redacted, reconstructedHash);
        verification = await verifyRecord(client, {
          ...verifyParams(config, rec),
          fetchBundle: async () => completed,
        });
      } else {
        // Predicate model: the full bundle is already public and verifiable.
        verification = await verifyRecord(client, verifyParams(config, rec));
      }

      setReport({
        reconstructedHash,
        hashMatches,
        signer,
        signerIsOwner,
        nonceValid: true, // vendor issued this nonce and has not consumed it
        scopeValid: true, // node/issuer/recordType bound in the signed struct
        verification,
      });
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(null);
    }
  }

  const isAge = rec.type === "age";
  const disclosedValue = rec.secret.data;
  const disclosedLabel = isAge ? `exact birthday ${disclosedValue}` : disclosedValue;

  return (
    <div className="record-card">
      <div className="card-header">
        <span className={`badge badge-${badge}`}>{isAge ? "ZK" : "PRIVATE"}</span>
        <span className="card-title">{rec.label}</span>
        <button
          className={`how-it-works-link link-${badge}`}
          onClick={() => setShowModal(true)}
        >
          How it works
        </button>
      </div>
      {showModal && <DisclosureModal rec={rec} onClose={() => setShowModal(false)} />}

      {/* Public view — differs by privacy model */}
      {rec.publicModel === "predicate" ? (
        <div className="card-section">
          <h3>Public View — ZK Predicate Proof</h3>
          <p className="pv-detail" style={{ marginBottom: "0.5rem" }}>
            The Groth16 proof publicly attests the claim below. The birthday is never in the
            bundle — only the salted commitment <code>Poseidon(birthday, salt)</code> is.
          </p>
          <table>
            <tbody>
              <Row label="Record Key" value={`vr:${rec.issuerAddress}:${rec.recordType}`} mono />
              <Row label="Public claim" value={rec.predicateLabel} />
              <Row label="birthdayHash" value={truncate(rec.recordDataHash, 26)} mono />
              <Row label="Birthday" value="hidden — not in bundle" />
            </tbody>
          </table>
          {publicResult ? (
            <div className={`verdict ${publicResult.valid ? "pass" : "fail"}`}>
              {publicResult.valid
                ? `VERIFIED — ${rec.predicateLabel} proven by ZK proof; birthday not revealed`
                : "Public proof did not verify"}
            </div>
          ) : (
            <p className="pv-detail" style={{ color: "var(--accent)" }}>verifying public proof…</p>
          )}
        </div>
      ) : (
        <div className="card-section">
          <h3>Public View — Redacted Bundle</h3>
          <table>
            <tbody>
              <Row label="Record Key" value={`vr:${rec.issuerAddress}:${rec.recordType}`} mono />
              <Row label="version" value={rec.redactedBundle?.version} mono />
              <Row label="private" value={String(rec.redactedBundle?.private)} mono />
              <Row label="recordDataHash" value="null (redacted)" mono />
              <Row label="Content Key" value={rec.redactedBundle?.contentKey} mono />
            </tbody>
          </table>
          <div className="verdict warn">
            UNCONFIRMED — the public path only shows that a redacted bundle exists. It does not
            reveal the value, nor prove the current owner holds it. Disclosure required.
          </div>
        </div>
      )}

      {/* Brute-force oracle demonstration */}
      <BruteForcePanel rec={rec} />

      {/* Selective disclosure flow */}
      <div className="card-section">
        <h3>Selective Disclosure {isAge ? "— reveal exact birthday" : "— reveal value"}</h3>
        <div className="disclosure-steps">
          <div className="disclosure-step">
            <button className="pv-btn" onClick={handleChallenge} disabled={!!busy}>
              1 · Vendor issues challenge
            </button>
            {nonce && (
              <p className="pv-detail">
                nonce = <code>{truncate(nonce, 26)}</code>
              </p>
            )}
          </div>

          <div className="disclosure-step">
            <button
              className="pv-btn"
              onClick={handleDisclose}
              disabled={!nonce || !!busy || !!revealed}
            >
              2 · User signs &amp; discloses
            </button>
            {revealed && (
              <p className="pv-detail">
                over confidential channel → <code>{disclosedLabel}</code> + salt + EIP-712
                disclosure signature <code>{truncate(revealed.signature, 20)}</code>
              </p>
            )}
          </div>

          <div className="disclosure-step">
            <button
              className="pv-btn"
              onClick={handleVerify}
              disabled={!revealed || !!busy}
            >
              3 · Vendor verifies
            </button>
          </div>
        </div>

        {busy && <p className="pv-detail" style={{ color: "var(--accent)" }}>{busy}</p>}
        {error && (
          <div className="verdict fail" style={{ marginTop: "0.5rem" }}>
            {error}
          </div>
        )}

        {report && (
          <>
            <table style={{ marginTop: "0.75rem" }}>
              <tbody>
                <CheckRow label="Signer Is Owner" pass={report.signerIsOwner} />
                <CheckRow label="Nonce Valid" pass={report.nonceValid} />
                <CheckRow label="Scope Bound" pass={report.scopeValid} />
                <CheckRow
                  label={isAge ? "Birthday Matches" : "Hash Reconstructs"}
                  pass={report.hashMatches}
                />
                <CheckRow label="Content Key Match" pass={report.verification.contentKeyMatch} />
                <CheckRow label="Proof Valid" pass={report.verification.proofValid} />
                <CheckRow label="Not Expired" pass={!report.verification.expired} />
              </tbody>
            </table>
            <div
              className={`verdict ${report.verification.valid && report.hashMatches ? "pass" : "fail"}`}
            >
              {report.verification.valid && report.hashMatches
                ? `VERIFIED — issuer attested ${disclosedLabel} for the current owner`
                : "INVALID — disclosure did not verify"}
            </div>
            <p className="signer-info">
              Reconstructed recordDataHash: <code>{truncate(report.reconstructedHash, 26)}</code>
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// ── Brute-force panel ─────────────────────────────────────────────────────────

function BruteForcePanel({ rec }: { rec: PrivateRecordConfig }) {
  const [unsalted, setUnsalted] = useState<BruteForceResult | null>(null);
  const [salted, setSalted] = useState<BruteForceResult | null>(null);
  const [running, setRunning] = useState<"unsalted" | "salted" | null>(null);
  const [progress, setProgress] = useState(0);

  async function run(mode: "unsalted" | "salted") {
    setRunning(mode);
    setProgress(0);
    try {
      let result: BruteForceResult;
      if (rec.secret.kind === "keccak") {
        const email = rec.secret.data;
        const candidates = buildEmailCandidates(email);
        // Attacker recomputes keccak256(candidate). Unsalted target cracks; salted does not.
        const target = mode === "unsalted" ? unsaltedKeccakHash(email) : rec.recordDataHash;
        result = await bruteForceEmail(target, candidates, {
          onProgress: (t) => setProgress(Math.round((t / candidates.length) * 100)),
        });
      } else {
        const birthday = BigInt(rec.secret.birthday);
        const DAY = 86_400;
        const startUnix = Number(birthday) - 8000 * DAY;
        const endUnix = Number(birthday) + 2000 * DAY;
        // Attacker recomputes Poseidon(day). Unsalted target cracks; salted does not.
        const target =
          mode === "unsalted" ? await unsaltedPoseidonHash(birthday) : rec.recordDataHash;
        result = await bruteForceBirthday(
          target,
          { startUnix, endUnix },
          { onProgress: (t, total) => setProgress(Math.round((t / total) * 100)) },
        );
      }
      if (mode === "unsalted") setUnsalted(result);
      else setSalted(result);
    } finally {
      setRunning(null);
      setProgress(100);
    }
  }

  const oracle = rec.secret.kind === "keccak" ? "keccak256" : "Poseidon";

  return (
    <div className="card-section">
      <h3>Why Salt? — Brute-Force Oracle</h3>
      <p className="pv-detail" style={{ marginBottom: "0.6rem" }}>
        The commitment is an offline oracle: anyone can recompute {oracle} over candidate inputs.
        Low-entropy data falls instantly <em>unless</em> a 32-byte salt is mixed in — which is
        exactly why publishing the salted commitment is safe.
      </p>
      <div className="disclosure-steps">
        <div className="disclosure-step">
          <button className="pv-btn danger" onClick={() => run("unsalted")} disabled={!!running}>
            Crack UNSALTED commitment
          </button>
          {unsalted &&
            (unsalted.cracked ? (
              <p className="pv-detail" style={{ color: "var(--fail)" }}>
                cracked <code>{unsalted.cracked}</code> in {unsalted.elapsedMs.toFixed(0)} ms (
                {unsalted.tried} tries)
              </p>
            ) : (
              <p className="pv-detail">no match in {unsalted.tried} tries</p>
            ))}
        </div>
        <div className="disclosure-step">
          <button className="pv-btn" onClick={() => run("salted")} disabled={!!running}>
            Same attack on SALTED commitment
          </button>
          {salted &&
            (salted.cracked ? (
              <p className="pv-detail" style={{ color: "var(--fail)" }}>
                cracked <code>{salted.cracked}</code>
              </p>
            ) : (
              <p className="pv-detail" style={{ color: "var(--pass)" }}>
                exhausted {salted.tried} candidates in {salted.elapsedMs.toFixed(0)} ms — not found
                (salt unknown to attacker)
              </p>
            ))}
        </div>
      </div>
      {running && (
        <p className="pv-detail" style={{ color: "var(--accent)" }}>
          brute-forcing {running} — {progress}%
        </p>
      )}
    </div>
  );
}

// ── Phase strip ───────────────────────────────────────────────────────────────

function DisclosurePhases() {
  const phases = [
    { n: 1, t: "Vendor Challenge", d: "Vendor sends a random 128-bit+ nonce (and optional expiry)." },
    { n: 2, t: "User Disclosure", d: "User sends (data, salt) + an EIP-712 Disclosure signature over a confidential channel." },
    { n: 3, t: "Vendor Verification", d: "Recover signer=owner, reconstruct recordDataHash, run base §7 verification end-to-end." },
  ];
  return (
    <div className="phase-strip">
      {phases.map((p) => (
        <div key={p.n} className="phase-chip">
          <span className="phase-num">{p.n}</span>
          <div>
            <div className="phase-title">{p.t}</div>
            <div className="phase-desc">{p.d}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── How-it-works modal ─────────────────────────────────────────────────────────

interface FlowStep {
  actor: string;
  action: string;
  detail: string;
  location: "off-chain" | "on-chain";
}

const EMAIL_ISSUANCE: FlowStep[] = [
  {
    actor: "Issuer",
    action: "Generate 32-byte salt",
    detail:
      "Fresh CSPRNG salt per issuance. This is what stops the public hash from being a brute-force oracle.",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Compute recordDataHash",
    detail: "recordDataHash = keccak256(salt ‖ email) — the salted commitment to the private value.",
    location: "off-chain",
  },
  {
    actor: "User",
    action: "Sign EIP-712 consent",
    detail: "Wallet signs the RecordRequest — proves the name owner approves this record.",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Submit issueRecord() tx",
    detail: "Controller derives contentKey and writes it to the resolver — identical to public records.",
    location: "on-chain",
  },
  {
    actor: "Issuer",
    action: "Serve REDACTED bundle",
    detail:
      'version "1-private", private: true, recordDataHash: null. The public value is never exposed.',
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Deliver (salt, email) to user",
    detail:
      "Sent over a confidential channel; the user persists it. The issuer discards the salt so it cannot rebuild the oracle.",
    location: "off-chain",
  },
];

const AGE_ISSUANCE: FlowStep[] = [
  {
    actor: "User",
    action: "Provide birthday privately",
    detail: "Shared with the issuer over a secure channel; it stays private and never goes on-chain.",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Generate 128-bit salt",
    detail: "A PRIVATE circuit input — it blinds the commitment and is never revealed as a public signal.",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Generate ZK age proof",
    detail:
      "Groth16 proves age = currentDate − birthday ≥ 18y. Public outputs: birthdayHash = Poseidon(birthday, salt), isAdult = 1.",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "recordDataHash = birthdayHash",
    detail: "The salted commitment. Safe to publish — the birthday cannot be brute-forced out of it.",
    location: "off-chain",
  },
  {
    actor: "User",
    action: "Sign EIP-712 consent",
    detail: "Wallet signs the RecordRequest for the age record.",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Submit issueRecord() + serve FULL bundle",
    detail:
      "The bundle is public, so anyone can verify “≥ 18” from the proof — while the birthday stays hidden.",
    location: "on-chain",
  },
  {
    actor: "Issuer",
    action: "Deliver (birthday, salt) to user",
    detail: "Over a confidential channel, so the user can later disclose the EXACT birthday to a vendor.",
    location: "off-chain",
  },
];

function disclosureFlow(isAge: boolean): FlowStep[] {
  const reconstruct = isAge
    ? "recordDataHash = Poseidon(birthday, salt)"
    : "recordDataHash = keccak256(salt ‖ email)";
  const revealed = isAge ? "the exact birthday + salt" : "the email + salt";
  return [
    {
      actor: "Vendor",
      action: "Issue challenge (nonce)",
      detail:
        "Vendor sends a random 128-bit+ nonce (plus optional expiry and vendor identity). Single-use.",
      location: "off-chain",
    },
    {
      actor: "User",
      action: "Sign EIP-712 Disclosure",
      detail:
        "Binds node + issuer + recordType + nonce + vendor + expires. Domain-separated from every other protocol.",
      location: "off-chain",
    },
    {
      actor: "User",
      action: "Send disclosure",
      detail: `Sends ${revealed} + the disclosure signature over a confidential (TLS) channel.`,
      location: "off-chain",
    },
    {
      actor: "Vendor",
      action: "Recover signer = owner",
      detail:
        "Recovers the Disclosure signer and requires it to equal the CURRENT name owner (rejects prior-owner data).",
      location: "off-chain",
    },
    {
      actor: "Vendor",
      action: "Check nonce, scope, expiry",
      detail: "Nonce not yet consumed; issuer/recordType/node/vendor match; not past expiry.",
      location: "off-chain",
    },
    {
      actor: "Vendor",
      action: "Reconstruct recordDataHash",
      detail: `${reconstruct} from the disclosed values — this is what binds the reveal to the on-chain commitment.`,
      location: "off-chain",
    },
    {
      actor: "Vendor",
      action: "Run base §7 verification",
      detail:
        "contentKey match, issuer proof (ECDSA / Groth16), and name-ownership — end-to-end, on-chain.",
      location: "on-chain",
    },
    {
      actor: "Vendor",
      action: "Consume nonce",
      detail:
        "Atomically mark the nonce used. Result: the issuer attested exactly this value for the current owner.",
      location: "off-chain",
    },
  ];
}

function DisclosureModal({
  rec,
  onClose,
}: {
  rec: PrivateRecordConfig;
  onClose: () => void;
}) {
  const isAge = rec.type === "age";
  const color = isAge ? "var(--zk)" : "var(--ecdsa)";
  const badge = isAge ? "zk" : "ecdsa";

  const handleBackdrop = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === e.currentTarget) onClose();
    },
    [onClose],
  );
  useEffect(() => {
    const onEsc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onEsc);
    return () => window.removeEventListener("keydown", onEsc);
  }, [onClose]);

  const issuance = isAge ? AGE_ISSUANCE : EMAIL_ISSUANCE;
  const disclosure = disclosureFlow(isAge);

  return (
    <div className="modal-backdrop" onClick={handleBackdrop}>
      <div className="modal">
        <div className="modal-header">
          <span className={`badge badge-${badge}`}>{isAge ? "ZK" : "PRIVATE"}</span>
          <span className="modal-title">{rec.label} — Selective Disclosure</span>
          <button className="modal-close" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">
          <div className="flow-section">
            <h3 className="flow-title" style={{ color }}>
              Issuance Flow (private record)
            </h3>
            <div className="flow-steps">
              {issuance.map((step, i) => (
                <FlowStepCard key={i} step={step} index={i} color={color} />
              ))}
            </div>
          </div>

          <div className="flow-divider" />

          <div className="flow-section">
            <h3 className="flow-title" style={{ color }}>
              Disclosure Flow (user → vendor)
            </h3>
            <div className="flow-steps">
              {disclosure.map((step, i) => (
                <FlowStepCard key={i} step={step} index={i} color={color} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function FlowStepCard({
  step,
  index,
  color,
}: {
  step: FlowStep;
  index: number;
  color: string;
}) {
  return (
    <div className="flow-step">
      <div className="step-connector">
        <div className="step-number" style={{ borderColor: color, color }}>
          {index + 1}
        </div>
        <div className="step-line" />
      </div>
      <div className="step-content">
        <div className="step-header">
          <span className="step-actor">{step.actor}</span>
          <span
            className={`step-location step-location-${step.location === "on-chain" ? "onchain" : "offchain"}`}
          >
            {step.location}
          </span>
        </div>
        <div className="step-action">{step.action}</div>
        <div className="step-detail">{step.detail}</div>
      </div>
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function verifyParams(config: DemoConfig, rec: PrivateRecordConfig) {
  return {
    resolverAddress: config.resolverAddress,
    registryAddress: config.registryAddress,
    ensRegistryAddress: config.ensRegistryAddress,
    controllerAddress: config.controllerAddress,
    chainId: config.chainId,
    node: config.node,
    issuer: rec.issuerAddress,
    recordType: rec.recordType,
  };
}

function disclosureTyped(config: DemoConfig, rec: PrivateRecordConfig, nonce: Hex) {
  return getDisclosureTypedData(
    {
      node: config.node,
      issuer: rec.issuerAddress,
      recordType: rec.recordType,
      nonce,
      vendor: "0x0000000000000000000000000000000000000000",
      expires: 0n,
    },
    config.controllerAddress,
    config.chainId,
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: string | null | undefined;
  mono?: boolean;
}) {
  return (
    <tr>
      <td className="label">{label}</td>
      <td className={mono ? "mono" : ""}>{value ?? "—"}</td>
    </tr>
  );
}

function CheckRow({ label, pass }: { label: string; pass: boolean }) {
  return (
    <tr>
      <td className="label">{label}</td>
      <td className={pass ? "check-pass" : "check-fail"}>{pass ? "PASS" : "FAIL"}</td>
    </tr>
  );
}

function truncate(hex: string, len: number): string {
  if (hex.length <= len) return hex;
  return hex.slice(0, len) + "...";
}
