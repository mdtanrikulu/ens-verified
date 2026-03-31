import { useEffect, useState, useCallback, useRef } from "react";
import {
  type Address,
  type Hex,
  type PublicClient,
  type Chain,
  type Transport,
} from "viem";
import {
  getIssuerInfo,
  resolveRecord,
  parseRecordValue,
  verifyRecord,
  recoverRecordSigner,
  getNodeOwner,
  fetchProofBundle,
  buildRecordKey,
  type IssuerInfo,
  type VerificationResult,
  type ProofBundle,
  type ParsedRecordValue,
} from "@ensverify/sdk";
import { runSetup, type DemoConfig, type IssuerConfig } from "./setup";

// ── Types ────────────────────────────────────────────────────────────────────

interface RecordState {
  issuerConfig: IssuerConfig;
  recordKey: string | null;
  rawRecordValue: string | null;
  parsed: ParsedRecordValue | null;
  issuer: IssuerInfo | null;
  verification: VerificationResult | null;
  signer: Address | null;
  bundle: ProofBundle | null;
}

interface DemoState {
  owner: Address | null;
  records: RecordState[];
}

type AppPhase =
  | { phase: "input" }
  | { phase: "setup"; steps: string[] }
  | { phase: "loading"; config: DemoConfig }
  | { phase: "ready"; config: DemoConfig; data: DemoState }
  | { phase: "error"; message: string };

// ── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const [phase, setPhase] = useState<AppPhase>({ phase: "input" });
  const clientRef = useRef<any>(null);

  async function handleStart() {
    setPhase({ phase: "setup", steps: [] });

    try {
      const { config, client } = await runSetup((_step, _total, msg) => {
        setPhase((prev) => ({
          phase: "setup",
          steps: [...(prev.phase === "setup" ? prev.steps : []), msg],
        }));
      });

      clientRef.current = client;
      setPhase({ phase: "loading", config });

      const data = await loadDashboardData(client as any, config);
      setPhase({ phase: "ready", config, data });
    } catch (err: any) {
      const message =
        err instanceof Error
          ? err.message
          : typeof err === "object" && err !== null
            ? JSON.stringify(err, null, 2)
            : String(err);
      setPhase({ phase: "error", message });
    }
  }

  if (phase.phase === "input") {
    return (
      <div className="container">
        <h1>ENS Verifiable Records | Demo</h1>
        <div className="section">
          <h2>Setup</h2>
          <p
            style={{
              marginBottom: "1rem",
              color: "var(--text-muted)",
              fontSize: "0.85rem",
            }}
          >
            This demo runs a full Ethereum EVM in your browser (via Tevm),
            deploys all contracts, registers an ENS name, generates a Groth16
            age proof, and issues both ECDSA and ZK verifiable records. Fully
            client-side, no RPC.
          </p>
          <button
            onClick={handleStart}
            style={{
              padding: "0.5rem 1.5rem",
              background: "var(--accent)",
              border: "none",
              borderRadius: "6px",
              color: "white",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Start Demo
          </button>
        </div>
      </div>
    );
  }

  if (phase.phase === "setup" || phase.phase === "loading") {
    const steps = phase.phase === "setup" ? phase.steps : [];
    return (
      <div className="container">
        <h1>ENS Verifiable Records | Demo</h1>
        <div className="section">
          <h2>Setting up...</h2>
          <div style={{ fontFamily: "var(--mono-font)", fontSize: "0.8rem" }}>
            {steps.map((step, i) => (
              <div
                key={i}
                style={{
                  padding: "0.25rem 0",
                  color:
                    i === steps.length - 1 ? "var(--accent)" : "var(--pass)",
                }}
              >
                {i < steps.length - 1 ? "\u2713" : "\u25CB"} {step}
              </div>
            ))}
            {phase.phase === "loading" && (
              <div style={{ padding: "0.25rem 0", color: "var(--accent)" }}>
                ○ Loading dashboard data...
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (phase.phase === "error") {
    return (
      <div className="container">
        <h1>ENS Verifiable Records | Demo</h1>
        <div className="section error">
          <h2>Error</h2>
          <pre>{phase.message}</pre>
          <button
            onClick={() => setPhase({ phase: "input" })}
            style={{
              marginTop: "1rem",
              padding: "0.4rem 1rem",
              background: "var(--border)",
              border: "none",
              borderRadius: "6px",
              color: "var(--text)",
              cursor: "pointer",
            }}
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  // phase === "ready"
  const { config, data } = phase;

  return (
    <div className="container">
      <h1>ENS Verifiable Records | Demo</h1>

      {/* ENS Name Info */}
      <div className="section">
        <h2>ENS Name Info</h2>
        <table>
          <tbody>
            <Row label="Name" value={config.ensName} />
            <Row label="Node" value={config.node} mono />
            <Row label="Owner" value={data.owner} mono />
            <Row label="Resolver" value={config.resolverAddress} mono />
          </tbody>
        </table>
      </div>

      {/* Records Grid */}
      <div className="records-grid">
        {data.records.map((rec) => (
          <RecordCard key={rec.issuerConfig.address} rec={rec} />
        ))}
      </div>
    </div>
  );
}

// ── Dashboard Data Loader ────────────────────────────────────────────────────

async function loadDashboardData(
  client: PublicClient<Transport, Chain>,
  config: DemoConfig,
): Promise<DemoState> {
  const node = config.node as Hex;
  const resolverAddr = config.resolverAddress as Address;
  const registryAddr = config.registryAddress as Address;
  const ensRegistryAddr = config.ensRegistryAddress as Address;
  const controllerAddr = config.controllerAddress as Address;

  const owner = await getNodeOwner(client, ensRegistryAddr, node);

  const records = await Promise.all(
    config.issuers.map(async (issuerCfg): Promise<RecordState> => {
      const issuerAddr = issuerCfg.address as Address;

      const [issuerInfo, rawValue] = await Promise.all([
        getIssuerInfo(client, registryAddr, issuerAddr),
        resolveRecord(
          client,
          resolverAddr,
          node,
          issuerAddr,
          issuerCfg.recordType,
        ),
      ]);

      const recordKey = buildRecordKey(issuerAddr, issuerCfg.recordType);
      const parsed = rawValue ? parseRecordValue(rawValue) : null;

      const [verification, bundle] = await Promise.all([
        verifyRecord(client, {
          resolverAddress: resolverAddr,
          registryAddress: registryAddr,
          ensRegistryAddress: ensRegistryAddr,
          controllerAddress: controllerAddr,
          chainId: config.chainId,
          node,
          issuer: issuerAddr,
          recordType: issuerCfg.recordType,
        }),
        issuerInfo?.specificationURI
          ? fetchProofBundle(issuerInfo.specificationURI)
          : Promise.resolve(null),
      ]);

      let signer: Address | null = null;
      if (bundle) {
        signer = await recoverRecordSigner(
          bundle.request,
          bundle.userSignature,
          controllerAddr,
          config.chainId,
        );
      }

      return {
        issuerConfig: issuerCfg,
        recordKey,
        rawRecordValue: rawValue,
        parsed,
        issuer: issuerInfo,
        verification,
        signer,
        bundle,
      };
    }),
  );

  return { owner, records };
}

// ── Record Card ──────────────────────────────────────────────────────────────

function RecordCard({ rec }: { rec: RecordState }) {
  const proofType = rec.issuerConfig.type;
  const [showModal, setShowModal] = useState(false);

  return (
    <div className="record-card">
      <div className="card-header">
        <span className={`badge badge-${proofType}`}>
          {proofType.toUpperCase()}
        </span>
        <span className="card-title">{rec.issuerConfig.label}</span>
        <button
          className={`how-it-works-link link-${proofType}`}
          onClick={() => setShowModal(true)}
        >
          How it works
        </button>
      </div>
      {showModal && (
        <HowItWorksModal
          proofType={proofType}
          onClose={() => setShowModal(false)}
        />
      )}

      {/* Issuer Info */}
      <div className="card-section">
        <h3>Issuer Info</h3>
        {rec.issuer ? (
          <table>
            <tbody>
              <Row label="Name" value={rec.issuer.name} />
              <Row label="Address" value={rec.issuerConfig.address} mono />
              <Row label="Active" value={rec.issuer.active ? "Yes" : "No"} />
              <Row label="Verifier" value={rec.issuer.verifierContract} mono />
              <Row label="Spec URI" value={rec.issuer.specificationURI} />
            </tbody>
          </table>
        ) : (
          <p>Issuer not found</p>
        )}
      </div>

      {/* On-Chain Record */}
      <div className="card-section">
        <h3>On-Chain Record</h3>
        <table>
          <tbody>
            <Row label="Record Key" value={rec.recordKey} mono />
            <Row label="Raw Value" value={rec.rawRecordValue} mono />
            <Row label="Content Key" value={rec.parsed?.contentKey} mono />
            <Row
              label="Expires"
              value={
                rec.parsed
                  ? `${rec.parsed.expires} (${new Date(Number(rec.parsed.expires) * 1000).toISOString()})`
                  : null
              }
            />
          </tbody>
        </table>
      </div>

      {/* Verification Result */}
      <div className="card-section">
        <h3>Verification Result</h3>
        {rec.verification ? (
          <>
            <table>
              <tbody>
                <CheckRow
                  label="Issuer Active"
                  pass={rec.verification.issuerActive}
                />
                <CheckRow
                  label="Content Key Match"
                  pass={rec.verification.contentKeyMatch}
                />
                <CheckRow
                  label="Proof Valid"
                  pass={rec.verification.proofValid}
                />
                <CheckRow
                  label="Signer Is Owner"
                  pass={rec.verification.signerIsOwner}
                />
                <CheckRow
                  label="Not Expired"
                  pass={!rec.verification.expired}
                />
              </tbody>
            </table>
            <div
              className={`verdict ${rec.verification.valid ? "pass" : "fail"}`}
            >
              {rec.verification.valid
                ? "VALID — All checks passed"
                : "INVALID — One or more checks failed"}
            </div>
            {rec.signer && (
              <p className="signer-info">
                Recovered signer: <code>{rec.signer}</code>
              </p>
            )}
          </>
        ) : (
          <p>Verification not available</p>
        )}
      </div>

      {/* Proof Bundle */}
      <div className="card-section">
        <h3>Proof Bundle</h3>
        {rec.bundle ? (
          <table>
            <tbody>
              <Row label="Content Key" value={rec.bundle.contentKey} mono />
              <Row
                label="User Signature"
                value={truncate(rec.bundle.userSignature, 42)}
                mono
              />
              <Row label="Proof" value={truncate(rec.bundle.proof, 42)} mono />
              <Row label="ENS Name" value={rec.bundle.request.ensName} />
              <Row label="Record Type" value={rec.bundle.request.recordType} />
              <Row
                label="Data Hash"
                value={rec.bundle.request.recordDataHash}
                mono
              />
              <Row label="Issuer" value={rec.bundle.request.issuer} mono />
            </tbody>
          </table>
        ) : (
          <p>Proof bundle not available</p>
        )}
      </div>
    </div>
  );
}

// ── How It Works Modal ───────────────────────────────────────────────────────

interface FlowStep {
  actor: string;
  action: string;
  detail: string;
  location: "off-chain" | "on-chain";
}

const ECDSA_ISSUANCE: FlowStep[] = [
  {
    actor: "Issuer",
    action: "Compute recordDataHash",
    detail: 'keccak256("github:ensverify") — hash of the claim payload',
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Build RecordRequest",
    detail:
      "Struct with node, ensName, resolver, recordType, recordDataHash, issuer, expires, nonce",
    location: "off-chain",
  },
  {
    actor: "User",
    action: "Sign EIP-712 consent",
    detail:
      "Wallet signs the typed RecordRequest — proves the name owner approves this record",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Submit issueRecord() tx",
    detail:
      "Controller validates signature, derives contentKey = keccak256(sig, name, resolver, data, issuer), writes to resolver",
    location: "on-chain",
  },
  {
    actor: "Issuer",
    action: "Sign proof (ECDSA)",
    detail: "Signs recordDataHash with issuer private key — this is the proof",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Host proof bundle",
    detail:
      "JSON with {request, userSignature, contentKey, proof} at specificationURI",
    location: "off-chain",
  },
];

const ECDSA_VERIFICATION: FlowStep[] = [
  {
    actor: "Verifier",
    action: "Check issuer status",
    detail:
      "IssuerRegistry.getIssuer() — is the issuer registered, active, not expired?",
    location: "on-chain",
  },
  {
    actor: "Verifier",
    action: "Read text record",
    detail:
      'resolver.text(node, "vr:{issuer}:{type}") — get contentKey + expires',
    location: "on-chain",
  },
  {
    actor: "Verifier",
    action: "Check expiration",
    detail: "Is block.timestamp < expires? (0 = no expiration)",
    location: "off-chain",
  },
  {
    actor: "Verifier",
    action: "Fetch proof bundle",
    detail: "HTTP GET from issuer's specificationURI",
    location: "off-chain",
  },
  {
    actor: "Verifier",
    action: "Recompute contentKey",
    detail:
      "keccak256(userSig, name, resolver, dataHash, issuer) — must match on-chain value",
    location: "off-chain",
  },
  {
    actor: "Verifier",
    action: "Verify proof on-chain",
    detail:
      "ECDSAProofVerifier.verifyProof() — recovers signer from ECDSA sig, checks signer == issuer",
    location: "on-chain",
  },
  {
    actor: "Verifier",
    action: "Check name ownership",
    detail:
      "Recover EIP-712 signer from userSignature, compare to ENSRegistry.owner(node)",
    location: "on-chain",
  },
];

const ZK_ISSUANCE: FlowStep[] = [
  {
    actor: "User",
    action: "Provide birthday privately",
    detail:
      "User shares their birthday (unix timestamp) with the issuer over a secure channel — this stays private",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Generate ZK age proof",
    detail:
      "Groth16 circuit proves: age = currentDate - birthday >= 18 years. Outputs: Poseidon(birthday) as commitment, isAdult = 1",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Compute recordDataHash",
    detail:
      "recordDataHash = Poseidon(birthday) — a non-reversible commitment binding the proof to this birthday",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Build RecordRequest",
    detail:
      'Same struct as ECDSA — node, ensName, resolver, recordType="age", recordDataHash, issuer, expires, nonce',
    location: "off-chain",
  },
  {
    actor: "User",
    action: "Sign EIP-712 consent",
    detail:
      "Wallet signs the typed RecordRequest — proves the name owner approves this age record",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Submit issueRecord() tx",
    detail:
      "Controller validates signature, derives contentKey, writes to resolver — identical to ECDSA path",
    location: "on-chain",
  },
  {
    actor: "Issuer",
    action: "Encode Groth16 proof",
    detail:
      "ABI-encode (pA, pB, pC, currentDate) as bytes — the proof field in the bundle",
    location: "off-chain",
  },
  {
    actor: "Issuer",
    action: "Host proof bundle",
    detail:
      "JSON with {request, userSignature, contentKey, proof} at specificationURI",
    location: "off-chain",
  },
];

const ZK_VERIFICATION: FlowStep[] = [
  {
    actor: "Verifier",
    action: "Check issuer status",
    detail:
      "IssuerRegistry.getIssuer() — is the issuer registered, active, not expired?",
    location: "on-chain",
  },
  {
    actor: "Verifier",
    action: "Read text record",
    detail:
      'resolver.text(node, "vr:{issuer}:{type}") — get contentKey + expires',
    location: "on-chain",
  },
  {
    actor: "Verifier",
    action: "Check expiration",
    detail: "Is block.timestamp < expires? (0 = no expiration)",
    location: "off-chain",
  },
  {
    actor: "Verifier",
    action: "Fetch proof bundle",
    detail: "HTTP GET from issuer's specificationURI",
    location: "off-chain",
  },
  {
    actor: "Verifier",
    action: "Recompute contentKey",
    detail:
      "keccak256(userSig, name, resolver, dataHash, issuer) — must match on-chain value",
    location: "off-chain",
  },
  {
    actor: "Verifier",
    action: "Verify ZK proof on-chain",
    detail:
      "ZkAgeVerifier decodes (pA, pB, pC, currentDate), reconstructs pubSignals = [birthdayHash, isAdult=1, currentDate], checks currentDate <= block.timestamp, then runs Groth16 BN254 pairing check",
    location: "on-chain",
  },
  {
    actor: "Verifier",
    action: "Check name ownership",
    detail:
      "Recover EIP-712 signer from userSignature, compare to ENSRegistry.owner(node)",
    location: "on-chain",
  },
];

function HowItWorksModal({
  proofType,
  onClose,
}: {
  proofType: "ecdsa" | "zk";
  onClose: () => void;
}) {
  const handleBackdrop = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === e.currentTarget) onClose();
    },
    [onClose],
  );

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleEsc);
    return () => window.removeEventListener("keydown", handleEsc);
  }, [onClose]);

  const issuance = proofType === "ecdsa" ? ECDSA_ISSUANCE : ZK_ISSUANCE;
  const verification =
    proofType === "ecdsa" ? ECDSA_VERIFICATION : ZK_VERIFICATION;
  const color = proofType === "ecdsa" ? "var(--ecdsa)" : "var(--zk)";
  const title =
    proofType === "ecdsa"
      ? "ECDSA Proof Verification"
      : "ZK Age Verification (Groth16)";

  return (
    <div className="modal-backdrop" onClick={handleBackdrop}>
      <div className="modal">
        <div className="modal-header">
          <span className={`badge badge-${proofType}`}>
            {proofType.toUpperCase()}
          </span>
          <span className="modal-title">{title}</span>
          <button className="modal-close" onClick={onClose}>
            &times;
          </button>
        </div>

        <div className="modal-body">
          <div className="flow-section">
            <h3 className="flow-title" style={{ color }}>
              Issuance Flow
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
              Verification Flow
            </h3>
            <div className="flow-steps">
              {verification.map((step, i) => (
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

// ── Components ───────────────────────────────────────────────────────────────

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
      <td className={pass ? "check-pass" : "check-fail"}>
        {pass ? "PASS" : "FAIL"}
      </td>
    </tr>
  );
}

function truncate(hex: string, len: number): string {
  if (hex.length <= len) return hex;
  return hex.slice(0, len) + "...";
}
