import { useEffect, useState } from "react";
import {
  createPublicClient,
  http,
  type Address,
  type Hex,
  type PublicClient,
  type Chain,
  type Transport,
} from "viem";
import { mainnet } from "viem/chains";
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
import config from "./config.json";

// ── Types ────────────────────────────────────────────────────────────────────

interface DemoState {
  loading: boolean;
  error: string | null;
  owner: Address | null;
  recordKey: string | null;
  rawRecordValue: string | null;
  parsed: ParsedRecordValue | null;
  issuer: IssuerInfo | null;
  verification: VerificationResult | null;
  signer: Address | null;
  bundle: ProofBundle | null;
}

const VERIFICATION_MODES = ["ECDSA Attestation", "ZK Proof", "Hybrid"];

// ── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const [state, setState] = useState<DemoState>({
    loading: true,
    error: null,
    owner: null,
    recordKey: null,
    rawRecordValue: null,
    parsed: null,
    issuer: null,
    verification: null,
    signer: null,
    bundle: null,
  });

  useEffect(() => {
    loadAll().catch((err) =>
      setState((s) => ({ ...s, loading: false, error: String(err) })),
    );
  }, []);

  async function loadAll() {
    const client = createPublicClient({
      chain: mainnet,
      transport: http(config.rpcUrl),
    }) as PublicClient<Transport, Chain>;

    const node = config.node as Hex;
    const issuerAddr = config.issuerAddress as Address;
    const resolverAddr = config.resolverAddress as Address;
    const registryAddr = config.registryAddress as Address;
    const ensRegistryAddr = config.ensRegistryAddress as Address;
    const controllerAddr = config.controllerAddress as Address;

    // Fetch everything in parallel where possible
    const [owner, issuerInfo, rawValue] = await Promise.all([
      getNodeOwner(client, ensRegistryAddr, node),
      getIssuerInfo(client, registryAddr, issuerAddr),
      resolveRecord(client, resolverAddr, node, issuerAddr, config.recordType),
    ]);

    const recordKey = buildRecordKey(issuerAddr, config.recordType);
    let parsed: ParsedRecordValue | null = null;
    if (rawValue) {
      parsed = parseRecordValue(rawValue);
    }

    // Fetch proof bundle and run verification in parallel
    const [verification, bundle] = await Promise.all([
      verifyRecord(client, {
        resolverAddress: resolverAddr,
        registryAddress: registryAddr,
        ensRegistryAddress: ensRegistryAddr,
        controllerAddress: controllerAddr,
        chainId: config.chainId,
        node,
        issuer: issuerAddr,
        recordType: config.recordType,
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

    setState({
      loading: false,
      error: null,
      owner,
      recordKey,
      rawRecordValue: rawValue,
      parsed,
      issuer: issuerInfo,
      verification,
      signer,
      bundle,
    });
  }

  if (state.loading) {
    return (
      <div className="container">
        <h1>ENS Verifiable Records</h1>
        <p className="loading">Loading data from Anvil...</p>
      </div>
    );
  }

  if (state.error) {
    return (
      <div className="container">
        <h1>ENS Verifiable Records</h1>
        <div className="section error">
          <h2>Error</h2>
          <pre>{state.error}</pre>
          <p>
            Make sure Anvil is running and you've run <code>npm run setup</code>{" "}
            first.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <h1>ENS Verifiable Records | Demo</h1>

      {/* 3. Issuer Info */}
      <div className="section">
        <h2>Issuer Info</h2>
        {state.issuer ? (
          <table>
            <tbody>
              <Row label="Name" value={state.issuer.name} />
              <Row label="Address" value={config.issuerAddress} mono />
              <Row label="Active" value={state.issuer.active ? "Yes" : "No"} />
              <Row
                label="Verification Mode"
                value={
                  VERIFICATION_MODES[state.issuer.verificationMode] ??
                  String(state.issuer.verificationMode)
                }
              />
              <Row
                label="Specification URI"
                value={state.issuer.specificationURI}
              />
              <Row
                label="Expires"
                value={`${state.issuer.expires} (${new Date(Number(state.issuer.expires) * 1000).toISOString()})`}
              />
            </tbody>
          </table>
        ) : (
          <p>Issuer not found</p>
        )}
      </div>

      {/* 2. ENS Name Info */}
      <div className="section">
        <h2>ENS Name Info</h2>
        <table>
          <tbody>
            <Row label="Name" value={config.ensName} />
            <Row label="Node" value={config.node} mono />
            <Row label="Owner" value={state.owner} mono />
            <Row label="Resolver" value={config.resolverAddress} mono />
          </tbody>
        </table>
      </div>

      {/* 3. On-Chain Record */}
      <div className="section">
        <h2>On-Chain Record</h2>
        <table>
          <tbody>
            <Row label="Record Key" value={state.recordKey} mono />
            <Row label="Raw Value" value={state.rawRecordValue} mono />
            <Row label="Content Key" value={state.parsed?.contentKey} mono />
            <Row
              label="Expires"
              value={
                state.parsed
                  ? `${state.parsed.expires} (${new Date(Number(state.parsed.expires) * 1000).toISOString()})`
                  : null
              }
            />
          </tbody>
        </table>
      </div>

      {/* 4. Verification Result */}
      <div className="section">
        <h2>Verification Result</h2>
        {state.verification ? (
          <>
            <table>
              <tbody>
                <CheckRow
                  label="Issuer Active"
                  pass={state.verification.issuerActive}
                />
                <CheckRow
                  label="Content Key Match"
                  pass={state.verification.contentKeyMatch}
                />
                <CheckRow
                  label="Attestation Valid"
                  pass={state.verification.attestationValid}
                />
                <CheckRow
                  label="Signer Is Owner"
                  pass={state.verification.signerIsOwner}
                />
                <CheckRow
                  label="Not Expired"
                  pass={!state.verification.expired}
                />
              </tbody>
            </table>
            <div
              className={`verdict ${state.verification.valid ? "pass" : "fail"}`}
            >
              {state.verification.valid
                ? "VALID — All checks passed"
                : "INVALID — One or more checks failed"}
            </div>
            {state.signer && (
              <p className="signer-info">
                Recovered signer: <code>{state.signer}</code>
              </p>
            )}
          </>
        ) : (
          <p>Verification not available</p>
        )}
      </div>

      {/* 5. Proof Bundle */}
      <div className="section">
        <h2>Proof Bundle</h2>
        {state.bundle ? (
          <table>
            <tbody>
              <Row label="Content Key" value={state.bundle.contentKey} mono />
              <Row
                label="User Signature"
                value={truncate(state.bundle.userSignature, 42)}
                mono
              />
              <Row
                label="Attestation"
                value={truncate(state.bundle.attestation, 42)}
                mono
              />
              <Row label="ENS Name" value={state.bundle.request.ensName} />
              <Row
                label="Record Type"
                value={state.bundle.request.recordType}
              />
              <Row
                label="Record Data Hash"
                value={state.bundle.request.recordDataHash}
                mono
              />
              <Row label="Issuer" value={state.bundle.request.issuer} mono />
              <Row
                label="Expires"
                value={String(state.bundle.request.expires)}
              />
              <Row label="Nonce" value={String(state.bundle.request.nonce)} />
            </tbody>
          </table>
        ) : (
          <p>Proof bundle not available</p>
        )}
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
