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

interface IssuerConfig {
  address: string;
  recordType: string;
  type: "ecdsa" | "zk";
  label: string;
}

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
  loading: boolean;
  error: string | null;
  owner: Address | null;
  records: RecordState[];
}

// ── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const [state, setState] = useState<DemoState>({
    loading: true,
    error: null,
    owner: null,
    records: [],
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
    const resolverAddr = config.resolverAddress as Address;
    const registryAddr = config.registryAddress as Address;
    const ensRegistryAddr = config.ensRegistryAddress as Address;
    const controllerAddr = config.controllerAddress as Address;

    const owner = await getNodeOwner(client, ensRegistryAddr, node);

    const issuers = (config as any).issuers as IssuerConfig[];

    const records = await Promise.all(
      issuers.map(async (issuerCfg): Promise<RecordState> => {
        const issuerAddr = issuerCfg.address as Address;

        const [issuerInfo, rawValue] = await Promise.all([
          getIssuerInfo(client, registryAddr, issuerAddr),
          resolveRecord(client, resolverAddr, node, issuerAddr, issuerCfg.recordType),
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

    setState({ loading: false, error: null, owner, records });
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

      {/* ENS Name Info */}
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

      {/* Records Grid */}
      <div className="records-grid">
        {state.records.map((rec) => (
          <RecordCard key={rec.issuerConfig.address} rec={rec} />
        ))}
      </div>
    </div>
  );
}

// ── Record Card ──────────────────────────────────────────────────────────────

function RecordCard({ rec }: { rec: RecordState }) {
  const proofType = rec.issuerConfig.type;

  return (
    <div className="record-card">
      <div className="card-header">
        <span className={`badge badge-${proofType}`}>
          {proofType.toUpperCase()}
        </span>
        <span className="card-title">{rec.issuerConfig.label}</span>
      </div>

      {/* Issuer Info */}
      <div className="card-section">
        <h3>Issuer Info</h3>
        {rec.issuer ? (
          <table>
            <tbody>
              <Row label="Name" value={rec.issuer.name} />
              <Row label="Address" value={rec.issuerConfig.address} mono />
              <Row label="Active" value={rec.issuer.active ? "Yes" : "No"} />
              <Row
                label="Verifier"
                value={rec.issuer.verifierContract}
                mono
              />
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
              <Row
                label="Proof"
                value={truncate(rec.bundle.proof, 42)}
                mono
              />
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
