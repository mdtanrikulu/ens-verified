import type { Address, Hex, PublicClient, Transport, Chain } from "viem";
import { recoverTypedDataAddress, decodeAbiParameters } from "viem";
import type {
  RecordRequest,
  ProofBundle,
  ParsedRecordValue,
  IssuerInfo,
  VerificationResult,
} from "./types.js";
import { TextResolverABI, IssuerRegistryABI, ENSRegistryABI, ProofVerifierABI, ProofBundleProviderABI } from "./abi.js";
import {
  computeContentKey,
  parseRecordValue as parseRecordValueUtil,
  buildRecordKey,
  validateProofBundle,
} from "./utils.js";
import { getEIP712TypedData } from "./issuer.js";

/**
 * Checks if a string looks like an Ethereum address (0x-prefixed, 42 chars, valid hex).
 */
function isContractAddress(uri: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(uri);
}

/**
 * Decodes an ABI-encoded proof bundle returned by an IProofBundleProvider contract.
 */
function decodeProofBundle(data: Hex): ProofBundle {
  const [node, ensName, resolver, recordType, recordDataHash, issuer, expires, nonce, userSignature, contentKey, proof] = decodeAbiParameters(
    [
      { name: "node", type: "bytes32" },
      { name: "ensName", type: "string" },
      { name: "resolver", type: "address" },
      { name: "recordType", type: "string" },
      { name: "recordDataHash", type: "bytes32" },
      { name: "issuer", type: "address" },
      { name: "expires", type: "uint64" },
      { name: "nonce", type: "uint256" },
      { name: "userSignature", type: "bytes" },
      { name: "contentKey", type: "bytes32" },
      { name: "proof", type: "bytes" },
    ],
    data
  );

  return {
    request: {
      node,
      ensName,
      resolver,
      recordType,
      recordDataHash,
      issuer,
      expires,
      nonce,
    },
    userSignature: userSignature as Hex,
    contentKey: contentKey as Hex,
    proof: proof as Hex,
  };
}

/**
 * Reads the text record from the resolver using key format `vr:{issuer}:{recordType}`.
 * Returns the raw string value or null if empty/not set.
 */
export async function resolveRecord(
  client: PublicClient<Transport, Chain>,
  resolverAddress: Address,
  node: Hex,
  issuer: Address,
  recordType: string
): Promise<string | null> {
  const key = buildRecordKey(issuer, recordType);

  const value = await client.readContract({
    address: resolverAddress,
    abi: TextResolverABI,
    functionName: "text",
    args: [node, key],
  });

  if (!value || value.length === 0) {
    return null;
  }

  return value;
}

/**
 * Parses a raw text record value "{contentKey} {expires}"
 * into a structured ParsedRecordValue.
 */
export function parseRecordValue(value: string): ParsedRecordValue {
  return parseRecordValueUtil(value);
}

/** IPFS/Arweave HTTPS gateways used to resolve content-addressed proof-bundle URIs. */
const IPFS_GATEWAY = "https://ipfs.io/ipfs/";
const AR_GATEWAY = "https://arweave.net/";
const FETCH_TIMEOUT_MS = 10_000;
const MAX_BUNDLE_BYTES = 1_000_000; // 1 MB hard cap on the bundle body
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;

/**
 * Translates content-addressed URIs to an HTTPS gateway. `ipfs://{cid}/{path}` and
 * `ar://{id}` are the durability schemes the spec recommends/requires for long-lived
 * records but that the global `fetch` cannot resolve directly. Other schemes pass through.
 */
function normalizeFetchUri(uri: string, ipfsGateway: string, arGateway: string): string {
  if (uri.startsWith("ipfs://")) {
    return ipfsGateway + uri.slice("ipfs://".length).replace(/^ipfs\//, "");
  }
  if (uri.startsWith("ar://")) {
    return arGateway + uri.slice("ar://".length);
  }
  return uri;
}

/**
 * Rejects schemes/hosts that are unsafe for a (possibly server-side) verifier. Browser-local
 * `blob:`/`data:` URIs are allowed (no network egress); `http:`/`file:` and `https:` URLs
 * pointing at loopback, link-local, or private hosts are rejected to blunt SSRF. Server-side
 * callers SHOULD still egress-filter, since a permitted host can redirect to an internal one.
 */
function assertSafeFetchUrl(uri: string): void {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    throw new Error(`Invalid proof bundle URI: "${uri}"`);
  }
  const scheme = u.protocol.toLowerCase();
  if (scheme === "blob:" || scheme === "data:") return; // browser-local, no egress
  if (scheme !== "https:") {
    throw new Error(
      `Unsupported proof bundle scheme "${scheme}" — use https://, ipfs://, or ar://`
    );
  }
  const host = u.hostname.toLowerCase();
  const internal =
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "0.0.0.0" ||
    host === "[::1]" ||
    host === "::1" ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^\[?(fc|fd)[0-9a-f]{2}:/.test(host) ||
    /^\[?fe80:/.test(host);
  if (internal) {
    throw new Error(`Refusing to fetch proof bundle from internal host "${host}"`);
  }
}

/** Reads a fetch `Response` body with a hard byte cap, then JSON-parses it. */
async function readBoundedJson(response: Response, maxBytes: number): Promise<any> {
  const reader = response.body?.getReader?.();
  if (!reader) {
    const text = await response.text();
    if (text.length > maxBytes) throw new Error("Proof bundle exceeds size limit");
    return JSON.parse(text);
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("Proof bundle exceeds size limit");
      }
      chunks.push(value);
    }
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.length;
  }
  return JSON.parse(new TextDecoder().decode(merged));
}

/** Parses a non-negative decimal value (string or integer number) to a bounded bigint. */
function asDecimalBigInt(v: unknown, field: string, max: bigint): bigint {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) v = String(v);
  if (typeof v !== "string" || !/^\d+$/.test(v)) {
    throw new Error(`Invalid proof bundle: ${field} must be a non-negative decimal value`);
  }
  const n = BigInt(v);
  if (n > max) throw new Error(`Invalid proof bundle: ${field} out of range`);
  return n;
}

/**
 * Parses + validates a proof bundle from already-fetched JSON. NO network — this is the
 * security-critical part the library owns. Bring your own transport (your own HTTP client,
 * IPFS node, gateway, cache, on-chain provider, …), then hand the parsed JSON here.
 *
 * Per ENSIP Section 8: `version` MUST be "1" with request, userSignature, contentKey, and proof
 * present; `expires`/`nonce` are validated as strict decimal values (rejecting "0x10", "1e3",
 * null, …) rather than silently coerced. Throws on any malformed bundle.
 */
export function parseProofBundle(data: any): ProofBundle {
  if (data?.version !== "1") {
    throw new Error(
      `Invalid proof bundle: unsupported version "${data?.version}" (expected "1")`
    );
  }
  if (!data.request || !data.userSignature || !data.contentKey || !data.proof) {
    throw new Error(
      "Invalid proof bundle: missing required fields (request, userSignature, contentKey, proof)"
    );
  }

  const bundle: ProofBundle = {
    request: {
      node: data.request.node as Hex,
      ensName: data.request.ensName as string,
      resolver: data.request.resolver as Address,
      recordType: data.request.recordType as string,
      recordDataHash: data.request.recordDataHash as Hex,
      issuer: data.request.issuer as Address,
      expires: asDecimalBigInt(data.request.expires, "expires", UINT64_MAX),
      nonce: asDecimalBigInt(data.request.nonce, "nonce", UINT256_MAX),
    },
    userSignature: data.userSignature as Hex,
    contentKey: data.contentKey as Hex,
    proof: data.proof as Hex,
  };

  const structural = validateProofBundle(bundle);
  if (!structural.valid) {
    throw new Error(`Invalid proof bundle: ${structural.errors.join("; ")}`);
  }

  return bundle;
}

/** Options for the built-in {@link fetchProofBundle} convenience transport. */
export interface FetchProofBundleOptions {
  /** Replace the network call entirely (e.g. an authenticated client, or a test stub). Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
  /** HTTPS gateway used to resolve `ipfs://` URIs. Defaults to `https://ipfs.io/ipfs/`. */
  ipfsGateway?: string;
  /** HTTPS gateway used to resolve `ar://` URIs. Defaults to `https://arweave.net/`. */
  arGateway?: string;
}

/**
 * Built-in CONVENIENCE transport: fetch a bundle from `specificationURI` and {@link parseProofBundle} it.
 * Resolves `https://`, `ipfs://`/`ar://` (via configurable gateways), and browser-local `blob:`/`data:`,
 * with a 10s timeout, a 1 MB body cap, and an SSRF scheme/host allowlist.
 *
 * This is entirely optional. If you don't want the SDK touching the network — or want a different
 * gateway, IPFS client, or caching — fetch the bundle yourself and call {@link parseProofBundle},
 * or pass your own resolver via `verifyRecord`'s `fetchBundle` option.
 */
export async function fetchProofBundle(
  specificationURI: string,
  options: FetchProofBundleOptions = {}
): Promise<ProofBundle> {
  const url = normalizeFetchUri(
    specificationURI,
    options.ipfsGateway ?? IPFS_GATEWAY,
    options.arGateway ?? AR_GATEWAY
  );
  assertSafeFetchUrl(url);

  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let data: any;
  try {
    const response = await doFetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(
        `Failed to fetch proof bundle from ${specificationURI}: ${response.status} ${response.statusText}`
      );
    }
    data = await readBoundedJson(response, MAX_BUNDLE_BYTES);
  } finally {
    clearTimeout(timer);
  }

  return parseProofBundle(data);
}

/**
 * Recomputes the contentKey locally and compares it to the expected value.
 * This verifies that the on-chain contentKey was correctly derived from the request and signature.
 */
export function verifyContentKey(
  request: RecordRequest,
  userSignature: Hex,
  expectedContentKey: Hex
): boolean {
  const computed = computeContentKey(request, userSignature);
  return computed.toLowerCase() === expectedContentKey.toLowerCase();
}

/**
 * Recovers the signer address from a proof bundle's EIP-712 signature.
 * Requires the controller address and chain ID to reconstruct the domain separator.
 */
export async function recoverRecordSigner(
  request: RecordRequest,
  userSignature: Hex,
  controllerAddress: Address,
  chainId: number
): Promise<Address> {
  const typedData = getEIP712TypedData(request, controllerAddress, chainId);

  return recoverTypedDataAddress({
    domain: typedData.domain,
    types: typedData.types,
    primaryType: typedData.primaryType,
    message: typedData.message,
    signature: userSignature,
  });
}

/**
 * Fetches the full IssuerInfo from the registry.
 * Returns null if the issuer is not registered.
 */
export async function getIssuerInfo(
  client: PublicClient<Transport, Chain>,
  registryAddress: Address,
  issuer: Address
): Promise<IssuerInfo | null> {
  try {
    const info = await client.readContract({
      address: registryAddress,
      abi: IssuerRegistryABI,
      functionName: "getIssuer",
      args: [issuer],
    });

    return {
      name: info.name,
      supportedRecordTypes: info.supportedRecordTypes,
      registeredAt: info.registeredAt,
      expires: info.expires,
      active: info.active,
      verifierContract: info.verifierContract,
      specificationURI: info.specificationURI,
    };
  } catch {
    return null;
  }
}

/**
 * Queries the ENS registry for the current owner of a node.
 */
export async function getNodeOwner(
  client: PublicClient<Transport, Chain>,
  ensRegistryAddress: Address,
  node: Hex
): Promise<Address> {
  return client.readContract({
    address: ensRegistryAddress,
    abi: ENSRegistryABI,
    functionName: "owner",
    args: [node],
  });
}

/** Parameters for the full verification pipeline */
export interface VerifyRecordParams {
  resolverAddress: Address;
  registryAddress: Address;
  ensRegistryAddress: Address;
  controllerAddress: Address;
  chainId: number;
  node: Hex;
  issuer: Address;
  recordType: string;
  /**
   * Optional: take full control of proof-bundle retrieval. When provided, the SDK does NOT
   * fetch — you resolve `specificationURI` however you like (your own HTTP/IPFS client, a
   * gateway you trust, a cache, an on-chain provider) and return a parsed `ProofBundle`
   * (run your fetched JSON through `parseProofBundle`). The `ctx` gives you the record
   * coordinates so you can do per-record retrieval. If omitted, the built-in transport is used.
   */
  fetchBundle?: (
    specificationURI: string,
    ctx: { node: Hex; recordType: string; issuer: Address }
  ) => Promise<ProofBundle>;
}

/**
 * Full verification pipeline:
 * 1. getIssuerInfo — fail fast if issuer is not registered/active, get specificationURI
 * 2. resolveRecord — read the text record from the resolver
 * 3. parseRecordValue — parse contentKey, expires
 * 4. fetchProofBundle — fetch the off-chain proof bundle from issuer's specificationURI
 * 5. verifyContentKey — recompute and compare contentKey
 * 6. recoverRecordSigner + owner check — verify the signer is the current name owner
 *
 * Returns a VerificationResult with granular status for each check.
 */
export async function verifyRecord(
  client: PublicClient<Transport, Chain>,
  params: VerifyRecordParams
): Promise<VerificationResult> {
  const result: VerificationResult = {
    valid: false,
    contentKeyMatch: false,
    proofValid: false,
    issuerActive: false,
    signerIsOwner: false,
    expired: false,
  };

  // Step 1: Get issuer info — fail fast if not registered, inactive, or missing specificationURI
  const issuerInfo = await getIssuerInfo(
    client,
    params.registryAddress,
    params.issuer
  );

  if (!issuerInfo || !issuerInfo.active) {
    return result;
  }

  result.issuerActive = true;

  if (!issuerInfo.specificationURI) {
    return result;
  }

  // Step 2: Resolve the on-chain text record
  const rawValue = await resolveRecord(
    client,
    params.resolverAddress,
    params.node,
    params.issuer,
    params.recordType
  );

  if (!rawValue) {
    return result;
  }

  // Step 3: Parse the record value
  let parsed: ParsedRecordValue;
  try {
    parsed = parseRecordValue(rawValue);
  } catch {
    return result;
  }

  // Check expiration (expires == 0n means no expiration)
  if (parsed.expires !== 0n) {
    const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
    if (parsed.expires <= nowSeconds) {
      result.expired = true;
      return result;
    }
  }

  // Step 4: Obtain the proof bundle. If the caller injected `fetchBundle`, they own retrieval
  // entirely (no SDK network/gateway). Otherwise use the built-in on-chain or HTTP transport.
  let bundle: ProofBundle;
  try {
    if (params.fetchBundle) {
      bundle = await params.fetchBundle(issuerInfo.specificationURI, {
        node: params.node,
        recordType: params.recordType,
        issuer: params.issuer,
      });
      const structural = validateProofBundle(bundle);
      if (!structural.valid) {
        return result;
      }
    } else if (isContractAddress(issuerInfo.specificationURI)) {
      // On-chain proof bundle provider (e.g., CCIP-Read for L2 storage proofs)
      const rawBundle = await client.readContract({
        address: issuerInfo.specificationURI as Address,
        abi: ProofBundleProviderABI,
        functionName: "getProofBundle",
        args: [params.node, params.recordType],
      });
      bundle = decodeProofBundle(rawBundle as Hex);
      const structural = validateProofBundle(bundle);
      if (!structural.valid) {
        return result;
      }
    } else {
      // fetchProofBundle already runs validateProofBundle and throws on failure.
      bundle = await fetchProofBundle(issuerInfo.specificationURI);
    }
  } catch {
    return result;
  }

  // Step 5: Verify contentKey matches. If this fails, the bundle does not correspond
  // to the on-chain record — short-circuit rather than consult the issuer's
  // verifierContract with data that is already known not to match.
  result.contentKeyMatch = verifyContentKey(
    bundle.request,
    bundle.userSignature,
    parsed.contentKey
  );

  if (!result.contentKeyMatch) {
    return result;
  }

  // Proof verification: call the issuer's verifierContract on-chain.
  try {
    result.proofValid = await client.readContract({
      address: issuerInfo.verifierContract,
      abi: ProofVerifierABI,
      functionName: "verifyProof",
      args: [bundle.proof, bundle.request.recordDataHash, params.issuer],
    });
  } catch {
    result.proofValid = false;
  }

  if (!result.proofValid) {
    return result;
  }

  // Step 6: Recover the signer and verify they are the current name owner
  try {
    const signer = await recoverRecordSigner(
      bundle.request,
      bundle.userSignature,
      params.controllerAddress,
      params.chainId
    );

    const currentOwner = await getNodeOwner(
      client,
      params.ensRegistryAddress,
      params.node
    );

    result.signerIsOwner =
      signer.toLowerCase() === currentOwner.toLowerCase();
  } catch {
    result.signerIsOwner = false;
  }

  // Overall validity — all checks must pass
  result.valid =
    result.contentKeyMatch &&
    result.proofValid &&
    result.issuerActive &&
    result.signerIsOwner &&
    !result.expired;

  return result;
}
