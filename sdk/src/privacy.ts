/**
 * ENSIP-PRIVACY — Selective Disclosure for Verifiable Records.
 *
 * Implements the privacy extension's client-side primitives:
 *
 *   - salted recordDataHash        (§1)  → saltedKeccakHash; ZK commitments via a caller-supplied fn
 *   - redacted proof bundle        (§2)  → redactProofBundle / parseRedactedProofBundle / completeRedactedBundle
 *   - public verification          (§3)  → verifyPrivateRecordPublic (issuer-published signal only)
 *   - disclosure flow, vendor side (§4)  → verifyDisclosure
 *   - EIP-712 Disclosure signature (§5)  → getDisclosureTypedData / recoverDisclosureSigner
 *   - bytes32(0) on-chain sentinel (§7)  → PRIVATE_RECORD_SENTINEL (re-exported from verifier)
 *
 * ZK-committed records (e.g. Poseidon(value, salt)) need a commitment function the SDK does
 * not ship (circomlibjs is a heavy browser/wasm dependency): pass `computeRecordDataHash`
 * to `verifyDisclosure` for those record types.
 */

import type { Address, Hex, PublicClient, Transport, Chain } from "viem";
import {
  encodePacked,
  keccak256,
  stringToBytes,
  toHex,
  isHex,
  recoverTypedDataAddress,
} from "viem";
import type { ProofBundle, RecordRequest, VerificationResult } from "./types.js";
import { assertCanonicalSignature } from "./utils.js";
import {
  asDecimalBigInt,
  fetchBundleJson,
  getIssuerInfo,
  getNodeOwner,
  resolveRecord,
  parseRecordValue,
  verifyRecord,
  UINT64_MAX,
  UINT256_MAX,
  PRIVATE_RECORD_SENTINEL,
  type FetchProofBundleOptions,
} from "./verifier.js";
import { expandSpecificationURI } from "./utils.js";

export { PRIVATE_RECORD_SENTINEL };

// ── Salted recordDataHash (§1) ────────────────────────────────────────────────

/**
 * keccak256(abi.encodePacked(salt, data)) — the salted-keccak commitment scheme (§1).
 * `salt` must be 32 bytes. A string `data` is ALWAYS encoded as UTF-8 text (the
 * record type's canonical encoding) — pass `Hex`/`Uint8Array` for raw bytes.
 */
export function saltedKeccakHash(salt: Hex, data: string | Hex | Uint8Array): Hex {
  if (!isHex(salt) || salt.length !== 66) {
    throw new Error("saltedKeccakHash: salt must be 32 bytes (0x + 64 hex chars)");
  }
  const bytes =
    typeof data === "string" && !isHex(data)
      ? stringToBytes(data)
      : data;
  const dataHex = typeof bytes === "string" ? (bytes as Hex) : toHex(bytes as Uint8Array);
  return keccak256(encodePacked(["bytes32", "bytes"], [salt, dataHex]));
}

/** A cryptographically random 32-byte value — vendor nonces (§4 step 1) and salts (§1). */
export function randomBytes32(): Hex {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  return ("0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")) as Hex;
}

// ── Redacted proof bundle (§2) ────────────────────────────────────────────────

/** The public, redacted bundle a private record serves at the issuer's specificationURI (§2). */
export interface RedactedProofBundle {
  version: "1-private";
  private: true;
  request: {
    node: Hex;
    ensName: string;
    resolver: Address;
    recordType: string;
    recordDataHash: null;
    issuer: Address;
    expires: string; // decimal string (JSON-safe, matching the base bundle encoding)
    nonce: string; // decimal string
  };
  userSignature: Hex;
  contentKey: Hex;
  proof: Hex;
}

/** Produces the redacted public bundle from a full one: recordDataHash → null, version pinned. */
export function redactProofBundle(bundle: ProofBundle): RedactedProofBundle {
  return {
    version: "1-private",
    private: true,
    request: {
      node: bundle.request.node,
      ensName: bundle.request.ensName,
      resolver: bundle.request.resolver,
      recordType: bundle.request.recordType,
      recordDataHash: null,
      issuer: bundle.request.issuer,
      expires: bundle.request.expires.toString(),
      nonce: bundle.request.nonce.toString(),
    },
    userSignature: bundle.userSignature,
    contentKey: bundle.contentKey,
    proof: bundle.proof,
  };
}

/**
 * Parses + validates a fetched JSON object against the §2 redaction rules. Throws on any
 * violation (mirroring `parseProofBundle` for base bundles):
 *   - version MUST be "1-private" and private MUST be true (both directions);
 *   - request.recordDataHash MUST be present with value null;
 *   - all other base-required fields MUST be present, expires/nonce strict decimal.
 */
export function parseRedactedProofBundle(data: any): RedactedProofBundle {
  if (data?.version !== "1-private") {
    throw new Error(
      `Invalid redacted bundle: version must be "1-private", got "${data?.version}"`
    );
  }
  if (data.private !== true) {
    throw new Error(
      'Invalid redacted bundle: version "1-private" requires "private": true (§2)'
    );
  }
  if (!data.request || !data.userSignature || !data.contentKey || !data.proof) {
    throw new Error(
      "Invalid redacted bundle: missing required fields (request, userSignature, contentKey, proof)"
    );
  }
  if (!("recordDataHash" in data.request) || data.request.recordDataHash !== null) {
    throw new Error(
      "Invalid redacted bundle: request.recordDataHash must be present with value null (§2)"
    );
  }
  // Validate decimals up front so completion can't smuggle malformed values through.
  asDecimalBigInt(data.request.expires, "expires", UINT64_MAX);
  asDecimalBigInt(data.request.nonce, "nonce", UINT256_MAX);
  return data as RedactedProofBundle;
}

/**
 * Vendor §4 step 7: complete a redacted bundle with the recordDataHash reconstructed from
 * the disclosed (salt, data). The result is a full base-spec ProofBundle, ready for the
 * standard §7 pipeline.
 */
export function completeRedactedBundle(
  redacted: RedactedProofBundle,
  recordDataHash: Hex
): ProofBundle {
  const request: RecordRequest = {
    node: redacted.request.node,
    ensName: redacted.request.ensName,
    resolver: redacted.request.resolver,
    recordType: redacted.request.recordType,
    recordDataHash,
    issuer: redacted.request.issuer,
    expires: asDecimalBigInt(redacted.request.expires, "expires", UINT64_MAX),
    nonce: asDecimalBigInt(redacted.request.nonce, "nonce", UINT256_MAX),
  };
  return {
    request,
    userSignature: redacted.userSignature,
    contentKey: redacted.contentKey,
    proof: redacted.proof,
  };
}

// ── Disclosure signature (§5, EIP-712) ────────────────────────────────────────

/** The EIP-712 `Disclosure` struct (§5). */
export interface Disclosure {
  node: Hex;
  issuer: Address;
  recordType: string;
  nonce: Hex; // vendor-issued, exactly 32 bytes
  vendor: Address; // address(0) if the vendor does not authenticate via a wallet
  vendorIdentity: string; // display identity (origin URL / DID); "" only when vendor != address(0)
  expires: bigint; // 0 = no expiry
}

/** EIP-712 typed data for the `Disclosure` struct — sign with walletClient.signTypedData. */
export function getDisclosureTypedData(
  disclosure: Disclosure,
  controllerAddress: Address,
  chainId: number
) {
  return {
    domain: {
      name: "ENS Selective Disclosure",
      version: "1",
      chainId: BigInt(chainId),
      verifyingContract: controllerAddress,
    },
    types: {
      Disclosure: [
        { name: "node", type: "bytes32" },
        { name: "issuer", type: "address" },
        { name: "recordType", type: "string" },
        { name: "nonce", type: "bytes32" },
        { name: "vendor", type: "address" },
        { name: "vendorIdentity", type: "string" },
        { name: "expires", type: "uint64" },
      ],
    },
    primaryType: "Disclosure" as const,
    message: {
      node: disclosure.node,
      issuer: disclosure.issuer,
      recordType: disclosure.recordType,
      nonce: disclosure.nonce,
      vendor: disclosure.vendor,
      vendorIdentity: disclosure.vendorIdentity,
      expires: disclosure.expires,
    },
  };
}

/** Recovers the signer of a disclosure signature (canonical low-s enforced, L-5). */
export async function recoverDisclosureSigner(
  disclosure: Disclosure,
  disclosureSignature: Hex,
  controllerAddress: Address,
  chainId: number
): Promise<Address> {
  assertCanonicalSignature(disclosureSignature);
  const typedData = getDisclosureTypedData(disclosure, controllerAddress, chainId);
  return recoverTypedDataAddress({
    domain: typedData.domain,
    types: typedData.types,
    primaryType: typedData.primaryType,
    message: typedData.message,
    signature: disclosureSignature,
  });
}

// ── Public verification without disclosure (§3) ───────────────────────────────

export interface PublicPrivateRecordParams {
  registryAddress: Address;
  resolverAddress: Address;
  node: Hex;
  issuer: Address;
  recordType: string;
  /** Custom redacted-bundle transport; defaults to the hardened built-in fetch. */
  fetchRedactedBundle?: (specificationURI: string) => Promise<any>;
  fetchOptions?: FetchProofBundleOptions;
}

export interface PublicPrivateRecordResult {
  /** All §3 checks 1–7 passed. NOT proof the current owner holds the attestation —
   *  the strongest establishable semantic is "issuer published a matching, non-expired
   *  redacted bundle for this record". Treat as unconfirmed / disclosure-required. */
  published: boolean;
  issuerActive: boolean;
  recordFound: boolean;
  bundleMatches: boolean;
  expiresMatches: boolean;
  expired: boolean;
  redactedBundle: RedactedProofBundle | null;
}

/**
 * §3 public verification of a private record: binds the owner-writable text record to an
 * artifact the issuer actually served, without recordDataHash. Cannot check the content-key
 * derivation, the issuer proof, or name ownership — those require disclosure (§4).
 */
export async function verifyPrivateRecordPublic(
  client: PublicClient<Transport, Chain>,
  params: PublicPrivateRecordParams
): Promise<PublicPrivateRecordResult> {
  const result: PublicPrivateRecordResult = {
    published: false,
    issuerActive: false,
    recordFound: false,
    bundleMatches: false,
    expiresMatches: false,
    expired: false,
    redactedBundle: null,
  };

  // §3 check 2 (issuer active) — same fail-fast ordering as the base flow.
  const issuerInfo = await getIssuerInfo(client, params.registryAddress, params.issuer);
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (!issuerInfo || !issuerInfo.active || issuerInfo.expires <= now) return result;
  result.issuerActive = true;

  // §3 check 1 (record exists) + check 3 (on-chain expiry).
  const raw = await resolveRecord(
    client,
    params.resolverAddress,
    params.node,
    params.issuer,
    params.recordType
  );
  if (!raw) return result;
  let parsed;
  try {
    parsed = parseRecordValue(raw);
  } catch {
    return result;
  }
  result.recordFound = true;
  if (parsed.expires !== 0n && parsed.expires <= now) {
    result.expired = true;
    return result;
  }

  // §3 steps 4–7: fetch the redacted bundle and bind it to the on-chain record.
  let redacted: RedactedProofBundle;
  try {
    const uri = expandSpecificationURI(
      issuerInfo.specificationURI,
      params.node,
      params.recordType
    );
    const json = params.fetchRedactedBundle
      ? await params.fetchRedactedBundle(uri)
      : await fetchBundleJson(uri, params.fetchOptions);
    redacted = parseRedactedProofBundle(json);
  } catch {
    return result;
  }
  result.redactedBundle = redacted;

  result.bundleMatches =
    redacted.request.node.toLowerCase() === params.node.toLowerCase() &&
    redacted.request.issuer.toLowerCase() === params.issuer.toLowerCase() &&
    redacted.request.recordType === params.recordType &&
    redacted.contentKey.toLowerCase() === parsed.contentKey.toLowerCase();

  const bundleExpires = asDecimalBigInt(redacted.request.expires, "expires", UINT64_MAX);
  result.expiresMatches =
    bundleExpires === parsed.expires && (bundleExpires === 0n || bundleExpires > now);

  result.published = result.bundleMatches && result.expiresMatches;
  return result;
}

// ── Vendor-side disclosure verification (§4, step 3) ──────────────────────────

/**
 * Single-use nonce store the vendor supplies. The spec (§4) requires the
 * issued-and-unconsumed check and the consume to be ONE atomic operation against a
 * store that is linearizable across every instance that can accept a disclosure —
 * implement `consume` as an atomic compare-and-set (conditional write, SELECT…FOR
 * UPDATE, SET…NX). The SDK cannot provide that guarantee for you.
 */
export interface DisclosureNonceStore {
  /** Advisory fail-fast check (§4 step 3.2). May be weaker than the consume. */
  isIssuedUnconsumed(nonce: Hex): Promise<boolean>;
  /** Atomic check-and-consume (§4 step 3.9). Returns false if already consumed/unknown. */
  consume(nonce: Hex): Promise<boolean>;
}

export interface VerifyDisclosureParams {
  /** The signed struct as received (the vendor MUST have issued this challenge). */
  disclosure: Disclosure;
  disclosureSignature: Hex;
  /** Disclosed raw value: strings are UTF-8 text; pass Hex/Uint8Array for raw bytes. */
  data: string | Hex | Uint8Array;
  /** Disclosed salt (hex; 32 bytes for salted keccak, field element for ZK schemes). */
  salt: Hex;
  /** What the vendor itself issued with the challenge — checked against the signed struct. */
  challenge: {
    nonce: Hex;
    node: Hex;
    issuer: Address;
    recordType: string;
    vendor: Address;
    vendorIdentity: string;
    expires: bigint;
  };
  /** §1 commitment scheme override for ZK records (e.g. Poseidon(value, salt)).
   *  Defaults to saltedKeccakHash. */
  computeRecordDataHash?: (salt: Hex, data: string | Hex | Uint8Array) => Hex | Promise<Hex>;
  nonceStore?: DisclosureNonceStore;
  /** Chain context for the base verification flow. */
  registryAddress: Address;
  resolverAddress: Address;
  ensRegistryAddress: Address;
  controllerAddress: Address;
  chainId: number;
  /** Custom redacted-bundle transport; defaults to the hardened built-in fetch. */
  fetchRedactedBundle?: (specificationURI: string) => Promise<any>;
  fetchOptions?: FetchProofBundleOptions;
}

export interface DisclosureVerificationResult {
  /** Every §4 step passed (including nonce consumption when a store was supplied). */
  valid: boolean;
  signer: Address | null;
  signerIsOwner: boolean;
  nonceValid: boolean;
  scopeValid: boolean;
  expiryValid: boolean;
  recordDataHash: Hex | null;
  /** Result of the full base §7 pipeline over the completed bundle (§4 step 3.8). */
  verification: VerificationResult | null;
  nonceConsumed: boolean;
}

/**
 * Vendor-side §4 step-3 verification, end to end. On success the vendor has proof that the
 * issuer attested to exactly this (data, salt) pair for the current owner of `node`.
 */
export async function verifyDisclosure(
  client: PublicClient<Transport, Chain>,
  params: VerifyDisclosureParams
): Promise<DisclosureVerificationResult> {
  const result: DisclosureVerificationResult = {
    valid: false,
    signer: null,
    signerIsOwner: false,
    nonceValid: false,
    scopeValid: false,
    expiryValid: false,
    recordDataHash: null,
    verification: null,
    nonceConsumed: false,
  };
  const d = params.disclosure;

  // Step 3.1 — disclosure signature vs current name owner.
  try {
    result.signer = await recoverDisclosureSigner(
      d,
      params.disclosureSignature,
      params.controllerAddress,
      params.chainId
    );
    const owner = await getNodeOwner(client, params.ensRegistryAddress, d.node);
    result.signerIsOwner = result.signer.toLowerCase() === owner.toLowerCase();
  } catch {
    return result;
  }
  if (!result.signerIsOwner) return result;

  // Step 3.2 — advisory nonce check (authoritative check happens in the consume, 3.9).
  result.nonceValid =
    d.nonce === params.challenge.nonce &&
    (params.nonceStore ? await params.nonceStore.isIssuedUnconsumed(d.nonce) : true);
  if (!result.nonceValid) return result;

  // Step 3.3 — scope: signed struct must equal what the vendor's challenge declared.
  result.scopeValid =
    d.node.toLowerCase() === params.challenge.node.toLowerCase() &&
    d.issuer.toLowerCase() === params.challenge.issuer.toLowerCase() &&
    d.recordType === params.challenge.recordType &&
    d.vendor.toLowerCase() === params.challenge.vendor.toLowerCase() &&
    d.vendorIdentity === params.challenge.vendorIdentity;
  if (!result.scopeValid) return result;

  // Step 3.4 — expiry: signed expires must equal the issued one, and must not have passed.
  const now = BigInt(Math.floor(Date.now() / 1000));
  result.expiryValid =
    d.expires === params.challenge.expires && (d.expires === 0n || now <= d.expires);
  if (!result.expiryValid) return result;

  // Step 3.5 — reconstruct recordDataHash per the record type's commitment scheme (§1).
  const compute = params.computeRecordDataHash ?? saltedKeccakHash;
  result.recordDataHash = await compute(params.salt, params.data);

  // Steps 3.6–3.8 — fetch redacted bundle, complete it, run the full base §7 pipeline
  // (which includes the context cross-checks, content key, proof, and ownership).
  try {
    const issuerInfo = await getIssuerInfo(client, params.registryAddress, d.issuer);
    if (!issuerInfo) return result;
    const uri = expandSpecificationURI(issuerInfo.specificationURI, d.node, d.recordType);
    const json = params.fetchRedactedBundle
      ? await params.fetchRedactedBundle(uri)
      : await fetchBundleJson(uri, params.fetchOptions);
    const redacted = parseRedactedProofBundle(json);
    const completed = completeRedactedBundle(redacted, result.recordDataHash);

    result.verification = await verifyRecord(client, {
      registryAddress: params.registryAddress,
      resolverAddress: params.resolverAddress,
      ensRegistryAddress: params.ensRegistryAddress,
      controllerAddress: params.controllerAddress,
      chainId: params.chainId,
      node: d.node,
      issuer: d.issuer,
      recordType: d.recordType,
      fetchBundle: async () => completed,
    });
  } catch {
    return result;
  }
  if (!result.verification?.valid) return result;

  // Step 3.9 — atomic consume, coupled to acceptance.
  if (params.nonceStore) {
    result.nonceConsumed = await params.nonceStore.consume(d.nonce);
    if (!result.nonceConsumed) return result;
  } else {
    result.nonceConsumed = true; // caller opted to manage nonce state externally
  }

  result.valid = true;
  return result;
}
