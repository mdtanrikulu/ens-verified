import {
  type Address,
  type Hex,
  encodePacked,
  keccak256,
  stringToBytes,
  isHex,
  isAddress,
  getAddress,
  hexToBigInt,
  slice,
} from "viem";
import type { RecordRequest, ProofBundle, ParsedRecordValue } from "./types.js";

/**
 * Replicates the Solidity `_deriveContentKey` exactly.
 *
 * Solidity: keccak256(abi.encodePacked(userSignature, keccak256(bytes(ensName)), resolver, recordDataHash, issuer))
 *
 * abi.encodePacked layout (addresses are 20 bytes, not padded):
 *   userSignature || keccak256(ensName) [32] || resolver [20] || recordDataHash [32] || issuer [20]
 */
export function computeContentKey(
  request: RecordRequest,
  userSignature: Hex
): Hex {
  // stringToBytes, NOT toBytes: viem's toBytes treats a "0x…"-prefixed name as hex
  // and would mis-encode names like "0xdead.eth" (L-8).
  const nameHash = keccak256(stringToBytes(request.ensName));

  const packed = encodePacked(
    ["bytes", "bytes32", "address", "bytes32", "address"],
    [userSignature, nameHash, request.resolver, request.recordDataHash, request.issuer]
  );

  return keccak256(packed);
}

/**
 * Parses the on-chain text record value format:
 * "{contentKey} {expires}"
 *
 * - contentKey: 66 chars (0x + 64 hex digits)
 * - expires: decimal digits (Unix timestamp), "0" means no expiration
 *
 * Proof bundle URI is obtained from IssuerRegistry.specificationURI, not from the record.
 */
export function parseRecordValue(rawValue: string): ParsedRecordValue {
  const spaceIdx = rawValue.indexOf(" ");
  if (spaceIdx === -1) {
    throw new Error("Invalid record value format: missing space delimiter");
  }

  const contentKey = rawValue.slice(0, spaceIdx);
  if (contentKey.length !== 66 || !contentKey.startsWith("0x")) {
    throw new Error(
      `Invalid contentKey: expected 66-char hex string, got "${contentKey}"`
    );
  }

  const expiresStr = rawValue.slice(spaceIdx + 1);
  if (!/^\d+$/.test(expiresStr)) {
    throw new Error(
      `Invalid expires value: expected decimal digits, got "${expiresStr}"`
    );
  }

  return {
    contentKey: contentKey as Hex,
    expires: BigInt(expiresStr),
  };
}

/**
 * Assembles a ProofBundle object from its components.
 */
export function createProofBundle(
  request: RecordRequest,
  userSignature: Hex,
  contentKey: Hex,
  proof: Hex
): ProofBundle {
  return {
    request,
    userSignature,
    contentKey,
    proof,
  };
}

/**
 * Validates the structural integrity of a ProofBundle.
 * Checks hex formats and required fields.
 */
export function validateProofBundle(bundle: ProofBundle): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Check request fields
  if (!bundle.request) {
    errors.push("Missing request");
  } else {
    if (!isHex(bundle.request.node) || bundle.request.node.length !== 66) {
      errors.push("Invalid request.node: expected 32-byte hex");
    }
    if (!bundle.request.ensName || bundle.request.ensName.length === 0) {
      errors.push("Missing request.ensName");
    }
    if (!isAddress(bundle.request.resolver)) {
      errors.push("Invalid request.resolver: not a valid address");
    }
    if (!bundle.request.recordType || bundle.request.recordType.length === 0) {
      errors.push("Missing request.recordType");
    }
    if (
      !isHex(bundle.request.recordDataHash) ||
      bundle.request.recordDataHash.length !== 66
    ) {
      errors.push("Invalid request.recordDataHash: expected 32-byte hex");
    }
    if (!isAddress(bundle.request.issuer)) {
      errors.push("Invalid request.issuer: not a valid address");
    }
  }

  // Check userSignature — must be canonical 65-byte low-s ECDSA, matching the
  // contract's OpenZeppelin ECDSA checks (L-5).
  {
    const sigErr = isHex(bundle.userSignature)
      ? checkCanonicalSignature(bundle.userSignature)
      : "expected hex";
    if (sigErr) {
      errors.push(`Invalid userSignature: ${sigErr}`);
    }
  }

  // Check contentKey
  if (!isHex(bundle.contentKey) || bundle.contentKey.length !== 66) {
    errors.push("Invalid contentKey: expected 32-byte hex");
  }

  // Check proof
  if (!isHex(bundle.proof) || bundle.proof.length < 4) {
    errors.push("Invalid proof: expected non-empty hex");
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validates a recordType against the on-chain rule (spec Section 2): it MUST match
 * `^[a-z0-9_]+$` — non-empty, lowercase ASCII letters, digits, and underscore only.
 * Mirrors `VerifiableRecordController._validateRecordType` so the SDK fails fast rather
 * than building a key the contract would reject (or that wouldn't match on lookup).
 */
const RECORD_TYPE_RE = /^[a-z0-9_]+$/;

export function assertValidRecordType(recordType: string): void {
  if (!RECORD_TYPE_RE.test(recordType)) {
    throw new Error(
      `Invalid recordType "${recordType}": must match ^[a-z0-9_]+$ (lowercase letters, digits, underscore)`
    );
  }
}

/**
 * Builds the text record key in the format: `vr:{issuer}:{recordType}`
 * The issuer address is lowercased (matching Solidity's `toHexString` output).
 */
export function buildRecordKey(issuer: Address, recordType: string): string {
  assertValidRecordType(recordType);
  // Solidity Strings.toHexString produces lowercase hex with 0x prefix
  const checksummed = getAddress(issuer);
  const lowercaseHex = checksummed.toLowerCase();
  return `vr:${lowercaseHex}:${recordType}`;
}

/**
 * Serializes a proof bundle to the canonical JSON document issuers host at their
 * specificationURI (ENSIP.md Section 8): `"version": "1"`, with `expires`/`nonce` as
 * decimal strings (uint256 exceeds JSON's safe-integer range). Inverse of
 * `parseProofBundle`. Note: plain JSON.stringify would throw on the bigint fields.
 */
export function serializeProofBundle(bundle: ProofBundle): string {
  return JSON.stringify({
    version: "1",
    request: {
      ...bundle.request,
      expires: bundle.request.expires.toString(),
      nonce: bundle.request.nonce.toString(),
    },
    userSignature: bundle.userSignature,
    contentKey: bundle.contentKey,
    proof: bundle.proof,
  });
}

// secp256k1 group order n and n/2 — low-s boundary per EIP-2.
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;

/**
 * Checks that a signature is a canonical 65-byte ECDSA signature: r || s || v with
 * 1 <= r < n, low-s (s <= n/2, EIP-2), and v in {27, 28}. Mirrors what the contract
 * enforces via OpenZeppelin ECDSA (which rejects high-s and malformed lengths), so the
 * SDK fails the same inputs the chain would (L-5). Returns an error string or null.
 */
export function checkCanonicalSignature(signature: Hex): string | null {
  if (!isHex(signature) || signature.length !== 132) {
    return "expected 65-byte signature (0x + 130 hex chars)";
  }
  const r = hexToBigInt(slice(signature, 0, 32));
  const s = hexToBigInt(slice(signature, 32, 64));
  const v = hexToBigInt(slice(signature, 64, 65));
  if (r === 0n || r >= SECP256K1_N) return "r out of range";
  if (s === 0n || s > SECP256K1_HALF_N) return "s is not low-s canonical (EIP-2)";
  if (v !== 27n && v !== 28n) return "v must be 27 or 28";
  return null;
}

/**
 * Throws unless the signature is canonical (see checkCanonicalSignature).
 */
export function assertCanonicalSignature(signature: Hex): void {
  const err = checkCanonicalSignature(signature);
  if (err) throw new Error(`Non-canonical signature: ${err}`);
}

/**
 * Expands the per-record URI template placeholders defined in ENSIP.md Section 8:
 * `{node}` → lowercase 0x-prefixed node hex, `{recordType}` → the record type verbatim.
 * URIs without placeholders are returned unchanged (single-bundle issuers).
 */
export function expandSpecificationURI(
  uri: string,
  node: Hex,
  recordType: string
): string {
  return uri
    .replaceAll("{node}", node.toLowerCase())
    .replaceAll("{recordType}", recordType);
}
