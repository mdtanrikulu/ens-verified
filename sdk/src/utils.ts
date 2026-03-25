import {
  type Address,
  type Hex,
  encodePacked,
  keccak256,
  toBytes,
  toHex,
  isHex,
  isAddress,
  getAddress,
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
  const nameHash = keccak256(toHex(toBytes(request.ensName)));

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
  attestation: Hex
): ProofBundle {
  return {
    request,
    userSignature,
    contentKey,
    attestation,
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

  // Check userSignature
  if (!isHex(bundle.userSignature) || bundle.userSignature.length < 4) {
    errors.push("Invalid userSignature: expected non-empty hex");
  }

  // Check contentKey
  if (!isHex(bundle.contentKey) || bundle.contentKey.length !== 66) {
    errors.push("Invalid contentKey: expected 32-byte hex");
  }

  // Check attestation
  if (!isHex(bundle.attestation) || bundle.attestation.length < 4) {
    errors.push("Invalid attestation: expected non-empty hex");
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Builds the text record key in the format: `vr:{issuer}:{recordType}`
 * The issuer address is lowercased (matching Solidity's `toHexString` output).
 */
export function buildRecordKey(issuer: Address, recordType: string): string {
  // Solidity Strings.toHexString produces lowercase hex with 0x prefix
  const checksummed = getAddress(issuer);
  const lowercaseHex = checksummed.toLowerCase();
  return `vr:${lowercaseHex}:${recordType}`;
}
