import type { Address, Hex } from "viem";

/** Mirrors IVerifiableRecordController.RecordRequest */
export interface RecordRequest {
  node: Hex;
  ensName: string;
  resolver: Address;
  recordType: string;
  recordDataHash: Hex;
  issuer: Address;
  expires: bigint;
  nonce: bigint;
}

/** Off-chain proof bundle fetched from the issuer's specificationURI */
export interface ProofBundle {
  request: RecordRequest;
  userSignature: Hex;
  contentKey: Hex;
  attestation: Hex;
  /** SDK-internal: tracks where the bundle was fetched from (issuer's specificationURI) */
  contentURI: string;
}

/** Parsed on-chain text record value: "{contentKey} {expires}" */
export interface ParsedRecordValue {
  contentKey: Hex;
  expires: bigint;
}

/** Mirrors IIssuerRegistry.IssuerInfo */
export interface IssuerInfo {
  name: string;
  supportedRecordTypes: bigint;
  verificationMode: number;
  registeredAt: bigint;
  expires: bigint;
  active: boolean;
  verifierContract: Address;
  specificationURI: string;
}

/** Result of the full verification pipeline */
export interface VerificationResult {
  valid: boolean;
  contentKeyMatch: boolean;
  attestationValid: boolean;
  issuerActive: boolean;
  signerIsOwner: boolean;
  expired: boolean;
}
