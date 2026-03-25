// Types
export type {
  RecordRequest,
  ProofBundle,
  ParsedRecordValue,
  IssuerInfo,
  VerificationResult,
} from "./types.js";

// ABIs
export {
  VerifiableRecordControllerABI,
  IssuerRegistryABI,
  ENSRegistryABI,
  TextResolverABI,
} from "./abi.js";

// Issuer functions
export {
  createRecordRequest,
  getEIP712TypedData,
  issueRecord,
  signAttestation,
  revokeRecord,
} from "./issuer.js";
export type { CreateRecordRequestParams } from "./issuer.js";

// Verifier functions
export {
  resolveRecord,
  parseRecordValue,
  fetchProofBundle,
  verifyContentKey,
  recoverRecordSigner,
  checkIssuerStatus,
  getIssuerInfo,
  getNodeOwner,
  verifyRecord,
} from "./verifier.js";
export type { VerifyRecordParams } from "./verifier.js";

// Utility functions
export {
  computeContentKey,
  parseRecordValue as parseRecordValueRaw,
  createProofBundle,
  validateProofBundle,
  buildRecordKey,
} from "./utils.js";
