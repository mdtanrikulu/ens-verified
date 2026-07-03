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
  ProofVerifierABI,
  ProofBundleProviderABI,
} from "./abi.js";

// Issuer functions
export {
  createRecordRequest,
  getEIP712TypedData,
  issueRecord,
  signRawDigest,
  signECDSAProof,
  revokeRecord,
} from "./issuer.js";
export type { CreateRecordRequestParams, Eip191Signer } from "./issuer.js";

// Verifier functions
export {
  resolveRecord,
  parseRecordValue,
  fetchProofBundle,
  parseProofBundle,
  verifyContentKey,
  recoverRecordSigner,
  getIssuerInfo,
  getNodeOwner,
  verifyRecord,
} from "./verifier.js";
export type { VerifyRecordParams, FetchProofBundleOptions } from "./verifier.js";

// Utility functions
export {
  computeContentKey,
  parseRecordValue as parseRecordValueRaw,
  createProofBundle,
  validateProofBundle,
  buildRecordKey,
  assertValidRecordType,
} from "./utils.js";
