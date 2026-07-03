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

// Privacy / Selective Disclosure (ENSIP-PRIVACY)
export {
  saltedKeccakHash,
  randomBytes32,
  redactProofBundle,
  parseRedactedProofBundle,
  completeRedactedBundle,
  getDisclosureTypedData,
  recoverDisclosureSigner,
  verifyPrivateRecordPublic,
  verifyDisclosure,
  PRIVATE_RECORD_SENTINEL,
} from "./privacy.js";
export type {
  RedactedProofBundle,
  Disclosure,
  DisclosureNonceStore,
  VerifyDisclosureParams,
  DisclosureVerificationResult,
  PublicPrivateRecordParams,
  PublicPrivateRecordResult,
} from "./privacy.js";

// Utility functions
export {
  computeContentKey,
  parseRecordValue as parseRecordValueRaw,
  createProofBundle,
  serializeProofBundle,
  validateProofBundle,
  buildRecordKey,
  assertValidRecordType,
  expandSpecificationURI,
  checkCanonicalSignature,
  assertCanonicalSignature,
} from "./utils.js";
