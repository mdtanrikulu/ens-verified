import type { Address, Hex, PublicClient, Transport, Chain } from "viem";
import { recoverTypedDataAddress } from "viem";
import type {
  RecordRequest,
  ProofBundle,
  ParsedRecordValue,
  IssuerInfo,
  VerificationResult,
} from "./types.js";
import { TextResolverABI, IssuerRegistryABI, ENSRegistryABI } from "./abi.js";
import {
  computeContentKey,
  parseRecordValue as parseRecordValueUtil,
  buildRecordKey,
} from "./utils.js";
import { getEIP712TypedData } from "./issuer.js";

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

/**
 * Fetches and parses a ProofBundle from a content URI.
 * Supports https:// and any other URI scheme handled by the global fetch().
 */
export async function fetchProofBundle(
  contentURI: string
): Promise<ProofBundle> {
  const response = await fetch(contentURI);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch proof bundle from ${contentURI}: ${response.status} ${response.statusText}`
    );
  }

  const data = await response.json();

  // Validate that the fetched data has the expected shape
  if (!data.request || !data.userSignature || !data.contentKey) {
    throw new Error(
      "Invalid proof bundle: missing required fields (request, userSignature, contentKey)"
    );
  }

  // Reconstruct with proper bigint types from JSON (which serializes as strings/numbers)
  const bundle: ProofBundle = {
    request: {
      node: data.request.node as Hex,
      ensName: data.request.ensName as string,
      resolver: data.request.resolver as Address,
      recordType: data.request.recordType as string,
      recordDataHash: data.request.recordDataHash as Hex,
      issuer: data.request.issuer as Address,
      expires: BigInt(data.request.expires),
      nonce: BigInt(data.request.nonce),
    },
    userSignature: data.userSignature as Hex,
    contentKey: data.contentKey as Hex,
    attestation: (data.attestation ?? "0x") as Hex,
    contentURI: (data.contentURI ?? contentURI) as string,
  };

  return bundle;
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
 * Checks whether an issuer is currently active in the IssuerRegistry.
 */
export async function checkIssuerStatus(
  client: PublicClient<Transport, Chain>,
  registryAddress: Address,
  issuer: Address
): Promise<boolean> {
  const isActive = await client.readContract({
    address: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "isActiveIssuer",
    args: [issuer],
  });

  return isActive;
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
      verificationMode: info.verificationMode,
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
}

/**
 * Full verification pipeline:
 * 1. checkIssuerStatus — fail fast if issuer is revoked/expired/paused
 * 2. getIssuerInfo — retrieve specificationURI for proof bundle location
 * 3. resolveRecord — read the text record from the resolver
 * 4. parseRecordValue — parse contentKey, expires
 * 5. fetchProofBundle — fetch the off-chain proof bundle from issuer's specificationURI
 * 6. verifyContentKey — recompute and compare contentKey
 * 7. recoverRecordSigner + owner check — verify the signer is the current name owner
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
    attestationValid: false,
    issuerActive: false,
    signerIsOwner: false,
    expired: false,
  };

  // Step 1: Check issuer status first — fail fast before any proof fetching
  result.issuerActive = await checkIssuerStatus(
    client,
    params.registryAddress,
    params.issuer
  );

  if (!result.issuerActive) {
    return result;
  }

  // Step 2: Get issuer info (specificationURI for proof bundle location)
  const issuerInfo = await getIssuerInfo(
    client,
    params.registryAddress,
    params.issuer
  );

  if (!issuerInfo || !issuerInfo.specificationURI) {
    return result;
  }

  // Step 3: Resolve the on-chain text record
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

  // Step 4: Parse the record value
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

  // Step 5: Fetch the off-chain proof bundle from issuer's specificationURI
  let bundle: ProofBundle;
  try {
    bundle = await fetchProofBundle(issuerInfo.specificationURI);
  } catch {
    return result;
  }

  // Step 6: Verify contentKey matches
  result.contentKeyMatch = verifyContentKey(
    bundle.request,
    bundle.userSignature,
    parsed.contentKey
  );

  // Check if the attestation field is present (basic structural check).
  // Full attestation verification depends on the issuer's verification mode
  // (ECDSA, ZK, or hybrid) and is delegated to the issuer's verifier contract.
  result.attestationValid =
    bundle.attestation !== undefined &&
    bundle.attestation.length > 2; // more than just "0x"

  // Step 7: Recover the signer and verify they are the current name owner
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
    result.attestationValid &&
    result.issuerActive &&
    result.signerIsOwner &&
    !result.expired;

  return result;
}
