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

/**
 * Fetches and parses a ProofBundle from the issuer's specificationURI.
 * Supports https:// and any other URI scheme handled by the global fetch().
 */
export async function fetchProofBundle(
  specificationURI: string
): Promise<ProofBundle> {
  const response = await fetch(specificationURI);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch proof bundle from ${specificationURI}: ${response.status} ${response.statusText}`
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
    proof: (data.proof ?? data.attestation ?? "0x") as Hex,
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

  // Step 4: Fetch the proof bundle
  let bundle: ProofBundle;
  try {
    if (isContractAddress(issuerInfo.specificationURI)) {
      // On-chain proof bundle provider (e.g., CCIP-Read for L2 storage proofs)
      const rawBundle = await client.readContract({
        address: issuerInfo.specificationURI as Address,
        abi: ProofBundleProviderABI,
        functionName: "getProofBundle",
        args: [params.node, params.recordType],
      });
      bundle = decodeProofBundle(rawBundle as Hex);
    } else {
      bundle = await fetchProofBundle(issuerInfo.specificationURI);
    }
  } catch {
    return result;
  }

  // Step 5: Verify contentKey matches
  result.contentKeyMatch = verifyContentKey(
    bundle.request,
    bundle.userSignature,
    parsed.contentKey
  );

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
