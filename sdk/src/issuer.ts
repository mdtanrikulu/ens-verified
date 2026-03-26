import type {
  Address,
  Hex,
  PublicClient,
  WalletClient,
  Account,
  Chain,
  Transport,
} from "viem";
import { getAddress } from "viem";
import type { RecordRequest } from "./types.js";
import { VerifiableRecordControllerABI } from "./abi.js";

/** Parameters for creating a RecordRequest */
export interface CreateRecordRequestParams {
  node: Hex;
  ensName: string;
  resolver: Address;
  recordType: string;
  recordDataHash: Hex;
  issuer: Address;
  expires: bigint;
  nonce: bigint;
}

/**
 * Builds a RecordRequest from user-friendly inputs.
 * Normalizes addresses to checksummed format.
 */
export function createRecordRequest(
  params: CreateRecordRequestParams
): RecordRequest {
  return {
    node: params.node,
    ensName: params.ensName,
    resolver: getAddress(params.resolver),
    recordType: params.recordType,
    recordDataHash: params.recordDataHash,
    issuer: getAddress(params.issuer),
    expires: params.expires,
    nonce: params.nonce,
  };
}

/**
 * Returns the full EIP-712 typed data object for signing a RecordRequest.
 *
 * Domain matches the Solidity constructor:
 *   EIP712("ENS Verifiable Records", "1")
 */
export function getEIP712TypedData(
  request: RecordRequest,
  controllerAddress: Address,
  chainId: number
) {
  return {
    domain: {
      name: "ENS Verifiable Records",
      version: "1",
      chainId: BigInt(chainId),
      verifyingContract: controllerAddress,
    },
    types: {
      RecordRequest: [
        { name: "node", type: "bytes32" },
        { name: "ensName", type: "string" },
        { name: "resolver", type: "address" },
        { name: "recordType", type: "string" },
        { name: "recordDataHash", type: "bytes32" },
        { name: "issuer", type: "address" },
        { name: "expires", type: "uint64" },
        { name: "nonce", type: "uint256" },
      ],
    },
    primaryType: "RecordRequest" as const,
    message: {
      node: request.node,
      ensName: request.ensName,
      resolver: request.resolver,
      recordType: request.recordType,
      recordDataHash: request.recordDataHash,
      issuer: request.issuer,
      expires: request.expires,
      nonce: request.nonce,
    },
  };
}

/**
 * Calls issueRecord on the VerifiableRecordController contract.
 * Must be called by the issuer (msg.sender must match request.issuer).
 * Proof bundle URI is derived from the issuer's specificationURI in IssuerRegistry.
 *
 * Returns the transaction hash.
 */
export async function issueRecord(
  client: WalletClient<Transport, Chain, Account>,
  controllerAddress: Address,
  request: RecordRequest,
  userSignature: Hex
): Promise<Hex> {
  const hash = await client.writeContract({
    address: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "issueRecord",
    args: [
      {
        node: request.node,
        ensName: request.ensName,
        resolver: request.resolver,
        recordType: request.recordType,
        recordDataHash: request.recordDataHash,
        issuer: request.issuer,
        expires: request.expires,
        nonce: request.nonce,
      },
      userSignature,
    ],
  });

  return hash;
}

/**
 * Signs arbitrary proof data with the wallet.
 * Used by issuers to create proof signatures for proof bundles.
 */
export async function signProof(
  walletClient: WalletClient<Transport, Chain, Account>,
  data: Hex
): Promise<Hex> {
  const signature = await walletClient.signMessage({
    message: { raw: data },
  });
  return signature;
}

/**
 * Calls revokeRecord on the VerifiableRecordController.
 * Must be called by the original issuer.
 *
 * Returns the transaction hash.
 */
export async function revokeRecord(
  client: WalletClient<Transport, Chain, Account>,
  controllerAddress: Address,
  node: Hex,
  recordType: string
): Promise<Hex> {
  const hash = await client.writeContract({
    address: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "revokeRecord",
    args: [node, recordType],
  });

  return hash;
}
