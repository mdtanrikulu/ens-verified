import type {
  Address,
  Hex,
  PublicClient,
  WalletClient,
  Account,
  Chain,
  Transport,
} from "viem";
import { getAddress, encodeAbiParameters, keccak256 } from "viem";
import type { RecordRequest } from "./types.js";
import { VerifiableRecordControllerABI } from "./abi.js";
import { assertValidRecordType } from "./utils.js";

/**
 * Anything that can produce an EIP-191 `personal_sign` over a raw digest — a viem
 * `WalletClient` (with a bound account) or a viem `Account` (e.g. `privateKeyToAccount`).
 */
export type Eip191Signer = {
  signMessage: (args: { message: { raw: Hex } }) => Promise<Hex>;
};

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
  assertValidRecordType(params.recordType);
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
 * Low-level EIP-191 `personal_sign` over a caller-computed digest. NO domain binding.
 *
 * This is a thin primitive, NOT a ready-made proof. For the reference `ECDSAProofVerifier`,
 * use `signECDSAProof`, which builds the domain-bound digest (recordDataHash, issuer, chainId,
 * verifier contract) the verifier expects. A custom verifier must sign its own domain-bound
 * preimage; this helper just signs whatever digest you pass.
 */
export async function signRawDigest(
  walletClient: WalletClient<Transport, Chain, Account>,
  digest: Hex
): Promise<Hex> {
  return walletClient.signMessage({
    message: { raw: digest },
  });
}

/**
 * Signs a proof for the reference `ECDSAProofVerifier`. Binds the signed preimage
 * to (recordDataHash, issuer, chainId, verifierContract) so the resulting proof
 * cannot be reused by a different verifier, on a different chain, or as a generic
 * `personal_sign` of the issuer's key.
 *
 * The on-chain verifier computes the identical digest and validates `personal_sign`
 * recovery against the declared issuer address.
 */
export async function signECDSAProof(
  signer: Eip191Signer,
  params: {
    recordDataHash: Hex;
    issuer: Address;
    chainId: bigint | number;
    verifierContract: Address;
  }
): Promise<Hex> {
  const digest = keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "address" },
        { type: "uint256" },
        { type: "address" },
      ],
      [
        params.recordDataHash,
        params.issuer,
        BigInt(params.chainId),
        params.verifierContract,
      ]
    )
  );
  return signer.signMessage({
    message: { raw: digest },
  });
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
