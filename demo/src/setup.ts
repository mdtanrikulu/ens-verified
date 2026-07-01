/**
 * ENS Verifiable Records — Browser Setup (Tevm)
 *
 * Deploys contracts, registers ENS name, issues records, and generates
 * ZK proofs — all inside a standalone in-browser Tevm EVM.
 * No external RPC required.
 */

import { createMemoryClient } from "tevm";
import { mainnet } from "@tevm/common";
import {
  namehash,
  keccak256,
  toHex,
  toBytes,
  encodeAbiParameters,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
// @ts-ignore — snarkjs has no types
import * as snarkjs from "snarkjs";

import {
  IssuerRegistryABI,
  VerifiableRecordControllerABI,
  createRecordRequest,
  getEIP712TypedData,
  computeContentKey,
  createProofBundle,
  signECDSAProof,
} from "@ensverify/sdk";
import { saltedKeccakHash, redactBundle, type RedactedBundle } from "./privacy";

import {
  IssuerRegistry,
  VerifiableRecordController,
  MockResolver,
  ECDSAProofVerifier,
  Groth16Verifier,
  ZkAgeVerifier,
  MockENSRegistry,
} from "./artifacts";

// ── Constants ────────────────────────────────────────────────────────────────

const ENS_NAME = "ensverify.eth";

const ECDSA_RECORD_TYPE = "github";
const ECDSA_CLAIM_PAYLOAD = "github:ensverify";

const ZK_RECORD_TYPE = "age";
const ZK_BIRTHDAY = "946684800"; // Jan 1, 2000

// Private (selective-disclosure) records — ENSIP-PRIVACY. These are served as REDACTED
// bundles and demonstrated in the "Selective Disclosure" tab.
const EMAIL_RECORD_TYPE = "email";
const EMAIL_VALUE = "alice@example.com"; // low-entropy private data, disclosed only to a vendor
const PRIVATE_AGE_RECORD_TYPE = "age";

// Well-known test private keys (deterministic, NOT secret)
const DAO_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const ECDSA_ISSUER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const USER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;
const ZK_ISSUER_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex;
const EMAIL_ISSUER_KEY = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" as Hex;
const PRIVATE_AGE_ISSUER_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" as Hex;

const MockENSRegistryABI = [
  {
    type: "function",
    name: "owner",
    inputs: [{ name: "node", type: "bytes32" }],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "setSubnodeOwner",
    inputs: [
      { name: "node", type: "bytes32" },
      { name: "label", type: "bytes32" },
      { name: "newOwner", type: "address" },
    ],
    outputs: [{ name: "", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setResolver",
    inputs: [
      { name: "node", type: "bytes32" },
      { name: "newResolver", type: "address" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

// ── Types ────────────────────────────────────────────────────────────────────

export interface IssuerConfig {
  address: string;
  recordType: string;
  type: "ecdsa" | "zk";
  label: string;
}

/**
 * A private (selective-disclosure) record for the Privacy tab. `secret` is the data the
 * user would hold in their wallet and reveal only to a vendor over a confidential channel;
 * it never appears on-chain or in the public (redacted) bundle. We keep it client-side here
 * purely to drive the demo's disclosure flow.
 */
export type DisclosureSecret =
  | { kind: "keccak"; data: string; salt: Hex }
  | { kind: "poseidon"; data: string; birthday: string; saltDecimal: string };

export interface PrivateRecordConfig {
  type: "email" | "age";
  label: string;
  recordType: string;
  issuerAddress: Address;
  verifierContract: Address;
  specificationURI: string;
  recordDataHash: Hex; // the true, salted on-chain hash (for "reconstruction matches" display)
  /**
   * How much the PUBLIC path reveals:
   *  - "redacted": nothing (bundle omits recordDataHash) — email. Disclosure reveals the value.
   *  - "predicate": a ZK-proven predicate (e.g. "age ≥ 18") is public while the value stays
   *    hidden — age. Disclosure reveals the exact value.
   */
  publicModel: "redacted" | "predicate";
  predicateLabel?: string; // predicate model only, e.g. "Age ≥ 18"
  redactedBundle?: RedactedBundle; // redacted model only (for display)
  secret: DisclosureSecret;
}

export interface DemoConfig {
  registryAddress: Address;
  controllerAddress: Address;
  resolverAddress: Address;
  ensRegistryAddress: Address;
  userAddress: Address;
  ensName: string;
  node: Hex;
  chainId: number;
  issuers: IssuerConfig[];
  privateRecords: PrivateRecordConfig[];
  /** The name owner's local account — used to sign disclosure requests in the demo. */
  userAccount: PrivateKeyAccount;
}

export type ProgressCallback = (step: number, total: number, message: string) => void;

// ── Helpers ──────────────────────────────────────────────────────────────────

function labelhash(label: string): Hex {
  return keccak256(toBytes(label));
}

function serializeBundle(bundle: any): string {
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

function blobUrl(json: string): string {
  return URL.createObjectURL(new Blob([json], { type: "application/json" }));
}

// ── Main Setup ───────────────────────────────────────────────────────────────

export async function runSetup(
  onProgress: ProgressCallback,
): Promise<{ config: DemoConfig; client: any }> {
  const TOTAL_STEPS = 7;

  // ── Step 1: Create in-browser EVM ────────────────────────────────────────

  onProgress(1, TOTAL_STEPS, "Creating in-browser EVM...");

  const client = createMemoryClient({
    common: mainnet,
  });
  await client.tevmReady();

  const daoAccount = privateKeyToAccount(DAO_KEY);
  const ecdsaIssuerAccount = privateKeyToAccount(ECDSA_ISSUER_KEY);
  const userAccount = privateKeyToAccount(USER_KEY);
  const zkIssuerAccount = privateKeyToAccount(ZK_ISSUER_KEY);
  const emailIssuerAccount = privateKeyToAccount(EMAIL_ISSUER_KEY);
  const privateAgeIssuerAccount = privateKeyToAccount(PRIVATE_AGE_ISSUER_KEY);

  // Fund all accounts on the local chain
  await Promise.all([
    client.setBalance({ address: daoAccount.address, value: 10n ** 18n }),
    client.setBalance({ address: ecdsaIssuerAccount.address, value: 10n ** 18n }),
    client.setBalance({ address: userAccount.address, value: 10n ** 18n }),
    client.setBalance({ address: zkIssuerAccount.address, value: 10n ** 18n }),
    client.setBalance({ address: emailIssuerAccount.address, value: 10n ** 18n }),
    client.setBalance({ address: privateAgeIssuerAccount.address, value: 10n ** 18n }),
  ]);

  // ── Step 2: Deploy contracts ─────────────────────────────────────────────

  onProgress(2, TOTAL_STEPS, "Deploying contracts (7 contracts)...");

  async function deploy(
    artifact: { abi: readonly any[]; bytecode: Hex },
    args: any[] = [],
    from: Address = daoAccount.address,
  ): Promise<Address> {
    const result = await client.tevmDeploy({
      from,
      abi: artifact.abi,
      bytecode: artifact.bytecode,
      args,
      createTransaction: true,
    } as any);
    if (!result.createdAddress) {
      throw new Error(`Deploy failed: ${result.errors?.map((e: any) => e.message).join(", ") ?? "no address"}`);
    }
    await client.tevmMine();
    return result.createdAddress as Address;
  }

  const ensRegistryAddress = await deploy(MockENSRegistry);
  const registryAddress = await deploy(IssuerRegistry);
  const controllerAddress = await deploy(VerifiableRecordController, [registryAddress]);
  const resolverAddress = await deploy(MockResolver);
  const ecdsaVerifierAddress = await deploy(ECDSAProofVerifier);
  const groth16Address = await deploy(Groth16Verifier);
  const zkVerifierAddress = await deploy(ZkAgeVerifier, [groth16Address]);

  // ── Step 3: Register ENS name ────────────────────────────────────────────

  onProgress(3, TOTAL_STEPS, "Registering ENS name...");

  const node = namehash(ENS_NAME);
  const rootNode = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;
  const ethLabel = labelhash("eth");
  const ensverifyLabel = labelhash("ensverify");

  async function call(params: any) {
    const result = await client.tevmContract({ ...params, createTransaction: true });
    await client.tevmMine();
    if (result.errors?.length) {
      throw new Error(`Call failed: ${result.errors.map((e: any) => e.message).join(", ")}`);
    }
    return result;
  }

  // DAO owns root (deployer of MockENSRegistry) → create "eth" subnode
  await call({
    from: daoAccount.address,
    to: ensRegistryAddress,
    abi: MockENSRegistryABI,
    functionName: "setSubnodeOwner",
    args: [rootNode, ethLabel, daoAccount.address],
  });

  // DAO owns "eth" → create "ensverify.eth" owned by user
  const ethNode = namehash("eth");
  await call({
    from: daoAccount.address,
    to: ensRegistryAddress,
    abi: MockENSRegistryABI,
    functionName: "setSubnodeOwner",
    args: [ethNode, ensverifyLabel, userAccount.address],
  });

  // User sets resolver for ensverify.eth
  await call({
    from: userAccount.address,
    to: ensRegistryAddress,
    abi: MockENSRegistryABI,
    functionName: "setResolver",
    args: [node, resolverAddress],
  });

  // ── Step 4: Prepare records + ZK proof + proof bundles ───────────────────
  // We prepare everything off-chain first so we can create blob URLs
  // before registering issuers (specificationURI is immutable).

  onProgress(4, TOTAL_STEPS, "Generating ZK age proof...");

  const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
  const oneYear = 365n * 24n * 60n * 60n;
  const issuerExpires = nowSeconds + oneYear;
  const recordExpires = nowSeconds + oneYear;

  // ── ECDSA record preparation (off-chain) ──

  const ecdsaRecordDataHash = keccak256(toHex(toBytes(ECDSA_CLAIM_PAYLOAD)));

  // Nonces: fresh controller → user starts at 0
  const ecdsaRequest = createRecordRequest({
    node,
    ensName: ENS_NAME,
    resolver: resolverAddress,
    recordType: ECDSA_RECORD_TYPE,
    recordDataHash: ecdsaRecordDataHash,
    issuer: ecdsaIssuerAccount.address,
    expires: recordExpires,
    nonce: 0n,
  });

  const ecdsaTypedData = getEIP712TypedData(ecdsaRequest, controllerAddress, 1);
  const ecdsaUserSig = await userAccount.signTypedData({
    domain: ecdsaTypedData.domain as any,
    types: ecdsaTypedData.types as any,
    primaryType: ecdsaTypedData.primaryType as any,
    message: ecdsaTypedData.message as any,
  });

  const ecdsaContentKey = computeContentKey(ecdsaRequest, ecdsaUserSig);
  // Domain-bound proof for the reference ECDSAProofVerifier. The digest construction
  // (recordDataHash, issuer, chainId, verifier contract) lives once in the SDK helper.
  const ecdsaProof = await signECDSAProof(ecdsaIssuerAccount, {
    recordDataHash: ecdsaRecordDataHash,
    issuer: ecdsaIssuerAccount.address,
    chainId: 1,
    verifierContract: ecdsaVerifierAddress,
  });
  const ecdsaBundle = createProofBundle(ecdsaRequest, ecdsaUserSig, ecdsaContentKey, ecdsaProof);

  // ── ZK age record preparation (off-chain) ──

  const currentDateUnix = Math.floor(Date.now() / 1000).toString();

  // Per ENSIP-PRIVACY "ZK Commitment Blinding": the birthday commitment MUST be salted so the
  // public birthdayHash (which becomes the on-chain recordDataHash) cannot be brute-forced from
  // the low-entropy birthday. The salt is a PRIVATE circuit input — it never appears in a public
  // signal or the public proof bundle. A real issuer generates it with a CSPRNG and delivers it to
  // the user confidentially, to be persisted for later selective disclosure.
  const saltBytes = crypto.getRandomValues(new Uint8Array(16)); // 128-bit
  const zkSalt = BigInt(
    "0x" + Array.from(saltBytes, (b) => b.toString(16).padStart(2, "0")).join(""),
  ).toString();

  const { proof: zkProofData, publicSignals } = await snarkjs.groth16.fullProve(
    { birthday: ZK_BIRTHDAY, salt: zkSalt, currentDate: currentDateUnix },
    `${import.meta.env.BASE_URL}age_verification.wasm`,
    `${import.meta.env.BASE_URL}age_verification_final.zkey`,
  );

  const birthdayHash = BigInt(publicSignals[0]);

  // Verify locally before proceeding
  const vkeyResp = await fetch(`${import.meta.env.BASE_URL}age_verification_vkey.json`);
  const vkey = await vkeyResp.json();
  const localValid = await snarkjs.groth16.verify(vkey, publicSignals, zkProofData);
  if (!localValid) throw new Error("ZK proof failed local verification");

  const zkRecordDataHash = ("0x" + birthdayHash.toString(16).padStart(64, "0")) as Hex;

  // After ECDSA record is issued, nonce increments to 1
  const zkRequest = createRecordRequest({
    node,
    ensName: ENS_NAME,
    resolver: resolverAddress,
    recordType: ZK_RECORD_TYPE,
    recordDataHash: zkRecordDataHash,
    issuer: zkIssuerAccount.address,
    expires: recordExpires,
    nonce: 1n,
  });

  const zkTypedData = getEIP712TypedData(zkRequest, controllerAddress, 1);
  const zkUserSig = await userAccount.signTypedData({
    domain: zkTypedData.domain as any,
    types: zkTypedData.types as any,
    primaryType: zkTypedData.primaryType as any,
    message: zkTypedData.message as any,
  });

  // Encode Groth16 proof (pi_b inner arrays reversed) + currentDate
  const pA: [bigint, bigint] = [BigInt(zkProofData.pi_a[0]), BigInt(zkProofData.pi_a[1])];
  const pB: [[bigint, bigint], [bigint, bigint]] = [
    [BigInt(zkProofData.pi_b[0][1]), BigInt(zkProofData.pi_b[0][0])],
    [BigInt(zkProofData.pi_b[1][1]), BigInt(zkProofData.pi_b[1][0])],
  ];
  const pC: [bigint, bigint] = [BigInt(zkProofData.pi_c[0]), BigInt(zkProofData.pi_c[1])];

  const zkProofBytes = encodeAbiParameters(
    [
      { type: "uint256[2]", name: "pA" },
      { type: "uint256[2][2]", name: "pB" },
      { type: "uint256[2]", name: "pC" },
      { type: "uint256", name: "currentDate" },
    ],
    [pA, pB, pC, BigInt(currentDateUnix)],
  );

  const zkContentKey = computeContentKey(zkRequest, zkUserSig);
  const zkBundle = createProofBundle(zkRequest, zkUserSig, zkContentKey, zkProofBytes);

  // Create blob URLs for proof bundles
  const ecdsaBlobUrl = URL.createObjectURL(
    new Blob([serializeBundle(ecdsaBundle)], { type: "application/json" }),
  );
  const zkBlobUrl = URL.createObjectURL(
    new Blob([serializeBundle(zkBundle)], { type: "application/json" }),
  );

  // ── Private (selective-disclosure) record preparation — ENSIP-PRIVACY ─────
  // Both are salted so the public hash is not a brute-force oracle, and both are served as
  // REDACTED bundles (recordDataHash omitted, version "1-private"). The on-chain record and
  // contentKey are still derived from the true salted hash; only the public bundle is redacted.

  onProgress(4, TOTAL_STEPS, "Preparing private records...");

  // Email — salted keccak commitment: recordDataHash = keccak256(salt ‖ email).
  const emailSaltBytes = crypto.getRandomValues(new Uint8Array(32));
  const emailSalt = ("0x" +
    Array.from(emailSaltBytes, (b) => b.toString(16).padStart(2, "0")).join("")) as Hex;
  const emailRecordDataHash = saltedKeccakHash(emailSalt, EMAIL_VALUE);

  const emailRequest = createRecordRequest({
    node,
    ensName: ENS_NAME,
    resolver: resolverAddress,
    recordType: EMAIL_RECORD_TYPE,
    recordDataHash: emailRecordDataHash,
    issuer: emailIssuerAccount.address,
    expires: recordExpires,
    nonce: 2n,
  });
  const emailTypedData = getEIP712TypedData(emailRequest, controllerAddress, 1);
  const emailUserSig = await userAccount.signTypedData({
    domain: emailTypedData.domain as any,
    types: emailTypedData.types as any,
    primaryType: emailTypedData.primaryType as any,
    message: emailTypedData.message as any,
  });
  const emailContentKey = computeContentKey(emailRequest, emailUserSig);
  const emailProof = await signECDSAProof(emailIssuerAccount, {
    recordDataHash: emailRecordDataHash,
    issuer: emailIssuerAccount.address,
    chainId: 1,
    verifierContract: ecdsaVerifierAddress,
  });
  const emailRedacted = redactBundle(
    createProofBundle(emailRequest, emailUserSig, emailContentKey, emailProof),
  );
  const emailBlobUrl = blobUrl(JSON.stringify(emailRedacted));

  // Private age — reuse the salted Poseidon commitment + Groth16 proof from the ZK record,
  // under a distinct private issuer serving a REDACTED bundle. The proof only attests the
  // public signals [birthdayHash, isAdult, currentDate], so it is issuer/nonce-independent.
  const ageRequest = createRecordRequest({
    node,
    ensName: ENS_NAME,
    resolver: resolverAddress,
    recordType: PRIVATE_AGE_RECORD_TYPE,
    recordDataHash: zkRecordDataHash,
    issuer: privateAgeIssuerAccount.address,
    expires: recordExpires,
    nonce: 3n,
  });
  const ageTypedData = getEIP712TypedData(ageRequest, controllerAddress, 1);
  const ageUserSig = await userAccount.signTypedData({
    domain: ageTypedData.domain as any,
    types: ageTypedData.types as any,
    primaryType: ageTypedData.primaryType as any,
    message: ageTypedData.message as any,
  });
  const ageContentKey = computeContentKey(ageRequest, ageUserSig);
  // The salted birthdayHash is safe to publish, so the ZK age record serves a FULL bundle:
  // the public can verify the "age ≥ 18" predicate proof while the birthday itself stays hidden
  // (it is never in the bundle). Selective disclosure then reveals the *exact* birthday to a
  // specific vendor. This is the key contrast with the email record, whose value is fully hidden.
  const ageFullBundle = createProofBundle(
    ageRequest,
    ageUserSig,
    ageContentKey,
    zkProofBytes,
  );
  const ageBlobUrl = blobUrl(serializeBundle(ageFullBundle));

  // ── Step 5: Register issuers (with real blob URLs) ───────────────────────

  onProgress(5, TOTAL_STEPS, "Registering issuers...");

  await call({
    from: daoAccount.address,
    to: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "registerIssuer",
    args: [
      ecdsaIssuerAccount.address,
      "ECDSA Demo Issuer",
      1n,
      issuerExpires,
      ecdsaVerifierAddress,
      ecdsaBlobUrl,
    ],
  });

  await call({
    from: daoAccount.address,
    to: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "registerIssuer",
    args: [
      zkIssuerAccount.address,
      "ZK Demo Issuer",
      2n,
      issuerExpires,
      zkVerifierAddress,
      zkBlobUrl,
    ],
  });

  await call({
    from: daoAccount.address,
    to: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "registerIssuer",
    args: [
      emailIssuerAccount.address,
      "Email Demo Issuer (private)",
      4n,
      issuerExpires,
      ecdsaVerifierAddress,
      emailBlobUrl,
    ],
  });

  await call({
    from: daoAccount.address,
    to: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "registerIssuer",
    args: [
      privateAgeIssuerAccount.address,
      "Age Demo Issuer (private)",
      8n,
      issuerExpires,
      zkVerifierAddress,
      ageBlobUrl,
    ],
  });

  // ── Step 6: Issue records on-chain ───────────────────────────────────────

  onProgress(6, TOTAL_STEPS, "Issuing records on-chain...");

  await call({
    from: ecdsaIssuerAccount.address,
    to: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "issueRecord",
    args: [
      {
        node: ecdsaRequest.node,
        ensName: ecdsaRequest.ensName,
        resolver: ecdsaRequest.resolver,
        recordType: ecdsaRequest.recordType,
        recordDataHash: ecdsaRequest.recordDataHash,
        issuer: ecdsaRequest.issuer,
        expires: ecdsaRequest.expires,
        nonce: ecdsaRequest.nonce,
      },
      ecdsaUserSig,
    ],
  });

  await call({
    from: zkIssuerAccount.address,
    to: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "issueRecord",
    args: [
      {
        node: zkRequest.node,
        ensName: zkRequest.ensName,
        resolver: zkRequest.resolver,
        recordType: zkRequest.recordType,
        recordDataHash: zkRequest.recordDataHash,
        issuer: zkRequest.issuer,
        expires: zkRequest.expires,
        nonce: zkRequest.nonce,
      },
      zkUserSig,
    ],
  });

  await call({
    from: emailIssuerAccount.address,
    to: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "issueRecord",
    args: [
      {
        node: emailRequest.node,
        ensName: emailRequest.ensName,
        resolver: emailRequest.resolver,
        recordType: emailRequest.recordType,
        recordDataHash: emailRequest.recordDataHash,
        issuer: emailRequest.issuer,
        expires: emailRequest.expires,
        nonce: emailRequest.nonce,
      },
      emailUserSig,
    ],
  });

  await call({
    from: privateAgeIssuerAccount.address,
    to: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "issueRecord",
    args: [
      {
        node: ageRequest.node,
        ensName: ageRequest.ensName,
        resolver: ageRequest.resolver,
        recordType: ageRequest.recordType,
        recordDataHash: ageRequest.recordDataHash,
        issuer: ageRequest.issuer,
        expires: ageRequest.expires,
        nonce: ageRequest.nonce,
      },
      ageUserSig,
    ],
  });

  // ── Step 7: Done ─────────────────────────────────────────────────────────

  onProgress(7, TOTAL_STEPS, "Setup complete!");

  const config: DemoConfig = {
    registryAddress,
    controllerAddress,
    resolverAddress,
    ensRegistryAddress,
    userAddress: userAccount.address,
    ensName: ENS_NAME,
    node,
    chainId: 1,
    issuers: [
      {
        address: ecdsaIssuerAccount.address,
        recordType: ECDSA_RECORD_TYPE,
        type: "ecdsa",
        label: "ECDSA Issuer",
      },
      {
        address: zkIssuerAccount.address,
        recordType: ZK_RECORD_TYPE,
        type: "zk",
        label: "ZK Issuer",
      },
    ],
    privateRecords: [
      {
        type: "email",
        label: "Email (value hidden)",
        recordType: EMAIL_RECORD_TYPE,
        issuerAddress: emailIssuerAccount.address,
        verifierContract: ecdsaVerifierAddress,
        specificationURI: emailBlobUrl,
        recordDataHash: emailRecordDataHash,
        publicModel: "redacted",
        redactedBundle: emailRedacted,
        secret: { kind: "keccak", data: EMAIL_VALUE, salt: emailSalt },
      },
      {
        type: "age",
        label: "Age ≥ 18 (ZK predicate)",
        recordType: PRIVATE_AGE_RECORD_TYPE,
        issuerAddress: privateAgeIssuerAccount.address,
        verifierContract: zkVerifierAddress,
        specificationURI: ageBlobUrl,
        recordDataHash: zkRecordDataHash,
        publicModel: "predicate",
        predicateLabel: "Age ≥ 18",
        secret: {
          kind: "poseidon",
          data: "2000-01-01",
          birthday: ZK_BIRTHDAY,
          saltDecimal: zkSalt,
        },
      },
    ],
    userAccount,
  };

  return { config, client };
}
