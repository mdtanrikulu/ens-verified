/**
 * ENS Verifiable Records — Local Demo Setup
 *
 * Deploys contracts on an Anvil mainnet fork, registers an ENS name,
 * issues two verifiable records (ECDSA + ZK), and writes proof bundles + config.
 *
 * Usage:
 *   anvil --fork-url $FORK_URL          (Terminal 1)
 *   npx tsx setup.ts                    (Terminal 2)
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  http,
  namehash,
  keccak256,
  toHex,
  toBytes,
  getAddress,
  encodeAbiParameters,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";
// @ts-ignore — snarkjs has no types
import * as snarkjs from "snarkjs";

import {
  IssuerRegistryABI,
  VerifiableRecordControllerABI,
  createRecordRequest,
  getEIP712TypedData,
  issueRecord,
  signProof,
  computeContentKey,
  createProofBundle,
} from "@ensverify/sdk";

// ── Paths ────────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, "..");

function readArtifact(contractPath: string) {
  const raw = readFileSync(resolve(ROOT, contractPath), "utf-8");
  const json = JSON.parse(raw);
  return {
    abi: json.abi,
    bytecode: json.bytecode.object as Hex,
  };
}

// ── Constants ────────────────────────────────────────────────────────────────

const RPC_URL = "http://127.0.0.1:8545";
const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e" as Address;
const BASE_REGISTRAR = "0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85" as Address;
const ENS_NAME = "ensverify.eth";

// ECDSA issuer
const ECDSA_RECORD_TYPE = "github";
const ECDSA_CLAIM_PAYLOAD = "github:ensverify";

// ZK issuer
const ZK_RECORD_TYPE = "commitment";
const ZK_SECRET = "42"; // The secret known to the ZK issuer

// Circuit artifacts
const CIRCUIT_WASM = resolve(ROOT, "circuits/build/commitment_js/commitment.wasm");
const CIRCUIT_ZKEY = resolve(ROOT, "circuits/build/commitment_final.zkey");

// Anvil default private keys
const DAO_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const ECDSA_ISSUER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const USER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;
const ZK_ISSUER_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex;

// Minimal ENS registry ABI for setSubnodeOwner / setResolver
const ENSRegistryFullABI = [
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
      { name: "owner", type: "address" },
    ],
    outputs: [{ name: "", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setResolver",
    inputs: [
      { name: "node", type: "bytes32" },
      { name: "resolver", type: "address" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

// ── Clients ──────────────────────────────────────────────────────────────────

const transport = http(RPC_URL);

const publicClient = createPublicClient({
  chain: mainnet,
  transport,
});

const testClient = createTestClient({
  chain: mainnet,
  transport,
  mode: "anvil",
});

const daoAccount = privateKeyToAccount(DAO_KEY);
const ecdsaIssuerAccount = privateKeyToAccount(ECDSA_ISSUER_KEY);
const userAccount = privateKeyToAccount(USER_KEY);
const zkIssuerAccount = privateKeyToAccount(ZK_ISSUER_KEY);

const daoClient = createWalletClient({
  account: daoAccount,
  chain: mainnet,
  transport,
});

const ecdsaIssuerClient = createWalletClient({
  account: ecdsaIssuerAccount,
  chain: mainnet,
  transport,
});

const userClient = createWalletClient({
  account: userAccount,
  chain: mainnet,
  transport,
});

const zkIssuerClient = createWalletClient({
  account: zkIssuerAccount,
  chain: mainnet,
  transport,
});

// ── Helpers ──────────────────────────────────────────────────────────────────

async function deploy(
  artifact: { abi: any; bytecode: Hex },
  args: any[] = [],
  client = daoClient
): Promise<Address> {
  const hash = await client.deployContract({
    abi: artifact.abi,
    bytecode: artifact.bytecode,
    args,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (!receipt.contractAddress) {
    throw new Error(`Deploy failed: no contract address in receipt (tx: ${hash})`);
  }
  return getAddress(receipt.contractAddress);
}

function labelhash(label: string): Hex {
  return keccak256(toBytes(label));
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  ENS Verifiable Records — Local Demo Setup");
  console.log("═══════════════════════════════════════════════════════════\n");

  // Check Anvil is running
  try {
    await publicClient.getBlockNumber();
  } catch {
    console.error("ERROR: Cannot connect to Anvil at", RPC_URL);
    console.error("Start Anvil first:  anvil --fork-url $FORK_URL");
    process.exit(1);
  }

  // ── Step 1: Deploy contracts ───────────────────────────────────────────

  console.log("1. Deploying contracts...");

  const registryArtifact = readArtifact("out/IssuerRegistry.sol/IssuerRegistry.json");
  const controllerArtifact = readArtifact("out/VerifiableRecordController.sol/VerifiableRecordController.json");
  const resolverArtifact = readArtifact("out/MockResolver.sol/MockResolver.json");
  const ecdsaVerifierArtifact = readArtifact("out/ECDSAProofVerifier.sol/ECDSAProofVerifier.json");
  const groth16Artifact = readArtifact("out/Groth16Verifier.sol/Groth16Verifier.json");
  const zkVerifierArtifact = readArtifact("out/ZkCommitmentVerifier.sol/ZkCommitmentVerifier.json");

  const registryAddress = await deploy(registryArtifact);
  console.log(`   IssuerRegistry:             ${registryAddress}`);

  const controllerAddress = await deploy(controllerArtifact, [registryAddress]);
  console.log(`   VerifiableRecordController: ${controllerAddress}`);

  const resolverAddress = await deploy(resolverArtifact);
  console.log(`   MockResolver:               ${resolverAddress}`);

  const ecdsaVerifierAddress = await deploy(ecdsaVerifierArtifact);
  console.log(`   ECDSAProofVerifier:         ${ecdsaVerifierAddress}`);

  const groth16Address = await deploy(groth16Artifact);
  console.log(`   Groth16Verifier:            ${groth16Address}`);

  const zkVerifierAddress = await deploy(zkVerifierArtifact, [groth16Address]);
  console.log(`   ZkCommitmentVerifier:       ${zkVerifierAddress}`);

  // ── Step 2: Register issuers ─────────────────────────────────────────

  console.log("\n2. Registering issuers...");

  const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
  const oneYear = 365n * 24n * 60n * 60n;
  const issuerExpires = nowSeconds + oneYear;

  // ECDSA issuer
  const registerEcdsaHash = await daoClient.writeContract({
    address: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "registerIssuer",
    args: [
      ecdsaIssuerAccount.address,
      "ECDSA Demo Issuer",
      1n,
      issuerExpires,
      ecdsaVerifierAddress,
      "http://localhost:5173/ecdsa-proof-bundle.json",
    ],
  });
  await publicClient.waitForTransactionReceipt({ hash: registerEcdsaHash });
  console.log(`   ECDSA Issuer: ${ecdsaIssuerAccount.address}`);

  // ZK issuer
  const registerZkHash = await daoClient.writeContract({
    address: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "registerIssuer",
    args: [
      zkIssuerAccount.address,
      "ZK Demo Issuer",
      2n,
      issuerExpires,
      zkVerifierAddress,
      "http://localhost:5173/zk-proof-bundle.json",
    ],
  });
  await publicClient.waitForTransactionReceipt({ hash: registerZkHash });
  console.log(`   ZK Issuer:    ${zkIssuerAccount.address}`);

  // ── Step 3: Register ENS name on fork ──────────────────────────────────

  console.log("\n3. Registering ENS name on fork...");

  const node = namehash(ENS_NAME);
  const ethNode = namehash("eth");
  const label = labelhash("ensverify");

  await testClient.impersonateAccount({ address: BASE_REGISTRAR });
  await testClient.setBalance({ address: BASE_REGISTRAR, value: 10n ** 18n });

  const impersonatedRegistrar = createWalletClient({
    account: BASE_REGISTRAR,
    chain: mainnet,
    transport,
  });

  const subnodeHash = await impersonatedRegistrar.writeContract({
    address: ENS_REGISTRY,
    abi: ENSRegistryFullABI,
    functionName: "setSubnodeOwner",
    args: [ethNode, label, userAccount.address],
  });
  await publicClient.waitForTransactionReceipt({ hash: subnodeHash });
  await testClient.stopImpersonatingAccount({ address: BASE_REGISTRAR });

  const setResolverHash = await userClient.writeContract({
    address: ENS_REGISTRY,
    abi: ENSRegistryFullABI,
    functionName: "setResolver",
    args: [node, resolverAddress],
  });
  await publicClient.waitForTransactionReceipt({ hash: setResolverHash });

  const owner = await publicClient.readContract({
    address: ENS_REGISTRY,
    abi: ENSRegistryFullABI,
    functionName: "owner",
    args: [node],
  });
  console.log(`   ${ENS_NAME} owner: ${owner}`);
  console.log(`   Resolver set to:  ${resolverAddress}`);

  // ── Step 4: Issue ECDSA record ────────────────────────────────────────

  console.log("\n4. Issuing ECDSA record...");

  const ecdsaRecordDataHash = keccak256(toHex(toBytes(ECDSA_CLAIM_PAYLOAD)));
  const recordExpires = nowSeconds + oneYear;

  const ecdsaNonce = await publicClient.readContract({
    address: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "nonces",
    args: [userAccount.address],
  });

  const ecdsaRequest = createRecordRequest({
    node,
    ensName: ENS_NAME,
    resolver: resolverAddress,
    recordType: ECDSA_RECORD_TYPE,
    recordDataHash: ecdsaRecordDataHash,
    issuer: ecdsaIssuerAccount.address,
    expires: recordExpires,
    nonce: ecdsaNonce,
  });

  const ecdsaTypedData = getEIP712TypedData(ecdsaRequest, controllerAddress, 1);
  const ecdsaUserSig = await userClient.signTypedData({
    domain: ecdsaTypedData.domain,
    types: ecdsaTypedData.types,
    primaryType: ecdsaTypedData.primaryType,
    message: ecdsaTypedData.message,
  });

  const ecdsaIssueTxHash = await issueRecord(
    ecdsaIssuerClient,
    controllerAddress,
    ecdsaRequest,
    ecdsaUserSig,
  );
  await publicClient.waitForTransactionReceipt({ hash: ecdsaIssueTxHash });
  console.log(`   ECDSA record issued (tx: ${ecdsaIssueTxHash.slice(0, 18)}...)`);

  // ── Step 5: Generate ZK proof + issue ZK record ───────────────────────

  console.log("\n5. Generating ZK proof and issuing ZK record...");

  // Generate Groth16 proof: proves knowledge of secret where Poseidon(secret) == commitment
  const { proof: zkProofData, publicSignals } = await snarkjs.groth16.fullProve(
    { secret: ZK_SECRET },
    CIRCUIT_WASM,
    CIRCUIT_ZKEY,
  );
  const commitment = BigInt(publicSignals[0]);
  console.log(`   Poseidon commitment: ${commitment}`);

  // Verify proof locally before proceeding
  const vkey = JSON.parse(readFileSync(resolve(ROOT, "circuits/build/verification_key.json"), "utf-8"));
  const localValid = await snarkjs.groth16.verify(vkey, publicSignals, zkProofData);
  console.log(`   Local proof verification: ${localValid ? "PASS" : "FAIL"}`);
  if (!localValid) throw new Error("ZK proof failed local verification");

  // The commitment (Poseidon hash) becomes our recordDataHash
  const zkRecordDataHash = ("0x" + commitment.toString(16).padStart(64, "0")) as Hex;

  const zkNonce = await publicClient.readContract({
    address: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "nonces",
    args: [userAccount.address],
  });

  const zkRequest = createRecordRequest({
    node,
    ensName: ENS_NAME,
    resolver: resolverAddress,
    recordType: ZK_RECORD_TYPE,
    recordDataHash: zkRecordDataHash,
    issuer: zkIssuerAccount.address,
    expires: recordExpires,
    nonce: zkNonce,
  });

  const zkTypedData = getEIP712TypedData(zkRequest, controllerAddress, 1);
  const zkUserSig = await userClient.signTypedData({
    domain: zkTypedData.domain,
    types: zkTypedData.types,
    primaryType: zkTypedData.primaryType,
    message: zkTypedData.message,
  });

  const zkIssueTxHash = await issueRecord(
    zkIssuerClient,
    controllerAddress,
    zkRequest,
    zkUserSig,
  );
  await publicClient.waitForTransactionReceipt({ hash: zkIssueTxHash });
  console.log(`   ZK record issued (tx: ${zkIssueTxHash.slice(0, 18)}...)`);

  // ── Step 6: Create proof bundles ─────────────────────────────────────

  console.log("\n6. Creating proof bundles...");

  mkdirSync(resolve(__dirname, "public"), { recursive: true });

  // ECDSA proof bundle
  const ecdsaContentKey = computeContentKey(ecdsaRequest, ecdsaUserSig);
  const ecdsaProof = await signProof(ecdsaIssuerClient, ecdsaRecordDataHash);
  const ecdsaBundle = createProofBundle(ecdsaRequest, ecdsaUserSig, ecdsaContentKey, ecdsaProof);

  writeFileSync(
    resolve(__dirname, "public", "ecdsa-proof-bundle.json"),
    JSON.stringify({
      request: {
        ...ecdsaBundle.request,
        expires: ecdsaBundle.request.expires.toString(),
        nonce: ecdsaBundle.request.nonce.toString(),
      },
      userSignature: ecdsaBundle.userSignature,
      contentKey: ecdsaBundle.contentKey,
      proof: ecdsaBundle.proof,
    }, null, 2),
  );
  console.log("   Written: public/ecdsa-proof-bundle.json");

  // ZK proof bundle — encode Groth16 proof as ABI bytes
  // IMPORTANT: snarkjs pi_b inner arrays must be reversed for Solidity
  const pA: [bigint, bigint] = [
    BigInt(zkProofData.pi_a[0]),
    BigInt(zkProofData.pi_a[1]),
  ];
  const pB: [[bigint, bigint], [bigint, bigint]] = [
    [BigInt(zkProofData.pi_b[0][1]), BigInt(zkProofData.pi_b[0][0])],
    [BigInt(zkProofData.pi_b[1][1]), BigInt(zkProofData.pi_b[1][0])],
  ];
  const pC: [bigint, bigint] = [
    BigInt(zkProofData.pi_c[0]),
    BigInt(zkProofData.pi_c[1]),
  ];

  const zkProofBytes = encodeAbiParameters(
    [
      { type: "uint256[2]", name: "pA" },
      { type: "uint256[2][2]", name: "pB" },
      { type: "uint256[2]", name: "pC" },
    ],
    [pA, pB, pC],
  );

  const zkContentKey = computeContentKey(zkRequest, zkUserSig);
  const zkBundle = createProofBundle(zkRequest, zkUserSig, zkContentKey, zkProofBytes);

  writeFileSync(
    resolve(__dirname, "public", "zk-proof-bundle.json"),
    JSON.stringify({
      request: {
        ...zkBundle.request,
        expires: zkBundle.request.expires.toString(),
        nonce: zkBundle.request.nonce.toString(),
      },
      userSignature: zkBundle.userSignature,
      contentKey: zkBundle.contentKey,
      proof: zkBundle.proof,
    }, null, 2),
  );
  console.log("   Written: public/zk-proof-bundle.json");

  // ── Step 7: Write config.json ────────────────────────────────────────

  console.log("\n7. Writing config...");

  const config = {
    registryAddress,
    controllerAddress,
    resolverAddress,
    ensRegistryAddress: ENS_REGISTRY,
    userAddress: userAccount.address,
    ensName: ENS_NAME,
    node,
    chainId: 1,
    rpcUrl: RPC_URL,
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
  };

  writeFileSync(
    resolve(__dirname, "src", "config.json"),
    JSON.stringify(config, null, 2),
  );
  console.log("   Written to src/config.json");

  // ── Summary ────────────────────────────────────────────────────────────

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  Setup Complete!");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`
  Contracts:
    IssuerRegistry:             ${registryAddress}
    VerifiableRecordController: ${controllerAddress}
    MockResolver:               ${resolverAddress}
    ECDSAProofVerifier:         ${ecdsaVerifierAddress}
    Groth16Verifier:            ${groth16Address}
    ZkCommitmentVerifier:       ${zkVerifierAddress}

  Actors:
    DAO:           ${daoAccount.address}
    ECDSA Issuer:  ${ecdsaIssuerAccount.address}
    ZK Issuer:     ${zkIssuerAccount.address}
    User:          ${userAccount.address}

  Records:
    ECDSA: vr:${ecdsaIssuerAccount.address}:${ECDSA_RECORD_TYPE}
    ZK:    vr:${zkIssuerAccount.address}:${ZK_RECORD_TYPE}

  ENS Name: ${ENS_NAME}
  Node:     ${node}

  Next steps:
    npm run dev          → http://localhost:5173
`);
}

main().catch((err) => {
  console.error("\nSetup failed:", err);
  process.exit(1);
});
