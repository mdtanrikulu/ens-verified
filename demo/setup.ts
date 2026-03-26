/**
 * ENS Verifiable Records — Local Demo Setup
 *
 * Deploys contracts on an Anvil mainnet fork, registers an ENS name,
 * issues a verifiable record, and writes the proof bundle + config for the frontend.
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
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";

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
const RECORD_TYPE = "github";
const CLAIM_PAYLOAD = "github:ensverify";

// Anvil default private keys
const DAO_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const ISSUER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const USER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;

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
const issuerAccount = privateKeyToAccount(ISSUER_KEY);
const userAccount = privateKeyToAccount(USER_KEY);

const daoClient = createWalletClient({
  account: daoAccount,
  chain: mainnet,
  transport,
});

const issuerClient = createWalletClient({
  account: issuerAccount,
  chain: mainnet,
  transport,
});

const userClient = createWalletClient({
  account: userAccount,
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
  const verifierArtifact = readArtifact("out/ECDSAProofVerifier.sol/ECDSAProofVerifier.json");

  const registryAddress = await deploy(registryArtifact);
  console.log(`   IssuerRegistry:             ${registryAddress}`);

  const controllerAddress = await deploy(controllerArtifact, [registryAddress]);
  console.log(`   VerifiableRecordController: ${controllerAddress}`);

  const resolverAddress = await deploy(resolverArtifact);
  console.log(`   MockResolver:               ${resolverAddress}`);

  const verifierAddress = await deploy(verifierArtifact);
  console.log(`   ECDSAProofVerifier:         ${verifierAddress}`);

  // ── Step 2: Register issuer ────────────────────────────────────────────

  console.log("\n2. Registering issuer...");

  const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
  const oneYear = 365n * 24n * 60n * 60n;
  const issuerExpires = nowSeconds + oneYear;

  const registerHash = await daoClient.writeContract({
    address: registryAddress,
    abi: IssuerRegistryABI,
    functionName: "registerIssuer",
    args: [
      issuerAccount.address,
      "Demo Issuer",
      1n,                                                    // supportedRecordTypes
      issuerExpires,                                         // expires
      verifierAddress,                                       // verifierContract
      "http://localhost:5173/proof-bundle.json",             // specificationURI
    ],
  });
  await publicClient.waitForTransactionReceipt({ hash: registerHash });
  console.log(`   Issuer registered: ${issuerAccount.address}`);

  // ── Step 3: Register ENS name on fork ──────────────────────────────────

  console.log("\n3. Registering ENS name on fork...");

  const node = namehash(ENS_NAME);
  const ethNode = namehash("eth");
  const label = labelhash("ensverify");

  // Impersonate the base registrar to assign the name
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

  // Set resolver
  const setResolverHash = await userClient.writeContract({
    address: ENS_REGISTRY,
    abi: ENSRegistryFullABI,
    functionName: "setResolver",
    args: [node, resolverAddress],
  });
  await publicClient.waitForTransactionReceipt({ hash: setResolverHash });

  // Verify ownership
  const owner = await publicClient.readContract({
    address: ENS_REGISTRY,
    abi: ENSRegistryFullABI,
    functionName: "owner",
    args: [node],
  });
  console.log(`   ${ENS_NAME} owner: ${owner}`);
  console.log(`   Resolver set to:  ${resolverAddress}`);

  // ── Step 4: Issue record ───────────────────────────────────────────────

  console.log("\n4. Issuing verifiable record...");

  const recordDataHash = keccak256(toHex(toBytes(CLAIM_PAYLOAD)));

  // Read nonce from controller
  const nonce = await publicClient.readContract({
    address: controllerAddress,
    abi: VerifiableRecordControllerABI,
    functionName: "nonces",
    args: [userAccount.address],
  });

  const recordExpires = nowSeconds + oneYear;

  const request = createRecordRequest({
    node,
    ensName: ENS_NAME,
    resolver: resolverAddress,
    recordType: RECORD_TYPE,
    recordDataHash,
    issuer: issuerAccount.address,
    expires: recordExpires,
    nonce,
  });

  // User signs consent via EIP-712
  const typedData = getEIP712TypedData(request, controllerAddress, 1);
  const userSignature = await userClient.signTypedData({
    domain: typedData.domain,
    types: typedData.types,
    primaryType: typedData.primaryType,
    message: typedData.message,
  });

  // Issuer submits the record on-chain
  const issueTxHash = await issueRecord(
    issuerClient,
    controllerAddress,
    request,
    userSignature
  );
  await publicClient.waitForTransactionReceipt({ hash: issueTxHash });
  console.log(`   Record issued (tx: ${issueTxHash.slice(0, 18)}...)`);

  // ── Step 5: Create proof bundle ────────────────────────────────────────

  console.log("\n5. Creating proof bundle...");

  const contentKey = computeContentKey(request, userSignature);
  const proof = await signProof(issuerClient, recordDataHash);
  const bundle = createProofBundle(request, userSignature, contentKey, proof);

  // Serialize bigints to strings for JSON
  const serializedBundle = {
    request: {
      ...bundle.request,
      expires: bundle.request.expires.toString(),
      nonce: bundle.request.nonce.toString(),
    },
    userSignature: bundle.userSignature,
    contentKey: bundle.contentKey,
    proof: bundle.proof,
  };

  mkdirSync(resolve(__dirname, "public"), { recursive: true });
  writeFileSync(
    resolve(__dirname, "public", "proof-bundle.json"),
    JSON.stringify(serializedBundle, null, 2)
  );
  console.log("   Written to public/proof-bundle.json");

  // ── Step 6: Write config.json ──────────────────────────────────────────

  console.log("\n6. Writing config...");

  const config = {
    registryAddress,
    controllerAddress,
    resolverAddress,
    ensRegistryAddress: ENS_REGISTRY,
    issuerAddress: issuerAccount.address,
    userAddress: userAccount.address,
    ensName: ENS_NAME,
    node,
    recordType: RECORD_TYPE,
    chainId: 1,
    rpcUrl: RPC_URL,
  };

  writeFileSync(
    resolve(__dirname, "src", "config.json"),
    JSON.stringify(config, null, 2)
  );
  console.log("   Written to src/config.json");

  // ── Summary ────────────────────────────────────────────────────────────

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  Setup Complete!");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`
  Addresses:
    IssuerRegistry:             ${registryAddress}
    VerifiableRecordController: ${controllerAddress}
    MockResolver:               ${resolverAddress}
    ENS Registry:               ${ENS_REGISTRY}

  Actors:
    DAO:    ${daoAccount.address}
    Issuer: ${issuerAccount.address}
    User:   ${userAccount.address}

  ENS Name: ${ENS_NAME}
  Node:     ${node}
  Record:   ${RECORD_TYPE} → ${CLAIM_PAYLOAD}

  Next steps:
    npm run dev          → http://localhost:5173
`);
}

main().catch((err) => {
  console.error("\nSetup failed:", err);
  process.exit(1);
});
