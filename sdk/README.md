# @ensverify/sdk

TypeScript SDK for ENS Verifiable Records. Issue, verify, and revoke third-party attestations stored as ENS text records.

## Install

```bash
npm install @ensverify/sdk viem
```

## Addresses

```ts
const CONTROLLER = "0x...";  // VerifiableRecordController
const REGISTRY = "0x...";    // IssuerRegistry
const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"; // ENS Registry (mainnet)
```

---

## Issuing a Record

Three parties involved: the **user** (ENS name owner) signs consent, the **issuer** (registered in IssuerRegistry) submits the tx.

### 1. User signs the request

```ts
import { createRecordRequest, getEIP712TypedData } from "@ensverify/sdk";
import { namehash } from "viem/ens";

// Build the request
const request = createRecordRequest({
  node: namehash("alice.eth"),
  ensName: "alice.eth",
  resolver: "0x...",         // alice.eth's resolver
  recordType: "identity",
  recordDataHash: keccak256(toHex(toBytes("credential-payload"))),
  issuer: "0x...",           // issuer address
  expires: BigInt(Math.floor(Date.now() / 1000) + 365 * 86400), // 1 year
  nonce: 0n,                 // fetch from controller.nonces(userAddress)
});

// Get EIP-712 typed data for wallet signing
const typedData = getEIP712TypedData(request, CONTROLLER, 1); // chainId = 1

// User signs with their wallet (e.g. via wagmi/viem)
const userSignature = await walletClient.signTypedData(typedData);
```

### 2. Issuer submits the tx

```ts
import { issueRecord } from "@ensverify/sdk";

// Issuer's wallet submits — msg.sender must be request.issuer
const txHash = await issueRecord(issuerWalletClient, CONTROLLER, request, userSignature);
```

### 3. Issuer creates and hosts proof bundle

```ts
import { createProofBundle, signAttestation, computeContentKey } from "@ensverify/sdk";

// Issuer signs the attestation
const attestation = await signAttestation(issuerWalletClient, request.recordDataHash);

// Build the proof bundle
const contentKey = computeContentKey(request, userSignature);
const bundle = createProofBundle(request, userSignature, contentKey, attestation, "https://issuer.example/proofs/alice");

// Host this JSON at the issuer's specificationURI (registered in IssuerRegistry)
await uploadToStorage(JSON.stringify(bundle));
```

---

## Verifying a Record

One call does everything: checks issuer status first (fail fast), then resolves the record, fetches the proof, verifies the content key, and confirms the signer is still the name owner.

### Full pipeline

```ts
import { verifyRecord } from "@ensverify/sdk";

const result = await verifyRecord(publicClient, {
  resolverAddress: "0x...",      // alice.eth's resolver
  registryAddress: REGISTRY,     // IssuerRegistry
  ensRegistryAddress: ENS_REGISTRY,
  controllerAddress: CONTROLLER,
  chainId: 1,
  node: namehash("alice.eth"),
  issuer: "0x...",
  recordType: "identity",
});

console.log(result);
// {
//   valid: true,              // all checks passed
//   issuerActive: true,       // issuer is registered, active, not expired
//   contentKeyMatch: true,    // on-chain key matches recomputed key
//   attestationValid: true,   // proof bundle has attestation data
//   signerIsOwner: true,      // EIP-712 signer == current ENS name owner
//   expired: false,           // record hasn't expired
// }
```

### Verification order (why it matters)

```
1. issuerActive?     --> NO  --> return early, skip everything
2. get specURI       --> from IssuerRegistry.getIssuer()
3. resolve record    --> read text record from resolver
4. parse + expiry    --> "{contentKey} {expires}"
5. fetch proof       --> from issuer's specificationURI
6. contentKey match  --> recompute locally, compare to on-chain
7. attestation       --> structural check (mode-specific verification is delegated)
8. signer == owner   --> recover EIP-712 signer, compare to ENS registry owner
```

The issuer check is first because if the issuer got revoked/paused/expired, there's no point fetching proofs or doing crypto. Saves bandwidth and compute.

### Step-by-step (if you need granular control)

```ts
import {
  checkIssuerStatus,
  getIssuerInfo,
  resolveRecord,
  parseRecordValue,
  fetchProofBundle,
  verifyContentKey,
  recoverRecordSigner,
  getNodeOwner,
} from "@ensverify/sdk";

// 1. Is the issuer legit?
const active = await checkIssuerStatus(publicClient, REGISTRY, issuerAddress);
if (!active) throw new Error("Issuer not active");

// 2. Where are the proofs?
const issuerInfo = await getIssuerInfo(publicClient, REGISTRY, issuerAddress);
const proofURI = issuerInfo.specificationURI;

// 3. What's on-chain?
const raw = await resolveRecord(publicClient, resolverAddress, node, issuerAddress, "identity");
const { contentKey, expires } = parseRecordValue(raw);

// 4. Fetch and verify proof
const bundle = await fetchProofBundle(proofURI);
const keyMatch = verifyContentKey(bundle.request, bundle.userSignature, contentKey);

// 5. Is the signer still the owner?
const signer = await recoverRecordSigner(bundle.request, bundle.userSignature, CONTROLLER, 1);
const owner = await getNodeOwner(publicClient, ENS_REGISTRY, node);
const ownerMatch = signer.toLowerCase() === owner.toLowerCase();
```

---

## Revoking a Record

Only the original issuer can revoke.

```ts
import { revokeRecord } from "@ensverify/sdk";

const txHash = await revokeRecord(issuerWalletClient, CONTROLLER, namehash("alice.eth"), "identity");
```

---

## Utilities

```ts
import { computeContentKey, buildRecordKey, validateProofBundle } from "@ensverify/sdk";

// Compute content key (matches Solidity exactly)
const key = computeContentKey(request, userSignature);

// Build the text record key
const recordKey = buildRecordKey(issuerAddress, "identity");
// => "vr:0x1234...abcd:identity"

// Validate proof bundle structure
const { valid, errors } = validateProofBundle(bundle);
```

---

## What's on-chain vs off-chain

| Data | Where | Why |
|------|-------|-----|
| `contentKey` + `expires` | ENS text record | Minimal on-chain footprint. The content key is the cryptographic anchor. |
| Proof bundle | Issuer's `specificationURI` | Full attestation data. Too expensive to store on-chain. |
| Issuer info + proof URI | IssuerRegistry | DAO-governed. Verifier queries this first. |
| User's EIP-712 signature | Proof bundle (off-chain) | Proves user consent. Used to recompute content key. |

---

## Exports

### Types

| Type | Description |
|------|-------------|
| `RecordRequest` | Mirrors the Solidity struct — all fields for an issuance request |
| `ProofBundle` | Off-chain proof data fetched from issuer's specificationURI |
| `ParsedRecordValue` | Parsed on-chain text record: `{ contentKey, expires }` |
| `IssuerInfo` | Issuer metadata from the registry |
| `VerificationResult` | Granular pass/fail for each verification step |

### Issuer Functions

| Function | Description |
|----------|-------------|
| `createRecordRequest(params)` | Build a `RecordRequest` from inputs |
| `getEIP712TypedData(request, controller, chainId)` | Get typed data for wallet signing |
| `issueRecord(client, controller, request, sig)` | Submit issuance tx |
| `signAttestation(client, data)` | Sign attestation data for proof bundle |
| `revokeRecord(client, controller, node, type)` | Revoke a record |

### Verifier Functions

| Function | Description |
|----------|-------------|
| `verifyRecord(client, params)` | Full verification pipeline (one call) |
| `checkIssuerStatus(client, registry, issuer)` | Is issuer active? |
| `getIssuerInfo(client, registry, issuer)` | Get issuer metadata + specificationURI |
| `resolveRecord(client, resolver, node, issuer, type)` | Read text record from resolver |
| `parseRecordValue(raw)` | Parse `"{contentKey} {expires}"` |
| `fetchProofBundle(uri)` | Fetch + parse proof bundle JSON |
| `verifyContentKey(request, sig, expected)` | Recompute content key, compare |
| `recoverRecordSigner(request, sig, controller, chainId)` | Recover EIP-712 signer address |
| `getNodeOwner(client, ensRegistry, node)` | Get current ENS name owner |

### Utility Functions

| Function | Description |
|----------|-------------|
| `computeContentKey(request, sig)` | Replicate Solidity content key derivation |
| `buildRecordKey(issuer, type)` | Build text record key `vr:{issuer}:{type}` |
| `createProofBundle(...)` | Assemble a proof bundle object |
| `validateProofBundle(bundle)` | Validate structural integrity |

### ABIs

| Export | Description |
|--------|-------------|
| `VerifiableRecordControllerABI` | Controller contract ABI |
| `IssuerRegistryABI` | Registry contract ABI |
| `ENSRegistryABI` | ENS Registry (owner lookup) |
| `TextResolverABI` | Resolver text record ABI |
