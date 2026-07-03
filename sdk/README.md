# @ensverify/sdk

TypeScript SDK for ENS Verifiable Records. Issue, verify, and revoke third-party verifiable records stored as ENS text records.

## Install

```bash
npm install @ensverify/sdk viem
```

## Addresses

```ts
const CONTROLLER = "0x...";  // VerifiableRecordController
const REGISTRY = "0x...";    // IssuerRegistry
const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"; // ENS Registry (mainnet, v1 interface)
```

> **Ownership lookups and ENSv2:** `getNodeOwner` (and the owner check inside `verifyRecord`)
> calls the ENSv1-compatible `owner(node)` interface at `ensRegistryAddress`. Under ENSv2,
> canonical ownership is resolved by traversing the registry hierarchy (see ENSIP.md §7
> step 10); point `ensRegistryAddress` at a contract exposing `owner(bytes32)` with those
> semantics, or override the check yourself. ERC-1271 contract owners are not yet validated
> by the SDK (ECDSA recovery only — see ENSIP.md, Security Considerations, Contract-Owned Names).

---

## Issuing a Record

Three parties involved: the **user** (ENS name owner) signs consent, the **issuer** (registered in IssuerRegistry) submits the tx.

### 1. User signs the request

```ts
import { createRecordRequest, getEIP712TypedData } from "@ensverify/sdk";
import { keccak256, stringToBytes } from "viem";
import { namehash } from "viem/ens";

// Build the request
const request = createRecordRequest({
  node: namehash("alice.eth"),
  ensName: "alice.eth",
  resolver: "0x...",         // alice.eth's resolver
  recordType: "identity",
  // stringToBytes, not toBytes: viem's toBytes would hex-decode a payload
  // (or ENS name) that happens to start with "0x".
  recordDataHash: keccak256(stringToBytes("credential-payload")),
  issuer: "0x...",           // issuer address
  expires: BigInt(Math.floor(Date.now() / 1000) + 365 * 86400), // 1 year
  nonce: 0n,                 // fetch from controller.nonces(userAddress, node) — scoped per (signer, node)
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
import { createProofBundle, serializeProofBundle, signECDSAProof, computeContentKey } from "@ensverify/sdk";

// Issuer signs a domain-bound preimage for the reference ECDSAProofVerifier:
//   keccak256(abi.encode(recordDataHash, issuer, chainId, verifierContract))
// wrapped in EIP-191 personal_sign. The domain binding prevents this proof
// from being reused with a different verifier or on another chain.
const proof = await signECDSAProof(issuerWalletClient, {
  recordDataHash: request.recordDataHash,
  issuer: request.issuer,
  chainId,
  verifierContract: ECDSA_VERIFIER_ADDRESS,
});

// Build the proof bundle
const contentKey = computeContentKey(request, userSignature);
const bundle = createProofBundle(request, userSignature, contentKey, proof);

// Host this JSON at the issuer's specificationURI (registered in IssuerRegistry).
// serializeProofBundle emits the canonical ENSIP §8 document: `"version": "1"` with
// expires/nonce as decimal strings (plain JSON.stringify would throw on the bigints).
await uploadToStorage(serializeProofBundle(bundle));
```

> `signRawDigest` is a low-level `personal_sign` primitive (no domain binding) for callers
> targeting a custom `IProofVerifier` with its own signed preimage — it is NOT a ready-made
> proof. Use `signECDSAProof` for the reference verifier; it builds the domain-bound digest
> (recordDataHash, issuer, chainId, verifier contract) for you and accepts a viem `WalletClient`
> or `Account`.

The proof bundle lives at the issuer's `specificationURI` registered in `IssuerRegistry` — either a URL (`https://`, `ipfs://`) or a contract address implementing `IProofBundleProvider` for on-chain retrieval. Verifiers get that URI from the registry — it's never stored in the text record.

---

## Verifying a Record

One call does everything: checks issuer status first (fail fast), then resolves the record, fetches the proof, cross-checks the bundle against the queried record, verifies the content key, and confirms the signer is still the name owner.

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
//   bundleMatchesQuery: true, // bundle request fields match the queried record
//   contentKeyMatch: true,    // on-chain key matches recomputed key
//   proofValid: true,          // proof bundle has valid proof data
//   signerIsOwner: true,      // EIP-712 signer == current ENS name owner
//   expired: false,           // record hasn't expired
// }
```

### Verification order (why it matters)

```
1. getIssuer()       --> null, !active, or expired --> return early, skip everything
2. resolve record    --> read text record from resolver
3. parse + expiry    --> "{contentKey} {expires}"
4. fetch proof       --> from issuer's specificationURI, after expanding {node}/{recordType}
                         URI-template placeholders (URL) or via IProofBundleProvider (contract)
5. cross-check       --> bundle.request node/ensName/recordType/issuer/resolver/expires
                         must match the queried record (ENSIP.md §7 step 6)
6. contentKey match  --> recompute locally, compare to on-chain
7. proof             --> call verifierContract.verifyProof() on-chain (ECDSA, ZK, etc.)
8. signer == owner   --> recover EIP-712 signer, compare to current name owner
```

`getIssuer()` is always the first call — if the issuer is not registered, inactive, or expired, there's no point fetching proofs or doing crypto. One RPC call gives you the status and the `specificationURI`.

The cross-check in step 5 is load-bearing: the content key doesn't commit to `node` or `recordType`, so without it a bundle for a *different* record owned by the same signer would verify. The signed `request.expires` is also compared against the on-chain value here — the on-chain field is owner-writable, the signed one is authoritative.

### Step-by-step (if you need granular control)

```ts
import {
  getIssuerInfo,
  resolveRecord,
  parseRecordValue,
  expandSpecificationURI,
  fetchProofBundle,
  verifyContentKey,
  recoverRecordSigner,
  getNodeOwner,
} from "@ensverify/sdk";
import { namehash } from "viem/ens";

// 1. Is the issuer legit? One call — gives status + specificationURI.
//    Mirror on-chain isActiveIssuer: registered, active AND not expired.
const now = BigInt(Math.floor(Date.now() / 1000));
const issuerInfo = await getIssuerInfo(publicClient, REGISTRY, issuerAddress);
if (!issuerInfo || !issuerInfo.active || issuerInfo.expires <= now) {
  throw new Error("Issuer not active");
}

// 2–3. What's on-chain?
const raw = await resolveRecord(publicClient, resolverAddress, node, issuerAddress, "identity");
const { contentKey, expires } = parseRecordValue(raw);

// 4. Fetch the bundle — expand per-record {node}/{recordType} placeholders first.
//    Built-in transport (https/ipfs/ar/blob, hardened):
const proofURI = expandSpecificationURI(issuerInfo.specificationURI, node, "identity");
const bundle = await fetchProofBundle(proofURI);
//    …or bring your own transport (no SDK network): you fetch, the SDK validates:
//    const bundle = parseProofBundle(await myClient.get(proofURI));
//    …or let verifyRecord do it via params.fetchBundle for full control.

// 5. Cross-check the bundle against what you queried (ENSIP.md §7 step 6) — without
//    this, a bundle for a different record of the same signer verifies circularly.
//    The signed request.expires is authoritative over the owner-writable on-chain value.
const bound =
  bundle.request.node === node &&
  namehash(bundle.request.ensName) === node &&
  bundle.request.recordType === "identity" &&
  bundle.request.issuer.toLowerCase() === issuerAddress.toLowerCase() &&
  bundle.request.resolver.toLowerCase() === resolverAddress.toLowerCase() &&
  bundle.request.expires === expires;
if (!bound) throw new Error("Bundle does not match the queried record");

// 6. Content key
const keyMatch = verifyContentKey(bundle.request, bundle.userSignature, contentKey);

// 8. Is the signer still the owner? (recoverRecordSigner enforces canonical low-s sigs)
const signer = await recoverRecordSigner(bundle.request, bundle.userSignature, CONTROLLER, 1);
const owner = await getNodeOwner(publicClient, ENS_REGISTRY, node);
const ownerMatch = signer.toLowerCase() === owner.toLowerCase();
// (step 7, the on-chain verifyProof call, omitted here — see verifyRecord for the full set)
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
| Proof bundle | Issuer's `specificationURI` (URL or `IProofBundleProvider` contract) | Full proof data. Fetched via HTTP/IPFS or on-chain via CCIP-Read. |
| Issuer info + `specificationURI` | IssuerRegistry | DAO-governed. Verifier queries this first to get proof bundle location. |
| User's EIP-712 signature | Proof bundle (off-chain) | Proves user consent. Used to recompute content key. |

---

## Exports

### Types

| Type | Description |
|------|-------------|
| `RecordRequest` | Mirrors the Solidity struct — all fields for an issuance request |
| `ProofBundle` | Proof data fetched from issuer's specificationURI (URL or on-chain provider) |
| `ParsedRecordValue` | Parsed on-chain text record: `{ contentKey, expires }` |
| `IssuerInfo` | Issuer metadata from the registry |
| `VerificationResult` | Granular pass/fail for each verification step (incl. `bundleMatchesQuery`) |
| `Disclosure` | The EIP-712 disclosure struct (§5): node, issuer, recordType, nonce, vendor, vendorIdentity, expires |
| `RedactedProofBundle` | `"1-private"` bundle with `recordDataHash: null` (§2) |
| `DisclosureNonceStore` | Vendor-supplied single-use nonce store (atomic consume) |
| `VerifyDisclosureParams` / `DisclosureVerificationResult` | Inputs/outputs of `verifyDisclosure` |
| `PublicPrivateRecordParams` / `PublicPrivateRecordResult` | Inputs/outputs of `verifyPrivateRecordPublic` |

### Issuer Functions

| Function | Description |
|----------|-------------|
| `createRecordRequest(params)` | Build a `RecordRequest` from inputs |
| `getEIP712TypedData(request, controller, chainId)` | Get typed data for wallet signing |
| `issueRecord(client, controller, request, sig)` | Submit issuance tx |
| `signECDSAProof(signer, {recordDataHash, issuer, chainId, verifierContract})` | Sign a domain-bound proof for the reference `ECDSAProofVerifier` |
| `signRawDigest(client, digest)` | Low-level `personal_sign` of a raw digest (custom verifiers; not a ready-made proof) |
| `revokeRecord(client, controller, node, type)` | Revoke a record |

### Verifier Functions

| Function | Description |
|----------|-------------|
| `verifyRecord(client, params)` | Full verification pipeline (one call) |
| `getIssuerInfo(client, registry, issuer)` | Get issuer metadata, status, and specificationURI |
| `resolveRecord(client, resolver, node, issuer, type)` | Read text record from resolver |
| `parseRecordValue(raw)` | Parse `"{contentKey} {expires}"` |
| `parseProofBundle(json)` | Validate + parse already-fetched bundle JSON (no network — bring your own transport) |
| `fetchProofBundle(uri, opts?)` | Built-in convenience transport: fetch + `parseProofBundle`. `opts`: `{ fetchImpl, ipfsGateway, arGateway }` |
| `fetchBundleJson(uri, opts?)` | The hardened raw-JSON transport behind `fetchProofBundle` (no schema validation) — also used for redacted bundles |
| `verifyContentKey(request, sig, expected)` | Recompute content key, compare |
| `recoverRecordSigner(request, sig, controller, chainId)` | Recover EIP-712 signer address (rejects non-canonical signatures) |
| `getNodeOwner(client, ensRegistry, node)` | Get current ENS name owner (`owner(node)` interface — see the ENSv2 note above) |

### Utility Functions

| Function | Description |
|----------|-------------|
| `computeContentKey(request, sig)` | Replicate Solidity content key derivation |
| `buildRecordKey(issuer, type)` | Build text record key `vr:{issuer}:{type}` |
| `createProofBundle(...)` | Assemble a proof bundle object |
| `serializeProofBundle(bundle)` | Canonical ENSIP §8 JSON document (`"version": "1"`, decimal `expires`/`nonce`) — inverse of `parseProofBundle` |
| `validateProofBundle(bundle)` | Validate structural integrity |
| `assertValidRecordType(type)` | Throw unless the record type matches `^[a-z0-9_]+$` (mirrors the contract check) |
| `expandSpecificationURI(uri, node, type)` | Expand `{node}`/`{recordType}` per-record URI template placeholders (ENSIP.md §8) |
| `checkCanonicalSignature(sig)` | Returns an error string unless sig is 65-byte, low-`s` (EIP-2), `v ∈ {27,28}` — what the contract enforces via OpenZeppelin ECDSA |
| `assertCanonicalSignature(sig)` | Throwing form of `checkCanonicalSignature` |

### ABIs

| Export | Description |
|--------|-------------|
| `VerifiableRecordControllerABI` | Controller contract ABI |
| `IssuerRegistryABI` | Registry contract ABI |
| `ProofVerifierABI` | `IProofVerifier` interface ABI |
| `ProofBundleProviderABI` | `IProofBundleProvider` interface ABI |
| `ENSRegistryABI` | ENS Registry (owner lookup) |
| `TextResolverABI` | Resolver text record ABI |

---

## Selective Disclosure (ENSIP-PRIVACY)

The privacy extension ([ENSIP-PRIVACY.md](../ENSIP-PRIVACY.md)) is implemented in the `privacy` module.

### Issuer side — salted hash + redacted bundle

```ts
import { saltedKeccakHash, randomBytes32, redactProofBundle } from "@ensverify/sdk";

const salt = randomBytes32();                            // §1: fresh per issuance, CSPRNG
const recordDataHash = saltedKeccakHash(salt, "alice@example.com"); // keccak256(salt ‖ utf8(data))
// ...issue the record with this recordDataHash as usual, deliver `salt` to the user
// confidentially, do NOT retain it (§ Salt and Issuer Storage)...

const redacted = redactProofBundle(bundle);              // §2: version "1-private", recordDataHash: null
// host `redacted` at the specificationURI instead of the full bundle
```

For ZK-committed records (`Poseidon(value, salt)`), compute the commitment with your circuit
tooling — the SDK deliberately doesn't ship circomlibjs; pass a `computeRecordDataHash`
override to `verifyDisclosure` (see below).

### User side — signing a disclosure

```ts
import { getDisclosureTypedData } from "@ensverify/sdk";

// From the vendor's challenge: nonce (32 bytes), vendor addr and/or vendorIdentity, expires.
const typed = getDisclosureTypedData(
  { node, issuer, recordType: "email", nonce, vendor, vendorIdentity, expires },
  CONTROLLER, 1
);
const disclosureSignature = await walletClient.signTypedData(typed);
// send { data, salt, disclosureSignature } to the vendor over an authenticated,
// confidential channel (§4)
```

### Vendor side — full §4 verification

```ts
import { verifyDisclosure } from "@ensverify/sdk";

const result = await verifyDisclosure(publicClient, {
  disclosure, disclosureSignature,
  data: "alice@example.com", salt,
  challenge: { nonce, node, issuer, recordType: "email", vendor, vendorIdentity, expires },
  nonceStore,                      // your linearizable single-use store (atomic consume)
  registryAddress: REGISTRY, resolverAddress, ensRegistryAddress: ENS_REGISTRY,
  controllerAddress: CONTROLLER, chainId: 1,
});
// result: { valid, signer, signerIsOwner, nonceValid, scopeValid, expiryValid,
//           recordDataHash, verification (full base §7 result), nonceConsumed }
```

The `nonceStore` you supply MUST implement `consume(nonce)` as one atomic compare-and-set
against a store that is linearizable across every instance that can accept a disclosure —
the spec's TOCTOU requirement (§4 steps 3.2/3.9) cannot be provided by a client library.

### Public path (no disclosure)

```ts
import { verifyPrivateRecordPublic } from "@ensverify/sdk";

const pub = await verifyPrivateRecordPublic(publicClient, {
  registryAddress, resolverAddress, node, issuer, recordType,
});
// pub.published === true means: "the issuer published a matching, non-expired redacted
// bundle for this record" — NOT that the current owner holds the attestation (§3).
// Label it unconfirmed / disclosure-required.
```

On-chain providers signal private records with `recordDataHash == bytes32(0)`
(`PRIVATE_RECORD_SENTINEL`); `verifyRecord` refuses the public path for them automatically.
`parseProofBundle`/`validateProofBundle` still reject redacted bundles — that is the
correct legacy-verifier behavior; use `parseRedactedProofBundle` for `"1-private"` bundles.

### Privacy exports

| Function | Description |
|----------|-------------|
| `saltedKeccakHash(salt, data)` | §1 salted-keccak commitment (strings = UTF-8 text; pass Hex/Uint8Array for raw bytes) |
| `randomBytes32()` | CSPRNG 32-byte value (salts, vendor nonces) |
| `redactProofBundle(bundle)` | Full bundle → `"1-private"` redacted bundle (§2) |
| `parseRedactedProofBundle(json)` | Validate + parse a redacted bundle (throws on §2 rule violations) |
| `completeRedactedBundle(redacted, hash)` | Vendor step 3.7: reinsert the reconstructed `recordDataHash` |
| `getDisclosureTypedData(disclosure, controller, chainId)` | EIP-712 typed data for the §5 `Disclosure` struct |
| `recoverDisclosureSigner(disclosure, sig, controller, chainId)` | Recover the disclosure signer (canonical low-s enforced) |
| `verifyDisclosure(client, params)` | Vendor-side §4 step-3 verification, end to end |
| `verifyPrivateRecordPublic(client, params)` | §3 public verification (issuer-published signal only) |
| `PRIVATE_RECORD_SENTINEL` | `bytes32(0)` — §7 on-chain private-record marker |

---

## Tests & Test Vectors

```bash
yarn build              # tsc → dist/
node test_vector.mjs    # ENSIP.md §4 content-key vector (recomputed from scratch)
node test_parsing.mjs   # record value / record key parsing (§2–§3)
node test_privacy.mjs   # salted hash, §2 redaction rules, disclosure sig roundtrip,
                        # low-s guard, serialize/parse roundtrip, sentinel
```

`gen_vectors.mjs` regenerates the **signed EIP-712 test vectors** published in ENSIP.md §5
and ENSIP-PRIVACY.md §5 (private key `0x…01`, controller `0x4242…42`, chainId 1). It
self-checks every manual hash against viem's `hashTypedData`, and the repository's
`test/TestVectors_t.sol` re-verifies the same values with raw Solidity `abi.encode` +
`ecrecover` + the reference controller. Regenerate and re-paste whenever any signed payload
(struct, typehash, domain) changes.
