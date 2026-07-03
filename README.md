# ENS Verifiable Records

Cryptographically-bound verifiable records for ENS (targeting **ENSv2**). An issuer registry (DAO-governed or community-managed) controls which entities may write records into user resolvers. Records are made tamper-evident and non-transferable by deriving content keys from the user's signature, ENS name, resolver address, record payload, and issuer identity. Proof verification is always on-chain via issuer-registered verifier contracts.

## Specifications

| Document | Scope |
|----------|-------|
| [ENSIP.md](./ENSIP.md) | Base spec: record key/value format, content key derivation, EIP-712 consent, issuance & verification flows, proof bundles, issuer registry. |
| [ENSIP-PRIVACY.md](./ENSIP-PRIVACY.md) | Selective Disclosure extension: salted `recordDataHash`, redacted proof bundles, ZK commitment blinding, off-chain user→vendor disclosure flow. |

## Repository Layout

```
src/            Solidity contracts (controller, registry, verifiers, interfaces)
circuits/       Circom ZK circuits (salted age-verification commitment)
sdk/            TypeScript SDK (@ensverify/sdk) — issuance + verification flows
demo/           End-to-end demo app, including the selective disclosure flow
test/           Foundry test suite
script/         Deployment script
docs/           Supplementary docs (zk-email issuer design)
```

## Architecture

```
Issuer Registry Governance (e.g. ENS DAO)
  └── IssuerRegistry              (on-chain: approved issuers, verifier contracts, specificationURI)
        └── Authorized Issuer      (off-chain: validates identity, signs proof, hosts proof bundle)
              ├── IProofVerifier    (on-chain: verifies proof — ECDSA, ZK, multisig, CCIP-Read)
              └── VerifiableRecordController  (on-chain: derives key, writes resolver)
                    └── User Resolver          (on-chain: stores content key + expiry)
                          └── Verifier          (reads chain + proof bundle, verifies)
```

| Contract | Purpose |
|----------|---------|
| `IssuerRegistry` | Governed whitelist of authorized issuers with bitmap roles, expiry, two-flag pause (issuer self-pause vs irreversible-by-issuer DAO pause), revoke |
| `VerifiableRecordController` | EIP-712 signature validation, content key derivation, resolver text record writes |
| `IProofVerifier` | Standard interface for on-chain proof verification (ECDSA, ZK, multisig, CCIP-Read) |
| `ECDSAProofVerifier` | Reference `IProofVerifier` using domain-bound ECDSA recovery (`recordDataHash, issuer, chainId, verifier`) |
| `ZkAgeVerifier` | `IProofVerifier` adapter for Groth16 age proofs over a **salted** Poseidon commitment (`Poseidon(birthday, salt)`) |
| `Groth16Verifier` | snarkjs-generated Groth16 verifier backing `ZkAgeVerifier` (demo-grade trusted setup — not for production) |
| `IProofBundleProvider` | Optional interface for on-chain proof bundle retrieval (L2 storage proofs via CCIP-Read) |
| `ITextResolver` | Minimal `setText`/`text` resolver interface the controller writes through |

Every issuer MUST register a `verifierContract` that implements `IProofVerifier`. The registry rejects `address(0)`.

Proof bundles (containing the full verification inputs) are hosted at the issuer's `specificationURI` — a URL (`https://`, `ipfs://`, with `{node}`/`{recordType}` template placeholders for per-record addressing) or a contract address implementing `IProofBundleProvider` for on-chain retrieval.

## Content Key Derivation

The content key binds a record to a specific user, name, and resolver — making it non-transferable by construction:

```
contentKey = keccak256(
    userSignature,      // EIP-712 sig from the name owner
    keccak256(ensName), // e.g. "alice.eth"
    resolverAddress,    // user's resolver contract
    recordDataHash,     // keccak256 of the credential payload (salted for private records)
    issuerAddress       // authorized issuer
)
```

Copying a content key to a different resolver or name will fail verification because the recomputed key won't match. The content key does **not** commit to `node` or `recordType` — that binding comes from the user's EIP-712 signature plus the mandatory bundle↔query cross-checks in the verification flow (ENSIP.md §7, step 6).

## Resolver Text Record

The controller writes a single namespaced text record per verifiable record:

```
Key:   vr:{issuerAddress}:{recordType}
Value: {contentKey} {expires}
```

The value is two space-delimited fields:

| Field | Format | Example |
|-------|--------|---------|
| `contentKey` | hex-encoded bytes32 (66 chars) | `0x4f71c5ad...e3694e` |
| `expires` | decimal unix timestamp, `0` = no expiration | `1735689600` or `0` |

No URI is stored in the text record. Verifiers get the proof bundle location from `IssuerRegistry.getIssuer(issuer).specificationURI` — this naturally requires checking issuer status first, which cuts unnecessary proof fetches early if the issuer is revoked/paused/expired.

One `setText` call to write, one `text()` call to read, one clear to revoke.

> **Approval blast radius:** the controller writes via the resolver, so the user must approve it. On ENSv2's `PublicResolverV2`, prefer the per-name `approve(node, controller, true)` over `setApprovalForAll` — and note that either grant covers *all* record profiles on the approved name(s), not just `vr:` keys. See ENSIP.md §11 for the Scoped Operator mitigation.

## Verification Flow

Issuer check is first — if the issuer is revoked, paused, DAO-paused, or expired, skip everything else.

```
Verifier                          Chain                     Proof Bundle Source
   │                                │                            │
   │─── isActiveIssuer(issuer) ────►│                            │
   │◄── false → INVALID, stop ──────│                            │
   │─── getIssuer(issuer) ─────────►│                            │
   │◄── { specURI, verifier, ... } ─│                            │
   │                                │                            │
   │─── text(vr:{issuer}:{type}) ──►│                            │
   │◄── "{contentKey} {expires}" ───│                            │
   │                                │                            │
   │─── fetch proof bundle ─────────┼───────────────────────────►│
   │◄── { request, sig, key, proof }┼────────────────────────────│
   │                                │                            │
   │  1. Parse contentKey, expires  │                            │
   │  2. Check expiration           │                            │
   │  3. Cross-check bundle against │                            │
   │     query: node, ensName,      │                            │
   │     recordType, issuer,        │                            │
   │     resolver, expires          │                            │
   │  4. Recompute contentKey       │                            │
   │     from proof bundle inputs   │                            │
   │                                │                            │
   │─── verifyProof(proof, hash, ──►│                            │
   │    issuer) on verifierContract │                            │
   │◄── true / false ───────────────│                            │
   │                                │                            │
   │  5. Validate EIP-712 signature │                            │
   │                                │                            │
   │─── ENSv2 owner lookup (node) ─►│                            │
   │◄── current owner ──────────────│                            │
   │                                │                            │
   │  6. signature ↔ owner?         │                            │
   │     result: valid / invalid    │                            │
```

Steps (full normative flow in [ENSIP.md §7](./ENSIP.md)):

1. **Check the issuer** via `IssuerRegistry.isActiveIssuer()` — registered, not paused, not DAO-paused, not expired. If inactive, stop. Get `specificationURI` from `getIssuer()`.
2. **Read** the `vr:{issuer}:{type}` text record. Parse content key and expires.
3. **Check expiration** against the current time.
4. **Fetch** the proof bundle from the issuer's `specificationURI`:
   - If URL (`https://`, `ipfs://`): expand `{node}`/`{recordType}` placeholders, fetch JSON (hardened: scheme allowlist, size cap, timeout — see ENSIP.md Security Considerations, "Proof Bundle Fetching").
   - If contract address (`0x...`, 42 chars): call `IProofBundleProvider.getProofBundle(node, recordType)` and ABI-decode. Supports CCIP-Read for L2 storage proofs.
5. **Cross-check** the bundle against the queried record: `request.node`, `namehash(request.ensName)`, `request.recordType`, `request.issuer`, `request.resolver` must match the query, and the **signed** `request.expires` must equal the on-chain value (the on-chain field is owner-writable; the signed one is authoritative).
6. **Recompute** the content key from the proof bundle's public inputs. Must match on-chain.
7. **Verify the proof** by calling `verifierContract.verifyProof(proof, recordDataHash, issuer)` on the issuer's registered verifier contract. This is always on-chain (`view` call, no gas cost for off-chain callers). Supports any verification mechanism: ECDSA recovery, ZK proof verification, multisig, CCIP-Read.
8. **Verify ownership**: resolve the current owner of the queried node through the ENSv2 registry hierarchy, then validate the EIP-712 user signature against it (ECDSA recovery for EOAs, ERC-1271 for contract owners). A mismatch means the record belongs to a previous owner.

If all checks pass, the record is valid.

## Selective Disclosure (Privacy Extension)

For records over low-entropy private data (emails, phone numbers, birthdates), [ENSIP-PRIVACY.md](./ENSIP-PRIVACY.md) adds:

- a mandatory high-entropy per-record **salt** in the `recordDataHash` preimage, so neither the on-chain content key nor the public signature can be brute-forced offline;
- a **redacted public bundle** (`"version": "1-private"`, `recordDataHash: null`) that legacy verifiers deterministically reject;
- an EIP-712 **disclosure signature** binding each off-chain reveal to a specific node, issuer, record type, vendor, and single-use nonce;
- **ZK predicate records** (e.g. "over 18" via `Poseidon(birthday, salt)` + Groth16) that prove properties without revealing values — see `circuits/` and `ZkAgeVerifier`.

The full disclosure flow is implemented in the SDK (`sdk/src/privacy.ts` — salted hashes, redacted bundles, the EIP-712 `Disclosure` signature, vendor-side verification, and the §3 public path); the demo consumes those exports and keeps only the Poseidon commitment helpers and brute-force visualizations.

## SDK

The TypeScript SDK ([`sdk/`](./sdk/README.md), `@ensverify/sdk`) implements the full protocol surface: request building, EIP-712 signing, issuance, proof bundle creation/serialization/hosting helpers, the full verification pipeline (`verifyRecord` — one call), and the selective-disclosure extension (redacted bundles, disclosure signatures, vendor verification). Signed test vectors for both specs are generated by `sdk/gen_vectors.mjs` and cross-verified in `test/TestVectors_t.sol`.

## Build & Test

Contracts (Foundry):

```shell
forge build
forge test
```

SDK:

```shell
cd sdk && yarn install && yarn build && node test_vector.mjs && node test_parsing.mjs && node test_privacy.mjs
```

Circuits (requires circom + snarkjs):

```shell
cd circuits && ./build_salted.sh
```

Demo:

```shell
cd demo && yarn install && yarn dev
```
