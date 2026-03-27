# ENS Verifiable Records

Cryptographically-bound verifiable records for ENS. A DAO-governed issuer registry controls which entities may write records into user resolvers. Records are made tamper-evident and non-transferable by deriving content keys from the user's signature, ENS name, resolver address, record payload, and issuer identity. Proof verification is always on-chain via issuer-registered verifier contracts.

## Architecture

```
ENS DAO
  └── IssuerRegistry              (on-chain: approved issuers, verifier contracts, specificationURI)
        └── Authorized Issuer      (off-chain: validates identity, signs proof, hosts proof bundle)
              ├── IProofVerifier    (on-chain: verifies proof — ECDSA, ZK, multisig, CCIP-Read)
              └── VerifiableRecordController  (on-chain: derives key, writes resolver)
                    └── User Resolver          (on-chain: stores content key + expiry)
                          └── Verifier          (reads chain + proof bundle, verifies)
```

| Contract | Purpose |
|----------|---------|
| `IssuerRegistry` | DAO-governed whitelist of authorized issuers with bitmap roles, expiry, pause/revoke |
| `VerifiableRecordController` | EIP-712 signature validation, content key derivation, resolver text record writes |
| `IProofVerifier` | Standard interface for on-chain proof verification (ECDSA, ZK, multisig, CCIP-Read) |
| `ECDSAProofVerifier` | Reference `IProofVerifier` implementation using ECDSA signature recovery |
| `IProofBundleProvider` | Optional interface for on-chain proof bundle retrieval (L2 storage proofs via CCIP-Read) |

Every issuer MUST register a `verifierContract` that implements `IProofVerifier`. The registry rejects `address(0)`.

Proof bundles (containing the full verification inputs) are hosted at the issuer's `specificationURI` — either a URL (`https://`, `ipfs://`) or a contract address implementing `IProofBundleProvider` for on-chain retrieval.

## Content Key Derivation

The content key binds a record to a specific user, name, and resolver — making it non-transferable by construction:

```
contentKey = keccak256(
    userSignature,      // EIP-712 sig from the name owner
    keccak256(ensName), // e.g. "alice.eth"
    resolverAddress,    // user's resolver contract
    recordDataHash,     // keccak256 of the credential payload
    issuerAddress       // authorized issuer
)
```

Copying a content key to a different resolver or name will fail verification because the recomputed key won't match.

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

## Verification Flow

Issuer check is first — if the issuer is revoked/paused/expired, skip everything else.

```
Verifier                          Chain                     Proof Bundle Source
   │                                │                            │
   │─── getIssuer(issuer) ─────────►│                            │
   │◄── { active, specURI, ... } ───│                            │
   │    (if !active → INVALID)      │                            │
   │                                │                            │
   │─── text(vr:{issuer}:{type}) ──►│                            │
   │◄── "{contentKey} {expires}" ───│                            │
   │                                │                            │
   │─── fetch proof bundle ─────────┼───────────────────────────►│
   │◄── { request, sig, key, proof }┼────────────────────────────│
   │                                │                            │
   │  1. Parse contentKey, expires  │                            │
   │  2. Check expiration           │                            │
   │  3. Recompute contentKey       │                            │
   │     from proof bundle inputs   │                            │
   │                                │                            │
   │─── verifyProof(proof, hash, ──►│                            │
   │    issuer) on verifierContract │                            │
   │◄── true / false ───────────────│                            │
   │                                │                            │
   │  4. Recover EIP-712 signer     │                            │
   │                                │                            │
   │─── ENSRegistry.owner(node) ───►│                            │
   │◄── current owner ──────────────│                            │
   │                                │                            │
   │  5. signer == owner?           │                            │
   │     result: valid / invalid    │                            │
```

Steps:

1. **Get issuer info** from `IssuerRegistry.getIssuer()`. If null or `!active`, stop.
2. **Read** the `vr:{issuer}:{type}` text record. Parse content key and expires.
3. **Check expiration** against the current time.
4. **Fetch** the proof bundle from the issuer's `specificationURI`:
   - If URL (`https://`, `ipfs://`): fetch JSON document.
   - If contract address (`0x...`, 42 chars): call `IProofBundleProvider.getProofBundle(node, recordType)` and ABI-decode. Supports CCIP-Read for L2 storage proofs.
5. **Recompute** the content key from the proof bundle's public inputs. Must match on-chain.
6. **Verify the proof** by calling `verifierContract.verifyProof(proof, recordDataHash, issuer)` on the issuer's registered verifier contract. This is always on-chain (`view` call, no gas cost for off-chain callers). Supports any verification mechanism: ECDSA recovery, ZK proof verification, multisig, CCIP-Read.
7. **Recover the EIP-712 signer** from the user signature. Compare against `ENSRegistry.owner(node)` to ensure the record belongs to the current name owner.

If all checks pass, the record is valid.

## Build

```shell
forge build
```

## Test

```shell
forge test
```
