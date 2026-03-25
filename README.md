# ENS Verifiable Records

Cryptographically-bound verifiable records for ENS v2. A DAO-governed issuer registry controls which entities may write records into user resolvers. Records are made tamper-evident and non-transferable by deriving content keys from the user's signature, ENS name, resolver address, record payload, and issuer identity.

## Architecture

```
ENS DAO
  └── IssuerRegistry          (on-chain: approved issuers, specificationURI for proof bundles)
        └── Authorized Issuer  (off-chain: validates identity, signs attestation, hosts proof bundle)
              └── VerifiableRecordController  (on-chain: derives key, writes resolver)
                    └── User Resolver          (on-chain: stores content key + expiry)
                          └── Verifier          (off-chain: resolves, fetches, verifies)
```

Two on-chain contracts, everything else is off-chain:

| Contract | Purpose |
|----------|---------|
| `IssuerRegistry` | DAO-governed whitelist of authorized issuers with bitmap roles, expiry, pause/revoke |
| `VerifiableRecordController` | EIP-712 signature validation, content key derivation, resolver text record writes |

Proofs (ECDSA attestations, ZK proofs) are stored off-chain by the issuer at their `specificationURI` (registered in IssuerRegistry). Verifiers query the registry for the URI, then fetch and verify independently.

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

Expiry is optional — issuers set `expires = 0` for records that don't expire. Verifiers treat `0` as "valid indefinitely".

One `setText` call to write, one `text()` call to read, one clear to revoke.

## Verification Flows

### Off-chain verification (recommended)

No transaction required. The verifier reads on-chain state and verifies the proof locally. Issuer check is first — if the issuer is revoked/paused/expired, skip everything else.

```
Verifier                          Chain                     Issuer Storage
   │                                │                            │
   │─── getIssuer(issuer) ─────────►│                            │
   │◄── { active, specURI, ... } ───│                            │
   │    (if null or !active         │                            │
   │     → return early)            │                            │
   │                                │                            │
   │─── text(vr:{issuer}:{type}) ──►│                            │
   │◄── "{contentKey} {expires}" ───│                            │
   │                                │                            │
   │─── fetch proof bundle ─────────┼───────────────────────────►│
   │◄── { request, sig, key, att } ─┼────────────────────────────│
   │                                │                            │
   │  ┌─────────────────────────────┤                            │
   │  │ 1. Parse contentKey,        │                            │
   │  │    expires from text value. │                            │
   │  │                             │                            │
   │  │ 2. Check expiration.        │                            │
   │  │                             │                            │
   │  │ 3. Recompute contentKey     │                            │
   │  │    from proof bundle.       │                            │
   │  │    Must match on-chain key. │                            │
   │  │                             │                            │
   │  │ 4. Verify attestation.      │                            │
   │  │                             │                            │
   │  │ 5. Recover EIP-712 signer   │                            │
   │  │    from user signature.     │                            │
   │  │    Must match current ENS   │                            │
   │  │    name owner.              │                            │
   │  └─────────────────────────────┤                            │
   │                                │                            │
   │─── ENSRegistry.owner(node) ───►│                            │
   │◄── current owner ──────────────│                            │
   │                                │                            │
   │  result: valid / invalid       │                            │
```

Steps:

1. **Get issuer info** from `IssuerRegistry.getIssuer()`. If null or `!active`, stop — no point fetching proofs. One call gives you status and the `specificationURI` where the proof bundle is hosted.
2. **Read** the `vr:{issuer}:{type}` text record. Parse the two space-delimited fields: content key and expires.
3. **Check expiration** against the current time.
4. **Fetch** the proof bundle from the issuer's `specificationURI`.
5. **Recompute** the content key from the proof bundle's public inputs (user signature, ENS name, resolver address, record data hash, issuer address). It must match the on-chain content key.
6. **Verify the attestation:**
   - ECDSA: recover the signer from the attestation signature and confirm it matches the issuer address. Pure cryptography — no gas cost.
   - ZK: call the issuer's registered verifier contract with the proof and public inputs. A `view` call — no gas cost.
7. **Recover the EIP-712 signer** from the user signature in the proof bundle. Compare against the current ENS name owner via `ENSRegistry.owner(node)`. This protects against stale attestations after name transfers.

If all checks pass, the record is valid.

### On-chain verification

For smart contracts that need to verify a record within a transaction (e.g. gating access, conditional logic).

```
Calling Contract                  Controller    Resolver    IssuerRegistry   ENSRegistry
   │                                  │             │              │              │
   │─── getIssuer(issuer) ────────────┼─────────────┼─────────────►│              │
   │◄── { active, specURI, ... } ────┼─────────────┼──────────────│              │
   │    (if null or !active → revert) │             │              │              │
   │                                  │             │              │              │
   │─── text(vr:{issuer}:{type}) ─────┼────────────►│              │              │
   │◄── "{contentKey} {expires}" ─────┼─────────────│              │              │
   │                                  │             │              │              │
   │─── computeContentKey() ─────────►│             │              │              │
   │    (request, userSignature)      │             │              │              │
   │◄── recomputed key ──────────────│             │              │              │
   │                                  │             │              │              │
   │─── owner(node) ──────────────────┼─────────────┼──────────────┼─────────────►│
   │◄── current owner ────────────────┼─────────────┼──────────────┼──────────────│
   │                                  │             │              │              │
   │  ┌───────────────────────────────┤             │              │              │
   │  │ Parse contentKey from value.  │             │              │              │
   │  │ Compare with recomputed key.  │             │              │              │
   │  │ Recover signer from EIP-712.  │             │              │              │
   │  │ If key match + issuer active  │             │              │              │
   │  │ + signer == owner             │             │              │              │
   │  │ + not expired → valid.        │             │              │              │
   │  └───────────────────────────────┤             │              │              │
```

Steps:

1. **Get issuer info** by calling `IssuerRegistry.getIssuer(issuer)`. If not registered or `!active`, revert early.
2. **Read** the `vr:{issuer}:{type}` text record from the resolver. Parse the two space-delimited fields: content key and expiration.
3. **Check expiration** against `block.timestamp`.
4. **Recompute** the content key by calling `VerifiableRecordController.computeContentKey(request, userSignature)` with the known public inputs. Compare it to the parsed value — they must match.
5. **Verify owner** — recover the EIP-712 signer from the user signature and compare against `ENSRegistry.owner(node)` to ensure the record belongs to the current name owner.

For on-chain verification the calling contract needs access to the original `RecordRequest` and `userSignature`. These can be passed as calldata by the transaction sender, or retrieved from an off-chain source and submitted as part of the transaction. The content key recomputation and comparison is the core integrity check — if it matches the resolver value, the record was legitimately issued.

Note: Full ECDSA attestation verification (signature recovery) can also be done on-chain but requires the attestation signature as calldata. ZK proof verification can be done on-chain by calling the issuer's verifier contract with the proof and public inputs. Both add gas cost proportional to the proof size.

## Build

```shell
forge build
```

## Test

```shell
forge test
```
