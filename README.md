# ENS Verifiable Records

Cryptographically-bound verifiable records for ENS v2. A DAO-governed issuer registry controls which entities may write records into user resolvers. Records are made tamper-evident and non-transferable by deriving content keys from the user's signature, ENS name, resolver address, record payload, and issuer identity.

## Architecture

```
ENS DAO
  └── IssuerRegistry          (on-chain: approved issuers)
        └── Authorized Issuer  (off-chain: validates identity, signs attestation)
              └── VerifiableRecordController  (on-chain: derives key, writes resolver)
                    └── User Resolver          (on-chain: stores content key + URI)
                          └── Verifier          (off-chain: resolves, fetches, verifies)
```

Two on-chain contracts, everything else is off-chain:

| Contract | Purpose |
|----------|---------|
| `IssuerRegistry` | DAO-governed whitelist of authorized issuers with bitmap roles, expiry, pause/revoke |
| `VerifiableRecordController` | EIP-712 signature validation, content key derivation, resolver text record writes |

Proofs (ECDSA attestations, ZK proofs) are stored off-chain by the issuer at the `contentURI`. Verifiers fetch and verify independently.

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

## Resolver Text Records

The controller writes three namespaced text records:

| Key | Value |
|-----|-------|
| `vr:{issuerAddress}:{recordType}` | Content key (hex-encoded bytes32) |
| `vr:{issuerAddress}:{recordType}:uri` | Content URI (IPFS CID or HTTPS URL) |
| `vr:{issuerAddress}:{recordType}:expires` | Expiration timestamp |

## Verification Flows

### Off-chain verification (recommended)

No transaction required. The verifier reads on-chain state and verifies the proof locally.

```
Verifier                          Chain                     Issuer Storage
   │                                │                            │
   │─── resolve ENS name ──────────►│                            │
   │◄── resolver address ───────────│                            │
   │                                │                            │
   │─── read text record ──────────►│                            │
   │    vr:{issuer}:{type}          │                            │
   │◄── contentKey ─────────────────│                            │
   │                                │                            │
   │─── read text record ──────────►│                            │
   │    vr:{issuer}:{type}:uri      │                            │
   │◄── contentURI ─────────────────│                            │
   │                                │                            │
   │─── fetch proof + credential ───┼───────────────────────────►│
   │◄── { attestation, payload } ───┼────────────────────────────│
   │                                │                            │
   │  ┌─────────────────────────────┤                            │
   │  │ 1. Recompute contentKey     │                            │
   │  │    from public inputs.      │                            │
   │  │    Must match on-chain key. │                            │
   │  │                             │                            │
   │  │ 2. Verify proof:            │                            │
   │  │    ECDSA ► ecrecover        │                            │
   │  │      locally (free).        │                            │
   │  │    ZK ► call issuer's       │                            │
   │  │      verifier contract      │                            │
   │  │      (view call, no gas).   │                            │
   │  │                             │                            │
   │  │ 3. Check issuer status:     │                            │
   │  │    isActiveIssuer() on      │                            │
   │  │    IssuerRegistry           │                            │
   │  │    (view call, no gas).     │                            │
   │  │                             │                            │
   │  │ 4. Check expiration from    │                            │
   │  │    text record or payload.  │                            │
   │  └─────────────────────────────┤                            │
   │                                │                            │
   │  result: valid / invalid       │                            │
```

Steps:

1. **Resolve** the ENS name via the Universal Resolver to get the resolver address.
2. **Read** the `vr:{issuer}:{type}` text record to get the content key.
3. **Read** the `vr:{issuer}:{type}:uri` text record to get the content URI.
4. **Fetch** the full credential and proof from the content URI.
5. **Recompute** the content key from the fetched data's public inputs (user signature, ENS name, resolver address, record data hash, issuer address). It must match the on-chain content key.
6. **Verify the proof:**
   - ECDSA attestation: recover the signer from the attestation signature and confirm it matches the issuer address. This is pure cryptography — no gas cost.
   - ZK proof: call the issuer's registered verifier contract with the proof and public inputs. This is a `view` call — no gas cost.
7. **Check issuer status** by calling `IssuerRegistry.isActiveIssuer()` — a `view` call.
8. **Check expiration** from the `:expires` text record or the credential payload.

If all checks pass, the record is valid.

### On-chain verification

For smart contracts that need to verify a record within a transaction (e.g. gating access, conditional logic).

```
Calling Contract                  Controller              IssuerRegistry
   │                                  │                        │
   │─── computeContentKey() ─────────►│                        │
   │◄── contentKey ───────────────────│                        │
   │                                  │                        │
   │─── verifyContentKey() ──────────►│                        │
   │    (contentKey, request, sig)    │                        │
   │◄── true / false ─────────────────│                        │
   │                                  │                        │
   │─── isActiveIssuer() ─────────────┼───────────────────────►│
   │◄── true / false ─────────────────┼────────────────────────│
   │                                  │                        │
   │─── read text() on resolver ──────►                        │
   │◄── contentKey from resolver ──────                        │
   │                                  │                        │
   │  ┌───────────────────────────────┤                        │
   │  │ Compare returned contentKey   │                        │
   │  │ with resolver value.          │                        │
   │  │ If equal + issuer active      │                        │
   │  │ + not expired → valid.        │                        │
   │  └───────────────────────────────┤                        │
```

Steps:

1. **Read** the content key from the resolver's text record `vr:{issuer}:{type}`.
2. **Recompute** the content key by calling `VerifiableRecordController.computeContentKey(request, userSignature)` with the known public inputs. Compare it to the stored value — they must match.
3. **Check issuer status** by calling `IssuerRegistry.isActiveIssuer(issuer)`.
4. **Check expiration** by reading the `:expires` text record or comparing against `block.timestamp`.

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
