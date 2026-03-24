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

## Resolver Text Record

The controller writes a single namespaced text record per verifiable record:

```
Key:   vr:{issuerAddress}:{recordType}
Value: {contentKey} {expires} {contentURI}
```

The value is three space-delimited fields:

| Field | Format | Example |
|-------|--------|---------|
| `contentKey` | hex-encoded bytes32 (66 chars) | `0x4f71c5ad...e3694e` |
| `expires` | decimal unix timestamp, `0` = no expiration | `1735689600` or `0` |
| `contentURI` | IPFS CID or HTTPS URL | `ipfs://QmTest` |

Expiry is optional — issuers set `expires = 0` for records that don't expire. Verifiers treat `0` as "valid indefinitely".

One `setText` call to write, one `text()` call to read, one clear to revoke.

## Verification Flows

### Off-chain verification (recommended)

No transaction required. The verifier reads on-chain state and verifies the proof locally.

```
Verifier                          Chain                     Issuer Storage
   │                                │                            │
   │─── resolve ENS name ──────────►│                            │
   │◄── resolver address ───────────│                            │
   │                                │                            │
   │─── text(vr:{issuer}:{type}) ──►│                            │
   │◄── "{contentKey} {exp} {uri}" ─│                            │
   │                                │                            │
   │─── fetch proof + credential ───┼───────────────────────────►│
   │◄── { attestation, payload } ───┼────────────────────────────│
   │                                │                            │
   │  ┌─────────────────────────────┤                            │
   │  │ 1. Parse contentKey,        │                            │
   │  │    expires, contentURI      │                            │
   │  │    from the text value.     │                            │
   │  │                             │                            │
   │  │ 2. Recompute contentKey     │                            │
   │  │    from public inputs.      │                            │
   │  │    Must match on-chain key. │                            │
   │  │                             │                            │
   │  │ 3. Verify proof:            │                            │
   │  │    ECDSA ► ecrecover        │                            │
   │  │      locally (free).        │                            │
   │  │    ZK ► call issuer's       │                            │
   │  │      verifier contract      │                            │
   │  │      (view call, no gas).   │                            │
   │  │                             │                            │
   │  │ 4. Check issuer status:     │                            │
   │  │    isActiveIssuer() on      │                            │
   │  │    IssuerRegistry           │                            │
   │  │    (view call, no gas).     │                            │
   │  │                             │                            │
   │  │ 5. Check expires against    │                            │
   │  │    current time.            │                            │
   │  └─────────────────────────────┤                            │
   │                                │                            │
   │  result: valid / invalid       │                            │
```

Steps:

1. **Resolve** the ENS name via the Universal Resolver to get the resolver address.
2. **Read** the `vr:{issuer}:{type}` text record. Parse the three space-delimited fields: content key, expires, content URI.
3. **Fetch** the full credential and proof from the content URI.
4. **Recompute** the content key from the fetched data's public inputs (user signature, ENS name, resolver address, record data hash, issuer address). It must match the on-chain content key.
5. **Verify the proof:**
   - ECDSA attestation: recover the signer from the attestation signature and confirm it matches the issuer address. This is pure cryptography — no gas cost.
   - ZK proof: call the issuer's registered verifier contract with the proof and public inputs. This is a `view` call — no gas cost.
6. **Check issuer status** by calling `IssuerRegistry.isActiveIssuer()` — a `view` call.
7. **Check expiration** against the current time.

If all checks pass, the record is valid.

### On-chain verification

For smart contracts that need to verify a record within a transaction (e.g. gating access, conditional logic).

```
Calling Contract                  Controller    Resolver    IssuerRegistry
   │                                  │             │              │
   │─── text(vr:{issuer}:{type}) ─────┼────────────►│              │
   │◄── "{key} {exp} {uri}" ──────────┼─────────────│              │
   │                                  │             │              │
   │─── verifyContentKey() ──────────►│             │              │
   │    (contentKey, request, sig)    │             │              │
   │◄── true / false ─────────────────│             │              │
   │                                  │             │              │
   │─── isActiveIssuer() ─────────────┼─────────────┼─────────────►│
   │◄── true / false ─────────────────┼─────────────┼──────────────│
   │                                  │             │              │
   │  ┌───────────────────────────────┤             │              │
   │  │ Parse contentKey from value.  │             │              │
   │  │ Compare with recomputed key.  │             │              │
   │  │ If equal + issuer active      │             │              │
   │  │ + not expired → valid.        │             │              │
   │  └───────────────────────────────┤             │              │
```

Steps:

1. **Read** the `vr:{issuer}:{type}` text record from the resolver. Parse the space-delimited value to extract content key, expiration, and content URI.
2. **Recompute** the content key by calling `VerifiableRecordController.computeContentKey(request, userSignature)` with the known public inputs. Compare it to the parsed value — they must match.
3. **Check issuer status** by calling `IssuerRegistry.isActiveIssuer(issuer)`.
4. **Check expiration** against `block.timestamp`.

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
