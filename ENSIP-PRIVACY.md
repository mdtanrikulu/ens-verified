# ENSIP-TBD: Selective Disclosure for Verifiable Records

| **Author**    | TBD                                              |
|---------------|--------------------------------------------------|
| **Status**    | Draft                                            |
| **Type**      | Standards Track                                  |
| **Created**   | 2026-04-02                                       |
| **Requires**  | ENSIP-TBD (Verifiable Records), EIP-191, EIP-712 |

---

## Abstract

This ENSIP extends Verifiable Records with a selective disclosure mechanism. Users can prove possession of verified private data (e.g., email, phone number) without exposing it on-chain or in public proof bundles. Disclosure happens off-chain, directly between user and vendor, with no issuer involvement at disclosure time.

The extension adds three pieces on top of the base spec:

1. A mandatory per-record 32-byte salt mixed into `recordDataHash`, so that the on-chain `contentKey` and the public `userSignature` cannot be used as offline brute-force oracles against low-entropy data.
2. A redacted public proof bundle that omits `recordDataHash` and is explicitly versioned so legacy verifiers reject it deterministically.
3. An EIP-712 disclosure signature that binds each reveal to a specific node, issuer, record type, vendor, and nonce.

## Motivation

Verifiable Records (ENSIP-TBD) allow issuers to write cryptographically verifiable attestations to ENS names. However, many real-world credentials contain private data that users do not want publicly visible — even in hashed form if the input space is brute-forceable.

A user who has verified their email address with an issuer should be able to:

1. Prove to the public that they have a verified email, without revealing it.
2. Selectively reveal the email to specific vendors who need it.
3. Allow those vendors to cryptographically verify the revealed email is the one the issuer attested to.

This should work without additional on-chain state, without issuer participation at disclosure time, and without the user managing secrets beyond the data itself and a per-record salt issued to them at attestation time.

---

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1. Private Record Data Hash

For records using selective disclosure, the `recordDataHash` MUST be computed with an issuer-generated salt:

```
recordDataHash = keccak256(abi.encodePacked(salt, data))
```

Where:

- `salt` is a 32-byte value chosen uniformly at random by the issuer at issuance time. A fresh salt MUST be generated for each issuance; salts MUST NOT be reused across records, users, or record types.
- `data` is the canonical byte encoding of the private value. The encoding is record-type specific (e.g., UTF-8 for email addresses, E.164 ASCII for phone numbers) and MUST be defined deterministically by the issuer's specification so that vendor and issuer produce the same `recordDataHash` from the same logical value.

The salt is delivered to the user over a confidential channel at issuance time and MUST be persisted by the user alongside the data. Without the salt, no party — including the user — can reconstruct `recordDataHash` and complete a disclosure.

This requirement is independent of how `recordDataHash` is computed. When `recordDataHash` is a zero-knowledge commitment rather than a keccak hash (e.g. a Poseidon commitment used as a circuit's public output), the salt MUST be mixed into the commitment preimage inside the circuit — see "ZK Commitment Blinding" under Security Considerations. A ZK commitment over an unsalted low-entropy value provides proof soundness but NOT preimage confidentiality, and does not satisfy this section.

Implementations MAY derive the salt deterministically from a user-held secret to avoid separate storage. The **KDF-based family below is RECOMMENDED**; the signature-based family carries a correlated-leak hazard and MUST follow the domain-separation rule given here. Two derivation families are recognized:

- **KDF-based (RECOMMENDED)** (e.g., HKDF-SHA-256 seeded by a stable wallet-derived secret and domain-separated per `(issuer, recordType, node)`). Each salt depends on a distinct derivation context, so compromise of one record's salt does not reveal another's. Requires the user to back up the seeding secret.
- **Signature-based** (e.g., `salt = keccak256(userSig)`, where `userSig` signs an EIP-712 message that **itself** commits to `(issuer, recordType, node)` plus a fixed `purpose` string such as `"ENS-salt-v1"`). The signing implementation MUST be RFC-6979 compliant — randomized ECDSA produces a different signature on each invocation and will break reproducibility; non-deterministic wallets MUST NOT be used.
  - The **signed message** MUST be unique per `(issuer, recordType, node)`. A scheme that signs a *fixed* message and then mixes the public tuple in afterward — e.g. `salt = keccak256(userSigOverFixedMsg || issuer || recordType || node)` — MUST NOT be used: because `issuer`, `recordType`, and `node` are all public (they are the on-chain `vr:{issuer}:{recordType}` key plus the namehash), the fixed-message signature is the *only* secret and is shared across every record. A single leak of that one signature lets an attacker derive **every** salt the user holds and re-open the brute-force oracle across their entire portfolio at once.
  - The salt-derivation signature is a long-lived root secret. Wallets MUST NOT reuse the salt-derivation message for any other purpose (login/SIWE, permits, etc.), MUST treat it as non-exportable, and MUST NOT solicit it on behalf of arbitrary dApps. Unlike a stored salt it cannot be rotated without re-issuing every affected record.

Issuers that offer deterministic derivation MUST document the exact scheme so vendors and future wallets can reproduce it.

### 2. Redacted Proof Bundle

The proof bundle served at the issuer's `specificationURI` for a private record MUST:

- Set `"version": "1-private"`.
- Set `"private": true`.
- Set `"recordDataHash": null`.
- Omit any salt or raw data.
- Include all remaining fields required by the base spec (`request.*` excluding `recordDataHash`, `userSignature`, `contentKey`, `proof`).

```json
{
  "version": "1-private",
  "private": true,
  "request": {
    "node": "0x<bytes32>",
    "ensName": "<string>",
    "resolver": "0x<address>",
    "recordType": "<string>",
    "recordDataHash": null,
    "issuer": "0x<address>",
    "expires": "<uint64>",
    "nonce": "<uint256>"
  },
  "userSignature": "0x<hex>",
  "contentKey": "0x<bytes32>",
  "proof": "0x<hex>"
}
```

Privacy-aware verifiers MUST apply the following rejection rules:

- A bundle with `"private": true` AND a non-null `recordDataHash` MUST be rejected.
- A bundle with `"private": true` AND any `version` other than `"1-private"` MUST be rejected.
- A privacy-aware verifier MUST NOT attempt any verification path that requires `recordDataHash` (base spec Section 7, steps 6–8) on a private bundle except via the disclosure flow in Section 4.

The distinct version string (`"1-private"`) gives legacy verifiers a deterministic signal to reject rather than silently coerce `recordDataHash=null` to zero.

### 3. Public Verification (Without Disclosure)

From the on-chain state alone, any party MAY read:

1. A record exists at text key `vr:{issuer}:{recordType}` on the target resolver.
2. The issuer is active in the Issuer Registry.
3. The record has not expired.

**Checks 1–3 are NOT evidence of issuer attestation.** The record lives on a standard ENS resolver, and the name owner can write any text record there directly (the controller is one authorized writer, not the only one — see base spec Section 11). A name owner can therefore `setText("vr:{issuer}:{recordType}", "{arbitrary contentKey} {future expiry}")` with no issuer involvement, and checks 1–3 pass for a record the issuer never issued. For non-private records this fabrication is caught by the content-key, proof, and ownership recomputation in base spec Section 7; the private public-path omits exactly those steps, so that backstop is absent.

To obtain any issuer-attestation signal without disclosure, a privacy-aware public verifier MUST additionally:

4. Fetch the redacted proof bundle for *this* record from the issuer's `specificationURI` (a per-record URI, or `IProofBundleProvider.getProofBundle(node, recordType)`), and apply the Section 2 rejection rules.
5. Confirm `bundle.request.node`, `bundle.request.issuer`, and `bundle.request.recordType` equal the `(node, issuer, recordType)` being verified.
6. Confirm `bundle.contentKey` equals the `contentKey` parsed from the on-chain text value.

Steps 4–6 bind the owner-writable text record to an artifact the issuer actually served, without needing `recordDataHash`: a fabricated record passes 1–3 but fails 4–6 because the issuer never serves a bundle whose `contentKey` matches the forged on-chain value. A record passing 1–3 but failing 4–6 MUST be treated as **unverified** (fabricated or stale), not as an attestation.

Public verifiers MUST NOT claim verification of the content key binding or the issuer's proof for private records — both require `recordDataHash` and therefore disclosure.

The strongest semantic public verification can establish for a private record — even with steps 4–6 — is: **"issuer Y published a non-expired redacted bundle for a record of type X on this name."** It is NOT proof that the *current name owner* holds the attestation (ownership is checkable only via disclosure, below), and it reveals nothing about the underlying data. Any "verified" indicator a relying party derives from public verification MUST be labeled unconfirmed / disclosure-required; an authenticated "this owner currently holds attestation X" statement MUST be obtained through the disclosure flow (Section 4).

Public verifiers also CANNOT perform the name-ownership check (base spec Section 7, step 9) for private records: recovering the `userSignature` signer requires reconstructing the EIP-712 digest, and that digest commits to `recordDataHash`, which is redacted in the public bundle. Name-ownership anchoring is therefore deferred to the disclosure flow (Section 4), where the vendor recomputes `recordDataHash` from the disclosed salt and data and runs the full base verification — including the ownership check — end to end. Callers that need an authenticated "this name owner currently holds an attestation" statement MUST obtain it via disclosure; they MUST NOT infer it from public verification alone.

### 4. Selective Disclosure Flow

All messages between user and vendor MUST travel over a channel that provides both **authentication** and **confidentiality** (e.g., TLS 1.2+ with verified endpoint identity). An authenticated-but-unencrypted channel is explicitly insufficient because the raw `data` and `salt` travel in the clear relative to channel encryption.

#### Step 1: Vendor Challenge

The vendor generates a cryptographically random `nonce` of at least 128 bits (32 bytes RECOMMENDED) and sends it to the user together with:

- the vendor's identity: either a 20-byte Ethereum address, or `address(0)` if the vendor does not authenticate via a wallet,
- an OPTIONAL `expires` Unix timestamp after which the vendor will refuse the disclosure.

The vendor MUST persist issued nonces until the later of: (a) the `expires` timestamp, (b) the nonce is consumed, or (c) 24 hours from issuance. The vendor MUST reject any duplicate nonce. The issued-and-consumed nonce set MUST be held in a store that is **linearizable across every vendor instance that can accept a disclosure**. A vendor serving disclosures from multiple processes or replicas MUST NOT keep nonce state in per-instance memory or an eventually-consistent cache: under weak consistency, the same valid disclosure routed to two instances can pass the not-yet-consumed check on both and be accepted twice (a TOCTOU double-accept — see Section 6).

Vendors handling a high volume of disclosures MAY front the authoritative store with a probabilistic structure (e.g., a bloom filter with collision probability below 2⁻³² per query) combined with TTL eviction, used only at *issuance time* to avoid handing out a colliding nonce; because nonces carry at least 128 bits of entropy, legitimate collisions are cryptographically negligible and a small false-positive rate only causes the vendor to re-issue a nonce, not to accept an invalid disclosure. Such a structure MUST NOT be the sole record of consumption: it cannot distinguish "issued-but-not-consumed" from "never-issued" and offers no atomic consume, so the validity check in Step 3.2 and the consume in Step 3.9 MUST run against the linearizable store, not the filter.

#### Step 2: User Disclosure

The user sends the vendor:

```json
{
  "data": "0x<hex bytes> or <string per record-type encoding>",
  "salt": "0x<bytes32>",
  "disclosureSignature": "0x<hex>"
}
```

Where `disclosureSignature` is an EIP-712 signature as defined in Section 5.

The signature intentionally does NOT cover `data` or `salt` directly: any substitution of those values by an intermediary (on a non-confidential channel) would cause the downstream `recordDataHash` check against the on-chain `contentKey` to fail. Binding them explicitly would also prevent the user from consenting to the disclosure before the raw values are rehydrated locally.

#### Step 3: Vendor Verification

The vendor MUST perform all of the following steps. Failure at any step fails the disclosure.

1. **Verify disclosure signature.** Reconstruct the EIP-712 digest from the fields in Section 5 and recover the signer. The recovered signer MUST equal the current owner of `node` in the ENS registry.
2. **Verify nonce.** The `nonce` in the signed struct MUST equal a nonce the vendor issued and has not previously consumed.
3. **Verify scope.** `issuer`, `recordType`, and `node` MUST match the record being verified. `vendor` MUST equal the vendor's declared identity (or `address(0)` if the vendor did not declare one).
4. **Verify expiry.** If `expires != 0`, the current time MUST be ≤ `expires`.
5. **Compute `recordDataHash`.** `recordDataHash = keccak256(abi.encodePacked(salt, data))` using the disclosed `salt` and `data`.
6. **Fetch the redacted bundle** from the issuer's `specificationURI`. Apply the rejection rules in Section 2.
7. **Complete the bundle** by inserting the computed `recordDataHash`.
8. **Run the base verification flow** (ENSIP-TBD Section 7) end-to-end — including content key recomputation (step 7), issuer proof verification (step 8), and name ownership (step 9). Any failure fails the disclosure.
9. **Mark the nonce consumed** in a single linearizable compare-and-set against the authoritative, strongly-consistent nonce store (e.g. a conditional/transactional write, `SELECT … FOR UPDATE`, or `SET key value NX`), atomically with acceptance of the verification result. The not-yet-consumed check (Step 2) and this consume MUST be one atomic operation against that store, so two concurrent disclosures bearing the same nonce cannot both observe it as unconsumed.

If all steps succeed, the vendor has proof that the issuer attested to exactly this `(data, salt)` pair for the current owner of `node`.

### 5. Disclosure Signature (EIP-712)

The disclosure signature uses EIP-712 to provide explicit domain separation and to bind every security-relevant parameter. EIP-191 personal_sign is deliberately **not** used — see Rationale.

#### Domain Separator

```
EIP712Domain {
    string  name              = "ENS Selective Disclosure"
    string  version           = "1"
    uint256 chainId           = <chain ID of the record's resolver>
    address verifyingContract = <VerifiableRecordController address>
}
```

Tying `verifyingContract` to the deployed `VerifiableRecordController` prevents cross-deployment replay (e.g., testnet disclosure being accepted on mainnet).

#### Primary Type

```solidity
struct Disclosure {
    bytes32 node;        // ENS namehash of the name being disclosed from
    address issuer;      // Record issuer
    string  recordType;  // Record type identifier
    bytes32 nonce;       // Vendor-issued nonce
    address vendor;      // Vendor identity; address(0) if not declared
    uint64  expires;     // Disclosure expiry; 0 = no expiry
}
```

#### Typehash

```
DISCLOSURE_TYPEHASH = keccak256(
    "Disclosure(bytes32 node,address issuer,string recordType,bytes32 nonce,address vendor,uint64 expires)"
)
```

Per EIP-712, `recordType` is encoded as `keccak256(bytes(recordType))` inside the struct hash.

#### Struct Hash

```
structHash = keccak256(abi.encode(
    DISCLOSURE_TYPEHASH,
    disclosure.node,
    disclosure.issuer,
    keccak256(bytes(disclosure.recordType)),
    disclosure.nonce,
    disclosure.vendor,
    disclosure.expires
))
```

The final digest is `keccak256("\x19\x01" || domainSeparator || structHash)`.

### 6. Replay and Misuse Protection

The design provides layered protection:

- **Per-vendor binding.** The `vendor` and `nonce` fields bind each disclosure to a specific vendor interaction. A vendor cannot reuse another vendor's disclosure even if it is intercepted.
- **Per-name binding.** The `node` field disambiguates disclosures for users who own multiple names with the same `(issuer, recordType)`.
- **Single-use nonces.** Vendors MUST reject already-consumed nonces.
- **Expiry.** The OPTIONAL `expires` caps the validity window of the authorization.
- **Ownership anchoring.** Base-spec verification step 9 rejects records whose `userSignature` signer no longer owns the name, so a seller cannot disclose records that belonged to a previous owner.
- **Domain separation.** The EIP-712 domain prevents the disclosure signature from being accepted by any unrelated protocol.

What this does NOT prevent:

- **Vendor collusion.** Two vendors that legitimately receive the raw data can share it out-of-band. Unlinkability across vendors is out of scope.
- **Post-disclosure forwarding of the data.** Any party that later obtains `(data, salt)` can re-run verification against the bundle and learn the same fact. This is inherent to selective disclosure of non-zero-knowledge attestations.
- **Cross-instance double-accept under weak consistency.** The single-use guarantee holds only within the vendor's own consistency boundary. A vendor that consumes nonces against per-instance or eventually-consistent state can accept one disclosure twice; the spec requires a linearizable store (Section 4) but cannot enforce the vendor's infrastructure. For one-shot, non-idempotent side effects (admit-one, single unlock, one-time discount) the vendor remains responsible for end-to-end idempotency beyond nonce single-use.
- **Public-verification fabrication.** Public verification of a private record (Section 3) is not proof of issuer attestation — a name owner can write a passing record directly. Relying parties MUST treat the public path as unconfirmed and require disclosure (Section 4) for any trust decision.

### 7. On-Chain Proof Bundle Provider

When `specificationURI` is an `IProofBundleProvider` contract (base spec Section 8), private records are signaled by returning `recordDataHash == bytes32(0)` in the ABI-encoded response.

This is a safe sentinel because `keccak256` output is statistically indistinguishable from random; the preimage of `bytes32(0)` is not discoverable, so no honest record can legitimately collide with the sentinel.

Verifiers that decode an `IProofBundleProvider` response with `recordDataHash == bytes32(0)` MUST:

- Treat the record as private.
- Refuse public verification paths that consume `recordDataHash`.
- Proceed with disclosure-based verification per Section 4, reconstructing `recordDataHash` from `keccak256(abi.encodePacked(salt, data))`.

All other fields MUST match the semantics of the JSON redacted bundle. Providers MAY implement CCIP-Read (EIP-3668) as in the base spec; the sentinel applies equally to direct and off-chain responses.

---

## Security Considerations

### Brute-Force Resistance

Both the on-chain `contentKey` and the publicly redacted `userSignature` are deterministic functions of `recordDataHash`:

- `contentKey = keccak256(userSignature || keccak256(ensName) || resolver || recordDataHash || issuer)`, with every other input public on-chain or in the redacted bundle.
- `userSignature` signs an EIP-712 digest that includes `recordDataHash`, and `ecrecover(digest, userSignature) == knownSigner` is a check function an attacker can run offline.

Either value acts as an offline oracle. For low-entropy `data` — email addresses, phone numbers, legal names, postal addresses — a candidate `data'` can be tested by reconstructing either the `contentKey` or the EIP-712 digest and comparing. Typical real-world search spaces are exhaustible in seconds to hours on commodity hardware.

The mandatory 32-byte random salt (Section 1) closes both oracles: the effective preimage is now `salt || data`, i.e. 256 bits of fresh randomness plus the data. Without the salt, `recordDataHash` is not reconstructible. This is why salting is REQUIRED, not OPTIONAL, for private records. Deployments that do not need disclosure at all (fully public records) use the base spec and its unsalted `recordDataHash`.

### ZK Commitment Blinding

The salt requirement in Section 1 applies to the `recordDataHash` preimage regardless of how the hash is computed — **including when `recordDataHash` is a zero-knowledge proof commitment** rather than a keccak hash. A ZK proof guarantees soundness (the prover knows a preimage satisfying the circuit); it does NOT guarantee preimage confidentiality. A circuit that commits `Poseidon(value)` over a low-entropy `value` — a birthday, an age band, an email, a phone number — produces a *public* commitment that an attacker recovers by enumerating candidate inputs and recomputing `Poseidon(candidate)` until it matches. The work is identical to brute-forcing an unhashed payload; the proof system adds nothing to confidentiality.

Therefore, for any private record whose `recordDataHash` is a ZK commitment over low-entropy data, the circuit MUST mix a high-entropy per-record salt into the commitment preimage:

```
recordDataHash = Poseidon(value, salt)
```

where `salt` is a **private** circuit input of at least 128 bits, generated by the issuer with a CSPRNG and delivered to the user per Section 1. The salt MUST NOT be exposed as a public signal (doing so re-opens the oracle). Circuits that omit this blinding MUST NOT be used for private records, and issuers MUST NOT describe an unsalted low-entropy commitment as "non-reversible" or "private."

This closes the same offline oracle for ZK records that the keccak salt closes for non-ZK records. The base specification's "Low-Entropy Payloads" note applies identically to commitment-based `recordDataHash` values.

### Salt and Issuer Storage

The salt is the mitigation; treat it with the same care as a password:

- The issuer MUST generate salt with a cryptographically secure RNG.
- The issuer MUST deliver the salt to the user over a confidential channel at issuance time.
- The issuer MUST NOT retain the salt after delivery. Retaining `(salt, recordDataHash)` recreates the brute-force oracle that salting is designed to prevent: an attacker who compromises issuer storage can exhaustively test candidate `data` values offline. A narrow operational exception is permitted for a bounded retry window required for correctness (e.g., reissuing after a transient failure); such retention MUST be explicitly documented in the issuer's specification, MUST be limited to the smallest window operationally necessary, and SHOULD NOT exceed 24 hours.
- The issuer MUST NOT retain the raw `data` beyond what is required to complete the issuance check.
- The user MUST store the salt alongside the data (or derive it deterministically, see Section 1). Losing the salt is equivalent to losing the ability to disclose, but does not expose the data.
- Wallets that manage private records SHOULD back up salts alongside seed-phrase backups (e.g., as an encrypted companion blob). A user whose wallet is restored from seed alone will permanently lose the ability to disclose random-salt records unless an orthogonal salt backup exists; this failure mode is silent from the chain's perspective (the record remains valid on-chain) and MUST be communicated clearly to users at issuance time.

If both the salt and `recordDataHash` leak simultaneously, the brute-force oracle is regained.

### Channel Confidentiality

The disclosure channel MUST be confidential. Raw `data` and `salt` travel in the clear relative to channel encryption. An authenticated-but-unencrypted channel is explicitly insufficient. Implementations SHOULD use TLS 1.2+ with verified endpoint identities, or an equivalent mechanism (e.g., end-to-end encryption to a known vendor public key).

### Vendor Trust Boundary

A vendor that receives a valid disclosure learns `(data, salt)` and can re-prove the attestation to any third party who has the redacted bundle. The disclosure signature itself is not transferable — a subsequent vendor would expect a different `nonce` and `vendor` — but the data is. Vendors SHOULD treat disclosed data under their own privacy and retention policies.

### Issuer Trust Boundary

The issuer learns the raw data at issuance time (the user proves it to them). After the issuance step the issuer is NOT involved in the disclosure flow and cannot track which vendors receive disclosures.

### Cross-Context Replay

EIP-712 domain separation (`name = "ENS Selective Disclosure"`, `version = "1"`, matching `chainId` and `verifyingContract`) prevents disclosure signatures from being replayed into unrelated protocols. Implementations MUST reject a disclosure whose `chainId` or `verifyingContract` does not match the deployed `VerifiableRecordController` managing the record.

### Name Transfer

If an ENS name is transferred between issuance and disclosure, base-spec verification step 9 (signer of `userSignature` must equal current owner) rejects the disclosure. The new owner cannot disclose the previous owner's attested data.

### Signature Malleability

Per the base spec, implementations MUST enforce low-`s` canonical ECDSA for both `userSignature` and `disclosureSignature`. Accepting both `s`-value variants of the user signature would allow an attacker to derive a different `contentKey` from the same logical consent.

### On-Chain Privacy

No private data, salt, or `recordDataHash` appears on-chain. The on-chain `contentKey` is a keccak256 over a 256-bit salted preimage plus other public inputs; it reveals nothing about `data` without knowledge of the salt.

---

## Rationale

### Why Mandatory Salt?

The intuitive argument for skipping salt is "the user already knows their own data, so the data is the secret." This conflates *known to the user* with *secret from the world*. Email addresses, phone numbers, names, and postal addresses are routinely known by many parties; their entropy against a targeted brute force is low (often under 40 bits for emails, 30 bits for phone numbers, 20 bits for common-pattern names). The on-chain `contentKey` and the public `userSignature` are both deterministic oracles for `recordDataHash` — without salt, both are exhaustible in seconds on commodity hardware. The salt is 32 bytes of extra state the user carries alongside the data; the UX cost is small, the security gain is categorical.

### Why EIP-712 for Disclosure (Not EIP-191)?

EIP-191 personal_sign over a bare keccak256 digest offers no domain separation: any other protocol that happens to sign 32-byte blobs can produce interchangeable signatures. EIP-712 gives an explicit domain (name + version + chainId + verifyingContract) and a typed schema, so disclosure signatures cannot be mistaken for, or replayed as, any other protocol's messages. The "overhead" of defining an EIP-712 type is a few lines of schema declaration and uses the same mechanism the base spec already requires.

### Why Bind `node` and `vendor`?

Binding `vendor` prevents a disclosure signature captured in transit from being presented to a different vendor (defense in depth beyond the channel confidentiality requirement and per-vendor nonce). Binding `node` removes ambiguity when a single owner has the same `(issuer, recordType)` record on multiple ENS names — without it, the signature could be applied to either name's record.

### Why Not Sign Over `data` or `salt`?

The `recordDataHash` check against the on-chain `contentKey` already provides integrity: any substitution of `data` or `salt` causes verification to fail. Binding those values in the disclosure signature would also prevent separation of concerns between consent (signed once by the user) and value transport (may be reconstructed locally from user storage).

### Why `bytes32(0)` as the Private Sentinel for the On-Chain Provider?

`keccak256` output is statistically indistinguishable from random; no honest record can legitimately produce `recordDataHash == bytes32(0)`. Using zero as the "this field is redacted" marker avoids adding a breaking interface change to `IProofBundleProvider` while remaining unambiguous in practice.

### Why Not Issuer-Mediated Disclosure?

An alternative design has the issuer broker all disclosures — the vendor asks the issuer, the issuer checks user authorization, the issuer reveals. This adds an availability dependency (issuer must be online), a privacy risk (issuer tracks all disclosures), and implementation complexity. Direct user-to-vendor disclosure is simpler and gives the user full control.

### Why Vendor Nonce (Not Timestamp)?

A timestamp-based replay window is ambiguous and introduces clock-skew issues. A vendor-issued nonce is explicit: the vendor controls exactly which disclosures it accepts.

---

## Backwards Compatibility

This extension is fully backwards compatible with the base Verifiable Records spec for **non-private records**: their bundles, `recordDataHash` computation, content key derivation, and verification flow are unchanged.

For **private records**, legacy (pre-this-extension) verifiers will deterministically reject the bundle — either because `version` is `"1-private"` (unrecognized) or because `recordDataHash` is `null` (missing required field). This is the correct failure mode: a legacy verifier cannot produce a meaningful verification without disclosure and MUST NOT appear to succeed.

The on-chain record format, content key derivation formula, `VerifiableRecordController` interface, and `IssuerRegistry` interface are unchanged. The `IProofBundleProvider` interface is extended only by a non-breaking sentinel convention (`recordDataHash == bytes32(0)` signals private) that legacy non-private bundles will never collide with.
