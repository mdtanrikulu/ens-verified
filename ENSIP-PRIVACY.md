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

1. A mandatory high-entropy per-record salt mixed into the `recordDataHash` preimage (32 bytes for keccak-hashed records; at least 128 bits for field-element ZK commitments — see Section 1), so that the on-chain `contentKey` and the public `userSignature` cannot be used as offline brute-force oracles against low-entropy data.
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

This document inherits all terminology from the base Verifiable Records specification (issuer, verifier, content key, proof bundle, record data hash, node, owner) and adds:

| Term | Definition |
|------|-----------|
| **Vendor** | The relying party that receives a selective disclosure directly from the user and verifies it (Section 4). A vendor is a verifier in the base-spec sense, plus a participant in the challenge/disclosure exchange. |
| **Private record** | A verifiable record whose `recordDataHash` preimage contains data the user does not want publicly recoverable. Private records use a salted preimage (Section 1) and a redacted public bundle (Section 2). |
| **Predicate record** | A private record whose public artifact is a salted ZK commitment plus a proof of a predicate over the committed value (e.g., "over 18"), rather than the value itself. See Section 2. |
| **Privacy-aware verifier** | A verifier that implements this extension: it recognizes `"1-private"` bundles and the rejection rules in Section 2. |
| **Legacy verifier** | A verifier that implements only the base specification. Legacy verifiers deterministically reject private bundles (see Backwards Compatibility). |

### 1. Private Record Data Hash

For records using selective disclosure, the `recordDataHash` MUST be computed over a salted preimage, using the **commitment scheme** declared for the record type in the issuer's specification. Every private record type has exactly one commitment scheme, and the issuer MUST document it so that users, vendors, and wallets can reproduce the computation. This document defines two schemes:

- **Salted keccak (default).** For records disclosed by revealing the raw value:

  ```
  recordDataHash = keccak256(abi.encodePacked(salt, data))
  ```

  `salt` MUST be exactly 32 bytes.

- **Salted field commitment (ZK records).** When `recordDataHash` is a zero-knowledge commitment used as a circuit's public output (e.g., Poseidon over BN254):

  ```
  recordDataHash = Poseidon(value, salt)
  ```

  The salt MUST be mixed into the commitment preimage **inside the circuit** as a private input — see "ZK Commitment Blinding" under Security Considerations. It MUST carry at least 128 bits of entropy and MUST be representable as a single element of the commitment's scalar field (a full 32-byte salt does not fit a BN254 field element; a uniformly random value below the field modulus does, and satisfies the entropy requirement). A ZK commitment over an unsalted low-entropy value provides proof soundness but NOT preimage confidentiality, and does not satisfy this section.

Where:

- `salt` is a high-entropy per-record value, sized per the scheme above. A fresh salt MUST be used for each issuance; salts MUST NOT be reused across records, users, or record types.
- `data` is the canonical byte encoding of the private value (for field commitments, `value` is its field-element encoding). The encoding is record-type specific (e.g., UTF-8 for email addresses, E.164 ASCII for phone numbers) and MUST be defined deterministically by the issuer's specification so that vendor and issuer produce the same `recordDataHash` from the same logical value.

Without the salt, no party — including the user — can reconstruct `recordDataHash` and complete a disclosure.

#### Salt Provenance

Exactly one of the following two regimes applies to each record, and the issuer's specification MUST state which:

- **Issuer-generated (default).** The issuer chooses the salt uniformly at random with a cryptographically secure RNG at issuance time, and delivers it to the user over a confidential channel. The user MUST persist the salt alongside the data. The issuer's delivery and non-retention obligations are specified under "Salt and Issuer Storage" in Security Considerations.
- **User-derived (deterministic).** The user derives the salt from a user-held secret and supplies it (or the resulting `recordDataHash` preimage material) to the issuer during the issuance exchange, avoiding separate salt storage. The issuer's *generation and delivery* obligations do not apply; its *non-retention* obligations do. The derivation MUST follow one of the two families below.

For user-derived salts, the **KDF-based family below is RECOMMENDED**; the signature-based family carries a correlated-leak hazard and MUST follow the domain-separation rule given here. Two derivation families are recognized:

- **KDF-based (RECOMMENDED)** (e.g., HKDF-SHA-256 seeded by a stable wallet-derived secret and domain-separated per `(issuer, recordType, node)`). Each salt depends on a distinct derivation context, so compromise of one record's salt does not reveal another's. Requires the user to back up the seeding secret.
- **Signature-based** (e.g., `salt = keccak256(userSig)`, where `userSig` signs an EIP-712 message that **itself** commits to `(issuer, recordType, node)` plus a fixed `purpose` string such as `"ENS-salt-v1"`). The signing implementation MUST be RFC-6979 compliant — randomized ECDSA produces a different signature on each invocation and will break reproducibility; non-deterministic wallets MUST NOT be used.
  - The **signed message** MUST be unique per `(issuer, recordType, node)`. A scheme that signs a *fixed* message and then mixes the public tuple in afterward — e.g. `salt = keccak256(userSigOverFixedMsg || issuer || recordType || node)` — MUST NOT be used: because `issuer`, `recordType`, and `node` are all public (they are the on-chain `vr:{issuer}:{recordType}` key plus the namehash), the fixed-message signature is the *only* secret and is shared across every record. A single leak of that one signature lets an attacker derive **every** salt the user holds and re-open the brute-force oracle across their entire portfolio at once.
  - The salt-derivation signature is a long-lived root secret. Wallets MUST NOT reuse the salt-derivation message for any other purpose (login/SIWE, permits, etc.), MUST treat it as non-exportable, and MUST NOT solicit it on behalf of arbitrary dApps. Unlike a stored salt it cannot be rotated without re-issuing every affected record.

Issuers that offer deterministic derivation MUST document the exact scheme so vendors and future wallets can reproduce it.

### 2. Redacted Proof Bundle

The proof bundle served at the issuer's `specificationURI` for a private record MUST:

- Set `"version": "1-private"`. This value is hereby registered in the base specification's proof-bundle version registry (base spec Section 8); verifiers that do not implement this extension reject it per the base rules.
- Set `"private": true`.
- Set `"request.recordDataHash"` to JSON `null`. The key MUST be present with the literal value `null` — it MUST NOT be omitted, so that consumers can distinguish "redacted" from "malformed".
- Omit any salt or raw data.
- Include all remaining fields required by the base spec (every other `request.*` field, plus `userSignature`, `contentKey`, `proof`), with unchanged semantics.

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
- A bundle with `"version": "1-private"` AND `private` absent, `false`, or non-boolean MUST be rejected — the two markers MUST agree in both directions.
- A privacy-aware verifier MUST NOT attempt any verification path that requires `recordDataHash` (base spec Section 7, steps 7–9) on a private bundle except via the disclosure flow in Section 4.

The distinct version string (`"1-private"`) gives legacy verifiers a deterministic signal to reject rather than silently coerce `recordDataHash=null` to zero.

#### Predicate Records (Full Bundles over Blinded Commitments)

A **predicate record** proves a property of a private value (e.g., an age-verification record whose `recordDataHash` is a salted Poseidon commitment to a birthdate, accompanied by a Groth16 proof of "over 18") without ever disclosing the value. Because the commitment preimage already contains the Section 1 salt, publishing the commitment itself leaks nothing about the underlying value.

Issuers of predicate records MAY therefore serve a standard **non-redacted** bundle (`"version": "1"`, `recordDataHash` present) instead of the redacted form: the public artifact is the blinded commitment plus the predicate proof, and the full base-spec verification flow (base spec Section 7) applies unchanged. The mandatory-redaction rules above apply to private records whose disclosure model reveals the raw `(salt, data)` preimage — for those, a public `recordDataHash` would be an oracle once the salt leaks, and redaction is REQUIRED. The Section 1 salt requirement applies to **both** classes.

### 3. Public Verification (Without Disclosure)

From the on-chain state alone, any party MAY read:

1. A record exists at text key `vr:{issuer}:{recordType}` on the target resolver.
2. The issuer is active in the Issuer Registry.
3. The record has not expired.

**Checks 1–3 are NOT evidence of issuer attestation.** The record lives on a standard ENS resolver, and the name owner can write any text record there directly (the controller is one authorized writer, not the only one — see base spec Section 11). A name owner can therefore `setText("vr:{issuer}:{recordType}", "{arbitrary contentKey} {future expiry}")` with no issuer involvement, and checks 1–3 pass for a record the issuer never issued. For non-private records this fabrication is caught by the content-key, proof, and ownership recomputation in base spec Section 7; the private public-path omits exactly those steps, so that backstop is absent.

To obtain any issuer-attestation signal without disclosure, a privacy-aware public verifier MUST additionally:

4. Fetch the redacted proof bundle for *this* record from the issuer's `specificationURI` (using the base spec's per-record URI templates, Section 8, or `IProofBundleProvider.getProofBundle(node, recordType)`), and apply the Section 2 rejection rules.
5. Confirm `bundle.request.node`, `bundle.request.issuer`, and `bundle.request.recordType` equal the `(node, issuer, recordType)` being verified.
6. Confirm `bundle.contentKey` equals the `contentKey` parsed from the on-chain text value.
7. Confirm `bundle.request.expires` equals the `expires` parsed from the on-chain text value, and that it has not passed. The signed, issuer-served `bundle.request.expires` is authoritative — the on-chain value is owner-writable, and check 3 alone would let the name owner extend an expired record indefinitely (see base spec Security Considerations, "Record Value Tampering").

Steps 4–7 bind the owner-writable text record to an artifact the issuer actually served, without needing `recordDataHash`: a fabricated record passes 1–3 but fails 4–7 because the issuer never serves a bundle whose `contentKey` matches the forged on-chain value. A record passing 1–3 but failing 4–7 MUST be treated as **unverified** (fabricated, tampered, or stale), not as an attestation.

Public verifiers MUST NOT claim verification of the content key binding or the issuer's proof for private records — both require `recordDataHash` and therefore disclosure.

The strongest semantic public verification can establish for a private record — even with steps 4–7 — is: **"issuer Y published a non-expired redacted bundle for a record of type X on this name."** It is NOT proof that the *current name owner* holds the attestation (ownership is checkable only via disclosure, below), and it reveals nothing about the underlying data. Any "verified" indicator a relying party derives from public verification MUST be labeled unconfirmed / disclosure-required; an authenticated "this owner currently holds attestation X" statement MUST be obtained through the disclosure flow (Section 4).

Public verifiers also CANNOT perform the name-ownership check (base spec Section 7, step 10) for private records: recovering the `userSignature` signer requires reconstructing the EIP-712 digest, and that digest commits to `recordDataHash`, which is redacted in the public bundle. Name-ownership anchoring is therefore deferred to the disclosure flow (Section 4), where the vendor recomputes `recordDataHash` from the disclosed salt and data and runs the full base verification — including the ownership check — end to end. Callers that need an authenticated "this name owner currently holds an attestation" statement MUST obtain it via disclosure; they MUST NOT infer it from public verification alone.

### 4. Selective Disclosure Flow

All messages between user and vendor MUST travel over a channel that provides both **authentication** and **confidentiality** (e.g., TLS 1.2+ with verified endpoint identity). An authenticated-but-unencrypted channel is explicitly insufficient because the raw `data` and `salt` travel in the clear relative to channel encryption.

#### Step 1: Vendor Challenge

The vendor generates a cryptographically random 32-byte `nonce` (filling the `bytes32` field of the `Disclosure` struct exactly — shorter nonces and padding rules are not defined by this specification) and sends it to the user together with:

- the record the challenge concerns: the `(node, issuer, recordType)` triple. The challenge MUST carry these explicitly; the user's wallet needs them to construct the Section 5 struct, and reconstructing them from out-of-band context risks signing a disclosure for the wrong record;
- the vendor's wallet identity: either a 20-byte Ethereum address, or `address(0)` if the vendor does not authenticate via a wallet,
- the vendor's display identity `vendorIdentity`: a human-readable, verifiable identifier such as an origin URL (`"https://shop.example.com"`) or a DID (`"did:web:example.com"`). Vendors with `vendor = address(0)` MUST supply a non-empty `vendorIdentity`; vendors with a wallet identity MAY supply one in addition (or the empty string). This string is bound into the signed struct (Section 5) and is what the user's wallet displays before signing (see Rationale — Why `vendorIdentity`?);
- an OPTIONAL `expires` Unix timestamp after which the vendor will refuse the disclosure.

Every nonce has a bounded **acceptance window**: it ends at the challenge's `expires`, or, when the challenge carries no expiry, after a vendor-defined implicit window (24 hours RECOMMENDED). The vendor MUST retain each issued nonce — with its consumed/unconsumed status — until its acceptance window ends, and MUST reject a disclosure whose nonce is unknown (never issued, or already evicted after its window). The vendor MUST reject any duplicate nonce. The issued-and-consumed nonce set MUST be held in a store that is **linearizable across every vendor instance that can accept a disclosure**. A vendor serving disclosures from multiple processes or replicas MUST NOT keep nonce state in per-instance memory or an eventually-consistent cache: under weak consistency, the same valid disclosure routed to two instances can pass the not-yet-consumed check on both and be accepted twice (a TOCTOU double-accept — see Section 6).

Vendors handling a high volume of disclosures MAY front the authoritative store with a probabilistic structure (e.g., a bloom filter with collision probability below 2⁻³² per query) combined with TTL eviction, used only at *issuance time* to avoid handing out a colliding nonce; because nonces carry 256 bits of entropy, legitimate collisions are cryptographically negligible and a small false-positive rate only causes the vendor to re-issue a nonce, not to accept an invalid disclosure. Such a structure MUST NOT be the sole record of consumption: it cannot distinguish "issued-but-not-consumed" from "never-issued" and offers no atomic consume, so the validity check in Step 3.2 and the consume in Step 3.9 MUST run against the linearizable store, not the filter.

#### Step 2: User Disclosure

The user sends the vendor:

```json
{
  "data": "0x<hex encoding of the canonical bytes>",
  "salt": "0x<hex>",
  "disclosureSignature": "0x<hex>"
}
```

Where `disclosureSignature` is an EIP-712 signature as defined in Section 5. The `data` field MUST be the `0x`-prefixed hex encoding of the record type's canonical byte encoding (Section 1) — the exact bytes that enter the `recordDataHash` preimage. Senders MAY additionally include a human-readable rendering for display, but the hex form is authoritative for verification. `salt` is hex-encoded with the length the record type's commitment scheme requires (32 bytes for salted keccak; the field-element encoding for ZK commitments).

The signature intentionally does NOT cover `data` or `salt` directly: any substitution of those values by an intermediary (on a non-confidential channel) would cause the downstream `recordDataHash` check against the on-chain `contentKey` to fail. Binding them explicitly would also prevent the user from consenting to the disclosure before the raw values are rehydrated locally.

#### Step 3: Vendor Verification

The vendor MUST perform all of the following steps. Failure at any step fails the disclosure.

1. **Verify disclosure signature.** Reconstruct the EIP-712 digest from the fields in Section 5 and validate it against the current owner of `node`, resolved per base spec Section 7, step 10 (ENSv2 registry traversal; EOA owners via ECDSA recovery, contract owners via ERC-1271 `isValidSignature`).
2. **Verify nonce (advisory).** The `nonce` in the signed struct MUST equal a nonce the vendor issued, within its acceptance window, and not observed as consumed. This early check fails fast before the fetch in step 6; the authoritative, race-free check happens atomically with the consume in step 9.
3. **Verify scope.** `issuer`, `recordType`, and `node` MUST match the record the vendor's challenge was issued for. `vendor` MUST equal the vendor's declared wallet identity (or `address(0)` if the vendor did not declare one), and `vendorIdentity` MUST equal — byte-for-byte — the display identity the vendor sent with the challenge.
4. **Verify expiry.** The signed `expires` MUST equal the `expires` the vendor issued with the challenge (including `0` when the challenge carried none) — a mismatch means the user signed a different challenge. If `expires != 0`, the current time MUST be ≤ `expires`.
5. **Compute `recordDataHash`** from the disclosed `salt` and `data`, using the record type's commitment scheme (Section 1): `keccak256(abi.encodePacked(salt, data))` for salted-keccak records, or the circuit's commitment function (e.g., `Poseidon(value, salt)`) for ZK-committed records. The vendor MUST use the scheme the issuer's specification declares for this record type; applying the keccak formula to a ZK-committed record (or vice versa) fails verification.
6. **Fetch the redacted bundle** from the issuer's `specificationURI`. Apply the rejection rules in Section 2.
7. **Complete the bundle** by inserting the computed `recordDataHash`.
8. **Run the base verification flow** (ENSIP-TBD Section 7) end-to-end — including the verification-context cross-checks (step 6), content key recomputation and comparison (steps 7–8), issuer proof verification (step 9), and name ownership (step 10). Any failure fails the disclosure.
9. **Mark the nonce consumed** in a single linearizable compare-and-set against the authoritative, strongly-consistent nonce store (e.g. a conditional/transactional write, `SELECT … FOR UPDATE`, or `SET key value NX`), atomically with acceptance of the verification result. The issued-and-not-yet-consumed check and this consume MUST be one atomic operation against that store, so two concurrent disclosures bearing the same nonce cannot both observe it as unconsumed. Step 2 does not substitute for this step.

If all steps succeed, the vendor has proof that the issuer attested to exactly this `(data, salt)` pair for the current owner of `node`.

### 5. Disclosure Signature (EIP-712)

The disclosure signature uses EIP-712 to provide explicit domain separation and to bind every security-relevant parameter. EIP-191 personal_sign is deliberately **not** used — see Rationale.

#### Domain Separator

```
EIP712Domain {
    string  name              = "ENS Selective Disclosure"
    string  version           = "1"
    uint256 chainId           = <chain ID of the chain where the record's VerifiableRecordController is deployed>
    address verifyingContract = <VerifiableRecordController address>
}
```

`chainId` is the chain of the **controller** that issued the record — the same chain the base spec's EIP-712 domain uses — not the chain of any L2 resolver serving the text record. `chainId` prevents cross-chain replay (e.g., a testnet disclosure being accepted on mainnet); tying `verifyingContract` to the deployed `VerifiableRecordController` prevents replay across different deployments on the same chain.

#### Primary Type

```solidity
struct Disclosure {
    bytes32 node;           // ENS namehash of the name being disclosed from
    address issuer;         // Record issuer
    string  recordType;     // Record type identifier
    bytes32 nonce;          // Vendor-issued nonce
    address vendor;         // Vendor wallet identity; address(0) if not declared
    string  vendorIdentity; // Vendor display identity (origin URL or DID); "" if none
    uint64  expires;        // Disclosure expiry; 0 = no expiry
}
```

#### Typehash

```
DISCLOSURE_TYPEHASH = keccak256(
    "Disclosure(bytes32 node,address issuer,string recordType,bytes32 nonce,address vendor,string vendorIdentity,uint64 expires)"
)
```

Per EIP-712, the `string` fields (`recordType` and `vendorIdentity`) are encoded as `keccak256(bytes(value))` inside the struct hash.

#### Struct Hash

```
structHash = keccak256(abi.encode(
    DISCLOSURE_TYPEHASH,
    disclosure.node,
    disclosure.issuer,
    keccak256(bytes(disclosure.recordType)),
    disclosure.nonce,
    disclosure.vendor,
    keccak256(bytes(disclosure.vendorIdentity)),
    disclosure.expires
))
```

The final digest is `keccak256("\x19\x01" || domainSeparator || structHash)`.

#### Test Vector

Signed with the well-known private key `0x…01` (address `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`), RFC-6979 deterministic. Verified against the reference implementation (`test/TestVectors_t.sol`); regenerate with `sdk/gen_vectors.mjs`.

Salted record data hash (Section 1, salted-keccak scheme):

```
salt           = 0x1111111111111111111111111111111111111111111111111111111111111111
data           = "alice@example.com"                      (UTF-8)
recordDataHash = keccak256(salt || data)
               = 0x08440f9313d3dc4f6c1601f93b58a1b8fb7f93b6473f99fcc680921f1d52e98b
```

Disclosure signature (domain: `name = "ENS Selective Disclosure"`, `version = "1"`, `chainId = 1`, `verifyingContract = 0x4242424242424242424242424242424242424242`):

| Field | Value |
|-------|-------|
| node | `namehash("alice.eth")` = `0x787192fc5378cc32aa956ddfdedbf26b24e8d78e40109add0eea2c1a012c3dec` |
| issuer | `0x2222222222222222222222222222222222222222` |
| recordType | `"email"` |
| nonce | `0x3333333333333333333333333333333333333333333333333333333333333333` |
| vendor | `0x0000000000000000000000000000000000000000` |
| vendorIdentity | `"https://vendor.example.com"` |
| expires | `0` |

```
DISCLOSURE_TYPEHASH = 0x8db61b22885ffb472999d0a94660ff21964e32193b7bce3e14195c73215696e5
domainSeparator     = 0xaa950cf535f79bee163e4b8cb2325176f654fbfa4375f01f07d56c528c74caa3
structHash          = 0x72e3a36b640c799a3bfc4ff13967d5bce78d2851a621546ce36bcde50620a15f
digest              = 0x3807e11ae11125a3a896c047e5f11a78fc6d1b9affd5dc858a834c792e759049
disclosureSignature = 0xfb64548e89c8b164f16121acacc1d23c54e637456abef4524d02ffe030b96e53
                        66641f8f5f607162d78c9a12cf5992825c205182ce245df35c4b91e4246299b61b
```

An implementation MUST reproduce every value above from the inputs. (The signature line is one 65-byte value, wrapped for display.)

### 6. Replay and Misuse Protection

The design provides layered protection:

- **Per-vendor binding.** The `vendor`, `vendorIdentity`, and `nonce` fields bind each disclosure to a specific vendor interaction. A vendor with a declared Ethereum identity cannot reuse another vendor's disclosure even if it is intercepted. Wallet-less vendors (`vendor = address(0)`) are distinguished by `vendorIdentity`, which the receiving vendor checks byte-for-byte against its own declared identity (Section 4, step 3), so a disclosure signed for one vendor's identity is rejected by another's. A phishing intermediary can still present another vendor's `vendorIdentity` in its own challenge; the resulting disclosure names the impersonated vendor, and capturing it in transit is prevented by the Section 4 channel requirements (authenticated TLS to the endpoint whose identity was displayed). Wallets SHOULD display `vendorIdentity` prominently and SHOULD corroborate it against the connected channel endpoint where the transport allows.
- **Per-name binding.** The `node` field disambiguates disclosures for users who own multiple names with the same `(issuer, recordType)`.
- **Single-use nonces.** Vendors MUST reject already-consumed nonces.
- **Expiry.** The OPTIONAL `expires` caps the validity window of the authorization.
- **Ownership anchoring.** Base-spec verification step 10 rejects records whose `userSignature` signer no longer owns the name, so a seller cannot disclose records that belonged to a previous owner.
- **Domain separation.** The EIP-712 domain prevents the disclosure signature from being accepted by any unrelated protocol.

What this does NOT prevent:

- **Vendor collusion.** Two vendors that legitimately receive the raw data can share it out-of-band. Unlinkability across vendors is out of scope.
- **Post-disclosure forwarding of the data.** Any party that later obtains `(data, salt)` can re-run verification against the bundle and learn the same fact. This is inherent to selective disclosure of non-zero-knowledge attestations.
- **Cross-instance double-accept under weak consistency.** The single-use guarantee holds only within the vendor's own consistency boundary. A vendor that consumes nonces against per-instance or eventually-consistent state can accept one disclosure twice; the spec requires a linearizable store (Section 4) but cannot enforce the vendor's infrastructure. For one-shot, non-idempotent side effects (admit-one, single unlock, one-time discount) the vendor remains responsible for end-to-end idempotency beyond nonce single-use.
- **Public-verification fabrication.** Public verification of a private record (Section 3) is not proof of issuer attestation — a name owner can write a passing record directly. Relying parties MUST treat the public path as unconfirmed and require disclosure (Section 4) for any trust decision.

### 7. On-Chain Proof Bundle Provider

When `specificationURI` is an `IProofBundleProvider` contract (base spec Section 8), private records are signaled by returning `recordDataHash == bytes32(0)` in the ABI-encoded response.

This is a safe sentinel because a conforming `recordDataHash` is always the output of the record type's commitment scheme (Section 1) — a keccak hash or field-element commitment, statistically indistinguishable from random — so no honest record can legitimately collide with the sentinel. Issuers and providers MUST NOT create or serve a record whose actual `recordDataHash` equals `bytes32(0)`, and controllers SHOULD reject issuance requests with `recordDataHash == bytes32(0)`.

Verifiers that decode an `IProofBundleProvider` response with `recordDataHash == bytes32(0)` MUST:

- Treat the record as private.
- Refuse public verification paths that consume `recordDataHash`.
- Proceed with disclosure-based verification per Section 4, reconstructing `recordDataHash` from the disclosed `salt` and `data` using the record type's commitment scheme (Section 1).

All other fields MUST match the semantics of the JSON redacted bundle. Providers MAY implement CCIP-Read (EIP-3668) as in the base spec; the sentinel applies equally to direct and off-chain responses.

---

## Security Considerations

### Brute-Force Resistance

Both the on-chain `contentKey` and the publicly redacted `userSignature` are deterministic functions of `recordDataHash`:

- `contentKey = keccak256(userSignature || keccak256(ensName) || resolver || recordDataHash || issuer)`, with every other input public on-chain or in the redacted bundle.
- `userSignature` signs an EIP-712 digest that includes `recordDataHash`, and `ecrecover(digest, userSignature) == knownSigner` is a check function an attacker can run offline.

Either value acts as an offline oracle. For low-entropy `data` — email addresses, phone numbers, legal names, postal addresses — a candidate `data'` can be tested by reconstructing either the `contentKey` or the EIP-712 digest and comparing. Typical real-world search spaces are exhaustible in seconds to hours on commodity hardware.

The mandatory high-entropy random salt (Section 1 — 32 bytes for salted keccak, at least 128 bits for field commitments) closes both oracles: the effective preimage now contains fresh randomness far beyond brute-force reach in addition to the data. Without the salt, `recordDataHash` is not reconstructible. This is why salting is REQUIRED, not OPTIONAL, for private records. Deployments that do not need disclosure at all (fully public records) use the base spec and its unsalted `recordDataHash`.

### ZK Commitment Blinding

The salt requirement in Section 1 applies to the `recordDataHash` preimage regardless of how the hash is computed — **including when `recordDataHash` is a zero-knowledge proof commitment** rather than a keccak hash. A ZK proof guarantees soundness (the prover knows a preimage satisfying the circuit); it does NOT guarantee preimage confidentiality. A circuit that commits `Poseidon(value)` over a low-entropy `value` — a birthday, an age band, an email, a phone number — produces a *public* commitment that an attacker recovers by enumerating candidate inputs and recomputing `Poseidon(candidate)` until it matches. The work is identical to brute-forcing an unhashed payload; the proof system adds nothing to confidentiality.

Therefore, for any private record whose `recordDataHash` is a ZK commitment over low-entropy data, the circuit MUST mix a high-entropy per-record salt into the commitment preimage:

```
recordDataHash = Poseidon(value, salt)
```

where `salt` is a **private** circuit input of at least 128 bits (fitting the scalar field), generated and delivered per the Salt Provenance rules in Section 1. The salt MUST NOT be exposed as a public signal (doing so re-opens the oracle). Circuits that omit this blinding MUST NOT be used for private records, and issuers MUST NOT describe an unsalted low-entropy commitment as "non-reversible" or "private."

This closes the same offline oracle for ZK records that the keccak salt closes for non-ZK records. The base specification's "Low-Entropy Payloads" note applies identically to commitment-based `recordDataHash` values.

### Salt and Issuer Storage

The salt is the mitigation; treat it with the same care as a password. The first two obligations below apply only to issuer-generated salts (Section 1, Salt Provenance); the rest apply to both regimes:

- The issuer MUST generate salt with a cryptographically secure RNG.
- The issuer MUST deliver the salt to the user over a confidential channel at issuance time.
- The issuer MUST NOT retain the salt after delivery. Retaining `(salt, recordDataHash)` recreates the brute-force oracle that salting is designed to prevent: an attacker who compromises issuer storage can exhaustively test candidate `data` values offline. A narrow operational exception is permitted for a bounded retry window required for correctness (e.g., reissuing after a transient failure); such retention MUST be explicitly documented in the issuer's specification, MUST be limited to the smallest window operationally necessary, and SHOULD NOT exceed 24 hours.
- The issuer MUST NOT retain the raw `data` beyond what is required to complete the issuance check.
- The user MUST store the salt alongside the data (or derive it deterministically, see Section 1). Losing the salt is equivalent to losing the ability to disclose, but does not expose the data.
- **Re-issuance rotates the salt.** Base-spec re-issuance is last-write-wins; a re-issued private record carries a fresh salt (Section 1 forbids reuse), and the previous salt is invalidated once the on-chain content key is overwritten. Issuers MUST deliver the new salt with every re-issuance, and wallets MUST replace their stored salt for the `(node, issuer, recordType)` triple.
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

If an ENS name is transferred between issuance and disclosure, base-spec verification step 10 (the `userSignature` must validate against the current owner, resolved through the ENSv2 registry hierarchy) rejects the disclosure. The new owner cannot disclose the previous owner's attested data.

### Signature Malleability

Per the base spec, implementations MUST enforce low-`s` canonical ECDSA for both `userSignature` and `disclosureSignature`. Accepting both `s`-value variants of the user signature would allow an attacker to derive a different `contentKey` from the same logical consent.

### On-Chain Privacy

No private data, salt, or `recordDataHash` appears on-chain. The on-chain `contentKey` is a keccak256 over a high-entropy salted preimage plus other public inputs; it reveals nothing about `data` without knowledge of the salt.

---

## Rationale

### Why Mandatory Salt?

The intuitive argument for skipping salt is "the user already knows their own data, so the data is the secret." This conflates *known to the user* with *secret from the world*. Email addresses, phone numbers, names, and postal addresses are routinely known by many parties; their entropy against a targeted brute force is low (often under 40 bits for emails, 30 bits for phone numbers, 20 bits for common-pattern names). The on-chain `contentKey` and the public `userSignature` are both deterministic oracles for `recordDataHash` — without salt, both are exhaustible in seconds on commodity hardware. The salt is a few dozen bytes of extra state the user carries alongside the data (or derives on demand); the UX cost is small, the security gain is categorical.

### Why EIP-712 for Disclosure (Not EIP-191)?

EIP-191 personal_sign over a bare keccak256 digest offers no domain separation: any other protocol that happens to sign 32-byte blobs can produce interchangeable signatures. EIP-712 gives an explicit domain (name + version + chainId + verifyingContract) and a typed schema, so disclosure signatures cannot be mistaken for, or replayed as, any other protocol's messages. The "overhead" of defining an EIP-712 type is a few lines of schema declaration and uses the same mechanism the base spec already requires.

### Why Bind `node` and `vendor`?

Binding `vendor` prevents a disclosure signature captured in transit from being presented to a different vendor (defense in depth beyond the channel confidentiality requirement and per-vendor nonce). Binding `node` removes ambiguity when a single owner has the same `(issuer, recordType)` record on multiple ENS names — without it, the signature could be applied to either name's record.

### Why `vendorIdentity`?

The wallet prompt is the only place a non-technical user can review "who am I disclosing to?" before signing. For wallet-less vendors, a `vendor` field of `0x0000…0000` fails that review gate entirely — the user has no wallet-level way to distinguish "disclosing to shop.example.com" from "disclosing to a phishing site". Binding a human-readable, verifiable identifier (an origin URL or DID) into the signed struct gives the wallet something meaningful to render, and makes the disclosure non-repudiable as to counterparty: a vendor cannot later claim a disclosure was made to someone else, which matters for dispute resolution.

`vendorIdentity` is a *user-visible label bound into consent*, not a replacement for channel authentication: an attacker can put a plausible-looking string in its own challenge. The mitigations are (a) a TLS-verified endpoint during the disclosure exchange, matching the displayed identity; (b) wallet-side corroboration of the label against the connected origin; (c) DID resolution to a known verification method for `did:` identities. Wallets SHOULD implement at least (a)+(b).

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

For **redacted private records**, legacy (pre-this-extension) verifiers will deterministically reject the bundle — the base specification's version rules (base spec Section 8) require rejecting versions the verifier does not implement, and `"1-private"` (registered by this extension) is exactly such a version; a bundle stripped of `recordDataHash` also fails the base REQUIRED-field check. This is the correct failure mode: a legacy verifier cannot produce a meaningful verification without disclosure and MUST NOT appear to succeed.

**Predicate records** (Section 2) serve standard `"1"` bundles over blinded commitments and verify under the unmodified base flow, on legacy and privacy-aware verifiers alike.

The on-chain record format, content key derivation formula, `VerifiableRecordController` interface, and `IssuerRegistry` interface are unchanged. The `IProofBundleProvider` interface is extended only by a non-breaking sentinel convention (`recordDataHash == bytes32(0)` signals private) that legacy non-private bundles will never collide with.

---

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
