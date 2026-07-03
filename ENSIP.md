# ENSIP-TBD: Verifiable Records for ENS

| **Author**    | TBD                           |
|---------------|-------------------------------|
| **Status**    | Draft                         |
| **Type**      | Standards Track               |
| **Created**   | 2026-03-25                    |
| **Requires**  | ENSIP-1 (EIP-137), ENSIP-5 (EIP-634), EIP-712 |

---

## Abstract

This ENSIP defines a protocol by which third-party **issuers** can write cryptographically verifiable attestation records to ENS names using standard text records (EIP-634). Each record contains an on-chain **content key** — a `bytes32` keccak256 binding commitment that ties the record to a specific ENS name, resolver, issuer, and user signature, preventing copy attacks across names. An **Issuer Registry** (which may be DAO-governed or community-managed) controls which addresses may issue records and hosts the URI from which verifiers fetch the off-chain **proof bundle**. Users authorize record creation by signing an EIP-712 typed data message, and verifiers independently validate records by recomputing the content key and checking the proof bundle.

## Motivation

ENS names serve as a universal namespace for Ethereum identities. Today, the data stored in ENS records is self-asserted: the name owner writes whatever they choose. There is no standard mechanism for a trusted third party to attach a cryptographically verifiable credential to an ENS name in a way that:

1. **Proves the name owner consented** to the record being written.
2. **Binds the record to that specific name and resolver**, preventing the credential from being copied to a different name.
3. **Allows off-chain verification** without requiring the verifier to replay an on-chain transaction.
4. **Provides a standard revocation path** via an on-chain issuer registry.

Use cases include:

- **Identity verification** -- KYC/KYB providers attesting that a name owner has passed identity checks.
- **Credential issuance** -- Professional certifications, organizational memberships, or educational credentials linked to an ENS name.
- **Compliance attestations** -- Regulatory compliance proofs that counterparties can verify on-chain or off-chain.
- **Reputation signals** -- Third-party reputation or trust scores anchored to a name.

This specification provides a minimal, composable framework that leverages existing ENS text records and requires no changes to ENS resolvers.

---

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**ENS version scope.** This specification targets **ENSv2**, in which names are managed by a hierarchical registry system (each name is a token in its parent's registry contract) rather than the flat ENSv1 registry. Text records are unchanged by ENSv2 — resolvers expose the same `text(bytes32 node, string key)` profile (ENSIP-5), keyed by the ENSIP-1 namehash — so record storage and retrieval in this document apply to both versions. Where name *ownership* matters (Section 7, step 10), this document defines the check in ENSv2 terms; there are no NameWrapper-wrapped names under ENSv2.

### 1. Terminology

| Term | Definition |
|------|-----------|
| **Issuer** | An Ethereum address registered in the Issuer Registry that is authorized to write verifiable records on behalf of users. |
| **User** | The owner (or controller) of an ENS name who consents to a record being written by signing an EIP-712 message. |
| **Verifier** | Any party that reads a verifiable record from ENS and validates it against the on-chain content key and off-chain proof bundle. |
| **Content Key** | A `bytes32` value derived via `keccak256` that cryptographically binds a record to a specific user signature, ENS name, resolver, record data, and issuer. Stored on-chain as the first field of the text record value. |
| **Proof Bundle** | A document containing the full inputs needed to recompute the content key and verify the issuer's proof. Typically a JSON document stored off-chain at the issuer's `specificationURI`, but MAY also be served on-chain via an `IProofBundleProvider` contract when `specificationURI` is a contract address. |
| **Record Type** | A normalized, lowercase string identifier (e.g., `"identity"`, `"kyc"`, `"credential"`) that categorizes the verifiable record. |
| **Record Data Hash** | A `bytes32` keccak256 digest of the record payload. The actual payload lives in the proof bundle; only its hash appears on-chain. |
| **Node** | The ENS namehash of the name, as defined in ENSIP-1 (EIP-137). Resolver profiles in ENSv2 remain keyed by node. |
| **Owner** | The current holder of the ENS name. Under ENSv2, the address obtained by traversing the registry hierarchy from the root registry to the name's parent registry and querying the ownership of the name's token (the traversal implemented by `LibRegistry.findOwner(rootRegistry, dnsEncodedName)` and exposed via the Universal Resolver); `address(0)` if the name is unowned or not found. Owners MAY be smart contracts (see Section 7, step 10). |

### 2. Record Key Format

Verifiable records are stored as ENS text records (EIP-634). The text record key MUST follow this format:

```
vr:{issuerAddress}:{recordType}
```

Where:

- `vr:` is the literal prefix identifying a verifiable record.
- `{issuerAddress}` is the issuer's Ethereum address rendered as a lowercase, `0x`-prefixed, 42-character hex string. Implementations MUST use lowercase hex (not EIP-55 checksummed), as produced by OpenZeppelin's `Strings.toHexString(address)`.
- `{recordType}` is a non-empty string identifier matching the regex `^[a-z0-9_]+$` (lowercase alphanumeric and underscores). Controllers MUST reject `issueRecord` and `revokeRecord` calls whose `recordType` is empty or contains any character outside `[a-z0-9_]`, reverting with `InvalidRecordType()`.

**Example:**

```
vr:0x1234567890abcdef1234567890abcdef12345678:identity
```

### 3. Record Value Format

The text record value MUST follow this format:

```
{contentKey} {expires}
```

Where:

- **`{contentKey}`**: A 66-character hex string (`0x` followed by 64 lowercase hex digits) representing the `bytes32` content key. This is the keccak256 binding commitment.
- **`{expires}`**: A decimal integer string representing a Unix timestamp (seconds since epoch). The value `"0"` means the record has no expiration.

**Grammar (strict):** the value is exactly `{contentKey}{SP}{expires}` where `{SP}` is a single ASCII space character (`0x20`). The value MUST NOT contain leading or trailing whitespace, additional spaces, or any character after the decimal `expires`. An empty-string text record value MUST be treated as "no record" (including after revocation, which sets the text record to the empty string).

**Parsing algorithm:**

1. Split the value on the first space to extract `contentKey`. Verifiers MUST reject values whose `contentKey` half does not match the regex `^0x[0-9a-f]{64}$` (lowercase hex, exactly 32 bytes).
2. The remainder is `expires`. Verifiers MUST reject values whose `expires` tail is not composed solely of ASCII decimal digits (i.e., match the regex `^[0-9]+$`).

All later comparisons against the parsed `contentKey` (Section 7, step 8) are equality comparisons on the decoded 32-byte value.

The proof bundle URI is NOT stored in the text record. Verifiers obtain it from the issuer's `specificationURI` field in the IssuerRegistry (see Section 10).

**Example:**

```
0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 1735689600
```

### 4. Content Key Derivation (Normative)

The content key MUST be derived as:

```
contentKey = keccak256(abi.encodePacked(
    userSignature,          // variable length bytes
    keccak256(ensName),     // 32 bytes
    resolver,               // 20 bytes (address, not padded)
    recordDataHash,         // 32 bytes
    issuer                  // 20 bytes (address, not padded)
))
```

Where:

- `userSignature` is the raw bytes of the user's EIP-712 signature. For EOA signers, implementations MUST accept only 65-byte canonical ECDSA signatures (`r || s || v`) with low-`s` form (see Security Considerations — Signature Malleability). Deployments that support ERC-1271 contract signers treat `userSignature` as opaque bytes; whatever bytes are presented at issuance are the ones bound into the content key (see Security Considerations — Contract-Owned Names).
- `keccak256(ensName)` is the keccak256 hash of the UTF-8 encoded ENS name string (e.g., `"alice.eth"`). This is **not** the ENS namehash; it is the hash of the raw string bytes.
- `resolver` is the resolver contract address (20 bytes, tightly packed per `abi.encodePacked`).
- `recordDataHash` is the `bytes32` hash of the record payload.
- `issuer` is the issuer address (20 bytes, tightly packed per `abi.encodePacked`).

The fixed-size portion is 104 bytes (32 + 20 + 32 + 20). Total input length is `len(userSignature) + 104`.

#### Test Vector

Given the following inputs:

| Field | Value |
|-------|-------|
| userSignature | `0xdead01` (3 bytes, illustration only; real signatures are 65 bytes per Section 4 — this vector exercises the derivation, not signature validation) |
| ensName | `"alice.eth"` |
| resolver | `0x1111111111111111111111111111111111111111` |
| recordDataHash | `0x00000000000000000000000000000000000000000000000000000000deadbeef` |
| issuer | `0x2222222222222222222222222222222222222222` |

Intermediate values:

- `keccak256("alice.eth")` = `0x08fa227fd019b562e0db08881c53ee5d3c7f10bff4becb46914a9481c62c3034`

The content key input is the concatenation (107 bytes total for this example):

```
dead01                                                               // userSignature (3 bytes)
08fa227fd019b562e0db08881c53ee5d3c7f10bff4becb46914a9481c62c3034     // keccak256("alice.eth") (32 bytes)
1111111111111111111111111111111111111111                               // resolver (20 bytes)
00000000000000000000000000000000000000000000000000000000deadbeef       // recordDataHash (32 bytes)
2222222222222222222222222222222222222222                               // issuer (20 bytes)
```

```
contentKey = keccak256(above) = 0xa23f163464ea35a52ab293ffcb1a2eee9fd79fba48a46fa58ec59adcf20c57b6
```

Implementations MUST produce identical content keys for identical inputs. The `computeContentKey` and `verifyContentKey` functions on the controller contract serve as the canonical reference.

### 5. EIP-712 Typed Data

The user's consent is captured via an EIP-712 signature.

#### Domain Separator

```
EIP712Domain {
    string  name              = "ENS Verifiable Records"
    string  version           = "1"
    uint256 chainId           = <deployment chain ID>
    address verifyingContract = <VerifiableRecordController address>
}
```

#### Primary Type

```solidity
struct RecordRequest {
    bytes32 node;           // ENS namehash of the name
    string  ensName;        // Human-readable ENS name (e.g., "alice.eth")
    address resolver;       // Resolver contract address
    string  recordType;     // Record type identifier (e.g., "identity")
    bytes32 recordDataHash; // keccak256 of the record payload
    address issuer;         // Issuer's Ethereum address
    uint64  expires;        // Unix timestamp; 0 = no expiration
    uint256 nonce;          // Replay protection nonce, scoped per (signer, node)
}
```

#### Typehash

```
RECORD_REQUEST_TYPEHASH = keccak256(
    "RecordRequest(bytes32 node,string ensName,address resolver,string recordType,bytes32 recordDataHash,address issuer,uint64 expires,uint256 nonce)"
)
```

Per EIP-712, the `string` fields (`ensName` and `recordType`) are encoded as `keccak256(value)` in the struct hash.

#### Struct Hash Computation

```
structHash = keccak256(abi.encode(
    RECORD_REQUEST_TYPEHASH,
    request.node,
    keccak256(bytes(request.ensName)),
    request.resolver,
    keccak256(bytes(request.recordType)),
    request.recordDataHash,
    request.issuer,
    request.expires,
    request.nonce
))
```

The final EIP-712 digest is:

```
digest = keccak256("\x19\x01" || domainSeparator || structHash)
```

#### Signed Test Vector

A full round-trip vector, signed with the well-known private key `0x…01` (RFC-6979 deterministic ECDSA). Verified against the reference implementation (`test/TestVectors_t.sol`); regenerate with `sdk/gen_vectors.mjs`.

| Field | Value |
|-------|-------|
| signer private key | `0x0000000000000000000000000000000000000000000000000000000000000001` |
| signer address | `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` |
| domain | `name = "ENS Verifiable Records"`, `version = "1"`, `chainId = 1`, `verifyingContract = 0x4242424242424242424242424242424242424242` |
| request.node | `namehash("alice.eth")` = `0x787192fc5378cc32aa956ddfdedbf26b24e8d78e40109add0eea2c1a012c3dec` |
| request.ensName | `"alice.eth"` |
| request.resolver | `0x1111111111111111111111111111111111111111` |
| request.recordType | `"identity"` |
| request.recordDataHash | `keccak256("credential-payload")` = `0x6e23a506c6a22dc4b781f8b5491e2d26c1d0b32c6ea3edea12ed4c7574afd7ba` |
| request.issuer | `0x2222222222222222222222222222222222222222` |
| request.expires | `1735689600` |
| request.nonce | `0` |

Expected outputs:

```
RECORD_REQUEST_TYPEHASH = 0x3704fa4accb8c16eb6e68883482b3f5138cdf9f9babcb44ad96f6c8d9d339583
domainSeparator         = 0xf1bc005db40997cc4699bea62574da4aad06ebad831ee91672e1322a61c37c1a
structHash              = 0x849e81a3dd142e923266842fb5b5cb72db95fbcfe6ba909e4fb131545217368f
digest                  = 0x03be0267ae30178d9d936a7e0078bccc8ff4faefe57bac5e29070a4366e3eeb7
userSignature (r||s||v) = 0x56551c5a25e0f94174be5ca05585771139fc618bb23f8854a0a56f8d456eb62d
                            6fa3605042208a215eefa165a0e13e46900f3f7140b8e8d4b3dc0f42832caa8b1b
contentKey (Section 4)  = 0x8259d5114ee13141f7669af46c0a30346f3aa8de5ee11145992d38e12c5906e1
```

An implementation MUST reproduce every value above from the inputs. (The signature line is one 65-byte value, wrapped for display.)

### 6. Issuance Flow (Normative)

Record issuance proceeds as follows. Each step is mandatory unless noted otherwise.

1. **User signs the RecordRequest.** The user constructs a `RecordRequest` struct with the desired parameters and signs it using EIP-712. The resulting signature is `userSignature`.

2. **Issuer calls `issueRecord`.** The issuer submits a transaction calling:
   ```solidity
   function issueRecord(
       RecordRequest calldata request,
       bytes calldata userSignature
   ) external returns (bytes32 contentKey);
   ```

3. **Contract verifies issuer authorization.** The contract calls `issuerRegistry.isActiveIssuer(msg.sender)`. If this returns `false`, the transaction MUST revert with `UnauthorizedIssuer()`. An issuer is active if and only if it is registered, not paused, and not expired.

4. **Contract verifies issuer identity.** The contract checks `msg.sender == request.issuer`. If they differ, the transaction MUST revert with `IssuerMismatch()`.

5. **Contract validates the record type.** `request.recordType` MUST match `^[a-z0-9_]+$` (Section 2). If it does not, the transaction MUST revert with `InvalidRecordType()`.

6. **Contract recovers the user signer.** The contract recovers the signer address from the EIP-712 digest and `userSignature` using ECDSA recovery. If the signature is not a 65-byte canonical low-`s` ECDSA signature, or recovery fails or yields the zero address, the transaction MUST revert with `InvalidSignature()`.

7. **Contract checks the nonce.** The contract verifies `request.nonce == nonces[signer][request.node]`. If the nonce does not match, the transaction MUST revert with `InvalidNonce()`. Upon success, the nonce for that `(signer, node)` pair is incremented.

8. **Contract checks expiration.** If `request.expires != 0 && request.expires <= block.timestamp`, the transaction MUST revert with `Expired()`.

9. **Contract derives the content key.** The content key is computed as specified in Section 4.

10. **Contract writes the text record.** The contract calls `resolver.setText(node, key, value)` where:
   - `key` is formatted as specified in Section 2.
   - `value` is formatted as specified in Section 3.

11. **Contract stores the issued record.** The contract stores a mapping from `(node, issuer, keccak256(recordType))` to the resolver address and content key, enabling future revocation. If a record already exists for this triple, the new content key and resolver overwrite the previous values. Re-issuance is a last-write-wins operation that does not require prior revocation.

12. **Contract emits an event.**
    ```solidity
    event VerifiableRecordSet(
        bytes32 indexed node,
        address indexed issuer,
        bytes32 indexed contentKey,
        string recordType
    );
    ```

Name ownership is not verified at issuance: the controller checks the user's consent signature but not that the signer currently owns `request.node`. Ownership is checked at verification time (Section 7, step 10), so records issued to a non-owner never verify and records self-invalidate on name transfer. Issuers SHOULD confirm off-chain that the signer owns the name before issuing, to avoid paying gas for records that will never verify.

#### Revocation

An issuer MAY revoke a record it previously issued by calling:

```solidity
function revokeRecord(bytes32 node, string calldata recordType) external;
```

The caller MUST be the original issuer (`msg.sender`). The contract sets the text record value to the empty string and deletes the internal record. The contract emits:

```solidity
event VerifiableRecordRevoked(bytes32 indexed node, address indexed issuer, string recordType);
```

If no record exists for the given `(node, msg.sender, recordType)` triple, the transaction MUST revert with `RecordNotFound()`.

### 7. Verification Flow (Normative)

A verifier MUST perform the following steps to validate a verifiable record. All steps are required for the record to be considered valid. The issuer registry check is performed **first** to fail fast and avoid unnecessary proof fetches for revoked/expired issuers.

**Result states.** This flow classifies a record as exactly one of: **VALID** (all steps pass), **INVALID** (a cryptographic or binding check fails, or the issuer is inactive), **EXPIRED** (step 4 or step 6 fails on time), or **STALE** (step 10 ownership mismatch). Verifiers MUST treat EXPIRED and STALE records as not valid; the distinct labels support diagnostics only. The **verification context** below means the tuple the verifier set out to check: the queried `node`, the `resolver` it queried, and the `issuer` and `recordType` taken from the text record key.

1. **Get issuer info.** Call `issuerRegistry.isActiveIssuer(issuer)` — or equivalently call `getIssuer(issuer)` and require all of: the issuer is registered (the call does not revert), the issuer is not paused (`active == true` **and** not DAO-paused, see Section 10), and the issuer has not expired (`expires > currentTimestamp`). If any condition fails, the record is INVALID. This check MUST be performed before fetching any off-chain data. Obtain `specificationURI` and `verifierContract` from `getIssuer(issuer)`.

2. **Resolve the text record.** Query the ENS resolver for the text record at key `vr:{issuer}:{recordType}` on the target node.

3. **Parse the value.** Split the value into `contentKey` and `expires` as specified in Section 3. If parsing fails, the record is INVALID.

4. **Check expiration.** If `expires > 0` and `expires <= currentTimestamp`, the record is EXPIRED. Verifiers SHOULD treat expired records as invalid unless the application semantics dictate otherwise.

5. **Fetch the proof bundle.** Retrieve the proof bundle using the issuer's `specificationURI` (obtained in step 1). If `specificationURI` is a standard URI (e.g., `https://`, `ipfs://`), expand any per-record template placeholders (Section 8) and fetch the JSON document from the resulting URL. If `specificationURI` is a contract address (matching `^0x[0-9a-fA-F]{40}$`), call `IProofBundleProvider.getProofBundle(node, recordType)` on that contract and ABI-decode the result (see Section 8). If the proof bundle is unavailable, the record CANNOT be verified. Verifiers SHOULD treat this as a verification failure. See Security Considerations — Proof Bundle Fetching for transport hardening requirements.

6. **Cross-check the bundle against the verification context.** The bundle's `request` fields MUST be bound to the record actually being verified. Verifiers MUST check ALL of the following, and MUST treat the record as INVALID if any check fails:

   - `request.node` equals the queried node;
   - `namehash(request.ensName)` equals the queried node (per ENSIP-1);
   - `request.recordType` equals the `recordType` from the text record key;
   - `request.issuer` equals the `issuer` from the text record key;
   - `request.resolver` equals the resolver the text record was read from;
   - `request.expires` equals the on-chain `expires` parsed in step 3, and satisfies the step-4 expiration check. The signed `request.expires` takes precedence: the on-chain value lives in an owner-writable text record, and a mismatch means the record value was modified after issuance.

   Without these checks, a bundle for a different record — another name owned by the same signer, or another record type sharing the same `recordDataHash` — recomputes to a matching content key: the content key commits to neither `node` nor `recordType`, and the signature digest in steps 7–10 is reconstructed from the bundle's own fields.

7. **Recompute the content key.** Using the `userSignature`, `ensName`, `resolver`, `recordDataHash`, and `issuer` from the proof bundle, recompute the content key as specified in Section 4.

8. **Verify the content key.** Compare the recomputed content key with the on-chain `contentKey`. If they do not match, the record is INVALID. Alternatively, the verifier MAY call the contract's `verifyContentKey` function:
   ```solidity
   function verifyContentKey(
       bytes32 contentKey,
       RecordRequest calldata request,
       bytes calldata userSignature
   ) external pure returns (bool);
   ```

9. **Verify the issuer's proof.** Call `verifierContract.verifyProof(proof, recordDataHash, issuer)` on the issuer's verifier contract (see Section 10). If the call returns `false` or reverts, the record is INVALID.

10. **Verify name ownership.** Determine the current owner of the queried node. Implementations MUST source this lookup from the verification context, not from the bundle. Under ENSv2, the owner is obtained by traversing the registry hierarchy from the root registry to the name's parent registry and querying the ownership of the name's token — the traversal implemented by `LibRegistry.findOwner(rootRegistry, dnsEncodedName)` and exposed through the Universal Resolver. If the owner is `address(0)` (unowned or unregistered), the record is INVALID.

    Then verify the user's signature against that owner:

    - **EOA owner** (no deployed code): recover the signer from the `userSignature` and the EIP-712 typed data (Section 5). If the recovered signer does NOT match the current owner, the record is STALE — it was issued to a previous owner.
    - **Contract owner** (deployed code at the owner address): call `isValidSignature(digest, userSignature)` (ERC-1271) on the owner contract with the EIP-712 digest. If the call does not return the ERC-1271 magic value, the record is STALE. Note that the reference `VerifiableRecordController` recovers signers via ECDSA only, so records for contract-owned names can only be *issued* through a controller that supports ERC-1271 (see Security Considerations — Contract-Owned Names).

    Verifiers MUST treat ownership-mismatched records as invalid. This prevents a sold or transferred name from carrying proofs that belong to the previous owner.

    ```
    currentOwner = findOwner(rootRegistry, dnsEncode(ensName))   // ENSv2 registry traversal
    if isEOA(currentOwner):
        require(ecrecover(EIP712Digest(request), userSignature) == currentOwner)
    else:
        require(IERC1271(currentOwner).isValidSignature(EIP712Digest(request), userSignature) == 0x1626ba7e)
    ```

### 8. Proof Bundle JSON Schema

The proof bundle is a JSON document hosted at the issuer's `specificationURI` (registered in the IssuerRegistry). Bundles MUST include every field marked REQUIRED in the table below; the schema is canonical, not merely suggestive. Issuers MAY include additional fields, and verifiers MUST ignore unrecognized fields, but verifiers MUST reject a bundle missing any REQUIRED field and MUST reject a bundle whose `version` is not a value the verifier implements. This specification defines version `"1"`; extension ENSIPs MAY register additional version values (the Selective Disclosure extension registers `"1-private"`), and verifiers MUST reject versions defined by extensions they do not implement.

```json
{
  "version": "1",
  "request": {
    "node": "0x<bytes32 hex>",
    "ensName": "<string>",
    "resolver": "0x<address hex>",
    "recordType": "<string>",
    "recordDataHash": "0x<bytes32 hex>",
    "issuer": "0x<address hex>",
    "expires": "<uint64 as decimal string>",
    "nonce": "<uint256 as decimal string>"
  },
  "userSignature": "0x<hex-encoded signature>",
  "contentKey": "0x<bytes32 hex>",
  "proof": "0x<hex-encoded issuer proof>"
}
```

`expires` and `nonce` are encoded as JSON strings containing their decimal representations. `uint256` exceeds JSON's safe integer range (2^53); encoding as a string avoids silent precision loss in common JSON parsers. Verifiers MAY accept the numeric form when they can prove no precision loss occurs (e.g., when a bundle is known to originate from a language with arbitrary-precision integers), but issuers MUST emit the string form for interoperability.

Field descriptions:

| Field | Required | Description |
|-------|----------|-------------|
| `version` | REQUIRED | Schema version. MUST be `"1"` for this specification. |
| `request` | REQUIRED | The full `RecordRequest` fields, sufficient to reconstruct the EIP-712 struct hash. |
| `userSignature` | REQUIRED | The user's EIP-712 signature over the `RecordRequest`. |
| `contentKey` | REQUIRED | The derived content key. Included for convenience; verifiers MUST recompute it. |
| `proof` | REQUIRED | The issuer's proof over the record data. The encoding depends on the issuer's `verifierContract` implementation (see Section 10). |

Issuers MAY include additional fields. Verifiers MUST ignore unrecognized fields.

#### Per-Record Bundle Addressing (URI Templates)

A single static URL cannot address one bundle per record. Issuers that serve more than one record from a URI-form `specificationURI` MUST embed the template placeholders `{node}` and/or `{recordType}` in the URI. Before fetching (Section 7, step 5), verifiers MUST substitute:

- `{node}` → the queried node as a lowercase, `0x`-prefixed, 66-character hex string;
- `{recordType}` → the record type string verbatim (its `^[a-z0-9_]+$` alphabet requires no URL escaping).

**Example:** `https://issuer.example/bundles/{node}/{recordType}.json`. A `specificationURI` without placeholders identifies a single bundle document and is only appropriate for issuers with exactly one outstanding record; issuers with multiple records MUST use template placeholders or register an `IProofBundleProvider` contract (below), which receives `(node, recordType)` as call parameters.

#### On-Chain Proof Bundle Provider (`IProofBundleProvider`)

The `specificationURI` field in the Issuer Registry can be either:

- **A standard URI** (e.g., `https://`, `ipfs://`) pointing to a JSON proof bundle as described above.
- **An Ethereum contract address** -- a `0x`-prefixed, 42-character hex string (e.g., `0x1234567890abcdef1234567890abcdef12345678`).

If `specificationURI` is a contract address, verifiers MUST call `IProofBundleProvider.getProofBundle(node, recordType)` on that contract to retrieve the ABI-encoded proof bundle. The issuer is implicit — the provider contract is registered per-issuer in the Issuer Registry.

```solidity
interface IProofBundleProvider {
    function getProofBundle(
        bytes32 node,
        string calldata recordType
    ) external view returns (bytes memory);
}
```

The returned `bytes` value is `abi.encode(...)` of the following parameters in this exact order (as a flat tuple, not a struct). Each parameter is encoded per standard Solidity ABI rules — dynamic types use offset pointers, fixed-size types are padded to 32 bytes:

| Parameter | Type | Description |
|-----------|------|-------------|
| `node` | `bytes32` | ENS namehash of the name |
| `ensName` | `string` | Human-readable ENS name |
| `resolver` | `address` | Resolver contract address |
| `recordType` | `string` | Record type identifier |
| `recordDataHash` | `bytes32` | keccak256 of the record payload |
| `issuer` | `address` | Issuer's Ethereum address |
| `expires` | `uint64` | Unix timestamp; 0 = no expiration |
| `nonce` | `uint256` | Replay protection nonce |
| `userSignature` | `bytes` | The user's EIP-712 signature |
| `contentKey` | `bytes32` | The derived content key |
| `proof` | `bytes` | The issuer's proof |

The ABI schema intentionally omits `version` — the on-chain provider path is tied to this ENSIP revision. Future breaking schema revisions MUST either extend the ABI tuple (in a way that decodes without errors for current verifiers) or define a new interface identifier.

This supports **CCIP-Read (EIP-3668)**: the provider contract MAY revert with `OffchainLookup` to redirect retrieval to an off-chain gateway. This enables use cases such as L2 storage proofs, where the proof bundle is stored on an L2 chain and fetched via a CCIP-Read gateway without requiring the verifier to interact directly with the L2.

Verifiers MUST detect the format of `specificationURI` (contract address vs. URI) and use the appropriate retrieval mechanism. A value matching the case-insensitive regex `^0x[0-9a-fA-F]{40}$` MUST be treated as a contract address; all other values MUST be treated as URIs. Verifiers MUST accept both lowercase and EIP-55 checksummed contract-address forms.

### 9. Record Type Taxonomy

The Issuer Registry tracks each issuer's supported record types as a `uint256` bitmap in the `supportedRecordTypes` field. The following bit assignments are RECOMMENDED:

| Bit | Value | Record Type | Description |
|-----|-------|-------------|-------------|
| 0   | `1`   | `identity`  | Identity verification (e.g., KYC/KYB) |
| 1   | `2`   | `credential`| Professional or educational credentials |
| 2   | `4`   | `compliance`| Regulatory compliance attestations |
| 3   | `8`   | `reputation`| Reputation or trust scores |
| 4   | `16`  | `membership`| Organizational membership |
| 5-255 | --  | --          | Reserved for future use |

An issuer with `supportedRecordTypes = 5` (bits 0 and 2 set) supports `identity` and `compliance` records.

The `supportedRecordTypes` bitmap is informational metadata — it is NOT enforced by the controller during issuance. The controller accepts any `recordType` string from an active issuer. The bitmap exists so that off-chain consumers (UIs, indexers) can filter issuers by capability without parsing record keys. Implementations SHOULD maintain a consistent mapping between bits and string identifiers.

### 10. Issuer Registry

The Issuer Registry is a contract that maintains a whitelist of authorized issuers. The `VerifiableRecordController` is registry-agnostic; while a single DAO-governed registry may be deployed, the controller can be configured to trust any contract implementing the `IIssuerRegistry` interface. This allows different communities (e.g., DeFi, Gaming, Compliance) to spin up their own decentralized whitelists without requiring permission from a central authority. It provides the following capabilities:

#### Issuer Record

Each registered issuer has an associated `IssuerInfo` struct:

```solidity
struct IssuerInfo {
    string name;                          // Human-readable issuer name
    uint256 supportedRecordTypes;         // Bitmap of supported record types
    uint64 registeredAt;                  // Registration timestamp
    uint64 expires;                       // Expiration timestamp
    bool active;                          // Pause flag (see Pause Semantics below — NOT the only pause state)
    address verifierContract;             // On-chain proof verifier (REQUIRED, cannot be address(0))
    string specificationURI;              // URL or contract address for proof bundle retrieval (see Section 8)
}
```

In addition to the struct, the registry maintains a separate governance-controlled pause flag per issuer (`daoPaused`, exposed via the `isDaoPaused` view) that is **not** part of `IssuerInfo`. See Pause Semantics below.

#### Proof Verification

Every issuer MUST have an on-chain verifier contract. The `registerIssuer` function MUST revert if `verifierContract` is `address(0)`. Verifiers MUST call the issuer's `verifierContract` to validate the `proof` field from the proof bundle.

The verifier contract MUST implement the `IProofVerifier` interface:

```solidity
interface IProofVerifier {
    function verifyProof(
        bytes calldata proof,
        bytes32 recordDataHash,
        address issuer
    ) external view returns (bool);
}
```

This interface is intentionally minimal and generic. It supports any verification mechanism that can be expressed as a Solidity `view` function:

- **ECDSA proof**: Recover the signer from the proof signature and confirm it matches the issuer address.
- **ZK proof verification**: Verify a zero-knowledge proof against public inputs.
- **Multisig verification**: Check that the proof contains signatures from a quorum of co-signers.
- **CCIP-Read (EIP-3668)**: The verifier contract MAY use CCIP-Read to offload computation off-chain while returning the result on-chain.

The `proof` bytes are opaque to the protocol — their encoding is defined by the specific `IProofVerifier` implementation.

#### Pause Semantics (DAO Pause vs Self-Pause)

The registry MUST track two independent pause states per issuer:

- **`active`** (in `IssuerInfo`) — the general pause flag. Cleared by `pauseIssuer`, set by `unpauseIssuer`, and togglable by the issuer itself via `setSelfActive`.
- **`daoPaused`** (separate storage, exposed via `isDaoPaused(address)`) — the governance pause flag. Set only by `pauseIssuer` and cleared only by `unpauseIssuer` (both role-gated); the issuer itself can never modify it.

`pauseIssuer` MUST set both `daoPaused = true` and `active = false`. `unpauseIssuer` MUST clear both. `setSelfActive(true)` MUST revert (`DaoPaused()`) while `daoPaused` is set: an issuer MUST NOT be able to reverse a governance pause. A registry that implements only the single `active` flag does not conform to this specification, since a paused issuer could reactivate itself via `setSelfActive(true)`.

#### Active Issuer Check

An issuer is considered active if and only if all four conditions hold:

1. The issuer address is registered (`_registered[issuer] == true`).
2. The issuer is not governance-paused (`daoPaused == false`).
3. The issuer is not paused (`active == true`).
4. The issuer has not expired (`expires > block.timestamp`).

#### Role-Based Access Control

The Issuer Registry uses a bitmap-based role system. Roles are assigned as bits in a `uint256`:

| Role | Bit | Value | Permissions |
|------|-----|-------|-------------|
| `ROLE_ISSUER_ADMIN` | 0 | `1` | Register issuers, revoke issuers, renew issuers, grant/revoke roles |
| `ROLE_ISSUER_PAUSER` | 1 | `2` | Pause and unpause issuers |
| `ROLE_SPEC_UPDATER` | 2 | `4` | Update an issuer's `specificationURI` |

The deployer receives all three roles at construction time.

#### Registry Operations

| Function | Required Role | Description |
|----------|--------------|-------------|
| `registerIssuer(...)` | `ROLE_ISSUER_ADMIN` | Register a new issuer. Reverts if the issuer or verifier contract address is zero, the address is already registered, or the expiry is in the past. |
| `revokeIssuer(address, string reason)` | `ROLE_ISSUER_ADMIN` | Permanently remove an issuer. Deletes the `IssuerInfo` and emits `IssuerRevoked` with the reason. |
| `pauseIssuer(address)` | `ROLE_ISSUER_PAUSER` | Governance pause. Sets `daoPaused = true` **and** `active = false`. The issuer cannot reverse this (see Pause Semantics). |
| `unpauseIssuer(address)` | `ROLE_ISSUER_PAUSER` | Lift a governance pause. Sets `daoPaused = false` and `active = true`. |
| `renewIssuer(address, uint64 newExpiry)` | `ROLE_ISSUER_ADMIN` | Extend an issuer's expiration. The new expiry MUST be in the future. MUST emit `IssuerRenewed(address indexed issuer, uint64 newExpiry)`. |
| `updateSpecificationURI(address, string newURI)` | `ROLE_SPEC_UPDATER` | Replace an issuer's `specificationURI` (e.g., migrating from HTTPS hosting to an `IProofBundleProvider` contract, per the availability requirements in Security Considerations). MUST revert for unregistered issuers and MUST emit `SpecificationURIUpdated(address indexed issuer, string newURI)`. |
| `updateVerifierContract(address, address newVerifier)` | `ROLE_ISSUER_ADMIN` | Replace an issuer's `verifierContract` (e.g., migrating to a new proof scheme; see Security Considerations — Post-Quantum). MUST reject `address(0)` and MUST emit `VerifierContractUpdated(address indexed issuer, address newVerifier)`. Admin-gated: this changes proof validity for all of the issuer's outstanding records. |
| `grantRoles(address, uint256 roles)` | `ROLE_ISSUER_ADMIN` | Grant role bits to an account. MUST revert (`InvalidRoles()`) if `roles` contains any bit outside the defined role set, and MUST emit `RolesGranted(address indexed account, uint256 roles)` with the bits actually granted. |
| `revokeRoles(address, uint256 roles)` | `ROLE_ISSUER_ADMIN` | Revoke role bits from an account. MUST revert (`InvalidRoles()`) on undefined bits, MUST emit `RolesRevoked(address indexed account, uint256 roles)` with the bits actually revoked, and MUST revert if the call would remove the last remaining holder of `ROLE_ISSUER_ADMIN` (otherwise the registry becomes permanently unmaintainable). |
| `setSelfActive(bool active)` | None (caller must be issuer) | Allows a registered issuer to toggle their own `active` flag. No DAO role required — intended as an emergency kill switch so an issuer can self-deactivate without waiting for DAO intervention. `setSelfActive(true)` MUST revert with `DaoPaused()` while the issuer is governance-paused. |

#### View Functions

| Function | Description |
|----------|-------------|
| `getIssuer(address)` | Returns the full `IssuerInfo` struct. Reverts if the issuer is not registered. `daoPaused` is NOT part of the struct; callers MUST use `isActiveIssuer` or `isDaoPaused` to determine pause status. |
| `isActiveIssuer(address)` | Returns `true` if the issuer is registered, not governance-paused, not paused, and not expired (all four Active Issuer Check conditions). |
| `isDaoPaused(address)` | Returns `true` if the issuer is governance-paused. |
| `hasRoles(address, uint256)` | Returns `true` if the account holds any of the specified role bits. |

### 11. Resolver Authorization

The `VerifiableRecordController` writes text records by calling `setText` on the user's resolver. For this to succeed, the resolver MUST authorize the controller as a writer.

The ENSv2 **PublicResolverV2** supports two approval scopes:

```solidity
// RECOMMENDED — per-name delegate approval: the controller may modify
// records for this node only.
resolver.approve(node, controllerAddress, true);

// Broader — operator approval: the controller may modify records for
// every node the caller owns on this resolver.
resolver.setApprovalForAll(controllerAddress, true);
```

Users SHOULD use the per-name `approve(node, delegate, approved)` form, which confines the grant to a single name. `setApprovalForAll` remains available for users managing many names, at the cost of a wider grant.

**Security Warning: Resolver Approval Blast Radius.** Either approval grants the controller contract permission to overwrite **any record profile** on the approved name(s) — text records, content hash, and address records — not just `vr:`-prefixed keys. If the `VerifiableRecordController` contract has a vulnerability, an attacker could redirect the user's website or steal funds. Per-name approval bounds the damage to one name; it does not bound it to verifiable records. **Recommendation:** Implementations SHOULD provide a reference "Scoped Operator" wrapper contract. Users approve this wrapper instead of the controller directly. The wrapper only forwards `setText` calls to the controller if the key strictly starts with the `vr:` prefix, neutralizing the blast radius.

Implementations MAY support alternative authorization mechanisms if the resolver supports them (on legacy ENSv1 PublicResolver deployments, only `setApprovalForAll` is available). The controller itself does not enforce any particular authorization model -- it delegates entirely to the resolver's access control.

### 12. CCIP-Read / L2 Compatibility

Verifiable records are standard ENS text records. Any resolver that implements the `text(bytes32 node, string key)` function (as defined in EIP-634) is compatible, including:

- **CCIP-Read (EIP-3668) resolvers** that fetch records from off-chain data sources.
- **L2 resolvers** that bridge data from Layer 2 networks.
- **Wildcard resolvers (ENSIP-10)** that resolve records for subdomains dynamically.

No special bridge logic or resolver modifications are required. The `VerifiableRecordController` writes records via `setText`, and verifiers read them via `text` -- both standard resolver operations.

Additionally, issuers MAY register an `IProofBundleProvider` contract address as their `specificationURI` (see Section 8). This contract can use CCIP-Read to serve proof bundles from L2 storage, enabling a fully on-chain proof retrieval path for cross-chain verification scenarios. The provider contract reverts with `OffchainLookup`, and CCIP-Read-aware clients transparently follow the gateway redirect to fetch the proof bundle from the L2.

---

## Rationale

### Why Text Records?

Text records (ENSIP-5 / EIP-634) are the most widely supported and flexible record type in ENS. Every major ENS resolver already implements `text()`, and ENSv2 resolvers expose the same profile. By storing verifiable records as text records, this specification requires zero changes to existing resolver infrastructure and benefits from the entire ENS tooling ecosystem (resolution libraries, CCIP-Read, L2 bridges) without modification.

### Why Off-Chain Proofs?

Storing full proof signatures or zero-knowledge proofs on-chain would be prohibitively expensive and would leak information that some issuance flows (particularly ZK-based ones) are designed to keep private. The content key serves as a constant-size binding commitment: it is small enough to store on-chain (32 bytes, rendered as a 66-character hex string in the text record) while providing the cryptographic anchor needed for off-chain verification.

### Why Include the Resolver in the Content Key?

Including the resolver address in the content key derivation prevents a subtle attack vector: if a user migrates to a new resolver and an attacker gains write access to the old resolver, the attacker cannot transplant records. The content key computed against the new resolver will not match the one computed against the old resolver.

### Why a Separate Issuer Registry?

A dedicated registry contract (rather than, say, an allowlist inside the controller) enables:

- **Governance separation**: The DAO can manage issuer lifecycle independently of controller upgrades.
- **Shared state**: Multiple controllers or future versions can reference the same registry.
- **Rich metadata**: Issuers carry structured metadata (verifier contract, specification URI, supported types) that would be awkward to embed in the controller.
- **Decentralization**: Because the controller is registry-agnostic, multiple competing or niche registries can exist simultaneously.

### Why Nonces per (Signer, Node)?

Scoping nonces per `(signer, node)` pair rather than per signer alone lets a single signing key authorize records for many names concurrently — DAOs and organizations managing name portfolios with one key, wallets batch-receiving credentials across their names, and issuers submitting batches — without forcing a strict global ordering on the signatures. A per-signer-only nonce would serialize issuance across unrelated names: signatures would have to be produced and mined in exact sequence, and one stuck transaction would invalidate every queued signature behind it. The cost is one extra mapping dimension; same-name replay protection is identical, since each signature commits to its node and can only be consumed against that node's own sequence.

---

## Backwards Compatibility

This specification is fully backwards compatible with existing ENS infrastructure:

- **Resolvers**: Any resolver that implements `ITextResolver` (specifically the `setText` and `text` functions from ENSIP-5 / EIP-634) is compatible — including ENSv2's `PublicResolverV2` and legacy ENSv1 resolvers. No resolver upgrades are needed.
- **ENS Registry**: No changes to the ENSv2 registry contracts (or, on legacy deployments, the ENSv1 registry) are required.
- **Existing records**: Verifiable records use the `vr:` prefix to namespace them within text record keys.
- **Clients**: ENS clients that do not understand verifiable records will simply see them as opaque text records. This is by design -- verifiable records degrade gracefully to standard text records.

The only prerequisite is that the user's resolver must authorize the `VerifiableRecordController` (or a Scoped Operator wrapper) as a writer (see Section 11).

---

## Reference Implementation

The reference implementation consists of the following components in this repository:

| Component | Path | Description |
|----------|------|-------------|
| `VerifiableRecordController` | `src/VerifiableRecordController.sol` | Core controller: EIP-712 signature verification, content key derivation, resolver writes, and revocation. |
| `IVerifiableRecordController` | `src/interfaces/IVerifiableRecordController.sol` | Interface definition with events, struct, and function signatures. |
| `IssuerRegistry` | `src/IssuerRegistry.sol` | Example DAO-governed issuer whitelist with role-based access control and two-flag pause semantics (Section 10). |
| `IIssuerRegistry` | `src/interfaces/IIssuerRegistry.sol` | Interface definition for the issuer registry. |
| `IProofVerifier` | `src/interfaces/IProofVerifier.sol` | Standard interface for on-chain proof verification. |
| `IProofBundleProvider` | `src/interfaces/IProofBundleProvider.sol` | Interface for on-chain proof bundle retrieval (supports CCIP-Read for L2 storage proofs). |
| `ITextResolver` | `src/interfaces/ITextResolver.sol` | Minimal resolver interface (`setText`/`text`) the controller writes through. |
| `ECDSAProofVerifier` | `src/verifiers/ECDSAProofVerifier.sol` | Reference `IProofVerifier` implementation using domain-bound ECDSA signature recovery. |
| `ZkAgeVerifier` | `src/verifiers/ZkAgeVerifier.sol` | `IProofVerifier` adapter for Groth16 age-verification proofs over a salted Poseidon commitment (see the Selective Disclosure extension). |
| `Groth16Verifier` | `src/verifiers/Groth16Verifier.sol` | snarkjs-generated Groth16 verifier backing `ZkAgeVerifier` (demo-grade trusted setup). |
| ZK circuits | `circuits/` | Circom circuits for the salted age-verification commitment. |
| TypeScript SDK | `sdk/` | Client library implementing the issuance and verification flows (Sections 6–7). |
| Demo application | `demo/` | End-to-end walkthrough, including the selective disclosure flow. |

The test suite at `test/VerifiableRecordController_t.sol` demonstrates the complete issuance flow, authorization checks, replay protection, and copy attack prevention.

---

## Security Considerations

### Content Key Binding

The content key binds a record to a specific combination of user signature, ENS name, resolver address, record data hash, and issuer address. This prevents **copy attacks**: if an attacker copies a record value from one name's resolver to another, verification will fail because the content key will not match when recomputed with the target name and resolver.

The inclusion of the `resolver` address in the content key derivation ensures that records cannot be transplanted across resolvers — if a user migrates to a new resolver, records written to the old resolver will fail content key verification.

The content key does **not** commit to `node` or `recordType`; binding to those comes from the user's EIP-712 signature together with the mandatory verification-context cross-checks in Section 7, step 6. Those cross-checks are a required part of the copy-attack defense.

### User Consent

The user's EIP-712 signature over the `RecordRequest` ensures that records can only be created with the name owner's explicit consent. The issuer cannot unilaterally write a record -- it must present a valid user signature.

### Replay Protection

Each `(signer, node)` pair maintains a monotonically increasing nonce. The nonce is checked and incremented atomically during `issueRecord`. This prevents:

- **Replay attacks**: Resubmitting a previously used signature.
- **Reordering attacks**: Using a signature intended for a future nonce value.

Nonces are scoped per `(signer, node)` — the recovered signer address paired with the ENS namehash. Each name owned by a signer has its own independent nonce sequence, so issuance for different names does not need to be serialized; replay protection within a single name is unchanged (a signature commits to its node via EIP-712, so it can only ever be consumed against that node's sequence).

### Name Transfer Protection

When an ENS name is transferred to a new owner, existing verifiable records become stale — they attest to the previous owner, not the current one. Verifiers MUST validate the proof bundle's EIP-712 signature against the name's current owner as resolved through the ENSv2 registry hierarchy (Section 7, step 10).

### Record Value Tampering

The text record value (`{contentKey} {expires}`) lives in owner-writable resolver storage. The content key half is protected by recomputation (Section 7, steps 7–8), but the `expires` half carries no independent commitment. Section 7, step 6 therefore requires verifiers to compare the on-chain `expires` against the signed `request.expires` from the proof bundle and reject on mismatch. A verifier that trusts the on-chain `expires` alone allows the name owner to extend an expired attestation indefinitely.

### Issuer Revocation

The Issuer Registry provides multiple mechanisms to disable a compromised or misbehaving issuer:

- **Pausing**: Temporarily prevents the issuer from writing new records. Existing records remain on-chain but verifiers SHOULD check issuer status. A governance pause (`pauseIssuer`) cannot be reversed by the issuer — `setSelfActive(true)` reverts while `daoPaused` is set (see Section 10, Pause Semantics).
- **Self-deactivation**: Issuers can call `setSelfActive(false)` to immediately deactivate themselves without DAO intervention. This serves as an emergency kill switch -- for example, if an issuer detects a key compromise, it can self-deactivate before the DAO responds.
- **Revocation**: Permanently removes the issuer. The `IssuerRevoked` event includes a reason string for audit purposes.
- **Expiration**: Issuers have a built-in expiration timestamp. Expired issuers are treated as inactive.

### Off-Chain Data Availability & Link Rot

Proof bundles are stored off-chain at the issuer's `specificationURI`. If the proof bundle becomes unavailable, the record cannot be independently verified (though the on-chain content key still exists), resulting in a "Schrödinger's Attestation" — dead weight on the blockchain. To prevent link rot, availability requirements scale with record lifetime:

- For short-lived records (hours to weeks), standard HTTPS hosting is acceptable.
- For medium-lived records (months), content-addressed storage (IPFS, Arweave) is RECOMMENDED.
- For long-lived records (years or open-ended), issuers MUST register an `IProofBundleProvider` contract or use strictly content-addressed URIs (`ipfs://`, `ar://`); standard HTTPS MUST NOT be used. CCIP-Read (Section 12) allows such providers to serve bundles from L2 without bloating L1 state.

Issuers MUST publish at least one `specificationURI` that remains resolvable for the full lifetime of any record they issue. Issuers that cannot commit to this SHOULD set a conservative `expires` on every record, so that availability loss after expiration has no practical consequence. The `updateSpecificationURI` registry operation (Section 10) allows an issuer's bundle hosting to migrate without re-registration.

### Re-Issuance Semantics

Section 6, step 11, specifies that re-issuance is a last-write-wins operation: a new valid `RecordRequest` for an existing `(node, issuer, recordType)` triple overwrites the previous content key without requiring prior revocation. Re-issuance still requires a fresh user signature over an advanced nonce, so it cannot be performed unilaterally by the issuer — renewed user consent is always required.

Verifiers observing multiple historical `VerifiableRecordSet` events for the same triple MUST treat only the latest as authoritative. Indexers that retain history MUST NOT present stale content keys as currently-valid records.

### Low-Entropy Payloads

The on-chain `contentKey` and the publicly-served `userSignature` are both deterministic functions of `recordDataHash`. Either value can be used as an offline oracle for brute-force recovery of the underlying record data when the payload is drawn from a small or enumerable space — email addresses, phone numbers, legal names, or similar personal identifiers typically have 20–40 bits of effective entropy, exhaustible in seconds to hours on commodity hardware.

Issuers whose records carry such payloads SHOULD adopt the Selective Disclosure extension (ENSIP-TBD Privacy) rather than this base specification. The extension introduces a mandatory per-record salt and a redacted proof bundle so that neither the on-chain content key nor the public signature forms an exploitable oracle. Deployments that intentionally publish low-entropy facts (e.g., public username attestations) are not subject to this recommendation.

Records whose `recordDataHash` is taken over a genuinely high-entropy preimage (a random attestation ID, a content hash, or a salted/blinded commitment) are not affected by this concern. A commitment is high-entropy only if its **preimage** is. A hash or ZK commitment computed directly over a low-entropy value — for example `Poseidon(birthday)` or `keccak256(email)` — remains fully brute-forceable: the attacker enumerates candidate inputs and recomputes the commitment, exactly as for an unhashed payload. Such commitments (including ZK proof commitments) MUST incorporate a high-entropy per-record salt into the preimage to qualify as high-entropy — see ENSIP-TBD Privacy, "ZK Commitment Blinding", for the salt sizing rules per commitment scheme. Do not assume "it's a hash/ZK commitment" implies "it's safe."

### Signature Malleability

Implementations MUST reject malleable ECDSA signatures (i.e., enforce the low-`s` canonical form per EIP-2). The user's signature is an input to the content key derivation — accepting both `s`-value variants would allow an attacker to derive a different content key from the same logical signature. For ERC-1271 signatures, see Contract-Owned Names below.

### Verifier Domain Binding

`IProofVerifier` implementations MUST bind their signed payload to a domain that includes at minimum the `issuer` address and the chain/verifier identifying information (`block.chainid` and `address(this)`). A verifier whose signed preimage is just `recordDataHash` (or any value the issuer's key might plausibly sign in another context, such as a bare `personal_sign` over arbitrary bytes) is cross-context replayable: a signature the issuer produced for an unrelated protocol could be accepted as a proof here.

The reference `ECDSAProofVerifier` in this repository signs `keccak256(abi.encode(recordDataHash, issuer, block.chainid, address(this)))` wrapped in the EIP-191 personal_sign prefix. Custom verifiers SHOULD follow the same pattern or use EIP-712 with a distinct domain separator.

### Proof Bundle Fetching (SSRF)

Fetching a bundle from `specificationURI` (Section 7, step 5) makes the verifier issue network requests to an issuer-controlled location. A malicious or compromised issuer can point `specificationURI` at internal infrastructure (cloud metadata endpoints, loopback, private ranges) and use the verifier as a request proxy. Verifiers that fetch bundles server-side MUST restrict retrieval to an allowlist of schemes (`https://`, plus gateway-resolved `ipfs://` and `ar://`), SHOULD reject URLs resolving to loopback, link-local, or private address ranges, SHOULD refuse cross-host redirects, and SHOULD enforce a response-size cap and timeout (the reference SDK uses 1 MB and 10 s). Bundle JSON is attacker-supplied input; verifiers MUST validate every field against the schema in Section 8 before use.

### Contract-Owned Names (ERC-1271)

ENSv2 names may be owned by smart contracts (multisigs, smart accounts). For such names, the ownership check (Section 7, step 10) uses ERC-1271 `isValidSignature` rather than ECDSA recovery. Two consequences:

- **Issuance**: the reference `VerifiableRecordController` validates `userSignature` via ECDSA recovery only, and tracks nonces by the recovered address. Records for contract-owned names verify as STALE under the reference deployment, because the EOA that signed can never equal the contract owner. Supporting contract owners end-to-end requires a controller that accepts ERC-1271 signatures and keys nonces by the owner address. Implementations that wish to be forward-compatible (including post-quantum smart accounts, below) SHOULD support ERC-1271 at both issuance and verification.
- **Signature canonicalization**: low-`s` enforcement applies to ECDSA signatures. An ERC-1271 wallet defines validity itself and might accept multiple byte encodings of the "same" approval; since the content key binds the exact signature bytes, verifiers MUST use the exact `userSignature` bytes from the proof bundle and MUST NOT re-encode them.

### Gas Costs of Mass Revocation

Revoking a record requires the issuer to pay gas to clear the storage slot (setting it to an empty string). If an issuer needs to revoke thousands of compromised records, the gas cost could be prohibitive. Issuers SHOULD maintain an ETH reserve for emergency revocations. Future iterations of this standard may explore Merkle-root-based mass revocation to mitigate this.

### Trust Model

The on-chain infrastructure guarantees:

1. The user consented (valid EIP-712 signature).
2. The issuer was authorized at issuance time (active in the registry).
3. The record is bound to a specific name/resolver/issuer (content key).

The semantic meaning and trustworthiness of the record payload (what the `recordDataHash` represents) is application-specific and determined by the verifier's trust policy regarding the specific issuer.

### Post-Quantum Considerations

This specification is **not** post-quantum secure, a property it inherits from Ethereum and ENS rather than from its own construction. The relevant primitives divide into three groups:

- **Signatures (ECDSA / secp256k1)** — the user's `RecordRequest` consent signature and the name-ownership check (Section 7, step 10). Broken by Shor's algorithm: a quantum adversary can recover private keys from public keys and forge consent. All authenticity in this spec ultimately rests here.
- **Issuer proofs** — scheme-dependent. The reference `ECDSAProofVerifier` inherits the ECDSA weakness above; a pairing-based ZK verifier (e.g. Groth16 over BN254) additionally loses *soundness* to Shor (and BN254 already sits near ~100-bit classical security).
- **Hashes (keccak256, Poseidon)** — content key derivation and salted `recordDataHash` commitments. Affected only by Grover's algorithm, which halves effective security. A 256-bit output retains ~128-bit preimage resistance; salts SHOULD be sized so that half their bit-length remains adequate (i.e. ≥256-bit salts for a post-quantum posture). This is the most quantum-resilient layer of the design.

Migration difficulty is asymmetric, and the architecture already isolates the easy part:

- **Issuer proofs are pluggable and require no protocol change.** `IProofVerifier.verifyProof` takes the proof as opaque `bytes`, and each issuer names its own `verifierContract`. A post-quantum scheme (a STARK verifier, or a lattice-signature verifier) is adopted by deploying a new verifier and updating the issuer's registration against it (`updateVerifierContract`, Section 10) — `IssuerRegistry` and `VerifiableRecordController` are untouched.
- **User authentication is bound to ECDSA and is the hard part.** The controller verifies `userSignature` via `ECDSA.recover`, and `contentKey` binds the raw signature bytes. Whether future migration is a configuration change or a redeployment hinges on one hook: **if the controller validates `userSignature` via ERC-1271 (`isValidSignature`) in addition to `ecrecover`, a name owner can migrate to a post-quantum smart-contract account and the controller needs no change** — signature validity is delegated to the account, and the ownership check follows Ethereum's own account upgrade automatically. Without ERC-1271 support, post-quantum user signatures require a controller change. Implementations that wish to be forward-compatible SHOULD support ERC-1271 signer validation now (see Contract-Owned Names).
- **Non-upgradeable contracts raise the cost of the bound path.** The reference contracts are deployed directly (no proxy), so any change to the signature-verification path is a redeployment plus re-issuance of existing records, not an in-place upgrade.
- **Large post-quantum signatures** (e.g. Dilithium ≈ 2.4 KB) hash into `contentKey` without correctness issues, but increase calldata/storage cost and affect any off-chain path (including the Selective Disclosure `Disclosure` signature) that assumes ECDSA recovery.

Because the on-chain records and public proof bundles are permanent, deployments handling private or long-lived data SHOULD also account for **harvest-now-decrypt-later**: material transmitted today over classical TLS (and any confidentiality resting on classical key exchange) may be broken retroactively by a future quantum adversary.

---

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).

**Note for Implementers (CC0 1.0 Universal):** The authors have dedicated this work to the public domain by waiving all rights worldwide under copyright law, including related and neighboring rights. You may copy, modify, distribute, and perform the work, even for commercial purposes, without asking permission. Patent and trademark rights are unaffected, as are publicity or privacy rights. The authors make no warranties about the work and disclaim liability for all uses. When using or citing this ENSIP, you should not imply endorsement by the original authors or the ENS DAO.
