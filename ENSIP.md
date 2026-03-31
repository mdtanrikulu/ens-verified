# ENSIP-TBD: Verifiable Records for ENS

| **Author**    | TBD                           |
|---------------|-------------------------------|
| **Status**    | Draft                         |
| **Type**      | Standards Track               |
| **Created**   | 2026-03-25                    |
| **Requires**  | EIP-137, EIP-634, EIP-712    |

---

## Abstract

This ENSIP defines a protocol by which third-party **issuers** can write cryptographically verifiable attestation records to ENS names using standard text records (EIP-634). Each record contains an on-chain **content key** — a `bytes32` keccak256 binding commitment that ties the record to a specific ENS name, resolver, issuer, and user signature, preventing copy attacks across names. A DAO-governed **Issuer Registry** controls which addresses may issue records and hosts the URI from which verifiers fetch the off-chain **proof bundle**. Users authorize record creation by signing an EIP-712 typed data message, and verifiers independently validate records by recomputing the content key and checking the proof bundle.

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

### 1. Terminology

| Term | Definition |
|------|-----------|
| **Issuer** | An Ethereum address registered in the Issuer Registry that is authorized to write verifiable records on behalf of users. |
| **User** | The owner (or controller) of an ENS name who consents to a record being written by signing an EIP-712 message. |
| **Verifier** | Any party that reads a verifiable record from ENS and validates it against the on-chain content key and off-chain proof bundle. |
| **Content Key** | A `bytes32` value derived via `keccak256` that cryptographically binds a record to a specific user signature, ENS name, resolver, record data, and issuer. Stored on-chain as the first field of the text record value. |
| **Proof Bundle** | A document containing the full inputs needed to recompute the content key and verify the issuer's proof. Typically a JSON document stored off-chain at the issuer's `specificationURI`, but MAY also be served on-chain via an `IProofBundleProvider` contract when `specificationURI` is a contract address. |
| **Record Type** | A human-readable string identifier (e.g., `"identity"`, `"kyc"`, `"credential"`) that categorizes the verifiable record. |
| **Record Data Hash** | A `bytes32` keccak256 digest of the record payload. The actual payload lives in the proof bundle; only its hash appears on-chain. |
| **Node** | The ENS namehash of the name, as defined in EIP-137. |

### 2. Record Key Format

Verifiable records are stored as ENS text records (EIP-634). The text record key MUST follow this format:

```
vr:{issuerAddress}:{recordType}
```

Where:

- `vr:` is the literal prefix identifying a verifiable record.
- `{issuerAddress}` is the issuer's Ethereum address rendered as a lowercase, `0x`-prefixed, 42-character hex string. Implementations MUST use lowercase hex (not EIP-55 checksummed), as produced by OpenZeppelin's `Strings.toHexString(address)`.
- `{recordType}` is a non-empty string identifier. It MUST NOT contain the colon character (`:`).

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

**Delimiter:** Fields are separated by a single ASCII space character (`0x20`).

**Parsing algorithm:**

1. Split the value on the first space to extract `contentKey`.
2. The remainder is `expires`.

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

- `userSignature` is the raw bytes of the user's EIP-712 signature.
- `keccak256(ensName)` is the keccak256 hash of the UTF-8 encoded ENS name string (e.g., `"alice.eth"`).
- `resolver` is the resolver contract address (20 bytes, tightly packed per `abi.encodePacked`).
- `recordDataHash` is the `bytes32` hash of the record payload.
- `issuer` is the issuer address (20 bytes, tightly packed per `abi.encodePacked`).

The fixed-size portion is 104 bytes (32 + 20 + 32 + 20). Total input length is `len(userSignature) + 104`.

#### Test Vector

Given the following inputs:

| Field | Value |
|-------|-------|
| userSignature | `0xdead01` (3 bytes, for illustration) |
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
    uint256 nonce;          // Replay protection nonce
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

5. **Contract recovers the user signer.** The contract recovers the signer address from the EIP-712 digest and `userSignature` using ECDSA recovery. If recovery yields the zero address, the transaction MUST revert with `InvalidSignature()`.

6. **Contract checks the nonce.** The contract verifies `request.nonce == nonces[signer]`. If the nonce does not match, the transaction MUST revert with `InvalidNonce()`. Upon success, the nonce is incremented.

7. **Contract checks expiration.** If `request.expires != 0 && request.expires <= block.timestamp`, the transaction MUST revert with `Expired()`.

8. **Contract derives the content key.** The content key is computed as specified in Section 4.

9. **Contract writes the text record.** The contract calls `resolver.setText(node, key, value)` where:
   - `key` is formatted as specified in Section 2.
   - `value` is formatted as specified in Section 3.

10. **Contract stores the issued record.** The contract stores a mapping from `(node, issuer, keccak256(recordType))` to the resolver address and content key, enabling future revocation. If a record already exists for this triple, the new content key and resolver overwrite the previous values. Re-issuance is a last-write-wins operation that does not require prior revocation.

11. **Contract emits an event.**
    ```solidity
    event VerifiableRecordSet(
        bytes32 indexed node,
        address indexed issuer,
        bytes32 indexed contentKey,
        string recordType
    );
    ```

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

1. **Get issuer info.** Call `issuerRegistry.getIssuer(issuer)` to obtain the issuer's status and `specificationURI`. If the call reverts (issuer not registered) or `active == false`, the record is INVALID. This check MUST be performed before fetching any off-chain data.

2. **Resolve the text record.** Query the ENS resolver for the text record at key `vr:{issuer}:{recordType}` on the target node.

3. **Parse the value.** Split the value into `contentKey` and `expires` as specified in Section 3. If parsing fails, the record is INVALID.

4. **Check expiration.** If `expires > 0` and `expires <= currentTimestamp`, the record is EXPIRED. Verifiers SHOULD treat expired records as invalid unless the application semantics dictate otherwise.

5. **Fetch the proof bundle.** Retrieve the proof bundle using the issuer's `specificationURI` (obtained in step 1). If `specificationURI` is a standard URI (e.g., `https://`, `ipfs://`), fetch the JSON document from that URL. If `specificationURI` is a contract address (matching `^0x[0-9a-fA-F]{40}$`), call `IProofBundleProvider.getProofBundle(node, recordType)` on that contract and ABI-decode the result (see Section 8). If the proof bundle is unavailable, the record CANNOT be verified. Verifiers SHOULD treat this as a verification failure.

6. **Recompute the content key.** Using the `userSignature`, `ensName`, `resolver`, `recordDataHash`, and `issuer` from the proof bundle, recompute the content key as specified in Section 4.

7. **Verify the content key.** Compare the recomputed content key with the on-chain `contentKey`. If they do not match, the record is INVALID. Alternatively, the verifier MAY call the contract's `verifyContentKey` function:
   ```solidity
   function verifyContentKey(
       bytes32 contentKey,
       RecordRequest calldata request,
       bytes calldata userSignature
   ) external pure returns (bool);
   ```

8. **Verify the issuer's proof.** Call `verifierContract.verifyProof(proof, recordDataHash, issuer)` on the issuer's verifier contract (see Section 10). If the call returns `false` or reverts, the record is INVALID.

9. **Verify name ownership.** Recover the signer address from the `userSignature` and the EIP-712 typed data (Section 5). Query the ENS registry for the current owner of the `node`. If the recovered signer does NOT match the current owner, the record is STALE — it was issued to a previous owner. Verifiers MUST treat ownership-mismatched records as invalid. This prevents a sold or transferred name from carrying proofs that belong to the previous owner.

    ```
    signer = ecrecover(EIP712Digest(request), userSignature)
    currentOwner = ENSRegistry.owner(node)
    require(signer == currentOwner)
    ```

### 8. Proof Bundle JSON Schema

The proof bundle is a JSON document hosted at the issuer's `specificationURI` (registered in the IssuerRegistry). It MUST contain sufficient information for a verifier to recompute the content key and verify the issuer's proof.

The following schema is RECOMMENDED:

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
    "expires": <uint64>,
    "nonce": <uint256>
  },
  "userSignature": "0x<hex-encoded signature>",
  "contentKey": "0x<bytes32 hex>",
  "proof": "0x<hex-encoded issuer proof>"
}
```

Field descriptions:

| Field | Required | Description |
|-------|----------|-------------|
| `version` | REQUIRED | Schema version. MUST be `"1"` for this specification. |
| `request` | REQUIRED | The full `RecordRequest` fields, sufficient to reconstruct the EIP-712 struct hash. |
| `userSignature` | REQUIRED | The user's EIP-712 signature over the `RecordRequest`. |
| `contentKey` | REQUIRED | The derived content key. Included for convenience; verifiers MUST recompute it. |
| `proof` | REQUIRED | The issuer's proof over the record data. The encoding depends on the issuer's `verifierContract` implementation (see Section 10). |

Issuers MAY include additional fields. Verifiers MUST ignore unrecognized fields.

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

The returned `bytes` value is ABI-encoded with the following parameters (in order):

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

This supports **CCIP-Read (EIP-3668)**: the provider contract MAY revert with `OffchainLookup` to redirect retrieval to an off-chain gateway. This enables use cases such as L2 storage proofs, where the proof bundle is stored on an L2 chain and fetched via a CCIP-Read gateway without requiring the verifier to interact directly with the L2.

Verifiers MUST detect the format of `specificationURI` (contract address vs. URI) and use the appropriate retrieval mechanism. A value matching the regex `^0x[0-9a-fA-F]{40}$` MUST be treated as a contract address.

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

The Issuer Registry is a DAO-governed contract that maintains a whitelist of authorized issuers. It provides the following capabilities:

#### Issuer Record

Each registered issuer has an associated `IssuerInfo` struct:

```solidity
struct IssuerInfo {
    string name;                          // Human-readable issuer name
    uint256 supportedRecordTypes;         // Bitmap of supported record types
    uint64 registeredAt;                  // Registration timestamp
    uint64 expires;                       // Expiration timestamp
    bool active;                          // Pause flag
    address verifierContract;             // On-chain proof verifier (REQUIRED, cannot be address(0))
    string specificationURI;              // URL or contract address for proof bundle retrieval (see Section 8)
}
```

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

#### Active Issuer Check

An issuer is considered active if and only if all three conditions hold:

1. The issuer address is registered (`_registered[issuer] == true`).
2. The issuer is not paused (`active == true`).
3. The issuer has not expired (`expires > block.timestamp`).

#### Role-Based Access Control

The Issuer Registry uses a bitmap-based role system. Roles are assigned as bits in a `uint256`:

| Role | Bit | Value | Permissions |
|------|-----|-------|-------------|
| `ROLE_ISSUER_ADMIN` | 0 | `1` | Register issuers, revoke issuers, renew issuers, grant/revoke roles |
| `ROLE_ISSUER_PAUSER` | 1 | `2` | Pause and unpause issuers |
| `ROLE_SPEC_UPDATER` | 2 | `4` | Reserved for future use |

The deployer receives all three roles at construction time.

#### Registry Operations

| Function | Required Role | Description |
|----------|--------------|-------------|
| `registerIssuer(...)` | `ROLE_ISSUER_ADMIN` | Register a new issuer. Reverts if the issuer or verifier contract address is zero, the address is already registered, or the expiry is in the past. |
| `revokeIssuer(address, string reason)` | `ROLE_ISSUER_ADMIN` | Permanently remove an issuer. Deletes the `IssuerInfo` and emits `IssuerRevoked` with the reason. |
| `pauseIssuer(address)` | `ROLE_ISSUER_PAUSER` | Temporarily deactivate an issuer. Sets `active = false`. The issuer can be unpaused later. |
| `unpauseIssuer(address)` | `ROLE_ISSUER_PAUSER` | Reactivate a paused issuer. Sets `active = true`. |
| `renewIssuer(address, uint64 newExpiry)` | `ROLE_ISSUER_ADMIN` | Extend an issuer's expiration. The new expiry MUST be in the future. |
| `grantRoles(address, uint256 roles)` | `ROLE_ISSUER_ADMIN` | Grant role bits to an account. |
| `revokeRoles(address, uint256 roles)` | `ROLE_ISSUER_ADMIN` | Revoke role bits from an account. |
| `setSelfActive(bool active)` | None (caller must be issuer) | Allows a registered issuer to toggle their own `active` flag. No DAO role required — intended as an emergency kill switch so an issuer can self-deactivate without waiting for DAO intervention. |

#### View Functions

| Function | Description |
|----------|-------------|
| `getIssuer(address)` | Returns the full `IssuerInfo` struct. Reverts if the issuer is not registered. |
| `isActiveIssuer(address)` | Returns `true` if the issuer is registered, not paused, and not expired. |
| `hasRoles(address, uint256)` | Returns `true` if the account holds any of the specified role bits. |

### 11. Resolver Authorization

The `VerifiableRecordController` writes text records by calling `setText` on the user's resolver. For this to succeed, the resolver MUST authorize the controller as a writer.

For the ENS **PublicResolver** (and any resolver supporting operator approval), the user MUST call:

```solidity
resolver.setApprovalForAll(controllerAddress, true);
```

This grants the controller permission to write records on the user's behalf for all names managed by that resolver. This is a one-time operation per resolver.

Implementations MAY support alternative authorization mechanisms (e.g., per-name approval) if the resolver supports them. The controller itself does not enforce any particular authorization model -- it delegates entirely to the resolver's access control.

### 12. CCIP-Read / L2 Compatibility

Verifiable records are standard ENS text records. Any resolver that implements the `text(bytes32 node, string key)` function (as defined in EIP-634) is compatible, including:

- **CCIP-Read (EIP-3668) resolvers** that fetch records from off-chain data sources.
- **L2 resolvers** that bridge data from Layer 2 networks.
- **Wildcard resolvers (ENSIP-10)** that resolve records for subdomains dynamically.

No special bridge logic or resolver modifications are required. The `VerifiableRecordController` writes records via `setText`, and verifiers read them via `text` -- both standard resolver operations.

Additionally, issuers MAY register an `IProofBundleProvider` contract address as their `specificationURI` (see Section 8). This contract can use CCIP-Read to serve proof bundles from L2 storage, enabling a fully on-chain proof retrieval path for cross-chain verification scenarios. The provider contract reverts with `OffchainLookup`, and CCIP-Read-aware clients transparently follow the gateway redirect to fetch the proof bundle from the L2.

### 13. Security Considerations

#### Content Key Binding

The content key binds a record to a specific combination of user signature, ENS name, resolver address, record data hash, and issuer address. This prevents **copy attacks**: if an attacker copies a record value from one name's resolver to another, verification will fail because the content key will not match when recomputed with the target name and resolver.

The inclusion of the `resolver` address in the content key derivation ensures that records cannot be transplanted across resolvers — if a user migrates to a new resolver, records written to the old resolver will fail content key verification.

#### User Consent

The user's EIP-712 signature over the `RecordRequest` ensures that records can only be created with the name owner's explicit consent. The issuer cannot unilaterally write a record -- it must present a valid user signature.

#### Replay Protection

Each user address maintains a monotonically increasing nonce. The nonce is checked and incremented atomically during `issueRecord`. This prevents:

- **Replay attacks**: Resubmitting a previously used signature.
- **Reordering attacks**: Using a signature intended for a future nonce value.

Nonces are tracked per signer address (the recovered address from the EIP-712 signature), not per ENS name. This means a single user address has a single nonce sequence across all names it controls.

#### Name Transfer Protection

When an ENS name is transferred to a new owner, existing verifiable records become stale — they attest to the previous owner, not the current one. Verifiers MUST recover the signer from the proof bundle's EIP-712 signature and compare it against the current ENS registry owner (Section 7, step 9).

#### Issuer Revocation

The Issuer Registry provides multiple mechanisms to disable a compromised or misbehaving issuer:

- **Pausing**: Temporarily prevents the issuer from writing new records. Existing records remain on-chain but verifiers SHOULD check issuer status.
- **Self-deactivation**: Issuers can call `setSelfActive(false)` to immediately deactivate themselves without DAO intervention. This serves as an emergency kill switch -- for example, if an issuer detects a key compromise, it can self-deactivate before the DAO responds.
- **Revocation**: Permanently removes the issuer. The `IssuerRevoked` event includes a reason string for audit purposes.
- **Expiration**: Issuers have a built-in expiration timestamp. Expired issuers are treated as inactive.

#### Off-Chain Data Availability

Proof bundles are stored off-chain at the issuer's `specificationURI` (registered in the IssuerRegistry). If the proof bundle becomes unavailable, the record cannot be independently verified (though the on-chain content key still exists). Issuers SHOULD use durable storage for proof bundles to mitigate availability risks.

#### Signature Malleability

Implementations MUST reject malleable signatures (i.e., enforce the low-`s` canonical form per EIP-2). The user's signature is an input to the content key derivation — accepting both `s`-value variants would allow an attacker to derive a different content key from the same logical signature.

#### Trust Model

The on-chain infrastructure guarantees:

1. The user consented (valid EIP-712 signature).
2. The issuer was authorized at issuance time (active in the registry).
3. The record is bound to a specific name/resolver/issuer (content key).

The semantic meaning and trustworthiness of the record payload (what the `recordDataHash` represents) is application-specific and determined by the verifier's trust policy regarding the specific issuer.

---

## Rationale

### Why Text Records?

Text records (EIP-634) are the most widely supported and flexible record type in ENS. Every major ENS resolver already implements `text()`. By storing verifiable records as text records, this specification requires zero changes to existing resolver infrastructure and benefits from the entire ENS tooling ecosystem (resolution libraries, CCIP-Read, L2 bridges) without modification.

### Why Off-Chain Proofs?

Storing full proof signatures or zero-knowledge proofs on-chain would be prohibitively expensive and would leak information that some issuance flows (particularly ZK-based ones) are designed to keep private. The content key serves as a constant-size binding commitment: it is small enough to store on-chain (32 bytes, rendered as a 66-character hex string in the text record) while providing the cryptographic anchor needed for off-chain verification.

### Why Include the Resolver in the Content Key?

Including the resolver address in the content key derivation prevents a subtle attack vector: if a user migrates to a new resolver and an attacker gains write access to the old resolver, the attacker cannot transplant records. The content key computed against the new resolver will not match the one computed against the old resolver.

### Why a Separate Issuer Registry?

A dedicated registry contract (rather than, say, an allowlist inside the controller) enables:

- **Governance separation**: The DAO can manage issuer lifecycle independently of controller upgrades.
- **Shared state**: Multiple controllers or future versions can reference the same registry.
- **Rich metadata**: Issuers carry structured metadata (verifier contract, specification URI, supported types) that would be awkward to embed in the controller.

### Why Nonces per Signer (Not per Name)?

Tracking nonces per recovered signer address rather than per `(signer, node)` pair simplifies the implementation and reduces storage costs. The tradeoff is that issuance across different names is serialized for a given signer. In practice, verifiable record issuance is an infrequent operation and this serialization is not a bottleneck.

---

## Backwards Compatibility

This specification is fully backwards compatible with existing ENS infrastructure:

- **Resolvers**: Any resolver that implements `ITextResolver` (specifically the `setText` and `text` functions from EIP-634) is compatible. No resolver upgrades are needed.
- **ENS Registry**: No changes to the ENS registry contract are required.
- **Existing records**: Verifiable records use the `vr:` prefix to namespace them within text record keys.
- **Clients**: ENS clients that do not understand verifiable records will simply see them as opaque text records. This is by design -- verifiable records degrade gracefully to standard text records.

The only prerequisite is that the user's resolver must authorize the `VerifiableRecordController` as a writer (see Section 11).

---

## Reference Implementation

The reference implementation consists of the following contracts in this repository:

| Contract | Path | Description |
|----------|------|-------------|
| `VerifiableRecordController` | `src/VerifiableRecordController.sol` | Core controller: EIP-712 signature verification, content key derivation, resolver writes, and revocation. |
| `IVerifiableRecordController` | `src/interfaces/IVerifiableRecordController.sol` | Interface definition with events, struct, and function signatures. |
| `IssuerRegistry` | `src/IssuerRegistry.sol` | DAO-governed issuer whitelist with role-based access control. |
| `IIssuerRegistry` | `src/interfaces/IIssuerRegistry.sol` | Interface definition for the issuer registry. |
| `IProofVerifier` | `src/interfaces/IProofVerifier.sol` | Standard interface for on-chain proof verification. |
| `IProofBundleProvider` | `src/interfaces/IProofBundleProvider.sol` | Interface for on-chain proof bundle retrieval (supports CCIP-Read for L2 storage proofs). |
| `ECDSAProofVerifier` | `src/verifiers/ECDSAProofVerifier.sol` | Reference `IProofVerifier` implementation using ECDSA signature recovery. |

The test suite at `test/VerifiableRecordController_t.sol` demonstrates the complete issuance flow, authorization checks, replay protection, and copy attack prevention.

---

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
