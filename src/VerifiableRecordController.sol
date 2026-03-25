// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IVerifiableRecordController} from "./interfaces/IVerifiableRecordController.sol";
import {IIssuerRegistry} from "./interfaces/IIssuerRegistry.sol";
import {ITextResolver} from "./interfaces/ITextResolver.sol";

/// @title VerifiableRecordController
/// @notice Orchestrates key derivation and resolver writes on behalf of authorized issuers.
///         Proof data (ECDSA attestations / ZK proofs) lives off-chain at the issuer's
///         specificationURI (from IssuerRegistry) — verifiers query the registry first,
///         then fetch and verify against the on-chain content key.
contract VerifiableRecordController is IVerifiableRecordController, EIP712 {
    using Strings for uint256;
    using Strings for address;

    // ── Constants ────────────────────────────────────────────────────────
    bytes32 public constant RECORD_REQUEST_TYPEHASH = keccak256(
        "RecordRequest(bytes32 node,string ensName,address resolver,string recordType,bytes32 recordDataHash,address issuer,uint64 expires,uint256 nonce)"
    );

    // ── Immutables ──────────────────────────────────────────────────────
    IIssuerRegistry public immutable issuerRegistry;

    // ── Storage ─────────────────────────────────────────────────────────
    mapping(address => uint256) public nonces;

    struct IssuedRecord {
        address resolver;
        bytes32 contentKey;
        bool exists;
    }

    mapping(bytes32 => mapping(address => mapping(bytes32 => IssuedRecord))) private _issuedRecords;

    // ── Errors ──────────────────────────────────────────────────────────
    error UnauthorizedIssuer();
    error IssuerMismatch();
    error InvalidSignature();
    error InvalidNonce();
    error Expired();
    error RecordNotFound();

    // ── Constructor ─────────────────────────────────────────────────────
    constructor(address _issuerRegistry) EIP712("ENS Verifiable Records", "1") {
        issuerRegistry = IIssuerRegistry(_issuerRegistry);
    }

    // ── Core functions ──────────────────────────────────────────────────

    /// @inheritdoc IVerifiableRecordController
    function issueRecord(RecordRequest calldata request, bytes calldata userSignature)
        external
        returns (bytes32 contentKey)
    {
        if (!issuerRegistry.isActiveIssuer(msg.sender)) revert UnauthorizedIssuer();
        if (msg.sender != request.issuer) revert IssuerMismatch();

        address signer = _recoverSigner(request, userSignature);
        if (signer == address(0)) revert InvalidSignature();

        if (request.nonce != nonces[signer]) revert InvalidNonce();
        unchecked {
            nonces[signer]++;
        }

        // expires == 0 means no expiration
        if (request.expires != 0 && request.expires <= block.timestamp) revert Expired();

        contentKey = _deriveContentKey(request, userSignature);

        _writeToResolver(request, contentKey);

        _issuedRecords[request.node][msg.sender][keccak256(bytes(request.recordType))] =
            IssuedRecord({resolver: request.resolver, contentKey: contentKey, exists: true});

        emit VerifiableRecordSet(request.node, msg.sender, contentKey, request.recordType);
    }

    /// @inheritdoc IVerifiableRecordController
    function revokeRecord(bytes32 node, string calldata recordType) external {
        bytes32 typeHash = keccak256(bytes(recordType));
        IssuedRecord memory record = _issuedRecords[node][msg.sender][typeHash];
        if (!record.exists) revert RecordNotFound();

        ITextResolver resolver = ITextResolver(record.resolver);
        resolver.setText(node, _buildRecordKey(msg.sender, recordType), "");

        delete _issuedRecords[node][msg.sender][typeHash];

        emit VerifiableRecordRevoked(node, msg.sender, recordType);
    }

    /// @inheritdoc IVerifiableRecordController
    function computeContentKey(RecordRequest calldata request, bytes calldata userSignature)
        external
        pure
        returns (bytes32)
    {
        return _deriveContentKey(request, userSignature);
    }

    /// @inheritdoc IVerifiableRecordController
    function verifyContentKey(bytes32 contentKey, RecordRequest calldata request, bytes calldata userSignature)
        external
        pure
        returns (bool)
    {
        return contentKey == _deriveContentKey(request, userSignature);
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// @dev Derives a content key by hashing: userSignature ‖ keccak256(ensName) ‖ resolver(20) ‖ recordDataHash ‖ issuer(20).
    ///      Matches abi.encodePacked layout: addresses are 20 bytes (no padding). Fixed portion = 104 bytes.
    function _deriveContentKey(RecordRequest calldata request, bytes calldata userSignature)
        internal
        pure
        returns (bytes32 result)
    {
        bytes32 nameHash = keccak256(bytes(request.ensName));
        address resolver = request.resolver;
        bytes32 dataHash = request.recordDataHash;
        address issuerAddr = request.issuer;

        assembly {
            let sigLen := userSignature.length
            let totalLen := add(sigLen, 104) // 32 + 20 + 32 + 20
            let buf := mload(0x40)

            // Copy userSignature from calldata
            calldatacopy(buf, userSignature.offset, sigLen)

            let p := add(buf, sigLen)
            mstore(p, nameHash) // [+0,  +32): nameHash
            mstore(add(p, 0x20), shl(96, resolver)) // [+32, +52): resolver (20 bytes) + 12 zero bytes
            mstore(add(p, 0x34), dataHash) // [+52, +84): recordDataHash (overwrites zeros)
            mstore(add(p, 0x54), shl(96, issuerAddr)) // [+84, +104): issuer (20 bytes)

            result := keccak256(buf, totalLen)
        }
    }

    /// @dev Recovers the user signer from an EIP-712 typed data signature.
    ///      Uses assembly to build the 9-slot (288 byte) struct hash in a single keccak256.
    function _recoverSigner(RecordRequest calldata request, bytes calldata signature) internal view returns (address) {
        bytes32 structHash;
        bytes32 typehash = RECORD_REQUEST_TYPEHASH;
        bytes32 nameHash = keccak256(bytes(request.ensName));
        bytes32 typeHash_ = keccak256(bytes(request.recordType));
        assembly {
            let buf := mload(0x40)
            mstore(buf, typehash)
            mstore(add(buf, 0x20), calldataload(request)) // node
            mstore(add(buf, 0x40), nameHash)
            mstore(add(buf, 0x60), calldataload(add(request, 0x40))) // resolver (padded)
            mstore(add(buf, 0x80), typeHash_)
            mstore(add(buf, 0xa0), calldataload(add(request, 0x80))) // recordDataHash
            mstore(add(buf, 0xc0), calldataload(add(request, 0xa0))) // issuer (padded)
            mstore(add(buf, 0xe0), calldataload(add(request, 0xc0))) // expires (padded)
            mstore(add(buf, 0x100), calldataload(add(request, 0xe0))) // nonce
            structHash := keccak256(buf, 0x120) // 9 × 32 = 288 bytes
        }
        bytes32 digest = _hashTypedDataV4(structHash);
        return ECDSA.recover(digest, signature);
    }

    /// @dev Writes the verifiable record to the resolver as a text record.
    ///      Record value format: "{contentKey} {expires}"
    ///        - contentKey: 66-char hex string (0x + 64 hex digits), the keccak256 binding commitment
    ///        - expires:    decimal digits (Unix timestamp), "0" means no expiration
    ///      Delimiter is a single ASCII space (0x20). Fields are positional.
    ///      Proof bundle URI is obtained from IssuerRegistry.specificationURI, not stored on-chain.
    function _writeToResolver(RecordRequest calldata request, bytes32 contentKey) internal {
        ITextResolver resolver = ITextResolver(request.resolver);
        string memory key = _buildRecordKey(request.issuer, request.recordType);
        string memory value =
            string.concat(uint256(contentKey).toHexString(32), " ", uint256(request.expires).toString());
        resolver.setText(request.node, key, value);
    }

    function _buildRecordKey(address issuer, string calldata recordType) internal pure returns (string memory) {
        return string.concat("vr:", issuer.toHexString(), ":", recordType);
    }
}
