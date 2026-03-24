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
///         Proof data (ECDSA attestations / ZK proofs) lives off-chain at the contentURI —
///         verifiers fetch it and verify independently against the on-chain content key.
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
    function issueRecord(RecordRequest calldata request, bytes calldata userSignature, string calldata contentURI)
        external
        returns (bytes32 contentKey)
    {
        if (!issuerRegistry.isActiveIssuer(msg.sender)) revert UnauthorizedIssuer();
        if (msg.sender != request.issuer) revert IssuerMismatch();

        address signer = _recoverSigner(request, userSignature);
        if (signer == address(0)) revert InvalidSignature();

        if (request.nonce != nonces[signer]) revert InvalidNonce();
        nonces[signer]++;

        // expires == 0 means no expiration
        if (request.expires != 0 && request.expires <= block.timestamp) revert Expired();

        contentKey = _deriveContentKey(request, userSignature);

        _writeToResolver(request, contentKey, contentURI);

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

    function _deriveContentKey(RecordRequest calldata request, bytes calldata userSignature)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                userSignature,
                keccak256(bytes(request.ensName)),
                request.resolver,
                request.recordDataHash,
                request.issuer
            )
        );
    }

    function _recoverSigner(RecordRequest calldata request, bytes calldata signature) internal view returns (address) {
        bytes32 structHash = keccak256(
            abi.encode(
                RECORD_REQUEST_TYPEHASH,
                request.node,
                keccak256(bytes(request.ensName)),
                request.resolver,
                keccak256(bytes(request.recordType)),
                request.recordDataHash,
                request.issuer,
                request.expires,
                request.nonce
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        return ECDSA.recover(digest, signature);
    }

    function _writeToResolver(RecordRequest calldata request, bytes32 contentKey, string calldata contentURI) internal {
        ITextResolver resolver = ITextResolver(request.resolver);
        string memory key = _buildRecordKey(request.issuer, request.recordType);
        // Format: "{contentKey} {expires} {contentURI}" — expires is "0" when unset
        string memory value = string.concat(
            uint256(contentKey).toHexString(32), " ", uint256(request.expires).toString(), " ", contentURI
        );
        resolver.setText(request.node, key, value);
    }

    function _buildRecordKey(address issuer, string calldata recordType) internal pure returns (string memory) {
        return string.concat("vr:", issuer.toHexString(), ":", recordType);
    }
}
