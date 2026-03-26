// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifiableRecordController {
    /// @notice Emitted when a verifiable record is written to a resolver
    event VerifiableRecordSet(
        bytes32 indexed node, address indexed issuer, bytes32 indexed contentKey, string recordType
    );

    /// @notice Emitted when a verifiable record is revoked
    event VerifiableRecordRevoked(bytes32 indexed node, address indexed issuer, string recordType);

    /// @notice EIP-712 typed record request
    struct RecordRequest {
        bytes32 node;
        string ensName;
        address resolver;
        string recordType;
        bytes32 recordDataHash;
        address issuer;
        uint64 expires;
        uint256 nonce;
    }

    /// @notice Issue a verifiable record.
    ///         Proof data (ECDSA proof or ZK proof) is stored off-chain at the issuer's
    ///         specificationURI (registered in IssuerRegistry) — verifiers query the registry
    ///         and fetch the proof independently.
    function issueRecord(RecordRequest calldata request, bytes calldata userSignature)
        external
        returns (bytes32 contentKey);

    /// @notice Revoke a previously issued record
    function revokeRecord(bytes32 node, string calldata recordType) external;

    /// @notice Compute a content key without writing it
    function computeContentKey(RecordRequest calldata request, bytes calldata userSignature)
        external
        pure
        returns (bytes32);

    /// @notice Verify that a content key is valid for the given inputs
    function verifyContentKey(bytes32 contentKey, RecordRequest calldata request, bytes calldata userSignature)
        external
        pure
        returns (bool);
}
