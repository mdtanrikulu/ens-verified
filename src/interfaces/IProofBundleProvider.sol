// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IProofBundleProvider
/// @notice Interface for on-chain proof bundle retrieval.
///         Issuers MAY register a contract address as their `specificationURI`
///         to serve proof bundles on-chain (e.g., via CCIP-Read for L2 storage proofs).
interface IProofBundleProvider {
    /// @notice Retrieve the proof bundle for a given record.
    /// @param node The ENS namehash of the name.
    /// @param recordType The record type identifier.
    /// @return The ABI-encoded proof bundle.
    function getProofBundle(bytes32 node, string calldata recordType) external view returns (bytes memory);
}
