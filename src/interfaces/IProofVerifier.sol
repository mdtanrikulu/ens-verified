// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IProofVerifier
/// @notice Standard interface for on-chain proof verification.
///         Issuers register a verifier contract in the IssuerRegistry.
///         Verifiers call it to validate the proof from a proof bundle.
///         Compatible with CCIP-Read (EIP-3668) for off-chain computation.
interface IProofVerifier {
    /// @notice Verify an issuer's proof over a record data hash.
    /// @param proof  The raw proof bytes from the proof bundle.
    /// @param recordDataHash  The keccak256 hash of the attested payload.
    /// @param issuer  The issuer address that produced the proof.
    /// @return True if the proof is valid.
    function verifyProof(
        bytes calldata proof,
        bytes32 recordDataHash,
        address issuer
    ) external view returns (bool);
}
