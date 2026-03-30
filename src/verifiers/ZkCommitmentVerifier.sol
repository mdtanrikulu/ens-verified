// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/// @notice Interface matching the snarkjs-generated Groth16 verifier.
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[1] calldata _pubSignals
    ) external view returns (bool);
}

/// @title ZkCommitmentVerifier
/// @notice IProofVerifier adapter for Groth16 ZK proofs.
///         Proof bytes encode (pA, pB, pC). The public signal (commitment) is
///         derived from recordDataHash, not carried in the proof bytes.
contract ZkCommitmentVerifier is IProofVerifier {
    IGroth16Verifier public immutable groth16Verifier;

    constructor(address _groth16Verifier) {
        groth16Verifier = IGroth16Verifier(_groth16Verifier);
    }

    /// @inheritdoc IProofVerifier
    function verifyProof(
        bytes calldata proof,
        bytes32 recordDataHash,
        address /* issuer */
    ) external view returns (bool) {
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        uint256[1] memory pubSignals;
        pubSignals[0] = uint256(recordDataHash);

        return groth16Verifier.verifyProof(pA, pB, pC, pubSignals);
    }
}
