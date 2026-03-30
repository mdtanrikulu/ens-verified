// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/// @notice Interface matching the snarkjs-generated Groth16 verifier for age verification.
///         Public signals: [birthdayHash, isAdult, currentDate]
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool);
}

/// @title ZkAgeVerifier
/// @notice IProofVerifier adapter for Groth16 age-verification ZK proofs.
///
///         The circuit proves that the prover knows a birthday such that:
///         1. Poseidon(birthday) == birthdayHash  (binds to recordDataHash)
///         2. currentDate - birthday >= 18 years  (age check)
///
///         Proof bytes encode: (pA, pB, pC, currentDate).
///         The verifier reconstructs public signals as:
///           [0] birthdayHash = uint256(recordDataHash)
///           [1] isAdult      = 1  (enforced — proof rejected if 0)
///           [2] currentDate  = decoded from proof bytes
///
///         The currentDate must not be in the future (prevents replay with
///         a far-future date that would make anyone appear 18+).
contract ZkAgeVerifier is IProofVerifier {
    IGroth16Verifier public immutable groth16Verifier;

    /// @notice Maximum clock skew tolerance (5 minutes)
    uint256 public constant MAX_CLOCK_DRIFT = 300;

    constructor(address _groth16Verifier) {
        groth16Verifier = IGroth16Verifier(_groth16Verifier);
    }

    /// @inheritdoc IProofVerifier
    function verifyProof(
        bytes calldata proof,
        bytes32 recordDataHash,
        address /* issuer */
    )
        external
        view
        returns (bool)
    {
        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC, uint256 currentDate) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2], uint256));

        // Reject proofs with a future currentDate (with small clock drift tolerance)
        if (currentDate > block.timestamp + MAX_CLOCK_DRIFT) {
            return false;
        }

        // Reconstruct public signals: [birthdayHash, isAdult, currentDate]
        uint256[3] memory pubSignals;
        pubSignals[0] = uint256(recordDataHash); // birthdayHash
        pubSignals[1] = 1; // isAdult must be 1
        pubSignals[2] = currentDate;

        return groth16Verifier.verifyProof(pA, pB, pC, pubSignals);
    }
}
