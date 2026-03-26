// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/// @title ECDSAProofVerifier
/// @notice Reference verifier for ECDSA-signed proofs.
///         Recovers the signer from the proof signature and checks it matches the issuer.
contract ECDSAProofVerifier is IProofVerifier {
    /// @inheritdoc IProofVerifier
    function verifyProof(
        bytes calldata proof,
        bytes32 recordDataHash,
        address issuer
    ) external pure returns (bool) {
        address signer = ECDSA.recover(
            MessageHashUtils.toEthSignedMessageHash(recordDataHash),
            proof
        );
        return signer == issuer;
    }
}
