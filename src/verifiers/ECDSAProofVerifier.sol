// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/// @title ECDSAProofVerifier
/// @notice Reference verifier for ECDSA-signed proofs.
///         The issuer signs `keccak256(abi.encode(recordDataHash, issuer, chainId, address(this)))`
///         wrapped in the EIP-191 personal_sign prefix. The domain binding (issuer, chainId, verifier
///         contract) prevents a signature produced for this verifier from being reused as a proof in
///         another verifier or another chain, and prevents an unrelated `personal_sign` by the issuer's
///         key from being accepted as a proof.
contract ECDSAProofVerifier is IProofVerifier {
    /// @inheritdoc IProofVerifier
    function verifyProof(bytes calldata proof, bytes32 recordDataHash, address issuer) external view returns (bool) {
        bytes32 digest = keccak256(abi.encode(recordDataHash, issuer, block.chainid, address(this)));
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), proof);
        return signer == issuer;
    }
}
