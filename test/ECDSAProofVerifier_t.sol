// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ECDSAProofVerifier} from "../src/verifiers/ECDSAProofVerifier.sol";

/// @notice Exercises the domain binding of ECDSAProofVerifier (ENSIP Section 13 — Verifier Domain Binding).
///         The signed preimage is keccak256(abi.encode(recordDataHash, issuer, chainId, verifierAddr))
///         wrapped in the EIP-191 personal_sign prefix.
contract ECDSAProofVerifierTest is Test {
    ECDSAProofVerifier public verifier;
    ECDSAProofVerifier public otherVerifier;

    uint256 issuerKey = 0x155DE8;
    address issuer;

    bytes32 recordDataHash = keccak256("payload");

    function setUp() public {
        issuer = vm.addr(issuerKey);
        verifier = new ECDSAProofVerifier();
        otherVerifier = new ECDSAProofVerifier();
    }

    function _signFor(ECDSAProofVerifier v, address issuerAddr, bytes32 dataHash, uint256 chainId)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = keccak256(abi.encode(dataHash, issuerAddr, chainId, address(v)));
        bytes32 ethDigest = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 sigV, bytes32 r, bytes32 s) = vm.sign(issuerKey, ethDigest);
        return abi.encodePacked(r, s, sigV);
    }

    function test_verifyProof_happyPath() public view {
        bytes memory proof = _signFor(verifier, issuer, recordDataHash, block.chainid);
        assertTrue(verifier.verifyProof(proof, recordDataHash, issuer));
    }

    function test_verifyProof_wrongRecordDataHash_fails() public view {
        bytes memory proof = _signFor(verifier, issuer, recordDataHash, block.chainid);
        assertFalse(verifier.verifyProof(proof, keccak256("different"), issuer));
    }

    function test_verifyProof_wrongIssuerArg_fails() public view {
        bytes memory proof = _signFor(verifier, issuer, recordDataHash, block.chainid);
        address impostor = vm.addr(0xBEEF);
        // Proof was over `issuer` — asking the verifier to validate it for `impostor` must fail.
        assertFalse(verifier.verifyProof(proof, recordDataHash, impostor));
    }

    function test_verifyProof_crossVerifier_fails() public view {
        // Signed for `otherVerifier`; `verifier` must reject (address(this) differs).
        bytes memory proof = _signFor(otherVerifier, issuer, recordDataHash, block.chainid);
        assertFalse(verifier.verifyProof(proof, recordDataHash, issuer));
    }

    function test_verifyProof_crossChain_fails() public view {
        // Sign for a chain id that differs from block.chainid.
        bytes memory proof = _signFor(verifier, issuer, recordDataHash, block.chainid + 1);
        assertFalse(verifier.verifyProof(proof, recordDataHash, issuer));
    }

    function test_verifyProof_barePersonalSignReuse_fails() public view {
        // Old (pre-binding) format: personal_sign over the raw recordDataHash.
        // Under the new verifier this MUST NOT be accepted as a valid proof.
        bytes32 ethDigest = MessageHashUtils.toEthSignedMessageHash(recordDataHash);
        (uint8 sigV, bytes32 r, bytes32 s) = vm.sign(issuerKey, ethDigest);
        bytes memory oldStyleProof = abi.encodePacked(r, s, sigV);
        assertFalse(verifier.verifyProof(oldStyleProof, recordDataHash, issuer));
    }
}
