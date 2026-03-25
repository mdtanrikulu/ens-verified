// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {VerifiableRecordController} from "../src/VerifiableRecordController.sol";
import {IVerifiableRecordController} from "../src/interfaces/IVerifiableRecordController.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";

/// @dev Proves that the assembly-optimized _deriveContentKey produces the same
///      result as a naive abi.encodePacked implementation.
contract ContentKeyEquivalenceTest is Test {
    VerifiableRecordController controller;

    function setUp() public {
        IssuerRegistry registry = new IssuerRegistry();
        controller = new VerifiableRecordController(address(registry));
    }

    function _referenceContentKey(
        IVerifiableRecordController.RecordRequest memory request,
        bytes memory userSignature
    ) internal pure returns (bytes32) {
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

    function test_assemblyMatchesEncodePacked() public view {
        IVerifiableRecordController.RecordRequest memory request = IVerifiableRecordController.RecordRequest({
            node: keccak256("alice.eth"),
            ensName: "alice.eth",
            resolver: address(0x1111111111111111111111111111111111111111),
            recordType: "identity",
            recordDataHash: bytes32(uint256(0xdeadbeef)),
            issuer: address(0x2222222222222222222222222222222222222222),
            expires: 1735689600,
            nonce: 0
        });

        bytes memory userSig = hex"dead01";
        bytes32 expected = _referenceContentKey(request, userSig);
        bytes32 optimized = controller.computeContentKey(request, userSig);

        assertEq(optimized, expected, "Assembly must match abi.encodePacked");
    }

    function test_assemblyMatchesEncodePacked_realSignature() public view {
        IVerifiableRecordController.RecordRequest memory request = IVerifiableRecordController.RecordRequest({
            node: keccak256("test.eth"),
            ensName: "test.eth",
            resolver: address(0xdead),
            recordType: "credential",
            recordDataHash: keccak256("payload"),
            issuer: address(0xbeef),
            expires: 0,
            nonce: 42
        });

        // 65-byte signature (typical ECDSA)
        bytes memory userSig = abi.encodePacked(
            bytes32(uint256(1)), bytes32(uint256(2)), uint8(27)
        );

        bytes32 expected = _referenceContentKey(request, userSig);
        bytes32 optimized = controller.computeContentKey(request, userSig);

        assertEq(optimized, expected, "Assembly must match abi.encodePacked for 65-byte sig");
    }
}
