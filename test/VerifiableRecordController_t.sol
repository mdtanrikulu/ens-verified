// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {VerifiableRecordController} from "../src/VerifiableRecordController.sol";
import {IIssuerRegistry} from "../src/interfaces/IIssuerRegistry.sol";
import {IVerifiableRecordController} from "../src/interfaces/IVerifiableRecordController.sol";

import {MockResolver} from "./mocks/MockResolver.sol";
import {ECDSAProofVerifier} from "../src/verifiers/ECDSAProofVerifier.sol";

contract VerifiableRecordControllerTest is Test {
    using Strings for address;
    using Strings for uint256;

    IssuerRegistry public registry;
    VerifiableRecordController public controller;
    MockResolver public resolverAlice;
    MockResolver public resolverMallory;
    ECDSAProofVerifier public verifier;

    uint256 userPrivateKey = 0xA11CE;
    address user;
    uint256 issuerPrivateKey = 0x155DE8;
    address issuer;
    address nonIssuer = makeAddr("nonIssuer");

    bytes32 node = keccak256("alice.eth");
    bytes32 malloryNode = keccak256("mallory.eth");
    string ensName = "alice.eth";
    string recordType = "identity";
    bytes32 recordDataHash = keccak256("credential-payload");
    uint64 defaultExpiry;

    function setUp() public {
        user = vm.addr(userPrivateKey);
        issuer = vm.addr(issuerPrivateKey);
        defaultExpiry = uint64(block.timestamp + 365 days);

        registry = new IssuerRegistry();
        controller = new VerifiableRecordController(address(registry));
        resolverAlice = new MockResolver();
        resolverMallory = new MockResolver();
        verifier = new ECDSAProofVerifier();

        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    function _buildRequest() internal view returns (IVerifiableRecordController.RecordRequest memory) {
        return IVerifiableRecordController.RecordRequest({
            node: node,
            ensName: ensName,
            resolver: address(resolverAlice),
            recordType: recordType,
            recordDataHash: recordDataHash,
            issuer: issuer,
            expires: defaultExpiry,
            nonce: controller.nonces(user)
        });
    }

    function _signRequest(IVerifiableRecordController.RecordRequest memory request, uint256 privateKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                controller.RECORD_REQUEST_TYPEHASH(),
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

        bytes32 domainSeparator = _computeDomainSeparator();
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ENS Verifiable Records"),
                keccak256("1"),
                block.chainid,
                address(controller)
            )
        );
    }

    function _issueDefault() internal returns (bytes32 contentKey) {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);
        contentKey = controller.computeContentKey(request, userSig);

        vm.prank(issuer);
        controller.issueRecord(request, userSig);
    }

    // ── Happy path ──────────────────────────────────────────────────────

    function test_issueRecord_happyPath() public {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);
        bytes32 expectedKey = controller.computeContentKey(request, userSig);

        vm.prank(issuer);
        bytes32 returnedKey = controller.issueRecord(request, userSig);

        assertEq(returnedKey, expectedKey);

        // Verify text record: "{contentKey} {expires}"
        string memory key = string.concat("vr:", issuer.toHexString(), ":", recordType);
        string memory expected =
            string.concat(uint256(expectedKey).toHexString(32), " ", uint256(defaultExpiry).toString());
        assertEq(resolverAlice.text(node, key), expected);
    }

    // ── Authorization failures ──────────────────────────────────────────

    function test_Revert_issueRecord_unauthorizedIssuer() public {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        request.issuer = nonIssuer;
        bytes memory userSig = _signRequest(request, userPrivateKey);

        vm.prank(nonIssuer);
        vm.expectRevert(VerifiableRecordController.UnauthorizedIssuer.selector);
        controller.issueRecord(request, userSig);
    }

    function test_Revert_issueRecord_issuerMismatch() public {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);

        registry.registerIssuer(nonIssuer, "Other", 1, defaultExpiry, address(verifier), "");

        vm.prank(nonIssuer);
        vm.expectRevert(VerifiableRecordController.IssuerMismatch.selector);
        controller.issueRecord(request, userSig);
    }

    function test_Revert_issueRecord_expiredIssuer() public {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);

        vm.warp(defaultExpiry + 1);

        vm.prank(issuer);
        vm.expectRevert(VerifiableRecordController.UnauthorizedIssuer.selector);
        controller.issueRecord(request, userSig);
    }

    // ── Signature failures ──────────────────────────────────────────────

    function test_Revert_issueRecord_invalidUserSignature() public {
        // Issue once to bump user nonce to 1
        _issueDefault();

        // Sign new request (nonce=1) with wrong key — recovered address has nonce 0
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory badSig = _signRequest(request, 0xBAD);

        vm.prank(issuer);
        vm.expectRevert(VerifiableRecordController.InvalidNonce.selector);
        controller.issueRecord(request, badSig);
    }

    // ── Replay protection ───────────────────────────────────────────────

    function test_Revert_issueRecord_replayedNonce() public {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);

        vm.prank(issuer);
        controller.issueRecord(request, userSig);

        vm.prank(issuer);
        vm.expectRevert(VerifiableRecordController.InvalidNonce.selector);
        controller.issueRecord(request, userSig);
    }

    // ── Optional expiry ──────────────────────────────────────────────────

    function test_issueRecord_noExpiry() public {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        request.expires = 0; // no expiration
        bytes memory userSig = _signRequest(request, userPrivateKey);

        vm.prank(issuer);
        bytes32 contentKey = controller.issueRecord(request, userSig);

        string memory key = string.concat("vr:", issuer.toHexString(), ":", recordType);
        string memory expected = string.concat(uint256(contentKey).toHexString(32), " ", uint256(0).toString());
        assertEq(resolverAlice.text(node, key), expected);
    }

    // ── Content key properties ──────────────────────────────────────────

    function test_computeContentKey_deterministic() public view {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);

        assertEq(controller.computeContentKey(request, userSig), controller.computeContentKey(request, userSig));
    }

    function test_verifyContentKey_validInputs() public view {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);

        bytes32 contentKey = controller.computeContentKey(request, userSig);
        assertTrue(controller.verifyContentKey(contentKey, request, userSig));
    }

    function test_verifyContentKey_differentResolver_fails() public view {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);
        bytes32 contentKey = controller.computeContentKey(request, userSig);

        request.resolver = address(resolverMallory);
        assertFalse(controller.verifyContentKey(contentKey, request, userSig));
    }

    function test_verifyContentKey_differentName_fails() public view {
        IVerifiableRecordController.RecordRequest memory request = _buildRequest();
        bytes memory userSig = _signRequest(request, userPrivateKey);
        bytes32 contentKey = controller.computeContentKey(request, userSig);

        request.ensName = "mallory.eth";
        assertFalse(controller.verifyContentKey(contentKey, request, userSig));
    }

    // ── Copy attack ─────────────────────────────────────────────────────

    function test_copyAttack_fails() public {
        // Issue for Alice
        IVerifiableRecordController.RecordRequest memory aliceRequest = _buildRequest();
        bytes memory aliceSig = _signRequest(aliceRequest, userPrivateKey);
        bytes32 aliceContentKey = controller.computeContentKey(aliceRequest, aliceSig);

        vm.prank(issuer);
        controller.issueRecord(aliceRequest, aliceSig);

        // Mallory copies Alice's content key to her resolver
        string memory baseKey = string.concat("vr:", issuer.toHexString(), ":", recordType);
        resolverMallory.setText(malloryNode, baseKey, vm.toString(aliceContentKey));

        // Recompute with Mallory's params — key won't match
        IVerifiableRecordController.RecordRequest memory malloryRequest = IVerifiableRecordController.RecordRequest({
            node: malloryNode,
            ensName: "mallory.eth",
            resolver: address(resolverMallory),
            recordType: recordType,
            recordDataHash: recordDataHash,
            issuer: issuer,
            expires: defaultExpiry,
            nonce: 0
        });

        bytes32 malloryRecomputedKey = controller.computeContentKey(malloryRequest, aliceSig);
        assertTrue(malloryRecomputedKey != aliceContentKey);
        assertFalse(controller.verifyContentKey(aliceContentKey, malloryRequest, aliceSig));
    }

    // ── Revocation ──────────────────────────────────────────────────────

    function test_revokeRecord_byIssuer() public {
        _issueDefault();

        string memory key = string.concat("vr:", issuer.toHexString(), ":", recordType);
        assertTrue(bytes(resolverAlice.text(node, key)).length > 0);

        vm.prank(issuer);
        controller.revokeRecord(node, recordType);

        assertEq(resolverAlice.text(node, key), "");
    }

    function test_Revert_revokeRecord_byNonIssuer() public {
        vm.prank(nonIssuer);
        vm.expectRevert(VerifiableRecordController.RecordNotFound.selector);
        controller.revokeRecord(node, recordType);
    }
}
