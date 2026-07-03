// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {IIssuerRegistry} from "../src/interfaces/IIssuerRegistry.sol";
import {ECDSAProofVerifier} from "../src/verifiers/ECDSAProofVerifier.sol";

contract IssuerRegistryTest is Test {
    IssuerRegistry public registry;
    ECDSAProofVerifier public verifier;

    address admin = address(this);
    address issuer = makeAddr("issuer");
    address nonAdmin = makeAddr("nonAdmin");
    address pauser = makeAddr("pauser");

    uint64 defaultExpiry;

    function setUp() public {
        registry = new IssuerRegistry();
        verifier = new ECDSAProofVerifier();
        defaultExpiry = uint64(block.timestamp + 365 days);

        // Grant pauser role
        registry.grantRoles(pauser, registry.ROLE_ISSUER_PAUSER());
    }

    // ── Registration ────────────────────────────────────────────────────

    function test_registerIssuer_withAdminRole() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "ipfs://spec");

        IIssuerRegistry.IssuerInfo memory info = registry.getIssuer(issuer);
        assertEq(info.name, "Test Issuer");
        assertEq(info.supportedRecordTypes, 1);
        assertTrue(info.active);
        assertEq(info.expires, defaultExpiry);
        assertEq(info.verifierContract, address(verifier));
        assertEq(info.specificationURI, "ipfs://spec");
    }

    function test_Revert_registerIssuer_withoutAdminRole() public {
        vm.prank(nonAdmin);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");
    }

    function test_Revert_registerIssuer_zeroIssuerAddress() public {
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        registry.registerIssuer(address(0), "Test Issuer", 1, defaultExpiry, address(verifier), "");
    }

    function test_Revert_registerIssuer_zeroVerifierContract() public {
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(0), "");
    }

    function test_Revert_registerIssuer_alreadyRegistered() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        vm.expectRevert(IssuerRegistry.AlreadyRegistered.selector);
        registry.registerIssuer(issuer, "Test Issuer 2", 1, defaultExpiry, address(verifier), "");
    }

    function test_Revert_registerIssuer_invalidExpiry() public {
        vm.expectRevert(IssuerRegistry.InvalidExpiry.selector);
        registry.registerIssuer(
            issuer,
            "Test Issuer",
            1,
            uint64(block.timestamp), // not strictly greater
            address(verifier),
            ""
        );
    }

    // ── Revocation ──────────────────────────────────────────────────────

    function test_revokeIssuer() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        registry.revokeIssuer(issuer, "misbehavior");
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_Revert_revokeIssuer_notRegistered() public {
        vm.expectRevert(IssuerRegistry.NotRegistered.selector);
        registry.revokeIssuer(issuer, "reason");
    }

    // ── Pause / Unpause ─────────────────────────────────────────────────

    function test_pauseIssuer() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        vm.prank(pauser);
        registry.pauseIssuer(issuer);

        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_unpauseIssuer() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        vm.prank(pauser);
        registry.pauseIssuer(issuer);
        assertFalse(registry.isActiveIssuer(issuer));

        vm.prank(pauser);
        registry.unpauseIssuer(issuer);
        assertTrue(registry.isActiveIssuer(issuer));
    }

    // ── isActiveIssuer edge cases ───────────────────────────────────────

    function test_isActiveIssuer_returnsFalseWhenExpired() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        assertTrue(registry.isActiveIssuer(issuer));

        // Warp past expiry
        vm.warp(defaultExpiry + 1);
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_isActiveIssuer_returnsFalseWhenPaused() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        vm.prank(pauser);
        registry.pauseIssuer(issuer);
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_isActiveIssuer_returnsFalseWhenRevoked() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        registry.revokeIssuer(issuer, "bad actor");
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_isActiveIssuer_returnsFalseWhenNeverRegistered() public {
        assertFalse(registry.isActiveIssuer(makeAddr("unknown")));
    }

    // ── Self-activation (emergency kill switch) ─────────────────────

    function test_setSelfActive_deactivate() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        assertTrue(registry.isActiveIssuer(issuer));

        vm.prank(issuer);
        registry.setSelfActive(false);
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_setSelfActive_reactivate() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        vm.prank(issuer);
        registry.setSelfActive(false);
        assertFalse(registry.isActiveIssuer(issuer));

        vm.prank(issuer);
        registry.setSelfActive(true);
        assertTrue(registry.isActiveIssuer(issuer));
    }

    function test_Revert_setSelfActive_notRegistered() public {
        vm.prank(nonAdmin);
        vm.expectRevert(IssuerRegistry.NotRegistered.selector);
        registry.setSelfActive(false);
    }

    // ── DAO pause cannot be undone by the issuer (regression for pause-bypass) ──

    function test_Revert_setSelfActive_cannotClearDaoPause() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        // DAO pauser pauses the (malicious) issuer.
        vm.prank(pauser);
        registry.pauseIssuer(issuer);
        assertFalse(registry.isActiveIssuer(issuer));
        assertTrue(registry.isDaoPaused(issuer));

        // The issuer attempting to self-reactivate MUST revert — the DAO pause holds.
        vm.prank(issuer);
        vm.expectRevert(IssuerRegistry.DaoPaused.selector);
        registry.setSelfActive(true);

        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_setSelfActive_deactivateAllowedWhileDaoPaused() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        vm.prank(pauser);
        registry.pauseIssuer(issuer);

        // Self-deactivation is always allowed (it never re-enables the issuer).
        vm.prank(issuer);
        registry.setSelfActive(false);
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_unpauseIssuer_restoresAfterAttemptedBypass() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        vm.prank(pauser);
        registry.pauseIssuer(issuer);

        // Only the DAO pauser can lift the pause.
        vm.prank(pauser);
        registry.unpauseIssuer(issuer);
        assertFalse(registry.isDaoPaused(issuer));
        assertTrue(registry.isActiveIssuer(issuer));
    }

    // ── Renewal ─────────────────────────────────────────────────────────

    function test_renewIssuer() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");

        uint64 newExpiry = defaultExpiry + 365 days;
        registry.renewIssuer(issuer, newExpiry);

        IIssuerRegistry.IssuerInfo memory info = registry.getIssuer(issuer);
        assertEq(info.expires, newExpiry);
    }

    // ── updateSpecificationURI / updateVerifierContract ─────────────────

    function test_updateSpecificationURI() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "ipfs://old");

        vm.expectEmit(true, false, false, true);
        emit IIssuerRegistry.SpecificationURIUpdated(issuer, "https://issuer.example/bundles/{node}/{recordType}.json");
        registry.updateSpecificationURI(issuer, "https://issuer.example/bundles/{node}/{recordType}.json");

        IIssuerRegistry.IssuerInfo memory info = registry.getIssuer(issuer);
        assertEq(info.specificationURI, "https://issuer.example/bundles/{node}/{recordType}.json");
    }

    function test_Revert_updateSpecificationURI_withoutRole() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "ipfs://old");
        vm.prank(nonAdmin);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.updateSpecificationURI(issuer, "ipfs://new");
    }

    function test_Revert_updateSpecificationURI_notRegistered() public {
        vm.expectRevert(IssuerRegistry.NotRegistered.selector);
        registry.updateSpecificationURI(issuer, "ipfs://new");
    }

    function test_updateSpecificationURI_specUpdaterRoleSuffices() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "ipfs://old");
        registry.grantRoles(nonAdmin, registry.ROLE_SPEC_UPDATER());

        vm.prank(nonAdmin);
        registry.updateSpecificationURI(issuer, "ipfs://new");
        assertEq(registry.getIssuer(issuer).specificationURI, "ipfs://new");
    }

    function test_updateVerifierContract() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");
        ECDSAProofVerifier newVerifier = new ECDSAProofVerifier();

        vm.expectEmit(true, false, false, true);
        emit IIssuerRegistry.VerifierContractUpdated(issuer, address(newVerifier));
        registry.updateVerifierContract(issuer, address(newVerifier));

        assertEq(registry.getIssuer(issuer).verifierContract, address(newVerifier));
    }

    function test_Revert_updateVerifierContract_zeroAddress() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        registry.updateVerifierContract(issuer, address(0));
    }

    function test_Revert_updateVerifierContract_notRegistered() public {
        vm.expectRevert(IssuerRegistry.NotRegistered.selector);
        registry.updateVerifierContract(issuer, address(verifier));
    }

    function test_Revert_updateVerifierContract_specUpdaterRoleInsufficient() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");
        registry.grantRoles(nonAdmin, registry.ROLE_SPEC_UPDATER());

        address verifierAddr = address(verifier);
        vm.prank(nonAdmin);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.updateVerifierContract(issuer, verifierAddr);
    }

    // ── Role management ─────────────────────────────────────────────────

    function test_grantRoles() public {
        vm.expectEmit(true, false, false, true);
        emit IIssuerRegistry.RolesGranted(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        registry.grantRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        assertTrue(registry.hasRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN()));
    }

    function test_Revert_grantRoles_undefinedBits() public {
        vm.expectRevert(IssuerRegistry.InvalidRoles.selector);
        registry.grantRoles(nonAdmin, 1 << 3);
    }

    function test_Revert_revokeRoles_undefinedBits() public {
        vm.expectRevert(IssuerRegistry.InvalidRoles.selector);
        registry.revokeRoles(nonAdmin, 1 << 200);
    }

    function test_revokeRoles_emitsEvent() public {
        registry.grantRoles(nonAdmin, registry.ROLE_SPEC_UPDATER());
        vm.expectEmit(true, false, false, true);
        emit IIssuerRegistry.RolesRevoked(nonAdmin, registry.ROLE_SPEC_UPDATER());
        registry.revokeRoles(nonAdmin, registry.ROLE_SPEC_UPDATER());
    }

    function test_grantRoles_alreadyHeld_noEvent() public {
        registry.grantRoles(nonAdmin, registry.ROLE_SPEC_UPDATER());
        // second grant of the same bit is a no-op: no event, count unchanged
        vm.recordLogs();
        registry.grantRoles(nonAdmin, registry.ROLE_SPEC_UPDATER());
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_Revert_grantRoles_byNonAdmin() public {
        uint256 adminRole = registry.ROLE_ISSUER_ADMIN();
        vm.prank(nonAdmin);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.grantRoles(nonAdmin, adminRole);
    }

    function test_revokeRoles() public {
        // Grant admin to a second account first so we can revoke from the
        // deployer without tripping the last-admin safeguard.
        registry.grantRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        assertTrue(registry.hasRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN()));

        registry.revokeRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        assertFalse(registry.hasRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN()));
    }

    // ── renewIssuer negative path + event ───────────────────────────────

    function test_Revert_renewIssuer_pastExpiry() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");
        vm.expectRevert(IssuerRegistry.InvalidExpiry.selector);
        registry.renewIssuer(issuer, uint64(block.timestamp));
    }

    function test_renewIssuer_emitsEvent() public {
        registry.registerIssuer(issuer, "Test Issuer", 1, defaultExpiry, address(verifier), "");
        uint64 newExpiry = defaultExpiry + 365 days;

        vm.expectEmit(true, false, false, true);
        emit IIssuerRegistry.IssuerRenewed(issuer, newExpiry);
        registry.renewIssuer(issuer, newExpiry);
    }

    // ── Last-admin safeguard ────────────────────────────────────────────

    function test_Revert_revokeRoles_lastAdmin_onSelf() public {
        // Deployer is the only admin. Attempting to revoke their own admin MUST revert.
        uint256 adminRole = registry.ROLE_ISSUER_ADMIN();
        vm.expectRevert(IssuerRegistry.LastAdminProtected.selector);
        registry.revokeRoles(address(this), adminRole);
    }

    function test_revokeRoles_lastAdmin_allowedAfterGrantingSecond() public {
        // Grant admin to nonAdmin, then the deployer can safely drop their own admin.
        registry.grantRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        registry.revokeRoles(address(this), registry.ROLE_ISSUER_ADMIN());
        assertFalse(registry.hasRoles(address(this), registry.ROLE_ISSUER_ADMIN()));
        assertTrue(registry.hasRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN()));
    }

    function test_Revert_revokeRoles_lastAdmin_onOther() public {
        // If we grant admin to someone and then try to revoke it from them while
        // the deployer also holds admin, it's fine (there are two admins).
        registry.grantRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        registry.revokeRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());

        // Now only the deployer is admin. Attempting to revoke their admin via
        // the deployer themselves MUST revert.
        uint256 adminRole = registry.ROLE_ISSUER_ADMIN();
        vm.expectRevert(IssuerRegistry.LastAdminProtected.selector);
        registry.revokeRoles(address(this), adminRole);
    }
}
