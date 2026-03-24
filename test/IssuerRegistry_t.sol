// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {IIssuerRegistry} from "../src/interfaces/IIssuerRegistry.sol";

contract IssuerRegistryTest is Test {
    IssuerRegistry public registry;

    address admin = address(this);
    address issuer = makeAddr("issuer");
    address nonAdmin = makeAddr("nonAdmin");
    address pauser = makeAddr("pauser");

    uint64 defaultExpiry;

    function setUp() public {
        registry = new IssuerRegistry();
        defaultExpiry = uint64(block.timestamp + 365 days);

        // Grant pauser role
        registry.grantRoles(pauser, registry.ROLE_ISSUER_PAUSER());
    }

    // ── Registration ────────────────────────────────────────────────────

    function test_registerIssuer_withAdminRole() public {
        registry.registerIssuer(
            issuer,
            "Test Issuer",
            1, // bit 0 = identity
            IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION,
            defaultExpiry,
            address(0),
            "ipfs://spec"
        );

        IIssuerRegistry.IssuerInfo memory info = registry.getIssuer(issuer);
        assertEq(info.name, "Test Issuer");
        assertEq(info.supportedRecordTypes, 1);
        assertEq(uint8(info.verificationMode), uint8(IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION));
        assertTrue(info.active);
        assertEq(info.expires, defaultExpiry);
        assertEq(info.specificationURI, "ipfs://spec");
    }

    function test_Revert_registerIssuer_withoutAdminRole() public {
        vm.prank(nonAdmin);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );
    }

    function test_Revert_registerIssuer_zeroAddress() public {
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        registry.registerIssuer(
            address(0),
            "Test Issuer",
            1,
            IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION,
            defaultExpiry,
            address(0),
            ""
        );
    }

    function test_Revert_registerIssuer_alreadyRegistered() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        vm.expectRevert(IssuerRegistry.AlreadyRegistered.selector);
        registry.registerIssuer(
            issuer,
            "Test Issuer 2",
            1,
            IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION,
            defaultExpiry,
            address(0),
            ""
        );
    }

    function test_Revert_registerIssuer_invalidExpiry() public {
        vm.expectRevert(IssuerRegistry.InvalidExpiry.selector);
        registry.registerIssuer(
            issuer,
            "Test Issuer",
            1,
            IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION,
            uint64(block.timestamp), // not strictly greater
            address(0),
            ""
        );
    }

    // ── Revocation ──────────────────────────────────────────────────────

    function test_revokeIssuer() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        registry.revokeIssuer(issuer, "misbehavior");
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_Revert_revokeIssuer_notRegistered() public {
        vm.expectRevert(IssuerRegistry.NotRegistered.selector);
        registry.revokeIssuer(issuer, "reason");
    }

    // ── Pause / Unpause ─────────────────────────────────────────────────

    function test_pauseIssuer() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        vm.prank(pauser);
        registry.pauseIssuer(issuer);

        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_unpauseIssuer() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        vm.prank(pauser);
        registry.pauseIssuer(issuer);
        assertFalse(registry.isActiveIssuer(issuer));

        vm.prank(pauser);
        registry.unpauseIssuer(issuer);
        assertTrue(registry.isActiveIssuer(issuer));
    }

    // ── isActiveIssuer edge cases ───────────────────────────────────────

    function test_isActiveIssuer_returnsFalseWhenExpired() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        assertTrue(registry.isActiveIssuer(issuer));

        // Warp past expiry
        vm.warp(defaultExpiry + 1);
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_isActiveIssuer_returnsFalseWhenPaused() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        vm.prank(pauser);
        registry.pauseIssuer(issuer);
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_isActiveIssuer_returnsFalseWhenRevoked() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        registry.revokeIssuer(issuer, "bad actor");
        assertFalse(registry.isActiveIssuer(issuer));
    }

    function test_isActiveIssuer_returnsFalseWhenNeverRegistered() public {
        assertFalse(registry.isActiveIssuer(makeAddr("unknown")));
    }

    // ── Renewal ─────────────────────────────────────────────────────────

    function test_renewIssuer() public {
        registry.registerIssuer(
            issuer, "Test Issuer", 1, IIssuerRegistry.VerificationMode.ECDSA_ATTESTATION, defaultExpiry, address(0), ""
        );

        uint64 newExpiry = defaultExpiry + 365 days;
        registry.renewIssuer(issuer, newExpiry);

        IIssuerRegistry.IssuerInfo memory info = registry.getIssuer(issuer);
        assertEq(info.expires, newExpiry);
    }

    // ── Role management ─────────────────────────────────────────────────

    function test_grantRoles() public {
        registry.grantRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        assertTrue(registry.hasRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN()));
    }

    function test_Revert_grantRoles_byNonAdmin() public {
        uint256 adminRole = registry.ROLE_ISSUER_ADMIN();
        vm.prank(nonAdmin);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.grantRoles(nonAdmin, adminRole);
    }

    function test_revokeRoles() public {
        registry.grantRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        assertTrue(registry.hasRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN()));

        registry.revokeRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN());
        assertFalse(registry.hasRoles(nonAdmin, registry.ROLE_ISSUER_ADMIN()));
    }
}
