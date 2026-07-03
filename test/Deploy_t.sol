// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";

/// @dev Exposes Deploy's internal helpers for unit testing without broadcasting.
contract DeployHarness is Deploy {
    function deployRegistry() external returns (IssuerRegistry) {
        return new IssuerRegistry(); // this harness becomes the sole admin
    }

    function handoff(IssuerRegistry r, address governance, address deployer) external {
        _handoffGovernance(r, governance, deployer);
    }

    function validate(address a) external view returns (address) {
        return address(_validateExistingRegistry(a));
    }
}

contract DeployTest is Test {
    DeployHarness harness;

    function setUp() public {
        harness = new DeployHarness();
    }

    function test_handoff_transfersRootOfTrustToGovernance() public {
        IssuerRegistry registry = harness.deployRegistry();
        address governance = address(new IssuerRegistry()); // any address with code

        // Before: harness (deployer) is admin, governance is not.
        assertTrue(registry.hasRoles(address(harness), registry.ROLE_ISSUER_ADMIN()));
        assertFalse(registry.hasRoles(governance, registry.ROLE_ISSUER_ADMIN()));

        harness.handoff(registry, governance, address(harness));

        // After: governance holds the full role set, deployer holds none.
        assertTrue(registry.hasRoles(governance, registry.ROLE_ISSUER_ADMIN()));
        assertTrue(registry.hasRoles(governance, registry.ROLE_ISSUER_PAUSER()));
        assertTrue(registry.hasRoles(governance, registry.ROLE_SPEC_UPDATER()));
        assertFalse(registry.hasRoles(address(harness), registry.ROLE_ISSUER_ADMIN()));
        assertFalse(registry.hasRoles(address(harness), registry.ROLE_ISSUER_PAUSER()));
        assertFalse(registry.hasRoles(address(harness), registry.ROLE_SPEC_UPDATER()));
    }

    function test_Revert_handoff_governanceWithoutCode() public {
        IssuerRegistry registry = harness.deployRegistry();
        vm.expectRevert(bytes("ADMIN_GOVERNANCE has no code (expected multisig/timelock)"));
        harness.handoff(registry, makeAddr("eoaMultisig"), address(harness));
    }

    function test_validateExistingRegistry_acceptsRealRegistry() public {
        IssuerRegistry registry = new IssuerRegistry();
        assertEq(harness.validate(address(registry)), address(registry));
    }

    function test_Revert_validateExistingRegistry_codelessAddress() public {
        vm.expectRevert(bytes("REGISTRY_ADDRESS has no code"));
        harness.validate(makeAddr("notAContract"));
    }
}
