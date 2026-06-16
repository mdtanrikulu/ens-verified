// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {VerifiableRecordController} from "../src/VerifiableRecordController.sol";
import {IIssuerRegistry} from "../src/interfaces/IIssuerRegistry.sol";

/// @notice Deploys the IssuerRegistry (or reuses an existing one) and the
///         VerifiableRecordController, then optionally hands the registry's
///         root-of-trust roles to a governance address (multisig/timelock).
///
/// Environment variables:
///   REGISTRY_ADDRESS  (optional) reuse an existing IssuerRegistry instead of deploying one.
///                     Validated to contain code and expose the IIssuerRegistry interface.
///   ADMIN_GOVERNANCE  (optional) if set when deploying a fresh registry, all roles are
///                     granted to this address and the deployer renounces its own roles,
///                     so the deployer EOA is not left as the sole root of trust.
contract Deploy is Script {
    function run() external {
        address existingRegistry = vm.envOr("REGISTRY_ADDRESS", address(0));
        address governance = vm.envOr("ADMIN_GOVERNANCE", address(0));

        vm.startBroadcast();
        address deployer = msg.sender;

        IssuerRegistry registry;
        if (existingRegistry == address(0)) {
            registry = new IssuerRegistry();
            console.log("IssuerRegistry deployed at:", address(registry));

            if (governance != address(0)) {
                _handoffGovernance(registry, governance, deployer);
            } else {
                console.log("WARNING: deployer retains sole root-of-trust roles.");
                console.log("         Set ADMIN_GOVERNANCE to hand off to a multisig/timelock,");
                console.log("         or grant a second admin and renounce manually post-deploy.");
            }
        } else {
            registry = _validateExistingRegistry(existingRegistry);
            console.log("Using existing IssuerRegistry at:", address(registry));
        }

        VerifiableRecordController controller = new VerifiableRecordController(address(registry));
        console.log("VerifiableRecordController deployed at:", address(controller));

        vm.stopBroadcast();
    }

    /// @dev Grants the full role set to `governance` and renounces the deployer's roles.
    ///      Safe against the last-admin guard: the new admin is granted before the
    ///      deployer's admin is revoked.
    function _handoffGovernance(IssuerRegistry registry, address governance, address deployer) internal {
        require(governance.code.length > 0, "ADMIN_GOVERNANCE has no code (expected multisig/timelock)");

        uint256 allRoles = registry.ROLE_ISSUER_ADMIN() | registry.ROLE_ISSUER_PAUSER() | registry.ROLE_SPEC_UPDATER();

        registry.grantRoles(governance, allRoles);
        registry.revokeRoles(deployer, allRoles);

        require(registry.hasRoles(governance, registry.ROLE_ISSUER_ADMIN()), "handoff: governance not admin");
        require(!registry.hasRoles(deployer, registry.ROLE_ISSUER_ADMIN()), "handoff: deployer still admin");
        console.log("Root-of-trust handed off to governance at:", governance);
    }

    /// @dev Confirms `addr` holds code and behaves like an IIssuerRegistry before
    ///      wiring it immutably into the controller. Prevents bricking the controller
    ///      by pointing it at an EOA or a typo'd address.
    function _validateExistingRegistry(address addr) internal view returns (IssuerRegistry) {
        require(addr.code.length > 0, "REGISTRY_ADDRESS has no code");
        try IIssuerRegistry(addr).isActiveIssuer(address(0)) returns (bool) {
            return IssuerRegistry(addr);
        } catch {
            revert("REGISTRY_ADDRESS is not an IIssuerRegistry");
        }
    }
}
