// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {VerifiableRecordController} from "../src/VerifiableRecordController.sol";

contract Deploy is Script {
    function run() external {
        // If REGISTRY_ADDRESS is set, reuse an existing IssuerRegistry;
        // otherwise deploy a fresh one.
        address registry = vm.envOr("REGISTRY_ADDRESS", address(0));

        vm.startBroadcast();

        if (registry == address(0)) {
            IssuerRegistry issuerRegistry = new IssuerRegistry();
            registry = address(issuerRegistry);
            console.log("IssuerRegistry deployed at:", registry);
        } else {
            console.log("Using existing IssuerRegistry at:", registry);
        }

        VerifiableRecordController controller = new VerifiableRecordController(registry);
        console.log("VerifiableRecordController deployed at:", address(controller));

        vm.stopBroadcast();
    }
}
