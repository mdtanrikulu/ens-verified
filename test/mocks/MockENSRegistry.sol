// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Minimal ENS Registry mock for testing — deployer owns the root node.
contract MockENSRegistry {
    mapping(bytes32 => address) private _owners;
    mapping(bytes32 => address) private _resolvers;

    constructor() {
        _owners[bytes32(0)] = msg.sender;
    }

    function owner(bytes32 node) external view returns (address) {
        return _owners[node];
    }

    function resolver(bytes32 node) external view returns (address) {
        return _resolvers[node];
    }

    function setSubnodeOwner(bytes32 node, bytes32 label, address newOwner) external returns (bytes32) {
        require(_owners[node] == msg.sender, "not owner");
        bytes32 subnode = keccak256(abi.encodePacked(node, label));
        _owners[subnode] = newOwner;
        return subnode;
    }

    function setResolver(bytes32 node, address newResolver) external {
        require(_owners[node] == msg.sender, "not owner");
        _resolvers[node] = newResolver;
    }
}
