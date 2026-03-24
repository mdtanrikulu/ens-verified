// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITextResolver} from "../../src/interfaces/ITextResolver.sol";

/// @dev Permissionless mock resolver for testing — anyone can call setText.
contract MockResolver is ITextResolver {
    mapping(bytes32 => mapping(bytes32 => string)) private _texts;

    function setText(bytes32 node, string calldata key, string calldata value) external {
        _texts[node][keccak256(bytes(key))] = value;
    }

    function text(bytes32 node, string calldata key) external view returns (string memory) {
        return _texts[node][keccak256(bytes(key))];
    }
}
