// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IIssuerRegistry} from "./interfaces/IIssuerRegistry.sol";

/// @title IssuerRegistry
/// @notice DAO-governed whitelist of authorized verifiable record issuers.
///         Uses a bitmap-based role system modeled after ENS v2's EnhancedAccessControl.
contract IssuerRegistry is IIssuerRegistry {
    // ── Role bitmaps ────────────────────────────────────────────────────
    uint256 public constant ROLE_ISSUER_ADMIN = 1 << 0;
    uint256 public constant ROLE_ISSUER_PAUSER = 1 << 1;
    uint256 public constant ROLE_SPEC_UPDATER = 1 << 2;

    // ── Storage ─────────────────────────────────────────────────────────
    mapping(address => uint256) private _roles;
    mapping(address => IssuerInfo) private _issuers;
    mapping(address => bool) private _registered;

    // ── Errors ──────────────────────────────────────────────────────────
    error Unauthorized();
    error AlreadyRegistered();
    error NotRegistered();
    error ZeroAddress();
    error InvalidExpiry();

    // ── Modifiers ───────────────────────────────────────────────────────
    modifier onlyRole(uint256 role) {
        if (_roles[msg.sender] & role == 0) revert Unauthorized();
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────────
    constructor() {
        _roles[msg.sender] = ROLE_ISSUER_ADMIN | ROLE_ISSUER_PAUSER | ROLE_SPEC_UPDATER;
    }

    // ── Role management ─────────────────────────────────────────────────
    function grantRoles(address account, uint256 roles) external onlyRole(ROLE_ISSUER_ADMIN) {
        _roles[account] |= roles;
    }

    function revokeRoles(address account, uint256 roles) external onlyRole(ROLE_ISSUER_ADMIN) {
        _roles[account] &= ~roles;
    }

    function hasRoles(address account, uint256 roles) external view returns (bool) {
        return _roles[account] & roles != 0;
    }

    // ── Issuer management ───────────────────────────────────────────────
    function registerIssuer(
        address issuer,
        string calldata name,
        uint256 supportedRecordTypes,
        VerificationMode mode,
        uint64 expires,
        address verifierContract,
        string calldata specificationURI
    ) external onlyRole(ROLE_ISSUER_ADMIN) {
        if (issuer == address(0)) revert ZeroAddress();
        if (_registered[issuer]) revert AlreadyRegistered();
        if (expires <= block.timestamp) revert InvalidExpiry();

        _issuers[issuer] = IssuerInfo({
            name: name,
            supportedRecordTypes: supportedRecordTypes,
            verificationMode: mode,
            registeredAt: uint64(block.timestamp),
            expires: expires,
            active: true,
            verifierContract: verifierContract,
            specificationURI: specificationURI
        });
        _registered[issuer] = true;

        emit IssuerRegistered(issuer, name, supportedRecordTypes, uint8(mode), expires);
    }

    function revokeIssuer(address issuer, string calldata reason) external onlyRole(ROLE_ISSUER_ADMIN) {
        if (!_registered[issuer]) revert NotRegistered();

        delete _issuers[issuer];
        _registered[issuer] = false;

        emit IssuerRevoked(issuer, reason);
    }

    function pauseIssuer(address issuer) external onlyRole(ROLE_ISSUER_PAUSER) {
        if (!_registered[issuer]) revert NotRegistered();

        _issuers[issuer].active = false;

        emit IssuerStatusChanged(issuer, false);
    }

    function unpauseIssuer(address issuer) external onlyRole(ROLE_ISSUER_PAUSER) {
        if (!_registered[issuer]) revert NotRegistered();

        _issuers[issuer].active = true;

        emit IssuerStatusChanged(issuer, true);
    }

    function renewIssuer(address issuer, uint64 newExpiry) external onlyRole(ROLE_ISSUER_ADMIN) {
        if (!_registered[issuer]) revert NotRegistered();
        if (newExpiry <= block.timestamp) revert InvalidExpiry();

        _issuers[issuer].expires = newExpiry;
    }

    /// @notice Allows a registered issuer to toggle their own active status.
    ///         No DAO role required — the issuer controls this for emergency self-deactivation.
    function setSelfActive(bool active) external {
        if (!_registered[msg.sender]) revert NotRegistered();

        _issuers[msg.sender].active = active;

        emit IssuerStatusChanged(msg.sender, active);
    }

    // ── View functions ──────────────────────────────────────────────────
    function getIssuer(address issuer) external view returns (IssuerInfo memory) {
        if (!_registered[issuer]) revert NotRegistered();
        return _issuers[issuer];
    }

    function isActiveIssuer(address issuer) external view returns (bool) {
        return _registered[issuer] && _issuers[issuer].active && _issuers[issuer].expires > block.timestamp;
    }

    function getIssuerVerificationMode(address issuer) external view returns (VerificationMode) {
        if (!_registered[issuer]) revert NotRegistered();
        return _issuers[issuer].verificationMode;
    }
}
