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

    /// @notice DAO-enforced pause flag, settable ONLY via pauseIssuer/unpauseIssuer
    ///         (ROLE_ISSUER_PAUSER). Kept distinct from IssuerInfo.active (the issuer's
    ///         own self-deactivation switch) so that a paused issuer cannot undo a DAO
    ///         pause via setSelfActive. isActiveIssuer requires BOTH !_daoPaused and active.
    mapping(address => bool) private _daoPaused;

    /// @notice Count of accounts holding each role bit. Used to prevent removing
    ///         the last ROLE_ISSUER_ADMIN, which would render the registry unmaintainable.
    mapping(uint256 => uint256) private _roleHolderCount;

    // ── Errors ──────────────────────────────────────────────────────────
    error Unauthorized();
    error AlreadyRegistered();
    error NotRegistered();
    error ZeroAddress();
    error InvalidExpiry();
    error LastAdminProtected();
    error DaoPaused();

    // ── Modifiers ───────────────────────────────────────────────────────
    modifier onlyRole(uint256 role) {
        if (_roles[msg.sender] & role == 0) revert Unauthorized();
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────────
    constructor() {
        _roles[msg.sender] = ROLE_ISSUER_ADMIN | ROLE_ISSUER_PAUSER | ROLE_SPEC_UPDATER;
        _roleHolderCount[ROLE_ISSUER_ADMIN] = 1;
        _roleHolderCount[ROLE_ISSUER_PAUSER] = 1;
        _roleHolderCount[ROLE_SPEC_UPDATER] = 1;
    }

    // ── Role management ─────────────────────────────────────────────────
    function grantRoles(address account, uint256 roles) external onlyRole(ROLE_ISSUER_ADMIN) {
        uint256 current = _roles[account];
        uint256 newlyGranted = roles & ~current;
        if (newlyGranted != 0) {
            _roles[account] = current | newlyGranted;
            _incrementRoleCounts(newlyGranted);
        }
    }

    function revokeRoles(address account, uint256 roles) external onlyRole(ROLE_ISSUER_ADMIN) {
        uint256 current = _roles[account];
        uint256 actuallyRevoked = roles & current;
        if (actuallyRevoked == 0) return;

        // Prevent removing the last ROLE_ISSUER_ADMIN.
        if ((actuallyRevoked & ROLE_ISSUER_ADMIN) != 0 && _roleHolderCount[ROLE_ISSUER_ADMIN] <= 1) {
            revert LastAdminProtected();
        }

        _roles[account] = current & ~actuallyRevoked;
        _decrementRoleCounts(actuallyRevoked);
    }

    function _incrementRoleCounts(uint256 rolesMask) internal {
        if (rolesMask & ROLE_ISSUER_ADMIN != 0) _roleHolderCount[ROLE_ISSUER_ADMIN]++;
        if (rolesMask & ROLE_ISSUER_PAUSER != 0) _roleHolderCount[ROLE_ISSUER_PAUSER]++;
        if (rolesMask & ROLE_SPEC_UPDATER != 0) _roleHolderCount[ROLE_SPEC_UPDATER]++;
    }

    function _decrementRoleCounts(uint256 rolesMask) internal {
        if (rolesMask & ROLE_ISSUER_ADMIN != 0) _roleHolderCount[ROLE_ISSUER_ADMIN]--;
        if (rolesMask & ROLE_ISSUER_PAUSER != 0) _roleHolderCount[ROLE_ISSUER_PAUSER]--;
        if (rolesMask & ROLE_SPEC_UPDATER != 0) _roleHolderCount[ROLE_SPEC_UPDATER]--;
    }

    function hasRoles(address account, uint256 roles) external view returns (bool) {
        return _roles[account] & roles != 0;
    }

    // ── Issuer management ───────────────────────────────────────────────
    function registerIssuer(
        address issuer,
        string calldata name,
        uint256 supportedRecordTypes,
        uint64 expires,
        address verifierContract,
        string calldata specificationURI
    ) external onlyRole(ROLE_ISSUER_ADMIN) {
        if (issuer == address(0)) revert ZeroAddress();
        if (verifierContract == address(0)) revert ZeroAddress();
        if (_registered[issuer]) revert AlreadyRegistered();
        if (expires <= block.timestamp) revert InvalidExpiry();

        _issuers[issuer] = IssuerInfo({
            name: name,
            supportedRecordTypes: supportedRecordTypes,
            registeredAt: uint64(block.timestamp),
            expires: expires,
            active: true,
            verifierContract: verifierContract,
            specificationURI: specificationURI
        });
        _registered[issuer] = true;

        emit IssuerRegistered(issuer, name, supportedRecordTypes, expires, verifierContract);
    }

    function revokeIssuer(address issuer, string calldata reason) external onlyRole(ROLE_ISSUER_ADMIN) {
        if (!_registered[issuer]) revert NotRegistered();

        delete _issuers[issuer];
        _registered[issuer] = false;

        emit IssuerRevoked(issuer, reason);
    }

    function pauseIssuer(address issuer) external onlyRole(ROLE_ISSUER_PAUSER) {
        if (!_registered[issuer]) revert NotRegistered();

        _daoPaused[issuer] = true;
        _issuers[issuer].active = false;

        emit IssuerStatusChanged(issuer, false);
    }

    function unpauseIssuer(address issuer) external onlyRole(ROLE_ISSUER_PAUSER) {
        if (!_registered[issuer]) revert NotRegistered();

        _daoPaused[issuer] = false;
        _issuers[issuer].active = true;

        emit IssuerStatusChanged(issuer, true);
    }

    function renewIssuer(address issuer, uint64 newExpiry) external onlyRole(ROLE_ISSUER_ADMIN) {
        if (!_registered[issuer]) revert NotRegistered();
        if (newExpiry <= block.timestamp) revert InvalidExpiry();

        _issuers[issuer].expires = newExpiry;

        emit IssuerRenewed(issuer, newExpiry);
    }

    /// @notice Allows a registered issuer to toggle their own active status.
    ///         No DAO role required — the issuer controls this for emergency self-deactivation.
    /// @dev    A self-reactivation (active == true) is rejected while the issuer is under a
    ///         DAO pause: the emergency pause can only be lifted by ROLE_ISSUER_PAUSER via
    ///         unpauseIssuer. Self-deactivation (active == false) is always permitted.
    function setSelfActive(bool active) external {
        if (!_registered[msg.sender]) revert NotRegistered();
        if (active && _daoPaused[msg.sender]) revert DaoPaused();

        _issuers[msg.sender].active = active;

        emit IssuerStatusChanged(msg.sender, active);
    }

    // ── View functions ──────────────────────────────────────────────────
    function getIssuer(address issuer) external view returns (IssuerInfo memory) {
        if (!_registered[issuer]) revert NotRegistered();
        return _issuers[issuer];
    }

    function isActiveIssuer(address issuer) external view returns (bool) {
        return _registered[issuer] && !_daoPaused[issuer] && _issuers[issuer].active
            && _issuers[issuer].expires > block.timestamp;
    }

    /// @notice Whether an issuer is currently under a DAO-enforced pause.
    ///         Distinct from the issuer's self-managed active flag in getIssuer().
    function isDaoPaused(address issuer) external view returns (bool) {
        return _daoPaused[issuer];
    }
}
