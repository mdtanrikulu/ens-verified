// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IIssuerRegistry {
    /// @notice Emitted when an issuer is registered
    event IssuerRegistered(
        address indexed issuer, string name, uint256 supportedRecordTypes, uint64 expires, address verifierContract
    );

    /// @notice Emitted when an issuer is revoked
    event IssuerRevoked(address indexed issuer, string reason);

    /// @notice Emitted when an issuer's status is paused/unpaused
    event IssuerStatusChanged(address indexed issuer, bool active);

    /// @notice Issuer record
    struct IssuerInfo {
        string name;
        uint256 supportedRecordTypes;
        uint64 registeredAt;
        uint64 expires;
        bool active;
        address verifierContract;
        string specificationURI;
    }

    function registerIssuer(
        address issuer,
        string calldata name,
        uint256 supportedRecordTypes,
        uint64 expires,
        address verifierContract,
        string calldata specificationURI
    ) external;

    function revokeIssuer(address issuer, string calldata reason) external;
    function pauseIssuer(address issuer) external;
    function unpauseIssuer(address issuer) external;
    function renewIssuer(address issuer, uint64 newExpiry) external;

    /// @notice Allows a registered issuer to toggle their own active status (emergency kill switch)
    function setSelfActive(bool active) external;

    function getIssuer(address issuer) external view returns (IssuerInfo memory);
    function isActiveIssuer(address issuer) external view returns (bool);
}
