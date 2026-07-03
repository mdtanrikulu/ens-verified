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

    /// @notice Emitted when an issuer's expiration is extended
    event IssuerRenewed(address indexed issuer, uint64 newExpiry);

    /// @notice Emitted when an issuer's specificationURI is replaced
    event SpecificationURIUpdated(address indexed issuer, string newURI);

    /// @notice Emitted when an issuer's verifier contract is replaced
    event VerifierContractUpdated(address indexed issuer, address newVerifier);

    /// @notice Emitted when role bits are granted to an account (mask = bits actually granted)
    event RolesGranted(address indexed account, uint256 roles);

    /// @notice Emitted when role bits are revoked from an account (mask = bits actually revoked)
    event RolesRevoked(address indexed account, uint256 roles);

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

    /// @notice Replace an issuer's specificationURI (bundle hosting migration; ROLE_SPEC_UPDATER)
    function updateSpecificationURI(address issuer, string calldata newURI) external;

    /// @notice Replace an issuer's verifier contract (proof scheme migration; ROLE_ISSUER_ADMIN)
    function updateVerifierContract(address issuer, address newVerifier) external;

    /// @notice Allows a registered issuer to toggle their own active status (emergency kill switch)
    function setSelfActive(bool active) external;

    function getIssuer(address issuer) external view returns (IssuerInfo memory);
    function isActiveIssuer(address issuer) external view returns (bool);

    /// @notice Whether an issuer is under a DAO-enforced pause (settable only by ROLE_ISSUER_PAUSER).
    ///         A paused issuer cannot self-reactivate via setSelfActive.
    function isDaoPaused(address issuer) external view returns (bool);
}
