// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/**
 * @title SubVault Errors Interface
 * @author ZeUSD Protocol Team
 * @notice Defines error types specific to SubVault operations
 * @dev Interface containing SubVault-specific error definitions
 */
interface ISubVaultErrors {
    /**
     * @notice Thrown when caller is not authorized
     * @param caller Address of unauthorized caller
     */
    error UnauthorizedCaller(address caller);

    /**
     * @notice Thrown when asset operation is unsupported
     * @param asset Address of unsupported asset
     */
    error UnsupportedAsset(address asset);

    /**
     * @notice Thrown when asset is already configured
     * @param asset Address of already supported asset
     */
    error AssetAlreadySupported(address asset);

    /**
     * @notice Thrown when address is invalid (usually zero)
     * @param addr The invalid address
     */
    error InvalidAddress(address addr);

    /**
     * @notice Thrown when amount is invalid (usually zero)
     */
    error InvalidAmount();

    /**
     * @notice Thrown when deposit operation fails
     * @param reason Description of failure
     */
    error DepositFailed(string reason);

    /**
     * @notice Thrown when withdrawal operation fails
     * @param reason Description of failure
     */
    error WithdrawFailed(string reason);

    /**
     * @notice Thrown when emergency delay period hasn't passed
     */
    error EmergencyDelayNotPassed();

    /**
     * @notice Thrown when emergency mode is active
     * @param timestamp Time when emergency mode was enabled
     */
    error EmergencyModeEnabled(uint256 timestamp);

    /**
     * @notice Thrown when emergency mode is not active
     */
    error EmergencyModeNotEnabled();

    /**
     * @notice Thrown when balance is insufficient
     * @param requested Amount requested
     * @param available Amount available
     */
    error InsufficientBalance(uint256 requested, uint256 available);

    /**
     * @notice Thrown when approval operation fails
     * @param asset Asset for which approval failed
     * @param spender Address that was to be approved
     */
    error ApprovalFailed(address asset, address spender);

    /**
     * @notice Thrown when attempting to remove primary asset
     */
    error CannotRemovePrimaryAsset();

    /**
     * @notice Thrown when primary asset operation fails
     * @param reason Description of failure
     */
    error PrimaryAssetOperationFailed(string reason);

    /**
     * @notice Thrown when secondary asset operation fails
     * @param reason Description of failure
     */
    error SecondaryAssetOperationFailed(string reason);

    /**
     * @notice Thrown when usual not initialized
     */
    error NotInitialized();

    /**
     * @notice Thrown when array length mismatch
     */
    error ArrayLengthMismatch();

    /**
     * @notice Thrown when an asset is not supported
     * @param asset The unsupported asset address
     * @dev Asset validation error
     */
    error AssetNotSupported(address asset);

    /**
     * @notice Thrown when a non-zero balance is found on an asset
     * @param asset The asset with a non-zero balance
     * @param balance The non-zero balance amount
     * @dev Balance validation error
     */
    error NonZeroBalance(address asset, uint256 balance);

    /**
     * @notice Thrown when user has no yield to claim
     * @dev Yield claim validation error
     */
    error NoYieldToClaim();

    /**
     * @notice Thrown when vault has insufficient balance for operation
     * @dev Balance validation error
     */
    error InsufficientVaultBalance();
}
