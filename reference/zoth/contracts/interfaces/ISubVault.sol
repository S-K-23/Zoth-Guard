// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import '../events/ISubVaultEvents.sol';
import '../errors/ISubVaultErrors.sol';

/**
 * @title Asset Specific SubVault Interface
 * @author ZeUSD Protocol Team
 * @notice Interface for specialized vaults handling primary and secondary assets
 * @dev Implements deposit/withdrawal functionality with primary asset focus
 * @custom:security-contact paras@zoth.io
 */
interface ISubVault is ISubVaultEvents, ISubVaultErrors {
    /// @notice SECURITY CONSIDERATIONS:
    /// - Primary asset operations must be validated separately
    /// - Secondary assets require additional validation
    /// - Balance checks before all operations
    /// - Emergency mode restrictions
    /// - Proper approval management for FundVaultV2
    /// - Asset-specific transfer validations
    ///
    /// STATE MANAGEMENT:
    /// - Normal: Full functionality for all assets
    /// - Paused: No operations allowed
    /// - Emergency: Only emergency withdrawals
    /// - Primary Asset: Always supported
    /// - Secondary Assets: Can be added/removed
    ///
    /// INTEGRATION REQUIREMENTS:
    /// - Must validate primary asset operations first
    /// - Must implement separate flows for primary/secondary assets
    /// - Must maintain accurate balances for all assets
    /// - Must emit appropriate events for tracking
    /// - Must handle FundVaultV2 interactions safely
    /// - Must implement proper access control
    ///
    /// ASSET HANDLING:
    /// Primary Asset:
    /// - Cannot be removed
    /// - Direct integration with FundVaultV2
    /// - Specialized event emission
    ///
    /// Secondary Assets:
    /// - Can be added/removed by admin
    /// - May require conversion logic
    /// - Separate event emission

    /**
     * @notice Handles deposit of any supported asset
     * @param user Address of the depositing user
     * @param asset Address of the asset being deposited
     * @param amount Amount to deposit
     * @return success Whether the deposit was successful
     * @dev Different handling for primary vs secondary assets
     */
    function handleDeposit(address user, address asset, uint256 amount) external returns (bool);

    /**
     * @notice Handles withdrawal of any supported asset
     * @param user Address of the withdrawing user
     * @param asset Address of the asset to withdraw
     * @param amount Amount to withdraw
     * @return success Whether the withdrawal was successful
     * @dev Different handling for primary vs secondary assets
     */
    function handleWithdraw(address user, address asset, uint256 amount) external returns (bool);

    /**
     * @notice Gets the current oracle price for the asset if available
     * @param asset Address of the asset to get price for
     * @return price Current oracle price (0 if not available)
     * @return success Whether oracle price was successfully fetched
     */
    function getOraclePrice(address asset) external view returns (uint256 price, bool success);

    /**
     * @notice Executes emergency withdrawal for any supported asset
     * @param asset Address of the asset to withdraw
     * @param to Recipient address
     * @param amount Amount to withdraw
     * @param reason Reason for emergency withdrawal
     * @return success Whether the withdrawal was successful
     * @dev Available in emergency mode only, special handling for primary asset
     */
    function withdrawEmergency(
        address asset,
        address to,
        uint256 amount,
        string calldata reason
    ) external returns (bool);

    /**
     * @notice Adds support for a secondary asset
     * @param asset Address of the asset to add
     * @param reason Reason for adding the asset
     * @dev Cannot add primary asset, reverts if asset already supported
     */
    function addAsset(address asset, string calldata reason) external;

    /**
     * @notice Removes support for a secondary asset
     * @param asset Address of the asset to remove
     * @param reason Reason for removing the asset
     * @dev Cannot remove primary asset, reverts if asset not supported
     */
    function removeAsset(address asset, string calldata reason) external;

    /**
     * @notice Gets complete list of supported assets
     * @return Array of supported asset addresses
     * @dev Primary asset is always first in the array
     */
    function getSupportedAssets() external view returns (address[] memory);

    /**
     * @notice Gets true for supported asset
     * @param asset Address of the asset to check
     * @return Whether the asset is supported
     */
    function isAssetSupported(address asset) external view returns (bool);

    /**
     * @notice Gets current emergency status
     * @return isEmergencyMode Whether emergency mode is active
     * @return isPaused Whether vault is paused
     * @return timeUntilNextAction Time until next emergency action allowed
     * @dev Used to check vault status before operations
     */
    function getEmergencyStatus()
        external
        view
        returns (bool isEmergencyMode, bool isPaused, uint256 timeUntilNextAction);

    /**
     * @notice Checks if an asset is the primary asset
     * @param asset Asset address to check
     * @return bool True if asset is primary asset
     * @dev Used to determine asset handling flow
     */
    function isPrimaryAsset(address asset) external view returns (bool);

    /**
     * @notice Gets the primary asset address
     * @return address Address of primary asset
     * @dev Primary asset cannot be changed after deployment
     */
    function getPrimaryAsset() external view returns (address);

    /**
     * @notice Enables emergency mode
     * @dev Pauses operations and starts emergency delay timer
     */
    function enableEmergencyMode() external;

    /**
     * @notice Disables emergency mode
     * @dev Can only be called after emergency delay period
     */
    function disableEmergencyMode() external;

    /**
     * @notice Pauses all vault operations
     * @dev Separate from emergency mode
     */
    function pause() external;

    /**
     * @notice Unpauses vault operations
     * @dev Cannot unpause if in emergency mode
     */
    function unpause() external;
}
