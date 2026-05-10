// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import '@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol';
import '@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol';
import '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import '@openzeppelin/contracts/proxy/utils/Initializable.sol';
import '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import '../HMACGuardedUUPS.sol';
import './interfaces/ISubVault.sol';
import './interfaces/IPriceOracle.sol';

/**
 * @title USD0PP SubVault — Protected Variant
 * @notice Verbatim port of Zoth's USD0PPSubVaultUpgradeable with one
 *         architectural change: the upgrade authority gate is replaced with
 *         our forward-secure HMAC verification (HMACGuardedUUPS).
 *
 * @dev    What changed from the original:
 *         1. `UUPSUpgradeable` -> `HMACGuardedUUPS` in inheritance
 *         2. `ReentrancyGuardUpgradeable` -> `ReentrancyGuard` (OZ v5.6 reorg)
 *         3. `__UUPSUpgradeable_init()` removed from initializer (no-op in v5)
 *         4. `__HMACGuardedUUPS_init(_initialCommitment)` added to initializer
 *         5. Initializer takes additional parameter `bytes32 _initialCommitment`
 *         6. `_authorizeUpgrade` override now combines AccessControl role check
 *            (preserved from original) with HMACGuardedUUPS transient flag check
 *
 *         All business logic — deposits, withdrawals, emergency mode, oracle
 *         management, treasury — is unchanged from Zoth's deployed contract.
 *         Storage layout is identical (verified: all OZ v5.0 namespace strings
 *         match v5.6 strings, so namespaced storage hashes are identical).
 */
contract USD0PPSubVaultProtected is
    Initializable,
    HMACGuardedUUPS,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuard,
    ISubVault
{
    using SafeERC20 for IERC20;

    /// @dev Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256('ADMIN_ROLE');
    /// @notice Core contract references
    address public router;
    /// @notice USD0++ token address
    address public USD0PP;
    /// @notice USUAL token address
    address public USUAL;
    /// @notice Treasury address
    address public TREASURY;
    /// @notice Asset management mappings
    mapping(address => bool) public supportedAssets;
    address[] private _supportedAssetsList;
    /// @notice Emergency control settings
    uint256 public constant EMERGENCY_DELAY = 1 hours;
    uint256 public lastEmergencyAction;
    bool public emergencyMode;
    /// @notice Price oracle mapping
    mapping(address => address) public assetOracles;
    address public ws;

    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);

    /**
     * @dev Constructor is disabled as this is an upgradeable contract
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract replacing the constructor for upgradeability.
     *         Same as Zoth's original but with one additional parameter:
     *         `_initialCommitment` — the terminal value of the off-chain hash chain.
     */
    function initialize(
        address _usd0pp,
        address _usual,
        address _router,
        address _admin,
        bytes32 _initialCommitment
    ) public initializer {
        require(_usd0pp != address(0), 'Invalid USD0++');
        require(_router != address(0), 'Invalid router');
        require(_admin != address(0), 'Invalid admin');

        // Initialize inherited contracts
        __AccessControl_init();
        __Pausable_init();
        // ReentrancyGuard in v5.6 is no longer Upgradeable; no init needed.
        // UUPSUpgradeable in v5+ has no state; no init needed.
        __HMACGuardedUUPS_init(_initialCommitment);

        USD0PP = _usd0pp;
        USUAL = _usual;
        router = _router;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _setRoleAdmin(ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        // Set up USD0++ as primary asset
        supportedAssets[_usd0pp] = true;
        _supportedAssetsList.push(_usd0pp);
        emit AssetAdded(_usd0pp, 'USD0++ configured as primary asset');
    }

    /**
     * @dev Override _authorizeUpgrade to combine the original AccessControl
     *      gate with HMACGuardedUUPS's HMAC verification.
     *      Both checks must pass: the caller must hold ADMIN_ROLE AND we must
     *      be inside the authenticated upgrade path (HMACGuardedUUPS transient flag).
     */
    function _authorizeUpgrade(address newImplementation)
        internal
        view
        override
        onlyRole(ADMIN_ROLE)
    {
        super._authorizeUpgrade(newImplementation);
    }

    /// @notice Ensures caller is authorized router
    modifier onlyRouter() {
        if (msg.sender != router) revert UnauthorizedCaller(msg.sender);
        _;
    }
    modifier onlyWithdrawalSystem() {
        if (msg.sender != ws) revert UnauthorizedCaller(msg.sender);
        _;
    }
    /// @notice Ensures address is not zero
    modifier validAddress(address addr) {
        if (addr == address(0)) revert InvalidAddress(addr);
        _;
    }

    // =====================================================================
    // BUSINESS LOGIC FROM ZOTH'S ORIGINAL — UNCHANGED
    // The remainder of this file is copied verbatim from Zoth's verified
    // source (lines 187-469 of contracts/subVaults/USD0PPSubVault.sol),
    // with only the inherited modifier names adjusted where necessary.
    // =====================================================================
// =====================================================================
    // BUSINESS LOGIC FROM ZOTH'S ORIGINAL — UNCHANGED
    // The remainder of this contract is copied verbatim from Zoth's verified
    // source (lines 187-469 of contracts/subVaults/USD0PPSubVault.sol).
    // No modifications. The defense lives entirely in the upgrade gate above.
    // =====================================================================

    /// @notice Sets the withdrawal system address
    /// @param _ws Address of the withdrawal system contract
    function WS(address _ws) external onlyRole(ADMIN_ROLE) validAddress(_ws) {
        ws = _ws;
        emit RouterSet(_ws);
    }

    /**
     * @notice Sets the price oracle for a specific asset
     * @param asset Address of the asset
     * @param oracle Address of the price oracle
     */
    function setAssetOracle(address asset, address oracle) external onlyRole(ADMIN_ROLE) {
        require(asset != address(0), 'Invalid asset address');
        require(oracle != address(0), 'Invalid oracle address');
        assetOracles[asset] = oracle;
        emit AssetOracleSet(asset, oracle);
    }

    /// @notice Gets the oracle price for a supported asset
    function getOraclePrice(
        address asset
    ) external view override returns (uint256 price, bool success) {
        if (!supportedAssets[asset]) {
            return (0, false);
        }

        address oracle = assetOracles[asset];
        if (oracle == address(0)) {
            return (0, false);
        }

        try IPriceOracle(oracle).latestRoundData() returns (
            uint80,
            int256 answer,
            uint256,
            uint256 /*updatedAt*/,
            uint80
        ) {
            // Check if the price is positive
            if (answer <= 0) {
                return (0, false);
            }

            return (uint256(answer), true);
        } catch {
            return (0, false);
        }
    }

    /// @notice Handles deposit of supported assets
    /// @dev Only handles primary asset deposits, reverts for secondary assets
    /// @param asset Address of asset being deposited
    /// @param amount Amount to deposit
    /// @return success Whether deposit was successful
    function handleDeposit(
        address,
        address asset,
        uint256 amount
    ) external override nonReentrant onlyRouter whenNotPaused returns (bool) {
        if (amount == 0) revert InvalidAmount();
        if (emergencyMode) revert EmergencyModeEnabled(block.timestamp);

        // Only allow deposits of primary asset
        if (asset != USD0PP) revert UnsupportedAsset(asset);
        if (asset == this.getPrimaryAsset()) {
            return true;
        }
        return false;
    }

    /// @notice Handles withdrawal of supported assets
    /// @dev Only handles primary asset withdrawals
    /// @param user Address of withdrawing user
    /// @param asset Address of asset being withdrawn
    /// @param amount Amount to withdraw
    /// @return success Whether withdrawal was successful
    function handleWithdraw(
        address user,
        address asset,
        uint256 amount
    ) external override nonReentrant onlyWithdrawalSystem whenNotPaused returns (bool) {
        if (amount == 0) revert InvalidAmount();
        if (emergencyMode) revert EmergencyModeEnabled(block.timestamp);

        // Only allow withdrawals of primary asset
        if (asset != USD0PP) revert UnsupportedAsset(asset);

        // Transfer primary asset directly
        IERC20(USD0PP).safeTransfer(user, amount);
        emit PrimaryAssetOperation(user, amount, false);
        return true;
    }

    /// @notice Adds support for a secondary asset
    /// @dev This functionality is disabled in this version
    function addAsset(
        address asset,
        string calldata
    ) external view override onlyRole(ADMIN_ROLE) validAddress(asset) {
        revert('Asset addition is not supported in this version');
    }

    /// @notice Removes support for a secondary asset
    /// @dev This functionality is disabled in this version
    function removeAsset(address, string calldata) external view override onlyRole(ADMIN_ROLE) {
        revert('Asset removal is not supported in this version');
    }

    /// @notice Enables emergency mode
    function enableEmergencyMode() external override onlyRole(ADMIN_ROLE) whenNotPaused {
        emergencyMode = true;
        _pause();
        lastEmergencyAction = block.timestamp;
        emit EmergencyModeSet(block.timestamp, true);
    }

    /// @notice Disables emergency mode
    function disableEmergencyMode() external override onlyRole(ADMIN_ROLE) {
        if (block.timestamp < lastEmergencyAction + EMERGENCY_DELAY)
            revert EmergencyDelayNotPassed();
        _unpause();
        emergencyMode = false;
        emit EmergencyModeSet(block.timestamp, false);
    }

    /// @notice Executes emergency withdrawal
    function withdrawEmergency(
        address asset,
        address to,
        uint256 amount,
        string calldata reason
    ) external override nonReentrant onlyRole(ADMIN_ROLE) returns (bool) {
        if (!emergencyMode) revert EmergencyModeNotEnabled();
        if (block.timestamp < lastEmergencyAction + EMERGENCY_DELAY)
            revert EmergencyDelayNotPassed();
        if (amount == 0) revert InvalidAmount();

        uint256 balance = IERC20(asset).balanceOf(address(this));
        uint256 withdrawAmount = amount > balance ? balance : amount;

        if (asset == USD0PP) {
            _revokeApproval(USD0PP, address(USD0PP));
        }

        IERC20(asset).safeTransfer(to, withdrawAmount);

        lastEmergencyAction = block.timestamp;
        emit EmergencyWithdrawalExecuted(asset, to, withdrawAmount, reason);

        return true;
    }

    /**
     * @notice Withdraws all USUAL tokens to a specified address
     * @dev Only callable by admin role
     * @return amount Amount of USUAL tokens withdrawn
     */
    function withdrawAllUSUAL()
        external
        nonReentrant
        onlyRole(ADMIN_ROLE)
        returns (uint256 amount)
    {
        if (USUAL == address(0)) revert NotInitialized();
        if (TREASURY == address(0)) revert NotInitialized();

        amount = IERC20(USUAL).balanceOf(address(this));
        if (amount <= 0) revert InvalidAmount();

        IERC20(USUAL).safeTransfer(TREASURY, amount);

        emit EmergencyWithdrawalExecuted(USUAL, TREASURY, amount, 'Admin USUAL withdrawal');

        return amount;
    }

    /**
     * @notice Sets the treasury address
     * @dev Only callable by admin role
     * @param newTreasury New treasury address
     */
    function setTreasury(address newTreasury) external onlyRole(ADMIN_ROLE) {
        require(newTreasury != address(0), 'Zero address not allowed');
        require(newTreasury != TREASURY, 'Same treasury address');

        address oldTreasury = TREASURY;
        TREASURY = newTreasury;
        emit TreasuryUpdated(oldTreasury, newTreasury);
    }

    /**
     * @notice Sets up initial approval for bridge operations
     * @dev Required before any bridge operations can occur
     * @custom:security Access controlled operation
     */
    function setupInitialApproval(address _asset) external onlyRole(ADMIN_ROLE) {
        IERC20(_asset).approve(ws, type(uint256).max);
    }

    /// @notice Pauses vault operations
    function pause() external override onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpauses vault operations
    function unpause() external override onlyRole(ADMIN_ROLE) {
        if (emergencyMode) revert EmergencyModeEnabled(block.timestamp);
        _unpause();
    }

    // Internal functions for approval management
    function _grantApproval(address asset, address spender, uint256 amount) internal {
        try IERC20(asset).approve(spender, amount) {
            emit ApprovalGranted(asset, spender, amount);
        } catch {
            revert ApprovalFailed(asset, spender);
        }
    }

    function _revokeApproval(address asset, address spender) internal {
        try IERC20(asset).approve(spender, 0) {
            emit ApprovalRevoked(asset, spender);
        } catch {
            revert ApprovalFailed(asset, spender);
        }
    }

    // View Functions
    function getSupportedAssets() external view override returns (address[] memory) {
        return _supportedAssetsList;
    }

    function isAssetSupported(address asset) external view override returns (bool) {
        return supportedAssets[asset];
    }

    function getEmergencyStatus()
        external
        view
        override
        returns (bool isEmergencyMode, bool isPaused, uint256 timeUntilNextAction)
    {
        uint256 nextActionTime = lastEmergencyAction + EMERGENCY_DELAY;
        uint256 timeUntil = block.timestamp >= nextActionTime
            ? 0
            : nextActionTime - block.timestamp;

        return (emergencyMode, paused(), timeUntil);
    }

    function isPrimaryAsset(address asset) external view override returns (bool) {
        return asset == USD0PP;
    }

    function getPrimaryAsset() external view override returns (address) {
        return USD0PP;
    }

    function getSupportedAssetsCount() external view returns (uint256) {
        return _supportedAssetsList.length;
    }

    function getUSD0PPBalance() external view returns (uint256) {
        return IERC20(USD0PP).balanceOf(address(this));
    }

    function isOperational() external view returns (bool) {
        return !paused() && !emergencyMode;
    }

    function getVaultStats()
        external
        view
        returns (uint256 usd0Balance, uint256 secondaryAssetCount, bool isActive)
    {
        return (
            IERC20(USD0PP).balanceOf(address(this)),
            _supportedAssetsList.length - 1,
            !paused() && !emergencyMode
        );
    }
}