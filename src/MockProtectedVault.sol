// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {HMACGuardedUUPS} from "./HMACGuardedUUPS.sol";

/// @title MockProtectedVault
/// @notice Minimal upgradeable contract used to test HMACGuardedUUPS.
///         Stores a balance and exposes a marker function (`version`) that
///         we change in upgraded versions to verify upgrades actually take
///         effect on the proxy.
/// @dev    This is V1. We'll create V2 as a separate contract for upgrade tests.
contract MockProtectedVault is HMACGuardedUUPS {
    /// @custom:storage-location erc7201:mockprotectedvault.main
    struct VaultStorage {
        uint256 balance;
        address owner;
    }

    // keccak256(abi.encode(uint256(keccak256("mockprotectedvault.main")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VAULT_STORAGE_LOCATION =
        0x658c6c8f81bdf1baea5d00b69128624d91bde6798eab230dfa206d7c6547e600;

    function _getVaultStorage() private pure returns (VaultStorage storage $) {
        bytes32 slot = VAULT_STORAGE_LOCATION;
        assembly {
            $.slot := slot
        }
    }

    /// @notice Disable initializers on the implementation contract.
    /// @dev Per OZ upgradeable pattern: the implementation must not be
    ///      initializable; only the proxy's storage can be initialized.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the vault. Called once during proxy deployment.
    /// @param initialCommitment The terminal value `S_N` of the hash chain.
    /// @param initialOwner The address that owns the vault.
    function initialize(bytes32 initialCommitment, address initialOwner)
        external
        initializer
    {
        __HMACGuardedUUPS_init(initialCommitment);

        VaultStorage storage $ = _getVaultStorage();
        $.owner = initialOwner;
        $.balance = 0;
    }

    /// @notice Marker for tracking which version is currently active.
    /// @dev V1 returns 1. Upgraded versions will return higher numbers.
    function version() external pure virtual returns (uint256) {
        return 1;
    }

    /// @notice Test deposit function — just updates a balance counter.
    function deposit(uint256 amount) external {
        VaultStorage storage $ = _getVaultStorage();
        $.balance += amount;
    }

    function getBalance() external view returns (uint256) {
        return _getVaultStorage().balance;
    }

    function getOwner() external view returns (address) {
        return _getVaultStorage().owner;
    }
}