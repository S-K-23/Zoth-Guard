// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MockProtectedVault} from "./MockProtectedVault.sol";

/// @title MockProtectedVaultV2
/// @notice V2 of the mock vault used to test upgrades. The only difference
///         from V1 is that `version()` returns 2.
/// @dev    A real upgrade would change logic, fix bugs, etc. For testing the
///         upgrade *mechanism*, just changing a marker function is sufficient.
contract MockProtectedVaultV2 is MockProtectedVault {
    function version() external pure override returns (uint256) {
        return 2;
    }
}