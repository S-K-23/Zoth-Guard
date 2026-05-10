// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import './USD0PPSubVaultProtected.sol';

/// @title USD0PPSubVaultProtectedV2
/// @notice Test V2 used to verify upgrades succeed. Inherits V1 unchanged
///         and adds a single marker function that proves the upgrade took
///         effect (V1 doesn't have this function, so calling it on the proxy
///         pre-upgrade reverts).
contract USD0PPSubVaultProtectedV2 is USD0PPSubVaultProtected {
    /// @notice Marker function added in V2.
    /// @return Always returns 2. Callable only after upgrade to V2.
    function v2Marker() external pure returns (uint256) {
        return 2;
    }
}