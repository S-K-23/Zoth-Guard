// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {HMACLib} from "./HMACLib.sol";

/// @title HMACGuardedUUPS
/// @notice An abstract base contract that protocols inherit instead of
///         OpenZeppelin's `UUPSUpgradeable` to gain forward-secure cryptographic
///         protection on the upgrade authority.
///
///         Standard UUPS lets any address with `ADMIN_ROLE` upgrade the
///         implementation. If that key is compromised, the protocol is
///         compromised. This contract requires every upgrade to also include
///         a valid hash chain preimage AND an HMAC binding the upgrade to its
///         specific parameters. The HMAC binding is encoded in the transaction's
///         priority fee LSBs.
///
///         An attacker holding only the signing key cannot construct a valid
///         upgrade transaction, because the chain preimage and HMAC require
///         the secret seed which is held in a separate trust domain.
///
/// @dev    Forward security: each successful upgrade reveals the next preimage
///         in a hash chain. Compromise of the seed at time T does not enable
///         forging upgrades from any time before T. Past reveals are already
///         on-chain (no information leaked); future reveals require seed access.
abstract contract HMACGuardedUUPS is Initializable, UUPSUpgradeable {
    // ============================================================
    // STORAGE — ERC-7201 namespaced
    // ============================================================

    /// @custom:storage-location erc7201:hmacguarded.uups.main
    struct HMACGuardedUUPSStorage {
        bytes32 currentCommitment;
        uint256 chainPosition;
    }

    // keccak256(abi.encode(uint256(keccak256("hmacguarded.uups.main")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant HMACGUARDED_UUPS_STORAGE_LOCATION =
        0x458c3c2e0776a3130c85b57ced762bdfbc81bf8b1a5065ff9ffdad7a99148600;

    function _getHMACGuardedUUPSStorage()
        private
        pure
        returns (HMACGuardedUUPSStorage storage $)
    {
        assembly {
            $.slot := HMACGUARDED_UUPS_STORAGE_LOCATION
        }
    }

    // ============================================================
    // EVENTS
    // ============================================================

    /// @notice Emitted when an authenticated upgrade is successfully authorized.
    /// @param chainPosition The chain step that was just consumed.
    /// @param newImplementation The implementation address being upgraded to.
    event AuthSuccess(
        uint256 indexed chainPosition,
        address indexed newImplementation
    );

    // ============================================================
    // ERRORS
    // ============================================================

    /// @notice The provided preimage does not hash to the current chain commitment.
    error InvalidChainPreimage();

    /// @notice The HMAC LSBs encoded in the priority fee do not match the expected value.
    error InvalidHMACBinding();

    /// @notice The transaction's gas price is below the base fee, which is structurally impossible
    ///         on a normal Ethereum transaction. Likely indicates a malformed test environment.
    error InvalidGasPriceConfig();

    /// @notice An unauthenticated upgrade was attempted via the standard UUPS path.
    ///         All upgrades must go through `upgradeToAndCallAuth`.
    error UnauthenticatedUpgradeBlocked();

    // ============================================================
    // INITIALIZER
    // ============================================================

    /// @notice Initialize the guardian with the tip of a hash chain.
    /// @param initialCommitment The terminal value `S_N` of a hash chain
    ///        of length N+1, generated off-chain by the protocol operator.
    ///        Each subsequent legitimate upgrade reveals one preimage in
    ///        reverse order: S_{N-1}, S_{N-2}, ...
    /// @dev   Must be called by the inheriting contract's own initializer.
    ///        Uses `onlyInitializing` to ensure it's only callable during
    ///        the inheriting contract's `initialize` flow.
    // solhint-disable-next-line func-name-mixedcase
    function __HMACGuardedUUPS_init(bytes32 initialCommitment)
        internal
        onlyInitializing
    {
        HMACGuardedUUPSStorage storage $ = _getHMACGuardedUUPSStorage();
        $.currentCommitment = initialCommitment;
        $.chainPosition = 0;
    }

    // ============================================================
    // AUTHENTICATED UPGRADE PATH
    // ============================================================

    /// @notice Authenticated upgrade entry point. The only valid way to upgrade
    ///         a contract that inherits HMACGuardedUUPS.
    /// @param newImplementation The new implementation address to upgrade to.
    /// @param data The initialization calldata to invoke on the new implementation,
    ///        or empty bytes if no initialization is needed.
    /// @param preimage The next hash chain preimage. Must satisfy
    ///        `sha256(preimage) == currentCommitment`.
    /// @dev The HMAC of the binding parameters, computed using `preimage` as the
    ///      key, must match the low 16 bits of the transaction's effective
    ///      priority fee (`tx.gasprice - block.basefee`).
    ///
    ///      The signing service is responsible for setting `maxPriorityFeePerGas`
    ///      such that its low 16 bits equal `HMAC(preimage, binding) & 0xFFFF`,
    ///      and for setting `maxFeePerGas` high enough that the priority fee is
    ///      not capped (recommended: `maxFeePerGas >= 2 * basefee + maxPriorityFeePerGas`).
    function upgradeToAndCallAuth(
        address newImplementation,
        bytes calldata data,
        bytes32 preimage
    ) external payable {
        HMACGuardedUUPSStorage storage $ = _getHMACGuardedUUPSStorage();

        // Step 1: Verify the preimage hashes to the current commitment.
        if (sha256(abi.encodePacked(preimage)) != $.currentCommitment) {
            revert InvalidChainPreimage();
        }

        // Step 2: Compute expected HMAC binding.
        bytes memory bindingData = abi.encode(
            $.chainPosition,
            newImplementation,
            msg.sender,
            keccak256(data)
        );
        bytes32 expectedHmac = HMACLib.hmacSha256(
            abi.encodePacked(preimage),
            bindingData
        );
        uint16 expectedLSBs = uint16(uint256(expectedHmac));

        // Step 3: Recover the priority fee LSBs from the transaction.
        if (tx.gasprice < block.basefee) {
            revert InvalidGasPriceConfig();
        }
        uint256 priorityFee = tx.gasprice - block.basefee;
        uint16 providedLSBs = uint16(priorityFee);

        // Step 4: Verify HMAC binding.
        if (providedLSBs != expectedLSBs) {
            revert InvalidHMACBinding();
        }

        // Step 5: Advance the chain.
        uint256 currentPosition = $.chainPosition;
        $.currentCommitment = preimage;
        $.chainPosition = currentPosition + 1;

        emit AuthSuccess(currentPosition, newImplementation);

        // Step 6: Perform the actual upgrade. We call the inherited `upgradeToAndCall`
        // which will invoke `_authorizeUpgrade`. Our overridden `_authorizeUpgrade`
        // checks a transient flag to confirm we're inside the authenticated path.
        _setAuthenticatedFlag(true);
        upgradeToAndCall(newImplementation, data);
        _setAuthenticatedFlag(false);
    }

    // ============================================================
    // SHIELDED UPGRADE — blocks the standard UUPS path
    // ============================================================

    /// @dev Transient storage slot used to mark "we are inside an authenticated upgrade."
    ///      `_authorizeUpgrade` reads this and reverts if it's not set.
    bytes32 private constant AUTH_FLAG_SLOT =
        keccak256("hmacguarded.uups.auth_flag");

    function _setAuthenticatedFlag(bool value) private {
        bytes32 slot = AUTH_FLAG_SLOT;
        assembly {
            tstore(slot, value)
        }
    }

    function _isAuthenticated() private view returns (bool flag) {
        bytes32 slot = AUTH_FLAG_SLOT;
        assembly {
            flag := tload(slot)
        }
    }

    /// @notice Override the UUPS upgrade authorization hook.
    /// @dev Reverts unless we're inside the `upgradeToAndCallAuth` flow.
    ///      This blocks any direct call to the standard `upgradeToAndCall`
    ///      function, forcing all upgrades through HMAC verification.
    function _authorizeUpgrade(address /* newImplementation */)
        internal
        view
        virtual
        override
    {
        if (!_isAuthenticated()) {
            revert UnauthenticatedUpgradeBlocked();
        }
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    function getCurrentCommitment() external view returns (bytes32) {
        return _getHMACGuardedUUPSStorage().currentCommitment;
    }

    function getChainPosition() external view returns (uint256) {
        return _getHMACGuardedUUPSStorage().chainPosition;
    }
}