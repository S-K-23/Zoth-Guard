// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {HMACLib} from "../src/HMACLib.sol";

/// @title AuthHelper
/// @notice Test helper that mirrors the cryptographic operations the eventual
///         Python signing service must perform. Used by HMACGuardedUUPS tests
///         to construct valid (and invalid) authenticated upgrade transactions.
/// @dev    The on-chain contract uses sha256 for chain verification and
///         HMAC-SHA256 (with the preimage as key) for the binding HMAC.
///         The binding committed to is exactly:
///             abi.encode(chainPosition, newImpl, sender, keccak256(data))
///         Any deviation from this in the helper will cause every test to fail.
library AuthHelper {
    /// @notice Generate a hash chain of length n+1 from a seed.
    /// @dev Returns array `chain` where `chain[0] == seed` and
    ///      `chain[n] == sha256(... sha256(seed))` (n iterations).
    ///      The contract is initialized with chain[n] as the commitment.
    ///      The first legitimate upgrade reveals chain[n-1].
    function generateChain(bytes32 seed, uint256 n)
        internal
        pure
        returns (bytes32[] memory chain)
    {
        chain = new bytes32[](n + 1);
        chain[0] = seed;
        for (uint256 i = 1; i <= n; i++) {
            chain[i] = sha256(abi.encodePacked(chain[i - 1]));
        }
    }

    /// @notice Compute the HMAC binding bytes for a specific upgrade.
    /// @dev Must match exactly what HMACGuardedUUPS computes:
    ///      abi.encode(chainPosition, newImplementation, sender, keccak256(data))
    function computeBinding(
        uint256 chainPosition,
        address newImplementation,
        address sender,
        bytes memory data
    ) internal pure returns (bytes memory) {
        return abi.encode(
            chainPosition,
            newImplementation,
            sender,
            keccak256(data)
        );
    }

    /// @notice Compute the full HMAC for a specific upgrade.
    function computeFullHmac(
        bytes32 preimage,
        uint256 chainPosition,
        address newImplementation,
        address sender,
        bytes memory data
    ) internal pure returns (bytes32) {
        bytes memory binding = computeBinding(
            chainPosition,
            newImplementation,
            sender,
            data
        );
        return HMACLib.hmacSha256(abi.encodePacked(preimage), binding);
    }

    /// @notice Compute the expected priority fee LSBs (low 16 bits of HMAC).
    function computeExpectedLSBs(
        bytes32 preimage,
        uint256 chainPosition,
        address newImplementation,
        address sender,
        bytes memory data
    ) internal pure returns (uint16) {
        bytes32 hmac = computeFullHmac(
            preimage,
            chainPosition,
            newImplementation,
            sender,
            data
        );
        return uint16(uint256(hmac));
    }

    /// @notice Construct a priority fee value whose low 16 bits equal `lsbs`.
    /// @dev Uses 1 gwei (10^9 wei) as base, then OR-s the LSBs into the low bits.
    ///      This produces a priority fee in the realistic Gwei range that
    ///      encodes the required HMAC LSBs.
    /// @param lsbs The HMAC low 16 bits to encode.
    /// @return Priority fee value to set as `maxPriorityFeePerGas`.
    function buildPriorityFee(uint16 lsbs) internal pure returns (uint256) {
        // Clear the low 16 bits, then OR in the LSBs.
        uint256 base = 1e9; // 1 gwei
        return (base & ~uint256(0xFFFF)) | uint256(lsbs);
    }
}