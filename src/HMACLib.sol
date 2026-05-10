// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HMACLib — Custom Built HMAC-SHA256 in Solidity
/// @notice Implements HMAC-SHA256 per RFC 2104, using the SHA-256 precompile
///         (address 0x02) via Solidity's `sha256()` builtin.
/// @dev    Validated against RFC 4231 test vectors. See test/HMACLib.t.sol.
///         The block size for SHA-256 is 64 bytes; this constant is hardcoded
///         throughout the file.
library HMACLib {
    /// @notice The SHA-256 block size in bytes. Defined by FIPS 180-4.
    uint256 internal constant BLOCK_SIZE = 64;

    /// @notice The HMAC inner-pad byte, per RFC 2104 §2.
    bytes1 internal constant IPAD_BYTE = 0x36;

    /// @notice The HMAC outer-pad byte, per RFC 2104 §2.
    bytes1 internal constant OPAD_BYTE = 0x5c;

    /// @notice Compute HMAC-SHA256(key, message).
    /// @param key The secret key. Any length permitted; will be normalized
    ///            to BLOCK_SIZE bytes per RFC 2104 (hashed if too long,
    ///            zero-padded if too short).
    /// @param message The message to authenticate. Any length.
    /// @return The 32-byte HMAC-SHA256 output.
    function hmacSha256(bytes memory key, bytes memory message)
        internal
        pure
        returns (bytes32)
    {
        // Step 1: Normalize the key to exactly BLOCK_SIZE (64) bytes.
        bytes memory normalizedKey = new bytes(BLOCK_SIZE);

        if (key.length > BLOCK_SIZE) {
            // Key is longer than the block: replace it with its hash, then
            // the natural zero-fill of `new bytes(BLOCK_SIZE)` handles padding.
            bytes32 hashedKey = sha256(key);
            for (uint256 i = 0; i < 32; i++) {
                normalizedKey[i] = hashedKey[i];
            }
            // bytes 32..63 are already zero from `new bytes(BLOCK_SIZE)`.
        } else {
            // Key fits in the block: copy it in, leave the rest as zero.
            for (uint256 i = 0; i < key.length; i++) {
                normalizedKey[i] = key[i];
            }
        }

        // Step 2: Build inner pad (key XOR ipad) and outer pad (key XOR opad).
        bytes memory innerPad = new bytes(BLOCK_SIZE);
        bytes memory outerPad = new bytes(BLOCK_SIZE);
        for (uint256 i = 0; i < BLOCK_SIZE; i++) {
            innerPad[i] = normalizedKey[i] ^ IPAD_BYTE;
            outerPad[i] = normalizedKey[i] ^ OPAD_BYTE;
        }

        // Step 3: Inner hash = SHA256(innerPad || message).
        bytes32 innerHash = sha256(abi.encodePacked(innerPad, message));

        // Step 4: Outer hash = SHA256(outerPad || innerHash). This is the HMAC.
        return sha256(abi.encodePacked(outerPad, innerHash));
    }
}