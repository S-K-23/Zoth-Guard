// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AuthHelper} from "../test/AuthHelper.sol";

/// @title PrintCrossValidation
/// @notice Prints binding bytes and full HMAC for fixed inputs, so we can
///         cross-check Python's computation produces the same values.
contract PrintCrossValidation is Script {
    function run() external pure {
        // Fixed inputs matching TestBindingCodec.SAMPLE_* in Python.
        uint256 chainPosition = 0;
        address newImpl = address(0xaaaa);
        address sender = address(0xbbbb);
        bytes memory data = "";
        bytes32 preimage = bytes32(uint256(0x42));

        // Compute and print binding.
        bytes memory binding = AuthHelper.computeBinding(
            chainPosition,
            newImpl,
            sender,
            data
        );

        console2.log("Binding length:", binding.length);
        console2.log("Binding bytes (hex):");
        console2.logBytes(binding);

        // Compute and print full HMAC.
        bytes32 hmac = AuthHelper.computeFullHmac(
            preimage,
            chainPosition,
            newImpl,
            sender,
            data
        );

        console2.log("HMAC (hex):");
        console2.logBytes32(hmac);

        // LSBs.
        uint16 lsbs = uint16(uint256(hmac));
        console2.log("LSBs (decimal):", lsbs);
    }
}