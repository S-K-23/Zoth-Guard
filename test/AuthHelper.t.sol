// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthHelper} from "./AuthHelper.sol";

/// @title AuthHelper Sanity Tests
/// @notice Light validation that the test helper's cryptographic operations
///         are stable and behave as expected. The helper is itself untested
///         against external references, but its determinism, distinctness,
///         and chain correctness can be verified internally.
contract AuthHelperTest is Test {
    function test_GenerateChain_FirstAndLast() public pure {
        bytes32 seed = bytes32(uint256(0x42));
        bytes32[] memory chain = AuthHelper.generateChain(seed, 5);

        assertEq(chain.length, 6, "chain length");
        assertEq(chain[0], seed, "chain[0] is seed");
        // Each step is sha256 of the previous
        assertEq(
            chain[1],
            sha256(abi.encodePacked(seed)),
            "chain[1] = sha256(seed)"
        );
        assertEq(
            chain[2],
            sha256(abi.encodePacked(chain[1])),
            "chain[2] = sha256(chain[1])"
        );
    }

    function test_GenerateChain_DifferentSeeds() public pure {
        bytes32[] memory a = AuthHelper.generateChain(bytes32(uint256(1)), 3);
        bytes32[] memory b = AuthHelper.generateChain(bytes32(uint256(2)), 3);
        assertNotEq(a[3], b[3], "different seeds, different tips");
    }

    function test_ComputeBinding_Deterministic() public pure {
        bytes memory data = bytes("init");
        bytes memory b1 = AuthHelper.computeBinding(0, address(0xAA), address(0xBB), data);
        bytes memory b2 = AuthHelper.computeBinding(0, address(0xAA), address(0xBB), data);
        assertEq(keccak256(b1), keccak256(b2), "binding deterministic");
    }

    function test_ComputeBinding_DistinctOnChainPosition() public pure {
        bytes memory data = bytes("init");
        bytes memory b1 = AuthHelper.computeBinding(0, address(0xAA), address(0xBB), data);
        bytes memory b2 = AuthHelper.computeBinding(1, address(0xAA), address(0xBB), data);
        assertNotEq(keccak256(b1), keccak256(b2), "different position, different binding");
    }

    function test_ComputeBinding_DistinctOnNewImpl() public pure {
        bytes memory data = bytes("init");
        bytes memory b1 = AuthHelper.computeBinding(0, address(0xAA), address(0xBB), data);
        bytes memory b2 = AuthHelper.computeBinding(0, address(0xCC), address(0xBB), data);
        assertNotEq(keccak256(b1), keccak256(b2), "different impl, different binding");
    }

    function test_ComputeBinding_DistinctOnSender() public pure {
        bytes memory data = bytes("init");
        bytes memory b1 = AuthHelper.computeBinding(0, address(0xAA), address(0xBB), data);
        bytes memory b2 = AuthHelper.computeBinding(0, address(0xAA), address(0xCC), data);
        assertNotEq(keccak256(b1), keccak256(b2), "different sender, different binding");
    }

    function test_ComputeBinding_DistinctOnData() public pure {
        bytes memory b1 = AuthHelper.computeBinding(0, address(0xAA), address(0xBB), bytes("data1"));
        bytes memory b2 = AuthHelper.computeBinding(0, address(0xAA), address(0xBB), bytes("data2"));
        assertNotEq(keccak256(b1), keccak256(b2), "different data, different binding");
    }

    function test_BuildPriorityFee_LSBsCorrect() public pure {
        uint16 lsbs = 0x1234;
        uint256 fee = AuthHelper.buildPriorityFee(lsbs);
        assertEq(uint16(fee), lsbs, "low 16 bits match");
        // Sanity: fee should be in the gwei range
        assertGt(fee, 1e8, "fee > 0.1 gwei");
        assertLt(fee, 1e10, "fee < 10 gwei");
    }

    function test_BuildPriorityFee_AllZeros() public pure {
        uint16 lsbs = 0x0000;
        uint256 fee = AuthHelper.buildPriorityFee(lsbs);
        assertEq(uint16(fee), 0, "low 16 bits are zero");
    }

    function test_BuildPriorityFee_AllOnes() public pure {
        uint16 lsbs = 0xFFFF;
        uint256 fee = AuthHelper.buildPriorityFee(lsbs);
        assertEq(uint16(fee), 0xFFFF, "low 16 bits are all ones");
    }
}