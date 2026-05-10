// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";

/// @title ZothForkSmokeTest
/// @notice Phase 2 smoke test: confirms we can fork mainnet at the right block
///         and read state. No defense logic yet — just proving the fork works.
contract ZothForkSmokeTest is Test {
    /// @dev Block immediately before the malicious upgradeToAndCall (22094140).
    uint256 internal constant FORK_BLOCK = 22094139;

    /// @dev Zoth's proxy contract (the one that got attacked).
    address internal constant ZOTH_PROXY = 0x82f3a0392F58C50fa90542519832471BaE93e43e;

    /// @dev ERC-1967 implementation slot.
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Zoth's legitimate implementation at FORK_BLOCK.
    address internal constant ZOTH_IMPL_LEGIT = 0x7Cb771ca7b9ABcCCFdc19564E7260795cD51629E;

    /// @dev The compromised Zoth deployer EOA.
    address internal constant ZOTH_DEPLOYER = 0x3604582f56565d7060D73829FfB9EBD579218Dca;

    function setUp() public {
        string memory rpcUrl = vm.envString("ALCHEMY_MAINNET_URL");
        vm.createSelectFork(rpcUrl, FORK_BLOCK);
    }

    /// Sanity: the fork is at the block we asked for.
    function test_Smoke_BlockNumberMatches() public view {
        assertEq(block.number, FORK_BLOCK, "block number matches expected fork block");
    }

    /// Sanity: chain id is mainnet (1).
    function test_Smoke_ChainIdIsMainnet() public view {
        assertEq(block.chainid, 1, "fork is mainnet");
    }

    /// Sanity: we can read the implementation slot from Zoth's proxy.
    /// This proves storage queries against the fork return real mainnet state.
    function test_Smoke_ReadZothImplementationSlot() public view {
        bytes32 implSlotValue = vm.load(ZOTH_PROXY, IMPL_SLOT);
        address impl = address(uint160(uint256(implSlotValue)));

        console2.log("Zoth proxy:", ZOTH_PROXY);
        console2.log("Implementation at fork block:", impl);

        assertEq(impl, ZOTH_IMPL_LEGIT, "impl matches legitimate Zoth contract");
    }

    /// Sanity: the legitimate implementation has bytecode (it's a real contract).
    function test_Smoke_LegitImplementationHasCode() public view {
        uint256 codeSize;
        address target = ZOTH_IMPL_LEGIT;
        assembly {
            codeSize := extcodesize(target)
        }
        assertGt(codeSize, 0, "Zoth implementation has bytecode");
        console2.log("Zoth implementation bytecode size (bytes):", codeSize);
    }

    /// Sanity: the deployer EOA has no bytecode (it's an EOA, not a contract).
    function test_Smoke_DeployerIsEOA() public view {
        uint256 codeSize;
        address target = ZOTH_DEPLOYER;
        assembly {
            codeSize := extcodesize(target)
        }
        assertEq(codeSize, 0, "deployer is an EOA");
    }
}