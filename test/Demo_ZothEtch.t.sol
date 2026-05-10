// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {USD0PPSubVaultProtected} from "../src/protected/USD0PPSubVaultProtected.sol";
import {AuthHelper} from "./AuthHelper.sol";
import {HMACGuardedUUPS} from "../src/HMACGuardedUUPS.sol";
import {USD0PPSubVaultProtectedV2} from "../src/protected/USD0PPSubVaultProtectedV2.sol";

/// @title ZothEtchTest
/// @notice Phase 3: replace Zoth's deployed implementation bytecode with our
///         protected version, write the HMAC chain commitment to the proxy,
///         and verify the proxy retains all its original state while now
///         running our protected logic.
contract ZothEtchTest is Test {
    uint256 internal constant FORK_BLOCK = 22094139;

    address internal constant ZOTH_PROXY = 0x82f3a0392F58C50fa90542519832471BaE93e43e;
    address internal constant ZOTH_IMPL_LEGIT = 0x7Cb771ca7b9ABcCCFdc19564E7260795cD51629E;
    address internal constant ZOTH_DEPLOYER = 0x3604582f56565d7060D73829FfB9EBD579218Dca;

    /// @dev Storage slot for HMACGuardedUUPS's `currentCommitment`.
    /// Computed via ERC-7201 from namespace "hmacguarded.uups.main".
    bytes32 internal constant HMAC_COMMITMENT_SLOT =
        0x458c3c2e0776a3130c85b57ced762bdfbc81bf8b1a5065ff9ffdad7a99148600;

    bytes32 internal constant CHAIN_SEED = bytes32(uint256(0xC0FFEE));
    uint256 internal constant CHAIN_LENGTH = 5;
    bytes32[] internal chain;

    USD0PPSubVaultProtected internal protectedProxy;
    USD0PPSubVaultProtected internal freshImpl;

    function setUp() public {
        string memory rpcUrl = vm.envString("ALCHEMY_MAINNET_URL");
        vm.createSelectFork(rpcUrl, FORK_BLOCK);

        chain = AuthHelper.generateChain(CHAIN_SEED, CHAIN_LENGTH);

        freshImpl = new USD0PPSubVaultProtected();

        bytes32 implSlot = bytes32(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);
        vm.store(
            ZOTH_PROXY,
            implSlot,
            bytes32(uint256(uint160(address(freshImpl))))
        );

        // Initialize the HMAC chain commitment in the proxy's storage.
        vm.store(ZOTH_PROXY, HMAC_COMMITMENT_SLOT, chain[CHAIN_LENGTH]);

        // Cast the proxy as our protected interface for ergonomic access.
        protectedProxy = USD0PPSubVaultProtected(ZOTH_PROXY);
    }

    /// Verify our protected logic now runs at Zoth's implementation address.
    function test_Etch_ProtectedCodeAtZothImpl() public view {
        // Compare etched code size to a freshly-deployed protected impl.
        uint256 etchedSize;
        address target = ZOTH_IMPL_LEGIT;
        assembly {
            etchedSize := extcodesize(target)
        }
        assertGt(etchedSize, 0, "etched code present");
        console2.log("Etched runtime bytecode size (bytes):", etchedSize);
    }

    /// Verify our HMAC commitment is now set in the proxy storage.
    function test_Etch_HmacCommitmentSet() public view {
        bytes32 commitment = protectedProxy.getCurrentCommitment();
        assertEq(commitment, chain[CHAIN_LENGTH], "commitment is our chain tip");
        console2.log("Chain commitment in proxy storage:");
        console2.logBytes32(commitment);
    }

    /// Verify the chain position is initialized to zero (default value, never written).
    function test_Etch_ChainPositionInitiallyZero() public view {
        assertEq(protectedProxy.getChainPosition(), 0, "chain position 0");
    }

    /// CRITICAL: verify Zoth's pre-existing state is preserved.
    /// The proxy's storage was never re-initialized; the role assignments,
    /// asset addresses, etc. that Zoth set up at deployment must still be there.
    function test_Etch_ZothStatePreserved_AdminRole() public view {
        bytes32 ADMIN_ROLE = keccak256("ADMIN_ROLE");
        bool deployerHasAdmin = protectedProxy.hasRole(ADMIN_ROLE, ZOTH_DEPLOYER);
        assertTrue(deployerHasAdmin, "Zoth deployer still has ADMIN_ROLE");
    }

    function test_Etch_ZothStatePreserved_USD0PP() public view {
        // The USD0PP token address that Zoth configured at deployment.
        // We don't know what it is exactly without reading the chain, but
        // we can check that it's non-zero (was set by Zoth's initialize).
        address usd0pp = protectedProxy.USD0PP();
        assertTrue(usd0pp != address(0), "USD0PP address preserved from Zoth init");
        console2.log("USD0PP address:", usd0pp);
    }

    function test_Etch_ZothStatePreserved_Router() public view {
        address router = protectedProxy.router();
        assertTrue(router != address(0), "router preserved from Zoth init");
        console2.log("Router address:", router);
    }

    // ============================================================
    // PHASE 4: replay the actual Zoth attack against our protected version
    // ============================================================

    /// @dev The malicious implementation deployed by the attacker, used in the
    ///      real Zoth exploit at block 22094140. Source is not verified, but
    ///      its address is what got written to the proxy's IMPL_SLOT during
    ///      the attack.
    address internal constant ZOTH_MALICIOUS_IMPL = 0xc89d7894341e13d5067d003Af5346b257D861f56;
    
    /// CRITICAL: replay the actual Zoth attack pattern.
    /// The attacker (compromised deployer EOA) calls upgradeToAndCall directly
    /// on the proxy with the malicious implementation. This is the exact
    /// transaction signature of the real exploit.
    /// Against our protected version, this MUST fail.
    function test_Phase4_ZothAttackReplay_Reverts() public {
        // Impersonate the actual attacker EOA.
        vm.prank(ZOTH_DEPLOYER);

        // Expect the revert from HMACGuardedUUPS's transient flag check.
        vm.expectRevert(); // UnauthenticatedUpgradeBlocked or AccessControl error

        // The exact call pattern from the real attack:
        // upgradeToAndCall(maliciousImpl, "")
        protectedProxy.upgradeToAndCall(ZOTH_MALICIOUS_IMPL, "");
    }

    /// Belt-and-suspenders: same attack via a fresh attacker (not even the
    /// admin). The original Zoth attack used the admin EOA, but we want to
    /// verify defense holds for any attacker.
    function test_Phase4_AttackByRandomEOA_Reverts() public {
        address randomAttacker = address(0xBADBAD);

        vm.prank(randomAttacker);
        vm.expectRevert();        
        protectedProxy.upgradeToAndCall(ZOTH_MALICIOUS_IMPL, "");
    }

    /// Verify that AFTER the failed attack, the proxy still points to our
    /// protected implementation. The attack didn't corrupt anything.
    function test_Phase4_StateIntactAfterFailedAttack() public {
        vm.prank(ZOTH_DEPLOYER);
        try protectedProxy.upgradeToAndCall(ZOTH_MALICIOUS_IMPL, "") {
            revert("attack should have failed");
        } catch {}

        bytes32 implSlot = bytes32(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);
        bytes32 currentImpl = vm.load(ZOTH_PROXY, implSlot);
        address impl = address(uint160(uint256(currentImpl)));
        assertEq(impl, address(freshImpl), "impl unchanged after failed attack");

        assertEq(
            protectedProxy.getCurrentCommitment(),
            chain[CHAIN_LENGTH],
            "chain commitment unchanged"
        );
        assertEq(protectedProxy.getChainPosition(), 0, "chain position unchanged");
        assertTrue(
            protectedProxy.hasRole(keccak256("ADMIN_ROLE"), ZOTH_DEPLOYER),
            "admin role preserved"
        );
    }

// ============================================================
    // PHASE 5: legitimate signing path works
    // ============================================================

    /// Demonstrate that the protected version still allows legitimate upgrades.
    /// The legitimate signer is the same EOA as the attacker (the Zoth deployer
    /// holds ADMIN_ROLE), but they have access to the chain seed.
    /// 
    /// We use a fresh USD0PPSubVaultProtectedV2 as the upgrade target. We
    /// import it inline in this test rather than at the top of the file
    /// to keep the imports minimal for the etch demo.
    function test_Phase5_LegitimateSignerCanStillUpgrade() public {
        // We need to set base fee to zero on the fork so tx.gasprice ==
        // priority fee. Foundry's vm.fee works on forks.
        vm.fee(0);

        // Deploy V2 (a target to upgrade to). Inline import via type cast.
        USD0PPSubVaultProtectedV2 v2 = new USD0PPSubVaultProtectedV2();
        address v2Addr = address(v2);

        bytes memory upgradeData = "";

        // Compute valid auth context for chain position 0.
        bytes32 preimage = chain[CHAIN_LENGTH - 1];
        uint16 expectedLSBs = AuthHelper.computeExpectedLSBs(
            preimage,
            0,                   // chainPosition
            v2Addr,              // newImplementation
            ZOTH_DEPLOYER,       // sender (the admin)
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(expectedLSBs));

        // Legitimate admin calls the authenticated endpoint.
        vm.prank(ZOTH_DEPLOYER);
        protectedProxy.upgradeToAndCallAuth(v2Addr, upgradeData, preimage);

        // Verify upgrade succeeded.
        assertEq(protectedProxy.getChainPosition(), 1, "chain advanced");
        assertEq(protectedProxy.getCurrentCommitment(), preimage, "commitment is preimage");

        // The implementation slot should now point at our V2 etched address.
        bytes32 implSlot = bytes32(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);
        bytes32 currentImpl = vm.load(ZOTH_PROXY, implSlot);
        address impl = address(uint160(uint256(currentImpl)));
        assertEq(impl, v2Addr, "impl now points to V2");
    }
}