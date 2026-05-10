// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {USD0PPSubVaultProtected} from "../src/protected/USD0PPSubVaultProtected.sol";
import {AuthHelper} from "./AuthHelper.sol";
import {HMACGuardedUUPS} from "../src/HMACGuardedUUPS.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/// @title ZothFullReplay
/// @notice Full mainnet replay: takes the actual attacker transactions from
///         the Zoth exploit and runs them on a forked mainnet, measuring
///         the USD0PP balance change in the vault.
///
///         Two scenarios:
///         - BASELINE (unprotected): replay the actual mainnet txs against
///           Zoth's deployed contract. Funds drain.
///         - PROTECTED: replay the same txs against a proxy redirected to
///           our protected implementation. Funds stay.
///
///         The transactions replayed are real:
///           Upgrade tx: 0xb2335f7bf58abbcaa006d0a2bed7db2c64a5dabed56fb1759260adc012c49abe
///           Drain tx:   0x33bf669d125d11c432ac9b52b9d56161101c072fd8b0ac2aa390f5760fb50ca4
///         Both occurred at block 22094140.
contract ZothFullReplayTest is Test {
    /// @dev Fork at block 22094139 (one before exploit block 22094140).
    uint256 internal constant FORK_BLOCK = 22094139;

    address internal constant ZOTH_PROXY = 0x82f3a0392F58C50fa90542519832471BaE93e43e;
    address internal constant ZOTH_DEPLOYER = 0x3604582f56565d7060D73829FfB9EBD579218Dca;
    address internal constant USD0PP_TOKEN = 0x35D8949372D46B7a3D5A56006AE77B215fc69bC0;
    address internal constant DRAIN_ATTACKER = 0x3b33c5Cd948Be5863b72cB3D6e9C0b36E67d01E5;
    bytes4 internal constant DRAIN_SELECTOR = 0x3ccfd60b;

    /// @dev Actual mainnet transaction hashes from the Zoth exploit.
    bytes32 internal constant UPGRADE_TX_HASH =
        0xb2335f7bf58abbcaa006d0a2bed7db2c64a5dabed56fb1759260adc012c49abe;
    bytes32 internal constant DRAIN_TX_HASH =
        0x33bf669d125d11c432ac9b52b9d56161101c072fd8b0ac2aa390f5760fb50ca4;

    /// @dev Storage slots.
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant HMAC_COMMITMENT_SLOT =
        0x458c3c2e0776a3130c85b57ced762bdfbc81bf8b1a5065ff9ffdad7a99148600;

    bytes32 internal constant CHAIN_SEED = bytes32(uint256(0xC0FFEE));
    uint256 internal constant CHAIN_LENGTH = 5;
    bytes32[] internal chain;

    function setUp() public {
        string memory rpcUrl = vm.envString("ALCHEMY_MAINNET_URL");
        vm.createSelectFork(rpcUrl, FORK_BLOCK);
        chain = AuthHelper.generateChain(CHAIN_SEED, CHAIN_LENGTH);
    }

    /// THE DRAMATIC BASELINE: replay the actual mainnet exploit transactions
    /// against the unmodified Zoth contract. The vault loses funds.
    function test_FullReplay_Baseline_VaultDrainedByActualAttack() public {
        // Snapshot pre-attack vault balance.
        uint256 vaultBalanceBefore = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerBalanceBefore = IERC20(USD0PP_TOKEN).balanceOf(DRAIN_ATTACKER);
        console2.log("=== BASELINE (UNPROTECTED) ===");
        console2.log("Vault USD0PP balance BEFORE attack:", vaultBalanceBefore);
        console2.log("Attacker USD0PP balance BEFORE:    ", attackerBalanceBefore);

        // Replay the actual upgrade tx from mainnet.
        vm.transact(UPGRADE_TX_HASH);

        // Verify the upgrade landed: implementation slot now points at malicious.
        bytes32 currentImpl = vm.load(ZOTH_PROXY, IMPL_SLOT);
        address impl = address(uint160(uint256(currentImpl)));
        console2.log("Implementation after upgrade tx:   ", impl);

        // Replay the actual drain tx from mainnet.
        vm.transact(DRAIN_TX_HASH);

        // Snapshot post-attack balances.
        uint256 vaultBalanceAfter = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerBalanceAfter = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_DEPLOYER);
        console2.log("Vault USD0PP balance AFTER attack: ", vaultBalanceAfter);
        console2.log("Attacker USD0PP balance AFTER:     ", attackerBalanceAfter);
        console2.log("USD0PP drained:                    ", vaultBalanceBefore - vaultBalanceAfter);

        // The vault should be drained.
        assertLt(vaultBalanceAfter, vaultBalanceBefore, "vault drained by attack");
    }


    /// THE PROTECTED VERSION: redirect the proxy to our protected impl, then
    /// attempt the same attack pattern. The upgrade fails; if the attacker
    /// tries the drain anyway, that fails too because our impl doesn't have
    /// the malicious withdraw() function. Vault balance preserved.
    ///
    /// Implementation note: vm.transact is NOT used here. vm.transact replays
    /// historical transactions against actual mainnet state, ignoring local
    /// fork mutations like vm.store. Since we need to redirect the proxy via
    /// vm.store for this scenario, we use direct calls with vm.prank to
    /// simulate the same caller and calldata.
    function test_FullReplay_Protected_VaultPreservesFunds() public {
        // Deploy protected implementation and redirect the proxy to it.
        USD0PPSubVaultProtected freshImpl = new USD0PPSubVaultProtected();
        vm.store(
            ZOTH_PROXY,
            IMPL_SLOT,
            bytes32(uint256(uint160(address(freshImpl))))
        );
        vm.store(ZOTH_PROXY, HMAC_COMMITMENT_SLOT, chain[CHAIN_LENGTH]);

        uint256 vaultBalanceBefore = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerBalanceBefore = IERC20(USD0PP_TOKEN).balanceOf(DRAIN_ATTACKER);
        console2.log("=== PROTECTED (HMACGuardedUUPS) ===");
        console2.log("Vault USD0PP balance BEFORE attack:", vaultBalanceBefore);
        console2.log("Attacker USD0PP balance BEFORE:    ", attackerBalanceBefore);

        // Step 1: same attacker, same calldata, same sender — but our HMAC
        // defense rejects the upgrade.
        bytes memory upgradeCalldata = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            address(0xc89d7894341e13d5067d003Af5346b257D861f56),
            ""
        );
        vm.prank(ZOTH_DEPLOYER);
        (bool upgradeSuccess, ) = ZOTH_PROXY.call(upgradeCalldata);
        assertFalse(upgradeSuccess, "upgrade rejected by HMAC defense");
        console2.log("Upgrade tx: REJECTED");

        // Verify the implementation slot did not change.
        bytes32 implAfter = vm.load(ZOTH_PROXY, IMPL_SLOT);
        address impl = address(uint160(uint256(implAfter)));
        assertEq(
            impl,
            address(freshImpl),
            "proxy still points at our protected impl"
        );

        // Step 2: even if the attacker desperately tries the drain anyway
        // (using the actual drain calldata from mainnet tx 0x33bf669d...),
        // it fails because our impl doesn't have the withdraw() selector.
        vm.prank(DRAIN_ATTACKER);
        (bool drainSuccess, ) = ZOTH_PROXY.call(abi.encodePacked(DRAIN_SELECTOR));
        assertFalse(drainSuccess, "drain rejected: our impl has no withdraw()");
        console2.log("Drain tx:   REJECTED");

        // Step 3: balance assertions — the crucial proof that funds are safe.
        uint256 vaultBalanceAfter = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerBalanceAfter = IERC20(USD0PP_TOKEN).balanceOf(DRAIN_ATTACKER);
        console2.log("Vault USD0PP balance AFTER attempt:", vaultBalanceAfter);
        console2.log("Attacker USD0PP balance AFTER:     ", attackerBalanceAfter);

        assertEq(
            vaultBalanceAfter,
            vaultBalanceBefore,
            "vault preserves all USD0PP under protection"
        );
        assertEq(
            attackerBalanceAfter,
            attackerBalanceBefore,
            "attacker gained nothing"
        );

        console2.log("USD0PP saved:", vaultBalanceBefore);
    }


}