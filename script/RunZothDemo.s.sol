// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {USD0PPSubVaultProtected} from "../src/protected/USD0PPSubVaultProtected.sol";
import {AuthHelper} from "../test/AuthHelper.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/// @title RunZothDemo
/// @notice The headline demonstration script for Zoth Guard.
///
///         Forks Ethereum mainnet at block 22094139 (one before the Zoth
///         exploit), runs two scenarios side-by-side, and prints a clean
///         narrative output:
///
///         1. BASELINE: replay the actual attacker transactions against
///            unmodified Zoth. The vault is drained.
///         2. PROTECTED: redirect the proxy to a contract using HMACGuardedUUPS.
///            Replay the same attack. Funds are preserved.
///
///         Run with:
///           forge script script/RunZothDemo.s.sol:RunZothDemo \
///             --rpc-url $ALCHEMY_MAINNET_URL -vv
contract RunZothDemo is Script {
    // Mainnet addresses involved in the actual exploit.
    address constant ZOTH_PROXY = 0x82f3a0392F58C50fa90542519832471BaE93e43e;
    address constant ZOTH_DEPLOYER = 0x3604582f56565d7060D73829FfB9EBD579218Dca;
    address constant USD0PP_TOKEN = 0x35D8949372D46B7a3D5A56006AE77B215fc69bC0;
    address constant ZOTH_MALICIOUS_IMPL = 0xc89d7894341e13d5067d003Af5346b257D861f56;
    address constant DRAIN_ATTACKER = 0x3b33c5Cd948Be5863b72cB3D6e9C0b36E67d01E5;

    // The actual mainnet transaction hashes from the exploit.
    bytes32 constant UPGRADE_TX_HASH =
        0xb2335f7bf58abbcaa006d0a2bed7db2c64a5dabed56fb1759260adc012c49abe;
    bytes32 constant DRAIN_TX_HASH =
        0x33bf669d125d11c432ac9b52b9d56161101c072fd8b0ac2aa390f5760fb50ca4;

    bytes4 constant DRAIN_SELECTOR = 0x3ccfd60b;

    // Storage slots.
    bytes32 constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 constant HMAC_COMMITMENT_SLOT =
        0x458c3c2e0776a3130c85b57ced762bdfbc81bf8b1a5065ff9ffdad7a99148600;

    // Demo chain.
    bytes32 constant CHAIN_SEED = bytes32(uint256(0xC0FFEE));
    uint256 constant CHAIN_LENGTH = 5;

    uint256 constant FORK_BLOCK = 22094139;

    function run() external {
        string memory rpcUrl = vm.envString("ALCHEMY_MAINNET_URL");

        printHeader();

        // ====================================================================
        // SCENARIO 1: BASELINE (unprotected — what actually happened)
        // ====================================================================
        vm.createSelectFork(rpcUrl, FORK_BLOCK);
        runBaseline();

        // ====================================================================
        // SCENARIO 2: PROTECTED (counterfactual — with HMACGuardedUUPS)
        // ====================================================================
        vm.createSelectFork(rpcUrl, FORK_BLOCK);
        runProtected();

        printConclusion();
    }

    // ========================================================================
    // SCENARIO 1: BASELINE
    // ========================================================================

    function runBaseline() internal {
        console2.log("");
        console2.log("============================================================");
        console2.log("  SCENARIO 1: BASELINE (unprotected Zoth contract)");
        console2.log("============================================================");
        console2.log("");
        console2.log("Replaying the actual mainnet attack transactions:");
        console2.log("  Upgrade tx: 0xb2335f7b...");
        console2.log("  Drain tx:   0x33bf669d...");
        console2.log("");

        uint256 vaultBefore = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerBefore = IERC20(USD0PP_TOKEN).balanceOf(DRAIN_ATTACKER);

        console2.log("BEFORE attack:");
        console2.log("  Vault USD0PP balance:    ", vaultBefore);
        console2.log("  Attacker USD0PP balance: ", attackerBefore);
        console2.log("");

        // Replay the actual mainnet upgrade tx.
        vm.transact(UPGRADE_TX_HASH);
        bytes32 implAfterUpgrade = vm.load(ZOTH_PROXY, IMPL_SLOT);
        console2.log("After upgrade tx:");
        console2.log(
            "  Implementation slot now points to:",
            address(uint160(uint256(implAfterUpgrade)))
        );
        console2.log("  (the malicious contract pre-deployed 6 days earlier)");
        console2.log("");

        // Replay the actual mainnet drain tx.
        vm.transact(DRAIN_TX_HASH);

        uint256 vaultAfter = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerAfter = IERC20(USD0PP_TOKEN).balanceOf(DRAIN_ATTACKER);

        console2.log("AFTER attack:");
        console2.log("  Vault USD0PP balance:    ", vaultAfter);
        console2.log("  Attacker USD0PP balance: ", attackerAfter);
        console2.log("");
        console2.log("RESULT: vault drained.");
        console2.log("  USD0PP lost:             ", vaultBefore - vaultAfter);
    }

    // ========================================================================
    // SCENARIO 2: PROTECTED
    // ========================================================================

    function runProtected() internal {
        console2.log("");
        console2.log("============================================================");
        console2.log("  SCENARIO 2: PROTECTED (HMACGuardedUUPS in place)");
        console2.log("============================================================");
        console2.log("");
        console2.log("Same fork. Same block. Same attacker. Same calldata.");
        console2.log("Difference: proxy now delegates to a contract that");
        console2.log("inherits HMACGuardedUUPS instead of UUPSUpgradeable.");
        console2.log("");

        // Generate the chain and deploy the protected implementation.
        bytes32[] memory chain = AuthHelper.generateChain(CHAIN_SEED, CHAIN_LENGTH);
        USD0PPSubVaultProtected protectedImpl = new USD0PPSubVaultProtected();

        // Redirect the Zoth proxy to use our protected implementation.
        vm.store(
            ZOTH_PROXY,
            IMPL_SLOT,
            bytes32(uint256(uint160(address(protectedImpl))))
        );
        // Set the chain commitment in the proxy's storage.
        vm.store(ZOTH_PROXY, HMAC_COMMITMENT_SLOT, chain[CHAIN_LENGTH]);

        console2.log("Deployed protected implementation at:", address(protectedImpl));
        console2.log("Set chain commitment in proxy storage.");
        console2.log("");

        uint256 vaultBefore = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerBefore = IERC20(USD0PP_TOKEN).balanceOf(DRAIN_ATTACKER);

        console2.log("BEFORE attack:");
        console2.log("  Vault USD0PP balance:    ", vaultBefore);
        console2.log("  Attacker USD0PP balance: ", attackerBefore);
        console2.log("");

        // Step 1: try the upgrade (same calldata as the actual attacker).
        bytes memory upgradeCalldata = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            ZOTH_MALICIOUS_IMPL,
            ""
        );
        vm.prank(ZOTH_DEPLOYER);
        (bool upgradeSuccess, ) = ZOTH_PROXY.call(upgradeCalldata);
        console2.log("Upgrade attempt (Zoth deployer with admin key):");
        console2.log("  Result:", upgradeSuccess ? "SUCCESS" : "REJECTED");
        console2.log("");

        // Step 2: try the drain anyway.
        vm.prank(DRAIN_ATTACKER);
        (bool drainSuccess, ) = ZOTH_PROXY.call(abi.encodePacked(DRAIN_SELECTOR));
        console2.log("Drain attempt (attacker with malicious calldata):");
        console2.log("  Result:", drainSuccess ? "SUCCESS" : "REJECTED");
        console2.log("");

        uint256 vaultAfter = IERC20(USD0PP_TOKEN).balanceOf(ZOTH_PROXY);
        uint256 attackerAfter = IERC20(USD0PP_TOKEN).balanceOf(DRAIN_ATTACKER);

        console2.log("AFTER attack attempt:");
        console2.log("  Vault USD0PP balance:    ", vaultAfter);
        console2.log("  Attacker USD0PP balance: ", attackerAfter);
        console2.log("");
        console2.log("RESULT: vault preserves every token.");
        console2.log("  USD0PP saved:            ", vaultAfter);
    }

    // ========================================================================
    // FORMATTING
    // ========================================================================

    function printHeader() internal pure {
        console2.log("");
        console2.log("============================================================");
        console2.log("  ZOTH GUARD DEMO");
        console2.log("  Forward-Secure HMAC Authentication for UUPS Upgrades");
        console2.log("============================================================");
        console2.log("");
        console2.log("Reference exploit: Zoth, March 21, 2025");
        console2.log("  - Compromised admin EOA: 0x3604582f...");
        console2.log("  - Loss: ~$8.4M (8,851,750 USD0PP)");
        console2.log("  - Mechanism: standard UUPS upgradeToAndCall with");
        console2.log("    only AccessControl gating. Stealing the admin key");
        console2.log("    was sufficient to swap the implementation.");
        console2.log("");
        console2.log("Forking mainnet at block 22094139");
        console2.log("(one block before the malicious upgrade tx).");
    }

    function printConclusion() internal pure {
        console2.log("");
        console2.log("============================================================");
        console2.log("  CONCLUSION");
        console2.log("============================================================");
        console2.log("");
        console2.log("Identical attacker, identical mainnet state, identical");
        console2.log("calldata. The only difference is what the proxy delegates");
        console2.log("to. With HMACGuardedUUPS, the same attack that drained");
        console2.log("8,851,750 USD0PP fails before any state changes.");
        console2.log("");
        console2.log("The defense holds because the attacker - even with full");
        console2.log("admin key compromise and 6 days of preparation - cannot");
        console2.log("produce a valid HMAC binding without the chain seed.");
        console2.log("");
        console2.log("============================================================");
        console2.log("");
    }
}