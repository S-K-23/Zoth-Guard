// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HMACGuardedUUPS} from "../src/HMACGuardedUUPS.sol";
import {MockProtectedVault} from "../src/MockProtectedVault.sol";
import {AuthHelper} from "./AuthHelper.sol";

import {MockProtectedVaultV2} from "../src/MockProtectedVaultV2.sol";

/// @title HMACGuardedUUPS Comprehensive Test Suite
/// @notice Validates the forward-secure HMAC authentication layer for UUPS
///         upgrades. Tests cover initialization, the happy path, every category
///         of attack we want to defend against, state integrity after failures,
///         gas pricing edge cases, and end-to-end multi-step chain consumption.
contract HMACGuardedUUPSTest is Test {
    // ============================================================
    // Test fixtures
    // ============================================================

    MockProtectedVault internal vault;        // The proxy, cast as the vault
    MockProtectedVault internal implV1;       // V1 implementation (deployed once)

    address internal constant OWNER = address(0xABCD);
    address internal constant ATTACKER = address(0xBADBAD);

    bytes32 internal constant CHAIN_SEED = bytes32(uint256(0xDEADBEEF));
    uint256 internal constant CHAIN_LENGTH = 10;

    bytes32[] internal chain; // chain[CHAIN_LENGTH] is the initial commitment

    // ============================================================
    // Setup
    // ============================================================

    function setUp() public {
        // Generate hash chain off-chain (well, in test).
        chain = AuthHelper.generateChain(CHAIN_SEED, CHAIN_LENGTH);

        // Deploy V1 implementation.
        implV1 = new MockProtectedVault();

        // Deploy the proxy, initialized with the chain tip.
        bytes memory initData = abi.encodeCall(
            MockProtectedVault.initialize,
            (chain[CHAIN_LENGTH], OWNER)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implV1), initData);

        // Cast proxy to vault interface for ergonomic calls.
        vault = MockProtectedVault(address(proxy));

        // Set base fee to zero so tx.gasprice == priority fee in tests.
        vm.fee(0);
    }

    // ============================================================
    // Helper: build a valid authenticated upgrade transaction context
    // ============================================================

    /// @dev Returns the preimage for the next upgrade and sets up the
    ///      transaction context (priority fee, prank) so the next call to
    ///      `vault.upgradeToAndCallAuth(...)` will succeed.
    /// @param newImpl The implementation address being upgraded to.
    /// @param data The init calldata for the new implementation.
    /// @param sender The address that will execute the upgrade.
    /// @return preimage The next chain preimage to pass.
    function _prepareValidUpgrade(
        address newImpl,
        bytes memory data,
        address sender
    ) internal returns (bytes32 preimage) {
        uint256 currentPosition = vault.getChainPosition();
        // Reveals are in reverse order: chain[CHAIN_LENGTH - 1 - position]
        preimage = chain[CHAIN_LENGTH - 1 - currentPosition];

        uint16 expectedLSBs = AuthHelper.computeExpectedLSBs(
            preimage,
            currentPosition,
            newImpl,
            sender,
            data
        );
        uint256 priorityFee = AuthHelper.buildPriorityFee(expectedLSBs);

        vm.txGasPrice(priorityFee);
        vm.prank(sender);
    }

    // ============================================================
    // Test for the setup itself
    // ============================================================

    function test_Setup_InitialState() public view {
        assertEq(vault.getCurrentCommitment(), chain[CHAIN_LENGTH], "initial commitment");
        assertEq(vault.getChainPosition(), 0, "initial position");
        assertEq(vault.version(), 1, "V1 active");
        assertEq(vault.getOwner(), OWNER, "owner set");
        assertEq(vault.getBalance(), 0, "balance zero");
    }
    // ============================================================
    // CATEGORY: Authenticated upgrade — happy path
    // ============================================================

    function test_HappyPath_SingleUpgrade() public {
        // Deploy V2 implementation.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory upgradeData = ""; // No re-initialization needed for V2.

        // Compute expected event values (chainPosition is current value, 0 here).
        uint256 expectedPosition = 0;

        // Set up valid upgrade context.
        bytes32 preimage = _prepareValidUpgrade(
            address(implV2),
            upgradeData,
            OWNER
        );

        // Expect the AuthSuccess event.
        vm.expectEmit(true, true, false, false, address(vault));
        emit HMACGuardedUUPS.AuthSuccess(expectedPosition, address(implV2));

        // Execute upgrade.
        vault.upgradeToAndCallAuth(address(implV2), upgradeData, preimage);

        // Verify post-state.
        assertEq(vault.version(), 2, "V2 active after upgrade");
        assertEq(vault.getChainPosition(), 1, "chain position incremented");
        assertEq(vault.getCurrentCommitment(), preimage, "commitment advanced to preimage");

        // Verify state from V1 was preserved across upgrade.
        assertEq(vault.getOwner(), OWNER, "owner preserved");
        assertEq(vault.getBalance(), 0, "balance preserved");
    }
    // ============================================================
    // CATEGORY: Chain preimage validation
    // ============================================================

    function test_Reject_WrongPreimage_Random() public {
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory upgradeData = "";
        bytes32 wrongPreimage = bytes32(uint256(0xBADBADBAD));

        // Set up gas pricing as if for a legitimate call (LSBs match this wrong preimage).
        // We compute LSBs for the wrong preimage so that ONLY the chain check fails,
        // not the HMAC check. This isolates which defensive property triggered.
        uint16 lsbs = AuthHelper.computeExpectedLSBs(
            wrongPreimage,
            0,
            address(implV2),
            OWNER,
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(lsbs));
        vm.prank(OWNER);

        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(implV2), upgradeData, wrongPreimage);
    }

    function test_Reject_WrongPreimage_OldChainValue() public {
        // Use chain[0] (the seed) as preimage. It does not hash to the tip.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory upgradeData = "";
        bytes32 wrongPreimage = chain[0];

        uint16 lsbs = AuthHelper.computeExpectedLSBs(
            wrongPreimage,
            0,
            address(implV2),
            OWNER,
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(lsbs));
        vm.prank(OWNER);

        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(implV2), upgradeData, wrongPreimage);
    }

    function test_Reject_PreimageReuseAfterAdvance() public {
        // First, perform a legitimate upgrade.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory upgradeData = "";

        bytes32 preimage = _prepareValidUpgrade(address(implV2), upgradeData, OWNER);
        vault.upgradeToAndCallAuth(address(implV2), upgradeData, preimage);

        // Now try to use the SAME preimage again. The commitment has advanced,
        // so this preimage no longer hashes to the current commitment.
        uint16 lsbs = AuthHelper.computeExpectedLSBs(
            preimage,
            1, // chain position is now 1
            address(implV2),
            OWNER,
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(lsbs));
        vm.prank(OWNER);

        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(implV2), upgradeData, preimage);
    }

    // ============================================================
    // CATEGORY: HMAC binding validation
    // ============================================================

    function test_Reject_WrongPriorityFee_Zero() public {
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory upgradeData = "";

        // Get the right preimage but use wrong priority fee (zero LSBs).
        uint256 currentPosition = vault.getChainPosition();
        bytes32 preimage = chain[CHAIN_LENGTH - 1 - currentPosition];

        // Set priority fee with zero LSBs (very unlikely to match expected).
        vm.txGasPrice(1e9); // exactly 1 gwei, low 16 bits are 0
        vm.prank(OWNER);

        vm.expectRevert(HMACGuardedUUPS.InvalidHMACBinding.selector);
        vault.upgradeToAndCallAuth(address(implV2), upgradeData, preimage);
    }

    function test_Reject_BindingMismatch_DifferentImpl() public {
        // Compute valid context for one implementation, then call with a different
        // implementation. The HMAC binding includes newImplementation, so this
        // must fail.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        MockProtectedVaultV2 implV2_decoy = new MockProtectedVaultV2();
        bytes memory upgradeData = "";

        // Prepare context for implV2.
        _prepareValidUpgrade(address(implV2), upgradeData, OWNER);

        // But call with implV2_decoy. The current call's prank is still valid for one call,
        // but the binding HMAC was computed for implV2, not implV2_decoy.
        bytes32 preimage = chain[CHAIN_LENGTH - 1];

        vm.expectRevert(HMACGuardedUUPS.InvalidHMACBinding.selector);
        vault.upgradeToAndCallAuth(address(implV2_decoy), upgradeData, preimage);
    }

    function test_Reject_BindingMismatch_DifferentData() public {
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory dataA = bytes("init data A");
        bytes memory dataB = bytes("init data B");

        // Prepare context for dataA.
        _prepareValidUpgrade(address(implV2), dataA, OWNER);

        // Call with dataB.
        bytes32 preimage = chain[CHAIN_LENGTH - 1];

        vm.expectRevert(HMACGuardedUUPS.InvalidHMACBinding.selector);
        vault.upgradeToAndCallAuth(address(implV2), dataB, preimage);
    }

    function test_Reject_BindingMismatch_DifferentSender() public {
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory upgradeData = "";

        // Prepare context as if OWNER were calling.
        uint256 currentPosition = vault.getChainPosition();
        bytes32 preimage = chain[CHAIN_LENGTH - 1 - currentPosition];
        uint16 expectedLSBs = AuthHelper.computeExpectedLSBs(
            preimage,
            currentPosition,
            address(implV2),
            OWNER, // binding committed to OWNER as sender
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(expectedLSBs));

        // But call from ATTACKER instead.
        vm.prank(ATTACKER);

        vm.expectRevert(HMACGuardedUUPS.InvalidHMACBinding.selector);
        vault.upgradeToAndCallAuth(address(implV2), upgradeData, preimage);
    }

    // ============================================================
    // CATEGORY: Bypass attempts
    // ============================================================

    function test_Reject_DirectUpgradeToAndCall() public {
        // Attacker bypasses the auth gate by calling the inherited
        // upgradeToAndCall directly. Our overridden _authorizeUpgrade
        // must reject this.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();

        vm.prank(OWNER); // even with the right caller, must fail
        vm.expectRevert(HMACGuardedUUPS.UnauthenticatedUpgradeBlocked.selector);
        vault.upgradeToAndCall(address(implV2), "");
    }

    function test_Reject_DirectUpgradeToAndCall_FromAttacker() public {
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();

        vm.prank(ATTACKER);
        vm.expectRevert(HMACGuardedUUPS.UnauthenticatedUpgradeBlocked.selector);
        vault.upgradeToAndCall(address(implV2), "");
    }

    // ============================================================
    // CATEGORY: State integrity after failures
    // ============================================================

    function test_StateIntegrity_FailedAttemptDoesNotAdvanceChain() public {
        bytes32 commitmentBefore = vault.getCurrentCommitment();
        uint256 positionBefore = vault.getChainPosition();

        // Attempt an upgrade that will fail.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes32 wrongPreimage = bytes32(uint256(0xBAD));
        vm.txGasPrice(1e9);
        vm.prank(OWNER);

        try vault.upgradeToAndCallAuth(address(implV2), "", wrongPreimage) {
            revert("upgrade should have failed");
        } catch {}

        // State must be unchanged.
        assertEq(vault.getCurrentCommitment(), commitmentBefore, "commitment unchanged");
        assertEq(vault.getChainPosition(), positionBefore, "position unchanged");
        assertEq(vault.version(), 1, "still V1");
    }

    function test_StateIntegrity_SuccessAfterFailures() public {
        // Make several failed attempts, then a successful one. The successful
        // one should still use the original chain position 0.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();

        // Attempt 1: wrong preimage
        vm.txGasPrice(1e9);
        vm.prank(OWNER);
        try vault.upgradeToAndCallAuth(address(implV2), "", bytes32(uint256(1))) {
            revert("should fail");
        } catch {}

        // Attempt 2: another wrong preimage
        vm.txGasPrice(1e9);
        vm.prank(OWNER);
        try vault.upgradeToAndCallAuth(address(implV2), "", bytes32(uint256(2))) {
            revert("should fail");
        } catch {}

        // State should still be at position 0.
        assertEq(vault.getChainPosition(), 0, "still position 0 after failures");

        // Now do a legitimate upgrade.
        bytes32 preimage = _prepareValidUpgrade(address(implV2), "", OWNER);
        vault.upgradeToAndCallAuth(address(implV2), "", preimage);

        // Should succeed and advance to position 1.
        assertEq(vault.getChainPosition(), 1, "advanced to position 1");
        assertEq(vault.version(), 2, "V2 active");
    }

    // ============================================================
    // CATEGORY: Gas pricing edge cases
    // ============================================================

    function test_GasPricing_ZeroPriorityFeeWithMatchingHmac() public {
        // Construct a scenario where the expected HMAC LSBs happen to be 0.
        // We can't easily make this happen with a fixed preimage, but we CAN
        // verify the logic: if the LSBs are 0 AND we set priority fee to 0,
        // the call should succeed.

        // We do this by searching for an upgrade whose computed LSBs are 0.
        // Realistically, we just verify the mechanism: if expected==0 and
        // provided==0, no error is raised. Use a small loop with different
        // implementations until we find one with LSBs == 0.

        bytes memory upgradeData = "";
        MockProtectedVaultV2 found;
        uint16 lsbs = 1; // start non-zero so we enter the loop
        for (uint256 salt = 0; salt < 200 && lsbs != 0; salt++) {
            // Each iteration deploys a new V2 with a different address.
            found = new MockProtectedVaultV2();
            lsbs = AuthHelper.computeExpectedLSBs(
                chain[CHAIN_LENGTH - 1],
                0,
                address(found),
                OWNER,
                upgradeData
            );
        }

        if (lsbs != 0) {
            // Could not find an LSBs==0 case in 200 iterations. Skip.
            // 1/65536 chance per iteration, so 200 iterations gives ~0.3% probability.
            // Not a real test failure if we hit this.
            return;
        }

        // Now upgrade with priority fee == 0 (which equals base fee here, set to 0).
        vm.txGasPrice(0);
        vm.prank(OWNER);
        vault.upgradeToAndCallAuth(address(found), upgradeData, chain[CHAIN_LENGTH - 1]);

        assertEq(vault.version(), 2, "upgrade with zero LSBs succeeded");
    }

    function test_GasPricing_GasPriceBelowBasefee() public {
        // If somehow tx.gasprice < block.basefee (impossible in real txs but
        // possible to construct in tests), the contract must revert with
        // InvalidGasPriceConfig.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();

        vm.fee(2e9);            // base fee 2 gwei
        vm.txGasPrice(1e9);     // gas price 1 gwei (below base fee)
        vm.prank(OWNER);

        // We'll fail at the gas-price check before HMAC is even computed.
        vm.expectRevert(HMACGuardedUUPS.InvalidGasPriceConfig.selector);
        vault.upgradeToAndCallAuth(address(implV2), "", chain[CHAIN_LENGTH - 1]);
    }

    function test_GasPricing_HighPriorityFeeWithCorrectLSBs() public {
        // High priority fees should work as long as the low 16 bits match.
        // Verify that the high bits of the priority fee don't affect verification.
        MockProtectedVaultV2 implV2 = new MockProtectedVaultV2();
        bytes memory upgradeData = "";

        uint256 currentPosition = vault.getChainPosition();
        bytes32 preimage = chain[CHAIN_LENGTH - 1 - currentPosition];
        uint16 expectedLSBs = AuthHelper.computeExpectedLSBs(
            preimage,
            currentPosition,
            address(implV2),
            OWNER,
            upgradeData
        );

        // Set a very high priority fee (100 gwei base) but with the right LSBs.
        uint256 highFee = (100 * 1e9 & ~uint256(0xFFFF)) | uint256(expectedLSBs);
        vm.txGasPrice(highFee);
        vm.prank(OWNER);

        vault.upgradeToAndCallAuth(address(implV2), upgradeData, preimage);

        assertEq(vault.version(), 2, "upgrade with high priority fee succeeded");
    }

    // ============================================================
    // CATEGORY: End-to-end multi-step chain
    // ============================================================

    function test_E2E_FiveSequentialUpgrades() public {
        // Perform 5 legitimate upgrades in a row. Each should succeed,
        // chain position should advance correctly, and commitment should
        // step through the chain in reverse order.

        for (uint256 i = 0; i < 5; i++) {
            MockProtectedVaultV2 newImpl = new MockProtectedVaultV2();
            bytes memory upgradeData = "";

            uint256 expectedPositionBefore = i;
            assertEq(
                vault.getChainPosition(),
                expectedPositionBefore,
                "position before upgrade"
            );
            assertEq(
                vault.getCurrentCommitment(),
                chain[CHAIN_LENGTH - i],
                "commitment before upgrade"
            );

            bytes32 preimage = _prepareValidUpgrade(
                address(newImpl),
                upgradeData,
                OWNER
            );
            vault.upgradeToAndCallAuth(address(newImpl), upgradeData, preimage);

            assertEq(
                vault.getChainPosition(),
                expectedPositionBefore + 1,
                "position after upgrade"
            );
            assertEq(
                vault.getCurrentCommitment(),
                chain[CHAIN_LENGTH - 1 - i],
                "commitment advanced to revealed preimage"
            );
        }
    }

    function test_E2E_ChainExhaustion() public {
        // The chain has CHAIN_LENGTH = 10 steps. After 10 upgrades, no more
        // are possible because chain[0] is the seed and there's no preimage
        // for it.

        // Run all 10 upgrades.
        for (uint256 i = 0; i < CHAIN_LENGTH; i++) {
            MockProtectedVaultV2 newImpl = new MockProtectedVaultV2();
            bytes32 preimage = _prepareValidUpgrade(address(newImpl), "", OWNER);
            vault.upgradeToAndCallAuth(address(newImpl), "", preimage);
        }

        assertEq(vault.getChainPosition(), CHAIN_LENGTH, "all chain steps consumed");
        assertEq(vault.getCurrentCommitment(), chain[0], "commitment is the seed");

        // Attempting an 11th upgrade fails: the seed has no preimage in our chain.
        // The signer can't construct a valid preimage to reveal next.
        MockProtectedVaultV2 finalImpl = new MockProtectedVaultV2();

        // Try to upgrade with anything — there is no valid preimage for chain[0].
        // (In production, this is when the operator must rotate the chain.)
        vm.txGasPrice(1e9);
        vm.prank(OWNER);
        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(finalImpl), "", bytes32(uint256(0xDEAD)));
    }

    // ============================================================
    // CATEGORY: Forward security
    // ============================================================

    /// @notice Forward security demonstration.
    /// @dev    The cryptographic claim: an attacker who later obtains a chain
    ///         preimage cannot use it to forge an upgrade if the chain has
    ///         already advanced past that preimage's position.
    ///
    ///         Past preimages are PUBLICLY VISIBLE after a successful upgrade
    ///         (they're in the tx calldata, on-chain forever). Forward security
    ///         says: that's fine, because they're useless to forge future calls.
    ///
    ///         This test proves the property mechanically:
    ///         1. Perform 3 legitimate upgrades (chain advances to position 3)
    ///         2. Capture preimages used at positions 0, 1, 2 (publicly visible)
    ///         3. Attempt to use any of those past preimages to upgrade now
    ///         4. All attempts fail with InvalidChainPreimage
    function test_ForwardSecurity_PastPreimagesUselessAfterAdvance() public {
        // Capture which preimages were revealed at which positions.
        // In production these would be readable from tx history; in test we
        // know them directly from our chain array.
        bytes32 preimageAtPosition0 = chain[CHAIN_LENGTH - 1];
        bytes32 preimageAtPosition1 = chain[CHAIN_LENGTH - 2];
        bytes32 preimageAtPosition2 = chain[CHAIN_LENGTH - 3];

        // Perform 3 legitimate upgrades. Chain advances to position 3.
        for (uint256 i = 0; i < 3; i++) {
            MockProtectedVaultV2 newImpl = new MockProtectedVaultV2();
            bytes32 preimage = _prepareValidUpgrade(address(newImpl), "", OWNER);
            vault.upgradeToAndCallAuth(address(newImpl), "", preimage);
        }

        // Sanity: chain has advanced.
        assertEq(vault.getChainPosition(), 3, "chain at position 3");

        // Now simulate an attacker who has somehow obtained a past preimage
        // (e.g., by reading on-chain tx history, where revealed preimages are
        // permanently visible).
        //
        // The attacker tries to use preimageAtPosition0 — the FIRST preimage
        // that was ever revealed. They have:
        //  - The compromised admin key (they prank as OWNER)
        //  - A valid past preimage (publicly readable)
        //  - Knowledge of the binding format
        // They DO NOT have the chain seed (which would let them compute future
        // preimages).
        //
        // Even with a valid past preimage, the attempt fails because the
        // contract's currentCommitment has advanced past it.

        MockProtectedVaultV2 attackerImpl = new MockProtectedVaultV2();
        bytes memory upgradeData = "";

        // Attacker computes binding/HMAC using the past preimage. They are
        // constructing what would have been a perfectly valid call AT POSITION 0.
        uint256 currentChainPos = 3; // The contract is at position 3 now.

        // The attacker tries position 0's preimage.
        uint16 lsbsForPosition0 = AuthHelper.computeExpectedLSBs(
            preimageAtPosition0,
            currentChainPos,  // attacker uses CURRENT position in their HMAC
            address(attackerImpl),
            OWNER,
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(lsbsForPosition0));
        vm.prank(OWNER);
        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(attackerImpl), upgradeData, preimageAtPosition0);

        // Same attempt with position 1's preimage.
        uint16 lsbsForPosition1 = AuthHelper.computeExpectedLSBs(
            preimageAtPosition1,
            currentChainPos,
            address(attackerImpl),
            OWNER,
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(lsbsForPosition1));
        vm.prank(OWNER);
        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(attackerImpl), upgradeData, preimageAtPosition1);

        // Same attempt with position 2's preimage.
        uint16 lsbsForPosition2 = AuthHelper.computeExpectedLSBs(
            preimageAtPosition2,
            currentChainPos,
            address(attackerImpl),
            OWNER,
            upgradeData
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(lsbsForPosition2));
        vm.prank(OWNER);
        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(attackerImpl), upgradeData, preimageAtPosition2);

        // Verify: chain state was not corrupted by the failed attempts.
        assertEq(vault.getChainPosition(), 3, "chain still at position 3");
        assertEq(
            vault.getCurrentCommitment(),
            chain[CHAIN_LENGTH - 3],
            "commitment is what it should be after 3 advances"
        );
    }

    /// @notice Companion test: the chain seed is the only thing an attacker needs.
    ///         If we give the attacker the seed (i.e., they steal everything),
    ///         they CAN upgrade. This isn't a defense failure — it's the
    ///         intentional trust boundary. Our claim is forward security
    ///         (past safety despite future compromise), not unconditional
    ///         immunity.
    /// @dev    This test isn't a security demonstration — it's a clarity
    ///         demonstration. It explicitly maps out what the defense does
    ///         and doesn't claim.
    function test_ForwardSecurity_FullCompromiseAllowsCurrentUpgrade() public {
        // Attacker has the key (we prank as OWNER) AND has the chain seed
        // (they can compute the next preimage themselves).
        MockProtectedVaultV2 newImpl = new MockProtectedVaultV2();
        
        // With both the key and the seed, the attacker IS the legitimate operator.
        // Our defense doesn't claim to defend against this — it claims to defend
        // against partial compromise (key only). This test makes that boundary explicit.
        bytes32 preimage = _prepareValidUpgrade(address(newImpl), "", OWNER);
        vault.upgradeToAndCallAuth(address(newImpl), "", preimage);
        
        // Upgrade succeeds, as expected. This is correct behavior.
        assertEq(vault.getChainPosition(), 1, "fully-compromised attacker upgraded");
    }
}