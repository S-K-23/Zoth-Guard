// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HMACGuardedUUPS} from "../src/HMACGuardedUUPS.sol";
import {USD0PPSubVaultProtected} from "../src/protected/USD0PPSubVaultProtected.sol";
import {USD0PPSubVaultProtectedV2} from "../src/protected/USD0PPSubVaultProtectedV2.sol";
import {AuthHelper} from "./AuthHelper.sol";

/// @title USD0PPSubVaultProtected Test Suite
/// @notice Validates the Zoth-port-with-HMAC-guard works end-to-end:
///         deployment, initialization, attack rejection, legitimate upgrade.
///
///         This is the isolation test for our protected port before we put
///         it on a forked mainnet. If anything is wrong with the integration
///         between Zoth's business logic and our HMACGuardedUUPS layer, this
///         catches it here, not on the fork.
contract USD0PPSubVaultProtectedTest is Test {
    USD0PPSubVaultProtected internal vault;
    USD0PPSubVaultProtected internal implV1;

    // The compromised Zoth deployer EOA, used to simulate attacker calls.
    address internal constant ZOTH_DEPLOYER = 0x3604582f56565d7060D73829FfB9EBD579218Dca;
    address internal constant DUMMY_ROUTER = address(0x111);

    bytes32 internal constant CHAIN_SEED = bytes32(uint256(0xC0FFEE));
    uint256 internal constant CHAIN_LENGTH = 5;

    bytes32[] internal chain;

    function setUp() public {
        chain = AuthHelper.generateChain(CHAIN_SEED, CHAIN_LENGTH);

        // Deploy the protected V1 implementation.
        implV1 = new USD0PPSubVaultProtected();

        // Deploy the proxy. Initialize with dummy addresses for non-upgrade-related
        // state (we're only exercising the upgrade path in these tests).
        bytes memory initData = abi.encodeCall(
            USD0PPSubVaultProtected.initialize,
            (
                address(0xFF1), // _usd0pp (any non-zero address)
                address(0xFF2), // _usual
                DUMMY_ROUTER,   // _router
                ZOTH_DEPLOYER,  // _admin (becomes ADMIN_ROLE holder)
                chain[CHAIN_LENGTH] // initial commitment
            )
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implV1), initData);
        vault = USD0PPSubVaultProtected(address(proxy));

        // Set base fee to zero so tx.gasprice == priority fee in tests.
        vm.fee(0);
    }

    /// Helper: sets up valid upgrade context and returns the next preimage.
    function _prepareValidUpgrade(
        address newImpl,
        bytes memory data,
        address sender
    ) internal returns (bytes32 preimage) {
        uint256 currentPosition = vault.getChainPosition();
        preimage = chain[CHAIN_LENGTH - 1 - currentPosition];

        uint16 expectedLSBs = AuthHelper.computeExpectedLSBs(
            preimage,
            currentPosition,
            newImpl,
            sender,
            data
        );
        vm.txGasPrice(AuthHelper.buildPriorityFee(expectedLSBs));
        vm.prank(sender);
    }

    // ============================================================
    // Initialization tests
    // ============================================================

    function test_Initialization_StateSetCorrectly() public view {
        assertEq(vault.getChainPosition(), 0, "chain position 0");
        assertEq(vault.getCurrentCommitment(), chain[CHAIN_LENGTH], "initial commitment");
        assertEq(vault.USD0PP(), address(0xFF1), "USD0PP set");
        assertEq(vault.router(), DUMMY_ROUTER, "router set");
        assertTrue(
            vault.hasRole(vault.ADMIN_ROLE(), ZOTH_DEPLOYER),
            "admin has ADMIN_ROLE"
        );
        assertTrue(
            vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), ZOTH_DEPLOYER),
            "admin has DEFAULT_ADMIN_ROLE"
        );
        assertTrue(vault.supportedAssets(address(0xFF1)), "USD0PP supported");
    }

    // ============================================================
    // Attack rejection tests — the centerpiece
    // ============================================================

    function test_Attack_DirectUpgradeToAndCall_ByZothDeployer_Reverts() public {
        // The actual Zoth attack: compromised deployer EOA calls upgradeToAndCall
        // on the proxy with a malicious implementation. This is exactly what
        // happened on mainnet at block 22094140.
        USD0PPSubVaultProtectedV2 maliciousImpl = new USD0PPSubVaultProtectedV2();

        vm.prank(ZOTH_DEPLOYER);
        vm.expectRevert(HMACGuardedUUPS.UnauthenticatedUpgradeBlocked.selector);
        vault.upgradeToAndCall(address(maliciousImpl), "");
    }

    function test_Attack_DirectUpgrade_ByRandomAttacker_Reverts() public {
        // Even if the attacker isn't the legitimate admin, the attack must fail.
        USD0PPSubVaultProtectedV2 maliciousImpl = new USD0PPSubVaultProtectedV2();

        vm.prank(address(0xBADBAD));
        // This will revert with AccessControlUnauthorizedAccount because the
        // attacker isn't ADMIN_ROLE. ADMIN_ROLE check fires first.
        vm.expectRevert();
        vault.upgradeToAndCall(address(maliciousImpl), "");
    }

    function test_Attack_AuthEndpointWithoutHmac_ByZothDeployer_Reverts() public {
        // Attacker tries the authenticated endpoint but with garbage preimage
        // (because they don't have the chain seed).
        USD0PPSubVaultProtectedV2 maliciousImpl = new USD0PPSubVaultProtectedV2();
        bytes32 garbagePreimage = bytes32(uint256(0xDEAD));

        vm.txGasPrice(1e9);
        vm.prank(ZOTH_DEPLOYER);
        vm.expectRevert(HMACGuardedUUPS.InvalidChainPreimage.selector);
        vault.upgradeToAndCallAuth(address(maliciousImpl), "", garbagePreimage);
    }

    // ============================================================
    // Legitimate upgrade tests
    // ============================================================

    function test_LegitimateUpgrade_BySigner_Succeeds() public {
        // Legitimate signer (the same admin EOA, but with full key + chain seed)
        // performs an authenticated upgrade to V2.
        USD0PPSubVaultProtectedV2 implV2 = new USD0PPSubVaultProtectedV2();

        bytes32 preimage = _prepareValidUpgrade(address(implV2), "", ZOTH_DEPLOYER);
        vault.upgradeToAndCallAuth(address(implV2), "", preimage);

        // Verify upgrade took effect: V2 marker function now callable.
        assertEq(
            USD0PPSubVaultProtectedV2(address(vault)).v2Marker(),
            2,
            "V2 marker callable after upgrade"
        );

        // Chain advanced.
        assertEq(vault.getChainPosition(), 1, "chain position advanced");
        assertEq(vault.getCurrentCommitment(), preimage, "commitment is preimage");

        // Pre-upgrade state preserved.
        assertEq(vault.USD0PP(), address(0xFF1), "USD0PP preserved");
        assertEq(vault.router(), DUMMY_ROUTER, "router preserved");
        assertTrue(
            vault.hasRole(vault.ADMIN_ROLE(), ZOTH_DEPLOYER),
            "admin role preserved"
        );
    }

    function test_LegitimateUpgrade_NonAdminSigner_RevertsOnRoleCheck() public {
        // Even with valid HMAC and preimage, a non-admin caller must fail
        // because our port preserves Zoth's ADMIN_ROLE check.
        USD0PPSubVaultProtectedV2 implV2 = new USD0PPSubVaultProtectedV2();
        address rando = address(0xC0FFEE);

        bytes32 preimage = _prepareValidUpgrade(address(implV2), "", rando);

        // Rando lacks ADMIN_ROLE; AccessControlUnauthorizedAccount fires.
        vm.expectRevert();
        vault.upgradeToAndCallAuth(address(implV2), "", preimage);
    }

    function test_StateIntegrity_AttackDoesNotCorruptState() public {
        // After a failed attack, the chain position must NOT have advanced,
        // commitment must NOT have changed, and the contract must still work
        // for a subsequent legitimate upgrade.
        USD0PPSubVaultProtectedV2 maliciousImpl = new USD0PPSubVaultProtectedV2();

        // Failed attempt by Zoth deployer.
        vm.prank(ZOTH_DEPLOYER);
        try vault.upgradeToAndCall(address(maliciousImpl), "") {
            revert("attack should have failed");
        } catch {}

        // State unchanged.
        assertEq(vault.getChainPosition(), 0, "chain position unchanged");
        assertEq(vault.getCurrentCommitment(), chain[CHAIN_LENGTH], "commitment unchanged");

        // Now do a legitimate upgrade — should still work.
        USD0PPSubVaultProtectedV2 legitImpl = new USD0PPSubVaultProtectedV2();
        bytes32 preimage = _prepareValidUpgrade(address(legitImpl), "", ZOTH_DEPLOYER);
        vault.upgradeToAndCallAuth(address(legitImpl), "", preimage);

        // Upgrade succeeded.
        assertEq(vault.getChainPosition(), 1, "chain advanced after legit upgrade");
        assertEq(
            USD0PPSubVaultProtectedV2(address(vault)).v2Marker(),
            2,
            "V2 active"
        );
    }

    /// @notice End-to-end Python ↔ Solidity round-trip.
    /// @dev    Calldata, priority fee, and signer address below are produced
    ///         by `signing-service/print_demo_tx.py`. The contract here is
    ///         initialized with the chain seed `0x42 * 32` matching that script,
    ///         and the test verifies the contract accepts what Python produced
    ///         byte-for-byte.
    ///
    ///         Together with the cross-validation test in test_signing_service.py,
    ///         this proves the cryptographic primitives are interoperable end-to-end:
    ///         Python computes the binding/HMAC the same way Solidity does, and
    ///         the resulting transaction is accepted at the protected gate.
    ///
    ///         If this test fails after a SigningService change, regenerate the
    ///         hardcoded values by re-running print_demo_tx.py.
    function test_E2E_PythonProducedTxAccepted() public {
        // ====================================================================
        // VALUES PRODUCED BY THE PYTHON SIGNING SERVICE
        // ====================================================================
        bytes32 PYTHON_SEED = bytes32(uint256(
            0x4242424242424242424242424242424242424242424242424242424242424242
        ));
        uint256 PYTHON_CHAIN_LENGTH = 5;
        bytes32 PYTHON_INITIAL_COMMITMENT =
            0x0b8be38fcdf7e0686478f1e671994a63b79b32ffdca6df4e8d883b7ebcf795fc;
        address PYTHON_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        uint256 PYTHON_PRIORITY_FEE = 999953427;
        bytes memory PYTHON_CALLDATA = hex"c9b1f5fc000000000000000000000000000000000000000000000000000000000000aa0100000000000000000000000000000000000000000000000000000000000000605b97ccf802c7ac2463c127b28dbeed405d40cdea5e36910ed40f56573302957f0000000000000000000000000000000000000000000000000000000000000000";

        // Verify our local chain generation matches Python's.
        bytes32[] memory localChain = AuthHelper.generateChain(
            PYTHON_SEED,
            PYTHON_CHAIN_LENGTH
        );
        require(
            localChain[PYTHON_CHAIN_LENGTH] == PYTHON_INITIAL_COMMITMENT,
            "chain seed produces same tip in Python and Solidity"
        );

        // Deploy a fresh proxy with the Python-matching commitment.
        USD0PPSubVaultProtected pythonImpl = new USD0PPSubVaultProtected();
        bytes memory initData = abi.encodeCall(
            USD0PPSubVaultProtected.initialize,
            (
                address(0xFF1),
                address(0xFF2),
                DUMMY_ROUTER,
                PYTHON_SIGNER,
                PYTHON_INITIAL_COMMITMENT
            )
        );
        ERC1967Proxy pyProxy = new ERC1967Proxy(address(pythonImpl), initData);
        USD0PPSubVaultProtected pyVault = USD0PPSubVaultProtected(address(pyProxy));

        // Etch UUPS-valid bytecode at 0xAa01 so it has a proxiableUUID() function.
        // The call will still fail at the next UUPS check (notDelegated on
        // proxiableUUID), but the HMAC layer will have accepted the calldata
        // first - which is what we're testing.
        USD0PPSubVaultProtectedV2 v2Source = new USD0PPSubVaultProtectedV2();
        vm.etch(
            0x000000000000000000000000000000000000Aa01,
            address(v2Source).code
        );

        // Execute the Python-produced calldata. We expect:
        // - HMAC verification passes (binding agrees byte-for-byte)
        // - chain commitment advances (proves we got past Step 5 in the contract)
        // - upgrade then fails downstream at UUPS proxiableUUID check because
        //   0xAa01 has no real UUPS contract. THAT FAILURE IS EXPECTED.
        // What we're testing is whether the HMAC layer accepts Python's output.
        vm.fee(0);
        vm.txGasPrice(PYTHON_PRIORITY_FEE);
        vm.prank(PYTHON_SIGNER);

        (bool success, bytes memory returnData) = address(pyVault).call(
            PYTHON_CALLDATA
        );

        // The call will revert downstream of HMAC check. The crucial question:
        // does it revert with HMAC errors, or with downstream UUPS errors?
        if (returnData.length >= 4) {
            bytes4 selector;
            assembly {
                selector := mload(add(returnData, 0x20))
            }

            // These would indicate Python's cryptography doesn't match Solidity's:
            assertTrue(
                selector != HMACGuardedUUPS.InvalidChainPreimage.selector,
                "FAIL: Python's preimage rejected (chain mismatch)"
            );
            assertTrue(
                selector != HMACGuardedUUPS.InvalidHMACBinding.selector,
                "FAIL: Python's HMAC LSBs rejected (binding mismatch)"
            );

            // ERC1967InvalidImplementation (0x4c9c8ce3) is EXPECTED here —
            // the synthetic newImpl address has no UUPS contract. This means
            // the HMAC layer accepted Python's output and we got far enough
            // for UUPS to reject downstream.
            bytes4 ERC1967_INVALID = 0x4c9c8ce3;
            assertEq(
                selector,
                ERC1967_INVALID,
                "expected downstream UUPS check, not HMAC failure"
            );

            console2.log("Python-Solidity HMAC round-trip: SUCCESS");
            console2.log("  Solidity's HMAC layer accepted Python's calldata.");
            console2.log("  (Test stops here; full upgrade requires UUPS-valid impl.)");
        } else {
            // Empty revert data — would indicate something deeper went wrong.
            assertTrue(false, "unexpected empty revert");
        }

        // The HMAC check passed and would have advanced the chain... but the
        // UUPS check rolled everything back via revert. So getChainPosition
        // should still be 0. (HMAC update happens before super call; super
        // call reverts → whole tx reverts → chain unchanged.)
        assertEq(pyVault.getChainPosition(), 0, "chain unchanged after rolled-back tx");
    }
}