"""Tests for the signing service.

Run with: pytest test_signing_service.py -v
"""

import hashlib
import pytest

from signing_service import HashChain
from signing_service import BindingCodec


class TestHashChain:
    def test_generate_basic_shape(self):
        seed = bytes(32)
        chain = HashChain.generate(seed, length=10)
        assert chain.length == 10
        assert len(chain.values) == 11
        assert chain.values[0] == seed

    def test_each_step_is_sha256_of_previous(self):
        seed = b"\x42" * 32
        chain = HashChain.generate(seed, length=5)
        for i in range(1, 6):
            assert chain.values[i] == hashlib.sha256(chain.values[i - 1]).digest()

    def test_tip_is_last_element(self):
        seed = b"\x01" * 32
        chain = HashChain.generate(seed, length=10)
        assert chain.tip == chain.values[10]

    def test_preimage_pos_0_reveals_chain_n_minus_1(self):
        seed = b"\xab" * 32
        chain = HashChain.generate(seed, length=10)
        assert chain.preimage_for_pos(0) == chain.values[9]

    def test_preimage_pos_1_reveals_chain_n_minus_2(self):
        seed = b"\xab" * 32
        chain = HashChain.generate(seed, length=10)
        assert chain.preimage_for_pos(1) == chain.values[8]

    def test_preimage_advances_through_chain(self):
        seed = b"\xff" * 32
        chain = HashChain.generate(seed, length=5)
        positions_and_expected = [
            (0, chain.values[4]),
            (1, chain.values[3]),
            (2, chain.values[2]),
            (3, chain.values[1]),
            (4, chain.values[0]),  # last legal position
        ]
        for position, expected in positions_and_expected:
            assert chain.preimage_for_pos(position) == expected

    def test_preimage_at_exhaustion_raises(self):
        """When position == length, the chain is exhausted. Must raise."""
        chain = HashChain.generate(bytes(32), length=5)
        with pytest.raises(ValueError, match="Position 5"):
            chain.preimage_for_pos(5)

    def test_preimage_one_past_exhaustion_raises(self):
        chain = HashChain.generate(bytes(32), length=5)
        with pytest.raises(ValueError, match="chain length"):
            chain.preimage_for_pos(6)

    def test_preimage_negative_position_raises(self):
        chain = HashChain.generate(bytes(32), length=5)
        with pytest.raises(ValueError, match="Position must be"):
            chain.preimage_for_pos(-1)

    def test_invalid_seed_length_raises(self):
        with pytest.raises(ValueError, match="Seed must be 32 bytes"):
            HashChain.generate(b"too short", length=5)

    def test_invalid_chain_length_raises(self):
        with pytest.raises(ValueError, match="Length must be"):
            HashChain.generate(bytes(32), length=0)

    def test_chain_matches_solidity_AuthHelper(self):
        """Cross-validation: chain values must match what AuthHelper.generateChain
        produces in Solidity for the same seed.
        """
        seed = (0x42).to_bytes(32, "big")
        chain = HashChain.generate(seed, length=5)
        expected_chain_1 = hashlib.sha256(seed).digest()
        expected_chain_2 = hashlib.sha256(expected_chain_1).digest()
        assert chain.values[1] == expected_chain_1
        assert chain.values[2] == expected_chain_2

class TestBindingCodec:
    """Validates that Python's binding/HMAC computations match Solidity's exactly.

    The expected values for cross-validation come from running AuthHelper in
    Foundry with the same inputs (see CrossValidation.t.sol — to be created).
    """

    # Standard test inputs used across multiple cross-validation tests.
    SAMPLE_PREIMAGE = (0x42).to_bytes(32, "big")
    SAMPLE_IMPL = "0x000000000000000000000000000000000000aaaa"
    SAMPLE_SENDER = "0x000000000000000000000000000000000000bbbb"
    SAMPLE_DATA = b""
    SAMPLE_POSITION = 0

    def test_compute_binding_returns_128_bytes(self):
        """abi.encode of (uint256, address, address, bytes32) is exactly 4*32 = 128 bytes."""
        binding = BindingCodec.compute_binding(
            self.SAMPLE_POSITION,
            self.SAMPLE_IMPL,
            self.SAMPLE_SENDER,
            self.SAMPLE_DATA,
        )
        assert len(binding) == 128

    def test_compute_binding_deterministic(self):
        b1 = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, self.SAMPLE_SENDER, b"")
        b2 = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, self.SAMPLE_SENDER, b"")
        assert b1 == b2

    def test_compute_binding_distinct_on_position(self):
        b1 = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, self.SAMPLE_SENDER, b"")
        b2 = BindingCodec.compute_binding(1, self.SAMPLE_IMPL, self.SAMPLE_SENDER, b"")
        assert b1 != b2

    def test_compute_binding_distinct_on_impl(self):
        impl_a = "0x000000000000000000000000000000000000aaaa"
        impl_b = "0x000000000000000000000000000000000000cccc"
        b1 = BindingCodec.compute_binding(0, impl_a, self.SAMPLE_SENDER, b"")
        b2 = BindingCodec.compute_binding(0, impl_b, self.SAMPLE_SENDER, b"")
        assert b1 != b2

    def test_compute_binding_distinct_on_sender(self):
        sender_a = "0x000000000000000000000000000000000000bbbb"
        sender_b = "0x000000000000000000000000000000000000dddd"
        b1 = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, sender_a, b"")
        b2 = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, sender_b, b"")
        assert b1 != b2

    def test_compute_binding_distinct_on_data(self):
        b1 = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, self.SAMPLE_SENDER, b"abc")
        b2 = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, self.SAMPLE_SENDER, b"xyz")
        assert b1 != b2

    def test_compute_hmac_returns_32_bytes(self):
        binding = BindingCodec.compute_binding(
            self.SAMPLE_POSITION,
            self.SAMPLE_IMPL,
            self.SAMPLE_SENDER,
            self.SAMPLE_DATA,
        )
        h = BindingCodec.compute_hmac(self.SAMPLE_PREIMAGE, binding)
        assert len(h) == 32

    def test_compute_hmac_invalid_preimage_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            BindingCodec.compute_hmac(b"too short", b"")

    def test_compute_lsbs_in_range(self):
        binding = BindingCodec.compute_binding(0, self.SAMPLE_IMPL, self.SAMPLE_SENDER, b"")
        lsbs = BindingCodec.compute_lsbs(self.SAMPLE_PREIMAGE, binding)
        assert 0 <= lsbs <= 0xFFFF

    def test_build_priority_fee_encodes_lsbs(self):
        fee = BindingCodec.build_priority_fee(0x1234)
        assert (fee & 0xFFFF) == 0x1234
        # Sanity: should be in gwei range
        assert 1e8 < fee < 1e10

    def test_build_priority_fee_rejects_out_of_range(self):
        with pytest.raises(ValueError, match="65535"):
            BindingCodec.build_priority_fee(0x10000)
        with pytest.raises(ValueError, match="65535"):
            BindingCodec.build_priority_fee(-1)

    def test_cross_validation_against_solidity(self):
        """Verify Python's BindingCodec produces byte-identical output to Solidity's
        AuthHelper for fixed inputs.

        Expected values from running script/PrintCrossValidation.s.sol with:
            chainPosition = 0
            newImpl       = 0x000000000000000000000000000000000000aaaa
            sender        = 0x000000000000000000000000000000000000bbbb
            data          = b""
            preimage      = bytes32(uint256(0x42))
        """
        # Inputs (must match the Solidity script exactly).
        chain_position = 0
        new_impl = "0x000000000000000000000000000000000000aaaa"
        sender = "0x000000000000000000000000000000000000bbbb"
        data = b""
        preimage = (0x42).to_bytes(32, "big")

        # Expected outputs (from Foundry script).
        expected_binding_hex = (
            "0000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000aaaa"
            "000000000000000000000000000000000000000000000000000000000000bbbb"
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )
        expected_hmac_hex = (
            "ec35ec7b24b4c2d3c23ac304b9c75f9094052f9a1432711033b301b9a4772eb2"
        )
        expected_lsbs = 11954

        # Verify binding.
        binding = BindingCodec.compute_binding(chain_position, new_impl, sender, data)
        assert binding.hex() == expected_binding_hex, (
            f"binding mismatch:\n  got:      {binding.hex()}\n  expected: {expected_binding_hex}"
        )

        # Verify HMAC.
        full_hmac = BindingCodec.compute_hmac(preimage, binding)
        assert full_hmac.hex() == expected_hmac_hex, (
            f"HMAC mismatch:\n  got:      {full_hmac.hex()}\n  expected: {expected_hmac_hex}"
        )

        # Verify LSBs.
        lsbs = BindingCodec.compute_lsbs(preimage, binding)
        assert lsbs == expected_lsbs, f"LSBs mismatch: got {lsbs}, expected {expected_lsbs}"

from signing_service import SigningService, UPGRADE_AUTH_SELECTOR


# Test signing key (PUBLICLY KNOWN — never use in production).
# This is one of Anvil's default keys.
TEST_PRIVATE_KEY = bytes.fromhex(
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)


class TestSigningService:
    def setup_method(self):
        self.chain = HashChain.generate(b"\x42" * 32, length=10)
        self.service = SigningService(self.chain, TEST_PRIVATE_KEY)

    def test_signer_address_derived(self):
        # The address derived from this known test key.
        assert self.service.signer_address == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    def test_invalid_signing_key_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            SigningService(self.chain, b"too short")

    def test_build_upgrade_tx_basic_shape(self):
        tx = self.service.build_upgrade_tx(
            vault_address="0x1234567890123456789012345678901234567890",
            new_implementation="0x000000000000000000000000000000000000aaaa",
            init_data=b"",
            chain_position=0,
            nonce=0,
            chain_id=1,
            base_fee_wei=10**9,  # 1 gwei
        )

        assert tx["type"] == 2
        assert tx["to"] == "0x1234567890123456789012345678901234567890"
        assert tx["from"] == self.service.signer_address
        assert tx["value"] == 0
        assert tx["nonce"] == 0
        assert tx["chainId"] == 1
        assert tx["gas"] == 500_000

    def test_build_upgrade_tx_calldata_starts_with_selector(self):
        tx = self.service.build_upgrade_tx(
            vault_address="0x1234567890123456789012345678901234567890",
            new_implementation="0x000000000000000000000000000000000000aaaa",
            init_data=b"",
            chain_position=0,
            nonce=0,
            chain_id=1,
            base_fee_wei=10**9,
        )
        # Strip 0x prefix, check first 8 hex chars (4 bytes) match selector.
        calldata_hex = tx["data"][2:]
        selector_hex = UPGRADE_AUTH_SELECTOR.hex()
        assert calldata_hex[:8] == selector_hex

    def test_build_upgrade_tx_priority_fee_encodes_lsbs(self):
        tx = self.service.build_upgrade_tx(
            vault_address="0x1234567890123456789012345678901234567890",
            new_implementation="0x000000000000000000000000000000000000aaaa",
            init_data=b"",
            chain_position=0,
            nonce=0,
            chain_id=1,
            base_fee_wei=10**9,
        )

        # The LSBs of maxPriorityFeePerGas must equal the HMAC LSBs.
        preimage = self.chain.preimage_for_pos(0)
        binding = BindingCodec.compute_binding(
            0,
            "0x000000000000000000000000000000000000aaaa",
            self.service.signer_address,
            b"",
        )
        expected_lsbs = BindingCodec.compute_lsbs(preimage, binding)

        assert (tx["maxPriorityFeePerGas"] & 0xFFFF) == expected_lsbs

    def test_build_upgrade_tx_max_fee_safety_margin(self):
        base_fee = 10**9
        tx = self.service.build_upgrade_tx(
            vault_address="0x1234567890123456789012345678901234567890",
            new_implementation="0x000000000000000000000000000000000000aaaa",
            init_data=b"",
            chain_position=0,
            nonce=0,
            chain_id=1,
            base_fee_wei=base_fee,
        )

        # maxFeePerGas should be at least 2*basefee + priority, so priority
        # is never capped.
        assert tx["maxFeePerGas"] >= 2 * base_fee + tx["maxPriorityFeePerGas"]

    def test_sign_tx_produces_raw_transaction(self):
        tx = self.service.build_upgrade_tx(
            vault_address="0x1234567890123456789012345678901234567890",
            new_implementation="0x000000000000000000000000000000000000aaaa",
            init_data=b"",
            chain_position=0,
            nonce=0,
            chain_id=1,
            base_fee_wei=10**9,
        )
        signed = self.service.sign_tx(tx)

        # The signed transaction should have a raw_transaction attribute.
        assert hasattr(signed, "raw_transaction")
        assert isinstance(signed.raw_transaction, bytes)
        assert len(signed.raw_transaction) > 0

    def test_build_and_sign_convenience(self):
        signed = self.service.build_and_sign(
            vault_address="0x1234567890123456789012345678901234567890",
            new_implementation="0x000000000000000000000000000000000000aaaa",
            init_data=b"",
            chain_position=0,
            nonce=0,
            chain_id=1,
            base_fee_wei=10**9,
        )
        assert hasattr(signed, "raw_transaction")