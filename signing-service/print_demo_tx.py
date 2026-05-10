"""Generate a deterministic demo transaction using the SigningService.

Output is hardcoded into Foundry test test_E2E_PythonSignedTxAccepted in
USD0PPSubVaultProtected.t.sol to prove that Python's signing service produces
transactions the Solidity contract accepts byte-for-byte.

Run this script once to refresh values if the SigningService logic changes.
The values printed must match what the Foundry test expects.
"""

from signing_service import HashChain, SigningService, BindingCodec

# Deterministic test inputs. These are the SAME values used in the Foundry
# test - any change here requires updating the test, and vice versa.
CHAIN_SEED = b"\x42" * 32
CHAIN_LENGTH = 5

# Fixed Anvil default key #0 - publicly known, never use in production.
SIGNING_KEY = bytes.fromhex(
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

# Test fixtures matching the Foundry test setup.
VAULT_ADDRESS = "0x0000000000000000000000000000000000000Bb1"
NEW_IMPL = "0x000000000000000000000000000000000000Aa01"
INIT_DATA = b""
CHAIN_POSITION = 0
NONCE = 0
CHAIN_ID = 31337  # local fork chain ID; doesn't matter for the test
BASE_FEE_WEI = 0  # Foundry test will set vm.fee(0)


def main():
    # Build the signing service.
    chain = HashChain.generate(CHAIN_SEED, CHAIN_LENGTH)
    service = SigningService(chain, SIGNING_KEY)

    # Construct the upgrade transaction.
    tx = service.build_upgrade_tx(
        vault_address=VAULT_ADDRESS,
        new_implementation=NEW_IMPL,
        init_data=INIT_DATA,
        chain_position=CHAIN_POSITION,
        nonce=NONCE,
        chain_id=CHAIN_ID,
        base_fee_wei=BASE_FEE_WEI,
    )

    print("=" * 70)
    print("Python-side demo transaction values")
    print("=" * 70)
    print(f"Signer address (msg.sender expected by contract):")
    print(f"  {service.signer_address}")
    print()
    print(f"Chain commitment (initial, used to initialize the contract):")
    print(f"  0x{chain.tip.hex()}")
    print()
    print(f"Preimage revealed at position 0:")
    print(f"  0x{chain.preimage_for_pos(0).hex()}")
    print()
    print(f"Calldata (the upgradeToAndCallAuth call):")
    print(f"  {tx['data']}")
    print()
    print(f"Priority fee (encodes HMAC LSBs in low 16 bits):")
    print(f"  {tx['maxPriorityFeePerGas']}")
    print(f"  Low 16 bits: 0x{tx['maxPriorityFeePerGas'] & 0xFFFF:04x}")
    print()
    print(f"For the Foundry test:")
    print(f"  vm.fee(0);")
    print(f"  vm.txGasPrice({tx['maxPriorityFeePerGas']});")
    print(f"  vm.prank({service.signer_address});")
    print(f"  vault.call(<calldata above>);")


if __name__ == "__main__":
    main()