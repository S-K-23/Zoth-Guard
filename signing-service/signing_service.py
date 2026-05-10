import hashlib
from dataclasses import dataclass
from typing import List
import hmac as hmac_mod

from eth_abi import encode as abi_encode
from eth_utils import keccak

from eth_account import Account
from eth_account.signers.local import LocalAccount


@dataclass
class HashChain:
    """A SHA-256 hash chain of length N+1.
    """
    seed: bytes
    length: int 
    values: List[bytes]

    @classmethod
    def generate(cls, seed: bytes, length: int) -> "HashChain":
        
        """ Build a new chain from 32 byte seed

        Args:
            seed: 32 bytes
            length: number of hash steps (N). Chain will have N valid upgrades
        """

        if (len(seed) != 32):
            raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")
        if length < 1:
            raise ValueError(f"Length must be > 1, got length {length}")
        
        values = [seed]
        for _ in range(length):
            values.append(hashlib.sha256(values[-1]).digest())

        return cls(seed=seed, length = length, values = values)
    
    @property
    def tip(self) -> None:
        """ Terminal value of the chain. Initializes the contract """
        return self.values[self.length]
    

    def preimage_for_pos(self, position: int) -> bytes:
        """ Return the preimage to reveal the current chain position 
        Position 0 reveals [N-1]
        Position 1 reveals [N-2], etc
        """
    
        if position < 0:
            raise ValueError(f"Position must be > 0, position is {position}")
        if position >= self.length:
            raise ValueError(
                f"Position {position} > chain length {self.length}"
                f"Make a new chain"
            )
        return self.values[self.length - 1 - position]

class BindingCodec:
    """ Mirrors the binding computation in HMACGuardedUUPS.sol. 
    
    The contract computes:
    bindingData = abi.encode(chainPosition, newImplementation, msg.sender, keccak256(data))
    hmac = HMAC-SHA256(preimage, bindingData)
    expectedLSBs = hmac & 0xFFFF 

    This class produces identical output to the Solidity computation.
    """

    @staticmethod
    def compute_binding(chain_position: int, new_implementation: str, sender: str, data: bytes) -> bytes:

        """Reproduce abi.encode(uint256, address, address, bytes32) where
        the bytes32 is keccak256(data).

        Args:
            chain_position: Current chain position (uint256).
            new_imp: Hex address of the implementation.
            sender: Hex address of the sender.
            data: Raw bytes of the upgrade init calldata.

        Returns:
            128 bytes — the abi-encoded binding.
        """
        hash = keccak(data)

        return abi_encode(["uint256", "address", "address", "bytes32"],
                          [chain_position, new_implementation, sender, hash]
                          )

    @staticmethod
    def compute_hmac(preimage: bytes, binding: bytes) -> bytes:
        """ Compute HMAC-SHA256(preimage, binding). Returns 32 bytes. """
        if len(preimage) != 32:
            raise ValueError(f"preimage must be 32 bytes, got {len(preimage)}")
        return hmac_mod.new(preimage, binding, hashlib.sha256).digest()

    @staticmethod
    def compute_lsbs(preimage: bytes, binding: bytes) -> int:
        """ Compute the low 16 bits of HMAC-SHA256(preimage, binding).
        Returns an int in [0, 65535].
        """
        full_hmac = BindingCodec.compute_hmac(preimage, binding)
        return int.from_bytes(full_hmac, "big") & 0xFFFF

    @staticmethod
    def build_priority_fee(lsbs: int, base_gwei: int = 1) -> int:
        """ Construct a priority fee value whose low 16 bits equal `lsbs`.

        Args:
            lsbs: The HMAC LSBs to encode.
            base_gwei: The base priority fee in Gwei. Default 1.

        Returns:
            Priority fee in wei, encoding the LSBs.
        """
        if not (0 <= lsbs <= 0xFFFF):
            raise ValueError(f"lsbs must be in [0, 65535], got {lsbs}")
        base_wei = base_gwei * 10**9
        return (base_wei & ~0xFFFF) | lsbs


# Function selector for upgradeToAndCallAuth(address,bytes,bytes32).
# Computed as keccak256("upgradeToAndCallAuth(address,bytes,bytes32)")[0:4].
UPGRADE_AUTH_SELECTOR = keccak(b"upgradeToAndCallAuth(address,bytes,bytes32)")[:4]


class SigningService:
    """ Orchestrates chain + binding codec + EOA signing to produce signed
    upgrade transactions for HMACGuardedUUPS-protected contracts.

    The service holds the chain seed and the signing key. In production these
    must live in different trust domains; for this POC they share a process.
    """

    def __init__(self, chain: HashChain, signing_key: bytes):
        if len(signing_key) != 32:
            raise ValueError(f"signing_key must be 32 bytes, got {len(signing_key)}")
        self._chain = chain
        self._account: LocalAccount = Account.from_key(signing_key)

    @property
    def signer_address(self) -> str:
        """ The EOA address derived from the signing key. """
        return self._account.address

    def build_upgrade_tx(
        self,
        vault_address: str,
        new_implementation: str,
        init_data: bytes,
        chain_position: int,
        nonce: int,
        chain_id: int,
        base_fee_wei: int,
        gas_limit: int = 500_000,
    ) -> dict:
        """ Build an unsigned EIP-1559 transaction that calls upgradeToAndCallAuth.

        Args:
            vault_address: The proxy contract being upgraded.
            new_implementation: New implementation address.
            init_data: Initialization calldata for the new implementation (often empty).
            chain_position: Current chain position read from the on-chain contract.
            nonce: The signer's transaction nonce.
            chain_id: EIP-155 chain id (1 = mainnet, 11155111 = sepolia, etc).
            base_fee_wei: Current base fee, used to compute maxFeePerGas with safety margin.
            gas_limit: Gas limit for the transaction. Default 500k, generous for HMAC verification.

        Returns:
            An unsigned EIP-1559 transaction dict, ready to be passed to sign_tx().
        """
        # Step 1: Get the next preimage for this chain position.
        preimage = self._chain.preimage_for_pos(chain_position)

        # Step 2: Compute the HMAC binding and LSBs.
        binding = BindingCodec.compute_binding(
            chain_position,
            new_implementation,
            self.signer_address,
            init_data,
        )
        lsbs = BindingCodec.compute_lsbs(preimage, binding)

        # Step 3: Build the priority fee that encodes the LSBs.
        max_priority_fee = BindingCodec.build_priority_fee(lsbs, base_gwei=1)

        # Step 4: Set max fee high enough that priority isn't capped.
        # Recommended: 2 * base_fee + max_priority_fee.
        max_fee = 2 * base_fee_wei + max_priority_fee

        # Step 5: Encode the function call.
        # upgradeToAndCallAuth(address newImpl, bytes data, bytes32 preimage)
        encoded_args = abi_encode(
            ["address", "bytes", "bytes32"],
            [new_implementation, init_data, preimage],
        )
        calldata = UPGRADE_AUTH_SELECTOR + encoded_args

        # Step 6: Assemble the transaction dict.
        return {
            "to": vault_address,
            "from": self.signer_address,
            "value": 0,
            "data": "0x" + calldata.hex(),
            "nonce": nonce,
            "chainId": chain_id,
            "gas": gas_limit,
            "maxPriorityFeePerGas": max_priority_fee,
            "maxFeePerGas": max_fee,
            "type": 2,  # EIP-1559
        }

    def sign_tx(self, tx: dict):
        """ Sign a transaction dict with the EOA key. Returns SignedTransaction object. """
        return self._account.sign_transaction(tx)

    def build_and_sign(
        self,
        vault_address: str,
        new_implementation: str,
        init_data: bytes,
        chain_position: int,
        nonce: int,
        chain_id: int,
        base_fee_wei: int,
        gas_limit: int = 500_000,
    ):
        """ Convenience: build and sign in one call. Returns SignedTransaction. """
        tx = self.build_upgrade_tx(
            vault_address=vault_address,
            new_implementation=new_implementation,
            init_data=init_data,
            chain_position=chain_position,
            nonce=nonce,
            chain_id=chain_id,
            base_fee_wei=base_fee_wei,
            gas_limit=gas_limit,
        )
        return self.sign_tx(tx)

