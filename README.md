# Zoth Guard - Forward-Secure HMAC Authentication for UUPS Upgrades

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636.svg)](https://soliditylang.org)
[![Foundry](https://img.shields.io/badge/Foundry-1.6.0-orange.svg)](https://book.getfoundry.sh/)

> A drop-in base contract that hardens DeFi protocols against compromised-key upgrade attacks, validated against the $8.4M Zoth exploit.

---

## Table of Contents

- [Overview](#overview)
- [What It Defends Against](#what-it-defends-against)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Running the Demo](#running-the-demo)
- [Testing](#testing)
- [How It Works](#how-it-works)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [License](#license)
- [Contact](#contact)

---

## Overview

**Zoth Guard** is a base contract, `HMACGuardedUUPS`, that protocols inherit instead of OpenZeppelin's `UUPSUpgradeable`. It adds **forward-secure cryptographic authentication** on top of role-based gating, so that even an attacker with full admin key compromise cannot perform a malicious upgrade.

Adoption is one line. Where a Zoth-style contract inherits `UUPSUpgradeable`, a protected version inherits `HMACGuardedUUPS`. Everything else stays the same: business logic, role checks, storage layout.

The defense is validated against the **actual Zoth exploit of March 21, 2025** ($8.4M loss). On a forked Ethereum mainnet at the exploit block, the protected version rejects the exact attacker transaction that drained the real vault.

---

## What It Defends Against

- **Compromised admin keys.** According to Chainalysis, 43.8% of stolen crypto in 2024 came from private key compromises ($964M of $2.2B).
- **Direct UUPS upgrade bypass.** The standard `upgradeToAndCall` is also gated by the HMAC layer, not just `_authorizeUpgrade`.
- **Past-preimage replay.** Forward security via Lamport-style hash chains. Once a chain position advances, no past preimage can forge an upgrade.
- **Pre-staged malicious implementations.** The Zoth attacker pre-deployed their malicious contract six days before the exploit. The defense still holds.

---

## Architecture

```
   ┌──────────────────────────┐         ┌─────────────────────────┐
   │  Off-Chain Signing       │         │  On-Chain Guardian      │
   │  Service (Python)        │         │  HMACGuardedUUPS        │
   │                          │         │                         │
   │  • Holds chain seed      │ ──tx──▶ │  • Verifies preimage    │
   │  • Computes HMAC binding │         │  • Recomputes HMAC      │
   │  • Builds EIP-1559 tx    │         │  • Compares fee LSBs    │
   │  • Encodes LSBs in fee   │         │  • Advances chain       │
   └──────────────────────────┘         │  • Performs upgrade     │
                                        └─────────────────────────┘
```

### Components

#### `HMACGuardedUUPS` (Solidity)

- Abstract base contract that protocols inherit.
- Uses ERC-7201 namespaced storage to avoid layout collisions with the parent contract.
- EIP-1153 transient storage flag blocks direct `upgradeToAndCall` bypass.
- Override-friendly: protocols can layer additional checks (role gates, timelocks) in their own `_authorizeUpgrade`.

#### `HMACLib` (Solidity)

- Custom HMAC-SHA256 implementation (no precompile available).
- Validated against RFC 4231 test vectors.

#### Signing Service (Python)

- Holds the chain seed in a separate trust domain from the EOA key.
- Computes the HMAC binding for a given upgrade.
- Builds a signed EIP-1559 transaction with the HMAC LSBs encoded in the priority fee.
- Byte-identical to the Solidity contract's verification path (cross-validated in tests).

---

## Getting Started

Follow these steps to run **Zoth Guard** locally.

### Prerequisites

- **Foundry 1.6.0+**
- **Python 3.12+** for the signing service
- **Alchemy or Infura API key** for the forked-mainnet demo (free tier)

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url> zoth-guard
   cd zoth-guard
   ```
2. **Install Solidity dependencies**

   ```bash
   forge install
   ```
3. **Install Python dependencies**

   ```bash
   cd signing-service
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   cd ..
   ```
4. **Set up environment variables**

   Create a `.env` file in the project root:

   ```bash
   ALCHEMY_MAINNET_URL=https://eth-mainnet.g.alchemy.com/v2/<KEY>
   ETHERSCAN_API_KEY=<KEY>
   ```

---

## Running the Demo

The headline demonstration: a forked-mainnet replay where the actual Zoth exploit transactions drain $8.4M in the baseline scenario, and the same transactions are rejected in the protected scenario.

```bash
forge script script/RunZothDemo.s.sol:RunZothDemo \
  --rpc-url $ALCHEMY_MAINNET_URL -vv
```

Expected output (abbreviated):

```
============================================================
  SCENARIO 1: BASELINE (unprotected Zoth contract)
============================================================
BEFORE attack:
  Vault USD0PP balance:     8851750373778311459263000
  Attacker USD0PP balance:  0
AFTER attack:
  Vault USD0PP balance:     0
  Attacker USD0PP balance:  8851750373778311459263000
RESULT: vault drained.

============================================================
  SCENARIO 2: PROTECTED (HMACGuardedUUPS in place)
============================================================
Upgrade attempt: REJECTED
Drain attempt:   REJECTED
RESULT: vault preserves every token.
  USD0PP saved:             8851750373778311459263000
```

---

## Testing

### Solidity tests

```bash
forge test
```

Expected: **85 passing tests** across 8 test suites in under one second.

For verbose output with logs:

```bash
forge test -vv
```

To run a specific suite:

```bash
forge test --match-contract ZothFullReplayTest -vv
```

### Python tests

```bash
cd signing-service
source venv/bin/activate
pytest
```

Expected: **32 passing tests**, including byte-level cross-validation against the Solidity HMAC implementation.

### Total: 117 passing tests

- 27 HMACLib tests (RFC 4231 vectors, boundary conditions, regression)
- 20 HMACGuardedUUPS tests (happy path, attack rejection, forward security)
- 8 protected Zoth port tests (in isolation, with Python-Solidity round-trip)
- 20 forked-mainnet tests (smoke, etch, attack rejection, full replay)
- 10 AuthHelper sanity tests
- 32 Python tests (HashChain, BindingCodec, SigningService, cross-validation)

---

## How It Works

Each authenticated upgrade goes through six verification steps inside `upgradeToAndCallAuth`:

1. **Preimage check.** Verify that `sha256(preimage) == currentCommitment`. This proves the caller knows the next value in the hash chain.
2. **HMAC computation.** Compute `HMAC-SHA256(preimage, abi.encode(chainPosition, newImplementation, msg.sender, keccak256(data)))`.
3. **Fee LSB recovery.** Recover priority fee LSBs from `tx.gasprice - block.basefee`.
4. **HMAC binding check.** Verify that the low 16 bits of the HMAC match the recovered fee LSBs.
5. **Chain advance.** Set `currentCommitment = preimage` and increment `chainPosition`.
6. **Perform the upgrade.** Set a transient auth flag, call the inherited `upgradeToAndCall`, clear the flag.

The transient flag (EIP-1153) is what makes direct `upgradeToAndCall` calls fail: the inherited `_authorizeUpgrade` is overridden to revert unless the flag is set.

---

## Limitations

- **Does not protect against joint key + seed compromise.** If both leak, the attacker is the legitimate operator. The trust boundary is explicit: the seed must live in a different trust domain than the signing key.
- **Does not protect against bugs in the upgraded implementation.** The defense is on the upgrade authority, not on what gets installed.
- **Gas cost.** Each authenticated upgrade runs roughly 1M gas (a few dollars at typical fees). Acceptable for rare operations.
- **Chain rotation.** After N upgrades the chain exhausts and must be rotated. A `rotateChain` mechanism that reserves the chain's final position for rollover is the cleanest design.
- **16-bit HMAC binding** is brute-forceable in isolation (1/65536). The defense relies on layered checks (role, chain, HMAC) and on monitoring failed attempts.

---

## Future Improvements

- **Chain rotation mechanism.** Production `rotateChain(preimage, newCommitment)` function with operational tooling.
- **Wider HMAC binding via custom transaction fields.** EIP-7702 or similar could provide more space than the priority fee LSBs.
- **HSM integration for the signing service.** Reference implementation against AWS KMS or a hardware security module.
- **Multi-protocol audit.** Apply the same forked-mainnet validation methodology to other UUPS-based exploits (PolyNetwork, Wintermute, etc.).
- **Monitoring dashboard.** Real-time alerts for failed upgrade attempts on protected contracts.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

**Author:** Sohum Kashyap
GitHub: [S-K-23](https://github.com/S-K-23)

For issues, suggestions, or contributions, please open a GitHub issue or reach out directly.
