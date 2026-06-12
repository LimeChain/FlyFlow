# FlyFlow

Post-quantum cryptography integration for ERC-4337 account abstraction, using ZKNox's audited FALCON and DILITHIUM Solidity implementations.

## Pinned Dependencies

Submodules are pinned to specific commit SHAs (never branches) per security policy (NFR-5).

| Submodule    | URL                                            | Pinned SHA                                 | Source release                                                     |
|--------------|------------------------------------------------|--------------------------------------------|--------------------------------------------------------------------|
| ETHFALCON    | https://github.com/ZKNoxHQ/ETHFALCON           | `03ed0d60c67087527de7c4a3c1c469b89611bd68` | `main` snapshot 2026-04-14 (no release tags published upstream)    |
| ETHDILITHIUM | https://github.com/ZKNoxHQ/ETHDILITHIUM        | `b9ca7f72526ecc696230d3c774a6e2c12c9b37c2` | `main` snapshot 2026-04-14 (no release tags published upstream)    |

Neither upstream repository publishes git tags or release branches. The pinned SHAs correspond to the latest `main` HEAD at the time of integration. Both SHAs were verified to contain the required entry-point files (`src/ZKNOX_falcon.sol` and `src/ZKNOX_dilithium.sol`).

To update a submodule:

```bash
cd <submodule-path>
git fetch origin
git checkout <new-sha>
cd ..
git add <submodule-path>
# Update the table above with the new SHA and rationale.
```

Submodule source is never modified in-tree (NFR-5). Any necessary adapter logic lives outside the submodule directories.

## Running the suite

1. Clone the repository and initialize submodules:

   ```bash
   git clone https://github.com/<owner>/flyflow
   cd flyflow
   git submodule update --init --recursive
   ```

   (Replace `<owner>` with the actual GitHub owner.)

2. Install dependencies:

   ```bash
   npm install
   ```

3. Compile contracts (also runs the warnings-as-errors gate):

   ```bash
   npm run compile
   ```

4. Run the full validation suite (ECDSA, Falcon, ML-DSA (NIST), ML-DSA-ETH (Keccak-PRG variant), and Falcon-ETH (Keccak-HashToPoint variant) acceptance + rejection tests + low-S invariants + the gas benchmark):

   ```bash
   npm test
   ```

5. Re-run only the gas benchmark in isolation (writes `test/bench/gas-data.json`):

   ```bash
   npx hardhat test test/bench/gas-benchmark.test.ts
   ```

6. Generate the comparison report from the captured gas data:

   ```bash
   npm run report
   ```

   This writes [`docs/gas-report.md`](docs/gas-report.md).

7. Read the report:

   - **Path:** [`docs/gas-report.md`](docs/gas-report.md)
   - **What you'll see:** a single table with one row per scheme (ecdsa, falcon, mldsa, mldsa-eth, falcon-eth) showing absolute gas, calldata vs execution split, overhead vs the ECDSA baseline as a percentage, and per-scheme variance. A pairwise ML-DSA-ETH ↔ Falcon-ETH delta section follows the main table.

The committed `docs/gas-report.md` reflects the most recent benchmark run that landed on `main` — re-run steps 5–6 locally to refresh against your machine's gas numbers.

## Supported schemes

| Scheme       | Algorithm                             | Signature size | Verifier origin                                                                                      |
|--------------|---------------------------------------|---------------:|------------------------------------------------------------------------------------------------------|
| `ecdsa`      | secp256k1 ECDSA                       |         65 B   | Ethereum-native                                                                                      |
| `falcon`     | Falcon-512 (NIST, SHAKE-HashToPoint)  |       1064 B   | [ZKNoxHQ/ETHFALCON](https://github.com/ZKNoxHQ/ETHFALCON) — `ZKNOX_falcon.sol`                       |
| `mldsa`      | ML-DSA-44 (NIST, SHAKE)               |       2420 B   | [ZKNoxHQ/ETHDILITHIUM](https://github.com/ZKNoxHQ/ETHDILITHIUM) — `ZKNOX_dilithium.sol`              |
| `mldsa-eth`  | ML-DSA-44 (Keccak-PRG variant)        |       2420 B   | [ZKNoxHQ/ETHDILITHIUM](https://github.com/ZKNoxHQ/ETHDILITHIUM) — `ZKNOX_ethdilithium.sol`           |
| `falcon-eth` | Falcon-512 (Keccak-HashToPoint variant)|       1064 B  | [ZKNoxHQ/ETHFALCON](https://github.com/ZKNoxHQ/ETHFALCON) — `ZKNOX_ethfalcon.sol`                    |

ZKNoxHQ authored the ETHFalcon and ETHDilithium designs (both Keccak-based ETH variants) and all four PQC Solidity verifiers integrated here (`ZKNOX_falcon.sol`, `ZKNOX_ethfalcon.sol`, `ZKNOX_dilithium.sol`, `ZKNOX_ethdilithium.sol`). This repository integrates their audited implementations as ERC-4337 account modules without modifying submodule sources (NFR-5).

The `mldsa` and `mldsa-eth` schemes share the same 2420-byte signature layout (`cTilde(32) || z(2304) || h(84)`) and identical FIPS 204 parameters — they differ only in the XOF primitive driving keygen + sign: NIST uses SHAKE-256/SHAKE-128, ETH uses Keccak-PRG for every XOF role. Keys generated under one variant are NOT interchangeable with the other.

The `falcon` and `falcon-eth` schemes share the same 1064-byte signature layout (`salt(40) || s2_compact(1024)`) and identical Falcon-512 parameters — they differ only in the HashToPoint XOF: `falcon` uses SHAKE-256, `falcon-eth` uses Keccak-256 (the ZKNox ETHFALCON variant). Keys generated under one variant are NOT interchangeable with the other.

**Python dev-oracle isolation (NFR-3):** the Python reference in `ETHDILITHIUM/pythonref/` is invoked exclusively by `scripts/generate-kat-fixtures.ts` at fixture-regeneration time (`npm run kat:regen`). `npm test` never spawns a Python interpreter — all runtime crypto is TypeScript + Solidity.

## Runbook: OOG during validation

If a user-op reverts with out-of-gas (OOG) during `validateUserOp`, the most common cause is the Hardhat 3 EDR per-tx gas cap (`tx_gas_limit_cap = 2^24 = 16,777,216`, per NFR-5). On-chain verify gas measured by the 5-scheme benchmark (see [`docs/gas-report.md`](docs/gas-report.md)):

| Scheme       | Verify gas (first run) | Headroom vs 2^24 cap |
|--------------|-----------------------:|---------------------:|
| `ecdsa`      |                 76,098 |                ~220× |
| `falcon-eth` |              1,536,489 |               ~10.9× |
| `falcon`     |              4,090,491 |                ~4.1× |
| `mldsa-eth`  |              4,946,763 |                ~3.4× |
| `mldsa`      |              8,378,277 |                ~2.0× |

Re-run the bench (`npx hardhat test test/bench/gas-benchmark.test.ts`) after changing `preVerificationGas`, signature layout, or verifier imports. The committed [`docs/gas-report.md`](docs/gas-report.md) is the canonical snapshot.

**Pre-audit posture (`@custom:experimental`):** `FalconEthAccount` and `MlDsaEthAccount` carry the `@custom:experimental` NatSpec tag — the Keccak-based ETH variants are not yet audited. Production deployments should pin the NIST variants (`falcon`, `mldsa`) until audits land.

## Fixtures

KAT (known-answer-test) fixtures under `test/fixtures/kat/` are regenerated
from the pinned `ETHDILITHIUM/` submodule via:

```bash
npm run kat:regen
```

Regeneration requires Python 3.9+ with the submodule's `dilithium_py`
dependencies installed (`pip install -r ETHDILITHIUM/pythonref/requirements.txt`).
The CLI verifies submodule pin, Python version, and dependencies before
writing fixtures — see `scripts/generate-kat-fixtures.ts` for diagnostic
codes.
