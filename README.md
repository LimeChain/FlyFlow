# pqc-4337-laim

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
   git clone https://github.com/<owner>/pqc-4337-laim
   cd pqc-4337-laim
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

4. Run the full validation suite (ECDSA, Falcon, ML-DSA acceptance + rejection tests + low-S invariants + the gas benchmark):

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
   - **What you'll see:** a single table with one row per scheme (ecdsa, falcon, mldsa) showing absolute gas, calldata vs execution split, overhead vs the ECDSA baseline as a percentage, and per-scheme variance.

The committed `docs/gas-report.md` reflects the most recent benchmark run that landed on `main` — re-run steps 5–6 locally to refresh against your machine's gas numbers.

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
