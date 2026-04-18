# PQC ERC-4337 Gas Comparison

_Generated: 2026-04-18T17:36:44.080Z_
_Source: `test/bench/gas-data.json` (produced by Story 5-1 benchmark)._

| Scheme | Status | Total gas | Calldata (gas, %) | Execution (gas, %) | Overhead vs ECDSA | Variance | Notes |
|---|---|---:|---:|---:|---:|---:|---|
| ecdsa | ok | 76110 | 1040 (1.4%) | 75070 (98.6%) | — | 1.58e-4 |  |
| falcon | ok | 4090133 | 14396 (0.4%) | 4075737 (99.6%) | +5274.0% | 6.37e-2 |  |
| mldsa | ok | 8438754 | 38408 (0.5%) | 8400346 (99.5%) | +10987.6% | 7.48e-3 |  |
| mldsa-eth | ok | 4944863 | 38444 (0.8%) | 4906419 (99.2%) | +6397.0% | 1.12e-3 |  |

## Notes

- **Variance** is `(max − min) / mean` across 3 measured runs after 2 warm-up rounds (Story 5-1 harness).
- **C-012:** PQC variance routinely exceeds the original NFR-3 target of `<0.01`. The benchmark gates ECDSA at `<0.01` and PQC at `<0.10` while the EIP-3529 refund-cap timing hypothesis is investigated. Cross-scheme cost ranking and calldata/execution split are unaffected.
- **Overhead** is computed as `(scheme.totalGas − ecdsa.totalGas) / ecdsa.totalGas` from the first measured run of each scheme.
- **Calldata gas** uses the EIP-2028 formula (16 gas per non-zero byte, 4 gas per zero byte) over the per-scheme signature bytes only; remaining gas is bucketed as execution.
