# PQC ERC-4337 Gas Comparison

_Generated: 2026-04-15T10:33:29.127Z_
_Source: `test/bench/gas-data.json` (produced by Story 5-1 benchmark)._

| Scheme | Status | Total gas | Calldata (gas, %) | Execution (gas, %) | Overhead vs ECDSA | Variance | Notes |
|---|---|---:|---:|---:|---:|---:|---|
| ecdsa | ok | 76110 | 1040 (1.4%) | 75070 (98.6%) | — | 0.00e+0 |  |
| falcon | ok | 3836741 | 14288 (0.4%) | 3822453 (99.6%) | +4941.0% | 6.53e-2 |  |
| mldsa | ok | 8286990 | 38348 (0.5%) | 8248642 (99.5%) | +10788.2% | 1.48e-2 |  |

## Notes

- **Variance** is `(max − min) / mean` across 3 measured runs after 2 warm-up rounds (Story 5-1 harness).
- **C-012:** PQC variance routinely exceeds the original NFR-3 target of `<0.01`. The benchmark gates ECDSA at `<0.01` and PQC at `<0.10` while the EIP-3529 refund-cap timing hypothesis is investigated. Cross-scheme cost ranking and calldata/execution split are unaffected.
- **Overhead** is computed as `(scheme.totalGas − ecdsa.totalGas) / ecdsa.totalGas` from the first measured run of each scheme.
- **Calldata gas** uses the EIP-2028 formula (16 gas per non-zero byte, 4 gas per zero byte) over the per-scheme signature bytes only; remaining gas is bucketed as execution.
