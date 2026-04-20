# PQC ERC-4337 Gas Comparison

_Generated: 2026-04-20T20:16:43.864Z_
_Source: `test/bench/gas-data.json` (produced by Story 5-1 benchmark)._

| Scheme | Status | Total gas | Calldata (gas, %) | Execution (gas, %) | Overhead vs ECDSA | Variance | Notes |
|---|---|---:|---:|---:|---:|---:|---|
| ecdsa | ok | 76098 | 1028 (1.4%) | 75070 (98.6%) | — | 1.58e-4 |  |
| falcon | ok | 4090491 | 14264 (0.3%) | 4076227 (99.7%) | +5275.3% | 6.50e-2 |  |
| mldsa | ok | 8378277 | 38456 (0.5%) | 8339821 (99.5%) | +10909.9% | 7.14e-3 |  |
| mldsa-eth | ok | 4946763 | 38432 (0.8%) | 4908331 (99.2%) | +6400.5% | 1.06e-3 |  |
| falcon-eth | ok | 1536489 | 13952 (0.9%) | 1522537 (99.1%) | +1919.1% | 3.91e-4 |  |

## Notes

- **Variance** is `(max − min) / mean` across 3 measured runs after 2 warm-up rounds (Story 5-1 harness).
- **C-012:** PQC variance routinely exceeds the original NFR-3 target of `<0.01`. The benchmark gates ECDSA at `<0.01` and PQC at `<0.10` while the EIP-3529 refund-cap timing hypothesis is investigated. Cross-scheme cost ranking and calldata/execution split are unaffected.
- **Overhead** is computed as `(scheme.totalGas − ecdsa.totalGas) / ecdsa.totalGas` from the first measured run of each scheme.
- **Calldata gas** uses the EIP-2028 formula (16 gas per non-zero byte, 4 gas per zero byte) over the per-scheme signature bytes only; remaining gas is bucketed as execution.

## ML-DSA-ETH ↔ Falcon-ETH pairwise delta

| Metric | ML-DSA-ETH | Falcon-ETH | Delta |
|---|---:|---:|---:|
| Verify gas (first run) | 4946763 | 1536489 | -68.9% |
| Calldata gas | 38432 | 13952 | -24480 |
