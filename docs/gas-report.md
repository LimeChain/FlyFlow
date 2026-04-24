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

## What the benchmark signs

The benchmark signs a deliberately-minimal `PackedUserOperation` (defined at `test/bench/gas-benchmark.test.ts:119-133`) — scheme-agnostic apart from the signature field itself:

| Field | Value | What it means |
|---|---|---|
| `sender` | proxy address of the deployed account | The 4337 account being benchmarked (per scheme) |
| `nonce` | `2n / 3n / 4n` (measured); `0n / 1n` (warm-up) | Sequential — bench measures runs 2-4 after 2 warm-ups so EIP-2929 cold SLOADs and EIP-3529 refund accounting have stabilised |
| `initCode` | `"0x"` | No factory deployment — account is pre-deployed via `ERC1967Proxy` outside the measurement loop |
| `callData` | `"0x"` | No execute payload. The post-validation execution phase is a near-no-op so the captured gas reflects the validation path, not arbitrary call work |
| `accountGasLimits` | `pack128(15_000_000, 100_000)` | High `verificationGasLimit` (15 M) so ML-DSA's ~10 M verify fits, plus the EIP-150 63/64 forwarding margin through EntryPoint → account → verifier; tiny `callGasLimit` (100k) since callData is empty |
| `preVerificationGas` | `100_000` | Fixed across schemes; covers the EntryPoint's pre-validation overhead the bundler reimburses |
| `gasFees` | `pack128(1, 1)` | `maxPriorityFee = maxFee = 1` wei — minimal priority/base, removes fee-market noise from the measurement |
| `paymasterAndData` | `"0x"` | No paymaster — account self-pays via deposit |
| `signature` | `signUserOp(scheme, sk, …)` output | The only per-scheme variable — 65 B for ECDSA, 1064 B Falcon/Falcon-ETH, 2420 B ML-DSA/ML-DSA-ETH |

What gets signed is the standard ERC-4337 v0.7 `userOpHash`: `keccak256(abi.encode(keccak256(hashPackedUserOp(op_without_sig)), entryPoint, chainId))`. Computed by the shared `test/signers/userOpHash.ts#computeUserOpHash` helper before the per-scheme `sign()` call.

The transaction wrapping all of this is `entryPoint.handleOps([signedOp], bundlerAddress)`, sent with an explicit `gas: TX_GAS_OVERRIDE = 16_777_215` (just under HH3 EDR's hard `tx_gas_limit_cap = 2^24`). The captured `receipt.gasUsed` is what each row in the main table above tabulates.

## Why ECDSA totals ~76k gas (not ~3k)

The bench measures `receipt.gasUsed` for the entire `entryPoint.handleOps([signedOp], bundler)` transaction (see `test/bench/gas-benchmark.test.ts:241-246`), not just `ecrecover`. Approximate breakdown of the ECDSA total:

| Bucket | ~gas | What |
|---|---:|---|
| Intrinsic tx | 21 000 | Base cost every Ethereum tx pays |
| Calldata (16/4 per byte) | ~1 000 | `handleOps` envelope + 65 B signature (matches the `Calldata` column above) |
| `EntryPoint.handleOps` orchestration | ~30 000–40 000 | Array loop, `_validatePrepayment`, deposit SSTORE/SLOAD, post-op refund accounting, `UserOperationEvent` LOG |
| `ERC1967Proxy` DELEGATECALL | ~5 000–8 000 | Impl-slot SLOAD + DELEGATECALL on each call into the account |
| `SimpleAccount._validateSignature` surround | ~5 000 | EIP-191 prefix keccak, owner SLOAD compare, prefund call back to EntryPoint |
| **`ecrecover` precompile** | **~3 000** | The only crypto cost |
| `callData` execution | ~0 | `buildUnsignedUserOp` sets `callData: "0x"` |

So `ecrecover` is ~3k of the ECDSA total — the other ~73k is the 4337 framework cost (base tx + EntryPoint orchestration + proxy DELEGATECALL + event log + deposit bookkeeping). This is deliberate per architecture decision DD-2: the bench measures the real production-path drop-in cost, so PQC overhead numbers reflect what an operator actually pays to swap ECDSA out of a 4337 account, not the bare verification delta.

A `_validateSignature`-only number (~8k for ECDSA = ~3k ecrecover + ~5k surround) would require either snapshotting `gasleft()` deltas inside the account, or a direct-call benchmark that bypasses `handleOps`. The current harness intentionally doesn't, because the same delta would understate PQC schemes that benefit/suffer differently from EIP-2929 warming and EIP-3529 refund-cap interactions during the EntryPoint loop.
