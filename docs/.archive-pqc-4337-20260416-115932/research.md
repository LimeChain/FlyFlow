---
status: complete
created: 2026-04-11
feature: pqc-4337
---

# Brief: PQC-4337

## Problem

Recent developments have accelerated the timeline for post-quantum cryptography migration. The team needs to understand the on-chain cost implications of replacing ECDSA signature validation with post-quantum schemes in ERC-4337 account abstraction. Without this data, migration planning lacks the gas overhead numbers needed for a go/no-go decision.

## Vision

A working proof-of-concept that demonstrates FN-DSA and ML-DSA signature validation within ERC-4337 smart accounts, benchmarked against ECDSA. The team has concrete gas cost data to inform PQC migration strategy.

## Users

- **Internal engineering team**: Evaluating PQC migration readiness. Needs gas benchmark data to assess feasibility and plan timelines.

## Success Metrics

- Gas cost comparison (absolute and relative) across ECDSA, FN-DSA, and ML-DSA for ERC-4337 UserOp validation, produced as a markdown report via `hardhat-gas-reporter`.

## Scope

### In Scope

- Three ERC-4337 smart accounts inheriting eth-infinitism SimpleAccount: ECDSA (baseline), FN-DSA, ML-DSA
- Swap signature validation logic per scheme
- Off-chain signing in JS/TS, on-chain verification via Hardhat tests
- Gas benchmarking via `hardhat-gas-reporter`
- Markdown report summarizing gas comparison

### Out of Scope

- Production deployment
- Key management infrastructure
- Migration tooling
- Bundler integration beyond what Hardhat provides for testing
- Paymaster or multi-sig flows
- Custom PQC implementations (using existing libraries)

## Constraints

- Local Hardhat Network devnet only
- Existing FN-DSA and ML-DSA Solidity implementations added as read-only git submodules (repos to be provided)
- Minimal glue code — inherit and swap, not build from scratch

## Design Decisions

- DD-1: Use Hardhat for testing and gas benchmarking (JS/TS aligns with future browser signing needs) [LOCKED]
- DD-2: Inherit eth-infinitism SimpleAccount as the base ERC-4337 implementation [LOCKED]
- DD-3: FN-DSA and ML-DSA implementations sourced from external repos as read-only git submodules [LOCKED]
- DD-4: Three accounts for comparison — ECDSA (baseline), FN-DSA, ML-DSA [LOCKED]
- DD-5: Specific FN-DSA and ML-DSA repos [DEFERRED — user will provide]
- DD-6: Benchmark output as markdown report generated via `hardhat-gas-reporter` [LOCKED]
