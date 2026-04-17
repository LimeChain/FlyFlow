---
status: complete
created: 2026-04-11
feature: pqc-4337
brief: docs/research.md
---

# Specification: PQC-4337

## Overview

Proof-of-concept benchmarking three signature validation schemes (ECDSA, FN-DSA, ML-DSA) within ERC-4337 smart accounts to quantify gas cost implications of post-quantum cryptography migration. Uses Hardhat (JS/TS) to align off-chain signing with future browser signing needs.

## Use Cases

UC-1: Benchmark PQC signature validation gas costs — Engineer runs the benchmark suite to obtain comparative gas data for migration planning
Primary actor: Engineer
Precondition: Local devnet is running; all three smart account contracts are compiled; off-chain signing tooling is available for each scheme
Main flow: 1. Engineer invokes the gas benchmark suite 2. System compiles all three smart account contracts 3. System deploys each smart account to the local devnet 4. System generates a valid UserOp for each account and signs it off-chain with the corresponding scheme 5. System submits each signed UserOp through the ERC-4337 validation entry point 6. System records gas consumed by signature validation for each scheme 7. System produces a markdown report with absolute gas costs and relative overhead versus the ECDSA baseline
Alternative flows: - Compilation failure: System reports which contract failed to compile and halts before deployment - Signature validation failure: System reports which scheme produced an invalid signature and marks that scheme as failed in the report
Postcondition: A markdown report exists containing gas cost data (absolute and relative) for ECDSA, FN-DSA, and ML-DSA UserOp validation

UC-2: Verify signature rejection for invalid input — Engineer confirms that each smart account correctly rejects an invalid signature
Primary actor: Engineer
Precondition: All three smart account contracts are deployed on the local devnet
Main flow: 1. Engineer runs the validation test suite 2. System submits a UserOp with a deliberately invalid signature to each smart account 3. System observes that each account returns a validation failure result 4. System reports pass/fail for each scheme's rejection behavior
Alternative flows: - An account accepts an invalid signature: System reports the scheme as failing the rejection test, indicating a verification logic defect
Postcondition: Test results confirm all three accounts reject invalid signatures

UC-3: Verify valid signature acceptance — Engineer confirms each smart account accepts a correctly signed UserOp
Primary actor: Engineer
Precondition: All three smart account contracts are deployed on the local devnet; valid key pairs exist for each scheme
Main flow: 1. Engineer runs the validation test suite 2. System generates a UserOp and signs it with a valid key for each scheme 3. System submits each signed UserOp to the corresponding smart account's validation function 4. System observes that each account returns a validation success result
Alternative flows: - A valid signature is rejected: System reports the scheme as failing the acceptance test, indicating a verification logic defect or key mismatch
Postcondition: Test results confirm all three accounts accept valid signatures

## Functional Requirements (Capability Contract)

FR-1: [Engineer] can [validate a UserOp signature using the ECDSA baseline scheme] [within an ERC-4337 smart account on a local devnet]
FR-2: [Engineer] can [validate a UserOp signature using the FN-DSA post-quantum scheme] [within an ERC-4337 smart account on a local devnet]
FR-3: [Engineer] can [validate a UserOp signature using the ML-DSA post-quantum scheme] [within an ERC-4337 smart account on a local devnet]
FR-4: [Engineer] can [sign UserOps off-chain with each supported signature scheme] [to produce valid signatures consumed by on-chain validation]
FR-5: [Engineer] can [run a gas benchmark suite across all three signature schemes] [and receive per-scheme gas cost data for UserOp validation]
FR-6: [Engineer] can [view a markdown report comparing gas costs] [with absolute and relative figures for ECDSA, FN-DSA, and ML-DSA validation]
FR-7: [Engineer] can [reject a UserOp with an invalid or malformed signature] [for each of the three signature schemes, returning a validation failure]

## Non-Functional Requirements (measurable targets)

NFR-1: Compatibility — All three smart accounts must conform to the ERC-4337 account interface such that they pass the same UserOp validation entry-point calls used by the baseline account
NFR-2: Maintainability — Each signature-scheme account must differ from the baseline account in no more than the signature validation logic (glue code limited to validation swap only)
NFR-3: Reliability — The gas benchmark suite must produce deterministic gas figures (< 1% variance) across repeated runs on the same local devnet state
NFR-4: Performance — The full benchmark suite (all three schemes) must complete in <= 5 minutes on a standard developer workstation
NFR-5: Maintainability — Post-quantum signature libraries must be consumed as read-only dependencies with zero modifications to their source code

## Quality Perspectives

### End User (INDIRECT, 2 concerns)
| # | Concern | Severity | Suggested AC |
|---|---------|----------|--------------|
| 1 | FR-6 doesn't specify report format on partial failure | MED | AC-U-1 |
| 2 | No FR covers discoverability of benchmark/test commands | LOW | AC-U-2 |

### Architect (2 concerns)
| # | Concern | Severity | Category | Suggested AC |
|---|---------|----------|----------|--------------|
| 1 | PQC signature sizes large; no calldata vs computation decomposition | MED | reliability | AC-A-1 |
| 2 | Off-chain PQC signing integration boundary (resolved by Hardhat JS/TS) | MED | boundary | AC-A-2 |

### Maintainer (2 concerns)
| # | Concern | Severity | Category | Suggested AC |
|---|---------|----------|----------|--------------|
| 1 | FR-7 returns generic validation failure; no error differentiation | MED | debuggability | AC-D-1 |
| 2 | NFR-2 minimal-glue has no mechanical enforcement | MED | extensibility | AC-D-2 |

## Acceptance Criteria

### AC-U: End User Criteria
AC-U-1: When a signature scheme fails validation during benchmarking, the markdown report must include the failure reason alongside that scheme's entry and clearly present valid gas data for remaining schemes.
AC-U-2: The project README must include exact commands to run the gas benchmark suite and validation test suite, including preconditions (e.g., npm install, submodule init).

### AC-FR: Functional Completeness
AC-FR-1: Each of the three smart accounts (ECDSA, FN-DSA, ML-DSA) must accept a correctly signed UserOp by returning validation success from the ERC-4337 validateUserOp entry point on a local devnet. (covers FR-1, FR-2, FR-3)
AC-FR-2: Running a single benchmark command must deploy all three accounts, sign UserOps off-chain per scheme, submit them through ERC-4337 validation, and record per-scheme gas consumed. (covers FR-5)
AC-FR-3: The benchmark must produce a markdown report containing: (a) absolute gas cost per scheme, (b) relative overhead of FN-DSA and ML-DSA as percentage over ECDSA baseline. (covers FR-6)
AC-FR-4: Each of the three accounts must reject a UserOp with an invalid or malformed signature. At minimum, one test per scheme uses a corrupted signature and one uses a signature from a wrong key. (covers FR-7)

### AC-A: Architecture Criteria
AC-A-1: The gas benchmark report must separately report calldata cost (data bytes) and computation cost (execution gas) for each scheme, so engineers can distinguish size overhead from verification overhead.
AC-A-2: Each PQC scheme must have a JS/TS off-chain signing implementation in the test suite, and a round-trip integration test per scheme: sign off-chain, submit to on-chain validation, assert success. (covers FR-4)

### AC-D: Developer/Maintainer Criteria
AC-D-1: Each scheme's validation must emit distinguishable error indicators for at least two failure classes: (a) malformed signature format and (b) cryptographic verification failure. Tests must assert each class independently.
AC-D-2: A structural test or automated check must verify each PQC account only overrides the signature validation entry point relative to baseline SimpleAccount. Additional overrides must cause the check to fail.

### AC-NFR: Non-Functional Criteria
AC-NFR-1: Same test harness entry-point call structure works identically across all three accounts with no per-scheme variations. (covers NFR-1)
AC-NFR-2: Each PQC account differs from ECDSA baseline only in signature validation logic; AC-D-2 provides enforcement. (covers NFR-2)
AC-NFR-3: Running the benchmark suite 3 times on same devnet state produces gas figures with < 1% variance (max - min < 1% of mean). (covers NFR-3)
AC-NFR-4: Full benchmark suite completes in <= 5 minutes wall-clock. (covers NFR-4)
AC-NFR-5: PQC libraries consumed as git submodules with zero source modifications; git diff within each submodule produces no output. (covers NFR-5)

## Traceability Matrix

| Requirement | Covered By |
|---|---|
| FR-1 | AC-FR-1 |
| FR-2 | AC-FR-1 |
| FR-3 | AC-FR-1 |
| FR-4 | AC-A-2 |
| FR-5 | AC-FR-2 |
| FR-6 | AC-FR-3, AC-U-1 |
| FR-7 | AC-FR-4, AC-D-1 |
| NFR-1 | AC-NFR-1 |
| NFR-2 | AC-NFR-2, AC-D-2 |
| NFR-3 | AC-NFR-3 |
| NFR-4 | AC-NFR-4 |
| NFR-5 | AC-NFR-5 |

## Content Quality

| Check | Status | Details |
|-------|--------|---------|
| CQ-1 Density | PASS | No filler phrases |
| CQ-2 Leakage | PASS | Domain terms only (ECDSA, ERC-4337, UserOp) |
| CQ-3 Measurability | PASS | All NFRs have numeric/boolean targets |
| CQ-4 Traceability | PASS | 7/7 FRs, 5/5 NFRs covered |

## Constraints & Assumptions

- C-1: All testing and benchmarking must run on a local Hardhat Network devnet only — DD-1 [LOCKED]
- C-2: Smart accounts must inherit eth-infinitism SimpleAccount — DD-2 [LOCKED]
- C-3: FN-DSA and ML-DSA implementations sourced from external repos as read-only git submodules — DD-3 [LOCKED]
- C-4: Exactly three accounts: ECDSA (baseline), FN-DSA, ML-DSA — DD-4 [LOCKED]
- C-5: Gas benchmarking output as markdown report via hardhat-gas-reporter — DD-6 [LOCKED]
- C-6: Minimal glue code — inherit and swap, not build from scratch — Constraints

- A-1: External PQC libraries expose Solidity-callable verification functions — Risk: custom wrappers needed
- A-2: PQC signature sizes fit within UserOp field and gas limits — Risk: infeasibility is itself a finding
- A-3: ECDSA baseline uses existing SimpleAccount ecrecover as-is — Risk: additional setup
- A-4: Specific PQC repos provided before implementation (DD-5 DEFERRED) — Risk: blocked

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| PQC sig sizes exceed EVM/gas limits (A-2) | Medium | High | Infeasibility is a valid finding; report as negative result |
| PQC libraries lack Solidity-callable verify (A-1) | Low | High | Evaluate library interfaces before implementation |
| PQC repos not provided in time (A-4) | Low | Medium | Block implementation until DD-5 resolved |

## Out of Scope

- Production deployment — PoC for internal benchmarking only
- Key management infrastructure — Not needed for local devnet testing
- Migration tooling — This PoC provides data, not the migration itself
- Bundler integration beyond Hardhat test framework — Unnecessary for gas measurement
- Paymaster or multi-sig flows — Orthogonal to signature scheme comparison
- Custom PQC implementations — Using existing libraries per constraints
