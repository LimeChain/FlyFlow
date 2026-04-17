---
status: complete
created: 2026-04-16
revised: 2026-04-17
feature: mldsa-eth
brief: docs/research.md
---

# Specification: ML-DSA-ETH — Keccak-Based ML-DSA for ERC-4337

## Overview

Extend the existing pqc-4337 benchmark framework with a 4th signature scheme — ML-DSA-ETH (ZKNox's Keccak-backed ML-DSA variant) — by porting a JavaScript signer, wiring a new ERC-4337 account contract against ZKNox's `ZKNOX_ethdilithium.sol` verifier, and adding matching test + benchmark coverage. No JS signer exists for MLDSAETH in the open-source ecosystem today (confirmed independently); this feature fills that gap.

## Use Cases

### UC-1: Sign and submit a userOp with ML-DSA-ETH
- **Primary actor:** Wallet engineer
- **Precondition:** Account deployed with a registered ML-DSA-ETH public key; engineer holds the corresponding secret key.
- **Main flow:**
  1. Engineer constructs a userOp targeting the deployed account.
  2. Engineer invokes the ML-DSA-ETH signer with the secret key and userOp hash.
  3. Signer returns a signature blob in the format expected by the verifier.
  4. Engineer attaches the signature and submits the userOp to the entry point.
  5. Account delegates verification to the verifier, which returns success.
  6. Entry point records validation as passed.
- **Alternative flows:**
  - Malformed signer input (e.g. wrong-length secret key): signer raises a structured error before producing any output.
  - Verifier rejects the signature (byte-layout drift): account returns validation failure; entry point records failure.
- **Postcondition:** Entry point validation result matches signer/verifier outcome (success or failure).

### UC-2: Regenerate known-answer test vectors
- **Primary actor:** Test author
- **Precondition:** External `ETHDILITHIUM/` submodule checked out at pinned commit; Python available.
- **Main flow:**
  1. Test author runs the fixture-generation command.
  2. Oracle generates ≥10 (public key, message, signature) tuples via the Python reference.
  3. Tuples serialized to JSON fixture file.
  4. Test author commits updated fixtures.
- **Alternative flows:**
  - Submodule missing or at wrong commit: halts with an error identifying the expected commit.
  - Python dependency unavailable: halts with dev-environment provisioning guidance.
- **Postcondition:** JSON fixture file exists with ≥10 vectors.

### UC-3: Verify signer against known-answer fixtures
- **Primary actor:** Test author
- **Precondition:** Fixtures exist at expected location.
- **Main flow:**
  1. Test author runs the signer-vs-fixture test suite.
  2. Suite invokes the JS signer per fixture tuple.
  3. Suite compares signer output to fixture signature byte-for-byte.
  4. Suite reports pass/fail per fixture and aggregate.
- **Alternative flows:**
  - Byte mismatch on any fixture: suite fails and reports the first divergent byte offset.
  - Fixture file missing: suite fails with an instruction to regenerate fixtures (UC-2).
- **Postcondition:** Observable pass/fail record per fixture.

### UC-4: Run the 4-way benchmark
- **Primary actor:** PQC researcher
- **Precondition:** Project checked out; local dev deps installed.
- **Main flow:**
  1. Researcher invokes the benchmark command.
  2. Harness runs a userOp validation workload per scheme (4 schemes).
  3. Harness records gas cost per scheme.
  4. Harness writes/updates the benchmark report.
  5. Researcher reads the report, compares ML-DSA-ETH to the 3 baselines.
- **Alternative flows:**
  - Harness fails for one scheme: reports the failing scheme, still emits results for the others with failure marker.
- **Postcondition:** Benchmark report on disk with 4-scheme gas measurements under identical methodology.

### UC-5: Reject an invalid signature at the account boundary
- **Primary actor:** Wallet engineer (as the party whose userOp is being validated)
- **Precondition:** Account deployed with registered public key.
- **Main flow:**
  1. userOp arrives at the account with a signature.
  2. Account passes signature + pk to the verifier.
  3. Verifier determines the signature is invalid (wrong key, tampered message, malformed).
  4. Account returns validation-failed to the entry point.
- **Alternative flows:**
  - Structurally malformed signature (wrong length/layout): account returns validation failure without corrupting unrelated state.
- **Postcondition:** Entry point observes validation-failed; no state change attributable to the rejected userOp.

## Functional Requirements (Capability Contract)

- **FR-1**: [Wallet engineer] can [obtain a signature over a userOp from the ML-DSA-ETH signer] [using a JavaScript/TypeScript module importable into Node.js toolchains]
- **FR-2**: [Wallet engineer] can [produce signatures that are byte-identical to those produced by the external Python reference oracle] [for the same (secret key, message) input pair]
- **FR-3**: [Account] can [accept a valid ML-DSA-ETH signature over a userOp] [and report successful validation to the ERC-4337 entry point]
- **FR-4**: [Account] can [reject an ML-DSA-ETH signature that does not correspond to the registered public key] [and report validation failure to the ERC-4337 entry point]
- **FR-5**: [Account] can [reject a malformed ML-DSA-ETH signature] [without reverting the entry point's overall simulation flow beyond the validation result]
- **FR-6**: [Wallet engineer] can [register an ML-DSA-ETH public key with the account at deployment time] [in the reshaped form expected by the verifier]
- **FR-7**: [Test author] can [regenerate known-answer test vectors from the external Python reference] [producing JSON fixtures containing public key, message, and expected signature tuples]
- **FR-8**: [Test author] can [execute the known-answer fixtures against the JavaScript signer] [and observe byte-for-byte equality between fixture signatures and signer output]
- **FR-9**: [PQC researcher] can [run the benchmark command] [and receive a report that compares ML-DSA-ETH against ECDSA, Falcon, and the NIST-spec ML-DSA on the same workload]
- **FR-10**: [PQC researcher] can [read the benchmark report and identify the measured gas cost of ML-DSA-ETH userOp validation] [relative to the three existing schemes]
- **FR-11**: [PQC researcher] can [reproduce the full 4-way benchmark comparison in a single command] [without manual per-scheme setup]
- **FR-12**: [Wallet engineer] can [read project documentation that identifies ML-DSA-ETH as a supported scheme] [including attribution to the external verifier authors]
- **FR-13**: [Test author] can [exercise acceptance, rejection, and failure-class test coverage for ML-DSA-ETH] [at parity with the coverage provided for ECDSA, Falcon, and NIST-spec ML-DSA]

## Non-Functional Requirements (measurable targets)

- **NFR-1**: Correctness — 100% of userOps signed by the JS signer verify on-chain against the external verifier (zero tolerance; byte-compatibility is a locked constraint).
- **NFR-2**: Correctness — ≥10 KAT vectors generated by the Python reference verify byte-for-byte against JS signer output.
- **NFR-3**: Maintainability — the final shipped tree contains zero Python source files outside the external `ETHDILITHIUM/` submodule.
- **NFR-4**: Compatibility — the signer targets the same tooling stack as the parent project (Node-based test runner, hardhat, viem, noble post-quantum) with no new Solidity compiler version.
- **NFR-5**: Reproducibility — the Python dev-oracle is pinned to a specific submodule commit so fixture regeneration is deterministic.
- **NFR-6**: Scheme parity — ML-DSA-ETH uses ML-DSA-44 parameters exactly (k=4, l=4, η=2, γ₁=2¹⁷, γ₂=95232, τ=39, ω=80, β=78); only the XOF is substituted.
- **NFR-7**: Traceability — the benchmark report presents ML-DSA-ETH as a 4th row alongside the three existing schemes using identical methodology (same columns, same workload, same harness).
- **NFR-8**: Informational performance — measured average gas cost of ML-DSA-ETH userOp validation recorded in the report; ~4.9M gas is an external reference, not a pass/fail threshold.
- **NFR-9**: Correctness — the Keccak-PRG port (`test/signers/keccak-prg.ts`) produces byte-identical output to the external Python reference `Keccak256PRNG` across a documented set of boundary invariants (≥5 scenarios): single-block extract (counter stays at 0), multi-block extract (counter increment + big-endian uint64 packing), cross-extract persistence (`extract(n)` + `extract(m)` on one instance yields the same bytes as `extract(n+m)`), multi-inject absorb (multiple `inject` before `flip` equals one `inject` of the concatenation), and empty-seed edge (`flip` with no prior `inject`). Distinct from NFR-2: NFR-2 is signer-scoped; NFR-9 tests the PRG primitive in isolation so downstream byte-identity failures have a localized root-cause path.

## Constraints & Assumptions

- **C-1**: Byte-compatibility with the external verifier is inviolable — no deviations in pk reshape, challenge derivation, or PRG calls. (Research LOCKED, DD-1/DD-2)
- **C-2**: Python oracle is dev-time only; must not appear in shipped package tree. (Research LOCKED, DD-4)
- **C-3**: Python oracle submodule pinned to a specific commit. (Research LOCKED)
- **C-4**: No change to project's Solidity compiler version. (Research LOCKED)
- **C-5**: Tooling stack unchanged from parent (hardhat, viem, node:test, noble post-quantum). (Research LOCKED)
- **C-6**: ML-DSA-44 parameters unchanged; only XOF swaps. (Research LOCKED, DD-1)
- **C-7**: Only Keccak-256 as XOF substitute. (Research LOCKED)
- **C-8**: No modifications to archived parent project artifacts. (Research LOCKED)
- **C-9**: JS signer created by forking noble's `ml_dsa44`, not monkey-patching. (DD-3)
- **C-10**: Account contract inherits the same SimpleAccount override pattern as ECDSA/Falcon/ML-DSA accounts. (DD-5)
- **C-11**: Verifier Solidity sourced from external submodule, not vendored or re-authored. (DD-6)
- **C-12**: External authors credited in README. (Research LOCKED)

- **A-1**: External verifier's on-chain interface is stable at the pinned commit. Risk: byte-compatibility unreachable without moving pin or re-porting.
- **A-2**: noble's `ml_dsa44` exposes enough XOF-injection surface (directly or via fork) at the 3 call-sites. Risk: deeper fork or full reimpl required.
- **A-3**: Existing `preparePublicKeyForDeployment` is XOF-parameterizable without structural change. Risk: duplication or refactor required.
- **A-4**: Parent benchmark harness has a clean 4th-scheme extension point. Risk: harness refactor, regression risk for existing 3 schemes.
- **A-5**: Python reference at pinned commit is self-sufficient (no undocumented env deps). Risk: dev setup more involved than one command.
- **A-6**: ~4.9M gas figure is indicative under a methodology comparable to ours. Risk: measurement gap needs explanatory note.
- **A-7**: Informational-only treatment of gas is acceptable (no hard threshold). Risk: hard perf requirement later forces optimization work.
- **A-8**: ≥10 fixtures establish adequate byte-compatibility confidence. Risk: drift in rare paths undetected.

## Out of Scope

- Python code in shipped package (dev-oracle only).
- Audit of the external verifier contract.
- ML-DSA-65 / ML-DSA-87 parameter sets.
- NIST-spec Dilithium (already exists as `MlDsaAccount`).
- Hash functions beyond Keccak-256.
- Migration of existing `MlDsaAccount` to the Keccak variant.
- Sepolia/mainnet deployment.

## Quality Perspectives

### End User (Developer-tooling domain, APPLICABLE)

| # | Concern | Severity | Suggested AC |
|---|---------|----------|--------------|
| 1 | Signer error taxonomy unspecified — FR-1/UC-1 promise "structured error" but don't enumerate codes | MED | AC-U-1 |
| 2 | Fixture-gen onboarding failure modes under-specified (submodule uninit / wrong commit / Python version / pip deps) | MED | AC-U-2 |
| 3 | Fixture/submodule version drift invisible at test time | MED | AC-U-3 |

Gaps: benchmark report format (→ AC-U-4), README/attribution discoverability (→ AC-U-5).

### Architect (modular monolith, medium complexity)

| # | Concern | Severity | Category | Suggested AC |
|---|---------|----------|----------|--------------|
| 1 | XOF injection coupling under-specified — shared `mldsa-encoding.ts` risks cross-contamination when benchmark runs NIST + ETH in one process | **HIGH** | boundary | AC-A-1 |
| 2 | Failure-mode discrimination at account→verifier boundary not required to match `MlDsaAccount` | MED | reliability | AC-A-2 |
| 3 | Benchmark per-scheme failure isolation invariant not encoded in FR-11 | MED | reliability | AC-A-3 |

Missing component: fixture path + schema stability (→ AC-A-4).

### Maintainer (Established codebase)

| # | Concern | Severity | Category | Suggested AC |
|---|---------|----------|----------|--------------|
| 1 | Existing harness hard-codes 3-scheme assumption in ≥4 sites (`SCHEMES` tuple, `scheme===...` branches, `results.length !== 3` guard) | MED | extensibility | AC-D-1 |
| 2 | `mldsa-encoding.ts` XOF refactor needs byte-identical NIST regression + shared NTT call-graph | MED | testability | AC-D-2 |
| 3 | ~~NFR-3 automated CI/grep enforcement~~ — **DROPPED per user directive** | — | — | — |

Gap-fill: byte-diff helper with first-divergent offset + ±8 context (→ AC-D-3).

Totals: 9 concerns surfaced (1 HIGH, 7 MED after drop). Each persona within Medium tier budget (0-3).

## Acceptance Criteria

### AC-U: End User Criteria

- **AC-U-1**: The JS signer module throws typed errors with stable `code` fields for distinguishable failures — at minimum `INVALID_SECRET_KEY_LENGTH`, `INVALID_MESSAGE`, and `INTERNAL_SIGNER_ERROR`. Codes are documented in the signer module README and covered by unit tests that assert on `code`, not message strings.
- **AC-U-2**: The fixture-generation command distinguishes four onboarding failure modes and emits the exact next command for each: (a) submodule uninitialised → `git submodule update --init --recursive`; (b) submodule at wrong commit → both expected and actual SHAs named; (c) Python interpreter version mismatch → required and detected versions named; (d) pip dependencies missing → the install command for the pinned requirements file named.
- **AC-U-3**: Each generated KAT JSON fixture embeds the submodule commit SHA it was generated from; the KAT test suite compares that SHA against the currently checked-out submodule SHA before running any byte-level comparison, and when they differ hard-fails with a message naming both SHAs and pointing to the regeneration command.
- **AC-U-4**: The benchmark command writes its report to a documented path in a diffable text format (Markdown or CSV). Re-running overwrites deterministically so `git diff` against a prior run shows only gas-cost deltas — no timestamp, process-id, or re-ordering noise.
- **AC-U-5**: The top-level `README.md` contains a "Supported schemes" section listing ML-DSA-ETH alongside ECDSA, Falcon, and NIST-spec ML-DSA; attributes ZKNox as the origin of the ETHDilithium design and `ZKNOX_ethdilithium.sol`; and explicitly notes that the Python oracle is a dev-time tool not shipped in the package.

### AC-FR: Functional Completeness

- **AC-FR-1**: A userOp signed by the JS signer over a registered ML-DSA-ETH public key is validated as successful by the deployed `MlDsaEthAccount` through the ERC-4337 entry point in an end-to-end hardhat test (covers FR-3, FR-6, UC-1).
- **AC-FR-2**: The JS signer module is importable by both the existing `node:test` suite and downstream TypeScript consumers (verified by an import smoke test compiled under the project's `tsconfig`) with no Node-only or CommonJS-only entrypoint regression (covers FR-1).

### AC-A: Architecture Criteria

- **AC-A-1** [HIGH]: The public-key reshape pipeline in `mldsa-encoding.ts` accepts the XOF as an explicit per-call parameter. No mutable module-level XOF state exists (verified by source-level check plus an interleaved test that reshapes NIST-spec and ETH public keys in the same process and asserts each output matches its own golden fixture). The same module-level no-shared-state invariant holds for `test/signers/keccak-prg.ts`: PRG state is scoped to instance lifetime (`inject`/`flip`/`extract` bound to an object returned by `createKeccakPrg`); no module-level buffer or counter exists, verified by the same source-level grep.
- **AC-A-2**: `MlDsaEthAccount._validateSignature` returns `SIG_VALIDATION_FAILED` for cryptographic rejection (wrong key, bit-flipped signature over a valid-length blob) and reverts with `SignatureMalformed()` for format errors (truncated, over-length, or structurally unparseable blobs). Each path is exercised by ≥1 test, matching the discrimination convention already established by `MlDsaAccount` and `FalconAccount` (covers FR-4, FR-5, FR-13, UC-5).
- **AC-A-3**: Adding ML-DSA-ETH preserves the existing invariant that one scheme's measurement failure does not prevent the others from producing data. The gas report renders a row for ML-DSA-ETH even when its measurement fails, marking the row failed with a human-readable reason; a test injects a deliberate ML-DSA-ETH failure and asserts the other three rows are still emitted (covers FR-11).
- **AC-A-4**: KAT fixtures live under a single fixed repository path documented in the architecture document; the fixture JSON schema (keys, encodings, SHA embed per AC-U-3) is specified there and remains stable across regenerations — schema change requires an amendment in `docs/amendments.md`.

### AC-D: Developer/Maintainer Criteria

- **AC-D-1**: Adding a new entry to the `Scheme` union produces TypeScript compilation errors at every site that needs edits — either via exhaustive `never`-check or a scheme→adapter registry. The `scripts/generate-report.ts` length guard is derived from `SCHEMES.length`, not the literal `3`. Verified by a compile-fail snapshot test or a grep that no `=== 3` / `!== 3` literal scheme-count remains in the harness.
- **AC-D-2**: After the XOF-injection refactor, `preparePublicKeyForDeployment(rawPk)` for the unchanged NIST-spec keypair produces byte-identical output to a pre-refactor golden fixture (regression guard), AND the ML-DSA-ETH variant matches the Python-oracle KAT. Both paths share a single NTT / Power2Round / compact-encoding call graph (verified by a same-file review check).
- **AC-D-3**: When an FR-8 byte-level comparison fails, the test report identifies the first divergent byte offset plus the surrounding ±8 bytes on both the actual and expected sides. A shared `assertBytesEqual(actual, expected, label)` helper is used across all KAT-style tests.

### AC-NFR: Non-Functional Criteria

- **AC-NFR-1**: 100% of userOps signed by the JS signer verify on-chain against the external verifier in the hardhat test suite — a parameterised test iterates all KAT fixtures plus ≥5 freshly-generated signer outputs and asserts verifier success for every one (covers NFR-1).
- **AC-NFR-2**: ≥10 KAT vectors generated by the Python reference verify byte-for-byte against JS signer output in the signer-vs-fixture suite; the suite fails if fewer than 10 fixtures are present (covers NFR-2, FR-2, FR-7, FR-8, UC-2, UC-3).
- **AC-NFR-3**: The signer and account integrate into the existing test and build toolchain without introducing a new Node-test runner, a new hardhat version, a new viem version, a new noble-post-quantum major, or a new Solidity compiler version. Verified by a lockfile / `package.json` diff review (covers NFR-4, C-4, C-5).
- **AC-NFR-4**: The Python dev-oracle submodule is pinned to a specific commit recorded in `.gitmodules`; the fixture-generation command reads that pin and refuses to run when the submodule's `HEAD` differs (covers NFR-5, C-3, AC-U-2, AC-U-3).
- **AC-NFR-5**: The JS signer uses ML-DSA-44 parameters exactly (k=4, l=4, η=2, γ₁=2¹⁷, γ₂=95232, τ=39, ω=80, β=78). A parameter-constants test asserts each value against a named constant in the signer module and flags any divergence (covers NFR-6, C-6).
- **AC-NFR-6**: The benchmark report renders ML-DSA-ETH as a 4th row alongside ECDSA, Falcon, and NIST-spec ML-DSA using identical column headers, workload, and harness; a report-structure test asserts all four rows are present under the same schema (covers NFR-7, FR-9, FR-10, UC-4).
- **AC-NFR-7**: The Keccak-PRG KAT suite contains ≥5 fixtures at `test/fixtures/kat/keccak-prg/vectors.json`, one per boundary invariant enumerated in NFR-9. Each fixture scripts an `inject`/`flip`/`extract` sequence and embeds Python-reference outputs; the suite hard-fails if fewer than 5 fixtures are present or any fixture's output diverges byte-for-byte. Fixtures carry the submodule commit SHA (per AC-U-3) so regenerating against a drifted Python reference is detected at test time (covers NFR-9, FR-7/FR-8 at the primitive level).

### Post-Launch Verification

| Original Item | Target | Reason for Demotion | Verification Method |
|---|---|---|---|
| NFR-8 | ML-DSA-ETH userOp-validation average gas recorded; ~4.9M external reference | Explicitly informational per spec; no pass/fail threshold | Read the generated benchmark report row post-merge; compare to the external ~4.9M figure as a sanity check, not a blocking gate |

### Traceability Matrix

| Requirement | Covered By |
|---|---|
| FR-1 | AC-FR-2, AC-U-1 |
| FR-2 | AC-NFR-2 |
| FR-3 | AC-FR-1 |
| FR-4 | AC-A-2 |
| FR-5 | AC-A-2 |
| FR-6 | AC-FR-1, AC-A-1 |
| FR-7 | AC-NFR-2, AC-U-2 |
| FR-8 | AC-NFR-2, AC-D-3 |
| FR-9 | AC-NFR-6, AC-U-4 |
| FR-10 | AC-NFR-6, AC-U-4 |
| FR-11 | AC-A-3 |
| FR-12 | AC-U-5 |
| FR-13 | AC-A-2 |
| NFR-1 | AC-NFR-1 |
| NFR-2 | AC-NFR-2 |
| NFR-3 | *(Constraint retained; no automated AC per explicit user directive — relies on code-review discipline)* |
| NFR-4 | AC-NFR-3 |
| NFR-5 | AC-NFR-4 |
| NFR-6 | AC-NFR-5 |
| NFR-7 | AC-NFR-6 |
| NFR-8 | Post-Launch Verification |
| NFR-9 | AC-NFR-7, AC-A-1 (extended clause) |

### Conflict Resolutions

- **Maintainer Concern #3 — NFR-3 CI enforcement — DROPPED per explicit user directive.** NFR-3 stays as a constraint in the spec but has no automated AC. Compliance relies on code-review discipline at PR time. No other conflicts raised.

### Gaps

None. Every FR is covered by ≥1 AC. Every NFR except NFR-3 is covered by an AC; NFR-3 is covered by a user-accepted deferral to code review. NFR-8 is moved to Post-Launch Verification per its informational framing.

## Content Quality

- **CQ-1 (Density)**: PASS — no filler phrases in FR/NFR/AC text.
- **CQ-2 (Impl Leakage)**: PASS in FRs (capability-level language only). NFR-4, NFR-6, NFR-9, AC-NFR-3, AC-NFR-5, AC-NFR-7 reference project tooling (hardhat, viem, noble, ML-DSA-44 params, `keccak-prg.ts`, `Keccak256PRNG`) because the research explicitly locked those via LOCKED constraints C-4/C-5/C-6 and DD-11 (Keccak-PRG promoted to first-class ported component) — acceptable under "pre-answered concerns" rule.
- **CQ-3 (Measurability)**: PASS — NFR-1 100% · NFR-2 ≥10 · NFR-3 0 Python files · NFR-4 binary compatibility · NFR-5 pinned commit · NFR-6 exact parameter tuple · NFR-7 4th row / identical methodology · NFR-8 → post-launch (informational) · NFR-9 ≥5 enumerated boundary scenarios.
- **CQ-4 (Traceability)**: PASS — every FR→≥1 AC, every NFR→AC or post-launch or user-accepted deferral; every AC traces to a FR/NFR/UC/persona source. NFR-9 → AC-NFR-7 (direct) + AC-A-1 extended clause (isolation).

## Open Questions

None — resolved via stated assumptions. DD-7 (fixture JSON schema/location/count), DD-8 (signature ABI layout), DD-9 (benchmark script scheme discovery) are explicitly DISCRETION/DEFERRED for the architecture phase.
