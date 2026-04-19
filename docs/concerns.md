# Concerns

Deferred findings and tech debt. Each entry lists severity, source, deferral rationale, and an optional fix path. Reviewed every 5 stories per test-integrity baseline refresh.

---

## C-001: AC-2 plan-text quirk — "Story 2-1 / 2-2" vs actual downstream blockers 2-1 + 2-3

- **Severity:** LOW
- **Source:** Story 1-2 code review, finding #3 (2026-04-19)
- **Story:** 1-2 (`keccak-prg-verification`)
- **Files:** `docs/plan.md:70`, `docs/stories/1-2.md:37`

### Description

`docs/plan.md` AC-2 for Story 1-2 says a G1 failure should emit a reminder pointing at "Story 2-1 / 2-2". The actually-blocked downstream stories on a G1 Keccak-PRG divergence are **2-1 (keygen G3)** and **2-3 (signer G4)** — both consume `keccakXofFactory`. Story 2-2 (G2 HashToPoint) uses pinned Solidity per DD-25 Option C and does NOT transitively consume the TS PRG.

The T2 test's DD-13 reminder message correctly cites 2-1 and 2-3; the plan text was left un-amended (handled only as a commit-message note on T2 and on the revision commit).

### Why deferred

Not a contract change (the plan text is frozen; the test's reminder is correct). The divergence between plan text and test text is a documentation hygiene issue, not a correctness issue. Opening A-005 for a one-line doc sweep is permissible but low value.

### Fix path (if / when)

Either:
- **(a)** Open amendment A-005 (Rule 1 minor) with a callout at `docs/plan.md:70` and `docs/stories/1-2.md:37` that the "2-1 / 2-2" wording is superseded by "2-1 + 2-3" for all Gate-5 verification purposes.
- **(b)** Edit the test's DD-13 reminder to quote the plan verbatim ("2-1 / 2-2") and add a supplementary sentence naming 2-3.

Recommendation: (a) when the next story touches plan.md anyway. No standalone fix warranted.

---

## C-002: Module-eval-time loader calls collapse probe failures into single stack trace

- **Severity:** LOW (observational)
- **Source:** Story 1-2 code review, finding #5 (2026-04-19)
- **Story:** 1-2 (`keccak-prg-verification`)
- **Files:** `test/signers/keccak-prg.falcon.kat.test.ts:87`, inherited from the pre-existing pattern at `test/fixtures/kat/index.ts:759`

### Description

The G1 test file calls `loadFalconPrgVectors()` at module-evaluation time (inside the top-level `describe` body, not inside `before` / `beforeAll`). Under `node:test`, this runs during test-file import. If the submodule SHA probe fails (e.g., ETHFALCON HEAD temporarily off-pin during a local rebase, missing fixture file, corrupted JSON), the entire file fails with a single untyped stack trace before any per-vector case can report individually — losing diagnostic granularity that the DD-13 reminder was designed to deliver.

### Why deferred

1. Same pattern the pre-existing mldsa-eth PRG test (`keccak-prg.kat.test.ts`) uses. Changing Story 1-2's test shape without also restructuring the mldsa-eth precedent would introduce asymmetry.
2. SHA-probe failures are a rare ops condition (happens only during rebases or submodule-pin drift). The fast-fail-at-import behavior is arguably preferable to per-vector failures: one clear error beats 6 identical ones.
3. For Story 2-1 / 2-3 (100-vector corpora), the tradeoff shifts — 100 identical failure lines would be noisier than one. If blast radius becomes a concern there, this pattern should be revisited across all KAT test files together, not just G1.

### Fix path (if / when)

Move the loader call into a `before()` hook so probe failures surface through the test runner's normal error path. Apply consistently across all KAT test files (mldsa-eth PRG, ml-dsa-eth keygen/sign, Falcon G2/G3/G4/G5, etc.). Not a per-story fix — refactor at the suite-structure level when Story 2-1 or 2-3 lands.
