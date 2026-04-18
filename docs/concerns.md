# Concerns

Deferred findings from code review + verification that do not block gates but are worth surfacing so future stories can address them with context.

---

## C-001 (MEDIUM, security): Test-only env-var hooks are documentation-gated, not runtime-gated

- **Story:** 1 · **Commit:** `e26c315`
- **Source:** Code-review agent finding #2
- **Affected files:**
  - `scripts/generate-kat-fixtures.ts:108-111` (`KAT_SUBMODULE_PATH`)
  - `scripts/generate-kat-fixtures.ts:248-249` (`KAT_SUBMODULE_PIN_OVERRIDE`)
  - `scripts/generate-kat-fixtures.ts:273-277` (`KAT_PYTHON_VERSION_OVERRIDE`)
  - `scripts/generate-kat-fixtures.ts:332-335` (`KAT_PYTHON_DEPS_PROBE_OVERRIDE`)
  - `test/fixtures/kat/index.ts:140-142` (`KAT_FIXTURE_DIR`)

**Issue:** Five env-var hooks labeled "test-only" are purely JSDoc-gated. No `NODE_ENV`/sentinel/regex guard. A CI operator or anyone with env-set capability can silently bypass:
- Pin-mismatch check (`KAT_SUBMODULE_PIN_OVERRIDE=<current-HEAD>` neutralizes AC-1-4 at fixture-gen time)
- Submodule-path validation (`KAT_SUBMODULE_PATH` redirects probes to attacker-controlled directory)
- Python version requirement (`KAT_PYTHON_VERSION_OVERRIDE="Python 3.99"` bypasses AC-1-6)

Additionally, `KAT_PYTHON_DEPS_PROBE_OVERRIDE` feeds directly into `python3 -c "import <value>"`. argv form prevents shell injection, but a linefeed-containing value splits into multi-line Python source — still constrained to valid Python syntax, but an attacker could execute arbitrary Python in the dev's shell via `KAT_PYTHON_DEPS_PROBE_OVERRIDE=$'os\nimport subprocess; subprocess.run([...])'`.

**Exploitability:** LOW — requires local env-set capability on the dev's machine or CI. No remote attack vector.

**Recommended resolution:**
- **Option A (sentinel gate):** Require `KAT_ALLOW_TEST_OVERRIDES=1` alongside any override env var. Only the test harness sets the sentinel. Trivial to implement; preserves test UX.
- **Option B (input validation):** Validate `KAT_PYTHON_DEPS_PROBE_OVERRIDE` against `/^[a-zA-Z0-9_.,\s]+$/`, `KAT_SUBMODULE_PIN_OVERRIDE` against `/^[0-9a-f]{40}$/`, `KAT_PYTHON_VERSION_OVERRIDE` against `/^Python \d+\.\d+(\.\d+)?$/`.

**Defer rationale:** Not blocking Gate 5 (no remote exposure; CLI is dev-time only; Python invocation is already argv-form). Story 1 is scoped to fixture-gen infrastructure, not test-hook hardening. Plan-level decision: address at the first story that hardens the fixture-gen toolchain for CI use, or when someone actually wires the CLI into CI (not currently planned in sprint-status.yaml).

---

## C-002 (MEDIUM, testability): AC-U-2 diagnostic tests use env-var overrides instead of real failure paths

- **Story:** 1 · **Commit:** `e26c315`
- **Source:** Code-review agent finding #3
- **Affected file:** `test/scripts/generate-kat-fixtures.test.ts:77-146` (all 4 tests)

**Issue:** All four AC-U-2 diagnostic tests drive failure via the test-only env-var hooks (`KAT_SUBMODULE_PATH`, `KAT_SUBMODULE_PIN_OVERRIDE`, `KAT_PYTHON_VERSION_OVERRIDE`, `KAT_PYTHON_DEPS_PROBE_OVERRIDE`) rather than exercising the real failure modes. If a future change breaks `parsePythonVersion()`'s regex (e.g., the regex at line 317 stops matching `Python 3.11.x`), every test still passes because the override short-circuits the real detection.

Combined with C-001 (security concern): the test harness is tightly coupled to the bypass mechanism it is supposed to validate. Security-tightening the bypass (per C-001) without also adding real-path tests would risk breaking the test suite alongside the hardening.

**Recommended resolution:**
- Add one "integration" test per diagnostic that verifies the real path works on the happy case:
  - Real `npx tsx scripts/generate-kat-fixtures.ts` on a clean tree exits 0 and writes both fixtures (already verified manually at Task 5 Gate 5; formalize as a test)
  - Real `parsePythonVersion("Python 3.11.2")` returns `{major: 3, minor: 11, patch: 2}` — unit test on the parsing function
  - Real `checkPythonDeps()` with the actual `PYTHON_DEPS_PROBE` list succeeds on a dev environment with deps installed
- Keep the 4 existing env-var tests for message-content coverage.

**Defer rationale:** Not blocking Gate 5 (ACs are satisfied; tests pass deterministically; no regression currently). Pairs naturally with C-001 resolution — tackle both when CI hardening lands.

---

## C-003 (LOW, maintainability): `scripts/generate-kat-fixtures.ts` at 1074 LOC bundles 9 concerns

- **Story:** 1 · **Commit:** `bbd96b7`
- **Source:** Code-review agent finding #4
- **Affected file:** `scripts/generate-kat-fixtures.ts` (entire)

**Issue:** The CLI conflates nine distinct concerns in a single file:
1. Path constants + submodule-dir resolver (lines 95-146, ~50 LOC)
2. AC-U-2 diagnostic types + `fail()` helper (lines 148-183, ~35 LOC)
3. Git plumbing — `readSubmoduleStatus`, status parsing (lines 185-215, 466-499, ~60 LOC)
4. AC-U-2 diagnostic check functions + orchestrator (lines 217-454, ~240 LOC)
5. `.rsp` file parser (lines 504-588, ~85 LOC)
6. Embedded 83-line Python program as TS template literal (lines 603-689, ~85 LOC)
7. PRG Layer-1 Zhenfei canonical specs + Layer-2 job specs (lines 691-822, ~130 LOC)
8. Deterministic JSON serialization (lines 825-873, ~50 LOC)
9. Orchestrator `main()` — Python spawn + result merge + file writes (lines 877-1074, ~200 LOC)

Story Dev Notes allocated ~120 LOC for Task 3. Actual Task 3 core = ~580 LOC; plus Task 4 diagnostics ~280 LOC; plus module-scope ~210 LOC. Roughly 8× overrun — worth calibrating future Task sizing for tooling-heavy scopes.

**Recommended resolution (if ever triggered):** split into `scripts/kat/{preflight,submodule-git,rsp-parser,python-batch,prg-layer1,prg-layer2,serialize}.ts` — 7-8 files, ~120 LOC avg each. The embedded Python template stays as a `const PYTHON_BATCH` (NFR-3 forbids adding `.py` files to the shipped tree).

**Defer rationale:**
- Not blocking Gate 5 (file compiles, zero warnings; tests pass; sections delineated by `// ---------` separator comments; functions are small and well-typed).
- YAGNI: no Story 2+ extends this file per `docs/plan.md`.
- Trigger: refactor only when a second CLI feature lands (e.g., an ad-hoc fixture-debugging command).
- Size-calibration signal: the ~8× overrun on Task 3's estimate is a retrospection candidate (captured as a retrospect rule in `.claude/rules/retrospect/`).

---

_Last updated: 2026-04-18 (Story 1 Gate 5 preparation)_
