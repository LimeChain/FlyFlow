---
id: "5-2"
slug: report-generator
epic: 5
wave: 4
size: M
status: draft
created: 2026-04-15
dependencies: ["5-1"]
---

# Story: Report generator + README run instructions

## User Story
As an engineer, I want a markdown report and README that let anyone reproduce the numbers and read them without running the suite.

## Acceptance Criteria

- AC-1: Given captured gas data from 5-1, When running the report generator, Then `docs/gas-report.md` is written with: (a) absolute gas per scheme, (b) relative overhead of Falcon and ML-DSA vs ECDSA baseline (percentage), (c) calldata vs execution breakdown per scheme (AC-FR-3, AC-A-1).
- AC-2: Given any scheme marked failed in 5-1 data, When generating the report, Then that scheme's row shows the failure reason and remaining schemes show valid gas data (AC-U-1).
- AC-3: Given the project README, When reading it, Then it contains exact commands for: `git submodule update --init`, `npm install`, running the validation suite, running the benchmark, and locating the report output (AC-U-2).

## Architecture Guardrails

**A-001 [BINDING] — TypeScript-only, `node:test` + `node:assert/strict`.** The report generator is TypeScript (`.ts`) executed directly by Node 24's native TS strip loader (`process.features.typescript === "strip"`, verified on v24.13.1). Do NOT add `tsx`, `ts-node`, or a build step. Invocation form for `npm run report` is `node scripts/generate-report.ts`. The unit test lives at `scripts/generate-report.test.ts` (or `test/scripts/...` — pick whichever matches the existing convention at `test/signers/ecdsa.test.ts`) and uses `node:test` + `node:assert/strict`, identical to every other test in this project. No `chai`, no `mocha`, no `vitest`.

**A-001 corollary — `package.json "type": "module"`.** Scripts are ESM. Use `import` syntax, `.js` extensions on relative imports (Node NodeNext moduleResolution), `node:fs/promises`, `node:path`, `node:url`, `node:process`.

**DD-6 [LOCKED] — markdown report format.** Architecture DD-6 mandates a markdown report; this story realizes it. The report is consumed by humans reading the repo (GitHub-rendered). Table syntax is standard GFM tables.

**C-012 [BINDING, surface in report] — PQC variance exceeds AC-2 threshold.** Story 5-1's benchmark relaxed the variance gate to `<0.10` for Falcon/ML-DSA while keeping ECDSA at `<0.01`. The report MUST display the observed variance per scheme verbatim from `gas-data.json` so readers understand the cross-scheme-ranking use-case is unaffected by the ±5% PQC noise. Do NOT gate the report on the variance value — the benchmark already gates it; the report is a passive presenter.

**Input shape (`test/bench/gas-data.json`) — inlined from Story 5-1 §Verified Interfaces:**

```ts
type Scheme = "ecdsa" | "falcon" | "mldsa";
type BenchResult =
  | {
      scheme: Scheme;
      status: "ok";
      runs: bigint[];            // JSON: string[]
      mean: bigint;              // JSON: string
      variance: number;          // JSON: number (IEEE-754)
      totalGas: bigint;          // JSON: string
      calldataGas: bigint;       // JSON: string
      executionGas: bigint;      // JSON: string
    }
  | { scheme: Scheme; status: "failed"; reason: string };
// Persisted shape on disk: BenchResult[]  (exactly 3 records — one per scheme)
// Bigint serialization: toString() in writer, BigInt(s) in reader.
```

The report generator reads this file at a known path — `test/bench/gas-data.json` — resolved relative to the script's own location via `new URL("../test/bench/gas-data.json", import.meta.url)`. Do NOT resolve against `process.cwd()` (same C-003 pattern Story 2-1 logged; apply the same fix preemptively here).

**AC-1(b) overhead computation.** ECDSA is the baseline. For each `status === "ok"` PQC scheme, overhead percentage is `((scheme.totalGas - ecdsa.totalGas) / ecdsa.totalGas) * 100`, formatted to 1 decimal place (e.g., `5274.1%`). If ECDSA itself has `status === "failed"`, the baseline is undefined — render `n/a` in the overhead column for all schemes and include an explanation line above the table. If a PQC scheme is `failed`, its overhead cell renders `n/a` with the failure reason in a separate column.

**AC-1(c) calldata-vs-execution breakdown.** Display `calldataGas` and `executionGas` as absolute integers and as a percentage of `totalGas` (e.g., `1040 (1.4%) / 75070 (98.6%)`). Arithmetic sanity check in the generator: `assert(calldataGas + executionGas === totalGas)` — the data was written by Story 5-1 which already asserts this, but the generator re-asserts to catch tampering / schema drift.

**AC-2 failed-scheme row shape.** A `{ status: "failed", scheme, reason }` row must still appear in the table — same column order, with `totalGas`, `calldata`, `execution`, `overhead` cells all showing `—` (em dash) or `FAILED`, and the `reason` string rendered in a dedicated column OR as a footnote markdown reference below the table. Choose footnote form if the `reason` contains newlines or exceeds ~60 chars; otherwise inline in a "Notes" column. The goal is one glanceable table where no scheme is silently dropped.

**AC-3 README structure.** README already exists at `/README.md` (27 lines, pinned-submodule documentation — do NOT delete or reorganize). ADD a `## Quickstart` or `## Running the suite` section (pick either — no established precedent in this project). The section must contain, in this exact order, as a fenced bash block or labeled sub-sections:

1. Clone + submodule init: `git clone … && cd pqc-4337-laim && git submodule update --init --recursive`
2. Install deps: `npm install`
3. Compile contracts + warnings gate: `npm run compile`
4. Run the validation suite (all account tests — ECDSA + Falcon + ML-DSA validity/rejection): `npm test`
5. Run the gas benchmark (writes `test/bench/gas-data.json`): included in `npm test` OR a dedicated focused form `node --test test/bench/gas-benchmark.test.ts` (choose the focused form — it surfaces the benchmark output in isolation).
6. Generate the comparison report: `npm run report` (also describe what it writes: `docs/gas-report.md`).
7. Where to find the report: relative path `docs/gas-report.md` with a GitHub-friendly link.

> Ref: docs/architecture.md#Key Workflows — WF-1 step 7 (ReportGenerator reads gas data → markdown) — defines report-generator responsibility boundary
> Ref: docs/architecture.md#Design Rationale — DD-6 [LOCKED] markdown report via hardhat-gas-reporter, as amended by A-001 (native receipt capture; report generator is our implementation of DD-6)
> Ref: docs/amendments.md#A-001 — TypeScript-only test/script harness, node:test+node:assert (BINDING)
> Ref: docs/concerns.md#C-003 — CWD-relative path bug pattern — apply preemptive `new URL(..., import.meta.url)` fix to the generator's input read
> Ref: docs/concerns.md#C-012 — PQC variance > 0.01 target; report must surface the observed variance so readers see the deviation from NFR-3
> Ref: docs/stories/5-1-gas-benchmark.md — upstream producer of `test/bench/gas-data.json` (BenchResult[] on disk)

## Verified Interfaces

### `BenchResult` discriminated union — input contract

- **Source:** `test/bench/gas-benchmark.test.ts:106-117` (type declaration is test-local, re-declare in the generator)
- **Signature:**
  ```ts
  type BenchResult =
    | {
        scheme: Scheme;
        status: "ok";
        runs: bigint[];
        mean: bigint;
        variance: number;
        totalGas: bigint;
        calldataGas: bigint;
        executionGas: bigint;
      }
    | { scheme: Scheme; status: "failed"; reason: string };
  ```
- **File hash:** `96ddf9de7e2ebd024af05d93aede0ee27ef601a04ceceddb0beb7a19dd7945fb`
- **Plan match:** ✓ Matches plan §5-2 AC-1/AC-2 consumption shape. Re-declare locally in `scripts/generate-report.ts` (the benchmark test does not export it; duplication is the right call over coupling a script to a test file).

### `gas-data.json` on-disk shape (live snapshot, 2026-04-15 post-5-1)

- **Source:** `test/bench/gas-data.json` (produced by Story 5-1 Task 2; checked into git at Story 5-1 Gate 5)
- **Shape:** JSON array of 3 objects. `bigint` fields are serialized as decimal strings (`"76110"`); `variance` is a raw JSON number; `status` is the string literal `"ok"` or `"failed"`; `runs` is an array of decimal strings.
- **Live sample (ECDSA row for reference — values will change per benchmark run):**
  ```json
  { "scheme": "ecdsa", "status": "ok",
    "runs": ["76110","76098","76098"],
    "mean": "76102", "variance": 0.00015768310951091955,
    "totalGas": "76110", "calldataGas": "1040", "executionGas": "75070" }
  ```
- **Reader must do:** `const raw = JSON.parse(text); for each entry: convert runs/mean/totalGas/calldataGas/executionGas via BigInt(...)`.

### `package.json` scripts section — CURRENT STATE

- **Source:** `package.json:5-9`
- **Signature (existing):**
  ```json
  "scripts": {
    "compile": "hardhat compile 2>&1 | tee compile.log && node scripts/check-compile-warnings.cjs compile.log",
    "test": "hardhat test",
    "clean": "hardhat clean && rm -rf artifacts cache compile.log"
  }
  ```
- **Task 3 adds:** a new `"report": "node scripts/generate-report.ts"` entry. Node 24's native TS strip (`process.features.typescript === "strip"`, verified `v24.13.1`) runs `.ts` files directly — no transpiler required. Do NOT add `tsx` or `ts-node` as a dep.

### `README.md` — CURRENT STATE

- **Source:** `/README.md` (27 lines)
- **Structure:** Title + single paragraph project summary + `## Pinned Dependencies` table + "To update a submodule" fenced block.
- **Task 2 adds:** a new section (after the summary paragraph, before `## Pinned Dependencies`, OR at the end — pick end to avoid interleaving with the existing submodule-pinning narrative which is reference material). Do NOT modify the existing content (NFR-5 is about submodule source, but the repo convention is also "do not churn docs unnecessarily" — existing pinned-dep table has value).

### `node:fs/promises.readFile` + `writeFile`

- **Source:** Node 24 standard library
- **Signatures:**
  - `readFile(path: string | URL, options: { encoding: "utf8" }): Promise<string>`
  - `writeFile(path: string | URL, data: string, options?: { encoding?: "utf8" }): Promise<void>`
- **Plan match:** ✓ Used by the generator for both the input JSON read and the output markdown write. URL-form path (`new URL(..., import.meta.url)`) is the correct CWD-independent form.

## Tasks

- [x] **Task 1: Report generator script**
  - Maps to: AC-1, AC-2
  - Files: `scripts/generate-report.ts` (new), `scripts/generate-report.test.ts` (new — OR `test/scripts/generate-report.test.ts` if the reviewer prefers co-locating with `test/`; default to `scripts/generate-report.test.ts` to keep script + its test together)
  - Script structure:
    1. Resolve input path: `const inputPath = new URL("../test/bench/gas-data.json", import.meta.url);`
    2. Resolve output path: `const outputPath = new URL("../docs/gas-report.md", import.meta.url);`
    3. Read + parse JSON, hydrate bigints (`runs`, `mean`, `totalGas`, `calldataGas`, `executionGas` — convert from string to bigint; leave `variance` as number, `status`/`reason`/`scheme` as string).
    4. Validate: exactly 3 records, one per `Scheme`; for each `"ok"` record assert `totalGas === calldataGas + executionGas` (re-check Story 5-1's invariant).
    5. Find ECDSA row → if `status === "ok"`, it's the baseline for overhead calc; else baseline is undefined.
    6. Build markdown: a header, a timestamp (ISO 8601 from `new Date().toISOString()`), a source reference (`Generated from test/bench/gas-data.json`), the main table, and a calldata/execution breakdown table (or fold both into one table with more columns — single table preferred for glanceability).
    7. Write `docs/gas-report.md` via `writeFile(outputPath, md, { encoding: "utf8" })`.
  - Formatting contract (single table form):
    - Columns: `Scheme | Status | Total gas | Calldata (gas, %) | Execution (gas, %) | Overhead vs ECDSA | Variance | Notes`
    - `Overhead` cell: `—` for ECDSA (self); `+{pct.toFixed(1)}%` for PQC when baseline is available; `n/a` when baseline is unavailable; `n/a` for a failed scheme.
    - `Variance` cell: `{variance.toExponential(2)}` (e.g. `1.58e-4`) — compact scientific form reads well across 4+ orders of magnitude.
    - `Notes` cell: empty string for `status === "ok"`; for `failed`, render `FAILED: {reason}` (truncate reason to ~60 chars with ellipsis if longer; full reason goes to a footnote below the table).
  - Unit test `scripts/generate-report.test.ts`:
    - Framework: `node:test` + `node:assert/strict`.
    - Fixture 1 (all-ok): 3 records, status "ok" → generated markdown includes one row per scheme, no `FAILED` token, correct overhead arithmetic for a known fixture (e.g., ecdsa total 100, falcon total 200 → `+100.0%`).
    - Fixture 2 (one failed): 2 ok + 1 failed → generated markdown has all 3 rows; failed row contains the literal `FAILED` token and the reason string; other rows are unaffected.
    - Fixture 3 (ECDSA failed): 1 failed (ecdsa) + 2 ok → overhead column shows `n/a` for all rows; a note line above the table explains "Baseline ECDSA failed — overhead not computable."
    - Fixture 4 (arithmetic-drift guard): a record where `totalGas !== calldataGas + executionGas` → the generator throws a descriptive error before writing anything to disk.
    - Tests build in-memory fixtures (pass a `BenchResult[]` directly to a pure `renderReport(results): string` function); do NOT do real disk I/O in the unit test. Factor the script so the pure rendering function is importable.
  - Deviation flag: `renderReport` is a pure function the script's `main()` wraps. That's Rule 1 (file organization, established convention — `test/signers/ecdsa.ts` exports both the pure and the I/O-bearing functions).

- [x] **Task 2: README run instructions**
  - Maps to: AC-3
  - Files: `README.md` (modify — append a new section; do NOT rewrite existing content)
  - Add a new second-level heading (`## Running the suite` or `## Quickstart` — pick `## Running the suite` since it's imperative and matches the verb-phrase style of "To update a submodule" already in-file).
  - Section must contain the 7 steps listed in Architecture Guardrails §AC-3 README structure above. Use a single fenced `bash` block OR a numbered list with per-step mini-blocks; numbered list with per-step fenced blocks is more readable in the GitHub renderer.
  - Each command MUST be copy-pasteable (no placeholders in angle brackets for the main path — the git-clone line is the only one that might contain an example URL; use `git clone https://github.com/<owner>/pqc-4337-laim` once with a note "(replace `<owner>` with the actual owner)" to stay honest without hardcoding a URL the project hasn't published).
  - After the 7 steps, include a short "What you'll see" paragraph pointing at `docs/gas-report.md` with the key output (3-scheme table, overhead column).
  - Do NOT duplicate the Pinned Dependencies table's content; cross-reference it via a one-line link.

- [x] **Task 3: Wire `npm run report` + gate**
  - Maps to: AC-1 (invocation), AC-3 (the README references this command)
  - Files: `package.json` (modify — add `"report": "node scripts/generate-report.ts"` inside `scripts`)
  - Verification:
    - `npm run compile` — still green (the warnings gate is unaffected; this story adds no Solidity).
    - `npm test` — all pre-existing tests still pass (baseline from Story 5-1 Gate 5: 28 + benchmark); new `scripts/generate-report.test.ts` tests pass.
    - `npm run report` — runs cleanly, produces `docs/gas-report.md` with 3 rows, exits 0. Verify the output file's content matches the current `test/bench/gas-data.json` live sample (manual eyeball; no assertion needed in-gate — the unit test covers rendering correctness with fixtures).
    - Open `README.md` in a markdown previewer: the 7 commands render as a legible numbered list.
  - Gate output: commit the generated `docs/gas-report.md` so readers see current numbers without running the suite locally (repo-as-artifact convention — the report IS the deliverable for FR-6).

## must_haves

truths:
  - "`scripts/generate-report.ts` exists, is pure TypeScript, runs under Node 24 via native strip (`node scripts/generate-report.ts` with zero transpiler deps)"
  - "`scripts/generate-report.ts` reads `test/bench/gas-data.json` via `new URL('../test/bench/gas-data.json', import.meta.url)` — NOT a CWD-relative path"
  - "`npm run report` in `package.json` invokes `node scripts/generate-report.ts` and produces `docs/gas-report.md`"
  - "`docs/gas-report.md` contains one markdown table row per scheme (ecdsa, falcon, mldsa) — exactly 3 data rows — matching the 3 BenchResult records on disk"
  - "For each `status === 'ok'` scheme, the report shows: absolute totalGas, calldataGas and executionGas (absolute + % of total), and — for Falcon and ML-DSA — overhead % vs ECDSA computed as `((scheme.totalGas - ecdsa.totalGas) / ecdsa.totalGas) * 100` (AC-1)"
  - "For any `status === 'failed'` scheme, the report still emits a row containing the literal token `FAILED` and the failure `reason` string; other schemes' rows are unaffected (AC-2)"
  - "If ECDSA itself is `failed`, the report shows `n/a` in the overhead column for every row and includes an explanatory note line above the table"
  - "The report's variance cell surfaces the observed variance per scheme (C-012 transparency) — PQC rows may show variance > 0.01 and the report does NOT fail on this (the benchmark already gates it per its own relaxed threshold)"
  - "The generator asserts `totalGas === calldataGas + executionGas` for every `ok` record and throws a descriptive error (exit code ≠ 0) before writing to disk if the invariant is violated"
  - "`README.md` contains a new section with the 7 required commands in order: submodule init, npm install, npm run compile, npm test, focused benchmark run, npm run report, path to docs/gas-report.md (AC-3)"
  - "`scripts/generate-report.test.ts` exists, uses `node:test` + `node:assert/strict`, and exercises a pure `renderReport(results: BenchResult[]): string` function with in-memory fixtures (no disk I/O)"
  - "Pre-existing README content (title, project summary, Pinned Dependencies table, submodule-update block) is UNCHANGED by this story"
  - "No new npm dependencies added — `package.json` `devDependencies` unchanged; in particular no `tsx`, `ts-node`, `chai`, `mocha`, or `hardhat-gas-reporter`"

artifacts:
  - path: "scripts/generate-report.ts"
    contains: ["renderReport", "BenchResult", "BigInt", "import.meta.url", "../test/bench/gas-data.json", "../docs/gas-report.md"]
  - path: "scripts/generate-report.test.ts"
    contains: ["node:test", "node:assert/strict", "renderReport", "FAILED"]
  - path: "docs/gas-report.md"
    contains: ["ecdsa", "falcon", "mldsa", "Overhead", "Calldata"]
  - path: "package.json"
    contains: ["\"report\":", "node scripts/generate-report.ts"]
  - path: "README.md"
    contains: ["git submodule update --init", "npm install", "npm test", "npm run report", "docs/gas-report.md"]

key_links:
  - pattern: "renderReport"
    in: ["scripts/generate-report.ts", "scripts/generate-report.test.ts"]
  - pattern: "import.meta.url"
    in: ["scripts/generate-report.ts"]
  - pattern: "../test/bench/gas-data.json"
    in: ["scripts/generate-report.ts"]
  - pattern: "npm run report"
    in: ["README.md"]
  - pattern: "\"report\":"
    in: ["package.json"]
  - pattern: "git submodule update --init"
    in: ["README.md"]

## Dev Notes (advisory)

**No new external dependencies.** Zero packages added. Node 24's built-in TS strip runs `.ts` files natively (confirmed `v24.13.1`, `process.features.typescript === "strip"`). Everything needed is already in the lockfile from Story 1-1. No `tsx`, no `ts-node`, no test framework beyond `node:test`.

**Testing standards (established, reused):** `node:test` + `node:assert/strict`; ESM `.js`-extension imports in TypeScript source; in-memory fixtures over disk I/O for unit tests; single test file per script module (matches `test/signers/ecdsa.ts` ↔ `test/signers/ecdsa.test.ts` pattern from Story 5-1 Task 1).

**Why the generator re-declares `BenchResult` instead of importing it from the benchmark test:** Importing a type from a `.test.ts` file would couple the production-adjacent script to the test file's lifecycle (test file might be refactored into a describe-block that doesn't export top-level types, might move under a different directory, etc.). The type is a ~8-line local re-declaration — worth the duplication for loose coupling. If a shared type file emerges (`test/bench/types.ts`), unify at that point.

**Why not hardhat-run the generator:** `hardhat run scripts/foo.ts` initializes the full Hardhat runtime environment (solc probe, EDR startup) — ~2s cold start for no benefit. The generator only reads JSON and writes markdown; it needs no blockchain context. Invoke via plain `node`.

**CWD-independence (pre-emptive C-003 fix):** C-003 flagged `test/accounts/ecdsa.test.ts` using `readFile("contracts/EcdsaAccount.sol", ...)` which resolves against `process.cwd()`. The same footgun applies here — a user running `node scripts/generate-report.ts` from inside `docs/` would fail silently. `new URL(..., import.meta.url)` resolves against the script's own location and is the canonical ESM form. Apply it uniformly to both input (`test/bench/gas-data.json`) and output (`docs/gas-report.md`) paths.

**Bigint JSON parse:** `JSON.parse` returns the numeric fields as IEEE-754 numbers when not quoted, and as strings when quoted. Story 5-1's writer quoted all `bigint` fields — so `parsed[i].totalGas` arrives as `string` and needs `BigInt(s)` coercion. `variance` is written unquoted (pure `number`) and arrives as `number` — do NOT `BigInt()` it. The script's type should reflect this intermediate step: `type RawBenchResult` (strings for bigints) vs `BenchResult` (hydrated bigints) — a 1:1 mapping function between them.

**Percentage formatting:** `((scheme.totalGas - baseline.totalGas) * 10000n / baseline.totalGas)` yields basis points as a bigint; divide by 100 during display formatting to get one decimal place. Avoid `Number(bigint)` for the arithmetic (silently lossy at large gas values once the diff exceeds 2^53, which happens around 9 quadrillion — not a realistic concern but cheap to avoid). Story 5-1's observed max is ~8.4M gas for ML-DSA, comfortably inside safe integer range, but the code style should be bigint-first regardless.

**What is NOT in this story:**
- Re-running Story 5-1's benchmark to regenerate `gas-data.json` (that's 5-1's job; this story consumes the artifact as-is).
- A CI check that regenerates the report on every PR (manual `npm run report` is sufficient for PoC scope).
- A JSON schema file for `gas-data.json` (duplication with the TS type; the generator's runtime validation covers the invariants that matter).
- Fancy rendering (HTML, Mermaid charts, graphs) — DD-6 [LOCKED] mandates markdown. Stay text-only.
- Multi-run historical comparison (across benchmark invocations). Scope is "current run → current report."
- Story 5-1 bug-fixes (C-012 root cause, if ever pinned). Report surfaces the symptom; the fix belongs in whatever future story pins EIP-3529 refund behavior.

**Version audit:** All package versions pinned by Story 1-1 are production-suitable for this story — no web-search required, no new deps to verify. Node 24 TS-strip is stable-shipped in v24.x (confirmed on `v24.13.1`).

**Config deviations:** None expected. Script does not touch `tsconfig.json`, `hardhat.config.ts`, `.eslintrc`, or any generated config. The `package.json` edit adds exactly one line (`"report": "node scripts/generate-report.ts"`) inside the existing `scripts` object — no structural change.

> Ref: test/signers/ecdsa.ts — pure-function + I/O-wrapper factoring pattern (Story 5-1 Task 1)
> Ref: test/signers/ecdsa.test.ts — node:test + node:assert/strict test shape
> Ref: scripts/check-compile-warnings.cjs — existing script precedent (CJS was chosen because it runs pre-HH3-ESM-compile; the new generator is ESM/.ts because it runs post-build)

## Detected Patterns

| Pattern | Value | Sampled from | Established? |
|---|---|---|---|
| Script location | `scripts/<verb>-<noun>.{ts,cjs}` | `scripts/check-compile-warnings.cjs` (only existing script) | ⚠ Single-sample — extend convention to `.ts` for new scripts |
| Test framework | `node:test` + `node:assert/strict` | `test/signers/ecdsa.test.ts`, `test/bench/gas-benchmark.test.ts` | ✅ Established |
| Test colocation | sibling `.test.ts` next to source | `test/signers/ecdsa.ts` ↔ `test/signers/ecdsa.test.ts` | ✅ Established |
| Relative import paths | `.js` extension even in TS (NodeNext) | all `test/**/*.ts` files | ✅ Established |
| Bigint JSON serialization | `toString()` on write, `BigInt(s)` on read | `test/bench/gas-benchmark.test.ts` writer side | ✅ Established (writer only — reader side is new with this story) |
| Path resolution | `new URL(..., import.meta.url)` for fixtures | absent from existing code; C-003 flagged cwd-relative usage as a footgun | ⚠ Emerging — this story is the first to apply it; log as Rule 1 minor |
| Error types | plain `throw new Error(message)` (scripts); `assert.rejects` patterns (tests) | `test/**/*.test.ts` — no `AppError` class in this project | ✅ Established — scripts and tests stay simple; no `AppError` needed |
| Script module style | ESM (`import` syntax, `.ts`/`.mts` files) | `package.json` `"type": "module"` + all `test/**/*.ts` | ✅ Established — `check-compile-warnings.cjs` is the single legacy exception |

## Wave Structure

This is a single-wave story (wave 4 per plan). No intra-story parallelism:

- **Task 1** produces the script + its test (self-contained, no external sequencing).
- **Task 2** modifies `README.md` (independent file — could in principle run in parallel with Task 1).
- **Task 3** depends on Task 1 (needs the script file to exist before wiring the npm script) AND Task 2 (gate includes README review).

Run Tasks 1 and 2 sequentially (simpler review), then Task 3 as the gate. Total expected effort: ~1 day including tests and review.

## Definition of Done

- [ ] All 3 ACs satisfied with corresponding assertions in `scripts/generate-report.test.ts` (AC-1 via fixture comparison, AC-2 via failed-scheme fixture, AC-3 via README grep in Task 3 gate).
- [ ] `npm run compile` — green (no Solidity changes expected).
- [ ] `npm test` — green (all pre-existing tests still pass + new generator unit tests pass).
- [ ] `npm run report` — produces `docs/gas-report.md` with 3 scheme rows matching the current `test/bench/gas-data.json` content.
- [ ] `docs/gas-report.md` committed (repo-as-artifact convention for FR-6).
- [ ] `README.md` contains the 7-command quickstart section; pre-existing content unchanged.
- [ ] `package.json` has `"report": "node scripts/generate-report.ts"` in `scripts`; `devDependencies` unchanged (no new packages).
- [ ] No references to `hardhat-gas-reporter`, `tsx`, or `ts-node` introduced anywhere (A-001 compliance check).
- [ ] C-012 transparency: report surfaces per-scheme variance values verbatim — user can see PQC variance > 0.01 without running the suite.
- [ ] CWD-independence: running `cd docs && node ../scripts/generate-report.ts` produces the identical output file (manual verification of the `import.meta.url` path resolution).
