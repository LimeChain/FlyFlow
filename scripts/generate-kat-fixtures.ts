/**
 * Fixture-gen CLI (Story 1, Tasks 3 + 4; extended Story 1-1 Task T0 — falcon-eth branch).
 *
 * Produces the two KAT fixture files consumed by the Story 2–5 test suite:
 *   - test/fixtures/kat/mldsa-eth/vectors.json (DD-7, 100 vectors)
 *   - test/fixtures/kat/keccak-prg/vectors.json (DD-11, 4 Layer-1 + ≥3 Layer-2)
 *
 * Invocation: `npx tsx scripts/generate-kat-fixtures.ts [--scheme mldsa-eth|falcon-eth]`.
 * Default scheme is `mldsa-eth`. The `--scheme falcon-eth` branch is gated by
 * Story 1-1: currently implements only T0 (PRE_G4_DRBG_PROBE) as a pre-flight
 * gate; T1 (bulk vectors.json write) + T2 (hashtopoint-vectors.json) land in
 * subsequent commits.
 *
 * Flow (per architecture §UC-2 "Fixture regeneration"):
 *   0. Pre-flight diagnostics (AC-U-2, Task 4). Four checks run in order —
 *      each, on failure, writes a single NDJSON line to stderr shaped as
 *      `{"code": "<CODE>", "message": "..."}` and exits 1:
 *        (a) `SUBMODULE_UNINIT` — ETHDILITHIUM directory missing or empty,
 *            or `git submodule status ETHDILITHIUM` output starts with `-`.
 *            Message names `git submodule update --init --recursive`.
 *        (b) `SUBMODULE_PIN_MISMATCH` — `git submodule status` leading char
 *            is `+`, OR parent-tree gitlink SHA ≠ `git -C ETHDILITHIUM
 *            rev-parse HEAD`. Message names both 40-hex SHAs + the re-pin
 *            command `git -C ETHDILITHIUM checkout <pinned>`.
 *        (c) `PYTHON_VERSION_MISMATCH` — `python3 --version` fails OR the
 *            parsed version does not satisfy `>=3.9, <4`. Message names
 *            both required-range and detected strings.
 *        (d) `PYTHON_DEPS_MISSING` — `python3 -c "import dilithium_py.*, ..."`
 *            raises `ImportError`. Message names the missing module(s) +
 *            `pip install -r ETHDILITHIUM/pythonref/requirements.txt`.
 *      Earlier checks gate later ones — no point probing Python deps if
 *      the submodule isn't there. The structured `code` strings are the
 *      contract surface asserted by tests; `message` contents are flexible
 *      as long as the required next-command substrings are present.
 *   1. Read the pinned ETHDILITHIUM SHA (parent-tree gitlink via
 *      `git submodule status`) and current HEAD via `git -C ETHDILITHIUM
 *      rev-parse HEAD`. Mismatch is already caught in step 0(b); this step
 *      reads the authoritative SHA + commit timestamp for fixture embed.
 *   2. Parse `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp`
 *      into 100 (count, seed, mlen, msg, pk, sk, sm) records; derive
 *      `sig = sm[:-mlen]` (strip appended message, per NIST KAT convention).
 *   3. Spawn ONE `python3 -c "..."` batch (architecture UC-2 requires a
 *      single spawn). The Python program:
 *        - replays `AES256_CTR_DRBG(drbgSeed)` per record with TWO
 *          separate `random_bytes(32)` calls to recover `(ζ, rnd)` —
 *          per A-005 (state-advanced CTR-DRBG; not bytes[32:64] of a
 *          single `random_bytes(64)` expansion, which Story 1 originally
 *          documented);
 *        - calls `Dilithium2.pk_for_eth(pk, _xof=Keccak256PRNG,
 *          _xof2=Keccak256PRNG)` and ABI-encodes the returned
 *          `(A_hat, tr, t1_new)` via `eth_abi.encode(['bytes','bytes',
 *          'bytes'], ...)` for the `reshapedPublicKey` slot (per
 *          `docs/amendments.md` §A-001 — `tr` is 64 B, not 32 B);
 *        - drives `Keccak256PRNG` directly to produce Layer-2 PRG boundary
 *          vectors (cross-extract, multi-inject, empty-seed, ML-DSA-shaped
 *          seed) — emits both via stdout NDJSON.
 *   4. Merge Python output with `.rsp`-derived fields into the 8-field DD-7
 *      schema. Layer-1 PRG vectors (4 Zhenfei-canonical) are embedded as
 *      hex literals in this source verbatim from
 *      `ETHDILITHIUM/test/keccak_prng.t.sol:12-27`.
 *   5. Write both JSON files deterministically: canonical key order, 2-space
 *      indent, LF line endings, trailing newline. `generatedAt` is derived
 *      from the submodule commit timestamp (`git -C ETHDILITHIUM log -1
 *      --format=%ct HEAD`) — NOT `new Date()` — so reruns without submodule
 *      change produce byte-identical output (AC-1-2).
 *
 * Test-only env-var hooks (documented here; production CLI ignores them if
 * not set — each is a pass-through override used ONLY by the colocated
 * `generate-kat-fixtures.test.ts` to simulate individual failure modes):
 *   - `KAT_SUBMODULE_PATH` — override the ETHDILITHIUM directory path used
 *     by the submodule-uninit detection. Test points this at `/nonexistent`
 *     to drive SUBMODULE_UNINIT deterministically.
 *   - `KAT_SUBMODULE_PIN_OVERRIDE` — override the parent-tree gitlink SHA
 *     used for pin comparison. Test sets this to a bogus 40-hex to drive
 *     SUBMODULE_PIN_MISMATCH without mutating the real submodule state.
 *   - `KAT_PYTHON_VERSION_OVERRIDE` — override the detected python version
 *     string (bypasses `python3 --version`). Test sets this to e.g.
 *     `"Python 3.7.5"` to drive PYTHON_VERSION_MISMATCH.
 *   - `KAT_PYTHON_DEPS_PROBE_OVERRIDE` — comma-separated import list to
 *     substitute into the deps-probe `python3 -c`. Test sets this to
 *     `"nonexistent_module_xyz_abc"` to drive PYTHON_DEPS_MISSING.
 * These overrides are test-only; production invocations never set them and
 * receive the unconditional real-system behavior.
 *
 * NFR-3 (zero Python files shipped): the Python batch is passed as a string
 * argument to `python3 -c` — no `.py` files are added under `scripts/` or
 * `test/`. The Python source that executes is resident under `ETHDILITHIUM/`
 * (pinned submodule).
 */

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type {
  KatVector,
  KatVectorsFile,
  PrgVector,
  PrgVectorsFile,
} from "../test/fixtures/kat/index.js";

// ---------------------------------------------------------------------------
// Path + constants
// ---------------------------------------------------------------------------

const THIS_FILE = fileURLToPath(import.meta.url);
// scripts/generate-kat-fixtures.ts → repo root is two levels up.
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), "..");

/**
 * Submodule directory. Test-only override: `KAT_SUBMODULE_PATH` replaces
 * the default to drive SUBMODULE_UNINIT detection deterministically.
 * Production invocations never set this.
 */
function submoduleDir(): string {
  const override = process.env["KAT_SUBMODULE_PATH"];
  if (override !== undefined && override !== "") return override;
  return path.join(REPO_ROOT, "ETHDILITHIUM");
}

const RSP_PATH = path.join(
  REPO_ROOT,
  "ETHDILITHIUM",
  "pythonref",
  "assets",
  "PQCsignKAT_Dilithium2_ETH.rsp",
);
const FIXTURE_DIR = path.join(REPO_ROOT, "test", "fixtures", "kat");
const ML_DSA_FIXTURE = path.join(FIXTURE_DIR, "mldsa-eth", "vectors.json");
const PRG_FIXTURE = path.join(FIXTURE_DIR, "keccak-prg", "vectors.json");

/**
 * ETHFALCON KAT .rsp path — consumed by Story 1-1 T0 (PRE_G4_DRBG_PROBE) and
 * T1 (bulk transcription). Test-only override: `KAT_ETHFALCON_RSP_PATH` (only
 * honored when `ALLOW_TEST_OVERRIDES=1`). Regex-validated at ingest (NFR-9).
 */
function ethfalconRspPath(): string {
  const override = process.env["KAT_ETHFALCON_RSP_PATH"];
  if (override !== undefined && override !== "") {
    requireTestOverrideSentinel("KAT_ETHFALCON_RSP_PATH");
    validateTestOverrideFormat(
      "KAT_ETHFALCON_RSP_PATH",
      override,
      /^[A-Za-z0-9_./-]+$/,
    );
    return path.isAbsolute(override)
      ? override
      : path.resolve(REPO_ROOT, override);
  }
  return path.join(REPO_ROOT, "ETHFALCON", "test", "ethfalcon512-KAT.rsp");
}

/**
 * Required Python version range (AC-1-6). Chosen ≥3.9 because local dev runs
 * Python 3.9.6 and `pycryptodome == 3.23.0` + `eth_abi` are verified against
 * that floor in the pinned submodule's `requirements.txt`. `<4` guards against
 * unknown future incompatibility.
 */
const PYTHON_MIN_MAJOR = 3;
const PYTHON_MIN_MINOR = 9;
const PYTHON_MAX_MAJOR = 4;
const PYTHON_REQUIRED_RANGE = `>=${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}, <${PYTHON_MAX_MAJOR}`;

/**
 * Python modules probed by the dep-probe (AC-1-7). These are the exact
 * imports the main batch below uses; if any of them are missing, the batch
 * will fail with a Python `ImportError`, so we probe them up-front.
 */
const PYTHON_DEPS_PROBE: readonly string[] = [
  "dilithium_py.dilithium",
  "dilithium_py.drbg.aes256_ctr_drbg",
  "dilithium_py.keccak_prng.keccak_prng_wrapper",
  "eth_abi",
];

// ---------------------------------------------------------------------------
// AC-U-2 pre-flight diagnostics (Task 4) — four failure modes, emit NDJSON
// to stderr and set exit code 1 on failure. Tests grep on the `code` field.
// ---------------------------------------------------------------------------

/**
 * AC-U-2 diagnostic codes. The string values are the test-facing contract
 * (asserted via `stderr.includes("\"code\":\"<CODE>\"")`) — do not rename
 * without updating tests and the AC-U-2 table in `docs/stories/1-*.md`.
 */
type DiagnosticCode =
  | "SUBMODULE_UNINIT"
  | "SUBMODULE_PIN_MISMATCH"
  | "PYTHON_VERSION_MISMATCH"
  | "PYTHON_DEPS_MISSING"
  | "PRE_G4_DRBG_PROBE_FAILED"
  | "TEST_OVERRIDE_SENTINEL_MISSING"
  | "TEST_OVERRIDE_INVALID_FORMAT";

// ---------------------------------------------------------------------------
// NFR-9 test-override safety helpers. Every new test-only env-var override
// MUST (a) be rejected when `ALLOW_TEST_OVERRIDES=1` is unset, AND (b) be
// regex-validated at ingest. See `.claude/rules/retrospect/universal.md`
// §"[2026-04-18] Security-relevant test overrides need runtime gates".
//
// The pre-existing mldsa-eth overrides (KAT_SUBMODULE_PATH,
// KAT_SUBMODULE_PIN_OVERRIDE, KAT_PYTHON_VERSION_OVERRIDE,
// KAT_PYTHON_DEPS_PROBE_OVERRIDE) predate NFR-9; they are left ungated for
// backward compatibility with `generate-kat-fixtures.test.ts` (test-harness
// trusted, not operator-facing). NEW overrides added as part of Story 1-1
// (falcon-eth branch) are all sentinel + regex gated.
// ---------------------------------------------------------------------------

/**
 * Structured error used for test-override safety and PRE_G4_DRBG_PROBE
 * failures. Uses the `readonly code` discriminant pattern established by
 * `KatFixtureError` (see `test/fixtures/kat/index.ts:49`) and `test/signers/
 * errors.ts`.
 */
export class FixtureGenError extends Error {
  readonly code: DiagnosticCode;

  constructor(
    message: string,
    code: DiagnosticCode,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "FixtureGenError";
    this.code = code;
  }
}

function requireTestOverrideSentinel(varName: string): void {
  const sentinel = process.env["ALLOW_TEST_OVERRIDES"];
  if (sentinel !== "1") {
    throw new FixtureGenError(
      `Refusing to honor '${varName}': ALLOW_TEST_OVERRIDES=1 sentinel is not set. ` +
        `Test-only overrides are off by default in operator-facing invocations.`,
      "TEST_OVERRIDE_SENTINEL_MISSING",
    );
  }
}

function validateTestOverrideFormat(
  varName: string,
  value: string,
  pattern: RegExp,
): void {
  if (!pattern.test(value)) {
    throw new FixtureGenError(
      `Invalid value for '${varName}': ${value} — expected pattern ${pattern.source}`,
      "TEST_OVERRIDE_INVALID_FORMAT",
    );
  }
}

/**
 * Diagnostic failure signal. `kind = "ok"` if the check passed; `kind =
 * "fail"` with a `code` + `message` if the check failed. The failure
 * payload is emitted as NDJSON to stderr by `runPreflightDiagnostics`.
 */
type DiagResult =
  | { kind: "ok" }
  | { kind: "fail"; code: DiagnosticCode; message: string };

const OK: DiagResult = { kind: "ok" };

function fail(code: DiagnosticCode, message: string): DiagResult {
  return { kind: "fail", code, message };
}

/**
 * Snapshot of `git submodule status ETHDILITHIUM` output. `statusChar` is
 * the leading status character (`+` HEAD differs from pin, `-` not init'd,
 * `U` merge conflict, ` ` clean, `""` if output was empty). `pinnedSha`
 * is the parent-tree gitlink SHA (empty string if unparseable).
 */
interface SubmoduleStatus {
  statusChar: string;
  pinnedSha: string;
  rawLine: string;
  probeFailed: boolean;
}

function readSubmoduleStatus(): SubmoduleStatus {
  const proc = spawnSync(
    "git",
    ["submodule", "status", "ETHDILITHIUM"],
    { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  if (proc.status !== 0) {
    return { statusChar: "", pinnedSha: "", rawLine: "", probeFailed: true };
  }
  const rawLine = (proc.stdout ?? "").split("\n")[0] ?? "";
  if (rawLine === "") {
    return { statusChar: "", pinnedSha: "", rawLine, probeFailed: false };
  }
  // First char is the status; strip it for the SHA field.
  const statusChar = /^[+\-U ]/.test(rawLine) ? rawLine.charAt(0) : "";
  const stripped = statusChar === "" ? rawLine : rawLine.slice(1);
  const pinnedSha = stripped.trim().split(/\s+/)[0] ?? "";
  return { statusChar, pinnedSha, rawLine, probeFailed: false };
}

/**
 * (a) SUBMODULE_UNINIT detection. Succeeds if the ETHDILITHIUM directory
 * exists and contains `src/`; fails otherwise. Tests drive the failure via
 * `KAT_SUBMODULE_PATH=/nonexistent`.
 */
function checkSubmoduleUninit(status: SubmoduleStatus): DiagResult {
  const dir = submoduleDir();

  // Missing directory entirely.
  if (!existsSync(dir)) {
    return fail(
      "SUBMODULE_UNINIT",
      `ETHDILITHIUM submodule directory not found at ${dir}. ` +
        `Initialize with: git submodule update --init --recursive`,
    );
  }

  // Present but empty (no src/ subdir).
  let hasContent = false;
  try {
    const entries = readdirSync(dir);
    hasContent = entries.length > 0 && entries.some((e) => e === "src");
  } catch {
    hasContent = false;
  }
  if (!hasContent) {
    return fail(
      "SUBMODULE_UNINIT",
      `ETHDILITHIUM submodule at ${dir} is empty or missing 'src/' subdir. ` +
        `Initialize with: git submodule update --init --recursive`,
    );
  }

  // `git submodule status` leading `-` = not initialized in parent-tree view.
  // Only meaningful when we're looking at the real submodule path (the
  // test-only override points elsewhere, so bypass in that case).
  const isOverriddenPath = process.env["KAT_SUBMODULE_PATH"] !== undefined
    && process.env["KAT_SUBMODULE_PATH"] !== "";
  if (!isOverriddenPath) {
    if (status.probeFailed || status.statusChar === "-") {
      return fail(
        "SUBMODULE_UNINIT",
        `git submodule status ETHDILITHIUM reports uninitialized state. ` +
          `Initialize with: git submodule update --init --recursive`,
      );
    }
  }

  return OK;
}

/**
 * (b) SUBMODULE_PIN_MISMATCH detection. Compares parent-tree gitlink SHA
 * (from `git submodule status`) to current submodule HEAD. Fails if they
 * differ, or if `git submodule status` reported the `+` (HEAD-diverged)
 * status char.
 *
 * Test-only override: `KAT_SUBMODULE_PIN_OVERRIDE` replaces the parent-tree
 * gitlink SHA to drive this failure mode without mutating real submodule state.
 */
function checkSubmodulePinMismatch(status: SubmoduleStatus): DiagResult {
  const pinOverride = process.env["KAT_SUBMODULE_PIN_OVERRIDE"];
  const pinnedSha =
    pinOverride !== undefined && pinOverride !== ""
      ? pinOverride
      : status.pinnedSha;

  let currentHead: string;
  try {
    currentHead = execFileSync(
      "git",
      ["-C", submoduleDir(), "rev-parse", "HEAD"],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ).trim();
  } catch {
    // Cannot probe HEAD — report as pin mismatch with unknown SHA.
    return fail(
      "SUBMODULE_PIN_MISMATCH",
      `Failed to read ETHDILITHIUM HEAD. expected=<unknown> actual=<unknown>. ` +
        `Re-pin with: git -C ETHDILITHIUM checkout ${pinnedSha}`,
    );
  }

  const hasMismatch =
    status.statusChar === "+" ||
    (pinnedSha !== "" && pinnedSha !== currentHead);

  if (hasMismatch) {
    return fail(
      "SUBMODULE_PIN_MISMATCH",
      `ETHDILITHIUM submodule at wrong commit: expected=${pinnedSha} actual=${currentHead}. ` +
        `Re-pin with: git -C ETHDILITHIUM checkout ${pinnedSha}`,
    );
  }

  return OK;
}

/**
 * Parse a `python3 --version` output into `(major, minor, patch)`. Returns
 * `undefined` if the string does not match `"Python <M>.<m>.<p>"` shape.
 */
function parsePythonVersion(
  raw: string,
): { major: number; minor: number; patch: number } | undefined {
  const match = raw.trim().match(/^Python\s+(\d+)\.(\d+)(?:\.(\d+))?/);
  if (match === null) return undefined;
  const major = Number.parseInt(match[1] ?? "", 10);
  const minor = Number.parseInt(match[2] ?? "", 10);
  const patch = Number.parseInt(match[3] ?? "0", 10);
  if (!Number.isFinite(major) || !Number.isFinite(minor)) return undefined;
  return { major, minor, patch };
}

/**
 * (c) PYTHON_VERSION_MISMATCH detection. Fails if `python3 --version` fails
 * or the parsed version is not in `[3.9, 4)`. Test-only override:
 * `KAT_PYTHON_VERSION_OVERRIDE` replaces the detected version string.
 */
function checkPythonVersion(): DiagResult {
  const override = process.env["KAT_PYTHON_VERSION_OVERRIDE"];
  let detected: string;
  if (override !== undefined && override !== "") {
    detected = override;
  } else {
    const proc = spawnSync("python3", ["--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (proc.status !== 0) {
      return fail(
        "PYTHON_VERSION_MISMATCH",
        `python3 --version failed (exit ${String(proc.status)}). ` +
          `Required: ${PYTHON_REQUIRED_RANGE}. Detected: <unavailable>. ` +
          `Install Python 3.9+ and ensure it is on PATH.`,
      );
    }
    // `python3 --version` writes to stdout in 3.4+; older versions used stderr.
    detected = ((proc.stdout ?? "") + (proc.stderr ?? "")).trim();
  }

  const parsed = parsePythonVersion(detected);
  if (parsed === undefined) {
    return fail(
      "PYTHON_VERSION_MISMATCH",
      `Failed to parse python3 version output. ` +
        `Required: ${PYTHON_REQUIRED_RANGE}. Detected: ${detected}.`,
    );
  }

  const { major, minor } = parsed;
  const satisfiesMin =
    major > PYTHON_MIN_MAJOR ||
    (major === PYTHON_MIN_MAJOR && minor >= PYTHON_MIN_MINOR);
  const satisfiesMax = major < PYTHON_MAX_MAJOR;
  if (!satisfiesMin || !satisfiesMax) {
    return fail(
      "PYTHON_VERSION_MISMATCH",
      `Python version out of range. ` +
        `Required: ${PYTHON_REQUIRED_RANGE}. Detected: ${detected}. ` +
        `Install a compatible Python and re-run.`,
    );
  }

  return OK;
}

/**
 * (d) PYTHON_DEPS_MISSING detection. Spawns a lightweight `python3 -c
 * "import <modules>"` probe. On `ImportError` (or any non-zero exit),
 * emit the missing-module name (scraped from stderr) + the install command.
 *
 * Test-only override: `KAT_PYTHON_DEPS_PROBE_OVERRIDE` is a comma-separated
 * list of module names that replaces the real probe list. Tests use a
 * known-missing module (e.g. `nonexistent_module_xyz_abc`) to drive this.
 */
function checkPythonDeps(): DiagResult {
  const override = process.env["KAT_PYTHON_DEPS_PROBE_OVERRIDE"];
  const modules: readonly string[] =
    override !== undefined && override !== ""
      ? override.split(",").map((s) => s.trim()).filter((s) => s !== "")
      : PYTHON_DEPS_PROBE;

  // Build the one-liner: `import a; import b; ...` — one line for speed.
  const pythonSnippet = modules.map((m) => `import ${m}`).join("; ");
  const proc = spawnSync("python3", ["-c", pythonSnippet], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    // Add the submodule pythonref to PYTHONPATH so dilithium_py resolves
    // without a prior `pip install -e .`.
    env: {
      ...process.env,
      PYTHONPATH: [
        path.join(REPO_ROOT, "ETHDILITHIUM", "pythonref"),
        process.env["PYTHONPATH"] ?? "",
      ]
        .filter((p) => p !== "")
        .join(path.delimiter),
    },
  });
  if (proc.status !== 0) {
    const stderrOut = (proc.stderr ?? "").trim();
    // Extract the specific missing module from `ModuleNotFoundError: No
    // module named 'foo'` or `ImportError: cannot import name ...`.
    const moduleMatch = stderrOut.match(/No module named ['"]([^'"]+)['"]/);
    const missing = moduleMatch?.[1] ?? modules.join(", ");
    return fail(
      "PYTHON_DEPS_MISSING",
      `Python dependency probe failed — missing module: ${missing}. ` +
        `Install with: pip install -r ETHDILITHIUM/pythonref/requirements.txt. ` +
        `Probe stderr: ${stderrOut.slice(0, 500)}`,
    );
  }

  return OK;
}

/**
 * Run all four AC-U-2 pre-flight checks in order. On the first failure,
 * emit an NDJSON diagnostic to stderr and return `false` so `main()` sets
 * a non-zero exit code without running the generation path. Return `true`
 * if all four checks pass.
 */
function runPreflightDiagnostics(): boolean {
  const status = readSubmoduleStatus();
  const checks: Array<() => DiagResult> = [
    () => checkSubmoduleUninit(status),
    () => checkSubmodulePinMismatch(status),
    () => checkPythonVersion(),
    () => checkPythonDeps(),
  ];
  for (const check of checks) {
    const result = check();
    if (result.kind === "fail") {
      process.stderr.write(
        JSON.stringify({ code: result.code, message: result.message }) + "\n",
      );
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// ETHFALCON pre-flight diagnostics (Story 1-1 Task T0 — parallel to the
// ETHDILITHIUM preflight above, parameterized for the `ETHFALCON/` submodule).
// Re-uses the 4-mode taxonomy (SUBMODULE_UNINIT, SUBMODULE_PIN_MISMATCH,
// PYTHON_VERSION_MISMATCH, PYTHON_DEPS_MISSING) so operator-facing error
// strings are uniform across schemes.
// ---------------------------------------------------------------------------

/**
 * Python modules probed before the ETHFALCON falcon-eth branch runs. The
 * probe-list is the exact import footprint of `FALCON_PROBE_PY_T0` below
 * (plus `polyntt.poly`, which is transitively imported by `falcon.py`).
 * ETHFALCON's `pythonref/` has no `requirements.txt` bundled at the standard
 * location; installation is via `pip install pycryptodome numpy` per
 * `ETHFALCON/pythonref/makefile`.
 */
const ETHFALCON_PYTHON_DEPS_PROBE: readonly string[] = [
  "drbg.aes256_ctr_drbg",
  "falcon",
  "ntrugen",
  "shake",
  "keccak_prng",
  "polyntt.poly",
];

function readEthfalconSubmoduleStatus(): SubmoduleStatus {
  const proc = spawnSync(
    "git",
    ["submodule", "status", "ETHFALCON"],
    { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  if (proc.status !== 0) {
    return { statusChar: "", pinnedSha: "", rawLine: "", probeFailed: true };
  }
  const rawLine = (proc.stdout ?? "").split("\n")[0] ?? "";
  if (rawLine === "") {
    return { statusChar: "", pinnedSha: "", rawLine, probeFailed: false };
  }
  const statusChar = /^[+\-U ]/.test(rawLine) ? rawLine.charAt(0) : "";
  const stripped = statusChar === "" ? rawLine : rawLine.slice(1);
  const pinnedSha = stripped.trim().split(/\s+/)[0] ?? "";
  return { statusChar, pinnedSha, rawLine, probeFailed: false };
}

function ethfalconSubmoduleDir(): string {
  const override = process.env["KAT_ETHFALCON_SUBMODULE_PATH"];
  if (override !== undefined && override !== "") {
    requireTestOverrideSentinel("KAT_ETHFALCON_SUBMODULE_PATH");
    validateTestOverrideFormat(
      "KAT_ETHFALCON_SUBMODULE_PATH",
      override,
      /^[A-Za-z0-9_./-]+$/,
    );
    return override;
  }
  return path.join(REPO_ROOT, "ETHFALCON");
}

function checkEthfalconSubmoduleUninit(status: SubmoduleStatus): DiagResult {
  const dir = ethfalconSubmoduleDir();
  if (!existsSync(dir)) {
    return fail(
      "SUBMODULE_UNINIT",
      `ETHFALCON submodule directory not found at ${dir}. ` +
        `Initialize with: git submodule update --init --recursive`,
    );
  }
  let hasContent = false;
  try {
    const entries = readdirSync(dir);
    hasContent = entries.length > 0 && entries.some((e) => e === "src");
  } catch {
    hasContent = false;
  }
  if (!hasContent) {
    return fail(
      "SUBMODULE_UNINIT",
      `ETHFALCON submodule at ${dir} is empty or missing 'src/' subdir. ` +
        `Initialize with: git submodule update --init --recursive`,
    );
  }
  const isOverriddenPath =
    process.env["KAT_ETHFALCON_SUBMODULE_PATH"] !== undefined &&
    process.env["KAT_ETHFALCON_SUBMODULE_PATH"] !== "";
  if (!isOverriddenPath) {
    if (status.probeFailed || status.statusChar === "-") {
      return fail(
        "SUBMODULE_UNINIT",
        `git submodule status ETHFALCON reports uninitialized state. ` +
          `Initialize with: git submodule update --init --recursive`,
      );
    }
  }
  return OK;
}

function checkEthfalconSubmodulePinMismatch(
  status: SubmoduleStatus,
): DiagResult {
  // Honor a test-only override via KAT_ETHFALCON_SUBMODULE_PIN_OVERRIDE
  // (sentinel + regex gated per NFR-9).
  let pinnedSha = status.pinnedSha;
  const pinOverride = process.env["KAT_ETHFALCON_SUBMODULE_PIN_OVERRIDE"];
  if (pinOverride !== undefined && pinOverride !== "") {
    requireTestOverrideSentinel("KAT_ETHFALCON_SUBMODULE_PIN_OVERRIDE");
    validateTestOverrideFormat(
      "KAT_ETHFALCON_SUBMODULE_PIN_OVERRIDE",
      pinOverride,
      /^[0-9a-f]{40}$/,
    );
    pinnedSha = pinOverride;
  }

  let currentHead: string;
  try {
    currentHead = execFileSync(
      "git",
      ["-C", ethfalconSubmoduleDir(), "rev-parse", "HEAD"],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ).trim();
  } catch {
    return fail(
      "SUBMODULE_PIN_MISMATCH",
      `Failed to read ETHFALCON HEAD. expected=<unknown> actual=<unknown>. ` +
        `Re-pin with: git -C ETHFALCON checkout ${pinnedSha}`,
    );
  }

  const hasMismatch =
    status.statusChar === "+" ||
    (pinnedSha !== "" && pinnedSha !== currentHead);
  if (hasMismatch) {
    return fail(
      "SUBMODULE_PIN_MISMATCH",
      `ETHFALCON submodule at wrong commit: expected=${pinnedSha} actual=${currentHead}. ` +
        `Re-pin with: git -C ETHFALCON checkout ${pinnedSha}`,
    );
  }
  return OK;
}

function checkEthfalconPythonDeps(): DiagResult {
  const modules: readonly string[] = ETHFALCON_PYTHON_DEPS_PROBE;
  const pythonSnippet = modules.map((m) => `import ${m}`).join("; ");
  const proc = spawnSync("python3", ["-c", pythonSnippet], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      PYTHONPATH: [
        path.join(REPO_ROOT, "ETHFALCON", "pythonref"),
        process.env["PYTHONPATH"] ?? "",
      ]
        .filter((p) => p !== "")
        .join(path.delimiter),
    },
  });
  if (proc.status !== 0) {
    const stderrOut = (proc.stderr ?? "").trim();
    const moduleMatch = stderrOut.match(/No module named ['"]([^'"]+)['"]/);
    const missing = moduleMatch?.[1] ?? modules.join(", ");
    return fail(
      "PYTHON_DEPS_MISSING",
      `ETHFALCON Python dependency probe failed — missing module: ${missing}. ` +
        `Install with: pip install pycryptodome numpy && ensure ETHFALCON/pythonref is on PYTHONPATH. ` +
        `Probe stderr: ${stderrOut.slice(0, 500)}`,
    );
  }
  return OK;
}

/**
 * Run all four pre-flight checks against the ETHFALCON submodule. Mirrors
 * the ETHDILITHIUM preflight contract: on first failure, NDJSON diagnostic
 * to stderr and return `false`.
 */
function runEthfalconPreflightDiagnostics(): boolean {
  const status = readEthfalconSubmoduleStatus();
  const checks: Array<() => DiagResult> = [
    () => checkEthfalconSubmoduleUninit(status),
    () => checkEthfalconSubmodulePinMismatch(status),
    () => checkPythonVersion(), // Python interpreter is cross-scheme.
    () => checkEthfalconPythonDeps(),
  ];
  for (const check of checks) {
    const result = check();
    if (result.kind === "fail") {
      process.stderr.write(
        JSON.stringify({ code: result.code, message: result.message }) + "\n",
      );
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Story 1-1 Task T0 — PRE_G4_DRBG_PROBE (A-005 audit, load-bearing).
//
// Replays `ETHFALCON/pythonref/test_falcon_KAT.py::TestFalconKAT::test_KAT_ETH`
// on vec 0 of `ETHFALCON/test/ethfalcon512-KAT.rsp` via a ONE-shot
// `python3 -c` subprocess, then asserts three byte-equalities per
// `docs/amendments.md` §A-002:
//
//   (1) `recoveredPk.pk == PublicKey.from_bytes(expected_pk).pk`
//       — proves keygen NTRU gen is DRBG-state-deterministic (the NTRU
//         generator consumes `inner_seed = drbg.random_bytes(48)`).
//   (2) `py_sig[1:41] == sm[2:42]`
//       — proves the post-keygen `drbg.random_bytes(SALT_LEN=40)` call
//         consumed by salt generation advances correctly.
//   (3) `py_sig[41:] == esig[1:1+len(py_enc_s)]` where
//       `esig = sm[42+mlen : 42+mlen+sig_len]`, `sig_len = (sm[0]<<8)|sm[1]`
//       — proves the Gaussian-sampling `drbg.random_bytes` stream is
//         state-reproducible byte-for-byte.
//
// Any failure is a structured FixtureGenError with code
// PRE_G4_DRBG_PROBE_FAILED that HALTS the CLI. The probe is REQUIRED before
// T1 (bulk vectors.json write) so a single vec-0 spot-check guards the
// correctness of all 100 downstream vectors.
// ---------------------------------------------------------------------------

/** Parsed vec-0 fields from the ETHFALCON .rsp (hex, lowercase). */
interface EthfalconRspVec0 {
  seedHex: string;
  mlen: number;
  msgHex: string;
  pkHex: string;
  smHex: string;
}

function parseEthfalconRspVec0(): EthfalconRspVec0 {
  const rspPath = ethfalconRspPath();
  if (!existsSync(rspPath)) {
    throw new FixtureGenError(
      `ETHFALCON .rsp not found at ${rspPath}. ` +
        `Initialize submodules with: git submodule update --init --recursive`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  const raw = readFileSync(rspPath, "utf8");
  const rec: Partial<EthfalconRspVec0> & { count?: number } = {};
  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      if (rec.count !== undefined) break; // first record complete
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    switch (key) {
      case "count":
        rec.count = Number.parseInt(value, 10);
        break;
      case "seed":
        rec.seedHex = value.toLowerCase();
        break;
      case "mlen":
        rec.mlen = Number.parseInt(value, 10);
        break;
      case "msg":
        rec.msgHex = value.toLowerCase();
        break;
      case "pk":
        rec.pkHex = value.toLowerCase();
        break;
      case "sm":
        rec.smHex = value.toLowerCase();
        break;
      default:
        break;
    }
  }
  if (rec.count !== 0) {
    throw new FixtureGenError(
      `Expected first record of ETHFALCON .rsp to be count=0, got count=${String(rec.count)}`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  for (const field of ["seedHex", "mlen", "msgHex", "pkHex", "smHex"] as const) {
    if (rec[field] === undefined) {
      throw new FixtureGenError(
        `ETHFALCON .rsp vec 0 missing field '${field}'`,
        "PRE_G4_DRBG_PROBE_FAILED",
      );
    }
  }
  return {
    seedHex: rec.seedHex!,
    mlen: rec.mlen!,
    msgHex: rec.msgHex!,
    pkHex: rec.pkHex!,
    smHex: rec.smHex!,
  };
}

/**
 * Python probe passed to `python3 -c`. Reads a single JSON object from stdin
 * with `{seed, msg}`, runs the `test_KAT_ETH` flow, emits one JSON object
 * on stdout: `{recoveredPk, pkCoeffsHex, salt, enc_s, py_header}`.
 *
 * NFR-3: stays as a TS string; no `.py` file ships under `scripts/`.
 */
const FALCON_PROBE_PY_T0 = `
import json
import sys
sys.path.insert(0, "ETHFALCON/pythonref")

from drbg.aes256_ctr_drbg import AES256_CTR_DRBG
from falcon import SecretKey, PublicKey
from ntrugen import ntru_gen
from shake import SHAKE
from keccak_prng import KeccakPRNG


def pk_coeffs_to_hex(pk_obj):
    # Each coefficient < 12289 fits in 14 bits; emit as 2-byte BE uint16s
    # (values are well under 2^16). This is a deterministic, compact
    # encoding used only for cross-process byte-equality comparison.
    return b"".join(int(c).to_bytes(2, "big") for c in pk_obj.pk).hex()


payload = json.loads(sys.stdin.read())
seed = bytes.fromhex(payload["seed"])
msg = bytes.fromhex(payload["msg"])

# Exact replay of test_KAT_ETH (ETHFALCON/pythonref/test_falcon_KAT.py:122-134).
drbg = AES256_CTR_DRBG(seed)
inner_seed = drbg.random_bytes(48)
prng = SHAKE.new(inner_seed)
prng.flip()
n = 512
f, g, F, G = ntru_gen(n, randombytes=prng.read, logn=9)
sk = SecretKey(n, [f, g, F, G])
pk = PublicKey(n, sk.h)
sig = sk.sign(msg, randombytes=drbg.random_bytes, xof=KeccakPRNG)

# Python sig layout: header(1) || salt(40) || enc_s(variable)
sys.stdout.write(json.dumps({
    "pkCoeffsHex": pk_coeffs_to_hex(pk),
    "sigHex": sig.hex(),
}))
sys.stdout.flush()
`;

interface ProbePythonResult {
  pkCoeffsHex: string;
  sigHex: string;
}

/**
 * Derive the hex uint16-BE coefficient encoding of a raw 897-byte ETHFALCON
 * public key. Mirrors `PublicKey.from_bytes(pk_bytes).pk` in Python
 * (falcon.py:237-285) — 14-bit unpacking + value check — then re-emits as
 * 2-byte BE uint16s to match the Python probe's `pk_coeffs_to_hex`. This
 * gives a side-by-side byte-equality comparison without depending on
 * Python-side pickling/serialization semantics.
 */
function expectedPkCoeffsHex(pkHex: string): string {
  const pk = Buffer.from(pkHex, "hex");
  if (pk.length !== 897) {
    throw new FixtureGenError(
      `ETHFALCON vec-0 pk has length ${String(pk.length)}, expected 897`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  if (pk[0] !== 0x09) {
    throw new FixtureGenError(
      `ETHFALCON vec-0 pk header byte is 0x${pk[0]!.toString(16)}, expected 0x09`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  const coeffs: number[] = [];
  let acc = 0n;
  let accBits = 0;
  const N = 512;
  for (let i = 1; i < pk.length && coeffs.length < N; i++) {
    acc = (acc << 8n) | BigInt(pk[i]!);
    accBits += 8;
    while (accBits >= 14 && coeffs.length < N) {
      accBits -= 14;
      const val = Number((acc >> BigInt(accBits)) & 0x3fffn);
      if (val >= 12289) {
        throw new FixtureGenError(
          `ETHFALCON vec-0 pk has invalid coefficient ${val} at index ${coeffs.length}`,
          "PRE_G4_DRBG_PROBE_FAILED",
        );
      }
      coeffs.push(val);
      acc &= (1n << BigInt(accBits)) - 1n;
    }
  }
  if (coeffs.length !== N) {
    throw new FixtureGenError(
      `ETHFALCON vec-0 pk decoded to ${coeffs.length} coefficients, expected ${N}`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  const out = Buffer.alloc(N * 2);
  for (let i = 0; i < N; i++) {
    out.writeUInt16BE(coeffs[i]!, i * 2);
  }
  return out.toString("hex");
}

/**
 * Run PRE_G4_DRBG_PROBE (Story 1-1 Task T0). Spawns the Python probe via
 * `python3 -c`, compares the three windows described above, HALTs (throws
 * FixtureGenError) on any mismatch. On success, returns `void` and the
 * caller proceeds.
 */
export function preG4DrbgProbe(): void {
  const vec0 = parseEthfalconRspVec0();

  // Honor an OPTIONAL test-hook: KAT_FALCON_PROBE_FORCE_FAIL=1 forces a
  // synthetic failure to exercise the HALT path (sentinel-gated).
  const forceFail = process.env["KAT_FALCON_PROBE_FORCE_FAIL"];
  if (forceFail !== undefined && forceFail !== "") {
    requireTestOverrideSentinel("KAT_FALCON_PROBE_FORCE_FAIL");
    validateTestOverrideFormat(
      "KAT_FALCON_PROBE_FORCE_FAIL",
      forceFail,
      /^[01]$/,
    );
    if (forceFail === "1") {
      throw new FixtureGenError(
        "PRE_G4_DRBG_PROBE forced to fail by KAT_FALCON_PROBE_FORCE_FAIL=1. " +
          "See docs/amendments.md §A-002 for the byte-equality predicates.",
        "PRE_G4_DRBG_PROBE_FAILED",
      );
    }
  }

  // Spawn ONE subprocess. NFR-3: Python source is passed as a `-c` string
  // argument (no .py file added under scripts/). NFR-9: the only
  // interpolated test-override `KAT_ETHFALCON_RSP_PATH` has already been
  // regex-validated by `parseEthfalconRspVec0`; the seed/msg values below
  // come from the pinned submodule .rsp (not from env vars), so there is
  // no operator-controllable interpolation into the Python source.
  const pyProc = spawnSync("python3", ["-c", FALCON_PROBE_PY_T0], {
    cwd: REPO_ROOT,
    input: JSON.stringify({ seed: vec0.seedHex, msg: vec0.msgHex }),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      PYTHONPATH: [
        path.join(REPO_ROOT, "ETHFALCON", "pythonref"),
        process.env["PYTHONPATH"] ?? "",
      ]
        .filter((p) => p !== "")
        .join(path.delimiter),
    },
  });
  if (pyProc.status !== 0) {
    throw new FixtureGenError(
      `PRE_G4_DRBG_PROBE: python3 subprocess failed (exit ${String(pyProc.status)}):\n${pyProc.stderr ?? ""}`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }

  let py: ProbePythonResult;
  try {
    py = JSON.parse(pyProc.stdout) as ProbePythonResult;
  } catch (cause) {
    throw new FixtureGenError(
      `PRE_G4_DRBG_PROBE: failed to parse python stdout as JSON: ${String(cause)}`,
      "PRE_G4_DRBG_PROBE_FAILED",
      { cause: cause instanceof Error ? cause : undefined },
    );
  }

  // Window 1: recovered PublicKey coefficients must equal the .rsp pk
  // decoded via the same 14-bit unpacking. This proves the keygen DRBG
  // state is reproducible (ntru_gen consumes drbg.random_bytes(48)).
  const expectedPkCoeffs = expectedPkCoeffsHex(vec0.pkHex);
  if (py.pkCoeffsHex !== expectedPkCoeffs) {
    throw new FixtureGenError(
      "PRE_G4_DRBG_PROBE FAILED window-1 (keygen DRBG state): " +
        `recovered pk coefficients differ from .rsp pk coefficients. ` +
        `recovered[:32]=0x${py.pkCoeffsHex.slice(0, 64)} ` +
        `expected[:32]=0x${expectedPkCoeffs.slice(0, 64)}. ` +
        `Log this as an A-005-equivalent finding in docs/amendments.md and HALT.`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }

  // Windows 2 and 3: parse the .rsp sm layout per amendments.md §A-002 and
  // compare salt + enc_s prefixes.
  const sm = Buffer.from(vec0.smHex, "hex");
  if (sm.length < 42 + vec0.mlen + 1) {
    throw new FixtureGenError(
      `PRE_G4_DRBG_PROBE: .rsp sm length ${sm.length} too short for header+salt+msg+header+esig layout`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  const sigLen = (sm[0]! << 8) | sm[1]!;
  const rspSaltHex = sm.subarray(2, 42).toString("hex");
  const rspMsgInSm = sm.subarray(42, 42 + vec0.mlen).toString("hex");
  const esig = sm.subarray(42 + vec0.mlen, 42 + vec0.mlen + sigLen);
  if (esig.length < 1) {
    throw new FixtureGenError(
      `PRE_G4_DRBG_PROBE: .rsp sm esig window is empty (sig_len=${sigLen})`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  // Sanity: the message embedded in sm must match the standalone .rsp msg.
  if (rspMsgInSm !== vec0.msgHex) {
    throw new FixtureGenError(
      `PRE_G4_DRBG_PROBE: sm embedded msg (${rspMsgInSm}) != .rsp msg (${vec0.msgHex}) — .rsp layout drift`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }

  const sig = Buffer.from(py.sigHex, "hex");
  if (sig.length < 1 + 40 + 1) {
    throw new FixtureGenError(
      `PRE_G4_DRBG_PROBE: python sig length ${sig.length} too short for header(1)+salt(40)+enc_s`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  const pySaltHex = sig.subarray(1, 41).toString("hex");
  const pyEncS = sig.subarray(41);

  // Window 2: salt.
  if (pySaltHex !== rspSaltHex) {
    throw new FixtureGenError(
      "PRE_G4_DRBG_PROBE FAILED window-2 (salt / post-keygen DRBG state): " +
        `recovered salt 0x${pySaltHex} != .rsp salt 0x${rspSaltHex}. ` +
        `Log this as an A-005-equivalent finding in docs/amendments.md and HALT.`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }

  // Window 3: enc_s prefix.
  const esigBody = esig.subarray(1); // strip the 1-byte esig header (0x29)
  const compareLen = Math.min(pyEncS.length, esigBody.length);
  if (compareLen === 0) {
    throw new FixtureGenError(
      "PRE_G4_DRBG_PROBE: no bytes to compare for window-3 (Gaussian body). " +
        `py_enc_s_len=${pyEncS.length} esig_body_len=${esigBody.length}`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }
  const pyEncSPrefix = pyEncS.subarray(0, compareLen);
  const esigBodyPrefix = esigBody.subarray(0, compareLen);
  if (!pyEncSPrefix.equals(esigBodyPrefix)) {
    // Locate the first mismatching byte for the error message.
    let diffIdx = 0;
    while (
      diffIdx < compareLen &&
      pyEncSPrefix[diffIdx] === esigBodyPrefix[diffIdx]
    ) {
      diffIdx++;
    }
    throw new FixtureGenError(
      "PRE_G4_DRBG_PROBE FAILED window-3 (Gaussian-body DRBG state): " +
        `enc_s prefix diverges at byte ${diffIdx} / ${compareLen}. ` +
        `recovered[${diffIdx}..${Math.min(diffIdx + 8, compareLen)}]=0x${pyEncSPrefix
          .subarray(diffIdx, Math.min(diffIdx + 8, compareLen))
          .toString("hex")} ` +
        `expected[${diffIdx}..${Math.min(diffIdx + 8, compareLen)}]=0x${esigBodyPrefix
          .subarray(diffIdx, Math.min(diffIdx + 8, compareLen))
          .toString("hex")}. ` +
        `Log this as an A-005-equivalent finding in docs/amendments.md and HALT.`,
      "PRE_G4_DRBG_PROBE_FAILED",
    );
  }

  process.stdout.write(
    JSON.stringify({
      event: "PRE_G4_DRBG_PROBE_PASS",
      vec: 0,
      rsp: path.relative(REPO_ROOT, ethfalconRspPath()),
      windows: {
        keygen: "recovered pk coefficients byte-identical to .rsp pk (512 coeffs)",
        salt: `py_salt == sm[2:42] (40 B): 0x${pySaltHex}`,
        encS: `py_enc_s[:${compareLen}] == esig[1:${compareLen + 1}] (${compareLen} B)`,
      },
      note: "DRBG state-advancement is byte-reproducible for vec 0. T1 bulk write may proceed under this invariant.",
    }) + "\n",
  );
}

// ---------------------------------------------------------------------------
// Git helpers — pin-read plumbing (AC-1-4's Task 4 finalization hooks here)
// ---------------------------------------------------------------------------

/**
 * Shape returned by {@link readSubmoduleShas}. `pinnedSha` is the parent-tree
 * gitlink (what `.gitmodules`-family convention records); `currentHead` is
 * the live submodule HEAD. Task 4 upgrades mismatch to code
 * `SUBMODULE_PIN_MISMATCH`.
 */
interface SubmoduleShas {
  pinnedSha: string;
  currentHead: string;
  commitTimestamp: number;
}

function git(args: string[], cwd: string = REPO_ROOT): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function readSubmoduleShas(): SubmoduleShas {
  // Parent-tree gitlink — strip optional leading [+ - U space] status char.
  const statusLine =
    git(["submodule", "status", "ETHDILITHIUM"]).split("\n")[0] ?? "";
  const stripped = statusLine.replace(/^[+\-U ]/, "");
  const pinnedSha = stripped.split(/\s+/)[0] ?? "";

  const submoduleRoot = path.join(REPO_ROOT, "ETHDILITHIUM");
  const currentHead = git(["rev-parse", "HEAD"], submoduleRoot);

  // Commit timestamp (seconds) — source of `generatedAt` determinism.
  const tsStr = git(["log", "-1", "--format=%ct", "HEAD"], submoduleRoot);
  const commitTimestamp = Number.parseInt(tsStr, 10);
  if (!Number.isFinite(commitTimestamp)) {
    throw new Error(
      `Failed to parse submodule commit timestamp from 'git log %ct': ${tsStr}`,
    );
  }

  return { pinnedSha, currentHead, commitTimestamp };
}

// ---------------------------------------------------------------------------
// .rsp parser
// ---------------------------------------------------------------------------

interface RspRecord {
  count: number;
  seed: string; // 48 B hex (normalized lowercase)
  mlen: number;
  msg: string; // mlen bytes hex
  pk: string;
  sk: string;
  sm: string; // smlen bytes hex (sig || msg)
}

/**
 * Parse the PQCsignKAT `.rsp` file into 100 records. Format is the standard
 * NIST-KAT newline-separated `key = value` blocks separated by blank lines.
 */
function parseRspFile(): RspRecord[] {
  const raw = readFileSync(RSP_PATH, "utf8");
  const records: RspRecord[] = [];
  let current: Partial<RspRecord> = {};

  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      if (current.count !== undefined) {
        records.push(finalizeRecord(current));
        current = {};
      }
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    switch (key) {
      case "count":
        current.count = Number.parseInt(value, 10);
        break;
      case "seed":
        current.seed = value.toLowerCase();
        break;
      case "mlen":
        current.mlen = Number.parseInt(value, 10);
        break;
      case "msg":
        current.msg = value.toLowerCase();
        break;
      case "pk":
        current.pk = value.toLowerCase();
        break;
      case "sk":
        current.sk = value.toLowerCase();
        break;
      case "sm":
        current.sm = value.toLowerCase();
        break;
      // "smlen" is redundant (derivable from sm); skip it.
      default:
        break;
    }
  }
  if (current.count !== undefined) {
    records.push(finalizeRecord(current));
  }
  return records;
}

function finalizeRecord(r: Partial<RspRecord>): RspRecord {
  for (const field of [
    "count",
    "seed",
    "mlen",
    "msg",
    "pk",
    "sk",
    "sm",
  ] as const) {
    if (r[field] === undefined) {
      throw new Error(
        `Malformed .rsp record (count=${String(r.count)}): missing '${field}'`,
      );
    }
  }
  return r as RspRecord;
}

// ---------------------------------------------------------------------------
// Python batch script (single spawn, JSON-on-stdin → NDJSON-on-stdout)
// ---------------------------------------------------------------------------

/**
 * Python driver passed to `python3 -c`. Reads a single JSON object from
 * stdin with `{vectors: [...], prg_jobs: [...]}`, writes NDJSON on stdout:
 * one line per ML-DSA vector, then one line per PRG job, each tagged with
 * a `kind` discriminator.
 *
 * Keeping the script as a TS string (not a `.py` file) is NFR-3 compliance:
 * zero Python files ship in the tree outside the pinned submodule.
 */
const PYTHON_BATCH = `
import json
import sys
sys.path.insert(0, "ETHDILITHIUM/pythonref")

from dilithium_py.dilithium import Dilithium2
from dilithium_py.drbg.aes256_ctr_drbg import AES256_CTR_DRBG
from dilithium_py.keccak_prng.keccak_prng_wrapper import Keccak256PRNG
from eth_abi import encode as abi_encode


def encode_matrix_bytes(A_hat):
    """Flatten A_hat (k x l matrix of polynomials) to 4B-BE per coefficient.

    pk_for_eth returns A_hat in NTT domain. The canonical ETHDilithium
    on-chain encoding packs each coeff as a 4-byte big-endian uint32,
    row-major. Emitting the flat bytes blob lets abi.encode(bytes,bytes,
    bytes) match the DD-7 'reshapedPublicKey' slot shape per A-001
    ('tr' is variable-length bytes, not bytes32).
    """
    flat = bytearray()
    rows = A_hat._data if hasattr(A_hat, "_data") else A_hat.rows
    for row in rows:
        cells = row if isinstance(row, list) else [row]
        for poly in cells:
            for c in poly.coeffs:
                flat.extend(int(c).to_bytes(4, "big"))
    return bytes(flat)


def encode_vector_bytes(t1):
    """Flatten t1 (k-length vector of polynomials) to 4B-BE per coefficient."""
    flat = bytearray()
    data = t1._data if hasattr(t1, "_data") else t1.rows
    for entry in data:
        cells = entry if isinstance(entry, list) else [entry]
        for poly in cells:
            for c in poly.coeffs:
                flat.extend(int(c).to_bytes(4, "big"))
    return bytes(flat)


def process_vector(rec):
    drbg = AES256_CTR_DRBG(bytes.fromhex(rec["seed"]))
    # A-005: two SEPARATE 32-byte calls, not one 64-byte call.
    # AES256_CTR_DRBG.random_bytes runs __ctr_drbg_update at the END of
    # each call (Section 10.2.1.5.1 of SP 800-90A), so bytes[32:64] of a
    # single random_bytes(64) are NOT equal to the second random_bytes(32)
    # output. Dilithium.sign() consumes rnd via a fresh random_bytes(32)
    # call AFTER keygen's random_bytes(32); the ETH KAT signatures in
    # PQCsignKAT_Dilithium2_ETH.rsp were produced with this
    # state-advanced rnd. Replicating the KAT flow requires two calls.
    zeta = drbg.random_bytes(32)
    rnd = drbg.random_bytes(32)
    pk_bytes = bytes.fromhex(rec["pk"])
    A_hat, tr, t1_new = Dilithium2.pk_for_eth(
        pk_bytes, _xof=Keccak256PRNG, _xof2=Keccak256PRNG
    )
    a_hat_bytes = encode_matrix_bytes(A_hat)
    t1_bytes = encode_vector_bytes(t1_new)
    # tr is 64 bytes (from _h(pk, 64)); encode as dynamic bytes.
    reshaped = abi_encode(
        ["bytes", "bytes", "bytes"], [a_hat_bytes, tr, t1_bytes]
    )
    return {
        "kind": "kat",
        "count": rec["count"],
        "zeta": zeta.hex(),
        "rnd": rnd.hex(),
        "reshapedPublicKey": reshaped.hex(),
    }


def process_prg_job(job):
    prng = Keccak256PRNG()
    for inj_hex in job["injects"]:
        prng.inject(bytes.fromhex(inj_hex))
    prng.flip()
    outputs = []
    for n in job["extracts"]:
        outputs.append(prng.extract(n).hex())
    return {"kind": "prg", "id": job["id"], "expected": outputs}


payload = json.loads(sys.stdin.read())
for vec in payload["vectors"]:
    sys.stdout.write(json.dumps(process_vector(vec)) + "\\n")
for job in payload["prg_jobs"]:
    sys.stdout.write(json.dumps(process_prg_job(job)) + "\\n")
sys.stdout.flush()
`;

/**
 * PRG Layer-2 boundary job spec. Each job scripts an `inject*`/`flip`/
 * `extract*` sequence; Python returns the extract outputs verbatim.
 */
interface PrgJobSpec {
  id: string;
  description: string;
  injectsHex: string[]; // hex WITHOUT 0x prefix
  extracts: number[];
}

const PRG_LAYER2_JOBS: PrgJobSpec[] = [
  {
    id: "prg-cross-extract",
    description:
      "inject 32 B seed; flip; extract(5) + extract(27) — validates out-buffer-pos persistence across extract calls",
    // Deterministic seed: bytes 00..1f so the fixture is reproducible.
    injectsHex: [
      Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString("hex"),
    ],
    extracts: [5, 27],
  },
  {
    id: "prg-multi-inject",
    description:
      "inject 16 B + inject 16 B; flip; extract(64) — validates absorb concatenation equivalence",
    injectsHex: [
      Buffer.from(Array.from({ length: 16 }, (_, i) => i + 0x40)).toString(
        "hex",
      ),
      Buffer.from(Array.from({ length: 16 }, (_, i) => i + 0x80)).toString(
        "hex",
      ),
    ],
    extracts: [64],
  },
  {
    id: "prg-empty-seed",
    description:
      'no inject; flip; extract(32) — validates keccak256(b"") initial state',
    injectsHex: [],
    extracts: [32],
  },
  {
    id: "prg-ml-dsa-shaped-seed",
    description:
      "inject 34 B (ρ ‖ j_uint16_le ‖ i_uint16_le shape); flip; extract(408) — realistic ExpandA rejection-sampling chunk",
    injectsHex: [
      // 32 B ρ (all 0xAA) || 0x0100 (j=1 LE-uint16) — 34 B total per DD-11.
      "aa".repeat(32) + "0100",
    ],
    extracts: [408],
  },
];

// ---------------------------------------------------------------------------
// Layer-1 Zhenfei canonical PRG vectors (hex literals from
// ETHDILITHIUM/test/keccak_prng.t.sol:12-27).
// ---------------------------------------------------------------------------

/**
 * The 4 canonical PRG vectors. Vectors 2 and 4 include `expected_slices`
 * because the reference Solidity test only reveals partial outputs:
 *   - v2: extract(64), Forge test documents bytes [32..64] only.
 *   - v4: three successive extract(32), Forge test documents high 16 B
 *         of each block only.
 *
 * For both v2 and v4 the `expected[]` field is filled with the FULL
 * reference stream (computed by the Python batch during fixture gen); the
 * `expected_slices[]` preserves the canonical documentation for downstream
 * Solidity-parity tests that want to assert only on ZKNox's published
 * evidence.
 */
function layer1ZhenfeiVectors(): PrgVector[] {
  const asciiHex = (s: string): string =>
    Buffer.from(s, "ascii").toString("hex");

  return [
    {
      id: "zhenfei-canonical-01",
      source: "zhenfei-canonical",
      description: 'inject "test input" (10 B); flip; extract(32)',
      injects: [`0x${asciiHex("test input")}`],
      extracts: [32],
      expected: [
        "0x5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601",
      ],
    },
    {
      id: "zhenfei-canonical-02",
      source: "zhenfei-canonical",
      description:
        'inject "test input" (10 B); flip; extract(64) — Forge test documents bytes [32..64] only',
      injects: [`0x${asciiHex("test input")}`],
      extracts: [64],
      // Populated by `main()` from Python batch (job id
      // "zhenfei-canonical-02-full"); placeholder until then.
      expected: ["0x"],
      expected_slices: [
        {
          from: 32,
          to: 64,
          value:
            "0x569857b781dd8b81dd9cb45d06999916742043ff52f1cf165e161bcc9938b705",
        },
      ],
    },
    {
      id: "zhenfei-canonical-03",
      source: "zhenfei-canonical",
      description: 'inject "testinput" (9 B); flip; extract(32)',
      injects: [`0x${asciiHex("testinput")}`],
      extracts: [32],
      expected: [
        "0x120f76b5b7198706bc294a942f8d17467aadb2bb1fa2cc1fecadbaba93c0dd74",
      ],
    },
    {
      id: "zhenfei-canonical-04-stream",
      source: "zhenfei-canonical",
      description:
        'inject "test sequence" (13 B); flip; extract(80) — Forge test documents high-16-B-of-each-32-B-block slices only',
      injects: [`0x${asciiHex("test sequence")}`],
      extracts: [80],
      // Populated by `main()` from Python batch (job id
      // "zhenfei-canonical-04-full"); placeholder until then.
      expected: ["0x"],
      expected_slices: [
        { from: 0, to: 16, value: "0x9e96b1e50719da6f0ea5b664ac8bbac5" },
        { from: 32, to: 48, value: "0x1be071eca45961aca979e88e3784a751" },
        { from: 64, to: 80, value: "0x5f19135442b6b848b2f51f7cb58bc583" },
      ],
    },
  ];
}

// ---------------------------------------------------------------------------
// Deterministic JSON serializer — stable key order per DD-7 / DD-11
// ---------------------------------------------------------------------------

function serializeKatFixture(f: KatVectorsFile): string {
  const obj: Record<string, unknown> = {
    scheme: f.scheme,
    params: f.params,
    submoduleSha: f.submoduleSha,
    generatedAt: f.generatedAt,
    source: {
      rspFile: f.source.rspFile,
      drbgDerivation: f.source.drbgDerivation,
      ctx: f.source.ctx,
    },
    vectors: f.vectors.map((v) => ({
      id: v.id,
      drbgSeed: v.drbgSeed,
      zeta: v.zeta,
      rnd: v.rnd,
      publicKey: v.publicKey,
      secretKey: v.secretKey,
      reshapedPublicKey: v.reshapedPublicKey,
      message: v.message,
      signature: v.signature,
    })),
  };
  return JSON.stringify(obj, null, 2) + "\n";
}

function serializePrgFixture(f: PrgVectorsFile): string {
  const obj: Record<string, unknown> = {
    submoduleSha: f.submoduleSha,
    generatedAt: f.generatedAt,
    vectors: f.vectors.map((v) => {
      const out: Record<string, unknown> = {
        id: v.id,
        source: v.source,
      };
      if (v.description !== undefined) out["description"] = v.description;
      out["injects"] = v.injects;
      out["extracts"] = v.extracts;
      out["expected"] = v.expected;
      if (v.expected_slices !== undefined) {
        out["expected_slices"] = v.expected_slices;
      }
      return out;
    }),
  };
  return JSON.stringify(obj, null, 2) + "\n";
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface PythonKatResult {
  kind: "kat";
  count: number;
  zeta: string;
  rnd: string;
  reshapedPublicKey: string;
}

interface PythonPrgResult {
  kind: "prg";
  id: string;
  expected: string[];
}

/**
 * Parse `--scheme <name>` out of argv. Supported values:
 *   - "mldsa-eth" (default, backward-compatible with pre-Story-1-1 CLI)
 *   - "falcon-eth" (Story 1-1 — currently runs T0 PRE_G4_DRBG_PROBE only)
 *
 * Unrecognized schemes cause a non-zero exit with an operator-readable error.
 * Missing `--scheme` defaults to "mldsa-eth" so `npm run kat:regen` (without
 * flags) preserves its pre-Story-1-1 behavior byte-for-byte.
 */
type Scheme = "mldsa-eth" | "falcon-eth";

function parseSchemeArg(argv: readonly string[]): Scheme | "invalid" {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--scheme") {
      const val = argv[i + 1];
      if (val === "mldsa-eth" || val === "falcon-eth") return val;
      return "invalid";
    }
    if (argv[i]?.startsWith("--scheme=")) {
      const val = argv[i]!.slice("--scheme=".length);
      if (val === "mldsa-eth" || val === "falcon-eth") return val;
      return "invalid";
    }
  }
  return "mldsa-eth";
}

/**
 * Story 1-1 Task T0 CLI branch. Runs:
 *   (1) ETHFALCON preflight diagnostics (submodule init, pin, python, deps);
 *   (2) PRE_G4_DRBG_PROBE on vec 0;
 *   (3) exits 0 with a "T1 bulk write not yet implemented" notice.
 *
 * T1 and T2 will replace the early exit with the full vectors.json +
 * hashtopoint-vectors.json write path.
 */
function mainFalconEth(): number {
  if (!runEthfalconPreflightDiagnostics()) {
    return 1;
  }
  try {
    preG4DrbgProbe();
  } catch (err) {
    if (err instanceof FixtureGenError) {
      process.stderr.write(
        JSON.stringify({ code: err.code, message: err.message }) + "\n",
      );
      return 1;
    }
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      JSON.stringify({
        code: "PRE_G4_DRBG_PROBE_FAILED",
        message: `Unexpected probe error: ${message}`,
      }) + "\n",
    );
    return 1;
  }
  process.stdout.write(
    "T0 PRE_G4_DRBG_PROBE passed; T1 bulk write not yet implemented — exiting\n",
  );
  return 0;
}

function main(): number {
  const scheme = parseSchemeArg(process.argv.slice(2));
  if (scheme === "invalid") {
    process.stderr.write(
      JSON.stringify({
        code: "INVALID_SCHEME",
        message:
          "Unrecognized --scheme value. Supported: 'mldsa-eth' (default), 'falcon-eth'.",
      }) + "\n",
    );
    return 1;
  }
  if (scheme === "falcon-eth") {
    return mainFalconEth();
  }

  // Step 0: AC-U-2 pre-flight diagnostics (Task 4). Covers SUBMODULE_UNINIT,
  // SUBMODULE_PIN_MISMATCH, PYTHON_VERSION_MISMATCH, PYTHON_DEPS_MISSING.
  // On any failure, the NDJSON diagnostic has already been written to stderr;
  // we return 1 so the generation path does not run (no partial-write risk).
  if (!runPreflightDiagnostics()) {
    return 1;
  }

  // Step 1: read SHA + commit timestamp for fixture embedding. The
  // pin-vs-HEAD check is already enforced in step 0 above.
  const { currentHead, commitTimestamp } = readSubmoduleShas();
  const submoduleSha = currentHead;
  const generatedAt = new Date(commitTimestamp * 1000).toISOString();

  // Step 2: parse .rsp corpus.
  const rspRecords = parseRspFile();
  if (rspRecords.length !== 100) {
    throw new Error(
      `Expected exactly 100 .rsp records, got ${rspRecords.length}`,
    );
  }

  // Step 3: build the single Python batch payload.
  const batchPayload = {
    vectors: rspRecords.map((r) => ({
      count: r.count,
      seed: r.seed,
      pk: r.pk,
    })),
    prg_jobs: [
      // Layer-2 boundary jobs.
      ...PRG_LAYER2_JOBS.map((j) => ({
        id: j.id,
        injects: j.injectsHex,
        extracts: j.extracts,
      })),
      // Layer-1 full-stream fills for vectors 2 and 4 (the canonical Forge
      // test only documents partial outputs; we want complete expected[]).
      {
        id: "zhenfei-canonical-02-full",
        injects: [Buffer.from("test input", "ascii").toString("hex")],
        extracts: [64],
      },
      {
        id: "zhenfei-canonical-04-full",
        injects: [Buffer.from("test sequence", "ascii").toString("hex")],
        extracts: [80],
      },
    ],
  };

  // Step 4: spawn ONE python3 -c with the batch payload on stdin.
  const pyProc = spawnSync("python3", ["-c", PYTHON_BATCH], {
    cwd: REPO_ROOT,
    input: JSON.stringify(batchPayload),
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024, // 100 vectors × ~500 KB reshapedPk headroom
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (pyProc.status !== 0) {
    // Task 4 classifies this as PYTHON_DEPS_MISSING or PYTHON_VERSION_MISMATCH.
    process.stderr.write(
      `python3 batch failed (exit ${String(pyProc.status)}):\n${pyProc.stderr ?? ""}\n`,
    );
    return 1;
  }
  const pyOut = pyProc.stdout.trim();

  // Step 5: parse NDJSON stdout, partition by kind.
  const katByCount = new Map<number, PythonKatResult>();
  const prgById = new Map<string, PythonPrgResult>();
  for (const rawLine of pyOut.split("\n")) {
    const line = rawLine.trim();
    if (line === "") continue;
    const parsed = JSON.parse(line) as PythonKatResult | PythonPrgResult;
    if (parsed.kind === "kat") {
      katByCount.set(parsed.count, parsed);
    } else {
      prgById.set(parsed.id, parsed);
    }
  }
  if (katByCount.size !== 100) {
    throw new Error(
      `Python batch returned ${katByCount.size} KAT results, expected 100`,
    );
  }

  // Step 6: merge Python output + .rsp-derived fields → DD-7 KatVector[].
  const katVectors: KatVector[] = rspRecords.map((r) => {
    const py = katByCount.get(r.count);
    if (py === undefined) {
      throw new Error(`Python batch missing KAT result for count=${r.count}`);
    }
    // sig = sm[:-mlen]: sm is hex (smlen*2 chars), mlen is a byte count.
    const sig = r.sm.slice(0, r.sm.length - r.mlen * 2);
    const idNum = String(r.count + 1).padStart(3, "0");
    return {
      id: `mldsa-eth-vec-${idNum}`,
      drbgSeed: `0x${r.seed}`,
      zeta: `0x${py.zeta}`,
      rnd: `0x${py.rnd}`,
      publicKey: `0x${r.pk}`,
      secretKey: `0x${r.sk}`,
      reshapedPublicKey: `0x${py.reshapedPublicKey}`,
      message: `0x${r.msg}`,
      signature: `0x${sig}`,
    };
  });

  const katFixture: KatVectorsFile = {
    scheme: "mldsa-eth",
    params: "dilithium2-keccak",
    submoduleSha,
    generatedAt,
    source: {
      rspFile: "ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp",
      drbgDerivation:
        "AES256_CTR_DRBG(drbgSeed): ζ=first random_bytes(32) call, rnd=second random_bytes(32) call (A-005 — state-advanced; not bytes[32:64] of a single 64-byte call)",
      ctx: "0x",
    },
    vectors: katVectors,
  };

  // Step 7: assemble PRG fixture (Layer 1 embedded + Layer 2 from Python).
  const layer1 = layer1ZhenfeiVectors();
  // Patch vectors 2 and 4's full expected[] from Python.
  const v2Full = prgById.get("zhenfei-canonical-02-full");
  const v4Full = prgById.get("zhenfei-canonical-04-full");
  if (v2Full === undefined || v2Full.expected[0] === undefined) {
    throw new Error(
      "Python batch did not return 'zhenfei-canonical-02-full'",
    );
  }
  if (v4Full === undefined || v4Full.expected[0] === undefined) {
    throw new Error(
      "Python batch did not return 'zhenfei-canonical-04-full'",
    );
  }
  const v2 = layer1[1];
  const v4 = layer1[3];
  if (v2 === undefined || v4 === undefined) {
    throw new Error("Layer 1 canonical vectors 2 or 4 missing from table");
  }
  v2.expected = [`0x${v2Full.expected[0]}`];
  v4.expected = [`0x${v4Full.expected[0]}`];

  const layer2: PrgVector[] = PRG_LAYER2_JOBS.map((job) => {
    const py = prgById.get(job.id);
    if (py === undefined) {
      throw new Error(`Python batch missing PRG result for id=${job.id}`);
    }
    return {
      id: job.id,
      source: "python-ref-extended",
      description: job.description,
      injects: job.injectsHex.map((h) => `0x${h}`),
      extracts: job.extracts,
      expected: py.expected.map((h) => `0x${h}`),
    };
  });

  const prgFixture: PrgVectorsFile = {
    submoduleSha,
    generatedAt,
    vectors: [...layer1, ...layer2],
  };

  // Step 8: write both files with canonical serialization.
  mkdirSync(path.dirname(ML_DSA_FIXTURE), { recursive: true });
  mkdirSync(path.dirname(PRG_FIXTURE), { recursive: true });
  writeFileSync(ML_DSA_FIXTURE, serializeKatFixture(katFixture), "utf8");
  writeFileSync(PRG_FIXTURE, serializePrgFixture(prgFixture), "utf8");

  process.stdout.write(
    `Wrote ${katVectors.length} ML-DSA-ETH vectors → ${path.relative(REPO_ROOT, ML_DSA_FIXTURE)}\n` +
      `Wrote ${prgFixture.vectors.length} PRG vectors (${layer1.length} Layer-1 + ${layer2.length} Layer-2) → ${path.relative(REPO_ROOT, PRG_FIXTURE)}\n`,
  );
  return 0;
}

process.exitCode = main();
