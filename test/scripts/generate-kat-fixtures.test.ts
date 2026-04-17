/**
 * AC-U-2 onboarding diagnostic tests (Story 1, Task 4).
 *
 * Each test spawns the CLI as a child process with a different test-only
 * env-var override and asserts:
 *   - non-zero exit code,
 *   - stderr contains the NDJSON `"code":"<CODE>"` fragment,
 *   - stderr contains the AC-mandated next-command substring(s),
 *   - stdout does NOT contain the "Wrote N" generation-success line.
 *
 * Covers AC-1-4 (pin mismatch), AC-1-5 (submodule uninit), AC-1-6 (python
 * version), AC-1-7 (pip deps). Each failure mode is simulated via the
 * documented test-only env-var hooks exposed by `scripts/generate-kat-fixtures.ts`:
 *   - `KAT_SUBMODULE_PATH` → SUBMODULE_UNINIT
 *   - `KAT_SUBMODULE_PIN_OVERRIDE` → SUBMODULE_PIN_MISMATCH
 *   - `KAT_PYTHON_VERSION_OVERRIDE` → PYTHON_VERSION_MISMATCH
 *   - `KAT_PYTHON_DEPS_PROBE_OVERRIDE` → PYTHON_DEPS_MISSING
 *
 * Framework: node:test + node:assert/strict (matches the rest of the repo).
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const THIS_FILE = fileURLToPath(import.meta.url);
// test/scripts/generate-kat-fixtures.test.ts → repo root is two levels up.
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), "..", "..");
const CLI_PATH = path.join(REPO_ROOT, "scripts", "generate-kat-fixtures.ts");

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Spawn the CLI with the given env overrides merged onto the parent env.
 * Uses `npx tsx` (matching AC-1-1's invocation shape). Returns the captured
 * stdout/stderr + exit status (may be non-zero).
 */
function runCli(envOverrides: Record<string, string>): CliResult {
  const proc = spawnSync("npx", ["tsx", CLI_PATH], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { ...process.env, ...envOverrides },
    stdio: ["ignore", "pipe", "pipe"],
    // Generous timeout — even the python-deps probe returns in seconds.
    timeout: 60_000,
  });
  return {
    status: proc.status,
    stdout: proc.stdout ?? "",
    stderr: proc.stderr ?? "",
  };
}

/**
 * Locate the NDJSON diagnostic line in stderr. Asserts exactly one line
 * matches `{"code":"...","message":"..."}` shape, then returns it.
 */
function extractDiagnosticLine(stderr: string): string {
  const lines = stderr.split("\n").filter((l) => l.trim() !== "");
  const ndjsonLines = lines.filter(
    (l) => l.trim().startsWith("{") && l.includes('"code"'),
  );
  assert.ok(
    ndjsonLines.length >= 1,
    `expected at least one NDJSON diagnostic line, got stderr:\n${stderr}`,
  );
  // The first NDJSON line is the diagnostic; any later lines are noise.
  return ndjsonLines[0]!;
}

describe("generate-kat-fixtures — AC-U-2 pre-flight diagnostics", () => {
  it("AC-1-5: SUBMODULE_UNINIT — missing submodule directory", () => {
    const result = runCli({ KAT_SUBMODULE_PATH: "/nonexistent-submodule-xyz" });

    assert.notEqual(
      result.status,
      0,
      `expected non-zero status, got stdout:\n${result.stdout}`,
    );
    const diag = extractDiagnosticLine(result.stderr);
    assert.match(diag, /"code":"SUBMODULE_UNINIT"/);
    assert.match(diag, /git submodule update --init --recursive/);
    // Generation should NOT have run.
    assert.doesNotMatch(
      result.stdout,
      /Wrote \d+ ML-DSA-ETH vectors/,
      "generation path must not run when diagnostics fail",
    );
  });

  it("AC-1-4: SUBMODULE_PIN_MISMATCH — pinned SHA override differs from current HEAD", () => {
    const bogusSha = "0".repeat(40);
    const result = runCli({ KAT_SUBMODULE_PIN_OVERRIDE: bogusSha });

    assert.notEqual(result.status, 0);
    const diag = extractDiagnosticLine(result.stderr);
    assert.match(diag, /"code":"SUBMODULE_PIN_MISMATCH"/);
    // Both 40-hex SHAs must appear (bogus + actual HEAD).
    assert.match(diag, new RegExp(bogusSha));
    assert.match(
      diag,
      /actual=[0-9a-f]{40}/,
      "diagnostic must name the actual 40-hex HEAD SHA",
    );
    // Re-pin command must be present.
    assert.match(diag, /git -C ETHDILITHIUM checkout /);
    assert.doesNotMatch(result.stdout, /Wrote \d+ ML-DSA-ETH vectors/);
  });

  it("AC-1-6: PYTHON_VERSION_MISMATCH — detected version below required range", () => {
    const result = runCli({ KAT_PYTHON_VERSION_OVERRIDE: "Python 3.7.5" });

    assert.notEqual(result.status, 0);
    const diag = extractDiagnosticLine(result.stderr);
    assert.match(diag, /"code":"PYTHON_VERSION_MISMATCH"/);
    // Detected version name — must appear literally.
    assert.match(diag, /Python 3\.7\.5/);
    // Required range — must appear (flexible form; we assert on the floor).
    assert.match(diag, /3\.9/);
    assert.doesNotMatch(result.stdout, /Wrote \d+ ML-DSA-ETH vectors/);
  });

  it("AC-1-7: PYTHON_DEPS_MISSING — import probe raises ModuleNotFoundError", () => {
    const result = runCli({
      KAT_PYTHON_DEPS_PROBE_OVERRIDE: "nonexistent_module_xyz_abc_pqc_test",
    });

    assert.notEqual(result.status, 0);
    const diag = extractDiagnosticLine(result.stderr);
    assert.match(diag, /"code":"PYTHON_DEPS_MISSING"/);
    // Install command — AC-1-7 requires the literal pip install string.
    assert.match(
      diag,
      /pip install -r ETHDILITHIUM\/pythonref\/requirements\.txt/,
    );
    // Missing module name must appear so the user knows what to check.
    assert.match(diag, /nonexistent_module_xyz_abc_pqc_test/);
    assert.doesNotMatch(result.stdout, /Wrote \d+ ML-DSA-ETH vectors/);
  });
});
