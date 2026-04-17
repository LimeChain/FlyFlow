/**
 * Unit tests for the KAT loader (Story 1, Task 2 — exercises AC-1-8).
 *
 * Real fixture JSON files are produced by Task 3. These tests instead point
 * the loader at synthetic temp-dir fixtures via the `KAT_FIXTURE_DIR`
 * env-var hook exported by `index.ts`, so loader logic is exercisable
 * before the CLI lands.
 *
 * The module's top-of-file `assertSubmoduleShaMatches()` call is NOT
 * neutralized here — these tests run in the real repo where the pinned
 * ETHDILITHIUM SHA matches current HEAD (ci + local both), so module import
 * succeeds. Drift-at-import is validated manually per Gate 5 Criterion 8.
 *
 * Framework: node:test + node:assert/strict (matches `test/signers/ecdsa.test.ts`).
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  KatFixtureError,
  loadKatVectors,
  loadPrgVectors,
} from "./index.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), "..", "..", "..");

/** Resolve the real submodule HEAD once for happy-path fixtures. */
function currentSubmoduleHead(): string {
  return execFileSync(
    "git",
    ["-C", path.join(REPO_ROOT, "ETHDILITHIUM"), "rev-parse", "HEAD"],
    { encoding: "utf8" },
  ).trim();
}

const BOGUS_SHA = "0".repeat(40);

/** Run `fn` and return the thrown error (fails if nothing thrown). */
function captureThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  assert.fail("expected function to throw");
}

describe("KAT loader — SHA guard + schema + missing fixture", () => {
  let tmpRoot: string;
  const savedEnv = process.env["KAT_FIXTURE_DIR"];

  before(() => {
    tmpRoot = mkdtempSync(path.join(tmpdir(), "kat-loader-test-"));
  });

  after(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
    if (savedEnv === undefined) {
      delete process.env["KAT_FIXTURE_DIR"];
    } else {
      process.env["KAT_FIXTURE_DIR"] = savedEnv;
    }
  });

  beforeEach(() => {
    // Clean slate per test — remove any stale subdirs from previous cases.
    for (const sub of ["mldsa-eth", "keccak-prg"]) {
      rmSync(path.join(tmpRoot, sub), { recursive: true, force: true });
    }
  });

  afterEach(() => {
    delete process.env["KAT_FIXTURE_DIR"];
  });

  it("throws KAT_SUBMODULE_SHA_MISMATCH when fixture SHA differs from current HEAD", () => {
    const prgDir = path.join(tmpRoot, "keccak-prg");
    mkdirSync(prgDir, { recursive: true });
    writeFileSync(
      path.join(prgDir, "vectors.json"),
      JSON.stringify({
        submoduleSha: BOGUS_SHA,
        generatedAt: "2026-04-17T00:00:00Z",
        vectors: [],
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadPrgVectors());
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_SUBMODULE_SHA_MISMATCH");
    assert.match(err.message, new RegExp(BOGUS_SHA));
    assert.match(err.message, new RegExp(currentSubmoduleHead()));
    assert.match(err.message, /generate-kat-fixtures\.ts/);
  });

  it("throws KAT_SCHEMA_MISMATCH when top-level 'vectors' key is missing", () => {
    const mldsaDir = path.join(tmpRoot, "mldsa-eth");
    mkdirSync(mldsaDir, { recursive: true });
    writeFileSync(
      path.join(mldsaDir, "vectors.json"),
      JSON.stringify({
        scheme: "mldsa-eth",
        params: "dilithium2-keccak",
        submoduleSha: currentSubmoduleHead(),
        generatedAt: "2026-04-17T00:00:00Z",
        source: { rspFile: "x", drbgDerivation: "y", ctx: "0x" },
        // NOTE: 'vectors' intentionally omitted.
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadKatVectors("mldsa-eth"));
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_SCHEMA_MISMATCH");
    assert.match(err.message, /vectors/);
  });

  it("throws KAT_FIXTURE_MISSING when the fixture file does not exist", () => {
    // No mldsa-eth/vectors.json written — directory empty.
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadKatVectors("mldsa-eth"));
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_FIXTURE_MISSING");
    assert.match(err.message, /generate-kat-fixtures\.ts/);
  });

  it("returns typed vectors on the happy path with a SHA-matched fixture", () => {
    const prgDir = path.join(tmpRoot, "keccak-prg");
    mkdirSync(prgDir, { recursive: true });
    const sampleVector = {
      id: "prg-vec-001",
      source: "zhenfei-canonical",
      injects: ["0x74657374"],
      extracts: [32],
      expected: [
        "0x5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601",
      ],
      description: "sample",
    };
    writeFileSync(
      path.join(prgDir, "vectors.json"),
      JSON.stringify({
        submoduleSha: currentSubmoduleHead(),
        generatedAt: "2026-04-17T00:00:00Z",
        vectors: [sampleVector],
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const vectors = loadPrgVectors();
    assert.ok(Array.isArray(vectors), "expected an array");
    assert.equal(vectors.length, 1);
    const v = vectors[0];
    assert.ok(v !== undefined, "expected vector at index 0");
    assert.equal(v.id, "prg-vec-001");
    assert.equal(v.source, "zhenfei-canonical");
    assert.deepEqual(v.injects, ["0x74657374"]);
    assert.deepEqual(v.extracts, [32]);
    assert.equal(v.expected.length, 1);
  });
});
