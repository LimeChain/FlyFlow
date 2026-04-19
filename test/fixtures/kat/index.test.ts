/**
 * Unit tests for the KAT loader.
 *
 * Originally landed by mldsa-eth Story 1 Task 2 (AC-1-8). Extended by
 * falcon-eth Story 1-1 Task T4 to cover the multi-submodule refactor:
 *   - AC-4 schema rejection of fixtures missing / with unknown
 *     `submoduleSource`.
 *   - AC-5 per-submodule SHA-drift detection for both ethdilithium and
 *     ethfalcon paths.
 *   - AC-6 compile-time discriminated overload (the `// @ts-expect-error`
 *     directives below ARE the assertions — `tsc` fails the build if the
 *     annotated line unexpectedly compiles).
 *   - Happy-path coverage for the new `loadKatVectors("falcon-eth")` and
 *     `loadHashToPointVectors()` loaders against the real fixture corpus.
 *
 * Synthetic-fixture tests point the loader at a tmp-dir root via the
 * `KAT_FIXTURE_DIR` env-var hook exported by `index.ts`; real-fixture
 * tests clear the override and exercise the repo's committed corpus.
 *
 * The module's top-of-file `assertSubmoduleShaMatches("ethdilithium")` call
 * is NOT neutralized here — these tests run in the real repo where the
 * pinned ETHDILITHIUM SHA matches current HEAD (ci + local both), so module
 * import succeeds. Drift-at-import is validated manually per Gate 5
 * Criterion 8.
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
  type FalconKatVector,
  type HashToPointVector,
  type MlDsaEthKatVector,
  KatFixtureError,
  loadHashToPointVectors,
  loadKatVectors,
  loadPrgVectors,
} from "./index.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), "..", "..", "..");

/** Resolve the real ETHDILITHIUM submodule HEAD for happy-path fixtures. */
function currentSubmoduleHead(): string {
  return execFileSync(
    "git",
    ["-C", path.join(REPO_ROOT, "ETHDILITHIUM"), "rev-parse", "HEAD"],
    { encoding: "utf8" },
  ).trim();
}

/** Resolve the real ETHFALCON submodule HEAD for happy-path fixtures. */
function currentEthfalconHead(): string {
  return execFileSync(
    "git",
    ["-C", path.join(REPO_ROOT, "ETHFALCON"), "rev-parse", "HEAD"],
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
    for (const sub of ["mldsa-eth", "falcon-eth", "keccak-prg"]) {
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
    assert.match(err.message, /kat:regen/);
  });

  it("throws KAT_SCHEMA_MISMATCH when top-level 'vectors' key is missing", () => {
    const mldsaDir = path.join(tmpRoot, "mldsa-eth");
    mkdirSync(mldsaDir, { recursive: true });
    writeFileSync(
      path.join(mldsaDir, "vectors.json"),
      JSON.stringify({
        scheme: "mldsa-eth",
        params: "dilithium2-keccak",
        submoduleSource: "ethdilithium",
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

// ---------------------------------------------------------------------------
// falcon-eth Story 1-1 Task T4 — AC-4, AC-5, AC-6, and happy-path coverage
// for the new loaders.
// ---------------------------------------------------------------------------

describe("KAT loader — multi-submodule discriminator (AC-4)", () => {
  let tmpRoot: string;
  const savedEnv = process.env["KAT_FIXTURE_DIR"];

  before(() => {
    tmpRoot = mkdtempSync(path.join(tmpdir(), "kat-loader-submod-test-"));
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
    for (const sub of ["mldsa-eth", "falcon-eth"]) {
      rmSync(path.join(tmpRoot, sub), { recursive: true, force: true });
    }
  });

  afterEach(() => {
    delete process.env["KAT_FIXTURE_DIR"];
  });

  it("throws KAT_SCHEMA_MISMATCH when 'submoduleSource' key is missing (AC-4 part 1)", () => {
    const mldsaDir = path.join(tmpRoot, "mldsa-eth");
    mkdirSync(mldsaDir, { recursive: true });
    writeFileSync(
      path.join(mldsaDir, "vectors.json"),
      JSON.stringify({
        scheme: "mldsa-eth",
        params: "dilithium2-keccak",
        // NOTE: 'submoduleSource' intentionally omitted.
        submoduleSha: currentSubmoduleHead(),
        generatedAt: "2026-04-17T00:00:00Z",
        source: { rspFile: "x", drbgDerivation: "y", ctx: "0x" },
        vectors: [],
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadKatVectors("mldsa-eth"));
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_SCHEMA_MISMATCH");
    assert.match(err.message, /submoduleSource/);
  });

  it("throws KAT_UNKNOWN_SUBMODULE_SOURCE when 'submoduleSource' is 'unknown' (AC-4 part 2)", () => {
    const mldsaDir = path.join(tmpRoot, "mldsa-eth");
    mkdirSync(mldsaDir, { recursive: true });
    writeFileSync(
      path.join(mldsaDir, "vectors.json"),
      JSON.stringify({
        scheme: "mldsa-eth",
        params: "dilithium2-keccak",
        submoduleSource: "unknown",
        submoduleSha: currentSubmoduleHead(),
        generatedAt: "2026-04-17T00:00:00Z",
        source: { rspFile: "x", drbgDerivation: "y", ctx: "0x" },
        vectors: [],
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadKatVectors("mldsa-eth"));
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_UNKNOWN_SUBMODULE_SOURCE");
    assert.match(err.message, /unknown/);
    assert.match(err.message, /ethdilithium/);
    assert.match(err.message, /ethfalcon/);
  });

  it("throws KAT_UNKNOWN_SUBMODULE_SOURCE for non-string submoduleSource is actually KAT_SCHEMA_MISMATCH", () => {
    // Defensive: a numeric 42 is 'wrong type' (SCHEMA_MISMATCH), NOT 'unknown
    // value' — the type-check fires before the enum-membership check.
    const mldsaDir = path.join(tmpRoot, "mldsa-eth");
    mkdirSync(mldsaDir, { recursive: true });
    writeFileSync(
      path.join(mldsaDir, "vectors.json"),
      JSON.stringify({
        scheme: "mldsa-eth",
        params: "dilithium2-keccak",
        submoduleSource: 42,
        submoduleSha: currentSubmoduleHead(),
        generatedAt: "2026-04-17T00:00:00Z",
        source: { rspFile: "x", drbgDerivation: "y", ctx: "0x" },
        vectors: [],
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadKatVectors("mldsa-eth"));
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_SCHEMA_MISMATCH");
    assert.match(err.message, /submoduleSource/);
  });
});

describe("KAT loader — per-submodule SHA-drift guard (AC-5)", () => {
  let tmpRoot: string;
  const savedEnv = process.env["KAT_FIXTURE_DIR"];

  before(() => {
    tmpRoot = mkdtempSync(path.join(tmpdir(), "kat-loader-drift-test-"));
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
    for (const sub of ["mldsa-eth", "falcon-eth"]) {
      rmSync(path.join(tmpRoot, sub), { recursive: true, force: true });
    }
  });

  afterEach(() => {
    delete process.env["KAT_FIXTURE_DIR"];
  });

  it("throws KAT_SUBMODULE_SHA_MISMATCH for stale ethfalcon pin with falcon regen command", () => {
    const falconDir = path.join(tmpRoot, "falcon-eth");
    mkdirSync(falconDir, { recursive: true });
    writeFileSync(
      path.join(falconDir, "vectors.json"),
      JSON.stringify({
        scheme: "falcon-eth",
        params: "falcon-512-keccak",
        submoduleSource: "ethfalcon",
        submoduleSha: BOGUS_SHA,
        generatedAt: "2026-04-17T00:00:00Z",
        source: { rspFile: "x", drbgDerivation: "y", ctx: "0x" },
        vectors: [],
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadKatVectors("falcon-eth"));
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_SUBMODULE_SHA_MISMATCH");
    assert.match(err.message, new RegExp(BOGUS_SHA));
    assert.match(err.message, new RegExp(currentEthfalconHead()));
    assert.match(err.message, /npm run kat:regen -- --scheme falcon-eth/);
    assert.match(err.message, /ETHFALCON/);
  });

  it("throws KAT_SUBMODULE_SHA_MISMATCH for stale ethdilithium pin with mldsa regen command", () => {
    const mldsaDir = path.join(tmpRoot, "mldsa-eth");
    mkdirSync(mldsaDir, { recursive: true });
    writeFileSync(
      path.join(mldsaDir, "vectors.json"),
      JSON.stringify({
        scheme: "mldsa-eth",
        params: "dilithium2-keccak",
        submoduleSource: "ethdilithium",
        submoduleSha: BOGUS_SHA,
        generatedAt: "2026-04-17T00:00:00Z",
        source: { rspFile: "x", drbgDerivation: "y", ctx: "0x" },
        vectors: [],
      }),
    );
    process.env["KAT_FIXTURE_DIR"] = tmpRoot;

    const err = captureThrow(() => loadKatVectors("mldsa-eth"));
    assert.ok(err instanceof KatFixtureError, "expected KatFixtureError");
    assert.equal(err.code, "KAT_SUBMODULE_SHA_MISMATCH");
    assert.match(err.message, new RegExp(BOGUS_SHA));
    assert.match(err.message, new RegExp(currentSubmoduleHead()));
    assert.match(err.message, /npm run kat:regen -- --scheme mldsa-eth/);
    assert.match(err.message, /ETHDILITHIUM/);
  });
});

describe("KAT loader — real-fixture happy paths (AC-1, AC-2)", () => {
  // These tests exercise the committed corpus under the canonical fixture
  // path — no KAT_FIXTURE_DIR override. They are the real-path counterpart
  // to the override-based tests above (.claude/rules/retrospect/universal.md
  // §"Override-based tests need a real-path counterpart").

  it("loads 100 falcon-eth KAT vectors with correct field shapes", () => {
    const vectors = loadKatVectors("falcon-eth");
    assert.equal(vectors.length, 100, "expected exactly 100 falcon-eth vectors");

    const first = vectors[0];
    assert.ok(first !== undefined, "expected vector at index 0");
    assert.equal(first.id, "vec-000");
    // 48 B drbgSeed = 0x + 96 hex chars.
    assert.equal(first.drbgSeed.length, 2 + 48 * 2);
    // 897 B raw pk = 0x + 1794 hex chars.
    assert.equal(first.publicKey.length, 2 + 897 * 2);
    // 1064 B signature = 0x + 2128 hex chars.
    assert.equal(first.signature.length, 2 + 1064 * 2);
    // reshapedPublicKey is abi.encode(uint256[32]) = 32 * 32 = 1024 B.
    assert.equal(first.reshapedPublicKey.length, 2 + 1024 * 2);

    // Every vector has a hex prefix and the right shape.
    for (const v of vectors) {
      assert.ok(v.id.startsWith("vec-"), `vector id must start with 'vec-': ${v.id}`);
      assert.ok(v.drbgSeed.startsWith("0x"));
      assert.ok(v.publicKey.startsWith("0x"));
      assert.ok(v.secretKey.startsWith("0x"));
      assert.ok(v.reshapedPublicKey.startsWith("0x"));
      assert.ok(v.message.startsWith("0x"));
      assert.ok(v.signature.startsWith("0x"));
      assert.equal(v.signature.length, 2 + 1064 * 2);
      assert.equal(v.publicKey.length, 2 + 897 * 2);
    }
  });

  it("loads 100 mldsa-eth KAT vectors (ensures T4 backfill left the corpus readable)", () => {
    const vectors = loadKatVectors("mldsa-eth");
    assert.equal(vectors.length, 100);
    const first = vectors[0];
    assert.ok(first !== undefined);
    // 1312 B pk = 0x + 2624 hex chars.
    assert.equal(first.publicKey.length, 2 + 1312 * 2);
    // 2560 B sk.
    assert.equal(first.secretKey.length, 2 + 2560 * 2);
    // 2420 B signature.
    assert.equal(first.signature.length, 2 + 2420 * 2);
  });

  it("loadHashToPointVectors returns 8 vectors with valid shapes (AC-2 consumer)", () => {
    const vectors = loadHashToPointVectors();
    assert.equal(vectors.length, 8, "expected 8 hashtopoint vectors");

    for (const v of vectors) {
      assert.ok(v.id.startsWith("vec-"));
      // 40 B salt = 0x + 80 hex chars.
      assert.equal(v.salt.length, 2 + 40 * 2);
      assert.ok(v.message.startsWith("0x"));
      assert.equal(v.expectedHash.length, 512, `expectedHash must be 512 coeffs`);
      for (const c of v.expectedHash) {
        assert.ok(Number.isInteger(c), `coefficient must be an integer: ${c}`);
        assert.ok(c >= 0 && c < 12289, `coefficient out of range: ${c}`);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// AC-6 — compile-time discriminated overload. These `// @ts-expect-error`
// directives ARE the assertions: tsc fails the build if the annotated line
// unexpectedly COMPILES (e.g., if we collapsed the overload back into a
// single `loadKatVectors(scheme: string): unknown[]`). The block also
// double-serves as runtime no-op sanity (nothing is called — these are
// purely types).
// ---------------------------------------------------------------------------

describe("KAT loader — discriminated overload (AC-6, compile-time)", () => {
  it("narrows to MlDsaEthKatVector for scheme='mldsa-eth' and FalconKatVector for 'falcon-eth'", () => {
    // Type-level assertion: these assignments only compile if the overload
    // narrows correctly. Guard them behind `false` so the body never runs
    // — we don't want to hit the filesystem here (the real-path happy-path
    // tests above cover the runtime behaviour).
    if (false as boolean) {
      const mldsa: MlDsaEthKatVector[] = loadKatVectors("mldsa-eth");
      const falcon: FalconKatVector[] = loadKatVectors("falcon-eth");
      const htp: HashToPointVector[] = loadHashToPointVectors();

      // Accessing a field that exists on the narrowed type must compile.
      void mldsa[0]?.zeta; // MlDsaEthKatVector.zeta exists.
      void falcon[0]?.drbgSeed; // FalconKatVector.drbgSeed exists.
      void htp[0]?.expectedHash;

      // The following lines are the AC-6 compile-time assertion. Each
      // `// @ts-expect-error` directive expects the NEXT line to produce a
      // tsc error. If the discriminated overload ever regresses (e.g., a
      // loose `string` parameter replacing the literal-union overload), the
      // directives themselves will fail with "Unused '@ts-expect-error'
      // directive", breaking the build.

      // @ts-expect-error — `cTilde` is ML-DSA-only; a falcon-eth vector has no such field.
      void falcon[0]?.cTilde;

      // @ts-expect-error — `zeta` is ML-DSA-only; FalconKatVector has no 'zeta'.
      void falcon[0]?.zeta;

      // @ts-expect-error — `salt` is HashToPointVector-only; FalconKatVector's
      // salt is embedded inside `signature`, not a top-level field.
      void falcon[0]?.salt;

      // @ts-expect-error — `rnd` is ML-DSA-only.
      void falcon[0]?.rnd;

      // @ts-expect-error — HashToPointVector has no `publicKey` field.
      void htp[0]?.publicKey;
    }

    // Trivial runtime assertion so node:test registers this as a passing
    // test (the real check is the tsc build above).
    assert.equal(typeof loadKatVectors, "function");
    assert.equal(typeof loadHashToPointVectors, "function");
  });
});
