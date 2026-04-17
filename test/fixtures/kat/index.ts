/**
 * KAT fixture loader + error class + SHA-drift guard (Story 1, Task 2).
 *
 * Enforces AC-1-8: importing this module when the committed `submoduleSha`
 * in either fixture file differs from the current ETHDILITHIUM submodule
 * HEAD throws `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"`
 * at module-evaluation time (not lazily inside loader calls).
 *
 * Downstream consumers (Stories 2-5) import only the named loaders:
 *   import { loadPrgVectors, loadKatVectors } from "../fixtures/kat/index.js";
 *
 * SHA-guard mechanism (per architecture §"KAT loader"):
 *   - pinned SHA:  `git submodule status ETHDILITHIUM | awk '{print $1}'`
 *     (strip leading `+`/`-` status prefix) — the pin recorded in the
 *     parent tree's gitlink.
 *   - current HEAD: `git -C ETHDILITHIUM rev-parse HEAD`.
 *   Commands are executed via `execFileSync` (argv form — no shell) from
 *   the repository root. Result is cached in a module-level `let` so the
 *   probe runs once per process regardless of how many fixture files are
 *   loaded. The top-level `assertSubmoduleShaMatches()` call below runs
 *   at import time.
 *
 * Path resolution: fixture JSON files live at paths relative to the repo
 * root (`test/fixtures/kat/...`). We resolve via `import.meta.url` (this
 * file is `test/fixtures/kat/index.ts`, so repo root is three levels up).
 *
 * Test-only hook: `process.env.KAT_FIXTURE_DIR`, if set, overrides the
 * fixture directory root. Used by the colocated unit tests to point the
 * loader at a temp directory with synthetic fixtures; production callers
 * never set this.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type KatFixtureErrorCode =
  | "KAT_SCHEMA_MISMATCH"
  | "KAT_SUBMODULE_SHA_MISMATCH"
  | "KAT_FIXTURE_MISSING"
  | "KAT_GIT_PROBE_FAILED";

/**
 * Structured error thrown by the KAT loader. Consumers discriminate on
 * `code` (not message text) — matches the established `readonly code`
 * pattern in `test/signers/errors.ts`.
 */
export class KatFixtureError extends Error {
  readonly code: KatFixtureErrorCode;

  constructor(
    message: string,
    code: KatFixtureErrorCode,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "KatFixtureError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Type schemas — mirror DD-7 (ML-DSA KAT) and DD-11 (PRG KAT) from the story.
// ---------------------------------------------------------------------------

/** One PRG KAT vector (DD-11). */
export interface PrgVector {
  id: string;
  source: "zhenfei-canonical" | "python-ref-extended";
  /** Bytes absorbed (in order) before `flip()`, each `"0x..."` hex. */
  injects: string[];
  /** One entry per `extract(N)` call in sequence — byte-count per call. */
  extracts: number[];
  /** Aligned to `extracts[]` — the raw concatenated output per extract. */
  expected: string[];
  /** Optional block-aligned slices (e.g., PRG vector 4). */
  expected_slices?: Array<{ from: number; to: number; value: string }>;
  description?: string;
}

/** One ML-DSA-ETH KAT vector (DD-7, eight load-bearing fields). */
export interface KatVector {
  id: string;
  /** 48 B hex — audit trail; JS never consumes. */
  drbgSeed: string;
  /** 32 B hex — G1 input (CTR-DRBG bytes [0:32]). */
  zeta: string;
  /** 32 B hex — G2 input (CTR-DRBG bytes [32:64]). */
  rnd: string;
  /** 1312 B hex — raw Dilithium2 pk (G1 expected / G3 input). */
  publicKey: string;
  /** 2560 B hex — raw Dilithium2 sk (G1 expected / G2 input). */
  secretKey: string;
  /** Variable — ABI-encoded (bytes,bytes32,bytes) tuple (G3 expected / G4 input). */
  reshapedPublicKey: string;
  /** Variable hex — G2 input. */
  message: string;
  /** 2420 B hex — cTilde‖z‖h (32+2304+84) (G2 expected / G4 input). */
  signature: string;
}

/** Top-level PRG fixture file shape. */
export interface PrgVectorsFile {
  submoduleSha: string;
  /** ISO 8601 timestamp. */
  generatedAt: string;
  vectors: PrgVector[];
}

/** Top-level ML-DSA-ETH fixture file shape. */
export interface KatVectorsFile {
  scheme: "mldsa-eth";
  params: "dilithium2-keccak";
  submoduleSha: string;
  /** ISO 8601 timestamp. */
  generatedAt: string;
  source: {
    rspFile: string;
    drbgDerivation: string;
    ctx: "0x";
  };
  vectors: KatVector[];
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

const THIS_FILE = fileURLToPath(import.meta.url);
// test/fixtures/kat/index.ts → repo root is three levels up.
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), "..", "..", "..");

/**
 * Resolve the root directory for fixture files. Defaults to
 * `<repo-root>/test/fixtures/kat`; overridable via
 * `process.env.KAT_FIXTURE_DIR` for tests only.
 */
function fixtureDir(): string {
  const override = process.env["KAT_FIXTURE_DIR"];
  if (override !== undefined && override !== "") return override;
  return path.join(REPO_ROOT, "test", "fixtures", "kat");
}

// ---------------------------------------------------------------------------
// Submodule SHA probe (cached)
// ---------------------------------------------------------------------------

interface ShaProbeResult {
  pinnedSha: string;
  currentHead: string;
}

let cachedProbe: ShaProbeResult | undefined;

function probeSubmoduleShas(): ShaProbeResult {
  if (cachedProbe !== undefined) return cachedProbe;

  // Step 1: current submodule HEAD.
  let currentHead: string;
  try {
    const out = execFileSync(
      "git",
      ["-C", path.join(REPO_ROOT, "ETHDILITHIUM"), "rev-parse", "HEAD"],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    currentHead = out.trim();
  } catch (err) {
    throw new KatFixtureError(
      `Failed to probe ETHDILITHIUM HEAD via 'git -C ETHDILITHIUM rev-parse HEAD'. ` +
        `Is the submodule initialized? Try: git submodule update --init --recursive`,
      "KAT_GIT_PROBE_FAILED",
      { cause: err },
    );
  }

  // Step 2: pinned SHA from parent-tree gitlink (git submodule status).
  // Output format: " <sha> ETHDILITHIUM (heads/main)" with a leading
  // status character (space = clean, `+` = HEAD differs, `-` = not init'd,
  // `U` = merge conflicts). Strip the status prefix, then take field 1.
  let pinnedSha: string;
  try {
    const out = execFileSync(
      "git",
      ["submodule", "status", "ETHDILITHIUM"],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    const line = out.split("\n")[0] ?? "";
    // Strip optional leading status char (`+`, `-`, `U`, or space).
    const stripped = line.replace(/^[+\-U ]/, "");
    const first = stripped.split(/\s+/)[0] ?? "";
    pinnedSha = first;
  } catch (err) {
    throw new KatFixtureError(
      `Failed to probe pinned ETHDILITHIUM SHA via 'git submodule status ETHDILITHIUM'.`,
      "KAT_GIT_PROBE_FAILED",
      { cause: err },
    );
  }

  cachedProbe = { pinnedSha, currentHead };
  return cachedProbe;
}

/**
 * Throw `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"` if the
 * pinned SHA (parent-tree gitlink) differs from current submodule HEAD.
 *
 * Exported for direct testing; invoked eagerly at module-evaluation time
 * (bottom of this file) and defensively from each loader.
 */
export function assertSubmoduleShaMatches(): void {
  const { pinnedSha, currentHead } = probeSubmoduleShas();
  if (pinnedSha !== currentHead) {
    throw new KatFixtureError(
      `Submodule ETHDILITHIUM at ${currentHead} but pinned to ${pinnedSha}. ` +
        `Re-pin with: git -C ETHDILITHIUM checkout ${pinnedSha}. Then run: ` +
        `npx tsx scripts/generate-kat-fixtures.ts to regenerate fixtures.`,
      "KAT_SUBMODULE_SHA_MISMATCH",
    );
  }
}

/**
 * Compare a fixture file's embedded `submoduleSha` to the current submodule
 * HEAD. Throw on drift.
 */
function assertFixtureShaMatches(
  fixtureSha: string,
  fixturePath: string,
): void {
  const { currentHead } = probeSubmoduleShas();
  if (fixtureSha !== currentHead) {
    throw new KatFixtureError(
      `Fixture ${fixturePath} was generated at submodule SHA ${fixtureSha} but ` +
        `current ETHDILITHIUM HEAD is ${currentHead}. Regenerate with: ` +
        `npx tsx scripts/generate-kat-fixtures.ts`,
      "KAT_SUBMODULE_SHA_MISMATCH",
    );
  }
}

// ---------------------------------------------------------------------------
// Fixture readers
// ---------------------------------------------------------------------------

function readJsonFile(fixturePath: string): unknown {
  let raw: string;
  try {
    raw = readFileSync(fixturePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new KatFixtureError(
        `KAT fixture not found at ${fixturePath}. Generate it with: ` +
          `npx tsx scripts/generate-kat-fixtures.ts`,
        "KAT_FIXTURE_MISSING",
        { cause: err },
      );
    }
    throw new KatFixtureError(
      `Failed to read KAT fixture at ${fixturePath}`,
      "KAT_SCHEMA_MISMATCH",
      { cause: err },
    );
  }

  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath} is not valid JSON`,
      "KAT_SCHEMA_MISMATCH",
      { cause: err },
    );
  }
}

function assertTopLevelKey(
  obj: Record<string, unknown>,
  key: string,
  fixturePath: string,
): void {
  if (!(key in obj)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath} is missing required top-level key '${key}'`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
}

/**
 * Load the PRG KAT fixture file (DD-11).
 *
 * Throws `KatFixtureError` with:
 *   - `KAT_FIXTURE_MISSING` if the file does not exist
 *   - `KAT_SCHEMA_MISMATCH` if required top-level keys are absent
 *   - `KAT_SUBMODULE_SHA_MISMATCH` if the fixture's embedded SHA differs
 *     from current submodule HEAD (defensive — also enforced at import time)
 */
export function loadPrgVectors(): PrgVector[] {
  assertSubmoduleShaMatches();
  const fixturePath = path.join(fixtureDir(), "keccak-prg", "vectors.json");
  const parsed = readJsonFile(fixturePath);

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath} must be a JSON object`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  const obj = parsed as Record<string, unknown>;
  assertTopLevelKey(obj, "submoduleSha", fixturePath);
  assertTopLevelKey(obj, "generatedAt", fixturePath);
  assertTopLevelKey(obj, "vectors", fixturePath);

  const submoduleSha = obj["submoduleSha"];
  if (typeof submoduleSha !== "string") {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSha' must be a string`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  assertFixtureShaMatches(submoduleSha, fixturePath);

  const vectors = obj["vectors"];
  if (!Array.isArray(vectors)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'vectors' must be an array`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  return vectors as PrgVector[];
}

/**
 * Load the ML-DSA-ETH KAT fixture file (DD-7).
 *
 * Throws `KatFixtureError` with:
 *   - `KAT_FIXTURE_MISSING` if the file does not exist
 *   - `KAT_SCHEMA_MISMATCH` if required top-level keys are absent
 *   - `KAT_SUBMODULE_SHA_MISMATCH` if the fixture's embedded SHA differs
 *     from current submodule HEAD (defensive — also enforced at import time)
 */
export function loadKatVectors(scheme: "mldsa-eth"): KatVector[] {
  assertSubmoduleShaMatches();
  const fixturePath = path.join(fixtureDir(), scheme, "vectors.json");
  const parsed = readJsonFile(fixturePath);

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath} must be a JSON object`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  const obj = parsed as Record<string, unknown>;
  for (const key of [
    "scheme",
    "params",
    "submoduleSha",
    "generatedAt",
    "source",
    "vectors",
  ]) {
    assertTopLevelKey(obj, key, fixturePath);
  }

  const submoduleSha = obj["submoduleSha"];
  if (typeof submoduleSha !== "string") {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSha' must be a string`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  assertFixtureShaMatches(submoduleSha, fixturePath);

  const vectors = obj["vectors"];
  if (!Array.isArray(vectors)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'vectors' must be an array`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  return vectors as KatVector[];
}

// ---------------------------------------------------------------------------
// AC-1-8: run SHA guard at module-evaluation time (NOT lazily). Any import
// of this module — including a dynamic `await import(...)` — invokes this
// call; drift surfaces as an eager, loud `KatFixtureError` at import time.
// ---------------------------------------------------------------------------
assertSubmoduleShaMatches();
