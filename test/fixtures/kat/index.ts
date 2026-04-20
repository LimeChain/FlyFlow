/**
 * KAT fixture loader + error class + multi-submodule SHA-drift guard.
 *
 * Originally landed by mldsa-eth Story 1 Task 2 with a single `ETHDILITHIUM`
 * pin. Extended by falcon-eth Story 1-1 Task T4 into a multi-submodule-aware
 * loader: fixtures embed a `submoduleSource` discriminator
 * (`"ethdilithium" | "ethfalcon"`), and the loader probes the matching
 * submodule's HEAD rather than hardcoding one.
 *
 * Enforces AC-1-8 (mldsa-eth) and AC-4/AC-5/AC-6 (falcon-eth Story 1-1):
 *   - import-time SHA-guard for ETHDILITHIUM (mldsa-eth fixture is always
 *     present in this repo; the import-time probe preserves the mldsa-eth
 *     A-001-era loud-fail posture).
 *   - per-call SHA-guard for whichever submodule the fixture declares
 *     via `submoduleSource` (AC-5).
 *   - schema rejection of fixtures missing `submoduleSource` (AC-4 part 1,
 *     `KAT_SCHEMA_MISMATCH`).
 *   - schema rejection of fixtures declaring an unknown `submoduleSource`
 *     (AC-4 part 2, `KAT_UNKNOWN_SUBMODULE_SOURCE`).
 *   - discriminated TypeScript overload on `loadKatVectors` so cross-scheme
 *     field access fails at `tsc` (AC-6).
 *
 * Downstream consumers (Stories 2-*) import only the named loaders:
 *   import { loadKatVectors, loadHashToPointVectors, loadPrgVectors }
 *     from "../fixtures/kat/index.js";
 *
 * SHA-guard mechanism (per architecture §"KAT loader"):
 *   - pinned SHA:  `git submodule status <SUBMODULE> | awk '{print $1}'`
 *     (strip leading `+`/`-`/`U`/space status prefix).
 *   - current HEAD: `git -C <SUBMODULE> rev-parse HEAD`.
 *   Commands are executed via `execFileSync` (argv form — no shell). Result
 *   is cached per-submodule in a module-level map so each probe runs at most
 *   once per submodule per process.
 *
 * Path resolution: fixture JSON files live at paths relative to the repo
 * root (`test/fixtures/kat/...`). Resolved via `import.meta.url` (this file
 * is `test/fixtures/kat/index.ts`, so repo root is three levels up).
 *
 * Test-only hook: `process.env.KAT_FIXTURE_DIR`, if set, overrides the
 * fixture directory root. Used by the colocated unit tests to point the
 * loader at a temp directory with synthetic fixtures; production callers
 * never set this. This loader-level override is test-harness-trusted per the
 * story's §"Detected Patterns" conflict-resolution note (distinct trust
 * model from CLI-side overrides, which are sentinel+regex gated).
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type KatFixtureErrorCode =
  | "KAT_SCHEMA_MISMATCH"
  | "KAT_SUBMODULE_SHA_MISMATCH"
  | "KAT_FIXTURE_MISSING"
  | "KAT_GIT_PROBE_FAILED"
  | "KAT_UNKNOWN_SUBMODULE_SOURCE";

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
// Submodule source — fixture discriminator (AC-4)
// ---------------------------------------------------------------------------

/**
 * Submodule providing the upstream reference for a given KAT fixture.
 * Written into each fixture's top-level `submoduleSource` field; used by the
 * multi-submodule loader to pick which git submodule to probe for
 * SHA-drift detection (AC-5).
 */
export type SubmoduleSource = "ethdilithium" | "ethfalcon";

const KNOWN_SUBMODULE_SOURCES: readonly SubmoduleSource[] = [
  "ethdilithium",
  "ethfalcon",
] as const;

/** Map submodule-source discriminator to the git-submodule directory name. */
function submoduleDirName(source: SubmoduleSource): string {
  return source === "ethdilithium" ? "ETHDILITHIUM" : "ETHFALCON";
}

/** Map scheme → regeneration command fragment for SHA-mismatch error text. */
function regenerateCommandFor(scheme: "mldsa-eth" | "falcon-eth"): string {
  return `npm run kat:regen -- --scheme ${scheme}`;
}

// ---------------------------------------------------------------------------
// Type schemas — mirror DD-7 (ML-DSA KAT) + falcon-eth Story 1-1 schemas.
// ---------------------------------------------------------------------------

/**
 * One PRG KAT vector (DD-11).
 *
 * The `source` union is additively extended for multi-submodule capture:
 *   - `"zhenfei-canonical"` — Layer-1 ZKNox Forge test hex literals
 *     (ETHDILITHIUM-era).
 *   - `"python-ref-extended"` — Layer-2 ETHDILITHIUM Python ref generator
 *     (cross-extract, multi-inject, empty-seed, ML-DSA-shape).
 *   - `"ethfalcon-python-ref"` — falcon-eth Story 1-2 G1 capture from
 *     `ETHFALCON/pythonref/keccak_prng.py::KeccakPRNG` (0-arg class).
 *
 * All three share the same `PrgVector` shape — the extension is purely a
 * provenance-discriminator string. Existing ETHDILITHIUM fixture data (which
 * uses the first two values) is unaffected; `loadPrgVectors()` (mldsa-eth)
 * and `loadFalconPrgVectors()` (falcon-eth) both return `PrgVector[]` and
 * rely on the loader-level `submoduleSource` discriminator for SHA probing.
 */
export interface PrgVector {
  id: string;
  source: "zhenfei-canonical" | "python-ref-extended" | "ethfalcon-python-ref";
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
export interface MlDsaEthKatVector {
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
  /** Variable — ABI-encoded (bytes,bytes,bytes) tuple per `docs/amendments.md` §A-001 (G3 expected / G4 input). Expected decoded lengths: `aHatEncoded` = 16384 B, `tr` = 64 B (Keccak-PRG stream), `t1Encoded` = 4096 B. */
  reshapedPublicKey: string;
  /** Variable hex — G2 input. */
  message: string;
  /** 2420 B hex — cTilde‖z‖h (32+2304+84) (G2 expected / G4 input). */
  signature: string;
}

/** One Falcon-ETH KAT vector (falcon-eth Story 1-1 AC-1). */
export interface FalconKatVector {
  readonly id: string;
  /** 48 B — AES256_CTR_DRBG seed from ETHFALCON `.rsp`; audit-replay only. */
  readonly drbgSeed: `0x${string}`;
  /** 897 B raw Falcon-512 public key. */
  readonly publicKey: `0x${string}`;
  /** Falcon-512 secret key (variable — poly-packed). */
  readonly secretKey: `0x${string}`;
  /** `abi.encode(uint256[32])` of the reshaped NTT-domain pk (G5 expected). */
  readonly reshapedPublicKey: `0x${string}`;
  /** Variable — signed message (`sm[2+40 : 2+40+mlen]`). */
  readonly message: `0x${string}`;
  /** 1064 B = `salt(40) ‖ s2_compact(1024)` (G4 expected — falcon-eth signature is NOT NIST-shaped). */
  readonly signature: `0x${string}`;
}

/**
 * One HashToPoint KAT vector (falcon-eth Story 1-1 AC-2). Generated by
 * deploying `ZKNOX_HashToPointExposed` on Hardhat and capturing
 * `compute(salt, msg)` — trust anchor is the pinned ETHFALCON Solidity
 * `hashToPointEVM` free function (DD-25 Option C).
 */
export interface HashToPointVector {
  readonly id: string;
  /** 40 B salt. */
  readonly salt: `0x${string}`;
  /** Variable-length input message. */
  readonly message: `0x${string}`;
  /** 512 uint16 coefficients, each `< 12289` (Falcon q). */
  readonly expectedHash: readonly number[];
}

/** Top-level PRG fixture file shape. */
export interface PrgVectorsFile {
  submoduleSha: string;
  /** ISO 8601 timestamp. */
  generatedAt: string;
  vectors: PrgVector[];
}

/** Top-level ML-DSA-ETH fixture file shape. */
export interface MlDsaEthKatVectorsFile {
  scheme: "mldsa-eth";
  params: "dilithium2-keccak";
  /**
   * Discriminator for the multi-submodule loader (falcon-eth Story 1-1 AC-4).
   * Always `"ethdilithium"` for the mldsa-eth fixture.
   */
  submoduleSource: "ethdilithium";
  submoduleSha: string;
  /** ISO 8601 timestamp. */
  generatedAt: string;
  source: {
    rspFile: string;
    drbgDerivation: string;
    ctx: "0x";
  };
  vectors: MlDsaEthKatVector[];
}

/** Top-level Falcon-ETH fixture file shape (falcon-eth Story 1-1 T1 schema). */
export interface FalconKatVectorsFile {
  readonly scheme: "falcon-eth";
  readonly params: "falcon-512-keccak";
  readonly submoduleSource: "ethfalcon";
  readonly submoduleSha: string;
  readonly generatedAt: string;
  readonly source: {
    readonly rspFile: string;
    readonly drbgDerivation: string;
    readonly ctx: "0x";
  };
  readonly vectors: readonly FalconKatVector[];
}

/** Top-level HashToPoint fixture file shape (falcon-eth Story 1-1 T2 schema). */
export interface HashToPointVectorsFile {
  readonly scheme: "falcon-eth";
  readonly gate: "G2-hashtopoint";
  readonly submoduleSource: "ethfalcon";
  readonly submoduleSha: string;
  readonly generatedAt: string;
  readonly source: {
    readonly solContract: string;
    readonly solFile: string;
    readonly upstreamFile: string;
    readonly algorithm: string;
    readonly generator: string;
  };
  readonly vectors: readonly HashToPointVector[];
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
// Submodule SHA probe (cached per-submodule)
// ---------------------------------------------------------------------------

interface ShaProbeResult {
  pinnedSha: string;
  currentHead: string;
}

/**
 * Per-submodule cache of probe results. Keyed by {@link SubmoduleSource} so
 * that the two submodules are probed independently (and so a mock of one
 * never leaks to the other in tests).
 */
const probeCache = new Map<SubmoduleSource, ShaProbeResult>();

/**
 * Run the two-step git probe for the given submodule — current HEAD via
 * `git -C <submodule> rev-parse HEAD`, pinned SHA via
 * `git submodule status <submodule>` with the leading status prefix
 * stripped. Cached per-submodule.
 *
 * Exported for direct testing; invoked by {@link assertSubmoduleShaMatches}
 * and the fixture loaders.
 */
export function probeSubmoduleShas(source: SubmoduleSource): ShaProbeResult {
  const cached = probeCache.get(source);
  if (cached !== undefined) return cached;

  const dirName = submoduleDirName(source);

  // Step 1: current submodule HEAD.
  let currentHead: string;
  try {
    const out = execFileSync(
      "git",
      ["-C", path.join(REPO_ROOT, dirName), "rev-parse", "HEAD"],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    currentHead = out.trim();
  } catch (err) {
    throw new KatFixtureError(
      `Failed to probe ${dirName} HEAD via 'git -C ${dirName} rev-parse HEAD'. ` +
        `Is the submodule initialized? Try: git submodule update --init --recursive`,
      "KAT_GIT_PROBE_FAILED",
      { cause: err },
    );
  }

  // Step 2: pinned SHA from parent-tree gitlink (git submodule status).
  // Output format: " <sha> <name> (heads/main)" with a leading status
  // character (space = clean, `+` = HEAD differs, `-` = not init'd,
  // `U` = merge conflicts). Strip the status prefix, then take field 1.
  let pinnedSha: string;
  try {
    const out = execFileSync(
      "git",
      ["submodule", "status", dirName],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    const line = out.split("\n")[0] ?? "";
    // Strip optional leading status char (`+`, `-`, `U`, or space).
    const stripped = line.replace(/^[+\-U ]/, "");
    const first = stripped.split(/\s+/)[0] ?? "";
    pinnedSha = first;
  } catch (err) {
    throw new KatFixtureError(
      `Failed to probe pinned ${dirName} SHA via 'git submodule status ${dirName}'.`,
      "KAT_GIT_PROBE_FAILED",
      { cause: err },
    );
  }

  const result: ShaProbeResult = { pinnedSha, currentHead };
  probeCache.set(source, result);
  return result;
}

/**
 * Throw `KatFixtureError` with `code: "KAT_SUBMODULE_SHA_MISMATCH"` if the
 * pinned SHA (parent-tree gitlink) differs from current submodule HEAD for
 * the given source.
 *
 * Exported for direct testing; invoked eagerly at module-evaluation time
 * (bottom of this file) for ETHDILITHIUM and defensively from each loader
 * for whichever submodule the fixture declares.
 */
export function assertSubmoduleShaMatches(
  source: SubmoduleSource = "ethdilithium",
): void {
  const { pinnedSha, currentHead } = probeSubmoduleShas(source);
  if (pinnedSha !== currentHead) {
    const dirName = submoduleDirName(source);
    const scheme = source === "ethdilithium" ? "mldsa-eth" : "falcon-eth";
    throw new KatFixtureError(
      `Submodule ${dirName} at ${currentHead} but pinned to ${pinnedSha}. ` +
        `Re-pin with: git -C ${dirName} checkout ${pinnedSha}. Then run: ` +
        `${regenerateCommandFor(scheme)} to regenerate fixtures.`,
      "KAT_SUBMODULE_SHA_MISMATCH",
    );
  }
}

/**
 * Compare a fixture file's embedded `submoduleSha` to the current submodule
 * HEAD for the fixture's declared source. Throw on drift with the matching
 * regeneration command.
 */
function assertFixtureShaMatches(
  fixtureSha: string,
  source: SubmoduleSource,
  fixturePath: string,
): void {
  const { currentHead } = probeSubmoduleShas(source);
  if (fixtureSha !== currentHead) {
    const dirName = submoduleDirName(source);
    const scheme = source === "ethdilithium" ? "mldsa-eth" : "falcon-eth";
    throw new KatFixtureError(
      `Fixture ${fixturePath} was generated at ${dirName} SHA ${fixtureSha} but ` +
        `current ${dirName} HEAD is ${currentHead}. Regenerate with: ` +
        `${regenerateCommandFor(scheme)}`,
      "KAT_SUBMODULE_SHA_MISMATCH",
    );
  }
}

/**
 * Validate the fixture's declared `submoduleSource` and return it typed.
 * Throws `KAT_SCHEMA_MISMATCH` if absent or non-string, and
 * `KAT_UNKNOWN_SUBMODULE_SOURCE` if the value is outside the known set
 * (AC-4 part 2).
 */
function readSubmoduleSource(
  obj: Record<string, unknown>,
  fixturePath: string,
): SubmoduleSource {
  const raw = obj["submoduleSource"];
  if (raw === undefined) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath} is missing required top-level key 'submoduleSource'`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  if (typeof raw !== "string") {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSource' must be a string`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  if (!(KNOWN_SUBMODULE_SOURCES as readonly string[]).includes(raw)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSource' value ${JSON.stringify(raw)} ` +
        `is not one of ${JSON.stringify(KNOWN_SUBMODULE_SOURCES)}`,
      "KAT_UNKNOWN_SUBMODULE_SOURCE",
    );
  }
  return raw as SubmoduleSource;
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
  // PRG fixture is mldsa-eth-scoped (Keccak-PRG is the XOF used by the
  // mldsa-eth Dilithium2 variant) — probe ETHDILITHIUM.
  assertSubmoduleShaMatches("ethdilithium");
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
  assertFixtureShaMatches(submoduleSha, "ethdilithium", fixturePath);

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
 * Load a scheme-typed KAT fixture file. Discriminated TypeScript overload:
 *   - `loadKatVectors("mldsa-eth")` → `MlDsaEthKatVector[]`
 *   - `loadKatVectors("falcon-eth")` → `FalconKatVector[]`
 *
 * Cross-scheme field access (e.g., a Falcon test accessing
 * `vec.cTilde`, which is ML-DSA-only) fails at `tsc` — this is AC-6.
 *
 * Throws `KatFixtureError` with:
 *   - `KAT_FIXTURE_MISSING` if the file does not exist
 *   - `KAT_SCHEMA_MISMATCH` if required top-level keys are absent or
 *     `submoduleSource` is missing / wrong type
 *   - `KAT_UNKNOWN_SUBMODULE_SOURCE` if `submoduleSource` is outside the
 *     known set `{"ethdilithium", "ethfalcon"}`
 *   - `KAT_SUBMODULE_SHA_MISMATCH` if the fixture's embedded SHA differs
 *     from current submodule HEAD (message includes both SHAs and the
 *     regeneration command)
 */
export function loadKatVectors(scheme: "mldsa-eth"): MlDsaEthKatVector[];
export function loadKatVectors(scheme: "falcon-eth"): FalconKatVector[];
export function loadKatVectors(
  scheme: "mldsa-eth" | "falcon-eth",
): MlDsaEthKatVector[] | FalconKatVector[] {
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
    "submoduleSource",
    "submoduleSha",
    "generatedAt",
    "source",
    "vectors",
  ]) {
    assertTopLevelKey(obj, key, fixturePath);
  }

  const submoduleSource = readSubmoduleSource(obj, fixturePath);

  const submoduleSha = obj["submoduleSha"];
  if (typeof submoduleSha !== "string") {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSha' must be a string`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  assertFixtureShaMatches(submoduleSha, submoduleSource, fixturePath);

  const vectors = obj["vectors"];
  if (!Array.isArray(vectors)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'vectors' must be an array`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  // The runtime shape is validated structurally by the caller's test
  // assertions; the discriminated overload above ensures TypeScript narrows
  // the return type at the call site.
  return vectors as MlDsaEthKatVector[] | FalconKatVector[];
}

/**
 * Load the HashToPoint KAT fixture file (falcon-eth Story 1-1 AC-2 / DD-25
 * Option C). Trust anchor is the pinned ETHFALCON `ZKNOX_HashToPoint.sol`.
 *
 * Throws `KatFixtureError` with:
 *   - `KAT_FIXTURE_MISSING` if the file does not exist
 *   - `KAT_SCHEMA_MISMATCH` if required top-level keys are absent
 *   - `KAT_UNKNOWN_SUBMODULE_SOURCE` if `submoduleSource` is outside the
 *     known set
 *   - `KAT_SUBMODULE_SHA_MISMATCH` if the fixture's embedded SHA differs
 *     from current ETHFALCON HEAD
 */
export function loadHashToPointVectors(): HashToPointVector[] {
  const fixturePath = path.join(
    fixtureDir(),
    "falcon-eth",
    "hashtopoint-vectors.json",
  );
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
    "gate",
    "submoduleSource",
    "submoduleSha",
    "generatedAt",
    "source",
    "vectors",
  ]) {
    assertTopLevelKey(obj, key, fixturePath);
  }

  const submoduleSource = readSubmoduleSource(obj, fixturePath);

  const submoduleSha = obj["submoduleSha"];
  if (typeof submoduleSha !== "string") {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSha' must be a string`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  assertFixtureShaMatches(submoduleSha, submoduleSource, fixturePath);

  const vectors = obj["vectors"];
  if (!Array.isArray(vectors)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'vectors' must be an array`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  return vectors as HashToPointVector[];
}

/**
 * Load the falcon-eth G1 Keccak-PRG KAT fixture (Story 1-2 / DD-13 LOCKED).
 *
 * Probes the ETHFALCON submodule (not ETHDILITHIUM) via per-submodule SHA
 * machinery Story 1-1 landed — the G1 corpus is captured from
 * `ETHFALCON/pythonref/keccak_prng.py::KeccakPRNG` (0-arg class per
 * `docs/amendments.md` §A-004), so SHA-drift must be detected against the
 * ETHFALCON pin, not the ETHDILITHIUM pin.
 *
 * Shape-parallel to {@link loadPrgVectors}, differing only in:
 *   - submodule probe target (`ethfalcon` not `ethdilithium`)
 *   - fixture path (`falcon-eth/prg-vectors.json` not
 *     `keccak-prg/vectors.json`)
 *   - schema: the G1 fixture carries the Story 1-1 multi-submodule
 *     `submoduleSource` discriminator (required-field-enforced here;
 *     `loadPrgVectors` is legacy mldsa-eth-scoped and does not require it).
 *
 * Throws `KatFixtureError` with:
 *   - `KAT_FIXTURE_MISSING` if the fixture file does not exist (message
 *     includes the `npm run kat:regen -- --scheme falcon-eth --target prg`
 *     regeneration command).
 *   - `KAT_SCHEMA_MISMATCH` if required top-level keys are absent or
 *     `submoduleSource` is missing / wrong type.
 *   - `KAT_UNKNOWN_SUBMODULE_SOURCE` if `submoduleSource` is outside the
 *     known set `{"ethdilithium", "ethfalcon"}`.
 *   - `KAT_SUBMODULE_SHA_MISMATCH` if the pinned ETHFALCON SHA differs from
 *     current ETHFALCON HEAD, OR if the fixture's embedded `submoduleSha`
 *     differs from current ETHFALCON HEAD. Message names both SHAs and the
 *     regeneration command.
 *
 * This loader ALSO rejects fixtures declaring a non-ethfalcon
 * `submoduleSource` (e.g., `"ethdilithium"`) with `KAT_SCHEMA_MISMATCH` —
 * the G1 loader is tightly scoped to ETHFALCON-sourced corpora per Story 1-2
 * must_haves. Cross-submodule fixture mixup is a schema error, not an
 * unknown-enum-value error.
 */
export function loadFalconPrgVectors(): PrgVector[] {
  // Per-submodule SHA probe — ETHFALCON is the upstream for the G1 corpus.
  assertSubmoduleShaMatches("ethfalcon");
  const fixturePath = path.join(
    fixtureDir(),
    "falcon-eth",
    "prg-vectors.json",
  );
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
    "gate",
    "submoduleSource",
    "submoduleSha",
    "generatedAt",
    "source",
    "vectors",
  ]) {
    assertTopLevelKey(obj, key, fixturePath);
  }

  // Validate the discriminator (throws KAT_SCHEMA_MISMATCH for missing/wrong
  // type; KAT_UNKNOWN_SUBMODULE_SOURCE for outside the known set).
  const submoduleSource = readSubmoduleSource(obj, fixturePath);
  if (submoduleSource !== "ethfalcon") {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSource' must be 'ethfalcon' ` +
        `for the G1 falcon-eth PRG loader, got ${JSON.stringify(submoduleSource)}`,
      "KAT_SCHEMA_MISMATCH",
    );
  }

  const submoduleSha = obj["submoduleSha"];
  if (typeof submoduleSha !== "string") {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'submoduleSha' must be a string`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  assertFixtureShaMatches(submoduleSha, "ethfalcon", fixturePath);

  const vectors = obj["vectors"];
  if (!Array.isArray(vectors)) {
    throw new KatFixtureError(
      `KAT fixture at ${fixturePath}: 'vectors' must be an array`,
      "KAT_SCHEMA_MISMATCH",
    );
  }
  return vectors as PrgVector[];
}

// ---------------------------------------------------------------------------
// AC-1-8 (mldsa-eth Story 1) — run ETHDILITHIUM SHA guard at module-evaluation
// time (NOT lazily). Any import of this module — including a dynamic
// `await import(...)` — invokes this call; drift surfaces as an eager, loud
// `KatFixtureError` at import time. Falcon-eth ETHFALCON drift is detected
// per-loader-call (AC-5) rather than at import time, because a repo that is
// valid for mldsa-eth consumers must not hard-fail to load simply because a
// falcon-eth fixture was regenerated under a different ETHFALCON pin.
// ---------------------------------------------------------------------------
assertSubmoduleShaMatches("ethdilithium");
