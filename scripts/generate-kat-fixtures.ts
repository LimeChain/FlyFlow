/**
 * Fixture-gen CLI (Story 1, Task 3) — core generation path.
 *
 * Produces the two KAT fixture files consumed by the Story 2–5 test suite:
 *   - test/fixtures/kat/mldsa-eth/vectors.json (DD-7, 100 vectors)
 *   - test/fixtures/kat/keccak-prg/vectors.json (DD-11, 4 Layer-1 + ≥3 Layer-2)
 *
 * Invocation: `npx tsx scripts/generate-kat-fixtures.ts` (AC-1-1).
 *
 * Flow (per architecture §UC-2 "Fixture regeneration"):
 *   1. Read the pinned ETHDILITHIUM SHA (parent-tree gitlink via
 *      `git submodule status`) and current HEAD via `git -C ETHDILITHIUM
 *      rev-parse HEAD`. Abort with a raw diagnostic on mismatch — Task 4
 *      wraps this with the structured SUBMODULE_PIN_MISMATCH taxonomy.
 *   2. Parse `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2_ETH.rsp`
 *      into 100 (count, seed, mlen, msg, pk, sk, sm) records; derive
 *      `sig = sm[:-mlen]` (strip appended message, per NIST KAT convention).
 *   3. Spawn ONE `python3 -c "..."` batch (architecture UC-2 requires a
 *      single spawn). The Python program:
 *        - replays `AES256_CTR_DRBG(drbgSeed).random_bytes(64)` per record
 *          to recover `(ζ, rnd)`;
 *        - calls `Dilithium2.pk_for_eth(pk, _xof=Keccak256PRNG,
 *          _xof2=Keccak256PRNG)` and ABI-encodes the returned
 *          `(A_hat, tr, t1_new)` via `eth_abi.encode(['bytes','bytes32',
 *          'bytes'], ...)` for the `reshapedPublicKey` slot;
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
 * Scope boundary: AC-1-4 pin-mismatch + AC-U-2 four-failure-mode diagnostics
 * (SUBMODULE_UNINIT, PYTHON_VERSION_MISMATCH, PYTHON_DEPS_MISSING) are
 * Task 4's scope; Task 3 only plumbs the pin-read + non-zero-exit skeleton.
 * The structured-error taxonomy strings (SUBMODULE_PIN_MISMATCH, etc.) are
 * referenced in comments below for Task 4 to grep against.
 *
 * NFR-3 (zero Python files shipped): the Python batch is passed as a string
 * argument to `python3 -c` — no `.py` files are added under `scripts/` or
 * `test/`. The Python source that executes is resident under `ETHDILITHIUM/`
 * (pinned submodule).
 */

import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
    row-major. Emitting the flat bytes blob lets abi.encode(bytes,bytes32,
    bytes) match the DD-7 'reshapedPublicKey' slot shape.
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
    bs = drbg.random_bytes(64)
    zeta = bs[0:32]
    rnd = bs[32:64]
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

function main(): number {
  // Step 1: pin + HEAD + timestamp (AC-1-4 plumbing; Task 4 wraps as diagnostic).
  const { pinnedSha, currentHead, commitTimestamp } = readSubmoduleShas();
  if (pinnedSha !== currentHead) {
    // Task 4 upgrades this to structured code "SUBMODULE_PIN_MISMATCH".
    process.stderr.write(
      `ETHDILITHIUM submodule HEAD (${currentHead}) differs from pinned SHA (${pinnedSha}).\n` +
        `Reset with: git -C ETHDILITHIUM checkout ${pinnedSha}\n`,
    );
    return 1;
  }
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
        "AES256_CTR_DRBG(drbgSeed).random_bytes(64) → ζ=[0:32], rnd=[32:64]",
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
