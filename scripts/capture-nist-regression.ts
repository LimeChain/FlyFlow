/**
 * Story 3 Task 1 — Pre-refactor NIST regression capture (AC-3-3 safety net).
 *
 * Captures the byte-level output of `preparePublicKeyForDeployment` over
 * all 100 vectors in `ETHDILITHIUM/pythonref/assets/PQCsignKAT_Dilithium2.rsp`,
 * writing `test/fixtures/kat/nist-regression/vectors.json`. The committed
 * fixture is the PRE-refactor baseline captured at Task 1 time; Task 2's
 * refactored two-factory signature (A-002) MUST reproduce it byte-for-byte,
 * and any divergence triggers the refactor-rollback protocol (architecture
 * §"Error Handling Strategy"). Re-running this script post-refactor against
 * the NIST call pair `(shake256XofFactory, shake128XofFactory)` — per A-002
 * mapping NIST `_xof = SHAKE-256` / `_xof2 = SHAKE-128` — produces a
 * byte-identical JSON when the refactor is correct; that is exactly the
 * AC-3-3 post-refactor assertion from the other direction.
 *
 * MUST have been committed BEFORE Task 2 begins — capturing after the
 * refactor would record the refactored code's output, defeating the
 * safety net.
 *
 * Invocation: `npx tsx scripts/capture-nist-regression.ts`
 *
 * Determinism (per `.claude/rules/test-integrity.md` + story §"File-tree
 * effects"): stable key order, 2-space indent, LF line endings, trailing
 * newline, lowercase hex with `0x` prefix. Deliberately NO `generatedAt`
 * timestamp (spurious diffs) and NO `submoduleSha` (this is a local
 * pre-refactor golden, independent of ZKNox submodule pin).
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { bytesToHex, hexToBytes, type Hex } from "viem";

import {
  preparePublicKeyForDeployment,
  shake128XofFactory,
  shake256XofFactory,
} from "../test/signers/mldsa-encoding.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), "..");
const RSP_PATH = path.join(
  REPO_ROOT,
  "ETHDILITHIUM",
  "pythonref",
  "assets",
  "PQCsignKAT_Dilithium2.rsp",
);
const OUT_DIR = path.join(REPO_ROOT, "test", "fixtures", "kat", "nist-regression");
const OUT_PATH = path.join(OUT_DIR, "vectors.json");

const EXPECTED_VECTOR_COUNT = 100;
const PUBLIC_KEY_BYTES = 1312;

interface NistRegressionVector {
  id: string;
  pk: Hex;
  expectedReshapedPk: Hex;
}

interface NistRegressionFile {
  scheme: "nist-dilithium2-pre-refactor";
  vectorCount: number;
  vectors: NistRegressionVector[];
}

interface RspPkRecord {
  count: number;
  pk: string;
}

/**
 * Parse `PQCsignKAT_Dilithium2.rsp` into `(count, pk)` pairs. Only `count`
 * and `pk` are required for this capture — the refactor-rollback assertion
 * only needs the 1312-byte public key per vector. Records are separated
 * by blank lines; comments begin with `#` and are ignored.
 */
function parseRspPkRecords(): RspPkRecord[] {
  const raw = readFileSync(RSP_PATH, "utf8");
  const records: RspPkRecord[] = [];
  let current: Partial<RspPkRecord> = {};

  const flush = (): void => {
    if (current.count !== undefined && current.pk !== undefined) {
      records.push({ count: current.count, pk: current.pk });
    }
    current = {};
  };

  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      flush();
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (key === "count") current.count = Number.parseInt(value, 10);
    else if (key === "pk") current.pk = value.toLowerCase();
  }
  flush();

  return records;
}

function main(): void {
  const records = parseRspPkRecords();
  if (records.length !== EXPECTED_VECTOR_COUNT) {
    throw new Error(
      `Expected ${EXPECTED_VECTOR_COUNT} vectors in ${RSP_PATH}, parsed ${records.length}`,
    );
  }

  const vectors: NistRegressionVector[] = records.map((r) => {
    const pkBytes = hexToBytes(`0x${r.pk}`);
    if (pkBytes.length !== PUBLIC_KEY_BYTES) {
      throw new Error(
        `Vector ${r.count}: pk length ${pkBytes.length} ≠ ${PUBLIC_KEY_BYTES}`,
      );
    }
    // A-002 two-factory NIST call: xofFactory = SHAKE-256 (H/tr),
    //                              xofFactory2 = SHAKE-128 (ExpandA).
    const reshaped = preparePublicKeyForDeployment(
      pkBytes,
      shake256XofFactory,
      shake128XofFactory,
    );
    return {
      id: `nist-vec-${String(r.count).padStart(3, "0")}`,
      pk: bytesToHex(pkBytes),
      expectedReshapedPk: reshaped,
    };
  });

  const out: NistRegressionFile = {
    scheme: "nist-dilithium2-pre-refactor",
    vectorCount: EXPECTED_VECTOR_COUNT,
    vectors,
  };

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(OUT_PATH, JSON.stringify(out, null, 2) + "\n");
  // eslint-disable-next-line no-console -- CLI tool user feedback
  console.log(`Wrote ${vectors.length} vectors to ${path.relative(REPO_ROOT, OUT_PATH)}`);
}

main();
