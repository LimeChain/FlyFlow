/**
 * Story 3 Task 2 — post-refactor NIST regression (AC-3-3 assertion half).
 *
 * Reads the frozen pre-refactor fixture at
 * `test/fixtures/kat/nist-regression/vectors.json` (captured by Task 1's
 * `scripts/capture-nist-regression.ts`) and asserts that the refactored
 * two-factory `preparePublicKeyForDeployment` produces byte-identical
 * output for all 100 NIST `PQCsignKAT_Dilithium2.rsp` public keys.
 *
 * Factory pairing per `docs/amendments.md` §A-002:
 *   xofFactory  = SHAKE-256 (H/tr role  — Python `_xof`)
 *   xofFactory2 = SHAKE-128 (ExpandA    — Python `_xof2`)
 *
 * Any mismatch HALTs the run (first-divergence) per the refactor-rollback
 * protocol in `docs/architecture.md` §"Error Handling Strategy".
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { hexToBytes, type Hex } from "viem";

import { assertBytesEqual } from "../utils/assert-bytes.js";
import {
  preparePublicKeyForDeployment,
  shake128XofFactory,
  shake256XofFactory,
} from "./mldsa-encoding.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const FIXTURE_PATH = path.resolve(
  path.dirname(THIS_FILE),
  "..",
  "fixtures",
  "kat",
  "nist-regression",
  "vectors.json",
);

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

describe("mldsa-encoding NIST regression (AC-3-3)", () => {
  const raw = readFileSync(FIXTURE_PATH, "utf8");
  const fixture = JSON.parse(raw) as NistRegressionFile;

  it("fixture metadata: scheme + count", () => {
    assert.equal(fixture.scheme, "nist-dilithium2-pre-refactor");
    assert.equal(fixture.vectorCount, 100);
    assert.equal(fixture.vectors.length, 100);
  });

  it("all 100 NIST vectors reshape byte-identical to pre-refactor baseline", () => {
    for (const v of fixture.vectors) {
      const pk = hexToBytes(v.pk);
      const reshapedHex = preparePublicKeyForDeployment(
        pk,
        shake256XofFactory,
        shake128XofFactory,
      );
      const actual = hexToBytes(reshapedHex);
      const expected = hexToBytes(v.expectedReshapedPk);
      assertBytesEqual(actual, expected, `nist-regression ${v.id}`, "shake256");
    }
  });
});
