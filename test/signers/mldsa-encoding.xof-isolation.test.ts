/**
 * Story 3 Task 2 — Interleaved XOF-isolation test (AC-3-5 + AC-3-4).
 *
 * Asserts that interleaving `shake256XofFactory + shake128XofFactory` with
 * `keccakXofFactory` across `preparePublicKeyForDeployment` calls in a
 * single process produces consistent per-factory outputs. No cached state
 * leaks from one factory to the next — the DD-10 isolation guarantee, per
 * AC-A-1 HIGH.
 *
 * Oracle pairing per `docs/amendments.md` §A-004 (format-mismatch amendment):
 *   Pass 1 — SHAKE on a NIST pk       →  equal to NIST regression golden.
 *   Pass 2 — Keccak on an mldsa-eth pk →  baseline captured (no external
 *                                         byte-achievable golden per A-004).
 *   Pass 3 — SHAKE on same NIST pk    →  equal to Pass 1 AND NIST golden
 *                                         (isolation + determinism).
 *   Pass 4 — Keccak on same ETH pk     →  equal to Pass 2 (isolation +
 *                                         determinism across an intervening
 *                                         SHAKE call).
 *
 * AC-3-4 surfaces via `assertBytesEqual`'s `xofId` argument — any
 * divergence message would contain `(factory=<xofId>)` for grep-anchored
 * triage.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { hexToBytes, type Hex } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { assertBytesEqual } from "../utils/assert-bytes.js";
import {
  keccakXofFactory,
  preparePublicKeyForDeployment,
  shake128XofFactory,
  shake256XofFactory,
} from "./mldsa-encoding.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const NIST_FIXTURE_PATH = path.resolve(
  path.dirname(THIS_FILE),
  "..",
  "fixtures",
  "kat",
  "nist-regression",
  "vectors.json",
);

interface NistVector {
  id: string;
  pk: Hex;
  expectedReshapedPk: Hex;
}

interface NistFixture {
  scheme: string;
  vectorCount: number;
  vectors: NistVector[];
}

describe("mldsa-encoding XOF isolation (AC-3-5, AC-3-4)", () => {
  it("interleaved SHAKE ↔ Keccak preserves per-factory output; no cross-contamination", () => {
    const nistRaw = readFileSync(NIST_FIXTURE_PATH, "utf8");
    const nistFixture = JSON.parse(nistRaw) as NistFixture;
    const nistVec = nistFixture.vectors[0];
    if (nistVec === undefined) {
      throw new Error("NIST regression fixture empty");
    }
    const ethVectors = loadKatVectors("mldsa-eth");
    const ethVec = ethVectors[0];
    if (ethVec === undefined) {
      throw new Error("mldsa-eth fixture empty");
    }

    const nistPk = hexToBytes(nistVec.pk);
    const nistGolden = hexToBytes(nistVec.expectedReshapedPk);
    const ethPk = hexToBytes(ethVec.publicKey as Hex);

    // Pass 1 — SHAKE on NIST pk → must equal NIST regression golden.
    const pass1Hex = preparePublicKeyForDeployment(
      nistPk,
      shake256XofFactory,
      shake128XofFactory,
    );
    const pass1 = hexToBytes(pass1Hex);
    assertBytesEqual(
      pass1,
      nistGolden,
      "pass 1 SHAKE@NIST vs regression golden",
      "shake256",
    );

    // Pass 2 — Keccak on ETH pk → capture as per-invocation baseline.
    const pass2Hex = preparePublicKeyForDeployment(
      ethPk,
      keccakXofFactory,
      keccakXofFactory,
    );
    const pass2 = hexToBytes(pass2Hex);

    // Pass 3 — SHAKE on NIST pk again. Must equal pass 1 AND the golden.
    // Proves the intervening Keccak call did not leak factory state into
    // the SHAKE pipeline (or vice versa through a shared module-level cache).
    const pass3Hex = preparePublicKeyForDeployment(
      nistPk,
      shake256XofFactory,
      shake128XofFactory,
    );
    const pass3 = hexToBytes(pass3Hex);
    assertBytesEqual(
      pass3,
      pass1,
      "pass 3 SHAKE@NIST (after Keccak interleave) vs pass 1",
      "shake256",
    );
    assertBytesEqual(
      pass3,
      nistGolden,
      "pass 3 SHAKE@NIST vs regression golden (cross-check)",
      "shake256",
    );

    // Pass 4 — Keccak on ETH pk again. Must equal pass 2.
    // Proves the intervening SHAKE call (pass 3) did not leak state into
    // the Keccak-PRG pipeline.
    const pass4Hex = preparePublicKeyForDeployment(
      ethPk,
      keccakXofFactory,
      keccakXofFactory,
    );
    const pass4 = hexToBytes(pass4Hex);
    assertBytesEqual(
      pass4,
      pass2,
      "pass 4 Keccak@ETH (after SHAKE interleave) vs pass 2",
      "keccak-prg",
    );
  });
});
