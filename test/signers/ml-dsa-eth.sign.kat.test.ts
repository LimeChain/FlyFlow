/**
 * Story 4 Task 4 — G2 KAT byte-identity + rejection-counter test
 * (AC-4-1 primary, AC-4-5 supporting).
 *
 * Iterates every vector in `test/fixtures/kat/mldsa-eth/vectors.json`
 * (Story 1 AC-1-1 capture — `sm[:-mlen]` extracted from
 * `PQCsignKAT_Dilithium2_ETH.rsp`) and asserts that the TS signer
 * fork produces byte-identical 2420 B signatures to the Python
 * reference via `signWithRnd(sk, msg, rnd)` — the G2 oracle in the
 * four-implementation chain (DD-11). Without G2, Story 5's on-chain
 * verifier gate (G4) would build on unverified signer ground.
 *
 * Factory under test: `keccakXofFactory` routed via
 * `ml-dsa-eth.kat-internal.ts#signWithRnd` →
 * `ml-dsa-eth.core.ts#signWithXof` (single-factory collapse per DD-1).
 *
 * A separate `it` block calls `signWithXofInstrumented` directly to
 * exercise the rejection-loop observably — AC-4-5 requires
 * `totalIterations > vectorCount` strictly (≥1 vector needed a retry).
 * Stats (min/max/avg iterations) print via `console.info` for a
 * historical record; they are informational, not assertions.
 *
 * Assertion style: `assertBytesEqual(..., "keccak-prg")` surfaces the
 * AC-3-4 factory discriminant on divergence. Counter assertion uses
 * `assert.ok` with an explicit message.
 *
 * Cost: noble-shape sign is ~200-300 ms / call × ~100 vectors × 2
 * passes ≈ 50 s. Comparable to Story 3's G1 KAT.
 *
 * Pure `node:test` — no Hardhat runtime needed (signer is pure JS).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { type Hex, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { assertBytesEqual } from "../utils/assert-bytes.js";
import { signWithXofInstrumented } from "./ml-dsa-eth.core.js";
import { signWithRnd } from "./ml-dsa-eth.kat-internal.js";
import { keccakXofFactory } from "./mldsa-encoding.js";

describe("G2 — ml-dsa-eth signer KAT byte-identity (AC-4-1)", () => {
  const vectors = loadKatVectors("mldsa-eth");

  it(`all ${vectors.length} vectors: signWithRnd(sk, msg, rnd) matches v.signature byte-for-byte`, () => {
    for (const v of vectors) {
      const sig = signWithRnd(
        hexToBytes(v.secretKey as Hex),
        hexToBytes(v.message as Hex),
        hexToBytes(v.rnd as Hex),
      );
      assertBytesEqual(
        hexToBytes(sig as Hex),
        hexToBytes(v.signature as Hex),
        `vec ${v.id} sig`,
        "keccak-prg",
      );
    }
  });
});

describe("G2 — rejection-loop counter (AC-4-5)", () => {
  const vectors = loadKatVectors("mldsa-eth");

  it(`signWithXofInstrumented: Σiterations > ${vectors.length} across all vectors`, () => {
    let total = 0;
    let minIters = Number.POSITIVE_INFINITY;
    let maxIters = 0;
    for (const v of vectors) {
      const { iterations } = signWithXofInstrumented(
        hexToBytes(v.secretKey as Hex),
        hexToBytes(v.message as Hex),
        hexToBytes(v.rnd as Hex),
        new Uint8Array(0),
        keccakXofFactory,
      );
      total += iterations;
      if (iterations < minIters) minIters = iterations;
      if (iterations > maxIters) maxIters = iterations;
    }
    const avg = (total / vectors.length).toFixed(2);
    console.info(
      `[G2 rejection stats] vectors=${vectors.length} totalIters=${total} avg=${avg} min=${minIters} max=${maxIters}`,
    );
    assert.ok(
      total > vectors.length,
      `AC-4-5: totalIterations ${total} must strictly exceed vectorCount ${vectors.length} — at least one vector should require >1 rejection iteration`,
    );
  });
});
