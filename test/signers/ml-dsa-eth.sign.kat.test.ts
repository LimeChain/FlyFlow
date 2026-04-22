/**
 * G2 KAT — ml-dsa-eth signer byte-identity (AC-4-1).
 *
 * Iterates every vector in `test/fixtures/kat/mldsa-eth/vectors.json`
 * (Story 1 AC-1-1 capture — `sm[:-mlen]` extracted from
 * `PQCsignKAT_Dilithium2_ETH.rsp`) and asserts that the fork's signer
 * produces byte-identical 2420 B signatures to the Python reference via
 * `ml_dsa44eth.sign(msg, sk, { extraEntropy: rnd })` — the G2 oracle in
 * the four-implementation chain (DD-11).
 *
 * Post-fork-extraction delta:
 *   - `signWithRnd(sk, msg, rnd)` → `ml_dsa44eth.sign(msg, sk, {extraEntropy: rnd})`
 *     (noble `DSA.sign` accepts `extraEntropy` directly; no repo-side wrapper).
 *   - AC-4-5 G2 instrumented path (`signWithXofInstrumented` + rejection
 *     counter) is DROPPED — final-signature byte-identity over the full
 *     corpus is a superset of intermediate-state divergence detection
 *     (LD-13 in `docs/extract-mldsaeth.md`). The previous rejection-
 *     counter assertion was a lower-information-content oracle than the
 *     signature byte-identity AC-4-1 already validates.
 *
 * Assertion style: `assertBytesEqual(..., "keccak-prg")` surfaces the
 * AC-3-4 factory discriminant on divergence.
 *
 * Cost: noble-shape sign is ~200-300 ms / call × ~100 vectors ≈ 25 s.
 *
 * Pure `node:test` — no Hardhat runtime needed (signer is pure JS).
 */

import { describe, it } from "node:test";

import { ml_dsa44eth } from "@noble/post-quantum/ml-dsa.js";
import { type Hex, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { assertBytesEqual } from "../utils/assert-bytes.js";

describe("G2 — ml-dsa-eth signer KAT byte-identity (AC-4-1)", () => {
  const vectors = loadKatVectors("mldsa-eth");

  it(`all ${vectors.length} vectors: ml_dsa44eth.sign(msg, sk, {extraEntropy: rnd}) matches v.signature byte-for-byte`, () => {
    for (const v of vectors) {
      const sig = ml_dsa44eth.sign(
        hexToBytes(v.message as Hex),
        hexToBytes(v.secretKey as Hex),
        { extraEntropy: hexToBytes(v.rnd as Hex) },
      );
      assertBytesEqual(
        sig,
        hexToBytes(v.signature as Hex),
        `vec ${v.id} sig`,
        "keccak-prg",
      );
    }
  });
});
