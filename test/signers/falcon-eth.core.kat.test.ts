/**
 * Falcon-ETH G2 HashToPoint KAT tier (Story 2-2, Task T2).
 *
 * Byte-identity tests against the committed HashToPoint KAT fixture
 * (`test/fixtures/kat/falcon-eth/hashtopoint-vectors.json`) — 8 vectors
 * captured by deploying `ZKNOX_HashToPointExposed` in Hardhat and calling
 * `.compute(salt, msg)` (Story 1-1 Task T2) at pinned ETHFALCON submodule
 * SHA `03ed0d60c67087527de7c4a3c1c469b89611bd68`.
 *
 * For each vector: invoke the TS port `hashToPointEVM(salt, msg)`
 * (`falcon-eth.core.ts`) and assert byte-identity against the pinned
 * `ZKNOX_HashToPoint.sol:22` Solidity free function (DD-25 LOCKED Option C
 * — trust anchor is the pinned Solidity, NOT a Python spec doc).
 *
 * ACs covered:
 *   - AC-1 (G2 byte-identity over all vectors returned by
 *     `loadHashToPointVectors()` — fixture drives the dynamic test count).
 *   - AC-2 (error path: on divergence, the failure message enumerates the
 *     debug checklist — chunk endianness, KQ=61445 threshold, mod-q
 *     reduction, absorb order, coefficient-order, counter endianness —
 *     plus first-differing-coefficient index + ±4 context window).
 *   - AC-3 (output constraints — length 512, every coeff < 12289; asserted
 *     both inside the port body AND at the test level here as a
 *     belt-and-braces invariant check).
 *   - AC-5 (trust-anchor regeneration pathway — inherited from Story 1-1
 *     Task T4's `loadHashToPointVectors` loader, which validates the
 *     fixture's pinned `submoduleSha` against `ETHFALCON` HEAD on every
 *     call. On mismatch the loader throws `KAT_SUBMODULE_SHA_MISMATCH`
 *     with the regeneration command — Story 2-2 inherits this pathway
 *     implicitly by calling the loader; no new code needed).
 *
 * G2 gate ordering: this test MUST PASS before Story 2-3 begins. The
 * oracle chain per `docs/architecture.md:198` says G4 uses G1-verified
 * XOF + G2-verified HashToPoint + G3-verified sk; byte-identity at G4 is
 * only trusted if every upstream gate holds. If G2 diverges here, HALT
 * and fix the port — do NOT proceed to 2-3 (the ~20-coefficient signature
 * surface of the signer would force the bisect up a layer).
 *
 * Framework: `node:test` + `node:assert/strict` — matches
 * `test/signers/keccak-prg.kat.test.ts` and `keccak-prg.falcon.kat.test.ts`.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { hexToBytes } from "viem";

import { loadHashToPointVectors } from "../fixtures/kat/index.js";
import { hashToPointEVM } from "./falcon-eth.core.js";

/**
 * Shared failure-message template for G2 coefficient divergence.
 *
 * Single source of truth for the divergence-message shape required by AC-2
 * (must_haves truth #5). Consumed by BOTH the real per-vector comparison
 * loop AND the synthetic AC-2 divergence-shape test — any edit to the
 * template touches both call sites, eliminating the drift risk flagged
 * by Story 2-2 code-review finding #1.
 *
 * Required substring anchors (asserted by the AC-2 synthetic test):
 *   (a) "first divergent coefficient at index"
 *   (b) the numeric index K
 *   (c) "actual [start..end):" and "expected [start..end):" context slices
 *   (d) "check chunk endianness"
 *   (e) "61445" (KQ threshold)
 *   (f) "mod-q" (reduction order hint)
 */
function formatG2DivergenceMessage(
  vectorId: string,
  k: number,
  actual: Uint16Array,
  expected: readonly number[],
): string {
  const start = Math.max(0, k - 4);
  const end = Math.min(expected.length, k + 5);
  const ctxActual = Array.from(actual.slice(start, end));
  const ctxExpected = expected.slice(start, end);
  return (
    `${vectorId}: first divergent coefficient at index ${k}\n` +
    `  actual   [${start}..${end}): ${JSON.stringify(ctxActual)}\n` +
    `  expected [${start}..${end}): ${JSON.stringify(ctxExpected)}\n` +
    `\n` +
    `  G2 divergence — debug checklist (AC-2):\n` +
    `    - check chunk endianness (big-endian, high bits first: ` +
    `(buffer[2k]<<8)|buffer[2k+1])\n` +
    `    - check rejection threshold kq=61445 (NOT 61440 — off-by-5 is silent)\n` +
    `    - check mod-q reduction applied AFTER the rejection check, q=12289\n` +
    `    - check absorb order: state = keccak256(salt‖msg), NOT keccak256(msg‖salt)\n` +
    `    - check coefficient-order: first accepted chunk → output[0], not output[511]\n` +
    `    - check counter endianness: big-endian uint64 at bytes 32..40 of extendedState\n`
  );
}

describe("HashToPoint KAT (G2 — byte-identity against pinned ETHFALCON ZKNOX_HashToPoint.sol)", () => {
  // Pre-loop AC-3 invariant test — asserts length and coefficient bound
  // across every vector in a single `it`. Runs BEFORE the per-vector
  // byte-identity loop so an AC-3 regression surfaces as a single crisp
  // failure rather than being diluted across every vector's compare loop.
  it("AC-3: every vector's hashToPointEVM output has length 512 and every coeff < 12289", () => {
    for (const vector of loadHashToPointVectors()) {
      const salt = hexToBytes(vector.salt);
      const msg = hexToBytes(vector.message);
      const actual = hashToPointEVM(salt, msg);
      assert.equal(
        actual.length,
        512,
        `${vector.id}: length ${actual.length} !== 512`,
      );
      for (let k = 0; k < 512; k++) {
        const coeff = actual[k] as number;
        assert.ok(
          coeff < 12289,
          `${vector.id}: coeff[${k}]=${coeff} >= 12289`,
        );
      }
    }
  });

  // Per-vector byte-identity tests (AC-1 + AC-2) — fixture-count-dynamic.
  // `loadHashToPointVectors()` returns `HashToPointVector[]`; `expectedHash`
  // is `readonly number[]` (plain JS numbers from JSON.parse), not a
  // `Uint16Array`. Element-wise strict equality between `number` (from
  // `expectedHash[k]`) and `number` (from `Uint16Array[k]` auto-unboxing)
  // works as expected — no coercion needed.
  for (const vector of loadHashToPointVectors()) {
    it(`${vector.id}: byte-identical to pinned Solidity hashToPointEVM`, () => {
      const salt = hexToBytes(vector.salt);
      const msg = hexToBytes(vector.message);
      const actual = hashToPointEVM(salt, msg);
      const expected = vector.expectedHash;

      // Length first — a length mismatch is categorically different from
      // a value divergence (signals a structural port bug, not a chunk-
      // endianness / threshold / mod-q bug).
      assert.equal(
        actual.length,
        expected.length,
        `${vector.id}: length ${actual.length} !== ${expected.length}`,
      );

      // Element-wise compare. On first divergence, emit AC-2's debug
      // checklist. The failure message MUST contain (per must_haves
      // truth #5): (a) literal "first divergent coefficient at index",
      // (b) the numeric index K, (c) ±4 context window from BOTH actual
      // and expected as JSON-serialized arrays, (d) literal "check chunk
      // endianness", (e) literal "61445", (f) literal "mod-q".
      for (let k = 0; k < expected.length; k++) {
        if (actual[k] !== expected[k]) {
          assert.fail(formatG2DivergenceMessage(vector.id, k, actual, expected));
        }
      }
    });
  }
});

// ---------------------------------------------------------------------------
// AC-2 synthetic divergence test — validates the error-path message shape
// without mutating the real fixture. Constructs a synthetic vector whose
// `expectedHash` is derived from a real vector but with one coefficient
// deliberately wrong, runs the comparison loop inline, and asserts the
// caught error's message contains ALL six AC-2 substring anchors required
// by Story 2-2 must_haves truth #5:
//   (a) "first divergent coefficient at index"
//   (b) the numeric index K
//   (c) ±4 context window (JSON-serialized arrays from both actual and expected)
//   (d) "check chunk endianness"
//   (e) "61445"
//   (f) "mod-q"
//
// This is the AUTOMATED real-path counterpart to any ad-hoc "temporarily
// mutate the fixture" smoke test; per
// `.claude/rules/retrospect/universal.md` §"Override-based tests need a
// real-path counterpart", both the happy path (above) and the failure
// path (this block) must exist so regressions in either are caught
// automatically. Pattern mirrors `keccak-prg.falcon.kat.test.ts` AC-2.
// ---------------------------------------------------------------------------

describe("HashToPoint KAT (G2 — AC-2 error-path divergence message shape)", () => {
  it("failure message includes coeff index, ±4 context, chunk endianness, 61445, mod-q", () => {
    const vectors = loadHashToPointVectors();
    const vector = vectors[0];
    assert.ok(
      vector !== undefined,
      "synthetic divergence test requires ≥1 vector in fixture",
    );

    const salt = hexToBytes(vector.salt);
    const msg = hexToBytes(vector.message);
    const actual = hashToPointEVM(salt, msg);

    // Synthetic mismatch: copy `expectedHash` and flip one coefficient
    // at a known index (10 — well inside any ±4 context window from the
    // first differing element so both actual and expected slices are
    // non-trivial). The flipped value stays `< 12289` to ensure the
    // divergence is a value mismatch, not an AC-3 bound violation.
    const tampered: number[] = [...vector.expectedHash];
    const flipIndex = 10;
    const original = tampered[flipIndex];
    assert.ok(
      original !== undefined,
      `tampered[${flipIndex}] must be defined (vector has length ${tampered.length})`,
    );
    // New value: (original + 1) mod Q — guaranteed different and in-range.
    tampered[flipIndex] = (original + 1) % 12289;

    // Replay the comparison loop verbatim against the tampered expected.
    // Uses the same shared helper `formatG2DivergenceMessage` the real
    // per-vector loop uses, so an edit to the message template touches
    // this synthetic test automatically.
    let thrown: unknown;
    try {
      for (let k = 0; k < tampered.length; k++) {
        if (actual[k] !== tampered[k]) {
          assert.fail(formatG2DivergenceMessage(vector.id, k, actual, tampered));
        }
      }
    } catch (err) {
      thrown = err;
    }

    // Guard OUTSIDE the try block — the inner loop's `assert.fail` is also
    // an Error that the catch swallows; if the loop never threw (flipIndex
    // somehow failed to produce a divergence), the `thrown === undefined`
    // sentinel surfaces that condition through the test runner directly
    // rather than being shadowed by a caught assertion.
    assert.ok(
      thrown !== undefined,
      "expected comparison loop to throw on synthetic divergence",
    );
    assert.ok(thrown instanceof Error, "thrown value must be an Error");
    const message = (thrown as Error).message;

    // (a) "first divergent coefficient at index" literal + (b) numeric K.
    assert.match(
      message,
      /first divergent coefficient at index 10/,
      `missing coefficient-index anchor: ${message}`,
    );
    // (c) ±4 context window from both actual and expected.
    assert.match(
      message,
      /actual\s+\[\d+\.\.\d+\):\s*\[/,
      `missing actual-context slice: ${message}`,
    );
    assert.match(
      message,
      /expected\s+\[\d+\.\.\d+\):\s*\[/,
      `missing expected-context slice: ${message}`,
    );
    // (d) chunk-endianness hint.
    assert.match(
      message,
      /check chunk endianness/,
      `missing chunk-endianness hint: ${message}`,
    );
    // (e) 61445 threshold literal.
    assert.match(message, /61445/, `missing 61445 threshold hint: ${message}`);
    // (f) mod-q reduction hint.
    assert.match(message, /mod-q/, `missing mod-q hint: ${message}`);
  });
});
