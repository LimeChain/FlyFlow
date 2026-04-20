/**
 * Falcon-ETH G5 pk-transform KAT structural coefficient-equality
 * (Story 2-4 Task T1; AC-1 + AC-2; amended by A-007).
 *
 * For every vector `v` returned by `loadKatVectors("falcon-eth")` (≥100):
 *   1. AC-1 (amended by A-007) —
 *      `decodeAbiParameters([{type:"uint256[]"}],
 *          preparePublicKeyForDeployment(hexToBytes(v.publicKey), keccakXofFactory))`
 *      returns a `bigint[]` element-wise equal to
 *      `decodeAbiParameters([{type:"uint256[32]"}], v.reshapedPublicKey)`.
 *
 *      The two ABI encodings are incidentally different wrappers around the
 *      same 32 `uint256` coefficients. Fixture encodes as fixed `uint256[32]`
 *      (1024 B; matches Python ref `ETHFALCON/pythonref/sig_sol.py:48`);
 *      `preparePublicKeyForDeployment` emits dynamic `uint256[]` (1088 B;
 *      required by on-chain `ZKNOX_ethfalcon.setKey` via `abi.decode(data,
 *      (uint256[]))`). The 64 B delta is the dynamic-array `[offset][length]`
 *      prefix. Structural coefficient-equality is the semantic oracle — see
 *      `docs/amendments.md` §A-007 for root cause, precedent
 *      (`test/signers/mldsa-encoding.pk-transform.kat.test.ts:146-204`), and
 *      the architecture divergence-probe anchor
 *      (`docs/architecture.md:199`).
 *
 *   2. AC-2 — `pkToNttCompact(hexToBytes(v.publicKey), keccakXofFactory)`
 *      returns a `bigint[]` of length 32 where every element `< 2^256`.
 *
 * THIS IS THE G5 GATE — the pk-transform empirical guard against DD drift
 * between falcon and falcon-eth pk encodings. Without it, Story 2-4's on-chain
 * `validateUserOp` path (G6) would build on unverified pk-transform ground.
 *
 * Binding notes (see docs/stories/2-4.md §"Architecture Guardrails §G5"):
 *   - The `xofFactory` parameter is present for NFR-11 cross-scheme symmetry
 *     with ml-dsa-eth's two-factory `preparePublicKeyForDeployment`. Falcon-ETH
 *     itself does NOT consume the factory internally because its forward NTT
 *     is deterministic over the 897-byte raw public key (no XOF-driven
 *     ingestion at pk-transform time). The parameter exists so a future
 *     NFR-11 structural grep sees the same function shape across schemes.
 *   - Both new exports delegate to `encodePublicKeyForZKNOX` at
 *     `test/signers/falcon-encoding.ts:128` — the raw→NTT→compact→`abi.encode`
 *     transform is already correct for falcon and the coefficient-difference
 *     between falcon and falcon-eth at the pk-transform layer is ZERO per DD.
 *     AC-1 is the empirical guard against any future DD drift.
 *
 * Framework: `node:test` + `node:assert/strict` — matches sibling KAT tests
 * (`falcon-eth.keygen.kat.test.ts`, `falcon-eth.sign.kat.test.ts`,
 * `mldsa-encoding.pk-transform.kat.test.ts`).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { decodeAbiParameters, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import {
  pkToNttCompact,
  preparePublicKeyForDeployment,
} from "./falcon-eth.core.js";
import { keccakXofFactory } from "./mldsa-encoding.js";

/** AC-2 structural bound: every compact element < 2^256. */
const UINT256_BOUND = 1n << 256n;
/** AC-2 structural bound: compact `bigint[]` length = 32 (= 16 coeffs × 14-bit-padded-to-16 × 512 / 256). */
const EXPECTED_COMPACT_WORDS = 32;

/**
 * Shared failure-message template for G5 pk-transform coefficient divergence.
 *
 * Single source of truth for the divergence-message shape — per
 * `.claude/rules/retrospect/typescript.md` §"[2026-04-20] Duplicated
 * failure-message templates", the helper is extracted to module scope so any
 * future synthetic divergence test references the same template as the real
 * per-vector loop.
 *
 * Reports the first-differing `uint256` coefficient index with ±3 neighbours
 * on each side, followed by a three-cause hint block. Coefficient-level
 * reporting (not byte-offset) because A-007 made structural decode the oracle;
 * a byte offset inside an ABI-encoded blob would not be actionable for
 * debugging (the ABI wrapper layout is not where bugs hide).
 *
 * Required substring anchors (for future regression debuggability):
 *   (a) vector id (e.g. `vec-000`)
 *   (b) first-differing coefficient index
 *   (c) ±3 coefficients actual-bigint window at that index
 *   (d) ±3 coefficients expected-bigint window at that index
 *   (e) three-cause hint line naming the most likely port-bug sources in
 *       prior-probability order:
 *         1. falcon-encoding drift (`encodePublicKeyForZKNOX` at
 *            `falcon-encoding.ts:128` — the delegation target)
 *         2. fixture regenerated under a different submodule SHA
 *            (check `FalconKatVectorsFile.submoduleSha` vs `.gitmodules`)
 *         3. DD drift between falcon and falcon-eth pk encodings
 *            (would break the delegate-to-`encodePublicKeyForZKNOX` design)
 */
function formatG5DivergenceMessage(
  vectorId: string,
  actual: readonly bigint[],
  expected: readonly bigint[],
): string {
  const commonLen = Math.min(actual.length, expected.length);
  let idx = -1;
  for (let i = 0; i < commonLen; i++) {
    if (actual[i] !== expected[i]) {
      idx = i;
      break;
    }
  }
  if (idx === -1) idx = commonLen;

  const start = Math.max(0, idx - 3);
  const endA = Math.min(actual.length, idx + 4);
  const endE = Math.min(expected.length, idx + 4);
  const ctxActual = actual.slice(start, endA).map((w) => `0x${w.toString(16)}`);
  const ctxExpected = expected
    .slice(start, endE)
    .map((w) => `0x${w.toString(16)}`);

  return (
    `${vectorId}: reshapedPublicKey first-differing coefficient at index ${idx} ` +
    `(actual.length=${actual.length}, expected.length=${expected.length})\n` +
    `  actual   [${start}..${endA}): ${ctxActual.join(", ")}\n` +
    `  expected [${start}..${endE}): ${ctxExpected.join(", ")}\n` +
    `\n` +
    `  G5 divergence — likely root causes (prior-probability order):\n` +
    `    1. encodePublicKeyForZKNOX drift — check test/signers/falcon-encoding.ts:128 ` +
    `(delegation target; the raw→NTT→compact→abi.encode transform)\n` +
    `    2. fixture regenerated under a different submodule SHA — ` +
    `check FalconKatVectorsFile.submoduleSha vs .gitmodules (pinned 03ed0d60c67087527de7c4a3c1c469b89611bd68)\n` +
    `    3. DD drift between falcon and falcon-eth pk encodings — ` +
    `would break the delegate-to-encodePublicKeyForZKNOX design\n`
  );
}

describe("Falcon-ETH pk-transform G5 KAT structural coefficient-equality (AC-1 amended by A-007) + structural sub-check (AC-2)", () => {
  const vectors = loadKatVectors("falcon-eth");

  it(`iterates ≥100 vectors (loaded ${vectors.length})`, () => {
    assert.ok(
      vectors.length >= 100,
      `expected ≥100 vectors, got ${vectors.length}`,
    );
  });

  // AC-2 — structural sub-check. Run ONCE across all vectors in a single `it`
  // block. Every vector's `pkToNttCompact` output must be `bigint[]` of length
  // 32 with every element < 2^256. The same loop also happens to exercise the
  // `pkToNttCompact` code path over the full corpus (belt-and-braces for the
  // AC-1 delegation — if `pkToNttCompact` silently diverged from the inner
  // transform `preparePublicKeyForDeployment` composes, both AC-1 and AC-2
  // would surface the bug, but AC-2 localises the failure to the pre-
  // `abi.encode` layer).
  it(`AC-2 — pkToNttCompact returns bigint[] of length ${EXPECTED_COMPACT_WORDS}, every element < 2^256 (all ${vectors.length} vectors)`, () => {
    for (const v of vectors) {
      const rawPk = hexToBytes(v.publicKey);
      const compact = pkToNttCompact(rawPk, keccakXofFactory);

      assert.equal(
        compact.length,
        EXPECTED_COMPACT_WORDS,
        `vec ${v.id}: pkToNttCompact length ${compact.length} !== ${EXPECTED_COMPACT_WORDS}`,
      );

      for (let i = 0; i < compact.length; i++) {
        const word = compact[i];
        assert.ok(
          typeof word === "bigint",
          `vec ${v.id}: pkToNttCompact[${i}] type ${typeof word} !== "bigint"`,
        );
        assert.ok(
          word < UINT256_BOUND,
          `vec ${v.id}: pkToNttCompact[${i}]=${word} >= 2^256`,
        );
      }
    }
  });

  // AC-1 (amended by A-007) — per-vector structural coefficient-equality.
  // One `it` block per vector so a single-vector regression does not mask
  // the rest of the corpus (matches the `falcon-eth.keygen.kat.test.ts`
  // pattern). Both sides decoded to `bigint[]` then compared element-wise;
  // fixture uses `uint256[32]` (fixed, 1024 B); our emit uses `uint256[]`
  // (dynamic, 1088 B). See A-007 for the oracle-shape rationale.
  for (const v of vectors) {
    it(`vec ${v.id}: preparePublicKeyForDeployment coefficient-equals reshapedPublicKey`, () => {
      const rawPk = hexToBytes(v.publicKey);
      const actualHex = preparePublicKeyForDeployment(rawPk, keccakXofFactory);

      const [actualCoeffs] = decodeAbiParameters(
        [{ type: "uint256[]" }],
        actualHex,
      );
      const [expectedCoeffs] = decodeAbiParameters(
        [{ type: "uint256[32]" }],
        v.reshapedPublicKey,
      );

      // Structural oracle: element-wise bigint equality. The two ABI wrappers
      // (dynamic vs fixed) differ by 64 B but hold the same 32 coefficients.
      if (
        actualCoeffs.length !== expectedCoeffs.length ||
        !actualCoeffs.every((w, i) => w === expectedCoeffs[i])
      ) {
        assert.fail(
          formatG5DivergenceMessage(v.id, actualCoeffs, expectedCoeffs),
        );
      }
    });
  }
});
