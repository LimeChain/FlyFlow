/**
 * Falcon-ETH G4 signer KAT byte-identity (Story 2-3 Task T4; AC-1 + AC-6).
 *
 * **G4 IS THE signer byte-identity gate for the falcon-eth oracle chain.**
 * Downstream Story 2-4 (integration + G5 pk-transform + G6 on-chain
 * validateUserOp) consumes G4's signer surface; a byte-wrong signer poisons
 * every downstream assertion.
 *
 * For every vector `v` returned by `loadKatVectors("falcon-eth")` (≥100):
 *   1. Derive a `BytesReader` from
 *      `rngAesCtrDrbg256(hexToBytes(v.drbgSeed))` — TS-side DRBG replay per
 *      `docs/amendments.md` §A-005 "DRBG derivation contract". Advance past
 *      the 48 B keygen draw (`drbg.randomBytes(48)`) BEFORE wiring the
 *      reader; the remaining stream is the 40 B salt + 48 B FFSampler seed
 *      noble's `signRaw` consumes per §A-005 "signingDrbg byte
 *      decomposition" (88 B total).
 *   2. Call `signWithKatBytes(hexToBytes(v.secretKey),
 *      hexToBytes(v.message), reader)` — routes through the
 *      HashToPoint-injected `falcon512paddedEth` per
 *      `docs/amendments.md` §A-006 Strategy E (fork-side injection), then
 *      re-encodes via `encodeSignatureForZKNOX` (Story 2-2).
 *   3. Assert the returned 1064 B `Uint8Array` (40 B salt || 1024 B
 *      s2_compact) byte-equals `hexToBytes(v.signature)` from the committed
 *      fixture (`test/fixtures/kat/falcon-eth/vectors.json`; pinned
 *      submodule SHA `03ed0d60c67087527de7c4a3c1c469b89611bd68`).
 *
 * On divergence, `formatG4DivergenceMessage` surfaces the first-differing
 * byte offset, ±8 B actual vs expected context, AND an AC-6 hint enumerating
 * the two likely divergence modes (A-005-equivalent DRBG state-advancement
 * bug OR fork-side HashToPoint injection bug) with a pointer to
 * `docs/amendments.md` §A-006 for logging.
 *
 * Framework: `node:test` + `node:assert/strict` — matches sibling KAT tests
 * (`falcon-eth.keygen.kat.test.ts`, `ml-dsa-eth.sign.kat.test.ts`).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { rngAesCtrDrbg256 } from "@noble/ciphers/aes.js";
import { type Hex, bytesToHex, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { bytesEqual } from "../utils/assert-bytes.js";
import {
  type BytesReader,
  signWithKatBytes,
} from "./falcon-eth.kat-internal.js";

/**
 * Shared failure-message template for G4 signature-divergence.
 *
 * Single source of truth for the divergence-message shape — per
 * `.claude/rules/retrospect/typescript.md` §"[2026-04-20] Duplicated
 * test-file code", the helper is extracted to module scope so the template
 * does not copy-paste-drift across call sites.
 *
 * Required substring anchors (for future regression debuggability):
 *   (a) vector id (e.g. `vec-000`)
 *   (b) first-differing byte offset
 *   (c) ±8 bytes actual-hex window at that offset
 *   (d) ±8 bytes expected-hex window at that offset
 *   (e) AC-6 two-mode divergence hint enumerating:
 *       1. DRBG state-advancement bug à la A-005 — hint: check that
 *          `drbg.randomBytes(48)` is called BEFORE the reader is wired
 *          (advances past keygen's inner_seed draw per A-005).
 *       2. Fork-side HashToPoint injection bug — hint: verify
 *          `falcon512paddedEth` spreads `falcon512paddedOpts` (for
 *          `maxS2Len: 625` + `padded: true`) AND sets
 *          `hashToPoint: hashToPointEVM`; verify the fork's branch
 *          `falcon-eth-hashtopoint-injection` is pushed (not local-only).
 *   (f) pointer to `docs/amendments.md` §A-006 for logging.
 */
function formatG4DivergenceMessage(
  vectorId: string,
  actual: Uint8Array,
  expected: Uint8Array,
): string {
  // Locate first-differing byte. If lengths mismatch, report at the shorter
  // length's boundary; otherwise scan for the first inequality.
  const commonLen = Math.min(actual.length, expected.length);
  let offset = -1;
  for (let i = 0; i < commonLen; i++) {
    if (actual[i] !== expected[i]) {
      offset = i;
      break;
    }
  }
  if (offset === -1) offset = commonLen; // length-only divergence past common prefix

  const start = Math.max(0, offset - 8);
  const endA = Math.min(actual.length, offset + 9);
  const endE = Math.min(expected.length, offset + 9);
  const ctxActual = bytesToHex(actual.slice(start, endA));
  const ctxExpected = bytesToHex(expected.slice(start, endE));

  return (
    `${vectorId}: signature first-differing byte at offset ${offset} ` +
    `(actual.length=${actual.length}, expected.length=${expected.length})\n` +
    `  actual   [${start}..${endA}): ${ctxActual}\n` +
    `  expected [${start}..${endE}): ${ctxExpected}\n` +
    `\n` +
    `  G4 divergence — AC-6 likely root causes (enumerate on >1 vector failing):\n` +
    `    1. DRBG state-advancement bug à la A-005 — hint: check that ` +
    `drbg.randomBytes(48) is called BEFORE the reader is wired ` +
    `(advances past keygen's inner_seed draw per docs/amendments.md §A-005 ` +
    `"DRBG derivation contract"; see "signingDrbg byte decomposition" for the ` +
    `40 B salt + 48 B FFSampler seed = 88 B budget).\n` +
    `    2. Fork-side HashToPoint injection bug — hint: verify ` +
    `falcon512paddedEth is constructed by spreading falcon512paddedOpts ` +
    `(which supplies maxS2Len: 625 + padded: true from the fork) AND setting ` +
    `hashToPoint: hashToPointEVM; verify the fork's branch ` +
    `falcon-eth-hashtopoint-injection is pushed (not local-only).\n` +
    `  See docs/amendments.md §A-006 (Strategy E fork injection) for logging.\n`
  );
}

describe("Falcon-ETH signer G4 KAT byte-identity (AC-1 / AC-6)", () => {
  const vectors = loadKatVectors("falcon-eth");

  it(`iterates all ${vectors.length} vectors (floor: ≥100)`, () => {
    assert.ok(
      vectors.length >= 100,
      `expected ≥100 vectors, got ${vectors.length}`,
    );
  });

  for (const v of vectors) {
    it(`vec ${v.id}: signWithKatBytes matches v.signature byte-for-byte`, () => {
      const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));
      // A-005 DRBG derivation contract — advance past keygen's 48 B innerSeed
      // draw (see docs/amendments.md §A-005 "signingDrbg byte decomposition").
      drbg.randomBytes(48);
      const reader: BytesReader = {
        read: (n: number): Uint8Array => drbg.randomBytes(n),
      };

      const actual = signWithKatBytes(
        hexToBytes(v.secretKey as Hex),
        hexToBytes(v.message as Hex),
        reader,
      );
      const expected = hexToBytes(v.signature as Hex);

      if (!bytesEqual(actual, expected)) {
        assert.fail(formatG4DivergenceMessage(v.id, actual, expected));
      }
    });
  }
});
