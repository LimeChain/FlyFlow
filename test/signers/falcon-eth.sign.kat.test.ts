/**
 * Falcon-ETH G4 signer KAT byte-identity.
 *
 * **G4 IS THE signer byte-identity gate for the falcon-eth oracle chain.**
 * A byte-wrong signer poisons every downstream assertion (pk-transform G5,
 * on-chain validateUserOp G6).
 *
 * For every vector `v` returned by `loadKatVectors("falcon-eth")` (≥100):
 *   1. Build a DRBG from `rngAesCtrDrbg256(hexToBytes(v.drbgSeed))`. Advance
 *      past the 48 B keygen draw (`drbg.randomBytes(48)`) BEFORE signing;
 *      the remaining stream is the 40 B salt + 48 B FFSampler seed the
 *      Falcon signer consumes (88 B total).
 *   2. Call `falcon512paddedEth.sign(msg, sk, { random })` where `random(n)`
 *      returns `drbg.randomBytes(n)`. Re-encode the detached signature via
 *      `encodeFalconSignature` from `@noble/post-quantum/utils-eth.js`.
 *   3. Assert the returned 1064 B `Uint8Array` (40 B salt || 1024 B
 *      s2_compact) byte-equals `hexToBytes(v.signature)` from the committed
 *      fixture (`test/fixtures/kat/falcon-eth/vectors.json`; pinned
 *      submodule SHA `03ed0d60c67087527de7c4a3c1c469b89611bd68`).
 *
 * On divergence, `formatG4DivergenceMessage` surfaces the first-differing
 * byte offset, ±8 B actual vs expected context, and a two-mode hint
 * enumerating the likely divergence sources (DRBG state-advancement bug or
 * fork-side HashToPoint drift).
 *
 * Framework: `node:test` + `node:assert/strict`.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { rngAesCtrDrbg256 } from "@noble/ciphers/aes.js";
import { falcon512paddedEth } from "@noble/post-quantum/falcon.js";
import { encodeFalconSignature } from "@noble/post-quantum/utils-eth.js";
import { type Hex, bytesToHex, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { bytesEqual } from "../utils/assert-bytes.js";

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
 *   (e) two-mode divergence hint enumerating:
 *       1. DRBG state-advancement bug — hint: check that
 *          `drbg.randomBytes(48)` is called BEFORE the sign call
 *          (advances past keygen's inner_seed draw).
 *       2. Fork-side HashToPoint drift — hint: verify
 *          `falcon512paddedEth` (from `@noble/post-quantum/falcon.js`)
 *          is correctly wired to `hashToPointEVM` from
 *          `@noble/post-quantum/utils-eth.js` (Keccak-256 counter mode).
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
    `  G4 divergence — likely root causes (enumerate on >1 vector failing):\n` +
    `    1. DRBG state-advancement bug — hint: check that ` +
    `drbg.randomBytes(48) is called BEFORE the sign call ` +
    `(advances past keygen's inner_seed draw; the remaining stream is ` +
    `40 B salt + 48 B FFSampler seed = 88 B total).\n` +
    `    2. Fork-side HashToPoint drift — hint: verify ` +
    `falcon512paddedEth (from @noble/post-quantum/falcon.js) is wired to ` +
    `hashToPointEVM from @noble/post-quantum/utils-eth.js.\n`
  );
}

describe("Falcon-ETH signer G4 KAT byte-identity", () => {
  const vectors = loadKatVectors("falcon-eth");

  it(`iterates all ${vectors.length} vectors (floor: ≥100)`, () => {
    assert.ok(
      vectors.length >= 100,
      `expected ≥100 vectors, got ${vectors.length}`,
    );
  });

  // Noble's `Falcon` type declares `sign` via the generic `Signer` shape
  // (`SigOpts` — no `random`). At runtime, `genFalcon` wires the
  // Falcon-specific `FalconSigOpts` which accepts a `random` callback.
  // The local cast names the wider contract without reaching into the
  // fork's private types.
  const signWithRandom = falcon512paddedEth.sign as (
    msg: Uint8Array,
    secretKey: Uint8Array,
    opts: { random: (n?: number) => Uint8Array },
  ) => Uint8Array;

  for (const v of vectors) {
    it(`vec ${v.id}: falcon512paddedEth.sign → encodeFalconSignature matches v.signature byte-for-byte`, () => {
      const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));
      // Advance past keygen's 48 B innerSeed draw. The remaining DRBG stream
      // feeds the signer (40 B salt + 48 B FFSampler seed).
      drbg.randomBytes(48);

      const nobleSig = signWithRandom(
        hexToBytes(v.message as Hex),
        hexToBytes(v.secretKey as Hex),
        { random: (n?: number): Uint8Array => drbg.randomBytes(n ?? 0) },
      );
      const actual = encodeFalconSignature(nobleSig);
      const expected = hexToBytes(v.signature as Hex);

      if (!bytesEqual(actual, expected)) {
        assert.fail(formatG4DivergenceMessage(v.id, actual, expected));
      }
    });
  }
});
