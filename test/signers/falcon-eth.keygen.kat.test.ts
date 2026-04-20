/**
 * Falcon-ETH G3 keygen KAT byte-identity (Story 2-1 Task T3; AC-1).
 *
 * For every vector `v` returned by `loadKatVectors("falcon-eth")` (≥100):
 *   1. Derive `innerSeed = rngAesCtrDrbg256(hexToBytes(v.drbgSeed)).randomBytes(48)`
 *      — TS-side DRBG replay per `docs/amendments.md` §A-005 "DRBG derivation
 *      contract". `@noble/ciphers#rngAesCtrDrbg256` is byte-identical to
 *      ETHFALCON's Python `AES256_CTR_DRBG` (A-005 Evidence §5; vec-0
 *      `innerSeed` starts with `0x7c9935a0b07694aa…`).
 *   2. Call `keygenInternal(innerSeed)` (Task T2 wrapper around
 *      `@noble/post-quantum/falcon.js#falcon512.keygen`).
 *   3. Assert `publicKey` (897 B) and `secretKey` (1281 B) are byte-identical
 *      to `hexToBytes(v.publicKey)` / `hexToBytes(v.secretKey)` from the
 *      committed fixture (`test/fixtures/kat/falcon-eth/vectors.json`;
 *      pinned submodule SHA `03ed0d60c67087527de7c4a3c1c469b89611bd68`).
 *
 * This IS the G3 gate — without it, downstream Stories 2-3 (signer G4) and
 * 2-4 (integration G5) would build on unverified keygen ground.
 *
 * Framework: `node:test` + `node:assert/strict` — matches sibling KAT tests
 * (`falcon-eth.core.kat.test.ts`, `keccak-prg.falcon.kat.test.ts`).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { rngAesCtrDrbg256 } from "@noble/ciphers/aes.js";
import { bytesToHex, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { bytesEqual } from "../utils/assert-bytes.js";
import { keygenInternal } from "./falcon-eth.kat-internal.js";

/**
 * Shared failure-message template for G3 pk/sk divergence.
 *
 * Single source of truth for the divergence-message shape — per
 * `.claude/rules/retrospect/typescript.md` §"[2026-04-20] Duplicated
 * failure-message templates", the helper is extracted to module scope so any
 * future synthetic divergence test references the same template as the real
 * per-vector loop.
 *
 * Required substring anchors (for future regression debuggability):
 *   (a) vector id (e.g. `vec-000`)
 *   (b) field name (`publicKey` or `secretKey`)
 *   (c) first-differing byte offset
 *   (d) ±4 bytes actual-hex window at that offset
 *   (e) ±4 bytes expected-hex window at that offset
 *   (f) three-cause hint line naming the most likely port-bug sources in
 *       prior-probability order:
 *         1. noble version drift (`@noble/post-quantum` / `@noble/ciphers` pin)
 *         2. `rngAesCtrDrbg256` semantics divergence from Python's
 *            `AES256_CTR_DRBG` (A-005 Evidence §5 vec-0 anchor still holds?)
 *         3. fixture regenerated under a different submodule SHA
 *            (check `FalconKatVectorsFile.submoduleSha` vs `.gitmodules`)
 */
function formatG3DivergenceMessage(
  vectorId: string,
  field: "publicKey" | "secretKey",
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

  const start = Math.max(0, offset - 4);
  const endA = Math.min(actual.length, offset + 5);
  const endE = Math.min(expected.length, offset + 5);
  const ctxActual = bytesToHex(actual.slice(start, endA));
  const ctxExpected = bytesToHex(expected.slice(start, endE));

  return (
    `${vectorId}: ${field} first-differing byte at offset ${offset} ` +
    `(actual.length=${actual.length}, expected.length=${expected.length})\n` +
    `  actual   [${start}..${endA}): ${ctxActual}\n` +
    `  expected [${start}..${endE}): ${ctxExpected}\n` +
    `\n` +
    `  G3 divergence — likely root causes (prior-probability order):\n` +
    `    1. noble version drift — check @noble/post-quantum / @noble/ciphers pins in package.json\n` +
    `    2. rngAesCtrDrbg256 semantics diverged from Python AES256_CTR_DRBG — ` +
    `verify A-005 Evidence §5 vec-0 anchor: innerSeed starts 0x7c9935a0b07694aa…\n` +
    `    3. fixture regenerated under a different submodule SHA — ` +
    `check FalconKatVectorsFile.submoduleSha vs .gitmodules (pinned 03ed0d60c67087527de7c4a3c1c469b89611bd68)\n`
  );
}

describe("Falcon-ETH keygen G3 KAT byte-identity (AC-1)", () => {
  const vectors = loadKatVectors("falcon-eth");

  it(`iterates ≥100 vectors (loaded ${vectors.length})`, () => {
    assert.ok(
      vectors.length >= 100,
      `expected ≥100 vectors, got ${vectors.length}`,
    );
  });

  for (const v of vectors) {
    it(`vec ${v.id}: keygenInternal(rngAesCtrDrbg256(drbgSeed).randomBytes(48)) byte-equals .rsp pk+sk`, () => {
      const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));
      const innerSeed = drbg.randomBytes(48);
      const { publicKey, secretKey } = keygenInternal(innerSeed);
      const expectedPk = hexToBytes(v.publicKey);
      const expectedSk = hexToBytes(v.secretKey);
      if (!bytesEqual(publicKey, expectedPk)) {
        assert.fail(
          formatG3DivergenceMessage(v.id, "publicKey", publicKey, expectedPk),
        );
      }
      if (!bytesEqual(secretKey, expectedSk)) {
        assert.fail(
          formatG3DivergenceMessage(v.id, "secretKey", secretKey, expectedSk),
        );
      }
    });
  }
});
