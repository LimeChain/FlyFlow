/**
 * Keccak-PRG G0 KAT tier (Story 2, Task 2).
 *
 * Byte-identity tests against the committed PRG KAT fixture
 * (`test/fixtures/kat/keccak-prg/vectors.json`) — 8 vectors total:
 *   - 4 `zhenfei-canonical-*` (Layer 1: ZKNox Forge test hex literals,
 *     already witnessed C equivalent to Solidity upstream)
 *   - 4 `python-ref-extended` (Layer 2: Python ref generator, extends
 *     coverage to cross-extract, multi-inject, empty-seed, ML-DSA-shape)
 *
 * For each fixture: construct a fresh `createKeccakPrg()`, replay the
 * scripted `injects[]`/`flip`/`extracts[]` sequence, and assert bytes
 * match either `expected[i]` (per-call) or the `expected_slices` (for
 * vectors exposing block-stream slices rather than full concatenation).
 *
 * ACs covered:
 *   - AC-2-1 (G0 Layer 1 canonical — NFR-9)
 *   - AC-2-2 (G0 Layer 2 cross-extract; `prg-cross-extract` fixture)
 *   - AC-2-3 (G0 Layer 2 absorb concatenation; `prg-multi-inject` fixture)
 *
 * Framework: `node:test` + `node:assert/strict` — matches
 * `test/signers/keccak-prg.test.ts` and `test/fixtures/kat/index.test.ts`.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { bytesToHex, hexToBytes } from "viem";

import { loadPrgVectors } from "../fixtures/kat/index.js";
import { createKeccakPrg } from "@noble/post-quantum/utils-eth.js";

describe("Keccak-PRG KAT (G0 — byte-identity against Python ref + Zhenfei C canonical)", () => {
  for (const vector of loadPrgVectors()) {
    it(`${vector.id} (${vector.source}): byte-identical inject/flip/extract sequence`, () => {
      const prg = createKeccakPrg();
      for (const injectHex of vector.injects) {
        prg.inject(hexToBytes(injectHex as `0x${string}`));
      }
      prg.flip();

      const outputs: Uint8Array[] = [];
      for (const n of vector.extracts) {
        outputs.push(prg.extract(n));
      }

      // Assert `expected[]` in full whenever present — the strongest
      // byte-identity check. Then additionally assert any `expected_slices`,
      // which provide audit-trail anchors against the Solidity-API reference
      // (per-block `pool` reads in ZKNox's Forge test). Both come from the
      // same generator; asserting both additively is stronger than either
      // alone and costs nothing.
      if (vector.expected !== undefined && vector.expected.length > 0) {
        assert.equal(
          outputs.length,
          vector.expected.length,
          `${vector.id}: extract count (${outputs.length}) ≠ expected count (${vector.expected.length})`,
        );
        for (let i = 0; i < outputs.length; i++) {
          const actual = outputs[i];
          const expected = vector.expected[i];
          assert.ok(actual !== undefined, `${vector.id}: missing output[${i}]`);
          assert.ok(
            expected !== undefined,
            `${vector.id}: missing expected[${i}]`,
          );
          assert.equal(
            bytesToHex(actual),
            expected,
            `${vector.id}: extract[${i}] (length ${vector.extracts[i]}) mismatch`,
          );
        }
      }

      if (vector.expected_slices !== undefined) {
        // Block-stream representation from ZKNox's Forge test mirrors: concat
        // all extract outputs, compare the documented slices (often per-block
        // `pool` reads, e.g., high-32-B or high-16-B of each 32-B block).
        // Redundant with `expected[]` when both present, but keeps the audit
        // trail to the Solidity reference auditable.
        const total = outputs.reduce((acc, o) => acc + o.length, 0);
        const concat = new Uint8Array(total);
        let offset = 0;
        for (const o of outputs) {
          concat.set(o, offset);
          offset += o.length;
        }
        for (const slice of vector.expected_slices) {
          const actual = concat.subarray(slice.from, slice.to);
          assert.equal(
            bytesToHex(actual),
            slice.value,
            `${vector.id}: slice [${slice.from}..${slice.to}) mismatch`,
          );
        }
      }
    });
  }
});
