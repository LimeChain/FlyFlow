/**
 * G1 KAT — ml-dsa-eth keygen byte-identity (AC-3-1).
 *
 * Iterates every vector in `test/fixtures/kat/mldsa-eth/vectors.json`
 * (100 records captured via Python `_keygen_internal(zeta,
 * _xof=Keccak256PRNG, _xof2=Keccak256PRNG)`) and asserts that the
 * fork's `ml_dsa44eth.keygen(zeta)` produces byte-identical
 * `(publicKey, secretKey)` to the stored fields. This is the G1 gate
 * in the four-implementation oracle chain (DD-11); without it, the
 * signer-side work would build on unverified keygen ground.
 *
 * Post-fork-extraction routing: `ml_dsa44eth` in the fork internally
 * drives every XOF call-site through `keccakXofFactory` (single-factory
 * collapse per DD-1). The earlier repo-side `keygenInternal` wrapper
 * at `ml-dsa-eth.kat-internal.ts` was removed; tests now call noble's
 * `DSA.keygen` surface directly.
 *
 * Assertion uses `assertBytesEqual` from `test/utils/assert-bytes.ts`
 * with `xofId = "keccak-prg"` so any divergence surfaces
 * `(factory=keccak-prg)` — the AC-3-4 discriminant.
 */

import { describe, it } from "node:test";

import { ml_dsa44eth } from "@noble/post-quantum/ml-dsa.js";
import { bytesToHex, type Hex, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { assertBytesEqual } from "../utils/assert-bytes.js";

describe("ml-dsa-eth keygen G1 KAT (AC-3-1)", () => {
  const vectors = loadKatVectors("mldsa-eth");

  it("all 100 KAT vectors: ml_dsa44eth.keygen(zeta) matches (publicKey, secretKey) byte-for-byte", () => {
    for (const v of vectors) {
      const zeta = hexToBytes(v.zeta as Hex);
      const { publicKey, secretKey } = ml_dsa44eth.keygen(zeta);
      const expectedPk = hexToBytes(v.publicKey as Hex);
      const expectedSk = hexToBytes(v.secretKey as Hex);
      assertBytesEqual(
        publicKey,
        expectedPk,
        `vec ${v.id} publicKey`,
        "keccak-prg",
      );
      assertBytesEqual(
        secretKey,
        expectedSk,
        `vec ${v.id} secretKey`,
        "keccak-prg",
      );
      // Sanity: the hex round-trip matches as an extra anchor; `assertBytesEqual`
      // already covers byte-level divergence, but asserting the hex round-trip
      // explicitly catches any unexpected shape change in `bytesToHex`.
      if (bytesToHex(publicKey) !== v.publicKey) {
        throw new Error(`vec ${v.id}: hex round-trip mismatch on publicKey`);
      }
    }
  });
});
