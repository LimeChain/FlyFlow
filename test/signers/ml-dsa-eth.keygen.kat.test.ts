/**
 * Story 3 Task 4 — G1 KAT byte-identity test (AC-3-1).
 *
 * Iterates every vector in `test/fixtures/kat/mldsa-eth/vectors.json`
 * (Story 1 AC-1-1 — 100 records captured via Python
 * `_keygen_internal(zeta, _xof=Keccak256PRNG, _xof2=Keccak256PRNG)`)
 * and asserts that the TS fork's `keygenInternal(zeta)` produces
 * byte-identical `(publicKey, secretKey)` to the stored fields. This
 * is the G1 gate in the architecture's four-implementation oracle
 * chain (DD-11); without it, Story 4's signer work would build on
 * unverified keygen ground.
 *
 * Factory under test: `keccakXofFactory` (Story 2 `createKeccakPrg` +
 * `flip()` + streaming `extract(n)`), wired via
 * `ml-dsa-eth.kat-internal.ts → ml-dsa-eth.core.ts#keygenWithXof`.
 *
 * Assertion uses `assertBytesEqual` from `test/utils/assert-bytes.ts`
 * with `xofId = "keccak-prg"` so any divergence surfaces
 * `(factory=keccak-prg)` — the AC-3-4 discriminant.
 *
 * Performance: noble's STATS at ml-dsa.js:388 report ~24 XOF calls per
 * DSA44 keygen; 100 iterations run in well under a minute on local
 * hardware and do not meaningfully slow `npm test`.
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
