/**
 * Story 5 Task 2 — G3 pk-transform KAT (AC-5-2).
 *
 * Iterates every vector in `test/fixtures/kat/mldsa-eth/vectors.json`
 * (Story 1 AC-1-1 capture) and asserts that
 * `preparePublicKeyForDeployment(rawPk, keccakXofFactory, keccakXofFactory)`
 * produces the same coefficient data as the fixture's `reshapedPublicKey`
 * field. This is the G3 oracle in the four-implementation chain (DD-11) —
 * without it, Story 5's on-chain verification (G4) would build on
 * unverified pk-transform ground.
 *
 * Reconciliation — A-004 USER-DECISION Option 1 (structural decode):
 * -------------------------------------------------------------------
 * The TS `preparePublicKeyForDeployment` output and the fixture's
 * `reshapedPublicKey` carry the SAME numeric coefficient data under
 * DIFFERENT ABI wrappers (see `docs/amendments.md` §A-004). The outer
 * `(bytes aHatEncoded, bytes tr, bytes t1Encoded)` tuple is identical
 * between the two formats, but the inner `aHat` / `t1` blobs differ:
 *
 *   TS        — `abi.encode(uint256[][][])` / `abi.encode(uint256[][])`
 *               (shape [K=4][L=4][N=256] / [K=4][N=256], one uint256 per
 *               coefficient, viem-serialised)
 *   Python    — flat 4-byte big-endian per coefficient, row-major
 *               (K*L*N*4 = 16,384 B for aHat; K*N*4 = 4,096 B for t1)
 *
 * The on-chain `ZKNOX_dilithium._readPubKey` decodes the TS-format. The
 * Python format is a fixture-storage convention. Both carry the same
 * numeric information.
 *
 * This test's oracle (USER-DECISION 2026-04-18: Option 1):
 *   1. Decode TS output outer → (aHatBlob_TS, trBlob_TS, t1Blob_TS).
 *   2. Decode aHatBlob_TS as `uint256[][][]` → `bigint[4][4][256]`;
 *      flatten to 4B-BE row-major bytes (16,384 B).
 *   3. Decode t1Blob_TS as `uint256[][]` → `bigint[4][256]`; flatten
 *      to 4B-BE row-major bytes (4,096 B).
 *   4. Decode fixture `reshapedPublicKey` outer →
 *      (aHatBlob_Py, trBlob_Py, t1Blob_Py). The Python aHat / t1 blobs
 *      are ALREADY in 4B-BE flat form.
 *   5. `assertBytesEqual(aHatFlat_TS, aHatBlob_Py, ..., "keccak-prg")` —
 *      direct byte compare surfaces the first divergent coefficient.
 *      Same for `tr` (byte-identical across the two formats) and for
 *      the `t1` flat buffer.
 *
 * Rejected: Option 2 (regenerate fixture in TS-format) — would diverge
 * fixtures from Python ground truth and add an A-007 amendment.
 *
 * Pure `node:test` — no Hardhat runtime.
 */

import { describe, it } from "node:test";

import {
  encodeMlDsaPublicKey,
  keccakXofFactory,
} from "@noble/post-quantum/utils-eth.js";
import { bytesToHex, decodeAbiParameters, type Hex, hexToBytes } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import { assertBytesEqual } from "../utils/assert-bytes.js";

// ML-DSA-44 parameter constants — FIPS 204 Table 2. Duplicated here (not
// imported) because core.ts is signer-internal and this test lives in
// the encoding surface; the constants are hardcoded on the on-chain
// ZKNOX_dilithium side regardless.
const K = 4;
const L = 4;
const N = 256;

// compactPoly256 (fork-private inside @noble/post-quantum/utils-eth.js)
// packs 8 × 32-bit coefficients into each uint256 word: coefficient i lives
// at bits [(i % 8) * 32 .. (i % 8) * 32 + 32) of packed word floor(i / 8).
// So 256 coefficients become 32 packed uint256s.
const WORDS_PER_POLY = 32;
const COEFFS_PER_WORD = 8;
const U32_MASK = 0xffffffffn;

/** Unpack one 256-bit word to 8 little-endian-ordered uint32 coefficients. */
function unpackWord(w: bigint, out: Uint8Array, writeOffset: number): void {
  let off = writeOffset;
  for (let i = 0; i < COEFFS_PER_WORD; i++) {
    const c = Number((w >> BigInt(i * 32)) & U32_MASK);
    out[off] = (c >>> 24) & 0xff;
    out[off + 1] = (c >>> 16) & 0xff;
    out[off + 2] = (c >>> 8) & 0xff;
    out[off + 3] = c & 0xff;
    off += 4;
  }
}

/**
 * Flatten the TS-format `aHat` tensor (`bigint[K][L][WORDS_PER_POLY]`
 * of `compactPoly256`-packed values) to the Python-format 4-byte big-
 * endian row-major byte buffer (`K*L*N*4 = 16,384 B`).
 */
function flatten3DPackedToBE4(
  aHat: readonly (readonly (readonly bigint[])[])[],
): Uint8Array {
  const out = new Uint8Array(K * L * N * 4);
  let off = 0;
  for (let k = 0; k < K; k++) {
    const row = aHat[k];
    if (row === undefined || row.length !== L) {
      throw new Error(
        `flatten3DPackedToBE4: row ${k} length ${row?.length} !== ${L}`,
      );
    }
    for (let l = 0; l < L; l++) {
      const packed = row[l];
      if (packed === undefined || packed.length !== WORDS_PER_POLY) {
        throw new Error(
          `flatten3DPackedToBE4: packed [${k}][${l}] length ${packed?.length} !== ${WORDS_PER_POLY}`,
        );
      }
      for (let w = 0; w < WORDS_PER_POLY; w++) {
        unpackWord(packed[w]!, out, off);
        off += COEFFS_PER_WORD * 4;
      }
    }
  }
  return out;
}

/**
 * Flatten the TS-format `t1` tensor (`bigint[K][WORDS_PER_POLY]` of
 * packed values) to the Python-format 4-byte big-endian row-major byte
 * buffer (`K*N*4 = 4,096 B`).
 */
function flatten2DPackedToBE4(t1: readonly (readonly bigint[])[]): Uint8Array {
  const out = new Uint8Array(K * N * 4);
  let off = 0;
  for (let k = 0; k < K; k++) {
    const packed = t1[k];
    if (packed === undefined || packed.length !== WORDS_PER_POLY) {
      throw new Error(
        `flatten2DPackedToBE4: packed ${k} length ${packed?.length} !== ${WORDS_PER_POLY}`,
      );
    }
    for (let w = 0; w < WORDS_PER_POLY; w++) {
      unpackWord(packed[w]!, out, off);
      off += COEFFS_PER_WORD * 4;
    }
  }
  return out;
}

describe("G3 — ml-dsa-eth pk-transform KAT (AC-5-2)", () => {
  const vectors = loadKatVectors("mldsa-eth");

  it(`all ${vectors.length} vectors: preparePublicKeyForDeployment coefficient-identical to fixture reshapedPublicKey`, () => {
    for (const v of vectors) {
      const actualHex = bytesToHex(
        encodeMlDsaPublicKey(
          hexToBytes(v.publicKey as Hex),
          keccakXofFactory,
          keccakXofFactory,
        ),
      );

      // Outer decode: both TS and Python use (bytes, bytes, bytes).
      const [aHatBlobTsHex, trBlobTsHex, t1BlobTsHex] = decodeAbiParameters(
        [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
        actualHex,
      );
      const [aHatBlobPyHex, trBlobPyHex, t1BlobPyHex] = decodeAbiParameters(
        [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
        v.reshapedPublicKey as Hex,
      );

      // Inner aHat: TS ABI-encoded uint256[][][], Python flat 4B-BE.
      // Decode TS to structured form, then flatten to Python layout for
      // byte-level compare.
      const [aHatTs] = decodeAbiParameters(
        [{ type: "uint256[][][]" }],
        aHatBlobTsHex,
      );
      const aHatFlatTs = flatten3DPackedToBE4(aHatTs);
      assertBytesEqual(
        aHatFlatTs,
        hexToBytes(aHatBlobPyHex),
        `vec ${v.id} aHat`,
        "keccak-prg",
      );

      // Inner t1: same pattern, uint256[][] → flat 4B-BE.
      const [t1Ts] = decodeAbiParameters(
        [{ type: "uint256[][]" }],
        t1BlobTsHex,
      );
      const t1FlatTs = flatten2DPackedToBE4(t1Ts);
      assertBytesEqual(
        t1FlatTs,
        hexToBytes(t1BlobPyHex),
        `vec ${v.id} t1`,
        "keccak-prg",
      );

      // tr: 64 B raw on both sides — direct byte compare.
      assertBytesEqual(
        hexToBytes(trBlobTsHex),
        hexToBytes(trBlobPyHex),
        `vec ${v.id} tr`,
        "keccak-prg",
      );
    }
  });
});
