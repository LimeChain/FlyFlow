import { shake128, shake256 } from "@noble/hashes/sha3.js";
import { genCrystals } from "@noble/post-quantum/_crystals.js";
import { bytesToHex, encodeAbiParameters, type Hex } from "viem";

// ML-DSA-44 (NIST FIPS 204) parameters; matches ETHDILITHIUM submodule
// constants k=4, l=4 at ETHDILITHIUM/src/ZKNOX_dilithium_utils.sol:44-45.
const N = 256;
const Q = 8380417;
const K = 4;
const L = 4;
const D = 13; // FIPS 204 Table 1: dropped low bits in Power2Round
const RHO_BYTES = 32;
const T1_POLY_BYTES = 320; // 256 coeffs * 10 bits = 2560 bits
const TR_BYTES = 64;
const PUBLIC_KEY_BYTES = RHO_BYTES + K * T1_POLY_BYTES; // 1312
const COMPACT_BITS = 32;

// Reuse noble's NTT machinery (FIPS 204 §7.5 BitRev_8 zetas, ROOT_OF_UNITY=1753,
// F=256^-1 mod q). ZKNOX stores t1 in the NTT domain after a 2^d shift —
// see noble's verify at ml-dsa.js:560 `MultiplyNTTs(NTT.encode(polyShiftl(t1[i])), c)`,
// which the on-chain verifier expects to be PRE-COMPUTED in the pubkey.
const F_INV = 8347681; // 256^-1 mod q
const noblePqCrystals = genCrystals({
  N,
  Q,
  F: F_INV,
  ROOT_OF_UNITY: 1753,
  newPoly: (n: number) => new Int32Array(n),
  isKyber: false,
  brvBits: 8,
});

export interface DecodedPublicKey {
  rho: Uint8Array;
  t1: number[][];
  tr: Uint8Array;
}

function rejectionSamplePoly(rho: Uint8Array, i: number, j: number): number[] {
  const seed = new Uint8Array(rho.length + 2);
  seed.set(rho, 0);
  seed[rho.length] = j;
  seed[rho.length + 1] = i;

  const xof = shake128.create();
  xof.update(seed);

  const r = new Array<number>(N).fill(0);
  let idx = 0;

  while (idx < N) {
    const buf = new Uint8Array(3 * 64);
    xof.xofInto(buf);

    for (let k = 0; idx < N && k <= buf.length - 3; k += 3) {
      let t = buf[k]! | (buf[k + 1]! << 8) | (buf[k + 2]! << 16);
      t &= 0x7fffff;
      if (t < Q) r[idx++] = t;
    }
  }

  return r;
}

export function recoverAhat(rho: Uint8Array, k: number, l: number): number[][][] {
  const aHat: number[][][] = [];
  for (let i = 0; i < k; i++) {
    const row: number[][] = [];
    for (let j = 0; j < l; j++) {
      row.push(rejectionSamplePoly(rho, i, j));
    }
    aHat.push(row);
  }
  return aHat;
}

function polyDecode10Bits(bytes: Uint8Array): number[] {
  const poly = new Array<number>(N).fill(0);
  let r = 0n;
  for (let i = 0; i < bytes.length; i++) r |= BigInt(bytes[i]!) << BigInt(8 * i);
  const mask = (1n << 10n) - 1n;
  for (let i = 0; i < N; i++) {
    poly[i] = Number((r >> BigInt(i * 10)) & mask);
  }
  return poly;
}

export function decodePublicKey(publicKey: Uint8Array): DecodedPublicKey {
  if (publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(
      `Invalid ML-DSA-44 publicKey length: expected ${PUBLIC_KEY_BYTES}, got ${publicKey.length}`,
    );
  }

  const rho = publicKey.slice(0, RHO_BYTES);

  const t1: number[][] = [];
  for (let i = 0; i < K; i++) {
    const offset = RHO_BYTES + i * T1_POLY_BYTES;
    t1.push(polyDecode10Bits(publicKey.slice(offset, offset + T1_POLY_BYTES)));
  }

  const tr = shake256(new Uint8Array(publicKey), { dkLen: TR_BYTES });
  return { rho, t1, tr };
}

export function compactPoly256(coeffs: ArrayLike<number | bigint>, m: number): bigint[] {
  if (m >= 256) throw new Error("m must be less than 256");
  if ((coeffs.length * m) % 256 !== 0) {
    throw new Error("Total bits must be divisible by 256");
  }

  const a: bigint[] = new Array(coeffs.length);
  for (let i = 0; i < coeffs.length; i++) {
    const x = coeffs[i]!;
    const v = typeof x === "bigint" ? x : BigInt(Math.floor(x));
    if (v >= 1n << BigInt(m)) {
      throw new Error(`Element ${v} too large for ${m} bits`);
    }
    a[i] = v;
  }

  const n = (a.length * m) / 256;
  const b = new Array<bigint>(n).fill(0n);

  for (let i = 0; i < a.length; i++) {
    const idx = Math.floor((i * m) / 256);
    const shift = BigInt((i % (256 / m)) * m);
    b[idx]! |= a[i]! << shift;
  }

  return b;
}

export function compactModule256(
  data: ArrayLike<ArrayLike<number | bigint>>[],
  m: number,
): bigint[][][] {
  const res: bigint[][][] = [];
  for (const row of data) {
    const inner: bigint[][] = [];
    for (let j = 0; j < row.length; j++) {
      inner.push(compactPoly256(row[j]!, m));
    }
    res.push(inner);
  }
  return res;
}

/**
 * Transform noble's raw 1,312-byte ML-DSA-44 NIST public key into the
 * ABI-encoded `(bytes aHatEncoded, bytes tr, bytes t1Encoded)` payload
 * that `ZKNOX_dilithium.setKey()` writes via SSTORE2 and `_readPubKey`
 * decodes (ETHDILITHIUM/src/ZKNOX_dilithium.sol:91-97). Port of
 * `ETHDILITHIUM/js/pkDeploy.js#preparePublicKeyForDeployment`, viem-flavored.
 */
/**
 * Apply the FIPS 204 verifier transform to one t1 polynomial: shift each
 * coefficient by 2^d (Power2Round high-bit lift) then forward NTT, leaving
 * coefficients mod q. ZKNOX_dilithium_core.sol#dilithiumCore2 uses these
 * pre-computed values directly when fusing `A*z - c*t1` (line 199), and
 * the on-chain test vectors at ETHDILITHIUM/test/dilithium.t.sol:543+
 * confirm storage in this transformed form (values up to ~2^23 ≫ 2^10).
 */
function transformT1Poly(poly: number[]): number[] {
  const buf = new Int32Array(N);
  for (let i = 0; i < N; i++) buf[i] = poly[i]! << D;
  noblePqCrystals.NTT.encode(buf);
  const out = new Array<number>(N);
  for (let i = 0; i < N; i++) {
    const v = buf[i]! % Q;
    out[i] = v >= 0 ? v : v + Q;
  }
  return out;
}

export function preparePublicKeyForDeployment(rawPublicKey: Uint8Array): Hex {
  const { rho, t1, tr } = decodePublicKey(rawPublicKey);
  const aHat = recoverAhat(rho, K, L);
  const t1Transformed = t1.map(transformT1Poly);

  const aHatCompact = compactModule256(aHat, COMPACT_BITS);
  const t1Compact = compactModule256([t1Transformed], COMPACT_BITS)[0]!;

  const aHatEncoded = encodeAbiParameters(
    [{ type: "uint256[][][]" }],
    [aHatCompact],
  );
  const t1Encoded = encodeAbiParameters(
    [{ type: "uint256[][]" }],
    [t1Compact],
  );

  return encodeAbiParameters(
    [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
    [aHatEncoded, bytesToHex(tr), t1Encoded],
  );
}
