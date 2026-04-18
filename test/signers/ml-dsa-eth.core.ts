/**
 * ML-DSA-ETH keygen core — XOF-parameterized fork of noble's
 * `@noble/post-quantum/ml-dsa.js#internal.keygen` (lines 344-397, pinned
 * version 0.6.1).
 *
 * Story 3 delivers the keygen half of the noble fork; Story 4 will add
 * `signWithXof` in a sibling module. Both callers (production `keygen()`
 * in `ml-dsa-eth.ts` and KAT-only `keygenInternal(zeta)` in
 * `ml-dsa-eth.kat-internal.ts`) share this module to satisfy the
 * grep-enforceable boundary at AC-3-7.
 *
 * The only deviation from noble's keygen is the XOF dispatch: every
 * `shake{128,256}` call in noble's body is routed through the provided
 * `XofFactory`. On the ETH path the factory is `keccakXofFactory`; on
 * the NIST path a Dilithium2 caller would pass noble's `shake128`/`shake256`
 * adapters (Story 3's NIST path stays on `ml_dsa44.keygen`, so the
 * single-factory NIST route is not exercised here).
 *
 * Parameter set: ML-DSA-44 — K=4, L=4, η=2, τ=39, γ₁=2¹⁷=131072,
 * γ₂=95232, ω=80, β=τη=78, D=13, Q=8380417, N=256, TR_BYTES=64
 * (`docs/plan.md` §"Story 3" §AC-3-8).
 */

import { splitCoder, vecCoder } from "@noble/post-quantum/utils.js";
import { genCrystals } from "@noble/post-quantum/_crystals.js";

import type { XofFactory, XofReader } from "./mldsa-encoding.js";

// === ML-DSA-44 parameter constants (FIPS 204 Table 1/2; AC-3-8) ==========

/** Polynomial degree. */
export const N = 256;
/** Prime modulus. */
export const Q = 8380417;
/** Module-lattice rows (public matrix height). */
export const K = 4;
/** Module-lattice columns (public matrix width). */
export const L = 4;
/** Dropped low bits in Power2Round. */
export const D = 13;
/** Secret coefficient magnitude bound. */
export const ETA = 2;
/** Challenge Hamming weight. */
export const TAU = 39;
/** ExpandMask range (2¹⁷). */
export const GAMMA1 = 1 << 17;
/** Decompose bucket width — `floor((Q - 1) / 88)`. */
export const GAMMA2 = 95232;
/** Hint count bound. */
export const OMEGA = 80;
/** Rejection bound β = τη. */
export const BETA = TAU * ETA;
/** Public-key digest length (H(pk, 64)). */
export const TR_BYTES = 64;
/** `256⁻¹ mod Q`, required by noble's NTT. */
const F_INV = 8347681;
/** FIPS 204 §7.5 BitRev_8 primitive root. */
const ROOT_OF_UNITY = 1753;

// === Crystals context (shared NTT + bits packer, noble-provided) =========

const crystals = genCrystals({
  N,
  Q,
  F: F_INV,
  ROOT_OF_UNITY,
  newPoly: (n: number) => new Int32Array(n),
  isKyber: false,
  brvBits: 8,
});

// === Coefficient coders (ETACoder / T0Coder / T1Coder) ===================
// Port of noble's `polyCoder` + per-parameter coder construction. Each
// coder packs `d` bits per coefficient into bytes; `encode`/`decode`
// compress via the FIPS 204 SimpleBitPack maps.

const id = (n: number): number => n;
const polyCoder = (
  d: number,
  compress: (n: number) => number = id,
  verify: (n: number) => number = id,
) =>
  crystals.bitsCoder(d, {
    encode: (i: number) => compress(verify(i)),
    decode: (i: number) => verify(compress(i)),
  });

// ETA=2: 3 bits per coefficient; SimpleBitPack map `ETA - i`.
const ETACoder = polyCoder(3, (i: number) => ETA - i, (i: number) => {
  // Reject malformed values outside [-ETA, ETA].
  if (i < -ETA || i > ETA) throw new Error(`ETACoder: coefficient ${i} out of range [±${ETA}]`);
  return i;
});
// T0 = 13 bits/coeff, SimpleBitPack map `(1 << (D-1)) - i`.
const T0Coder = polyCoder(D, (i: number) => (1 << (D - 1)) - i);
// T1 = 10 bits/coeff, plain pack.
const T1Coder = polyCoder(10);

// === Composite coders (splitCoder + vecCoder wrappers) ===================

const seedCoder = splitCoder("seed", 32, 64, 32); // rho (32) || rhoPrime (64) || K_ (32)
const publicCoder = splitCoder("publicKey", 32, vecCoder(T1Coder, K));
const secretCoder = splitCoder(
  "secretKey",
  32,
  32,
  TR_BYTES,
  vecCoder(ETACoder, L),
  vecCoder(ETACoder, K),
  vecCoder(T0Coder, K),
);

// === Polynomial helpers (noble port, mutates first arg in place) =========

const newPoly = (n: number): Int32Array => new Int32Array(n);

/** In-place `a ← a + b mod Q`. */
const polyAdd = (a: Int32Array, b: Int32Array): Int32Array => {
  for (let i = 0; i < a.length; i++) a[i] = crystals.mod(a[i]! + b[i]!);
  return a;
};

/** Pointwise multiplication in the NTT domain; returns a fresh polynomial. */
const multiplyNTTs = (a: Int32Array, b: Int32Array): Int32Array => {
  const c = newPoly(N);
  for (let i = 0; i < a.length; i++) c[i] = crystals.mod(a[i]! * b[i]!);
  return c;
};

/** FIPS 204 Power2Round: split `r` into `r = r1 · 2^D + r0` with `|r0| ≤ 2^(D-1)`. */
const power2Round = (r: number): { r0: number; r1: number } => {
  const rPlus = crystals.mod(r);
  const shift = 1 << D;
  const r1 = (rPlus + (1 << (D - 1)) - 1) >> D;
  const r0 = rPlus - r1 * shift;
  return { r0: r0 | 0, r1: r1 | 0 };
};

const polyPowerRound = (p: Int32Array): { r0: Int32Array; r1: Int32Array } => {
  const r0 = newPoly(N);
  const r1 = newPoly(N);
  for (let i = 0; i < p.length; i++) {
    const { r0: pr0, r1: pr1 } = power2Round(p[i]!);
    r0[i] = pr0;
    r1[i] = pr1;
  }
  return { r0, r1 };
};

// === RejBoundedPoly (ExpandS) — ETA=2 half-byte rejection ================
// Samples one polynomial in `R_q` with coefficients in `[-η, η]`. Same
// inner loop as noble; factored to accept the XOF closure returned by
// `makeXofGet(rhoPrime, blockLen, xofFactory)(x, y)`.

// ETA=2 → `CoefFromHalfByte(n)` per FIPS 204 Alg 15: `n < 15 ? 2 - (n%5) : reject`.
const coefFromHalfByteEta2 = (n: number): number | false => (n < 15 ? 2 - (n % 5) : false);

function rejBoundedPoly(xofCall: () => Uint8Array): Int32Array {
  const r = newPoly(N);
  for (let j = 0; j < N;) {
    const buf = xofCall();
    for (let i = 0; j < N && i < buf.length; i++) {
      const b = buf[i]!;
      const d1 = coefFromHalfByteEta2(b & 0x0f);
      const d2 = coefFromHalfByteEta2((b >> 4) & 0x0f);
      if (d1 !== false) r[j++] = d1;
      if (j < N && d2 !== false) r[j++] = d2;
    }
  }
  return r;
}

// === RejNTTPoly (ExpandA) — 3-byte triple rejection ======================
// Same as mldsa-encoding.ts's rejectionSamplePoly; duplicated here to keep
// the core module self-contained.

function rejNTTPoly(xofCall: () => Uint8Array): Int32Array {
  const r = newPoly(N);
  for (let j = 0; j < N;) {
    const buf = xofCall();
    if (buf.length % 3 !== 0) {
      throw new Error(`rejNTTPoly: xof block length ${buf.length} not divisible by 3`);
    }
    for (let i = 0; j < N && i <= buf.length - 3; i += 3) {
      const b0 = buf[i]!;
      const b1 = buf[i + 1]!;
      const b2 = buf[i + 2]!;
      const t = (b0 | (b1 << 8) | (b2 << 16)) & 0x7fffff;
      if (t < Q) r[j++] = t;
    }
  }
  return r;
}

// === XOF `.get(x, y)` adapter — replaces noble's XOF128/XOF256 ===========
// Noble's `XOF{128,256}(seed).get(x, y)` appends one byte per coordinate
// to `seed` and returns a closure that squeezes `blockLen` bytes per call.
// Our adapter wraps `xofFactory(seed || x || y)` into the same closure
// shape; the factory produces a fresh `XofReader` per (x, y) pair and
// each squeeze pulls sequential bytes from that reader.

function makeXofGet(
  seed: Uint8Array,
  blockLen: number,
  xofFactory: XofFactory,
): (x: number, y: number) => () => Uint8Array {
  return (x: number, y: number): (() => Uint8Array) => {
    const fullSeed = new Uint8Array(seed.length + 2);
    fullSeed.set(seed, 0);
    fullSeed[seed.length] = x;
    fullSeed[seed.length + 1] = y;
    const reader: XofReader = xofFactory(fullSeed);
    return () => reader.xof(blockLen);
  };
}

// SHAKE-128 block length (168 bytes, 56 triples) — used for ExpandA by
// noble. SHAKE-256 block length is 136; we round down to 132 so ExpandS's
// half-byte loop consumes an integer number of coefficient pairs and the
// rejection semantics stay well-defined.
const EXPAND_A_BLOCK = 168;
const EXPAND_S_BLOCK = 136;

// === Keypair type (mirrors `test/signers/index.ts` shape) ================

export interface Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// === keygenWithXof =======================================================

/**
 * XOF-parameterized ML-DSA-44 keygen. Given a 32-byte `zeta` and an
 * {@link XofFactory}, produces a `(publicKey, secretKey)` pair
 * byte-identical to the Python reference's
 * `_keygen_internal(zeta, _xof=xofFactory, _xof2=xofFactory)` on the ETH
 * path (single-factory; the factory serves both `_xof` and `_xof2` roles
 * per DD-1).
 *
 * Pre-conditions:
 * - `zeta.length === 32` — the input domain-separation seed (the caller
 *   is responsible for sourcing randomness; KAT callers pass `.rsp` zeta).
 * - `xofFactory` produces fresh stateful {@link XofReader}s (no cached
 *   state between invocations — DD-10 LOCKED).
 *
 * This function does NOT randomize `zeta` internally — that is the
 * caller's responsibility (`ml-dsa-eth.ts` wraps
 * `crypto.getRandomValues(new Uint8Array(32))`; KAT callers pass the
 * `.rsp` vector's zeta verbatim).
 */
export function keygenWithXof(zeta: Uint8Array, xofFactory: XofFactory): Keypair {
  if (zeta.length !== 32) {
    throw new Error(`keygenWithXof: zeta must be 32 bytes, got ${zeta.length}`);
  }

  // Step 1 — seed expansion: `xof(zeta || K || L)` → 128 bytes split into
  // (rho: 32, rhoPrime: 64, K_: 32). Python `_h(seed_domain_sep, 128, _xof=_xof)`.
  const seedDst = new Uint8Array(32 + 2);
  seedDst.set(zeta);
  seedDst[32] = K;
  seedDst[33] = L;
  const seedBytes = xofFactory(seedDst).xof(seedCoder.bytesLen);
  const decoded = seedCoder.decode(seedBytes) as [Uint8Array, Uint8Array, Uint8Array];
  const [rho, rhoPrime, K_] = decoded;

  // Step 2 — s1/s2 via RejBoundedPoly over XOF(rhoPrime || i_low || i_high).
  // Python `_expand_vector_from_seed(rho_prime, _xof=_xof)`.
  const xofPrime = makeXofGet(rhoPrime, EXPAND_S_BLOCK, xofFactory);
  const s1: Int32Array[] = [];
  for (let i = 0; i < L; i++) {
    s1.push(rejBoundedPoly(xofPrime(i & 0xff, (i >> 8) & 0xff)));
  }
  const s2: Int32Array[] = [];
  for (let i = L; i < L + K; i++) {
    s2.push(rejBoundedPoly(xofPrime(i & 0xff, (i >> 8) & 0xff)));
  }

  // Step 3 — NTT-encode a copy of s1 for the matrix-vector product.
  const s1Hat = s1.map((p) => crystals.NTT.encode(new Int32Array(p)));

  // Step 4 — `t = A_hat · s1_hat + s2` with `A_hat` expanded per (j, i).
  // Python `A_hat = _expand_matrix_from_seed(rho, _xof=_xof2)` +
  // `t = (A_hat @ s1_hat).from_ntt() + s2`.
  const xof = makeXofGet(rho, EXPAND_A_BLOCK, xofFactory);
  const t1: Int32Array[] = [];
  const t0: Int32Array[] = [];
  for (let i = 0; i < K; i++) {
    const t = newPoly(N);
    for (let j = 0; j < L; j++) {
      const aij = rejNTTPoly(xof(j, i));
      polyAdd(t, multiplyNTTs(aij, s1Hat[j]!));
    }
    crystals.NTT.decode(t);
    const { r0, r1 } = polyPowerRound(polyAdd(t, s2[i]!));
    t0.push(r0);
    t1.push(r1);
  }

  // Step 5 — pack pk, compute tr via xof, pack sk.
  // Python `pk = _pack_pk(rho, t1)` / `tr = _h(pk, 64, _xof=_xof)` /
  // `sk = _pack_sk(rho, K_, tr, s1, s2, t0)`.
  const publicKey = publicCoder.encode([rho, t1]);
  const tr = xofFactory(publicKey).xof(TR_BYTES);
  const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);

  return { publicKey, secretKey };
}
