import { invert } from "@noble/curves/abstract/modular.js";
import { genCrystals } from "@noble/post-quantum/_crystals.js";
import { bytesToHex, encodeAbiParameters, type Hex } from "viem";

import { compactPoly256 } from "./mldsa-encoding.js";

// Falcon-512 parameters (Round-3 spec §3.2, logn=9).
// Matches ZKNOX constants at ETHFALCON/src/ZKNOX_falcon_utils.sol:33-49
// (q=12289, n=512, kq=5q=61445, nm1modq=12265, sigBytesLen=666).
const N = 512;
const Q = 12289;
const ROOT_OF_UNITY = 7;
// F = n^-1 mod q, required by genCrystals for NTT-decode normalization.
// We only use NTT.encode here (forward), but genCrystals still demands F up front.
const F_INV = Number(invert(BigInt(N), BigInt(Q)));
const noblePqCrystals = genCrystals({
  N,
  Q,
  F: F_INV,
  ROOT_OF_UNITY,
  newPoly: (n: number) => new Uint16Array(n),
  isKyber: false,
  brvBits: 10,
});

// Public key:  headerByte(0x00+logn) || 512 coeffs packed MSB 14 bits each = 1+896 bytes.
// Signature:   headerByte(0x30+logn) || nonce(40) || Algorithm-17 compressed s2 (variable).
const PUBLIC_KEY_HEADER_BYTE = 0x09;
const PUBLIC_KEY_BODY_BYTES = 896;
const PUBLIC_KEY_BYTES = 1 + PUBLIC_KEY_BODY_BYTES; // 897
const SIG_HEADER_BYTE = 0x39;
const SALT_LEN = 40;
const COMPACT_BITS = 16; // pack 16 coefficients (≤14 bits each, space-padded to 16) per uint256
const COMPACT_WORDS = (N * COMPACT_BITS) / 256; // 32
const ALGO17_LIMIT = 2047;

/**
 * Unpack noble's 896-byte 14-bit-MSB-packed public-key body into 512
 * coefficients in [0, q). Mirrors `bitsCoderMSB(d=14).decode` from
 * @noble/post-quantum/falcon.js (identity element coder), without importing
 * noble's non-exported internals.
 */
function decodePublicKey14Bit(body: Uint8Array): Uint16Array {
  if (body.length !== PUBLIC_KEY_BODY_BYTES) {
    throw new Error(
      `Falcon-512 public key body: expected ${PUBLIC_KEY_BODY_BYTES} bytes, got ${body.length}`,
    );
  }
  const out = new Uint16Array(N);
  let buf = 0;
  let bufLen = 0;
  let pos = 0;
  for (let i = 0; i < body.length; i++) {
    buf = (buf << 8) | body[i]!;
    bufLen += 8;
    if (bufLen >= 14) {
      bufLen -= 14;
      const v = (buf >>> bufLen) & 0x3fff;
      if (v >= Q) throw new Error(`pk coefficient ${pos}=${v} >= q`);
      out[pos++] = v;
      buf &= (1 << bufLen) - 1;
    }
  }
  if (pos !== N) throw new Error(`expected ${N} coefficients, decoded ${pos}`);
  return out;
}

/**
 * Decode Falcon's Algorithm 18 (Golomb-Rice decompress) from the variable-
 * length tail of a detached signature into 512 signed coefficients in
 * [-2047, 2047]. Reproduces Round-3 spec Page 48; canonical-encoding checks
 * (negative-zero, non-empty accumulator, non-zero trailing bits) are
 * enforced to match noble's verifier.
 */
function decompressSignature(body: Uint8Array): Int16Array {
  const out = new Int16Array(N);
  let buf = 0;
  let bufLen = 0;
  let pos = 0;

  const readBits = (n: number): number => {
    while (bufLen < n) {
      if (pos >= body.length) {
        throw new Error("Falcon-512 compressed s2: buffer underrun");
      }
      buf = (buf << 8) | body[pos++]!;
      bufLen += 8;
    }
    bufLen -= n;
    const val = (buf >>> bufLen) & ((1 << n) - 1);
    buf &= (1 << bufLen) - 1;
    return val;
  };

  for (let i = 0; i < N; i++) {
    const sign = readBits(1);
    const low = readBits(7);
    let high = 0;
    while (readBits(1) === 0) {
      if (++high > 2047) throw new Error("Falcon-512 compressed s2: runaway unary");
    }
    const v = low | (high << 7);
    if (sign && v === 0) throw new Error("Falcon-512 compressed s2: negative zero");
    if (v > ALGO17_LIMIT) throw new Error(`Falcon-512 compressed s2: coeff ${v} > ${ALGO17_LIMIT}`);
    out[i] = sign ? -v : v;
  }
  if (buf !== 0) throw new Error("Falcon-512 compressed s2: non-zero accumulator");
  for (let i = pos; i < body.length; i++) {
    if (body[i] !== 0) throw new Error("Falcon-512 compressed s2: non-zero trailing byte");
  }
  return out;
}

/**
 * Transform noble's raw 897-byte Falcon-512 NIST public key into the bytes
 * payload that `ZKNOX_falcon.setKey()` writes via SSTORE2 — the ABI-encoded
 * `uint256[]` holding 32 compacted NTT-domain coefficients of `h`.
 *
 * Port of `ETHFALCON/pythonref/sig_sol.py:31`:
 *   `pk_compact = falcon_compact(Poly(sk.h, q).ntt())`.
 */
export function encodePublicKeyForZKNOX(rawPublicKey: Uint8Array): Hex {
  if (rawPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(
      `Falcon-512 public key: expected ${PUBLIC_KEY_BYTES} bytes, got ${rawPublicKey.length}`,
    );
  }
  if (rawPublicKey[0] !== PUBLIC_KEY_HEADER_BYTE) {
    throw new Error(
      `Falcon-512 public key: expected header byte 0x${PUBLIC_KEY_HEADER_BYTE.toString(16)}, ` +
        `got 0x${rawPublicKey[0]!.toString(16)}`,
    );
  }
  const h = decodePublicKey14Bit(rawPublicKey.subarray(1));
  noblePqCrystals.NTT.encode(h); // forward NTT, in-place; leaves coeffs in [0, q)
  const compact = compactPoly256(h, COMPACT_BITS);
  if (compact.length !== COMPACT_WORDS) {
    throw new Error(`compact length mismatch: expected ${COMPACT_WORDS}, got ${compact.length}`);
  }
  return encodeAbiParameters([{ type: "uint256[]" }], [compact]);
}

/**
 * Transform a noble detached Falcon-512 signature (header || nonce ||
 * compressed_s2) into the 1064-byte `salt(40) || s2_compact(1024)` payload
 * expected by `ZKNOX_falcon.verify(bytes,bytes32,bytes)`. The payload is
 * raw concatenation, NOT ABI-encoded — see ZKNOX_falcon.sol:81-122
 * (assembly treats `sig[0..40]` as salt and `sig[40..]` as 32 big-endian
 * uint256 words).
 *
 * Port of `ETHFALCON/pythonref/sig_sol.py:41-48`.
 */
export function encodeSignatureForZKNOX(nobleSig: Uint8Array): Hex {
  if (nobleSig.length < 1 + SALT_LEN + 1) {
    throw new Error(`Falcon-512 signature too short: ${nobleSig.length} bytes`);
  }
  if (nobleSig[0] !== SIG_HEADER_BYTE) {
    throw new Error(
      `Falcon-512 signature: expected header byte 0x${SIG_HEADER_BYTE.toString(16)}, ` +
        `got 0x${nobleSig[0]!.toString(16)}`,
    );
  }
  const salt = nobleSig.subarray(1, 1 + SALT_LEN);
  const s2Signed = decompressSignature(nobleSig.subarray(1 + SALT_LEN));

  const s2ModQ = new Uint16Array(N);
  for (let i = 0; i < N; i++) {
    const v = s2Signed[i]!;
    s2ModQ[i] = v < 0 ? v + Q : v;
  }
  const compact = compactPoly256(s2ModQ, COMPACT_BITS);
  if (compact.length !== COMPACT_WORDS) {
    throw new Error(`compact length mismatch: expected ${COMPACT_WORDS}, got ${compact.length}`);
  }

  const out = new Uint8Array(SALT_LEN + COMPACT_WORDS * 32);
  out.set(salt, 0);
  for (let i = 0; i < COMPACT_WORDS; i++) {
    const word = compact[i]!;
    const wordOffset = SALT_LEN + i * 32;
    for (let j = 0; j < 32; j++) {
      out[wordOffset + (31 - j)] = Number((word >> BigInt(8 * j)) & 0xffn);
    }
  }
  return bytesToHex(out);
}
