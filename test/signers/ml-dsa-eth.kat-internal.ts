/**
 * ML-DSA-ETH KAT-only surface (Story 3 G1 consumer; Story 4 adds
 * `signWithRnd` here).
 *
 * This module exposes deterministic entry points that accept an explicit
 * `zeta` (and, in Story 4, explicit `rnd` / `ctx`), for byte-identity
 * testing against `PQCsignKAT_Dilithium2_ETH.rsp` vectors. Production
 * code MUST NEVER import from this module — dispatchers at
 * `test/signers/index.ts` and benchmarks under `test/bench/**` are
 * prohibited consumers, enforced at runtime by
 * `test/signers/ml-dsa-eth.test.ts`'s grep assertion (AC-3-7;
 * `docs/amendments.md` §A-003).
 *
 * **KAT-only — NEVER imported from `test/signers/index.ts` or
 * `test/bench/**`. Boundary asserted by
 * `test/signers/ml-dsa-eth.test.ts` via runtime grep.**
 *
 * @delta-from-ml-dsa
 * The byte-level differences from `test/signers/ml-dsa.ts` / `ml-dsa.kat`
 * helpers:
 *
 * 1. **XOF primitive.** Keccak-PRG (via `keccakXofFactory`) replaces
 *    SHAKE-256 / SHAKE-128 for every XOF role. DD-1 collapses both
 *    `_xof` and `_xof2` onto Keccak-PRG on the ETH path.
 * 2. **Fork scope.** Noble's `ml_dsa44` is forked at keygen (this
 *    module) and sign (Story 4). Shared core at `ml-dsa-eth.core.ts`.
 * 3. **pk-transform factory argument** (`preparePublicKeyForDeployment`
 *    per `docs/amendments.md` §A-002): ETH path passes
 *    `(keccakXofFactory, keccakXofFactory)`.
 * 4. **ctx handling.** `signWithRnd` accepts optional `ctx` with default
 *    `new Uint8Array(0)`; the upstream signer prepends
 *    `0x00 || len(ctx) || ctx` to `msg` before mu computation,
 *    byte-matching Python `dilithium.py:445`.
 * 5. **Signature layout.** `signWithXof` emits exactly 2420 B raw concat:
 *    32 B cTilde (Keccak-PRG over `mu ‖ w1_bytes`) + 2304 B z
 *    (bit-packed 20 bits/coeff → 18 bits/coeff for ML-DSA-44,
 *    4 polynomials) + 84 B h (k + ω = 4 + 80; ω entries of nonzero
 *    coefficient positions + k cumulative counts at positions
 *    [80..83]). Returned raw from `signWithRnd` as
 *    `bytesToHex(sig)`; abi-encoding is applied at the Solidity
 *    boundary (Story 5 scope).
 */

import { bytesToHex, hexToBytes, type Hex } from "viem";

import { SignerInputError } from "./errors.js";
import { keccakXofFactory } from "./mldsa-encoding.js";
import {
  type Keypair,
  keygenWithXof,
  SECRET_KEY_BYTES,
  signWithXof,
} from "./ml-dsa-eth.core.js";

/**
 * Explicit-zeta ML-DSA-ETH keygen. Accepts the caller's 32-byte `zeta`
 * verbatim (no randomness), making the output deterministic for KAT
 * comparison against `.rsp` vectors.
 *
 * @param zeta - 32-byte domain-separation seed (e.g. a `.rsp` vector's
 *               recovered ζ post-DRBG).
 * @returns `{ publicKey, secretKey }` byte-identical to the Python
 *          reference `_keygen_internal(zeta, _xof=Keccak256PRNG,
 *          _xof2=Keccak256PRNG)` on the ETH path.
 * @throws `Error` when `zeta.length !== 32`.
 */
export function keygenInternal(zeta: Uint8Array): Keypair {
  if (zeta.length !== 32) {
    throw new Error(
      `keygenInternal: zeta must be 32 bytes, got ${zeta.length}`,
    );
  }
  return keygenWithXof(zeta, keccakXofFactory);
}

/**
 * Coerce a caller-supplied `msg` to bytes. Accepts `Uint8Array` (returned
 * verbatim) and `0x`-prefixed lowercase hex strings (viem `hexToBytes`).
 * Any other shape raises {@link SignerInputError} with
 * `code: "INVALID_MESSAGE"` (AC-4-4).
 */
function coerceMessageBytes(msg: Uint8Array | Hex): Uint8Array {
  if (msg instanceof Uint8Array) return msg;
  if (typeof msg === "string" && msg.startsWith("0x")) {
    try {
      return hexToBytes(msg);
    } catch {
      throw new SignerInputError(
        "INVALID_MESSAGE",
        `signWithRnd: msg is not a valid 0x-hex string`,
      );
    }
  }
  throw new SignerInputError(
    "INVALID_MESSAGE",
    `signWithRnd: msg must be a Uint8Array or a 0x-prefixed hex string`,
  );
}

/**
 * Explicit-rnd ML-DSA-ETH signer. Deterministic for a fixed
 * `(sk, msg, rnd, ctx)` tuple — the G2 KAT test (Story 4 Task 4) calls
 * this surface to reproduce `PQCsignKAT_Dilithium2_ETH.rsp` signatures
 * byte-for-byte.
 *
 * Input validation (ACs 4-3, 4-4):
 * - `sk.length !== SECRET_KEY_BYTES (2560)` → throws
 *   {@link SignerInputError} with `code: "INVALID_SECRET_KEY_LENGTH"`.
 * - `msg` neither `Uint8Array` nor a `0x`-hex string → throws
 *   {@link SignerInputError} with `code: "INVALID_MESSAGE"`.
 *
 * `ctx` defaults to `new Uint8Array(0)` (empty) — matches the ETH KAT
 * convention and Python `sign(sk, m, ctx=b"")`. `signWithXof` internally
 * applies the domain-separation prefix `0x00 || len(ctx) || ctx` to
 * `msg` before mu computation.
 *
 * @returns the 2420 B signature as a 0x-prefixed hex string (viem
 *          idiom; matches `.rsp` `signature` field shape).
 */
export function signWithRnd(
  sk: Uint8Array,
  msg: Uint8Array | Hex,
  rnd: Uint8Array,
  ctx: Uint8Array = new Uint8Array(0),
): Hex {
  if (sk.length !== SECRET_KEY_BYTES) {
    throw new SignerInputError(
      "INVALID_SECRET_KEY_LENGTH",
      `signWithRnd: sk must be ${SECRET_KEY_BYTES} bytes, got ${sk.length}`,
    );
  }
  const msgBytes = coerceMessageBytes(msg);
  const signature = signWithXof(sk, msgBytes, rnd, ctx, keccakXofFactory);
  return bytesToHex(signature);
}
