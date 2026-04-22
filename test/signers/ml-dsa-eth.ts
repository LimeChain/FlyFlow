/**
 * ML-DSA-ETH production keygen + signer surfaces.
 *
 * Thin ERC-4337 glue around the fork-owned crypto surface at
 * `@noble/post-quantum/{ml-dsa,utils-eth}.js`. After the ml-dsa-eth fork
 * extraction, this module holds only the repo-local seams:
 *
 *   - `keygen()`            — delegates directly to `ml_dsa44eth.keygen()`
 *                             (noble sources its own 32 B seed via
 *                             `randomBytes`).
 *   - `signUserOp(...)`     — computes `userOpHash`, calls
 *                             `ml_dsa44eth.sign` with hedged `extraEntropy`,
 *                             packs the result into a `PackedUserOperation`.
 *   - `preparePublicKeyForDeployment(rawPk, xofTr, xofExpandA)` — NFR-11
 *                             cross-scheme shape shim over
 *                             `encodeMlDsaPublicKey`. Hex-wraps for the viem
 *                             boundary.
 *
 * All low-level crypto (samplers, Keccak-PRG primitive, ABI-level encoders,
 * raw signature layout) lives in the fork. The fork returns `Uint8Array`
 * throughout; this module wraps with `bytesToHex` at the viem boundary.
 *
 * Entropy source: noble's `randomBytes` inside `ml_dsa44eth.keygen()` /
 * `ml_dsa44eth.sign(...)` — ultimately Node's global Web Crypto API.
 *
 * @delta-from-ml-dsa
 * Byte-level differences from the NIST ML-DSA-44 path (`test/signers/ml-dsa.ts`
 * which wraps `@noble/post-quantum/ml-dsa.js#ml_dsa44`). Full implementation
 * of all five deltas lives inside the fork at
 * `@noble/post-quantum/ml-dsa.js#ml_dsa44eth` — this repo module is the
 * thin ERC-4337 glue.
 *
 * 1. **XOF primitive.** `ml_dsa44eth` consumes Keccak-PRG (`createKeccakPrg`
 *    + `flip()` + sequential `extract(n)`) for every XOF role. The NIST
 *    path uses SHAKE-256 + SHAKE-128. Identical `zeta` seeds produce
 *    DIFFERENT keys across the two variants.
 * 2. **Fork scope.** `ml_dsa44eth` is an independent DSA instance inside
 *    the fork's `ml-dsa.ts`, appended after `ml_dsa87`. It does NOT share
 *    `getDilithium`'s internals — the per-coordinate XOF rebinding
 *    convention (noble's `XOF128(rho).get(x,y)`) is incompatible with
 *    Keccak-PRG's flat-sequential `extract(n)` model.
 * 3. **pk-transform factory** argument (`preparePublicKeyForDeployment`
 *    below): ETH callers pass `(keccakXofFactory, keccakXofFactory)`;
 *    NIST callers pass `(shake256XofFactory, shake128XofFactory)`.
 * 4. **ctx handling.** `signUserOp` always passes an empty `ctx`; the
 *    fork internally prepends `0x00 || len(ctx) || ctx` to `msg` via
 *    noble's `getMessage` helper before mu computation, byte-matching
 *    ETHDILITHIUM Python `sign(sk, m, ctx=b"")`.
 * 5. **Signature layout.** `ml_dsa44eth.sign` emits exactly 2420 B raw
 *    concat: 32 B cTilde + 2304 B z (bit-packed 18 bits/coeff for
 *    ML-DSA-44, 4 polynomials) + 84 B h (k + ω = 4 + 80). Returned as a
 *    0x-prefixed hex string inside the `PackedUserOperation.signature`
 *    field; on-chain ABI wrapping happens at the Solidity verifier boundary.
 */

import { ml_dsa44eth } from "@noble/post-quantum/ml-dsa.js";
import {
  encodeMlDsaPublicKey,
  type XofFactory,
} from "@noble/post-quantum/utils-eth.js";
import { bytesToHex, hexToBytes, type Hex } from "viem";

import type {
  Keypair,
  PackedUserOperation,
  UnsignedUserOp,
} from "./index.js";
import { computeUserOpHash } from "./userOpHash.js";

/**
 * Generate a fresh ML-DSA-ETH keypair. Delegates to
 * `ml_dsa44eth.keygen()` which sources a 32 B `zeta` internally via noble's
 * `randomBytes` (Web Crypto) and threads it through the Keccak-PRG-driven
 * keygen fork.
 *
 * @returns `{ publicKey, secretKey }` — 1312 B + 2560 B raw Uint8Array.
 */
export function keygen(): Keypair {
  return ml_dsa44eth.keygen();
}

/**
 * Sign an ERC-4337 v0.7 UserOperation with an ML-DSA-ETH secret key.
 *
 * Computes `userOpHash` via the shared helper and routes through
 * `ml_dsa44eth.sign` with no explicit `extraEntropy` — noble sources a fresh
 * 32 B hedge per call via Web Crypto. Two back-to-back calls with identical
 * inputs return different signatures because the hedge differs.
 *
 * @returns `PackedUserOperation` with `.signature` as a `0x`-prefixed hex
 *   string of exactly 4842 characters (2 prefix + 2420 bytes × 2 hex
 *   chars = 32 cTilde ‖ 2304 z ‖ 84 h).
 */
export async function signUserOp(
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);
  const signature = ml_dsa44eth.sign(hexToBytes(userOpHash), secretKey);
  return {
    ...userOp,
    signature: bytesToHex(signature),
  };
}

/**
 * NFR-11 cross-scheme shape shim over
 * `@noble/post-quantum/utils-eth.js#encodeMlDsaPublicKey`.
 *
 * Two-factory signature matches the Python reference
 * `_keygen_internal(_xof, _xof2)` split:
 *
 * - `xofFactory`  ≡ Python `_xof`  — drives the `tr` H-of-pk computation.
 * - `xofFactory2` ≡ Python `_xof2` — drives ExpandA / rejection sampling.
 *
 * ETH callers pass `(keccakXofFactory, keccakXofFactory)`; NIST callers pass
 * `(shake256XofFactory, shake128XofFactory)`. Emits the same ABI-encoded
 * `(bytes aHatEncoded, bytes tr, bytes t1Encoded)` payload as the pre-
 * extraction helper — wrapped at the viem boundary via `bytesToHex`.
 *
 * @param rawPk       1312 B raw ML-DSA-44 NIST public key.
 * @param xofFactory  Factory used for the `tr` H-of-pk computation.
 * @param xofFactory2 Factory used for ExpandA.
 * @returns           `Hex` payload directly passable to
 *                    `mlDsaEthVerifier.setKey(hex)`.
 */
export function preparePublicKeyForDeployment(
  rawPk: Uint8Array,
  xofFactory: XofFactory,
  xofFactory2: XofFactory,
): Hex {
  return bytesToHex(encodeMlDsaPublicKey(rawPk, xofFactory, xofFactory2));
}
