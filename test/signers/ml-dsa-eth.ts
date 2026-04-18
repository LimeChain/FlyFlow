/**
 * ML-DSA-ETH production signer surface.
 *
 * Variant of NIST ML-DSA-44 that swaps every SHAKE XOF for the Keccak-PRG
 * primitive (DD-1; `docs/architecture.md` §"Design Rationale"). Consumers:
 * `MlDsaEthAccount.initialize` (Story 5) and any future ETH-variant
 * signer usages. KAT-only helpers (explicit-zeta keygen / explicit-rnd
 * sign) live in `ml-dsa-eth.kat-internal.ts` and MUST NOT be imported
 * here — the runtime grep at `ml-dsa-eth.test.ts` enforces that boundary
 * (AC-3-7, `docs/amendments.md` §A-003).
 *
 * Entropy source: Node 24's global Web Crypto API —
 * `globalThis.crypto.getRandomValues(new Uint8Array(32))`. No `node:crypto`
 * import is required; the ETH keygen is the first direct `getRandomValues`
 * caller in this repo, locking the idiom for future stories.
 *
 * @delta-from-ml-dsa
 * Byte-level differences from `test/signers/ml-dsa.ts` (the NIST path):
 *
 * 1. **XOF primitive.** This module uses `keccakXofFactory` (Story 2
 *    `createKeccakPrg` + `flip()` then sequential `extract(n)`) for every
 *    XOF role — `_xof` and `_xof2` in the Python reference, both collapsed
 *    onto Keccak-PRG per DD-1. NIST path uses SHAKE-256 (`_xof`: seed
 *    expansion, ExpandS, tr, mu, c_tilde) and SHAKE-128 (`_xof2`: ExpandA
 *    / A_hat). Identical `zeta` seeds produce DIFFERENT keys across the
 *    two variants; ML-DSA-ETH keys are NOT interchangeable with NIST
 *    ML-DSA keys.
 * 2. **Fork scope.** Noble's `ml_dsa44` is forked at BOTH keygen + sign
 *    call-sites; Python ref `_keygen_internal` and `_sign_internal` both
 *    take `_xof, _xof2` parameters. Story 3 delivers the keygen half
 *    (`keygenWithXof` in `ml-dsa-eth.core.ts`); Story 4 delivers
 *    `signWithXof`.
 * 3. **pk-transform factory argument.** The refactored
 *    `preparePublicKeyForDeployment` (`mldsa-encoding.ts`) accepts two
 *    XOF factories per `docs/amendments.md` §A-002. The ETH path passes
 *    `(keccakXofFactory, keccakXofFactory)`; NIST passes
 *    `(shake256XofFactory, shake128XofFactory)`.
 * 4. **ctx handling.** Production `signUserOp` always passes an empty
 *    `ctx`; the core signer prepends `0x00 || len(ctx) || ctx` to `msg`
 *    (the `userOpHash`) before mu computation, byte-matching Python
 *    `dilithium.py:445`. KAT-only `signWithRnd` takes optional `ctx`
 *    (default empty).
 * 5. **Signature layout.** `signWithXof` emits exactly 2420 B raw
 *    concat: 32 B cTilde (Keccak-PRG over `mu ‖ w1_bytes`) + 2304 B z
 *    (bit-packed 18 bits/coeff for ML-DSA-44, 4 polynomials) + 84 B h
 *    (k + ω = 4 + 80; ω entries of nonzero coefficient positions + k
 *    cumulative counts at positions [80..83]). Returned raw; the
 *    Solidity verifier applies `abi.encode(bytes cTilde, bytes z,
 *    bytes h)` at its entry point (Story 5 scope).
 */

import { bytesToHex, hexToBytes } from "viem";

import type { PackedUserOperation, UnsignedUserOp } from "./index.js";
import {
  type Keypair,
  keygenWithXof,
  signWithXof,
} from "./ml-dsa-eth.core.js";
import { keccakXofFactory } from "./mldsa-encoding.js";
import { computeUserOpHash } from "./userOpHash.js";

/**
 * Generate a fresh ML-DSA-ETH keypair. Sources a 32-byte `zeta` from
 * `crypto.getRandomValues` and threads it through the Keccak-PRG-driven
 * keygen fork.
 *
 * @returns `{ publicKey, secretKey }` — 1312 B + 2560 B raw Uint8Array.
 *
 * @remarks
 * Production callers must NEVER pass explicit seeds — use
 * `keygenInternal(zeta)` from `ml-dsa-eth.kat-internal.ts` (KAT-only)
 * for deterministic test vectors.
 */
export function keygen(): Keypair {
  const zeta = new Uint8Array(32);
  globalThis.crypto.getRandomValues(zeta);
  return keygenWithXof(zeta, keccakXofFactory);
}

/**
 * Sign an ERC-4337 v0.7 UserOperation with an ML-DSA-ETH secret key.
 *
 * Computes `userOpHash` via the shared helper, sources a fresh 32-byte
 * `rnd` from `crypto.getRandomValues` (AC-4-6 hedge — two back-to-back
 * calls with identical inputs return different signatures), and routes
 * through `signWithXof` with empty `ctx` + `keccakXofFactory` per the
 * DD-1 single-factory convention for the ETH path.
 *
 * Mirrors `test/signers/ml-dsa.ts#signUserOp` shape; the byte divergence
 * from the NIST path is in the XOF primitive + explicit `rnd` routing,
 * not in the public signature or the returned `PackedUserOperation`
 * layout.
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
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  const signature = signWithXof(
    secretKey,
    hexToBytes(userOpHash),
    rnd,
    new Uint8Array(0),
    keccakXofFactory,
  );
  return {
    ...userOp,
    signature: bytesToHex(signature),
  };
}
