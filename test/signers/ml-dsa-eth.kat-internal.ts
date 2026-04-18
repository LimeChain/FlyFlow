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
 * 4. **ctx handling** (Story 4): ETH path uses `ctx = 0x`.
 * 5. **Signature layout** (Story 4): cTilde derived via Keccak-PRG.
 */

import { keccakXofFactory } from "./mldsa-encoding.js";
import { type Keypair, keygenWithXof } from "./ml-dsa-eth.core.js";

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
