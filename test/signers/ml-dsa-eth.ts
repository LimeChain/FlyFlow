/**
 * ML-DSA-ETH production signer surface (Story 3 G1; Story 4 will add sign).
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
 * 4. **ctx handling (informational; exercised by Story 4).** ETH path
 *    uses `ctx = 0x` (empty bytes) to match `generate_KAT_example.py`
 *    and the `.rsp` convention.
 * 5. **Signature layout (informational; Story 4).** Same 32 B cTilde +
 *    2304 B z + 84 B h = 2420 B as NIST, but cTilde is derived via
 *    Keccak-PRG, not SHAKE-256.
 */

import { keccakXofFactory } from "./mldsa-encoding.js";
import { type Keypair, keygenWithXof } from "./ml-dsa-eth.core.js";

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
