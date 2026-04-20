/**
 * Falcon-ETH KAT-only keygen surface (Story 2-1 Task T2; `docs/amendments.md`
 * §A-005 library-first).
 *
 * Exposes `keygenInternal(innerSeed)` — a thin wrapper around
 * `@noble/post-quantum/falcon.js#falcon512.keygen` that accepts the caller's
 * 48-byte `innerSeed` verbatim (no randomness), making the output deterministic
 * for byte-identity comparison against ETHFALCON's `.rsp` vectors. The G3 KAT
 * test at `falcon-eth.keygen.kat.test.ts` (Story 2-1 Task T3) derives
 * `innerSeed` at test time via `rngAesCtrDrbg256(hexToBytes(v.drbgSeed)).randomBytes(48)`
 * and compares `{publicKey, secretKey}` against `.rsp` fields byte-for-byte.
 *
 * **KAT-only — NEVER imported from `test/signers/index.ts` or
 * `test/bench/**`.** Boundary asserted by `test/signers/falcon-eth.test.ts`
 * via runtime grep (AC-5).
 */

import { falcon512 } from "@noble/post-quantum/falcon.js";

import { SignerInputError } from "./errors.js";
import type { Keypair } from "./index.js";

/**
 * Explicit-innerSeed Falcon-ETH keygen. Accepts the caller's 48-byte
 * `innerSeed` verbatim (no randomness), producing a `(publicKey, secretKey)`
 * byte-identical to ETHFALCON's `_keygen_internal(innerSeed)` reference.
 *
 * @param innerSeed - 48-byte domain-separation seed (e.g. a `.rsp` vector's
 *                    recovered inner seed via `AES256_CTR_DRBG.randomBytes(48)`).
 * @returns `{ publicKey, secretKey }` — 897 B pk + 1281 B sk.
 * @throws {@link SignerInputError} with `code: "INVALID_INNER_SEED_LENGTH"`
 *         when `innerSeed` is not a 48-byte `Uint8Array`.
 */
export function keygenInternal(innerSeed: Uint8Array): Keypair {
  if (!(innerSeed instanceof Uint8Array) || innerSeed.length !== 48) {
    throw new SignerInputError(
      "INVALID_INNER_SEED_LENGTH",
      `expected 48 B Uint8Array, got ${
        innerSeed instanceof Uint8Array
          ? `${innerSeed.length} B`
          : `non-Uint8Array (${typeof innerSeed})`
      }`,
    );
  }
  return falcon512.keygen(innerSeed);
}
