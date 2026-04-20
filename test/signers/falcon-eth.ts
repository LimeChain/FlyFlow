/**
 * Falcon-ETH production keygen + signer surfaces (Story 2-1 Task T2 + Story
 * 2-3 Task T3; `docs/amendments.md` §A-005 library-first + §A-006 Strategy E
 * fork injection).
 *
 * Exposes:
 *   - `keygen()` — sources a 48-byte `innerSeed` from
 *     `globalThis.crypto.getRandomValues` (Node ≥19 / browser Web Crypto)
 *     and forwards to `@noble/post-quantum/falcon.js#falcon512.keygen`.
 *   - `signUserOp(sk, userOp, entryPoint, chainId)` — computes `userOpHash`,
 *     sources a fresh 88 B hedge from `globalThis.crypto.getRandomValues`,
 *     routes through `falcon512paddedEth.sign` (HashToPoint-injected fork;
 *     see `falcon-eth.core.ts`), then re-encodes via
 *     `encodeSignatureForZKNOX` into the 1064 B `salt(40) || s2_compact(1024)`
 *     on-chain layout and packs into a `PackedUserOperation`.
 *
 * KAT-only helpers (explicit-innerSeed keygen, explicit-reader sign) live
 * in `falcon-eth.kat-internal.ts` and MUST NOT be imported here — the
 * runtime grep at `falcon-eth.test.ts` enforces that boundary (AC-5 / AC-6).
 *
 * Entropy source: Node's global Web Crypto API —
 * `globalThis.crypto.getRandomValues(new Uint8Array(n))`. No `node:crypto`
 * import is required; this matches the idiom established by
 * `test/signers/ml-dsa-eth.ts`.
 */

import { falcon512 } from "@noble/post-quantum/falcon.js";
import { hexToBytes } from "viem";

import { SignerInputError } from "./errors.js";
import { falcon512paddedEth } from "./falcon-eth.core.js";
import { encodeSignatureForZKNOX } from "./falcon-encoding.js";
import type {
  Keypair,
  PackedUserOperation,
  UnsignedUserOp,
} from "./index.js";
import { computeUserOpHash } from "./userOpHash.js";

/**
 * Generate a fresh Falcon-ETH keypair. Sources a 48-byte `innerSeed` from
 * `globalThis.crypto.getRandomValues` and forwards to noble's
 * `falcon512.keygen`.
 *
 * @returns `{ publicKey, secretKey }` — 897 B pk + 1281 B sk.
 *
 * @remarks
 * Production callers must NEVER pass explicit seeds — use `keygenInternal`
 * from `falcon-eth.kat-internal.ts` (KAT-only) for deterministic test
 * vectors.
 */
export function keygen(): Keypair {
  const innerSeed = new Uint8Array(48);
  globalThis.crypto.getRandomValues(innerSeed);
  return falcon512.keygen(innerSeed);
}

// === Signer (production surface) — Story 2-3 T3; docs/amendments.md §A-006 ==

/**
 * Cumulative byte budget consumed by one Falcon signing call. Noble's
 * `signRaw` calls `random(40)` for the salt then `random(48)` for the
 * FFSampler seed (ETHFALCON `docs/amendments.md` §A-005 "signingDrbg byte
 * decomposition") — exactly 88 B on the happy path. The inline reader below
 * slices this buffer sequentially and throws `SIGNING_BYTES_EXHAUSTED` on
 * over-draw (defense in depth — the budget is tight enough that an
 * exhausted CSPRNG or a future noble-version re-entry would be caught
 * loudly at the randomness boundary rather than leak a short chunk into
 * noble's `abytes` length check).
 */
const SIGNING_RANDOMNESS_BUDGET = 88;

/**
 * Sign an ERC-4337 v0.7 UserOperation with a Falcon-ETH secret key.
 *
 * Computes `userOpHash` via the shared helper, sources a fresh 88 B hedge
 * from `globalThis.crypto.getRandomValues` (AC-2 — two back-to-back calls
 * with identical inputs return different signatures because the 40 B salt
 * differs), wraps it as a sequential byte stream, and routes through
 * `falcon512paddedEth.sign` (HashToPoint-injected fork — see
 * `falcon-eth.core.ts`). Noble's ~666 B detached output is re-encoded via
 * `encodeSignatureForZKNOX` (Story 2-2) into the 1064 B `salt(40) ||
 * s2_compact(1024)` layout consumed by the on-chain
 * `ZKNOX_falcon.verify(bytes,bytes32,bytes)` entry point (Story 2-4 G6).
 *
 * Mirrors `test/signers/ml-dsa-eth.ts#signUserOp` structure one-for-one; the
 * byte divergence from the ml-dsa-eth path is in the randomness budget
 * (88 vs 32 B), the underlying signer (`falcon512paddedEth.sign` vs
 * `signWithXof`), and the signature layout (1064 B salt||s2_compact vs
 * 2420 B cTilde||z||h).
 *
 * AC-6 boundary: does NOT import from `falcon-eth.kat-internal.ts` — the
 * production path calls `falcon512paddedEth.sign` directly, the same
 * primitive the KAT surface's `signWithKatBytes` wraps with a budget guard.
 *
 * @returns `PackedUserOperation` with `.signature` as a `0x`-prefixed hex
 *   string of exactly 2130 characters (2 prefix + 1064 B × 2 hex chars =
 *   40 salt ‖ 1024 s2_compact).
 */
export async function signUserOp(
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);

  const randomness = new Uint8Array(SIGNING_RANDOMNESS_BUDGET);
  globalThis.crypto.getRandomValues(randomness);

  let offset = 0;
  // The `Falcon` type alias in `@noble/post-quantum/falcon.d.ts` exposes
  // `sign` via the generic `Signer` shape (`SigOpts` — no `random`). At
  // runtime, `genFalcon` wires the signing pipeline to accept the
  // Falcon-specific `FalconSigOpts` (`random?: (n?: number) => Uint8Array`).
  // The local type cast names the wider contract without reaching into the
  // fork's private types.
  const signWithRandom = falcon512paddedEth.sign as (
    msg: Uint8Array,
    secretKey: Uint8Array,
    opts: { random: (n?: number) => Uint8Array },
  ) => Uint8Array;
  const nobleSig = signWithRandom(hexToBytes(userOpHash), secretKey, {
    random: (n?: number): Uint8Array => {
      const len = n ?? 0;
      if (offset + len > SIGNING_RANDOMNESS_BUDGET) {
        throw new SignerInputError(
          "SIGNING_BYTES_EXHAUSTED",
          `signUserOp CSPRNG over-draw: ${offset} + ${len} B > ${SIGNING_RANDOMNESS_BUDGET} B budget`,
        );
      }
      const chunk = randomness.subarray(offset, offset + len);
      offset += len;
      return chunk;
    },
  });

  return {
    ...userOp,
    signature: encodeSignatureForZKNOX(nobleSig),
  };
}
