/**
 * Falcon-ETH KAT-only keygen + signer surfaces (Story 2-1 Task T2 + Story
 * 2-3 Task T3; `docs/amendments.md` §A-005 library-first + §A-006 Strategy E
 * fork injection).
 *
 * Exposes:
 *   - `keygenInternal(innerSeed)` — thin wrapper around
 *     `@noble/post-quantum/falcon.js#falcon512.keygen` accepting the caller's
 *     48-byte `innerSeed` verbatim. Deterministic for byte-identity
 *     comparison against ETHFALCON's `.rsp` vectors. G3 KAT at
 *     `falcon-eth.keygen.kat.test.ts` (Story 2-1 T3).
 *   - `BytesReader` interface + `signWithKatBytes(sk, msg, reader)` —
 *     deterministic Falcon-ETH sign routed through `falcon512paddedEth.sign`
 *     (HashToPoint-injected fork; see `falcon-eth.core.ts`) then re-encoded
 *     via `encodeSignatureForZKNOX` (Story 2-2). Returns 1064 B `salt(40) ||
 *     s2_compact(1024)`. G4 KAT at `falcon-eth.sign.kat.test.ts` (Story 2-3
 *     T4).
 *
 * **KAT-only — NEVER imported from `test/signers/index.ts` or
 * `test/bench/**`.** Boundary asserted by `test/signers/falcon-eth.test.ts`
 * (AC-5 keygen) and `test/signers/falcon-eth.sign.test.ts` (AC-7 signer)
 * via runtime grep.
 */

import { falcon512 } from "@noble/post-quantum/falcon.js";
import { hexToBytes } from "viem";

import { SignerInputError } from "./errors.js";
import { falcon512paddedEth } from "./falcon-eth.core.js";
import { encodeSignatureForZKNOX } from "./falcon-encoding.js";
import type { Keypair } from "./index.js";

/**
 * Explicit-innerSeed Falcon-ETH keygen. Accepts the caller's 48-byte
 * `innerSeed` verbatim (no randomness), producing a `(publicKey, secretKey)`
 * byte-identical to ETHFALCON's `_keygen_internal(innerSeed)` reference.
 *
 * @param innerSeed - 48-byte domain-separation seed (e.g. a `.rsp` vector's
 *                    recovered inner seed via
 *                    `@noble/ciphers/aes.js#rngAesCtrDrbg256(drbgSeed).randomBytes(48)`
 *                    — byte-identical to ETHFALCON's Python
 *                    `AES256_CTR_DRBG(seed).random_bytes(48)` per
 *                    `docs/amendments.md` §A-005 Evidence §5).
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

// === Signer (KAT surface) — Story 2-3 T3; docs/amendments.md §A-006 ==========

/**
 * Sequential byte stream for deterministic signing. Production `signUserOp`
 * (in `falcon-eth.ts`) allocates 88 B from `globalThis.crypto.getRandomValues`
 * and wraps it as a `BytesReader`; the G4 KAT test wraps `rngAesCtrDrbg256`
 * advanced past the 48 B keygen draw (per `docs/amendments.md` §A-005
 * "DRBG derivation contract"). Implementations serve the requested count
 * verbatim — budget enforcement is layered on top by `signWithKatBytes` via
 * a `SIGNING_BYTES_EXHAUSTED` guard around noble's `random` callback.
 */
export interface BytesReader {
  /** Returns exactly `n` bytes. Implementations enforce budgets at this boundary. */
  read(n: number): Uint8Array;
}

/**
 * Cumulative byte budget consumed by one Falcon signing call via
 * `falcon512paddedEth.sign`. Noble's `signRaw` calls `random(40)` for the
 * salt then `random(48)` for the FFSampler seed (ETHFALCON
 * `docs/amendments.md` §A-005 "signingDrbg byte decomposition"). A reader
 * that is asked for more than 88 B cumulative indicates either a TS-side
 * signer divergence bug (KAT path) or an exhausted CSPRNG source
 * (production path).
 */
const SIGNING_BUDGET = 88;
const SECRET_KEY_LEN = 1281;

/**
 * Deterministic Falcon-ETH sign (KAT surface). Returns 1064 B `salt(40) ||
 * s2_compact(1024)` — the ETHFALCON on-chain format captured in
 * `test/fixtures/kat/falcon-eth/vectors.json#signature` fields (see
 * `scripts/generate-kat-fixtures.ts:1310-1337` for the Python-side
 * derivation).
 *
 * Routes through `falcon512paddedEth.sign` (HashToPoint-injected fork; see
 * `falcon-eth.core.ts`) then re-encodes noble's ~666 B detached output via
 * `encodeSignatureForZKNOX` (Story 2-2; handles decompress + falcon_compact
 * + 32-uint256-BE packing).
 *
 * @param sk 1281-byte Falcon-512 secret key.
 * @param msg Non-empty message (the on-chain `userOpHash` in the production
 *            path; a KAT vector's `message` field at test time).
 * @param reader Sequential 88 B stream driving noble's rejection loop.
 *               Over-draw throws `SIGNING_BYTES_EXHAUSTED` (KAT port bug);
 *               invalid sk/msg throw before any randomness is consumed.
 * @returns 1064 B `Uint8Array` (40 B salt || 1024 B s2_compact).
 * @throws {@link SignerInputError} codes:
 *   - `INVALID_SECRET_KEY_LENGTH` when sk is not a 1281-byte Uint8Array
 *   - `INVALID_MESSAGE` when msg is not a non-empty Uint8Array
 *   - `SIGNING_BYTES_EXHAUSTED` when reader over-draws past 88 B cumulative
 */
export function signWithKatBytes(
  sk: Uint8Array,
  msg: Uint8Array,
  reader: BytesReader,
): Uint8Array {
  if (!(sk instanceof Uint8Array) || sk.length !== SECRET_KEY_LEN) {
    throw new SignerInputError(
      "INVALID_SECRET_KEY_LENGTH",
      `expected ${SECRET_KEY_LEN} B sk, got ${
        sk instanceof Uint8Array ? `${sk.length} B` : `non-Uint8Array (${typeof sk})`
      }`,
    );
  }
  if (!(msg instanceof Uint8Array) || msg.length === 0) {
    throw new SignerInputError(
      "INVALID_MESSAGE",
      `expected non-empty Uint8Array msg, got ${
        msg instanceof Uint8Array ? "length 0" : `non-Uint8Array (${typeof msg})`
      }`,
    );
  }

  // Over-draw guard — noble's signRaw happy path calls `random(40)` then
  // `random(48)` = exactly 88 B. A reader asked for (or returning) more
  // bytes cumulatively signals either a port bug (KAT path; e.g. a future
  // noble version re-entering signRaw on rejection and re-calling random)
  // or a buggy reader that serves more than requested. Fire on BOTH
  // requested-count over-draw AND returned-chunk over-draw so the guard
  // catches over-serving readers too (the actual byte spend is what
  // violates the ETHFALCON DRBG consumption contract).
  let consumed = 0;
  const guardedRandom = (n?: number): Uint8Array => {
    const requested = n ?? 0;
    if (consumed + requested > SIGNING_BUDGET) {
      throw new SignerInputError(
        "SIGNING_BYTES_EXHAUSTED",
        `reader over-draw (requested): ${consumed} + ${requested} B > ${SIGNING_BUDGET} B budget`,
      );
    }
    const chunk = reader.read(requested);
    if (consumed + chunk.length > SIGNING_BUDGET) {
      throw new SignerInputError(
        "SIGNING_BYTES_EXHAUSTED",
        `reader over-draw (returned): ${consumed} + ${chunk.length} B > ${SIGNING_BUDGET} B budget`,
      );
    }
    consumed += chunk.length;
    return chunk;
  };

  // The `Falcon` type alias in `@noble/post-quantum/falcon.d.ts` exposes
  // `sign` via the generic `Signer` shape (`SigOpts` — no `random`). At
  // runtime, `genFalcon` wires the signing pipeline to accept the
  // Falcon-specific `FalconSigOpts` (`random?: (n?: number) => Uint8Array`)
  // — our fork pins this shape. The local type cast here names the wider
  // contract without reaching into the fork's private types.
  const signWithRandom = falcon512paddedEth.sign as (
    msg: Uint8Array,
    secretKey: Uint8Array,
    opts: { random: (n?: number) => Uint8Array },
  ) => Uint8Array;
  const nobleSig = signWithRandom(msg, sk, { random: guardedRandom });
  return hexToBytes(encodeSignatureForZKNOX(nobleSig));
}
