/**
 * Falcon-ETH production keygen surface (Story 2-1 Task T2; `docs/amendments.md`
 * §A-005 library-first).
 *
 * Exposes `keygen()` — production entry point that sources a 48-byte
 * `innerSeed` from `globalThis.crypto.getRandomValues` (Node ≥19 / browser
 * Web Crypto) and forwards to `@noble/post-quantum/falcon.js#falcon512.keygen`.
 *
 * KAT-only helpers (explicit-innerSeed keygen) live in
 * `falcon-eth.kat-internal.ts` and MUST NOT be imported here — the runtime
 * grep at `falcon-eth.test.ts` enforces that boundary (AC-5 / AC-6).
 *
 * Entropy source: Node's global Web Crypto API —
 * `globalThis.crypto.getRandomValues(new Uint8Array(48))`. No `node:crypto`
 * import is required; this matches the idiom established by
 * `test/signers/ml-dsa-eth.ts#keygen`.
 */

import { falcon512 } from "@noble/post-quantum/falcon.js";

import type { Keypair } from "./index.js";

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
