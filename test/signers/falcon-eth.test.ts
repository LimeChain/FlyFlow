/**
 * falcon-eth module production-surface + seed-rejection unit tests.
 *
 * Covers the non-G3 acceptance surface for `test/signers/falcon-eth.ts`
 * after the fork extraction moved the crypto surface to
 * `@noble/post-quantum/utils-eth.js`:
 *
 * - Production `keygen()` hedging — two consecutive calls return byte-distinct
 *   public keys (entropy from `globalThis.crypto.getRandomValues`).
 * - Production `keygen()` returns 897 B pk + 1281 B sk.
 * - Seed-length rejection at the fork boundary — noble's `falcon512.keygen`
 *   uses `abytes(seed, 48, 'seed')` which throws on non-48-byte or non-
 *   `Uint8Array` inputs. Post-extraction, the repo does NOT wrap this with
 *   a `SignerInputError`; tests assert on noble's native error class
 *   (deliberate coverage reduction per `docs/.archive-extract-falconeth/
 *   quick-extract-falconeth.md` LD-6 — the ML-DSA paths followed the same
 *   pattern during the subsequent ml-dsa-eth extraction, fully collapsing
 *   the `SignerInputError` class).
 *
 * KAT byte-identity is covered by `falcon-eth.keygen.kat.test.ts`.
 *
 * AC-5/AC-6 kat-internal boundary grep tests are dropped — the
 * `falcon-eth.kat-internal.ts` module no longer exists after the fork
 * extraction. KAT surfaces (signing, keygen) now route directly through
 * noble's public APIs; there is no `kat-internal` boundary to enforce.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { falcon512 } from "@noble/post-quantum/falcon.js";

import { bytesEqual } from "../utils/assert-bytes.js";
import { keygen } from "./falcon-eth.js";

describe("falcon-eth keygen surfaces (hedging + seed rejection)", () => {
  it("keygen() returns byte-distinct public keys across two calls (hedging)", () => {
    const a = keygen();
    const b = keygen();
    // Collision probability ~2^-897 — equality here means CSPRNG was mocked.
    assert.ok(
      !bytesEqual(a.publicKey, b.publicKey),
      "two production keygen() calls returned identical publicKey",
    );
  });

  it("keygen() returns 897 B publicKey + 1281 B secretKey", () => {
    const { publicKey, secretKey } = keygen();
    assert.equal(publicKey.length, 897, "publicKey length");
    assert.equal(secretKey.length, 1281, "secretKey length");
  });

  describe("seed-length rejection (noble's abytes, post-fork-extraction)", () => {
    it("rejects 47-byte seed with an Error (length mismatch)", () => {
      assert.throws(
        () => falcon512.keygen(new Uint8Array(47)),
        (e: unknown) => e instanceof Error,
      );
    });

    it("rejects 49-byte seed with an Error (length mismatch)", () => {
      assert.throws(
        () => falcon512.keygen(new Uint8Array(49)),
        (e: unknown) => e instanceof Error,
      );
    });

    it("rejects empty Uint8Array (0 B) with an Error", () => {
      assert.throws(
        () => falcon512.keygen(new Uint8Array(0)),
        (e: unknown) => e instanceof Error,
      );
    });

    it("rejects non-Uint8Array (string) with an Error (type mismatch)", () => {
      assert.throws(
        () =>
          falcon512.keygen("not-bytes" as unknown as Uint8Array),
        (e: unknown) => e instanceof Error,
      );
    });
  });
});
