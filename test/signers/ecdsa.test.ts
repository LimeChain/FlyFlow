/**
 * Story 5-1, Task 1 — Low-S normalization invariant.
 *
 * Resolves C-006: viem signMessage produces ~50% high-S signatures, and
 * OpenZeppelin's ECDSA.recover rejects them with ECDSAInvalidSignature().
 * normalizeLowS must always return s <= n/2 and preserve recovery.
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  bytesToHex,
  hexToBytes,
  recoverMessageAddress,
  toBytes,
  type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { normalizeLowS } from "./ecdsa.js";

const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;

function extractS(sig: Hex): bigint {
  const bytes = hexToBytes(sig);
  return BigInt(bytesToHex(bytes.slice(32, 64)));
}

describe("ECDSA low-S normalization", () => {
  it("invariant: normalized s is always <= n/2", async () => {
    const SAMPLES = 64;
    const account = privateKeyToAccount(generatePrivateKey());

    for (let i = 0; i < SAMPLES; i++) {
      const message = toBytes(`sample-${i}`);
      const raw = await account.signMessage({ message: { raw: message } });
      const low = normalizeLowS(raw);
      assert.ok(
        extractS(low) <= SECP256K1_HALF_N,
        `signature ${i}: s above n/2 after normalization`,
      );
    }
  });

  it("flips a synthetic high-S signature to low-S and toggles v", () => {
    const r = new Uint8Array(32).fill(0xab);
    const sBig = SECP256K1_HALF_N + 1n;
    const sBytes = hexToBytes(
      `0x${sBig.toString(16).padStart(64, "0")}` as Hex,
    );
    const sig = new Uint8Array(65);
    sig.set(r, 0);
    sig.set(sBytes, 32);
    sig[64] = 27;
    const sigHex = bytesToHex(sig);

    const flipped = normalizeLowS(sigHex);
    const flippedBytes = hexToBytes(flipped);
    const flippedS = BigInt(bytesToHex(flippedBytes.slice(32, 64)));

    assert.ok(flippedS <= SECP256K1_HALF_N, "synthetic high-S did not flip");
    assert.equal(flippedS, SECP256K1_N - sBig);
    assert.equal(flippedBytes[64], 28, "v should toggle 27 → 28");
    assert.deepEqual(
      flippedBytes.slice(0, 32),
      r,
      "r must be preserved across normalization",
    );
  });

  it("preserves recovery to the signing address", async () => {
    const pk = generatePrivateKey();
    const account = privateKeyToAccount(pk);
    const message = toBytes("recovery-check");

    const raw = await account.signMessage({ message: { raw: message } });
    const low = normalizeLowS(raw);

    const recovered = await recoverMessageAddress({
      message: { raw: message },
      signature: low,
    });
    assert.equal(recovered.toLowerCase(), account.address.toLowerCase());
  });

  it("is idempotent on already-low-S input", async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const message = toBytes("idempotent");

    const raw = await account.signMessage({ message: { raw: message } });
    const once = normalizeLowS(raw);
    const twice = normalizeLowS(once);
    assert.equal(once, twice);
  });
});
