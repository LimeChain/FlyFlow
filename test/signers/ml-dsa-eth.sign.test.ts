/**
 * Story 4 Task 5 — Input-validation + production-path + hedged-sign
 * test (AC-4-2, AC-4-3, AC-4-4, AC-4-6).
 *
 * Covers the four ACs the G2 KAT (Task 4) does not exercise:
 *   - AC-4-2: `signUserOp` returns a 2420 B signature (4842 hex chars)
 *     and preserves every {@link UnsignedUserOp} field via spread.
 *   - AC-4-3: `signWithRnd` throws `SignerInputError` with
 *     `code: "INVALID_SECRET_KEY_LENGTH"` on `sk.length !== 2560`.
 *   - AC-4-4: `signWithRnd` throws `SignerInputError` with
 *     `code: "INVALID_MESSAGE"` on shapes other than `Uint8Array` /
 *     `0x`-prefixed hex string.
 *   - AC-4-6: two back-to-back `signUserOp` calls with identical inputs
 *     diverge — validates the hedged `rnd` path.
 *
 * Assertion style: `err instanceof SignerInputError && err.code === "..."`
 * NEVER `err.message.includes(...)`. Per `.claude/rules/test-integrity.md`
 * and the error-discriminant convention established by
 * `KatFixtureError` / `PrgLifecycleError` / `NotImplementedError`.
 *
 * `signUserOp` tests inline a minimal static {@link UnsignedUserOp} — the
 * ACs assert on format + spread preservation + hedge divergence, not on
 * ERC-4337 on-chain acceptance (that's Story 5's G4 gate behind a
 * deployed verifier).
 *
 * Pure `node:test` — no Hardhat runtime.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { type Hex, hexToBytes } from "viem";

import { SignerInputError } from "./errors.js";
import type { UnsignedUserOp } from "./index.js";
import { keygen, signUserOp } from "./ml-dsa-eth.js";
import { signWithRnd } from "./ml-dsa-eth.kat-internal.js";

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const SENDER: `0x${string}` = "0x0000000000000000000000000000000000000001";
// Any valid 20-byte address works — computeUserOpHash only needs it for
// hashing; these tests assert on signature format + hedge divergence, not
// on ERC-4337 on-chain validity. Using all-zeros-plus-2 avoids viem's
// EIP-55 checksum enforcement on mixed-case addresses.
const ENTRY_POINT: `0x${string}` = "0x0000000000000000000000000000000000000002";
const CHAIN_ID = 31337n;

function buildUserOp(): UnsignedUserOp {
  return {
    sender: SENDER,
    nonce: 0n,
    initCode: "0x",
    callData: "0x",
    accountGasLimits: ZERO_BYTES32,
    preVerificationGas: 0n,
    gasFees: ZERO_BYTES32,
    paymasterAndData: "0x",
  };
}

describe("signWithRnd input validation (AC-4-3, AC-4-4)", () => {
  // Materialised once — node:test `describe` body runs synchronously at
  // collection time so a single module-load keygen covers every it().
  const validSk = keygen().secretKey;
  const validMsg = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const validRnd = new Uint8Array(32);

  it("test setup sanity: keygen() produces a 2560 B secret key", () => {
    assert.equal(validSk.length, 2560);
  });

  describe("AC-4-3: INVALID_SECRET_KEY_LENGTH", () => {
    it("throws on sk.length === 2559 (one byte short)", () => {
      assert.throws(
        () => signWithRnd(new Uint8Array(2559), validMsg, validRnd),
        (err: unknown) =>
          err instanceof SignerInputError &&
          err.code === "INVALID_SECRET_KEY_LENGTH",
      );
    });

    it("throws on sk.length === 2561 (one byte long)", () => {
      assert.throws(
        () => signWithRnd(new Uint8Array(2561), validMsg, validRnd),
        (err: unknown) =>
          err instanceof SignerInputError &&
          err.code === "INVALID_SECRET_KEY_LENGTH",
      );
    });

    it("throws on empty sk (sk.length === 0)", () => {
      assert.throws(
        () => signWithRnd(new Uint8Array(0), validMsg, validRnd),
        (err: unknown) =>
          err instanceof SignerInputError &&
          err.code === "INVALID_SECRET_KEY_LENGTH",
      );
    });
  });

  describe("AC-4-4: INVALID_MESSAGE", () => {
    const rejectedShapes: Array<[string, unknown]> = [
      ["null", null],
      ["plain object", {}],
      ["number", 42],
      ["non-0x-prefixed string", "not-hex"],
      ["0x-prefixed string with invalid hex chars", "0xZZ"],
    ];
    for (const [label, msg] of rejectedShapes) {
      it(`throws on ${label}`, () => {
        assert.throws(
          () => signWithRnd(validSk, msg as Uint8Array, validRnd),
          (err: unknown) =>
            err instanceof SignerInputError && err.code === "INVALID_MESSAGE",
        );
      });
    }
  });

  describe("positive path", () => {
    it("returns a 0x-prefixed 4842-char hex string for Uint8Array msg", () => {
      const sig = signWithRnd(validSk, validMsg, validRnd);
      assert.equal(typeof sig, "string");
      assert.ok(sig.startsWith("0x"));
      // 2 prefix chars + 2420 B × 2 hex chars = 4842.
      assert.equal(sig.length, 4842);
    });

    it("hex-string msg and Uint8Array msg produce IDENTICAL output (coercion equivalence)", () => {
      const sigFromHex = signWithRnd(validSk, "0xdeadbeef" as Hex, validRnd);
      const sigFromBytes = signWithRnd(
        validSk,
        hexToBytes("0xdeadbeef"),
        validRnd,
      );
      assert.equal(sigFromHex, sigFromBytes);
    });
  });
});

describe("signUserOp production path (AC-4-2, AC-4-6)", () => {
  it("AC-4-2: returns a PackedUserOperation with a 4842-char signature; spread preserved", async () => {
    const { secretKey } = keygen();
    const userOp = buildUserOp();
    const signed = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);

    assert.equal(signed.signature.length, 4842);
    assert.ok(signed.signature.startsWith("0x"));
    // Spread preserves every UnsignedUserOp field verbatim.
    assert.equal(signed.sender, userOp.sender);
    assert.equal(signed.nonce, userOp.nonce);
    assert.equal(signed.initCode, userOp.initCode);
    assert.equal(signed.callData, userOp.callData);
    assert.equal(signed.accountGasLimits, userOp.accountGasLimits);
    assert.equal(signed.preVerificationGas, userOp.preVerificationGas);
    assert.equal(signed.gasFees, userOp.gasFees);
    assert.equal(signed.paymasterAndData, userOp.paymasterAndData);
  });

  it("AC-4-6: two identical-input calls produce DIFFERENT signatures (hedged rnd)", async () => {
    const { secretKey } = keygen();
    const userOp = buildUserOp();
    const s1 = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);
    const s2 = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);

    assert.notEqual(
      s1.signature,
      s2.signature,
      "hedged sign should diverge on repeated calls with identical inputs",
    );
    assert.equal(s1.signature.length, 4842);
    assert.equal(s2.signature.length, 4842);
  });
});
