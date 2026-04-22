/**
 * ml-dsa-eth signer input-validation + hedged-sign tests.
 *
 * Post-fork-extraction scope (AC-4-2, AC-4-3, AC-4-4, AC-4-6):
 *
 * - **AC-4-2**: `signUserOp` returns a 4842-char hex signature and
 *   preserves every {@link UnsignedUserOp} field via spread.
 * - **AC-4-3** (retargeted — LD-12): wrong-length `sk` causes
 *   `ml_dsa44eth.sign` to throw. The original `SignerInputError` code
 *   `INVALID_SECRET_KEY_LENGTH` is dropped — noble throws natively from
 *   `secretCoder.decode(sk)` via `splitCoder` when the total byte count
 *   mismatches the expected layout. We assert on `throws`, not on class.
 * - **AC-4-4** (retargeted): non-`Uint8Array` `msg` causes noble's
 *   `abytes_(msg)` inside `getMessage` to throw a native `TypeError`.
 *   The original `SignerInputError` code `INVALID_MESSAGE` is dropped.
 * - **AC-4-6**: two back-to-back `signUserOp` calls with identical
 *   inputs diverge — validates the hedged `extraEntropy` path
 *   (noble sources fresh 32 B per call).
 *
 * Deliberate coverage reductions vs pre-extraction:
 * - Hex-string `msg` coercion test removed — noble accepts `Uint8Array`
 *   only; no in-signer hex path to exercise.
 * - `SignerInputError`-class assertions removed — tests now assert on
 *   the throw alone. The original class discriminant was a repo-side
 *   wrapper; noble's native errors (`TypeError` / `Error`) are the new
 *   contract surface.
 *
 * Pure `node:test` — no Hardhat runtime.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ml_dsa44eth } from "@noble/post-quantum/ml-dsa.js";
import { type Hex } from "viem";

import type { UnsignedUserOp } from "./index.js";
import { keygen, signUserOp } from "./ml-dsa-eth.js";

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const SENDER: `0x${string}` = "0x0000000000000000000000000000000000000001";
// Any valid 20-byte address works — computeUserOpHash only needs it for
// hashing; these tests assert on signature format + hedge divergence, not
// on ERC-4337 on-chain validity.
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

describe("ml_dsa44eth.sign input validation (AC-4-3, AC-4-4 retargeted)", () => {
  const validSk = keygen().secretKey;
  const validMsg = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

  it("test setup sanity: keygen() produces a 2560 B secret key", () => {
    assert.equal(validSk.length, 2560);
  });

  describe("AC-4-3 (retargeted): wrong-length sk throws", () => {
    it("throws on sk.length === 2559 (one byte short)", () => {
      assert.throws(() => ml_dsa44eth.sign(validMsg, new Uint8Array(2559)));
    });

    it("throws on sk.length === 2561 (one byte long)", () => {
      assert.throws(() => ml_dsa44eth.sign(validMsg, new Uint8Array(2561)));
    });

    it("throws on empty sk (sk.length === 0)", () => {
      assert.throws(() => ml_dsa44eth.sign(validMsg, new Uint8Array(0)));
    });
  });

  describe("AC-4-4 (retargeted): non-Uint8Array msg throws TypeError", () => {
    const rejectedShapes: Array<[string, unknown]> = [
      ["null", null],
      ["plain object", {}],
      ["number", 42],
      ["plain string", "not-bytes"],
    ];
    for (const [label, msg] of rejectedShapes) {
      it(`throws on ${label}`, () => {
        assert.throws(
          () => ml_dsa44eth.sign(msg as Uint8Array, validSk),
          TypeError,
        );
      });
    }
  });

  describe("positive path", () => {
    it("returns a 2420 B signature on valid Uint8Array msg + sk", () => {
      const sig = ml_dsa44eth.sign(validMsg, validSk);
      assert.equal(sig.length, 2420);
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
