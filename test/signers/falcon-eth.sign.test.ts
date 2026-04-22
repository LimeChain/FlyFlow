/**
 * Falcon-ETH signer-surface unit tests — production `signUserOp` hedging
 * + signature-length invariants.
 *
 * Covers the non-G4 acceptance surface for `test/signers/falcon-eth.ts`
 * after the fork extraction moved the crypto surface to
 * `@noble/post-quantum/{falcon,utils-eth}.js`:
 *
 * - **Hedged production sign.** Two `signUserOp` calls with identical
 *   `(sk, userOp, entryPoint, chainId)` produce signatures whose first 40 B
 *   (salt) differ — the randomness source is Web Crypto, not a fixed seed.
 * - **Signature-length + spread invariants.** 1064 B ZKNox layout → 2130
 *   hex chars (0x prefix + 2128 body). Every `UnsignedUserOp` field passes
 *   through unchanged.
 *
 * KAT byte-identity (signer parity over ~100 fixture vectors) is covered by
 * `falcon-eth.sign.kat.test.ts`. The old AC-3/AC-5/AC-6/AC-7 blocks that
 * tested `signWithKatBytes` / `BytesReader` / `keygenInternal` + kat-internal
 * boundary grep are dropped — those surfaces no longer exist post-fork-
 * extraction (KAT tests now call noble primitives directly; there is no
 * kat-internal module to enforce a boundary against).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { type Hex, hexToBytes } from "viem";

import { bytesEqual } from "../utils/assert-bytes.js";
import { keygen, signUserOp } from "./falcon-eth.js";
import type { UnsignedUserOp } from "./index.js";

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const SENDER: `0x${string}` = "0x0000000000000000000000000000000000000001";
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

describe("Falcon-ETH signUserOp surface (hedging + length/spread invariants)", () => {
  it("two calls with identical inputs return signatures with DIFFERENT salts", async () => {
    const { secretKey } = keygen();
    const userOp = buildUserOp();
    const a = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);
    const b = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);

    // Signature layout is salt(40) || s2_compact(1024). First 40 B must
    // differ — collision probability ≈ 2⁻³²⁰.
    const aBytes = hexToBytes(a.signature);
    const bBytes = hexToBytes(b.signature);
    const saltA = aBytes.subarray(0, 40);
    const saltB = bBytes.subarray(0, 40);
    assert.ok(
      !bytesEqual(saltA, saltB),
      "two hedged signUserOp calls returned identical 40 B salts",
    );
  });

  it("returns a 2130-char 0x-prefixed hex signature and preserves every UserOp field", async () => {
    const { secretKey } = keygen();
    const userOp = buildUserOp();
    const signed = await signUserOp(secretKey, userOp, ENTRY_POINT, CHAIN_ID);

    // 1064 B × 2 hex chars + 2 prefix chars = 2130.
    assert.equal(signed.signature.length, 2130);
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
});
