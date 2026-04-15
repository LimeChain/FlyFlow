/**
 * Story 1-1 smoke test.
 *
 * Exercises the full Task 4 + Task 5 surface to prove scaffolding works
 * end-to-end before Wave 2 stories layer on scheme-specific logic:
 *   - Deploys EntryPoint via `deployEntryPoint()`
 *   - Generates an ECDSA keypair via `keygen("ecdsa")`
 *   - Signs a minimal UserOp via `signUserOp("ecdsa", ...)`
 *   - Confirms `falcon` and `mldsa` stubs throw `NOT_IMPLEMENTED`
 *
 * Test framework: `node:test` (HH3 default via `@nomicfoundation/hardhat-node-test-runner`).
 * Assertions: `node:assert/strict` (A-001 dropped chai + hardhat-chai-matchers).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { deployEntryPoint } from "./fixtures/entryPoint.js";
import {
  keygen,
  signUserOp,
  type UnsignedUserOp,
} from "./signers/index.js";

describe("Story 1-1 smoke", () => {
  it("deploys EntryPoint with a non-zero address", async () => {
    const { entryPoint } = await deployEntryPoint();

    assert.match(entryPoint.address, /^0x[0-9a-fA-F]{40}$/);
    assert.notStrictEqual(
      entryPoint.address.toLowerCase(),
      "0x0000000000000000000000000000000000000000",
    );
  });

  it("ecdsa keygen returns a 20-byte publicKey and 32-byte secretKey", () => {
    const { publicKey, secretKey } = keygen("ecdsa");

    assert.equal(publicKey.length, 20);
    assert.equal(secretKey.length, 32);
  });

  it("ecdsa signUserOp returns a 65-byte signature", async () => {
    const { secretKey } = keygen("ecdsa");
    const { entryPoint } = await deployEntryPoint();

    const zeroBytes32 = `0x${"0".repeat(64)}` as `0x${string}`;

    const userOp: UnsignedUserOp = {
      sender: "0x0000000000000000000000000000000000000001",
      nonce: 0n,
      initCode: "0x",
      callData: "0x",
      accountGasLimits: zeroBytes32,
      preVerificationGas: 0n,
      gasFees: zeroBytes32,
      paymasterAndData: "0x",
    };

    const signed = await signUserOp(
      "ecdsa",
      secretKey,
      userOp,
      entryPoint.address,
      31337n,
    );

    // 65-byte signature encoded as 0x + 130 hex chars = 132 chars total
    assert.equal(signed.signature.length, 132);
    assert.match(signed.signature, /^0x[0-9a-fA-F]{130}$/);
  });

  it("falcon keygen returns a 897-byte Falcon-512 publicKey and 1281-byte secretKey", () => {
    const { publicKey, secretKey } = keygen("falcon");

    assert.equal(publicKey.length, 897);
    assert.equal(secretKey.length, 1281);
  });

  it("mldsa keygen returns a 1312-byte ML-DSA-44 publicKey and 2560-byte secretKey", () => {
    const { publicKey, secretKey } = keygen("mldsa");

    assert.equal(publicKey.length, 1312);
    assert.equal(secretKey.length, 2560);
  });
});
