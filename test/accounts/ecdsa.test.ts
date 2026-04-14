/**
 * Story 2-1 — EcdsaAccount acceptance + rejection tests.
 *
 * Covers AC-1/AC-2/AC-3 by calling `validateUserOp` directly with the
 * EntryPoint impersonated as msg.sender, so the `uint256 validationData`
 * return is observable without decoding `FailedOp` revert reasons.
 * AC-4 is a source-inspection grep that enforces DD-10 (no
 * `_validateSignature` override in EcdsaAccount.sol).
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import hre from "hardhat";
import {
  BaseError,
  ContractFunctionRevertedError,
  bytesToHex,
  encodeFunctionData,
  hexToBytes,
  parseEther,
} from "viem";

import { deployEntryPoint } from "../fixtures/entryPoint.js";
import {
  keygen,
  signUserOp,
  type PackedUserOperation,
  type UnsignedUserOp,
} from "../signers/index.js";

const SIG_VALIDATION_SUCCESS = 0n;
const SIG_VALIDATION_FAILED = 1n;

const ZERO_BYTES32 = `0x${"0".repeat(64)}` as `0x${string}`;

/**
 * Deploy EntryPoint + EcdsaAccount (via ERC1967Proxy, matching production
 * usage — SimpleAccount's constructor calls `_disableInitializers()` so
 * `initialize` must run through a proxy with fresh storage). Impersonate
 * the EntryPoint so subsequent `validateUserOp` simulations pass the
 * `_requireFromEntryPoint()` gate.
 */
async function setup() {
  const { entryPoint, publicClient } = await deployEntryPoint();
  const connection = await hre.network.connect();
  const { viem } = connection;
  const testClient = await viem.getTestClient();

  const alice = keygen("ecdsa");
  const aliceAddress = bytesToHex(alice.publicKey);

  const implementation = await viem.deployContract("EcdsaAccount", [
    entryPoint.address,
  ]);
  const initData = encodeFunctionData({
    abi: implementation.abi,
    functionName: "initialize",
    args: [aliceAddress],
  });
  const proxy = await viem.deployContract("ERC1967Proxy", [
    implementation.address,
    initData,
  ]);
  const account = await viem.getContractAt("EcdsaAccount", proxy.address);

  await testClient.impersonateAccount({ address: entryPoint.address });
  await testClient.setBalance({
    address: entryPoint.address,
    value: parseEther("1"),
  });

  const chainId = BigInt(await publicClient.getChainId());

  return {
    entryPoint,
    account,
    alice,
    aliceAddress,
    chainId,
    testClient,
  };
}

function buildUnsignedUserOp(sender: `0x${string}`): UnsignedUserOp {
  return {
    sender,
    nonce: 0n,
    initCode: "0x",
    callData: "0x",
    accountGasLimits: ZERO_BYTES32,
    preVerificationGas: 0n,
    gasFees: ZERO_BYTES32,
    paymasterAndData: "0x",
  };
}

/**
 * Compute the canonical userOpHash via the on-chain EntryPoint's
 * `getUserOpHash`. Using the live contract removes any risk of a hash
 * drift between the signer module and the verifier bypassing the test.
 */
async function canonicalUserOpHash(
  entryPoint: Awaited<ReturnType<typeof deployEntryPoint>>["entryPoint"],
  packed: PackedUserOperation,
): Promise<`0x${string}`> {
  return (await entryPoint.read.getUserOpHash([packed])) as `0x${string}`;
}

/**
 * Call `validateUserOp` with the EntryPoint as msg.sender via simulate.
 * `validateUserOp` is non-view, so `read` won't work — `simulate` executes
 * the call against current state without mining a tx and returns the
 * `uint256 validationData`.
 */
async function simulateValidateUserOp(
  account: Awaited<ReturnType<typeof setup>>["account"],
  entryPointAddress: `0x${string}`,
  signed: PackedUserOperation,
  userOpHash: `0x${string}`,
): Promise<bigint> {
  const { result } = await account.simulate.validateUserOp(
    [signed, userOpHash, 0n],
    { account: entryPointAddress },
  );
  return result as bigint;
}

describe("Story 2-1 — EcdsaAccount", () => {
  it("AC-1: valid owner signature returns SIG_VALIDATION_SUCCESS", async () => {
    const { entryPoint, account, alice, chainId } = await setup();

    const userOp = buildUnsignedUserOp(account.address);
    const signed = await signUserOp(
      "ecdsa",
      alice.secretKey,
      userOp,
      entryPoint.address,
      chainId,
    );
    const userOpHash = await canonicalUserOpHash(entryPoint, signed);

    const validationData = await simulateValidateUserOp(
      account,
      entryPoint.address,
      signed,
      userOpHash,
    );

    assert.equal(validationData, SIG_VALIDATION_SUCCESS);
  });

  it("AC-2: wrong-key signature returns SIG_VALIDATION_FAILED", async () => {
    const { entryPoint, account, chainId } = await setup();
    const bob = keygen("ecdsa");

    const userOp = buildUnsignedUserOp(account.address);
    const signed = await signUserOp(
      "ecdsa",
      bob.secretKey,
      userOp,
      entryPoint.address,
      chainId,
    );
    const userOpHash = await canonicalUserOpHash(entryPoint, signed);

    const validationData = await simulateValidateUserOp(
      account,
      entryPoint.address,
      signed,
      userOpHash,
    );

    assert.equal(validationData, SIG_VALIDATION_FAILED);
  });

  it("AC-3: bit-flipped signature is rejected", async () => {
    const { entryPoint, account, alice, chainId } = await setup();

    const userOp = buildUnsignedUserOp(account.address);
    const signed = await signUserOp(
      "ecdsa",
      alice.secretKey,
      userOp,
      entryPoint.address,
      chainId,
    );
    const userOpHash = await canonicalUserOpHash(entryPoint, signed);

    // Flip one bit inside byte 5 of r (well away from s/v malleability checks).
    const sigBytes = hexToBytes(signed.signature);
    sigBytes[5] ^= 0x01;
    const corrupted: PackedUserOperation = {
      ...signed,
      signature: bytesToHex(sigBytes),
    };

    // Accept either a `1n` return (ecrecover → different address) or an
    // OpenZeppelin ECDSA revert (malleability / invalid-signature class).
    // Both satisfy AC-3's "not SUCCESS" intent. Rethrow any unrelated
    // error so test-infrastructure regressions don't masquerade as
    // valid rejections.
    let validationData: bigint | null = null;
    let reverted = false;
    try {
      validationData = await simulateValidateUserOp(
        account,
        entryPoint.address,
        corrupted,
        userOpHash,
      );
    } catch (err) {
      if (err instanceof BaseError) {
        const revert = err.walk(
          (e) => e instanceof ContractFunctionRevertedError,
        ) as ContractFunctionRevertedError | null;
        const name = revert?.data?.errorName;
        if (
          name === "ECDSAInvalidSignature" ||
          name === "ECDSAInvalidSignatureS" ||
          name === "ECDSAInvalidSignatureLength"
        ) {
          reverted = true;
        } else {
          throw err;
        }
      } else {
        throw err;
      }
    }

    assert.ok(
      reverted || validationData === SIG_VALIDATION_FAILED,
      `expected rejection; got validationData=${String(validationData)} reverted=${reverted}`,
    );
  });

  it("AC-4: source contains no _validateSignature override (DD-10)", async () => {
    const source = await readFile("contracts/EcdsaAccount.sol", "utf8");

    assert.ok(
      !source.includes("_validateSignature"),
      "EcdsaAccount.sol must not override _validateSignature (DD-10)",
    );
    assert.ok(
      source.includes("is SimpleAccount"),
      "EcdsaAccount.sol must inherit from SimpleAccount",
    );
  });
});
