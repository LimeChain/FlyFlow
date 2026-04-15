/**
 * Story 3-2 — FalconAccount failure classes.
 *
 * Three rejection paths a FalconAccount must distinguish:
 *   AC-1: Crypto failure (wrong signer) → SIG_VALIDATION_FAILED (1n).
 *   AC-2: Bit-flipped but structurally-parseable signature → 1n.
 *   AC-3: Structurally-invalid signature (100 zero bytes) → reverts with
 *         SignatureMalformed() (try/catch in FalconAccount turns the
 *         ZKNOX_falcon.verify revert into a typed custom error).
 *
 * Bit-flip locus (AC-2): byte 5 sits inside the 40-byte salt region of the
 * 1064-byte ZKNOX payload. Flipping there mutates the hash pre-image without
 * corrupting the Algorithm-18 compressed s2 tail, so the signature remains
 * parseable and the verifier takes the crypto-invalid branch. A flip inside
 * `[40, 1064)` could trip the canonicity checks in `decompressSignature`
 * upstream or the assembly-level unpack in `ZKNOX_falcon.verify`, silently
 * collapsing AC-2 into AC-3.
 *
 * Assertion mechanics (AC-4) are node-native per A-001: `assert.equal` for
 * return-value checks and `assert.rejects(fn, predicate)` with a viem error
 * walker for AC-3. No chai, no hardhat-chai-matchers.
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
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

import { deployFalconVerifier, registerPublicKey } from "../fixtures/falcon.js";
import {
  keygen,
  signUserOp,
  type PackedUserOperation,
  type UnsignedUserOp,
} from "../signers/index.js";

const SIG_VALIDATION_FAILED = 1n;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as `0x${string}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

async function setup() {
  // Single network connection for every contract — same invariant as
  // Story 3-1 happy path (test/accounts/falcon.test.ts:37-75).
  const connection = await hre.network.connect();
  const { viem } = connection;
  const publicClient = await viem.getPublicClient();
  const testClient = await viem.getTestClient();

  const entryPoint = await viem.deployContract("EntryPoint");
  const { falconVerifier } = await deployFalconVerifier(viem);

  const alice = keygen("falcon");
  const pointerHex = await registerPublicKey(falconVerifier, alice.publicKey, publicClient);

  const implementation = await viem.deployContract("FalconAccount", [
    entryPoint.address,
    falconVerifier.address,
  ]);
  const initData = encodeFunctionData({
    abi: implementation.abi,
    functionName: "initialize",
    args: [ZERO_ADDRESS, pointerHex],
  });
  const proxy = await viem.deployContract("ERC1967Proxy", [
    implementation.address,
    initData,
  ]);
  const account = await viem.getContractAt("FalconAccount", proxy.address);

  await testClient.impersonateAccount({ address: entryPoint.address });
  await testClient.setBalance({
    address: entryPoint.address,
    value: parseEther("1"),
  });

  const chainId = BigInt(await publicClient.getChainId());

  return { entryPoint, account, alice, falconVerifier, chainId, testClient };
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

async function canonicalUserOpHash(
  entryPoint: Awaited<ReturnType<typeof setup>>["entryPoint"],
  packed: PackedUserOperation,
): Promise<`0x${string}`> {
  return (await entryPoint.read.getUserOpHash([packed])) as `0x${string}`;
}

async function simulateValidateUserOp(
  account: Awaited<ReturnType<typeof setup>>["account"],
  entryPointAddress: `0x${string}`,
  signed: PackedUserOperation,
  userOpHash: `0x${string}`,
): Promise<bigint> {
  const { result } = await account.simulate.validateUserOp!(
    [signed, userOpHash, 0n],
    { account: entryPointAddress },
  );
  return result as bigint;
}

describe("Story 3-2 — FalconAccount failure classes", () => {
  it(
    "AC-1: wrong signer returns SIG_VALIDATION_FAILED",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, chainId } = await setup();
      // Account is registered with Alice's pk in setup(). Bob is a separate
      // keygen — noble uses crypto.getRandomValues so the two keypairs are
      // statistically independent without any explicit seeding.
      const bob = keygen("falcon");

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
        "falcon",
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
    },
  );

  it(
    "AC-2: bit-flipped signature (salt region) returns SIG_VALIDATION_FAILED",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, alice, chainId } = await setup();

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
        "falcon",
        alice.secretKey,
        userOp,
        entryPoint.address,
        chainId,
      );
      const userOpHash = await canonicalUserOpHash(entryPoint, signed);

      const sigBytes = hexToBytes(signed.signature);
      assert.equal(sigBytes.length, 1064, "Falcon signature must be 1064 bytes");

      // Salt region is [0, 40). Flipping byte 5 mutates the hash pre-image
      // without touching the Algorithm-18 compressed s2 tail, so the signature
      // stays parseable and the verifier returns SIG_VALIDATION_FAILED instead
      // of reverting.
      sigBytes[5] ^= 0x01;
      const corrupted: PackedUserOperation = {
        ...signed,
        signature: bytesToHex(sigBytes),
      };

      const validationData = await simulateValidateUserOp(
        account,
        entryPoint.address,
        corrupted,
        userOpHash,
      );

      assert.equal(validationData, SIG_VALIDATION_FAILED);
    },
  );

  it(
    "AC-3: malformed signature reverts with SignatureMalformed",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, alice, chainId } = await setup();
      const accountAddress = account.address.toLowerCase();

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
        "falcon",
        alice.secretKey,
        userOp,
        entryPoint.address,
        chainId,
      );
      const userOpHash = await canonicalUserOpHash(entryPoint, signed);

      // 100 zero bytes — length mismatch (≠ 1064) and no 40-byte salt prefix.
      // ZKNOX_falcon.verify's assembly will revert during unpack; FalconAccount's
      // try/catch translates that into the typed SignatureMalformed() error.
      const malformed: PackedUserOperation = {
        ...signed,
        signature: bytesToHex(new Uint8Array(100)),
      };

      await assert.rejects(
        () =>
          simulateValidateUserOp(
            account,
            entryPoint.address,
            malformed,
            userOpHash,
          ),
        (err: unknown) => {
          if (!(err instanceof BaseError)) throw err;
          // Canonical viem path: ContractFunctionRevertedError with a decoded
          // `data.errorName`. Populated when viem's ABI-aware decoder runs.
          const revert = err.walk(
            (e) => e instanceof ContractFunctionRevertedError,
          ) as ContractFunctionRevertedError | null;
          if (revert?.data?.errorName === "SignatureMalformed") return true;
          // HH3 EDR path: the revert surfaces as a `SolidityError` at the chain
          // tail and viem's decoder doesn't populate `errorName`, but the EDR
          // message text deterministically contains "SignatureMalformed()".
          // Bind the match to the account-under-test's address so that a future
          // co-defined `SignatureMalformed()` in a sibling contract (e.g. when
          // Story 4-2 introduces ML-DSA failure tests) can't spuriously satisfy
          // this predicate.
          const message = err.message.toLowerCase();
          return (
            /custom error 'signaturemalformed\(\)'/.test(message) &&
            message.includes(accountAddress)
          );
        },
      );
    },
  );
});
