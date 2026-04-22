/**
 * Story 3-1 — FalconAccount happy-path acceptance.
 *
 * Mirrors the Story 4-1 MlDsaAccount setup pattern (single
 * `hre.network.connect()` + deploy EntryPoint + verifier + ERC1967Proxy +
 * impersonate EntryPoint + simulate validateUserOp). Falcon-specific
 * differences: raw 897-byte NIST public key is decoded, NTT-transformed,
 * and compacted into a 32-word uint256[] by `encodeFalconPublicKey`
 * (from `@noble/post-quantum/utils-eth.js`) before `setKey` writes it via
 * SSTORE2; noble's detached signature is reshaped to the 1064-byte
 * `salt(40) || s2_compact(1024)` form by `encodeFalconSignature`
 * inside `signUserOp("falcon", ...)`.
 *
 * Failure-class cases (wrong-key, bit-flipped, malformed) are Story 3-2.
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import hre from "hardhat";
import { encodeFunctionData, hexToBytes, parseEther } from "viem";

import { deployFalconVerifier, registerPublicKey } from "../fixtures/falcon.js";
import {
  keygen,
  signUserOp,
  type PackedUserOperation,
  type UnsignedUserOp,
} from "../signers/index.js";

const SIG_VALIDATION_SUCCESS = 0n;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as `0x${string}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

async function setup() {
  // Single network connection for every contract — same constraint as
  // Story 4-1 (see test/accounts/mldsa.test.ts:38-42).
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

describe("Story 3-1 — FalconAccount", () => {
  it("AC-1: keygen returns 897-byte Falcon-512 publicKey", () => {
    const { publicKey, secretKey } = keygen("falcon");
    assert.equal(publicKey.length, 897);
    assert.equal(secretKey.length, 1281);
  });

  it("AC-2: signed UserOp signature is 1064 bytes (salt(40)+s2_compact(1024))", async () => {
    const { entryPoint, account, alice, chainId } = await setup();
    const userOp = buildUnsignedUserOp(account.address);
    const signed = await signUserOp(
      "falcon",
      alice.secretKey,
      userOp,
      entryPoint.address,
      chainId,
    );
    assert.equal(hexToBytes(signed.signature).length, 1064);
  });

  it(
    "AC-3: valid Falcon signature returns SIG_VALIDATION_SUCCESS",
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

      const validationData = await simulateValidateUserOp(
        account,
        entryPoint.address,
        signed,
        userOpHash,
      );

      assert.equal(validationData, SIG_VALIDATION_SUCCESS);
    },
  );

  it("AC-4: source wraps falconVerifier.verify in try/catch with SignatureMalformed", async () => {
    const source = await readFile("contracts/FalconAccount.sol", "utf8");

    assert.ok(
      source.includes(
        "falconVerifier.verify(publicKeyPointer, userOpHash, userOp.signature)",
      ),
      "FalconAccount.sol must call falconVerifier.verify with the canonical 3-arg form (A-006: publicKey → publicKeyPointer)",
    );
    // Single bound check: try { falconVerifier.verify(...) ... } catch ... SignatureMalformed.
    // Looser regex (separate try/catch/SignatureMalformed includes) allowed an unrelated
    // try/catch elsewhere in the file to satisfy the AC while the verifier call lost its
    // catch arm. Story 3-2's runtime assertion is the real backstop, but until then this
    // structural check should bind the three pieces together.
    assert.match(
      source,
      /try\s+falconVerifier\.verify[\s\S]{0,400}?\}\s*catch[\s\S]{0,200}?SignatureMalformed/,
      "must bind try/catch/SignatureMalformed to the falconVerifier.verify call",
    );
    assert.ok(
      source.includes("is SimpleAccount"),
      "must inherit from SimpleAccount",
    );
  });
});
