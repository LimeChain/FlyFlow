/**
 * Story 4-1 — MlDsaAccount happy-path acceptance.
 *
 * Mirrors the Story 2-1 EcdsaAccount setup pattern (deploy EntryPoint +
 * implementation + ERC1967Proxy + impersonate EntryPoint + simulate
 * validateUserOp). Adds the ML-DSA-specific path: deploy the
 * ZKNOX_dilithium verifier, ABI-encode the noble public key via the
 * Task 2 bridge, register it via setKey() to obtain the 20-byte SSTORE2
 * pointer, and pass that pointer (NOT the raw 1,312-byte key, per A-003)
 * into MlDsaAccount.initialize.
 *
 * Failure-class cases (wrong-key, bit-flipped, malformed) are Story 4-2.
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import hre from "hardhat";
import { encodeFunctionData, hexToBytes, parseEther } from "viem";

import { deployDilithiumVerifier, registerPublicKey } from "../fixtures/mldsa.js";
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
  // Single network connection for every contract: HH3's `network.connect()`
  // hands out an isolated chain per call, so deploying EntryPoint, the
  // verifier, and the account on separate connections leaves
  // `MlDsaAccount.dilithiumVerifier` pointing at an empty address from the
  // account's chain — the staticcall returns empty data and the bytes4
  // decode reverts (caught as `SignatureMalformed`).
  const connection = await hre.network.connect();
  const { viem } = connection;
  const publicClient = await viem.getPublicClient();
  const testClient = await viem.getTestClient();

  const entryPoint = await viem.deployContract("EntryPoint");
  const { dilithiumVerifier } = await deployDilithiumVerifier(viem);

  const alice = keygen("mldsa");
  const pointerHex = await registerPublicKey(dilithiumVerifier, alice.publicKey);

  const implementation = await viem.deployContract("MlDsaAccount", [
    entryPoint.address,
    dilithiumVerifier.address,
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
  const account = await viem.getContractAt("MlDsaAccount", proxy.address);

  await testClient.impersonateAccount({ address: entryPoint.address });
  await testClient.setBalance({
    address: entryPoint.address,
    value: parseEther("1"),
  });

  const chainId = BigInt(await publicClient.getChainId());

  return { entryPoint, account, alice, dilithiumVerifier, chainId, testClient };
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

describe("Story 4-1 — MlDsaAccount", () => {
  it("AC-1: keygen returns 1312-byte ML-DSA-44 publicKey", () => {
    const { publicKey, secretKey } = keygen("mldsa");
    assert.equal(publicKey.length, 1312);
    assert.equal(secretKey.length, 2560);
  });

  it("AC-2: signed UserOp signature is 2420 bytes (cTilde(32)+z(2304)+h(84))", async () => {
    const { entryPoint, account, alice, chainId } = await setup();
    const userOp = buildUnsignedUserOp(account.address);
    const signed = await signUserOp(
      "mldsa",
      alice.secretKey,
      userOp,
      entryPoint.address,
      chainId,
    );
    assert.equal(hexToBytes(signed.signature).length, 2420);
  });

  it(
    "AC-3: valid ML-DSA signature returns SIG_VALIDATION_SUCCESS",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, alice, chainId } = await setup();

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
        "mldsa",
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

  it("AC-4: source wraps dilithiumVerifier.verify in try/catch with SignatureMalformed", async () => {
    const source = await readFile("contracts/MlDsaAccount.sol", "utf8");

    assert.ok(
      source.includes(
        "dilithiumVerifier.verify(publicKey, userOpHash, userOp.signature)",
      ),
      "MlDsaAccount.sol must call dilithiumVerifier.verify with the canonical 3-arg form",
    );
    assert.match(
      source,
      /try\s+dilithiumVerifier\.verify\s*\(/,
      "must wrap dilithiumVerifier.verify call in a `try` block (not just contain the word 'try')",
    );
    assert.match(
      source,
      /\}\s*catch\b/,
      "must close the try with a `catch` block (not just contain the word 'catch')",
    );
    assert.ok(
      source.includes("SignatureMalformed"),
      "must declare SignatureMalformed custom error",
    );
    assert.ok(
      source.includes("is SimpleAccount"),
      "must inherit from SimpleAccount",
    );
  });
});
