/**
 * Story 5 Task 4 — G4 happy path + AC-FLOW-1 end-to-end test.
 *
 * Two it blocks:
 *
 *   1. AC-5-3 (G4 happy path) — iterate N .rsp vectors, for each:
 *      setKey the reshaped public key, deploy a fresh proxy, sign the
 *      userOp with `signWithRnd` (deterministic .rsp rnd), submit through
 *      EntryPoint's `validateUserOp` simulator, assert
 *      SIG_VALIDATION_SUCCESS (0n).
 *
 *   2. AC-FLOW-1 — 5 iterations of a full fresh-keypair end-to-end:
 *      `keygen()` from ml-dsa-eth.ts → `registerPublicKey` →
 *      fresh proxy → `signUserOp` (production path, hedged rnd via
 *      `crypto.getRandomValues`) → `validateUserOp` simulate → assert
 *      success. Proves the production `signUserOp` path composes with
 *      the on-chain verifier end-to-end, not just the KAT signer.
 *
 * Vector count (AC-5-3) — N constant:
 * -----------------------------------
 * USER DECISION (2026-04-18): smoke-first. Initial landing was N = 5
 * to validate the scaffolding end-to-end and measure runtime; at Gate 5
 * the empirical measurement showed ~80 ms/vector (full 100 ≈ 8 s total,
 * well under the 3 min budget), so N was tuned up to 100 to cover the
 * full KAT corpus per the AC's "all ~100 vectors" literal wording.
 * `N` remains a top-of-file constant for easy future tuning.
 *
 * Failure-class tests (AC-5-4 crypto-invalid + AC-5-5 malformed) live
 * in the sibling `mldsa-eth-failures.test.ts` (Task 5).
 *
 * Import boundary (per story Dev Notes §"test/accounts/** is NOT in the
 * AC-3-7 grep scope"):
 *   - `signWithRnd` from `../signers/ml-dsa-eth.kat-internal.js` is
 *     PERMITTED here (AC-3-7 enforcement is file-path-scoped and does
 *     not cover `test/accounts/**`).
 *   - `keygen` + `signUserOp` imported DIRECTLY from
 *     `../signers/ml-dsa-eth.js` rather than through the dispatcher in
 *     `../signers/index.js` — Task 6 extends that dispatcher's `Scheme`
 *     union to include `"mldsa-eth"`, but this test file lands before
 *     Task 6 commits so we sidestep the ordering.
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import hre from "hardhat";
import { type Hex, encodeFunctionData, hexToBytes, parseEther } from "viem";

import { loadKatVectors } from "../fixtures/kat/index.js";
import {
  deployDilithiumEthVerifier,
  registerPublicKey,
} from "../fixtures/mldsa-eth.js";
import type {
  PackedUserOperation,
  UnsignedUserOp,
} from "../signers/index.js";
import { keygen, signUserOp } from "../signers/ml-dsa-eth.js";
import { signWithRnd } from "../signers/ml-dsa-eth.kat-internal.js";

const SIG_VALIDATION_SUCCESS = 0n;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

/**
 * Vector count for AC-5-3 iteration. Smoke-first (per user decision
 * 2026-04-18): start at 5; tune at Gate 5 if the full 100 fits inside
 * the ≤3 min budget. One-line edit to expand.
 */
const AC_5_3_VECTOR_COUNT = 100;

const FLOW_1_ITERATIONS = 5;

async function deployStack() {
  // Single network connection for EntryPoint + verifier + account —
  // HH3's `network.connect()` hands out an isolated chain per call
  // (see test/fixtures/mldsa.ts top comment for the full rationale).
  const connection = await hre.network.connect();
  const { viem } = connection;
  const publicClient = await viem.getPublicClient();
  const testClient = await viem.getTestClient();

  const entryPoint = await viem.deployContract("EntryPoint");
  const { dilithiumEthVerifier } = await deployDilithiumEthVerifier(viem);

  const implementation = await viem.deployContract("MlDsaEthAccount", [
    entryPoint.address,
    dilithiumEthVerifier.address,
  ]);

  await testClient.impersonateAccount({ address: entryPoint.address });
  await testClient.setBalance({
    address: entryPoint.address,
    value: parseEther("1"),
  });

  const chainId = BigInt(await publicClient.getChainId());

  return {
    viem,
    entryPoint,
    dilithiumEthVerifier,
    implementation,
    chainId,
  };
}

type Stack = Awaited<ReturnType<typeof deployStack>>;

async function deployProxy(stack: Stack, pointerHex: Hex) {
  const initData = encodeFunctionData({
    abi: stack.implementation.abi,
    functionName: "initialize",
    args: [ZERO_ADDRESS, pointerHex],
  });
  const proxy = await stack.viem.deployContract("ERC1967Proxy", [
    stack.implementation.address,
    initData,
  ]);
  return stack.viem.getContractAt("MlDsaEthAccount", proxy.address);
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
  entryPoint: Stack["entryPoint"],
  packed: PackedUserOperation,
): Promise<Hex> {
  return (await entryPoint.read.getUserOpHash([packed])) as Hex;
}

async function simulateValidateUserOp(
  account: Awaited<ReturnType<typeof deployProxy>>,
  entryPointAddress: `0x${string}`,
  signed: PackedUserOperation,
  userOpHash: Hex,
): Promise<bigint> {
  const { result } = await account.simulate.validateUserOp!(
    [signed, userOpHash, 0n],
    { account: entryPointAddress },
  );
  return result as bigint;
}

describe("G4 — MlDsaEthAccount happy path (AC-5-3)", () => {
  const vectors = loadKatVectors("mldsa-eth").slice(0, AC_5_3_VECTOR_COUNT);

  it(
    `${vectors.length} .rsp vectors → SIG_VALIDATION_SUCCESS via signWithRnd + EntryPoint.validateUserOp`,
    { timeout: 5 * 60_000 },
    async () => {
      const stack = await deployStack();

      for (const v of vectors) {
        const rawPk = hexToBytes(v.publicKey as Hex);
        const pointerHex = await registerPublicKey(
          stack.dilithiumEthVerifier,
          rawPk,
        );
        const account = await deployProxy(stack, pointerHex);

        const userOp = buildUnsignedUserOp(account.address);
        const userOpHash = await canonicalUserOpHash(
          stack.entryPoint,
          { ...userOp, signature: "0x" },
        );
        // signWithRnd → deterministic signature per .rsp rnd; this is
        // what AC-5-3 asserts. Production signUserOp (hedged rnd) is
        // exercised in the AC-FLOW-1 block below.
        const sigHex = signWithRnd(
          hexToBytes(v.secretKey as Hex),
          hexToBytes(userOpHash),
          hexToBytes(v.rnd as Hex),
        );
        const signed: PackedUserOperation = { ...userOp, signature: sigHex };

        const validationData = await simulateValidateUserOp(
          account,
          stack.entryPoint.address,
          signed,
          userOpHash,
        );
        assert.equal(
          validationData,
          SIG_VALIDATION_SUCCESS,
          `vec ${v.id}: expected SIG_VALIDATION_SUCCESS (0), got ${validationData}`,
        );
      }
    },
  );
});

describe("AC-FLOW-1 — fresh-keypair end-to-end (production signUserOp)", () => {
  it(
    `${FLOW_1_ITERATIONS} fresh keypairs × production signUserOp → SIG_VALIDATION_SUCCESS`,
    { timeout: 5 * 60_000 },
    async () => {
      const stack = await deployStack();

      for (let i = 0; i < FLOW_1_ITERATIONS; i++) {
        const alice = keygen();
        const pointerHex = await registerPublicKey(
          stack.dilithiumEthVerifier,
          alice.publicKey,
        );
        const account = await deployProxy(stack, pointerHex);

        const userOp = buildUnsignedUserOp(account.address);
        // Production path: signUserOp derives userOpHash internally and
        // sources rnd via crypto.getRandomValues (hedged). Each iteration
        // produces a different signature for the same underlying userOp.
        const signed = await signUserOp(
          alice.secretKey,
          userOp,
          stack.entryPoint.address,
          stack.chainId,
        );
        const userOpHash = await canonicalUserOpHash(stack.entryPoint, signed);

        const validationData = await simulateValidateUserOp(
          account,
          stack.entryPoint.address,
          signed,
          userOpHash,
        );
        assert.equal(
          validationData,
          SIG_VALIDATION_SUCCESS,
          `iteration ${i}: expected SIG_VALIDATION_SUCCESS (0), got ${validationData}`,
        );
      }
    },
  );
});
