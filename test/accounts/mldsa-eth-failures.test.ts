/**
 * Story 5 Task 5 — MlDsaEthAccount failure classes (AC-5-4, AC-5-5).
 *
 * Three rejection paths an MlDsaEthAccount must distinguish — structurally
 * identical to test/accounts/mldsa-failures.test.ts with three swaps
 * (fixture → mldsa-eth, account → MlDsaEthAccount, signer → ml-dsa-eth
 * direct imports per the Task 4 import-boundary note):
 *
 *   AC-5-4a: Crypto failure (wrong signer) → SIG_VALIDATION_FAILED (1n).
 *   AC-5-4b: Bit-flipped but structurally-parseable signature → 1n.
 *   AC-5-5:  Structurally-invalid signature (100 zero bytes) → reverts with
 *            SignatureMalformed() (try/catch in MlDsaEthAccount turns the
 *            ZKNOX_ethdilithium.verify revert into a typed custom error).
 *
 * Bit-flip locus (AC-5-4b): byte 5 sits inside the 32-byte cTilde region of
 * the 2420-byte ML-DSA-44 payload (DD-8 LOCKED byte layout, identical
 * between NIST and ETH variants). Flipping there mutates the Fiat-Shamir
 * challenge hash input without corrupting the z-polynomial (offset
 * 32..2335) or h-hint (offset 2336..2419), so the signature stays
 * parseable and the verifier takes the crypto-invalid branch. A flip
 * inside z could push a coefficient past the z-norm check, and a flip
 * inside h could trip the omegaVal ordering check in unpackH — both still
 * return false (soft fail) rather than reverting, but cTilde is the
 * canonical safe region (mirrors Story 3-2's byte-5-in-salt precedent and
 * Story 4-2 NIST MlDsaAccount test's identical locus).
 *
 * Malformed locus (AC-5-5): 100 zero bytes. Length mismatch (≠ 2420)
 * causes ZKNOX_ethdilithium.verify's `slice(signature, 32, 2304)` to
 * revert on OOB at BytesLib.slice's bounds check; MlDsaEthAccount's
 * try/catch translates that into SignatureMalformed(). A full-length
 * all-zeros blob would NOT work — it parses through slice, succeeds
 * unpackZ, and collapses into AC-5-4b via unpackH's soft fail.
 *
 * Walker disambiguation (AC-5-5): MlDsaAccount, FalconAccount, AND
 * MlDsaEthAccount all declare the same `SignatureMalformed()` custom
 * error (identical selector `0x2c3c2fe1` — keccak256("SignatureMalformed()")
 * truncated to 4 bytes). The HH3 EDR fallback path matches on a regex
 * over the chain-tail message, and that message could in principle
 * match any of the three contracts in a multi-contract test run. Bind
 * the match to `accountAddress.toLowerCase()` so the predicate is
 * account-scoped — mirrors mldsa-failures.test.ts:213 exactly.
 *
 * Assertion mechanics (per A-001): node-native `assert.equal` for
 * return-value checks and `assert.rejects(fn, predicate)` with a dual-
 * path viem walker for AC-5-5 (canonical
 * ContractFunctionRevertedError.data.errorName + HH3 EDR message-regex
 * fallback bound to the account address). No chai, no hardhat-chai-
 * matchers.
 *
 * Import boundary: same as Task 4 — signWithRnd is not needed here
 * (we use production signUserOp throughout, since crypto-invalid and
 * malformed assertions don't require KAT determinism). keygen +
 * signUserOp direct-imported from ../signers/ml-dsa-eth.js, sidestepping
 * the dispatcher extension in Task 6.
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import hre from "hardhat";
import {
  type Hex,
  bytesToHex,
  encodeFunctionData,
  hexToBytes,
  parseEther,
} from "viem";

import {
  deployDilithiumEthVerifier,
  registerPublicKey,
} from "../fixtures/mldsa-eth.js";
import type {
  PackedUserOperation,
  UnsignedUserOp,
} from "../signers/index.js";
import { keygen, signUserOp } from "../signers/ml-dsa-eth.js";
import { assertSignatureMalformedForAccount } from "../utils/signature-malformed-walker.js";

const SIG_VALIDATION_FAILED = 1n;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

async function setup() {
  // Single network connection — same invariant as Task 4 happy path.
  const connection = await hre.network.connect();
  const { viem } = connection;
  const publicClient = await viem.getPublicClient();
  const testClient = await viem.getTestClient();

  const entryPoint = await viem.deployContract("EntryPoint");
  const { dilithiumEthVerifier } = await deployDilithiumEthVerifier(viem);

  const alice = keygen();
  const pointerHex = await registerPublicKey(
    dilithiumEthVerifier,
    alice.publicKey,
  );

  const implementation = await viem.deployContract("MlDsaEthAccount", [
    entryPoint.address,
    dilithiumEthVerifier.address,
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
  const account = await viem.getContractAt("MlDsaEthAccount", proxy.address);

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
    dilithiumEthVerifier,
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

async function canonicalUserOpHash(
  entryPoint: Awaited<ReturnType<typeof setup>>["entryPoint"],
  packed: PackedUserOperation,
): Promise<Hex> {
  return (await entryPoint.read.getUserOpHash([packed])) as Hex;
}

async function simulateValidateUserOp(
  account: Awaited<ReturnType<typeof setup>>["account"],
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

describe("Story 5 Task 5 — MlDsaEthAccount failure classes", () => {
  it(
    "AC-5-4a: wrong signer returns SIG_VALIDATION_FAILED",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, chainId } = await setup();
      // Account is registered with Alice's pk in setup(). Bob is a
      // separate keygen — crypto.getRandomValues produces statistically
      // independent keypairs without any explicit seeding.
      const bob = keygen();

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
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
    "AC-5-4b: bit-flipped signature (cTilde region) returns SIG_VALIDATION_FAILED",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, alice, chainId } = await setup();

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
        alice.secretKey,
        userOp,
        entryPoint.address,
        chainId,
      );
      const userOpHash = await canonicalUserOpHash(entryPoint, signed);

      const sigBytes = hexToBytes(signed.signature);
      assert.equal(
        sigBytes.length,
        2420,
        "ML-DSA-44 signature must be 2420 bytes (cTilde 32 + z 2304 + h 84)",
      );

      // cTilde region is [0, 32). Flipping byte 5 mutates the
      // Fiat-Shamir challenge hash without touching the z-polynomial
      // (offset 32..2335) or h-hint (offset 2336..2419), so the
      // signature stays parseable and the verifier returns
      // SIG_VALIDATION_FAILED instead of reverting.
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
    "AC-5-5: malformed signature reverts with SignatureMalformed",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, alice, chainId } = await setup();

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
        alice.secretKey,
        userOp,
        entryPoint.address,
        chainId,
      );
      const userOpHash = await canonicalUserOpHash(entryPoint, signed);

      // 100 zero bytes — length mismatch (≠ 2420). ZKNOX_ethdilithium.verify's
      // slice(signature, 32, 2304) reverts on OOB at BytesLib's bounds
      // check; MlDsaEthAccount's try/catch translates that into the typed
      // SignatureMalformed() error. A full 2420-byte all-zeros blob would
      // collapse into AC-5-4b via unpackH soft fail — the length mismatch
      // is what guarantees the revert path.
      const malformed: PackedUserOperation = {
        ...signed,
        signature: bytesToHex(new Uint8Array(100)),
      };

      // Dual-path walker bound to `account.address.toLowerCase()` —
      // disambiguates against the other 3 contracts that declare the same
      // `SignatureMalformed()` custom error (identical 4-byte selector
      // `0x2c3c2fe1`). See `test/utils/signature-malformed-walker.ts`.
      await assert.rejects(
        () =>
          simulateValidateUserOp(
            account,
            entryPoint.address,
            malformed,
            userOpHash,
          ),
        assertSignatureMalformedForAccount(account.address),
      );
    },
  );
});
