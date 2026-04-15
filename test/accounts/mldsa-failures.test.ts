/**
 * Story 4-2 — MlDsaAccount failure classes.
 *
 * Three rejection paths an MlDsaAccount must distinguish:
 *   AC-1: Crypto failure (wrong signer) → SIG_VALIDATION_FAILED (1n).
 *   AC-2: Bit-flipped but structurally-parseable signature → 1n.
 *   AC-3: Structurally-invalid signature (100 zero bytes) → reverts with
 *         SignatureMalformed() (try/catch in MlDsaAccount turns the
 *         ZKNOX_dilithium.verify revert into a typed custom error).
 *
 * Bit-flip locus (AC-2): byte 5 sits inside the 32-byte cTilde region of the
 * 2420-byte ML-DSA-44 payload. Flipping there mutates the Fiat-Shamir
 * challenge hash input without corrupting the z-polynomial (offset 32..2335)
 * or h-hint (offset 2336..2419), so the signature remains parseable and the
 * verifier takes the crypto-invalid branch. A flip inside z could push a
 * coefficient past the z-norm check and a flip inside h could trip the
 * omegaVal ordering check in unpackH — both still return false (soft fail)
 * rather than reverting, but cTilde is the canonical safe region and mirrors
 * Story 3-2's byte-5-in-salt precedent.
 *
 * Malformed locus (AC-3): 100 zero bytes. Length mismatch (≠ 2420) causes
 * ZKNOX_dilithium.verify's `slice(signature, 32, 2304)` to revert on OOB at
 * BytesLib.slice's bounds check; MlDsaAccount's try/catch translates that
 * into SignatureMalformed(). A full-length all-zeros blob would NOT work —
 * it parses through slice, succeeds unpackZ, and collapses into AC-2 via
 * unpackH's soft fail.
 *
 * Assertion mechanics (per A-001): node-native `assert.equal` for return-value
 * checks and `assert.rejects(fn, predicate)` with a dual-path viem walker for
 * AC-3 (canonical ContractFunctionRevertedError.data.errorName + HH3 EDR
 * message-regex fallback bound to the account's origin address — necessary
 * because FalconAccount declares the same SignatureMalformed() selector).
 * No chai, no hardhat-chai-matchers.
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

import { deployDilithiumVerifier, registerPublicKey } from "../fixtures/mldsa.js";
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
  // Story 4-1 happy path (test/accounts/mldsa.test.ts:36-78).
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

describe("Story 4-2 — MlDsaAccount failure classes", () => {
  it(
    "AC-1: wrong signer returns SIG_VALIDATION_FAILED",
    { timeout: 120_000 },
    async () => {
      const { entryPoint, account, chainId } = await setup();
      // Account is registered with Alice's pk in setup(). Bob is a separate
      // keygen — noble uses crypto.getRandomValues so the two keypairs are
      // statistically independent without any explicit seeding.
      const bob = keygen("mldsa");

      const userOp = buildUnsignedUserOp(account.address);
      const signed = await signUserOp(
        "mldsa",
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
    "AC-2: bit-flipped signature (cTilde region) returns SIG_VALIDATION_FAILED",
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

      const sigBytes = hexToBytes(signed.signature);
      assert.equal(sigBytes.length, 2420, "ML-DSA-44 signature must be 2420 bytes");

      // cTilde region is [0, 32). Flipping byte 5 mutates the Fiat-Shamir
      // challenge hash without touching the z-polynomial (offset 32..2335)
      // or h-hint (offset 2336..2419), so the signature stays parseable and
      // the verifier returns SIG_VALIDATION_FAILED instead of reverting.
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
        "mldsa",
        alice.secretKey,
        userOp,
        entryPoint.address,
        chainId,
      );
      const userOpHash = await canonicalUserOpHash(entryPoint, signed);

      // 100 zero bytes — length mismatch (≠ 2420). ZKNOX_dilithium.verify's
      // slice(signature, 32, 2304) reverts on OOB; MlDsaAccount's try/catch
      // translates that into the typed SignatureMalformed() error. A full
      // 2420-byte all-zeros blob would collapse into AC-2 via unpackH soft
      // fail — the length mismatch is what guarantees the revert path.
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
          // Bind the match to the account-under-test's address so that the
          // co-defined `SignatureMalformed()` in FalconAccount (same selector,
          // different contract) can't spuriously satisfy this predicate.
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
