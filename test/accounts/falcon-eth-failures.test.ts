/**
 * Story 2-4 Task T5 — FalconEthAccount failure classes (AC-4, AC-5, AC-6).
 *
 * Three rejection paths a FalconEthAccount must distinguish — structurally
 * mirrors `test/accounts/mldsa-eth-failures.test.ts` with three swaps
 * (fixture → falcon-eth, account → FalconEthAccount, signer → falcon-eth
 * direct imports per the Task 4 import-boundary note):
 *
 *   AC-4:   Crypto failure (wrong signer) → SIG_VALIDATION_FAILED (1n). NO
 *           revert — the soft-fail branch of the `_VERIFY_SELECTOR` check.
 *   AC-5a:  Bit-flip at signature[5] (salt region, offset 5 < 40). Per AC-5
 *           "OR" semantics, either SIG_VALIDATION_FAILED (1n) OR a
 *           `SignatureMalformed()` revert is acceptable — EntryPoint does
 *           not accept either way. Falcon's salt is the 40 B prefix of the
 *           1064 B on-chain signature blob (`salt(40) || s2_compact(1024)`).
 *   AC-5b:  Bit-flip at signature[100] (s2 region, offset 100 ∈ [40, 1064)).
 *           Same "OR" semantics as AC-5a. Two sub-cases mandated by Story
 *           2-4 §AC-5 (falcon-eth has TWO bit-flip loci vs ml-dsa-eth's
 *           single cTilde locus — the distinction is called out in the
 *           story text).
 *   AC-6:   Structurally-invalid signature (100 zero bytes, length ≠ 1064)
 *           → reverts with `SignatureMalformed()`. FalconEthAccount's
 *           try/catch in `_validateSignature` translates the internal
 *           `ZKNOX_ethfalcon.verify` revert (BytesLib OOB on the s2
 *           slice) into the typed custom error.
 *
 * Bit-flip loci (AC-5):
 *   - Salt region is [0, 40). Flipping byte 5 mutates the salt used to
 *     derive the Fiat-Shamir challenge hash, so the verifier recomputes
 *     `hashToPoint(salt || msg)` → different point → `|s1 + s2*h|` fails
 *     the norm check → soft-fail (SIG_VALIDATION_FAILED). Parse path
 *     stays intact because salt is untouched by the ZKNOX signature-shape
 *     decoder.
 *   - s2 region is [40, 1064) — 1024 bytes of compactPoly-encoded s2. Byte
 *     100 sits inside s2's encoding. The decode path tolerates any
 *     bit-pattern (no OOB on a fixed-length slice), so we get the
 *     crypto-soft-fail branch. A hostile flip could in principle push a
 *     coefficient past a decoder bound — AC-5's "OR SignatureMalformed()"
 *     wording accommodates that possibility.
 *
 * Malformed locus (AC-6): 100 zero bytes. Length mismatch (100 ≠ 1064)
 * causes `ZKNOX_ethfalcon.verify` to revert on OOB at its internal s2
 * slice (`slice(signature, 40, 1024)` needs ≥1064 bytes); the account's
 * try/catch converts the revert into `SignatureMalformed()`. A full
 * 1064-byte all-zeros blob would parse through slice and collapse into
 * AC-5b's soft-fail via the norm check — length mismatch is what
 * guarantees the revert path.
 *
 * Walker disambiguation (AC-6): FOUR contracts (MlDsaAccount,
 * FalconAccount, MlDsaEthAccount, FalconEthAccount) all declare the
 * same `SignatureMalformed()` custom error (identical 4-byte selector
 * `0x2c3c2fe1` — `keccak256("SignatureMalformed()")` truncated). The
 * dual-path walker binds to `account.address.toLowerCase()` so the
 * predicate is account-scoped even when multiple accounts coexist in a
 * test run. The walker implementation lives in
 * `test/utils/signature-malformed-walker.ts` — shared with
 * `mldsa-eth-failures.test.ts` (extracted at T5 time per
 * `.claude/rules/retrospect/typescript.md` §"[2026-04-20] Duplicated
 * test-file code" — two copies was the extraction trigger, before silent
 * drift could invalidate the account-bind invariant).
 *
 * Assertion mechanics (per A-001): node-native `assert.equal` for
 * return-value checks and `assert.rejects(fn, predicate)` with the
 * shared dual-path viem walker for AC-6. No chai, no
 * hardhat-chai-matchers.
 *
 * Import boundary: same as Task 4 — `keygen` + `signUserOp` direct-imported
 * from `../signers/falcon-eth.js`, sidestepping the dispatcher extension
 * in Task 6. `signWithKatBytes` NOT imported here — the failure-class
 * tests use the production signer throughout (crypto-invalid and
 * malformed assertions don't require KAT determinism), matching the
 * ml-dsa-eth-failures precedent.
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
  deployFalconEthVerifier,
  registerPublicKey,
} from "../fixtures/falcon-eth.js";
import { keygen, signUserOp } from "../signers/falcon-eth.js";
import type {
  PackedUserOperation,
  UnsignedUserOp,
} from "../signers/index.js";
import { assertSignatureMalformedForAccount } from "../utils/signature-malformed-walker.js";

const SIG_VALIDATION_FAILED = 1n;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

/**
 * Falcon-ETH on-chain signature layout — 1064 bytes:
 *   - `salt`          : offset [0, 40)
 *   - `s2_compact`    : offset [40, 1064) — 1024 bytes, 512 × 16-bit coeffs
 * See `test/signers/falcon-eth.kat-internal.ts` + ZKNOX wire format.
 */
const FALCON_ETH_SIGNATURE_LENGTH = 1064;

async function setup() {
  // Single network connection — same invariant as Task 4 happy path.
  const connection = await hre.network.connect();
  const { viem } = connection;
  const publicClient = await viem.getPublicClient();
  const testClient = await viem.getTestClient();

  const entryPoint = await viem.deployContract("EntryPoint");
  const { falconEthVerifier } = await deployFalconEthVerifier(viem);

  const alice = keygen();
  const pointerHex = await registerPublicKey(
    falconEthVerifier,
    alice.publicKey,
  );

  const implementation = await viem.deployContract("FalconEthAccount", [
    entryPoint.address,
    falconEthVerifier.address,
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
  const account = await viem.getContractAt("FalconEthAccount", proxy.address);

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
    falconEthVerifier,
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

/**
 * Shared helper for AC-5 sub-cases — sign a valid userOp, flip one byte
 * at `offset`, return `{corrupted, userOpHash}`. Offset bounds are
 * asserted against the Falcon-ETH 1064-byte signature layout.
 */
async function signAndFlipByte(
  stack: Awaited<ReturnType<typeof setup>>,
  offset: number,
): Promise<{ corrupted: PackedUserOperation; userOpHash: Hex }> {
  const { entryPoint, account, alice, chainId } = stack;
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
    FALCON_ETH_SIGNATURE_LENGTH,
    `Falcon-ETH signature must be ${FALCON_ETH_SIGNATURE_LENGTH} bytes (salt 40 + s2_compact 1024)`,
  );
  assert.ok(
    offset >= 0 && offset < sigBytes.length,
    `bit-flip offset ${offset} outside signature length ${sigBytes.length}`,
  );

  sigBytes[offset] ^= 0x01;
  const corrupted: PackedUserOperation = {
    ...signed,
    signature: bytesToHex(sigBytes),
  };
  return { corrupted, userOpHash };
}

describe("Story 2-4 Task T5 — FalconEthAccount failure classes", () => {
  it(
    "AC-4: wrong signer returns SIG_VALIDATION_FAILED",
    { timeout: 120_000 },
    async () => {
      const stack = await setup();
      const { entryPoint, account, chainId } = stack;
      // Account is registered with Alice's pk in setup(). Bob is a
      // separate keygen — `globalThis.crypto.getRandomValues` seeds an
      // independent 48 B innerSeed per call, so the two keypairs are
      // statistically independent.
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
    "AC-5a: bit-flip at signature[5] (salt region, offset < 40) rejects (soft-fail OR SignatureMalformed)",
    { timeout: 120_000 },
    async () => {
      const stack = await setup();
      // Salt is [0, 40) — byte 5 sits inside. Flipping it changes the
      // salt fed into `hashToPoint(salt || msg)`, so the verifier
      // recomputes a different challenge point and the `|s1 + s2*h|`
      // norm check fails → SIG_VALIDATION_FAILED. Per AC-5's "OR"
      // wording, a revert with `SignatureMalformed()` is also acceptable
      // if an EDR path surfaces the corruption that way.
      const { corrupted, userOpHash } = await signAndFlipByte(stack, 5);

      // Try the happy path first; catch the revert path as equivalent.
      try {
        const validationData = await simulateValidateUserOp(
          stack.account,
          stack.entryPoint.address,
          corrupted,
          userOpHash,
        );
        assert.equal(
          validationData,
          SIG_VALIDATION_FAILED,
          `salt bit-flip: expected SIG_VALIDATION_FAILED (1) or SignatureMalformed revert, got ${validationData}`,
        );
      } catch (err) {
        // AC-5 "OR" — revert path accepted; must still be
        // `SignatureMalformed()` bound to this account to avoid
        // masking a wrong-path EDR surface.
        assert.ok(
          assertSignatureMalformedForAccount(stack.account.address)(err),
          `salt bit-flip rejected via revert, but not SignatureMalformed() bound to account: ${(err as Error).message}`,
        );
      }
    },
  );

  it(
    "AC-5b: bit-flip at signature[100] (s2 region, offset ∈ [40, 1064)) rejects (soft-fail OR SignatureMalformed)",
    { timeout: 120_000 },
    async () => {
      const stack = await setup();
      // s2_compact is [40, 1064) — byte 100 sits 60 bytes into s2's
      // 1024-byte compactPoly encoding. Flipping it perturbs one (or two,
      // depending on bit alignment) 16-bit s2 coefficient(s); the norm
      // check fails → SIG_VALIDATION_FAILED. AC-5's "OR" wording accepts
      // a `SignatureMalformed()` revert if the perturbation pushes a
      // coefficient past a decoder bound.
      const { corrupted, userOpHash } = await signAndFlipByte(stack, 100);

      try {
        const validationData = await simulateValidateUserOp(
          stack.account,
          stack.entryPoint.address,
          corrupted,
          userOpHash,
        );
        assert.equal(
          validationData,
          SIG_VALIDATION_FAILED,
          `s2 bit-flip: expected SIG_VALIDATION_FAILED (1) or SignatureMalformed revert, got ${validationData}`,
        );
      } catch (err) {
        assert.ok(
          assertSignatureMalformedForAccount(stack.account.address)(err),
          `s2 bit-flip rejected via revert, but not SignatureMalformed() bound to account: ${(err as Error).message}`,
        );
      }
    },
  );

  it(
    "AC-6: malformed (100 zero bytes) signature reverts with SignatureMalformed",
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

      // 100 zero bytes — length mismatch (≠ 1064). ZKNOX_ethfalcon.verify
      // reverts on OOB inside its s2 slice extraction; FalconEthAccount's
      // try/catch translates that into the typed `SignatureMalformed()`
      // custom error. A full 1064-byte all-zeros blob would parse
      // through slice and collapse into AC-5b's soft-fail via the norm
      // check — length mismatch is what guarantees the revert path.
      const malformed: PackedUserOperation = {
        ...signed,
        signature: bytesToHex(new Uint8Array(100)),
      };

      // Dual-path walker bound to `account.address.toLowerCase()` —
      // disambiguates against the other 3 contracts that declare the
      // same `SignatureMalformed()` custom error (identical 4-byte
      // selector `0x2c3c2fe1`). See
      // `test/utils/signature-malformed-walker.ts`.
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
