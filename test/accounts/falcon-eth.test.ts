/**
 * Story 2-4 Task T4 — G6 happy path + AC-FLOW-1 end-to-end test.
 *
 * Two it blocks:
 *
 *   1. AC-3 (G6 happy path) — iterate N .rsp vectors, for each:
 *      register the raw public key via the fixture, deploy a fresh proxy,
 *      reconstruct the vector's deterministic randomness by seeding
 *      `rngAesCtrDrbg256(hexToBytes(v.drbgSeed))` and advancing past the
 *      48 B keygen draw (per docs/amendments.md §A-005 "DRBG derivation
 *      contract"; mirrors the Story 2-3 T4 G4 KAT test pattern), sign the
 *      userOp with `signWithKatBytes`, submit through EntryPoint's
 *      `validateUserOp` simulator, assert SIG_VALIDATION_SUCCESS (0n), then
 *      estimate the validateUserOp gas from an impersonated EntryPoint and
 *      assert it is under the HH3 EDR `tx_gas_limit_cap` of 2^24 =
 *      16_777_216n (AC-3 — NFR-5 verifyGas cap).
 *
 *   2. AC-FLOW-1 — 5 iterations of a full fresh-keypair end-to-end:
 *      `keygen()` from falcon-eth.ts (production surface, hedged 48 B
 *      CSPRNG innerSeed) → `registerPublicKey` (goes through
 *      `preparePublicKeyForDeployment` + `keccakXofFactory`) → fresh proxy
 *      → `signUserOp` (production path, hedged 88 B RNG via
 *      `globalThis.crypto.getRandomValues`) → `validateUserOp` simulate →
 *      assert success. Proves the production `signUserOp` path composes
 *      with the on-chain verifier end-to-end, not just the KAT signer.
 *
 * Vector count (AC-3) — N constant:
 * ----------------------------------
 * Smoke-first per the ml-dsa-eth Story 5 precedent + Story 2-4 T4 spec:
 * initial landing at N = 5 to validate the scaffolding end-to-end and
 * measure runtime; expand to 100 at Gate 5 if the full corpus fits inside
 * the budget (Falcon on-chain verify is slower than ml-dsa-eth's due to
 * larger calldata, so the timeout is bumped from 5min to 10min as a
 * safety margin). `AC_3_VECTOR_COUNT` remains a top-of-file constant for
 * easy future tuning.
 *
 * Failure-class tests (AC-4 wrong-key, AC-5 bit-flip, AC-6 malformed)
 * live in the sibling `falcon-eth-failures.test.ts` (Task 5).
 *
 * Import boundary (per Story 2-3 AC-7 Dev Notes §"test/accounts/** is NOT
 * in the AC-7 grep scope"; established by ml-dsa-eth precedent):
 *   - `signWithKatBytes` from `../signers/falcon-eth.kat-internal.js` is
 *     PERMITTED here (AC-7 enforcement is file-path-scoped to
 *     `test/signers/index.ts` + `test/bench/**` and does not cover
 *     `test/accounts/**`).
 *   - `keygen` + `signUserOp` imported DIRECTLY from
 *     `../signers/falcon-eth.js` rather than through the dispatcher in
 *     `../signers/index.js` — Task T6 extends that dispatcher's `Scheme`
 *     union to include `"falcon-eth"`, but this test file lands before
 *     T6 commits so we sidestep the ordering.
 *
 * Framework: node:test + node:assert/strict.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { rngAesCtrDrbg256 } from "@noble/ciphers/aes.js";
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
import { loadKatVectors } from "../fixtures/kat/index.js";
import { keygen, signUserOp } from "../signers/falcon-eth.js";
import {
  type BytesReader,
  signWithKatBytes,
} from "../signers/falcon-eth.kat-internal.js";
import type {
  PackedUserOperation,
  UnsignedUserOp,
} from "../signers/index.js";

const SIG_VALIDATION_SUCCESS = 0n;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

/**
 * HH3 EDR per-tx gas limit cap (2^24). AC-3 asserts
 * `verifyGas < 16_777_216n` — the tx's estimated gas for a single
 * `validateUserOp` call must stay under this cap (also serves NFR-5).
 */
const HH3_TX_GAS_LIMIT_CAP = 16_777_216n;

/**
 * Vector count for AC-3 iteration. Smoke-first (Story 2-4 T4 spec + ml-dsa-eth
 * Story 5 precedent): start at 5; tune at Gate 5 if the full 100 fits inside
 * the ≤10 min budget. One-line edit to expand.
 */
const AC_3_VECTOR_COUNT = 100;

const FLOW_1_ITERATIONS = 5;

async function deployStack() {
  // Single network connection for EntryPoint + verifier + account —
  // HH3's `network.connect()` hands out an isolated chain per call
  // (see test/fixtures/falcon-eth.ts for the full rationale on why the
  // verifier fixture accepts an existing `viem` instance).
  const connection = await hre.network.connect();
  const { viem } = connection;
  const publicClient = await viem.getPublicClient();
  const testClient = await viem.getTestClient();

  const entryPoint = await viem.deployContract("EntryPoint");
  const { falconEthVerifier } = await deployFalconEthVerifier(viem);

  const implementation = await viem.deployContract("FalconEthAccount", [
    entryPoint.address,
    falconEthVerifier.address,
  ]);

  await testClient.impersonateAccount({ address: entryPoint.address });
  await testClient.setBalance({
    address: entryPoint.address,
    value: parseEther("1"),
  });

  const chainId = BigInt(await publicClient.getChainId());

  return {
    viem,
    publicClient,
    entryPoint,
    falconEthVerifier,
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
  return stack.viem.getContractAt("FalconEthAccount", proxy.address);
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

describe("G6 — FalconEthAccount happy path (AC-3)", () => {
  const vectors = loadKatVectors("falcon-eth").slice(0, AC_3_VECTOR_COUNT);

  it(
    `${vectors.length} .rsp vectors → SIG_VALIDATION_SUCCESS via signWithKatBytes + EntryPoint.validateUserOp (verifyGas < 16_777_216n)`,
    { timeout: 10 * 60_000 },
    async () => {
      const stack = await deployStack();

      for (const v of vectors) {
        // 1. Register the raw KAT public key via the fixture → 20 B pointer.
        //    `registerPublicKey` threads through
        //    `preparePublicKeyForDeployment(rawPk, keccakXofFactory)` + the
        //    verifier's simulate+write `setKey` flow (see
        //    test/fixtures/falcon-eth.ts).
        const rawPk = hexToBytes(v.publicKey);
        const pointerHex = await registerPublicKey(
          stack.falconEthVerifier,
          rawPk,
        );
        const account = await deployProxy(stack, pointerHex);

        // 2. Build an unsigned userOp + compute its canonical EntryPoint hash.
        const unsigned = buildUnsignedUserOp(account.address);
        const userOpHash = await canonicalUserOpHash(stack.entryPoint, {
          ...unsigned,
          signature: "0x",
        });

        // 3. Reconstruct the vector's deterministic randomness — seed the
        //    AES-CTR-DRBG with `v.drbgSeed` and advance past the 48 B
        //    keygen draw before wiring the reader (per A-005 DRBG
        //    derivation contract; mirrors the Story 2-3 T4 G4 KAT pattern
        //    at test/signers/falcon-eth.sign.kat.test.ts:130-135). The
        //    remaining stream feeds noble's 40 B salt + 48 B FFSampler
        //    seed (88 B total budget).
        const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));
        drbg.randomBytes(48);
        const reader: BytesReader = {
          read: (n: number): Uint8Array => drbg.randomBytes(n),
        };

        // 4. Sign the userOpHash via the KAT surface. `signWithKatBytes`
        //    returns the on-chain-ready 1064 B `salt(40) || s2_compact(1024)`
        //    layout (ZKNOX-encoded internally — see
        //    test/signers/falcon-eth.kat-internal.ts:114-177); hex-encode
        //    for the signature field.
        const rawSig = signWithKatBytes(
          hexToBytes(v.secretKey),
          hexToBytes(userOpHash),
          reader,
        );
        const signatureHex = bytesToHex(rawSig);
        const signed: PackedUserOperation = {
          ...unsigned,
          signature: signatureHex,
        };

        // 5. Simulate validateUserOp from the impersonated EntryPoint.
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

        // 6. AC-3 / NFR-5 gas-cap: estimate the validateUserOp call's gas
        //    (from the impersonated EntryPoint — the production caller)
        //    and assert it stays under the HH3 EDR `tx_gas_limit_cap` of
        //    2^24 = 16_777_216. A verify that can't fit under this cap
        //    cannot be submitted as a tx in HH3's EDR at all, so this
        //    assertion is the binding integration constraint for the
        //    Falcon-ETH on-chain path.
        const estimatedGas = await stack.publicClient.estimateContractGas({
          abi: account.abi,
          address: account.address,
          functionName: "validateUserOp",
          args: [signed, userOpHash, 0n],
          account: stack.entryPoint.address,
        });
        assert.ok(
          estimatedGas < HH3_TX_GAS_LIMIT_CAP,
          `vec ${v.id}: verifyGas=${estimatedGas} >= ${HH3_TX_GAS_LIMIT_CAP} (HH3 tx cap)`,
        );
      }
    },
  );
});

describe("AC-FLOW-1 — fresh-keypair end-to-end (production signUserOp)", () => {
  it(
    `${FLOW_1_ITERATIONS} fresh keypairs × production signUserOp → SIG_VALIDATION_SUCCESS`,
    { timeout: 10 * 60_000 },
    async () => {
      const stack = await deployStack();

      for (let i = 0; i < FLOW_1_ITERATIONS; i++) {
        // 1. Production keygen — hedged 48 B innerSeed via
        //    globalThis.crypto.getRandomValues; forwards to noble's
        //    falcon512.keygen.
        const alice = keygen();

        // 2. Register the fresh public key via the fixture.
        const pointerHex = await registerPublicKey(
          stack.falconEthVerifier,
          alice.publicKey,
        );
        const account = await deployProxy(stack, pointerHex);

        // 3. Build + sign userOp via the production surface. signUserOp
        //    derives userOpHash internally and sources 88 B of hedged
        //    randomness per call — each iteration produces a different
        //    signature for the same underlying userOp (AC-2 hedging
        //    invariant, exercised end-to-end here).
        const unsigned = buildUnsignedUserOp(account.address);
        const signed = await signUserOp(
          alice.secretKey,
          unsigned,
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
