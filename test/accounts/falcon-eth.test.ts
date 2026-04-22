/**
 * Falcon-ETH G6 happy path + AC-FLOW-1 end-to-end test.
 *
 * Two it blocks:
 *
 *   1. G6 happy path — iterate N .rsp vectors. For each:
 *      register the raw public key via the fixture, deploy a fresh proxy,
 *      reconstruct the vector's deterministic randomness by seeding
 *      `rngAesCtrDrbg256(hexToBytes(v.drbgSeed))` and advancing past the
 *      48 B keygen draw (mirrors the G4 KAT pattern at
 *      `test/signers/falcon-eth.sign.kat.test.ts`), sign the userOpHash
 *      inline via `falcon512paddedEth.sign` + `encodeFalconSignature`
 *      (both from the fork at `@noble/post-quantum/{falcon,utils-eth}.js`),
 *      submit through EntryPoint's `validateUserOp` simulator, assert
 *      SIG_VALIDATION_SUCCESS (0n), then estimate the validateUserOp gas
 *      from an impersonated EntryPoint and assert it is under the HH3 EDR
 *      `tx_gas_limit_cap` of 2^24 = 16_777_216n (NFR-5 verifyGas cap).
 *
 *   2. AC-FLOW-1 — 5 iterations of a full fresh-keypair end-to-end:
 *      `keygen()` from falcon-eth.ts (production surface, hedged 48 B
 *      CSPRNG innerSeed) → `registerPublicKey` (routes through
 *      `preparePublicKeyForDeployment` + `keccakXofFactory`) → fresh proxy
 *      → `signUserOp` (production path, hedged per-call randomness via
 *      `globalThis.crypto.getRandomValues`) → `validateUserOp` simulate →
 *      assert success. Proves the production `signUserOp` path composes
 *      with the on-chain verifier end-to-end.
 *
 * Vector count: 100 .rsp vectors per KAT corpus; timeout 10 min.
 *
 * Failure-class tests (wrong-key, bit-flip, malformed) live in the sibling
 * `falcon-eth-failures.test.ts`.
 *
 * Post-fork-extraction: the KAT signing path no longer uses a repo-side
 * `signWithKatBytes` wrapper — the test inlines
 * `encodeFalconSignature(falcon512paddedEth.sign(msg, sk, { random }))`
 * directly (both symbols live in the fork). Production `keygen` +
 * `signUserOp` remain imported from `../signers/falcon-eth.js` (repo
 * thin shim retained for ERC-4337 glue).
 *
 * Framework: node:test + node:assert/strict.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { rngAesCtrDrbg256 } from "@noble/ciphers/aes.js";
import { falcon512paddedEth } from "@noble/post-quantum/falcon.js";
import { encodeFalconSignature } from "@noble/post-quantum/utils-eth.js";
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
import type {
  PackedUserOperation,
  UnsignedUserOp,
} from "../signers/index.js";

// Noble's `Falcon` type alias declares `sign` via the generic `Signer` shape
// (`SigOpts` — no `random`). At runtime, `genFalcon` wires the
// Falcon-specific `FalconSigOpts` which accepts a `random` callback. The
// local cast names the wider contract without reaching into fork internals.
const signWithRandom = falcon512paddedEth.sign as (
  msg: Uint8Array,
  secretKey: Uint8Array,
  opts: { random: (n?: number) => Uint8Array },
) => Uint8Array;

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

describe("G6 — FalconEthAccount happy path", () => {
  const vectors = loadKatVectors("falcon-eth").slice(0, AC_3_VECTOR_COUNT);

  it(
    `${vectors.length} .rsp vectors → SIG_VALIDATION_SUCCESS via falcon512paddedEth.sign + EntryPoint.validateUserOp (verifyGas < 16_777_216n)`,
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
        //    keygen draw. The remaining stream feeds noble's 40 B salt +
        //    48 B FFSampler seed (88 B total).
        const drbg = rngAesCtrDrbg256(hexToBytes(v.drbgSeed));
        drbg.randomBytes(48);

        // 4. Sign the userOpHash via the fork surface:
        //    falcon512paddedEth.sign + encodeFalconSignature. The encoder
        //    returns the on-chain-ready 1064 B `salt(40) || s2_compact(1024)`
        //    layout; hex-encode for the signature field.
        const nobleSig = signWithRandom(
          hexToBytes(userOpHash),
          hexToBytes(v.secretKey),
          { random: (n?: number): Uint8Array => drbg.randomBytes(n ?? 0) },
        );
        const rawSig = encodeFalconSignature(nobleSig);
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

        // 6. NFR-5 gas-cap: estimate the validateUserOp call's gas
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
