/**
 * Per-scheme account deployers — Story 2-4 Task T6 (AC-9 / AC-A-2).
 *
 * Extracted verbatim from `test/bench/gas-benchmark.test.ts`'s inline
 * if-cascade (previously at lines 155-251) into a `Record<Scheme, Deployer>`
 * registry so that:
 *
 *   1. TypeScript's exhaustiveness check on `Record<Scheme, Deployer>` makes
 *      `tsc --noEmit` fail the moment a new `Scheme` union member is added
 *      without a corresponding registry entry (AC-9 compile-time guard).
 *   2. The runtime assertion
 *      `Object.keys(SCHEME_DEPLOYERS).length === SCHEMES.length` in the bench
 *      harness catches array vs union drift (defense-in-depth — covers the
 *      easy mistake of growing `Scheme` without growing `SCHEMES`).
 *   3. Adding a new scheme (e.g., Story 3-X / 4-X) is a mechanical one-entry
 *      edit to this registry + the dispatcher + the SCHEMES array — no bench
 *      harness surgery required.
 *
 * The `DeployContext` bundles the three state handles each deployer needs
 * (a shared viem connection, its public client, and the entrypoint address)
 * so the registry presents a uniform `(ctx) => Promise<DeployResult>` shape
 * regardless of per-scheme fixture differences.
 */

import type { Hex } from "viem";
import { encodeFunctionData } from "viem";

import hre from "hardhat";

import { deployFalconEthVerifier, registerPublicKey as registerFalconEthKey } from "../fixtures/falcon-eth.js";
import { deployFalconVerifier, registerPublicKey as registerFalconKey } from "../fixtures/falcon.js";
import { deployDilithiumEthVerifier, registerPublicKey as registerMldsaEthKey } from "../fixtures/mldsa-eth.js";
import { deployDilithiumVerifier, registerPublicKey as registerMldsaKey } from "../fixtures/mldsa.js";
import { keygen, type Keypair, type Scheme } from "./index.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

type ViemConnection = Awaited<ReturnType<typeof hre.network.connect>>["viem"];
type PublicClient = Awaited<ReturnType<ViemConnection["getPublicClient"]>>;

export type DeployContext = {
  viem: ViemConnection;
  publicClient: PublicClient;
  entryPointAddress: `0x${string}`;
};

export type DeployResult = {
  proxyAddress: `0x${string}`;
  alice: Keypair;
};

export type Deployer = (ctx: DeployContext) => Promise<DeployResult>;

/**
 * Per-scheme account deployer registry.
 *
 * `Record<Scheme, Deployer>` is exhaustive by TypeScript's type system — if
 * `Scheme` grows (e.g., `"dilithium-3"`) without a corresponding registry
 * entry, `tsc --noEmit` fails with a missing-key error. This is the AC-9
 * compile-time guard the story calls for. The runtime assertion in the bench
 * harness (`Object.keys(SCHEME_DEPLOYERS).length === SCHEMES.length`) covers
 * the separate SCHEMES-array-drift failure mode.
 */
export const SCHEME_DEPLOYERS: Record<Scheme, Deployer> = {
  ecdsa: async (ctx): Promise<DeployResult> => {
    const alice = keygen("ecdsa");
    const ownerAddress = `0x${Buffer.from(alice.publicKey).toString("hex")}` as `0x${string}`;
    const implementation = await ctx.viem.deployContract("EcdsaAccount", [
      ctx.entryPointAddress,
    ]);
    const initData = encodeFunctionData({
      abi: implementation.abi,
      functionName: "initialize",
      args: [ownerAddress],
    });
    const proxy = await ctx.viem.deployContract("ERC1967Proxy", [
      implementation.address,
      initData,
    ]);
    return { proxyAddress: proxy.address, alice };
  },

  falcon: async (ctx): Promise<DeployResult> => {
    const alice = keygen("falcon");
    const { falconVerifier } = await deployFalconVerifier(ctx.viem);
    const pointerHex: Hex = await registerFalconKey(
      falconVerifier,
      alice.publicKey,
      ctx.publicClient,
    );
    const implementation = await ctx.viem.deployContract("FalconAccount", [
      ctx.entryPointAddress,
      falconVerifier.address,
    ]);
    const initData = encodeFunctionData({
      abi: implementation.abi,
      functionName: "initialize",
      args: [ZERO_ADDRESS, pointerHex],
    });
    const proxy = await ctx.viem.deployContract("ERC1967Proxy", [
      implementation.address,
      initData,
    ]);
    return { proxyAddress: proxy.address, alice };
  },

  mldsa: async (ctx): Promise<DeployResult> => {
    const alice = keygen("mldsa");
    const { dilithiumVerifier } = await deployDilithiumVerifier(ctx.viem);
    const pointerHex: Hex = await registerMldsaKey(
      dilithiumVerifier,
      alice.publicKey,
    );
    const implementation = await ctx.viem.deployContract("MlDsaAccount", [
      ctx.entryPointAddress,
      dilithiumVerifier.address,
    ]);
    const initData = encodeFunctionData({
      abi: implementation.abi,
      functionName: "initialize",
      args: [ZERO_ADDRESS, pointerHex],
    });
    const proxy = await ctx.viem.deployContract("ERC1967Proxy", [
      implementation.address,
      initData,
    ]);
    return { proxyAddress: proxy.address, alice };
  },

  "mldsa-eth": async (ctx): Promise<DeployResult> => {
    const alice = keygen("mldsa-eth");
    const { dilithiumEthVerifier } = await deployDilithiumEthVerifier(ctx.viem);
    const pointerHex: Hex = await registerMldsaEthKey(
      dilithiumEthVerifier,
      alice.publicKey,
    );
    const implementation = await ctx.viem.deployContract("MlDsaEthAccount", [
      ctx.entryPointAddress,
      dilithiumEthVerifier.address,
    ]);
    const initData = encodeFunctionData({
      abi: implementation.abi,
      functionName: "initialize",
      args: [ZERO_ADDRESS, pointerHex],
    });
    const proxy = await ctx.viem.deployContract("ERC1967Proxy", [
      implementation.address,
      initData,
    ]);
    return { proxyAddress: proxy.address, alice };
  },

  "falcon-eth": async (ctx): Promise<DeployResult> => {
    const alice = keygen("falcon-eth");
    const { falconEthVerifier } = await deployFalconEthVerifier(ctx.viem);
    const pointerHex: Hex = await registerFalconEthKey(
      falconEthVerifier,
      alice.publicKey,
    );
    const implementation = await ctx.viem.deployContract("FalconEthAccount", [
      ctx.entryPointAddress,
      falconEthVerifier.address,
    ]);
    const initData = encodeFunctionData({
      abi: implementation.abi,
      functionName: "initialize",
      args: [ZERO_ADDRESS, pointerHex],
    });
    const proxy = await ctx.viem.deployContract("ERC1967Proxy", [
      implementation.address,
      initData,
    ]);
    return { proxyAddress: proxy.address, alice };
  },
};
