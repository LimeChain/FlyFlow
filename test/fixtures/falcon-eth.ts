/**
 * Falcon-ETH verifier fixture
 *
 * Deploys a fresh `ZKNOX_ethfalcon` instance per test setup (DD-9
 * LOCKED — never shared across accounts). Provides a `registerPublicKey`
 * helper that reshapes the raw 897-byte Falcon-512 NIST public key into
 * the `uint256[]` ABI payload the verifier's `setKey` decodes, writes it
 * via `setKey()`, and returns the 20-byte SSTORE2 pointer suitable for
 * `FalconEthAccount.initialize`'s `_publicKeyPointer` argument
 * (per A-006).
 *
 * Byte divergence from `test/fixtures/falcon.ts` (the NIST helper):
 * Falcon-ETH swaps NIST Falcon's SHAKE-256-based HashToPoint for a
 * Keccak-256-based variant (per A-006's fork-injection mechanism). The
 * XOF primitive swap is HashToPoint-specific — Falcon's hash-to-point is
 * NOT a Keccak-PRG construction in the ML-DSA sense; only the message
 * digest primitive changes. `preparePublicKeyForDeployment` is called
 * with a single `keccakXofFactory` (NOT a two-factory pair like
 * ml-dsa-eth): Falcon-ETH's public-key transform is deterministic over
 * the raw bytes, so the factory argument is retained for NFR-11
 * cross-scheme symmetry only. The deployed contract is `ZKNOX_ethfalcon`
 * (wrapper at `contracts/imports/FalconRef.sol:29`), NOT
 * `ZKNOX_falcon`. Signatures produced against this verifier's keys are
 * NOT interchangeable with NIST-variant signatures.
 *
 * Two-step capture (simulate then write): viem's `write.*` returns the tx
 * hash, not the Solidity return value. To capture the pointer bytes we
 * `simulate.setKey` first (returns `result.result`), then `write.setKey`
 * to actually persist on-chain. Pattern mirrored verbatim from
 * `test/fixtures/mldsa-eth.ts`.
 *
 * Cross-fixture network sharing: HH3's `hre.network.connect()` returns an
 * isolated EdrProvider per call. Deploying the verifier on a separate
 * connection from the account would point
 * `FalconEthAccount.falconEthVerifier` at an empty address on the
 * account's chain — staticcall returns no data and the bytes4 decode
 * reverts (caught as `SignatureMalformed`). Callers that compose multiple
 * fixtures must pass an existing `viem` instance so all contracts land
 * on the same chain.
 *
 * Ref: ETHFALCON/src/ZKNOX_ethfalcon.sol (setKey returns
 *      abi.encodePacked(pointer)).
 */

import hre from "hardhat";
import { type Hex, hexToBytes } from "viem";

import { preparePublicKeyForDeployment } from "../signers/falcon-eth.core.js";
import { keccakXofFactory } from "../signers/mldsa-encoding.js";

type ViemConnection = Awaited<ReturnType<typeof hre.network.connect>>["viem"];

export async function deployFalconEthVerifier(viem?: ViemConnection) {
  const v: ViemConnection = viem ?? (await hre.network.connect()).viem;

  const publicClient = await v.getPublicClient();
  const walletClients = await v.getWalletClients();
  const falconEthVerifier = await v.deployContract("ZKNOX_ethfalcon");

  return { falconEthVerifier, publicClient, walletClients };
}

export async function registerPublicKey(
  falconEthVerifier: Awaited<
    ReturnType<typeof deployFalconEthVerifier>
  >["falconEthVerifier"],
  rawPublicKey: Uint8Array,
): Promise<Hex> {
  // ETH path (A-006): single-factory signature — `keccakXofFactory` is
  // accepted for NFR-11 cross-scheme symmetry but not consumed internally
  // by falcon-eth's deterministic NTT transform. Distinct from ml-dsa-eth's
  // two-factory binding.
  const encoded = preparePublicKeyForDeployment(
    rawPublicKey,
    keccakXofFactory,
  );

  // Use the contract's bound simulate/write so the calls hit the same
  // network the verifier was deployed on. Fixtures open their own
  // `hre.network.connect()`, so a publicClient from a different fixture
  // (e.g. the EntryPoint fixture) targets a different chain — calling
  // setKey there hits an unrelated contract at the same address.
  const { result: pointerHex } =
    await falconEthVerifier.simulate.setKey!([encoded]);

  // viem's typed contract narrows write methods as possibly undefined;
  // the method exists at runtime — same pattern as test/fixtures/mldsa-eth.ts
  // and test/accounts/ecdsa.test.ts.
  await falconEthVerifier.write.setKey!([encoded]);

  if (hexToBytes(pointerHex as Hex).length !== 20) {
    throw new Error(
      `Expected 20-byte SSTORE2 pointer, got ${hexToBytes(pointerHex as Hex).length} bytes`,
    );
  }

  return pointerHex as Hex;
}
