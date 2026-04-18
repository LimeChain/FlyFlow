/**
 * ML-DSA verifier fixture
 *
 * Deploys a fresh `ZKNOX_dilithium` instance per test setup (DD-9 LOCKED —
 * never shared across accounts). Provides a `registerPublicKey` helper that
 * encodes the raw 1,312-byte ML-DSA-44 NIST public key into the
 * `(aHatEncoded, tr, t1Encoded)` ABI tuple the verifier's `_readPubKey`
 * decodes, then writes it via `setKey()` and returns the 20-byte SSTORE2
 * pointer suitable for `MlDsaAccount.initialize`'s `_publicKey` argument
 * (per A-003).
 *
 * Two-step capture (simulate then write): viem's `write.*` returns the tx
 * hash, not the Solidity return value. To capture the pointer bytes we
 * `simulate.setKey` first (returns `result.result`), then `write.setKey`
 * to actually persist on-chain.
 *
 * Cross-fixture network sharing: HH3's `hre.network.connect()` returns an
 * isolated EdrProvider per call. Deploying the verifier on a separate
 * connection from the account would point `MlDsaAccount.dilithiumVerifier`
 * at an empty address on the account's chain — staticcall returns no data
 * and the bytes4 decode reverts (caught as `SignatureMalformed`). Callers
 * that compose multiple fixtures must pass an existing `viem` instance so
 * all contracts land on the same chain.
 *
 * Ref: ETHDILITHIUM/src/ZKNOX_dilithium.sol:23 (setKey returns abi.encodePacked(pointer))
 */

import hre from "hardhat";
import { hexToBytes, type Hex } from "viem";

import {
  preparePublicKeyForDeployment,
  shake128XofFactory,
  shake256XofFactory,
} from "../signers/mldsa-encoding.js";

type ViemConnection = Awaited<ReturnType<typeof hre.network.connect>>["viem"];

export async function deployDilithiumVerifier(viem?: ViemConnection) {
  const v: ViemConnection = viem ?? (await hre.network.connect()).viem;

  const publicClient = await v.getPublicClient();
  const walletClients = await v.getWalletClients();
  const dilithiumVerifier = await v.deployContract("ZKNOX_dilithium");

  return { dilithiumVerifier, publicClient, walletClients };
}

export async function registerPublicKey(
  dilithiumVerifier: Awaited<ReturnType<typeof deployDilithiumVerifier>>["dilithiumVerifier"],
  rawPublicKey: Uint8Array,
): Promise<Hex> {
  // NIST path (A-002): xofFactory = _xof = SHAKE-256 (H/tr);
  //                     xofFactory2 = _xof2 = SHAKE-128 (ExpandA).
  const encoded = preparePublicKeyForDeployment(
    rawPublicKey,
    shake256XofFactory,
    shake128XofFactory,
  );

  // Use the contract's bound simulate/write so the calls hit the same
  // network the verifier was deployed on. Fixtures open their own
  // `hre.network.connect()`, so a publicClient from a different fixture
  // (e.g. the EntryPoint fixture) targets a different chain — calling
  // setKey there hits an unrelated contract at the same address.
  const { result: pointerHex } = await dilithiumVerifier.simulate.setKey!([encoded]);

  // viem's typed contract narrows write methods as possibly undefined; the
  // method exists at runtime — same pattern as test/accounts/ecdsa.test.ts.
  await dilithiumVerifier.write.setKey!([encoded]);

  if (hexToBytes(pointerHex as Hex).length !== 20) {
    throw new Error(
      `Expected 20-byte SSTORE2 pointer, got ${hexToBytes(pointerHex as Hex).length} bytes`,
    );
  }

  return pointerHex as Hex;
}
