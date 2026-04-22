/**
 * ML-DSA-ETH verifier fixture
 *
 * Deploys a fresh `ZKNOX_ethdilithium` instance per test setup (DD-9
 * LOCKED — never shared across accounts). Provides a `registerPublicKey`
 * helper that reshapes the raw 1,312-byte ML-DSA-44 NIST public key into
 * the `(aHatEncoded, tr, t1Encoded)` ABI tuple the verifier's
 * `_readPubKey` decodes, writes it via `setKey()`, and returns the
 * 20-byte SSTORE2 pointer suitable for
 * `MlDsaEthAccount.initialize`'s `_publicKeyPointer` argument
 * (per A-006).
 *
 * Byte divergence from `test/fixtures/mldsa.ts` (the NIST helper):
 * `preparePublicKeyForDeployment` is called with `(keccakXofFactory,
 * keccakXofFactory)` on the ETH path per A-002's two-factory API + DD-1's
 * single-factory collapse — NOT `(shake256XofFactory, shake128XofFactory)`.
 * The deployed contract is `ZKNOX_ethdilithium` (wrapper at
 * `contracts/imports/DilithiumRef.sol:37`), NOT `ZKNOX_dilithium`. Keys
 * produced by this fixture are NOT interchangeable with NIST-variant
 * keys: identical ζ seeds produce different keypairs under Keccak-PRG vs
 * SHAKE.
 *
 * Two-step capture (simulate then write): viem's `write.*` returns the tx
 * hash, not the Solidity return value. To capture the pointer bytes we
 * `simulate.setKey` first (returns `result.result`), then `write.setKey`
 * to actually persist on-chain. Pattern mirrored verbatim from
 * `test/fixtures/mldsa.ts`.
 *
 * Cross-fixture network sharing: HH3's `hre.network.connect()` returns an
 * isolated EdrProvider per call. Deploying the verifier on a separate
 * connection from the account would point
 * `MlDsaEthAccount.dilithiumEthVerifier` at an empty address on the
 * account's chain — staticcall returns no data and the bytes4 decode
 * reverts (caught as `SignatureMalformed`). Callers that compose multiple
 * fixtures must pass an existing `viem` instance so all contracts land
 * on the same chain.
 *
 * Ref: ETHDILITHIUM/src/ZKNOX_ethdilithium.sol:29 (setKey returns
 *      abi.encodePacked(pointer)).
 */

import {
  encodeMlDsaPublicKey,
  keccakXofFactory,
} from "@noble/post-quantum/utils-eth.js";
import hre from "hardhat";
import { bytesToHex, type Hex, hexToBytes } from "viem";

type ViemConnection = Awaited<ReturnType<typeof hre.network.connect>>["viem"];

export async function deployDilithiumEthVerifier(viem?: ViemConnection) {
  const v: ViemConnection = viem ?? (await hre.network.connect()).viem;

  const publicClient = await v.getPublicClient();
  const walletClients = await v.getWalletClients();
  const dilithiumEthVerifier = await v.deployContract("ZKNOX_ethdilithium");

  return { dilithiumEthVerifier, publicClient, walletClients };
}

export async function registerPublicKey(
  dilithiumEthVerifier: Awaited<
    ReturnType<typeof deployDilithiumEthVerifier>
  >["dilithiumEthVerifier"],
  rawPublicKey: Uint8Array,
): Promise<Hex> {
  // ETH path (DD-1 LOCKED + A-002): xofFactory = xofFactory2 =
  // keccakXofFactory — same factory twice, replacing the NIST
  // `(shake256, shake128)` pair. Fork's `encodeMlDsaPublicKey` returns
  // `Uint8Array`; wrap with `bytesToHex` at the viem boundary.
  const encoded = bytesToHex(
    encodeMlDsaPublicKey(rawPublicKey, keccakXofFactory, keccakXofFactory),
  );

  // Use the contract's bound simulate/write so the calls hit the same
  // network the verifier was deployed on. Fixtures open their own
  // `hre.network.connect()`, so a publicClient from a different fixture
  // (e.g. the EntryPoint fixture) targets a different chain — calling
  // setKey there hits an unrelated contract at the same address.
  const { result: pointerHex } =
    await dilithiumEthVerifier.simulate.setKey!([encoded]);

  // viem's typed contract narrows write methods as possibly undefined;
  // the method exists at runtime — same pattern as test/fixtures/mldsa.ts
  // and test/accounts/ecdsa.test.ts.
  await dilithiumEthVerifier.write.setKey!([encoded]);

  if (hexToBytes(pointerHex as Hex).length !== 20) {
    throw new Error(
      `Expected 20-byte SSTORE2 pointer, got ${hexToBytes(pointerHex as Hex).length} bytes`,
    );
  }

  return pointerHex as Hex;
}
