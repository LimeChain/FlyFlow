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
 * `simulateContract` first (returns `result.result`), then `write` to
 * actually persist on-chain — same pattern Story 3-1 documents for Falcon.
 *
 * Ref: ETHDILITHIUM/src/ZKNOX_dilithium.sol:23 (setKey returns abi.encodePacked(pointer))
 */

import hre from "hardhat";
import { hexToBytes, type Hex } from "viem";

import { preparePublicKeyForDeployment } from "../signers/mldsa-encoding.js";

export async function deployDilithiumVerifier() {
  const connection = await hre.network.connect();
  const { viem } = connection;

  const publicClient = await viem.getPublicClient();
  const walletClients = await viem.getWalletClients();
  const dilithiumVerifier = await viem.deployContract("ZKNOX_dilithium");

  return { dilithiumVerifier, publicClient, walletClients };
}

export async function registerPublicKey(
  dilithiumVerifier: Awaited<ReturnType<typeof deployDilithiumVerifier>>["dilithiumVerifier"],
  publicClient: Awaited<ReturnType<typeof deployDilithiumVerifier>>["publicClient"],
  rawPublicKey: Uint8Array,
): Promise<Hex> {
  const encoded = preparePublicKeyForDeployment(rawPublicKey);

  const { result: pointerHex } = await publicClient.simulateContract({
    address: dilithiumVerifier.address,
    abi: dilithiumVerifier.abi,
    functionName: "setKey",
    args: [encoded],
  });

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
