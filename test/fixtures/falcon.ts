/**
 * Falcon-512 verifier fixture
 *
 * Deploys a fresh `ZKNOX_falcon` instance per test setup (DD-9 LOCKED —
 * never shared across accounts). Provides a `registerPublicKey` helper that
 * encodes the raw 897-byte Falcon-512 NIST public key into the ABI-encoded
 * `uint256[]` the verifier's `_readPubKey` assembly path decodes, then
 * writes it via `setKey()` and returns the 20-byte SSTORE2 pointer suitable
 * for `FalconAccount.initialize`'s `_publicKey` argument (per A-003).
 *
 * Mirrors `test/fixtures/mldsa.ts`. See that file's header for rationale on
 * the two-step simulate+write capture and the cross-fixture network-sharing
 * constraint.
 *
 * Ref: ETHFALCON/src/ZKNOX_falcon.sol:36-39 (setKey writes via SSTORE2 and
 *      returns `abi.encodePacked(pointer)`).
 */

import hre from "hardhat";
import { hexToBytes, type Hex } from "viem";

import { encodePublicKeyForZKNOX } from "../signers/falcon-encoding.js";

type ViemConnection = Awaited<ReturnType<typeof hre.network.connect>>["viem"];

export async function deployFalconVerifier(viem: ViemConnection) {
  const falconVerifier = await viem.deployContract("ZKNOX_falcon");
  return { falconVerifier };
}

export async function registerPublicKey(
  falconVerifier: Awaited<ReturnType<typeof deployFalconVerifier>>["falconVerifier"],
  rawPublicKey: Uint8Array,
): Promise<Hex> {
  const encoded = encodePublicKeyForZKNOX(rawPublicKey);

  const { result: pointerHex } = await falconVerifier.simulate.setKey!([encoded]);

  await falconVerifier.write.setKey!([encoded]);

  if (hexToBytes(pointerHex as Hex).length !== 20) {
    throw new Error(
      `Expected 20-byte SSTORE2 pointer, got ${hexToBytes(pointerHex as Hex).length} bytes`,
    );
  }

  return pointerHex as Hex;
}
