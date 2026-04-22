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

import { encodeFalconPublicKey } from "@noble/post-quantum/utils-eth.js";
import hre from "hardhat";
import { bytesToHex, hexToBytes, type Hex, type PublicClient } from "viem";

type ViemConnection = Awaited<ReturnType<typeof hre.network.connect>>["viem"];

export async function deployFalconVerifier(viem: ViemConnection) {
  const falconVerifier = await viem.deployContract("ZKNOX_falcon");
  return { falconVerifier };
}

export async function registerPublicKey(
  falconVerifier: Awaited<ReturnType<typeof deployFalconVerifier>>["falconVerifier"],
  rawPublicKey: Uint8Array,
  publicClient: PublicClient,
): Promise<Hex> {
  const encoded = bytesToHex(encodeFalconPublicKey(rawPublicKey));

  const { result: pointerHex } = await falconVerifier.simulate.setKey!([encoded]);

  await falconVerifier.write.setKey!([encoded]);

  if (hexToBytes(pointerHex as Hex).length !== 20) {
    throw new Error(
      `Expected 20-byte SSTORE2 pointer, got ${hexToBytes(pointerHex as Hex).length} bytes`,
    );
  }

  // simulate.setKey predicts the SSTORE2 deploy address from the verifier's
  // current nonce; write.setKey then performs the real deploy. On Hardhat
  // these match because eth_call doesn't bump the nonce. Verify the predicted
  // pointer actually has bytecode now — fail loudly rather than silently
  // initializing an account against an empty pointer if the addresses ever drift.
  const code = await publicClient.getBytecode({ address: pointerHex as Hex });
  if (!code || code === "0x") {
    throw new Error(
      `SSTORE2 pointer ${pointerHex} has no deployed bytecode — simulate/write address drift`,
    );
  }

  return pointerHex as Hex;
}
