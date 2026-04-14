/**
 * ECDSA (secp256k1) signer — baseline scheme.
 *
 * Implemented via viem (A-001 BINDING): `privateKeyToAccount(pk).signMessage`
 * with `{ message: { raw: hash } }` produces an EIP-191 prefixed signature,
 * which SimpleAccount's `toEthSignedMessageHash().recover()` accepts byte-for-byte.
 */

import { bytesToHex, hexToBytes } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import type { Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js";
import { computeUserOpHash } from "./userOpHash.js";

/**
 * Generate a fresh secp256k1 keypair.
 *
 * `publicKey` is the 20-byte Ethereum address (NOT the 64-byte uncompressed
 * secp256k1 public key) — this matches SimpleAccount's `recover-to-owner`
 * model per DD-2. Consumers comparing against an on-chain `owner` field
 * should compare 20-byte address bytes directly.
 */
export function keygen(): Keypair {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);

  return {
    publicKey: hexToBytes(account.address),
    secretKey: hexToBytes(privateKey),
  };
}

export async function signUserOp(
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);

  const account = privateKeyToAccount(bytesToHex(secretKey));
  const signature = await account.signMessage({
    message: { raw: userOpHash },
  });

  return {
    ...userOp,
    signature,
  };
}
