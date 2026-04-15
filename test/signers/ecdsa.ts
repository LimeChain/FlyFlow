/**
 * ECDSA (secp256k1) signer — baseline scheme.
 *
 * Implemented via viem (A-001 BINDING): `privateKeyToAccount(pk).signMessage`
 * with `{ message: { raw: hash } }` produces an EIP-191 prefixed signature,
 * which SimpleAccount's `toEthSignedMessageHash().recover()` accepts byte-for-byte.
 */

import { bytesToHex, hexToBytes, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import type { Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js";
import { computeUserOpHash } from "./userOpHash.js";

const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;

/**
 * Normalize an ECDSA signature to low-S form per EIP-2.
 *
 * Why: viem's signMessage produces ~50% high-S signatures, but
 * OpenZeppelin's ECDSA.recover (used by SimpleAccount) rejects high-S with
 * ECDSAInvalidSignature(). Without this, AC-1/AC-3 tests flake by coin flip.
 */
export function normalizeLowS(signature: Hex): Hex {
  const bytes = hexToBytes(signature);
  if (bytes.length !== 65) {
    throw new Error(`expected 65-byte signature, got ${bytes.length}`);
  }

  const s = BigInt(bytesToHex(bytes.slice(32, 64)));
  if (s <= SECP256K1_HALF_N) return signature;

  const flippedS = SECP256K1_N - s;
  const sBytes = hexToBytes(
    `0x${flippedS.toString(16).padStart(64, "0")}` as Hex,
  );

  const out = new Uint8Array(65);
  out.set(bytes.slice(0, 32), 0);
  out.set(sBytes, 32);
  const v = bytes[64]!;
  out[64] = v === 27 ? 28 : v === 28 ? 27 : v ^ 1;
  return bytesToHex(out);
}

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
    signature: normalizeLowS(signature),
  };
}
