/**
 * ECDSA (secp256k1) signer — baseline scheme.
 *
 * Implemented via viem (A-001 BINDING): `privateKeyToAccount(pk).signMessage`
 * with `{ message: { raw: hash } }` produces an EIP-191 prefixed signature,
 * which SimpleAccount's `toEthSignedMessageHash().recover()` accepts byte-for-byte.
 */

import {
  bytesToHex,
  encodeAbiParameters,
  hexToBytes,
  keccak256,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import type { Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js";

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

/**
 * Compute the ERC-4337 v0.7 userOpHash over a PackedUserOperation and sign
 * it with EIP-191 prefixing.
 *
 * See EIP-4337 v0.7: userOpHash = keccak256(abi.encode(
 *   keccak256(abi.encode(packed fields...)),
 *   entryPointAddress,
 *   chainId,
 * ))
 */
export async function signUserOp(
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  const inner = keccak256(
    encodeAbiParameters(
      [
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        userOp.sender,
        userOp.nonce,
        keccak256(userOp.initCode),
        keccak256(userOp.callData),
        userOp.accountGasLimits,
        userOp.preVerificationGas,
        userOp.gasFees,
        keccak256(userOp.paymasterAndData),
      ],
    ),
  );

  const userOpHash = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
      [inner, entryPointAddress as `0x${string}`, chainId],
    ),
  );

  const account = privateKeyToAccount(bytesToHex(secretKey));
  const signature = await account.signMessage({
    message: { raw: userOpHash },
  });

  return {
    ...userOp,
    signature,
  };
}
