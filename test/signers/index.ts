/**
 * Signer dispatch module (PD-2 LOCKED layout).
 *
 * This file is the ONLY dispatcher — it contains no per-scheme signing logic.
 * Each scheme's `keygen` and `signUserOp` live in its own module so that
 * Stories 2-1 / 3-1 / 4-1 can evolve them in parallel without shared-file
 * merge conflicts.
 */

import * as ecdsa from "./ecdsa.js";
import * as falcon from "./falcon.js";
import * as mldsa from "./ml-dsa.js";

export type Scheme = "ecdsa" | "falcon" | "mldsa";

export type Keypair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

/**
 * ERC-4337 v0.7 PackedUserOperation (unsigned form). The on-chain struct
 * packs verificationGasLimit/callGasLimit into `accountGasLimits` and
 * maxPriorityFeePerGas/maxFeePerGas into `gasFees`.
 */
export type UnsignedUserOp = {
  sender: `0x${string}`;
  nonce: bigint;
  initCode: `0x${string}`;
  callData: `0x${string}`;
  accountGasLimits: `0x${string}`;
  preVerificationGas: bigint;
  gasFees: `0x${string}`;
  paymasterAndData: `0x${string}`;
};

/**
 * Signed counterpart to `UnsignedUserOp`. For ECDSA the signature is the
 * 65-byte `r || s || v` produced by EIP-191 prefixed signing.
 */
export type PackedUserOperation = UnsignedUserOp & {
  signature: `0x${string}`;
};

export function keygen(scheme: Scheme): Keypair {
  switch (scheme) {
    case "ecdsa":
      return ecdsa.keygen();
    case "falcon":
      return falcon.keygen();
    case "mldsa":
      return mldsa.keygen();
  }
}

export async function signUserOp(
  scheme: Scheme,
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  switch (scheme) {
    case "ecdsa":
      return ecdsa.signUserOp(secretKey, userOp, entryPointAddress, chainId);
    case "falcon":
      return falcon.signUserOp(secretKey, userOp, entryPointAddress, chainId);
    case "mldsa":
      return mldsa.signUserOp(secretKey, userOp, entryPointAddress, chainId);
  }
}
