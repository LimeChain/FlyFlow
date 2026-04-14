/**
 * ERC-4337 v0.7 userOpHash derivation, shared across signer modules.
 *
 * userOpHash = keccak256(abi.encode(
 *   keccak256(abi.encode(packed fields...)),
 *   entryPointAddress,
 *   chainId,
 * ))
 *
 * Centralised here so ECDSA, Falcon, and ML-DSA signers all hash an
 * identical preimage — drift here would silently desynchronise off-chain
 * signing from the on-chain `EntryPoint.getUserOpHash` view that account
 * implementations use during validation.
 */

import { encodeAbiParameters, keccak256 } from "viem";

import type { UnsignedUserOp } from "./index.js";

export function computeUserOpHash(
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): `0x${string}` {
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

  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
      [inner, entryPointAddress as `0x${string}`, chainId],
    ),
  );
}
