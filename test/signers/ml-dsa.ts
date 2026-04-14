/**
 * ML-DSA (Dilithium) signer — STUB. Real implementation lands in Story 4-1.
 *
 * Both entry points throw `NotImplementedError` with code `"NOT_IMPLEMENTED"`
 * so callers can distinguish "not yet built" from genuine runtime errors.
 */

import { NotImplementedError } from "./errors.js";
import type { Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js";

export function keygen(): Keypair {
  throw new NotImplementedError("mldsa");
}

export async function signUserOp(
  _secretKey: Uint8Array,
  _userOp: UnsignedUserOp,
  _entryPointAddress: string,
  _chainId: bigint,
): Promise<PackedUserOperation> {
  throw new NotImplementedError("mldsa");
}
