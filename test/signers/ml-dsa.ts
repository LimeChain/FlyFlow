/**
 * ML-DSA-44 (Dilithium) signer — wraps `@noble/post-quantum` `ml_dsa44`.
 *
 * Parameter-set choice: ML-DSA-44 (NIST FIPS 204 Level 2) matches the
 * ETHDILITHIUM verifier submodule, which is hard-wired to k=4, l=4 at
 * `ETHDILITHIUM/src/ZKNOX_dilithium_utils.sol:44-45`. The plan originally
 * specified ML-DSA-65; DD-7 [DISCRETION] anticipates the adjustment.
 *
 * Signature side needs no encoding bridge: noble's `ml_dsa44.sign` output
 * (cTilde(32) || z(2304) || h(84) = 2,420 bytes) matches byte-for-byte
 * what `ZKNOX_dilithium.sol:80` slices on the verifier side. Public-key
 * side DOES need a bridge — see `@noble/post-quantum/utils-eth.js#encodeMlDsaPublicKey`
 * (shared with ML-DSA-ETH via the two-factory `(xofTr, xofExpandA)` signature;
 * NIST callers pass `(shake256XofFactory, shake128XofFactory)`).
 *
 * Hash domain: noble's default `sign(msg, secretKey)` path prepends the
 * FIPS 204 §5.2 domain prefix `0x00 || ctxLen(0) || msg` before SHAKE256
 * mu computation; ZKNOX matches at `ZKNOX_dilithium.sol:77`. No `ctx` or
 * `internal` API needed.
 */

import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { bytesToHex, hexToBytes } from "viem";

import type { Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js";
import { computeUserOpHash } from "./userOpHash.js";

export function keygen(): Keypair {
  const { publicKey, secretKey } = ml_dsa44.keygen();
  return { publicKey, secretKey };
}

export async function signUserOp(
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);
  const signature = ml_dsa44.sign(hexToBytes(userOpHash), secretKey);

  return {
    ...userOp,
    signature: bytesToHex(signature),
  };
}
