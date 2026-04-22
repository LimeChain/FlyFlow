/**
 * Falcon-512 signer — wraps `@noble/post-quantum` `falcon512`.
 *
 * Parameter-set choice: Falcon-512 (NIST Level 1) matches the ZKNoxHQ
 * ETHFALCON verifier submodule, which is hard-wired to n=512, q=12289 at
 * `ETHFALCON/src/ZKNOX_falcon_utils.sol:33-34`.
 *
 * Unlike ML-DSA, BOTH the public key AND the signature need an encoding
 * bridge to the on-chain dialect:
 *  - noble's public key is the 897-byte NIST form (header || 14-bit-packed
 *    coefficients); the verifier stores an SSTORE2 pointer (20 bytes) to an
 *    ABI-encoded NTT-domain compacted `uint256[32]`. See
 *    `encodeFalconPublicKey` in the `utils-eth` subpath of the fork (A-003
 *    rationale: account stores pointer, raw key off-chain).
 *  - noble emits a Falcon detached signature (header || 40-byte nonce ||
 *    Algorithm-17 Golomb-Rice compressed s2); ZKNOX expects a flat
 *    `salt(40) || s2_compact(1024)` = 1064 bytes. `encodeFalconSignature`
 *    in the fork's `utils-eth` subpath performs the reshape.
 *
 * Hash domain: noble's `falcon512.sign` computes HashToPoint internally over
 * `nonce || msg` using SHAKE256; ZKNOX matches at `ZKNOX_falcon.sol:73`
 * (`hashToPointNIST(salt, h)`), so no ctx prefix or internal-API call is
 * required here.
 */

import { falcon512 } from "@noble/post-quantum/falcon.js";
import { encodeFalconSignature } from "@noble/post-quantum/utils-eth.js";
import { bytesToHex, hexToBytes } from "viem";

import type { Keypair, PackedUserOperation, UnsignedUserOp } from "./index.js";
import { computeUserOpHash } from "./userOpHash.js";

export function keygen(): Keypair {
  const { publicKey, secretKey } = falcon512.keygen();
  return { publicKey, secretKey };
}

export async function signUserOp(
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);
  const nobleSig = falcon512.sign(hexToBytes(userOpHash), secretKey);

  return {
    ...userOp,
    signature: bytesToHex(encodeFalconSignature(nobleSig)),
  };
}
