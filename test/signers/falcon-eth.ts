/**
 * Falcon-ETH production keygen + signer surfaces.
 *
 * Thin ERC-4337 glue around the fork-owned crypto surface at
 * `@noble/post-quantum/{falcon,utils-eth}.js`. After the falcon-eth fork
 * extraction, this module holds only the repo-local seams:
 *
 *   - `keygen()`            — sources a 48 B `innerSeed` from Web Crypto
 *                             and forwards to noble's `falcon512.keygen`.
 *   - `signUserOp(...)`     — computes `userOpHash`, calls
 *                             `falcon512paddedEth.sign` (Keccak-256
 *                             HashToPoint variant), re-encodes the detached
 *                             signature via `encodeFalconSignature`, and
 *                             packs into a `PackedUserOperation`.
 *   - `preparePublicKeyForDeployment(rawPk, _xofFactory)` — NFR-11 cross-
 *                             scheme shape shim over `encodeFalconPublicKey`.
 *                             The `_xofFactory` parameter is unused
 *                             (Falcon-ETH's pk-transform is deterministic
 *                             over raw pk bytes); accepted only so the
 *                             5-scheme call-site grep stays uniform with
 *                             `mldsa-encoding.ts#preparePublicKeyForDeployment`.
 *
 * All low-level crypto (HashToPoint primitive, ABI-level encoders, raw
 * signature layout) lives in the fork. The fork returns `Uint8Array`
 * throughout; this module wraps with `bytesToHex` at the viem boundary.
 *
 * Entropy source: Node's global Web Crypto API —
 * `globalThis.crypto.getRandomValues(new Uint8Array(n))`. Matches the idiom
 * used by `test/signers/ml-dsa-eth.ts`.
 */

import { falcon512, falcon512paddedEth } from "@noble/post-quantum/falcon.js";
import {
  encodeFalconPublicKey,
  encodeFalconSignature,
} from "@noble/post-quantum/utils-eth.js";
import { bytesToHex, hexToBytes, type Hex } from "viem";

import type {
  Keypair,
  PackedUserOperation,
  UnsignedUserOp,
} from "./index.js";
import type { XofFactory } from "./mldsa-encoding.js";
import { computeUserOpHash } from "./userOpHash.js";

/**
 * Generate a fresh Falcon-ETH keypair. Sources a 48 B `innerSeed` from
 * `globalThis.crypto.getRandomValues` and forwards to noble's
 * `falcon512.keygen` (which validates length via `abytes`).
 *
 * @returns `{ publicKey, secretKey }` — 897 B pk + 1281 B sk.
 */
export function keygen(): Keypair {
  const innerSeed = new Uint8Array(48);
  globalThis.crypto.getRandomValues(innerSeed);
  return falcon512.keygen(innerSeed);
}

/**
 * Sign an ERC-4337 v0.7 UserOperation with a Falcon-ETH secret key.
 *
 * Computes `userOpHash`, routes through `falcon512paddedEth.sign`
 * (HashToPoint-injected via the fork), then re-encodes noble's detached
 * signature (~666 B: `header ‖ salt ‖ compressed_s2`) into the 1064 B
 * `salt(40) ‖ s2_compact(1024)` layout consumed by
 * `ZKNOX_falcon.verify(bytes,bytes32,bytes)`.
 *
 * Randomness comes from `globalThis.crypto.getRandomValues` per call —
 * noble requests 40 B salt + 48 B FFSampler seed, on-demand. No pre-
 * allocated buffer, no budget guard: the randomness source is trusted
 * and the request size is fixed by Falcon's construction.
 *
 * Two back-to-back calls with identical inputs return different
 * signatures because the 40 B salt differs (AC-2 of Story 2-3).
 */
export async function signUserOp(
  secretKey: Uint8Array,
  userOp: UnsignedUserOp,
  entryPointAddress: string,
  chainId: bigint,
): Promise<PackedUserOperation> {
  const userOpHash = computeUserOpHash(userOp, entryPointAddress, chainId);

  // Noble's `Falcon` type alias declares `sign` via the generic `Signer`
  // shape (`SigOpts` — no `random`). At runtime, `genFalcon` wires the
  // Falcon-specific `FalconSigOpts` which accepts a `random` callback.
  // The local cast names the wider contract without reaching into the
  // fork's private types.
  const signWithRandom = falcon512paddedEth.sign as (
    msg: Uint8Array,
    secretKey: Uint8Array,
    opts: { random: (n?: number) => Uint8Array },
  ) => Uint8Array;
  const nobleSig = signWithRandom(hexToBytes(userOpHash), secretKey, {
    random: (n?: number): Uint8Array => {
      const buf = new Uint8Array(n ?? 0);
      globalThis.crypto.getRandomValues(buf);
      return buf;
    },
  });

  return {
    ...userOp,
    signature: bytesToHex(encodeFalconSignature(nobleSig)),
  };
}

/**
 * NFR-11 cross-scheme shape shim over
 * `@noble/post-quantum/utils-eth.js#encodeFalconPublicKey`.
 *
 * Mirrors the 2-parameter signature of
 * `mldsa-encoding.ts#preparePublicKeyForDeployment` so the 5-scheme
 * call-site grep stays uniform across Falcon-NIST, Falcon-ETH, ML-DSA-NIST,
 * ML-DSA-ETH, and ECDSA. The `_xofFactory` parameter is unused —
 * Falcon-ETH's pk-transform is deterministic over the 897 B raw public key
 * (forward NTT + compact packing), with no XOF-driven ingestion. Callers
 * pass `keccakXofFactory` by convention.
 *
 * Emits the same 1088-byte `abi.encode(uint256[])` payload as the pre-
 * extraction `encodePublicKeyForZKNOX` — wrapped at the viem boundary via
 * `bytesToHex`. On-chain ingestion via `ZKNOX_falcon.setKey(bytes)` +
 * `abi.decode(data, (uint256[]))` is unchanged.
 *
 * @param rawPk       897 B raw Falcon-512 NIST public key.
 * @param _xofFactory Unused — NFR-11 cross-scheme shape only.
 * @returns           `Hex` payload directly passable to
 *                    `falconEthVerifier.setKey(hex)`.
 */
export function preparePublicKeyForDeployment(
  rawPk: Uint8Array,
  _xofFactory: XofFactory,
): Hex {
  return bytesToHex(encodeFalconPublicKey(rawPk));
}
