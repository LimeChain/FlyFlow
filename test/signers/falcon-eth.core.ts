/**
 * Falcon-ETH shared-core primitives — XOF-parameterized fork of
 * `@noble/post-quantum/src/falcon.ts` + ETH-variant extensions.
 *
 * Story 2-2 seeds this file with `hashToPointEVM` only — the DD-25
 * Option C G2 port. Stories 2-1 / 2-3 / 2-4 will append keygen, sign,
 * and pk-transform surfaces (each with their own @delta-from-falcon
 * delta enumeration; see docs/architecture.md §"Testing Strategy"
 * FALCON_DELTA_HEADINGS for the full substring list AC-D-3 enforces).
 *
 * @ported-from ETHFALCON/src/ZKNOX_HashToPoint.sol:22 at submodule SHA
 * 03ed0d60c67087527de7c4a3c1c469b89611bd68. G2 KAT at
 * test/signers/falcon-eth.core.kat.test.ts witnesses byte-identity
 * against the Hardhat-captured corpus at
 * test/fixtures/kat/falcon-eth/hashtopoint-vectors.json.
 *
 * @module falcon-eth.core
 * @custom:experimental
 */

import {
  genFalcon,
  falcon512paddedOpts,
  type Falcon,
} from "@noble/post-quantum/falcon.js";
import { decodeAbiParameters, keccak256, type Hex } from "viem";

import { encodePublicKeyForZKNOX } from "./falcon-encoding.js";
import type { XofFactory } from "./mldsa-encoding.js";

// === Falcon-512 constants (authoritative — from ZKNOX_HashToPoint.sol) =====

/** Falcon-512 prime modulus — coefficients live in Z_q. */
const Q = 12289;
/**
 * Rejection threshold — exactly `5 * Q`. Chunks `>= KQ` are discarded;
 * chunks `< KQ` are reduced mod Q. NOT `61440` — off-by-5 is a silent
 * bug that only shows up on rare keccak-buffer chunks in `[61440, 61445)`.
 */
const KQ = 61445;
/** Output coefficient count (Falcon-512 polynomial degree). */
const N = 512;

/** Initial state size (bytes) — `keccak256(salt‖msg)` output. */
const STATE_SIZE = 32;
/** Big-endian uint64 counter appended after the state. */
const COUNTER_SIZE = 8;
/** Full absorb buffer size — state(32) ‖ counter_u64_be(8). */
const EXTENDED_STATE_SIZE = STATE_SIZE + COUNTER_SIZE;
/** Number of 16-bit big-endian chunks per 32-byte keccak buffer. */
const CHUNKS_PER_BUFFER = 16;

/**
 * Port of `hashToPointEVM(salt, msgHash)` from ETHFALCON's
 * `ZKNOX_HashToPoint.sol:22-52` at pinned submodule SHA
 * 03ed0d60c67087527de7c4a3c1c469b89611bd68. Pure function (AC-4):
 * same (salt, msg) → same 512-coefficient output, every coeff `< 12289`
 * (AC-3). G2 KAT witnesses byte-identity against the Hardhat-captured
 * corpus (DD-25 Option C).
 *
 * Algorithm summary (see story 2-2 §"Architecture Guardrails §Algorithm"
 * for the full pseudocode):
 *
 *   1. Initial state  — `state = keccak256(salt ‖ msg)`           (32 B)
 *   2. Extended state — `extendedState = state ‖ counter_u64_be`  (40 B)
 *   3. Per outer iter — `buffer = keccak256(extendedState)`       (32 B)
 *                       Extract 16 chunks of 2 B BIG-ENDIAN.
 *                       For each chunk < KQ, append `chunk % Q` to
 *                       output at the next index (forward order).
 *                       Stop when output has 512 coefficients.
 *                       Otherwise increment counter (BE u64 at bytes
 *                       32..40 of extendedState) and re-hash.
 *
 * Implementer notes (see story 2-2 §Risks for full enumeration):
 *
 *   - Chunk endianness is BIG-ENDIAN: `(buffer[2k] << 8) | buffer[2k+1]`
 *     for k=0..15. NOT little-endian.
 *   - KQ = 61445 exactly (= 5 * Q). Not 61440.
 *   - `mod Q` is applied AFTER the rejection check — a chunk equal to Q
 *     is valid and reduces to 0.
 *   - First accepted chunk goes to `output[0]`, not `output[511]` —
 *     coefficients are appended in forward (acceptance) order.
 *   - `keccak256(extendedState)` is a ONE-SHOT hash per iteration, NOT a
 *     Keccak-PRG session. Do NOT wire this through the Keccak-PRG state
 *     machine in `keccak-prg.ts` — wrong primitive shape (three-phase
 *     inject/flip/extract vs one-shot hash). See story 2-2 §"Keccak
 *     primitive authority" for the binding rationale.
 *   - Counter is a u64 big-endian at bytes [32..40) of `extendedState`,
 *     incremented by 1 per outer iteration. Use `bigint` + `DataView`.
 *   - Absorb order: `salt ‖ msg` (NOT `msg ‖ salt` — that would be
 *     `hashToPointTETRATION`, a different algorithm).
 *
 * @param salt Salt bytes (typically 40 B for Falcon-512, but length is
 *             not constrained by the algorithm — the concatenation
 *             `salt ‖ msg` is fed directly to keccak256).
 * @param msg  Message bytes (arbitrary length).
 * @returns Uint16Array of length 512, every element `< 12289` (AC-3).
 */
export function hashToPointEVM(
  salt: Uint8Array,
  msg: Uint8Array,
): Uint16Array {
  // --- Initial state: keccak256(salt ‖ msg), 32 bytes ---
  const concat = new Uint8Array(salt.length + msg.length);
  concat.set(salt, 0);
  concat.set(msg, salt.length);
  const initialState = keccak256(concat, "bytes");

  // --- Extended absorb buffer: state(32) ‖ counter_u64_be(8), 40 bytes ---
  const extendedState = new Uint8Array(EXTENDED_STATE_SIZE);
  extendedState.set(initialState, 0);
  // Counter bytes [32..40) start at 0 (Uint8Array default). `DataView`
  // below rewrites them as the counter advances, big-endian.
  const extendedView = new DataView(
    extendedState.buffer,
    extendedState.byteOffset,
    extendedState.byteLength,
  );

  const output = new Uint16Array(N);
  let i = 0;
  // bigint counter — matches keccak-prg.ts:107 convention. Avoids the
  // JS Number 2^53-1 ceiling (not reachable in practice for Falcon, but
  // bigint is zero-cost at this scale and mirrors the Solidity uint64
  // semantics exactly).
  let counter = 0n;

  // --- Main rejection-sampling loop ---
  // Outer iter: one keccak256 call per 32-byte buffer of candidate chunks.
  while (i < N) {
    const buffer = keccak256(extendedState, "bytes");

    // Inner iter: 16 chunks of 2 bytes each, BIG-ENDIAN (high bits first).
    // The Solidity loop `for { let j := 240 } lt(j, 666) { j := sub(j, 16) }`
    // reads chunks from j=240 down to j=0, which in big-endian memory
    // corresponds to bytes [0..2), [2..4), ..., [30..32) of the buffer
    // in forward order. See story 2-2 §"Why lt(j, 666) is NOT 666
    // iterations" for why the Solidity literal `666` is a uint-underflow
    // guard, not a semantic bound — it is NOT ported.
    for (let chunkIdx = 0; chunkIdx < CHUNKS_PER_BUFFER; chunkIdx++) {
      const byteOffset = chunkIdx * 2;
      // Non-null assertions are unavoidable here: TS doesn't narrow
      // buffer[k] (Uint8Array indexer returns `number | undefined` under
      // noUncheckedIndexedAccess — not currently enabled, but future-
      // proof). The indices are in-range by construction:
      //   chunkIdx ∈ [0, 16)  ⇒  byteOffset ∈ [0, 30]  ⇒  both reads
      //   land in [0, 32) of the 32-byte keccak output.
      const hi = buffer[byteOffset];
      const lo = buffer[byteOffset + 1];
      const chunk = ((hi as number) << 8) | (lo as number);

      // Rejection-sampling gate — `chunk < KQ` (NOT `<= KQ`). KQ = 5*Q
      // = 61445 exactly. `chunk % Q` is applied AFTER the gate, so a
      // chunk of exactly Q (=12289) passes the gate and reduces to 0;
      // this is intentional per the Solidity and preserves uniformity
      // over Z_q (each residue class has exactly 5 pre-images in
      // [0, KQ)).
      if (chunk < KQ) {
        output[i] = chunk % Q;
        i++;
        if (i === N) break;
      }
    }

    // --- Increment counter (big-endian u64 at bytes 32..40) ---
    // The Solidity `counter := add(counter, 1 << 192)` + `mstore` pair
    // increments a u64 that lives MSB-aligned at bytes [0..8) of a
    // uint256 word stored at memory offset 32 of extendedState — which
    // lands at bytes [32..40) of the concrete buffer. This DataView
    // write mirrors keccak-prg.ts:176 (`blockView.setBigUint64(...,
    // false)` — third arg false = big-endian).
    counter += 1n;
    extendedView.setBigUint64(STATE_SIZE, counter, false);
  }

  // --- Defensive invariants (AC-3 defense-in-depth) ---
  // Cheap — O(N) with N=512, negligible vs the keccak iterations above.
  // Surfaces port bugs BEFORE they reach the KAT test; AC-3 is also
  // re-asserted at the test level (belt-and-braces).
  if (output.length !== N) {
    throw new Error(
      `hashToPointEVM: output length ${output.length} !== ${N}`,
    );
  }
  for (let k = 0; k < N; k++) {
    const coeff = output[k] as number;
    if (coeff >= Q) {
      throw new Error(
        `hashToPointEVM: coeff[${k}]=${coeff} >= q=${Q}`,
      );
    }
  }

  return output;
}

// === Falcon-ETH signer instance (Story 2-3 T2; docs/amendments.md §A-006) =====

/**
 * Falcon-ETH variant of noble's `falcon512padded` — swaps the factory's
 * `HashToPoint` binding for `hashToPointEVM` above (Keccak256-based,
 * byte-identical to ETHFALCON's Solidity + Python references per G2 KAT
 * at `test/signers/falcon-eth.core.kat.test.ts`).
 *
 * The `falcon512paddedOpts` spread carries the fork's
 * ETHFALCON-compatible rejection bound — `compress(s[1], 625)` at
 * `ETHFALCON/pythonref/falcon.py:474`. Noble's unpadded `falcon512`
 * uses a looser bound (711 bytes), a different acceptance criterion
 * that produces different s2 polynomials on rejection iterations and
 * would break G4 byte-identity against the `.rsp` corpus. Consuming
 * the fork-exported opts bundle at `@noble/post-quantum/falcon.js`
 * makes the parity point implicit — no magic numbers in our repo, no
 * drift risk if noble ever re-tunes the padded construction.
 *
 * The `: Falcon` annotation is load-bearing: the spread + `hashToPoint`
 * injection makes `genFalcon`'s return type inference-unfriendly; the
 * explicit annotation documents the intended surface and helps tsc.
 *
 * Consumed by:
 *   - `test/signers/falcon-eth.kat-internal.ts#signWithKatBytes` (Story 2-3 T3)
 *   - `test/signers/falcon-eth.ts#signUserOp` (Story 2-3 T3)
 *   - G4 KAT test at `test/signers/falcon-eth.sign.kat.test.ts` (Story 2-3 T4)
 */
export const falcon512paddedEth: Falcon = genFalcon({
  ...falcon512paddedOpts,
  hashToPoint: hashToPointEVM,
});

// === Falcon-ETH G5 pk-transform (Story 2-4 T1; AC-1 + AC-2) ================

/**
 * Compact NTT-domain Falcon-512 public key representation.
 *
 * Decodes the 897 B raw NIST Falcon-512 public key, applies forward NTT to the
 * `h` polynomial, and packs the 512 coefficients (≤14 bits each, space-padded
 * to 16 bits) into 32 `uint256` words — one `bigint` per word. THIS IS the
 * intermediate shape that `preparePublicKeyForDeployment` ABI-encodes.
 *
 * The byte-difference between `falcon` and `falcon-eth` at the pk-transform
 * layer is ZERO per DD (both schemes share the raw→NTT→compact transform —
 * ZKNOX's ETHFALCON uses the same packing as the non-ETH falcon verifier).
 * This export therefore delegates to `encodePublicKeyForZKNOX` at
 * `falcon-encoding.ts:128` and decodes the outer `abi.encode([uint256[]])`
 * to recover the `bigint[]` shape. AC-1 (G5 KAT) is the empirical guard
 * against any future DD drift; if falcon-eth ever diverges from falcon at
 * this layer, the KAT will surface it before the delegation assumption
 * causes an on-chain failure.
 *
 * The `xofFactory` parameter is UNUSED inside — it exists for NFR-11 cross-
 * scheme symmetry with `mldsa-encoding.ts#preparePublicKeyForDeployment`
 * (which takes two `XofFactory` arguments because ml-dsa-eth drives
 * `aHat` ingestion and `tr` H-of-pk through XOF streams). Falcon-ETH's
 * NTT ingestion is deterministic over the 897 B raw key — no XOF needed —
 * but keeping the parameter preserves the 5-scheme function-shape
 * invariant that a future NFR-11 structural grep asserts.
 *
 * AC-2 (G5 structural sub-check) asserts `returned.length === 32` AND
 * `returned[i] < 2^256` for every `i`. Both invariants are guaranteed by
 * `encodePublicKeyForZKNOX`'s internal `compactPoly256(..., 16)` call
 * (16 coefficients × 16 bits per packed word ⇒ 32 uint256 words) — this
 * export is a thin projection.
 *
 * @param rawPk 897-byte raw Falcon-512 NIST public key (header byte 0x09 +
 *              896 byte 14-bit-MSB-packed `h` polynomial body).
 * @param _xofFactory Unused; accepted for NFR-11 cross-scheme symmetry with
 *                    `mldsa-encoding.ts#preparePublicKeyForDeployment`.
 *                    Callers pass `keccakXofFactory` by convention.
 * @returns `bigint[]` of length 32, every element `< 2^256`.
 */
export function pkToNttCompact(
  rawPk: Uint8Array,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- NFR-11 shape
  _xofFactory: XofFactory,
): bigint[] {
  const encoded = encodePublicKeyForZKNOX(rawPk);
  const [compact] = decodeAbiParameters(
    [{ type: "uint256[]" }],
    encoded,
  );
  // `decodeAbiParameters` returns `readonly bigint[]` for `uint256[]`; we
  // project to a plain mutable `bigint[]` to match the declared signature
  // (callers may iterate; immutability is not a stated contract).
  return [...compact];
}

/**
 * Prepare a Falcon-ETH public key for on-chain deployment via `setKey`.
 *
 * Produces the `abi.encode([uint256[]])` hex payload `ZKNOX_ethfalcon.setKey`
 * writes via SSTORE2 — byte-identical to the non-ETH `falcon` path per DD
 * (ETHFALCON's `ZKNOX_ethfalcon` uses the same `compactPoly256` packing over
 * the same forward-NTT `h` as `ZKNOX_falcon`). THIS IS the G5 gate surface.
 *
 * AC-1 oracle (per `docs/amendments.md` §A-007): structural coefficient-
 * equality against `v.reshapedPublicKey`, not raw `Hex` byte-equality. The
 * fixture encodes the same 32 `uint256` coefficients as `uint256[32]`
 * (fixed, 1024 B, matches Python ref `ETHFALCON/pythonref/sig_sol.py:48`);
 * this export emits `uint256[]` (dynamic, 1088 B, required by on-chain
 * `abi.decode(data, (uint256[]))`). Same 32 coefficients wrapped in two
 * ABI shapes — the 64-byte delta is the dynamic-array `[offset][length]`
 * prefix. AC-1 decodes both sides with `decodeAbiParameters` and compares
 * the resulting `bigint[]`s element-wise across ≥100 KAT vectors.
 *
 * NFR-11 cross-scheme symmetry: the signature mirrors
 * `mldsa-encoding.ts#preparePublicKeyForDeployment`:
 *   - Same function name
 *   - Same `Hex` return type
 *   - Same caller pattern: `const payload = preparePublicKeyForDeployment(rawPk, factory);
 *     await falconEthVerifier.write.setKey([payload])`
 *
 * Delegates to `encodePublicKeyForZKNOX` — single source of truth for the
 * raw→NTT→compact→abi.encode transform. The `xofFactory` parameter is not
 * consumed internally (Falcon-ETH's NTT is deterministic over the raw
 * public-key bytes; no XOF-driven ingestion at pk-transform time). Callers
 * pass `keccakXofFactory` by convention to keep the 5-scheme call-site
 * shape uniform.
 *
 * @param rawPk 897-byte raw Falcon-512 NIST public key.
 * @param _xofFactory Unused; accepted for NFR-11 cross-scheme symmetry.
 *                    Callers pass `keccakXofFactory` by convention.
 * @returns `Hex` payload directly passable to `falconEthVerifier.setKey(hex)`
 *          (dynamic `uint256[]` ABI-encoded). Coefficient-equal to the
 *          `reshapedPublicKey` fixture field (which uses `uint256[32]`
 *          encoding) over the full KAT corpus — AC-1 empirical guard per
 *          A-007 structural oracle.
 */
export function preparePublicKeyForDeployment(
  rawPk: Uint8Array,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- NFR-11 shape
  _xofFactory: XofFactory,
): Hex {
  return encodePublicKeyForZKNOX(rawPk);
}
