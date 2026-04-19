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

import { keccak256 } from "viem";

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
