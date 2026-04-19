/**
 * Keccak-PRG G1 KAT tier (Story 1-2, Task T2).
 *
 * Byte-identity tests against the committed ETHFALCON-captured G1 PRG KAT
 * fixture (`test/fixtures/kat/falcon-eth/prg-vectors.json`) — 6 vectors total,
 * each captured from `ETHFALCON/pythonref/keccak_prng.py::KeccakPRNG` at
 * pinned submodule SHA `03ed0d60c67087527de7c4a3c1c469b89611bd68`.
 *
 * Per vector: construct a fresh `createKeccakPrg()`, replay the scripted
 * `injects[] / flip / extracts[]` sequence, and assert every `extract(n_i)`
 * output byte-equals the fixture's `expected[i]` via
 * `assertBytesEqual(actual, expected, label, "keccak-prg")` — producing the
 * `(factory=keccak-prg)` divergence tag (AC-1 discriminant).
 *
 * ACs covered:
 *   - AC-1 (G1 byte-identity; first-differing-byte ±8 B context +
 *     `(factory=keccak-prg)` discriminant — FR-11 satisfaction).
 *   - AC-2 (error path: on divergence, the failure message ALSO carries a
 *     DD-13 reminder that a `falconKeccakXofFactory` adapter MUST be ported
 *     before Stories 2-1 (keygen G3) and 2-3 (signer G4) can proceed — both
 *     downstream stories consume `keccakXofFactory` transitively per DD-13
 *     LOCKED at `docs/architecture.md`).
 *
 * AC-2 implementation: each `assertBytesEqual` call is wrapped in a
 * `try/catch` that appends the DD-13 reminder to the thrown error's message
 * and rethrows. This keeps the reminder local to this test file — the shared
 * `assertBytesEqual` helper is used by mldsa-eth tests too and MUST NOT be
 * modified to inject falcon-specific text (per Risks §6 of Story 1-2).
 *
 * Note on AC-2 verbatim text (per Risks §7): the plan's AC-2 text says
 * "Story 2-1 / 2-2". The actual downstream stories blocked on a G1 failure
 * are 2-1 (keygen G3 — consumes keccakXofFactory) and 2-3 (signer G4 — also
 * consumes keccakXofFactory). Story 2-2 is G2 HashToPoint, which captures
 * from pinned Solidity per DD-25 Option C and does NOT transitively consume
 * the TS PRG. The DD-13 reminder here therefore names "2-1" and "2-3" — see
 * commit message for the Rule-1 minor clarification note.
 *
 * Framework: `node:test` + `node:assert/strict` — matches
 * `test/signers/keccak-prg.kat.test.ts` (the mldsa-era sibling).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { hexToBytes } from "viem";

import { loadFalconPrgVectors } from "../fixtures/kat/index.js";
import { assertBytesEqual } from "../utils/assert-bytes.js";
import { createKeccakPrg } from "./keccak-prg.js";

/**
 * DD-13 reminder appended to any divergence failure. Names `falconKeccakXofFactory`
 * (the adapter DD-13 points at as the scope-expansion response) and both
 * downstream stories that would be blocked on a G1 failure (`2-1` keygen,
 * `2-3` signer). Grep anchors required by Story 1-2 must_haves: "DD-13",
 * "falconKeccakXofFactory", "2-1".
 */
const DD13_REMINDER =
  "\n\nDD-13 reminder: Keccak-PRG byte-identity failure BLOCKS Stories 2-1 (keygen G3) " +
  "and 2-3 (signer G4). Both consume `keccakXofFactory` transitively. Before proceeding, " +
  "port a `falconKeccakXofFactory` adapter (gated behind `id: \"falcon-keccak-prg\"`) " +
  "or amend DD-13. See docs/architecture.md §\"Design Rationale\" DD-13.";

/**
 * Invoke `assertBytesEqual`; on any thrown assertion, append the DD-13 reminder
 * (AC-2 requirement) to `err.message` and rethrow. Keeps the reminder local to
 * this test file — the shared helper is unchanged (mldsa-eth tests get no
 * falcon-specific pollution in their failure output).
 */
function assertBytesEqualWithDD13(
  actual: Uint8Array,
  expected: Uint8Array,
  label: string,
): void {
  try {
    assertBytesEqual(actual, expected, label, "keccak-prg");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const augmented = new Error(message + DD13_REMINDER);
    // Preserve the original error as `cause` for structured debugging.
    (augmented as Error & { cause?: unknown }).cause = err;
    throw augmented;
  }
}

describe("Keccak-PRG KAT (G1 — byte-identity against ETHFALCON Python KeccakPRNG)", () => {
  const vectors = loadFalconPrgVectors();

  for (const vector of vectors) {
    it(`${vector.id}: ${vector.description ?? "(no description)"}`, () => {
      const prg = createKeccakPrg();
      for (const injectHex of vector.injects) {
        prg.inject(hexToBytes(injectHex as `0x${string}`));
      }
      prg.flip();

      assert.equal(
        vector.expected.length,
        vector.extracts.length,
        `${vector.id}: fixture shape — expected[] length (${vector.expected.length}) ≠ extracts[] length (${vector.extracts.length})`,
      );

      for (let i = 0; i < vector.extracts.length; i++) {
        const n = vector.extracts[i];
        const expectedHex = vector.expected[i];
        assert.ok(n !== undefined, `${vector.id}: missing extracts[${i}]`);
        assert.ok(
          expectedHex !== undefined,
          `${vector.id}: missing expected[${i}]`,
        );
        const actual = prg.extract(n);
        const expected = hexToBytes(expectedHex as `0x${string}`);
        assertBytesEqualWithDD13(
          actual,
          expected,
          `G1-keccak-prg ${vector.id} extract[${i}]`,
        );
      }
    });
  }
});

// ---------------------------------------------------------------------------
// AC-2 synthetic divergence test — validates the error-path contract without
// mutating the real fixture. Constructs a mismatched `expected` byte-array in
// memory and asserts the thrown error carries ALL six AC-2 substring anchors
// required by Story 1-2 must_haves:
//   (a) first-differing byte index
//   (b) ±8 B hex context from both actual and expected (`actual   [` / `expected [`)
//   (c) literal `(factory=keccak-prg)` discriminant
//   (d) literal `DD-13`
//   (e) literal `falconKeccakXofFactory`
//   (f) reference to Story `2-1` (first blocked downstream story)
//
// This is the AUTOMATED real-path counterpart to any ad-hoc "temporarily
// mutate the fixture" smoke test; per
// `.claude/rules/retrospect/universal.md` §"Override-based tests need a
// real-path counterpart", both the happy path (above) and the failure path
// (this block) must exist so regressions in either are caught automatically.
// ---------------------------------------------------------------------------

describe("Keccak-PRG KAT (G1 — AC-2 error-path divergence message shape)", () => {
  it("failure message includes byte offset, ±8 B context, (factory=keccak-prg), DD-13, falconKeccakXofFactory, 2-1", () => {
    const prg = createKeccakPrg();
    prg.inject(hexToBytes("0x7465737420696e707574" as `0x${string}`));
    prg.flip();
    const actual = prg.extract(32);

    // Synthetic mismatch: flip the middle byte of the real expected output.
    // Real expected: 0x5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601
    // (Zhenfei-canonical parity anchor). We mutate index 16 (0x53 → 0x00) to
    // force a divergence strictly inside the ±8 B context window.
    const realExpectedHex =
      "0x5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601";
    const tampered = hexToBytes(realExpectedHex as `0x${string}`);
    const original = tampered[16];
    assert.ok(original !== undefined, "tampered[16] must be defined");
    tampered[16] = original ^ 0xff;

    let thrown: unknown;
    try {
      assertBytesEqualWithDD13(
        actual,
        tampered,
        "G1-keccak-prg synthetic-mismatch extract[0]",
      );
      assert.fail("expected assertBytesEqualWithDD13 to throw");
    } catch (err) {
      thrown = err;
    }

    assert.ok(thrown instanceof Error, "thrown value must be an Error");
    const message = (thrown as Error).message;

    // (a) first divergent byte index — `assertBytesEqual` emits "first divergent byte at index <N>"
    assert.match(
      message,
      /first divergent byte at index 16/,
      `missing byte-offset: ${message}`,
    );
    // (b) ±8 B context from both actual and expected.
    assert.match(
      message,
      /actual\s+\[\d+\.\.\d+\):/,
      `missing actual-context slice: ${message}`,
    );
    assert.match(
      message,
      /expected\s+\[\d+\.\.\d+\):/,
      `missing expected-context slice: ${message}`,
    );
    // (c) factory-id discriminant tag.
    assert.match(
      message,
      /\(factory=keccak-prg\)/,
      `missing (factory=keccak-prg) discriminant: ${message}`,
    );
    // (d) DD-13 reminder.
    assert.match(message, /DD-13/, `missing DD-13 marker: ${message}`);
    // (e) falconKeccakXofFactory — adapter name the DD-13 resolution points at.
    assert.match(
      message,
      /falconKeccakXofFactory/,
      `missing falconKeccakXofFactory marker: ${message}`,
    );
    // (f) Story 2-1 reference (first blocked downstream story).
    assert.match(
      message,
      /2-1/,
      `missing Story 2-1 reference: ${message}`,
    );
    // Also assert 2-3 (per AC-2 text-quirk correction — see file-top note).
    assert.match(
      message,
      /2-3/,
      `missing Story 2-3 reference: ${message}`,
    );
  });

  // -------------------------------------------------------------------------
  // AC-2 loop-scope test — proves the wrap-throw is PER-EXTRACT and not
  // hoisted outside the extract loop. A regression that moved the try/catch
  // outside `for (let i = 0; i < extracts.length; i++)` would still catch
  // divergence on extract[0] but would lose the `extract[<i>]` label
  // granularity for later iterations. This test reproduces a divergence on
  // extract[1] specifically, asserts the label carries index 1, and that
  // the DD-13 anchors are still appended (proving wrap-throw fires on the
  // second iteration too).
  // -------------------------------------------------------------------------

  it("failure on extract[1] (second iteration) carries label index and all AC-2 anchors", () => {
    // Reuses the `ethfalcon-g1-cross-extract` vector's sequence:
    //   inject 32 B [0x00..0x1f]; flip; extract(5); extract(27)
    // The first extract matches the real fixture, so the loop reaches
    // extract[1] — where we substitute a tampered `expected` that diverges
    // at index 0 of the second extract's 27-byte output.
    const prg = createKeccakPrg();
    prg.inject(
      hexToBytes(
        "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" as `0x${string}`,
      ),
    );
    prg.flip();

    // First extract — real expected, must NOT throw so the loop advances.
    const realExtract0Hex = "0x77b7caf29d";
    const actual0 = prg.extract(5);
    assertBytesEqualWithDD13(
      actual0,
      hexToBytes(realExtract0Hex as `0x${string}`),
      "G1-keccak-prg ethfalcon-g1-cross-extract extract[0]",
    );

    // Second extract — tamper index 0 of the real expected to force a
    // divergence on the SECOND loop iteration, not the first.
    const realExtract1Hex =
      "0x0c44ef38344ab0bec3724d4d73fcb0c022b364125a19ff674e1fea";
    const tampered1 = hexToBytes(realExtract1Hex as `0x${string}`);
    const original1 = tampered1[0];
    assert.ok(original1 !== undefined, "tampered1[0] must be defined");
    tampered1[0] = original1 ^ 0xff;

    const actual1 = prg.extract(27);
    let thrown: unknown;
    try {
      assertBytesEqualWithDD13(
        actual1,
        tampered1,
        "G1-keccak-prg ethfalcon-g1-cross-extract extract[1]",
      );
      assert.fail("expected assertBytesEqualWithDD13 to throw on extract[1]");
    } catch (err) {
      thrown = err;
    }

    assert.ok(thrown instanceof Error, "thrown value must be an Error");
    const message = (thrown as Error).message;

    // The label contains `extract[1]` (NOT `extract[0]`) — proves the
    // wrap-throw fires within the per-extract loop and carries the correct
    // index on the second iteration.
    assert.match(
      message,
      /extract\[1\]/,
      `missing extract[1] label (wrap-throw hoisted outside loop?): ${message}`,
    );
    assert.doesNotMatch(
      message,
      /extract\[0\]/,
      `unexpected extract[0] label on extract[1] divergence: ${message}`,
    );
    // All AC-2 anchors must still be present — the wrap-throw augmentation
    // applies to every iteration, not just the first.
    assert.match(
      message,
      /first divergent byte at index 0/,
      `missing byte-offset: ${message}`,
    );
    assert.match(
      message,
      /\(factory=keccak-prg\)/,
      `missing (factory=keccak-prg) discriminant: ${message}`,
    );
    assert.match(message, /DD-13/, `missing DD-13 marker: ${message}`);
    assert.match(
      message,
      /falconKeccakXofFactory/,
      `missing falconKeccakXofFactory marker: ${message}`,
    );
    assert.match(message, /2-1/, `missing Story 2-1 reference: ${message}`);
  });
});
