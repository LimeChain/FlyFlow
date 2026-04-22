/**
 * Keccak-PRG lifecycle unit tests (Story 2, Task 1).
 *
 * Exercises the four `PrgLifecycleError` codes and the SHAKE-parity
 * aliases. Tests assert on `err.code` (the discriminant) and never on
 * message text — contract per `docs/architecture.md` §"Error Handling
 * Strategy" §"JS signer taxonomy" rows 6-9.
 *
 * ACs covered:
 *   - AC-2-4 (inject-after-flip → `PRG_INJECT_AFTER_FLIP`)
 *   - AC-2-5 (extract-before-flip → `PRG_EXTRACT_BEFORE_FLIP`)
 * Plus lifecycle-guard completeness: `PRG_DOUBLE_FLIP`,
 * `PRG_BUFFER_OVERFLOW`, empty-seed happy path, and alias equivalence.
 *
 * Framework: `node:test` + `node:assert/strict` — matches
 * `test/fixtures/kat/index.test.ts` and `test/signers/falcon-encoding.test.ts`.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createKeccakPrg,
  PrgLifecycleError,
} from "@noble/post-quantum/utils-eth.js";

describe("Keccak-PRG lifecycle guards", () => {
  it("throws PRG_INJECT_AFTER_FLIP when inject() is called after flip()", () => {
    const prg = createKeccakPrg();
    prg.flip();
    assert.throws(
      () => prg.inject(new Uint8Array([0x01, 0x02, 0x03])),
      (err: unknown) =>
        err instanceof PrgLifecycleError &&
        err.code === "PRG_INJECT_AFTER_FLIP",
    );
  });

  it("throws PRG_EXTRACT_BEFORE_FLIP when extract() is called before flip()", () => {
    const prg = createKeccakPrg(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    assert.throws(
      () => prg.extract(32),
      (err: unknown) =>
        err instanceof PrgLifecycleError &&
        err.code === "PRG_EXTRACT_BEFORE_FLIP",
    );
  });

  it("throws PRG_DOUBLE_FLIP when flip() is called twice on the same instance", () => {
    const prg = createKeccakPrg();
    prg.flip();
    assert.throws(
      () => prg.flip(),
      (err: unknown) =>
        err instanceof PrgLifecycleError && err.code === "PRG_DOUBLE_FLIP",
    );
  });

  it("throws PRG_BUFFER_OVERFLOW when cumulative inject exceeds MAX_BUFFER_SIZE (4096 B)", () => {
    const prg = createKeccakPrg();
    // Fill to exactly 4096 (valid): 4 × 1024-byte injects.
    const block = new Uint8Array(1024);
    for (let i = 0; i < 4; i++) prg.inject(block);
    // One more byte would push cumulative length to 4097 — must throw.
    assert.throws(
      () => prg.inject(new Uint8Array([0x00])),
      (err: unknown) =>
        err instanceof PrgLifecycleError &&
        err.code === "PRG_BUFFER_OVERFLOW",
    );
  });

  it("empty-seed path: createKeccakPrg() → flip() → extract(32) returns 32 bytes", () => {
    const prg = createKeccakPrg();
    prg.flip();
    const out = prg.extract(32);
    assert.ok(out instanceof Uint8Array, "expected Uint8Array");
    assert.equal(out.length, 32);
  });

  it("update() is an alias for inject() — same state after flip+extract", () => {
    const a = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const b = new Uint8Array([0xaa, 0xbb, 0xcc]);

    const viaInject = createKeccakPrg();
    viaInject.inject(a);
    viaInject.inject(b);
    viaInject.flip();

    const viaUpdate = createKeccakPrg();
    viaUpdate.update(a);
    viaUpdate.update(b);
    viaUpdate.flip();

    assert.deepEqual(viaInject.extract(64), viaUpdate.extract(64));
  });

  it("read() is an alias for extract() — same bytes on identically-seeded instances", () => {
    const seed = new Uint8Array([0x74, 0x65, 0x73, 0x74]); // ASCII 'test'

    const viaExtract = createKeccakPrg(seed);
    viaExtract.flip();
    const viaRead = createKeccakPrg(seed);
    viaRead.flip();

    assert.deepEqual(viaExtract.extract(32), viaRead.read(32));
  });
});
