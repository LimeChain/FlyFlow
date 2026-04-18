/**
 * Shared byte-array assertion helper (Story 3 — AC-3-4).
 *
 * On divergence, prints the first differing index plus ±8 bytes of context
 * from both `actual` and `expected`. When `xofId` is provided (M-3
 * discriminant surfaced by {@link XofReader.id}), the message appends a
 * `(factory=<xofId>)` tag so interleaved-XOF regressions have a
 * grep-friendly anchor in test output.
 */

import assert from "node:assert/strict";

import { bytesToHex } from "viem";

export function assertBytesEqual(
  actual: Uint8Array,
  expected: Uint8Array,
  label: string,
  xofId?: string,
): void {
  const tag = xofId !== undefined ? ` (factory=${xofId})` : "";

  if (actual.length !== expected.length) {
    assert.fail(
      `${label}: length mismatch — expected ${expected.length}, got ${actual.length}${tag}`,
    );
  }

  for (let i = 0; i < actual.length; i++) {
    const a = actual[i];
    const e = expected[i];
    if (a !== e) {
      const start = Math.max(0, i - 8);
      const end = Math.min(actual.length, i + 9);
      const ctxActual = bytesToHex(actual.slice(start, end));
      const ctxExpected = bytesToHex(expected.slice(start, end));
      assert.fail(
        `${label}: first divergent byte at index ${i}${tag}\n` +
          `  actual   [${start}..${end}): ${ctxActual}\n` +
          `  expected [${start}..${end}): ${ctxExpected}`,
      );
    }
  }
}
