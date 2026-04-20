/**
 * Shared byte-array assertion helper (Story 3 — AC-3-4).
 *
 * On divergence, prints the first differing index plus ±8 bytes of context
 * from both `actual` and `expected`. When `xofId` is provided (M-3
 * discriminant surfaced by {@link XofReader.id}), the message appends a
 * `(factory=<xofId>)` tag so interleaved-XOF regressions have a
 * grep-friendly anchor in test output.
 *
 * Also exports `bytesEqual` — a boolean-returning counterpart for callers
 * that need to branch on equality rather than throw (e.g., the Falcon-ETH
 * G3 KAT per-vector loop routes through its own `formatG3DivergenceMessage`
 * helper on divergence rather than `assertBytesEqual`'s generic shape).
 * Extracted here per `.claude/rules/retrospect/typescript.md` §"[2026-04-20]
 * Duplicated test-file code drifts silently" — previously duplicated in
 * `falcon-eth.test.ts` and `falcon-eth.keygen.kat.test.ts`.
 */

import assert from "node:assert/strict";

import { bytesToHex } from "viem";

/**
 * Boolean-returning byte-array equality. Use `assertBytesEqual` instead when
 * a throw-on-mismatch flow is appropriate; use this when the caller needs to
 * branch (e.g., format a richer failure message before calling `assert.fail`).
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

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
