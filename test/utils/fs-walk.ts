/**
 * Shared filesystem walkers for test-time grep assertions.
 *
 * `listTsFiles(dir)` recursively enumerates `.ts` files under `dir`. Returns
 * `[]` when the directory does not exist (vacuous pass — e.g., a fresh
 * clone with no `test/bench/` tree). Used by boundary-grep tests in
 * `ml-dsa-eth.test.ts` and `falcon-eth.test.ts` (AC-3-7 / AC-5 respectively)
 * to enumerate consumer-facing files that must NOT import from a
 * `*.kat-internal` surface.
 *
 * Extracted here per `.claude/rules/retrospect/typescript.md` §"[2026-04-20]
 * Duplicated test-file code drifts silently" — previously duplicated in
 * both test files.
 */

import { readdirSync, statSync } from "node:fs";
import path from "node:path";

/**
 * Recursively enumerate `.ts` files under `dir`. Returns `[]` when the
 * directory does not exist — vacuous pass for boundary-grep tests on fresh
 * clones that lack `test/bench/`.
 */
export function listTsFiles(dir: string): string[] {
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    return [];
  }
  if (!stat.isDirectory()) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listTsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}
