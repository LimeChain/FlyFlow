/**
 * Story 2-4 Task T6 — AC-10 snake-case prohibition grep.
 *
 * AC-10 (binding from `docs/stories/2-4.md:278-284`): the literal token
 * `falcon_eth` (lowercase snake_case) MUST NOT appear in `src/`, `test/`,
 * `contracts/`, or `scripts/`. Canonical forms per the naming table
 * (`docs/architecture.md` §"Naming table"):
 *
 *   - `falcon-eth`   (kebab — file paths, `Scheme` literal, fixture dir)
 *   - `falconEth`    (camelCase — TS identifiers)
 *   - `FalconEthAccount` / `FalconEthFixture` (PascalCase)
 *   - `Falcon512_ETH` (docstring attribution only)
 *
 * Case-sensitive lowercase check only — SCREAMING_SNAKE constants like
 * `FALCON_ETH_SIGNATURE_LENGTH` / `FALCON_ETH_FILE` (Story 2-3 convention)
 * are permitted and MUST NOT trigger this grep. Test file scans files byte
 * by byte for the literal substring "falcon_eth".
 *
 * Scope: the four top-level trees `src/`, `test/`, `contracts/`, `scripts/`.
 * This file MUST exclude itself from the scan — the AC-10 literal appears
 * in this file's own prose/JSDoc as documentation and is the one sanctioned
 * exception.
 *
 * Framework: node:test + node:assert/strict (project convention).
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const THIS_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), "..", "..");

/**
 * Roots to scan for the snake_case violation. Order matches the AC-10 text
 * in `docs/stories/2-4.md:278`.
 */
const SCAN_ROOTS = ["src", "test", "contracts", "scripts"] as const;

/**
 * File extensions to scan. Any text-bearing source or config file that a
 * future naming drift could hide inside — `.ts` for TS, `.sol` for
 * Solidity, `.md` for docs living under these trees, `.json` for configs,
 * `.yaml` / `.yml` for CI / hardhat config, `.sh` for any helper scripts.
 */
const SCAN_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".cjs",
  ".mjs",
  ".sol",
  ".md",
  ".json",
  ".yaml",
  ".yml",
  ".sh",
]);

/**
 * Directories to skip during the scan — build outputs + VCS internals that
 * may legitimately contain the string without being part of our source of
 * record.
 */
const SKIP_DIRS = new Set([
  "node_modules",
  "artifacts",
  "cache",
  "typechain-types",
  ".git",
]);

function* walk(dir: string): Generator<string> {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".") continue;
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (SCAN_EXTENSIONS.has(ext)) yield full;
    }
  }
}

describe("naming discipline — AC-10", () => {
  it("no `falcon_eth` (lowercase snake) appears under src/ test/ contracts/ scripts/", () => {
    const hits: Array<{ file: string; line: number; text: string }> = [];

    for (const root of SCAN_ROOTS) {
      const rootPath = path.join(REPO_ROOT, root);
      let stat;
      try {
        stat = statSync(rootPath);
      } catch {
        // Root doesn't exist on a fresh clone or under a slimmed checkout —
        // vacuous pass for this root, not an AC-10 violation.
        continue;
      }
      if (!stat.isDirectory()) continue;

      for (const file of walk(rootPath)) {
        // Exclude this test file — it documents the AC-10 literal in its
        // own prose / JSDoc and is the single sanctioned exception.
        if (path.resolve(file) === path.resolve(THIS_FILE)) continue;

        const content = readFileSync(file, "utf8");
        if (!content.includes("falcon_eth")) continue;

        // Report per-line for a helpful failure message.
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const l = lines[i] ?? "";
          if (l.includes("falcon_eth")) {
            hits.push({
              file: path.relative(REPO_ROOT, file),
              line: i + 1,
              text: l.trim().slice(0, 120),
            });
          }
        }
      }
    }

    assert.equal(
      hits.length,
      0,
      `AC-10 violation: literal 'falcon_eth' found in ${hits.length} location(s) — canonical form is kebab ('falcon-eth') or camel ('falconEth') per docs/architecture.md §"Naming table".\n${hits
        .map((h) => `  ${h.file}:${h.line}: ${h.text}`)
        .join("\n")}`,
    );
  });
});
