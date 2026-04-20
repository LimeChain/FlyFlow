/**
 * Story 2-1 Task T2 — falcon-eth module boundary + production/KAT surface
 * unit tests.
 *
 * Covers the non-G3 acceptance surface for the Falcon-ETH signer module set:
 *
 * - **AC-2** — Production `keygen()` hedging: two consecutive calls return
 *   byte-distinct public keys (entropy-sourced from
 *   `globalThis.crypto.getRandomValues`).
 * - **AC-3** — `keygenInternal(innerSeed)` input validation: rejects
 *   non-48-byte `Uint8Array` + non-`Uint8Array` inputs with
 *   `SignerInputError { code: "INVALID_INNER_SEED_LENGTH" }`. Four cases
 *   per story: 47 B, 49 B, empty (0 B), non-`Uint8Array` (string).
 * - **AC-5** — Runtime grep boundary: `test/signers/index.ts` and every
 *   file under `test/bench/` MUST NOT import from `falcon-eth.kat-internal`.
 *   Mirrors `ml-dsa-eth.test.ts` AC-3-7 (project has no ESLint; per
 *   `docs/amendments.md` §A-003 the enforcement is a runtime grep).
 * - **AC-6** — Bidirectional boundary: neither `falcon-eth.ts` nor
 *   `falcon-eth.kat-internal.ts` imports the other.
 *
 * Story 2-1 AC-1 (G3 KAT byte-identity over ≥100 vectors) is covered by
 * Task T3's separate test file `falcon-eth.keygen.kat.test.ts` — NOT here.
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { SignerInputError } from "./errors.js";
import { keygen } from "./falcon-eth.js";
import { keygenInternal } from "./falcon-eth.kat-internal.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const SIGNERS_DIR = path.dirname(THIS_FILE);
const TEST_DIR = path.resolve(SIGNERS_DIR, "..");
const BENCH_DIR = path.join(TEST_DIR, "bench");
const INDEX_FILE = path.join(SIGNERS_DIR, "index.ts");
const FALCON_ETH_FILE = path.join(SIGNERS_DIR, "falcon-eth.ts");
const FALCON_ETH_KAT_FILE = path.join(SIGNERS_DIR, "falcon-eth.kat-internal.ts");

/** String-based import detector for `falcon-eth.kat-internal` (AC-5).
 *  Catches both double- and single-quoted variants, with or without the
 *  `.js` suffix. */
const KAT_INTERNAL_IMPORT_RE =
  /from\s+["'][^"']*falcon-eth\.kat-internal[^"']*["']/;

/** Detector for `falcon-eth.ts` imports from within
 *  `falcon-eth.kat-internal.ts` (AC-6 reverse direction). Matches relative
 *  paths `./falcon-eth` or `./falcon-eth.js` in single or double quotes. */
const FALCON_ETH_IMPORT_RE = /from\s+["']\.\.?\/falcon-eth(\.js)?["']/;

function listTsFiles(dir: string): string[] {
  let stat;
  try {
    stat = statSync(dir);
  } catch {
    return []; // directory missing (fresh clone, no bench tree) — vacuous pass.
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe("falcon-eth keygen surfaces (AC-2 / AC-3 / AC-5 / AC-6)", () => {
  // === AC-2: production hedging ==========================================

  it("AC-2: keygen() returns byte-distinct public keys across two calls", () => {
    const a = keygen();
    const b = keygen();
    // Collision probability is ~2^-897 — equality here means CSPRNG is
    // mocked or the universe ended.
    assert.ok(
      !bytesEqual(a.publicKey, b.publicKey),
      "two production keygen() calls returned identical publicKey",
    );
  });

  it("keygen() returns 897 B publicKey + 1281 B secretKey", () => {
    const { publicKey, secretKey } = keygen();
    assert.equal(publicKey.length, 897, "publicKey length");
    assert.equal(secretKey.length, 1281, "secretKey length");
  });

  // === AC-3: keygenInternal input validation =============================

  describe("AC-3: keygenInternal input validation", () => {
    it("rejects 47-byte Uint8Array with INVALID_INNER_SEED_LENGTH", () => {
      assert.throws(
        () => keygenInternal(new Uint8Array(47)),
        (e: unknown) =>
          e instanceof SignerInputError &&
          e.code === "INVALID_INNER_SEED_LENGTH",
      );
    });

    it("rejects 49-byte Uint8Array with INVALID_INNER_SEED_LENGTH", () => {
      assert.throws(
        () => keygenInternal(new Uint8Array(49)),
        (e: unknown) =>
          e instanceof SignerInputError &&
          e.code === "INVALID_INNER_SEED_LENGTH",
      );
    });

    it("rejects empty Uint8Array (0 B) with INVALID_INNER_SEED_LENGTH", () => {
      assert.throws(
        () => keygenInternal(new Uint8Array(0)),
        (e: unknown) =>
          e instanceof SignerInputError &&
          e.code === "INVALID_INNER_SEED_LENGTH",
      );
    });

    it("rejects non-Uint8Array (string) with INVALID_INNER_SEED_LENGTH", () => {
      assert.throws(
        () => keygenInternal("not-bytes" as unknown as Uint8Array),
        (e: unknown) =>
          e instanceof SignerInputError &&
          e.code === "INVALID_INNER_SEED_LENGTH",
      );
    });
  });

  // === AC-5: KAT-internal import boundary ================================

  it("AC-5: test/signers/index.ts has no import from falcon-eth.kat-internal", () => {
    const contents = readFileSync(INDEX_FILE, "utf8");
    const match = contents.match(KAT_INTERNAL_IMPORT_RE);
    assert.equal(
      match,
      null,
      `test/signers/index.ts must not import from falcon-eth.kat-internal — matched: ${String(match?.[0])}`,
    );
  });

  it("AC-5: no file under test/bench/ imports from falcon-eth.kat-internal", () => {
    const benchFiles = listTsFiles(BENCH_DIR);
    for (const file of benchFiles) {
      const contents = readFileSync(file, "utf8");
      const match = contents.match(KAT_INTERNAL_IMPORT_RE);
      assert.equal(
        match,
        null,
        `${path.relative(TEST_DIR, file)} must not import from falcon-eth.kat-internal — matched: ${String(match?.[0])}`,
      );
    }
  });

  // === AC-6: bidirectional boundary ======================================

  it("AC-6: falcon-eth.ts does not import from falcon-eth.kat-internal", () => {
    const contents = readFileSync(FALCON_ETH_FILE, "utf8");
    const match = contents.match(KAT_INTERNAL_IMPORT_RE);
    assert.equal(
      match,
      null,
      `falcon-eth.ts must not import from falcon-eth.kat-internal — matched: ${String(match?.[0])}`,
    );
  });

  it("AC-6: falcon-eth.kat-internal.ts does not import from falcon-eth", () => {
    const contents = readFileSync(FALCON_ETH_KAT_FILE, "utf8");
    const match = contents.match(FALCON_ETH_IMPORT_RE);
    assert.equal(
      match,
      null,
      `falcon-eth.kat-internal.ts must not import from falcon-eth — matched: ${String(match?.[0])}`,
    );
  });
});
