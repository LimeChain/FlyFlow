/**
 * Story 3 Task 3 — ml-dsa-eth module boundary + parameter-constant
 * + `@delta-from-ml-dsa` assertions.
 *
 * Covers the non-KAT acceptance surface for the ETH signer module set:
 *
 * - **AC-3-7** — Runtime grep boundary: `test/signers/index.ts` and every
 *   file under `test/bench/` MUST NOT import from `ml-dsa-eth.kat-internal`.
 *   Enforced here rather than via ESLint per `docs/amendments.md` §A-003
 *   (project has no ESLint configuration; bootstrapping ESLint for one
 *   rule exceeds Story 3's scope).
 * - **AC-3-8** — ML-DSA-44 parameter constants imported from
 *   `ml-dsa-eth.core.ts` must match the FIPS 204 Table 1/2 tuple
 *   `(K=4, L=4, D=13, GAMMA1=131072, GAMMA2=95232, TAU=39, ETA=2,
 *    OMEGA=80, BETA=78)`.
 * - **AC-3-6** — Both `ml-dsa-eth.ts` and `ml-dsa-eth.kat-internal.ts`
 *   module-header JSDoc contains the literal string `@delta-from-ml-dsa`
 *   plus the five enumerated byte-level deltas (XOF, fork scope,
 *   pk-transform factory, ctx, signature layout).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { listTsFiles } from "../utils/fs-walk.js";
import {
  BETA,
  D,
  ETA,
  GAMMA1,
  GAMMA2,
  K,
  L,
  OMEGA,
  TAU,
} from "./ml-dsa-eth.core.js";

const THIS_FILE = fileURLToPath(import.meta.url);
const SIGNERS_DIR = path.dirname(THIS_FILE);
const TEST_DIR = path.resolve(SIGNERS_DIR, "..");
const BENCH_DIR = path.join(TEST_DIR, "bench");
const INDEX_FILE = path.join(SIGNERS_DIR, "index.ts");
const ML_DSA_ETH_FILE = path.join(SIGNERS_DIR, "ml-dsa-eth.ts");
const ML_DSA_ETH_KAT_FILE = path.join(SIGNERS_DIR, "ml-dsa-eth.kat-internal.ts");

/** `/from\s+["'][^"']*ml-dsa-eth\.kat-internal[^"']*["']/` — string-based
 *  import detector used by AC-3-7. Catches both `from "…ml-dsa-eth.kat-internal…"`
 *  and single-quoted variants, with or without the `.js` suffix. */
const KAT_INTERNAL_IMPORT_RE =
  /from\s+["'][^"']*ml-dsa-eth\.kat-internal[^"']*["']/;

describe("ml-dsa-eth boundary + params + delta-header (AC-3-6/-3-7/-3-8)", () => {
  it("AC-3-7: test/signers/index.ts has no import from ml-dsa-eth.kat-internal", () => {
    const contents = readFileSync(INDEX_FILE, "utf8");
    const match = contents.match(KAT_INTERNAL_IMPORT_RE);
    assert.equal(
      match,
      null,
      `test/signers/index.ts must not import from ml-dsa-eth.kat-internal — matched: ${String(match?.[0])}`,
    );
  });

  it("AC-3-7: no file under test/bench/ imports from ml-dsa-eth.kat-internal", () => {
    const benchFiles = listTsFiles(BENCH_DIR);
    for (const file of benchFiles) {
      const contents = readFileSync(file, "utf8");
      const match = contents.match(KAT_INTERNAL_IMPORT_RE);
      assert.equal(
        match,
        null,
        `${path.relative(TEST_DIR, file)} must not import from ml-dsa-eth.kat-internal — matched: ${String(match?.[0])}`,
      );
    }
  });

  it("AC-3-8: ML-DSA-44 parameter constants match FIPS 204 Table 1/2", () => {
    assert.equal(K, 4, "K");
    assert.equal(L, 4, "L");
    assert.equal(D, 13, "D");
    assert.equal(GAMMA1, 131072, "GAMMA1 (2^17)");
    assert.equal(GAMMA2, 95232, "GAMMA2 (floor((Q-1)/88))");
    assert.equal(TAU, 39, "TAU");
    assert.equal(ETA, 2, "ETA");
    assert.equal(OMEGA, 80, "OMEGA");
    assert.equal(BETA, 78, "BETA (= TAU * ETA)");
  });

  it("AC-3-6: ml-dsa-eth.ts module header contains @delta-from-ml-dsa", () => {
    const contents = readFileSync(ML_DSA_ETH_FILE, "utf8");
    assert.ok(
      contents.includes("@delta-from-ml-dsa"),
      "ml-dsa-eth.ts missing @delta-from-ml-dsa JSDoc tag",
    );
  });

  it("AC-3-6: ml-dsa-eth.kat-internal.ts module header contains @delta-from-ml-dsa", () => {
    const contents = readFileSync(ML_DSA_ETH_KAT_FILE, "utf8");
    assert.ok(
      contents.includes("@delta-from-ml-dsa"),
      "ml-dsa-eth.kat-internal.ts missing @delta-from-ml-dsa JSDoc tag",
    );
  });

  it("AC-3-6: @delta-from-ml-dsa section enumerates all 5 deltas (both files)", () => {
    for (const file of [ML_DSA_ETH_FILE, ML_DSA_ETH_KAT_FILE]) {
      const contents = readFileSync(file, "utf8");
      for (const marker of [
        "XOF",
        "Fork scope",
        "pk-transform factory",
        "ctx",
        "Signature layout",
      ]) {
        assert.ok(
          contents.toLowerCase().includes(marker.toLowerCase()),
          `${path.basename(file)}: @delta-from-ml-dsa missing marker "${marker}"`,
        );
      }
    }
  });
});
