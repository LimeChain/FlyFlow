/**
 * README runbook + attribution assertions (Story 2-4 Task T7; AC-12, FR-20).
 *
 * Guards against the NFR-5 gas-cap runbook and FR-20 attribution drifting
 * out of README.md. These are documentation-discipline tests, not
 * behavioral tests.
 *
 * Framework: node:test + node:assert/strict (project convention — matches
 * `test/signers/naming.test.ts` pattern). Pure string-assertion; no
 * Hardhat / viem / filesystem walk.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";

const README = readFileSync(
  path.resolve(import.meta.dirname, "../../README.md"),
  "utf8",
);

describe("README runbook + attribution (Story 2-4 T7)", () => {
  it("AC-12: contains 'OOG during validation' runbook entry", () => {
    assert.ok(
      /OOG during validation/i.test(README),
      "README.md missing the 'OOG during validation' runbook heading",
    );
  });

  it("AC-12: runbook references NFR-5 gas cap (NFR-5 or 2^24 or 16,777,216)", () => {
    const nfr5 = /NFR-5/.test(README);
    const twoPow24 = /2\^24/.test(README);
    const numeric = /16[,_]?777[,_]?216/.test(README);
    assert.ok(
      nfr5 || twoPow24 || numeric,
      "README.md runbook missing NFR-5 gas-cap reference (expected one of: 'NFR-5', '2^24', '16,777,216')",
    );
  });

  it("FR-20: Falcon-512 + ETH-variant attribution present", () => {
    assert.ok(
      /Falcon-512/i.test(README),
      "README.md missing 'Falcon-512' mention",
    );
    // ETHFALCON (the ZKNox project) satisfies the ETH-variant attribution
    // requirement; the ZKNOX_ethfalcon contract name is also accepted.
    assert.ok(
      /ETHFALCON|ZKNOX_ethfalcon|ETH-variant/i.test(README),
      "README.md missing ETH-variant attribution (expected ETHFALCON or ZKNOX_ethfalcon or ETH-variant)",
    );
  });

  it("FR-20 + AC-11: ETHDilithium attribution regression (not removed by T7 edits)", () => {
    assert.ok(
      /ETHDILITHIUM|ZKNOX_ethdilithium/i.test(README),
      "README.md missing ETHDILITHIUM attribution — T7 edit may have accidentally clobbered prior attribution",
    );
  });
});
