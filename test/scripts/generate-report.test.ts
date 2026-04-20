/**
 * Story 5-2 — generate-report unit tests.
 *
 * Pure rendering function `renderReport(results)` is exercised with
 * in-memory fixtures (no disk I/O). Covers AC-1 (table content), AC-2
 * (failed-scheme row preservation), and arithmetic-drift guard.
 *
 * Framework: node:test + node:assert/strict (A-001).
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { renderReport, type BenchResult } from "../../scripts/generate-report.ts";

const FIXED_TS = "2026-04-15T10:30:00.000Z";

function ok(
  scheme: BenchResult extends { scheme: infer S } ? S : never,
  totalGas: bigint,
  calldataGas: bigint,
  variance = 1e-4,
): BenchResult {
  return {
    scheme,
    status: "ok",
    runs: [totalGas, totalGas, totalGas],
    mean: totalGas,
    variance,
    totalGas,
    calldataGas,
    executionGas: totalGas - calldataGas,
  };
}

describe("renderReport", () => {
  it("AC-1: renders 5 ok rows with overhead, variance, calldata/execution split", () => {
    const results: BenchResult[] = [
      ok("ecdsa", 100_000n, 1_000n),
      ok("falcon", 4_000_000n, 14_000n),
      ok("mldsa", 8_000_000n, 38_000n),
      ok("mldsa-eth", 8_500_000n, 38_000n),
      ok("falcon-eth", 1_600_000n, 14_000n),
    ];
    const md = renderReport(results, FIXED_TS);

    assert.match(md, /^# PQC ERC-4337 Gas Comparison/);
    assert.match(md, /\| ecdsa \| ok \| 100000 \|/);
    assert.match(md, /\| falcon \| ok \| 4000000 \|/);
    assert.match(md, /\| mldsa \| ok \| 8000000 \|/);
    assert.match(md, /\| mldsa-eth \| ok \| 8500000 \|/);
    assert.match(md, /\| falcon-eth \| ok \| 1600000 \|/);
    // ECDSA gets em-dash overhead (self)
    assert.match(md, /\| ecdsa \| ok \|[^|]*\|[^|]*\|[^|]*\| — \|/);
    // Falcon overhead = (4_000_000 - 100_000)/100_000 = 39.0 → +3900.0%
    assert.match(md, /\+3900\.0%/);
    // ML-DSA overhead = (8_000_000 - 100_000)/100_000 = 79.0 → +7900.0%
    assert.match(md, /\+7900\.0%/);
    // ML-DSA-ETH overhead = (8_500_000 - 100_000)/100_000 = 84.0 → +8400.0%
    assert.match(md, /\+8400\.0%/);
    // Falcon-ETH overhead = (1_600_000 - 100_000)/100_000 = 15.0 → +1500.0%
    assert.match(md, /\+1500\.0%/);
    // Variance scientific form
    assert.match(md, /1\.00e-4/);
    // Story 2-4 AC-8 — pairwise delta section present
    assert.match(md, /ML-DSA-ETH ↔ Falcon-ETH pairwise delta/);
  });

  it("AC-2: failed scheme still emits a row with FAILED token + reason", () => {
    const results: BenchResult[] = [
      ok("ecdsa", 100_000n, 1_000n),
      { scheme: "falcon", status: "failed", reason: "AA23 reverted: SignatureMalformed" },
      ok("mldsa", 8_000_000n, 38_000n),
      ok("mldsa-eth", 8_500_000n, 38_000n),
      ok("falcon-eth", 1_600_000n, 14_000n),
    ];
    const md = renderReport(results, FIXED_TS);

    assert.match(md, /\| falcon \| FAILED \|/);
    assert.match(md, /FAILED: AA23 reverted: SignatureMalformed/);
    assert.match(md, /### Failure reasons/);
    assert.match(md, /\*\*falcon failure reason:\*\* AA23 reverted: SignatureMalformed/);
    // Other rows unaffected
    assert.match(md, /\| ecdsa \| ok \| 100000 \|/);
    assert.match(md, /\| mldsa \| ok \| 8000000 \|/);
    assert.match(md, /\| mldsa-eth \| ok \| 8500000 \|/);
    // ML-DSA overhead still computable from ECDSA baseline
    assert.match(md, /\+7900\.0%/);
  });

  it("AC-2 (ECDSA failed): every overhead cell becomes n/a + explanatory note", () => {
    const results: BenchResult[] = [
      { scheme: "ecdsa", status: "failed", reason: "RPC error" },
      ok("falcon", 4_000_000n, 14_000n),
      ok("mldsa", 8_000_000n, 38_000n),
      ok("mldsa-eth", 8_500_000n, 38_000n),
      ok("falcon-eth", 1_600_000n, 14_000n),
    ];
    const md = renderReport(results, FIXED_TS);

    assert.match(md, /ECDSA baseline run failed/);
    // Every row's overhead column is n/a. Regex pins to the row start and
    // uses longest-form-first alternation so `mldsa-eth` / `falcon-eth`
    // aren't shadowed by their shorter `mldsa` / `falcon` prefixes.
    const dataRows = md
      .split("\n")
      .filter((l) =>
        /^\| (ecdsa|falcon-eth|falcon|mldsa-eth|mldsa) \|/.test(l),
      );
    assert.equal(dataRows.length, 5);
    for (const row of dataRows) {
      assert.match(row, /\| n\/a \|/, `row missing n/a overhead: ${row}`);
    }
  });

  it("arithmetic drift: throws when totalGas != calldataGas + executionGas", () => {
    const broken: BenchResult = {
      scheme: "ecdsa",
      status: "ok",
      runs: [100n],
      mean: 100n,
      variance: 0,
      totalGas: 100n,
      calldataGas: 30n,
      executionGas: 50n,
    };
    const results: BenchResult[] = [
      broken,
      ok("falcon", 200n, 10n),
      ok("mldsa", 300n, 20n),
      ok("mldsa-eth", 400n, 30n),
      ok("falcon-eth", 500n, 40n),
    ];
    assert.throws(
      () => renderReport(results, FIXED_TS),
      /arithmetic drift in ecdsa/,
    );
  });

  it("input validation: rejects wrong record count", () => {
    assert.throws(
      () => renderReport([ok("ecdsa", 100n, 10n)], FIXED_TS),
      /expected 5 BenchResult records, got 1/,
    );
  });

  it("escapes pipe in reason so the table column count is preserved", () => {
    const results: BenchResult[] = [
      ok("ecdsa", 100_000n, 1_000n),
      {
        scheme: "falcon",
        status: "failed",
        reason: "AA23 reverted | inner data | more pipes",
      },
      ok("mldsa", 8_000_000n, 38_000n),
      ok("mldsa-eth", 8_500_000n, 38_000n),
      ok("falcon-eth", 1_600_000n, 14_000n),
    ];
    const md = renderReport(results, FIXED_TS);
    const failedRow = md
      .split("\n")
      .find((l) => /^\| falcon \| FAILED \|/.test(l));
    assert.ok(failedRow, "failed row should be present");
    // Count UNESCAPED pipes in the row — escaped `\|` must not count.
    const unescapedPipes = failedRow!.replace(/\\\|/g, "").split("|").length - 1;
    // Header row has 9 columns → 10 pipe characters.
    const header = md
      .split("\n")
      .find((l) => l.startsWith("| Scheme |"));
    const headerPipes = header!.split("|").length - 1;
    assert.equal(
      unescapedPipes,
      headerPipes,
      `failed row pipe count (${unescapedPipes}) must match header (${headerPipes})`,
    );
    // Footnote preserves the pipes as-is (raw reason — not in a table cell).
    assert.match(md, /AA23 reverted \| inner data \| more pipes/);
  });

  it("rounds percentages half-up to one decimal place", () => {
    // Falcon total = 100_000 + 1_385 = 101_385 → calldata% = 1.366… → 1.4%
    // Construct a record that targets boundary behavior.
    const results: BenchResult[] = [
      ok("ecdsa", 100_000n, 1_000n),
      ok("falcon", 101_385n, 1_385n), // calldataGas = 1385, exec = 100000
      ok("mldsa", 200_000n, 2_000n),
      ok("mldsa-eth", 210_000n, 2_100n),
      ok("falcon-eth", 105_000n, 1_500n),
    ];
    const md = renderReport(results, FIXED_TS);
    // 1385 / 101385 = 1.3661...% → rounds half-up to 1.4%
    assert.match(md, /1385 \(1\.4%\)/);
    // overhead falcon: (101385 - 100000)/100000 = 1.385% → +1.4%
    assert.match(md, /\+1\.4%/);
  });

  it("input validation: rejects missing scheme", () => {
    // Exactly SCHEMES.length records but missing "falcon" — must trigger
    // the missing-scheme check rather than the count check.
    const results: BenchResult[] = [
      ok("ecdsa", 100n, 10n),
      ok("ecdsa", 200n, 20n),
      ok("ecdsa", 300n, 30n),
      ok("ecdsa", 400n, 40n),
      ok("ecdsa", 500n, 50n),
    ];
    assert.throws(
      () => renderReport(results, FIXED_TS),
      /missing scheme in input: falcon/,
    );
  });
});
