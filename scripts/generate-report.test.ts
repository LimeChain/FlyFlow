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

import { renderReport, type BenchResult } from "./generate-report.ts";

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
  it("AC-1: renders 3 ok rows with overhead, variance, calldata/execution split", () => {
    const results: BenchResult[] = [
      ok("ecdsa", 100_000n, 1_000n),
      ok("falcon", 4_000_000n, 14_000n),
      ok("mldsa", 8_000_000n, 38_000n),
    ];
    const md = renderReport(results, FIXED_TS);

    assert.match(md, /^# PQC ERC-4337 Gas Comparison/);
    assert.match(md, /\| ecdsa \| ok \| 100000 \|/);
    assert.match(md, /\| falcon \| ok \| 4000000 \|/);
    assert.match(md, /\| mldsa \| ok \| 8000000 \|/);
    // ECDSA gets em-dash overhead (self)
    assert.match(md, /\| ecdsa \| ok \|[^|]*\|[^|]*\|[^|]*\| — \|/);
    // Falcon overhead = (4_000_000 - 100_000)/100_000 = 39.0 → +3900.0%
    assert.match(md, /\+3900\.0%/);
    // ML-DSA overhead = (8_000_000 - 100_000)/100_000 = 79.0 → +7900.0%
    assert.match(md, /\+7900\.0%/);
    // Variance scientific form
    assert.match(md, /1\.00e-4/);
  });

  it("AC-2: failed scheme still emits a row with FAILED token + reason", () => {
    const results: BenchResult[] = [
      ok("ecdsa", 100_000n, 1_000n),
      { scheme: "falcon", status: "failed", reason: "AA23 reverted: SignatureMalformed" },
      ok("mldsa", 8_000_000n, 38_000n),
    ];
    const md = renderReport(results, FIXED_TS);

    assert.match(md, /\| falcon \| FAILED \|/);
    assert.match(md, /FAILED: AA23 reverted: SignatureMalformed/);
    assert.match(md, /### Failure reasons/);
    assert.match(md, /\*\*falcon failure reason:\*\* AA23 reverted: SignatureMalformed/);
    // Other rows unaffected
    assert.match(md, /\| ecdsa \| ok \| 100000 \|/);
    assert.match(md, /\| mldsa \| ok \| 8000000 \|/);
    // ML-DSA overhead still computable from ECDSA baseline
    assert.match(md, /\+7900\.0%/);
  });

  it("AC-2 (ECDSA failed): every overhead cell becomes n/a + explanatory note", () => {
    const results: BenchResult[] = [
      { scheme: "ecdsa", status: "failed", reason: "RPC error" },
      ok("falcon", 4_000_000n, 14_000n),
      ok("mldsa", 8_000_000n, 38_000n),
    ];
    const md = renderReport(results, FIXED_TS);

    assert.match(md, /ECDSA baseline run failed/);
    // Every row's overhead column is n/a
    const dataRows = md.split("\n").filter((l) => /^\| (ecdsa|falcon|mldsa) \|/.test(l));
    assert.equal(dataRows.length, 3);
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
    ];
    assert.throws(
      () => renderReport(results, FIXED_TS),
      /arithmetic drift in ecdsa/,
    );
  });

  it("input validation: rejects wrong record count", () => {
    assert.throws(
      () => renderReport([ok("ecdsa", 100n, 10n)], FIXED_TS),
      /expected 3 BenchResult records, got 1/,
    );
  });

  it("input validation: rejects missing scheme", () => {
    const results: BenchResult[] = [
      ok("ecdsa", 100n, 10n),
      ok("ecdsa", 200n, 20n),
      ok("ecdsa", 300n, 30n),
    ];
    assert.throws(
      () => renderReport(results, FIXED_TS),
      /missing scheme in input: falcon/,
    );
  });
});
