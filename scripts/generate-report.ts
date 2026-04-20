/**
 * Story 5-2 — Gas comparison report generator.
 *
 * Reads `test/bench/gas-data.json` (produced by Story 5-1, extended to
 * 4 schemes by Story 5 Task 6) and writes `docs/gas-report.md`: one row
 * per scheme with absolute gas, calldata vs execution split, ECDSA-
 * baseline overhead %, and per-scheme variance (C-012 transparency).
 *
 * AC-5-7 strict determinism (Story 5 Task 6): the `_Generated:` header
 * line is sourced from `gas-data.json.generatedAt` (written by the
 * bench test at `UPDATE_BENCH=1` invocation time), NOT from
 * `new Date().toISOString()` at render time. Two consecutive
 * `npm run report` runs on an unchanged `gas-data.json` produce a
 * byte-identical `docs/gas-report.md` — `git diff` is empty.
 *
 * Snapshot schema (Story 5 Task 6 one-time bump): the file now carries
 * `{ generatedAt: string, results: RawBenchResult[] }` instead of a
 * bare `RawBenchResult[]`. The bump is logged inline as a Rule 1
 * deviation — the loader change is committed atomically with the
 * bench-test write change, so no downstream consumer ever sees the
 * old shape.
 *
 * Run via `npm run report` (Node 24 native TS strip — no transpiler).
 * Paths resolve via `import.meta.url` so `node scripts/generate-report.ts`
 * works from any CWD (preempts C-003).
 */

import { readFile, writeFile } from "node:fs/promises";

type Scheme = "ecdsa" | "falcon" | "mldsa" | "mldsa-eth" | "falcon-eth";

export type BenchResult =
  | {
      scheme: Scheme;
      status: "ok";
      runs: bigint[];
      mean: bigint;
      variance: number;
      totalGas: bigint;
      calldataGas: bigint;
      executionGas: bigint;
    }
  | { scheme: Scheme; status: "failed"; reason: string };

type RawOk = {
  scheme: Scheme;
  status: "ok";
  runs: string[];
  mean: string;
  variance: number;
  totalGas: string;
  calldataGas: string;
  executionGas: string;
};
type RawFailed = { scheme: Scheme; status: "failed"; reason: string };
type RawBenchResult = RawOk | RawFailed;

const SCHEMES: readonly Scheme[] = [
  "ecdsa",
  "falcon",
  "mldsa",
  "mldsa-eth",
  "falcon-eth",
] as const;

/**
 * Top-level snapshot shape written by `test/bench/gas-benchmark.test.ts`
 * when invoked with `UPDATE_BENCH=1` (Story 5 Task 6 schema bump). The
 * `generatedAt` field anchors AC-5-7 strict determinism — the report
 * generator reads this string verbatim into the `_Generated:` header so
 * two consecutive render runs on an unchanged snapshot produce a
 * byte-identical report.
 */
type GasSnapshot = {
  generatedAt: string;
  results: RawBenchResult[];
};

export function hydrate(raw: RawBenchResult): BenchResult {
  if (raw.status === "failed") return raw;
  return {
    scheme: raw.scheme,
    status: "ok",
    runs: raw.runs.map((s) => BigInt(s)),
    mean: BigInt(raw.mean),
    variance: raw.variance,
    totalGas: BigInt(raw.totalGas),
    calldataGas: BigInt(raw.calldataGas),
    executionGas: BigInt(raw.executionGas),
  };
}

function fmtBpToPct(bp: bigint): string {
  // Convert basis points (×100 of percent) to one-decimal percent with
  // half-up rounding. bp/10 yields tenths-of-percent; rounding the units
  // digit before truncation gives proper half-up behavior.
  const tenths = (bp + 5n) / 10n;
  const wholePct = tenths / 10n;
  const fracDigit = tenths % 10n;
  return `${wholePct}.${fracDigit}%`;
}

function pct(part: bigint, whole: bigint): string {
  return fmtBpToPct((part * 10000n) / whole);
}

function overheadPct(scheme: bigint, baseline: bigint): string {
  const diff = scheme - baseline;
  const negative = diff < 0n;
  const abs = negative ? -diff : diff;
  return `${negative ? "-" : "+"}${fmtBpToPct((abs * 10000n) / baseline)}`;
}

/**
 * Story 2-4 AC-8 / AC-U-1 — render a labelled `ML-DSA-ETH ↔ Falcon-ETH
 * pairwise delta` section. Determinism: every number is read from the
 * snapshot passed in by `renderReport` (which itself reads from the
 * unchanged `gas-data.json`), so two consecutive `npm run report` runs on
 * an unchanged snapshot produce byte-identical output (AC-13).
 *
 * Returned lines are markdown; caller concatenates them into the report's
 * line buffer below the main table.
 */
function renderPairwiseDelta(
  mldsaEth: Extract<BenchResult, { status: "ok" }> | undefined,
  falconEth: Extract<BenchResult, { status: "ok" }> | undefined,
): string[] {
  const lines: string[] = [];
  lines.push("## ML-DSA-ETH ↔ Falcon-ETH pairwise delta");
  lines.push("");
  if (mldsaEth === undefined || falconEth === undefined) {
    lines.push(
      "> ⚠ Pairwise delta unavailable — one or both of `mldsa-eth` / `falcon-eth` failed in the bench run.",
    );
    return lines;
  }
  lines.push("| Metric | ML-DSA-ETH | Falcon-ETH | Delta |");
  lines.push("|---|---:|---:|---:|");
  const gasDeltaAbs =
    mldsaEth.totalGas > falconEth.totalGas
      ? mldsaEth.totalGas - falconEth.totalGas
      : falconEth.totalGas - mldsaEth.totalGas;
  const gasDeltaSign =
    falconEth.totalGas >= mldsaEth.totalGas ? "+" : "-";
  const gasDeltaPct = fmtBpToPct((gasDeltaAbs * 10000n) / mldsaEth.totalGas);
  lines.push(
    `| Verify gas (first run) | ${mldsaEth.totalGas} | ${falconEth.totalGas} | ${gasDeltaSign}${gasDeltaPct} |`,
  );
  const cdDeltaAbs =
    mldsaEth.calldataGas > falconEth.calldataGas
      ? mldsaEth.calldataGas - falconEth.calldataGas
      : falconEth.calldataGas - mldsaEth.calldataGas;
  const cdDeltaSign =
    falconEth.calldataGas >= mldsaEth.calldataGas ? "+" : "-";
  lines.push(
    `| Calldata gas | ${mldsaEth.calldataGas} | ${falconEth.calldataGas} | ${cdDeltaSign}${cdDeltaAbs} |`,
  );
  return lines;
}

function escapeMarkdownCell(s: string): string {
  // Pipe and backslash are GFM table cell delimiters / escapes. A `|`
  // inside a reason string breaks the column count silently.
  return s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}

function fmtVariance(v: number): string {
  return v.toExponential(2);
}

function truncReason(reason: string, max = 60): string {
  const oneLine = reason.replace(/\s+/g, " ").trim();
  if (oneLine.length <= max) return oneLine;
  return `${oneLine.slice(0, max - 1)}…`;
}

export function renderReport(
  results: BenchResult[],
  generatedAt: string,
): string {
  if (results.length !== SCHEMES.length) {
    throw new Error(
      `expected ${SCHEMES.length} BenchResult records, got ${results.length}`,
    );
  }
  const seen = new Set(results.map((r) => r.scheme));
  for (const s of SCHEMES) {
    if (!seen.has(s)) throw new Error(`missing scheme in input: ${s}`);
  }
  for (const r of results) {
    if (r.status !== "ok") continue;
    if (r.totalGas !== r.calldataGas + r.executionGas) {
      throw new Error(
        `arithmetic drift in ${r.scheme}: totalGas=${r.totalGas} != calldataGas(${r.calldataGas}) + executionGas(${r.executionGas})`,
      );
    }
  }

  const byScheme = new Map(results.map((r) => [r.scheme, r]));
  const ecdsa = byScheme.get("ecdsa");
  if (ecdsa === undefined) {
    throw new Error("missing scheme in input: ecdsa");
  }
  const baselineAvailable = ecdsa.status === "ok";
  const baselineTotal = ecdsa.status === "ok" ? ecdsa.totalGas : null;

  const lines: string[] = [];
  lines.push("# PQC ERC-4337 Gas Comparison");
  lines.push("");
  lines.push(`_Generated: ${generatedAt}_`);
  lines.push(
    "_Source: `test/bench/gas-data.json` (produced by Story 5-1 benchmark)._",
  );
  lines.push("");

  if (!baselineAvailable) {
    lines.push(
      "> ⚠ ECDSA baseline run failed — overhead column is `n/a` for every row.",
    );
    lines.push("");
  }

  lines.push(
    "| Scheme | Status | Total gas | Calldata (gas, %) | Execution (gas, %) | Overhead vs ECDSA | Variance | Notes |",
  );
  lines.push("|---|---|---:|---:|---:|---:|---:|---|");

  const footnotes: string[] = [];
  for (const scheme of SCHEMES) {
    const r = byScheme.get(scheme);
    if (r === undefined) continue;
    if (r.status === "failed") {
      const note = `FAILED: ${escapeMarkdownCell(truncReason(r.reason))}`;
      lines.push(`| ${scheme} | FAILED | — | — | — | n/a | — | ${note} |`);
      footnotes.push(
        `- **${scheme} failure reason:** ${r.reason.replace(/\s+/g, " ").trim()}`,
      );
      continue;
    }
    const calldataCell = `${r.calldataGas} (${pct(r.calldataGas, r.totalGas)})`;
    const executionCell = `${r.executionGas} (${pct(r.executionGas, r.totalGas)})`;
    let overheadCell: string;
    if (!baselineAvailable) {
      overheadCell = "n/a";
    } else if (scheme === "ecdsa") {
      overheadCell = "—";
    } else if (baselineTotal !== null) {
      overheadCell = overheadPct(r.totalGas, baselineTotal);
    } else {
      overheadCell = "n/a";
    }
    lines.push(
      `| ${scheme} | ok | ${r.totalGas} | ${calldataCell} | ${executionCell} | ${overheadCell} | ${fmtVariance(r.variance)} |  |`,
    );
  }

  lines.push("");
  lines.push("## Notes");
  lines.push("");
  lines.push(
    "- **Variance** is `(max − min) / mean` across 3 measured runs after 2 warm-up rounds (Story 5-1 harness).",
  );
  lines.push(
    "- **C-012:** PQC variance routinely exceeds the original NFR-3 target of `<0.01`. The benchmark gates ECDSA at `<0.01` and PQC at `<0.10` while the EIP-3529 refund-cap timing hypothesis is investigated. Cross-scheme cost ranking and calldata/execution split are unaffected.",
  );
  lines.push(
    "- **Overhead** is computed as `(scheme.totalGas − ecdsa.totalGas) / ecdsa.totalGas` from the first measured run of each scheme.",
  );
  lines.push(
    "- **Calldata gas** uses the EIP-2028 formula (16 gas per non-zero byte, 4 gas per zero byte) over the per-scheme signature bytes only; remaining gas is bucketed as execution.",
  );
  if (footnotes.length > 0) {
    lines.push("");
    lines.push("### Failure reasons");
    lines.push("");
    lines.push(...footnotes);
  }

  // Story 2-4 AC-8 / AC-U-1 — pairwise delta section at the end of the
  // report. Numbers flow from the snapshot (already hydrated into
  // `results`), so the section is deterministic under AC-13.
  lines.push("");
  const mldsaEthResult = byScheme.get("mldsa-eth");
  const falconEthResult = byScheme.get("falcon-eth");
  const mldsaEthOk =
    mldsaEthResult !== undefined && mldsaEthResult.status === "ok"
      ? mldsaEthResult
      : undefined;
  const falconEthOk =
    falconEthResult !== undefined && falconEthResult.status === "ok"
      ? falconEthResult
      : undefined;
  lines.push(...renderPairwiseDelta(mldsaEthOk, falconEthOk));

  lines.push("");
  return lines.join("\n");
}

async function main(): Promise<void> {
  const inputUrl = new URL("../test/bench/gas-data.json", import.meta.url);
  const outputUrl = new URL("../docs/gas-report.md", import.meta.url);

  const text = await readFile(inputUrl, { encoding: "utf8" });
  const snapshot = JSON.parse(text) as GasSnapshot;
  if (
    typeof snapshot.generatedAt !== "string" ||
    !Array.isArray(snapshot.results)
  ) {
    throw new Error(
      "gas-data.json schema: expected { generatedAt: string, results: [...] } (Story 5 Task 6 bump)",
    );
  }
  const results = snapshot.results.map(hydrate);

  // AC-5-7 strict determinism: timestamp flows from the snapshot, not
  // from `new Date()` at render time. Two consecutive `npm run report`
  // invocations against an unchanged snapshot produce a byte-identical
  // report.
  const md = renderReport(results, snapshot.generatedAt);
  await writeFile(outputUrl, md, { encoding: "utf8" });
  process.stdout.write(`wrote ${outputUrl.pathname}\n`);
}

const argv1 = process.argv[1];
const isMain =
  argv1 !== undefined &&
  import.meta.url === new URL(argv1, "file://").href;

if (isMain) {
  try {
    await main();
  } catch (err) {
    process.stderr.write(
      `generate-report failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exitCode = 1;
  }
}
