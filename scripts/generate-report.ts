/**
 * Story 5-2 — Gas comparison report generator.
 *
 * Reads `test/bench/gas-data.json` (produced by Story 5-1) and writes
 * `docs/gas-report.md`: one row per scheme with absolute gas, calldata
 * vs execution split, ECDSA-baseline overhead %, and per-scheme
 * variance (C-012 transparency).
 *
 * Run via `npm run report` (Node 24 native TS strip — no transpiler).
 * Paths resolve via `import.meta.url` so `node scripts/generate-report.ts`
 * works from any CWD (preempts C-003).
 */

import { readFile, writeFile } from "node:fs/promises";

type Scheme = "ecdsa" | "falcon" | "mldsa";

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

const SCHEMES: readonly Scheme[] = ["ecdsa", "falcon", "mldsa"] as const;

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
  generatedAt: string = new Date().toISOString(),
): string {
  if (results.length !== 3) {
    throw new Error(`expected 3 BenchResult records, got ${results.length}`);
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
  lines.push("");
  return lines.join("\n");
}

async function main(): Promise<void> {
  const inputUrl = new URL("../test/bench/gas-data.json", import.meta.url);
  const outputUrl = new URL("../docs/gas-report.md", import.meta.url);

  const text = await readFile(inputUrl, { encoding: "utf8" });
  const raw = JSON.parse(text) as RawBenchResult[];
  const results = raw.map(hydrate);

  const md = renderReport(results);
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
