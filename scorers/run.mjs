#!/usr/bin/env node
// CLI entry point.
//
//   node scorers/run.mjs --adapter <path-or-builtin-name> [--corpus <name|all>] [--json]
//                        [--misses] [--fps] [--timeout-ms N] [--fail-under N]
//
// Zero setup: `npm run score -- --adapter keyword` runs the whole benchmark with no install step,
// no config and no external product.
import { pathToFileURL } from "node:url";
import { loadAdapter, AdapterError, BUILTIN_ADAPTERS } from "./adapter.mjs";
import { loadCorpus, corpusList, CORPORA, ALIASES } from "./corpus.mjs";
import { evalSample, score, aggregate } from "./score.mjs";
import { renderReport, renderJson } from "./report.mjs";

const HELP = `agentic-security-benchmark — score a security product against the AMTSO agentic attack vectors.

Usage:
  node scorers/run.mjs --adapter <path-or-builtin> [options]

Options:
  --adapter <spec>     built-in name (${Object.keys(BUILTIN_ADAPTERS).join(", ")}) or a path to your own ES module
  --corpus <name|all>  default "all"; comma-separated list accepted
  --json               emit the machine-readable result object (the shape results/ files hold)
  --misses             list every missed attack id
  --fps                list every false positive
  --timeout-ms <n>     per-scan time budget; a scan that blows it is INCONCLUSIVE, never a miss
  --fail-under <n>     exit 1 when overall recall is below n percent
  --corpus-dir <path>  read corpora from somewhere other than ./corpora
  --help

Corpora: ${Object.keys(CORPORA).join(", ")}
Aliases: ${Object.keys(ALIASES).join(", ")}

The adapter contract is documented in scorers/adapter.mjs and scorers/README.md. A product implements
four optional scan methods and returns findings; the harness never reaches past that interface.
`;

export function parseArgs(argv) {
  const has = (f) => argv.includes(f);
  const val = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  return {
    help: has("--help") || has("-h"),
    adapter: val("--adapter"),
    corpus: val("--corpus") || "all",
    corpusDir: val("--corpus-dir") || null,
    json: has("--json"),
    misses: has("--misses"),
    fps: has("--fps"),
    timeoutMs: val("--timeout-ms") !== undefined ? Number(val("--timeout-ms")) : null,
    failUnder: val("--fail-under") !== undefined ? Number(val("--fail-under")) : null
  };
}

export async function run(args) {
  let adapter = await loadAdapter(args.adapter);
  if (typeof adapter.impl.init === "function") {
    await adapter.impl.init({ timeoutMs: args.timeoutMs ?? null });
    // init() is where an adapter that wraps an external checkout learns which VERSION it actually
    // loaded, so re-read it: the version in the report has to be the one that produced the numbers.
    if (typeof adapter.impl.version === "string" && adapter.impl.version && adapter.impl.version !== adapter.version) {
      adapter = Object.freeze({ ...adapter, version: adapter.impl.version });
    }
  }

  const names = corpusList(args.corpus);
  const corpora = [];
  try {
    for (const name of names) {
      const corpus = loadCorpus(name, { dir: args.corpusDir });
      const rows = [];
      for (const s of corpus.samples) rows.push(await evalSample(adapter, s, { timeoutMs: args.timeoutMs }));
      corpora.push({ name: corpus.name, vector: corpus.vector, label: corpus.label, rows, score: score(rows) });
    }
  } finally {
    if (typeof adapter.impl.close === "function") await adapter.impl.close();
  }

  return {
    generatedAt: new Date().toISOString(),
    adapter,
    options: { corpus: args.corpus, timeoutMs: args.timeoutMs ?? null },
    corpora,
    overall: aggregate(corpora.map((c) => c.score))
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.adapter) {
    process.stdout.write(HELP);
    process.exit(args.adapter ? 0 : (args.help ? 0 : 2));
  }

  let result;
  try {
    result = await run(args);
  } catch (e) {
    if (e instanceof AdapterError) { process.stderr.write(`\nadapter error: ${e.message}\n\n`); process.exit(2); }
    process.stderr.write(`\n${e && e.message ? e.message : e}\n\n`);
    process.exit(2);
  }

  if (args.json) process.stdout.write(JSON.stringify(renderJson(result), null, 2) + "\n");
  else process.stdout.write(renderReport(result, { misses: args.misses, fps: args.fps }));

  if (args.failUnder != null && result.overall.recall * 100 < args.failUnder) {
    process.stderr.write(`overall recall ${(result.overall.recall * 100).toFixed(1)}% below --fail-under ${args.failUnder}%\n`);
    process.exit(1);
  }
  process.exit(0);
}

// pathToFileURL, not a template literal: a repo path can contain spaces, which a raw `file://${path}`
// leaves unescaped, so it never equals import.meta.url and the script would exit silently.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
