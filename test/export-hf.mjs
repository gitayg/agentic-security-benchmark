// Hugging Face export gate — scripts/export-hf.mjs.
//
//   node --test            (runs with the corpus validator)
//
// Asserts that the export is the published corpora and nothing else: row counts per split equal the
// source files counted independently of the scorer's loader, every exported row carries its source
// sample verbatim, no file outside the seven published corpora is written, a locked-split filename
// is refused, and every column keeps one type across the whole export (the Hub infers the schema).
//
// Runs against a temp directory, never dist/hf, and in non-strict mode: strict mode compares
// corpora/ to origin/main, which a corpus PR under review legitimately differs from.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, sep } from "node:path";
import { buildExport, assertPublishedOnly, EXPORT, PUBLISHED_CORPORA } from "../scripts/export-hf.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS_DIR = join(ROOT, "corpora");

// The test's own copy of the published set, so a change to the script's allowlist cannot pass
// silently.
const PUBLISHED = [
  "benign-corpus-v2.json",
  "benign-web-content-tune.json",
  "heldout-v2-tune.json",
  "vector2-indirect-content.json",
  "vector3-supply-chain.json",
  "vector4-outbound-action.json",
  "vector5-memory-crossagent.json"
];

const OUT = mkdtempSync(join(tmpdir(), "asb-hf-"));
process.on("exit", () => rmSync(OUT, { recursive: true, force: true }));

let result, buildError;
try {
  result = buildExport({ outDir: OUT });
} catch (e) {
  buildError = e;
}

function listFiles(root, dir = root) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...listFiles(root, p));
    else out.push(relative(root, p).split(sep).join("/"));
  }
  return out;
}

const readJsonl = (rel) => readFileSync(join(OUT, rel), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

// Source samples counted the way test/validate-corpora.mjs counts them, not through scorers/corpus.mjs.
function sourceSamples(file) {
  const j = JSON.parse(readFileSync(join(CORPUS_DIR, file), "utf8"));
  const out = [];
  for (const key of ["attacks", "benign", "samples"]) {
    for (const s of j[key] || []) {
      const attack = s.shouldDetect === true || (s.shouldDetect === undefined && key === "attacks");
      out.push({ s, label: attack ? "attack" : "benign" });
    }
  }
  return out;
}

test("the export builds from the published corpora", () => {
  assert.equal(buildError, undefined, `buildExport threw: ${buildError?.message}`);
});

test("the export list is exactly the published corpora", () => {
  assert.deepEqual([...EXPORT].sort(), PUBLISHED);
  assert.deepEqual([...PUBLISHED_CORPORA].sort(), PUBLISHED);
  assert.deepEqual(readdirSync(CORPUS_DIR).filter((f) => f.endsWith(".json")).sort(), PUBLISHED,
    "corpora/ holds a file the export does not know about — widen PUBLISHED_CORPORA deliberately or remove it");
});

test("a locked or unpublished file in the export list is refused", () => {
  for (const extra of ["heldout-v2-test.json", "benign-web-content-test-split.json", "locked/anything.json", "corpus.json"]) {
    assert.throws(() => assertPublishedOnly([...EXPORT, extra]), /not a published corpus|locked/,
      `assertPublishedOnly accepted ${extra}`);
  }
  assert.throws(() => assertPublishedOnly(EXPORT.slice(1)), /missing from the export list/);
});

test("only published corpora, README, LICENSE and NOTICE are written", { skip: !!buildError }, () => {
  const allowed = new Set(["README.md", "LICENSE", "NOTICE"]);
  for (const f of PUBLISHED) for (const split of ["attack", "benign"]) allowed.add(`data/${f.replace(/\.json$/, "")}/${split}.jsonl`);
  const written = listFiles(OUT);
  const stray = written.filter((f) => !allowed.has(f));
  assert.deepEqual(stray, [], `files outside the published set were exported: ${stray.join(", ")}`);
});

test("row counts per split equal the source corpora", { skip: !!buildError }, () => {
  let total = 0;
  for (const f of PUBLISHED) {
    const name = f.replace(/\.json$/, "");
    const src = sourceSamples(f);
    for (const split of ["attack", "benign"]) {
      const want = src.filter((x) => x.label === split).length;
      const rel = `data/${name}/${split}.jsonl`;
      const got = listFiles(OUT).includes(rel) ? readJsonl(rel).length : 0;
      assert.equal(got, want, `${rel}: exported ${got} rows, ${f} holds ${want} ${split} samples`);
      assert.equal(result.counts[name][split], want, `${name}.${split}: reported count ${result.counts[name][split]} != ${want}`);
      total += got;
    }
    assert.equal(src.length, result.counts[name].attack + result.counts[name].benign);
  }
  assert.equal(total, PUBLISHED.reduce((n, f) => n + sourceSamples(f).length, 0));
});

test("every exported row carries its source sample verbatim, with the source's label", { skip: !!buildError }, () => {
  const bySourceId = new Map();
  for (const f of PUBLISHED) for (const x of sourceSamples(f)) bySourceId.set(x.s.id, x);
  const seen = new Set();
  for (const rel of listFiles(OUT).filter((f) => f.endsWith(".jsonl"))) {
    for (const row of readJsonl(rel)) {
      const src = bySourceId.get(row.id);
      assert.ok(src, `${rel}: id ${row.id} is in no published corpus`);
      assert.ok(!seen.has(row.id), `${rel}: id ${row.id} exported twice`);
      seen.add(row.id);
      assert.deepEqual(JSON.parse(row.source), src.s, `${row.id}: source column differs from the corpus`);
      assert.equal(row.label, src.label, `${row.id}: exported as ${row.label}, source says ${src.label}`);
      assert.ok(rel.endsWith(`/${row.label}.jsonl`), `${row.id}: ${row.label} row filed in ${rel}`);
    }
  }
  assert.equal(seen.size, bySourceId.size, "some published samples were not exported");
});

test("every column has one non-null type across the whole export", { skip: !!buildError }, () => {
  const kind = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);
  const shape = (row) => Object.fromEntries(Object.entries(row).map(([k, v]) =>
    [k, kind(v) === "object" ? shape(v) : kind(v)]));
  let first = null, firstAt = null;
  for (const rel of listFiles(OUT).filter((f) => f.endsWith(".jsonl")).sort()) {
    for (const row of readJsonl(rel)) {
      const s = shape(row);
      assert.ok(!JSON.stringify(s).includes('"null"') && !JSON.stringify(s).includes('"array"'),
        `${rel}:${row.id}: null or list column ${JSON.stringify(s)}`);
      if (!first) { first = s; firstAt = `${rel}:${row.id}`; continue; }
      assert.deepEqual(s, first, `${rel}:${row.id}: schema differs from ${firstAt}`);
    }
  }
});

test("the dataset card's configs point only at exported files", { skip: !!buildError }, () => {
  const card = readFileSync(join(OUT, "README.md"), "utf8");
  const yaml = card.split("\n---\n")[0];
  assert.match(yaml, /^---\nlicense: apache-2\.0\n/);
  const written = new Set(listFiles(OUT));
  const paths = [...yaml.matchAll(/path: "([^"]+)"/g)].map((m) => m[1]);
  assert.ok(paths.length > 0, "no data_files paths in the card");
  for (const p of paths) {
    const re = new RegExp("^" + p.replace(/[.]/g, "\\.").replace(/\*/g, "[^/]+") + "$");
    assert.ok([...written].some((f) => re.test(f)), `card config path ${p} matches no exported file`);
  }
  for (const f of written) {
    if (!f.endsWith(".jsonl")) continue;
    assert.ok(paths.includes(f), `${f} is exported but no config names it`);
  }
});
