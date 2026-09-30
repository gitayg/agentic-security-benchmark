// Hugging Face dataset export. Builds dist/hf/ — JSONL data files plus a dataset card — from the
// PUBLISHED corpora in corpora/, and nothing else.
//
//   node scripts/export-hf.mjs              # strict: corpora/ must match origin/main exactly
//   node scripts/export-hf.mjs --out <dir>
//
// Zero dependencies, like the rest of the repository. Uploading is not done here; see
// HUGGINGFACE.md for the owner's steps.
//
// THE HARD RULE: a locked held-out split is never exported. The export list is checked against a
// frozen allowlist of the seven published corpus files before a single file is opened, against the
// same locked-split filename patterns .gitignore refuses to commit, and every loaded file is checked
// for the `split: "test"` rows and lock-shaped top-level keys that test/validate-corpora.mjs rejects.
// Any failure throws; nothing is written for a list that fails.
//
// SCHEMA STABILITY. Every row carries every column, and no column is ever null. This is a
// precaution, not a measured failure: when no features are declared, the `datasets` JSON loader
// infers column types per file, and a column that is entirely null (or an all-empty list) in one
// file is typed null / list<null>, which a later file's strings cannot be cast to. So an absent
// string is "", an absent flag is false, and an absent integer is 0 (AMTSO vectors are 1-6, so 0
// cannot be mistaken for one). There is no list column: structured payloads (turns, actions,
// steps, events) travel as one JSON string in `payload`. The verbatim sample is always kept in
// `source`, so no absent-vs-empty distinction is lost.
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, resolve, sep } from "node:path";
import { CORPORA, ALL_CORPORA, CORPUS_DIR, loadCorpus } from "../scorers/corpus.mjs";
import { renderCard } from "./hf-card.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// The seven files published in the GitHub repository. This is the export script's own copy on
// purpose: if the scorer registry grows a corpus, the export must be widened deliberately here,
// not inherited silently.
export const PUBLISHED_CORPORA = Object.freeze([
  "vector2-indirect-content.json",
  "vector3-supply-chain.json",
  "vector4-outbound-action.json",
  "vector5-memory-crossagent.json",
  "heldout-v2-tune.json",
  "benign-corpus-v2.json",
  "benign-web-content-tune.json"
]);

// Filename shapes that .gitignore marks as locked held-out splits.
const LOCKED_SHAPES = [/heldout.*-test\.json$/i, /test-split.*\.json$/i, /(^|[\\/])locked[\\/]/i];

// The export list. Derived from the scorer registry, then checked against PUBLISHED_CORPORA.
export const EXPORT = Object.freeze(ALL_CORPORA.map((name) => CORPORA[name].file));

const FILE_TO_CORPUS = Object.fromEntries(Object.entries(CORPORA).map(([name, c]) => [c.file, name]));
const PAYLOAD_KEYS = ["turns", "action", "actions", "consumeAction", "steps", "consumeStep", "events"];

function git(args) {
  const r = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  return { ok: r.status === 0, out: (r.stdout || "").trim(), err: (r.stderr || "").trim() };
}

// Throws unless `files` is exactly the published set and every file is free of locked-split markers.
// `strict` additionally requires every file to be tracked and byte-identical to origin/main.
export function assertPublishedOnly(files, { corpusDir = CORPUS_DIR, strict = false } = {}) {
  const published = new Set(PUBLISHED_CORPORA);
  for (const f of files) {
    if (!published.has(f)) {
      throw new Error(`export-hf: ${JSON.stringify(f)} is not a published corpus — only ${PUBLISHED_CORPORA.join(", ")} may be exported`);
    }
    for (const re of LOCKED_SHAPES) {
      if (re.test(f)) throw new Error(`export-hf: ${JSON.stringify(f)} has a locked held-out split's filename shape (${re})`);
    }
  }
  const missing = PUBLISHED_CORPORA.filter((f) => !files.includes(f));
  if (missing.length) throw new Error(`export-hf: published corpora missing from the export list: ${missing.join(", ")}`);
  if (new Set(files).size !== files.length) throw new Error("export-hf: the export list names a file twice");

  for (const f of files) {
    const j = JSON.parse(readFileSync(join(corpusDir, f), "utf8"));
    const lockish = Object.keys(j).filter((k) => /lock/i.test(k));
    if (lockish.length) throw new Error(`export-hf: ${f} has lock-shaped top-level key(s) ${lockish.join(", ")}`);
    for (const key of ["attacks", "benign", "samples"]) {
      for (const s of j[key] || []) {
        if (s.split === "test") throw new Error(`export-hf: ${f}:${s.id} carries split:"test" — a locked half must never be exported`);
      }
    }
  }

  if (strict) {
    if (resolve(corpusDir) !== resolve(CORPUS_DIR)) throw new Error("export-hf: strict mode exports only the repository's own corpora/");
    for (const f of files) {
      const t = git(["ls-files", "--error-unmatch", "--", `corpora/${f}`]);
      if (!t.ok) throw new Error(`export-hf: corpora/${f} is not tracked by git — it has never been published`);
    }
    const ref = git(["rev-parse", "--verify", "--quiet", "origin/main"]);
    if (!ref.ok) throw new Error("export-hf: origin/main not found — run `git fetch origin` so the export can be compared to what GitHub publishes");
    const diff = git(["diff", "--name-only", "origin/main", "--", ...files.map((f) => `corpora/${f}`)]);
    if (!diff.ok) throw new Error(`export-hf: git diff failed: ${diff.err}`);
    if (diff.out) throw new Error(`export-hf: these corpora differ from origin/main, so they are not what GitHub publishes:\n  ${diff.out.split("\n").join("\n  ")}`);
  }
}

function toRow(s, n) {
  const payload = {};
  for (const k of PAYLOAD_KEYS) if (s[k] !== undefined) payload[k] = s[k];
  const a = s.amtso || {};
  return {
    id: n.id,
    corpus: n.corpus,
    label: n.shouldDetect ? "attack" : "benign",
    vector: n.vector ?? 0,
    family: s.family ?? "",
    subTechnique: s.subTechnique ?? "",
    category: s.category ?? "",
    channel: s.channel ?? "",
    axis: s.axis ?? "",
    stage: n.stage,
    harness: n.harness,
    text: typeof s.text === "string" ? s.text : "",
    payload: Object.keys(payload).length ? JSON.stringify(payload) : "",
    validity: s.validity ?? "",
    hard_negative: s.hard_negative === true,
    twin_of: s.twin_of ?? "",
    ambiguous: s.ambiguous === true,
    amtso: {
      attackVector: a.attackVector ?? 0,
      targetOfProtection: a.targetOfProtection ?? "",
      harm: a.harm ?? "",
      requiredCapability: a.requiredCapability ?? ""
    },
    source: JSON.stringify(s)
  };
}

// Rows for one corpus file, in source order, split by ground truth. Labels come from the scorer's
// own loader, so the export and the harness can never disagree about which rows are attacks.
export function corpusRows(file, corpusDir = CORPUS_DIR) {
  const name = FILE_TO_CORPUS[file];
  const cfg = CORPORA[name];
  const raw = JSON.parse(readFileSync(join(corpusDir, file), "utf8"));
  const rawSamples = cfg.layout === "benign-only" ? raw[cfg.benignKey] || [] : [...(raw.attacks || []), ...(raw.benign || [])];
  const { samples } = loadCorpus(name, { dir: corpusDir });
  if (samples.length !== rawSamples.length) throw new Error(`export-hf: ${file}: loader returned ${samples.length} samples, file holds ${rawSamples.length}`);
  const out = { attack: [], benign: [] };
  samples.forEach((n, i) => {
    if (String(rawSamples[i].id) !== n.id) throw new Error(`export-hf: ${file}: sample order diverged at ${i}`);
    const row = toRow(rawSamples[i], n);
    out[row.label].push(row);
  });
  return { name, cfg, raw, rows: out };
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

export function buildExport({ outDir, corpusDir = CORPUS_DIR, files = EXPORT, strict = false } = {}) {
  assertPublishedOnly(files, { corpusDir, strict });

  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const head = git(["rev-parse", "HEAD"]);
  const corpora = files.map((f) => corpusRows(f, corpusDir));

  const ids = new Set();
  for (const c of corpora) for (const r of [...c.rows.attack, ...c.rows.benign]) {
    if (ids.has(r.id)) throw new Error(`export-hf: duplicate id ${r.id}`);
    ids.add(r.id);
  }

  rmSync(outDir, { recursive: true, force: true });
  const expected = new Set(["README.md", "LICENSE", "NOTICE"]);
  const counts = {};
  for (const c of corpora) {
    counts[c.name] = { attack: c.rows.attack.length, benign: c.rows.benign.length };
    mkdirSync(join(outDir, "data", c.name), { recursive: true });
    for (const split of ["attack", "benign"]) {
      if (!c.rows[split].length) continue;
      const rel = `data/${c.name}/${split}.jsonl`;
      writeFileSync(join(outDir, rel), c.rows[split].map((r) => JSON.stringify(r)).join("\n") + "\n");
      expected.add(rel);
    }
  }
  writeFileSync(join(outDir, "LICENSE"), readFileSync(join(ROOT, "LICENSE")));
  writeFileSync(join(outDir, "NOTICE"), readFileSync(join(ROOT, "NOTICE")));
  writeFileSync(join(outDir, "README.md"), renderCard({
    counts,
    corpora: corpora.map((c) => ({ name: c.name, file: c.cfg.file, vector: c.cfg.vector, raw: c.raw })),
    version: pkg.version,
    commit: head.ok ? head.out : "unknown"
  }));

  // Nothing may sit in the output that this function did not intend to write.
  const written = listFiles(outDir).sort();
  const stray = written.filter((f) => !expected.has(f));
  if (stray.length) throw new Error(`export-hf: unexpected file(s) in ${outDir}: ${stray.join(", ")}`);

  return { outDir, counts, files: written };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const i = process.argv.indexOf("--out");
  const outDir = resolve(i > 0 ? process.argv[i + 1] : join(ROOT, "dist", "hf"));
  const { counts, files } = buildExport({ outDir, strict: true });
  let a = 0, b = 0;
  for (const [name, c] of Object.entries(counts)) {
    console.log(`${name.padEnd(28)} attack ${String(c.attack).padStart(4)}  benign ${String(c.benign).padStart(4)}`);
    a += c.attack; b += c.benign;
  }
  console.log(`${"all".padEnd(28)} attack ${String(a).padStart(4)}  benign ${String(b).padStart(4)}`);
  console.log(`wrote ${files.length} files to ${relative(process.cwd(), outDir) || "."}`);
}
