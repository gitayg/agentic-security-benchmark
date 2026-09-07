// Corpus integrity validator — the gate every corpus PR has to pass.
//
//   node --test test/            (or: npm run validate)
//
// WHAT THIS DOES NOT DO: it does not score anything and it pins no recall or precision number. A
// corpus test that asserts "recall >= X" turns every adapter change into a spurious failure while
// proving nothing about the corpus. What is asserted here is only that the corpus can still be
// believed: well-formed samples, unique ids, a validity justification behind every attack sample,
// AMTSO labels where the corpus carries them, no credential-shaped string that would trip GitHub
// push protection, and no leak of a locked held-out split.
//
// EVERY ASSERTION BELOW WAS CHECKED AGAINST THE SHIPPED CORPORA BEFORE IT WAS WRITTEN. Where a
// corpus does not yet carry a field, the invariant is asserted for the corpora that DO and the gap
// is recorded in CORPORA (see `notes`) rather than weakened everywhere. A validator that has been
// loosened until it passes is not a gate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// Overridable so the validator can be pointed at a deliberately-broken copy to prove it still
// fails (see CONTRIBUTING.md, "Falsify the validator"). Never point it at a locked split.
const CORPUS_DIR = process.env.BENCHMARK_CORPORA_DIR || join(ROOT, "corpora");

const SAMPLE_ARRAYS = ["attacks", "benign", "samples"];

// The five stages content can reach an agent at, and the five harnesses a sample can be replayed
// through. Both sets are closed: a sample outside them cannot be routed to any scorer entry point.
const ALLOWED_STAGES = new Set(["prompt", "file", "index", "output", "tool"]);
const ALLOWED_HARNESSES = new Set(["text", "action", "steps", "session", "events"]);

const AMTSO_CORE = ["targetOfProtection", "harm", "requiredCapability"];
const MIN_VALIDITY_LEN = 40; // shortest shipped validity string is 53 chars (vector 3)

// ---------------------------------------------------------------- allowlists ----
//
// PLACEHOLDER CREDENTIALS. These four exact strings are well-known, public documentation values
// that grant access to nothing, and they are the ONLY credential-shaped strings in the corpora
// today. The list is exact-match on purpose: a NEW secret-shaped string still fails the scan and
// has to be added here deliberately, in a reviewed PR, with a maintainer signing off that it is a
// placeholder. This is not hypothetical — GitHub push protection has already blocked a push over a
// placeholder-shaped fixture in the upstream repo.
const ALLOWED_PLACEHOLDER_SECRETS = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "ghp_ABCDEF0123456789ABCDEF0123456789ABCD",
  "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  "AIzaSyEXAMPLE_KEY_NOT_REAL_000000000000"
]);

// ---------------------------------------------------------------------------------------------
// ID NAMESPACES.
//
// There is no collision allowlist here, and there must never be one again. `v2-doc-001`..`-006` used
// to denote two different samples each — `v2-` meant "benign corpus v2, docs bucket" in one file and
// "vector 2, document channel" in the other — and the collision was allowlisted with a staleness
// test. An allowlist that outlives its defect rots into a blanket exemption, so the defect was fixed
// instead: benign-corpus-v2's ids were re-prefixed `v2-` -> `bcv2-` and the namespace is now
// STRUCTURAL. Each corpus owns a prefix, no prefix may be a prefix of another, and every id in the
// corpus must start with its own. A corpus added later therefore cannot re-create the collision.
//
// This table is the test's own copy on purpose: it must fail if scorers/corpus.mjs and the corpora
// drift apart, which importing the registry would hide.
const ID_PREFIXES = {
  "benign-corpus-v2.json": "bcv2-",
  "benign-web-content-tune.json": "wf-",
  "heldout-v2-tune.json": "hv2-",
  "vector2-indirect-content.json": "v2-",
  "vector3-supply-chain.json": "v3-",
  "vector4-outbound-action.json": "v4-",
  "vector5-memory-crossagent.json": "v5-"
};

// Credential shapes that must never enter the tree. The first three are inherited from the upstream
// repo's corpus tests; the last three were added here because they are the shapes GitHub push
// protection scans for and a placeholder in any of them can block a push for everyone.
const FORBIDDEN_SECRET_SHAPES = [
  [/sk_live_[0-9a-zA-Z]{10,}/g, "Stripe live-key shape (trips push protection)"],
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, "private key block"],
  [/AKIA[0-9A-Z]{16}/g, "AWS access key id"],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/g, "Slack token shape"],
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, "GitHub token shape"],
  [/AIza[0-9A-Za-z_-]{20,}/g, "Google API key shape"]
];

// ---------------------------------------------------------------- corpus table ----
//
// What each shipped corpus actually carries today. Read from the files, not assumed. `notes`
// records a genuine gap so the next person does not mistake a missing assertion for an oversight.
const CORPORA = {
  "benign-corpus-v2.json": {
    arrays: ["benign"],
    benignOnly: true, // no sample carries shouldDetect at all; benign is implied by the corpus
    labelledArrays: false,
    requiresValidity: false,
    requiresAmtsoOnAttacks: false,
    requiresTwinOnHardNegatives: true,
    notes: "No shouldDetect field and no validity/amtso labels: a pure precision corpus predating the AMTSO labelling pass."
  },
  "benign-web-content-tune.json": {
    arrays: ["samples"],
    benignOnly: false, // 9 of 158 samples are shouldDetect:true (injection-tutorial pages, reclassified as true positives)
    labelledArrays: false, // single mixed `samples` array, so array name does not imply the label
    requiresValidity: true,
    requiresAmtsoOnAttacks: false,
    requiresTwinOnHardNegatives: false,
    notes: "GAP: 62 hard negatives carry no twin_of — this corpus predates the twin convention. Every sample does carry validity."
  },
  "heldout-v2-tune.json": {
    arrays: ["attacks", "benign"],
    benignOnly: false,
    labelledArrays: true,
    requiresValidity: false,
    requiresAmtsoOnAttacks: false,
    requiresTwinOnHardNegatives: true,
    notes: "GAP: the tune half of the held-out set carries neither validity nor amtso. New samples here should carry both."
  },
  "vector2-indirect-content.json": {
    arrays: ["attacks", "benign"],
    benignOnly: false,
    labelledArrays: true,
    requiresValidity: true,
    requiresAmtsoOnAttacks: true,
    requiresAttackVector: 2, // this corpus DOES carry amtso.attackVector
    requiresTwinOnHardNegatives: true
  },
  "vector3-supply-chain.json": {
    arrays: ["attacks", "benign"],
    benignOnly: false,
    labelledArrays: true,
    requiresValidity: true,
    requiresAmtsoOnAttacks: true,
    requiresTwinOnHardNegatives: true,
    notes: "GAP: amtso carries only the three core dimensions; attackVector is implied by the file's own `vector: 3` and is not repeated per sample. Benign controls carry no validity/amtso."
  },
  "vector4-outbound-action.json": {
    arrays: ["attacks", "benign"],
    benignOnly: false,
    labelledArrays: true,
    requiresValidity: true,
    requiresAmtsoOnAttacks: true,
    requiresAttackVector: 4,
    requiresTwinOnHardNegatives: true
  },
  "vector5-memory-crossagent.json": {
    arrays: ["attacks", "benign"],
    benignOnly: false,
    labelledArrays: true,
    requiresValidity: true,
    requiresAmtsoOnAttacks: true,
    requiresTwinOnHardNegatives: true,
    notes: "GAP: same as vector 3 — amtso omits attackVector (implied by `vector: 5`); benign controls carry no validity/amtso."
  }
};

// ---------------------------------------------------------------- loading ----

const files = readdirSync(CORPUS_DIR).filter((f) => f.endsWith(".json")).sort();

const raw = new Map();
const parsed = new Map();
for (const f of files) {
  const text = readFileSync(join(CORPUS_DIR, f), "utf8");
  raw.set(f, text);
  parsed.set(f, JSON.parse(text)); // a parse failure here fails the whole file, which is the point
}

/** Every sample in every corpus, tagged with where it came from. */
function everySample() {
  const out = [];
  for (const f of files) {
    const j = parsed.get(f);
    for (const key of SAMPLE_ARRAYS) {
      if (!Array.isArray(j[key])) continue;
      for (const s of j[key]) out.push({ file: f, array: key, s });
    }
  }
  return out;
}

const ALL = everySample();
const spec = (f) => CORPORA[f] || null;

/** Attack sample = one the corpus says a product is supposed to flag. */
const isAttack = (row) =>
  row.s.shouldDetect === true || (row.s.shouldDetect === undefined && row.array === "attacks");

// ---------------------------------------------------------------- tests ----

test("every corpus file parses and has a recognised top-level shape", () => {
  assert.ok(files.length > 0, `no corpora found in ${CORPUS_DIR}`);
  for (const f of files) {
    const j = parsed.get(f);
    assert.equal(typeof j, "object", `${f}: top level must be an object`);
    assert.ok(j !== null && !Array.isArray(j), `${f}: top level must be an object, not an array`);
    const present = SAMPLE_ARRAYS.filter((k) => Array.isArray(j[k]));
    assert.ok(present.length > 0, `${f}: needs at least one of ${SAMPLE_ARRAYS.join("/")}`);
    const known = spec(f);
    if (known) {
      assert.deepEqual(present.sort(), [...known.arrays].sort(),
        `${f}: sample arrays changed from the declared shape — update CORPORA in this file deliberately`);
    }
    for (const k of present) {
      for (const [i, s] of j[k].entries()) {
        assert.equal(typeof s, "object", `${f}.${k}[${i}]: sample must be an object`);
        assert.ok(s !== null && !Array.isArray(s), `${f}.${k}[${i}]: sample must be an object`);
      }
    }
  }
});

test("every corpus file is described in the CORPORA table", () => {
  // A new corpus dropped in without a table entry would silently skip every corpus-scoped
  // assertion below, so the table itself is the gate on adding one.
  const undescribed = files.filter((f) => !spec(f));
  assert.deepEqual(undescribed, [],
    `corpora with no CORPORA entry in test/validate-corpora.mjs: ${undescribed.join(", ")}`);
});

test("every sample has a non-empty string id", () => {
  for (const { file, array, s } of ALL) {
    assert.equal(typeof s.id, "string", `${file}.${array}: sample id must be a string, got ${JSON.stringify(s.id)}`);
    assert.ok(s.id.trim().length > 0, `${file}.${array}: sample id must not be empty`);
  }
});

test("no duplicate ids within a corpus", () => {
  for (const f of files) {
    const seen = new Set();
    for (const { s } of ALL.filter((r) => r.file === f)) {
      assert.ok(!seen.has(s.id), `${f}: duplicate id ${s.id}`);
      seen.add(s.id);
    }
  }
});

test("no duplicate ids across corpora", () => {
  // No allowlist and no exemption. An id names exactly one sample in the whole benchmark.
  const owner = new Map();
  for (const { file, array, s } of ALL) {
    const where = `${file}:${array}`;
    assert.ok(!owner.has(s.id),
      `id ${s.id} appears in both ${owner.get(s.id)} and ${where}; ids must be unique across the whole benchmark`);
    owner.set(s.id, where);
  }
});

test("every corpus declares an id prefix and no prefix is a prefix of another", () => {
  // The structural half of the uniqueness guarantee. Disjoint prefixes mean two corpora cannot
  // produce the same id even by accident, so uniqueness survives a corpus being added by someone
  // who never read the other files.
  const undeclared = files.filter((f) => !ID_PREFIXES[f]);
  assert.deepEqual(undeclared, [],
    `corpora with no ID_PREFIXES entry in test/validate-corpora.mjs: ${undeclared.join(", ")}`);
  const entries = Object.entries(ID_PREFIXES);
  for (const [fa, pa] of entries) {
    for (const [fb, pb] of entries) {
      if (fa === fb) continue;
      assert.ok(!pb.startsWith(pa),
        `id prefix "${pa}" (${fa}) is a prefix of "${pb}" (${fb}) — the two namespaces can collide`);
    }
  }
});

test("every sample id sits inside its corpus's id namespace", () => {
  for (const { file, array, s } of ALL) {
    const p = ID_PREFIXES[file];
    if (!p) continue; // the previous test is the gate on a missing entry
    assert.ok(s.id.startsWith(p),
      `${file}.${array}: id ${JSON.stringify(s.id)} must start with this corpus's id prefix ${JSON.stringify(p)}`);
  }
});

test("every sample declares shouldDetect, or sits in a corpus where benign is implied", () => {
  for (const { file, array, s } of ALL) {
    const known = spec(file);
    if (known?.benignOnly) {
      // Implied benign: the corpus is a pure precision denominator. An explicit false is fine; a
      // true would mean an attack has been filed into the false-positive denominator.
      assert.notEqual(s.shouldDetect, true, `${file}:${s.id}: benign-only corpus cannot contain shouldDetect:true`);
      continue;
    }
    assert.equal(typeof s.shouldDetect, "boolean", `${file}:${s.id}: must declare a boolean shouldDetect`);
  }
});

test("labelled arrays agree with the label on the sample", () => {
  for (const { file, array, s } of ALL) {
    if (!spec(file)?.labelledArrays) continue;
    if (array === "attacks") assert.equal(s.shouldDetect, true, `${file}:${s.id} is in attacks[] but shouldDetect is not true`);
    if (array === "benign") assert.equal(s.shouldDetect, false, `${file}:${s.id} is in benign[] but shouldDetect is not false`);
  }
});

test("every attack sample carries a meaningful validity statement", () => {
  // The validity rule: a sample counts only if the malicious outcome could actually occur with the
  // product absent. The statement is how a reviewer checks that without re-deriving it.
  for (const row of ALL) {
    if (!spec(row.file)?.requiresValidity) continue;
    if (!isAttack(row)) continue;
    const v = row.s.validity;
    assert.equal(typeof v, "string", `${row.file}:${row.s.id}: attack samples need a validity statement`);
    assert.ok(v.trim().length >= MIN_VALIDITY_LEN,
      `${row.file}:${row.s.id}: validity statement is too short to justify anything (${v.trim().length} chars)`);
  }
});

test("benign samples carry a validity statement wherever the corpus does", () => {
  // benign-web-content-tune carries one on every sample; the vector corpora carry them on some
  // benign controls and not others, so this only checks the shape of what is there.
  for (const { file, s } of ALL) {
    if (s.validity === undefined) continue;
    assert.equal(typeof s.validity, "string", `${file}:${s.id}: validity must be a string`);
    assert.ok(s.validity.trim().length >= MIN_VALIDITY_LEN,
      `${file}:${s.id}: validity statement is too short (${s.validity.trim().length} chars)`);
  }
});

test("AMTSO labels are complete wherever a corpus carries them", () => {
  for (const row of ALL) {
    const known = spec(row.file);
    const { file, s } = row;
    if (known?.requiresAmtsoOnAttacks && isAttack(row)) {
      assert.equal(typeof s.amtso, "object", `${file}:${s.id}: attack samples in this corpus need an amtso object`);
      assert.ok(s.amtso !== null, `${file}:${s.id}: amtso must not be null`);
    }
    if (!s.amtso) continue;
    for (const k of AMTSO_CORE) {
      assert.ok(s.amtso[k] !== undefined && s.amtso[k] !== null && String(s.amtso[k]).trim() !== "",
        `${file}:${s.id}: amtso.${k} is missing or empty`);
    }
    if (known?.requiresAttackVector !== undefined) {
      assert.equal(s.amtso.attackVector, known.requiresAttackVector,
        `${file}:${s.id}: amtso.attackVector must be ${known.requiresAttackVector}`);
    }
    if (s.amtso.attackVector !== undefined) {
      assert.ok(Number.isInteger(s.amtso.attackVector) && s.amtso.attackVector >= 1 && s.amtso.attackVector <= 6,
        `${file}:${s.id}: amtso.attackVector must be an integer 1-6, got ${JSON.stringify(s.amtso.attackVector)}`);
    }
  }
});

test("harness and stage, where present, come from the allowed sets", () => {
  for (const { file, s } of ALL) {
    if (s.harness !== undefined) {
      assert.ok(ALLOWED_HARNESSES.has(s.harness), `${file}:${s.id}: unknown harness ${JSON.stringify(s.harness)}`);
    }
    if (s.stage !== undefined) {
      assert.ok(ALLOWED_STAGES.has(s.stage), `${file}:${s.id}: unknown stage ${JSON.stringify(s.stage)}`);
    }
    for (const [i, st] of (Array.isArray(s.steps) ? s.steps : []).entries()) {
      assert.ok(ALLOWED_STAGES.has(st.stage), `${file}:${s.id}: steps[${i}].stage ${JSON.stringify(st.stage)} is not a real stage`);
    }
  }
});

test("every hard negative declares the attack sample it is the twin of", () => {
  for (const { file, s } of ALL) {
    if (s.hard_negative !== true) continue;
    if (!spec(file)?.requiresTwinOnHardNegatives) continue; // see CORPORA notes for the gap
    assert.equal(typeof s.twin_of, "string", `${file}:${s.id}: hard negatives must declare twin_of`);
    assert.ok(s.twin_of.trim().length > 0, `${file}:${s.id}: twin_of must not be empty`);
  }
});

test("no secret-shaped string outside the documented placeholder allowlist", () => {
  for (const f of files) {
    const text = raw.get(f);
    for (const [re, why] of FORBIDDEN_SECRET_SHAPES) {
      for (const m of text.match(new RegExp(re.source, "g")) || []) {
        assert.ok(ALLOWED_PLACEHOLDER_SECRETS.has(m),
          `${f}: ${why} not on the placeholder allowlist: ${JSON.stringify(m)} — if it really is a public documentation placeholder, add it to ALLOWED_PLACEHOLDER_SECRETS in a reviewed PR`);
      }
    }
  }
});

test("no locked held-out split has leaked into the published corpora", () => {
  // The whole value of a held-out split is that nobody has tuned against it, the maintainer
  // included. A `split: "test"` row or a lock-shaped top-level key here means the split is burnt.
  for (const { file, s } of ALL) {
    assert.notEqual(s.split, "test",
      `${file}:${s.id}: carries split:"test" — the locked held-out half must never be published`);
  }
  for (const f of files) {
    const lockish = Object.keys(parsed.get(f)).filter((k) => /lock/i.test(k));
    assert.deepEqual(lockish, [], `${f}: lock-shaped top-level key(s) ${lockish.join(", ")} suggest a locked split was published`);
  }
});

// ---------------------------------------------------------------------------------------------
// results/ <-> corpora consistency.
//
// A results file names sample ids in its `misses` and `falsePositives` lists. Those ids are the only
// actionable part of a published result — "which attacks did it miss" — and they go stale silently
// the moment a corpus is edited. This is not hypothetical: the corpora once carried six ids that
// denoted two different samples each, and the results files pointed at both.
//
// Skipped when BENCHMARK_CORPORA_DIR is set: pointing the validator at a deliberately-broken corpus
// copy says nothing about whether the published results match the REAL corpora.
test("every sample id named in results/ still exists in the corpora", { skip: !!process.env.BENCHMARK_CORPORA_DIR }, () => {
  const known = new Set(ALL.map((r) => r.s.id));
  const dir = join(ROOT, "results");
  const resultFiles = readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "TEMPLATE.json").sort();
  assert.ok(resultFiles.length > 0, "no results files found — results/ should hold at least one");
  for (const f of resultFiles) {
    const j = JSON.parse(readFileSync(join(dir, f), "utf8"));
    for (const c of j.corpora || []) {
      for (const key of ["misses", "falsePositives", "inconclusiveRows", "notApplicableRows"]) {
        for (const row of c[key] || []) {
          assert.ok(known.has(row.id),
            `results/${f}: ${c.corpus}.${key} names sample id ${JSON.stringify(row.id)}, which is in no corpus — regenerate this results file (see results/README.md)`);
        }
      }
    }
  }
});

// ── the README's hard-negative table ──────────────────────────────────────────
//
// corpora/README.md publishes a per-file count of `hard_negative: true` and `twin_of`. It drifted
// once and nothing caught it: the table carried each vector's `twin_of` count in the
// `hard_negative` column, which is invisible for vector3 and vector5 (where the two counts happen
// to be equal) and wrong for vector2 (16 vs 17) and vector4 (17 vs 24). The published total was
// 409 against a measured 401.
//
// A hard negative and a twin are not the same thing: a sample can be shaped to look malicious
// without being written against one specific attack, so `twin_of` is a subset relationship in one
// direction only and the counts must be read separately. This test is the reason the table can be
// trusted — it is derived from the same files the table describes.
test("the README's hard-negative table matches the corpora", () => {
  const md = readFileSync(join(ROOT, "corpora", "README.md"), "utf8");

  // Measure: walk every object, skipping `_`-prefixed metadata keys so a `_stats` block that
  // mentions these fields cannot be counted as a sample.
  const measured = {};
  const walk = (node, hit) => {
    if (Array.isArray(node)) { for (const x of node) walk(x, hit); return; }
    if (!node || typeof node !== "object") return;
    if (node.hard_negative === true) hit.hn++;
    if (node.twin_of) hit.tw++;
    for (const k of Object.keys(node)) if (k[0] !== "_") walk(node[k], hit);
  };
  for (const f of files) {
    const hit = { hn: 0, tw: 0 };
    walk(JSON.parse(readFileSync(join(CORPUS_DIR, f), "utf8")), hit);
    measured[f.replace(/\.json$/, "")] = hit;
  }

  // Parse: rows look like `| `name` | 269 | 269 |`; the totals row uses bold.
  const rows = new Map();
  let totals = null;
  for (const line of md.split("\n")) {
    const cells = line.split("|").map((c) => c.trim()).filter((c) => c !== "");
    if (cells.length !== 3) continue;
    const num = (c) => Number(c.replace(/\*/g, ""));
    if (/^\*\*total\*\*$/i.test(cells[0])) { totals = { hn: num(cells[1]), tw: num(cells[2]) }; continue; }
    const name = cells[0].replace(/`/g, "");
    if (!Object.hasOwn(measured, name)) continue;
    rows.set(name, { hn: num(cells[1]), tw: num(cells[2]) });
  }

  assert.ok(rows.size > 0, "corpora/README.md has no recognisable hard-negative table rows");

  for (const name of Object.keys(measured)) {
    assert.ok(rows.has(name), `corpora/README.md's hard-negative table is missing a row for ${name}`);
    const want = measured[name], got = rows.get(name);
    assert.equal(got.hn, want.hn, `corpora/README.md says ${name} has ${got.hn} \`hard_negative: true\` samples; the file has ${want.hn}`);
    assert.equal(got.tw, want.tw, `corpora/README.md says ${name} has ${got.tw} \`twin_of\` samples; the file has ${want.tw}`);
  }

  const sum = Object.values(measured).reduce((a, m) => ({ hn: a.hn + m.hn, tw: a.tw + m.tw }), { hn: 0, tw: 0 });
  assert.ok(totals, "corpora/README.md's hard-negative table has no **total** row");
  assert.equal(totals.hn, sum.hn, `corpora/README.md totals ${totals.hn} hard negatives; the corpora contain ${sum.hn}`);
  assert.equal(totals.tw, sum.tw, `corpora/README.md totals ${totals.tw} twins; the corpora contain ${sum.tw}`);
});
