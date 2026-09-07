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

// KNOWN CROSS-CORPUS ID COLLISIONS. `v2-doc-001`..`v2-doc-006` genuinely exist twice, as two
// DIFFERENT samples: in benign-corpus-v2.json the prefix means "v2 corpus, docs bucket", and in
// vector2-indirect-content.json it means "vector 2, document channel". Two id namespaces collided.
// This is a defect in the shipped corpora, not an intended alias — it is allowlisted so the gate
// still catches NEW collisions instead of being switched off, and it should be fixed by renaming
// one side (which changes published per-sample rows, so it needs maintainer sign-off).
const KNOWN_CROSS_CORPUS_ID_COLLISIONS = new Set([
  "v2-doc-001", "v2-doc-002", "v2-doc-003", "v2-doc-004", "v2-doc-005", "v2-doc-006"
]);

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
  const owner = new Map();
  for (const { file, array, s } of ALL) {
    const where = `${file}:${array}`;
    if (owner.has(s.id)) {
      assert.ok(KNOWN_CROSS_CORPUS_ID_COLLISIONS.has(s.id),
        `id ${s.id} appears in both ${owner.get(s.id)} and ${where}; ids must be unique across the whole benchmark`);
      continue;
    }
    owner.set(s.id, where);
  }
});

test("the known-collision allowlist has not gone stale", () => {
  // If a collision is fixed, the allowlist entry must be removed in the same PR — otherwise the
  // list quietly grows into a blanket exemption.
  const counts = new Map();
  for (const { s } of ALL) counts.set(s.id, (counts.get(s.id) || 0) + 1);
  const stale = [...KNOWN_CROSS_CORPUS_ID_COLLISIONS].filter((id) => (counts.get(id) || 0) < 2);
  assert.deepEqual(stale, [], `no longer colliding, remove from KNOWN_CROSS_CORPUS_ID_COLLISIONS: ${stale.join(", ")}`);
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
