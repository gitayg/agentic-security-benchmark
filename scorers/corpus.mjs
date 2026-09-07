// Corpus loading and NORMALIZATION. Every corpus in corpora/ has its own historical shape; this file
// is the only place that knows about those differences. Everything downstream (score.mjs, report.mjs)
// sees one uniform sample record, so adding a corpus never touches the scorer.
//
// Corpora are read as data and never modified. Nothing here writes to disk.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, isAbsolute, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
export const CORPUS_DIR = join(HERE, "..", "corpora");

// ---------------------------------------------------------------------------------------------
// Vector 4 placeholder tokens.
//
// The corpus writes its file paths and credential fixtures as placeholders so a scorer can point them
// at a throwaway sandbox. This harness has no sandbox — it hands the action to an adapter rather than
// executing it — so the tokens are resolved to FIXED, deterministic strings. Every adapter therefore
// sees byte-identical action payloads, on every machine, on every run.
//
// The credential values are the public AWS documentation example key pair and a syntactically valid
// but fictitious GitHub token. They grant access to nothing.
// ---------------------------------------------------------------------------------------------
export const PLACEHOLDERS = Object.freeze({
  "{{HOME}}": "/home/agent",
  "{{CRED_FILE}}": "/home/agent/creds/.env",
  "{{BENIGN_FILE}}": "/home/agent/src/math.js",
  "{{STAGE_FILE}}": "/home/agent/tmp/staged.txt",
  "{{AWS_KEY}}": "AKIAIOSFODNN7EXAMPLE",
  "{{AWS_SECRET}}": "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1",
  "{{GH_TOKEN}}": "ghp_ABCDEFghijklMNOPqrstUVWXyz0123456789"
});

function resolvePlaceholders(action) {
  let s = JSON.stringify(action);
  for (const [token, value] of Object.entries(PLACEHOLDERS)) s = s.replaceAll(token, value);
  return JSON.parse(s);
}

// ---------------------------------------------------------------------------------------------
// The registry. `defaultStage` applies to any sample that declares no `stage` of its own.
// ---------------------------------------------------------------------------------------------
export const CORPORA = Object.freeze({
  "vector2-indirect-content": {
    file: "vector2-indirect-content.json",
    vector: 2,
    label: "indirect content injection",
    layout: "attacks+benign",
    defaultStage: "prompt",
    defaultHarness: "text"
  },
  "vector3-supply-chain": {
    file: "vector3-supply-chain.json",
    vector: 3,
    label: "tool / skill / extension / MCP supply chain",
    layout: "attacks+benign",
    // No `harness` field anywhere in this corpus: every sample is a blob of tool metadata or config
    // text, scanned at the stage the sample declares (tool | file | index | output).
    defaultStage: "prompt",
    defaultHarness: "text"
  },
  "vector4-outbound-action": {
    file: "vector4-outbound-action.json",
    vector: 4,
    label: "outbound action",
    layout: "attacks+benign",
    defaultStage: "prompt",
    defaultHarness: "action"
  },
  "vector5-memory-crossagent": {
    file: "vector5-memory-crossagent.json",
    vector: 5,
    label: "memory, context and cross-agent propagation",
    layout: "attacks+benign",
    defaultStage: "prompt",
    defaultHarness: "text"
  },
  "heldout-v2-tune": {
    file: "heldout-v2-tune.json",
    vector: 1,
    label: "direct prompt injection / jailbreak (tune half)",
    layout: "attacks+benign",
    defaultStage: "prompt",
    defaultHarness: "text"
  },
  "benign-corpus-v2": {
    file: "benign-corpus-v2.json",
    vector: null,
    label: "benign developer traffic (false-positive corpus)",
    layout: "benign-only",
    benignKey: "benign",
    defaultStage: "prompt",
    defaultHarness: "text"
  },
  "benign-web-content-tune": {
    file: "benign-web-content-tune.json",
    vector: null,
    label: "benign fetched web content (hard negatives, tune half)",
    layout: "benign-only",
    benignKey: "samples",
    defaultStage: "output",
    defaultHarness: "text"
  }
});

// Short aliases so the CLI is typeable.
export const ALIASES = Object.freeze({
  vector2: "vector2-indirect-content", v2: "vector2-indirect-content",
  vector3: "vector3-supply-chain", v3: "vector3-supply-chain",
  vector4: "vector4-outbound-action", v4: "vector4-outbound-action",
  vector5: "vector5-memory-crossagent", v5: "vector5-memory-crossagent",
  heldout: "heldout-v2-tune", "heldout-tune": "heldout-v2-tune",
  "benign-v2": "benign-corpus-v2", benign: "benign-corpus-v2",
  "benign-web": "benign-web-content-tune"
});

// Order used by `--corpus all`: the four AMTSO vectors, then the direct-injection set, then the two
// benign-only corpora (which carry the false-positive budget).
export const ALL_CORPORA = Object.freeze([
  "vector2-indirect-content",
  "vector3-supply-chain",
  "vector4-outbound-action",
  "vector5-memory-crossagent",
  "heldout-v2-tune",
  "benign-corpus-v2",
  "benign-web-content-tune"
]);

export function resolveCorpusName(name) {
  if (Object.prototype.hasOwnProperty.call(CORPORA, name)) return name;
  if (Object.prototype.hasOwnProperty.call(ALIASES, name)) return ALIASES[name];
  return null;
}

// ---------------------------------------------------------------------------------------------
// Sample normalization
// ---------------------------------------------------------------------------------------------

// Infer the harness when the corpus does not declare one. The inference is structural and ordered:
// steps[] -> "steps", events[] -> "events", turns[] -> "session", action/actions -> "action",
// otherwise the corpus default. This reproduces the source scorers' behavior, where a sample carrying
// `turns` was routed to the session entry point purely because it had turns.
function inferHarness(s, def) {
  if (s.harness) return s.harness;
  if (Array.isArray(s.steps) && s.steps.length) return "steps";
  if (Array.isArray(s.events)) return "events";
  if (Array.isArray(s.turns) && s.turns.length) return "session";
  if (s.action || (Array.isArray(s.actions) && s.actions.length)) return "action";
  return def;
}

function normalizeSample(s, cfg, corpusName, shouldDetect) {
  const harness = inferHarness(s, cfg.defaultHarness);
  const stage = s.stage || cfg.defaultStage;

  const out = {
    id: String(s.id),
    corpus: corpusName,
    vector: s.vector ?? cfg.vector ?? null,
    family: s.family || s.subTechnique || s.category || "—",
    subTechnique: s.subTechnique || s.family || s.category || "—",
    category: s.category || null,
    channel: s.channel || null,
    hiding: s.hiding || null,
    harness,
    stage,
    shouldDetect,
    expectThreat: s.expectThreat ?? null,
    expectDetections: Array.isArray(s.expectDetections) && s.expectDetections.length ? s.expectDetections : null,
    hardNegative: !!s.hard_negative,
    text: typeof s.text === "string" ? s.text : null,
    turns: Array.isArray(s.turns) ? s.turns.map(String) : null,
    events: Array.isArray(s.events) ? s.events : null,
    steps: null,
    consumeStep: null,
    actions: null,
    consumeAction: null
  };

  if (harness === "steps" || (Array.isArray(s.steps) && s.steps.length)) {
    const steps = (Array.isArray(s.steps) && s.steps.length ? s.steps : [{ role: "consume", stage, text: s.text }])
      .map((st) => ({ role: st.role || null, stage: st.stage || stage, text: typeof st.text === "string" ? st.text : "" }));
    out.steps = steps;
    // 1-based in the corpus; clamped, and defaulting to the LAST step when unset.
    const idx = Number.isInteger(s.consumeStep) ? s.consumeStep - 1 : steps.length - 1;
    out.consumeStep = Math.max(0, Math.min(steps.length - 1, idx));
    out.stage = steps[out.consumeStep].stage;
  }

  if (harness === "action") {
    const acts = (Array.isArray(s.actions) && s.actions.length ? s.actions : [s.action]).filter(Boolean);
    out.actions = acts.map(resolvePlaceholders);
    const idx = Number.isInteger(s.consumeAction) ? s.consumeAction - 1 : out.actions.length - 1;
    out.consumeAction = Math.max(0, Math.min(Math.max(out.actions.length - 1, 0), idx));
  }

  return out;
}

// Load one corpus by registry name (or alias) and return { name, meta, samples }.
//
// GROUND TRUTH PRECEDENCE: a sample's own `shouldDetect` ALWAYS wins; the array it lives in is only
// the fallback for a sample that does not declare one. This is not a stylistic choice — it is a
// correctness requirement, and getting it backwards silently corrupts both headline numbers.
//
// `benign-web-content-tune.json` is the case that proves it. It is a "benign" corpus, but 9 of its
// 158 samples carry `shouldDetect: true`: prompt-injection tutorial pages, deliberately reclassified
// from hard negatives on the reasoning that an injection example on a tutorial page is a LIVE payload
// — the agent fetching it cannot tell teaching material from an attack, because the text is identical
// either way. Firing on them is correct behaviour.
//
// Reading the array instead of the field counts those 9 as benign, so every catch on them becomes a
// FALSE POSITIVE and every miss becomes a correct allow. That inflates the measured FP rate and hides
// real misses — the exact error the corpus's own maintainer corrected upstream. A benign-only corpus
// is therefore "benign unless a sample says otherwise", never "benign, full stop".

export function loadCorpus(name, opts = {}) {
  const key = resolveCorpusName(name);
  if (!key) {
    throw new Error(
      `unknown corpus "${name}".\n  Known: ${Object.keys(CORPORA).join(", ")}\n  Aliases: ${Object.keys(ALIASES).join(", ")}`
    );
  }
  const cfg = CORPORA[key];
  const dir = opts.dir ? (isAbsolute(opts.dir) ? opts.dir : resolve(process.cwd(), opts.dir)) : CORPUS_DIR;
  const path = join(dir, cfg.file);
  if (!existsSync(path)) throw new Error(`corpus file not found: ${path}`);
  const data = JSON.parse(readFileSync(path, "utf8"));

  const samples = [];
  if (cfg.layout === "benign-only") {
    for (const s of data[cfg.benignKey] || []) samples.push(normalizeSample(s, cfg, key, s.shouldDetect === true));
  } else {
    for (const s of data.attacks || []) samples.push(normalizeSample(s, cfg, key, s.shouldDetect !== false));
    for (const s of data.benign || []) samples.push(normalizeSample(s, cfg, key, s.shouldDetect === true));
  }

  return {
    name: key,
    file: cfg.file,
    vector: cfg.vector,
    label: data.vectorName || cfg.label,
    samples
  };
}

export function corpusList(spec) {
  if (!spec || spec === "all") return [...ALL_CORPORA];
  return spec.split(",").map((s) => s.trim()).filter(Boolean).map((s) => {
    const k = resolveCorpusName(s);
    if (!k) throw new Error(`unknown corpus "${s}". Known: ${Object.keys(CORPORA).join(", ")}`);
    return k;
  });
}
