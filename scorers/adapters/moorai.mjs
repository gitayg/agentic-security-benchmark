// REFERENCE ADAPTER — MoorAI.
//
// This is the worked example of a real product behind the contract, and the reason the contract has
// the shape it does. It imports NOTHING from this repository's dependencies; it dynamically loads a
// MoorAI checkout named by the environment.
//
//   MOORAI_REPO=/path/to/moorai npm run score -- --adapter moorai
//   npm run score -- --adapter moorai --moorai-repo /path/to/moorai
//
// The MoorAI checkout is NOT vendored here and is not a dependency of the benchmark. Without it this
// adapter refuses with an actionable message instead of a module-not-found stack.
//
// WHAT IT MAPS
//   scanText     -> DetectionEngine.scan(text, stage)          finding id = MoorAI threat id (number)
//   scanSession  -> DetectionEngine.scanSession(turns)         same id space
//   scanEvents   -> runAgentDetections(events)                 finding id = detection bucket name
//   scanAction   -> NOT IMPLEMENTED. See below.
//
// WHY THERE IS NO scanAction, AND WHAT THAT COSTS — MEASURED, NOT ASSERTED.
//
// MoorAI's action surface is not a library call: it is the PreToolUse hook (cli/moorai-hook.mjs) run
// as a subprocess against a sandboxed HOME, with an org policy planted in a cache and credential
// fixtures on disk. Re-implementing that here would be a re-implementation, not a measurement, and
// pretending a text scan of the prose around an action is action enforcement is exactly the reporting
// error this benchmark exists to prevent. So `capabilities.action` is false and the harness scores
// vector 4 through its documented degraded fallback, marking every such row `degraded: true`.
//
// THIS IS NOT FIXED HERE, and the size of the gap is stated rather than left to the reader. MoorAI's
// own `scripts/score-vector24.mjs` spawns the real hook against the SAME 57 attacks / 24 benign
// controls (byte-for-byte the same samples; only JSON formatting differs). Run on 2026-09-07 against
// checkout c6439a3:
//
//   posture                                  stopped (deny/ask)   benign FP
//   real hook, unenrolled                          0/57   0.0%      0/24
//   real hook, enrolled, no org policy            18/57  31.6%      1/24    <- same posture as below
//   real hook, offline fail-closed                49/57  86.0%     11/24
//   real hook, enforcing org policy               43/57  75.4%      3/24
//
//   this adapter, flattened text, no org policy   20/57  35.1% prevented, 36/57 63.2% detected, 3/24 FP
//
// Read that carefully, because the deviation is NOT one-directional and the earlier one-line caveat
// implied it was:
//   * PREVENTION is the comparable column. The flattening lands within 2 samples of the real hook at
//     the same posture (20/57 vs 18/57), so the published vector-4 prevention figure is roughly
//     right — by luck of the corpus, not by construction.
//   * DETECTION (36/57) has NO real-hook analogue: the hook's decision channel carries only deny/ask,
//     and its `notify` findings go out-of-band to the alert wire. A "63.2% caught" from this harness
//     and a "31.6% stopped" from the hook are two different questions.
//   * The TENANT-POLICY deviation is the large one: 18/57 -> 43/57 under an enforcing org policy,
//     +25 attacks stopped, for 1/24 -> 3/24 benign. Prevention here really is understated, by about
//     that much. That deviation is now a PARAMETER, not a limitation — see MOORAI_POLICY below.
//
// THE SHIPPED INBOUND PATH, REPLICATED IN FULL. MoorAI's inbound surface is not a bare engine.scan at
// the "output" stage. cli/moorai-hook.mjs `handlePostToolUse` scans ingested content at "output" and
// then calls `dropOutboundOnly(raw, new Set([65, 32]), policy, text)`, which does TWO things:
//
//   1. DROPS threats 65 (egress-credential-shaped) and 32 (out-code-exec) unconditionally. They are
//      outbound-only detectors and nothing is leaving the device on an inbound page. The hook's own
//      comment records #32 firing on 62 of 158 benign fetched pages and catching zero attacks
//      uniquely.
//   2. GATES threats 15 (dlp-email) and 17 (out-links) through `INBOUND_GATES` — per-threat
//      predicates that keep the finding only when the ingested text ALSO looks egress-shaped: an
//      address in a header/verb position for #15, a link that is the object of an instruction for
//      #17. The hook records #17 ungated at 38.0% FP and gated at 21.5% on the same corpus.
//
// Both are load-bearing, and an adapter that replicated only the first would publish an inbound
// false-positive rate the shipped product does not have. Earlier versions of this adapter did exactly
// that, and said so — the gates were "private module state that cannot be imported without executing
// the hook", so the inbound number was published as an UPPER BOUND rather than a measurement.
//
// That is now fixed, and NOT by importing: the predicates are copied literally below, and `init()`
// re-reads `cli/moorai-hook.mjs` from the checkout and asserts that this copy's regex sources are
// still byte-identical to the ones in the hook, in order (see assertGateFidelity). A copy that has
// drifted from the shipped hook FAILS THE RUN with an actionable message instead of quietly
// publishing a stale number. The same check covers OUTBOUND_ONLY_THREATS.
//
// Set MOORAI_ADAPTER_RAW_OUTPUT=1 to turn the whole inbound reconciliation off and see the raw-engine
// numbers instead. That is the upper bound the adapter used to publish, kept as a diagnostic.
//
// WHAT `action` MEANS HERE. Prevention is derived from `threatActionFor(policy, threatId)` — the same
// function MoorAI's shipped hook enforces with — under the BUILTIN-DEFAULT posture (policy = null,
// i.e. a device with no org policy at all). It is never derived from the fact that a detector fired,
// and never from a detector's own `mode`, because the enforcement path ignores that field.
//
// MOORAI_POLICY=/path/to/policy.json swaps that null for a real org policy, so an enforcing tenant
// posture can be scored instead of only the out-of-the-box one. The file is passed to the SAME
// `threatActionFor`, so its `threatPolicy` / `tierPolicy` keys mean exactly what they mean in the
// product. The DEFAULT stays null on purpose: a policy is a per-tenant configuration choice, and a
// headline measured under a policy the maintainer wrote for the occasion is a number about that
// policy. Anything published with MOORAI_POLICY set must say so and name the policy.
import { readFileSync, existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { join, isAbsolute, resolve } from "node:path";

function repoRoot() {
  const argv = process.argv;
  const i = argv.indexOf("--moorai-repo");
  const spec = (i >= 0 && argv[i + 1]) || process.env.MOORAI_REPO;
  if (!spec) {
    throw new Error(
      "the moorai adapter needs a MoorAI checkout, and none was given.\n" +
      "  Set MOORAI_REPO, or pass --moorai-repo:\n" +
      "    MOORAI_REPO=/path/to/moorai npm run score -- --adapter moorai\n" +
      "    npm run score -- --adapter moorai --moorai-repo /path/to/moorai\n" +
      "  MoorAI is NOT bundled with this benchmark. If you only want a runnable example, use\n" +
      "  `--adapter keyword`, which needs nothing at all."
    );
  }
  const root = isAbsolute(spec) ? spec : resolve(process.cwd(), spec);
  const must = ["data/detectors.js", "data/content-rules.js", "src/engine.js", "cli/hook-core.mjs", "data/threats.json"];
  const missing = must.filter((p) => !existsSync(join(root, p)));
  if (missing.length) {
    throw new Error(
      `"${root}" does not look like a MoorAI checkout.\n` +
      `  Missing: ${missing.join(", ")}\n` +
      "  Point MOORAI_REPO at the repository ROOT (the directory containing package.json, src/ and data/)."
    );
  }
  return root;
}

// ---------------------------------------------------------------------------------------------
// The inbound reconciliation, copied from cli/moorai-hook.mjs `handlePostToolUse` /
// `dropOutboundOnly`. Copied rather than imported: importing that module EXECUTES the hook (it reads
// stdin and writes a hook envelope), so it is not loadable as a library. The copy is verified against
// the checkout at init() — see assertGateFidelity — so "copied" does not mean "allowed to drift".
// ---------------------------------------------------------------------------------------------

// Dropped unconditionally on ingested content.
//   cli/moorai-hook.mjs: const OUTBOUND_ONLY_THREATS = new Set([65, 32]);
const OUTBOUND_ONLY_THREATS = new Set([65, 32]);

// Kept only when the ingested text is also egress-shaped.
//   cli/moorai-hook.mjs: const INBOUND_GATES = { 15: ..., 17: ... }
// VERBATIM. Do not "tidy" these — assertGateFidelity compares `.source` and `.flags` against the
// literals in the checkout and fails the run on any difference, including a reordering.
const INBOUND_GATES = {
  15: [
    /^[ \t]{0,3}(?:from|to|cc|bcc|reply-to|organizer|sender)[ \t]*:[^\n]{0,120}@/im,
    /\b(?:send|email|e-mail|forward|cc|bcc|report|deliver|mail|exfiltrate|transmit)\b[^\n]{0,80}@/i
  ],
  17: [
    /\b(?:send|post|upload|exfiltrate|transmit|deliver|report|submit|forward|curl|wget|fetch)\b[^\n]{0,80}https?:\/\//i,
    /https?:\/\/[^\s]{0,120}\?[^\s]{0,80}=(?:\$|\{\{|%7B)/i,
    /\b(?:migrate|switch|point|redirect|repoint|move)\b[^\n]{0,40}\bto\b[^\n]{0,40}https?:\/\//i,
    /\b(?:retry|re-?run|reissue|authenticate|register|install|download|pull|clone)\b[^\n]{0,60}https?:\/\//i,
    /--?(?:registry|index-url|repo|remote|endpoint|host|url)[ =]https?:\/\//i,
    /!\[[^\]]{0,60}\]\(https?:\/\//i
  ]
};

// The hook's predicate is a disjunction over that threat's patterns; a threat with no gate is kept.
const gatePasses = (threatId, text) => {
  const pats = INBOUND_GATES[threatId];
  return pats ? pats.some((re) => re.test(text)) : true;
};

// Read the two constants back out of the checkout and assert this file still matches them.
//
// WHY TEXT AND NOT AN IMPORT: cli/moorai-hook.mjs runs its whole hook on import. So the fidelity
// check is a source-text comparison of the REGEX LITERALS inside the `INBOUND_GATES` block and the
// ids inside the `OUTBOUND_ONLY_THREATS` set. It is deliberately strict: order, source and flags all
// have to match. A benchmark that silently kept scoring after the product's suppression logic
// changed would publish a number for a build that no longer exists.
function assertGateFidelity(root) {
  const path = join(root, "cli", "moorai-hook.mjs");
  const src = readFileSync(path, "utf8");
  const fail = (what) => {
    throw new Error(
      `${path} no longer matches this adapter's copy of the shipped inbound reconciliation.\n` +
      `  ${what}\n` +
      "  scorers/adapters/moorai.mjs replicates handlePostToolUse's OUTBOUND_ONLY_THREATS and\n" +
      "  INBOUND_GATES literally, because that module executes its hook on import and cannot be\n" +
      "  imported as a library. Re-copy them from the hook and re-run, or the published inbound\n" +
      "  false-positive rate describes a build that no longer exists."
    );
  };

  const setBlock = src.match(/const OUTBOUND_ONLY_THREATS = new Set\(\[([^\]]*)\]\)/);
  if (!setBlock) fail("could not find `const OUTBOUND_ONLY_THREATS = new Set([...])` in the hook.");
  const hookIds = setBlock[1].split(",").map((s) => Number(s.trim())).filter((n) => Number.isFinite(n));
  const mineIds = [...OUTBOUND_ONLY_THREATS];
  if (hookIds.length !== mineIds.length || hookIds.some((n, i) => n !== mineIds[i])) {
    fail(`OUTBOUND_ONLY_THREATS: hook has [${hookIds}], this adapter has [${mineIds}].`);
  }

  const gateBlock = src.match(/const INBOUND_GATES = \{[\s\S]*?\n\};/);
  if (!gateBlock) fail("could not find the `const INBOUND_GATES = { ... };` block in the hook.");
  // Per-threat: everything from `<id>:` up to the next `<id>:` or the closing brace.
  for (const [id, pats] of Object.entries(INBOUND_GATES)) {
    const per = gateBlock[0].match(new RegExp(`\\n\\s*${id}:\\s*\\(t\\)[\\s\\S]*?(?=\\n\\s*\\d+:\\s*\\(t\\)|\\n\\};)`));
    if (!per) fail(`INBOUND_GATES has no entry for threat ${id} in the hook.`);
    // Regex literals appear only as `/…/flags.test(t)` in this block, which makes them unambiguous
    // to lift without parsing JavaScript.
    const hookPats = [...per[0].matchAll(/\/((?:\\.|\[(?:\\.|[^\]])*\]|[^/\\\n])+)\/([a-z]*)\.test\(t\)/g)]
      .map((m) => `/${m[1]}/${m[2]}`);
    const minePats = pats.map((re) => `/${re.source}/${re.flags}`);
    if (hookPats.length !== minePats.length) {
      fail(`INBOUND_GATES[${id}]: hook has ${hookPats.length} pattern(s), this adapter has ${minePats.length}.`);
    }
    for (let i = 0; i < minePats.length; i++) {
      if (hookPats[i] !== minePats[i]) {
        fail(`INBOUND_GATES[${id}] pattern ${i}:\n    hook    ${hookPats[i]}\n    adapter ${minePats[i]}`);
      }
    }
  }
  // Also assert the two are actually WIRED to the PostToolUse path, not merely defined. A hook that
  // stopped calling dropOutboundOnly would leave both constants intact and every check above green.
  if (!/dropOutboundOnly\(raw, OUTBOUND_ONLY_THREATS, policy, text\)/.test(src)) {
    fail("handlePostToolUse no longer calls dropOutboundOnly(raw, OUTBOUND_ONLY_THREATS, policy, text).");
  }
  if (!/const gate = INBOUND_GATES\[f\.threatId\];/.test(src)) {
    fail("dropOutboundOnly no longer consults INBOUND_GATES per finding.");
  }
}

let engine = null;
let threatActionFor = null;
let runAgentDetections = null;
let version = "unknown";
// null = BUILTIN-DEFAULT posture (no org policy). Replaced by MOORAI_POLICY, if set.
let policy = null;
let policySource = null;

// Load the optional org policy. Parsed here and handed straight to MoorAI's own threatActionFor, so
// this file never interprets a policy field itself.
function loadPolicy() {
  const spec = process.env.MOORAI_POLICY;
  if (!spec) return { policy: null, source: null };
  const path = isAbsolute(spec) ? spec : resolve(process.cwd(), spec);
  if (!existsSync(path)) {
    throw new Error(`MOORAI_POLICY="${spec}" does not exist (resolved to ${path}).`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`MOORAI_POLICY="${path}" is not valid JSON: ${e && e.message ? e.message : e}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`MOORAI_POLICY="${path}" must contain a JSON object (a MoorAI org policy).`);
  }
  return { policy: parsed, source: path };
}

export default {
  name: "moorai",
  version: "0.0.0", // replaced in init() with the version of the checkout actually loaded
  // No `action`: see the header. Vector 4 is scored through the harness's degraded text fallback.
  capabilities: { text: true, action: false, session: true, events: true },

  async init() {
    const root = repoRoot();
    const imp = (p) => import(pathToFileURL(join(root, p)).href);
    let mods;
    try {
      mods = {
        detectors: await imp("data/detectors.js"),
        contentRules: await imp("data/content-rules.js"),
        engine: await imp("src/engine.js"),
        hookCore: await imp("cli/hook-core.mjs"),
        baseline: await imp("data/agent-baseline.js")
      };
    } catch (e) {
      throw new Error(
        `failed to load the MoorAI engine from "${root}".\n` +
        `  ${e && e.message ? e.message : e}\n` +
        "  The checkout must be a full one (data/, src/ and cli/ present) on a Node that can import it."
      );
    }
    const threats = JSON.parse(readFileSync(join(root, "data/threats.json"), "utf8"));
    engine = new mods.engine.DetectionEngine(threats, mods.detectors.DETECTORS, mods.contentRules.CONTENT_RULES);
    threatActionFor = mods.hookCore.threatActionFor;
    runAgentDetections = mods.baseline.runAgentDetections;
    if (!process.env.MOORAI_ADAPTER_RAW_OUTPUT) assertGateFidelity(root);
    ({ policy, source: policySource } = loadPolicy());
    // Loud on purpose. A run under an enforcing org policy is a DIFFERENT measurement from the
    // out-of-the-box one, and the difference is large (see the header table). Nobody should be able
    // to produce that number without it appearing in their own terminal.
    if (policySource) {
      process.stderr.write(
        `moorai adapter: enforcing org policy loaded from ${policySource}.\n` +
        "  Prevention is derived under THAT policy, not the built-in default. Say so when publishing.\n"
      );
    }
    try { version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version || "unknown"; } catch { /* keep "unknown" */ }
    this.version = version;
  },

  async scanText(text, stage) {
    const st = stage || "prompt";
    const t = String(text ?? "");
    const findings = toFindings(engine.scan(t, st));
    if (st === "output" && !process.env.MOORAI_ADAPTER_RAW_OUTPUT) {
      // cli/moorai-hook.mjs handlePostToolUse -> dropOutboundOnly(raw, OUTBOUND_ONLY_THREATS, policy, text)
      return findings.filter((f) => !OUTBOUND_ONLY_THREATS.has(f.id) && gatePasses(f.id, t));
    }
    return findings;
  },

  async scanSession(turns) {
    return toFindings(engine.scanSession(Array.isArray(turns) ? turns : []));
  },

  async scanEvents(events) {
    const det = runAgentDetections(Array.isArray(events) ? events : []);
    return Object.keys(det)
      .filter((k) => Array.isArray(det[k]) && det[k].length > 0)
      // The bucket NAME is the finding id, which is the id space vector 5's `expectDetections` uses,
      // so right-reason is measurable for the events harness. These buckets are behavioral signals
      // with no enforcement action of their own, so they are notify — detections, not preventions.
      .map((k) => ({ id: k, category: "agent-behavioral", severity: "medium", action: "notify" }));
  }
};

function toFindings(findings) {
  const out = [];
  const seen = new Set();
  for (const f of findings || []) {
    const id = f?.threat?.id;
    if (id === undefined || seen.has(id)) continue;
    seen.add(id);
    out.push({
      id,
      category: f.detectorId ? String(f.detectorId) : null,
      severity: f?.threat?.riskLevel ? String(f.threat.riskLevel) : null,
      // Same function the shipped PreToolUse hook enforces with, under the same posture: BUILTIN
      // DEFAULT (policy === null) unless MOORAI_POLICY named a real org policy.
      action: threatActionFor(policy, id)
    });
  }
  return out;
}
