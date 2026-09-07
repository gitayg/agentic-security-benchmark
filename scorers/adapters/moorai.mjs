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
// WHY THERE IS NO scanAction. MoorAI's action surface is not a library call: it is the PreToolUse hook
// (cli/moorai-hook.mjs) run as a subprocess against a sandboxed HOME, with an org policy planted in a
// cache. Re-implementing that here would be a re-implementation, not a measurement, and pretending a
// text scan of the prose around an action is action enforcement is exactly the reporting error this
// benchmark exists to prevent. So `capabilities.action` is false and the harness scores vector 4
// through its documented degraded fallback, marking every such row `degraded: true`.
//
// ONE SHIPPED-PATH FIDELITY FIX, AND WHY IT IS HERE. MoorAI's inbound surface is not a bare
// engine.scan at the "output" stage: cli/moorai-hook.mjs `handlePostToolUse` scans ingested content at
// "output" and then DROPS threats 65 (egress-credential-shaped) and 32 (out-code-exec) via
// `dropOutboundOnly`, because those two are outbound-only detectors and nothing is leaving the device
// on an inbound page. That suppression is load-bearing, not cosmetic — the hook's own comment records
// #32 firing on 62 of 158 benign fetched pages. An adapter that skipped it would publish a
// false-positive rate the shipped product does not have. So the same two ids are dropped here, at the
// "output" stage only, exactly as the hook does. Set MOORAI_ADAPTER_RAW_OUTPUT=1 to turn the
// suppression off and see the raw-engine numbers instead.
//
// WHAT THIS ADAPTER DOES **NOT** REPRODUCE, stated so the number is not read as more than it is. The
// same `dropOutboundOnly` call also consults `INBOUND_GATES` — per-threat predicates (currently for
// threats 15 and 17) that keep a finding only when the ingested text also matches an egress-shaped
// pattern. Those live as private module state inside cli/moorai-hook.mjs, which cannot be imported
// without executing the hook, so they are NOT replicated here. The consequence is one-directional and
// worth saying plainly: this adapter's INBOUND (stage "output") false-positive rate is an UPPER BOUND
// on what MoorAI's shipped hook produces, never an under-count. Recall is unaffected — a gate can only
// remove findings.
//
// WHAT `action` MEANS HERE. Prevention is derived from `threatActionFor(policy, threatId)` — the same
// function MoorAI's shipped hook enforces with — under the BUILTIN-DEFAULT posture (policy = null,
// i.e. a device with no org policy at all). It is never derived from the fact that a detector fired,
// and never from a detector's own `mode`, because the enforcement path ignores that field.
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

// The two outbound-only threat ids the shipped hook suppresses on INGESTED content. Kept as a literal
// set with the citation above rather than imported, so this adapter stays a read-only consumer of the
// MoorAI checkout and cannot break when that file moves.
const OUTBOUND_ONLY_THREATS = new Set([65, 32]);

let engine = null;
let threatActionFor = null;
let runAgentDetections = null;
let version = "unknown";

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
    try { version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version || "unknown"; } catch { /* keep "unknown" */ }
    this.version = version;
  },

  async scanText(text, stage) {
    const st = stage || "prompt";
    const findings = toFindings(engine.scan(String(text ?? ""), st));
    if (st === "output" && !process.env.MOORAI_ADAPTER_RAW_OUTPUT) {
      // cli/moorai-hook.mjs handlePostToolUse -> dropOutboundOnly(raw, new Set([65, 32]), ...)
      return findings.filter((f) => !OUTBOUND_ONLY_THREATS.has(f.id));
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
      // BUILTIN-DEFAULT posture: no org policy. Same function the shipped PreToolUse hook enforces with.
      action: threatActionFor(null, id)
    });
  }
  return out;
}
