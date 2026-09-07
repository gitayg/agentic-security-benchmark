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
//   scanAction   -> the REAL cli/moorai-hook.mjs PreToolUse hook, spawned as a subprocess
//
// HOW scanAction WORKS, AND WHY IT IS A SUBPROCESS.
//
// MoorAI's action surface is not a library call: it is the PreToolUse hook (cli/moorai-hook.mjs) run
// as a subprocess against a sandboxed HOME. So this adapter drives exactly that, the same way
// MoorAI's own scripts/score-vector24.mjs and scripts/moorai-validate-blocking.mjs do — it
// re-implements none of the hook's logic. init() builds one throwaway sandbox HOME under the OS temp
// dir, plants the credential/benign/staging fixtures the corpus's placeholders name, and close()
// deletes it. Each scanAction call writes {tool_name, tool_input, session_id} to the hook's stdin and
// reads the permissionDecision back off its stdout.
//
//   decision "deny"  -> one finding, action "block"    (hard prevention)
//   decision "ask"   -> one finding, action "justify"  (prevention: halted pending a human)
//   decision "allow" -> no findings
//   anything else / a spawn failure / unparseable stdout -> THROWS, so the row is INCONCLUSIVE
//                       rather than a silent miss.
//
// The finding id is the threat id parsed out of the hook's own permissionDecisionReason ("#65"), so
// action findings live in the SAME id space as the scanText ones. A reason with no id falls back to
// "moorai.hook.<decision>".
//
// POSTURE. Two, and each one byte-matches a mode of scripts/score-vector24.mjs:
//   * default (no MOORAI_POLICY) -> score-vector24's "builtin" mode: the sandbox gets an enrollment
//     token (~/.moorai/config.json with an installToken) and NO org policy, so cli/hook-core.mjs
//     BUILTIN_DEFAULT_ACTIONS is the whole of the enforcement. This is the same posture the text side
//     scores under (policy === null), which is what makes the two halves of this adapter comparable.
//   * MOORAI_POLICY set -> score-vector24's "policy" mode: the policy file is planted in
//     ~/.moorai/hook-policy.json and no enrollment token is written. NOTE the one deviation from
//     score-vector24 here: it DERIVES `mcpAllow` from the servers its benign controls use; this
//     adapter plants the caller's policy verbatim, because inventing an allow-list on the caller's
//     behalf would be the benchmark writing the policy it then scores.
//
// The sandbox is a single HOME shared by every action sample in a run, and samples are scored in
// corpus order (attacks, then benign) — deliberately identical to score-vector24, because the hook
// accumulates content-free agent-behaviour events under HOME across calls.
//
// RECONCILED AGAINST THE SOURCE SCORER, not asserted. See the results file's knownDeviations and
// scorers/README.md for the measured agreement and the residual divergence.
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
// `threatActionFor` on the text side and planted in the hook's own policy cache on the action side,
// so its `threatPolicy` / `tierPolicy` keys mean exactly what they mean in the product. The DEFAULT
// stays null on purpose: a policy is a per-tenant configuration choice, and a headline measured
// under a policy the maintainer wrote for the occasion is a number about that policy. Anything
// published with MOORAI_POLICY set must say so and name the policy.
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { join, dirname, isAbsolute, resolve } from "node:path";
// The ONE thing this adapter imports from the harness, and it is imported rather than copied on
// purpose: corpus.mjs resolves the corpus's {{CRED_FILE}}-style tokens to fixed strings before any
// adapter sees them, and scanAction has to map those fixed strings back onto the paths of the
// sandbox it actually built. Copying the table would let the two drift into a silent mismatch, where
// the hook is handed a path to a file that does not exist and dutifully allows it.
import { PLACEHOLDERS } from "../corpus.mjs";

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
  const must = ["data/detectors.js", "data/content-rules.js", "src/engine.js", "cli/hook-core.mjs", "cli/moorai-hook.mjs", "data/threats.json"];
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

// ---------------------------------------------------------------------------------------------
// The ACTION surface: a sandboxed HOME plus a spawn of the real cli/moorai-hook.mjs.
//
// Everything here mirrors scripts/score-vector24.mjs's buildSandbox/hookEnv/runHook. It is a MIRROR
// rather than an import because that script lives in the product's repository, which this benchmark
// does not depend on for anything except the checkout the user points it at; and it is a mirror of
// the SCAFFOLDING only — the decision itself comes from the hook subprocess, which is the point.
// ---------------------------------------------------------------------------------------------

// Public, non-secret fixtures. These are the values corpus.mjs already resolved the corpus's
// {{AWS_KEY}} / {{AWS_SECRET}} / {{GH_TOKEN}} tokens to, asserted equal at init() so a corpus change
// cannot leave the sandbox writing one credential while the action payload names another.
const FIXTURE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const FIXTURE_AWS_SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1";
const FIXTURE_GH_TOKEN = "ghp_ABCDEFghijklMNOPqrstUVWXyz0123456789";
const FIXTURE_CRED = `AWS_SECRET_ACCESS_KEY=${FIXTURE_AWS_SECRET}\nAWS_ACCESS_KEY_ID=${FIXTURE_AWS_KEY}\n`;
const FIXTURE_BENIGN = "export function add(a, b) { return a + b; }\n";

let hookPath = null;
let sandbox = null;      // { home, credFile, benignFile, stageFile }
let pathRemap = null;    // [[fixed corpus string, sandbox path], ...] longest-first

function buildSandbox(root, policyObject) {
  const home = mkdtempSync(join(tmpdir(), "moorai-bench-v4-"));
  const sb = {
    home,
    credFile: join(home, "creds", ".env"),
    benignFile: join(home, "src", "math.js"),
    stageFile: join(home, "tmp", "staged.txt")
  };
  for (const f of [sb.credFile, sb.benignFile, sb.stageFile]) mkdirSync(dirname(f), { recursive: true });
  writeFileSync(sb.credFile, FIXTURE_CRED);
  writeFileSync(sb.benignFile, FIXTURE_BENIGN);
  writeFileSync(sb.stageFile, "");
  mkdirSync(join(home, ".moorai"), { recursive: true });
  if (policyObject) {
    // score-vector24.mjs "policy" mode: an unsigned policy in the cache. A fresh sandbox has no trust
    // anchor and no key pin, so the hook admits it as "unanchored" — the documented no-brick path.
    writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policyObject));
  } else {
    // score-vector24.mjs "builtin" mode: ENROLLED, no policy. cli/moorai-hook.mjs uses `installToken`
    // as its enrolled predicate; without this file the device is UNENROLLED and the hook is inert
    // (0/57 stopped), which is a different measurement, not a stricter one.
    writeFileSync(join(home, ".moorai", "config.json"),
      JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "benchmark-v4", installToken: "tok-benchmark-v4" }));
  }
  return sb;
}

// Map the FIXED strings corpus.mjs resolved the path placeholders to onto this sandbox's real paths.
// Longest first: "/home/agent" is a prefix of "/home/agent/creds/.env", and replacing it first would
// corrupt the longer paths.
function buildPathRemap(sb) {
  const pairs = [
    [PLACEHOLDERS["{{CRED_FILE}}"], sb.credFile],
    [PLACEHOLDERS["{{BENIGN_FILE}}"], sb.benignFile],
    [PLACEHOLDERS["{{STAGE_FILE}}"], sb.stageFile],
    [PLACEHOLDERS["{{HOME}}"], sb.home]
  ];
  for (const [from] of pairs) {
    if (typeof from !== "string" || !from) {
      throw new Error("scorers/corpus.mjs PLACEHOLDERS no longer defines the four vector-4 path tokens this adapter remaps.");
    }
  }
  // The credential tokens are NOT remapped: the sandbox writes exactly those values, so the payload
  // and the file on disk already agree. Assert that rather than assume it.
  const creds = [["{{AWS_KEY}}", FIXTURE_AWS_KEY], ["{{AWS_SECRET}}", FIXTURE_AWS_SECRET], ["{{GH_TOKEN}}", FIXTURE_GH_TOKEN]];
  for (const [token, want] of creds) {
    if (PLACEHOLDERS[token] !== want) {
      throw new Error(
        `scorers/corpus.mjs resolves ${token} to ${JSON.stringify(PLACEHOLDERS[token])}, but this adapter's ` +
        `sandbox fixture is ${JSON.stringify(want)}. The hook would be scanning a credential that is not ` +
        "the one on disk. Re-sync the fixture constants in scorers/adapters/moorai.mjs."
      );
    }
  }
  return pairs.sort((a, b) => b[0].length - a[0].length);
}

// Substituted into the SERIALIZED action so a path is remapped wherever it appears — a file_path, a
// shell command, an MCP argument, a file body. JSON.stringify/parse round-trip, same as the source
// scorer, so a path containing a character that needs escaping stays escaped.
function remapAction(action) {
  let ser = JSON.stringify(action);
  for (const [from, to] of pathRemap) ser = ser.replaceAll(from, JSON.stringify(to).slice(1, -1));
  return JSON.parse(ser);
}

// Curated, from-scratch env: PATH plus sandbox-scoped HOME/XDG, so every hook state path lands inside
// the sandbox and the user's real MoorAI config can never leak in. The server points at a closed port,
// so the fetch fails fast (connection refused) and the run is fully offline.
function hookEnv() {
  return {
    PATH: process.env.PATH || "/usr/bin:/bin",
    HOME: sandbox.home,
    USERPROFILE: sandbox.home,
    XDG_CONFIG_HOME: join(sandbox.home, ".config"),
    XDG_STATE_HOME: join(sandbox.home, ".local", "state"),
    MoorAI_SERVER: "http://127.0.0.1:1",
    MoorAI_TENANT: "benchmark-v4"
  };
}

// Spawn the REAL hook and read the decision off stdout. The hook prints a JSON decision only for
// deny/ask, prints nothing for allow, and always exits 0 (it is governance, not a sandbox).
//
// cwd is pinned to the sandbox. cli/moorai-hook.mjs's indexSurfacePaths() resolves project-relative
// paths (.mcp.json, .claude/settings.json) against process.cwd(), so an unpinned cwd would make the
// measurement depend on which directory the benchmark was invoked from. score-vector24.mjs leaves cwd
// at the product repo; the two agree anyway, which is stated as a measurement in the results file
// rather than assumed here.
function runHook(payload) {
  const res = spawnSync(process.execPath, [hookPath], {
    input: JSON.stringify(payload),
    env: hookEnv(),
    cwd: sandbox.home,
    encoding: "utf8",
    timeout: 20000
  });
  if (res.error) throw new Error(`cli/moorai-hook.mjs failed to run: ${res.error.message || res.error}`);
  const out = (res.stdout || "").trim();
  if (!out) return { decision: "allow", reason: "" };
  let parsed;
  try { parsed = JSON.parse(out); } catch { throw new Error(`cli/moorai-hook.mjs wrote unparseable stdout (${out.length} bytes)`); }
  const o = parsed.hookSpecificOutput || {};
  return { decision: o.permissionDecision || "allow", reason: String(o.permissionDecisionReason || "") };
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
  // All four. `action` is the real PreToolUse hook, spawned per tool call — see the header.
  capabilities: { text: true, action: true, session: true, events: true },

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

    // The action surface. One sandbox for the whole run, shared by every action sample, exactly as
    // scripts/score-vector24.mjs does it: the hook accumulates content-free agent-behaviour events
    // under HOME, so a fresh sandbox per sample would be a different deployment on every call.
    hookPath = join(root, "cli", "moorai-hook.mjs");
    sandbox = buildSandbox(root, policy);
    pathRemap = buildPathRemap(sandbox);
  },

  async close() {
    if (sandbox) rmSync(sandbox.home, { recursive: true, force: true });
    sandbox = null;
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

  // The real PreToolUse hook, one subprocess per tool call. `ctx.sessionId` is the harness's per-
  // SAMPLE id: every step of a multi-action chain shares it, which is what lets the hook's session
  // state see a chain as a chain. The `v4-` prefix reproduces score-vector24.mjs's own construction
  // (`session_id: \`v4-${s.id}\``) verbatim, so the two harnesses hand the hook the same string.
  async scanAction(action, ctx) {
    const payload = { ...remapAction(action), session_id: `v4-${ctx?.sessionId ?? "unknown"}` };
    const { decision, reason } = runHook(payload);
    if (decision === "allow") return [];
    if (decision !== "deny" && decision !== "ask") {
      // Not a miss and not a catch: the hook said something this adapter does not understand, which
      // is exactly the "contradictory evidence" the INCONCLUSIVE bucket is for.
      throw new Error(`cli/moorai-hook.mjs returned an unknown permissionDecision ${JSON.stringify(decision)}`);
    }
    // The hook's own reason carries the threat id ("MoorAI: blocked via Bash — #65 Data Exposure"),
    // so an action finding lands in the SAME id space as a scanText one.
    const m = /#(\d+)/.exec(reason);
    return [{
      id: m ? Number(m[1]) : `moorai.hook.${decision}`,
      category: "pretooluse-hook",
      severity: null,
      // deny = hard prevention; ask = the call does not auto-execute, it halts pending a human.
      // Derived from the hook's decision channel and nothing else — never from "a detector fired".
      action: decision === "deny" ? "block" : "justify"
    }];
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
