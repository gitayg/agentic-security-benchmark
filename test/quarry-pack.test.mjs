// Quarry rule pack gate — quarry/.
//
//   node --test            (runs with the corpus validator)
//
// Runs without Quarry. It reads every .rule file with a small parser for the subset the pack uses,
// compiles each declared pattern as a JavaScript RegExp, and checks that the rule matches its paired
// quarry/data/<name>.json and does not match <name>.negative.json or the benign control. It also checks
// the structure Quarry itself enforces: one rule per file, unique rule names, the conversation contract
// in Quarry's docs/messages.md (allowed roles and keys, unique tool-call ids, no orphan or early tool
// responses), and that rules outside quarry/rules/flow/ use only the simplest Quarry forms (one
// declaration, one contains condition). Whether MoorAI imports a rule is checked separately, at the end. Quarry runs regexes on RE2; the patterns here are restricted to syntax both engines read the
// same way (asserted below, not assumed). On ASCII text without \r or \v the two engines agree; the
// remaining differences (\s, ., non-ASCII case folding) are listed in quarry/README.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACK = join(ROOT, "quarry");
const RULES = join(PACK, "rules");
const FLOW = join(RULES, "flow");
const DATA = join(PACK, "data");

// ------------------------------------------------------------------------------- parser ----

function tokenize(src) {
  const toks = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (src.startsWith("//", i)) { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\n") throw new Error(`newline inside a string at ${i}`);
        j += src[j] === "\\" ? 2 : 1;
      }
      if (j >= src.length) throw new Error(`unterminated string at ${i}`);
      toks.push({ t: "str", raw: src.slice(i + 1, j), at: i });
      i = j + 1;
      continue;
    }
    const m = /^(\$[A-Za-z_]\w*|[A-Za-z_]\w*:?|\d+|[()[\],.=*:~#@<>!]+)/.exec(src.slice(i));
    if (!m) throw new Error(`unexpected character ${JSON.stringify(c)} at ${i}`);
    toks.push({ t: "word", v: m[1], at: i });
    i += m[1].length;
  }
  return toks;
}

// A literal (no regex modifier) is decoded; the pack keeps literals free of escapes so decoding is exact.
function literal(raw) {
  assert.ok(!raw.includes("\\"), `literal ${JSON.stringify(raw)} carries an escape; use a regex declaration`);
  return raw;
}

function parseRule(src) {
  const toks = tokenize(src);
  const ruleCount = toks.filter((t) => t.t === "word" && t.v === "rule").length;
  let p = 0;
  const word = (v) => { const t = toks[p++]; assert.ok(t && t.t === "word" && t.v === v, `expected ${v}, got ${JSON.stringify(t)}`); };
  const str = () => { const t = toks[p++]; assert.ok(t && t.t === "str", `expected a string, got ${JSON.stringify(t)}`); return t.raw; };
  word("rule");
  const name = literal(str());
  const metadata = {};
  const strings = {};
  if (toks[p]?.v === "metadata:") {
    p++;
    while (toks[p] && toks[p].t === "word" && /^[A-Za-z_]\w*$/.test(toks[p].v) && toks[p + 1]?.v === "=") {
      const k = toks[p].v; p += 2;
      assert.ok(!(k in metadata), `duplicate metadata key ${k}`);
      metadata[k] = literal(str());
    }
  }
  if (toks[p]?.v === "strings:") {
    p++;
    while (toks[p] && toks[p].t === "word" && toks[p].v.startsWith("$")) {
      const n = toks[p].v; p++;
      word("=");
      let values;
      if (toks[p]?.v === "[") {
        p++;
        values = [];
        for (;;) {
          values.push(str());
          const t = toks[p++];
          if (t.v === "]") break;
          assert.equal(t.v, ",", `expected , or ] in ${n}`);
        }
      } else values = [str()];
      const mods = [];
      while (toks[p] && ["nocase", "fullword", "base64", "regex"].includes(toks[p].v)) mods.push(toks[p++].v);
      assert.ok(!(n in strings), `duplicate declaration ${n}`);
      strings[n] = { raw: values, mods };
    }
  }
  assert.ok(toks[p]?.v !== "variables:" && toks[p]?.v !== "parameters:", "the pack uses no variables: or parameters: block");
  assert.equal(toks[p]?.v, "condition:", `expected condition:, got ${JSON.stringify(toks[p])}`);
  const condition = src.slice(toks[p].at + "condition:".length).trim();
  return { name, metadata, strings, condition, ruleCount };
}

// A declaration as a JS matcher. regex: the raw token contents are the pattern, as Quarry passes them to
// RE2 (quarry/dsl/transformer.py string_def keeps raw_value for regex). nocase: case-folded.
function matcher(decl) {
  const ci = decl.mods.includes("nocase");
  if (decl.mods.includes("regex")) {
    const res = decl.raw.map((r) => new RegExp(r, ci ? "i" : ""));
    return (text) => typeof text === "string" && text !== "" && res.some((r) => r.test(text));
  }
  const lits = decl.raw.map(literal).map((l) => (ci ? l.toLowerCase() : l));
  return (text) => typeof text === "string" && text !== "" && lits.some((l) => (ci ? text.toLowerCase() : text).includes(l));
}

// ---------------------------------------------------------------------- conversation model ----

const flat = (c) => (typeof c === "string" ? c : Array.isArray(c) ? c.filter((x) => x.type === "text").map((x) => x.text).join("\n") : "");

// Events in conversation order. Each user message, each tool call and each tool response is one event.
function events(conv) {
  const ev = [];
  for (const m of conv.messages) {
    if (m.role === "user") ev.push({ surface: "user_messages", content: flat(m.content) });
    if (m.role === "assistant") for (const c of m.tool_calls || []) ev.push({ surface: "tool_calls", name: c.function.name, arguments: JSON.parse(c.function.arguments) });
    if (m.role === "tool") ev.push({ surface: "tool_responses", content: m.content });
  }
  return ev.map((e, i) => ({ ...e, i }));
}

// Values a field path reads: .content, .arguments.<key>, .arguments.* (every top-level value), .description.
function fieldValues(item, path) {
  if (path === "content") return [item.content];
  if (path === "description") return [item.description];
  if (path === "arguments.*") return Object.values(item.arguments || {}).filter((v) => typeof v === "string");
  const m = /^arguments\.([A-Za-z_]\w*)$/.exec(path);
  if (m) return [item.arguments?.[m[1]]];
  throw new Error(`unsupported field ${path}`);
}

// ------------------------------------------------------------------------ condition evaluator ----
//
// The condition shapes the pack uses, and nothing else (anything else throws, so a new shape cannot pass
// unchecked): a comprehension `any v in <surface> where v.<field> contains $s`, an `or` of them, a flow
// `A after(within: N) B` over those (A strictly after B, at most N events apart), and an `and` of flows.

function splitTop(s, sep) {
  const parts = [];
  let depth = 0, start = 0;
  const re = new RegExp(`^\\s${sep}\\s`);
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "(") depth++;
    else if (s[i] === ")") depth--;
    else if (depth === 0 && re.test(s.slice(i, i + sep.length + 2))) { parts.push(s.slice(start, i)); start = i + sep.length + 2; }
  }
  parts.push(s.slice(start));
  return parts.map((x) => x.trim());
}
function unwrap(s) {
  s = s.trim();
  while (s.startsWith("(") && s.endsWith(")")) {
    let depth = 0, closesAtEnd = true;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === "(") depth++;
      else if (s[i] === ")") depth--;
      if (depth === 0 && i < s.length - 1) { closesAtEnd = false; break; }
    }
    if (!closesAtEnd) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

const COMP = /^any ([A-Za-z_]\w*) in (user_messages|tool_responses|tool_calls|tools) where \1\.(content|description|arguments\.\*|arguments\.[A-Za-z_]\w*) contains (\$[A-Za-z_]\w*)$/;

function compHits(text, rule, conv) {
  const m = COMP.exec(text.replace(/\s+/g, " ").trim());
  if (!m) throw new Error(`unsupported comprehension: ${text}`);
  const [, , surface, field, decl] = m;
  assert.ok(rule.strings[decl], `${rule.name}: ${decl} is not declared`);
  const hit = matcher(rule.strings[decl]);
  if (surface === "tools") {
    const ok = (conv.tools || []).some((t) => fieldValues(t.function, field).some(hit));
    return ok ? [-1] : [];
  }
  return events(conv).filter((e) => e.surface === surface && fieldValues(e, field).some(hit)).map((e) => e.i);
}

function evalCond(cond, rule, conv) {
  return splitTop(unwrap(cond), "and").every((part) => {
    const p = unwrap(part);
    const flow = /\safter\(within:\s*(\d+)\)\s/.exec(p);
    if (flow) {
      const n = Number(flow[1]);
      const late = splitTop(unwrap(p.slice(0, flow.index)), "or").flatMap((c) => compHits(unwrap(c), rule, conv));
      const early = splitTop(unwrap(p.slice(flow.index + flow[0].length)), "or").flatMap((c) => compHits(unwrap(c), rule, conv));
      return late.some((l) => early.some((e) => l > e && l - e <= n));
    }
    return splitTop(p, "or").some((c) => compHits(unwrap(c), rule, conv).length > 0);
  });
}

// ----------------------------------------------------------------- Quarry conversation contract ----
// quarry/safety/validator.py validate_conversation at the pinned commit, restated for the data here.

const ROLE_KEYS = {
  system: ["role", "content"], developer: ["role", "content"], user: ["role", "content"],
  assistant: ["role", "content", "tool_calls", "refusal"], tool: ["role", "content", "tool_call_id"]
};
function checkConversation(conv, where) {
  assert.equal(typeof conv, "object", `${where}: not an object`);
  for (const k of Object.keys(conv)) assert.ok(["messages", "tools"].includes(k), `${where}: top-level key ${k} is not allowed`);
  assert.ok(Array.isArray(conv.messages) && conv.messages.length > 0, `${where}: messages must be a non-empty array`);
  const callAt = new Map(), responded = new Set();
  conv.messages.forEach((m, i) => {
    assert.ok(ROLE_KEYS[m.role], `${where}: message ${i} has role ${m.role}`);
    for (const k of Object.keys(m)) assert.ok(ROLE_KEYS[m.role].includes(k), `${where}: message ${i} (${m.role}) has key ${k}`);
    if (["system", "developer", "user"].includes(m.role)) assert.equal(typeof m.content, "string", `${where}: message ${i} needs string content`);
    if (m.role === "assistant") {
      assert.ok("content" in m || "tool_calls" in m, `${where}: assistant message ${i} has neither content nor tool_calls`);
      if ("tool_calls" in m) {
        assert.ok(Array.isArray(m.tool_calls) && m.tool_calls.length > 0, `${where}: message ${i} tool_calls must be non-empty`);
        for (const c of m.tool_calls) {
          assert.deepEqual(Object.keys(c).sort(), ["function", "id", "type"], `${where}: tool call keys`);
          assert.equal(c.type, "function");
          assert.ok(typeof c.id === "string" && c.id, `${where}: tool call id`);
          assert.ok(!callAt.has(c.id), `${where}: duplicate tool-call id ${c.id}`);
          assert.deepEqual(Object.keys(c.function).sort(), ["arguments", "name"], `${where}: tool call function keys`);
          assert.equal(typeof c.function.arguments, "string", `${where}: arguments must be a JSON string`);
          const a = JSON.parse(c.function.arguments);
          assert.ok(a && typeof a === "object" && !Array.isArray(a), `${where}: arguments must decode to an object`);
          callAt.set(c.id, i);
        }
      }
    }
  });
  conv.messages.forEach((m, i) => {
    if (m.role !== "tool") return;
    assert.equal(typeof m.content, "string", `${where}: tool message ${i} content`);
    assert.ok(callAt.has(m.tool_call_id), `${where}: tool message ${i} answers unknown call ${m.tool_call_id} (orphan response)`);
    assert.ok(callAt.get(m.tool_call_id) < i, `${where}: tool message ${i} comes before its call`);
    assert.ok(!responded.has(m.tool_call_id), `${where}: second response to ${m.tool_call_id}`);
    responded.add(m.tool_call_id);
  });
  if ("tools" in conv) {
    const names = new Set();
    for (const t of conv.tools) {
      assert.deepEqual(Object.keys(t).sort(), ["function", "type"], `${where}: tool keys`);
      assert.equal(t.type, "function");
      for (const k of Object.keys(t.function)) assert.ok(["name", "description", "parameters"].includes(k), `${where}: tool function key ${k}`);
      assert.ok(typeof t.function.name === "string" && t.function.name && !names.has(t.function.name), `${where}: tool names must be unique and non-empty`);
      names.add(t.function.name);
    }
  }
}

// ---------------------------------------------------------------------------------- inputs ----

const ruleFiles = [
  ...readdirSync(RULES).filter((f) => f.endsWith(".rule")).map((f) => ({ f, dir: RULES, flow: false })),
  ...readdirSync(FLOW).filter((f) => f.endsWith(".rule")).map((f) => ({ f, dir: FLOW, flow: true }))
];
const rules = ruleFiles.map(({ f, dir, flow }) => {
  const src = readFileSync(join(dir, f), "utf8");
  return { file: f, stem: f.replace(/\.rule$/, ""), flow, src, ...parseRule(src) };
});
const dataFiles = readdirSync(DATA).filter((f) => f.endsWith(".json"));
const readData = (f) => JSON.parse(readFileSync(join(DATA, f), "utf8"));

// RE2 and JavaScript read these the same way. Anything outside them is refused rather than trusted:
// lookaround and backreferences (RE2 has none), (?P< and \z (JS has none), \C, possessive quantifiers,
// inline flags (JS has no (?i)), and any letter escape other than the ones below.
const ALLOWED_ESCAPES = new Set(["b", "B", "d", "D", "s", "S", "w", "W", "n", "r", "t", "f", "x"]);
function re2CompatibleWithJs(p) {
  if (/\(\?(?:<?[=!]|P?<|[imsU-]+[:)])/.test(p.replace(/\\./g, "__"))) return "lookaround, named group or inline flag";
  if (/[*+?}]\+/.test(p.replace(/\\./g, "_"))) return "possessive quantifier";
  for (const m of p.matchAll(/\\(.)/g)) {
    const e = m[1];
    if (/[A-Za-z0-9]/.test(e) && !ALLOWED_ESCAPES.has(e)) return `escape \\${e}`;
    if (e === "x" && !/^\\x[0-9A-Fa-f]{2}/.test(p.slice(m.index))) return "\\x without two hex digits";
  }
  return null;
}

// The same secret shapes test/validate-corpora.mjs refuses in corpora/, applied to the pack. The
// allowlist is exact-match: the four placeholders the corpus validator already allows, plus two this
// pack adds deliberately (a Slack-shaped string that is plainly fake, and a PEM header whose body is
// no key material).
const FORBIDDEN_SECRET_SHAPES = [
  [/sk_live_[0-9a-zA-Z]{10,}/g, "Stripe live-key shape"],
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, "private key block"],
  [/AKIA[0-9A-Z]{16}/g, "AWS access key id"],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/g, "Slack token shape"],
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, "GitHub token shape"],
  [/AIza[0-9A-Za-z_-]{20,}/g, "Google API key shape"]
];
const ALLOWED_PLACEHOLDER_SECRETS = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "ghp_ABCDEF0123456789ABCDEF0123456789ABCD",
  "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  "AIzaSyEXAMPLE_KEY_NOT_REAL_000000000000",
  "xoxb-EXAMPLE-NOT-A-REAL-TOKEN-0000",
  "-----BEGIN RSA PRIVATE KEY-----"
]);

// -------------------------------------------------------------------------------- the tests ----

test("the pack has rules, and each file holds exactly one rule", () => {
  assert.ok(rules.length >= 15, `only ${rules.length} rules`);
  for (const r of rules) assert.equal(r.ruleCount, 1, `${r.file}: ${r.ruleCount} rule keywords`);
});

test("rule names are unique (Quarry rejects duplicate names when it loads a directory)", () => {
  const seen = new Map();
  for (const r of rules) {
    assert.ok(!seen.has(r.name), `${r.file} and ${seen.get(r.name)} share the name ${JSON.stringify(r.name)}`);
    seen.set(r.name, r.file);
  }
});

test("every rule carries the required metadata", () => {
  for (const r of rules) {
    const m = r.metadata;
    for (const k of ["description", "severity", "atlas", "moorai_threat", "source"]) assert.ok(m[k] && m[k].trim(), `${r.file}: metadata ${k} missing`);
    assert.ok(["critical", "high", "medium", "low"].includes(m.severity), `${r.file}: severity ${m.severity}`);
    assert.match(m.atlas, /^AML\.T\d{4}(?:\.\d{3})?(?:,AML\.T\d{4}(?:\.\d{3})?)*$/, `${r.file}: atlas ${m.atlas}`);
    assert.match(m.moorai_threat, /^[1-9]\d*$/, `${r.file}: moorai_threat ${m.moorai_threat}`);
    if (r.flow) assert.equal(m.requires, "quarry-engine", `${r.file}: a flow/ rule must say it needs Quarry's engine`);
    else assert.equal(m.requires, undefined, `${r.file}: a rule outside flow/ must not carry requires`);
    if ("moorai_mode" in m) {
      assert.ok(!r.flow, `${r.file}: a flow/ rule cannot import, so it carries no moorai_mode`);
      assert.equal(m.moorai_mode, "warn", `${r.file}: moorai_mode ${m.moorai_mode}`);
    }
  }
});

test("every pattern compiles in JavaScript and uses only syntax RE2 reads the same way", () => {
  for (const r of rules) {
    for (const [n, d] of Object.entries(r.strings)) {
      if (!d.mods.includes("regex")) continue;
      for (const p of d.raw) {
        assert.equal(re2CompatibleWithJs(p), null, `${r.file} ${n}: ${re2CompatibleWithJs(p)} in ${p}`);
        assert.doesNotThrow(() => new RegExp(p), `${r.file} ${n}: ${p}`);
      }
    }
  }
});

test("rules outside flow/ use only the simplest Quarry forms", () => {
  const IMPORTABLE = /^any (msg in user_messages where msg\.content|r in tool_responses where r\.content|call in tool_calls where call\.arguments\.[A-Za-z_]\w*) contains(?:_any)? \$[A-Za-z_]\w*$/;
  for (const r of rules.filter((x) => !x.flow)) {
    const decls = Object.values(r.strings);
    assert.equal(decls.length, 1, `${r.file}: one declaration`);
    for (const d of decls) for (const mod of d.mods) assert.ok(["nocase", "regex"].includes(mod), `${r.file}: modifier ${mod}`);
    assert.match(r.condition.replace(/\s+/g, " "), IMPORTABLE, `${r.file}: condition outside the simplest Quarry forms`);
  }
});

test("the flow/ directory says its rules need Quarry's engine", () => {
  const readme = readFileSync(join(FLOW, "README.md"), "utf8");
  assert.match(readme, /Quarry's (own )?engine/);
  assert.match(readme, /do not import/i);
});

test("every rule has a positive and a negative dataset, and no dataset is an orphan", () => {
  const stems = new Set(rules.map((r) => r.stem));
  for (const s of stems) {
    assert.ok(existsSync(join(DATA, `${s}.json`)), `quarry/data/${s}.json missing`);
    assert.ok(existsSync(join(DATA, `${s}.negative.json`)), `quarry/data/${s}.negative.json missing`);
  }
  for (const f of dataFiles) {
    if (f === "benign.json") continue;
    const stem = f.replace(/\.negative\.json$|\.json$/, "");
    assert.ok(stems.has(stem), `quarry/data/${f} has no rule`);
  }
  assert.ok(dataFiles.includes("benign.json"), "quarry/data/benign.json (the benign control) is missing");
});

test("every dataset is a conversation Quarry accepts (docs/messages.md)", () => {
  for (const f of dataFiles) checkConversation(readData(f), `quarry/data/${f}`);
});

test("each rule matches its positive dataset", () => {
  for (const r of rules) assert.equal(evalCond(r.condition, r, readData(`${r.stem}.json`)), true, `${r.file} does not match quarry/data/${r.stem}.json`);
});

test("each rule stays silent on its negative dataset", () => {
  for (const r of rules) assert.equal(evalCond(r.condition, r, readData(`${r.stem}.negative.json`)), false, `${r.file} matches quarry/data/${r.stem}.negative.json`);
});

test("no rule matches the benign control", () => {
  const benign = readData("benign.json");
  for (const r of rules) assert.equal(evalCond(r.condition, r, benign), false, `${r.file} matches quarry/data/benign.json`);
});

test("no secret-shaped string in the pack outside the exact placeholder allowlist", () => {
  const files = [...dataFiles.map((f) => join(DATA, f)), ...ruleFiles.map(({ f, dir }) => join(dir, f))];
  for (const path of files) {
    const text = readFileSync(path, "utf8");
    for (const [re, why] of FORBIDDEN_SECRET_SHAPES) {
      for (const m of text.match(new RegExp(re.source, "g")) || []) {
        assert.ok(ALLOWED_PLACEHOLDER_SECRETS.has(m), `${path}: ${why} not on the allowlist: ${JSON.stringify(m)}`);
      }
    }
  }
});

test("no pack file names a held-out or locked split", () => {
  for (const f of [...dataFiles, ...ruleFiles.map((x) => x.f)]) assert.doesNotMatch(f, /held-?out|locked/i);
});

// MoorAI imports a rule only when every pattern passes the agent's ReDoS guard (src/safe-regex.js: at most
// 400 characters, at most one unbounded quantifier, no ambiguous quantified alternation). The rules
// carrying moorai_mode must pass it; the rest fail it and ship in the agent as built-in detectors. The
// guard lives in the MoorAI agent, not in this repository, so this check runs only when MOORAI_AGENT_DIR
// points at an agent checkout and is skipped otherwise.
const AGENT = process.env.MOORAI_AGENT_DIR;
const GUARD = AGENT && join(AGENT, "src", "safe-regex.js");
test("rules with moorai_mode pass MoorAI's ReDoS guard, and no other rule does", { skip: GUARD && existsSync(GUARD) ? false : "set MOORAI_AGENT_DIR to a MoorAI agent checkout to run this check" }, async () => {
  const { redosReason } = await import(GUARD);
  for (const r of rules.filter((x) => !x.flow)) {
    const d = Object.values(r.strings)[0];
    const refused = d.raw.map((p) => redosReason(p)).filter(Boolean);
    if (d.mods.includes("nocase") && d.raw.some((p) => /[^\x00-\x7f]/.test(p))) refused.push("non-ascii-nocase");
    if (r.metadata.moorai_mode) assert.deepEqual(refused, [], `${r.file} carries moorai_mode but MoorAI refuses it: ${refused.join(", ")}`);
    else assert.notDeepEqual(refused, [], `${r.file} passes MoorAI's guard; give it moorai_mode or say why not`);
  }
});
