// The ADAPTER CONTRACT. This is the entire surface a security product has to implement to be scored
// by this benchmark; nothing in scorers/ ever reaches past it, which is what makes the harness
// vendor-neutral and the numbers comparable.
//
// An adapter is an ES module with a DEFAULT EXPORT:
//
//   export default {
//     name: "acme-guard",                 // required, string
//     version: "1.4.2",                   // required, string
//     capabilities: { text: true, action: false, session: false, events: false }, // required
//     async init(ctx) {},                                 // optional
//     async scanText(text, stage) { return []; },         // required iff capabilities.text
//     async scanAction(action, ctx) { return []; },       // optional; action = { tool_name, tool_input }
//                                                         // ctx = { sessionId, index, of, consume }
//     async scanSession(turns) { return []; },            // optional; turns = string[]
//     async scanEvents(events) { return []; },            // optional; opaque array from the sample
//     async close() {}                                    // optional
//   };
//
// Every scan* method returns an ARRAY OF FINDINGS:
//
//   { id: string|number, category?: string, severity?: string,
//     action?: "disabled"|"notify"|"alert"|"justify"|"block"|"kill" }
//
// `action` is what the product's OWN policy would do about that finding. A finding that omits `action`
// is treated as "notify" — a DETECTION, never a prevention. That default is deliberate and is the
// single most important rule in this file: prevention is derived from the enforcement action, never
// from the fact that something fired. An adapter cannot earn a "prevented" outcome by returning more
// findings; only by returning findings whose action is justify/block/kill.
import { pathToFileURL } from "node:url";
import { isAbsolute, resolve } from "node:path";

export const STAGES = Object.freeze(["prompt", "file", "output", "index", "tool"]);
export const ACTIONS = Object.freeze(["disabled", "notify", "alert", "justify", "block", "kill"]);
export const HARNESSES = Object.freeze(["text", "steps", "session", "events", "action"]);

// Which capability flag a harness requires. A sample whose harness maps to a capability the adapter
// does not declare is NOT-APPLICABLE — never a miss, never a catch, excluded from every rate.
//
// THERE IS NO EXCEPTION, AND THERE USED TO BE ONE. Until result schema @2 an `action` sample was
// scored against a deterministic flattening of the tool call fed to scanText, and the row was marked
// `degraded`. That answered a different question from the one the corpus asks: a vector-4 sample is a
// RESOLVED ACTION, and the only thing that can stop it is a surface that sees tool calls. Scanning the
// prose form of an action measures a text scanner. The flattening is gone; an adapter with no
// scanAction now gets `not-applicable` on those rows, exactly like an events sample against a
// text-only adapter, and its denominator shrinks instead of being filled with a proxy measurement.
export const HARNESS_CAPABILITY = Object.freeze({
  text: "text",
  steps: "text",
  session: "session",
  events: "events",
  action: "action"
});

// Built-in adapters, resolvable by bare name so `npm run score -- --adapter keyword` needs no paths.
export const BUILTIN_ADAPTERS = Object.freeze({
  null: "./adapters/null.mjs",
  keyword: "./adapters/keyword.mjs",
  moorai: "./adapters/moorai.mjs"
});

export class AdapterError extends Error {}

// ---------------------------------------------------------------------------------------------
// Finding normalization
// ---------------------------------------------------------------------------------------------

// Normalize ONE finding and validate it hard. A malformed finding is a bug in the adapter, and a
// benchmark that silently swallowed it would report a number nobody can reproduce — so this throws
// with the adapter name, the method and the offending index rather than coercing.
export function normalizeFinding(f, where) {
  if (f == null || typeof f !== "object" || Array.isArray(f)) {
    throw new AdapterError(`${where}: finding must be an object, got ${Array.isArray(f) ? "array" : typeof f}`);
  }
  if (f.id === undefined || f.id === null || f.id === "") {
    throw new AdapterError(`${where}: finding is missing the required \`id\` (the product's own rule/threat id)`);
  }
  if (typeof f.id !== "string" && typeof f.id !== "number") {
    throw new AdapterError(`${where}: finding \`id\` must be a string or a number, got ${typeof f.id}`);
  }
  // The DETECTION-IS-NOT-PREVENTION default. No action declared => "notify" => allowed-but-reported.
  const action = f.action === undefined || f.action === null ? "notify" : f.action;
  if (!ACTIONS.includes(action)) {
    throw new AdapterError(`${where}: finding \`action\` must be one of ${ACTIONS.join("|")}, got ${JSON.stringify(f.action)}`);
  }
  if (f.category !== undefined && f.category !== null && typeof f.category !== "string") {
    throw new AdapterError(`${where}: finding \`category\` must be a string when present`);
  }
  if (f.severity !== undefined && f.severity !== null && typeof f.severity !== "string") {
    throw new AdapterError(`${where}: finding \`severity\` must be a string when present`);
  }
  return {
    id: f.id,
    category: f.category ?? null,
    severity: f.severity ?? null,
    action
  };
}

export function normalizeFindings(list, where) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) {
    throw new AdapterError(`${where}: expected an array of findings, got ${typeof list}`);
  }
  return list.map((f, i) => normalizeFinding(f, `${where}[${i}]`));
}

// ---------------------------------------------------------------------------------------------
// Adapter validation
// ---------------------------------------------------------------------------------------------

// Validate the module's default export and return a frozen descriptor. Throws AdapterError with an
// actionable message on anything malformed — an adapter author should never have to read a stack.
export function validateAdapter(mod, source = "<adapter>") {
  const a = mod && mod.default !== undefined ? mod.default : mod;
  if (!a || typeof a !== "object") {
    throw new AdapterError(`${source}: module must have a default export that is an object (see scorers/adapter.mjs)`);
  }
  if (typeof a.name !== "string" || !a.name) throw new AdapterError(`${source}: adapter.name must be a non-empty string`);
  if (typeof a.version !== "string" || !a.version) throw new AdapterError(`${source}: adapter.version must be a non-empty string`);
  if (!a.capabilities || typeof a.capabilities !== "object") {
    throw new AdapterError(`${source}: adapter.capabilities must be an object, e.g. { text: true, action: false, session: false, events: false }`);
  }
  const caps = {
    text: !!a.capabilities.text,
    action: !!a.capabilities.action,
    session: !!a.capabilities.session,
    events: !!a.capabilities.events
  };
  const need = [["text", "scanText"], ["action", "scanAction"], ["session", "scanSession"], ["events", "scanEvents"]];
  for (const [cap, fn] of need) {
    if (caps[cap] && typeof a[fn] !== "function") {
      throw new AdapterError(`${source}: capabilities.${cap} is true but adapter.${fn} is not a function`);
    }
  }
  if (!caps.text && !caps.action && !caps.session && !caps.events) {
    throw new AdapterError(`${source}: adapter declares no capabilities — there is nothing to score`);
  }
  for (const opt of ["init", "close"]) {
    if (a[opt] !== undefined && typeof a[opt] !== "function") {
      throw new AdapterError(`${source}: adapter.${opt} must be a function when present`);
    }
  }
  return Object.freeze({ impl: a, name: a.name, version: a.version, capabilities: Object.freeze(caps), source });
}

// Resolve `--adapter <spec>` to a module URL: a built-in bare name, or a path (relative to CWD).
export function resolveAdapterSpec(spec, baseUrl) {
  if (Object.prototype.hasOwnProperty.call(BUILTIN_ADAPTERS, spec)) {
    return { url: new URL(BUILTIN_ADAPTERS[spec], baseUrl).href, builtin: true };
  }
  const p = isAbsolute(spec) ? spec : resolve(process.cwd(), spec);
  return { url: pathToFileURL(p).href, builtin: false };
}

export async function loadAdapter(spec, baseUrl = import.meta.url) {
  const { url, builtin } = resolveAdapterSpec(spec, baseUrl);
  let mod;
  try {
    mod = await import(url);
  } catch (e) {
    if (builtin) throw e;
    throw new AdapterError(
      `could not load adapter "${spec}".\n` +
      `  Built-ins: ${Object.keys(BUILTIN_ADAPTERS).join(", ")}\n` +
      `  Anything else is treated as a path to your own ES module.\n` +
      `  Underlying error: ${e && e.message ? e.message : e}`
    );
  }
  return validateAdapter(mod, spec);
}

// ---------------------------------------------------------------------------------------------
// NO-OP defaults — the shape an adapter that implements nothing would have. Used by adapters/null.mjs
// and by tests; also documents that every optional method may simply be absent.
// ---------------------------------------------------------------------------------------------
export const NO_OP = Object.freeze({
  name: "no-op",
  version: "0.0.0",
  capabilities: Object.freeze({ text: true, action: true, session: true, events: true }),
  async init() {},
  async scanText() { return []; },
  async scanAction() { return []; },
  async scanSession() { return []; },
  async scanEvents() { return []; },
  async close() {}
});
