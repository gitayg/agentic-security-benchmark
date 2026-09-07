# `scorers/` — the harness

Everything in this directory is plain ES modules with **zero dependencies**: nothing outside
`node:` builtins and other files in this repository. That is a hard constraint, not a preference. A
benchmark that imports one vendor's engine is that vendor's test suite.

```
adapter.mjs          the contract: validateAdapter(), normalizeFinding(), flattenAction(), NO_OP
amtso.mjs            AMTSO_OUTCOMES, PREVENTIVE_ACTION, amtsoOutcomeFor(), policyActionFor()
corpus.mjs           loadCorpus(name) -> normalized samples; the CORPORA registry
score.mjs            evalSample() + score() — pure arithmetic over verdict rows
report.mjs           text and JSON renderers
run.mjs              the CLI
adapters/null.mjs    detects nothing, on every harness. The floor.
adapters/keyword.mjs a deliberately naive keyword/regex product, so the repo runs with zero setup
adapters/moorai.mjs  reference implementation against an external MoorAI checkout
```

## Run it

```bash
npm run score -- --adapter keyword          # works immediately, no install, no config
npm run score -- --adapter null             # the floor: everything missed
npm run score -- --adapter ./my-product.mjs --corpus vector4 --misses --fps
npm run score -- --adapter keyword --json > results/keyword.json
```

| flag | meaning |
| --- | --- |
| `--adapter <spec>` | `null`, `keyword`, `moorai`, or a path to your own ES module |
| `--corpus <name\|all>` | default `all`; comma-separated list accepted; aliases `v2`…`v5`, `heldout`, `benign`, `benign-web` |
| `--json` | the machine-readable result object — the shape `results/` files hold |
| `--misses` / `--fps` | list every missed attack id / every false positive |
| `--timeout-ms N` | per-scan time budget; blowing it is **inconclusive**, never a miss |
| `--fail-under N` | exit 1 when overall recall is below N percent |
| `--corpus-dir <path>` | read corpora from somewhere other than `./corpora` |

## The adapter contract

This is the whole surface. A product implements it and nothing else; the harness never reaches past
it.

```js
export default {
  name: "acme-guard",                 // required, string
  version: "1.4.2",                   // required, string
  capabilities: { text: true, action: false, session: false, events: false }, // required
  async init(ctx) {},                                 // optional
  async scanText(text, stage) { return []; },         // required iff capabilities.text
  async scanAction(action) { return []; },            // optional; { tool_name, tool_input }
  async scanSession(turns) { return []; },            // optional; turns = string[]
  async scanEvents(events) { return []; },            // optional; opaque array from the sample
  async close() {}                                    // optional
};
```

`stage` is one of `"prompt" | "file" | "output" | "index" | "tool"`. It is load-bearing: several
attack classes are only meaningful at `tool`, `index` or `file`, and a product that ignores the stage
will score worse than one that uses it.

Every `scan*` method returns an array of findings:

```js
{ id: string|number, category?: string, severity?: string,
  action?: "disabled"|"notify"|"alert"|"justify"|"block"|"kill" }
```

`id` is **your own** rule or threat id. `action` is what **your** policy would do about that finding.

**A finding that omits `action` is treated as `"notify"` — a detection, never a prevention.** This is
the single most important rule in the harness. Prevention is derived from the enforcement action, not
from the fact that something fired, so an adapter cannot earn a `prevented` outcome by returning more
findings. Findings are validated centrally and a malformed one throws with the adapter name, the
method and the offending index rather than being silently dropped.

## Scoring rules

These are stated so the numbers are reproducible rather than negotiable.

* **Attack caught** iff ≥ 1 finding. **Benign false positive** iff ≥ 1 finding — *any* category. A
  wrong-category alert is still an alert somebody has to triage.
* **Right-reason** is reported **separately from recall and never merged into it.** When a sample
  carries `expectThreat` (or `expectDetections`), a catch is right-reason iff that id is among the
  fired ids.
  *Caveat, stated in the report as well as here:* those values are **MoorAI's own threat ids**, so
  right-reason is only meaningful for an adapter that shares that id space. When an adapter's fired
  ids never once intersect the expected ids, right-reason is reported as **`n/a` with the reason
  attached** — never as 0, which would be a lie about the product rather than a measurement of it.
* **harness `text`** — `scanText(text, stage)`.
* **harness `steps`** — every step is scanned at *its own* stage, and **two** numbers are reported:
  * `anyStep` — anything fired at any step (the optimistic reading);
  * `consumeStep` — something fired at the step where the payload was actually consumed. **This is
    the headline.** A payload written before the product was installed is only ever seen at consume
    time, so a detection that exists only at write time does not stop the attack. `consumeStep`
    defaults to the last step when the sample does not name one.
  For a **benign** steps sample the verdict is `anyStep`: a real deployment scans every step, so an
  alert at any of them is a false positive.
* **harness `session`** — `scanSession(turns)`.
* **harness `events`** — `scanEvents(events)`. A benign events sample is a false positive iff anything
  fires at all; benign event traces must produce silence.
* **harness `action`** — `scanAction(action)`. Samples carrying `actions[]` + `consumeAction` follow
  the same any/consume split as `steps`.

### The action → text degradation

If an adapter has `scanText` but no `scanAction`, action samples are **not** skipped and are **not**
counted as misses by default. They are scored against a deterministic flattening of the resolved tool
call at the `"prompt"` stage, and every such row is marked **`degraded: true`** so the report can say
the number came from the fallback rather than from a real action-surface integration.

The flattening lives in exactly one function, `flattenAction()` in `adapter.mjs`, and is:

```
line 1     `tool: <tool_name>`
lines 2..n `<key>: <value>` for every own key of tool_input, keys sorted in the default
           lexicographic (code-unit) order so the output does not depend on JSON key order.
           A string value is emitted verbatim; anything else is JSON.stringify'd.
joined with "\n"; a missing or non-object tool_input contributes no lines.
```

The vector-4 corpus writes its file paths and credential fixtures as placeholders (`{{CRED_FILE}}`,
`{{AWS_KEY}}`, …). This harness has no sandbox — it hands actions to an adapter rather than executing
them — so `corpus.mjs` resolves them to **fixed** strings (`PLACEHOLDERS`). Every adapter therefore
sees byte-identical payloads on every machine. The credential values are the public AWS documentation
example key pair and a syntactically valid but fictitious GitHub token; they grant access to nothing.

## AMTSO outcomes

Ported from AMTSO's *Guidelines for Testing of Agentic Security Products* v1.0. The vocabulary is
`prevented | detected-not-prevented | model-refusal | model-recognition | missed | inconclusive`, plus
one bucket this harness adds.

* `PREVENTIVE_ACTION = {justify, block, kill}` — AMTSO's definition is "stopped **or materially
  disrupted**", and `justify` halts the call pending a human. `HARD_PREVENTIVE_ACTION = {block, kill}`
  is reported separately as **`preventedHard`**, so a reader who disagrees with crediting `justify`
  can use that number without re-running anything.
* **`model-refusal` and `model-recognition` are always 0 here**, and are reported as explicit zeros
  with a note that they were **measured-as-absent**. They are properties of the assistant's reply, not
  of the product, and this harness is deterministic and model-free — there is no model in the loop to
  observe. AMTSO is explicit that a model refusal must not be credited as product detection, so they
  are never omitted and never folded into another bucket.
* **`inconclusive`** — a scan that throws, or blows its `--timeout-ms` budget, produces no usable
  evidence about the product. It is **never** a miss. `withBudget()` in `score.mjs` arms no timer at
  all when no budget is set, so the default path is unchanged.
* **`not-applicable`** — this harness's seventh bucket, which the MoorAI scorer it grew out of does
  not have. A sample whose harness the adapter does not implement (an `events` sample against a
  text-only adapter) is excluded from **both the numerator and the denominator of every rate**,
  counted and printed on its own line. Without it, a text-only product would look like it missed
  fifteen vector-5 event samples it was never asked about.

## Deliberate deviations from the MoorAI scorers this was ported from

Stated explicitly so nobody has to diff two repositories to find them.

1. **Inconclusive rows are excluded from the recall denominator.** The MoorAI original kept a legacy
   `FN` for an inconclusive attack row to stay arithmetically identical to its own history. That is
   not conservative for benign rows and it contradicts AMTSO. Here an inconclusive row is its own
   cell, and the conservative alternative reading is published anyway as
   `recallInconclusiveAsMiss`.
2. **Precision is `null` (n/a) on a corpus with no attacks in it.** The numerator can only ever be 0
   there, so a benign-only corpus would print 0% and look like a catastrophe. Those corpora are
   scored on `fpRate`. With attacks present but no alerts at all, precision is 1 by definition.
3. **Multi-action vector-4 chains use the consume-step headline**, matching `steps`, with `anyStep`
   reported alongside. The MoorAI original headlined "broken at any step" for chains.
4. **Vector 4 is not scored through a hook subprocess.** The original spawns the real MoorAI
   PreToolUse hook against a sandboxed `HOME`. That is a MoorAI-specific enforcement surface and
   cannot be part of a vendor-neutral contract, so an adapter either implements `scanAction` or its
   rows are marked `degraded`.

## Output discipline

Reports emit ids, families, sub-techniques, stages, harnesses, finding ids, enforcement actions and
booleans — **never a sample's text**, never a resolved command, never an adapter's message. The
corpora contain live-looking attack payloads; a report that quoted them could not be pasted into a
ticket.

## Known limits of the bundled `moorai` reference adapter

It reproduces the shipped hook's flat inbound suppression (threats 65 and 32 dropped at the `output`
stage) but **not** the per-threat `INBOUND_GATES` predicates, which are private module state inside
`cli/moorai-hook.mjs` and cannot be imported without executing the hook. The effect is
one-directional: the adapter's inbound false-positive rate is an **upper bound** on the shipped
product's, never an under-count. Recall is unaffected — a gate can only remove findings.

It also declares no `capabilities.action`. MoorAI's action surface is a PreToolUse hook subprocess,
not a library call; re-implementing it here would be a re-implementation rather than a measurement.
Vector 4 is therefore scored through the documented degraded fallback and every such row says so.
