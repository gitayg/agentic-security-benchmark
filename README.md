# Agentic Security Benchmark

**A corpus and a harness for measuring what an agentic-AI security product actually stops.**

You bring a product. You write about twenty lines of adapter. You get a recall number, a
false-positive number, and a distribution of outcomes graded against
[AMTSO's *Guidelines for Testing of Agentic Security Products* v1.0](https://www.amtso.org/wp-content/uploads/2026/09/AMTSO_Guidelines_for_Testing_of_Agentic_Security_Products_FINAL_V1.0.pdf).

```bash
git clone <this repo> && cd agentic-security-benchmark
npm run score -- --adapter keyword          # no npm install — there is nothing to install
```

**There is no install step.** Zero dependencies, no API key, no network call, no model in the loop,
no `node_modules`. Node 20+ and a clone is the whole setup; `npm run score` is equivalent to
`node scorers/run.mjs`.

That command runs a deliberately naive reference adapter so you can see the output shape immediately.
Swap in your own product and the same command scores it.

---

## Why this exists

Published detection rates for AI-agent security products are mostly uninterpretable. Not dishonest —
uninterpretable. A percentage with no stated corpus, no false-positive line, no held-out split, and no
model-refusal baseline is a number about nothing, and two products quoting the same figure can be
adding wildly different amounts of protection.

This repository is an attempt to fix that with shared infrastructure rather than another vendor
scorecard. Everything needed to disagree with a result is here: the samples, the scoring arithmetic,
the split algorithm, and the outcome vocabulary.

### The one idea most worth taking away

**A detection rate silently includes attacks the model would have refused unaided.**

An agent security product sits behind a model that already declines a large share of obvious attacks.
If you measure your product against a full attack corpus without first measuring what the bare model
refuses, you are credited with every one of those refusals. The number that describes what a product
*adds* is coverage of the **gap** — the attacks the model does *not* refuse on its own.

AMTSO states plainly that a model refusal must not be counted as product detection. Almost nobody
runs the baseline, because it can only ever lower your number. In the reference implementation it did
something more useful than lowering a number: it showed that an entire shipped detection wave bought
**almost no marginal protection**, because the model refused those families anyway. That produced a
rule worth stealing — *measure a family's refusal baseline before building detectors for it, and
build where the model complies.*

Full treatment in [`AMTSO.md`](./AMTSO.md).

---

## What is in here

| | |
|---|---|
| [`corpora/`](./corpora/README.md) | **286 attack samples, 875 benign**, across five AMTSO attack vectors. 225 of the 286 attacks carry a validity statement and 216 carry AMTSO labels; 102 carry all four label dimensions. (The gaps are per-corpus and are itemised in [`corpora/README.md`](./corpora/README.md) — the tune half of the held-out set carries neither.) A large share of the benign samples are **hard negatives** — legitimate work deliberately shaped to look like an attack. |
| [`scorers/`](./scorers/README.md) | The harness. A small adapter interface with **one required method**, plus three reference adapters (`null`, `keyword`, `moorai`). Zero dependencies. |
| [`AMTSO.md`](./AMTSO.md) | The outcome vocabulary, the six classification dimensions, baseline validation, and why model refusal must not be credited to the product. |
| [`METHODOLOGY.md`](./METHODOLOGY.md) | The locked split, right-reason scoring, falsification discipline, and how to grade your own product. |
| [`results/`](./results/README.md) | One file per product. Built to hold more than one. |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | How to propose a sample, and what it must satisfy. |

---

## Scoring your own product

An adapter is a single ES module. Only `scanText` is required.

```js
export default {
  name: "acme-guard",
  version: "1.4.2",
  capabilities: { text: true, action: false, session: false, events: false },

  async scanText(text, stage) {
    // stage ∈ "prompt" | "file" | "output" | "index" | "tool"
    return myProduct.inspect(text).map(hit => ({
      id: hit.ruleId,                 // your own rule id
      action: hit.blocking ? "block" : "notify"
    }));
  }
};
```

```bash
node scorers/run.mjs --adapter ./acme-adapter.mjs --corpus all --json > results/acme-1.4.2.json
```

**Every `scan*` returns an array of findings.** An empty array means "nothing fired" — that is a
normal answer, not an error.

```js
{ id: "RULE-17",            // REQUIRED. string or number. Your own rule/threat id.
  action: "block",          // optional. "disabled"|"notify"|"alert"|"justify"|"block"|"kill"
  category: "exfiltration", // optional, string
  severity: "high" }        // optional, string
```

**The one rule worth reading twice: a finding with no `action` is treated as `notify`, which is a
DETECTION and never a prevention.** Prevention is derived from the enforcement action your own policy
would take — `justify`, `block` or `kill` — never from the fact that something fired. You cannot earn
a "prevented" outcome by returning more findings. If your product's policy would only log, say
`notify`, and your prevention rate will correctly read low; that is the number, not a penalty.

A malformed finding (missing `id`, an `action` outside that list) **fails the run** with the adapter
name, the method and the offending index. It is never coerced or silently dropped, because a number
produced from a swallowed error is a number nobody can reproduce.

`init(ctx)` and `close()` are optional and run once each, around the whole run — that is where an
adapter loads a model, opens a socket, or checks that an external checkout is present.

Optional `scanAction`, `scanSession` and `scanEvents` unlock the action-, sequence- and event-graph
samples. **You are not penalised for omitting them.** Samples whose harness you do not implement land
in a `not-applicable` bucket and are excluded from every rate — a text-only product does not appear to
have *missed* fifteen event-graph samples it was never shown. The one exception is `action`: if you
have `scanText` but no `scanAction`, those samples are scored against a deterministic flattening of
the tool call and every such row is marked `degraded: true`, so a reader can tell a text scan from
action enforcement.

Details in [`scorers/README.md`](./scorers/README.md) — including the exact flattening format and the
right-reason rules. Adding your results: [`results/README.md`](./results/README.md).

---

## Proposing changes

Corpora only get better if people who are not the maintainer add to them. There are structured issue
forms for proposing an attack sample, proposing a benign sample, reporting a mislabelled sample, and
submitting results for another product.

Every addition requires maintainer approval, and the sample forms require the fields the methodology
depends on — attack vector, target of protection, harm type, required capability, the validity
statement, and for benign samples whether it is a hard negative and which attack it twins.

**Additions to a held-out split are not accepted from outside**, since that would compromise the
split. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

---

## Licensing: two separate projects

**This benchmark is Apache-2.0.** That is deliberate. Competitors must be able to run their own
products through it, and publish the results, without inheriting a copyleft obligation. A benchmark
nobody but its author can safely use is not infrastructure.

The corpora and harness originated in the **MoorAI agent**, which is **AGPL-3.0** and is a **separate
project**. Nothing here imposes AGPL obligations on a product under test. See [`NOTICE`](./NOTICE).

---

## Honest limits

Read these before quoting anything from this repository.

**AMTSO has not reviewed, certified or endorsed this benchmark, its corpora, its harness, or any
result published here.** The Guidelines are cited as published criteria that this benchmark grades
against. That is self-assessment, not accreditation. AMTSO is a trademark of the Anti-Malware Testing
Standards Organization.

**The corpora are authored, not captured.** No sample is a real incident and no deployment telemetry
feeds them. What a result describes is behaviour against *attacks somebody knew how to write*.

**MoorAI graded itself.** The first result in `results/` was produced by the author of both the
product and the benchmark, and it says so in its own `conflictOfInterest` field. It is not an
independent test and is not presented as one. No third-party lab has reproduced anything here.

**The published numbers have not had a refusal baseline subtracted.** This harness is deterministic
and model-free by design, so `model-refusal` and `model-recognition` are reported as
measured-as-absent zeros. Every recall figure in `results/` is therefore a **raw detection rate**, not
a marginal contribution — including MoorAI's.

**Vector 4 is scored against a text flattening, not a real action surface.** 81 rows in every result
here are marked `degraded: true` because no bundled adapter implements `scanAction`. Driving MoorAI's
real enforcement hook over the same 57 attacks stops 18 of them at the same posture, against 20
"prevented" from this harness — close, but the two are not the same measurement, and the *detection*
figure has no hook analogue at all. Numbers and method in
[`scorers/README.md`](./scorers/README.md#actions-vector-4--still-degraded-and-here-is-what-it-costs).

**Two of the seven corpora are half a corpus.** The locked test halves are withheld on purpose. See
below.

**Right-reason scoring is not vendor-neutral.** It keys off `expectThreat`, which holds one product's
threat ids, so it is reported as `n/a` for adapters that do not share that id space. A vendor-neutral
right-reason label is an open problem; proposals welcome.

**One "benign" corpus is not entirely benign,** and its header comment is stale. Nine of its samples
are deliberately labelled as attacks. [`corpora/README.md`](./corpora/README.md) explains why, and it
is the best worked example here of a relabel that cut both ways.

---

## The locked split, and why part of the corpus is missing

Two held-out splits are deliberately **not published**: the `test` half of the web-content benign
corpus, and a separate held-out attack set.

Their entire value is that nobody tunes against them — including the maintainer. A held-out set is a
consumable: it measures generalisation exactly once per decision made in ignorance of it. Tuning
against one silently converts it into a training set, not through cheating but through ordinary
iteration, and nothing about the set looks different afterwards. Publishing them would destroy them
permanently and retroactively invalidate every generalisation claim built on them.

**This is a feature of the methodology, not a hedge, and any vendor doing this properly should keep
one too.** The split algorithm is published and needs no stored seed, so you can generate your own:
bucket by stratum, sort by id inside the bucket, assign alternately — even index to `tune`, odd to
`test` — then never open the `test` half while tuning.

There is a live demonstration of why it matters in `results/`. MoorAI scores **100% recall (61/61)**
on `heldout-v2-tune` — the half its detectors were developed against. That figure measures
memorisation, not generalisation, and it is published here precisely so the gap between a tune-half
score and a locked-half score is visible rather than flattering.

[`METHODOLOGY.md`](./METHODOLOGY.md) has the full argument.
