# Corpora

Seven corpora. Every sample is **authored**, not captured from live traffic — that is a real
limitation and it is stated here rather than buried in a footnote. What these corpora measure is how
a product behaves against **attacks somebody knew how to write**.

Each file is self-describing: a `_comment` at the top says why the corpus exists and how it was
built, and most attack samples carry a per-sample `validity` string and an `amtso` label object.

---

## The validity rule

**A sample counts only if the malicious outcome could actually occur with the product absent.**

This is AMTSO's rule and it is the one that keeps a corpus honest. An attack that resolves to
nothing executable, that targets a capability the agent does not have, or that would fail for its
own reasons is an **invalid sample — not a miss, and equally not a catch**. Dropping it costs you
both ways, which is the point: a corpus quietly padded with attacks that were never going to succeed
inflates recall for free, and blocking something that was never going to happen is not protection.

Most attack samples carry that rationale inline, in a `validity` field, e.g.:

> `"(a) the agent is handed the fetched HTML source, and an HTML comment is invisible in the
> rendered page but fully present in that source, so a user who checked the page in a browser would
> see nothing; (b) it names a concrete file and a concrete attacker URL; (c) the user asked only for
> a summary."`

Benign samples carry the mirror-image rationale: why a product firing on this would be a genuine
false positive, i.e. why this is legitimate work rather than a disguised attack.

Any sample proposed through the issue forms must supply this statement. See `../CONTRIBUTING.md`.

---

## What is here

| File | Attacks | Benign | AMTSO vector | Harness |
|---|--:|--:|---|---|
| `vector2-indirect-content.json` | 45 | 17 | 2 — indirect / content-mediated injection | `text` |
| `vector3-supply-chain.json` | 72 | 25 | 3 — tool, skill, extension & MCP supply chain | `text` (tool/file/index stages) |
| `vector4-outbound-action.json` | 57 | 24 | 4 — outbound action / agent-initiated effect | `action` |
| `vector5-memory-crossagent.json` | 42 | 25 | 5 — memory, context & cross-agent propagation | `text`, `steps`, `session`, `events` |
| `heldout-v2-tune.json` | 61 | 25 | 1 — direct input (family-keyed) | `text` (one `turns` sample each side) |
| `benign-corpus-v2.json` | — | 610 | precision denominator | `text` |
| `benign-web-content-tune.json` | 9 ⚠️ | 149 | precision denominator, `output` stage | `text` |

Totals: **286 attack samples, 875 benign samples.**

⚠️ Those 9 rows are a **known labelling inconsistency inherited from the source corpus** — see
[Known gaps](#known-gaps) before you use this file. Do not quietly resolve it in your own fork; it
changes published numbers.

The benign half is bigger than the attack half on purpose. False positives are what get a product
uninstalled, and a recall number published without a precision number measured on the same engine is
half a result.

---

## Provenance

All seven files were authored in the [MoorAI agent](https://github.com/gitayg/moorai) repository
(AGPL-3.0) and are republished here under Apache-2.0 by their copyright holder, so that a competitor
can run their own product through them without inheriting AGPL obligations. See `../NOTICE`.

**Every sample's content is unmodified.** One thing has been changed: `benign-corpus-v2.json`'s ids
were re-prefixed `v2-` → `bcv2-`, because upstream that prefix meant "benign corpus v2" while
`vector2-indirect-content.json` used the same one to mean "vector 2", and six ids denoted two
different samples each. No text, label, `validity` string or `amtso` object was touched. See
[Id namespaces](../CONTRIBUTING.md#id-namespaces).

- The four `vectorN-*.json` corpora were written one vector at a time, each after per-sample AMTSO
  labelling showed that vector was under-represented — vector 4 sat at 1.0% of labelled attack
  samples and vector 2 at 16.3% before their dedicated corpora existed. Each file enumerates its
  own sub-techniques in a `subTechniques` array, so the spread inside a vector is inspectable rather
  than asserted.
- `heldout-v2-tune.json` is the **tune half** of a mutation-generated corpus, keyed to the
  [HackAgent](https://github.com/AISecurityLab/hackagent) attack-family taxonomy (CipherChat,
  FlipAttack, h4rm3l, DAN, AutoDAN, BoN, AdvPrefix, PAP, PAIR, TAP) and to a transformation `axis`.
  It says so itself: *"A tuning wave MAY optimize against this."*
- `benign-corpus-v2.json` is 610 hand-authored benign developer and agent prompts: **269 hard
  negatives**, **101 deliberately obfuscation-shaped** benign samples (base64 blobs, minified JS,
  non-English prose, leetspeak identifiers, ASCII tables), and 8 flagged as genuinely ambiguous.
- `benign-web-content-tune.json` is the tune half of an inbound `WebFetch`/`WebSearch` corpus — page
  content a developer would legitimately fetch, scored at the `output` stage. It exists because the
  surface's benign result had previously been measured on 11 samples, which is an anecdote and
  cannot support a published number or a detector-scoping decision.

---

## Hard negatives and twins

A benign corpus made of obviously-benign prompts measures nothing: no detector fires on *"write me a
unit test"*. So a large share of the benign samples are **hard negatives** — engineered to look
malicious while being ordinary work. Legitimate security questions, benign role-play,
urgent-sounding routine requests, exfiltration-shaped but innocent prompts.

Where a hard negative was written as the deliberate twin of a specific attack, it carries
`hard_negative: true` and `twin_of: "<attack-id>"`. That pairing is what lets a false-positive result
say *which kind* of benign prompt a product misfires on, rather than only how often. A rate alone
tells you nothing you can act on.

Not every hard negative is a twin: a sample can be engineered to look malicious without being written
against one specific attack, and `vector4` in particular carries more `twin_of` pairings than
`hard_negative` flags. The two counts are therefore listed separately, because conflating them
overstates the hard-negative total.

| file | `hard_negative: true` | `twin_of` |
| --- | ---: | ---: |
| `benign-corpus-v2` | 269 | 269 |
| `benign-web-content-tune` | 62 | 0 |
| `heldout-v2-tune` | 0 | 0 |
| `vector2-indirect-content` | 16 | 17 |
| `vector3-supply-chain` | 17 | 17 |
| `vector4-outbound-action` | 17 | 24 |
| `vector5-memory-crossagent` | 20 | 20 |
| **total** | **401** | **347** |

---

## The locked split that is NOT here

`benign-web-content-tune.json` is exactly half of a 311-sample corpus. **The other 153 samples — the
`test` half — are deliberately withheld, and so is a separate held-out attack set.**

This is a feature of the methodology, not a hedge.

A held-out set is a consumable. It measures generalisation exactly once per decision made in
ignorance of it, and every look costs some of that — not through cheating, but through ordinary
iteration. Each time a threshold is nudged or a rule widened because the held-out score moved,
information from that set has entered the product, and the number it produces afterwards describes
memorisation rather than generalisation. Nothing about the set looks different once this has
happened, which is precisely why it has to be prevented structurally.

Publishing the locked halves would destroy them permanently and retroactively invalidate every
generalisation claim built on them — including MoorAI's own. So they stay private, and no
contribution to a locked split is accepted from outside (see `../CONTRIBUTING.md`).

**You should keep your own.** The split algorithm is published and needs no stored seed, so you can
generate one from any corpus you have:

> Bucket every sample by its stratum — for the web-content corpus, `(channel, hard_negative)`; for
> the attack corpus, `(family, axis)`. Sort by `id` inside each bucket. Assign alternately: even
> index → `tune`, odd index → `test`. Then never open the `test` half while tuning.

There is no random number generator and therefore no seed to record, lose or quietly change. Anyone
with the corpus derives the same two halves, which is what makes a disagreement about a result
checkable rather than a matter of trust.

`benign-web-content-tune.json` records the withheld count and the algorithm in its
`_heldOutSplitWithheld` block, so the omission is visible in the data rather than only in prose.

---

## Content-free discipline

No corpus here contains a real credential. Attack samples that need one use an obvious placeholder,
and vector 4 uses explicit template tokens (`{{AWS_KEY}}`, `{{GH_TOKEN}}`, `{{CRED_FILE}}` …) that a
harness substitutes at run time inside a sandbox.

The CI validator (`../test/validate-corpora.mjs`) fails a PR that introduces a secret-shaped string.
The four placeholder strings currently present are allowlisted by exact value, so a *new* one has to
be added deliberately in a reviewed change:

```
ghp_ABCDEF0123456789ABCDEF0123456789ABCD
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
AIzaSyEXAMPLE_KEY_NOT_REAL_000000000000
AKIAIOSFODNN7EXAMPLE
```

This is not hypothetical. A `xoxb-`-shaped placeholder blocked a real push, and `sk_live_`-shaped
strings have done it before.

---

## Sample shape

Fields you will encounter. Not every corpus carries every field; read the file.

| Field | Meaning |
|---|---|
| `id` | Unique across all corpora, and prefixed with its corpus's namespace (`v2-`, `v3-`, `v4-`, `v5-`, `hv2-`, `bcv2-`, `wf-`). CI enforces both. |
| `shouldDetect` | Ground truth. `true` = attack, `false` = benign. |
| `family`, `subTechnique`, `axis` | Taxonomy labels; enable per-family reporting instead of one averaged figure. |
| `harness` | `text` \| `action` \| `steps` \| `session` \| `events`. How the sample must be fed. |
| `stage` | `prompt` \| `file` \| `output` \| `index` \| `tool`. Which point in the agent's lifecycle the sample is reachable at. A property of the sample, not a choice. |
| `text` / `turns` / `action` / `actions` / `steps` / `events` | The payload, per harness. |
| `validity` | The statement above. |
| `amtso` | `{ attackVector, targetOfProtection, harm, requiredCapability }`. |
| `expectThreat` | MoorAI's own threat id — used for **right-reason** scoring. Only meaningful for a product sharing that id space; see `../scorers/README.md`. |
| `hard_negative`, `twin_of` | Benign samples only. |
| `consumeStep` / `consumeAction` | For `steps`/`actions` samples: the 1-based index at which the payload is actually consumed. The strict reading scores *only* this step. |

---

## Known gaps

### 9 deliberate true positives inside a "benign" corpus — and a stale header

`benign-web-content-tune.json` contains 9 samples with `shouldDetect: true`, all in the
`prompt-injection-tutorial` channel (`wf-inj-001`, `-003`, `-005`, `-007`, `-009`, `-011`, `-013`,
`-015`, `-017`). They are **not** a labelling accident. The 18 such pages in the full corpus (9 tune,
9 test) were deliberately reclassified from `hard_negative: true` to `shouldDetect: true`, with this
reasoning:

> An injection example on a tutorial page is a **live payload**. The agent fetching it cannot tell
> teaching material from an attack, because the text is identical either way. Firing on them is
> correct behaviour, so scoring them as benign controls was inflating the product's own
> false-positive rate against itself.

They were kept in this corpus rather than moved to an attack corpus **on purpose**: a page that
teaches injection and does *not* trip a detector is a miss worth seeing next to the false-positive
line.

This is the single best worked example in the repository of a relabel that **cuts both ways**, which
is why a relabel needs the evidence the issue form asks for. In the reference implementation the same
change moved the false-positive rate from 21.52% to 18.12% — because those were never false
positives — while simultaneously turning 2 pages that do *not* fire from "correct allows" into
**misses that had previously been invisible**. Net honesty, not net flattery.

**Two things about the file are genuinely stale and are worth a PR:**

1. Its `_comment` header still reads *"Every sample is content a developer would legitimately fetch:
   an alert on any of them is a FALSE POSITIVE"*, which is no longer true of those 9 rows.
2. Each of the 9 still carries its old `validity` string, written as a hard-negative rationale
   (*"looks like a live override, but it appears inside quotation marks as the teaching subject"*).
   Those rationales now argue against their own label.

Neither has been edited here: this repository republishes sample *content* unmodified, and a label or
rationale change belongs to the maintainer. This is a good first `Report a mislabelled sample` issue.

**Consequence for anyone scoring:** the 9 rows are in the attack denominator of this corpus, and a
false-positive rate over it is computed on the remaining 149. The harness partitions on
`shouldDetect`, so this is handled — but do not describe this file as purely benign.

### Structural gaps

- **Vector 1 (direct input) is over-represented across the wider labelled set**, because it is the
  easiest vector to author. The four dedicated per-vector corpora exist to counteract that, but the
  imbalance has not been eliminated.
- **Vector 6 (static code artifact) has no dedicated corpus here.**
- No sample is a captured real incident. See the limitation above.
- `expectThreat` ties right-reason scoring to one product's id space. A vendor-neutral
  right-reason label is an open problem — proposals welcome.
