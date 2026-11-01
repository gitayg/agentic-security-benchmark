# Results

**One file per product.** This directory is meant to hold more than one entry, and it is not
interesting until it does.

MoorAI is the first row because somebody had to be. It is not the reference standard, and a result
here is not an endorsement of anything — it is a number with its conditions attached, which is the
only kind of number worth publishing.

Files are replaced rather than accumulated, one per product. `moorai-v0.79.6.json` was the previous
row; it was produced by a harness that scored vector 4 through a text flattening that no longer
exists, so it is superseded rather than kept alongside. It is still in git history.
`moorai-v0.79.9.json` is superseded the same way. Two builds were scored for its replacement,
`moorai-v1.46.1.json` and `moorai-v1.47.0.json`; one row is kept when the result is published and the
other dropped. Both were produced by the adapter at `c9ef086` (benchmark 0.5.1), named in each file's
`product.adapterVersion`. The corpora had grown in
between (vector 3's runtime-preload set, 286 → 299 attacks, 875 → 878 benign), so the like-for-like
comparison is 0.79.9 re-run on today's corpora, listed in the new file's `knownDeviations`.

## What is here

| File | Product | Recall | FP rate | Run by | Conflict of interest |
|---|---|--:|--:|---|---|
| `moorai-v1.46.1.json` | MoorAI agent 1.46.1 | 77.6% (232/299) | 4.9% (43/878) | the benchmark maintainer | **Yes — same author.** Stated, not hidden. |
| `moorai-v1.47.0.json` | MoorAI agent 1.47.0 | 77.9% (233/299) | 4.9% (43/878) | the benchmark maintainer | **Yes — same author.** Stated, not hidden. |
| `keyword-baseline.json` | `keyword` reference adapter | 40.3% (85/211) | 5.0% (42/841) | the benchmark maintainer | None. Floor, not a product. |
| `null-floor.json` | `null` adapter | 0.0% (0/286) | 0.0% (0/875) | the benchmark maintainer | None. Harness sanity check. |
| `TEMPLATE.json` | — | — | — | — | Copy this. |

Read that table with the limits attached, not as a ranking:

- **None of these recall figures has had a model-refusal baseline subtracted.** This harness is
  deterministic and model-free, so every figure is a **raw detection rate** over the full attack
  corpus, not a product's marginal contribution. See [`../AMTSO.md`](../AMTSO.md) §3.
- **The denominators differ**, and that is correct. `keyword` implements `scanText` and nothing else,
  so the 28 vector-5 event and session samples and the 81 vector-4 action samples were never put to it
  and are excluded rather than counted as misses — its denominator is 211, not 286. Compare rates,
  never raw counts.
- **MoorAI's number includes a tune half it was developed against.** It scores 98.4% (60/61) on
  `heldout-v2-tune`, which measures memorisation rather than generalisation. That corpus is in the
  total, so the 77.6% / 77.9% is flattered by it. This is stated rather than corrected because removing it
  would be a different kind of dishonesty — the fix is to read the per-corpus breakdown.
- **MoorAI's adapter has documented deviations** from the shipped product, listed in its own
  `knownDeviations` field, each with a measured size rather than a caveat:
  - **Inbound: none left.** From agent v1.4.0 the adapter calls the checkout's own
    `cli/inbound.mjs` `decideInbound` rather than a copy of it. At 1.46.1 it agrees sample-for-sample
    with MoorAI's own hook-spawning scorer — 10 false positives of 149 either way, the same ids and
    threats, 8 of 9 true positives — and fires the same threat ids as the real hook on all 207
    output-stage texts in the corpora (1.47.0 likewise). (At 0.79.9, through the literal copy older checkouts still use,
    the figure was 27/149.)
  - **Vector 4: fixed, and reconciled.** The adapter now implements `scanAction` and spawns the
    product's real PreToolUse hook as a subprocess against a sandboxed `HOME`, at the same
    out-of-the-box posture the text side uses. It agrees with MoorAI's own `scripts/score-vector24.mjs
    --mode builtin` sample-for-sample: at 1.46.1, 25/57 stopped and 1/24 false positive on both sides,
    the same 32 missed ids, the same one false-positive id; at 1.47.0, 26/57 at the harm step and
    27/57 at any step on both sides (`v4-chain-002` is asked at its first step and allowed at the harm
    step). Residual divergence: **zero**. The previous harness
    flattened those 81 tool calls to text and reported 20/57 prevented, 36/57 detected and 3/24 FP —
    the detection figure had no hook analogue at all. That is the whole of the movement in MoorAI's
    overall number: every other corpus scores identically to the 0.79.6 file.
  - **No enrolled tenant policy**, so prevention is understated — by roughly 18/57 → 43/57 on vector
    4, measured at 0.79.9 and not re-measured at 1.46.1. `MOORAI_POLICY` now makes that a parameter on both surfaces, but no number here was
    produced with it.

`null-floor.json` and `keyword-baseline.json` are not products and are not for sale. They exist so a
reader can tell whether a number is *good*. `null` must score exactly zero on both axes — if it ever
does not, the harness is broken and every other result here is suspect. `keyword` is a naive regex
matcher; a real product that does not comfortably beat it on **both** recall and false positives has
not demonstrated much.

## Adding your product

1. Write an adapter implementing the interface in [`../scorers/README.md`](../scorers/README.md).
   It has one required method.
2. Run the harness and capture the JSON:
   ```
   node scorers/run.mjs --adapter ./path/to/your-adapter.mjs --corpus all --json > results/yourproduct-vX.Y.Z.json
   ```
   Then copy the `product` block out of [`TEMPLATE.json`](./TEMPLATE.json) into it and fill it in.
   **`product` is the only block you write** — the `--json` output has no `product` key, and every
   other block is pasted verbatim. Record `product.corporaCommit`
   (`git log -1 --format=%H -- corpora`): a result is only interpretable against a specific corpus
   state, and without it a reader who re-runs and gets a different number cannot tell whether the
   product changed or the corpus did.
3. Open a **Submit results for another product** issue with the outcome distribution, the exact
   command, and your conflict-of-interest declaration.
4. Open a PR adding the results file (and your adapter, if you want it in-tree). A maintainer
   reviews it — see [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## What a results file must state

These are not decoration. A file missing them will be asked to add them before it is merged.

- **Recall and false-positive rate on separate lines.** Never a single blended "block rate".
  A product tuned to alert on everything has perfect recall and is unusable.
- **The full AMTSO outcome distribution** — `prevented`, `detected-not-prevented`, `model-refusal`,
  `model-recognition`, `missed`, `inconclusive` — plus this harness's seventh bucket,
  `not-applicable`, for samples whose harness your adapter does not implement. `not-applicable` rows
  are excluded from every rate; that is the point of having the bucket. An adapter that only reads
  text must not appear to have *missed* the event-graph samples it was never shown.
- **Which corpora were run.** Partial runs are fine and are more honest than a padded total —
  say which.
- **Whether you ran a model-refusal baseline, and against which model.** A detection rate that has
  not subtracted what the underlying model refuses unaided is **not comparable** to one that has.
  This is the single most common way a published detection rate becomes uninterpretable, and it is
  why `AMTSO.md` exists.
- **Whether you keep your own locked held-out split.** A number from a corpus you tuned against
  measures memorisation. See [`../METHODOLOGY.md`](../METHODOLOGY.md).
- **Conflicts of interest.** "I am the vendor" is an acceptable answer. Not saying it is not.

## What is not measured here

No result in this directory is an independent test. Each is self-run by whoever submitted it, on
corpora that are authored rather than captured, using a harness that is deterministic and
model-free. **AMTSO has not reviewed, certified or endorsed this benchmark or any result in it.**

The mitigation on offer is not a certificate — it is that the corpora, the harness and the split
algorithm are all public, so a disagreement about a result is checkable rather than a matter of
trust. If a number here does not survive your re-run, open an issue and say so.
