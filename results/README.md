# Results

**One file per product.** This directory is meant to hold more than one entry, and it is not
interesting until it does.

MoorAI is the first row because somebody had to be. It is not the reference standard, and a result
here is not an endorsement of anything — it is a number with its conditions attached, which is the
only kind of number worth publishing.

Files are replaced rather than accumulated, one per product. `moorai-v0.79.6.json` was the previous
row; it was produced by a harness that scored vector 4 through a text flattening that no longer
exists, so it is superseded rather than kept alongside. It is still in git history.

## What is here

| File | Product | Recall | FP rate | Run by | Conflict of interest |
|---|---|--:|--:|---|---|
| `moorai-v0.79.9.json` | MoorAI agent 0.79.9 | 74.1% (212/286) | 7.3% (64/875) | the benchmark maintainer | **Yes — same author.** Stated, not hidden. |
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
- **MoorAI's number includes a tune half it was developed against.** It scores 100% (61/61) on
  `heldout-v2-tune`, which measures memorisation rather than generalisation. That corpus is in the
  total, so the 74.1% is flattered by it. This is stated rather than corrected because removing it
  would be a different kind of dishonesty — the fix is to read the per-corpus breakdown.
- **MoorAI's adapter has documented deviations** from the shipped product, listed in its own
  `knownDeviations` field, each with a measured size rather than a caveat:
  - **Inbound: none left.** The adapter now replicates the shipped hook's whole `PostToolUse` path,
    including the `INBOUND_GATES` predicates it previously could not. It agrees sample-for-sample
    with MoorAI's own hook-spawning scorer on the same corpus — 27 false positives of 149 either way.
    The previous version of this file published 43.62% there as an *upper bound*; the real figure is
    18.12%, and the correction moved the overall FP rate from 12.0% (105/875) to 7.5% (66/875).
    Recall did not move: a gate can only remove findings.
  - **Vector 4: fixed, and reconciled.** The adapter now implements `scanAction` and spawns the
    product's real PreToolUse hook as a subprocess against a sandboxed `HOME`, at the same
    out-of-the-box posture the text side uses. It agrees with MoorAI's own `scripts/score-vector24.mjs
    --mode builtin` sample-for-sample: 18/57 stopped and 1/24 false positive on both sides, the same
    39 missed ids, the same one false-positive id. Residual divergence: **zero**. The previous harness
    flattened those 81 tool calls to text and reported 20/57 prevented, 36/57 detected and 3/24 FP —
    the detection figure had no hook analogue at all. That is the whole of the movement in MoorAI's
    overall number: every other corpus scores identically to the 0.79.6 file.
  - **No enrolled tenant policy**, so prevention is understated — by roughly 18/57 → 43/57 on vector
    4, measured. `MOORAI_POLICY` now makes that a parameter on both surfaces, but no number here was
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
