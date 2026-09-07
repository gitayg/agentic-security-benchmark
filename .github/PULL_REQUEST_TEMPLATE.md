<!--
Open the issue form first. A PR that arrives with no corresponding issue will usually be asked to
back up and open one, because the labelling decisions are easier to argue before the JSON exists
than after.
-->

## What this changes

<!-- One or two sentences. Which corpus, how many samples, what they cover that is not covered today. -->

Related issue: #

## Type of change

- [ ] New attack sample(s)
- [ ] New benign control(s) / hard negative(s)
- [ ] Relabel of an existing sample (**changes numbers already published for other products**)
- [ ] Scorer / adapter change
- [ ] Documentation only

---

## Corpus checklist

Tick only what you have actually verified. An unticked box is fine and reviewable; a ticked box
that turns out to be false is the thing that wastes everyone's time.

- [ ] **Schema-valid JSON** — the file parses and keeps the top-level shape it already had.
- [ ] **Unique id** — unique across the *whole benchmark*, not just within the file it lives in.
- [ ] **Validity statement present** on every attack sample, and it names the concrete mechanism
      that makes the malicious outcome reachable **with the security product absent**. A sample
      whose validity statement cannot be written is not a valid sample.
- [ ] **All six AMTSO dimensions labelled** for attack samples — attack vector, target of
      protection, harm, required capability, plus the harness and stage the sample is actually
      reachable at. (Note: `vector3` and `vector5` omit the per-sample `attackVector` because the
      file declares it once; match the convention of the corpus you are editing.)
- [ ] **Hard-negative twin declared** — every `hard_negative: true` sample carries `twin_of`
      naming the attack sample or detector concept it is the near-twin of, so a future false
      positive is diagnosable in one line.
- [ ] **No secret-shaped strings** — no real credentials, and no new credential-shaped
      placeholder. New secret-shaped strings fail CI by design and must be added to
      `ALLOWED_PLACEHOLDER_SECRETS` in `test/validate-corpora.mjs` deliberately, with a reason.
      Placeholder-shaped fixtures trip GitHub push protection and block pushes for everyone.
- [ ] **Content-free** — no real person's, customer's or organisation's data; no captured real
      incident; every attacker host is a placeholder under `.example`.
- [ ] **No locked-split additions** — this PR adds nothing to a held-out / locked split, and
      leaks none of one (`split: "test"` rows and lock-shaped top-level keys fail CI).
- [ ] **`npm run validate` passes locally**, and I ran it *before* opening this PR rather than
      waiting for CI to tell me.
- [ ] **Apache-2.0** — I have the right to contribute this content and I license it under the
      repository's licence.

## For a relabel only

- [ ] I have said, in the issue, **how many samples the argument applies to** — one, or a whole
      channel.
- [ ] I understand this changes recall and false-positive rates already published for other
      vendors' products.

## For a results submission only

- [ ] Results are on my product's **own lines**; nothing is merged with another product's numbers.
- [ ] The **model-refusal baseline** is reported, with the exact model named — or its absence is
      stated plainly, because a detection rate that has not subtracted model refusals is not
      comparable.
- [ ] **Conflicts of interest are declared** (being the vendor is fine; concealing it is not).

---

## Verification

<!--
Paste the real output of `npm run validate`. Not "tests pass" — the actual output. If you changed
the validator itself, also say what you deliberately broke to confirm each new check goes red,
and what the failure message was.
-->

```
```

---

**Maintainer approval required.** Every addition, relabel and results submission needs review and
approval from @gitayg before it merges. CI passing is a floor, not a decision — a green run means
the sample is well-formed, not that it is a good sample.
