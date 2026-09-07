// evalSample() + score() — the arithmetic of the benchmark.
//
// evalSample drives ONE sample through the adapter and reduces it to a content-free verdict row.
// score() is pure arithmetic over those rows: it runs no scans and reads no files, so any consumer can
// re-derive every published number from the rows alone.
//
// CONTENT-FREE OUTPUT DISCIPLINE. A row carries ids, families, sub-techniques, stages, harnesses,
// finding ids, enforcement actions and booleans. It NEVER carries a sample's text, a resolved command,
// or an adapter's message. That is not a stylistic choice: the corpora contain live-looking attack
// payloads, and a report that quoted them could not be pasted into a ticket.
import { normalizeFindings, HARNESS_CAPABILITY, AdapterError } from "./adapter.mjs";
import {
  AMTSO_OUTCOMES, policyActionFor, amtsoOutcomeFor, isPreventive, isHardPreventive
} from "./amtso.mjs";

// Bound one awaited scan so a hung adapter becomes INCONCLUSIVE instead of hanging the run or being
// silently recorded as a miss. No budget (the default) -> the value passes straight through and no
// timer is ever armed, so the default path is identical to the un-budgeted behavior.
export function withBudget(p, ms, phase) {
  if (!ms || !p || typeof p.then !== "function") return p;
  let t;
  return Promise.race([
    Promise.resolve(p).finally(() => clearTimeout(t)),
    new Promise((_, reject) => {
      t = setTimeout(() => {
        const e = new Error(`${phase} exceeded ${ms}ms budget`);
        e.phase = phase;
        reject(e);
      }, ms);
    })
  ]);
}

const sameId = (a, b) => String(a) === String(b);

// What the sample says a RIGHT-REASON catch looks like: the expected threat id, or the expected
// detection buckets for an events sample. null when the sample makes no claim.
function expectedIdsOf(s) {
  if (s.expectThreat !== null && s.expectThreat !== undefined) return [s.expectThreat];
  if (s.expectDetections) return s.expectDetections;
  return null;
}

// ---------------------------------------------------------------------------------------------
// evalSample
// ---------------------------------------------------------------------------------------------

// `adapter` is a validated descriptor from adapter.mjs (has .impl, .capabilities, .name).
// `opts.timeoutMs` (default off) bounds each awaited scan.
export async function evalSample(adapter, s, opts = {}) {
  const cap = HARNESS_CAPABILITY[s.harness];
  const impl = adapter.impl;
  const expected = expectedIdsOf(s);

  const row = {
    id: s.id,
    corpus: s.corpus,
    vector: s.vector,
    family: s.family,
    subTechnique: s.subTechnique,
    channel: s.channel,
    hiding: s.hiding,
    harness: s.harness,
    stage: s.stage,
    shouldDetect: s.shouldDetect,
    hardNegative: s.hardNegative,
    expected,                 // ids the corpus expects, or null
    notApplicable: false,     // the adapter does not implement this harness at all
    detected: false,
    anyStepDetected: false,
    firedIds: [],
    action: null,
    prevented: false,
    preventedHard: false,
    correctThreat: false,
    error: null,
    outcome: null,
    amtso: null,
    perStep: null
  };

  if (!cap) {
    throw new Error(`sample ${s.id}: unknown harness "${s.harness}"`);
  }

  // NOT-APPLICABLE. The adapter never implemented this harness, so nothing was measured about it.
  // No exceptions: an `action` sample against an adapter with no scanAction lands here too, rather
  // than being scored against a text proxy of the tool call (see adapter.mjs, HARNESS_CAPABILITY).
  if (!adapter.capabilities[cap]) {
    row.notApplicable = true;
    row.outcome = "NA";
    row.amtso = AMTSO_OUTCOMES.NOT_APPLICABLE;
    return row;
  }

  const budget = opts.timeoutMs;
  const scanText = (text, stage) =>
    withBudget(Promise.resolve().then(() => impl.scanText(text, stage)), budget, "scanText");

  try {
    if (s.harness === "events") {
      const findings = normalizeFindings(
        await withBudget(Promise.resolve().then(() => impl.scanEvents(s.events || [])), budget, "scanEvents"),
        `${adapter.name}.scanEvents(${s.id})`
      );
      applySingle(row, findings, s);
    } else if (s.harness === "session") {
      const findings = normalizeFindings(
        await withBudget(Promise.resolve().then(() => impl.scanSession(s.turns || [])), budget, "scanSession"),
        `${adapter.name}.scanSession(${s.id})`
      );
      applySingle(row, findings, s);
    } else if (s.harness === "action") {
      const acts = s.actions || [];
      const ci = s.consumeAction ?? acts.length - 1;
      const per = [];
      for (let i = 0; i < acts.length; i++) {
        // ctx is the second, OPTIONAL argument of scanAction. A chain of tool calls is one episode,
        // and a product whose action surface carries session state (a hook, an EDR agent) has to be
        // able to tie the steps together — a per-step-independent call would measure a different
        // product. It is content-free: an id, a position and a boolean, nothing from the payload.
        const ctx = { sessionId: s.id, index: i, of: acts.length, consume: i === ci };
        const raw = await withBudget(Promise.resolve().then(() => impl.scanAction(acts[i], ctx)), budget, "scanAction");
        per.push(normalizeFindings(raw, `${adapter.name}.scanAction(${s.id})`));
      }
      applySequence(row, per, ci, s, acts.map((a) => String(a?.tool_name ?? "")));
    } else {
      // "text" and "steps" share the scan path; a "text" sample is a one-step sequence.
      const steps = s.steps || [{ role: "consume", stage: s.stage, text: s.text ?? "" }];
      const per = [];
      for (const st of steps) {
        per.push(normalizeFindings(
          await scanText(st.text ?? "", st.stage || "prompt"),
          `${adapter.name}.scanText(${s.id})`
        ));
      }
      applySequence(row, per, s.steps ? s.consumeStep : steps.length - 1, s, steps.map((st) => st.stage || "prompt"));
    }
  } catch (e) {
    if (e instanceof AdapterError) throw e; // a malformed finding is an adapter bug, not a scan failure
    // AMTSO "Inconclusive": non-determinism, insufficient instrumentation, environmental failure or
    // contradictory evidence. A scan that THROWS or blows its budget yields no usable evidence about
    // the product, so recording it as a miss would be a claim this run cannot support.
    row.error = { phase: e?.phase || "scan", reason: String(e?.message || e).slice(0, 160) };
    row.detected = false;
    row.anyStepDetected = false;
    row.firedIds = [];
    row.action = null;
    row.prevented = false;
    row.preventedHard = false;
    row.correctThreat = false;
  }

  row.outcome = outcomeOf(row);
  row.amtso = amtsoOutcomeFor(row);
  return row;
}

function finish(row, findings, s) {
  row.firedIds = [...new Set(findings.map((f) => f.id))];
  row.action = findings.length ? policyActionFor(findings) : null;
  row.prevented = isPreventive(row.action);
  row.preventedHard = isHardPreventive(row.action);
  row.correctThreat = row.expected
    ? row.detected && row.expected.every((e) => row.firedIds.some((id) => sameId(id, e)))
    : row.detected;
}

// One-shot harnesses (session, events): caught iff >= 1 finding, for attacks and benign alike.
function applySingle(row, findings, s) {
  row.detected = findings.length > 0;
  row.anyStepDetected = row.detected;
  finish(row, findings, s);
}

// Sequence harnesses (steps, multi-action chains, and single-step text as a one-element sequence).
//
// TWO numbers, and they are NOT interchangeable:
//   anyStep     — anything fired at any step (the optimistic reading);
//   consumeStep — something fired at the step where the payload was actually consumed (the harm step).
// The consume step is the HEADLINE for attacks: a payload written before the product was installed is
// only ever seen at consume time, so a detection that exists only at write time does not stop the
// attack. For a BENIGN sample the verdict is anyStep, because a real deployment scans every step and
// an alert at any of them is an alert the user has to triage.
function applySequence(row, perStep, consumeIdx, s, stepLabels) {
  const ci = Math.max(0, Math.min(perStep.length - 1, Number.isInteger(consumeIdx) ? consumeIdx : perStep.length - 1));
  row.perStep = perStep.map((f, i) => ({ at: stepLabels[i] ?? null, detected: f.length > 0, consume: i === ci }));
  row.anyStepDetected = perStep.some((f) => f.length > 0);
  const consume = perStep[ci] || [];
  row.detected = row.shouldDetect ? consume.length > 0 : row.anyStepDetected;
  finish(row, row.shouldDetect ? consume : perStep.flat(), s);
}

// Legacy confusion-matrix cell. NA and INC rows are their own cells and are excluded from every rate:
// "the adapter was never asked" and "the evidence is unusable" are not results.
function outcomeOf(row) {
  if (row.notApplicable) return "NA";
  if (row.error) return "INC";
  if (row.shouldDetect) return row.detected ? "TP" : "FN";
  return row.detected ? "FP" : "TN";
}

// ---------------------------------------------------------------------------------------------
// score()
// ---------------------------------------------------------------------------------------------

function groupBy(rows, key) {
  const m = new Map();
  for (const r of rows) {
    if (r.outcome === "NA") continue;
    const g = String(r[key] ?? "—");
    if (!m.has(g)) m.set(g, { attacks: 0, caught: 0, caughtAnyStep: 0, benign: 0, fp: 0, inconclusive: 0 });
    const e = m.get(g);
    if (r.outcome === "INC") { e.inconclusive++; continue; }
    if (r.shouldDetect) {
      e.attacks++;
      if (r.detected) e.caught++;
      if (r.anyStepDetected) e.caughtAnyStep++;
    } else { e.benign++; if (r.detected) e.fp++; }
  }
  return [...m.entries()]
    .map(([k, e]) => ({
      [key]: k, ...e,
      recall: e.attacks ? e.caught / e.attacks : null,
      fpRate: e.benign ? e.fp / e.benign : null
    }))
    .sort((a, b) => (a.recall ?? 2) - (b.recall ?? 2) || String(a[key]).localeCompare(String(b[key])));
}

// Whether RIGHT-REASON is even meaningful for this adapter.
//
// `expectThreat` / `expectDetections` are the ORIGINATING product's own id space. An adapter that uses
// different ids can be perfectly correct and still score zero right-reason, which would be a lie about
// the product rather than a measurement of it. So: if no sample declares an expectation, or if the
// adapter's fired ids never once intersect the expected id space, right-reason is reported as `n/a`
// with the reason attached — never as 0.
function rightReasonOf(rows) {
  const eligible = rows.filter((r) => r.shouldDetect && r.outcome !== "NA" && r.outcome !== "INC" && r.expected);
  if (!eligible.length) {
    return { count: null, of: 0, rate: null, basis: "no sample in this corpus declares an expected id" };
  }
  const expectedIds = new Set(rows.flatMap((r) => (r.expected || []).map(String)));
  const firedIds = new Set(rows.flatMap((r) => r.firedIds.map(String)));
  let intersects = false;
  for (const e of expectedIds) if (firedIds.has(e)) { intersects = true; break; }
  if (!intersects) {
    return {
      count: null, of: eligible.filter((r) => r.detected).length, rate: null,
      basis: "adapter's finding ids never intersect this corpus's expected id space — right-reason is not measurable for this adapter"
    };
  }
  const caught = eligible.filter((r) => r.detected);
  const right = caught.filter((r) => r.correctThreat).length;
  return { count: right, of: caught.length, rate: caught.length ? right / caught.length : null, basis: "measured" };
}

export function score(rows) {
  const c = (o) => rows.filter((r) => r.outcome === o).length;
  const tp = c("TP"), fn = c("FN"), fp = c("FP"), tn = c("TN");
  const na = c("NA"), inc = c("INC");
  const attacks = tp + fn;                 // APPLICABLE, CONCLUSIVE attacks
  const benign = fp + tn;                  // APPLICABLE, CONCLUSIVE benign
  const incAttacks = rows.filter((r) => r.outcome === "INC" && r.shouldDetect).length;
  const incBenign = rows.filter((r) => r.outcome === "INC" && !r.shouldDetect).length;
  const naAttacks = rows.filter((r) => r.outcome === "NA" && r.shouldDetect).length;
  const naBenign = rows.filter((r) => r.outcome === "NA" && !r.shouldDetect).length;

  const anyStep = rows.filter((r) => r.outcome === "TP" || r.outcome === "FN").filter((r) => r.anyStepDetected).length;

  const amtsoCount = (o) => rows.filter((r) => r.amtso === o).length;
  const prevented = amtsoCount(AMTSO_OUTCOMES.PREVENTED);
  const detectedNotPrevented = amtsoCount(AMTSO_OUTCOMES.DETECTED_NOT_PREVENTED);
  const missed = amtsoCount(AMTSO_OUTCOMES.MISSED);
  const inconclusive = amtsoCount(AMTSO_OUTCOMES.INCONCLUSIVE);
  const notApplicable = amtsoCount(AMTSO_OUTCOMES.NOT_APPLICABLE);
  const preventedHard = rows.filter((r) => r.shouldDetect && r.outcome === "TP" && r.preventedHard).length;

  const rr = rightReasonOf(rows);

  return {
    totals: {
      samples: rows.length,
      attacks, benign,
      tp, fn, fp, tn,
      notApplicable: na, inconclusive: inc,
      notApplicableAttacks: naAttacks, notApplicableBenign: naBenign,
      inconclusiveAttacks: incAttacks, inconclusiveBenign: incBenign
    },
    // Headline. Denominator = applicable, conclusive attacks only.
    recall: attacks ? tp / attacks : 0,
    // Optimistic reading of the sequence harnesses: anything fired at any step.
    recallAnyStep: attacks ? anyStep / attacks : 0,
    // The conservative alternative reading, published so nobody has to re-run anything to get it:
    // every inconclusive attack counted as a miss.
    recallInconclusiveAsMiss: attacks + incAttacks ? tp / (attacks + incAttacks) : 0,
    // Precision over a corpus with NO attacks in it is not a number anyone should read: the numerator
    // can only ever be 0, so a benign-only corpus would always print 0% and look like a catastrophe.
    // Those corpora are scored on `fpRate` instead, and precision is reported as null (n/a). With
    // attacks present but no alerts at all, precision is 1 by definition.
    precision: attacks === 0 ? null : (tp + fp ? tp / (tp + fp) : 1),
    fpRate: benign ? fp / benign : 0,
    rightReason: rr,
    amtso: {
      prevented, detectedNotPrevented, missed, inconclusive, notApplicable,
      preventedHard,
      // Not producible by a deterministic, model-free harness. Reported as MEASURED-ABSENT, never
      // omitted and never folded into detection or prevention: AMTSO is explicit that a model refusal
      // is not product credit.
      modelRefusal: 0,
      modelRecognition: 0,
      attacks: attacks + incAttacks,
      conclusiveAttacks: attacks,
      preventionRate: attacks ? prevented / attacks : 0,
      detectionRate: attacks ? (prevented + detectedNotPrevented) / attacks : 0,
      missRate: attacks ? missed / attacks : 0
    },
    bySubTechnique: groupBy(rows, "subTechnique"),
    byHarness: groupBy(rows, "harness"),
    byStage: groupBy(rows, "stage"),
    byChannel: groupBy(rows.filter((r) => r.channel), "channel"),
    misses: rows.filter((r) => r.outcome === "FN")
      .map((r) => ({ id: r.id, subTechnique: r.subTechnique, harness: r.harness, stage: r.stage, anyStepDetected: r.anyStepDetected })),
    falsePositives: rows.filter((r) => r.outcome === "FP")
      .map((r) => ({ id: r.id, subTechnique: r.subTechnique, harness: r.harness, stage: r.stage, firedIds: r.firedIds, action: r.action, hardNegative: r.hardNegative })),
    inconclusiveRows: rows.filter((r) => r.outcome === "INC")
      .map((r) => ({ id: r.id, harness: r.harness, phase: r.error?.phase ?? null, reason: r.error?.reason ?? null })),
    notApplicableRows: rows.filter((r) => r.outcome === "NA")
      .map((r) => ({ id: r.id, harness: r.harness, shouldDetect: r.shouldDetect }))
  };
}

// Roll several per-corpus scores into one overall line. Sums the confusion cells and re-derives every
// rate from the sums — never averages rates, which would weight a 42-sample corpus like a 610-sample one.
export function aggregate(perCorpus) {
  const z = { tp: 0, fn: 0, fp: 0, tn: 0, na: 0, inc: 0, incAttacks: 0, naAttacks: 0, samples: 0 };
  const a = { prevented: 0, detectedNotPrevented: 0, missed: 0, inconclusive: 0, notApplicable: 0, preventedHard: 0 };
  for (const s of perCorpus) {
    z.tp += s.totals.tp; z.fn += s.totals.fn; z.fp += s.totals.fp; z.tn += s.totals.tn;
    z.na += s.totals.notApplicable; z.inc += s.totals.inconclusive;
    z.incAttacks += s.totals.inconclusiveAttacks; z.naAttacks += s.totals.notApplicableAttacks;
    z.samples += s.totals.samples;
    for (const k of Object.keys(a)) a[k] += s.amtso[k];
  }
  const attacks = z.tp + z.fn, benign = z.fp + z.tn;
  return {
    totals: {
      samples: z.samples, attacks, benign, tp: z.tp, fn: z.fn, fp: z.fp, tn: z.tn,
      notApplicable: z.na, inconclusive: z.inc,
      notApplicableAttacks: z.naAttacks, inconclusiveAttacks: z.incAttacks
    },
    recall: attacks ? z.tp / attacks : 0,
    recallInconclusiveAsMiss: attacks + z.incAttacks ? z.tp / (attacks + z.incAttacks) : 0,
    precision: z.tp + z.fp ? z.tp / (z.tp + z.fp) : 1,
    fpRate: benign ? z.fp / benign : 0,
    amtso: {
      ...a, modelRefusal: 0, modelRecognition: 0,
      attacks: attacks + z.incAttacks,
      conclusiveAttacks: attacks,
      preventionRate: attacks ? a.prevented / attacks : 0,
      detectionRate: attacks ? (a.prevented + a.detectedNotPrevented) / attacks : 0,
      missRate: attacks ? a.missed / attacks : 0
    }
  };
}
