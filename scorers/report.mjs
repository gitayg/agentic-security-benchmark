// Rendering. Two renderers over the SAME score objects: a human report and the JSON object that
// results/ files hold. Neither renderer computes anything — every number here came out of score.mjs.
//
// Content-free: ids, families, sub-techniques, stages, harnesses, finding ids, actions and booleans.
// Never a sample's text.

const pct = (x) => (x == null ? "   n/a" : (x * 100).toFixed(1).padStart(5) + "%");
const num = (n, w = 3) => String(n).padStart(w);

// ---------------------------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------------------------

export function renderCorpus(entry, opts = {}) {
  const { name, label, vector, score: sc } = entry;
  const t = sc.totals;
  const L = [];
  L.push("");
  L.push(`=== ${name}${vector ? `  (AMTSO vector ${vector})` : ""} — ${label} ===`);
  L.push(`samples ${t.samples}   attacks ${t.attacks}   benign ${t.benign}` +
    (t.notApplicable ? `   not-applicable ${t.notApplicable}` : "") +
    (t.inconclusive ? `   inconclusive ${t.inconclusive}` : ""));
  L.push("");
  if (t.attacks > 0) {
    L.push(`  recall (consume step)     ${pct(sc.recall)}   ${t.tp}/${t.attacks}`);
    if (sc.recallAnyStep !== sc.recall) {
      L.push(`  recall (any step)         ${pct(sc.recallAnyStep)}   optimistic reading of multi-step samples`);
    }
  }
  L.push(sc.precision === null
    ? `  precision                    n/a   no attacks in this corpus — read the false-positive rate instead`
    : `  precision                 ${pct(sc.precision)}   ${t.tp} TP / ${t.tp + t.fp} alerts`);
  L.push(`  false-positive rate       ${pct(sc.fpRate)}   ${t.fp}/${t.benign}`);
  if (sc.rightReason.count === null) {
    L.push(`  right-reason              ${"   n/a".padStart(6)}   ${sc.rightReason.basis}`);
  } else {
    L.push(`  right-reason              ${pct(sc.rightReason.rate)}   ${sc.rightReason.count}/${sc.rightReason.of} caught for the id the corpus expected`);
  }
  L.push("");
  const a = sc.amtso;
  if (a.attacks === 0) {
    L.push(`  AMTSO outcome split       n/a   this corpus contains no attacks; it measures the false-positive budget only`);
    // Not "benign sample(s)": a corpus can reach this branch with attacks in it, if every attack was
    // not-applicable and so left the conclusive denominator. Print the real split.
    if (a.notApplicable) L.push(`    not-applicable ${a.notApplicable} sample(s) — ${t.notApplicableAttacks} attack(s), ${t.notApplicableBenign} benign — harness not implemented by this adapter`);
    return finishCorpus(L, sc, opts);
  }
  L.push("  AMTSO outcome split (attacks only)");
  const den = a.conclusiveAttacks || 1;
  const row = (k, v, note = "") => L.push(`    ${k.padEnd(26)} ${num(v)}  ${pct(v / den)}${note ? "   " + note : ""}`);
  row("prevented", a.prevented, `of which hard-deny (block/kill): ${a.preventedHard}`);
  row("detected, NOT prevented", a.detectedNotPrevented);
  row("missed", a.missed);
  // No percentage for inconclusive / not-applicable: they are EXCLUDED from the denominator, so a
  // percentage of that denominator would be arithmetic nonsense (and can exceed 100%).
  L.push(`    ${"inconclusive".padEnd(26)} ${num(a.inconclusive)}         ${t.inconclusiveAttacks} attack(s), ${t.inconclusiveBenign} benign — scan threw or blew its budget; excluded from every rate`);
  L.push(`    ${"not-applicable".padEnd(26)} ${num(a.notApplicable)}         ${t.notApplicableAttacks} attack(s), ${t.notApplicableBenign} benign — harness not implemented by this adapter; excluded from every rate`);
  L.push(`    ${"model-refusal".padEnd(26)} ${num(a.modelRefusal)}         measured-as-absent: no model in this loop`);
  L.push(`    ${"model-recognition".padEnd(26)} ${num(a.modelRecognition)}         measured-as-absent: no model in this loop`);
  L.push(`    detection rate ${pct(a.detectionRate)} · prevention rate ${pct(a.preventionRate)} · denominator ${a.conclusiveAttacks} conclusive of ${a.attacks} applicable attacks`);
  return finishCorpus(L, sc, opts);
}

// The breakdown tail, shared by the two exits of renderCorpus (with and without attacks).
function finishCorpus(L, sc, opts) {
  if (opts.breakdown !== false && sc.bySubTechnique.length > 1) {
    L.push("");
    L.push("  per sub-technique:");
    L.push("    " + "sub-technique".padEnd(34) + "atk  caught  recall   benign  FP");
    for (const g of sc.bySubTechnique) {
      L.push("    " + String(g.subTechnique).slice(0, 33).padEnd(34) + num(g.attacks) + "  " + num(g.caught, 6) +
        "  " + pct(g.recall) + "  " + num(g.benign, 6) + "  " + num(g.fp, 2));
    }
  }
  if (sc.byHarness.length > 1) {
    L.push("");
    L.push("  per harness:");
    for (const g of sc.byHarness) {
      L.push("    " + String(g.harness).padEnd(12) + `attacks ${num(g.attacks)}  recall ${pct(g.recall)}   benign ${num(g.benign)}  FP ${g.fp}`);
    }
  }
  if (sc.notApplicableRows.length) {
    const byH = new Map();
    for (const r of sc.notApplicableRows) {
      const k = r.harness;
      if (!byH.has(k)) byH.set(k, { attacks: 0, benign: 0 });
      byH.get(k)[r.shouldDetect ? "attacks" : "benign"]++;
    }
    L.push("");
    L.push("  NOT APPLICABLE — the adapter does not implement these harnesses, so these samples scored nothing:");
    for (const [h, v] of byH) L.push(`    ${h.padEnd(12)} ${v.attacks} attack(s), ${v.benign} benign   [not counted as missed, not counted as caught]`);
  }
  if (sc.inconclusiveRows.length) {
    L.push("");
    L.push(`  INCONCLUSIVE (${sc.inconclusiveRows.length}) — the scan threw or blew its budget; no evidence either way:`);
    for (const r of sc.inconclusiveRows.slice(0, 20)) L.push(`    ${r.id.padEnd(28)} ${String(r.phase).padEnd(12)} ${r.reason}`);
    if (sc.inconclusiveRows.length > 20) L.push(`    ... and ${sc.inconclusiveRows.length - 20} more`);
  }
  if (opts.misses) {
    L.push("");
    L.push(`  misses (${sc.misses.length}):`);
    for (const m of sc.misses) {
      L.push(`    ${m.id.padEnd(28)} ${String(m.subTechnique).slice(0, 30).padEnd(31)} ${m.harness}/${m.stage}` +
        (m.anyStepDetected ? "   (caught at an earlier step only)" : ""));
    }
  }
  if (opts.fps) {
    L.push("");
    L.push(`  false positives (${sc.falsePositives.length}):`);
    for (const f of sc.falsePositives) {
      L.push(`    ${f.id.padEnd(28)} ${String(f.subTechnique).slice(0, 30).padEnd(31)} ids=[${f.firedIds.join(",")}] action=${f.action}` +
        (f.hardNegative ? "  [hard negative]" : ""));
    }
  }
  return L.join("\n");
}

export function renderReport(result, opts = {}) {
  const L = [];
  L.push("");
  L.push(`agentic-security-benchmark — adapter: ${result.adapter.name} v${result.adapter.version}`);
  L.push(`capabilities: text=${result.adapter.capabilities.text} action=${result.adapter.capabilities.action} ` +
    `session=${result.adapter.capabilities.session} events=${result.adapter.capabilities.events}`);
  L.push(`deterministic · model-free · ${result.corpora.length} corpus/corpora`);
  for (const c of result.corpora) L.push(renderCorpus(c, opts));

  const o = result.overall;
  L.push("");
  L.push("=== OVERALL (confusion cells summed across corpora, rates re-derived from the sums) ===");
  L.push(`  attacks ${o.totals.attacks}   benign ${o.totals.benign}   not-applicable ${o.totals.notApplicable}   inconclusive ${o.totals.inconclusive}`);
  L.push(`  recall                    ${pct(o.recall)}   ${o.totals.tp}/${o.totals.attacks}`);
  L.push(`  precision                 ${pct(o.precision)}`);
  L.push(`  false-positive rate       ${pct(o.fpRate)}   ${o.totals.fp}/${o.totals.benign}`);
  L.push(`  AMTSO: prevented ${o.amtso.prevented} (hard ${o.amtso.preventedHard}) · detected-only ${o.amtso.detectedNotPrevented} · missed ${o.amtso.missed} · inconclusive ${o.amtso.inconclusive} · not-applicable ${o.amtso.notApplicable}`);
  L.push(`         model-refusal ${o.amtso.modelRefusal} · model-recognition ${o.amtso.modelRecognition}  (measured-as-absent: this harness has no model in the loop)`);
  L.push("");
  return L.join("\n");
}

// ---------------------------------------------------------------------------------------------
// JSON — the shape a results/ file holds.
// ---------------------------------------------------------------------------------------------

export function renderJson(result) {
  return {
    // @2 dropped the `degraded` counters. They existed only for the action -> flattened-text fallback,
    // which is gone: an adapter with no scanAction now scores those rows `not-applicable`. Nothing
    // else in the shape changed, so an @1 reader sees @2 as an @1 file with no degraded rows.
    schema: "agentic-security-benchmark/result@2",
    generatedAt: result.generatedAt,
    harness: {
      deterministic: true,
      modelInLoop: false,
      note: "model-refusal and model-recognition are always 0 here and are MEASURED-AS-ABSENT, not omitted: there is no model in this loop to observe."
    },
    adapter: {
      name: result.adapter.name,
      version: result.adapter.version,
      capabilities: result.adapter.capabilities,
      source: result.adapter.source
    },
    options: result.options,
    corpora: result.corpora.map((c) => ({
      corpus: c.name,
      vector: c.vector,
      label: c.label,
      attacks: c.score.totals.attacks,
      benign: c.score.totals.benign,
      caught: c.score.totals.tp,
      recall: c.score.recall,
      recallAnyStep: c.score.recallAnyStep,
      recallInconclusiveAsMiss: c.score.recallInconclusiveAsMiss,
      fp: c.score.totals.fp,
      precision: c.score.precision,
      fpRate: c.score.fpRate,
      rightReason: c.score.rightReason,
      amtso: {
        prevented: c.score.amtso.prevented,
        preventedHard: c.score.amtso.preventedHard,
        detectedNotPrevented: c.score.amtso.detectedNotPrevented,
        missed: c.score.amtso.missed,
        inconclusive: c.score.amtso.inconclusive,
        notApplicable: c.score.amtso.notApplicable,
        modelRefusal: c.score.amtso.modelRefusal,
        modelRecognition: c.score.amtso.modelRecognition,
        detectionRate: c.score.amtso.detectionRate,
        preventionRate: c.score.amtso.preventionRate,
        missRate: c.score.amtso.missRate
      },
      bySubTechnique: c.score.bySubTechnique,
      byHarness: c.score.byHarness,
      byStage: c.score.byStage,
      misses: c.score.misses,
      falsePositives: c.score.falsePositives,
      inconclusiveRows: c.score.inconclusiveRows,
      notApplicableRows: c.score.notApplicableRows
    })),
    overall: {
      attacks: result.overall.totals.attacks,
      benign: result.overall.totals.benign,
      caught: result.overall.totals.tp,
      recall: result.overall.recall,
      recallInconclusiveAsMiss: result.overall.recallInconclusiveAsMiss,
      fp: result.overall.totals.fp,
      precision: result.overall.precision,
      fpRate: result.overall.fpRate,
      notApplicable: result.overall.totals.notApplicable,
      inconclusive: result.overall.totals.inconclusive,
      amtso: result.overall.amtso
    }
  };
}
