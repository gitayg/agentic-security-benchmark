// Renders dist/hf/README.md, the Hugging Face dataset card. Every number in it is passed in from
// scripts/export-hf.mjs, which counts the rows it actually wrote; nothing here is typed by hand.
//
// YAML fields follow https://huggingface.co/docs/hub/datasets-cards (license, language,
// task_categories, tags, size_categories, pretty_name) and
// https://huggingface.co/docs/hub/datasets-manual-configuration (configs / config_name /
// data_files with split + path, default: true).

const GITHUB = "https://github.com/gitayg/agentic-security-benchmark";
const HOMEPAGE = "https://moorai.dev/benchmark.html";
const AMTSO_PDF = "https://www.amtso.org/wp-content/uploads/2026/09/AMTSO_Guidelines_for_Testing_of_Agentic_Security_Products_FINAL_V1.0.pdf";

const HARNESS = {
  "vector2-indirect-content": "`text`",
  "vector3-supply-chain": "`text` (tool / file / index / output / prompt stages)",
  "vector4-outbound-action": "`action`",
  "vector5-memory-crossagent": "`text`, `steps`, `session`, `events`",
  "heldout-v2-tune": "`text` (one multi-turn `session` sample each side)",
  "benign-corpus-v2": "`text`",
  "benign-web-content-tune": "`text`, `output` stage"
};

const VECTOR_CELL = {
  1: "1 — direct input (family-keyed)",
  2: "2 — indirect / content-mediated injection",
  3: "3 — tool, skill, extension & MCP supply chain",
  4: "4 — outbound action / agent-initiated effect",
  5: "5 — memory, context & cross-agent propagation"
};

function sizeCategory(n) {
  if (n < 1000) return "n<1K";
  if (n < 10000) return "1K<n<10K";
  if (n < 100000) return "10K<n<100K";
  return "100K<n<1M";
}

function yamlConfigs(counts) {
  const lines = [
    "configs:",
    "- config_name: all",
    "  default: true",
    "  data_files:",
    "  - split: attack",
    "    path: \"data/*/attack.jsonl\"",
    "  - split: benign",
    "    path: \"data/*/benign.jsonl\""
  ];
  for (const [name, c] of Object.entries(counts)) {
    lines.push(`- config_name: ${name}`, "  data_files:");
    for (const split of ["attack", "benign"]) {
      if (!c[split]) continue;
      lines.push(`  - split: ${split}`, `    path: "data/${name}/${split}.jsonl"`);
    }
  }
  return lines.join("\n");
}

export function renderCard({ counts, corpora, version, commit }) {
  let totalA = 0, totalB = 0;
  for (const c of Object.values(counts)) { totalA += c.attack; totalB += c.benign; }
  const web = corpora.find((c) => c.name === "benign-web-content-tune");
  const withheld = web?.raw?._heldOutSplitWithheld?.withheld;

  const rows = corpora.map((c) => {
    const n = counts[c.name];
    const vec = c.vector ? VECTOR_CELL[c.vector] : "none — precision denominator";
    return `| \`${c.name}\` | ${n.attack || "—"} | ${n.benign || "—"} | ${vec} | ${HARNESS[c.name] || ""} |`;
  });

  return `---
license: apache-2.0
language:
- en
pretty_name: Agentic Security Benchmark
task_categories:
- text-classification
tags:
- security
- prompt-injection
- ai-agents
- agentic-ai
- benchmark
- amtso
size_categories:
- ${sizeCategory(totalA + totalB)}
${yamlConfigs(counts)}
---

# Agentic Security Benchmark

A corpus for measuring what an agentic-AI security product stops, graded against
[AMTSO's *Guidelines for Testing of Agentic Security Products* v1.0](${AMTSO_PDF}).
This Hugging Face dataset is a **data-only mirror** of the corpora in
[${GITHUB.replace("https://", "")}](${GITHUB}). The scoring harness, the adapter interface, the
methodology and the published results live in that repository. Overview: <${HOMEPAGE}>.

Exported from benchmark version **${version}**, commit \`${commit}\`, by \`scripts/export-hf.mjs\`.

## What it measures

Each sample is labelled \`attack\` (a product should flag or stop it) or \`benign\` (a product firing
on it is a false positive). Scoring a product means putting each sample to it through the entry point
the sample's \`harness\` names and counting which attacks it catches and which benign samples it fires
on. The benign half is larger than the attack half on purpose: a recall number published without a
false-positive number measured on the same engine is half a result. A large share of the benign
samples are **hard negatives** — legitimate work deliberately shaped to look like an attack.

The harness (\`node scorers/run.mjs\` in the GitHub repository) is deterministic, model-free and has
no dependencies. This mirror does not include it.

## Subsets

| Subset | Attack | Benign | AMTSO vector | Harness |
|---|--:|--:|---|---|
${rows.join("\n")}
| **\`all\`** (default) | **${totalA}** | **${totalB}** | | |

Each subset has an \`attack\` and a \`benign\` split (\`benign-corpus-v2\` has no attacks, so it has only
\`benign\`). \`all\` is the union of the seven.

\`\`\`python
from datasets import load_dataset
ds = load_dataset("moorai-dev/agentic-security-benchmark", "vector4-outbound-action", split="attack")
\`\`\`

## AMTSO attack vectors

| Vector | What it covers | Here |
|---|---|---|
| 1 · Direct input | Prompts and instructions supplied by the user, or by an attacker posing as one. | \`heldout-v2-tune\` (tune half only) |
| 2 · Indirect / content-mediated | Instructions hidden in fetched pages, files and retrieved documents. | \`vector2-indirect-content\` |
| 3 · Tool, skill, extension & MCP supply chain | Hostile tool definitions, servers and installers reached over MCP. | \`vector3-supply-chain\` |
| 4 · Outbound action / agent-initiated effect | The action the agent is being steered into taking. | \`vector4-outbound-action\` |
| 5 · Memory, context & cross-agent propagation | Persisted state and content passed between agents; samples are sequences. | \`vector5-memory-crossagent\` |
| 6 · Static code artifact | Instructions embedded in source, configuration and repository files. | **no dedicated corpus** |

## Columns

Every row carries every column and no column is null, so the subsets load with one schema. An absent
string is \`""\`, an absent flag is \`false\`, and an absent integer is \`0\` (AMTSO vectors are 1–6). \`source\` always holds the original sample verbatim, so nothing is lost by
the flattening.

| Column | Meaning |
|---|---|
| \`id\` | Unique across the whole benchmark; prefixed with its corpus's namespace (\`v2-\`, \`v3-\`, \`v4-\`, \`v5-\`, \`hv2-\`, \`bcv2-\`, \`wf-\`). |
| \`corpus\` | Source file in \`corpora/\` (without \`.json\`). |
| \`label\` | \`attack\` or \`benign\`, from the sample's own \`shouldDetect\`, with the array it sits in as the fallback — the same rule the harness uses. |
| \`vector\` | AMTSO attack vector of the corpus (\`0\` for the two precision corpora). |
| \`family\`, \`subTechnique\`, \`category\`, \`channel\`, \`axis\` | Taxonomy labels, as the source sample carries them. |
| \`stage\` | \`prompt\` \\| \`file\` \\| \`output\` \\| \`index\` \\| \`tool\` — where in the agent's lifecycle the sample is reachable. Corpus default applied where the sample declares none. |
| \`harness\` | \`text\` \\| \`action\` \\| \`steps\` \\| \`session\` \\| \`events\` — how the sample must be fed. Inferred by the harness's own rule where the sample declares none. |
| \`text\` | The payload for single-text samples; \`""\` for structured ones. |
| \`payload\` | JSON string holding \`turns\` / \`action\` / \`actions\` / \`consumeAction\` / \`steps\` / \`consumeStep\` / \`events\` for structured samples; \`""\` for single-text ones. Vector-4 actions keep their template tokens (\`{{CRED_FILE}}\`, \`{{AWS_KEY}}\` …), which a harness resolves inside a sandbox. |
| \`validity\` | Why the malicious outcome could occur with the product absent (attacks), or why firing would be a genuine false positive (benign). Not every corpus carries it. |
| \`hard_negative\`, \`twin_of\` | Benign sample engineered to look malicious, and the attack it twins where it was written against one. |
| \`ambiguous\` | \`benign-corpus-v2\` only: benign meta-discussion of attacks, which the harness reports both with and without. |
| \`amtso\` | \`{ attackVector, targetOfProtection, harm, requiredCapability }\` where the sample carries it. \`vector3\` and \`vector5\` omit \`attackVector\` per sample; it is implied by the file. |
| \`source\` | The original sample object as JSON, including fields not flattened above (\`expectThreat\`, \`expectStopBy\`, \`expectDetections\`, \`note\`, \`hiding\`, \`tool\`, \`mimics\` …). |

\`expectThreat\` in \`source\` is MoorAI's own threat id, used for right-reason scoring. It is only
meaningful for a product sharing that id space.

## How the samples were produced

Every sample is **authored**, not captured from live traffic. All seven files were authored in the
[MoorAI agent](https://github.com/gitayg/moorai) repository (MIT) and are republished under
Apache-2.0 by their copyright holder. Sample content is unmodified; the one change is that
\`benign-corpus-v2\`'s ids were re-prefixed \`v2-\` → \`bcv2-\` to end an id collision with the vector-2
corpus.

- The four \`vectorN-*\` corpora were written one vector at a time, each after per-sample AMTSO
  labelling showed that vector was under-represented. Each file lists its own sub-techniques.
- \`heldout-v2-tune\` is the **tune half** of a mutation-generated corpus keyed to the
  [HackAgent](https://github.com/AISecurityLab/hackagent) attack-family taxonomy and to a
  transformation \`axis\`. Its own header says a tuning wave may optimise against it.
- \`benign-corpus-v2\` is hand-authored benign developer and agent prompts, including hard negatives
  and deliberately obfuscation-shaped benign samples (encoded blobs, mixed scripts, non-English
  prose). Most text is English; some benign samples are deliberately not.
- \`benign-web-content-tune\` is the tune half of an inbound \`WebFetch\` / \`WebSearch\` corpus — page
  content a developer would legitimately fetch, scored at the \`output\` stage.

## What is not in this dataset

Two held-out splits are withheld from the benchmark on purpose and are **not** in this mirror: the
\`test\` half of the web-content corpus${withheld ? ` (${withheld} samples)` : ""} and a separate held-out
attack set. They are not secret — both are in the public MoorAI repository — but their value is that
nobody tunes against them. The split algorithm needs no seed: bucket by stratum, sort by id inside the
bucket, assign alternately (even index → tune, odd → test). The export script refuses to write any file
outside the seven published corpora.

## Limitations

- **AMTSO has not reviewed, certified or endorsed this benchmark**, its corpora, its harness, or any
  result. The Guidelines are cited as published criteria it grades against. AMTSO is a trademark of the
  Anti-Malware Testing Standards Organization.
- **The corpora are authored, not captured.** No sample is a real incident. A result describes
  behaviour against attacks somebody knew how to write.
- **No refusal baseline is subtracted.** A detection rate measured on this data includes attacks the
  underlying model would have refused unaided. The harness is model-free, so every published recall
  figure is a raw detection rate, not a marginal contribution.
- **Two of the seven corpora are half a corpus** — the tune halves described above.
- **\`benign-web-content-tune\` is not entirely benign.** ${counts["benign-web-content-tune"]?.attack ?? 0} of its samples
  (prompt-injection tutorial pages) are deliberately labelled \`attack\`: an injection example on a
  tutorial page is a live payload to an agent that fetches it. Its header comment, and those samples'
  \`validity\` strings, still describe them as benign; that is a known stale spot in the source.
- **Vector 1 is over-represented** across the wider labelled set, because it is the easiest vector
  to author; the per-vector corpora counteract that without eliminating it. **Vector 6 has no
  dedicated corpus.**
- **Right-reason labels are not vendor-neutral.** \`expectThreat\` holds one product's threat ids.

## License and attribution

Apache-2.0. \`LICENSE\` and \`NOTICE\` are included. The MoorAI agent the corpora originated in is a
separate MIT project; nothing here imposes its obligations on a product under test.

## Citation

\`\`\`bibtex
@misc{agentic_security_benchmark,
  title        = {Agentic Security Benchmark},
  author       = {Glick, Itay},
  year         = {2026},
  howpublished = {\\url{${GITHUB}}},
  note         = {Version ${version}. ${HOMEPAGE}}
}
\`\`\`
`;
}
