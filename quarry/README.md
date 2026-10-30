# Quarry rule pack

Detection rules for [Project Quarry](https://github.com/cisco-ai-defense/project-quarry), an open rule
language for finding agent behaviour in a recorded OpenAI-shaped conversation (messages, tool calls, tool
results, offered tools). Quarry is a detection layer that reads a conversation after the fact. MoorAI is
an enforcement layer that runs inside the agent host. This pack carries MoorAI's public detection
patterns into Quarry's format so either can use them.

- **License:** Apache-2.0, like the rest of this repository.
- **Source of the patterns:** the MoorAI agent v1.43.0 (MIT), `data/detectors.js` and `data/tool-tags.js`,
  relicensed here by their copyright holder. Every pattern is the agent's own regex source, or a rewrite
  listed below that keeps the match result the same.
- **Quarry version:** written and checked against Quarry `0.1.0` (`quarry/_version.py`) at commit
  `eadc6e3`. Quarry is alpha and its DSL may change before 1.0.
- Quarry is a Cisco open-source project. This pack references it and copies none of its files; Cisco has
  not reviewed or endorsed it.

## Layout

| Path | What it is |
|---|---|
| `rules/*.rule` | 21 rules in the simplest Quarry forms. 9 also import into MoorAI policy; the other 12 are refused by MoorAI's import guard and are built-in MoorAI detectors already. See [below](#which-rules-import-into-moorai-policy). |
| `rules/flow/*.rule` | 3 rules that need Quarry's own engine (event order, offered tools). They do not import into MoorAI. See [`rules/flow/README.md`](rules/flow/README.md). |
| `data/<rule>.json` | A conversation the rule must match (Quarry's example layout). |
| `data/<rule>.negative.json` | A benign twin the rule must not match. |
| `data/benign.json` | A benign control no rule may match. |
| `quarry.yaml` | Quarry configuration that loads both rule directories. |

Where each dataset comes from (a published corpus sample, or synthetic) is in
[`data/README.md`](data/README.md). No dataset uses a held-out or locked split.

## Running it

With Quarry installed (Python 3.11 to 3.13; see Quarry's own README), from the repository root:

```bash
quarry scan -c quarry/quarry.yaml -t quarry/data/benign.json --validate-only   # load, compile, lint
quarry scan -c quarry/quarry.yaml -t quarry/data/ -o json                       # scan every dataset
quarry scan -c quarry/quarry.yaml -t my-trace.json                              # scan your own trace
```

`quarry scan` exits `0` when nothing matched, `1` on a match and `2` when a scan could not complete
(`quarry/cli.py`). Rule paths in `quarry.yaml` are relative to the working directory.

Without Quarry, `node --test` (or `npm run validate`) runs `test/quarry-pack.test.mjs`. It parses each
rule, compiles its patterns as JavaScript regexes, evaluates the condition shapes this pack uses, and
checks every rule against its positive, negative and control datasets. It also checks the conversation
contract from Quarry's `docs/messages.md`, one rule per file, unique rule names, required metadata,
that patterns use only syntax RE2 and JavaScript read alike, and that the rules outside `rules/flow/`
use only the simplest Quarry forms. With `MOORAI_AGENT_DIR` set to a MoorAI agent checkout, it also checks
that exactly the rules carrying `moorai_mode` pass the agent's import guard (otherwise that check is
skipped).

Checked with Quarry `0.1.0` at `eadc6e3`: `--validate-only` reported `Validated 24 rules`,
`Total warnings: 0`. A scan of `data/` completed for all 49 files; every rule matched its positive
dataset, stayed silent on its negative dataset, and no rule matched `benign.json`. The Node test's
verdicts equalled Quarry's on all 24 x 49 rule and dataset pairs.

## Rules

`moorai_threat` is the MoorAI threat id the agent's detector reports, so MoorAI's console importer maps a
rule without asking. `atlas` is the MITRE ATLAS technique from MoorAI's `data/threats.json` for that
threat, leaving out a bounded credit whose limit does not cover the rule. Quarry metadata values are
strings (`metadata_item: METADATA_KEY "=" STRING`, `quarry/dsl/grammar.py`), so ids are quoted.

| Rule | Surface | `moorai_threat` | ATLAS | Severity | MoorAI detector | Patterns | Imports into MoorAI |
|---|---|---|---|---|---|---|---|
| `secret_aws_access_key_id` | user messages | 39 | AML.T0057 | critical | secret-aws-akia | 1 | yes |
| `secret_github_token` | user messages | 39 | AML.T0057 | critical | secret-github | 2 | yes |
| `secret_google_api_key` | user messages | 39 | AML.T0057 | critical | secret-google-api | 1 | yes |
| `secret_openai_anthropic_key` | user messages | 39 | AML.T0057 | critical | secret-openai-anthropic | 1 | yes |
| `secret_slack_token` | user messages | 39 | AML.T0057 | critical | secret-slack | 1 | yes |
| `secret_jwt_or_bearer_token` | user messages | 39 | AML.T0057 | critical | dlp-jwt | 2 | no: unbounded quantifiers |
| `secret_private_key_block` | user messages | 39 | AML.T0057 | critical | dlp-private-key | 1 | yes |
| `secret_in_tool_result` | tool results | 39 | AML.T0057 | critical | the seven above | 9 | no: unbounded quantifiers |
| `prompt_instruction_override` | user messages | 3 | AML.T0051, AML.T0054 | critical | inj-ignore | 7 | no: non-ASCII `’` in a nocase pattern |
| `prompt_system_prompt_extraction` | user messages | 51 | AML.T0056 | medium | sysprompt-extract | 3 | no: unbounded quantifiers |
| `prompt_hidden_instructions` | user messages | 40 | AML.T0051 | high | idx-hidden-instructions | 5 | no: unbounded quantifiers |
| `prompt_exfiltration_request` | user messages | 2 | AML.T0051, AML.T0054 | critical | inj-exfil | 1 | yes |
| `result_indirect_injection` | tool results | 40 | AML.T0051, AML.T0099 | high | inj-untrusted-directive | 12 | no: unbounded quantifiers |
| `cmd_reverse_shell` | tool call `command` | 54 | AML.T0112 | high | exec-reverse-shell | 9 | no: unbounded quantifiers |
| `cmd_credential_file_access` | tool call `command` | 55 | AML.T0098 | high | cred-file-access | 10 | no: unbounded quantifiers |
| `cmd_etc_shadow_read` | tool call `command` | 55 | AML.T0098 | high | cred-file-access | 1 | yes |
| `cmd_untrusted_package_install` | tool call `command` | 57 | AML.T0010 | high | pkg-install-untrusted | 9 | no: unbounded quantifiers |
| `cmd_destructive` | tool call `command` | 43 | AML.T0101 | high | destructive-command | 26 | no: unbounded quantifiers |
| `cmd_destructive_tool_call` | tool call `command` | 56 | AML.T0101 | medium | mcp-destructive-call | 7 | no: unbounded quantifiers |
| `cmd_security_config_change` | tool call `command` | 46 | AML.T0048 | high | action-security-config | 29 | no: unbounded quantifiers |
| `cmd_external_comms` | tool call `command` | 47 | AML.T0048 | medium | action-external-comms | 4 | yes |
| `flow/flow_private_read_then_network` | tool calls and results, in order | 59 | AML.T0057 | high | tool-tags `CRED_PATH`, secrets, egress sinks | 13 | no: needs Quarry's engine |
| `flow/flow_lethal_trifecta` | tool calls and results, in order | 59 | AML.T0057 | high | as above, plus inj-untrusted-directive | 25 | no: needs Quarry's engine |
| `flow/tool_description_poisoning` | offered tool descriptions | 60 | AML.T0051, AML.T0110 | high | mcp-tool-poisoning | 5 | no: needs Quarry's engine |

### Which rules import into MoorAI policy

MoorAI imports a pattern from outside the agent only through a ReDoS guard (`src/safe-regex.js` in the
agent): at most 400 characters, at most one unbounded quantifier (`+`, `*`, `{n,}`), no ambiguous
quantified alternation. Its console importer also refuses a non-ASCII character in a `nocase` pattern and
counts length with the case folding spelled out. The pack does not bound or change a pattern to get past
these limits: a changed pattern is no longer MoorAI's detector.

- **Import (9 rules):** `secret_aws_access_key_id`, `secret_github_token`, `secret_google_api_key`,
  `secret_openai_anthropic_key`, `secret_slack_token`, `secret_private_key_block`, `cmd_etc_shadow_read`,
  `cmd_external_comms`, `prompt_exfiltration_request`. They carry `moorai_mode = "warn"`, so they import
  in warn mode with no choice for the administrator.
- **Refused (12 rules):** every other rule in `rules/`. The table above gives the reason. For 11 of them
  at least one pattern has more than one unbounded quantifier, which the guard refuses; several also pass
  400 characters once `nocase` folding is spelled out. `prompt_instruction_override` is refused for the
  `’` in one `inj-ignore` pattern (its patterns have at most one unbounded quantifier each). These rules carry the patterns of MoorAI's built-in detectors, which every
  MoorAI agent already runs, so importing them would add nothing on a MoorAI device. They are here for
  Quarry.
- **Flow rules (3):** need Quarry's engine and never import.

Every rule in `rules/` uses one `strings:` declaration (`regex`, optionally `nocase`) and one condition of
the form `any msg in user_messages where msg.content contains $p`, `any r in tool_responses where
r.content contains $p`, or `any call in tool_calls where call.arguments.command contains $p`. No
`within`, counts, captures, `model()`, `base64` or `fullword`. The test enforces this.

## How the pack differs from MoorAI

The rules carry MoorAI's patterns, not its whole engine. Read these before relying on a rule.

- **No code checks.** Some MoorAI detectors pass a match through code before reporting it. A rule here
  has only the pattern. `prompt_instruction_override` therefore also fires on a defensive sentence ("never
  ignore previous instructions"), which MoorAI drops (`data/injection-tells.js`).
- **Secret rules are shape only.** They fire on documented placeholders such as `AKIAIOSFODNN7EXAMPLE`,
  as MoorAI's own detectors for these formats do. This benchmark's benign corpora count several such
  placeholders as false positives (for example `bcv2-hn-cre-001`, `bcv2-hn-cre-002`, `wf-b64-001`). The
  `sk-` prefix in `secret_openai_anthropic_key` is shared by other providers.
- **Surfaces.** MoorAI scans a shell command, a prompt, a tool result and a tool description at
  different stages. A rule here reads one Quarry surface: the `cmd_*` rules read the `command` argument
  only, so the same text in another argument (an MCP tool's `sql` or `query`) does not match.
- **No decoded variants.** MoorAI also scans base64, rot13 and other decoded copies of some inputs. Quarry
  scans the text as written.
- **Regex engines.** Quarry uses RE2; MoorAI uses JavaScript. The patterns avoid every construct the two
  read differently (lookaround, backreferences, `(?P<`, `\z`, `\C`, possessive quantifiers, inline
  flags). Three differences remain: RE2's `\s` is `[\t\n\f\r ]` while JavaScript's also takes `\v` and
  Unicode spaces; RE2's `.` excludes only `\n` while JavaScript's also excludes `\r`, U+2028 and U+2029;
  case folding under `nocase` may differ outside ASCII.

### Rewrites that keep the match result

A `contains` test only asks whether some match exists. These rewrites keep that answer for every input.

- A one-character negative lookbehind at the start, `(?<![C])X`, becomes `(?:^|[^C])X` (destructive-command
  6, 8, 10-21; action-security-config 5, 6, 11, 13, 16-19, 21-32; pkg-install-untrusted 9, 10).
- A one-character negative lookahead at the end, `X(?![C])`, becomes `X(?:[^C]|$)` (destructive-command 4).
- A one-character positive lookahead at the end, `X(?=[C])`, becomes `X[C]` (action-security-config 30).
- cred-file-access 1: the leading lookbehind only picks the first start of a run of path characters (a
  ReDoS guard in MoorAI). A match exists with it exactly when one exists without it, so it is removed.
- dlp-jwt 1 is case-insensitive in MoorAI; in a case-sensitive rule the word `Bearer` is written as
  `[Bb][Ee][Aa][Rr][Ee][Rr]`. The rest of the pattern was already case-free.
- inj-ignore 9 uses the `m` flag, but its only `^` is inside `(?:^|\s)`. A line start after the first
  line follows a newline, which `\s` already matches, so the flag is dropped.

### Patterns not ported

Dropped because RE2 cannot express them and no rewrite keeps the match result:

| MoorAI pattern | Why |
|---|---|
| inj-ignore 4 (`DAN`) | negative lookahead after the word |
| inj-ignore 7 (enter / activate jailbreak) | negative lookahead that excludes "jailbreak detection" and the like |
| inj-ignore 8 (jailbreak yourself) | lookahead inside an alternation |
| exec-reverse-shell 5 (Python socket shell at any length) | three lookaheads, in any order |
| cred-file-access 0 (a read verb, then `.env` and other credential files) | variable-length lookbehind and a lookahead that excludes `.env.example`; so `cat .env` is **not** covered |
| pkg-install-untrusted 7, 8 (PowerShell download into `iex` without `powershell`) | lookaheads in the middle |
| destructive-command 1, 2, 3 (`rm -r -f` with split flags, `Remove-Item -Recurse -Force`, `rd /s /q`) | several lookaheads, flags in any order |
| destructive-command 7 (shrinking the shadow-copy store) | lookahead with an alternation at the end |
| action-security-config 8, 10, 14, 15 (certificate copy into an anchor directory, `trust anchor`, `visudo -f`, `NOPASSWD`) | `m` flag with lookbehind, or lookarounds in the middle |

Not ported, by choice:

- **Payment cards (#90).** MoorAI fires only when a digit run passes the Luhn check and an issuer range
  check (`cardNumberValid`). The shape alone (`\b(?:\d[ -]?){13,19}\b`) fires on rulers and nil UUIDs, so it
  is left out.
- **Secrets gated by entropy or a value check** (generic and named assignments, the AWS secret key,
  labeled credentials, credential lists under a heading, app passwords, database URLs with a password):
  the gate is code.
- **Provider tokens with no documented placeholder** (GitLab, npm, PyPI, SendGrid, Twilio, Stripe, Azure,
  GCP service account): the pack's test data uses only placeholder values, and these have none this
  repository accepts.
- **Detectors that parse a command** rather than match a pattern (secret-file upload, object-storage
  upload, out-of-band callbacks, fetch-then-exec): there is no pattern to port.
- Detectors outside this pack's scope: multilingual injection, jailbreak templates, typo-perturbed
  injection, insecure-code detectors, PII.
