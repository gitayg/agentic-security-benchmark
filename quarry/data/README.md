# Quarry pack test data

One conversation per file, in the OpenAI-shaped form Quarry scans (`messages`, optional `tools`; see
Quarry's `docs/messages.md`). The layout is Quarry's own example layout: `<rule>.json` is a conversation
the rule must match, `<rule>.negative.json` a benign twin it must not match, and `benign.json` a control
that no rule in the pack may match.

Samples taken from this repository's published corpora are used verbatim and placed on the surface the
rule reads (a web page as the result of a fetch, a vector-4 command as a shell tool call). No file here
comes from a held-out or locked split. Synthetic twins differ from their positive in the one detail the
rule keys on.

Credentials are fake. The AWS, GitHub and Google values are the documentation placeholders the corpus
validator already allows; the Slack-shaped value and the PEM header (with no key material) are allowed,
by exact match, only in `test/quarry-pack.test.mjs`.

| Rule | Positive (`<rule>.json`) | Negative (`<rule>.negative.json`) |
|---|---|---|
| `secret_aws_access_key_id` | synthetic (AWS documentation placeholder key ID) | synthetic |
| `secret_github_token` | synthetic (placeholder already on the corpus validator allowlist) | synthetic |
| `secret_google_api_key` | synthetic (placeholder already on the corpus validator allowlist) | synthetic |
| `secret_openai_anthropic_key` | synthetic (the fake key Quarry's own regex example uses) | synthetic |
| `secret_slack_token` | synthetic (fake token, allowlisted in the pack test) | synthetic |
| `secret_jwt_or_bearer_token` | synthetic | synthetic (twin: the value is a shell variable) |
| `secret_private_key_block` | synthetic (header and footer only, no key material) | synthetic |
| `secret_in_tool_result` | synthetic (the {{CRED_FILE}} the vector-4 corpus describes: the AWS EXAMPLE key) | synthetic |
| `prompt_instruction_override` | synthetic | `benign-corpus-v2` bcv2-hn-ign-001 (hard negative) |
| `prompt_system_prompt_extraction` | synthetic | synthetic |
| `prompt_hidden_instructions` | `vector2` v2-email-002, pasted into a prompt | `vector2` v2-benign-009 (its benign twin), pasted into a prompt |
| `prompt_exfiltration_request` | synthetic | synthetic |
| `result_indirect_injection` | `vector2` v2-web-001 as a fetched page | `vector2` v2-benign-004 (hard negative) as a fetched page |
| `cmd_reverse_shell` | `vector4` v4-shell-002 | `vector4` v4-benign-001 |
| `cmd_credential_file_access` | synthetic (the read v2-web-001 asks for) | synthetic |
| `cmd_etc_shadow_read` | synthetic | synthetic |
| `cmd_untrusted_package_install` | `vector4` v4-shell-001 | synthetic (twin: a registry install) |
| `cmd_destructive` | `vector4` v4-shell-003 | synthetic |
| `cmd_destructive_tool_call` | synthetic | synthetic |
| `cmd_security_config_change` | synthetic | synthetic |
| `cmd_external_comms` | synthetic | synthetic |
| `flow_private_read_then_network` | synthetic (read, then send) | synthetic (the same two calls in the other order) |
| `flow_lethal_trifecta` | private read, then `vector2` v2-web-001 as a fetched page, then a send | synthetic (the same session with a page that carries no instruction) |
| `tool_description_poisoning` | `vector3` v3-schema-001 as an offered tool | `vector3` v3-benign-006 (its benign twin) as an offered tool |
| `benign.json` (control, every rule) | `benign-corpus-v2` bcv2-cod-001 and `vector4` v4-benign-002 | — |
