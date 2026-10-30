# Rules that need Quarry's engine

The rules in this directory run only on Quarry's own engine. They use the `after(within: N)` flow
operator or the offered-tools surface (`tools`), and they read every top-level tool argument
(`call.arguments.*`). The MoorAI console importer reads none of these, so these rules **do not import
into MoorAI policy**. Each carries `requires = "quarry-engine"` in its metadata.

| Rule | What it detects | `moorai_threat` |
|---|---|---|
| `flow_private_read_then_network.rule` | A credential path read (or a credential in a tool result), then within 100 events a tool call to a network sink. The order MoorAI's `tagRules` example `no-net-after-private` denies. | 59 (two of its three legs) |
| `flow_lethal_trifecta.rule` | A private read and a tool result carrying an injected instruction, each followed within 100 events by a call to a network sink. | 59 |
| `tool_description_poisoning.rule` | An injected directive in the description of a tool offered to the model (MCP tool poisoning). | 60 |

How the flow rules differ from MoorAI:

- MoorAI tracks the three trifecta legs per session on its session ledger, in any order, and holds the call
  that would add the missing leg. Quarry reads one recorded conversation. Quarry rejects a flow as the
  operand of another flow (`quarry/engine/desugar.py`, `alternatives`: "a flow operand is one event"), so
  the trifecta is written as two flows joined by `and`: some callout follows the private read and some
  callout follows the instruction. The later of the two callouts follows both legs.
- Each leg must be within 100 timeline events of a callout after it. An unbounded `after` is a Quarry
  performance warning (`quarry/safety/validator.py`), so the window is bounded.
- The credential-path pattern is MoorAI's `CRED_PATH` (`data/tool-tags.js`). MoorAI also exempts env
  templates (`.env.example` and the like) in code, so this rule does not.
- The network-sink patterns are the outbound sinks of MoorAI's `egress-credential-shaped` detector
  (#65): a curl, wget, nc, scp or rsync client, a URL, or an HTTP client call.
