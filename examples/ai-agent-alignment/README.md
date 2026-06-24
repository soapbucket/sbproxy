# ai-agent-alignment

![ai-agent-alignment](../../docs/assets/ai-agent-alignment.gif)

Demonstrates the `agent_alignment` input guardrail (WOR-801).

The guardrail audits the assistant's `tool_calls` array against an
operator-declared ruleset: allow + deny lists, a forbidden-substring
scan over the JSON-encoded tool arguments, and a per-turn budget on
the number of tool calls. Three curl invocations in `sb.yml` exercise
the allow, deny, and forbidden-substring rules.

The full guardrail surface is documented at
[`docs/ai-gateway.md` → Agent-alignment guardrail](../../docs/ai-gateway.md#agent-alignment-guardrail).
