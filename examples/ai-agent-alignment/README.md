# ai-agent-alignment

*Last modified: 2026-07-09*

![ai-agent-alignment](../../docs/assets/ai-agent-alignment.gif)

Demonstrates the `agent_alignment` input guardrail.

The guardrail audits the assistant's `tool_calls` array against an
operator-declared ruleset: allow + deny lists, a forbidden-substring
scan over the JSON-encoded tool arguments, and a per-turn budget on
the number of tool calls. Three curl invocations in `sb.yml` exercise
the allow, deny, and forbidden-substring rules.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/ai-agent-alignment/sb.yml
```

## Try it

The header comment in [sb.yml](sb.yml) has three ready-to-paste curl
invocations: an allowed tool call that reaches Anthropic, a denied
tool call that returns 400 before any upstream call, and an allowed
tool whose arguments trip the forbidden-substring rule (also 400).

The full guardrail surface is documented at
[`docs/ai-gateway.md` → Agent-alignment guardrail](../../docs/ai-gateway.md#agent-alignment-guardrail).
