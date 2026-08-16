# ai-agent-alignment

*Last modified: 2026-08-16*

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

Verified against a live Anthropic account: the denied-tool and
forbidden-substring cases both return 400 with the documented
`guardrail_violation` body (`"tool \"delete_account\" is in
denied_tools"` / `"tool \"fetch\" arguments contain forbidden
substring \"/etc/passwd\""`), exactly as described, since the
guardrail rejects both before any upstream dispatch.

**SUSPECTED PRODUCT BUG:** the first ("allowed") case does not reach
Anthropic successfully as shipped. It passes the guardrail, but the
gateway's OpenAI → Anthropic request translator
(`crates/sbproxy-ai/src/translators/anthropic.rs::request_to_native`)
never converts an OpenAI-shaped assistant message's `tool_calls`
array (with `content: null`) into Anthropic's native
`content: [{"type": "tool_use", ...}]` block shape; it passes
`content: null` straight through. Anthropic's Messages API rejects
that with `messages.1.content: Input should be a valid array` (a real
400 from Anthropic, not from sbproxy). The translator's response-side
tool-call handling (Anthropic `tool_use` → OpenAI `tool_calls`) is
implemented; the request-side direction used by any multi-turn
tool-calling conversation targeting Anthropic is not, so this
"allowed" case cannot currently demonstrate an end-to-end success
against a real Anthropic account. The guardrail feature itself works;
only the pass-through path for this particular payload shape is
affected.

The full guardrail surface is documented at
[`docs/ai-gateway.md` → Agent-alignment guardrail](../../docs/ai-gateway.md#agent-alignment-guardrail).
