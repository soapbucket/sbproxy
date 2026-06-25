# AI policy plane (CEL)
*Last modified: 2026-06-24*

The AI policy plane is one sandboxed CEL expression that expresses
cross-cutting rules over the AI decision pipeline. Instead of spreading a
decision across the guardrail, budget, routing, and logging config blocks,
you write a single expression over the signals the gateway already computes
and emit a small, closed set of typed actions.

The expression runs on the same sandboxed CEL engine as the rest of
sbproxy, at line rate, and can only emit actions from a fixed set. There is
no arbitrary code path: a policy can reroute, redact, block, tag, or audit,
and nothing else.

## Configuration

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      provider_type: openai
      api_key: ${OPENAI_API_KEY}
      default_model: gpt-4o-mini
      models: [gpt-4o, gpt-4o-mini]
  ai_policy:
    expression: |
      ai.principal.tier == "free" && ai.guardrails.flagged_count >= 2
        ? ["redact", "route_to:gpt-4o-mini", "audit:high"]
        : ["allow"]
    on_error: allow
```

The expression returns either one action token (a string) or a list of
tokens. `on_error` is the action applied when the expression fails to
evaluate or returns an unrecognized value; it defaults to `allow`
(fail-open), so a policy mistake degrades to current behavior rather than
taking the gateway down.

The hook runs after guardrail evaluation and before provider selection.
Default off: with no `ai_policy` block, the pipeline behaves exactly as
before.

## Actions

| Token | Effect |
|---|---|
| `allow` | Proceed unchanged. |
| `block` | Reject the request before dispatch with a `403`. |
| `redact` | Mask sensitive content in the prompt (via the origin's PII redactor) and continue. |
| `route_to:<model>` | Force the request onto a specific model. |
| `set_sink_tag:<tag>` | Tag the usage record (and the verifiable ledger entry) emitted for this request. |
| `audit:<priority>` | Emit a structured audit event at the given priority. |

The action set is closed: an unrecognized token at evaluation time falls
back to `on_error`. The expression itself is compiled (syntax-checked) when
the policy is first built; a syntax error is logged and the policy is
disabled (fail-open).

## The `ai.*` namespace

| Field | Type | Meaning |
|---|---|---|
| `ai.surface` | string | Classified surface (`chat_completions`, `embeddings`, ...). |
| `ai.model` | string | Requested / resolved model. |
| `ai.provider` | string | Leading routing candidate. |
| `ai.principal.tenant` | string | Tenant the request resolved to. |
| `ai.principal.api_key_id` | string | Authenticated key id. |
| `ai.principal.tier` | string | Principal risk tier (from the `SB-Attr-Risk-Tier` tag). |
| `ai.guardrails.flagged` | bool | Whether any guardrail flagged the request. |
| `ai.guardrails.flagged_count` | int | Number of guardrails that flagged. |
| `ai.guardrails.labels` | list | Labels of the flagging guardrails. |
| `ai.budget.fraction` | double | Fraction of the tightest active budget window consumed. |
| `ai.budget.exceeded` | bool | Whether a budget window is already exceeded. |
| `ai.tokens.input_est` | int | Estimated prompt tokens. |

The guardrail-verdict and budget-fraction dimensions are richest when the
[guardrail mesh](ai-gateway.md) and predictive budgets are configured,
which produce the multi-verdict set and live burn rate the policy fuses.

## Try it

The runnable example is in
[`examples/ai-policy-cel/`](../examples/ai-policy-cel/).
