# AI policy plane (CEL)

*Last modified: 2026-07-23*

The AI policy plane is one sandboxed CEL expression that expresses
cross-cutting rules over the AI decision pipeline. Instead of spreading a
decision across the guardrail, budget, routing, and logging config blocks,
you write a single expression over the signals the gateway already computes
and emit a small, closed set of typed actions.

The expression runs on the same sandboxed CEL engine as the rest of
sbproxy, at line rate, and can only emit actions from a fixed set. There is no
arbitrary code path. A policy can reroute, select a route-local compression
pipeline, redact, block, tag, or audit, and nothing else.

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
      ai.tokens.input_est > 12000
        ? ["compression:compact", "route_to:gpt-4o-mini", "audit:high"]
        : ["allow"]
    on_error: allow
  compression:
    levers: []
    profiles:
      compact:
        levers:
          - type: window_fit
            input_budget_tokens: 8192
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
| `compression:<selector>` | Select `on`, `off`, or one declared route-local compression profile. |
| `set_sink_tag:<tag>` | Tag the usage record (and the verifiable ledger entry) emitted for this request. |
| `audit:<priority>` | Emit a structured audit event at the given priority. |

The action set is closed: an unrecognized token at evaluation time falls
back to `on_error`. The expression itself is compiled (syntax-checked) when
the policy is first built; a syntax error is logged and the policy is
disabled (fail-open).

Compression selectors use lowercase ASCII profile names of up to 64 bytes,
with `_` and `-` allowed after the first letter or digit. A malformed
`compression:` selector is treated as an invalid operator choice and safely
disables compression for that request. A valid name that is not declared on
the route has the same safe-off behavior. Both cases emit the content-free
`ai_compression_selection` event and increment
`sbproxy_ai_compression_selection_total` with
`source="cel_policy", outcome="invalid_operator"`. They do not apply the
policy-wide `on_error`, because that could enable a route default the operator
did not select.

The full selector precedence is `X-Compression` header, governed key
`compression_profile`, CEL, then the route default. A caller header therefore
overrides a CEL decision. SBproxy strips that header before sending the request
upstream. See [AI context compression](ai-context-compression.md#profiles-and-request-selection)
for the shared grammar and rejection rules.

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
| `ai.tokens.input_est` | int | Target-model input estimate for the current uncompressed JSON messages. |

`ai.tokens.input_est` is computed before CEL and before compression. Known
OpenAI model families use their registered tokenizer; other model names use
the documented UTF-8 byte-length heuristic. This makes an expression such as
`ai.tokens.input_est > 12000 ? "compression:compact" : "compression:off"`
depend on the caller's original context rather than a stale or post-compression
accounting field.

`ai.guardrails.labels` carries the name of every guardrail that flagged. A
[`classifier` guardrail](ai-classifier-routing.md) contributes its predicted
class instead, so an expression can read that label and emit a matching
`route_to:`.

The guardrail-verdict and budget-fraction dimensions are richest when the
[guardrail mesh](ai-guardrail-mesh.md) and
[predictive budgets](ai-predictive-budget.md) are configured, which
produce the multi-verdict set and live burn rate the policy fuses.

## Try it

The runnable example is in
[`examples/ai-policy-cel/`](../examples/ai-policy-cel/).

![a request without a tenant header rejected 403, then an unlisted X-Tenant: stranger rejected before any provider call](assets/ai-cel-tenant-gate.gif)

A related recording shows CEL gating tenants at the network layer ([config](../examples/ai-cel-tenant-gate/)).
