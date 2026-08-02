# Predictive budgets with soft-landing
*Last modified: 2026-08-02*

A fixed-window budget enforces a hard cliff: requests pass until the cap,
then block at 100%. Soft-landing degrades gracefully as a scope approaches
its limit, so spend tapers instead of stopping dead. It is an opt-in
addition to the existing `budget` block; without it the hard-block behavior
is unchanged.

## Configuration

<!-- sbproxy-config-excerpt -->
```yaml
action:
  type: ai_proxy
  budget:
    limits:
      - scope: workspace
        max_cost_usd: 1000.0
        period: total
    on_exceed: block
    soft_landing:
      warn_at: 0.8
      downgrade_at: 0.95
      downgrade_to: gpt-4o-mini
```

| Field | Default | What it does |
|---|---|---|
| `limits[].scope` | required | Which window the spend accumulates in. One of `workspace`, `api_key`, `user`, `model`, `origin`, `tag`, `agent`. `workspace` keys on the request Host. Do not pair `model` with soft-landing: the downgrade rewrites the model and the scope key is recomputed against it, so crossing `downgrade_at` moves spend into a fresh empty bucket and the cap never fires. |
| `limits[].max_cost_usd` | optional | The cost cap for the window. A limit may also carry `max_tokens`; when both are set the tightest of the two fractions wins. |
| `limits[].period` | `total` when omitted | `daily`, `weekly`, `monthly`, `total`, `lifetime`, or a LiteLLM-style duration such as `30d` or `1h`. `daily` is a fixed bucket aligned to UTC midnight, not a rolling 24 hours, so a window that straddles 00:00 UTC resets. An unrecognised value is a load error rather than a silent fallthrough. |
| `on_exceed` | `block` | What happens at 100%. `block` refuses with 402, `log` allows and records, `downgrade` rewrites the model and refuses with 402 anyway if no target resolves. |
| `soft_landing` | absent | Opt-in. Without it the hard-block behaviour above is unchanged. |
| `soft_landing.warn_at` | `0.8` | Past this fraction, a request is allowed and a warning is logged. |
| `soft_landing.downgrade_at` | `0.95` | Past this fraction, the request's model is rewritten before dispatch. Nothing validates that it is above `warn_at`. |
| `soft_landing.downgrade_to` | optional | The rewrite target. Without it the per-limit `downgrade_to` applies, and without that the cheapest model across the configured providers. It has to be a model the providers serve, and a rewrite to the model already requested is a no-op with no log line and no tag. |

Cost per call comes from the completed response's own `usage` object,
priced by the built-in catalog. The `model_prices` block beside `budget:`
overrides that catalog per model, and `rate_card` loads a LiteLLM-format
price file underneath it. A model no layer knows is priced pessimistically
at $5.00 per million tokens in each direction rather than silently at zero.

## Behavior

The soft-landing check runs after the hard pre-flight clears, on the
tightest active window across the configured limits (the larger of the
token and cost fractions). Below `warn_at` nothing changes. Between
`warn_at` and `downgrade_at` the request is allowed and a warning is
logged. Between `downgrade_at` and the cap the request's model is rewritten
to the soft-landing target. At or above the cap the hard `on_exceed` action
owns the decision (block, downgrade, or log), so the two never fight.

Every threshold is compared against the fraction as it stood *before* the
request was dispatched, not after it was billed.

A soft-landing downgrade is recorded on the usage record (and the
verifiable ledger, when configured) with a `budget_soft_landing` tag, so
the degradation is queryable in the spend history. Nothing is stamped on
the response: there is no header for a warn or a downgrade, and the only
signal a client sees is the model the upstream was actually handed.

The bands run on the chat and completions dispatch path. Other AI surfaces
and realtime run the hard pre-flight only, so they block at the cap with no
warn band and no downgrade.

## Integration with the policy plane

The live window fraction is published to the AI policy plane as
`ai.budget.fraction` and `ai.budget.exceeded` (see
[ai-policy-cel.md](ai-policy-cel.md)), so a CEL rule can compose budget
pressure with guardrail verdicts and principal context, for example to
route free-tier traffic to a cheaper model earlier than paid traffic.

## Try it

[`examples/ai-predictive-budget/`](../examples/ai-predictive-budget/) walks
one workspace up its own cap. Its fixture lets a request name the tokens it
wants billed, so the window fraction can be placed anywhere on the curve
without real traffic or a provider account, and it echoes the dispatched
model back, which is what makes the rewrite visible from the client.

```bash
python3 examples/ai-predictive-budget/fixture.py &
make run CONFIG=examples/ai-predictive-budget/sb.yml
```

The four bands, with the fraction the gateway compared each threshold
against:

<!-- CAPTURE: bash examples/ai-predictive-budget/bin/soft-landing.sh -->

The third row is the feature: the client asked for `gpt-4o`, and
`gpt-4o-mini` is what the upstream was handed.

The fraction itself is a gauge, served unauthenticated on the data-plane
port:

<!-- CAPTURE: curl -s http://127.0.0.1:8080/metrics | grep sbproxy_ai_budget_utilization_ratio -->

Both bands log at warn level, and the downgrade line names the model it
rewrote to:

<!-- CAPTURE: grep -F 'soft-landing' /tmp/sbproxy-predictive-budget.log -->

The tag lands on the usage record and nowhere else, so a sink is what makes
the degradation queryable afterwards:

<!-- CAPTURE: python3 -c 'import json; [print(json.dumps({k: json.loads(l).get(k) for k in ("model","tag","cost_usd")})) for l in open("/tmp/sbproxy-predictive-budget-usage.jsonl") if json.loads(l).get("tag")]' -->

And the cap, once the window is spent:

<!-- CAPTURE: curl -s -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' -H 'Content-Type: application/json' -d '{"model":"gpt-4o","messages":[{"role":"user","content":"spend=1"}]}' -->
