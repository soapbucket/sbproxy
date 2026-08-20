# Predictive budgets with soft-landing
*Last modified: 2026-08-19*

A fixed-window budget enforces a hard cliff: requests pass until the cap,
then block at 100%. Soft-landing degrades gracefully as a scope approaches
its limit, so spend tapers instead of stopping dead. It is an opt-in
addition to the existing `budget` block (see [ai-gateway.md#budgets](ai-gateway.md#budgets)
for the base `limits`, `on_exceed`, and `model_prices` fields this page
builds on); without `soft_landing` the hard-block behavior is unchanged.

This is a cost cap, not a request-rate cap: it tracks dollars and tokens
against a window, not requests per second per caller. For a semantic
rate limit keyed on the calling agent's identity instead, see
[agent-budget.md](agent-budget.md).

One thing this page's title oversells: nothing here forecasts spend. The
mechanism is a ladder of fixed threshold fractions, `warn_at` and then
`downgrade_at`, each compared against the window's current spend before a
request is dispatched. There is no model of future usage and no
extrapolation; a scope that is at 0.79 of its cap gets exactly the same
treatment whether it is climbing fast or idle.

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
| `limits[].period` | `total` when omitted | `daily`, `weekly`, `monthly`, `total`, `lifetime`, or a LiteLLM-style duration such as `30d` or `1h`. `daily` is a fixed bucket aligned to UTC midnight, not a rolling 24 hours, so a window that straddles 00:00 UTC resets. An unrecognized value is not caught at config load: it is silently treated as cumulative (the same as `total`/`lifetime`), so a typo in this field does not fail loudly. |
| `on_exceed` | `block` | What happens at 100%. `block` refuses with 402, `log` allows and records, `downgrade` rewrites the model and refuses with 402 anyway if no target resolves. |
| `soft_landing` | absent | Opt-in. Without it the hard-block behavior above is unchanged. |
| `soft_landing.warn_at` | `0.8` | Past this fraction, a request is allowed and a warning is logged. |
| `soft_landing.downgrade_at` | `0.95` | Past this fraction, the request's model is rewritten before dispatch. Nothing validates that it is above `warn_at`. |
| `soft_landing.downgrade_to` | optional | The fallback rewrite target. A per-limit `downgrade_to` on the limit that tripped always wins over this one when the limit sets it, not only when this field is absent; without either, the cheapest model across the configured providers is used. It has to be a model the providers serve, and a rewrite to the model already requested is a no-op with no log line and no tag. |

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

Only the downgrade band is tagged. A warn-band request is dispatched
exactly as it was sent, so it leaves nothing behind on the usage record and
a tag query will not find it. The warn log line is the only place it shows,
which is why the two bands are read from different surfaces below.

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
make run CONFIG=examples/ai-predictive-budget/sb.yml 2>&1 | tee /tmp/sbproxy-predictive-budget.log
```

The proxy logs to stderr and writes no log file of its own, so the `tee` is
what gives the `grep` further down something to read. Nothing else needs it.

The four bands, with the fraction the gateway compared each threshold
against:

```
1 below warn_at          preflight=0        status=200  served=gpt-4o
2 past warn_at           preflight=0.85     status=200  served=gpt-4o
3 past downgrade_at      preflight=0.969    status=200  served=gpt-4o-mini
4 at the cap             preflight=6000.969059999999 status=402  served=budget_exceeded
```

The third row is the feature: the client asked for `gpt-4o`, and
`gpt-4o-mini` is what the upstream was handed.

The fraction itself is a gauge, served unauthenticated on the data-plane
port:

```
# HELP sbproxy_ai_budget_utilization_ratio Budget utilization as a fraction of the limit; above 1 is over budget
# TYPE sbproxy_ai_budget_utilization_ratio gauge
sbproxy_ai_budget_utilization_ratio{scope="workspace"} 6000.969059999999
```

Both bands log at warn level, and the downgrade line names the model it
rewrote to:

```
2026-08-02T20:38:51.639345Z  WARN sbproxy_core::server::ai_dispatch: AI budget: approaching limit (soft-landing warn) fraction=0.85
2026-08-02T20:38:51.704920Z  WARN sbproxy_core::server::ai_dispatch: AI budget: approaching limit (soft-landing warn) fraction=0.851
2026-08-02T20:38:51.753606Z  WARN sbproxy_core::server::ai_dispatch: AI budget: soft-landing downgrade before hard cap fraction=0.969 new_model=gpt-4o-mini
2026-08-02T20:38:51.792899Z  WARN sbproxy_core::server::ai_dispatch: AI budget: soft-landing downgrade before hard cap fraction=0.9690599999999999 new_model=gpt-4o-mini
```

The tag lands on the usage record and nowhere else, so a sink is what makes
the degradation queryable afterwards. A `ledger` sink (see
[ai-usage-ledger.md](ai-usage-ledger.md)) carries the same tag in its
hash-chained, optionally signed entry, so a downgrade shows up in the
tamper-evident record too, not only in whatever plain sink you also
configure:

```
{"model": "gpt-4o-mini", "tag": "budget_soft_landing", "cost_usd": 0.06}
{"model": "gpt-4o-mini", "tag": "budget_soft_landing", "cost_usd": 6000000.0}
```

And the cap, once the window is spent:

```
HTTP/1.1 402 Payment Required
content-type: application/json
content-length: 117
Date: Sun, 02 Aug 2026 20:38:51 GMT
Connection: keep-alive

{"error":{"message":"cost limit exceeded: $6000969.0600 >= $1000.0000","scope":"workspace","type":"budget_exceeded"}}
```

## See also

- [ai-gateway.md#budgets](ai-gateway.md#budgets) - the base `budget` block (`limits`, `on_exceed`, `model_prices`) this page adds `soft_landing` to.
- [ai-usage-ledger.md](ai-usage-ledger.md) - the tamper-evident sink a `budget_soft_landing` tag lands in when configured.
- [agent-budget.md](agent-budget.md) - a request-rate and token-rate cap keyed on the calling agent, independent of this cost-based budget.
