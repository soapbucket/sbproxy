# ai-waste-signals

*Last modified: 2026-08-16*

> **Known issue: `duplicate_request` and `context_bloat` never fire.**
> `response_dedup` below is not a recognized config key: the proxy accepts
> it silently (no validation error, no warning) and it has no effect, so
> the "Drive a `duplicate_request` waste event" walkthrough does not
> actually produce a cache hit. Sending the same payload twice makes two
> full upstream calls (confirmed: two different response ids, near-identical
> latency, `served_from_cache: false` on both access-log rows). More
> generally, the `duplicate_request` and `context_bloat` waste kinds are
> defined in the metric taxonomy (`sbproxy_ai_wasted_tokens_total{kind=...}`
> registers and accepts both label values) but nothing in the request path
> currently records either one; only `validation_failed`, `abandoned_stream`,
> and `failover_loser` are wired up to real events. This is a product gap,
> not a config mistake: fixing it needs a `response_dedup` implementation
> (or equivalent) and a `context_bloat` detector wired into the AI dispatch
> path, tracked for follow-up.

Tokenomics layer: surface tokens spent with no outcome. The proxy
emits two Prometheus counters per waste class so a FinOps dashboard
can answer "what fraction of our AI spend was wasted, and why?"

These are **observational** counters; they do not enforce. Pair with
the budget enforcer in [`ai-budget`](../ai-budget/) for enforcement
and with the attribution-tag schema in
[`ai-attribution-tags`](../ai-attribution-tags/) for per-team
grouping.

## Metrics

| Counter | Description |
|---|---|
| `sbproxy_ai_wasted_tokens_total{kind, provider, model, surface, project, feature, team, agent_type, environment}` | Token count tagged as wasted, partitioned by waste class + attribution |
| `sbproxy_ai_wasted_cost_dollars_total{kind, provider, model, surface, project, feature, team, agent_type, environment}` | Estimated USD cost of the wasted spend |

Attribution labels without a value (here `feature`, `agent_type`, and `environment`) are emitted as empty strings so `sum without (...)` queries keep working.

## Waste classes (the `kind` label)

| kind | Triggered by |
|---|---|
| `duplicate_request` | **Not currently emitted; see the known-issue note above.** Documented intent: exact-context resend caught by a `response_dedup` layer, re-tagged as wasted spend. |
| `abandoned_stream` | The client cancelled or the upstream completed but the client never read it. Input + reasoning tokens still billed. Live. |
| `validation_failed` | The request completed upstream but the gateway's structured-output / guardrail validation rejected the result; the spend happened anyway. Live. |
| `context_bloat` | **Not currently emitted; see the known-issue note above.** Documented intent: input token count significantly above the route's rolling median. |
| `failover_loser` | A cascade tier returned a body but lost (5xx, refusal, or below its quality threshold) to a later tier; the losing tier's tokens bought no served outcome. Live. |

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/ai-waste-signals/sb.yml
```

## Drive a `duplicate_request` waste event

**Currently a no-op; see the known-issue note at the top.** The intent:
a `response_dedup` layer catches exact-context resends and the second
call hits a cached response, with the waste-tagger registering the
duplicate as wasted spend. As shipped, both calls below make a full,
separate upstream request (different response ids, comparable latency,
`served_from_cache: false` on both access-log rows), and no
`duplicate_request` sample appears on either counter.

```bash
PAYLOAD='{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"hello"}]}'

# First call: cache miss, real upstream spend.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H "Authorization: Bearer ${ANTHROPIC_API_KEY}" \
  -d "$PAYLOAD" | head -c 80

# Second call: dedup hit, the cached response is served. The
# second's input tokens get tagged as wasted (duplicate_request).
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H "Authorization: Bearer ${ANTHROPIC_API_KEY}" \
  -d "$PAYLOAD" | head -c 80
```

## Read the counters

```bash
curl -s http://127.0.0.1:8080/metrics | grep -E "^sbproxy_ai_wasted"
```

As shipped, no `kind="duplicate_request"` sample appears at all (see the
known-issue note at the top); both calls above are plain cache misses. This
is the sample shape once `response_dedup` and the `duplicate_request` waste
kind are wired up:

```
sbproxy_ai_wasted_tokens_total{agent_type="",environment="",feature="",kind="duplicate_request",model="claude-haiku-4-5",project="demo",provider="anthropic",surface="chat_completions",team="demo-team"} 5
sbproxy_ai_wasted_cost_dollars_total{agent_type="",environment="",feature="",kind="duplicate_request",model="claude-haiku-4-5",project="demo",provider="anthropic",surface="chat_completions",team="demo-team"} 0.000005
```

## Dashboarding pattern

A "wasted spend by reason" stacked bar in Grafana:

```promql
sum by (kind) (rate(sbproxy_ai_wasted_cost_dollars_total[5m]))
```

A "wasted spend by team" pie, useful for chargeback conversations:

```promql
sum by (team) (rate(sbproxy_ai_wasted_cost_dollars_total[1h]))
```

## See also

- [`ai-budget`](../ai-budget/) - budget enforcement (the
  observational counters here pair with the enforcement there).
- [`ai-attribution-tags`](../ai-attribution-tags/) - per-team
  attribution that makes the waste counters groupable.
- [`docs/observability.md`](../../docs/observability.md) - the
  metric naming convention and stability guarantees.
