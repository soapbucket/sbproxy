# ai-waste-signals

*Last modified: 2026-06-04*

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
| `sbproxy_ai_wasted_tokens_total{kind, provider, model, project, team}` | Token count tagged as wasted, partitioned by waste class + attribution |
| `sbproxy_ai_wasted_cost_dollars_total{kind, provider, model, project, team}` | Estimated USD cost of the wasted spend |

## Waste classes (the `kind` label)

| kind | Triggered by |
|---|---|
| `duplicate_request` | Exact-context resend; the `response_dedup` layer caught it. Re-tagging the spend as wasted is the canonical reuse signal. |
| `abandoned_stream` | The client cancelled or the upstream completed but the client never read it. Input + reasoning tokens still billed. |
| `validation_failed` | The request completed upstream but the gateway's structured-output / guardrail validation rejected the result; the spend happened anyway. |
| `context_bloat` | Input token count significantly above the route's rolling median (free-form heuristic signal an oversized prompt was sent). |

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/ai-waste-signals/sb.yml
```

## Drive a `duplicate_request` waste event

The `response_dedup` layer in this config catches exact-context
resends; the second call hits the cached response. The waste-tagger
registers the duplicate as wasted spend on the duplicate's wire
shape.

```bash
PAYLOAD='{"model":"claude-3-5-haiku-latest","messages":[{"role":"user","content":"hello"}]}'

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
curl -s http://127.0.0.1:9090/metrics | grep -E "^sbproxy_ai_wasted"
```

Expected (counter samples; values depend on the actual prompt):

```
sbproxy_ai_wasted_tokens_total{kind="duplicate_request",provider="anthropic",model="claude-3-5-haiku-latest",project="demo",team="demo-team"} 5
sbproxy_ai_wasted_cost_dollars_total{kind="duplicate_request",provider="anthropic",model="claude-3-5-haiku-latest",project="demo",team="demo-team"} 0.000005
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
