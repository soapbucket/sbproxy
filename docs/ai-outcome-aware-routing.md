# Outcome-aware routing
*Last modified: 2026-07-28*

The latency- and cost-aware routing strategies decide from live signals or
static catalog price. None of them consume the *realized* outcome of a
request: whether it succeeded, was refused or content-filtered, what it
actually cost, and how long it took. The `outcome_aware` strategy closes
that loop. Every completed call feeds a per-provider rolling estimate, and
selection scores candidates by realized cost-per-success rather than list
price, demoting a provider whose refusal or error rate is rising.

This turns the gateway's own observations into a control signal, with no
external service.

## Configuration

```yaml
action:
  type: ai_proxy
  routing: outcome_aware
  providers:
    - name: openai-primary
      provider_type: openai
      api_key: ${OPENAI_API_KEY}
      default_model: gpt-4o-mini
      models: [gpt-4o-mini]
    - name: openai-secondary
      provider_type: openai
      api_key: ${OPENAI_API_KEY}
      default_model: gpt-4o-mini
      models: [gpt-4o-mini]
```

## How it scores

For each provider the store keeps an exponentially-weighted moving average
of realized cost, success rate, refusal rate, and latency. The score is the
realized cost per successful request, penalized by the refusal rate:

```
score = (ewma_cost / success_rate) * (1 + refusal_rate)
```

Lower is better. A provider that never succeeds scores infinity and is
avoided. Selection routes to the lowest-scoring eligible provider.

## Warm-up

Warm-up blends learned selection with deterministic round-robin rather than
switching all at once. Let `n` be the smallest sample count among the eligible
candidates, capped at five. In each repeating five-selection schedule, `n`
selections use the learned score and `5 - n` selections round-robin:

| Least-observed candidate | Learned selections | Round-robin selections |
| --- | --- | --- |
| 0 samples | 0 of 5 | 5 of 5 |
| 1 sample | 1 of 5 | 4 of 5 |
| 2 samples | 2 of 5 | 3 of 5 |
| 3 samples | 3 of 5 | 2 of 5 |
| 4 samples | 4 of 5 | 1 of 5 |
| 5 or more samples | 5 of 5 | 0 of 5 |

A fresh process therefore starts with pure round-robin. The first observation
from every candidate begins contributing learned choices without starving
exploration. The schedule uses the router's counter, so it is deterministic
for a fixed request order. Round-robin branches increment
`sbproxy_ai_routing_fallbacks_total{strategy="outcome_aware",reason="warmup"}`.

## Behavior

- A provider that starts refusing (or erroring) sees its success rate fall
  and its score rise, so traffic shifts to a healthier alternative within a
  bounded window.
- Between two healthy providers, the one with the lower realized
  cost-per-success wins, which is not always the lower list price.

The feedback store is process-wide and keyed by provider name. Replacing a
handler during a config hot reload does not discard its observations, so a
new router immediately sees the same learned scores. Restarting the process
does reset the store. Changing a provider name also creates a new feedback
identity.

The store is not a cluster-wide ledger. Each gateway process learns from its
own completed calls. It exposes read-only per-provider snapshots containing
sample count, accumulated latency-sensitive reward, realized cost, success,
refusal, and latency aggregates. Future bandit strategies can consume that
same snapshot instead of building a second feedback pipeline.

## Try it

The runnable example is in
[`examples/ai-outcome-aware-routing/`](../examples/ai-outcome-aware-routing/).
