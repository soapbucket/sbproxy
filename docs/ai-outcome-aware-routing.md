# Outcome-aware routing
*Last modified: 2026-06-24*

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

While any candidate has fewer than a handful of samples, the strategy
round-robins so every provider earns an estimate before the store commits
to the cheapest-per-success one. A fresh deployment therefore behaves
exactly like round-robin until it has data, which makes the strategy safe
to enable with no other change.

## Behavior

- A provider that starts refusing (or erroring) sees its success rate fall
  and its score rise, so traffic shifts to a healthier alternative within a
  bounded window.
- Between two healthy providers, the one with the lower realized
  cost-per-success wins, which is not always the lower list price.

The feedback store is process-wide and keyed by provider name, so it
survives a config hot reload and is shared across an origin's deployments.

## Try it

The runnable example is in
[`examples/ai-outcome-aware-routing/`](../examples/ai-outcome-aware-routing/).
