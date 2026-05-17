# AI gateway: cascade routing across two tiers

*Last modified: 2026-05-17*

The `cascade` strategy walks an ordered list of `(provider, model)` tiers from cheapest to most expensive. Each tier's response is graded against a `quality_threshold`, compared against the response body's top-level `confidence_score` field. When the score falls below the threshold, the response is empty, or the response is refused, the cascade retries on the next tier. The dispatcher stops as soon as a tier's response meets the threshold or the cumulative cost reaches `max_total_cost`.

This is the pattern proven Pareto-optimal in [A Unified Approach to Routing and Cascading for LLMs](https://arxiv.org/abs/2410.10347): try the cheap model first, fall back to the expensive one only when the cheap answer is not good enough.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-cascade-routing/sb.yml
```

## Try it

A short factual query: cheap tier wins.

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [{"role": "user",
      "content": "What is the capital of France?"}]
  }'
```

A harder analytical query, where the cheap tier may return a low-confidence answer and the cascade falls through to the expensive tier:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [{"role": "user",
      "content": "Explain why cascade routing is Pareto-optimal."}]
  }'
```

## How quality is graded

The proxy looks for a top-level `confidence_score` field on the upstream response body. When the field is missing the response is treated as `1.0` (always accepted), so providers that do not emit a score do not cause unnecessary escalation. Future iterations will support classifier-based scoring and CEL expressions; this v1 release uses the explicit field only.

## Metrics

Each tier outcome ticks the cascade counter:

```
sbproxy_ai_cascade_tier_outcomes_total{tier="0", outcome="accepted"}
sbproxy_ai_cascade_tier_outcomes_total{tier="0", outcome="retry"}
sbproxy_ai_cascade_tier_outcomes_total{tier="1", outcome="accepted"}
sbproxy_ai_cascade_tier_outcomes_total{tier="1", outcome="cost_cap"}
```

The `outcome` label is one of `accepted`, `retry`, or `cost_cap`. Plot the ratio of `tier="0", outcome="accepted"` to total requests to see how often the cheap tier is sufficient.

## Limitations

- Streaming requests dispatch to tier 1 only. Mid-stream retry is out of scope for v1.
- The semantic response cache is not engaged on the cascade path. The other 10 routing strategies still cache normally.
- Idempotency capture is skipped on cascade responses in v1.
