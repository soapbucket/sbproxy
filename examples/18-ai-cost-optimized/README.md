# AI gateway: cost-optimised routing with weighted scoring

*Last modified: 2026-04-27*

The `cost_optimized` strategy scores each provider as `in_flight_requests * 1000 + weight` and routes to the lowest score. Cheaper providers get a lower weight and win ties when load is balanced; pricier providers get a higher weight and only run when cheaper providers saturate. Three providers are configured: `openrouter` (weight 1), `anthropic-haiku` (weight 5), and `anthropic-sonnet` (weight 50). Under light traffic, OpenRouter wins every request. As OpenRouter in-flight requests climb, the score crosses Anthropic Haiku's, and Haiku starts taking traffic. If both Haiku routes saturate, Anthropic Sonnet takes over.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENROUTER_API_KEY=sk-or-...
make run CONFIG=examples/18-ai-cost-optimized/sb.yml
```

Both env vars are required so all three providers can serve traffic.

## Try it

A single request lands on the cheapest provider:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-haiku-latest",
      "messages": [{"role": "user", "content": "Hello! Which provider served this?"}]
    }' | jq -r '.model'
anthropic/claude-3-haiku
```

(With the model rewrite the proxy applies on the OpenRouter route, the response's `model` field reflects the upstream model alias rather than the client request.)

Run a sustained burst and watch the distribution skew toward the more expensive routes only when in-flight load grows:

```bash
$ for i in $(seq 1 100); do
    curl -s http://127.0.0.1:8080/v1/chat/completions \
      -H 'Host: ai.local' -H 'Content-Type: application/json' \
      -d '{"model":"claude-3-5-haiku-latest","messages":[{"role":"user","content":"ping"}]}' \
      | jq -r '.model'
  done | sort | uniq -c
     78 anthropic/claude-3-haiku
     19 claude-3-5-haiku-latest
      3 claude-3-5-sonnet-latest
```

The proxy publishes `sbproxy_ai_requests_total{provider}` per provider so the per-route distribution is visible on a dashboard.

## What this exercises

- `ai_proxy.routing.strategy: cost_optimized` - weighted scoring with in-flight pressure
- Provider `weight` - lower weight wins first, higher weight is a spare
- `provider_type` override - reuse the Anthropic translator under a different display name
- `sbproxy_ai_requests_total{provider}` - per-provider request counters for traffic shape inspection

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/routing-strategies.md](../../docs/routing-strategies.md) - cost-optimised scoring formula
- [docs/metrics-stability.md](../../docs/metrics-stability.md) - per-provider AI metrics
