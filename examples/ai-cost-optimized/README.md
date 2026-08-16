# AI gateway: cost-optimized routing with weighted scoring

*Last modified: 2026-08-16*

The `cost_optimized` strategy scores each provider as `in_flight_requests * 1000 + weight` and routes to the lowest score. Cheaper providers get a lower weight and win ties when load is balanced; pricier providers get a higher weight and only run when cheaper providers saturate. Three providers are configured: `openrouter` (weight 1), `anthropic-haiku` (weight 5), and `anthropic-sonnet` (weight 50). All three declare the same logical model, `claude-haiku-4-5`, and each `model_map` rewrites it to what that upstream actually serves, so any provider can take any request. Under light traffic, OpenRouter wins every request. As OpenRouter in-flight requests climb, the score crosses Anthropic Haiku's, and Haiku starts taking traffic. If both Haiku routes saturate, the Sonnet tier takes over.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENROUTER_API_KEY=sk-or-...
make run CONFIG=examples/ai-cost-optimized/sb.yml
```

Both env vars are required so all three providers can serve traffic.

## Try it

A single request lands on the cheapest provider:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-haiku-4-5",
      "messages": [{"role": "user", "content": "Hello! Which provider served this?"}]
    }' | jq -r '.model'
anthropic/claude-3-haiku
```

(The OpenRouter route's `model_map` rewrites the requested `claude-haiku-4-5` to the alias `anthropic/claude-3-haiku` on the way out, so the response's `model` field reflects the upstream alias rather than the client request.)

Verifying this pass required a real `OPENROUTER_API_KEY`, which was not available in this pass; a dummy key confirmed the routing decision itself (a single idle-load request is dispatched to `openrouter`, the weight-1 provider, exactly as described) but the upstream call then fails auth rather than returning the 200 shown above. The `model` field and the response shape are documented as OpenRouter would return them, unverified end-to-end here.

Run a sustained *concurrent* burst and watch the distribution skew toward the more expensive routes only when in-flight load grows. The `in_flight_requests` term in the scoring formula is a live gauge, incremented on dispatch and decremented when that request's response headers come back, so a one-request-at-a-time loop never builds up any load: each `curl` completes (and releases its slot) before the next one starts, and the strategy degenerates to picking the lowest `weight` on every single call. Fire the requests in parallel instead:

```bash
$ seq 1 100 | xargs -P 20 -I{} curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"ping"}]}' \
    | jq -r '.model' \
  | sort | uniq -c
```

Exact counts vary run to run with real network timing, but expect most requests on `anthropic/claude-3-haiku` (OpenRouter, weight 1) with a smaller share spilling onto `claude-haiku-4-5` (weight 5) and fewer still onto `claude-sonnet-4-5` (weight 50) as OpenRouter's in-flight count climbs above zero. `-P 20` (20 requests in flight at once against a pool of three providers) is generally enough to push some traffic off the cheapest route; `-P 1`, i.e. the sequential loop this example used to document, is not, because a request's in-flight slot is released as soon as its own response headers arrive and never overlaps the next request in a one-at-a-time loop. The proxy publishes `sbproxy_ai_provider_attempts_total{provider,outcome}` per provider (there is no metric literally named `sbproxy_ai_requests_total`), so the per-route distribution is visible on a dashboard.

## What this exercises

- `ai_proxy.routing.strategy: cost_optimized` - weighted scoring with in-flight pressure
- Provider `weight` - lower weight wins first, higher weight is a spare
- Shared logical model plus per-provider `model_map` - one request model, three upstream implementations
- `provider_type` override - reuse the Anthropic translator under a different display name
- `sbproxy_ai_provider_attempts_total{provider,outcome}` - per-provider request counters for traffic shape inspection

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/routing-strategies.md](../../docs/routing-strategies.md) - cost-optimized scoring formula
- [docs/metrics-stability.md](../../docs/metrics-stability.md) - per-provider AI metrics
