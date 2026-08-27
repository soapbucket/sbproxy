# AI race routing

*Last modified: 2026-08-16*

Race strategy fans out the request to every eligible provider in parallel, returns the first 2xx response, and cancels the losers. Trade-off: race minimises p99 latency by always taking the fastest provider for any given request; the cost is N times the API spend (one paid completion per provider per request). The config below pairs it with `resilience.outlier_detection` so persistently failing providers fall out of the eligible set instead of being dialed forever: every leg that settles feeds the circuit breaker, the outlier detector, and the per-error-class cooldown policy, so a provider that loses every race by failing is ejected and the fan-out shrinks.

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GROQ_API_KEY=gsk-...
sbproxy serve -f sb.yml
```

## Try it

```bash
# The fastest of the three providers wins; the other two are cancelled
# as soon as the first 2xx lands.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq '.choices[0].message, .model'
```

```bash
# Run a small batch; the response model field rotates depending on
# which provider answered first that round. Each provider's model_map
# translates the requested gpt-4o-mini to a model it actually serves
# (claude-haiku-4-5 on Anthropic, llama-3.1-8b-instant on Groq), so
# every racer can win.
for i in 1 2 3 4 5; do
  curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
       -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}' \
       http://127.0.0.1:8080/v1/chat/completions | jq -r .model
done
```

```bash
# Watch the per-provider attempt counter (sbproxy_ai_provider_attempts_total,
# labeled by outcome) on the data-plane metrics endpoint. The race path does
# not populate sbproxy_ai_provider_errors_total; that counter is fed by the
# sequential failover/cascade dispatch paths, not race.
curl -s http://127.0.0.1:8080/metrics | grep sbproxy_ai_provider
# sbproxy_ai_provider_attempts_total{outcome="error",provider="groq"} 11
# sbproxy_ai_provider_attempts_total{outcome="success",provider="anthropic"} 2
# sbproxy_ai_provider_attempts_total{outcome="success",provider="openai"} 9
```

Watch the ejection land. Point `groq` at an invalid key so it fails every
attempt, then send a batch of requests past `min_requests: 5` at a 100%
error rate against `threshold: 0.5`. An `"ai provider ejected by outlier
detection"` line names `groq`, its attempt counter stops climbing, and the
fan-out drops to the two providers still eligible. A `5xx` and a transport
error both count as the provider's failure; a `4xx` counts as the caller's
and does not eject, so a provider rate-limiting every request is parked by
`resilience.cooldown_policy: { rate_limit: <seconds> }` rather than by the
outlier detector.

## What this exercises

- `ai_proxy` action with `routing.strategy: race`
- Three providers (OpenAI, Anthropic, Groq) racing in parallel; first 2xx wins, losers are cancelled
- `resilience.outlier_detection` ejecting a persistently failing racer, so the fan-out shrinks instead of paying for a leg that always fails

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/features.md](../../docs/features.md)
