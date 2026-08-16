# AI race routing

*Last modified: 2026-08-16*

Race strategy fans out the request to every eligible provider in parallel, returns the first 2xx response, and cancels the losers. Trade-off: race minimises p99 latency by always taking the fastest provider for any given request; the cost is N times the API spend (one paid completion per provider per request). The config below pairs it with `resilience.outlier_detection` so persistently failing providers are meant to fall out of the eligible set instead of being dialed forever, but as of this pass that does not hold in practice for race (see the SUSPECTED PRODUCT BUG note under "Try it"): a losing racer's outcome never reaches the circuit breaker or the outlier detector, so it keeps getting raced no matter how often it fails.

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

**SUSPECTED PRODUCT BUG:** `resilience.outlier_detection` never ejects a
provider from a race. The race dispatch loop in
`crates/sbproxy-core/src/server/ai_dispatch.rs` (the `race_mode` block) only
calls `sbproxy_observe::metrics::record_provider_attempt(...)` for a losing
or erroring racer; it never calls `Router::record_provider_failure` /
`record_provider_success`, which are the only entry points that feed the
circuit breaker and the outlier detector. Repro: point `groq` at an invalid
key so it errors on every attempt (well past `min_requests: 5` at 100% error
rate, against `threshold: 0.5`) and send a batch of requests. `groq`'s
attempt counter keeps climbing forever and neither an `"ai provider ejected
by outlier detection"` nor an `"ai provider circuit breaker opened"` log line
ever appears, confirmed over 11 consecutive failing attempts in this session.
`Router::eligible_indices` (used elsewhere, e.g. by `forward_race` in
`crates/sbproxy-ai/src/client.rs`, which does call `record_provider_failure`)
never sees a race-mode failure to eject on, so the "pair with resilience"
guidance in this example's config comments does not currently hold for the
strategy actually reached by the HTTP server.

## What this exercises

- `ai_proxy` action with `routing.strategy: race`
- Three providers (OpenAI, Anthropic, Groq) racing in parallel; first 2xx wins, losers are cancelled
- `resilience.outlier_detection` config accepted and parsed for a race origin, though ejection does not currently take effect on the race dispatch path (SUSPECTED PRODUCT BUG, see "Try it")

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/features.md](../../docs/features.md)
