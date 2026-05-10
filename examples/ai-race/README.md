# AI race routing

*Last modified: 2026-04-27*

Race strategy fans out the request to every eligible provider in parallel, returns the first 2xx response, and cancels the losers. Trade-off: race minimises p99 latency by always taking the fastest provider for any given request; the cost is N times the API spend (one paid completion per provider per request). Pair with `resilience` so persistently slow providers fall out of the eligible set instead of being dialed for every request forever. Race is wired through the same `Router::eligible_indices` filter the other strategies use, so circuit-breaker and outlier-detection ejections continue to apply.

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
# which provider answered first that round.
for i in 1 2 3 4 5; do
  curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
       -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}' \
       http://127.0.0.1:8080/v1/chat/completions | jq -r .model
done
```

```bash
# When outlier_detection ejects a provider it stops being raced. The
# other providers continue racing each other.
curl -s http://127.0.0.1:8080/__sbproxy/metrics 2>/dev/null \
  | grep ai_provider_state
```

## What this exercises

- `ai_proxy` action with `routing.strategy: race`
- Three providers (OpenAI, Anthropic, Groq) racing in parallel; first 2xx wins, losers are cancelled
- `resilience.outlier_detection` ejecting persistently slow providers from the race
- `Router::eligible_indices` filter applied identically to race and to other strategies

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/features.md](../../docs/features.md)
