# AI gateway resilience primitives

*Last modified: 2026-04-27*

Three independent resilience signals run on the AI provider pool. Any one can eject a provider from the routing list. (1) `circuit_breaker` is the classic Closed -> Open -> HalfOpen state machine; five consecutive 5xx or transport errors flip a provider Open for 30s and two successful HalfOpen probes close it again. (2) `outlier_detection` watches a 60-second sliding window; once a provider hits 50% failure rate over five or more requests it is ejected for 30s. (3) `health_check` makes a passive HTTP probe to `/models` every 30s; three consecutive failures eject and two consecutive successes reinstate. When every provider is ejected the router falls back to the unfiltered enabled list rather than refusing the request, so a misconfigured threshold never causes a total outage.

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
sbproxy serve -f sb.yml
```

## Try it

```bash
# Round-robin healthy traffic across both providers.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq .choices[0].message
```

```bash
# Watch provider health metrics. With OpenAI returning 503s, the breaker
# trips Open within 5 consecutive failures and traffic shifts entirely
# to Anthropic until the open duration elapses.
curl -s http://127.0.0.1:8080/metrics 2>/dev/null \
  | grep -E 'sbproxy_ai_(requests|failovers|request_duration)'
```

```bash
# Outlier detection complements the breaker by ejecting on aggregate
# failure rate over a sliding window, even when there is no consecutive
# streak (intermittent flapping).
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"claude-3-5-haiku-latest","messages":[{"role":"user","content":"hi"}]}'
```

## What this exercises

- `ai_proxy` action with `routing.strategy: round_robin` across multiple providers
- `resilience.circuit_breaker` - per-provider Closed/Open/HalfOpen state machine
- `resilience.outlier_detection` - sliding-window failure-rate ejection
- `resilience.health_check` - active probe of `/models` with unhealthy / healthy thresholds
- Fallback to the unfiltered provider list when every provider is ejected at once

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
