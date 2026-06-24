# AI gateway: fallback chain across providers

*Last modified: 2026-06-24*

![sbproxy failing over from a down primary provider to a live backup](../../docs/assets/ai-fallback.gif)

Providers are listed in priority order. With `routing.strategy: fallback_chain`, the proxy tries the highest-priority provider first and advances to the next when an attempt fails at the transport level (connection refused, DNS failure, timeout) or returns a retriable 5xx (500, 502, 503). From the client's perspective the call simply succeeds.

In this example the primary provider points at a closed local port to simulate an outage, so every request fails over to the live backup. Swap the primary's `base_url` for a real upstream in production and keep the backup as a warm spare.

A 4xx such as 401 (a bad key) is treated as a client error and is **not** retried on another provider; only transport failures and retriable 5xx advance the chain.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/ai-routing-fallback/sb.yml
```

## Try it

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' \
    | jq -r '.model, .choices[0].message.content'
claude-haiku-4-5-20251001
A reverse proxy is a server that sits between clients and backend servers, forwarding requests to the appropriate backend.
```

The client gets a clean answer. The primary attempt and the handover are visible in the proxy log:

```
AI proxy: upstream request failed error=... provider=primary-unreachable attempt=0
```

## What this exercises

- `routing.strategy: fallback_chain` with priority-ordered providers
- Transport-level failure detection and automatic advancement to the next provider
- A live backup serving the request transparently, with no client-side retry

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview, routing strategies
- [examples/ai-cost-optimized](../ai-cost-optimized) - cost-aware provider selection
- [examples/ai-multi-provider](../ai-multi-provider) - multi-provider with guardrails
