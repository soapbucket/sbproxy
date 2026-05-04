# AI gateway: fallback chain across three providers

*Last modified: 2026-04-27*

Three providers in priority order. Provider 1 (`broken-anthropic`) is intentionally configured with an invalid API key so it always returns 401. The router treats any non-2xx as an upstream failure and advances to provider 2 (`anthropic`), which serves the request with a real key. Provider 3 (`openrouter`) is the final fallback, picked up if Anthropic itself is unhealthy. From the client's perspective the call simply succeeds. Every handover increments `sbproxy_ai_failovers_total{from_provider, to_provider, reason}` so dashboards can show how often each spare is engaged.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENROUTER_API_KEY=sk-or-...
make run CONFIG=examples/17-ai-routing-fallback/sb.yml
```

Both env vars are required.

## Try it

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-sonnet-latest",
      "messages": [{"role": "user", "content": "Which provider answered this request?"}]
    }'
{
  "id": "msg_01...",
  "object": "chat.completion",
  "model": "claude-3-5-sonnet-latest",
  "choices": [
    {"index": 0, "message": {"role": "assistant", "content": "Anthropic served this request directly."}, "finish_reason": "stop"}
  ],
  "usage": {"prompt_tokens": 17, "completion_tokens": 8, "total_tokens": 25}
}
```

Inspect the failover counter in `/metrics` (proxy admin endpoint, if exposed) to confirm the path:

```
sbproxy_ai_failovers_total{from_provider="broken-anthropic",to_provider="anthropic",reason="401"} 1
```

If you remove the broken provider from the chain, the same request returns the same response, but `sbproxy_ai_failovers_total` does not increment.

## What this exercises

- `ai_proxy.routing.strategy: fallback_chain` - priority-ordered provider list
- Provider `priority` - lower wins first; failover advances down the list on non-2xx or timeout
- `provider_type` override - reuse the Anthropic translator with a custom provider name (`broken-anthropic`)
- `sbproxy_ai_failovers_total` metric - one increment per handover, labelled with the reason

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/routing-strategies.md](../../docs/routing-strategies.md) - fallback chain semantics
- [docs/providers.md](../../docs/providers.md) - per-provider notes
