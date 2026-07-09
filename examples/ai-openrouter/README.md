# AI gateway: OpenRouter

*Last modified: 2026-07-09*

Routes OpenAI-compatible chat completion requests through OpenRouter. Clients speak the OpenAI protocol; SBproxy injects the OpenRouter API key, forwards the request to `https://openrouter.ai/api/v1`, and returns the response unchanged. Four model aliases are allowlisted via `allowed_models`, with `anthropic/claude-sonnet-4.5` as the default if a request arrives without an explicit `model` field. Routing is `fallback_chain`, but with a single provider the chain is effectively a passthrough; the gateway behaves like a thin authenticated proxy in front of OpenRouter.

## Run

```bash
export OPENROUTER_API_KEY=sk-or-...
make run CONFIG=examples/ai-openrouter/sb.yml
```

Requires an OpenRouter account and `OPENROUTER_API_KEY` in the environment.

## Try it

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "anthropic/claude-sonnet-4.5",
      "messages": [{"role": "user", "content": "Hello!"}]
    }'
{
  "id": "gen-1714200000-abc123",
  "object": "chat.completion",
  "created": 1714200000,
  "model": "anthropic/claude-sonnet-4.5",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "Hello! How can I help you today?"},
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 8, "completion_tokens": 11, "total_tokens": 19}
}
```

A request for a model outside `allowed_models` is rejected with 403 before any upstream call:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"model":"openai/gpt-4-turbo","messages":[{"role":"user","content":"hi"}]}' | head -n 1
HTTP/1.1 403 Forbidden
```

The body is `{"error":"model 'openai/gpt-4-turbo' is not allowed"}`.

Omit the `model` field and the configured `default_model` is used:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"messages":[{"role":"user","content":"Pick a colour."}]}' \
  | jq -r '.model'
anthropic/claude-sonnet-4.5
```

## What this exercises

- `ai_proxy` action - OpenAI-compatible front door
- OpenRouter provider - upstream auth via `${OPENROUTER_API_KEY}` interpolation
- `default_model` and `allowed_models` - default selection plus gateway-level model gating (403 outside the list)
- `routing: fallback_chain` - single-provider chain behaves as a passthrough

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/providers.md](../../docs/providers.md) - per-provider notes
- [docs/routing-strategies.md](../../docs/routing-strategies.md) - routing strategies
