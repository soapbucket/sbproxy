# AI gateway: Anthropic Claude direct

*Last modified: 2026-04-27*

Direct integration with the Anthropic Messages API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to Anthropic's `/v1/messages` shape on the way out and converts the response back to OpenAI shape on the way in. The translator hoists `system` role messages, defaults `max_tokens`, drops OpenAI-only fields (`logit_bias`, `n`, `presence_penalty`, `frequency_penalty`, `response_format`, `seed`, `user`), rewrites the path, then reassembles `choices[].message.content` from Anthropic's content blocks and renames usage fields. The result is that any OpenAI SDK works against `api.local` without modification, and Claude does the work.

## Run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/11-ai-claude/sb.yml
```

Requires `ANTHROPIC_API_KEY` in the environment.

## Try it

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "claude-3-5-sonnet-latest",
      "messages": [
        {"role": "system", "content": "You write terse haiku."},
        {"role": "user", "content": "Write a haiku about caching."}
      ]
    }'
{
  "id": "msg_01XyZ...",
  "object": "chat.completion",
  "created": 1714200000,
  "model": "claude-3-5-sonnet-latest",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Bytes wait by the door,\nReturn before the hot path,\nLatency sleeps deep."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 21, "completion_tokens": 23, "total_tokens": 44}
}
```

The response shape is OpenAI even though Claude served it. `usage.prompt_tokens` and `usage.completion_tokens` are renamed from Anthropic's `input_tokens` / `output_tokens`.

A model outside the allowlist is rejected:

```bash
$ curl -is http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}' | head -n 1
HTTP/1.1 400 Bad Request
```

## What this exercises

- `ai_proxy` action with the Anthropic provider - OpenAI-compatible front door over Anthropic Messages on the upstream
- Request translator - hoists `system`, defaults `max_tokens`, strips OpenAI-only fields, rewrites the path
- Response translator - concatenates content blocks into `choices[].message.content`, maps `stop_reason` to `finish_reason`, renames token fields
- `routing: round_robin` over a single provider - degenerate case, every request lands on `anthropic`

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md) - AI gateway overview
- [docs/providers.md](../../docs/providers.md) - per-provider behaviour and translator details
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
