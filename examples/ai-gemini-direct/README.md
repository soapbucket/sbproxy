# AI gateway: Google Gemini direct

*Last modified: 2026-05-15*

Direct integration with the Google Gemini API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to Gemini's `:generateContent` shape on the way out and converts the response back to OpenAI shape on the way in. The translator hoists `system` role messages to `systemInstruction`, moves sampling knobs under `generationConfig`, rewrites `tools` to `functionDeclarations`, drops OpenAI-only fields, rewrites the path, then reassembles `choices[].message.content` from Gemini's content parts and renames usage fields. The result is that any OpenAI SDK works against `ai.local` without modification, and Gemini does the work.

## Run

```bash
export GEMINI_API_KEY=...
make run CONFIG=examples/ai-gemini-direct/sb.yml
```

Requires `GEMINI_API_KEY` in the environment.

## Try it

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "gemini-1.5-pro",
      "messages": [
        {"role": "system", "content": "You write terse haiku."},
        {"role": "user", "content": "Write a haiku about caching."}
      ]
    }'
{
  "id": "gen_01XyZ...",
  "object": "chat.completion",
  "model": "gemini-1.5-pro",
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

The response shape is OpenAI even though Gemini served it. `usage.prompt_tokens` and `usage.completion_tokens` are renamed from Gemini's `promptTokenCount` / `candidatesTokenCount`.

## What this exercises

- `ai_proxy` action with the Gemini provider, OpenAI-compatible front door over Gemini's generative API on the upstream
- Request translator, hoists `system`, moves sampling under `generationConfig`, translates `tools` to `functionDeclarations`, strips OpenAI-only fields, rewrites the path to `/v1beta/models/{model}:generateContent`
- Response translator, concatenates text parts into `choices[].message.content`, converts `functionCall` parts to `tool_calls`, maps `finishReason` to `finish_reason`, renames token fields
- `routing: round_robin` over a single provider, degenerate case, every request lands on `gemini`

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md), AI gateway overview
- [docs/providers.md](../../docs/providers.md), per-provider behaviour and translator details
- [docs/configuration.md](../../docs/configuration.md), configuration schema
