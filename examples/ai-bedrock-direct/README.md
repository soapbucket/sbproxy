# AI gateway: AWS Bedrock direct (Converse API)

*Last modified: 2026-05-15*

Direct integration with AWS Bedrock's model-agnostic Converse API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to the Converse shape on the way out and converts the response back to OpenAI shape on the way in. Because Converse is model-agnostic, the same configuration fans out across Claude on Bedrock, Llama on Bedrock, Mistral on Bedrock, and Titan, with no per-model branching at the gateway layer. The translator hoists `system` role messages, moves sampling knobs under `inferenceConfig`, rewrites `tools` to `toolConfig.tools[].toolSpec`, drops OpenAI-only fields, rewrites the path to `/model/{modelId}/converse`, then reassembles `choices[].message.content` from Bedrock's content blocks and renames usage fields.

## Auth

Bedrock requires AWS SigV4 request signing. This example uses a static `Authorization` header for simplicity; production deployments should wire SigV4 signing into the upstream request path or front Bedrock with a sidecar that handles it.

## Run

```bash
export BEDROCK_AUTH="Bearer ${AWS_SESSION_TOKEN}"
make run CONFIG=examples/ai-bedrock-direct/sb.yml
```

Requires AWS credentials with `bedrock:InvokeModel` permission for the listed models.

## Try it

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
      "messages": [
        {"role": "system", "content": "You write terse haiku."},
        {"role": "user", "content": "Write a haiku about caching."}
      ]
    }'
{
  "object": "chat.completion",
  "model": null,
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

The response shape is OpenAI even though Bedrock served it. `usage.prompt_tokens` and `usage.completion_tokens` are renamed from Bedrock's `inputTokens` / `outputTokens`.

## What this exercises

- `ai_proxy` action with the Bedrock provider, OpenAI-compatible front door over Bedrock Converse on the upstream
- Request translator, hoists `system` to a top-level array, moves sampling under `inferenceConfig`, translates `tools` to `toolConfig.tools[].toolSpec`, strips OpenAI-only fields, rewrites the path to `/model/{modelId}/converse`
- Response translator, concatenates text content blocks into `choices[].message.content`, converts `toolUse` blocks to `tool_calls`, maps `stopReason` to `finish_reason`, renames token fields
- `routing: round_robin` over a single provider, the same configuration handles every Bedrock model family

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md), AI gateway overview
- [docs/providers.md](../../docs/providers.md), per-provider behaviour and translator details
- [docs/configuration.md](../../docs/configuration.md), configuration schema
