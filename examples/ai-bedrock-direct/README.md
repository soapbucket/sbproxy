# AI gateway: AWS Bedrock direct (Converse API)

*Last modified: 2026-08-21*

Direct integration with AWS Bedrock's model-agnostic Converse API. Clients send OpenAI-shaped chat completion requests; SBproxy translates them to the Converse shape on the way out and converts the response back to OpenAI shape on the way in. Because Converse is model-agnostic, the same configuration fans out across Claude on Bedrock, Llama on Bedrock, Mistral on Bedrock, and Titan, with no per-model branching at the gateway layer. The translator hoists `system` role messages, moves sampling knobs under `inferenceConfig`, rewrites `tools` to `toolConfig.tools[].toolSpec`, drops OpenAI-only fields, rewrites the path to `/model/{modelId}/converse`, then reassembles `choices[].message.content` from Bedrock's content blocks and renames usage fields.

## Auth

Bedrock requires AWS SigV4 request signing, which the `aws_sigv4:` block on the provider entry handles. There is no `api_key` here and no sidecar in front: SBproxy computes the `Authorization: AWS4-HMAC-SHA256 ...` header for each request, over that request's method, host, path, signed headers, and a SHA-256 of the translated Converse body.

`region` is the credential scope and is required. It is separate from the endpoint, the way an AWS SDK's `endpoint_url` override is separate from its configured region, so a VPC endpoint in `base_url` would still sign for `us-east-1`. With `base_url` unset, as it is here, `region` fills the `{region}` placeholder in the provider catalog's default URL.

Credentials come from the standard AWS provider chain by default, so anything the AWS CLI can find works: environment variables, `~/.aws/credentials`, an EKS web identity token, an ECS task role, an EC2 instance profile. Set `credentials.source: static` for an explicit key pair, or `assume_role` for an STS session SBproxy renews 900 seconds before it expires. See [docs/providers.md](../../docs/providers.md#aws-sigv4-signing-for-bedrock-and-sagemaker) for the credential table and for what expiry and clock skew look like in the log.

## Run

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
make run CONFIG=examples/ai-bedrock-direct/sb.yml
```

Requires AWS credentials with `bedrock:InvokeModel` permission for the listed models. Set `AWS_REGION` for a region other than `us-east-1`.

## Try it

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "anthropic.claude-sonnet-4-5-20250929-v1:0",
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
- `aws_sigv4` request signing on the outbound path, with the region filling the catalog's `{region}` endpoint placeholder and credentials resolved from the standard AWS provider chain

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md), AI gateway overview
- [docs/providers.md](../../docs/providers.md), per-provider behavior and translator details
- [docs/configuration.md](../../docs/configuration.md), configuration schema
