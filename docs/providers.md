# Supported providers
*Last modified: 2026-04-25*

SBproxy ships native adapters for 43 LLM providers, reaching 200+ models behind one OpenAI-compatible API. Most adapters speak the OpenAI wire format and pass through unchanged; a few (Anthropic, Bedrock, Gemini, SageMaker, Oracle, Watsonx) translate to the provider's native shape.

## Native providers

Each provider has a default base URL and auth format. Override `base_url` if you self-host or use a regional endpoint.

| Name | Provider | Format | Auth | Default Base URL |
|------|----------|--------|------|------------------|
| `openai` | OpenAI | OpenAI | `Authorization: Bearer` | `https://api.openai.com/v1` |
| `anthropic` | Anthropic Claude | Anthropic Messages | `x-api-key` | `https://api.anthropic.com/v1` |
| `gemini` | Google Gemini | Google | `Authorization: Bearer` | `https://generativelanguage.googleapis.com/v1beta` |
| `azure` | Azure OpenAI | OpenAI | `api-key` | `https://{resource}.openai.azure.com/openai` |
| `bedrock` | AWS Bedrock | Bedrock | Authorization (SigV4 signed externally)[^sigv4] | `https://bedrock-runtime.{region}.amazonaws.com` |
| `cohere` | Cohere | OpenAI | `Authorization: Bearer` | `https://api.cohere.com/v2` |
| `mistral` | Mistral AI | OpenAI | `Authorization: Bearer` | `https://api.mistral.ai/v1` |
| `groq` | Groq | OpenAI | `Authorization: Bearer` | `https://api.groq.com/openai/v1` |
| `deepseek` | DeepSeek | OpenAI | `Authorization: Bearer` | `https://api.deepseek.com/v1` |
| `ollama` | Ollama (local) | OpenAI | `Authorization: Bearer` (optional)[^ollama] | `http://localhost:11434/v1` |
| `vllm` | vLLM (self-hosted) | OpenAI | `Authorization: Bearer` | `http://localhost:8000/v1` |
| `tgi` | Hugging Face TGI (self-hosted) | OpenAI | `Authorization: Bearer` | `http://localhost:8080/v1` |
| `lmstudio` | LM Studio (local) | OpenAI | `Authorization: Bearer` | `http://localhost:1234/v1` |
| `llamacpp` | `llama.cpp` server (local) | OpenAI | `Authorization: Bearer` | `http://localhost:8080/v1` |
| `together` | Together AI | OpenAI | `Authorization: Bearer` | `https://api.together.xyz/v1` |
| `fireworks` | Fireworks AI | OpenAI | `Authorization: Bearer` | `https://api.fireworks.ai/inference/v1` |
| `perplexity` | Perplexity | OpenAI | `Authorization: Bearer` | `https://api.perplexity.ai` |
| `xai` | xAI (Grok) | OpenAI | `Authorization: Bearer` | `https://api.x.ai/v1` |
| `sagemaker` | Amazon SageMaker | Custom | Authorization (SigV4 signed externally)[^sigv4] | `https://runtime.sagemaker.{region}.amazonaws.com` |
| `databricks` | Databricks | OpenAI | `Authorization: Bearer` | `https://{workspace}.cloud.databricks.com/serving-endpoints` |
| `oracle` | Oracle OCI Generative AI | Custom | `Authorization: Bearer` | `https://inference.generativeai.{region}.oci.oraclecloud.com` |
| `watsonx` | IBM watsonx | Custom | `Authorization: Bearer` | `https://us-south.ml.cloud.ibm.com/ml/v1` |
| `openrouter` | OpenRouter (aggregator) | OpenAI | `Authorization: Bearer` | `https://openrouter.ai/api/v1` |
| `cloudflare` | Cloudflare Workers AI | OpenAI | `Authorization: Bearer` | `https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1` |
| `vertex` | Google Vertex AI | OpenAI | `Authorization: Bearer`[^vertex-oauth] | `https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/endpoints/openapi` |
| `runpod` | RunPod Serverless | OpenAI | `Authorization: Bearer` | `https://api.runpod.ai/v2/{endpoint_id}/openai/v1` |
| `crusoe` | Crusoe Cloud Inference | OpenAI | `Authorization: Bearer` | `https://managed-inference-api-proxy.crusoecloud.com/v1` |
| `featherless` | Featherless AI | OpenAI | `Authorization: Bearer` | `https://api.featherless.ai/v1` |
| `reka` | Reka AI | OpenAI | `Authorization: Bearer` | `https://api.reka.ai/v1` |
| `voyage` | Voyage AI (embeddings only)[^embed-only] | OpenAI | `Authorization: Bearer` | `https://api.voyageai.com/v1` |
| `jina` | Jina AI (embeddings only)[^embed-only] | OpenAI | `Authorization: Bearer` | `https://api.jina.ai/v1` |

The `cloudflare`, `vertex`, and `runpod` defaults contain path template parameters (`{account_id}`, `{location}`, `{project_id}`, `{endpoint_id}`). Fill them in by overriding `base_url` per-origin, typically with environment-or-config interpolation (for example `base_url: https://api.runpod.ai/v2/${RUNPOD_ENDPOINT_ID}/openai/v1`). Paths left with literal placeholders will reach the upstream as-is and 404.

[^vertex-oauth]: Vertex AI requires a short-lived OAuth2 access token rather than a static API key. Generate one with `gcloud auth print-access-token` (or your service account flow) and rotate it before expiry. SBproxy forwards the configured `api_key` verbatim as the bearer token.

[^embed-only]: Voyage and Jina expose embeddings (and rerank) endpoints only. Their catalog entries set `supports_chat: false` so chat-completion configs against these providers will fail closed at validation time once the runtime check is wired.

`format` is the wire protocol the upstream expects. OpenAI-compatible upstreams pass through unchanged. Anthropic is translated bidirectionally for non-streaming requests: clients send OpenAI-shaped chat completions, sbproxy rewrites the body and path on the way out and rewrites the response back to OpenAI shape. Streaming SSE event translation for Anthropic is not yet implemented; `stream: true` requests pass through in Anthropic's native event shape. Google Gemini, AWS Bedrock, Oracle OCI, Watsonx, and SageMaker are not translated yet, so the client must send the provider's native body shape or route through OpenRouter.

Override `base_url` to use a region other than us-south for watsonx, or to point Bedrock and SageMaker at a non-default region.

[^sigv4]: Bedrock and SageMaker requests must be signed with SigV4 before reaching SBproxy. The gateway forwards the signed `Authorization` header verbatim.

[^ollama]: Ollama allows blank API keys; SBproxy forwards an empty Bearer token if `api_key` is unset.

## Configuring a provider

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          default_model: claude-3-5-sonnet-latest
          models:
            - claude-3-5-sonnet-latest
            - claude-3-5-haiku-latest
```

Useful per-provider knobs:

```yaml
providers:
  - name: openai
    api_key: ${OPENAI_API_KEY}
    base_url: https://api.openai.com/v1     # Override default
    models: ["gpt-4o", "gpt-4o-mini"]       # Whitelist
    default_model: gpt-4o-mini              # Used when client omits `model`
    model_map:                              # Rename models on the way out
      fast: gpt-4o-mini
      smart: gpt-4o
    weight: 3                               # For weighted routing
    priority: 1                             # For fallback chain (lower wins)
    enabled: true
    max_retries: 3
    timeout_ms: 30000
```

## Reaching providers not on this list

Route through `openrouter`. One API key, 200+ models including Claude, Llama, GPT, Gemini, Mistral, DeepSeek, and Command:

```yaml
providers:
  - name: openrouter
    api_key: ${OPENROUTER_API_KEY}
    default_model: anthropic/claude-3.5-sonnet
    models:
      - anthropic/claude-3.5-sonnet
      - meta-llama/llama-3.1-70b-instruct
      - mistralai/mistral-large
```

Local and self-hosted OpenAI-compatible runtimes are first-class providers in the registry: `ollama`, `vllm`, `tgi`, `lmstudio`, and `llamacpp`. Each has a sensible default `base_url` matching the runtime's convention. Override `base_url` if you bind elsewhere. See [example 86](../examples/86-local-models/sb.yml) for a hybrid local-plus-cloud config that falls back from a local Ollama to OpenAI when local is offline.

## See also

- [AI gateway](ai-gateway.md) - routing strategies, guardrails, budgets, streaming.
- [Configuration reference](configuration.md) - every `sb.yml` field.
- [Examples](../examples/) - runnable AI configs against OpenRouter and Claude.
