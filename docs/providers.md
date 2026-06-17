# Supported providers
*Last modified: 2026-06-17*

SBproxy ships native adapters for 66 LLM providers behind one OpenAI-compatible API. You bring your own key per provider, and the `model` field passes straight through to the upstream, so the gateway reaches 200+ models (and whatever a provider ships next) without enumerating them. Most adapters speak the OpenAI wire format and pass through unchanged. Anthropic, Bedrock, and Gemini use in-tree translators for OpenAI-shaped chat or embedding clients; SageMaker, Oracle, Watsonx, and other `Custom` formats pass through in their native shape.

The catalog is plain YAML and you can extend it yourself: see [Extending the provider catalog](#extending-the-provider-catalog).

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
| `anyscale` | Anyscale Endpoints | OpenAI | `Authorization: Bearer` | `https://api.endpoints.anyscale.com/v1` |
| `cerebras` | Cerebras Inference | OpenAI | `Authorization: Bearer` | `https://api.cerebras.ai/v1` |
| `nvidia` | NVIDIA NIM | OpenAI | `Authorization: Bearer` | `https://integrate.api.nvidia.com/v1` |
| `hyperbolic` | Hyperbolic | OpenAI | `Authorization: Bearer` | `https://api.hyperbolic.xyz/v1` |
| `lepton` | Lepton AI | OpenAI | `Authorization: Bearer` | `https://api.lepton.run/v1` |
| `deepinfra` | DeepInfra | OpenAI | `Authorization: Bearer` | `https://api.deepinfra.com/v1/openai` |
| `novita` | Novita AI | OpenAI | `Authorization: Bearer` | `https://api.novita.ai/v3/openai` |
| `sambanova` | SambaNova Cloud | OpenAI | `Authorization: Bearer` | `https://api.sambanova.ai/v1` |
| `siliconflow` | SiliconFlow | OpenAI | `Authorization: Bearer` | `https://api.siliconflow.cn/v1` |
| `moonshot` | Moonshot AI (Kimi) | OpenAI | `Authorization: Bearer` | `https://api.moonshot.cn/v1` |
| `dashscope` | Alibaba DashScope (Qwen) | OpenAI | `Authorization: Bearer` | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| `zhipu` | Zhipu AI (GLM) | OpenAI | `Authorization: Bearer` | `https://open.bigmodel.cn/api/paas/v4` |
| `voyage` | Voyage AI (embeddings only)[^embed-only] | OpenAI | `Authorization: Bearer` | `https://api.voyageai.com/v1` |
| `jina` | Jina AI (embeddings only)[^embed-only] | OpenAI | `Authorization: Bearer` | `https://api.jina.ai/v1` |
| `huggingface` | Hugging Face Inference Providers | OpenAI | `Authorization: Bearer` | `https://router.huggingface.co/v1` |
| `github_models` | GitHub Models | OpenAI | `Authorization: Bearer` | `https://models.github.ai/inference` |
| `vercel` | Vercel AI Gateway | OpenAI | `Authorization: Bearer` | `https://ai-gateway.vercel.sh/v1` |
| `nebius` | Nebius AI Studio | OpenAI | `Authorization: Bearer` | `https://api.studio.nebius.ai/v1` |
| `baseten` | Baseten Model APIs | OpenAI | `Authorization: Bearer` | `https://inference.baseten.co/v1` |
| `lambda` | Lambda Inference API | OpenAI | `Authorization: Bearer` | `https://api.lambda.ai/v1` |
| `friendliai` | FriendliAI Serverless | OpenAI | `Authorization: Bearer` | `https://api.friendli.ai/serverless/v1` |
| `scaleway` | Scaleway Generative APIs | OpenAI | `Authorization: Bearer` | `https://api.scaleway.ai/v1` |
| `nscale` | Nscale Serverless Inference | OpenAI | `Authorization: Bearer` | `https://inference.api.nscale.com/v1` |
| `digitalocean` | DigitalOcean Gradient Inference | OpenAI | `Authorization: Bearer` | `https://inference.do-ai.run/v1` |
| `ovhcloud` | OVHcloud AI Endpoints | OpenAI | `Authorization: Bearer` | `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1` |
| `inferencenet` | Inference.net | OpenAI | `Authorization: Bearer` | `https://api.inference.net/v1` |
| `kluster` | kluster.ai | OpenAI | `Authorization: Bearer` | `https://api.kluster.ai/v1` |
| `openpipe` | OpenPipe | OpenAI | `Authorization: Bearer` | `https://api.openpipe.ai/api/v1` |
| `writer` | Writer (Palmyra) | OpenAI | `Authorization: Bearer` | `https://api.writer.com/v1` |
| `upstage` | Upstage (Solar) | OpenAI | `Authorization: Bearer` | `https://api.upstage.ai/v1/solar` |
| `alephalpha` | Aleph Alpha | OpenAI | `Authorization: Bearer` | `https://api.aleph-alpha.com/v1` |
| `minimax` | MiniMax | OpenAI | `Authorization: Bearer` | `https://api.minimax.io/v1` |
| `volcengine` | Volcengine Ark (Doubao) | OpenAI | `Authorization: Bearer` | `https://ark.cn-beijing.volces.com/api/v3` |
| `hunyuan` | Tencent Hunyuan | OpenAI | `Authorization: Bearer` | `https://api.hunyuan.cloud.tencent.com/v1` |
| `qianfan` | Baidu Qianfan (ERNIE) | OpenAI | `Authorization: Bearer` | `https://qianfan.baidubce.com/v2` |
| `stepfun` | StepFun | OpenAI | `Authorization: Bearer` | `https://api.stepfun.com/v1` |
| `mixedbread` | Mixedbread (embeddings only)[^embed-only] | OpenAI | `Authorization: Bearer` | `https://api.mixedbread.com/v1` |

The `cloudflare`, `vertex`, and `runpod` defaults contain path template parameters (`{account_id}`, `{location}`, `{project_id}`, `{endpoint_id}`). Fill them in by overriding `base_url` per-origin, typically with environment-or-config interpolation (for example `base_url: https://api.runpod.ai/v2/${RUNPOD_ENDPOINT_ID}/openai/v1`). Paths left with literal placeholders will reach the upstream as-is and 404.

[^vertex-oauth]: Vertex AI requires a short-lived OAuth2 access token rather than a static API key. Generate one with `gcloud auth print-access-token` (or your service account flow) and rotate it before expiry. SBproxy forwards the configured `api_key` verbatim as the bearer token.

[^embed-only]: Voyage and Jina expose embeddings (and rerank) endpoints only. Their catalog entries set `supports_chat: false` so chat-completion configs against these providers will fail closed at validation time once the runtime check is wired.

`format` is the wire protocol the upstream expects. OpenAI-compatible upstreams pass through unchanged. Anthropic, Google Gemini, and AWS Bedrock are translated bidirectionally for chat-completions requests: clients send OpenAI-shaped bodies, SBproxy rewrites the body and path on the way out, and SBproxy rewrites the response back to OpenAI shape. For streaming, the relay parses native Anthropic, Gemini, and Bedrock stream frames into the internal hub stream and re-emits OpenAI Chat, Anthropic Messages, or OpenAI Responses shape based on the inbound route. Gemini embeddings at `/v1/embeddings` translate to and from Gemini embedding calls. Oracle OCI, Watsonx, SageMaker, and other `Custom` formats remain native pass-through, so clients must send the provider's native body shape or route through OpenRouter/custom translation.

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

Three options, roughly in order of preference:

1. **Point any provider at a custom `base_url`.** Most upstreams speak the OpenAI wire format, so a `provider_type: openai` entry with your own `base_url` reaches anything OpenAI-compatible: a self-hosted vLLM or SGLang pool, an internal gateway, or a proprietary endpoint.
2. **Add the provider to the catalog yourself.** It is plain YAML and ships uncompiled. See [Extending the provider catalog](#extending-the-provider-catalog).
3. **Use `openrouter` as a single-key aggregator** when you want many vendors without holding a direct account with each. It is one of the native providers, no different from the rest:

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

Local and self-hosted OpenAI-compatible runtimes are first-class providers in the registry: `ollama`, `vllm`, `tgi`, `lmstudio`, and `llamacpp`. Each has a sensible default `base_url` matching the runtime's convention. Override `base_url` if you bind elsewhere. See [example 86](../examples/local-models/sb.yml) for a hybrid local-plus-cloud config that falls back from a local Ollama to OpenAI when local is offline.

### base_url validation and local servers

An overridden `base_url` is validated at config load to keep it from becoming an SSRF vector. Non-`http(s)` schemes (`file://`, ...) are always rejected, and by default a URL that targets a loopback, link-local, or private (RFC 1918) address is rejected too, so a stray `http://169.254.169.254/` or `http://127.0.0.1/` fails fast instead of being dispatched at request time.

A local model server is the legitimate exception: it lives on `127.0.0.1` or a LAN address. Set `allow_private_base_url: true` on that provider to permit its private `base_url`. The scheme check still applies. Providers that use a registry default (no `base_url` override) are unaffected.

```yaml
providers:
  - name: local-ollama
    provider_type: ollama
    base_url: http://127.0.0.1:11434/v1
    allow_private_base_url: true
```

## Extending the provider catalog

The provider list above is not hard-coded. It is a plain YAML registry that ships embedded in the binary; the source of truth is `crates/sbproxy-ai/data/ai_providers.yml`. Each entry maps a provider `name` to its base URL, auth header, and wire format. Models are never listed here: the `model` field on a request passes straight through to the upstream, so a provider's whole model lineup is reachable the moment the provider is in the catalog, and new models work the day the upstream ships them.

There are three ways to reach a provider that is not already listed, from least to most permanent:

### 1. Override `base_url` on a single provider (no catalog change)

For a one-off OpenAI-compatible endpoint, reuse an existing OpenAI-format `provider_type` and point it wherever you like. Nothing to rebuild.

```yaml
providers:
  - name: my-endpoint
    provider_type: openai          # reuse the OpenAI wire format
    base_url: https://llm.internal.example.com/v1
    api_key: ${INTERNAL_LLM_KEY}
    default_model: my-finetune
```

### 2. Replace the catalog at runtime with `proxy.ai_providers_file`

Point the gateway at your own catalog on disk. The file fully replaces the embedded set, so include every provider you intend to use. This needs no rebuild and survives upgrades.

```yaml
proxy:
  ai_providers_file: /etc/sbproxy/ai_providers.yml
```

Each entry uses these fields:

```yaml
providers:
  - name: my_provider              # canonical id used in sb.yml (required)
    display_name: My Provider      # human label (required)
    aliases: [mine, myprov]        # optional alternative lookup names
    default_base_url: https://api.my-provider.com/v1   # required
    auth_header: Authorization     # header carrying the key (default Authorization)
    auth_prefix: "Bearer "         # prefix prepended to the key ("" for raw keys)
    format: openai                 # wire format: openai | anthropic | google | bedrock | custom
    supports_streaming: true
    supports_embeddings: false
    supports_chat: true            # set false for embeddings/rerank-only providers
```

A malformed override file is rejected and the gateway falls back to the embedded catalog rather than booting with no providers.

### 3. Add it to the in-tree registry

To make a provider part of the default build, append an entry to `crates/sbproxy-ai/data/ai_providers.yml` using the same schema, then regenerate the embedded copy:

```bash
gzip -9 -n -c crates/sbproxy-ai/data/ai_providers.yml \
  > crates/sbproxy-ai/data/ai_providers.yml.gz
```

The registry picks it up on the next build. `format: openai` covers any OpenAI-compatible upstream; reach for `anthropic`, `google`, `bedrock`, or `custom` only when the upstream speaks that native shape.

## See also

- [AI gateway](ai-gateway.md) - routing strategies, guardrails, budgets, streaming.
- [Configuration reference](configuration.md) - every `sb.yml` field.
- [Examples](../examples/) - runnable AI configs against OpenRouter and Claude.
