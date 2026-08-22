# Supported providers
*Last modified: 2026-08-21*

SBproxy ships native adapters for 70 LLM providers behind one OpenAI-compatible API. The 70 breaks down as: 63 entries that speak the OpenAI wire format and pass through unchanged, 3 with in-tree request and response translators (Anthropic, Gemini, Bedrock), and 4 `Custom`-format entries (SageMaker, Oracle, Watsonx, Writer) that pass through in their native shape with no translation. You bring your own key per provider, and the `model` field passes straight through to the upstream, so the gateway reaches 200+ models (and whatever a provider ships next) without enumerating them.

Read the table below for what it is: a catalog, not a test report. It is hand-maintained against
`crates/sbproxy-ai/data/ai_providers.yml`, and it records what each entry says about a provider,
not the result of calling one. Base URLs and auth headers change on the provider's schedule and
every row would need a live account to exercise. For a request that actually crosses the gateway,
[ai-gateway.md](ai-gateway.md) is the reference and
[`examples/ai-gateway-quickstart/`](../examples/ai-gateway-quickstart/) is the shortest runnable
config. [vercel-ai-sdk.md](vercel-ai-sdk.md), [langchain.md](langchain.md),
[pydantic-ai.md](pydantic-ai.md), and [mastra.md](mastra.md) each ship a runnable example that
needs no provider account.

The catalog is plain YAML and you can extend it yourself: see [Extending the provider catalog](#extending-the-provider-catalog).

## Native providers

Each provider has a default base URL and auth format. Override `base_url` if you self-host or use a regional endpoint.

| Name | Provider | Format | Auth | Default Base URL |
|------|----------|--------|------|------------------|
| `openai` | OpenAI | OpenAI | `Authorization: Bearer` | `https://api.openai.com/v1` |
| `anthropic` | Anthropic Claude | Anthropic Messages | `x-api-key` | `https://api.anthropic.com/v1` |
| `gemini` | Google Gemini | Google | `x-goog-api-key` | `https://generativelanguage.googleapis.com/v1beta` |
| `azure` | Azure OpenAI | OpenAI | `api-key` | `https://{resource}.openai.azure.com/openai/v1` |
| `bedrock` | AWS Bedrock | Bedrock | AWS SigV4[^sigv4] | `https://bedrock-runtime.{region}.amazonaws.com` |
| `meta` | Meta Model API | OpenAI | `Authorization: Bearer` | `https://api.meta.ai/v1` |
| `cohere` | Cohere | OpenAI | `Authorization: Bearer` | `https://api.cohere.ai/compatibility/v1` |
| `mistral` | Mistral AI | OpenAI | `Authorization: Bearer` | `https://api.mistral.ai/v1` |
| `groq` | Groq | OpenAI | `Authorization: Bearer` | `https://api.groq.com/openai/v1` |
| `deepseek` | DeepSeek | OpenAI | `Authorization: Bearer` | `https://api.deepseek.com/v1` |
| `ollama` | Ollama (local) | OpenAI | `Authorization: Bearer` (optional)[^ollama] | `http://localhost:11434/v1` |
| `vllm` | vLLM (self-hosted) | OpenAI | `Authorization: Bearer` | `http://localhost:8000/v1` |
| `sglang` | SGLang (self-hosted) | OpenAI | `Authorization: Bearer` (optional) | `http://localhost:30000/v1` |
| `localai` | LocalAI (self-hosted) | OpenAI | `Authorization: Bearer` (optional) | `http://localhost:8080/v1` |
| `tgi` | Hugging Face TGI (self-hosted)[^tgi] | OpenAI | `Authorization: Bearer` | `http://localhost:8080/v1` |
| `lmstudio` | LM Studio (local) | OpenAI | `Authorization: Bearer` | `http://localhost:1234/v1` |
| `llamacpp` | `llama.cpp` server (local) | OpenAI | `Authorization: Bearer` | `http://localhost:8080/v1` |
| `together` | Together AI | OpenAI | `Authorization: Bearer` | `https://api.together.ai/v1` |
| `fireworks` | Fireworks AI | OpenAI | `Authorization: Bearer` | `https://api.fireworks.ai/inference/v1` |
| `perplexity` | Perplexity | OpenAI | `Authorization: Bearer` | `https://api.perplexity.ai/router/v1` |
| `xai` | xAI (Grok) | OpenAI | `Authorization: Bearer` | `https://api.x.ai/v1` |
| `sagemaker` | Amazon SageMaker | Custom | AWS SigV4[^sigv4] | `https://runtime.sagemaker.{region}.amazonaws.com` |
| `databricks` | Databricks | OpenAI | `Authorization: Bearer` | `https://{workspace}.cloud.databricks.com/serving-endpoints` |
| `oracle` | Oracle OCI Generative AI | Custom | Authorization (OCI request signature, signed externally)[^oci] | `https://inference.generativeai.{region}.oci.oraclecloud.com` |
| `watsonx` | IBM watsonx | Custom | `Authorization: Bearer` | `https://us-south.ml.cloud.ibm.com/ml/v1` |
| `openrouter` | OpenRouter (aggregator) | OpenAI | `Authorization: Bearer` | `https://openrouter.ai/api/v1` |
| `cloudflare` | Cloudflare Workers AI | OpenAI | `Authorization: Bearer` | `https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1` |
| `vertex` | Google Vertex AI | OpenAI | `Authorization: Bearer`[^vertex-oauth] | `https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/endpoints/openapi` |
| `runpod` | RunPod Serverless | OpenAI | `Authorization: Bearer` | `https://api.runpod.ai/v2/{endpoint_id}/openai/v1` |
| `crusoe` | Crusoe Cloud Inference | OpenAI | `Authorization: Bearer` | `https://api.inference.crusoecloud.com/v1` |
| `featherless` | Featherless AI | OpenAI | `Authorization: Bearer` | `https://api.featherless.ai/v1` |
| `reka` | Reka AI | OpenAI | `X-Api-Key` | `https://api.reka.ai/v1` |
| `cerebras` | Cerebras Inference | OpenAI | `Authorization: Bearer` | `https://api.cerebras.ai/v1` |
| `nvidia` | NVIDIA NIM | OpenAI | `Authorization: Bearer` | `https://integrate.api.nvidia.com/v1` |
| `hyperbolic` | Hyperbolic | OpenAI | `Authorization: Bearer` | `https://api.hyperbolic.xyz/v1` |
| `deepinfra` | DeepInfra | OpenAI | `Authorization: Bearer` | `https://api.deepinfra.com/v1/openai` |
| `novita` | Novita AI | OpenAI | `Authorization: Bearer` | `https://api.novita.ai/openai` |
| `sambanova` | SambaNova Cloud | OpenAI | `Authorization: Bearer` | `https://api.sambanova.ai/v1` |
| `siliconflow` | SiliconFlow | OpenAI | `Authorization: Bearer` | `https://api.siliconflow.cn/v1` |
| `moonshot` | Moonshot AI (Kimi)[^regional] | OpenAI | `Authorization: Bearer` | `https://api.moonshot.ai/v1` |
| `dashscope` | Alibaba DashScope (Qwen)[^regional] | OpenAI | `Authorization: Bearer` | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` |
| `zhipu` | Z.ai / Zhipu AI (GLM)[^regional] | OpenAI | `Authorization: Bearer` | `https://api.z.ai/api/paas/v4` |
| `voyage` | Voyage AI (embeddings only)[^embed-only] | OpenAI | `Authorization: Bearer` | `https://api.voyageai.com/v1` |
| `jina` | Jina AI (embeddings only)[^embed-only] | OpenAI | `Authorization: Bearer` | `https://api.jina.ai/v1` |
| `huggingface` | Hugging Face Inference Providers | OpenAI | `Authorization: Bearer` | `https://router.huggingface.co/v1` |
| `vercel` | Vercel AI Gateway | OpenAI | `Authorization: Bearer` | `https://ai-gateway.vercel.sh/v1` |
| `nebius` | Nebius Token Factory | OpenAI | `Authorization: Bearer` | `https://api.tokenfactory.nebius.com/v1` |
| `baseten` | Baseten Model APIs | OpenAI | `Authorization: Bearer` | `https://inference.baseten.co/v1` |
| `friendliai` | FriendliAI Serverless | OpenAI | `Authorization: Bearer` | `https://api.friendli.ai/serverless/v1` |
| `scaleway` | Scaleway Generative APIs | OpenAI | `Authorization: Bearer` | `https://api.scaleway.ai/v1` |
| `nscale` | Nscale Serverless Inference | OpenAI | `Authorization: Bearer` | `https://inference.api.nscale.com/v1` |
| `digitalocean` | DigitalOcean Inference | OpenAI | `Authorization: Bearer` | `https://inference.do-ai.run/v1` |
| `ovhcloud` | OVHcloud AI Endpoints | OpenAI | `Authorization: Bearer` | `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1` |
| `inferencenet` | Inference.net | OpenAI | `Authorization: Bearer` | `https://api.inference.net/v1` |
| `wandb` | W&B Inference (CoreWeave) | OpenAI | `Authorization: Bearer` | `https://api.inference.wandb.ai/v1` |
| `gmi` | GMI Cloud | OpenAI | `Authorization: Bearer` | `https://api.gmi-serving.com/v1` |
| `writer` | Writer (Palmyra) | Custom[^writer] | `Authorization: Bearer` | `https://api.writer.com/v1` |
| `upstage` | Upstage (Solar) | OpenAI | `Authorization: Bearer` | `https://api.upstage.ai/v1` |
| `minimax` | MiniMax[^regional] | OpenAI | `Authorization: Bearer` | `https://api.minimax.io/v1` |
| `volcengine` | Volcengine Ark (Doubao)[^regional] | OpenAI | `Authorization: Bearer` | `https://ark.cn-beijing.volces.com/api/v3` |
| `hunyuan` | Tencent Hunyuan | OpenAI | `Authorization: Bearer` | `https://api.hunyuan.cloud.tencent.com/v1` |
| `qianfan` | Baidu Qianfan (ERNIE) | OpenAI | `Authorization: Bearer` | `https://qianfan.baidubce.com/v2` |
| `stepfun` | StepFun | OpenAI | `Authorization: Bearer` | `https://api.stepfun.com/v1` |
| `mixedbread` | Mixedbread | OpenAI | `Authorization: Bearer` | `https://api.mixedbread.com/v1` |
| `azure_foundry` | Azure AI Foundry Models | OpenAI | `api-key` | `https://{resource}.services.ai.azure.com/openai/v1` |
| `snowflake` | Snowflake Cortex | OpenAI | `Authorization: Bearer` | `https://{account}.snowflakecomputing.com/api/v2/cortex/v1` |
| `ai21` | AI21 Labs (Jamba) | OpenAI | `Authorization: Bearer` | `https://api.ai21.com/studio/v1` |
| `clarifai` | Clarifai | OpenAI | `Authorization: Key` | `https://api.clarifai.com/v2/ext/openai/v1` |
| `inception` | Inception Labs (Mercury) | OpenAI | `Authorization: Bearer` | `https://api.inceptionlabs.ai/v1` |
| `sarvam` | Sarvam AI | OpenAI | `Authorization: Bearer` | `https://api.sarvam.ai/v1` |

The `cloudflare`, `vertex`, `runpod`, `azure_foundry`, and `snowflake` defaults contain path template parameters (`{account_id}`, `{location}`, `{project_id}`, `{endpoint_id}`, `{resource}`, `{account}`). Fill them in by overriding `base_url` per-origin, typically with environment-or-config interpolation (for example `base_url: https://api.runpod.ai/v2/${RUNPOD_ENDPOINT_ID}/openai/v1`). Paths left with literal placeholders will reach the upstream as-is and 404.

[^vertex-oauth]: Vertex AI requires a short-lived OAuth2 access token rather than a static API key. Generate one with `gcloud auth print-access-token` (or your service account flow) and rotate it before expiry. SBproxy forwards the configured `api_key` verbatim as the bearer token.

[^embed-only]: Voyage and Jina expose embeddings (and rerank) endpoints only. Their catalog entries record that as `supports_chat: false`, which keeps `chat_completions` off their model listings: `GET /v1/models` shows `["embeddings"]` and nothing else. It is not a gate, though. A chat-completions request against one of them is still forwarded and 404s at the upstream, so keep chat traffic away by leaving chat models out of their `models` list, or with `allowed_models`. Mixedbread used to sit in this group and no longer does: its current API reference documents OpenAI-shaped `/v1/chat/completions`, so refusing chat there had become a false refusal.

[^tgi]: Hugging Face archived the TGI repository on 2026-03-21 and put it in maintenance mode, pointing new deployments at vLLM, SGLang, or `llama.cpp`. The entry stays because an existing TGI server keeps serving on this base; the port matches the published Docker quickstart's host mapping rather than the binary's own default.

[^oci]: Oracle Cloud authenticates with a signed `Authorization` header (`Signature version="1",keyId=...`), not a bearer token. As with SigV4, SBproxy does not compute the signature: the request must arrive already signed and the header is forwarded verbatim, so the catalog entry prepends no prefix.

[^writer]: Writer's published OpenAPI puts chat at `/v1/chat` and contains no `chat/completions` path at all, so an OpenAI-shaped request would 404. The entry is `Custom` for that reason: clients must send Writer's own path and body shape.

[^regional]: These vendors run separate domestic and international platforms with distinct accounts and billing. The catalog default is the international endpoint, because that is the one an operator outside the vendor's home market can sign up for. The domestic hosts (`api.moonshot.cn`, `dashscope.aliyuncs.com`, `open.bigmodel.cn`, `api.minimaxi.com`, and BytePlus ModelArk for Volcengine) are a per-origin `base_url` override away.

`format` is the wire protocol the upstream expects. OpenAI-compatible upstreams pass through unchanged. Anthropic, Google Gemini, and AWS Bedrock are translated bidirectionally for chat-completions requests: clients send OpenAI-shaped bodies, SBproxy rewrites the body and path on the way out, and SBproxy rewrites the response back to OpenAI shape. For streaming, the relay parses native Anthropic, Gemini, and Bedrock stream frames into the internal hub stream and re-emits OpenAI Chat, Anthropic Messages, or OpenAI Responses shape based on the inbound route. Gemini embeddings at `/v1/embeddings` translate to and from Gemini embedding calls. Oracle OCI, Watsonx, SageMaker, and other `Custom` formats remain native pass-through, so clients must send the provider's native body shape or route through OpenRouter/custom translation.

Override `base_url` to use a region other than us-south for watsonx. Bedrock and SageMaker take their region from `aws_sigv4.region`, which fills the `{region}` placeholder in the default URL; set `base_url` as well only when the endpoint itself moves, as it does for a VPC endpoint.

[^sigv4]: Bedrock and SageMaker do not accept a bearer token. Add `aws_sigv4:` to the provider entry and SBproxy computes the signature for each request. An entry without that block still forwards `api_key` verbatim as the `Authorization` header, which is what you want when a signing sidecar already sits in front of the endpoint. See [AWS SigV4 signing for Bedrock and SageMaker](#aws-sigv4-signing-for-bedrock-and-sagemaker).

[^ollama]: Ollama allows blank API keys; SBproxy forwards an empty Bearer token if `api_key` is unset.

## Declared data-handling posture

Every catalog entry also declares a `data_posture` block: `retains_data` (does the vendor's API retain prompt data on a stock account, for example an abuse-monitoring window) and `zdr_available` (does the vendor sell a zero-data-retention arrangement at all). The same honesty rule as the rest of this page applies: these record what each vendor's published data-processing terms say, not the result of auditing an account, and vendors change terms on their own schedule. The `data_posture:` block on an `ai_proxy` action turns these declarations into a hard routing eligibility filter; see [ai-gateway.md](ai-gateway.md#provider-data-posture).

`zdr_available` is informational and is deliberately not an input to that filter. It tells you an agreement exists to go and sign, not that your account holds one, and five of the entries below offer one while retaining by default. Declaring what your own deployment holds is a line in your config (`data_posture.zdr: true` on the provider entry).

The entries with a non-pessimistic declaration:

| Name | `retains_data` | `zdr_available` | Basis |
|------|----------------|-----------------|-------|
| `openai` | `true` | `true` | Abuse-monitoring retention up to 30 days; ZDR offered for approved use cases (OpenAI API data-usage policy). |
| `anthropic` | `true` | `true` | Limited trust-and-safety retention; ZDR agreements offered commercially (Anthropic commercial terms). |
| `azure` | `true` | `true` | Abuse-monitoring storage up to 30 days; approved subscriptions can disable it (Azure OpenAI data-privacy note). |
| `bedrock` | `true` | `true` | Zero data retention is the platform default, but the abuse-detection page carves out named models: classifier-flagged traffic to the OpenAI GPT-5.x family is retained up to 30 days with no opt-in, and the model name passes straight through from the caller. Eligible customers may request full ZDR through their AWS account team (Bedrock abuse-detection docs). |
| `vertex` | `true` | `true` | No training on customer data; caching and abuse logging can be disabled for zero-retention configurations (Vertex AI data-governance docs). |
| `perplexity` | `false` | `true` | Published zero-data-retention policy for the completions API: data sent through it is not retained and is not used for training (Perplexity privacy and security docs). |
| `cerebras` | `false` | `true` | States it does not retain inputs and outputs associated with its inference services (Cerebras privacy policy). |
| `ollama`, `vllm`, `sglang`, `localai`, `tgi`, `lmstudio`, `llamacpp` | `false` | `true` | Local engines; the default base URL keeps prompts on the operator's own host. |

The five entries with `retains_data: true, zdr_available: true` retain on a stock account, so they satisfy `require_zdr` only once you declare the agreement you hold. The nine with `retains_data: false` store nothing to begin with and satisfy it as they stand. Bedrock moved from the second group to the first in this pass, which is a fail-closed change: an origin that required ZDR and configured only Bedrock now gets refused at config load instead of routing to a provider whose no-retention default no longer covers every model it serves. Every other entry carries the pessimistic default, `retains_data: true, zdr_available: false`, spelled out in the YAML: with no published commitment recorded, a posture-constrained origin fails closed rather than optimistically routing there. If your own agreement with a vendor differs (a signed ZDR addendum, say), declare it on your provider entry with `data_posture.zdr: true` / `data_posture.retains_data: false`, or ship a corrected catalog via `proxy.ai_providers_file`. A locally served (`serve:`) or `managed_model` provider is treated as zero-data-retention by construction.

## Configuring a provider

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          default_model: claude-sonnet-4-5
          models:
            - claude-sonnet-4-5
            - claude-haiku-4-5
```

`default_model` names the model shown in this provider's `/v1/models` listing and the model a request routes to when it omits `model`, on hosted and locally served providers alike. On the hosted path the fallback is origin-wide rather than per-provider, because provider selection has not happened yet when the model is read: it applies only when every enabled provider that names a default names the same one, and only on the chat-shaped surfaces (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`). See [ai-gateway.md](ai-gateway.md#defaulting-the-model) for the rule and its carve-outs in full.

Useful per-provider knobs:

```yaml
providers:
  - name: openai
    api_key: ${OPENAI_API_KEY}
    base_url: https://api.openai.com/v1     # Override default
    models: ["gpt-4o", "gpt-4o-mini"]       # Whitelist
    default_model: gpt-4o-mini              # Used when a request omits `model`, and shown in /v1/models metadata
    model_map:                              # Rename models on the way out
      fast: gpt-4o-mini
      smart: gpt-4o
    weight: 3                               # For weighted routing
    priority: 1                             # For fallback chain (lower wins)
    enabled: true
    max_retries: 3
    timeout_ms: 30000
```

### AWS SigV4 signing for Bedrock and SageMaker

Bedrock and SageMaker reject a bearer token. Each request needs an `Authorization: AWS4-HMAC-SHA256 ...` header computed over a canonical form of that exact request, body hash included. Add `aws_sigv4:` and SBproxy computes it per request:

```yaml
providers:
  - name: bedrock
    aws_sigv4:
      region: us-east-1
    default_model: anthropic.claude-sonnet-4-5-20250929-v1:0
```

That is the whole minimum. A signed entry has no `api_key`, and setting both is refused at config load, because the signature overwrites `Authorization` and the static credential would be discarded without a word.

`region` is required, and it sets the credential scope. Where the request goes is `base_url`'s business: overriding it moves the endpoint and leaves the signing region alone, which is how the AWS SDKs behave and what makes a PrivateLink endpoint work:

```yaml
providers:
  - name: bedrock
    base_url: https://vpce-0a1b2c3d.bedrock-runtime.us-east-1.vpce.amazonaws.com
    aws_sigv4:
      region: us-east-1
```

With `base_url` unset, `region` fills the `{region}` placeholder in the catalog default, so the dial goes to `https://bedrock-runtime.us-east-1.amazonaws.com`.

`service` defaults to `bedrock` or `sagemaker` from the provider type. Set it only when a provider entry fronts some other AWS service.

#### Credentials

`credentials.source` selects where the key comes from. Omit `credentials:` entirely and you get `default_chain`.

| Source | Reads | Use it for |
|---|---|---|
| `default_chain` | `AWS_ACCESS_KEY_ID` and the other standard environment variables, the shared config and credentials files, the EKS web identity token, the ECS task role, the EC2 instance profile | Anything running inside AWS. The chain renews short-lived credentials itself. |
| `static` | `access_key_id`, `secret_access_key`, optional `session_token` | An IAM user key held outside AWS. |
| `assume_role` | `role_arn`, optional `external_id`, `session_name`, `session_duration_secs` | Cross-account access, and any deployment that wants short-lived credentials SBproxy renews. The base identity comes from the default chain. |

`secret_access_key`, `session_token`, and `external_id` are secret-resolving fields: `${VAR}`, `vault://`, `awssm://`, `secret://`, and `file:` are all dereferenced at config load, and a reference that cannot be resolved is a hard error rather than a value that reaches AWS verbatim. Once resolved they are held in a type whose `Debug` prints `[REDACTED]` and whose bytes are zeroed on drop, and no SBproxy code path formats them into a log line, an error string, or a metric label.

Prefer a reference over an inlined literal, for `external_id` especially. The admin config endpoints run a redaction pass over the raw config text before returning it, and that pass keys off a fixed list of credential field names. `secret_access_key` and `session_token` are covered; `external_id` is not, because the same field name carries a non-secret payment identifier elsewhere in SBproxy and masking it there would hide reconciliation IDs. A reference sidesteps the question: the file holds `vault://...`, which the redactor deliberately preserves and which is not a secret.

`profile` names a profile in the shared AWS config files and applies to `default_chain` and to the identity `assume_role` starts from.

```yaml
providers:
  - name: bedrock
    aws_sigv4:
      region: us-east-1
      credentials:
        source: assume_role
        role_arn: arn:aws:iam::123456789012:role/sbproxy-bedrock
        external_id: ${BEDROCK_EXTERNAL_ID}
        session_name: sbproxy-prod
```

#### Expiry and clock skew

An `assume_role` session is renewed 900 seconds before it expires. If STS is unreachable at that moment, the request still goes out on the cached credential and the refresh is retried on the next one, with a WARN naming the failure. Only inside the last 600 seconds does a failed refresh fail the request. Both windows are botocore's, from `RefreshableCredentials`. `refresh_margin_secs` moves the first one and has to stay at or above 600; leave it above 600 if you want the overlap that makes a failed refresh survivable.

A `static` block carrying a `session_token` is the one credential SBproxy cannot renew, because a session token arrives already issued and there is nothing to reissue it from. Once it lapses, Bedrock answers 403 `ExpiredTokenException` until the config supplies a new one. Use `assume_role` or `default_chain` when you want the renewal handled.

Clock skew is the other way a correct key produces a 403. AWS refuses a signature whose timestamp sits too far from its own clock, and Bedrock reports that as a plain 403 that looks much like a permissions error. SBproxy reads the `Date` header off the rejection, estimates the local offset against the round trip's midpoint, and once the offset passes four minutes it logs a WARN naming clock skew and applies the correction to later signatures. Traffic recovers on its own; the log line is your cue to fix NTP on that host, since a correction is not a repair. A wrong secret key never moves the measured offset, which is what tells the two apart in the log.

#### What signing does not cover

Active health checks are skipped for a signed provider, and the startup log names each one skipped. `bedrock-runtime` has no cheap liveness route worth signing, and the control plane's `ListFoundationModels` is a different host, a different signing service, and a different IAM action, so it reports nothing about the data plane. The health axis abstains and routing leans on real-traffic failures instead. Envoy arrives at the same behavior from the other direction: its `aws_request_signing` filter lives in the HTTP filter chain, and active health checks never traverse it.

Shadow and race legs are signed like anything else. A shadow copy of a Bedrock call is a real `InvokeModel` billed to your account and recorded in CloudTrail, tagged on the wire with `x-sbproxy-shadow: 1`. Turn `shadow:` off if you do not want the second call.

A request whose body is a stream is refused rather than signed as `UNSIGNED-PAYLOAD`, which is an Amazon S3 extension `bedrock-runtime` does not accept. It should not come up on this path anyway: Bedrock's streaming operations stream the response and take an ordinary buffered JSON request body.

## Reaching providers not on this list

Three options, roughly in order of preference:

1. **Point any provider at a custom `base_url`.** Most upstreams speak the OpenAI wire format, so a `provider_type: openai` entry with your own `base_url` reaches anything OpenAI-compatible: a self-hosted vLLM or SGLang pool, an internal gateway, or a proprietary endpoint. Wire compatibility does not authorize caller-owned OpenAI credentials. Leave `accept_native_credentials_for` unset unless you intend to trust this exact endpoint with those credentials.
2. **Add the provider to the catalog yourself.** It is plain YAML and ships uncompiled. See [Extending the provider catalog](#extending-the-provider-catalog).
3. **Use `openrouter` as a single-key aggregator** when you want many vendors without holding a direct account with each. It is one of the native providers, no different from the rest:

```yaml
providers:
  - name: openrouter
    api_key: ${OPENROUTER_API_KEY}
    default_model: anthropic/claude-sonnet-4.5
    models:
      - anthropic/claude-sonnet-4.5
      - meta-llama/llama-3.1-70b-instruct
      - mistralai/mistral-large
```

Local and self-hosted OpenAI-compatible runtimes are first-class providers in the registry: `ollama`, `vllm`, `tgi`, `lmstudio`, and `llamacpp`. Each has a sensible default `base_url` matching the runtime's convention. Override `base_url` if you bind elsewhere. See [example 86](../examples/local-models/sb.yml) for a hybrid local-plus-cloud config that falls back from a local Ollama to OpenAI when local is offline.

### base_url validation and local servers

An overridden `base_url` is validated at config load to keep it from becoming an SSRF vector. Non-`http(s)` schemes (`file://`, ...) are always rejected, and by default a URL that targets a loopback, link-local, or private (RFC 1918) address is rejected too, so a stray `http://169.254.169.254/` or `http://127.0.0.1/` fails fast instead of being dispatched at request time.

A local model server is the legitimate exception: it lives on `127.0.0.1` or a LAN address. Set `allow_private_base_url: true` on that provider to permit its private `base_url`. The scheme check still applies. Providers that use a registry default (no `base_url` override) are unaffected.

`allow_private_base_url` controls network reachability. It does not authorize
native credential forwarding. That requires the separate
`accept_native_credentials_for` destination binding, and locally served or
managed providers cannot enable it.

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

This endpoint uses its configured `api_key`. If it is also the intended
destination for caller-owned OpenAI keys, add
`accept_native_credentials_for: openai` after reviewing that endpoint's trust
boundary.

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
    auth_header: Authorization     # header carrying the key (required)
    auth_prefix: "Bearer "         # prefix prepended to the key ("" for raw keys, defaults to "")
    format: openai                 # wire format: openai | anthropic | google | bedrock | custom (required)
    supports_streaming: true       # advertised, not enforced, see below
    supports_embeddings: false     # advertised, not enforced, see below
    supports_chat: true            # advertised, not enforced, see below
```

A malformed override file is rejected and the gateway falls back to the embedded catalog rather than booting with no providers.

The three `supports_*` keys are claims about the vendor's own API. Nothing in
the request path reads them, so changing one changes nothing about what the
gateway forwards. That is decided by `format` plus the per-provider surface
matrix documented under
[Supported endpoints](ai-gateway.md#supported-endpoints), and a custom entry
with `format: openai` gets the full OpenAI surface row whatever its
`supports_embeddings` value says.

What they do decide is what a model listing advertises. `GET /v1/models`
publishes the intersection of the two, so setting a key to `false` takes the
surface off the listing and leaves the forwarding alone, and setting it to
`true` adds the surface only where the matrix already agrees.

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
