# SBproxy AI gateway guide

*Last modified: 2026-05-03*

SBproxy includes an AI gateway that sits between your application and LLM providers. You get one API endpoint with automatic failover, cost tracking, rate limits, and programmable routing across OpenAI, Anthropic, and other providers. The proxy ships with 36 OpenAI-compatible providers plus a native Anthropic translator, and the OpenRouter aggregator routes 200+ more.

## Provider setup

Configure one or more providers under the `action` block. Each provider needs a name, API key, and model list:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini, gpt-4-turbo]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514, claude-3-5-haiku-20241022]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
```

API keys support environment variable interpolation with `${VAR_NAME}` syntax. Never put raw keys in config files.

### Native providers

36 OpenAI-compatible providers ship in-tree alongside a native Anthropic translator and the OpenRouter aggregator (which routes 200+ more models). Direct adapters include `openai`, `anthropic`, `gemini`, `azure`, `bedrock`, `cohere`, `mistral`, `groq`, `deepseek`, `ollama`, `vllm`, `together`, `fireworks`, `perplexity`, `xai`, `sagemaker`, `databricks`, `oracle`, `watsonx`, and `openrouter`.

For models that are not natively supported, route through `openrouter` (200+ models behind one key) or point a `vllm` or generic OpenAI-compatible provider at a self-hosted endpoint via `base_url`. See `providers.md` for the full per-provider model table.

## Routing strategies

The `routing.strategy` field controls how the proxy picks a provider for each request.

### round_robin

Spreads requests evenly across healthy providers. A reasonable default.

```yaml
routing:
  strategy: round_robin
```

### weighted

Assigns a weight to each provider. Higher weight means more traffic.

```yaml
routing:
  strategy: weighted
```

### fallback_chain

Tries providers in priority order. When the selected provider fails or returns 5xx, the router moves to the next provider.

```yaml
routing:
  strategy: fallback_chain
```

### cost_optimized

Picks the cheapest provider that is not already loaded. The router scores each provider as `in_flight_requests * 1000 + weight` and routes to the lowest score. Set a lower `weight` on cheaper providers so they win ties when utilization is similar.

```yaml
routing:
  strategy: cost_optimized
```

### lowest_latency

Routes to the provider with the lowest observed latency based on recent request history.

```yaml
routing:
  strategy: lowest_latency
```

### least_connections

Routes to the provider with the fewest in-flight requests.

```yaml
routing:
  strategy: least_connections
```

### sticky

Pins a user or session to the same provider. Falls back to round_robin for the initial pick.

```yaml
routing:
  strategy: sticky
```

### random

Picks a provider uniformly at random. Useful for spreading load when no other signal applies.

```yaml
routing:
  strategy: random
```

### token_rate

Routes to the provider with the most remaining token-per-minute capacity. Pair with per-provider token limits so the router can score headroom.

```yaml
routing:
  strategy: token_rate
```

### race

Fans the request out to every eligible provider in parallel, returns the first 2xx, cancels the in-flight losers. Optimizes p99 latency at the cost of N times the API spend per request. Pair with `resilience` so persistently slow providers fall out of the eligible set.

```yaml
routing:
  strategy: race
```

See [examples/89-ai-race](../examples/89-ai-race/sb.yml).

## Resilience

Per-provider circuit breaker, outlier detection, and active health probes layered on top of the routing strategy. Each signal independently ejects a provider; when every provider is ejected, the router falls back to the unfiltered enabled list rather than refusing the request.

```yaml
resilience:
  circuit_breaker:
    failure_threshold: 5
    success_threshold: 2
    open_duration_secs: 30
  outlier_detection:
    threshold: 0.5
    window_secs: 60
    min_requests: 5
    ejection_duration_secs: 30
  health_check:
    path: /models
    interval_secs: 30
    timeout_ms: 5000
    unhealthy_threshold: 3
    healthy_threshold: 2
```

See [examples/87-ai-resilience](../examples/87-ai-resilience/sb.yml). Field reference in [configuration.md#resilience-resilience](configuration.md#resilience-resilience).

## Shadow eval

Mirror each request to a second provider concurrently. The primary's response is what the client sees; the shadow body is drained and metrics are emitted at `target=sbproxy_ai_shadow` (status, latency, prompt/completion tokens, finish_reason). Useful for prompt regression checks before swapping a primary model.

```yaml
shadow:
  provider: anthropic
  sample_rate: 0.1
  timeout_ms: 30000
```

See [examples/88-ai-shadow](../examples/88-ai-shadow/sb.yml).

## Proxy-native AI patterns

SBproxy is a proxy first, so AI traffic composes with everything else the proxy offers: CEL policies, forward rules, regex guardrails, request modifiers. Patterns that are awkward or impossible to express in a pure AI gateway library:

| Pattern | Mechanism | Example |
|---------|-----------|---------|
| Tenant access control before any AI call | `policies` (CEL expression) | [93-ai-cel-tenant-gate](../examples/93-ai-cel-tenant-gate/sb.yml) |
| Mixed AI + non-AI on one hostname (health probes, docs, model catalog) | `forward_rules` with inline child origins | [94-ai-mixed-traffic](../examples/94-ai-mixed-traffic/sb.yml) |
| Custom DLP beyond built-in PII (codenames, ticket IDs, internal hostnames) | `guardrails.input` with `regex` patterns | [95-ai-regex-dlp](../examples/95-ai-regex-dlp/sb.yml) |
| Topic enforcement (allow-list of approved keywords) | `regex` guardrail with `action: allow` | [95-ai-regex-dlp](../examples/95-ai-regex-dlp/sb.yml) |

CEL policies and request modifiers run before the AI handler dispatches, so a rejection costs no provider tokens. Forward rules dispatch by path, which means health checks and probe traffic can stay on the same hostname without billing a model. Regex guardrails inspect the parsed prompt body and slot in next to PII, injection, jailbreak, and schema guardrails.

## Native format translation

Clients always speak the OpenAI chat completions shape; sbproxy rewrites the body, path, and response back to OpenAI shape when the upstream provider speaks a different protocol.

| Provider format | Direction | Status |
|-----------------|-----------|--------|
| OpenAI | pass-through | always |
| Anthropic Messages API | bidirectional, non-streaming | shipped |
| Anthropic SSE events | streaming | not yet translated, passes through native |
| Google Gemini | bidirectional | not yet implemented |
| AWS Bedrock | bidirectional | not yet implemented |

For Anthropic, the request hoists `system` role messages to the top-level `system` field, defaults `max_tokens` when missing, strips OpenAI-only knobs (`logit_bias`, `n`, `presence_penalty`, `frequency_penalty`, `response_format`, `seed`, `user`), and rewrites the path from `/v1/chat/completions` to `/v1/messages`. The response converts text and tool_use blocks back into the OpenAI `choices[].message.content` and `tool_calls` shape, maps `stop_reason` to `finish_reason`, and renames `usage.input_tokens` / `output_tokens` to `prompt_tokens` / `completion_tokens`.

See [examples/11-ai-claude](../examples/11-ai-claude/sb.yml) and [providers.md](providers.md).

## Rate limits

Apply rate limits per client or globally to control costs and prevent abuse:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
    policies:
      - type: rate_limiting
        requests_per_minute: 100
```

Clients exceeding the limit receive a `429 Too Many Requests` response with a `Retry-After` header.

## Guardrails

The proxy supports seven guardrail types: `pii`, `injection`, `jailbreak`, `toxicity`, `content_safety`, `schema`, and `regex`. Guardrails run on input (before the provider call) or output (after), and they can block, flag, or rewrite content. See the CEL guardrails section below for inline CEL conditions, and `features.md` for the higher-level configuration of each guardrail type.

## Lua hooks

Use Lua scripts for more complex routing logic. Lua hooks run in a sandbox with access to request context variables.

Example: route coding questions to Anthropic based on the request path:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
    request_modifiers:
      lua:
        script: |
          local path = request.path
          if string.find(path, "/code") then
            return {
              add_headers = {
                ["X-Preferred-Provider"] = "anthropic"
              }
            }
          end
          return {}
```

## CEL guardrails

Block or modify AI requests with CEL expressions:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
    policies:
      - type: rate_limiting
        requests_per_minute: 100
    request_modifiers:
      cel:
        - expression: >
            request.headers['x-department'] == ''
              ? {"set_headers": {"X-Block": "true"}}
              : {}
```

## Budgets

Set token or dollar caps that apply across a workspace, a single virtual key, an end user, a model, an origin, or a metadata tag. The `budget` block sits under `action` and is parsed by `BudgetConfig` in `crates/sbproxy-ai/src/budget.rs`.

```yaml
action:
  type: ai_proxy
  budget:
    on_exceed: downgrade
    limits:
      - scope: workspace
        max_cost_usd: 500
        period: monthly
      - scope: api_key
        max_tokens: 1000000
        period: daily
        downgrade_to: gpt-4o-mini
      - scope: user
        max_cost_usd: 5
        period: daily
      - scope: model
        max_tokens: 200000
        period: daily
      - scope: origin
        max_cost_usd: 50
        period: daily
      - scope: tag
        max_cost_usd: 25
        period: monthly
```

### `budget` fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `limits` | list | `[]` | One or more `BudgetLimit` entries. Each is checked on every request. |
| `on_exceed` | enum | `block` | One of `block`, `log`, `downgrade`. Applies to whichever limit fires. |

### `BudgetLimit` fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `scope` | enum | required | One of `workspace`, `api_key`, `user`, `model`, `origin`, `tag`. |
| `max_tokens` | u64 | unset | Total prompt + completion tokens allowed for the scope. |
| `max_cost_usd` | f64 | unset | Total cost ceiling in USD across all requests in the scope. |
| `period` | string | unset | One of `daily`, `weekly`, `monthly`, `total`. Window over which usage accumulates. |
| `downgrade_to` | string | unset | Model name routed to when this limit fires and `on_exceed` is `downgrade`. |

### Behaviour notes

- A limit fires the first time `usage >= max_tokens` or `usage >= max_cost_usd`. Limits are checked in declaration order and the first match wins.
- `on_exceed: log` records a warning and a `sbproxy_ai_budget_utilization_ratio` gauge update, then lets the request through.
- `on_exceed: downgrade` swaps the request's model to the firing limit's `downgrade_to` and proceeds. If `downgrade_to` is unset, the request is blocked.
- Setting only `max_tokens` and leaving `max_cost_usd` unset (or vice versa) is supported. A limit with neither field is a no-op.
- A hierarchical view (`org`, `team`, `project`, `user`, `model` keys with 80% warning band) is exposed to in-process callers via `HierarchicalBudget` in `hierarchical_budget.rs`. There is no top-level YAML knob for it today; it is wired by the runtime when the gateway tracks spend.

## Virtual API keys

Issue per-team or per-app keys that the gateway validates locally. Each key can restrict allowed providers and models, set its own request and token rates, carry its own budget ceiling, and tag requests for downstream attribution. The `virtual_keys` list sits under `action` and is parsed by `VirtualKeyConfig` in `crates/sbproxy-ai/src/identity.rs`.

```yaml
action:
  type: ai_proxy
  virtual_keys:
    - key: ${TEAM_A_KEY}
      name: team-a
      enabled: true
      allowed_providers: [openai, anthropic]
      allowed_models: [gpt-4o-mini, claude-3-5-haiku-20241022]
      blocked_models: [gpt-4-turbo]
      max_requests_per_minute: 60
      max_tokens_per_minute: 200000
      budget:
        max_tokens: 5000000
        max_cost_usd: 100
      tags: [team-a, beta]
```

### `virtual_keys[]` fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `key` | string | required | The token clients send. Treat it like a secret and inject via `${VAR}`. |
| `name` | string | unset | Human label used in logs and metrics. |
| `enabled` | bool | `true` | Disable a key without deleting the entry. |
| `allowed_providers` | list of string | `[]` | Empty list allows all configured providers. |
| `allowed_models` | list of string | `[]` | Empty list allows all models. Otherwise the request model must match one entry. |
| `blocked_models` | list of string | `[]` | Takes precedence over `allowed_models`. A blocked model is rejected even if it appears in the allow list. |
| `max_requests_per_minute` | u64 | unset | Per-key RPM cap. The 60-second window starts on the first request and resets after one minute of wall time. |
| `max_tokens_per_minute` | u64 | unset | Per-key TPM cap. Tokens are recorded after the response is read. |
| `budget` | object | unset | `KeyBudget` with `max_tokens` and `max_cost_usd`. Independent of the global `budget` block. |
| `tags` | list of string | `[]` | Free-form labels attached to every request the key authenticates. Surfaced in logs and emitted in the `sbproxy_ai_key_*` metric labels. |

Per-key usage shows up in the `sbproxy_ai_key_*` metrics.

## Caching

Three independent caches sit in front of providers. Each has its own runtime configuration in `crates/sbproxy-ai/src/`. Hit and miss counts land in `sbproxy_ai_cache_results_total`.

### Exact prompt cache

Hashes the request body and serves byte-for-byte hits. Implemented in `prompt_cache.rs`. The cache key is the SHA-256 of the canonicalised JSON `messages` array, so request key ordering does not affect lookups. The module also detects Anthropic's native `cache_control` blocks (top-level `system`, per-message, or per-content-part) and lets those pass through to the upstream provider.

The exact-match path is a runtime construct rather than an `action` field today. It is enabled implicitly when the gateway is built with a cache backing store. There are no YAML knobs for the exact prompt cache.

### Semantic cache

Stores responses keyed by the SHA-256 of the messages array with TTL and capacity bounds. Implemented in `semantic_cache.rs` as `SemanticCache`. The constructor takes `max_entries: usize` and `ttl_secs: u64`; entries are evicted with an insert-order LRU when the cache is full, and lazily expired on lookup.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `max_entries` | usize | constructor arg | Hard cap on cached responses. The oldest insert is evicted on overflow. |
| `ttl_secs` | u64 | constructor arg | Seconds before an entry is treated as a miss and removed. |

The semantic cache is configured via per-origin `extensions.semantic_cache` rather than `action.semantic_cache`. Example:

```yaml
origins:
  ai.example.com:
    action:
      type: ai_proxy
      providers: [...]
    extensions:
      semantic_cache:
        enabled: true
        ttl_secs: 1200
        key_template: "{embedding_model}:{lsh_bucket}"
```

The `extensions` map is opaque to the OSS config parser; runtime components that recognise the key apply it.

### Idempotency cache

Returns the same response for retries carrying a matching `Idempotency-Key` header. Implemented in `idempotency.rs` as `IdempotencyCache`. The constructor takes a single argument: `ttl_secs: u64`. Entries are removed lazily on the next lookup after they expire.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `ttl_secs` | u64 | constructor arg | Window during which a duplicate `Idempotency-Key` returns the cached response. |

Like the exact prompt cache, the idempotency cache is built by the runtime rather than configured under `action`.

## Per-provider limits

The proxy reads rate limit headers off provider responses and pre-emptively throttles when remaining capacity falls under a configured fraction. Implemented in `provider_ratelimit.rs` as `ProviderRateLimitTracker`.

Recognised response headers (case-insensitive):

- `x-ratelimit-remaining-requests`, `x-ratelimit-remaining-tokens`
- `x-ratelimit-reset-requests`, `x-ratelimit-reset-tokens` (formats: `1s`, `500ms`, plain seconds)
- `retry-after` (plain seconds)
- `anthropic-ratelimit-requests-remaining`, `anthropic-ratelimit-tokens-remaining`
- `anthropic-ratelimit-requests-reset`

The tracker takes a single `throttle_threshold: f64` between 0.0 and 1.0. The implementation throttles when remaining requests fall to or below `floor(1000 * threshold)`, treating 1000 req/min as a baseline. Default: `0.1`, which throttles at 100 remaining requests or fewer.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `throttle_threshold` | f64 | `0.1` | Clamped to `[0.0, 1.0]`. Lower values delay throttling until the provider is closer to its hard limit. |

Per-provider throttling is a runtime construct. There is no top-level YAML field; the tracker is instantiated alongside the provider pool and updated from every upstream response.

For per-model rate limits configurable in YAML, use `model_rate_limits` on the `action` block. The struct is `ModelRateConfig` in `ratelimit.rs`:

```yaml
action:
  type: ai_proxy
  model_rate_limits:
    gpt-4o:
      requests_per_minute: 200
      tokens_per_minute: 400000
    claude-sonnet-4-20250514:
      requests_per_minute: 100
      tokens_per_minute: 200000
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `requests_per_minute` | u64 | unset | Sliding one-minute window cap on requests for the model. |
| `tokens_per_minute` | u64 | unset | Sliding one-minute window cap on tokens for the model. |

## Model aliases

Map friendly names onto specific provider plus model pairs, with optional deprecation pointers. Implemented in `model_alias.rs` as `ModelAliasRegistry`, with each entry typed as `ModelAlias`. The registry is constructed by the runtime; entries deserialise from YAML or JSON when loaded.

```yaml
model_aliases:
  - alias: fast
    provider: openai
    model_id: gpt-4o-mini
  - alias: smart
    provider: anthropic
    model_id: claude-sonnet-4-20250514
  - alias: claude-old
    provider: anthropic
    model_id: claude-3-opus-20240229
    deprecated: true
    replacement: smart
```

### `ModelAlias` fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `alias` | string | required | The friendly name clients send. |
| `provider` | string | required | Provider name to route to. |
| `model_id` | string | required | The model ID actually sent upstream. |
| `deprecated` | bool | `false` | When true, a warning is logged on every resolution. |
| `replacement` | string | unset | Suggested alias to migrate to. Surfaces in the deprecation log line. |

Resolution returns `None` for unknown names so the request falls back to literal model ID matching. Re-registering the same alias overwrites the previous entry.

The alias registry is wired by the runtime rather than read off the `action` block. Treat the YAML above as the canonical shape when serialising aliases for code paths that load them.

## Supported endpoints

Path detection happens in `crates/sbproxy-ai/src/api_routes.rs::parse_endpoint` for the chat-style surface and in per-feature handler modules for the rest. All endpoint paths are OpenAI-compatible. Provider selection at every path uses the same provider list, routing strategy, virtual keys, budgets, and rate limits as the chat path. Modality-aware filtering (see `multimodal.rs`) removes providers that do not support the request type before routing runs.

| Path | Method | Handler module | Notes |
|------|--------|----------------|-------|
| `/v1/chat/completions` | POST | `handler.rs`, `api_routes.rs` | Text and multimodal chat. Multimodal is detected when `messages[].content` includes `image_url` or `image` parts. |
| `/v1/completions` | POST | `handler.rs` | Legacy text completion. |
| `/v1/embeddings` | POST | `api_routes.rs` | Embedding generation. Routed only to providers that report embedding support (OpenAI, Gemini, Cohere, Mistral). |
| `/v1/rerank`, `/v1/reranking` | POST | `api_routes.rs` | Document reranking. OpenAI, Anthropic, Gemini, Cohere. |
| `/v1/moderations` | POST | `api_routes.rs` | Content moderation. OpenAI, Anthropic, Gemini. |
| `/v1/models` | GET | `api_routes.rs` | List models. All providers respond. |
| `/v1/images/generations` | POST | `image.rs`, `api_routes.rs` | Image generation. Routed only to providers that report image support (OpenAI, Gemini). |
| `/v1/images/edits` | POST | `image.rs` | Image edit. |
| `/v1/images/variations` | POST | `image.rs` | Image variation. |
| `/v1/audio/transcriptions` | POST | `audio.rs`, `api_routes.rs` | Speech to text. Routed only to providers that report audio support (OpenAI, Gemini, Groq). |
| `/v1/audio/translations` | POST | `audio.rs` | Translate audio to English text. |
| `/v1/audio/speech` | POST | `audio.rs`, `api_routes.rs` | Text to speech. |
| `/v1/realtime` | WebSocket | `realtime.rs` | OpenAI realtime audio session. Disabled by default; enable with `realtime.enabled: true` and pick `realtime.model` (default `gpt-4o-realtime-preview`). |
| `/v1/assistants` | POST, GET | `assistants.rs` | Create or list assistants. |
| `/v1/assistants/{id}` | GET | `assistants.rs` | Fetch a single assistant by ID. |
| `/v1/threads` | POST | `assistants.rs`, `threads.rs` | Create a thread. The proxy keeps a local `ThreadStore` for session continuity. |
| `/v1/threads/{thread_id}/messages` | POST | `assistants.rs`, `threads.rs` | Append a message to a thread. |
| `/v1/threads/{thread_id}/runs` | POST | `assistants.rs` | Start a run on a thread. |
| `/v1/threads/{thread_id}/runs/{run_id}` | GET | `assistants.rs` | Fetch run status. |
| `/v1/batches` | POST, GET | `batch.rs` | Create or list batch jobs. The proxy keeps a `BatchStore` (in-memory by default) tracking job lifecycle (`pending`, `in_progress`, `completed`, `failed`, `cancelled`). |
| `/v1/fine_tuning/jobs` | POST, GET | `finetune.rs` | Create or list fine-tuning jobs. |
| `/v1/fine_tuning/jobs/{id}` | GET | `finetune.rs` | Fetch a single job. |
| `/v1/fine_tuning/jobs/{id}/cancel` | POST | `finetune.rs` | Cancel a job. |
| `/v1/fine_tuning/jobs/{id}/events` | GET | `finetune.rs` | List job events. |

### Per-endpoint config

Most non-chat endpoints have no dedicated YAML block; they reuse the top-level `providers`, `routing`, `virtual_keys`, `budget`, `model_rate_limits`, and `max_concurrent` fields. The exceptions:

- `realtime`: `RealtimeConfig { enabled: bool, model: String }`. Without `enabled: true` the websocket path is rejected.
- `assistants`: `AssistantConfig { enabled: bool }`. Pure passthrough flag.
- `finetune`: `FinetuneConfig { enabled: bool }`. Pure passthrough flag.

Audio (`audio.rs`), image (`image.rs`), and batch (`batch.rs`) define request/response shapes and stores but expose no YAML config of their own. Multimodal detection (`multimodal.rs`) is runtime-only: it inspects the path and request body to set a modality, then filters the provider list. There is no `multimodal:` block.

## Context handling

Three modules handle prompts that approach or exceed a model's context window. They are layered: relay carries history across rotations, overflow decides what to do when the next request will not fit, and compress trims when the answer is to keep going with a smaller history.

### Context relay

`crates/sbproxy-ai/src/context_relay.rs` is a thread-safe map of session ID to message history. When the router rotates between providers or virtual keys mid-session, it pulls the prior message list out of the relay and replays it to the new provider so the conversation does not reset. Messages are kept as raw `serde_json::Value` so provider-specific shapes survive the round trip. No YAML config: it is internal state used by the router.

### Context overflow

`crates/sbproxy-ai/src/context_overflow.rs` ships a registry of context windows for the OpenAI, Anthropic, Gemini, Mistral, and Llama families and decides what to do when a request would overflow. Three actions are available:

- `Error`: return a 4xx to the client.
- `FallbackToLarger(model)`: resend to a larger-window model named in config.
- `Truncate`: drop oldest turns and retry, available through `check_overflow_with_truncate`.

The choice is driven by a `context_overflow` block on the AI handler:

```yaml
action:
  type: ai_proxy
  context_overflow:
    fallback_model: gpt-4o      # used when the current model overflows and gpt-4o has a larger window
    on_overflow: truncate       # error | fallback | truncate
```

If the requested model is not in the registry, overflow checks are skipped (no window to compare against) and the request is forwarded as-is.

### Context compress

`crates/sbproxy-ai/src/context_compress.rs` does cost-aware history trimming. `estimate_message_tokens` uses a four-characters-per-token approximation. `trim_to_budget` always keeps the leading system message, then walks remaining messages newest-to-oldest, including each one only if it fits in the remaining token budget, then restores chronological order before returning.

This module exposes pure functions; it is invoked by the routing strategy and overflow handler. There is no `context_compress:` YAML block.

## Streaming analytics

`crates/sbproxy-ai/src/streaming_analytics.rs` tracks per-stream timing for SSE responses. `StreamTracker` records start time, first-token instant, and last-token instant; from these it computes Time to First Token (`ttft_ms`), Tokens Per Second (`tps`), and average inter-token latency (`avg_itl_ms`). `StreamRegistry` is the global map of in-flight streams keyed by request ID.

These values feed the `sbproxy_ai_request_duration_seconds` histogram and request-scoped log records. The module has no YAML config; it is wired in whenever streaming responses are observed.

## Structured output

`crates/sbproxy-ai/src/structured_output.rs` validates responses against a JSON Schema. The config struct sits on the AI handler:

```yaml
action:
  type: ai_proxy
  structured_output:
    schema:                     # JSON Schema the response must conform to
      type: object
      required: [name, age]
      properties:
        name: {type: string}
        age:  {type: integer}
    retry_on_failure: true      # default: false
    max_retries: 2              # default: 1
```

When `retry_on_failure` is true, a failed validation triggers a retry with the schema injected into the system prompt via `build_schema_instruction`. `extract_json` strips ` ```json ` and ` ``` ` fences before parsing, so models that wrap output in markdown still validate. Validation is structural: required-field presence and per-property type checks (`string`, `number`, `integer`, `boolean`, `array`, `object`, `null`). Full JSON Schema features such as `$ref` and `oneOf` are not implemented.

## Per-request attribution

The gateway records provider, model, token counts, and estimated cost for every AI request and exposes them through Prometheus metrics (see below). Direct response headers for these fields are not emitted today.

## Token usage metrics

The proxy exposes aggregate AI usage as Prometheus metrics. When `telemetry.bind_port` is configured, the following counters and gauges are available at `/metrics` under the `sbproxy_ai_*` namespace:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sbproxy_ai_requests_total` | Counter | `provider`, `model`, `status` | Total AI requests |
| `sbproxy_ai_tokens_total` | Counter | `provider`, `model`, `direction` | Tokens consumed (`direction` is `input` or `output`) |
| `sbproxy_ai_cost_dollars_total` | Counter | `provider`, `model` | Estimated cost in USD |
| `sbproxy_ai_request_duration_seconds` | Histogram | `provider`, `model` | End-to-end AI request latency |
| `sbproxy_ai_failovers_total` | Counter | `from_provider`, `to_provider`, `reason` | Provider failover events |
| `sbproxy_ai_guardrail_blocks_total` | Counter | `category` | Guardrail block events (pii, injection, jailbreak, etc.) |
| `sbproxy_ai_cache_results_total` | Counter | `provider`, `cache_type`, `result` | AI response cache results (`cache_type` is `exact` or `semantic`, `result` is `hit` or `miss`) |
| `sbproxy_ai_budget_utilization_ratio` | Gauge | `scope` | Current budget utilization as a 0 to 1 ratio |
| `sbproxy_ai_key_requests_total` | Counter | `virtual_key`, `provider`, `model` | Requests per virtual key |
| `sbproxy_ai_key_tokens_total` | Counter | `virtual_key`, `direction` | Tokens per virtual key |
| `sbproxy_ai_key_cost_dollars_total` | Counter | `virtual_key` | Cost in USD per virtual key |

Use these to build spending dashboards, set budget alerts, and track provider reliability without any application-level instrumentation.

## Dashboards

The metrics above can be wired into any Prometheus-compatible dashboard tool. A pre-built JSON for AI gateway health is on the roadmap; for now, point your existing Prometheus or Grafana setup at `/metrics` and chart the counters and histograms listed above.

## Streaming

The proxy supports streaming responses. When your client sends a streaming request (e.g. `"stream": true` in the OpenAI API), the proxy:

1. Validates the request (auth, rate limits, guardrails).
2. Picks a provider using the configured routing strategy.
3. Opens a streaming connection to the provider.
4. Forwards SSE chunks to the client as they arrive.
5. Reads token usage from the final chunk and records it to the metrics counters.

No special configuration is needed. Streaming works with all routing strategies and all providers.

### Usage extraction

Different providers report streaming token counts in different SSE shapes. The streaming relay scans every chunk through a pluggable parser and records the captured tokens against the configured budget scopes when the stream closes. Pick the parser explicitly with `usage_parser`, or leave it at the default `auto` and the proxy resolves it from the upstream URL host, response `Content-Type`, and an optional `X-Provider` response header.

| `usage_parser` | Wire format | Notes |
|---|---|---|
| `openai` | `data: {..., "usage": {...}}\n\n` terminal frame | OpenAI, Azure OpenAI, OpenAI-compatible relays |
| `anthropic` | `event: message_start` plus `event: message_delta` with `usage` | Max-of across both events; `input_tokens` from start, `output_tokens` from delta |
| `vertex` | `data: {..., "usageMetadata": {...}}` on every chunk | Vertex AI / Gemini; values grow monotonically |
| `bedrock` | `data: {"bytes": "<base64>"}` envelope | Decodes the envelope and delegates to the Anthropic parser for the inner stream |
| `cohere` | `data: {..., "event_type": "stream-end", ..., "billed_units": {...}}` | Reads `response.meta.billed_units` or `meta.billed_units` |
| `ollama` | NDJSON: `{..., "done": true, "prompt_eval_count": N, "eval_count": M}\n` | Line-delimited JSON instead of SSE |
| `generic` | Best-effort across all of the above | Default fallback when `auto` cannot match a known upstream |
| `auto` | Resolved at request time | See order below |
| `none` | Skip parsing | Disables streaming budget recording for this origin |

`auto` resolves in this order:

1. Response `X-Provider` header (operator-controlled).
2. Upstream URL host: `*.openai.com` plus `*.openai.azure.com` -> `openai`, `*.anthropic.com` -> `anthropic`, `*.googleapis.com` or any host containing `aiplatform` -> `vertex`, `bedrock-*` or `*.amazonaws.com` -> `bedrock`, `*.cohere.ai` or `*.cohere.com` -> `cohere`, `localhost:11434` or any host containing `ollama` -> `ollama`.
3. Response `Content-Type`: `application/x-ndjson` or `application/jsonl` -> `ollama`.
4. Fall back to `generic`.

Unknown values warn once and fall back to `generic` so a typo never silently disables budget recording.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      usage_parser: anthropic    # or auto, openai, vertex, bedrock, cohere, ollama, generic, none
      providers:
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          base_url: https://api.anthropic.com/v1
```

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="unused",
    default_headers={"Host": "ai.example.com"},
)

stream = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Write a haiku about proxies."}],
    stream=True,
)
for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="")
```

## Full example

An AI gateway with two providers, fallback routing, API key auth, and a rate limit:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          priority: 1
          models: [gpt-4o, gpt-4o-mini, gpt-4-turbo]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          priority: 2
          models: [claude-sonnet-4-20250514, claude-3-5-haiku-20241022]
      default_model: gpt-4o-mini
      routing:
        strategy: fallback_chain
    authentication:
      type: api_key
      api_keys:
        - ${AI_GATEWAY_KEY}
    policies:
      - type: rate_limiting
        requests_per_minute: 200
```

## See also

- [providers.md](providers.md) - full provider table and per-provider model lists.
- [scripting.md](scripting.md) - CEL and Lua reference, including AI selector and guardrail variables.
- [configuration.md](configuration.md) - general configuration model, origin schema, and the full `sb.yml` field reference.
- [features.md](features.md) - higher-level overview of features including guardrails.
