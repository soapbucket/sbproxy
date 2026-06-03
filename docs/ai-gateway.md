# SBproxy AI gateway guide

*Last modified: 2026-05-12*

SBproxy includes an AI gateway that sits between your application and LLM providers. You get one API endpoint with automatic failover, cost tracking, rate limits, and programmable routing across OpenAI, Anthropic, and other providers. The proxy ships with 43 native providers, including a native Anthropic translator, and the OpenRouter aggregator routes 200+ more.

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

43 native providers ship in-tree alongside a native Anthropic translator and the OpenRouter aggregator (which routes 200+ more models). Direct adapters include `openai`, `anthropic`, `gemini`, `azure`, `bedrock`, `cohere`, `mistral`, `groq`, `deepseek`, `ollama`, `vllm`, `together`, `fireworks`, `perplexity`, `xai`, `sagemaker`, `databricks`, `oracle`, `watsonx`, and `openrouter`.

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

See [examples/ai-race](../examples/ai-race/sb.yml).

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

See [examples/ai-resilience](../examples/ai-resilience/sb.yml). Field reference in [configuration.md#resilience-resilience](configuration.md#resilience-resilience).

## Shadow eval

Mirror each request to a second provider concurrently. The primary's response is what the client sees; the shadow body is drained and metrics are emitted at `target=sbproxy_ai_shadow` (status, latency, prompt/completion tokens, finish_reason). Useful for prompt regression checks before swapping a primary model.

```yaml
shadow:
  provider: anthropic
  sample_rate: 0.1
  timeout_ms: 30000
```

See [examples/ai-shadow](../examples/ai-shadow/sb.yml).

## Proxy-native AI patterns

SBproxy is a proxy first, so AI traffic composes with everything else the proxy offers: CEL policies, forward rules, regex guardrails, request modifiers. Patterns that are awkward or impossible to express in a pure AI gateway library:

| Pattern | Mechanism | Example |
|---------|-----------|---------|
| Tenant access control before any AI call | `policies` (CEL expression) | [93-ai-cel-tenant-gate](../examples/ai-cel-tenant-gate/sb.yml) |
| Mixed AI + non-AI on one hostname (health probes, docs, model catalog) | `forward_rules` with inline child origins | [94-ai-mixed-traffic](../examples/ai-mixed-traffic/sb.yml) |
| Custom DLP beyond built-in PII (codenames, ticket IDs, internal hostnames) | `guardrails.input` with `regex` patterns | [95-ai-regex-dlp](../examples/ai-regex-dlp/sb.yml) |
| Topic enforcement (allow-list of approved keywords) | `regex` guardrail with `action: allow` | [95-ai-regex-dlp](../examples/ai-regex-dlp/sb.yml) |

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

See [examples/ai-claude](../examples/ai-claude/sb.yml) and [providers.md](providers.md).

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

### Per-surface rate limits

Per-model and per-tenant rate limits cap each user, key, or model independently. The AI gateway also supports per-surface caps that apply to a classified API surface (chat completions, assistants, image generation, audio speech, ...) so expensive paths can be throttled without affecting cheap ones.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
      per_surface_rate_limits:
        image_generation:
          requests_per_minute: 30
        audio_speech:
          requests_per_minute: 60
        chat_completions:
          requests_per_minute: 600
```

Keys are the `AiSurface` labels emitted on metrics (`chat_completions`, `models`, `embeddings`, `assistants`, `threads`, `batches`, `fine_tuning`, `files`, `realtime`, `image_generation`, `image_edits`, `image_variations`, `audio_transcription`, `audio_speech`, `moderations`, `reranking`). Surfaces without an entry are uncapped. When the cap fires, the proxy returns 429 before any upstream call.

The sliding window is one minute, shared across all configured origins (state is process-global). Audio-seconds-per-hour caps for realtime sessions are reserved for the realtime dispatch phase.

## Guardrails

The proxy supports nine guardrail types: `pii`, `injection`, `jailbreak`, `toxicity`, `content_safety`, `schema`, `regex`, `context_poisoning`, and `agent_alignment`. Guardrails run on input (before the provider call) or output (after), and they can block, flag, or rewrite content. See the CEL guardrails section below for inline CEL conditions, and `features.md` for the higher-level configuration of each guardrail type.

Input guardrails apply to whichever body field the surface carries user text in:

| Surface | Field guarded |
|---|---|
| `chat_completions`, `assistants`, `threads` | `body["messages"][].content` |
| `image_generation`, `image_edits`, `image_variations` | `body["prompt"]` |
| `audio_speech` | `body["input"]` |
| `reranking` | `body["query"]` |
| `moderations` | `body["input"]` |

A single guardrail block on the AI handler config covers every supported surface; the proxy picks the right field automatically based on the classified surface. Multipart-bodied surfaces (image edits, image variations, audio transcription) bypass the input-guardrail check today because their bodies are forwarded byte-transparently; output-side scanning for those surfaces is reserved for a follow-up.

### Streaming policy

A guardrail is *streaming-safe* when its block decision is stable as soon as the chunk it sees is decided. The proxy classifies the built-in guardrails as follows:

| Guardrail | Streaming-safe | Reason |
|---|---|---|
| `regex` | yes | per-chunk regex match is stable |
| `pii` | yes | PII patterns match per-chunk |
| `schema` | yes | JSON schema validation is decided on the parsed value |
| `context_poisoning` | yes | rule matches are per-message |
| `injection` | no | multi-token context windows; partial windows produce false negatives |
| `toxicity` | no | full-text classifier; partial-window scores are misleading |
| `jailbreak` | no | multi-pattern + multi-token detector |
| `content_safety` | no | full-text classifier (self-harm, violence, etc.) |
| `agent_alignment` | no | runs on the input body only (it inspects assistant tool_calls); streaming output is not in scope |

On the buffered (non-streaming) path the proxy runs every configured output guardrail against the full response. On the streaming output path the proxy runs only the streaming-safe guardrails on each chunk; non-safe guardrails are skipped because evaluating them against a partial window produces both false positives (tripping on benign mid-stream substrings) and false negatives (missing late-stream signal). Input guardrails always run against the full request regardless of `stream`.

Operators that want a non-safe guardrail to apply to streaming responses anyway should accept the partial-window risk explicitly and run a second buffered pass once the stream closes; the per-entry `streaming_safe` override surface for that case rides a follow-up.

### Context-poisoning guardrail

The `context_poisoning` input guardrail flags untrusted retrieval content that tries to manipulate the model before a downstream tool call. This is the indirect prompt injection vector from Greshake et al. (2023): a RAG pipeline pulls a poisoned page into the model's context, and the model then issues a tool call influenced by that content.

The check runs on the full input, including any `role: tool` or `role: function` messages that the AI gateway treats as retrieval content. Findings carry a stable `rule_id` and a confidence weight; the `min_confidence` setting filters out low-weight rules.

```yaml
guardrails:
  input:
    - type: context_poisoning
      enabled: true
      action: deny           # log | score | deny (default deny)
      min_confidence: 0.5
      rules:                 # optional allowlist; omit for all rules
        - cp_instruction_ignore_previous
        - cp_tool_call_scaffold
        - cp_encoded_instruction
        - cp_conflicting_directive
```

The rule catalogue covers four families:

| Family | Sample rule IDs | Detects |
|---|---|---|
| Instruction-like patterns | `cp_instruction_ignore_previous`, `cp_instruction_you_are_now`, `cp_instruction_system_prompt_leak`, `cp_suspicious_url` | "ignore previous instructions" style payloads, role-swap framings, exfiltration URL shapes |
| Tool-call hints | `cp_tool_call_scaffold`, `cp_tool_call_json_shape` | Literal `<tool_use>`, `function_call:`, or JSON tool invocations inside passive content |
| Encoded instructions | `cp_encoded_instruction` | Base64 and hex blobs that decode to instruction-like text |
| Conflicting directives | `cp_conflicting_directive`, `cp_instruction_imperative_regex` | Imperative second-person language in `role: tool` or `role: function` content |

Every hit emits `sbproxy_ai_context_poisoning_findings_total{rule_id, action}`. When `action: deny`, the request is also counted in `sbproxy_ai_context_poisoning_blocked_total` and the proxy returns a 4xx before any upstream call. `action: log` and `action: score` keep the request flowing; they differ only in the metric label so dashboards can separate observability volume from scoring volume.

See `examples/ai-context-poisoning/` for a complete sample configuration and curl commands.

### Agent-alignment guardrail

The `agent_alignment` input guardrail audits the assistant's `tool_calls` array against operator-declared rules: an allow list of tools the agent is permitted to invoke, an explicit deny list that always trips even when allowed elsewhere, a forbidden-substring scan over the tool arguments, and a per-turn budget on the number of tool calls. The check is the LlamaFirewall (arXiv:2505.03574) "Agent Alignment Check" use case rendered as a deterministic ruleset so the per-request cost is bounded; an LLM-judge advisory variant rides a follow-up and slots into the same configuration.

Unlike the other guardrails this one runs against the raw request body so it can read the OpenAI / Anthropic / MCP tool-call shapes; the flat-text view that backs `pii` / `injection` / etc. strips `tool_calls` and would silently miss the goal-divergence cases.

```yaml
guardrails:
  input:
    - type: agent_alignment
      enabled: true
      mode: flag                # flag (default, observability only) | block
      allowed_tools: [search, fetch]
      denied_tools: [delete_account]
      forbidden_arg_substrings:
        - "/etc/passwd"
        - "AKIA"                # leaked AWS-key shapes
      max_tool_calls_per_turn: 4
```

`mode: flag` records every violation as a log line + access-log entry but lets the request through; once the operator has tuned the rule lists they flip to `mode: block` so the dispatch loop short-circuits to a 400 on the next violation. Tool calls in any of three shapes are recognised: OpenAI (`tool_calls[*].function.name` + `function.arguments`), Anthropic (`tool_calls[*].name` + `input`), and MCP (`tool_calls[*].tool` or `tool_calls[*].name` + `arguments`). The forbidden-substring scan is case-insensitive against the JSON encoding of whichever argument field is present.

See `examples/ai-agent-alignment/` for a runnable configuration that exercises every rule.

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

### Idempotency middleware (RFC 8594)

Engages on `action: ai_proxy` origins when an `Idempotency-Key`
header is present on a POST / PUT / PATCH request. The middleware
sits ahead of the upstream provider call: on a cache hit the
gateway replays the cached `(status, headers, body)` triple
directly to the client with `x-sbproxy-idempotency: HIT` and
never contacts the provider, so Stripe-style retries do not
double-bill the upstream. On a body conflict the gateway returns
409 `ledger.idempotency_conflict`. On a miss the gateway forwards
and records the post-translation OpenAI-shape bytes the client
saw so retries replay byte-identical.

Per-origin caps (`max_request_body_bytes`,
`max_response_body_bytes`, `max_concurrent_buffers`) bound memory
and skip caching gracefully when a request exceeds them. Skip
reasons stamp on the outgoing response as
`x-sbproxy-idempotency: SKIPPED-...` so operators can spot
graceful degradation in dashboards.

Configuration is identical to general HTTP origins: see the
`idempotency:` block reference under
[`configuration.md`](configuration.md). v1 limitations: multipart
request bodies (audio transcription, image edit / variation, file
upload) are not cached, and SSE streaming responses abandon the
cache record above the response cap.

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

Every inbound request to an `action: ai_proxy` origin is classified into an `AiSurface` by `classify_surface(method, path)` in `crates/sbproxy-ai/src/handler.rs`. The classifier accepts canonical OpenAI paths with optional `/v1` or `/api/v1` prefix and any trailing slash. The surface label appears on the per-surface metrics, on the request tracing span, and on every per-surface decision (rate limit, guardrail extractor, 501 gate).

Provider capability is the source of truth for which surfaces a configured provider can serve. The matrix lives in `crates/sbproxy-ai/src/api_routes.rs::provider_supports_surface`. When no configured provider supports the requested surface, the proxy returns **501 Not Implemented** before any upstream call. Universal surfaces (chat completions and models) bypass the gate. Unknown surfaces fall through to the existing dispatch and 404 at the upstream.

| Surface label | Method(s) | Path(s) | Providers (today) |
|---|---|---|---|
| `chat_completions` | POST | `/v1/chat/completions` | All |
| `models` | GET | `/v1/models`, `/v1/models/{id}` | All |
| `embeddings` | POST | `/v1/embeddings` | OpenAI, Gemini, Cohere |
| `assistants` | POST, GET, DELETE | `/v1/assistants[/{id}[/files[/{file_id}]]]` | OpenAI |
| `threads` | POST, GET, DELETE | `/v1/threads[/{id}[/messages[/{id}] \| /runs[/{id}[/cancel]]]]`, `/v1/threads/runs` | OpenAI |
| `batches` | POST, GET | `/v1/batches[/{id}[/cancel]]` | OpenAI |
| `fine_tuning` | POST, GET | `/v1/fine_tuning/jobs[/{id}[/cancel \| /events]]` | OpenAI |
| `files` | POST, GET, DELETE | `/v1/files[/{id}[/content]]` | OpenAI |
| `realtime` | GET (WebSocket upgrade) | `/v1/realtime` | OpenAI |
| `image_generation` | POST | `/v1/images/generations` | OpenAI, Gemini |
| `image_edits` | POST (multipart) | `/v1/images/edits` | OpenAI, Gemini |
| `image_variations` | POST (multipart) | `/v1/images/variations` | OpenAI, Gemini |
| `audio_transcription` | POST (multipart) | `/v1/audio/transcriptions`, `/v1/audio/translations` | OpenAI, Gemini |
| `audio_speech` | POST | `/v1/audio/speech` | OpenAI, Gemini |
| `moderations` | POST | `/v1/moderations` | OpenAI |
| `reranking` | POST | `/v1/rerank`, `/v1/reranking` | Cohere |

### Response shape contract

"Supported" in the table above means the gateway accepts the surface and routes it. It does NOT mean the gateway normalises the response. Per-surface translation behaviour:

| Surface | Response shape |
|---|---|
| `chat_completions` | normalised to / from the OpenAI shape on Anthropic and Google (gemini) formats; passthrough on OpenAI-compatible upstreams |
| `messages`, `responses` | native-format inbound shims that translate down to the same hub shape as chat completions |
| `models` | **passthrough only**: the gateway forwards the upstream's native model-list body unchanged. Clients calling `/v1/models` through a non-OpenAI provider see the upstream's shape, not the OpenAI `{"object": "list", "data": [...]}` envelope |
| everything else | passthrough on the providers listed in the table; clients see the upstream's native response shape |

The Models passthrough decision is deliberate. OpenAI returns `{"object": "list", "data": [{"id": "...", "owned_by": "..."}]}`; Anthropic returns `{"data": [{"id": "...", "display_name": "..."}], "has_more": false}`; Google's `models.list` returns `{"models": [{"name": "models/...", "displayName": "..."}]}`. A lossy normalisation would conflate these and mislead clients about per-model metadata. Callers that need a unified shape across providers should consume the proxy's own model registry instead of the passthrough.

### Method coverage

The gateway accepts any standard HTTP method for any supported surface. GET, POST, PUT, DELETE, PATCH, HEAD, and OPTIONS all dispatch through the same provider-selection and observability surface. Methods other than GET/POST forward via `AiClient::forward_with_method` and do not engage the chat-completions body-parse pipeline (no JSON parsing, no budget enforcement, no input guardrails). Method-aware dispatch is what makes `DELETE /v1/assistants/{id}`, `POST /v1/threads/{id}/runs/{id}/cancel`, and the other non-POST verbs work end-to-end.

### Multipart bodies

Image edits, image variations, audio transcription, and audio translation send multipart request bodies. The proxy detects multipart by inspecting the inbound `Content-Type` header; when it starts with `multipart/`, the body is forwarded byte-for-byte via `AiClient::forward_bytes` with the original Content-Type preserved. Provider format translation (Anthropic, etc.) does not run for multipart, since these surfaces are OpenAI-only.

### Per-surface configuration

Per-surface knobs live under `per_surface_rate_limits` (see [Per-surface rate limits](#per-surface-rate-limits)) and apply automatically based on the classified surface. Surfaces have no dedicated YAML config block beyond that; they share the top-level `providers`, `routing`, `virtual_keys`, `budget`, `model_rate_limits`, `max_concurrent`, and `guardrails` settings.

### Surfaces marked enterprise-only

`reranking` is gated to ship dispatch in the enterprise build. In the OSS build the surface is classified (so observability still tags requests with `surface = "reranking"`) and the 501 gate fires unless an enterprise license check passes. The same surface label and matrix entry exist in both builds.

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

The validator and the schema-instruction builder are live functions; the wiring that calls them on every chat response is a runtime construct rather than a top-level YAML field. The YAML block above is the shape that ships when a runtime caller threads `StructuredOutputConfig` into the chat handler. Source: `crates/sbproxy-ai/src/structured_output.rs`.

## OpenAI surface-area modules

The `sbproxy-ai` crate ships shape definitions and lightweight handlers for the OpenAI surface beyond chat completions: assistants, threads, batch jobs, image generation, audio, fine-tuning, realtime sessions, and structured output. The shapes are stable and round-trip through `serde_json`; the chat-path router (`crates/sbproxy-ai/src/handler.rs:parse_ai_path` and `crates/sbproxy-ai/src/api_routes.rs:parse_endpoint`) recognises a subset (chat, embeddings, models, rerank, moderations, image generation, audio transcription, audio speech) and falls back to `Unknown` for the rest. The remaining shapes are present so plugin authors can build on top of them and so the action config surface is forward-compatible.

The subsections below describe what each module contributes today.

### `assistants`

Shape definitions for the OpenAI Assistants API. `AssistantHandler::route_request(path, method)` classifies a request into one of: `CreateAssistant`, `ListAssistants`, `GetAssistant(id)`, `CreateThread`, `CreateMessage(thread_id)`, `CreateRun(thread_id)`, `GetRun(thread_id, run_id)`, or `Unknown`. The optional `/v1` prefix is stripped before matching. `AssistantConfig { enabled: bool }` is the on/off shape.

```yaml
action:
  type: ai_proxy
  providers: [...]
  # Forward-compatible flag, recognised by the parser but not yet enforced.
  assistants:
    enabled: true
```

The router classifier is implemented; routing into the chat dispatcher is not yet wired in the OSS build. Use chat completions for assistant-style flows until the dispatcher lands. Source: `crates/sbproxy-ai/src/assistants.rs:AssistantHandler`.

### `threads`

In-memory `ThreadStore` for OpenAI-style threads and their messages. Stores `Thread { id, created_at, metadata }` and ordered `ThreadMessage { id, thread_id, role, content, created_at }`. The store is thread-safe (mutex-backed) and used by the assistants handler for local session continuity. There is no YAML field that selects a backing store today; the in-memory store is the only implementation. Source: `crates/sbproxy-ai/src/threads.rs:ThreadStore`.

### `batch`

`BatchJob` shape (id, status, created_at, completed_at, total_requests, completed_requests, failed_requests, metadata) plus a `BatchStore` trait with one implementation, `MemoryBatchStore`. Status lifecycle: `pending`, `in_progress`, `completed`, `failed`, `cancelled`. The store is wired by the runtime when a batch dispatcher is constructed; there is no top-level `batch:` YAML block. Source: `crates/sbproxy-ai/src/batch.rs`.

### `image`

Request and response shapes for image generation, edit, and variation. `ImageGenerationRequest { prompt, model, size, n }` and `ImageGenerationResponse { images: Vec<ImageData> }`, where each `ImageData` carries either a `url` or a base-64 `b64_json` payload depending on the provider's `response_format`. `/v1/images/generations` is routed by `api_routes.rs`; the per-call dispatch is built by the runtime. No dedicated YAML knobs. Source: `crates/sbproxy-ai/src/image.rs`.

### `audio`

Request and response shapes for audio transcription and speech synthesis. `TranscriptionRequest { file_url, model, language }`, `TranscriptionResponse { text, duration }`, and `SpeechRequest { input, model, voice }`. `/v1/audio/transcriptions` and `/v1/audio/speech` are recognised by `api_routes.rs`. No dedicated YAML knobs; the audio dispatcher reuses the top-level provider list and routing strategy. Source: `crates/sbproxy-ai/src/audio.rs`.

### `finetune`

Fine-tuning API classifier. `FinetuneHandler::route_request(path, method)` classifies into `CreateJob`, `ListJobs`, `GetJob(id)`, `CancelJob(id)`, `ListEvents(id)`, or `Unknown`, with the optional `/v1` prefix stripped. `FinetuneConfig { enabled: bool }` is the on/off shape.

```yaml
action:
  type: ai_proxy
  providers: [...]
  # Forward-compatible flag, recognised by the parser but not yet enforced.
  finetune:
    enabled: true
```

Like `assistants`, the classifier is implemented; routing into the chat dispatcher is not yet wired in the OSS build. Source: `crates/sbproxy-ai/src/finetune.rs:FinetuneHandler`.

### `realtime`

Shape definitions and config for OpenAI's Realtime websocket API. `RealtimeConfig { enabled, model }` defaults to `enabled: false` and `model: "gpt-4o-realtime-preview"`. `RealtimeSession { session_id, model, created_at, status }` and `RealtimeEvent { event_type, data }` round-trip through serde. The `/v1/realtime` websocket path is recognised by the proxy but session bridging requires a runtime-level dispatcher; the config shape above is the YAML form that the dispatcher reads.

```yaml
action:
  type: ai_proxy
  providers: [...]
  realtime:
    enabled: true
    model: gpt-4o-realtime-preview
```

Source: `crates/sbproxy-ai/src/realtime.rs`.

### `structured_output`

Already covered above under [Structured output](#structured-output). Shape and validator are live (`extract_json`, `validate_response`, `build_schema_instruction`); the wiring that runs the validator on every chat response is a runtime construct rather than a top-level YAML field. Source: `crates/sbproxy-ai/src/structured_output.rs`.

## Per-request attribution

The gateway records provider, model, token counts, and estimated cost for every AI request and exposes them through Prometheus metrics (see below). Direct response headers for these fields are not emitted today.

## Token usage metrics

The proxy exposes aggregate AI usage as Prometheus metrics. When `telemetry.bind_port` is configured, the following counters and gauges are available at `/metrics` under the `sbproxy_ai_*` namespace:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sbproxy_ai_requests_total` | Counter | `provider`, `model`, `status` | Total AI requests |
| `sbproxy_ai_surface_requests_total` | Counter | `surface`, `method` | Total AI requests partitioned by classified surface (chat completions, assistants, image generation, ...) and HTTP method |
| `sbproxy_ai_surface_request_duration_seconds` | Histogram | `surface`, `method` | Per-surface request latency. Buckets match `sbproxy_ai_request_duration_seconds` for side-by-side dashboards |
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
| `sbproxy_ai_realtime_sessions_active` | Gauge | | Currently open OpenAI Realtime API WebSocket sessions |
| `sbproxy_ai_realtime_session_duration_seconds` | Histogram | `provider`, `close_reason` | Wall-clock duration of a Realtime WebSocket session, observed at close. `close_reason` is `client_closed` or `error` |
| `sbproxy_ai_realtime_audio_seconds_total` | Counter | `provider`, `direction` | Cumulative audio seconds forwarded over Realtime sessions. Frame-exact accounting requires terminate-and-relay (not on the OSS path); the OSS dispatcher uses session wall-clock as a duration proxy on close |
| `sbproxy_ai_realtime_frames_forwarded_total` | Counter | `provider`, `direction`, `kind` | Cumulative frames forwarded over Realtime sessions (`kind` is `text` or `audio`). Reserved for a future enterprise terminate-and-relay path |

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

## Realtime

The AI gateway routes OpenAI Realtime API WebSocket sessions through the same dispatch path as the rest of the surface set. A client opens `GET /v1/realtime` with `Upgrade: websocket` against the proxy, the gateway runs its standard pre-upgrade gating, picks an enabled provider that supports Realtime (today: OpenAI), and lets Pingora forward bytes between the client and the provider after the `101 Switching Protocols` handshake.

What runs before the upgrade:
- Surface classification stamps `ai.surface = "realtime"` on the request span and the access log.
- The 501 capability gate fires if no configured provider supports Realtime.
- The per-surface rate limit (`per_surface_rate_limits.realtime`) fires before the upgrade is attempted, returning 429 when the cap is hit.
- The active-sessions gauge `sbproxy_ai_realtime_sessions_active` ticks up.

What runs during the session:
- Pingora forwards WebSocket frames byte-transparently. The proxy does not inspect individual frames (per-frame guardrails are not on the OSS path; they would require terminate-and-relay, which is reserved for an enterprise build).

What runs at session close (the `logging` hook):
- The active-sessions gauge ticks down.
- `sbproxy_ai_realtime_session_duration_seconds` records the wall-clock session lifetime.
- An `AiBillingEvent` fires with `usage = AudioSeconds { seconds = wall_clock }` so operators see realtime usage on the standard billing event bus. Cost is reported as 0.0 in OSS until the realtime rate card lands in the pricing helper; downstream consumers can compute cost from the duration.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          base_url: https://api.openai.com/v1
          models: [gpt-4o-realtime-preview]
      per_surface_rate_limits:
        realtime:
          requests_per_minute: 30
```

A client connects with the standard OpenAI Realtime URL, replacing the OpenAI host with the proxy host:

```python
import websocket  # websocket-client

ws = websocket.create_connection(
    "wss://ai.example.com/v1/realtime?model=gpt-4o-realtime-preview",
    header=[
        "Authorization: Bearer <virtual-key>",
        "OpenAI-Beta: realtime=v1",
    ],
)
```

The proxy enforces gating before the upgrade and emits a session-end billing event after close; per-frame inspection is reserved for an enterprise terminate-and-relay path that would land alongside a dedicated Pingora `Service` impl.

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

## Hot-reload behavior

A `SIGHUP`, an admin-API reload, or an in-place edit of `sb.yml` (when the file watcher is on) refreshes the AI gateway without restarting the proxy. The provider catalog under `proxy.ai_providers_file`, the live `AiClient`, and the compiled handler chain are rebuilt and swapped atomically; in-flight requests continue against their existing snapshot until they finish, and subsequent requests pick up the new state. Adding a provider, rotating a `default_base_url`, or fixing a typo in `ai_providers.yml` no longer requires shedding connections.

The process-wide AI budget tracker is deliberately left alone on reload. Budget windows are wall-clock-relative (daily, monthly, custom), so the per-scope token and cost accumulators must outlive a config reload. Wiping the tracker would silently roll counters back to zero and let already-spent budget through a second time. To clear a budget intentionally, restart the process or call the per-scope reset path on the admin surface.

## See also

- [providers.md](providers.md) - full provider table and per-provider model lists.
- [scripting.md](scripting.md) - CEL and Lua reference, including AI selector and guardrail variables.
- [configuration.md](configuration.md) - general configuration model, origin schema, and the full `sb.yml` field reference.
- [features.md](features.md) - higher-level overview of features including guardrails.
