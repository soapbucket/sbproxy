# SBproxy AI gateway guide

*Last modified: 2026-08-08*

![the same OpenAI-shape request answered by OpenAI, Claude, and Gemini, switched only by Host header](assets/ai-gateway.gif)

Three providers behind one wire format ([config](../examples/ai-gateway-quickstart/)).

SBproxy includes an AI gateway that sits between your application and LLM providers. You get one API endpoint with automatic failover, cost tracking, rate limits, and programmable routing across OpenAI, Anthropic, and other providers. The proxy ships with 72 native providers behind one OpenAI-compatible API. That count is worth unpacking: 66 of the 72 catalog entries speak the OpenAI wire format and pass through unchanged, 3 (Anthropic, Gemini, Bedrock) get in-tree request and response translation, and 3 custom-format entries (SageMaker, Oracle OCI, Watsonx) are forwarded in their native shape with no translation. You bring your own provider keys and the model name passes straight through, so you reach 200+ models without waiting on us to add them.

This guide owns the end-to-end picture: provider setup, wire compatibility, routing, streaming, budgets, caching, prompt controls, and per-request attribution. Coming from an agent framework? [langchain.md](langchain.md) is the shortest path: it points LangChain's model client and MCP tools at the gateway and runs a first request end to end. Seven features get a summary here and a full page of their own: the [guardrail mesh](ai-guardrail-mesh.md), [outcome-aware routing](ai-outcome-aware-routing.md), the [AI policy plane](ai-policy-cel.md), [budget soft-landing](ai-predictive-budget.md), the [verifiable usage ledger](ai-usage-ledger.md), [LLM-aware resilience](ai-llm-aware-resilience.md), and [AI context compression](ai-context-compression.md). For those seven, the linked page is canonical; it carries the semantics, tuning advice, and reference tables.

## Provider setup

Configure one or more providers under the `action` block. Each provider needs a name, API key, and model list. Callers of hosted providers should send an explicit `model`. A `default_model` can select among locally served models and appears in model metadata, but the hosted dynamic-routing path does not inject one into a request that omitted `model`:

**Fragment:** This is one `origins` entry; it needs a sibling top-level `proxy:` block (at minimum `proxy.http_bind_port`) to be a runnable `sb.yml`. See [Full example](#full-example) below or [`examples/ai-gateway-quickstart/`](../examples/ai-gateway-quickstart/) for a complete file.

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
          models: [claude-sonnet-4-20250514, claude-haiku-4-5]
      routing:
        strategy: round_robin
```

API keys support environment variable interpolation with `${VAR_NAME}` syntax. Never put raw keys in config files. `default_model` is a per-provider field, not an `action`-level one; an action-level `default_model` key is ignored. Context compression also requires the request's effective `model` to be non-empty, so hosted requests that omit it do not run the compression pipeline.

### Native providers
72 native providers ship in-tree. The split: 66 entries are OpenAI-format passthrough, 3 (Anthropic, Gemini, Bedrock) carry in-tree translators, and 3 custom-format entries (SageMaker, Oracle OCI, Watsonx) pass through untranslated, so clients must send those three their native body shape. You bring your own key per provider and the `model` field passes straight through, so the gateway reaches 200+ models (and any model a provider ships next) without enumerating them. Direct adapters include `openai`, `anthropic`, `gemini`, `azure`, `bedrock`, `cohere`, `mistral`, `groq`, `deepseek`, `together`, `fireworks`, `cerebras`, `sambanova`, `nvidia`, `vertex`, `databricks`, `huggingface`, `vllm`, and `openrouter`. For the AWS entries, SBproxy does not mint SigV4 signatures: `bedrock` and `sagemaker` requests must arrive with an operator-provided, pre-signed `Authorization` header, which the gateway forwards verbatim.

Any model a listed provider serves works without extra config. For a self-hosted or proprietary endpoint, point `vllm` or any provider at it with a custom `base_url`. `openrouter` is available as one of the providers when you want many vendors behind a single key. See `providers.md` for the full per-provider table.

### Managed local and cluster models

Use `provider_type: managed_model` to route a public model name to a deployment
owned by `proxy.model_host`:

**Fragment:** Nest under a top-level `proxy:` block that also configures `model_host`; see [model-host.md](model-host.md) and [`examples/model-host-managed/`](../examples/model-host-managed/) for a runnable pairing of both.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      routing: fallback_chain
      providers:
        - name: managed-qwen
          provider_type: managed_model
          deployment: local-qwen
          models: [qwen]
          default_model: qwen
        - name: openrouter
          api_key: ${OPENROUTER_API_KEY}
          models: [qwen]
```

The normal caller authentication, provider allowlist, model allowlist, policy,
budget, and routing stages run before managed replica selection. A ready
co-located replica uses the local fast path. A ready remote replica uses the
authenticated private HTTP/2 model plane. Public bearer credentials stop at
the gateway and are not sent to workers or engines.

Every AI origin serves `GET /v1/models` and `GET /models` locally as an
OpenAI-compatible logical list built from its configured eligible providers and
models. Managed entries report aggregate `ready`, `cold`, or `unavailable`
state, ready and desired replica counts, and bounded capability names. The list
omits worker identity, engine ports, and private endpoints. It does not call an
ordinary provider's native model-list endpoint or reproduce provider-specific
model metadata.

Successful completions add `x-sbproxy-logical-model` and an allowlisted
`x-sbproxy-route-class` of `local`, `peer`, or `external`. Managed availability
and cold-start failures that expose a public reason use an OpenAI-style
`managed_model_error` body with a stable code, request ID, retryable flag, and
`sbproxy_reason`. Other resolution, authentication, TLS, and transport failures
use the gateway's generic error path; private detail remains in bounded logs
and metrics. Replica failover is permitted only before client output. A partial
stream is never replayed on another worker, and client cancellation propagates
to the selected engine.

Deployment `cold_start` chooses how a no-ready-replica state behaves. `wait`
coordinates one bounded launch per selected replica generation, `reject`
returns a retryable `503` with
`Retry-After: 1`, and `fallback` advances to the next provider without
launching. For `authority: file_managed`, omission follows the security
profile: production mTLS clusters use `fallback`, while development and
single-process runtimes use `wait`. Admin-managed and cluster-authority
deployments must set `cold_start` explicitly.

## Model-based provider selection

Before the routing strategy runs, the proxy narrows the candidate providers to those that declare the requested model in their `models` list. With one model per provider you get a single OpenAI-compatible endpoint where the `model` field picks the vendor:

**Fragment:** This uses the same `origins` entry shape as [Provider setup](#provider-setup) above; nest it under `proxy:` to run it. This exact shape (three providers, one model each) is the base config in [`use-case-own-openrouter.md`](use-case-own-openrouter.md) and [`examples/use-case-own-openrouter/sb.yml`](../examples/use-case-own-openrouter/sb.yml).

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      routing:
        strategy: round_robin
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-haiku-4-5]
        - name: gemini
          api_key: ${GEMINI_API_KEY}
          models: [gemini-3.5-flash]
```

A request for `gpt-4o-mini` reaches OpenAI, one for `claude-haiku-4-5` reaches Anthropic, and so on, regardless of strategy. The rules:

- A provider with an **empty** `models` list is a wildcard and stays eligible for every model (point one provider, such as `openrouter`, at many vendors this way).
- If **no** provider declares the requested model, the model name passes straight through to the configured providers unchanged, so you still reach the 200+ models a provider serves without enumerating each one.
- When more than one provider qualifies (an enumerated match plus a wildcard, say), the `routing.strategy` below picks among them.

## Routing strategies

The `routing.strategy` field controls how the proxy picks a provider for each request, after model-based selection has narrowed the candidates.

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

### token_rate (refused)

`token_rate` ranks providers by remaining tokens-per-minute headroom against a declared per-provider limit, and no configuration field declares one. With every limit at zero the score reduces to observed usage alone, which is `least_token_usage` under a different name. A config that selects it is now refused at load rather than served as a strategy other than the one it asks for.

If you have `strategy: token_rate` today, `least_token_usage` is the strategy you have actually been getting; switching to it keeps your routing unchanged. For capacity-aware routing that scores real numbers, `headroom` and `reset_aware` read the rate-limit headers providers return.

### headroom

Routes to the provider with the lowest request-quota pressure from fresh
provider rate-limit headers (`1 - remaining/limit`). Ties keep enabled-list
order. Unknown or stale snapshots are advisory only: they sort after known
fresh observations and never invent a capacity guarantee. It scores what a
provider reports about itself, which is why it is the capacity-aware
strategy to reach for.

```yaml
routing:
  strategy: headroom
```

### reset_aware

Routes to the provider whose quota window resets soonest among candidates
waiting for positive capacity. Providers that already report remaining
capacity sort first. Unknown or stale signals sort last and do not invent
a reset time. `Retry-After` is accepted as delta-seconds or HTTP-date.

```yaml
routing:
  strategy: reset_aware
```

### race

![one request fanned out to every provider, the first 2xx returned and the slow racer canceled](assets/ai-race-routing.gif)

Lower tail latency at the cost of duplicate upstream calls ([config](../examples/ai-race-routing/)).

Fans the request out to every eligible provider in parallel, returns the first 2xx, cancels the in-flight losers. Optimizes p99 latency at the cost of N times the API spend per request. Pair with `resilience` so persistently slow providers fall out of the eligible set.

```yaml
routing:
  strategy: race
```

See [examples/ai-race](../examples/ai-race/sb.yml). Billing implications, streaming behavior, and the interaction with the failover loop are in [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md#hedged-raced-requests).

### least_token_usage

Routes to the provider with the lowest absolute observed token throughput in
the current 60-second window, regardless of any configured limit. It scores
raw observed throughput rather than headroom against a declared cap, so it
suits self-hosted vLLM or SGLang pools that do not pre-declare a token cap,
and it is the strategy `token_rate` collapsed into. Untried providers sort lowest
and are explored first. The same recent-token state breaks ties for
`prefix_affinity`.

```yaml
routing:
  strategy: least_token_usage
```

### prefix_affinity

Routes a repeated prompt prefix to a provider that has already accepted that
prefix, so a vLLM or SGLang replica can reuse its local KV cache. This is
observed affinity, not a hash assignment. On the first request for a prefix,
the router picks the eligible provider with the lowest recent token load and
records that provider as a holder only after it accepts the response. A live
holder wins on later turns. When there is no live holder, recent token load
chooses the fallback provider; exact load ties rotate with round-robin.

```yaml
routing:
  strategy: prefix_affinity
  ttl_secs: 300
  max_prefixes_per_provider: 1024
```

The default TTL is five minutes and the default capacity is 1,024 prefixes per
provider. Expired entries and least-recently-used entries beyond the capacity
are removed. Disabled or credential-ineligible providers are never selected,
even if they hold the prefix.

The affinity identity comes from the translated hub request. It includes
leading `system` and `developer` messages plus the first `user` message, and
ignores later conversation turns. The normalizer preserves roles, content,
part order, whitespace, case, and Unicode, canonicalizes JSON object keys, and
caps the canonical input at a valid UTF-8 boundary before hashing it. The
resolved model or deployment is part of the namespace, so incompatible caches
do not share an identity. A request without a usable first user message falls
back to the least-loaded eligible provider.

Prefix locations are deliberately process-local. Each gateway replica learns
its own bounded directory; locations are not looked up through the cluster
mesh. This keeps remote cluster latency out of every routing decision. Use
`sbproxy_ai_prefix_affinity_decisions_total{outcome}` to distinguish hits,
misses, and missing signals, and
`sbproxy_ai_prefix_affinity_evictions_total{reason}` to see TTL and capacity
evictions.

### peak_ewma

Power-of-two-choices over time-decayed latency and current in-flight load:
sample two eligible providers and route to the lower effective cost. A latency
spike takes effect immediately and decays toward the pool's neutral latency.
After one configured half-life without a completed attempt, the provider
re-enters at neutral cost so it can prove recovery. In-flight requests multiply
the cost, so a provider that has just started queueing is deprioritized before
a slow response completes. Providers without observations use the same nonzero
pool-neutral score.

```yaml
routing:
  strategy: peak_ewma
  half_life: 10s
```

The default half-life is `10s`. Set `half_life` as integer seconds or a
human-readable duration such as `10s`. Shorter values react and recover faster;
longer values retain spike penalties longer. Provider eligibility and
power-of-two candidate sampling are unchanged.

### cascade

Tries a sequence of `(provider, model)` tiers from cheapest to most expensive. Each tier's response is graded against its `quality_threshold`; a response that is below threshold, empty, or refused retries on the next tier. `max_total_cost` (micro-USD) is an optional cumulative budget cap. Streaming requests dispatch only to the first tier.

```yaml
routing:
  strategy: cascade
  max_total_cost: 100000
  tiers:
    - provider_id: openai
      model: gpt-4o-mini
      quality_threshold: 0.7
    - provider_id: openai
      model: gpt-4o
      quality_threshold: 0.85
```

See [examples/ai-cascade-routing](../examples/ai-cascade-routing/sb.yml).

### cost_quality

Scores each prompt's difficulty and routes simple prompts to a cheap model and hard prompts to a frontier model, on a single `cost_threshold` dial (`0.0` sends almost everything to the frontier, `1.0` sends almost everything to the cheap model).

```yaml
routing:
  strategy: cost_quality
  cheap_provider: openai-mini
  frontier_provider: openai
  cost_threshold: 0.5
```

### outcome_aware

Scores each provider by realized cost per successful request, learned from the gateway's own completed calls. A provider whose refusal or error rate is rising gets demoted; between two healthy providers, the one with the lower realized cost-per-success wins, which is not always the lower list price. Until every provider has a few samples the strategy round-robins, so enabling it on a fresh deployment is safe.

```yaml
routing: outcome_aware
```

The strategy blends learned picks with deterministic round-robin during
warm-up instead of waiting for a hard threshold. The scoring formula,
confidence schedule, and feedback lifetime are in
[ai-outcome-aware-routing.md](ai-outcome-aware-routing.md).

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

Each signal also recovers on its own terms, and none of them writes to another. A breaker admits a probe once `open_duration_secs` has passed and closes after `success_threshold` probes succeed. An outlier ejection lapses after `ejection_duration_secs`. A probe verdict flips back after `healthy_threshold` consecutive passes, whether or not the provider is receiving traffic. A provider that failed on two signals returns when both have cleared, and no signal can hold it out on another's behalf.

See [examples/ai-resilience](../examples/ai-resilience/sb.yml). Field reference in [configuration.md#resilience-resilience](configuration.md#resilience-resilience).

### LLM-aware resilience

Status-code retries treat every failure the same. The gateway can instead classify each upstream failure into a typed cause (rate limit, context-window overflow, content-policy refusal, auth, malformed request) and apply a retry count per class, so a transient failure retries while a request that would only fail again goes to a fallback. Switch it on with a `retry_policy` under `resilience`:

```yaml
resilience:
  retry_policy:
    rate_limit: 3      # retry a 429 up to 3 times
    server_error: 2
    content_policy: 0  # never retry a refusal in place
```

The same block hosts the legacy `llm_aware.context_compress` shorthand, which maps to stateless `window_fit` when no explicit compression policy is present, and `content_policy_fallback`, which routes a refusal to the next provider in priority order. The failure-cause table and hedged-request behavior are in [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md). Ordered summary, query selection, token pruning, retrieval shaping, and final fitting are documented in [AI context compression](ai-context-compression.md).

## Shadow eval

Mirror a sampled set of non-streaming chat evaluation requests to a second provider. V1 includes Chat Completions plus Messages and Responses requests after those native formats are normalized to the chat hub. Mutating and non-chat surfaces, including Assistants, Threads, Batches, Fine Tuning, Files, images, audio, embeddings, moderation, and reranking, are never copied. The copy is taken after request policy, guardrails, model rewrites, and context compression. Shadow admission is bounded by both 16 in-flight tasks and a 64 MiB reservation budget per live AI client, and the upstream call is fire-and-forget: a slow, failed, timed-out, policy-disallowed, or saturated shadow never delays or rejects the primary. Streaming requests are intentionally skipped.

When a fair-share quota pool is enabled, a sampled shadow copy reserves its
own request unit after the local shadow gates and commits it only at the
background send boundary. A quota denial suppresses only the optional copy;
it never replaces or delays the primary response.

The shadow body is drained while at most 1 MiB is retained for comparison metadata, which is logged at `target=sbproxy_ai_shadow` (status, latency, prompt/completion tokens, finish reason). Configured usage sinks also receive a separate row with `tag: shadow` and a fresh server-generated request ID ending in `:shadow`. That row estimates shadow cost for comparison, but it never debits the primary budget tracker.

```yaml
shadow:
  provider: anthropic
  sample_rate: 0.1
  timeout_ms: 30000
  task_timeout_ms: 30000
```

The shadow provider must appear in `providers`. Set `enabled: false` on a shadow-only provider to exclude it from primary routing; explicit shadow selection still uses it. Credential `allowed_providers` and `blocked_providers` rules apply to it independently; a disallowed shadow is suppressed while the primary continues. The `x-sbproxy-disallow-prompt-training` opt-out also suppresses a shadow provider unless it declares `no_prompt_training: true`. If the hosting process attaches a purpose-scoped egress authorizer to `AiClient`, v1 shadow dispatch fails closed because the shadow transport cannot yet consume authorized DNS pins and redirect checks. `sbproxy_ai_shadow_dropped_total{reason=...}` reports the closed skip/drop reasons `streaming`, `provider_not_found`, `provider_not_allowed`, `prompt_training_disallowed`, `egress_denied`, and `saturated`. Deliberate sample misses are not failures and do not increment that counter.

See [examples/ai-shadow](../examples/ai-shadow/sb.yml).

## Proxy-native AI patterns

SBproxy is a proxy first, so AI traffic composes with everything else the proxy offers: CEL policies, forward rules, regex guardrails, request modifiers. Patterns that are awkward or impossible to express in a pure AI gateway library:

| Pattern | Mechanism | Example |
|---------|-----------|---------|
| Tenant access control before any AI call | `policies` (CEL expression) | [93-ai-cel-tenant-gate](../examples/ai-cel-tenant-gate/sb.yml) |
| Mixed AI + non-AI on one hostname (health probes, docs, model catalog) | `forward_rules` with inline child origins | [94-ai-mixed-traffic](../examples/ai-mixed-traffic/sb.yml) |
| Custom DLP beyond built-in PII (codenames, ticket IDs, internal hostnames) | `guardrails.input` with `regex` patterns | [95-ai-regex-dlp](../examples/ai-regex-dlp/sb.yml) |
| Topic enforcement (allow-list of approved keywords) | `regex` guardrail with `action: allow` | [95-ai-regex-dlp](../examples/ai-regex-dlp/sb.yml) |

![a benign prompt passing while one naming the internal codename Project Bluebird is blocked before egress](assets/ai-regex-dlp.gif)

Regex DLP rules run in the guardrail stage, so the rejection costs no tokens ([config](../examples/ai-regex-dlp/)).

CEL policies and request modifiers run before the AI handler dispatches, so a rejection costs no provider tokens. Forward rules dispatch by path, which means health checks and probe traffic can stay on the same hostname without billing a model. Regex guardrails inspect the parsed prompt body and slot in next to PII, injection, jailbreak, and schema guardrails.

## Native format translation

Clients always speak the OpenAI chat completions shape; sbproxy rewrites the body, path, and response back to OpenAI shape when the upstream provider speaks a different protocol.

| Provider format | Direction | Status |
|-----------------|-----------|--------|
| OpenAI | pass-through | always |
| Anthropic Messages API | bidirectional, non-streaming | shipped |
| Anthropic SSE events | native stream to hub stream | shipped |
| Google Gemini `generateContent` | bidirectional, non-streaming | shipped |
| Google Gemini `streamGenerateContent` | native stream to hub stream | shipped |
| Google Gemini embeddings | bidirectional `/v1/embeddings` | shipped |
| AWS Bedrock Converse | bidirectional, non-streaming | shipped |
| AWS Bedrock Converse stream | native stream to hub stream | shipped |

For Anthropic, the request hoists `system` role messages to the top-level `system` field, defaults `max_tokens` when missing, strips OpenAI-only knobs (`logit_bias`, `n`, `presence_penalty`, `frequency_penalty`, `response_format`, `seed`, `user`), and rewrites the path from `/v1/chat/completions` to `/v1/messages`. The response converts text and tool_use blocks back into the OpenAI `choices[].message.content` and `tool_calls` shape, maps `stop_reason` to `finish_reason`, and renames `usage.input_tokens` / `output_tokens` to `prompt_tokens` / `completion_tokens`.

For Gemini, chat completions are rewritten to `generateContent`: roles become Gemini `contents`, system messages become `systemInstruction`, sampling options move under `generationConfig`, and Gemini candidates plus `usageMetadata` are converted back into OpenAI choices and usage. Gemini embeddings translate OpenAI `/v1/embeddings` requests to Gemini embedding calls and normalize the response back to OpenAI embedding objects.

For Bedrock, chat completions are rewritten to the model-agnostic Converse API. System messages become Bedrock `system` entries, user and assistant turns become `messages`, supported sampling and tool fields move into Bedrock's native request shape, and Converse responses are converted back to OpenAI choices and usage. Bedrock and SageMaker SigV4 signing is still operator-provided; SBproxy forwards the signed `Authorization` header rather than minting AWS signatures itself.

For streaming responses, the relay parses native Anthropic, Gemini, and Bedrock frames into the internal hub stream, then re-emits the client-facing format selected by the inbound route. Oracle OCI, Watsonx, SageMaker, and other `Custom` formats are not translated in-tree; send their native body shape or route through a custom/OpenRouter adapter.

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

### Fair-share quota pools

An AI action can reserve every upstream attempt against a weighted request
pool. Pool members are immutable virtual-key or API-key ids from the resolved
request principal, not provider names. Use the credential's immutable public
`key_id` in `weights`; a mutable display `name` is never an accounting key.
Only traffic on an origin with no authentication or explicit `noop`
authentication uses the literal `__anonymous__` member. A request accepted by
Bearer, forward-auth, plugin, or another authentication provider without an
immutable key id fails closed when a quota pool is enabled; add `key_id` to
legacy inline credentials before enabling the pool. Every admitted identity
must appear in `weights`; an unknown member is denied instead of borrowing
another member's share.

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
    - name: anthropic
      api_key: ${ANTHROPIC_API_KEY}
  quota_pool:
    name: shared-agents
    window: 1m
    total_limit: 120
    weights:
      team-a: 3
      team-b: 1
    policy: hard
    dimension: request
    consistency: local
    failure_mode: closed
```

`local` is the dependency-free default. `approximate` reuses the installed
approximate governance store and its cluster-mesh dissemination. `strong`
reuses the installed strict Redis governance store for atomic cross-process
admission. A shared pool's consistency must match
`proxy.key_management.governance.consistency`: quota `approximate` pairs with
governance `approximate`, while quota `strong` pairs with governance `strict`.
See [Governed admission: strict and approximate](key-management.md#governed-admission-strict-and-approximate)
for the mesh and Redis configuration.

The policies have these admission guarantees:

| Policy | Behavior |
| --- | --- |
| `hard` | Enforces both the aggregate limit and each member's weighted entitlement. |
| `soft` | Enforces the aggregate limit, admits over-entitlement use while capacity remains, and meters the over-share. |
| `burst` | Lets a busy member borrow idle aggregate capacity while preserving the pool total. |

Each failover or retry is a separate upstream attempt and receives its own
reservation. Failures before dispatch release the reservation; once an
attempt can leave the process it is committed even if the upstream later
returns an error. A real policy denial returns `429` and never fails open.

Shared-backend failure defaults to `failure_mode: closed`, which returns `503`
before dispatch. `allow_unreserved` admits an attempt only when the backend is
unavailable; it does not bypass a real quota denial. Every such admission
increments `sbproxy_ai_quota_pool_fail_open_total{pool}`.

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

The sliding window is one minute, shared across all configured origins
(state is process-global). Realtime runs configured hard-budget admission
before its WebSocket upgrade, but the byte-transparent relay does not inspect
or charge individual frames. Frame-derived audio or token caps therefore
remain unavailable.

## Guardrails

![a prompt-injection attempt and an SSN-bearing prompt both rejected before any provider is contacted](assets/ai-guardrails.gif)

Input guardrails inspect the parsed prompt ahead of egress ([config](../examples/ai-guardrails/)).

The built-in pipeline supports ten guardrail types: `pii`, `injection`, `jailbreak`, `toxicity`, `content_safety`, `schema`, `regex`, `context_poisoning`, `agent_alignment`, and `classifier`. Built-in guardrails run on input (before the provider call) or output (after), and they can block, flag, or rewrite content. For HTTP policy services, use [external guardrail adapters](guardrails.md). For CEL-based request gating see the CEL section below, and [configuration.md](configuration.md#guardrails-guardrails) for the per-type field schema.

An external guardrail entry carries two independent settings that are easy to confuse. `mode` picks when the adapter runs and, in the `logging_only` case, says it must never refuse; that is the enforcement axis. `failure_posture` says what happens when the adapter cannot be reached, is too slow, or returns something that is not a verdict; that is the failure axis. They compose: a guardrail can sit in `mode: logging_only` during rollout while already declaring `failure_posture: closed` for the day it starts enforcing. Accepted values are `closed` (refuse, the default), `open` (admit), and `degraded` (admit, and record that the content was never scanned; prefer this over `open`). `observe` is rejected on this axis, because a provider that never answered leaves no verdict to shadow-record; `mode: logging_only` is the observe-shaped setting, on the other axis. The older boolean spelling `fail_open: true|false` still parses and still means `open` and `closed`; setting both to values that disagree is a config-load error naming both keys. Field reference and the per-provider contracts are in [guardrails.md](guardrails.md).

Input guardrails apply to whichever body field the surface carries user text in:

| Surface | Field guarded |
|---|---|
| `chat_completions`, `assistants`, `threads` | `body["messages"][].content` |
| `image_generation`, `image_edits`, `image_variations` | `body["prompt"]` |
| `audio_speech` | `body["input"]` |
| `reranking` | `body["query"]` |
| `moderations` | `body["input"]` |

A single built-in guardrail block on the AI handler config covers every supported surface; the proxy picks the right field automatically based on the classified surface. Multipart-bodied surfaces (image edits, image variations, audio transcription) bypass the built-in input check today because their bodies are forwarded byte-transparently; built-in output scanning for those surfaces is reserved for a follow-up. External adapters apply their documented [unavailable-content policy](guardrails.md#streaming-and-multipart-content) to multipart bodies.

### Gateway-side retrieval (RAG)

An `ai_proxy` route can carry a `rag:` block that makes the gateway perform retrieval itself: it embeds the request's query, runs a tenant-scoped search against a configured vector store, and injects the retrieved chunks as marked system context before dispatch. The stage order is fixed: input guardrails run over the original request, then retrieval, then context injection, then the input guardrails run again over the augmented request, and only then do the AI policy plane, budgets, caching, and routing proceed. Retrieved text therefore gets the same screening as user text, and a prompt the original pass rejects never causes embedding egress. Field reference, failure policy, limits, build features, and metrics are in [rag.md](rag.md); the runnable fixture walkthrough is [`examples/ai-rag-local/`](../examples/ai-rag-local/). The optional `use_stale` retrieval cache is in-memory and per route, and it deliberately has no admin listing or purge endpoint; restarting or reloading the process is what clears it.

### Safety guardrail modes

`toxicity`, `jailbreak`, and `content_safety` each have two explicit modes.
`mode: keyword` is the default and preserves the zero-dependency behavior:
case-insensitive substring matching over operator-supplied words or the
built-in jailbreak/content-safety lists. Keyword mode is fast and requires no
model files, but it does not understand paraphrases, obfuscation, translation,
or meaning. Do not describe it as ML classification.

`mode: classifier` uses the local embedding classifier and is enforcing. It
does not silently fall back to keyword matching. Structural errors such as a
missing classifier block, unknown taxonomy class, or ignored keyword-only
field make the candidate configuration fail before publication. Startup and
reload construct enforcing safety classifiers before publishing the pipeline.
If either artifact is unavailable or its digest does not match the centroid
pin, boot or reload fails with a configuration error; keyword matching is
never substituted.

```yaml
guardrails:
  input:
    - type: jailbreak
      mode: classifier
      classifier:
        backend:
          kind: embedding
          model_path: /var/lib/sbproxy/models/minilm/model.onnx
          tokenizer_path: /var/lib/sbproxy/models/minilm/tokenizer.json
        scope: last_user_message
        max_chars: 2000
```

The class sets are closed and intentionally separate:

| Guardrail | Required classifier classes | Blocked classes |
|---|---|---|
| `toxicity` | `toxic`, `safe` | `toxic` |
| `jailbreak` | `jailbreak`, `safe` | `jailbreak` |
| `content_safety` | `violence`, `self_harm`, `sexual`, `hate_speech`, `illegal`, `safe` | the nonempty `blocked_categories` selection |

The three enforcing taxonomies ship versioned, precomputed centroids, so
`classes` is optional. Operator examples under a known class extend its
shipped centroid instead of replacing it. The artifact pins
`sentence-transformers/all-MiniLM-L6-v2` at revision
`5641a7880f40ebf4035d05e60c5f9b7a9c272c84`, its ONNX and tokenizer SHA-256
digests, and the artifact's own detached SHA-256. Any mismatch is a hard
configuration error. Omitted thresholds use the calibrated artifact values;
explicit threshold fields remain available for operator tuning. The measured
precision and recall, fixtures, method, false-positive budget, and
regeneration command are recorded in
[the default centroid evaluation](ai-default-centroids-evaluation.md).
Run `scripts/regenerate-default-safety-centroids.sh --write` with the pinned
model available locally to rebuild the vectors and report. CI-style freshness
checks use the same script with `--check`.

Classifier entries that resolve to the same artifacts share one loaded
embedder. Input classification defaults to the last user message;
set `scope: full_text` to classify the complete prompt. Output classification
always sees the complete assistant text, extracted from OpenAI Chat, Anthropic
Messages, or OpenAI Responses envelopes using the same concatenation as
decoded streaming deltas. An explicit `scope: last_user_message` is therefore
rejected under `output:`.

Classifier-backed output checks default to `stream_policy: close`. For a
non-streaming response this blocks before the response is returned. For a
streaming response the relay holds every response-body frame until it evaluates
the accumulated assistant text at stream close. A clean verdict releases the
original frames in order. A blocked verdict, classifier error, decode failure,
or 1 MiB decoded-text or relay-buffer overflow fails closed without releasing
body bytes and prevents cache admission. Response headers may already have
been sent, so a blocked client sees an empty terminated stream rather than a
new error status. Use `stream_policy: off` only as an explicit coverage
tradeoff; `stream_policy: chunk` is rejected because a full-text classifier is
not prefix-stable.

Every evaluation increments
`sbproxy_ai_safety_guardrail_verdicts_total{guardrail,class,backend,verdict}`.
The `backend` label distinguishes `keyword` from `classifier`, so dashboards
can verify which path is actually active. This is an evaluation counter, not
a request counter: streaming keyword mode can record more than one allowed
evaluation while successive deltas are scanned. Classifier inference errors
use `class="error"` and `verdict="block"`; they are never counted or cached as
allows. The complete enforcing example is
[ai-safety-classifiers](../examples/ai-safety-classifiers/).

### Embedding classifier

The input-only `classifier` guardrail labels a prompt with the nearest
operator-defined class. It runs a local sentence-embedding model, embeds each
configured example once when the guardrail is built, averages those vectors
into one unit centroid per class, and compares each request with cosine
similarity. A class wins only when it clears both `min_score` and the
`min_margin` over the runner-up.

```yaml
guardrails:
  input:
    - type: classifier
      backend:
        kind: embedding
        model_path: /var/lib/sbproxy/models/minilm/model.onnx
        tokenizer_path: /var/lib/sbproxy/models/minilm/tokenizer.json
        min_score: 0.30
        min_margin: 0.05
        max_model_bytes: 209715200
      classes:
        documentation:
          - "write the readme"
          - "prepare an upgrade guide"
        coding:
          - "implement the parser"
          - "fix the request handler"
      scope: last_user_message
      max_chars: 2000
```

Classifier output is a non-enforcing routing label, separate from security
guardrail block verdicts. The winning class appears in
`ai.guardrails.labels` in both the serial and mesh paths, where an `ai_policy`
expression can select `route_to:<model>`. A classifier label never contributes
to the mesh's `flagged_count`, block quorum, or redaction decision. Putting
`classifier` under `output:` is a hard config error because the backend needs
message scope and cannot safely classify streaming response chunks.

Classifier configuration fails before publication when it contains unknown
fields, blank artifact paths or labels, a class without a nonblank example, or
non-finite/out-of-range score thresholds. `max_chars` is a Unicode-character
limit for both request subjects and configured centroid examples; an example
over the limit is rejected rather than silently embedding an unbounded string.

The released binary includes `inprocess-classify`. Source builds that disable
default features must enable it explicitly. Model and tokenizer files remain
operator-supplied. For the routing-only `classifier` guardrail, artifacts are
opened lazily and a load or inference failure emits a warning and no class, so
existing routing continues and neighboring security guardrails remain active.
Classifier-backed safety guardrails are constructed during startup or reload;
an artifact load or digest failure rejects the candidate pipeline, and a later
inference failure produces a fail-closed block.

The public JSON schema deliberately leaves `action` as raw JSON so the module
registry can accept built-in and external actions without regenerating one
union for every plugin. It therefore cannot enumerate the nested classifier
fields in editor completion. The field table in
[configuration.md](configuration.md#classifier-input-guardrail) is the
normative public schema, and the AI action compiler validates the tagged
backend shape when it builds the pipeline.

Internally, `sbproxy-ai` owns the `TextClassifier` trait and config shape,
while `sbproxy-core` installs the ONNX implementation. That split is
intentional: `sbproxy-classifiers` already depends on `sbproxy-ai`, so naming
its `OnnxEmbedder` directly inside `sbproxy-ai` would create a crate cycle.
Classifier entries share one loaded embedder when the resolved artifact paths
and digests match and each entry's model-size limit accepts the current file.
Replacing either file at the same path invalidates reuse on reload.

The runnable configuration is
[ai-classifier-routing](../examples/ai-classifier-routing/).

### Guardrail mesh

By default the input guardrails run as a serial chain that blocks on the first security detector to flag. The opt-in mesh runs them as a cascade instead, collects security verdicts plus routing labels, and fuses the security verdicts under a quorum rule, with optional redact-and-continue, a verdict cache, and a latency budget for the expensive classifiers. Switch it on with a `mesh` block under `guardrails`:

```yaml
guardrails:
  input:
    - type: injection
    - type: pii
      patterns: [email]
  mesh:
    block_threshold: 2     # block only when >= 2 detectors flag
    redact_on_flag: true   # below the threshold, mask the prompt and continue
```

Fusion semantics, verdict-cache keying, and the latency cascade are in [ai-guardrail-mesh.md](ai-guardrail-mesh.md).

### Streaming policy

Every built-in output guardrail runs on streaming responses, and the verdicts match what the buffered path would decide for the same assistant text. The proxy decodes each streamed delta (the JSON content, not the raw SSE frame bytes) and feeds it to a per-stream guardrail session that keeps matcher state across chunks, so a pattern split across two deltas still matches.

| Guardrail | On streaming output | How |
|---|---|---|
| `regex` | yes | runs per decoded delta; set `stream_policy: close` when a pattern must span delta boundaries |
| `pii` | yes | runs per decoded delta |
| `schema` | yes | the complete accumulated response is validated once, at stream close; per-delta evaluation never runs because an intermediate delta is incomplete JSON |
| `context_poisoning` | yes | rule matches are per-message |
| `injection` | yes | case-insensitive substring set, matched over a cumulative window |
| `toxicity` | yes | keyword mode matches over a cumulative window; classifier mode holds body frames for full-response evaluation at close |
| `jailbreak` | yes | keyword mode includes the standalone-DAN word rule and a cumulative window; classifier mode holds body frames for full-response evaluation at close |
| `content_safety` | yes | keyword mode matches category terms over a cumulative window; classifier mode holds body frames for full-response evaluation at close |
| `agent_alignment` | yes | streamed `tool_calls` deltas are assembled per call and judged when each call completes; block mode holds tool-call frames back until their call is judged, while text deltas flow |

A block terminates the stream and the response is never admitted to any cache. Live keyword and chunk-policy guards can only withhold the violating chunk and everything after it. Classifier-backed close-policy guards hold the entire response body, so a block releases no body bytes. Headers may already be sent, so the client sees the stream terminate rather than receive a new error status. Input guardrails always run against the full request regardless of `stream`.

Each output entry takes an optional `stream_policy` when the default live evaluation is not what you want:

```yaml
guardrails:
  output:
    - type: toxicity
      keywords: [badword]          # default: evaluated live as deltas arrive
    - type: regex
      patterns: ["(?s)BEGIN.*END"] # spans deltas: check the full text at stream end
      stream_policy: close
    - type: content_safety
      blocked_categories: [violence]
      stream_policy: "off"         # never evaluated on streaming responses
```

`close` defers the check to stream end over the accumulated text. Mid-stream bytes have already reached the client by then, so its guarantees are the recorded verdict, the violation metric, and cache denial, not recall of delivered content. `off` skips the guardrail on streaming responses entirely and increments `sbproxy_ai_stream_guardrail_skipped_total` so the coverage gap stays visible. Violations under any policy increment `sbproxy_ai_stream_guardrail_violations_total`.

`schema` entries default to `stream_policy: close` and reject an explicit `chunk`, for the same reason classifier-mode entries do: the verdict is only meaningful over the complete result. A schema block on a streaming response is therefore a close-time verdict with the close-policy guarantees above; it does not hold body frames back, so it cannot recall bytes the client already received.

### Schema guardrail

`type: schema` on the output side enforces that the model produced structured output matching a JSON Schema ([config](../examples/ai-guardrails/)):

```yaml
guardrails:
  output:
    - type: schema
      schema:
        type: object
        required: [summary, tags]
        properties:
          summary:
            type: string
          tags:
            type: array
```

The schema compiles once, when the configuration is published, and the full compiled schema is enforced on every response: property types, nested `required`, `additionalProperties`, array constraints, `enum` and `const`, numeric and string bounds, and `allOf` / `anyOf` / `oneOf` / `not` composition. In-document `#/...` references resolve. A configuration whose schema is missing, invalid, larger than 64 KiB serialized, nested deeper than 32 levels, or carrying an external `$ref` fails to load with an error naming the problem. Remote reference fetching is disabled outright, the same SSRF posture as the `json_schema` transform and the OpenAPI validator.

The guardrail judges the assistant payload, not the transport envelope. For OpenAI Chat responses that is `choices[].message.content` (multiple choices concatenate in index order), for OpenAI Responses it is the assistant message output items, and for Anthropic Messages it is the text content blocks. This is the same canonical extraction the classifier-backed output guardrails use, so a route that translates between provider formats validates the same payload on every surface. The extracted text is parsed as JSON before validation; when the schema's top-level `type` is exactly `string`, the text is validated directly as a string instance instead. A response the gateway cannot map to an assistant payload fails closed with a `schema` block: an unrecognized response shape, a tool-call-only turn with no content, or a body that is not valid UTF-8.

A block reports the failing JSON path and the schema keyword in the form `Schema validation failed at /summary (keyword: type)`. The offending value never appears in the error, because it is model output that would otherwise be relayed into the client-visible error body. Missing `required` property names are the one exception; those names come from the operator's schema, not from the response.

### Context-poisoning guardrail

![a clean tool result summarized normally, then a tool result carrying an embedded instruction blocked](assets/ai-context-poisoning.gif)

The guardrail scans tool and retrieval content, not just the user turn ([config](../examples/ai-context-poisoning/)).

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

The rule catalog covers four families:

| Family | Sample rule IDs | Detects |
|---|---|---|
| Instruction-like patterns | `cp_instruction_ignore_previous`, `cp_instruction_you_are_now`, `cp_instruction_system_prompt_leak`, `cp_suspicious_url` | "ignore previous instructions" style payloads, role-swap framings, exfiltration URL shapes |
| Tool-call hints | `cp_tool_call_scaffold`, `cp_tool_call_json_shape` | Literal `<tool_use>`, `function_call:`, or JSON tool invocations inside passive content |
| Encoded instructions | `cp_encoded_instruction` | Base64 and hex blobs that decode to instruction-like text |
| Conflicting directives | `cp_conflicting_directive`, `cp_instruction_imperative_regex` | Imperative second-person language in `role: tool` or `role: function` content |

Every hit emits `sbproxy_ai_context_poisoning_findings_total{rule_id, action}`. When `action: deny`, the request is also counted in `sbproxy_ai_context_poisoning_blocked_total` and the proxy returns a 4xx before any upstream call. `action: log` and `action: score` keep the request flowing; they differ only in the metric label so dashboards can separate observability volume from scoring volume.

See `examples/ai-context-poisoning/` for a complete sample configuration and curl commands.

### Agent-alignment guardrail

![a search tool call matching the user's ask allowed, then an off-task delete_account call stopped](assets/ai-agent-alignment.gif)

The guardrail compares each tool call against the stated user goal ([config](../examples/ai-agent-alignment/)).

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

`mode: flag` records every violation as a log line + access-log entry but lets the request through; once the operator has tuned the rule lists they flip to `mode: block` so the dispatch loop short-circuits to a 400 on the next violation. Tool calls in any of three shapes are recognized: OpenAI (`tool_calls[*].function.name` + `function.arguments`), Anthropic (`tool_calls[*].name` + `input`), and MCP (`tool_calls[*].tool` or `tool_calls[*].name` + `arguments`). The forbidden-substring scan is case-insensitive against the JSON encoding of whichever argument field is present.

See `examples/ai-agent-alignment/` for a runnable configuration that exercises every rule.

## Lua hooks

Lua request modifiers run on AI origins the same way they do on plain proxy origins: an entry in the `request_modifiers` list carries a `lua_script` that defines `modify_request(req, ctx)` and returns headers to set. Scripts run in a sandboxed VM with wall-clock and memory budgets; see [scripting.md](scripting.md) for the full contract.

Note that a header set from Lua does not steer AI provider selection; the gateway picks a provider from the requested model and the `routing.strategy`. Use Lua for tagging and classification, and model-based selection for routing:

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
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514]
      routing:
        strategy: round_robin
    request_modifiers:
      - lua_script: |
          function modify_request(req, ctx)
            local caller = "human"
            local ua = req.headers["user-agent"] or ""
            if string.find(ua, "python") or string.find(ua, "node") then
              caller = "sdk"
            end
            return {
              set_headers = { ["X-Caller-Kind"] = caller }
            }
          end
```

## CEL request gating

Block AI requests with a CEL `expression` policy. The expression returns a boolean; `false` denies the request with the configured `deny_status` and `deny_message`. There is no `cel:` key under `request_modifiers`.

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
      - type: expression
        expression: 'request.headers["x-department"] != ""'
        deny_status: 403
        deny_message: "requests must carry an x-department header"
```

For CEL over the AI pipeline's own signals (surface, guardrail verdicts, budget state), use the AI policy plane below.

## AI policy plane (CEL)

Where CEL guardrails and request modifiers act on the raw HTTP request, the AI policy plane is one sandboxed CEL expression over the signals the AI pipeline itself computes: `ai.surface`, `ai.principal.*`, `ai.guardrails.*`, `ai.budget.*`, `ai.tokens.*`. It runs after guardrail evaluation and before provider selection, and it can only emit actions from a closed set (allow, block, redact, `route_to:<model>`, `set_sink_tag:<tag>`, `audit:<priority>`). Off until you add an `ai_policy` block:

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
  ai_policy:
    expression: |
      ai.principal.tier == "free" && ai.guardrails.flagged_count >= 2
        ? ["redact", "route_to:gpt-4o-mini", "audit:high"]
        : ["allow"]
    on_error: allow
```

The action table, the full `ai.*` namespace, and the fail-open semantics are in [ai-policy-cel.md](ai-policy-cel.md).

`on_error` is the one failure setting in the AI gateway that does not use the shared `closed` / `open` / `degraded` / `observe` posture words, and that is deliberate. A posture answers a single question, does the request proceed. `on_error` is a whole fallback decision drawn from the same action set the expression itself emits, so it can route, redact, tag, and audit in one go: `on_error: redact route_to:gpt-4o-mini audit:high` is a real configuration that no posture word can express. Two of the seven tokens do line up, and it is worth knowing which: `block` is the shared `closed`, and `allow` is the shared `open`. Every token is parsed and validated when the policy is compiled at config load, so a bad `on_error` is a startup failure rather than a request-time surprise.

The default is `allow`, and it is the one place in the gateway where defaulting open is correct. `on_error` fires when the operator's own expression could not be evaluated: a typo in a field path, a type error, a token outside the closed set. That is a bug in a rule, not evidence that the request is dangerous, and the guardrails, budgets, and rate limits that do enforce security boundaries have already run and are unaffected. Defaulting closed would let one malformed expression black-hole every request on the route. Set `on_error: block` for the strict reading, or `on_error: allow audit:high` to keep the failure visible without refusing traffic.

## Budgets

Set token or dollar caps that apply across a workspace, a single virtual key, an end user, a model, an origin, a metadata tag, or a single agent. The `budget` block sits under `action` and is parsed by `BudgetConfig` in `crates/sbproxy-ai/src/budget.rs`.

By default the counters are per-instance (an in-process tracker), so a cluster of N replicas enforces roughly N times a given cap. When the key store runs on Redis (a `key_management` Redis backend, which is the clustered deployment shape), the same Redis also accumulates the spend and enforcement reads the shared total, so the fleet enforces one budget. Nothing extra is configured: cluster-shared budgets turn on whenever a Redis key store is present. If Redis is briefly unreachable the shared read fails open to the local tracker, so the per-instance count stays the floor.

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
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
| `scope` | enum | required | One of `workspace`, `api_key`, `user`, `model`, `origin`, `tag`, `agent`. |
| `max_tokens` | u64 | unset | Total prompt + completion tokens allowed for the scope. |
| `max_cost_usd` | f64 | unset | Total cost ceiling in USD across all requests in the scope. |
| `period` | string | unset | One of `daily`, `weekly`, `monthly`, `total`. Window over which usage accumulates. |
| `downgrade_to` | string | unset | Model name routed to when this limit fires and `on_exceed` is `downgrade`. |

### Behavior notes

- A limit fires the first time `usage >= max_tokens` or `usage >= max_cost_usd`. Limits are checked in declaration order and the first match wins.
- `on_exceed: log` records a warning and a `sbproxy_ai_budget_utilization_ratio` gauge update, then lets the request through.
- `on_exceed: downgrade` swaps the request's model to the firing limit's
  `downgrade_to` and proceeds. When that field is unset, the gateway selects
  the cheapest configured model it can price; it blocks only when no target is
  available.
- Setting only `max_tokens` and leaving `max_cost_usd` unset (or vice versa) is supported. A limit with neither field is a no-op.
- Multiple limits on the same scope with different `period` values (for example daily and monthly) accrue in separate window buckets. Each limit is checked against its own key; the tightest binding that is exceeded fires first in declaration order. There is no separate org/team/project hierarchy tracker: `BudgetScope` is the single enum (`workspace`, `api_key`, `user`, `model`, `origin`, `tag`, `agent`) used by `BudgetLimit`.
- An `agent`-scoped limit keys on the agent-to-agent caller identity, so per-agent spend is enforced rather than only reported. It names an agent only when the proxy verified that identity: asserted by a peer listed in `proxy.trusted_proxies`, or lifted from the RFC 8693 `act` chain of a signed token. An unverified caller names itself, so honoring the name would let it spend to the cap and then rename itself for a fresh allowance, or burn through the budget of an agent whose name it borrowed. Unverified and unidentified spend therefore pools into one shared bucket that is still capped, which is the same `__unattributed__` fallback a request missing `x-user-id` gets. That fails closed: one noisy unverified caller can exhaust the shared bucket, and no unverified caller can reach a named agent's budget. Reporting keeps the finer grain, since the usage ledger records the claimed id and the trust flag either way. This is a different mechanism from the `agent_budget` policy, which rate-limits requests per fingerprinted agent class; this caps spend per asserted agent identity.
- Realtime WebSocket requests run the same hard-limit preflight before the
  upgrade. `block` returns 402 without an upstream WebSocket handshake, `log`
  permits the upgrade, and `downgrade` replaces every inbound `model` query
  value with one effective model while preserving unrelated query parameters.
  Realtime frames are byte-transparent and do not debit token or cost
  counters, so this is admission control over usage already recorded by other
  requests, not per-frame accounting.

### Soft-landing budget thresholds

A hard budget is a cliff: requests pass until the cap, then block at 100%. The opt-in `soft_landing` block tapers instead. It is a ladder of fixed threshold fractions checked against the current window's accumulated spend before each dispatch; nothing forecasts future spend. Past `warn_at` the request is allowed and a warning is logged; past `downgrade_at` the model is rewritten to a cheaper target; at the cap the hard `on_exceed` action takes over as before.

```yaml
budget:
  limits:
    - scope: workspace
      max_cost_usd: 10.0
      period: daily
  on_exceed: block
  soft_landing:
    warn_at: 0.8
    downgrade_at: 0.95
    downgrade_to: gpt-4o-mini
```

Window selection, the downgrade-target resolution order, and how a downgrade is tagged in the spend history are in [ai-predictive-budget.md](ai-predictive-budget.md).

### Model prices

Cost tracking and cost-based routing need a per-model price. SBproxy ships a built-in catalog of current families (GPT-5 / 4.1 / 4o / o-series, Claude 4.x and 3.x, Gemini 2.x and 1.5); a model the catalog does not know is billed at a deliberately high $5 / $5 per million tokens so a budget cap fires early rather than late. You can supply prices two ways, both layered over the catalog.

Inline prices, per model, in USD per million tokens:

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
  model_prices:
    claude-haiku-4-5:
      input_per_million: 1.0
      output_per_million: 5.0
    my-local-qwen:
      input_per_million: 0.0        # self-hosted, no marginal token cost
      output_per_million: 0.0
```

Or point at an external rate card in the LiteLLM `model_prices_and_context_window.json` schema (the ecosystem's canonical dataset, 2,900+ models):

```yaml
  rate_card: /etc/sbproxy/model_prices.json
```

Refresh the vendored file out of band with `scripts/refresh-model-prices.sh /etc/sbproxy/model_prices.json`; the gateway loads it at config load and never fetches at runtime, so an egress-restricted host is unaffected. Resolution order for a model's price is: `model_prices` (highest), then the rate card, then the built-in catalog, then the $5 / $5 fallback. A missing or malformed rate card is logged and skipped, not fatal. Cache-read and cache-write rates carry through from both sources; the built-in catalog does not yet include them.

## Virtual API keys (`credentials:`)

Issue per-team or per-app keys that the gateway checks on every request, once the origin also turns enforcement on. A `credentials:` block by itself only declares named keys; it does not make the gateway check them. The origin (or the tenant or proxy scope the credential lives at) must also set `action.require_governed_key: true`, or config compile now rejects it: without that flag, a `credentials:` block would silently do nothing, and the origin would accept any bearer token, or none, and dispatch every request ungoverned. See `require_governed_key` below.

Each key can pin a provider, restrict models, set its own request rate, carry its own budget ceiling, and tag requests for downstream attribution. The shipped shape is a `credentials:` list of `type: ai_provider` entries next to the origin's `action:` block; the same block also lives at `tenants[].credentials` and `proxy.credentials` scope, with origin shadowing tenant shadowing proxy for entries that share a `name`. The legacy `virtual_keys:` key is rejected at config compile with a pointer to [migration-credentials.md](migration-credentials.md).

With key management enabled, exact configured values are resolved from every
carrier in `key_management.inbound.headers`, including its configured scheme;
the defaults cover `Authorization: Bearer`, `x-api-key`, and `x-sb-api`.
Canonical and stored legacy keys take precedence, and provider-native policy is
the final fallback. Without key management, configured values retain the
legacy `Authorization: Bearer` lookup.

Set `action.require_governed_key: true` to reject requests that do not resolve
to a governed public key identity on that origin. Dynamic mutation, the full
policy field contract, effective-policy preview, and fail-closed behavior are
documented in [Dynamic key management](key-management.md).

Stored-key token-per-minute and lifetime token or cost caps currently settle
only on standard JSON POST inference surfaces when the provider response
reports parseable usage. Multipart and non-POST requests can dispatch, but do
not settle those stored-key counters, so treat the caps as advisory for those
surfaces. For a strict cluster-wide ceiling on JSON inference traffic, govern
the key and set `key_management.governance.consistency: strict`; see
[Governed admission](key-management.md#governed-admission-strict-and-approximate).

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini, gpt-4o]
    credentials:
      - name: team-a
        type: ai_provider
        provider: openai
        key: ${TEAM_A_KEY}
        models:
          allow: [gpt-4o-mini]
          deny: [gpt-4o]
        policies:
          - type: rate_limit
            rpm: 60
        attrs:
          project: checkout
          tags: [team-a, beta]
          budget:
            max_tokens: 5000000
            max_cost_usd: 100
```

### `credentials[]` fields (type: ai_provider)

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `name` | string | required | Stable operator-supplied name, unique within its scope. Used in logs and metrics. |
| `type` | string | required | `ai_provider` for gateway-validated AI keys. |
| `key` | string | required | The token clients send. Treat it like a secret and inject via `${VAR}` or a secret-reference scheme. |
| `provider` | string | unset | Pins the credential to one configured provider. Requests that resolve to a different provider are rejected. |
| `models.allow` | list of string | `[]` | Empty allows all models; otherwise the request model must match one entry. |
| `models.deny` | list of string | `[]` | Takes precedence over `models.allow`. |
| `principals` | list | `[]` | Principal selectors gating who may use the credential. Empty matches everyone. |
| `policies` | list | `[]` | Closed set: `rate_limit` (with `rpm`) and `require_pii_redaction`. There is no per-key tokens-per-minute knob; cap token spend with `attrs.budget.max_tokens`. |
| `attrs` | object | unset | Attribution: `project`, `user`, `cost_center`, `tags`, `metadata`, and `budget`. `team` is accepted with a config-only warning but is not copied into the principal; use `tags` or `metadata` instead. `budget.max_tokens` and `.max_cost_usd` add total per-key ceilings; `.reset` is also accepted with a config-only warning and does not install a reset schedule. The per-key budget is independent of the global `budget` block. |
| `route_to_model` | string | unset | Pins every request from this credential to one model. |
| `compression_profile` | string | unset | Selects `on`, `off`, or a named compression profile declared by this AI route. |
| `inject_tools` | list | `[]` | Provider-native tool definitions injected into requests from this credential. |

At compile time each `ai_provider` credential is lowered onto the runtime key registry (`VirtualKeyConfig` in `crates/sbproxy-ai/src/identity.rs`) that AI dispatch reads. Per-key usage shows up in the attributed spend metrics: filter or `sum by (api_key_id)` on `sbproxy_ai_requests_attributed_total`, `sbproxy_ai_tokens_attributed_total`, and `sbproxy_ai_cost_dollars_attributed_total`.

## Caching

Two caches run on the serving path: the semantic cache and the idempotency middleware, both described below. Cache hit and miss counts land in `sbproxy_ai_cache_results_total`.

### Exact replay

For byte-identical replay of retried requests, use the idempotency middleware
below. The gateway does not have a separate exact-prompt-cache configuration
surface. For near-duplicate prompts, use the semantic cache.

### Semantic cache

![a first prompt logging x-semcache MISS, then a reworded equivalent served as HIT in a fraction of the time](assets/semantic-cache.gif)

Different words, same meaning, no provider call ([config](../examples/semantic-cache-openai/)).

Serves cached responses to prompts that mean the same thing without a provider call. Implemented in `semantic_cache.rs` as `EmbeddingCache`: on a miss the dispatcher embeds the prompt once via the configured source, and on later requests a cosine-similarity scan over the stored vectors replays the closest response that meets `threshold`. Vectors are L2-normalized at insert time, eviction is LRU with a `max_entries` cap, entries past `ttl_secs` are dropped lazily on lookup, and every entry is scoped to the calling tenant and credential so one caller's cached response is never replayed to another. Embedding failures fail open to an uncached upstream call.

A request bypasses semantic-cache reads and writes when it carries an explicit
header, governed-key, or CEL compression selector; when its route declares
named profiles; when the route default uses `token_prune`, `query_select`, a
retrieval-aware lever, or an explicit input budget; or when a captured session
could use `summary_buffer`. A supported chat surface also bypasses the cache
when its route has a non-`off` reasoning policy, because current cache keys do
not include that policy or its output budget. The decision happens before
lookup and also prevents write-back. A legacy default-only compatibility
`window_fit` route keeps its prior cache behavior. See
[Semantic cache interaction](ai-context-compression.md#semantic-cache-interaction).

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | bool | `false` | Opts an origin into semantic-cache lookup and storage. |
| `threshold` | float | `0.85` | Minimum cosine similarity for a near-duplicate prompt to hit. |
| `ttl_secs` | u64 | `3600` | Seconds before an entry is treated as a miss and removed. |
| `max_entries` | usize | `1024` | Hard cap on cached responses. The oldest insert is evicted on overflow. |
| `source` | string | `provider` | `provider`, `sidecar`, `inprocess`, or `openai`. |
| `embedding` | object | unset | Provider and model used when `source: provider`. |
| `sidecar` | object | unset | gRPC endpoint, model, and timeout used when `source: sidecar`. |
| `inprocess` | object | unset | ONNX model path, tokenizer path, and memory guard used when `source: inprocess`. |
| `openai` | object | unset | Standalone OpenAI-compatible endpoint (base URL, model, auth) used when `source: openai`. |

The semantic cache is configured on each AI origin under `action.semantic_cache`. The default `source: provider` calls the configured embedding provider's `/v1/embeddings` endpoint:

```yaml
origins:
  ai.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, text-embedding-3-small]
      routing:
        strategy: round_robin
      semantic_cache:
        enabled: true
        threshold: 0.85
        ttl_secs: 3600
        max_entries: 1024
        source: provider
        embedding:
          provider: openai
          model: text-embedding-3-small
```

For local embeddings with no provider egress, set `source: sidecar` and run the classifier sidecar with an embedding model. For single-process experiments, `source: inprocess` loads the ONNX model into the proxy process and should be paired with `max_model_bytes`. See [local-inference.md](local-inference.md) and [examples/semantic-cache-local](../examples/semantic-cache-local/sb.yml).

To vectorize via an OpenAI-compatible endpoint that is not one of the origin's chat providers, set `source: openai`. This points the cache at any `/v1/embeddings` URL with its own key, so you can embed through another sbproxy that fronts an embedding model, through OpenRouter, or through a hosted provider, without adding it to `providers`:

```yaml
      semantic_cache:
        enabled: true
        threshold: 0.85
        source: openai
        openai:
          base_url: https://openrouter.ai/api/v1   # or http://sbproxy.internal/v1
          api_key: ${EMBEDDING_API_KEY}
          model: text-embedding-3-small
          timeout_ms: 2000
```

Auth defaults to `Authorization: Bearer ${api_key}`. For endpoints that expect a different header (Azure `api-key`, an `x-api-key` gateway), set `auth_header` and clear `auth_prefix`; endpoints that need extra headers (such as OpenRouter's `HTTP-Referer` / `X-Title`) take a `headers` list of name/value pairs, sent verbatim. For header-only auth, omit `api_key` and carry the credential in `headers`. The endpoint base URL joins `/v1/embeddings` the same way chat provider base URLs do (an overlapping trailing `/v1` is collapsed). Embedding transport or parse errors degrade to an uncached upstream call. A configured fair-share quota still applies to an external embedding attempt; quota denial or closed-backend failure returns `429` or `503` instead of failing open. See [local-inference.md](local-inference.md) and [examples/semantic-cache-openai](../examples/semantic-cache-openai/sb.yml).

### Idempotency middleware (RFC 8594)

Engages on `action: ai_proxy` origins when an `Idempotency-Key`
header is present on a POST / PUT / PATCH request. The middleware
sits ahead of the upstream provider call: on a cache hit the
gateway replays the cached `(status, headers, body)` triple
directly to the client with `x-sbproxy-idempotency: HIT` and
never contacts the provider, so Stripe-style retries do not
double-bill the upstream. On a body conflict the gateway returns
409 `ledger.idempotency_conflict`. On a miss the gateway forwards
and records the final client-wire bytes after native-format wrapping
and reversible PII restoration. Retries replay those bytes without
running the format adapter again. Semantic-cache entries remain in
the canonical hub shape. For native client formats, the conflict hash
uses the original client request bytes. Changing a vendor-only field
therefore produces a conflict instead of replaying a response for a
different request.

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
upload) are not cached, and successful SSE event streams are not
recorded. A `stream: true` request that receives buffered JSON still
uses the normal idempotency path.

## Per-provider limits

The proxy reads rate limit headers off provider responses into advisory
`ProviderQuotaSnapshot` values and pre-emptively throttles when remaining
capacity falls under a configured fraction of a *known* limit. Implemented
in `provider_ratelimit.rs` as `ProviderRateLimitTracker`, wired from
`ai_dispatch` before retry/reselect so `headroom` and `reset_aware` see
live signals.

Signal quality is explicit:

| Quality | Meaning | Routing / throttle behavior |
|---------|---------|-----------------------------|
| `KnownFresh` | Header-derived observation inside the freshness window | May score pressure / reset; throttle uses real `remaining/limit` |
| `Stale` | Observed before, but aged past freshness or cleared after reset | Advisory only; must not invent hard guarantees |
| `Unknown` | Never observed for that provider | No invented capacity; throttle stays off |

Recognized response headers (case-insensitive):

- `x-ratelimit-remaining-requests`, `x-ratelimit-remaining-tokens`
- `x-ratelimit-limit-requests`, `x-ratelimit-limit-tokens`
- `x-ratelimit-reset-requests`, `x-ratelimit-reset-tokens` (formats: `1s`, `500ms`, plain seconds)
- `retry-after` (delta-seconds or HTTP-date)
- `anthropic-ratelimit-requests-remaining`, `anthropic-ratelimit-tokens-remaining`
- `anthropic-ratelimit-requests-limit`, `anthropic-ratelimit-tokens-limit`
- `anthropic-ratelimit-requests-reset`

A `429` response marks remaining requests as exhausted when the upstream
omits an explicit remaining count.

The tracker takes a single `throttle_threshold: f64` between 0.0 and 1.0.
Throttling uses the real limit from headers: remaining requests at or below
`floor(limit * threshold)`. Without a known limit, remaining alone does not
invent a synthetic denominator. Hard blocks still apply when remaining
requests or tokens are reported as zero. Default threshold: `0.1`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `throttle_threshold` | f64 | `0.1` | Clamped to `[0.0, 1.0]`. Lower values delay throttling until the provider is closer to its hard limit. |

Per-provider throttling is a runtime construct. There is no top-level YAML field; the tracker is instantiated alongside the provider router and updated from every upstream response on the dispatch path.

For per-model rate limits configurable in YAML, use `model_rate_limits` on the `action` block. The struct is `ModelRateConfig` in `ratelimit.rs`:

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
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

## Model aliases (design stage)

Model aliases are design-stage library code: `model_alias.rs` ships a `ModelAliasRegistry` with `ModelAlias` entries, but nothing on the serving path constructs the registry, and a `model_aliases:` key in the config is ignored. To map a friendly name onto an upstream model today, use the shipped per-provider `model_map` field, which rewrites the requested model name before dispatch. The rest of this section records the registry's intended shape.

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
    model_id: claude-sonnet-4-5
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

In the library code, resolution returns `None` for unknown names so a caller can fall back to literal model ID matching, and re-registering the same alias overwrites the previous entry. None of this runs per-request today.

## Supported endpoints

Every inbound request to an `action: ai_proxy` origin is classified into an `AiSurface` by `classify_surface(method, path)` in `crates/sbproxy-ai/src/handler.rs`. The classifier accepts canonical OpenAI paths with optional `/v1` or `/api/v1` prefix and any trailing slash. The surface label appears on the per-surface metrics, on the request tracing span, and on every per-surface decision (rate limit, guardrail extractor, 501 gate).

Provider capability is the source of truth for which surfaces a configured provider can serve. The matrix lives in `crates/sbproxy-ai/src/api_routes.rs::provider_supports_surface`. When no configured provider supports the requested surface, the proxy returns **501 Not Implemented** before any upstream call. The universal surfaces are chat completions, Anthropic Messages, OpenAI Responses, and models. Unknown surfaces fall through to the existing dispatch and 404 at the upstream.

| Surface label | Method(s) | Path(s) | Providers (today) |
|---|---|---|---|
| `chat_completions` | POST | `/v1/chat/completions` | All |
| `messages` | POST | `/v1/messages` | All |
| `responses` | POST | `/v1/responses` | All |
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

"Supported" in the table above means the gateway accepts the surface and routes it. It does NOT mean the gateway normalizes the response. Per-surface translation behavior:

| Surface | Response shape |
|---|---|
| `chat_completions` | normalized to / from the OpenAI shape on Anthropic and Google (gemini) formats; passthrough on OpenAI-compatible upstreams |
| `messages`, `responses` | accepted in their native client shapes and governed through the chat hub. Successful generations return in the shape the client used. Provider error envelopes keep the provider's status and body. A safe Anthropic-to-Anthropic request can use the native bypass described below. |
| `models` | `GET /v1/models` and `GET /models` are served locally for every AI origin as an OpenAI `{"object": "list", "data": [...]}` logical listing. Other model endpoints use the ordinary GET dispatch path and have no unified response shape. |
| everything else | passthrough on the providers listed in the table; clients see the upstream's native response shape |

The local list contract is deliberate: it gives clients one topology-free
discovery shape across ordinary and managed providers without pretending to
preserve provider-specific metadata. Call the provider directly when native
model-list fields are required.

#### Native Anthropic bypass

An Anthropic client calling `/v1/messages` can bypass the internal format round trip when the selected upstream also uses Anthropic Messages. The gateway substitutes the resolved model and sends the original native request shape to the upstream `/v1/messages` path. After output governance and reversible PII restoration, the upstream response keeps its native shape and fields.

The bypass is deliberately narrow. Every request content and control field must have a lossless representation in the governed canonical tree. Unknown extensions and unsupported blocks such as `document` and `search_result` use the normal hub path, so the gateway never forwards content its policies could not inspect. The bypass is also disabled for streaming requests and whenever request processing changes content, including request PII redaction, prompt or tool injection, policy redaction, compression, and reasoning controls.

A request with `stream: true` enters the SSE relay only when the upstream returns a successful `text/event-stream` response. Provider errors keep their original status, content type, and body. A successful buffered JSON response uses the normal provider translation and returns in the client's inbound shape. Both buffered paths have a bounded body read and can be replayed by idempotency.

### Method coverage

The gateway accepts any standard HTTP method for any supported surface. GET,
POST, PUT, DELETE, PATCH, HEAD, and OPTIONS share credential resolution,
provider policy, rate admission, and observability. PUT and PATCH JSON bodies
also apply governed model routing, model allow/block policy, request PII
redaction, and token/cost budget preflight before idempotency lookup or
dispatch. Locally served discovery endpoints filter their results by provider
and model policy. Other bodyless methods cannot interpret a model or redact a
body, so a credential that requires either fails closed on those requests.

Non-POST responses do not yet settle stored-key token and cost counters.
Method-aware dispatch is what makes `DELETE /v1/assistants/{id}`,
`POST /v1/threads/{id}/runs/{id}/cancel`, and the other non-POST verbs work
end-to-end when their credential policy is satisfiable. Strict settlement for
these methods is not implemented yet.

### Multipart bodies

Image edits, image variations, audio transcription, and audio translation send
multipart request bodies. The proxy detects multipart from the inbound
`Content-Type`; when it starts with `multipart/`, the body is forwarded with
that Content-Type preserved. A governed key's model policy is checked against
the bounded `model` part, and `route_to_model` or a budget downgrade rewrites
only that part. A required model with no interpretable model part fails closed.
Because the gateway cannot safely apply JSON PII redaction to arbitrary
multipart bytes, a credential with `require_pii_redaction` is rejected before
idempotency, cache, or provider dispatch.

Provider format translation does not run for multipart. Multipart responses do
not currently settle stored-key token-per-minute or lifetime token and cost
counters; that work is not implemented yet.

### Per-surface configuration

Per-surface knobs live under `per_surface_rate_limits` (see [Per-surface rate limits](#per-surface-rate-limits)) and apply automatically based on the classified surface. Surfaces have no dedicated YAML config block beyond that; they share the top-level `providers`, `routing`, `budget`, `model_rate_limits`, `max_concurrent`, and `guardrails` settings, plus the origin's `credentials:` list.

### Reranking

`reranking` ships. It classifies the surface, dispatches it when a configured provider supports it (Cohere today), and captures the request's document count for per-unit billing. When no configured provider supports reranking, the proxy returns 501 before any upstream call, the same as every other surface.

## Reasoning policy

An AI route can ask eligible models to use less reasoning:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-5-mini]
      reasoning: concise
```

The closed values are:

```yaml
reasoning: off
reasoning: concise
reasoning:
  budget: 2048
```

`off` is the default and leaves the body unchanged at this stage. `concise`
selects the provider's lowest known native reasoning setting. `{budget: N}`
requires a positive integer and uses a native token budget when the provider
offers one. A provider attempt sees this policy after its `model_map` rewrite,
so support is decided from the model that will reach that provider. Retries,
fallback tiers, cascade tiers, race participants, and admitted shadow calls
each apply the policy to their own mapped model.

Because reasoning transforms happen after provider selection, a supported
chat surface with `concise` or `{budget: N}` bypasses semantic-cache reads and
writes. This prevents an older cached response from skipping the current
reasoning policy. Exact idempotency replay remains a separate contract: an
accepted key replays its original response until that entry expires, even
across a route-policy reload. New keys and cache misses use the current
reasoning policy, and every replay still passes current output guardrails.

`N` has provider-specific wire semantics. Anthropic and Gemini use it as the
native thinking-token budget when the mapped model accepts that value.
Anthropic requires `budget_tokens` to remain below `max_tokens`, so SBproxy
keeps a separate visible-output allowance and raises `max_tokens` to cover the
thinking budget plus that allowance. OpenAI exposes effort rather than a
numeric reasoning-token budget. SBproxy therefore selects low effort and caps
the available completion at `N`, using `max_completion_tokens` for Chat
Completions or `max_output_tokens` for a direct Responses-shaped call. The
fixed fallback also caps the available completion or output field at `N`.
Native values outside a model's supported range use that fallback safely.

| Provider capability | `concise` | `{budget: N}` |
|---|---|---|
| OpenAI, Azure OpenAI, or Azure Foundry reasoning model | Chat Completions uses `reasoning_effort: low`; direct Responses uses `reasoning.effort: low` | Keep low effort; cap Chat Completions `max_completion_tokens` or Responses `max_output_tokens` at `N` |
| Anthropic model with adaptive thinking | Set `thinking.type: adaptive` and `output_config.effort: low` | Use manual thinking only when that model supports it and `N` meets Anthropic's 1,024-token minimum; otherwise use the fixed fallback |
| Anthropic model with manual thinking | Use the fixed prompt fallback when adaptive thinking is unavailable | Set `thinking.type: enabled` and `thinking.budget_tokens: N`; preserve the visible-output allowance in `max_tokens` |
| Gemini model with thinking levels | Set `generationConfig.thinkingConfig.thinkingLevel: low` | Use a native budget only when that model exposes one and `N` is within its model-specific bounds; otherwise use the fixed fallback |
| Gemini model with thinking budgets | Set `thinkingBudget: 1024` | Set `thinkingBudget: N` when `N` is within the model-specific minimum and maximum |
| Bedrock with an Anthropic model | Use the matching Anthropic control under `additionalModelRequestFields` | Use the matching Anthropic budget under `additionalModelRequestFields`, subject to the same support and minimum checks |
| Other providers and models | Fixed prompt fallback | Fixed prompt fallback with a completion cap |

The runtime keeps the provider capability checks, including new adaptive
Anthropic families and Gemini budget ranges. Treat the table as the wire
behavior for a matched capability, not a permanent model-name allowlist.

For Chat Completions and Messages, the fallback prepends this fixed system
message once:

```text
Use brief, compact draft reasoning with only essential intermediate steps, then give the answer.
```

For a Responses-shaped call, SBproxy prepends the same fixed text to
`instructions` instead. The fallback contains no request text. A budget
fallback caps `max_output_tokens` for Responses. For other request shapes, it
caps an existing `max_completion_tokens` or `max_tokens` at `N`; when neither
exists it adds `max_tokens: N`.

Tool and code safety takes priority. A non-empty top-level `tools` or legacy
`functions` declaration bypasses reasoning changes. Code-shaped input also
bypasses them. The detector recognizes fenced code, common source declarations,
source syntax, common source-file paths such as `src/main.rs`, and explicit
requests such as "debug this Rust function." It does not treat a prose mention
of "code" or "function" as sufficient. SBproxy captures these eligibility
facts before context compression, so a compression lever cannot erase the
evidence and make the request eligible later.

Only Chat Completions, Anthropic Messages, and OpenAI Responses use this
policy. Images, audio, embeddings, reranking, moderation, assistants, threads,
batches, files, fine tuning, model listing, and Realtime keep their existing
request behavior.

`sbproxy_ai_reasoning_policy_attempts_total{provider,outcome}` records one
closed result per provider attempt. `outcome` is `native`, `prompt_fallback`,
`off`, `tool_bypass`, or `code_bypass`. It contains no prompt or tool content.

## Context handling

The shipped answer to a prompt that approaches a model's context window is an
ordered, per-handler compression pipeline. `query_select` keeps sentences
related to a marked question, and `token_prune` can use a local classifier
sidecar to make that text shorter. `summary_buffer` compacts eligible older
history into external state. `window_fit` can keep the legacy model-window
behavior or enforce a positive `input_budget_tokens` target with the
target-model counter. Levers run in declaration order, only strict token
reductions commit, and a skip or runtime failure leaves the last committed
messages in place while later levers continue.

### Context compression (shipped)

Configure the route default in `compression.levers` and optional named
pipelines in `compression.profiles`. A request chooses `on`, `off`, or a named
profile with precedence `X-Compression` header, governed key, CEL, then route
default. Explicit-budget fitting preserves leading system and developer
instructions, the newest complete turn, contiguous recent history, and
OpenAI/Anthropic tool-call groupings.

Marked retrieval blocks can run a quality-first fallback sequence:
`query_select`, `token_prune`, then `window_fit`. The first lever is local and
deterministic. The second calls an operator-supplied
LLMLingua-2-compatible ONNX model through the classifier sidecar. If the
query has no usable sentence, the sidecar is down, or its response fails
validation, later levers still receive the last valid message list.

A stateful summary requires a captured session ID. A stateful pipeline with no
explicit `state` block uses a process-owned Local redb file with a 24-hour TTL.
Choose `backend: redis` explicitly for serialized state shared across processes,
or `backend: mesh` for an eventually consistent Redis-free fleet already
running `proxy.cluster.replication`. Explicit backends fail startup when their
dependency is unavailable and never fall back to Local. There is no OmniRoute
dependency, import, or migration path.

The legacy `resilience.llm_aware.context_compress` switch remains a shorthand
for one `window_fit` lever only when the explicit block is absent.

The complete configuration, session and structured-content safety rules,
state-backend guarantees, failure table, metrics, logs, and PromQL are
in [AI context compression](ai-context-compression.md).

### Context overflow (design stage)

The overflow decision layer is design-stage: `crates/sbproxy-ai/src/context_overflow.rs` ships a registry of context windows for the OpenAI, Anthropic, Gemini, Mistral, and Llama families plus typed overflow actions (`Error`, `FallbackToLarger`, `Truncate`), but no dispatch code drives those actions and a `context_overflow:` block in the config is ignored. The one part of the module that does run is its window registry, which context compression consults to size a model's budget. The shipped way to handle overflow is `resilience.llm_aware.context_compress` above.

## Stored prompts and offline optimization

The prompt store keeps named, versioned prompts. A request can refer to
`"prompt": "name@version"` or use a bare name. A bare name resolves to the
pinned default, or to the highest numeric version label when no version is
pinned. SBproxy renders that version, prepends it as a system message, removes
the gateway-only `prompt` field, and records the resolved name and version in
run metadata. Runtime versions are added, replaced, and pinned through the
authenticated Admin API. Use a new version label when you need immutable
history.

`sbproxy ai prompt optimize` compiles a shorter static system prompt offline.
It never changes live route state. The command first scores the source prompt,
asks an OpenAI-compatible model for shorter instruction-only candidates, then
scores each shorter candidate against the same customer-owned JSONL cases. It
writes an artifact only after one candidate stays within the configured quality
noise.

Each nonblank JSONL line has this shape:

```json
{"id":"approved","input":"Access granted","expected":"approved"}
```

`id` must be unique and nonblank. `input` must be nonblank. `expected` must be
a string for `exact-match` and `contains`, or any non-null JSON value for
`json-exact`.

| Metric | Match rule |
|---|---|
| `exact-match` | Trim the response and expected string, then require equality |
| `contains` | Require the response to contain the expected string |
| `json-exact` | Parse the complete trimmed response as JSON and require value equality |

The aggregate score is matched cases divided by total cases. A candidate passes
when its score is at least `baseline_score - noise_tolerance`. The default
noise tolerance is `0.02`; accepted values range from 0 through 1.

The runnable prompt fixture lives in
[`examples/ai-hosted-prompts/`](../examples/ai-hosted-prompts/):

```bash
cargo run -p sbproxy -- ai prompt optimize \
  --prompt examples/ai-hosted-prompts/source-prompt.txt \
  --eval-set examples/ai-hosted-prompts/eval-set.jsonl \
  --endpoint http://127.0.0.1:8080/v1 \
  --host-header test.sbproxy.dev \
  --task-model claude-haiku-4-5 \
  --optimizer-model claude-haiku-4-5 \
  --metric exact-match \
  --noise-tolerance 0 \
  --max-candidates 4 \
  --max-requests 24 \
  --timeout-secs 60 \
  --name access-decision \
  --prompt-version 2 \
  --output /tmp/access-decision-v2.json
```

`--endpoint` accepts an HTTP or HTTPS base URL or a full
`/chat/completions` URL. It rejects embedded credentials, query parameters, and
fragments. `--host-header` keeps the dial address from `--endpoint` but
overrides the HTTP `Host` header, which lets the local command reach the
`test.sbproxy.dev` origin. Use `--api-key-env OPENAI_API_KEY` when the endpoint
expects a Bearer key; the flag names an environment variable and does not
accept the key itself. `--optimizer-model` defaults to `--task-model`.

The source prompt is capped at 1 MiB and the eval set at 16 MiB. Each model
response is capped at 1 MiB. `--max-candidates` accepts from 1 through 64.
`--max-requests` covers the baseline cases, one candidate-generation request,
and candidate evaluations. For `C` cases, the minimum useful budget is
`2 * C + 1`: one baseline, one candidate, and the generation call. SBproxy
sorts usable shorter candidates by token count, then evaluates only the number
of complete `C`-request evaluations that fit. To evaluate up to `K` candidates,
allow `C * (K + 1) + 1` requests. The command never crosses the cap. It fails
without writing an artifact if no evaluated candidate passes or a model
request fails.

The source must be a static instruction without Minijinja markers. The
optimizer response must be a JSON array of strings, with an optional JSON code
fence. SBproxy discards blank, duplicate, unchanged, and non-shorter
candidates. It also discards candidates with common few-shot markers such as
`Example:`, paired `Input:` and `Output:`, or paired `User:` and `Assistant:`.
Minijinja markers such as `{{`, `{%`, and `{#` are also rejected. These checks
are conservative syntax guards, not a semantic proof that a candidate contains
no demonstration. Optimize dynamic templates and few-shot prompts with a
task-specific process that evaluates their rendered form.

Among candidates that pass, SBproxy chooses the lowest target-model token
estimate. A token-count tie prefers the higher quality score, then lexical
order for determinism. The JSON artifact includes the source SHA-256, metric,
both scores, noise tolerance, token counts, and an Admin-ready
`prompt_version` object with an empty `variables` map.

Install the selected version explicitly:

```bash
jq '.prompt_version' /tmp/access-decision-v2.json \
  | curl -u admin:change-this \
      http://127.0.0.1:9090/admin/prompts/test.sbproxy.dev/access-decision/versions \
      -H 'Content-Type: application/json' \
      --data-binary @-
```

Review the artifact before this call. The optimizer proves only the chosen
metric on the supplied cases, and the Admin mutation changes the live prompt
overlay. Pinning remains a separate Admin operation, which gives operators a
clear review and rollback point. The full runnable flow is in
[`examples/ai-hosted-prompts/`](../examples/ai-hosted-prompts/).

## Streaming analytics

The dispatch pipeline measures streaming responses inline: time to first token,
output throughput, and average inter-token latency are recorded in
`sbproxy_ai_ttft_seconds`,
`sbproxy_ai_output_throughput_tokens_per_second`, and
`sbproxy_ai_inter_token_latency_seconds`, labeled by provider and model.

## Structured output

Provider-enforced JSON output works where the upstream supports it:
`response_format` passes through to OpenAI-compatible upstreams (the Gemini
translator drops it as an unsupported knob). The proxy does not re-validate
the returned JSON, and there is no `structured_output:` config key. When you
need the gateway itself to enforce a shape, that is what the
[schema guardrail](#schema-guardrail) is for: a `type: schema` output
guardrail validates the response against a compiled JSON Schema and blocks
on mismatch, independent of whatever the provider did with
`response_format`.

## OpenAI surface-area routing

Assistants, threads, batches, image generation, audio, and fine-tuning remain
live passthrough surfaces. `classify_surface(method, path)` in
`crates/sbproxy-ai/src/handler.rs` labels every request with an `AiSurface`,
and `provider_supports_surface(provider, surface)` in
`crates/sbproxy-ai/src/api_routes.rs` answers whether that provider exposes it.
Those two are the whole path: a surface the classifier names is a surface the
matrix answers for. The gateway forwards the request to an eligible provider;
it does not emulate those provider APIs locally, and there are no per-surface
emulation config blocks.

### `realtime`

Realtime WebSocket proxying ships and is documented in the
[Realtime](#realtime-1) section below. The gateway resolves credential policy,
checks provider and model eligibility, applies per-key and per-surface RPM plus
budget preflight, and then forwards frames byte-transparently. A credential
that requires PII redaction is rejected because opaque WebSocket frames cannot
meet that requirement. There is no `realtime:` config key on the action;
writing one is silently ignored.

The action-level `budget` block and governed-key identity also participate in
pre-upgrade admission. Provider and bound key-plane credentials are selected
at the final outbound header seam; origin `outbound_credential` resolvers do
not run for Realtime.

The `realtime.rs` module itself is design-stage shape code with no serving-path callers: `RealtimeConfig { enabled, model }`, `RealtimeSession { session_id, model, created_at, status }`, and `RealtimeEvent { event_type, data }` round-trip through serde but nothing constructs them. Source: `crates/sbproxy-ai/src/realtime.rs`.

## Per-request attribution

The gateway records provider and model when they are resolved, and token counts
or estimated cost when the surface and provider response make them
interpretable. It does not invent token/cost values for opaque multipart,
method-aware, or Realtime traffic. Available values are exposed through
Prometheus metrics (see below); direct response headers are not emitted today.

### Authoritative identity: tenant and credential

The attributed AI request, token, and cost metric families are partitioned by
two authoritative identity dimensions in addition to provider/model:

- `tenant_id`: the tenant the request resolved to (`__default__` in single-tenant deployments), taken from the matched origin.
- `api_key_id`: a stable id for the credential (API key) that authenticated the request and injected its policy. This is the join key that ties spend back to the agent routing traffic through the gateway.

Both are sourced from the resolved principal, never from a request header, so a caller cannot misattribute its own spend. The business attribution tags (`project`, `feature`, `team`, ...) remain caller-overridable through `SB-Attr-*` headers over the credential defaults; the trust dimensions above do not, and neither does `agent_id` (see the next section).

`api_key_id` resolution:

- For an `api_key` auth credential, set a stable id explicitly with `key_id:` on the entry. When omitted, the gateway derives a non-reversible `sk_<hex>` fingerprint of the secret so the key is still attributable. The raw secret never reaches a metric label, span, or log line.
- For a config-defined virtual key, the operator-supplied virtual-key `name` is
  used. For an admin-managed governed key, the immutable public `key_id` is
  used instead of its mutable display name.

**Fragment:** This is an origin's `authentication:` block (alias `auth:`; this page uses the canonical name). Nest it under an origin alongside `action:`; see [key-management.md](key-management.md) for the full key lifecycle.

```yaml
authentication:
  type: api_key
  api_keys:
    - secret: ${TEAM_A_KEY}
      key_id: team-a-prod      # stable reporting id; spend rolls up here
      project: checkout
      team: payments
    - secret: ${TEAM_B_KEY}    # no key_id -> derived sk_<hex> fingerprint
      team: growth
```

The access log stamps both `api_key_id` and `tenant_id`. The request-event
envelope stamps `api_key_id`; use the access log or usage sink when a durable
tenant/key join is required. Usage sinks and enabled access logs retain
operator-supplied project, user, tags, and metadata. Request spans and metrics
use a smaller fixed field set, and security audit events exclude free-form
metadata.

### Cost per agent

`api_key_id` answers "which credential spent this". It stops answering the
question you actually have the moment one service runs several agents behind one
key, which is the normal shape: a planner, a researcher, and a summarizer all
holding the same credential, and a bill that says only that the credential spent
$4,000.

So spend is also attributed to the agent that spent it, to the run it happened
inside, and to the workflow that run belongs to.

| Dimension | Where it comes from | Metric label | Usage ledger | Request span | Access log |
|---|---|---|---|---|---|
| agent | the resolved agent-to-agent identity (`x-a2a-caller-agent-id`, or an RFC 8693 `act` chain) | `agent_id` | `agent_id` | `sbproxy.a2a.caller_agent_id` | `attribution.agent_id` |
| run | the A2A `contextId` | none, deliberately | `a2a_context_id` | `session.id` | `a2a_context_id` |
| workflow | the `SB-Attr-Trace-Id` header | none, deliberately | join through `request_id` | none | `attribution.trace_id` |
| trust | whether the proxy verified the identity | none | `a2a_identity_verified` | `sbproxy.a2a.identity_verified` | `a2a_identity_verified` |

Only the agent becomes a metric label. An agent id names a member of your agent
roster, so its distinct values are bounded by how many agents you run. A run id
or a workflow id takes a fresh value every time, so as a label each one would
mint a Prometheus time series per run and the series count would grow with your
traffic instead of with your system. Those two live on the span, the access log,
and the usage ledger, which is where an unbounded correlation key belongs, and
the build fails if anyone tries to make either a label.

One caveat on the run column. The A2A `contextId` travels in the JSON-RPC request
body, and the AI gateway answers the request before the body phase that parses
it, so on this surface the run id is currently absent and `session.id` falls back
to the capture session. `sbproxy.run.id_source` on the span says which of the two
filled it, so a query never has to guess. The agent id has no such gap: it
arrives in a header and is resolved before dispatch.

With that in place, per-agent burn is one query and no join:

```promql
# USD per minute, by agent, over the last 5 minutes
sum by (agent_id) (rate(sbproxy_ai_cost_dollars_attributed_total[5m])) * 60

# The same, split by model, to see which agent is on the expensive one
sum by (agent_id, model) (rate(sbproxy_ai_cost_dollars_attributed_total[5m])) * 60
```

#### The agent cannot name itself

There is no `SB-Attr-Agent-Id` header. Sending one is a `400`, the same as any
other unrecognised `SB-Attr-*` key. (`SB-Attr-Agent` is a different tag and still
works: it carries `agent_type`, the `runtime` versus `development` bucket.)

The reason is that a caller who can name its own agent can charge its spend to a
different agent, or invent a fresh agent per request until the label's
cardinality budget demotes every real agent to `__other__` and the whole view
goes dark. So `agent_id` is filled from the agent-to-agent identity the proxy
resolved, and it reaches a metric label only when that identity was verified:
supplied by a peer in `proxy.trusted_proxies`, or lifted from the RFC 8693 `act`
chain of a signed token. Spend the gateway could not tie to a verified agent
still counts, under an empty `agent_id`, which reads as "not attributed" rather
than as somebody else's bill.

The usage ledger is stricter about this than the metrics are, because it is the
record you would take to a chargeback argument. It keeps the agent id and the
run id even when they were not verified, and writes `a2a_identity_verified:
false` beside them. Dropping the ids would lose real spend; recording them
without the flag would launder a number the caller chose into a number you
signed. Filter on that flag before you total anything per agent or per run. It is
the same trust decision the access log writes as `a2a_identity_verified` and the
`sbproxy_a2a_hops_total` metric splits with its `allow:verified` and
`allow:unverified` labels.

Every identifier is capped at 128 bytes, once, at the point the request context
first records it. The span, the ledger entry, and the metric label then all read
the same capped string, so a long agent id cannot end up looking like two
different agents on two different surfaces.

#### Nobody else does this, and here is why that matters

Per-agent cost has no industry convention to follow. That is not a gap we are
filling ahead of a standard; there is no standard in progress.

OpenTelemetry's GenAI semantic conventions, which this gateway otherwise tracks
closely (currently pinned at v1.36.0), define no cost attribute and no cost
metric at all. Tokens are covered. Money is not. So there is no
`gen_ai.usage.cost` in the spec to be compliant with, and certainly no
convention for attributing it to an agent.

Observability vendors do not model it either. Langfuse is the clearest case
because its limit is structural rather than a missing feature: cost lives on
`generation` and `embedding` observations, and an agent is not one of those, so
there is no place in the data model for "what this agent cost". You can put an
agent id in metadata, which is what our Langfuse sink does, but that is a tag on
a span, not a cost dimension you can roll up.

The part worth insisting on is where the numbers come from. Our token counts and
USD figures are parsed out of the provider's own response, in
`crates/sbproxy-ai/src/usage_parser.rs`, at the point the response passes through
the proxy. They are the provider's numbers, priced against a pinned catalog
whose revision is stamped on the span so a re-price can reproduce the original
math. A tool that only observes the agent protocol never sees the provider
response. It has to take the agent's word for what it spent, which means an agent
with a bug, or an agent that never reports at all, is invisible in its own cost
report. Sitting on the wire is what makes the attribution worth attributing.

### Request-path prompt accounting

For chat-completions requests the gateway computes, on the request path before any upstream call, an estimated prompt-token count and a salted, non-reversible prompt fingerprint (`pf_<hex>`). Both ride on the request-event envelope (`prompt_tokens_est`, `prompt_fingerprint`). The fingerprint lets identical prompts be correlated for cache/value analysis without persisting prompt text; the salt is per-process so fingerprints are not reversible or cross-deployment correlatable. When a request is blocked or fails before producing upstream usage, the estimated prompt tokens are still attributed (see the outcome metric below), so request-path value is never lost.

Trace content capture is opt-in per AI origin with `trace_content: true`.
When enabled, the request span records redacted prompt and completion text as
OpenInference `input.value` / `output.value` attributes and emits role-aware
message events for trace backends such as Phoenix and Langfuse. The capture is
off by default; every captured value runs through the secret redactor, the
origin's configured PII redactor when present, and an 8 KiB payload cap with a
`...[truncated]` marker. Streaming responses are assembled from forwarded
chunks before the completion is recorded.

### Console content samples

`capture_content: true` on an AI origin retains a redacted sample of the
prompt and response in a bounded in-memory store so an operator can inspect
one request's content from the admin console without a trace backend. The
gate is two-sided and fails closed: a sample is retained only when the origin
sets this flag AND the governed key's policy sets `allow_content_capture`.
Unkeyed and native-key traffic is never sampled, because only a minted key's
policy can carry the consent bit.

The same redaction stack as `trace_content` always applies (the secret
redactor, the origin's PII redactor when configured, the 8 KiB cap), and
configured credential carriers never reach capture surfaces. The store holds
the most recent 200 samples, at most 50 per tenant, and clears on restart.
Samples are fetched with `GET /api/requests/{request_id}/content` (admin role
only; every read is audited with the operator's name). For durable content
capture, use `trace_content` with your collector; this store is a runtime
inspection sample, not a log.

## Verifiable usage ledger

The `ledger` usage sink turns the stream of completed LLM calls into a tamper-evident record: each entry is hash-chained to the one before it, so editing any past record breaks every link after it, and with a signing seed configured each entry is Ed25519-signed. Appends happen after the response is already sent, so the ledger never adds latency to the call it records.

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
  usage_sinks:
    - type: ledger
      path: /var/lib/sbproxy/usage-ledger.jsonl
      signing_seed_hex: ${LEDGER_SIGNING_SEED_HEX}   # optional; enables signing
```

Verify the chain (and, with the seed, the signatures) with `sbproxy ai ledger verify <path>`. The proxy writes and verifies the chain locally; publishing entries to an external transparency log is out of scope, so anchoring to one is something you build on top of the same entries. The entry format, dedup semantics, durability guarantees, and the verify CLI are in [ai-usage-ledger.md](ai-usage-ledger.md).

## Token usage metrics

The proxy exposes aggregate AI usage as Prometheus metrics. The `/metrics` endpoint is served on the proxy listener itself and on the admin listener when the admin API is enabled; there is no separate `telemetry.bind_port` key. The following counters and gauges appear under the `sbproxy_ai_*` namespace:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sbproxy_ai_surface_requests_total` | Counter | `surface`, `method` | Total AI requests partitioned by classified surface (chat completions, assistants, image generation, ...) and HTTP method |
| `sbproxy_ai_surface_request_duration_seconds` | Histogram | `surface`, `method` | Per-surface request latency. Buckets match `sbproxy_ai_request_duration_seconds` for side-by-side dashboards |
| `sbproxy_ai_cost_usd_micros_total` | Counter | `provider`, `model`, `tenant_id` | Derived request cost in micro-USD (`1e-6` USD); mirrored to OTLP as `sbproxy.ai.cost_usd_micros` when `telemetry.export_metrics` is enabled |
| `sbproxy_ai_request_duration_seconds` | Histogram | `provider`, `model` | End-to-end AI request latency. Now recorded on the live path for every accepted upstream response |
| `sbproxy_ai_inter_token_latency_seconds` | Histogram | `provider`, `model` | Average inter-token latency (TPOT) per streaming response, derived from the generation window. Completes the TTFT / TPOT / throughput serving triple |
| `sbproxy_ai_tokens_attributed_total` | Counter | `origin`, `provider`, `model`, `surface`, `direction`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id`, `agent_id` | Per-attribution token spend. `sum by (tenant_id, model)` for multi-tenant multi-model token volume; `sum by (agent_id)` for per-agent volume |
| `sbproxy_ai_cost_dollars_attributed_total` | Counter | same as above minus `direction` | Per-attribution USD spend. `sum by (api_key_id)` for per-credential chargeback, `sum by (agent_id)` for per-agent chargeback. `agent_id` is empty unless a verified agent identity resolved; see [Cost per agent](#cost-per-agent) |
| `sbproxy_ai_request_duration_attributed_seconds` | Histogram | `provider`, `model`, `surface`, `tenant_id`, `api_key_id` | Model latency sliceable per tenant / credential / model. `histogram_quantile(0.95, sum by (le, tenant_id, model) (rate(..._bucket[5m])))` |
| `sbproxy_ai_requests_attributed_total` | Counter | `origin`, `provider`, `model`, `surface`, `tenant_id`, `api_key_id`, `outcome` | One row per request with a closed `outcome` label (`ok`, `guardrail_block`, `content_filter`, `budget_exceeded`, `rate_limited`, `timeout`, `upstream_5xx`, `auth_denied`, `client_error`, `other`). `sum by (tenant_id, outcome)` answers value-vs-waste |
| `sbproxy_ai_failovers_total` | Counter | `from_provider`, `to_provider`, `reason` | Provider failover events |
| `sbproxy_ai_guardrail_blocks_total` | Counter | `category` | Guardrail block events (pii, injection, jailbreak, etc.) |
| `sbproxy_ai_safety_guardrail_verdicts_total` | Counter | `guardrail`, `class`, `backend`, `verdict` | Toxicity, jailbreak, and content-safety evaluations, including whether keyword or classifier mode produced the verdict |
| `sbproxy_ai_reasoning_policy_attempts_total` | Counter | `provider`, `outcome` | Per-provider concise-reasoning result: `native`, `prompt_fallback`, `off`, `tool_bypass`, or `code_bypass` |
| `sbproxy_ai_cache_results_total` | Counter | `provider`, `cache_type`, `result` | AI response cache results (`cache_type` is `exact` or `semantic`, `result` is `hit` or `miss`) |
| `sbproxy_ai_budget_utilization_ratio` | Gauge | `scope` | Current budget utilization as a fraction of the limit. Above 1 means the scope is over budget; the hard `on_exceed` action fires at 1 |
| `sbproxy_ai_realtime_sessions_active` | Gauge | | Currently open OpenAI Realtime API WebSocket sessions |
| `sbproxy_ai_realtime_session_duration_seconds` | Histogram | `provider`, `close_reason` | Wall-clock duration of a Realtime WebSocket session, observed at close. `close_reason` is `client_closed` or `error` |
| `sbproxy_ai_realtime_audio_seconds_total` | Counter | `provider`, `direction` | Cumulative audio seconds forwarded over Realtime sessions. Frame-exact accounting requires terminate-and-relay, which is not implemented; the dispatcher uses session wall-clock as a duration proxy on close |
| `sbproxy_ai_realtime_frames_forwarded_total` | Counter | `provider`, `direction`, `kind` | Cumulative frames forwarded over Realtime sessions (`kind` is `text` or `audio`). A future terminate-and-relay implementation would add per-frame inspection. |

Use these to build spending dashboards, set budget alerts, and track provider reliability without any application-level instrumentation.

Context compression adds selection, lever, request, token-savings,
success-time value, state-operation, and Redis-coordination metrics under
`sbproxy_ai_compression_*`. The Admin value report keeps per-model, per-lever
token and gross cost savings separate from local-serving completions and marks
the counter precision as `model_tokenizer` or `heuristic`. Exact labels and
accounting rules are in
[AI context compression metrics](ai-context-compression.md#metrics).

## Dashboards

The metrics above can be wired into any Prometheus-compatible dashboard tool. Point your existing Prometheus or Grafana setup at `/metrics` and chart the counters and histograms listed above.

The repo ships per-credential / per-tenant / per-model recording rules and alerts in `dashboards/prometheus/` (`recording-rules.yml`, `alerts.yml`), including per-tenant and per-credential spend alerts, an AI waste-ratio alert (share of requests ending in a non-served outcome), and a per-tenant/model latency alert. Sample queries:

```promql
# Spend by tenant and model, last 5m
sum by (tenant_id, model) (rate(sbproxy_ai_cost_dollars_attributed_total[5m]))

# Top credentials by cost
topk(10, sum by (api_key_id) (rate(sbproxy_ai_cost_dollars_attributed_total[5m])))

# Value vs waste: non-served share of a tenant's requests
sum by (tenant_id) (rate(sbproxy_ai_requests_attributed_total{outcome!="ok"}[5m]))
  / sum by (tenant_id) (rate(sbproxy_ai_requests_attributed_total[5m]))

# p95 model latency per tenant + model
histogram_quantile(0.95,
  sum by (le, tenant_id, model) (rate(sbproxy_ai_request_duration_attributed_seconds_bucket[5m])))
```

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
- Governed-key identity is resolved before dispatch. Its immutable public key
  id scopes any per-key budget; the plaintext key is never used as a budget
  key or stored on the realtime request context.
- Provider allow/block policy and explicit native-credential destination
  binding constrain the selected Realtime provider. `provider_type` alone
  never authorizes caller-secret forwarding. Model allow/block policy is applied to the
  query model; a required model that is absent fails closed. A
  `route_to_model` override becomes the authoritative upstream query value.
- Per-key RPM is charged once before upgrade. A credential requiring PII
  redaction fails closed because frame-transparent proxying cannot inspect and
  rewrite the session safely.
- Hard budget admission uses the action budget merged with the governed key's
  budget. `block` returns the existing 402 `budget_exceeded` JSON response,
  `log` warns and continues, and `downgrade` makes the target model
  authoritative in the upstream query.
- One trusted upstream credential is selected. A credential bound to a
  governed key wins. For admitted native traffic, the caller credential is
  used only when the selected provider sets a matching
  `accept_native_credentials_for`; otherwise selection fails before upgrade.
  All other traffic uses the selected provider's nonblank `api_key`. If no
  authoritative credential exists, the request fails closed with 503 and no
  upstream WebSocket handshake.

Credential headers are finalized after ordinary header modifiers and Lua
scripts. The proxy removes caller-controlled `Authorization`,
`Proxy-Authorization`, `DPoP`, `x-api-key`, `api-key`, `x-goog-api-key`,
`x-sb-api`, every primary carrier from `inbound.headers` and
`inbound.provider_hints`, the origin
`outbound_credential` presentation header, and the selected credential's own
header, then inserts exactly one trusted credential. This means a Lua script
cannot replace the provider credential. Credential carriers cannot claim
WebSocket handshake, tracing, or Web Bot Auth signature headers. WebSocket
handshake metadata (`Upgrade`, `Connection`, and every `Sec-WebSocket-*`
header) and `OpenAI-Beta` are preserved.

Realtime deliberately skips the origin-level `outbound_credential` and DPoP
minting paths. Those mechanisms retain their existing semantics for ordinary
HTTP proxy requests, but they neither authorize nor add a second credential
to a Realtime upgrade.

After the provider accepts the upgrade with `101 Switching Protocols`, the
active-sessions gauge `sbproxy_ai_realtime_sessions_active` ticks up. A
non-`101` provider response does not change that gauge and does not emit
session-duration or realtime billing events.

What runs during the session:
- Pingora forwards WebSocket frames byte-transparently. The proxy does not inspect individual frames. Per-frame guardrails require a future terminate-and-relay implementation.
- Admission is evaluated once. A hot policy/config update applies to new
  upgrades; a socket that already received 101 continues relaying frames and
  can complete its close handshake.
- There is no per-frame token, cost, or audio accounting. In particular, an
  accepted session is not rechecked against a budget after each frame.

What runs at session close (the `logging` hook):
- For an accepted session, the active-sessions gauge ticks down.
- `sbproxy_ai_realtime_session_duration_seconds` records the wall-clock session lifetime.
- An `AiBillingEvent` fires with `usage = AudioSeconds { seconds = wall_clock }` so operators see realtime usage on the standard billing event bus. Cost is reported as 0.0 until the realtime rate card lands in the pricing helper; downstream consumers can compute cost from the duration.

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

The proxy enforces gating before the upgrade and emits a session-end billing event after close. Per-frame inspection requires a future terminate-and-relay implementation alongside a dedicated Pingora `Service` implementation.

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
          default_model: gpt-4o-mini
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          priority: 2
          models: [claude-sonnet-4-20250514, claude-haiku-4-5]
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

## Examples in Practice

To help you get started with the AI gateway, we provide several runnable examples demonstrating these concepts:

| Example | What it is | How to use it | Outcome |
|---------|------------|---------------|---------|
| [`ai-bedrock-direct`](../examples/ai-bedrock-direct/) | Direct integration with AWS Bedrock. | Configure `type: bedrock`; SigV4 signing is operator-provided, and the gateway forwards the signed `Authorization` header verbatim. | Exposes Bedrock via the standard OpenAI-compatible API. |
| [`ai-gemini-direct`](../examples/ai-gemini-direct/) | Direct integration with Google Gemini. | Configure `type: gemini` with a Gemini API key. | Seamless integration with Gemini models without client SDK changes. |
| [`ai-model-group`](../examples/ai-model-group/) | Model pooling. | Use `model_group` in routing config. | Requests load-balance automatically across multiple underlying models. |
| [`ai-streaming`](../examples/ai-streaming/) | Streaming LLM completions. | Send requests with `stream: true`. | SBproxy streams Server-Sent Events (SSE) securely back to the client. |
| [`ai-routing-fallback`](../examples/ai-routing-fallback/) | High-availability failover. | Configure `fallbacks:` for a provider. | 5xx errors from the primary provider are transparently retried. |
| [`ai-cost-optimized`](../examples/ai-cost-optimized/) | Cost-optimized routing. | Set `strategy: cost_optimized`. | Traffic is routed to the cheapest capable model for the given prompt length. |
| [`ai-attribution-tags`](../examples/ai-attribution-tags/) | Request tagging for cost attribution. | Pass `tags:` in request headers or config. | Emitted metrics and logs include the tags for fine-grained cost allocation. |

## See also

- [providers.md](providers.md) - full provider table and per-provider model lists.
- [`examples/ai-hosted-prompts/`](../examples/ai-hosted-prompts/) - prompt
  versioning and the offline optimizer with a runnable eval set.
- [local-inference.md](local-inference.md) - classifier-sidecar models used by
  token pruning, embeddings, and safety checks.
- [scripting.md](scripting.md) - CEL and Lua reference, including AI selector and guardrail variables.
- [configuration.md](configuration.md) - general configuration model, origin schema, and the full `sb.yml` field reference.
- [features.md](features.md) - the capability tour across the whole proxy, AI and non-AI.

Deep-dive pages summarized in this guide:

- [ai-guardrail-mesh.md](ai-guardrail-mesh.md) - quorum blocking, redact-and-continue, verdict cache.
- [ai-outcome-aware-routing.md](ai-outcome-aware-routing.md) - routing on realized cost-per-success.
- [ai-policy-cel.md](ai-policy-cel.md) - one CEL expression over the AI decision pipeline.
- [ai-predictive-budget.md](ai-predictive-budget.md) - soft-landing budget degradation.
- [ai-usage-ledger.md](ai-usage-ledger.md) - hash-chained, signable spend records.
- [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md) - typed failure causes, per-error retries, hedging.
- [ai-context-compression.md](ai-context-compression.md) - ordered context compression, external summary state, degradation, and observability.
