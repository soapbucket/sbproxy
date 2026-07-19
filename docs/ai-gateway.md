# SBproxy AI gateway guide

*Last modified: 2026-07-19*

![the same OpenAI-shape request answered by OpenAI, Claude, and Gemini, switched only by Host header](assets/ai-gateway.gif)

Three providers behind one wire format ([config](../examples/ai-gateway-quickstart/)).

SBproxy includes an AI gateway that sits between your application and LLM providers. You get one API endpoint with automatic failover, cost tracking, rate limits, and programmable routing across OpenAI, Anthropic, and other providers. The proxy ships with 66 native providers behind one OpenAI-compatible API, including native Anthropic, Gemini, and Bedrock translators. You bring your own provider keys and the model name passes straight through, so you reach 200+ models without waiting on us to add them.

This guide owns the end-to-end picture: provider setup, wire compatibility, routing, streaming, budgets, caching, and per-request attribution. Seven features get a summary here and a full page of their own: the [guardrail mesh](ai-guardrail-mesh.md), [outcome-aware routing](ai-outcome-aware-routing.md), the [AI policy plane](ai-policy-cel.md), [predictive budgets with soft-landing](ai-predictive-budget.md), the [verifiable usage ledger](ai-usage-ledger.md), [LLM-aware resilience](ai-llm-aware-resilience.md), and [AI context compression](ai-context-compression.md). For those seven, the linked page is canonical; it carries the semantics, tuning advice, and reference tables.

## Provider setup

Configure one or more providers under the `action` block. Each provider needs a name, API key, and model list. Callers of hosted providers should send an explicit `model`. A `default_model` can select among locally served models and appears in model metadata, but the hosted dynamic-routing path does not inject one into a request that omitted `model`:

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
66 native providers ship in-tree alongside native translators for Anthropic, Gemini, and Bedrock. You bring your own key per provider and the `model` field passes straight through, so the gateway reaches 200+ models (and any model a provider ships next) without enumerating them. Direct adapters include `openai`, `anthropic`, `gemini`, `azure`, `bedrock`, `cohere`, `mistral`, `groq`, `deepseek`, `together`, `fireworks`, `cerebras`, `sambanova`, `nvidia`, `vertex`, `databricks`, `huggingface`, `vllm`, and `openrouter`.

Any model a listed provider serves works without extra config. For a self-hosted or proprietary endpoint, point `vllm` or any provider at it with a custom `base_url`. `openrouter` is available as one of the providers when you want many vendors behind a single key. See `providers.md` for the full per-provider table.

### Managed local and cluster models

Use `provider_type: managed_model` to route a public model name to a deployment
owned by `proxy.model_host`:

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

### token_rate

Routes to the provider with the most remaining token-per-minute capacity. Pair with per-provider token limits so the router can score headroom.

```yaml
routing:
  strategy: token_rate
```

### race

![one request fanned out to every provider, the first 2xx returned and the slow racer cancelled](assets/ai-race-routing.gif)

Lower tail latency at the cost of duplicate upstream calls ([config](../examples/ai-race-routing/)).

Fans the request out to every eligible provider in parallel, returns the first 2xx, cancels the in-flight losers. Optimizes p99 latency at the cost of N times the API spend per request. Pair with `resilience` so persistently slow providers fall out of the eligible set.

```yaml
routing:
  strategy: race
```

See [examples/ai-race](../examples/ai-race/sb.yml). Billing implications, streaming behavior, and the interaction with the failover loop are in [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md#hedged-raced-requests).

### least_token_usage

Routes to the provider with the lowest absolute observed token throughput in the current minute, regardless of any configured limit. Unlike `token_rate`, which scores remaining headroom against a declared per-provider TPM cap, this scores raw observed throughput, so it suits self-hosted vLLM or SGLang pools that do not pre-declare a token cap. Untried providers sort lowest and are explored first.

```yaml
routing:
  strategy: least_token_usage
```

### prefix_affinity

Hashes a stable prefix of the request body to an enabled provider so requests that share a prompt prefix land on the same upstream and reuse its KV cache (vLLM, SGLang). The hash is deterministic and stable across reloads as long as the provider list does not reorder. Falls back to round_robin when no prefix can be extracted.

```yaml
routing:
  strategy: prefix_affinity
```

### peak_ewma

Power-of-two-choices over observed latency: sample two eligible providers and route to the one with the lower recently observed latency. Cuts tail latency under skewed load versus always picking the single lowest-latency provider, which herds traffic. An untried provider is explored first.

```yaml
routing:
  strategy: peak_ewma
```

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

The scoring formula, warm-up behavior, and the feedback store are in [ai-outcome-aware-routing.md](ai-outcome-aware-routing.md).

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

### LLM-aware resilience

Status-code retries treat every failure the same. The gateway can instead classify each upstream failure into a typed cause (rate limit, context-window overflow, content-policy refusal, auth, malformed request) and apply a retry count per class, so a transient failure retries while a request that would only fail again goes to a fallback. Switch it on with a `retry_policy` under `resilience`:

```yaml
resilience:
  retry_policy:
    rate_limit: 3      # retry a 429 up to 3 times
    server_error: 2
    content_policy: 0  # never retry a refusal in place
```

The same block hosts the legacy `llm_aware.context_compress` shorthand, which maps to stateless `window_fit` when no explicit compression policy is present, and `content_policy_fallback`, which routes a refusal to the next provider in priority order. The failure-cause table and hedged-request behavior are in [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md). The ordered `summary_buffer` and `window_fit` pipeline is documented in [AI context compression](ai-context-compression.md).

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

![a prompt-injection attempt and an SSN-bearing prompt both rejected before any provider is contacted](assets/ai-guardrails.gif)

Input guardrails inspect the parsed prompt ahead of egress ([config](../examples/ai-guardrails/)).

The proxy supports nine guardrail types: `pii`, `injection`, `jailbreak`, `toxicity`, `content_safety`, `schema`, `regex`, `context_poisoning`, and `agent_alignment`. Guardrails run on input (before the provider call) or output (after), and they can block, flag, or rewrite content. For CEL-based request gating see the CEL section below, and [configuration.md](configuration.md#guardrails-guardrails) for the per-type field schema.

Input guardrails apply to whichever body field the surface carries user text in:

| Surface | Field guarded |
|---|---|
| `chat_completions`, `assistants`, `threads` | `body["messages"][].content` |
| `image_generation`, `image_edits`, `image_variations` | `body["prompt"]` |
| `audio_speech` | `body["input"]` |
| `reranking` | `body["query"]` |
| `moderations` | `body["input"]` |

A single guardrail block on the AI handler config covers every supported surface; the proxy picks the right field automatically based on the classified surface. Multipart-bodied surfaces (image edits, image variations, audio transcription) bypass the input-guardrail check today because their bodies are forwarded byte-transparently; output-side scanning for those surfaces is reserved for a follow-up.

### Guardrail mesh

By default the input guardrails run as a serial chain that blocks on the first detector to flag. The opt-in mesh runs them as a cascade instead, collects the full verdict set, and fuses it under a quorum rule, with optional redact-and-continue, a verdict cache, and a latency budget for the expensive classifiers. Switch it on with a `mesh` block under `guardrails`:

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

Every built-in output guardrail runs on streaming responses, and the verdicts match what the buffered path would decide for the same text. The proxy decodes each streamed delta (the JSON content, not the raw SSE frame bytes) and feeds it to a per-stream guardrail session that keeps matcher state across chunks, so a pattern split across two deltas still matches.

| Guardrail | On streaming output | How |
|---|---|---|
| `regex` | yes | runs per decoded delta; set `stream_policy: close` when a pattern must span delta boundaries |
| `pii` | yes | runs per decoded delta |
| `schema` | yes | decided on the parsed value |
| `context_poisoning` | yes | rule matches are per-message |
| `injection` | yes | case-insensitive substring set, matched over a cumulative window |
| `toxicity` | yes | operator keyword set, matched over a cumulative window |
| `jailbreak` | yes | pattern set plus the standalone-DAN word rule, matched over a cumulative window; a word split across deltas (Dan + iel) never false-blocks |
| `content_safety` | yes | category keyword sets, matched over a cumulative window |
| `agent_alignment` | yes | streamed `tool_calls` deltas are assembled per call and judged when each call completes; block mode holds tool-call frames back until their call is judged, while text deltas flow |

A block terminates the stream: the violating content and everything after it is withheld, and the response is never admitted to any cache. Headers are already sent by then, so the client sees the stream cut rather than an error status. Input guardrails always run against the full request regardless of `stream`.

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

### Context-poisoning guardrail

![a clean tool result summarised normally, then a tool result carrying an embedded instruction blocked](assets/ai-context-poisoning.gif)

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

`mode: flag` records every violation as a log line + access-log entry but lets the request through; once the operator has tuned the rule lists they flip to `mode: block` so the dispatch loop short-circuits to a 400 on the next violation. Tool calls in any of three shapes are recognised: OpenAI (`tool_calls[*].function.name` + `function.arguments`), Anthropic (`tool_calls[*].name` + `input`), and MCP (`tool_calls[*].tool` or `tool_calls[*].name` + `arguments`). The forbidden-substring scan is case-insensitive against the JSON encoding of whichever argument field is present.

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

## Budgets

Set token or dollar caps that apply across a workspace, a single virtual key, an end user, a model, an origin, or a metadata tag. The `budget` block sits under `action` and is parsed by `BudgetConfig` in `crates/sbproxy-ai/src/budget.rs`.

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
- Multiple limits on the same scope with different `period` values (for example daily and monthly) accrue in separate window buckets. Each limit is checked against its own key; the tightest binding that is exceeded fires first in declaration order. There is no separate org/team/project hierarchy tracker: `BudgetScope` is the single enum (`workspace`, `api_key`, `user`, `model`, `origin`, `tag`) used by `BudgetLimit`.

### Soft-landing (predictive budgets)

A hard budget is a cliff: requests pass until the cap, then block at 100%. The opt-in `soft_landing` block tapers instead. Past `warn_at` the request is allowed and a warning is logged; past `downgrade_at` the model is rewritten to a cheaper target; at the cap the hard `on_exceed` action takes over as before.

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

Issue per-team or per-app keys that the gateway validates locally. Each key can pin a provider, restrict models, set its own request rate, carry its own budget ceiling, and tag requests for downstream attribution. The shipped shape is a `credentials:` list of `type: ai_provider` entries next to the origin's `action:` block; the same block also lives at `tenants[].credentials` and `proxy.credentials` scope, with origin shadowing tenant shadowing proxy for entries that share a `name`. The legacy `virtual_keys:` key is rejected at config compile with a pointer to [migration-credentials.md](migration-credentials.md).

Set `action.require_governed_key: true` to reject requests that do not resolve
to a governed public key identity on that origin. Dynamic mutation, the full
policy field contract, effective-policy preview, and fail-closed behavior are
documented in [Dynamic key management](key-management.md).

Stored-key token-per-minute and lifetime token or cost caps currently settle
only on standard JSON POST inference surfaces when the provider response
reports parseable usage. Multipart and non-POST requests can dispatch, but do
not settle those stored-key counters. Settlement for those surfaces and strict
multi-node reservations are deferred to WOR-1845. Treat the caps as advisory,
not a strict ceiling, for multipart, non-POST, or concurrent multi-node traffic.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
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
| `attrs` | object | unset | Attribution: `project`, `user`, `team`, `cost_center`, `tags`, `metadata`, and `budget` (`max_tokens`, `max_cost_usd`, `reset`). The per-key budget is independent of the global `budget` block. |
| `route_to_model` | string | unset | Pins every request from this credential to one model. |
| `compression_profile` | string | unset | Selects `on`, `off`, or a named compression profile declared by this AI route. |
| `inject_tools` | list | `[]` | Provider-native tool definitions injected into requests from this credential. |

At compile time each `ai_provider` credential is lowered onto the runtime key registry (`VirtualKeyConfig` in `crates/sbproxy-ai/src/identity.rs`) that AI dispatch reads. Per-key usage shows up in the attributed spend metrics: filter or `sum by (api_key_id)` on `sbproxy_ai_requests_attributed_total`, `sbproxy_ai_tokens_attributed_total`, and `sbproxy_ai_cost_dollars_attributed_total`.

## Caching

Two caches run on the serving path: the semantic cache and the idempotency middleware, both described below. Cache hit and miss counts land in `sbproxy_ai_cache_results_total`.

### Exact prompt cache (design stage)

An exact-match prompt cache is design-stage library code, not part of the serving path: `prompt_cache.rs` in `crates/sbproxy-ai` implements SHA-256 keying over the canonicalised JSON `messages` array and detection of Anthropic's native `cache_control` blocks, but nothing in the dispatch pipeline calls it, and there are no YAML knobs for it. For byte-identical replay of retried requests today, use the idempotency middleware below; for near-duplicate prompts, use the semantic cache.

### Semantic cache

![a first prompt logging x-semcache MISS, then a reworded equivalent served as HIT in a fraction of the time](assets/semantic-cache.gif)

Different words, same meaning, no provider call ([config](../examples/semantic-cache-openai/)).

Serves cached responses to prompts that mean the same thing without a provider call. Implemented in `semantic_cache.rs` as `EmbeddingCache`: on a miss the dispatcher embeds the prompt once via the configured source, and on later requests a cosine-similarity scan over the stored vectors replays the closest response that meets `threshold`. Vectors are L2-normalised at insert time, eviction is LRU with a `max_entries` cap, entries past `ttl_secs` are dropped lazily on lookup, and every entry is scoped to the calling tenant and credential so one caller's cached response is never replayed to another. Embedding failures fail open to an uncached upstream call.

A request bypasses semantic-cache reads and writes when it carries an explicit
header, governed-key, or CEL compression selector; when its route declares
named profiles; when the route default has an explicit input budget; or when a
captured session could use `summary_buffer`. The decision happens before
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

Auth defaults to `Authorization: Bearer ${api_key}`. For endpoints that expect a different header (Azure `api-key`, an `x-api-key` gateway), set `auth_header` and clear `auth_prefix`; endpoints that need extra headers (such as OpenRouter's `HTTP-Referer` / `X-Title`) take a `headers` list of name/value pairs, sent verbatim. For header-only auth, omit `api_key` and carry the credential in `headers`. The endpoint base URL joins `/v1/embeddings` the same way chat provider base URLs do (an overlapping trailing `/v1` is collapsed). On any embedding error the lookup degrades to an uncached upstream call. See [local-inference.md](local-inference.md) and [examples/semantic-cache-openai](../examples/semantic-cache-openai/sb.yml).

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
| `models` | `GET /v1/models` and `GET /models` are served locally for every AI origin as an OpenAI `{"object": "list", "data": [...]}` logical listing. Other model endpoints use the ordinary GET dispatch path and have no unified response shape. |
| everything else | passthrough on the providers listed in the table; clients see the upstream's native response shape |

The local list contract is deliberate: it gives clients one topology-free
discovery shape across ordinary and managed providers without pretending to
preserve provider-specific metadata. Call the provider directly when native
model-list fields are required.

### Method coverage

The gateway accepts any standard HTTP method for any supported surface. GET, POST, PUT, DELETE, PATCH, HEAD, and OPTIONS all dispatch through the same provider-selection and observability surface. Non-POST methods do not engage the standard JSON POST inference pipeline, so they do not perform JSON body parsing or stored-key token and cost settlement. Method-aware dispatch is what makes `DELETE /v1/assistants/{id}`, `POST /v1/threads/{id}/runs/{id}/cancel`, and the other non-POST verbs work end-to-end. Strict settlement for these methods is deferred to WOR-1845.

### Multipart bodies

Image edits, image variations, audio transcription, and audio translation send multipart request bodies. The proxy detects multipart by inspecting the inbound `Content-Type` header; when it starts with `multipart/`, the body is forwarded via `AiClient::forward_bytes` with the original Content-Type preserved. A governed key's `route_to_model` rewrites only the bounded multipart `model` part before forwarding; every other part remains byte-for-byte. Provider format translation (Anthropic, etc.) does not run for multipart, since these surfaces are OpenAI-only. Multipart responses do not currently settle stored-key token-per-minute or lifetime token and cost counters; that work is deferred to WOR-1845.

### Per-surface configuration

Per-surface knobs live under `per_surface_rate_limits` (see [Per-surface rate limits](#per-surface-rate-limits)) and apply automatically based on the classified surface. Surfaces have no dedicated YAML config block beyond that; they share the top-level `providers`, `routing`, `budget`, `model_rate_limits`, `max_concurrent`, and `guardrails` settings, plus the origin's `credentials:` list.

### Reranking

`reranking` is not enterprise-gated. The OSS build classifies the surface, dispatches it when a configured provider supports it (Cohere today), and captures the request's document count for per-unit billing. The only gate is the capability check above: when no configured provider supports reranking, the proxy returns 501 before any upstream call, same as every other surface.

## Context handling

The shipped answer to a prompt that approaches a model's context window is an
ordered, per-handler compression pipeline. `summary_buffer` compacts eligible
older text into externally stored running summary state. `window_fit` can keep
the legacy model-window behavior or enforce a positive `input_budget_tokens`
target with the target-model counter. Levers run in declaration order, only
strict token reductions commit, and a skip or runtime failure leaves the last
committed messages in place while later levers continue.

### Context compression (shipped)

Configure the route default in `compression.levers` and optional named
pipelines in `compression.profiles`. A request chooses `on`, `off`, or a named
profile with precedence `X-Compression` header, governed key, CEL, then route
default. Explicit-budget fitting preserves leading system and developer
instructions, the newest complete turn, contiguous recent history, and
OpenAI/Anthropic tool-call groupings.

A stateful summary requires a captured session ID and the configured Redis L2
service. Request workers retain no canonical session summary in process.
`proxy.cluster.replication` provides a durable replicated mesh substrate, but
compression's legacy mesh adapter is not integrated with or validated against
its `ReplicatedStore` session and Admin lifecycle semantics. Public
`backend: mesh` selection therefore remains rejected as a separate, unshipped
integration. There is no OmniRoute dependency, import, or migration path.
The legacy `resilience.llm_aware.context_compress` switch remains a shorthand
for one `window_fit` lever only when the explicit block is absent.

The complete configuration, session and structured-content safety rules,
Redis state guarantees, failure table, metrics, logs, and PromQL are
in [AI context compression](ai-context-compression.md).

### Context relay (design stage)

Context relay is design-stage: nothing on the serving path uses it. `crates/sbproxy-ai/src/context_relay.rs` implements a thread-safe map of session ID to message history, intended to replay prior messages to a new provider when the router rotates mid-session so the conversation does not reset. The router does not call it today, and there is no YAML config for it.

### Context overflow (design stage)

The overflow decision layer is design-stage: `crates/sbproxy-ai/src/context_overflow.rs` ships a registry of context windows for the OpenAI, Anthropic, Gemini, Mistral, and Llama families plus typed overflow actions (`Error`, `FallbackToLarger`, `Truncate`), but no dispatch code drives those actions and a `context_overflow:` block in the config is ignored. The one part of the module that does run is its window registry, which context compression consults to size a model's budget. The shipped way to handle overflow is `resilience.llm_aware.context_compress` above.

## Streaming analytics

Per-stream timing on the live path is limited to Time to First Token: the dispatch pipeline measures TTFT on streaming responses and records it to the `sbproxy_ai_ttft_seconds` histogram, labelled by provider and model.

The richer per-stream tracker is design-stage: `crates/sbproxy-ai/src/streaming_analytics.rs` ships a `StreamTracker` (start, first-token, and last-token instants, with derived tokens-per-second and average inter-token latency) and a `StreamRegistry` map of in-flight streams, but nothing on the serving path constructs either type today.

## Structured output (design stage)

Gateway-side structured-output validation is design-stage: `crates/sbproxy-ai/src/structured_output.rs` implements the validator, but no dispatch code calls it and a `structured_output:` block in the config is ignored. Provider-enforced JSON output still works where the upstream supports it: `response_format` passes through to OpenAI-compatible upstreams (the Gemini translator drops it as an unsupported knob). What does not exist is the proxy re-checking the response.

The library code covers the intended flow: `extract_json` strips ` ```json ` and ` ``` ` fences before parsing so models that wrap output in markdown still validate, `validate_response` does structural checks (required-field presence and per-property type checks for `string`, `number`, `integer`, `boolean`, `array`, `object`, `null`; no `$ref` or `oneOf`), and `build_schema_instruction` renders the schema into a system-prompt retry instruction for a validation-failure retry loop.

## OpenAI surface-area modules

The `sbproxy-ai` crate ships shape definitions and lightweight handlers for the OpenAI surface beyond chat completions: assistants, threads, batch jobs, image generation, audio, fine-tuning, realtime sessions, and structured output. The shapes are stable and round-trip through `serde_json`. Path classification on the live dispatch path is done by two functions: `classify_surface(method, path)` in `crates/sbproxy-ai/src/handler.rs` labels every request with an `AiSurface` (the full table above), and `parse_endpoint(path)` in `crates/sbproxy-ai/src/api_routes.rs` types a narrower endpoint subset (chat, embeddings, models, rerank, moderations, image generation, audio transcription, audio speech) for the per-provider capability check, falling back to `Unknown` for the rest. There is no `parse_ai_path` function. The remaining shapes are present so plugin authors can build on top of them.

The subsections below describe what each module contributes today.

### `assistants`

Assistants requests are served by the generic surface dispatch described above: `classify_surface` labels them, and the gateway forwards them passthrough to a provider that supports the surface (OpenAI). There is no `assistants:` config key; writing one is silently ignored, since the action config drops unknown fields rather than rejecting them.

The module itself is design-stage shape code with no serving-path callers: `AssistantHandler::route_request(path, method)` classifies a request into `CreateAssistant`, `ListAssistants`, `GetAssistant(id)`, `CreateThread`, `CreateMessage(thread_id)`, `CreateRun(thread_id)`, `GetRun(thread_id, run_id)`, or `Unknown` (optional `/v1` prefix stripped), and `AssistantConfig { enabled: bool }` is the intended on/off shape. Nothing constructs either today. Source: `crates/sbproxy-ai/src/assistants.rs:AssistantHandler`.

### `threads`

Threads requests, like assistants, are proxied passthrough by the generic surface dispatch. The `ThreadStore` module is design-stage with no serving-path callers: it implements an in-memory, mutex-backed store of `Thread { id, created_at, metadata }` and ordered `ThreadMessage { id, thread_id, role, content, created_at }`, intended for gateway-local session continuity, but nothing constructs it today and there is no YAML field for it. Source: `crates/sbproxy-ai/src/threads.rs:ThreadStore`.

### `batch`

Batch requests are proxied passthrough by the generic surface dispatch (`batches` in the surface table). The module's `BatchJob` shape (id, status, created_at, completed_at, total_requests, completed_requests, failed_requests, metadata), `BatchStore` trait, and `MemoryBatchStore` implementation (status lifecycle `pending`, `in_progress`, `completed`, `failed`, `cancelled`) are design-stage code that nothing constructs today; there is no `batch:` YAML block. Source: `crates/sbproxy-ai/src/batch.rs`.

### `image`

Request and response shapes for image generation, edit, and variation. `ImageGenerationRequest { prompt, model, size, n }` and `ImageGenerationResponse { images: Vec<ImageData> }`, where each `ImageData` carries either a `url` or a base-64 `b64_json` payload depending on the provider's `response_format`. `/v1/images/generations` is routed by `api_routes.rs`; the per-call dispatch is built by the runtime. No dedicated YAML knobs. Source: `crates/sbproxy-ai/src/image.rs`.

### `audio`

Request and response shapes for audio transcription and speech synthesis. `TranscriptionRequest { file_url, model, language }`, `TranscriptionResponse { text, duration }`, and `SpeechRequest { input, model, voice }`. `/v1/audio/transcriptions` and `/v1/audio/speech` are recognised by `api_routes.rs`. No dedicated YAML knobs; the audio dispatcher reuses the top-level provider list and routing strategy. Source: `crates/sbproxy-ai/src/audio.rs`.

### `finetune`

Fine-tuning requests are proxied passthrough by the generic surface dispatch (`fine_tuning` in the surface table). There is no `finetune:` config key; writing one is silently ignored. The module's `FinetuneHandler::route_request(path, method)` classifier (`CreateJob`, `ListJobs`, `GetJob(id)`, `CancelJob(id)`, `ListEvents(id)`, `Unknown`) and `FinetuneConfig { enabled: bool }` shape are design-stage code with no serving-path callers. Source: `crates/sbproxy-ai/src/finetune.rs:FinetuneHandler`.

### `realtime`

Realtime WebSocket proxying ships and is documented in the [Realtime](#realtime-1) section below: the gateway gates the upgrade on provider capability, applies `per_surface_rate_limits.realtime`, and forwards frames byte-transparently. There is no `realtime:` config key on the action; writing one is silently ignored. The knobs that exist are the provider list (a provider that supports Realtime must be configured) and the per-surface rate limit.

The `realtime.rs` module itself is design-stage shape code with no serving-path callers: `RealtimeConfig { enabled, model }`, `RealtimeSession { session_id, model, created_at, status }`, and `RealtimeEvent { event_type, data }` round-trip through serde but nothing constructs them. Source: `crates/sbproxy-ai/src/realtime.rs`.

### `structured_output`

Design-stage; covered above under [Structured output](#structured-output-design-stage). The validator functions (`extract_json`, `validate_response`, `build_schema_instruction`) have no serving-path callers and there is no `structured_output:` config key. Source: `crates/sbproxy-ai/src/structured_output.rs`.

## Per-request attribution

The gateway records provider, model, token counts, and estimated cost for every AI request and exposes them through Prometheus metrics (see below). Direct response headers for these fields are not emitted today.

### Authoritative identity: tenant and credential

The attributed AI request, token, and cost metric families are partitioned by
two authoritative identity dimensions in addition to provider/model:

- `tenant_id`: the tenant the request resolved to (`__default__` in single-tenant deployments), taken from the matched origin.
- `api_key_id`: a stable id for the credential (API key) that authenticated the request and injected its policy. This is the join key that ties spend back to the agent routing traffic through the gateway.

Both are sourced from the resolved principal, never from a request header, so a caller cannot misattribute its own spend. The business attribution tags (`project`, `feature`, `team`, ...) remain caller-overridable through `SB-Attr-*` headers over the credential defaults; the trust dimensions above do not.

`api_key_id` resolution:

- For an `api_key` auth credential, set a stable id explicitly with `key_id:` on the entry. When omitted, the gateway derives a non-reversible `sk_<hex>` fingerprint of the secret so the key is still attributable. The raw secret never reaches a metric label, span, or log line.
- For a config-defined virtual key, the operator-supplied virtual-key `name` is
  used. For an admin-managed governed key, the immutable public `key_id` is
  used instead of its mutable display name.

```yaml
auth:
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

Verify the chain (and, with the seed, the signatures) with `sbproxy ai ledger verify <path>`. The entry format, dedup semantics, durability guarantees, and the verify CLI are in [ai-usage-ledger.md](ai-usage-ledger.md).

## Token usage metrics

The proxy exposes aggregate AI usage as Prometheus metrics. The `/metrics` endpoint is served on the proxy listener itself and on the admin listener when the admin API is enabled; there is no separate `telemetry.bind_port` key. The following counters and gauges appear under the `sbproxy_ai_*` namespace:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sbproxy_ai_surface_requests_total` | Counter | `surface`, `method` | Total AI requests partitioned by classified surface (chat completions, assistants, image generation, ...) and HTTP method |
| `sbproxy_ai_surface_request_duration_seconds` | Histogram | `surface`, `method` | Per-surface request latency. Buckets match `sbproxy_ai_request_duration_seconds` for side-by-side dashboards |
| `sbproxy_ai_cost_usd_micros_total` | Counter | `provider`, `model`, `tenant_id` | Derived request cost in micro-USD (`1e-6` USD); mirrored to OTLP as `sbproxy.ai.cost_usd_micros` when `telemetry.export_metrics` is enabled |
| `sbproxy_ai_request_duration_seconds` | Histogram | `provider`, `model` | End-to-end AI request latency. Now recorded on the live path for every accepted upstream response |
| `sbproxy_ai_inter_token_latency_seconds` | Histogram | `provider`, `model` | Average inter-token latency (TPOT) per streaming response, derived from the generation window. Completes the TTFT / TPOT / throughput serving triple |
| `sbproxy_ai_tokens_attributed_total` | Counter | `provider`, `model`, `surface`, `direction`, `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id` | Per-attribution token spend. `sum by (tenant_id, model)` for multi-tenant multi-model token volume |
| `sbproxy_ai_cost_dollars_attributed_total` | Counter | same as above minus `direction` | Per-attribution USD spend. `sum by (api_key_id)` for per-credential chargeback |
| `sbproxy_ai_request_duration_attributed_seconds` | Histogram | `provider`, `model`, `surface`, `tenant_id`, `api_key_id` | Model latency sliceable per tenant / credential / model. `histogram_quantile(0.95, sum by (le, tenant_id, model) (rate(..._bucket[5m])))` |
| `sbproxy_ai_requests_attributed_total` | Counter | `provider`, `model`, `surface`, `tenant_id`, `api_key_id`, `outcome` | One row per request with a closed `outcome` label (`ok`, `guardrail_block`, `content_filter`, `budget_exceeded`, `rate_limited`, `timeout`, `upstream_5xx`, `auth_denied`, `client_error`, `other`). `sum by (tenant_id, outcome)` answers value-vs-waste |
| `sbproxy_ai_failovers_total` | Counter | `from_provider`, `to_provider`, `reason` | Provider failover events |
| `sbproxy_ai_guardrail_blocks_total` | Counter | `category` | Guardrail block events (pii, injection, jailbreak, etc.) |
| `sbproxy_ai_cache_results_total` | Counter | `provider`, `cache_type`, `result` | AI response cache results (`cache_type` is `exact` or `semantic`, `result` is `hit` or `miss`) |
| `sbproxy_ai_budget_utilization_ratio` | Gauge | `scope` | Current budget utilization as a 0 to 1 ratio |
| `sbproxy_ai_realtime_sessions_active` | Gauge | | Currently open OpenAI Realtime API WebSocket sessions |
| `sbproxy_ai_realtime_session_duration_seconds` | Histogram | `provider`, `close_reason` | Wall-clock duration of a Realtime WebSocket session, observed at close. `close_reason` is `client_closed` or `error` |
| `sbproxy_ai_realtime_audio_seconds_total` | Counter | `provider`, `direction` | Cumulative audio seconds forwarded over Realtime sessions. Frame-exact accounting requires terminate-and-relay (not on the OSS path); the OSS dispatcher uses session wall-clock as a duration proxy on close |
| `sbproxy_ai_realtime_frames_forwarded_total` | Counter | `provider`, `direction`, `kind` | Cumulative frames forwarded over Realtime sessions (`kind` is `text` or `audio`). Reserved for a future enterprise terminate-and-relay path |

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

## See also

- [providers.md](providers.md) - full provider table and per-provider model lists.
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
