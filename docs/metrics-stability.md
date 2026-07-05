# Metrics stability

*Last modified: 2026-06-23*

Naming conventions, stability guarantees, and the full catalogue of metrics emitted by SBproxy.

---

## Naming convention

- Prefix: all metrics use `sbproxy_`.
- Case: snake_case.
- Units: encoded in the metric name suffix, following Prometheus conventions:
  - `_seconds` for durations
  - `_bytes` for byte counts
  - `_total` for cumulative counters (monotonically increasing)
  - `_ratio` for ratios (0.0 to 1.0)
  - `_dollars` for monetary values
- Gauges: metrics without `_total` that represent a current state (e.g. `sbproxy_active_connections`).
- Histograms: duration and size metrics are histograms with `_bucket`, `_sum`, and `_count` suffixes exposed automatically by the metrics library.

---

## Stability tiers

### `stable`

A `stable` metric will not be renamed or removed without a deprecation period.

- Renaming or removing a stable metric requires: announce deprecation in the next minor release (adding a `_DEPRECATED` alias), then remove it in the following major release.
- Label names on stable metrics are also stable. New labels may be added in minor releases. Removing labels follows the same deprecation process.

### `beta`

A `beta` metric is functional. Its name or labels may still change in a minor release with a changelog entry.

### `alpha`

An `alpha` metric may be renamed, relabeled, or removed in any release without notice.

---

## Metric catalogue

All metrics below are currently `stable`.

### HTTP traffic

#### `sbproxy_requests_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of HTTP requests processed by the proxy, including all origins. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname (origin key from sb.yml) | `api.example.com` |
| `method` | HTTP method of the request | `GET`, `POST` |
| `status` | HTTP status code returned to the client | `200`, `404`, `502` |

---

#### `sbproxy_request_duration_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | End-to-end request duration in seconds, from first byte received to last byte sent. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `method` | HTTP method | `GET`, `POST` |
| `status` | HTTP status code | `200`, `502` |

---

#### `sbproxy_phase_duration_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | Intra-request phase duration in seconds. Splits `sbproxy_request_duration_seconds` into the parts of the pipeline that contributed: time in the auth provider, time waiting for the first upstream byte, time running response transforms. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `phase` | Phase name (closed enum, additive) | `auth`, `upstream_ttfb`, `response_filter` |
| `origin` | Virtual hostname | `api.example.com` |

**Bucket schedule:** `0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0`. Identical to `sbproxy_request_duration_seconds` so dashboards can overlay phase vs end-to-end without bucket interpolation.

**Phase definitions:**

* `auth` is from the request's first byte to the moment the auth provider returns (allow, deny, or challenge). Not emitted for origins without an auth provider.
* `upstream_ttfb` is from the request's first byte to the first byte of the upstream response header. Not emitted for requests that never reach an upstream (early auth/policy short-circuit, cache hit).
* `response_filter` is from the first upstream byte to the end of `response_filter`. Not emitted when no response_filter ran.

The same observations appear as `auth_ms` / `upstream_ttfb_ms` / `response_filter_ms` on the access log; this histogram is the aggregate view.

---

### Agent detection

#### `sbproxy_agent_detect_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Number of agent-detect scorer verdicts emitted by the request pipeline. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `agent_id` | Matched agent id, or the empty-string sentinel when the scorer produced an anonymous verdict | `claude-code-cli`, `` |
| `provenance` | Identity provenance tier | `signed`, `unsigned-named`, `unsigned-anonymous` |

---

#### `sbproxy_agent_detect_score`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | Distribution of agent-detect scores, scaled 0-100. |

**Labels:** none.

**Bucket schedule:** `0, 5, 10, 20, 40, 60, 80, 90, 95, 100`.

---

#### `sbproxy_agent_detect_inference_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | In-process agent-detect scorer latency in seconds. |

**Labels:** none.

**Bucket schedule:** `0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.002, 0.005, 0.01`.

---

#### `sbproxy_active_connections`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **stable** |
| Description | Current number of active client connections being handled by the proxy. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |

---

#### `sbproxy_bytes_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total bytes transferred through the proxy. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `direction` | Transfer direction relative to the proxy | `inbound` (client -> proxy), `outbound` (proxy -> client) |

---

### Authentication

#### `sbproxy_auth_results_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total authentication attempts and their outcomes. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `auth_type` | Authentication plugin used | `basic_auth`, `api_keys`, `oauth2`, `jwt` |
| `result` | Outcome of the authentication check | `allow`, `deny`, `error` |

---

### Policies

#### `sbproxy_policy_triggers_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of times a policy plugin matched and took an action on a request. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `policy_type` | Policy plugin name | `rate_limit`, `ip_filter`, `waf`, `cel`, `lua` |
| `action` | Action taken by the policy | `allow`, `block`, `throttle`, `log` |

---

### Caching

#### `sbproxy_cache_results_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total response cache lookups and their results. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `result` | Cache lookup outcome | `hit`, `miss`, `stale`, `bypass` |

---

### Circuit breaker

#### `sbproxy_circuit_breaker_transitions_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of circuit breaker state transitions for upstream connections. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `from_state` | State before the transition | `closed`, `open`, `half_open` |
| `to_state` | State after the transition | `closed`, `open`, `half_open` |

---

### AI gateway

#### `sbproxy_ai_requests_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total AI inference requests forwarded by the proxy. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic`, `google`, `cohere` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet`, `gemini-3.5-flash` |
| `status` | Request outcome | `success`, `error`, `timeout`, `rate_limited` |

---

#### `sbproxy_ai_surface_requests_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total AI gateway requests, partitioned by classified surface (chat completions, assistants, image generation, etc.). Additive sibling of `sbproxy_ai_requests_total`. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `surface` | Classified AI surface from `AiSurface::label()` | `chat_completions`, `assistants`, `threads`, `batches`, `fine_tuning`, `files`, `realtime`, `image_generation`, `image_edits`, `image_variations`, `audio_transcription`, `audio_speech`, `moderations`, `reranking`, `embeddings`, `models`, `unknown` |
| `method` | Inbound HTTP method | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD` |

A `status` partition is reserved for a future phase that emits surface-aware billing events with the final response status.

---

#### `sbproxy_ai_surface_request_duration_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | Per-surface request latency in seconds. Recorded via a Drop guard on every exit path of `handle_ai_proxy`, including early-return validation failures. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `surface` | Classified AI surface | (same value set as `sbproxy_ai_surface_requests_total`) |
| `method` | Inbound HTTP method | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD` |

Buckets: `0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0`. Matches the bucket schedule of the per-provider `sbproxy_ai_request_duration_seconds` for cross-cut dashboards.

---

#### `sbproxy_ai_tokens_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total AI tokens processed. Counts input and output tokens separately. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet` |
| `direction` | Token direction | `input`, `output` |

---

#### `sbproxy_ai_cost_dollars_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Cumulative estimated cost of AI requests in US dollars, based on the provider pricing catalog. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet` |

---

#### `sbproxy_ai_price_source_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **alpha** |
| Description | Cost estimates by the price-table layer that produced the price (WOR-1710). A high `fallback` share means models are being billed at the pessimistic $5/$5 default, a stale-catalog or missing-rate-card signal. |

**Labels:** `source` (`config`, `rate_card`, `catalog`, `fallback`).

---

#### `sbproxy_ai_cost_usd_micros_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Cumulative derived AI request cost in micro-USD (`1e-6` USD), based on the provider pricing catalog. This is the exact integer-cost surface used for tenant spend dashboards and the optional OTLP metric mirror (`sbproxy.ai.cost_usd_micros`). |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet` |
| `tenant_id` | Resolved tenant id for the matched origin | `acme`, `__default__` |

---

#### `sbproxy_ai_tokens_attributed_total` / `sbproxy_ai_cost_dollars_attributed_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Per-attribution token and USD spend, so an operator can answer "what did project / feature / team X spend this week" from Prometheus. Fed from the single AI billing choke point, so unary, streaming, and non-chat surfaces (embeddings, image, audio, reranking) plus closed realtime sessions all contribute. Cache hits contribute the cached token count under `direction=cache_read` at zero cost. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider`, `model` | Provider + model | `openai` / `gpt-4o` |
| `surface` | Classified AI surface the spend came from, so non-chat spend is distinguishable on the dashboard | `chat_completions`, `embeddings`, `image_generation`, `audio_speech`, `reranking`, `realtime` |
| `direction` | Token kind (tokens metric only) | `input`, `output`, `cache_read` |
| `project`, `feature`, `team`, `agent_type`, `environment` | Bounded business attribution dimensions, resolved from the credential `attrs:` + `SB-Attr-*` headers | `checkout`, `prod`, `runtime` |
| `tenant_id` | Tenant the request resolved to. Sourced from the resolved principal, never from a request header, so it cannot be spoofed | `acme`, `__default__` |
| `api_key_id` | Stable id of the credential (API key) that injected the policy: an operator-supplied id or a derived `sk_<hex>` fingerprint of the secret. Never the raw secret. Empty for un-credentialed traffic | `billing-prod-01`, `sk_9f2a1c4b77e0` |

The `tenant_id` and `api_key_id` dimensions make per-tenant, multi-model, per-credential spend a single PromQL: `sum by (tenant_id, model) (rate(sbproxy_ai_tokens_attributed_total[5m]))` or `sum by (api_key_id) (sbproxy_ai_cost_dollars_attributed_total)`.

High-cardinality dimensions (customer, trace_id, okr, risk_tier) are deliberately kept **off** the metric labels and ride on the access log's `attribution` map / the trace span instead.

---

#### `sbproxy_ai_audio_seconds_attributed_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Audio seconds consumed by realtime and audio surfaces, partitioned by the same attribution set as the token/cost metrics. Realtime sessions consume seconds rather than tokens and have no catalogue price yet, so neither the token nor the cost attributed counter captures them; this sibling gives those surfaces an attributed-spend presence so a project / team dashboard can see realtime + audio usage. |

**Labels:** `provider`, `model`, `surface` (`realtime`, `audio_transcription`, `audio_speech`), `project`, `feature`, `team`, `agent_type`, `environment`, `tenant_id`, `api_key_id`.

---

#### `sbproxy_ai_requests_attributed_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | One row per AI request, partitioned by the authoritative identity dimensions plus a closed `outcome` label, so token / cost spend can be reconciled against value-vs-waste. Recorded once per request in the logging phase (independent of whether access-log emission is enabled), so blocked and failed requests are counted too. `sum by (tenant_id, outcome) (...)` answers "how much of tenant X's traffic ended in a refusal / guardrail block / budget block / error". |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider`, `model`, `surface` | Provider, model, classified surface | `openai` / `gpt-4o` / `chat_completions` |
| `tenant_id`, `api_key_id` | Authoritative identity, as on the attributed token/cost metrics | `acme` / `billing-prod-01` |
| `outcome` | Closed set: `ok`, `guardrail_block`, `content_filter`, `budget_exceeded`, `rate_limited`, `timeout`, `upstream_5xx`, `auth_denied`, `client_error`, `other`. Derived from the final HTTP status, with an AI-specific override at block sites so a guardrail block (wire status 400/403) is not mislabeled | `ok`, `guardrail_block`, `budget_exceeded` |

---

#### `sbproxy_ai_request_duration_attributed_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **beta** |
| Description | Upstream model latency, partitioned by surface plus the authoritative identity dimensions, so p50 / p95 latency is sliceable per tenant, per credential, and per model rather than only globally per provider/model. Recorded on the accepted upstream response for all surfaces. The sibling global histogram `sbproxy_ai_request_duration_seconds{provider, model}` is observed from the same call site. |

**Labels:** `provider`, `model`, `surface`, `tenant_id`, `api_key_id`. Buckets match `sbproxy_ai_request_duration_seconds`: `0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0`.

Example: `histogram_quantile(0.95, sum by (le, tenant_id, model) (rate(sbproxy_ai_request_duration_attributed_seconds_bucket[5m])))`.

---

#### `sbproxy_ai_wasted_tokens_total` / `sbproxy_ai_wasted_cost_dollars_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Tokens (and estimated USD) spent upstream that bought no served outcome, classified by waste detector. Observational only: the gateway flags the spend, it does not block it. The matching billing event still records the real spend, so these counters are an overlay, not a substitute. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `kind` | Waste detector that fired | `duplicate_request`, `abandoned_stream`, `validation_failed`, `context_bloat`, `failover_loser` |
| `provider`, `model` | Provider + model that absorbed the spend | `openai` / `gpt-4o` |
| `surface` | Classified AI surface | `chat_completions`, `realtime` |
| `project`, `feature`, `team`, `agent_type`, `environment` | Same bounded attribution set as the attributed-spend metrics | `checkout`, `prod`, `runtime` |

Detector meanings: `abandoned_stream` fires when a stream closes before the upstream signalled completion (client cancel or truncation); `validation_failed` fires when an output guardrail or the stream-safety classifier rejects a response whose tokens were already consumed; `failover_loser` fires for a cascade tier that returned a body but lost (5xx, refusal, or below the quality threshold) to a later tier; `duplicate_request` and `context_bloat` are reserved for the dedup and rolling-median observers.

---

#### `sbproxy_ai_failovers_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of AI provider failover events where the proxy switched to a backup provider. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `from_provider` | Provider that failed | `openai` |
| `to_provider` | Provider selected as fallback | `anthropic` |
| `reason` | Reason the primary provider was bypassed | `error`, `timeout`, `rate_limited`, `budget_exceeded` |

---

#### `sbproxy_ai_guardrail_blocks_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of requests blocked by the AI guardrail engine. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `category` | Guardrail category that triggered | `pii`, `toxicity`, `off_topic`, `prompt_injection` |

---

#### `sbproxy_ai_ttft_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | Streaming time to first token, in seconds. Recorded once per streaming response when the first token arrives. Buckets cover the typical 50ms to 30s range. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet` |

---

#### `sbproxy_ai_provider_errors_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total per-provider error events. Incremented at each site where an upstream interaction fails or returns a non-success status. The label set is intentionally narrow so the dashboard can group by provider; raw upstream error strings are mapped to a small stable set of `error_kind` values before recording. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `error_kind` | Stable error class | `transport`, `timeout`, `http_4xx`, `http_5xx`, `parse` |

---

#### `sbproxy_ai_cache_results_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total AI response cache lookups and their results, covering both exact-match and semantic (vector) caches. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `cache_type` | Type of cache layer consulted | `exact`, `semantic` |
| `result` | Lookup outcome | `hit`, `miss` |

---

#### `sbproxy_ai_budget_utilization_ratio`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **stable** |
| Description | Current AI spend as a fraction of the configured budget limit (0.0 = no spend, 1.0 = budget fully consumed). Values above 1.0 indicate overspend before enforcement caught up. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `scope` | Budget scope level | `workspace`, `origin`, `global` |

---

#### `sbproxy_ai_realtime_sessions_active`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **stable** |
| Description | Currently open OpenAI Realtime API WebSocket sessions. Ticks up at upgrade time and down at session close (whether the client or upstream initiated the close). |

No labels.

---

#### `sbproxy_ai_realtime_session_duration_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | Wall-clock duration of a Realtime WebSocket session, observed once at session close. Buckets span 1 s to 30 min for typical Realtime call durations. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider that handled the session | `openai` |
| `close_reason` | Why the session ended | `client_closed`, `upstream_closed`, `policy_violation`, `error` |

---

#### `sbproxy_ai_realtime_audio_seconds_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Cumulative audio seconds forwarded over Realtime sessions. Frame-exact accounting requires terminate-and-relay (not on the OSS dispatch path); the OSS dispatcher uses session wall-clock duration as a duration proxy on close, partitioned per direction so dashboards see "inbound" (client to provider) and "outbound" (provider to client) separately. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider | `openai` |
| `direction` | Audio direction | `inbound`, `outbound` |

---

#### `sbproxy_ai_realtime_frames_forwarded_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Cumulative frames forwarded over Realtime sessions. Today this counter is only incremented when an enterprise terminate-and-relay path is in use; the OSS transparent forwarding path doesn't see individual frames. Reserved label set is stable so dashboards built against the metric continue to work when the enterprise dispatch lands. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider | `openai` |
| `direction` | Frame direction | `inbound`, `outbound` |
| `kind` | Frame payload kind | `text`, `audio` |

---

### Observability + reliability

These surface the proxy's own telemetry pipeline and pre-routing
rejections so an operator can alert on a telemetry blackhole or a flood
of misrouted traffic.

#### `sbproxy_unrouted_requests_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Requests rejected before origin resolution because no configured origin matched the inbound `Host`. These never reach the access log or any per-origin counter, so this is the only signal for misrouted / probing traffic. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `reason` | Why the request was unrouted | `unknown_host` |

---

#### `sbproxy_sink_install_failures_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Failed installs of the process-wide telemetry sink dispatcher (a poisoned dispatcher lock). Non-zero means the proxy may be serving traffic with no log / event export. The readiness probe `telemetry_sink` drains the pod in this state. |

---

#### `sbproxy_telemetry_dropped_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Telemetry records dropped or sinks that failed to set up, instead of failing silently. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `kind` | Which sink / path dropped | `webhook`, `file_sink`, `otlp_log` |
| `reason` | Why it was dropped | `no_runtime`, `mkdir_failed` |

---

#### `sbproxy_config_reload_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Config (hot) reload attempts, by outcome. Alert on a non-zero `failure` rate or a stalled `success` cadence. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `result` | Reload outcome | `success`, `failure` |

---

#### `sbproxy_ai_provider_attempts_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | AI provider attempts on the failover/selection path, by provider and outcome. Gives the per-provider load distribution and failure rate that the bare `sbproxy_ai_failovers_total` "a failover happened" signal cannot. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | Provider attempted | `openai`, `anthropic` |
| `outcome` | Attempt result | `success`, `error` |

---

#### `sbproxy_silent_degradations_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Best-effort operations that failed and were previously dropped silently (cache promotion, cache cleanup, ...), by op. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `op` | Operation that degraded | `cache_promote`, `cache_cleanup` |

---

#### Tenant label additions

The following existing counters now carry a bounded `tenant` label so
multi-tenant deployments can attribute rejections per tenant (the
matching security-audit records already carried it):
`sbproxy_http_framing_blocks_total`, `sbproxy_waf_persistent_blocks_total`,
and `sbproxy_ai_ratelimit_rejected_total`. The label is the resolved
tenant (`__default__` for single-tenant deployments) and is run through
the cardinality limiter.

### Local inference and semantic cache

#### `sbproxy_semantic_cache_results_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Embedding semantic-cache outcomes, attributed per tenant. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `tenant` | Tenant id the request was attributed to | `acme`, `__default__` |
| `origin` | Virtual hostname | `api.example.com` |
| `source` | Embedding source that vectorized the prompt | `provider`, `sidecar`, `inprocess` |
| `result` | Lookup outcome | `hit`, `miss`, `error` |

#### `sbproxy_inference_requests_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Local ONNX inference calls (embeddings and classify) and their outcome. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `kind` | Inference kind | `embed`, `classify` |
| `backend` | Where inference ran | `sidecar`, `inprocess` |
| `model` | Logical model id | `all-MiniLM-L6-v2`, `prompt-injection-v2` |
| `result` | Call outcome | `ok`, `error` |

#### `sbproxy_inference_duration_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **beta** |
| Description | Local ONNX inference latency in seconds. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `kind` | Inference kind | `embed`, `classify` |
| `backend` | Where inference ran | `sidecar`, `inprocess` |
| `model` | Logical model id | `all-MiniLM-L6-v2` |

#### `sbproxy_ai_tokens_saved_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Tokens a semantic-cache hit avoided (the upstream call that did not happen). The value-delivered side of usage tracking, attributed per tenant. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `tenant` | Tenant id the savings are attributed to | `acme`, `__default__` |
| `origin` | Virtual hostname | `api.example.com` |
| `model` | Model id from the cached response | `gpt-4o`, `claude-sonnet-4-5` |
| `kind` | Token kind | `prompt`, `completion` |

#### `sbproxy_ai_cost_saved_micros_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **beta** |
| Description | Micro-USD a semantic-cache hit avoided. Saved cost uses the same cost table as spent cost, so saved and spent reconcile. Attributed per tenant. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `tenant` | Tenant id the savings are attributed to | `acme`, `__default__` |
| `origin` | Virtual hostname | `api.example.com` |
| `model` | Model id from the cached response | `gpt-4o` |

### Model host

The local model host (`serve:`) publishes these. All **alpha** while the
engine-runtime phases land; names may change before they graduate.

#### `sbproxy_model_host_time_to_ready_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **alpha** |
| Description | Time from engine launch to the readiness probe passing (cold weight load + warm-up). Observed only on a successful launch. |

**Labels:** `engine` (`vllm`, `llama_cpp`), `model` (catalog id / advertised name).

#### `sbproxy_model_host_launches_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **alpha** |
| Description | Engine launch attempts, by outcome. |

**Labels:** `engine`, `model`, `outcome` (`ready`, `failed`).

#### `sbproxy_model_host_evictions_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **alpha** |
| Description | Model evictions from VRAM. |

**Labels:** `reason` (`lru`, `keep_alive`, `manual`).

#### `sbproxy_model_host_resident_models`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **alpha** |
| Description | Local models currently loaded and Ready. |

#### `sbproxy_model_host_load_queue_depth`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **alpha** |
| Description | Requests parked waiting for a cold model to become Ready. |

**Labels:** `model`.

#### `sbproxy_model_host_gpu_vram_bytes`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **alpha** |
| Description | GPU memory in bytes, per device. |

**Labels:** `device`, `kind` (`total`, `free`).

#### `sbproxy_model_host_gpu_utilization`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **alpha** |
| Description | GPU utilization fraction (0.0-1.0), per device. This is the signal the `gpu-aware` routing strategy reads. |

**Labels:** `device`.

#### `sbproxy_model_host_lora_loads_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **alpha** |
| Description | LoRA adapters loaded onto a base engine (dynamic-paging cache misses). |

#### `sbproxy_model_host_lora_evictions_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **alpha** |
| Description | LoRA adapters paged out of a base engine's adapter cache to make room past `max_loras`. |

#### `sbproxy_model_host_resident_adapters`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **alpha** |
| Description | LoRA adapters currently loaded across all base engines. |

---

## Deprecation process

When a stable metric must change:

1. The new metric is introduced alongside the old one in the next minor release.
2. The old metric emits a log warning on first scrape, noting the deprecation and target removal version.
3. The old metric is removed in the next major release.

Beta and alpha metrics may be removed or renamed without this process. Check the changelog.
