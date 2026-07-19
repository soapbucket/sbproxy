# AI context compression

*Last modified: 2026-07-18*

SBproxy can transform an AI chat request through an ordered, per-handler
compression pipeline before provider selection and dispatch. Use `window_fit`
for stateless, deterministic compatibility trimming. Add `summary_buffer` when
conversations need a compact running summary stored in Redis so gateway
workers can restart and successive turns can land on different replicas.

This page is the canonical operator guide for compression configuration,
runtime behavior, state, degradation, and telemetry.

## Runtime contract

Each `ai_proxy` action can declare one `compression.levers` array. SBproxy runs
the entries in declaration order against one working message list:

1. A lever sees the output committed by earlier levers.
2. An applied candidate replaces the working list only when it strictly reduces
   SBproxy's token estimate for the request's effective model.
3. A skipped or failed lever leaves the working list unchanged.
4. Later levers still run after a skip or failure.
5. Provider routing and failover see only the final committed list.

The common production order is `summary_buffer` followed by `window_fit`.
Summary buffering preserves useful historical facts first. Window fitting then
applies the existing deterministic compatibility heuristic for models whose
context window SBproxy knows.

| Lever | State | Purpose | Typical position |
|---|---|---|---|
| `summary_buffer` | Configured Redis L2 service | Replace eligible older text history with a bounded, incremental summary | First |
| `window_fit` | None | Apply the legacy newest-to-oldest message-selection heuristic within the known model window | Last |

Request workers do not retain canonical summaries in process. Canonical
session summary state lives only in the configured Redis L2 service. A worker
can restart or a later request can land on another replica without relying on
worker-local conversation memory.

The compression record key is an opaque digest over the tenant, normalized AI
origin, captured session ID, and a stable summary-policy fingerprint. The
fingerprint covers provider, model, threshold, retained-tail size, summary
target, state lifetime, fixed prompt text, record schema, and summary behavior
version. A policy or incompatible behavior change starts a separate lineage,
so mixed replicas cannot reuse each other's summaries. Raw session IDs and
original messages are not stored in the record.

## Stateless window fitting

`window_fit` needs no session ID and no external state. The hosted request must
carry a non-empty effective `model`; otherwise the compression pipeline is not
invoked. It looks up that model's known context window, subtracts
`completion_reserve_tokens`, preserves a leading system message, and considers
the remaining messages from newest to oldest. Its compatibility estimator is
the message's string `content` byte length divided by four, plus one token. A
message is kept whenever that estimate fits the remaining budget, so an
oversized newer message can be skipped while an older smaller message is kept.
Kept messages return to chronological order before dispatch.

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
      compression:
        levers:
          - type: window_fit
            completion_reserve_tokens: 1024
```

The completion reserve defaults to `1024`. If the model window is unknown, or
the compatibility estimate already fits, the lever skips without changing the
request. This is deliberately the existing `context_compress` behavior, not an
exact provider tokenizer or a new hard input-budget guarantee. Explicit input
budget targeting remains separate work.

The older `resilience.llm_aware.context_compress: true` switch remains a
compatibility shorthand for a one-lever `window_fit` policy when no explicit
`compression` block is present. An explicit `compression` block is
authoritative, including `levers: []`.

## Stateful summary buffering

`summary_buffer` is eligible only for a supported `/v1/chat/completions`
message array with a non-empty effective model, captured session ID, tenant,
and origin. It runs when SBproxy's model-aware estimate reaches `min_tokens`
and enough eligible history remains after the protected prefix and recent tail
are excluded.

### Captured session identity

The compression layer never creates a session ID. It consumes the session ULID
already captured by the request envelope. A caller should send a stable,
valid `X-Sb-Session-Id` on every turn in one conversation:

```yaml
origins:
  "ai.example.com":
    sessions:
      capture: true
      auto_generate: never
```

With `auto_generate: never`, a missing or invalid header leaves no captured
session and `summary_buffer` skips with `missing_session`. The rest of the
pipeline and the upstream request continue.

The general session-capture layer can be configured to generate and echo a
ULID for anonymous traffic, but that is outside compression. If an SDK uses
that behavior, it must read the echoed `X-Sb-Session-Id` and send the same ID
on later turns. A newly generated ID on every request does not join those
requests into one summary history.

### Material that can be summarized

The lever partitions the message list into three regions:

- Every contiguous leading `system` or `developer` message is protected and
  copied byte-for-byte.
- The last `retain_recent_messages` entries are protected and copied
  byte-for-byte.
- Only the middle region is eligible for summarization. Every entry there must
  contain exactly `role` and string `content`, with role `user` or
  `assistant`.

Top-level `tools`, `functions`, `response_format`, `schema`, `json_schema`, or
`output_schema` fields make the summary lever skip with
`structured_request`. A tool call, tool result, name field, multimodal content
array, schema material, or any other structured entry in the middle region
also causes that safe skip. Structured material in the protected recent tail
is preserved exactly and does not prevent older simple text from being
summarized.

The generated summary is inserted immediately after the protected prefix as a
synthetic `role: user` message. It is untrusted historical context, inside
explicit wrapper tags and with an instruction that it must never be treated as
instructions. The dedicated summarizer receives the source as untrusted JSON
under its own fixed system instruction.

### Incremental state and branch mismatch

The stored record includes digests of the protected prefix and all original
history covered by the summary. On a later request with the same tenant,
origin, and captured session:

- An exact history match reuses the stored summary without a summarizer call or
  state write. Because there is no write, exact reuse does not refresh the
  record TTL.
- Appended history sends only newly covered messages plus the prior summary to
  the summarizer, then advances the logical version.
- A record at or past its logical expiration skips with `state_expired`, even
  during the short interval before Redis physically removes it.
- A changed protected prefix, edited covered message, shortened history, or
  different history fork skips with `branch_mismatch`. SBproxy does not reuse
  or overwrite the record for the mismatched branch.

Treat a deliberate conversation fork as a new session. If a caller reused a
session ID after resetting or editing history, assign a new ID or remove the
old opaque record through the authenticated Admin API.

### Dedicated summarizer policy

Every `summary_buffer` selects one exact provider and model from the same AI
handler. Startup validation requires the provider to exist and be enabled, the
model to be declared by that provider or accepted by its wildcard model
configuration, and the model to pass the handler's model policy.

The internal request does not enter ordinary routing, semantic caching,
shadowing, or compression, so it cannot recurse. It is a non-streaming chat
completion sent only to the configured provider and model with
`max_tokens: target_summary_tokens`.

Request-scoped credential governance and the effective AI budget still apply:

- A credential that disallows the summarizer provider or model produces the
  safe skip `policy_denied`.
- A budget preflight that would block or downgrade the internal call produces
  the safe skip `budget_denied`.
- A successful internal call is charged to the same tenant and sanitized
  credential identifier with surface `compression_summary`. That usage remains
  charged even if a later state commit fails.
- Prior summary plus new source must fit the summarizer model's input window.
  Oversized input skips as `summarizer_input_too_large` before dispatch.
- `summarizer.timeout` is a hard wall-clock deadline. A timeout fails open as
  `summarizer_timeout`.

Empty, malformed, or oversized summary output fails validation. The provider's
reported output count and a conservative local estimate must both fit
`target_summary_tokens`.

## Redis state

`backend: redis` reuses the process-wide Redis L2 configuration and Redis
service. It inherits all four connection fields: `dsn`, `ca_file`, `cert_file`,
and `key_file`. The compression runtime clones the same validated Redis client
and opens its own lazy multiplexed connection. The compression block does not
accept a separate DSN, CA, or client identity, so it cannot silently lose the
L2 trust or mTLS configuration.

Redis serializes updates with a bounded lease, a monotonic fence, and a
logical-version compare-and-set. The lease is the configured summarizer timeout
plus a fixed 5-second margin for the bounded state load, validation, and commit;
it is not renewed indefinitely.

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: rediss://cache-user:${REDIS_PASSWORD_URLENCODED}@redis.internal:6380/7
      ca_file: /etc/sbproxy/redis/ca.pem
      cert_file: /etc/sbproxy/redis/client.pem
      key_file: /etc/sbproxy/redis/client-key.pem

origins:
  "ai.example.com":
    sessions:
      capture: true
      auto_generate: never
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini]
      compression:
        state:
          backend: redis
          ttl: 24h
        levers:
          - type: summary_buffer
            min_tokens: 12000
            retain_recent_messages: 8
            target_summary_tokens: 2048
            summarizer:
              provider: openai
              model: gpt-4o-mini
              timeout: 5s
          - type: window_fit
            completion_reserve_tokens: 1024
```

Selecting Redis without `proxy.l2_cache_settings.driver: redis` is a startup
configuration error. Invalid DSN semantics, invalid TLS field combinations,
and bad local PEM material are also rejected before serving. Configuration
validation does not open a network connection. TLS verification,
authentication, and database selection happen when the lazy compression
connection is first used.

Once the runtime is active, a Redis connection, TLS, authentication, database,
or command failure makes the stateful lever fail open for that request. The
current internal bounds are 500 milliseconds for connection setup, 1 second
for a command response, and 2 seconds for a complete state operation. A failed
cached connection is replaced, and a later request can recover without
restarting SBproxy. There is no worker-local summary fallback.

The general synchronous L2 metrics named `sbproxy_redis_kv_*` cover
`RedisKVStore` consumers such as shared response cache and rate limiting. The
compression runtime remains covered by
`sbproxy_ai_compression_state_operations_total`,
`sbproxy_ai_compression_state_operation_duration_seconds`, and
`sbproxy_ai_compression_redis_coordination_total`; it does not double-count its
async operations in the synchronous families.

## Why mesh is not a supported state backend

`compression.state.backend` currently accepts only `redis`. The existing proxy
mesh routes cache keys to one in-memory owner; it does not yet replicate,
restore, hand off, or repair that state across topology changes. That is not a
safe canonical store for sensitive running summaries or Admin deletion. SBproxy
therefore rejects `backend: mesh` during configuration parsing instead of
claiming restart safety or eventual convergence it cannot provide.

## Configuration reference

| Field | Required | Constraint |
|---|---|---|
| `compression.state.backend` | For `summary_buffer` | `redis` |
| `compression.state.ttl` | For `summary_buffer` | Positive seconds or human duration |
| `compression.allow_admin_content_inspection` | No | Default `false`; enables audited Admin-only content inspection for configured origins |
| `compression.levers` | No | Ordered list; an explicit empty list disables compression |
| `summary_buffer.min_tokens` | Yes | Greater than zero |
| `summary_buffer.retain_recent_messages` | Yes | Greater than zero |
| `summary_buffer.target_summary_tokens` | Yes | Greater than zero and smaller than `min_tokens` |
| `summary_buffer.summarizer.provider` | Yes | Enabled provider on the same handler |
| `summary_buffer.summarizer.model` | Yes | Non-empty model allowed by the handler and configured provider |
| `summary_buffer.summarizer.timeout` | Yes | Positive seconds or human duration |
| `window_fit.completion_reserve_tokens` | No | Defaults to `1024` |

Unknown fields in the compression policy, state, lever, or summarizer blocks
are rejected.

Summary content is sensitive. Metadata listing, optional audited inspection,
single-record deletion, and bounded purge are documented in the
[Admin API reference](admin-api-reference.md#ai-compression-session-state). Keep
`allow_admin_content_inspection: false` unless an audited operational workflow
requires content access. Do not operate on backend keys directly.

Metadata listing and purge scan the shared Redis namespace using bounded pages
and opaque cursors.

## Semantic cache interaction

A handler policy that contains `summary_buffer` bypasses semantic-cache reads
and writes whenever the request has a captured session. The bypass is decided
before compression runs and remains in effect even when the summary lever later
skips or fails open. This prevents a session-dependent summary from sharing a
cached response with another conversation.

| Policy and request | Semantic cache |
|---|---|
| `summary_buffer` and captured session | Bypassed for read and write |
| `summary_buffer` and no captured session | Not bypassed; summary lever skips `missing_session` |
| `window_fit` only | Not bypassed |

This rule applies to the semantic cache. It does not disable the separate
idempotency middleware.

## Failure and degradation behavior

Compression runtime failures fail open. They do not reject the caller's AI
request. A failed lever preserves the last message list committed by an earlier
lever, records a closed failure reason, and lets later levers run. If no lever
has applied, the original list remains available to a later fallback such as
`window_fit` or to upstream dispatch.

| Condition | Lever outcome | Request and state behavior |
|---|---|---|
| Missing captured session | `skipped`, `missing_session` | No state access; later levers run |
| Below threshold, insufficient history, unknown window, or no need | `skipped` | Working messages and state remain unchanged |
| Structured or multimodal material would be summarized | `skipped`, `structured_request` | Protected material is never sent to the summarizer |
| Stored digest does not match the incoming branch | `skipped`, `branch_mismatch` | Existing record is not reused or overwritten |
| Stored record reached its logical expiry | `skipped`, `state_expired` | Expired summary is not reused; Redis removes the record at its TTL |
| Update permit is contended | `skipped`, `lock_contended` | No unbounded wait; later levers run |
| Credential or budget denies internal summarization | `skipped`, `policy_denied` or `budget_denied` | No summarizer call and no state write |
| Summarizer input is too large | `skipped`, `summarizer_input_too_large` | No summarizer call and no state write |
| State load or commit is unavailable | `failed`, `state_unavailable` | Last committed messages continue; no local state fallback |
| Lease, fence, or logical version changed | `failed`, `lease_lost` or `stale_version` | Candidate is not committed to the request |
| Summarizer times out or provider fails | `failed`, `summarizer_timeout` or `summarizer_provider` | Last committed messages continue |
| Summary output is empty, malformed, or too large | `failed`, `invalid_summary` | No state write and no message replacement |
| Candidate is equal or larger by target-model estimate | `skipped`, `no_savings` | Candidate is discarded; only strict reductions apply |

Configuration errors are different from runtime degradation. A
`summary_buffer` without `compression.state`, an unavailable selected runtime
wiring, an invalid summarizer reference, or an invalid numeric constraint is
rejected at load or startup rather than silently weakened.

### Closed outcomes and reasons

Lever outcomes are `applied`, `skipped`, and `failed`. Applied outcomes use an
empty `reason` label. Skip reasons are:

`no_savings`, `not_eligible`, `not_needed`, `unknown_model_window`,
`missing_session`, `unsupported_request`, `below_threshold`,
`insufficient_history`, `structured_request`, `branch_mismatch`,
`state_expired`, `no_new_history`, `summarizer_input_too_large`, `budget_denied`,
`policy_denied`, and `lock_contended`.

Failure reasons are:

`state_unavailable`, `lease_lost`, `stale_version`, `summarizer_timeout`,
`summarizer_provider`, `invalid_summary`, `serialization`, and `internal`.

The request outcome is failure-first:

- `failed` when any lever failed, even if a later lever applied.
- `applied` when at least one lever applied and none failed.
- `skipped` when every lever skipped.

## Metrics

All token measurements use the same model-aware SBproxy counter at the runner
boundary. A lever is applied only when `after_tokens < before_tokens`.
Skipped and failed levers report zero saved tokens.

The arithmetic is exact relative to that shared estimate. For model families
without a dedicated tokenizer, the estimator uses its documented conservative
character heuristic; these metrics are not reconciled to provider-reported
usage after dispatch.

Per-lever savings can be summed safely because every applied lever starts from
the preceding committed output. At request scope,
`initial_tokens - final_tokens` is observed exactly once in
`sbproxy_ai_compression_request_tokens_saved`, so a two-lever request is not
double-counted in the request distribution.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sbproxy_ai_compression_lever_total` | Counter | `tenant_id`, `api_key_id`, `lever`, `outcome`, `reason`, `backend` | One row per lever invocation |
| `sbproxy_ai_compression_tokens_total` | Counter | `tenant_id`, `api_key_id`, `lever`, `direction` | Applied-lever tokens with `direction="input"` or `"output"` |
| `sbproxy_ai_compression_tokens_saved_total` | Counter | `tenant_id`, `api_key_id`, `lever` | Applied reduction in SBproxy's model-aware token estimate per lever |
| `sbproxy_ai_compression_ratio` | Histogram | `tenant_id`, `api_key_id`, `lever` | Applied `after_tokens / before_tokens` |
| `sbproxy_ai_compression_duration_seconds` | Histogram | `tenant_id`, `api_key_id`, `lever`, `outcome`, `backend` | Wall-clock duration of every lever invocation |
| `sbproxy_ai_compression_requests_total` | Counter | `tenant_id`, `api_key_id`, `outcome`, `backend`, `cache_bypass` | One row per executed non-empty compression pipeline |
| `sbproxy_ai_compression_request_tokens_saved` | Histogram | `tenant_id`, `api_key_id`, `outcome`, `backend` | One initial-minus-final observation per request |
| `sbproxy_ai_compression_request_levers_run` | Histogram | `tenant_id`, `api_key_id`, `outcome`, `backend` | Number of configured levers executed per request |
| `sbproxy_ai_compression_state_operations_total` | Counter | `backend`, `operation`, `outcome` | External state operations |
| `sbproxy_ai_compression_state_operation_duration_seconds` | Histogram | `backend`, `operation`, `outcome` | External state operation latency |
| `sbproxy_ai_compression_redis_coordination_total` | Counter | `event` | Redis contention and rejected update events |

`lever` is `summary_buffer` or `window_fit`. `backend` is `redis` or `none`.
Request `cache_bypass` is `true` or `false`. State `operation` is
`get`, `commit`, `delete`, `list`, or `purge`; its `outcome` is `ok`,
`missing`, or `error`.

Redis coordination `event` values are `contention`, `lease_expiry`,
`stale_version`, and `fence_rejection`.

The `tenant_id` and public `api_key_id` label values pass through the shared
cardinality budget. Bearer credentials are never used as metric labels.

### PromQL examples

```promql
# Model-aware estimated tokens removed per second, split by lever
sum by (lever) (
  rate(sbproxy_ai_compression_tokens_saved_total[5m])
)

# P95 initial-to-final tokens saved per request, counted once
histogram_quantile(
  0.95,
  sum by (le, backend) (
    rate(sbproxy_ai_compression_request_tokens_saved_bucket[5m])
  )
)

# Failure-first request ratio
sum(rate(sbproxy_ai_compression_requests_total{outcome="failed"}[5m]))
/
clamp_min(sum(rate(sbproxy_ai_compression_requests_total[5m])), 0.000001)

# Lever skip and failure reasons
sum by (lever, outcome, reason, backend) (
  rate(sbproxy_ai_compression_lever_total{outcome=~"skipped|failed"}[5m])
)

# External state errors by backend and operation
sum by (backend, operation) (
  rate(sbproxy_ai_compression_state_operations_total{outcome="error"}[5m])
)

# Redis coordination pressure
sum by (event) (
  rate(sbproxy_ai_compression_redis_coordination_total[5m])
)

# Requests that conservatively bypassed the semantic cache
sum by (cache_bypass) (
  rate(sbproxy_ai_compression_requests_total[5m])
)
```

The bundled Prometheus recording rules and alerts include application rate,
failure ratio, P95 lever latency, saved-token rate, sustained compression
failures, and state rejections.

## Safe summary log event

Every executed non-empty pipeline emits one structured event with
`event="ai_compression_summary"` on the `ai_compression` tracing target.

| Request result | Level |
|---|---|
| Every lever skipped | `DEBUG` |
| At least one applied and none failed | `INFO` |
| Any lever failed | `WARN` |

The top-level fields are `event`, `tenant_id`, `api_key_id`, `outcome`,
`initial_tokens`, `final_tokens`, `tokens_saved`, `levers_run`,
`levers_applied`, `latency_ms`, `backend`, `consistency`, `cache_bypass`,
`lever_outcomes`, and `targets`.

`backend` is `redis` or `none`. The corresponding `consistency` value is
`serialized` or `none`.

`lever_outcomes` is a JSON-encoded list containing only `lever`, `outcome`,
`reason`, `backend`, `before_tokens`, `after_tokens`, `tokens_saved`, and
`duration_ms`. `targets` is a JSON-encoded list. A summary target contains
`lever`, `min_tokens`, `retain_recent_messages`, `target_summary_tokens`, and
`timeout_ms`; a window-fit target contains `lever` and
`completion_reserve_tokens`.

The event never contains message text, generated or prior summary content, raw
session IDs, record IDs, request bodies, provider credentials, bearer values,
or other credential material. `api_key_id` is the sanitized public credential
identifier used for attribution, not a secret.

## Operational rollout

1. Start with `window_fit` and confirm model-window coverage and saved-token
   telemetry.
2. Make callers send and reuse a stable captured session ULID.
3. Configure the shared Redis L2 service and validate the policy on every
   replica.
4. Put `summary_buffer` before `window_fit` and begin with a conservative
   `min_tokens`, recent-tail size, summary target, and timeout.
5. Watch failure reasons, state errors, Redis coordination, request savings,
   and summarizer spend before widening traffic.
6. Use the authenticated Admin API for metadata, deletion, and purge. Leave
   content inspection disabled unless an audited incident workflow requires it.

To disable the new pipeline explicitly, set `compression.levers: []`. Existing
Redis records remain until their TTL expires; re-enabling the same policy before
expiry can reuse them. Metadata, delete, and purge remain available through the
Admin API as long as the global Redis L2 configuration remains present, even
when no active handler uses `summary_buffer`; content inspection stays disabled
without an active origin opt-in. To keep only stateless protection, remove
`summary_buffer`, its `state` block, and leave `window_fit` configured. A newly
committed summary refreshes its TTL, while an exact-summary reuse does not.

SBproxy has no OmniRoute runtime dependency, compatibility layer, state import,
or migration path for context compression. Configure SBproxy policies directly
and begin with fresh external summary state.

## See also

- [AI gateway guide](ai-gateway.md) for provider, policy, budget, cache, and
  routing behavior around the compression stage.
- [LLM-aware resilience](ai-llm-aware-resilience.md) for typed upstream
  failures and the legacy window-fit shorthand.
- [Dependency degradation matrix](degradation.md) for fleet-wide outage
  behavior.
- [Admin API reference](admin-api-reference.md#ai-compression-session-state) for
  summary-state operations.
- [Metric stability](metrics-stability.md) for the public Prometheus contract.
