# Dependency degradation matrix

*Last modified: 2026-08-02*

What happens when each dependency that SBproxy talks to is unavailable, and how the proxy degrades while it heals.

## Principles

1. A policy that selects shared runtime state must have that state wiring at startup.
2. Once active, the proxy MUST keep serving traffic during dependency outages where the feature contract is fail-open.
3. Degradation must be visible in metrics and logs.
4. Recovery is automatic. No manual intervention required.
5. One word per decision. A control that cannot reach a verdict takes a
   `failure_posture`, spelled the same everywhere it appears:

   | Posture | The request | What is left behind |
   |---|---|---|
   | `closed` | Refused | The refusal |
   | `degraded` | Admitted | An explicit record that the guarantee was not made |
   | `open` | Admitted | Nothing |
   | `observe` | Admitted | The verdict the control would have reached |

   `degraded` and `open` do the same thing to the request and differ only in
   what they leave behind, which is the part that matters six months later
   when someone asks whether a control was protecting anything. Prefer
   `degraded`. Sites where a posture is meaningless reject it at
   config-compile time with a message naming the key, rather than accepting
   it and picking something else for you.

## Matrix

| Dependency | When down | Fallback | Recovery | Metrics |
|---|---|---|---|---|
| Upstream target (`proxy` or `load_balancer`) | Connection error / timeout | Active health checks + outlier detection + circuit breaker eject the target. Retries pick the next healthy peer. With every target ejected, the LB falls back to the unfiltered list rather than 502'ing the client. | Auto on next probe success / breaker recovery window | `sbproxy_requests_total{status}`, `sbproxy_origin_requests_total{origin,method,status}` |
| AI provider (OpenAI, Anthropic, OpenRouter, ...) | 5xx, timeout, rate-limit | Routing strategy picks the next provider in the chain (`fallback_chain` / `cost_optimized`). All-providers-failed returns 502. | Auto on next successful request | `sbproxy_ai_failovers_total`, `sbproxy_ai_provider_errors_total` |
| Redis (`proxy.l2_cache_settings`) | Connection, TLS, authentication, database selection, protocol, or command failure | A response-cache lookup failure bypasses the cache and does not arm write-back for that request. A shared rate-limit operation failure admits the request fail-open instead of switching to a local bucket. AI `summary_buffer` state never falls back to worker memory: that lever fails open, preserves the last committed message list, and lets later levers run. Other L2 consumers keep their feature-specific failure posture. | A later operation opens a fresh connection automatically; summary updates resume on a later request | `sbproxy_redis_kv_connections_total`, `sbproxy_redis_kv_operation_duration_seconds`, `sbproxy_redis_kv_operation_errors_total`, plus the compression state metrics |
| Dedicated AI compression summarizer | Timeout, provider failure, invalid output, policy denial, or budget denial | `summary_buffer` skips safe admission denials or fails open on runtime errors. The primary AI request continues with the last committed messages, and a later `window_fit` lever still runs. | Next eligible request retries under the configured policy and timeout | `sbproxy_ai_compression_lever_total`, `sbproxy_ai_compression_requests_total`, `sbproxy_ai_compression_duration_seconds` |
| Token-pruning classifier sidecar | Connection failure, timeout, unknown model, or invalid extractive output | `token_prune` fails open at its lever boundary. The primary request keeps the last committed messages, and later entries such as `window_fit` still run. | The route connects lazily again on the next eligible request | `sbproxy_ai_compression_lever_total{lever="token_prune"}`, `sbproxy_ai_compression_requests_total`, `sbproxy_ai_compression_duration_seconds` |
| Virtual key store (`key_management.store`) | Connection / read failure | `key_management.failure_posture` decides it, and all four inbound-key paths (header sweep, playground ticket, bearer token, OIDC claim map) read the same value. The default `closed` denies with `503`. `degraded` and `open` both fall through to the origin's own configured auth, which is not a blanket admit; they differ in whether the lost per-key policy, budget, and attribution are recorded as lost. | Auto on the next successful store read; the cache never caches an error | None dedicated; logged at WARN with `failure_posture` and `guarantee_waived` fields |
| Governed-key budget backend (`key_management.governance.backend`, strict tier only) | Connection / command failure | Only affects keys governed under `consistency: strict`. The default `approximate` tier does not depend on this backend at all; its per-node counters keep disseminating over the cluster mesh. For a strict key, a reserve call that cannot reach the backend denies the request (`503`) by default (`failure_posture: closed`); `degraded` admits it without a reservation and audits the fact; `open` admits it and records nothing. A settle call on an already-admitted request is unaffected by the posture and stays best-effort. | Auto-reconnect; enforcement resumes on the next successful call | `sbproxy_governance_fail_open_total{key_id}` on `degraded`; also logged at WARN (admit/deny) or DEBUG (other reserve/settle errors) |
| Fair-share quota accounting backend (`quota_pools[].consistency: approximate \| strong`) | Connection / command failure | `quota_pools[].failure_posture` decides it, on the AI dispatch path and the realtime WebSocket path alike. The default `closed` rejects with `503`. `degraded` admits the attempt with no reservation held and counts it; `open` admits and counts nothing. A real quota denial (`429`) and inconsistent pool state (`503`) never consult the posture. | Auto-reconnect; accounting resumes on the next successful call | `sbproxy_ai_quota_pool_fail_open_total{pool}` on `degraded` |
| ACME CA (Let's Encrypt) | Renewal request fails | Existing cert keeps serving until expiry. With no usable cert, an HTTP-01 self-signed bootstrap is served and an `ERROR` is logged loudly. | Retry with exponential backoff (1m to 24h) | `sbproxy_acme_renewals_total{result}` |
| Upstream DNS (`service_discovery`) | Resolver timeout / NXDOMAIN | The cached A/AAAA set keeps serving past TTL until the next refresh succeeds. New unseen hostnames fall back to Pingora's connect-time resolver. | Auto on next refresh | None dedicated; resolver failures are logged at WARN |
| Vault / secrets backend (`proxy.secrets.backends`) | Fetch fails | Unresolved provider URI references fail startup; backend-local caches retain already resolved values where supported. | Backend reconnect/re-fetch behavior | `sbproxy_vault_resolution_total{backend,result}` |
| Origin callback hooks (`origins.*.on_request` / `on_response`) | Send fails | Fire-and-forget for audit-mode callbacks; the triggering request or response is unaffected. Enrichment-mode (`enrich: true`) callbacks are awaited inline with their own `timeout`, but a failed or timed-out enrichment still lets the request flow (no `X-Inject-*` headers applied, nothing else changes). A failed delivery is logged at WARN. | None needed; the next matching request/response fires independently | None dedicated; failures are logged at WARN |
| Alert-channel webhook delivery (`proxy.alerting.channels[].type: webhook`) | Send fails | Webhook delivery is fire-and-forget. A failed POST is logged at WARN and the firing alert still reaches any other configured channel. | None needed; the next alert evaluation tries again | None dedicated; failures are logged at WARN |

## Detailed reference

### Upstream target (proxy or load_balancer)

**When down:** the target returns a connect error, a timeout, or a 5xx response.

**Fallback:** four signals compose a self-healing pool:

* **Active health checks** mark a target unhealthy after `unhealthy_threshold` consecutive probe failures and healthy again after `healthy_threshold` successes.
* **Outlier detection** ejects targets whose error rate over `window_secs` crosses `threshold` (5xx + connect failures count).
* **Circuit breaker** trips on `failure_threshold` consecutive failures and recovers via `success_threshold` HalfOpen probes.
* **Retries** rerun `upstream_peer` on connect-error, timeout, or configured response status codes such as `502` and `503`. For load balancers the failed target is reported to outlier and breaker so the next attempt picks a different healthy peer.

When every target is ejected at once, the LB falls back to the unfiltered list rather than failing the client.

![20 requests against a two-target pool while the always-503 target crosses the failure threshold and is ejected](assets/outlier-detection.gif)

Ejection lasts ejection_duration_secs, then the target gets another chance ([config](../examples/outlier-detection/)).

**Log level:** `WARN` on first failure, `WARN` again when a target is ejected, `INFO` on recovery.

**Alert:** yes. Configure via `proxy.alerting.channels`. Alerts include the standard `X-Sbproxy-*` identity headers and (when `secret` is set) HMAC-SHA256 signatures.

**Config:**
```yaml
action:
  type: load_balancer
  retry:
    max_attempts: 3
    retry_on: [connect_error, timeout, 502, 503]
    backoff_ms: 100
  circuit_breaker:
    failure_threshold: 5
    success_threshold: 2
    open_duration_secs: 30
  outlier_detection:
    threshold: 0.5
    window_secs: 60
    min_requests: 5
    ejection_duration_secs: 30
  targets:
    - url: https://backend-1.internal:8080
      health_check:
        path: /healthz
        interval_secs: 10
        unhealthy_threshold: 3
        healthy_threshold: 2
```

![a request to a connection-refused upstream retried up to max_attempts before the proxy reports the failure](assets/upstream-retries.gif)

Connect errors, timeouts, and listed status codes qualify for retry ([config](../examples/upstream-retries/)).

See [`examples/resilience-stack/sb.yml`](../examples/resilience-stack/sb.yml).

![a healthy request passing, then a 20-request burst exercising retries, circuit breaker, and outlier ejection together](assets/resilience-stack.gif)

All four signals come from one config ([config](../examples/resilience-stack/)).

---

### AI provider

**When down:** the provider returns a 5xx, times out, or signals rate-limit. Streaming responses that fail mid-stream are not retried (no proxy can replay a partial SSE stream cleanly).

**Fallback:** the routing strategy (`fallback_chain`, `cost_optimized`, `weighted`, ...) picks the next provider. Per-provider rate limits and budgets are honoured across the fallback chain. If every configured provider fails, the request returns 502.

**Log level:** `INFO` per failover, `WARN` once a request walks past two providers, `ERROR` on chain exhaustion.

**Alert:** yes. Sustained failover rate is a signal that either the proxy's view of upstream health is wrong or a provider really is degraded.

**Config:**
```yaml
action:
  type: ai_proxy
  routing:
    strategy: fallback_chain
  providers:
    - name: anthropic
      api_key: ${ANTHROPIC_API_KEY}
    - name: openrouter
      api_key: ${OPENROUTER_API_KEY}
```

---

### Redis L2 cache and cross-replica state

**When down:** a lazy Redis connection can fail during TCP setup, verified TLS,
authentication, or database selection. An established connection can fail on a
pool deadline, command deadline, transport error, server error, or protocol
error. Invalid DSN syntax, unsupported query parameters or fragments, and bad
local PEM material are configuration errors caught before the runtime starts;
they do not enter degradation mode.

**Fallback:** degradation depends on the L2 consumer. A response-cache lookup
failure bypasses the cache and fetches the response from the upstream. Unlike a
true cache miss, the failed lookup does not retain the cache key for the
response phase, so that request's upstream response is not written to Redis or
to a local outage cache. When a shared rate-limit increment fails, SBproxy
admits the request fail-open; it does not consult a process-local token bucket.
A local token bucket is used only when no shared store is configured. Other L2
consumers retain their own feature-specific failure posture.

A broken pooled connection is discarded. A later operation can open a fresh
connection, so recovery does not require an SBproxy restart.

AI context summary state is intentionally different. When an AI handler selects
`compression.state.backend: redis`, Redis is the only canonical summary store.
On a connection, TLS, authentication, database, or command failure,
`summary_buffer` records
`state_unavailable`, preserves the last committed message list, and continues
to later levers and upstream dispatch. It never creates a worker-local summary
fork. The compression runtime uses its existing bounded async reconnect policy
and inherits the same validated L2 DSN and TLS material.

**Log level:** the platform events named `redis store health failed`,
`redis store health remains failed`, and `redis store health recovered` are
transition-based. The first is `WARN`, repeated platform health failures are
`DEBUG`, and the recovery event is `INFO`. This sequence applies only to those
platform events. Response-cache lookup, write, and invalidation call sites and
the shared rate-limit increment call site can emit their own `WARN` for each
failed operation, so an outage can produce more than one warning.

The platform transition events contain only the closed `operation` and
`reason` values. They do not contain a DSN, endpoint, username, database, key,
value, or certificate path. When troubleshooting consumer warnings, correlate
their fixed message text with the closed-label metrics. Do not print the DSN,
credentials, cache keys, or cache values into tickets or shell history.

**Alert:** yes when running clustered. Redis unavailability degrades multi-replica consistency.

**Config:**
```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: rediss://cache-user:${REDIS_PASSWORD_URLENCODED}@redis.internal:6380/7
      ca_file: /etc/sbproxy/redis/ca.pem
      cert_file: /etc/sbproxy/redis/client.pem
      key_file: /etc/sbproxy/redis/client-key.pem
```

The synchronous L2 store exposes three bounded metric families:

| Metric | Labels |
|---|---|
| `sbproxy_redis_kv_connections_total` | `result`: `success` or `error` |
| `sbproxy_redis_kv_operation_duration_seconds` | `operation`: `get`, `set`, `set_ttl`, `delete`, `increment`, `lock`, `unlock`, or `scan` |
| `sbproxy_redis_kv_operation_errors_total` | `operation` above and `reason`: `pool_timeout`, `connect_timeout`, `command_timeout`, `tls`, `auth`, `transport`, `server`, or `protocol` |

Every general L2 call records one duration observation. A failed call adds one
error count, and each new connection attempt adds one connection result. None
of these labels includes an endpoint, tenant, application key, username,
database, or free-form error text.

For strict Redis leases, fences, coordination events, and the full fail-open
table, see [AI context compression](ai-context-compression.md).

---

### AI compression selection and explicit fitting

Request selection has no external dependency. A malformed, repeated, or
undeclared `X-Compression` header is a caller error and returns `400` before
cache lookup or provider dispatch. SBproxy never silently replaces a bad
caller override with the route default. A malformed or undeclared governed-key
or CEL selector is an operator error; it resolves to `off`, logs the
content-free `ai_compression_selection` event, and increments
`sbproxy_ai_compression_selection_total{outcome="invalid_operator"}`. The
primary request continues without compression.

An explicit `window_fit.input_budget_tokens` target is also dependency-free.
If the protected instruction prefix or complete newest protocol unit cannot
fit, the lever skips as `not_eligible` and preserves the original message list.
It does not drop half of a tool exchange or dispatch old history without the
current turn.

`query_select` is dependency-free and deterministic. A malformed retrieval
shape, more than 4,096 source sentences in one block, a blank query in any
block, or any structured chunk skips the whole lever without a partial rewrite.
The sentence limit is checked before ranking. A block with no positive-scoring
sentence stays unchanged; another block can still produce a complete candidate.
`token_prune` depends on its configured classifier sidecar, but a failed RPC or
invalid response changes no messages and does not stop the rest of the ordered
pipeline. Keep `window_fit` last when the route needs a bound that survives a
sidecar outage.

Semantic-cache bypass is decided before either cache can read. Explicit
selectors, profile-capable routes, `token_prune`, `query_select`,
retrieval-aware route defaults, explicit-budget route defaults, and
session-dependent summaries remain bypassed even when selection resolves to
`off` or a lever later skips. Legacy default-only compatibility fitting keeps
its existing cache behavior.

Invalid profile definitions and configured-key references fail configuration
loading. There is no OmniRoute dependency or imported state to fall back to.

---

### Dedicated AI compression summarizer

**When down:** the exact summarizer provider times out or returns an invalid
response. Credential policy and budget admission can also decline the internal
summary call without contacting the provider.

**Fallback:** runtime failures are failure-open for the caller's primary AI
request. The failed lever keeps the last committed message list and later
levers continue. Safe admission conditions such as `policy_denied`,
`budget_denied`, `lock_contended`, and `state_expired` are skips rather than
failures. An expired summary is never reused even when the selected backend
has not physically removed it yet.

Omitting `state` from a stateful pipeline selects the process-owned Local redb
store with a 24-hour TTL. Selecting `backend: redis` without Redis L2 wiring or
`backend: mesh` without live `proxy.cluster.replication` is a startup
configuration error; explicit backends never fall back to Local. Runtime
failure-open behavior begins only after a valid pipeline has been built.

**Log level:** the content-free `ai_compression_summary` event is `DEBUG` when
all levers skip, `INFO` when at least one applies and none fail, and `WARN` when
any lever fails.

**Alert:** the bundled rules alert on a sustained compression failure ratio and
on state errors or rejected Redis updates.

**Config and full behavior:** see
[AI context compression](ai-context-compression.md).

---

### Governed-key budget backend (strict tier)

**When down:** the dedicated Redis connection configured under `key_management.governance.backend` fails to connect, or a reserve, renew, settle, or release script call errors.

**Fallback:** this only affects keys governed under `consistency: strict`. The `approximate` tier (the default) never talks to this backend; its per-node counters keep disseminating over the cluster mesh instead, bounded by a staleness window rather than an outage. See [Governed admission: strict and approximate](key-management.md#governed-admission-strict-and-approximate) for both tiers. For a strict key, `key_management.governance.failure_posture` decides what a reserve call does when it cannot reach the backend: the default `closed` denies the request with `503` rather than let the governed limit go unenforced; `degraded` admits it without a reservation and records that decision on the `security_audit` channel; `open` admits it and records neither the audit event nor the counter. A settle call that cannot reach the backend after a reservation already succeeded is unaffected by the posture; it stays best-effort, and the reservation's own drop-time repair reconciles it later. An in-flight request also renews its reservation lease at half the lease lifetime; during an outage those renewals retry on a short delay until the last known expiry passes. An outage shorter than `lease_ttl_secs` therefore costs nothing, while a longer one lets the backend reclaim the reservation as expired, after which that request's eventual settle is refused and its usage goes uncharged.

**Log level:** `WARN` per admit or deny decision on a reserve call, and per failed lease renewal; `DEBUG` for other reserve/settle errors.

**Alert:** off by default. `sbproxy_governance_fail_open_total{key_id}` counts admissions when `failure_posture: degraded` is set. It stays flat under `open`, which is the reason to prefer `degraded`.

**Config:**
```yaml
proxy:
  key_management:
    governance:
      consistency: strict
      backend:
        type: redis
        url: rediss://governance.internal:6379/2
      failure_posture: closed     # closed | degraded | open
```

The older `failure_mode: closed | allow_unreserved` still parses and is used only when `failure_posture` is absent, resolving to `closed` and `degraded` respectively. `observe` is rejected at config-compile time: a reserve call that never reached its backend produced no verdict to record.

---

### Virtual key store

**When down:** the configured `key_management.store` backend (embedded redb, Redis, a secrets manager, or the cluster mesh) cannot be read. For the mesh backend this includes a lost read quorum during a partition and the hold a node applies to itself after rejoining from a long absence, until its first complete anti-entropy round; both surface as store errors and read the same posture below.

**Fallback:** `key_management.failure_posture` decides it, and all four inbound-key paths read the same value: the pre-auth header sweep, the playground impersonation ticket, the AI gateway's bearer path, and the OIDC claim map. The default `closed` denies with `503`. `degraded` and `open` fall through to the origin's own configured auth rather than admitting outright, so an origin with a `credentials:` block still authenticates the caller; what is lost is the per-key policy, budget, and attribution the virtual key would have carried. `degraded` says so in the log; `open` does not. `observe` is rejected at config-compile time: a store that could not be read produced no verdict to record.

The policy cache in front of the store never caches an error and never decides admission. It propagates the failure so exactly one place applies the posture.

**Log level:** `WARN` per admitted request, carrying `failure_posture` and `guarantee_waived` fields.

**Alert:** yes if you run anything other than `closed`. A sustained stream of `guarantee_waived=true` means governed keys stopped being governed.

**Config:**
```yaml
proxy:
  key_management:
    enabled: true
    failure_posture: closed        # closed | degraded | open
```

The older `failure_mode_allow: bool` still parses and is used only when `failure_posture` is absent: `false` resolves to `closed` and `true` resolves to `degraded`.

---

### Fair-share quota accounting backend

**When down:** a quota pool running `consistency: approximate` or `strong` cannot reach its shared accounting backend, so a reserve or settle call fails with a backend-unavailable error.

**Fallback:** `quota_pools[].failure_posture` decides it, on the AI dispatch path and the realtime WebSocket path alike (both call one mapping, so they cannot drift apart). The default `closed` rejects with `503`. `degraded` admits the attempt with no reservation held and counts it on `sbproxy_ai_quota_pool_fail_open_total{pool}`; `open` admits and counts nothing. The posture applies only to backend unavailability: a real quota denial still returns `429`, and inconsistent reservation state still returns `503`, because a pool whose accounting is contradictory cannot be said to have admitted anything.

**Log level:** none dedicated; the fail-open counter is the signal.

**Alert:** off by default. Alert on `sbproxy_ai_quota_pool_fail_open_total{pool}` if you run `degraded`.

**Config:**
```yaml
proxy:
  ai:
    quota_pools:
      - name: shared-upstream
        total_limit: 1000
        weights: {team-a: 3, team-b: 1}
        policy: burst
        consistency: strong
        failure_posture: closed    # closed | degraded | open
```

The older `failure_mode: closed | allow_unreserved` still parses and is used only when `failure_posture` is absent, resolving to `closed` and `degraded` respectively. `observe` is rejected at config-compile time.

---

### ACME CA (Let's Encrypt)

**When down:** ACME directory or order requests fail.

**Fallback:** existing certificates keep serving. If the listener has no cert at all (fresh boot, ACME never succeeded), a self-signed bootstrap cert is generated so the HTTPS listener can come up; ACME replaces it with a real cert once issuance succeeds. Renewal failures are retried with exponential backoff (1 minute to 24 hours). Attempts and outcomes are counted in `sbproxy_acme_renewals_total{result}`.

**Log level:** `WARN` per renewal failure with time-to-expiry, `ERROR` if the active cert has expired.

**Alert:** yes. Fires when expiry is within 14 days and renewal is failing.

**Config:** see the `ACME / auto TLS` section in [configuration.md](configuration.md#acme--auto-tls).

---

### Upstream DNS (service_discovery)

![four requests dispatched while the resolver refreshes and rotates the upstream A-record set round-robin](assets/service-discovery.gif)

service_discovery re-resolves every refresh_secs instead of pinning the pooled IP ([config](../examples/service-discovery/)).

**When down:** the OS resolver times out or returns NXDOMAIN.

**Fallback:** the cached A/AAAA set from the previous successful resolution keeps serving past TTL until the next refresh window. Connections that were already established to a still-reachable IP keep working. The first request to a never-resolved hostname returns 502 if DNS is fully unreachable. The DNS-SD idle-timeout cap (`min(refresh_secs/2, 10s)`) ensures stale connections cycle quickly when DNS does recover.

**Log level:** `WARN` on resolver failure, `INFO` on recovery.

**Alert:** off by default. DNS failures are usually transient.

**Config:**
```yaml
action:
  type: proxy
  url: http://backend.namespace.svc.cluster.local:8080
  service_discovery:
    enabled: true
    refresh_secs: 30
    ipv6: true
```

See [`examples/service-discovery/sb.yml`](../examples/service-discovery/sb.yml).

---

### Vault / secrets backend

**When down:** secret fetches fail.

**Fallback:** secrets resolved at config-load are cached in the running pipeline. The proxy keeps using those values until the next reload. New `secret:` references introduced by a reloaded config will fail their resolution attempt and the reload aborts (the previous pipeline stays live).

**Log level:** `WARN` on fetch failure, `ERROR` if a reload is aborted because of secret resolution.

**Alert:** yes. A sustained Vault outage blocks config rollouts.

**Config:** see the `Secrets` section in [configuration.md](configuration.md#secrets).

---

### Origin callback hooks

**When down:** an `origins.*.on_request` or `on_response` webhook POST fails (connect error, timeout, non-2xx).

**Fallback:** audit-mode callbacks (the default) are fire-and-forget; the triggering request or response proceeds unaffected regardless of delivery outcome. Enrichment-mode callbacks (`enrich: true`) are awaited inline, bounded by their own `timeout` (default 5s); a failure or timeout there just means no `X-Inject-*` response headers get applied, not a failed request. The failure is logged at WARN with the URL and event type (`on_request` / `on_response`). There is no retry queue; the next matching request or response fires independently.

**Log level:** `WARN` per failed delivery (`debug!` on success).

**Alert:** off by default.

**Config:** see the `on_request` / `on_response` origin fields and the `Webhook envelope and signing` section in [configuration.md](configuration.md#webhook-envelope-and-signing).

---

### Alert-channel webhook delivery

**When down:** an alert-channel `webhook` POST fails (connect error, timeout, non-2xx).

**Fallback:** webhook delivery is fire-and-forget. The firing alert still reaches any other configured channel. The failure is logged at WARN with the URL. There is no retry queue today; the next alert evaluation sends independently.

**Log level:** `WARN` per failed delivery.

**Alert:** off by default. A spike of failed deliveries usually means the receiver is down, which it knows about.

**Config:** see the `Webhook envelope and signing` section in [configuration.md](configuration.md#webhook-envelope-and-signing).

---

## Extension points

The code base reserves opaque `extensions` blocks at both the proxy and origin level so out-of-tree crates can read their own keys without the proxy needing to know about them. `Hooks` slots are `Option<Arc<dyn TraitName>>`; the shipped binary leaves them `None` and the request path falls through unannotated. Plugin crates can register concrete implementations through the `sbproxy-plugin` registry.
