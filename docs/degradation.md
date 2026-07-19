# Dependency degradation matrix

*Last modified: 2026-07-18*

What happens when each dependency that SBproxy talks to is unavailable, and how the proxy degrades while it heals.

## Principles

1. A policy that selects shared runtime state must have that state wiring at startup.
2. Once active, the proxy MUST keep serving traffic during dependency outages where the feature contract is fail-open.
3. Degradation must be visible in metrics and logs.
4. Recovery is automatic. No manual intervention required.

## Matrix

| Dependency | When down | Fallback | Recovery | Metrics |
|---|---|---|---|---|
| Upstream target (`proxy` or `load_balancer`) | Connection error / timeout | Active health checks + outlier detection + circuit breaker eject the target. Retries pick the next healthy peer. With every target ejected, the LB falls back to the unfiltered list rather than 502'ing the client. | Auto on next probe success / breaker recovery window | `sbproxy_requests_total{status}`, `sbproxy_origin_requests_total{origin,method,status}` |
| AI provider (OpenAI, Anthropic, OpenRouter, ...) | 5xx, timeout, rate-limit | Routing strategy picks the next provider in the chain (`fallback_chain` / `cost_optimized`). All-providers-failed returns 502. | Auto on next successful request | `sbproxy_ai_failovers_total`, `sbproxy_ai_provider_errors_total` |
| Redis (`proxy.l2_cache_settings`) | Connection / command failure | General response caching and rate limiting fall back to per-process behavior. AI `summary_buffer` state never falls back to worker memory: that lever fails open, preserves the last committed message list, and lets later levers run. | Auto-reconnect; summary updates resume on a later request | `sbproxy_ai_compression_state_operations_total`, `sbproxy_ai_compression_redis_coordination_total` for compression state |
| Dedicated AI compression summarizer | Timeout, provider failure, invalid output, policy denial, or budget denial | `summary_buffer` skips safe admission denials or fails open on runtime errors. The primary AI request continues with the last committed messages, and a later `window_fit` lever still runs. | Next eligible request retries under the configured policy and timeout | `sbproxy_ai_compression_lever_total`, `sbproxy_ai_compression_requests_total`, `sbproxy_ai_compression_duration_seconds` |
| Governed-key budget backend (`key_management.governance.backend`, strict tier only) | Connection / command failure | Only affects keys governed under `consistency: strict`. The default `approximate` tier does not depend on this backend at all; its per-node counters keep disseminating over the cluster mesh. For a strict key, a reserve call that cannot reach the backend denies the request (`503`) by default (`failure_mode: closed`); `failure_mode: allow_unreserved` admits it instead without a reservation. A settle call on an already-admitted request is unaffected by `failure_mode` and stays best-effort. | Auto-reconnect; enforcement resumes on the next successful call | `sbproxy_governance_fail_open_total{key_id}` on `allow_unreserved`; also logged at WARN (fail-open/fail-closed) or DEBUG (other reserve/settle errors) |
| ACME CA (Let's Encrypt) | Renewal request fails | Existing cert keeps serving until expiry. With no usable cert, an HTTP-01 self-signed bootstrap is served and an `ERROR` is logged loudly. | Retry with exponential backoff (1m to 24h) | `sbproxy_acme_renewals_total{result}` |
| Upstream DNS (`service_discovery`) | Resolver timeout / NXDOMAIN | The cached A/AAAA set keeps serving past TTL until the next refresh succeeds. New unseen hostnames fall back to Pingora's connect-time resolver. | Auto on next refresh | None dedicated; resolver failures are logged at WARN |
| Vault / secrets backend (`proxy.secrets`) | Fetch fails | Secrets resolved at config-load are cached and reused. New rotation calls fail loudly. | Auto-reconnect, re-fetch on recover | `sbproxy_vault_resolution_total{backend,result}` |
| Webhook receivers (`on_request` / `on_response` / alerting) | Send fails | Webhook delivery is fire-and-forget by design. A failed POST is logged at WARN; the request itself is not affected. | None needed; next event tries again | `sbproxy_outbound_webhook_attempts_total{result}` |

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

### Redis (l2 cache + cross-replica state)

**When down:** Redis connect or command fails.

**Fallback:** for the general L2 consumers, the proxy keeps using the per-origin in-memory cache. Rate-limit counters become node-local; with multiple replicas, slightly more traffic may sneak through the global limit until Redis recovers. Response cache entries written during the outage are local and not shared. Reconnects use exponential backoff with a circuit breaker so a sustained outage does not pile up retry attempts.

AI context summary state is intentionally different. When an AI handler selects
`compression.state.backend: redis`, Redis is the only canonical summary store.
On a connection or command failure, `summary_buffer` records
`state_unavailable`, preserves the last committed message list, and continues
to later levers and upstream dispatch. It never creates a worker-local summary
fork.

**Log level:** `ERROR` on initial disconnect, `WARN` per reconnect attempt, `INFO` on recovery.

**Alert:** yes when running clustered. Redis unavailability degrades multi-replica consistency.

**Config:**
```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://redis.internal:6379/0
```

For strict Redis leases, fences, coordination events, and the full fail-open
table, see [AI context compression](ai-context-compression.md).

---

### Dedicated AI compression summarizer

**When down:** the exact summarizer provider times out or returns an invalid
response. Credential policy and budget admission can also decline the internal
summary call without contacting the provider.

**Fallback:** runtime failures are failure-open for the caller's primary AI
request. The failed lever keeps the last committed message list and later
levers continue. Safe admission conditions such as `policy_denied`,
`budget_denied`, `lock_contended`, and `state_expired` are skips rather than
failures. An expired summary is never reused while Redis awaits physical TTL
removal.

Selecting `backend: redis` without the Redis L2 wiring is a startup
configuration error. `backend: mesh` is rejected because the current mesh
cache is not a durable replicated session store. Runtime failure-open behavior
begins only after a valid pipeline has been built.

**Log level:** the content-free `ai_compression_summary` event is `DEBUG` when
all levers skip, `INFO` when at least one applies and none fail, and `WARN` when
any lever fails.

**Alert:** the bundled rules alert on a sustained compression failure ratio and
on state errors or rejected Redis updates.

**Config and full behavior:** see
[AI context compression](ai-context-compression.md).

---

### Governed-key budget backend (strict tier)

**When down:** the dedicated Redis connection configured under `key_management.governance.backend` fails to connect, or a reserve, settle, or release script call errors.

**Fallback:** this only affects keys governed under `consistency: strict`. The `approximate` tier (the default) never talks to this backend; its per-node counters keep disseminating over the cluster mesh instead, bounded by a staleness window rather than an outage. See [Governed admission: strict and approximate](key-management.md#governed-admission-strict-and-approximate) for both tiers. For a strict key, `key_management.governance.failure_mode` decides what a reserve call does when it cannot reach the backend: the default `closed` denies the request with `503` rather than let the governed limit go unenforced; `allow_unreserved` admits it instead without a reservation, and that decision is always recorded on the `security_audit` channel. A settle call that cannot reach the backend after a reservation already succeeded is unaffected by `failure_mode`; it stays best-effort, and the reservation's own drop-time repair reconciles it later.

**Log level:** `WARN` per fail-open or fail-closed decision on a reserve call; `DEBUG` for other reserve/settle errors.

**Alert:** off by default. `sbproxy_governance_fail_open_total{key_id}` counts fail-open admissions when `failure_mode: allow_unreserved` is set.

**Config:**
```yaml
proxy:
  key_management:
    governance:
      consistency: strict
      backend:
        type: redis
        url: rediss://governance.internal:6379/2
      failure_mode: closed        # closed | allow_unreserved
```

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

### Webhook receivers

**When down:** `on_request`, `on_response`, or alert-channel POSTs fail (connect error, timeout, non-2xx).

**Fallback:** webhook delivery is fire-and-forget. The request that triggered the webhook is unaffected. The failure is logged at WARN with the URL and event type. There is no retry queue today; the next event is sent independently.

**Log level:** `WARN` per failed delivery.

**Alert:** off by default. A spike of failed deliveries usually means the receiver is down, which it knows about.

**Config:** see the `Webhook envelope and signing` section in [configuration.md](configuration.md#webhook-envelope-and-signing).

---

## Extension points

The OSS code base reserves opaque `extensions` blocks at both the proxy and origin level so third-party crates can read their own keys without OSS needing to know about them. `Hooks` slots are `Option<Arc<dyn TraitName>>`; the OSS binary leaves them `None` and the request path falls through unannotated. Plugin crates can register concrete implementations through the `sbproxy-plugin` registry.
