# Dependency degradation matrix

*Last modified: 2026-05-03*

What happens when each dependency that SBproxy talks to is unavailable, and how the proxy degrades while it heals.

## Principles

1. The proxy MUST always start, even if dependencies are down.
2. The proxy MUST keep serving traffic during dependency outages.
3. Degradation must be visible in metrics and logs.
4. Recovery is automatic. No manual intervention required.

## Matrix

| Dependency | When down | Fallback | Recovery | Metrics |
|---|---|---|---|---|
| Upstream target (`proxy` or `load_balancer`) | Connection error / timeout | Active health checks + outlier detection + circuit breaker eject the target. Retries pick the next healthy peer. With every target ejected, the LB falls back to the unfiltered list rather than 502'ing the client. | Auto on next probe success / breaker recovery window | `sbproxy_requests_total{status}`, `sbproxy_origin_errors_total` |
| AI provider (OpenAI, Anthropic, OpenRouter, ...) | 5xx, timeout, rate-limit | Routing strategy picks the next provider in the chain (`fallback_chain` / `cost_optimized`). All-providers-failed returns 502. | Auto on next successful request | `sbproxy_ai_failovers_total`, `sbproxy_ai_provider_errors_total` |
| Redis (`proxy.l2_cache_settings`) | Connection / command failure | Per-origin in-memory cache and per-process rate-limit counters take over. Cross-replica state is suspended until reconnect. | Auto-reconnect with exponential backoff | `sbproxy_redis_connection_errors_total` |
| ACME CA (Let's Encrypt) | Renewal request fails | Existing cert keeps serving until expiry. With no usable cert, an HTTP-01 self-signed bootstrap is served and an `ERROR` is logged loudly. | Retry with exponential backoff (1m → 24h) | `sbproxy_acme_errors_total` |
| Upstream DNS (`service_discovery`) | Resolver timeout / NXDOMAIN | The cached A/AAAA set keeps serving past TTL until the next refresh succeeds. New unseen hostnames fall back to Pingora's connect-time resolver. | Auto on next refresh | `sbproxy_dns_resolver_errors_total` |
| Vault / secrets backend (`proxy.secrets`) | Fetch fails | Secrets resolved at config-load are cached and reused. New rotation calls fail loudly. | Auto-reconnect, re-fetch on recover | `sbproxy_secrets_errors_total` |
| Webhook receivers (`on_request` / `on_response` / alerting) | Send fails | Webhook delivery is fire-and-forget by design. A failed POST is logged at WARN; the request itself is not affected. | None needed; next event tries again | `sbproxy_webhook_failures_total` |

## Detailed reference

### Upstream target (proxy or load_balancer)

**When down:** the target returns a connect error, a timeout, or a 5xx response.

**Fallback:** four signals compose a self-healing pool:

* **Active health checks** mark a target unhealthy after `unhealthy_threshold` consecutive probe failures and healthy again after `healthy_threshold` successes.
* **Outlier detection** ejects targets whose error rate over `window_secs` crosses `threshold` (5xx + connect failures count).
* **Circuit breaker** trips on `failure_threshold` consecutive failures and recovers via `success_threshold` HalfOpen probes.
* **Retries** rerun `upstream_peer` on connect-error / timeout. For load balancers the failed target is reported to outlier and breaker so the next attempt picks a different healthy peer.

When every target is ejected at once, the LB falls back to the unfiltered list rather than failing the client.

**Log level:** `WARN` on first failure, `WARN` again when a target is ejected, `INFO` on recovery.

**Alert:** yes. Configure via `proxy.alerting.channels`. Alerts include the standard `X-Sbproxy-*` identity headers and (when `secret` is set) HMAC-SHA256 signatures.

**Config:**
```yaml
action:
  type: load_balancer
  retry:
    max_attempts: 3
    retry_on: [connect_error, timeout]
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

See [`examples/90-resilience-stack/sb.yml`](../examples/90-resilience-stack/sb.yml).

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

**Fallback:** the proxy keeps using the per-origin in-memory cache. Rate-limit counters become node-local; with multiple replicas, slightly more traffic may sneak through the global limit until Redis recovers. Response cache entries written during the outage are local and not shared. Reconnects use exponential backoff with a circuit breaker so a sustained outage does not pile up retry attempts.

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

---

### ACME CA (Let's Encrypt)

**When down:** ACME directory or order requests fail.

**Fallback:** existing certificates keep serving. If the listener has no cert at all (fresh boot, ACME never succeeded), a self-signed bootstrap cert is generated so the HTTPS listener can come up; ACME replaces it with a real cert once issuance succeeds. Renewal failures are retried with exponential backoff (1 minute → 24 hours).

**Log level:** `WARN` per renewal failure with time-to-expiry, `ERROR` if the active cert has expired.

**Alert:** yes. Fires when expiry is within 14 days and renewal is failing.

**Config:** see the `ACME / auto TLS` section in [configuration.md](configuration.md#acme--auto-tls).

---

### Upstream DNS (service_discovery)

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

See [`examples/83-service-discovery/sb.yml`](../examples/83-service-discovery/sb.yml).

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
