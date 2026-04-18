# Dependency Degradation Matrix
*Last modified: 2026-04-17*

What happens when each external dependency is unavailable, and how the proxy degrades.

## Degradation Behaviors

| Dependency | Impact When Down | Fallback Behavior | Recovery |
|-----------|-----------------|-------------------|----------|
| **Redis** | Distributed rate limiting, shared cache, pub/sub | In-memory rate limiting (per-instance), local cache only, events queued | Auto-reconnect with exponential backoff |
| **Classifier sidecar** | AI content classification | Skip classification, log warning, pass requests through | Health check polls every 10s |
| **ACME CA** (Let's Encrypt) | New certificate issuance | Serve existing certs until expiry, alert at 7d/1d | Retry with backoff, fall back to staging CA |
| **Upstream providers** | AI requests to that provider | Failover to next provider in chain, circuit breaker opens | Circuit breaker half-open probe every 30s |
| **DNS** | Hostname resolution | Serve from DNS cache (TTL-based), stale entries used up to 5min | Retry resolution on next request |
| **HashiCorp Vault** | Secret resolution | Cache fallback (last known values), env var fallback | Reconnect on next resolve interval |
| **Config source** (file/API) | Config updates | Continue with last known good config | File watcher re-attaches, API retried |
| **Prometheus** (scrape target down) | Metrics collection | Metrics buffer in-memory, no data loss | Next scrape picks up accumulated counters |
| **ClickHouse** | Log export | Buffer logs in memory (bounded), drop oldest on overflow | Reconnect with backoff, flush buffer |
| **Upstream origin** | Proxy requests to that origin | Fallback origin if configured, circuit breaker, custom error page | Health check probes, circuit breaker recovery |

## Circuit Breaker States

```
Closed (normal) --[failure threshold]--> Open (rejecting)
                                            |
                                     [probe interval]
                                            |
                                        Half-Open (single probe)
                                            |
                                  success: --> Closed
                                  failure: --> Open
```

Default thresholds:
- **Failure threshold**: 5 consecutive failures or 50% error rate in 30s window
- **Open duration**: 30 seconds before half-open probe
- **Half-open probes**: 1 request allowed through

## Configuration

```yaml
proxy:
  circuit_breaker:
    failure_threshold: 5
    failure_rate_threshold: 0.5
    failure_rate_window_secs: 30
    open_duration_secs: 30

  dns_cache:
    ttl_secs: 300
    stale_ttl_secs: 300   # serve stale for 5 min after TTL expires

  secrets:
    fallback: cache       # "cache", "reject", or "env"
```

## Health Check Endpoints

| Endpoint | What It Checks | Failure Impact |
|----------|---------------|----------------|
| `/health` | Proxy process alive | Load balancer removes instance |
| `/health/ready` | Config loaded, at least one origin active | Stops receiving traffic |
| `/health/live` | Process not deadlocked | K8s restarts pod |

## Monitoring Recommendations

- Alert on circuit breaker state transitions (open events)
- Alert on DNS cache serving stale entries for > 2 minutes
- Alert on vault cache fallback usage (secrets not refreshing)
- Alert on config age > 10 minutes without reload
- Alert on upstream error rate > 10% sustained for 5 minutes
