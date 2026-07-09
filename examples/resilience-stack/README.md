# Production resilience stack

*Last modified: 2026-07-09*

![Production resilience stack](../../docs/assets/resilience-stack.gif)

Composes four signals on a single load balancer so a flaky backend gets isolated quickly and recovers automatically without operator intervention. Active health checks mark a target unhealthy after `unhealthy_threshold` consecutive failed background probes (catches "the pod is gone" without waiting for real traffic to fail). Outlier detection tracks each target's error rate in a sliding window and ejects when it crosses `threshold` (catches "the pod is up but answering 5xx under load"). The circuit breaker is a formal Closed/Open/HalfOpen state machine, one per target, that trips on consecutive failures (catches "the pod is hard down right now"). Retries automatically try the next target on TCP connect failure, timeout, or configured status codes such as `502` and `503`; the failed target feeds outlier and breaker so subsequent requests skip it without paying the same failure latency again. Each signal is independent. With every target ejected, the load balancer falls back to the unfiltered list rather than 502'ing the client.

## Run

```bash
sbproxy serve -f sb.yml
```

No setup required. Targets are `test.sbproxy.dev` and `test.sbproxy.dev/status/503`; load balancer targets are addressed by scheme, host, and port only, so the second target's `/status/503` path is not applied to traffic and both lanes reach the same echo upstream. Drive failures by requesting `/status/503`, which the echo answers with 503 from either lane; healthy traffic via `/anything` and `/status/200`.

## Try it

```bash
# Healthy traffic distributed round-robin across both targets; both
# lanes answer 200.
for i in 1 2 3 4; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H 'Host: localhost' http://127.0.0.1:8080/status/200
done
# 200 (x4)
```

```bash
# Drive 20 requests through /anything to populate metrics; if either
# target degrades the breaker / outlier detection ejects it.
for i in $(seq 1 20); do
  curl -s -o /dev/null -H 'Host: localhost' \
       http://127.0.0.1:8080/anything
done
```

```bash
# Simulate sustained 5xx. /status/503 answers 503 from either lane;
# each 503 is retried per retry_on and recorded against the lane that
# served it. After 5 consecutive failures a lane's breaker opens;
# once every lane is open the LB falls back to the unfiltered list
# rather than failing closed, and the path keeps returning 503 to
# the client. Recovery runs via HalfOpen probes after
# open_duration_secs.
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H 'Host: localhost' http://127.0.0.1:8080/status/503
done
# 503 (x6)
```

## What this exercises

- `load_balancer` action with `algorithm: round_robin` across multiple `targets`
- `retry` on `connect_error`, `timeout`, and numeric status codes with bounded `max_attempts` and `backoff_ms`
- `circuit_breaker` per target with `failure_threshold` / `success_threshold` / `open_duration_secs`
- `outlier_detection` with sliding-window threshold and ejection duration
- Per-target `health_check` background probes with unhealthy / healthy thresholds

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
