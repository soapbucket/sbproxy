# Retry on status

*Last modified: 2026-08-16*

![Retry on status](../../docs/assets/retry-on-status.gif)

Demonstrates status-code retries across a two-target load balancer. The `retry` block lists `503` in `retry_on`, so a matching upstream response is discarded before any bytes reach the client and target selection runs again. One target points at a deliberately failing local backend, the other at the healthy `test.sbproxy.dev` placeholder; with `algorithm: round_robin` the retry pass advances to the next target, so every request returns 200 even when it first lands on the failing backend.

Status retries are replayed only for safe/idempotent methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, `DELETE`) whose bodies still fit in Pingora's retry buffer. A matching status the proxy cannot safely replay passes through unchanged with an `x-sbproxy-retry-skip-reason` header. When `max_attempts` is exhausted, the client sees the real upstream status.

Whether a retry lands on a different target depends on the algorithm. `round_robin` advances on every selection and needs no health machinery to move on. `weighted_random` and `least_connections` can re-pick the failed target. The hash-based algorithms (`ip_hash`, `uri_hash`, `header_hash`, `cookie_hash`) are deterministic and re-select the same target until outlier detection, a circuit breaker, or an active health check ejects it.

## Run

```bash
sbproxy serve -f sb.yml
```

In a second terminal, run a backend that always answers 503 on the first target's port:

```bash
python3 -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(503); self.send_header("Content-Length", "0"); self.end_headers()
http.server.HTTPServer(("127.0.0.1", 9503), H).serve_forever()'
```

## Try it

```bash
# Always 200. Requests that round-robin onto the failing target are
# retried on the healthy one before anything reaches the client.
for i in 1 2 3 4; do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/get -o /dev/null -w '%{http_code}\n'
done

# To see the cap, both targets need to genuinely fail within the
# attempt budget. Stopping the python backend alone will not do it:
# the second target is the real test.sbproxy.dev, which stays healthy,
# so round-robin still finds a 200. Lowering max_attempts to 1 will
# not do it either: `enabled()` on the retry config is `max_attempts >
# 1`, so max_attempts: 1 turns status-retries off entirely rather than
# capping them at one, and no x-sbproxy-retry-skip-reason header is
# emitted at all. Point both targets at local always-503 backends
# instead (leave max_attempts at its default of 2) and the second
# 503 comes back to the client with:
#   x-sbproxy-retry-skip-reason: max_attempts_exhausted
```

Each fired retry increments `sbproxy_upstream_status_retries_total{origin, status}` on `/metrics`.

## What this exercises

- `action.retry.retry_on` with a response status code
- Retry-pass target re-selection under `round_robin`
- The replay gate (`x-sbproxy-retry-skip-reason` on non-replayable matches)
- `sbproxy_upstream_status_retries_total`

## See also

- [upstream-retries](../upstream-retries/) for the combined connect-error + status story
- [docs/configuration.md](../../docs/configuration.md) (Upstream retries)
- [resilience-stack](../resilience-stack/) for outlier detection, circuit breakers, and health checks
