# Upstream retries

*Last modified: 2026-04-27*

When the proxy cannot establish a TCP/TLS connection to the upstream (DNS failure, refused, unreachable, TLS handshake fail), Pingora calls back into the proxy and the request is retried. With `retry.max_attempts: 3` the proxy attempts the upstream up to three times. `retry_on: [connect_error, timeout]` selects which transport-level failures qualify; status-code retries are not yet wired since they require buffering the upstream response. `backoff_ms: 100` is the base delay, doubled on each attempt and capped at 5s. For load_balancer actions the failed target is reported to the outlier detector so the next attempt picks a different target.

## Run

```bash
sb run -c sb.yml
```

The upstream URL `http://127.0.0.1:9999` deliberately points at a closed port so you can observe the retry behaviour.

## Try it

```bash
# Connect refused -> 3 attempts, ~100ms + 200ms backoff between them, then 502.
time curl -i -H 'Host: localhost' http://127.0.0.1:8080/get
# HTTP/1.1 502 Bad Gateway
#
# real    0m0.42s    (connection refused is fast; retries add the backoff)

# Bring up a backend on :9999 and the first attempt succeeds.
python3 -m http.server 9999 &
curl -s -H 'Host: localhost' http://127.0.0.1:8080/get -o /dev/null -w '%{http_code}\n'
# 200
kill %1

# Watch the proxy log to see the retry attempts:
#   retry attempt=1 reason=connect_error backoff_ms=100
#   retry attempt=2 reason=connect_error backoff_ms=200
#   retry attempt=3 reason=connect_error backoff_ms=400
```

## What this exercises

- `action.retry.max_attempts`
- `action.retry.retry_on` (connect_error, timeout)
- `action.retry.backoff_ms` with exponential doubling capped at 5s
- Per-attempt `upstream_peer` reselection (LB target rotation)

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
