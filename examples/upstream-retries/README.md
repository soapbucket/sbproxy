# Upstream retries

*Last modified: 2026-08-16*

![Upstream retries](../../docs/assets/upstream-retries.gif)

When the proxy cannot establish a TCP/TLS connection to the upstream (DNS failure, refused, unreachable, TLS handshake fail), Pingora calls back into the proxy and the request is retried. With `retry.max_attempts: 3` the proxy attempts the upstream up to three times. `retry_on: [connect_error, timeout, 502, 503]` selects which transport-level failures and upstream response statuses qualify. `backoff_ms: 100` is the base delay, doubled on each attempt and capped at 5s. For load_balancer actions the failed target is reported to the outlier detector so the next attempt picks a different target.

Status-code retries are replayed only for safe/idempotent methods and replayable bodies. If a matching status cannot be safely replayed, the upstream response passes through with `x-sbproxy-retry-skip-reason`.

## Run

```bash
sbproxy serve -f sb.yml
```

The upstream URL `http://127.0.0.1:9999` deliberately points at a closed port so you can observe the retry behaviour.

## Try it

```bash
# Connect refused -> 3 attempts, ~100ms + 200ms backoff between them, then 502.
time curl -i -H 'Host: localhost' http://127.0.0.1:8080/get
# HTTP/1.1 502 Bad Gateway
#
# real    0m0.42s    (connection refused is fast; retries add the backoff)

# Bring up a backend on :9999 and the first attempt succeeds. Request `/`
# (not `/get`) since a bare http.server 404s on any path that is not a real
# file in its directory, and `/` always serves a directory listing.
python3 -m http.server 9999 &
curl -s -H 'Host: localhost' http://127.0.0.1:8080/ -o /dev/null -w '%{http_code}\n'
# 200
kill %1

# Watch the proxy log to see the retry attempts (Pingora's own connect-error
# line, one per attempt; `retry: true` on the first two, `retry: false` and
# a 502 on the third):
#   WARN pingora_proxy: Fail to proxy: Upstream ConnectRefused ... tries: 1, retry: true, GET /get, Host: localhost
#   WARN pingora_proxy: Fail to proxy: Upstream ConnectRefused ... tries: 2, retry: true, GET /get, Host: localhost
#   ERROR pingora_proxy: Fail to proxy: Upstream ConnectRefused ... status: 502, tries: 3, retry: false, GET /get, Host: localhost
```

## What this exercises

- `action.retry.max_attempts`
- `action.retry.retry_on` (connect_error, timeout, numeric status codes)
- `action.retry.backoff_ms` with exponential doubling capped at 5s
- Per-attempt `upstream_peer` reselection (LB target rotation)

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
