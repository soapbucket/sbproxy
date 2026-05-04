# Connection pool

*Last modified: 2026-04-27*

The `connection_pool` block on `api.local` sizes the proxy's outbound HTTP client for this origin. `max_connections: 32` caps concurrent in-flight upstream connections, `idle_timeout_secs: 60` reaps idle keep-alive connections after a minute, and `max_lifetime_secs: 300` is the hard ceiling on any single connection's lifetime. Tune these when an upstream is sensitive to too many concurrent connections, or when an LB aggressively terminates long-lived TCP sessions.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Send a small parallel burst. Connections are reused within the cap;
# anything over queues briefly.
for i in $(seq 1 10); do
  curl -s -H 'Host: api.local' http://127.0.0.1:8080/get \
    -o /dev/null -w '%{http_code} %{time_total}s\n' &
done; wait
# 200 0.082s
# 200 0.084s
# 200 0.090s
# ... (all 200, time_total varies)

# Single warm-up request. Subsequent requests reuse the same connection.
curl -s -H 'Host: api.local' http://127.0.0.1:8080/get -o /dev/null -w '%{time_total}s\n'
# 0.310s   (cold)
curl -s -H 'Host: api.local' http://127.0.0.1:8080/get -o /dev/null -w '%{time_total}s\n'
# 0.082s   (warm, pool hit)

# After idle_timeout_secs (60s) the proxy releases idle connections.
sleep 65 && curl -s -H 'Host: api.local' http://127.0.0.1:8080/get -o /dev/null -w '%{time_total}s\n'
# 0.310s   (cold again)
```

## What this exercises

- `connection_pool.max_connections`
- `connection_pool.idle_timeout_secs`
- `connection_pool.max_lifetime_secs`
- Per-origin upstream pool sizing

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
