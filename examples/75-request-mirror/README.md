# Request mirror

*Last modified: 2026-04-27*

Every request matched by `localhost` is forwarded to the primary upstream `httpbin.org` as normal AND a copy is fired at `https://httpbingo.org` (the mirror). The mirror response is read and discarded; the client only sees the primary's response. Mirror traffic is fire-and-forget. Method, path/query, and headers are mirrored. Body teeing is opt-in via `mirror_body: true` (capped at `max_body_bytes`, default 1 MiB). `Host` and hop-by-hop headers are skipped on the mirror request so vhost-routing on the shadow destination still works. `sample_rate: 1.0` mirrors every request; lower values down to `0.0` sample. Mirror requests carry `X-Sbproxy-Mirror: 1`.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Single request: client sees the httpbin.org body. The mirror at httpbingo.org
# also receives the request asynchronously.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/get | jq .url
# "https://httpbin.org/get"

# Quick burst to show that the client never blocks on the mirror.
for i in $(seq 1 5); do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/get -o /dev/null -w '%{time_total}s\n'
done
# 0.310s
# 0.082s
# 0.085s
# 0.090s
# 0.084s

# A mirror failure does not affect the client. Point mirror.url at an
# unresolvable host and rerun: client still gets 200 from the primary.

# Inside the mirror upstream's logs you would see X-Sbproxy-Mirror: 1
# stamped on every shadow request, distinguishing them from real traffic.
```

## What this exercises

- `mirror.url` shadow upstream
- `mirror.sample_rate` (1.0 = 100%, default)
- `mirror.timeout_ms` independent timeout on the mirror call
- Fire-and-forget semantics; mirror response discarded
- `X-Sbproxy-Mirror: 1` marker on shadow requests
- Optional `mirror_body` for POST/PUT/PATCH replay

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
