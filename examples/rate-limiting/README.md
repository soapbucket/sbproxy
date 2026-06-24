# Rate limiting policy

*Last modified: 2026-04-27*

![Rate limiting policy](../../docs/assets/rate-limiting.gif)

A token-bucket rate limit attached to a `proxy` action. The `rate_limiting` policy caps each client IP at 5 requests per second with a burst capacity of 10. Excess requests are rejected with HTTP 429 and a `Retry-After` header before the upstream is contacted, so the limit also acts as a circuit-protection layer in front of `test.sbproxy.dev`. The bucket is keyed on the client IP, so different callers get independent budgets.

## Run

```bash
make run CONFIG=examples/rate-limiting/sb.yml
```

Uses the public `test.sbproxy.dev` service as the upstream. No env vars required.

## Try it

```bash
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"args":{},"headers":{"Host":"test.sbproxy.dev",...},"url":"https://test.sbproxy.dev/get"}
```

Burst past the limit. Fire the requests concurrently, otherwise network latency keeps a sequential loop under 5 rps and the bucket refills between calls:

```bash
$ seq 1 30 | xargs -P 30 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: api.local' http://127.0.0.1:8080/get | sort | uniq -c
  10 200
  20 429
```

The burst of 10 passes; the rest are throttled. Inspect a rejected response:

```bash
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/get
HTTP/1.1 429 Too Many Requests
content-type: text/plain
retry-after: 1

rate limit exceeded
```

## What this exercises

- `rate_limiting` policy - token bucket with `requests_per_second` and `burst`
- `key: ip` partitioning - each source IP gets its own bucket
- Pre-upstream rejection - 429 is returned without consulting `test.sbproxy.dev`, with `Retry-After` set so well-behaved clients can back off

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
