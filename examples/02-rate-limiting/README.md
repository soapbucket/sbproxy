# Rate limiting policy

*Last modified: 2026-04-27*

A token-bucket rate limit attached to a `proxy` action. The `rate_limiting` policy caps each client IP at 5 requests per second with a burst capacity of 10. Excess requests are rejected with HTTP 429 and a `Retry-After` header before the upstream is contacted, so the limit also acts as a circuit-protection layer in front of `httpbin.org`. The bucket is keyed on the client IP, so different callers get independent budgets.

## Run

```bash
make run CONFIG=examples/02-rate-limiting/sb.yml
```

Uses the public `httpbin.org` service as the upstream. No env vars required.

## Try it

```bash
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"args":{},"headers":{"Host":"httpbin.org",...},"url":"https://httpbin.org/get"}
```

Burst past the limit:

```bash
$ for i in $(seq 1 20); do
    curl -s -o /dev/null -w '%{http_code}\n' \
      -H 'Host: api.local' http://127.0.0.1:8080/get
  done
200
200
200
200
200
200
200
200
200
200
429
429
429
429
429
429
429
429
429
429
```

The 11th request and beyond are throttled. Inspect a rejected response:

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
- Pre-upstream rejection - 429 is returned without consulting `httpbin.org`, with `Retry-After` set so well-behaved clients can back off

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
