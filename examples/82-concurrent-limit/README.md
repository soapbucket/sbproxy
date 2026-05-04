# Concurrent request limit

*Last modified: 2026-04-27*

Demonstrates the `concurrent_limit` policy. The limiter caps the number of in-flight requests per key, distinct from the requests-per-second `rate_limiting` policy. Each accepted request takes a permit; the permit is released when the request finishes (success, error, or client disconnect). Once `max` permits are issued for a given key, further requests are rejected with the configured `status` and `error_body`. Useful for protecting backends with low concurrency budgets such as legacy SOAP services, database-bound endpoints, or GPU inference workers with a fixed slot count.

## Run

```bash
sb run -c sb.yml
```

No setup required. The example caps in-flight requests at 3 per client IP and routes overflow to a 503 with a JSON body.

## Try it

```bash
# Open 5 slow requests in parallel; the 4th and 5th get 503.
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H 'Host: localhost' http://127.0.0.1:8080/delay/3 &
done
wait
# 200
# 200
# 200
# 503
# 503
```

```bash
# A single request well under the cap completes normally.
curl -s -o /dev/null -w "%{http_code}\n" \
  -H 'Host: localhost' http://127.0.0.1:8080/get
# 200
```

```bash
# Once the in-flight requests drain, new requests are admitted again.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/get | jq .url
```

## What this exercises

- `concurrent_limit` policy - permit-based in-flight cap with configurable rejection status and body
- `key: ip` - per-client-IP counter (alternatives are `origin` for a global counter and `api_key` for per-token)
- `proxy` action - permits release on completion regardless of upstream outcome

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
