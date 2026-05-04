# Response caching

*Last modified: 2026-04-27*

Demonstrates the per-origin `response_cache` block. Successful responses are stored in the in-memory cache for 60 seconds, keyed on the request method, host, path, and query string. The second request for the same URL is served from cache without contacting `httpbin.org`. With `cache_control: true`, SBproxy honours upstream `Cache-Control` directives such as `no-store` or `max-age` overrides when they are stricter than the configured TTL. The TTL difference is most visible against `/delay/N`, an httpbin endpoint that sleeps server-side.

## Run

```bash
make run CONFIG=examples/03-response-caching/sb.yml
```

No env vars required. Uses `httpbin.org` for the slow upstream call.

## Try it

First request hits the upstream and pays the 2 second delay:

```bash
$ time curl -s -H 'Host: cached.local' http://127.0.0.1:8080/delay/2 -o /dev/null

real    0m2.156s
user    0m0.014s
sys     0m0.011s
```

Second request, same URL, served from cache:

```bash
$ time curl -s -H 'Host: cached.local' http://127.0.0.1:8080/delay/2 -o /dev/null

real    0m0.012s
user    0m0.005s
sys     0m0.004s
```

Inspect the cached response headers:

```bash
$ curl -is -H 'Host: cached.local' http://127.0.0.1:8080/delay/2 | head -n 6
HTTP/1.1 200 OK
content-type: application/json
x-cache: HIT
age: 4
```

A request with a different query string is treated as a separate cache key and hits the upstream again.

## What this exercises

- `response_cache` action sibling - per-origin cache configuration
- `ttl_seconds` - hard upper bound on cache entry age
- `cache_control: true` - upstream `Cache-Control` headers can shorten the TTL
- `X-Cache: HIT` and `Age` response headers indicate a cached serve

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/cache-reserve.md](../../docs/cache-reserve.md) - tiered cache notes
