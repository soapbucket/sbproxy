# Response caching

*Last modified: 2026-07-09*

![Response caching](../../docs/assets/response-caching.gif)

Demonstrates the per-origin `response_cache` block. Successful responses are stored in the in-memory cache for 60 seconds, keyed on the request method, host, path, and query string. The second request for the same URL is served from cache without contacting `test.sbproxy.dev`. With `cache_control: true`, SBproxy honours upstream `Cache-Control` directives such as `no-store` or `max-age` overrides when they are stricter than the configured TTL. The cache is easiest to see in the round-trip time: the first request pays the full trip to the echo upstream, the cached one answers from memory.

## Run

```bash
make run CONFIG=examples/response-caching/sb.yml
```

No env vars required. Uses `test.sbproxy.dev` (the echo upstream) for the upstream call.

## Try it

First request hits the upstream and pays the full round trip. No `x-sbproxy-cache` header appears on a miss:

```bash
$ time curl -s -H 'Host: cached.local' http://127.0.0.1:8080/get -o /dev/null

real    0m0.213s
user    0m0.014s
sys     0m0.011s
```

Second request, same URL, served from cache:

```bash
$ time curl -s -H 'Host: cached.local' http://127.0.0.1:8080/get -o /dev/null

real    0m0.012s
user    0m0.005s
sys     0m0.004s
```

Inspect the cached response headers:

```bash
$ curl -is -H 'Host: cached.local' http://127.0.0.1:8080/get | head -n 4
HTTP/1.1 200 OK
content-type: application/json
x-sbproxy-cache: HIT
```

A request with a different query string is treated as a separate cache key and hits the upstream again.

## What this exercises

- `response_cache` action sibling - per-origin cache configuration
- `ttl_seconds` - hard upper bound on cache entry age
- `cache_control: true` - upstream `Cache-Control` headers can shorten the TTL
- `x-sbproxy-cache` response header - `HIT`, `STALE`, or `HIT-RESERVE` marks a cached serve; the header is absent on a miss, and no `Age` header is set

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/cache-reserve.md](../../docs/cache-reserve.md) - tiered cache notes
