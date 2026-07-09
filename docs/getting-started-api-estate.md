# Getting started: API estate governance (reverse proxy in front of existing APIs)

*Last modified: 2026-07-09*

## What you will build

You will put SBproxy in front of a set of existing HTTP APIs as a reverse proxy, with one origin per public hostname. The gateway matches the inbound `Host` header, forwards the request to the right upstream, and applies a layer of governance on the way through: a bearer-token allowlist, a per-IP rate limit, and request and response header rewrites. The result is a single edge that every caller goes through, so authentication and traffic policy live in config rather than in each backend.

## Prerequisites

- `curl` for testing requests.
- A reachable upstream API. This guide uses `https://test.sbproxy.dev`, the project's public HTTP echo service (request inspection, similar to httpbin), as a stand-in for your real backend. Swap in your own upstream URL when you are ready.

## Install

One line installs the prebuilt binary on macOS or Linux. The script detects your OS and architecture, fetches the matching release binary, and drops it in `~/.local/bin`:

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

Homebrew, Docker, binary downloads, and source builds are in the [runtime manual's installation section](manual.md#1-installation). Run the gateway against a config file:

```bash
sbproxy serve -f sb.yml
```

The proxy binds to `0.0.0.0:8080` by default.

## Minimal config

Save this as `sb.yml`. Every key here exists in `schemas/sb-config.schema.json` and is drawn from the shipped examples. It governs one origin keyed on `api.example.com`: callers present a bearer token, requests are rate limited per IP, and headers are rewritten on the way to and from the upstream. `example.com` is reserved (RFC 2606), so the client-facing hostname never collides with a real domain; replace it with your own hostname in production, and replace the upstream URL with your real backend.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev

    authentication:
      type: bearer
      tokens:
        - svc-token-alpha
        - svc-token-beta

    policies:
      - type: rate_limiting
        requests_per_second: 5
        burst: 10
        key: connection.remote_ip
        headers:
          enabled: true
          include_retry_after: true

    request_modifiers:
      - headers:
          set:
            X-Forwarded-By: sbproxy
            X-Trace-Id: "{{ request.id }}"
          delete:
            - cookie

    response_modifiers:
      - headers:
          set:
            X-Served-By: sbproxy
            Cache-Control: "public, max-age=60"
```

The `key:` field is a CEL expression that names the rate-limit bucket: `connection.remote_ip` gives each client IP its own token bucket, and something like `request.headers["x-api-key"]` buckets per API key instead. Leave `key:` out and every caller shares one bucket. The `headers` block opts 429 responses into the `X-RateLimit-*` set and `Retry-After`; without it, throttled responses carry no rate-limit headers. `{{ request.id }}` in the `X-Trace-Id` value resolves to the proxy's request id, the same value the access log records as `request_id`. To route different paths to different backends from the same hostname, add a `forward_rules` block; see `examples/forward-rules` for path-, header-, and query-based dispatch.

## Run it and expected output

Start the gateway:

```bash
sbproxy serve -f sb.yml
```

A request with no token is rejected before the upstream is contacted:

```console
$ curl -i -H 'Host: api.example.com' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: application/json

{"error":"unauthorized"}
```

A request with a valid token is forwarded, and you can see the injected request headers reflected back by the echo upstream. The echo lowercases header names, and the body below is trimmed: the hosted service sits behind a CDN that adds headers of its own.

```console
$ curl -is -H 'Host: api.example.com' \
       -H 'Authorization: Bearer svc-token-alpha' \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
Cache-Control: public, max-age=60
Content-Type: application/json; charset=utf-8
x-served-by: sbproxy
...

{"method":"GET","url":"/get","headers":{"authorization":"Bearer svc-token-alpha","host":"test.sbproxy.dev","x-forwarded-by":"sbproxy","x-trace-id":"019f487ef3e573e38ad2f4f568b5c7c3",...},"query":{},"timestamp":"..."}
```

Now trip the rate limit. The bucket refills at 5 tokens a second, so a sequential loop that waits on each round trip never empties it; the burst has to be concurrent:

```console
$ seq 1 30 | xargs -P 15 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: api.example.com' \
    -H 'Authorization: Bearer svc-token-alpha' \
    http://127.0.0.1:8080/get | sort | uniq -c
  10 200
  20 429
```

Each 429 carries the rate-limit headers the policy's `headers` block enabled:

```console
HTTP/1.1 429 Too Many Requests
content-type: application/json
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 2
Retry-After: 2

{"error":"rate limited"}
```

A `Host` header that matches no configured origin is rejected by the proxy itself:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' \
       -H 'Host: unknown.example.com' http://127.0.0.1:8080/get
404
```

## You are done when

- A request with no `Authorization` header returns `401 Unauthorized` with `{"error":"unauthorized"}`.
- A request with `Authorization: Bearer svc-token-alpha` returns `200 OK`.
- The 200 response carries the `x-served-by: sbproxy` and `Cache-Control: public, max-age=60` headers added by `response_modifiers`.
- The echoed request body shows the injected `x-forwarded-by: sbproxy` header, an `x-trace-id` holding the proxy's request id, and no `cookie` header.
- A concurrent burst from one IP drains the 10-token bucket and starts returning `429 Too Many Requests` with `X-RateLimit-*` and `Retry-After` headers.
- A request with an unknown `Host` returns `404`.

## Next steps

- [docs/configuration.md](configuration.md) - the full configuration schema and every origin field.
- [docs/policy.md](policy.md) - the policy engine, including rate limiting and IP filtering.
- [docs/headers-reference.md](headers-reference.md) - the headers SBproxy reads and writes, including the forwarding headers added by default.
- [docs/routing-strategies.md](routing-strategies.md) - host- and path-based routing across multiple backends.
