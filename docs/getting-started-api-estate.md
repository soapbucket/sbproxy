# Getting started: API estate governance (reverse proxy in front of existing APIs)

*Last modified: 2026-06-04*

## What you will build

You will put SBproxy in front of a set of existing HTTP APIs as a reverse proxy, with one origin per public hostname. The gateway matches the inbound `Host` header, forwards the request to the right upstream, and applies a layer of governance on the way through: a bearer-token allowlist, a per-IP rate limit, and request and response header rewrites. The result is a single edge that every caller goes through, so authentication and traffic policy live in config rather than in each backend.

## Prerequisites

- Rust 1.95+ and `cargo` (only needed to build from source).
- `curl` for testing requests.
- A reachable upstream API. This guide uses `https://test.sbproxy.dev`, the project's public HTTP echo service (request inspection, similar to httpbin), as a stand-in for your real backend. Swap in your own upstream URL when you are ready.

You do not need Rust at all if you install a prebuilt binary (see below).

## Install and build

Pick one install path.

Prebuilt binary with curl (macOS / Linux):

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

The script detects your OS and architecture, fetches the matching release binary, and drops it in `~/.local/bin`.

Homebrew (macOS / Linux):

```bash
brew tap soapbucket/tap
brew install sbproxy
```

Docker:

```bash
docker pull ghcr.io/soapbucket/sbproxy:latest
```

From source:

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
make build
```

`make build` produces a debug binary at `target/debug/sbproxy`. For an optimised binary at `target/release/sbproxy`, run:

```bash
cargo build --release -p sbproxy
```

Run the gateway against a config file:

```bash
./target/release/sbproxy serve -f sb.yml
```

The proxy binds to `127.0.0.1:8080` by default.

## Minimal config

Save this as `sb.yml`. Every key here exists in `schemas/sb-config.schema.json` and is drawn from the shipped examples. It governs one origin keyed on `api.example.com`: callers present a bearer token, requests are rate limited per IP, and headers are rewritten on the way to and from the upstream. `example.com` is reserved (RFC 2606), so the client-facing hostname never collides with a real domain; replace it with your own hostname in production, and replace the upstream URL with your real backend.

```yaml
# yaml-language-server: $schema=./schemas/sb-config.schema.json
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
        key: ip

    request_modifiers:
      - headers:
          set:
            X-Forwarded-By: sbproxy
            X-Trace-Id: "{{ uuid() }}"
          delete:
            - cookie

    response_modifiers:
      - headers:
          set:
            X-Served-By: sbproxy
            Cache-Control: "public, max-age=60"
```

To route different paths to different backends from the same hostname, add a `forward_rules` block; see `examples/forward-rules` for path-, header-, and query-based dispatch.

## Run it and expected output

Start the gateway:

```bash
./target/release/sbproxy serve -f sb.yml
```

A request with no token is rejected before the upstream is contacted:

```console
$ curl -i -H 'Host: api.example.com' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: text/plain

unauthorized
```

A request with a valid token is forwarded, and you can see the injected request headers reflected back by the echo upstream:

```console
$ curl -is -H 'Host: api.example.com' \
       -H 'Authorization: Bearer svc-token-alpha' \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json
x-served-by: sbproxy
cache-control: public, max-age=60

{"args":{},"headers":{"Authorization":"Bearer svc-token-alpha","Host":"test.sbproxy.dev","X-Forwarded-By":"sbproxy","X-Trace-Id":"..."},"url":"https://test.sbproxy.dev/get"}
```

Burst past the rate limit and the bucket starts returning 429 with a `Retry-After` header:

```console
$ for i in $(seq 1 20); do
    curl -s -o /dev/null -w '%{http_code}\n' \
      -H 'Host: api.example.com' \
      -H 'Authorization: Bearer svc-token-alpha' \
      http://127.0.0.1:8080/get
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

A `Host` header that matches no configured origin is rejected by the proxy itself:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' \
       -H 'Host: unknown.example.com' http://127.0.0.1:8080/get
404
```

## You are done when

- A request with no `Authorization` header returns `401 Unauthorized`.
- A request with `Authorization: Bearer svc-token-alpha` returns `200 OK`.
- The 200 response carries the `x-served-by: sbproxy` and `cache-control: public, max-age=60` headers added by `response_modifiers`.
- The forwarded request body shows the injected `X-Forwarded-By: sbproxy` and `X-Trace-Id` headers and no `Cookie` header.
- A burst of more than 10 requests per second from one IP starts returning `429 Too Many Requests` with a `Retry-After` header.
- A request with an unknown `Host` returns `404`.

## Next steps

- [docs/configuration.md](configuration.md) - the full configuration schema and every origin field.
- [docs/policy.md](policy.md) - the policy engine, including rate limiting and IP filtering.
- [docs/headers-reference.md](headers-reference.md) - the headers SBproxy reads and writes, including the forwarding headers added by default.
- [docs/routing-strategies.md](routing-strategies.md) - host- and path-based routing across multiple backends.
