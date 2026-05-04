# Basic reverse proxy

*Last modified: 2026-04-27*

The simplest possible sbproxy configuration. A single origin keyed on `myapp.example.com` forwards every inbound request to `https://test.sbproxy.dev`, sbproxy's public HTTP echo service. The proxy listens on `127.0.0.1:8080`, matches the `Host` header to the configured origin, and rewrites the request line to point at the upstream. The echo service replies with the inbound request serialised as JSON, so you can confirm headers, method, and path made it through unchanged.

## Run

```bash
make run CONFIG=examples/00-basic-proxy/sb.yml
```

No external services or env vars required. `test.sbproxy.dev` is a public endpoint operated by the project.

## Try it

`test.sbproxy.dev` exposes three endpoints we can hit through the proxy: `/echo` (echoes the request back as JSON), `/health` (liveness), and `/status/<code>` (returns the requested HTTP status).

```bash
$ curl -s -H 'Host: myapp.example.com' http://127.0.0.1:8080/echo
{
  "method": "GET",
  "url": "/echo",
  "headers": {
    "host": "test.sbproxy.dev",
    "user-agent": "curl/8.4.0",
    "x-forwarded-for": "127.0.0.1",
    "x-forwarded-proto": "http"
  },
  "query": {},
  "timestamp": "..."
}
```

```bash
$ curl -s -H 'Host: myapp.example.com' http://127.0.0.1:8080/health
{"status":"ok","service":"test.sbproxy.dev","timestamp":"..."}
```

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: myapp.example.com' http://127.0.0.1:8080/status/404
404
```

The proxy faithfully forwards whatever status the upstream emits, including 4xx/5xx.

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: unknown.example.com' http://127.0.0.1:8080/echo
404
```

A `Host` header that does not match any configured origin is rejected by the proxy itself with a 404.

## What this exercises

- `proxy` action - forwards the request to a single upstream URL
- Host-based origin routing - the `Host` header selects which origin handles the request
- Default forwarding header behaviour - `X-Forwarded-For`, `X-Forwarded-Proto`, and `Host` rewrites are added automatically

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/architecture.md](../../docs/architecture.md) - how the request pipeline is structured
