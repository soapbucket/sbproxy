# Basic reverse proxy

*Last modified: 2026-04-27*

The simplest possible sbproxy configuration. A single origin keyed on `myapp.example.com` forwards every inbound request to `https://test.sbproxy.dev`, sbproxy's public HTTP echo service. The proxy listens on `127.0.0.1:8080`, matches the `Host` header to the configured origin, and rewrites the request line to point at the upstream. The echo service replies with the inbound request serialised as JSON, so you can confirm headers, method, and path made it through unchanged.

## Run

```bash
make run CONFIG=examples/00-basic-proxy/sb.yml
```

No external services or env vars required. `test.sbproxy.dev` is a public endpoint operated by the project.

## Try it

```bash
$ curl -s -H 'Host: myapp.example.com' http://127.0.0.1:8080/get
{
  "args": {},
  "headers": {
    "Host": "test.sbproxy.dev",
    "User-Agent": "curl/8.4.0",
    "X-Forwarded-For": "127.0.0.1",
    "X-Forwarded-Proto": "http"
  },
  "method": "GET",
  "url": "https://test.sbproxy.dev/get"
}
```

```bash
$ curl -s -H 'Host: myapp.example.com' http://127.0.0.1:8080/headers
{
  "headers": {
    "Accept": "*/*",
    "Host": "test.sbproxy.dev",
    "User-Agent": "curl/8.4.0",
    "X-Forwarded-For": "127.0.0.1"
  }
}
```

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: unknown.example.com' http://127.0.0.1:8080/get
404
```

A `Host` header that does not match any configured origin is rejected with a 404.

## What this exercises

- `proxy` action - forwards the request to a single upstream URL
- Host-based origin routing - the `Host` header selects which origin handles the request
- Default forwarding header behaviour - `X-Forwarded-For`, `X-Forwarded-Proto`, and `Host` rewrites are added automatically

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/architecture.md](../../docs/architecture.md) - how the request pipeline is structured
