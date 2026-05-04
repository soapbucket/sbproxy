# Correlation ID

*Last modified: 2026-04-27*

The proxy mints a per-request correlation ID early in the request lifecycle. With the default policy, an inbound `X-Request-Id` is adopted as-is so upstream callers can tie their traces to ours; otherwise the proxy generates a fresh 32-hex UUID v4. The chosen value is forwarded to the upstream under the same header name and echoed back on the response (`echo_response: true`). The same value flows through `ctx.request_id` so webhooks (`X-Sbproxy-Request-Id`), the `Forwarded` header, access logs, and AI gateway records share one identifier.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# No inbound header: proxy generates a fresh UUID and echoes it.
curl -sI -H 'Host: localhost' http://127.0.0.1:8080/headers | grep -i x-request-id
# x-request-id: 4a1f6c8d2b3e7f0a9d8c7b6a5e4d3c2b

# Upstream sees the same value (httpbin echoes the request headers).
curl -s -H 'Host: localhost' http://127.0.0.1:8080/headers | jq '.headers["X-Request-Id"]'
# "4a1f6c8d2b3e7f0a9d8c7b6a5e4d3c2b"

# Inbound header present: proxy adopts it verbatim.
curl -sI -H 'Host: localhost' \
     -H 'X-Request-Id: my-trace-abc123' \
     http://127.0.0.1:8080/headers | grep -i x-request-id
# x-request-id: my-trace-abc123

# Confirm the upstream view.
curl -s -H 'Host: localhost' \
     -H 'X-Request-Id: my-trace-abc123' \
     http://127.0.0.1:8080/headers | jq '.headers["X-Request-Id"]'
# "my-trace-abc123"

# Disable response echoing (set echo_response: false) and the same call
# still propagates the value upstream but the response header drops.
```

## What this exercises

- `proxy.correlation_id.enabled`
- `proxy.correlation_id.header` (default `X-Request-Id`, rename to `X-Correlation-Id`)
- `proxy.correlation_id.echo_response`
- Inbound adoption versus generation
- Single shared `ctx.request_id` across access logs, webhooks, and `Forwarded`

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
