# Headers reference
*Last modified: 2026-07-21*

Every header SBproxy reads or stamps, with the config that triggers it.
This is the single source of truth; `docs/manual.md` and the marketing
pages link here rather than duplicating the table inline.

The proxy touches headers in three places: request headers it reads
from the client, response headers it emits back to the client, and
headers it stamps on outbound requests it makes itself (webhooks,
mirrors, shadow traffic, ledger calls). Each gets its own section
below.

## Request headers the proxy reads

These arrive on the inbound request. The proxy consumes them; most are
also forwarded or stripped depending on trust.

| Header | Description | Source |
|---|---|---|
| `X-Request-Id` | Correlation ID. If present (and `proxy.correlation_id.enabled`, the default), its value is adopted as the request's correlation ID; otherwise the proxy mints a UUID v4. The header name is configurable via `proxy.correlation_id.header`. | `crates/sbproxy-core/src/server/request_phase.rs` |
| `x-sb-session-id` | Caller-supplied session ULID. Captured when it parses; invalid values are dropped and counted. The admin Sessions page reconstructs only the requests still present in the in-memory ring. | `crates/sbproxy-observe/src/capture.rs` |
| `x-sb-parent-session-id` | Caller-supplied parent session ULID for chaining agent sessions. Never auto-generated. When both sessions remain in the request ring, the admin console links their hierarchy. | `crates/sbproxy-observe/src/capture.rs` |
| `x-sb-user-id` | Caller-supplied user identifier. First in the user-ID resolution order, ahead of the JWT `sub` claim and forward-auth headers. | `crates/sbproxy-observe/src/capture.rs` |
| `x-sb-property-*` | Per-request properties captured onto the request event and admin request ring. Length-capped, allowlist-checked, and redacted per `properties.redact`. Keys explicitly named in `properties.rollup_keys` are promoted into durable usage rollups only after redaction; arbitrary properties never become Prometheus labels. | `crates/sbproxy-observe/src/capture.rs` |
| `x-sb-flags` | Per-request feature flags. `x-sb-flags: debug` turns on the debug response headers listed below and a DEBUG-level log line. Kill switch: `--disable-sb-flags` / `SB_DISABLE_SB_FLAGS=1`. | `crates/sbproxy-core/src/sb_flags.rs` |
| `x-sbproxy-tag` | Caller-supplied attribution tag read by the AI dispatch path. | `crates/sbproxy-core/src/server/ai_dispatch.rs` |
| `traceparent` / `tracestate` / `b3` / `x-b3-*` | W3C Trace Context or B3 propagation. Parsed when present; a random trace context is generated otherwise. | `crates/sbproxy-core/src/server/request_phase.rs` |

### TLS fingerprint sidecar headers

The `x-sbproxy-tls-*` family carries TLS fingerprints computed by a
trusted TLS-terminating sidecar in front of the proxy. They are
request headers, read only when the immediate TCP peer is in
`proxy.trusted_proxies`, and stripped from untrusted peers so a
client cannot forge its own fingerprint. They are never emitted on
responses. Configuration lives under
`proxy.extensions.tls_fingerprint` (the older `features.tls_fingerprint`
block is migrated there by the config compiler), which also carries a
`sidecar_header_allowlist` for alternate names such as
`x-forwarded-ja4`.

| Header | Description |
|---|---|
| `x-sbproxy-tls-ja3` | JA3 client TLS fingerprint hash from the sidecar. |
| `x-sbproxy-tls-ja4` | JA4 client TLS fingerprint hash from the sidecar. |
| `x-sbproxy-tls-ja4h` | JA4H HTTP fingerprint. Sidecar-supplied, or computed by the proxy from the request when absent. |
| `x-sbproxy-tls-ja4s` | JA4S server-side TLS fingerprint hash from the sidecar. |
| `x-sbproxy-tls-trustworthy` | Sidecar's trust assertion. Overrides the proxy's own CIDR-based classification when present. |

## Response headers the proxy emits

### Present by default

| Header | Description | Source |
|---|---|---|
| `X-Request-Id` | The correlation ID (adopted or minted) echoed to the client. On by default; disable with `proxy.correlation_id.echo_response: false`. The header name follows `proxy.correlation_id.header`. | `crates/sbproxy-core/src/server/proxy_http.rs` |
| `traceparent` | W3C Trace Context, echoed on the response. Generated when no inbound trace headers were present, otherwise derived from them. `tracestate` accompanies it when one exists. | `crates/sbproxy-core/src/server/proxy_http.rs` |

### Conditional

These fire only when the relevant config or request state applies.

| Header | Trigger | Description |
|---|---|---|
| `X-Sb-Session-Id` | A session ID was captured | Echoed when the caller supplied a valid ULID, or when the proxy auto-generated one. Auto-generation follows `sessions.auto_generate`: the default `anonymous` mints an ID only for requests with no resolved user identity; `always` and `never` do what they say. No session captured means no header. |
| `x-sbproxy-cache` | `response_cache.enabled: true` on the origin | Values: `HIT`, `STALE`, `HIT-RESERVE`. There is no `MISS` value; a cache miss simply omits the header. |
| `x-sbproxy-debug-request-id` | Request carried `x-sb-flags: debug` | The request's correlation ID, stamped for quick copy-paste debugging. |
| `x-sbproxy-debug-config-rev` | Request carried `x-sb-flags: debug` | The compiled-config revision that served the request. |
| `X-Sb-Property-<key>` | `properties.echo: true` on the origin | Each captured `x-sb-property-*` request property echoed back. Off by default. |
| `x-sbproxy-idempotency` | Idempotency middleware disengaged mid-request | Skip reason (oversize body, pool exhausted). Informational only. |
| `x-sbproxy-retry-skip-reason` | Status-retry middleware skipped a retry | Skip reason for dashboards. |
| `Retry-After` | 429 or a2a chain-depth denial | On rate-limit 429s this is opt-in via the policy's `headers.include_retry_after` (the built-in ddos and ai-crawl enforcers turn it on themselves). The a2a chain-depth-exceeded denial always sends `Retry-After: 0`, unconditionally. |

## Headers on outbound requests the proxy makes

These never appear on the client-facing response. A client `curl`
will not see them.

### Webhook and callback delivery

Stamped on event-sink, audit-log-sink, and callback deliveries
(`crates/sbproxy-core/src/server/callbacks.rs`).

| Header | Description |
|---|---|
| `x-sbproxy-instance` | Stable identifier for the SBproxy instance that emitted the webhook. |
| `x-sbproxy-config-revision` | The compiled-config revision that produced the event. |
| `x-sbproxy-timestamp` | Unix ms when the webhook was dispatched. |
| `x-sbproxy-event` | The event type (e.g. `ai.request.completed`, `policy.violation`, `audit.session_close`). |
| `x-sbproxy-signature` | HMAC-SHA256 over the body, prefixed by the algorithm tag. Present when a signing secret is configured. |
| `x-sbproxy-request-id` | The originating request's correlation ID, propagated to the sink. |

### Mirror, shadow, and ledger traffic

| Header | Where it goes | Description |
|---|---|---|
| `x-sbproxy-mirror: 1` | The mirrored copy of the request sent to the mirror upstream (`mirror.enabled: true`) | Lets the mirror target distinguish mirrored traffic from live traffic. Mirror responses are discarded; the client response carries nothing. |
| `x-sbproxy-shadow: 1` | The shadow request sent by AI shadow traffic | Same idea for the AI shadow path (`crates/sbproxy-ai/src/client.rs`). |
| `x-sb-ledger-key-id` | The outbound ledger POST | Identifies the signing key for the usage-ledger submission (`crates/sbproxy-modules/src/policy/ai_crawl/http_ledger.rs`). |
| `x-sb-ledger-signature` | The outbound ledger POST | Detached signature over the ledger submission body. |

## Not headers: OpenAPI vendor-extension keys

`x-sbproxy-prefix-match`, `x-sbproxy-regex-path`, and
`x-sbproxy-auth-type` look like header names but are JSON keys in the
OpenAPI document the proxy emits for an origin with
`expose_openapi: true`. They annotate path items and security schemes
in the spec (`crates/sbproxy-openapi/src/lib.rs`). They are never on
the wire as HTTP headers.

## Middleware helpers (RFC-shaped responses)

Two helpers produce response shapes that follow published RFCs. Both
are opt-in per origin and fire on two error paths: proxy-generated
errors (auth deny, policy deny, default 404) and upstream failures
routed through Pingora's `fail_to_proxy` path (connect refused,
connect timeout, TLS handshake error, mid-stream connection loss).
See [configuration.md](configuration.md) for the per-origin config
block.

### `Proxy-Status` (RFC 9209)

Source: `crates/sbproxy-middleware/src/proxy_status.rs`. Stamped on
non-2xx responses when the origin has
`proxy_status.enabled: true`. The header carries the proxy
identity (`sbproxy` by default; configurable per origin), the
received upstream status, and a short error token sourced from the
failure mode.

```text
Proxy-Status: sbproxy; received-status=502; error="connection_refused"
Proxy-Status: sbproxy; received-status=504; error="connection_timeout"
Proxy-Status: sbproxy; received-status=502; error="tls_protocol_error"
Proxy-Status: sbproxy; received-status=502; error="connection_terminated"
```

The error token catalogue mirrors RFC 9209 section 2.3.4
(`connection_refused`, `connection_timeout`, `tls_protocol_error`,
`connection_terminated`, `http_request_error`).

### `application/problem+json` (RFC 9457)

Source: the `render_problem_details` function in
`crates/sbproxy-core/src/server.rs`. Renders the response body as
`application/problem+json` when the origin has
`problem_details.enabled: true` and no custom `error_pages` entry
matches the status. The body shape is the RFC 9457 problem details
format with `type`, `title`, `status`, `detail`, `instance` fields.

```json
{
  "type": "https://api.example.com/errors/502",
  "title": "Bad Gateway",
  "status": 502,
  "detail": "connection_refused",
  "instance": "/v1/orders"
}
```

![an unauthenticated request answered with an RFC 9457 application/problem+json body](assets/problem-details.gif)

problem_details.enabled turns proxy-generated errors into typed problem documents ([config](../examples/problem-details/)).

On upstream failures the `detail` field carries the same RFC 9209
error token that lands in the `Proxy-Status` header so downstream
tooling reading either signal sees the same vocabulary.

## Debugging a live request

Send `x-sb-flags: debug` on the request and the proxy stamps
`x-sbproxy-debug-request-id` and `x-sbproxy-debug-config-rev` on the
response, plus a DEBUG-level log line keyed by the same request ID.
For verbose process-wide logs, set `RUST_LOG=debug` on the proxy
process.

## Verifying live

Run any request through a configured proxy and inspect with curl:

```bash
curl -i -H "Host: myapp.example.com" http://127.0.0.1:8080/
# X-Request-Id: ee1f1806769b467bbaf5ca3550f17780
# traceparent: 00-dc5a693f...-dc3096404c44485a-01
# X-Sb-Session-Id: 01KQRPPS5FZ8MDQR0H01D0V52E   (when a session was captured)
```

`X-Request-Id` and `traceparent` appear on every response the proxy
emits with default config. `X-Sb-Session-Id` appears when a session
was captured for the request. Anything else you see is configured by
the active `sb.yml`.
