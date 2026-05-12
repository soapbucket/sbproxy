# Response headers reference
*Last modified: 2026-05-04*

Every response header SBproxy can stamp on a client-facing response,
with the config that triggers it. This is the single source of truth;
`docs/manual.md` and the marketing pages link here rather than
duplicating the table inline.

## Always present

These headers fire on every response from the data plane, regardless
of config. Use them to anchor SIEM rules and incident-response
runbooks.

| Header | Description | Source |
|---|---|---|
| `x-sb-session-id` | ULID identifying the client session. Stable across requests on the same connection. | `crates/sbproxy-observe/src/capture.rs` |
| `x-sb-request-id` | Per-request UUID. Use to correlate proxy logs with upstream logs. | `crates/sbproxy-config/src/types.rs` (default) |
| `traceparent` | W3C Trace Context. Generated when no inbound `traceparent` is present, otherwise propagated. | `crates/sbproxy-core/src/server.rs` |

The `x-sb-request-id` header name is configurable via
`proxy.request_id_header`; the default is `x-sb-request-id`.

## Conditional

These headers only fire when the relevant config is enabled. They are
NOT promises of the v1.x stability surface unless the corresponding
config knob is documented as stable.

| Header | Trigger | Description |
|---|---|---|
| `x-sbproxy-cache` | `response_cache.enabled: true` on the origin | Values: `HIT`, `MISS`, `STALE`, `HIT-RESERVE`. Indicates the response cache outcome. |
| `x-sbproxy-mirror` | `mirror.enabled: true` on the origin | `1` if the request was mirrored to a shadow upstream. Mirror responses are silently discarded; this header lets test traffic confirm mirroring. |
| `x-sbproxy-tls-ja3` | `tls.fingerprint: ja3` | JA3 client TLS fingerprint hash. |
| `x-sbproxy-tls-ja4` | `tls.fingerprint: ja4` | JA4 client TLS fingerprint hash. |
| `x-sbproxy-tls-ja4h` | `tls.fingerprint: ja4h` | JA4H HTTP/TLS fingerprint hash. |
| `x-sbproxy-tls-ja4s` | `tls.fingerprint: ja4s` | JA4S server-side TLS fingerprint hash. |
| `x-sbproxy-tls-trustworthy` | `tls.fingerprint: *` and the client's fingerprint is on the trust list | `true` if the JA4 family matches a known-good entry; absent otherwise. |
| `x-sb-parent-session-id` | A2A request envelope present | Set on agent-to-agent traffic to chain sessions across hops. |
| `x-sb-user-id` | Auth provider populated `request.user_id` | The authenticated user identifier; safe to log. |
| `x-sb-ledger-key-id` | `policies: [ai_crawl_control]` issued a quote token | Identifies the signing key for the issued quote token. |
| `x-sb-ledger-signature` | `policies: [ai_crawl_control]` issued a quote token | The detached signature over the quote token. |
| `Retry-After` | 429 from rate-limit, ddos, or a2a chain-depth-exceeded | Seconds until retry, or `0` for a2a depth denial. |

## Webhook / callback delivery only

These headers fire on outbound webhook deliveries (event sinks,
audit-log sinks, callback hooks), NOT on inbound client responses. A
client `curl` will not see them.

| Header | Description |
|---|---|
| `x-sbproxy-instance` | Stable identifier for the SBproxy instance that emitted the webhook. |
| `x-sbproxy-config-revision` | The compiled-config revision that produced the event. |
| `x-sbproxy-timestamp` | Unix ms when the webhook was dispatched. |
| `x-sbproxy-event` | The event type (e.g. `ai.request.completed`, `policy.violation`, `audit.session_close`). |
| `x-sbproxy-signature` | HMAC-SHA256 over the body, prefixed by the algorithm tag. |
| `x-sbproxy-request-id` | The originating request's `x-sb-request-id`, propagated to the sink. |

## Internal-only (not on the wire)

These header names appear in the source but are stripped before the
response leaves the proxy, or are used inside the request pipeline
for inter-stage signalling.

| Header | Use |
|---|---|
| `x-sb-property-*` | Per-request session properties stored on the context; never emitted. |
| `x-sbproxy-auth-type` | Inserted by the auth phase for downstream policies; stripped before egress. |
| `x-sbproxy-prefix-match` / `x-sbproxy-regex-path` / `x-sbproxy-shadow` / `x-sbproxy-tag` | Internal routing breadcrumbs; stripped before egress. |

## Middleware helpers (RFC-shaped responses)

Two helpers in `crates/sbproxy-middleware` produce response shapes
that follow published RFCs. Both are opt-in per origin and fire on
two error paths: proxy-generated errors (auth deny, policy deny,
default 404) and upstream failures routed through Pingora's
`fail_to_proxy` path (connect refused, connect timeout, TLS
handshake error, mid-stream connection loss). See
[configuration.md](configuration.md) for the per-origin config block.

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

Source: `crates/sbproxy-middleware/src/problem_details.rs`. Renders
the response body as `application/problem+json` when the origin has
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

On upstream failures the `detail` field carries the same RFC 9209
error token that lands in the `Proxy-Status` header so downstream
tooling reading either signal sees the same vocabulary.

## What you will NOT see

The following names sometimes appear in older docs or marketing
copy. They are not implemented and not on the v1.0 surface:

- `x-sb-flags`: per-request feature-flag system documented in
  `docs/manual.md` §10. Tracked in [WOR-114](https://linear.app/12345r/issue/WOR-114).
- `x-sbproxy-debug`: there is no debug header. Set `RUST_LOG=debug`
  on the proxy process for verbose logs.
- Any header beginning with `x-sb-debug-*`: same.

## Verifying live

Run any request through a configured proxy and inspect with curl:

```bash
curl -i -H "Host: myapp.example.com" http://127.0.0.1:8080/
# x-sb-session-id: 01KQRPPS5FZ8MDQR0H01D0V52E
# x-sb-request-id: ee1f1806769b467bbaf5ca3550f17780
# traceparent: 00-dc5a693f...-dc3096404c44485a-01
```

The three "always present" headers above will appear on every response
the proxy emits. Anything else you see is configured by the active
`sb.yml`.
