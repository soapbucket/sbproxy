# Access log

*Last modified: 2026-05-04*

Structured-JSON access logs give every completed request a single line on
stdout, ready to ship to ELK, Loki, Datadog, or any pipeline that already
speaks JSON. The proxy emits the line via the `access_log` tracing target
so log routers can split access logs from application logs without
additional plumbing.

## Default behaviour

Off. SBproxy emits no access-log lines unless the top-level `access_log`
block is present and `enabled: true`. Metrics, traces, and the audit log
are unaffected by this knob.

## Enabling

Add the block to `sb.yml`:

```yaml
access_log:
  enabled: true

origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
```

A request to `api.example.com` now produces a line such as:

```json
{"timestamp":"2026-04-27T12:00:03.521Z","request_id":"7f7c","origin":"api.example.com","method":"GET","path":"/health","status":200,"latency_ms":24.7,"auth_ms":1.2,"upstream_ttfb_ms":18.9,"response_filter_ms":4.1,"bytes_in":0,"bytes_out":1024,"client_ip":"203.0.113.10"}
```

The three `*_ms` phase fields (`auth_ms`, `upstream_ttfb_ms`,
`response_filter_ms`) split `latency_ms` into the parts of the
pipeline that contributed to it. They are emitted whenever the
matching phase ran on the request; an origin with no auth provider
omits `auth_ms`, an early WAF block omits `upstream_ttfb_ms` and
`response_filter_ms`, a cache hit served from the proxy omits both
upstream fields. The same observations also feed the
`sbproxy_phase_duration_seconds` Prometheus histogram (see
[metrics-stability.md](./metrics-stability.md)) so the aggregate
view does not require log scraping.

Optional fields (`provider`, `model`, `tokens_in`, `tokens_out`,
`cache_result`, `trace_id`, `request_headers`, `response_headers`,
`upstream_host`) are omitted when not applicable, keeping non-AI lines
compact.

## Filters

`status_codes` and `methods` narrow the set of requests that get logged:

```yaml
access_log:
  enabled: true
  status_codes: [500, 502, 503, 504]
  methods: ["POST", "PUT", "PATCH", "DELETE"]
```

Empty or omitted lists match every value. Method comparison is
case-insensitive.

## Sampling

`sample_rate` is a probability in `[0.0, 1.0]` applied after the
status/method filters:

```yaml
access_log:
  enabled: true
  sample_rate: 0.05    # log 5% of matching requests
```

`1.0` (the default) logs every match. `0.0` is equivalent to disabling
emission entirely.

### Forced emission

Two knobs bypass `sample_rate` after the status/method filters match:

```yaml
access_log:
  enabled: true
  sample_rate: 0.05
  slow_request_threshold_ms: 1000
  always_log_errors: true
```

`slow_request_threshold_ms` logs every matching request whose end-to-end
latency is at or above the threshold. `always_log_errors: true` logs
every matching `5xx` response. Both knobs are off by default, preserving
the sampler-only behavior for existing configs.

## Header capture

Opt in by listing header names in `access_log.capture_headers.request`
and / or `access_log.capture_headers.response`. Captured values land in
the `request_headers` and `response_headers` fields of the emitted entry.

```yaml
access_log:
  enabled: true
  capture_headers:
    request: ["user-agent", "x-request-id", "x-ratelimit-*"]
    response: ["x-sbproxy-cache", "content-length"]
    max_value_bytes: 1024
    redact_pii: false
```

Three pattern shapes are accepted:

* Exact name: `"user-agent"`, `"x-cache"`.
* `"*"`: capture every header (subject to the sensitive-header denylist
  below).
* Trailing glob: `"x-ratelimit-*"` captures every header whose name
  starts with the prefix before the `*`. Only one trailing `*` is
  supported; embedded wildcards are treated as literal.

Header names are matched case-insensitively. Captured values are
truncated to `max_value_bytes` (default 1024) with a trailing `"..."`
that counts toward the cap.

A hardcoded denylist of sensitive headers (`authorization`, `cookie`,
`set-cookie`, `proxy-authorization`, `x-api-key`) is excluded from `*`
and glob matches. To capture one of these, list it by exact name; the
proxy logs a `WARN` at config load so the choice is visible.

When `redact_pii: true`, the `sbproxy-security` PII redactor runs over
captured header values. `redact_pii_rules` (empty by default) optionally
restricts the rule set; accepted names are `email`, `us_ssn`,
`credit_card`, `phone_us`, `ipv4`, `openai_key`, `anthropic_key`,
`aws_access`, `github_token`.

## Record shape

| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | string | RFC 3339 (UTC) of when the response was sent. |
| `request_id` | string | Unique per request. Reuses the propagated `X-Request-Id` when set; otherwise a fresh UUIDv4. |
| `origin` | string | Hostname routing matched. |
| `method` | string | HTTP method. |
| `path` | string | Request path, no query string. |
| `status` | int | HTTP response status code. |
| `latency_ms` | float | Wall-clock end-to-end latency in milliseconds. |
| `auth_ms` | float? | Time spent in the auth check (provider dispatch, JWT verify, forward-auth subrequest, OIDC cookie open). Absent when the origin has no auth provider. |
| `upstream_ttfb_ms` | float? | Time from request start to the first byte of the upstream response header. Absent when the request never reached an upstream (early auth/policy short-circuit, cache hit). |
| `response_filter_ms` | float? | Time spent running response transforms between first upstream byte and end of `response_filter`. Absent when no response_filter ran. |
| `query` | string? | Request query string without the leading `?`. Captured separately from `path` so per-route aggregations on `path` are not split by every distinct query. Absent when no query was supplied. |
| `protocol` | string? | HTTP version on the wire (`HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`). |
| `scheme` | string? | Scheme the client used to reach the proxy (`http` or `https`). Distinct from `upstream_host`'s scheme. |
| `host` | string? | Client-supplied `Host` header. May differ from `origin` (the matched virtual-host pattern, which can be a wildcard) and from `upstream_host` (where the proxy forwarded to). |
| `user_agent` | string? | Client `User-Agent` header. Pulled out as a primary field because nearly every analytics consumer wants it; the header allowlist still works as a redundant capture path. |
| `referer` | string? | Client `Referer` header (the canonical RFC 7231 misspelling). |
| `upstream_status` | int? | Upstream's response status code, when it differs from `status`. Populated when a retry chain, fallback, or `response_modifier` rewrote the status the client sees; absent when the proxy passed the upstream status through unchanged. |
| `response_content_type` | string? | Response `Content-Type` as sent to the client. |
| `response_content_encoding` | string? | Response `Content-Encoding` (`gzip`, `br`, `zstd`, ...) when the body was compressed; absent when uncompressed. |
| `bytes_in` | int | Inbound request body bytes (post header-decode). |
| `bytes_out` | int | Bytes written to the client. |
| `client_ip` | string | Post-trust-boundary client IP. |
| `provider` | string? | AI provider when an AI gateway route handled the request. |
| `model` | string? | Selected AI model identifier. |
| `tokens_in` | int? | Prompt tokens, when known. |
| `tokens_out` | int? | Completion tokens, when known. |
| `trace_id` | string? | W3C trace id when distributed tracing is active, for span correlation. |
| `cache_result` | string? | One of `hit`, `miss`, `stale`, `bypass` for cached responses. |
| `upstream_host` | string? | Upstream host the proxy contacted; absent on short-circuited requests (auth deny, WAF block, cache hit). |
| `request_headers` | object? | Captured request headers, lowercased keys. Absent when no allowlist or no matches. |
| `response_headers` | object? | Captured response headers, same shape as `request_headers`. |
| `attribution` | object? | Resolved business attribution tags (project, feature, okr, team, customer, environment, agent_type, risk_tier, trace_id) merged from the credential `attrs:` and `SB-Attr-*` headers. Same tag set the per-attribution spend metric is labeled by. Absent when none resolved. |
| `custom` | object? | Operator-defined custom fields from `observability.log.custom_fields:`. See below. Absent when none configured or none resolved. |

Optional fields are omitted from the JSON object when their value is
`None`.

## Custom fields

`observability.log.custom_fields:` adds operator-defined keys to each
line's `custom` object, so you can pivot logs on dimensions the built-in
schema does not carry (region, deployment, a derived tier, a routing
decision) without forking the binary. Each field's value is computed per
request from either a static string with `${...}` variable interpolation
or a script.

```yaml
proxy:
  observability:
    log:
      custom_fields:
        - name: region                       # static value + interpolation
          value: "${env.REGION}"
        - name: caller_tier                  # CEL expression
          engine: cel
          source: 'has(request.headers["x-tier"]) ? request.headers["x-tier"] : "standard"'
        - name: route_class                  # Lua script (returns the value)
          engine: lua
          source: 'return string.find(ctx.request.method, "GET") and "read" or "write"'
        - name: upper_method                 # JS script
          engine: js
          source: "ctx.request.method.toUpperCase()"
```

Rules:

- Each field sets exactly one of `value` or (`source` + `engine`).
  Both, or neither, is a config error.
- `engine` is one of `cel`, `lua`, `js`. WASM is not supported for log
  fields because it is a compiled module, not inline source.
- Static `value` interpolation variables: `${env.NAME}`, `${tenant_id}`,
  `${method}`, `${path}`, `${host}`, `${status}`, `${provider}`,
  `${model}`, `${request.header.NAME}`, `${attribution.KEY}`. An
  unresolved variable becomes the empty string.
- CEL expressions see the context keys as top-level variables
  (`request`, `response`, `tenant_id`, `provider`, `model`,
  `attribution`). Lua and JS scripts see the whole context as a `ctx`
  global and `return` (Lua) / evaluate to (JS) the value to log.
- A field whose script errors, or that resolves to the empty string, is
  omitted from the line rather than failing the request.
- Custom values pass through the same redaction as every other field.
- Resolved at proxy scope today. A tenant- and origin-scope
  `custom_fields:` is a planned extension; tenant and origin
  observability already carry their own `redact:` and `sinks:` (see the
  sink-scope and tenant/origin redaction sections in the observability
  guide), and custom fields will compose proxy then tenant then origin
  the same way.

A worked example is in `examples/custom-log-fields/`.

## Redaction

Every line is passed through the same secret redactor that protects
metric labels and audit events. Bearer tokens, API keys with
recognisable prefixes (`sk-`, `pk-`, `ghp_`, ...), and JWT-shaped
strings are replaced with `[REDACTED]` before the line reaches stdout.
Apply additional masking at your log shipper if your origin embeds
custom secrets in URLs or other places the line carries verbatim.

The PII redactor described under [Header capture](#header-capture) runs
before secret redaction, but only over captured header values. Other
fields (`path`, `request_id`, `client_ip`) are not PII-redacted.

## Routing the lines

Every line carries `target = "access_log"` in tracing metadata. Common
patterns:

* Filter via `RUST_LOG=info,access_log=info,sbproxy=warn` to keep
  operator logs quiet while keeping access logs.
* Use the JSON log subscriber (default in `sbproxy-observe`) and let
  your collector tag by `target`.
* Pipe stdout through `vector` or `fluent-bit` to split on `target`.

### File output

To write access logs directly to disk instead of the tracing target:

```yaml
access_log:
  enabled: true
  output:
    type: file
    path: /var/log/sbproxy/access.log
    max_size_mb: 100
    max_backups: 7
    compress: true
```

When the active file reaches `max_size_mb`, SBproxy rotates it before
writing the next line. Rotated files use suffixes like
`access.log.1` or `access.log.1.gz`; `max_backups` caps how many
rotated files are retained. `compress: true` gzips rotated files.

Omitting `output` keeps the default behavior: emit JSON through the
`access_log` tracing target.
