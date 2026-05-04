# Access Log

*Last modified: 2026-04-27*

Structured-JSON access logs give every completed request a single line on stdout, ready to ship to ELK, Loki, Datadog, or any pipeline that already speaks JSON. The proxy emits the line via the `access_log` tracing target so log routers can split access logs from application logs without additional plumbing.

## Default behaviour

Off. SBproxy emits no access-log lines unless the top-level `access_log` block is present and `enabled: true`. Metrics, traces, and the audit log are unaffected by this knob.

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
{"timestamp":"2026-04-27T12:00:03.521Z","request_id":"7f7c…","origin":"api.example.com","method":"GET","path":"/health","status":200,"latency_ms":3.4,"bytes_in":0,"bytes_out":0,"client_ip":"203.0.113.10"}
```

Optional AI fields (`provider`, `model`, `tokens_in`, `tokens_out`, `cache_result`, `trace_id`) are omitted when not applicable, keeping non-AI lines compact.

## Filters

`status_codes` and `methods` narrow the set of requests that get logged:

```yaml
access_log:
  enabled: true
  status_codes: [500, 502, 503, 504]
  methods: ["POST", "PUT", "PATCH", "DELETE"]
```

Empty or omitted lists match every value. Method comparison is case-insensitive.

## Sampling

`sample_rate` is a probability in `[0.0, 1.0]` applied after the status/method filters:

```yaml
access_log:
  enabled: true
  sample_rate: 0.05    # log 5% of matching requests
```

`1.0` (the default) logs every match. `0.0` is equivalent to disabling emission entirely.

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
| `bytes_in` | int | Currently `0`. Wired in F2.11. |
| `bytes_out` | int | Currently `0`. Wired in F2.11. |
| `client_ip` | string | Post-trust-boundary client IP. |
| `provider` | string? | AI provider when an AI gateway route handled the request. |
| `model` | string? | Selected AI model identifier. |
| `tokens_in` | int? | Prompt tokens, when known. |
| `tokens_out` | int? | Completion tokens, when known. |
| `trace_id` | string? | W3C trace id when distributed tracing is active, for span correlation. |
| `cache_result` | string? | One of `hit`, `miss`, `stale`, `bypass` for cached responses. |

Optional fields are omitted from the JSON object when their value is `None`.

## Redaction

Each emitted line is passed through the same secret redactor that protects metric labels and audit events. Bearer tokens, API keys with recognisable prefixes (`sk-`, `pk-`, `ghp_`, …), and JWT-shaped strings are replaced with `[REDACTED]` before the line reaches stdout. Apply additional masking at your log shipper if your origin embeds custom secrets in URLs or headers.

## Routing the lines

Every line carries `target = "access_log"` in tracing metadata. Common patterns:

* Filter via `RUST_LOG=info,access_log=info,sbproxy=warn` to keep operator logs quiet while keeping access logs.
* Use the JSON log subscriber (default in `sbproxy-observe`) and let your collector tag by `target`.
* Pipe stdout through `vector`, `fluent-bit`, or `vector` to split on `target`.

## Roadmap

`access_log` is the Prereq.A wire-up. Two follow-ups build directly on top:

* **F2.11 - filter and sample primitives**: percentile-based sampling, per-host overrides, structured tail-sampling for slow requests, and the `bytes_in` / `bytes_out` plumbing.
* **F2.12 - enterprise sinks**: pluggable destinations (S3, Kafka, Datadog, Loki) so operators can keep stdout-shipping for staging while routing prod lines straight to a managed log store.
