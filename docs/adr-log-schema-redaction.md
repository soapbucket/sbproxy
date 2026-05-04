# ADR: Structured-log schema v1 and redaction policy

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-observability.md` and `adr-event-envelope.md`. The redaction contract is regressed on every PR.

## Context

Three log streams (access, error, audit) plus the OTel trace exporter and any customer-facing telemetry sink all need a consistent schema and a deterministic redaction pipeline. Today `sbproxy-observe` writes structured fields ad hoc per call site, which means:

1. Field names drift (`req_id`, `request_id`, `requestId` all appear in the same log file in old code).
2. Redaction is per-callsite (every `info!()` has to remember which fields are sensitive). One missed call leaks a Stripe SK to Loki.
3. Per-sink overrides don't exist: the same line goes to internal Loki and to a customer's external collector with no way to apply stricter redaction on the external sink.

This ADR pins the schema, the denylist, the redaction marker, and the per-sink override mechanism. It is consumed verbatim by:

- The access log (every request, one line).
- The error log (one line per WARN/ERROR/FATAL).
- The audit log (admin actions; see `adr-admin-action-audit.md`).
- The trace exporter (span attributes go through the same redaction).
- The customer-facing telemetry pipe.

## Decision

### Encoding

JSON-line (one JSON object per line, terminated by `\n`). UTF-8 encoded. No pretty-printing in production sinks; the `stdout` sink in dev mode may pretty-print behind a config flag (`log.pretty: true`).

Field ordering inside the object is not significant, but emitters SHOULD write top-level fields in the order below for grep-ability.

### Schema v1: top-level fields

Required on every line, regardless of event type:

| Field | Type | Notes |
|---|---|---|
| `ts` | string (RFC 3339 UTC, ms precision) | `2026-04-30T14:23:45.123Z` |
| `level` | string enum | `trace` \| `debug` \| `info` \| `warn` \| `error` \| `fatal` |
| `msg` | string | Human-readable message; SHOULD be a constant per call site |
| `target` | string | Module path (`sbproxy_modules::policy::ai_crawl`) |
| `event_type` | string enum | See section on event types below |
| `schema_version` | string | `"1"` for this ADR; bumped per `adr-schema-versioning.md` |

Required when the line is associated with an in-flight request (everything except boot-time / shutdown / config-reload):

| Field | Type | Notes |
|---|---|---|
| `request_id` | string (ULID) | Same value as `RequestEvent.request_id` |
| `trace_id` | string (32 hex) | Current OTel trace ID (lowercase hex, no dashes) |
| `span_id` | string (16 hex) | Current OTel span ID |
| `tenant_id` | string | Workspace ID; `"default"` in single-tenant deployments |
| `route` | string | Origin route key (matches `RequestEvent.hostname` plus path-prefix) |

Required when the line is a per-request lifecycle event (request_started, request_completed, request_error). These mirror `RequestEvent` and SHOULD be a 1:1 serialization of that envelope (see `adr-event-envelope.md`):

| Field | Type | Notes |
|---|---|---|
| `agent_id` | string, optional | Resolved by the agent-class resolver |
| `agent_class` | string, optional | One of `vendor:purpose` from the taxonomy |
| `rail` | string, optional | `stripe` \| `x402` \| `mpp` \| `lightning` \| `none` |
| `shape` | string, optional | Content shape |
| `status_code` | u16, optional | HTTP status returned |
| `latency_ms` | u32, optional | End-of-request only |
| `error_class` | string, optional | Machine-readable; see `adr-event-envelope.md` |

Per-event extras live under a typed `extra` object, schema'd per event type (e.g. ledger redeem result, audit before/after diff). The denylist in § Redaction below applies inside `extra` recursively.

### Event types

The `event_type` enum values:

| Value | Pillar | Emitter |
|---|---|---|
| `request_started` | intake | per-request middleware |
| `request_completed` | intake | per-request middleware |
| `request_error` | intake | per-request middleware |
| `policy_evaluated` | policy | per-policy module |
| `policy_blocked` | policy | per-policy module |
| `action_challenge_issued` | action | 402 challenge handler |
| `action_redeemed` | action | redemption handler |
| `ledger_call` | ledger | `HttpLedger` client |
| `audit_emit` | audit | audit-log emitter |
| `notify_dispatch` | notify | outbound webhook framework |
| `boot` | system | tracer / metrics / cache init |
| `config_reload` | system | hot reload |
| `health_status_change` | system | `/readyz` flips |

Adding a new event type is an ADR amendment. Renaming or removing one is a breaking change per `adr-schema-versioning.md`.

### Denylist (typed enum)

Sensitive fields are matched by **field key**, not by value heuristics. The denylist lives as a typed enum so middleware can match deterministically without runtime regex on every line:

```rust
pub enum RedactedField {
    AuthorizationHeader,    // any header named "authorization" (case-insensitive)
    StripeSecretKey,        // header or body field matching sk_(test|live)_*
    LedgerHmacKey,          // SBPROXY_LEDGER_HMAC_KEY value
    KyaToken,               // KYA bearer tokens
    PromptBody,             // raw inbound prompt content
    EnvelopePayloadRaw,     // raw outbound origin response body
    Cookie,                 // any header named "cookie" or "set-cookie"
    OAuthClientSecret,
    Ja3Fingerprint,         // JA3 hash on external sinks
    Ja4Fingerprint,         // JA4 hash on external sinks
    PaymentReceiptSecret,   // facilitator-issued receipt secrets
    ApiKey,                 // generic api_key field
}
```

Field names that the redactor matches (case-insensitive substring on the bottom-leaf JSON key, expanded to all denylist members):

- `authorization`, `proxy-authorization`
- `cookie`, `set-cookie`
- `x-stripe-signature`, `stripe-signature`
- `*_secret`, `*_token`, `*_key` (suffix match, then cross-checked against the typed enum)
- `prompt`, `messages` (when the parent path is the inbound AI request body)
- `ja3`, `ja3_hash`, `ja4`, `ja4_hash` (only on external sinks; internal sinks keep them)

Each denylist member maps to a redaction marker.

### Redaction marker

The marker is a fixed string with a typed suffix:

```
<redacted:authorization>
<redacted:stripe-secret-key>
<redacted:ledger-hmac-key>
<redacted:prompt-body>
```

Marker format: `<redacted:` + kebab-cased member name + `>`. The marker is a string literal; consumers (Loki, ClickHouse, the portal) treat it as opaque. We never substitute a hash or partial value at the log layer; the temptation to log "first 4 chars" leaks structure (Stripe SKs share a prefix; the suffix is the secret part).

For nested objects, the redactor replaces the **value**, not the key:

```json
{ "headers": { "authorization": "<redacted:authorization>" } }
```

For top-level fields, same treatment:

```json
{ "stripe_sk": "<redacted:stripe-secret-key>" }
```

### Per-sink override

Sinks declare a redaction profile in `sb.yml`:

```yaml
observability:
  log:
    sinks:
      - name: stdout
        format: json
        profile: internal
      - name: loki_internal
        endpoint: "http://loki.internal:3100"
        profile: internal
      - name: loki_external
        endpoint: "https://loki.customer.example/api/v1/push"
        profile: external
        tenant_label: "${WORKSPACE_ID}"
```

Two profiles ship by default:

- `internal`: applies the denylist above. Allows `agent_id`, `tenant_id`, JA3/JA4, request paths.
- `external`: applies the denylist **plus** these additional redactions: JA3/JA4 fingerprints, raw query strings (replaced with path only), `User-Agent` header (replaced with `<redacted:user-agent>` when JA-style fingerprint redaction is required by tenant policy), full URL (replaced with `route`).

A custom profile is a list of `RedactedField` plus path globs:

```yaml
observability:
  log:
    profiles:
      gov_cloud:
        deny:
          - authorization
          - stripe-secret-key
          - prompt-body
          - ja3-fingerprint
          - ja4-fingerprint
        deny_paths:
          - "$.headers.x-internal-*"
```

Profiles are applied at sink-write time, after the line is constructed. The same in-process structured-log event is fanned out to N sinks, each redacting per its profile. Cost is one allocation per sink per line; the budget for log-emit is under 10 us per line per sink at the 95th percentile.

### Correlation between log and trace

`trace_id` and `span_id` are populated from the current OTel context (per `adr-observability.md`). A log line emitted outside a span (boot, shutdown, config reload) has both fields absent, never empty-string.

Loki is configured to extract `trace_id` as a label so the Grafana "logs to traces" link works. The dashboards JSON wires this. Trace exemplars on histograms round-trip to logs via this label.

### Sampling

Per-level sampling is supported but discouraged. The default is 100% emission for `info` and above, 10% for `debug` and `trace`. Operators can tune via:

```yaml
observability:
  log:
    sampling:
      info: 1.0
      debug: 0.1
      trace: 0.01
```

Audit events (`event_type: audit_emit`) are **never** sampled. They are always emitted.

### Per-sink redaction tests

The redaction contract is regressed by `e2e/tests/redaction.rs`. The test:

1. Injects fixture inputs containing every member of `RedactedField` (real-shape Authorization header, fake-but-valid-format Stripe SK, fake KYA token, raw prompt body, ledger HMAC, payment-receipt secret).
2. Runs one request that exercises every emitter (access, error, audit, trace).
3. Asserts the marker (`<redacted:*>`) appears in every sink, and the original value appears in **none** of them.
4. Asserts the marker variant matches the field type (Authorization header gets `<redacted:authorization>`, not a generic marker).

A failure is a CI block. There is no override; redaction is the line we don't cross.

### What this ADR does NOT decide

- The OTel span attribute redaction implementation. Lives in `adr-observability.md`; this ADR's denylist is reused by the span attribute scrubber that runs before export.
- Audit-log envelope (the `event_type: audit_emit` payload). Lives in `adr-admin-action-audit.md`; that ADR specifies the typed `before` and `after` snapshots, and reuses this ADR's redactor.
- Schema migration to v2. Lives in `adr-schema-versioning.md`. This ADR pins v1 only.
- Customer-export of redacted telemetry. The "external" profile is forward-compatible with that work.

## Consequences

- One typed schema, one denylist, one redaction marker, one regression test. New emitters get redaction for free by routing through `sbproxy-observe::log`.
- Per-sink profiles let us ship the same proxy binary to a strict-redaction tenant and a permissive one without code changes.
- The denylist is enum-based, which means CI catches "a new field that should be redacted but the redactor doesn't know about it" via an exhaustive-match clippy lint (`#[deny(non_exhaustive_omitted_patterns)]` in the redactor switch).
- Schema v1 is locked. Any breaking change requires the migration window in `adr-schema-versioning.md`. Adding new optional fields is non-breaking and does not require a version bump.
- Performance: redaction is a string-replace pass per sink, around 1us per field. 5 fields per line, 3 sinks gives around 15 us per line. Within the substrate p99 budget.

## Alternatives considered

**Value-based redaction (regex-scan every value for SK-shaped strings).** Rejected. Regex on every value of every line is expensive (over 50us per line at p99) and false-positive-prone (hex strings that aren't tokens get redacted; tokens that don't match the regex slip through). Field-key matching is deterministic and faster.

**Per-sink encoding (Protobuf to internal Loki, JSON to external).** Rejected. JSON-line is universal and operators understand it. Protobuf is a future optimization if log volume becomes a bandwidth issue. The schema is forward-compatible with a Protobuf encoding (every field has a stable name).

**Allowlist instead of denylist.** Considered seriously. The argument: an allowlist fails closed (anything not on the list is redacted), which is safer. Rejected because we want operators to add custom fields per their plugins without forcing a fork of the redactor. The compromise: the denylist is exhaustive on the typed enum (compile-time enforced by exhaustiveness check), and operators can add custom redactions via the per-sink profile's `deny_paths` glob.

## References

- Companion ADRs: `adr-observability.md`, `adr-admin-action-audit.md`, `adr-schema-versioning.md`, `adr-event-envelope.md`.
- Existing event surface: `crates/sbproxy-observe/src/events.rs`, `crates/sbproxy-observe/src/log.rs`.
- RFC 3339 timestamp format: <https://www.rfc-editor.org/rfc/rfc3339>.
