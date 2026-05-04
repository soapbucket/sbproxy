# ADR: Event envelope (Wave 8 / T5.1)

*Last modified: 2026-04-28*

## Status

Accepted. Foundational to Wave 8 P0 streams (T1 custom properties, T2 sessions, T3 users, T4 ingest pipeline).

## Context

Helicone parity work (`docs/PORTAL.md`) requires four observability dimensions to land in lockstep: per-request properties, session linking, user attribution, and a durable ingest pipeline. Each stream touches the same in-flight event payload. Without a single agreed-upon shape, the four streams will accrete fields independently, with subtly different types and naming, and the enterprise ingest pipeline will inherit the mess.

Today `crates/sbproxy-observe/src/events.rs` ships a thin `ProxyEvent { event_type, hostname, timestamp, data: serde_json::Value }`. The free-form `data` field is what every existing event mode targets. That has been fine for in-process subscribers but is the wrong shape for ClickHouse ingestion: every consumer ends up rediscovering the same field names from the JSON blob, and the enterprise wire format cannot evolve cleanly.

## Decision

Define one canonical event envelope, called `RequestEvent`, that all four Wave 8 streams populate and the enterprise ingest pipeline consumes verbatim. The existing `ProxyEvent`/`EventBus` stays for non-request events (config reloads, alerts, audit). Request lifecycle events graduate to the typed envelope.

### Field set

Top-level envelope fields, all required unless noted:

| Field | Type | Notes |
|---|---|---|
| `request_id` | ULID (string, 26 chars) | Generated at request entry; appears as `X-Request-Id` and `X-Sb-Request-Id` (echo) |
| `parent_request_id` | ULID, optional | Set when this request is a retry, replay, or sub-call inside an agent pattern |
| `workspace_id` | string, opaque | Tenant key; required in enterprise builds, defaulted to `"default"` in OSS |
| `hostname` | string | Origin hostname (matches today's `ProxyEvent.hostname`) |
| `timestamp_ms` | u64 | Unix epoch milliseconds at request start |
| `latency_ms` | u32, optional | Filled on `request_completed`/`request_error`; absent on `request_started` |
| `event_type` | enum | See `EventType` in `events.rs`; constrained subset documented per stream |
| `session_id` | ULID, optional | Set per T2 ADR; auto-generated when configured for anonymous sessions |
| `parent_session_id` | ULID, optional | Set per T2 ADR for child sessions in agent flows |
| `user_id` | string, optional | Set per T3 ADR; subject to cardinality cap |
| `properties` | `BTreeMap<String, String>` | Set per T1 ADR; capped per request and per value length |
| `provider` | string, optional | AI provider chosen (openai, anthropic, ...); empty for non-AI requests |
| `model` | string, optional | Model name; empty for non-AI requests |
| `tokens_in` | u32, optional | Prompt tokens (AI requests only) |
| `tokens_out` | u32, optional | Completion tokens (AI requests only) |
| `tokens_cached` | u32, optional | Provider cache hit tokens (Anthropic prompt cache et al) |
| `cost_usd_micros` | u64, optional | Estimated cost in micro-USD (1e-6 USD); avoids float for ClickHouse |
| `status_code` | u16, optional | HTTP status returned to the client |
| `error_class` | string, optional | When `event_type == request_error`, machine-readable class (`upstream_5xx`, `policy_blocked`, `auth_denied`, ...) |
| `request_geo` | string, optional | ISO-3166-1 alpha-2 country (filled by 3.1 P2 geo enrichment when configured) |

Notable choices:

- **ULIDs over UUIDs.** ULIDs are lexicographic by time, which matches ClickHouse partition pruning and gives session/parent ordering for free.
- **`cost_usd_micros: u64` over float.** ClickHouse `Float64` aggregations carry rounding error at scale; integer micros are exact.
- **`properties: BTreeMap<String, String>`.** Strings only at the wire level. T1 ADR keeps caps tight (<=20 keys/req, <=64 chars per key, <=512 chars per value, allowlist regex). Anything richer (numbers, arrays, nested) belongs in a future ADR; we can promote then.
- **`event_type` enum stays the discriminator.** No new variants for Wave 8; `RequestStarted`/`RequestCompleted`/`RequestError` already cover the lifecycle. T1/T2/T3 are envelope dimensions, not new event types.

### Crate placement

The envelope type lives in `sbproxy-observe::request_event::RequestEvent`. `sbproxy-observe` already owns the event surface, and it has no enterprise dependency, so the type flows freely across the OSS/enterprise boundary. Enterprise's ingest producer (T4.6 transport adapter, T4.2 producer crate) consumes `RequestEvent` directly.

The pre-existing `ProxyEvent`/`EventBus` stay for config/audit/alert events that don't share the request shape. New work targeting the request lifecycle uses `RequestEvent`.

### Wire format

In-process subscribers consume `RequestEvent` directly (no encode/decode). External transport adapters that serialize to protobuf or JSON at the broker boundary live outside this ADR.

### What this ADR does NOT decide

- T1.1 properties allowlist regex, exact caps, redaction hooks. Lives in `adr-custom-properties.md`.
- T2.1 session ID auto-generation rules, TTL, parent linking semantics. Lives in `adr-session-id.md`.
- T3.1 resolution precedence and PII handling. Lives in `adr-user-id.md`.
- T4.1 broker choice rationale, partitioning, retention tiers, replay. Lives in `adr-event-ingest-pipeline.md` (enterprise repo).

Each stream ADR may extend the envelope only for fields documented in this table. Adding a new top-level field is an envelope ADR amendment; adding a value into `properties` is not.

## Consequences

- One serializable Rust struct that the four streams target. Schema drift is enforceable via `serde_json::to_value(&event).keys()` parity tests.
- ClickHouse table generated from the same struct via a small build-script step (T1.4 / T4.3). One source of truth for both the wire and the table.
- The free-form `ProxyEvent.data` field stays for non-request events. New request fields go through this ADR.
- Breaking changes to the envelope require an ADR amendment + a protobuf field number reservation. We do not get to silently rename or retype fields.

## References

- `docs/PORTAL.md` sec 6.5 (cross-cutting tasks) and sec 6.6 (suggested order).
- `crates/sbproxy-observe/src/events.rs` (current `ProxyEvent` shape).
- Companion ADRs: `adr-custom-properties.md`, `adr-session-id.md`, `adr-user-id.md`. Enterprise: `adr-event-ingest-pipeline.md`.
