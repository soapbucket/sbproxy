# ADR: Custom properties (Wave 8 / T1.1)

*Last modified: 2026-04-28*

## Status

Accepted. Builds on `adr-event-envelope.md` (T5.1).

## Context

The portal's segmentation, sessions-by-property, and dataset-curation features all need a way for the SDK caller to tag a request with arbitrary metadata. Helicone's convention is `Helicone-Property-*` headers; the contract we want is the same shape with our prefix.

## Decision

### Header convention

Clients tag a request with one or more `X-Sb-Property-<key>: <value>` headers. The proxy strips the prefix, lowercases the key, and stores the (key, value) pairs in `RequestEvent.properties`.

- Prefix: `X-Sb-Property-` (case-insensitive on the wire; lowercased on capture).
- Key: the suffix after the prefix. Lowercased, trimmed of surrounding whitespace.
- Value: the header value, trimmed of surrounding whitespace.

Examples:

```
X-Sb-Property-Environment: prod
X-Sb-Property-Feature-Flag: agent-v2
X-Sb-Property-Customer-Tier: enterprise
```

Captured as `properties = {"environment": "prod", "feature-flag": "agent-v2", "customer-tier": "enterprise"}`.

### Caps

Per request:

| Cap | Value | Rationale |
|---|---|---|
| Max property count | 20 | Holds Helicone parity on common SDK usage; ClickHouse materialized columns scale linearly |
| Max key length | 64 chars | Long keys break ClickHouse column names if materialized |
| Max value length | 512 chars | Caps log/event growth; long blobs belong in body capture (T1 P1 P2) |
| Total payload | 8 KiB | Backstop against header bombs |

Over-cap behavior: drop the offending headers, increment `sbproxy_property_dropped_total{reason}` with `reason ∈ {count, key_len, value_len, payload_size, regex}`, and continue. We do not 4xx the request.

### Key allowlist regex

Keys must match `^[a-z0-9][a-z0-9_-]{0,63}$` after normalization. This rejects spaces, dots, slashes, and the colon needed to embed structured keys, leaving the safe subset for ClickHouse column names.

### Redaction hook

Two hooks, both opt-in via `sb.yml`:

```yaml
properties:
  capture: true
  redact:
    keys: ["customer-email", "ssn"]    # exact key match; value replaced with "[redacted]"
    value_regex:                        # any value matching this regex is redacted entirely
      - "\\b[\\w._%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}\\b"  # email
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"                  # US SSN
```

Redaction runs after capture and before any subscriber sees the event. We do not log the original value anywhere.

### Scripting exposure

The captured map is exposed read-only to the four scripting runtimes:

- CEL: `req.properties` (`map<string, string>`).
- Lua: `req.properties` table.
- JS: `req.properties` object.
- WASM: function import `sbproxy_get_property(key) -> Option<String>`.

Scripts can read but not mutate. Mutation requires a separate ADR (we do not want scripted property injection in the audit path).

### Optional response echo (T1.3)

When `properties.echo: true`, the proxy echoes captured properties back as `X-Sb-Property-<key>: <value>` response headers so SDKs can correlate replies. Off by default; opt-in per origin.

### Cardinality safety

`properties` is **not** a Prometheus metric label. Including it would unbound the metrics cardinality. Properties live in `RequestEvent`, ClickHouse, and structured logs only. We expose `sbproxy_property_count_distinct` (a single-key cardinality estimate via HyperLogLog) for ops visibility, but never `sbproxy_requests_total{property_*}`.

## Consequences

- Lightweight capture path: header iteration, length check, regex check, BTreeMap insert. Roughly 5 us per property at p50.
- ClickHouse stores `properties` as a `Map(String, String)` column. T1.4 declares well-known materialized keys (e.g. `environment`) for index-friendly filtering; the rest stay in the map.
- Scripting users can build per-request routing decisions on properties (e.g. route `customer-tier=enterprise` to a different model). This is one of the "configuration not traits" extension stories.
- Echo mode is opt-in to avoid leaking property metadata to misconfigured clients.

## References

- `docs/PORTAL.md` sec 6.1.
- `docs/adr-event-envelope.md` (the canonical envelope this ADR populates).
- Helicone reference: docs.helicone.ai (custom properties section, retrieved 2026-04).
