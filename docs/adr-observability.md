# ADR: Observability baseline

*Last modified: 2026-05-03*

## Status

Accepted. Every later feature inherits OTel tracing, W3C TraceContext propagation, and the Prometheus exemplar wiring defined here. Tail-based sampling and exporter tuning revisit once trace volume baselines exist.

## Context

The AI Governance Gateway crosses six trust boundaries on a single inbound 402 request: caller, intake, policy, action (paywall / redeem), payment rail (Stripe, MPP, x402 facilitator), ledger, and outbound origin. Without a single trace stitching those together, every incident becomes a manual log-grep across pillars, and every cross-pillar e2e test has to reconstruct causality from timestamps.

The `sbproxy-observe` crate already ships metrics (`sbproxy_*` Prometheus families) and an event bus. What's missing is:

1. A canonical tracer that propagates `traceparent` and `tracestate` on every outbound HTTP call (Stripe, ledger, facilitators, Web Bot Auth directory, KYA token endpoints, registry feeds).
2. A span-naming convention so dashboards can group by pillar.
3. Exemplars on the histograms that matter (request latency, ledger redeem latency) so the Grafana "click an outlier" story works.
4. An OTLP exporter wired by config and disabled by default.

This ADR pins the substrate.

## Decision

### Tracer

OpenTelemetry Rust SDK, pinned to the `0.27.x` family (re-pin per release). Use the `opentelemetry_sdk` tracer with the `opentelemetry-otlp` exporter.

The tracer is initialized once at boot in `sbproxy-observe::tracing::init`. Configuration lives in `observability.tracing` in `sb.yml`:

```yaml
observability:
  tracing:
    enabled: false                 # default off; opt-in per deployment
    exporter: otlp                 # otlp | stdout | none
    endpoint: "http://localhost:4317"
    protocol: grpc                 # grpc (default) | http/protobuf
    service_name: "sbproxy"        # used as resource attribute
    sampling:
      parent_based: true           # honor inbound traceparent sampled bit
      head_rate: 0.1               # 10% of unsampled roots
      always_sample_errors: true   # 100% on 5xx and policy block paths
    resource_attrs:
      deployment.environment: "prod"
      service.version: "${SBPROXY_VERSION}"
```

OTLP gRPC (port 4317) is the default exporter. HTTP/protobuf (port 4318) is supported for environments that block gRPC. `stdout` exporter is for local debugging only.

### W3C TraceContext propagation

The W3C TraceContext propagator (`opentelemetry_sdk::propagation::TraceContextPropagator`) is registered as the global propagator. Every inbound and outbound HTTP path uses it.

**Inbound**: middleware extracts `traceparent` and `tracestate` from request headers. If absent, a fresh root span is started. If present and the `sampled` bit is set, the span inherits sampling.

**Outbound**: every HTTP client owned by sbproxy injects `traceparent` and `tracestate` before send. This is non-negotiable for the following clients (each has a unit test asserting the header injection):

| Client | Crate | Used for |
|---|---|---|
| `HttpLedger` | `sbproxy-modules/policy/ai_crawl.rs` | Ledger redeem |
| Web Bot Auth directory fetcher | `sbproxy-modules/auth/bot_auth.rs` | Directory refresh |
| KYA token verifier | `sbproxy-modules/auth/kya.rs` | Identity proof |
| Outbound webhook delivery | `sbproxy-observe/notify.rs` | Customer notifications |
| OAuth / token endpoints | `sbproxy-modules/auth/oauth.rs` | Token exchange |

The propagation invariant: any HTTP request leaving the proxy MUST carry `traceparent`. Propagation tests live in `sbproxy-observe/tests/propagation.rs` and gate CI.

### Span naming convention

Span names follow `sbproxy.<pillar>.<verb>` where:

- `pillar` is one of: `intake`, `policy`, `action`, `transform`, `ledger`, `rail`, `audit`, `notify`.
- `verb` is the action being performed: `challenge`, `redeem`, `verify`, `enforce`, `route`, `emit`, `deliver`, `refresh`, `dispatch`, `settle`.

Concrete examples:

| Span | Where |
|---|---|
| `sbproxy.intake.accept` | Top-level request span (root for inbound) |
| `sbproxy.policy.enforce` | Per-policy execution (rate limit, WAF, AI crawl) |
| `sbproxy.action.challenge` | Issue 402 challenge |
| `sbproxy.action.redeem` | Verify presented token / receipt |
| `sbproxy.ledger.redeem` | Outbound HTTP call to ledger |
| `sbproxy.rail.settle` | Outbound payment-rail settlement |
| `sbproxy.transform.shape` | Content transform (PDF, OCR, summarize) |
| `sbproxy.audit.emit` | Append audit-log entry |
| `sbproxy.notify.deliver` | Outbound webhook delivery |

Span attributes follow OTel semantic conventions where applicable (`http.request.method`, `http.response.status_code`, `server.address`, `client.address`), plus the sbproxy-specific set:

| Attribute | Type | Pillars |
|---|---|---|
| `sbproxy.request_id` | string (ULID) | all |
| `sbproxy.tenant_id` | string | all (enterprise) |
| `sbproxy.route` | string | intake, policy, action |
| `sbproxy.agent_id` | string | policy, action, audit |
| `sbproxy.agent_class` | string | policy, action |
| `sbproxy.rail` | string | rail, action |
| `sbproxy.shape` | string | transform |
| `sbproxy.ledger.idempotency_key` | string | ledger |

Per the cardinality budget (see `adr-slo-alert-taxonomy.md`), high-cardinality attributes (`request_id`, `agent_id`) are span attributes only, never Prometheus labels.

### Sampling policy

The default is **head-based sampling** with the following rules, evaluated at the root span:

1. If the inbound `traceparent` has the `sampled` bit set, sample (parent-based).
2. Else if the request errors (5xx response, policy block, ledger denial), sample 100%.
3. Else sample at `head_rate` (default 0.1, configurable).

Tail-based sampling (decision deferred to span end based on outcome, latency, or error class) is deferred. The OTel SDK supports it via the `tail_sampling` processor in the OTel Collector; we ship a Collector recipe in `examples/00-observability-stack/` that operators can opt into. The sbproxy binary itself does not run a tail sampler; that complexity belongs in the Collector.

When tail sampling lands, head_rate is reduced (likely to 0.01) and the Collector keeps 100% of "interesting" tails (errors, slow, audit-relevant). The decision lives in a follow-up ADR (`adr-tail-sampling.md`).

### Exemplars on Prometheus histograms

Exemplars are wired on every histogram where "click the outlier in Grafana, get the trace" is a high-value debugging path. The exemplar set:

| Histogram | Why |
|---|---|
| `sbproxy_request_duration_seconds_bucket` | Top-level latency outliers |
| `sbproxy_ledger_redeem_duration_seconds_bucket` | Ledger tail latency, the most common real incident |
| `sbproxy_policy_evaluation_duration_seconds_bucket` | Policy regression hunting |
| `sbproxy_outbound_request_duration_seconds_bucket` | Per-outbound (rail, registry, directory) tail latency |
| `sbproxy_audit_emit_duration_seconds_bucket` | Audit-log write tail (paged at SLO breach) |

Exemplars carry the `trace_id` (and `span_id` when supported by the scraper) of one sample request per bucket per scrape interval. The Prometheus client library used (`prometheus`, with the `exemplars` feature) writes them in the OpenMetrics text format. The `examples/00-observability-stack/` Prometheus is configured with `--enable-feature=exemplar-storage`.

Future histograms SHOULD carry exemplars unless the histogram is purely an SLO numerator (e.g. `sbproxy_audit_batch_write_success_total` is a counter, not a histogram, so no exemplars).

### Coordination with existing `sbproxy-observe`

The `sbproxy-observe` crate today owns metrics, events, and structured logging. This ADR adds a `tracing` submodule:

```
crates/sbproxy-observe/src/
  metrics.rs    # existing
  events.rs     # existing (RequestEvent in adr-event-envelope.md)
  log.rs        # existing scaffolding; extended per adr-log-schema-redaction.md
  tracing.rs    # NEW: tracer init, propagation, span helpers
  health.rs     # NEW: /healthz and /readyz
```

The structured-log schema (`adr-log-schema-redaction.md`) carries `trace_id` and `span_id` on every line, so logs and traces correlate without join-by-timestamp.

### What this ADR does NOT decide

- Per-metric cardinality budgets and SLO thresholds. Lives in `adr-slo-alert-taxonomy.md`.
- Field-level redaction in span attributes and log lines. Lives in `adr-log-schema-redaction.md`. Redaction applies to span attributes the same way it applies to log fields.
- Tail-based sampling rules and storage policy. Deferred.
- Per-tenant trace export (different OTLP endpoint per tenant). Tracked in `docs/historical/multi-tenant-trace-export.md`.

## Consequences

- Every later feature inherits a working trace from inbound 402 to outbound rail settlement. The `smoke_substrate` e2e can assert a span chain of length >= 5.
- Outbound HTTP clients gain a non-negotiable "must inject traceparent" invariant. Adding a new outbound integration without propagation breaks CI.
- Exemplar wiring lets us publish Grafana dashboards that double as trace launchers. The dashboards JSON files reference the `trace_id` exemplar by Tempo's standard linking syntax.
- OTLP-only as the default exporter means Jaeger users wire the OTel Collector in front. The reference Compose stack ships that wiring out of the box.
- We pay an SDK-version pin tax: every minor bump of `opentelemetry_sdk` triggers a workspace-wide bump and a propagation regression run. Worth it; the alternative (in-tree fork) is worse.

## Alternatives considered

**Tracing crate (`tracing` + `tracing-opentelemetry`) only, no direct OTel SDK use.** Rejected because the `tracing` ecosystem is a logging facade first; some OTel features (exemplar emission, propagator registration, resource attributes) round-trip awkwardly through it. We use `tracing` for log-line emission (`adr-log-schema-redaction.md`) and `opentelemetry_sdk` directly for span management. The two integrate via `tracing-opentelemetry::OpenTelemetryLayer` so devs can write `tracing::info_span!()` and the span emits to OTel; the dual stack is intentional.

**B3 / B3-multi propagators alongside W3C.** Rejected. W3C TraceContext is the OTel-default and what every modern collector understands. Operators running B3-only environments (older Zipkin) can register an additional propagator at boot via a config option (`tracing.extra_propagators: [b3]`); we don't ship it on by default.

**Tail sampling at the proxy.** Rejected. Tail sampling needs a buffer of in-flight spans plus an end-of-span decision engine; building that into a hot-path proxy adds memory pressure and a new failure mode (buffer overflow drops traces). The OTel Collector handles it correctly out of the box. We defer until trace volume at scale tells us the actual sample budget.

## References

- Companion ADRs: `adr-log-schema-redaction.md`, `adr-slo-alert-taxonomy.md`.
- `crates/sbproxy-observe/` (current metrics + events + log surfaces).
- W3C TraceContext: <https://www.w3.org/TR/trace-context/>.
- OpenTelemetry semantic conventions: <https://opentelemetry.io/docs/specs/semconv/>.
- OpenMetrics exemplars: <https://github.com/OpenObservability/OpenMetrics/blob/main/specification/OpenMetrics.md#exemplars>.
