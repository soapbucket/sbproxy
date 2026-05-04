# Observability
*Last modified: 2026-04-30*

SBproxy ships metrics, logs, and traces from one process. This guide covers the Wave 1 substrate: the SLO catalog, the metric label budget, the log schema and redaction policy, the trace propagation contract, the health endpoints, the dashboards, and the reference Compose stack you can boot in one command.

## Three pillars

| Pillar | Surface | Default state | Where it goes |
|---|---|---|---|
| Metrics | `/metrics` (Prometheus / OpenMetrics) | Always on | Prometheus, scraped on a 15 s cadence |
| Logs | `stdout` and configurable sinks | Always on, JSON-line | Loki, S3, customer collectors |
| Traces | OTLP exporter | Off by default; opt in per deployment | Tempo, Jaeger via the OTel Collector |

All three speak the same correlation triple: every log line and every span attribute carries `request_id` (ULID), `trace_id` (32-hex), and `span_id` (16-hex). One inbound 402 with one trace stitches metrics, logs, and traces together without join-by-timestamp.

## Configuration

```yaml
observability:
  tracing:
    enabled: false
    exporter: otlp                  # otlp | stdout | none
    endpoint: "http://localhost:4317"
    protocol: grpc                  # grpc (default) | http/protobuf
    service_name: "sbproxy"
    sampling:
      parent_based: true
      head_rate: 0.1                # 10% of unsampled roots
      always_sample_errors: true    # 100% on 5xx and policy block paths
    resource_attrs:
      deployment.environment: "prod"
      service.version: "${SBPROXY_VERSION}"
  log:
    level: info
    pretty: false
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

## Metrics

### Naming and labels

Every metric name starts with `sbproxy_`. The label set is closed: a label that is not on the budget table below is a CI failure. The closed set protects the scrape from cardinality blow-ups when an attacker rolls a fresh UA per request.

The Wave 1 substrate adds five labels: `agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, `content_shape`. `agent_id`, `agent_class`, and `agent_vendor` are bounded to the agent-class registry plus three reserved sentinels (`human`, `unknown`, `anonymous`); `payment_rail` and `content_shape` are closed enums.

### SLO catalog

| ID | Pillar | SLI | Target | Window | Tier on breach |
|---|---|---|---|---|---|
| SLO-AVAIL-INBOUND | Substrate | inbound request availability (non-5xx / total) | 99.9% | 30d | Page |
| SLO-LATENCY-P95 | Substrate | inbound p95 latency excl. rail wait | < 30 ms | 5 min sustained | Ticket |
| SLO-LATENCY-P99 | Substrate | inbound p99 latency excl. rail wait | < 50 ms | 5 min sustained | Page |
| SLO-LEDGER-REDEEM | Ledger | redeem success rate | 99.95% | 30d | Page |
| SLO-LEDGER-LATENCY | Ledger | redeem p99 latency | < 200 ms | 5 min sustained | Ticket |
| SLO-RAIL-SETTLE | Rails (per rail) | settle success rate | 99.5% | 7d | Page |
| SLO-RAIL-QUORUM | Rails | facilitator quorum (>= 1 healthy per chain) | 100% | instant | Page (immediate) |
| SLO-AUDIT-WRITE | Audit | batch-write success | 100% | 24h | Page (immediate) |
| SLO-AUDIT-LATENCY | Audit | emit-to-durable latency p99 | < 5 s | 1h sustained | Ticket |
| SLO-DR-RESTORE | DR | restore drill | succeed monthly | calendar | Page on missed |
| SLO-WEBHOOK-IN | Webhooks (in) | inbound verification success | 99.9% | 7d | Ticket |
| SLO-WEBHOOK-OUT | Webhooks (out) | outbound delivery success (incl. retries) | 99% | 7d | Ticket |
| SLO-CONFIG-RELOAD | Config | hot-reload success | 100% | 24h | Page |
| SLO-BOT-AUTH-DIR | Bot Auth | directory freshness (TTL not exceeded) | 99.9% | 7d | Ticket |
| SLO-CARD-BUDGET | Substrate | per-metric series count under cap | 100% | continuous | Log-only (CI gate) |

PromQL recording rules pre-compute each SLI at 1m, 5m, 1h, 6h, and 24h windows. Burn-rate alerts use the multi-window pattern from the SRE workbook (5m AND 1h at 14.4x for page tier, 30m AND 6h at 6x, 2h AND 24h at 3x for ticket). The full rule set lives in `deploy/alerts/`.

See [adr-slo-alert-taxonomy.md](adr-slo-alert-taxonomy.md) for the full table and the alert ID convention.

### Cardinality budget

| Metric family | Cardinality cap | Notes |
|---|---|---|
| `sbproxy_requests_total` | 50 000 | Labels: `route`, `status_class`, `agent_class`, `rail`, `tenant_id`. `agent_id` is NOT a label here. |
| `sbproxy_request_duration_seconds_bucket` | 100 000 | Same labels plus 10 buckets. |
| `sbproxy_policy_triggers_total` | 20 000 | Labels: `policy`, `decision`, `route`, `tenant_id`. |
| `sbproxy_ledger_redeem_total` | 5 000 | Labels: `result`, `tenant_id`. |
| `sbproxy_ledger_redeem_duration_seconds_bucket` | 10 000 | Plus buckets. |
| `sbproxy_outbound_request_total` | 30 000 | Labels: `target`, `result`, `tenant_id`. `target` is enum-bounded. |
| `sbproxy_audit_emit_total` | 5 000 | Labels: `result`, `tenant_id`. |
| `sbproxy_webhook_in_total` | 10 000 | Labels: `provider`, `result`, `tenant_id`. |
| `sbproxy_webhook_out_total` | 10 000 | Labels: `subscription`, `result`, `tenant_id`. |
| `sbproxy_session_count_distinct` | 1 | HLL gauge; cardinality independent of session count. |

Hard rule: `agent_id`, `request_id`, `session_id`, and `user_id` are never label values on Prometheus metrics. They live as span attributes (under traces) and log fields (under logs). The full per-label budget lives in [adr-metric-cardinality.md](adr-metric-cardinality.md); the reasoning lives in [adr-slo-alert-taxonomy.md](adr-slo-alert-taxonomy.md).

When a budget is exhausted the offending label demotes to `__other__` and `sbproxy_label_demotion_total` increments. The metric update still happens; a demoted bucket is preferable to a missing one because gaps look like real traffic dips.

## Logs

### Structured-log schema

JSON-line, UTF-8, one object per line. Field order is not significant but emitters write top-level fields in the order below for grep-ability.

Required on every line:

| Field | Type | Notes |
|---|---|---|
| `ts` | string (RFC 3339 UTC, ms precision) | `2026-04-30T14:23:45.123Z` |
| `level` | string enum | `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `msg` | string | Human-readable message |
| `target` | string | Module path |
| `event_type` | string enum | See list below |
| `schema_version` | string | `"1"` for the Wave 1 schema |

Required when the line is request-scoped:

| Field | Type | Notes |
|---|---|---|
| `request_id` | string (ULID) | Same value as `RequestEvent.request_id` |
| `trace_id` | string (32 hex) | Current OTel trace id |
| `span_id` | string (16 hex) | Current OTel span id |
| `tenant_id` | string | Workspace id; `default` in OSS |
| `route` | string | Origin route key |

Per-request lifecycle lines (`request_started`, `request_completed`, `request_error`) carry the same body as `RequestEvent` (`agent_id`, `agent_class`, `rail`, `shape`, `status_code`, `latency_ms`, `error_class`).

Event types pinned for Wave 1: `request_started`, `request_completed`, `request_error`, `policy_evaluated`, `policy_blocked`, `action_challenge_issued`, `action_redeemed`, `ledger_call`, `audit_emit`, `notify_dispatch`, `boot`, `config_reload`, `health_status_change`.

### Redaction policy

Sensitive fields are matched by **field key**, not by value heuristics. Field names that the redactor matches: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-stripe-signature`, `stripe-signature`, `*_secret`, `*_token`, `*_key`, `prompt`, `messages`, `ja3`, `ja4`.

Each match replaces the value with a marker:

```json
{ "headers": { "authorization": "<redacted:authorization>" } }
{ "stripe_sk": "<redacted:stripe-secret-key>" }
{ "messages": "<redacted:prompt-body>" }
```

Two profiles ship in Wave 1:

- **`internal`** applies the denylist above. Allows `agent_id`, `tenant_id`, JA3/JA4, request paths.
- **`external`** applies the denylist plus extra redactions: JA3/JA4 fingerprints, raw query strings (replaced with path only), full URL (replaced with `route`), and User-Agent if tenant policy demands fingerprint redaction.

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

### Enabling the redaction tests

The redaction contract is regressed by `e2e/tests/redaction.rs`. To run it locally:

```bash
cargo test -p sbproxy-e2e --release --test redaction
```

The test injects fixture inputs covering every member of the typed `RedactedField` enum, exercises every emitter (access, error, audit, trace), and asserts the marker appears in every sink while the original value appears in none of them. A failure is a CI block; redaction is the line we don't cross.

The full schema, denylist, marker format, and per-sink override mechanism live in [adr-log-schema-redaction.md](adr-log-schema-redaction.md).

## Traces

### Tracer setup

OpenTelemetry SDK, pinned to the `0.27.x` family. The tracer is initialized once at boot in `sbproxy-observe::telemetry::init`; configuration lives under `observability.tracing` in `sb.yml` (see "Configuration" above).

OTLP gRPC (port 4317) is the default exporter. HTTP/protobuf (port 4318) is supported for environments that block gRPC. The `stdout` exporter is for local debugging only.

### W3C TraceContext propagation

Every inbound HTTP path extracts `traceparent` and `tracestate` from request headers; if absent, a fresh root span starts. Every outbound HTTP client owned by SBproxy injects `traceparent` and `tracestate` before send. The propagation invariant is non-negotiable for these clients (each has a unit test asserting the header injection):

| Client | Used for |
|---|---|
| `HttpLedger` | Ledger redeem |
| Stripe adapter | Metered billing (Wave 2) |
| MPP / x402 facilitator clients | Payment settlement (Wave 3) |
| Web Bot Auth directory fetcher | Directory refresh |
| KYA token verifier | Identity proof (Wave 5) |
| Agent registry feed client | Reputation feed (Wave 2) |
| Outbound webhook delivery | Customer notifications |
| OAuth / token endpoints | Token exchange |

Adding a new outbound integration without propagation breaks CI.

### Span naming

Span names follow `sbproxy.<pillar>.<verb>`:

| Span | Pillar |
|---|---|
| `sbproxy.intake.accept` | Top-level inbound request (root) |
| `sbproxy.policy.enforce` | Per-policy execution |
| `sbproxy.action.challenge` | Issue 402 challenge |
| `sbproxy.action.redeem` | Verify presented token / receipt |
| `sbproxy.ledger.redeem` | Outbound HTTP call to ledger |
| `sbproxy.rail.settle` | Outbound payment-rail settlement |
| `sbproxy.transform.shape` | Content transform |
| `sbproxy.audit.emit` | Append audit-log entry |
| `sbproxy.notify.deliver` | Outbound webhook delivery |

Span attributes include the OTel semantic conventions (`http.request.method`, `http.response.status_code`, `server.address`) plus the SBproxy-specific set (`sbproxy.request_id`, `sbproxy.tenant_id`, `sbproxy.route`, `sbproxy.agent_id`, `sbproxy.agent_class`, `sbproxy.rail`, `sbproxy.shape`, `sbproxy.ledger.idempotency_key`).

High-cardinality attributes (`request_id`, `agent_id`) are span attributes only, never Prometheus labels.

### Sampling

Wave 1 ships head-based sampling, evaluated at the root span:

1. If the inbound `traceparent` has the `sampled` bit set, sample (parent-based).
2. Else if the request errors (5xx, policy block, ledger denial), sample 100%.
3. Else sample at `head_rate` (default 0.1).

Tail-based sampling (drop based on outcome at span end) is deferred to Wave 6. The reference Compose stack ships an OTel Collector recipe operators can opt into; the proxy itself does not run a tail sampler.

### Exemplars

Exemplars are wired on every histogram where "click the outlier in Grafana, get the trace" is a high-value debugging path:

- `sbproxy_request_duration_seconds_bucket` (top-level latency)
- `sbproxy_ledger_redeem_duration_seconds_bucket` (ledger tail)
- `sbproxy_policy_evaluation_duration_seconds_bucket` (policy regressions)
- `sbproxy_outbound_request_duration_seconds_bucket` (per-outbound tail)
- `sbproxy_audit_emit_duration_seconds_bucket` (audit-log write tail)

Exemplars carry `trace_id` per scrape interval. Prometheus needs `--enable-feature=exemplar-storage`; the reference stack sets it.

The full ADR is [adr-observability.md](adr-observability.md).

## Dashboards

JSON files live under `deploy/dashboards/`:

- `overview.json` - request rate, error rate, latency p95/p99, ledger health.
- `per-agent.json` - per-`agent_class` and per-`agent_vendor` request rate, redeem rate, revenue (Wave 2 fills the revenue panel).
- `policy-triggers.json` - per-policy block rate, decision distribution.
- `audit-log.json` - admin-action volume, outcome distribution, append-only verification status.
- `traces-overview.json` - span chain length, slowest spans, sampling rate.

The Helm chart provisions them via the kiwigrid sidecar:

```yaml
# values.yaml
dashboards:
  enabled: true
  configMap:
    sbproxy-dashboards:
      labels:
        grafana_dashboard: "1"
```

The sidecar mounts `deploy/dashboards/*.json` into Grafana at startup. Operators who run Grafana outside Helm can `kubectl create configmap` the JSON files directly with the `grafana_dashboard=1` label.

## Alerts

Three tiers, each with explicit on-call semantics:

- **Page (P1, immediate human action).** Goes to PagerDuty; on-call acks within 15 minutes. Examples: ledger down, audit-log write failure, rail quorum loss, restore-drill miss.
- **Ticket (P2, next business day).** Files an issue in the on-call queue. Examples: latency p95 sustained breach, webhook delivery failure rate, classifier drift (Wave 5).
- **Log-only (P3).** Records the alert in Alertmanager but routes to log destinations only. Examples: cardinality near budget (90% of cap), deprecated-flag use, exemplar emission rate dropping.

Burn-rate windows for the page tier: 5m AND 1h at 14.4x, 30m AND 6h at 6x. Ticket tier: 2h AND 24h at 3x. Every paging alert has a runbook entry; the `runbook_id` label maps 1:1 to a section in `docs/operator-runbook.md`.

The full alert ID convention, runbook stub format, and game-day requirements live in [adr-slo-alert-taxonomy.md](adr-slo-alert-taxonomy.md).

## Health endpoints

Two endpoints, both on the management port (default `127.0.0.1:9091`):

```bash
curl http://localhost:9091/healthz
# 200 OK, no body. Liveness only; the kubelet uses this to decide whether to restart the pod.

curl http://localhost:9091/readyz
# 200 OK with a JSON body listing each component status.
# 503 with the same body when any required dependency is unhealthy.
```

`/readyz` reports per-component status: ledger reachable, bot-auth directory fresh, agent registry loaded (Wave 2), Stripe reachable (Wave 2), facilitator quorum (Wave 3). Components not yet wired into the build report `not_wired` and pass readiness; Wave 2 onward fills them in.

## Reference Compose stack

`examples/00-observability-stack/` boots Prometheus, Grafana, Tempo, Loki, and an OTel Collector with one command:

```bash
cd examples/00-observability-stack
docker compose up -d
```

Then open:

- Grafana at http://localhost:3000 (login `admin` / `admin`)
- Prometheus at http://localhost:9090
- Loki ready endpoint at http://localhost:3100/ready
- Tempo via Grafana (no first-class UI)

Point SBproxy at the stack with two extra flags:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4327 \
  sbproxy run --config sb.yml --metrics-listen 127.0.0.1:9091
```

The OTLP endpoint targets the OTel Collector (host port 4327, mapped to the container's 4317). Prometheus scrapes the proxy at `host.docker.internal:9091`. The dashboards from `deploy/dashboards/` are pre-provisioned, so you see metrics, logs, and traces flow as soon as the proxy starts handling requests.

`docker compose down -v` drops the four named volumes (`prometheus_data`, `grafana_data`, `tempo_data`, `loki_data`) for a fresh start.

## See also

- [adr-observability.md](adr-observability.md) - tracer choice, propagation contract, span naming.
- [adr-log-schema-redaction.md](adr-log-schema-redaction.md) - log schema v1 and per-sink redaction profiles.
- [adr-slo-alert-taxonomy.md](adr-slo-alert-taxonomy.md) - SLO catalog, alert tiers, runbook conventions.
- [adr-metric-cardinality.md](adr-metric-cardinality.md) - per-metric label budget and demotion rules.
- [audit-log.md](audit-log.md) - admin-action audit envelope.
- [ai-crawl-control.md](ai-crawl-control.md) - per-agent observability for the Pay Per Crawl policy.
- `deploy/dashboards/` - Grafana JSON for the Wave 1 panels.
- `deploy/alerts/` - PromQL recording and alerting rules.
- `examples/00-observability-stack/` - the reference Compose stack.
