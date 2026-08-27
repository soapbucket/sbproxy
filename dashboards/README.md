# SBproxy Dashboards and Alerts
*Last modified: 2026-08-26*

Grafana dashboards and Prometheus alert/recording rules for monitoring SBproxy.

## Prerequisites

- **Prometheus** scraping SBproxy's telemetry endpoint (default `:9090/metrics`)
- **Grafana** with a Prometheus datasource configured

Ensure your Prometheus `scrape_configs` include SBproxy:

```yaml
scrape_configs:
  - job_name: sbproxy
    static_configs:
      - targets: ["sbproxy:9090"]
```

## Grafana Dashboards

| Dashboard | File | UID | Description |
|-----------|------|-----|-------------|
| SBProxy Overview | `grafana/sbproxy-overview.json` | `sbproxy-overview` | Request rate, latency percentiles, error rate, active connections, cache hit ratio, bandwidth |
| AI Gateway | `grafana/sbproxy-ai-gateway.json` | `sbproxy-ai-gateway` | AI provider request rates, token usage, TTFT, guardrail triggers, fallbacks, context-compression savings, latency, failures, and state coordination, plus pre-provider admission refusals by reason and by share of each surface's arriving traffic, and an arrived / dispatched / refused reconciliation. The routing and reliability section covers post-commit streaming failures, provider-key fallbacks, model groups, prompt-cache affinity, service tiers, request-timeout overrides, shadow evaluation, classifier failures, chargeback integrity, and the live workflow/evaluation/prompt-rollout toolkit outcomes. |
| AI Value | `grafana/sbproxy-ai-value.json` | `sbproxy-ai-value` | Per-credential, multi-tenant, multi-model value tracking: spend, token volume, p95 model latency, value-vs-waste by outcome, and success-only compression tokens and cost saved. Tokenizer precision stays visible. Ends with a trust row that says how much of the spend figure is measured: which price table produced each price, price-ceiling outcomes, token-estimate error p05 and p95 by model, and semantic-cache dollars saved. |
| Judge Backend | `grafana/sbproxy-judge-backend.json` | `sbproxy-judge-backend` | LLM-as-judge call rate by verdict, cache hit ratio, latency, cost per decision, budget exhaustion |
| Policy Verdicts | `grafana/sbproxy-policy-verdicts.json` | `sbproxy-policy-verdicts` | Verdict rate by tag, audit bus drops per tenant, plugin vs built-in surface ratio, decision latency percentiles, top policies |
| Security | `grafana/sbproxy-security.json` | `sbproxy-security` | WAF blocks, rate limiting, auth failures, IP filter blocks, bot detections, key operations and credential resolution, audit write failures, CORS refusals by reason, RFC 9421 legacy signature derivation on its deprecation window, and certificate-store degradation |
| Origins | `grafana/sbproxy-origins.json` | `sbproxy-origins` | Per-origin request rate, latency, and error rate |
| AI Bot & Agent Traffic | `grafana/sbproxy-ai-bot-traffic.json` | `sbproxy-ai-bot-traffic` | Inbound AI bot / agent volume by class, vendor, and verification status (verified Web Bot Auth vs anonymous vs unknown); paid vs unpaid breakdown; AI crawl policy verdicts (allow / block / tarpit); bot-auth integrity (nonce replays, skill digest mismatches) |
| Model Host | `grafana/sbproxy-model-host.json` | `sbproxy-model-host` | Local inference-engine lifecycle: resident models, cold-start (time-to-ready) latency, launch/eviction rates, load-queue depth, and per-device VRAM used/free and GPU utilization |
| Mesh Admission & Storage | `grafana/sbproxy-mesh-storage.json` | `sbproxy-mesh-storage` | Mesh inbound connection admission by refusal reason and regrouped by operator fix, plus storage backend latency percentiles, error rate by error kind, operation throughput, and error ratio. Both halves report only where the mesh runs with its Redis backend, and the header tiles say so rather than leaving an empty chart to read as health. |
| Classifier Sidecar | `grafana/sbproxy-classifier.json` | `sbproxy-classifier` | The rich classifier sidecar (`sbproxy-classifier`): admission queue/refusals, registered tenant count, request rate by transport and command, errors by reason, quality-score distribution (p50/p95), streaming safety verdict rate, the typed attempt/completion/terminal-outcome lifecycle, and the release startup owner. This sidecar runs as its own process with its own `/metrics` endpoint (`--metrics-addr`, default `127.0.0.1:9402`), separate from the main proxy scrape target. Its eleven families are classified in the central `docs/metrics-stability.md` capability catalog, and this dashboard graphs all eleven. The last panel is the exception to the scrape target: `sbproxy_classifier_client_fallback_total` is written by the proxy, not the sidecar, because an unreachable sidecar emits nothing at all and only the caller can say the fallback is carrying the traffic. |

The routing and reliability section on `sbproxy-ai-gateway` follows the
convention `sbproxy-mesh-storage` set: a strip of `absent()` tiles reading
`In use` or `Not in use`, then panels whose `noValue` string says which kind of
emptiness you are looking at. Named model groups, prompt-cache affinity, shadow
evaluation and the per-request timeout override each register their family on
first use, so a deployment that has not configured one has no series at all
rather than a series sitting at zero. Read the tile before reading the chart.
Provider-key fallbacks and post-commit stream failures are the other kind: they
are absent because nothing has gone wrong yet, and an empty chart there is the
healthy state.

The final three AI Gateway panels slice the single bounded
`sbproxy_ai_toolkit_operations_total{capability,outcome}` family into workflow,
evaluation, and prompt-rollout views. Capability and outcome are closed enums.
Workflow names, datasets, prompt names, run IDs, endpoints, prompt/response
content, tokens, and secret references are intentionally absent from labels;
use authenticated bounded admin records and typed events for per-operation
diagnosis.

One family cannot be charted at all and it is the obvious one to reach for on
the mesh board: `mesh_peer_count`. The coverage scanner in
`crates/sbproxy-capability/src/scan.rs` canonicalizes a `_count` suffix back to
the family it belongs to, because that is how a histogram's derived series are
folded into their parent. Applied to a gauge whose real name ends in `_count`,
it resolves `mesh_peer_count` to `mesh_peer`, which no crate declares, and the
build refuses the panel. It is the only one of the 331 declared families with
that name shape. `sbproxy-mesh-storage.json` uses `mesh_node_isolated` as its
mesh-is-running tile instead; mesh bootstrap publishes that gauge at 0 when it
builds the isolation observer, so its presence carries the same signal.

### Reading "not reported"

Some families only exist once the feature that writes them is configured. On a
Prometheus datasource a family that was never written and a family sitting at
zero both render as a flat zero line, so a panel over an unconfigured feature
reads as a healthy zero.

Panels over an optional family therefore carry a second target,
`absent(<family>)`, whose series is named `not reported` and pinned red by a
`byName` field override. When that red line sits at 1 the family has never been
written and the panel below it is not a measurement of anything. When the red
line is missing and the other series read zero, that is a real zero. Each such
panel's description says which of the two its absence means.

The `absent()` target must carry the same label selector as the target it
guards. A panel filtered to `{tenant=~"$tenant"}` whose guard reads the bare
family goes quiet the moment any other tenant writes the family, which is the
false healthy zero the convention exists to prevent.

The trust row on `sbproxy-ai-value` is the current example, on all four of its
panels.

### Importing via Grafana UI

1. Open Grafana and navigate to **Dashboards > Import**
2. Click **Upload JSON file** and select a dashboard file from `grafana/`
3. Select your Prometheus datasource when prompted for `DS_PROMETHEUS`
4. Click **Import**

### Importing via Provisioning

Add a provisioning config at `/etc/grafana/provisioning/dashboards/sbproxy.yml`:

```yaml
apiVersion: 1
providers:
  - name: sbproxy
    type: file
    options:
      path: /var/lib/grafana/dashboards/sbproxy
      foldersFromFilesStructure: false
```

Then copy the JSON files into `/var/lib/grafana/dashboards/sbproxy/`.

Note: When using provisioning, replace `${DS_PROMETHEUS}` in the JSON files with your actual Prometheus datasource UID, or use Grafana's `__inputs` resolution.

## Prometheus Alerts

The alert rules file is at `prometheus/alerts.yml`. Add it to your Prometheus configuration:

```yaml
rule_files:
  - /etc/prometheus/rules/sbproxy-alerts.yml
```

### Alert Summary

| Alert | Severity | Condition |
|-------|----------|-----------|
| SBProxyHighErrorRate | critical | 5xx error rate > 5% for 2 minutes |
| SBProxyHighLatency | warning | P95 latency > 2 seconds for 5 minutes |
| SBProxyAIProviderDown | critical | AI provider returning only errors for 2 minutes |
| SBProxyGuardrailSpike | warning | Guardrail block rate > 10/min for 1 minute |
| SBProxyHighTokenUsage | info | Over 1M output tokens in the last hour |
| SBProxyAIAdmissionRefusalShare | warning | More than 5% of one AI surface's arriving requests refused before any provider was called, for 15 minutes |
| SBProxyAICompressionFailures | warning | Compression failure ratio > 10% for 10 minutes |
| SBProxyAICompressionStateRejections | warning | Compression state-operation errors > 0.1/sec for 10 minutes |
| SBProxyAICompressionValueUnpriced | warning | Successful compression saves > 10 estimated tokens/sec for a model while avoided cost remains zero for 15 minutes |

## Recording Rules

Pre-computed metrics for faster dashboard queries. Located at `prometheus/recording-rules.yml`.

Add to your Prometheus config:

```yaml
rule_files:
  - /etc/prometheus/rules/sbproxy-recording-rules.yml
```

### Recording Rule Reference

| Metric | Expression |
|--------|------------|
| `sbproxy:request_rate_5m` | Total request rate (5m window) |
| `sbproxy:error_rate_5m` | 5xx error ratio (5m window) |
| `sbproxy:ai_token_rate_5m` | AI output token rate (5m window) |
| `sbproxy:ai_latency_p95_5m` | AI request P95 latency (5m window) |
| `sbproxy:ai_compression_application_rate_5m` | Fraction of compression lever invocations that applied (5m window) |
| `sbproxy:ai_compression_failure_ratio_5m` | Fraction of non-empty compression requests with any failed lever (5m window) |
| `sbproxy:ai_compression_latency_p95_5m` | Compression lever P95 latency (5m window) |
| `sbproxy:ai_compression_tokens_saved_rate_5m` | Reduction in SBproxy's shared token estimate from applied compression levers per second (5m window) |
| `sbproxy:ai_compression_value_tokens_saved_by_tenant_model_lever_5m` | Success-only estimated tokens saved per second, preserving tenant, origin, model, lever, and tokenizer precision |
| `sbproxy:ai_compression_value_cost_saved_dollars_by_tenant_model_lever_5m` | Success-only gross input cost saved per second in USD, preserving tenant, origin, model, lever, and tokenizer precision |

## Metric names reference

The catalogue lives in [`docs/metrics-stability.md`](../docs/metrics-stability.md),
which is generated from the executable metric registry in
`crates/sbproxy-observe/src/metric_registry.rs`. It lists every family SBproxy
emits, its labels, whether anything increments it, and what we promise about
its name.

A hand-written copy used to live here. It had drifted into fiction: it listed
five metrics that no crate declares (`sbproxy_cache_misses_total`,
`sbproxy_bandwidth_bytes_total`, `sbproxy_ai_cache_hits_total`,
`sbproxy_ai_guardrail_triggers_total`, `sbproxy_ai_fallbacks_total`) and gave
`sbproxy_requests_total` three labels it does not carry. Anyone who built a
query from it got no data back and no explanation. That is precisely the class
of drift the generated catalogue exists to end, so this section is a pointer
now, and cannot rot.
