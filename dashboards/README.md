# SBproxy Dashboards and Alerts
*Last modified: 2026-07-18*

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
| AI Gateway | `grafana/sbproxy-ai-gateway.json` | `sbproxy-ai-gateway` | AI provider request rates, token usage, TTFT, guardrail triggers, fallbacks, and context-compression savings, latency, failures, and state coordination |
| AI Value | `grafana/sbproxy-ai-value.json` | `sbproxy-ai-value` | Per-credential, multi-tenant, multi-model value tracking: spend, token volume, p95 model latency, value-vs-waste by outcome, and success-only compression tokens and cost saved. Tokenizer precision stays visible. |
| Judge Backend | `grafana/sbproxy-judge-backend.json` | `sbproxy-judge-backend` | LLM-as-judge call rate by verdict, cache hit ratio, latency, cost per decision, budget exhaustion |
| Policy Verdicts | `grafana/sbproxy-policy-verdicts.json` | `sbproxy-policy-verdicts` | Verdict rate by tag, audit bus drops per tenant, plugin vs built-in surface ratio, decision latency percentiles, top policies |
| Security | `grafana/sbproxy-security.json` | `sbproxy-security` | WAF blocks, rate limiting, auth failures, IP filter blocks, bot detections |
| Origins | `grafana/sbproxy-origins.json` | `sbproxy-origins` | Per-origin request rate, latency, and error rate |
| AI Bot & Agent Traffic | `grafana/sbproxy-ai-bot-traffic.json` | `sbproxy-ai-bot-traffic` | Inbound AI bot / agent volume by class, vendor, and verification status (verified Web Bot Auth vs anonymous vs unknown); paid vs unpaid breakdown; AI crawl policy verdicts (allow / block / tarpit); bot-auth integrity (nonce replays, skill digest mismatches) |
| Model Host | `grafana/sbproxy-model-host.json` | `sbproxy-model-host` | Local inference-engine lifecycle: resident models, cold-start (time-to-ready) latency, launch/eviction rates, load-queue depth, and per-device VRAM used/free and GPU utilization |

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
