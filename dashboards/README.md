# SBproxy Dashboards and Alerts
*Last modified: 2026-04-27*

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
| AI Gateway | `grafana/sbproxy-ai-gateway.json` | `sbproxy-ai-gateway` | AI provider request rates, token usage, TTFT, guardrail triggers, fallbacks |
| Security | `grafana/sbproxy-security.json` | `sbproxy-security` | WAF blocks, rate limiting, auth failures, IP filter blocks, bot detections |
| Origins | `grafana/sbproxy-origins.json` | `sbproxy-origins` | Per-origin request rate, latency, and error rate |

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

## Metric Names Reference

### Core Proxy Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sbproxy_requests_total` | Counter | `status`, `origin`, `instance` | Total HTTP requests |
| `sbproxy_request_duration_seconds_bucket` | Histogram | `origin`, `le` | Request duration distribution |
| `sbproxy_active_connections` | Gauge | `instance` | Current active connections |
| `sbproxy_cache_hits_total` | Counter | | Cache hits |
| `sbproxy_cache_misses_total` | Counter | | Cache misses |
| `sbproxy_bandwidth_bytes_total` | Counter | `direction` (in/out) | Bytes transferred |

### AI Gateway Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sbproxy_ai_requests_total` | Counter | `provider`, `status` | AI provider requests |
| `sbproxy_ai_tokens_input_total` | Counter | `provider` | Input tokens consumed |
| `sbproxy_ai_tokens_output_total` | Counter | `provider` | Output tokens generated |
| `sbproxy_ai_request_duration_seconds_bucket` | Histogram | `provider`, `le` | AI request latency distribution |
| `sbproxy_ai_ttft_seconds_bucket` | Histogram | `le` | Time to first token distribution |
| `sbproxy_ai_cache_hits_total` | Counter | | AI semantic cache hits |
| `sbproxy_ai_guardrail_triggers_total` | Counter | `type`, `action` | Guardrail trigger events |
| `sbproxy_ai_provider_errors_total` | Counter | `provider` | Provider-level errors |
| `sbproxy_ai_fallbacks_total` | Counter | `from_provider`, `to_provider` | Provider fallback events |

### Security Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sbproxy_waf_blocks_total` | Counter | `rule` | WAF rule blocks |
| `sbproxy_rate_limit_hits_total` | Counter | `origin` | Rate limiter rejections |
| `sbproxy_auth_failures_total` | Counter | `type` | Authentication failures |
| `sbproxy_ip_filter_blocks_total` | Counter | `list_type` | IP filter rejections |
| `sbproxy_bot_detections_total` | Counter | `category` | Bot detection events |
