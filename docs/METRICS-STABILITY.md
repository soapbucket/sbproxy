# Metrics Stability Policy
*Last modified: 2026-04-17*

Prometheus metric names and labels follow stability tiers to prevent breaking dashboards and alerts.

## Tiers

### Stable Metrics
Cannot be renamed or removed without a major version bump. Label sets cannot change.

### Beta Metrics
May be renamed or have labels adjusted in minor releases with a deprecation period (one release with both old and new names).

### Alpha Metrics
May change or be removed in any release. Experimental.

## Current Metrics

### Request Metrics (Stable)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `sbproxy_http_requests_total` | counter | - | Total HTTP requests |
| `sbproxy_http_ok_total` | counter | - | 2xx responses |
| `sbproxy_http_client_errors_total` | counter | - | 4xx responses |
| `sbproxy_http_server_errors_total` | counter | - | 5xx responses |
| `sbproxy_http_duration_seconds` | histogram | - | Request latency |

### Config Metrics (Stable)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `sbproxy_config_cache_hits_total` | counter | source | Config cache hits |
| `sbproxy_config_cache_misses_total` | counter | source | Config cache misses |
| `sbproxy_config_cache_size` | gauge | - | Cached configs |
| `sbproxy_config_active_origins` | gauge | source | Active origins |
| `sbproxy_config_loads_total` | counter | source | Config loads |
| `sbproxy_config_load_duration_seconds` | histogram | source | Load latency |
| `sbproxy_config_load_errors_total` | counter | source | Load failures |

### Storage Metrics (Beta)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `sbproxy_storage_operations_total` | counter | backend, operation | Storage ops |
| `sbproxy_storage_operation_duration_seconds` | histogram | backend, operation | Op latency |
| `sbproxy_storage_operation_errors_total` | counter | backend, operation | Op failures |

### AI Metrics (Beta)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `sbproxy_ai_requests_total` | counter | provider, model, status | AI requests |
| `sbproxy_ai_tokens_input_total` | counter | provider, model | Input tokens |
| `sbproxy_ai_tokens_output_total` | counter | provider, model | Output tokens |
| `sbproxy_ai_duration_seconds` | histogram | provider, model | AI latency |
| `sbproxy_ai_cost_total` | counter | provider, model | Estimated cost |

### Cache Metrics (Beta)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `sbproxy_cache_hits_total` | counter | backend | Cache hits |
| `sbproxy_cache_misses_total` | counter | backend | Cache misses |
| `sbproxy_cache_evictions_total` | counter | backend | Evictions |

### Security Metrics (Beta)

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `sbproxy_security_blocks_total` | counter | reason | Blocked requests |
| `sbproxy_rate_limit_hits_total` | counter | origin | Rate limit triggers |

## Cardinality Limits

All metrics with variable labels are subject to cardinality limiting (default: 1000 unique values per label). When exceeded, new values are mapped to `"other"`. Configure via:

```yaml
proxy:
  metrics:
    max_cardinality_per_label: 1000
```

## Deprecation Process

1. Old metric continues to emit alongside new metric for one minor release
2. Old metric logs a deprecation warning at startup
3. Old metric removed in the following minor release
