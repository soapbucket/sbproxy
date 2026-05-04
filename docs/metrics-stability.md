# Metrics stability

*Last modified: 2026-04-24*

Naming conventions, stability guarantees, and the full catalogue of metrics emitted by SBproxy.

---

## Naming convention

- Prefix: all metrics use `sbproxy_`.
- Case: snake_case.
- Units: encoded in the metric name suffix, following Prometheus conventions:
  - `_seconds` for durations
  - `_bytes` for byte counts
  - `_total` for cumulative counters (monotonically increasing)
  - `_ratio` for ratios (0.0 to 1.0)
  - `_dollars` for monetary values
- Gauges: metrics without `_total` that represent a current state (e.g. `sbproxy_active_connections`).
- Histograms: duration and size metrics are histograms with `_bucket`, `_sum`, and `_count` suffixes exposed automatically by the metrics library.

---

## Stability tiers

### `stable`

A `stable` metric will not be renamed or removed without a deprecation period.

- Renaming or removing a stable metric requires: announce deprecation in the next minor release (adding a `_DEPRECATED` alias), then remove it in the following major release.
- Label names on stable metrics are also stable. New labels may be added in minor releases. Removing labels follows the same deprecation process.

### `beta`

A `beta` metric is functional. Its name or labels may still change in a minor release with a changelog entry.

### `alpha`

An `alpha` metric may be renamed, relabeled, or removed in any release without notice.

---

## Metric catalogue

All metrics below are currently `stable`.

### HTTP traffic

#### `sbproxy_requests_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of HTTP requests processed by the proxy, including all origins. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname (origin key from sb.yml) | `api.example.com` |
| `method` | HTTP method of the request | `GET`, `POST` |
| `status` | HTTP status code returned to the client | `200`, `404`, `502` |

---

#### `sbproxy_request_duration_seconds`

| Property | Value |
|---|---|
| Type | Histogram |
| Stability | **stable** |
| Description | End-to-end request duration in seconds, from first byte received to last byte sent. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `method` | HTTP method | `GET`, `POST` |
| `status` | HTTP status code | `200`, `502` |

---

#### `sbproxy_active_connections`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **stable** |
| Description | Current number of active client connections being handled by the proxy. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |

---

#### `sbproxy_bytes_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total bytes transferred through the proxy. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `direction` | Transfer direction relative to the proxy | `inbound` (client -> proxy), `outbound` (proxy -> client) |

---

### Authentication

#### `sbproxy_auth_results_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total authentication attempts and their outcomes. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `auth_type` | Authentication plugin used | `basic_auth`, `api_keys`, `oauth2`, `jwt` |
| `result` | Outcome of the authentication check | `allow`, `deny`, `error` |

---

### Policies

#### `sbproxy_policy_triggers_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of times a policy plugin matched and took an action on a request. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `policy_type` | Policy plugin name | `rate_limit`, `ip_filter`, `waf`, `cel`, `lua` |
| `action` | Action taken by the policy | `allow`, `block`, `throttle`, `log` |

---

### Caching

#### `sbproxy_cache_results_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total response cache lookups and their results. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `result` | Cache lookup outcome | `hit`, `miss`, `stale`, `bypass` |

---

### Circuit breaker

#### `sbproxy_circuit_breaker_transitions_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of circuit breaker state transitions for upstream connections. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `origin` | Virtual hostname | `api.example.com` |
| `from_state` | State before the transition | `closed`, `open`, `half_open` |
| `to_state` | State after the transition | `closed`, `open`, `half_open` |

---

### AI gateway

#### `sbproxy_ai_requests_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total AI inference requests forwarded by the proxy. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic`, `google`, `cohere` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet`, `gemini-1.5-pro` |
| `status` | Request outcome | `success`, `error`, `timeout`, `rate_limited` |

---

#### `sbproxy_ai_tokens_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total AI tokens processed. Counts input and output tokens separately. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet` |
| `direction` | Token direction | `input`, `output` |

---

#### `sbproxy_ai_cost_dollars_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Cumulative estimated cost of AI requests in US dollars, based on the provider pricing catalog. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `model` | Model identifier | `gpt-4o`, `claude-3-5-sonnet` |

---

#### `sbproxy_ai_failovers_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of AI provider failover events where the proxy switched to a backup provider. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `from_provider` | Provider that failed | `openai` |
| `to_provider` | Provider selected as fallback | `anthropic` |
| `reason` | Reason the primary provider was bypassed | `error`, `timeout`, `rate_limited`, `budget_exceeded` |

---

#### `sbproxy_ai_guardrail_blocks_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total number of requests blocked by the AI guardrail engine. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `category` | Guardrail category that triggered | `pii`, `toxicity`, `off_topic`, `prompt_injection` |

---

#### `sbproxy_ai_cache_results_total`

| Property | Value |
|---|---|
| Type | Counter |
| Stability | **stable** |
| Description | Total AI response cache lookups and their results, covering both exact-match and semantic (vector) caches. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `provider` | AI provider name | `openai`, `anthropic` |
| `cache_type` | Type of cache layer consulted | `exact`, `semantic` |
| `result` | Lookup outcome | `hit`, `miss` |

---

#### `sbproxy_ai_budget_utilization_ratio`

| Property | Value |
|---|---|
| Type | Gauge |
| Stability | **stable** |
| Description | Current AI spend as a fraction of the configured budget limit (0.0 = no spend, 1.0 = budget fully consumed). Values above 1.0 indicate overspend before enforcement caught up. |

**Labels:**

| Label | Description | Example values |
|---|---|---|
| `scope` | Budget scope level | `workspace`, `origin`, `global` |

---

## Deprecation process

When a stable metric must change:

1. The new metric is introduced alongside the old one in the next minor release.
2. The old metric emits a log warning on first scrape, noting the deprecation and target removal version.
3. The old metric is removed in the next major release.

Beta and alpha metrics may be removed or renamed without this process. Check the changelog.
