# SBproxy Configuration Reference (Field-Level)

*Last modified: 2026-04-12*

Field-level reference for all configuration options. Field names are the exact JSON/YAML keys used in `sb.yml`.

---

## Top-Level Structure

```yaml
proxy:        # Server-level settings (ports, TLS, timeouts)
origins:      # Map of hostname -> origin config
```

---

## 1. Proxy Server Settings (`proxy:`)

These settings go under the `proxy:` key in `sb.yml`.

| Field | Type | Default | Description |
|---|---|---|---|
| `http_bind_port` | int | 0 | HTTP listen port (e.g. 8080) |
| `https_bind_port` | int | 0 | HTTPS listen port (e.g. 8443) |
| `http3_bind_port` | int | 0 | HTTP/3 (QUIC) listen port |
| `enable_http3` | bool | false | Enable HTTP/3 on the HTTPS port |
| `bind_address` | string | `""` | Bind address (default: all interfaces) |
| `read_timeout` | duration | 30s | Maximum time to read an entire request |
| `write_timeout` | duration | 30s | Maximum time to write a response |
| `idle_timeout` | duration | 120s | Keep-alive idle connection timeout |
| `grace_time` | duration | 10s | Graceful shutdown drain time |
| `tls_cert` | string | `""` | Path to TLS certificate file |
| `tls_key` | string | `""` | Path to TLS private key file |

### 1.1 ACME / Automatic TLS (`proxy.certificate_settings`)

| Field | Type | Default | Description |
|---|---|---|---|
| `use_acme` | bool | false | Enable ACME (Let's Encrypt) certificate management |
| `acme_email` | string | `""` | Contact email for certificate notices |
| `acme_domains` | []string | — | Domains to issue certificates for |
| `acme_cache_dir` | string | `""` | Directory to cache ACME state |
| `acme_directory_url` | string | Let's Encrypt | Custom ACME directory URL |
| `min_tls_version` | int | 12 | Minimum TLS version: 12 = TLS 1.2, 13 = TLS 1.3 |
| `client_auth` | string | `"none"` | Inbound mTLS policy: `none`, `request`, `require`, `require_and_verify` |
| `client_ca_cert_file` | string | `""` | CA certificate bundle for verifying client certs |

### 1.2 PROXY Protocol (`proxy.proxy_protocol`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Parse HAProxy PROXY protocol v1/v2 headers |
| `trusted_cidrs` | []string | — | Source IPs trusted to send PROXY protocol headers |

### 1.3 Logging (`proxy.logging`)

| Field | Type | Default | Description |
|---|---|---|---|
| `format` | string | `"json"` | Log format: `json` or `dev` (colored) |

### 1.4 OpenTelemetry (`otel:`)

Top-level `otel:` key.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable OpenTelemetry export |
| `otlp_endpoint` | string | `""` | OTLP collector endpoint |
| `otlp_protocol` | string | `"grpc"` | `grpc` or `http/protobuf` |
| `otlp_insecure` | bool | false | Disable TLS for OTLP |
| `service_name` | string | `"sbproxy"` | Service name in traces/metrics |
| `sample_rate` | float64 | 1.0 | Trace sampling rate (0.0 - 1.0) |

### 1.5 Telemetry / Prometheus (`telemetry:`)

Top-level `telemetry:` key.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable Prometheus metrics endpoint |
| `bind_address` | string | `""` | Metrics server bind address |
| `bind_port` | int | 0 | Metrics server port (e.g. 9090) |

```yaml
# Example: minimal server config
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  read_timeout: 30s
  write_timeout: 30s
  certificate_settings:
    use_acme: true
    acme_email: ops@example.com
    acme_domains: [api.example.com]
    acme_cache_dir: /var/cache/sbproxy/acme

telemetry:
  enabled: true
  bind_port: 9090

otel:
  enabled: true
  otlp_endpoint: http://otelcol:4317
  service_name: my-proxy
```

---

## 2. Origin Settings

Each key in `origins:` is a hostname. The value is an origin config object.

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | string | — | Unique origin identifier (auto-set from hostname when inline) |
| `hostname` | string | — | Hostname this origin serves |
| `workspace_id` | string | — | Workspace identifier for isolation |
| `version` | string | — | Config version string |
| `environment` | string | `""` | Environment tag: `dev`, `stage`, `prod` |
| `tags` | []string | — | User-defined tags for filtering |
| `disabled` | bool | false | Disable this origin |
| `force_ssl` | bool | false | Redirect HTTP to HTTPS |
| `debug` | bool | false | Enable debug headers (X-Sb-*) |
| `allowed_methods` | []string | — | Restrict to specific HTTP methods |
| `default_content_type` | string | `application/json` | Fallback Content-Type for error responses |
| `action` | object | — | Required. The action to perform (see section 3) |
| `authentication` | object | — | Authentication config (see section 4) |
| `policies` | []object | — | Policy list (see section 5) |
| `transforms` | []object | — | Transform list (see section 6) |
| `response_cache` | object | — | Response cache config (see section 7) |
| `request_modifiers` | []object | — | Request modification rules (see section 8) |
| `response_modifiers` | []object | — | Response modification rules (see section 8) |
| `forward_rules` | []object | — | Path-based routing rules (see section 9) |
| `session` | object | none | Session settings (see section 10) |
| `error_pages` | []object | — | Custom error page definitions (see section 11) |
| `variables` | object | — | Key-value variables for template use (see section 12) |
| `secrets` | object | — | Secret references (see section 12) |
| `vaults` | object | — | Named vault backends |
| `cors` | object | — | CORS configuration |
| `compression` | object | — | Response compression |
| `hsts` | object | — | HSTS header configuration |
| `on_load` | []object | — | Callbacks executed at config load time |
| `on_request` | []object | — | Callbacks executed per request |
| `events` | []string | — | Event types to emit (e.g. `"ai.*"`, `"*"`) |

---

## 3. Action Types

Every origin requires an `action` block with a `type` field.

### 3.1 `proxy` - Reverse Proxy

Forwards requests to an upstream HTTP/HTTPS server.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"proxy"` |
| `url` | string | — | Upstream URL (required) |
| `method` | string | `""` | Override HTTP method |
| `alt_hostname` | string | `""` | Override Host header sent to backend |
| `strip_base_path` | bool | false | Use request path as-is, ignoring URL base path |
| `preserve_query` | bool | false | Use only request query params, ignoring URL query |
| `timeout` | duration | 30s | Request timeout (max: 1m) |
| `skip_tls_verify_host` | bool | false | Disable TLS certificate verification |
| `disable_follow_redirects` | bool | false | Do not follow backend redirects |
| `disable_compression` | bool | false | Do not request compressed responses |
| `http11_only` | bool | false | Force HTTP/1.1 |
| `enable_http3` | bool | false | Enable HTTP/3 for backend connections |
| `min_tls_version` | string | `""` | Minimum TLS version: `"1.2"` or `"1.3"` |
| `max_redirects` | int | 10 | Max redirects to follow (max: 20) |
| `flush_interval` | duration | 0 | Streaming flush interval |
| `idle_conn_timeout` | duration | 60s | Idle connection timeout |
| `tls_handshake_timeout` | duration | 10s | TLS handshake timeout |
| `dial_timeout` | duration | 10s | TCP dial timeout |
| `keep_alive` | duration | 30s | TCP keep-alive interval |
| `max_connections` | int | 0 | Max concurrent connections (max: 10000) |
| `max_idle_conns` | int | 0 | Max idle connections across all hosts |
| `max_idle_conns_per_host` | int | 0 | Max idle connections per host |
| `rate_limit` | int | 0 | Outbound requests per second |
| `burst_limit` | int | 0 | Outbound burst limit |
| `mtls_client_cert_file` | string | `""` | Client certificate for mTLS to backend |
| `mtls_client_key_file` | string | `""` | Client private key for mTLS to backend |
| `mtls_ca_cert_file` | string | `""` | CA certificate for verifying backend |
| `certificate_pinning` | object | — | TLS certificate pinning config |
| `transport_wrappers` | object | — | Retry, hedging, and health check wrappers |

```yaml
action:
  type: proxy
  url: https://test.sbproxy.dev
  timeout: 30s
  strip_base_path: false
```

### 3.2 `redirect` - HTTP Redirect

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"redirect"` |
| `url` | string | — | Redirect destination URL |
| `status_code` | int | 302 | HTTP redirect status (e.g. 301, 302, 307, 308) |
| `strip_base_path` | bool | false | Ignore base path of destination URL |
| `preserve_query` | bool | false | Preserve original query string |

```yaml
action:
  type: redirect
  url: https://www.example.com
  status_code: 301
  preserve_query: true
```

### 3.3 `static` - Static Response

Returns a fixed HTTP response without contacting any backend.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"static"` |
| `status_code` | int | 200 | HTTP status code |
| `content_type` | string | `""` | Content-Type header |
| `headers` | map[string]string | — | Additional response headers |
| `body` | string | `""` | Response body (plain text) |
| `body_base64` | string | `""` | Response body as base64-encoded bytes |
| `json_body` | object | — | Response body as inline JSON |

```yaml
action:
  type: static
  status_code: 200
  content_type: application/json
  json_body:
    status: ok
    service: api.example.com
```

### 3.4 `storage` - Cloud Storage

Serves files from S3, GCS, or other object storage backends.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"storage"` |
| `kind` | string | — | Storage provider: `s3`, `gcs`, `azure`, `swift` |
| `bucket` | string | — | Bucket/container name |
| `key` | string | `""` | Access key / credentials |
| `secret` | string | `""` | Secret key |
| `region` | string | `""` | Cloud region |
| `project_id` | string | `""` | GCS project ID |
| `account` | string | `""` | Azure storage account |
| `conn_cache_duration` | duration | 0 | Connection cache TTL (max: 24h) |

### 3.5 `loadbalancer` - Load Balancer

Distributes traffic across multiple upstream targets.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"loadbalancer"` |
| `targets` | []Target | — | Upstream targets (required) |
| `algorithm` | string | `"weighted_random"` | LB algorithm (see below) |
| `hash_key` | string | `""` | Header or cookie name for `header_hash` / `cookie_hash` |
| `disable_sticky` | bool | false | Disable sticky sessions |
| `sticky_cookie_name` | string | `""` | Custom sticky session cookie name |
| `strip_base_path` | bool | false | Strip URL base path |
| `preserve_query` | bool | false | Preserve URL query params |
| `discovery` | object | — | Dynamic backend discovery config |

**Algorithms:** `weighted_random`, `round_robin`, `weighted_round_robin`, `least_connections`, `ip_hash`, `uri_hash`, `header_hash`, `cookie_hash`, `random`, `first`

**Target fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | — | Backend URL |
| `weight` | int | 1 | Relative weight for weighted algorithms |
| `health_check` | object | — | Per-target health check config |
| `circuit_breaker` | object | — | Per-target circuit breaker config |
| `request_modifiers` | []object | — | Per-target request modifications |
| `response_modifiers` | []object | — | Per-target response modifications |
| `request_matchers` | []object | — | Match conditions for this target |

**HealthCheckConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable health checks |
| `interval` | duration | 10s | Check frequency |
| `timeout` | duration | 5s | Check timeout |
| `path` | string | `"/"` | HTTP path to check |
| `method` | string | `"GET"` | HTTP method |
| `expected_status` | []int | [200-299] | Acceptable response codes |
| `healthy_threshold` | int | 2 | Consecutive successes to mark healthy |
| `unhealthy_threshold` | int | 2 | Consecutive failures to mark unhealthy |

**CircuitBreakerConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable circuit breaker |
| `failure_threshold` | int | 5 | Failures before opening circuit |
| `success_threshold` | int | 2 | Successes to close from half-open |
| `request_volume_threshold` | int | 10 | Minimum requests before evaluating |
| `timeout` | duration | 30s | How long circuit stays open |
| `error_rate_threshold` | float64 | 50.0 | Error rate % to open circuit |
| `half_open_requests` | int | 3 | Test requests in half-open state |

**DNS SRV Discovery (`discovery`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"dns_srv"` |
| `service` | string | — | SRV service name (e.g. `_http._tcp.api.example.com`) |
| `refresh_interval` | string | `"30s"` | Re-resolution interval |
| `resolver` | string | `""` | Custom DNS resolver address |

```yaml
action:
  type: loadbalancer
  algorithm: round_robin
  targets:
    - url: https://backend-1.test.sbproxy.dev
      weight: 2
      health_check:
        enabled: true
        path: /health
        interval: 10s
      circuit_breaker:
        enabled: true
        failure_threshold: 5
        timeout: 30s
    - url: https://backend-2.test.sbproxy.dev
      weight: 1
```

### 3.6 `graphql` - GraphQL Proxy

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"graphql"` |
| `url` | string | — | Backend GraphQL URL |
| `max_depth` | int | 10 | Maximum query nesting depth (max: 50) |
| `max_complexity` | int | 100 | Maximum query complexity (max: 10000) |
| `max_cost` | int | 1000 | Maximum query cost (max: 100000) |
| `max_aliases` | int | 10 | Maximum aliased fields (max: 100) |
| `enable_introspection` | bool | false | Allow introspection queries |
| `persistent_queries` | bool | false | Enable persistent queries |
| `automatic_persisted_queries` | bool | false | Enable APQ (Apollo spec) |
| `enable_query_batching` | bool | false | Enable query batching |
| `enable_query_deduplication` | bool | false | Deduplicate identical concurrent queries |
| `enable_result_caching` | bool | false | Cache query results |
| `result_cache_ttl` | duration | 5m | Result cache TTL (max: 24h) |
| `result_cache_size` | int | 1000 | Result cache entry count (max: 100000) |

### 3.7 `websocket` - WebSocket Proxy

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"websocket"` |
| `url` | string | — | Backend WebSocket URL (`ws://` or `wss://`) |
| `strip_base_path` | bool | false | Strip URL base path |
| `preserve_query` | bool | false | Preserve URL query params |
| `ping_interval` | duration | 0 | Send ping frames (0 = disabled) |
| `pong_timeout` | duration | 10s | Pong response timeout |
| `idle_timeout` | duration | 0 | Close idle connections after this duration |
| `max_frame_size` | int | 0 | Maximum frame payload size |
| `enable_compression` | bool | false | Enable per-message compression |
| `handshake_timeout` | duration | 10s | WebSocket handshake timeout |
| `subprotocols` | []string | — | Supported subprotocols |
| `allowed_origins` | []string | — | Allowed CORS origins (empty = all) |
| `check_origin` | bool | false | Validate Origin header |
| `enable_rfc8441` | bool | false | Enable WebSocket over HTTP/2 |
| `pool_max_connections` | int | 100 | Max pooled connections (max: 1000) |
| `disable_pool` | bool | false | Disable connection pooling |

### 3.8 `grpc` - gRPC Proxy

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"grpc"` |
| `url` | string | — | Backend gRPC URL (e.g. `grpc://host:50051`) |
| `strip_base_path` | bool | true | Strip URL base path |
| `preserve_query` | bool | true | Preserve URL query params |
| `enable_grpc_web` | bool | false | Enable gRPC-Web protocol support |
| `forward_metadata` | bool | true | Forward gRPC metadata headers |
| `max_call_recv_msg_size` | int | 4MB | Maximum receive message size |
| `max_call_send_msg_size` | int | 4MB | Maximum send message size |

### 3.9 `ai_proxy` - AI Gateway

OpenAI-compatible API gateway with multi-provider routing.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"ai_proxy"` |
| `providers` | []ProviderConfig | — | Upstream LLM providers (required) |
| `default_model` | string | `""` | Model used when request omits one |
| `timeout` | duration | 30s | Provider request timeout (max: 5m) |
| `routing` | object | — | Routing strategy config |
| `budget` | object | — | Cost and token limits |
| `guardrails` | object | — | Safety guardrail pipeline |
| `allowed_models` | []string | — | Whitelist of allowed models |
| `blocked_models` | []string | — | Blocked model names |
| `allowed_providers` | []string | — | Allowed provider names |
| `blocked_providers` | []string | — | Blocked provider names |
| `gateway` | bool | false | Enable unified model registry mode |
| `model_registry` | []object | — | Model-to-provider mapping for gateway mode |
| `zero_data_retention` | bool | false | Suppress memory and sensitive log fields |
| `drop_unsupported_params` | bool | false | Remove params unsupported by selected model |
| `failure_mode` | string | `"open"` | Default subsystem failure behavior: `open` or `closed` |
| `skip_tls_verify_host` | bool | false | Disable TLS for provider connections |
| `max_request_body_size` | int64 | 10MB | Maximum request body size |

**ProviderConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | — | Logical provider name |
| `type` | string | name | Provider type (e.g. `openai`, `anthropic`, `gemini`) |
| `api_key` | string | `""` | Provider API key |
| `base_url` | string | `""` | Override provider base URL |
| `models` | []string | — | Models this provider serves |
| `model_map` | map[string]string | — | Map incoming model names to provider model names |
| `weight` | int | 1 | Weight for weighted routing |
| `priority` | int | 0 | Priority for fallback routing |
| `timeout` | duration | 30s | Per-provider timeout |
| `max_retries` | int | 0 | Provider-level retry count |
| `format` | string | `"openai"` | Wire format: `openai`, `anthropic`, `passthrough` |
| `auth_header` | string | `""` | Custom auth header name |
| `max_tokens_per_minute` | int | 0 | TPM rate limit |
| `max_requests_per_minute` | int | 0 | RPM rate limit |

**RoutingConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `strategy` | string | `"round_robin"` | `round_robin`, `weighted`, `lowest_latency`, `cost_optimized`, `fallback_chain`, `least_connections`, `token_rate`, `sticky`, `semantic` |
| `fallback_order` | []string | — | Provider names in priority order |
| `model_selector` | string | `""` | CEL expression returning model name override |
| `provider_selector` | string | `""` | CEL expression returning preferred provider |

**BudgetConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `limits` | []BudgetLimit | — | Budget constraints |
| `on_exceed` | string | `"block"` | Action: `block`, `log`, `downgrade` |
| `alert_threshold_pct` | int | 80 | Alert at this % of budget |
| `downgrade_map` | map[string]string | — | Model -> cheaper model for downgrade action |

**BudgetLimit:**

| Field | Type | Default | Description |
|---|---|---|---|
| `scope` | string | — | `workspace`, `api_key`, `user`, `model`, `origin`, `tag:<key>` |
| `max_cost_usd` | float64 | 0 | Maximum spend in USD |
| `max_tokens` | int64 | 0 | Maximum token usage |
| `period` | string | — | `hourly`, `daily`, `weekly`, `monthly` |

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
      models: [gpt-4o, gpt-4o-mini]
    - name: anthropic
      api_key: ${ANTHROPIC_API_KEY}
      models: [claude-3-5-sonnet-20241022]
  default_model: gpt-4o-mini
  routing:
    strategy: fallback_chain
    fallback_order: [openai, anthropic]
  budget:
    limits:
      - scope: workspace
        max_cost_usd: 100.00
        period: monthly
    on_exceed: block
```

### 3.10 `mcp` - MCP Server

Exposes an MCP (Model Context Protocol) server for AI agent tool use.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"mcp"` |
| `mode` | string | `"orchestrator"` | `orchestrator` or `gateway` |
| `server_info` | object | — | Server name and version |
| `capabilities` | object | — | Advertised MCP capabilities |
| `tools` | []object | — | Tool definitions |
| `resources` | []object | — | Resource definitions |
| `prompts` | []object | — | Prompt definitions |
| `federated_servers` | []object | — | Upstream MCP servers to federate |
| `default_timeout` | duration | 30s | Tool execution timeout (max: 5m) |

### 3.11 `a2a` - Agent-to-Agent

Implements Google's Agent-to-Agent (A2A) protocol for inter-agent communication.

### 3.12 `mock` - Mock Response

Returns a synthetic response for testing and development.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"mock"` |
| `status_code` | int | 200 | HTTP status code |
| `headers` | map[string]string | — | Response headers |
| `body` | string | `""` | Response body |
| `delay` | duration | 0 | Simulated response delay (max: 30s) |

### 3.13 `echo` - Echo Server

Returns request details as JSON response. Useful for debugging.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"echo"` |
| `include_context` | bool | false | Include proxy context in response |

### 3.14 `beacon` - Tracking Pixel

Returns a 1x1 transparent GIF or static response.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"beacon"` |
| `empty_gif` | bool | false | Return a 1x1 transparent GIF |
| (inherits StaticConfig fields) | | | |

### 3.15 `noop` - No-op

Accepts requests and returns 200 OK with no body.

### Transport Wrappers (`transport_wrappers`)

Applies to `proxy`, `loadbalancer`, and similar connection-based actions.

| Field | Type | Default | Description |
|---|---|---|---|
| `retry` | object | — | Automatic retry configuration |
| `hedging` | object | — | Request hedging configuration |
| `health_check` | object | — | Transport-level health checking |

**RetryConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable retries |
| `max_retries` | int | 3 | Maximum retry attempts (max: 10) |
| `initial_delay` | duration | 100ms | Delay before first retry |
| `max_delay` | duration | 10s | Maximum delay between retries |
| `multiplier` | float64 | 2.0 | Exponential backoff multiplier |
| `jitter` | float64 | 0.1 | Jitter factor (0.0 - 1.0) |
| `retryable_status` | []int | [502,503,504,429] | Status codes that trigger retry |

---

## 4. Authentication Types

The `authentication` block at the origin level. Only one auth type per origin.

### 4.1 `api_key`

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"api_key"` |
| `api_keys` | []string | — | Valid API key values |
| `api_keys_callback` | object | — | Callback to fetch valid keys dynamically |
| `disabled` | bool | false | Disable authentication |

Keys are accepted from the `X-API-Key` header by default. To accept from a different header or query param, use `request_modifiers` to rewrite first.

```yaml
authentication:
  type: api_key
  api_keys:
    - secret-key-1
    - ${API_KEY_FROM_ENV}
```

### 4.2 `basic_auth`

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"basic_auth"` |
| `users` | []BasicAuthUser | — | User list with username and password |
| `users_callback` | object | — | Callback to fetch users dynamically |

**BasicAuthUser:**

| Field | Type | Description |
|---|---|---|
| `username` | string | Username |
| `password` | string | Password (plaintext or bcrypt hash) |

```yaml
authentication:
  type: basic_auth
  users:
    - username: alice
      password: secret123
```

### 4.3 `bearer_token`

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"bearer_token"` |
| `tokens` | []string | — | Valid bearer token values |
| `tokens_callback` | object | — | Callback to fetch tokens dynamically |

### 4.4 `jwt`

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"jwt"` |
| `secret` | string | `""` | HMAC signing secret |
| `public_key` | string | `""` | Base64 RSA/ECDSA public key |
| `jwks_url` | string | `""` | URL to fetch JWKS from |
| `jwks_cache_duration` | duration | 1h | JWKS cache TTL (max: 24h) |
| `issuer` | string | `""` | Expected `iss` claim |
| `audience` | string | `""` | Expected `aud` claim |
| `algorithm` | string | `"RS256"` | Signing algorithm |
| `header_name` | string | `"Authorization"` | Header to extract token from |
| `header_prefix` | string | `"Bearer "` | Prefix to strip from header value |
| `cookie_name` | string | `""` | Extract token from cookie |
| `query_param` | string | `""` | Extract token from query param |
| `cache_duration` | duration | 0 | Cache validated tokens (max: 24h) |

```yaml
authentication:
  type: jwt
  jwks_url: https://auth.example.com/.well-known/jwks.json
  issuer: https://auth.example.com
  audience: api.example.com
```

### 4.5 `forward`

Delegates authentication to an external service via subrequest.

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"forward"` |
| `url` | string | — | External auth service URL |
| `method` | string | `"GET"` | HTTP method for subrequest |
| `trust_headers` | []string | — | Headers from auth response to inject |
| `forward_headers` | []string | — | Headers to forward from original request |
| `forward_body` | bool | false | Forward request body to auth service |
| `cache_duration` | duration | 0 | Cache positive auth responses |
| `cache_key` | string | `""` | Cache key template |
| `success_status` | []int | [200] | Status codes considered successful |
| `timeout` | duration | 5s | Auth subrequest timeout |

### 4.6 `digest`

HTTP Digest Authentication (RFC 7616).

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"digest"` |
| `users` | []BasicAuthUser | — | Username and password list |

### 4.7 `grpc_auth`

gRPC external authorization (Envoy ext_authz compatible).

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"grpc_auth"` |
| `address` | string | — | gRPC auth server address (host:port) |
| `timeout` | duration | 5s | Auth call timeout |
| `tls` | bool | false | Use TLS |
| `tls_ca_cert` | string | `""` | CA certificate for TLS |
| `fail_open` | bool | false | Allow requests when auth server is down |
| `trust_headers` | []string | — | Headers from auth response to inject |

---

## 5. Policy Types

Policies are listed under `policies:` as an ordered array. They execute after authentication.

Every policy includes:

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | Policy type name |
| `disabled` | bool | false | Disable this policy |
| `match` | object | — | Conditional match (CEL or request rules) |

### 5.1 `waf` - Web Application Firewall

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"waf"` |
| `owasp_crs` | object | — | OWASP Core Rule Set config |
| `custom_rules` | []object | — | Custom WAF rules |
| `modsecurity_rules` | []string | — | Raw ModSecurity rule strings |
| `rule_sets` | []string | — | Named rule sets to load |
| `default_action` | string | `"log"` | Default action: `block`, `log`, `pass` |
| `action_on_match` | string | `"block"` | Action when a rule matches |
| `test_mode` | bool | false | Log but do not block |
| `fail_open` | bool | false | Allow requests on WAF evaluation errors |

**OWASPCRSConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable OWASP CRS |
| `paranoia_level` | int | 1 | Rule paranoia level (1-4) |

```yaml
policies:
  - type: waf
    owasp_crs:
      enabled: true
      paranoia_level: 1
    action_on_match: block
    fail_open: false
```

### 5.2 `ddos_protection` - DDoS Protection

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"ddos_protection"` |
| `detection` | object | — | Detection thresholds |
| `mitigation` | object | — | Mitigation actions |

**DDoSDetectionConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `request_rate_threshold` | int | 0 | Requests per detection window to trigger |
| `connection_rate_threshold` | int | 0 | Connections per window to trigger |
| `bandwidth_threshold` | string | `""` | Bandwidth threshold (e.g. `"100MB"`) |
| `detection_window` | string | `"10s"` | Detection time window |
| `adaptive_thresholds` | bool | false | Use baseline-relative thresholds |
| `baseline_window` | string | `""` | Window for baseline calculation |
| `threshold_multiplier` | float64 | 2.0 | Multiplier above baseline |

**DDoSMitigationConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `block_duration` | string | `""` | How long to block attackers |
| `challenge_response` | bool | false | Enable challenge-response |
| `challenge_type` | string | `"header"` | `header`, `proof_of_work`, `javascript`, `captcha` |
| `auto_block` | bool | false | Automatically block attacker IPs |
| `block_after_attacks` | int | 3 | Attack count before auto-block |

### 5.3 `rate_limiting` - Rate Limiting

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"rate_limiting"` |
| `algorithm` | string | `"sliding_window"` | `sliding_window`, `token_bucket`, `leaky_bucket`, `fixed_window` |
| `requests_per_minute` | int | 0 | RPM limit |
| `requests_per_hour` | int | 0 | RPH limit |
| `requests_per_day` | int | 0 | RPD limit |
| `burst_size` | int | 0 | Allowed burst capacity |
| `refill_rate` | float64 | 0 | Tokens/sec for token bucket |
| `whitelist` | []string | — | IPs/CIDRs that bypass rate limiting |
| `blacklist` | []string | — | IPs/CIDRs that are always blocked |
| `custom_limits` | map | — | IP-specific limits |
| `endpoint_limits` | map | — | Path-pattern-specific limits |
| `headers` | object | — | Rate limit response header configuration |
| `throttle` | object | — | Queue-based throttling instead of 429 |
| `quota` | object | — | Per-consumer daily/monthly quotas |

**RateLimitHeadersConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Add `X-RateLimit-*` headers |
| `include_limit` | bool | false | Include `X-RateLimit-Limit` |
| `include_remaining` | bool | false | Include `X-RateLimit-Remaining` |
| `include_reset` | bool | false | Include `X-RateLimit-Reset` |
| `include_retry_after` | bool | false | Include `Retry-After` on 429 |
| `reset_format` | string | `"delta_seconds"` | `delta_seconds` or `unix_timestamp` |
| `header_prefix` | string | `"X-RateLimit"` | Header prefix |

**ThrottleConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Queue excess requests instead of 429 |
| `max_queue` | int | 100 | Max queued requests |
| `max_wait` | duration | 5s | Max time to wait in queue |

```yaml
policies:
  - type: rate_limiting
    algorithm: sliding_window
    requests_per_minute: 60
    burst_size: 10
    headers:
      enabled: true
      include_limit: true
      include_remaining: true
      include_retry_after: true
```

### 5.4 `ip_filtering` - IP Filtering

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"ip_filtering"` |
| `whitelist` | []string | — | Allowed IPs/CIDRs |
| `blacklist` | []string | — | Blocked IPs/CIDRs |
| `action` | string | `"block"` | Default action: `allow` or `block` |
| `temporary_bans` | map | — | IP -> duration for temporary bans |
| `trusted_proxy_cidrs` | []string | — | CIDRs trusted to set `X-Forwarded-For` |
| `blocklist_ttl` | duration | 24h | Dynamic blocklist cache TTL (max: 30d) |

```yaml
policies:
  - type: ip_filtering
    whitelist:
      - 10.0.0.0/8
      - 192.168.0.0/16
    trusted_proxy_cidrs:
      - 10.0.0.0/8
```

### 5.5 `csrf` - CSRF Protection

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"csrf"` |
| `secret` | string | — | Signing secret (required) |
| `cookie_name` | string | `"_csrf"` | CSRF cookie name |
| `cookie_same_site` | string | `"Lax"` | `Strict`, `Lax`, `None` |
| `header_name` | string | `"X-CSRF-Token"` | Header for AJAX requests |
| `form_field_name` | string | `"_csrf"` | Form field name |
| `token_length` | int | 32 | Token length in bytes |
| `methods` | []string | POST,PUT,DELETE,PATCH | Methods to protect |
| `exempt_paths` | []string | — | Paths exempt from CSRF checks |

### 5.6 `security_headers` - Security Headers

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"security_headers"` |
| `headers` | []object | none | List of `{name, value}` response headers to set (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-* etc.) |
| `content_security_policy` | object | none | Advanced CSP block (nonce injection, report-only, per-route policies) |

**CSPConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `policy` | string | `""` | Base CSP policy string |
| `enable_nonce` | bool | false | Inject per-request nonce in `script-src`/`style-src` |
| `report_only` | bool | false | Use `Content-Security-Policy-Report-Only` |
| `report_uri` | string | `""` | Violation report endpoint |
| `dynamic_routes` | map | none | Route-prefix to override CSP policy |

```yaml
policies:
  - type: security_headers
    headers:
      - name: Strict-Transport-Security
        value: "max-age=31536000; includeSubDomains"
      - name: X-Frame-Options
        value: DENY
      - name: X-Content-Type-Options
        value: nosniff
      - name: Referrer-Policy
        value: strict-origin-when-cross-origin
      - name: Permissions-Policy
        value: "camera=()"
    # Optional: detailed CSP block for nonce / dynamic routes only.
    content_security_policy:
      policy: "default-src 'self'"
      enable_nonce: false     # true to inject per-request nonce in script-src/style-src
      report_only: false
      report_uri: ""
      # dynamic_routes:
      #   "/admin":
      #     policy: "default-src 'self' admin.example.com"
```

### 5.7 `request_limiting` - Request Size Limiting

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"request_limiting"` |
| `size_limits` | object | — | URL, header, and body size limits |
| `complexity_limits` | object | — | JSON/query complexity limits |
| `protection` | object | — | Slowloris/slow read protection |

**SizeLimitsConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `max_url_length` | int | 0 | Maximum URL length in bytes |
| `max_query_string_length` | int | 0 | Maximum query string length |
| `max_headers_count` | int | 0 | Maximum number of request headers |
| `max_header_size` | string | `""` | Maximum header size (e.g. `"10KB"`) |
| `max_request_size` | string | `""` | Maximum request body size (e.g. `"10MB"`) |

### 5.8 `sri` - Subresource Integrity

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"sri"` |
| `validate_responses` | bool | false | Validate SRI hashes in responses |
| `fail_on_missing_integrity` | bool | false | Reject resources without integrity attributes |
| `fail_on_invalid_integrity` | bool | false | Reject resources with invalid hashes |
| `known_hashes` | map | — | URL -> list of valid hash strings |
| `algorithm` | string | `"sha384"` | Hash algorithm: `sha256`, `sha384`, `sha512` |

### 5.9 `expression` - CEL/Lua Policy

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | `"expression"` |
| `cel_expr` | string | `""` | CEL expression returning bool (true = block) |
| `lua_script` | string | `""` | Lua script returning bool (true = block) |
| `status_code` | int | 403 | HTTP status code when expression triggers |

```yaml
policies:
  - type: expression
    cel_expr: |
      !(request.headers.x_role == "admin" || request.headers.x_role == "editor")
    status_code: 403
```

---

## 6. Transform Types

Transforms are listed under `transforms:` as an ordered array. They modify request or response bodies.

Every transform includes:

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | — | Transform type name |
| `content_types` | []string | — | Only apply to these content types |
| `fail_on_error` | bool | false | Return 500 if transform fails |
| `disabled` | bool | false | Disable this transform |
| `max_body_size` | int64 | 10MB | Max body size to process (-1 = unlimited) |
| `request_matcher` | object | — | Conditional: only apply when request matches |
| `response_matcher` | object | — | Conditional: only apply when response matches |

### 6.1 `json` - JSON Cleanup

| Field | Type | Default | Description |
|---|---|---|---|
| `remove_empty_objects` | bool | false | Strip `{}` values |
| `remove_empty_arrays` | bool | false | Strip `[]` values |
| `remove_false_booleans` | bool | false | Strip `false` values |
| `remove_empty_strings` | bool | false | Strip `""` values |
| `remove_zero_numbers` | bool | false | Strip `0` numeric values |
| `pretty_print` | bool | false | Pretty-print output |
| `rules` | []JSONRule | — | Set specific JSON paths to values |

### 6.2 `json_projection` - JSON Field Filtering

| Field | Type | Default | Description |
|---|---|---|---|
| `include` | []string | — | Fields to keep (gjson paths) |
| `exclude` | []string | — | Fields to remove (gjson paths) |
| `flatten` | bool | false | Flatten nested structure |

### 6.3 `json_schema` - JSON Schema Validation

| Field | Type | Default | Description |
|---|---|---|---|
| `schema` | object | — | Inline JSON Schema |
| `action` | string | `"validate"` | `validate` (reject 400), `warn` (log), `strip` |

### 6.4 `html` - HTML Transformation

| Field | Type | Default | Description |
|---|---|---|---|
| `format_options` | object | — | HTML formatting options |
| `attribute_options` | object | — | HTML attribute options |
| `add_to_tags` | []AddToTagConfig | — | Inject content into HTML tags |

### 6.5 `optimize_html` - HTML Optimization

| Field | Type | Default | Description |
|---|---|---|---|
| `format_options` | object | — | Minification options |
| `add_to_tags` | []AddToTagConfig | — | Inject content before/after tags |

**AddToTagConfig:**

| Field | Type | Default | Description |
|---|---|---|---|
| `tag` | string | — | Tag name (e.g. `head`, `body`) |
| `add_before_end_tag` | bool | null | `true` = before `</tag>`, null/false = after `<tag>` |
| `content` | string | — | HTML content to inject |

### 6.6 `css` - CSS Transformation

| Field | Type | Default | Description |
|---|---|---|---|
| `precision` | int | 0 | Decimal precision for numeric values |
| `inline` | bool | false | Process inline styles |
| `version` | int | 0 | CSS specification version |

### 6.7 `javascript` - JavaScript Transformation

| Field | Type | Default | Description |
|---|---|---|---|
| `number_precision` | int | 0 | Numeric precision |
| `change_variable_names` | bool | false | Rename variables |
| `supported_version` | int | 0 | JS version level |

### 6.8 `markdown` - Markdown to HTML

| Field | Type | Default | Description |
|---|---|---|---|
| `sanitize` | bool | false | Sanitize output HTML |
| `disable_tables` | bool | false | Disable table rendering |
| `disable_fenced_code` | bool | false | Disable code blocks |
| `skip_html` | bool | false | Strip HTML tags |
| `nofollow` | bool | false | Add `rel="nofollow"` to links |
| `href_target_blank` | bool | false | Add `target="_blank"` to links |

### 6.9 `html_to_markdown` - HTML to Markdown

Converts HTML response bodies to Markdown.

### 6.10 `template` - Template Rendering

| Field | Type | Default | Description |
|---|---|---|---|
| `template` | string | — | Mustache/Go template string |
| `data` | any | — | Static data passed to template |

### 6.11 `encoding` - Encoding Transform

Encode or decode body content (base64, etc.).

### 6.12 `format_convert` - Format Conversion

| Field | Type | Default | Description |
|---|---|---|---|
| `from` | string | — | Source format: `xml`, `csv`, `yaml` |
| `to` | string | — | Target format: `json` |

### 6.13 `replace_strings` - String Replacement

| Field | Type | Default | Description |
|---|---|---|---|
| `replace_strings` | object | — | Replacement configuration |

**ReplaceStrings:**

| Field | Type | Default | Description |
|---|---|---|---|
| `replacements` | []ReplaceString | — | List of replacement rules |

**ReplaceString:**

| Field | Type | Default | Description |
|---|---|---|---|
| `find` | string | — | String to find |
| `replace` | string | — | Replacement string |
| `regex` | bool | false | Treat `find` as regex |
| `cel_expr` | string | `""` | CEL expression for dynamic replacement |
| `lua_script` | string | `""` | Lua script for dynamic replacement |

### 6.14 `payload_limit` - Payload Size Enforcement

| Field | Type | Default | Description |
|---|---|---|---|
| `max_size` | int64 | — | Maximum body size in bytes |
| `action` | string | `"reject"` | `truncate`, `reject` (413), `warn` |

### 6.15 `normalize` - URL/Path Normalization

Normalizes URI encoding and path structure.

### 6.16 `discard` - Body Discard

| Field | Type | Default | Description |
|---|---|---|---|
| `bytes` | int | — | Number of bytes to discard from body start |

### 6.17 `sse_chunking` - SSE Stream Processing

Processes Server-Sent Events from LLM streaming APIs.

| Field | Type | Default | Description |
|---|---|---|---|
| `provider` | string | `""` | Provider hint: `openai`, `anthropic` |
| `filter_events` | []string | — | Event types to filter out |
| `buffer_chunks` | int | 0 | Number of chunks to buffer |

### 6.18 `lua_json` - Lua JSON Transform

| Field | Type | Default | Description |
|---|---|---|---|
| `lua_script` | string | — | Lua script defining `modify_json(data, ctx)` |
| `timeout` | duration | 100ms | Script execution timeout (max: 10s) |

```yaml
transforms:
  - type: lua_json
    content_types: [application/json]
    timeout: 200ms
    lua_script: |
      function modify_json(data, ctx)
        data.processed_by = "sbproxy"
        return data
      end
```

---

## 7. Response Cache (`response_cache`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable caching |
| `ttl` | duration | — | Cache entry TTL |
| `cache_key` | string | `""` | Cache key strategy |
| `vary_by` | []string | — | Headers to vary cache key by |
| `ignore_no_cache` | bool | false | Cache even when `Cache-Control: no-cache` |
| `cache_private` | bool | false | Cache `Cache-Control: private` responses |
| `store_non_200` | bool | false | Cache non-200 responses |
| `stale_while_revalidate` | object | — | SWR configuration |
| `key_normalization` | object | — | Cache key normalization rules |
| `conditions` | object | — | Cache conditions |
| `invalidation` | object | — | Cache invalidation rules |

**CacheConditions:**

| Field | Type | Default | Description |
|---|---|---|---|
| `status_codes` | []int | — | Cacheable status codes |
| `methods` | []string | — | Cacheable HTTP methods |
| `min_size` | int | 0 | Minimum response size to cache (bytes) |
| `max_size` | int | 0 | Maximum response size to cache (bytes) |

**StaleWhileRevalidate:**

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable stale-while-revalidate |
| `duration` | duration | — | How long to serve stale while revalidating |
| `stale_if_error` | duration | — | Serve stale on backend error |
| `max_age` | duration | — | Max age before stale cannot be served |
| `async_revalidate` | bool | true | Revalidate in background |

```yaml
response_cache:
  enabled: true
  ttl: 60s
  conditions:
    methods: [GET, HEAD]
    status_codes: [200, 301, 404]
  stale_while_revalidate:
    enabled: true
    duration: 10s
    stale_if_error: 60s
```

---

## 8. Request and Response Modifiers

### RequestModifier

Each entry in `request_modifiers:` can have:

| Field | Type | Description |
|---|---|---|
| `url` | object | URL modifications |
| `method` | string | Override HTTP method |
| `headers` | object | Header modifications |
| `query` | object | Query parameter modifications |
| `body` | object | Body modifications |
| `form` | object | Form field modifications |
| `lua_script` | string | Lua modifier script |
| `rules` | []object | Apply only when these request rules match |

**HeaderModifications:**

| Field | Type | Description |
|---|---|---|
| `set` | map[string]string | Set header to value (overwrites) |
| `add` | map[string]string | Add header value (appends) |
| `delete` | []string | Remove headers by name |

**QueryModifications:**

| Field | Type | Description |
|---|---|---|
| `set` | map[string]string | Set query param (overwrites) |
| `add` | map[string]string | Add query param (appends) |
| `delete` | []string | Remove params by name |

**URLModifications:**

| Field | Type | Description |
|---|---|---|
| `set` | string | Set entire URL |
| `scheme` | string | Override scheme |
| `host` | string | Override host |
| `path` | object | Path modifications |

**BodyModifications:**

| Field | Type | Description |
|---|---|---|
| `remove` | bool | Remove the body |
| `replace` | string | Replace with string |
| `replace_json` | object | Replace with JSON object |
| `replace_base64` | string | Replace with base64-decoded bytes |

```yaml
request_modifiers:
  - headers:
      set:
        X-Forwarded-By: sbproxy
        X-Origin-Host: api.example.com
      delete:
        - X-Internal-Token
  - rules:
      - path:
          prefix: /api/
    query:
      set:
        version: "2"
```

### ResponseModifier

Each entry in `response_modifiers:` can have:

| Field | Type | Description |
|---|---|---|
| `status` | object | Status code modification |
| `headers` | object | Header modifications |
| `body` | object | Body modifications |
| `lua_script` | string | Lua modifier script |
| `rules` | []object | Apply only when response rules match |

**StatusModifications:**

| Field | Type | Description |
|---|---|---|
| `code` | int | Override status code |
| `text` | string | Override status text |

```yaml
response_modifiers:
  - headers:
      set:
        X-Powered-By: sbproxy
      delete:
        - Server
        - X-Generator
  - rules:
      - status: [404]
    status:
      code: 200
```

---

## 9. Forward Rules (`forward_rules`)

Route requests to a different origin based on request matching.

| Field | Type | Description |
|---|---|---|
| `hostname` | string | Target origin hostname |
| `origin` | object | Inline embedded origin config (alternative to hostname) |
| `rules` | []RequestRule | Match conditions (empty = always match) |

```yaml
forward_rules:
  - rules:
      - path:
          exact: /health
    origin:
      id: health-check
      hostname: health-check
      workspace_id: default
      version: "1.0.0"
      action:
        type: static
        status_code: 200
        json_body: {status: ok}

  - rules:
      - path:
          prefix: /api/v2/
    hostname: api-v2.example.com
```

---

## 10. Session Config (`session`)

| Field | Type | Default | Description |
|---|---|---|---|
| `disabled` | bool | false | Disable session management |
| `cookie_name` | string | `""` | Session cookie name |
| `max_age` | int | 0 | Session cookie max age in seconds |
| `same_site` | string | `""` | `Strict`, `Lax`, `None` |
| `disable_http_only` | bool | false | Remove HttpOnly flag from cookie |
| `allow_non_ssl` | bool | false | Allow sessions over HTTP |
| `enable_cookie_jar` | bool | false | Proxy backend Set-Cookie headers via session |
| `cookie_jar_config` | object | — | Cookie jar settings |
| `on_session_start` | []object | — | Callbacks on session start |

---

## 11. Error Pages (`error_pages`)

| Field | Type | Default | Description |
|---|---|---|---|
| `status` | []int | — | Status codes this page applies to (empty = all 4xx/5xx) |
| `body` | string | `""` | Response body |
| `body_base64` | string | `""` | Base64-encoded response body |
| `json_body` | object | — | JSON response body |
| `content_type` | string | `""` | Response content type |
| `headers` | map | — | Additional response headers |
| `status_code` | int | 0 | Override HTTP status code |
| `template` | bool | false | Render body as Mustache template |
| `callback` | object | — | Fetch error page from external URL |

Template variables: `status_code`, `error`, `request.url`, `request.method`, `request.headers`.

```yaml
error_pages:
  - status: [401, 403]
    content_type: application/json
    template: true
    body: |
      {"error": true, "status": {{ status_code }}, "message": "{{ error }}"}

  - status: [429]
    content_type: application/json
    body: |
      {"error": true, "message": "Rate limit exceeded"}
```

---

## 12. Variables and Secrets

### Variables (`variables`)

User-defined key-value data available in templates as `{{ variables.name }}`.

```yaml
variables:
  api_version: "v2"
  environment: production
  config:
    region: us-east-1
```

### Secrets (`secrets`)

Secrets reference external vaults. New format uses `vault:path` references.

```yaml
vaults:
  env:
    type: env              # Read from environment variables

secrets:
  api_key: "env:MY_API_KEY"
  db_password: "env:DB_PASSWORD"
```

Secrets are available in templates as `{{ secrets.api_key }}`.

### Vault Types

| Type | Description |
|---|---|
| `env` | Environment variables |
| `file` | JSON or YAML file on disk |
| `hashicorp` | HashiCorp Vault via HTTP API |
| `local` | Inline key-value in config |

```yaml
vaults:
  prod-vault:
    type: hashicorp
    address: https://vault.example.com
    token: ${VAULT_TOKEN}
    path_prefix: secret/data/myapp
```

---

## 13. Compression (`compression`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | false | Enable response compression |
| `algorithms` | []string | `["gzip","br"]` | Algorithms in preference order (`gzip`, `br`, `zstd`) |
| `min_size` | int | 1024 | Minimum body size to compress (bytes) |
| `level` | int | 6 | Compression level (1-9) |
| `exclude_content_types` | []string | — | Content types to skip |

```yaml
compression:
  enable: true
  algorithms: [br, gzip]
  min_size: 1024
  level: 6
```

---

## 14. CORS (`cors`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | false | Enable CORS header injection |
| `allow_origins` | []string | — | Allowed origins (`["*"]` for any) |
| `allow_methods` | []string | Standard methods | Allowed HTTP methods |
| `allow_headers` | []string | Standard headers | Allowed request headers |
| `expose_headers` | []string | — | Headers exposed to browser |
| `max_age` | int | 86400 | Preflight cache duration in seconds |
| `allow_credentials` | bool | false | Allow cookies and auth headers |

---

## 15. HSTS (`hsts`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Enable HSTS header |
| `max_age` | int | 0 | `max-age` in seconds |
| `include_subdomains` | bool | false | Include subdomains |
| `preload` | bool | false | Include `preload` |
