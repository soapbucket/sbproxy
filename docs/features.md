# SBproxy Features Manual

*Last modified: 2026-04-12*

Comprehensive guide to sbproxy features. Each section explains what a feature does, how to configure it, and shows a working example using `test.sbproxy.dev`.

---

## 1. Overview

sbproxy is a high-performance reverse proxy and AI gateway in a single binary. It handles both traditional HTTP proxying and LLM API traffic in one configuration file.

**Core capabilities:**
- Reverse proxy with hot-reload, path routing, and forwarding rules
- AI gateway with 103+ provider integrations, model routing, and budget enforcement
- Load balancer with 10 algorithms, health checks, and circuit breakers
- 7 authentication methods, 9 security policies, 18+ response transforms
- CEL and Lua scripting for custom logic
- MCP server for AI agent tool use
- Agent-to-Agent (A2A) protocol support

### Install

```bash
# Script
curl -fsSL https://download.sbproxy.dev | sh

# Homebrew
brew tap soapbucket/sbproxy && brew install sbproxy

# Go
go install github.com/soapbucket/sbproxy/cmd/sbproxy@latest

# Docker
docker pull ghcr.io/soapbucket/sbproxy:latest
```

### Run

```bash
sbproxy serve -f sb.yml          # Start from config file
sbproxy serve -d ./configs/      # Start from config directory
sbproxy validate -c sb.yml       # Validate config without starting
sbproxy version                  # Show version
```

### Minimal config

```yaml
proxy:
  http_bind_port: 8080

origins:
  "test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

```bash
curl -H "Host: test.sbproxy.dev" http://localhost:8080/echo
```

---

## 2. Proxy Basics

### How requests are processed

Every request flows through this pipeline:

1. Host filter - blocks unknown hostnames (bloom filter, fast reject)
2. Global middleware - connection tracking, protocol detection
3. Config lookup - find origin config by hostname
4. Authentication - validate credentials (if configured)
5. Policies - rate limiting, WAF, IP filter, etc. (in order)
6. Callbacks - `on_request` hooks for dynamic enrichment
7. Action - proxy, redirect, static response, etc.
8. Response transforms - body and header modification
9. Response modifiers - header injection and cleanup

### Hostname matching

Origins are matched by exact hostname. The `Host` header in the request determines which origin config is used.

```yaml
origins:
  "api.example.com":        # Exact match
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

For wildcard or pattern-based routing, use `forward_rules` within an origin to dispatch based on path, headers, or query parameters.

### Hot reload

sbproxy watches config files for changes and reloads without dropping connections.

- Config changes take effect within seconds
- In-flight requests complete using the previous config
- Invalid configs are rejected; the previous valid config stays active
- Check logs for `config reloaded` or `config reload failed`

### Debug headers

Set `debug: true` on an origin to emit `X-Sb-*` headers on every response:

```yaml
origins:
  "api.example.com":
    debug: true
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

Debug headers include: `X-Sb-Origin` (origin chain), `X-Sb-Config-Mode`, `X-Sb-Request-Id`.

---

## 3. AI Gateway

The `ai_proxy` action turns sbproxy into an OpenAI-compatible API gateway. It accepts OpenAI Chat Completions API requests and routes them to one or more configured providers.

### Providers

sbproxy includes built-in adapters for 100+ providers. The `type` field on a provider selects the adapter.

Supported provider types include: `openai`, `anthropic`, `gemini`, `bedrock`, `azure`, `mistral`, `groq`, `together`, `ollama`, and many more.

```yaml
origins:
  "ai.test.sbproxy.dev":
    action:
      type: ai_proxy
      providers:
        - name: openai
          type: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini, o1-mini]

        - name: anthropic
          type: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-3-5-sonnet-20241022, claude-3-5-haiku-20241022]

        - name: local
          type: ollama
          base_url: http://localhost:11434
          models: [llama3.2, qwen2.5]
      default_model: gpt-4o-mini
```

```bash
# Chat completion
curl -H "Host: ai.test.sbproxy.dev" \
     -H "Content-Type: application/json" \
     -X POST http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'

# List models
curl -H "Host: ai.test.sbproxy.dev" http://localhost:8080/v1/models
```

### Routing strategies

The `routing.strategy` field controls how requests are distributed across providers:

| Strategy | Description |
|---|---|
| `round_robin` | Cycle through providers in order |
| `weighted` | Distribute by provider weight |
| `fallback_chain` | Try in order, fall back on failure |
| `lowest_latency` | Route to the fastest responding provider |
| `cost_optimized` | Route to cheapest provider per token |
| `least_connections` | Route to provider with fewest active requests |
| `token_rate` | Balance by token consumption rate |
| `sticky` | Pin requests to a provider using session/key |
| `semantic` | Route based on semantic content classification |

```yaml
action:
  type: ai_proxy
  providers:
    - name: primary
      api_key: ${OPENAI_API_KEY}
      models: [gpt-4o]
      weight: 3
    - name: fallback
      api_key: ${ANTHROPIC_API_KEY}
      models: [claude-3-5-sonnet-20241022]
      weight: 1
  routing:
    strategy: fallback_chain
    fallback_order: [primary, fallback]
    retry:
      max_attempts: 3
      backoff_ms: 100
      retry_on_timeout: true
```

### Dynamic routing with CEL

Use CEL expressions in `routing.model_selector` and `routing.provider_selector` to make routing decisions based on request properties:

```yaml
routing:
  strategy: round_robin
  # Route reasoning requests to o1-mini
  model_selector: |
    request.body.messages.exists(m, m.content.contains("step by step"))
    ? "o1-mini" : ""
  # Pin high-priority requests to primary provider
  provider_selector: |
    request.headers["x-priority"] == "high" ? "primary" : ""
```

### Streaming

sbproxy streams responses for all providers using Server-Sent Events (SSE). Set `"stream": true` in the request body.

```bash
curl -H "Host: ai.test.sbproxy.dev" \
     -H "Content-Type: application/json" \
     -X POST http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"Count to 5"}]}'
```

### Budget enforcement

Limit AI spending and token usage across workspaces, API keys, or users:

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
  budget:
    limits:
      - scope: workspace
        max_cost_usd: 500.00
        period: monthly
      - scope: api_key
        max_tokens: 1000000
        period: daily
    on_exceed: block        # "block", "log", or "downgrade"
    downgrade_map:
      gpt-4o: gpt-4o-mini  # Fall back to cheaper model when over budget
```

### Gateway mode

Enable `gateway: true` to activate unified model registry mode. Clients send requests with any model name; sbproxy routes to the provider that serves that model:

```yaml
action:
  type: ai_proxy
  gateway: true
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
      models: [gpt-4o, gpt-4o-mini]
    - name: anthropic
      api_key: ${ANTHROPIC_API_KEY}
      models: [claude-3-5-sonnet-20241022]
```

The client sends `"model": "claude-3-5-sonnet-20241022"` and sbproxy routes to Anthropic automatically.

### Cost headers

sbproxy adds cost headers to AI responses:

- `X-Sb-Cost-Usd` - estimated cost in USD
- `X-Sb-Tokens-In` - input tokens
- `X-Sb-Tokens-Out` - output tokens
- `X-Sb-Provider` - provider that handled the request
- `X-Sb-Model` - model used

---

## 4. Load Balancing

The `loadbalancer` action distributes traffic across multiple upstream targets.

### Algorithms

10 algorithms are available via the `algorithm` field:

| Algorithm | Description |
|---|---|
| `weighted_random` | Random selection weighted by target weight (default) |
| `round_robin` | Cycle through targets in order |
| `weighted_round_robin` | Round-robin with weight-based frequency |
| `least_connections` | Route to target with fewest active connections |
| `ip_hash` | Consistent hashing by client IP |
| `uri_hash` | Consistent hashing by request URI |
| `header_hash` | Consistent hashing by header value |
| `cookie_hash` | Consistent hashing by cookie value |
| `random` | Uniform random selection |
| `first` | Always use first healthy target |

```yaml
origins:
  "lb.test.sbproxy.dev":
    action:
      type: loadbalancer
      algorithm: least_connections
      targets:
        - url: https://test.sbproxy.dev/echo
          weight: 2
        - url: https://test.sbproxy.dev/
          weight: 1
```

```bash
for i in $(seq 1 6); do
  curl -s -H "Host: lb.test.sbproxy.dev" http://localhost:8080/echo | grep -o '"path":"[^"]*"'
done
```

### Consistent hashing

Use `header_hash` or `cookie_hash` with `hash_key` to pin users to the same backend:

```yaml
action:
  type: loadbalancer
  algorithm: header_hash
  hash_key: X-User-ID          # Hash by this header value
  targets:
    - url: https://backend-1.test.sbproxy.dev
    - url: https://backend-2.test.sbproxy.dev
```

### Sticky sessions

By default, `ip_hash`, `header_hash`, and `cookie_hash` provide stickiness. For session-cookie-based stickiness on other algorithms, set `disable_sticky: false`:

```yaml
action:
  type: loadbalancer
  algorithm: round_robin
  sticky_cookie_name: _sb_backend    # Custom cookie name
  disable_sticky: false              # Enable sticky sessions (uses cookie)
```

### Health checks

Each target can have independent health checks. Unhealthy targets are removed from rotation:

```yaml
action:
  type: loadbalancer
  targets:
    - url: https://test.sbproxy.dev
      health_check:
        enabled: true
        path: /health
        interval: 10s
        timeout: 3s
        healthy_threshold: 2
        unhealthy_threshold: 3
        expected_status: [200]
```

### Circuit breaker

Prevent cascading failures by automatically isolating failing backends:

```yaml
action:
  type: loadbalancer
  targets:
    - url: https://test.sbproxy.dev
      circuit_breaker:
        enabled: true
        failure_threshold: 5      # Open after 5 consecutive failures
        timeout: 30s              # Stay open for 30s
        success_threshold: 2      # Close after 2 successful probes
        half_open_requests: 3     # Probe with 3 requests in half-open state
```

### DNS SRV Discovery

Dynamically discover backends via DNS SRV records:

```yaml
action:
  type: loadbalancer
  discovery:
    type: dns_srv
    service: _http._tcp.api.internal
    refresh_interval: 30s
    resolver: 8.8.8.8:53
```

### Per-target modifications

Each target can have its own request and response modifiers:

```yaml
action:
  type: loadbalancer
  targets:
    - url: https://backend-1.test.sbproxy.dev
      request_modifiers:
        - headers:
            set:
              X-Backend-ID: "1"
    - url: https://backend-2.test.sbproxy.dev
      request_modifiers:
        - headers:
            set:
              X-Backend-ID: "2"
```

---

## 5. Authentication

sbproxy supports 7 authentication types. Specify one per origin under `authentication:`.

### API Key (`api_key`)

Accept requests with a valid API key in the `X-API-Key` header.

```yaml
origins:
  "api.test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    authentication:
      type: api_key
      api_keys:
        - prod-key-abc123
        - staging-key-xyz789
        - ${THIRD_PARTY_KEY}      # From environment variable
```

```bash
curl -H "Host: api.test.sbproxy.dev" \
     -H "X-API-Key: prod-key-abc123" \
     http://localhost:8080/echo

# Without key: 401
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo
```

### Basic Auth (`basic_auth`)

Standard HTTP Basic Authentication.

```yaml
authentication:
  type: basic_auth
  users:
    - username: alice
      password: secret123
    - username: bob
      password: hunter2
```

```bash
curl -H "Host: api.test.sbproxy.dev" \
     -u alice:secret123 \
     http://localhost:8080/echo
```

### Bearer Token (`bearer_token`)

Accept requests with a valid token in the `Authorization: Bearer` header.

```yaml
authentication:
  type: bearer_token
  tokens:
    - token-value-1
    - ${BEARER_TOKEN}
```

### JWT (`jwt`)

Validate JSON Web Tokens via JWKS URL, inline public key, or shared secret.

```yaml
authentication:
  type: jwt
  jwks_url: https://auth.test.sbproxy.dev/.well-known/jwks.json
  issuer: https://auth.test.sbproxy.dev
  audience: api.test.sbproxy.dev
  algorithm: RS256
  # Optional: cache validated tokens to reduce JWKS lookups
  cache_duration: 5m
  jwks_cache_duration: 1h
```

```bash
TOKEN=$(curl -s https://auth.test.sbproxy.dev/token | jq -r .access_token)
curl -H "Host: api.test.sbproxy.dev" \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/echo
```

### Forward Auth (`forward`)

Delegate authentication to an external service. The subrequest result determines access.

```yaml
authentication:
  type: forward
  url: https://auth.test.sbproxy.dev/verify
  method: GET
  forward_headers: [Authorization, Cookie]
  trust_headers: [X-User-ID, X-User-Role]  # Inject these from auth response
  success_status: [200]
  cache_duration: 30s
  timeout: 5s
```

Headers returned by the auth service in `trust_headers` are injected into the upstream request.

### Digest Auth (`digest`)

HTTP Digest Authentication (RFC 7616).

```yaml
authentication:
  type: digest
  users:
    - username: alice
      password: secret123
```

### gRPC External Auth (`grpc_auth`)

Envoy ext_authz compatible gRPC authorization server.

```yaml
authentication:
  type: grpc_auth
  address: authz-service.internal:9001
  timeout: 5s
  tls: true
  fail_open: false              # Block requests if auth server is down
  trust_headers: [X-User-ID]
```

### Authentication callbacks

All auth types support `*_callback` fields to fetch credentials dynamically from an external URL:

```yaml
authentication:
  type: api_key
  api_keys_callback:
    url: https://config.example.com/api-keys
    method: GET
    cache_duration: 5m
```

---

## 6. Security Policies

Policies run after authentication, in order. All policies in the list must pass.

### WAF - Web Application Firewall

The WAF policy applies ModSecurity-compatible rules and optionally the OWASP Core Rule Set (CRS).

```yaml
origins:
  "api.test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: waf
        owasp_crs:
          enabled: true
          paranoia_level: 1      # 1=balanced, 2=moderate, 3=strict, 4=paranoid
        action_on_match: block
        fail_open: false         # Fail closed (block on error)
        test_mode: false         # Set true to log but not block
```

```bash
# Normal request (passes WAF)
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo

# SQL injection attempt (blocked by WAF)
curl -H "Host: api.test.sbproxy.dev" \
     "http://localhost:8080/echo?id=1%27%20OR%20%271%27=%271"
```

### DDoS Protection

Detect and mitigate traffic spikes and volumetric attacks.

```yaml
policies:
  - type: ddos_protection
    detection:
      request_rate_threshold: 1000     # Trigger at 1000 req per window
      detection_window: "10s"
      adaptive_thresholds: true        # Auto-adjust to baseline traffic
      baseline_window: "1h"
      threshold_multiplier: 3.0        # 3x baseline triggers DDoS mode
    mitigation:
      block_duration: "5m"
      auto_block: true
      block_after_attacks: 3
      challenge_type: proof_of_work   # "header", "proof_of_work", "captcha"
```

### Rate Limiting

Control request rates per client IP with four algorithm choices.

```yaml
policies:
  - type: rate_limiting
    algorithm: sliding_window          # sliding_window, token_bucket, leaky_bucket, fixed_window
    requests_per_minute: 60
    burst_size: 10                     # Allow up to 10 immediate burst requests
    whitelist:
      - 127.0.0.1
      - 10.0.0.0/8
    endpoint_limits:
      "/health":
        requests_per_minute: 600       # Health checks can poll freely
    headers:
      enabled: true                    # Add X-RateLimit-* headers
      include_limit: true
      include_remaining: true
      include_reset: true
      include_retry_after: true
    throttle:
      enabled: true                    # Queue excess instead of 429
      max_queue: 50
      max_wait: 3s
```

```bash
# Send 15 rapid requests to trigger rate limiting
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
       -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo
done
```

### IP Filtering

Allow or block requests by IP address or CIDR range.

```yaml
policies:
  - type: ip_filtering
    whitelist:
      - 127.0.0.1
      - 10.0.0.0/8
      - 192.168.0.0/16
    blacklist:
      - 203.0.113.0/24
    trusted_proxy_cidrs:
      - 10.0.0.0/8               # Only trust X-Forwarded-For from these
```

### CSRF Protection

Protect state-changing requests from cross-site forgery.

```yaml
policies:
  - type: csrf
    secret: ${CSRF_SECRET}        # Required for token signing
    cookie_name: _csrf
    header_name: X-CSRF-Token
    methods: [POST, PUT, DELETE, PATCH]
    exempt_paths:
      - /webhooks/
      - /api/public/
```

### Security Headers

Inject security-oriented HTTP response headers.

```yaml
policies:
  - type: security_headers
    strict_transport_security:
      enabled: true
      max_age: 31536000
      include_subdomains: true
      preload: true
    content_security_policy:
      enabled: true
      directives:
        default_src: ["'self'"]
        script_src: ["'self'", "'nonce-{generated}'"]
        connect_src: ["'self'", "https://api.test.sbproxy.dev"]
    x_frame_options:
      enabled: true
      value: DENY
    x_content_type_options:
      enabled: true
      no_sniff: true
    referrer_policy:
      enabled: true
      policy: strict-origin-when-cross-origin
```

### Request Limiting

Enforce limits on request size and complexity.

```yaml
policies:
  - type: request_limiting
    size_limits:
      max_url_length: 2048
      max_headers_count: 50
      max_header_size: "8KB"
      max_request_size: "10MB"
    complexity_limits:
      max_nested_depth: 10
      max_object_properties: 100
      max_array_elements: 1000
    protection:
      slowloris_protection: true
      slow_read_protection: true
      timeout: 30s
```

### SRI - Subresource Integrity

Validate resource integrity hashes in HTML responses.

```yaml
policies:
  - type: sri
    validate_responses: true
    fail_on_invalid_integrity: true
    algorithm: sha384
```

### Expression Policy (CEL/Lua)

Evaluate custom access control logic per request.

```yaml
policies:
  # Block by header value
  - type: expression
    cel_expr: |
      !(request.headers["x-role"] == "admin" || request.headers["x-role"] == "editor")
    status_code: 403

  # Block by path prefix
  - type: expression
    cel_expr: request.path.startsWith("/internal/")
    status_code: 404

  # Block by time of day (9 AM - 5 PM only)
  - type: expression
    cel_expr: |
      int(timestamp(now).getHours()) < 9 || int(timestamp(now).getHours()) >= 17
    status_code: 503
```

CEL has access to:
- `request.method` - HTTP method string
- `request.path` - request path
- `request.query` - map of query parameters
- `request.headers` - map of headers (lowercased, hyphens as underscores)
- `request.host` - Host header value
- `now` - current timestamp

---

## 7. Caching

### Response Cache

Cache upstream responses to reduce backend load.

```yaml
origins:
  "cached.test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    response_cache:
      enabled: true
      ttl: 60s
      conditions:
        methods: [GET, HEAD]
        status_codes: [200, 301, 404]
      stale_while_revalidate:
        enabled: true
        duration: 10s            # Serve stale for up to 10s while revalidating
        stale_if_error: 300s     # Serve stale for 5m if backend is down
        async_revalidate: true   # Revalidate in background
```

```bash
# First request - cache miss
curl -v -H "Host: cached.test.sbproxy.dev" http://localhost:8080/echo \
     2>&1 | grep -i "x-cache\|age"

# Second request - cache hit
curl -v -H "Host: cached.test.sbproxy.dev" http://localhost:8080/echo \
     2>&1 | grep -i "x-cache\|age"

# Force revalidation
curl -H "Host: cached.test.sbproxy.dev" \
     -H "Cache-Control: no-cache" \
     http://localhost:8080/echo
```

### Cache key normalization

Control which request attributes create distinct cache entries:

```yaml
response_cache:
  enabled: true
  ttl: 60s
  vary_by: [Accept-Language, X-App-Version]   # Vary cache key by these headers
  key_normalization:
    query_params:
      ignore: [utm_source, utm_medium, fbclid]  # Ignore tracking params
      sort: true                                 # Sort remaining params
    headers:
      ignore: [X-Request-ID, X-Trace-ID]
    case_normalization: true
```

### Cache invalidation

Invalidate cached responses when mutation requests arrive:

```yaml
response_cache:
  enabled: true
  ttl: 60s
  invalidation:
    on_methods: [POST, PUT, DELETE, PATCH]
    pattern: "^/api/users"          # Invalidate matching URLs
```

---

## 8. Content Transforms

Transforms modify request or response bodies. Multiple transforms are applied in order.

### JSON field filtering

Keep or remove specific fields from JSON responses:

```yaml
origins:
  "api.test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    transforms:
      - type: json_projection
        include: [id, name, email]    # Keep only these fields
        # exclude: [password, secret] # Or exclude specific fields
```

```bash
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo
# Response JSON only contains id, name, email fields
```

### JSON cleanup

Remove empty or falsy values from JSON responses:

```yaml
transforms:
  - type: json
    remove_empty_objects: true
    remove_empty_arrays: true
    remove_empty_strings: true
    pretty_print: false
```

### JSON schema validation

Reject responses that do not conform to a schema:

```yaml
transforms:
  - type: json_schema
    schema:
      type: object
      required: [id, name]
      properties:
        id: {type: integer}
        name: {type: string}
    action: validate    # "validate" (reject 400), "warn" (log), "strip"
```

### HTML transforms

Modify or minify HTML responses:

```yaml
transforms:
  - type: html
    content_types: [text/html]
    format_options:
      strip_comments: true
      strip_newlines: true
      strip_space: true
      lowercase_tags: true
    add_to_tags:
      - tag: head
        add_before_end_tag: true
        content: '<script src="/analytics.js"></script>'
      - tag: body
        add_before_end_tag: true
        content: '<div id="chat-widget"></div>'
```

### Format conversion

Convert XML, CSV, or YAML responses to JSON:

```yaml
transforms:
  - type: format_convert
    from: xml
    to: json
```

### String replacement

Find and replace strings in response bodies:

```yaml
transforms:
  - type: replace_strings
    replace_strings:
      replacements:
        - find: "old-api.example.com"
          replace: "new-api.example.com"
        - find: "INTERNAL_VERSION"
          replace: "{{ variables.api_version }}"
        - find: '\bfoo\b'
          replace: "bar"
          regex: true
```

### Payload size limit

Truncate or reject oversized responses:

```yaml
transforms:
  - type: payload_limit
    max_size: 5242880    # 5MB
    action: reject       # "truncate", "reject" (413), "warn"
```

### Markdown to HTML

Convert Markdown responses to HTML:

```yaml
transforms:
  - type: markdown
    content_types: [text/markdown]
    sanitize: true
    href_target_blank: true
```

### SSE stream processing

Process LLM streaming responses:

```yaml
transforms:
  - type: sse_chunking
    provider: openai
    filter_events: [ping, comment]
```

---

## 9. Scripting

### CEL Expressions

CEL (Common Expression Language) is a compiled expression engine used in policies, modifiers, forward rules, and routing decisions. It is evaluated once per request with access to request context.

**Available variables:**

| Variable | Type | Description |
|---|---|---|
| `request.method` | string | HTTP method |
| `request.path` | string | URL path |
| `request.query` | map | Query parameters |
| `request.headers` | map | Request headers (lowercase, hyphens as underscores) |
| `request.host` | string | Host header |
| `request.size` | int | Request body size |
| `now` | timestamp | Current time |

**Example uses:**

```yaml
# Expression policy - block non-admin users
policies:
  - type: expression
    cel_expr: request.headers["x-role"] != "admin"
    status_code: 403

# Forward rule condition - route API v2 to different origin
forward_rules:
  - rules:
      - header:
          name: X-API-Version
          value: "2"
    hostname: api-v2.example.com
```

### Lua Scripting

Lua scripts handle more complex transformations. sbproxy embeds a Lua 5.4 runtime.

**JSON transform:** Define `modify_json(data, ctx)` to reshape JSON response bodies.

```yaml
origins:
  "api.test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    transforms:
      - type: lua_json
        content_types: [application/json]
        timeout: 200ms
        lua_script: |
          function modify_json(data, ctx)
            -- Add proxy metadata
            data.proxy = "sbproxy"
            data.timestamp = ctx.request_time or "unknown"

            -- Rename a field
            if data.method then
              data.http_method = data.method
              data.method = nil
            end

            -- Filter sensitive fields
            data.authorization = nil
            data.internal_token = nil

            return data
          end
```

```bash
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo
# Response includes proxy and timestamp fields, method renamed to http_method
```

**Lua context variables (`ctx`):**

| Variable | Description |
|---|---|
| `ctx.request_time` | Request start timestamp |
| `ctx.request_id` | Unique request ID |
| `ctx.origin_id` | Origin configuration ID |
| `ctx.workspace_id` | Workspace identifier |

**Request modifier with Lua:**

```yaml
request_modifiers:
  - lua_script: |
      function modify_request(req)
        req.headers["X-Processed-By"] = "sbproxy"
        req.headers["X-Timestamp"] = tostring(os.time())
        return req
      end
```

**Lua in replace_strings:**

```yaml
transforms:
  - type: replace_strings
    replace_strings:
      replacements:
        - find: '"price":\s*(\d+)'
          regex: true
          lua_script: |
            function transform(match, ctx)
              local price = tonumber(match:match("%d+"))
              return '"price": ' .. tostring(price * 1.1)  -- Apply 10% markup
            end
```

---

## 10. Observability

### Prometheus metrics

Enable Prometheus metrics endpoint:

```yaml
telemetry:
  enabled: true
  bind_address: 0.0.0.0
  bind_port: 9090
```

```bash
curl http://localhost:9090/metrics
```

Key metrics exported:

| Metric | Type | Description |
|---|---|---|
| `sbproxy_requests_total` | counter | Total requests by origin, method, status |
| `sbproxy_request_duration_seconds` | histogram | Request latency |
| `sbproxy_active_connections` | gauge | Active connections by protocol |
| `sbproxy_upstream_requests_total` | counter | Requests forwarded to upstreams |
| `sbproxy_upstream_duration_seconds` | histogram | Upstream response latency |
| `sbproxy_cache_hits_total` | counter | Cache hit count |
| `sbproxy_cache_misses_total` | counter | Cache miss count |
| `sbproxy_rate_limit_total` | counter | Rate limited request count |
| `sbproxy_waf_blocks_total` | counter | WAF-blocked request count |
| `sbproxy_ai_tokens_in_total` | counter | AI input token count |
| `sbproxy_ai_tokens_out_total` | counter | AI output token count |
| `sbproxy_ai_cost_usd_total` | counter | AI spend in USD |

### OpenTelemetry

Export traces and metrics via OTLP:

```yaml
otel:
  enabled: true
  otlp_endpoint: http://otelcol:4317
  otlp_protocol: grpc
  service_name: my-proxy
  service_version: "1.0.0"
  environment: production
  sample_rate: 0.1             # Sample 10% of traces
```

sbproxy creates spans for:
- Incoming request processing
- Authentication verification
- Policy evaluation
- Upstream HTTP calls
- Transform execution

### Structured logging

sbproxy uses structured JSON logging by default:

```yaml
proxy:
  logging:
    format: json               # "json" or "dev" (human-readable, colored)
```

Log output includes: `time`, `level`, `msg`, `origin`, `method`, `path`, `status`, `duration_ms`, `remote_addr`, `request_id`.

Set `SBPROXY_LOG_LEVEL=debug` to enable verbose logging.

### Events system

Emit structured events for real-time monitoring. Subscribe to specific event types:

```yaml
origins:
  "api.test.sbproxy.dev":
    events:
      - "ai.*"         # All AI-related events
      - "auth.*"       # Auth success and failure
      - "*"            # All events
```

Events are emitted via the configured messenger (Redis Streams, in-process, or SSE stream).

---

## 11. Advanced Features

### Forward Rules

Route requests to different origins based on request attributes. Forward rules are evaluated in order; the first match wins.

```yaml
origins:
  "api.test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev

    forward_rules:
      # Static health endpoint - no backend needed
      - rules:
          - path:
              exact: /health
        origin:
          id: health-static
          hostname: health-static
          workspace_id: default
          version: "1.0.0"
          action:
            type: static
            status_code: 200
            json_body: {status: ok}

      # Route v2 API to different backend
      - rules:
          - path:
              prefix: /api/v2/
        hostname: api-v2.example.com

      # Route by header
      - rules:
          - header:
              name: X-Beta-User
              value: "true"
        hostname: beta.example.com
```

```bash
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/health      # Static response
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/api/v2/foo  # Routes to v2
```

### Custom Error Pages

Return branded error responses instead of default proxy errors:

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
      {"error": true, "message": "Rate limit exceeded. Retry in {{ retry_after }}s."}

  - status: [500, 502, 503, 504]
    content_type: text/html
    template: true
    body: |
      <html><body><h1>Service Unavailable</h1><p>Status: {{ status_code }}</p></body></html>
```

### Sessions

sbproxy maintains a session layer for cookie-based state:

```yaml
session_config:
  cookie_name: _sb_session
  cookie_max_age: 3600          # 1 hour
  cookie_same_site: Lax
  disable_http_only: false      # HttpOnly enabled by default
  allow_non_ssl: false          # Require HTTPS for session cookies
  enable_cookie_jar: true       # Proxy backend Set-Cookie via session
  on_session_start:             # Run callbacks when session is created
    - url: https://analytics.example.com/session
      method: POST
```

### Callbacks and Webhooks

Execute HTTP requests at specific lifecycle points:

```yaml
# on_load: called once when config is loaded (for bootstrapping)
on_load:
  - url: https://config.example.com/api-keys
    method: GET
    cache_duration: 5m         # Re-fetch every 5 minutes

# on_request: called per-request before the action (for enrichment)
on_request:
  - url: https://user-service.internal/profile
    method: GET
    forward_headers: [Authorization]
    cache_duration: 60s

# Session start callback
session_config:
  on_session_start:
    - url: https://analytics.example.com/events
      method: POST
```

### Compression

sbproxy can compress responses using gzip, Brotli, or Zstandard:

```yaml
compression:
  enable: true
  algorithms: [br, gzip, zstd]  # Preference order
  min_size: 1024                 # Only compress responses >= 1KB
  level: 6                       # Compression level (1-9)
  exclude_content_types:
    - image/jpeg
    - image/png
    - image/webp
    - video/*
    - application/zip
```

```bash
curl -H "Host: api.test.sbproxy.dev" \
     -H "Accept-Encoding: br, gzip" \
     --compressed \
     http://localhost:8080/echo
```

### PROXY Protocol

For deployments behind HAProxy or AWS NLB, parse PROXY protocol headers to extract the real client IP:

```yaml
proxy:
  proxy_protocol:
    enabled: true
    trusted_cidrs:
      - 10.0.0.0/8           # Only trust from internal load balancers
```

### CORS

Add Cross-Origin Resource Sharing headers:

```yaml
cors:
  enable: true
  allow_origins:
    - https://app.example.com
    - https://admin.example.com
  allow_methods: [GET, POST, PUT, DELETE, OPTIONS]
  allow_headers: [Content-Type, Authorization, X-API-Key]
  expose_headers: [X-RateLimit-Remaining, X-Request-ID]
  max_age: 3600
  allow_credentials: true
```

### mTLS to Backend

Authenticate to upstream services with client certificates:

```yaml
action:
  type: proxy
  url: https://secure-backend.example.com
  mtls_client_cert_file: /certs/client.crt
  mtls_client_key_file: /certs/client.key
  mtls_ca_cert_file: /certs/ca.crt
```

Or use base64-encoded inline data:

```yaml
action:
  type: proxy
  url: https://secure-backend.example.com
  mtls_client_cert_data: ${MTLS_CERT_B64}
  mtls_client_key_data: ${MTLS_KEY_B64}
```

### Retry and Hedging

Automatically retry failed upstream requests:

```yaml
action:
  type: proxy
  url: https://test.sbproxy.dev
  transport_wrappers:
    retry:
      enabled: true
      max_retries: 3
      initial_delay: 100ms
      max_delay: 5s
      multiplier: 2.0
      jitter: 0.1
      retryable_status: [502, 503, 504, 429]
    hedging:
      enabled: true
      delay: 200ms             # Send hedge request after 200ms
      max_hedges: 1
      methods: [GET, HEAD]
```

### Variables and Templates

Define variables for use in header values, bodies, and callbacks:

```yaml
variables:
  api_version: "v2"
  region: us-east-1
  environment: production

request_modifiers:
  - headers:
      set:
        X-API-Version: "{{ variables.api_version }}"
        X-Region: "{{ variables.region }}"
        X-Request-ID: "{{ request.id }}"
        X-Start-Time: "{{ request.start_time }}"
```

**Available template scopes:**

| Scope | Description |
|---|---|
| `{{ variables.name }}` | User-defined variables from `variables:` |
| `{{ secrets.name }}` | Resolved secret values |
| `{{ request.id }}` | Unique request ID |
| `{{ request.method }}` | HTTP method |
| `{{ request.path }}` | URL path |
| `{{ request.host }}` | Host header |
| `{{ request.start_time }}` | Request start timestamp |
| `{{ env.hostname }}` | Origin hostname |
| `{{ env.workspace_id }}` | Workspace identifier |
| `{{ env.environment }}` | Environment tag |

### Secrets Management

Reference secrets from environment variables, files, or HashiCorp Vault:

```yaml
vaults:
  env:
    type: env

  prod:
    type: hashicorp
    address: https://vault.example.com
    token: ${VAULT_TOKEN}

secrets:
  api_key: "env:MY_API_KEY"
  db_password: "prod:secret/data/app/db_password"
  jwt_secret: "env:JWT_SECRET"
```

Secrets are available as `{{ secrets.api_key }}` in templates and are substituted at runtime without appearing in logs or config dumps.

### MCP Server

Turn sbproxy into an MCP (Model Context Protocol) server that AI agents can call:

```yaml
origins:
  "mcp.test.sbproxy.dev":
    action:
      type: mcp
      mode: orchestrator
      server_info:
        name: example-mcp-server
        version: "1.0.0"
      capabilities:
        tools:
          listChanged: false
      default_timeout: 30s
      tools:
        - name: echo
          description: "Echo back a message"
          input_schema: |
            {"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}
          handler:
            type: proxy
            proxy:
              url: https://test.sbproxy.dev/echo
              method: GET
              query_params:
                message: "{{ message }}"
```

```bash
# Initialize MCP session
curl -X POST -H "Host: mcp.test.sbproxy.dev" \
     -H "Content-Type: application/json" \
     http://localhost:8080/ \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# List tools
curl -X POST -H "Host: mcp.test.sbproxy.dev" \
     -H "Content-Type: application/json" \
     http://localhost:8080/ \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# Call a tool
curl -X POST -H "Host: mcp.test.sbproxy.dev" \
     -H "Content-Type: application/json" \
     http://localhost:8080/ \
     -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"Hello MCP"}}}'
```

---

## 12. Plugin Development

sbproxy uses a plugin registry pattern. Plugins register themselves during `init()` and are looked up by name at config load time.

### Request pipeline

Plugins extend four extension points:

1. **Action** - terminal step that produces the response
2. **Auth** - authenticates the request (runs before policies)
3. **Policy** - gates access (runs after auth)
4. **Transform** - modifies the response body (runs after action)

All plugin types are registered in `pkg/plugin/` and are safe for concurrent use.

### Implementing an Action

```go
package myplugin

import (
    "encoding/json"
    "net/http"

    "github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
    plugin.RegisterAction("my_action", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
        var config MyActionConfig
        if err := json.Unmarshal(cfg, &config); err != nil {
            return nil, err
        }
        return &MyAction{config: config}, nil
    })
}

type MyAction struct {
    config MyActionConfig
}

func (a *MyAction) Type() string { return "my_action" }

func (a *MyAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"handled_by":"my_action"}`))
}
```

### Implementing a Policy

```go
func init() {
    plugin.RegisterPolicy("my_policy", func(cfg json.RawMessage) (plugin.PolicyEnforcer, error) {
        var config MyPolicyConfig
        if err := json.Unmarshal(cfg, &config); err != nil {
            return nil, err
        }
        return &MyPolicy{config: config}, nil
    })
}

type MyPolicy struct{ config MyPolicyConfig }

func (p *MyPolicy) Type() string { return "my_policy" }

func (p *MyPolicy) Enforce(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("X-Custom-Key") != p.config.RequiredKey {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

### Implementing a Transform

```go
func init() {
    plugin.RegisterTransform("my_transform", func(cfg json.RawMessage) (plugin.TransformHandler, error) {
        return &MyTransform{}, nil
    })
}

type MyTransform struct{}

func (t *MyTransform) Type() string { return "my_transform" }

func (t *MyTransform) Apply(resp *http.Response) error {
    // Read, modify, replace response body
    body, err := io.ReadAll(resp.Body)
    resp.Body.Close()
    if err != nil {
        return err
    }

    modified := bytes.Replace(body, []byte("old"), []byte("new"), -1)
    resp.Body = io.NopCloser(bytes.NewReader(modified))
    resp.ContentLength = int64(len(modified))
    return nil
}
```

### Plugin interfaces summary

| Interface | Package | Register function | Description |
|---|---|---|---|
| `ActionHandler` | `pkg/plugin` | `RegisterAction` | Terminal request handler |
| `ReverseProxyAction` | `pkg/plugin` | `RegisterAction` | Extended proxy with rewrite/transport hooks |
| `AuthProvider` | `pkg/plugin` | `RegisterAuth` | Authentication wrapper |
| `PolicyEnforcer` | `pkg/plugin` | `RegisterPolicy` | Access control wrapper |
| `TransformHandler` | `pkg/plugin` | `RegisterTransform` | Response body transformer |
| `MiddlewareRegistration` | `pkg/plugin` | `RegisterMiddleware` | Global middleware applied to all requests |
| `HealthCheckerFactory` | `pkg/plugin` | `RegisterHealthChecker` | Custom health check strategy |
| `TransportFactory` | `pkg/plugin` | `RegisterTransport` | Custom `http.RoundTripper` |

Import the plugin package (not any `internal/` package) to register your plugin:

```go
import "github.com/soapbucket/sbproxy/pkg/plugin"
```

Side-effect import your plugin package from your `main.go` to trigger registration:

```go
import (
    _ "github.com/mycompany/sbproxy-myplugin"
)
```
