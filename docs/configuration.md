# Configuration Reference

This is the complete configuration reference for sbproxy. Every option, every field, every action type is documented here with real-world examples you can copy-paste and run.

For AI-specific features in depth, see [ai-gateway.md](ai-gateway.md). For CEL and Lua scripting details, see [scripting.md](scripting.md). For the event system, see [events.md](events.md).

## Table of Contents

1. [Overview](#overview)
2. [Top-Level Structure](#top-level-structure)
3. [Proxy Settings](#proxy-settings)
4. [Origins](#origins)
5. [Actions](#actions)
6. [Authentication](#authentication)
7. [Policies](#policies)
8. [Transforms](#transforms)
9. [Request Modifiers](#request-modifiers)
10. [Response Modifiers](#response-modifiers)
11. [Response Cache](#response-cache)
12. [Forward Rules](#forward-rules)
13. [Variables, Vaults, and Secrets](#variables-vaults-and-secrets)
14. [Events](#events)
15. [Session Config](#session-config)
16. [Failure Mode](#failure-mode)
17. [Environment Variables](#environment-variables)
18. [ACME / Auto TLS](#acme--auto-tls)
19. [Redis Integration](#redis-integration)
20. [Validation](#validation)

---

## Overview

sbproxy reads its configuration from a YAML file, typically named `sb.yml`. This file defines how the proxy listens for traffic, which hostnames it handles, and what it does with each request.

**Load a config file:**

```bash
# Default (looks for sb.yml in current directory)
sbproxy serve

# Custom path
sbproxy serve -f /etc/sbproxy/production.yml
```

**Validate without starting:**

```bash
sbproxy validate -c sb.yml
```

The config has two main sections: `proxy` (server-level settings) and `origins` (per-hostname routing and behavior). Everything else, including Redis, caching, and telemetry, is configured at the top level alongside these.

---

## Top-Level Structure

Here is the complete YAML skeleton showing every top-level key:

```yaml
# Server settings (ports, TLS, timeouts)
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  http3_bind_port: 8443
  enable_http3: false
  bind_address: "0.0.0.0"
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 90s
  grace_time: 30s
  tls_cert: /path/to/cert.pem
  tls_key: /path/to/key.pem
  compression_level: 6
  certificate_settings: { ... }
  logging: { ... }
  vaults: { ... }

# L2 cache (Redis) for distributed rate limiting and caching
l2_cache_settings:
  driver: redis
  params:
    dsn: redis://localhost:6379/0

# Messenger (Redis) for real-time config updates
messenger_settings:
  driver: redis
  params:
    addr: localhost:6379

# Per-hostname origin configurations
origins:
  "api.example.com":
    action: { ... }
    authentication: { ... }
    policies: [ ... ]
    transforms: [ ... ]
    request_modifiers: { ... }
    response_modifiers: { ... }
    forward_rules: [ ... ]
    response_cache: { ... }
    variables: { ... }
    vaults: { ... }
    secrets: { ... }
    session_config: { ... }
    events: [ ... ]
    cors: { ... }
    compression: { ... }

# Telemetry and observability
telemetry: { ... }
otel: { ... }
```

---

## Proxy Settings

The `proxy` block configures server-level behavior: ports, timeouts, TLS, and compression.

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  http3_bind_port: 8443
  enable_http3: true
  bind_address: "0.0.0.0"
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 90s
  grace_time: 30s
  tls_cert: /etc/sbproxy/cert.pem
  tls_key: /etc/sbproxy/key.pem
  compression_level: 6
  max_recursion_depth: 10

  certificate_settings:
    use_acme: true
    acme_email: admin@example.com
    acme_cache_dir: /etc/sbproxy/certs
    min_tls_version: 1.2
    client_auth: none

  logging:
    format: json

  dns_cache:
    enabled: true
    max_entries: 10000
    default_ttl: 5m
```

### Proxy Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_bind_port` | int | 8080 | HTTP listen port |
| `https_bind_port` | int | 8443 | HTTPS listen port |
| `http3_bind_port` | int | 8443 | HTTP/3 (QUIC) listen port |
| `enable_http3` | bool | false | Enable HTTP/3 support |
| `bind_address` | string | "0.0.0.0" | Network interface to bind to |
| `read_timeout` | duration | 30s | Maximum time to read the full request |
| `write_timeout` | duration | 30s | Maximum time to write the response |
| `idle_timeout` | duration | 90s | Maximum time to wait for the next request on a keep-alive connection |
| `grace_time` | duration | 30s | Seconds to wait for in-flight requests during shutdown |
| `tls_cert` | string | | Path to TLS certificate file (PEM) |
| `tls_key` | string | | Path to TLS private key file (PEM) |
| `compression_level` | int | 0 | Response compression level (0 = disabled, 1-9 = gzip) |
| `max_recursion_depth` | int | 10 | Maximum depth for nested forward rules |
| `config_sync_mode` | string | "hybrid" | Config sync mode: "push", "pull", or "hybrid" |
| `ai_pricing_file` | string | | Path to LiteLLM-format JSON pricing file for cost routing |

### Certificate Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `use_acme` | bool | false | Enable automatic certificate provisioning via ACME |
| `acme_email` | string | | Contact email for ACME account |
| `acme_domains` | []string | | Domains to request certificates for (empty = all origin hostnames) |
| `acme_cache_dir` | string | | Directory to store ACME certificates |
| `acme_directory_url` | string | Let's Encrypt production | ACME directory URL |
| `acme_insecure_skip_verify` | bool | false | Skip TLS verification for ACME server (testing only) |
| `acme_ca_cert_file` | string | | CA cert file for custom ACME server |
| `min_tls_version` | int | 1.2 | Minimum TLS version (1.2 or 1.3) |
| `tls_cipher_suites` | []string | | Allowed TLS cipher suites |
| `client_auth` | string | "none" | mTLS client auth: "none", "request", "require", "verify_if_given", "require_and_verify" |
| `client_ca_cert_file` | string | | CA cert file for verifying client certificates |

### DNS Cache Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable DNS response caching |
| `max_entries` | int | 10000 | Maximum cached DNS entries |
| `default_ttl` | duration | 5m | Default TTL for cached entries |
| `negative_ttl` | duration | 30s | TTL for negative (NXDOMAIN) responses |
| `serve_stale_on_error` | bool | false | Serve stale entries when DNS lookup fails |
| `background_refresh` | bool | false | Refresh entries in background before expiry |

---

## Origins

Each key under `origins` is a hostname. When a request arrives, sbproxy matches the `Host` header to an origin key and applies that origin's configuration. Every origin must have an `action` block.

```yaml
origins:
  "api.example.com":
    disabled: false
    environment: prod
    tags: [backend, v2]
    version: "2.1.0"
    force_ssl: true
    allowed_methods: [GET, POST, PUT, DELETE]
    max_connections: 500
    action:
      type: proxy
      url: https://backend.internal:8080
```

### Hostname Matching

- **Exact match:** `"api.example.com"` matches only `api.example.com`.
- **Wildcard match:** `"*.example.com"` matches `api.example.com`, `www.example.com`, etc. The wildcard must be the first character and only covers one subdomain level.
- **Multiple origins:** Define as many origins as you need. Each has independent auth, policies, and routing.

### Origin Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `disabled` | bool | false | Disable this origin without removing it from config |
| `environment` | string | | Deployment environment label (dev, staging, prod) |
| `tags` | []string | | User-defined tags for filtering and reporting |
| `version` | string | | Configuration version string |
| `force_ssl` | bool | false | Redirect all HTTP requests to HTTPS |
| `allowed_methods` | []string | all | Restrict which HTTP methods are accepted |
| `max_connections` | int | unlimited | Maximum concurrent connections (max: 10000) |
| `default_content_type` | string | application/json | Fallback content type for error responses |
| `failure_mode` | string | | Default failure mode: "open" or "closed" |

### Origin Architecture

Every origin config block supports these sibling fields. They are all at the same level, not nested inside `action`:

```yaml
origins:
  "api.example.com":
    action: { ... }              # Required: what to do with the request
    authentication: { ... }      # Optional: who can access
    policies: [ ... ]            # Optional: rate limits, security
    transforms: [ ... ]          # Optional: modify response body
    request_modifiers: { ... }   # Optional: modify request via CEL/Lua
    response_modifiers: { ... }  # Optional: modify response via CEL/Lua
    forward_rules: [ ... ]       # Optional: path-based routing to sub-origins
    response_cache: { ... }      # Optional: cache responses
    variables: { ... }           # Optional: template variables
    vaults: { ... }              # Optional: secret vault backends
    secrets: { ... }             # Optional: secret references
    session_config: { ... }      # Optional: session/cookie settings
    events: [ ... ]              # Optional: event types to emit
    cors: { ... }                # Optional: CORS headers
    compression: { ... }         # Optional: response compression
    error_pages: [ ... ]         # Optional: custom error pages
    proxy_headers: { ... }       # Optional: proxy header behavior
```

---

## Actions

The `action` block defines what the proxy does with a matched request. The `type` field selects the handler.

### proxy

Forward requests to an upstream URL. This is the most common action type. Use it when you want sbproxy to sit in front of an existing backend service.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
      timeout: 30s
      strip_base_path: false
      preserve_query: true
      alt_hostname: backend.internal
      disable_follow_redirects: false
      skip_tls_verify_host: false
      idle_conn_timeout: 60s
      tls_handshake_timeout: 10s
      dial_timeout: 10s
      keep_alive: 30s
      max_idle_conns: 100
      max_idle_conns_per_host: 10
      max_conns_per_host: 100
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Upstream URL to forward requests to |
| `timeout` | duration | 30s | Total request timeout (max: 60s) |
| `strip_base_path` | bool | false | Remove the URL's base path, use request path as-is |
| `preserve_query` | bool | false | Use only the request query string (skip merging with URL query) |
| `alt_hostname` | string | | Override the Host header sent to the backend |
| `method` | string | | Override the HTTP method |
| `disable_follow_redirects` | bool | false | Do not follow upstream redirects |
| `skip_tls_verify_host` | bool | false | Skip TLS hostname verification (insecure) |
| `min_tls_version` | string | | Minimum TLS version for upstream ("1.2" or "1.3") |
| `http11_only` | bool | false | Force HTTP/1.1 (disable HTTP/2 and HTTP/3) |
| `enable_http3` | bool | false | Enable HTTP/3 for upstream connections |
| `max_redirects` | int | 10 | Maximum redirects to follow (max: 20) |
| `idle_conn_timeout` | duration | 60s | Idle connection timeout |
| `tls_handshake_timeout` | duration | 10s | TLS handshake timeout |
| `dial_timeout` | duration | 10s | TCP dial timeout |
| `keep_alive` | duration | 30s | TCP keep-alive interval |
| `max_connections` | int | unlimited | Max concurrent connections (max: 10000) |
| `max_idle_conns` | int | | Max idle connections across all hosts (max: 5000) |
| `max_idle_conns_per_host` | int | | Max idle connections per host (max: 500) |
| `max_conns_per_host` | int | | Max connections per host (max: 5000) |
| `delay` | duration | | Artificial delay before forwarding (testing) |
| `flush_interval` | duration | | How often to flush buffered response data |
| `rate_limit` | int | | Requests per second to upstream (max: 1000000) |
| `burst_limit` | int | | Burst allowance for upstream rate limit (max: 100000) |
| `response_header_timeout` | duration | 30s | Max time waiting for response headers |

**Retry configuration** (nested under the proxy action):

```yaml
action:
  type: proxy
  url: https://backend.example.com
  transport_wrappers:
    retry:
      enabled: true
      max_retries: 3
      initial_delay: 100ms
      max_delay: 10s
      multiplier: 2.0
      jitter: 0.1
      retryable_status: [502, 503, 504, 429]
    health_check:
      enabled: true
      endpoint: /health
      interval: 30s
      timeout: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3
```

**Shadow traffic** (mirror traffic to a secondary upstream):

```yaml
action:
  type: proxy
  url: https://backend.example.com
  shadow:
    upstream_url: https://shadow-backend.example.com
    sample_rate: 0.1
    timeout: 500ms
    max_concurrent: 100
```

**Canary deployments** (split traffic between primary and canary):

```yaml
action:
  type: proxy
  url: https://backend.example.com
  canary:
    enabled: true
    percentage: 10
    target: https://canary-backend.example.com
    sticky_header: X-Canary
```

**mTLS to upstream** (mutual TLS for backend authentication):

```yaml
action:
  type: proxy
  url: https://secure-backend.example.com
  mtls_client_cert_file: /etc/sbproxy/client.crt
  mtls_client_key_file: /etc/sbproxy/client.key
  mtls_ca_cert_file: /etc/sbproxy/backend-ca.crt
```

### static

Return a fixed response without proxying to any upstream. Use this for health check endpoints, maintenance pages, or mock APIs.

```yaml
origins:
  "status.example.com":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        status: healthy
        version: "2.1.0"
        services:
          database: up
          cache: up
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status_code` | int | 200 | HTTP status code |
| `content_type` | string | | Content-Type header |
| `body` | string | | Plain text or HTML body |
| `body_base64` | string | | Base64-encoded body (for binary content) |
| `json_body` | object | | JSON body (auto-sets Content-Type to application/json) |
| `headers` | map | | Additional response headers |

### redirect

Return an HTTP redirect. Use this for domain migrations, HTTPS enforcement, or URL shortening.

```yaml
origins:
  "old.example.com":
    action:
      type: redirect
      url: https://new.example.com
      status_code: 301
      preserve_query: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Redirect target URL |
| `status_code` | int | 301 | HTTP status code (301, 302, 303, 307, or 308) |
| `strip_base_path` | bool | false | Append original request path to redirect URL |
| `preserve_query` | bool | false | Preserve original query string |

### echo

Return the incoming request as a JSON response. Use this for debugging proxy behavior, testing forward rules, or verifying that headers and auth are set up correctly.

```yaml
origins:
  "debug.example.com":
    action:
      type: echo
      include_context: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `include_context` | bool | false | Include additional context (GeoIP, user agent, session) in response |

### loadbalancer

Distribute traffic across multiple backend targets. Use this when you have multiple instances of a service and need to spread the load.

```yaml
origins:
  "api.example.com":
    action:
      type: loadbalancer
      algorithm: weighted_round_robin
      targets:
        - url: https://backend-1.internal:8080
          weight: 70
          health_check:
            enabled: true
            path: /health
            interval: 10s
          circuit_breaker:
            enabled: true
            failure_threshold: 5
            timeout: 30s
        - url: https://backend-2.internal:8080
          weight: 30
          health_check:
            enabled: true
            path: /health
            interval: 10s
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `targets` | []Target | required | Backend targets with URLs and weights |
| `algorithm` | string | weighted_random | Load balancing algorithm (see below) |
| `disable_sticky` | bool | false | Disable sticky sessions |
| `sticky_cookie_name` | string | sb_sticky | Cookie name for sticky sessions |
| `strip_base_path` | bool | false | Strip target URL base path |
| `preserve_query` | bool | false | Use only request query string |

**Algorithms:**

| Algorithm | Description |
|-----------|-------------|
| `round_robin` | Distributes requests in a sequential cycle across all healthy targets |
| `weighted_round_robin` | Like round_robin but proportional to each target's weight |
| `weighted_random` | Randomly selects targets with probability proportional to weight (default) |
| `least_connections` | Routes to the target with fewest in-flight requests |
| `ip_hash` | Routes based on client IP hash for session affinity |

**Target fields:**

Each target inherits from the proxy action's connection settings and adds:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend URL |
| `weight` | int | 1 | Relative weight for weighted algorithms |
| `health_check` | object | | Health check configuration |
| `circuit_breaker` | object | | Circuit breaker configuration |
| `request_modifiers` | object | | Per-target request modifications |
| `response_modifiers` | object | | Per-target response modifications |

### websocket

Proxy WebSocket connections. Use this for real-time applications, chat systems, or streaming APIs.

```yaml
origins:
  "ws.example.com":
    action:
      type: websocket
      url: wss://ws-backend.internal:8080
      ping_interval: 30s
      pong_timeout: 10s
      idle_timeout: 5m
      max_frame_size: 1048576
      enable_compression: true
      handshake_timeout: 10s
      subprotocols: [graphql-ws, graphql-transport-ws]
      allowed_origins: ["https://app.example.com"]
      check_origin: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend WebSocket URL (ws:// or wss://) |
| `ping_interval` | duration | disabled | Interval to send ping frames |
| `pong_timeout` | duration | 10s | Max wait for pong response |
| `idle_timeout` | duration | | Close connections after this idle period |
| `max_frame_size` | int | | Maximum WebSocket message size (max: 10MB) |
| `read_buffer_size` | int | 4096 | Read buffer size |
| `write_buffer_size` | int | 4096 | Write buffer size |
| `enable_compression` | bool | false | Enable per-message compression |
| `handshake_timeout` | duration | 10s | WebSocket handshake timeout |
| `subprotocols` | []string | | Supported WebSocket subprotocols |
| `allowed_origins` | []string | all | CORS allowed origins |
| `check_origin` | bool | false | Enable origin checking |
| `enable_rfc8441` | bool | false | WebSocket-over-HTTP/2 support |
| `enable_rfc9220` | bool | false | WebSocket-over-HTTP/3 support |
| `strip_base_path` | bool | false | Strip base path from URL |

### grpc

Proxy gRPC traffic. Use this for microservice architectures using gRPC.

```yaml
origins:
  "grpc.example.com":
    action:
      type: grpc
      url: grpc://grpc-backend.internal:50051
      timeout: 30s
      enable_grpc_web: true
      forward_metadata: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend gRPC URL |
| `enable_grpc_web` | bool | false | Enable gRPC-Web for browser clients |
| `forward_metadata` | bool | true | Forward gRPC metadata headers |
| `strip_base_path` | bool | true | Strip base path |

### ai_proxy

Route requests across LLM providers with automatic failover, cost tracking, and content-based routing. This is a full AI gateway. For comprehensive details, see [ai-gateway.md](ai-gateway.md).

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini, gpt-4-turbo]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514, claude-3-5-haiku-20241022]
      default_model: gpt-4o-mini
      routing:
        strategy: fallback_chain
        fallback_order: [openai, anthropic]
        retry:
          max_attempts: 3
        model_selector: >
          request.headers['x-priority'] == 'high'
            ? 'gpt-4o'
            : 'gpt-4o-mini'
      failure_mode: open
      failure_overrides:
        guardrails: closed
```

**Routing strategies:** `round_robin`, `weighted`, `fallback_chain`, `cost_optimized`, `lowest_latency`, `least_connections`, `sticky`, `semantic`.

See the [AI Gateway Guide](ai-gateway.md) for CEL selectors, Lua hooks, guardrails, context window validation, cost headers, and streaming behavior.

---

## Authentication

The `authentication` block is a **sibling** of `action`, not nested inside it. It controls who can access the origin.

### api_key

Authenticate requests with an API key. Keys are checked in the `X-API-Key` header by default. Use this for machine-to-machine API access.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: api_key
      api_keys:
        - ${API_KEY_1}
        - ${API_KEY_2}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `api_key` |
| `api_keys` | []string | required | List of valid API keys |
| `disabled` | bool | false | Disable authentication (pass all requests) |

Test with:
```bash
curl -H "Host: api.example.com" -H "X-API-Key: your-key-here" http://localhost:8080/
```

### basic_auth

HTTP Basic Authentication with username/password pairs. Use this for simple internal services or admin panels.

```yaml
origins:
  "admin.example.com":
    action:
      type: proxy
      url: https://admin-backend.internal:8080
    authentication:
      type: basic_auth
      users:
        - username: admin
          password: ${ADMIN_PASSWORD}
        - username: readonly
          password: ${READONLY_PASSWORD}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `basic_auth` |
| `users` | []User | required | List of username/password pairs |
| `disabled` | bool | false | Disable authentication |

### bearer_token

Authenticate with Bearer tokens in the Authorization header. Use this for token-based service auth.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: bearer_token
      tokens:
        - ${SERVICE_TOKEN_1}
        - ${SERVICE_TOKEN_2}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `bearer_token` |
| `tokens` | []string | required | List of valid bearer tokens |

### jwt

Validate JSON Web Tokens. Supports JWKS endpoints for key rotation, multiple audiences, and claims validation. Use this for OAuth2/OIDC-protected APIs.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: jwt
      jwks_url: https://auth.example.com/.well-known/jwks.json
      jwks_cache_duration: 1h
      issuer: https://auth.example.com
      audience: my-api
      audiences: [my-api, my-api-v2]
      algorithm: RS256
      header_name: Authorization
      header_prefix: "Bearer "
      claims_namespace: "https://example.com/claims"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `jwt` |
| `jwks_url` | string | | URL to fetch JWKS from |
| `jwks_cache_duration` | duration | 1h | How long to cache JWKS (max: 24h) |
| `secret` | string | | HMAC signing secret (for HS256/HS384/HS512) |
| `public_key` | string | | Base64-encoded public key (for RS256/ES256) |
| `issuer` | string | | Expected `iss` claim value |
| `audience` | string | | Expected `aud` claim value |
| `audiences` | []string | | Multiple expected audiences (any must match) |
| `algorithm` | string | RS256 | Signing algorithm |
| `header_name` | string | Authorization | Header to extract token from |
| `header_prefix` | string | "Bearer " | Prefix to strip from header value |
| `cookie_name` | string | | Extract token from a cookie instead |
| `query_param` | string | | Extract token from a query parameter instead |
| `claims_namespace` | string | | Namespace prefix for custom claims |
| `cache_duration` | duration | | Cache public keys (max: 24h) |

### oauth2

Full OAuth 2.0 / OpenID Connect authentication with login flow, token refresh, and session management. Use this for user-facing applications that need SSO.

```yaml
origins:
  "app.example.com":
    action:
      type: proxy
      url: https://app-backend.internal:8080
    authentication:
      type: oauth2
      provider: google
      client_id: ${GOOGLE_CLIENT_ID}
      client_secret: ${GOOGLE_CLIENT_SECRET}
      redirect_url: https://app.example.com/auth/callback
      session_secret: ${SESSION_SECRET}
      session_cookie_name: sb_auth
      session_max_age: 86400
      scopes: [openid, email, profile]
      callback_path: /auth/callback
      login_path: /auth/login
      logout_path: /auth/logout
      force_authentication: true
      pkce: true
```

For OIDC providers, you can set the `issuer` field and sbproxy will auto-discover endpoints:

```yaml
authentication:
  type: oauth2
  issuer: https://accounts.google.com
  client_id: ${GOOGLE_CLIENT_ID}
  client_secret: ${GOOGLE_CLIENT_SECRET}
  redirect_url: https://app.example.com/auth/callback
  session_secret: ${SESSION_SECRET}
```

**Supported provider presets:** google, github, okta, auth0, azure. For other providers, set `auth_url` and `token_url` manually.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `oauth2` |
| `provider` | string | | Provider preset (google, github, okta, auth0, azure) |
| `client_id` | string | required | OAuth client ID |
| `client_secret` | string | required | OAuth client secret |
| `redirect_url` | string | required | OAuth callback URL |
| `session_secret` | string | required | Secret for signing session cookies |
| `session_cookie_name` | string | | Session cookie name |
| `session_max_age` | int | 3600 | Session lifetime in seconds |
| `auth_url` | string | | Authorization endpoint (auto-discovered with provider) |
| `token_url` | string | | Token endpoint (auto-discovered with provider) |
| `scopes` | []string | [openid] | OAuth scopes to request |
| `issuer` | string | | OIDC issuer URL (enables auto-discovery) |
| `callback_path` | string | /auth/callback | Path for OAuth callback |
| `login_path` | string | /auth/login | Path that triggers login |
| `logout_path` | string | /auth/logout | Path that triggers logout |
| `force_authentication` | bool | false | Require auth on all requests |
| `pkce` | bool | true | Enable PKCE for code exchange |
| `tenant` | string | | Tenant ID for multi-tenant providers |

### forward_auth

Delegate authentication to an external service. sbproxy sends a subrequest to the auth service and uses the response to allow or deny the original request. Use this when your auth logic lives in a separate service.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: forward_auth
      url: https://auth.internal/verify
      method: GET
      timeout: 5s
      forward_headers: [Authorization, Cookie]
      trust_headers: [X-User-ID, X-User-Email, X-User-Roles]
      success_status: [200]
      cache_duration: 5m
      cache_key: "{{request.headers.Authorization}}"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `forward_auth` |
| `url` | string | required | External auth service URL |
| `method` | string | GET | HTTP method for auth subrequest |
| `timeout` | duration | 5s | Auth request timeout |
| `forward_headers` | []string | | Headers to send from original request |
| `forward_body` | bool | false | Forward the original request body |
| `trust_headers` | []string | | Headers from auth response to inject into upstream request |
| `success_status` | []int | [200] | Status codes that mean "authenticated" |
| `cache_duration` | duration | | Cache auth responses for this duration |
| `cache_key` | string | | Template for cache key |

### grpc_auth

External gRPC auth service compatible with Envoy's ext_authz protocol. Use this in service mesh environments.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: grpc_auth
      address: auth-service.internal:50051
      timeout: 5s
      tls: true
      fail_open: false
      trust_headers: [x-user-id, x-user-role]
```

---

## Policies

Policies are evaluated **before** the action runs. They enforce rate limits, security rules, and access controls. The `policies` field is a sibling of `action` and is an array of policy objects.

### rate_limit

Rate limit clients by IP, API key, or custom key. Use this to prevent abuse and protect backend resources.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    policies:
      - type: rate_limit
        requests_per_minute: 60
        requests_per_hour: 1000
        burst_size: 10
        algorithm: sliding_window
        whitelist:
          - 10.0.0.0/8
        blacklist:
          - 203.0.113.50/32
```

Clients exceeding the limit receive `429 Too Many Requests` with a `Retry-After` header.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `rate_limit` |
| `algorithm` | string | fixed_window | Algorithm: `sliding_window`, `token_bucket`, `leaky_bucket`, `fixed_window` |
| `requests_per_minute` | int | | Requests allowed per minute |
| `requests_per_hour` | int | | Requests allowed per hour |
| `requests_per_day` | int | | Requests allowed per day |
| `burst_size` | int | | Max burst capacity (for token_bucket) |
| `refill_rate` | float | | Tokens per second (for token_bucket) |
| `queue_size` | int | | Max queue size (for leaky_bucket) |
| `drain_rate` | float | | Requests per second (for leaky_bucket) |
| `whitelist` | []string | | IPs/CIDRs exempt from rate limiting |
| `blacklist` | []string | | IPs/CIDRs always blocked |
| `custom_limits` | map | | Per-IP custom limits |
| `endpoint_limits` | map | | Per-endpoint custom limits |
| `disabled` | bool | false | Disable the policy |

**Distributed rate limiting:** In a single-instance deployment, rate limits are tracked in memory. For multi-instance deployments, configure an L2 Redis cache so counters are shared across all proxy instances:

```yaml
l2_cache_settings:
  driver: redis
  params:
    dsn: redis://redis.internal:6379/0
```

### ip_filter

Allow or block requests by client IP address or CIDR range. Use this for restricting access to internal services or blocking known bad actors.

```yaml
policies:
  - type: ip_filter
    whitelist:
      - 10.0.0.0/8
      - 192.168.1.0/24
      - 172.16.0.0/12
    blacklist:
      - 10.0.0.99/32
    trusted_proxy_cidrs:
      - 172.16.0.0/12
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `ip_filter` |
| `whitelist` | []string | | IPs/CIDRs to allow |
| `blacklist` | []string | | IPs/CIDRs to block |
| `trusted_proxy_cidrs` | []string | | CIDRs of trusted proxies (for X-Forwarded-For) |
| `dynamic_blocklist` | []string | | URLs to fetch blocklists from |
| `blocklist_ttl` | duration | 24h | How long dynamic blocklist entries last (max: 30d) |
| `temporary_bans` | map | | IP to ban duration mapping (e.g., "1h") |

### expression

CEL or Lua expressions that evaluate to allow or deny a request. Use this for custom access control logic that goes beyond simple IP/key checks.

```yaml
policies:
  - type: expression
    cel_expr: 'request.headers["x-internal"] == "true"'
    status_code: 403
```

```yaml
policies:
  - type: expression
    lua_script: |
      if request.headers["x-admin-key"] == "secret" then
        return true
      end
      return false
    status_code: 401
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `expression` |
| `cel_expr` | string | | CEL expression returning boolean |
| `lua_script` | string | | Lua script returning boolean |
| `status_code` | int | 403 | HTTP status code when denied |

### concurrency

Limit the number of concurrent requests being processed. Use this to prevent a single origin from consuming all proxy resources.

```yaml
policies:
  - type: concurrency
    max_concurrent: 100
```

### security_headers

Inject security headers into every response. Use this to harden browser security.

```yaml
policies:
  - type: security_headers
    strict_transport_security:
      enabled: true
      max_age: 31536000
      include_subdomains: true
      preload: true
    content_security_policy:
      policy: "default-src 'self'; script-src 'self' https://cdn.example.com"
    x_frame_options:
      value: DENY
    x_content_type_options:
      enabled: true
    referrer_policy:
      value: strict-origin-when-cross-origin
    permissions_policy:
      policy: "camera=(), microphone=(), geolocation=()"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `strict_transport_security` | object | | HSTS settings (max_age, include_subdomains, preload) |
| `content_security_policy` | object | | CSP policy string |
| `x_frame_options` | object | | Frame embedding control (DENY, SAMEORIGIN) |
| `x_content_type_options` | object | | Prevent MIME type sniffing |
| `x_xss_protection` | object | | XSS filter (legacy browsers) |
| `referrer_policy` | object | | Controls Referer header |
| `permissions_policy` | object | | Feature permissions |
| `cross_origin_embedder_policy` | object | | COEP header |
| `cross_origin_opener_policy` | object | | COOP header |
| `cross_origin_resource_policy` | object | | CORP header |

### csrf

Cross-Site Request Forgery protection. Use this for web applications that accept form submissions.

```yaml
policies:
  - type: csrf
    secret: ${CSRF_SECRET}
    cookie_name: _csrf
    cookie_path: /
    cookie_same_site: Lax
    header_name: X-CSRF-Token
    methods: [POST, PUT, DELETE, PATCH]
    exempt_paths: [/api/webhooks, /api/health]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `csrf` |
| `secret` | string | required | Secret key for token signing |
| `cookie_name` | string | _csrf | CSRF cookie name |
| `cookie_path` | string | / | Cookie path |
| `cookie_same_site` | string | Lax | SameSite attribute (Strict, Lax, None) |
| `cookie_secure` | bool | true | Set Secure flag |
| `cookie_http_only` | bool | true | Set HttpOnly flag |
| `header_name` | string | X-CSRF-Token | Header name for token |
| `form_field_name` | string | _csrf | Form field name for token |
| `token_length` | int | 32 | Token length in bytes |
| `methods` | []string | [POST, PUT, DELETE, PATCH] | Methods requiring CSRF validation |
| `exempt_paths` | []string | | Paths exempt from CSRF checks |

### circuit_breaker

Open the circuit when a backend is unhealthy, preventing request pileup. Use this as a policy wrapping an entire origin (for per-target circuit breakers, use the load balancer target config instead).

```yaml
policies:
  - type: circuit_breaker
    enabled: true
    failure_threshold: 5
    success_threshold: 2
    timeout: 30s
    error_rate_threshold: 50.0
    half_open_requests: 3
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | required | Enable circuit breaker |
| `failure_threshold` | int | 5 | Failures to open circuit (max: 1000) |
| `success_threshold` | int | 2 | Successes to close from half-open (max: 100) |
| `timeout` | duration | 30s | How long circuit stays open |
| `error_rate_threshold` | float | 50.0 | Error rate % to open circuit |
| `half_open_requests` | int | 3 | Test requests in half-open state (max: 100) |

---

## Transforms

Transforms modify the response body before it reaches the client. They are specified as a list under `transforms` and run in order. Use transforms when you need to reshape API responses for different consumers.

### json

Reshape JSON responses by including or excluding fields.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    transforms:
      - type: json
        projection:
          include: [id, name, email, role]
```

Remove sensitive fields:

```yaml
transforms:
  - type: json
    projection:
      exclude: [password, ssn, internal_notes]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `json` |
| `projection.include` | []string | | Fields to keep (whitelist) |
| `projection.exclude` | []string | | Fields to remove (blacklist) |

### html

Modify HTML responses by injecting content into head or body.

```yaml
transforms:
  - type: html
    inject_head: '<link rel="stylesheet" href="https://cdn.example.com/override.css">'
    inject_body_start: '<div id="banner">Maintenance scheduled for tonight</div>'
    inject_body_end: '<script src="https://cdn.example.com/analytics.js"></script>'
```

### css

Rewrite CSS URLs to point to a CDN or different domain.

```yaml
transforms:
  - type: css
    rewrite_urls: true
    base_url: https://cdn.example.com/assets
```

---

## Request Modifiers

Request modifiers run CEL or Lua scripts to alter requests before they reach the action. Use them to add headers, rewrite paths, or inject computed values.

### CEL Request Modifier

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    request_modifiers:
      cel:
        - expression: >
            {
              "add_headers": {
                "X-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
                "X-Client-IP": request_ip
              }
            }
        - expression: >
            {
              "path": request.path.startsWith('/old/')
                ? '/new/' + request.path.substring(5)
                : request.path
            }
```

### Lua Request Modifier

```yaml
request_modifiers:
  lua:
    script: |
      local access_level = "guest"
      if ip.in_cidr(request_ip, "10.0.1.0/24") then
        access_level = "admin"
      elseif ip.in_cidr(request_ip, "10.0.0.0/16") then
        access_level = "user"
      end

      return {
        add_headers = {
          ["X-Access-Level"] = access_level
        },
        add_query = {
          access_level = access_level
        }
      }
```

### Available Request Modification Operations

| Field | Type | Description |
|-------|------|-------------|
| `add_headers` | map | Add or append headers |
| `set_headers` | map | Replace headers (overwrites existing) |
| `delete_headers` | list | Remove headers |
| `path` | string | Override request path |
| `method` | string | Override HTTP method |
| `add_query` | map | Add query parameters |
| `delete_query` | list | Remove query parameters |

---

## Response Modifiers

Response modifiers run CEL or Lua scripts to alter responses before they reach the client. Use them to add security headers, mask errors, or inject custom data.

### CEL Response Modifier

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    response_modifiers:
      cel:
        - expression: >
            {
              "add_headers": {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY"
              }
            }
        - expression: >
            response.status_code >= 500
              ? {
                  "status_code": 503,
                  "set_headers": {"Content-Type": "application/json"},
                  "body": "{\"error\": \"Service temporarily unavailable\"}"
                }
              : {}
```

### Lua Response Modifier

```yaml
response_modifiers:
  lua:
    script: |
      local allowed = location.country_code == "US" or
                      location.country_code == "CA"

      if not allowed then
        return {
          status_code = 451,
          set_headers = {
            ["Content-Type"] = "application/json"
          },
          body = '{"error": "Content not available in your region"}'
        }
      end

      return {
        add_headers = {
          ["X-Content-Type-Options"] = "nosniff",
          ["X-Frame-Options"] = "DENY"
        },
        delete_headers = {"X-Powered-By", "Server"}
      }
```

### Available Response Modification Operations

| Field | Type | Description |
|-------|------|-------------|
| `add_headers` | map | Add or append headers |
| `set_headers` | map | Replace headers |
| `delete_headers` | list | Remove headers |
| `status_code` | int | Override response status code |
| `body` | string | Override response body |

### JSON-Specific Response Modifications

| Field | Type | Description |
|-------|------|-------------|
| `set_fields` | map | Add or update JSON fields |
| `delete_fields` | list | Remove JSON fields |
| `modified_json` | map | Replace entire JSON object |

Example - strip sensitive fields and add computed fields:

```yaml
response_modifiers:
  cel:
    - expression: >
        {
          "delete_fields": ["password", "ssn", "credit_card"],
          "set_fields": {
            "full_name": json.first_name + " " + json.last_name,
            "is_adult": json.age >= 18
          }
        }
```

---

## Response Cache

Cache responses at the origin level. Use this to reduce backend load and improve response times for cacheable content. The `response_cache` block is a sibling of `action`.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    response_cache:
      enabled: true
      ttl: 5m
      conditions:
        methods: [GET, HEAD]
        status_codes: [200, 301]
        max_size: 1048576
      vary_by: [Authorization, Accept-Language]
      ignore_no_cache: false
      cache_private: false
      stale_while_revalidate:
        enabled: true
        duration: 30s
        stale_if_error: 60s
        async_revalidate: true
      invalidation:
        on_methods: [POST, PUT, DELETE]
        pattern: "/api/.*"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable response caching |
| `ttl` | duration | 5m | Cache time-to-live |
| `cache_key` | string | | Custom cache key template |
| `vary_by` | []string | | Headers to include in cache key |
| `conditions.methods` | []string | [GET] | HTTP methods to cache |
| `conditions.status_codes` | []int | [200] | Status codes to cache |
| `conditions.min_size` | int | 0 | Minimum response size to cache |
| `conditions.max_size` | int | | Maximum response size to cache |
| `ignore_no_cache` | bool | false | Cache even if Cache-Control says no-cache |
| `cache_private` | bool | false | Cache responses with Cache-Control: private |
| `store_non_200` | bool | false | Cache non-200 responses (404, 301, etc.) |
| `invalidation.on_methods` | []string | | Methods that trigger cache invalidation |
| `invalidation.pattern` | string | | URL pattern for invalidation |

### Stale-While-Revalidate

Serve stale content while refreshing the cache in the background. This keeps latency low even when cache entries expire.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable stale-while-revalidate |
| `duration` | duration | | How long to serve stale while revalidating |
| `stale_if_error` | duration | | Serve stale on backend error |
| `max_age` | duration | | Maximum age before stale cannot be served |
| `async_revalidate` | bool | true | Revalidate in background |

---

## Forward Rules

Forward rules route specific requests to different origins based on path, header, or other conditions. They are evaluated in order; the first match wins. Use this for path-based microservice routing or version routing.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://default-backend.internal:8080
    forward_rules:
      # Route /api/v2/* to the v2 backend
      - rules:
          - path:
              prefix: /api/v2/
        origin:
          id: v2-backend
          hostname: v2-backend
          workspace_id: example
          version: "2.0.0"
          action:
            type: proxy
            url: https://v2-backend.internal:8080

      # Route /health to a static response
      - rules:
          - path:
              exact: /health
        origin:
          id: health
          hostname: health
          workspace_id: example
          version: "1.0.0"
          action:
            type: static
            status_code: 200
            content_type: application/json
            json_body:
              status: healthy

      # Route mobile users to mobile backend
      - rules:
          - user_agent:
              os_families: [iOS, Android]
        origin:
          id: mobile-backend
          hostname: mobile-backend
          workspace_id: example
          version: "1.0.0"
          action:
            type: proxy
            url: https://mobile-backend.internal:8080
```

### Rule Matching

Each forward rule has a `rules` array where each entry is a `RequestRule` with these match conditions:

| Field | Type | Description |
|-------|------|-------------|
| `methods` | []string | Match specific HTTP methods |
| `path.prefix` | string | Path starts with this value |
| `path.exact` | string | Path exactly matches this value |
| `path.regex` | string | Path matches this regex |
| `path.suffix` | string | Path ends with this value |
| `headers.required` | map | Headers that must be present with specific values |
| `headers.present` | []string | Headers that must exist (any value) |
| `query.required` | map | Query parameters that must match |
| `ip.cidrs` | []string | Client IP must be in one of these CIDRs |
| `location.countries` | []string | GeoIP country codes |
| `user_agent.os_families` | []string | User agent OS family |
| `content_types` | []string | Request content types |
| `protocol` | string | Protocol: http1, http2, http3, websocket, grpc |

### Inline Origins

Forward rules embed full origin configurations via the `origin` field. Each inline origin can have its own action, authentication, policies, and transforms - exactly like a top-level origin.

```yaml
forward_rules:
  - rules:
      - path:
          prefix: /admin/
    origin:
      id: admin
      hostname: admin
      workspace_id: example
      version: "1.0.0"
      action:
        type: proxy
        url: https://admin-backend.internal:8080
      authentication:
        type: basic_auth
        users:
          - username: admin
            password: ${ADMIN_PASSWORD}
      policies:
        - type: rate_limit
          requests_per_minute: 30
```

---

## Variables, Vaults, and Secrets

### Variables

User-defined key-value pairs available in template context as `{{ variables.name }}`. Variables can be any JSON type, including nested objects.

```yaml
origins:
  "api.example.com":
    variables:
      api_version: v2
      base_url: https://api.example.com
      feature_flags:
        new_ui: true
        beta_api: false
    action:
      type: proxy
      url: "{{ variables.base_url }}/{{ variables.api_version }}"
```

### Vaults

Vaults load secrets from external sources at startup. Define vault backends, then reference secrets by vault name and key path.

**File vault:**

```yaml
origins:
  "api.example.com":
    vaults:
      local:
        type: file
        address: /etc/sbproxy/secrets.json
    secrets:
      db_password: "local:db_password"
      api_token: "local:api_token"
    action:
      type: proxy
      url: https://backend.internal:8080
```

**HTTP vault:**

```yaml
vaults:
  configserver:
    type: http
    url: https://config.internal/secrets
    method: GET
    headers:
      Authorization: "Bearer ${CONFIG_TOKEN}"
```

**Supported vault types:** `file`, `http`, `aws`, `gcp`.

| Field | Type | Description |
|-------|------|-------------|
| `type` | VaultType | Vault backend type: file, http, aws, gcp |
| `address` | string | Vault address or file path |
| `auth_method` | string | Authentication method for the vault |
| `namespace` | string | Vault namespace |
| `region` | string | Cloud region (for aws, gcp) |
| `project_id` | string | GCP project ID |
| `url` | string | HTTP endpoint (for http vaults) |
| `method` | string | HTTP method (for http vaults) |
| `headers` | map | HTTP headers (for http vaults) |

### Secrets

Secrets map names to vault references using the format `"vault_name:secret_path"`. Once loaded, secrets are available in templates as `{{ secrets.name }}`.

```yaml
secrets:
  database_url: "local:db_url"
  stripe_key: "aws:stripe/api_key"
```

### Template Scopes

Templates have access to these scopes:

| Scope | Description | Example |
|-------|-------------|---------|
| `request` | Current HTTP request | `{{ request.headers.x-api-key }}` |
| `variables` | User-defined variables | `{{ variables.api_version }}` |
| `secrets` | Loaded secrets | `{{ secrets.api_token }}` |
| `config` | Config metadata | `{{ config.hostname }}` |
| `session` | Session data | `{{ session.auth.email }}` |
| `env` | Config identity fields | `{{ env.workspace_id }}` |
| `server` | Server-level vars | `{{ server.var_name }}` |

---

## Events

Configure which event types this origin should emit. Events are sent to the configured messenger (Redis, in-memory, etc.) and can be consumed by external systems.

```yaml
origins:
  "api.example.com":
    events:
      - "circuit_breaker_open"
      - "circuit_breaker_closed"
      - "config_updated"
      - "ai.*"
      - "*"
```

**Event filter syntax:**

- Exact match: `"circuit_breaker_open"`
- Prefix wildcard: `"ai.*"` matches `ai.request.completed`, `ai.cost.tracked`, etc.
- Global wildcard: `"*"` matches all events

For the full list of event types and their payloads, see [events.md](events.md).

---

## Session Config

Configure session behavior for an origin. Sessions are stored in encrypted cookies and can persist backend cookies via a cookie jar.

```yaml
origins:
  "app.example.com":
    session_config:
      cookie_name: sb_session
      cookie_max_age: 3600
      cookie_same_site: Strict
      disable_http_only: false
      allow_non_ssl: false
      enable_cookie_jar: true
      cookie_jar_config:
        max_cookies: 100
        max_cookie_size: 4096
        store_secure_only: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `disabled` | bool | false | Disable sessions entirely |
| `cookie_name` | string | sb_session | Session cookie name |
| `cookie_max_age` | int | 3600 | Cookie lifetime in seconds |
| `cookie_same_site` | string | Lax | SameSite attribute (Strict, Lax, None) |
| `disable_http_only` | bool | false | If true, cookie is accessible to JavaScript |
| `allow_non_ssl` | bool | false | Allow sessions over HTTP (not just HTTPS) |
| `enable_cookie_jar` | bool | false | Store backend cookies in the session |

### Cookie Jar Config

When `enable_cookie_jar` is true, the proxy stores backend Set-Cookie headers in the session and replays them on subsequent requests.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_cookies` | int | 100 | Max cookies per session (max: 500) |
| `max_cookie_size` | int | 4096 | Max single cookie size in bytes (max: 16384) |
| `store_secure_only` | bool | false | Only store cookies with Secure flag |

---

## Failure Mode

Control what happens when an optional subsystem fails. This is configured at the origin level or per-subsystem in the action block.

```yaml
origins:
  "api.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
      default_model: gpt-4o-mini
      failure_mode: open
      failure_overrides:
        guardrails: closed
        rate_limiting: open
        cache: open
```

| Value | Behavior |
|-------|----------|
| `open` | Allow requests through when a subsystem fails (best effort). Good default for caching, rate limiting. |
| `closed` | Reject requests when a subsystem fails (fail safe). Use for security-critical subsystems like guardrails. |

Guardrails default to `closed`. Everything else defaults to `open`.

---

## Environment Variables

Reference environment variables anywhere in the config with `${VAR_NAME}` syntax. This keeps secrets out of config files.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: ${BACKEND_URL}
    authentication:
      type: api_key
      api_keys:
        - ${API_KEY}
```

Environment variables are resolved at config load time. If a variable is not set, the literal `${VAR_NAME}` string is preserved (it does not fail).

**Common pattern:** Use `.env` files with your shell or Docker:

```bash
export BACKEND_URL=https://backend.internal:8080
export API_KEY=my-secret-key
sbproxy serve -f sb.yml
```

---

## ACME / Auto TLS

sbproxy can automatically provision and renew TLS certificates using the ACME protocol (Let's Encrypt or any ACME-compatible CA).

### Production Setup (Let's Encrypt)

```yaml
proxy:
  http_bind_port: 80
  https_bind_port: 443
  certificate_settings:
    use_acme: true
    acme_email: admin@example.com
    acme_cache_dir: /etc/sbproxy/certs

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    force_ssl: true
```

The proxy handles the ACME HTTP-01 challenge automatically on port 80. Certificates are cached in `acme_cache_dir` and renewed before expiry.

### Local Development (Pebble)

For local testing, use Pebble as a test ACME server:

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  certificate_settings:
    use_acme: true
    acme_email: test@example.com
    acme_directory_url: https://pebble:14000/dir
    acme_insecure_skip_verify: true
    acme_cache_dir: /tmp/certs
```

### mTLS (Mutual TLS)

For client certificate authentication on inbound connections:

```yaml
proxy:
  https_bind_port: 8443
  certificate_settings:
    use_acme: true
    acme_email: admin@example.com
    client_auth: require_and_verify
    client_ca_cert_file: /etc/sbproxy/client-ca.pem
```

---

## Redis Integration

Redis serves two purposes in sbproxy: distributed caching (L2 cache) and real-time messaging (config sync, cache invalidation).

### L2 Cache (Distributed Rate Limiting and Caching)

```yaml
l2_cache_settings:
  driver: redis
  params:
    dsn: redis://redis.internal:6379/0
```

When configured, rate limit counters are shared across all proxy instances. Response cache entries can also be stored in Redis for shared caching.

### Messenger (Real-Time Config Updates)

```yaml
messenger_settings:
  driver: redis
  params:
    addr: redis.internal:6379
```

When configured, config changes pushed via the API propagate to all proxy instances in real time via Redis pub/sub.

### Full Redis Setup

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443

l2_cache_settings:
  driver: redis
  params:
    dsn: redis://redis.internal:6379/0

messenger_settings:
  driver: redis
  params:
    addr: redis.internal:6379

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    policies:
      - type: rate_limit
        requests_per_minute: 100
        algorithm: sliding_window
    response_cache:
      enabled: true
      ttl: 5m
```

---

## Validation

Check your configuration for errors without starting the proxy:

```bash
sbproxy validate -c sb.yml
```

This catches:
- YAML syntax errors
- Missing required fields (action type, URLs)
- Invalid field values (bad status codes, out-of-range durations)
- Unknown action types or policy types
- CEL expression compilation errors

Validate every config change before deploying to production.

---

## CORS

Cross-Origin Resource Sharing can be configured as a top-level origin field:

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    cors:
      enable: true
      allow_origins: ["https://app.example.com", "https://admin.example.com"]
      allow_methods: [GET, POST, PUT, DELETE, OPTIONS]
      allow_headers: [Content-Type, Authorization, X-Requested-With]
      expose_headers: [X-Request-ID, X-RateLimit-Remaining]
      max_age: 3600
      allow_credentials: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable` | bool | false | Enable CORS header injection |
| `allow_origins` | []string | | Allowed origins (use ["*"] for any) |
| `allow_methods` | []string | standard methods | Allowed HTTP methods |
| `allow_headers` | []string | standard headers | Allowed request headers |
| `expose_headers` | []string | | Headers exposed to browser |
| `max_age` | int | | Preflight cache duration in seconds |
| `allow_credentials` | bool | false | Allow credentials (cookies, auth headers) |

---

## Quick Reference: Config Field Locations

A common mistake is nesting fields inside `action` when they should be siblings. Here is the correct layout:

```yaml
origins:
  "api.example.com":
    # These are ALL at the same level (siblings of action):
    action: { ... }
    authentication: { ... }
    policies: [ ... ]
    transforms: [ ... ]
    request_modifiers: { ... }
    response_modifiers: { ... }
    forward_rules: [ ... ]
    response_cache: { ... }
    variables: { ... }
    vaults: { ... }
    secrets: { ... }
    session_config: { ... }
    events: [ ... ]
    cors: { ... }
    compression: { ... }
    error_pages: [ ... ]
```

None of these belong inside the `action` block. The `action` block only contains action-specific fields (type, url, targets, providers, etc.).
