# SBproxy Configuration Reference

*Last modified: 2026-05-03*

The complete configuration reference for SBproxy. Every option, every field, every action type is documented here with real-world examples you can copy-paste and run.

For AI-specific features in depth, see [ai-gateway.md](ai-gateway.md). For CEL, Lua, JavaScript, and WASM scripting, see [scripting.md](scripting.md). For the event system, see [events.md](events.md).

## Table of contents

1. [Overview](#overview)
2. [Top-level structure](#top-level-structure)
3. [Proxy settings](#proxy-settings)
4. [Origins](#origins)
5. [Actions](#actions)
6. [Authentication](#authentication)
7. [Policies](#policies)
8. [Transforms](#transforms)
9. [Request modifiers](#request-modifiers)
10. [Response modifiers](#response-modifiers)
11. [Response cache](#response-cache)
12. [Forward rules](#forward-rules)
13. [Fallback origin](#fallback-origin)
14. [Variables, vaults, and secrets](#variables-vaults-and-secrets)
15. [Session config](#session-config)
16. [Compression](#compression)
17. [HSTS](#hsts)
18. [Connection pool](#connection-pool)
19. [Bot detection](#bot-detection)
20. [Threat protection](#threat-protection)
21. [Error pages](#error-pages)
22. [Rate limit headers](#rate-limit-headers)
23. [Message signatures](#message-signatures)
24. [Traffic capture](#traffic-capture)
25. [Host header semantics](#host-header-semantics)
26. [Trusted proxies and forwarding headers](#trusted-proxies-and-forwarding-headers)
27. [Request mirror](#request-mirror)
28. [Upstream retries](#upstream-retries)
29. [Active health checks](#active-health-checks)
30. [Circuit breaker](#circuit-breaker)
31. [Outlier detection](#outlier-detection)
32. [Service discovery](#service-discovery)
33. [Correlation ID](#correlation-id)
34. [mTLS client authentication](#mtls-client-authentication)
35. [Webhook envelope and signing](#webhook-envelope-and-signing)
36. [Secrets](#secrets)
37. [Environment variables](#environment-variables)
38. [ACME / auto TLS](#acme--auto-tls)
39. [Redis integration](#redis-integration)
40. [Validation](#validation)

---

## Overview

SBproxy reads its configuration from a YAML file, typically named `sb.yml`. This file defines how the proxy listens for traffic, which hostnames it handles, and what it does with each request.

Load a config file:

```bash
# Default (looks for sb.yml in current directory)
sbproxy serve

# Custom path
sbproxy serve -f /etc/sbproxy/production.yml
```

Validate without starting:

```bash
sbproxy validate -c sb.yml
```

The config has two main sections: `proxy` (server-level settings) and `origins` (per-hostname routing and behavior). Optional shared-state blocks (`l2_cache_settings`, `messenger_settings`) live nested under `proxy`.

---

## Top-level structure

Complete YAML skeleton with every top-level key:

```yaml
# Server settings (ports, TLS, ACME, admin, secrets, shared state)
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  tls_cert_file: /etc/sbproxy/cert.pem
  tls_key_file: /etc/sbproxy/key.pem
  acme: { ... }
  http3: { ... }
  metrics: { ... }
  alerting: { ... }
  admin: { ... }
  secrets: { ... }

  # L2 cache (Redis) for distributed rate limiting and caching
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://localhost:6379/0

  # Messenger (Redis) for real-time config updates
  messenger_settings:
    driver: redis
    params:
      dsn: redis://localhost:6379

  # Opaque per-server extensions consumed by enterprise / third-party crates.
  extensions: { ... }

# Per-hostname origin configurations
origins:
  "api.example.com":
    action: { ... }
    authentication: { ... }
    policies: [ ... ]
    transforms: [ ... ]
    request_modifiers: [ ... ]
    response_modifiers: [ ... ]
    forward_rules: [ ... ]
    response_cache: { ... }
    variables: { ... }
    session: { ... }
    cors: { ... }
    compression: { ... }
    hsts: { ... }
    connection_pool: { ... }
    extensions: { ... }
```

`l2_cache_settings` and `messenger_settings` are nested under `proxy:` (the deserializer also accepts `l2_cache` as a canonical alias).

---

## Proxy settings

The `proxy` block configures server-level behavior: ports, TLS, ACME, the admin API, metrics, secrets, and the optional shared-state backends.

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  tls_cert_file: /etc/sbproxy/cert.pem
  tls_key_file: /etc/sbproxy/key.pem

  acme:
    enabled: true
    email: admin@example.com
    storage_path: /var/lib/sbproxy/certs

  http3:
    enabled: false

  metrics:
    max_cardinality_per_label: 1000

  admin:
    enabled: false
    port: 9090
```

### Proxy fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_bind_port` | int | 8080 | HTTP listen port |
| `https_bind_port` | int | unset | Optional HTTPS listen port. Requires `tls_cert_file` + `tls_key_file` or an `acme` block. |
| `tls_cert_file` | string | | Path to PEM-encoded TLS certificate. Ignored when `acme` is configured. |
| `tls_key_file` | string | | Path to PEM-encoded TLS private key. |
| `acme` | object | | ACME (auto-TLS) block. Overrides manual cert/key when set. See [ACME / auto TLS](#acme--auto-tls). |
| `http3` | object | | HTTP/3 (QUIC) listener config. |
| `metrics` | object | | Metrics tuning, including label cardinality limits. |
| `alerting` | object | | Alert notification channels. |
| `admin` | object | | Embedded read-only admin / stats API server. |
| `secrets` | object | | Secrets management backend. See [Secrets](#secrets). |
| `l2_cache_settings` | object | | Optional shared-state backend. Alias: `l2_cache`. |
| `messenger_settings` | object | | Optional shared message bus for inter-component eventing. |
| `trusted_proxies` | array of CIDR strings | `[]` | Source ranges whose inbound `X-Forwarded-For` / `X-Real-IP` / `Forwarded` headers are honoured. Connections from outside the list have those headers stripped on ingress so they cannot spoof identity. IPv6 CIDRs work. See [Trusted proxies and forwarding headers](#trusted-proxies-and-forwarding-headers). |
| `correlation_id` | object | enabled, `X-Request-Id`, echo on | Correlation-ID propagation policy. See [Correlation ID](#correlation-id). |
| `mtls` | object | unset | mTLS client-certificate verification on the HTTPS listener. See [mTLS client authentication](#mtls-client-authentication). |
| `extensions` | object | | Opaque map for enterprise / third-party top-level config blocks. OSS never parses these. |

### HTTP/3 fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable the HTTP/3 (QUIC) listener |
| `max_streams` | int | 100 | Maximum concurrent QUIC streams per connection |
| `idle_timeout_secs` | int | 30 | Idle timeout for QUIC connections |

### Admin fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable the admin server |
| `port` | int | 9090 | Listen port |
| `username` | string | "admin" | HTTP Basic Auth username |
| `password` | string | "changeme" | HTTP Basic Auth password |
| `max_log_entries` | int | 1000 | Recent-request log buffer size |

When enabled, the admin server binds on `127.0.0.1:<port>` only,
gates every request behind HTTP Basic auth, and applies a 60-rps
per-IP rate limit. Endpoints:

| Path | Description |
|------|-------------|
| `GET /api/health` | Liveness check returning `{"status":"ok"}`. |
| `GET /api/openapi.json` | Emitted OpenAPI 3.0 document for the running pipeline. |
| `GET /api/openapi.yaml` | Same document in YAML. |

Unauthenticated requests get a 401 with a `WWW-Authenticate: Basic`
header. Requests from outside `127.0.0.1` are dropped at the
socket level.

### Metrics fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_cardinality_per_label` | int | 1000 | Cap on unique label values per metric. New values are collapsed to `__other__`. |

### access_log

Top-level block (sibling of `proxy:` and `origins:`) that turns on structured-JSON access logging. Off by default. When enabled, every completed request emits one JSON line at info level via the `access_log` tracing target after status, method, and sampling filters apply. Secrets are redacted before the line is written. See [Access log](access-log.md) for the full record shape.

```yaml
access_log:
  enabled: true
  sample_rate: 1.0
  status_codes: []           # empty = log every status
  methods: []                # empty = log every method
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch. When false, no access-log lines are emitted. |
| `sample_rate` | float | `1.0` | Probability in `[0.0, 1.0]` that a matching request is logged. |
| `status_codes` | list | `[]` | HTTP status codes to log. Empty matches every status. |
| `methods` | list | `[]` | HTTP methods to log (case-insensitive). Empty matches every method. |

### Alerting fields

The `proxy.alerting` block defines notification channels that receive alert events from the runtime.

```yaml
proxy:
  alerting:
    channels:
      - type: webhook
        url: https://hooks.example.com/sbproxy
        headers:
          X-Auth: ${ALERT_TOKEN}
      - type: log
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `channels` | list | `[]` | Notification channels. |
| `channels[].type` | string | required | Channel type. Supported: `webhook`, `log`. |
| `channels[].url` | string | | Webhook URL. Required when `type` is `webhook`. |
| `channels[].headers` | map | `{}` | Extra HTTP headers added to webhook deliveries. |
| `channels[].secret` | string | | Optional shared secret. When set, the dispatcher signs the payload with HMAC-SHA256 and emits `X-Sbproxy-Signature: v1=<hex>`. Receivers verify with `<X-Sbproxy-Timestamp>.<body>`. See [Webhook envelope and signing](#webhook-envelope-and-signing). |

Alert webhook deliveries also include the standard `X-Sbproxy-*` identity headers (`Event`, `Instance`, `Rule`, `Severity`, `Timestamp`) and a `User-Agent: sbproxy/<version>`. The body is wrapped in an envelope:

```json
{
  "event": "alert",
  "proxy": { "instance_id": "...", "version": "..." },
  "alert": { "rule": "...", "severity": "...", "message": "...", "timestamp": "...", "labels": { ... } }
}
```

### l2_cache_settings

The `l2_cache_settings` block points the proxy at a shared key-value backend used for cluster-wide rate limit counters and (optionally) response cache entries. When unset, every replica keeps its own in-memory state. The deserializer also accepts `l2_cache:` as an alias.

The `driver` field selects the backend; `params` is a flat string map whose keys depend on the driver. Only the `redis` driver is implemented in the Rust proxy today.

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://redis.internal:6379/0
```

`params` keys for the `redis` driver:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dsn` | string | | Connection string. Accepts `redis://[user[:pass]@]host:port[/db]`, `rediss://...`, or a bare `host:port`. The database index in the path is parsed but ignored by the single-connection RESP client. |

Pool size and acquire timeout are not exposed via `params` and use built-in defaults (pool size 8, acquire timeout 5 seconds).

### messenger_settings

The `messenger_settings` block configures the message bus the proxy uses for inter-component events such as config updates and semantic-cache purges. When unset, the proxy runs without a bus, which is fine for single-replica deployments.

The `driver` field picks the implementation; `params` is a flat string map whose keys depend on the driver. Unknown driver names cause startup to error.

```yaml
proxy:
  messenger_settings:
    driver: redis
    params:
      dsn: redis://redis.internal:6379
```

Supported drivers and their `params` keys:

`memory` takes no `params`. It uses bounded in-process channels and only works for a single replica.

`redis`:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dsn` | string | `redis://127.0.0.1:6379` | Redis connection string. Same parsing rules as the L2 cache `dsn`. |

`sqs` (all required):

| Key | Type | Description |
|-----|------|-------------|
| `queue_url` | string | Full SQS queue URL. |
| `region` | string | AWS region the queue lives in. |
| `api_key` | string | AWS access key used to sign requests. |

`gcp_pubsub` (all required):

| Key | Type | Description |
|-----|------|-------------|
| `project` | string | GCP project ID that owns the topic. |
| `topic` | string | Pub/Sub topic name. |
| `subscription` | string | Pub/Sub subscription name. |
| `access_token` | string | OAuth2 access token used on requests. |

---

## Origins

Each key under `origins` is a hostname. When a request arrives, SBproxy matches the `Host` header to an origin key and applies that origin's configuration. Every origin must have an `action` block.

```yaml
origins:
  "api.example.com":
    force_ssl: true
    allowed_methods: [GET, POST, PUT, DELETE]
    action:
      type: proxy
      url: https://backend.internal:8080
```

### Hostname matching

- Exact match: `"api.example.com"` matches only `api.example.com`.
- Wildcard match: `"*.example.com"` matches `api.example.com`, `www.example.com`, and so on. The wildcard must be the first character and only covers one subdomain level.
- Multiple origins: define as many as you need. Each has independent auth, policies, and routing.

### Origin fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `action` | object | required | What to do with the request (proxy, redirect, static, etc.). |
| `authentication` | object | | Auth provider. Alias: `auth`. |
| `policies` | list | | Policy enforcers (rate limit, IP filter, WAF, etc.). |
| `transforms` | list | | Body transforms applied in order. |
| `request_modifiers` | list | | Header / URL / query / body / script edits before the action. |
| `response_modifiers` | list | | Header / status / body / script edits after the action. |
| `cors` | object | | CORS header injection. |
| `hsts` | object | | HSTS header injection. |
| `compression` | object | | Response compression. |
| `session` | object | | Session cookie settings. Alias: `session_config`. |
| `force_ssl` | bool | false | Redirect plain HTTP requests to HTTPS. |
| `allowed_methods` | list | empty (allow all) | Whitelist of HTTP methods. |
| `forward_rules` | list | | Path / header / IP rules that route to inline child origins. |
| `fallback_origin` | object | | Inline origin served when the primary upstream errors or returns a configured status. See [Fallback origin](#fallback-origin). |
| `response_cache` | object | | Per-origin response cache. |
| `variables` | map | | Static template variables. |
| `on_request` | list | | Webhook callbacks invoked when a request enters the origin. Each entry accepts `url`, `method` (default POST), `secret` (HMAC), `timeout` (seconds), `on_error`. Lua callbacks are also accepted. See [Webhook envelope and signing](#webhook-envelope-and-signing). |
| `on_response` | list | | Same shape as `on_request`; fired after the upstream response is observed. Payload includes `status` and `duration_ms`. |
| `mirror` | object | | Shadow traffic configuration. See [Request mirror](#request-mirror). |
| `bot_detection` | object | | Bot detection config. |
| `threat_protection` | object | | IP reputation / blocklist config. |
| `rate_limit_headers` | object | | `X-RateLimit-*` and `Retry-After` header configuration. |
| `error_pages` | list | | Custom error pages keyed by status code or class. |
| `traffic_capture` | object | | Traffic capture / mirroring. |
| `message_signatures` | object | | RFC 9421 HTTP message signatures. |
| `connection_pool` | object | | Per-origin connection pool tuning. |
| `extensions` | object | | Opaque map for enterprise / third-party origin-level blocks. |

### Origin architecture

Every origin config block supports the fields above as siblings. They sit at the same level as `action`, never inside it:

```yaml
origins:
  "api.example.com":
    action: { ... }              # Required
    authentication: { ... }      # Optional
    policies: [ ... ]            # Optional
    transforms: [ ... ]          # Optional
    request_modifiers: [ ... ]   # Optional
    response_modifiers: [ ... ]  # Optional
    forward_rules: [ ... ]       # Optional
    response_cache: { ... }      # Optional
    variables: { ... }           # Optional
    session: { ... }             # Optional
    cors: { ... }                # Optional
    compression: { ... }         # Optional
    hsts: { ... }                # Optional
    connection_pool: { ... }     # Optional
```

---

## Actions

The `action` block defines what the proxy does with a matched request. The `type` field selects the handler.

### proxy

Forward requests to an upstream URL. The most common action type, and the right choice when SBproxy sits in front of an existing backend.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
      strip_base_path: false
      preserve_query: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Upstream URL to forward requests to |
| `strip_base_path` | bool | false | Strip the matched origin path before forwarding |
| `preserve_query` | bool | false | Forward the original query string to the upstream |
| `host_override` | string | unset | Override the upstream `Host` header. Default is the upstream URL's hostname (so vhost-routed services like Vercel, Cloudflare-fronted origins, S3, ALBs work without configuration). See [Host header semantics](#host-header-semantics). |
| `sni_override` | string | unset | Override the SNI server name sent during the upstream TLS handshake (and the cert verification target). Use when the cert's hostname differs from the URL host. See [Origin overrides](#origin-overrides). |
| `resolve_override` | string | unset | Pin the upstream connect address, bypassing DNS for the URL host. Accepts `ip`, `ip:port`, `[ipv6]:port`, or `host:port`. Equivalent to `curl --connect-to`. See [Origin overrides](#origin-overrides). |
| `service_discovery` | object | unset | DNS-based service discovery. Re-resolves the upstream hostname on a TTL. See [Service discovery](#service-discovery). |
| `disable_forwarded_host_header` | bool | false | Suppress the `X-Forwarded-Host` header that the proxy would otherwise set to the client's original `Host` whenever it rewrites the upstream `Host`. |
| `disable_forwarded_for_header` | bool | false | Suppress `X-Forwarded-For` (the client IP appended to the chain). |
| `disable_real_ip_header` | bool | false | Suppress `X-Real-IP`. |
| `disable_forwarded_proto_header` | bool | false | Suppress `X-Forwarded-Proto` (`http`/`https`). |
| `disable_forwarded_port_header` | bool | false | Suppress `X-Forwarded-Port` (the listener port). |
| `disable_forwarded_header` | bool | false | Suppress the RFC 7239 `Forwarded` header. |
| `disable_via_header` | bool | false | Suppress the `Via: 1.1 sbproxy` header. |
| `retry` | object | unset | Upstream retry policy. See [Upstream retries](#upstream-retries). |

The same `host_override` and `disable_*_header` flags are accepted on every URL-bearing action: `proxy`, `load_balancer` targets, `websocket`, `grpc` (via the `:authority` field), `graphql`, `a2a`, and `forward_auth`.

### static

Return a fixed response without proxying to any upstream. Good for health check endpoints, maintenance pages, and mock APIs.

```yaml
origins:
  "status.example.com":
    action:
      type: static
      status: 200
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
| `status` | int | 200 | HTTP status code (alias: `status_code`) |
| `content_type` | string | | Content-Type header |
| `body` | string | | Plain text or HTML body (alias: `text_body`) |
| `json_body` | object | | JSON body. Auto-sets Content-Type to application/json. Overrides `body`. |
| `headers` | map | | Additional response headers |

### redirect

Return an HTTP redirect. Common uses: domain migrations, HTTPS enforcement, URL shortening, large URL lookup tables.

```yaml
origins:
  "old.example.com":
    action:
      type: redirect
      url: https://new.example.com
      status: 302
      preserve_query: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required* | Redirect target URL. Required when `bulk_list` is unset. |
| `status` | int | 302 | HTTP status code (alias: `status_code`). |
| `preserve_query` | bool | false | Preserve original query string. |
| `bulk_list` | object | unset | Per-origin bulk redirect source. See [bulk-redirects.md](bulk-redirects.md). |

`bulk_list` accepts three source types: `inline` (rows embedded in YAML), `file` (CSV or YAML on disk; CSV detected by `.csv` suffix), and `url` (HTTPS document fetched at config-load). Per-row `status` and `preserve_query` overrides win when set; otherwise rows inherit the action's defaults. Unmapped paths fall through to the action's `url:` (or 404 when `url:` is empty).

```yaml
origins:
  "marketing.local":
    action:
      type: redirect
      status_code: 301
      preserve_query: true
      bulk_list:
        type: file
        path: /etc/sbproxy/marketing-redirects.csv
```

### echo

Return the incoming request as a JSON response. Handy for debugging proxy behavior, testing forward rules, and verifying that headers and auth are set up correctly. Echo takes no fields.

```yaml
origins:
  "debug.example.com":
    action:
      type: echo
```

### mock

Return a fixed JSON response for API mocking. Optionally injects an artificial delay so you can test slow-backend behavior.

```yaml
origins:
  "mock.example.com":
    action:
      type: mock
      status: 200
      body:
        ok: true
        message: "mocked"
      headers:
        X-Mock: "true"
      delay_ms: 250
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | int | 200 | HTTP status code |
| `body` | object | `null` | JSON body returned to the client |
| `headers` | map | | Additional response headers |
| `delay_ms` | int | | Optional artificial delay in milliseconds |

### beacon

Return a 1x1 transparent GIF. Useful for tracking pixel endpoints. Beacon takes no fields.

```yaml
origins:
  "px.example.com":
    action:
      type: beacon
```

### load_balancer

Distribute traffic across multiple backend targets when you have several instances of a service.

```yaml
origins:
  "api.example.com":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: https://backend-1.internal:8080
          weight: 70
        - url: https://backend-2.internal:8080
          weight: 30
      sticky:
        cookie_name: sb_sticky
        ttl: 3600
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `targets` | list | required | Backend targets. |
| `algorithm` | string \| object | `round_robin` | Routing algorithm (see below). |
| `sticky` | object | | Sticky-session config: `cookie_name` (default `sb_sticky`), `ttl` seconds. |
| `deployment_mode` | object | `{mode: normal}` | Deployment mode. See below. |
| `outlier_detection` | object | unset | Passive ejection policy. See [Outlier detection](#outlier-detection). |

Algorithms:

| Algorithm | Description |
|-----------|-------------|
| `round_robin` | Cycle through active targets in order (default). |
| `weighted_random` | Pick a target with probability proportional to its weight. |
| `least_connections` | Route to the target with the fewest in-flight requests. |
| `ip_hash` | Hash the client IP to a target (sticky by client). |
| `uri_hash` | Hash the request URI to a target (sticky by path). |
| `header_hash` | Hash a named request header. Configured as `algorithm: { header_hash: { header: X-User } }`. |
| `cookie_hash` | Hash a named cookie. Configured as `algorithm: { cookie_hash: { cookie: sid } }`. |

Target fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend URL. |
| `weight` | int | 1 | Weight used by weighted algorithms. |
| `backup` | bool | false | Reserved for fallback. Excluded from normal selection. |
| `group` | string | | Deployment group label (`blue`, `green`, `canary`). |
| `priority` | int | 5 | Routing priority (1 = highest, 10 = lowest). Read from `X-Priority` header when not set here. |
| `zone` | string | | Availability zone or region label for locality-aware routing. |
| `health_check` | object | | Active health-check probe config. See [Active health checks](#active-health-checks). |
| `host_override` | string | unset | Override the upstream `Host` for this target. Default is the target URL's hostname. |
| `disable_*_header` | bool | false | Same per-header opt-outs as on `proxy` actions; see [Forwarding headers](#trusted-proxies-and-forwarding-headers). |

#### Blue-green deployments

Route 100% of traffic to the named active group. Targets must have a `group` field set to `blue` or `green`.

```yaml
action:
  type: load_balancer
  deployment_mode:
    mode: blue_green
    active: green
  targets:
    - url: https://blue.internal:8080
      group: blue
    - url: https://green.internal:8080
      group: green
```

#### Canary deployments

Route a configurable percentage of requests to canary targets (group `canary`); remaining traffic goes to primary targets.

```yaml
action:
  type: load_balancer
  deployment_mode:
    mode: canary
    weight: 10            # 10% to canary
  targets:
    - url: https://primary.internal:8080
    - url: https://canary.internal:8080
      group: canary
```

### websocket

Proxy WebSocket connections for real-time applications, chat systems, and streaming APIs.

```yaml
origins:
  "ws.example.com":
    action:
      type: websocket
      url: wss://ws-backend.internal:8080
      subprotocols: [graphql-ws, graphql-transport-ws]
      max_message_size: 5242880
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend WebSocket URL (ws:// or wss://) |
| `subprotocols` | list | | Supported WebSocket subprotocols |
| `max_message_size` | int | 10485760 | Maximum message payload size in bytes (10 MB) |

### grpc

Proxy gRPC traffic for microservice architectures.

```yaml
origins:
  "grpc.example.com":
    action:
      type: grpc
      url: grpcs://grpc-backend.internal:50051
      tls: true
      authority: grpc-backend.internal
      timeout_secs: 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend gRPC URL (`grpc://`, `grpcs://`, `http://`, `https://`) |
| `tls` | bool | false | Force TLS regardless of URL scheme |
| `authority` | string | | Override the HTTP/2 `:authority` pseudo-header |
| `timeout_secs` | int | 30 | Request timeout in seconds |

### ai_proxy

Route requests across LLM providers with automatic failover, cost tracking, and content-based routing. Supports many native providers; route through OpenRouter for hundreds of models. For full details, see [ai-gateway.md](ai-gateway.md) and [providers.md](providers.md).

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini, gpt-4-turbo]
          default_model: gpt-4o-mini
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514, claude-3-5-haiku-20241022]
      routing: fallback_chain
      allowed_models: [gpt-4o, gpt-4o-mini, claude-3-5-haiku-20241022]
      blocked_models: []
      max_body_size: 4194304
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `providers` | list | required | Configured upstream AI providers. |
| `routing` | string \| object | `round_robin` | Routing strategy. Either a flat string or `{strategy: ..., ...}`. |
| `allowed_models` | list | empty (allow all) | Allow-list of model names. |
| `blocked_models` | list | | Block-list of model names. Takes precedence over allow-list. |
| `max_body_size` | int | | Maximum request body size in bytes. |
| `guardrails` | object | | Input/output guardrails pipeline. |
| `budget` | object | | Budget enforcement configuration. |
| `virtual_keys` | list | | Virtual API keys mapped to provider keys and scopes. |
| `model_rate_limits` | map | | Per-model rate limit overrides keyed by model name. |
| `max_concurrent` | map | | Maximum concurrent in-flight requests per provider. |
| `resilience` | object | | Per-provider circuit breaker, outlier detection, and active health probes. |
| `shadow` | object | | Side-by-side eval: mirror each request to a second provider and log metrics. |

Routing strategies: `round_robin`, `weighted`, `fallback_chain`, `random`, `lowest_latency`, `least_connections`, `cost_optimized`, `token_rate`, `sticky`, `race`.

`default_model` is a per-provider field, not an action-level field. Set it on each `providers[]` entry.

#### AI provider fields (`providers[]`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique provider name used to reference this entry. |
| `provider_type` | string | inferred from `name` | Provider type (`openai`, `anthropic`, `google`, etc.). |
| `api_key` | string | | API key used to authenticate with the upstream. |
| `base_url` | string | provider default | Override the upstream base URL. |
| `models` | list | `[]` | Models served by this provider; empty defers to the provider catalog. |
| `default_model` | string | | Model used when the request omits an explicit model. |
| `model_map` | map | `{}` | Logical to upstream model name mapping. |
| `weight` | int | 1 | Weight used by weighted routing strategies. |
| `priority` | int | unset | Priority used by priority routing (lower runs first). |
| `enabled` | bool | true | When false, this provider is skipped during routing. |
| `max_retries` | int | unset | Maximum retries on transient upstream failures. |
| `timeout_ms` | int | unset | Request timeout in milliseconds. |
| `organization` | string | | Organization identifier for providers that scope keys per org. |
| `api_version` | string | | API version header value (e.g. for Anthropic and Azure OpenAI). |

#### Virtual keys (`virtual_keys[]`)

Virtual API keys map a client-facing key to provider keys, model allow-lists, and per-key rate limits.

```yaml
virtual_keys:
  - key: vk-prod-abc123
    name: production-app
    allowed_models: [gpt-4o-mini, claude-3-5-haiku-20241022]
    blocked_models: []
    allowed_providers: [openai, anthropic]
    max_tokens_per_minute: 10000
    max_requests_per_minute: 60
    budget:
      max_tokens: 1000000
      max_cost_usd: 50.0
    tags: [team-frontend]
    enabled: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `key` | string | required | The virtual key string clients send. |
| `name` | string | | Human-readable label. |
| `allowed_models` | list | `[]` | Models this key may use. Empty allows all. |
| `blocked_models` | list | `[]` | Models this key is blocked from using. |
| `allowed_providers` | list | `[]` | Providers this key may route to. Empty allows all. |
| `max_tokens_per_minute` | int | unset | Per-key tokens-per-minute limit. |
| `max_requests_per_minute` | int | unset | Per-key requests-per-minute limit. |
| `budget` | object | | Per-key total budget (`max_tokens`, `max_cost_usd`). |
| `tags` | list | `[]` | Free-form tags surfaced in metrics. |
| `enabled` | bool | true | When false, the key is rejected. |

#### Budget (`budget`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `limits` | list | `[]` | Budget rules. See below. |
| `on_exceed` | string | `block` | Action when a limit is hit: `block`, `log`, `downgrade`. |

Each `limits[]` entry:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scope` | string | required | `workspace`, `api_key`, `user`, `model`, `origin`, or `tag`. |
| `max_tokens` | int | unset | Maximum tokens for this scope. |
| `max_cost_usd` | float | unset | Maximum spend in USD for this scope. |
| `period` | string | unset | Time window: `daily`, `monthly`, `total`. |
| `downgrade_to` | string | | Model to swap to when `on_exceed: downgrade`. |

#### Per-model rate limits (`model_rate_limits`)

Keyed by model name; each entry has `requests_per_minute` and `tokens_per_minute`.

```yaml
model_rate_limits:
  gpt-4o:
    requests_per_minute: 60
    tokens_per_minute: 200000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `requests_per_minute` | int | unset | Requests-per-minute cap for this model. |
| `tokens_per_minute` | int | unset | Tokens-per-minute cap for this model. |

#### Guardrails (`guardrails`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `input` | list | `[]` | Guardrails evaluated against the incoming request body. |
| `output` | list | `[]` | Guardrails evaluated against the model output. |

Each entry is an object with a `type` field and type-specific config. Built-in types: `pii`, `secrets`, `injection` (alias `prompt_injection`), `toxicity`, `jailbreak`, `content_safety`, `schema`, `regex`, `regex_guard`. See [ai-gateway.md](ai-gateway.md) for per-guardrail fields.

See the [AI Gateway Guide](ai-gateway.md) for CEL selectors, Lua hooks, guardrails, context window validation, cost headers, and streaming behavior.

#### Resilience (`resilience`)

Three independent signals that eject misbehaving providers from the routing pool. Any signal alone is enough to skip a provider; when every provider is ejected, the router falls back to the unfiltered enabled list rather than returning no provider at all.

```yaml
resilience:
  circuit_breaker:
    failure_threshold: 5      # consecutive 5xx / transport errors before opening
    success_threshold: 2      # half-open successes before closing
    open_duration_secs: 30    # cooldown before half-open probe
  outlier_detection:
    threshold: 0.5            # eject when failure rate >= 50%
    window_secs: 60           # sliding window
    min_requests: 5           # minimum sample before ejecting
    ejection_duration_secs: 30
  health_check:
    path: /models             # GET endpoint probed on each provider
    interval_secs: 30
    timeout_ms: 5000
    unhealthy_threshold: 3
    healthy_threshold: 2
```

When `resilience` is set, retries fan across providers up to `min(providers.len(), 5)` attempts; ejected providers are skipped on the second and later attempts.

#### Shadow (`shadow`)

Mirrors each request to a second provider concurrently. The primary's response is what the client sees; the shadow body is drained and metrics are logged at `target: sbproxy_ai_shadow` (status, latency, prompt/completion tokens, finish_reason). Useful for prompt regression checks before swapping a primary model.

```yaml
shadow:
  provider: anthropic         # must also appear in `providers`
  model: claude-3-5-haiku-latest   # optional override; defaults to client's model
  sample_rate: 0.1            # mirror 10% of traffic; 1.0 mirrors all
  timeout_ms: 30000
```

#### Race strategy (`routing.strategy: race`)

Fans the request out to every eligible provider in parallel; returns the first 2xx and cancels the in-flight losers. Failures still feed `resilience` so persistently slow providers eventually drop out of the eligible set. Use sparingly: race fans up your provider spend by N until one wins.

```yaml
routing:
  strategy: race
providers:
  - name: openai
    api_key: ${OPENAI_API_KEY}
  - name: anthropic
    api_key: ${ANTHROPIC_API_KEY}
```

### graphql

Proxy GraphQL requests to an upstream HTTP endpoint with optional query depth limiting and introspection control.

```yaml
origins:
  "graphql.example.com":
    action:
      type: graphql
      url: https://graphql-backend.internal/graphql
      max_depth: 10
      allow_introspection: false
      validate_queries: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend GraphQL endpoint URL (`http://` or `https://`). |
| `max_depth` | int | 0 | Maximum query nesting depth. `0` means unlimited. |
| `allow_introspection` | bool | true | When false, introspection queries are rejected. |
| `validate_queries` | bool | false | When true, validate incoming GraphQL queries. |

### storage

Serve files from an object storage backend (S3, GCS, Azure Blob, or local filesystem). The OSS implementation currently returns a 501 placeholder; the action exists so configs validate and for future runtime support.

```yaml
origins:
  "static.example.com":
    action:
      type: storage
      backend: s3
      bucket: my-public-assets
      prefix: web/
      index_file: index.html
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | string | required | One of `s3`, `gcs`, `azure`, `local`. |
| `bucket` | string | | Bucket name. Required for `s3`, `gcs`, and `azure`. |
| `prefix` | string | | Key prefix prepended to request paths. May not contain `..` segments or NUL bytes. |
| `path` | string | | Local filesystem root. Required for `backend: local`. May not contain `..` segments or NUL bytes. |
| `index_file` | string | | Index file served for directory requests (e.g. `index.html`). May not contain `..` segments or NUL bytes. |

### a2a

Proxy requests to an Agent-to-Agent (A2A) endpoint that speaks the Google A2A protocol. The agent card metadata can be cached locally for discovery.

```yaml
origins:
  "agent.example.com":
    action:
      type: a2a
      url: https://agent-backend.internal/a2a
      agent_card:
        name: SearchAgent
        version: "1.0"
        capabilities: [text, tool-use]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Upstream agent URL. |
| `agent_card` | object | | Cached A2A agent card (free-form JSON). |

---

## Authentication

The `authentication` block is a sibling of `action`, not nested inside it. It controls who can access the origin. SBproxy ships eight built-in auth providers: `api_key`, `basic_auth`, `bearer`, `jwt`, `digest`, `forward_auth`, `bot_auth`, and `noop`.

`bot_auth` verifies cryptographically-signed AI agents per RFC 9421 + the IETF Web Bot Auth draft. Full reference: [web-bot-auth.md](web-bot-auth.md).

Anything else falls through to the inventory-based auth plugin registry, so a linked third-party crate can register additional types (`oauth`, `oauth_introspection`, `oauth_client_credentials`, `ext_authz`, `biscuit`, `saml`, ...) without patching the OSS engine. Plugins register on the typed `AuthPluginRegistration` channel and surface through the standard `authentication.type` config field.

### api_key

Authenticate requests with an API key. Keys are checked in the `X-Api-Key` header by default; an optional `query_param` lets clients pass keys via the URL. Typical fit: machine-to-machine API access.

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
      query_param: api_key
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `api_key` |
| `api_keys` | list | required | Accepted API keys |
| `header_name` | string | `X-Api-Key` | Header carrying the API key |
| `query_param` | string | | When set, keys can be supplied via the named URL query parameter |

Test with:
```bash
curl -H "Host: api.example.com" -H "X-Api-Key: your-key-here" http://localhost:8080/
```

### basic_auth

HTTP Basic Authentication with username/password pairs. Fits simple internal services and admin panels.

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
      realm: "Admin Panel"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `basic_auth` |
| `users` | list | required | Username/password pairs |
| `realm` | string | | Optional realm shown in the `WWW-Authenticate` challenge |

### bearer

Authenticate with Bearer tokens in the Authorization header. The default for token-based service auth.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: bearer
      tokens:
        - ${SERVICE_TOKEN_1}
        - ${SERVICE_TOKEN_2}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `bearer` |
| `tokens` | list | required | Accepted bearer tokens |

### jwt

Validate JSON Web Tokens. Supports JWKS endpoints for key rotation and claims validation. Pick this for OAuth2/OIDC-protected APIs.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: jwt
      jwks_url: https://auth.example.com/.well-known/jwks.json
      issuer: https://auth.example.com
      audience: my-api
      algorithms: [RS256]
      required_claims:
        scope: api:read
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `jwt` |
| `secret` | string | | HMAC signing secret (HS256/HS384/HS512) |
| `jwks_url` | string | | URL to fetch JWKS from (RS / ES / PS family) |
| `issuer` | string | | Required `iss` claim value |
| `audience` | string | | Required `aud` claim value |
| `algorithms` | list | inferred | Allowed signing algorithms. Defaults to HS256/HS384/HS512 with `secret`, RS256 with `jwks_url`. |
| `required_claims` | map | | Claims that must be present and equal to the configured value. |

The list must contain at least one entry; an empty list rejects all tokens. Bearer tokens must be supplied via `Authorization: Bearer <jwt>`.

### digest

HTTP Digest Authentication (RFC 7616). The right pick when a legacy system insists on digest auth. The stored `password` is the HA1 hash, `MD5(username:realm:password)`, not the plaintext password.

```yaml
origins:
  "legacy.example.com":
    action:
      type: proxy
      url: https://legacy-backend.internal:8080
    authentication:
      type: digest
      realm: "Legacy"
      users:
        - username: alice
          password: ${ALICE_HA1}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `digest`. |
| `realm` | string | required | Realm string sent in the `WWW-Authenticate` challenge. |
| `users` | list or map | required | Accepted users. Either a list of `{username, password}` objects, or a map of `username: ha1_hex`. |

### forward_auth

Delegate authentication to an external service. SBproxy sends a subrequest to the auth service and uses the response status to allow or deny the original request. The right choice when auth logic lives in its own service.

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
      timeout: 5000
      headers_to_forward: [Authorization, Cookie]
      trust_headers: [X-User-ID, X-User-Email, X-User-Roles]
      success_status: 200
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `forward_auth` |
| `url` | string | required | External auth service URL |
| `method` | string | GET | HTTP method for the subrequest |
| `timeout` | int | | Subrequest timeout in milliseconds |
| `headers_to_forward` | list | | Headers to copy from the original request. Alias: `forward_headers`. |
| `trust_headers` | list | | Headers from the auth response to inject into the upstream request |
| `success_status` | int \| list | 200 | Status code(s) that mean "authenticated". A list is accepted, but only the first element is used. |

### noop

The no-op auth provider accepts every request without checking credentials. Set this explicitly to mark an origin as unauthenticated, so the intent is obvious in the config.

```yaml
authentication:
  type: noop
```

---

## Policies

Policies are evaluated before the action runs. They enforce rate limits, security rules, and access controls. The `policies` field is a sibling of `action` and is an array of policy objects.

SBproxy ships ten policy types: `rate_limiting`, `ip_filter`, `expression`, `waf`, `ddos`, `csrf`, `security_headers`, `request_limit`, `sri`, `assertion`.

### rate_limiting

Rate limit clients to prevent abuse and protect backend resources. Uses a token bucket by default (in-process) or a fixed-window counter (when an L2 Redis backend is configured).

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    policies:
      - type: rate_limiting
        requests_per_minute: 60
        burst: 10
        algorithm: token_bucket
        whitelist:
          - 10.0.0.0/8
```

Clients exceeding the limit receive `429 Too Many Requests` with a `Retry-After` header.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `rate_limiting` |
| `requests_per_second` | float | | Per-second token refill rate |
| `requests_per_minute` | float | | Per-minute token refill rate (mutually exclusive with `requests_per_second`) |
| `burst` | int | derived from rate | Maximum burst capacity |
| `algorithm` | string | `token_bucket` | Algorithm hint: `token_bucket`, `fixed_window`. The runtime picks based on whether an L2 backend is attached. |
| `headers` | object | | `X-RateLimit-*` and `Retry-After` header configuration |
| `whitelist` | list | | IPs/CIDRs exempt from rate limiting |

Distributed rate limiting: a single-instance deployment tracks counters in memory. For multi-instance deployments, configure an L2 Redis cache so counters are shared across all proxy replicas:

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://redis.internal:6379/0
```

### ip_filter

Allow or block requests by client IP address or CIDR range. Useful for locking down internal services or blocking known bad actors.

```yaml
policies:
  - type: ip_filter
    whitelist:
      - 10.0.0.0/8
      - 192.168.1.0/24
      - 172.16.0.0/12
    blacklist:
      - 10.0.0.99/32
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `ip_filter` |
| `whitelist` | list | | CIDR ranges that are explicitly permitted. Empty allows everything. |
| `blacklist` | list | | CIDR ranges that are explicitly denied. |

If `whitelist` is non-empty, the client IP must match at least one entry. If `blacklist` is non-empty, the client IP must not match any entry. Both lists may be used together.

### expression

CEL expression that evaluates to allow or deny a request. Pick this for custom access control logic that goes beyond simple IP or key checks.

```yaml
policies:
  - type: expression
    expression: 'request.headers["x-internal"] == "true"'
    deny_status: 403
    deny_message: "internal traffic only"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `expression` |
| `expression` | string | required | CEL expression returning a boolean. Alias: `cel_expr`. |
| `deny_status` | int | 403 | HTTP status code when denied. Alias: `status_code`. |
| `deny_message` | string | "forbidden by policy" | Body returned with the deny status code. |

Expression policies evaluate CEL only. For Lua-driven access control, use a request modifier with a `lua_script`.

### request_validator

Validate request bodies against a JSON Schema at the edge. Inbound payloads that fail validation are rejected with a configurable status (default 400) and a typed JSON error body, before they reach the upstream.

```yaml
policies:
  - type: request_validator
    content_types: [application/json]   # default
    status: 400                         # default
    error_content_type: application/json
    schema:
      type: object
      required: [name, age]
      properties:
        name: { type: string, minLength: 1 }
        age:  { type: integer, minimum: 0 }
      additionalProperties: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema` | JSON | required | JSON Schema document. Compiled once at config-load. |
| `content_types` | array | `[application/json]` | Media types this policy applies to. Other types pass through untouched. Matched case-insensitively against the leading media type (parameters are ignored). |
| `status` | int | 400 | HTTP status returned on validation failure. |
| `error_body` | string | structured JSON | Optional rejection body. Default is `{"error":"...","detail":"<location>"}` with no echoed payload. |
| `error_content_type` | string | `application/json` | Content-Type for the rejection body. |

The proxy buffers the request body locally until validation completes, then either releases it as one chunk to the upstream or aborts with the configured rejection. Remote `$ref` resolution in schemas is disabled at the workspace level so a malicious schema cannot become an SSRF primitive. The rejection body never echoes the offending payload back to the caller, only the JSON path where validation failed.

See [example 81](../examples/81-request-validator/sb.yml).

### openapi_validation

Load an OpenAPI 3.0 document at startup and validate each request body against the matching operation's `requestBody` schema. Requests whose path + method are not described in the spec, or whose `Content-Type` has no schema, are passed through. Full reference: [openapi-validation.md](openapi-validation.md).

```yaml
policies:
  - type: openapi_validation
    mode: enforce             # or 'log'
    status: 422               # status returned on enforce-mode rejection
    spec:
      openapi: "3.0.3"
      info: {title: my-api, version: "1.0"}
      paths:
        "/users/{id}":
          post:
            requestBody:
              required: true
              content:
                application/json:
                  schema:
                    type: object
                    required: [name]
                    additionalProperties: false
                    properties:
                      name: {type: string, minLength: 1}
                      age:  {type: integer, minimum: 0, maximum: 150}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spec` | object | required* | Inline OpenAPI document. *One of `spec` or `spec_file` is required. |
| `spec_file` | string | required* | Path to an OpenAPI document on disk (`.json` or `.yaml`). |
| `mode` | string | `enforce` | `enforce` rejects mismatched bodies; `log` warns and forwards. |
| `status` | int | 400 | Status returned in `enforce` mode on validation failure. |
| `error_body` | string | auto | Optional rejection body. Defaults to a JSON object naming the failing JSON pointer. |
| `error_content_type` | string | `application/json` | `Content-Type` for the rejection body. |

OpenAPI path templates compile to anchored regexes at startup; per-operation schemas compile once. The rejection body lists only the offending JSON pointer, not the value itself, to keep the surface area an attacker can probe small.

See [example 97](../examples/97-openapi-validation/sb.yml).

### concurrent_limit

Cap in-flight requests per key. Distinct from `rate_limiting`, which throttles RPS. Concurrent limits protect backends with low concurrency budgets: legacy SOAP services, DB-bound endpoints, GPU inference workers, anywhere slow requests pile up faster than they drain.

```yaml
policies:
  - type: concurrent_limit
    max: 50
    key: api_key      # or 'ip', or 'origin' (default)
    status: 503
    error_body: '{"error":"too many concurrent requests"}'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max` | int | required | Maximum concurrent requests per key. Must be `> 0`. |
| `key` | string | `origin` | Bucket strategy: `origin` (one global counter for the route), `ip` (per client IP), or `api_key` (per `X-Api-Key` or `Bearer` token). |
| `status` | int | 503 | HTTP status when the limit is exceeded. |
| `error_body` | string | unset | Optional response body for rejections. |

Each accepted request takes a permit; the permit is released when the request finishes (success, error, or client disconnect). Counters use a sharded `DashMap` so contention across keys is bounded.

See [example 82](../examples/82-concurrent-limit/sb.yml).

### ai_crawl_control

Pay Per Crawl: respond with `402 Payment Required` to AI crawlers that arrive without a valid `Crawler-Payment` token. Each token redeems once. Full reference: [ai-crawl-control.md](ai-crawl-control.md).

```yaml
policies:
  - type: ai_crawl_control
    price: 0.001
    currency: USD
    crawler_user_agents: [GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, Google-Extended, PerplexityBot, CCBot]
    valid_tokens:
      - tok_a89be2f1
      - tok_b7cf012e
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `price` | float | unset | Price emitted in the challenge body and the `price=` challenge parameter. |
| `currency` | string | `USD` | ISO-4217 code surfaced in the challenge. |
| `header` | string | `crawler-payment` | Header carrying the payment token. |
| `crawler_user_agents` | list | major AI crawler defaults | Case-insensitive substring matches against User-Agent. Empty list treats every GET/HEAD as a crawler. |
| `valid_tokens` | list | `[]` | Seeds the in-memory single-use ledger. Enterprise replaces this with an HTTP-callable ledger. |

Only `GET` and `HEAD` are subject to charging. `POST`/`PUT`/`PATCH`/`DELETE` bypass.

### exposed_credentials

Detect requests carrying a known-leaked password against a static exposure list. Tags the upstream request with `exposed-credential-check: leaked-password` (default) or rejects the request outright. Full reference and rollout guidance: [exposed-credentials.md](exposed-credentials.md).

```yaml
policies:
  - type: exposed_credentials
    action: tag                       # or "block"
    passwords:                        # plaintext, hashed at compile-time
      - password
      - password123
    sha1_hashes:                      # uppercase or lowercase hex
      - 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    sha1_file: /etc/sbproxy/leaked-sha1.txt   # one hash per line; `#` comments
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | `static` | OSS only ships `static`. Enterprise extends with `hibp` (k-anonymity range query). |
| `action` | string | `tag` | `tag` stamps the configured header on the upstream request. `block` returns `403`. |
| `header` | string | `exposed-credential-check` | Header name when `action: tag`. |
| `passwords` | list | `[]` | Plaintext passwords. Hashed at compile time; the source strings are not retained on the policy. |
| `sha1_hashes` | list | `[]` | Inline SHA-1 hex hashes. |
| `sha1_file` | string | unset | Path to a file with one SHA-1 hex hash per line. |

The policy refuses to compile when no list is supplied. SHA-1 uppercase hex matches the format HIBP returns from its range queries, so a downloaded list drops onto disk without preprocessing.

### page_shield

Stamps a Content Security Policy header on every proxied response and runs an intake endpoint at `/__sbproxy/csp-report` for browser-emitted violation reports. Reports are logged structured under the `sbproxy::page_shield` tracing target so logpush sinks (and the enterprise Connection Monitor, F3.20) pick them up.

```yaml
policies:
  - type: page_shield
    mode: report-only           # or "enforce"
    directives:
      - "default-src 'self'"
      - "script-src 'self' https://cdn.example"
      - "img-src 'self' https: data:"
    report_path: /__sbproxy/csp-report   # default
    report_to_group: csp-endpoint        # optional; emits report-to too
    respect_upstream: false              # yield to an upstream-supplied CSP
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `report-only` | `report-only` emits `Content-Security-Policy-Report-Only`. `enforce` emits `Content-Security-Policy`. |
| `directives` | list | required, non-empty | Each entry is a complete CSP directive (`default-src 'self'`). Joined with `; `. |
| `report_path` | string | `/__sbproxy/csp-report` | Override the intake path. Used in the auto-appended `report-uri` directive. |
| `report_to_group` | string | unset | When set, the policy also emits `report-to <name>` for the modern Reporting API. |
| `respect_upstream` | bool | `false` | When `true` and the upstream already emits a CSP header, the policy yields and does not write its own. |

The intake accepts up to 64 KiB per report via `POST /__sbproxy/csp-report` and returns `204 No Content`. The header is applied to proxied responses; static / redirect / mock actions short-circuit before the response-header phase and bypass injection.

### dlp

Data Loss Prevention scan over the request URI and headers. Matches against the configured detector catalogue (or every default when `detectors: []`) and either tags the upstream request with `dlp-detection: <names>` (`action: tag`, default) or rejects with `403` (`action: block`).

```yaml
policies:
  - type: dlp
    action: tag                  # or "block"
    detectors: []                # empty = enable every default detector
    rules:                       # optional custom rules layered on top
      - name: internal_ticket
        pattern: '\bTICKET-\d{6}\b'
        replacement: '[REDACTED:TICKET]'
        anchor: 'TICKET-'
```

**Default detectors:** `email`, `us_ssn`, `credit_card`, `phone_us`, `ipv4`, `openai_key`, `anthropic_key`, `aws_access`, `github_token`, `slack_token`, `iban`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detectors` | list | `[]` (all defaults) | Detector names to enable. Unknown names fail at compile-time. |
| `action` | string | `tag` | `tag` stamps `<header>: <detector_csv>` on the upstream. `block` returns `403`. |
| `direction` | string | `request` | `request` is the only path enforced today; `response` and `both` are accepted for forward compatibility. |
| `header` | string | `dlp-detection` | Header name when `action: tag`. |
| `rules` | list | `[]` | Custom regex rules layered on top of the catalogue. Same shape as the `pii.rules` block on `ai_proxy` origins. |

The scan covers the request URI (path + query) and request headers; auth-class headers (`Authorization`, `Cookie`, `Set-Cookie`) are excluded so tokens carried by design don't self-flag. Body scanning is on the roadmap; the existing `pii:` block on `ai_proxy` origins handles request-body redaction with the same regex catalogue today.

### prompt_injection_v2

Successor to the v1 `prompt_injection` heuristic. The v2 policy splits detection from enforcement: a swappable detector returns a score in `[0.0, 1.0]` plus a categorical label, and the policy maps the score onto an action. The OSS build registers a heuristic detector by default (`detector: heuristic-v1`) so the policy works out of the box. Future builds register additional detectors (e.g. an ONNX classifier) without touching the policy core.

```yaml
policies:
  - type: prompt_injection_v2
    action: tag                         # tag (default) | block | log
    detector: heuristic-v1              # default; lookup is link-time
    threshold: 0.5                      # fires when score >= threshold
    score_header: x-prompt-injection-score
    label_header: x-prompt-injection-label
    block_body: 'prompt injection detected'
    block_content_type: text/plain
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detector` | string | `heuristic-v1` | Detector name. Resolved against the inventory registry; unknown names fail at compile time. |
| `threshold` | float | `0.5` | Score threshold in `[0.0, 1.0]`; the policy fires when `score >= threshold`. |
| `action` | string | `tag` | `tag` stamps the score / label headers on the upstream. `block` returns `403` with `block_body`. `log` writes a structured warn under `sbproxy::prompt_injection_v2`. |
| `score_header` | string | `x-prompt-injection-score` | Header carrying the numeric score (formatted as `"%.3f"`) on `action: tag`. |
| `label_header` | string | `x-prompt-injection-label` | Header carrying `clean` / `suspicious` / `injection` on `action: tag`. |
| `block_body` | string | `prompt injection detected` | Response body returned on `action: block`. |
| `block_content_type` | string | `text/plain` | Content-Type for the block body. |

The OSS scaffold scans the request URI + non-auth headers (`Authorization`, `Cookie`, `Set-Cookie` are excluded so tokens carried by design don't self-flag) at request-filter time. Tag mode stamps the score / label headers via the existing trust-headers channel before `upstream_request_filter` builds the upstream request; block mode rejects with `403` immediately. Body-aware detection (the prompt typically lives in the JSON body) is on the roadmap and lands with the ONNX classifier follow-up. See [prompt-injection-v2.md](prompt-injection-v2.md) for the trait shape, the eval harness, and how to register a custom detector.

### waf

Web Application Firewall. Built-in patterns cover SQL injection, XSS, and path traversal. Custom rules can extend behavior.

```yaml
policies:
  - type: waf
    owasp_crs:
      enabled: true
    action_on_match: block
    test_mode: false
    fail_open: false
    custom_rules: []
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `waf` |
| `owasp_crs` | object | | OWASP Core Rule Set configuration. |
| `action_on_match` | string | "block" | Action when a rule matches: `block`, `log`. |
| `test_mode` | bool | false | If true, log matches but do not block. |
| `fail_open` | bool | false | If true, allow requests through on WAF engine failure. |
| `custom_rules` | list | | Custom WAF rules (regex patterns or JS-defined matchers). |

### ddos

DDoS protection with per-IP rate tracking and temporary blocks.

```yaml
policies:
  - type: ddos
    requests_per_second: 100
    block_duration_secs: 300
    whitelist:
      - 10.0.0.0/8
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `ddos` |
| `requests_per_second` | int | 100 | Per-IP threshold that triggers blocking. |
| `block_duration_secs` | int | 300 | Duration in seconds an IP stays blocked once the threshold trips. |
| `whitelist` | list | `[]` | CIDR ranges that bypass DDoS checks. |
| `detection` | object | | Go-compat nested form. When `detection.request_rate_threshold` is set, it overrides `requests_per_second`. |
| `mitigation` | object | | Go-compat nested form. When `mitigation.block_duration` is set as a Go duration string (`10s`, `5m`, `1h`), it overrides `block_duration_secs`. |

### csrf

Cross-Site Request Forgery protection for web applications that accept form submissions.

```yaml
policies:
  - type: csrf
    secret_key: ${CSRF_SECRET}
    cookie_name: csrf_token
    header_name: X-CSRF-Token
    methods: [POST, PUT, DELETE, PATCH]
    safe_methods: [GET, HEAD, OPTIONS]
    cookie_path: /
    cookie_same_site: Lax
    exempt_paths: [/api/webhooks, /api/health]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `csrf` |
| `secret_key` | string | required | HMAC key used to sign CSRF tokens. Alias: `secret`. |
| `header_name` | string | `X-CSRF-Token` | Header carrying the CSRF token |
| `cookie_name` | string | `csrf_token` | Cookie carrying the canonical CSRF token |
| `methods` | list | | Methods that require CSRF token validation. When empty, falls back to "anything not in `safe_methods`". |
| `safe_methods` | list | `[GET, HEAD, OPTIONS]` | Methods exempt from CSRF checking |
| `cookie_path` | string | | Cookie path |
| `cookie_same_site` | string | | SameSite attribute (`Strict`, `Lax`, `None`) |
| `exempt_paths` | list | | Paths exempt from CSRF checking |

### request_limit

Cap request body size, header count, header value size, URL length, and query string length. Any field left unset means that dimension is not checked.

```yaml
policies:
  - type: request_limit
    max_body_size: 1048576
    max_header_count: 50
    max_header_size: 8KB
    max_url_length: 2048
    max_query_string_length: 1024
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_body_size` | int | unset | Maximum request body size in bytes. |
| `max_header_count` | int | unset | Maximum number of request headers. Alias: `max_headers_count`. |
| `max_header_size` | int or string | unset | Maximum size of a single header value. Strings like `"4KB"` or `"1MB"` are accepted. |
| `max_url_length` | int | unset | Maximum URL length in characters. |
| `max_query_string_length` | int | unset | Maximum query string length in characters. |
| `max_request_size` | int or string | unset | Go-compat overall request size cap. Same string-or-number rules as `max_header_size`. |
| `size_limits` | object | | Go-compat nested form. When set, fields here are merged into the policy at load time. |

### security_headers

Inject security headers into every response to harden browser security.

```yaml
policies:
  - type: security_headers
    headers:
      - name: Strict-Transport-Security
        value: "max-age=31536000; includeSubDomains; preload"
      - name: X-Frame-Options
        value: DENY
      - name: X-Content-Type-Options
        value: nosniff
      - name: Referrer-Policy
        value: strict-origin-when-cross-origin
      - name: Permissions-Policy
        value: "camera=(), microphone=(), geolocation=()"
    # Optional: detailed CSP block for nonce / dynamic routes only.
    content_security_policy:
      policy: "default-src 'self'; script-src 'self' https://cdn.example.com"
      enable_nonce: false
      report_only: false
      report_uri: ""
```

`headers` is a list of `{name, value}` pairs for any response header (HSTS, Cross-Origin-*, COEP/COOP/CORP, Referrer-Policy, Permissions-Policy, and so on). The optional `content_security_policy` block is for advanced CSP behavior only: per-request nonce injection, report-only mode, per-route overrides. For a plain CSP without nonce or dynamic routes, add a `Content-Security-Policy` entry to `headers` directly.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `security_headers`. |
| `headers` | list | `[]` | Canonical `{name, value}` pairs to inject. Takes precedence over the legacy flat fields below. |
| `content_security_policy` | string or object | | CSP. Either a plain policy string or an object (see below). |
| `x_frame_options` | string | | Legacy flat shortcut. Deprecated. |
| `x_content_type_options` | string | | Legacy flat shortcut. Deprecated. |
| `x_xss_protection` | string | | Legacy flat shortcut. Deprecated. |
| `referrer_policy` | string | | Legacy flat shortcut. Deprecated. |
| `permissions_policy` | string | | Legacy flat shortcut. Deprecated. |
| `strict_transport_security` | string | | Legacy flat HSTS shortcut. Deprecated. |

When `content_security_policy` is an object, it accepts:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy` | string | `""` | The CSP policy string. |
| `enable_nonce` | bool | false | When true, generate a per-request nonce and inject it into `script-src` / `style-src` directives. |
| `report_only` | bool | false | When true, emit `Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`. |
| `report_uri` | string | `""` | Appended to the policy as `; report-uri <uri>` when set. |
| `dynamic_routes` | map | `{}` | Per-route CSP overrides keyed by URL path. Exact key match wins, then longest matching prefix. |

### sri

Subresource Integrity validation. When `enforce` is true, sub-resource responses must include valid integrity hashes using one of the configured algorithms.

```yaml
policies:
  - type: sri
    enforce: true
    algorithms: [sha256, sha384, sha512]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `sri`. |
| `enforce` | bool | false | When true, missing or invalid integrity hashes cause the response to be rejected. |
| `algorithms` | list | `[]` | Accepted integrity hash algorithms (e.g. `sha256`, `sha384`, `sha512`). |

### assertion

CEL assertion policy. Evaluates a CEL expression and logs/flags when it returns false. Unlike `expression`, assertions do not block traffic; they are informational only.

```yaml
policies:
  - type: assertion
    expression: 'response.status_code < 500'
    name: "no-server-errors"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `expression` | string | required | CEL expression evaluated for its truth value |
| `name` | string | "assertion" | Human-readable name attached to assertion log entries |

---

## Transforms

Transforms modify the response body before it reaches the client. They are specified as a list under `transforms` and run in order. Reach for transforms when you need to reshape API responses for different consumers.

SBproxy supports nineteen transform types: `json`, `json_projection`, `json_schema`, `template`, `replace_strings`, `normalize`, `encoding`, `format_convert`, `payload_limit`, `discard`, `sse_chunking`, `html`, `optimize_html`, `html_to_markdown`, `markdown`, `css`, `lua_json`, `javascript`, `js_json`, plus a `noop` for testing.

### json

Reshape JSON responses by setting or merging fields.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    transforms:
      - type: json
        # Field-level edits handled by this transform.
```

For include/exclude projection, use `json_projection`:

```yaml
transforms:
  - type: json_projection
    projection:
      include: [id, name, email, role]
```

Or to remove sensitive fields:

```yaml
transforms:
  - type: json_projection
    projection:
      exclude: [password, ssn, internal_notes]
```

### html

Modify HTML responses by removing elements, injecting content at known positions, and rewriting attributes.

```yaml
transforms:
  - type: html
    remove_selectors: [script, "#banner"]
    inject:
      - position: head_end
        content: '<link rel="stylesheet" href="https://cdn.example.com/override.css">'
      - position: body_start
        content: '<div id="banner">Maintenance scheduled for tonight</div>'
      - position: body_end
        content: '<script src="https://cdn.example.com/analytics.js"></script>'
    rewrite_attributes:
      - selector: img
        attribute: loading
        value: lazy
    format_options:
      strip_comments: true
      strip_space: true
      lowercase_tags: false
```

`position` accepts `head_end`, `body_start`, or `body_end`. Each `inject` entry is `{position, content}`.

### css

Modify CSS responses by injecting rules, removing rule blocks for specific selectors, and minifying.

```yaml
transforms:
  - type: css
    inject:
      - "body { background: #fafafa; }"
    remove_selectors: [".legacy-banner"]
    minify: true
```

### Common transform fields

Every entry in the `transforms:` list is wrapped with these pipeline-level fields, parsed by `TransformConfig`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Transform type discriminator (e.g. `json`, `template`). |
| `content_types` | list | `[]` | Content-Type substrings the transform applies to. Empty matches all. |
| `fail_on_error` | bool | false | When true, an error in this transform fails the whole response. |
| `max_body_size` | int | 10485760 | Maximum body size, in bytes, that this transform will buffer. Larger bodies skip the transform. |
| `disabled` | bool | false | When true, the transform is parsed but not applied. |

Type-specific fields are listed below.

### json (field manipulation)

Reshape JSON by setting, removing, and renaming fields.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `set` | map | `{}` | Fields to set or overwrite. Values may be any JSON. |
| `remove` | list | `[]` | Field names to delete. |
| `rename` | map | `{}` | `old_name -> new_name` mapping. Renames happen before `set`. |

### json_projection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fields` | list | required | Field names to keep (default) or drop (when `exclude` is true). Alias: `include`. |
| `exclude` | bool | false | When true, drop the listed fields instead of keeping them. |

### json_schema

Validate the response body against a JSON Schema document. Schemas are compiled at config-load time. Remote `$ref` resolution is disabled to prevent SSRF.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema` | object | required | The JSON Schema document. |

### template

Render the JSON body as input to a minijinja template.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `template` | string | required | Template source with `{{ variable }}` syntax. |

### replace_strings

Apply a list of literal or regex find-and-replace rules to the body.

```yaml
- type: replace_strings
  replacements:
    - find: "internal.example.com"
      replace: "public.example.com"
    - find: '\d{16}'
      replace: "[REDACTED]"
      regex: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `replacements` | list | required | Ordered list of replacement rules. |
| `replacements[].find` | string | required | Literal substring or regex pattern. |
| `replacements[].replace` | string | required | Replacement string. |
| `replacements[].regex` | bool | false | When true, treat `find` as a regex. |

### normalize

Whitespace and newline normalization.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trim` | bool | false | Trim leading and trailing whitespace. |
| `collapse_whitespace` | bool | false | Collapse runs of spaces and tabs into a single space. |
| `normalize_newlines` | bool | false | Replace `\r\n` with `\n`. |

### encoding

Base64 or URL encode/decode the body.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `encoding` | string | required | One of `base64_encode`, `base64_decode`, `url_encode`, `url_decode`. |

### format_convert

Convert between JSON and YAML.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `from` | string | required | Source format: `json` or `yaml`. |
| `to` | string | required | Target format: `json` or `yaml`. |

### payload_limit

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_size` | int | required | Maximum allowed body size in bytes. |
| `truncate` | bool | false | When true, truncate to `max_size`. When false, error on oversize. |

### discard

Drop the response body entirely. Takes no fields.

```yaml
- type: discard
```

### sse_chunking

Format the body as Server-Sent Events with the configured prefix and double-newline delimiters.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `line_prefix` | string | `"data: "` | Prefix prepended to each non-empty line. |

### optimize_html

Minify HTML by removing comments and collapsing whitespace.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `remove_comments` | bool | true | Strip `<!-- ... -->` comments. |
| `collapse_whitespace` | bool | true | Collapse runs of whitespace into a single space (preserves `<pre>` and `<code>` content). |
| `remove_optional_tags` | bool | false | Remove optional closing tags such as `</li>`, `</p>`, `</tr>` (experimental). |

### html_to_markdown

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `heading_style` | string | `"atx"` | Heading style: `atx` (uses `#`), `setext` (underline). |

### markdown

Convert Markdown to HTML using `pulldown-cmark`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `smart_punctuation` | bool | false | Enable smart punctuation (curly quotes, dashes). |
| `tables` | bool | false | Enable GitHub-flavored tables. |
| `strikethrough` | bool | false | Enable `~~strikethrough~~`. |

### Scripting transforms

`lua_json` runs a Lua script against a parsed JSON body. `javascript` and `js_json` run JavaScript. Each is documented in [scripting.md](scripting.md). Replace any `type: lua` references in older configs with `type: lua_json`.

| Type | Field | Default | Description |
|------|-------|---------|-------------|
| `lua_json` | `script` | required | Lua source. The Go-format function name is `modify_json(data, ctx)`; legacy scripts may use a `body` global. Alias: `lua_script`. |
| `javascript` | `script` | required | JavaScript source. |
| `javascript` | `function_name` | `transform` | Entrypoint function name. Receives the body as a string. |
| `js_json` | `script` | required | JavaScript source. Alias: `js_script`. |
| `js_json` | `function_name` | `modify_json` | Entrypoint function name. Receives the parsed JSON body. |

---

## Request modifiers

Request modifiers run before the action and edit the request. Each entry is an object with one or more of `headers`, `url`, `query`, `method`, `body`, `lua_script`, or `js_script`. Multiple entries are applied in order.

### Header / URL / query / method / body

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    request_modifiers:
      - headers:
          set:
            X-Source: sbproxy
          add:
            X-Trace-Id: "{{ request.headers.x_request_id }}"
          remove:
            - X-Internal-Token
        url:
          path:
            replace:
              old: /old/
              new: /new/
        query:
          set:
            tenant: prod
          add:
            extra: "1"
          remove:
            - debug
        method: POST
        body:
          replace_json:
            injected: true
            source: proxy
```

| Field | Type | Description |
|-------|------|-------------|
| `headers.set` | map | Replace headers (overwrites existing) |
| `headers.add` | map | Append headers (preserves existing) |
| `headers.remove` | list | Remove headers (alias: `delete`) |
| `url.path.replace.old` | string | Substring to find in the request path |
| `url.path.replace.new` | string | Replacement string |
| `query.set` | map | Replace query parameters |
| `query.add` | map | Append query parameters |
| `query.remove` | list | Remove query parameters (alias: `delete`) |
| `method` | string | Override the HTTP method |
| `body.replace` | string | Replace the body with this string |
| `body.replace_json` | object | Replace the body with this JSON value |

### Scripted request modifiers

Each modifier entry can supply a `lua_script` or `js_script` instead of (or in addition to) the structured fields above. Scripts run with full access to the request context. See [scripting.md](scripting.md) for the script API.

```yaml
request_modifiers:
  - lua_script: |
      local access_level = "guest"
      if ip.in_cidr(request_ip, "10.0.1.0/24") then
        access_level = "admin"
      end
      request.headers["X-Access-Level"] = access_level
      return request
```

```yaml
request_modifiers:
  - js_script: |
      function modify_request(req, ctx) {
        req.headers["X-Injected"] = "from-js";
        return req;
      }
```

---

## Response modifiers

Response modifiers run after the action and edit the response. Each entry is an object with one or more of `headers`, `status`, `body`, `lua_script`, or `js_script`. Multiple entries are applied in order.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    response_modifiers:
      - headers:
          set:
            X-Content-Type-Options: nosniff
            X-Frame-Options: DENY
          remove:
            - Server
            - X-Powered-By
        status:
          code: 200
          text: OK
        body:
          replace: '{"ok": true}'
```

| Field | Type | Description |
|-------|------|-------------|
| `headers.set` | map | Replace headers |
| `headers.add` | map | Append headers |
| `headers.remove` | list | Remove headers (alias: `delete`) |
| `status.code` | int | Override the response status code |
| `status.text` | string | Optional reason phrase (informational only; not sent in HTTP/2) |
| `body.replace` | string | Replace the response body with this string |
| `body.replace_json` | object | Replace the response body with this JSON value |

For JSON-field-level edits (set fields, delete fields, etc.), use the `json` transform rather than a response modifier.

### Scripted response modifiers

```yaml
response_modifiers:
  - lua_script: |
      if location.country_code ~= "US" and location.country_code ~= "CA" then
        response.status_code = 451
        response.body = '{"error": "Content not available in your region"}'
      end
      return response
```

```yaml
response_modifiers:
  - js_script: |
      function modify_response(res, ctx) {
        res.headers["X-Injected"] = "from-js";
        return res;
      }
```

---

## Response cache

Cache responses at the origin level to reduce backend load and improve response times for cacheable content. The `response_cache` block is a sibling of `action`.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    response_cache:
      enabled: true
      ttl_secs: 300
      cacheable_methods: [GET, HEAD]
      cacheable_status: [200, 301]
      max_size: 10000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable response caching |
| `ttl_secs` | duration | 300 | Cache entry TTL. Accepts integers (`60`) or humanized strings (`60s`, `5m`, `2h30m`). Alias: `ttl`. |
| `cacheable_methods` | list | `[GET]` | HTTP methods eligible for caching. Alias: `methods`. |
| `cacheable_status` | list | `[200]` | Status codes eligible for caching. Alias: `status_codes`. |
| `max_size` | int | 10000 | Upper bound on the in-memory cache size in entries. Ignored when an L2 Redis backend is attached. |

When `proxy.l2_cache_settings` is configured with `driver: redis`, response cache entries are stored in the shared backend; the in-memory `max_size` becomes irrelevant.

---

## Forward rules

Forward rules route specific requests to different origins based on path, header, or other conditions. They are evaluated in order; the first match wins. Common uses: path-based microservice routing and version routing.

Forward rules are deserialized lazily; required fields are enforced when the rule is exercised, not at config-load time.

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
            status: 200
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

### Rule matching

Each forward rule has a `rules` array where each entry is a path matcher. The OSS deserializer accepts these forms only:

| Field | Type | Description |
|-------|------|-------------|
| `path.prefix` | string | Path starts with this value. |
| `path.exact` | string | Path matches this value exactly. If both `prefix` and `exact` are set on the same matcher, `prefix` wins. |
| `match` | string | Shorthand. Equivalent to `path: { prefix: <value> }`. |

When a rule has multiple matcher entries, the rule fires when any one of them matches. Other Go-era fields (`methods`, `headers`, `query`, `ip`, `location`, `user_agent`, `content_types`, `protocol`) are not parsed by the Rust runtime today and are ignored if present.

### Forward rule fields

The forward rule itself wraps the matcher list and the inline child origin to dispatch to.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rules` | list | `[]` | Matcher entries. The rule fires when any one matches. |
| `origin` | object | required | Inline child origin. See below. |

The `origin` object is a full child origin config plus identifying metadata:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | string | | Identifier surfaced in metrics and logs. |
| `hostname` | string | | Informational hostname tag. The parent origin's hostname is what routed the request. |
| `workspace_id` | string | | Workspace identifier. |
| `version` | string | | Version label. |
| `action` | object | required | Action executed when the rule fires. Same schema as a top-level `action`. |
| `request_modifiers` | list | `[]` | Request modifiers applied before the action runs. |

### Inline origins

Forward rules embed full origin configurations via the `origin` field. Each inline origin can have its own action, authentication, policies, and transforms, exactly like a top-level origin.

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
        - type: rate_limiting
          requests_per_minute: 30
```

---

## Fallback origin

When the primary action errors or the upstream returns a configured status code, the proxy can swap in a backup origin. The fallback runs the action you'd normally write at the top level (static, redirect, mock, proxy, anything), so you can serve a cached body, redirect to a status page, or route to a degraded backend.

```yaml
origins:
  "api.local":
    action:
      type: proxy
      url: https://primary-backend:8080

    fallback_origin:
      on_error: true
      on_status: [502, 503, 504]
      add_debug_header: true
      origin:
        id: degraded-stub
        action:
          type: static
          status: 200
          content_type: application/json
          json_body:
            status: degraded
            message: primary upstream temporarily unavailable
            retry_after_secs: 30
```

### Trigger fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_error` | bool | false | Trigger the fallback on transport-level upstream failures (DNS, connect, TLS, timeout). |
| `on_status` | list[int] | `[]` | Trigger the fallback when the upstream responds with one of these status codes. Pair with `on_error` for full coverage. |
| `add_debug_header` | bool | false | When true, the proxy sets `X-Fallback-Trigger` on the response so callers can tell the fallback path served the request. |
| `origin` | object | required | Inline origin spec used to serve the request when a trigger fires. Must contain an `action` block; `id`, `hostname`, `workspace_id`, and `version` are accepted as optional metadata. |

### Inline origin

The `origin:` field carries the same action types as a top-level origin (proxy, static, redirect, mock, echo, beacon, noop, ai_proxy, load_balancer, websocket, grpc). Authentication, policies, and transforms are not applied to the fallback path; only the action runs. If you need richer behaviour from the fallback, point its action at another origin via `proxy` and let the host router apply that origin's full chain.

---

## Variables, vaults, and secrets

### Variables

User-defined key-value pairs available in template context as `{{ variables.name }}`. Any JSON type works, including nested objects.

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

### Secret references

Secrets are resolved through the top-level `proxy.secrets` block (see [Secrets](#secrets)). Once resolved, secrets are available in templates as `{{ secrets.name }}`.

```yaml
proxy:
  secrets:
    backend: hashicorp
    hashicorp:
      addr: https://vault.example.com:8200
    map:
      database_url: secret/data/prod/db_url
      stripe_key: secret/data/prod/stripe_key

origins:
  "api.example.com":
    action:
      type: proxy
      url: "{{ secrets.database_url }}"
```

### Template scopes

Templates have access to these scopes:

| Scope | Description | Example |
|-------|-------------|---------|
| `request` | Current HTTP request | `{{ request.headers.x_api_key }}` |
| `variables` | User-defined variables | `{{ variables.api_version }}` |
| `secrets` | Loaded secrets | `{{ secrets.api_token }}` |
| `config` | Config metadata | `{{ config.hostname }}` |
| `session` | Session data | `{{ session.auth.email }}` |
| `env` | Config identity fields | `{{ env.workspace_id }}` |
| `server` | Server-level vars | `{{ server.var_name }}` |

---

## Session config

Configure session behavior for an origin. Sessions are stored in encrypted cookies.

```yaml
origins:
  "app.example.com":
    session:
      cookie_name: sb_session
      max_age: 3600
      same_site: Strict
      http_only: true
      secure: true
      allow_non_ssl: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cookie_name` | string | | Session cookie name |
| `max_age` | int | | Cookie lifetime in seconds. Alias: `cookie_max_age`. |
| `http_only` | bool | false | Set the `HttpOnly` cookie attribute |
| `secure` | bool | false | Set the `Secure` cookie attribute (HTTPS only) |
| `same_site` | string | | SameSite attribute (`Strict`, `Lax`, `None`). Alias: `cookie_same_site`. |
| `allow_non_ssl` | bool | false | Allow sessions over plain HTTP |

Sessions disable themselves implicitly when the block is omitted.

---

## Compression

Configure response compression on a per-origin basis.

```yaml
origins:
  "api.example.com":
    compression:
      enabled: true
      algorithms: [br, gzip]
      min_size: 512
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Master switch. Alias: `enable`. |
| `algorithms` | list | | Allowed algorithms in priority order (e.g. `["br", "gzip"]`) |
| `min_size` | int | 0 | Minimum response size in bytes before compression is applied |
| `level` | int | | Go-compat compression level. Not used by the Rust runtime. |

---

## HSTS

Inject the `Strict-Transport-Security` header on responses.

```yaml
origins:
  "secure.example.com":
    hsts:
      max_age: 31536000
      include_subdomains: true
      preload: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_age` | int | 31536000 | `max-age` directive in seconds |
| `include_subdomains` | bool | false | Emit the `includeSubDomains` directive |
| `preload` | bool | false | Emit the `preload` directive |

---

## Connection pool

Per-origin connection pool tuning. When unset, falls back to proxy-wide defaults.

```yaml
origins:
  "api.example.com":
    connection_pool:
      max_connections: 128
      idle_timeout_secs: 90
      max_lifetime_secs: 300
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_connections` | int | 128 | Maximum concurrent connections to the upstream |
| `idle_timeout_secs` | int | 90 | Maximum idle time before a connection is closed |
| `max_lifetime_secs` | int | 300 | Maximum total lifetime of a connection |

---

## Bot detection

Bot detection blocks requests based on `User-Agent` substring matches. The deny list rejects user agents that contain any of the listed substrings (case-insensitive). The allow list exempts user agents from the deny check, so trusted crawlers can pass through even when their substring is otherwise denied.

```yaml
origins:
  "api.example.com":
    bot_detection:
      enabled: true
      mode: block
      deny_list:
        - badbot
        - scrapy
        - python-requests
      allow_list:
        - Googlebot
        - bingbot
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Master switch. When false, every request is admitted. |
| `mode` | string | | Mode hint (`block`, `log`). Currently informational; the runtime always blocks denied agents. |
| `deny_list` | list | `[]` | User-Agent substrings (case-insensitive) that are blocked with 403. |
| `allow_list` | list | `[]` | User-Agent substrings (case-insensitive) that bypass the deny check. Evaluated before the deny list. |

---

## Threat protection

Threat protection guards against pathological JSON request bodies. When the request `Content-Type` is `application/json`, the proxy parses the body and checks it against limits on nesting depth, key count, string length, array size, and total body size. A request that exceeds any limit is rejected before it reaches the upstream.

```yaml
origins:
  "api.example.com":
    threat_protection:
      enabled: true
      json:
        max_depth: 32
        max_keys: 1000
        max_string_length: 65536
        max_array_size: 10000
        max_total_size: 1048576
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Master switch for threat checks on this origin. |
| `json` | object | | JSON-specific limits applied when the body is `application/json`. Omitting this block disables JSON checks even when `enabled` is true. |
| `json.max_depth` | int | unlimited | Maximum nesting depth across objects and arrays. |
| `json.max_keys` | int | unlimited | Maximum number of keys in any single object. |
| `json.max_string_length` | int | unlimited | Maximum length of any single string value. |
| `json.max_array_size` | int | unlimited | Maximum length of any single array. |
| `json.max_total_size` | int | unlimited | Maximum total body size in bytes, checked before parsing. |

---

## Error pages

Error pages let you replace upstream error responses with operator-defined bodies. Each entry declares the status codes it covers, the `Content-Type` it produces, and the response body. When more than one entry matches the status code, the proxy performs `Accept` header content negotiation across the candidates and picks the highest-quality match. With no concrete preference it prefers `application/json`, then `text/html`, then the first candidate.

The block is a list at the origin level. Each entry's `status` field accepts a single integer or a list of integers. When `template` is true, the body is rendered with `{{ status_code }}` and `{{ request.path }}` substituted at request time.

```yaml
origins:
  "api.example.com":
    error_pages:
      - status: [502, 503, 504]
        content_type: text/html; charset=utf-8
        template: true
        body: |
          <h1>Service unavailable</h1>
          <p>Status {{ status_code }} on {{ request.path }}.</p>
      - status: [502, 503, 504]
        content_type: application/json
        template: true
        body: '{"error":"upstream_unavailable","status":{{ status_code }},"path":"{{ request.path }}"}'
      - status: 404
        content_type: application/json
        body: '{"error":"not_found"}'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | int or list | | Status code or list of status codes this entry covers. Required for the entry to match. |
| `content_type` | string | `application/json` | `Content-Type` header sent with the response. |
| `body` | string | `""` | Response body. May contain template placeholders when `template` is true. |
| `template` | bool | false | When true, substitute `{{ status_code }}` and `{{ request.path }}` in the body. Both spaced and unspaced forms are accepted. |

---

## Rate limit headers

The `rate_limit_headers` field at the origin level is reserved for future expansion and is not consumed by the open-source binary. To control `X-RateLimit-*` and `Retry-After` emission today, configure the `headers` block on the rate-limiting policy itself.

```yaml
origins:
  "api.example.com":
    policies:
      - type: rate_limiting
        requests_per_minute: 600
        headers:
          enabled: true
          include_retry_after: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `headers.enabled` | bool | false | When true, emit `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` on responses. |
| `headers.include_retry_after` | bool | false | When true, emit `Retry-After` on 429 responses. |

The origin-level `rate_limit_headers` block is accepted for forward compatibility but ignored by the OSS runtime.

---

## Message signatures

The `message_signatures` block declares the schema for RFC 9421 HTTP Message Signatures. The configuration type is defined in `sbproxy-middleware`, but the signing and verification path is not wired into the OSS request pipeline yet. The block parses cleanly so configs that target a future release validate today.

```yaml
origins:
  "api.example.com":
    message_signatures:
      algorithm: hmac-sha256
      key_id: proxy-key-1
      covered_components:
        - "@method"
        - "@target-uri"
        - content-digest
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `algorithm` | string | | Signature algorithm identifier. Required. Examples: `hmac-sha256`, `ed25519`. |
| `key_id` | string | | Key identifier emitted in the `Signature-Input` header. Required. |
| `covered_components` | list | `[]` | HTTP message components covered by the signature, e.g. `@method`, `@target-uri`, `content-digest`. |

---

## Traffic capture

The `traffic_capture` block is reserved for request mirroring and capture configuration. There is no consumer for it in the open-source binary. The field is accepted on the origin so configs that target a future release or an external capture hook validate without errors. Set the block only when an out-of-tree component reads it.

For shadow traffic that is wired into the OSS request path, use [`mirror`](#request-mirror) instead.

---

## Host header semantics

When the proxy forwards a request to an upstream, it controls the upstream `Host` header explicitly:

1. The default is the upstream URL's hostname. So `url: https://api.upstream.com:8443` causes the upstream to see `Host: api.upstream.com:8443`. This works correctly with vhost-routed services like Vercel, Cloudflare-fronted origins, S3 website endpoints, and AWS ALBs out of the box.
2. If the action sets `host_override: <value>`, that value wins.
3. If a request modifier sets `Host`, the modifier takes precedence over both above (it runs after the proxy's default).

Whenever the proxy rewrites `Host` (i.e. the upstream value differs from what the client sent), it also sets `X-Forwarded-Host: <client's original Host>` so the upstream can still observe the public name. Suppress that breadcrumb with `disable_forwarded_host_header: true`.

The same `host_override` field is accepted on every URL-bearing action: `proxy`, each `load_balancer` target, `websocket`, `graphql`, `a2a`, `forward_auth`, and AI provider entries. `grpc` exposes the equivalent control as `authority`, matching the HTTP/2 spec name.

---

## Origin overrides

Three knobs control how the proxy reaches the upstream, all independent so they compose:

| Field | What it changes | curl analogue |
|-------|-----------------|---------------|
| `host_override` | Upstream `Host` HTTP header | `--header "Host: ..."` |
| `sni_override` | TLS SNI server name (and cert verification target) | `--resolve` (TLS leg) |
| `resolve_override` | Connect address (skips DNS for the URL host) | `--connect-to` |

Common patterns:

**Front a SaaS where the cert hostname differs from the URL host.**

```yaml
action:
  type: proxy
  url: https://api.tenant.example.com
  sni_override: cdn.provider.net           # cert is for *.provider.net
  host_override: api.tenant.example.com    # upstream still expects the tenant hostname
```

**Pin a region without polluting the system resolver.**

```yaml
action:
  type: proxy
  url: https://api.example.com
  resolve_override: 203.0.113.7:443        # eu-west-1 anycast
```

**Stage a cutover by pointing at a candidate IP.**

```yaml
action:
  type: proxy
  url: https://api.example.com
  resolve_override: "[2001:db8::1]:8443"
```

`resolve_override` accepts `ip`, `ip:port`, `[ipv6]:port`, or `host:port`. When the port is omitted, the URL's port is used. The proxy still sends the URL's hostname in the request line; only the connect address changes.

---

## Trusted proxies and forwarding headers

When SBproxy is itself behind another load balancer or CDN (Cloudflare, AWS ALB, Fly.io, internal LB), the immediate TCP peer is that LB, not the real client. To recover the real client identity safely, configure `proxy.trusted_proxies` with the source ranges of those upstream hops:

```yaml
proxy:
  trusted_proxies:
    - 10.0.0.0/8
    - 2001:db8::/32        # IPv6 supported
```

Behaviour:

- If the immediate TCP peer falls inside any trusted CIDR, the proxy parses the inbound `X-Forwarded-For` chain and uses the leftmost untrusted hop as the real client IP. This becomes `ctx.client_ip` for the rest of the request: rate limits, IP filters, audit logs.
- If the immediate TCP peer is **not** trusted, every inbound forwarding header is stripped on ingress. A direct client cannot spoof its source identity by setting `X-Forwarded-For: 1.2.3.4`.

The proxy then sets the standard forwarding headers on every upstream request:

| Header | Set to | Opt-out flag |
|---|---|---|
| `X-Forwarded-Host` | client's original `Host` (when proxy rewrites `Host`) | `disable_forwarded_host_header` |
| `X-Forwarded-For` | client IP appended to existing chain | `disable_forwarded_for_header` |
| `X-Real-IP` | the immediate client IP | `disable_real_ip_header` |
| `X-Forwarded-Proto` | `https` if the listener was TLS, else `http` | `disable_forwarded_proto_header` |
| `X-Forwarded-Port` | the listener port | `disable_forwarded_port_header` |
| `Forwarded` (RFC 7239) | `for=<client>; proto=<scheme>; host=<orig>; by=<proxy>` (IPv6 bracketed per RFC) | `disable_forwarded_header` |
| `Via` | appended `1.1 sbproxy` | `disable_via_header` |

All flags live on the action (or per-target on a load balancer). Default is enabled (no flag set). See [example 73](../examples/73-trusted-proxies/sb.yml) and [example 74](../examples/74-forwarding-headers/sb.yml).

---

## Request mirror

Send a fire-and-forget copy of every matched request to a shadow upstream. The mirror response is read and discarded; the client only ever sees the primary's response. Useful for safe rollouts of new backends, replay-style testing, and capturing production traffic patterns without affecting end-users.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://primary.internal:8080
    mirror:
      url: https://shadow.internal:8080
      sample_rate: 0.1       # mirror ~10% of requests; default 1.0
      timeout_ms: 5000       # mirror request timeout; default 5000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Mirror upstream URL. IPv6 hosts must be bracketed (`http://[2001:db8::1]:8080`). |
| `sample_rate` | float | `1.0` | Probability in `[0.0, 1.0]` that a given request is mirrored. |
| `timeout_ms` | int | `5000` | Per-mirror request timeout. Independent of the primary upstream timeout. |
| `mirror_body` | bool | `false` | Tee the inbound request body into the mirror request. Off by default, mirror sees only method, path, query, and headers (sufficient for read endpoints; safe for any case where shadow-replaying writes is unsafe). Set `true` to shadow-replay POST/PUT/PATCH endpoints during migrations. |
| `max_body_bytes` | int | `1048576` | Body size cap (bytes). Bodies larger than this fire the mirror without a body so a single large upload can't blow up proxy memory. Defaults to 1 MiB. |

Mirror requests carry `X-Sbproxy-Mirror: 1` and the original `X-Sbproxy-Request-Id` so the shadow upstream can distinguish them from real traffic. Method, path/query, and headers are mirrored; body teeing is not yet supported (sufficient for read endpoints; POST bodies are not replayed in this cut). Hop-by-hop headers and `Host` are not forwarded, `reqwest` rebuilds `Host` from the mirror URL.

See [example 75](../examples/75-request-mirror/sb.yml).

---

## Upstream retries

When an upstream connection fails (TCP refused, DNS failure, TLS handshake error, or connect timeout), the proxy can retry the request automatically.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://backend.internal:8080
      retry:
        max_attempts: 3
        retry_on:
          - connect_error
          - timeout
        backoff_ms: 100
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_attempts` | int | `1` | Total request attempts including the original. `1` disables retries. |
| `retry_on` | array | `[connect_error, timeout]` | Retry conditions. Currently honoured: `connect_error`, `timeout`. Status-code retries (`502`, `503`, ...) are accepted but not yet wired in this cut because they require buffering the upstream response. |
| `backoff_ms` | int | `100` | Base backoff before the next attempt. Doubles on each retry, capped at 5000ms. |

`retry` is accepted on both `proxy` and `load_balancer` actions. For `load_balancer`, a failed target is reported to the outlier detector and circuit breaker so the next retry attempt selects a different healthy peer rather than retrying the same dead target.

See [example 76](../examples/76-upstream-retries/sb.yml).

---

## Active health checks

Configure background probes per `load_balancer` target. The proxy GETs the probe URL on a fixed interval and tracks consecutive success / failure counts. Targets that fail the threshold are excluded from `select_target` until they recover. Probe results also feed the outlier detector when one is configured, so passive and active signals share state.

```yaml
action:
  type: load_balancer
  targets:
    - url: http://backend-1.internal:8080
      health_check:
        path: /healthz
        interval_secs: 10        # probe period in seconds
        timeout_ms: 2000
        unhealthy_threshold: 3
        healthy_threshold: 2
    - url: http://[2001:db8::1]:8080
      health_check:
        path: /healthz
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `/healthz` | Path to probe. Must start with `/`. |
| `interval_secs` | int | `10` | Probe period in seconds (alias: `period_secs`). |
| `timeout_ms` | int | `2000` | Per-probe timeout. |
| `unhealthy_threshold` | int | `3` | Consecutive failures required to mark unhealthy. |
| `healthy_threshold` | int | `2` | Consecutive successes required to recover. |

IPv6 targets are supported: the URL builder preserves bracketing. See [example 77](../examples/77-active-health-checks/sb.yml).

---

## Circuit breaker

A formal Closed → Open → HalfOpen → Closed state machine attached to each `load_balancer` target. On `failure_threshold` consecutive failures (5xx response, connect error, timeout) the breaker trips Open; every subsequent request to that target is excluded from `select_target` and routed to a healthy peer instead. After `open_duration_secs`, the breaker enters HalfOpen and admits probe requests; on `success_threshold` consecutive successes it closes again, otherwise it re-opens.

```yaml
action:
  type: load_balancer
  circuit_breaker:
    failure_threshold: 5         # trip after 5 consecutive failures
    success_threshold: 2         # close after 2 consecutive HalfOpen successes
    open_duration_secs: 30       # stay Open for 30s before trying probes
  targets:
    - url: http://backend-1.internal:8080
    - url: http://backend-2.internal:8080
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_threshold` | int | `5` | Consecutive failures before tripping Open. |
| `success_threshold` | int | `2` | Consecutive successes in HalfOpen to return to Closed. |
| `open_duration_secs` | int | `30` | How long the breaker stays Open before admitting probes. |

The breaker is **complementary to** [outlier detection](#outlier-detection):

| Signal | Trigger |
|---|---|
| Circuit breaker | `N` failures in a row, immediate isolation |
| Outlier detection | Failure *rate* over a sliding window |

Either signal independently ejects a target from `select_target`. Configure both for robust resilience: outlier detection catches "this target is bad in aggregate," the breaker catches "this target is hard down right now." When every target is tripped, the LB falls back to the unfiltered list rather than 502'ing the client.

See [example 84](../examples/84-circuit-breaker/sb.yml).

---

## Outlier detection

Track each `load_balancer` target's success/failure rate over a sliding window and eject targets whose error rate crosses the threshold. Failures are recorded from upstream 5xx responses and from connect errors; recovery happens automatically after the cooldown.

```yaml
action:
  type: load_balancer
  outlier_detection:
    threshold: 0.5              # 50% error rate
    window_secs: 60             # sliding window length
    min_requests: 5             # minimum requests in window before ejection
    ejection_duration_secs: 30  # cooldown before re-admission
  targets:
    - url: http://backend-1.internal:8080
    - url: http://backend-2.internal:8080
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `threshold` | float | `0.5` | Failure rate at which to eject (0.0–1.0). |
| `window_secs` | int | `60` | Sliding window length in seconds. |
| `min_requests` | int | `5` | Minimum requests in the window before ejection is considered. |
| `ejection_duration_secs` | int | `30` | How long to keep an ejected target out of rotation. |

When all active targets are ejected, the proxy falls back to the unfiltered list rather than 502'ing the client (better to send to a flaky peer than to fail closed). See [example 78](../examples/78-outlier-detection/sb.yml).

---

## Service discovery

Without service discovery, the proxy resolves an upstream hostname once when a connection is established and the connection pool reuses that connection (and that IP) for as long as the connection lives. When the upstream's IP set changes, K8s `Service` endpoints rotate, ECS Cloud Map adds a new task, the backend behind a `Headless` service scales horizontally, the proxy keeps using the stale IP until the connection eventually closes.

`service_discovery` on a `proxy` action makes the proxy re-resolve the hostname every `refresh_secs` and rotate the chosen upstream IP across the current A/AAAA record set.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.namespace.svc.cluster.local:8080
      service_discovery:
        enabled: true
        refresh_secs: 30        # default
        ipv6: true              # default; drop to false to skip AAAA
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch. The presence of the block usually means "I want it on"; set `false` to keep the config without enabling. |
| `refresh_secs` | int | `30` | How often to re-resolve. Setting this below the upstream record's actual TTL has no effect, the system resolver applies its own caching, but the proxy will at least notice changes within `refresh_secs` of the upstream-side update. |
| `ipv6` | bool | `true` | Whether AAAA records contribute to the rotation set. |

The hostname stays as the SNI / `Host` header so TLS verification continues to match the certificate that was issued for the hostname. IPv6 resolved addresses are wrapped in brackets (`[2001:db8::1]:port`) when handed to Pingora. Round-robin selection within the resolved set spreads load across all current IPs.

When DNS resolution fails (network glitch, hostname temporarily NXDOMAIN), the proxy falls back to letting Pingora's connect-time resolver handle the lookup.

See [example 83](../examples/83-service-discovery/sb.yml).

---

## Correlation ID

The proxy mints a per-request correlation identifier early in the request lifecycle. With the default policy:

1. If the inbound request carries `X-Request-Id`, its value becomes the request's correlation ID. Upstream callers (a frontend, an API client, another proxy) get to thread their traces through ours.
2. Otherwise the proxy generates a fresh UUID v4 (32 hex chars).
3. The chosen value is set on the upstream request under the same header name so the upstream sees the same ID the proxy logged.
4. The chosen value is echoed back to the client on the response, so the client can hand it to support to find the matching server logs.

```yaml
proxy:
  correlation_id:
    enabled: true              # default
    header: X-Request-Id       # default; rename for shops that use X-Correlation-Id
    echo_response: true        # default; set false to omit the response header
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch. |
| `header` | string | `X-Request-Id` | Header name read on ingress, set on the upstream, and echoed on the response. |
| `echo_response` | bool | `true` | Whether to set the header on the downstream response. |

The same value is exposed as `ctx.request_id` to every other component: webhook envelopes (`X-Sbproxy-Request-Id`), access logs, alert webhooks, and the AI gateway's per-call records. Set `enabled: false` to opt out entirely.

Inbound values longer than 256 characters are ignored (the proxy generates a fresh ID). Empty / whitespace-only inbound values are ignored.

See [example 80](../examples/80-correlation-id/sb.yml).

---

## mTLS client authentication

When set, the HTTPS listener requires (or optionally accepts) a client TLS certificate signed by the configured CA bundle. The verification happens during the TLS handshake, clients without a valid cert are rejected before `request_filter` ever runs.

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  tls_cert_file: /etc/ssl/sbproxy/server.pem
  tls_key_file: /etc/ssl/sbproxy/server.key
  mtls:
    client_ca_file: /etc/ssl/sbproxy/clients-ca.pem
    require: true              # default; set false to allow anonymous TLS clients
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `client_ca_file` | string | required | PEM-encoded CA bundle used to verify client certs. May contain multiple `BEGIN CERTIFICATE` blocks; each becomes a trust anchor. |
| `require` | bool | `true` | When `true`, the handshake fails if the client does not present a certificate. When `false`, anonymous clients are admitted and the upstream sees no `X-Client-Cert-*` headers (so it can choose its own policy). |

After a successful handshake, the proxy strips any inbound `X-Client-Cert-*` headers (so a non-TLS client cannot forge them) and sets the verified cert metadata for the upstream:

| Header | Value |
|---|---|
| `X-Client-Cert-Verified` | `1` |
| `X-Client-Cert-CN` | Subject Common Name, when present |
| `X-Client-Cert-SAN` | Comma-separated `DNS:`/`URI:`/`email:`/`IP:` SANs |
| `X-Client-Cert-Organization` | Subject's `O` field, when present |
| `X-Client-Cert-Serial` | hex serial number |
| `X-Client-Cert-Fingerprint` | hex SHA-256 of the cert |

CN and SAN are extracted by a wrapping `ClientCertVerifier` that captures them at handshake time and indexes by SHA-256 of the cert DER (which matches Pingora's internal `cert_digest`). Chain validation is unchanged. The cache is bounded so a churning client population does not grow it without bound.

See [example 85](../examples/85-mtls-client-auth/sb.yml).

---

## Webhook envelope and signing

Every webhook the proxy fires (`on_request`, `on_response`, alerting channels) carries a standard identifying envelope and optional HMAC-SHA256 signature.

### Envelope

```json
{
  "event": "on_request",
  "proxy": {
    "instance_id": "sbproxy-host-7c4d8b9a",
    "version": "0.1.0",
    "config_revision": "a7b3f9c11d80"
  },
  "request": {
    "id": "01j9x4af1k73c5dvkk1xvb6f9w",
    "received_at": "2026-04-25T07:32:00Z"
  },
  "origin": { "name": "api.example.com" },
  "method": "GET",
  "path": "/api/users",
  "host": "api.example.com",
  "client_ip": "203.0.113.7",
  "headers": { "...": "..." }
}
```

`on_response` payloads include the same `proxy.*` and `request.id` fields, plus `status` and `duration_ms`, so receivers can correlate the request/response pair.

### Headers on the webhook request

| Header | Value |
|---|---|
| `User-Agent` | `sbproxy/<version>` |
| `X-Sbproxy-Event` | `on_request`, `on_response`, or `alert` |
| `X-Sbproxy-Instance` | per-process instance identifier |
| `X-Sbproxy-Request-Id` | matches `request.id` in the envelope |
| `X-Sbproxy-Config-Revision` | short hex hash of the loaded config |
| `X-Sbproxy-Timestamp` | unix seconds at send time |
| `X-Sbproxy-Signature` | `v1=<hex>` (only when `secret` is configured) |

### Signing

Set a `secret` on the callback to enable HMAC-SHA256:

```yaml
on_request:
  - url: https://hooks.example.com/sbproxy
    method: POST
    secret: shared-webhook-secret
    timeout: 5
```

The signed material is `"<timestamp>.<body>"`. Receivers should:

1. Read `X-Sbproxy-Timestamp` and reject anything older than ~5 minutes (replay defence).
2. Compute `HMAC-SHA256(secret, timestamp + "." + raw_body)`.
3. Compare to `X-Sbproxy-Signature` (`v1=<hex>`) using a constant-time comparison.

The same `secret` field is accepted on alert webhook channels (`proxy.alerting.channels[]`). See [example 79](../examples/79-webhook-signing/sb.yml).

---

## Secrets

The top-level `proxy.secrets` block configures how `secret:` references are resolved at config-load time and how rotation is handled.

```yaml
proxy:
  secrets:
    backend: hashicorp
    hashicorp:
      addr: https://vault.example.com:8200
      token: ${VAULT_TOKEN}
      mount: secret
    map:
      openai_key: secret/data/prod/openai_key
      db_password: secret/data/prod/db_password
    rotation:
      grace_period_secs: 300
      re_resolve_interval_secs: 60
    fallback: cache
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | string | `env` | Backend used to resolve secrets. Supported: `env`, `local`, `hashicorp`. |
| `hashicorp.addr` | string | | Vault server address (required when `backend = hashicorp`) |
| `hashicorp.token` | string | from `VAULT_TOKEN` env var | Vault token |
| `hashicorp.mount` | string | `secret` | KV secrets engine mount path |
| `map` | map | | Logical-name to vault-path mapping |
| `rotation.grace_period_secs` | int | 300 | Seconds the previous secret value remains valid after rotation |
| `rotation.re_resolve_interval_secs` | int | 60 | How often to re-fetch secrets from the backend |
| `fallback` | string | `cache` | Strategy when the backend is unavailable. Supported: `cache`, `reject`, `env`. |

The `extensions` map at both the proxy and the origin level holds opaque blocks consumed by enterprise / third-party crates. OSS does not parse them.

---

## Environment variables

Reference environment variables anywhere in the config with `${VAR_NAME}` syntax to keep secrets out of config files.

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

Environment variables are resolved at config load time. An unset variable leaves the literal `${VAR_NAME}` string in place rather than failing the load.

Common pattern: load variables from `.env` with your shell or Docker:

```bash
export BACKEND_URL=https://backend.internal:8080
export API_KEY=my-secret-key
sbproxy serve -f sb.yml
```

---

## ACME / auto TLS

SBproxy can automatically provision and renew TLS certificates using the ACME protocol (Let's Encrypt or any ACME-compatible CA).

### Production setup (Let's Encrypt)

```yaml
proxy:
  http_bind_port: 80
  https_bind_port: 443
  acme:
    enabled: true
    email: admin@example.com
    storage_path: /var/lib/sbproxy/certs

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    force_ssl: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Master switch for ACME-managed TLS |
| `email` | string | | Account contact email registered with the ACME directory |
| `directory_url` | string | Let's Encrypt production | ACME directory URL |
| `challenge_types` | list | `[tls-alpn-01, http-01]` | Allowed challenge types in priority order |
| `storage_backend` | string | `redb` | Backing store for issued certificates (`redb`, `sqlite`) |
| `storage_path` | string | `/var/lib/sbproxy/certs` | Filesystem path for the certificate store |
| `renew_before_days` | int | 30 | Days before expiry to attempt renewal |

### Local development (Pebble)

Pebble is a test ACME server suitable for local development. Point `directory_url` at it:

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  acme:
    enabled: true
    email: test@example.com
    directory_url: https://pebble:14000/dir
    storage_path: /tmp/certs
```

---

## Redis integration

Redis has two roles in SBproxy: distributed caching (L2 cache) and real-time messaging (config sync, cache invalidation). Both blocks are nested under `proxy:`.

### L2 cache (distributed rate limiting and caching)

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://redis.internal:6379/0
```

When configured, rate limit counters are shared across all proxy instances. Response cache entries can also be stored in Redis for shared caching. The deserializer also accepts `l2_cache:` as a canonical alias.

### Messenger (real-time config updates)

```yaml
proxy:
  messenger_settings:
    driver: redis
    params:
      dsn: redis://redis.internal:6379
```

When configured, config changes pushed via the API propagate to all proxy instances in real time over Redis Streams.

The Redis driver expects `params.dsn`. SQS uses `queue_url`, `region`, `api_key`. GCP Pub/Sub uses `project`, `topic`, `subscription`, `access_token`. The `memory` driver takes no params and is single-replica only.

### Full Redis setup

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
      dsn: redis://redis.internal:6379

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    policies:
      - type: rate_limiting
        requests_per_minute: 100
    response_cache:
      enabled: true
      ttl_secs: 300
```

---

## Validation

Check the configuration for errors without starting the proxy:

```bash
sbproxy validate -c sb.yml
```

This catches:
- YAML syntax errors
- Missing required top-level fields
- Unknown action / policy / transform types

Validate every config change before deploying to production. Metrics are exposed via the embedded admin server: set `proxy.admin.enabled: true`, `proxy.admin.port: 9090`, and tune `proxy.metrics.max_cardinality_per_label` for high-traffic deployments.

---

## CORS

Configure Cross-Origin Resource Sharing as a top-level origin field:

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
| `enable` | bool | false | Enable CORS header injection. Alias: `enabled`. |
| `allow_origins` | list | | Allowed origins (use `["*"]` for any). Alias: `allowed_origins`. |
| `allow_methods` | list | standard methods | Allowed HTTP methods. Alias: `allowed_methods`. |
| `allow_headers` | list | standard headers | Allowed request headers. Alias: `allowed_headers`. |
| `expose_headers` | list | | Headers exposed to the browser |
| `max_age` | int | | Preflight cache duration in seconds |
| `allow_credentials` | bool | false | Allow credentials (cookies, auth headers) |

---

## Quick reference: config field locations

A common mistake is nesting fields inside `action` when they should be siblings. The correct layout:

```yaml
origins:
  "api.example.com":
    # These are ALL at the same level (siblings of action):
    action: { ... }
    authentication: { ... }
    policies: [ ... ]
    transforms: [ ... ]
    request_modifiers: [ ... ]
    response_modifiers: [ ... ]
    forward_rules: [ ... ]
    response_cache: { ... }
    variables: { ... }
    session: { ... }
    cors: { ... }
    compression: { ... }
    hsts: { ... }
    connection_pool: { ... }
    mirror: { ... }                # shadow traffic; sibling of action
    on_request: [ ... ]            # webhook callbacks
    on_response: [ ... ]
    extensions: { ... }
```

None of these belong inside the `action` block. The `action` block only contains action-specific fields (type, url, targets, providers, etc.).

A handful of fields *do* live inside an action because they govern how the proxy talks to that specific upstream:

```yaml
action:
  type: proxy
  url: https://upstream.example/api
  host_override: api.upstream.example       # rewrite the upstream Host
  disable_via_header: true                  # any of the disable_*_header flags
  retry: { ... }                            # connect-error retry policy
```

`load_balancer` actions accept an `outlier_detection` block at the action level and per-target `health_check`, `host_override`, and `disable_*_header` flags inside each target.

## Environment variable templating in header modifiers

Request and response header modifiers may reference environment variables using the `{{env.NAME}}` template form. To prevent multi-tenant exfiltration of process secrets, env expansion is gated by an explicit allowlist on `TemplateContext::allowed_env_vars`. This change is tracked under OPENSOURCE.md H4.

- The default allowlist is empty. With the default, every `{{env.X}}` template resolves to the empty string and a `tracing::warn!` is logged. This includes well-known secret names like `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and any custom `_TOKEN` / `_KEY` env vars set on the proxy process.
- Operators opt in per-installation by adding env var names to `TemplateContext::allowed_env_vars` when populating the per-request template context. Names are matched literally; case matters.
- Allowlisted env vars that are unset at the OS level resolve to the literal `{{env.X}}` string so misconfiguration shows up as obviously broken header values rather than silently empty ones.

Example header modifier and the matching allowlist a deployment would use:

```yaml
request_modifiers:
  - headers:
      set:
        X-Build-Id: "{{env.SBPROXY_BUILD_ID}}"
        X-Region:   "{{env.SBPROXY_REGION}}"
```

```rust
// Inside the proxy runtime that builds TemplateContext per request.
let mut tmpl = sbproxy_middleware::modifiers::TemplateContext::new();
tmpl.allowed_env_vars.push("SBPROXY_BUILD_ID".to_string());
tmpl.allowed_env_vars.push("SBPROXY_REGION".to_string());
```

A header value of `{{env.AWS_SECRET_ACCESS_KEY}}` will not resolve unless `AWS_SECRET_ACCESS_KEY` is added to that allowlist. There is no global "allow all env vars" switch.
