# SBproxy features manual

*Last modified: 2026-05-03*

Reference for SBproxy features. Each section covers what a feature does, how to configure it, and a working example against `test.sbproxy.dev`.

---

## 1. Overview

SBproxy is a reverse proxy and AI gateway shipped as a single binary, built on Cloudflare's Pingora framework. It handles HTTP proxying and LLM API traffic from one config file.

Core capabilities:
- Reverse proxy with hot reload, path routing, and forward rules
- AI gateway with 20+ native provider integrations (route through OpenRouter for 200+ models), model routing, and budget enforcement
- Load balancer with multiple algorithms, health checks, and circuit breakers
- 7 authentication methods, 10 security policies, 19 response transforms
- CEL, Lua, JavaScript, and WASM scripting for custom logic
- MCP server for AI agent tool use

### Install

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
make build-release
# Binary at target/release/sbproxy

# Docker
docker pull ghcr.io/soapbucket/sbproxy:latest
```

### Run

```bash
make run CONFIG=sb.yml           # Convenience runner
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

## 2. Proxy basics

### How requests are processed

Every request flows through an ordered pipeline:

1. Host filter: blocks unknown hostnames (bloom filter, fast reject)
2. Global middleware: connection tracking, protocol detection
3. Config lookup: find origin config by hostname
4. Authentication: validate credentials (if configured)
5. Policies: rate limiting, WAF, IP filter, etc. (in order)
6. Callbacks: `on_request` hooks for dynamic enrichment
7. Action: proxy, redirect, static response, etc.
8. Response transforms: body and header modification
9. Response modifiers: header injection and cleanup

### Hostname matching

Origins match by exact hostname. The `Host` header determines which origin config is used.

```yaml
origins:
  "api.example.com":        # Exact match
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

For wildcard or pattern-based routing, use `forward_rules` within an origin to dispatch based on path, headers, or query parameters.

### Hot reload

SBproxy watches config files for changes and reloads without dropping connections.

- Config changes take effect within seconds
- In-flight requests finish under the previous config
- Invalid configs are rejected; the last valid config stays active
- Check logs for `config reloaded` or `config reload failed`

---

## 3. AI gateway

The `ai_proxy` action turns SBproxy into an OpenAI-compatible API gateway. It accepts OpenAI Chat Completions requests and routes them to one or more configured providers.

### Providers

SBproxy ships with 36 OpenAI-compatible providers plus a native Anthropic translator and the OpenRouter aggregator routing 200+ more. Adapters include openai, anthropic, gemini, azure, bedrock, cohere, mistral, groq, deepseek, ollama, vllm, together, fireworks, perplexity, xai, sagemaker, databricks, oracle, watsonx, openrouter, plus three local-runtime adapters (`tgi`, `lmstudio`, `llamacpp`). The `provider_type` field on a provider picks the adapter (when unset, SBproxy infers it from `name`). For models not covered by a native adapter, route through the openrouter provider (200+ models), or use a self-hosted OpenAI-compatible server via the `vllm`/`generic` adapter with a custom `base_url`.

```yaml
origins:
  "ai.test.sbproxy.dev":
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini, o1-mini]
          default_model: gpt-4o-mini

        - name: anthropic
          provider_type: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-3-5-sonnet-20241022, claude-3-5-haiku-20241022]

        - name: local
          provider_type: ollama
          base_url: http://localhost:11434
          models: [llama3.2, qwen2.5]
```

When `provider_type` is omitted, SBproxy infers it from `name`.

```bash
# Chat completion
curl -H "Host: ai.test.sbproxy.dev" \
     -H "Content-Type: application/json" \
     -X POST http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'

# List models
curl -H "Host: ai.test.sbproxy.dev" http://localhost:8080/v1/models
```

See [providers.md](providers.md) for the full provider matrix.

### Routing strategies

The `routing.strategy` field controls how requests are distributed across providers.

| Strategy | Description |
|---|---|
| `round_robin` | Cycle through providers in order |
| `weighted` | Distribute by provider weight |
| `fallback_chain` | Try in order, fall back on failure |
| `random` | Pick a provider uniformly at random |
| `lowest_latency` | Route to the fastest responding provider |
| `cost_optimized` | Route to cheapest provider per token |
| `least_connections` | Route to provider with fewest active requests |
| `token_rate` | Balance by token consumption rate |
| `sticky` | Pin requests to a provider using session/key |

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
```

Provider order in the `providers` list determines fallback order. The router walks the list and tries each provider until one succeeds.

### Streaming

All providers stream responses over Server-Sent Events (SSE). Set `"stream": true` in the request body.

```bash
curl -H "Host: ai.test.sbproxy.dev" \
     -H "Content-Type: application/json" \
     -X POST http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"Count to 5"}]}'
```

### Budget enforcement

Cap AI spend and token usage by workspace, API key, or user:

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
        downgrade_to: gpt-4o-mini    # Per-limit downgrade target
    on_exceed: block                  # "block", "log", or "downgrade"
```

`on_exceed` is one of:
- `block`: reject the request with 429 (default)
- `log`: log a warning but allow the request through
- `downgrade`: rewrite the request's model to the limit's `downgrade_to` value

### Unified model registry

When clients send requests with any model name, SBproxy routes to the provider that serves it (based on each provider's `models:` list). No extra flag is required:

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
```

A request for `"model": "claude-3-5-sonnet-20241022"` routes to Anthropic; a request for `"model": "gpt-4o"` routes to OpenAI.

### Cost headers

AI responses pick up cost headers:

- `X-Sb-Cost-Usd`: estimated cost in USD
- `X-Sb-Tokens-In`: input tokens
- `X-Sb-Tokens-Out`: output tokens
- `X-Sb-Provider`: provider that handled the request
- `X-Sb-Model`: model used

---

## 4. Load balancing

The `load_balancer` action distributes traffic across multiple upstream targets.

### Algorithms

Pick an algorithm via the `algorithm` field. Seven algorithms are supported:

| Algorithm | Description |
|---|---|
| `round_robin` | Cycle through targets in order (default) |
| `weighted_random` | Random selection weighted by target weight |
| `least_connections` | Route to target with fewest active connections |
| `ip_hash` | Consistent hashing by client IP |
| `uri_hash` | Consistent hashing by request URI |
| `header_hash` | Consistent hashing by named header value |
| `cookie_hash` | Consistent hashing by named cookie value |

```yaml
origins:
  "lb.test.sbproxy.dev":
    action:
      type: load_balancer
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

`header_hash` and `cookie_hash` take a nested object naming the source of the hash key:

```yaml
action:
  type: load_balancer
  algorithm:
    header_hash:
      header: X-User-ID
  targets:
    - url: https://backend-1.test.sbproxy.dev
    - url: https://backend-2.test.sbproxy.dev
```

`cookie_hash` follows the same pattern with `cookie: <name>`.

### Sticky sessions

Set `sticky:` to issue an affinity cookie so subsequent requests from the same client return to the same target:

```yaml
action:
  type: load_balancer
  algorithm: round_robin
  sticky:
    cookie_name: _sb_backend     # Defaults to sb_sticky
    ttl: 3600                    # Optional cookie TTL in seconds
  targets:
    - url: https://backend-1.test.sbproxy.dev
    - url: https://backend-2.test.sbproxy.dev
```

`ip_hash`, `header_hash`, and `cookie_hash` are inherently sticky and do not need a separate `sticky:` block.

### Targets

Each target is an object with `url` plus optional fields:

| Field | Type | Description |
|---|---|---|
| `url` | string | Full upstream URL (required) |
| `weight` | int | Weight for `weighted_random` (default 1) |
| `backup` | bool | Reserved for fallback only |
| `group` | string | Tag used by blue-green / canary (`blue`, `green`, `canary`) |
| `priority` | int | 1 (highest) to 10 (lowest); default 5 |
| `zone` | string | Availability zone label for locality routing |
| `health_check` | object | Health check configuration (Go-compat opaque) |

### Deployment modes

Set `deployment_mode:` for blue-green or canary rollouts. Targets must be tagged with the matching `group:`.

Blue-green - 100 percent of traffic goes to the active group:

```yaml
action:
  type: load_balancer
  deployment_mode:
    mode: blue_green
    active: blue
  targets:
    - url: https://blue.example.com
      group: blue
    - url: https://green.example.com
      group: green
```

Canary - `weight` percent of traffic goes to canary targets, the rest to primary:

```yaml
action:
  type: load_balancer
  deployment_mode:
    mode: canary
    weight: 10
  targets:
    - url: https://primary.example.com
    - url: https://canary.example.com
      group: canary
```

### Health checks

Each target has its own health check. Unhealthy targets are dropped from rotation until they recover.

```yaml
action:
  type: load_balancer
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

---

## 5. Authentication

SBproxy supports 7 authentication types. Pick one per origin under `authentication:`.

### API key (`api_key`)

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

### Basic auth (`basic_auth`)

Standard HTTP Basic authentication.

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

### Bearer token (`bearer`)

Accept requests with a valid token in the `Authorization: Bearer` header.

```yaml
authentication:
  type: bearer
  tokens:
    - token-value-1
    - ${BEARER_TOKEN}
```

### JWT (`jwt`)

Validate JSON Web Tokens against a JWKS URL, an inline public key, or a shared secret.

```yaml
authentication:
  type: jwt
  jwks_url: https://auth.test.sbproxy.dev/.well-known/jwks.json
  issuer: https://auth.test.sbproxy.dev
  audience: api.test.sbproxy.dev
  algorithms: [RS256]
  required_claims:
    role: editor       # Map of claim name to required value
```

Use `secret:` instead of `jwks_url:` for HS-family algorithms with a shared HMAC secret.

```bash
TOKEN=$(curl -s https://auth.test.sbproxy.dev/token | jq -r .access_token)
curl -H "Host: api.test.sbproxy.dev" \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/echo
```

### Forward auth (`forward_auth`)

Delegate authentication to an external service. The subrequest result decides access.

```yaml
authentication:
  type: forward_auth
  url: https://auth.test.sbproxy.dev/verify
  method: GET
  headers_to_forward: [Authorization, Cookie]   # Alias: forward_headers
  trust_headers: [X-User-ID, X-User-Role]       # Injected from auth response
  success_status: 200                            # Status that signals success
  timeout: 5000                                  # Milliseconds
```

Headers returned by the auth service that are listed in `trust_headers` are injected into the upstream request.

### Digest auth (`digest`)

HTTP Digest authentication (RFC 7616).

```yaml
authentication:
  type: digest
  users:
    - username: alice
      password: secret123
```

### Noop (`noop`)

Accepts every request without checking credentials. Use it to explicitly mark an origin as unauthenticated.

```yaml
authentication:
  type: noop
```

---

## 6. Security policies

Policies run after authentication, in order. Every policy in the list must pass.

### WAF (web application firewall)

The WAF policy applies ModSecurity-compatible rules, with the OWASP Core Rule Set (CRS) available as an option.

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
        paranoia: 1              # 1 (default) through 4. Top-level field;
                                 # `owasp_crs.paranoia_level` is honored as
                                 # a fallback for back-compat.
        action_on_match: block
        fail_open: false         # Fail closed (block on error)
        test_mode: false         # Set true to log but not block
```

#### Paranoia level

The `paranoia` field follows the OWASP CRS convention. Only rules whose paranoia level is less than or equal to the configured value run on each request. Built-in patterns and custom rules without an explicit `paranoia` attribute default to paranoia=1 and are always evaluated.

| Level | Posture | Trade-off |
|-------|---------|-----------|
| 1 (default) | Baseline. High-confidence signatures only. | Lowest false-positive rate. |
| 2 | Adds stricter signatures (e.g. boolean-blind and time-delay SQLi). | Catches more edge cases; small false-positive uptick. |
| 3 | Aggressive. Edge-case payloads, broader keyword detection. | Notable false-positive risk; review logs before enforcing. |
| 4 | Strictest. Most restrictive ruleset. | Highest false-positive risk. Treat as opt-in for hardened endpoints. |

Custom rules can carry their own `paranoia: <n>` attribute; rules above the policy's level are skipped at evaluation time. Values outside 1-4 are clamped into range.

```bash
# Normal request (passes WAF)
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo

# SQL injection attempt (blocked by WAF)
curl -H "Host: api.test.sbproxy.dev" \
     "http://localhost:8080/echo?id=1%27%20OR%20%271%27=%271"

# Time-based SQLi only flagged when paranoia >= 2
curl -H "Host: api.test.sbproxy.dev" \
     "http://localhost:8080/echo?q=BENCHMARK(1000000,sha1(1))"
```

#### Rule feed

The OSS WAF can subscribe to a remote feed that publishes signed rule bundles. The proxy downloads, verifies, and hot-loads bundles in the background; in-flight requests see a stable snapshot. This lets operators ship updated detection signatures without redeploying.

The publisher side (the service that signs and serves bundles) is shipped as part of the enterprise build. The subscriber documented below is in the OSS proxy.

```yaml
policies:
  - type: waf
    paranoia: 2
    feed:
      enabled: true
      transport: http                  # or "redis"
      url: "https://feed.example.com/waf/rules/owasp-crs-paranoia-4"
      redis_url: "redis://localhost:6379"
      redis_stream: "waf:rules:owasp-crs-paranoia-4"
      channel: "owasp-crs-paranoia-4"  # used for cache filename + events
      auth_token_env: "SBPROXY_FEED_TOKEN"
      signature_key_env: "SBPROXY_FEED_SIGNATURE_KEY"
      poll_interval: 60                # seconds, HTTP transport only
      max_age: 86400                   # reject bundles older than this
      fallback_to_static: true         # keep last-good if feed is unreachable
```

##### Wire contract (canonical)

Two transports are supported.

HTTP polling:

```
GET https://<feed-host>/waf/rules/<channel>?after=<version>
Authorization: Bearer <token>
```

Returns one of:

* `200 OK` with `X-SBProxy-Feed-Sig: <hex hmac-sha256>` over the raw response body, plus a JSON payload (see below).
* `304 Not Modified` when the publisher has nothing newer than `after=<version>`.

Redis Streams:

```
XREAD COUNT 10 BLOCK 5000 STREAMS waf:rules:<channel> $
```

Each entry exposes the fields `version`, `bundle` (the raw JSON document below), and `signature` (hex HMAC-SHA256 over the bundle string).

Bundle payload:

```json
{
  "version": "2026-04-28T12:00:00Z",
  "channel": "owasp-crs-paranoia-4",
  "expires_at": "2026-05-28T00:00:00Z",
  "rules": [
    {
      "id": "942100",
      "paranoia": 4,
      "category": "sqli",
      "pattern": "(?i)\\bunion\\s+select\\b",
      "action": "block",
      "severity": "critical"
    }
  ]
}
```

##### Failure semantics

* Signature mismatch: the bundle is dropped, the failure is logged, and the proxy keeps serving the last-good corpus.
* Network or transport error: warn and keep last-good. When `fallback_to_static: false`, the rule set is cleared and a `WafFeedDown` event is emitted so operators know the proxy is running without dynamic rules.
* Bundle older than `max_age`: rejected as stale.
* On every successful fetch the raw bundle and its signature are persisted to `~/.cache/sbproxy/waf-feed-<channel>.json`. A cold proxy start with the feed unreachable still hot-loads that last-good corpus.

##### Merge semantics

Feed rules are evaluated alongside the built-in OWASP-lite signatures and any inline `custom_rules`. They share the same `paranoia` gate as the rest of the policy: a rule with `paranoia: 4` only runs when the policy's `paranoia` is also >= 4. A feed rule whose `id` matches an inline custom rule shadows the inline rule, so operators can ship overrides through the publisher without redeploying.

### HTTP framing defenses (request smuggling)

Defends against the request-smuggling / desync attack class documented at <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn> by rejecting requests whose framing is ambiguous BEFORE they reach the upstream.

```yaml
policies:
  - type: http_framing
```

The policy is on/off only. There are no tunable knobs because each violation maps to a known smuggling primitive that no legitimate caller produces.

#### What it rejects (all return 400)

| Violation | Reason label | What it catches |
|---|---|---|
| Dual CL+TE | `dual_cl_te` | A request carries both `Content-Length` and `Transfer-Encoding`. RFC 9112 § 6.1 says receivers MUST pick one and SHOULD reject; we reject so a downstream proxy or upstream cannot disagree with our pick. |
| Duplicate CL | `duplicate_cl` | Multiple `Content-Length` headers, or a single CL with a comma-folded list (`6, 6`), or non-numeric / negative CL. |
| Malformed TE | `malformed_te` | Any `Transfer-Encoding` value that is not exactly `chunked` after trimming + lowercasing. Catches `xchunked`, `Transfer-Encoding: gzip, chunked` chains, `identity`, and similar smuggling primitives. |
| Duplicate TE | `duplicate_te` | Multiple `Transfer-Encoding` headers. The classic TE.TE attack relies on one parser honoring the first and another the last. |
| Control chars | `control_chars` | CR, LF, or NUL bytes in any header value. Defense in depth: `http::HeaderValue` already rejects these at construction; the policy is the safety net for any future parser regression. |

#### Defense layers

The protection is multi-layered:

1. **Pingora HTTP/1.1 parser** rejects most wire-level malformed input at parse time.
2. **Request normalization**: when a smuggling-shaped request slips through, Pingora reparses it before forwarding upstream, so the upstream receives a clean HTTP/1.1 request with a single canonical framing header. This closes the on-wire smuggle even when the policy itself does not see the original ambiguity.
3. **Hop-by-hop strip** (`crates/sbproxy-core/src/dispatch.rs:414`) removes `Transfer-Encoding`, `TE`, `Connection`, `Upgrade`, `Keep-Alive`, `Proxy-Connection`, and `Trailer` from the forwarded request, eliminating CL.TE attacks where the attacker injects `Transfer-Encoding: chunked` hoping the backend honors it. This layer also closes HTTP/2 → HTTP/1 downgrade smuggling: an attacker who reaches the proxy over h2c and sets `transfer-encoding: chunked` as a regular header still cannot smuggle that header to the H1 upstream because the strip runs at every hop regardless of inbound protocol.
4. **`http_framing` policy** (this section) rejects the semantic ambiguities Pingora's parser does not catch, with explicit `400 Bad Request` and observable signals.

#### Observability

Every block fires three signals so operators can monitor the attack rate independently of other policy denies:

| Signal | Channel | Usage |
|---|---|---|
| `sbproxy_http_framing_blocks_total{reason}` | Prometheus, 5-cardinality | Dashboard the attack rate by reason |
| `tracing::warn target=sbproxy::http_framing` | Operational log | Lands alongside other policy events |
| `SecurityAuditEntry` JSON, `target=security_audit` | Dedicated security log channel | Route to SIEM via tracing's per-target subscriber |

The `security_audit` channel is separate from the operational log; route it to a dedicated sink (Splunk, Datadog Security, etc.) by filtering tracing events on `target=security_audit`. The schema deliberately omits the offending header value to avoid SIEM poisoning via attacker-controlled data; the stable `reason` discriminator is enough for triage. The full audit envelope:

```json
{
  "timestamp": "2026-04-29T18:42:00Z",
  "event_type": "framing_violation",
  "reason": "dual_cl_te",
  "hostname": "api.example.com",
  "client_ip": "203.0.113.7",
  "request_id": "req-abc123",
  "method": "POST",
  "status_code": 400
}
```

#### Recommended configuration

The policy ships off by default in OSS. Enable on every public-facing origin:

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: "https://upstream.internal:8080"
    policies:
      - type: http_framing
      # ... other policies
```

There is no measurable per-request cost; the policy reads two headers from a `HashMap` lookup.

### DDoS protection

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

### Rate limiting

Cap request rates per client IP with four algorithm choices.

```yaml
policies:
  - type: rate_limiting
    requests_per_minute: 60       # Or requests_per_second
    burst: 10                     # Bucket capacity, defaults to the rate
    algorithm: token_bucket       # Hint: token_bucket or fixed_window
    whitelist:
      - 127.0.0.1
      - 10.0.0.0/8
    headers:
      enabled: true               # Add X-RateLimit-* headers
      include_retry_after: true
```

When an L2 store (Redis) is attached, SBproxy switches to a distributed fixed-window counter so multiple proxy replicas share a single limit.

```bash
# Send 15 rapid requests to trigger rate limiting
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
       -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo
done
```

#### Rate limit by JWT claim

The `key:` field accepts a CEL expression evaluated against the request context. Each distinct value gets its own token bucket via an LRU cache (default 100k keys; tune with `max_keys`). Useful for the API Shield "volumetric abuse detection" pattern: cap traffic per tenant, per API key, or per JWT subject without giving a noisy tenant the headroom of the global limit.

```yaml
policies:
  - type: rate_limiting
    requests_per_minute: 100
    burst: 20
    key: 'jwt.claims.tenant_id'   # bucket per tenant
    max_keys: 50000               # cap on tracked keys (LRU eviction)
    headers:
      enabled: true
```

Common keying idioms:

| Expression | Bucketing |
|------------|-----------|
| `connection.remote_ip` | per-IP (the default when `key:` is unset) |
| `request.headers["x-api-key"]` | per-API-key |
| `jwt.claims.sub` | per-subject |
| `jwt.claims.tenant_id` | per-tenant |
| `jwt.claims.sub + ":" + jwt.claims.tenant_id` | composite |

`jwt.claims` is decoded from `Authorization: Bearer <jwt>` without checking the signature. The rate-limit key is using the token as data; the `jwt` auth provider remains responsible for actually authenticating the caller. When the expression fails or returns empty, the bucket falls back to the default IP-based key. Full CEL surface: see [scripting.md](scripting.md).

### IP filtering

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
```

If `whitelist` is non-empty, the client IP must match an entry. `blacklist` always takes effect when set.

### CSRF protection

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

### Security headers

Inject security-oriented HTTP response headers.

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
        value: "camera=()"
    # Optional: detailed CSP block for nonce / dynamic routes only.
    content_security_policy:
      policy: "default-src 'self'; script-src 'self' 'nonce-{generated}'; connect-src 'self' https://api.test.sbproxy.dev"
      enable_nonce: true       # true to inject per-request nonce in script-src/style-src
      report_only: false
      report_uri: ""
      # dynamic_routes:
      #   "/admin":
      #     policy: "default-src 'self' admin.example.com"
```

### Request limiting

Enforce limits on request size and complexity.

```yaml
policies:
  - type: request_limiting
    max_body_size: 10485760        # 10 MB, in bytes
    max_url_length: 2048
    max_header_count: 50           # Alias: max_headers_count
    max_header_size: "8KB"
    max_query_string_length: 4096
    max_request_size: "10MB"
```

Any limit set to `null` (or omitted) is unchecked. Sizes accept either a raw byte count or a string with `KB`/`MB` suffixes.

### SRI (subresource integrity)

Validate resource integrity hashes in HTML responses.

```yaml
policies:
  - type: sri
    enforce: true
    algorithms: [sha384, sha512]
```

### Expression policy (CEL/Lua)

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
- `request.method`: HTTP method string
- `request.path`: request path
- `request.query`: map of query parameters
- `request.headers`: map of headers (lowercased, hyphens as underscores)
- `request.host`: Host header value
- `now`: current timestamp

---

## 7. Caching

### Response cache

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

Decide which request attributes create distinct cache entries:

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

### Implementation: Vary, query normalization, SWR, mutation invalidation

The Rust pipeline ships a subset of the schema above with concrete
runtime semantics. The fields below are live in OSS today and pinned
by `e2e/tests/cache_response.rs`.

#### `vary`

List the request headers whose values must segment the cache key.
Header names are matched case-insensitively; missing headers contribute
an empty value (still distinct from any non-empty value).

```yaml
response_cache:
  enabled: true
  ttl: 60
  vary: ["Accept", "Accept-Language", "X-App-Version"]
```

The cache key shape is
`<workspace>:<hostname>:<method>:<path>:<canonical-query>:<vary-fingerprint>`,
where `vary-fingerprint` is a SHA-256 prefix over the lowercased
(name, value) pairs. This bounds key length even when callers send
long header values.

#### `query_normalize`

Controls how the query string contributes to the cache key.

```yaml
# Default. Sorts params alphabetically by name; preserves duplicates
# and values. `?a=1&b=2` and `?b=2&a=1` collapse to one entry.
response_cache:
  query_normalize:
    mode: sort

# Drop the query entirely. `/x?utm_source=foo` and `/x?utm_source=bar`
# share a single cache entry.
response_cache:
  query_normalize:
    mode: ignore_all

# Keep only the listed params. Unlisted params are dropped before
# the cache key is computed; retained params are sorted.
response_cache:
  query_normalize:
    mode: allowlist
    allowlist: ["page", "lang"]
```

#### `stale_while_revalidate`

When set, an entry past TTL but still within
`ttl + stale_while_revalidate` seconds is served immediately with
`x-sbproxy-cache: STALE`. A background fetch (tracked by
`CACHE_REVALIDATE_TASKS` for graceful shutdown) refreshes the cache
in parallel. Subsequent requests inside the window continue to see
the stale entry until the refresh lands.

```yaml
response_cache:
  enabled: true
  ttl: 60
  stale_while_revalidate: 300   # 5 minutes of grace past TTL
```

The refresh path applies the same `cacheable_status` gate as the live
path, so a transient 5xx during revalidation does not poison the
cache; the stale entry simply expires naturally once the SWR window
closes.

#### `invalidate_on_mutation`

When `true` (the default), `POST` / `PUT` / `PATCH` / `DELETE` to a
path evicts every cached `GET` entry for that path before the
mutation is forwarded to the upstream. The eviction walks the cache
by the prefix
`<workspace>:<hostname>:GET:<path>:`
so every Vary fingerprint and every query-string variant is dropped
in a single sweep. Set to `false` to keep stale GET entries alive
through writes (rare, useful for read-heavy origins where mutation
is followed by an explicit cache-bust elsewhere).

```yaml
response_cache:
  enabled: true
  ttl: 300
  invalidate_on_mutation: true   # default
```

Mutation invalidation runs through the same `delete_prefix` hook
that the in-process `MemoryCacheStore` implements directly. Backends
that cannot scan keys efficiently (Redis, memcached) treat
`delete_prefix` as a no-op and rely on TTL expiry instead. For those
deployments, set a short `ttl` plus a generous `stale_while_revalidate`
window if write-after-read freshness matters.

---

## 8. Content transforms

Transforms modify request or response bodies. Multiple transforms run in order. SBproxy ships nineteen transform types; the common ones are documented here.

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
        fields: [id, name, email]     # Or use the alias `include`
        # To exclude instead, flip the bool:
        # fields: [password, secret]
        # exclude: true
```

```bash
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/echo
# Response JSON only contains id, name, email fields
```

### JSON field manipulation

Set, remove, or rename top-level fields in a JSON response:

```yaml
transforms:
  - type: json
    set:
      proxy: sbproxy
      version: "1.0"
    remove: [internal_token, debug_info]
    rename:
      old_name: new_name
```

`remove` runs first, then `rename`, then `set` (so set values overwrite renamed targets).

### JSON schema validation

Reject responses that don't conform to a schema:

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

Inject or remove HTML content and rewrite element attributes:

```yaml
transforms:
  - type: html
    remove_selectors: [script, style, "#banner"]
    inject:
      - position: head_end       # head_end | body_start | body_end
        content: '<script src="/analytics.js"></script>'
      - position: body_end
        content: '<div id="chat-widget"></div>'
    rewrite_attributes:
      - selector: a              # Tag name (CSS selector subset)
        attribute: rel
        value: noopener
    format_options:
      strip_comments: true
      strip_newlines: true
      strip_space: true
      lowercase_tags: true
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

Render Markdown responses as HTML:

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

### HTML to Markdown / HTML optimization

Convert rendered HTML to Markdown for downstream LLM consumers, or shrink HTML for size:

```yaml
transforms:
  - type: html_to_markdown

  - type: optimize_html
    strip_scripts: true
    strip_styles: false
    minify: true
```

### Lua and JavaScript transforms

Run user-supplied scripts to reshape responses. See [scripting.md](scripting.md) for the full API.

```yaml
transforms:
  - type: lua_json
    script: |
      function modify_json(data, ctx)
        data.proxy = "sbproxy"
        return data
      end

  - type: javascript
    script: |
      function transform(body) {
        const data = JSON.parse(body);
        data.processed_at = new Date().toISOString();
        return JSON.stringify(data);
      }
```

The Lua entrypoint receives a decoded JSON value and returns the modified value. The JavaScript entrypoint receives the body as a string and returns a string (or any value, which SBproxy serializes via JSON).

### Content negotiation and licensing for AI agents

The content-shaping pillar adds Markdown projection, JSON envelope, citation block, boilerplate stripping, and four well-known projection routes (`/robots.txt`, `/llms.txt`, `/licenses.xml`, `/.well-known/tdmrep.json`) for any origin that has an `ai_crawl_control` policy. Configuration is auto-prepended for AI-enabled origins; agents that send `Accept: text/markdown` or `Accept: application/json` get the right shape, the right pricing tier, and a license URN they can verify against the served `/licenses.xml`.

```yaml
origins:
  "blog.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    transforms:
      - type: boilerplate          # strip nav / footer / aside / comment-section
      - type: markup               # HTML to Markdown via pulldown-cmark
      - type: citation_block       # prepend source / license line when citation_required
      - type: json_envelope        # wrap Markdown in the JSON envelope for application/json
    policies:
      - type: ai_crawl_control
        content_signal: ai-train
        tiers:
          - route_pattern: /articles/*
            content_shape: markdown
            citation_required: true
            price:
              amount_micros: 1000
              currency: USD
```

For the full guide (concept map, two-pass `Accept` resolution, the four projection cookbook, JSON envelope schema, aipref scripting surface, PDF transform teaser), read [content-for-agents.md](content-for-agents.md). For the RSL 1.0 cookbook (license-term recipes, URN format, validation), read [rsl.md](rsl.md). For the operator runbook playbooks (shape rollout, licensing-edit), read [operator-runbook.md](operator-runbook.md).

---

## 9. Scripting

SBproxy embeds four extension languages: CEL, Lua, JavaScript, and WebAssembly. CEL is best for boolean predicates and field selection. Lua and JavaScript handle larger transformation logic. WASM is for sandboxed binary plugins. Full reference in [scripting.md](scripting.md).

### CEL expressions

CEL (Common Expression Language) is a compiled expression engine used in policies, modifiers, forward rules, and routing decisions. Each expression evaluates once per request with access to request context.

Available variables:

| Variable | Type | Description |
|---|---|---|
| `request.method` | string | HTTP method |
| `request.path` | string | URL path |
| `request.query` | map | Query parameters |
| `request.headers` | map | Request headers (lowercase, hyphens as underscores) |
| `request.host` | string | Host header |
| `request.size` | int | Request body size |
| `now` | timestamp | Current time |

Examples:

```yaml
# Expression policy: block non-admin users
policies:
  - type: expression
    cel_expr: request.headers["x-role"] != "admin"
    status_code: 403

# Forward rule condition: route API v2 to different origin
forward_rules:
  - rules:
      - header:
          name: X-API-Version
          value: "2"
    hostname: api-v2.example.com
```

### Lua scripting

Lua scripts handle larger transformations. SBproxy embeds the Luau runtime via the `mlua` crate.

JSON transform: define `modify_json(data, ctx)` to reshape JSON response bodies. `data` is already decoded; return the modified value.

```yaml
origins:
  "api.test.sbproxy.dev":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    transforms:
      - type: lua_json
        script: |
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

Lua context variables (`ctx`):

| Variable | Description |
|---|---|
| `ctx.request_time` | Request start timestamp |
| `ctx.request_id` | Unique request ID |
| `ctx.origin_id` | Origin configuration ID |
| `ctx.workspace_id` | Workspace identifier |

Request modifier with Lua:

```yaml
request_modifiers:
  - lua_script: |
      function modify_request(req)
        req.headers["X-Processed-By"] = "sbproxy"
        req.headers["X-Timestamp"] = tostring(os.time())
        return req
      end
```

### JavaScript

JavaScript transforms run in a QuickJS sandbox. They can return modified bodies or full transformation directives. See [scripting.md](scripting.md) for the complete API.

### WebAssembly

WASM modules run inside the wasmtime runtime, sandboxed from the host. Use them for compiled-language plugins (Rust, AssemblyScript, Go via TinyGo) that need predictable performance.

---

## 10. Observability

### Prometheus metrics

The embedded admin server exposes metrics at `/metrics`. Configure it under `proxy.admin`, with optional cardinality limiting under `proxy.metrics`:

```yaml
proxy:
  admin:
    enabled: true
    port: 9090
  metrics:
    max_cardinality_per_label: 1000
```

```bash
curl http://localhost:9090/metrics
```

Metrics exported:

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

### Structured logging

SBproxy emits structured JSON logs to stderr. Set `SBPROXY_LOG_LEVEL` to control verbosity (`debug`, `info`, `warn`, `error`).

Log output includes: `time`, `level`, `msg`, `origin`, `method`, `path`, `status`, `duration_ms`, `remote_addr`, `request_id`.

### Request envelope: properties, sessions, users

SBproxy stamps every request with a typed observability envelope so downstream tools (in-process subscribers today; the enterprise ingest pipeline and portal next) can slice traffic without re-deriving fields. The envelope shape is locked by `docs/adr-event-envelope.md`; per-stream semantics live in `adr-custom-properties.md`, `adr-session-id.md`, and `adr-user-id.md`.

Three caller-supplied dimensions land at request entry:

#### Custom properties

Tag any request with metadata for slicing. The proxy strips the prefix, lowercases the key, and stores `(key, value)` pairs on the envelope.

```text
X-Sb-Property-Environment: prod
X-Sb-Property-Feature-Flag: agent-v2
X-Sb-Property-Customer-Tier: enterprise
```

Caps per request, all defaults:

| Cap | Value |
|---|---|
| Maximum properties | 20 |
| Maximum key length | 64 chars |
| Maximum value length | 512 chars |
| Maximum total payload | 8 KiB |
| Allowlist regex (key) | `^[a-z0-9][a-z0-9_-]{0,63}$` |

Over-cap entries are dropped silently and counted; the request still serves a 200. Redaction can be configured per origin to replace values for specific keys or values matching regex patterns:

```yaml
properties:
  capture: true
  redact:
    keys: ["customer-email", "ssn"]
    value_regex:
      - '\b[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,}\b'
      - '\b\d{3}-\d{2}-\d{4}\b'
```

Captured properties feed structured logs, the in-memory event bus, and (with the enterprise ingest pipeline wired) ClickHouse. They are NOT exported as Prometheus labels: that would unbound metric cardinality.

#### Sessions

Group requests that belong to one logical interaction. Useful for multi-turn chat threads, agent tool-call loops, and any client-side workflow.

```text
X-Sb-Session-Id: 01HQRP1KJVH3JPCJ8SAVAV6F4Z
X-Sb-Parent-Session-Id: 01HQRP1KJV...     # optional, for sub-sessions
```

Format: ULID (26 chars, Crockford base32). Caller-supplied IDs survive intact; auto-generation kicks in when configured:

| Mode | Behavior |
|---|---|
| `never` | Capture only what the caller supplied |
| `anonymous` (default) | Auto-generate a fresh session for traffic with no resolved user identity |
| `always` | Auto-generate whenever the caller did not supply one |

The proxy echoes the captured or auto-generated ID back as `X-Sb-Session-Id` on the response so stateless SDK callers can adopt it.

#### Users

Tag requests with the end user's identifier. Required for per-user analytics, per-user budgets, and the portal's Users view.

Resolution precedence:

1. `X-Sb-User-Id` request header (caller-supplied).
2. JWT `sub` claim when JWT auth is configured.
3. Forward-auth trust header (default `X-Authenticated-User`).

Today the proxy threads only the header source end-to-end; JWT and forward-auth subject plumbing land in a follow-up. Configure caps per origin:

```yaml
user:
  capture: true
  max_length: 256
```

User IDs are NOT used as Prometheus labels; per-user analytics live in the event store.

#### Example: tagging a request

```bash
curl https://proxy.example.com/v1/chat/completions \
  -H "X-Sb-User-Id: user_42" \
  -H "X-Sb-Session-Id: 01HQRP1KJVH3JPCJ8SAVAV6F4Z" \
  -H "X-Sb-Property-Environment: prod" \
  -H "X-Sb-Property-Feature-Flag: agent-v2" \
  -d '{"model": "gpt-4o", "messages": [...]}'
```

Response includes the session ID echo:

```text
HTTP/1.1 200 OK
X-Sb-Session-Id: 01HQRP1KJVH3JPCJ8SAVAV6F4Z
```

---

## 11. Advanced features

### Forward rules

Route requests to different origins based on request attributes. Forward rules evaluate in order; first match wins.

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

      # Route by header (exact value or value prefix)
      - rules:
          - header:
              name: X-Beta-User
              value: "true"
        hostname: beta.example.com

      # Route by query parameter
      - rules:
          - query:
              name: env
              value: staging
        hostname: staging.example.com

      # AND across matchers in one entry: path AND header must both hold
      - rules:
          - path:
              prefix: /api/
            header:
              name: Authorization
              prefix: "Bearer "
        hostname: authed-api.example.com
```

Matcher reference:

| Matcher | Shape | Notes |
| --- | --- | --- |
| `path.prefix` | string | Request path starts with the prefix. |
| `path.exact` | string | Request path equals the value. |
| `path.template` | string | OpenAPI-style `/users/{id}` template. Captures named segments. |
| `path.regex` | string | Whole-path regex; named captures become path params. |
| `match` | string | Shorthand for `path.prefix`. |
| `header.name` + `header.value` | string + string | Header equals value (header name is case-insensitive). |
| `header.name` + `header.prefix` | string + string | Header value starts with prefix. |
| `query.name` + `query.value` | string + string | Query param equals value. |
| `query.name` (alone) | string | Query param is present (any value). |

Within a single entry the present matchers are ANDed: every matcher must
succeed for the entry to fire. Across entries inside one rule's `rules:`
list they are ORed: the first matching entry wins. Across forward rules the
first matching rule wins.

```bash
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/health      # Static response
curl -H "Host: api.test.sbproxy.dev" http://localhost:8080/api/v2/foo  # Routes to v2
```

### Custom error pages

Return branded error responses instead of the default proxy errors:

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

SBproxy keeps a session layer for cookie-based state:

```yaml
session:
  cookie_name: _sb_session
  max_age: 3600                 # 1 hour, also accepts cookie_max_age alias
  same_site: Lax                # Also accepts cookie_same_site alias
  http_only: true               # Sets HttpOnly cookie attribute
  secure: true                  # Sets Secure cookie attribute (HTTPS only)
  allow_non_ssl: false          # Require HTTPS for session cookies
```

### Request enrichment callbacks

Each origin can call out to an HTTP service before the action runs, then merge the response into the request context:

```yaml
on_request:
  - url: https://user-service.internal/profile
    method: GET
    forward_headers: [Authorization]
    cache_duration: 60s
```

The matching `on_response` hook fires after the action and can shape outgoing data (audit logs, side-channel notifications).

### Compression

SBproxy can compress responses with gzip, Brotli, or Zstandard:

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

### CORS

Add Cross-Origin Resource Sharing headers.

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

### Variables and templates

Define variables to use in header values, bodies, and callbacks:

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

Available template scopes:

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

### Secrets management

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

Secrets are available as `{{ secrets.api_key }}` in templates and substituted at runtime. They never appear in logs or config dumps.

### MCP support

MCP (Model Context Protocol) is supported as a top-level action via `type: mcp`. The action federates one or more upstream MCP servers behind a single virtual MCP endpoint. Each upstream gets a namespace `prefix:`, optional `rbac:` label, and optional per-server `timeout:`; an inline `tool_allowlist` guardrail short-circuits any call to a tool not on the allowlist.

```yaml
origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: my-mcp
        version: "1.0.0"
      federated_servers:
        - origin: github.example.com
          prefix: gh
          rbac: read_only
          timeout: 10s
        - origin: postgres.example.com
          prefix: db
          timeout: 10s
      guardrails:
        - type: tool_allowlist
          allow: [gh.search_repos, db.query]
```

The action speaks JSON-RPC 2.0: `initialize` returns the configured `server_info`, `tools/list` aggregates the federated catalogue, `tools/call` enforces the allowlist guardrail and routes to the upstream that owns the prefix. Tool aggregation, name-collision handling, and the upstream transports (`streamable_http`, `sse`) live in the federation library at `crates/sbproxy-extension/src/mcp/`. See [examples/97-mcp-federation/](../examples/97-mcp-federation/) for a runnable config.

---

## 12. Reference: less common building blocks

Brief schemas for actions, policies, transforms, and origin fields not covered above. See [configuration.md](configuration.md) for the full type list.

### More action types

| Type | Description |
|---|---|
| `graphql` | Proxy GraphQL requests to an upstream HTTP endpoint, with operation parsing |
| `storage` | Serve files from object storage (S3, GCS, Azure, local) |
| `a2a` | Proxy to an Agent-to-Agent endpoint |
| `mcp` | MCP (Model Context Protocol) gateway that federates one or more upstream MCP servers |
| `websocket` | Proxy upstream WebSocket connections |
| `grpc` | Proxy to an upstream gRPC server |

WebSocket and gRPC actions take an upstream URL plus optional protocol-specific tuning:

```yaml
action:
  type: websocket
  url: wss://realtime.example.com

action:
  type: grpc
  url: https://grpc-backend.example.com:443
```

### More policy types

The `assertion` policy (alias `response_assertion`) evaluates a CEL expression against the response and logs failures without blocking traffic:

```yaml
policies:
  - type: assertion
    expression: response.status < 500
    name: no-server-errors
```

### More transform types

| Type | Description |
|---|---|
| `template` | Render a Tera/Handlebars-style template against the body |
| `normalize` | Whitespace collapse, trim, case normalization |
| `encoding` | Base64, hex, URL encode / decode |
| `discard` | Drop the body entirely |
| `css` | Manipulate CSS responses |
| `js_json` | JavaScript transform that operates on a parsed JSON value (parallel to `lua_json`) |

```yaml
transforms:
  - type: js_json
    script: |
      function modify_json(data) {
        data.processed = true;
        return data;
      }
```

### Origin-level extras

| Field | Description |
|---|---|
| `bot_detection` | Bot scoring and challenge configuration (opaque, see configuration.md) |
| `threat_protection` | IP reputation and dynamic blocklist hooks |
| `fallback_origin` | Origin used when the primary upstream fails |
| `traffic_capture` | Mirror or capture request/response traffic |
| `message_signatures` | RFC 9421 HTTP message signatures |
| `connection_pool` | Per-origin pool tuning (size, idle timeout) |

### Proxy-level extras

`l2_cache` (alias `l2_cache_settings`) and `messenger_settings` configure the shared backend for multi-replica deployments. `l2_cache` keeps rate-limit counters and response-cache entries cluster-wide; `messenger_settings` carries config-update and semantic-cache events between replicas:

```yaml
proxy:
  l2_cache:
    driver: redis
    params:
      dsn: redis://cache.internal:6379/0
  messenger_settings:
    driver: redis
    params:
      dsn: redis://cache.internal:6379/0
```

Both are required when running more than one proxy replica behind a load balancer.

---

## 13. Plugin development

SBproxy uses a plugin registry pattern. Plugins register themselves at startup and are looked up by name when the config loads. Each plugin lives in its own crate or module and implements one of the trait types defined in `sbproxy-plugin`.

### Crate layout

The proxy is split into focused crates:

- `sbproxy`: main binary, Pingora server, host routing
- `sbproxy-config`: YAML parsing, type definitions
- `sbproxy-core`: CompiledOrigin, phase dispatch, plugin registry, hot reload
- `sbproxy-modules`: actions, auth, policies, transforms
- `sbproxy-ai`: AI gateway (20+ providers, routing, guardrails, budgets, MCP)
- `sbproxy-middleware`: CORS, HSTS, compression, header modifiers
- `sbproxy-extension`: WASM (wasmtime), Lua (mlua/Luau), CEL (cel-rust), JavaScript (QuickJS)
- `sbproxy-cache`: response cache, pluggable backends
- `sbproxy-security`: WAF, DDoS, CSRF, message signatures
- `sbproxy-tls`: TLS, ACME auto-cert, HTTP/3
- `sbproxy-transport`: retry, coalescing, hedged requests, circuit breaker
- `sbproxy-vault`: secret management
- `sbproxy-observe`: logging, metrics, event bus
- `sbproxy-platform`: KV store, DNS cache, messenger, health
- `sbproxy-httpkit`: HTTP utilities
- `sbproxy-plugin`: plugin trait definitions

### Request pipeline

Plugins extend five points:

1. Action: terminal step that produces the response
2. Auth: authenticates the request (runs before policies)
3. Policy: gates access (runs after auth)
4. Transform: modifies request or response bodies
5. Request enricher: attaches data to the request context (GeoIP, UA parsing)

All plugin traits are exported from `sbproxy-plugin` and built for safe concurrent use across worker tasks.

### Registration

Plugins register themselves via `inventory::submit!` with a `PluginRegistration` entry. The proxy discovers them at link time without any centralized registration call:

```rust
use sbproxy_plugin::{PluginKind, PluginRegistration};

inventory::submit! {
    PluginRegistration {
        kind: PluginKind::Action,
        name: "my_action",
        factory: |config| {
            let handler = MyAction::from_config(config)?;
            Ok(Box::new(handler))
        },
    }
}
```

### Implementing an action

Implement `ActionHandler` and submit a registration entry:

```rust
use std::future::Future;
use std::pin::Pin;
use anyhow::Result;
use sbproxy_plugin::{ActionHandler, ActionOutcome, PluginKind, PluginRegistration};

pub struct MyAction;

impl ActionHandler for MyAction {
    fn handler_type(&self) -> &'static str { "my_action" }

    fn handle(
        &self,
        _req: &mut http::Request<bytes::Bytes>,
        _ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<ActionOutcome>> + Send + '_>> {
        Box::pin(async { Ok(ActionOutcome::Responded) })
    }
}

inventory::submit! {
    PluginRegistration {
        kind: PluginKind::Action,
        name: "my_action",
        factory: |_cfg| Ok(Box::new(MyAction)),
    }
}
```

### Implementing a policy

```rust
use std::future::Future;
use std::pin::Pin;
use anyhow::Result;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

pub struct MyPolicy {
    required_key: String,
}

impl PolicyEnforcer for MyPolicy {
    fn policy_type(&self) -> &'static str { "my_policy" }

    fn enforce(
        &self,
        req: &http::Request<bytes::Bytes>,
        _ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        let allowed = req
            .headers()
            .get("x-custom-key")
            .map(|v| v.as_bytes() == self.required_key.as_bytes())
            .unwrap_or(false);
        Box::pin(async move {
            if allowed {
                Ok(PolicyDecision::Allow)
            } else {
                Ok(PolicyDecision::Deny {
                    status: 403,
                    message: "missing custom key".into(),
                })
            }
        })
    }
}
```

### Implementing a transform

```rust
use std::future::Future;
use std::pin::Pin;
use anyhow::Result;
use sbproxy_plugin::{TransformContext, TransformHandler};

pub struct ReplaceFooBar;

impl TransformHandler for ReplaceFooBar {
    fn transform_type(&self) -> &'static str { "my_transform" }

    fn apply<'a>(
        &'a self,
        _body: &'a mut bytes::BytesMut,
        _content_type: Option<&'a str>,
        _ctx: &'a TransformContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
```

### Plugin traits

| Trait | Crate | `PluginKind` | Description |
|---|---|---|---|
| `ActionHandler` | `sbproxy-plugin` | `Action` | Terminal request handler |
| `AuthProvider` | `sbproxy-plugin` | `Auth` | Authentication wrapper |
| `PolicyEnforcer` | `sbproxy-plugin` | `Policy` | Access control wrapper |
| `TransformHandler` | `sbproxy-plugin` | `Transform` | Body transformer |
| `RequestEnricher` | `sbproxy-plugin` | `Enricher` | Adds context data (GeoIP, UA parsing) |

External plugins ship as separate crates that depend on `sbproxy-plugin` and submit their registrations via `inventory::submit!` at module scope.

### CORS security defaults

The CORS middleware enforces the following safety rules. These changes are tracked under OPENSOURCE.md H5 and are a deliberate breaking change versus the pre-1.0 development behaviour.

- **Empty `allowed_origins` is deny-all.** Earlier revisions echoed any `Origin` header back when `allowed_origins` was empty. Combined with `allow_credentials: true` this allowed credentialed cross-origin access from arbitrary callers. The middleware now emits no CORS headers when the list is empty, regardless of `allow_credentials`.
- **Wildcard plus credentials is refused.** The combination `allowed_origins: ["*"]` with `allow_credentials: true` is rejected at config-load time by `cors::validate_cors_config`, and the runtime path also refuses to emit headers for that combination as a belt-and-suspenders check. Browsers reject this pairing per the Fetch spec; surfacing it as a config error matches that behaviour.
- **Explicit any-origin opt-in.** Operators who genuinely want to permit any origin must set `allowed_origins: ["*"]` and `allow_credentials: false`. Echo-the-request-origin behaviour is no longer reachable through configuration; the only way to allow a specific origin is to list it.

Migration notes for existing configs:

```yaml
# Pre-1.0 dev builds: empty list = allow any origin (UNSAFE)
cors:
  allow_credentials: true        # combined with empty list this was a credential leak

# v1.0.0+: pick one of these explicit forms.

# Form A: lock down to known origins (recommended).
cors:
  allowed_origins:
    - https://app.example.com
  allow_credentials: true

# Form B: allow any origin, no credentials.
cors:
  allowed_origins: ["*"]
  allow_credentials: false
```

### Listener

The plain HTTP listener bound on `proxy.http_bind_port` defaults to HTTP/1.1. Most browsers and curl-style clients work out of the box. Plaintext gRPC clients, h2 prior-knowledge clients, and any tonic Channel that has not negotiated TLS+ALPN need HTTP/2 over the unencrypted port (h2c) instead, and that is opt-in.

#### HTTP/2 cleartext (h2c)

Set `proxy.http2_cleartext: true` to allow the plain HTTP listener to detect the HTTP/2 connection preface and serve those connections as HTTP/2.

```yaml
proxy:
  http_bind_port: 8080
  http2_cleartext: true   # default: false

origins:
  "grpc.example.com":
    action:
      type: grpc
      url: "grpc://upstream.internal:50051"
```

When the flag is `false` (the default), the listener parses every connection as HTTP/1.1 and rejects raw h2 prefaces as malformed requests. When `true`, the listener peeks the first 24 bytes; connections that match the h2 preface are upgraded to HTTP/2, and connections that do not continue to be served as HTTP/1.1, so a single port can carry both protocols.

This flag only affects the plain `http_bind_port` listener. TLS-fronted HTTP/2 on `https_bind_port` already negotiates h2 via ALPN during the TLS handshake and is unaffected. Operators that terminate TLS at a load balancer or sidecar and forward plaintext h2 to sbproxy are the primary audience for this flag.

### HTTP/3 limitations

The HTTP/3 (QUIC) listener uses a separate dispatch path that does not yet route through every action and auth module. Until those are wired through, the H3 listener handles each case as follows.

Auth modules over HTTP/3:

- `forward_auth`: not supported. Requests are denied with `401 Unauthorized` (fail closed) so the configured auth is never silently bypassed. Configure an HTTP/1.1 or HTTP/2 listener for origins that depend on `forward_auth`.
- `bot_auth` and plugin auth: not supported. Requests are denied with `401 Unauthorized`.
- `api_key`, `basic_auth`, `bearer`, `jwt`, `digest`, `noop`: supported.

Action modules over HTTP/3 that return `501 Not Implemented`:

- `load_balancer`
- `ai_proxy`
- `websocket`
- `grpc`
- `graphql`
- `storage`
- `a2a`
- `plugin`

The 501 response body identifies the action type and tells operators to configure an HTTP/1.1 or HTTP/2 listener for the origin. Other actions (`proxy`, `redirect`, `static`, `echo`, `mock`, `beacon`, `noop`) work over HTTP/3 today.

