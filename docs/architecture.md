# SBproxy - Architecture and Deployment Guide

*Last modified: 2026-04-12*

This document covers the internal architecture of sbproxy, the request lifecycle, the plugin
system, the AI gateway, caching, events, and common deployment topologies.

---

## 1. Overview

sbproxy is a single static binary with zero required external runtime dependencies. It is
written in Go and ships as a self-contained executable. There is no JVM, no Python interpreter,
no Node.js runtime, and no shared library requirement beyond libc (or none at all with CGO
disabled).

The design is inspired by the Caddy web server's plugin registry pattern. Every extensible
component type - action handlers, auth providers, policy evaluators, transforms, and middleware -
is registered via a factory function during `init()`. The binary composition root is
`cmd/sbproxy/main.go`, which pulls in components via blank imports. Changing the set of
registered components requires only modifying which packages are imported there. No other
file needs to change.

Key properties:

- **Single binary.** One file to copy, one process to manage.
- **Zero-dependency startup.** Works without Redis, a database, or a sidecar. External
  integrations (Redis cache, webhook events, OTEL tracing) are opt-in and fail gracefully
  when unavailable.
- **Hot reload.** Config changes are applied without restarting. The engine detects file
  changes and recompiles the affected origin handler chains atomically.
- **Embedding-ready.** The `pkg/proxy` package provides a `New/Run/Shutdown` lifecycle API
  suitable for use as a library inside another Go binary.

---

## 2. Package Layout

```
sbproxy/
  cmd/sbproxy/           - Binary entry point (main.go calls pkg/cli.Execute)
  pkg/                   - Public API. No internal imports allowed.
    cli/                 - CLI entry point for external binaries
    config/              - Public config types (Origin struct with json.RawMessage)
    plugin/              - Plugin registry and interfaces:
                             ActionHandler, AuthProvider, PolicyEnforcer,
                             TransformHandler, RequestEnricher,
                             ServiceProvider, MiddlewareRegistration
    plugin/memorycache/  - In-memory LRU ResponseCache implementation
    events/              - EventBus interface (no-op default)
    httpkit/             - HTTP utilities (ClientIP, SplitHostPort)
    modules/             - Module loader (blank imports trigger init)
  internal/
    cli/                 - CLI commands (serve, validate)
    service/             - Server lifecycle, startup orchestration, HTTP/HTTPS/H3 listeners
    config/              - Config loading, validation, origin compilation
      compiler.go        - CompileOrigin(): builds 18-layer handler chain from RawOrigin
      loader.go          - YAML/JSON/TOML config parsing
      error_pages.go     - Error page rendering with Mustache templates
      types.go           - Config struct definitions (SessionConfig, ErrorPages, etc.)
      snapshot.go        - CompiledOrigin (immutable, atomic swap)
      registry.go        - Plugin registry bridge
      plugin_bridge.go   - Adapters between pkg/plugin interfaces and internal types
    engine/              - HTTP request pipeline
      middleware/         - Global middleware chain, origin routing, enricher
      handler/            - Proxy, echo, SSE handlers
      transport/          - Outbound HTTP transport: retry, coalescing, hedging,
                             shadow, timeout, cert pinning, HTTP/2/3
      proxy/              - Proxy utilities: flush control, trust, response copying
      streaming/          - Streaming protocol mediation (Kafka, SSE)
    modules/             - Self-contained modules registered via pkg/plugin
      action/             - proxy, loadbalancer, redirect, static, echo, mock,
                             beacon, graphql, grpc, websocket, mcp, a2a, aiproxy, noop, storage
      auth/               - apikey, basicauth, bearer, digest, forwardauth, grpcauth, jwt, noop
      policy/             - ratelimit, ipfilter, waf, ddos, csrf, expression,
                             secheaders, requestlimit, assertion, sri
      transform/          - json, jsonprojection, jsonschema, html, markdown, template,
                             luajson, css, javascript, encoding, formatconvert, normalize,
                             optimizehtml, payloadlimit, replacestrings, ssechunking,
                             htmltomarkdown, discard, noop
    middleware/           - Per-origin middleware implementations
      callback/           - HTTP callbacks/webhooks (on_load, on_request, on_response)
      compression/        - gzip, brotli, zstd response compression
      cors/               - CORS preflight and headers
      csp/                - Content Security Policy
      forward/            - Forward rules (path-based routing to inline origins)
      hsts/               - HTTP Strict Transport Security
      httpsig/            - RFC 9421 HTTP Message Signatures
      modifier/           - Request/response modification (headers, body, URL, templates)
      rule/               - Request/response matching (path, method, headers, CEL, Lua)
      waf/                - WAF engine, OWASP CRS, rule parser
    ai/                  - AI gateway (providers, routing, guardrails, keys, memory,
                             metrics, observability, prompts, rbac)
    extension/           - Scripting and extension runtimes
      cel/                - CEL expression evaluation, JSON modification
      lua/                - Lua scripting (gopher-lua)
      mcp/                - MCP server implementation
      scripting/          - Shared scripting context
      wasm/               - WASM stub (enterprise provides full runtime)
    observe/             - Observability
      events/             - Internal event bus (InProcessEventBus with worker pool)
      logging/            - Structured logging (slog, ClickHouse), IP masking, sampling
      metric/             - Prometheus metrics
      telemetry/          - OpenTelemetry integration
    loader/              - Config lifecycle
      configloader/       - Origin loading, compilation, hot reload
      featureflags/       - Feature flag evaluation
      manager/            - Manager interface (crypto, cache, messenger, storage)
      settings/           - Global proxy settings
    platform/            - Infrastructure primitives
      circuitbreaker/     - Circuit breaker with atomic CAS
      discovery/          - Service discovery (DNS SRV)
      dns/                - DNS caching resolver
      health/             - Health check management
      messenger/          - Message bus (in-memory, Redis)
      storage/            - Storage abstraction
      servervar/          - Server variable management
    request/             - Per-request context
      reqctx/             - RequestData, OriginContext, ServerContext types
      session/            - Session middleware (cookie-based, encrypted)
      ratelimit/          - Rate limiting state
      classifier/         - ML classifier client (sbproxy-classifier sidecar)
      data/               - Request data capture
    security/            - Security primitives
      certpin/            - Certificate pinning
      core/               - Core security utilities
      crypto/             - HKDF key derivation, encryption
      hostfilter/         - Bloom filter hostname validation
      pii/                - PII detection and redaction
      signature/          - Digital signatures (HMAC, RSA)
      tlsutil/            - TLS configuration utilities
    cache/               - Caching
      store/              - Cache store interface (Cacher)
      response/           - Response cache middleware
      object/             - Object cache
      origin/             - Origin config cache
    vault/               - Secret management (local backend)
    template/            - Mustache template resolution
    httpkit/             - HTTP utilities, buffer pools, zerocopy
  examples/              - 16 annotated sb.yml examples
  docs/                  - Documentation
```

The `pkg/` constraint is enforced by `scripts/import-guard.sh`. Any `pkg/` package that
imports from `internal/` fails CI.

---

## 3. Request Pipeline

Every inbound request passes through the following stages in order. A rejection at any stage
short-circuits the remaining stages and writes the error response immediately.

```
  Client
    |
    v
+-------------------+
| TCP Accept        |  net/http listener. HTTP/1.1 and HTTP/2.
| TLS Termination   |  certmagic-managed certificates. ALPN negotiation.
+-------------------+
    |
    v
+-------------------+
| Global Middleware |  Applied to every request regardless of origin config.
|                   |  - Recoverer:          panic -> 500, log stack trace.
|                   |  - Compressor:         Accept-Encoding -> gzip/brotli.
|                   |  - RealIP:             X-Forwarded-For validated against
|                   |                        TrustedProxyCIDRs. Prevents spoofing.
|                   |  - FastPath:           Populates RequestData struct,
|                   |                        captures original request snapshot.
|                   |  - CorrelationID:      Assigns X-Request-ID if absent.
|                   |  - RequestLogger:      Structured access log entry.
|                   |  - ShutdownMiddleware: Rejects new requests during drain,
|                   |                        tracks in-flight count.
+-------------------+
    |
    v
+-------------------+
| Health Check      |  /_health and /_ready are handled before host resolution.
| Short-Circuit     |  Returns 200 immediately. No config lookup required.
+-------------------+
    |
    v
+-------------------+
| Host Filter       |  Bloom filter pre-check (sub-microsecond rejection for
|                   |  unknown hostnames). Falls through to exact LRU lookup.
|                   |  Returns 404 if hostname is not configured.
+-------------------+
    |
    v
+-------------------+
| Config Middleware |  Applied after the origin config is resolved.
|                   |  - Feature flags:    Evaluate per-origin flag overrides.
|                   |  - Session:          Initialize or restore session cookie.
|                   |  - Bot detection:    Traffic classification.
|                   |  - Enricher:         Calls all registered RequestEnrichers
|                   |                      (GeoIP, UA parser, etc. via plugin system).
+-------------------+
    |
    v
+-------------------+
| Authentication    |  One or more auth providers applied in order.
|                   |  Types: api_key, basic_auth, bearer_token, jwt,
|                   |         forward_auth, digest, grpc_auth.
|                   |  Failure -> 401 or 403. Auth result stored in context.
+-------------------+
    |
    v
+-------------------+
| Policy Evaluation |  Policies applied in declaration order.
|                   |  Types: rate_limiting, ip_filtering, expression (CEL),
|                   |  waf, ddos_protection, csrf, security_headers,
|                   |  request_limiting, response_assertion, sri.
|                   |  rate_limiting -> 429 with Retry-After.
|                   |  expression -> 403 with custom message.
|                   |  request_limiting -> 503 when slot pool exhausted.
+-------------------+
    |
    v
+-------------------+
| Request Modifiers |  Mutate the upstream request before forwarding.
|                   |  - Add, remove, or rewrite headers.
|                   |  - Rewrite URL path or query string.
|                   |  - Inject template variables (session, env, secret scopes).
|                   |  - Run CEL or Lua scripts for dynamic modification.
+-------------------+
    |
    v
+-------------------+
| Forward Rules     |  Evaluate path/header/CEL conditions. If a rule matches,
|                   |  the request is re-routed to an inline origin config.
|                   |  The matched inline config re-enters the pipeline from
|                   |  the Authentication stage onward.
+-------------------+
    |
    v
+-------------------+
| Action Handler    |  Executes the origin's configured action.
|                   |  Types: proxy, static, redirect, echo, loadbalancer,
|                   |          websocket, grpc, graphql, ai_proxy, mcp, a2a,
|                   |          mock, beacon, storage, noop.
|                   |  Handler chain compiled once via sync.Once on first use.
+-------------------+
    |
    v
+-------------------+
| Response Cache    |  Check cache before forwarding (cache hit -> skip action).
| (pre-write)       |  Store response after action completes (on cache miss).
|                   |  Supports TTL and stale-while-revalidate.
+-------------------+
    |
    v
+-------------------+
| Response          |  Mutate the upstream response before returning to client.
| Transforms        |  HTML rewriting, CSS rewriting, JSON projection,
|                   |  header injection.
+-------------------+
    |
    v
+-------------------+
| Response          |  Same modifier API as request modifiers but applied to
| Modifiers         |  the outbound response. CEL/Lua scripts may read request
|                   |  context when computing response mutations.
+-------------------+
    |
    v
  Client
```

---

## 4. Plugin System

All extensible component types use a single pattern: register a factory function during
`init()`, keyed by the type string that appears in YAML configs.

### Registry interfaces (pkg/plugin)

```go
type ActionFactory    func(json.RawMessage) (ActionHandler, error)
type AuthFactory      func(json.RawMessage) (AuthProvider, error)
type PolicyFactory    func(json.RawMessage) (PolicyEnforcer, error)
type TransformFactory func(json.RawMessage) (TransformHandler, error)
```

Additionally, `RequestEnricher` implementations register via `RegisterEnricher` and are
called by the enricher middleware on every request. Unlike the factory-based types above,
enrichers register a concrete instance rather than a factory. This pattern allows enterprise
and third-party packages to inject GeoIP, user-agent parsing, or custom context enrichment
without modifying the core engine.

Other registration types include `RegisterMiddleware` (global middleware),
`RegisterHealthChecker` (custom health check strategies), and `RegisterTransport`
(custom HTTP round-trippers).

### Registration example

```go
// internal/modules/action/proxy/proxy.go
func init() {
    plugin.RegisterAction("proxy", func(raw json.RawMessage) (plugin.ActionHandler, error) {
        var cfg ProxyConfig
        if err := json.Unmarshal(raw, &cfg); err != nil {
            return nil, err
        }
        return NewProxyAction(cfg), nil
    })
}
```

### Composition root

`internal/modules/imports.go` uses blank imports to trigger `init()` registration:

```go
import (
    _ "github.com/soapbucket/sbproxy/internal/modules/action"
    _ "github.com/soapbucket/sbproxy/internal/modules/action/aiproxy"
    _ "github.com/soapbucket/sbproxy/internal/modules/action/loadbalancer"
    _ "github.com/soapbucket/sbproxy/internal/modules/action/mcp"
    _ "github.com/soapbucket/sbproxy/internal/modules/auth"
    _ "github.com/soapbucket/sbproxy/internal/modules/policy"
    _ "github.com/soapbucket/sbproxy/internal/modules/transform"
    // ... and so on
)
```

No other file needs to change when adding a new component type.

### Adding a new module (step by step)

1. Create `internal/modules/{type}/mymodule/` with your handler struct.
2. Implement the appropriate `pkg/plugin` interface (ActionHandler, AuthProvider, PolicyEnforcer, TransformHandler, or RequestEnricher).
3. Add an `init()` block calling the matching Register function.
4. Add a blank import to `internal/modules/imports.go`.
5. The new type is now usable in any `sb.yml` without changes to the engine.

The same steps apply to auth providers (`RegisterAuth`), policies
(`RegisterPolicy`), transforms (`RegisterTransform`), enrichers
(`RegisterEnricher`), and middleware (`RegisterMiddleware`).

### Thread safety

The registry is populated exclusively during `init()` before `main()` runs. All writes
happen before the first read. Lookups during request handling use a `sync.RWMutex`
read-lock. No writes occur after startup, so lock contention is negligible.

---

## 5. Config Architecture

### Pure types layer (pkg/config)

`pkg/config` contains only struct definitions and their JSON tags. It has zero imports from
`internal/`. This makes it safe to import from external programs (for config generation,
validation tools, or SDKs) without pulling in any proxy implementation.

The JSON tags in `pkg/config` (and mirrored in `internal/config`) are the canonical field
names. When in doubt about a YAML field name, read the Go struct tag, not the documentation.

### Config lifecycle

```
sb.yml (YAML file or API-delivered bytes)
    |
    v
configloader.Parse()        Raw YAML -> pkg/config.Config struct.
                            Schema validation. Unknown fields rejected.
    |
    v
configloader.Resolve()      Secret references expanded via vault.
                            Template variables validated.
                            Parent/child origin inheritance applied.
    |
    v
loader.Manager.Store()      Compiled config stored in LRU map keyed by hostname.
                            Bloom filter updated with new hostname set.
    |
    v
First request for hostname
    |
    v
CompileOrigin() [sync.Once]   18-layer handler chain compiled: action, cache,
                              transforms, callbacks, modifiers, auth, compression,
                              CORS, HSTS, policies, bot detection, threat protection,
                              session, message signatures, error pages, and more.
                              Result cached on the origin object. Subsequent
                              requests use the pre-compiled chain with zero
                              per-request allocation.
```

### Parent/child origin inheritance

Origins can declare a `parent` field referencing another origin by name. The child inherits
all fields from the parent and can override any of them. This is resolved at parse time, not
at request time. The resulting child config is fully materialized before compilation.

### Hot reload

The config watcher (`internal/service/hotreload`) uses `fsnotify` to detect file changes.
On change it re-parses and re-resolves the config. New origin entries are added to the
manager. Removed entries are evicted from the LRU. Modified entries atomically replace the
old compiled chain by resetting the `sync.Once` on the origin object, ensuring in-flight
requests complete against the old chain while new requests use the updated one.

---

## 6. AI Gateway Architecture

The `ai_proxy` action delegates entirely to `internal/ai`. It presents an OpenAI-compatible
API surface and can route requests to any supported LLM provider.

```
  Client (OpenAI-compatible request)
    |
    v
+------------------+
| AI Handler       |  Validates request format. Extracts consumer identity.
|                  |  Checks concurrency limits.
+------------------+
    |
    v
+------------------+
| Guardrails       |  Pre-request evaluation. CEL/Lua selectors determine
| (pre-request)    |  which guardrail rules apply. Rules may block, flag,
|                  |  or redact content before the request leaves the proxy.
+------------------+
    |
    v
+------------------+
| Router           |  Selects provider and model based on routing strategy.
|                  |  Strategies: round_robin, fallback_chain, cost, latency.
|                  |  Context window validation: token count checked against
|                  |  provider model limits. Oversized requests routed to a
|                  |  model with a larger context window or rejected.
+------------------+
    |
    v
+------------------+
| Provider         |  Translates normalized request to provider-specific wire
|                  |  format. Injects API key from vault.
+------------------+
    |
    v
  LLM API (OpenAI / Anthropic / Gemini / ...)
    |
    v
+------------------+
| Response Handler |  For streaming: SSE proxy with buffered guardrail
|                  |  evaluation on complete chunks. Spend tracking updated
|                  |  atomically. Conversation memory written to store.
|                  |  For non-streaming: full response passed to post-request
|                  |  guardrails before returning to client.
+------------------+
    |
    v
  Client
```

### Provider registry

Providers are registered the same way as action types. Each provider implements
`internal/ai/providers.Provider`. The providers list is also driven by `providers.yaml`,
which maps provider names to their base URLs and supported models. Go implementations handle
request serialization and response normalization.

### Routing strategies

| Strategy        | Behavior |
|-----------------|----------|
| `round_robin`   | Distributes load evenly across all configured backends. |
| `fallback_chain` | Tries each provider in order. Moves to next on error or timeout. |
| `cost_optimized` | Routes to the provider with the most available token capacity, favoring less-loaded providers. |
| `latency`       | Selects the provider with the lowest observed p50 latency using an EWMA. |

### Streaming

The SSE proxy reads chunks from the upstream provider and forwards them to the client
immediately. For guardrail evaluation, the proxy buffers a rolling window of the last N
tokens. When the stream completes, a final guardrail pass runs against the accumulated
content. If a violation is detected mid-stream, the proxy injects a stop chunk and closes
the stream.

---

## 7. Event System

sbproxy uses two event mechanisms with different scopes and semantics.

### Internal bus (internal/observe/events)

High-throughput, in-process publish/subscribe. Components call `events.Emit(SystemEvent{...})`.
Subscribers register for specific event type strings. Used for:

- Circuit breaker state transitions.
- Config hot-reload completion.
- Buffer overflow warnings.
- Rate limit threshold crossings.
- Workspace quota alerts.

Events carry a `WorkspaceID` field. Per-workspace bounded queues (backed by
`internal/platform/messenger` with a 10k-entry cap) prevent one active workspace from
starving event delivery to others.

### Public bus (pkg/events)

The `EventBus` interface is exposed to external consumers via the embedding API. The default
implementation is a no-op. Three built-in subscriber types are available:

- **log subscriber.** Writes events as structured JSON to the configured logger.
- **webhook subscriber.** POSTs event payloads to a configurable HTTPS endpoint with HMAC
  signing.
- **prometheus subscriber.** Increments labeled counters for each event type.

### Event filtering

Subscribers declare a filter predicate at registration time. The bus evaluates predicates
before delivering the event, so filtered subscribers never receive irrelevant events. The
filter is evaluated inline (no goroutine per delivery for the common case).

---

## 8. Caching Architecture

### Response cache

The response cache sits inside the request pipeline at two points: before the action handler
(cache hit check) and after the action handler (cache write on miss). It is keyed by a
signature derived from the request method, URL, selected request headers, and optionally
request body hash.

Configurable per origin:

- `ttl` - Time-to-live for cached entries.
- `stale_while_revalidate` - Serve stale content while a background refresh runs.
- `vary` - List of request headers to include in the cache key.
- `methods` - Which HTTP methods are eligible for caching (default: GET, HEAD).

### Store backends

| Backend   | Use case |
|-----------|----------|
| `memory`  | Single-instance deployments. LRU eviction. No persistence. |
| `file`    | Survives restarts. Suitable for low-traffic origins with slow upstreams. |
| `pebble`  | Embedded Pebble KV store. Pure Go. Sub-millisecond reads. Good default for persistent cache without external dependencies. |
| `redis`   | Shared cache across multiple proxy instances. Requires Redis 6+. JSON serialization with TTL via `SETEX`. Circuit breaker on Redis failures. |

### Object cache

Separate from the response cache. Stores arbitrary objects (compiled CEL programs, parsed
Lua scripts, provider capability metadata). Backed by the same store interface. TTL and
LRU eviction policy configurable separately.

### Cache key partitioning

Keys are namespaced as `workspaceID:configID:hostname:signature`. This prevents cross-tenant
cache collisions even when multiple origins share a backend store. A test-mode fallback
omits the workspace and config prefix for isolation in unit tests.

---

## 9. Observability

sbproxy includes a built-in observability stack with three components: Prometheus metrics,
OpenTelemetry tracing, and structured logging.

### Prometheus metrics

When `telemetry.bind_port` is configured, sbproxy runs a dedicated HTTP server that exposes
a `/metrics` endpoint in Prometheus exposition format. Core HTTP metrics use the `http_*`
namespace. AI gateway metrics use the `sbproxy_ai_*` namespace and include per-provider,
per-model counters for requests, tokens, latency, cache hits, guardrail triggers, and
fallback events. Load balancer metrics use the `sb_lb_*` namespace with per-target breakdown.

### Grafana dashboards

The project ships four pre-built Grafana dashboards in `dashboards/grafana/`:

- `sbproxy-overview.json` - Request rates, latency percentiles, error rates, active connections.
- `sbproxy-ai-gateway.json` - AI provider health, token throughput, TTFT, cache efficiency, guardrail activity.
- `sbproxy-security.json` - WAF blocks, rate limit triggers, auth failures, bot detection.
- `sbproxy-origins.json` - Per-origin request breakdown with cache and latency panels.

### Prometheus alerts

Pre-built alert rules in `dashboards/prometheus/alerts.yml` cover high error rates, latency
spikes, AI provider outages, guardrail anomalies, and token budget thresholds.

### OpenTelemetry tracing

The `otel` config block enables distributed tracing via OTLP (gRPC or HTTP). Traces include
spans for the full request pipeline: host resolution, auth, policy evaluation, action handler,
upstream round-trip, and response transforms. AI requests include additional spans for
provider selection, guardrail evaluation, and streaming.

---

## 10. Deployment Topologies

### Single instance (simplest)

```
  Internet
     |
     v
 [ sbproxy ]  <-- single binary, one process
     |
     v
 [ Upstream services / APIs ]
```

One process, one config file. TLS handled by sbproxy via certmagic (ACME). Suitable for
internal tools, development environments, and low-traffic production services.

### Behind a load balancer (horizontal scaling)

```
  Internet
     |
     v
[ Load Balancer ]  (e.g., AWS ALB, Nginx, HAProxy)
     |       |
     v       v
[ sbproxy ] [ sbproxy ]  (2+ instances, same sb.yml)
     |           |
     v           v
[ Upstream services / APIs ]
```

For shared cache and session state, configure the `redis` store backend. All instances
connect to the same Redis. TLS is terminated at the load balancer. Set `behind_proxy: true`
in sbproxy config to trust the load balancer's `X-Forwarded-For` header.

### Kubernetes with Ingress

```
  Internet
     |
     v
[ Ingress Controller ]  (nginx, traefik, etc.)
     |
     v
[ sbproxy Service ]  (ClusterIP or NodePort)
  /     |     \
 v      v      v
[pod] [pod] [pod]  (3+ replicas, Deployment)
  |
  v
[ Upstream Services ]  (other Deployments or external APIs)
```

Sample topology:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sbproxy
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: sbproxy
        image: sbproxy:latest
        args: ["-c", "/config/sb.yml"]
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /_ready
            port: 8080
        livenessProbe:
          httpGet:
            path: /_health
            port: 8080
        volumeMounts:
        - name: config
          mountPath: /config
      volumes:
      - name: config
        configMap:
          name: sbproxy-config
```

Config is supplied via a ConfigMap. Hot reload detects the kubelet's atomic symlink swap
when the ConfigMap updates.

### Docker Compose (dev and test)

```
  Browser / curl
     |
     v
[ sbproxy ]  (port 8080)
     |
     +---> [ mock-api ]    (local upstream for testing)
     |
     +---> [ redis ]       (shared cache for multi-instance testing)
```

Sample `docker-compose.yml` fragment:

```yaml
services:
  sbproxy:
    image: sbproxy:latest
    ports:
      - "8080:8080"
    volumes:
      - ./sb.yml:/config/sb.yml:ro
    command: ["-c", "/config/sb.yml"]
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

---

## 11. Performance Characteristics

### Handler chain compilation

The most significant optimization in the request path is that auth chains, policy chains,
modifier chains, and the action handler are compiled exactly once per origin (via
`sync.Once`) and stored as a slice of function closures. A request through a compiled chain
is a simple slice iteration with no map lookups, no type assertions, and no config re-reads.

### Per-request allocation budget

The goal is zero heap allocations on the hot path for a proxy-type request:

- `RequestData` is populated from a `sync.Pool` of pre-allocated structs.
- Buffer pools (`internal/httpkit`) recycle read and write buffers.
- The compiled handler chain itself allocates nothing at call time.
- Context values are stored in the `RequestData` struct (passed by pointer), not in
  `context.WithValue` chains, which avoids interface boxing.

### Connection pooling and HTTP/2

The transport layer (`internal/engine/transport`) maintains a `http.Transport` per upstream
origin with tuned idle connection limits. HTTP/2 coalescing is enabled for upstreams that
negotiate it via ALPN. Connection reuse eliminates TCP and TLS setup cost for repeated
requests to the same upstream.

### DNS cache

`internal/platform/dns` wraps the system resolver with an LRU cache. Cache entries are
keyed by hostname and carry a configurable TTL (default: 30 seconds). Lookups are O(1).
Eviction uses a doubly-linked list to maintain LRU order without O(n) scans. This is
particularly impactful for AI proxy routes, which resolve provider hostnames on every
request.

### Bloom filter for hostname pre-check

The loader manager maintains an in-memory bloom filter over all configured hostnames. On
each request, the filter is checked before any LRU map lookup. Requests for unconfigured
hostnames (scanners, bots, misconfigurations) are rejected in sub-microsecond time without
touching the LRU map or acquiring its lock.

### Sharded mutexes for AI session tracking

The AI identity subsystem tracks per-consumer session state. Rather than a single global
mutex, state is sharded across 16 buckets based on a hash of the consumer ID. This reduces
lock contention by up to 16x under concurrent load from many distinct consumers.

### Circuit breaker design

Each upstream has a circuit breaker backed by atomic compare-and-swap operations
(`internal/platform/circuitbreaker`). The open/half-open/closed state transition uses a
single atomic int64. Only one probe request is allowed through per recovery cycle. All other
requests during the open state fail fast without acquiring any lock or making any network
call.

### Observed overhead

Under typical workloads (no Lua, no CEL, no response transforms), the proxy adds less than
1 millisecond of overhead to the end-to-end request latency. The dominant cost is the
upstream network round-trip.
