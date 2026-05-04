# SBproxy architecture and deployment guide

*Last modified: 2026-05-03*

This document covers the internal architecture of SBproxy, the request lifecycle, the plugin
system, the AI gateway, caching, events, and common deployment topologies.

---

## 1. Overview

SBproxy is a single static binary with no required external runtime dependencies. It is
written in Rust and ships as a self-contained executable. There is no JVM, no Python
interpreter, no Node.js runtime, and no shared library requirement beyond libc (or none at
all when built with `musl` or `--target *-unknown-linux-musl`).

The proxy is built on Cloudflare's [Pingora](https://github.com/cloudflare/pingora)
framework. Pingora supplies the tokio runtime, listener management, HTTP/1.1, HTTP/2, HTTP/3
(QUIC via `quinn`), TLS termination, and a phase-based callback model for the request
pipeline. SBproxy layers its host router, compiled origin pipeline, plugin registry, and
hot-reload machinery on top of those primitives.

The plugin system is modeled on Caddy's module pattern. Every extensible component type
(action handlers, auth providers, policy evaluators, transforms, middleware) registers
itself at compile time through the `inventory` crate. The proxy crate is the binary
composition root; pulling a feature in or out is a matter of which workspace crates are
linked into the final executable.

Key properties:

- Single binary. One file to copy, one process to manage. mimalloc is the global
  allocator, typically 5 to 10 percent faster than glibc's allocator under contention.
- Zero-dependency startup. Runs without Redis, a database, or a sidecar. External
  integrations (Redis cache, webhook events, OTEL tracing) are opt-in and fail gracefully
  when unavailable.
- Hot reload. Config changes are applied without restarting. The watcher detects file
  changes and atomically swaps the compiled origin map via `arc-swap`. In-flight requests
  finish on their snapshot; new requests pick up the new map immediately.
- Embeddable. The `sbproxy-core` crate exposes a small `run` / `shutdown` API for use as a
  library inside another Rust binary.

---

## 2. Workspace layout

```
sbproxy/
  crates/
    sbproxy/              - Binary entry point. Wires modules and starts the server.
    sbproxy-core/         - Pingora server, host router, phase dispatch,
                              hot reload, hook registry.
    sbproxy-config/       - YAML/JSON schema, type definitions, parsing,
                              compilation (RawOrigin -> CompiledOrigin).
    sbproxy-plugin/       - Plugin trait definitions and `inventory` registry
                              (PUBLIC API for third-party modules).
    sbproxy-modules/      - Built-in modules:
                              action/   - proxy, loadbalancer, redirect, static,
                                          echo, mock, beacon, websocket, grpc,
                                          ai_proxy, mcp, noop, storage
                              auth/     - api_key, basic_auth, bearer, jwt,
                                          digest, forward_auth, jwks
                              policy/   - rate_limit, ip_filter, waf, ddos,
                                          csrf, security_headers, request_limit,
                                          assertion, sri, cel
                              transform/- json, json_projection, html, markdown,
                                          template, lua, javascript, css,
                                          encoding, format_convert, normalize,
                                          payload_limit, replace_strings,
                                          html_to_markdown, sse_chunking, noop
    sbproxy-ai/           - AI gateway: 20+ native providers, routing,
                              guardrails, budget enforcement, key vault,
                              memory store, MCP federation.
    sbproxy-extension/    - Scripting and extension runtimes:
                              cel/       - cel-rust expression evaluation
                              lua/       - mlua + Luau scripting
                              wasm/      - wasmtime sandboxed plugins
                              js/        - QuickJS via rquickjs
                              mcp/       - Model Context Protocol server
    sbproxy-middleware/   - CORS, HSTS, compression (gzip/brotli/zstd),
                              header modifiers, error pages, forward rules.
    sbproxy-cache/        - Response cache trait, memory backend,
                              pluggable store interface, cache key partitioning.
    sbproxy-security/     - WAF engine (OWASP CRS), DDoS protection, CSRF,
                              RFC 9421 message signatures, PII masking,
                              host filter (bloom + HashMap lookup).
    sbproxy-tls/          - TLS termination via rustls 0.23 with the `ring`
                              crypto provider, ACME auto-cert (Let's Encrypt),
                              HTTP/3 listener wiring, OCSP stapling.
    sbproxy-transport/    - Outbound transport: retry with exponential backoff,
                              request coalescing, hedged requests,
                              circuit breaker, upstream rate limiting.
    sbproxy-vault/        - Secret management. Encrypted local vault,
                              rotation hooks, secret reference resolution.
    sbproxy-observe/      - tracing-based structured logging,
                              Prometheus metrics, typed event bus.
    sbproxy-platform/     - Infrastructure primitives: KV store abstraction,
                              DNS cache, messenger, health tracking,
                              circuit breaker.
    sbproxy-httpkit/      - HTTP utilities: client IP extraction,
                              host:port splitting, buffer pools, body limit
                              readers.
  examples/               - Working sb.yml examples per feature
  docs/                   - Documentation
  e2e/                    - End-to-end test harness
  schemas/                - JSON schema for sb.yml
```

The dependency graph is enforced by the workspace structure. `sbproxy-plugin` is the public
API surface and depends only on `sbproxy-config`. Built-in modules depend on
`sbproxy-plugin`, never on `sbproxy-core`. Third-party plugins built against the published
`sbproxy-plugin` crate are link-compatible with the binary.

---

## 3. Request pipeline

Every inbound request passes through the following stages in order. A rejection at any stage
short-circuits the rest and writes the error response immediately. The pipeline is
implemented as a sequence of `ProxyHttp` callbacks; the per-request work happens inside
those callbacks rather than in a separate dispatcher.

```
request_filter:
  1.  Trace context extract (W3C / B3)
  2.  ACME HTTP-01 challenge interception
  3.  /health and /metrics short-circuit
  4.  Hostname extraction and origin resolution (bloom + HashMap)
  5.  Force-SSL redirect
  6.  Allowed methods check
  7.  CORS preflight handling
  8.  Bot detection
  9.  Threat protection (JSON body checks)
  10. Authentication
  11. Policy enforcement (rate limit, IP filter, WAF, CSRF, DDoS, CEL, ...)
  12. Response cache lookup
  13. on_request callbacks
  14. Forward rule matching
  15. Non-proxy action dispatch (static, redirect, echo, mock, beacon, AI, ...)

upstream_peer:
  Resolve upstream peer for proxy actions.

upstream_request_filter:
  URL rewrite, query injection, method override, body replacement, request
  header modifiers, distributed tracing headers.

response_filter:
  CORS, HSTS, security headers, response modifiers, forward rule echo,
  rate limit headers, Alt-Svc, CSRF cookie, session cookie, on_response
  callbacks, traceparent echo.

response_body_filter:
  Response cache write on miss, transform pipeline, fallback body swap.

logging:
  Metrics emission, access log, event publication.
```

Action types dispatched inside `request_filter` step 15 (or via `upstream_peer` for
`proxy` actions): `proxy`, `load_balancer`, `ai_proxy`, `static`, `mock`, `redirect`,
`echo`, `beacon`, `noop`, `websocket`, `grpc`. Built-in actions are enum variants; the
compiler turns the dispatch site into a branch-predicted match. Third-party plugins use
`Plugin(Box<dyn ActionHandler>)` and pay one indirect call per request.

---

## 4. Plugin system

All extensible component types use a single pattern: register at compile time via the
`inventory` crate, keyed by the type string that appears in YAML configs.

### Registry traits (sbproxy-plugin)

```rust
pub trait ActionHandler: Send + Sync + 'static {
    fn handler_type(&self) -> &'static str;
    fn handle(
        &self,
        req: &mut http::Request<bytes::Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<ActionOutcome>> + Send + '_>>;
}
// Same shape for AuthProvider, PolicyEnforcer, TransformHandler, RequestEnricher.
```

Factory closures construct concrete handlers from a `serde_json::Value` config blob and
return `Box<dyn Any + Send>`. The factory itself is the registration unit.

### Registration pattern

```rust
inventory::submit! {
    PluginRegistration {
        kind: PluginKind::Policy,
        name: "rate_limit_custom",
        factory: |raw| {
            let cfg: MyConfig = serde_json::from_value(raw)?;
            Ok(Box::new(MyPolicy::new(cfg)))
        },
    }
}
```

`inventory::submit!` writes a static descriptor into a link-section that the binary
enumerates at startup. There is no central wiring file. Adding a policy is:

1. Implement `PolicyEnforcer` for the new struct.
2. Drop the file in `sbproxy-modules/src/policy/`.
3. Add an `inventory::submit!` block.
4. Add `pub mod my_policy;` to the parent `mod.rs`.

The compile_config step in `sbproxy-config` looks up factories by name from the inventory
registry. Built-in modules are exposed as enum variants (`Policy::RateLimit(...)`,
`Policy::Plugin(Box<dyn PolicyEnforcer>)`); the compiler prefers the enum variant when
available for cache locality and branch prediction, falling back to dynamic dispatch for
third-party names.

### Built-in vs plugin dispatch

Built-in modules are enum variants. Match dispatch over enums is a single
branch-predicted jump that the compiler typically inlines. Third-party plugins go through
`Box<dyn Trait>` for dynamic dispatch. That costs one indirect call per phase but keeps
the plugin ABI stable across compiler versions.

```rust
enum Action {
    Proxy(ProxyAction),
    Static(StaticAction),
    Redirect(RedirectAction),
    LoadBalancer(LoadBalancerAction),
    AiProxy(AiProxyAction),
    // ... built-ins
    Plugin(Box<dyn ActionHandler>), // third-party
}
```

### Thread safety

`inventory` is populated at link time before `main` runs. All registry reads happen after
that, against an immutable slice. There is no lock on the hot path: the compiled origin
holds direct `Arc` pointers to the handler instances, so per-request dispatch is a pointer
dereference followed by a virtual or static call.

---

## 5. Config architecture

### Pure types layer (sbproxy-config)

The `sbproxy-config` crate contains type definitions, serde derives, and the
compilation step. Its workspace dependencies are limited to `sbproxy-plugin`,
`sbproxy-httpkit`, and `sbproxy-platform` (for the `KVStore` trait used by `l2_store`).
It does not pull in Pingora, the module set, or any networking runtime.

The serde tags in `sbproxy-config` are the canonical field names. When in doubt about a
YAML field name, read the struct definition, not prose documentation.

### Config lifecycle

```
sb.yml (YAML file or API-delivered bytes)
    |
    v
serde_yaml::from_str -> ConfigFile { proxy, origins, secrets, ... }
                            |
                            v
           validate_schema()  - Reject unknown fields, type-check.
                            |
                            v
           resolve_secrets()  - Expand ${secret.X} references via the vault.
                            |
                            v
           apply_inheritance() - Parent / child origin merge.
                            |
                            v
           compile_config()  - For each origin:
                              build CompiledOrigin {
                                action,
                                auths: SmallVec<[Auth; 2]>,
                                policies: SmallVec<[Policy; 4]>,
                                request_modifiers, response_modifiers,
                                transforms, hooks, cache, error_pages, ...
                              }
                            |
                            v
           build host_map: bloom filter + HashMap of hostname -> origin index
                            |
                            v
           Arc<CompiledConfig>  - Immutable snapshot.
                            |
                            v
           ArcSwap::store()    - Atomic publish. Old readers continue
                                 against the previous snapshot.
```

### Parent/child origin inheritance

Origins can declare a `parent` field that references another origin by name. The child
inherits all fields from the parent and can override any of them. This is resolved at
parse time, not at request time. The resulting child config is fully materialized before
compilation.

### Hot reload

The config watcher (`sbproxy-core::reload`) uses the `notify` crate to detect file changes.
On change it re-parses, re-resolves, and recompiles the config. The new
`Arc<CompiledConfig>` is published via `ArcSwap::store`. Requests that already loaded a
snapshot continue with it; new requests pick up the new pointer on their next snapshot
load. Old snapshots are dropped when their refcount hits zero, after all in-flight
requests using them complete. There is no global lock and no quiescence period.

---

## 6. AI gateway architecture

The `ai_proxy` action delegates entirely to the `sbproxy-ai` crate. It presents an
OpenAI-compatible API surface and routes requests to any supported LLM provider.

```
  Client (OpenAI-compatible request)
    |
    v
+------------------+
| AI Handler       |  Validates request format. Extracts consumer identity.
|                  |  Checks per-key concurrency limits.
+------------------+
    |
    v
+------------------+
| Guardrails       |  Pre-request evaluation. CEL/Lua selectors determine
| (pre-request)    |  which guardrail rules apply. Rules may block, flag,
|                  |  or redact content before the request leaves the proxy.
|                  |  Built-in types: PII, prompt injection, toxicity,
|                  |  jailbreak, content safety, JSON schema, regex.
+------------------+
    |
    v
+------------------+
| Router           |  Selects provider and model based on routing strategy.
|                  |  Strategies: round_robin, weighted, fallback_chain,
|                  |  random, lowest_latency, least_connections,
|                  |  cost_optimized, token_rate, sticky.
|                  |  Context window validation: token count checked against
|                  |  provider model limits. Oversized requests routed to a
|                  |  model with a larger context window or rejected.
+------------------+
    |
    v
+------------------+
| Budget Enforcer  |  Hierarchical scopes (workspace, key, route).
|                  |  Action on exceed: log, downgrade to cheaper model,
|                  |  or hard-block with 402.
+------------------+
    |
    v
+------------------+
| Provider         |  Translates normalized request to provider-specific
|                  |  wire format. Injects API key from vault.
+------------------+
    |
    v
  LLM API (OpenAI / Anthropic / Gemini / Bedrock / ...)
    |
    v
+------------------+
| Response Handler |  For streaming: SSE proxy with buffered guardrail
|                  |  evaluation on accumulated chunks. Token usage and
|                  |  cost updated atomically. Conversation memory written.
|                  |  For non-streaming: full response passed to post-request
|                  |  guardrails before returning to client.
+------------------+
    |
    v
  Client
```

### Provider registry

Providers register through the same `inventory` mechanism as actions. Each provider
implements `sbproxy_ai::providers::Provider`. The provider list is also driven by
`providers.yaml`, which maps provider names to their base URLs and supported models. Rust
implementations handle request serialization and response normalization.

36 OpenAI-compatible providers ship in-tree alongside a native Anthropic
translator and the OpenRouter aggregator (which routes 200+ more models).
Direct adapters include OpenAI, Anthropic, Google Gemini, Azure
OpenAI, AWS Bedrock, Cohere, Mistral, DeepSeek, xAI / Grok, Perplexity,
Groq, Together AI, Fireworks AI, OpenRouter, Ollama, vLLM, AWS SageMaker,
Databricks, Oracle Cloud GenAI, IBM Watsonx, plus three local-runtime
adapters (Hugging Face TGI, LM Studio, llama.cpp).

### Routing strategies

| Strategy            | Behavior |
|---------------------|----------|
| `round_robin`       | Rotate through providers in order. |
| `weighted`          | Distribute proportional to provider weight. |
| `fallback_chain`    | Try providers in priority order, falling back on failure. |
| `random`            | Uniform random pick. |
| `lowest_latency`    | Provider with the lowest observed latency (microseconds, atomic counter). |
| `least_connections` | Provider with the fewest in-flight requests. |
| `cost_optimized`    | Lowest score of `connections * 1000 + weight`. Utilization dominates; weight breaks ties in favor of cheaper providers. |
| `token_rate`        | Provider with the most remaining tokens-per-minute headroom. |
| `sticky`            | Pin a session key to one provider. Falls back to round robin without a session key. |

### Streaming

The SSE proxy reads chunks from the upstream provider and forwards them to the client
immediately. For guardrail evaluation, the proxy keeps a rolling window of the last N
tokens. When the stream completes, a final guardrail pass runs against the accumulated
content. If a violation shows up mid-stream, the proxy injects a stop chunk and closes
the stream.

### Streaming cache recorder hook

`StreamCacheRecorderHook` (in `sbproxy-core/src/hooks.rs`) is the OSS-side seam that lets
an enterprise build record streaming AI responses for later replay. It mirrors the shape
of `SemanticLookupHook` and `StreamSafetyHook`: a trait, a per-session context type
(`StreamCacheCtx`), and a unit slot on the `Hooks` bundle that defaults to `None`.

The hook lives in OSS because the emit point is on the SSE forwarding hot path. Threading
chunks across a crate boundary at runtime would be expensive; landing the trait in
`sbproxy-core` keeps the per-chunk fan-out cheap and lets the enterprise impl plug in
through `EnterpriseStartupHook::on_startup` exactly like every other slot.

When the slot is wired, `relay_ai_stream` calls `start_session` once at stream start,
forwards a copy of every chunk into the returned channel, and emits exactly one terminal
`StreamCacheEvent::End { complete }`. The `complete` flag is true on a clean
end-of-stream and false on every other terminal condition (client cancel, upstream
error, mid-stream abort). A `StreamCacheGuard` RAII wrapper owns this terminal-event
invariant: `guard.finish()` sends `complete: true`, and the guard's `Drop` impl sends
`complete: false` if `finish` was never called.

What stays out of OSS: caching policy decisions (deterministic tool calls only, image
data by reference only), replay pacing (`as_fast_as_possible` vs `natural`), eviction,
and persistence. The OSS proxy passes the AI handler's `semantic_cache.streaming` config
block through verbatim as a `serde_json::Value` so the enterprise recorder reads
whatever shape it expects without OSS validating those fields. The enterprise crate
fills the slot from its `EnterpriseStartupHook::on_startup` implementation.

### MCP federation

`sbproxy-extension::mcp` implements a Model Context Protocol server. Tools from upstream
MCP endpoints can be federated and exposed as a single combined tool surface to clients.
Tool calls are routed to the registered upstream by name, with optional auth injection.

---

## 7. Event system

SBproxy uses two event mechanisms with different scopes and semantics.

### Internal bus (sbproxy-observe::events)

High-throughput, in-process publish/subscribe. Components call
`events::emit(SystemEvent { ... })`. Subscribers register for specific event type strings.
Used for:

- Circuit breaker state transitions.
- Config hot-reload completion.
- Buffer overflow warnings.
- Rate limit threshold crossings.
- Workspace quota alerts.

Events carry a `workspace_id` field. Per-workspace bounded queues (backed by
`sbproxy-platform::messenger` with a 10k-entry cap) prevent one active workspace from
starving event delivery to others. The bus is implemented over tokio broadcast channels
plus per-subscriber filter predicates.

### Public bus

The `EventBus` trait is exposed to external consumers via the embedding API. The default
implementation is a no-op. Three built-in subscriber types ship with the binary:

- log subscriber: writes events as structured JSON via `tracing`.
- webhook subscriber: POSTs event payloads to a configurable HTTPS endpoint with HMAC
  signing.
- prometheus subscriber: increments labeled counters for each event type.

### Event filtering

Subscribers declare a filter predicate at registration time. The bus evaluates predicates
before delivering the event, so filtered subscribers never receive irrelevant events. The
filter is evaluated inline (no spawn per delivery in the common case).

---

## 8. Caching architecture

### Response cache

The response cache sits inside the request pipeline at two points: before the action handler
(cache hit check) and after the action handler (cache write on miss). It is keyed by a
signature derived from the request method, URL, selected request headers, and optionally
the request body hash.

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
| `memcached` | Distributed cache via memcached protocol. |
| `redis`   | Shared cache across multiple proxy instances. Requires Redis 6+. JSON serialization with TTL. Circuit breaker on Redis failures. |

The `Cacher` trait is the pluggable surface; new backends are added without touching the
pipeline.

### Object cache

Separate from the response cache. Stores arbitrary objects (compiled CEL programs, parsed
Lua scripts, provider capability metadata). Backed by the same store interface. TTL and
LRU eviction policy are configured independently.

### Cache key partitioning

Keys are namespaced as `workspace_id:config_id:hostname:signature`. This prevents
cross-tenant collisions when multiple origins share a backend store. A test-mode fallback
omits the workspace and config prefix for isolation in unit tests.

---

## 9. Observability

The observability stack has three components: Prometheus metrics, OpenTelemetry tracing,
and structured logging via `tracing`.

### Prometheus metrics

When `telemetry.bind_port` is configured, SBproxy runs a dedicated HTTP server that exposes
a `/metrics` endpoint in Prometheus exposition format. Metric names share a single
`sbproxy_*` namespace. Core HTTP counters include `sbproxy_requests_total`,
`sbproxy_request_duration_seconds`, `sbproxy_errors_total`, and
`sbproxy_active_connections`. AI gateway metrics carry `sbproxy_ai_*`. Per-origin
breakdowns use `sbproxy_origin_*` variants. Auth, policy, cache, and circuit breaker
counters follow the same convention.

### Grafana dashboards

Two Grafana dashboards ship in `crates/sbproxy-observe/dashboards/`:

- `proxy-overview.json` - Request rates, latency, active connections,
  cache hit ratio, error breakdown.
- `mesh-overview.json` - Per-origin and per-edge topology view.

Pre-built Prometheus alert rules are not bundled today; build your own
against the `sbproxy_*` metric names.

### Structured logging

Logging uses the `tracing` crate. `release_max_level_info` is set at the workspace level,
which compile-strips `debug!` and `trace!` calls from release builds entirely. On hot paths
the macro arguments are eliminated rather than evaluated and filtered at runtime.

### Distributed tracing

Distributed tracing extracts W3C Trace Context (`traceparent` / `tracestate`)
and B3 single / multi-header formats, generates a child span ID for each
upstream call, and echoes the propagation headers back to the downstream
client. Full OTLP export to an external collector is wireframed in
`sbproxy-observe::export::otlp_grpc` but not yet shipped; the runtime
emits structured logs and Prometheus counters today.

---

## 10. Deployment topologies

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

One process, one config file. TLS handled by SBproxy via ACME (Let's Encrypt). Fine for
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
connect to the same Redis. TLS is terminated at the load balancer.

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

```yaml
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
        args: ["--config", "/config/sb.yml"]
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        volumeMounts:
        - name: config
          mountPath: /config
      volumes:
      - name: config
        configMap:
          name: sbproxy-config
```

Config is supplied via a ConfigMap. The hot-reload watcher detects the kubelet's atomic
symlink swap when the ConfigMap updates.

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
    command: ["--config", "/config/sb.yml"]
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

---

## 11. Performance characteristics

### Compiled pipeline, not interpreted

The biggest win in the request path is that auth chains, policy chains, modifier chains,
and the action handler are compiled exactly once per origin and stored as inline
collections of trait objects (or enum variants for built-ins). A request through a
compiled pipeline is a slice iteration with no map lookups, no JSON re-parsing, and no
config re-reads.

### Per-request allocation budget

The goal is near-zero heap allocations on the hot path for a proxy-type request:

- Per-request state lives in a `bumpalo` arena that resets after the response is written.
  Many small allocations become a single bump-pointer increment.
- `bytes::Bytes` and `BytesMut` carry request and response bodies, avoiding copies as
  data moves through pipeline phases.
- `compact_str::CompactString` keeps short strings (hostnames, IDs, header names) inline
  on the stack without heap allocation.
- `smallvec::SmallVec<[T; N]>` keeps policies, transforms, and modifiers inline; most
  origins have 1 to 3 of each.
- The compiled pipeline itself allocates nothing at call time.

### Connection pooling and HTTP/2

Pingora maintains a connection pool per upstream peer with tuned idle connection limits.
HTTP/2 multiplexing is enabled for upstreams that negotiate it via ALPN. Connection reuse
eliminates TCP and TLS setup cost for repeated requests to the same upstream. Pingora is
production-tested at Cloudflare scale; SBproxy inherits its IO model directly.

### DNS cache

`sbproxy-platform::dns` wraps the system resolver with an LRU cache. Cache entries are
keyed by hostname and carry a configurable TTL (default: 30 seconds). Lookups are O(1).
Eviction uses a doubly-linked list to maintain LRU order without O(n) scans. This matters
most for AI proxy routes, which resolve provider hostnames on every request.

### Bloom filter for hostname pre-check

The host router maintains an in-memory bloom filter over all configured hostnames. On
each request, the filter is checked before any HashMap lookup. Requests for unconfigured
hostnames (scanners, bots, misconfigurations) are rejected in sub-microsecond time without
touching the HashMap.

### Sharded counters for hot state

Subsystems that track per-consumer or per-origin state (rate limiters, AI session counters)
shard their state across N buckets based on a hash of the key. Each shard uses
`parking_lot::Mutex` or atomic counters. That cuts lock contention by a factor of N
under concurrent load from many distinct keys. The rate limiter also has atomic-only fast
paths when the bucket has clear capacity.

### Lock-free config reads

`arc-swap` provides atomic pointer swap with no locking on the read side. Every request
loads the current `Arc<CompiledConfig>` once, which is a single atomic read plus a refcount
increment. Hot reload publishes a new pointer; in-flight requests continue against their
existing snapshot until they complete and drop their `Arc`.

### Circuit breaker design

Each upstream has a circuit breaker backed by atomic compare-and-swap operations. The
open / half-open / closed state transition uses a single atomic int. Only one probe request
is allowed through per recovery cycle. All other requests during the open state fail fast
without acquiring any lock or making any network call.

### Compiler optimizations

Release builds use `lto = "fat"`, `codegen-units = 1`, and `panic = "abort"`. mimalloc
replaces the system allocator. `tracing`'s `release_max_level_info` feature compile-strips
all debug and trace logging from the binary.

### Observed overhead

Under typical workloads (no Lua, no CEL, no response transforms), the proxy adds well
under 1 millisecond of overhead at p99 to end-to-end request latency. The dominant cost
is the upstream network round-trip. Microbenchmarks for static and echo actions clear
100k requests per second on a single core; full-pipeline scenarios with auth, rate
limiting, CORS, and HSTS sustain 80k or more.

For benchmark methodology, scenario definitions, and how to reproduce these numbers, see
[performance.md](performance.md). For feature-by-feature comparisons against other proxies
and AI gateways, see [comparison.md](comparison.md). For the YAML schema reference, see
[configuration.md](configuration.md).
