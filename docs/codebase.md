# SBproxy codebase guide
*Last modified: 2026-05-03*

For developers who want to know what each part of the codebase does, without needing to know Rust syntax.

---

## Rust concepts you will see

Rust-specific patterns used throughout this codebase, in plain English:

- Trait: an interface. A contract that types must fulfill. Like `interface` in Go/Java/TypeScript.
- Enum: a tagged union. A value that can be one of several named variants, each optionally carrying data. Like a TypeScript discriminated union: `type Action = { type: "proxy", url: string } | { type: "static", body: string }`.
- Arc: a shared pointer. Multiple parts of the program hold a reference to the same data. Thread-safe reference counting.
- ArcSwap: a thread-safe pointer that can be atomically swapped. Used for hot config reload: swap the entire config in one atomic operation while in-flight requests keep using the old one.
- Mutex: a lock. Only one thread can access the protected data at a time.
- OnceLock: a value initialized exactly once (lazily), then read-only forever.
- Box: a heap-allocated pointer. Used when the size of a value is not known at compile time (e.g. trait objects).
- SmallVec: an array that lives on the stack for small sizes and spills to the heap when it grows. Avoids allocation for the common case of 1 to 4 items.
- CompactString: a string optimized for short values. Stores small strings inline (no heap allocation), only allocates for longer strings.
- async/await: asynchronous programming. Functions that pause and resume, supporting thousands of concurrent requests on a small number of threads.
- inventory crate: link-time plugin discovery. Plugins register themselves with a global list at compile or link time, so the core never needs to know about specific plugins.

---

## Architecture overview

```
                    HTTP/1.1, HTTP/2           HTTP/3 (QUIC/UDP)
                         |                           |
                         v                           v
                  +-------------+            +---------------+
                  |   Pingora   |            |  H3 Listener  |
                  |   Server    |            |  (Quinn/s2n)  |
                  +------+------+            +-------+-------+
                         |                           |
                         v                           v
                  +------+------+            +-------+-------+
                  |  SbProxy    |            |  dispatch.rs  |
                  | (ProxyHttp) |            | (standalone)  |
                  +------+------+            +-------+-------+
                         |                           |
                         +----------+  +-------------+
                                    |  |
                                    v  v
                            +-------+-------+
                            |    reload.rs   |  <-- ArcSwap<CompiledPipeline>
                            | (hot config)   |      atomically swappable
                            +-------+-------+
                                    |
                                    v
                         +----------+-----------+
                         |  CompiledPipeline    |
                         |  (per-origin arrays) |
                         +----------+-----------+
                                    |
                    +---------------+----------------+
                    |               |                 |
                    v               v                 v
              +---------+    +----------+      +-----------+
              | Actions |    |   Auth   |      | Policies  |
              +---------+    +----------+      +-----------+
              | proxy   |    | api_key  |      | rate_limit|
              | static  |    | basic    |      | ip_filter |
              | redirect|    | bearer   |      | waf       |
              | echo    |    | jwt      |      | csrf      |
              | mock    |    | digest   |      | ddos      |
              | beacon  |    | forward  |      | expression|
              | lb      |    | noop     |      | sec_hdrs  |
              | ai_proxy|    +----------+      +-----------+
              | grpc    |
              | ws      |         +-------------+
              +---------+         | Transforms  |
                                  +-------------+
                                  | json        |
                                  | html/css    |
                                  | template    |
                                  | encoding    |
                                  | lua_json    |
                                  +-------------+

  Shared infrastructure crates:
  +------------+  +-----------+  +----------+  +----------+
  | sbproxy-   |  | sbproxy-  |  | sbproxy- |  | sbproxy- |
  | platform   |  | security  |  | cache    |  | transport|
  | (storage,  |  | (crypto,  |  | (resp    |  | (retry,  |
  |  messenger,|  |  IP, PII) |  |  cache)  |  |  coalesce|
  |  circuit   |  +-----------+  +----------+  |  hedge)  |
  |  breaker,  |                               +----------+
  |  DNS,      |  +-----------+  +----------+  +----------+
  |  health)   |  | sbproxy-  |  | sbproxy- |  | sbproxy- |
  +------------+  | extension |  | observe  |  | vault    |
                  | (CEL,Lua, |  | (metrics,|  | (secrets)|
                  |  WASM,MCP)|  |  events) |  +----------+
                  +-----------+  +----------+
```

---

## Request lifecycle

The full path an HTTP request takes when it arrives at the proxy:

1. Connection accepted. Pingora (for HTTP/1.1 and HTTP/2) or the Quinn-based H3 listener (for HTTP/3) accepts the TCP or UDP connection.

2. Request filter. The server extracts the hostname from the `Host` header, generates a unique request ID, and records the client IP.

3. Origin lookup. The `HostRouter` checks a bloom filter first. If the hostname is definitely not configured, it rejects immediately with 404. Otherwise it looks up the hostname in a HashMap to find the origin index.

4. Force-SSL check. If the origin has `force_ssl: true` and the request arrived over HTTP, the proxy redirects to HTTPS.

5. CORS preflight. If the request is an `OPTIONS` with CORS headers, the proxy handles it directly and short-circuits.

6. Auth check. If the origin has authentication configured (API key, basic auth, bearer token, JWT, digest, or forward auth), the request is checked. Failure returns 401 or 403.

7. Policy enforcement. Each policy runs in order: rate limiting, IP filtering, WAF, CSRF, DDoS protection, CEL expressions, security headers. The first deny short-circuits with the appropriate error status.

8. Forward rule matching. If path-based forward rules are configured, the proxy checks whether the request path matches a rule's prefix or exact pattern. On match, the request routes to an inline origin with its own action and modifiers.

9. Action dispatch. The action determines what happens to the request:
   - `proxy`: forward to an upstream HTTP server.
   - `static`: return a fixed response body.
   - `redirect`: return a 301/302/307/308 redirect.
   - `echo`: mirror the request back as JSON.
   - `mock`: return a configurable JSON response (with optional delay).
   - `ai_proxy`: route to AI providers (OpenAI, Anthropic, etc.).
   - `load_balancer`: distribute across multiple upstream targets.
   - Others: grpc, graphql, websocket, storage, a2a.

10. Upstream request. For proxy actions, Pingora opens a connection to the upstream, applying request modifiers along the way (header injection, URL rewrite, query manipulation, body replacement).

11. Response filter. When the upstream responds, the proxy applies CORS headers, HSTS, compression, response modifiers, and rate limit headers.

12. Response transforms. If transforms are configured, the response body is buffered and passed through the transform pipeline (JSON manipulation, HTML rewriting, template rendering).

13. Fallback handling. If the upstream returned an error status (502/503/504) and a fallback origin is configured, the proxy serves the fallback response instead.

14. Metrics and events. Request duration, status code, and other metadata are recorded in Prometheus counters and published to the event bus.

---

## Standard proxy (sbproxy/crates/)

### sbproxy (binary entry point)

**What it does:** The main executable. Parses command-line arguments to find the config file path, initializes structured logging (log levels via `RUST_LOG`), and calls `sbproxy_core::run()` to start the server.

**Key files:**
- `src/main.rs` - CLI argument parsing, logging init, calls `sbproxy_core::run()`

**How it fits in:** Top of the dependency tree. Depends on `sbproxy-core` (and transitively on everything else).

---

### sbproxy-core (Pingora server, request routing, pipeline dispatch)

**What it does:** The heart of the proxy. Implements the Pingora `ProxyHttp` trait, which defines callback methods for each phase of an HTTP request (request filter, upstream peer selection, response filter). Also manages hot config reload and hostname-based routing.

**Key files:**
- `src/server.rs` - The `SbProxy` struct that implements Pingora's `ProxyHttp` trait. Contains the full request lifecycle: auth checking, policy enforcement, action dispatch, request/response modification, CORS, HSTS, caching, transforms, fallback handling, metrics. The largest file in the codebase.
- `src/context.rs` - `RequestContext`, a per-request state bag threaded through every Pingora phase. Holds the request ID, client IP, hostname, origin index, auth result, rate limit info, transform buffers, and short-circuit flags.
- `src/pipeline.rs` - `CompiledPipeline`, the bridge between config and modules. Holds parallel arrays of compiled actions, auths, policies, transforms, forward rules, and fallbacks, indexed by origin position. Avoids per-request JSON parsing.
- `src/router.rs` - `HostRouter`, maps hostnames to origin indices. Uses a bloom filter (1% false positive rate) to fast-reject unknown hostnames without touching the HashMap, reducing cost for attack traffic.
- `src/reload.rs` - Hot config reload via `ArcSwap`. The compiled pipeline is stored in a global atomic pointer. Reloading swaps it atomically; in-flight requests continue using their snapshot until they finish.
- `src/dispatch.rs` - Standalone HTTP/3 dispatch function. Processes requests through the pipeline without depending on Pingora's Session type. Used by the H3 listener for QUIC-based HTTP/3 traffic.

**How it fits in:** Everything depends on this crate indirectly. It depends on `sbproxy-config` (for types), `sbproxy-modules` (for compiled actions/auth/policies/transforms), `sbproxy-plugin` (for trait definitions), `sbproxy-middleware` (for CORS/HSTS/modifiers), `sbproxy-ai` (for AI gateway), `sbproxy-observe` (for metrics), and `sbproxy-tls` (for TLS/H3).

**Key concepts:**
- The `CompiledPipeline` uses parallel arrays, not a map of maps. Origin index 0 means `actions[0]`, `auths[0]`, `policies[0]`, etc. Array indexing is faster than hash lookups.
- The enum dispatch pattern (see `sbproxy-modules`) means built-in actions compile to a flat `match` statement with predicted branches, not virtual function calls through a pointer table.

---

### sbproxy-config (YAML parsing, config compilation)

**What it does:** Parses the `sb.yml` configuration file from YAML into typed structs, then compiles those into immutable snapshots optimized for read performance. Handles environment variable interpolation (`${VAR_NAME}`) and template variable resolution (`{{vars.X}}`).

**Key files:**
- `src/types.rs` - User-facing config structs that map directly to YAML fields: `ConfigFile`, `ProxyServerConfig`, `AcmeConfig`, `Http3Config`, `RawOriginConfig`, `CorsConfig`, `HstsConfig`, `SessionConfig`, `RequestModifierConfig`, `ResponseModifierConfig`, etc.
- `src/raw.rs` - Intermediate representation for parsing. Handles the transition from raw YAML strings to typed config values.
- `src/compiler.rs` - `compile_config()` turns a raw YAML string into a `CompiledConfig`. Performs env var interpolation, template variable resolution, and validates all required fields. Lua scripts are exempt from interpolation to avoid breaking script syntax.
- `src/snapshot.rs` - `CompiledConfig` and `CompiledOrigin`, the immutable output. Plugin-specific fields (action, auth, policies, transforms) are kept as `serde_json::Value` blobs at this layer. They get compiled into typed enums by the module layer.

**How it fits in:** Depended on by `sbproxy-core` and `sbproxy-modules`. Does not depend on any other sbproxy crate.

**Key concepts:**
- Plugin configs are stored as raw JSON (`serde_json::Value`) in the config layer. This avoids a circular dependency: config does not need to know about specific module implementations. `sbproxy-core::pipeline` compiles these JSON blobs into typed enums at startup.
- `SmallVec<[RequestModifierConfig; 2]>` means: "usually 0 to 2 modifiers per origin, store them inline without heap allocation, spill to heap if more."

---

### sbproxy-plugin (plugin trait definitions, registry)

**What it does:** Defines the public API that all modules (built-in and third-party) depend on. Provides trait definitions for action handlers, auth providers, policy enforcers, and transform handlers. Also provides the `inventory`-based plugin registry for link-time plugin discovery.

**Key files:**
- `src/traits.rs` - Trait definitions: `ActionHandler`, `AuthProvider`, `PolicyEnforcer`, `TransformHandler`. Also defines `ActionOutcome` (proxy vs. responded), `AuthDecision` (allow/deny), and `PolicyDecision` (allow/deny). These traits exist ONLY for the `Plugin(Box<dyn T>)` fallback variant in module enums. Built-in modules use enum dispatch instead.
- `src/registry.rs` - `PluginRegistration` and `inventory::collect!()`. Third-party plugins register themselves via `inventory::submit!` with a name, kind, and factory function. The proxy discovers them at link time. No centralized registration code needed.
- `src/lifecycle.rs` - Plugin lifecycle phases: provision, validate, init, cleanup.
- `src/context.rs` - Plugin context passed during provisioning.

**How it fits in:** This is the lowest-level abstraction crate. `sbproxy-modules` depends on it for trait definitions and registry. `sbproxy-core` depends on it for `AuthDecision` and `ActionOutcome`.

**Key concepts:**
- The `inventory` crate is a Rust pattern for automatic plugin registration. When a crate calls `inventory::submit!`, it registers a struct at link time. The core calls `inventory::iter::<PluginRegistration>()` to discover all registered plugins.

---

### sbproxy-modules (actions, auth, policies, transforms)

**What it does:** Implements all built-in action handlers, auth providers, policy enforcers, and response transforms. Uses enum dispatch for performance: each module type is a Rust enum where each variant holds its compiled config inline. Only the `Plugin(...)` variant falls back to dynamic dispatch (virtual function calls) for third-party extensions.

**Key files:**

**Actions** (`src/action/`):
- `mod.rs` - The `Action` enum with variants: `Proxy`, `Redirect`, `Static`, `Echo`, `Mock`, `Beacon`, `LoadBalancer`, `AiProxy`, `WebSocket`, `Grpc`, `GraphQL`, `Storage`, `A2a`, `Noop`, `Plugin`.
- `aiproxy.rs` - AI proxy action config (connects to `sbproxy-ai`).
- `loadbalancer.rs` - Round-robin, weighted, random, and IP-hash load balancing across multiple upstream targets.
- `websocket.rs` - WebSocket proxy action.
- `grpc.rs` - gRPC proxy action (HTTP/2 with application/grpc content type).
- `graphql.rs` - GraphQL proxy with query introspection and schema validation.
- `storage.rs` - Serve files from S3, GCS, Azure Blob, or local filesystem.
- `a2a.rs` - Agent-to-Agent protocol proxy (Google's A2A specification).

**Auth** (`src/auth/`):
- `mod.rs` - The `Auth` enum with variants: `ApiKey`, `BasicAuth`, `Bearer`, `Jwt`, `Digest`, `ForwardAuth`, `Noop`, `Plugin`. Includes implementations for each: API key checks header/query param, Basic Auth validates username:password, Bearer validates token, JWT checks structure and expiry, Digest implements MD5 challenge-response, ForwardAuth delegates to an external HTTP service.
- `jwks.rs` - `JwksCache` for fetching JWT signing keys from a JWKS endpoint. TTL-based refresh, used by the `Jwt` auth variant when configured with a JWKS URL.

**Policies** (`src/policy/`):
- `mod.rs` - The `Policy` enum: `RateLimit`, `IpFilter`, `SecHeaders`, `RequestLimit`, `Csrf`, `Ddos`, `Sri`, `Expression`, `Assertion`, `Waf`, `Plugin`. Rate limiting uses a token bucket algorithm. IP filtering checks CIDR allow/deny lists. WAF runs OWASP-style rules. Expression evaluates CEL against the request. DDoS tracks connections per IP with LRU eviction.
- `sharded_limiter.rs` - 16-way sharded rate limiter for high-concurrency scenarios.

**Transforms** (`src/transform/`):
- `mod.rs` - The `Transform` enum: `Json`, `JsonProjection`, `JsonSchema`, `Template`, `ReplaceStrings`, `Normalize`, `Encoding`, `FormatConvert`, `PayloadLimit`, `Discard`, `SseChunking`, `Html`, `OptimizeHtml`, `HtmlToMarkdown`, `Markdown`, `Css`, `LuaJson`, `JavaScript`, `JsJson`, `Noop`, `Plugin`.
- `json.rs` - Set, remove, rename JSON fields. JSON projection (include/exclude fields).
- `markup.rs` - HTML manipulation (inject elements, remove selectors, rewrite attributes), CSS manipulation, HTML-to-Markdown conversion, Markdown-to-HTML.
- `text.rs` - Template rendering, regex-based string replacement, whitespace normalization, base64/URL encoding, JSON-to-YAML format conversion.
- `control.rs` - Payload size limits, body discard, SSE chunking.

The Lua and JavaScript transform variants are defined directly in `mod.rs` rather than in dedicated files. Their script execution is delegated to `sbproxy-extension::lua` and `sbproxy-extension::js`.

**Compilation** (`src/compile.rs`):
- `compile_action()`, `compile_auth()`, `compile_policy()`, `compile_transform()` - Factory functions that take a `serde_json::Value` and return the appropriate enum variant.

**How it fits in:** Depended on by `sbproxy-core` (which compiles and dispatches modules). Depends on `sbproxy-plugin` (for trait definitions), `sbproxy-config` (for config types), and `sbproxy-extension` (for CEL/Lua evaluation in expression policies and Lua transforms).

**Key concepts:**
- Enum dispatch vs. trait objects: built-in modules are enum variants, so calling `action.execute()` compiles to a `match` statement where the CPU can predict branches. Third-party plugins use `Box<dyn ActionHandler>`, which requires an indirect call through a vtable pointer. This is the main performance optimization.
- `AiProxy` is `Box<AiProxyAction>` because AI gateway configs are large and rarely used. Boxing keeps the `Action` enum small for the common case.

---

### sbproxy-ai (AI gateway)

**What it does:** Full AI gateway: multi-provider routing, streaming SSE support, guardrails pipeline, budget tracking, rate limiting, semantic caching, session management, and virtual key mapping. Supports OpenAI, Anthropic, and other LLM providers.

**Key files:**
- `src/handler.rs` - `AiHandlerConfig`, the top-level AI gateway configuration. Defines providers, routing strategy, model allow/block lists, guardrails, budget, virtual keys, and per-model rate limits.
- `src/routing.rs` - `Router` with strategies: `RoundRobin`, `Weighted`, `FallbackChain`, `Random`, `LowestLatency`, `LeastConnections`, `CostOptimized`, `TokenRate`, `Sticky`. Tracks per-provider latency, connection count, and token usage with atomic counters for lock-free concurrency.
- `src/provider.rs` - `ProviderConfig` for individual AI providers (API key, base URL, model mappings).
- `src/providers/mod.rs` - Provider info registry (known providers, their base URLs, supported models).
- `src/client.rs` - `AiClient`, the HTTP client for making requests to AI providers.
- `src/streaming.rs` - SSE (Server-Sent Events) parser and writer. Parses `data: {...}` lines from streaming AI responses, handles `[DONE]` sentinels, accumulates chunks into complete responses.
- `src/guardrails/mod.rs` - Content safety pipeline with built-in guardrails: PII detection, prompt injection detection, toxicity scoring, jailbreak detection, content safety classification, JSON schema validation, and regex-based rules. Each guardrail can block or flag content.
- `src/budget.rs` - Budget tracking for cost control. Tracks spend per workspace/user and can block, warn, or downgrade to cheaper models when budgets are exceeded.
- `src/ratelimit.rs` - Per-model rate limiting (requests per minute, tokens per minute).
- `src/concurrency.rs` - Per-provider concurrency limiter using semaphores.
- `src/semantic_cache.rs` - Exact-match cache for AI responses keyed by prompt hash. LRU eviction when full, TTL-based expiry.
- `src/session.rs` - Conversation session store for multi-turn AI interactions.
- `src/identity.rs` - Virtual key system. Maps user-facing API keys to provider-specific keys, enabling key rotation and access control without client changes.
- `src/types.rs` - Shared types: `Message`, `StreamChunk`, `AiResponse`, `Usage` (token counts).
- `src/realtime.rs` - Real-time/WebSocket AI API support.
- `src/threads.rs` - OpenAI Assistants-style thread management.
- `src/assistants.rs` - OpenAI Assistants API support.
- `src/audio.rs` - Audio/speech AI API support.
- `src/image.rs` - Image generation AI API support.
- `src/batch.rs` - Batch request processing with job tracking.
- `src/finetune.rs` - Fine-tuning job management.

**How it fits in:** Used by `sbproxy-modules` (the `AiProxy` action variant) and by `sbproxy-core` (which holds a global `AiClient`).

**Key concepts:**
- `DashMap` (used in sticky routing) is a concurrent HashMap. Multiple threads can read and write at once without a global lock. Each shard has its own lock.
- The router uses `AtomicU64` and `AtomicU32` for lock-free counters. These are CPU-level atomic operations that guarantee correctness without locks.

---

### sbproxy-extension (CEL, Lua, WASM, MCP)

**What it does:** Provides scripting and expression evaluation engines for user-defined logic in routing, access control, policy enforcement, and request/response processing.

**Key files:**

**CEL** (`src/cel/`):
- `mod.rs` - `CelExpression` and `CelContext`. Compiles and evaluates Common Expression Language expressions against HTTP request data. Used for conditional routing and expression-based policies.
- `context.rs` - Builds CEL evaluation context from request data (method, path, headers, query, client IP).
- `functions.rs` - Custom CEL functions available in expressions.

**Lua** (`src/lua/`):
- `mod.rs` - `LuaEngine`, a sandboxed Lua execution environment using Luau (Roblox's Lua dialect). Dangerous globals (`os`, `io`, `loadfile`, `dofile`, `require`) are removed. JSON helper functions are registered.
- `sandbox.rs` - Sandbox configuration (memory limits, execution timeouts).
- `bindings.rs` - Lua-to-Rust bindings for request/response objects.

**JS** (`src/js/`):
- `mod.rs` - `JsEngine`, a sandboxed JavaScript execution environment using QuickJS via `rquickjs`. Default 16 MB memory limit and 1 MB stack. `eval` is removed; `json_encode` / `json_decode` are registered as helpers. Used by JavaScript and JsJson transforms.

**WASM** (`src/wasm/`):
- `mod.rs` - `WasmRuntime`, a sandboxed WebAssembly execution environment. Currently a passthrough stub; full wasmtime integration is planned behind a feature flag. Config supports module paths, allowed hosts, memory limits, and execution timeouts.

**MCP** (`src/mcp/`):
- `mod.rs` - `McpHandler` implements JSON-RPC 2.0 based Model Context Protocol for exposing tools and resources to LLMs.
- `registry.rs` - `ToolRegistry` for registering and discovering MCP tools.
- `handler.rs` - Request handling for MCP protocol messages.
- `types.rs` - MCP protocol types (tool definitions, resource descriptors).

**How it fits in:** Used by `sbproxy-modules` for expression policies, Lua transforms, and Lua-based matching logic. The MCP handler is used by the AI gateway for tool-use scenarios.

---

### sbproxy-middleware (CORS, HSTS, compression, modifiers)

**What it does:** HTTP middleware for cross-cutting concerns that apply to most requests, regardless of action type.

**Key files:**
- `src/cors.rs` - CORS header injection. Handles preflight OPTIONS requests and adds `Access-Control-*` headers based on per-origin config.
- `src/hsts.rs` - HTTP Strict Transport Security header injection (`Strict-Transport-Security`).
- `src/compression.rs` - Response body compression (gzip, brotli, deflate).
- `src/modifiers.rs` - Request and response header modifiers. Applies set/add/remove operations to HTTP headers. Supports `{{vars.X}}`, `{{request.id}}`, and `{{env.X}}` template patterns in header values.
- `src/callback.rs` - Webhook callback support for on_request/on_response hooks.
- `src/problem_details.rs` - RFC 7807 Problem Details JSON error formatting.
- `src/proxy_status.rs` - RFC 9209 Proxy-Status header generation.
- `src/signatures.rs` - HTTP Message Signatures (RFC 9421) for request signing/verification.
- `src/error_pages.rs` - Error page rendering. When an upstream returns a status that matches a configured error page, the proxy substitutes the configured template (path, JSON, redirect, or static body) and serves it in place of the upstream body.

**How it fits in:** Used directly by `sbproxy-core` in the response filter phase. Does not depend on any other sbproxy crate except `sbproxy-config` (for config types).

---

### sbproxy-cache (response caching)

**What it does:** Caches upstream HTTP responses to avoid repeating upstream requests. Supports multiple storage backends.

**Key files:**
- `src/response.rs` - Cache key computation (based on method, host, path, headers), cacheability checks (only safe methods, non-zero TTL, cacheable status codes), and `ResponseCacheConfig`.
- `src/store/mod.rs` - `CacheStore` trait and `CachedResponse` type.
- `src/store/memory.rs` - In-memory LRU cache with TTL-based expiry.
- `src/store/file.rs` - File-based cache store (persists across restarts).
- `src/store/memcached.rs` - Memcached-backed cache store for distributed caching.

**How it fits in:** Used by `sbproxy-core` in the request/response pipeline. If a cached response exists and is fresh, the upstream request is skipped entirely.

---

### sbproxy-platform (storage backends, messengers, circuit breaker, DNS, health)

**What it does:** Infrastructure services the proxy needs regardless of what it is proxying. Pluggable storage backends, message brokers, circuit breakers, DNS caching, health tracking, and PROXY protocol support.

**Key files:**

**Storage** (`src/storage/`):
- `mod.rs` - `KVStore` trait (get, set, delete, list). Generic key-value storage for configs, certs, sessions.
- `memory.rs` - In-memory store (for testing and single-node deployments).
- `redis.rs` - Redis-backed store (for distributed deployments).
- `postgres.rs` - PostgreSQL-backed store.
- `sqlite.rs` - SQLite-backed store (embedded, no external service needed).
- `redb_store.rs` - redb-backed store (embedded pure-Rust database, similar to LMDB).
- `file.rs` - Filesystem-backed store.
- `async_kv.rs` - Async wrapper trait that adapts blocking backends to the async pipeline.
- `async_redis.rs` - Async Redis backend used by the AI gateway and shared cache for non-blocking I/O.

**Messengers** (`src/messenger/`):
- `mod.rs` - `Messenger` trait (publish, subscribe). For real-time event distribution.
- `memory.rs` - In-memory bounded channel (single-node, 10k message limit).
- `redis.rs` - Redis Streams-backed messenger.
- `aws_sqs.rs` - AWS SQS-backed messenger.
- `gcp_pubsub.rs` - GCP Pub/Sub-backed messenger.

**Infrastructure:**
- `src/circuitbreaker.rs` - Lock-free circuit breaker using atomic operations. States: Closed (normal), Open (all rejected), HalfOpen (probe requests), Closed. Prevents cascading failures when upstreams are down.
- `src/adaptive_breaker.rs` - Adaptive variant that tunes its open / half-open windows based on observed error and latency rates.
- `src/outlier.rs` - Outlier detection that ejects misbehaving upstream instances from the load balancer pool.
- `src/dns.rs` - DNS cache with TTL-based expiry and O(1) lookups via doubly-linked list for LRU eviction.
- `src/health.rs` - `HealthTracker` for monitoring upstream health. Tracks success/failure rates and determines healthy/degraded/unhealthy state.
- `src/proxy_protocol.rs` - PROXY protocol v1 parser for extracting real client IPs from load balancers (HAProxy, AWS NLB).

**How it fits in:** Used throughout. `sbproxy-tls` uses storage for certificate persistence, `sbproxy-core` uses health for upstream monitoring, `sbproxy-observe` uses messengers for event distribution, and circuit breakers protect upstream connections.

---

### sbproxy-security (crypto, IP filtering, PII)

**What it does:** Security utilities used across the proxy: cryptographic operations, IP address handling, hostname validation, and PII masking in logs.

**Key files:**
- `src/crypto.rs` - `hkdf_derive()` for deriving encryption and signing keys from a master secret using HKDF with distinct info strings. Prevents key reuse across different purposes.
- `src/ip.rs` - `ip_in_cidrs()` checks if an IP is in any of a list of CIDR ranges. `is_private_ip()` detects RFC 1918 private addresses (for SSRF prevention). `parse_cidrs()` parses CIDR strings. Handles both IPv4 and IPv6.
- `src/hostfilter.rs` - `HostFilter` validates hostnames against allow/deny lists. Used to prevent cross-tenant access in multi-tenant deployments.
- `src/pii.rs` - `mask_email()`, `mask_credit_card()`, `mask_ip()` for redacting sensitive data in log messages.

**How it fits in:** Used by `sbproxy-core` (IP filtering policies), `sbproxy-vault` (key derivation), and `sbproxy-observe` (PII masking in logs).

---

### sbproxy-transport (coalescing, hedging, retry, rate limiting)

**What it does:** Advanced HTTP transport features that sit between the proxy and upstream servers.

**Key files:**
- `src/coalescing.rs` - `RequestCoalescer` deduplicates concurrent identical requests. The first request becomes the "leader" and goes upstream. Subsequent requests for the same key wait and share the leader's response via a broadcast channel. Saves upstream load when many clients request the same resource at once.
- `src/hedging.rs` - `HedgingConfig` for speculative request hedging. Sends a second request to a different upstream after a timeout and uses whichever responds first. Reduces tail latency at the cost of extra upstream load.
- `src/retry.rs` - `RetryConfig` with configurable retry count, backoff strategy, and retryable status codes.
- `src/ratelimit.rs` - `UpstreamRateLimiter` keeps upstream services from being overwhelmed. Different from the policy-layer rate limiter (which limits clients). This one limits outbound traffic to upstreams.

**How it fits in:** Used by `sbproxy-core` in the upstream connection phase. These are transparent to clients.

---

### sbproxy-vault (secret management)

**What it does:** Manages secrets (API keys, database passwords, encryption keys) with pluggable backends. Provides variable interpolation for config files.

**Key files:**
- `src/lib.rs` - Re-exports `LocalVault`, `VaultManager`, and the supporting types.
- `src/manager.rs` - `VaultManager` orchestrates multiple named vault backends. Routes secret operations to the appropriate backend based on a prefix or explicit backend name. `VaultBackend` trait defines get/set operations.
- `src/local.rs` - `LocalVault`, a file-based vault backend for development and single-node deployments.
- `src/resolver.rs` - Expands `${secret.X}` references in config strings by walking the manager and substituting values.
- `src/rotation.rs` - Rotation policy state and helpers. Tracks rotation timestamps and triggers re-encryption when a master key is rolled.
- `src/metadata.rs` - Per-secret metadata: created/updated timestamps, version counter, expected scope.
- `src/scope.rs` - Scope qualifiers (workspace, environment, origin) used to keep secrets from leaking across tenants.
- `src/secret_string.rs` - `SecretString` wrapper that zeros memory on drop and avoids accidental logging via custom `Debug`.
- `src/convergent.rs` - Deterministic encryption helpers used to derive lookup keys without exposing plaintext.

**How it fits in:** Used by `sbproxy-config` for secret interpolation in config files (e.g., `{{secret.db_password}}`).

---

### sbproxy-observe (events, logging, metrics, telemetry)

**What it does:** Observability stack. Collects metrics, emits structured events, and configures logging.

**Key files:**
- `src/metrics.rs` - `ProxyMetrics` using Prometheus. Tracks: `sbproxy_requests_total` (by hostname, method, status), `sbproxy_request_duration_seconds` (histogram with latency buckets from 1ms to 10s), `sbproxy_errors_total`, `sbproxy_active_connections`, `sbproxy_cache_hits`, `sbproxy_ai_tokens_total`.
- `src/events.rs` - `EventBus` pub/sub system. Event types: `RequestStarted`, `RequestCompleted`, `RequestError`, `AuthDenied`, `PolicyDenied`, `CacheHit`, `CacheMiss`, `ProviderSelected`, `BudgetExceeded`, `GuardrailTriggered`, `ConfigReloaded`. Handlers subscribe to specific event types.
- `src/logging.rs` - `LoggingConfig` for structured logging configuration.
- `src/telemetry.rs` - Wireframe entry point for OpenTelemetry integration. Currently a placeholder; structured logs and Prometheus counters carry the runtime today.
- `src/access_log.rs` - Per-request access log writer with configurable fields and sinks (stdout, file, rotated file).
- `src/alerting/` - Alert rule evaluation against metric streams. Emits `AlertFired` events when thresholds are crossed.
- `src/audit.rs` - Audit log writer for security-relevant events (auth denials, policy violations, config changes).
- `src/cardinality.rs` - Cardinality guards that cap the number of distinct label values a counter can carry, preventing label explosions from runaway clients.
- `src/export/` - Telemetry exporters. `otlp_grpc.rs` exposes a thin convenience layer over the gRPC OTLP transport; the canonical pipeline lives in `telemetry.rs::init_otlp_pipeline` and a `transport: http | grpc` field on `TelemetryConfig` selects the protocol. `webhook.rs` ships events to an external HTTPS endpoint with HMAC signing.
- `src/golden_signals.rs` - Computes the four golden signals (latency, traffic, errors, saturation) from raw metric series.
- `src/redact.rs` - Redaction helpers that strip secrets from log records before they hit a sink.
- `src/topology.rs` - Topology graph derived from observed traffic, used by the mesh dashboard.
- `src/trace_ctx/` - Trace-context extraction and propagation. `w3c.rs` parses `traceparent` / `tracestate`; `b3.rs` parses single and multi-header B3.

**How it fits in:** `sbproxy-core` records metrics after each request. Other crates emit events. Metrics are exposed at `/metrics` for Prometheus scraping.

---

### sbproxy-httpkit (buffer pooling)

**What it does:** HTTP utility library. Currently a thread-safe buffer pool for reusing memory allocations during response body processing.

**Key files:**
- `src/bufferpool.rs` - `BufferPool`, a bounded pool of reusable `BytesMut` buffers. When the proxy needs to buffer a response body (for transforms or caching), it grabs a pre-allocated buffer from the pool instead of allocating new memory. When done, the buffer is returned (cleared but keeping its allocated capacity). If the pool is full, extra buffers are dropped.

**How it fits in:** Used by `sbproxy-core` during response body buffering for transforms. Reduces garbage collection pressure under high load.

---

### sbproxy-tls (TLS, ACME auto-cert, HTTP/3)

**What it does:** Everything related to encrypted connections: TLS termination, automatic certificate provisioning via ACME (Let's Encrypt), certificate storage, SNI-based certificate selection, and HTTP/3 over QUIC.

**Key files:**
- `src/lib.rs` - `TlsState`, the central coordinator. Initializes the certificate resolver, loads manual and cached ACME certificates, spawns a background renewal task (checks every 12 hours), and can generate self-signed bootstrap certificates for ACME-only mode.
- `src/acme.rs` - `AcmeClient` for the full ACME flow: account registration, authorization, HTTP-01/TLS-ALPN-01 challenges, certificate issuance, and key management.
- `src/cert_resolver.rs` - `CertResolver`, an SNI-aware certificate resolver. When a TLS handshake arrives, it picks the correct certificate based on the Server Name Indication (SNI) field. Falls back to a default certificate if no hostname-specific cert is available.
- `src/cert_store.rs` - `CertStore` persists certificates and metadata (issued date, expiry, serial number) to a `KVStore` backend.
- `src/challenges.rs` - `Http01ChallengeStore` handles ACME HTTP-01 challenge tokens. When Let's Encrypt asks "do you control this domain?", the proxy serves the challenge response at `/.well-known/acme-challenge/<token>`.
- `src/h3_listener.rs` - HTTP/3 listener using Quinn (a QUIC implementation). Binds a UDP socket on the same port as HTTPS and processes QUIC connections.
- `src/alt_svc.rs` - Generates `Alt-Svc` headers to advertise HTTP/3 availability to clients.
- `src/mtls.rs` - Mutual TLS configuration. Validates client certificates against a configured CA bundle for origins that require mTLS.
- `src/ocsp.rs` - OCSP stapling. Caches OCSP responses for served certificates and attaches them during the TLS handshake to avoid client-side OCSP fetches.

**How it fits in:** `sbproxy-core` calls into this during server startup to configure TLS and optionally start the H3 listener. The ACME renewal task runs as a background Tokio task.

**Key concepts:**
- SNI (Server Name Indication) is a TLS extension where the client tells the server which hostname it wants before the encrypted connection is established. The proxy uses it to serve different certificates for different hostnames on the same IP.
- The renewal task checks certificate expiry against a configurable window (default: 30 days before expiry) and issues new certificates via ACME.

---

## Crate dependency summary

```
sbproxy (binary)
  sbproxy-core
    sbproxy-config
    sbproxy-modules
      sbproxy-plugin
      sbproxy-extension
      sbproxy-security
      sbproxy-transport
      sbproxy-vault
      sbproxy-cache
      sbproxy-platform
    sbproxy-ai
    sbproxy-middleware
    sbproxy-cache
    sbproxy-platform
    sbproxy-observe
    sbproxy-httpkit
    sbproxy-tls
```

`sbproxy-core` itself depends only on the crates listed at the top level above. `sbproxy-security`, `sbproxy-transport`, and `sbproxy-vault` reach the binary transitively through `sbproxy-modules`.

The architectural boundary: `sbproxy-config` stores plugin configs as raw JSON. `sbproxy-modules` compiles that JSON into typed enums. `sbproxy-core::pipeline` bridges the two. This avoids circular dependencies and keeps the config layer ignorant of specific module implementations.

---

## Per-crate orientation

A one-paragraph tour of every crate under `crates/`. Use this as a bus-factor index when you are dropped into the codebase cold and need to know which crate to open. For each crate, the "start reading here" file is the canonical entry point; the "key types" are the names you should be able to grep for and find in seconds.

### sbproxy (binary)

The thin executable wrapper. Installs the mimalloc global allocator, selects the `rustls` ring crypto provider before any TLS path runs, initialises `tracing-subscriber` from `RUST_LOG`, parses CLI flags, and either hands a config path off to `sbproxy_core::run` or dispatches the `projections render` subcommand for offline rendering of robots.txt, llms.txt, licenses.xml, and tdmrep.json. **Key types:** `parse_config_path`, `RenderArgs`, `handle_projections_render`. **Start reading here:** `crates/sbproxy/src/main.rs`. The binary itself contains no proxy logic; everything material lives in workspace crates.

### sbproxy-core

Heart of the runtime. Implements the Pingora `ProxyHttp` trait through `SbProxy`, threads a per-request `RequestContext` through every phase, and dispatches against the per-origin `CompiledPipeline` array (parallel arrays of compiled actions, auth, policies, transforms, forward rules, and fallbacks indexed by origin position). Owns `HostRouter` (bloom filter plus `HashMap`), the `ArcSwap`-based hot reload path in `reload.rs`, the standalone HTTP/3 dispatch path in `dispatch.rs`, the Wave 8 P0 edge-capture wiring in `wave8.rs`, and the admin and identity surfaces. **Key types:** `SbProxy`, `RequestContext`, `CompiledPipeline`, `HostRouter`, `run`. **Start reading here:** `crates/sbproxy-core/src/lib.rs` then `server.rs`.

### sbproxy-config

YAML to typed snapshot pipeline. Parses `sb.yml` into the user-facing structs in `types.rs`, walks an intermediate raw representation for env-var interpolation and template-variable resolution, and emits an immutable `CompiledConfig` of `CompiledOrigin` records ready for the runtime. Plugin-specific blocks (action, auth, policies, transforms) ride through this layer as opaque `serde_json::Value` blobs so the config crate never needs to know what specific modules exist. **Key types:** `ConfigFile`, `CompiledConfig`, `CompiledOrigin`, `compile_config`. **Start reading here:** `crates/sbproxy-config/src/lib.rs` then `compiler.rs`. Does not depend on any other sbproxy crate.

### sbproxy-modules

All the built-in actions, auth providers, policies, transforms, and projection generators, plus the compile-time factory functions that turn raw JSON into typed enums. Built-in modules use enum dispatch (`Action`, `Auth`, `Policy`, `Transform`); only the `Plugin(...)` variant on each enum falls back to `Box<dyn Trait>` for third-party extensions. Surface area is broad on purpose because every shipped feature lands here: load balancer routing strategies, A2A detection, AI crawl-control ledger, prompt-injection v2, OpenAPI validation, DLP, SRI, Page Shield, exposed-creds, robots/llms/tdmrep projections, and the full transform set including JSON, HTML, Markdown, CEL, Lua, JavaScript, and WASM bridges. **Key types:** `Action`, `Auth`, `Policy`, `Transform`, `compile_action`, `render_projections`. **Start reading here:** `crates/sbproxy-modules/src/lib.rs` then `compile.rs`.

### sbproxy-plugin

The lowest-level abstraction crate. Defines the public traits (`ActionHandler`, `AuthProvider`, `PolicyEnforcer`, `TransformHandler`), the inventory-based registry that lets third-party crates self-register at link time, the lifecycle phases (provision, validate, init, cleanup), the admin-audit emitter seam, and the identity-resolver and ML-classifier hook tables consumed by `sbproxy-core`. **Key types:** `ActionHandler`, `IdentityResolverHook`, `PluginRegistration`. **Start reading here:** `crates/sbproxy-plugin/src/lib.rs` then `traits.rs`. The traits exist for the `Plugin(...)` fallback variant; built-ins go through enum dispatch in `sbproxy-modules`.

### sbproxy-platform

Pluggable infrastructure services the proxy needs regardless of what is upstream: a `KVStore` trait with memory/redis/postgres/sqlite/redb/file backends, a `Messenger` trait with memory/redis/SQS/GCP Pub-Sub backends, a lock-free `CircuitBreaker` plus an `AdaptiveBreaker` variant, an `OutlierDetector` for ejecting bad upstream instances, a TTL-aware `DnsCache` with O(1) LRU eviction, a `HealthTracker` for upstream state, and a PROXY-protocol v1 parser. **Key types:** `KVStore`, `Messenger`, `CircuitBreaker`, `DnsCache`, `HealthTracker`. **Start reading here:** `crates/sbproxy-platform/src/lib.rs`.

### sbproxy-cache

HTTP response caching with multi-tier and reserve semantics. Owns cache-key computation (method, host, path, vary fingerprint), cacheability checks, a `CacheStore` trait with memory, file, memcached, and Redis backends, a two-tier (memory in front of remote) layer, and a Cache Reserve tier with FS, memory, and Redis backends and metadata tracking. **Key types:** `CacheStore`, `CachedResponse`, `ReserveCacheStore`, `compute_cache_key`. **Start reading here:** `crates/sbproxy-cache/src/lib.rs` then `response.rs`.

### sbproxy-ai

The AI gateway. Easily the largest crate by file count: provider routing across OpenAI, Anthropic, and friends with eight strategies including cost-optimised and lowest-latency, SSE streaming, the multi-stage guardrails pipeline (PII, prompt injection, toxicity, jailbreak, JSON schema), hierarchical and per-scope budgets, per-model and per-provider rate limits, semantic and prompt caching, virtual key scoping and rotation, response dedup, idempotency, fine-tune and batch job tracking, multimodal modality detection, context overflow and compression, and OpenAI Assistants/Threads/Audio/Image surface compatibility. **Key types:** `AiClient`, `Router`, `BudgetTracker`, `SemanticCache`, `KeyStore`, `HierarchicalBudget`. **Start reading here:** `crates/sbproxy-ai/src/lib.rs` then `handler.rs`.

### sbproxy-extension

Scripting and expression runtimes that user-defined logic plugs into: CEL (compiled `CelExpression` evaluated against a request-derived context), Luau-based Lua with a removed-globals sandbox, QuickJS-based JavaScript with a 16 MB memory cap, a WASM scaffold that today is a passthrough stub with config plumbing for a future wasmtime integration, the `McpHandler` JSON-RPC 2.0 Model Context Protocol server with its tool registry, and a feature-flag module. These are the four extension surfaces the public docs steer users toward. **Key types:** `CelExpression`, `LuaEngine`, `JsEngine`, `WasmRuntime`, `McpHandler`. **Start reading here:** `crates/sbproxy-extension/src/lib.rs`.

### sbproxy-observe

The observability stack: `ProxyMetrics` (Prometheus counters and histograms covering requests, durations, errors, AI tokens, cache, golden signals), the typed `EventBus` and `RequestEvent` envelope used by the four Wave 8 streams, the `RequestEventSink` global transport seam, structured logging with sampling and redaction, OTLP pipeline plumbing (`init_otlp_pipeline`, http or gRPC selectable), W3C and B3 trace-context parsers, an outbound webhook notifier with Ed25519 or HMAC-SHA256 signing and a deadletter queue, an SNTP-based clock-skew monitor wired into `/readyz`, the access-log writer, the audit-log writer, the cardinality limiter, and per-agent metric label bundles. **Key types:** `ProxyMetrics`, `EventBus`, `RequestEvent`, `Notifier`, `TelemetryConfig`. **Start reading here:** `crates/sbproxy-observe/src/lib.rs` then `metrics.rs`.

### sbproxy-security

Security primitives shared across crates: `hkdf_derive` for purpose-distinct key derivation, IP and CIDR helpers (`ip_in_cidrs`, `is_private_ip`, `parse_cidrs`) covering IPv4 and IPv6, a `HostFilter` for cross-tenant isolation, a `PiiRedactor` with email/credit-card/IP masking helpers, a `validate_url`-family of SSRF guards (HTTPS-only, private-IP block, size cap, allowlist variant), the optional headless-browser detector behind a `tls-fingerprint` feature, and the optional reverse-DNS-based agent verifier behind an `agent-class` feature. **Key types:** `HostFilter`, `PiiRedactor`, `validate_url`, `hkdf_derive`. **Start reading here:** `crates/sbproxy-security/src/lib.rs`.

### sbproxy-tls

TLS, ACME, and HTTP/3 in one crate. `TlsState` is the central coordinator: it loads manual cert/key files, pre-loads cached ACME certs from the cert store, spawns the 12-hour ACME renewal task, can mint a self-signed bootstrap cert when ACME is the only configured source, and can start the Quinn-based H3 listener on the same UDP port as HTTPS. Companion modules cover the full ACME flow, the SNI-aware `CertResolver`, the `CertStore` persistence layer, HTTP-01 challenge handling, `Alt-Svc` header generation, mTLS configuration, OCSP stapling, and JA4H TLS fingerprinting. **Key types:** `TlsState`, `CertResolver`, `AcmeClient`, `Http01ChallengeStore`, `TlsFingerprint`. **Start reading here:** `crates/sbproxy-tls/src/lib.rs`.

### sbproxy-transport

Upstream-side transport features that sit between the proxy and origin servers: `RequestCoalescer` (deduplicate concurrent identical requests via a leader/follower broadcast), `HedgingConfig` (speculative second request after a timeout), `RetryConfig` and `RetryBudget` (configurable backoff and budget), `UpstreamRateLimiter` (cap outbound traffic, distinct from the client-facing rate-limit policy), `DedupCache`, request mirroring, and an `auto_pool` self-tuning connection pool. **Key types:** `RequestCoalescer`, `HedgingConfig`, `RetryConfig`, `UpstreamRateLimiter`. **Start reading here:** `crates/sbproxy-transport/src/lib.rs`.

### sbproxy-vault

Secret management with a pluggable `VaultBackend` trait. `VaultManager` orchestrates multiple named backends and routes by prefix or explicit name; `LocalVault` is the file-backed default; `SecretResolver` expands `${secret.X}` references in compiled config strings; `RotationManager` tracks rotation timestamps and triggers re-encryption when a master key rolls; `SecretScope` enforces workspace/environment/origin tenancy; `SecretString` zeros memory on drop and refuses to print itself in `Debug`; `ConvergentFingerprinter` derives deterministic lookup keys without exposing plaintext. **Key types:** `VaultManager`, `VaultBackend`, `SecretResolver`, `SecretString`. **Start reading here:** `crates/sbproxy-vault/src/lib.rs` then `manager.rs`.

### sbproxy-middleware

Cross-cutting HTTP middleware that runs regardless of action type: CORS preflight and header injection, HSTS, response compression (gzip, brotli, deflate), header `modifiers` with template interpolation (`{{vars.X}}`, `{{request.id}}`, `{{env.X}}`), webhook callbacks for `on_request` and `on_response` hooks, RFC 7807 Problem Details rendering, RFC 9209 Proxy-Status emission, RFC 9421 HTTP Message Signatures, configurable error pages with template, JSON, redirect, and static body modes, and the Idempotency-Key middleware with cached-retry-versus-conflict semantics. **Key types:** `CorsConfig`, `Modifier`, `IdempotencyConfig`, `ErrorPagesConfig`. **Start reading here:** `crates/sbproxy-middleware/src/lib.rs`.

### sbproxy-openapi

Single-file crate that emits an OpenAPI 3.0 document from a live `CompiledConfig` snapshot. Walks origins, forward rules, allowed methods, declared parameters, auth configs, error pages, and cacheable status codes, and renders them into a spec consumable by Postman, Swagger UI, ReadMe.io, and Stainless. Auth-type mapping is itself extensible: registered `AuthSchemeMapper` entries (link-time `inventory`-style) win over OSS built-ins, with a `x-sbproxy-auth-type` extension fallback for unknown types so the doc still validates. **Key types:** `build`, `render_json`, `render_yaml`, `AuthSchemeMapper`. **Start reading here:** `crates/sbproxy-openapi/src/lib.rs` (the entire crate is one file plus tests).

### sbproxy-k8s-operator

OSS Kubernetes operator scaffold. Defines two CRDs in the `sbproxy.dev/v1alpha1` group: `SBProxy` (a desired proxy deployment with replica count, image, resources, and a config reference) and `SBProxyConfig` (a versioned `sb.yml` document). The reconciler renders a desired Deployment, Service, and ConfigMap triple, applies it server-side, and triggers a rollout-restart when the config hash changes. Includes a hand-rolled `coordination.k8s.io/v1.Lease` leader-election loop because `kube-runtime` 0.95 lacks a built-in helper at the pinned version. The crate publishes both a library (so tests and kubectl plugins share one source of truth) and a binary. **Key types:** `SBProxy`, `SBProxyConfig`, `reconcile`, `leader`. **Start reading here:** `crates/sbproxy-k8s-operator/src/lib.rs` then `reconcile.rs`.

### sbproxy-classifiers

Pure-Rust ONNX inference plus tokenizer wrapper that detector policies (notably `prompt_injection_v2`) call into. `OnnxClassifier::load` parses and optimises a Hugging Face style ONNX classification graph; `download_and_load` caches model files on disk keyed by URL hash and validates pinned SHA-256 hashes before use; `classify` tokenises text, runs the forward pass, and returns a top label and softmax score. Uses `tract-onnx` rather than the C++ ONNX Runtime so the proxy compiles cleanly in containers, CI sandboxes, and musl/arm64 cross builds with no extra system deps. Also ships the agent-class catalog (`AgentClass`, `AgentId`, `DEFAULT_CATALOG_YAML`) and a `KNOWN_MODELS` registry consumed by the agent-classification path. **Key types:** `OnnxClassifier`, `ClassificationOutput`, `AgentClass`, `KnownModel`. **Start reading here:** `crates/sbproxy-classifiers/src/lib.rs`.
