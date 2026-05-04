# How SBproxy compares

*Last modified: 2026-05-03*

SBproxy is a reverse proxy that doubles as an AI gateway. Most tools do one or the other; this page is honest about where SBproxy fits and where you should pick something else.

## The short version

| Tool | Type | AI Gateway | General Proxy | Single Binary | Scripting |
|------|------|-----------|---------------|---------------|-----------|
| **SBproxy** | Proxy + AI gateway | Yes (200+ models) | Yes | Yes (Rust) | CEL + Lua + WASM + JS |
| LiteLLM | AI gateway only | Yes (100+ providers) | No | No (Python) | No |
| Portkey | AI gateway (SaaS) | Yes | No | No (Node.js) | No |
| Helicone | AI observability | Proxy + observability | No | No (managed or self-host) | No |
| Kong | API gateway | Yes (plugin) | Yes | Yes (Lua/C) | Lua |
| Caddy | Reverse proxy | No | Yes | Yes | Modules |
| Traefik | Reverse proxy | No | Yes | Yes | Limited |
| Nginx | Reverse proxy | No | Yes | Yes (C) | Lua (OpenResty) |
| Pingora (raw) | Proxy framework | No (DIY) | Yes (DIY) | Library, not a binary | Rust code |
| Envoy | Service mesh proxy | No | Yes | Yes (C++) | WASM |

## When SBproxy is the right choice

SBproxy fits when you need a production reverse proxy *and* an AI gateway in the same traffic layer. Pick it when:

- **You run both kinds of traffic.** HTTP and LLM. Most teams glue Nginx or Traefik together with LiteLLM, Portkey, or a SaaS AI gateway. Two systems to configure, deploy, and monitor. SBproxy is one binary, one config, one place to put policies.
- **You care about overhead.** Sub-millisecond p99 on the proxy path. Idle RSS in single-digit megabytes. LiteLLM wants 4 CPU and 8 GB plus Python, PostgreSQL, and Redis. Managed gateways add a public network hop.
- **You want scripting that ships in the binary.** CEL for routing (compiled once, evaluates in microseconds), Lua for transforms, JavaScript via QuickJS, and sandboxed WebAssembly for plugins. No C modules to compile, no separate plugin daemon.
- **You need MCP federation.** SBproxy proxies and federates Model Context Protocol traffic alongside HTTP and AI. No other general-purpose proxy ships this.
- **You want to self-host without a database.** Single binary. No PostgreSQL. Redis is optional, only needed for distributed rate limiting and shared cache.

## When to pick something else

- **AI-only with maximum provider breadth.** LiteLLM has 100+ native providers and is simpler to set up if HTTP routing isn't part of your problem. Note: its current Business Source License restricts commercial self-hosting.
- **Managed AI gateway, zero ops.** Portkey Cloud or one of the SaaS-only AI gateways (OpenRouter, Cloudflare AI Gateway, Vercel AI Gateway) is worth a look. Those are not on this comparison page because they don't ship as a self-hostable proxy.
- **Pure reverse proxy.** Caddy and Traefik have larger communities and simpler config for the basics. Pingora is the framework underneath SBproxy if you'd rather hand-roll in Rust.

## Detailed comparisons

### vs LiteLLM

LiteLLM is the most popular open-source AI gateway. It supports 100+ LLM providers.
SBproxy reaches 200+ models: 36 OpenAI-compatible providers plus a native Anthropic translator and the OpenRouter aggregator routing 200+ more, alongside a generic OpenAI-compatible adapter for self-hosted or proprietary endpoints.

| | SBproxy | LiteLLM |
|---|---------|---------|
| LLM providers | 200+ models (36 OpenAI-compatible + native Anthropic + OpenRouter + generic adapter) | 100+ native |
| General HTTP proxy | Yes | No |
| Implementation | Compiled native binary | Python |
| Min resources | 1 CPU, 256 MB | 4 CPU, 8 GB |
| Database required | No | PostgreSQL |
| HTTP/3 | Yes | No |
| WebSocket proxy | Yes | No |
| gRPC proxy | Yes | No |
| MCP federation | Yes | No |
| Authentication | 7+ types (JWT, forward auth, digest, ...) | API key |
| Scripting | CEL + Lua + WASM + JS | No |
| Rate limiting | Built-in, distributed | Built-in |
| Response caching | Built-in (memory, file, sled, redis) | 7 backends |
| Guardrails | 7 built-in types (PII, injection, ...) | External integrations |
| P99 proxy overhead | < 1 ms | 240-1200 ms |

Choose LiteLLM if you only need an AI gateway and want the broadest provider coverage out
of the box.

Choose SBproxy if you need a general proxy that also routes AI traffic, or you care about
performance and resource efficiency.

### vs Portkey

Portkey is a managed AI gateway focused on observability and prompt management.

| | SBproxy | Portkey |
|---|---------|---------|
| Deployment | Self-hosted | SaaS (primary) |
| Open source | Full proxy (Apache 2.0) | Gateway component (MIT) |
| General HTTP proxy | Yes | No |
| Response caching | Built-in | Yes |
| Prompt management | No | Yes |
| Cost tracking | Yes (events + budget enforcement) | Yes (dashboard) |

Choose Portkey if you want a managed service with dashboards and prompt management and
don't need a general proxy.

Choose SBproxy if you want to self-host, need a general proxy, or want full control over
your infrastructure.

### vs Helicone

Helicone focuses on AI observability, with a proxy in the path that captures requests for
analytics.

| | SBproxy | Helicone |
|---|---------|---------|
| Primary focus | Proxy + AI gateway | Observability with a proxy in the path |
| General HTTP proxy | Yes | No |
| Self-host | Yes | Yes (managed primary) |
| Caching, guardrails, budgets | Built-in | Caching only |
| Custom transforms and scripting | Yes | No |

Choose Helicone if observability is your sole need.

Choose SBproxy if you want gateway features (routing, fallbacks, budgets, guardrails,
caching) plus observability, or also need a general proxy.

### vs Kong

Kong is a mature API gateway with a large plugin ecosystem. It added AI gateway
capabilities via plugins in 2024.

| | SBproxy | Kong |
|---|---------|------|
| Primary focus | Proxy + AI gateway | API gateway |
| Implementation | Native binary on Pingora | Lua/C (OpenResty) |
| Database | Not required | PostgreSQL (or DB-less mode) |
| AI gateway | Native | Plugin-based |
| Plugin system | CEL + Lua + WASM + JS + registry | Lua plugins |
| HTTP/3 | Yes | No |
| Rate limiting | Built-in, distributed | Plugin |
| Authentication | 7+ built-in types | Plugin-based |
| MCP federation | Yes | No |
| gRPC proxy | Yes | Yes |

Choose Kong if you want a mature API gateway ecosystem with hundreds of community
plugins.

Choose SBproxy if you want native AI gateway features without plugins, HTTP/3 support,
or a lighter deployment footprint.

### vs Caddy

Caddy is a Go reverse proxy known for automatic HTTPS.

| | SBproxy | Caddy |
|---|---------|-------|
| Automatic HTTPS | Yes (ACME via rustls + Let's Encrypt) | Yes (ACME) |
| AI gateway | Yes (200+ models) | No |
| Config format | YAML | Caddyfile or JSON |
| Rate limiting | Built-in, distributed | Community module |
| Scripting | CEL + Lua + WASM + JS | Modules |
| HTTP/3 | Yes | Yes |
| Compression | Gzip, Brotli, Zstd | Gzip, Brotli, Zstd |
| Circuit breaker | Built-in (3-state) | Latency-based |
| Health checks | Active + passive | Active + passive |
| Retries | Configurable with backoff | Configurable |
| PROXY protocol | Yes (v1/v2) | Yes (v1/v2) |
| Service discovery | DNS SRV, Consul | SRV, A/AAAA |
| Load balancing | 12 algorithms | 12+ algorithms |
| WAF | Built-in (OWASP, SQLi, XSS) | Community module |
| DDoS protection | Built-in | No |
| gRPC proxy | Yes | Yes |
| MCP federation | Yes | No |
| Authentication | 7+ built-in types | Community modules |
| Memory model | No garbage collector | Garbage collected |

Caddy and SBproxy overlap heavily on core proxy features. Caddy has a larger community,
deeper static-file support, and simpler config for the simplest cases. SBproxy adds AI
gateway features, more scripting options, no GC pauses, and built-in distributed rate
limiting and DDoS protection.

Choose Caddy if you want the simplest reverse proxy with automatic HTTPS and don't need
AI features or scripting.

Choose SBproxy if you need AI gateway capabilities, programmable scripting, predictable
latency without GC pauses, or built-in rate limiting and caching.

### vs Traefik

Traefik is a cloud-native reverse proxy with automatic service discovery.

| | SBproxy | Traefik |
|---|---------|---------|
| Service discovery | Config-based + DNS | Docker, K8s, Consul |
| AI gateway | Yes | No |
| Middleware | CEL + Lua + WASM + JS + built-in | Declarative chain |
| HTTP/3 | Yes | Experimental |
| Rate limiting | Built-in, distributed | Traefik Hub only (paid) |
| MCP federation | Yes | No |
| Plugin system | CEL + Lua + WASM + JS | WASM/Yaegi |

Choose Traefik if you need automatic service discovery from Docker or Kubernetes labels.

Choose SBproxy if you need AI gateway features, more flexible scripting, or built-in
distributed rate limiting.

### vs Nginx

Nginx is the most widely deployed reverse proxy.

| | SBproxy | Nginx |
|---|---------|-------|
| Config reload | Hot reload (atomic in-process swap) | Worker process restart (graceful, but new process) |
| AI gateway | Yes | No |
| gRPC proxy | Yes | Yes |
| MCP federation | Yes | No |
| Scripting | CEL + Lua + WASM + JS | Lua (OpenResty) / C modules |
| HTTP/3 | Yes | Yes (newer builds) |
| Active health checks | Built-in | NGINX Plus only |
| Dynamic config | Feature flags | NGINX Plus only |
| Static file serving | Not supported (proxy focus) | Excellent |
| Memory model | No garbage collector | Native |

Nginx is hard to beat for static content and simple reverse proxying, and it's likely
already in your stack.

Choose Nginx if you need maximum raw throughput for static content, simple reverse
proxying, or you already have a mature Nginx footprint.

Choose SBproxy if you need AI gateway features, dynamic configuration via feature flags,
or programmable routing without writing Lua or C modules.

### vs Pingora (raw framework)

Pingora is the Cloudflare-built proxy framework that SBproxy is built on. Using Pingora
directly means writing your proxy logic in Rust against its `ProxyHttp` trait.

| | SBproxy | Pingora (direct) |
|---|---------|---------|
| Out-of-the-box config | YAML, hot reload | None, you write Rust |
| Auth, policies, transforms, AI | Built-in | DIY |
| Plugin ecosystem | CEL + Lua + WASM + JS + native | DIY in Rust |
| Operational tooling | Metrics, dashboards, events | DIY |

Choose Pingora directly if you have narrow custom requirements and a team comfortable
maintaining a Rust codebase.

Choose SBproxy if you want the Pingora performance envelope without writing and
maintaining proxy infrastructure yourself.

### vs Envoy

Envoy is a high-performance L4/L7 proxy designed for service mesh deployments.

| | SBproxy | Envoy |
|---|---------|-------|
| Deployment model | Standalone binary | Sidecar or edge (needs control plane) |
| Configuration | YAML file | xDS API (usually via Istio) |
| AI gateway | Yes | No |
| gRPC proxy | Yes | Yes (native) |
| MCP federation | Yes | No |
| Rate limiting | Built-in | External gRPC service |
| Caching | Built-in | No |
| Authentication | 7+ built-in types | External service or filters |
| Extensibility | CEL + Lua + WASM + JS | WASM |

Choose Envoy if you're building a service mesh or need L4 TCP proxying with advanced
traffic management.

Choose SBproxy if you want a standalone proxy with built-in features (rate limiting,
caching, AI gateway) that doesn't require a control plane.

## Summary

SBproxy is a full reverse proxy (like Nginx, Caddy, or Traefik) and an AI gateway (like LiteLLM or Portkey) in one binary, with MCP federation built in. Most teams run two separate systems today. SBproxy collapses them.

Next: the [manual](manual.md), [architecture](architecture.md), [performance](performance.md), or runnable [examples](../examples/).
