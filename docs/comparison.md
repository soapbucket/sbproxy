# How SBproxy Compares

*Last modified: 2026-04-14*

> **Open-source vs Enterprise:** Features marked *(enterprise)* are available
> in sbproxy Cloud. Everything else ships in the open-source binary.

SBproxy is a reverse proxy that also works as an AI gateway. Most tools do
one or the other. This page explains where sbproxy fits and when you might
choose something else.

## The Short Version

| Tool | Type | AI Gateway | General Proxy | Single Binary | Scripting |
|------|------|-----------|---------------|---------------|-----------|
| **sbproxy** | Proxy + AI gateway | Yes (100+ providers) | Yes | Yes (Go) | CEL + Lua |
| LiteLLM | AI gateway only | Yes (100+ providers) | No | No (Python) | No |
| Portkey | AI gateway (SaaS) | Yes | No | No (Node.js) | No |
| Kong | API gateway | Yes (plugin) | Yes | Yes (Lua/C) | Lua |
| Caddy | Reverse proxy | No | Yes | Yes (Go) | Go modules |
| Traefik | Reverse proxy | No | Yes | Yes (Go) | Limited |
| Nginx | Reverse proxy | No | Yes | Yes (C) | Lua (OpenResty) |
| Envoy | Service mesh proxy | No | Yes | Yes (C++) | WASM |

## When to choose sbproxy

SBproxy is the right choice when you need both a production-grade reverse proxy and
an AI gateway in the same traffic layer. If you only need one or the other, there are
tools that specialize:

- **Only need an AI gateway with no HTTP routing?** LiteLLM is simpler to start with,
  though note its current Business Source License restricts commercial self-hosting.
- **Only need a reverse proxy with no AI features?** Traefik or Caddy are mature and
  have larger communities.
- **Need a managed platform with no self-hosting?** Portkey Cloud is worth evaluating.

SBproxy's advantage is the unified traffic layer: one config file, one binary, one
set of policies that apply to both your API traffic and your AI model traffic. Apache 2.0,
no usage restrictions.

**You need a proxy AND an AI gateway.** Most teams run Nginx/Traefik for HTTP
traffic and LiteLLM/Portkey for LLM traffic. That's two systems to configure,
deploy, and monitor. sbproxy handles both in one binary.

**You want low overhead.** sbproxy is a compiled Go binary. Sub-millisecond proxy
overhead. 256 MB RAM minimum. LiteLLM requires Python + PostgreSQL + Redis
(4 CPU, 8 GB recommended). Portkey is a SaaS with network round-trips.

**You want scripting without a heavy plugin system.** CEL expressions for
routing decisions (compiled once, evaluates in microseconds). Lua scripts for
request/response transformation. No WASM compilation, no C modules, no Yaegi
interpreter.

**You need MCP or A2A protocol support.** sbproxy natively proxies Model
Context Protocol (MCP) and Agent-to-Agent (A2A) traffic alongside regular
HTTP and AI requests. No other general-purpose proxy supports these protocols.

**You want to self-host everything.** Single binary, no external database
required. Redis optional (for distributed rate limiting). Compare to Kong
(requires PostgreSQL) or LiteLLM (requires PostgreSQL + optionally Redis).

## Detailed Comparisons

### vs LiteLLM

LiteLLM is the most popular open-source AI gateway. It supports 100+ LLM
providers. sbproxy matches that with 100+ native providers in its registry,
plus any additional OpenAI-compatible API via the generic provider.

| | sbproxy | LiteLLM |
|---|---------|---------|
| LLM providers | 100+ native | 100+ native |
| General HTTP proxy | Yes | No |
| Language | Go | Python |
| Min resources | 1 CPU, 256 MB | 4 CPU, 8 GB |
| Database required | No | PostgreSQL |
| HTTP/3 | Yes | No |
| WebSocket proxy | Yes | No |
| gRPC proxy | Yes | No |
| MCP / A2A protocols | Yes | No |
| Authentication | 8 types (JWT, forward auth, digest, ...) | API key |
| Scripting | CEL + Lua | No |
| Authentication | 8 built-in types (JWT, forward auth, digest, ...) | API key |
| Rate limiting | Built-in, distributed | Built-in |
| Response caching | Built-in | 7 backends |
| Guardrails | CEL expressions | External integrations |
| MCP / A2A protocols | Yes | No |
| GraphQL proxy | Yes | No |
| P99 proxy overhead | < 1 ms | 240-1200 ms |

**Choose LiteLLM if** you only need an AI gateway and want maximum provider
coverage out of the box.

**Choose sbproxy if** you need a general proxy that also routes AI traffic,
or you care about performance and resource efficiency.

### vs Portkey

Portkey is a managed AI gateway focused on observability and prompt management.

| | sbproxy | Portkey |
|---|---------|---------|
| Deployment | Self-hosted | SaaS (primary) |
| Open source | Full proxy (Apache 2.0) | Gateway component (MIT) |
| General HTTP proxy | Yes | No |
| Response caching | Built-in | Yes |
| Prompt management | No | Yes |
| Cost tracking | Yes (events) | Yes (dashboard) |

**Choose Portkey if** you want a managed service with dashboards and prompt
management and don't need a general proxy.

**Choose sbproxy if** you want to self-host, need a general proxy, or want
full control over your infrastructure.

### vs Kong

Kong is a mature API gateway with a large plugin ecosystem. It added AI
gateway capabilities via plugins in 2024.

| | sbproxy | Kong |
|---|---------|------|
| Primary focus | Proxy + AI gateway | API gateway |
| Language | Go | Lua/C (OpenResty) |
| Database | Not required | PostgreSQL (or DB-less mode) |
| AI gateway | Native | Plugin-based |
| Plugin system | CEL + Lua + registry | Lua plugins |
| HTTP/3 | Yes | No |
| Rate limiting | Built-in, distributed | Plugin |
| Authentication | 8 built-in types | Plugin-based |
| MCP / A2A protocols | Yes | No |
| gRPC proxy | Yes | Yes |

**Choose Kong if** you need a mature API gateway ecosystem with hundreds of
community plugins.

**Choose sbproxy if** you want native AI gateway features without plugins,
HTTP/3 support, or a lighter deployment footprint.

### vs Caddy

Caddy is a modern Go reverse proxy known for automatic HTTPS.

| | sbproxy | Caddy |
|---|---------|-------|
| Automatic HTTPS | Yes (ACME) | Yes (ACME) |
| AI gateway | Yes (100+ providers) | No |
| Config format | YAML | Caddyfile or JSON |
| Rate limiting | Built-in, distributed | Community module |
| Scripting | CEL + Lua | Go modules |
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
| MCP / A2A protocols | Yes | No |
| Authentication | 8 built-in types | Community modules |
| Plugin system | CEL + Lua, WASM *(enterprise)* | Go modules (compile-time) |

**Choose Caddy if** you want the simplest possible reverse proxy with
automatic HTTPS and don't need AI features or scripting.

**Choose sbproxy if** you need AI gateway capabilities, CEL/Lua scripting,
or built-in rate limiting and caching.

### vs Traefik

Traefik is a cloud-native reverse proxy with automatic service discovery.

| | sbproxy | Traefik |
|---|---------|---------|
| Service discovery | Config-based | Docker, K8s, Consul |
| AI gateway | Yes | No |
| Middleware | CEL + Lua + built-in | Declarative chain |
| HTTP/3 | Yes | Experimental |
| Rate limiting | Built-in, distributed | Enterprise (Hub) |
| MCP / A2A protocols | Yes | No |
| Plugin system | CEL + Lua | WASM/Yaegi |

**Choose Traefik if** you need automatic service discovery from Docker or
Kubernetes labels.

**Choose sbproxy if** you need AI gateway features, more flexible scripting,
or built-in distributed rate limiting.

### vs Nginx

Nginx is the most widely deployed reverse proxy.

| | sbproxy | Nginx |
|---|---------|-------|
| Config reload | Hot reload | Requires reload signal |
| AI gateway | Yes | No |
| gRPC proxy | Yes | Yes |
| MCP / A2A protocols | Yes | No |
| Scripting | CEL + Lua | Lua (OpenResty) / C modules |
| HTTP/3 | Yes | Yes (newer builds) |
| Active health checks | Built-in | NGINX Plus only |
| Dynamic config | Feature flags | NGINX Plus only |

**Choose Nginx if** you need maximum raw throughput for static content or
simple reverse proxying.

**Choose sbproxy if** you need AI gateway features, dynamic configuration
via feature flags, or CEL-based routing without writing Lua.

### vs Envoy

Envoy is a high-performance L4/L7 proxy designed for service mesh deployments.

| | sbproxy | Envoy |
|---|---------|-------|
| Deployment model | Standalone binary | Sidecar or edge (needs control plane) |
| Configuration | YAML file | xDS API (usually via Istio) |
| AI gateway | Yes | No |
| gRPC proxy | Yes | Yes (native) |
| MCP / A2A protocols | Yes | No |
| Rate limiting | Built-in | External gRPC service |
| Caching | Built-in | No |
| Authentication | 8 built-in types | External service or filters |
| Extensibility | CEL + Lua | WASM |

**Choose Envoy if** you're building a service mesh or need L4 TCP proxying
with advanced traffic management.

**Choose sbproxy if** you want a standalone proxy with built-in features
(rate limiting, caching, AI gateway) that doesn't require a control plane.

## Summary

sbproxy occupies a unique position: it's a **full reverse proxy** (like Nginx,
Caddy, or Traefik) that's also a **native AI gateway** (like LiteLLM or
Portkey) with support for emerging protocols like **MCP** and **A2A**. Most
teams currently run two separate systems for these use cases. sbproxy replaces
both with a single binary.

For more details, see the [Manual](manual.md) or browse the [examples](../examples/).
