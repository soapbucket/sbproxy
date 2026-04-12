# SBproxy

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/v/release/soapbucket/sbproxy)](https://github.com/soapbucket/sbproxy/releases)
[![CI](https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml)

A high-performance reverse proxy and AI gateway. One binary, one config file, sub-millisecond overhead.

[Website](https://sbproxy.dev) | [Documentation](https://sbproxy.dev/docs) | [Quick Start](https://sbproxy.dev/docs/quick-start) | [Examples](examples/) | [E2E Tests](e2e/) | [Docs](docs/)

---

## Why SBproxy

Most teams run separate systems for HTTP proxying and AI traffic. SBproxy handles both in a single binary. One YAML config file covers your entire traffic layer: path-based routing, authentication, rate limiting, response caching, AI model routing with fallback chains, content safety guardrails, and more.

- **Single binary** with zero external dependencies. Works without Redis, a database, or a sidecar.
- **Sub-millisecond overhead** via compiled handler chains (no per-request config lookups).
- **200+ native LLM providers** with OpenAI-compatible API. See [docs/providers.md](docs/providers.md).
- **Hot reload** without restarts.

## Install

```bash
# Homebrew
brew tap soapbucket/sbproxy && brew install sbproxy

# Go
go install github.com/soapbucket/sbproxy/cmd/sbproxy@latest

# Docker
docker pull ghcr.io/soapbucket/sbproxy:latest

# Script
curl -fsSL https://download.sbproxy.dev | sh
```

## Quick Start

### Reverse Proxy

```yaml
# sb.yml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

```bash
sbproxy serve -f sb.yml
curl -H "Host: api.example.com" http://localhost:8080/echo
```

### AI Gateway

```yaml
# sb.yml
proxy:
  http_bind_port: 8080

origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini]
      default_model: gpt-4o-mini
      routing:
        strategy: fallback_chain

    authentication:
      type: api_key
      api_keys: [my-key]

    policies:
      - type: rate_limiting
        requests_per_minute: 60
        algorithm: sliding_window
```

```bash
sbproxy serve -f sb.yml

curl -H "Host: ai.example.com" \
     -H "X-API-Key: my-key" \
     -H "Content-Type: application/json" \
     http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

Returns an OpenAI-compatible response regardless of which provider handled the request.

### Production Config

See [examples/16-full-production.yml](examples/16-full-production.yml) for a production-grade configuration combining API key auth, rate limiting, WAF, response caching, compression, CORS, security headers, path-based routing, and custom error pages.

All 16 examples in [examples/](examples/) use [test.sbproxy.dev](https://test.sbproxy.dev) as the backend and work out of the box.

---

## Features

### Routing

| Feature | Description | Docs |
|---|---|---|
| Reverse Proxy | Forward requests to upstream servers with configurable timeouts | [Config](https://sbproxy.dev/docs/config#proxy) |
| Path-Based Routing | Route different paths to different backends via forward rules | [Config](https://sbproxy.dev/docs/config#forward-rules) |
| Load Balancing | 10 algorithms (round-robin, weighted, least-connections, IP hash, and more) with health checks | [Config](https://sbproxy.dev/docs/config#loadbalancer) |
| AI Gateway | OpenAI-compatible API with 200+ native providers, model routing, fallback chains | [AI Docs](https://sbproxy.dev/docs/ai) |
| WebSocket | Full-duplex WebSocket proxying | [Config](https://sbproxy.dev/docs/config#websocket) |
| gRPC | gRPC and gRPC-Web proxying | [Config](https://sbproxy.dev/docs/config#grpc) |
| GraphQL | GraphQL-aware proxying | [Config](https://sbproxy.dev/docs/config#graphql) |
| MCP Server | Model Context Protocol for AI agent tool use | [Config](https://sbproxy.dev/docs/config#mcp) |
| A2A Protocol | Google Agent-to-Agent protocol | [Config](https://sbproxy.dev/docs/config#a2a) |

### Security

| Feature | Description | Docs |
|---|---|---|
| Authentication | API keys, basic auth, bearer tokens, JWT (HS256/RS256/ES256), forward auth, digest | [Auth Docs](https://sbproxy.dev/docs/auth) |
| WAF | OWASP Core Rule Set with paranoia levels 1-4, custom rules | [Security](https://sbproxy.dev/docs/security#waf) |
| Rate Limiting | Sliding window, fixed window, token bucket, leaky bucket. Per-endpoint overrides. | [Config](https://sbproxy.dev/docs/config#rate-limiting) |
| DDoS Protection | Adaptive rate-based detection with block, throttle, or challenge actions | [Security](https://sbproxy.dev/docs/security#ddos) |
| IP Filtering | Allowlist/blocklist with CIDR support and trusted proxy configuration | [Security](https://sbproxy.dev/docs/security#ip-filtering) |
| CORS | Origin allowlist, method/header control, credentials, preflight caching | [Config](https://sbproxy.dev/docs/config#cors) |
| Security Headers | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy | [Security](https://sbproxy.dev/docs/security#headers) |
| CSRF Protection | Token-based CSRF with cookie + header validation | [Security](https://sbproxy.dev/docs/security#csrf) |
| HTTP Signatures | RFC 9421 inbound verification and outbound signing | [Security](https://sbproxy.dev/docs/security#signatures) |
| Bot Detection | Per-origin bot detection with allow/deny lists | [Security](https://sbproxy.dev/docs/security#bot-detection) |
| CEL Expressions | Custom access control via Common Expression Language | [Scripting](https://sbproxy.dev/docs/scripting#cel) |

### Traffic Processing

| Feature | Description | Docs |
|---|---|---|
| Response Caching | TTL, stale-while-revalidate, stale-if-error, cache key customization | [Config](https://sbproxy.dev/docs/config#response-cache) |
| Compression | gzip, brotli, zstd with content-type exclusions | [Config](https://sbproxy.dev/docs/config#compression) |
| Request Modifiers | Header injection, URL rewrite, body replacement with template variables | [Config](https://sbproxy.dev/docs/config#modifiers) |
| Response Modifiers | Response header injection, status override | [Config](https://sbproxy.dev/docs/config#modifiers) |
| Transforms | JSON projection, HTML, Markdown, Lua JSON, template rendering, and 15+ more | [Config](https://sbproxy.dev/docs/config#transforms) |
| Error Pages | Custom error pages with Mustache template rendering | [Config](https://sbproxy.dev/docs/config#error-pages) |
| Webhooks | Lifecycle callbacks (on_load, on_request, on_response) with sync and async modes | [Webhooks](https://sbproxy.dev/docs/webhooks) |
| Session Management | Cookie-based sessions with configurable policies | [Config](https://sbproxy.dev/docs/config#session) |
| Feature Flags | Per-origin behavior overrides via headers or config | [Config](https://sbproxy.dev/docs/config#feature-flags) |
| Lua Scripting | JSON transforms and custom request/response logic | [Scripting](https://sbproxy.dev/docs/scripting#lua) |

### Observability

| Feature | Description | Docs |
|---|---|---|
| Structured Logging | Multi-backend (stderr, ClickHouse) with IP masking and sampling | [Logging](https://sbproxy.dev/docs/logging) |
| Prometheus Metrics | Request latency, throughput, cache hit rates, error rates | [Metrics](https://sbproxy.dev/docs/metrics) |
| OpenTelemetry | Distributed tracing with OTLP export | [Tracing](https://sbproxy.dev/docs/tracing) |
| Events | Publish/subscribe event bus for lifecycle and security events | [Events](https://sbproxy.dev/docs/events) |
| PROXY Protocol | v1/v2 support for L4 load balancer deployments | [Config](https://sbproxy.dev/docs/config#proxy-protocol) |

### Protocol Support

| Protocol | Status |
|---|---|
| HTTP/1.1 | Supported |
| HTTP/2 | Supported (with connection coalescing) |
| HTTP/3 (QUIC) | Supported |
| WebSocket | Supported |
| gRPC | Supported |
| SSE | Supported (streaming) |

---

## Architecture

SBproxy compiles each origin config into an 18-layer handler chain at startup. Requests execute the pre-compiled chain as a function call sequence with zero map lookups or config re-reads.

```
Request -> Global Middleware (14 layers) -> Host Routing (O(1) lookup) -> Origin Chain (18 layers) -> Action
```

Origin handler chain (execution order):

```
AllowedMethods -> ForceSSL -> ErrorPages -> TrafficCapture ->
MessageSignatures -> Session -> ThreatProtection -> BotDetection ->
RateLimitHeaders -> Policies -> OnRequest -> Auth ->
RequestModifiers -> ResponseModifiers -> OnResponse ->
ResponseCache -> Transforms -> Action
```

See [docs/architecture.md](docs/architecture.md) for the full startup flow, request flow, and package map.

## Plugin System

Caddy-style module architecture. Every component registers via `init()` into `pkg/plugin`:

```go
func init() {
    plugin.RegisterAction("my_action", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
        return &myHandler{}, nil
    })
}
```

Five extension points: **ActionHandler**, **AuthProvider**, **PolicyEnforcer**, **TransformHandler**, **RequestEnricher**. New modules implement the interface, register in `init()`, and become available in config. See [docs/architecture.md](docs/architecture.md) for details.

---

## SBproxy Cloud

[cloud.sbproxy.dev](https://cloud.sbproxy.dev) provides enterprise features, managed hosting, and a configuration dashboard.

Enterprise capabilities include canary deployments, traffic shadowing, API versioning, geo-blocking, threat detection, AI guardrails, semantic caching, budget enforcement, WASM plugins, OAuth 2.0, A/B testing, orchestration pipelines, and more.

---

## Documentation

| Resource | Link |
|---|---|
| Full Documentation | [sbproxy.dev/docs](https://sbproxy.dev/docs) |
| Configuration Reference | [sbproxy.dev/docs/config](https://sbproxy.dev/docs/config) |
| AI Gateway Guide | [sbproxy.dev/docs/ai](https://sbproxy.dev/docs/ai) |
| Security Guide | [sbproxy.dev/docs/security](https://sbproxy.dev/docs/security) |
| Scripting (CEL + Lua) | [sbproxy.dev/docs/scripting](https://sbproxy.dev/docs/scripting) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Examples | [examples/](examples/) |
| Comparison | [docs/comparison.md](docs/comparison.md) |

## Contributing

Contributions are welcome. Please open an issue to discuss your idea before submitting a pull request.

```bash
git clone https://github.com/soapbucket/sbproxy.git && cd sbproxy
go build ./... && go test ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

SBproxy is a [Soap Bucket LLC](https://www.soapbucket.org) project.
