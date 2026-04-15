# SBproxy

**The reverse proxy and AI gateway, unified.**

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Release](https://img.shields.io/github/v/release/soapbucket/sbproxy)](https://github.com/soapbucket/sbproxy/releases) [![CI](https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml)

Most teams run nginx or Traefik for HTTP traffic, then route AI requests through a separate LiteLLM or Portkey instance. SBproxy handles both in a single Go binary. One config file covers your entire traffic layer.

[Website](https://sbproxy.dev) | [Docs](https://sbproxy.dev/docs) | [Quick Start](https://sbproxy.dev/docs/quick-start) | [Examples](examples/)

---
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
---
## Quick Start
### Reverse proxy
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
### AI gateway
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
curl -H "Host: ai.example.com" -H "X-API-Key: my-key" -H "Content-Type: application/json" \
     http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```
Returns an OpenAI-compatible response regardless of which provider handled it. See [examples/16-full-production.yml](examples/16-full-production.yml) for a production config with auth, WAF, caching, and routing combined.

---
## Why SBproxy
- **One binary, zero dependencies.** No Redis, no database, no sidecar required.
- **Sub-millisecond overhead.** Compiled handler chains with zero per-request config lookups.
- **Full HTTP stack.** Path routing, load balancing, WAF, rate limiting, JWT, gRPC, WebSocket, MCP, A2A.
- **200+ native LLM providers.** OpenAI-compatible API. Model fallback chains, guardrails, semantic caching, budget enforcement.
- **Hot reload** without restarts or dropped connections.

See [docs/comparison.md](docs/comparison.md) for a side-by-side with LiteLLM, Portkey, Traefik, and Kong.

---
## Features
| Area | What's included |
|---|---|
| **Routing** | Reverse proxy, path-based forwarding, load balancing (10 algorithms), AI gateway (200+ providers), WebSocket, gRPC, GraphQL, MCP, A2A |
| **Security** | API key, basic auth, bearer, JWT, forward auth, digest auth, WAF (OWASP CRS), DDoS protection, IP filtering, CORS, CSRF, HTTP signatures, bot detection, CEL expressions |
| **Traffic** | Response caching (TTL, SWR, SIE), compression (gzip, brotli, zstd), request/response modifiers, 15+ transforms, error pages, webhooks, session management, feature flags, Lua scripting |
| **Observability** | Structured logging, Prometheus metrics, OpenTelemetry tracing, event bus, PROXY protocol |
| **Protocols** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, SSE streaming |

Full reference at [sbproxy.dev/docs](https://sbproxy.dev/docs).

---
## Architecture
SBproxy compiles each origin config into an 18-layer handler chain at startup. Requests execute the pre-compiled chain with zero map lookups or config re-reads.
```
Request -> Global Middleware (14 layers) -> Host Routing (O(1) lookup) -> Origin Chain (18 layers) -> Action
```
Handler chain (execution order):
```
AllowedMethods -> ForceSSL -> ErrorPages -> TrafficCapture -> MessageSignatures -> Session ->
ThreatProtection -> BotDetection -> RateLimitHeaders -> Policies -> OnRequest -> Auth ->
RequestModifiers -> ResponseModifiers -> OnResponse -> ResponseCache -> Transforms -> Action
```
See [docs/architecture.md](docs/architecture.md) for full startup flow, request lifecycle, and package map.

---
## SBproxy Cloud
[cloud.sbproxy.dev](https://cloud.sbproxy.dev) provides managed hosting, a configuration dashboard, and enterprise capabilities including canary deployments, geo-blocking, AI guardrails, orchestration pipelines, and more.

---
## Contributing
```bash
git clone https://github.com/soapbucket/sbproxy.git && cd sbproxy
go build ./... && go test ./...
```
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
## License
Apache 2.0. See [LICENSE](LICENSE). A [Soap Bucket LLC](https://www.soapbucket.org) project.
