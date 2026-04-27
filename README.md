<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

<h1 align="center">SBproxy</h1>
<h3 align="center">The unified application gateway.</h3>
<p align="center">Simplify your traffic layer. One gateway for every protocol and provider.</p>

> [!IMPORTANT]
> **The Go implementation is archived.** Every commit through `v1.0.0-go-final`
> on this repository is the last release of the Go-based engine. The full Go
> history is preserved at
> [**`soapbucket/sbproxy-go`**](https://github.com/soapbucket/sbproxy-go) for
> reference and reproducibility.
>
> The active implementation will land on this repository as `v2.0.0`, built on
> Cloudflare's Pingora. Background and benchmark numbers behind the migration
> are at [sbproxy.dev/benchmark](https://sbproxy.dev/benchmark). Existing
> `sb.yml` config files run on the new engine unmodified.
>
> If you are pinning a Go-engine release, pin `v1.0.0-go-final` and depend on
> `soapbucket/sbproxy-go`. New issues and pull requests should target the v2
> tree once it lands.

<p align="center">
  <a href="https://github.com/soapbucket/sbproxy/releases"><img src="https://img.shields.io/github/v/release/soapbucket/sbproxy" alt="Release"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml"><img src="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/soapbucket/sbproxy/stargazers"><img src="https://img.shields.io/github/stars/soapbucket/sbproxy" alt="Stars"></a>
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="https://sbproxy.dev/docs">Docs</a> &middot;
  <a href="examples/">Examples</a> &middot;
  <a href="https://github.com/soapbucket/sbproxy/discussions">Community</a> &middot;
  <a href="https://cloud.sbproxy.dev">Cloud</a>
</p>

---

## Why SBproxy

- **One config file** replaces your reverse proxy, AI gateway, and a dozen middleware scripts.
- **Add AI capabilities** to any existing API without changing your backend.
- **Ship secure by default** with authentication, rate limiting, and caching already built in.
- **Reload configuration** without dropping a single connection.

---

## Install

```bash
# Homebrew
brew tap soapbucket/sbproxy && brew install sbproxy

# Docker
docker pull ghcr.io/soapbucket/sbproxy:latest

# Script
curl -fsSL https://download.sbproxy.dev | sh
```

## Quick Start

Create `sb.yml` and run:

```yaml
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://httpbin.org
```

```bash
sbproxy serve -f sb.yml
curl -H "Host: api.example.com" http://localhost:8080/get
```

That's a reverse proxy. Now add AI routing, auth, and rate limiting in the same file:

```yaml
proxy:
  http_bind_port: 8080
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
      routing:
        strategy: fallback_chain
    authentication:
      type: api_key
      api_keys: [my-key]
    policies:
      - type: rate_limiting
        requests_per_minute: 60
```

One config file. Every protocol. Every provider.

See [examples/](examples/) for 17 production-ready configurations.

---

## What Can You Build?

**Reverse proxy** - Route HTTP, WebSocket, gRPC, and GraphQL traffic with path-based forwarding, load balancing, and automatic failover.

**AI gateway** - Route requests across 200+ LLM providers with a single OpenAI-compatible API. Fallback chains, guardrails, spend tracking, and semantic caching.

**API security layer** - Protect any backend with authentication, WAF, rate limiting, DDoS protection, and bot detection. No code changes required.

**Protocol bridge** - Connect HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC, SSE, MCP, and A2A through one unified gateway.

---

## Features

| Area | Capabilities |
|---|---|
| **Traffic** | Reverse proxy, load balancing (10 algorithms), path routing, forwarding rules, WebSocket, gRPC, GraphQL, MCP, A2A |
| **AI** | 200+ providers, OpenAI-compatible API, model fallback chains, guardrails, spend tracking, semantic caching, streaming |
| **Security** | API key, JWT, basic auth, bearer, forward auth, digest auth, WAF, DDoS, IP filtering, CORS, CSRF, bot detection |
| **Performance** | Response caching, compression (gzip, brotli, zstd), hot reload, zero-downtime config updates |
| **Observability** | Structured logging, Prometheus metrics, OpenTelemetry tracing, event bus |
| **Scripting** | CEL expressions, Lua scripting, request/response transforms, template engine |
| **Protocols** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, SSE |

---

## Community

- [Issue Tracker](https://github.com/soapbucket/sbproxy/issues) - bug reports and feature requests
- [Contributing Guide](CONTRIBUTING.md) - how to contribute

Need managed hosting and advanced analytics? See [SBproxy Cloud](https://cloud.sbproxy.dev).

---

## License

Apache 2.0. See [LICENSE](LICENSE). A [Soap Bucket LLC](https://www.soapbucket.org) project.
