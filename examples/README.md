# SBproxy Example Configurations

Complete, working example configurations for SBproxy. Each file is self-contained
and exercises a specific feature area. All examples use `https://test.sbproxy.dev`
as the backend - a real test endpoint that reflects requests and provides mock
AI/MCP/A2A responses.

## Quick Start

```bash
# Start any example
sbproxy serve -f examples/01-basic-proxy.yml

# Test with curl (Host header routes to the right origin)
curl -H "Host: api.example.com" http://localhost:8080/
```

## Test Endpoints

All examples route to `https://test.sbproxy.dev`:

| Path | Description |
|------|-------------|
| `/` | Hello page (HTML, JSON, Markdown) |
| `/echo` | Request echo - returns method, headers, query as JSON |
| `/health` | Health check - returns `{"status":"ok"}` |
| `/slow?ms=1000` | Delayed response (configurable milliseconds) |
| `/status/:code` | Returns any HTTP status code |
| `/v1/chat/completions` | Mock OpenAI chat completions API |
| `/v1/models` | Mock OpenAI model list |
| `/mcp` | Mock MCP server |
| `/a2a` | Mock A2A agent endpoint |

## Examples

| File | Description |
|------|-------------|
| [01-basic-proxy.yml](01-basic-proxy.yml) | Minimal reverse proxy - the simplest possible configuration |
| [02-ai-gateway.yml](02-ai-gateway.yml) | AI gateway with mock OpenAI backend, routing, and rate limiting |
| [03-load-balancer.yml](03-load-balancer.yml) | Load balancer with 3 backends, health checks, round-robin |
| [04-authentication.yml](04-authentication.yml) | All four OSS auth types: api_key, basic_auth, bearer_token, jwt, forward |
| [05-rate-limiting.yml](05-rate-limiting.yml) | Rate limiting with sliding window, response headers, per-endpoint overrides |
| [06-waf-ddos.yml](06-waf-ddos.yml) | WAF with OWASP CRS rules and DDoS protection |
| [07-caching.yml](07-caching.yml) | Response caching with TTL, stale-while-revalidate, cache key params |
| [08-transforms.yml](08-transforms.yml) | JSON projection, HTML minification, Markdown-to-HTML, template rendering |
| [09-scripting.yml](09-scripting.yml) | CEL expression access control and Lua JSON body transformation |
| [10-forwarding-rules.yml](10-forwarding-rules.yml) | Path-based routing: /api/* to API, /health to static, /docs/* to redirect |
| [11-mcp-server.yml](11-mcp-server.yml) | MCP (Model Context Protocol) server with HTTP-backed tools |
| [12-a2a-agent.yml](12-a2a-agent.yml) | A2A (Agent-to-Agent) protocol server with skills |
| [13-security-headers.yml](13-security-headers.yml) | HSTS, CSP, X-Frame-Options, CORS, CSRF, IP filtering |
| [14-compression.yml](14-compression.yml) | Response compression: gzip, brotli, zstd with content negotiation |
| [15-error-pages.yml](15-error-pages.yml) | Custom error pages with Mustache template variables |
| [16-full-production.yml](16-full-production.yml) | Production config combining auth, rate limiting, WAF, caching, compression, security |
| [17-observability.yml](17-observability.yml) | Prometheus metrics, AI token tracking, Grafana dashboard setup |

## Common Patterns

### Run with a specific port

```yaml
proxy:
  http_bind_port: 9090  # Change from default 8080
```

### Use environment variables

```yaml
origins:
  "api.example.com":
    authentication:
      type: api_key
      api_keys:
        - ${MY_SECRET_KEY}  # Reads from environment at startup
```

### Multiple origins in one file

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev/echo

  "static.example.com":
    action:
      type: static
      status_code: 200
      body: "Hello from static origin"
```

### Validate a config without starting the server

```bash
sbproxy validate -c examples/16-full-production.yml
```
