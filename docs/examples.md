# Examples

*Last modified: 2026-04-14*

All examples in the `examples/` directory use `test.sbproxy.dev` as the backend
and work out of the box with no changes.

Run any example:
```shell
sbproxy serve -f examples/01-basic-proxy.yml
curl -H "Host: api.example.com" http://localhost:8080/echo
```

## Example index

### examples/01-basic-proxy.yml
**For:** Platform engineers new to sbproxy.
The simplest possible reverse proxy configuration. Use this as a starting point when you want to proxy HTTP traffic to a single upstream.

### examples/02-ai-gateway.yml
**For:** AI platform engineers setting up their first gateway.
Configures sbproxy as an OpenAI-compatible AI gateway with mock provider, routing strategy, and rate limiting. Use this when you want to route LLM requests through sbproxy instead of calling providers directly.

### examples/03-load-balancer.yml
**For:** Platform engineers distributing traffic across multiple backends.
Load balancer with 3 backends, health checks, and round-robin algorithm. Use this when you need to spread requests across multiple upstream instances.

### examples/04-authentication.yml
**For:** Platform and AI platform engineers adding access control.
Demonstrates all OSS auth types: API key, basic auth, bearer token, JWT, and forward auth. Use this as a reference when adding authentication to any origin.

### examples/05-rate-limiting.yml
**For:** Platform engineers protecting upstream services from overload.
Rate limiting with sliding window algorithm, response headers, and per-endpoint overrides. Use this when you need to cap request volume per origin.

### examples/06-waf-ddos.yml
**For:** Platform engineers hardening public-facing services.
WAF with OWASP Core Rule Set and DDoS protection with adaptive rate detection. Use this when exposing services to the internet and you need protection against common attacks.

### examples/07-caching.yml
**For:** Platform engineers reducing upstream load.
Response caching with TTL, stale-while-revalidate, and cache key customization. Use this when upstream responses are cacheable and you want to reduce latency and backend traffic.

### examples/08-transforms.yml
**For:** Platform and AI platform engineers reshaping response bodies.
JSON projection, HTML minification, Markdown-to-HTML conversion, and template rendering. Use this when you need to transform upstream responses before returning them to clients.

### examples/09-scripting.yml
**For:** Platform and AI platform engineers adding custom logic.
CEL expression-based access control and Lua JSON body transformation. Use this when built-in policies and transforms are not flexible enough for your use case.

### examples/10-forwarding-rules.yml
**For:** Platform engineers routing paths to different backends.
Path-based routing: `/api/*` to an API backend, `/health` to a static response, `/docs/*` to a redirect. Use this when a single hostname needs to route different paths to different upstreams.

### examples/11-mcp-server.yml
**For:** AI platform engineers building tool-using agents.
MCP (Model Context Protocol) server with HTTP-backed tools. Use this when you need to expose backend services as MCP tools for AI agents.

### examples/12-a2a-agent.yml
**For:** AI platform engineers building multi-agent systems.
A2A (Agent-to-Agent) protocol server with skill definitions. Use this when you need agents to discover and communicate with each other using Google's A2A protocol.

### examples/13-security-headers.yml
**For:** Platform engineers meeting security compliance requirements.
HSTS, CSP, X-Frame-Options, CORS, CSRF protection, and IP filtering in one config. Use this as a reference when you need to apply defense-in-depth security headers.

### examples/14-compression.yml
**For:** Platform engineers optimizing bandwidth.
Response compression with gzip, brotli, and zstd with content negotiation. Use this when upstream responses are large and clients support compressed responses.

### examples/15-error-pages.yml
**For:** Platform engineers customizing error responses.
Custom error pages with Mustache template variables for status code, method, path, and host. Use this when you want branded or informative error pages instead of default responses.

### examples/16-full-production.yml
**For:** Platform and AI platform engineers building a production deployment.
Production-grade configuration combining API key auth, rate limiting, WAF, response caching, compression, CORS, security headers, path-based routing, and custom error pages. Use this as a starting point for real deployments.

### examples/17-observability.yml
**For:** Platform engineers setting up monitoring.
Prometheus metrics, AI token tracking, and Grafana dashboard configuration. Use this when you need visibility into request volume, latency, cache hit rates, and AI token usage.

---

For production-ready starting configs combining multiple features, start with
`examples/16-full-production.yml`.
