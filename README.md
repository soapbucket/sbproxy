# sbproxy

A high-performance, programmable reverse proxy and AI gateway.

sbproxy sits between your clients and backends, giving you authentication, caching, rate limiting, request/response transforms, load balancing, and AI model routing in a single binary with zero external dependencies.

## Features

- **Reverse proxy** with path-based routing and host matching
- **AI gateway** - unified API across OpenAI, Anthropic, and other providers with fallback chains, cost routing, and usage tracking
- **Load balancing** - round-robin, weighted, and least-connections algorithms
- **Authentication** - API keys, basic auth, JWT validation, and OAuth2
- **Response caching** - in-memory and Redis-backed with TTL and stale-while-revalidate
- **Rate limiting** - per-client and per-origin with sliding window counters
- **Request/response transforms** - header injection, body rewriting, JSON field projection
- **WAF** - built-in web application firewall with configurable rulesets
- **Programmable** - CEL expressions and Lua scripting for custom logic
- **Observability** - structured logging, Prometheus metrics, health checks

## Quick Start

### Binary

```bash
# Download the latest release
curl -fsSL https://github.com/soapbucket/sbproxy/releases/latest/download/sbproxy-$(uname -s)-$(uname -m).tar.gz | tar xz

# Run with a config file
./sbproxy serve -f examples/minimal.yml
```

### Docker

```bash
docker run -p 8080:8080 \
  -v $(pwd)/sb.yml:/etc/sbproxy/sb.yml \
  ghcr.io/soapbucket/sbproxy:latest
```

### From Source

```bash
git clone https://github.com/soapbucket/sbproxy.git
cd sbproxy
go build -o sbproxy ./cmd/sbproxy
./sbproxy serve -f examples/minimal.yml
```

## Minimal Configuration

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://httpbin.org
```

This proxies all requests to `api.example.com:8080` through to `httpbin.org`. See the [examples/](examples/) directory for more configurations including authentication, caching, AI proxying, and load balancing.

## Documentation

- [Examples](examples/) - ready-to-use configuration files
- [Configuration Reference](docs/PROXY_CONFIG.md) - full config field reference
- [Proxy Manual](docs/PROXY_MANUAL.md) - detailed usage guide

## SoapBucket Cloud

Need managed infrastructure, a dashboard, team collaboration, and enterprise support? [SoapBucket Cloud](https://www.soapbucket.com) runs sbproxy for you with:

- Web-based configuration UI
- Real-time analytics and monitoring
- Automatic TLS certificate management
- Team access controls and audit logs
- 99.9% uptime SLA

Visit [soapbucket.com](https://www.soapbucket.com) to get started.

## Contributing

Contributions are welcome. Please open an issue to discuss your idea before submitting a pull request.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

SoapBucket and sbproxy are trademarks of SoapBucket, Inc. See [TRADEMARKS.md](TRADEMARKS.md).
