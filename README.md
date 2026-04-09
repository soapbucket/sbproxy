# sbproxy

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/v/release/soapbucket/sbproxy)](https://github.com/soapbucket/sbproxy/releases)
[![CI](https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml)

A high-performance reverse proxy and AI gateway in a single binary.

**Website:** [www.soapbucket.com](https://www.soapbucket.com) | **Docs:** [www.soapbucket.com/docs](https://www.soapbucket.com/docs) | **Examples:** [examples/](examples/)

## Install

```bash
brew tap soapbucket/sbproxy
brew install sbproxy
```

Or with Go:

```bash
go install github.com/soapbucket/sbproxy/cmd/sbproxy@latest
```

Or Docker:

```bash
docker pull ghcr.io/soapbucket/sbproxy:latest
```

## What it does

Most teams run separate systems for HTTP proxying (Nginx, Traefik) and AI traffic (LiteLLM, Portkey). sbproxy handles both. One config file covers your entire traffic layer, from path-based routing to model fallback chains. Single Go binary, sub-millisecond overhead, 103 native LLM providers, zero external dependencies.

## API Proxy

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

## AI Gateway

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
          models: [gpt-4o, gpt-4o-mini]
      default_model: gpt-4o-mini
```

```bash
OPENAI_API_KEY=sk-... sbproxy serve -f sb.yml

curl -H "Host: ai.example.com" http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

sbproxy returns an OpenAI-compatible response regardless of which provider handled the request.

## Key features

- **Reverse proxy** with path-based routing, host matching, and WebSocket/gRPC support
- **AI gateway** with 103+ native providers (OpenAI, Anthropic, Google, and more)
- **Load balancing** - round-robin, weighted, least-connections
- **Authentication** - API keys, JWT, OAuth2, mTLS
- **Response caching** with stale-while-revalidate
- **Rate limiting** - local and distributed via Redis
- **Scripting** - CEL expressions and Lua for custom logic
- **HTTP/3** with QUIC
- **Observability** - Prometheus metrics and OpenTelemetry tracing

Looking for WAF, DDoS protection, semantic caching, virtual keys, or budget enforcement? See [SOAPBUCKET Cloud](https://www.soapbucket.com).

## Documentation

[Manual](docs/manual.md) | [Configuration](docs/configuration.md) | [Architecture](docs/architecture.md) | [Scripting](docs/scripting.md) | [AI Gateway](docs/ai-gateway.md) | [Comparison](docs/comparison.md) | [www.soapbucket.com/docs](https://www.soapbucket.com/docs)

## Docker

The `docker/` directory includes a Compose stack with sbproxy, Redis, and a local ACME server for testing automatic TLS.

```bash
docker compose -f docker/docker-compose.yml up --build
```

See [docker/README.md](docker/README.md) for the full setup guide.

## Contributing

Contributions are welcome. Please open an issue to discuss your idea before submitting a pull request.

```bash
git clone https://github.com/soapbucket/sbproxy.git && cd sbproxy
go build ./... && go test ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

sbproxy is a [Soap Bucket LLC](https://www.soapbucket.org) project. SOAPBUCKET and sbproxy are trademarks of Soap Bucket LLC.
