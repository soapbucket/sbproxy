# Examples

Quick-start configurations for sbproxy. Each example is a self-contained config
you can run immediately. See the [Manual](../docs/manual.md)
for a step-by-step walkthrough.

## Docker Compose Setup

For a full local environment with auto-TLS (via the Pebble ACME test server) and Redis-backed rate limiting, see the [`docker/`](../docker/) directory. The config used by that stack is also available as a standalone example:

| Example | Description | Requirements |
|---------|-------------|-------------|
| [docker-redis-acme.yml](docker-redis-acme.yml) | Auto-TLS via Pebble ACME + Redis rate limiting | Docker Compose stack in `docker/` |

See [`docker/README.md`](../docker/README.md) for startup instructions, how to test certificate issuance, and how to verify Redis-backed rate limiting.

## Proxy Examples

| Example | Description | Test Command |
|---------|-------------|-------------|
| [minimal.yml](minimal.yml) | Simplest reverse proxy | `curl -H "Host: api.example.com" http://localhost:8080/get` |
| [with-auth.yml](with-auth.yml) | API key authentication | `curl -H "Host: api.example.com" -H "X-API-Key: my-secret-key" http://localhost:8080/get` |
| [with-caching.yml](with-caching.yml) | Response caching (5 min TTL) | `curl -H "Host: api.example.com" http://localhost:8080/get` (second request is cached) |
| [with-rate-limiting.yml](with-rate-limiting.yml) | Rate limiting (5 req/min) | Send 6 rapid requests - the 6th returns 429 |
| [with-transforms.yml](with-transforms.yml) | Request/response header injection | `curl -v -H "Host: api.example.com" http://localhost:8080/get` (check response headers) |
| [load-balancer.yml](load-balancer.yml) | Weighted load balancing (70/30) | `curl -H "Host: api.example.com" http://localhost:8080/get` |
| [with-cel-routing.yml](with-cel-routing.yml) | Path-based routing with forward rules | `curl -H "Host: api.example.com" http://localhost:8080/api/users` |
| [with-static-response.yml](with-static-response.yml) | Static JSON responses (no upstream) | `curl -H "Host: api.example.com" http://localhost:8080/` |
| [with-websocket.yml](with-websocket.yml) | WebSocket proxy | `websocat ws://localhost:8080 -H "Host: ws.example.com"` |

## AI Gateway Examples

| Example | Description | Requirements |
|---------|-------------|-------------|
| [ai-proxy.yml](ai-proxy.yml) | AI gateway with OpenAI + Anthropic fallback | `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` env vars |
| [with-scripting.yml](with-scripting.yml) | CEL model routing + guardrail expressions | `OPENAI_API_KEY` env var |
| [with-failure-mode.yml](with-failure-mode.yml) | Fail-open/closed per subsystem | `OPENAI_API_KEY` env var |

## Usage

Run any example:

    sbproxy serve -f examples/minimal.yml

Validate config without starting:

    sbproxy validate -f examples/minimal.yml

With Docker:

    docker run -p 8080:8080 -v $(pwd)/examples/minimal.yml:/etc/sbproxy/sb.yml ghcr.io/soapbucket/sbproxy:latest

For AI examples, pass your API key:

    OPENAI_API_KEY=sk-... sbproxy serve -f examples/ai-proxy.yml

Test the AI gateway with curl:

    curl -X POST http://localhost:8080/v1/chat/completions \
      -H "Host: ai.example.com" \
      -H "Content-Type: application/json" \
      -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'

Or with the OpenAI Python SDK:

    from openai import OpenAI
    client = OpenAI(base_url="http://localhost:8080/v1", api_key="unused")
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Hello"}]
    )
    print(response.choices[0].message.content)

## Next Steps

- [Manual](../docs/manual.md)
- [Configuration Reference](../docs/configuration.md)
- [AI Gateway Guide](../docs/ai-gateway.md)
- [Scripting Guide](../docs/scripting.md)
