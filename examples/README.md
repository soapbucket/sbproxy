# Examples

Quick-start configurations for sbproxy. Each example is a self-contained config you can run immediately.

## Run Any Example

```bash
sbproxy serve -f examples/minimal.yml
```

Validate without starting:

```bash
sbproxy validate -f examples/minimal.yml
```

## Proxy Examples

### minimal.yml - Simplest Reverse Proxy

```bash
sbproxy serve -f examples/minimal.yml
curl -H "Host: api.example.com" http://localhost:8080/get
```

### with-auth.yml - API Key Authentication

```bash
sbproxy serve -f examples/with-auth.yml

# Without key (returns 401)
curl -H "Host: api.example.com" http://localhost:8080/get

# With key
curl -H "Host: api.example.com" -H "X-API-Key: my-secret-key" http://localhost:8080/get
```

### with-caching.yml - Response Caching

```bash
sbproxy serve -f examples/with-caching.yml

# First request hits backend
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i x-cache
# Second request served from cache
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i x-cache
```

### with-rate-limiting.yml - Rate Limiting

```bash
sbproxy serve -f examples/with-rate-limiting.yml

# Send 6 requests (limit is 5/min, the 6th returns 429)
for i in $(seq 1 6); do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: api.example.com" http://localhost:8080/get)
  echo "Request $i: $code"
done
```

### with-transforms.yml - Header Injection

```bash
sbproxy serve -f examples/with-transforms.yml
curl -v -H "Host: api.example.com" http://localhost:8080/get 2>&1 | grep -i "x-proxy\|x-request"
```

### load-balancer.yml - Weighted Load Balancing

```bash
sbproxy serve -f examples/load-balancer.yml

# Run multiple times to see weighted distribution
for i in $(seq 1 10); do
  curl -s -H "Host: api.example.com" http://localhost:8080/get | grep -o '"url":"[^"]*"'
done
```

### with-cel-routing.yml - Path-Based Routing

```bash
sbproxy serve -f examples/with-cel-routing.yml

curl -H "Host: api.example.com" http://localhost:8080/api/users
curl -H "Host: api.example.com" http://localhost:8080/api/orders
curl -H "Host: api.example.com" http://localhost:8080/anything-else
```

### with-static-response.yml - Static JSON Response

```bash
sbproxy serve -f examples/with-static-response.yml
curl -H "Host: api.example.com" http://localhost:8080/
```

### with-websocket.yml - WebSocket Proxy

```bash
sbproxy serve -f examples/with-websocket.yml
websocat ws://localhost:8080 -H "Host: ws.example.com"
```

## AI Gateway Examples

Requires provider API keys. See [examples/ai/README.md](ai/README.md) for detailed instructions.

### ai-proxy.yml - Multi-Provider AI Gateway

```bash
OPENAI_API_KEY=sk-... ANTHROPIC_API_KEY=sk-ant-... sbproxy serve -f examples/ai-proxy.yml

curl -H "Host: ai.example.com" http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

### with-scripting.yml - CEL Model Routing + Guardrails

```bash
OPENAI_API_KEY=sk-... sbproxy serve -f examples/with-scripting.yml

curl -H "Host: ai.example.com" http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Tier: premium" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

### with-failure-mode.yml - Fail-Open/Closed

```bash
OPENAI_API_KEY=sk-... sbproxy serve -f examples/with-failure-mode.yml

curl -H "Host: ai.example.com" http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

## More Examples

| Directory | Description |
|-----------|-------------|
| [ai/](ai/) | AI gateway configs: single provider, multi-provider, fallback, cost routing, guardrails |
| [api/](api/) | API proxy configs: JWT auth, caching, rate limiting, transforms, microservice routing |

## OpenAI SDK Compatibility

All AI examples return OpenAI-compatible responses:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="unused")
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
    extra_headers={"Host": "ai.example.com"}
)
print(response.choices[0].message.content)
```

## Docker

```bash
docker run -p 8080:8080 \
  -v $(pwd)/examples/minimal.yml:/etc/sbproxy/sb.yml \
  ghcr.io/soapbucket/sbproxy:latest
```

For the full stack with Redis, Prometheus, Grafana, and Jaeger, see [docker/README.md](../docker/README.md).

## Documentation

[Manual](../docs/manual.md) | [Configuration](../docs/configuration.md) | [AI Gateway](../docs/ai-gateway.md) | [Scripting](../docs/scripting.md)
