# Getting Started

This guide takes you from zero to a running sbproxy in about five minutes.

## Install

### Go install

```bash
go install github.com/soapbucket/sbproxy/cmd/sbproxy@latest
```

### Docker

```bash
docker run -p 8080:8080 \
  -v $(pwd)/sb.yml:/etc/sbproxy/sb.yml \
  ghcr.io/soapbucket/sbproxy:latest
```

### From source

```bash
git clone https://github.com/soapbucket/sbproxy.git
cd sbproxy
make build
# Binary is at ./bin/sbproxy
```

## 1. Your First Proxy

Create a file called `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://httpbin.org
```

Start the proxy:

```bash
sbproxy serve -f sb.yml
```

Test it:

```bash
curl -H "Host: api.example.com" http://localhost:8080/get
```

You should see a JSON response from httpbin.org. Every request to `api.example.com:8080` is now forwarded to `httpbin.org`.

## 2. Add Authentication

Protect your origin with API key authentication. Update `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://httpbin.org
    authentication:
      type: api_key
      api_keys:
        - my-secret-key
```

Restart sbproxy, then test:

```bash
# Rejected (401)
curl -H "Host: api.example.com" http://localhost:8080/get

# Accepted
curl -H "Host: api.example.com" \
     -H "X-API-Key: my-secret-key" \
     http://localhost:8080/get
```

## 3. Add Rate Limiting

Add a rate limit to prevent abuse:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://httpbin.org
    authentication:
      type: api_key
      api_keys:
        - my-secret-key
    policies:
      rate_limiting:
        requests_per_minute: 60
```

Clients exceeding 60 requests per minute receive a `429 Too Many Requests` response with a `Retry-After` header.

## 4. AI Gateway

Route AI requests across providers with automatic fallbacks. Create `ai.yml`:

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
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514]
      default_model: gpt-4o-mini
      routing:
        strategy: fallback_chain
```

Start it:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
sbproxy serve -f ai.yml
```

Use it with the OpenAI Python SDK:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="unused",
    default_headers={"Host": "ai.example.com"},
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)
print(response.choices[0].message.content)
```

If OpenAI is unavailable, sbproxy automatically falls back to Anthropic.

## 5. CEL Routing

Use CEL expressions to route requests dynamically. This example routes mobile clients to a different backend:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "app.example.com":
    action:
      type: proxy
      url: https://default-backend.example.com
    forward_rules:
      - match:
          cel: >
            size(user_agent) > 0 &&
            user_agent['os_family'] in ['iOS', 'Android']
        origin:
          action:
            type: proxy
            url: https://mobile-backend.example.com
```

Mobile users hit `mobile-backend.example.com`. Everyone else hits `default-backend.example.com`.

## 6. Validate Your Config

Check a configuration file for errors without starting the proxy:

```bash
sbproxy validate -c sb.yml
```

This catches syntax errors, invalid field names, and missing required values before you deploy.

## Next Steps

- [AI Gateway Guide](ai-gateway.md) - provider setup, routing strategies, cost tracking
- [Scripting Guide](scripting.md) - CEL and Lua examples for custom logic
- [Events Guide](events.md) - subscribe to proxy events for monitoring
- [Examples](../examples/) - ready-to-use configuration files
