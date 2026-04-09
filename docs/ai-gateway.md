# AI Gateway Guide

sbproxy provides a unified AI gateway that sits between your application and LLM providers. It gives you a single API endpoint with automatic failover, cost tracking, rate limits, and programmable routing across OpenAI, Anthropic, and other providers.

## Provider Setup

Configure one or more providers under the `action` block. Each provider needs a name, API key, and model list:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini, gpt-4-turbo]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514, claude-3-5-haiku-20241022]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
```

API keys support environment variable interpolation with `${VAR_NAME}` syntax. Never put raw keys in config files.

## Routing Strategies

The `routing.strategy` field controls how sbproxy selects a provider for each request.

### round_robin

Distributes requests evenly across all healthy providers. Good default for load distribution.

```yaml
routing:
  strategy: round_robin
```

### weighted

Assigns a weight to each provider. Higher weight means more traffic.

```yaml
routing:
  strategy: weighted
```

### fallback_chain

Tries providers in order. If the first fails, tries the second, and so on. Best for reliability.

```yaml
routing:
  strategy: fallback_chain
  fallback_order: [openai, anthropic]
  retry:
    max_attempts: 3
```

### cost_optimized

Routes to the provider with the most available token capacity. Providers with `max_tokens_per_minute` configured are scored by remaining capacity and utilization. This favors cheaper, less-loaded providers. Falls back to provider priority order when no token limits are set.

```yaml
routing:
  strategy: cost_optimized
```

### lowest_latency

Routes to the provider with the lowest observed latency based on recent request history.

```yaml
routing:
  strategy: lowest_latency
```

### least_connections

Routes to the provider with the fewest in-flight requests.

```yaml
routing:
  strategy: least_connections
```

### sticky

Pins a user or session to the same provider for consistency. Falls back to round_robin for initial selection.

```yaml
routing:
  strategy: sticky
```

### semantic

Classifies the request content and routes to a provider/model based on the classification label.

```yaml
routing:
  strategy: semantic
  semantic_routes:
    default_confidence: 0.7
    routes:
      coding:
        provider: anthropic
        model: claude-sonnet-4-20250514
        min_confidence: 0.8
      general:
        provider: openai
        model: gpt-4o-mini
```

## Fallbacks and Retries

Configure retry behavior for transient failures:

```yaml
routing:
  strategy: fallback_chain
  fallback_order: [openai, anthropic]
  retry:
    max_attempts: 3
```

When a provider returns a 5xx error or times out, sbproxy retries with the next provider in the fallback order. The response includes an `X-SBProxy-Provider` header so you know which provider ultimately handled the request.

## Context Window Validation

sbproxy validates that the request fits within the model's context window before sending it to the provider. If a request is too large, sbproxy can automatically fall back to a model with a larger context window.

```yaml
routing:
  strategy: fallback_chain
  context_window_margin: 0.05  # 5% safety margin (default)
  context_fallbacks:
    gpt-4o: gpt-4-turbo
    claude-sonnet-4-20250514: claude-sonnet-4-20250514
```

The `context_window_margin` reserves a percentage of the context window for the response. If the input tokens plus the margin exceed the model's limit, sbproxy checks `context_fallbacks` for a larger-context alternative.

## Rate Limits

Apply rate limits per client or globally to control costs and prevent abuse:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
    policies:
      rate_limiting:
        requests_per_minute: 100
```

Clients exceeding the limit receive a `429 Too Many Requests` response with a `Retry-After` header.

## CEL Selectors

Use CEL expressions in the routing config for dynamic per-request decisions. These are compiled once at config load time.

### Model selector

Override the requested model based on request context:

```yaml
routing:
  strategy: round_robin
  model_selector: >
    request.headers['x-priority'] == 'high'
      ? 'gpt-4o'
      : 'gpt-4o-mini'
```

### Provider selector

Route to a specific provider based on request context:

```yaml
routing:
  provider_selector: >
    size(location) > 0 && location['country_code'] == 'EU'
      ? 'anthropic'
      : 'openai'
```

### Cache bypass

Skip the response cache for certain requests:

```yaml
routing:
  cache_bypass: >
    request.headers['x-no-cache'] == 'true'
```

### Dynamic RPM

Override the rate limit for specific clients:

```yaml
routing:
  dynamic_rpm: >
    request.headers['x-tier'] == 'premium' ? 1000 : 100
```

## Lua Hooks

Use Lua scripts for more complex routing logic. Lua hooks run in a sandboxed environment with access to request context variables.

Example: route coding questions to Anthropic based on message content analysis:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
    request_modifiers:
      lua:
        script: |
          local path = request.path
          if string.find(path, "/code") then
            return {
              add_headers = {
                ["X-Preferred-Provider"] = "anthropic"
              }
            }
          end
          return {}
```

## CEL Guardrails

Block or modify AI requests based on content rules using CEL expressions:

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
      default_model: gpt-4o-mini
      routing:
        strategy: round_robin
    policies:
      rate_limiting:
        requests_per_minute: 100
    request_modifiers:
      cel:
        - expression: >
            request.headers['x-department'] == ''
              ? {"set_headers": {"X-Block": "true"}}
              : {}
```

## Cost Headers

sbproxy tracks token usage and estimated cost for every AI request. The response includes headers with usage details:

| Header | Description |
|--------|-------------|
| `X-SBProxy-Provider` | Which provider handled the request |
| `X-SBProxy-Model` | Which model was used |
| `X-SBProxy-Tokens-In` | Input token count |
| `X-SBProxy-Tokens-Out` | Output token count |
| `X-SBProxy-Cost` | Estimated cost in USD |

These headers let you build dashboards, track spending, and allocate costs to internal teams without modifying your application code.

## Streaming

sbproxy fully supports streaming responses. When your client sends a streaming request (e.g., `"stream": true` in the OpenAI API), sbproxy:

1. Validates the request (auth, rate limits, guardrails).
2. Selects a provider using the configured routing strategy.
3. Opens a streaming connection to the provider.
4. Forwards SSE chunks to the client as they arrive.
5. Tracks token usage from the final chunk for cost headers.

No special configuration is needed. Streaming works with all routing strategies and all providers.

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="unused",
    default_headers={"Host": "ai.example.com"},
)

stream = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Write a haiku about proxies."}],
    stream=True,
)
for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="")
```

## Full Example

Putting it all together - an AI gateway with two providers, fallback routing, rate limits, context validation, and CEL-based model selection:

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
          models: [gpt-4o, gpt-4o-mini, gpt-4-turbo]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514, claude-3-5-haiku-20241022]
      default_model: gpt-4o-mini
      routing:
        strategy: fallback_chain
        fallback_order: [openai, anthropic]
        retry:
          max_attempts: 3
        context_window_margin: 0.05
        context_fallbacks:
          gpt-4o: gpt-4-turbo
        model_selector: >
          request.headers['x-priority'] == 'high'
            ? 'gpt-4o'
            : 'gpt-4o-mini'
    authentication:
      type: api_key
      api_keys:
        - ${AI_GATEWAY_KEY}
    policies:
      rate_limiting:
        requests_per_minute: 200
```
