# Pydantic AI with SBproxy

*Last modified: 2026-07-12*

A Pydantic AI agent produces two kinds of outbound traffic: completion calls to a model provider and tool calls to MCP servers. Point both at an SBproxy you run and everything the agent does crosses one gateway you control. That is where virtual keys scope which models an application may use and attribute its spend, budgets meter tokens and dollars, guardrails screen prompts and tool calls, and the usage ledger records what actually happened. On the Pydantic AI side the change is a provider with a different base URL and one toolset entry.

## Chat completions through the gateway

SBproxy serves an OpenAI-compatible endpoint at `/v1/chat/completions`, so Pydantic AI's standard OpenAI model class works unchanged. Build an `OpenAIProvider` with the gateway's base URL and your virtual key, and hand the model to an `Agent`:

```python
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

model = OpenAIChatModel(
    "gpt-4o-mini",
    provider=OpenAIProvider(
        base_url="http://127.0.0.1:8080/v1",
        api_key="sk-your-virtual-key",
    ),
)

agent = Agent(model)

result = agent.run_sync("In one sentence, what does an AI gateway do?")
print(result.output)
```

Install the package with `pip install pydantic-ai`. This page was written against pydantic-ai 2.7.0; releases before 2.0 named the model class `OpenAIModel` rather than `OpenAIChatModel`. Streaming, structured output, and function tools all ride the same OpenAI wire format, so nothing else in your agent changes.

The gateway needs an origin with an `ai_proxy` action and a credential for the virtual key. Save this as `sb.yml` and start the gateway with `sbproxy sb.yml`:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "127.0.0.1":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          default_model: gpt-4o-mini
          models:
            - gpt-4o-mini
    credentials:
      - name: pydantic-ai-app
        type: ai_provider
        provider: openai
        key: sk-your-virtual-key
        attrs:
          project: pydantic-ai
          tags: [pydantic-ai-app]
          budget:
            max_tokens: 1000000
            max_cost_usd: 25
        models:
          allow: [gpt-4o-mini]
```

Origin keys match the `Host` header and hostname matching strips the port, so `"127.0.0.1"` matches a client whose base URL is `http://127.0.0.1:8080/v1`. When the gateway runs elsewhere, key the origin with the hostname your application connects to. The real provider key comes from the environment through `${OPENAI_API_KEY}` interpolation; the file never holds a raw provider secret.

It is worth being precise about what the virtual key does. `OpenAIProvider` sends it as `Authorization: Bearer sk-your-virtual-key`; the gateway matches it to the `pydantic-ai-app` credential, enforces the `models.allow` list (a request for a model outside the list gets a 403 before any upstream call), stamps the request with the credential's `project` and `tags` so metrics and the ledger can attribute usage to this application, and swaps in the real `${OPENAI_API_KEY}` before calling the provider. Your agent never holds the provider key. Two caveats: the `attrs.budget` block is attribution metadata surfaced as attribution labels on the `sbproxy_ai_*_attributed_total` metrics, and enforced spend ceilings belong in an action-level `budget:` block; and the virtual key is not inbound authentication by itself, since anyone who can reach the listener could present a key string, so add an `authentication` block to the origin once the gateway is reachable beyond localhost. [ai-gateway.md](ai-gateway.md) covers both in depth.

## MCP tools through the gateway

SBproxy is also a gateway for the Model Context Protocol, the JSON-RPC protocol agents use to discover and call tools. It aggregates any number of upstream MCP servers behind one endpoint at the origin root: clients send `tools/list` and `tools/call` to the gateway, which federates the catalog, applies guardrails, and routes each call to the upstream that owns the tool.

A minimal `mcp` origin federating two upstream tool servers:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "127.0.0.1":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: gateway-tools
        version: "1.0.0"
      federated_servers:
        - origin: orders.internal
          prefix: orders
        - origin: weather.internal
          prefix: weather
```

Bare hostnames under `federated_servers` are normalised to `https://<host>/mcp`; use a full URL for any other path. Tool names stay bare in the federated catalog by default; each upstream's `prefix` steps in only to disambiguate a clash, when two upstreams advertise the same tool name. One origin key carries one action, so when you want chat completions and MCP behind the same gateway, give each its own origin keyed by hostname.

Pydantic AI connects to MCP servers through `MCPToolset` from `pydantic_ai.mcp` (releases before 2.0 called this `MCPServerStreamableHTTP`). Give it the gateway URL and it speaks the streamable HTTP transport, which is what the gateway serves. One toolset pointed at the gateway is enough, because the gateway is already the aggregation point:

```python
import asyncio

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

gateway = MCPToolset("http://127.0.0.1:8080/")

model = OpenAIChatModel(
    "gpt-4o-mini",
    provider=OpenAIProvider(
        base_url="http://127.0.0.1:8080/v1",
        api_key="sk-your-virtual-key",
    ),
)

agent = Agent(model, toolsets=[gateway])


async def main():
    async with agent:
        # List the federated catalog straight off the gateway.
        tools = await gateway.list_tools()
        print("tools:", sorted(t.name for t in tools))

        # Call one tool directly through the same client.
        out = await gateway.direct_call_tool(
            "get_weather", {"city": "Lisbon"}
        )
        print("direct call:", out)

        # Let the model drive tool use.
        result = await agent.run("What is the weather in Lisbon right now?")
        print("agent:", result.output)


asyncio.run(main())
```

The `agent.run` call reaches a tool only if the model decides to request one, so its output depends on the model you route to. The `list_tools` and `direct_call_tool` lines talk to the gateway regardless of what the model does, which is what makes this snippet a reliable wiring check: if those two lines print your catalog and a tool result, the transport, the federation, and the routing all work. That is also how this page was validated, against a scripted model that never requests tools.

Every call the toolset makes goes through the gateway's controls: `tool_allowlist` guardrails, per-upstream RBAC, and per-server timeouts from [mcp.md](mcp.md) apply whether the tool call came from the model or from `direct_call_tool`.

## What you get at the gateway

Routing both flows through SBproxy buys you, without any further code in the agent:

- Virtual keys with per-application model allow-lists and spend attribution, plus action-level budgets that turn a runaway agent into a 403 instead of an invoice. See [ai-gateway.md](ai-gateway.md).
- Guardrails on prompts, completions, and tool calls at one choke point, so a policy change is a config edit rather than a redeploy.
- A hash-chained usage ledger recording every completion and every `tools/call`, so you can audit what each key spent and which tools each agent touched.
- Response caching, provider fallback, and retry policies on the completion path.
- Tool federation with allow-lists, RBAC, and timeouts on the MCP path. See [mcp.md](mcp.md).
