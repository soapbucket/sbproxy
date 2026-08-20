# Pydantic AI with SBproxy

*Last modified: 2026-08-19*

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
      require_governed_key: true
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

It is worth being precise about what the virtual key does. `OpenAIProvider` sends it as `Authorization: Bearer sk-your-virtual-key`; the gateway matches it to the `pydantic-ai-app` credential, enforces the `models.allow` list (a request for a model outside the list gets a 403 before any upstream call), stamps the request with the credential's `project` and `tags` so metrics and the ledger can attribute usage to this application, and swaps in the real `${OPENAI_API_KEY}` before calling the provider. Your agent never holds the provider key. Two caveats: the `attrs.budget` block is attribution metadata surfaced as attribution labels on the `sbproxy_ai_*_attributed_total` metrics, and enforced spend ceilings belong in an action-level `budget:` block; and `action.require_governed_key: true` (now required by config compile whenever `credentials:` is set) is what makes the key check enforced rather than declarative, rejecting an unknown or missing key with a 401 before any upstream call. The key itself is still a static bearer secret with no rate limiting on guessing it, so add an `authentication` block to the origin once the gateway is reachable beyond localhost. [ai-gateway.md](ai-gateway.md) covers both in depth.

## Run it without a provider account

The repository ships this page's gateway config as a runnable example in [`examples/pydantic-ai/`](../examples/pydantic-ai/), with the `openai` provider pointed at a local OpenAI-shaped fixture instead of `api.openai.com`. The virtual key match, the `models.allow` gate, and the provider dispatch all run for real; only the model is canned (it answers `fixture response` and echoes the model name back). Boot it and send the curl equivalent of what `OpenAIProvider` puts on the wire:

```bash
cd examples/pydantic-ai
docker compose up -d --wait
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"In one sentence, what does an AI gateway do?"}]}'
```

```
{
  "id": "chatcmpl-fixture",
  "object": "chat.completion",
  "created": 0,
  "model": "gpt-4o-mini",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "fixture response"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 1,
    "completion_tokens": 1,
    "total_tokens": 2
  }
}
```

Ask for a model outside the credential's allow list and the gateway refuses before any upstream call:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Try the expensive model."}]}'
```

```
HTTP/1.1 403 Forbidden
content-type: application/json
content-length: 54
Date: Sun, 02 Aug 2026 03:43:51 GMT
Connection: keep-alive

{"error":"model 'gpt-4o' is not allowed for this key"}
```

The Pydantic AI snippet above works against the same stack unchanged. `docker compose down -v` tears it down.

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

Bare hostnames under `federated_servers` are normalized to `https://<host>/mcp`; use a full URL for any other path. Tool names stay bare in the federated catalog by default; each upstream's `prefix` steps in only to disambiguate a clash, when two upstreams advertise the same tool name. One origin key carries one action, so when you want chat completions and MCP behind the same gateway, give each its own origin keyed by hostname.

The two remaining fields are the gateway's own identity. `mode: gateway` is what puts the origin in federating mode, where the gateway owns the catalog and fans each `tools/call` out to the upstream that holds the tool; `server_info` is the name and version the gateway reports for itself during the `initialize` handshake, which is what MCP clients display when they list their connected servers.

Both `federated_servers` entries above are placeholders. `orders.internal` and `weather.internal` do not resolve, so booting that config as written gives you an empty `tools/list`: the gateway degrades per server, dropping an unreachable upstream with a log line instead of failing the whole catalog. Substitute your own tool servers, or run the federation example below against an upstream that answers.

### Run the MCP half without writing a tool server

[`examples/mcp-federation/`](../examples/mcp-federation/) is the runnable version of the config above, and it ships its own upstream so nothing external has to resolve. Its `gh` entry is a `type: openapi` federated server: the gateway derives MCP tools from an inline OpenAPI spec and dispatches each `tools/call` as an ordinary REST request, so there is no MCP server code anywhere in the example. Its `db` entry is left unresolvable on purpose, so you can watch the per-server degradation described above happen right next to an upstream that works.

It runs as two processes, the mock REST API and the gateway that federates it:

```bash
sbproxy serve -f examples/mcp-federation/upstream.yml &
sbproxy serve -f examples/mcp-federation/sb.yml
```

Every call below is an HTTP POST of a JSON-RPC envelope. The `Accept` header has to offer both `application/json` and `text/event-stream`, because the streamable HTTP transport picks between them per response, and `MCPToolset` sends both for you.

This is the federated catalog, the same list `gateway.list_tools()` returns:

```
{"description":"Search repositories by query.","inputSchema":{"properties":{"q":{"type":"string"}},"required":["q"],"type":"object"},"name":"gh.search_repos"}
```

One tool, not two, because the `db` upstream never answered. Calling the tool that did register dispatches a real HTTP request to the mock upstream and returns its response as MCP tool-result content, which is what `direct_call_tool` hands back:

```
[{"full_name":"soapbucket/sbproxy","name":"sbproxy","stars":4200},{"full_name":"soapbucket/docs","name":"docs","stars":12}]
```

To point the script below at this stack, build the toolset against `http://127.0.0.1:8080/` with a `Host: mcp.example.com` header and call `direct_call_tool("gh.search_repos", {"q": "sbproxy"})` instead of the weather tool. The example's origin is keyed by hostname, so the `Host` header is what selects the MCP origin.

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
