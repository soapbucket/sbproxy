# LangChain with SBproxy

*Last modified: 2026-07-12*

A LangChain application normally talks to providers directly: `langchain-openai` calls `api.openai.com`, and each tool server is a separate connection with its own credentials. Point both sides at an SBproxy you run and every model call and every tool call crosses one gateway you control. That is where virtual keys scope models and attribute spend, budgets meter tokens and dollars, guardrails screen traffic, the usage ledger records what happened, and repeated completions can come back from cache. On the LangChain side the change is a base URL on the model and one server entry for tools.

## Chat completions through the gateway

SBproxy serves an OpenAI-compatible endpoint at `/v1/chat/completions`, so `ChatOpenAI` from the `langchain-openai` package works unchanged. Set `base_url` to the gateway and pass your virtual key as the `api_key`:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    base_url="http://127.0.0.1:8080/v1",
    api_key="sk-your-virtual-key",
)

reply = llm.invoke("In one sentence, what does an AI gateway do?")
print(reply.content)
```

Install the package with `pip install langchain-openai`. Streaming, `bind_tools`, structured output, and every other `ChatOpenAI` feature ride the same wire format, so nothing else in your chains changes.

The gateway needs an origin with an `ai_proxy` action and a credential for the virtual key. Save this as `sb.yml`, export `OPENAI_API_KEY`, and start the gateway with `sbproxy sb.yml` (`sbproxy validate sb.yml` checks the file without booting, and fails loud if the variable is unset):

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
      - name: langchain-app
        type: ai_provider
        provider: openai
        key: sk-your-virtual-key
        attrs:
          project: langchain
          tags: [langchain-app]
          budget:
            max_tokens: 1000000
            max_cost_usd: 25
        models:
          allow: [gpt-4o-mini]
```

Origin keys match the `Host` header and hostname matching strips the port, so `"127.0.0.1"` matches a client whose base URL is `http://127.0.0.1:8080`. When the gateway runs on another machine, key the origin with the hostname your application uses. The real provider key comes from the environment through `${OPENAI_API_KEY}` interpolation; never put a raw provider key in the file.

Be precise about what the virtual key is doing here. When a request arrives with `Authorization: Bearer sk-your-virtual-key`, the gateway matches it to the `langchain-app` credential, enforces the `models.allow` list (a request for a model outside the list is rejected with 403 before any upstream call), stamps the request with the credential's `project` and `tags` for attribution in metrics and the ledger, and swaps in the real `${OPENAI_API_KEY}` before calling the provider. Your application never holds the provider key. The `attrs.budget` block is attribution metadata that surfaces as attribution labels on the `sbproxy_ai_*_attributed_total` metrics; enforced spend ceilings live in an action-level `budget:` block. The virtual key is not inbound authentication by itself either: a request presenting an unknown key, or no key at all, still passes through on the provider's configured key, so add an `authentication` block to the origin whenever the gateway is reachable beyond localhost. [ai-gateway.md](ai-gateway.md) covers all of this in depth.

## MCP tools through the gateway

SBproxy is also a gateway for the Model Context Protocol (MCP), the JSON-RPC protocol agents use to discover and call tools. The gateway aggregates any number of upstream MCP servers behind one endpoint: clients POST JSON-RPC requests such as `tools/list` and `tools/call` to the origin root, and the gateway federates the catalog, applies guardrails, and routes each call to the upstream that owns the tool.

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

Bare hostnames under `federated_servers` are normalised to `https://<host>/mcp`; use a full URL for any other path. Tool names stay bare in the federated catalog by default; each upstream's `prefix` steps in only to disambiguate a clash, when two upstreams advertise the same tool name. An origin key can carry one action, so when you want chat completions and MCP behind the same gateway process, give each its own origin keyed by hostname.

LangChain consumes the gateway through the `langchain-mcp-adapters` package (`pip install langchain-mcp-adapters`, which also pulls in the `mcp` SDK and `httpx`). Its `MultiServerMCPClient` speaks the streamable HTTP transport, which is exactly what the gateway serves. One server entry pointed at the gateway is enough, because the gateway is already the aggregation point.

Two practical notes: do not name your script `mcp.py`, because that shadows the `mcp` package the adapters import, and `get_tools()` is a coroutine, so the client lives in async code.

```python
import asyncio

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI


async def main():
    client = MultiServerMCPClient(
        {
            "gateway": {
                "transport": "streamable_http",
                "url": "http://127.0.0.1:8080/",
            }
        }
    )
    tools = await client.get_tools()
    print("tools:", sorted(tool.name for tool in tools))

    # Bind the federated catalog to a model that also talks through
    # the gateway, then hand llm_with_tools to your agent loop or
    # langgraph graph as usual.
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        base_url="http://127.0.0.1:8080/v1",
        api_key="sk-your-virtual-key",
    )
    llm_with_tools = llm.bind_tools(tools)

    # Tools are ordinary LangChain tools, so you can also invoke one
    # directly. The gateway routes the tools/call to the upstream
    # that owns it.
    get_weather = next(t for t in tools if t.name.endswith("get_weather"))
    print(await get_weather.ainvoke({"city": "Lisbon"}))


asyncio.run(main())
```

`get_tools()` fetches the federated catalog and converts every MCP tool into a standard LangChain tool, so the rest of your agent code does not know a gateway is involved. Guardrails such as `tool_allowlist`, per-upstream RBAC, and per-server timeouts from [mcp.md](mcp.md) apply to every call the client makes.

## What the operator gets

With both flows on the gateway, you set token and dollar budgets in one place instead of per application, and a runaway agent hits a 403 instead of a surprise invoice. Guardrails screen prompts, completions, and tool calls at the choke point, so a policy change is a config edit rather than a code deploy. Every model call and tool call lands in the hash-chained usage ledger, giving you a tamper-evident record of what each key spent and which tools each agent touched. Response caching serves repeated completions without an upstream call, which is free latency and free money on eval loops and retries. Details live in [ai-gateway.md](ai-gateway.md) and [mcp.md](mcp.md).
