# LangChain with SBproxy

*Last modified: 2026-08-19*

A LangChain application normally talks to providers directly: `langchain-openai` calls `api.openai.com`, and each tool server is a separate connection with its own credentials. Point both sides at an SBproxy you run and every model call and every tool call crosses one gateway you control. That is where virtual keys scope models and attribute spend, budgets meter tokens and dollars, guardrails screen traffic, the usage ledger records what happened, and repeated completions can come back from cache. On the LangChain side the change is a base URL on the model and one server entry for tools.

## Chat completions through the gateway

SBproxy serves an OpenAI-compatible endpoint at `/v1/chat/completions`, so `ChatOpenAI` from the `langchain-openai` package works unchanged: set `base_url` to the gateway and pass your virtual key as the `api_key`. Save this as `chat.py`:

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

The gateway needs an origin with an `ai_proxy` action and a credential for the virtual key. Save this as `sb.yml`:

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

Origin keys match the `Host` header and hostname matching strips the port, so `"127.0.0.1"` matches a client whose base URL is `http://127.0.0.1:8080`. When the gateway runs on another machine, key the origin with the hostname your application uses.

Two different keys appear across the two files, and you fill in both yourself:

- **The virtual key** (`sk-your-virtual-key`) is a value you invent. It must be identical in two places: `api_key` in `chat.py` and `key:` under `credentials:` in `sb.yml`. Replace the placeholder with your own value in both; [Generating secret values](secrets.md#generating-secret-values) shows how to generate a strong one.
- **The provider key** (`${OPENAI_API_KEY}`) is the real key from your provider's console. It lives only in the environment variable; the gateway reads it through `${OPENAI_API_KEY}` interpolation at startup. Never put a raw provider key in either file.

Be precise about what the virtual key is doing here. When a request arrives with `Authorization: Bearer sk-your-virtual-key`, the gateway matches it to the `langchain-app` credential, enforces the `models.allow` list (a request for a model outside the list is rejected with 403 before any upstream call), stamps the request with the credential's `project` and `tags` for attribution in metrics and the ledger, and swaps in the real `${OPENAI_API_KEY}` before calling the provider. Your application never holds the provider key. The `attrs.budget` block is attribution metadata that surfaces as attribution labels on the `sbproxy_ai_*_attributed_total` metrics; enforced spend ceilings live in an action-level `budget:` block. `action.require_governed_key: true` is what makes any of this enforced rather than declarative: config compile now refuses an origin that declares `credentials:` without it, and with it set, a request presenting an unknown key or no key gets a 401 before any upstream call. The virtual key is still a static bearer secret with no rate limiting on guessing it, so add an `authentication` block to the origin whenever the gateway is reachable beyond localhost. [ai-gateway.md](ai-gateway.md) covers all of this in depth.

## Run it

Use two terminals. In the first, set the provider key, check the config, and start the gateway:

```bash
export OPENAI_API_KEY=sk-proj-...
sbproxy validate sb.yml
sbproxy serve -f sb.yml
```

`validate` compiles the file without booting and fails loud when `${OPENAI_API_KEY}` is unset. `serve` stays in the foreground; startup is done when the log prints `starting sbproxy on 0.0.0.0:8080`.

In the second terminal, run the script:

```bash
python chat.py
```

The model's one-sentence answer prints to the terminal. To check the gateway without Python in the loop, send the same request with curl:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello."}]}'
```

Either way, the request shows up in the gateway's access log, counts against the `langchain-app` credential, and appears in the `sbproxy_ai_*` metrics.

**On Windows**, two of these commands differ in PowerShell:

- `curl` is an alias for `Invoke-WebRequest` there, and it rejects flags like `-H`. Call `curl.exe` explicitly (real curl ships with Windows 10 and later).
- `export` is a Unix shell builtin. Set the provider key with `$env:OPENAI_API_KEY = "sk-proj-..."` instead. When the gateway runs in Docker, pass the variable into the container with `-e OPENAI_API_KEY` or `--env-file secrets.env` on the `docker run` command line. If you write an env file, save it as UTF-8 without a byte order mark: Docker silently ignores every line of the UTF-16 files that Windows PowerShell 5's `>` redirection produces by default.

## Run it without a provider account

The repository ships this page's gateway config as a runnable example in [`examples/langchain/`](../examples/langchain/), with the `openai` provider pointed at a local OpenAI-shaped fixture instead of `api.openai.com`. The virtual key match, the `models.allow` gate, and the provider dispatch all run for real; only the model is canned (it answers `fixture response` and echoes the model name back). Boot it and send the same curl check as above:

```bash
cd examples/langchain
docker compose up -d --wait
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-your-virtual-key' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello."}]}'
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
Date: Sun, 02 Aug 2026 03:43:49 GMT
Connection: keep-alive

{"error":"model 'gpt-4o' is not allowed for this key"}
```

The `chat.py` script above works against the same stack unchanged. `docker compose down -v` tears it down.

## Anthropic and every other provider

`ChatOpenAI` is not tied to OpenAI models. It is a client for the OpenAI wire format, and the gateway speaks that format for every provider it fronts; the translation to each provider's native API happens inside the gateway. The same class drives Claude, Gemini, Mistral, or a local model: declare the provider in the config and request its model by name.

```yaml
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
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models:
            - claude-haiku-4-5
```

```python
llm = ChatOpenAI(
    model="claude-haiku-4-5",
    base_url="http://127.0.0.1:8080/v1",
    api_key="sk-your-virtual-key",
)
```

The gateway routes on the request's `model` field, calls Anthropic's native API upstream, and answers in the OpenAI shape `ChatOpenAI` expects. Add each new model to the credential's `models.allow` list too, or the gateway rejects the request with a 403 before any upstream call.

The gateway also serves Anthropic's native Messages API at `/v1/messages`, so `langchain-anthropic` works without switching classes. Point `ChatAnthropic` at the gateway host with no path suffix; the Anthropic SDK appends `/v1/messages` itself:

```python
from langchain_anthropic import ChatAnthropic

llm = ChatAnthropic(
    model="claude-haiku-4-5",
    base_url="http://127.0.0.1:8080",
    api_key="sk-your-virtual-key",
)
```

Two caveats on the native path. Releases through v1.9.0 answered `/v1/messages` in the OpenAI response shape, which Anthropic clients cannot parse; use a newer release for this path, or stay on `ChatOpenAI`, which works on every version. And the Anthropic SDK presents its key in the `x-api-key` header, which the static `credentials:` block does not read (it reads `Authorization: Bearer`), so on this path the virtual key is ignored; with `require_governed_key: true` set, that means the request gets a 401 instead of dispatching, unless you enable [dynamic key management](key-management.md), whose default header sweep includes `x-api-key`.

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

Bare hostnames under `federated_servers` are normalized to `https://<host>/mcp`; use a full URL for any other path. Tool names stay bare in the federated catalog by default; each upstream's `prefix` steps in only to disambiguate a clash, when two upstreams advertise the same tool name. An origin key can carry one action, so when you want chat completions and MCP behind the same gateway process, give each its own origin keyed by hostname.

The two remaining fields are the gateway's own identity. `mode: gateway` is what puts the origin in federating mode, where the gateway owns the catalog and fans each `tools/call` out to the upstream that holds the tool; `server_info` is the name and version the gateway reports for itself during the `initialize` handshake, which is what MCP clients display when they list their connected servers.

Both `federated_servers` entries above are placeholders. `orders.internal` and `weather.internal` do not resolve, so booting that config as written gives you an empty `tools/list`: the gateway degrades per server, dropping an unreachable upstream with a log line instead of failing the whole catalog. Substitute your own tool servers, or run the federation example below against an upstream that answers.

### Run the MCP half without writing a tool server

[`examples/mcp-federation/`](../examples/mcp-federation/) is the runnable version of the config above, and it ships its own upstream so nothing external has to resolve. Its `gh` entry is a `type: openapi` federated server: the gateway derives MCP tools from an inline OpenAPI spec and dispatches each `tools/call` as an ordinary REST request, so there is no MCP server code anywhere in the example. Its `db` entry is left unresolvable on purpose, so you can watch the per-server degradation described above happen right next to an upstream that works.

It runs as two processes, the mock REST API and the gateway that federates it:

```bash
sbproxy serve -f examples/mcp-federation/upstream.yml &
sbproxy serve -f examples/mcp-federation/sb.yml
```

Every call below is an HTTP POST of a JSON-RPC envelope. The `Accept` header has to offer both `application/json` and `text/event-stream`, because the streamable HTTP transport picks between them per response, and `langchain-mcp-adapters` sends both for you.

This is the federated catalog, the same list `get_tools()` returns:

```
{"description":"Search repositories by query.","inputSchema":{"properties":{"q":{"type":"string"}},"required":["q"],"type":"object"},"name":"gh.search_repos"}
```

One tool, not two, because the `db` upstream never answered. Calling the tool that did register dispatches a real HTTP request to the mock upstream and returns its response as MCP tool-result content:

```
[{"full_name":"soapbucket/sbproxy","name":"sbproxy","stars":4200},{"full_name":"soapbucket/docs","name":"docs","stars":12}]
```

To point the Python client below at this stack, change its URL to `http://127.0.0.1:8080/` with a `Host: mcp.example.com` header and look for `gh.search_repos` instead of `get_weather`. The example's origin is keyed by hostname, so the `Host` header is what selects the MCP origin.

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
