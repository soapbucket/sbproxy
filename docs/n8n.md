# n8n with SBproxy

*Last modified: 2026-07-12*

n8n workflows normally talk to model providers directly: you paste an OpenAI key into a credential and every AI Agent run calls `api.openai.com`. Point that credential at an SBproxy you run instead, and every workflow run crosses one gateway you control. That is where virtual keys scope models and attribute spend, budgets meter tokens and dollars, guardrails screen traffic, the usage ledger records what happened, and repeated completions can come back from cache. n8n is configured through its UI rather than code, so this page walks through the fields to fill in and the exact values to type, on both sides of the wire.

## Chat models through the gateway

SBproxy serves an OpenAI-compatible endpoint at `/v1/chat/completions`, and n8n's OpenAI credential has a Base URL field. Changing that one field routes the OpenAI Chat Model node, and every AI Agent built on it, through the gateway. You do not need a custom node.

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
      - name: n8n
        type: ai_provider
        provider: openai
        key: sk-your-virtual-key
        attrs:
          project: n8n
          tags: [n8n]
          budget:
            max_tokens: 1000000
            max_cost_usd: 25
        models:
          allow: [gpt-4o-mini]
```

Origin keys match the `Host` header and hostname matching strips the port, so `"127.0.0.1"` matches a client whose base URL is `http://127.0.0.1:8080`. When the gateway runs on another machine, key the origin with the hostname n8n will dial. The real provider key comes from the environment through `${OPENAI_API_KEY}` interpolation; never put a raw provider key in the file.

Be precise about what the virtual key does. When a request arrives with `Authorization: Bearer sk-your-virtual-key`, the gateway matches it to the `n8n` credential, enforces the `models.allow` list (a request for a model outside the list is rejected with 403 before any upstream call), stamps the request with the credential's `project` and `tags` for attribution in metrics and the ledger, and swaps in the real `${OPENAI_API_KEY}` before calling the provider. n8n never holds the provider key. The `attrs.budget` block is attribution metadata that surfaces as attribution labels on the `sbproxy_ai_*_attributed_total` metrics; enforced spend ceilings live in an action-level `budget:` block. The virtual key is not inbound authentication by itself either: anyone who can reach the listener and guess a key could present it, so add an `authentication` block to the origin when the gateway is reachable beyond localhost. [ai-gateway.md](ai-gateway.md) covers all of this in depth.

### Verify the gateway side

Before opening n8n, send the request its OpenAI Chat Model node will send:

```console
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Authorization: Bearer sk-your-virtual-key' \
    -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi in one sentence."}]}' \
  | jq -r '.choices[0].message.content'
```

A one-line greeting back means the whole path works: key matched, model allowed, provider reached. A 403 naming the model means it is missing from the credential's `models.allow` list, which is the scoping doing its job.

### Create the OpenAI credential in n8n

1. From the n8n home screen, open the Credentials tab and add a new credential. You can also create one later from inside the model node's credential selector.
2. Search for and pick OpenAI. This is the credential type the OpenAI Chat Model node uses.
3. In API Key, enter `sk-your-virtual-key`, exactly the string from the `key:` line in `sb.yml`.
4. Leave Organization ID empty. It exists for accounts that belong to several OpenAI organizations and means nothing to the gateway.
5. In Base URL, replace the default `https://api.openai.com/v1` with `http://127.0.0.1:8080/v1`.
6. Save. n8n tests the credential with a model-list request to the Base URL. SBproxy answers `GET /v1/models` on `ai_proxy` origins, so a passing test proves n8n reached your gateway, not OpenAI.

If n8n runs in Docker and the gateway runs on the host, `127.0.0.1` inside the container is the container itself. Use `http://host.docker.internal:8080/v1` as the Base URL and key the origin `"host.docker.internal"` in `sb.yml`.

### Select it on an OpenAI Chat Model node

1. Create a workflow and add the When chat message received trigger.
2. Add an AI Agent node after it. On the canvas the agent exposes three sockets underneath: Chat Model, Memory, and Tool.
3. Click the plus on the Chat Model socket and pick OpenAI Chat Model.
4. Open the node. In the credential selector at the top of its settings (labeled Credential to connect with), choose the credential you created.
5. In Model, pick `gpt-4o-mini`. The dropdown is filled by a model-list call to your Base URL, so it shows what the gateway config exposes. If the list fails to load (an origin fronting a non-OpenAI provider passes the upstream's native list format through), switch the Model field from its list mode to its ID mode and type `gpt-4o-mini`.
6. Open the chat panel and send a message. The reply crossed the gateway: the run is attributed to the `n8n` key (its `api_key_id` label on the `sbproxy_ai_*_attributed_total` metrics) and the usage ledger, and the same completion asked twice can come back from cache.

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
        name: sbproxy-gateway
        version: "1.0.0"
      federated_servers:
        - origin: orders.internal
          prefix: orders
        - origin: weather.internal
          prefix: weather
```

Bare hostnames under `federated_servers` are normalised to `https://<host>/mcp`; use a full URL for any other path. Tool names stay bare in the federated catalog by default; each upstream's `prefix` steps in only to disambiguate a clash, when two upstreams advertise the same tool name. An origin key carries one action, so to run chat completions and MCP behind the same gateway process, give each its own origin keyed by hostname.

### Verify the gateway side

n8n's MCP client opens the session with `initialize`, then fetches the catalog with `tools/list`. Send both by hand first:

```console
$ curl -s -X POST http://127.0.0.1:8080/ \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"n8n-mcp-client","version":"1.0.0"}}}'
{"jsonrpc":"2.0","result":{"capabilities":{"tools":{"listChanged":true}},"protocolVersion":"2025-06-18","serverInfo":{"name":"sbproxy-gateway","version":"1.0.0"}},"id":1}

$ curl -s -X POST http://127.0.0.1:8080/ \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | jq -r '.result.tools[].name'
get_order_status
get_weather
```

The `serverInfo` in the first response echoes your config, and the second lists the federated catalog drawn from both upstreams. If both answers come back, the gateway side is done.

### Attach the MCP Client Tool node

n8n ships an MCP Client Tool node for AI Agent workflows (since n8n 1.88; use a current release so the streamable transport option is present):

1. In the AI Agent workflow from above, click the plus on the agent's Tool socket and pick MCP Client Tool.
2. In the node's endpoint URL field, enter `http://127.0.0.1:8080/`. In current builds this field sits at the top of the node parameters next to the transport selector and is labeled Endpoint; older builds label it SSE Endpoint.
3. Set the transport selector (labeled Server Transport) to HTTP Streamable.
4. Leave Authentication set to None for the config above. The node also offers bearer and header credentials for when you put authentication in front of the origin.
5. Leave Tools to Include on All. The agent now sees `get_order_status` and `get_weather` and calls them through the gateway, subject to whatever `tool_allowlist` guardrails, RBAC, and per-server timeouts the origin defines.

The connection also works in the other direction: n8n's MCP Server Trigger node exposes the workflows you wire to it as an MCP server (the node's Path field and its production URL give you the endpoint), and you can federate that into the gateway as one more entry so every MCP client behind the gateway gets n8n's workflows as tools, with the `n8n` prefix stepping in if a workflow's tool name clashes with another upstream's:

```yaml
      federated_servers:
        - origin: https://n8n.internal.example.com/mcp/order-tools
          prefix: n8n
```

## What every workflow run gets

With chat models and tools both on the gateway, token and dollar budgets live in one place instead of per workflow, and a runaway agent gets refused at the gateway instead of showing up on an invoice. Guardrails screen prompts, completions, and tool calls at the choke point, so a policy change is a config edit rather than a workflow edit. Every model call and tool call lands in the hash-chained usage ledger, a tamper-evident record of what each key spent and which tools each agent touched. Response caching serves repeated completions without an upstream call, which matters in n8n because the same workflow runs on every trigger fire. Details live in [ai-gateway.md](ai-gateway.md) and [mcp.md](mcp.md).
