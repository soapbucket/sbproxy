# Mastra with SBproxy

*Last modified: 2026-07-12*

A Mastra agent normally reaches providers directly: the model comes from the AI SDK provider layer and calls `api.openai.com`, and each MCP tool server is a separate connection with its own credentials. Point both sides at an SBproxy you run and every model call and every tool call crosses one gateway you control. That is where virtual keys scope models and attribute spend, budgets meter tokens and dollars, guardrails screen traffic, the usage ledger records what happened, and repeated completions can come back from cache. On the Mastra side the change is a base URL on the model and one server entry for tools.

## Chat completions through the gateway

SBproxy serves an OpenAI-compatible endpoint at `/v1/chat/completions`, and a Mastra `Agent` takes its model straight from the AI SDK provider layer, so `createOpenAI` from `@ai-sdk/openai` works unchanged. Set `baseURL` to the gateway, pass your virtual key as the `apiKey`, and take the model from `.chat()`:

```typescript
// Validated with @mastra/core@1.50.1, @ai-sdk/openai@4.0.10, zod@3.25.76.
// Install: npm install @mastra/core @ai-sdk/openai zod
import { Agent } from "@mastra/core/agent";
import { createOpenAI } from "@ai-sdk/openai";

const openai = createOpenAI({
  baseURL: "http://127.0.0.1:8080/v1",
  apiKey: "sk-your-virtual-key",
});

const agent = new Agent({
  name: "gateway-agent",
  instructions: "You are a concise assistant.",
  model: openai.chat("gpt-4o-mini"),
});

const result = await agent.generate("In one sentence, what does an AI gateway do?");
console.log(result.text);
```

Save it as `agent.mjs` and run `node agent.mjs`. The `.chat()` call is deliberate: the bare form `openai("gpt-4o-mini")` builds a model for OpenAI's Responses API, which the gateway does not serve. `openai.chat("gpt-4o-mini")` speaks `/v1/chat/completions`, the wire format SBproxy translates for every provider it fronts. If you prefer a provider with no OpenAI-specific behavior, `@ai-sdk/openai-compatible` (validated at 3.0.7) works the same way: `createOpenAICompatible({ name: "sbproxy", baseURL, apiKey }).chatModel("gpt-4o-mini")`.

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
      - name: mastra-app
        type: ai_provider
        provider: openai
        key: sk-your-virtual-key
        attrs:
          project: mastra
          tags: [mastra-app]
          budget:
            max_tokens: 1000000
            max_cost_usd: 25
        models:
          allow: [gpt-4o-mini]
```

Origin keys match the `Host` header and hostname matching strips the port, so `"127.0.0.1"` matches a client whose base URL is `http://127.0.0.1:8080`. When the gateway runs elsewhere, key the origin with the hostname your application uses. The real provider key comes from the environment through `${OPENAI_API_KEY}` interpolation; never put a raw provider key in the file.

Be precise about what the virtual key does here. When a request arrives with `Authorization: Bearer sk-your-virtual-key`, the gateway matches it to the `mastra-app` credential, enforces the `models.allow` list (a request for a model outside the list is rejected with 403 before any upstream call), stamps the request with the credential's `project` and `tags` for attribution in metrics and the ledger, and swaps in the real `${OPENAI_API_KEY}` before calling the provider. Your application never holds the provider key. The `attrs.budget` block is attribution metadata that surfaces as attribution labels on the `sbproxy_ai_*_attributed_total` metrics; enforced spend ceilings live in an action-level `budget:` block. The virtual key is not inbound authentication by itself either: anyone who can reach the listener and guess a key could present it, so add an `authentication` block to the origin when the gateway is reachable beyond localhost. [ai-gateway.md](ai-gateway.md) covers all of this in depth.

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

Bare hostnames under `federated_servers` are normalised to `https://<host>/mcp`; use a full URL for any other path. The `prefix` is the server label: by default tool names stay bare in the federated catalog and the label steps in only when two upstreams advertise the same name (the first-listed server keeps the bare name and the later server's tool becomes `orders.get_order_status`). Set `namespace: always` on an entry to prefix everything it exposes. An origin key carries one action, so when you want chat completions and MCP behind the same gateway process, give each its own origin keyed by hostname.

Mastra consumes the gateway through the `MCPClient` in `@mastra/mcp` (validated at 1.13.1), which speaks the streamable HTTP transport the gateway serves. One server entry pointed at the gateway is enough, because the gateway is already the aggregation point:

```typescript
// Install: npm install @mastra/mcp (plus the chat packages above)
import { Agent } from "@mastra/core/agent";
import { createOpenAI } from "@ai-sdk/openai";
import { MCPClient } from "@mastra/mcp";

const mcp = new MCPClient({
  servers: {
    gateway: {
      url: new URL("http://127.0.0.1:8080/"),
    },
  },
});

const tools = await mcp.listTools();
console.log("tools:", Object.keys(tools));

const openai = createOpenAI({
  baseURL: "http://127.0.0.1:8080/v1",
  apiKey: "sk-your-virtual-key",
});

const agent = new Agent({
  name: "gateway-agent",
  instructions: "Use the available tools to answer questions.",
  model: openai.chat("gpt-4o-mini"),
  tools,
});

const reply = await agent.generate("What is the weather in Lisbon?");
console.log(reply.text);

// Tools are ordinary Mastra tools, so you can also call one directly.
// The gateway routes the tools/call to the upstream that owns it.
const weatherKey = Object.keys(tools).find((n) => n.endsWith("get_weather"));
console.log(await tools[weatherKey].execute({ city: "Lisbon" }));

await mcp.disconnect();
```

`listTools()` returns the federated catalog with each tool namespaced by your server entry name, so `get_weather` arrives as `gateway_get_weather`; that is why the lookup above matches on the suffix. Passing the result as `tools:` fixes the catalog when the agent is constructed. To inject tools per request instead, `listToolsets()` groups them by server and `generate()` accepts them per call:

```typescript
const reply = await agent.generate("What is the weather in Lisbon?", {
  toolsets: await mcp.listToolsets(),
});
```

Older `@mastra/mcp` releases named these methods `getTools()` and `getToolsets()`; 1.13 renamed them to `listTools()` and `listToolsets()`. Guardrails such as `tool_allowlist`, per-upstream RBAC, and per-server timeouts from [mcp.md](mcp.md) apply to every call the client makes.

## What the gateway gives you

With both flows on the gateway, you set token and dollar budgets in one place instead of per application, and a runaway agent hits a 403 instead of a surprise invoice. Guardrails screen prompts, completions, and tool calls at the choke point, so a policy change is a config edit rather than a code deploy. Every model call and tool call lands in the hash-chained usage ledger, a tamper-evident record of what each key spent and which tools each agent touched. Response caching serves repeated completions without an upstream call, which is free latency and free money on eval loops and retries. Details live in [ai-gateway.md](ai-gateway.md) and [mcp.md](mcp.md).
