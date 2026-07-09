# Vercel AI SDK with SBproxy

*Last modified: 2026-07-09*

An AI SDK application normally talks to providers directly: the provider package calls `api.openai.com`, and each MCP tool server is a separate connection with its own credentials. Point both sides at an SBproxy you run and every model call and every tool call crosses one gateway you control. That is where virtual keys scope models and attribute spend, budgets meter tokens and dollars, guardrails screen traffic, the usage ledger records what happened, and repeated completions can come back from cache. On the AI SDK side the change is one provider instance with a `baseURL` and one MCP client pointed at the gateway.

The snippets on this page are plain ES modules: save one as `app.mjs` and run it with `node app.mjs`. They work unchanged in a TypeScript project.

## Chat completions through the gateway

SBproxy serves an OpenAI-compatible endpoint at `/v1/chat/completions`, and the `@ai-sdk/openai-compatible` package is the client built for exactly that shape. Its default model type posts to `/v1/chat/completions` and sends your key as a `Bearer` token:

```js
import { generateText } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";

const sbproxy = createOpenAICompatible({
  name: "sbproxy",
  baseURL: "http://127.0.0.1:8080/v1",
  apiKey: "sk-your-virtual-key",
});

const { text } = await generateText({
  model: sbproxy("gpt-4o-mini"),
  prompt: "In one sentence, what does an AI gateway do?",
});
console.log(text);
```

Install the packages with `npm install ai @ai-sdk/openai-compatible`.

`createOpenAI` from `@ai-sdk/openai` also works, with one trap: a bare `openai("gpt-4o-mini")` posts to `/v1/responses`, the OpenAI Responses API, which the gateway does not serve. If you prefer that package, build models with `openai.chat("gpt-4o-mini")`. `createOpenAICompatible` has no such split, which is why this page uses it.

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
      - name: ai-sdk-app
        type: ai_provider
        provider: openai
        key: sk-your-virtual-key
        attrs:
          project: ai-sdk
          tags: [ai-sdk-app]
          budget:
            max_tokens: 1000000
            max_cost_usd: 25
        models:
          allow: [gpt-4o-mini]
```

Origin keys match the `Host` header and hostname matching strips the port, so `"127.0.0.1"` matches a client whose base URL is `http://127.0.0.1:8080`. When the gateway runs elsewhere, key the origin with the hostname your application uses. The real provider key comes from the environment through `${OPENAI_API_KEY}` interpolation; never put a raw provider key in the file.

Be precise about what the virtual key does here. When a request arrives with `Authorization: Bearer sk-your-virtual-key`, the gateway matches it to the `ai-sdk-app` credential, enforces the `models.allow` list (a request for a model outside the list is rejected with 403 before any upstream call), stamps the request with the credential's `project` and `tags` for attribution in metrics and the ledger, and swaps in the real `${OPENAI_API_KEY}` before calling the provider. Your application never holds the provider key. The `attrs.budget` block is attribution metadata that surfaces in the `sbproxy_ai_key_*` metrics; enforced spend ceilings live in an action-level `budget:` block. The virtual key is not inbound authentication by itself either: anyone who can reach the listener and guess a key could present it, so add an `authentication` block to the origin when the gateway is reachable beyond localhost. [ai-gateway.md](ai-gateway.md) covers all of this in depth.

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

Bare hostnames under `federated_servers` are normalised to `https://<host>/mcp`; use a full URL for any other path. Tool names stay bare in the federated catalog by default; each upstream's `prefix` steps in only to disambiguate a clash, when two upstreams advertise the same tool name. An origin key carries one action, so when you want chat completions and MCP behind the same gateway process, give each its own origin keyed by hostname.

The AI SDK's MCP client is `createMCPClient` from the `@ai-sdk/mcp` package (AI SDK 5 shipped the same client as `experimental_createMCPClient` in the `ai` package). Pair it with the streamable HTTP transport from the official `@modelcontextprotocol/sdk`, which speaks exactly what the gateway serves. Install both with `npm install @ai-sdk/mcp @modelcontextprotocol/sdk`.

```js
import { generateText, stepCountIs } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { createMCPClient } from "@ai-sdk/mcp";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const sbproxy = createOpenAICompatible({
  name: "sbproxy",
  baseURL: "http://127.0.0.1:8080/v1",
  apiKey: "sk-your-virtual-key",
});

const mcpClient = await createMCPClient({
  transport: new StreamableHTTPClientTransport(new URL("http://127.0.0.1:8080/")),
});

try {
  const tools = await mcpClient.tools();
  console.log("tools:", Object.keys(tools));

  // The federated catalog drops straight into generateText's tools
  // parameter. The model decides when to call one, the SDK executes it
  // through the MCP client, and the gateway routes the tools/call to
  // the upstream that owns the prefix.
  const answer = await generateText({
    model: sbproxy("gpt-4o-mini"),
    tools,
    stopWhen: stepCountIs(5),
    prompt: "What is the weather in Lisbon?",
  });
  console.log(answer.text);

  // Each tool is also directly executable, which makes a good smoke
  // test. Catalog names can carry an upstream prefix, so look the tool
  // up by suffix.
  const weatherTool =
    tools[Object.keys(tools).find((name) => name.endsWith("get_weather"))];
  const report = await weatherTool.execute(
    { city: "Lisbon" },
    { toolCallId: "smoke-1", messages: [] },
  );
  console.log(report);
} finally {
  await mcpClient.close();
}
```

`tools()` fetches the federated catalog and converts every MCP tool into a standard AI SDK tool, so the rest of your agent code does not know a gateway is involved. `stopWhen: stepCountIs(5)` lets the loop continue past tool results until the model produces its answer. Guardrails such as `tool_allowlist`, per-upstream RBAC, and per-server timeouts from [mcp.md](mcp.md) apply to every call the client makes.

## What the operator gets

With both flows on the gateway, token and dollar budgets live in one config file instead of scattered across applications, and a runaway agent hits a 403 instead of a surprise invoice. Guardrails screen prompts, completions, and tool calls at the choke point, so tightening policy is a config edit rather than a code deploy. Every model call and tool call lands in the hash-chained usage ledger, a tamper-evident record of what each key spent and which tools each agent touched. Response caching answers repeated completions without an upstream call, which pays for itself quickly on eval loops and retries. Details live in [ai-gateway.md](ai-gateway.md) and [mcp.md](mcp.md).
