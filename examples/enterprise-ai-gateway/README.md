# Enterprise AI gateway

*Last modified: 2026-07-29*

This credential-free example grows one SBproxy process from a conventional
API gateway into a gateway for API, MCP, and AI traffic. Every request in the
walkthrough stays on the local machine. The fixed fixture on port 8091 returns
a valid OpenAI-compatible chat completion, so the three paths are repeatable
without a provider key, container runtime, GPU, or outbound provider request.

SBproxy currently binds its data listener to all host interfaces. Run this
example on a trusted development machine or behind a host firewall, and stop
both processes when you finish. The commands below connect through
`127.0.0.1`.

## Start the local fixture

In the first terminal, start the fixed JSON service:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/upstream.yml
```

The fixture accepts connections on port `8091`; this walkthrough reaches it
at `127.0.0.1:8091`. Keep it running while you try each gateway stage below.

## Stage 1: API

![A conventional API request passing through SBproxy](../../docs/assets/enterprise-ai-gateway-api.gif)

In a second terminal:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/api.yml
```

Then send a conventional HTTP request:

```bash
curl -s -H 'Host: api.example.com' http://127.0.0.1:8080/status | jq .
```

The response contains `"gateway": "sbproxy"`. Stop this gateway with
Ctrl-C before starting the next stage. Leave the fixture running.

The `proxy.extensions.upstream.allow_private_cidrs` block explicitly permits
this example's loopback API target. Keep the default private-network block for
public upstreams, and allow only the internal CIDRs your deployment owns.

## Stage 2: MCP

![An OpenAPI contract exposed as an MCP tool](../../docs/assets/enterprise-ai-gateway-mcp.gif)

Start the API plus MCP configuration:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/mcp.yml
```

Initialize the MCP client:

```bash
curl -s http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}' \
  | jq .
```

Complete the initialization lifecycle:

```bash
curl -s -o /dev/null -w 'initialized: HTTP %{http_code}\n' \
  http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

This example leaves the optional MCP `sessions` block disabled, so the
gateway stays stateless and does not issue an `Mcp-Session-Id`. Initialization
is still part of the MCP lifecycle.

Now list the tool derived from the inline OpenAPI document:

```bash
curl -s http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | jq .
```

The result contains `local.gateway_status`. Call it:

```bash
curl -s http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"local.gateway_status","arguments":{}}}' \
  | jq .
```

The tool result contains `sbproxy`. Stop this gateway before the final stage.

## Stage 3: API, MCP, and AI

![An OpenAI-compatible chat completion through the final gateway](../../docs/assets/enterprise-ai-gateway-ai.gif)

Start the complete configuration:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/sb.yml
```

The API and MCP requests above still work. The third origin accepts an
OpenAI-compatible chat request:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.example.com' \
  -H 'Content-Type: application/json' \
  -d '{"model":"local-demo","messages":[{"role":"user","content":"Say hello."}]}' \
  | jq .
```

The response has `"object": "chat.completion"` and a non-empty
`choices[0].message.content`.

Stop both SBproxy processes with Ctrl-C when you are finished.
