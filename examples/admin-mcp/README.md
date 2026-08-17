# Manage SBproxy over MCP

*Last modified: 2026-08-08*

![Manage SBproxy over MCP](../../docs/assets/admin-mcp.gif)

This example turns the gateway's own admin API into MCP tools, so an MCP client such as Claude Code or Cursor can check health, read config, and inspect spend by calling tools instead of shelling out to curl. One process serves both surfaces: the admin API on `127.0.0.1:9090`, and an `mcp` origin on the data plane whose `type: openapi` federated server points back at that admin port.

The OpenAPI spec in `sb.yml` is a hand-declared, curated subset of the admin control plane (the document the admin server emits at `/api/openapi.json` describes the routes the gateway proxies, not the admin API itself). Each declared operation becomes one MCP tool, and each `tools/call` dispatches as a REST request to the admin port with the admin Basic credential attached from the server's static `headers:` entry. The MCP client never holds or sees the credential.

## What's real here

- **Six read-only tools by default**: `sbproxy.get_health`, `sbproxy.get_health_targets`, `sbproxy.get_stats`, `sbproxy.get_spend`, `sbproxy.get_config`, `sbproxy.get_drift`. Each round-trips against the running admin API; `sbproxy.get_health` returns the same JSON `curl -u admin:... http://127.0.0.1:9090/api/health` would.
- **One mutating operation, denied by default**: the spec declares `reload_config` (POST `/admin/reload`), but the `admin_read_only` RBAC policy and the `tool_allowlist` guardrail both exclude it. It is filtered out of `tools/list`, and a direct `tools/call` for it is refused before any request reaches the admin port. See the opt-in section below.

## Run

```bash
make run CONFIG=examples/admin-mcp/sb.yml
```

The demo defaults pair with each other: admin password `admin-mcp-demo` and a matching pre-encoded Basic header. For anything beyond a local demo, export both before starting:

```bash
export SBPROXY_ADMIN_PASSWORD='a-real-password'
export SBPROXY_ADMIN_MCP_BASIC=$(printf 'admin:%s' "$SBPROXY_ADMIN_PASSWORD" | base64)
```

## Try it

```bash
# Start the MCP lifecycle (answered locally by the gateway).
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: localhost' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}' | jq .

# Complete initialization. Sessions are disabled, so no
# Mcp-Session-Id header is needed. Returns HTTP 202.
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:8080 \
  -H 'Host: localhost' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# List the admin-derived tools. Exactly the six read tools appear;
# reload_config is filtered out by the default gates.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: localhost' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq .

# Call one. The gateway sends GET /api/health to its own admin port
# with the Basic credential attached and wraps the admin response as
# MCP tool-result content.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: localhost' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sbproxy.get_health","arguments":{}}}' | jq .

# The declared mutating tool is refused without reaching the admin
# API: the tool_allowlist guardrail blocks it with a JSON-RPC error.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: localhost' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sbproxy.reload_config","arguments":{}}}' | jq .
```

## Connect a client

The origin is keyed on `localhost`, so a local MCP client can connect to `http://localhost:8080/` with no Host tricks.

Claude Code (either form):

```bash
claude mcp add --transport http sbproxy-admin http://localhost:8080/
```

```json
{
  "mcpServers": {
    "sbproxy-admin": {
      "type": "http",
      "url": "http://localhost:8080/"
    }
  }
}
```

Cursor (`.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "sbproxy-admin": {
      "url": "http://localhost:8080/"
    }
  }
}
```

After connecting, the client's tool list shows the six `sbproxy.*` read tools and the agent can call them like any other MCP tool.

## Opting in to mutation

Exposing mutating admin operations to an agent is an explicit, two-step decision. Both gates must agree:

1. Switch the federated server's `rbac: admin_read_only` label to `admin_operator` (declared in the same file; it additionally allows `sbproxy.reload_config`).
2. Add `sbproxy.reload_config` to the `tool_allowlist` guardrail.

Leaving either gate closed keeps the call blocked. The same pattern extends to any other admin route: declare the operation in the spec, then allow its tool name in both places.

## What this exercises

- `action.type: mcp` + `federated_servers[].type: openapi` - the gateway derives MCP tools from an OpenAPI spec and dispatches `tools/call` as REST (see [docs/mcp.md](../../docs/mcp.md#openapi-backed-servers))
- `federated_servers[].headers` - static outbound headers on the OpenAPI REST dispatch, carrying the admin Basic credential from the environment
- `federated_servers[].egress` - `deny_by_default` scoped to `127.0.0.1` with `allow_private: true`, so the only host this server can ever dial is the local admin listener
- `rbac_policies` + `federated_servers[].rbac` - default-deny tool access; the read-only policy is applied, the operator policy is the documented opt-in
- `guardrails[].type: tool_allowlist` - a second, coarser gate that also filters `tools/list`
- `proxy.admin` - the admin server whose API becomes the tool surface

## See also

- [docs/admin-mcp.md](../../docs/admin-mcp.md) - the full walkthrough: each config component, the RBAC scoping, and the security posture
- [docs/admin-api-reference.md](../../docs/admin-api-reference.md) - the per-route admin API reference the spec subset is drawn from
- [docs/mcp.md](../../docs/mcp.md) - wire format, `federated_servers[]` fields, OpenAPI-backed servers
- [examples/mcp-federation](../mcp-federation/) - the general federation example this one specializes
