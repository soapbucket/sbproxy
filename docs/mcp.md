# MCP gateway

*Last modified: 2026-05-09*

SBproxy ships an MCP (Model Context Protocol) gateway that speaks
JSON-RPC 2.0 over HTTP POST. Configure it as the origin's action and
the proxy serves the canonical MCP method set: `initialize`,
`tools/list`, `tools/call`, and `ping`. Federated upstream MCP servers
contribute their tool catalogues through the embedded
[`McpFederation`] module.

This document covers the operator-facing surface. Buyer-facing MCP
discussion lives in [`features.md`](features.md).

## Wire shape

```
POST /  HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "method": "initialize",
  "id": 1,
  "params": {}
}
```

`initialize` returns the server identity, the protocol version
(`2025-06-18`), and the capability advertisement.

## Capabilities

The `initialize` response includes:

- `tools` - present when the registry has at least one tool registered.
- `resources` - reserved; absent in the OSS build.
- `prompts` - reserved; absent in the OSS build.
- `experimental` - non-stable capability advertisements; see below.

### `experimental.agentSkillsUrl` (WOR-195)

When the origin has `agent_skills:` configured, the proxy advertises
the absolute URL of the origin's
`/.well-known/agent-skills/index.json` manifest under
`capabilities.experimental.agentSkillsUrl`. MCP clients that have
learned to fetch and verify the manifest discover skills without
out-of-band configuration.

```json
{
  "result": {
    "protocol_version": "2025-06-18",
    "capabilities": {
      "tools": {},
      "experimental": {
        "agentSkillsUrl": "https://api.example.com/.well-known/agent-skills/index.json"
      }
    },
    "server_info": { "name": "sbproxy-mcp", "version": "1.0" }
  }
}
```

The advertised path is the same for anonymous and authenticated
callers; the manifest itself filters by visibility at serve time. When
`agent_skills:` is not configured, the field is omitted entirely. See
[`agent-skills.md`](agent-skills.md) for the manifest format and the
integrity contract.

## See also

- [`agent-skills.md`](agent-skills.md) - manifest schema, integrity,
  archive safety.
- [`features.md`](features.md) - tour of the MCP gateway in context.
- [`scripting.md`](scripting.md) - CEL / Lua / JS / WASM hooks that
  shape MCP requests.
