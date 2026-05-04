# MCP gateway with federated upstreams

*Last modified: 2026-04-27*

The `mcp` action turns SBproxy into a Model Context Protocol gateway. It speaks JSON-RPC 2.0 on a configured origin, aggregates the tool catalogues of one or more upstream MCP servers, and routes `tools/call` requests back to the upstream that owns each tool. Per-server `prefix:`, `rbac:`, and `timeout:` options live alongside the `origin:` entries; an inline `tool_allowlist` guardrail short-circuits any call to a tool not on the allowlist before it leaves the proxy.

The wire format matches the schema published on `www.sbproxy.dev`. The action is a thin adapter on top of the federation library in `crates/sbproxy-extension/src/mcp/`; tool aggregation, name-collision handling, and the underlying transports live there.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Initialize an MCP session.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | jq .
# Returns the configured server_info.name / .version.

# List the federated tool catalogue.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq .
# Tools from each upstream are exposed under their configured prefix
# (e.g. gh.search_repos, db.query). The exact list depends on what
# the upstream MCP servers report from their tools/list call.

# Call a federated tool. The gateway routes the request to the
# upstream that owns the prefix.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":3,
    "method":"tools/call",
    "params":{
      "name":"gh.search_repos",
      "arguments":{"q":"sbproxy"}
    }
  }' | jq .

# A blocked tool (not in the allowlist) returns a JSON-RPC error.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":4,
    "method":"tools/call",
    "params":{
      "name":"gh.delete_repo",
      "arguments":{"owner":"foo","repo":"bar"}
    }
  }' | jq .
# {"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"tool 'gh.delete_repo' is blocked by tool_allowlist guardrail"}}
```

## What this exercises

- `action.type: mcp` - the top-level MCP gateway action
- `mode: gateway` - federate one or more upstreams behind a virtual MCP endpoint
- `server_info.name` / `server_info.version` - identity returned in MCP `initialize`
- `federated_servers[].origin` - upstream MCP endpoint (bare hostname or full URL)
- `federated_servers[].prefix` - namespace applied to the upstream's tools
- `guardrails[].type: tool_allowlist` - inline allowlist that short-circuits `tools/call`

### Planned but not yet enforced

These knobs parse but the dispatch layer does not honour them yet. Tracked in [WOR-119](https://linear.app/12345r/issue/WOR-119).

- `federated_servers[].rbac` - per-server RBAC label
- `federated_servers[].timeout` - per-server request budget

### Caveat: cannot be run end-to-end as-shipped

The federated origins (`github.example.com`, `postgres.example.com`) are RFC 2606 placeholders, not live MCP servers. `tools/list` against this config hits DNS errors. A docker-compose stack with mock MCP servers is tracked in [WOR-123](https://linear.app/12345r/issue/WOR-123).

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- The federation library at `crates/sbproxy-extension/src/mcp/`
