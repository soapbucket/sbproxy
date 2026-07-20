# MCP gateway with federated upstreams

*Last modified: 2026-07-19*

The `mcp` action turns SBproxy into a Model Context Protocol gateway. It speaks JSON-RPC 2.0 on a configured origin, aggregates the tool catalogues of one or more upstream servers, and routes `tools/call` requests back to the upstream that owns each tool. Per-server `prefix:`, `rbac:`, and `timeout:` options live alongside the `origin:` entries; an inline `tool_allowlist` guardrail short-circuits any call to a tool not on the allowlist before it leaves the proxy.

The wire format matches the schema published on `www.sbproxy.dev`. The action is a thin adapter on top of the federation library in `crates/sbproxy-extension/src/mcp/`; tool aggregation, name-collision handling, and the underlying transports live there.

## What's real here

This package federates **two** upstreams so you can see both stories side by side:

- **`gh`** is a `type: openapi` server (see [docs/mcp.md](../../docs/mcp.md#openapi-backed-servers)) pointed at the tiny REST mock in `upstream.yml`. The gateway derives the `gh.search_repos` tool from the inline OpenAPI spec with no code, and dispatches `tools/call` as a real HTTP request to that mock. `tools/list` and `tools/call gh.search_repos` below are genuine round-trips — run the two processes and you get real responses, not a transcript.
- **`db`** is a plain `type: mcp` server pointed at `postgres.example.com`, an RFC 2606 reserved placeholder, not a running server. It exists to show the honest failure mode next to the real one: it is silently absent from `tools/list` (federation degrades per-server, logging and skipping a dead upstream rather than failing the whole catalogue) and `tools/call db.query` returns `"unknown tool: db.query"`. Point `db`'s `origin` at your own MCP server, or convert it to `type: openapi` the same way `gh` is done, to make it real too.

For the full end-to-end product story (problem, RBAC, next steps), see [docs/use-case-mcp-federation.md](../../docs/use-case-mcp-federation.md).

## Run

Two processes: the mock upstream, then the gateway that federates it.

```bash
sbproxy serve -f examples/mcp-federation/upstream.yml &
sbproxy serve -f examples/mcp-federation/sb.yml
```

## Try it

```bash
# Initialize an MCP session. Answered locally by the gateway — no
# upstream is contacted, so this works even before you start
# upstream.yml.
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
# Real output with both processes running:
# {"jsonrpc":"2.0","id":2,"result":{"tools":[
#   {"name":"gh.search_repos","description":"Search repositories by query.", ...}
# ]}}
# Only gh.search_repos appears: db's tools/list fetch fails against
# the unreachable placeholder and is dropped, not fatal to the call.

# Call the real federated tool. The gateway resolves the OpenAPI
# route, substitutes `q` into the query string, and sends a real GET
# to the mock upstream.
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
# {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"[{\"full_name\":\"soapbucket/sbproxy\", ...}]"}],"isError":false}}

# A blocked tool (not in the allowlist) returns a JSON-RPC error
# without ever reaching an upstream.
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

# db.query names the honest gap: db's upstream never answered
# tools/list, so the tool never entered the registry.
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":5,
    "method":"tools/call",
    "params":{"name":"db.query","arguments":{"sql":"select 1"}}
  }' | jq .
# {"jsonrpc":"2.0","id":5,"error":{"code":-32603,"message":"tool call failed: unknown tool: db.query"}}
```

## What this exercises

- `action.type: mcp` - the top-level MCP gateway action
- `mode: gateway` - federate one or more upstreams behind a virtual MCP endpoint
- `server_info.name` / `server_info.version` - identity returned in MCP `initialize`, answered locally with no upstream round-trip
- `federated_servers[].type: openapi` - derive MCP tools from an OpenAPI spec and dispatch `tools/call` as REST, with no code against the upstream (see [docs/mcp.md](../../docs/mcp.md#openapi-backed-servers))
- `federated_servers[].origin` - upstream endpoint: a bare hostname / full MCP URL for `type: mcp`, or a REST base URL for `type: openapi`
- `federated_servers[].prefix` + `namespace: always` - namespace applied to every tool from this upstream, unconditionally
- `federated_servers[].rbac` - per-server RBAC label, enforced on every `tools/call` against the caller's principal (default-deny), for both `mcp` and `openapi` servers
- `federated_servers[].timeout` - per-server request budget; a call that outlasts it fails rather than hanging the request
- `rbac_policies` - named default-deny tool-access policies referenced by each server's `rbac:` label
- `guardrails[].type: tool_allowlist` - a second, coarser allowlist on top of RBAC that short-circuits `tools/call`

RBAC and timeout are enforced by the dispatch layer, not merely parsed:
a tool the policy denies returns a JSON-RPC error and never reaches the
upstream, and a call that exceeds the per-server `timeout` fails inside
that budget. Deeper RBAC and quota behaviour has its own runnable
example under [`examples/mcp-rbac-quotas`](../mcp-rbac-quotas).

## Make `db` real too

Swap `db`'s `origin: postgres.example.com` for a running MCP server (bare hostname normalises to `https://<host>/mcp`, or give a full URL including `http://127.0.0.1:<port>/mcp` for local testing), or convert it to a second `type: openapi` server the way `gh` is done here — point `origin` at any REST API you own and give it an inline `spec` or `spec_path`. Either way `db`'s `rbac: db_writer` and the `tool_allowlist` guardrail keep applying with no other config change.

## See also

- [docs/use-case-mcp-federation.md](../../docs/use-case-mcp-federation.md) - the end-to-end solution guide: problem, config, RBAC, next steps
- [docs/mcp.md](../../docs/mcp.md) - wire format, `federated_servers[]` fields, OpenAPI-backed servers, sessions
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- The federation library at `crates/sbproxy-extension/src/mcp/`
