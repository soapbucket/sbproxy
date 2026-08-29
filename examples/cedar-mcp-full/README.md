# Cedar ABAC on federated MCP tools/call

*Last modified: 2026-08-29*

Three OpenAPI-derived tools behind one MCP gateway, with Cedar compiled at config load. RBAC allows all three so you can see Cedar allow, forbid, and Confirm-refuse on the same origin. The upstream is a local mock (`upstream.yml`), not `type: local`: the Cedar hook does not run on local tools.

There is no parked approval. A `@confirm("…")` forbid becomes a JSON-RPC error whose message starts with `confirmation required:`.

## Run

Two processes: the mock REST upstream, then the gateway.

```bash
sbproxy serve -f examples/cedar-mcp-full/upstream.yml &
sbproxy serve -f examples/cedar-mcp-full/sb.yml
```

## Try it

Initialize, then call each tool. No auth is configured, so the Cedar principal is `Agent::"anonymous"`.

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}' | jq .
```

Allow (`search_repos`): the mock upstream answers.

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_repos","arguments":{"q":"sbproxy"}}}' | jq .
```

Deny (`delete_repo`): Cedar forbid. The upstream is not contacted.

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}' | jq .
```

Confirm-kind refuse (`approve_deploy`): look for `confirmation required: deploy needs a human` in the error message. That is a refusal, not a waiting approval. Parking that verdict for a human is [`examples/cedar-confirm-flow/`](../cedar-confirm-flow/). Preview a Cedar edit offline with [`examples/cedar-replay/`](../cedar-replay/).

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"approve_deploy","arguments":{}}}' | jq .
```

`principal in AgentClass::"..."` would never match here. The hook evaluates against an empty entity store. Match `Agent::"anonymous"` or a specific `Agent::"<id>"`.

## What this exercises

- `cedar_policies.policies` compiled at load
- RBAC allow-list first, Cedar ABAC second
- OpenAPI-backed federated tools (not `type: local`)
- Allow, forbid, and `@confirm` as a labelled refusal

## See also

- [docs/cedar-policy.md](../../docs/cedar-policy.md)
- [docs/mcp.md](../../docs/mcp.md)
- [examples/mcp-federation](../mcp-federation/) for federation without Cedar
