# Cedar Confirm: park, notify, approve, retry

*Last modified: 2026-08-29*

A `@confirm("deploy needs a human")` forbid on `approve_deploy` parks the call because this origin also has `approval:`. The caller's HTTP connection is never held open. The gateway returns JSON-RPC `-32097` with `hold_id`, `snapshot`, and `expires_at`. A fresh hold fires alert rule `mcp_confirm` on every configured `proxy.alerting` channel (this example uses `type: log`). A retry that collapses onto a pending hold does not fire again.

Unanswered holds expire fail-closed after `hold_ttl` (default and here: 15 minutes). Expiry never becomes an allow.

Without `approval:`, the same Cedar source is a labelled refusal (`confirmation required: deploy needs a human`). That path is [`examples/cedar-mcp-full/`](../cedar-mcp-full/).

Do not put `approve_deploy` on `approval.tools[]`. That selector parks before Cedar runs, so you would never see a Confirm-originated hold.

## Run

Two processes: the cedar-mcp-full mock REST upstream, then this gateway.

```bash
sbproxy serve -f examples/cedar-mcp-full/upstream.yml &
sbproxy serve -f examples/cedar-confirm-flow/sb.yml
```

## Park

Initialize, then call `approve_deploy`. No auth is configured, so the Cedar principal is `Agent::"anonymous"`.

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}' | jq .

curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"approve_deploy","arguments":{}}}' | jq .
```

Look for `-32097` and a `hold_id`. The process log should carry an `mcp_confirm` warning on that first park.

## Approve

JSON admin routes and the console queue are the same hold. Default admin basic auth is `admin:changeme`.

```bash
curl -s -u admin:changeme http://127.0.0.1:9900/api/mcp/approvals | jq .
curl -s -u admin:changeme -X POST \
  http://127.0.0.1:9900/api/mcp/approvals/HOLD_ID/approve \
  -H 'content-type: application/json' \
  -d '{"approved_by":"alice"}' | jq .
```

Or open `http://127.0.0.1:9900/admin/ui/mcp-approvals`, sign in, and use Approve.

## Retry

The next matching `tools/call` (same tool contract and canonical arguments) consumes the approval once and reaches the mock upstream.

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"approve_deploy","arguments":{}}}' | jq .
```

`search_repos` still allows through Cedar. `delete_repo` is still a Cedar forbid (not a hold).

## See also

- [docs/cedar-policy.md](../../docs/cedar-policy.md)
- [docs/mcp.md](../../docs/mcp.md) gateway-originated approval
- [examples/mcp-approval-gate](../mcp-approval-gate/) for a hold that does not go through Cedar
- [examples/cedar-replay](../cedar-replay/) to preview a Cedar edit offline
