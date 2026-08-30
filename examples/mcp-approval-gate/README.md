# Gateway-originated MCP approval hold

*Last modified: 2026-08-29*

A high-risk `tools/call` is parked until an operator approves the
content snapshot. The caller's HTTP connection is never held open.
TrueFoundry is the surveyed state of the art for this gate. Approve
from `POST /api/mcp/approvals/{id}/approve` or the admin console at
`/admin/ui/mcp-approvals`.

## Run

```bash
sbproxy serve -f examples/mcp-approval-gate/sb.yml
```

## Try it

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
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reports.hello","arguments":{"name":"world"}}}' | jq .
```

Expect JSON-RPC error `-32097` with `hold_id`, `snapshot`, and
`expires_at`. Approve, then retry the same call:

```bash
curl -s -u admin:changeme http://127.0.0.1:9900/api/mcp/approvals | jq .
curl -s -u admin:changeme -X POST \
  http://127.0.0.1:9900/api/mcp/approvals/HOLD_ID/approve \
  -H 'content-type: application/json' \
  -d '{"approved_by":"alice"}' | jq .
```

The next matching `tools/call` consumes the approval once.
