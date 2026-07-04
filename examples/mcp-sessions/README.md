# MCP sessions and a file-sink ledger

Turns on streamable HTTP session management and writes a session-ledger
NDJSON artifact.

Run it:

```bash
sbproxy serve -f sb.yml
```

What proves it is working:

- `initialize` responds with an `Mcp-Session-Id` header.
- A later request without that header returns `400`; with an unknown
  or expired id, `404` (the client's cue to re-initialize).
- `DELETE /` with the id returns `204` and the id then fails with
  `404`.
- Each `tools/call` appends a record to `mcp-session-ledger.ndjson`.
