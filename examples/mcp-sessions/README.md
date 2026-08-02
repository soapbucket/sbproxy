# MCP sessions and a file-sink ledger

> **Partially runnable.** `federated_servers[].origin` here is
> `github.example.com`, an RFC 2606 reserved placeholder, not a running MCP
> server, so a federated `tools/call` cannot complete end-to-end. Session
> lifecycle (`initialize`, the `Mcp-Session-Id` header, `400`/`404` on a
> missing or unknown id, `DELETE`) is handled by the gateway itself and
> works as shipped; the session ledger records whatever calls you can make
> against your own upstream. See
> [`examples/mcp-federation`](../mcp-federation/) for the base federation
> mechanics and its own end-to-end caveat.

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
