# MCP progressive tool discovery

> **Snippet, depends on a live upstream.** `federated_servers[].origin`
> here is `github.example.com` / `postgres.example.com`, RFC 2606 reserved
> placeholders, not running MCP servers, so the catalogue behind `search`
> and `execute` is empty as-shipped and `tools/call execute` cannot
> complete end-to-end. Point the origins at your own MCP server(s) to
> exercise this locally. See [`examples/mcp-federation`](../mcp-federation/)
> for the base federation mechanics and the same caveat spelled out in full.

Keeps a large federated catalogue out of the model's context window by
advertising only `search` and `execute` meta-tools.

Run it:

```bash
sbproxy serve -f sb.yml
```

What proves it is working:

- `tools/list` returns exactly two tools, `search` and `execute`, not
  the full federated catalogue.
- `tools/call` `search` with a `query` returns matching catalogue
  entries; `tools/call` `execute` with a tool `name` invokes it.
