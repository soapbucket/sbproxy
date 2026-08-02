# MCP Code Mode TypeScript module

> **Snippet, depends on a live upstream.** `federated_servers[].origin` here
> is `github.example.com`, an RFC 2606 reserved placeholder, not a running
> MCP server, so the federated catalogue this module is generated from is
> empty as-shipped. Point the origin at your own MCP server to see typed
> functions in the generated module. See
> [`examples/mcp-federation`](../mcp-federation/) for the base federation
> mechanics and the same caveat spelled out in full.

Serves the federated tool catalogue as a typed TypeScript module for
Cloudflare Code Mode agents.

Run it:

```bash
sbproxy serve -f sb.yml
```

What proves it is working:

```bash
curl -s http://127.0.0.1:8080/.well-known/mcp/codemode.ts \
  -H 'Host: mcp.example.com'
```

- Returns a TypeScript module with one typed function per federated
  tool and an `ETag` header.
- A repeat request with `If-None-Match: <that etag>` returns `304`
  until the catalogue changes.
- The runtime stub in the module POSTs each call back to the gateway
  with `mcp-caller: code-execution`, so those calls are attributed to
  the code-execution sandbox in the session ledger.
