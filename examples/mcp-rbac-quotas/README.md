# MCP RBAC and per-tool quotas

> **Snippet, depends on a live upstream.** `federated_servers[].origin` here
> is `github.example.com`, an RFC 2606 reserved placeholder, not a running
> MCP server, so this config cannot be run end-to-end as-shipped: `tools/list`
> against it hits a DNS error. Point the origin at your own MCP server to
> exercise the RBAC and quota behavior below. See
> [`examples/mcp-federation`](../mcp-federation/) for the base federation
> mechanics and the same caveat spelled out in full.

Default-deny tool access plus a sliding-window quota, both keyed on the
caller's principal.

Run it:

```bash
sbproxy serve -f sb.yml
```

What proves it is working:

- A `tools/call` for `gh.search_repos` is allowed and forwarded.
- A `tools/call` for any other tool returns a JSON-RPC error and the
  upstream never sees it (default-deny).
- More than 30 calls to `gh.search_repos` in a minute return JSON-RPC
  error `-32099` (`tool quota exceeded`) until the window rolls.
