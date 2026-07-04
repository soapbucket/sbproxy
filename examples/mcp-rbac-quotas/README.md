# MCP RBAC and per-tool quotas

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
