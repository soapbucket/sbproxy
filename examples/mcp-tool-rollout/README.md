# MCP tool rollout

MCP has no tool version field, so shipping a breaking change to a tool
normally breaks every caller at once. This example publishes two
versions of `search` behind one gateway: the default consumer gets
2.0.0 from the new upstream, the checkout team stays pinned to 1.x on
the legacy upstream, and the old version carries a sunset date.

Run it:

```bash
sbproxy --config sb.yml
```

What proves it is working:

- `tools/list` shows one `search` (the consumer's resolved version in
  `_meta.sbproxy.dev/version`) plus `search_v1` and `search_v2`
  aliases. Every entry lists the available versions and the sunset.
- A caller whose principal matches `team: checkout` resolves `search`
  to 1.4.0 and routes to `legacy-api`; everyone else gets 2.0.0 on
  `new-api`. A `tools/call` with `_meta` `sbproxy.dev/version: "^1"`
  gets 1.4.0 regardless of identity.
- Every versioned call increments
  `sbproxy_mcp_tool_version_calls_total{tool,version,via,deprecated}`;
  the per-version split is the migration dashboard. Results carry
  `_meta.sbproxy.dev/version` naming the version that served them.
- Calls to the deprecated 1.4.0 log a warning; flip its
  `after_sunset:` to `block` and, past the date, they fail with a
  typed error naming the sunset.

When the legacy upstream is retired, swap its `server:` for the
`adapter:` in `adapters/search-v1.js` plus an inline `contract:`; v1
calls are then translated onto the new upstream and nothing on the
caller's side changes. See `docs/tool-versioning.md` for the full
resolution ladder and the adapter contract.
