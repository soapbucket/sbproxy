# MCP tool versioning

> **Snippet, depends on a live upstream.** `federated_servers[].origin`
> here is `test.sbproxy.dev`, the project's public HTTP echo service (like
> httpbin), not an MCP server, so it publishes no `search` tool and
> `tools/list` / `tools/call` against it cannot complete end-to-end as
> shipped. Point the origin at your own MCP server to exercise the
> versioning oracle below. See
> [`examples/mcp-federation`](../mcp-federation/) for the base federation
> mechanics and its own end-to-end caveat.

An MCP tool has no version field, so a tool can change under the
agents that call it with no error. This example turns on the
compatibility oracle: every catalogue refresh diffs the live tools
against the committed `tool-versions.lock.yaml` and lints the declared
version bump.

Run it:

```bash
sbproxy --config sb.yml
```

What proves it is working:

- A tool whose contract matches the lockfile serves normally.
- Change a tool upstream (rename an argument, reword the description)
  without bumping `declared_versions`: with `mode: warn` the gateway
  logs a `mcp.tool_versioning.violation` audit event and increments
  `sbproxy_mcp_tool_compat_verdicts_total{outcome="violation"}`; with
  `mode: block` the tool also disappears from `tools/list` and a
  `tools/call` on it returns an error naming the grade it required.
- Declare the matching bump under `declared_versions` and the next
  refresh clears the violation.

The lockfile is a committed YAML baseline; copy the format from
`tool-versions.lock.yaml` here (see `docs/tool-versioning.md` for the
field reference). An unreadable lockfile fails open: nothing is
blocked and the gateway logs a loud `lockfile_error`.
