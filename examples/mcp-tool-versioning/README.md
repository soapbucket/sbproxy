# MCP tool versioning

*Last modified: 2026-08-16*

> **Runs end-to-end against a live upstream, but not against the
> committed lockfile's tool.** `federated_servers[].origin` here is
> `test.sbproxy.dev`, the project's public test service. It also serves
> a small real MCP endpoint (tools `echo` and `hello`), so `tools/list`
> and `tools/call` against it are genuine round-trips, not a transcript.
> What it does not have is the `search` tool that
> `tool-versions.lock.yaml` was committed against. As shipped this
> demonstrates the oracle's `removed_tool` path (`search` is in the
> lockfile but no longer live: a `major`-grade violation) plus two
> `unlocked_tool` verdicts (`echo` and `hello` are live but not in the
> lockfile, so there is no baseline to diff against and neither is
> blocked). To see the `changed` / `violation` path below (a live
> contract edited without a matching version bump), point the origin at
> your own MCP server whose tools you can edit and re-lock. See
> [`examples/mcp-federation`](../mcp-federation/) for the base federation
> mechanics.

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

- As shipped, one `tools/list` call against `test.sbproxy.dev` is enough
  to see the oracle run: `curl -s -X POST -H 'Host: mcp.example.com' -d
  '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
  http://127.0.0.1:8080/` returns `echo` and `hello` (`search` is gone),
  and `sbproxy_mcp_tool_compat_verdicts_total` on `/metrics` shows
  `{grade="major",outcome="removed_tool"} 1` for the missing `search`
  tool and `{grade="none",outcome="unlocked_tool"} 2` for `echo` and
  `hello`. The audit log carries the matching `sbproxy::audit` event,
  `mcp.tool_versioning.removed`, naming `search`.
- A tool whose contract matches the lockfile serves normally.
- Change a tool upstream (rename an argument, reword the description)
  without bumping `declared_versions`: with `mode: warn` the gateway
  logs a `mcp.tool_versioning.violation` audit event and increments
  `sbproxy_mcp_tool_compat_verdicts_total{outcome="violation"}`; with
  `mode: block` the tool also disappears from `tools/list` and a
  `tools/call` on it returns an error naming the grade it required.
  (Needs a server you control: nothing live against this example's
  `test.sbproxy.dev` origin has a lockfile entry to change under.)
- Declare the matching bump under `declared_versions` and the next
  refresh clears the violation.

The lockfile is a committed YAML baseline; copy the format from
`tool-versions.lock.yaml` here (see `docs/tool-versioning.md` for the
field reference). An unreadable lockfile fails open: nothing is
blocked and the gateway logs a loud `lockfile_error`.
