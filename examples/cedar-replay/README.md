# Cedar replay against a traffic sample

*Last modified: 2026-08-29*

Offline preview of a Cedar policy change before `sbproxy apply`. The live set (`baseline.yml`) allows `search_repos`, forbids `delete_repo`, and Confirm-refuses `approve_deploy`. The proposed set (`sb.yml`) also forbids `search_repos`. `traffic.jsonl` is three tool-call samples in the same principal / resource shape the live MCP hook evaluates.

This command does not start a proxy. Samples do not carry arguments: the live hook uses an empty Cedar context.

## Replay the change

From the repository root:

```bash
sbproxy cedar replay -f examples/cedar-replay/sb.yml \
  --against examples/cedar-replay/traffic.jsonl \
  --baseline examples/cedar-replay/baseline.yml
```

Expect exit 1 (a verdict moved) and text like:

```
search ToolInvocation::"demo/search_repos" -> deny  [changed from allow]
delete ToolInvocation::"demo/delete_repo" -> deny
deploy ToolInvocation::"demo/approve_deploy" -> confirm (deploy needs a human)
3 sample(s), 1 changed, 0 expected mismatch(es)
```

`--format json` emits the same report as one object for CI. `--origin mcp.example.com` restricts extraction when a document has several Cedar origins.

## Assert the proposed set alone

Add `"expected":"deny"` (or `allow` / `confirm`) on a JSONL line. Without `--baseline`, a mismatch is still exit 1; a clean run is exit 0. Exit 2 means the YAML, the sample, or the Cedar source did not compile.

## Plan the same edit

Cedar source is a Reload change and is named as Cedar, not an opaque action-body tweak:

```bash
sbproxy plan -f examples/cedar-replay/sb.yml \
  --against examples/cedar-replay/baseline.yml
```

## See also

- [docs/cedar-policy.md](../../docs/cedar-policy.md)
- [docs/manual.md](../../docs/manual.md) `cedar replay`
- [examples/cedar-mcp-full](../cedar-mcp-full/) for the live allow / forbid / Confirm-refuse path
- [examples/cedar-confirm-flow](../cedar-confirm-flow/) when Confirm should park for a human
