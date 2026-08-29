# Cedar policy on MCP tools/call

*Last modified: 2026-08-29*

Cedar is the ABAC layer on an `mcp` action's federated `tools/call` path. You write Cedar source under `cedar_policies.policies`. The gateway compiles it once at config load against the built-in MCP schema, installs a hook, and evaluates every non-`local` tool call after RBAC has already allowed it. There is no natural-language-to-Cedar compiler.

Runnable:

- Allow / forbid / Confirm-refuse (no park): [`examples/cedar-mcp-full/`](../examples/cedar-mcp-full/)
- Confirm parks for a human: [`examples/cedar-confirm-flow/`](../examples/cedar-confirm-flow/)
- Offline replay of a policy change: [`examples/cedar-replay/`](../examples/cedar-replay/)

Catalog of every policy type: [policy.md](policy.md). MCP federation: [mcp.md](mcp.md). CLI: [manual.md](manual.md). Admin queue: [admin-ui.md](admin-ui.md#mcp-approvals-mcp-approvals).

## What is live

| Surface | Status |
|---|---|
| `cedar_policies.policies` on an `mcp` action | Compiled at load. A syntax or schema error refuses the config, not the first request. |
| Default MCP schema | `Agent`, `AgentClass`, `User`, `Group`, `Server`, `Tool`, `ToolInvocation`, `ArgumentBinding`, action `MCP::CallTool`. |
| `schema_override` | Optional extra Cedar schema. It must not collide with the default types. |
| Hook placement | After RBAC, argument policies, and quotas. An RBAC deny never reaches Cedar. A Cedar forbid can still refuse a call RBAC allowed. |
| Scope | Non-`local` federated servers (`type: openapi` or a real MCP upstream). `type: local` tools skip this hook. |
| Entity store | Empty. Match `principal == Agent::"<id>"` or `Agent::"anonymous"`. `principal in AgentClass::"..."` never matches. |
| Confirm annotation | `@confirm("reason")` on a `forbid` maps to a Confirm verdict. Without `approval:` on the same action that is still a refusal (`confirmation required: {reason}`). With `approval:`, the call is parked (JSON-RPC `-32097`) until an operator approves the content snapshot. |
| `sbproxy plan` / `apply` | A Cedar-only edit is blast-radius **Reload**, reason `Cedar MCP policies recompile on reload`. The changed path is named `action.cedar_policies`, not an opaque action body. |
| `sbproxy cedar replay` | Offline evaluation of a JSONL traffic sample against `cedar_policies` in an `sb.yml`. Optional `--baseline` diffs verdicts. No second CLI binary. |
| Admin console | Pending MCP holds, including Cedar Confirm parks, at `/admin/ui/mcp-approvals`. Approve and deny call the same JSON routes as curl. |
| Alerting | A **fresh** Confirm park fires rule `mcp_confirm` (severity `warning`) on every configured `proxy.alerting` channel (webhook, Slack, PagerDuty, log). A retry that joins an existing pending hold does not fire again. If `proxy.alerting` was not installed at boot, this fire is a no-op; per-origin `approval.webhook` still runs. |
| Policy store / visual authoring | The embedded redb store is in the tree and is not wired to this hook. Policies come from YAML. There is no Cedar JSON Schema field and no visual Cedar authoring page. |

## Entities the hook builds

Every `tools/call` becomes one request:

- **principal:** `Agent::"<agent_id>"`, or `Agent::"anonymous"` when the caller has no resolved agent identity.
- **action:** `Action::"MCP::CallTool"` (fixed).
- **resource:** `ToolInvocation::"<mcp_server>/<tool_name>"`. `mcp_server` is the federated server's `prefix` (or the name derived from `origin`). `tool_name` is the advertised tool name: with default `namespace: on_collision` on a single server that is the bare OpenAPI `operationId`; with `namespace: always` it is `<prefix>.<operationId>`.
- **context:** empty. Policies cannot yet read `resource.tool.name` or argument values.

Write the resource id the way the hook joins it. For `prefix: demo` and a tool advertised as `search_repos`:

```cedar
permit(principal, action, resource);

forbid(
  principal,
  action,
  resource == ToolInvocation::"demo/delete_repo"
);

@confirm("deploy needs a human")
forbid(
  principal,
  action,
  resource == ToolInvocation::"demo/approve_deploy"
);
```

A catch-all `permit` is load-bearing. Cedar's default is deny, so a config that only forbids one tool and never permits the rest refuses everything.

## Alongside RBAC

RBAC (`rbac_policies` + per-server `rbac:`) is the coarse, default-deny gate. Cedar does not reopen a tool RBAC already hid. Put every tool Cedar should see on the RBAC allowlist, then forbid the ones Cedar should stop.

Do not use `type: local` to demo Cedar. Local tools never hit the hook, so a policy that looks correct in YAML does nothing.

## What you will see on the wire

Allow is a normal JSON-RPC result from the upstream.

Deny is a JSON-RPC error (`INVALID_PARAMS`) whose message comes from the Cedar forbid.

Confirm without `approval:` is the same error shape, with message `confirmation required: {reason}`. Treat that as a refusal.

## Confirm: park, notify, approve

When the same `mcp` action also has `approval:` (`store` plus optional `hold_ttl`), a Confirm verdict parks instead of refusing:

1. The gateway returns JSON-RPC `-32097` with `hold_id`, `snapshot`, and `expires_at`. The caller's HTTP connection is never held open.
2. A **fresh** insert fires `mcp_confirm` on `proxy.alerting.channels`. Add `type: log` for a process-local line, or webhook / Slack / PagerDuty the same way any other alert channel is configured. Per-origin `approval.webhook` is a separate, SSRF-checked POST and still works when alerting was not installed.
3. An operator approves or denies from `GET`/`POST /api/mcp/approvals` or the admin page `/admin/ui/mcp-approvals`. Approval is single-use and bound to the content snapshot (tool-contract digest plus canonical arguments), so a rename cannot consume another tool's decision.
4. The next matching `tools/call` consumes an approval once and proceeds. A deny deletes the row, so a retry of the same snapshot parks again (a fresh insert, another `mcp_confirm`) rather than staying refused until `hold_ttl`. Unanswered holds are the ones that expire fail-closed.

Do not list the Confirm tool on `approval.tools[]` if you want Cedar to be the layer that parks. That selector holds matching `tools/call` before the Cedar hook runs.

### Fail-closed timeout

`hold_ttl` defaults to **15 minutes**. An unanswered hold expires fail-closed: it is dropped, never auto-allowed. Configure a longer window on `approval.hold_ttl` when an operator is not always at the console. There is no fail-open mode.

Runnable: [`examples/cedar-confirm-flow/`](../examples/cedar-confirm-flow/). The hold that does not go through Cedar is [`examples/mcp-approval-gate/`](../examples/mcp-approval-gate/).

## `sbproxy plan` and `sbproxy cedar replay`

A Cedar-only YAML edit participates in the existing plan/apply workflow. `sbproxy plan -f proposed.yml --against live.yml` classifies `origins.*.action.cedar_policies` as Reload. `sbproxy apply` reloads; there is no hitless Cedar swap, because the hook recompiles from source at load.

Replay is the traffic-shaped preview, not a second plan:

```bash
sbproxy cedar replay -f proposed.yml --against traffic.jsonl --baseline live.yml
```

Each JSONL line is `{principal, resource, expected?, action?, id?}`. `principal` and `resource` must be Cedar UIDs (`Agent::"anonymous"`, `ToolInvocation::"demo/search_repos"`). `action` defaults to `Action::"MCP::CallTool"`. Replay compiles one origin the way the live hook does (merged schema, including `schema_override`). When several origins have Cedar, pass `--origin`. Exit 0 when every `expected` label holds and (with `--baseline`) no verdict moved; 1 when a sample missed or a verdict changed; 2 when the sample, the YAML, or the Cedar source could not be compiled.

`sbproxy audit verify` already covers the audit trail. This binary does not add a Cedar verifier.

Runnable: [`examples/cedar-replay/`](../examples/cedar-replay/).

## See also

- [configuration.md](configuration.md) `cedar_policies` and `approval` rows on the `mcp` action
- [policy.md](policy.md#nl-to-cedar-decision) for why there is no NL-to-Cedar path
- [manual.md](manual.md) for `sbproxy cedar replay`
- [a2a-gateway.md](a2a-gateway.md) for the separate A2A policy surface (not Cedar)
