# Cedar policy on MCP tools/call

*Last modified: 2026-08-28*

Cedar is the ABAC layer on an `mcp` action's federated `tools/call` path. You write Cedar source under `cedar_policies.policies`. The gateway compiles it once at config load against the built-in MCP schema, installs a hook, and evaluates every non-`local` tool call after RBAC has already allowed it. There is no natural-language-to-Cedar compiler, no parked human-approval flow, and no Cedar console or CLI in this binary.

Runnable: [`examples/cedar-mcp-full/`](../examples/cedar-mcp-full/). Catalog of every policy type: [policy.md](policy.md). MCP federation: [mcp.md](mcp.md).

## What is live

| Surface | Status |
|---|---|
| `cedar_policies.policies` on an `mcp` action | Compiled at load. A syntax or schema error refuses the config, not the first request. |
| Default MCP schema | `Agent`, `AgentClass`, `User`, `Group`, `Server`, `Tool`, `ToolInvocation`, `ArgumentBinding`, action `MCP::CallTool`. |
| `schema_override` | Optional extra Cedar schema. It must not collide with the default types. |
| Hook placement | After RBAC, argument policies, and quotas. An RBAC deny never reaches Cedar. A Cedar forbid can still refuse a call RBAC allowed. |
| Scope | Non-`local` federated servers (`type: openapi` or a real MCP upstream). `type: local` tools skip this hook. |
| Entity store | Empty. Match `principal == Agent::"<id>"` or `Agent::"anonymous"`. `principal in AgentClass::"..."` never matches. |
| Confirm annotation | `@confirm("reason")` on a `forbid` maps to a Confirm verdict, then the federation refuses with `confirmation required: {reason}`. Nothing parks the call for a later approve. |
| Policy store / CLI / admin UI | The embedded redb store is in the tree and is not wired to this hook. Policies come from YAML. There is no Cedar JSON Schema field, no Cedar CLI, and no Cedar page in the admin UI. |

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

Confirm is the same error shape, with message `confirmation required: {reason}`. Treat that as a refusal, not a 202 waiting for an approver.

## See also

- [configuration.md](configuration.md) `cedar_policies` row on the `mcp` action
- [policy.md](policy.md#nl-to-cedar-decision) for why there is no NL-to-Cedar path
- [a2a-gateway.md](a2a-gateway.md) for the separate A2A policy surface (not Cedar)
