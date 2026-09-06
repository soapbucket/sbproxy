# Cedar policy on MCP tools/call

*Last modified: 2026-09-05*

Use `cedar_policies` on an `mcp` action to allow, deny, or require operator approval for federated tool calls. SBproxy compiles the Cedar source when it loads the configuration and evaluates it after RBAC, argument policies, and quotas allow the call.

**Current limits:** the HTTP `tools/call` dispatcher supplies `Agent::"anonymous"` to Cedar, including for authenticated callers. Cedar receives an empty entity store and context. Use MCP RBAC for caller-specific access and CEL or Rego argument policies for argument-based checks. `type: local` tools bypass Cedar. These limits apply to the running gateway; offline replay lets you supply a principal UID yourself.

## Quickstart: allow, deny, and require confirmation

This walkthrough uses the files in [examples/cedar-mcp-full](../examples/cedar-mcp-full/). Install SBproxy 1.14.0 and `jq`, then run the commands from the repository root. The example has no inbound authentication and is intended for local testing.

Start the mock REST upstream in one terminal:

```bash
sbproxy serve -f examples/cedar-mcp-full/upstream.yml
```

In another terminal, validate and start the MCP gateway:

```bash
sbproxy validate examples/cedar-mcp-full/sb.yml
sbproxy serve -f examples/cedar-mcp-full/sb.yml
```

The upstream listens on port 8091; the gateway listens on 8080. The complete gateway configuration is below. Each OpenAPI `operationId` becomes an advertised tool. The RBAC allowlist admits all three so you can observe the Cedar decisions.

<!-- sbproxy-config-excerpt -->
```yaml
proxy:
  http_bind_port: 8080

origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: cedar-demo
        version: "1.0.0"
      rbac_policies:
        all_tools:
          default_allow: false
          tool_access:
            - principals: []
              allowed:
                - search_repos
                - delete_repo
                - approve_deploy
      cedar_policies:
        policies: |
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
      federated_servers:
        - type: openapi
          origin: http://127.0.0.1:8091
          prefix: demo
          rbac: all_tools
          timeout: 10s
          spec:
            openapi: "3.0.0"
            info:
              title: Cedar demo tools
              version: "1.0"
            paths:
              "/search/repositories":
                get:
                  operationId: search_repos
                  summary: Search repositories by query.
                  parameters:
                    - name: q
                      in: query
                      required: true
                      schema:
                        type: string
              "/repos/delete":
                post:
                  operationId: delete_repo
                  summary: Delete a repository (Cedar forbids this).
              "/deploy/approve":
                post:
                  operationId: approve_deploy
                  summary: Approve a deploy (Cedar Confirm-refuses this).
      guardrails:
        - type: tool_allowlist
          allow:
            - search_repos
            - delete_repo
            - approve_deploy
```

In a third terminal, define a helper and initialize the MCP connection:

```bash
mcp() {
  curl -fsS http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' \
    --data "$1"
}

mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cedar-demo","version":"1.0.0"}}}' | jq .
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | jq '.result.tools[].name'
```

Call each tool:

```bash
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_repos","arguments":{"q":"sbproxy"}}}' | jq .
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}' | jq .
mcp '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"approve_deploy","arguments":{}}}' | jq .
```

| Tool | Expected response |
|---|---|
| `search_repos` | A JSON-RPC `result` containing the mock upstream's response |
| `delete_repo` | JSON-RPC error `-32602` (`INVALID_PARAMS`), with a message beginning `denied by cedar policy` |
| `approve_deploy` | JSON-RPC error `-32602`, message `confirmation required: deploy needs a human` |

The last call is refused because this configuration has no `approval` store. To queue it for an operator, use the confirmation walkthrough below. Check the JSON-RPC body when testing; an HTTP success status alone does not mean the tool was allowed.

## Configuration and request mapping

`cedar_policies` belongs under `origins.<host>.action`, beside `rbac_policies` and `federated_servers`.

| Field | Meaning |
|---|---|
| `policies` | Required Cedar source containing one or more `permit` or `forbid` statements. Empty source, invalid syntax, and schema validation errors prevent the MCP action from being constructed. |
| `schema_override` | Optional Cedar schema source appended to the default schema. New names must not collide with default types or actions. Declaring a type does not populate entities or request attributes. |

The built-in schema declares `Agent`, `AgentClass`, `User`, `Group`, `Server`, `Tool`, `ToolInvocation`, and `ArgumentBinding`. It also declares actions for initialization, tool listing, and ping, but the live Cedar hook evaluates `tools/call` only.

| Cedar input | Value on the HTTP tool-call path |
|---|---|
| `principal` | `Agent::"anonymous"`. The generic hook can construct `Agent::"<agent_id>"`, but this dispatcher currently passes no agent ID. Inbound authentication and identity headers do not change that Cedar input. |
| `action` | `Action::"MCP::CallTool"` |
| `resource` | `ToolInvocation::"<server>/<advertised_tool_name>"` |
| `context` | Empty |
| Entity store | Empty: there are no agent attributes, ancestor relationships, tool attributes, or argument entities to read. |

`<server>` is the federated server's `prefix`, or the name derived from its origin when no prefix is set. Use an explicit prefix to make policy resource IDs easier to maintain. Read the advertised names from `tools/list`:

| Federation naming | Advertised tool | Cedar resource |
|---|---|---|
| `prefix: demo`, default `namespace: on_collision`, one server | `search_repos` | `ToolInvocation::"demo/search_repos"` |
| `prefix: demo`, `namespace: always` | `demo.search_repos` | `ToolInvocation::"demo/demo.search_repos"` |

`principal in AgentClass::"trusted"` cannot match an ancestor relationship with the current empty store. Attribute expressions such as `resource.tool.name` may be valid against the schema but fail during evaluation because the referenced entity is absent. Cedar logs evaluation diagnostics and still returns its overall decision; an errored `forbid` does not reliably block a separate matching `permit`. Write UID comparisons for this hook. Use [MCP argument and result policies](mcp-security.md) when the decision needs `mcp.arguments`, `mcp.principal`, or result data.

## Policy examples and precedence

For a strict allowlist, omit the catch-all permit and allow only named resources:

```cedar
permit(
  principal,
  action == Action::"MCP::CallTool",
  resource == ToolInvocation::"demo/search_repos"
);
```

Every other tool is denied by default. RBAC must still allow `search_repos` before Cedar can evaluate it.

For a broad allow with exceptions, use the quickstart's catch-all `permit`, then add `forbid` rules for the resources to block. `@confirm` is an SBproxy annotation on a `forbid`; Cedar itself still evaluates that statement as a forbid.

| Matching policies | SBproxy verdict |
|---|---|
| At least one permit, no matching forbid | Allow |
| No matching permit and no matching forbid | Deny |
| Any matching plain forbid | Deny, even if a permit or an annotated forbid also matches |
| One or more matching forbids, all annotated `@confirm` | Confirm |

An empty `@confirm("")` reason becomes `cedar policy requires confirmation`. If several annotated forbids match, the reported reason comes from one matching policy; do not depend on which one is selected. Adding the annotation to a permit does not make that permit require approval.

RBAC denial, a failed argument policy, and an exceeded quota stop the call before Cedar. Cedar can restrict a call those checks allowed. Local tools execute through a separate dispatcher and bypass the Cedar hook, so use OpenAPI-backed or remote MCP tools when testing Cedar enforcement.

## Confirmation: queue, inspect, approve, retry

Stop the quickstart gateway, keep the mock upstream running, and start [examples/cedar-confirm-flow](../examples/cedar-confirm-flow/):

```bash
sbproxy validate examples/cedar-confirm-flow/sb.yml
sbproxy serve -f examples/cedar-confirm-flow/sb.yml
```

It uses the same tool definitions and Cedar policies, with these additions:

<!-- sbproxy-config-excerpt -->
```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9900
  alerting:
    channels:
      - type: log

origins:
  "mcp.example.com":
    action:
      type: mcp
      approval:
        store: /tmp/sbproxy-cedar-confirm-approvals.json
        hold_ttl: 15m
      # Keep the Cedar policies, RBAC, and federation from the example.
```

`approval.store` names the persistent JSON approval file. Its path must be writable by SBproxy. The temporary path above is for the demo; choose a durable path for deployment. `hold_ttl` defaults to 15 minutes and controls how long an unanswered hold remains pending. Expiry drops the hold without authorizing the call.

Keep `approve_deploy` out of `approval.tools` for this walkthrough. That selector queues matching tools before Cedar runs; the store alone is enough to queue a Cedar Confirm verdict.

Initialize the new gateway with the `mcp` helper, then capture the hold:

```bash
mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cedar-demo","version":"1.0.0"}}}' | jq .
held=$(mcp '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"approve_deploy","arguments":{}}}')
printf '%s\n' "$held" | jq .
hold_id=$(printf '%s\n' "$held" | jq -er '.error.data.hold_id')
```

The response has `error.code: -32097` and `error.data` containing `hold_id`, `snapshot`, and `expires_at` (Unix seconds). The HTTP request finishes immediately. A retry while the same hold is pending returns that hold rather than creating another.

The example uses the local admin credentials `admin:changeme`. Use your configured admin credentials outside this demo. List holds and approve the captured ID:

```bash
curl -fsS -u admin:changeme http://127.0.0.1:9900/api/mcp/approvals | jq .
curl -fsS -u admin:changeme -X POST \
  "http://127.0.0.1:9900/api/mcp/approvals/${hold_id}/approve" \
  -H 'Content-Type: application/json' \
  --data '{"approved_by":"alice"}' | jq .
```

The list response contains `enabled`, `holds`, and `console_page`. Each hold includes its ID, origin, tool name, principal and tenant IDs, snapshot, reason, state, and timestamps. The same queue is available at `/admin/ui/mcp-approvals`.

Retry the original tool call:

```bash
mcp '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"approve_deploy","arguments":{}}}' | jq .
```

Approval authorizes one matching retry. It is bound to the content snapshot, which includes the tool contract digest and canonical arguments, and the approval lookup also matches the origin, principal, and tenant. A changed contract or argument set cannot consume that decision. After the approved call, another invocation requires a new approval. A plain Cedar forbid still denies after approval.

To try denial, call the tool again to create a new hold, then deny its ID:

```bash
held=$(mcp '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"approve_deploy","arguments":{}}}')
hold_id=$(printf '%s\n' "$held" | jq -er '.error.data.hold_id')
curl -fsS -u admin:changeme -X POST \
  "http://127.0.0.1:9900/api/mcp/approvals/${hold_id}/deny" \
  -H 'Content-Type: application/json' \
  --data '{"approved_by":"alice"}' | jq .
```

Denying deletes the row. Retrying the same snapshot then creates a fresh hold; denial is not a persistent tool ban. Use a plain Cedar forbid or RBAC rule for that.

A fresh Cedar Confirm hold triggers `mcp_confirm` at warning severity on the configured `proxy.alerting` channels. Retries that join an existing hold do not emit another alert. The per-origin `approval.webhook` is a separate, SSRF-checked POST with hold metadata and no arguments or secrets. It can notify an operator even when `proxy.alerting` was not installed at startup.

## Replay policy changes before reload

`sbproxy cedar replay` evaluates a JSONL sample without starting a proxy or calling upstream tools. It compiles one origin's Cedar source with the same merged schema as the live action. It does not execute RBAC, quotas, argument policies, or the approval queue.

Each nonblank, noncomment line is one sample. Lines beginning with `#` are comments:

```jsonl
{"id":"search","principal":"Agent::\"anonymous\"","resource":"ToolInvocation::\"demo/search_repos\"","expected":"allow"}
{"id":"delete","principal":"Agent::\"anonymous\"","resource":"ToolInvocation::\"demo/delete_repo\"","expected":"deny"}
{"id":"deploy","principal":"Agent::\"anonymous\"","resource":"ToolInvocation::\"demo/approve_deploy\"","expected":"confirm"}
```

| Field | Meaning |
|---|---|
| `principal` | Required Cedar UID. Use `Agent::"anonymous"` to model the current HTTP dispatcher. A supplied `Agent::"alice"` tests that hypothetical principal; it does not prove the gateway forwards an authenticated identity. |
| `resource` | Required Cedar UID matching the server and advertised tool name |
| `action` | Optional UID, default `Action::"MCP::CallTool"` |
| `id` | Optional report label; otherwise generated as `line-1`, `line-2`, and so on, counting parsed samples |
| `expected` | Optional `allow`, `deny`, or `confirm` assertion |

Save the JSONL above as `traffic.jsonl` and verify the quickstart's decisions:

```bash
sbproxy cedar replay -f examples/cedar-mcp-full/sb.yml \
  --against traffic.jsonl --format json
```

The JSON output has `rows`, `expected_mismatches`, and `changed`. Each row names the evaluated principal, action, resource, and verdict, with `reason` for Confirm. With `--baseline`, rows also carry the baseline verdict and a `changed` boolean.

The existing [replay example](../examples/cedar-replay/) changes search from Allow to Deny:

```bash
sbproxy cedar replay -f examples/cedar-replay/sb.yml \
  --against examples/cedar-replay/traffic.jsonl \
  --baseline examples/cedar-replay/baseline.yml
```

Expect exit 1 and `3 sample(s), 1 changed, 0 expected mismatch(es)`. The baseline comparison checks verdict labels only. Changing a Confirm reason while keeping the Confirm verdict does not count as a changed decision.

| Exit code | Meaning |
|---|---|
| `0` | All supplied expectations match, and no verdict label changed against the baseline |
| `1` | At least one expected label mismatched or a verdict label changed |
| `2` | Input could not be read or parsed, the sample was empty, origin selection failed, or Cedar/schema compilation failed |

A malformed Cedar UID in an otherwise valid JSONL sample becomes a Deny verdict during evaluation. It is not a JSONL parse error; with no expectation or baseline, that sample can still exit 0. Add `expected` labels when using replay as an assertion suite.

When multiple origins define Cedar, pass `--origin mcp.example.com` to select one in both configurations. Combining policies across origins would change their meaning, so replay requires this choice.

Use the existing plan/apply commands to review and deploy the configuration change:

```bash
sbproxy plan -f examples/cedar-replay/sb.yml \
  --against examples/cedar-replay/baseline.yml
```

A Cedar-only edit has blast radius **Reload**, with a path under `action.cedar_policies`. `sbproxy apply` reloads the configuration and recompiles the hook. See the [CLI manual](manual.md) for applying a plan to a running instance.

## Troubleshooting

| Symptom | Check |
|---|---|
| Every tool is denied | Confirm that Cedar has a matching permit and that the server's RBAC policy allows the tool. A collection of forbids alone still has Cedar's default deny. |
| A forbidden tool succeeds | Check whether its server is `type: local`, then compare the advertised name from `tools/list` with the full `ToolInvocation` UID. |
| A principal-specific rule never matches | The HTTP dispatcher currently supplies `Agent::"anonymous"`; use RBAC for authenticated caller restrictions. |
| Entity attributes produce diagnostic errors | The hook does not populate entities or context. Replace attribute access with supported UID comparisons or use MCP CEL/Rego policies for the richer call context. |
| `confirmation required:` appears without a hold ID | Add `approval.store` to the same MCP action to enable queuing. |
| A denied approval reappears | Denial removes the pending row; a retry creates another. Use a policy denial to block further attempts. |
| The approval queue reports `enabled: false` | The running pipeline has no MCP action with an approval store. Check the loaded configuration and the admin port. |
| No `mcp_confirm` notification | Check whether the call joined an existing pending hold, whether `approval.tools` queued it before Cedar, and whether alerting was configured at boot. |
| Replay refuses multiple origins | Supply `--origin` with the same hostname present in the proposed and baseline YAML. |
| Replay exits 0 despite unexpected denies | Add `expected` labels; without assertions or a baseline, successful evaluation alone is enough for exit 0. |

Cedar policies are authored in YAML. The embedded policy store is not connected to this MCP hook, and the admin console has no visual Cedar editor. SBproxy does not compile natural-language prompts into Cedar. See [the policy catalog](policy.md#nl-to-cedar-decision) for that boundary.

## See also

- [MCP federation](mcp.md) and [MCP security](mcp-security.md)
- [Configuration reference](configuration.md) for `cedar_policies` and `approval`
- [Scripting](scripting.md) for CEL and Rego policies over arguments and results
- [Gateway-originated approvals](../examples/mcp-approval-gate/) for holds configured without Cedar
- [A2A policy](a2a-gateway.md) for the separate agent-to-agent controls
