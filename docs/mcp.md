# MCP gateway

*Last modified: 2026-06-02*

SBproxy ships an MCP (Model Context Protocol) gateway that speaks
JSON-RPC 2.0 over HTTP POST. Configure the `mcp` action on an origin
and the proxy serves the canonical MCP method set (`initialize`,
`tools/list`, `tools/call`, `ping`), federates one or more upstream
MCP servers, and enforces gateway-level guardrails before any
`tools/call` is forwarded.

This page is operator-facing. For the higher-level pitch, see
[`features.md`](features.md).

## Wire shape

```
POST /  HTTP/1.1
Host: mcp.example.com
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "method": "initialize",
  "id": 1,
  "params": {}
}
```

`initialize` returns the server identity, the protocol version
(`2025-06-18`), and a capability advertisement. `tools/list` returns
the aggregated tool catalogue across every federated upstream.
`tools/call` routes by tool name to the owning upstream. `ping`
returns `"pong"`. Notifications (requests with no `id`) get no
response. Unknown methods return JSON-RPC error `-32601`
(`method_not_found`). See
`crates/sbproxy-extension/src/mcp/handler.rs:McpHandler` and
`crates/sbproxy-extension/src/mcp/types.rs` for the wire enums.

## Minimal config

```yaml
proxy:
  http_bind_port: 8080

origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: my-mcp
        version: "1.0.0"
      federated_servers:
        - origin: github.example.com
          prefix: gh
        - origin: postgres.example.com
          prefix: db
      guardrails:
        - type: tool_allowlist
          allow:
            - gh.search_repos
            - db.query
```

Adapted from `examples/mcp-federation/sb.yml`. The wire-format
struct is `McpActionConfig` in
`crates/sbproxy-modules/src/action/mcp.rs`.

## `mcp` action fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `gateway` | Only `gateway` is implemented today. Unknown values fail config validation. |
| `server_info.name` | string | `sbproxy-mcp` | Returned in `initialize` responses. |
| `server_info.version` | string | `0.1.0` | Returned in `initialize` responses. |
| `rbac_policies` | map<string, ToolAccessPolicy> | `{}` | Named tool-access labels referenced by `federated_servers[].rbac`. |
| `federated_servers` | list | required, non-empty | Upstream MCP servers to aggregate. |
| `guardrails` | list | `[]` | Gateway-level safety checks. |

### `federated_servers[]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `origin` | string | required | Bare hostname (normalised to `https://<host>/mcp`) or a full `https://...` URL. |
| `prefix` | string | derived from host | Namespace prefix applied to every tool from this upstream. Tools become `<prefix>.<tool>`. |
| `rbac` | string | unset | Label referencing a key in `rbac_policies`. Validated at config-load time. |
| `timeout` | duration | unset | Caps each `tools/call` dispatch. Accepts `250ms`, `10s`, `2m`. |
| `transport` | string | `streamable_http` | Either `streamable_http` or `sse`. |

A `rbac` value that does not match a key in `rbac_policies` is a hard
config error (see `McpAction::from_parsed` in
`crates/sbproxy-modules/src/action/mcp.rs`).

### `guardrails[]`

One entry type today, keyed by `type`:

```yaml
guardrails:
  - type: tool_allowlist
    allow: [gh.search_repos, db.query]
```

Multiple `tool_allowlist` entries are unioned. An empty `allow` list
denies every call. No guardrails means open access. Source:
`crates/sbproxy-modules/src/action/mcp.rs:McpGuardrailEntry`.

## Submodules

The gateway is built on `crates/sbproxy-extension/src/mcp/`. The
`mcp` action is a thin wrapper that translates YAML into calls into
that library. Each submodule below is operator-visible either
through a YAML knob or a runtime behaviour worth knowing about.

### `handler`: JSON-RPC dispatcher

Dispatches `initialize`, `tools/list`, `tools/call`, and `ping`.
Notifications return nothing. `initialize` answers with the configured
`server_info` plus a `capabilities` block. When the host origin has
`agent_skills:` configured, `capabilities.experimental.agentSkillsUrl`
is set to the absolute URL of
`/.well-known/agent-skills/index.json`; see
[`agent-skills.md`](agent-skills.md). Source:
`crates/sbproxy-extension/src/mcp/handler.rs:McpHandler`.

No direct YAML knobs. The `server_info` block on the action shapes
the response.

### `registry`: embedded tool catalogue

Backs the embedded handler with a static map of tool definitions and
their fulfilment strategy (`Static(value)` returns a fixed JSON
payload, `Proxy { origin }` forwards to another origin). Used when
SBproxy serves its own tools rather than federating; in the OSS build,
federation is the documented path. Source:
`crates/sbproxy-extension/src/mcp/registry.rs:ToolRegistry`.

### `types`: protocol envelopes

Defines `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError`, the
standard error codes (`-32600` through `-32700`), and the MCP `Tool`
shape. Source: `crates/sbproxy-extension/src/mcp/types.rs`.

### `federation`: aggregate upstream catalogues

Fetches `tools/list` from every entry under `federated_servers` and
merges the results into one registry. Tool-name collisions are
resolved by prefixing the later entry with its server name. The
catalogue is stored in an `ArcSwap` so refreshes do not block
in-flight `tools/call` traffic. Source:
`crates/sbproxy-extension/src/mcp/federation.rs:McpFederation`.

Refresh failures on one upstream are logged at `error` level and the
remaining upstreams still contribute to the merged catalogue.

### `streamable`: Streamable HTTP transport

Default transport for upstreams. POST sends the JSON-RPC request;
the server may answer with `application/json` or
`text/event-stream`. Supports JSON-RPC batching via `send_batch`.
Selected with `transport: streamable_http` (or omit `transport`
entirely). Source:
`crates/sbproxy-extension/src/mcp/streamable.rs:send_request`.

### `sse_client`: legacy SSE transport

For upstreams that expose the older SSE handshake. Selected with
`transport: sse`. The client posts to the SSE URL and parses events
out of the response body; if the upstream replies with the two-leg
handshake (an `endpoint` event followed by a POST to that endpoint),
the client handles that path too. Source:
`crates/sbproxy-extension/src/mcp/sse_client.rs:send_via_sse`.

### `access_control`: principal-aware tool ACL

`ToolAccessPolicy` is the per-upstream ACL that gates every
`tools/call` and filters `tools/list`. The policy reads off the
inbound `Principal` (tenant, virtual key, team, project, role, sub),
walks an ordered `tool_access[]` rule list, and either allows or
denies the named tool. The policy is **default-deny**: an unknown
caller (no matching rule) is denied; an empty `allowed: []` is
"deny all". Operators who want the legacy open-by-default behaviour
add `default_allow: true` to the policy.

The legacy `key_permissions: { key: [tools] }` shape is gone.
See [`migration-mcp-rbac.md`](migration-mcp-rbac.md) for upgrade
walk-throughs.

#### Per-team allowlist

```yaml
rbac_policies:
  read_only:
    default_allow: false
    tool_access:
      - principals:
          - team: frontend            # exact match on attrs.team
            tenant_id: acme           # exact match on tenant_id
        allowed: [search_docs, list_projects]
      - principals:
          - role: admin               # any of attrs.roles
        allowed: ["*"]
federated_servers:
  - origin: github.example.com
    prefix: gh
    rbac: read_only
```

#### Virtual-key glob

```yaml
rbac_policies:
  frontend:
    default_allow: false
    tool_access:
      - principals:
          - virtual_key: vk_frontend_*    # trailing-* glob
        allowed: [search, list_projects]
```

#### Legacy open behaviour

```yaml
rbac_policies:
  legacy_open:
    default_allow: true               # opt back in to allow-by-default
```

#### `tools/list` RBAC filter

`tools/list` now returns only the subset of the federated catalogue
the inbound principal can call. The legacy schema returned the full
catalogue even when the matching `tools/call` would be denied,
leaking tool names to callers that could not invoke them.

#### Per-tool quotas

`tool_quotas[]` enforces sliding-window quotas keyed on
`(tenant_id, principal_id, tool_name)`. A caller over quota gets
JSON-RPC error code `-32099`; the upstream is never contacted.

```yaml
rbac_policies:
  ops:
    default_allow: false
    tool_access:
      - principals:
          - role: admin
        allowed: ["*"]
    tool_quotas:
      - tool_name: delete_user
        principals:
          - team: frontend
        rate:
          per: 24h                   # accepts ms / s / m / h / d
          max: 5
```

The store is per-action and lives in process memory; SIGHUP reload
rebuilds the action and resets the counters.

Source: `crates/sbproxy-extension/src/mcp/access_control.rs:ToolAccessPolicy`.

### `guardrails`: blocklist and arg-size limits

`McpGuardrailConfig` holds a blocked-tool list and a maximum
serialised argument size. The gateway action exposes the
`tool_allowlist` form in YAML; the blocklist and arg-size forms are
available to plugin authors but have no top-level YAML knob in the
OSS action today. Source:
`crates/sbproxy-extension/src/mcp/guardrails.rs:check_tool_invocation`.

### `code_mode`: schema compression

`compress_tool_schema` walks a tool schema and strips `description`
and `examples` keys at every level. The function is wired by the
runtime when payload-size pressure justifies the trade-off; there is
no top-level YAML knob today. Source:
`crates/sbproxy-extension/src/mcp/code_mode.rs:compress_tool_schema`.

### `context_opt`: usage-weighted tool prioritisation

`ToolUsageTracker` counts invocations per tool and exposes
`filter_by_budget(tools, max_tokens)`, which returns the
most-frequently-used tools that fit a token budget (4-chars-per-token
approximation). Used internally to trim oversized catalogues; no
YAML knob today. Source:
`crates/sbproxy-extension/src/mcp/context_opt.rs:ToolUsageTracker`.

### `openapi_convert`: OpenAPI to MCP

`openapi_to_mcp_tools(spec)` converts an OpenAPI 3.x JSON spec into a
list of MCP tool definitions. Each `path + method` becomes one tool;
`operationId` becomes the tool name, `summary` or `description`
becomes the tool description, and `parameters` build the
`inputSchema`. Source:
`crates/sbproxy-extension/src/mcp/openapi_convert.rs:openapi_to_mcp_tools`.

Used by `rest_to_mcp`. No direct YAML knob.

### `rest_to_mcp`: wrap REST APIs as MCP servers

`RestToMcpConfig { base_url, openapi_spec }` plus
`create_mcp_handler(config)` turns an OpenAPI service into an MCP
tool catalogue. Tool execution returns a request descriptor
(`url`, `method`, `args`) for the caller to dispatch; the conversion
is intentionally synchronous so callers control the HTTP I/O. Source:
`crates/sbproxy-extension/src/mcp/rest_to_mcp.rs`.

### `audit`: structured audit log

Every tool invocation produces an `McpAuditEntry` (timestamp, tool
name, server name, caller ID, arguments, result status, duration)
emitted at INFO level under the tracing target `mcp_audit`. Filter
this target separately in your log pipeline to route MCP audit
events to long-term storage. Source:
`crates/sbproxy-extension/src/mcp/audit.rs:McpAuditEntry`.

No YAML knob; emission is unconditional.

### `spans`: tracing spans

`tool_call_span(tool_name, server_name)` opens a tracing span named
`mcp.tool_call` with `tool` and `server` fields. These spans show
up alongside regular proxy request spans in any OTLP / Jaeger
backend. Source:
`crates/sbproxy-extension/src/mcp/spans.rs:tool_call_span`.

## End-to-end example

The full happy path lives at
[`examples/mcp-federation/sb.yml`](../examples/mcp-federation/sb.yml).
That fixture covers federated upstreams, prefix namespacing,
`tool_allowlist`, and a curl recipe for `initialize`, `tools/list`,
and `tools/call`.

## See also

- [`migration-mcp-rbac.md`](migration-mcp-rbac.md): upgrade
  walk-through for the principal-aware ACL and default-deny
  flip.
- [`agent-skills.md`](agent-skills.md): Agent Skills manifest
  advertised via `experimental.agentSkillsUrl`.
- [`features.md`](features.md): feature overview that covers the
  MCP gateway in context.
- [`scripting.md`](scripting.md): CEL, Lua, JavaScript, and WASM
  hooks that shape MCP requests before dispatch.
