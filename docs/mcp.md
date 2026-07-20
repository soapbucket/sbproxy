# MCP gateway

*Last modified: 2026-07-19*

SBproxy ships an MCP (Model Context Protocol) gateway that speaks
JSON-RPC 2.0 over HTTP POST. Configure the `mcp` action on an origin
and the proxy serves the MCP method set (`initialize`, `tools/list`,
`tools/call`, `resources/list`, `resources/read`, `ping`), federates
one or more upstream MCP servers, and enforces gateway-level
guardrails before any `tools/call` is forwarded.

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

`initialize` negotiates the protocol version (see below) and returns
the server identity plus a capability advertisement. `tools/list`
returns the aggregated tool catalogue across every federated upstream.
`tools/call` routes by tool name to the owning upstream.
`resources/list` and `resources/read` pass the federated resource
surface through (the OpenAI Apps SDK / SEP-1865 UI-template path).
`ping` returns `"pong"`. Notifications (requests with no `id`) get a
`202 Accepted`. Unknown methods return JSON-RPC error `-32601`
(`method_not_found`). The gateway serves this from
`crates/sbproxy-core/src/server/action_dispatch.rs`
(`handle_mcp_action`); the wire enums are in
`crates/sbproxy-extension/src/mcp/types.rs`.

## Protocol version negotiation

The gateway serves the revisions in `SUPPORTED_PROTOCOL_VERSIONS`
(`2025-06-18` today). On `initialize` it echoes the client's requested
`protocolVersion` when it is supported, otherwise it answers with the
newest revision it does support and lets the client decide whether to
continue. A post-initialize request carrying an unsupported
`MCP-Protocol-Version` header gets a `400`; a missing header follows
the spec's assumed-version rule. `2025-03-26` is deliberately absent:
that revision requires servers to accept JSON-RPC batches, which this
gateway does not, so a batch body returns a specific invalid-request
error rather than a silent mis-negotiation.

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
| `progressive_discovery` | bool | `false` | Advertise `search` / `execute` meta-tools instead of the full catalogue (see [`examples/mcp-progressive-discovery`](../examples/mcp-progressive-discovery)). |
| `oauth` | object | unset | RFC 9728 auth discovery (see the OAuth section below and [`examples/mcp-oauth-discovery`](../examples/mcp-oauth-discovery)). |
| `sessions` | object | unset | Streamable HTTP session management: `{enabled, ttl}` (see [`examples/mcp-sessions`](../examples/mcp-sessions)). |
| `egress` | object | unset | Default OpenAPI REST egress policy. See [mcp-archestra-guardrails.md](mcp-archestra-guardrails.md). |
| `token_compaction` | object | unset | Opt-in compaction for large MCP text result blocks. |
| `dual_llm_quarantine` | object | unset | Opt-in dual-LLM judge quarantine for untrusted MCP text result blocks (`enabled`, `endpoint`, optional `model` / `timeout`). Fail closed; reason-code only. |
| `refresh_interval` | duration | `60s` | How often the background task re-fetches upstream catalogues. Inbound requests always serve the cached snapshot; this is the only steady-state fan-out. |
| `upstream_connect_timeout` | duration | `5s` | TCP connect deadline per upstream exchange. |
| `upstream_timeout` | duration | `30s` | Whole-request deadline per upstream exchange (refreshes, calls, reads). Per-server `timeout:` can only shorten it for `tools/call`. |
| `max_upstream_response_bytes` | integer | `8388608` | Cap on upstream response bytes buffered per exchange. |
| `tool_versioning` | object | unset | Version-bump gate plus the tool rollout plane (`rollout:` publishes several versions of one tool, resolved per consumer). See [tool-versioning.md](tool-versioning.md). |
| `tool_pricing` | map<string, float> | `{}` | Per-tool USD cost for the usage-sink attribution. |
| `usage_sinks` | list | `[]` | Sinks for MCP tool-call usage rows (same shapes as the AI path). |

### `federated_servers[]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `origin` | string | required | For an `mcp` server, a bare hostname (normalised to `https://<host>/mcp`) or a full URL. For an `openapi` server, the REST base URL. |
| `type` | string | `mcp` | `mcp` speaks MCP to the origin; `openapi` derives tools from a spec and dispatches `tools/call` as REST (see the OpenAPI section below). |
| `spec` / `spec_path` | object / string | unset | Inline OpenAPI spec or a path to one, for a `type: openapi` server. Read at config load; a bad spec fails startup. |
| `prefix` | string | derived from host | Namespace prefix applied to every tool from this upstream. Tools become `<prefix>.<tool>`. |
| `rbac` | string | unset | Label referencing a key in `rbac_policies`. Validated at config-load time. Enforced on every `tools/call`. |
| `timeout` | duration | unset | Caps each `tools/call` dispatch. Accepts `250ms`, `10s`, `2m`. |
| `transport` | string | `streamable_http` | `streamable_http`, `sse`, or supervised local `stdio`. |
| `command` / `args` | string / list | unset | Required command and optional arguments for `transport: stdio`. |
| `egress` | object | inherited | Per-server OpenAPI REST egress policy. |
| `run_as_user_auth` | bool | `false` | Mint per-caller upstream `Authorization` via `upstream_auth` (never tool args). |
| `upstream_auth` | object | unset | Required when `run_as_user_auth` is true. See [mcp-archestra-guardrails.md](mcp-archestra-guardrails.md). |

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

## Progressive discovery

Set `progressive_discovery: true` and `tools/list` advertises exactly
two meta-tools, `search` and `execute`, instead of the full federated
catalogue. The agent calls `search` with a `query` to find relevant
tools, then `execute` with a tool `name` and `arguments` to invoke
one. This keeps a large catalogue out of the model's context window.
See [`examples/mcp-progressive-discovery`](../examples/mcp-progressive-discovery).

## OAuth auth discovery (RFC 9728)

With an `oauth` block, the gateway serves OAuth 2.0 Protected Resource
Metadata at `/.well-known/oauth-protected-resource`, advertises a
pointer to it in the discovery manifest, and challenges a
credential-less MCP request with a `401` whose `WWW-Authenticate`
header names that metadata URL, which is where the MCP auth discovery
flow begins.

```yaml
oauth:
  authorization_servers: ["https://issuer.example.com"]
  scopes_supported: ["mcp.read", "mcp.call"]
```

Token validation itself stays in the generic auth layer; this block
only drives discovery and the challenge. A request that already
carries an `Authorization` header is never re-challenged. See
[`examples/mcp-oauth-discovery`](../examples/mcp-oauth-discovery).

## OpenAPI-backed servers

A `federated_servers[]` entry with `type: openapi` turns an existing
REST API into governed MCP tools with no code: the gateway derives the
tools from an OpenAPI spec and dispatches each `tools/call` as a REST
request against the `origin`, substituting `{path}` parameters from the
arguments and sending the rest as a query string (GET) or JSON body.
The spec is read at config load (from inline `spec:` or `spec_path:`),
so a bad or missing spec fails startup rather than the hot path. These
tools live in the same registry as native MCP tools, so RBAC, quotas,
the version gate, and usage attribution all apply.

```yaml
federated_servers:
  - type: openapi
    origin: "https://api.internal"
    spec_path: "petstore.openapi.yaml"
    prefix: pets
```

## Sessions

With `sessions.enabled`, the gateway issues an `Mcp-Session-Id` on
`initialize`, requires it on every later request (`400` when missing,
`404` when unknown or expired, the client's cue to re-initialize), and
ends a session on `DELETE`. A GET with `Accept: text/event-stream`
opens the server-to-client stream that delivers
`notifications/tools/list_changed` and
`notifications/resources/list_changed` when the federated catalogue
changes, which is what the `listChanged` capability advertises. Off by
default: the gateway is otherwise stateless. See
[`examples/mcp-sessions`](../examples/mcp-sessions).

## Usage attribution

Every `tools/call` records dispatch count and duration on
`sbproxy_mcp_tool_dispatch_*`. With a `tool_pricing` map, the resolved
USD cost also lands on `sbproxy_mcp_tool_cost_usd_total`, and with
`usage_sinks` configured the gateway emits one usage row per call
(provider `mcp`, the owning server as the model, the caller's
principal and tenant, latency, cost) into the same sink stream as
model spend, so tool spend is queryable next to it. Code-mode calls
(from the emitted `codemode.ts` runtime) are attributed to the
code-execution sandbox in the session ledger.

## Submodules

The gateway is built on `crates/sbproxy-extension/src/mcp/`. The
`mcp` action is a thin wrapper that translates YAML into calls into
that library. Each submodule below is operator-visible either
through a YAML knob or a runtime behaviour worth knowing about.

### JSON-RPC dispatcher

Dispatches `initialize`, `tools/list`, `tools/call`, `ping`,
`resources/list`, and `resources/read`. Notifications (no `id`) get a
`202 Accepted`. `initialize` answers with the configured `server_info`
plus a `capabilities` block; it negotiates the protocol version and,
when the host origin has `agent_skills:` configured, sets
`capabilities.experimental.agentSkillsUrl` to the absolute URL of
`/.well-known/agent-skills/index.json` (see
[`agent-skills.md`](agent-skills.md)). The dispatcher lives in the
runtime, not the extension library:
`crates/sbproxy-core/src/server/action_dispatch.rs`
(`handle_mcp_action`). The `federation` submodule below holds the tool
aggregation, transports, and the injectable-source registry it calls
into.

No direct YAML knobs. The `server_info` block on the action shapes
the response.

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

### `openapi_convert` + `rest_to_mcp`: OpenAPI-backed servers

`openapi_to_mcp_tools(spec)` converts an OpenAPI 3.x spec into MCP
tool definitions and `openapi_to_routes(spec)` derives the matching
`name -> (method, path)` routing table. A `federated_servers[]` entry
with `type: openapi` uses both: the gateway serves the derived tools
and dispatches `tools/call` as REST against the origin (see the
OpenAPI section above). Source:
`crates/sbproxy-extension/src/mcp/openapi_convert.rs`.

### Prompt-linked audit

When a subscriber is attached to the `mcp_audit` tracing target (the
enterprise audit layer), each `tools/call` emits an `mcp_audit` event
carrying the tool name, arguments, the SEP-1865 `params.audit.cause`
when present, the upstream status, and the duration. The event is
gated on that subscriber, so an OSS-only deployment pays nothing;
there is no separate YAML knob. The per-call spend and behavioural
record live in the session ledger below, not this event. Source:
`emit_mcp_prompt_audit` in
`crates/sbproxy-core/src/server/action_dispatch.rs`.

## Session ledger

SBproxy sits on the `tools/call` path, so it can record what an agent
did at the tool boundary, which tools, in what order, with what
arguments, instead of leaving you to reconstruct it from a transcript.
With the ledger enabled, each call appends one record to a session
ledger: an append-only, newline-delimited JSON (NDJSON) artifact that
behavioral evaluation can query directly. The record shape is the
canonical `session-ledger-v1` schema shared with mcptest, so a
production capture and an mcptest run speak the same format.

A ledger is one `header` record per session followed by one `tool_call`
record per call, in call order:

```json
{"type":"header","schema_version":"v1","session_id":"01J0...","started_at":"2026-06-05T12:00:00Z"}
{"type":"tool_call","session_id":"01J0...","agent_id":"planner","hop_index":0,"tool_name":"get_weather","server":"weather","params":{"city":"sf"},"result":{"content":[...]},"is_error":false,"started_at":"2026-06-05T12:00:01Z","duration_ms":42,"caller":"direct"}
```

Each record carries the session id, the zero-based `hop_index` (the
call's position in the session), the bare tool name and its server, the
redacted arguments and result, an error flag, and the round-trip
duration. `agent_id` comes from the resolved caller principal and is set
on multi-agent runs. `params` and `result` are redacted with the same
secret-stripping the access log uses, so keys and tokens never reach the
artifact.

Turn it on with a top-level `session_ledger:` block:

```yaml
session_ledger:
  enabled: true
  sink: file          # `logging` (default) or `file`
  path: ./ledger.ndjson   # required for `sink: file`
```

`sink: logging` emits each record as a structured `session_ledger`
tracing line, so an existing log pipeline captures the ledger with no
extra wiring. `sink: file` appends NDJSON to `path`, giving a single
developer the same `*.ndjson` artifact mcptest writes. When the block is
absent or `enabled: false`, the `tools/call` path pays a single atomic
load and emits nothing.

## End-to-end example

The full happy path lives at
[`examples/mcp-federation/sb.yml`](../examples/mcp-federation/sb.yml).
That fixture covers federated upstreams, prefix namespacing,
`tool_allowlist`, and a curl recipe for `initialize`, `tools/list`,
and `tools/call`. [use-case-mcp-federation.md](use-case-mcp-federation.md)
walks through that same fixture end to end, including a real
`type: openapi` upstream that runs with no external dependency.

## See also

- [`use-case-mcp-federation.md`](use-case-mcp-federation.md): the
  solution guide — problem, RBAC allowlist, and next steps.
- [`migration-mcp-rbac.md`](migration-mcp-rbac.md): upgrade
  walk-through for the principal-aware ACL and default-deny
  flip.
- [`agent-skills.md`](agent-skills.md): Agent Skills manifest
  advertised via `experimental.agentSkillsUrl`.
- [`features.md`](features.md): feature overview that covers the
  MCP gateway in context.
- [`scripting.md`](scripting.md): CEL, Lua, JavaScript, and WASM
  hooks that shape MCP requests before dispatch.
