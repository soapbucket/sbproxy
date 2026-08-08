# Manage SBproxy over MCP

*Last modified: 2026-08-08*

SBproxy can serve its own admin API as MCP tools. Point an MCP client
such as Claude Code or Cursor at the gateway and the agent can check
health, read the running config, and inspect spend by calling
`sbproxy.get_health` or `sbproxy.get_config` instead of you shelling
out to curl with an admin credential in the command line.

No separate MCP server is involved. The gateway already knows how to
turn an OpenAPI spec into MCP tools (a `type: openapi` federated
server, see [mcp.md](mcp.md#openapi-backed-servers)), and it already
runs an admin API. This page wires the two together: an `mcp` origin
federates an OpenAPI-backed server whose REST base URL is the
gateway's own admin listener. Every `tools/call` becomes a REST
request from the gateway to itself, carrying the admin credential
that the MCP client never sees.

## Where the spec comes from

The admin server emits an OpenAPI document at `/api/openapi.json`,
but that document describes the data plane: the routes the gateway
proxies, derived from its live configuration (see
[openapi-emission.md](openapi-emission.md)), with nothing in it about
the admin control plane.

So the config below declares the spec by hand: a curated subset of
the admin API, one operation per tool, with paths and methods drawn
from [admin-api-reference.md](admin-api-reference.md). Hand-declaring
the subset earns its keep. The spec is the tool catalog, so the
operator decides exactly which admin operations an agent can even
see, before RBAC says a word.

## The config

The runnable example lives at
[`examples/admin-mcp/`](../examples/admin-mcp/sb.yml):

<!-- sbproxy-config: examples/admin-mcp/sb.yml -->
```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
    username: admin
    password: ${SBPROXY_ADMIN_PASSWORD:-admin-mcp-demo}

origins:
  # Keyed on `localhost` so a local MCP client (Claude Code, Cursor)
  # can connect to http://localhost:8080/ directly; the router strips
  # the port from the Host header before matching.
  "localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: sbproxy-admin
        version: "1.0.0"
      # Default-deny RBAC. `admin_read_only` (applied below) allows
      # only the read tools; `admin_operator` is declared for the
      # explicit opt-in and additionally allows `reload_config`.
      rbac_policies:
        admin_read_only:
          default_allow: false
          tool_access:
            - principals: []
              allowed:
                - sbproxy.get_health
                - sbproxy.get_health_targets
                - sbproxy.get_stats
                - sbproxy.get_spend
                - sbproxy.get_config
                - sbproxy.get_drift
        admin_operator:
          default_allow: false
          tool_access:
            - principals: []
              allowed:
                - sbproxy.get_health
                - sbproxy.get_health_targets
                - sbproxy.get_stats
                - sbproxy.get_spend
                - sbproxy.get_config
                - sbproxy.get_drift
                - sbproxy.reload_config
      federated_servers:
        - type: openapi
          # The gateway's own admin listener. Loopback-only by
          # default, so the egress policy below opts in to private
          # addresses for exactly this host.
          origin: http://127.0.0.1:9090
          prefix: sbproxy
          namespace: always
          rbac: admin_read_only
          timeout: 10s
          egress:
            mode: deny_by_default
            hosts: ["127.0.0.1"]
            allow_private: true
          # The admin API accepts HTTP Basic auth. The static header
          # rides on every dispatched REST call; the MCP client never
          # sees or supplies it. The default pairs with the demo
          # password above; export both variables for real use.
          headers:
            authorization: "Basic ${SBPROXY_ADMIN_MCP_BASIC:-YWRtaW46YWRtaW4tbWNwLWRlbW8=}"
          # Curated subset of the admin control plane, one operation
          # per tool. Paths and methods match
          # docs/admin-api-reference.md.
          spec:
            openapi: "3.0.0"
            info:
              title: SBproxy admin API (curated subset)
              version: "1.0"
            paths:
              "/api/health":
                get:
                  operationId: get_health
                  summary: Aggregate proxy liveness summary.
              "/api/health/targets":
                get:
                  operationId: get_health_targets
                  summary: >-
                    Per-target health: probe state, outlier ejection,
                    breaker state, in-flight connections.
              "/api/stats":
                get:
                  operationId: get_stats
                  summary: Request-log statistics summary.
              "/api/usage/spend":
                get:
                  operationId: get_spend
                  summary: Spend summary over a trailing window.
                  parameters:
                    - name: window
                      in: query
                      required: false
                      description: "Trailing window, e.g. 1h or 24h."
                      schema:
                        type: string
              "/admin/config":
                get:
                  operationId: get_config
                  summary: >-
                    Read the loaded config file. Inline plaintext
                    secrets are redacted before the response leaves
                    the admin server.
              "/admin/drift":
                get:
                  operationId: get_drift
                  summary: >-
                    Compare the loaded config against the on-disk
                    file.
              "/admin/reload":
                post:
                  operationId: reload_config
                  summary: >-
                    Hot-reload the config from disk. Mutating; denied
                    by the default read-only policy.
      guardrails:
        # Second, coarser gate on top of RBAC: even an RBAC-allowed
        # tool must appear here to be forwarded. `reload_config` is
        # deliberately absent; add it here AND switch `rbac:` to
        # `admin_operator` to enable mutation.
        - type: tool_allowlist
          allow:
            - sbproxy.get_health
            - sbproxy.get_health_targets
            - sbproxy.get_stats
            - sbproxy.get_spend
            - sbproxy.get_config
            - sbproxy.get_drift
```

Start it:

```bash
make run CONFIG=examples/admin-mcp/sb.yml
```

## Each component

**`proxy.admin`** enables the admin server on `127.0.0.1:9090`. The
password interpolates from `SBPROXY_ADMIN_PASSWORD` with a demo-only
default. The admin listener binds loopback-only by default, which is
exactly what this setup wants: the only client it needs is the
gateway itself.

**The `mcp` origin** is keyed on `localhost`, so a local MCP client
can connect to `http://localhost:8080/` directly; the router strips
the port from the inbound Host header before matching. The action
speaks MCP JSON-RPC on the data-plane port and answers `initialize`
and `tools/list` locally.

**`federated_servers[]` with `type: openapi`** is the bridge. Its
`origin` is the admin listener's base URL, its `spec` is the curated
admin subset, and each declared operation becomes one tool
(`operationId` names it). A `tools/call` dispatches as a REST request
against the admin port, substituting path parameters and sending
remaining arguments as the query string (GET) or JSON body.
`namespace: always` plus `prefix: sbproxy` gives every tool the
`sbproxy.` prefix the policies below match on.

**`headers`** carries the admin credential. The admin API accepts
HTTP Basic auth, so the server declares a static `authorization`
header whose value resolves from the environment at config load
(`${SBPROXY_ADMIN_MCP_BASIC}`, a base64-encoded `user:password`
pair). The header rides on every dispatched REST call and never
appears in tool arguments, tool results, or anything the MCP client
holds. Static headers are only accepted on `type: openapi` servers,
and configuring an `authorization` header together with
`run_as_user_auth` is a config error, so there is exactly one
credential source per server.

**`egress`** pins the blast radius. `deny_by_default` with
`hosts: ["127.0.0.1"]` and `allow_private: true` means the only
destination this server can ever dial is the local admin listener. A
redirect answer pointing anywhere else is refused before a second
connection is made.

**`rbac_policies` + `guardrails`** scope the tool set; the next
section walks through them.

## Tool scoping

Two independent gates sit between the agent and the admin API, and
both are default-deny:

1. **RBAC.** The server carries `rbac: admin_read_only`, a
   default-deny policy allowing exactly six read tools: `get_health`,
   `get_health_targets`, `get_stats`, `get_spend`, `get_config`, and
   `get_drift` (all under the `sbproxy.` prefix). A second policy,
   `admin_operator`, is declared in the same file but applied
   nowhere; it additionally allows `sbproxy.reload_config`.
2. **The `tool_allowlist` guardrail.** A coarser gate on top of RBAC
   listing the same six read tools. Even an RBAC-allowed tool must
   also appear here to be forwarded, and the allowlist filters
   `tools/list` too.

The spec deliberately declares one mutating operation,
`reload_config` (POST `/admin/reload`), that neither gate allows. The
result is the deny path you can demonstrate: the tool is absent from
`tools/list`, and a direct `tools/call` for it returns a JSON-RPC
error from the guardrail without any request reaching the admin port.

To expose mutation, opt in at both gates: switch the server's `rbac:`
label to `admin_operator`, and add `sbproxy.reload_config` to the
guardrail allowlist. Leaving either gate closed keeps the call
blocked. The same recipe extends to any other admin route: declare
the operation in the spec, then allow its tool name in both places.

## Security posture

**The agent never holds the admin credential.** The Basic header is
attached by the gateway on the outbound hop, from an env-interpolated
config value. Rotating the credential is an env change and a reload;
no MCP client config is touched.

**Read-only is the default because agents retry.** An agent that can
call `reload_config` or a future `write_config` tool can also call it
repeatedly, in a loop, on a misread error message. The read tools are
safe to hand to an unattended session; the mutating ones are an
explicit, two-gate opt-in an operator makes deliberately, per tool.

**The tool surface is a positive declaration three times over.** An
admin route becomes reachable only when (1) the spec declares it,
(2) RBAC allows it, and (3) the guardrail lists it. Adding a tool is
a config diff that names it in all three places, which is easy to
review and hard to do by accident.

**Demo defaults are for loopback demos.** The example ships a paired
demo password and header so it runs with zero exports, and the admin
server refuses default credentials once its surface is reachable off
loopback (see [admin.md](admin.md)). Export
`SBPROXY_ADMIN_PASSWORD` and `SBPROXY_ADMIN_MCP_BASIC` together for
anything real.

## Connecting Claude Code

Register the gateway as an HTTP MCP server, either from the CLI:

```bash
claude mcp add --transport http sbproxy-admin http://localhost:8080/
```

or in a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "sbproxy-admin": {
      "type": "http",
      "url": "http://localhost:8080/"
    }
  }
}
```

Claude Code performs the MCP initialize handshake, lists the tools,
and the six `sbproxy.*` read tools become callable in the session
like any other MCP tool. No credential goes into the client config;
the gateway attaches it upstream.

## Connecting Cursor

Cursor reads `.cursor/mcp.json` in the project (or `~/.cursor/mcp.json`
globally):

```json
{
  "mcpServers": {
    "sbproxy-admin": {
      "url": "http://localhost:8080/"
    }
  }
}
```

After Cursor connects, the tools appear in its MCP tool list under
the `sbproxy-admin` server and the agent can invoke them in chat and
agent mode.

## See also

- [mcp.md](mcp.md) - the MCP gateway: wire shape, `federated_servers[]` fields, OpenAPI-backed servers.
- [admin-api-reference.md](admin-api-reference.md) - every admin route, its auth requirement, and its response shape; the menu the curated spec is drawn from.
- [admin.md](admin.md) - enabling the admin server, credential rules, and the off-loopback default-credential refusal.
- [mcp-gateway-guardrails.md](mcp-gateway-guardrails.md) - egress policy, run-as-user upstream auth, and the rest of the MCP guardrail surface.
- [openapi-emission.md](openapi-emission.md) - the emitted data-plane OpenAPI document, and why it is not the admin spec.
