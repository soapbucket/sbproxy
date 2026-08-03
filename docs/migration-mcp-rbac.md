# Migrating MCP tool access policies

*Last modified: 2026-08-02*

This is a migration record for one breaking change, kept so an operator upgrading from a config
written before it can find the shape their file needs to become. It is reference material: the
before-and-after pairs below are configuration, not a walkthrough, and there is no outcome to run
because the outcome is that your existing config keeps working.

For the current policy surface as a thing you configure rather than a thing you migrate to, read
[mcp.md](mcp.md); [`examples/mcp-rbac-quotas/`](../examples/mcp-rbac-quotas/) is the same policy
as a runnable config.

## BREAKING CHANGE: MCP default-deny

The MCP `ToolAccessPolicy` flipped from open-by-default to
closed-by-default. The legacy `key_permissions:` schema is gone, and
the policy now reads off the inbound `Principal` (tenant, virtual
key, team, project, role, sub) instead of just the resolved auth
subject. This page walks through the three migration shapes that
cover the existing configs in the wild.

The flip is intentional. The previous default silently allowed every
tool when the policy table was absent, when the per-server `rbac:`
label was omitted, or when an empty allowlist was misread as
"unrestricted". Each of those failure modes appeared in real configs
during the v1.0 audit. The fix is to make the safe shape the default
and force operators who need the legacy behavior to opt in.

## What changed at a glance

| Surface | Before | After |
|---|---|---|
| Policy schema | `key_permissions: { key: [tools] }` | `tool_access[]` with `principals[]` + `allowed[]` |
| Default for an unknown caller | Allow | Deny |
| Empty `allowed: []` | Allow all | Deny all |
| `tools/list` | Returned full catalog | Filtered by per-server RBAC against inbound principal |
| Per-tool quotas | Not supported | `tool_quotas[]` sliding-window, keyed on `(tenant_id, principal_id, tool_name)` |
| Identity carrier | Resolved auth subject only | `Principal` (tenant, virtual key, team, project, role, sub) |

## 1. Legacy "no policy" config

A config that omitted the policy table at all relied on the previous
open-by-default. The minimum-friction migration is to opt back in.

Before:

```yaml
origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      federated_servers:
        - origin: github.example.com
          prefix: gh
```

After:

```yaml
origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      rbac_policies:
        legacy_open:
          default_allow: true
      federated_servers:
        - origin: github.example.com
          prefix: gh
          rbac: legacy_open
```

The `default_allow: true` flag preserves the legacy behavior for
the upstream that binds to the `legacy_open` label. New upstreams
inherit the deny-by-default until you bind them to a policy with
their own `allowed[]` list.

## 2. Legacy `key_permissions:` config

The legacy schema mapped a virtual key string to its allowlist:

Before:

```yaml
rbac_policies:
  read_only:
    key_permissions:
      alice: [gh.search_repos, db.query]
      bob:   [gh.search_repos]
```

After:

```yaml
rbac_policies:
  read_only:
    default_allow: false
    tool_access:
      - principals:
          - virtual_key: alice
        allowed: [gh.search_repos, db.query]
      - principals:
          - virtual_key: bob
        allowed: [gh.search_repos]
```

The `virtual_key:` field accepts a trailing-`*` glob, so
`virtual_key: vk_frontend_*` matches every key with that prefix.
Use `sub:` instead when the matching principal is a bearer / api-key
caller and not a virtual key.

## 3. New selector-based per-team allowlist

The new schema is principal-aware. An operator can write a single
rule that matches every member of a team rather than enumerating
each virtual key.

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
    tool_quotas:
      - tool_name: delete_user
        principals:
          - team: frontend
        rate:
          per: 24h
          max: 5
```

Selector fields (every field is optional; an unset field is a
wildcard):

| Field | Match | Source |
|---|---|---|
| `virtual_key` | Trailing-`*` glob on `Principal.virtual_key.name` | AI gateway virtual key |
| `sub` | Trailing-`*` glob on `Principal.sub` | Bearer / API key / basic auth subject |
| `team` | Exact match on `Principal.attrs.team` | Credentials block |
| `project` | Exact match on `Principal.attrs.project` | Credentials block |
| `user` | Exact match on `Principal.attrs.user` | Credentials block |
| `role` | Any of `Principal.attrs.roles` | JWT / API key |
| `tenant_id` | Exact match on `Principal.tenant_id` | Multi-tenant scope |

Multiple selector fields on the same row AND together; multiple rows
in `principals[]` OR together; multiple rules in `tool_access[]` are
walked top-to-bottom and the first matching rule decides.

## Per-tool quotas

Each rule in `tool_quotas[]` declares a sliding-window quota. The
counter is keyed on `(tenant_id, principal_id, tool_name)`, so
tenant A's traffic cannot starve tenant B's of the same tool. A
caller over quota gets JSON-RPC error code `-32099` with a
human-readable message; the upstream is never contacted.

Window units: `ms`, `s`, `m`, `h`, `d`. The store is per-action and
lives in process memory; SIGHUP reload rebuilds the action and
resets the counters.

## See also

- `crates/sbproxy-extension/src/mcp/access_control.rs`: the typed
  policy and quota store.
- `crates/sbproxy-modules/src/action/mcp.rs`: the `mcp` action that
  wires the policy into each federated upstream.
- `docs/mcp.md`: the wider operator-facing MCP gateway reference.
