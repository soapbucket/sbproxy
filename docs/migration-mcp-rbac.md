# Migrating MCP tool access policies

*Last modified: 2026-08-21*

This is a migration record for one breaking change, kept so an operator upgrading from a config
written before it can find the shape their file needs to become. It is reference material: the
before-and-after pairs below are configuration, not a walkthrough, and there is no outcome to run.
The outcome is a config that boots with the behavior described here, or the config-load error
quoted below when a policy table is mixed with an unlabeled server.

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
during the v1.0 audit. The default-deny policy closes two of them:
an unknown caller (no matching rule) is denied, and an empty
`allowed: []` denies everything.

The omitted label is closed at config load instead. Once an action
declares any `rbac_policies`, every entry in `federated_servers[]`
must carry an `rbac:` label. A server without one is a hard config
error, and the message names the server:

```
mcp action: federated_servers[] origin 'postgres.example.com' has no
rbac label while rbac_policies are configured; add `rbac: <label>`
(a policy with `default_allow: true` keeps deliberate allow-all)
```

There is no runtime deny path to reason about here: a config that
mixes a policy table with an unlabeled server never boots. Allow-all
for one upstream stays expressible, but only explicitly, by binding
that server to a policy with `default_allow: true` (shape 1 below).

The absent policy table is the one legacy shape that still works
unchanged: an action with no `rbac_policies` at all applies no tool
ACL to any server. That keeps non-RBAC deployments booting; migrate
it with shape 1 when you want the ACL surface at all.

## What changed at a glance

| Surface | Before | After |
|---|---|---|
| Policy schema | `key_permissions: { key: [tools] }` | `tool_access[]` with `principals[]` + `allowed[]` |
| Default for an unknown caller | Allow | Deny |
| Empty `allowed: []` | Allow all | Deny all |
| Unlabeled server while `rbac_policies` exist | Silently allowed every tool | Hard config error naming the server |
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
the upstream that binds to the `legacy_open` label. Once the policy
table exists, every server has to carry an `rbac:` label; adding a
new upstream without one fails config load with the error shown
above. So a new server gets either a policy with its own `allowed[]`
list or a deliberate `legacy_open` binding, and never an accidental
allow-all.

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

Window units: `ms`, `s`, `m`, `h`, `d`. Anything else is refused at
config load with an error naming the policy and the rule. The store is
per-action and lives in process memory; SIGHUP reload rebuilds the
action and resets the counters. Windows are held per
`(tenant_id, principal_id, tool_name)` and reclaimed once they age
out; past 10,000 live windows for one tenant, or 100,000 across the
process, a principal with no window of its own is refused rather than
admitted unmetered. The per-tenant ceiling is what keeps the sentence
above true under load: without it, one tenant authenticating under
many distinct `sub` values fills the whole map and every other
tenant's next unseen principal is refused too. That refusal is counted
on `sbproxy_mcp_tool_quota_registry_saturated_total`, which is what
tells it apart from a caller genuinely over quota.

## See also

- `crates/sbproxy-extension/src/mcp/access_control.rs`: the typed
  policy and quota store.
- `crates/sbproxy-modules/src/action/mcp.rs`: the `mcp` action that
  wires the policy into each federated upstream.
- `docs/mcp.md`: the wider operator-facing MCP gateway reference.
