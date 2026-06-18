# Migration: credentials block

*Last modified: 2026-06-17*

The legacy `virtual_keys:` YAML array under `origins[].action.providers` is no longer supported. The canonical replacement is the unified `credentials:` block, configurable at proxy, tenant, or origin scope.

This is a breaking change for any config that declared `virtual_keys:`. An operator with the old shape sees a hard compile error pointing at this guide.

## Why

The credentials epic unifies inbound and outbound credentials under one schema with first-class metadata, principal selectors, and multi-tenant scoping. The legacy `virtual_keys:` array could only sit at origin scope, had no selector grammar, and split attribution across two parallel paths (`ai_project`, `ai_tags`, plus the access-log `project` column) that did not survive across non-AI auth providers. The new block carries all of that on one shape and applies to every credential kind (`ai_provider`, `bearer`, `api_key`, `jwt`, `basic`, `oidc_client`, `outbound_token_exchange`, `outbound_client_credentials`).

## Manual migration

Walk each origin's `action.providers[*].virtual_keys` array. Rewrite each entry as a `credentials:` entry alongside the origin's `action:` block. Field map:

| Old (`virtual_keys[]`) | New (`credentials[]`) |
|---|---|
| `key` | `key` |
| `name` | `name` |
| `enabled` (default `true`) | drop (every declared credential is enabled; use `principals: []` to gate access) |
| `allowed_providers` | drop the array, set `provider: <name>` on the credential (one provider per credential) |
| `allowed_models` | `models.allow` |
| `blocked_models` | `models.deny` |
| `max_requests_per_minute` | `policies: [{ type: rate_limit, rpm: <n> }]` |
| `max_tokens_per_minute` | `policies: [{ type: rate_limit, tpm: <n> }]` |
| `budget` | `attrs.budget` |
| `tags` | `attrs.tags` |
| `project` | `attrs.project` |
| `user` | `attrs.user` |
| `metadata` | `attrs.metadata` |
| `route_to_model` | top-level on the credential (`route_to_model: gpt-4o-mini`). Lowered to the runtime virtual-key entry at config-compile time. |
| `inject_tools` | top-level on the credential. Same lowering. The shape is provider-native (`function` objects today). |

The credential `type:` is `ai_provider` for every entry migrated from `virtual_keys:`. The `provider:` field names the upstream provider this credential authenticates against; the credential is rejected at routing time if its request resolves to a different provider.

### Worked example

Before:

```yaml
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          default_model: claude-3-5-haiku-latest
      virtual_keys:
        - key: ${TEAM_FRONTEND_KEY}
          name: team-frontend
          allowed_providers: [anthropic]
          allowed_models: [claude-3-5-haiku-latest]
          max_requests_per_minute: 30
          max_tokens_per_minute: 60000
          tags: [team-frontend, tier-haiku]
          project: frontend
          budget:
            max_tokens: 500000
            max_cost_usd: 10
```

After:

```yaml
origins:
  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          default_model: claude-3-5-haiku-latest
    credentials:
      - name: team-frontend
        type: ai_provider
        provider: anthropic
        key: ${TEAM_FRONTEND_KEY}
        attrs:
          project: frontend
          tags: [team-frontend, tier-haiku]
          budget:
            max_tokens: 500000
            max_cost_usd: 10
        models:
          allow: [claude-3-5-haiku-latest]
        policies:
          - type: rate_limit
            rpm: 30
            tpm: 60000
```

Behaviour is identical at runtime: the compile-time lowering materialises the credentials of type `ai_provider` as entries in the legacy `VirtualKeyConfig` registry the AI dispatch already reads. Existing access-log columns (`project`, `user`, `metadata`) and per-credential attribution metrics keep populating from the unified `Principal` write.

## Multi-tenant scope

The new block lives at three scopes:

* `proxy.credentials:` - operator defaults shared across every tenant.
* `tenants[].credentials:` - tenant-scoped credentials.
* `origins[].credentials:` - origin-scoped credentials (the closest analog to today's `virtual_keys:`).

Resolution at request time walks origin → tenant → proxy. A credential at origin with the same `name:` as one at tenant or proxy scope shadows the broader scope. This lets an operator declare a shared `proxy.credentials[].openai-shared` default and then re-declare `openai-shared` at a tenant scope to override the key + budget for that tenant only.

## Field reference

| Field | Type | Description |
|---|---|---|
| `name` | string | Stable operator-supplied name. Unique within the declaring scope. |
| `type` | enum | One of `ai_provider`, `bearer`, `api_key`, `jwt`, `basic`, `oidc_client`, `outbound_token_exchange`, `outbound_client_credentials`. |
| `provider` | string | Provider name for `ai_provider` credentials. Matches an entry in the origin's `providers:` list. |
| `key` | string | Secret reference. Accepts provider-specific schemes such as `vault://`, `awssm://`, `gcpsm://`, `k8ssecret://`, `secretfile://`, and `secret://`, plus `${ENV}`, `file:`, and `secret:`. |
| `principals` | list | Principal selectors. Empty matches every principal. |
| `attrs` | object | Attribution attributes copied onto matched principals. See below. |
| `models.allow` / `models.deny` | lists | Stack on top of the origin-level allowlist. Most-restrictive wins. |
| `policies` | list | Per-credential sub-policies. Closed enum: `rate_limit`, `require_pii_redaction`. |

### `attrs:`

| Field | Type | Description |
|---|---|---|
| `project` | string | Project the credential's spend rolls up to. |
| `user` | string | User the credential is owned by. |
| `team` | string | Team grouping. |
| `cost_center` | string | Cost center. Lifted onto `Principal.attrs.metadata` under the `cost_center` key. |
| `tags` | list | Operator-supplied tags. Each tag becomes a separate attribution row. |
| `metadata` | map | Free-form metadata copied verbatim onto `Principal.attrs.metadata`. |
| `budget.max_tokens` | int | Total input + output tokens per reset window. |
| `budget.max_cost_usd` | float | USD spend cap per reset window. |
| `budget.reset` | string | Reset window in LiteLLM-style `30s|30m|30h|30d`. |

## Secret Reference Migration

Credential keys use the same secret-reference grammar as other secret-bearing fields. The old umbrella form used the first `vault://` path segment as a backend alias:

```text
vault://aws/prod/openai?key=api_key
vault://k8s/default/sbproxy-secrets/openai-key
vault://file/etc/sbproxy/secrets/openai
vault://env/OPENAI_API_KEY
```

New configs should use provider-specific schemes instead:

```text
awssm://aws/prod/openai?key=api_key
k8ssecret://k8s/default/sbproxy-secrets/openai-key
secretfile://file/etc/sbproxy/secrets/openai
${OPENAI_API_KEY}
```

HashiCorp Vault owns `vault://` after the migration, so a HashiCorp reference should name the configured HashiCorp backend instance:

```text
vault://primary/secret/data/openai-prod?key=api_key
```

The legacy `vault://<alias>/...` forms are accepted with a warning during the compatibility window. The shim is scheduled for removal in SBproxy `1.2.0`. Rewrite known aliases with:

```bash
sbproxy config migrate sb.yml --out sb.migrated.yml
```

### `principals:`

A list of selectors. A selector matches when at least one of its fields matches the inbound principal. An entirely empty selector is rejected at compile time.

| Selector | Matches |
|---|---|
| `virtual_key` | Glob against `Principal.virtual_key.name`. `vk_frontend_*` matches every key with that prefix. |
| `team` | Exact match on `Principal.attrs.team`. |
| `project` | Exact match on `Principal.attrs.project`. |
| `user` | Exact match on `Principal.attrs.user`. |
| `role` | Any role on `Principal.attrs.roles`. |
| `claim.<name>` | Exact key=value match on `Principal.attrs.claims`. |

Empty `principals: []` matches every principal. When a presented credential key
matches but none of its selector rows match the already-resolved inbound
principal, SBproxy rejects the request with `403` before applying that
credential's attribution, model route override, tool injection, or provider
dispatch.

### `require_pii_redaction`

`policies: [{ type: require_pii_redaction, rules: [...] }]` requires the
matching origin's AI handler to have request-body PII redaction enabled before
the credential can dispatch upstream. Rule names are checked against the active
default and custom PII rules. If a required rule is missing, or `pii.enabled` /
`pii.redact_request` disables request redaction, SBproxy rejects the request
before provider dispatch and emits a structured warning.

## What's deferred

* `outbound_token_exchange` and `outbound_client_credentials` types parse but defer to the existing outbound resolver until the resolver migrates to the unified `Credential` shape.
