# Migration: credentials block

*Last modified: 2026-06-02*

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
| `route_to_model` | (unchanged; still on the legacy VirtualKeyConfig surface until the AI route override moves to the credentials block in a follow-up) |
| `inject_tools` | (unchanged; same caveat as above) |

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

* `proxy.credentials:` — operator defaults shared across every tenant.
* `tenants[].credentials:` — tenant-scoped credentials.
* `origins[].credentials:` — origin-scoped credentials (the closest analog to today's `virtual_keys:`).

Resolution at request time walks origin → tenant → proxy. A credential at origin with the same `name:` as one at tenant or proxy scope shadows the broader scope. This lets an operator declare a shared `proxy.credentials[].openai-shared` default and then re-declare `openai-shared` at a tenant scope to override the key + budget for that tenant only.

## Field reference

| Field | Type | Description |
|---|---|---|
| `name` | string | Stable operator-supplied name. Unique within the declaring scope. |
| `type` | enum | One of `ai_provider`, `bearer`, `api_key`, `jwt`, `basic`, `oidc_client`, `outbound_token_exchange`, `outbound_client_credentials`. |
| `provider` | string | Provider name for `ai_provider` credentials. Matches an entry in the origin's `providers:` list. |
| `key` | string | Secret reference. Accepts `vault://...`, `${ENV}`, `file:`, `secret:`. |
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

## What's deferred

* Selector matching is parsed but not yet enforced; the lowering materialises every `ai_provider` credential into the legacy registry regardless of selector. Selector enforcement lands alongside the principal-aware policy work in a follow-up.
* The `require_pii_redaction` policy variant parses but does not yet attach to a per-request enforcer; that lands when the PII pass picks up policy-driven configuration.
* `outbound_token_exchange` and `outbound_client_credentials` types parse but defer to the existing outbound resolver until the resolver migrates to the unified `Credential` shape.
