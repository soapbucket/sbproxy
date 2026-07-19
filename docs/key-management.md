# SBproxy dynamic key management

*Last modified: 2026-07-19*

A virtual key is a live, governed resource, not a line of YAML. With the
`key_management:` block enabled, you mint, revoke, and rotate inbound keys at
runtime through an admin API. Each change takes effect on the next request
without a reload, because every request resolves its key through a cache and
then the store. Inbound keys are hashed at rest; upstream provider credentials
can be encrypted at rest. One pluggable store, one policy cache, and one admin
API sit underneath both. Each key also carries an immutable public identity and
a monotonic policy revision, so concurrent operators cannot silently overwrite
one another's policy changes.

This is the runtime layer on top of the static `credentials:` block. The static
block still works; it lowers into the same store as config-sourced records.

## When to use it

Reach for dynamic key management when keys outlive a config file: a fleet of
agents that each need their own key, keys you must revoke the instant a laptop is
lost, per-customer keys with their own rate limits and budgets, or keys minted by
another system through the API. If your keys rarely change, the static
`credentials:` block is simpler and enough.

## The block

```yaml
proxy:
  key_management:
    enabled: true
    store:
      backend: embedded              # embedded | redis | secrets_manager
      path: /var/lib/sbproxy/keystore.redb
    cache:
      ttl_secs: 60                   # how long a resolved key stays cached
      negative_ttl_secs: 5           # how long an unknown key stays cached
      max_entries: 10000
      tier: none                     # none | redis | mesh
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER       # HMAC key for inbound hashing
      master_key: env:SBPROXY_KEY_MASTER   # envelope key for upstream creds
    failure_mode_allow: false        # fail closed when the store is down
    allow_api_override: false        # config records win on reload
    oidc_claim_map:
      claim_field: virtual_key       # JWT/OIDC claim that names the record
    seed:
      keys: []                       # optional declarative keys
      credentials: []                # optional declarative credentials
```

When `enabled` is false (the default) the block is inert and inbound auth keeps
using the compiled `credentials:` blocks.

## Store backends

The store is sbproxy's own mutable system of record. It is distinct from the
vault, which reads external secrets you do not own.

- `embedded` (default): a redb file on local disk. Single node, no dependencies.
  Good for one replica or a shared volume.
- `redis`: a Redis instance, usable as the source of truth for a replica fleet
  or as a coherence tier behind the embedded store. Every mutation bumps a
  revision counter and publishes the changed id, so peers drop their cached copy
  and pick up the change. Set `store.url` to the Redis connection string.
- `secrets_manager`: an external secrets manager is itself the system of record,
  for operators who want exactly one place secrets live. Configured under
  `store.secrets_manager` with a `provider` of `hashicorp` (token auth, token
  from `token_env`), `aws` (default credential chain), or `local` (in-memory, for
  dev and tests). Only writable managers are supported; read-only backends are
  not offered here.

### Atomic policy mutation support

Revisioned policy and lifecycle writes use compare-and-swap. The backend checks
the supplied `expected_revision`, writes the replacement, and advances the
revision as one atomic operation.

| Key store | Revisioned policy writes |
|---|---|
| `embedded` | Supported in one redb write transaction. The guarantee is local to that store file. |
| `redis` | Supported in one server-side Redis operation. The revision update and cache-invalidation publication advance together. |
| `secrets_manager` | Not supported by the common secrets-manager interface. `PATCH`, block, unblock, revoke, and rotate fail closed with `409` instead of performing a racy read-then-write. |

Creation and deletion are separate operations. In particular,
`DELETE /admin/keys/{id}` is not guarded by `policy_revision`; coordinate
destructive deletion separately from policy editing.

This compare-and-swap protects the key policy document, not the runtime usage
counters. RPM, TPM, and budget accounting for a governed key run through a
separate ledger with its own consistency guarantee, approximate by default or
strict against Redis; see
[Governed admission: strict and approximate](#governed-admission-strict-and-approximate).
Authenticated caller introspection is separate rollout work and is not
documented as available here.

![a key minted on node A, read immediately from node B, then revoked with both replicas seeing it, no reload](assets/ai-dynamic-keys-cluster.gif)

Two replicas share a Redis store with a mesh cache in front ([config](../examples/ai-dynamic-keys-cluster/)).

## The policy cache

A small in-memory cache sits in front of the store so per-request resolution is
fast and does not hammer the store. A found key is cached for `ttl_secs`
(default 60); an unknown key is cached for `negative_ttl_secs` (default 5) so a
flood of bad keys cannot stampede the store. Mutations invalidate the entry, so a
revoke or a limit change is visible on the next request.

For a multi-replica deployment, set `cache.tier: redis` (or `mesh`) to add a
shared second tier. With Redis, a peer's mutation publishes an invalidation that
drops the matching entry on every node, so a revoke is clusterwide.

```
request -> L1 in-memory cache -> L2 tier (redis/mesh, optional) -> store
```

The mesh tier makes the L2 a gossip cluster instead of Redis: a SWIM membership
protocol feeds a consistent-hash ring, and reads and writes route to the replica
that owns a key, so the resolution order is L1, then the mesh cache, then the
store. A durable shared store still sits behind it as the source of truth (Redis,
or a secrets manager for a Redis-free fleet); the mesh keeps the cache coherent
and carries CRDT-based per-key spend and rate counters across replicas. Bootstrap
it with a `cache.mesh:` block of seed peers plus gossip and transport ports:

```yaml
cache:
  tier: mesh
  mesh_node_id: node-a            # unique per replica
  mesh:
    seeds: ["node-b:7946"]        # another replica's gossip endpoint
    gossip_port: 7946
    transport_port: 8946
    advertise_addr: node-a:7946   # what this node advertises to peers
    transport_advertise_addr: node-a:8946 # optional when host is the same
    # shared_key: env:SBPROXY_MESH_KEY  # encrypt gossip + transport (optional)
```

See the runnable `examples/ai-dynamic-keys-cluster/` for a two-replica setup.

## The security model

Two kinds of secret, two different treatments.

Inbound virtual keys are **hashed**, never stored in a form you can read back.
The at-rest verifier is `HMAC-SHA256(secret, pepper)`. The server pepper means a
stolen store is useless without it, which a bare SHA-256 of the key would not
give you. A minted token has the shape `sk-<key_id>-<secret>`; the `key_id` is a
public prefix, the `secret` is shown once and never stored. Verification is
constant-time.

Upstream provider credentials are **encrypted**, because the proxy has to present
them to the provider. Two options: a vault reference (`vault://`, `awssm://`,
`gcpsm://`, ...) resolved at use, which is first-class and keeps the secret out
of the store entirely; or an AEAD envelope. The envelope generates a per-record
data key, encrypts the secret with AES-256-GCM bound to the record id, then wraps
the data key under a key derived from the `master_key`. Only the wrapped data key
reaches disk, so you can rotate the master without re-encrypting every payload.

Set `pepper` and `master_key` to a stable secret in production. Both accept
`env:NAME` or `file:PATH` so you can inject them from your secret manager. If you
leave them unset, sbproxy generates an ephemeral value and warns: stored hashes
and encrypted credentials will not survive a restart.

By default the plane fails closed. If the store cannot be reached, a request
carrying a virtual key is denied. Set `failure_mode_allow: true` only if you have
weighed an outage of the store against an outage of your gateway.

## Key identity and policy revisions

`key_id` is the immutable public identity of a key. It is the stable part of the
token prefix (`sk-<key_id>-...`) and the identity used for policy and usage
attribution. Rotation changes the secret but keeps the same `key_id`. The admin
API does not accept `key_id` in a policy patch.

`name` is a mutable operator-facing display label. Rename or clear it without
changing the caller's token identity. Use `key_id`, not `name`, for automation,
joins, and long-lived dashboards.

`policy_revision` starts at `1`. Each successful revisioned policy, lifecycle,
or rotation write increments it by one. Read the key before changing it and use
the returned revision as the write precondition and conflict evidence.

## The admin API

Mounted on the existing admin server, under the same bind and basic auth. Every
call below also has a point-and-click equivalent on the Keys page of the
[built-in web UI](admin.md#the-built-in-web-ui):

![The Keys page of the admin UI: active keys with policy, budget, expiry, and per-key Edit, Rotate, Block, Revoke, and Delete actions](assets/admin-keys.png)

Enable the admin server first:

```yaml
proxy:
  admin:
    enabled: true
    port: 9090
    username: admin
    password: change-me
```

Mint a key. The plaintext token comes back exactly once.

```bash
curl -s -u admin:change-me -X POST http://127.0.0.1:9090/admin/keys \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-runner","max_requests_per_minute":60,"allowed_models":["gpt-4o-mini"]}'
# { "token": "sk-ab12cd34-...", "key": { "key_id": "ab12cd34", ... } }
```

![a virtual key minted, listed, rotated with a grace window, and revoked through the admin API with no reload](assets/ai-dynamic-keys.gif)

The plaintext token appears once at mint; list calls only ever show the key_id ([config](../examples/ai-dynamic-keys/)).

| Method and path | Effect |
|---|---|
| `POST /admin/keys` | Mint a key (token shown once) |
| `GET /admin/keys` | List keys (no secrets) |
| `GET /admin/keys/policy-schema` | Fetch the server-driven field, editor, clear, and enforcement contract |
| `GET /admin/keys/{id}` | Fetch one key |
| `GET /admin/keys/{id}/usage` | Fetch governed usage (used, reserved, remaining) and governance backend health |
| `POST /admin/keys/{id}/effective-policy/preview` | Evaluate a bounded sample without dispatching or changing counters |
| `PATCH /admin/keys/{id}` | Update policy with required `expected_revision` |
| `DELETE /admin/keys/{id}` | Delete a key |
| `POST /admin/keys/{id}/revoke` | Mark revoked (terminal) |
| `POST /admin/keys/{id}/block` | Mark blocked (reversible) |
| `POST /admin/keys/{id}/unblock` | Mark active |
| `POST /admin/keys/{id}/rotate` | Rotate with a grace window |
| `POST /admin/credentials` | Create an upstream credential |
| `GET /admin/credentials` | List credentials (no secrets) |
| `GET/PATCH/DELETE /admin/credentials/{id}` | Read, update, delete |
| `POST /admin/credentials/{id}/revoke\|block\|unblock` | Lifecycle |

### Policy PATCH contract

The PATCH body is flat. Do not wrap fields under `policy` or `budget`.

- `expected_revision` is required and must be at least `1`.
- An absent field is unchanged.
- JSON `null` clears a nullable field such as `name`, `route_to_model`,
  `compression_profile`, a limit, a budget cap, attribution, `inject_mcp`, or
  `expires_at`.
- A list or map is replaced in full. Use `[]` or `{}` to clear it. The API
  rejects `null` for non-nullable collections such as model/provider lists,
  `tags`, `metadata`, and injected tools. `allowed_tools` is the exception:
  `[]` means deny all caller tools, while `null` means unrestricted.
- Unknown fields are rejected. A create request must not include
  `expected_revision`.

The following table is the complete PATCH contract. In every row, omitting the
field leaves it unchanged.

| PATCH field | Replacement value | Clear or reset value | Read response |
|---|---|---|---|
| `name` | string | `null` | `name` |
| `max_requests_per_minute` | non-negative integer | `null` | same field |
| `max_tokens_per_minute` | non-negative integer | `null` | same field |
| `priority` | `interactive`, `standard`, or `batch` | `null` | same field |
| `max_budget_tokens` | non-negative integer | `null` | `budget.max_tokens` |
| `max_budget_usd` | finite non-negative number | `null` | `budget.max_cost_usd` |
| `allowed_models` | string list | `[]` | same field |
| `blocked_models` | string list | `[]` | same field |
| `allowed_providers` | string list | `[]` | same field |
| `blocked_providers` | string list | `[]` | same field |
| `require_pii_redaction` | string list | `[]` | same field |
| `principal_selectors` | selector object list | `[]` | same field |
| `route_to_model` | string | `null` | same field |
| `compression_profile` | `on`, `off`, or a valid profile name | `null` | same field |
| `allowed_tools` | string list | `null` for unrestricted; `[]` denies all | same field |
| `inject_tools` | tool object list | `[]` | same field |
| `inject_mcp` | object with a non-empty `ref` | `null` | same field |
| `bypass_prompt_injection` | `true` | `false` | same field |
| `project` | string | `null` | same field |
| `user` | string | `null` | same field |
| `tags` | string list | `[]` | same field |
| `metadata` | string-to-string object | `{}` | same field |
| `tenant` | string | `null` | `tenant_id` |
| `expires_at` | RFC 3339 timestamp | `null` | same field |

`key_id` is immutable and is never accepted in PATCH. `status` changes only
through the block, unblock, and revoke action routes. Revocation is terminal.
Those action routes and rotation accept an optional `expected_revision`; PATCH
always requires it.

### Server schema and effective-policy preview

Admin clients should fetch `GET /admin/keys/policy-schema` instead of keeping a
separate list of editable fields. Each descriptor names the effective-policy
field, its PATCH field or lifecycle action, the recommended editor, its exact
clear value, the corresponding preview field, and the request-path enforcement
proof. The schema is available even when key management has not been enabled.

Preview a stored key against an optional request sample:

```bash
curl -s -u admin:change-me -X POST \
  http://127.0.0.1:9090/admin/keys/ab12cd34/effective-policy/preview \
  -H 'Content-Type: application/json' \
  -d '{
    "origin_tenant_id":"acme",
    "model":"gpt-4o-mini",
    "provider":"openai",
    "tools":["search"],
    "principal":{"team":"platform","user":"alice"},
    "active_pii_rules":["email"],
    "prompt_injection_detected":false,
    "estimated_tokens":1000,
    "estimated_micro_usd":2000,
    "usage":{"requests_in_window":2,"tokens_in_window":1000,
             "total_tokens":100000,"total_micro_usd":3000000}
  }'
```

The response contains the canonical `effective_policy`, its revision and
digest under `policy_version`, and bounded decisions for lifecycle, tenant,
model, provider, tools, principal, rate limits, budget, priority, and
guardrails. Preview never contacts a provider, reserves budget, increments a
counter, or returns bearer material or verifier hashes. An empty `{}` sample is
valid and uses safe defaults. Unknown sample fields and oversized bodies,
lists, strings, or claim maps return `400`.

List, get, create, and mutation responses include `policy_digest` when a key
record owns an explicit tenant. A tenantless key inherits the request origin,
so it has no single effective digest and those responses return `null`. Use an
`origin_tenant_id` preview to obtain the exact digest enforced for that origin.

Fetch the current record, then patch only the fields you intend to change:

```bash
curl -s -u admin:change-me \
  http://127.0.0.1:9090/admin/keys/ab12cd34 \
  | jq '{key_id: .key.key_id, policy_revision: .key.policy_revision}'

curl -s -u admin:change-me -X PATCH \
  http://127.0.0.1:9090/admin/keys/ab12cd34 \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":3,"max_requests_per_minute":60,
       "max_budget_usd":50,"compression_profile":"compact",
       "name":"ci-runner"}'
```

A stale write returns `409` without exposing record contents:

```json
{
  "error": "key policy revision conflict",
  "key_id": "ab12cd34",
  "expected_revision": 3,
  "current_revision": 4
}
```

On conflict, fetch `GET /admin/keys/{id}`, compare the current record with your
intended changes, and retry with the new revision. Do not blindly replace the
entire record from a stale copy.

### Conflict recovery in the web UI

The Keys page keeps an immutable baseline while an edit form is open and sends
only fields changed from that baseline. If the server returns `409`, the UI
preserves the local edits and fetches the current server record. It shows both
the original and current revision.

Choose **Rebase preserved edits** to apply only your locally changed fields on
top of the refreshed record, review the result, and save again. Choose
**Load current policy** to discard the local draft and use the server record.
**Refresh current policy** refetches conflict evidence without discarding the
preserved draft.

Revoke is instant. The next request with that key is denied. Supplying the
revision is optional on action routes, but doing so lets operator automation
detect a stale decision explicitly.

```bash
curl -s -u admin:change-me -X POST http://127.0.0.1:9090/admin/keys/ab12cd34/revoke \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":3}'
```

Rotation mints a fresh secret for the same `key_id` and keeps the prior secret
valid for a grace window (default one hour). Both tokens work during the window,
so a client fleet can pick up the new token before the old one stops working.

```bash
curl -s -u admin:change-me -X POST http://127.0.0.1:9090/admin/keys/ab12cd34/rotate \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":3,"grace_secs":3600}'
# { "token": "sk-ab12cd34-<new>", "grace_expires_at": "...", "key": { ... } }
```

List, get, and conflict responses never carry a verifier hash, an envelope, or
a plaintext secret. Create and rotate are the only responses that carry a
plaintext token, and each token is shown once. Do not record admin request
bodies or create/rotate responses in shell history, reverse-proxy access logs,
or support bundles.

Successful key mutations emit a structured `key_audit` event with the operation,
resource kind, and public record id. The event does not contain a plaintext
secret or verifier hash. Route that tracing target to a protected audit sink and
apply normal operational-log access controls. See [Audit log](audit-log.md).

## Live policy

A key is not just an auth token; it carries its own policy. Everything below
rides on the record, so a successful `PATCH` invalidates the cached record and
takes effect without a config reload. Cache coherence and distributed usage
accounting are different guarantees; see
[Atomic policy mutation support](#atomic-policy-mutation-support).

- **Model and provider access:** `allowed_models`, `blocked_models`,
  `allowed_providers`, and `blocked_providers`. Empty allow-lists mean "all".
  A matching block takes precedence over an allow.
- **Rate and budget:** `max_requests_per_minute` and `max_tokens_per_minute`
  cap the key's one-minute windows (requests admitted, then tokens actually
  consumed by responses). `max_budget_tokens` and `max_budget_usd` are the flat
  mutation fields for lifetime caps. Read responses return those caps in the
  key's `budget.max_tokens` and `budget.max_cost_usd` fields.

  Stored-key token and cost settlement currently applies only to standard JSON
  POST inference surfaces when the provider response reports parseable usage.
  Multipart and non-POST requests can still dispatch, but they do not settle
  `max_tokens_per_minute`, `max_budget_tokens`, or `max_budget_usd` counters, so
  do not treat these caps as a hard ceiling on multipart or non-POST traffic.
  For standard JSON POST traffic, a governed key reserves against these caps
  before the request dispatches; see
  [Governed admission: strict and approximate](#governed-admission-strict-and-approximate)
  for what "cluster-aware" means under each consistency tier.
- **Scheduling lane:** `priority` (`interactive`, `standard`, or `batch`)
  places the key's requests in a lane on the locally served model's admission
  queue. Unset means standard. See the model host doc for how lanes queue and
  spill.
- **Lifecycle:** `status` (active, blocked, revoked) and `expires_at`.
- **Guardrails:** `require_pii_redaction` lists redaction rules that must be
  active before the key can dispatch; `bypass_prompt_injection` skips the
  body-aware injection scan for a trusted caller (eval pipelines, red-team
  tooling). Default off, so every key is scanned.
- **Model pinning and tools:** `route_to_model` overwrites the request's `model`
  before routing, so the caller cannot pick another. `allowed_tools` controls
  caller-supplied tool names. `inject_tools` replaces the client's tool list
  with a set the key owns. `inject_mcp` (an object naming a federated MCP
  gateway, for example `{"ref": "toolhub"}`) attaches that gateway's tools to
  the key's requests. Together these make a key a fixed "model plus tools"
  surface.
- **Context compression:** `compression_profile` selects the AI route's default
  pipeline with `on`, disables compression with `off`, or selects one named
  route-local profile. Header `X-Compression` overrides the governed key, CEL
  is consulted only when the key has no selector, and an absent selector uses
  the route default. SBproxy strips the request header before upstream
  dispatch. The Admin API validates selector syntax but cannot prove which AI
  origin a dynamic key will reach. A syntactically valid profile that is not
  declared on the eventual route safely resolves to `off` and records
  `invalid_operator`. Static configured credentials are route-bound, so an
  undeclared profile is a configuration error at load time.
- **Principal gate:** `principal_selectors` restricts which inbound identities
  may present the key, matched by `virtual_key`, `team`, `project`, `user`,
  `role`, or `claim`. Empty means any principal.
- **Attribution:** `tenant_id` and the immutable `key_id` identify the governed
  request. Usage sinks and enabled access logs retain `project`, `user`,
  `tags`, and string `metadata` for detailed reporting. Treat those values as
  operator-controlled log data: do not store secrets or regulated personal
  data in them. Request spans retain only tenant, key, policy revision,
  project, and user. Security audit and managed-route events deliberately omit
  free-form tags and metadata. Prometheus attribution uses the fixed
  tenant/key/project label set and excludes user and metadata.

`allowed_tools` has three distinct states in JSON and YAML:

| Value | Caller-supplied tools |
|---|---|
| omitted or `null` | Unrestricted |
| `[]` | All denied |
| `["search", "calculator"]` | Only the named tools are allowed |

This field does not control the key-owned definitions in `inject_tools` or
`inject_mcp`. In the web UI, choose **Unrestricted** for `null`, or **Use
allowlist** for a list. An empty allowlist intentionally denies every
caller-supplied tool.

### Governed admission: strict and approximate

A governed key with at least one of `max_requests_per_minute`,
`max_tokens_per_minute`, `max_budget_tokens`, or `max_budget_usd` set reserves
against a dedicated governance ledger before the request dispatches, and
settles the reservation once the provider's response reports usage. A request
that would exceed a limit is denied before it reaches an upstream.
`key_management.governance:` picks the consistency guarantee behind that
ledger:

```yaml
proxy:
  key_management:
    governance:
      consistency: approximate      # approximate | strict
      # backend:                    # required only when consistency is strict
      #   type: redis
      #   url: rediss://governance.internal:6379/2
      lease_ttl_secs: 120
      terminal_retention_secs: 300
      failure_mode: closed        # closed | allow_unreserved
      missing_rate: zero_cost     # zero_cost | require_rate
```

- **`approximate`** (the default) counts requests, tokens, and cost locally on
  each gateway process. In a cluster, each node periodically publishes its own
  settled usage and merges every live peer's usage back in, so a governed
  key's admission check weighs the rest of the fleet's spend, not just this
  node's own counters. That merged view catches up on a short interval rather
  than updating instantly, so treat it as cluster-aware within a bounded
  staleness window, not an exact global total. Only settled usage
  disseminates; an open reservation stays local until it settles or expires.
  No external database is required, but the cross-node view only exists when
  clustering itself is active; an unclustered node in approximate mode counts
  only its own traffic.
- **`strict`** reserves and settles against a dedicated Redis backend instead.
  Every gateway targets the same hash-tagged key, and the reserve, settle, and
  release operations run as atomic Redis-side scripts, so two nodes cannot
  both admit a request only one of them has budget for. Set
  `governance.backend` to `{type: redis, url: ...}` (`redis://` or
  `rediss://`). `consistency: strict` without a `backend` fails config
  validation at load and reload rather than silently falling back to per-node
  enforcement, and a `backend` set under `consistency: approximate` fails
  validation the same way. This backend is independent of
  `key_management.store` and `cache.tier: redis`; configure a strict
  governance URL separately even if you already point those at Redis.

`failure_mode` (default `closed`) decides what happens when a governance
backend outage stops a reserve call from completing. `closed` denies the
request with `503` rather than let a governed limit go silently unenforced.
`allow_unreserved` is the audited escape hatch: it admits the request without
a reservation instead, and every time it fires the decision is logged,
recorded on the `security_audit` channel, and counted on
`sbproxy_governance_fail_open_total{key_id}`, so leaving it off the default
posture is a deliberate choice you can see in the numbers, not a silent one.

`missing_rate` (default `zero_cost`) governs a key that carries a
`total_micro_usd` limit when the resolved model has no configured rate.
`zero_cost` treats the request as free at reserve time and still settles the
key's cost limit from actually billed usage. `require_rate` denies the request
instead, so a monetary limit is never left silently unenforced against a model
whose spend cannot be pre-accounted.

See [Dependency degradation matrix](degradation.md) for current outage
behavior per backend.

Set policy fields at mint time or with `PATCH /admin/keys/{id}`. Admin writes
and seed records both use flat `max_budget_tokens`, `max_budget_usd`, and
`tenant` fields. Read responses expose `budget` and `tenant_id`. Seed records
can set tags and metadata but cannot seed lifecycle status; a seeded key starts
active and lifecycle changes go through the API. For example:

```bash
curl -s -u admin:change-me -X PATCH http://127.0.0.1:9090/admin/keys/ab12cd34 \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":3,"allowed_models":["gpt-4o-mini"],
       "blocked_providers":["unapproved-provider"],"allowed_tools":[],
       "max_requests_per_minute":60,"max_budget_usd":50,
       "route_to_model":"gpt-4o-mini","compression_profile":"compact",
       "require_pii_redaction":["email"],
       "tags":["team:payments"]}'
```

Beyond the structured fields, the resolved key becomes the request principal, so
the CEL policy plane can make decisions keyed on `project`, `user`, `tenant_id`,
`tags`, or `key_id`.

### Require a governed key on one AI origin

Set `require_governed_key: true` on an `ai_proxy` action when every request to
that origin must resolve to a key with an immutable public `key_id` and an
effective policy:

```yaml
origins:
  "regulated-ai.example.com":
    tenant_id: acme
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
```

The default is `false`, independently for each origin, so enabling the gate on
one hostname does not change compatibility behavior on another. A missing or
unknown key is rejected before model selection, cache lookup, or provider
dispatch. Blocked, revoked, expired, malformed, and cross-tenant records also
fail closed. Dynamic records minted through the admin API and configured keys
lowered from the unified `credentials:` block carry governed public identities.
The bearer token itself is never used as a policy, budget, trace, usage, or peer
dispatch identifier.

## OIDC and JWT

If your callers authenticate with an OIDC or JWT identity instead of a bearer
key, set `oidc_claim_map.claim_field` to the claim whose value names a key
record. After the token is verified, the claim value resolves the record and its
policy applies, so a bearer key and an OIDC identity converge on the same record
and the same limits. No secret is checked on this path, since the identity was
already proven by the token.

Revocation applies to this front door the same way it applies to bearer keys: a
token whose mapped claim names a revoked, blocked, or expired record is denied
with 403 on the next request, and a claim naming a record that does not exist
is denied with 401. A token that carries no mapped claim at all is simply
unmapped; it authenticates on its own terms with no per-key policy. When the
store is unreachable this path fails closed unless `failure_mode_allow` is set,
matching the bearer path.

## Migrating from static credentials

You do not have to move everything at once. The static `credentials:` blocks
keep working and lower into the same store as config-sourced records. To
migrate a key:

1. Enable `key_management:` with a stable `pepper` and a store backend.
2. Move the key into `key_management.seed.keys` (or mint a fresh one through the
   API and hand the new token to the client).
3. Remove it from `credentials:` once the client uses the new token.

Config-seeded records are authoritative on reload: they are re-applied every time
the config is reloaded, so the file stays the source of truth. Set
`allow_api_override: true` if you want runtime API changes to a seeded key to
survive a reload instead.

## Seeding

For a self-contained config, declare keys and credentials inline. A seed key
takes either a `secret` (hashed at boot) or a precomputed `secret_hash`.

The `key_management:` block nests under `proxy:`; a top-level `key_management:`
key is silently dropped with a warning and the feature stays off.

```yaml
proxy:
  key_management:
    enabled: true
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER
      master_key: env:SBPROXY_KEY_MASTER
    seed:
      keys:
        - key_id: ci0001
          secret: rotate-me-in-production
          name: ci-runner
          max_requests_per_minute: 60
          max_tokens_per_minute: 120000
          priority: batch
          max_budget_tokens: 1000000
          max_budget_usd: 50
          allowed_models: [gpt-4o-mini]
          blocked_models: [gpt-4o]
          allowed_providers: [openai]
          blocked_providers: [unapproved-provider]
          allowed_tools: []          # explicit empty list denies all caller tools
          route_to_model: gpt-4o-mini
          compression_profile: compact
          bypass_prompt_injection: false
          project: payments
          tenant: acme
          tags: [team:payments]
          metadata:
            owner: platform
          expires_at: "2027-01-01T00:00:00Z"
      credentials:
        - id: openai-prod
          provider: openai
          vault_ref: vault://openai
```

See the runnable `examples/ai-dynamic-keys/` config for the full setup.

The secret-free `EffectiveKeyPolicy` schema is version 2. Version 2 carries
`compression_profile` through configured keys, dynamic records, cache tiers,
and effective-policy preview. Readers still accept a version 1 policy that
lacks the field and treat it as unset, so rolling upgrades do not invent a
selector for an older record.
