# SBproxy dynamic key management

*Last modified: 2026-08-29*

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
      backend: embedded              # embedded | redis | secrets_manager | mesh
      # node-local: see "Clustered deployments" below before using this
      # on more than one node
      path: /var/lib/sbproxy/keystore.redb
    cache:
      ttl_secs: 60                   # how long a resolved key stays cached
      negative_ttl_secs: 5           # how long an unknown key stays cached
      max_entries: 10000
      tier: none                     # none | redis | mesh
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER       # HMAC key for inbound hashing
      master_key: env:SBPROXY_KEY_MASTER   # envelope key for upstream creds
    inbound:
      headers:                             # one minted token resolves; conflicts deny
        - {name: authorization, scheme: "Bearer "}
        - {name: x-api-key,     scheme: ""}
        - {name: x-sb-api,      scheme: ""}
      require: false                       # 401 when no minted key resolved
      native_key_policy:
        allowed_providers: [openai, anthropic]
        max_requests_per_minute: 600
        max_tokens_per_minute: 200000
        max_budget_tokens: 10000000
        max_budget_usd: 250.00
        allowed_models: [gpt-5, claude-sonnet-4]
        blocked_models: []
        require_pii_redaction: [email]
    failure_posture: closed          # closed | degraded | open
    allow_api_override: false        # config records win on reload
    oidc_claim_map:
      claim_field: virtual_key       # JWT/OIDC claim that names the record
    seed:
      keys: []                       # optional declarative keys
      credentials: []                # optional declarative credentials
```

When `enabled` is false (the default) the block is inert and inbound auth keeps
using the compiled `credentials:` blocks.

In Docker, mount a volume at `/var/lib/sbproxy` so the keystore survives
container replacement (`-v sbproxy-state:/var/lib/sbproxy`). Images up to
v1.9.0 ship without that directory and the nonroot runtime user cannot create
it, so on those versions the mount is required: without it the key plane
fails to install at boot with `create keystore directory '/var/lib/sbproxy'`.
A bind mount to a host directory works too.

## Which header carries the key

A minted key is presented in whatever header the calling tool already sends.
An Anthropic SDK sends `x-api-key`, Azure OpenAI sends `api-key`, and an
internal tool sends whatever its author picked. Rather than ask you to rewrite
those tools, SBproxy sweeps a configured list of headers for a token.

The list is route-level, not per-key, and it has to be: to know which header
holds the key you would have to have resolved the key already. The default
covers the three common shapes and you can add your own.

A minted token looks like `sbp_<16 hex>_<64 hex>`, a fixed 85 characters over a
fixed alphabet. SBproxy recognizes that shape before store access, then looks
up the public key id and verifies the secret. Shape recognition alone never
authenticates a request. A caller presenting their own `sk-proj-...` or
`sk-ant-...` provider key enters the native-key policy described below and,
when allowed, passes through to the upstream that owns it.

The configured carrier list is also the lookup surface for legacy stored
`sk-<id>-<secret>` keys and exact `credentials: {type: ai_provider}` values on
AI routes. Resolution order is canonical `sbp_...`, stored legacy key, a
verified OIDC/JWT claim mapped to a stored record, exact configured credential,
then provider-native policy. The winning governed carrier is removed before
dispatch, so that presented value does not accompany the operator's provider
credential upstream.

### Two ways to use it

**Substitution.** The tool already sends `x-api-key`. Point it at SBproxy,
give it a minted key instead of the provider key, and bind that key to a stored
credential. The upstream sees its own real key in `x-api-key`; the tool never
holds it.

```
client  ->  x-api-key: sbp_0a1b..._9f8e...     (minted, governed)
upstream <- x-api-key: <the real provider key>  (from the bound credential)
```

**Sidecar.** The tool keeps sending its own credential, and the minted key
rides alongside in `x-sb-api`. SBproxy governs the request without storing or
managing the caller-owned upstream secret; it still receives and forwards that
secret on the proxied request.

```
client  ->  authorization: Bearer <the tool's own key>
            x-sb-api: sbp_0a1b..._9f8e...
upstream <- authorization: Bearer <the tool's own key>   (untouched)
```

Both fall out of one rule: the key's header is consumed, and a bound
credential, if any, is written to its own header.

### Attributing native provider keys

A request that carries no minted key but does carry a recognizable provider
credential is attributed to and governed as that provider. The rules live under
`inbound.provider_hints`, ship with defaults for the common shapes (`sk-ant-`
is Anthropic, `sk-or-` is OpenRouter, a bare `sk-` bearer is OpenAI,
`x-goog-api-key` is Gemini, `api-key` is Azure), and are ordered: the first
match wins, so specific prefixes belong before loose ones.

Primary credential carriers are security-sensitive protocol fields, so SBproxy
validates them even when `key_management.enabled` is currently `false`.
Carriers cannot reuse hop-by-hop, framing, WebSocket, tracing, signature,
correlation, budget identity, A2A envelope, access-log identity, or
capture-envelope headers. This includes `x-user-id`, `x-end-user`,
`x-sbproxy-tag`, `x-sb-user-id`, the session headers, and the `x-a2a-*` and
`x-sb-property-*` namespaces.
`provider_hints[].also_header` is match metadata rather than a credential
carrier, so it may still name protocol metadata such as a provider version
header.

Recognized native credentials require an explicit
`inbound.native_key_policy.allowed_providers` allowlist. If the policy is
absent or the recognized provider is not listed, SBproxy returns 403 before
dispatch. A credential matching no hint remains unattributed and follows the
origin's ordinary auth behavior.

`provider_hints` ships non-empty by default and `native_key_policy` defaults
to absent, so turning on `key_management.enabled` alone is enough to arm this
403 with nothing behind it to admit the traffic it now recognizes. Boot, and
every SIGHUP reload, emits a WARN naming the recognized providers whenever
that combination is detected, so the gap is visible before the first caller
hits it. `sbproxy validate` does not catch this: validation mode checks the
config schema and stops there, skipping key-plane construction entirely, so
only a live boot or reload surfaces the warning. Fix it by declaring the
allowlist:

```yaml
inbound:
  native_key_policy:
    allowed_providers: [openai]
```

and, on each `ai_proxy` provider that may receive a caller credential:

```yaml
accept_native_credentials_for: openai
```

The same block is lowered to a secret-free KeyRecord-shaped default. Every
traffic type gets provider admission, audit attribution, a stable
tenant/origin/provider identity, and automatic
`max_requests_per_minute` enforcement. AI routes additionally apply provider
and model policy, token/cost budget preflight, and PII requirements wherever
the request shape can be interpreted. JSON POST and PUT/PATCH bodies can be
inspected and redacted. Multipart and Realtime cannot safely satisfy required
PII redaction and fail closed when a credential requires it; bodyless or
otherwise uninterpretable methods fail closed when model policy requires a
model. Multipart and non-POST responses do not yet settle token/cost counters,
so those fields are admission signals rather than strict usage ceilings on
those surfaces.

Limits are bucketed by tenant, origin, and recognized provider. The native
policy identity is built from those labels and contains no credential bytes.

On a generic proxy route, an allowed caller-owned credential passes upstream
unchanged, even when that origin also configures `outbound_credential`: native
mode represents an explicit caller-owned identity, so the origin credential
must not replace it. SBproxy receives and forwards the caller-owned secret, but
does not store, manage, or substitute it. An AI provider must opt in as an
exact credential destination. Set `accept_native_credentials_for` to the
canonical hint label, and make it match the provider's wire type:

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai-primary
      provider_type: openai
      accept_native_credentials_for: openai
      base_url: https://api.openai.com/v1
      api_key: ${OPENAI_API_KEY} # used when the caller is not in native mode
```

The opt-in belongs to this provider entry and its effective `base_url`.
`provider_type` selects the wire format; it does not grant a destination access
to caller credentials. Without the opt-in, a custom endpoint that speaks the
OpenAI protocol receives only its operator credential. If the native
credential cannot be re-resolved or no opted-in provider exists, the request
fails before an upstream call. Minted `sbp_...` keys take precedence and never
enter native-key policy resolution.

Confidence cascade and race routing are unavailable for native credentials.
Cascade returns 503 and race returns 403 before request-body processing, cache
or idempotency lookup, managed-model preparation, streaming dispatch, or the
first upstream attempt. Sequential fallback can use another provider only when
that provider entry has its own matching `accept_native_credentials_for`
binding.
For the same reason, configured shadow copies are suppressed for native
traffic: the primary response proceeds normally, while neither the caller
credential nor an operator credential is sent to the shadow target.

The companion metric
`sbproxy_inbound_key_requests_total{provider,key_mode,tenant_id,api_key_id}`
uses the closed `key_mode` values `none`, `minted`, and `native`. An unresolved
provider or key id is the empty label value. Native `api_key_id` is the stable,
secret-free tenant/origin/provider policy-bucket id. Access logs, request
events, and security audit records carry the same `key_provider` and
`key_mode` fields. No raw provider key is stored in those records or metric
labels.

One canonical key id spans every per-request surface: the admin request
ring (`GET /api/requests?api_key_id=`), the access log, the metric label,
usage events, and the `sbproxy.key_id` span attribute all report the same
id for the same request, so "what did this key do" has one answer
everywhere. Key and credential lifecycle changes are audited with the
acting operator and a status diff, queryable at `GET /api/audit/events`;
see [admin-api-reference.md](admin-api-reference.md).

A key policy may set `allow_content_capture: true` to consent to the
origin's opt-in console content sampling. Consent alone captures nothing:
the AI origin must also set `capture_content: true`, and every retained
sample is redacted before storage. See the console content samples
section of [ai-gateway.md](ai-gateway.md).

### Requiring a key

`require: true` refuses a request that carried no minted key, with a 401. It is
off by default, so turning the sweep on changes nothing for an existing route.
Reach for it on an origin that has no other auth provider, where the default is
to admit unauthenticated traffic.

A resolved minted key satisfies auth on its own and skips the origin's
configured provider, so an origin with a JWT provider accepts either a valid
JWT or a valid minted key. That is what makes minted keys work in parallel with
credentials you already issue.

### Rate limiting a minted key

Bucket on `request.key_id`, not on the header:

```yaml
policies:
  - type: rate_limit
    key: request.key_id
    requests_per_minute: 600
```

The header carries the presented secret, so bucketing on it means the bucket
changes when you rotate the key and the caller gets a fresh budget. The key id
does not change. `request.key_id` is the secret-free native policy-bucket id for
admitted native traffic and an empty string when no key policy resolved, so the
expression still evaluates on unauthenticated traffic.

`concurrent_limit` with `key_by: api_key` already does this for you: it uses the
resolved key id when there is one and falls back to the header otherwise.

## Binding a key to an upstream credential

A key can name a stored credential with `credential_id`. That credential is
then the only upstream identity the key can reach an origin with.

The credential carries its own presentation, because how a secret must be sent
is a property of the upstream rather than of the caller:

```bash
curl -X POST localhost:9090/admin/credentials \
  -d '{"id":"anthropic-prod","secret":"sk-ant-...","header":"x-api-key","scheme":""}'

curl -X POST localhost:9090/admin/keys \
  -d '{"name":"research-team","credential_id":"anthropic-prod"}'
```

`header` defaults to `authorization` and `scheme` to `Bearer `. Set `scheme` to
an empty string for raw-value headers.

**A bound credential fails closed.** If it is missing, revoked, or cannot be
resolved, the request is refused with a 503. It never falls back to the
origin's own `outbound_credential`, because that would hand the key an upstream
identity it was never bound to. Deleting a credential that keys still bind is
refused with a 409 naming those keys; clear `credential_id` on them first.

A key and the credential it binds must belong to the same tenant. That is
checked when you set the binding and again on every request, because either
record's tenant can change afterwards.

**Credential bindings need a fully upgraded fleet.** A node on an older build
drops `credential_id` when the record replicates to it, resolves the key
without a binding, and dispatches on the origin's shared credential. You cannot
make an already-running binary refuse a field it ignores, so minting a bound
key is refused unless every node is known to understand it.

Each node republishes what it understands into cluster state, and the gate
reads one record per member before allowing a binding. A member with no record
refuses the mint and is named in the error, whether it is on an older build or
just unreachable: neither can be told apart from the case the gate exists to
prevent. A single-node deployment has no peers and is unaffected.

The records carry a two-minute expiry and are republished at half that, so a
node that is replaced by an older build drops out of the set on its own and the
fleet starts refusing again without anyone intervening. Pin your image tag when
you roll out.


## Referencing a credential from an AI provider entry

A seeded credential is also nameable from the other direction: an `ai_proxy`
provider entry can point `fallback_credential_id` at one, and the gateway
retries that provider on the named credential when the entry's own `api_key`
is refused with a `401` or `403`.

```yaml
proxy:
  key_management:
    seed:
      credentials:
        - id: house-openai
          provider: openai
          vault_ref: vault://primary/secret/data/house/openai?key=api_key

origins:
  api.acme.example.com:
    tenant_id: acme
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: vault://primary/secret/data/acme/openai?key=api_key
          fallback_credential_id: house-openai
```

Two things this gets that a second `api_key` on the entry would not. The
record resolves per request through the key plane rather than once at action
build, so rotating it lands without a config reload and a vault outage inside
the grace window still serves the last known-good value. And the tenant check
above applies here too: a credential belonging to another tenant is refused at
resolution, per request, not only when the config was written.

**A credential the inbound key is BOUND to still never falls back.** The two
mechanisms sit in the same problem space and answer opposite questions. A
`credential_id` on a key is an identity the caller was granted, so failing over
off it would hand that key an upstream identity it was never bound to, and it
fails closed with a 503. `fallback_credential_id` on a provider entry is the
operator's own alternative to the operator's own `api_key`, so retrying on it
grants nobody anything they did not already have. Only the second one falls
back.

For the postures, the precedence against provider failover, and the rule that a
caller-owned native credential never falls back, see
[multi-tenant.md](multi-tenant.md#when-a-tenants-provider-key-is-refused).


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
- `mesh`: the cluster's own replicated state substrate is the system of record,
  so a key minted on one node resolves on its peers with no Redis and no
  external secrets manager. Requires `proxy.cluster` with a `replication`
  block. See [The mesh backend](#the-mesh-backend) for the guarantees and the
  full configuration.

### The mesh backend

`backend: mesh` puts the keystore on the same quorum-replicated, durable
substrate the cluster already runs for its own state
([mesh-replication.md](mesh-replication.md)). Every record is written to
`replication.factor` nodes and acknowledged only after a majority committed it
to disk, so the fleet needs no external store at all.

The consistency levels are pinned by the backend and are not configurable:
writes and reads run at quorum, and revocation is written at one
acknowledgment. The only knobs that apply come from the cluster's existing
`replication` block, which the keystore shares with every other consumer of
the substrate.

```yaml
proxy:
  cluster:
    cluster_id: prod
    node_id: gw-1
    seeds: ["gw-2:7946"]                 # the peers this node joins
    state_dir: /var/lib/sbproxy/cluster  # durable identity + replica shard
    security:
      mode: mtls
      shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
      cert_file: /var/lib/sbproxy/cluster/node.pem
      key_file: /var/lib/sbproxy/cluster/node-key.pem
      ca_file: /var/lib/sbproxy/cluster/ca.pem
      server_name: sbproxy-mesh
    replication:
      factor: 2                          # copies per key record
      anti_entropy_interval_secs: 30     # repair cadence after partitions
      tombstone_gc_grace_secs: 86400     # also the rejoin quarantine bound
  key_management:
    enabled: true
    store:
      backend: mesh                      # no url, no path: the cluster is the store
    cache:
      ttl_secs: 60                       # per-node resolution cache (see below)
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER
      master_key: env:SBPROXY_KEY_MASTER
```

Each component earns its place:

- `proxy.cluster` is required. Selecting `backend: mesh` on a node with no
  cluster fails at config validation, because a mesh keystore on a node with
  no mesh is an embedded keystore with extra steps.
- `proxy.cluster.replication` is where the keystore's records physically live:
  the durable replica shard under `state_dir`. The `factor` is how many nodes
  hold each record; `anti_entropy_interval_secs` bounds how long a healed
  partition takes to reconverge; `tombstone_gc_grace_secs` doubles as the
  rejoin quarantine window described below. There are no keystore-specific
  consistency knobs on purpose.
- `store.backend: mesh` is the whole store surface. No URL, no file path, no
  credentials to a third system.
- `cache.ttl_secs` is the per-node resolution cache every backend has. For
  this backend it is also half of the revocation propagation bound, so
  shortening it tightens cluster-wide denial.
- `crypto.pepper` and `crypto.master_key` matter more here than on a
  single-node store: every node verifies hashes and opens envelopes minted by
  every other node, so all nodes must be configured with the same values.

What the backend guarantees, stated exactly:

| Guarantee | `mesh` backend |
|---|---|
| Acknowledged mint survives any minority failure | Yes. Writes are quorum-acknowledged and durable on a majority before success is reported. |
| Revocation visible cluster-wide | Eventual: bounded by `anti_entropy_interval_secs` plus `cache.ttl_secs`. Redis is bounded by `cache.ttl_secs` alone, because its pub/sub invalidation pushes to every node. |
| Revisioned policy CAS | Write-then-verify: the backend reads at quorum, writes, reads back, and reports success only if its exact write won. Never a false success; a false conflict is possible and the caller retries. |
| Mint from a partitioned minority | No. A minority cannot reach a write quorum, so the mint fails. |
| Revoke from a partitioned minority | Yes. Revocation is written at one acknowledgment, and anti-entropy carries it across the heal. |

If you need synchronous cluster-wide denial, the mesh backend is the wrong
tool: use the `redis` backend. Its mutations commit the record, bump the
store revision, and publish the invalidation as one atomic Redis operation,
so an acknowledged revoke has always published. A connected replica drops
the entry as the message arrives.

A replica whose subscriber connection was down during the revoke is covered
from two directions, and both matter when `cache.tier` is `redis`:

- The revoking replica deletes the shared L2 entry itself, in the same call
  that announces the id. That deletion is not a broadcast anyone has to
  receive, so a disconnected peer cannot miss it.
- On reconnect, the subscriber clears its own in-memory L1 before it
  processes anything, so nothing cached before the gap survives it.

The worst-case window is therefore the subscriber's reconnect delay
(5 seconds), not the L1 TTL. What the reconnect does *not* do is clear the
shared L2 on every peer's behalf; it does not need to, and a resync that
broadcast to the fleet would be answered by every peer broadcasting back.

One security rule is enforced at mint time: a credential whose material is
raw plaintext is refused, with an error naming the credential, because the
substrate would copy the secret onto every replica's disk. Hand the API or the
seed a `secret` (sealed into an AEAD envelope under the master key) or a
`vault_ref`; both replicate safely. Key records are unaffected, since they
only ever store an HMAC of the secret.

Three operational behaviors to know:

- **A failed mint must not be assumed not-to-have-happened.** A mint that
  errored below quorum may still have landed on some replicas, and
  anti-entropy will propagate that record later. It is inert litter, because
  the caller never received the token, but it exists: reconcile by listing
  (`GET /admin/keys`), which fails loudly rather than returning a partial
  fleet view.
- **Revocation is terminal, and the substrate enforces it.** A revoked record
  can never merge back to a usable one, not even against a stale replica
  pushing a higher-version copy. Rotating a compromised key id means minting a
  new id; there is no un-revocation.
- **A node returning from a long absence holds authentication until it
  catches up.** A node offline longer than `tombstone_gc_grace_secs` rejoins
  with a quarantined (wiped) shard and refuses keystore reads until its first
  complete anti-entropy round finishes; with the default `closed` failure
  posture that is a 503, not a false allow or a false deny. The admin health
  registry reports the same state through the `keystore` component on
  `/readyz`.

### Clustered deployments

A key minted on one node is resolvable on every node only when the store itself
is shared, which `redis`, `secrets_manager`, and `mesh` are. The `embedded`
backend is a redb file on local disk, so a key minted on node A is written only
to node A and node B cannot resolve it.

A shared `cache.tier` changes how bad that is, though it does not make the store
shared. Both the `mesh` and `redis` tiers propagate records to peers, so a key
minted on node A is readable on node B for as long as it stays cached. What you
do not get is durability: once the entry expires or a node restarts, the peer
falls back to its own store and cannot resolve the key. A revocation may also
fail to deny on a peer that never cached the record.

So a node declaring `proxy.cluster.seeds` with `key_management.enabled: true` and
`store.backend: embedded` gets one of two outcomes at boot:

- **With `cache.tier: mesh` or `redis`, it warns.** Cross-node resolution works
  while cached, so this is a usable development topology, but it is not a durable
  cluster-wide keystore and the log says so.
- **With `cache.tier: none`, it fails to start.** Nothing propagates records, so a
  minted key is invisible to peers from the moment it is created. Minting keys
  that silently do not work elsewhere is worse than not starting.

For a durable cluster-wide keystore, set `store.backend` to `redis`,
`secrets_manager`, or `mesh`. A single node with no seeds keeps the embedded
default and needs no change. The `mesh` backend has the reverse requirement,
checked at config validation: selecting it without `proxy.cluster` (or without
its `replication` block) refuses to start, because there is no substrate for
the records to live on.

One gap worth knowing: the check fires on nodes that declare seeds. A node others
join, which has no seeds of its own, is not itself classified, though every node
that joins it is, so the misconfiguration still surfaces.

A bulk credential purge on any node is cluster-wide. It fans out to every peer
rather than clearing only the local cache, so peers do not keep serving stale
resolved credentials until their TTL expires. A peer that cannot be reached is
logged, because the purge did not fully take.

### Atomic policy mutation support

Revisioned policy and lifecycle writes use compare-and-swap. The backend checks
the supplied `expected_revision`, writes the replacement, and advances the
revision as one atomic operation.

| Key store | Revisioned policy writes |
|---|---|
| `embedded` | Supported in one redb write transaction. The guarantee is local to that store file. |
| `redis` | Supported in one server-side Redis operation. The revision update and cache-invalidation publication advance together. |
| `secrets_manager` | Not supported by the common secrets-manager interface. `PATCH`, block, unblock, revoke, and rotate fail closed with `409` instead of performing a racy read-then-write. |
| `mesh` | Supported as write-then-verify, not an atomic primitive: read at quorum, write, read back, and report success only if this node's write won the deterministic merge. Never a false success; a concurrent loser sees `409` and retries. |

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
drops the matching entry on every node, so a revoke is clusterwide. The
mutation and its invalidation are one atomic server-side operation, and a
replica that reconnects after missing messages resynchronizes by clearing its
local cache, so a revoke cannot be missed permanently by a healthy replica.

```
request -> L1 in-memory cache -> L2 tier (redis/mesh, optional) -> store
```

The mesh tier makes the L2 a gossip cluster instead of Redis: a SWIM membership
protocol feeds a consistent-hash ring, and reads and writes route to the replica
that owns a key, so the resolution order is L1, then the mesh cache, then the
store. A durable shared store still sits behind it as the source of truth
(Redis, a secrets manager, or the mesh store backend for a fully self-contained
fleet); the mesh tier keeps the cache coherent.
Governed-key spend and rate counters are separate from this cache tier: see
[Governed admission: strict and approximate](#governed-admission-strict-and-approximate)
for how approximate mode merges each node's settled usage. Bootstrap the mesh
tier with a `cache.mesh:` block of seed peers plus gossip and transport ports:

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

### What bounds the mesh transport

The node-to-node RPC port (`transport_port` above) is a network listener like
any other, so it carries admission limits and deadlines rather than trusting
peers to behave. There is nothing to configure. Every bound below is a fixed
default sized against how a mesh actually behaves, because a limit that only
exists when an operator remembers to set it is not a limit.

| Bound | Default | What it stops |
|---|---|---|
| Inbound connections | 1024 | A peer opening sockets until the node has no task left to serve anyone. Sized to cluster shape: one connection per peer per direction, so 1024 is several times the largest mesh anyone runs. |
| Inbound TLS handshakes at once | 64 | A handshake flood turning into a CPU stall. Each handshake is a signature verification for a peer that has proved nothing yet. |
| TLS admission | 10s | A peer that opens a socket and sends no ClientHello. Covers the wait for a handshake slot as well, so the queue in front of the handshake is bounded too. |
| Inbound idle | 5 minutes | A connection that is admitted and then says nothing, forever, while holding a slot. |
| Inbound frame body | 30s | A peer that announces a 16 MiB frame and then delivers it one byte at a time. The deadline covers the whole body, so a single byte does not reset it. |
| Response write | 30s | A peer that issues a request and then stops reading, parking the handler inside the write. |
| Outbound RPC slot | 5s | A caller queueing behind a wedged peer. The transport holds one connection per peer with one request in flight, so callers wait their turn; failing the queue fast is what keeps one bad peer from occupying every task that wants it. |
| Outbound connect / TLS / write / response | 3s / 5s / 10s / 10s | A dead or wedged peer stalling a resolution that a request is waiting on. Scanning operations (`purge`, digest, snapshot) get 60s instead of 10s, because they walk the peer's shard rather than looking one key up. |
| Outbound request, overall | 15s (90s for a scan) | Five phase timeouts that each restart the clock are not a bound on the call. This one is, and every phase is clamped by whichever expires first. |

A peer refused by the connection limit gets an immediate close rather than a
hang: its next RPC fails as a transport error, it drops the connection, and
it reconnects on the call after that. Every refusal, and every connection
torn down by one of the deadlines, increments
`mesh_transport_inbound_rejected_total` with a `reason` from a fixed set
(`connection_limit`, `handshake_timeout`, `handshake_failed`,
`idle_timeout`, `frame_timeout`, `write_timeout`). The peer address is not a
label, because it is attacker-chosen; it goes in a rate-limited log line
instead, so the counter says how much and the log says who.

Five of those six reasons are worth an alert, and `idle_timeout` is not.
A quiet cluster reclaims idle connections as a matter of course, so that
value climbs on its own on a perfectly healthy fleet; it is recorded because
a sudden jump is still a signal, not because a steady rate is one. Alert on
`reason!="idle_timeout"`, and on any sustained `connection_limit` rate in
particular. The reclaim also logs at `debug` rather than `warn` for the same
reason, so it does not bury the five refusals that do want reading.

Client-side deadlines report on `mesh_transport_rpc_errors_total` under five
`timeout_` kinds, kept separate from the failure kinds beside them: a
`connect` is a peer that refused, a `timeout_connect` is a peer that answered
with nothing, and only the second one means reachable-but-wedged.

The two halves are tuned against each other, and it is worth being precise
about what that buys. A node replaces its own cached connection to a peer
after 60 seconds of quiet, but it checks that when it next issues a request
rather than on a timer, so a link nobody uses for more than five minutes is
still reclaimed by the peer's reaper. What the 60 seconds guarantees is that
the client's first request after any such gap is past its own mark too, so it
dials a fresh connection instead of writing into a socket the peer has
already closed. A quiet period costs one extra handshake, never a failed RPC.

## Operational metrics

Key management exports four Prometheus families on `/metrics`, modeled on the operational surface Vault publishes at `/v1/sys/metrics?format=prometheus`: operation rates, resolution latency, cache effectiveness, and an audit-write-failure counter whose healthy reading is exactly zero. The fourth is the one that reaches past the key plane: it carries the admin-console action trail on the same family, because the signal is "an audit record did not reach a sink it was promised" regardless of which trail it was. Every label value is a compile-time constant chosen from the real result of the code path it describes. None is operator-supplied, so none passes through the cardinality limiter and the series counts are fixed; the caps live in the [cardinality budget table](observability.md#cardinality-budget).

| Family | Labels | What moves it |
|---|---|---|
| `sbproxy_key_operations_total` | `operation` (mint\|update\|delete\|revoke\|block\|unblock\|rotate), `outcome` (ok\|refused\|error) | One increment per admin key-lifecycle call, counted at the dispatch seam from the status class the handler actually returned. `refused` is a 4xx the caller can fix (validation, revision conflict, rotating a revoked key); `error` means the store or governance backend failed. The two are never folded into one value, because a busy console and an outage are different facts. Keys only: `/admin/credentials` mutations are not counted on this family. |
| `sbproxy_credential_resolution_duration_seconds` | `cache` (hit\|stale\|miss), `outcome` (ok\|refused\|error) | One observation per bound-credential resolution. `hit` is the per-generation resolved-secret cache answering fresh; `stale` is the `proxy.secrets.rotation` grace window serving the last known-good value after the backend failed to answer; `miss` ran the full keystore/vault path. `refused` covers absent, revoked/blocked, and cross-tenant records; `error` is the secret backend failing. |
| `sbproxy_key_lookup_cache_total` | `kind` (key\|credential), `outcome` (hit\|negative_hit\|tier_hit\|miss\|error) | One increment per lookup through the TTL policy cache described above. `negative_hit` is the known-absent cache answering, reported as itself so a stampede of unknown keys stays visible. |
| `sbproxy_audit_write_failures_total` | `channel` (key_path\|admin_path) | Key or admin-console audit emissions that did not reach a sink they were promised. The channel's series is touched at 0 on every emission, so an `increase()` alert has a baseline before the first failure; it increments only from the write path's actual result. Any nonzero value means the tamper-evident trail has a hole that cannot be backfilled, and the existing `SBPROXY-AUDIT-WRITE-FAILURE` page alert fires on the same condition across every audit channel. |

Two caches sit on the credential path, and the two ratio metrics deliberately do not share a family, because they answer different capacity questions:

```mermaid
flowchart LR
    R[Request with a bound credential] --> RS{Resolved-secret cache fresh?}
    RS -- "yes: cache=hit" --> H[Present cached header]
    RS -- no --> TTL{TTL policy cache}
    TTL -- "hit / negative_hit / tier_hit" --> REC[Credential record]
    TTL -- miss --> STORE[(Key store)] --> REC
    TTL -- error --> GRACE{Grace window open?}
    REC -- absent --> REF["cache=miss, outcome=refused"]
    REC --> SECRET{Secret material}
    SECRET -- "plaintext / envelope" --> OK["cache=miss, outcome=ok"]
    SECRET -- "vault ref" --> VAULT[(Secret backend)]
    VAULT -- ok --> OK
    VAULT -- down --> GRACE
    GRACE -- yes --> STALE["cache=stale, outcome=ok"]
    GRACE -- no --> ERR["cache=miss, outcome=error"]
    TTL -.-> C1[sbproxy_key_lookup_cache_total]
    RS -.-> C2[sbproxy_credential_resolution_duration_seconds]
```

A falling TTL-cache hit ratio hammers the key store; a falling resolved-secret hit ratio hammers the secret backend. The two PromQL ratios:

```promql
# TTL policy-cache hit ratio (key + credential record lookups)
sum(rate(sbproxy_key_lookup_cache_total{outcome=~"hit|negative_hit|tier_hit"}[5m]))
  / sum(rate(sbproxy_key_lookup_cache_total[5m]))

# Resolved-secret hit ratio (vault round trips avoided)
sum(rate(sbproxy_credential_resolution_duration_seconds_count{cache="hit",outcome="ok"}[5m]))
  / sum(rate(sbproxy_credential_resolution_duration_seconds_count{outcome="ok"}[5m]))
```

What that looks like end to end. This config is the smallest one that exercises the three key-side families (the credential histogram needs a bound credential on an AI route):

```yaml
proxy:
  http_bind_port: 8080
  admin:
    enabled: true
    port: 9090
    username: admin
    password: change-me
  key_management:
    enabled: true
    store:
      backend: embedded
      path: /var/lib/sbproxy/keystore.redb
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER
      master_key: env:SBPROXY_KEY_MASTER

origins:
  "api.local":
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

Mint a key, run it through its lifecycle, then ask for one operation that has to be refused, and send three requests carrying a key that was never minted:

```bash
KEY=$(curl -s -u admin:change-me -X POST -H 'content-type: application/json' \
  -d '{"name":"analytics-batch"}' http://127.0.0.1:9090/admin/keys \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"]["key_id"])')

for action in block unblock rotate revoke; do
  curl -s -o /dev/null -u admin:change-me -X POST \
    http://127.0.0.1:9090/admin/keys/$KEY/$action
done

# Revoked is terminal, so this one is refused (409), not an error.
curl -s -o /dev/null -u admin:change-me -X POST \
  http://127.0.0.1:9090/admin/keys/$KEY/rotate

# Three requests carrying a key that does not exist.
UNKNOWN="sbp_deadbeefdeadbeef_$(python3 -c 'print("0"*64)')"
for i in 1 2 3; do
  curl -s -o /dev/null -H 'Host: api.local' -H "x-api-key: $UNKNOWN" \
    http://127.0.0.1:8080/
done

curl -s -u admin:change-me http://127.0.0.1:9090/metrics \
  | grep -E '^sbproxy_(audit_write_failures|key_(operations|lookup_cache))_total' | sort
```

```text
sbproxy_audit_write_failures_total{channel="admin_path"} 0
sbproxy_audit_write_failures_total{channel="key_path"} 0
sbproxy_key_lookup_cache_total{kind="key",outcome="miss"} 1
sbproxy_key_lookup_cache_total{kind="key",outcome="negative_hit"} 2
sbproxy_key_operations_total{operation="block",outcome="ok"} 1
sbproxy_key_operations_total{operation="mint",outcome="ok"} 1
sbproxy_key_operations_total{operation="revoke",outcome="ok"} 1
sbproxy_key_operations_total{operation="rotate",outcome="ok"} 1
sbproxy_key_operations_total{operation="rotate",outcome="refused"} 1
sbproxy_key_operations_total{operation="unblock",outcome="ok"} 1
```

Three things in that output are the whole design. The refused rotate sits on its own series rather than inside `rotate/ok` or `rotate/error`, so a dashboard can show operator mistakes without them reading as an outage. Three requests for one unknown key produced one store lookup and two negative hits, which is the stampede protection working and visible as itself. And both audit channels report an explicit `0` rather than no series at all, so an `increase()` alert has a baseline from the first scrape instead of from the first failure.

The `sbproxy-security` Grafana dashboard (`dashboards/grafana/sbproxy-security.json`) ships a Key Operations rate panel, the resolution p95 with its should-read-zero stale and error series, both hit ratios, and the audit-write-failure counter.

These four families are aggregate counters and histograms, and they are deliberately narrower than the per-event record. A metric tells you that three rotations happened in the last five minutes; it cannot tell you which key, under which tenant, at whose hands. For that, subscribe to the typed lifecycle events described under [the admin API](#the-admin-api), which carry the record id and the acting principal. The two surfaces watch the same seam on purpose, at deliberately different widths: `sbproxy_credential_resolution_duration_seconds{cache="stale"}` counts every grace-window serve, and a `credential_resolved` event with `outcome: stale_served` marks each episode once. Alert on the rate; investigate with the record. The event is not per serve because the grace path does not refresh the cached value's timestamp, so a five-minute window on a busy origin would otherwise put one event on the feed per request, and that feed is shared with `key_revoked`.

## The security model

Two kinds of secret, two different treatments.

Inbound virtual keys are **hashed**, never stored in a form you can read back.
The at-rest verifier is `HMAC-SHA256(secret, pepper)`. The server pepper means a
stolen store is useless without it, which a bare SHA-256 of the key would not
give you. A minted token has the shape `sbp_<key_id>_<secret>`; the `key_id` is
a public prefix, the `secret` is shown once and never stored. Verification is
constant-time. A legacy `sk-<key_id>-<secret>` shape is still accepted for keys
minted before the `sbp_` prefix and for config-seeded keys.

Upstream provider credentials are **encrypted**, because the proxy has to present
them to the provider. Two options: a vault reference (`vault://`, `awssm://`,
`gcpsm://`, ...) resolved at use, which is first-class and keeps the secret out
of the store entirely; or an AEAD envelope. The envelope generates a per-record
data key, encrypts the secret with AES-256-GCM bound to the record id, then wraps
the data key under a key derived from the `master_key`. Only the wrapped data key
reaches disk, so you can rotate the master without re-encrypting every payload.

Set `pepper` and `master_key` to a stable secret in production. Both accept the
same secret forms as the rest of `sb.yml`: `${NAME}` interpolation,
`env:NAME`, `file:PATH`, inline values, and configured secret-provider URIs.
`${NAME}` is expanded while the YAML is loaded; the remaining reference forms
are resolved when the key plane is constructed. Both `${NAME}` and `env:NAME`
are valid here, so you do not need to translate an existing environment-secret
convention for these two fields.

If either value is unset, sbproxy generates a new ephemeral value and warns.
That value changes on every process restart and every successful config reload,
including SIGHUP, filesystem-watch reload, and `POST /admin/reload`. Stored key
hashes and encrypted credentials created under the previous value immediately
become unusable when the new generation is published.

Generate each value as 32 bytes of cryptographic randomness, hex-encoded
(`openssl rand -hex 32`), and never reuse one value for both roles. See
[Generating secret values](secrets.md#generating-secret-values) for the full
guidance, including the PowerShell equivalent for Windows machines without
`openssl`.

### What happens when the store is down

`failure_posture` decides it. The default is `closed`: if the store cannot be
reached, a request carrying a virtual key is denied with `503`.

```yaml
proxy:
  key_management:
    enabled: true
    failure_posture: closed        # closed | degraded | open
```

| Posture | The request | What is left behind |
|---|---|---|
| `closed` (default) | Denied with `503` | The denial itself, at `WARN` |
| `degraded` | Falls through to the origin's own configured auth | `WARN` with `failure_posture=degraded` and `guarantee_waived=true` |
| `open` | Falls through to the origin's own configured auth | `WARN` with `failure_posture=open` and `guarantee_waived=false` |

Both admitting postures do the same thing to the request. Neither is a blanket
admit: the request falls through to whatever auth the origin already has, so an
origin with a `credentials:` block still authenticates it. What they change is
the record. A key-store outage means the request runs with no per-key policy,
no budget, and no attribution, and `degraded` is the posture that says so out
loud, in a field you can alert on. `open` admits the same request and claims
nothing about what was lost.

Pick `degraded` over `open` unless you have a specific reason to suppress the
signal. Pick either only if you have weighed an outage of the store against an
outage of your gateway.

`observe` is rejected at config-compile time here. It means "record the verdict
the control would have reached", and a store that could not be read reached no
verdict. Setting it fails startup with a message naming the key rather than
quietly picking one of the other three for you.

Try it against a store that is not there:

```bash
$ sbproxy run --config sb.yml            # store path points at a dead volume
$ curl -si -H "Authorization: Bearer sk-abc123-secret" http://localhost:8080/v1/models \
    | head -1
HTTP/1.1 503 Service Unavailable         # failure_posture: closed
```

Flip the posture to `degraded`, restart, and the same call falls through to the
origin's configured auth instead, leaving this in the log:

```
WARN key store unavailable; falling through to configured auth with no per-key
     policy, budget, or attribution failure_posture="degraded" guarantee_waived=true
```

An outage of the store is transient, not sticky. The `redis` backend holds a
reconnecting connection, so a Redis restart, a failover, or a `CLIENT KILL`
costs the resolutions that were in flight plus one redial: the next resolution
opens a fresh socket, `sbproxy_key_store_unavailable` returns to 0, and the
posture stops applying. Redis coming back is enough; the proxy does not need a
restart to notice.

The older boolean `failure_mode_allow` still parses and still means what it
always meant. It is used only when `failure_posture` is absent: `false` resolves
to `closed`, and `true` resolves to `degraded`. Nothing in the runtime reads the
boolean directly any more, so an existing config keeps its exact behavior and a
new one gets a knob that can say which kind of "allow" it means.

## Key identity and policy revisions

`key_id` is the immutable public identity of a key. It is the stable part of the
token prefix (`sbp_<key_id>_...`) and the identity used for policy and usage
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
# { "token": "sbp_a1b2c3d4e5f60789_...", "key": { "key_id": "a1b2c3d4e5f60789", ... } }
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
| `POST /admin/keys/{id}/budget-override` | Grant a temporary, auto-expiring budget raise |
| `DELETE /admin/keys/{id}/budget-override` | End an active raise early |
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
| `credential_id` | string | `null` | not exposed in read responses |
| `allow_content_capture` | `true` or `false` | rejects `null`; PATCH `false` to reset | same field |

`key_id` is immutable and is never accepted in PATCH. `status` changes only
through the block, unblock, and revoke action routes. Revocation is terminal.
Those action routes and rotation accept an optional `expected_revision`; PATCH
always requires it.

### Temporary budget overrides

`POST /admin/keys/{id}/budget-override` raises the key's effective budget
without touching the base caps, until an expiry the grant names, after
which the base resumes on its own. The body takes `max_tokens_increase`
and `max_cost_usd_increase` (at least one, each raising the matching base
cap), the expiry as either `ttl_secs` or an RFC 3339 `expires_at`, an
optional `reason`, and an optional `expected_revision`. A raise only lifts
caps the base budget has: an uncapped axis stays uncapped, and a key with
no base budget cannot be raised. Regranting replaces the current raise.

While the raise is live, read responses carry three budget fields: the
untouched `budget`, the `budget_override` (increases, `expires_at`,
`granted_by`, `granted_at`, `reason`), and the `effective_budget` the
request path is enforcing. `DELETE /admin/keys/{id}/budget-override` ends
a raise early; expiry needs no call at all. Three ends of the raise's
life reach the `key_audit` trail: `budget_override_grant` naming the
operator who granted it, `budget_override_clear` naming the operator who
ended a live raise early, and `budget_override_expire` for the
unattributed, time-driven end an admin read retires. Reconcile every
raise against `clear` OR `expire`; matching only one of them leaves
operator-cancelled raises looking like they are still running. The
override lifecycle,
the enforcement seam, and the runnable walkthrough are in
[ai-gateway.md](ai-gateway.md) under "Temporary budget overrides".

### Server schema and effective-policy preview

Admin clients should fetch `GET /admin/keys/policy-schema` instead of keeping a
separate list of editable fields. Each descriptor names the effective-policy
field, its PATCH field or lifecycle action, the recommended editor, its exact
clear value, the corresponding preview field, and the request-path enforcement
proof. The schema is available even when key management has not been enabled.

Preview a stored key against an optional request sample:

```bash
curl -s -u admin:change-me -X POST \
  http://127.0.0.1:9090/admin/keys/a1b2c3d4e5f60789/effective-policy/preview \
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
  http://127.0.0.1:9090/admin/keys/a1b2c3d4e5f60789 \
  | jq '{key_id: .key.key_id, policy_revision: .key.policy_revision}'

curl -s -u admin:change-me -X PATCH \
  http://127.0.0.1:9090/admin/keys/a1b2c3d4e5f60789 \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":3,"max_requests_per_minute":60,
       "max_budget_usd":50,"compression_profile":"compact",
       "name":"ci-runner"}'
```

A stale write returns `409` without exposing record contents:

```json
{
  "error": "key policy revision conflict",
  "key_id": "a1b2c3d4e5f60789",
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
curl -s -u admin:change-me -X POST http://127.0.0.1:9090/admin/keys/a1b2c3d4e5f60789/revoke \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":3}'
```

Rotation mints a fresh secret for the same `key_id` and keeps the prior secret
valid for a grace window (default one hour). Both tokens work during the window,
so a client fleet can pick up the new token before the old one stops working.

```bash
curl -s -u admin:change-me -X POST http://127.0.0.1:9090/admin/keys/a1b2c3d4e5f60789/rotate \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":3,"grace_secs":3600}'
# { "token": "sbp_a1b2c3d4e5f60789_<new>", "grace_expires_at": "...", "key": { ... } }
```

List, get, and conflict responses never carry a verifier hash, an envelope, or
a plaintext secret. Create and rotate are the only responses that carry a
plaintext token, and each token is shown once. Do not record admin request
bodies or create/rotate responses in shell history, reverse-proxy access logs,
or support bundles.

Successful key mutations emit a structured `key_audit` event with the operation,
resource kind, and public record id. The event does not contain a plaintext
secret or verifier hash. Route that tracing target to a protected audit sink and
apply normal operational-log access controls. With `audit.key_path` set, the
same mutations also land on the tamper-evident key chain, browsable from the
console's Audit view with per-read verification; see
[Audit log](audit-log.md#browsing-it-from-the-console).

Mint, revoke, rotate, and block additionally publish typed events on the
`events:` egress (`key_minted`, `key_revoked`, `key_rotated`, `key_blocked`),
so a SIEM alerts on a lifecycle change in real time instead of polling the
admin API, and `credential_resolved` joins them whenever an upstream
credential's material is actually read. `credential_fallback` joins them
when an AI provider entry falls back onto a seeded credential, or fails to.
Subscribe with the `events:` block:

```yaml
events:
  sink: webhook
  url: https://siem.example.com/sbproxy
  signing_secret: secret://local/siem-hmac
  types:
    - key_minted
    - key_revoked
    - key_rotated
    - key_blocked
    - credential_resolved
    - credential_fallback
```

A mint, rotate, block, revoke sequence lands in the feed as four NDJSON
lines (file-sink form shown, captured from a real run; timestamps and ids
will differ):

```json
{"event_type":"key_minted","hostname":"","tenant_id":"acme","timestamp":1787251963170,"data":{"id":"a7237f88fdd6fb04","op":"create","outcome":"applied","resource":"key"}}
{"event_type":"key_rotated","hostname":"","tenant_id":"acme","timestamp":1787251963173,"data":{"id":"a7237f88fdd6fb04","op":"rotate","outcome":"applied","resource":"key"}}
{"event_type":"key_blocked","hostname":"","tenant_id":"acme","timestamp":1787251963173,"data":{"id":"a7237f88fdd6fb04","new_status":"blocked","op":"block","outcome":"applied","prior_status":"active","resource":"key"}}
{"event_type":"key_revoked","hostname":"","tenant_id":"acme","timestamp":1787251963174,"data":{"id":"a7237f88fdd6fb04","new_status":"revoked","op":"revoke","outcome":"applied","prior_status":"blocked","resource":"key"}}
```

The payload never carries the plaintext token, a verifier hash, or the
`key_audit` diff, and that is a property under test rather than a
convention. [events.md](events.md#key-lifecycle-events-the-dual-record)
has the full field posture and the dual-record design (chain for tamper
evidence, typed event for real-time delivery).

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

`inject_mcp.ref` resolves an MCP action by `server_info.name` only within the
request route's tenant and pinned configuration generation. The injected set
is the intersection of the MCP action's tool allowlist, per-server RBAC,
version-gate verdict, and the key's optional `inject_mcp.filter`. A reference
cannot select another tenant's catalogue, and a rejected reload cannot replace
the source held by an in-flight request. If that governed intersection is
empty or the tenant-local reference is unknown, SBproxy sends an empty tool
array; it never falls back to caller-supplied tools.

The tenant is worth checking on an existing config. The reference used to
resolve by name across the whole node, so a key could reach a catalogue on any
tenant. It is now scoped, and a reference that crosses a tenant boundary
resolves to nothing: the request still succeeds, with no tools. Give the MCP
origin the same `tenant_id` as the `ai_proxy` origin whose keys name it. The
refusal is logged with the reference and the route's tenant, so grep for
`inject_mcp references an unknown MCP gateway` to find one.

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
      failure_posture: closed     # closed | degraded | open
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

`failure_posture` (default `closed`) decides what happens when a governance
backend outage stops a reserve call from completing. It takes the same three
values the key store's posture takes, and they mean the same things here:

| Posture | The request | What is left behind |
|---|---|---|
| `closed` (default) | Denied with `503` | The denial, at `WARN` |
| `degraded` | Admitted with no reservation | `WARN`, a `security_audit` event, and `sbproxy_governance_fail_open_total{key_id}` |
| `open` | Admitted with no reservation | `WARN` only |

`degraded` is the audited escape hatch: it admits the request without a
reservation, and every time it fires the decision is logged, recorded on the
`security_audit` channel, and counted, so running off the default posture is a
choice you can see in the numbers rather than a silent one. `open` admits the
same request and records neither the audit event nor the counter. That is the
only difference between them, and it is the reason to prefer `degraded`.

`observe` is rejected at config-compile time here too: a reserve call that never
reached its backend produced no verdict to record.

The older `failure_mode: closed | allow_unreserved` still parses and is used
only when `failure_posture` is absent. `closed` resolves to `closed` and
`allow_unreserved` resolves to `degraded`, which is what `allow_unreserved`
always did: the audit event and the fail-open counter have fired on that path
since it shipped. An existing config keeps its exact behavior.

A settle call that cannot reach the backend after a reservation already
succeeded is unaffected by either key. It stays best-effort, and the
reservation's own drop-time repair reconciles it later.

Every accepted reservation is held under a lease of `lease_ttl_secs`
(default 120). While the request or stream is in flight, the gateway renews
that lease at half its lifetime, so a long-running stream keeps its hold for
as long as it is actually running. Renewal only moves the expiry; it never
changes the held units. If the backend stays unreachable past the lease, the
reservation expires on the backend and its held units return to the pool; a
settle after that point is refused rather than revived, so an outage that
outlives the lease can leave that one request's usage uncharged.
`terminal_retention_secs` (default 300) is how long a settled, released, or
expired reservation's outcome is kept so replayed terminal calls stay
idempotent.

The token portion of a reservation is a conservative ceiling, not a guess:
models with a known tokenizer hold their exact prompt count, and unknown or
self-hosted models hold at least one token per raw request byte, which cannot
undercount a byte-pair encoded prompt. Settlement replaces the ceiling with
the usage the provider actually reported.

#### How close to the limit is "at the limit"

Under `strict`, admission is exact: a reserve either fits inside
`used + reserved + this request's ceiling <= limit` or it is denied, and
that arithmetic runs inside one Redis script, so two gateways racing the
same key cannot both win the last slot. For a request limit that makes the
accepted total exact, with no rounding at all.

For a token or monetary limit there is one rounding unit, and it is worth
stating plainly:

- **A response that settles no more than its reservation held moves the
  ledger by exactly what it consumed.** The accepted total lands at or
  under the limit with no overshoot. This is the ordinary case, because
  the ceiling covers the whole prompt and most replies are much smaller
  than the prompt they answer.
- **A response that settles more than its reservation held overshoots by
  that excess, once.** Only the prompt can be measured before dispatch; a
  reply's length is not knowable until it arrives, so a short prompt with
  a long unbounded completion can settle above its hold. The overshoot is
  bounded by that single request's excess per in-flight request, never
  compounding, and each such settlement is recorded against the
  reservation as `tokens_exceeded_reservation` (or
  `micro_usd_exceeded_reservation`) so it is countable rather than
  invisible.

If you need the second case bounded too, cap the reply: a request that
carries `max_tokens` cannot settle more than prompt plus that cap, and the
overshoot goes to zero.

The `approximate` tier adds a second, larger unit on top of both: peers
publish on an interval, so a node's view of fleet spend lags by up to one
dissemination cycle. Choose `strict` when the limit has to be exact.

An AI cascade counts every attempt it made, not only the one it served. A
tier whose answer scored too low is discarded from the response but was
still generated and still billed by the provider, so its tokens are folded
into the same settlement as the served reply. Without that, a caller who
can drive a cascade could hold a governed budget flat while spending
freely. The discarded portion is separately visible as
`sbproxy_ai_wasted_tokens_total{kind="failover_loser"}`, which is a breakdown of
the billed total rather than a second charge.

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
curl -s -u admin:change-me -X PATCH http://127.0.0.1:9090/admin/keys/a1b2c3d4e5f60789 \
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
store is unreachable this path reads the same `failure_posture` every other
inbound-key path reads, so it fails closed by default and falls through under
`degraded` or `open`, matching the bearer path.

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

Give a seeded key an id in the shape the gateway mints, sixteen lowercase hex
characters. Nothing validates the field, and a seeded key with any id
authenticates fine as `sk-<key_id>-<secret>`, but the minted token shape is
`sbp_<16 hex>_<64 hex>` and a rotated token has to parse back on the inbound
path. `POST /admin/keys/{id}/rotate` refuses a non-conforming id with a `409`
rather than hand you a token that authenticates nowhere. Avoid a dash in the
id for the same family of reasons: the legacy parser splits on the first one.

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
        - key_id: a1b2c3d4e5f60789
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

## Crypto material is pinned, not minted

An enabled key plane needs two secrets: `pepper`, which hashes inbound virtual
keys at rest, and `master_key`, which wraps the data key on every stored
upstream-credential envelope. Neither has a default, and a process that pins
neither refuses to boot.

That refusal is deliberate and it is a change. Earlier builds minted a random
pepper and logged a warning. The warning was read once, by whoever happened to
be watching the boot; the consequence arrived at the next restart, when every
stored key hash stopped verifying and every stored envelope stopped opening.
The first symptom was a flood of 401s, which is a long way from the cause.

```yaml
proxy:
  key_management:
    enabled: true
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER
      master_key: vault://secret/sbproxy/master
```

Both fields take a secret reference (`env:`, `file:`, `vault://`, `awssm://`,
`gcpsm://`, `azurekv://`, `k8ssecret://`) or an inline literal. A provider URI
needs a matching backend under `proxy.secrets.backends`; without one the field
is refused rather than becoming key material, because the reference text itself
is source-visible and identical on every deployment that copied the same
config.

Two further guards sit on these fields:

* A resolution that hands back the literal text of the reference that named it
  is refused. That is the shape of a real incident: a `pepper:
  awssm://prod/pepper` that nothing dereferenced became the 19-character ASCII
  string `awssm://prod/pepper`, offline-crackable by anyone who had read the
  documentation. The refusal covers the class, not the one instance: any
  scheme, any backend.
* An inline literal is exempt from that check and has to be, because
  `pepper: a-literal-value` is the documented way to pin one on a single node.

For a local development run where a key plane that does not outlive the process
is exactly what you want:

```yaml
proxy:
  key_management:
    enabled: true
    crypto:
      allow_ephemeral_secrets: true    # local development only
```

The process then mints both, warns on every boot, and the store is effectively
scratch.

## Rotation cadence

`key_management.crypto.rotation` names a crypto period per class of key
material. NIST SP 800-57 Part 1 Rev 5 frames a key's life as generation,
activation, active use, rotation, and destruction, and expects a deployment to
*state* its crypto period rather than leave "rotate periodically" as the whole
policy. These defaults are that statement.

| Field | Default | What it covers | Why that number |
|---|---|---|---|
| `inbound_key_days` | 90 | Minted virtual keys | A bearer token with no proof of possession, held by a caller sbproxy does not control |
| `credential_days` | 90 | Upstream provider credentials | Also a bearer credential, and one whose blast radius is the provider bill |
| `master_key_days` | 365 | The envelope master key | The symmetric data-encryption-key end of NIST's range. Under a customer-managed root this is the customer's Transit key cadence, not sbproxy's |
| `credential_grace_secs` | 300 | The rotation overlap window, below | Long enough for a provider-side activation to land, short enough that a retired secret is not left usable overnight |

Nothing enforces a cadence. What sbproxy provides is the number to alert on:
`GET /admin/credentials` publishes `sbproxy_key_rotation_age_days{kind="credential"}`
for the oldest record it listed, and each credential's detail view carries its
own `rotation_age_days`. Page when the gauge exceeds the period you named.

```promql
sbproxy_key_rotation_age_days{kind="credential"} > 90   # your credential_days
sbproxy_key_rotation_age_days{kind="key"}        > 90   # your inbound_key_days
```

Both series are published by their listing route, `GET /admin/credentials` and
`GET /admin/keys`, rather than by a timer: the gauge is refreshed by the thing
that was going to look at it anyway, and a deployment that never lists never
pays for it. A flat line means nothing is polling the admin API, not that
nothing is ageing.

## Rotating an upstream credential

`POST /admin/keys/{id}/rotate` has minted a fresh inbound secret with a
dual-validity window since the beginning. Rotating an *upstream* credential
used to be a `PATCH` overwrite: the instant it landed, every request presented
the new value, and a value the provider had not activated yet took the
deployment down with it.

```bash
curl -sS -u admin:admin -X POST \
  http://127.0.0.1:9901/admin/credentials/cred-openai/rotate \
  -H 'content-type: application/json' \
  -d '{"secret":"sk-the-new-one","grace_secs":300}'
```

```json
{
  "credential": {
    "id": "cred-openai",
    "storage": "encrypted",
    "rotated_at": "2026-08-28T09:14:02Z",
    "rotation_age_days": 0,
    "rotation_overlap_expires_at": "2026-08-28T09:19:02Z"
  },
  "overlap": {
    "grace_secs": 300,
    "previous_material_expires_at": "2026-08-28T09:19:02Z",
    "effect": "the previous material is used only if the new material will not resolve, and only until it expires"
  }
}
```

Read the overlap precisely, because it is narrower than the inbound-key one and
the two are easy to conflate. sbproxy *presents* an upstream credential rather
than validating one, so there is no old-value acceptance to do. The new
material is what every request uses. The previous material is reached only when
the new one will not resolve, and only while the window is open. A rotation that
works never presents the retired secret at all, and a warn line plus a
`credential_resolved` event with `outcome: rotation_overlap` fires when the
fallback is used, so a rotation that silently stayed in overlap is visible.

Pass `grace_secs: 0` when the secret you are replacing is compromised. The old
material is retired at once and there is no window.

Rotation is refused on a revoked credential. Revocation is terminal, and a
rotate that reactivated a revoked record would make revocation reversible by
anyone who can rotate.

## Customer-managed root of trust

By default the envelope's data key is wrapped by a key derived from
`master_key`, which this process holds for its whole life. A `vault://`
reference on that field does not change the shape: the read happens once, at
boot, and the copy is sbproxy's. Revoking the operator's Vault policy afterwards
changes nothing about what the process can still decrypt.

`key_management.crypto.root_of_trust` changes the shape. The data key is
wrapped and unwrapped by an external key service, and sbproxy never receives the
key that did it.

```yaml
proxy:
  key_management:
    enabled: true
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER
      master_key: env:SBPROXY_KEY_MASTER
      root_of_trust:
        provider: vault_transit
        address: https://vault.internal:8200
        mount: transit
        key_name: sbproxy-root
        token: env:SBPROXY_TRANSIT_TOKEN
        unwrap_cache_ttl_secs: 60
        liveness_interval_secs: 30
```

The provider is HashiCorp Vault's Transit secrets engine, chosen because its
contract is the one the claim needs: the caller hands over plaintext and gets
back ciphertext, or the reverse, and never receives the key. That is the same
shape AWS KMS `Encrypt`/`Decrypt` take, and it is what makes revoking the
customer's grant actually stop decryption rather than merely inconvenience it.
The `vault:v1:` prefix on Vault's ciphertext carries the key version, so the
customer can rotate their Transit key without re-wrapping a single stored
envelope: old ciphertext names the version that made it.

### The Vault policy, which is the customer's half

The customer creates the Transit key and owns it. sbproxy never creates it and
never reads it. What the customer grants is a token with exactly two
capabilities:

```hcl
# The whole grant. sbproxy needs `update` on encrypt and decrypt, and
# nothing else: not `read` on the key, not `create`, not `delete`.
path "transit/encrypt/sbproxy-root" {
  capabilities = ["update"]
}

path "transit/decrypt/sbproxy-root" {
  capabilities = ["update"]
}
```

Attach it to whatever auth method mints the token in
`root_of_trust.token`, and mount path and key name follow `mount:` and
`key_name:` if you changed them.

**Revoking is the point, so it is worth saying exactly what to revoke.** Any of
these stops decryption inside the bound below: delete the policy, delete or
revoke the token, or remove the two `path` stanzas. Dropping only
`transit/decrypt/...` is the narrowest form and still works. Deleting the
Transit key also works, but only if the key was created with
`deletion_allowed=true` on its `config` endpoint; Vault refuses the delete
otherwise, and answers an unrecognized parameter on key *creation* with a
warning rather than an error, so it is easy to believe you set it and find
the delete does nothing.

The liveness probe deliberately needs nothing beyond that policy. It encrypts a
fixed non-secret probe value and decrypts it again, which is the same pair of
capabilities the credential path uses, so it cannot fail on a correctly-scoped
policy and cannot keep passing through a revocation of either capability. An
earlier version read `transit/keys/sbproxy-root` instead, which needs `read` on
a third path the policy above deliberately does not grant: against a
least-privilege policy that probe failed forever on a healthy deployment, and
against a revocation that dropped only encrypt and decrypt it passed forever.
Neither is a thing you have to configure around now, and the policy above is
the whole grant.

One shape it still cannot see, stated rather than left to be found: the probe
encrypts a fresh value, so it always exercises the *current* key version. A
customer who rotates and then trims old versions with `min_decryption_version`
past the version that sealed existing envelopes keeps a green probe while
those stored credentials stop opening. Nothing is unsafe there, since the
`unwrap_cache_ttl_secs` bound still holds and the failures are loud at
resolution time, but the probe is a check that the grant is live, not that
every stored envelope still opens.

### The revocation-latency bound

`unwrap_cache_ttl_secs` is the number, and it is the product claim. An unwrap
per request would put a network round trip on the credential path, so an
unwrapped data key is reused for up to that long. **After the customer revokes
sbproxy's grant, decryption of customer-managed credentials stops within
`unwrap_cache_ttl_secs` seconds, or at the next failed liveness probe,
whichever comes first.** With the defaults above, that is 60 seconds worst
case, and typically sooner: the liveness probe runs every 30 seconds and drops
both caches on its first failure.

That is the whole exposure, not the first of two, and the distinction is worth
spelling out because getting it wrong is easy. There are two caches in series:
this module caches the unwrapped data key, and the resolved-credential cache
downstream caches the decrypted secret. Clamping each of them to the same
window W does **not** give you W, it gives you up to 2W, because the second
clock starts when the first hands over.

So the data key carries its own remaining time, and the credential cache
inherits that deadline instead of starting a fresh one. A secret decrypted one
second before its data key lapses is held for one more second, not for another
full window. The stale-serve grace window in `proxy.secrets.rotation` is
clamped the same way, so a grace period bought for a briefly unreachable secret
store does not become a grace period for a revoked root of trust.

A failed liveness probe drops every cached data key immediately, and with it
every already-decrypted credential, which is what turns the TTL into an upper
bound rather than a per-entry lottery. Both matter: purging only the data keys
would leave a credential this process had already decrypted going upstream for
its full inherited deadline while the admin surface reported
`cached_data_keys: 0`. The probe runs every `liveness_interval_secs` and
reports on the admin surface below.

### The dependency you are buying

A customer-managed root makes credential decryption strictly dependent on the
customer's key service. That is the feature, and it is also the cost, and the
two are the same sentence read from either side. HashiCorp documents the
identical trade for its own auto-unseal: a Vault whose KMS key is unavailable
stays sealed and cannot serve, and recovery keys do not substitute for the
seal mechanism.

Here the blast radius is narrower than Vault's, because only the
upstream-credential envelope depends on it: inbound key authentication, policy,
budgets, and every `vault_ref` credential keep working while the Transit mount
is unreachable. What stops is presenting a credential whose envelope the
customer's key wrapped. Requests bound to one fail to resolve rather than
falling back, which is the whole point and is not a bug to route around.

Two things follow. Size `unwrap_cache_ttl_secs` against your key service's
availability, not only against your revocation appetite: it is also how long a
blip is invisible. And keep at least one non-customer-managed path to the
providers you cannot afford to lose, if the customer's key service and your
proxy do not share a failure domain.

### What it covers, and what it does not

Read this before quoting the claim to anyone.

* It covers the **upstream-credential envelope**. A credential stored as an
  envelope after the root of trust was configured is unreadable without the
  external key service.
* It does **not** cover `pepper`, which hashes inbound virtual keys and is
  still held locally, nor the key-audit chain's fingerprint key, which is
  derived from `master_key`. Both are still required, and `master_key` also
  still opens envelopes sealed *before* the root of trust was turned on.
* Turning the feature on does **not** re-wrap existing envelopes. They keep
  opening under the local master, which is why nothing breaks at the switch and
  also why the claim is not retroactive. `POST /admin/credentials/{id}/rotate`
  re-seals under the current root and is the migration path; the credential's
  detail view carries `root_of_trust`, so an operator can see which records have
  moved.
* Credentials stored as `vault_ref` are not envelopes at all and are not
  covered. Their secret lives in the vault backend and the root of trust never
  touches them.
* A `plaintext` credential is not covered either, and never was.

### The admin surface

```bash
curl -sS -u admin:admin http://127.0.0.1:9901/admin/crypto/root-of-trust
```

```json
{
  "mode": "customer_managed",
  "kek": "transit/sbproxy-root",
  "revocation_window_secs": 60,
  "detail": "the envelope data key is wrapped by the external key service and is never held here. After the customer revokes sbproxy's grant, decryption of customer-managed credentials stops within 60 seconds, or at the next failed liveness probe, whichever comes first. The 60 seconds is the whole exposure, not the first of two: a decrypted credential inherits the time left on the data key that opened it rather than starting a fresh window.",
  "liveness": {
    "probe": "ok",
    "last_success_unix": 1787999640,
    "cached_data_keys": 3,
    "detail": "cached data keys are what a revoked grant still has to age out; a failed probe drops them and every already-decrypted credential immediately"
  },
  "rotation": { "master_key_days": 365, "credential_days": 90, "inbound_key_days": 90 }
}
```

`mode` is `local` when no root of trust is configured, and the body says so in
those words rather than leaving the reader to infer it from a missing field.

## Leased credentials, and the scope limit

Read the scope before the mechanism, because the scope is the honest part.

Every credential shape above is static until somebody rotates it. Vault's
actual differentiator is the opposite: mint on demand, hand back something with
a lease, let it expire. That works where the platform underneath can mint
short-lived credentials, and **most AI provider API keys cannot**. OpenAI,
Anthropic, and the OpenAI-passthrough catalog have no STS equivalent and no
short-TTL issuance, so there is nothing to lease against and no amount of
gateway plumbing creates one.

So leasing here covers exactly what it can: an enterprise buyer's own cloud IAM
(AWS for Bedrock, GCP for Vertex, Azure for Azure OpenAI) and Vault-fronted
database credentials, reached through a dynamic-secrets mount sbproxy reads.

One upgrade note: `leased` is a new `CredentialMaterial` variant, so a record
written by a node that has it and read by one that does not will fail to
deserialize. Roll the fleet before creating one. The three fields the rotation
overlap added to a credential record are `serde(default)` and are safe in both
directions.

```bash
curl -sS -u admin:admin -X POST http://127.0.0.1:9901/admin/credentials \
  -H 'content-type: application/json' \
  -d '{"id":"cred-bedrock","name":"bedrock-prod","provider":"bedrock",
       "lease":{"reference":"vault://aws/creds/sbproxy-bedrock",
                "platform":"aws","lease_duration_secs":900}}'
```

```json
{
  "credential": {
    "id": "cred-bedrock",
    "storage": "leased",
    "vault_ref": "vault://aws/creds/sbproxy-bedrock",
    "lease": {
      "platform": "aws",
      "lease_duration_secs": 900,
      "detail": "material is minted on demand and never cached past the lease; sbproxy re-leases at use time rather than renewing ahead of expiry"
    }
  }
}
```

The record stores the mount, not a credential. A resolution that cannot be
served from cache reads the mount, which mints; the resolved material is then
cached for at most `lease_duration_secs`, never longer, whatever
`proxy.secrets.rotation.re_resolve_interval_secs` says. That ceiling is the
whole difference between a leased credential and a `vault_ref` one.

`lease` for a provider whose platform cannot mint short-lived credentials is
refused at creation, with the limitation named:

```
provider 'openai' cannot be leased against platform 'aws'. Leasing needs a
platform that mints short-lived credentials (AWS, GCP, or Azure IAM, or a
Vault-fronted database mount); an AI provider API key has no short-TTL issuance
to lease against, so a leased record would be exactly as static as a stored one
```

Accepting that and reading the reference once would produce a record that says
"leased" on the admin view, never expires, and is exactly as static as the
stored secret it replaced. An operator would believe they had short-lived
upstream credentials and would not.

Three things this does not do, stated rather than implied:

* **No background renewal loop.** sbproxy re-leases lazily, at the next
  resolution after the cache lapses, rather than renewing ahead of expiry.
  For a non-renewable mount that is the correct behavior and the only
  available one. For a renewable mount it means a fresh lease rather than an
  extended one.
* **No lease revocation.** sbproxy does not call `sys/leases/revoke` on a lease
  it stops using; it relies on the mount's own TTL to reap it. Set
  `lease_duration_secs` to match the mount's configured TTL so the two agree.
* **The vault backend's own read cache still applies.** A dynamic mount read
  goes through the same `sbproxy-vault` backend as any other reference, and
  that backend caches. Keep its cache TTL below `lease_duration_secs`, or the
  effective re-mint interval is the backend's rather than the lease's.

## Read and access audit

`audit.key_path` records who *changed* a key or credential. It does not record
who *read* one, and "who touched this secret" is the question a breach
investigation actually asks.

```yaml
proxy:
  key_management:
    read_audit:
      enabled: true
      detail_window_secs: 300
      hash_identifiers: true
```

State the claim precisely, because the honest one is narrower than "we audit
every read":

* **Volume is recorded unconditionally.** `sbproxy_credential_read_total{outcome}`
  moves on every credential resolution, including the ones that ride the
  per-request cache. This is on whether or not `read_audit.enabled` is set.
* **Detail is recorded on a bounded cadence.** A chained record fires at most
  once per credential per `detail_window_secs`. The reads that do not get one
  are counted as `sbproxy_credential_read_audit_records_total{outcome="suppressed"}`,
  so the divergence is visible rather than silent.

A detail record per request at gateway volume would be a real hot-path tax and a
chain nobody could read. Cost here scales with credential count, not request
rate, which is the same shape HashiCorp Vault's audit devices take when they
separate what is counted from what is kept.

Field posture follows Vault's selective hash. With `hash_identifiers: true`
(the default) the credential id in the detail record is replaced by
`hmac-sha256:<hex>` under the key-audit fingerprint key, and the timestamp,
outcome, tenant, and cache layer pass through readable. An investigator who
suspects a specific credential confirms it by hashing that id the same way,
rather than by reading a chain that enumerates every credential the deployment
holds. Two fingerprints are comparable only when they carry the same
`key_epoch`; a rotated `master_key` re-bases every fingerprint after it.

The records land on the existing `key_audit` channel with `op: resolve`, which
means they reach the chain when `audit.key_path` is set and reach the tracing
target and the admin ring either way. That was a choice between extending a
proven channel and adding a fifth one: the read records share the payload
shape, the fingerprint key, and the verification command with the mutation
records, and a reviewer pulling one credential's history wants both in one file
rather than in two joined on a timestamp. The per-channel opt-in cost stays
separated by the second key: reads need both `audit.key_path` and
`read_audit.enabled`.

## Break-glass emergency access

Before this, the narrowest thing available for "I need access to this one
credential, right now, and I want it to be impossible to use quietly" was the
standing admin credential.

```yaml
proxy:
  key_management:
    break_glass:
      enabled: true
      approvers: [alice, bob, carol, dave]
      quorum: 2
      max_ttl_secs: 3600
      review_window_secs: 86400
```

A grant is not a new authorization model. It is a time-boxed, scoped, audited
marker on an admin session: authorization is still the admin RBAC roles. What
the grant adds is that the access was asked for, agreed to by other people,
bounded, and attributable afterwards to one id. The shape follows what every
vault and PAM product surveyed converges on: pre-staged, time-boxed at 15 to 60
minutes, scope-limited, two-person or quorum approved, and reviewed inside a
fixed window.

```bash
# 1. Request. Scope and justification are both required.
curl -sS -u alice:… -X POST http://127.0.0.1:9901/admin/break-glass \
  -H 'content-type: application/json' \
  -d '{"justification":"incident 4412, provider key rotated out from under us",
       "scope":["cred-openai"],"ttl_secs":900}'
# 201 { "grant": { "id": "bg_…", "state": "pending_approval", "approvals_needed": 2 } }

# 2. Approve, twice, by two other operators on the roster.
curl -sS -u bob:…   -X POST http://127.0.0.1:9901/admin/break-glass/bg_…/approve
curl -sS -u carol:… -X POST http://127.0.0.1:9901/admin/break-glass/bg_…/approve
# 200 { "grant": { "state": "active", "expires_at": "…" } }

# 3. Anything alice does now is tagged with the grant id in the key audit chain.

# 4. After it expires, somebody else signs off. The reviewer must be on the
#    approver roster and must not be the requester, the same two rules
#    `approve` enforces: a grant its own requester can close is a grant
#    nobody reviewed.
curl -sS -u dave:… -X POST http://127.0.0.1:9901/admin/break-glass/bg_…/review \
  -H 'content-type: application/json' -d '{"note":"rotation confirmed, no other access"}'

# The queue a reviewer opens.
curl -sS -u admin:admin http://127.0.0.1:9901/admin/break-glass
```

The sign-off note comes back on the grant as `reviewed_note`, beside
`reviewed_by` and `reviewed_at`, on both the `review` response and every grant
in the queue:

```json
{ "grant": { "id": "bg_...", "state": "reviewed",
             "reviewed_by": "dave", "reviewed_at": "2026-08-28T14:02:11Z",
             "reviewed_note": "rotation confirmed, no other access" } }
```

It is a field rather than only a line in the audit record's context string
because that string is capped at 256 bytes and shares its budget with `scope`,
which is bounded two orders of magnitude higher. A grant with a large scope
truncated `approvals=`, `ttl_secs=`, and the note out of the record, which is
to say it dropped the sign-off on exactly the grants most likely to want one.
The context string now carries bounded counters and the note rides the
structured diff, where the justification already lives. A note over 1024 bytes
is truncated on a character boundary; an empty note is recorded as absent
rather than as an empty string.

Rules the endpoints enforce rather than document:

* **No self-approval and no self-review**, both refused before the roster is
  consulted, so adding yourself to `approvers` does not close either gap. A
  two-person rule one person can satisfy is not a two-person rule, and a review
  queue its own subject can clear is not a review queue. **A refusal is
  recorded**, on the same `key_audit` channel as the transitions, with
  `outcome: refused` and a closed-vocabulary `reason` of `self_approval`,
  `self_review`, `not_an_approver`, or `registry_full`. `reason` is a field
  of the record's structured `after` diff, not a top-level `KeyAuditEntry`
  field, so a SIEM rule selects on `outcome` and reads `after.reason`. The
  refusal is counted on `sbproxy_break_glass_grants_total{event="refused"}`,
  which carries no reason dimension. An operator caught trying to close
  their own grant is the event this feature is bought for, so it leaves more
  than an HTTP 403.
* **`review` has no `enabled` guard, and that is deliberate.** `request`,
  `approve`, and `tag_action` all refuse when `break_glass.enabled` is false,
  because those three create or extend access. `review` closes access out. A
  kill switch that also blocks the closing-out would strand every open grant:
  grants live in process memory and survive a config reload, so nothing could
  ever reach `reviewed`, and the `awaiting_review` gauge below would stay
  pinned above zero for the life of the process.
* **An empty roster falls back to "any admin who is not the requester",
  and that is the only strand this closes.**
  Deleting the `break_glass:` block entirely reaches the same strand by a
  different route, because the block's default is `enabled: false,
  approvers: []` and the config compiler validates the roster only while
  `enabled` is true. So an empty roster means the feature was turned off
  with grants still open, and a plain roster check would refuse every
  operator. The two-person property survives the fallback, since the
  requester is still refused; what is given up is "and that person was
  pre-named". Those sign-offs are recorded with
  `outcome: reviewed_without_roster`, on the audit record and on
  `sbproxy_break_glass_grants_total`, so they are distinguishable in the
  chain and on the dashboard.

  **A roster that is non-empty but has no eligible reviewer left still
  strands.** With `enabled: true` and a roster whose last non-requester
  approver has been removed, every other operator is `NotAnApprover` and
  the requester is refused as the subject, so the grant cannot reach
  `reviewed`. There is no force-close and no admin override. Keep at least
  two people on `approvers` for as long as any grant is open, or empty the
  list, which is the case the fallback covers.
* **Removing `key_management.enabled` hides the queue.** With the whole
  block gone, `GET /admin/break-glass` reports `{"enabled": false,
  "grants": []}` and `review` answers `409 disabled`, while the grants stay
  in process memory and come back if the block returns. The gauges are
  published as zero rather than left at their last value, so the
  `awaiting_review` alert cannot sit frozen above zero with no route able
  to move it. Turning the block off is not a way to close out a queue.
* **`quorum` is validated at config compile.** Zero is refused, because a grant
  would activate on its first approval while the admin surface reported it as
  quorate; a quorum above the roster is refused too, because you would discover
  it during the incident.
* **A TTL above `max_ttl_secs` is refused, not clamped**, so the requester finds
  out now rather than when the grant expires early.
* **An unscoped request is refused.** An unscoped break-glass grant is a
  standing admin credential with extra paperwork. The scope is *declared*
  rather than enforced: it is what the requester said they needed and what the
  reviewer reads afterwards, and it is not compared against the records the
  tagged actions touch. Enforcing it would mean a second authorization model,
  which is what this deliberately is not.
* **Expiry is computed on read.** There is no sweeper to fail to run.
* **An expired grant with no sign-off does not close.** It moves to
  `awaiting_review` and stays on the queue and on
  `sbproxy_break_glass_open{state="awaiting_review"}` until a human signs off,
  and is marked overdue past `review_window_secs`. Expiry is time-driven and
  nothing sweeps, so `GET /admin/break-glass` is what observes it: that read
  republishes the gauges and emits the `expired` or `denied` transition once.
  A deployment that never reads the queue never sees it move, which is the same
  trade the rotation-age gauge makes.

Two limitations to know before relying on it.

**Break-glass is a single-node feature today.** Grants live in process memory,
so a restart voids every active grant, which fails safe. The fleet half needs
stating plainly rather than left to be derived: behind a normal admin load
balancer the four calls above land on different processes, so alice's request
goes to node A, bob's approve goes to node B and answers `404 no such
break-glass grant`, and there is no supported way to pin them together. Point
this flow at a single admin endpoint. Closing the gap means a store-backed
grant record, which this does not have.

What that does *not* mean is that a fleet bypasses the control. A grant confers
no authority: authorization is still admin RBAC, so an operator who wants to act
on node B can already act on node B, grant or no grant. The quorum is an
attestation recorded beside the actions, not a gate, which is why a per-node
quorum is a weaker record rather than an open door.

**No console page.** The request, approval, countdown, and review queue are
JSON routes; the console flow is deferred to the admin-console work and these
routes are what that page will read.

## Key-lifecycle events in CEF

`key_minted`, `key_revoked`, `key_rotated`, and `key_blocked` reach the
`events:` egress as JSON. A SIEM that cannot take JSON gets the same records
flattened into ArcSight CEF on the `key_audit_cef` tracing target, the format
Vault's own audit device emits:

```
CEF:0|Soap Bucket|sbproxy|1.13.0|sbproxy.key.revoke|key revoke|7|rt=1787999640 outcome=applied duid=sbp_a1b2c3d4e5f60789 cs1Label=resource cs1=key suser=operator-jo cs2Label=tenant cs2=acme cn1Label=evidenceSeq cn1=42 cs3Label=evidenceInstance cs3=…
```

Route that target wherever the SIEM reads. A deployment that does not subscribe
to it pays one disabled-callsite check per mutation and nothing else. LEEF is
not emitted, and that is a decision rather than an omission. CEF is the open
standard every major SIEM has an ingest path for, and it is what Vault's own
audit device emits. LEEF is IBM's own format: QRadar parses it more tightly
than it parses CEF, but QRadar does read CEF through its Universal DSM, so the
choice costs a QRadar-only shop some parsing polish and buys everyone else one
mapping instead of two. A second mapping is a second place a later field can
silently stop crossing, and only one of them would be exercised daily.

Every record on this feed now carries `sbproxy.evidence.seq` and
`sbproxy.evidence.instance`. Within one instance, one tenant's sequence is
gapless and strictly increasing, so a receiver that sees `1, 2, 4` knows exactly
one record was lost. The feed is still a lossy real-time copy and the local hash
chain is still the durable record; what the sequence adds is that a loss is
*visible to the receiver* without trusting the process that wrote it, which
matters because the chain's Ed25519 signing key lives in that same process.

## Examples in Practice

To see various authentication schemes configured in practice, refer to these runnable examples:

| Example | What it is | How to use it | Outcome |
|---------|------------|---------------|---------|
| [`auth-api-key`](../examples/auth-api-key/) | Simple API Key auth. | Validate keys against a static list or external Vault. | Rapidly secure internal or simple B2B APIs. |
| [`auth-basic`](../examples/auth-basic/) | Standard HTTP Basic Auth. | Use `auth: basic` with hashed credentials. | Secure legacy clients that only support Basic Auth. |
| [`auth-bearer`](../examples/auth-bearer/) | Bearer token validation. | Check generic bearer tokens against a known authority. | Standard, stateless client authentication. |
| [`auth-bearer-dpop`](../examples/auth-bearer-dpop/) | Bearer tokens with DPoP. | Enforce Demonstrating Proof-of-Possession (DPoP). | Prevents token theft by binding tokens to a client's private key. |
| [`auth-cap`](../examples/auth-cap/) | CAP Auth. | Use `auth: cap` for capability-based authorization. | Granular, cryptographically secure capability delegation. |
| [`keys-inbound-headers`](../examples/keys-inbound-headers/) | Key resolution from headers. | Map custom headers (e.g. `X-My-Key`) to auth principals. | Flexible integrations with existing client code. |
| [`sessions`](../examples/sessions/) | Stateful browser sessions. | Manage secure HTTP-only cookies and CSRF. | Full lifecycle management for web applications behind SBproxy. |
