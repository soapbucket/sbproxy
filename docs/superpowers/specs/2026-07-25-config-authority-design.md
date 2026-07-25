# Config authority: signed config distribution for a proxy fleet

Status: design accepted 2026-07-25. Not yet implemented.

## The problem

A single SBproxy reads its config from a local YAML file. That works for one box. It stops working the moment you have a fleet, and it stops working completely once we run a managed service, because the thing that decides what a customer's proxy should do lives on our side of the network and the proxy lives on theirs.

We need a proxy that can ask an upstream service "what should I be running?", get an answer it can prove came from the right place, and apply it without a human touching the box. That upstream can be a proxy the customer runs themselves, or it can be us.

## What already exists

Most of the hard parts are built. I went looking expecting to design a signing scheme and found one already in production use.

`SignedDeploymentBundle` in `crates/sbproxy-model-host/src/cluster_authority.rs` does authority-signs / followers-verify for model deployments. Ed25519 over RFC 8785 canonical JSON, a monotonic authority revision, a content digest, and a `DeploymentBundleCursor` that rejects both revision rollback and same-revision content drift. The config bundle is the same shape with a different payload.

`proxy.cluster.deployment_authority` already splits `signing_key_file` (authority only) from `verifying_key_file` (every node). `ClusterNodeRole::Authority` already exists and is authenticated rather than self-declared, because it lives in the enrollment-signed identity document.

The reload transaction in `crates/sbproxy-core/src/server/lifecycle.rs` is the piece that makes this cheap. `reload_from_config_yaml` takes YAML, compiles it, reconciles every subsystem, and only then publishes into the `ArcSwap<CompiledPipeline>`. Any failure returns before the swap and the previous pipeline keeps serving. A subscriber does not need its own apply path. It needs to produce YAML and hand it to that function.

`/admin/config` already does read, optimistic-concurrency write, validate-before-persist, atomic temp-file rename, and hot swap. `/admin/drift` already compares loaded against on-disk. `schemas/sb-config.schema.json` is generated from `ConfigFile` and CI-gated for freshness, and nothing serves it to anyone.

`/admin/cluster/enroll` is dispatched before the admin auth gate and authenticates with a single-use token instead of admin credentials. That is exactly the shape the subscriber endpoint needs, and the token format (`sbce1.<id>.<secret>`, stored as SHA-256, compared in constant time) is already written and tested.

## Two things I found that this epic has to clean up

`ConfigSource` (`Local | Git | GitOverlay`) parses, appears in the JSON Schema, and is silently ignored. `compile_config_from_source` has no production call site; boot and reload both call `compile_config` directly. Two Linear tickets closed this as Done in May, and the ADR one of them references (`docs/adr-config-source-modes.md`) does not exist. So an operator can write `source: {kind: git, ...}` today, get no error, and run their local file.

`ConfigBroadcaster` and `ConfigVersion` in `crates/sbproxy-mesh/src/state/config_broadcast.rs` are dead. Nothing constructs a broadcaster. The only reference is an unwritten `PersistedState.config_version` field.

Both answer the question "where does config come from", which is the question this epic exists to answer. Leaving them in place means three overlapping mechanisms and one true one. The epic owns deleting or wiring them.

## Design

### Naming

No master and no slave. The publishing node is a **config authority** and the pulling node is a **subscriber**, which extends the `Authority` role already in the cluster vocabulary rather than inventing a second one. This lands in public docs and YAML keys, so it matters.

### Config shape

```yaml
proxy:
  config_authority:
    # Present on a subscriber. This node pulls.
    upstream:
      url: https://control.example.com
      mode: overlay                    # overlay | replace
      subscriber_id: edge-01
      credential: env:SB_CONFIG_TOKEN
      verifying_keys_file: /etc/sbproxy/authority-keys.json
      poll_interval: 30s
      cache_path: /var/lib/sbproxy/config-bundle.json
      max_staleness: 24h               # alert threshold
      require_bundle_on_boot: false    # forced true when mode is replace

    # Present on an authority. This node publishes.
    publish:
      signing_key_file: /etc/sbproxy/authority.key
      key_id: prod-2026-07
      authority_id: acme-prod
      store_dir: /var/lib/sbproxy/config-authority
```

A node may set `upstream` or `publish`, never both. Chained authorities are rejected at config validation. One hop keeps the provenance story answerable.

### The bundle

```json
{
  "schema_version": 1,
  "bundle": {
    "authority_id": "acme-prod",
    "revision": 42,
    "mode": "overlay",
    "content_digest": "sha256:...",
    "config_yaml": "...",
    "issued_at_unix_ms": 1753400000000,
    "expires_at_unix_ms": null
  },
  "key_id": "prod-2026-07",
  "algorithm": "ed25519",
  "signature": "base64..."
}
```

Signing bytes are RFC 8785 canonical JSON of the `bundle` object prefixed with the domain-separation context `sbproxy.config-bundle.v1`, matching the existing `sbproxy.cluster-state.v1` and `sbproxy.model-dispatch.v1` conventions. Use `serde_json_canonicalizer`, which is already a workspace dependency and already used for model-host bundles. Do not copy the `model_plane/envelope.rs` approach, which uses plain `serde_json::to_vec` and is inconsistent with everything around it.

Ed25519 is the default and the only algorithm the managed service will offer. HMAC-SHA256 with a shared secret is available for single-tenant and development, gated behind an explicit `algorithm: hmac-sha256` plus an acknowledgement flag, the same way `ClusterSecurityConfig` gates `shared_key` behind `development: true`. The reason to prefer Ed25519 is blunt: with a shared secret every subscriber holds key material that can forge configs for every other subscriber.

`verifying_keys_file` holds a map of `key_id` to public key so the authority can rotate without a synchronized fleet restart. The multi-kid verifier in `crates/sbproxy-modules/src/policy/quote_token.rs` is the pattern to copy.

### Anti-rollback

Persist `{revision, content_digest}` next to the cached bundle. Reject any candidate whose revision is lower than the stored one, and reject a candidate at the same revision with a different digest. This is `DeploymentBundleCursor` verbatim. The cursor survives restart, so a signed-but-old bundle replayed by a network attacker is refused even across a reboot.

### Merge semantics and the deny-list

Some config describes the fleet and some describes the box. An authority that can set `proxy.admin.password` owns the box, so the boundary is a security control and not a convenience.

Paths the authority may never set:

- `proxy.cluster` (node id, seeds, ports, advertise addresses, state dir, security material, enrollment)
- `proxy.admin` (credentials, bind, allowlist, TLS)
- `proxy.listeners`
- `proxy.tls`
- `proxy.secrets`
- `proxy.config_authority` (a bundle that could repoint the subscriber at a different authority, or turn verification off, defeats the whole design)
- `proxy.model_host` (`SignedDeploymentBundle` already owns that channel; two signed writers on one piece of state is a correctness hazard)
- `source`

Everything else is fair game: origins, AI providers, policies, transforms, rate limits, agent classes, audit, access log, extensions.

A denied path present in a remote document rejects the entire bundle and logs which paths caused it. It is never silently dropped. The LiteLLM importer already learned this lesson and has a silent-drop gate for the same reason.

The two modes then differ in one sentence each:

- **overlay**: the local file is the base, the remote document merges on top, and remote wins key by key.
- **replace**: the remote document is the base, deny-listed paths are grafted in from local, and every other local key is discarded.

Merge is a pure function from `(local_yaml, remote_yaml, mode)` to `(merged_yaml, provenance_map)` where the provenance map records, for every leaf path, whether the value came from local or from the authority. Table-test it hard. It is the piece most likely to produce a subtle wrong answer.

### Failure behaviour

| Situation | Behaviour |
| --- | --- |
| Authority unreachable | Keep serving the last verified bundle. Alert. `sbproxy_config_bundle_age_seconds` climbs. |
| Signature, schema, or compile failure | Reject the candidate. Previous config keeps serving. Counter plus alert. Never partially applied. |
| Denied path in bundle | Same as above, with the offending paths named in the log. |
| Cold boot, no cache, mode `overlay` | Boot on the local file with a loud warning, unless `require_bundle_on_boot` is set. |
| Cold boot, no cache, mode `replace` | Refuse to start. There is nothing to serve. |

Staleness is an alert, not an enforcement gate. An authority outage should not become a fleet outage, and a grace window would just become one more number everyone has to tune correctly.

### Refresh

Baseline is `GET /config-authority/v1/bundle` with `If-None-Match`, on `poll_interval`, answering 304 when nothing changed. It works identically whether or not the subscriber is a mesh member, which matters because managed-service subscribers reach us over the internet and are not in anyone's gossip cluster.

Mesh members get an accelerator. The authority publishes `{revision, digest, authority_id}` into cluster typed state under a `config-authority` namespace, which is already signed and generation-fenced by `ClusterStateEnvelope`. A subscriber that observes a higher revision pulls immediately instead of waiting out the interval. Gossip is never required for correctness, so a bug there degrades propagation speed and nothing else.

Build this on `ClusterHandle::publish_state`. Delete `config_broadcast.rs` and the unwritten `PersistedState.config_version` field rather than reviving a mutex-wrapped struct nothing ever called.

### Applying

The subscriber produces merged YAML and calls `reload_from_config_yaml`, taking `CONFIG_RELOAD_LOCK` like every other reload path. Atomicity, subsystem reconciliation, and the `ArcSwap` publish all already work and are already tested by `empty_startup_reload_is_atomic_and_collects_every_origin`. The subscriber contributes a source of bytes and nothing else.

### The editor

The rule is that the editor is live only where the node owns its own config. A node that pulls from an upstream authority must not offer an editing surface that the next poll will silently overwrite.

Concretely:

- No `upstream` configured: the editor works as it does today.
- `upstream` in `replace` mode: fully read-only, with a banner naming the authority, its id, and the current revision.
- `upstream` in `overlay` mode: locally-owned keys stay editable, and every key the authority defines renders locked with an `authority: <id> rev <n>` badge.

Enforcement is server-side. `PUT /admin/config` rejects any write touching an authority-owned path with 409 and the conflicting paths listed, so the rule holds for curl and for the UI equally. The UI state is a courtesy on top of a real guard.

New admin surface:

- `GET /admin/config/effective` returns merged config plus the provenance map.
- `GET /admin/config/schema` serves the generated JSON Schema, which exists and is CI-gated and is currently served nowhere.

### Schema-generated forms

Operators should be able to change config without writing YAML. `sb-config.schema.json` is 302KB and genuinely polymorphic in places, so a form renderer cannot cover all of it and should not pretend to.

Render forms for the tractable subset: scalars, enums, arrays of scalars, and nested objects with declared properties. For nodes the schema deliberately leaves opaque (`origins[].action`, `policies[]`, `transforms[]`, `authentication` are all `serde_json::Value` in the Rust types), drop to a YAML sub-editor for that node only. Every field carries provenance and renders locked when the authority owns it.

The part that is easy to get wrong: a form must never destroy config it did not render. Re-serializing the whole document through `serde_yaml` drops comments and key order, which operators will correctly treat as data loss. So the form emits a patch, a set of path-to-value operations, and applies it client-side with the `yaml` npm package, which preserves comments and ordering. That also means no CodeMirror, so the bundle grows by roughly 40KB gzipped instead of 200KB and the UI stays close to its dependency-light intent. The existing textarea remains as the raw escape hatch.

### Metrics

- `sbproxy_config_bundle_revision` gauge
- `sbproxy_config_bundle_age_seconds` gauge, measured from `issued_at`
- `sbproxy_config_bundle_fetch_total{result}` where result is `ok`, `not_modified`, `unreachable`, `verify_failed`, `compile_failed`, or `denied_path`
- `sbproxy_config_bundle_applied_total`

Wire them at the point of use. Three metrics in the observability epic shipped declared-but-never-incremented and had to be fixed later, and the counter-name collision hazard from that work applies here too.

### Licensing

Subscriber, bundle format, signing, and a single-tenant authority all ship Apache 2.0. Anyone can run their own control plane, and the managed service becomes a second implementation of the same versioned REST contract, which is the only reliable way to find out whether the contract is actually implementable by something that is not SBproxy.

Multi-tenancy, per-tenant key management, editor RBAC and approvals, config history and audit, and staged rollout stay enterprise.

## Components

Each of these should be understandable and testable on its own.

| Component | Where | Depends on |
| --- | --- | --- |
| Bundle format, sign, verify, revision cursor | `sbproxy-config` | nothing |
| Merge engine and deny-list | `sbproxy-config` | nothing |
| Subscriber client and poller | `sbproxy-core` | bundle, merge |
| Authority server and revision store | `sbproxy-core` | bundle |
| Gossip accelerator | `sbproxy-core` + `sbproxy-mesh` | subscriber, authority |
| Admin effective-config and provenance API | `sbproxy-core` | merge |
| Schema-form editor | `ui/` | admin API |
| CLI | `sbproxy` | bundle, authority |

The first two are pure functions with no I/O and carry most of the correctness risk, so they land first and get the heaviest tests.

## Testing

Unit and table tests cover bundle round-trip, signature rejection under every mutation, rollback and same-revision-drift rejection, merge semantics in both modes, and deny-list detection at every listed path.

Integration tests cover subscriber boot from cache, 304 handling, apply through the real reload transaction, and the `PUT /admin/config` guard rejecting authority-owned paths.

End-to-end certification is a two-node drill: authority publishes, subscriber applies, then key rotation, then a replayed old bundle, then authority killed mid-poll. These run locally and stay out of the required CI gate, matching existing practice for `sbproxy-e2e`.

## Non-goals for v1

Per-subscriber targeting and label selectors, staged or canary rollout, config history and diff browsing beyond one rollback step, secret values traveling in bundles (URI references travel, resolved values never do), and chained authorities.
