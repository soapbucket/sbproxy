# Config authority: signed config distribution for a proxy fleet

Status: design accepted 2026-07-25, and partly built. Shipped: the reload
transaction rework everything else depends on, the signed bundle format
and its replay cursor, the merge engine and its deny-list, the admin
hardening, the subscriber client, the authority server, and the gossip
accelerator. Still to build: the git source, the admin API and editor
surfaces, the CLI, and certification.

The "Hard edges" and "Solutions" sections below are left as first
written rather than tidied afterwards. What changed during the audit is
the useful part of this document, and a version that reads as though it
were correct from the start would be worth less.

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

## Two things I found that this epic has to fix

`ConfigSource` (`Local | Git | GitOverlay`) parses, appears in the JSON Schema, and is silently ignored. `compile_config_from_source` has no production call site; boot and reload both call `compile_config` directly. Two Linear tickets closed this as Done in May, and the ADR one of them references (`docs/adr-config-source-modes.md`) does not exist. So an operator can write `source: {kind: git, ...}` today, get no error, and run their local file. `source.rs` itself is 452 lines of real, tested implementation that nothing calls.

`ConfigBroadcaster` and `ConfigVersion` in `crates/sbproxy-mesh/src/state/config_broadcast.rs` are dead. Nothing constructs a broadcaster. The only reference is an unwritten `PersistedState.config_version` field.

Both answer the question "where does config come from", which is the question this epic exists to answer. Git source gets wired properly (see below). The mesh broadcaster gets deleted, because typed cluster state already does that job with signing and generation fencing, and maintaining a weaker second version of it helps nobody.

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

### Git as a source

`source:` and `config_authority:` answer different questions, so both stay. `source:` says where a config document comes from. `config_authority:` says who is allowed to change it remotely and how that change is proven. A document fetched from git is still a document, and it can still have an authority overlaid on top of it.

That gives one mechanism and three useful deployment shapes:

- **Standalone GitOps.** A proxy with `source: {kind: git, ...}` and no authority pulls its whole config from a repo on a timer. This is the Kong-declarative and Flux-style story people ask for, and it needs no signing infrastructure.
- **Git base with an authority overlay.** A subscriber whose local file declares a git source resolves that first, then merges the signed authority overlay on top. The operator keeps their own baseline in their repo, and central policy still lands on it.
- **Git-backed authority.** An authority whose published document declares a git source resolves it before signing. Customers keep config in their own repo, and we sign and distribute it. This is the shape the managed service wants, and it falls out for free as long as the publish path in CA-04 calls the source-resolving compile rather than the plain one.

Resolution order is fixed: resolve `source:` to get the base document, then apply the authority overlay, then compile. The authority always wins over git, because the deny-list is what protects the box and the authority is the layer the deny-list is enforced against. Git content is operator-owned and therefore unrestricted, which is right, since it is equivalent to the operator editing the file by hand.

Two things about git deserve to be said plainly rather than discovered later.

**Git is a weaker trust story than a signed bundle.** There is no signature, no revision fence, and no provenance beyond "the remote said so". It is transport trust: HTTPS plus whatever the git host authenticated. That is fine and it is what every GitOps tool does, but it is not the same guarantee as a bundle, and the docs should not imply that it is. Two cheap hardening steps close most of the gap. Pin `revision` to a full commit SHA and verify the resolved HEAD matches it, which buys immutability against a branch moving underneath you. And offer `verify_signature: true` for repos using signed tags or commits, for operators who want the real guarantee.

**The `git` binary is a runtime dependency.** `GitBinaryCloner` shells out. Every proxy host that uses a git source needs git installed, container images included. Make that a loud preflight failure with a clear message rather than a confusing clone error, and have `doctor` report it. Also note that `git clone --depth 1` cannot fetch an arbitrary commit SHA against a server without `uploadpack.allowReachableSHA1InWant`, so pinning to a SHA needs `git init` plus `git fetch origin <sha> --depth 1` with a fallback to a full fetch. That is the kind of detail that eats an afternoon if it is not written down.

Refresh borrows wholesale from the subscriber poller: an interval with jitter, a cached last-good document, and the same failure table. The resolved commit SHA plays the part the ETag plays for bundles, so an unchanged SHA means no recompile and no reload. The fetch gets a hard timeout that kills the child process, because a config-load path with no timeout has already hung startup in this codebase once.

Credentials for private repos resolve through `SecretResolver`, so a deploy token can be `env:`, `file:`, or `vault://` and never sits inline in YAML. Credentials must never reach a log line, including inside a URL.

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
- `source` (the authority overlays the base document, it does not get to choose which repo the base comes from)

Everything else is fair game: origins, AI providers, policies, transforms, rate limits, agent classes, audit, access log, extensions.

A denied path present in a remote document rejects the entire bundle and logs which paths caused it. It is never silently dropped. The LiteLLM importer already learned this lesson and has a silent-drop gate for the same reason.

The two modes then differ in one sentence each:

- **overlay**: the local file is the base, the remote document merges on top, and remote wins key by key.
- **replace**: the remote document is the base, deny-listed paths are grafted in from local, and every other local key is discarded.

Merge is a pure function from `(base_yaml, base_origin, remote_yaml, mode)` to `(merged_yaml, provenance_map)` where the provenance map records, for every leaf path, whether the value came from the base or from the authority. Git resolution happens before merge and produces the base document, so the caller tags the base as `local` or `git` and merge propagates that tag. The function itself never knows what git is. Table-test it hard. It is the piece most likely to produce a subtle wrong answer.

### Failure behaviour

| Situation | Behaviour |
| --- | --- |
| Authority unreachable | Keep serving the last verified bundle. Alert. `sbproxy_config_bundle_age_seconds` climbs. |
| Signature, schema, or compile failure | Reject the candidate. Previous config keeps serving. Counter plus alert. Never partially applied, which today is not true and is why CA-00 exists. |
| Denied path in bundle | Same as above, with the offending paths named in the log. |
| Cold boot, no cache, mode `overlay` | Boot on the local file with a loud warning, unless `require_bundle_on_boot` is set. |
| Cold boot, no cache, mode `replace` | Refuse to start. There is nothing to serve. |

Staleness is an alert, not an enforcement gate. An authority outage should not become a fleet outage, and a grace window would just become one more number everyone has to tune correctly.

### Refresh

Baseline is `GET /config-authority/v1/bundle` with `If-None-Match`, on `poll_interval`, answering 304 when nothing changed. It works identically whether or not the subscriber is a mesh member, which matters because managed-service subscribers reach us over the internet and are not in anyone's gossip cluster.

Mesh members get an accelerator. The authority publishes `{revision, digest, authority_id}` into cluster typed state under a `config-authority` namespace, which is already signed and generation-fenced by `ClusterStateEnvelope`. A subscriber that observes a higher revision pulls immediately instead of waiting out the interval. Gossip is never required for correctness, so a bug there degrades propagation speed and nothing else.

Build this on `ClusterHandle::publish_state`. Delete `config_broadcast.rs` and the unwritten `PersistedState.config_version` field rather than reviving a mutex-wrapped struct nothing ever called.

### Applying

The subscriber produces merged YAML and calls `reload_from_config_yaml`, taking `CONFIG_RELOAD_LOCK` like every other reload path. The subscriber contributes a source of bytes and nothing else.

I originally wrote that atomicity and subsystem reconciliation already work here. They do not, and the correction is the most important thing in this document. See the next section.

## Hard edges found in the code audit

I read the reload, drift, validation, and admin paths line by line before committing to this plan. Most of what I found is pre-existing and survivable when a human drives reloads one box at a time. None of it is survivable when a control plane drives them automatically across a fleet. The difference is blast radius and the absence of a person watching the log.

### The reload transaction is not atomic

`reload_from_config_yaml` has four hard-error points (`compile_config`, `reconcile_process_cluster`, `CompiledPipeline::from_config`, `reconcile_model_runtime_blocking`) and the publish at the end. Between the second and third of those, it mutates process-global state: Lua sandbox limits, the operator redaction state, tenant cardinality caps, the sink dispatcher, usage rollups, the AI provider catalog, detection singletons, and the key plane. Those are all installed through their own swaps, before the pipeline publish.

So a config that compiles but fails at `CompiledPipeline::from_config` returns `Err`, logs "serving prior pipeline", and leaves the node running new redaction rules, a new AI catalog, a new key plane, and the old pipeline. The failure message says nothing happened. Something happened.

A human hitting this once on one box notices and restarts. A bad bundle hitting it does so on every subscriber at the same time, unattended.

### "Applied" does not mean applied

Seven subsystems fail soft inside a reload that reports success: the AI provider catalog and AI client, the dynamic key plane, the listings registry, the enterprise `on_reload` hook, sink validation and the sink dispatcher, the agent-detect scorer, and governance dissemination. Each logs and continues.

That is a defensible choice for a local reload. It is not defensible for a managed service, where `sbproxy_config_bundle_applied_total` incrementing is what we would tell a customer means their config is live. Worth noting one specific trap: `reload_ai_client()` sits in the `else` branch of the provider-registry reload, so a registry failure silently skips the client rebuild too.

### The secret resolver is set once per process

`install_process_resolver` is a `OnceLock` and a second call is discarded with `let _ = ... .set(...)`. Nothing in `sbproxy-core` calls it. A reload that changes `proxy.secrets` is therefore silently ignored, and every handler is rebuilt against the boot-time `VaultManager`.

Two consequences for this design. `proxy.secrets` is on the deny-list, so an authority can never ship a config that introduces a new secret backend; a bundle referencing `secret://newbackend/...` hard-fails at handler construction on every node. And git content is unrestricted, so a repo *can* change `proxy.secrets`, at which point the change is silently ignored and the references to it hard-fail. Silent ignore followed by a confusing hard failure is the worst of both.

The fix is not to make the resolver reloadable, which is a much larger change involving live network clients. The fix is to detect the situation and refuse loudly, the way the cluster fingerprint already does.

### `/admin/drift` is already wrong, and multi-source makes it worse

`loaded_config_content_hash` is written in exactly two places: boot, and `POST /admin/reload`. The file watcher and SIGHUP paths do not update it. After a watcher or SIGHUP reload the running config matches disk while the stale baseline does not, so drift reports `true` incorrectly until the next admin reload or a restart.

A subscriber poller would be the fifth path into reload. If it does not maintain that hash, every subscriber reports permanent drift. And on a git-sourced node the local file is a `source:` pointer, so both sides of the comparison hash the same unchanged pointer and drift reports `false` while the actual content moved. False positive on one path, false negative on the other.

Drift needs to become per-source rather than one hash: local file against loaded local file, git against resolved commit, authority against accepted revision.

### Node identity cannot come from a shared git repo

This is the gap I got wrong when I first wrote the git section. I said git content is operator-owned and therefore unrestricted, which is true, and then did not follow it through.

`ClusterRestartFingerprint` covers eighteen fields including `cluster_id`, `node_id`, `roles`, `labels`, `seeds`, both ports, both advertise addresses, `state_dir`, `security`, `enrollment`, `deployment_authority`, and `replication`. Any change rejects the entire reload, and so does removing `proxy.cluster:` from a process that had one.

The obvious deployment, one repo pointed at by a whole fleet, therefore cannot work as written. Either every node claims the same `node_id`, or the repo omits `proxy.cluster` and every clustered node hard-fails its reload. Node-local values have to come from somewhere else.

Two mechanisms already exist and either would do. `${VAR}` interpolation is a textual pre-pass, so a shared repo can carry `node_id: ${SB_NODE_ID}` and each host supplies its own. And `ConfigSource::GitOverlay` takes a base plus ordered overlays, with `Local` already a variant, so a git base with a node-local overlay is expressible. Pick one, document it as the supported pattern, and make the failure mode obvious when someone does neither.

The `${VAR}` route carries its own edge: an unresolved reference is only a warning and is left as literal text. So a bundle referencing a variable a node does not set produces a literally wrong value rather than a refusal. Admin credentials are the sole exception and hard-fail. Any node-local value the design depends on needs the same treatment.

### Publish-side validation is weaker than boot

`compile_config` alone does not catch what boot catches. Action and policy and transform blocks are opaque `serde_json::Value` until `CompiledPipeline::from_config` constructs them, which is where a typo inside a `policies:` entry, an unknown transform type, or a provider setting both `serve:` and `base_url:` finally surfaces. The `validate` subcommand knows this and runs the full construction plus `validate_model_runtime`.

If the authority validates with `compile_config` only, it will happily publish a bundle that fails on every subscriber. Publish has to run at least what `validate` runs. It must also use `from_config_for_validation` rather than `from_config`, because the runtime variant touches process-global state and starts background tasks on a pipeline that is then dropped. `PUT /admin/config` makes exactly that mistake today.

### The admin listener is the wrong place to expose a fleet endpoint

Admin credentials default to `admin` and `changeme`, hardcoded in three places. Nothing validates them against the bind address. `bind: 0.0.0.0` with `allow_ips: ["0.0.0.0/0"]`, default credentials, and no TLS boots cleanly and serves the full admin API in plaintext. `AdminIpFilter::new(vec![])` is fail-open, and the safe default lives in a single `is_empty()` branch at the one call site rather than in the type. `localhost_only()` compares literal strings, so an IPv4-mapped IPv6 loopback peer is rejected.

Putting `GET /config-authority/v1/bundle` on this listener means telling operators to expose that port to their whole fleet. I am no longer comfortable with "operators must bind admin accordingly" as the mitigation. The authority endpoint gets its own listener, and a node configured to publish refuses to start with default admin credentials.

### Smaller edges worth knowing before someone hits them

The `reload_in_progress` single-flight flag is `/admin/reload` only, despite a doc comment claiming otherwise. The watcher, SIGHUP, and `apply` serialize on the mutex instead, which blocks rather than returning a conflict. A poller that blocks behind a slow reload will queue up, so it should try the lock and skip with a metric rather than wait.

`PUT /admin/config` writes the file and then re-reads it from disk instead of applying the bytes it just validated, and the rename also wakes the file watcher, so a write can race itself.

`proxy.admin.*` is never re-read on reload, but `plan.rs` declares it as `Reload` with the reason "admin auth / TLS settings re-read on reload". Any plan diff we show an operator is lying about that path.

`sbproxy apply` calls `reload_from_config_path` in the short-lived CLI process. It swaps the CLI's own pipeline, prints a success line, and exits. The running server picks the change up only because its file watcher happens to see the file. There is no IPC and no admin call anywhere in that function.

`migrate_features_to_extensions` does a full YAML round-trip whenever a `features:` block exists, so comments are already destroyed on those configs today. Our merge will round-trip too. Comment preservation is therefore a property of the local-file editing path only, never of the effective config, and CA-08 should say so rather than imply otherwise.

`scan_yaml_hazards` early-returns an empty result when the generic YAML parse fails, so hazard detection is skipped entirely on a document that does not parse.

Boot does not take `CONFIG_RELOAD_LOCK`, and the admin listener can come up before boot finishes its own publish.

## Solutions

Every finding above has a worked answer. Two of them are smaller than they first looked, and one is a limit we accept rather than solve.

### Reload atomicity: reordering, not a rewrite

I estimated this as the most invasive ticket in the epic, then traced what `CompiledPipeline::from_config` actually reads. **Only one of the nine installs is a genuine construction-time dependency.** The other eight are pure request-path state and constrain nothing.

The one that matters is the AI provider registry, which `AiHandlerConfig::from_config` reads twice and can `bail!` on. Its static is already `OnceLock<ArcSwap<Registry>>` and it self-initializes from the embedded catalog, so the ordering only bites when an `ai_providers_file:` override is in play. Two more construction-time reads exist that were not on my list, and both are already handled: the process secret resolver is boot-only and never touched by reload, and the cluster handle plus AI client are already abstracted behind `PipelineConstructionMode`.

Everything else is read on the request path or the admin path and nowhere else. The Lua sandbox config is read only by `LuaEngine::new()` during WAF evaluation. Redact state is read at the log-emit chokepoint. Tenant cardinality is read when recording metrics. The sink dispatcher is read on emit, usage rollups from one admin handler, all five detection singletons from `request_phase.rs`, and the key plane from four admin and dispatch call sites with zero at construction.

So the work is: move the six request-path installs to after the last hard-error point, build the key plane early but install it late (its construction does real I/O and is fallible), and thread one `Arc<Registry>` into `from_config` instead of installing it first. A context struct carrying one value, plus a reordering. Contained.

### Reporting: report, do not escalate

The seven soft-failing subsystems stay soft. Making them hard would change behaviour for existing operators, and a degraded AI catalog really is better than a refused reload on a box someone is watching. The fix is a `ReloadOutcome` that names what degraded, returned rather than logged, so each caller picks its own policy. A human reload sees a warning; a subscriber treats degraded as a rejected bundle and keeps the previous config. That also gives the managed service something honest to show a customer.

### Secrets: a documented limit, not a fix

Do not make the secret resolver reloadable. It owns live network clients for Vault, AWS, GCP, and Kubernetes, and swapping it under a running fleet is a bigger problem than this epic needs solved. Detect that `proxy.secrets` changed, refuse loudly the way the cluster fingerprint already does, and document that secret backends are process-owned and need a restart.

This is a real product limit the managed service will eventually hit, so it belongs in the docs now rather than as a support surprise later.

### Node identity: env interpolation by default

Support both mechanisms, and document `${VAR}` as the default pattern. It needs no new machinery, and environment is the natural carrier in containers and Kubernetes where a shared repo is most likely. Use a local overlay when the difference between nodes is structural rather than a handful of scalars; `GitOverlay` already models it and CA-06 wires it anyway.

The one thing that must change is the failure mode. An unresolved `${VAR}` currently warns and leaves literal text, so a host that forgets to export its node id gets `${SB_NODE_ID}` as a node id. Node-local values must hard-fail when unresolved, the way admin credentials already do.

### The rest

Publish validation runs the full `validate` sequence with `from_config_for_validation`. Drift becomes per-source rather than one hash. The admin listener gets a sibling listener for the authority endpoint, plus startup checks that refuse default credentials off loopback. The three lying doc comments get corrected. All mechanical.

### What this changes about the plan

Two new children, both prerequisites rather than follow-ons. **CA-00** makes the reload transaction honest. **CA-11** hardens the admin surface and gives the authority its own listener.

Two pre-existing bugs came out of the audit and are filed separately, because neither should wait on this epic. `sbproxy apply` reloads the CLI's own process and exits, so its success message is not evidence the server did anything. And `start_background_tasks()` is called unconditionally regardless of construction mode, so every `PUT /admin/config` spawns health-probe tasks for a pipeline that is immediately dropped; they hold the pipeline alive and keep probing the operator's upstreams forever. The admin UI's save button triggers it. That one is a one-line mode guard.

The rest of the findings attach to the children that already own the relevant code.

### The editor

The rule is that the editor is live only where the node owns its own config. A node that pulls config from anywhere else must not offer an editing surface that the next poll will silently overwrite. That applies to a git source exactly as it applies to an authority, since a local edit is just as doomed either way.

Concretely:

- No `upstream` and no remote `source`: the editor works as it does today.
- `upstream` in `replace` mode: fully read-only, with a banner naming the authority, its id, and the current revision.
- `upstream` in `overlay` mode: locally-owned keys stay editable, and every key the authority defines renders locked with an `authority: <id> rev <n>` badge.
- `source` resolving to git, with no authority: fully read-only, with a banner naming the repo, ref, and resolved SHA, and a pointer at the repo as the place to make the change.
- Git base with an authority overlay: read-only throughout, since neither layer is locally owned. The provenance badge distinguishes which of the two supplied each key, which is what makes an operator's "why is this value here" question answerable.

Provenance therefore has three sources rather than two: `local`, `git`, and `authority`.

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
- `sbproxy_config_source_fetch_total{kind, result}` and `sbproxy_config_source_revision_info{sha}` for the git path, so a stuck source is as visible as a stale bundle

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
| Git source resolution and refresh | `sbproxy-config` + `sbproxy-core` | existing `source.rs` |
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

Git source gets its own integration coverage against a local bare repo, which needs no network: resolve and compile, unchanged SHA producing no reload, a moved branch triggering one, a pinned SHA refusing to follow a moved branch, unreachable remote falling back to the cached document, clone timeout, and a missing `git` binary producing a clear preflight error. Layering is tested directly: git base plus an authority overlay resolves in the documented order, and an authority bundle carrying `source:` is rejected.

End-to-end certification is a two-node drill: authority publishes, subscriber applies, then key rotation, then a replayed old bundle, then authority killed mid-poll. A third shape covers git, with a git-backed authority publishing from a repo and a standalone git-source proxy with no authority at all. These run locally and stay out of the required CI gate, matching existing practice for `sbproxy-e2e`.

## Non-goals for v1

Per-subscriber targeting and label selectors, staged or canary rollout, config history and diff browsing beyond one rollback step, secret values traveling in bundles (URI references travel, resolved values never do), and chained authorities.

On the git side specifically: no write-back (the editor never commits to a repo, and a git-sourced node is read-only in the same way a subscriber is), no `db` source mode, no submodule or LFS support, and no in-process git implementation. The `git` binary stays the transport.
