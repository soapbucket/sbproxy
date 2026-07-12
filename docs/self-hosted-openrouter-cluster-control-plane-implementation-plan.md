# Self-Hosted OpenRouter Cluster Control Plane Implementation Plan

*Last modified: 2026-07-11*

> **For agentic workers:** Follow the tasks in order. Every behavior change
> uses a red, green, refactor loop, and every task ends at a reviewable commit
> checkpoint.

**Goal:** Deliver PR 3 of the self-hosted OpenRouter program: one shared local
or distributed cluster handle, durable identity and enrollment, versioned node
model snapshots, a lock-free live directory, deterministic multi-node
placement, safe rollout, and signed cluster-authority deployment revisions.

**Architecture:** `sbproxy-mesh` owns cluster identity, membership, peer
security, and typed state. `sbproxy-model-host` owns snapshot DTOs, strict
deployment bundles, placement, and rollout state. `sbproxy-ai` owns the
lock-free directory read facade. `sbproxy-core` owns the single process handle
and composes cluster decisions with the existing local runtime. CLI and admin
routes remain adapters over these shared services.

**Primary Linear scope:** WOR-1838, WOR-1846, and WOR-1849.

## Global constraints

- Start from merged `origin/main` commit `e2df27ed` in the dedicated
  `rickcrawford/wor-1835-cluster-control-plane` worktree.
- Preserve existing unmanaged providers, local managed-model behavior, key
  management, cluster metrics, and schema-v1 compatibility.
- `proxy.cluster` is canonical. Legacy `key_management.cache.mesh` lowers to
  the same process handle and emits a migration diagnostic.
- Exactly one `MeshNode`, gossip loop, and peer transport may exist per
  process.
- A missing cluster block creates a local handle and starts zero network or
  background cluster tasks.
- Production canonical clusters require mTLS. Shared-key mode is explicit
  development configuration.
- Secret material, raw errors, prompts, keys, tokens, private paths, and
  unbounded labels never enter snapshots, directory views, metrics, or admin
  JSON.
- Request-path directory reads are immutable `ArcSwap` loads with no locks or
  network calls.
- Placement is deterministic from normalized inputs. Partition behavior may
  overprovision but cannot make unreachable replicas eligible.
- Rolling removal waits for replacement readiness or the documented handoff
  timeout. Old generations cannot accept new work after a newer generation is
  committed.
- Signed bundles contain only model deployment and placement data and reject
  unknown fields.
- Peer inference, dispatch envelopes, streaming, and remote cancellation stay
  in PR 4. Admin model-management UI stays in PR 6. Live GCP validation stays
  in PR 7.
- User-facing content, rustdoc, commit messages, and generated documentation
  contain no em dash characters.
- Before publication, run every repository gate in `AGENTS.md`, docs CI,
  schema drift, capability drift, multi-process tests, and blocker-only review.

## File map

- `crates/sbproxy-config/src/cluster.rs`: canonical cluster DTOs, validation,
  legacy lowering input, restart fingerprint, and migration diagnostics.
- `crates/sbproxy-config/src/types.rs`: `ProxyServerConfig::cluster` and legacy
  mesh compatibility wiring.
- `crates/sbproxy-config/src/plan.rs`: restart classification for identity,
  listener, role, label, endpoint, and peer-security fields.
- `crates/sbproxy-mesh/src/cluster_handle.rs`: cloneable local or distributed
  handle, identity, membership, isolation, and typed-state access.
- `crates/sbproxy-mesh/src/enrollment.rs`: authority initialization, token
  issuance, CSR signing, atomic consume, replay rejection, and installed
  identity manifests.
- `crates/sbproxy-mesh/src/node_handle.rs`: shared `Arc<MeshNode>` accessors and
  live membership or transport diagnostics required by `ClusterHandle`.
- `crates/sbproxy-model-host/src/node_snapshot.rs`: bounded snapshot schema and
  validation.
- `crates/sbproxy-model-host/src/cluster_authority.rs`: strict signed bundle,
  canonical digest, signer, verifier, and content-addressed keys.
- `crates/sbproxy-model-host/src/placement.rs`: eligibility filtering, weighted
  rendezvous, spread, variants, movement, and plan output.
- `crates/sbproxy-model-host/src/rollout.rs`: readiness-gated handoff and
  generation fencing.
- `crates/sbproxy-ai/src/model_directory.rs`: `ArcSwap` directory, monotonic
  ingestion, exclusion reasons, replica indexes, and diagnostics.
- `crates/sbproxy-core/src/cluster.rs`: one process owner, canonical or legacy
  bootstrap, restart validation, publisher, collector, placement controller,
  and authority service.
- `crates/sbproxy-core/src/key_plane.rs`: consumes the shared handle and removes
  private mesh bootstrap globals.
- `crates/sbproxy-core/src/cluster_metrics.rs` and
  `crates/sbproxy-core/src/mesh_cache.rs`: shared-handle adapters.
- `crates/sbproxy-core/src/server/model_host.rs`: full desired input, local
  assignment filtering, serialized placement commits, and runtime snapshots.
- `crates/sbproxy-core/src/server/lifecycle.rs`: cluster-before-key/model boot,
  reload checks, controller start, and graceful shutdown.
- `crates/sbproxy-core/src/admin_cluster.rs`: status, enrollment, and
  authority-only deployment endpoints.
- `crates/sbproxy-core/src/admin.rs`: routing, enrollment auth exception, RBAC,
  and JSON limits.
- `crates/sbproxy/src/main.rs`: cluster CLI commands and stable text or JSON
  output.
- `crates/sbproxy-config/tests/cluster_config.rs`: canonical, legacy,
  validation, migration, and restart contracts.
- `crates/sbproxy-mesh/tests/cluster_handle.rs`: local and distributed handle,
  expiry, membership, and one-node ownership.
- `crates/sbproxy-mesh/tests/enrollment.rs`: init, token, CSR, install, replay,
  constraints, and manual identity equivalence.
- `crates/sbproxy-model-host/tests/model_directory.rs`: snapshot bounds,
  generations, compatibility, expiry, and exclusion.
- `crates/sbproxy-model-host/tests/placement.rs`: filters, rendezvous, movement,
  spread, partitions, variants, and rollout.
- `crates/sbproxy-core/tests/cluster_control_plane.rs`: shared startup,
  key-cache independence, publication, placement, and safe local reconcile.
- `crates/sbproxy/tests/cluster_cli.rs`: CLI filesystem and wire contracts.
- `e2e/tests/model_cluster_control.rs`: ephemeral multi-process convergence,
  stale/dead exclusion, mismatch, and handoff.
- `docs/model-cluster.md`, `docs/model-host.md`, `docs/key-management.md`,
  `docs/admin.md`, `docs/manual.md`, `docs/security-model-host.md`, and
  `docs/troubleshooting.md`: stable operator contract and migration guidance.
- `examples/model-cluster/`: runnable local symmetric and split-role examples.
- `schemas/sb-config.schema.json`, `docs/model-host-capabilities.md`, and
  `docs/llms-full.txt`: generated outputs.

### Task 1: Canonical cluster config and restart contract

**Red tests:**

- Canonical mTLS config round-trips and appears in the generated schema.
- Production rejects missing peer security, empty identity, invalid roles,
  oversized labels, invalid endpoints, and unsafe snapshot timing.
- Development shared-key mode requires `development: true`.
- Legacy mesh fields lower to an equivalent effective cluster and report one
  migration diagnostic.
- Conflicting canonical and legacy boot fields fail validation.
- Identity, roles, labels, listeners, advertise address, endpoint, and security
  changes classify as restart-required; cadence remains reloadable.

**Implementation:** Add `cluster.rs`, wire `ProxyServerConfig`, expose an
`EffectiveClusterConfig` builder, and extend config planning. Keep secret
resolution in core.

**Focused gate:**

```bash
cargo test -p sbproxy-config --test cluster_config
cargo test -p sbproxy-config plan::tests::cluster
```

**Commit:** `feat: add canonical cluster configuration`

### Task 2: Shared local or distributed ClusterHandle

**Red tests:**

- Local mode returns its identity and typed local state without creating
  sockets, tasks, or peer transports.
- Distributed mode maps SWIM entries to stable membership states and preserves
  isolation, distributed cache, and transport access.
- Typed state round-trips generation and expiry, rejects namespace mismatch,
  and distinguishes unreachable from missing.
- Clones refer to one inner handle and dropping the final clone stops owned
  tasks.

**Implementation:** Add `cluster_handle.rs`, wrap `MeshNode` in the distributed
inner, expose bounded membership snapshots, and add namespaced state envelopes
over the existing distributed cache.

**Focused gate:**

```bash
cargo test -p sbproxy-mesh --test cluster_handle
cargo test -p sbproxy-mesh --lib
```

**Commit:** `feat: expose one shared cluster handle`

### Task 3: Process ownership and key-plane migration

**Red tests:**

- Startup installs one local handle when clustering is absent.
- `proxy.cluster` bootstraps once even when key cache, metrics, and model
  serving all consume the handle.
- Model clustering works while dynamic key management is disabled.
- Legacy mesh cache still receives clustered cache semantics.
- A reload that changes restart fields fails and retains prior runtime state.
- Listener bind or canonical mTLS failure prevents canonical cluster startup.

**Implementation:** Add `sbproxy-core::cluster`, install it before key-plane and
model reconciliation, pass clones to existing consumers, and delete the
key-plane `MeshNode` `OnceLock` and bootstrap helper.

**Focused gate:**

```bash
cargo test -p sbproxy-core cluster::
cargo test -p sbproxy-core key_plane::
cargo test -p sbproxy-core --test cluster_control_plane startup
```

**Commit:** `refactor: promote mesh ownership into core`

### Task 4: Durable identity and one-time enrollment

**Red tests:**

- Init writes CA, authority identity, signing key, and token store atomically
  with owner-only permissions.
- Token storage contains only a token hash and bounded constraints.
- A worker generates its private key locally and submits a valid CSR.
- The authority signs a permitted CSR, consumes the token atomically, and
  rejects replay, expiry, widened roles, changed labels, bad CSR signatures,
  and oversized requests.
- Two concurrent enrollments with one token produce exactly one success.
- Manual mTLS material and enrolled material normalize to the same runtime
  identity fields.

**Implementation:** Add `enrollment.rs` using rcgen CSR parsing and signing,
file locking, atomic rename, SHA-256 token hashing, bounded JSON DTOs, and a
signed identity manifest. Add the HTTPS admin enrollment adapter and cluster
CLI commands.

**Focused gate:**

```bash
cargo test -p sbproxy-mesh --test enrollment
cargo test -p sbproxy --test cluster_cli enrollment
cargo test -p sbproxy-core admin_cluster::tests::enrollment
```

**Commit:** `feat: add cluster identity enrollment`

### Task 5: Versioned node model snapshots

**Red tests:**

- Schema v1 round-trips every required field and rejects unknown fields.
- Validation bounds roles, labels, endpoints, engines, devices, artifacts,
  replicas, adapters, and reason codes.
- Snapshot generation survives publisher restart and increments monotonically.
- Runtime conversion reports exact lifecycle, queue, active, engine, artifact,
  device, variant, adapter, and bounded error data without paths or raw errors.
- Local deployment digest mismatches remain visible.

**Implementation:** Add `node_snapshot.rs`, a persistent generation counter,
runtime-to-snapshot conversion, and typed publication under a stable namespace.

**Focused gate:**

```bash
cargo test -p sbproxy-model-host --test model_directory snapshot
cargo test -p sbproxy-core --test cluster_control_plane publication
```

**Commit:** `feat: publish versioned model snapshots`

### Task 6: Lock-free live model directory

**Red tests:**

- Membership and payloads join by node ID.
- Suspect, dead, expired, unreachable, malformed, incompatible, and old
  generation nodes are excluded with stable reasons.
- A compatible older schema normalizes and remains routable.
- An older generation never replaces a newer one for the same identity.
- Readers load immutable views without acquiring the writer lock.
- Admin JSON reports snapshot age, exclusion, digest mismatch, and eligible
  replica counts.

**Implementation:** Add `sbproxy-ai::model_directory`, one serialized collector
writer, `ArcSwap<ModelDirectoryView>`, deployment indexes, and the cluster
status admin route.

**Focused gate:**

```bash
cargo test -p sbproxy-ai model_directory::
cargo test -p sbproxy-model-host --test model_directory directory
cargo test -p sbproxy-core admin_cluster::tests::status
```

**Commit:** `feat: build the live model directory`

### Task 7: Deterministic placement and variant policy

**Red tests:**

- Candidate filtering covers role, labels, accelerator, memory, engine, and
  artifact compatibility.
- A one-node `replicas: 1` deployment selects the local node.
- Weighted rendezvous produces the same plan for every input order.
- Adding or removing one node changes only rankings displaced by that node.
- `spread_by` prefers distinct zone and rack values before reusing a domain.
- Pinned variants are identical across replicas.
- Explicit heterogeneous mode selects deterministic per-node variants and
  exposes them in plan status.
- A partition can produce two local plans but neither contains an unreachable
  node.

**Implementation:** Add placement DTOs, catalog requirement lowering,
SHA-256-based weighted rendezvous scoring, deterministic spread selection, and
stable plan status.

**Focused gate:**

```bash
cargo test -p sbproxy-model-host --test placement planner
```

**Commit:** `feat: add deterministic model placement`

### Task 8: Safe rollout and local assignment reconcile

**Red tests:**

- Rolling changes start replacement assignments before draining losers.
- Losers remain retained until required replacements report ready or the
  handoff deadline elapses.
- Recreate policy drains first.
- A newer deployment generation excludes old replicas from new admission while
  allowing active permits to finish.
- A failed local prepare leaves the prior plan and runtime active.
- Config reload and placement refresh serialize through one commit boundary.
- Unaffected deployments and engine generations remain unchanged.

**Implementation:** Add rollout state, assignment filtering on
`RuntimeDesiredState`, a core model controller, and generation-fenced runtime
commit integration.

**Focused gate:**

```bash
cargo test -p sbproxy-model-host --test placement rollout
cargo test -p sbproxy-core --test cluster_control_plane reconcile
cargo test -p sbproxy-model-host --test runtime_reconcile
```

**Commit:** `feat: reconcile cluster model assignments`

### Task 9: Signed cluster-authority deployments

**Red tests:**

- Strict bundle parsing rejects unknown fields, secrets, arbitrary proxy
  blocks, private keys, duplicate deployments, invalid digests, and bad
  signatures.
- Content-addressed bundle keys match canonical bytes.
- Only an authority role with the private key can publish.
- Non-authority write endpoints return a stable read-only error.
- Older authority revisions cannot replace newer active state.
- File-managed and verified authority bundles yield identical normalized
  placement input.
- Local-mode hash mismatches report without overwriting either file.

**Implementation:** Add strict bundle DTOs and Ed25519 signing, publish content
plus current pointer through typed cluster state, verify before desired-state
swap, and add authority-only admin adapters.

**Focused gate:**

```bash
cargo test -p sbproxy-model-host cluster_authority::
cargo test -p sbproxy-core --test cluster_control_plane authority
```

**Commit:** `feat: verify cluster deployment authority`

### Task 10: Multi-process convergence and failure drills

**Red tests:** Build an ephemeral fixture with one authority, one gateway, and
two workers using temporary ports, certificates, identity stores, fake engine
drivers, and bounded timeouts.

Prove:

- all processes converge on the same placement;
- the key cache and model serving share one mesh;
- stale, suspect, dead, and unreachable workers leave the eligible directory;
- removing or adding one worker causes minimal placement movement;
- a rolling revision starts replacements before old-generation drain;
- a partition may overprovision but never yields a cross-partition eligible
  route;
- deployment hash mismatch and recovery are visible;
- shutdown leaves no child engine, gossip, transport, or collector task.

**Focused gate:**

```bash
cargo test -p sbproxy-e2e --test model_cluster_control -- --nocapture
```

**Commit:** `test: prove cluster control-plane convergence`

### Task 11: Stable docs, examples, schema, and capability truth

Document canonical configuration, security modes, enrollment, manual PKI,
roles, labels, directory exclusions, placement, spread, variants, rollout,
authority, migration, status JSON, troubleshooting, and the PR 4 transport
boundary. Add runnable local symmetric and split-role examples.

Promote only the cluster control-plane capabilities proven in this PR. Keep
remote inference dispatch unsupported until PR 4. Regenerate schema,
capability docs, and `llms-full.txt` from source generators.

**Focused gate:**

```bash
cargo test -p sbproxy-config --test validate_examples
scripts/check-config-schema.sh
scripts/check-model-host-capabilities.sh
scripts/check-docs-ci.sh
scripts/check-llms-full.sh
```

**Commit:** `docs: document managed model clustering`

### Task 12: Full verification, review, publication, and merge

Run the exact repository gates:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci
cargo test --workspace --exclude sbproxy-e2e --locked --doc
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
```

Also run the cluster multi-process suite, docs CI, schema drift, capability
drift, `git diff --check`, and the no-added-em-dash check. Request a
blocker-only review against WOR-1838, WOR-1846, WOR-1849, this design, and the
delivery contract. Fix all Critical and Important findings, rerun affected
focused gates and the full exact-head gate, then push and open PR 3 with an
acceptance-to-evidence table. Monitor CI, fix failures, and merge only when all
required checks are green.

