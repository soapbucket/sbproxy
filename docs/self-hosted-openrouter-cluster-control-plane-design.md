# Self-Hosted OpenRouter Cluster Control Plane Design

*Last modified: 2026-07-11*

*Status: Approved PR 3 design under the approved seven-PR delivery contract.*

## Decision

PR 3 promotes the existing key-cache mesh into one process-owned cluster
substrate and adds the control-plane contracts needed for managed model
replicas. The implementation has four independently testable layers:

1. `sbproxy-mesh` exposes a cloneable `ClusterHandle` with local and
   distributed modes.
2. Workers publish versioned, expiring `NodeModelSnapshot` values into typed
   cluster state.
3. `sbproxy-ai` maintains an immutable `ModelDirectoryView` behind `ArcSwap`
   for lock-free request reads.
4. `sbproxy-model-host` computes deterministic placement and generation-fenced
   rollout decisions from a deployment revision and an eligible directory
   view.

Core startup constructs exactly one handle and supplies it to keys, metrics,
model publication, placement, and admin diagnostics. A process without
`proxy.cluster` receives a zero-network local handle. It starts no gossip,
peer transport, publication, or collection tasks.

PR 3 does not send inference requests between nodes. The authenticated private
model plane, dispatch envelopes, streaming, cancellation, and remote failover
remain PR 4. Live GCP validation remains PR 7.

## Scope and acceptance mapping

This design implements:

- WOR-1838: shared cluster ownership, compatibility lowering, restart
  validation, identity, enrollment, peer security, and signed deployment
  authority.
- WOR-1846: versioned node model snapshots, membership joining, eligibility,
  monotonic generations, lock-free reads, rolling compatibility, and admin
  exclusion diagnostics.
- WOR-1849: deterministic filtering and placement, weighted rendezvous,
  failure-domain spread, partition behavior, rollout handoff, generation
  fencing, and pinned or heterogeneous variants.

## Canonical configuration

The stable configuration lives under `proxy.cluster`:

```yaml
proxy:
  cluster:
    cluster_id: production-a
    node_id: worker-a
    roles: [gateway, worker]
    labels:
      zone: us-central1-a
      accelerator: l4
    seeds: [10.0.0.11:7946]
    gossip_port: 7946
    transport_port: 8946
    advertise_addr: 10.0.0.12:7946
    model_endpoint: https://10.0.0.12:9443
    security:
      mode: mtls
      cert_file: /var/lib/sbproxy/cluster/node.pem
      key_file: /var/lib/sbproxy/cluster/node-key.pem
      ca_file: /var/lib/sbproxy/cluster/ca.pem
      server_name: sbproxy-mesh
    snapshot_ttl_secs: 30
    publish_interval_secs: 5
```

`roles` accepts `gateway`, `worker`, and `authority`. A canonical distributed
cluster requires a nonempty node ID, at least one role, bounded labels, and an
explicit security mode. `mtls` is the production mode. `shared_key` is an
explicit development mode and requires `development: true`. Plaintext is not
accepted by canonical configuration.

An authority node may additionally configure an enrollment store and a
deployment signing key. A non-authority node may configure only the
corresponding public verification key. Secret material remains a file or
secret reference and never enters cluster state, snapshots, admin responses,
or signed deployment bundles.

`key_management.cache.mesh` remains compatible for one migration window. It
lowers to the same effective cluster bootstrap fields and emits a migration
diagnostic. When both canonical and legacy blocks exist, their node, listener,
seed, advertised address, and security values must agree. The key cache only
consumes the shared handle and can no longer bootstrap a second mesh.

Node identity, roles, labels, gossip listener, peer transport listener,
advertised address, and security material are restart-required fields.
Snapshot cadence and deployment content are reloadable. Config planning marks
restart fields explicitly, and the live reload path refuses an in-process
identity or listener replacement while retaining the last-good pipeline.

## ClusterHandle ownership

`sbproxy-mesh::ClusterHandle` is a cheap clone over one inner allocation. Its
public contract exposes:

- immutable `ClusterIdentity` containing cluster ID, node ID, roles, labels,
  and advertised endpoints;
- `ClusterMode::Local` or `ClusterMode::Distributed`;
- immutable membership snapshots with `alive`, `suspect`, `dead`, and
  `unreachable` states;
- existing distributed cache, liveness, isolation, and peer-address views for
  compatibility consumers;
- a namespaced typed-state API that stores generation and expiry metadata with
  each payload.

The distributed implementation owns an `Arc<MeshNode>`. The local
implementation owns only an in-memory state map and its own identity. The
handle does not decide model fit, placement, admission, or routing.

`sbproxy-core::cluster` is the process owner. It resolves canonical or legacy
configuration, reads secret and TLS material, bootstraps the handle once, and
retains a restart fingerprint. Startup orders cluster installation before key
plane and model runtime construction. The key cache, mesh counters, and fleet
metrics receive clones from this owner.

## Identity and enrollment

Enrollment uses the existing admin listener as a narrowly scoped control-plane
endpoint. Production enrollment requires HTTPS. The one-time token is the
credential for this endpoint, so it does not require a pre-existing admin
session.

The workflow is:

1. `sbproxy cluster init` creates a cluster CA, authority signing identity,
   authority node identity, and an atomic token store with owner-only file
   permissions.
2. `sbproxy cluster token create` records a random, hashed, expiring token with
   allowed roles and label constraints.
3. `sbproxy cluster enroll` generates the worker private key locally, creates a
   CSR, and submits the CSR plus requested identity to the authority.
4. The authority verifies the CSR signature, token hash, expiry, requested
   role subset, and label constraints while holding the durable store lock.
5. It atomically marks the token consumed before returning a signed leaf
   certificate and cluster identity document. A retry with the same token is
   rejected as replay.
6. The worker atomically installs its key, certificate, CA, and identity
   manifest. The private key never leaves the worker.

Manual PKI remains supported. An operator supplies the same certificate, key,
CA, node ID, roles, and labels directly in `proxy.cluster`; runtime identity is
the same `ClusterIdentity` value regardless of how the files were produced.

## Typed cluster state

Typed state uses a versioned `ClusterStateEnvelope` containing namespace, key,
schema version, publisher node ID, generation, published time, expiry time,
and payload bytes. The distributed backend stores it through the existing
encrypted and optionally mTLS-authenticated mesh transport. The local backend
keeps the same semantics without network tasks.

Writes fail when the selected remote owner is unreachable. Reads distinguish
missing, expired, malformed, incompatible-schema, and unreachable results.
Consumers apply their own monotonic generation checks before publication.

## Node model snapshots

`NodeModelSnapshot` schema version 1 contains only bounded operational data:

- cluster identity: node ID, roles, labels, and model-plane endpoint;
- engine capabilities and availability;
- hardware accelerators, total and available memory, and placement weight;
- artifact digests and local cache state;
- replica deployment, deployment generation, model, selected variant, engine,
  lifecycle state, endpoint, active requests, queue depth, and adapters;
- bounded last-error reason codes;
- snapshot generation, publish time, and expiry time;
- active deployment content digest for local-mode mismatch reporting.

Raw errors, local artifact paths, private addresses outside the configured
model endpoint, prompts, keys, tokens, certificates, and secrets are forbidden.
Length and cardinality bounds are validated before publication and after
decode.

A worker publisher derives snapshots from the shared local runtime, catalog,
engine capability probes, artifact cache, and cluster identity. Generation is
monotonic for the life of the installed node identity and is persisted with the
identity state so a restart cannot replace a newer snapshot with generation
zero.

## Model directory

`sbproxy-ai::ModelDirectory` has one serialized writer and lock-free readers.
The writer joins live membership with typed snapshot results and publishes one
immutable `Arc<ModelDirectoryView>` through `ArcSwap`.

Every node in membership appears in admin diagnostics. A node is excluded from
new routing when it is suspect, dead, snapshot-expired, snapshot-unreachable,
malformed, schema-incompatible, or behind the active deployment generation.
An older compatible snapshot schema remains routable after normalization. An
older snapshot generation cannot replace a newer generation already observed
for the same installed node identity.

Each directory node records snapshot age and one stable exclusion reason.
Eligible replicas are indexed by deployment and generation for PR 4 routing.
No request-path call acquires the directory writer lock or performs network
I/O.

## Placement

Placement is a pure function of:

- a normalized deployment revision and its monotonic generation;
- the current eligible directory nodes;
- catalog variant requirements;
- the prior committed placement plan and rollout deadline.

Candidate filtering requires the worker role, required labels, requested
accelerator, sufficient available memory, compatible engine capability, and a
compatible or cached artifact variant. Pinned deployments use one exact
variant on every replica. A deployment that explicitly enables heterogeneous
variants chooses the best compatible variant independently per selected node,
with deterministic tie breaking.

Weighted rendezvous hashing ranks candidates from the deployment ID,
deployment generation, node ID, and selected variant. Capacity produces a
bounded positive weight. Identical inputs produce identical rankings on every
node. Adding or removing one node changes only assignments whose rendezvous
ranking is displaced.

`spread_by` is an ordered list of label keys. Selection first maximizes new
failure-domain values for those keys and then follows rendezvous rank. Missing
labels form an explicit unknown domain and never create nondeterministic order.

A one-node directory assigns a `replicas: 1` deployment locally. A partition
may temporarily produce more replicas because each side computes from its own
reachable view. Neither side publishes or routes to a replica excluded by its
local directory.

## Rollout and generation fencing

A placement plan identifies one deployment revision, deployment generation,
and exact node/variant assignments. A replacement plan starts new assignments
before removing old assignments for rolling policy. Losing assignments remain
retained until all required replacements report ready in the directory or the
configured handoff timeout expires. Recreate policy drains first.

Once a newer generation is committed, older replicas enter draining and are
removed from the eligible directory index. They may finish admitted work but
cannot accept new work. Existing worker-local admission generation checks
remain authoritative.

The core cluster model controller serializes config revisions and placement
revisions through the existing model runtime commit lock. It filters the full
desired revision to assignments owned by the local node, retains safe-handoff
assignments, reconciles that local subset through `ModelRuntimeManager`, and
then publishes the resulting replica truth. A failed placement or local
runtime prepare leaves the prior committed plan and runtime active.

## Signed deployment authority

Both file-managed and cluster-authority sources normalize into one
`PlacementInput`. Cluster authority uses a strict, schema-versioned
`RestrictedDeploymentBundle` containing only catalog revision, deployment
revision, model deployments, and placement rules. The DTO uses unknown-field
denial at every level.

The configured authority signs canonical bundle bytes with Ed25519 and
publishes the content-addressed bundle plus a small current-version pointer.
Readers verify signer identity, signature, content digest, schema version, and
monotonic revision before swapping desired state. A non-authority node refuses
all persistent deployment writes. Tests explicitly reject `secrets`, arbitrary
`proxy` configuration, private keys, and unknown fields in a bundle.

In local file mode, each snapshot publishes its active deployment digest. The
directory and admin status report mismatches, but no node silently overwrites
another node's local file.

## Operator surfaces

PR 3 adds:

- `sbproxy cluster init`;
- `sbproxy cluster token create`;
- `sbproxy cluster enroll`;
- `sbproxy cluster status --format text|json`;
- `GET /admin/cluster/status` with identity, membership, directory age,
  exclusions, placement, and deployment digest consistency;
- `POST /admin/cluster/enroll`, authenticated only by a valid one-time token;
- authority-only signed deployment publication and explicit read-only errors
  elsewhere.

The model-management UI remains PR 6. PR 3 admin JSON is the stable backend
contract that UI will consume.

## Failure and security rules

- Canonical production clustering fails closed without valid mTLS material.
- Shared-key mode is explicit development configuration and never advertised
  as production peer identity.
- Token files store token hashes, not bearer values.
- Token consumption and replay rejection are atomic across processes.
- Enrollment never accepts authority role unless the token permits it.
- Snapshot decode and bundle decode have byte, string, collection, and label
  bounds.
- Suspect, dead, stale, incompatible, and unreachable nodes receive no new
  assignments or routes.
- Cluster bootstrap failure fails canonical distributed startup. Legacy mesh
  compatibility retains its documented local-only fallback with a warning.
- Cluster identity and listener changes are restart-required, not partially
  applied during reload.
- A failed signed revision, placement plan, or runtime reconcile retains the
  last-good state.

## Verification

Focused unit and property tests cover config lowering, restart classification,
local-handle zero-network behavior, one process bootstrap, membership mapping,
typed-state expiry, enrollment replay, CSR signing, role and label constraints,
manual PKI normalization, bundle restrictions, signature tampering, snapshot
generation, schema compatibility, directory exclusion, weighted rendezvous,
minimal movement, spread, pinned and heterogeneous variants, partition
overprovision, and rollout handoff.

Multi-process integration tests start ephemeral authority, gateway, and worker
processes with temporary certificates and ports. They prove assignment
convergence, stale and dead exclusion, local deployment hash mismatch, safe
drain, and no second mesh when the key cache is enabled. These tests use local
CPU fixtures and fake engines. GCP T4, L4, and three-node live evidence remains
PR 7.
