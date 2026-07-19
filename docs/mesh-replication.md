# Replicated cluster state

*Last modified: 2026-07-19*

The mesh's typed-state cache routes every key to a single owner and keeps
everything in memory. That is fine for best-effort caching, but it cannot
hold canonical state: an owner restart loses data, a delete reaches only
the current owner, and a healed partition never reconciles. The
replicated state substrate closes those gaps. It is configured under
`proxy.cluster.replication` and stores each record on several nodes, on
disk, with explicit consistency levels and a deletion protocol that
keeps removed data removed.

This substrate is infrastructure for cluster-internal state. No public
feature selects it yet: in particular, `compression.state.backend: mesh`
remains rejected at config validation, and re-enabling it is a separate
change gated on this substrate's guarantees. Configuring `replication`
today provisions the substrate and its admin surface without changing
any request-path behavior.

## Configuration

```yaml
proxy:
  cluster:
    cluster_id: prod
    node_id: gw-1
    state_dir: /var/lib/sbproxy/cluster
    # ... seeds, security, roles ...
    replication:
      factor: 2                      # copies kept per record
      write_consistency: quorum      # one | quorum | all
      read_consistency: quorum       # one | quorum | all
      anti_entropy_interval_secs: 30
      tombstone_gc_grace_secs: 86400
      max_entries: 65536
      max_value_bytes: 1048576
```

`state_dir` is required for canonical clusters and the replica shard
persists to `<state_dir>/replicated-state.redb`. A shard that cannot
open fails startup rather than running without durability.

Validation enforces: `factor` between 1 and 8, `anti_entropy_interval_secs`
between 5 and 3600, `tombstone_gc_grace_secs` at least ten anti-entropy
intervals, `max_entries` at most 1048576, and `max_value_bytes` at most
4 MiB.

## Placement and consistency

Each key maps to a preference list: the first `factor` distinct nodes
reached walking the consistent-hash ring clockwise from the key's hash.
The first entry is the same node the single-owner cache would pick, so a
factor of 1 degenerates to the old routing. A cluster smaller than the
factor replicates to every node it has and runs degraded rather than
unavailable.

Writes build a versioned record (a logical version above the highest
version any reachable replica holds), fan out to the whole preference
list, and report success only after the configured number of replicas
acknowledged:

- `one`: a single acknowledgement. The write is durable on at least one
  node.
- `quorum`: a majority of the key's replica set. With `factor: 2` this
  means both replicas; with `factor: 3` it means two.
- `all`: every replica.

A replica acknowledges only after committing the record to its disk
shard, so an acknowledged write does not depend on any process's memory.
If fewer replicas acknowledge than the level requires, the write returns
a quorum failure. The write may still have applied on some replicas;
retrying is safe (see idempotency below), and anti-entropy converges the
remainder either way.

Reads consult `read_consistency` replicas, reconcile divergent answers
by logical version (ties resolve deterministically), and repair stale or
missing replicas in line before returning. Choose levels by the usual
overlap rule: `write quorum` plus `read quorum` yields
read-your-latest-acknowledged-write behavior; `one`/`one` maximizes
availability and tolerates stale reads.

A node that the failure detector has isolated from the cluster fails
its state operations fast instead of pretending a quorum is reachable.
`one`-level operations still serve from the local shard.

## Durability and restart

Every replica apply is written through to a redb database before it is
acknowledged or served. On restart a node reloads its shard from disk,
drops live records whose absolute TTL elapsed while it was down, and
keeps serving. Expiries are wall-clock deadlines, not process-relative,
so they survive restarts.

One deliberate exception: a node that was offline longer than
`tombstone_gc_grace_secs` discards its stored records on startup and
rebuilds from the surviving replicas via anti-entropy. The reason is
deletion safety, explained next.

## Deletion, tombstones, and why deleted data stays deleted

A delete is a write: it replicates a tombstone through the same quorum
path. Tombstones never expire by TTL. They are physically removed only
by acknowledgement-aware garbage collection, which requires both:

1. The tombstone is older than `tombstone_gc_grace_secs`.
2. Every replica in the key's current preference list confirms it holds
   the tombstone (or a causally newer record) for that key.

Until both hold, the tombstone stays and fences out every stale live
copy: the merge rejects any candidate at a lower or equal version. A
legitimate re-create is still possible, because a coordinator that read
the tombstone writes at a higher version.

The no-resurrection argument composes three rules:

- While the tombstone exists anywhere in the replica set, a stale live
  record loses every merge against it.
- The tombstone is collected only after every current replica confirmed
  it AND the grace period elapsed, so no replica that participated in
  the deletion can later surface the old value.
- A node absent longer than the grace period might hold a live record
  whose covering tombstone was already collected cluster-wide. Such a
  node discards its shard on rejoin (the quarantine rule above) and
  resyncs from the current replicas, so its stale copy never re-enters
  the cluster.

The remaining window is a node absent for less than the grace period:
its covering tombstone cannot have been collected yet (collection
requires the full grace period), so anti-entropy delivers the tombstone
to it, not the other way around.

## Repair

A maintenance loop runs every `anti_entropy_interval_secs` on every
node, in three bounded phases:

1. **Handoff.** Records this node holds but no longer replicates (the
   ring changed: a node joined, left, or was evicted) are pushed to
   every current replica. The local copy is dropped only after every
   push acknowledged; a failed push retries next round. Rebalancing
   moves data, it does not lose it.
2. **Anti-entropy.** For each peer, exchange compact per-key digests
   (version, writer, tombstone flag) in bounded pages and reconcile
   both directions. This is what converges both live records and
   tombstones after a partition heals.
3. **Tombstone GC.** As described above.

Quorum reads additionally repair stale replicas in line, so hot keys
converge faster than the maintenance cadence.

## Idempotent retries

Every successful write returns a receipt containing the exact versioned
record that was replicated. A caller whose response was lost (timeout,
connection drop) retries by re-submitting the receipt: replicas merge
the identical record and report it unchanged. No version inflation, no
duplicate effects, any number of retries.

## Admin surface

Three authenticated admin routes operate on the whole fleet:

- `GET /admin/cluster/state?prefix=&page_token=&limit=` walks every
  current member and lists each record every holder still has. Entries
  name their holder, so a key with `factor: 2` appears twice; collapse
  by key client-side. Pagination is bounded and topology-safe: if the
  member a page token points at leaves the cluster, the walk resumes at
  the next surviving member instead of failing or looping. Members that
  could not be queried are listed in `unreachable` rather than silently
  skipped.
- `DELETE /admin/cluster/state?key=` performs a replicated delete with
  the configured write consistency.
- `POST /admin/cluster/state/purge` with `{"prefix": "...", "max": 1000}`
  deletes every distinct live key under the prefix, bounded by `max`;
  the response reports `deleted`, `failed`, and `truncated` so an
  operator can repeat until done.

## Bounds and metrics

Each node's shard holds at most `max_entries` records; a write that
would exceed the bound is rejected, not silently dropped, and the
rejection is the backpressure signal. Values are capped at
`max_value_bytes`. Digest and listing pages are bounded server-side.
Diagnostics never log record values.

The substrate exports `mesh_replication_writes_total{outcome}`,
`mesh_replication_read_repairs_total`, `mesh_anti_entropy_rounds_total`,
`mesh_anti_entropy_keys_total{direction}`,
`mesh_tombstone_gc_total{outcome}`, `mesh_handoff_keys_total{outcome}`,
and `mesh_replica_shard_entries`.

## What this is not

These guarantees are scoped to what is written here: quorum-checked
eventual consistency with durable local shards, deterministic conflict
resolution, and a proven deletion protocol. It is not a consensus
system, it does not serialize concurrent writers (the deterministic
merge picks one), and it is not a claim of parity with any external
datastore. Strict atomic semantics (reservations, compare-and-swap
budgets) remain the job of a shared backend; see
[key-management.md](key-management.md) for that split.

## Wire compatibility

The replica operations extend the mesh transport protocol. The mesh
wire format is not versioned across releases: all nodes in a cluster
must run the same sbproxy release, and a rolling upgrade should drain
nodes one at a time as usual. See [upgrade.md](upgrade.md).
