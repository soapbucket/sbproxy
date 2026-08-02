# WOR-2062: rate limits and key state converge on the mesh

Design decision, 2026-07-29. Verified against `origin/main` at `7a868668`.

## Problem

State that has to be cluster-wide is only cluster-wide when Redis is configured. Three holes, one theme.

1. `rate_limit` distributes through the L2 store only. On a gossip-mesh cluster with no Redis, every node limits independently, so 600 rpm configured on three nodes admits roughly 1800 rpm. Nothing warns the operator that the limit is per-node.
2. `MeshCacheTier::invalidate_all` clears the local shard only, while `key_plane.rs:1329` calls it on admin mutation. A bulk credential purge on one node leaves peers stale until TTL.
3. There is no mesh keystore backend. With the default embedded redb keystore, a key minted on node A is written only to node A, so peers cannot resolve it regardless of caching.

## What already exists

The exploration changed the shape of this work. Two of the three holes are much smaller than they look.

`governance_crdt.rs` and `governance_cluster.rs` are a working converge-and-over-admit implementation: per-node slots keyed `(key_id, policy_revision, window_start_millis)`, newest generation wins per node, summed into a read-optimised view, peers merged with this node excluded, installed via `set_peer_counters`, entries expiring at three times the cadence. Governed-key rate usage already converges over the mesh. The `rate_limit` policy does not.

The cluster-wide purge already exists end to end. `transport/frame.rs` defines the wire op, `transport/server.rs:297` dispatches `CacheOp::PurgePrefix` and treats an empty prefix as purge-everything, and `transport/client.rs:380` is the client call. Its doc states plainly that the caller is responsible for broadcasting to every peer. Hole 2 is unwired, not unbuilt.

`sbproxy-mesh/src/state/sliding_window.rs` is 213 lines with zero readers and no re-export from `lib.rs`. It is the shape #722 deleted `MeshKeyCounters` for.

`sbproxy-modules` already depends on `sbproxy-ai`, so reusing the governance CRDT adds no dependency and creates no cycle. `governance_crdt` itself has no mesh dependency, which is why the dissemination loop lives in `sbproxy-core` where mesh and ai meet.

## A bug found on the way

In clustered mode `MeshCacheTier`'s cache is `node.distributed_cache()`, the node-wide cache. So `invalidate_all` calling `purge_all_local()` both over-purges locally, discarding every unrelated entry in the shared cache, and under-purges cluster-wide, never reaching peers. A prefix-scoped fan-out over `keymgmt:key:` and `keymgmt:cred:` fixes both directions at once.

## Decision: converge and over-admit

Each node enforces locally against its own count plus a merged view of its peers, refreshed on a cadence. The alternative, leasing a slice of the window from a shared budget, buys tighter enforcement but needs a recovery story for a node that dies holding a lease, and adds a second dissemination mechanism next to governance. A shorter cadence buys most of the same tightness for none of that cost.

Rate limits reuse the governance CRDT primitives rather than a parallel mechanism, on a separate channel with its own cadence.

### Overshoot bound

Overshoot is bounded by the work peers can do before this node hears about it: `(N - 1) * rate * cadence`.

| Configuration | Today | 15s cadence | 3s cadence |
| --- | --- | --- | --- |
| 600 rpm, 3 nodes | 1800 (3.0x) | 900 (1.5x) | 660 (1.1x) |
| 600 rpm, 5 nodes | 3000 (5.0x) | 1200 (2.0x) | 720 (1.2x) |

The default cadence is 3 seconds, chosen so a per-minute limit converges within about five percent per added node. Governance keeps its 15 second cadence, which suits spend where the window is long and the cost of overshoot is money rather than a broken promise.

This bound is documented and metered, not implicit. An operator setting a hard limit is told it is approximate and by how much.

### Windows must align across nodes

Slots only merge when every node computes the same `window_start_millis`, so the window start is `floor(now / window_secs) * window_secs` from wall clock. This assumes nodes agree on the time. Clock skew between peers widens the effective overshoot because a skewed node contributes to a window its peers have already closed. The docs state the NTP assumption.

### Per-second limits do not converge

`rate_limit.rs:429` sets `window_secs` to 60 for `requests_per_minute` and 1 for `requests_per_second`. A one second window cannot be reconciled across nodes at any sane gossip cadence, because the window closes before a peer's contribution arrives.

So `requests_per_second` stays per-node, and boot warns when it is configured on a clustered deployment without Redis. Pretending otherwise would be the same overclaim this ticket exists to fix. Operators who need a cluster-wide per-second limit configure Redis, which remains authoritative and exact.

## Architecture

Four slices, each independently reviewable.

### Slice A: rate-limit convergence

`sbproxy-modules/src/policy/rate_limit.rs` gains a cluster tier alongside the existing store setters. It publishes this node's count for the current window and reads a merged peer view. The setter mirrors `with_store` in shape so the construction site stays uniform.

Rate-limit slots reuse `NodeCounterSlot`, `GovernanceContribution` and `merge_contributions`. They travel on their own channel keyed distinctly from governed-key spend, so the two cannot collide in one merged map, and only the `requests` field of `GovernanceUsage` is used.

A dissemination loop in `sbproxy-core` mirrors `governance_cluster::run_loop`: a tokio interval, publish this node's contribution, merge every live peer with self excluded, install the merged view. Separate from the governance loop because the cadence differs.

The production wiring point is `pipeline.rs:1736`, where `with_store` is already attached.

Decision on the request path: admit when `local + merged_peers < window_limit`. The local count is immediate and authoritative for this node. The peer view lags by at most one cadence.

`sliding_window.rs` is deleted. Governance slots are the chosen substrate, and leaving a second unread CRDT in the tree is the exact thing #722 removed.

### Slice B: cluster-wide invalidate_all

`MeshCacheTier::invalidate_all` purges the two key-plane prefixes locally and fans `purge_prefix` out to every peer, summing the counts. This replaces `purge_all_local()`, fixing the over-purge and the missing propagation together.

The peer list is needed, not just the id-to-address lookup the tier holds today. The tier already takes a `MeshNode` in `clustered`, so membership comes from there.

### Slice C: keystore guard

Boot rejects a clustered deployment whose keystore cannot be shared, naming the fix: use a Redis or Secrets Manager keystore, or accept per-node keys deliberately. The embedded redb and in-memory backends cannot be shared.

This closes the acceptance criterion as written and fixes the `docs/enterprise.md` claim that a key minted on one replica is usable on any, which holds today only when the keystore itself is shared. The real mesh keystore backend is a separate ticket: `state/replicated` provides quorum replication, anti-entropy and read repair, but a system of record deserves its own design pass.

### Slice D: docs

`docs/enterprise.md` and the clustering docs state which state converges, by what mechanism, and with what bound. That means naming rate limits as approximate with the formula, per-second limits as per-node, credential purge as cluster-wide, and minting as requiring a shared keystore.

Marketing copy deliberately omits rate limits from mesh-backed state. It stays omitted until Slice A lands, and then says approximate rather than implying exact.

## Observability

A metric exposes the divergence between the local count and the merged view, so the approximation is visible rather than inferred.

The reader is the request path itself, which consults the merged view on every decision, so this is not a counter that nothing reads. Per the metric drift guard, a stable metric needs a non-test increment site and coverage in `dashboards/grafana/`, `dashboards/prometheus/` or `deploy/alerts/`, so the dashboard entry lands with the metric. Label cardinality follows the existing multi-tenancy convention.

## Error handling

Dissemination is best effort. A failed publish or a peer that does not answer leaves the last merged view in place until its TTL expires, at which point the node falls back to enforcing on its own count alone. That fails toward over-admitting rather than denying traffic, which matches the chosen model: a partitioned node keeps serving at its local limit instead of blocking.

A peer that goes away stops contributing once its entry expires at three times the cadence, so a dead node does not hold the cluster's budget down. This is the property leasing would have had to solve explicitly.

The keystore guard fails at boot rather than at first use, so a misconfigured cluster never starts and silently mints unresolvable keys.

## Testing

The acceptance criteria are mostly tests, and one of them is the guardrail for this whole design.

- Multi-node convergence: three nodes, 600 rpm, admitting close to 600 rather than 1800. `compression_mesh_store.rs` pins membership directly without binding ports, which is the pattern to follow.
- Cross-node merge: a counter written on one node is read through the merged view on another. Without this the work is the `MeshKeyCounters` shape again.
- Window alignment: nodes computing the same window boundary merge, and a skewed node is accounted for.
- Per-second limits warn at boot on a mesh-only cluster.
- Divergence metric moves when local and merged counts differ.
- `invalidate_all` propagates: an entry cached on a peer is gone after a purge elsewhere, and unrelated entries in the node-wide cache survive.
- Keystore guard: clustered plus embedded keystore fails at boot with an error naming the fix.

## Out of scope

At-rest cache encryption, per-origin multi-tenant keys, and the plaintext-credential caching issue are WOR-2063. The mesh keystore backend is its own ticket. Neither belongs in a change about convergence.
