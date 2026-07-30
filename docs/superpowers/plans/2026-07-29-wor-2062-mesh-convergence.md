# WOR-2062 Mesh Convergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make rate limits converge cluster-wide on a mesh-only cluster with no Redis, propagate bulk credential purges to peers, and refuse to start a clustered deployment whose keystore cannot be shared.

**Architecture:** Rate limits reuse the existing governance CRDT (`NodeCounterSlot` / `GovernanceContribution` / `merge_contributions`) on a separate cluster-state channel with its own cadence, rather than a second dissemination mechanism. Each node admits against its own immediate count plus a merged, self-excluded peer view refreshed every 3 seconds. The bulk purge wires up an RPC that already exists end to end. The keystore gap ships as a fail-loud boot guard, with the real backend tracked as WOR-2064.

**Tech Stack:** Rust, tokio, `sbproxy-mesh` (ClusterHandle, transport), `sbproxy-ai::governance_crdt`, prometheus via `sbproxy-observe`, `cargo nextest`.

## Global Constraints

- Design decisions are fixed by `docs/superpowers/specs/2026-07-29-wor-2062-mesh-convergence-design.md`. Do not relitigate them mid-implementation.
- Overshoot bound is `(N - 1) * rate * cadence`. Default cadence is 3 seconds.
- `requests_per_second` (window of 1s) does NOT converge. It stays per-node and warns at boot. Do not attempt to converge it.
- Any CRDT counter added here needs a production reader and a test proving cross-node merge. A counter nothing reads is the `MeshKeyCounters` shape deleted in #722. This is the hard guardrail on this work.
- No em-dashes or en-dashes in any prose, code comment, or doc.
- Public docs (`docs/*.md`, CHANGELOG, README, PR bodies) must never cite `WOR-NNNN`. Internal specs and plans under `docs/superpowers/` may.
- Build with the per-branch target dir to avoid a sibling worktree's stale rmeta faking compile errors:
  `export CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/.worktrees/.cargo-targets/wor-2062-mesh-convergence`
- Use `CARGO_BUILD_JOBS=2` for test runs. The gate OOMs at higher job counts.
- Per-crate clippy is stricter than workspace clippy. Run `cargo clippy -p <crate> --all-targets -- -D warnings` per touched crate.
- Adding a stable metric requires a non-test increment site AND coverage in `dashboards/grafana/`, `dashboards/prometheus/` or `deploy/alerts/`, else the metric drift guard fails.

---

### Task 1: RateLimitClusterTier holds local slots and a merged peer view

The tier is the data structure the policy reads and the dissemination loop publishes. It deliberately mirrors `InMemoryGovernanceStore` (`crates/sbproxy-ai/src/governance.rs:395`, with `set_peer_counters` at `:522` and `local_slots` at `:527`) so there is one shape to understand.

**Files:**
- Create: `crates/sbproxy-modules/src/policy/rate_limit_cluster.rs`
- Modify: `crates/sbproxy-modules/src/policy/mod.rs` (add `pub mod rate_limit_cluster;`)
- Test: inline `#[cfg(test)] mod tests` in the new file

**Interfaces:**
- Consumes: `sbproxy_ai::governance_crdt::{GovernanceContribution, MergedCounters, NodeCounterSlot, merge_contributions}`, `sbproxy_ai::governance::GovernanceUsage`
- Produces:
  - `RateLimitClusterTier::new(node_id: impl Into<String>) -> Self`
  - `fn increment_local(&self, bucket: &str, window_start_secs: u64) -> u64` (returns post-increment local count)
  - `fn merged_peers(&self, bucket: &str, window_start_secs: u64) -> u64`
  - `fn local_slots(&self) -> Vec<NodeCounterSlot>`
  - `fn set_peer_counters(&self, merged: MergedCounters)`
  - `fn node_id(&self) -> &str`
  - `const RATE_LIMIT_POLICY_REVISION: u64 = 0`

Rate-limit slots set `policy_revision` to `RATE_LIMIT_POLICY_REVISION` and store the count in `GovernanceUsage::requests`, leaving `tokens` and `micro_usd` zero. `window_start_millis` is `window_start_secs * 1000`. The bucket string is used verbatim as `key_id`; the caller has already namespaced it with the origin via `key_prefix`, so spend slots and rate slots cannot collide across the two separate channels.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_local_accumulates_per_bucket_and_window() {
        let tier = RateLimitClusterTier::new("node-a");
        assert_eq!(tier.increment_local("ip:1.2.3.4", 60), 1);
        assert_eq!(tier.increment_local("ip:1.2.3.4", 60), 2);
        // A different window is a different slot.
        assert_eq!(tier.increment_local("ip:1.2.3.4", 120), 1);
        // A different bucket is a different slot.
        assert_eq!(tier.increment_local("ip:5.6.7.8", 60), 1);
    }

    #[test]
    fn local_slots_exports_every_live_slot_for_publication() {
        let tier = RateLimitClusterTier::new("node-a");
        tier.increment_local("ip:1.2.3.4", 60);
        tier.increment_local("ip:1.2.3.4", 60);
        tier.increment_local("ip:5.6.7.8", 60);

        let mut slots = tier.local_slots();
        slots.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].key_id, "ip:1.2.3.4");
        assert_eq!(slots[0].usage.requests, 2);
        assert_eq!(slots[0].window_start_millis, 60_000);
        assert_eq!(slots[0].policy_revision, RATE_LIMIT_POLICY_REVISION);
        assert_eq!(slots[1].usage.requests, 1);
    }

    #[test]
    fn merged_peers_reads_the_installed_peer_view() {
        let tier = RateLimitClusterTier::new("node-a");
        assert_eq!(tier.merged_peers("ip:1.2.3.4", 60), 0);

        let peer = GovernanceContribution {
            node_id: "node-b".into(),
            generation: 1,
            slots: vec![NodeCounterSlot {
                key_id: "ip:1.2.3.4".into(),
                policy_revision: RATE_LIMIT_POLICY_REVISION,
                window_start_millis: 60_000,
                usage: GovernanceUsage { requests: 7, tokens: 0, micro_usd: 0 },
            }],
        };
        tier.set_peer_counters(merge_contributions([peer]));

        assert_eq!(tier.merged_peers("ip:1.2.3.4", 60), 7);
        // Local count stays separate from the peer view.
        assert_eq!(tier.increment_local("ip:1.2.3.4", 60), 1);
        assert_eq!(tier.merged_peers("ip:1.2.3.4", 60), 7);
        // A window the peers did not report is zero, not a stale read.
        assert_eq!(tier.merged_peers("ip:1.2.3.4", 120), 0);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
export CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/.worktrees/.cargo-targets/wor-2062-mesh-convergence
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-modules --lib policy::rate_limit_cluster::
```

Expected: FAIL, unresolved module `rate_limit_cluster`.

- [ ] **Step 3: Implement the tier**

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cluster tier for the rate-limit policy.
//!
//! Holds this node's per-window counts and the merged, self-excluded view
//! of every live peer. The dissemination loop in `sbproxy-core` publishes
//! [`RateLimitClusterTier::local_slots`] and installs peer contributions
//! through [`RateLimitClusterTier::set_peer_counters`]; the policy reads
//! [`RateLimitClusterTier::merged_peers`] on the request path.
//!
//! This reuses the governance CRDT rather than introducing a second
//! mergeable counter. Rate-limit slots travel on their own cluster-state
//! namespace, so they never mix with governed-key spend slots.

use std::collections::HashMap;
use std::sync::RwLock;

use sbproxy_ai::governance::GovernanceUsage;
use sbproxy_ai::governance_crdt::{MergedCounters, NodeCounterSlot};

/// Rate-limit slots do not carry a policy revision. The limit is taken
/// from live config on every request, so there is no revision to pin.
pub const RATE_LIMIT_POLICY_REVISION: u64 = 0;

/// This node's counts plus the merged peer view, for one origin's policy.
pub struct RateLimitClusterTier {
    node_id: String,
    /// `(bucket, window_start_secs) -> count` counted by this node.
    local: RwLock<HashMap<(String, u64), u64>>,
    /// Merged contributions from every live peer, this node excluded.
    peers: RwLock<MergedCounters>,
}

impl RateLimitClusterTier {
    /// Build an empty tier owned by `node_id`.
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            local: RwLock::new(HashMap::new()),
            peers: RwLock::new(MergedCounters::default()),
        }
    }

    /// The publishing node's identifier.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Count one request against `bucket` in `window_start_secs` and return
    /// this node's post-increment count for that slot.
    pub fn increment_local(&self, bucket: &str, window_start_secs: u64) -> u64 {
        let mut guard = match self.local.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard
            .entry((bucket.to_string(), window_start_secs))
            .or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    /// The cluster's peer-contributed count for one slot, this node excluded.
    pub fn merged_peers(&self, bucket: &str, window_start_secs: u64) -> u64 {
        let guard = match self.peers.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .merged_usage(
                bucket,
                RATE_LIMIT_POLICY_REVISION,
                window_start_secs.saturating_mul(1000),
            )
            .requests
    }

    /// Every live local slot, shaped for publication.
    pub fn local_slots(&self) -> Vec<NodeCounterSlot> {
        let guard = match self.local.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .iter()
            .map(|((bucket, window_start), count)| NodeCounterSlot {
                key_id: bucket.clone(),
                policy_revision: RATE_LIMIT_POLICY_REVISION,
                window_start_millis: window_start.saturating_mul(1000),
                usage: GovernanceUsage {
                    requests: *count,
                    tokens: 0,
                    micro_usd: 0,
                },
            })
            .collect()
    }

    /// Install a freshly merged peer view.
    pub fn set_peer_counters(&self, merged: MergedCounters) {
        match self.peers.write() {
            Ok(mut g) => *g = merged,
            Err(poisoned) => *poisoned.into_inner() = merged,
        }
    }

    /// Drop local slots whose window closed before `oldest_window_secs`, so
    /// a long-lived process does not accumulate one entry per window
    /// forever. Called by the dissemination loop each tick.
    pub fn evict_before(&self, oldest_window_secs: u64) {
        let mut guard = match self.local.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|(_, window_start), _| *window_start >= oldest_window_secs);
    }
}
```

Add to `crates/sbproxy-modules/src/policy/mod.rs`:

```rust
pub mod rate_limit_cluster;
```

- [ ] **Step 4: Add the eviction test, then run the suite**

```rust
    #[test]
    fn evict_before_drops_closed_windows_only() {
        let tier = RateLimitClusterTier::new("node-a");
        tier.increment_local("ip:1.2.3.4", 60);
        tier.increment_local("ip:1.2.3.4", 120);
        tier.evict_before(120);
        let slots = tier.local_slots();
        assert_eq!(slots.len(), 1, "the closed window is gone");
        assert_eq!(slots[0].window_start_millis, 120_000);
    }
```

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-modules --lib policy::rate_limit_cluster::
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy -p sbproxy-modules --all-targets -- -D warnings
git add crates/sbproxy-modules/src/policy/rate_limit_cluster.rs crates/sbproxy-modules/src/policy/mod.rs
git commit -m "feat(policy): add a mergeable cluster tier for rate-limit counts"
```

---

### Task 2: The policy admits against local plus merged peers

**Files:**
- Modify: `crates/sbproxy-modules/src/policy/rate_limit.rs` (struct field near the L2 block at `:112-133`, a `with_cluster` setter beside `with_observer` at `:479`, and the fallback branch at `:669`)
- Test: inline tests in the same file

**Interfaces:**
- Consumes: `RateLimitClusterTier` from Task 1
- Produces:
  - `RateLimitPolicy::with_cluster(self, cluster: Option<Arc<RateLimitClusterTier>>) -> Self`
  - `RateLimitPolicy::converges_on_mesh(&self) -> bool` (false when `window_secs <= 1`)

The decision reuses the window alignment the Redis path already computes at `:688`, so all nodes agree on the boundary. `window_secs <= 1` returns the local token-bucket result untouched, per the fixed decision that per-second limits do not converge.

- [ ] **Step 1: Write the failing tests**

```rust
    fn rpm_policy(rpm: f64) -> RateLimitPolicy {
        RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": rpm }))
            .expect("valid rpm policy")
    }

    #[tokio::test]
    async fn cluster_tier_denies_once_local_plus_peers_reaches_the_limit() {
        let tier = std::sync::Arc::new(
            crate::policy::rate_limit_cluster::RateLimitClusterTier::new("node-a"),
        );
        let policy = rpm_policy(10.0).with_cluster(Some(tier.clone()));

        // Peers already report 8 requests in the current window.
        let window = 60u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let window_start = now - (now % window);
        let peer = sbproxy_ai::governance_crdt::GovernanceContribution {
            node_id: "node-b".into(),
            generation: 1,
            slots: vec![sbproxy_ai::governance_crdt::NodeCounterSlot {
                key_id: format!("{}c1:{}", policy.debug_key_prefix(), window_start),
                policy_revision:
                    crate::policy::rate_limit_cluster::RATE_LIMIT_POLICY_REVISION,
                window_start_millis: window_start * 1000,
                usage: sbproxy_ai::governance::GovernanceUsage {
                    requests: 8,
                    tokens: 0,
                    micro_usd: 0,
                },
            }],
        };
        tier.set_peer_counters(sbproxy_ai::governance_crdt::merge_contributions([peer]));

        // Local requests 1 and 2 bring the cluster total to 9 then 10.
        assert!(policy.allow_with_info_async("c1").await.allowed);
        assert!(policy.allow_with_info_async("c1").await.allowed);
        // The 11th cluster request is over the limit of 10.
        assert!(!policy.allow_with_info_async("c1").await.allowed);
    }

    #[tokio::test]
    async fn per_second_limits_do_not_use_the_cluster_tier() {
        let tier = std::sync::Arc::new(
            crate::policy::rate_limit_cluster::RateLimitClusterTier::new("node-a"),
        );
        let policy =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_second": 5.0 }))
                .expect("valid rps policy")
                .with_cluster(Some(tier.clone()));

        assert!(!policy.converges_on_mesh(), "a 1s window cannot converge");
        assert!(policy.allow_with_info_async("c1").await.allowed);
        assert!(
            tier.local_slots().is_empty(),
            "rps must not publish slots it cannot reconcile"
        );
    }
```

- [ ] **Step 2: Run to verify failure**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-modules --lib policy::rate_limit::
```

Expected: FAIL, no method `with_cluster`.

- [ ] **Step 3: Add the field, setter, and decision path**

Add to the struct after the `observer` field (near `:133`):

```rust
    /// Optional mesh cluster tier. When `Some` and no L2 store is
    /// configured, the policy admits against this node's count plus the
    /// merged peer view instead of a purely local token bucket. Only
    /// consulted for windows longer than one second; see
    /// [`Self::converges_on_mesh`].
    #[serde(skip)]
    cluster: Option<Arc<rate_limit_cluster::RateLimitClusterTier>>,
```

Add the setter beside `with_observer`:

```rust
    /// Attach the mesh cluster tier so this policy enforces an approximate
    /// cluster-wide limit without Redis.
    ///
    /// Overshoot is bounded by `(peers) * rate * dissemination_cadence`.
    /// With the default 3 second cadence, each additional node can admit
    /// about `rate * 3` requests before this node hears about them. Pass
    /// `None` to clear a previously attached tier.
    pub fn with_cluster(
        mut self,
        cluster: Option<Arc<rate_limit_cluster::RateLimitClusterTier>>,
    ) -> Self {
        self.cluster = cluster;
        self
    }

    /// Whether this policy's window is long enough to reconcile across
    /// nodes. A one second window closes before a peer contribution can
    /// arrive, so `requests_per_second` limits stay per-node.
    pub fn converges_on_mesh(&self) -> bool {
        self.window_secs > 1
    }

    /// Test-only accessor for the counter-key prefix.
    #[cfg(test)]
    pub(crate) fn debug_key_prefix(&self) -> &str {
        &self.key_prefix
    }
```

Replace the fallback branch at `:669`:

```rust
        if self.async_store.is_none() && self.store.is_none() {
            if let Some(cluster) = self.cluster.as_ref() {
                if self.converges_on_mesh() {
                    return self.allow_with_info_cluster(client_id, cluster.as_ref());
                }
            }
            return self.allow_with_info_for(client_id);
        }
```

Add the cluster decision, mirroring the Redis path's window maths:

```rust
    /// Admit against this node's count plus the merged peer view.
    ///
    /// The window boundary is computed exactly as the Redis path computes
    /// it, so every node buckets the same request into the same window and
    /// the slots merge. Local counting is immediate; the peer view lags by
    /// at most one dissemination cadence, which is the documented source of
    /// overshoot.
    fn allow_with_info_cluster(
        &self,
        client_id: &str,
        cluster: &rate_limit_cluster::RateLimitClusterTier,
    ) -> RateLimitInfo {
        let window = if self.window_secs > 0 {
            self.window_secs
        } else {
            1
        };
        let limit = self.window_limit();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = now_secs - (now_secs % window);
        let bucket = format!("{}{}:{}", self.key_prefix, client_id, window_start);

        let local = cluster.increment_local(&bucket, window_start);
        let peers = cluster.merged_peers(&bucket, window_start);
        let count = local.saturating_add(peers);

        crate::policy::rate_limit_cluster::record_divergence(local, peers);

        RateLimitInfo {
            allowed: count <= limit,
            limit,
            remaining: limit.saturating_sub(count),
            reset_secs: window.saturating_sub(now_secs - window_start),
            headers_enabled: self.headers_enabled(),
            include_retry_after: self.include_retry_after(),
            include_ratelimit_policy: false,
        }
    }
```

Add `cluster: None` to every `RateLimitPolicy` struct literal the compiler flags. Find them all first, across the whole workspace including the binary crate, since a per-crate build will not surface them all:

```bash
grep -rn "RateLimitPolicy {" crates/ --include="*.rs"
```

Add `use crate::policy::rate_limit_cluster;` and `use std::sync::Arc;` if not already imported.

- [ ] **Step 4: Run to verify pass**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-modules --lib policy::rate_limit
```

Expected: PASS, including the two new tests and every pre-existing rate-limit test.

- [ ] **Step 5: Lint and commit**

```bash
cargo clippy -p sbproxy-modules --all-targets -- -D warnings
git add crates/sbproxy-modules/src/policy/rate_limit.rs
git commit -m "feat(policy): admit against local plus merged peer counts on a mesh cluster"
```

---

### Task 3: Divergence metric

The metric makes the approximation observable, which is the third acceptance criterion. Its production reader is the request path itself, which consults the merged view on every decision, so this is not a write-only counter.

**Files:**
- Modify: `crates/sbproxy-observe/src/metric_registry.rs` (register the metric)
- Modify: `crates/sbproxy-modules/src/policy/rate_limit_cluster.rs` (add `record_divergence`)
- Modify: `dashboards/prometheus/` (add a rule covering the new metric)
- Test: inline test asserting the gauge moves

**Interfaces:**
- Produces: `rate_limit_cluster::record_divergence(local: u64, peers: u64)`

- [ ] **Step 1: Read the existing registration pattern**

```bash
grep -n "rate_limit" crates/sbproxy-observe/src/metric_registry.rs | head -20
ls dashboards/prometheus/
```

Follow whatever pattern the neighbouring rate-limit metrics use for naming, labels and stability tier. Match the existing tenant-label convention rather than inventing one.

- [ ] **Step 2: Write the failing test**

```rust
    #[test]
    fn record_divergence_reports_the_peer_share_of_the_cluster_count() {
        // 3 local and 9 peer-contributed is a divergence of 9: the amount
        // this node would have missed enforcing on without the merged view.
        record_divergence(3, 9);
        // The gauge is process-global; assert it observed the sample.
        assert_eq!(last_recorded_divergence(), 9);
    }
```

- [ ] **Step 3: Implement**

Register a gauge named for the peer-contributed count the local view would otherwise miss, then:

```rust
/// Record how much of the current cluster count came from peers rather
/// than this node. A divergence near zero on a multi-node cluster means
/// dissemination is not reaching this node.
pub fn record_divergence(local: u64, peers: u64) {
    let _ = local;
    sbproxy_observe::metrics::RATE_LIMIT_CLUSTER_PEER_COUNT.set(peers as f64);
}
```

- [ ] **Step 4: Run the metric-drift guard**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-observe --lib metric_drift
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-modules --lib policy::rate_limit_cluster::
```

Expected: PASS. If the drift guard fails, the dashboard entry is missing; add it rather than downgrading the metric's stability tier.

- [ ] **Step 5: Commit**

```bash
git add crates/sbproxy-observe crates/sbproxy-modules dashboards/
git commit -m "feat(observe): expose the peer-contributed share of cluster rate-limit counts"
```

---

### Task 4: Dissemination loop publishes and merges every cadence

**Files:**
- Create: `crates/sbproxy-core/src/rate_limit_cluster.rs`
- Modify: `crates/sbproxy-core/src/lib.rs` (add the module)
- Test: inline tests

**Interfaces:**
- Consumes: `ClusterHandle` (`identity()`, `publish_state`, `membership()`, `read_state`), `RateLimitClusterTier`
- Produces: `pub(crate) async fn run_loop(handle: ClusterHandle, tier: Arc<RateLimitClusterTier>, interval_secs: u64)`

This mirrors `crates/sbproxy-core/src/governance_cluster.rs:81-130` exactly, with three deliberate differences: its own namespace constant, a default cadence of 3 rather than 15, and an `evict_before` call each tick so closed windows do not accumulate.

- [ ] **Step 1: Read the loop being mirrored**

```bash
sed -n '1,145p' crates/sbproxy-core/src/governance_cluster.rs
```

- [ ] **Step 2: Write the failing test**

```rust
    #[test]
    fn merged_peer_view_excludes_this_node() {
        let mine = GovernanceContribution {
            node_id: "self".into(),
            generation: 1,
            slots: vec![slot("b1", 60_000, 100)],
        };
        let theirs = GovernanceContribution {
            node_id: "other".into(),
            generation: 1,
            slots: vec![slot("b1", 60_000, 5)],
        };
        let merged = merged_peer_view("self", vec![mine, theirs]);
        assert_eq!(
            merged.merged_usage("b1", RATE_LIMIT_POLICY_REVISION, 60_000).requests,
            5,
            "this node's own 100 is counted locally, not merged in twice"
        );
    }
```

- [ ] **Step 3: Implement, mirroring governance_cluster**

```rust
/// Cluster-state namespace for rate-limit slots. Distinct from the
/// governance namespace so spend slots and rate slots never mix.
const RATE_LIMIT_STATE_NAMESPACE: &str = "rate-limit-counters";
const RATE_LIMIT_STATE_SCHEMA_VERSION: u32 = 1;

/// Default dissemination cadence. Shorter than governance's 15s because
/// a per-minute window needs several exchanges inside one window for the
/// overshoot bound to stay near 5 percent per added node.
pub(crate) const DEFAULT_RATE_LIMIT_CADENCE_SECS: u64 = 3;
```

Then `run_loop` and `tick` following `governance_cluster.rs:48-130`: publish this node's `local_slots()` as a `GovernanceContribution` under the rate-limit namespace with `ttl = cadence * 3`, read every live peer's contribution excluding self, install via `tier.set_peer_counters(...)`, and call `tier.evict_before(...)` for windows older than the TTL.

- [ ] **Step 4: Run tests**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-core --lib rate_limit_cluster::
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sbproxy-core/src/rate_limit_cluster.rs crates/sbproxy-core/src/lib.rs
git commit -m "feat(core): disseminate and merge rate-limit counters across the mesh"
```

---

### Task 5: Wire the tier at the production call site

Without this task everything above is dead code. `pipeline.rs:1736` is where the policy already receives its L2 store.

**Files:**
- Modify: `crates/sbproxy-core/src/pipeline.rs` (around `:1729-1740`)
- Test: `crates/sbproxy-core/tests/` new integration test

- [ ] **Step 1: Read the existing attachment site**

```bash
sed -n '1720,1745p' crates/sbproxy-core/src/pipeline.rs
```

- [ ] **Step 2: Attach the tier and spawn the loop**

Build one `Arc<RateLimitClusterTier>` per origin policy when a mesh cluster handle exists and no L2 store is configured, attach it with `with_cluster`, and spawn `rate_limit_cluster::run_loop` once per tier. Follow the existing task-spawn pattern used for `governance_cluster::run_loop` so shutdown behaves the same way.

Emit the boot warning here when `!policy.converges_on_mesh()` on a clustered deployment with no Redis:

```rust
tracing::warn!(
    origin = %origin_id,
    "requests_per_second is enforced per node on a mesh cluster: a one second \
     window cannot be reconciled across peers. Configure an L2 store for an \
     exact cluster-wide per-second limit, or use requests_per_minute."
);
```

- [ ] **Step 3: Verify the wiring compiles and the warning fires**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-core --lib pipeline
```

- [ ] **Step 4: Commit**

```bash
git add crates/sbproxy-core/src/pipeline.rs
git commit -m "feat(core): attach the rate-limit cluster tier on mesh-only deployments"
```

---

### Task 6: Multi-node convergence proof

This is the second acceptance criterion and the guardrail test for the whole design. `crates/sbproxy-core/tests/compression_mesh_store.rs` pins membership directly without binding ports; copy that harness.

**Files:**
- Create: `crates/sbproxy-core/tests/rate_limit_mesh_convergence.rs`

- [ ] **Step 1: Read the multi-node harness to copy**

```bash
sed -n '1,60p' crates/sbproxy-core/tests/compression_mesh_store.rs
```

- [ ] **Step 2: Write the test**

Three nodes, one policy of 600 rpm each, sharing a pinned membership. Drive requests round-robin across the three policies, running one dissemination tick between batches. Assert the total admitted is close to 600 and nowhere near 1800:

```rust
    assert!(
        admitted <= 900,
        "three nodes admitted {admitted}, which is past the documented \
         (N-1) * rate * cadence bound"
    );
    assert!(
        admitted < 1800,
        "three nodes admitted {admitted}: that is per-node enforcement, \
         the bug this test exists to catch"
    );
```

Also assert the cross-node merge directly, so the counter provably has a reader:

```rust
    assert!(
        node_a_tier.merged_peers(&bucket, window_start) > 0,
        "node A must see node B and C's counts, or this is a write-only CRDT"
    );
```

- [ ] **Step 3: Run**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-core --test rate_limit_mesh_convergence
```

- [ ] **Step 4: Commit**

```bash
git add crates/sbproxy-core/tests/rate_limit_mesh_convergence.rs
git commit -m "test(core): prove three mesh nodes admit near the configured limit"
```

---

### Task 7: Delete the dead sliding-window CRDT

213 lines, zero readers, no re-export from `lib.rs`. Governance slots are the chosen substrate, so leaving a second unread mergeable counter is exactly what #722 removed.

**Files:**
- Delete: `crates/sbproxy-mesh/src/state/sliding_window.rs`
- Modify: `crates/sbproxy-mesh/src/state/mod.rs:9` (drop `pub mod sliding_window;`)

- [ ] **Step 1: Confirm it is still unreferenced**

```bash
grep -rn "SlidingWindow\|sliding_window" crates/ --include="*.rs" | grep -v "state/sliding_window.rs"
```

Expected: only the `state/mod.rs:9` declaration. If anything else appears, stop and reassess.

- [ ] **Step 2: Delete and build**

```bash
git rm crates/sbproxy-mesh/src/state/sliding_window.rs
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-mesh --lib
cargo clippy -p sbproxy-mesh --all-targets -- -D warnings
```

- [ ] **Step 3: Commit**

```bash
git add crates/sbproxy-mesh/src/state/mod.rs
git commit -m "refactor(mesh): delete the unread sliding-window CRDT"
```

---

### Task 8: invalidate_all propagates cluster-wide

Fixes two bugs at once. Clustered mode's cache is `node.distributed_cache()`, the node-wide cache, so `purge_all_local()` discards every unrelated entry locally while never reaching peers.

**Files:**
- Modify: `crates/sbproxy-core/src/mesh_cache.rs:181-185`, plus the `Backing::Clustered` variant to carry the peer list
- Test: inline tests

**Interfaces:**
- Consumes: `TransportClient::purge_prefix(prefix: String) -> anyhow::Result<u64>` (`transport/client.rs:380`), `node_handle.rs:215 peers() -> &[String]`

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test]
    async fn invalidate_all_purges_only_key_plane_prefixes_locally() {
        let node = MeshNode::new("purge-a".into(), vec![], MESH_VNODES);
        let cache = node.distributed_cache();
        // An unrelated entry in the node-wide cache must survive.
        cache.put_local_with_ttl("compression:session:s1", Bytes::from("keep"), 60);

        let tier = MeshCacheTier::clustered(&node);
        let rec = KeyRecord::new("k1", "h1", Utc::now());
        tier.put_key(&rec, Duration::from_secs(60)).await;

        tier.invalidate_all().await;

        assert!(tier.get_key("k1").await.is_none(), "key-plane entry purged");
        assert!(
            cache.get_local("compression:session:s1").is_some(),
            "invalidate_all must not nuke the whole node-wide cache"
        );
    }
```

- [ ] **Step 2: Run to verify failure**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-core --lib mesh_cache::
```

Expected: FAIL, the unrelated entry is gone because `purge_all_local` cleared everything.

- [ ] **Step 3: Implement the prefix-scoped fan-out**

```rust
    async fn invalidate_all(&self) {
        // Scope the purge to the key-plane prefixes. In clustered mode the
        // backing cache is the node-wide distributed cache, so purging
        // everything would discard unrelated entries. Purge is cluster-wide
        // rather than consistent-hash-routed, so every peer is contacted.
        for prefix in [KEY_PREFIX, CRED_PREFIX] {
            match &self.backing {
                Backing::Local(c) => {
                    c.purge_prefix_local(prefix);
                }
                Backing::Clustered {
                    cache,
                    pool,
                    peer_addr,
                    peers,
                } => {
                    cache.purge_prefix_local(prefix);
                    for peer in peers.iter() {
                        let Some(addr) = peer_addr(peer) else { continue };
                        let client = pool.client_for(&addr);
                        if let Err(error) = client.purge_prefix(prefix.to_string()).await {
                            tracing::warn!(
                                %peer, %error,
                                "mesh cache purge fan-out failed for a peer; it will \
                                 keep stale entries until TTL"
                            );
                        }
                    }
                }
            }
        }
    }
```

Extend `Backing::Clustered` with `peers: Vec<String>` populated from `node.peers().to_vec()` in `clustered`. Confirm the pool accessor name first:

```bash
grep -n "pub fn client_for\|pub async fn client_for\|pub fn get" crates/sbproxy-mesh/src/transport/client.rs
```

- [ ] **Step 4: Run to verify pass**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-core --lib mesh_cache::
cargo clippy -p sbproxy-core --all-targets -- -D warnings
```

- [ ] **Step 5: Commit**

```bash
git add crates/sbproxy-core/src/mesh_cache.rs
git commit -m "fix(core): scope bulk cache purge to the key plane and fan it out to peers"
```

---

### Task 9: Boot refuses a clustered deployment with an unshareable keystore

**Files:**
- Modify: `crates/sbproxy-config/src/cluster.rs` (validation lives beside the existing `security.shared_key` check at `:600`)
- Test: inline tests

- [ ] **Step 1: Find where clustering and keystore config meet**

```bash
grep -rn "keystore\|key_management" crates/sbproxy-config/src/cluster.rs crates/sbproxy-config/src/validate.rs | head -15
```

- [ ] **Step 2: Write the failing test**

```rust
    #[test]
    fn clustered_deployment_rejects_an_unshareable_keystore() {
        let err = validate_cluster_keystore(/* clustered */ true, "embedded")
            .expect_err("embedded redb cannot be shared across nodes");
        let msg = err.to_string();
        assert!(msg.contains("embedded"), "names the offending backend");
        assert!(
            msg.contains("redis") || msg.contains("secrets_manager"),
            "names an actionable fix"
        );
    }

    #[test]
    fn clustered_deployment_accepts_a_shared_keystore() {
        assert!(validate_cluster_keystore(true, "redis").is_ok());
        assert!(validate_cluster_keystore(true, "secrets_manager").is_ok());
    }

    #[test]
    fn a_single_node_deployment_accepts_the_embedded_keystore() {
        assert!(validate_cluster_keystore(false, "embedded").is_ok());
    }
```

- [ ] **Step 3: Implement**

```rust
/// Reject a clustered deployment whose keystore is node-local.
///
/// `MeshCacheTier` caches in front of the keystore; it is not a system of
/// record. With a node-local keystore a key minted on one node is written
/// only to that node, so peers cannot resolve it whether or not it is
/// cached. Failing at boot beats minting keys that silently do not work
/// on the rest of the cluster.
fn validate_cluster_keystore(clustered: bool, backend: &str) -> anyhow::Result<()> {
    if !clustered {
        return Ok(());
    }
    if matches!(backend, "embedded" | "memory") {
        anyhow::bail!(
            "clustering is enabled but the '{backend}' keystore is node-local, so a key \
             minted on one node cannot be resolved by its peers. Set the keystore backend \
             to 'redis' or 'secrets_manager', or disable clustering if per-node keys are \
             intended."
        );
    }
    Ok(())
}
```

Call it from the same boot validation path as the neighbouring cluster checks.

- [ ] **Step 4: Run**

```bash
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-config --lib cluster::
cargo clippy -p sbproxy-config --all-targets -- -D warnings
```

- [ ] **Step 5: Check the config schema, which the local gate skips**

```bash
./scripts/check-config-schema.sh
```

- [ ] **Step 6: Commit**

```bash
git add crates/sbproxy-config/src/cluster.rs
git commit -m "feat(config): refuse a clustered deployment whose keystore is node-local"
```

---

### Task 10: Docs state what converges and by how much

**Files:**
- Modify: `docs/enterprise.md` (remove the unqualified minting claim)
- Modify: the clustering doc (find it first)
- Modify: `docs/configuration.md` (the rate-limit section)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Find the claims to correct**

```bash
grep -rn "minted on one replica\|revocation on one\|without an external\|no external database" docs/*.md | head -20
ls docs/ | grep -i "clust\|mesh"
```

- [ ] **Step 2: Write the corrections**

State plainly: credential purge is cluster-wide; per-minute rate limits converge approximately with overshoot bounded by `(N - 1) * rate * cadence` at a 3 second default cadence; per-second rate limits are enforced per node; minting on any node requires a shared keystore, and boot refuses a clustered deployment without one. Include the worked 600 rpm numbers so the bound is concrete.

No `WOR-NNNN` references in any of these files.

- [ ] **Step 3: Check no doc test pins the old strings**

```bash
grep -rn "minted on one replica" crates/ --include="*.rs"
CARGO_BUILD_JOBS=2 cargo test -p sbproxy-capability --lib
```

- [ ] **Step 4: Commit**

```bash
git add docs/ CHANGELOG.md
git commit -m "docs: state which cluster state converges, by what mechanism, and with what bound"
```

---

### Task 11: Full gate

- [ ] **Step 1: Sync with main before gating**

```bash
git fetch origin && git merge origin/main
```

- [ ] **Step 2: Format first, since it is the gate's first step**

```bash
cargo fmt --all
```

- [ ] **Step 3: Run the gate, capturing the real exit code without a pipe**

```bash
./scripts/check.sh > /tmp/gate-wor2062.log 2>&1; echo "REAL_EXIT=$?"
```

- [ ] **Step 4: Verify from the log file**

```bash
grep -c "FAILED" /tmp/gate-wor2062.log
grep "All checks passed" /tmp/gate-wor2062.log
grep "nextest" /tmp/gate-wor2062.log | head -3
```

Require `REAL_EXIT=0`, `All checks passed` present, zero `FAILED`, and the nextest banner confirming the fast runner was used. A per-crate clippy failure is not a red main; fix it.

- [ ] **Step 5: Open the PR**

Base the PR on `main`, never on another feature branch. No Claude Code attribution in the body. No `WOR-NNNN` in the body.

---

## Self-Review

**Spec coverage:** Decision written (spec, committed). Cluster-wide enforcement proven by Task 6. Divergence metric in Task 3. `invalidate_all` in Task 8. Keystore guard in Task 9. Docs in Task 10. Per-second caveat in Tasks 2 and 5. Dead CRDT removed in Task 7. All six acceptance criteria are covered.

**Type consistency:** `increment_local`, `merged_peers`, `local_slots`, `set_peer_counters`, `evict_before`, `node_id` are defined in Task 1 and used with those exact names in Tasks 2, 4 and 6. `with_cluster` and `converges_on_mesh` are defined in Task 2 and used in Task 5. `RATE_LIMIT_POLICY_REVISION` is defined in Task 1 and used in Tasks 2 and 4.

**Known unknowns to resolve during execution, each with a lookup step in its task:** the transport pool's client accessor name (Task 8 Step 3), the exact metric registration pattern and dashboard file (Task 3 Step 1), the clustering doc filename (Task 10 Step 1), and where cluster validation is invoked at boot (Task 9 Step 1).
