// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cross-node dissemination of rate-limit counters.
//!
//! The rate-limit policy distributes through its L2 store only, so on a
//! gossip-mesh cluster with no Redis every node limited independently: 600 rpm
//! configured on three nodes admitted roughly 1800 rpm, and nothing told the
//! operator the limit it was enforcing was per-node.
//!
//! This module closes that gap the same way [`crate::governance_cluster`]
//! closes it for governed-key spend. Each node periodically publishes a
//! compact snapshot of its own counter slots through the process-wide cluster
//! handle, and merges every live peer's snapshot back into the tier the policy
//! reads on the request path.
//!
//! It mirrors `governance_cluster::run_loop` structurally: tokio interval,
//! monotonic generation, publish then collect-live-members then `read_state`
//! each tick, with this node's own contribution excluded from the merged view
//! because the tier already counts local requests directly.
//!
//! # Convergence model
//!
//! Enforcement is approximate by construction. A node admits against its own
//! immediate count plus a peer view that is at most one cadence stale, so the
//! cluster over-admits by at most `(N - 1) * rate * cadence`. At the default 3
//! second cadence a 600 rpm limit across three nodes admits about 660 rather
//! than 1800. The bound is documented in `docs/enterprise.md` and observable
//! through the peer-count metric, because an approximation an operator cannot
//! see is worse than an honest one they can.
//!
//! # One tier per process
//!
//! A single tier is shared by every origin, with bucket strings namespaced by
//! origin through the policy's `key_prefix`. That keeps one publish loop for
//! the whole process and, more importantly, means a config reload does not
//! reset counters: the policy objects are rebuilt on reload, but the tier they
//! attach to outlives them.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use sbproxy_mesh::{ClusterHandle, ClusterMemberState, ClusterStateRead};
use sbproxy_modules::policy::rate_limit_cluster::RateLimitClusterTier;

use sbproxy_ai::governance_crdt::{merge_contributions, GovernanceContribution, MergedCounters};

/// Cluster state namespace for published rate-limit contributions. Distinct
/// from the governance namespace so rate slots and spend slots never mix.
const RATE_LIMIT_STATE_NAMESPACE: &str = "rate-limit-counters";

/// Schema version for the contribution payload as published to the mesh.
const RATE_LIMIT_STATE_SCHEMA_VERSION: u32 = 1;

/// Default dissemination cadence in seconds.
///
/// Shorter than governance's 15s on purpose. Governance guards spend, where
/// the window is long and overshoot costs money; a rate limit is a promise
/// about a 60 second window, so it needs several exchanges inside one window
/// to keep the overshoot near five percent per added node.
pub(crate) const DEFAULT_RATE_LIMIT_CADENCE_SECS: u64 = 3;

/// The process-wide tier, created once and shared by every origin.
static PROCESS_TIER: OnceLock<Arc<RateLimitClusterTier>> = OnceLock::new();

/// The process-wide rate-limit cluster tier, initialised on first use.
///
/// Shared across origins and across config reloads so counters survive both.
/// `node_id` is only honoured on the first call, which is the boot call.
pub(crate) fn process_tier(node_id: &str) -> Arc<RateLimitClusterTier> {
    PROCESS_TIER
        .get_or_init(|| Arc::new(RateLimitClusterTier::new(node_id)))
        .clone()
}

/// The process-wide tier, but only when this node is actually clustered.
///
/// Returns `None` for a single-node deployment or during `sbproxy validate`,
/// where there is no mesh to converge with and the policy should keep using
/// its local token bucket.
pub(crate) fn tier_if_clustered() -> Option<Arc<RateLimitClusterTier>> {
    let handle = crate::cluster::current_cluster_handle()?;
    handle.mesh_node()?;
    Some(process_tier(&handle.identity().node_id))
}

/// Merge every peer contribution except this node's own.
///
/// Excluding self is required: the tier counts local requests directly, so a
/// self-slot here would double-count this node against its own limit.
fn merged_peer_view(my_id: &str, contributions: Vec<GovernanceContribution>) -> MergedCounters {
    merge_contributions(contributions.into_iter().filter(|c| c.node_id != my_id))
}

/// Publish this node's rate-limit slots and merge every live peer's slots into
/// `tier`, forever, on the given cadence. Failures are skipped; the next tick
/// republishes.
pub(crate) async fn run_loop(
    handle: ClusterHandle,
    tier: Arc<RateLimitClusterTier>,
    interval_secs: u64,
) {
    let mut generation = generation_seed();
    let mut tick_timer = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        tick_timer.tick().await;
        generation = generation.saturating_add(1);
        tick(&handle, tier.as_ref(), generation, interval_secs).await;
    }
}

/// One publish-then-collect cycle.
async fn tick(
    handle: &ClusterHandle,
    tier: &RateLimitClusterTier,
    generation: u64,
    interval_secs: u64,
) {
    let my_id = handle.identity().node_id.clone();
    let cadence = interval_secs.max(1);
    let ttl = Duration::from_secs(cadence.saturating_mul(3));

    let contribution = GovernanceContribution {
        node_id: my_id.clone(),
        generation,
        slots: tier.local_slots(),
    };
    if let Err(error) = handle
        .publish_state(
            RATE_LIMIT_STATE_NAMESPACE,
            &my_id,
            RATE_LIMIT_STATE_SCHEMA_VERSION,
            generation,
            ttl,
            &contribution,
        )
        .await
    {
        tracing::debug!(%error, "rate-limit-counters: publish failed (retry next tick)");
    }

    let live: Vec<_> = handle
        .membership()
        .into_iter()
        .filter(|m| m.node_id == my_id || m.state == ClusterMemberState::Alive)
        .collect();
    let mut contributions = Vec::new();
    for member in &live {
        if member.node_id == my_id {
            continue; // local counts are held by the tier directly
        }
        if let ClusterStateRead::Present(record) = handle
            .read_state::<GovernanceContribution>(
                RATE_LIMIT_STATE_NAMESPACE,
                &member.node_id,
                RATE_LIMIT_STATE_SCHEMA_VERSION,
            )
            .await
        {
            contributions.push(record.payload);
        }
    }
    tier.set_peer_counters(merged_peer_view(&my_id, contributions));

    // Drop local slots for windows that closed before any live peer could
    // still be reporting them. Without this a long-lived process accumulates
    // one slot per window forever and republishes them all every tick.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    tier.evict_before(now_secs.saturating_sub(ttl.as_secs().saturating_mul(2)));
}

/// A coarse, monotonic-enough starting generation derived from wall-clock
/// time, so a restarted node's first publish still outranks any stale record
/// a peer might still hold from before the restart.
fn generation_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_ai::governance::GovernanceUsage;
    use sbproxy_ai::governance_crdt::NodeCounterSlot;
    use sbproxy_modules::policy::rate_limit_cluster::RATE_LIMIT_POLICY_REVISION;

    fn slot(bucket: &str, window_start_millis: u64, requests: u64) -> NodeCounterSlot {
        NodeCounterSlot {
            key_id: bucket.to_string(),
            policy_revision: RATE_LIMIT_POLICY_REVISION,
            window_start_millis,
            usage: GovernanceUsage {
                requests,
                tokens: 0,
                micro_usd: 0,
            },
        }
    }

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
            merged
                .merged_usage("b1", RATE_LIMIT_POLICY_REVISION, 60_000)
                .requests,
            5,
            "this node's own 100 is counted locally, so merging it again would double-count"
        );
    }

    #[test]
    fn merged_peer_view_sums_every_peer() {
        let b = GovernanceContribution {
            node_id: "b".into(),
            generation: 1,
            slots: vec![slot("b1", 60_000, 4)],
        };
        let c = GovernanceContribution {
            node_id: "c".into(),
            generation: 1,
            slots: vec![slot("b1", 60_000, 6)],
        };
        let merged = merged_peer_view("self", vec![b, c]);
        assert_eq!(
            merged
                .merged_usage("b1", RATE_LIMIT_POLICY_REVISION, 60_000)
                .requests,
            10
        );
    }

    #[test]
    fn process_tier_is_stable_across_calls() {
        // Reload rebuilds the policies, so the tier must outlive them or every
        // reload would silently reset the cluster's counters.
        let first = process_tier("node-a");
        first.increment_local("bucket", 60);
        let second = process_tier("ignored-on-second-call");
        assert_eq!(second.node_id(), "node-a");
        assert_eq!(
            second.local_slots().len(),
            1,
            "the same tier must come back, counts intact"
        );
    }

    #[test]
    fn the_default_cadence_keeps_a_per_minute_overshoot_near_five_percent() {
        // Documented bound: (N - 1) * rate * cadence. This pins the constant
        // to the promise made in the docs.
        let rate_per_sec = 10.0; // 600 rpm
        let overshoot = 2.0 * rate_per_sec * DEFAULT_RATE_LIMIT_CADENCE_SECS as f64;
        assert_eq!(overshoot, 60.0, "three nodes overshoot 600 rpm by 60");
        assert!(overshoot / 600.0 <= 0.1);
    }
}
