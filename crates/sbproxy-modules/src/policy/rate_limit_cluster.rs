// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cluster tier for the rate-limit policy.
//!
//! Holds this node's per-window counts and the merged, self-excluded view of
//! every live peer. The dissemination loop in `sbproxy-core` publishes
//! [`RateLimitClusterTier::local_slots`] and installs peer contributions
//! through [`RateLimitClusterTier::set_peer_counters`]; the policy reads
//! [`RateLimitClusterTier::merged_peers`] on the request path.
//!
//! # Why the governance CRDT and not a new one
//!
//! `sbproxy-ai`'s governance counters already solve this exact problem:
//! per-node slots keyed by `(key_id, policy_revision, window)`, merged with
//! last-generation-wins per node and summed across nodes. Reusing them keeps
//! one mergeable-counter shape in the tree instead of two. Rate-limit slots
//! travel on their own cluster-state namespace, so they never mix with
//! governed-key spend slots.
//!
//! # Convergence model
//!
//! Each node admits against its own immediate count plus a peer view that is
//! at most one dissemination cadence stale, so the cluster over-admits by at
//! most `(peers) * rate * cadence`. That bound is the deliberate trade for
//! not needing a shared database. Per-second limits are not reconciled here
//! at all: a one second window closes before a peer contribution can arrive.

use std::collections::HashMap;
use std::sync::RwLock;

use sbproxy_ai::governance::GovernanceUsage;
use sbproxy_ai::governance_crdt::{MergedCounters, NodeCounterSlot};

/// Rate-limit slots do not carry a policy revision. The limit is read from
/// live config on every request, so there is no revision to pin a slot to.
pub const RATE_LIMIT_POLICY_REVISION: u64 = 0;

/// This node's rate-limit counts plus the merged view of its peers.
pub struct RateLimitClusterTier {
    node_id: String,
    /// `(bucket, window_start_secs) -> count` counted by this node alone.
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

    /// Count one request against `bucket` in `window_start_secs`, returning
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

    /// The peer-contributed count for one slot, this node excluded.
    ///
    /// Zero when peers have not reported the slot, which is also what a
    /// partitioned node sees once its peer view expires. That fails toward
    /// admitting rather than denying, matching the policy's fail-open
    /// posture for its Redis path.
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

    /// Every live local slot, shaped for publication to peers.
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

    /// Install a freshly merged peer view, replacing the previous one.
    pub fn set_peer_counters(&self, merged: MergedCounters) {
        match self.peers.write() {
            Ok(mut g) => *g = merged,
            Err(poisoned) => *poisoned.into_inner() = merged,
        }
    }

    /// Drop local slots for windows that started before `oldest_window_secs`,
    /// so a long-lived process does not accumulate one entry per window
    /// forever. The dissemination loop calls this each tick.
    pub fn evict_before(&self, oldest_window_secs: u64) {
        let mut guard = match self.local.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|(_, window_start), _| *window_start >= oldest_window_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_ai::governance_crdt::{merge_contributions, GovernanceContribution};

    fn peer_slot(bucket: &str, window_start_secs: u64, requests: u64) -> NodeCounterSlot {
        NodeCounterSlot {
            key_id: bucket.to_string(),
            policy_revision: RATE_LIMIT_POLICY_REVISION,
            window_start_millis: window_start_secs * 1000,
            usage: GovernanceUsage {
                requests,
                tokens: 0,
                micro_usd: 0,
            },
        }
    }

    #[test]
    fn increment_local_accumulates_per_bucket_and_window() {
        let tier = RateLimitClusterTier::new("node-a");
        assert_eq!(tier.increment_local("ip:1.2.3.4", 60), 1);
        assert_eq!(tier.increment_local("ip:1.2.3.4", 60), 2);
        // A different window is a different slot.
        assert_eq!(tier.increment_local("ip:1.2.3.4", 120), 1);
        // A different bucket is a different slot.
        assert_eq!(tier.increment_local("ip:5.6.7.8", 60), 1);
        assert_eq!(tier.node_id(), "node-a");
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
            slots: vec![peer_slot("ip:1.2.3.4", 60, 7)],
        };
        tier.set_peer_counters(merge_contributions([peer]));

        assert_eq!(tier.merged_peers("ip:1.2.3.4", 60), 7);
        // The local count stays separate from the peer view, so the policy
        // can add them rather than double-counting this node.
        assert_eq!(tier.increment_local("ip:1.2.3.4", 60), 1);
        assert_eq!(tier.merged_peers("ip:1.2.3.4", 60), 7);
        // A window the peers did not report reads zero, not a stale value.
        assert_eq!(tier.merged_peers("ip:1.2.3.4", 120), 0);
    }

    #[test]
    fn merged_peers_sums_every_reporting_peer() {
        let tier = RateLimitClusterTier::new("node-a");
        let b = GovernanceContribution {
            node_id: "node-b".into(),
            generation: 1,
            slots: vec![peer_slot("ip:1.2.3.4", 60, 4)],
        };
        let c = GovernanceContribution {
            node_id: "node-c".into(),
            generation: 1,
            slots: vec![peer_slot("ip:1.2.3.4", 60, 6)],
        };
        tier.set_peer_counters(merge_contributions([b, c]));
        assert_eq!(tier.merged_peers("ip:1.2.3.4", 60), 10);
    }

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
}
