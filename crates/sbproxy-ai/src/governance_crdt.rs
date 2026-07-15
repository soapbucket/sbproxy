//! Cross-node approximate counters. Each node owns one slot per
//! (key, policy revision, window); the cluster value is the sum of the
//! newest slot from every node. This is a grow-only counter merged by
//! last-generation-wins per node, which is monotonic within a window.

use crate::governance::GovernanceUsage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One node's counted usage for a single (key, revision, window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCounterSlot {
    /// Immutable, non-secret governed key identifier.
    pub key_id: String,
    /// Effective policy revision the slot was counted under.
    pub policy_revision: u64,
    /// Fixed-window start instant in Unix milliseconds.
    pub window_start_millis: u64,
    /// Usage this node counted locally for the slot.
    pub usage: GovernanceUsage,
}

/// One node's published counter state at a generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceContribution {
    /// Publishing node identifier.
    pub node_id: String,
    /// Monotonic generation; higher replaces lower for the same node.
    pub generation: u64,
    /// Every live slot this node currently counts.
    pub slots: Vec<NodeCounterSlot>,
}

/// Read-optimized merge of peer contributions.
#[derive(Debug, Default, Clone)]
pub struct MergedCounters {
    sums: HashMap<(String, u64, u64), GovernanceUsage>,
}

impl MergedCounters {
    /// Cluster-summed usage for one (key, revision, window), zero if absent.
    pub fn merged_usage(
        &self,
        key_id: &str,
        policy_revision: u64,
        window_start_millis: u64,
    ) -> GovernanceUsage {
        self.sums
            .get(&(key_id.to_string(), policy_revision, window_start_millis))
            .copied()
            .unwrap_or_default()
    }
}

/// Sum the newest contribution from each node into a read-optimized view.
pub fn merge_contributions(
    peers: impl IntoIterator<Item = GovernanceContribution>,
) -> MergedCounters {
    let mut newest: HashMap<String, GovernanceContribution> = HashMap::new();
    for c in peers {
        match newest.get(&c.node_id) {
            Some(existing) if existing.generation >= c.generation => {}
            _ => {
                newest.insert(c.node_id.clone(), c);
            }
        }
    }
    let mut sums: HashMap<(String, u64, u64), GovernanceUsage> = HashMap::new();
    for c in newest.into_values() {
        for slot in c.slots {
            let entry = sums
                .entry((slot.key_id, slot.policy_revision, slot.window_start_millis))
                .or_default();
            entry.requests = entry.requests.saturating_add(slot.usage.requests);
            entry.tokens = entry.tokens.saturating_add(slot.usage.tokens);
            entry.micro_usd = entry.micro_usd.saturating_add(slot.usage.micro_usd);
        }
    }
    MergedCounters { sums }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::GovernanceUsage;

    fn slot(key: &str, rev: u64, win: u64, r: u64, t: u64, c: u64) -> NodeCounterSlot {
        NodeCounterSlot {
            key_id: key.to_string(),
            policy_revision: rev,
            window_start_millis: win,
            usage: GovernanceUsage {
                requests: r,
                tokens: t,
                micro_usd: c,
            },
        }
    }

    #[test]
    fn cluster_usage_is_the_sum_of_per_node_slots() {
        let a = GovernanceContribution {
            node_id: "a".into(),
            generation: 1,
            slots: vec![slot("k1", 7, 60_000, 3, 300, 30)],
        };
        let b = GovernanceContribution {
            node_id: "b".into(),
            generation: 1,
            slots: vec![slot("k1", 7, 60_000, 5, 500, 50)],
        };
        let merged = merge_contributions([a, b]);
        let u = merged.merged_usage("k1", 7, 60_000);
        assert_eq!(u.requests, 8);
        assert_eq!(u.tokens, 800);
        assert_eq!(u.micro_usd, 80);
    }

    #[test]
    fn a_later_generation_replaces_an_earlier_one_for_the_same_node() {
        let old = GovernanceContribution {
            node_id: "a".into(),
            generation: 1,
            slots: vec![slot("k1", 7, 60_000, 9, 0, 0)],
        };
        let new = GovernanceContribution {
            node_id: "a".into(),
            generation: 2,
            slots: vec![slot("k1", 7, 60_000, 2, 0, 0)],
        };
        let merged = merge_contributions([old, new]);
        assert_eq!(merged.merged_usage("k1", 7, 60_000).requests, 2);
    }

    #[test]
    fn slots_from_other_windows_or_revisions_do_not_leak_in() {
        let a = GovernanceContribution {
            node_id: "a".into(),
            generation: 1,
            slots: vec![
                slot("k1", 7, 60_000, 4, 0, 0),
                slot("k1", 7, 120_000, 99, 0, 0),
                slot("k1", 8, 60_000, 99, 0, 0),
            ],
        };
        let merged = merge_contributions([a]);
        assert_eq!(merged.merged_usage("k1", 7, 60_000).requests, 4);
    }
}
