// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! What a cluster-wide total is allowed to claim about itself.
//!
//! Summing over the nodes that happened to answer and presenting the
//! result as the cluster total is the defect this module exists to
//! prevent. It is not a rounding error. A node dying makes the number go
//! down, every figure on the resulting dashboard still looks plausible, and
//! nobody finds out for a quarter because there is no signal anywhere
//! saying the number was assembled from an incomplete set.
//!
//! So a total never travels alone. Every
//! [`crate::coverage::ClusterUsageSummary`] carries a
//! [`crate::coverage::MeterCoverage`] naming which nodes are inside it and
//! which are not, and [`crate::coverage::ClusterUsageSummary::is_partial`]
//! is the one question a caller has to answer before quoting the figure.
//!
//! # A missing node reports a number, not a zero
//!
//! An unreachable node has not stopped metering. Its chain is still on its
//! own disk, or already exported to its sink, and it will still be there
//! when the node comes back. Reporting it as zero, or dropping it from the
//! report entirely, describes a state of the world that has never existed.
//!
//! [`crate::coverage::LastKnownHeads`] keeps the last head every node was
//! ever seen at and never evicts, so the honest line is available: "node-3
//! unreachable, last known seq 48213". Compare that with an aggregator that
//! retains only nodes in the caller's live view, which is correct for
//! autoscaling and silently wrong for billing.
//!
//! # The last known value is reported beside the total, never inside it
//!
//! Adding an unreachable node's last known units back into the sum was
//! considered and rejected. It produces an estimate wearing the clothes of
//! a count: the figure would look complete, would be labelled complete by
//! anything downstream that reads only the number, and would be wrong by
//! however much that node metered while nobody was watching. A total is
//! either a count of what was gathered or it is not a total.
//!
//! So [`crate::coverage::ClusterUsageSummary::totals`] sums the segments it
//! actually holds, and [`crate::coverage::UncoveredNode::last_known_seq`]
//! sits next to it in the coverage block. Nothing folds one into the other.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::segment::{ChainSegment, UnitTotal};

/// Why one node's units are outside a cluster total.
///
/// A closed set rather than a free-text reason, because the reason drives
/// what an operator should do next and a string would let a new gather path
/// invent a category nobody has a runbook for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGap {
    /// The node is in the membership view and has never reported a segment.
    ///
    /// Normal for a node that joined seconds ago and has not published yet.
    /// Persistent means the node is running a build that does not publish,
    /// or its publish is failing.
    NeverReported,
    /// The node's last report is older than the gather is willing to treat
    /// as current.
    ///
    /// The distinction from [`CoverageGap::Unreachable`] is worth keeping:
    /// stale means something answered and the answer was old, which usually
    /// points at a stalled publish loop rather than at the network.
    Stale,
    /// Membership no longer considers the node live.
    ///
    /// A last report may well still be readable. It is not counted anyway,
    /// because a reading taken before the node left describes traffic up to
    /// that point and nothing since, and there is no way to tell from here
    /// which of the two a caller is looking at.
    NotLive,
    /// The node's report could not be fetched at all.
    Unreachable,
    /// A report arrived and could not be used.
    ///
    /// A schema this build cannot read, a malformed payload, or a segment
    /// filed under one node while claiming to describe another. The last of
    /// those is the interesting one: folding it in would merge two chains,
    /// so it is refused rather than repaired.
    Unreadable,
}

impl CoverageGap {
    /// Stable snake-case name, for logs, JSON, and metric label values.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverReported => "never_reported",
            Self::Stale => "stale",
            Self::NotLive => "not_live",
            Self::Unreachable => "unreachable",
            Self::Unreadable => "unreadable",
        }
    }
}

/// One node that is inside the cluster and outside the total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncoveredNode {
    /// The node whose units are missing from the total.
    pub node_id: String,
    /// Why they are missing.
    pub gap: CoverageGap,
    /// The last chain head this node was ever seen reporting.
    ///
    /// The whole reason this type is not just a list of names. A node that
    /// cannot be reached still has a chain, and its length is the one fact
    /// still worth stating about traffic nobody can currently see. `None`
    /// means the node has never been seen at all, which is a different and
    /// much less reassuring statement than "seen, at 48213".
    ///
    /// This number is never added to a total. See the module documentation.
    pub last_known_seq: Option<u64>,
    /// RFC 3339 timestamp of the report [`UncoveredNode::last_known_seq`]
    /// came from, so an operator can tell a node that vanished a minute ago
    /// from one that vanished last week.
    pub last_seen_at: Option<String>,
}

/// Which nodes a cluster total covers, and which it does not.
///
/// Both halves are named. A coverage block that listed only the answering
/// nodes would leave a reader counting names against a membership list they
/// do not have, which is the same as not reporting it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MeterCoverage {
    /// Nodes whose segments are inside the total, sorted.
    pub answered: Vec<String>,
    /// Nodes that are not, sorted by node id, each with what is still known
    /// about it.
    pub uncovered: Vec<UncoveredNode>,
}

impl MeterCoverage {
    /// Build a coverage block, sorting both halves.
    ///
    /// Sorting here rather than at the call site because two gathers of an
    /// unchanged cluster should produce identical documents. Membership
    /// iteration order is not something a caller should have to think about
    /// to get that.
    pub fn new(answered: Vec<String>, uncovered: Vec<UncoveredNode>) -> Self {
        let mut coverage = Self {
            answered,
            uncovered,
        };
        coverage.answered.sort_unstable();
        coverage
            .uncovered
            .sort_by(|left, right| left.node_id.cmp(&right.node_id));
        coverage
    }

    /// Whether every node in the cluster is inside the total.
    pub fn is_complete(&self) -> bool {
        self.uncovered.is_empty()
    }

    /// How many nodes the gather expected to hear from.
    pub fn expected(&self) -> usize {
        self.answered.len().saturating_add(self.uncovered.len())
    }
}

/// The cluster-wide answer: whole segments, and what they do not cover.
///
/// Segments are held whole and never interleaved. The chain each one
/// describes verifies on its own node against its own genesis, and that
/// stays true no matter how many summaries quote it, because a summary
/// quotes heads and totals rather than entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterUsageSummary {
    /// RFC 3339 timestamp at which the gather ran.
    pub gathered_at: String,
    /// One segment per node that answered, sorted by node id.
    pub segments: Vec<ChainSegment>,
    /// What this summary covers and what it does not.
    pub coverage: MeterCoverage,
}

impl ClusterUsageSummary {
    /// Assemble a summary, sorting the segments for a stable document.
    pub fn new(
        gathered_at: impl Into<String>,
        segments: Vec<ChainSegment>,
        coverage: MeterCoverage,
    ) -> Self {
        let mut summary = Self {
            gathered_at: gathered_at.into(),
            segments,
            coverage,
        };
        summary
            .segments
            .sort_by(|left, right| left.node_id.cmp(&right.node_id));
        summary
    }

    /// Whether this total was assembled from fewer than all the nodes.
    ///
    /// The question to answer before quoting [`ClusterUsageSummary::totals`]
    /// anywhere a person will read it as a bill. A partial total is still
    /// useful, and during a rolling restart it is the only kind available,
    /// but it has to say so.
    pub fn is_partial(&self) -> bool {
        !self.coverage.is_complete()
    }

    /// Sum the units across the segments this summary actually holds.
    ///
    /// Only those. An uncovered node's last known head is reported in
    /// [`ClusterUsageSummary::coverage`] and contributes nothing here, on
    /// purpose: carrying it into the sum would turn a count into an
    /// estimate while leaving it looking like a count.
    pub fn totals(&self) -> Vec<UnitTotal> {
        let mut folded: BTreeMap<(&str, &str, crate::event::UnitSource), u64> = BTreeMap::new();
        for segment in &self.segments {
            for total in &segment.totals {
                let key = (total.tenant.as_str(), total.unit.as_str(), total.source);
                let entry = folded.entry(key).or_insert(0);
                *entry = entry.saturating_add(total.count);
            }
        }
        folded
            .into_iter()
            .map(|((tenant, unit, source), count)| UnitTotal {
                tenant: tenant.to_string(),
                unit: unit.to_string(),
                source,
                count,
            })
            .collect()
    }

    /// Distinct claims across the segments this summary holds.
    ///
    /// Summing claim counts across nodes is safe in a way that summing
    /// chains is not: a claim belongs to exactly one node, because the node
    /// that minted it is part of its identity. See
    /// [`crate::segment::ClaimKey`].
    pub fn claims(&self) -> u64 {
        self.segments.iter().fold(0u64, |running, segment| {
            running.saturating_add(segment.claims)
        })
    }
}

/// The last head every node was ever seen at.
///
/// Deliberately unbounded in time: entries are added and updated, never
/// removed. That single property is the difference between this and a fleet
/// metrics aggregator, and it is the whole reason this type exists rather
/// than one being reused. An aggregator that keeps only the nodes in the
/// caller's live view is right for autoscaling, where a departed node's
/// capacity genuinely is gone, and wrong for billing, where a departed
/// node's consumption is not.
///
/// Growth is bounded in practice by the number of distinct node ids a
/// cluster has ever had, and each entry is a node id, a `u64`, and a
/// timestamp. A deployment that churns node ids fast enough for that to
/// matter has a naming problem this type cannot fix, and losing the
/// billing record would be the wrong way to discover it.
#[derive(Debug, Default)]
pub struct LastKnownHeads {
    /// Node id to the last head seen for it.
    inner: parking_lot::Mutex<BTreeMap<String, LastKnownHead>>,
}

/// The last head one node was seen at, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastKnownHead {
    /// Number of entries the node's chain held at that reading.
    pub head_seq: u64,
    /// RFC 3339 timestamp the reading was taken at.
    pub observed_at: String,
}

impl LastKnownHeads {
    /// Start with no memory of any node.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record what a node has just been seen reporting.
    ///
    /// Called for every segment a gather collects, including this node's
    /// own. Nothing is compared or rejected here: the newest reading wins,
    /// because a node that restarted onto a shorter chain has genuinely
    /// done that and pretending otherwise would report a head that no
    /// longer exists.
    pub fn remember(&self, segment: &ChainSegment) {
        self.inner.lock().insert(
            segment.node_id.clone(),
            LastKnownHead {
                head_seq: segment.head_seq,
                observed_at: segment.observed_at.clone(),
            },
        );
    }

    /// What is known about `node_id`, or `None` if it has never been seen.
    pub fn get(&self, node_id: &str) -> Option<LastKnownHead> {
        self.inner.lock().get(node_id).cloned()
    }

    /// Describe a node that is not in the total, filling in what is still
    /// known about it.
    ///
    /// The constructor to prefer over building an
    /// [`crate::coverage::UncoveredNode`] by hand, because it is what makes
    /// "node-3 unreachable, last known seq 48213" the default answer rather
    /// than something a call site has to remember to look up.
    pub fn uncovered(&self, node_id: &str, gap: CoverageGap) -> UncoveredNode {
        let last = self.get(node_id);
        UncoveredNode {
            node_id: node_id.to_string(),
            gap,
            last_known_seq: last.as_ref().map(|known| known.head_seq),
            last_seen_at: last.map(|known| known.observed_at),
        }
    }

    /// How many distinct nodes have ever been seen.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether no node has ever been seen.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Evidence, Unit, UnitSource};
    use crate::segment::{ClaimKey, SegmentRecorder};

    /// A node that has metered `calls` search calls for `tenant`, at head
    /// `head_seq`.
    fn node(node_id: &str, tenant: &str, calls: u64, head_seq: u64) -> ChainSegment {
        let recorder = SegmentRecorder::new(node_id);
        for index in 0..calls {
            recorder.record(
                &ClaimKey::new(node_id, format!("{node_id}-claim-{index}")),
                tenant,
                &[Unit::new(
                    "search_call",
                    1,
                    Evidence::RouteWeight {
                        config_revision: "9f2c41a0be77".to_string(),
                    },
                )],
            );
        }
        recorder.segment(head_seq, format!("head-of-{node_id}"))
    }

    fn search_calls(summary: &ClusterUsageSummary) -> u64 {
        summary
            .totals()
            .iter()
            .filter(|total| total.unit == "search_call")
            .map(|total| total.count)
            .sum()
    }

    #[test]
    fn a_complete_gather_says_so_and_sums_every_node() {
        let segments = vec![
            node("node-1", "acme", 10, 100),
            node("node-2", "acme", 20, 200),
            node("node-3", "acme", 30, 48_213),
        ];
        let coverage = MeterCoverage::new(
            vec![
                "node-3".to_string(),
                "node-1".to_string(),
                "node-2".to_string(),
            ],
            Vec::new(),
        );
        let summary = ClusterUsageSummary::new("2026-08-01T00:00:00Z", segments, coverage);

        assert!(!summary.is_partial());
        assert!(summary.coverage.is_complete());
        assert_eq!(summary.coverage.expected(), 3);
        assert_eq!(
            summary.coverage.answered,
            vec!["node-1", "node-2", "node-3"],
            "the answered list is sorted so two identical gathers produce identical documents"
        );
        assert_eq!(search_calls(&summary), 60);
        assert_eq!(summary.claims(), 60);
    }

    #[test]
    fn killing_a_node_mid_query_reports_its_last_known_seq_and_labels_the_total() {
        // The acceptance case. node-3 is at 48,213 when it dies. The next
        // gather must not report 30 fewer calls as though that were the
        // cluster's total, and must not report node-3's contribution as
        // zero either.
        let heads = LastKnownHeads::new();
        let before: Vec<ChainSegment> = vec![
            node("node-1", "acme", 10, 100),
            node("node-2", "acme", 20, 200),
            node("node-3", "acme", 30, 48_213),
        ];
        for segment in &before {
            heads.remember(segment);
        }
        let complete = ClusterUsageSummary::new(
            "2026-08-01T00:00:00Z",
            before,
            MeterCoverage::new(
                vec![
                    "node-1".to_string(),
                    "node-2".to_string(),
                    "node-3".to_string(),
                ],
                Vec::new(),
            ),
        );
        assert_eq!(search_calls(&complete), 60);
        assert!(!complete.is_partial());

        // node-3 dies. Everything it metered is still on its own disk.
        let after = ClusterUsageSummary::new(
            "2026-08-01T00:01:00Z",
            vec![
                node("node-1", "acme", 10, 100),
                node("node-2", "acme", 20, 200),
            ],
            MeterCoverage::new(
                vec!["node-1".to_string(), "node-2".to_string()],
                vec![heads.uncovered("node-3", CoverageGap::Unreachable)],
            ),
        );

        assert!(
            after.is_partial(),
            "a total gathered while a peer was unreachable is a partial total"
        );
        assert_eq!(after.coverage.expected(), 3, "node-3 is still expected");
        let missing = &after.coverage.uncovered[0];
        assert_eq!(missing.node_id, "node-3");
        assert_eq!(missing.gap, CoverageGap::Unreachable);
        assert_eq!(
            missing.last_known_seq,
            Some(48_213),
            "`node-3 unreachable, last known seq 48213`, never a silent omission"
        );
        assert!(missing.last_seen_at.is_some());

        // The total is smaller, and it is smaller out loud. It is also not
        // quietly topped up with node-3's last known figures, which would
        // be an estimate wearing the clothes of a count.
        assert_eq!(search_calls(&after), 30);
        assert!(
            search_calls(&after) < search_calls(&complete),
            "the shrink is real; `is_partial` is what stops it being silent"
        );
    }

    #[test]
    fn a_node_never_seen_reports_no_seq_rather_than_a_zero_one() {
        // `None` and `Some(0)` are different statements. `Some(0)` says a
        // node reported an empty chain; `None` says nobody has ever heard
        // from it. Reading the first as the second hides a node that has
        // been silently failing to publish since it joined.
        let heads = LastKnownHeads::new();
        assert!(heads.is_empty());

        let never = heads.uncovered("node-9", CoverageGap::NeverReported);
        assert_eq!(never.last_known_seq, None);
        assert_eq!(never.last_seen_at, None);

        heads.remember(&node("node-8", "acme", 0, 0));
        let empty_chain = heads.uncovered("node-8", CoverageGap::Unreachable);
        assert_eq!(empty_chain.last_known_seq, Some(0));
        assert_eq!(heads.len(), 1);
    }

    #[test]
    fn a_rolling_restart_keeps_returning_usable_partial_totals() {
        // Three nodes, restarted one at a time. At every step the total is
        // usable, the coverage names exactly who is down, and the down
        // node's last known seq is still reported.
        let heads = LastKnownHeads::new();
        let fleet = [
            ("node-1", 10u64, 100u64),
            ("node-2", 20, 200),
            ("node-3", 30, 48_213),
        ];
        for (node_id, calls, head_seq) in fleet {
            heads.remember(&node(node_id, "acme", calls, head_seq));
        }

        for (restarting, restarting_calls, restarting_head) in fleet {
            let segments: Vec<ChainSegment> = fleet
                .iter()
                .filter(|(node_id, _, _)| *node_id != restarting)
                .map(|(node_id, calls, head_seq)| node(node_id, "acme", *calls, *head_seq))
                .collect();
            let answered: Vec<String> = segments
                .iter()
                .map(|segment| segment.node_id.clone())
                .collect();
            let summary = ClusterUsageSummary::new(
                "2026-08-01T00:02:00Z",
                segments,
                MeterCoverage::new(
                    answered,
                    vec![heads.uncovered(restarting, CoverageGap::NotLive)],
                ),
            );

            assert!(summary.is_partial(), "{restarting} is down and it says so");
            assert_eq!(summary.coverage.answered.len(), 2);
            assert_eq!(summary.coverage.expected(), 3);
            assert_eq!(summary.coverage.uncovered[0].node_id, restarting);
            assert_eq!(
                summary.coverage.uncovered[0].last_known_seq,
                Some(restarting_head),
                "a restarting node's chain is still on its own disk"
            );
            assert_eq!(
                search_calls(&summary),
                60 - restarting_calls,
                "the surviving nodes' units, and only those"
            );
        }
    }

    #[test]
    fn totals_fold_across_nodes_without_folding_tenants_or_provenance() {
        let measured = |node_id: &str, count: u64| {
            let recorder = SegmentRecorder::new(node_id);
            recorder.record(
                &ClaimKey::new(node_id, "claim-1"),
                "acme",
                &[Unit::new(
                    "egress_kib",
                    count,
                    Evidence::Measured {
                        bytes_in: 1,
                        bytes_out: count * 1024,
                        duration_ms: 1,
                    },
                )],
            );
            recorder.record(
                &ClaimKey::new(node_id, "claim-2"),
                "globex",
                &[Unit::new(
                    "egress_kib",
                    count,
                    Evidence::RouteWeight {
                        config_revision: "9f2c41a0be77".to_string(),
                    },
                )],
            );
            recorder.segment(2, "head")
        };

        let summary = ClusterUsageSummary::new(
            "2026-08-01T00:00:00Z",
            vec![measured("node-1", 5), measured("node-2", 7)],
            MeterCoverage::new(vec!["node-1".to_string(), "node-2".to_string()], Vec::new()),
        );

        let totals = summary.totals();
        assert_eq!(totals.len(), 2, "one line per tenant and provenance");
        assert_eq!(
            totals
                .iter()
                .map(|total| (total.tenant.as_str(), total.source, total.count))
                .collect::<Vec<_>>(),
            vec![
                ("acme", UnitSource::Measured, 12),
                ("globex", UnitSource::RouteWeight, 12)
            ]
        );
    }

    #[test]
    fn the_newest_reading_of_a_node_wins() {
        // A node that restarted onto a shorter chain has genuinely done
        // that. Holding the older, longer head would report a chain
        // position that no longer exists.
        let heads = LastKnownHeads::new();
        heads.remember(&node("node-1", "acme", 10, 48_213));
        heads.remember(&node("node-1", "acme", 1, 4));

        assert_eq!(heads.get("node-1").expect("seen").head_seq, 4);
        assert_eq!(heads.len(), 1);
    }

    #[test]
    fn a_summary_round_trips_through_json_unchanged() {
        let heads = LastKnownHeads::new();
        heads.remember(&node("node-3", "acme", 30, 48_213));
        let summary = ClusterUsageSummary::new(
            "2026-08-01T00:00:00Z",
            vec![node("node-1", "acme", 10, 100)],
            MeterCoverage::new(
                vec!["node-1".to_string()],
                vec![heads.uncovered("node-3", CoverageGap::Unreachable)],
            ),
        );

        let json = serde_json::to_string(&summary).expect("summary serialises");
        let back: ClusterUsageSummary = serde_json::from_str(&json).expect("summary deserialises");

        assert_eq!(back, summary);
        assert!(back.is_partial());
        assert_eq!(back.coverage.uncovered[0].last_known_seq, Some(48_213));
    }

    #[test]
    fn every_gap_has_a_distinct_wire_spelling() {
        let spellings: Vec<&str> = [
            CoverageGap::NeverReported,
            CoverageGap::Stale,
            CoverageGap::NotLive,
            CoverageGap::Unreachable,
            CoverageGap::Unreadable,
        ]
        .into_iter()
        .map(CoverageGap::as_str)
        .collect();
        assert_eq!(
            spellings,
            [
                "never_reported",
                "stale",
                "not_live",
                "unreachable",
                "unreadable"
            ]
        );
    }

    #[test]
    fn an_empty_cluster_view_is_complete_rather_than_partial() {
        // Vacuously, and that is the right answer: there is no node whose
        // absence is unaccounted for. It is also why `is_partial` is not
        // the only thing a caller should look at; `expected()` is zero here
        // and a zero-node cluster is its own problem.
        let summary =
            ClusterUsageSummary::new("2026-08-01T00:00:00Z", Vec::new(), MeterCoverage::default());

        assert!(!summary.is_partial());
        assert_eq!(summary.coverage.expected(), 0);
        assert!(summary.totals().is_empty());
        assert_eq!(summary.claims(), 0);
    }

    #[test]
    fn two_nodes_segments_are_held_whole_and_never_interleaved() {
        // Both nodes minted the same claim ids, which is the case a merged
        // chain would silently collapse. The summary holds two segments, and
        // ten claims rather than five, because a claim's identity includes
        // the node that minted it. The chain half of this property is
        // pinned in `crate::ledger`, where two independently verifiable
        // files are built and checked.
        let summary = ClusterUsageSummary::new(
            "2026-08-01T00:00:00Z",
            vec![node("node-a", "acme", 5, 5), node("node-b", "acme", 5, 5)],
            MeterCoverage::new(vec!["node-a".to_string(), "node-b".to_string()], Vec::new()),
        );

        assert_eq!(summary.segments.len(), 2, "two segments, never interleaved");
        assert_eq!(
            summary
                .segments
                .iter()
                .map(|segment| segment.node_id.as_str())
                .collect::<Vec<_>>(),
            vec!["node-a", "node-b"],
            "each segment still names the chain it describes"
        );
        assert_eq!(summary.claims(), 10);
        assert_eq!(search_calls(&summary), 10);
    }
}
