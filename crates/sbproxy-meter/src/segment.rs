// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! One chain per node, and the running total that describes it.
//!
//! A hash chain proves completeness by proving that nothing was removed
//! from between two links. That proof is what [`crate::ledger`] exists for,
//! and it is exactly the property that merging two nodes' chains destroys:
//! interleaving entries from two writers means re-linking them, and a
//! re-linked chain proves only that somebody re-linked it. So chains are
//! never merged. Each node writes its own, verifies its own, and keeps its
//! own sequence, and a cluster-wide answer is assembled out of whole
//! segments rather than out of individual entries.
//!
//! That makes attribution load-bearing rather than decorative. A `seq` of
//! 48,213 means nothing until you know which node counted it, so
//! [`crate::segment::ChainSegment`] carries `node_id` next to the head, and
//! [`crate::segment::ClaimKey`] carries it next to the claim.
//!
//! # Why a claim id cannot collide across nodes
//!
//! `claim_id` is a ULID, so it is unique on the node that minted it with
//! very high probability. "Very high probability" is not the guarantee a
//! billing system wants, and it is not the guarantee this module offers.
//! [`crate::segment::ClaimKey`] pairs the claim id with the node that
//! minted it, and two nodes never share a node id: mesh membership is keyed
//! on it, so two live members with the same id are one member. Two claims
//! minted on different nodes therefore differ in their first component
//! whatever their ULIDs do, and no amount of clock skew, entropy failure,
//! or seed reuse can make them equal.
//!
//! [`crate::segment::SegmentRecorder`] turns that from an argument into a
//! mechanism: it holds one node id for its whole life and refuses any claim
//! that names another node, so a merge cannot happen by accident on the
//! recording path either.
//!
//! # The totals are a summary, not the record
//!
//! [`crate::segment::ChainSegment::totals`] is a convenience for answering
//! "how much did this node meter" without replaying its chain. The chain is
//! still the record. A total that disagrees with a replay of the same
//! chain means this recorder missed an append or counted one twice, and the
//! chain wins.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::event::{Unit, UnitSource};

/// The globally unique identity of one invoice line.
///
/// Two components, and the first one is the interesting one. A bare
/// `claim_id` is unique on the node that minted it; pairing it with that
/// node makes it unique everywhere, because node ids are unique by
/// construction across a mesh. See the module documentation.
///
/// The fields are private and there is no setter. A claim key whose node
/// component could be edited after the fact would be a claim that could be
/// moved between chains, which is the merge this module exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimKey {
    /// The node that minted the claim and owns the chain it was written to.
    node_id: String,
    /// The ULID every attempt at one unit of work shares.
    claim_id: String,
}

impl ClaimKey {
    /// Bind a claim id to the node that minted it.
    pub fn new(node_id: impl Into<String>, claim_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            claim_id: claim_id.into(),
        }
    }

    /// The node that owns the chain this claim was written to.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The ULID retries of the same call share.
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }
}

impl std::fmt::Display for ClaimKey {
    /// Renders as `node_id/claim_id`.
    ///
    /// The separator is a `/` rather than nothing, because a concatenation
    /// with no separator can be ambiguous when node ids vary in length, and
    /// an ambiguous identity is the collision this type exists to rule out.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.node_id, self.claim_id)
    }
}

/// One line of a node's running unit total.
///
/// Keyed by tenant, unit name, and provenance rather than by unit name
/// alone. Folding two provenances into one number is the thing
/// [`crate::event`] refuses to do on a single receipt, and a summary that
/// did it anyway would undo that refusal at exactly the point an operator
/// looks at the figures.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnitTotal {
    /// The billing account these units are charged to.
    pub tenant: String,
    /// Operator-chosen unit name, as it appears on the invoice line.
    pub unit: String,
    /// Which mechanism produced the count.
    pub source: UnitSource,
    /// How many of the unit were metered.
    pub count: u64,
}

/// What one node says about its own chain: how far it has got, and what it
/// counted getting there.
///
/// This is the unit a cluster-wide answer is assembled from. It is never
/// split and never merged with another node's: a summary holds whole
/// segments, and a total is a sum over the segments it actually has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSegment {
    /// The node that wrote this chain.
    ///
    /// Checked against the key a segment arrived under before it is
    /// counted. A segment filed under one node while claiming another is a
    /// bug or an attack, and either way it is not something to fold into a
    /// total.
    pub node_id: String,
    /// Number of entries in this node's chain, which is also the sequence
    /// number the next entry will take.
    ///
    /// The single most useful number when a node is unreachable, because it
    /// is the one figure that still says something true about traffic
    /// nobody can currently see.
    pub head_seq: u64,
    /// Hex digest of the most recent entry, or the genesis digest for an
    /// empty chain.
    ///
    /// Carried so that a later gather can tell "this node has not served a
    /// request" from "this node restarted onto a different chain": the
    /// first leaves the hash alone, the second changes it.
    pub head_hash: String,
    /// Distinct claims this node has folded, counting every claim once no
    /// matter how many attempts it took.
    pub claims: u64,
    /// The node's running unit totals, in a deterministic order.
    pub totals: Vec<UnitTotal>,
    /// RFC 3339 timestamp at which the segment was taken.
    ///
    /// A gather uses it to decide whether a reachable node's last report is
    /// current enough to count, so it is a fact about the reading rather
    /// than about the chain.
    pub observed_at: String,
}

/// What a recorder did with one settled claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordOutcome {
    /// The claim was new on this node and its units were added.
    Recorded,
    /// The claim was already counted here, so its units were not added
    /// again. This is the retry case: four attempts at a flaky origin are
    /// one sale.
    Folded,
    /// The claim names a different node, so nothing was recorded.
    ///
    /// Refusing is the point. Accepting it would be the first half of a
    /// chain merge, and the totals would then describe traffic this node
    /// cannot produce a chain for.
    ForeignNode,
}

impl RecordOutcome {
    /// Stable snake-case name, for logs and for a metric label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Folded => "folded",
            Self::ForeignNode => "foreign_node",
        }
    }
}

/// Mutable recorder state, behind one lock.
///
/// A `BTreeMap` rather than a `HashMap` so the totals come out in a
/// deterministic order without a sort on every read. The published segment
/// is a wire document that operators diff between gathers, and a summary
/// whose lines move around between two identical readings wastes their
/// time.
#[derive(Default)]
struct RecorderState {
    /// `(tenant, unit, source)` to the count metered under it.
    totals: BTreeMap<(String, String, UnitSource), u64>,
    /// Claim ids already folded on this node.
    claims: BTreeSet<String>,
}

/// One node's running view of its own chain.
///
/// Holds a node id for its whole life, and that is the invariant everything
/// else here rests on. A recorder is bound to exactly one chain, refuses
/// claims belonging to any other node, and therefore cannot be talked into
/// producing a segment that describes two chains at once.
pub struct SegmentRecorder {
    /// The node this recorder speaks for.
    node_id: String,
    /// Totals and folded claims.
    state: parking_lot::Mutex<RecorderState>,
}

impl std::fmt::Debug for SegmentRecorder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Tenant names are operator data. The counts are the interesting
        // part for a log line and the names are not, so report shape rather
        // than content.
        let state = self.state.lock();
        formatter
            .debug_struct("SegmentRecorder")
            .field("node_id", &self.node_id)
            .field("claims", &state.claims.len())
            .field("total_lines", &state.totals.len())
            .finish()
    }
}

impl SegmentRecorder {
    /// Start a recorder for `node_id`.
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            state: parking_lot::Mutex::new(RecorderState::default()),
        }
    }

    /// The node this recorder speaks for.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Fold one settled claim into this node's totals.
    ///
    /// `units` is what actually bills, which is
    /// [`crate::outcome::OutcomeTable::billable_units`]'s answer rather than
    /// everything the attempt accrued. Passing the raw units instead would
    /// count work the operator's own table says is free.
    ///
    /// A claim already seen here is folded rather than added, so a retry
    /// does not multiply the total. A claim naming another node is refused;
    /// see [`crate::segment::RecordOutcome::ForeignNode`].
    pub fn record(&self, claim: &ClaimKey, tenant: &str, units: &[Unit]) -> RecordOutcome {
        if claim.node_id() != self.node_id {
            return RecordOutcome::ForeignNode;
        }
        let mut state = self.state.lock();
        if !state.claims.insert(claim.claim_id().to_string()) {
            return RecordOutcome::Folded;
        }
        for unit in units {
            let key = (tenant.to_string(), unit.name.clone(), unit.source);
            let entry = state.totals.entry(key).or_insert(0);
            // Saturating rather than wrapping. A total that wraps to nearly
            // zero reads as a quiet month rather than as an overflow, and
            // this is the one number an operator is least likely to
            // double-check.
            *entry = entry.saturating_add(unit.count);
        }
        RecordOutcome::Recorded
    }

    /// Distinct claims folded so far.
    pub fn claims(&self) -> u64 {
        self.state.lock().claims.len() as u64
    }

    /// The running totals, in a deterministic order.
    pub fn totals(&self) -> Vec<UnitTotal> {
        self.state
            .lock()
            .totals
            .iter()
            .map(|((tenant, unit, source), count)| UnitTotal {
                tenant: tenant.clone(),
                unit: unit.clone(),
                source: *source,
                count: *count,
            })
            .collect()
    }

    /// Take a segment describing this node as of the chain head it is given.
    ///
    /// The head is a parameter rather than something read from a ledger
    /// here, because this crate must stay usable by a caller who chains
    /// through [`crate::ledger::UsageLedger`] and by one who does not. Pass
    /// [`crate::ledger::UsageLedger::head`]'s two return values straight
    /// through.
    ///
    /// The timestamp is taken here rather than accepted, because a caller
    /// who could supply it could supply a stale one, and staleness is
    /// exactly what a gather uses this field to judge.
    pub fn segment(&self, head_seq: u64, head_hash: impl Into<String>) -> ChainSegment {
        ChainSegment {
            node_id: self.node_id.clone(),
            head_seq,
            head_hash: head_hash.into(),
            claims: self.claims(),
            totals: self.totals(),
            observed_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Evidence;

    fn measured(name: &str, count: u64) -> Unit {
        Unit::new(
            name,
            count,
            Evidence::Measured {
                bytes_in: 128,
                bytes_out: 4_096,
                duration_ms: 12,
            },
        )
    }

    fn weighted(name: &str, count: u64) -> Unit {
        Unit::new(
            name,
            count,
            Evidence::RouteWeight {
                config_revision: "9f2c41a0be77".to_string(),
            },
        )
    }

    #[test]
    fn a_claim_id_collision_across_nodes_is_impossible_by_construction() {
        // The adversarial case, not the likely one. Assume the ULID
        // generator has failed completely and two nodes have minted the
        // same claim id in the same millisecond. The claim keys still
        // differ, because the node component differs, and mesh membership
        // cannot contain two live nodes sharing an id.
        let collided_ulid = "01J9ZQ8N4T7WYQ4CQ9K5R2VXAB";
        let on_a = ClaimKey::new("node-a", collided_ulid);
        let on_b = ClaimKey::new("node-b", collided_ulid);

        assert_eq!(on_a.claim_id(), on_b.claim_id(), "the ULIDs are identical");
        assert_ne!(on_a, on_b, "the claims are still not the same claim");
        assert_ne!(on_a.to_string(), on_b.to_string());

        // And the recorders enforce it rather than merely describing it: a
        // recorder bound to node-a will not count node-b's claim even
        // though the claim id is byte-identical to one it would accept.
        let recorder_a = SegmentRecorder::new("node-a");
        assert_eq!(
            recorder_a.record(&on_a, "acme", &[measured("egress_kib", 4)]),
            RecordOutcome::Recorded
        );
        assert_eq!(
            recorder_a.record(&on_b, "acme", &[measured("egress_kib", 4_000)]),
            RecordOutcome::ForeignNode,
            "accepting another node's claim is the first half of a chain merge"
        );
        assert_eq!(recorder_a.claims(), 1);
        assert_eq!(
            recorder_a.totals(),
            vec![UnitTotal {
                tenant: "acme".to_string(),
                unit: "egress_kib".to_string(),
                source: UnitSource::Measured,
                count: 4,
            }],
            "the refused claim contributed nothing"
        );
    }

    #[test]
    fn retries_of_one_claim_are_counted_once() {
        let recorder = SegmentRecorder::new("node-a");
        let claim = ClaimKey::new("node-a", "01J9ZQ8N4T7WYQ4CQ9K5R2VXAB");

        assert_eq!(
            recorder.record(&claim, "acme", &[weighted("search_call", 1)]),
            RecordOutcome::Recorded
        );
        for _ in 0..3 {
            assert_eq!(
                recorder.record(&claim, "acme", &[weighted("search_call", 1)]),
                RecordOutcome::Folded,
                "four attempts at a flaky origin are one sale"
            );
        }

        assert_eq!(recorder.claims(), 1);
        assert_eq!(recorder.totals()[0].count, 1);
    }

    #[test]
    fn totals_keep_provenance_apart_rather_than_summing_it() {
        // The same unit name metered two ways. Summing them to 43 would
        // produce one unfalsifiable line where there were two checkable
        // ones, which is the failure `crate::event` is built to prevent.
        let recorder = SegmentRecorder::new("node-a");
        recorder.record(
            &ClaimKey::new("node-a", "claim-1"),
            "acme",
            &[measured("api_call", 3), weighted("api_call", 40)],
        );

        let totals = recorder.totals();
        assert_eq!(totals.len(), 2, "two provenances, two lines");
        assert_eq!(
            totals
                .iter()
                .map(|total| (total.source, total.count))
                .collect::<Vec<_>>(),
            vec![(UnitSource::Measured, 3), (UnitSource::RouteWeight, 40)]
        );
    }

    #[test]
    fn tenants_are_never_folded_together() {
        let recorder = SegmentRecorder::new("node-a");
        recorder.record(
            &ClaimKey::new("node-a", "claim-1"),
            "acme",
            &[weighted("search_call", 2)],
        );
        recorder.record(
            &ClaimKey::new("node-a", "claim-2"),
            "globex",
            &[weighted("search_call", 5)],
        );

        let totals = recorder.totals();
        assert_eq!(totals.len(), 2);
        assert_eq!(
            totals
                .iter()
                .map(|total| (total.tenant.as_str(), total.count))
                .collect::<Vec<_>>(),
            vec![("acme", 2), ("globex", 5)],
            "one bill per tenant is the whole point of the field"
        );
    }

    #[test]
    fn a_segment_carries_the_node_it_describes() {
        let recorder = SegmentRecorder::new("node-3");
        recorder.record(
            &ClaimKey::new("node-3", "claim-1"),
            "acme",
            &[weighted("search_call", 1)],
        );

        let segment = recorder.segment(48_213, "a3f19c8b");

        assert_eq!(segment.node_id, "node-3");
        assert_eq!(segment.head_seq, 48_213);
        assert_eq!(segment.head_hash, "a3f19c8b");
        assert_eq!(segment.claims, 1);
        assert!(
            !segment.observed_at.is_empty(),
            "a segment with no reading time cannot be judged stale"
        );
    }

    #[test]
    fn a_segment_round_trips_through_json_unchanged() {
        // The segment is published into typed cluster state and read back
        // by every other node, so its serialised form is a wire contract.
        let recorder = SegmentRecorder::new("node-a");
        recorder.record(
            &ClaimKey::new("node-a", "claim-1"),
            "acme",
            &[measured("egress_kib", 12), weighted("search_call", 1)],
        );
        let segment = recorder.segment(7, "deadbeef");

        let json = serde_json::to_string(&segment).expect("segment serialises");
        let back: ChainSegment = serde_json::from_str(&json).expect("segment deserialises");

        assert_eq!(back, segment);
    }

    #[test]
    fn a_recorder_never_reports_a_count_it_could_not_add() {
        // Saturating addition, exercised at the boundary. A wrapped total
        // reads as a quiet month, which is the one failure nobody
        // double-checks.
        let recorder = SegmentRecorder::new("node-a");
        recorder.record(
            &ClaimKey::new("node-a", "claim-1"),
            "acme",
            &[measured("egress_kib", u64::MAX)],
        );
        recorder.record(
            &ClaimKey::new("node-a", "claim-2"),
            "acme",
            &[measured("egress_kib", 10)],
        );

        assert_eq!(recorder.totals()[0].count, u64::MAX);
    }

    #[test]
    fn every_record_outcome_has_a_distinct_wire_spelling() {
        let spellings: Vec<&str> = [
            RecordOutcome::Recorded,
            RecordOutcome::Folded,
            RecordOutcome::ForeignNode,
        ]
        .into_iter()
        .map(RecordOutcome::as_str)
        .collect();
        assert_eq!(spellings, ["recorded", "folded", "foreign_node"]);
    }

    #[test]
    fn debug_reports_shape_rather_than_tenant_names() {
        let recorder = SegmentRecorder::new("node-a");
        recorder.record(
            &ClaimKey::new("node-a", "claim-1"),
            "a-very-identifiable-customer",
            &[weighted("search_call", 1)],
        );

        let rendered = format!("{recorder:?}");
        assert!(rendered.contains("node-a"), "{rendered}");
        assert!(rendered.contains("claims: 1"), "{rendered}");
        assert!(
            !rendered.contains("a-very-identifiable-customer"),
            "{rendered}"
        );
    }
}
