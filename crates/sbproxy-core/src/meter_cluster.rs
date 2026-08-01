// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Mesh-wide meter reporting: one chain per node, gathered with explicit
//! coverage (WOR-2130).
//!
//! Each node writes its own receipt chain and publishes a summary of it,
//! [`sbproxy_meter::segment::ChainSegment`], into typed cluster state under
//! its own node id. A cluster-wide answer is a scatter-gather over the
//! membership view: read one segment per member, sum the segments that came
//! back, and name every member that did not answer next to the total.
//!
//! # Chains are gathered, never merged
//!
//! The hash links are what make completeness provable, and interleaving two
//! nodes' entries means re-linking them, after which the chain proves only
//! that somebody re-linked it. So nothing here ever touches an entry. A
//! segment carries a head sequence, a head digest, and unit totals, and it
//! travels whole. Two nodes' chains keep verifying independently, on their
//! own disks, against their own genesis digests, forever.
//!
//! The one place that could go wrong is a segment arriving under one node's
//! key while claiming to describe another.
//! [`crate::meter_cluster::ClusterMeterView::gather`] refuses it rather than
//! repairing it: a mismatch there is either a bug or an attack, and folding
//! it in would be the first half of a merge.
//!
//! # A partial total says it is partial
//!
//! [`sbproxy_meter::coverage::ClusterUsageSummary::is_partial`] is the
//! question to answer before quoting a figure at a person. During a rolling
//! restart every gather is partial, and a partial total is still the most
//! useful thing available, so the answer is to label it rather than to
//! withhold it.
//!
//! A node that did not answer is reported with the last chain head it was
//! ever seen at, held in [`sbproxy_meter::coverage::LastKnownHeads`], which
//! never evicts. Its units are not carried into the sum, because a sum
//! topped up with values nobody could confirm is an estimate wearing the
//! clothes of a count. The number sits beside the total, not inside it.
//!
//! # Why this does not reuse the fleet metrics aggregator
//!
//! The fleet aggregator in [`crate::cluster_metrics`] does look like the
//! same job, and it is not. It retains only the nodes in the caller's live
//! view, which is exactly right for autoscaling and monitoring, where a
//! departed node's capacity genuinely is gone. Applied to receipts it means
//! a node dying makes the cluster-wide unit count go down with no marker
//! anywhere, which is a revenue defect that survives for months because
//! every individual figure on the dashboard still looks plausible.
//!
//! Receipts therefore never aggregate through it. The distinction is
//! restated as a comment inside
//! [`crate::meter_cluster::ClusterMeterView::gather`], where somebody
//! reaching for the convenient reuse would be standing.

use std::sync::Arc;
use std::time::Duration;

use sbproxy_mesh::{ClusterHandle, ClusterMemberState, ClusterStateRead};
use sbproxy_meter::coverage::{
    ClusterUsageSummary, CoverageGap, LastKnownHead, LastKnownHeads, MeterCoverage, UncoveredNode,
};
use sbproxy_meter::segment::{ChainSegment, ClaimKey, RecordOutcome, SegmentRecorder, UnitTotal};
use sbproxy_meter::Unit;

/// Cluster state namespace this node's chain segment is published under.
const SEGMENT_NAMESPACE: &str = "meter-receipt-segments";

/// Schema version for the published [`ChainSegment`].
///
/// Bumped when the segment's serialised shape changes. A peer publishing a
/// version this build cannot read is reported as
/// [`CoverageGap::Unreadable`] rather than skipped, so a half-upgraded
/// cluster produces a partial total that names the nodes it could not read
/// instead of a complete-looking total missing half the fleet.
const SEGMENT_SCHEMA_VERSION: u32 = 1;

/// How many publish intervals a record stays valid for.
///
/// Three rather than one so a single missed tick, which happens under load
/// and during a reload, does not blank the fleet's coverage.
const TTL_INTERVALS: u64 = 3;

/// This node's half of the mesh-wide report.
///
/// Holds one [`SegmentRecorder`], which is bound to one node id for its
/// whole life. Everything a claim needs in order to be attributable is
/// therefore supplied here rather than trusted from a caller: a claim
/// recorded through [`LocalMeter::record_claim`] is stamped with this
/// node's id on the way in, so [`RecordOutcome::ForeignNode`] is
/// unreachable through this type by construction.
#[derive(Debug)]
pub struct LocalMeter {
    /// Running totals for this node's chain.
    recorder: SegmentRecorder,
}

impl LocalMeter {
    /// Start recording for `node_id`.
    ///
    /// The id should be the cluster identity's node id, which is what the
    /// gather keys segments by and what mesh membership guarantees unique.
    /// Anything else produces segments that no gather will attribute.
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            recorder: SegmentRecorder::new(node_id),
        }
    }

    /// The node this meter speaks for.
    pub fn node_id(&self) -> &str {
        self.recorder.node_id()
    }

    /// Fold one settled claim into this node's running totals.
    ///
    /// `billed` is the outcome table's answer
    /// ([`sbproxy_meter::OutcomeTable::billable_units`]), not everything the
    /// attempt accrued. Passing the raw units would count work the
    /// operator's own table says is free.
    ///
    /// Returns [`RecordOutcome::Folded`] for a retry of a claim already
    /// counted here, which is how four attempts at a flaky origin stay one
    /// sale. It cannot return [`RecordOutcome::ForeignNode`]: the claim key
    /// is built from this meter's own node id.
    pub fn record_claim(&self, claim_id: &str, tenant: &str, billed: &[Unit]) -> RecordOutcome {
        let claim = ClaimKey::new(self.recorder.node_id(), claim_id);
        self.recorder.record(&claim, tenant, billed)
    }

    /// This node's running unit totals, in a deterministic order.
    pub fn totals(&self) -> Vec<UnitTotal> {
        self.recorder.totals()
    }

    /// Take a segment describing this node as of the chain head it is given.
    ///
    /// Pass [`sbproxy_meter::ledger::UsageLedger::head`]'s two return values
    /// straight through. The head is a parameter rather than something read
    /// here because the ledger is opened elsewhere and a meter that guessed
    /// at the head would publish a number the chain does not support.
    pub fn segment(&self, head_seq: u64, head_hash: &str) -> ChainSegment {
        self.recorder.segment(head_seq, head_hash)
    }
}

/// The cluster-wide view, and the memory that keeps an unreachable node
/// reporting a number instead of a zero.
///
/// One per process. Cheap to clone behind an [`Arc`]; the memory inside is
/// mutated through an internal lock rather than by taking `&mut self`, so a
/// gather and a publish loop can share it.
#[derive(Debug, Default)]
pub struct ClusterMeterView {
    /// The last head every node was ever seen at. Never evicted.
    heads: LastKnownHeads,
}

impl ClusterMeterView {
    /// Start with no memory of any node.
    pub fn new() -> Self {
        Self::default()
    }

    /// What is still known about `node_id`, or `None` if this process has
    /// never seen it report.
    ///
    /// `None` and `Some(head_seq: 0)` are different statements and stay
    /// different here: the first is "nobody has ever heard from it", the
    /// second is "it reported an empty chain".
    pub fn last_known_head(&self, node_id: &str) -> Option<LastKnownHead> {
        self.heads.get(node_id)
    }

    /// Publish this node's segment into typed cluster state.
    ///
    /// Returns whether the publish landed. A failure is not fatal and not
    /// worth retrying inline: the next tick republishes, and in the
    /// meantime every peer's gather reports this node as uncovered with its
    /// last known head, which is the honest description of the situation.
    pub async fn publish(
        &self,
        handle: &ClusterHandle,
        segment: &ChainSegment,
        generation: u64,
        ttl: Duration,
    ) -> bool {
        match handle
            .publish_state(
                SEGMENT_NAMESPACE,
                &segment.node_id,
                SEGMENT_SCHEMA_VERSION,
                generation,
                ttl,
                segment,
            )
            .await
        {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(
                    %error,
                    node_id = %segment.node_id,
                    "meter-cluster: segment publish failed (retry next tick)"
                );
                false
            }
        }
    }

    /// Gather one segment per member and report what the total covers.
    ///
    /// `local` short-circuits this node: a process never needs the network
    /// to know its own chain head, and taking the local segment directly
    /// keeps a single-node deployment working with no mesh at all. Pass
    /// `None` to read this node's own published record instead, which is
    /// what a caller with no meter in hand should do.
    ///
    /// `max_age` bounds how old a peer's published record may be and still
    /// count. Older records are reported as [`CoverageGap::Stale`] rather
    /// than summed, because a reading from twenty minutes ago describes
    /// traffic up to that point and nothing since.
    pub async fn gather(
        &self,
        handle: &ClusterHandle,
        local: Option<ChainSegment>,
        max_age: Duration,
    ) -> ClusterUsageSummary {
        // Receipts never aggregate through ClusterMetrics, and the reuse is
        // tempting enough to be worth naming here rather than in a design
        // document nobody opens. That aggregator drops the snapshot of any
        // node outside the caller's live view. For autoscaling that is
        // correct: a departed node's capacity really is gone. For billing it
        // means a node dying makes the cluster-wide unit count go down with
        // nothing anywhere saying so, and every individual number on the
        // dashboard still looks plausible, so nobody notices for a quarter.
        //
        // The loop below does the opposite on purpose. A node that cannot be
        // reached keeps its place in the report, keeps its last known chain
        // head, and is excluded only from the sum, which is then labelled
        // partial. Do not replace this with the aggregator.
        let my_id = handle.identity().node_id.clone();
        let now_ms = unix_millis();
        let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);

        let mut segments: Vec<ChainSegment> = Vec::new();
        let mut answered: Vec<String> = Vec::new();
        let mut uncovered: Vec<UncoveredNode> = Vec::new();

        for member in handle.membership() {
            if member.node_id == my_id {
                if let Some(segment) = &local {
                    self.heads.remember(segment);
                    answered.push(member.node_id.clone());
                    segments.push(segment.clone());
                    continue;
                }
                // No local segment in hand: fall through and read this
                // node's own published record like any other member's.
            } else if member.state != ClusterMemberState::Alive {
                // A last record may well still be readable. It is not
                // counted anyway: a reading taken before the node left says
                // nothing about the interval since, and from here there is
                // no way to tell those two apart.
                uncovered.push(self.heads.uncovered(&member.node_id, CoverageGap::NotLive));
                continue;
            }

            let read = handle
                .read_state::<ChainSegment>(
                    SEGMENT_NAMESPACE,
                    &member.node_id,
                    SEGMENT_SCHEMA_VERSION,
                )
                .await;

            match read {
                ClusterStateRead::Present(record) => {
                    if record.payload.node_id != member.node_id {
                        // A segment filed under one node while describing
                        // another. Folding it in would attribute one chain's
                        // units to a different chain, which is a merge by
                        // another name. Refuse rather than repair.
                        tracing::warn!(
                            key = %member.node_id,
                            claimed = %record.payload.node_id,
                            "meter-cluster: segment claims a node other than its key; refusing it"
                        );
                        uncovered.push(
                            self.heads
                                .uncovered(&member.node_id, CoverageGap::Unreadable),
                        );
                        continue;
                    }
                    // Remembered before the freshness verdict, because even
                    // a stale reading is the most recent thing this process
                    // has seen and is what an uncovered line should quote.
                    self.heads.remember(&record.payload);
                    if now_ms.saturating_sub(record.published_at_unix_ms) > max_age_ms {
                        uncovered.push(self.heads.uncovered(&member.node_id, CoverageGap::Stale));
                        continue;
                    }
                    answered.push(member.node_id.clone());
                    segments.push(record.payload);
                }
                ClusterStateRead::Missing => {
                    // Never seen and seen-then-gone are different problems
                    // with different runbooks, so they get different gaps.
                    let gap = if self.heads.get(&member.node_id).is_some() {
                        CoverageGap::Unreachable
                    } else {
                        CoverageGap::NeverReported
                    };
                    uncovered.push(self.heads.uncovered(&member.node_id, gap));
                }
                ClusterStateRead::Expired { .. } => {
                    uncovered.push(self.heads.uncovered(&member.node_id, CoverageGap::Stale));
                }
                ClusterStateRead::Unreachable { .. } => {
                    uncovered.push(
                        self.heads
                            .uncovered(&member.node_id, CoverageGap::Unreachable),
                    );
                }
                ClusterStateRead::IncompatibleSchema { .. }
                | ClusterStateRead::Malformed { .. } => {
                    uncovered.push(
                        self.heads
                            .uncovered(&member.node_id, CoverageGap::Unreadable),
                    );
                }
            }
        }

        ClusterUsageSummary::new(
            chrono::Utc::now().to_rfc3339(),
            segments,
            MeterCoverage::new(answered, uncovered),
        )
    }
}

/// Publish this node's segment forever, on the given cadence.
///
/// `local_segment` is called once per tick rather than captured, so a
/// reload that replaces the meter cannot leave this loop republishing a
/// segment from a runtime that no longer exists. Returning `None` skips the
/// tick, which is what a process with attestation switched off does.
///
/// Publishing only. Gathering is a request, not a background job: it
/// happens when somebody asks for a cluster total, so that the coverage
/// block describes the moment they asked rather than the last time a timer
/// fired.
pub async fn run_loop<F>(
    handle: ClusterHandle,
    view: Arc<ClusterMeterView>,
    local_segment: F,
    interval_secs: u64,
) where
    F: Fn() -> Option<ChainSegment> + Send + Sync + 'static,
{
    let interval_secs = interval_secs.max(1);
    let ttl = Duration::from_secs(interval_secs.saturating_mul(TTL_INTERVALS));
    let mut generation = generation_seed();
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        ticker.tick().await;
        generation = generation.saturating_add(1);
        let Some(segment) = local_segment() else {
            continue;
        };
        view.publish(&handle, &segment, generation, ttl).await;
    }
}

/// A coarse, monotonic-enough starting generation derived from wall-clock
/// time, so a restarted node's first publish still outranks any stale
/// record a peer is holding from before the restart.
fn generation_seed() -> u64 {
    unix_millis()
}

/// Unix milliseconds, or `0` when the clock is before the epoch.
///
/// Zero is the safe fallback for the freshness comparison: it makes
/// `now - published` saturate to zero and every record look current, which
/// beats labelling the whole fleet stale because one node's clock is wrong.
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_mesh::{ClusterIdentity, ClusterNodeRole};
    use sbproxy_meter::event::Evidence;
    use std::collections::{BTreeMap, BTreeSet};

    fn identity(node_id: &str) -> ClusterIdentity {
        ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: node_id.to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        }
    }

    fn handle(node_id: &str) -> ClusterHandle {
        ClusterHandle::local(identity(node_id)).expect("a local handle needs no network")
    }

    fn weighted(count: u64) -> Unit {
        Unit::new(
            "search_call",
            count,
            Evidence::RouteWeight {
                config_revision: "9f2c41a0be77".to_string(),
            },
        )
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
    fn nothing_on_the_receipt_path_reaches_for_the_fleet_metrics_aggregator() {
        // The acceptance criterion, checked mechanically rather than left to
        // a reviewer noticing. Comments are stripped first, because the
        // comment inside `gather` names the aggregator on purpose: naming it
        // is what stops the next person reusing it.
        let source = include_str!("meter_cluster.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        for (offset, line) in production.lines().enumerate() {
            let code = line.split_once("//").map_or(line, |(before, _)| before);
            assert!(
                !code.contains("ClusterMetrics"),
                "line {}: receipts must never aggregate through the fleet aggregator",
                offset + 1
            );
            assert!(
                !code.contains("cluster_metrics"),
                "line {}: receipts must never aggregate through the fleet aggregator",
                offset + 1
            );
        }
    }

    #[test]
    fn a_local_meter_stamps_its_own_node_and_folds_its_own_retries() {
        // A foreign claim cannot reach the recorder through this type: the
        // claim key is built here, from this meter's own node id. The
        // refusal path itself is exercised in `sbproxy_meter::segment`,
        // where a caller can hand over a key naming somebody else.
        let meter = LocalMeter::new("node-a");
        assert_eq!(meter.node_id(), "node-a");

        assert_eq!(
            meter.record_claim("01J9ZQ8N4T7WYQ4CQ9K5R2VXAB", "acme", &[weighted(1)]),
            RecordOutcome::Recorded
        );
        // Same claim id again: a retry, folded rather than doubled.
        assert_eq!(
            meter.record_claim("01J9ZQ8N4T7WYQ4CQ9K5R2VXAB", "acme", &[weighted(1)]),
            RecordOutcome::Folded
        );

        let segment = meter.segment(48_213, "a3f19c8b");
        assert_eq!(segment.node_id, "node-a");
        assert_eq!(segment.head_seq, 48_213);
        assert_eq!(segment.claims, 1);
        assert_eq!(meter.totals()[0].count, 1);
    }

    #[tokio::test]
    async fn a_gather_with_the_local_segment_in_hand_needs_no_network() {
        let handle = handle("node-a");
        let view = ClusterMeterView::new();
        let meter = LocalMeter::new("node-a");
        meter.record_claim("claim-1", "acme", &[weighted(3)]);

        let summary = view
            .gather(
                &handle,
                Some(meter.segment(7, "deadbeef")),
                Duration::from_secs(60),
            )
            .await;

        assert!(!summary.is_partial(), "one node, and it answered");
        assert_eq!(summary.coverage.answered, vec!["node-a"]);
        assert_eq!(summary.segments.len(), 1);
        assert_eq!(search_calls(&summary), 3);
        assert_eq!(
            view.last_known_head("node-a").expect("seen").head_seq,
            7,
            "a gather remembers every head it sees"
        );
    }

    #[tokio::test]
    async fn a_published_segment_is_read_back_without_a_local_copy() {
        let handle = handle("node-a");
        let view = ClusterMeterView::new();
        let meter = LocalMeter::new("node-a");
        meter.record_claim("claim-1", "acme", &[weighted(5)]);

        let segment = meter.segment(12, "cafebabe");
        let published = view
            .publish(&handle, &segment, 1, Duration::from_secs(60))
            .await;
        assert!(published, "publishing into a local handle cannot fail");

        let summary = view.gather(&handle, None, Duration::from_secs(3_600)).await;

        assert!(!summary.is_partial());
        assert_eq!(summary.segments.len(), 1);
        assert_eq!(summary.segments[0].head_seq, 12);
        assert_eq!(search_calls(&summary), 5);
    }

    #[tokio::test]
    async fn a_node_that_has_published_nothing_is_named_rather_than_omitted() {
        // The shape of the defect this whole module exists to prevent: a
        // node in the membership view contributing nothing. It must not
        // vanish from the report, and the total must not read as complete.
        let handle = handle("node-a");
        let view = ClusterMeterView::new();

        let summary = view.gather(&handle, None, Duration::from_secs(60)).await;

        assert!(summary.is_partial(), "a total missing a node is partial");
        assert!(summary.coverage.answered.is_empty());
        assert_eq!(summary.coverage.expected(), 1);
        assert_eq!(summary.coverage.uncovered[0].node_id, "node-a");
        assert_eq!(
            summary.coverage.uncovered[0].gap,
            CoverageGap::NeverReported
        );
        assert_eq!(
            summary.coverage.uncovered[0].last_known_seq, None,
            "never seen is not the same statement as seen at zero"
        );
        assert!(summary.totals().is_empty());
    }

    #[tokio::test]
    async fn a_node_that_stops_answering_keeps_reporting_its_last_known_seq() {
        // Kill a node mid-query. Everything it metered is still on its own
        // disk, so the honest line is its last known head, not a zero and
        // not an omission.
        let handle = handle("node-3");
        let view = ClusterMeterView::new();
        let meter = LocalMeter::new("node-3");
        for index in 0..30 {
            meter.record_claim(&format!("claim-{index}"), "acme", &[weighted(1)]);
        }

        let healthy = view
            .gather(
                &handle,
                Some(meter.segment(48_213, "a3f19c8b")),
                Duration::from_secs(60),
            )
            .await;
        assert!(!healthy.is_partial());
        assert_eq!(search_calls(&healthy), 30);

        // The node goes away: no local segment, and nothing published.
        let after = view.gather(&handle, None, Duration::from_secs(60)).await;

        assert!(after.is_partial(), "the shrink is labelled, not silent");
        let missing = &after.coverage.uncovered[0];
        assert_eq!(missing.node_id, "node-3");
        assert_eq!(missing.gap, CoverageGap::Unreachable);
        assert_eq!(
            missing.last_known_seq,
            Some(48_213),
            "the chain is still durable on the node's own disk"
        );
        assert!(missing.last_seen_at.is_some());
        assert!(
            after.totals().is_empty(),
            "an unreachable node's last known units are reported beside the total, never inside it"
        );
    }

    #[tokio::test]
    async fn a_stale_record_is_labelled_rather_than_counted() {
        let handle = handle("node-a");
        let view = ClusterMeterView::new();
        let meter = LocalMeter::new("node-a");
        meter.record_claim("claim-1", "acme", &[weighted(9)]);
        let segment = meter.segment(4, "beef");
        view.publish(&handle, &segment, 1, Duration::from_secs(3_600))
            .await;

        // A zero-length freshness window makes every record older than the
        // gather, which is the same verdict a stalled publish loop earns.
        // The sleep is what puts a measurable millisecond between the
        // publish and the reading; without it the two can share a
        // millisecond and the record is legitimately not yet stale.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let summary = view.gather(&handle, None, Duration::ZERO).await;

        assert!(summary.is_partial());
        assert_eq!(summary.coverage.uncovered[0].gap, CoverageGap::Stale);
        assert_eq!(
            summary.coverage.uncovered[0].last_known_seq,
            Some(4),
            "a stale reading is still the most recent thing anybody has seen"
        );
        assert!(summary.totals().is_empty());
    }

    #[tokio::test]
    async fn a_segment_claiming_a_node_other_than_its_key_is_refused() {
        // The one path that could merge two chains: a record filed under
        // node-a while describing node-b. Refusing keeps every entry on the
        // chain that produced it.
        let handle = handle("node-a");
        let view = ClusterMeterView::new();
        let impostor = LocalMeter::new("node-b");
        impostor.record_claim("claim-1", "acme", &[weighted(1_000_000)]);

        handle
            .publish_state(
                SEGMENT_NAMESPACE,
                "node-a",
                SEGMENT_SCHEMA_VERSION,
                1,
                Duration::from_secs(3_600),
                &impostor.segment(1, "forged"),
            )
            .await
            .expect("publishing into a local handle cannot fail");

        let summary = view.gather(&handle, None, Duration::from_secs(3_600)).await;

        assert!(summary.is_partial());
        assert!(
            summary.segments.is_empty(),
            "the forged segment is not held"
        );
        assert_eq!(summary.coverage.uncovered[0].gap, CoverageGap::Unreadable);
        assert_eq!(
            view.last_known_head("node-a"),
            None,
            "a refused segment does not get to seed the last-known memory either"
        );
        assert!(summary.totals().is_empty());
    }

    #[tokio::test]
    async fn a_rolling_restart_keeps_returning_labelled_partial_totals() {
        // One node's worth of the sequence, repeated: publish, answer,
        // disappear, come back. Every step is either complete or partial and
        // says which, and the down step still quotes a head.
        let handle = handle("node-a");
        let view = ClusterMeterView::new();
        let meter = LocalMeter::new("node-a");

        for round in 1..=3u64 {
            meter.record_claim(&format!("claim-{round}"), "acme", &[weighted(1)]);
            let segment = meter.segment(round, &format!("head-{round}"));
            let up = view
                .gather(&handle, Some(segment), Duration::from_secs(60))
                .await;
            assert!(!up.is_partial(), "round {round} is a complete gather");
            assert_eq!(search_calls(&up), round);

            let down = view.gather(&handle, None, Duration::from_secs(60)).await;
            assert!(down.is_partial(), "round {round} restart is labelled");
            assert_eq!(down.coverage.expected(), 1, "the node is still expected");
            assert_eq!(
                down.coverage.uncovered[0].last_known_seq,
                Some(round),
                "the restarting node's chain is still on its own disk"
            );
        }
    }
}
