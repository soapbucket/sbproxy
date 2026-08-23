//! Showback / chargeback reporting for AI usage (WOR-2672 port of
//! `sbproxy-enterprise-ai::billing::chargeback`).
//!
//! Records per-request usage details so that platform operators can
//! attribute costs to the teams and projects that incurred them.
//!
//! # Layered on the existing usage sink, not a parallel capture path
//!
//! The enterprise source fed this tracker from its own
//! `sbproxy-enterprise-bootstrap::UsageSink` trait (`record(&self,
//! workspace: &WorkspaceId, kind: UsageKind, amount: f64)`, three
//! partial-amount calls per request) and persisted workspace totals to a
//! `HashKv` backend for cross-replica summing. Neither type exists in
//! this OSS tree: `sbproxy-enterprise-bootstrap` and
//! `sbproxy-enterprise-storage` are dropped outright per WOR-2661's
//! sequencing, and the port's own scope is storage-free.
//!
//! [`ChargebackTracker`] instead implements *this* crate's existing
//! [`crate::usage_sink::UsageSink`] trait, the seam every completed AI
//! gateway call already flows through (`JsonlFileSink`, `WebhookSink`,
//! `LangfuseSink`, `DatadogSink`, ... all implement it the same way).
//! One [`crate::usage_sink::LlmUsageEvent`] carries the whole completed
//! call, not a partial amount, so one `record()` call updates the bounded
//! recent-entry log and the team/workspace rollups under one lock. A
//! [`ChargebackTracker::snapshot`] can therefore never observe half an
//! event. This is simpler than the enterprise source's
//! deliberately-isolated design: that isolation existed only to protect
//! against three *partial* sink calls per request corrupting a
//! per-event log built for *complete* entries, a problem that does not
//! exist when the sink already receives one complete event per call.
//!
//! Workspace attribution keys on [`crate::usage_sink::LlmUsageEvent::tenant_id`]
//! (this crate's multi-tenant boundary) rather than the enterprise
//! source's separate `WorkspaceId` type; team/project chargeback keys on
//! the event's own `team` / `project` attribution fields (see
//! `crate::attribution`). Both fall back to [`UNATTRIBUTED`] when the
//! caller never set the corresponding header, so a tracker fed live
//! traffic never drops a record for lacking a tag.
//!
//! # Storage: none
//!
//! Per the port's disposition, this tracker is in-memory only and every
//! live structure is bounded. Raw entries evict oldest-first; excess
//! workspace/team cardinality folds into [`OVERFLOW`] and increments both
//! snapshot counters and Prometheus counters. The
//! enterprise source's `ChargebackPersistence` (write-behind to a
//! `HashKv`, cross-replica summing via `WorkspaceTotals::merge`) is not
//! ported; an embedder that needs durability exports
//! [`ChargebackTracker::snapshot`] periodically into its own store. A
//! configured sink is readable through
//! [`crate::usage_sink::UsageSink::chargeback_snapshot`] and the
//! authenticated JSON/CSV admin endpoints.
//!
//! # Employee-scoped chargeback: not ported
//!
//! The enterprise source's `#[cfg(feature = "employee-binding")]` module
//! (per-employee rollups keyed by SSO subject, a four-level hierarchical
//! budget walk) is not ported. `employee_binding` is being rescoped on a
//! separate branch (WOR-2667); this port does not gate on that landing
//! first, and [`ChargebackTracker`] / [`WorkspaceTotals`] work standalone
//! at the workspace level without it, which is the whole of what this
//! ticket asks for.
//!
//! See `docs/ai-chargeback.md` and `examples/ai-chargeback-billing/` for
//! a runnable walkthrough that also exercises [`super::forecast`] and
//! [`super::unified`] against the same tracker.

use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::usage_sink::{LlmUsageEvent, UsageSink};

/// Sentinel used for the team, project, or workspace dimension when an
/// [`LlmUsageEvent`] carries no attribution for it. Distinguishes "no tag
/// was set" from "the tag was set to an empty string" without dropping
/// the record: the money was still spent.
pub const UNATTRIBUTED: &str = "unattributed";

/// Rollup bucket used once a tracker's configured dimension cardinality
/// has been exhausted. This keeps caller-controlled workspace and team
/// names from growing the live process without bound while retaining the
/// associated usage and cost.
pub const OVERFLOW: &str = "__other__";

/// Default number of recent raw entries retained by a configured tracker.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default maximum number of workspace or team rollup rows retained by a
/// configured tracker. One row is reserved for [`OVERFLOW`].
pub const DEFAULT_MAX_DIMENSIONS: usize = 1_000;

const MAX_DIMENSION_BYTES: usize = 256;

/// A single AI usage event with full attribution metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebackEntry {
    /// Team that owns this usage. [`UNATTRIBUTED`] when the request
    /// carried no `SB-Attr-Team` / governed team tag.
    pub team: String,
    /// Project within the team. Empty when the request carried no
    /// project attribution.
    pub project: String,
    /// AI provider (e.g. `"openai"`, `"anthropic"`).
    pub provider: String,
    /// Model identifier (e.g. `"gpt-4o"`, `"claude-3-5-sonnet"`).
    pub model: String,
    /// Total tokens consumed (prompt + completion).
    pub tokens: u64,
    /// Estimated cost in USD.
    pub cost: f64,
    /// RFC 3339 timestamp for the request, stamped at record time.
    pub timestamp: String,
}

/// Per-workspace totals accumulated through the [`UsageSink`] surface.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceTotals {
    /// Total AI tokens (prompt + completion) recorded for the workspace.
    pub tokens: u64,
    /// Total estimated cost in USD recorded for the workspace.
    pub cost_usd: f64,
    /// Total request count recorded for the workspace.
    pub request_count: u64,
}

impl WorkspaceTotals {
    fn add(&mut self, tokens: u64, cost_usd: f64) {
        self.tokens = self.tokens.saturating_add(tokens);
        let next_cost = self.cost_usd + cost_usd;
        self.cost_usd = if next_cost.is_finite() {
            next_cost
        } else {
            f64::MAX
        };
        self.request_count = self.request_count.saturating_add(1);
    }
}

/// One atomic, owned view of a chargeback tracker.
///
/// Raw entries and both rollup dimensions are copied while holding the
/// tracker's single state lock. A caller therefore cannot observe an event
/// in one surface before it appears in the other surfaces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebackSnapshot {
    /// Maximum recent raw entries retained by this tracker.
    pub max_entries: usize,
    /// Maximum workspace rollup rows, including [`OVERFLOW`].
    pub max_workspaces: usize,
    /// Maximum team rollup rows, including [`OVERFLOW`].
    pub max_teams: usize,
    /// Recent raw entries, oldest first.
    pub entries: Vec<ChargebackEntry>,
    /// All-time workspace totals, bounded by `max_workspaces`.
    pub workspace_totals: BTreeMap<String, WorkspaceTotals>,
    /// All-time team totals, bounded by `max_teams`.
    pub team_totals: BTreeMap<String, WorkspaceTotals>,
    /// Total events accepted since this tracker was created.
    pub recorded_entries: u64,
    /// Raw entries discarded from the front of the retention window.
    pub evicted_entries: u64,
    /// Events whose workspace attribution was folded into [`OVERFLOW`].
    pub collapsed_workspace_events: u64,
    /// Events whose team attribution was folded into [`OVERFLOW`].
    pub collapsed_team_events: u64,
}

#[derive(Debug, Default)]
struct ChargebackState {
    entries: VecDeque<ChargebackEntry>,
    workspace_totals: BTreeMap<String, WorkspaceTotals>,
    team_totals: BTreeMap<String, WorkspaceTotals>,
    recorded_entries: u64,
    evicted_entries: u64,
    collapsed_workspace_events: u64,
    collapsed_team_events: u64,
}

/// Thread-safe store for accumulating [`ChargebackEntry`] records and
/// per-workspace totals, fed by [`UsageSink::record`].
#[derive(Debug)]
pub struct ChargebackTracker {
    max_entries: usize,
    max_workspaces: usize,
    max_teams: usize,
    state: Mutex<ChargebackState>,
}

impl Default for ChargebackTracker {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_MAX_ENTRIES,
            DEFAULT_MAX_DIMENSIONS,
            DEFAULT_MAX_DIMENSIONS,
        )
    }
}

impl ChargebackTracker {
    /// Create a new, empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty tracker with explicit retention and rollup limits.
    ///
    /// Each limit is clamped to at least one. Configuration parsing rejects
    /// zero explicitly; the clamp keeps direct library construction safe and
    /// bounded too.
    pub fn with_limits(max_entries: usize, max_workspaces: usize, max_teams: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_workspaces: max_workspaces.max(1),
            max_teams: max_teams.max(1),
            state: Mutex::new(ChargebackState::default()),
        }
    }

    /// Append a chargeback entry directly, bypassing the [`UsageSink`]
    /// path. Used by tests and by callers that already have a
    /// [`ChargebackEntry`] in hand rather than an [`LlmUsageEvent`].
    pub fn record(&self, entry: ChargebackEntry) {
        self.record_for_workspace(UNATTRIBUTED, entry);
    }

    /// Aggregate total cost per team across all recorded entries.
    pub fn total_by_team(&self) -> HashMap<String, f64> {
        self.state
            .lock()
            .team_totals
            .iter()
            .map(|(team, totals)| (team.clone(), totals.cost_usd))
            .collect()
    }

    /// Return the number of recent entries currently retained.
    pub fn entries_count(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Snapshot the retained recent entries, in record order. Used to feed
    /// [`super::unified::generate_bill`] and [`super::forecast`].
    pub fn entries_snapshot(&self) -> Vec<ChargebackEntry> {
        self.state.lock().entries.iter().cloned().collect()
    }

    /// Snapshot of the per-workspace totals. Returns a fresh `HashMap` so
    /// callers cannot accidentally hold the internal mutex.
    pub fn workspace_totals_snapshot(&self) -> HashMap<String, WorkspaceTotals> {
        self.state
            .lock()
            .workspace_totals
            .iter()
            .map(|(workspace, totals)| (workspace.clone(), totals.clone()))
            .collect()
    }

    /// Return an atomic snapshot of retained entries and all bounded
    /// rollups/counters.
    pub fn snapshot(&self) -> ChargebackSnapshot {
        let state = self.state.lock();
        ChargebackSnapshot {
            max_entries: self.max_entries,
            max_workspaces: self.max_workspaces,
            max_teams: self.max_teams,
            entries: state.entries.iter().cloned().collect(),
            workspace_totals: state.workspace_totals.clone(),
            team_totals: state.team_totals.clone(),
            recorded_entries: state.recorded_entries,
            evicted_entries: state.evicted_entries,
            collapsed_workspace_events: state.collapsed_workspace_events,
            collapsed_team_events: state.collapsed_team_events,
        }
    }

    fn record_for_workspace(&self, workspace: &str, mut entry: ChargebackEntry) {
        entry.team = bounded_dimension(&entry.team, UNATTRIBUTED);
        entry.project = bounded_dimension(&entry.project, "");
        entry.provider = bounded_dimension(&entry.provider, UNATTRIBUTED);
        entry.model = bounded_dimension(&entry.model, UNATTRIBUTED);
        entry.timestamp = bounded_dimension(&entry.timestamp, "");
        entry.cost = valid_cost(entry.cost);
        let workspace = bounded_dimension(workspace, UNATTRIBUTED);

        let mut state = self.state.lock();
        state.recorded_entries = state.recorded_entries.saturating_add(1);
        if state.entries.len() == self.max_entries {
            state.entries.pop_front();
            state.evicted_entries = state.evicted_entries.saturating_add(1);
            crate::ai_metrics::record_chargeback_entry_evicted();
        }
        state.entries.push_back(entry.clone());

        let workspace_collapsed = fold_rollup(
            &mut state.workspace_totals,
            &workspace,
            self.max_workspaces,
            entry.tokens,
            entry.cost,
        );
        if workspace_collapsed {
            state.collapsed_workspace_events = state.collapsed_workspace_events.saturating_add(1);
            crate::ai_metrics::record_chargeback_rollup_collapsed("workspace");
        }
        let team_collapsed = fold_rollup(
            &mut state.team_totals,
            &entry.team,
            self.max_teams,
            entry.tokens,
            entry.cost,
        );
        if team_collapsed {
            state.collapsed_team_events = state.collapsed_team_events.saturating_add(1);
            crate::ai_metrics::record_chargeback_rollup_collapsed("team");
        }
    }
}

fn valid_cost(cost: f64) -> f64 {
    if cost.is_finite() && cost >= 0.0 {
        cost
    } else {
        0.0
    }
}

fn bounded_dimension(value: &str, fallback: &str) -> String {
    let value = if value.is_empty() { fallback } else { value };
    if value.len() <= MAX_DIMENSION_BYTES {
        return value.to_string();
    }
    let mut end = MAX_DIMENSION_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn fold_rollup(
    totals: &mut BTreeMap<String, WorkspaceTotals>,
    requested_key: &str,
    max_dimensions: usize,
    tokens: u64,
    cost_usd: f64,
) -> bool {
    let (key, collapsed) = if totals.contains_key(requested_key) {
        (requested_key.to_string(), false)
    } else if requested_key == OVERFLOW {
        (OVERFLOW.to_string(), false)
    } else if totals.len() < max_dimensions.saturating_sub(1) {
        (requested_key.to_string(), false)
    } else {
        (OVERFLOW.to_string(), true)
    };
    totals.entry(key).or_default().add(tokens, cost_usd);
    collapsed
}

impl UsageSink for ChargebackTracker {
    /// Record one completed AI gateway call.
    ///
    /// Appends a [`ChargebackEntry`] to the per-event log AND folds the
    /// same event into [`WorkspaceTotals`] for `event`'s `tenant_id`, in
    /// one call: unlike the enterprise source's three-partial-calls
    /// design, this sink surface always hands over one complete event,
    /// so there is nothing to keep isolated. A non-finite or negative
    /// `cost_usd` (which should not happen upstream, but this is the
    /// boundary of an external trait) is dropped from the cost side
    /// without dropping the entry itself: the tokens and request count
    /// are still real.
    fn record(&self, event: &LlmUsageEvent) {
        let team = event
            .team
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| UNATTRIBUTED.to_string());
        let project = event.project.clone().unwrap_or_default();
        let workspace = event
            .tenant_id
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| UNATTRIBUTED.to_string());
        let cost = valid_cost(event.cost_usd);

        self.record_for_workspace(
            &workspace,
            ChargebackEntry {
                team,
                project,
                provider: event.provider.clone(),
                model: event.model.clone(),
                tokens: event.total_tokens,
                cost,
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        );
    }

    fn name(&self) -> &str {
        "chargeback"
    }

    fn chargeback_snapshot(&self) -> Option<ChargebackSnapshot> {
        Some(self.snapshot())
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(team: &str, cost: f64) -> ChargebackEntry {
        ChargebackEntry {
            team: team.to_string(),
            project: "p1".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            tokens: 1000,
            cost,
            timestamp: "2026-04-16T00:00:00Z".to_string(),
        }
    }

    fn usage_event(tenant_id: Option<&str>, team: Option<&str>, cost_usd: f64) -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "anthropic".to_string(),
            model: "claude-3-5-sonnet".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            cost_usd,
            latency_ms: 250,
            status: 200,
            key_id: None,
            tenant_id: tenant_id.map(str::to_string),
            project: None,
            user: None,
            team: team.map(str::to_string),
            tags: Vec::new(),
            metadata: Default::default(),
            request_id: None,
            session_id: None,
            tag: None,
            priority: None,
            engine_version: None,
            agent_id: None,
            a2a_context_id: None,
            a2a_identity_verified: None,
            workflow_id: None,
            logical_model: None,
            served_model: None,
            finish_reason: None,
            shadow_of: None,
            credential_source: None,
        }
    }

    #[test]
    fn new_tracker_is_empty() {
        let tracker = ChargebackTracker::new();
        assert_eq!(tracker.entries_count(), 0);
    }

    #[test]
    fn record_increases_count() {
        let tracker = ChargebackTracker::new();
        tracker.record(entry("eng", 1.5));
        assert_eq!(tracker.entries_count(), 1);
        tracker.record(entry("eng", 0.5));
        assert_eq!(tracker.entries_count(), 2);
    }

    #[test]
    fn total_by_team_aggregates_correctly() {
        let tracker = ChargebackTracker::new();
        tracker.record(entry("eng", 1.0));
        tracker.record(entry("eng", 2.0));
        tracker.record(entry("data", 3.0));
        let totals = tracker.total_by_team();
        assert!((totals["eng"] - 3.0).abs() < 0.001);
        assert!((totals["data"] - 3.0).abs() < 0.001);
    }

    #[test]
    fn total_by_team_single_team() {
        let tracker = ChargebackTracker::new();
        tracker.record(entry("platform", 5.0));
        let totals = tracker.total_by_team();
        assert_eq!(totals.len(), 1);
        assert!((totals["platform"] - 5.0).abs() < 0.001);
    }

    #[test]
    fn empty_tracker_returns_empty_totals() {
        let tracker = ChargebackTracker::new();
        assert!(tracker.total_by_team().is_empty());
    }

    #[test]
    fn multiple_teams_are_independent() {
        let tracker = ChargebackTracker::new();
        for i in 0..5 {
            tracker.record(ChargebackEntry {
                team: format!("team-{i}"),
                project: "proj".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-3-haiku".to_string(),
                tokens: 500,
                cost: i as f64,
                timestamp: "2026-04-16T00:00:00Z".to_string(),
            });
        }
        let totals = tracker.total_by_team();
        assert_eq!(totals.len(), 5);
    }

    // --- UsageSink impl coverage ---

    #[test]
    fn usage_sink_routes_tokens_cost_and_request_count() {
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(Some("ws-ai-1"), Some("eng"), 0.42));
        UsageSink::record(&t, &usage_event(Some("ws-ai-1"), Some("eng"), 0.13));

        let snap = t.workspace_totals_snapshot();
        assert_eq!(snap["ws-ai-1"].tokens, 300);
        assert_eq!(snap["ws-ai-1"].request_count, 2);
        assert!((snap["ws-ai-1"].cost_usd - 0.55).abs() < 1e-9);
    }

    #[test]
    fn usage_sink_keeps_separate_totals_per_tenant() {
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(Some("ws-a"), None, 1.0));
        UsageSink::record(&t, &usage_event(Some("ws-b"), None, 2.0));

        let snap = t.workspace_totals_snapshot();
        assert_eq!(snap.len(), 2);
        assert!((snap["ws-a"].cost_usd - 1.0).abs() < 1e-9);
        assert!((snap["ws-b"].cost_usd - 2.0).abs() < 1e-9);
    }

    #[test]
    fn usage_sink_falls_back_to_unattributed_workspace_when_tenant_id_missing() {
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(None, None, 1.0));
        let snap = t.workspace_totals_snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap.contains_key(UNATTRIBUTED));
    }

    #[test]
    fn usage_sink_falls_back_to_unattributed_team_when_team_missing() {
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(Some("ws"), None, 1.0));
        let totals = t.total_by_team();
        assert_eq!(totals.len(), 1);
        assert!(totals.contains_key(UNATTRIBUTED));
    }

    #[test]
    fn usage_sink_clamps_invalid_cost() {
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(Some("ws"), None, -2.0));
        UsageSink::record(&t, &usage_event(Some("ws"), None, f64::NAN));
        UsageSink::record(&t, &usage_event(Some("ws"), None, f64::INFINITY));
        UsageSink::record(&t, &usage_event(Some("ws"), None, 1.0));

        let snap = t.workspace_totals_snapshot();
        // Every call still recorded tokens and a request; only the
        // invalid cost contributions were dropped.
        assert_eq!(snap["ws"].request_count, 4);
        assert!((snap["ws"].cost_usd - 1.0).abs() < 1e-9);
    }

    #[test]
    fn usage_sink_populates_both_event_log_and_workspace_totals() {
        // Unlike the enterprise source's deliberately-isolated design
        // (partial per-kind amounts vs a complete per-event log), one
        // `LlmUsageEvent` is a complete record, so a single sink call
        // must land on both surfaces.
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(Some("ws"), Some("eng"), 1.5));

        assert_eq!(t.entries_count(), 1);
        let totals = t.total_by_team();
        assert!((totals["eng"] - 1.5).abs() < 1e-9);
        let snap = t.workspace_totals_snapshot();
        assert_eq!(snap["ws"].request_count, 1);
    }

    #[test]
    fn workspace_totals_snapshot_is_owned_clone() {
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(Some("ws-snap"), None, 0.0));
        let snap = t.workspace_totals_snapshot();
        UsageSink::record(&t, &usage_event(Some("ws-snap"), None, 0.0));
        assert_eq!(snap["ws-snap"].tokens, 150);
        assert_eq!(t.workspace_totals_snapshot()["ws-snap"].tokens, 300);
    }

    #[test]
    fn entries_snapshot_returns_recorded_entries_in_order() {
        let t = ChargebackTracker::new();
        t.record(entry("a", 1.0));
        t.record(entry("b", 2.0));
        let snap = t.entries_snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].team, "a");
        assert_eq!(snap[1].team, "b");
    }

    #[test]
    fn usage_sink_name_is_stable() {
        let t = ChargebackTracker::new();
        assert_eq!(UsageSink::name(&t), "chargeback");
    }

    #[test]
    fn high_volume_retention_is_bounded_without_losing_rollups() {
        let tracker = ChargebackTracker::with_limits(3, 4, 4);
        for _ in 0..10 {
            UsageSink::record(
                &tracker,
                &usage_event(Some("workspace-a"), Some("team-a"), 0.25),
            );
        }

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.max_entries, 3);
        assert_eq!(snapshot.entries.len(), 3);
        assert_eq!(snapshot.recorded_entries, 10);
        assert_eq!(snapshot.evicted_entries, 7);
        assert_eq!(snapshot.workspace_totals["workspace-a"].request_count, 10);
        assert_eq!(snapshot.team_totals["team-a"].request_count, 10);
    }

    #[test]
    fn dimension_cardinality_is_bounded_and_overflow_is_counted() {
        let tracker = ChargebackTracker::with_limits(20, 2, 2);
        for index in 0..10 {
            UsageSink::record(
                &tracker,
                &usage_event(
                    Some(&format!("workspace-{index}")),
                    Some(&format!("team-{index}")),
                    1.0,
                ),
            );
        }

        let snapshot = tracker.snapshot();
        assert!(snapshot.workspace_totals.len() <= 2);
        assert!(snapshot.team_totals.len() <= 2);
        assert!(snapshot.workspace_totals.contains_key(OVERFLOW));
        assert!(snapshot.team_totals.contains_key(OVERFLOW));
        assert!(snapshot.collapsed_workspace_events > 0);
        assert!(snapshot.collapsed_team_events > 0);
        assert_eq!(
            snapshot
                .workspace_totals
                .values()
                .map(|totals| totals.request_count)
                .sum::<u64>(),
            snapshot.recorded_entries
        );
    }

    #[test]
    fn concurrent_snapshots_never_observe_half_recorded_events() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::sync::Arc;

        let tracker = Arc::new(ChargebackTracker::with_limits(32, 8, 8));
        let finished = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        let writer_tracker = Arc::clone(&tracker);
        let writer_finished = Arc::clone(&finished);
        let writer = std::thread::spawn(move || {
            UsageSink::record(
                writer_tracker.as_ref(),
                &usage_event(Some("workspace-a"), Some("team-a"), 0.01),
            );
            started_tx.send(()).expect("reader is waiting");
            resume_rx.recv().expect("reader releases writer");
            for _ in 1..2_000 {
                UsageSink::record(
                    writer_tracker.as_ref(),
                    &usage_event(Some("workspace-a"), Some("team-a"), 0.01),
                );
                std::thread::yield_now();
            }
            writer_finished.store(true, Ordering::Release);
        });

        started_rx.recv().expect("writer recorded its first event");
        let first = tracker.snapshot();
        assert_eq!(first.recorded_entries, 1);
        let mut snapshots_checked = 1;
        resume_tx.send(()).expect("writer is waiting");
        while !finished.load(Ordering::Acquire) {
            let snapshot = tracker.snapshot();
            snapshots_checked += 1;
            let workspace_requests = snapshot
                .workspace_totals
                .values()
                .map(|totals| totals.request_count)
                .sum::<u64>();
            let team_requests = snapshot
                .team_totals
                .values()
                .map(|totals| totals.request_count)
                .sum::<u64>();
            assert_eq!(workspace_requests, snapshot.recorded_entries);
            assert_eq!(team_requests, snapshot.recorded_entries);
        }

        writer.join().expect("writer joins");
        assert!(
            snapshots_checked > 0,
            "reader observed the concurrent write"
        );
        assert_eq!(tracker.snapshot().recorded_entries, 2_000);
    }
}
