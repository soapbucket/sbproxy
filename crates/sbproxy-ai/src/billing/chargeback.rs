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
//! call, not a partial amount, so one `record()` call updates both the
//! per-event log ([`ChargebackTracker::total_by_team`]) and the
//! per-workspace totals ([`ChargebackTracker::workspace_totals_snapshot`])
//! together, which is simpler than the enterprise source's
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
//! Per the port's disposition, this tracker is in-memory only. The
//! enterprise source's `ChargebackPersistence` (write-behind to a
//! `HashKv`, cross-replica summing via `WorkspaceTotals::merge`) is not
//! ported; an embedder that needs durability drains
//! [`ChargebackTracker::workspace_totals_snapshot`] or
//! [`ChargebackTracker::entries_count`] periodically into its own store,
//! the same way any other [`crate::usage_sink::UsageSink`] would.
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
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::usage_sink::{LlmUsageEvent, UsageSink};

/// Sentinel used for the team, project, or workspace dimension when an
/// [`LlmUsageEvent`] carries no attribution for it. Distinguishes "no tag
/// was set" from "the tag was set to an empty string" without dropping
/// the record: the money was still spent.
pub const UNATTRIBUTED: &str = "unattributed";

/// A single AI usage event with full attribution metadata.
#[derive(Debug, Clone, PartialEq)]
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

/// Thread-safe store for accumulating [`ChargebackEntry`] records and
/// per-workspace totals, fed by [`UsageSink::record`].
#[derive(Debug, Default)]
pub struct ChargebackTracker {
    entries: Mutex<Vec<ChargebackEntry>>,
    workspace_totals: Mutex<HashMap<String, WorkspaceTotals>>,
}

impl ChargebackTracker {
    /// Create a new, empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a chargeback entry directly, bypassing the [`UsageSink`]
    /// path. Used by tests and by callers that already have a
    /// [`ChargebackEntry`] in hand rather than an [`LlmUsageEvent`].
    pub fn record(&self, entry: ChargebackEntry) {
        self.entries.lock().push(entry);
    }

    /// Aggregate total cost per team across all recorded entries.
    pub fn total_by_team(&self) -> HashMap<String, f64> {
        let entries = self.entries.lock();
        let mut totals: HashMap<String, f64> = HashMap::new();
        for e in entries.iter() {
            *totals.entry(e.team.clone()).or_insert(0.0) += e.cost;
        }
        totals
    }

    /// Return the number of entries recorded so far.
    pub fn entries_count(&self) -> usize {
        self.entries.lock().len()
    }

    /// Snapshot every recorded entry, in record order. Used to feed
    /// [`super::unified::generate_bill`] and [`super::forecast`].
    pub fn entries_snapshot(&self) -> Vec<ChargebackEntry> {
        self.entries.lock().clone()
    }

    /// Snapshot of the per-workspace totals. Returns a fresh `HashMap` so
    /// callers cannot accidentally hold the internal mutex.
    pub fn workspace_totals_snapshot(&self) -> HashMap<String, WorkspaceTotals> {
        self.workspace_totals.lock().clone()
    }
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
        let cost = if event.cost_usd.is_finite() && event.cost_usd >= 0.0 {
            event.cost_usd
        } else {
            0.0
        };

        self.entries.lock().push(ChargebackEntry {
            team,
            project,
            provider: event.provider.clone(),
            model: event.model.clone(),
            tokens: event.total_tokens,
            cost,
            timestamp: chrono::Utc::now().to_rfc3339(),
        });

        let mut totals = self.workspace_totals.lock();
        let entry = totals.entry(workspace).or_default();
        entry.tokens = entry.tokens.saturating_add(event.total_tokens);
        entry.cost_usd += cost;
        entry.request_count = entry.request_count.saturating_add(1);
    }

    fn name(&self) -> &str {
        "chargeback"
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
}
