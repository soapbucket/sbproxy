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
//! See `docs/ai-chargeback.md` and `examples/ai_chargeback_billing.rs` for
//! a runnable walkthrough that also exercises [`super::forecast`] and
//! [`super::unified`] against the same tracker.

use parking_lot::Mutex;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
const DIMENSION_DIGEST_SEPARATOR: &str = "~";
const SHA256_HEX_BYTES: usize = 64;
const DIGEST_PROJECTION_LITERAL_PREFIX: &str = "~v~";
const DIGEST_PROJECTION_LITERAL_DOMAIN: &[u8] =
    b"sbproxy:chargeback:digest-projection-literal:v1\0";
const RESERVED_DIMENSION_LITERAL_DOMAIN: &[u8] =
    b"sbproxy:chargeback:reserved-dimension-literal:v1\0";

/// Schema version emitted by [`ChargebackSnapshot`].
pub const CHARGEBACK_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

/// Scope whose exact accounting value could not represent an accepted event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargebackOverflowScope {
    /// Tracker-wide accepted-entry accounting.
    Tracker,
    /// A workspace rollup.
    Workspace,
    /// A team rollup.
    Team,
}

/// Exact aggregate field that would overflow while recording an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargebackOverflowField {
    /// Number of accepted entries.
    RecordedEntries,
    /// Number of requests in a rollup.
    RequestCount,
    /// Token total in a rollup.
    Tokens,
    /// Cost total in a rollup.
    Cost,
}

/// A typed refusal returned when an event cannot be recorded exactly.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Error,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChargebackRecordError {
    /// Cost was negative or non-finite.
    #[error("chargeback cost must be finite and non-negative")]
    InvalidCost,
    /// Timestamp was neither RFC 3339 nor an ISO date.
    #[error("chargeback timestamp must be RFC 3339 or YYYY-MM-DD")]
    InvalidTimestamp,
    /// An exact aggregate could not represent the next value.
    #[error("chargeback arithmetic overflow in {scope:?} {field:?}")]
    ArithmeticOverflow {
        /// Aggregate scope that overflowed.
        scope: ChargebackOverflowScope,
        /// Aggregate field that overflowed.
        field: ChargebackOverflowField,
    },
}

/// Typed workspace/team identity used by schema-v2 snapshots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DimensionKey {
    /// A caller supplied a value, retained as a bounded collision-safe key.
    Value(String),
    /// The caller supplied no value.
    Missing,
    /// Internal bucket for values beyond a configured cardinality ceiling.
    Overflow,
}

impl DimensionKey {
    /// Project a typed dimension onto the legacy schema-v1/CSV string
    /// namespace without merging caller-supplied sentinel literals with the
    /// internal missing and overflow buckets.
    ///
    /// Schema v2 should serialize the typed key directly. This projection is
    /// only for compatibility surfaces whose string-only shape cannot express
    /// [`DimensionKey::Missing`] or [`DimensionKey::Overflow`].
    pub fn legacy_projection(&self) -> Cow<'_, str> {
        match self {
            Self::Value(value) if matches!(value.as_str(), UNATTRIBUTED | OVERFLOW) => {
                Cow::Owned(escaped_reserved_dimension_literal(value))
            }
            Self::Value(value) => Cow::Borrowed(value),
            Self::Missing => Cow::Borrowed(UNATTRIBUTED),
            Self::Overflow => Cow::Borrowed(OVERFLOW),
        }
    }
}

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
    fn checked_with_entry(
        &self,
        tokens: u64,
        cost_usd: f64,
        scope: ChargebackOverflowScope,
    ) -> Result<Self, ChargebackRecordError> {
        let request_count =
            self.request_count
                .checked_add(1)
                .ok_or(ChargebackRecordError::ArithmeticOverflow {
                    scope,
                    field: ChargebackOverflowField::RequestCount,
                })?;
        let tokens =
            self.tokens
                .checked_add(tokens)
                .ok_or(ChargebackRecordError::ArithmeticOverflow {
                    scope,
                    field: ChargebackOverflowField::Tokens,
                })?;
        let cost = checked_money_add(self.cost_usd, cost_usd).ok_or(
            ChargebackRecordError::ArithmeticOverflow {
                scope,
                field: ChargebackOverflowField::Cost,
            },
        )?;
        Ok(Self {
            tokens,
            cost_usd: cost,
            request_count,
        })
    }
}

pub(super) fn checked_money_add(left: f64, right: f64) -> Option<f64> {
    let sum = left + right;
    if !sum.is_finite() || (right > 0.0 && sum == left) || (left > 0.0 && sum == right) {
        None
    } else {
        Some(sum)
    }
}

/// One retained schema-v2 finance row with typed attribution.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(not(test), derive(Clone))]
pub struct ChargebackSnapshotEntry {
    /// Workspace identity carried by the event.
    pub workspace: DimensionKey,
    /// Team identity carried by the event.
    pub team: DimensionKey,
    /// Project within the team.
    pub project: String,
    /// AI provider.
    pub provider: String,
    /// Model identifier.
    pub model: String,
    /// Total tokens consumed.
    pub tokens: u64,
    /// Estimated cost in USD.
    pub cost: f64,
    /// Caller timestamp retained in its validated input representation.
    pub timestamp: String,
}

#[cfg(test)]
impl Clone for ChargebackSnapshotEntry {
    fn clone(&self) -> Self {
        // Observe the language-level operation itself. Unlike a manually
        // maintained "rows cloned" counter beside one implementation, this
        // catches any production path that restores `entry.clone()` or
        // `.iter().cloned()` while either scoped probe is installed.
        observe_chargeback_callsite(|counters| counters.snapshot_entry_clones += 1);
        crate::billing::unified::observe_snapshot_entry_clone();
        Self {
            workspace: self.workspace.clone(),
            team: self.team.clone(),
            project: self.project.clone(),
            provider: self.provider.clone(),
            model: self.model.clone(),
            tokens: self.tokens,
            cost: self.cost,
            timestamp: self.timestamp.clone(),
        }
    }
}

/// One typed dimension rollup in a schema-v2 snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebackRollup {
    /// Typed dimension identity.
    pub dimension: DimensionKey,
    /// Exact totals for this identity or internal overflow bucket.
    pub totals: WorkspaceTotals,
}

/// Bounded aggregate count for one closed refusal reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChargebackRefusalCount {
    /// Typed refusal reason.
    pub reason: ChargebackRecordError,
    /// Saturating number of events refused for this reason.
    pub count: u64,
}

/// Timestamp interval covered by evicted retained rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChargebackEvictionWatermark {
    /// Earliest known evicted timestamp.
    pub min_timestamp: Option<String>,
    /// Latest known evicted timestamp.
    pub max_timestamp: Option<String>,
    /// Whether malformed legacy data prevents a trustworthy interval.
    pub poisoned: bool,
}

/// One atomic, owned view of a chargeback tracker.
///
/// Raw entries and both rollup dimensions are copied while holding the
/// tracker's single state lock. A caller therefore cannot observe an event
/// in one surface before it appears in the other surfaces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebackSnapshot {
    /// Explicit typed snapshot schema version.
    pub schema_version: u32,
    /// Maximum recent raw entries retained by this tracker.
    pub max_entries: usize,
    /// Maximum workspace rollup rows, including [`OVERFLOW`].
    pub max_workspaces: usize,
    /// Maximum team rollup rows, including [`OVERFLOW`].
    pub max_teams: usize,
    /// Recent raw entries, oldest first.
    pub entries: Vec<ChargebackSnapshotEntry>,
    /// All-time typed workspace totals, bounded by `max_workspaces`.
    pub workspace_rollups: Vec<ChargebackRollup>,
    /// All-time typed team totals, bounded by `max_teams`.
    pub team_rollups: Vec<ChargebackRollup>,
    /// Total events accepted since this tracker was created.
    pub recorded_entries: u64,
    /// Raw entries discarded from the front of the retention window.
    pub evicted_entries: u64,
    /// Events whose workspace attribution was folded into [`OVERFLOW`].
    pub collapsed_workspace_events: u64,
    /// Events whose team attribution was folded into [`OVERFLOW`].
    pub collapsed_team_events: u64,
    /// Whether every attempted finance row was represented exactly.
    pub complete: bool,
    /// Saturating number of refused rows.
    pub refused_entries: u64,
    /// Bounded counts for the closed refusal vocabulary.
    pub refusal_counts: Vec<ChargebackRefusalCount>,
    /// Earliest timestamp among retained rows.
    pub earliest_retained_timestamp: Option<String>,
    /// Latest timestamp among retained rows.
    pub latest_retained_timestamp: Option<String>,
    /// Conservative evidence about timestamps removed from retention.
    pub eviction_watermark: ChargebackEvictionWatermark,
}

#[derive(Debug)]
struct ChargebackState {
    entries: VecDeque<ChargebackSnapshotEntry>,
    entry_timestamps: VecDeque<DateTime<Utc>>,
    retained_timestamp_index: BTreeMap<DateTime<Utc>, VecDeque<String>>,
    workspace_totals: BTreeMap<DimensionKey, WorkspaceTotals>,
    team_totals: BTreeMap<DimensionKey, WorkspaceTotals>,
    recorded_entries: u64,
    evicted_entries: u64,
    collapsed_workspace_events: u64,
    collapsed_team_events: u64,
    complete: bool,
    refused_entries: u64,
    refusal_counts: BTreeMap<ChargebackRecordError, u64>,
    earliest_retained_timestamp: Option<String>,
    latest_retained_timestamp: Option<String>,
    eviction_watermark: ChargebackEvictionWatermark,
    earliest_evicted_at: Option<DateTime<Utc>>,
    latest_evicted_at: Option<DateTime<Utc>>,
}

impl Default for ChargebackState {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            entry_timestamps: VecDeque::new(),
            retained_timestamp_index: BTreeMap::new(),
            workspace_totals: BTreeMap::new(),
            team_totals: BTreeMap::new(),
            recorded_entries: 0,
            evicted_entries: 0,
            collapsed_workspace_events: 0,
            collapsed_team_events: 0,
            complete: true,
            refused_entries: 0,
            refusal_counts: BTreeMap::new(),
            earliest_retained_timestamp: None,
            latest_retained_timestamp: None,
            eviction_watermark: ChargebackEvictionWatermark::default(),
            earliest_evicted_at: None,
            latest_evicted_at: None,
        }
    }
}

/// Borrowed, lock-scoped view of one live chargeback tracker.
///
/// The admin export uses this to page and size-admit retained raw rows
/// before materializing them, while still reading exact rollups and
/// counters from the same state snapshot.
pub struct ChargebackExportView<'a> {
    max_entries: usize,
    max_workspaces: usize,
    max_teams: usize,
    entries: &'a VecDeque<ChargebackSnapshotEntry>,
    workspace_totals: &'a BTreeMap<DimensionKey, WorkspaceTotals>,
    team_totals: &'a BTreeMap<DimensionKey, WorkspaceTotals>,
    recorded_entries: u64,
    evicted_entries: u64,
    collapsed_workspace_events: u64,
    collapsed_team_events: u64,
    complete: bool,
    refused_entries: u64,
    refusal_counts: &'a BTreeMap<ChargebackRecordError, u64>,
    earliest_retained_timestamp: Option<&'a str>,
    latest_retained_timestamp: Option<&'a str>,
    eviction_watermark: &'a ChargebackEvictionWatermark,
}

impl<'a> ChargebackExportView<'a> {
    /// Configured raw-entry retention cap for this tracker.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Configured workspace rollup cardinality cap for this tracker.
    pub fn max_workspaces(&self) -> usize {
        self.max_workspaces
    }

    /// Configured team rollup cardinality cap for this tracker.
    pub fn max_teams(&self) -> usize {
        self.max_teams
    }

    /// Current number of retained raw entries.
    pub fn entries_len(&self) -> usize {
        self.entries.len()
    }

    /// Borrow one retained entry page without cloning the retained rows.
    pub fn entries(
        &self,
        offset: usize,
        limit: usize,
    ) -> impl Iterator<Item = &'a ChargebackSnapshotEntry> + 'a {
        self.entries.iter().skip(offset).take(limit)
    }

    /// Borrow the typed workspace rollups currently held by the tracker.
    pub fn workspace_totals(
        &self,
    ) -> impl Iterator<Item = (&'a DimensionKey, &'a WorkspaceTotals)> + 'a {
        self.workspace_totals.iter()
    }

    /// Borrow the typed team rollups currently held by the tracker.
    pub fn team_totals(
        &self,
    ) -> impl Iterator<Item = (&'a DimensionKey, &'a WorkspaceTotals)> + 'a {
        self.team_totals.iter()
    }

    /// Materialize the legacy workspace rollup map with projected names.
    pub fn legacy_workspace_totals(&self) -> HashMap<String, WorkspaceTotals> {
        legacy_totals(self.workspace_totals)
    }

    /// Materialize the legacy team rollup map with projected names.
    pub fn legacy_team_totals(&self) -> HashMap<String, WorkspaceTotals> {
        legacy_totals(self.team_totals)
    }

    /// Total events accepted since tracker creation.
    pub fn recorded_entries(&self) -> u64 {
        self.recorded_entries
    }

    /// Number of retained raw rows evicted from the front of the window.
    pub fn evicted_entries(&self) -> u64 {
        self.evicted_entries
    }

    /// Number of events folded into the workspace overflow bucket.
    pub fn collapsed_workspace_events(&self) -> u64 {
        self.collapsed_workspace_events
    }

    /// Number of events folded into the team overflow bucket.
    pub fn collapsed_team_events(&self) -> u64 {
        self.collapsed_team_events
    }

    /// Whether every attempted finance row was represented exactly.
    pub fn complete(&self) -> bool {
        self.complete
    }

    /// Saturating number of refused rows.
    pub fn refused_entries(&self) -> u64 {
        self.refused_entries
    }

    /// Borrow the closed refusal-count vocabulary as typed rows.
    pub fn refusal_counts(
        &self,
    ) -> impl Iterator<Item = (&'a ChargebackRecordError, &'a u64)> + 'a {
        self.refusal_counts.iter()
    }

    /// Earliest timestamp among retained rows, when one exists.
    pub fn earliest_retained_timestamp(&self) -> Option<&'a str> {
        self.earliest_retained_timestamp
    }

    /// Latest timestamp among retained rows, when one exists.
    pub fn latest_retained_timestamp(&self) -> Option<&'a str> {
        self.latest_retained_timestamp
    }

    /// Conservative evidence about rows evicted from retention.
    pub fn eviction_watermark(&self) -> &'a ChargebackEvictionWatermark {
        self.eviction_watermark
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ChargebackCallsiteCounters {
    accepted_timestamp_parses: usize,
    snapshot_entry_clones: usize,
    accepted_commits: usize,
    finance_metric_publications: usize,
    finance_metric_publications_with_state_lock_held: usize,
}

#[cfg(test)]
std::thread_local! {
    static CHARGEBACK_CALLSITE_COUNTERS: std::cell::RefCell<Option<ChargebackCallsiteCounters>> =
        std::cell::RefCell::new(None);
}

/// Scoped, current-thread observation of the real accepted-record callsites.
///
/// Timestamp parsing is observed at the parser and entry cloning is observed
/// by the test-only manual [`Clone`] implementation, so restoring a retained
/// row scan/reparse/clone cannot pass through unwritten zero counters.
#[cfg(test)]
struct ChargebackCallsiteProbe;

#[cfg(test)]
impl ChargebackCallsiteProbe {
    fn install_for_current_thread() -> Self {
        CHARGEBACK_CALLSITE_COUNTERS.with(|slot| {
            let previous = slot.replace(Some(ChargebackCallsiteCounters::default()));
            assert!(
                previous.is_none(),
                "chargeback callsite probe already installed"
            );
        });
        Self
    }

    fn counters(&self) -> ChargebackCallsiteCounters {
        CHARGEBACK_CALLSITE_COUNTERS.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("chargeback callsite probe is installed")
                .clone()
        })
    }
}

#[cfg(test)]
impl Drop for ChargebackCallsiteProbe {
    fn drop(&mut self) {
        CHARGEBACK_CALLSITE_COUNTERS.with(|slot| {
            let _ = slot.replace(None);
        });
    }
}

#[cfg(test)]
fn observe_chargeback_callsite(update: impl FnOnce(&mut ChargebackCallsiteCounters)) {
    CHARGEBACK_CALLSITE_COUNTERS.with(|slot| {
        if let Some(counters) = slot.borrow_mut().as_mut() {
            update(counters);
        }
    });
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
        let _ = self.try_record(None, entry);
    }

    /// Try to append one row as a single checked finance transaction.
    ///
    /// Any refusal updates only bounded refusal evidence and permanently
    /// marks later snapshots incomplete. Retained rows, rollups, retention
    /// counters, and accepted-entry accounting remain unchanged.
    pub fn try_record(
        &self,
        workspace: Option<&str>,
        entry: ChargebackEntry,
    ) -> Result<(), ChargebackRecordError> {
        let workspace = dimension_key(workspace);
        let team = dimension_key((!entry.team.is_empty()).then_some(entry.team.as_str()));
        self.try_record_attributed(workspace, team, entry)
    }

    /// Aggregate total cost per team across all recorded entries.
    pub fn total_by_team(&self) -> HashMap<String, f64> {
        let state = self.state.lock();
        let mut result = HashMap::new();
        for (team, totals) in &state.team_totals {
            let value = result
                .entry(team.legacy_projection().into_owned())
                .or_insert(0.0);
            let next = *value + totals.cost_usd;
            *value = if next.is_finite() { next } else { f64::MAX };
        }
        result
    }

    /// Return the number of recent entries currently retained.
    pub fn entries_count(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Snapshot the retained recent entries, in record order.
    ///
    /// This is the lower-level retained-slice surface for callers that can
    /// independently prove the billed period is complete. Use
    /// [`super::unified::generate_bill_from_snapshot`] for the safe
    /// snapshot-aware billing path, and [`super::forecast`] when only the
    /// retained window matters.
    pub fn entries_snapshot(&self) -> Vec<ChargebackEntry> {
        self.state.lock().entries.iter().map(legacy_entry).collect()
    }

    /// Snapshot of the per-workspace totals. Returns a fresh `HashMap` so
    /// callers cannot accidentally hold the internal mutex.
    pub fn workspace_totals_snapshot(&self) -> HashMap<String, WorkspaceTotals> {
        legacy_totals(&self.state.lock().workspace_totals)
    }

    /// Return an atomic snapshot of retained entries and all bounded
    /// rollups/counters.
    pub fn snapshot(&self) -> ChargebackSnapshot {
        let state = self.state.lock();
        ChargebackSnapshot {
            schema_version: CHARGEBACK_SNAPSHOT_SCHEMA_VERSION,
            max_entries: self.max_entries,
            max_workspaces: self.max_workspaces,
            max_teams: self.max_teams,
            entries: state.entries.iter().cloned().collect(),
            workspace_rollups: rollup_snapshot(&state.workspace_totals),
            team_rollups: rollup_snapshot(&state.team_totals),
            recorded_entries: state.recorded_entries,
            evicted_entries: state.evicted_entries,
            collapsed_workspace_events: state.collapsed_workspace_events,
            collapsed_team_events: state.collapsed_team_events,
            complete: state.complete,
            refused_entries: state.refused_entries,
            refusal_counts: state
                .refusal_counts
                .iter()
                .map(|(reason, count)| ChargebackRefusalCount {
                    reason: *reason,
                    count: *count,
                })
                .collect(),
            earliest_retained_timestamp: state.earliest_retained_timestamp.clone(),
            latest_retained_timestamp: state.latest_retained_timestamp.clone(),
            eviction_watermark: state.eviction_watermark.clone(),
        }
    }

    /// Borrow the live tracker state under its one lock for export work that
    /// must page or size-admit retained rows before cloning them.
    pub fn with_export_view<R>(&self, f: impl FnOnce(ChargebackExportView<'_>) -> R) -> R {
        let state = self.state.lock();
        f(ChargebackExportView {
            max_entries: self.max_entries,
            max_workspaces: self.max_workspaces,
            max_teams: self.max_teams,
            entries: &state.entries,
            workspace_totals: &state.workspace_totals,
            team_totals: &state.team_totals,
            recorded_entries: state.recorded_entries,
            evicted_entries: state.evicted_entries,
            collapsed_workspace_events: state.collapsed_workspace_events,
            collapsed_team_events: state.collapsed_team_events,
            complete: state.complete,
            refused_entries: state.refused_entries,
            refusal_counts: &state.refusal_counts,
            earliest_retained_timestamp: state.earliest_retained_timestamp.as_deref(),
            latest_retained_timestamp: state.latest_retained_timestamp.as_deref(),
            eviction_watermark: &state.eviction_watermark,
        })
    }

    fn try_record_attributed(
        &self,
        workspace: DimensionKey,
        team: DimensionKey,
        entry: ChargebackEntry,
    ) -> Result<(), ChargebackRecordError> {
        if !entry.cost.is_finite() || entry.cost < 0.0 {
            let error = ChargebackRecordError::InvalidCost;
            self.record_refusal(error);
            return Err(error);
        }
        if entry.timestamp.len() > MAX_DIMENSION_BYTES {
            let error = ChargebackRecordError::InvalidTimestamp;
            self.record_refusal(error);
            return Err(error);
        }
        let Some(parsed_timestamp) = parse_chargeback_timestamp(&entry.timestamp) else {
            let error = ChargebackRecordError::InvalidTimestamp;
            self.record_refusal(error);
            return Err(error);
        };

        let normalized = ChargebackSnapshotEntry {
            workspace,
            team,
            project: bounded_text(&entry.project, ""),
            provider: bounded_text(&entry.provider, UNATTRIBUTED),
            model: bounded_text(&entry.model, UNATTRIBUTED),
            tokens: entry.tokens,
            cost: entry.cost,
            timestamp: entry.timestamp,
        };
        let mut state = self.state.lock();

        let next_recorded_entries = match state.recorded_entries.checked_add(1) {
            Some(next) => next,
            None => {
                let error = ChargebackRecordError::ArithmeticOverflow {
                    scope: ChargebackOverflowScope::Tracker,
                    field: ChargebackOverflowField::RecordedEntries,
                };
                let outcome = refuse_locked(&mut state, error);
                drop(state);
                self.publish_refusal(outcome, error);
                return Err(error);
            }
        };
        let (workspace_key, workspace_collapsed) = rollup_key(
            &state.workspace_totals,
            &normalized.workspace,
            self.max_workspaces,
        );
        let next_workspace = match state
            .workspace_totals
            .get(&workspace_key)
            .cloned()
            .unwrap_or_default()
            .checked_with_entry(
                normalized.tokens,
                normalized.cost,
                ChargebackOverflowScope::Workspace,
            ) {
            Ok(next) => next,
            Err(error) => {
                let outcome = refuse_locked(&mut state, error);
                drop(state);
                self.publish_refusal(outcome, error);
                return Err(error);
            }
        };
        let (team_key, team_collapsed) =
            rollup_key(&state.team_totals, &normalized.team, self.max_teams);
        let next_team = match state
            .team_totals
            .get(&team_key)
            .cloned()
            .unwrap_or_default()
            .checked_with_entry(
                normalized.tokens,
                normalized.cost,
                ChargebackOverflowScope::Team,
            ) {
            Ok(next) => next,
            Err(error) => {
                let outcome = refuse_locked(&mut state, error);
                drop(state);
                self.publish_refusal(outcome, error);
                return Err(error);
            }
        };

        let mut entry_evicted = false;
        let mut first_watermark_poison = false;
        if state.entries.len() == self.max_entries {
            if let Some(evicted) = state.entries.pop_front() {
                let evicted_at = state
                    .entry_timestamps
                    .pop_front()
                    .or_else(|| parse_chargeback_timestamp(&evicted.timestamp));
                first_watermark_poison = note_eviction(&mut state, &evicted.timestamp, evicted_at);
                if let Some(evicted_at) = evicted_at {
                    remove_retained_timestamp(&mut state, evicted_at);
                }
            }
            state.evicted_entries = state.evicted_entries.saturating_add(1);
            entry_evicted = true;
        }
        insert_retained_timestamp(&mut state, parsed_timestamp, normalized.timestamp.as_str());
        state.entries.push_back(normalized);
        state.entry_timestamps.push_back(parsed_timestamp);
        state.recorded_entries = next_recorded_entries;
        state.workspace_totals.insert(workspace_key, next_workspace);
        state.team_totals.insert(team_key, next_team);
        if workspace_collapsed {
            state.collapsed_workspace_events = state.collapsed_workspace_events.saturating_add(1);
        }
        if team_collapsed {
            state.collapsed_team_events = state.collapsed_team_events.saturating_add(1);
        }
        #[cfg(test)]
        observe_chargeback_callsite(|counters| counters.accepted_commits += 1);
        drop(state);
        if entry_evicted {
            self.publish_finance_metric(|| {
                crate::ai_metrics::record_chargeback_entry_evicted();
            });
        }
        if workspace_collapsed {
            self.publish_finance_metric(|| {
                crate::ai_metrics::record_chargeback_rollup_collapsed("workspace");
            });
        }
        if team_collapsed {
            self.publish_finance_metric(|| {
                crate::ai_metrics::record_chargeback_rollup_collapsed("team");
            });
        }
        if first_watermark_poison {
            self.publish_finance_metric(|| {
                crate::ai_metrics::record_chargeback_incomplete(
                    crate::ai_metrics::ChargebackIncompleteReason::EvictionWatermarkPoisoned,
                );
            });
        }
        signal_first_watermark_poison(first_watermark_poison);
        Ok(())
    }

    fn record_refusal(&self, error: ChargebackRecordError) {
        let outcome = {
            let mut state = self.state.lock();
            refuse_locked(&mut state, error)
        };
        self.publish_refusal(outcome, error);
    }

    fn publish_refusal(&self, outcome: RefusalOutcome, error: ChargebackRecordError) {
        self.publish_finance_metric(|| crate::ai_metrics::record_chargeback_refusal(error));
        if outcome.became_incomplete {
            self.publish_finance_metric(|| {
                crate::ai_metrics::record_chargeback_incomplete(
                    crate::ai_metrics::ChargebackIncompleteReason::RefusedRow,
                );
            });
        }
        signal_first_refusal(outcome.first_occurrence, error);
    }

    fn publish_finance_metric(&self, publish: impl FnOnce()) {
        #[cfg(test)]
        {
            let state_lock_held = self.state.try_lock().is_none();
            observe_chargeback_callsite(|counters| {
                counters.finance_metric_publications += 1;
                if state_lock_held {
                    counters.finance_metric_publications_with_state_lock_held += 1;
                }
            });
        }
        publish();
    }
}

#[derive(Debug, Clone, Copy)]
struct RefusalOutcome {
    first_occurrence: bool,
    became_incomplete: bool,
}

fn refuse_locked(state: &mut ChargebackState, error: ChargebackRecordError) -> RefusalOutcome {
    let became_incomplete = state.complete;
    if became_incomplete {
        state.complete = false;
    }
    state.refused_entries = state.refused_entries.saturating_add(1);
    let first_occurrence = match state.refusal_counts.entry(error) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(1);
            true
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let count = entry.get_mut();
            *count = count.saturating_add(1);
            false
        }
    };
    RefusalOutcome {
        first_occurrence,
        became_incomplete,
    }
}

fn signal_first_refusal(first_occurrence: bool, error: ChargebackRecordError) {
    if first_occurrence {
        tracing::warn!(
            target: "sbproxy_ai::billing::chargeback",
            code = "chargeback_row_refused",
            reason = ?error,
            "chargeback usage row refused"
        );
    }
}

fn signal_first_watermark_poison(first_occurrence: bool) {
    if first_occurrence {
        tracing::warn!(
            target: "sbproxy_ai::billing::chargeback",
            code = "chargeback_eviction_watermark_poisoned",
            reason = "eviction_watermark_poisoned",
            "chargeback eviction watermark poisoned"
        );
    }
}

fn dimension_key(value: Option<&str>) -> DimensionKey {
    match value {
        Some(value) => DimensionKey::Value(bounded_text(value, "")),
        None => DimensionKey::Missing,
    }
}

fn escaped_reserved_dimension_literal(value: &str) -> String {
    debug_assert!(matches!(value, UNATTRIBUTED | OVERFLOW));
    let mut digest = Sha256::new();
    digest.update(RESERVED_DIMENSION_LITERAL_DOMAIN);
    digest.update(value.as_bytes());
    format!(
        "{value}{DIMENSION_DIGEST_SEPARATOR}{}",
        hex::encode(digest.finalize())
    )
}

fn bounded_text(value: &str, fallback: &str) -> String {
    let value = if value.is_empty() { fallback } else { value };
    if value.len() <= MAX_DIMENSION_BYTES {
        if is_digest_projection_literal(value) {
            let mut digest = Sha256::new();
            digest.update(DIGEST_PROJECTION_LITERAL_DOMAIN);
            digest.update(value.as_bytes());
            return format!(
                "{DIGEST_PROJECTION_LITERAL_PREFIX}{}",
                hex::encode(digest.finalize())
            );
        }
        return value.to_string();
    }
    let digest = Sha256::digest(value.as_bytes());
    let suffix = format!("{DIMENSION_DIGEST_SEPARATOR}{}", hex::encode(digest));
    debug_assert_eq!(
        suffix.len(),
        DIMENSION_DIGEST_SEPARATOR.len() + SHA256_HEX_BYTES
    );
    let mut end = MAX_DIMENSION_BYTES - suffix.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &value[..end], suffix)
}

fn is_digest_projection_literal(value: &str) -> bool {
    let Some((prefix, digest)) = value.rsplit_once(DIMENSION_DIGEST_SEPARATOR) else {
        return false;
    };
    // A UTF-8-safe cut can shorten the 256-byte projection by at most three
    // bytes. The second shape reserves this function's own escape namespace.
    let has_generated_length =
        (MAX_DIMENSION_BYTES.saturating_sub(3)..=MAX_DIMENSION_BYTES).contains(&value.len());
    let is_literal_escape = value.len()
        == DIGEST_PROJECTION_LITERAL_PREFIX.len() + SHA256_HEX_BYTES
        && value.starts_with(DIGEST_PROJECTION_LITERAL_PREFIX);
    let is_reserved_literal_escape = matches!(prefix, UNATTRIBUTED | OVERFLOW)
        && value.len() == prefix.len() + DIMENSION_DIGEST_SEPARATOR.len() + SHA256_HEX_BYTES;
    (has_generated_length || is_literal_escape || is_reserved_literal_escape)
        && digest.len() == SHA256_HEX_BYTES
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn rollup_key(
    totals: &BTreeMap<DimensionKey, WorkspaceTotals>,
    requested_key: &DimensionKey,
    max_dimensions: usize,
) -> (DimensionKey, bool) {
    if totals.contains_key(requested_key) {
        (requested_key.clone(), false)
    } else if totals.len() < max_dimensions.saturating_sub(1) {
        (requested_key.clone(), false)
    } else {
        (DimensionKey::Overflow, true)
    }
}

fn parse_chargeback_timestamp(value: &str) -> Option<DateTime<Utc>> {
    #[cfg(test)]
    observe_chargeback_callsite(|counters| counters.accepted_timestamp_parses += 1);
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()?
                .and_hms_opt(0, 0, 0)
                .map(|timestamp| timestamp.and_utc())
        })
}

fn note_eviction(
    state: &mut ChargebackState,
    timestamp: &str,
    evicted_at: Option<DateTime<Utc>>,
) -> bool {
    let Some(evicted_at) = evicted_at else {
        let first_poison = !state.eviction_watermark.poisoned;
        if first_poison {
            state.eviction_watermark.poisoned = true;
        }
        state.complete = false;
        return first_poison;
    };
    if state
        .earliest_evicted_at
        .as_ref()
        .is_none_or(|current| &evicted_at < current)
    {
        state.earliest_evicted_at = Some(evicted_at);
        state.eviction_watermark.min_timestamp = Some(timestamp.to_string());
    }
    if state
        .latest_evicted_at
        .as_ref()
        .is_none_or(|current| &evicted_at > current)
    {
        state.latest_evicted_at = Some(evicted_at);
        state.eviction_watermark.max_timestamp = Some(timestamp.to_string());
    }
    false
}

fn insert_retained_timestamp(
    state: &mut ChargebackState,
    timestamp: DateTime<Utc>,
    timestamp_text: &str,
) {
    state
        .retained_timestamp_index
        .entry(timestamp)
        .or_default()
        .push_back(timestamp_text.to_string());
    refresh_retained_extrema(state);
}

fn remove_retained_timestamp(state: &mut ChargebackState, timestamp: DateTime<Utc>) {
    let remove_bucket = if let Some(bucket) = state.retained_timestamp_index.get_mut(&timestamp) {
        let removed = bucket.pop_front();
        debug_assert!(removed.is_some(), "retained timestamp bucket is non-empty");
        bucket.is_empty()
    } else {
        false
    };
    if remove_bucket {
        state.retained_timestamp_index.remove(&timestamp);
    }
    refresh_retained_extrema(state);
}

fn refresh_retained_extrema(state: &mut ChargebackState) {
    state.earliest_retained_timestamp = state
        .retained_timestamp_index
        .first_key_value()
        .and_then(|(_, timestamps)| timestamps.front())
        .cloned();
    state.latest_retained_timestamp = state
        .retained_timestamp_index
        .last_key_value()
        .and_then(|(_, timestamps)| timestamps.front())
        .cloned();
}

fn rollup_snapshot(totals: &BTreeMap<DimensionKey, WorkspaceTotals>) -> Vec<ChargebackRollup> {
    totals
        .iter()
        .map(|(dimension, totals)| ChargebackRollup {
            dimension: dimension.clone(),
            totals: totals.clone(),
        })
        .collect()
}

fn legacy_entry(entry: &ChargebackSnapshotEntry) -> ChargebackEntry {
    #[cfg(test)]
    crate::billing::unified::observe_legacy_entry_materialization();
    ChargebackEntry {
        team: entry.team.legacy_projection().into_owned(),
        project: entry.project.clone(),
        provider: entry.provider.clone(),
        model: entry.model.clone(),
        tokens: entry.tokens,
        cost: entry.cost,
        timestamp: entry.timestamp.clone(),
    }
}

fn legacy_totals(
    totals: &BTreeMap<DimensionKey, WorkspaceTotals>,
) -> HashMap<String, WorkspaceTotals> {
    let mut result: HashMap<String, WorkspaceTotals> = HashMap::new();
    for (dimension, source) in totals {
        let target = result
            .entry(dimension.legacy_projection().into_owned())
            .or_default();
        target.tokens = target.tokens.saturating_add(source.tokens);
        target.request_count = target.request_count.saturating_add(source.request_count);
        let cost = target.cost_usd + source.cost_usd;
        target.cost_usd = if cost.is_finite() { cost } else { f64::MAX };
    }
    result
}

impl UsageSink for ChargebackTracker {
    /// Record one completed AI gateway call.
    ///
    /// Appends a [`ChargebackEntry`] to the per-event log AND folds the
    /// same event into [`WorkspaceTotals`] for `event`'s `tenant_id`, in
    /// one call: unlike the enterprise source's three-partial-calls
    /// design, this sink surface always hands over one complete event,
    /// so there is nothing to keep isolated. Invalid or unrepresentable
    /// finance rows are refused atomically and leave typed, bounded evidence
    /// in the next snapshot.
    fn record(&self, event: &LlmUsageEvent) {
        let workspace = dimension_key(event.tenant_id.as_deref());
        let team = dimension_key(event.team.as_deref());
        let _ = self.try_record_attributed(
            workspace,
            team,
            ChargebackEntry {
                team: event.team.clone().unwrap_or_default(),
                project: event.project.clone().unwrap_or_default(),
                provider: event.provider.clone(),
                model: event.model.clone(),
                tokens: event.total_tokens,
                cost: event.cost_usd,
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

    fn chargeback_tracker(&self) -> Option<&ChargebackTracker> {
        Some(self)
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CapturedChargebackRefusalSignal {
        reason: String,
        rendered_fields: Vec<String>,
        state_lock_available: bool,
    }

    struct ChargebackRefusalSignalVisitor {
        reason: Option<String>,
        rendered_fields: Vec<String>,
    }

    impl ChargebackRefusalSignalVisitor {
        fn record_value(&mut self, field: &tracing::field::Field, value: String) {
            if field.name() == "reason" {
                self.reason = Some(value.clone());
            }
            self.rendered_fields
                .push(format!("{}={value}", field.name()));
        }
    }

    impl tracing::field::Visit for ChargebackRefusalSignalVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.record_value(field, format!("{value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.record_value(field, value.to_string());
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.record_value(field, value.to_string());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.record_value(field, value.to_string());
        }

        fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
            self.record_value(field, value.to_string());
        }

        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            self.record_value(field, value.to_string());
        }
    }

    #[derive(Clone)]
    struct ChargebackRefusalSignalLayer {
        tracker: std::sync::Arc<ChargebackTracker>,
        signals: std::sync::Arc<std::sync::Mutex<Vec<CapturedChargebackRefusalSignal>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ChargebackRefusalSignalLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() != "sbproxy_ai::billing::chargeback"
                || *event.metadata().level() != tracing::Level::WARN
            {
                return;
            }
            let mut visitor = ChargebackRefusalSignalVisitor {
                reason: None,
                rendered_fields: Vec::new(),
            };
            event.record(&mut visitor);
            let Some(reason) = visitor.reason else {
                return;
            };
            let signal = CapturedChargebackRefusalSignal {
                reason,
                rendered_fields: visitor.rendered_fields,
                state_lock_available: self.tracker.state.try_lock().is_some(),
            };
            self.signals
                .lock()
                .expect("chargeback refusal signal capture mutex poisoned")
                .push(signal);
        }
    }

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

    fn counter_total(name: &str, labels: &[(&str, &str)]) -> u64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == name)
            .and_then(|family| {
                family.get_metric().iter().find_map(|metric| {
                    labels
                        .iter()
                        .all(|(key, value)| {
                            metric
                                .get_label()
                                .iter()
                                .any(|pair| pair.name() == *key && pair.value() == *value)
                        })
                        .then(|| metric.get_counter().value() as u64)
                })
            })
            .unwrap_or(0)
    }

    fn value_key(value: &str) -> DimensionKey {
        dimension_key(Some(value))
    }

    fn workspace_rollup<'a>(
        snapshot: &'a ChargebackSnapshot,
        dimension: &DimensionKey,
    ) -> Option<&'a WorkspaceTotals> {
        snapshot
            .workspace_rollups
            .iter()
            .find(|rollup| &rollup.dimension == dimension)
            .map(|rollup| &rollup.totals)
    }

    fn team_rollup<'a>(
        snapshot: &'a ChargebackSnapshot,
        dimension: &DimensionKey,
    ) -> Option<&'a WorkspaceTotals> {
        snapshot
            .team_rollups
            .iter()
            .find(|rollup| &rollup.dimension == dimension)
            .map(|rollup| &rollup.totals)
    }

    fn workspace_values(snapshot: &ChargebackSnapshot) -> Vec<String> {
        let mut values: Vec<String> = snapshot
            .workspace_rollups
            .iter()
            .filter_map(|rollup| match &rollup.dimension {
                DimensionKey::Value(value) => Some(value.clone()),
                DimensionKey::Missing | DimensionKey::Overflow => None,
            })
            .collect();
        values.sort();
        values
    }

    fn team_values(snapshot: &ChargebackSnapshot) -> Vec<String> {
        let mut values: Vec<String> = snapshot
            .team_rollups
            .iter()
            .filter_map(|rollup| match &rollup.dimension {
                DimensionKey::Value(value) => Some(value.clone()),
                DimensionKey::Missing | DimensionKey::Overflow => None,
            })
            .collect();
        values.sort();
        values
    }

    fn refusal_count(snapshot: &ChargebackSnapshot, reason: &ChargebackRecordError) -> u64 {
        snapshot
            .refusal_counts
            .iter()
            .find(|refusal| &refusal.reason == reason)
            .map_or(0, |refusal| refusal.count)
    }

    fn assert_financial_state_unchanged(before: &ChargebackSnapshot, after: &ChargebackSnapshot) {
        assert_eq!(
            after.entries, before.entries,
            "a refused event must not enter retained finance rows"
        );
        assert_eq!(
            after.workspace_rollups, before.workspace_rollups,
            "a refused event must not alter workspace rollups"
        );
        assert_eq!(
            after.team_rollups, before.team_rollups,
            "a refused event must not alter team rollups"
        );
        assert_eq!(
            after.recorded_entries, before.recorded_entries,
            "a refused event must not be counted as accepted"
        );
        assert_eq!(
            after.evicted_entries, before.evicted_entries,
            "a refused event must not evict a valid retained row"
        );
        assert_eq!(
            after.collapsed_workspace_events, before.collapsed_workspace_events,
            "a refused event must not consume workspace cardinality"
        );
        assert_eq!(
            after.collapsed_team_events, before.collapsed_team_events,
            "a refused event must not consume team cardinality"
        );
        assert_eq!(
            after.earliest_retained_timestamp, before.earliest_retained_timestamp,
            "a refused event must not alter the retained lower timestamp"
        );
        assert_eq!(
            after.latest_retained_timestamp, before.latest_retained_timestamp,
            "a refused event must not alter the retained upper timestamp"
        );
        assert_eq!(
            after.eviction_watermark, before.eviction_watermark,
            "a refused event must not alter eviction evidence"
        );
    }

    fn assert_refusal_delta(
        before: &ChargebackSnapshot,
        after: &ChargebackSnapshot,
        reason: &ChargebackRecordError,
    ) {
        assert_eq!(
            after.refused_entries.checked_sub(before.refused_entries),
            Some(1),
            "one refused record must produce one bounded refusal delta"
        );
        assert_eq!(
            refusal_count(after, reason).checked_sub(refusal_count(before, reason)),
            Some(1),
            "the closed refusal reason must receive the delta"
        );
        let before_selected = before
            .refusal_counts
            .iter()
            .filter(|refusal| &refusal.reason == reason)
            .collect::<Vec<_>>();
        let after_selected = after
            .refusal_counts
            .iter()
            .filter(|refusal| &refusal.reason == reason)
            .collect::<Vec<_>>();
        assert!(
            before_selected.len() <= 1 && after_selected.len() == 1,
            "one closed reason must have exactly one aggregate row"
        );
        assert_eq!(
            after.refusal_counts.len(),
            before.refusal_counts.len() + if before_selected.is_empty() { 1 } else { 0 },
            "only a previously absent selected reason may add a row"
        );
        for before_row in &before.refusal_counts {
            let after_row = after
                .refusal_counts
                .iter()
                .find(|candidate| &candidate.reason == &before_row.reason)
                .expect("every preexisting refusal row must remain present");
            let expected = if &before_row.reason == reason {
                before_row
                    .count
                    .checked_add(1)
                    .expect("ordinary refusal-delta fixtures stay below saturation")
            } else {
                before_row.count
            };
            assert_eq!(
                after_row.count, expected,
                "every unselected reason must remain byte-for-byte unchanged"
            );
        }
        for after_row in &after.refusal_counts {
            if &after_row.reason != reason {
                assert!(
                    before.refusal_counts.iter().any(|before_row| {
                        &before_row.reason == &after_row.reason
                            && before_row.count == after_row.count
                    }),
                    "a refusal must not create or alter any unselected reason"
                );
            }
        }
        assert!(
            !after.complete,
            "a finance refusal must poison completeness"
        );
    }

    fn overflow_scope_name(scope: &ChargebackOverflowScope) -> &'static str {
        match scope {
            ChargebackOverflowScope::Tracker => "tracker",
            ChargebackOverflowScope::Workspace => "workspace",
            ChargebackOverflowScope::Team => "team",
        }
    }

    fn overflow_field_name(field: &ChargebackOverflowField) -> &'static str {
        match field {
            ChargebackOverflowField::RecordedEntries => "recorded_entries",
            ChargebackOverflowField::RequestCount => "request_count",
            ChargebackOverflowField::Tokens => "tokens",
            ChargebackOverflowField::Cost => "cost",
        }
    }

    fn record_error_name(error: &ChargebackRecordError) -> &'static str {
        match error {
            ChargebackRecordError::InvalidCost => "invalid_cost",
            ChargebackRecordError::InvalidTimestamp => "invalid_timestamp",
            ChargebackRecordError::ArithmeticOverflow { scope, field } => {
                let _ = (overflow_scope_name(scope), overflow_field_name(field));
                "arithmetic_overflow"
            }
        }
    }

    fn assert_live_invalid_cost_is_transactionally_refused(cost_usd: f64) {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-a"), 1.0),
        );
        let before = tracker.snapshot();
        assert_eq!(before.recorded_entries, 1, "the valid control must commit");

        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-a"), cost_usd),
        );

        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &ChargebackRecordError::InvalidCost);
    }

    fn long_multibyte_dimension(suffix: &str) -> String {
        // 86 copies occupy 258 bytes, so the differentiating suffix starts
        // beyond the current 256-byte prefix and also exercises a split
        // inside a three-byte UTF-8 code point.
        format!("{}-{suffix}", "界".repeat(86))
    }

    fn long_ascii_dimension(suffix: &str) -> String {
        format!("{}-{suffix}", "x".repeat(270))
    }

    fn record_at(
        tracker: &ChargebackTracker,
        workspace: Option<&str>,
        team: &str,
        timestamp: &str,
        cost: f64,
    ) -> Result<(), ChargebackRecordError> {
        let mut input = entry(team, cost);
        input.timestamp = timestamp.to_string();
        tracker.try_record(workspace, input)
    }

    fn snapshot_entry(
        workspace: DimensionKey,
        team: DimensionKey,
        timestamp: &str,
    ) -> ChargebackSnapshotEntry {
        ChargebackSnapshotEntry {
            workspace,
            team,
            project: "p1".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            tokens: 1000,
            cost: 1.0,
            timestamp: timestamp.to_string(),
        }
    }

    fn long_dimension_snapshot() -> (ChargebackSnapshot, Vec<String>) {
        let tracker = ChargebackTracker::with_limits(16, 3, 3);
        let mut raw_dimensions = Vec::new();
        for index in 0..8 {
            let dimension = long_multibyte_dimension(&index.to_string());
            UsageSink::record(
                &tracker,
                &usage_event(Some(&dimension), Some(&dimension), 1.0),
            );
            raw_dimensions.push(dimension);
        }
        (tracker.snapshot(), raw_dimensions)
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
    fn usage_sink_invalid_cost_refusal_stays_incomplete_after_a_valid_record() {
        let t = ChargebackTracker::new();
        UsageSink::record(&t, &usage_event(Some("ws"), Some("team"), -2.0));
        let refused = t.snapshot();
        assert_eq!(refused.entries.len(), 0);
        assert_eq!(refused.refused_entries, 1);
        assert_eq!(
            refusal_count(&refused, &ChargebackRecordError::InvalidCost),
            1
        );
        assert!(!refused.complete);

        UsageSink::record(&t, &usage_event(Some("ws"), None, 1.0));

        let after_valid = t.snapshot();
        assert_eq!(after_valid.entries.len(), 1);
        assert_eq!(after_valid.refused_entries, 1);
        assert!(
            !after_valid.complete,
            "later success must not erase a refusal"
        );
    }

    #[test]
    fn group_f_live_usage_sink_refuses_negative_cost_transactionally() {
        assert_live_invalid_cost_is_transactionally_refused(-0.01);
    }

    #[test]
    fn group_f_live_usage_sink_refuses_nan_cost_transactionally() {
        assert_live_invalid_cost_is_transactionally_refused(f64::NAN);
    }

    #[test]
    fn group_f_live_usage_sink_refuses_infinite_cost_transactionally() {
        assert_live_invalid_cost_is_transactionally_refused(f64::INFINITY);
    }

    #[test]
    fn group_f_live_usage_sink_refuses_valid_cost_arithmetic_overflow_transactionally() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", f64::MAX)),
            Ok(())
        );
        let before = tracker.snapshot();
        assert!(
            before.complete,
            "the maximum finite cost is valid by itself"
        );

        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-b"), f64::MAX),
        );

        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Workspace,
            field: ChargebackOverflowField::Cost,
        };
        let refused = tracker.snapshot();
        assert_financial_state_unchanged(&before, &refused);
        assert_refusal_delta(&before, &refused, &reason);

        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-b"), Some("team-b"), 0.5),
        );
        let after_valid = tracker.snapshot();
        assert_eq!(after_valid.recorded_entries, 2);
        assert_eq!(refusal_count(&after_valid, &reason), 1);
        assert_eq!(after_valid.refused_entries, 1);
        assert!(
            !after_valid.complete,
            "a later valid UsageSink event cannot clear overflow incompleteness"
        );
    }

    #[test]
    fn group_f_refusal_and_overflow_vocabularies_are_closed_and_exhaustive() {
        assert_eq!(
            [
                ChargebackOverflowScope::Tracker,
                ChargebackOverflowScope::Workspace,
                ChargebackOverflowScope::Team,
            ]
            .iter()
            .map(overflow_scope_name)
            .collect::<Vec<_>>(),
            ["tracker", "workspace", "team"]
        );
        assert_eq!(
            [
                ChargebackOverflowField::RecordedEntries,
                ChargebackOverflowField::RequestCount,
                ChargebackOverflowField::Tokens,
                ChargebackOverflowField::Cost,
            ]
            .iter()
            .map(overflow_field_name)
            .collect::<Vec<_>>(),
            ["recorded_entries", "request_count", "tokens", "cost"]
        );
        assert_eq!(
            [
                ChargebackRecordError::InvalidCost,
                ChargebackRecordError::InvalidTimestamp,
                ChargebackRecordError::ArithmeticOverflow {
                    scope: ChargebackOverflowScope::Tracker,
                    field: ChargebackOverflowField::RecordedEntries,
                },
            ]
            .iter()
            .map(record_error_name)
            .collect::<Vec<_>>(),
            ["invalid_cost", "invalid_timestamp", "arithmetic_overflow"]
        );
    }

    #[test]
    fn group_f_try_record_returns_typed_invalid_cost_and_refusal_delta() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-01T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        let before = tracker.snapshot();

        let result = record_at(
            &tracker,
            Some("workspace-a"),
            "team-a",
            "2026-08-02T00:00:00Z",
            -0.01,
        );

        assert_eq!(result, Err(ChargebackRecordError::InvalidCost));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &ChargebackRecordError::InvalidCost);
    }

    #[test]
    fn group_f_try_record_rejects_invalid_timestamp_before_finance_mutation() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-01T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        let before = tracker.snapshot();

        let result = record_at(
            &tracker,
            Some("workspace-a"),
            "team-a",
            "yesterday-ish",
            1.0,
        );

        assert_eq!(result, Err(ChargebackRecordError::InvalidTimestamp));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &ChargebackRecordError::InvalidTimestamp);
    }

    #[test]
    fn group_f_second_refusal_preserves_the_first_reason_row() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        let initial = tracker.snapshot();

        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-01T00:00:00Z",
                -0.01,
            ),
            Err(ChargebackRecordError::InvalidCost)
        );
        let after_first = tracker.snapshot();
        assert_refusal_delta(&initial, &after_first, &ChargebackRecordError::InvalidCost);
        assert_eq!(after_first.refusal_counts.len(), 1);
        assert_eq!(
            refusal_count(&after_first, &ChargebackRecordError::InvalidCost),
            1
        );

        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "not-a-timestamp",
                1.0,
            ),
            Err(ChargebackRecordError::InvalidTimestamp)
        );
        let after_second = tracker.snapshot();

        assert_financial_state_unchanged(&after_first, &after_second);
        assert_refusal_delta(
            &after_first,
            &after_second,
            &ChargebackRecordError::InvalidTimestamp,
        );
        assert_eq!(
            after_second
                .refused_entries
                .checked_sub(initial.refused_entries),
            Some(2),
            "two ordinary refusals must produce an exact aggregate delta of two"
        );
        assert_eq!(after_second.refusal_counts.len(), 2);
        assert_eq!(
            refusal_count(&after_second, &ChargebackRecordError::InvalidCost),
            1,
            "recording a second reason must preserve the first exact row and count"
        );
        assert_eq!(
            refusal_count(&after_second, &ChargebackRecordError::InvalidTimestamp,),
            1,
            "only the selected second reason may gain one"
        );
    }

    #[test]
    fn group_f_checked_workspace_token_overflow_is_transactionally_inert() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        let mut maximum = entry("team-a", 1.0);
        maximum.tokens = u64::MAX;
        assert_eq!(tracker.try_record(Some("workspace-a"), maximum), Ok(()));
        let before = tracker.snapshot();
        assert_eq!(
            workspace_rollup(&before, &value_key("workspace-a")).map(|totals| totals.tokens),
            Some(u64::MAX)
        );
        assert_eq!(
            team_rollup(&before, &value_key("team-a")).map(|totals| totals.tokens),
            Some(u64::MAX)
        );

        let mut overflow = entry("team-b", 1.0);
        overflow.tokens = 1;
        let result = tracker.try_record(Some("workspace-a"), overflow);

        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Workspace,
            field: ChargebackOverflowField::Tokens,
        };
        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_checked_team_token_overflow_is_transactionally_inert() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        let mut maximum = entry("team-a", 1.0);
        maximum.tokens = u64::MAX;
        assert_eq!(tracker.try_record(Some("workspace-a"), maximum), Ok(()));
        let before = tracker.snapshot();
        assert_eq!(
            workspace_rollup(&before, &value_key("workspace-a")).map(|totals| totals.tokens),
            Some(u64::MAX)
        );
        assert_eq!(
            team_rollup(&before, &value_key("team-a")).map(|totals| totals.tokens),
            Some(u64::MAX)
        );

        let mut overflow = entry("team-a", 1.0);
        overflow.tokens = 1;
        let result = tracker.try_record(Some("workspace-b"), overflow);

        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Team,
            field: ChargebackOverflowField::Tokens,
        };
        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_checked_workspace_cost_overflow_is_transactionally_inert() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", f64::MAX)),
            Ok(())
        );
        let before = tracker.snapshot();
        assert_eq!(
            workspace_rollup(&before, &value_key("workspace-a")).map(|totals| totals.cost_usd),
            Some(f64::MAX)
        );
        assert_eq!(
            team_rollup(&before, &value_key("team-a")).map(|totals| totals.cost_usd),
            Some(f64::MAX)
        );

        let result = tracker.try_record(Some("workspace-a"), entry("team-b", f64::MAX));

        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Workspace,
            field: ChargebackOverflowField::Cost,
        };
        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);

        assert_eq!(
            tracker.try_record(Some("workspace-b"), entry("team-b", 0.5)),
            Ok(()),
            "a representable record must still commit after a refused overflow"
        );
        let continued = tracker.snapshot();
        assert_eq!(continued.recorded_entries, 2);
        assert_eq!(continued.refused_entries, 1);
        assert!(!continued.complete, "the earlier refusal remains sticky");
        assert_eq!(
            workspace_rollup(&continued, &value_key("workspace-b")).map(|totals| totals.cost_usd),
            Some(0.5)
        );
    }

    #[test]
    fn group_f_checked_team_cost_overflow_is_transactionally_inert() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", f64::MAX)),
            Ok(())
        );
        let before = tracker.snapshot();
        assert_eq!(
            workspace_rollup(&before, &value_key("workspace-a")).map(|totals| totals.cost_usd),
            Some(f64::MAX)
        );
        assert_eq!(
            team_rollup(&before, &value_key("team-a")).map(|totals| totals.cost_usd),
            Some(f64::MAX)
        );

        let result = tracker.try_record(Some("workspace-b"), entry("team-a", f64::MAX));

        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Team,
            field: ChargebackOverflowField::Cost,
        };
        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_positive_workspace_cost_absorption_is_transactionally_refused() {
        assert_eq!(
            f64::MAX + 0.5,
            f64::MAX,
            "the fixture must exercise finite positive monetary absorption"
        );
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", f64::MAX)),
            Ok(())
        );
        let before = tracker.snapshot();
        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Workspace,
            field: ChargebackOverflowField::Cost,
        };

        let result = tracker.try_record(Some("workspace-a"), entry("team-b", 0.5));

        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_positive_team_cost_absorption_is_transactionally_refused() {
        assert_eq!(
            f64::MAX + 0.5,
            f64::MAX,
            "the fixture must exercise finite positive monetary absorption"
        );
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", f64::MAX)),
            Ok(())
        );
        let before = tracker.snapshot();
        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Team,
            field: ChargebackOverflowField::Cost,
        };

        let result = tracker.try_record(Some("workspace-b"), entry("team-a", 0.5));

        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_exact_token_rollup_boundary_is_accepted() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        let mut first = entry("team-a", 1.0);
        first.tokens = u64::MAX - 1;
        let mut second = entry("team-a", 1.0);
        second.tokens = 1;

        assert_eq!(tracker.try_record(Some("workspace-a"), first), Ok(()));
        assert_eq!(tracker.try_record(Some("workspace-a"), second), Ok(()));

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.recorded_entries, 2);
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(
            workspace_rollup(&snapshot, &value_key("workspace-a")).map(|totals| totals.tokens),
            Some(u64::MAX)
        );
        assert_eq!(
            team_rollup(&snapshot, &value_key("team-a")).map(|totals| totals.tokens),
            Some(u64::MAX)
        );
        assert!(snapshot.complete);
    }

    #[test]
    fn group_f_checked_workspace_request_count_overflow_is_transactionally_inert() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", 1.0)),
            Ok(())
        );
        let seeded = {
            let mut state = tracker.state.lock();
            state
                .workspace_totals
                .get_mut(&value_key("workspace-a"))
                .map(|totals| totals.request_count = u64::MAX)
        };
        assert_eq!(seeded, Some(()), "the workspace seed row must exist");
        let before = tracker.snapshot();

        let result = tracker.try_record(Some("workspace-a"), entry("team-b", 1.0));
        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Workspace,
            field: ChargebackOverflowField::RequestCount,
        };

        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_checked_team_request_count_overflow_is_transactionally_inert() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", 1.0)),
            Ok(())
        );
        let seeded = {
            let mut state = tracker.state.lock();
            state
                .team_totals
                .get_mut(&value_key("team-a"))
                .map(|totals| totals.request_count = u64::MAX)
        };
        assert_eq!(seeded, Some(()), "the team seed row must exist");
        let before = tracker.snapshot();

        let result = tracker.try_record(Some("workspace-b"), entry("team-a", 1.0));
        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Team,
            field: ChargebackOverflowField::RequestCount,
        };

        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_checked_recorded_entries_overflow_is_transactionally_inert() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", 1.0)),
            Ok(())
        );
        tracker.state.lock().recorded_entries = u64::MAX;
        let before = tracker.snapshot();

        let result = tracker.try_record(Some("workspace-b"), entry("team-b", 1.0));
        let reason = ChargebackRecordError::ArithmeticOverflow {
            scope: ChargebackOverflowScope::Tracker,
            field: ChargebackOverflowField::RecordedEntries,
        };

        assert_eq!(result, Err(reason));
        let after = tracker.snapshot();
        assert_financial_state_unchanged(&before, &after);
        assert_refusal_delta(&before, &after, &reason);
    }

    #[test]
    fn group_f_saturated_refusal_counters_cannot_hide_incompleteness() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        {
            let mut state = tracker.state.lock();
            state.complete = true;
            state.refused_entries = u64::MAX;
            state
                .refusal_counts
                .insert(ChargebackRecordError::InvalidCost, u64::MAX);
        }

        let before = tracker.snapshot();
        let result = tracker.try_record(Some("workspace-a"), entry("team-a", -1.0));

        assert_eq!(result, Err(ChargebackRecordError::InvalidCost));
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.refused_entries, u64::MAX);
        assert_eq!(
            refusal_count(&snapshot, &ChargebackRecordError::InvalidCost),
            u64::MAX
        );
        assert_eq!(
            snapshot.refusal_counts, before.refusal_counts,
            "the selected per-reason aggregate has an exact zero telemetry delta at saturation"
        );
        assert_eq!(
            snapshot.refused_entries, before.refused_entries,
            "the overall aggregate has an exact zero telemetry delta at saturation"
        );
        assert!(snapshot.entries.is_empty());
        assert!(snapshot.workspace_rollups.is_empty());
        assert!(snapshot.team_rollups.is_empty());
        assert!(
            !snapshot.complete,
            "completeness is a monotonic state bit, not a counter delta"
        );
    }

    #[test]
    fn group_f_lossy_collapse_counters_preserve_exact_finance_and_completeness() {
        let tracker = ChargebackTracker::with_limits(4, 2, 2);
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", 1.0)),
            Ok(())
        );
        {
            let mut state = tracker.state.lock();
            state.collapsed_workspace_events = u64::MAX;
            state.collapsed_team_events = u64::MAX;
        }

        assert_eq!(
            tracker.try_record(Some("workspace-b"), entry("team-b", 2.0)),
            Ok(())
        );

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.collapsed_workspace_events, u64::MAX);
        assert_eq!(snapshot.collapsed_team_events, u64::MAX);
        assert_eq!(
            workspace_rollup(&snapshot, &DimensionKey::Overflow).map(|totals| (
                totals.request_count,
                totals.tokens,
                totals.cost_usd
            )),
            Some((1, 1000, 2.0))
        );
        assert_eq!(
            team_rollup(&snapshot, &DimensionKey::Overflow).map(|totals| (
                totals.request_count,
                totals.tokens,
                totals.cost_usd
            )),
            Some((1, 1000, 2.0))
        );
        assert!(snapshot.complete);
    }

    #[test]
    fn group_f_workspace_shortening_preserves_long_utf8_distinctness() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        let first = long_multibyte_dimension("alpha");
        let second = long_multibyte_dimension("beta");

        UsageSink::record(&tracker, &usage_event(Some(&first), Some("team-a"), 1.0));
        UsageSink::record(&tracker, &usage_event(Some(&second), Some("team-a"), 1.0));

        let snapshot = tracker.snapshot();
        assert_eq!(
            workspace_values(&snapshot).len(),
            2,
            "distinct long workspace identities must not share a prefix-only key"
        );
        assert!(workspace_values(&snapshot)
            .iter()
            .all(|key| key.len() <= 256 && !key.contains('\u{fffd}')));
    }

    #[test]
    fn group_f_team_shortening_preserves_long_utf8_distinctness() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        let first = long_multibyte_dimension("alpha");
        let second = long_multibyte_dimension("beta");

        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some(&first), 1.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some(&second), 1.0),
        );

        let snapshot = tracker.snapshot();
        assert_eq!(
            team_values(&snapshot).len(),
            2,
            "distinct long team identities must not share a prefix-only key"
        );
        assert!(team_values(&snapshot)
            .iter()
            .all(|key| key.len() <= 256 && !key.contains('\u{fffd}')));
    }

    #[test]
    fn group_f_literal_unattributed_workspace_is_distinct_from_missing() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        UsageSink::record(&tracker, &usage_event(None, Some("team-a"), 1.0));
        UsageSink::record(
            &tracker,
            &usage_event(Some("unattributed"), Some("team-a"), 1.0),
        );

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.workspace_rollups.len(), 2);
        assert_eq!(
            workspace_rollup(&snapshot, &DimensionKey::Missing).map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            workspace_rollup(&snapshot, &value_key("unattributed"))
                .map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(snapshot.entries[0].workspace, DimensionKey::Missing);
        assert_eq!(snapshot.entries[1].workspace, value_key("unattributed"));
        assert_eq!(
            snapshot.entries[1].workspace,
            DimensionKey::Value("unattributed".to_string())
        );
    }

    #[test]
    fn group_f_literal_unattributed_team_is_distinct_from_missing() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        UsageSink::record(&tracker, &usage_event(Some("workspace-a"), None, 1.0));
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("unattributed"), 1.0),
        );

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.team_rollups.len(), 2);
        assert_eq!(
            team_rollup(&snapshot, &DimensionKey::Missing).map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            team_rollup(&snapshot, &value_key("unattributed")).map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(snapshot.entries[0].team, DimensionKey::Missing);
        assert_eq!(snapshot.entries[1].team, value_key("unattributed"));
        assert_eq!(
            snapshot.entries[1].team,
            DimensionKey::Value("unattributed".to_string())
        );
    }

    #[test]
    fn group_f_literal_overflow_workspace_is_distinct_from_internal_bucket() {
        let tracker = ChargebackTracker::with_limits(4, 3, 4);
        UsageSink::record(
            &tracker,
            &usage_event(Some("__other__"), Some("team-a"), 1.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-a"), 2.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-forces-overflow"), Some("team-a"), 3.0),
        );

        let snapshot = tracker.snapshot();
        assert_eq!(
            workspace_rollup(&snapshot, &value_key("__other__"))
                .map(|totals| (totals.request_count, totals.cost_usd)),
            Some((1, 1.0))
        );
        assert_eq!(
            workspace_rollup(&snapshot, &DimensionKey::Overflow)
                .map(|totals| (totals.request_count, totals.cost_usd)),
            Some((1, 3.0))
        );
        assert_eq!(snapshot.collapsed_workspace_events, 1);
        assert_eq!(snapshot.entries[0].workspace, value_key("__other__"));
        assert_eq!(
            snapshot.entries[0].workspace,
            DimensionKey::Value("__other__".to_string())
        );
        assert_eq!(
            snapshot.entries[2].workspace,
            value_key("workspace-forces-overflow")
        );
        assert_eq!(
            workspace_rollup(&snapshot, &value_key("workspace-a"))
                .map(|totals| totals.request_count),
            Some(1)
        );
    }

    #[test]
    fn group_f_literal_overflow_team_is_distinct_from_internal_bucket() {
        let tracker = ChargebackTracker::with_limits(4, 4, 3);
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("__other__"), 1.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-a"), 2.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-forces-overflow"), 3.0),
        );

        let snapshot = tracker.snapshot();
        assert_eq!(
            team_rollup(&snapshot, &value_key("__other__"))
                .map(|totals| (totals.request_count, totals.cost_usd)),
            Some((1, 1.0))
        );
        assert_eq!(
            team_rollup(&snapshot, &DimensionKey::Overflow)
                .map(|totals| (totals.request_count, totals.cost_usd)),
            Some((1, 3.0))
        );
        assert_eq!(snapshot.collapsed_team_events, 1);
        assert_eq!(snapshot.entries[0].team, value_key("__other__"));
        assert_eq!(
            snapshot.entries[0].team,
            DimensionKey::Value("__other__".to_string())
        );
        assert_eq!(snapshot.entries[2].team, value_key("team-forces-overflow"));
        assert_eq!(
            team_rollup(&snapshot, &value_key("team-a")).map(|totals| totals.request_count),
            Some(1)
        );
    }

    #[test]
    fn group_f_workspace_totals_snapshot_keeps_reserved_literals_distinct_from_internal_buckets() {
        let tracker = ChargebackTracker::with_limits(8, 5, 8);
        UsageSink::record(&tracker, &usage_event(None, Some("team-a"), 1.0));
        UsageSink::record(
            &tracker,
            &usage_event(Some("unattributed"), Some("team-a"), 2.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("__other__"), Some("team-a"), 3.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-a"), 4.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-forces-overflow"), Some("team-a"), 5.0),
        );

        let snapshot = tracker.snapshot();
        let escaped_missing_literal = snapshot.entries[1]
            .workspace
            .legacy_projection()
            .into_owned();
        let escaped_overflow_literal = snapshot.entries[2]
            .workspace
            .legacy_projection()
            .into_owned();
        assert_ne!(escaped_missing_literal, UNATTRIBUTED);
        assert_ne!(escaped_overflow_literal, OVERFLOW);

        let totals = tracker.workspace_totals_snapshot();
        assert_eq!(
            totals.get(UNATTRIBUTED).map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            totals
                .get(&escaped_missing_literal)
                .map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            totals
                .get(&escaped_overflow_literal)
                .map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            totals.get(OVERFLOW).map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            totals.get("workspace-a").map(|totals| totals.request_count),
            Some(1)
        );
    }

    #[test]
    fn group_f_total_by_team_keeps_reserved_literals_distinct_from_internal_buckets() {
        let tracker = ChargebackTracker::with_limits(8, 8, 5);
        UsageSink::record(&tracker, &usage_event(Some("workspace-a"), None, 1.0));
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("unattributed"), 2.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("__other__"), 3.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-a"), 4.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some("workspace-a"), Some("team-forces-overflow"), 5.0),
        );

        let snapshot = tracker.snapshot();
        let escaped_missing_literal = snapshot.entries[1].team.legacy_projection().into_owned();
        let escaped_overflow_literal = snapshot.entries[2].team.legacy_projection().into_owned();
        assert_ne!(escaped_missing_literal, UNATTRIBUTED);
        assert_ne!(escaped_overflow_literal, OVERFLOW);

        let totals = tracker.total_by_team();
        assert_eq!(totals.get(UNATTRIBUTED).copied(), Some(1.0));
        assert_eq!(totals.get(&escaped_missing_literal).copied(), Some(2.0));
        assert_eq!(totals.get(&escaped_overflow_literal).copied(), Some(3.0));
        assert_eq!(totals.get("team-a").copied(), Some(4.0));
        assert_eq!(totals.get(OVERFLOW).copied(), Some(5.0));
    }

    #[test]
    fn group_f_reserved_literal_projection_namespace_is_collision_safe() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        let projected_missing = escaped_reserved_dimension_literal(UNATTRIBUTED);
        UsageSink::record(
            &tracker,
            &usage_event(Some(UNATTRIBUTED), Some(OVERFLOW), 1.0),
        );
        UsageSink::record(
            &tracker,
            &usage_event(Some(&projected_missing), Some("team-a"), 2.0),
        );

        let snapshot = tracker.snapshot();
        assert_eq!(
            snapshot.entries[0].workspace,
            DimensionKey::Value(UNATTRIBUTED.to_string()),
            "typed v2 identity retains exact short caller text"
        );
        assert_ne!(
            snapshot.entries[1].workspace,
            DimensionKey::Value(projected_missing.clone()),
            "caller input that resembles a legacy projection is escaped before storage"
        );

        let totals = tracker.workspace_totals_snapshot();
        assert_eq!(totals.len(), 2);
        assert_eq!(
            totals
                .get(&projected_missing)
                .map(|value| value.request_count),
            Some(1)
        );
        assert!(totals
            .iter()
            .any(|(key, value)| key != &projected_missing && value.request_count == 1));
    }

    #[test]
    fn group_f_long_dimensions_do_not_retain_full_raw_values() -> Result<(), serde_json::Error> {
        let (snapshot, raw_dimensions) = long_dimension_snapshot();
        let wire = serde_json::to_string(&snapshot)?;
        for raw in &raw_dimensions {
            assert!(
                !wire.contains(raw),
                "the complete caller-controlled dimension must not survive normalization"
            );
        }
        Ok(())
    }

    #[test]
    fn group_f_distinct_long_dimensions_exert_bounded_cardinality_pressure() {
        let (snapshot, _) = long_dimension_snapshot();
        assert!(snapshot.workspace_rollups.len() <= 3);
        assert!(snapshot.team_rollups.len() <= 3);
        assert_eq!(
            snapshot
                .workspace_rollups
                .iter()
                .map(|rollup| rollup.totals.request_count)
                .sum::<u64>(),
            8
        );
        assert_eq!(
            snapshot
                .team_rollups
                .iter()
                .map(|rollup| rollup.totals.request_count)
                .sum::<u64>(),
            8
        );
        assert!(
            snapshot.collapsed_workspace_events > 0,
            "distinct shortened workspaces must exert bounded cardinality pressure"
        );
        assert!(
            snapshot.collapsed_team_events > 0,
            "distinct shortened teams must exert bounded cardinality pressure"
        );
    }

    #[test]
    fn group_f_snapshot_v2_wire_replaces_ambiguous_unversioned_dimension_maps(
    ) -> Result<(), serde_json::Error> {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        UsageSink::record(&tracker, &usage_event(None, None, 1.0));
        UsageSink::record(
            &tracker,
            &usage_event(Some("unattributed"), Some("__other__"), 2.0),
        );

        let wire = serde_json::to_value(tracker.snapshot())?;

        assert_eq!(CHARGEBACK_SNAPSHOT_SCHEMA_VERSION, 2);
        assert_eq!(wire["schema_version"], serde_json::json!(2));
        assert!(
            wire.get("workspace_totals").is_none(),
            "the implicit-v1 forgeable string map must not be emitted in v2"
        );
        assert!(
            wire.get("team_totals").is_none(),
            "the implicit-v1 forgeable string map must not be emitted in v2"
        );
        assert_eq!(
            wire["entries"][0]["workspace"],
            serde_json::json!({"kind": "missing"})
        );
        assert_eq!(
            wire["entries"][0]["team"],
            serde_json::json!({"kind": "missing"})
        );
        assert_eq!(
            wire["entries"][1]["workspace"],
            serde_json::json!({"kind": "value", "value": "unattributed"})
        );
        assert_eq!(
            wire["entries"][1]["team"],
            serde_json::json!({"kind": "value", "value": "__other__"})
        );
        assert!(wire["workspace_rollups"].as_array().is_some_and(|rollups| {
            rollups
                .iter()
                .any(|rollup| rollup["dimension"] == serde_json::json!({"kind": "missing"}))
        }));
        assert!(wire["workspace_rollups"]
            .as_array()
            .is_some_and(|rollups| rollups.iter().any(|rollup| {
                rollup["dimension"] == serde_json::json!({"kind": "value", "value": "unattributed"})
            })));

        let overflow_tracker = ChargebackTracker::with_limits(4, 2, 2);
        UsageSink::record(
            &overflow_tracker,
            &usage_event(Some("workspace-a"), Some("team-a"), 1.0),
        );
        UsageSink::record(
            &overflow_tracker,
            &usage_event(Some("workspace-b"), Some("team-b"), 2.0),
        );
        let overflow_wire = serde_json::to_value(overflow_tracker.snapshot())?;
        assert!(overflow_wire["workspace_rollups"]
            .as_array()
            .is_some_and(|rollups| rollups
                .iter()
                .any(|rollup| { rollup["dimension"] == serde_json::json!({"kind": "overflow"}) })));
        assert!(overflow_wire["team_rollups"]
            .as_array()
            .is_some_and(|rollups| rollups
                .iter()
                .any(|rollup| { rollup["dimension"] == serde_json::json!({"kind": "overflow"}) })));
        assert_eq!(
            overflow_wire["entries"][1]["workspace"],
            serde_json::json!({"kind": "value", "value": "workspace-b"})
        );
        assert_eq!(
            overflow_wire["entries"][1]["team"],
            serde_json::json!({"kind": "value", "value": "team-b"})
        );
        Ok(())
    }

    #[test]
    fn group_f_dimension_digest_is_stable_across_trackers_and_reversed_order() {
        let alpha = long_multibyte_dimension("alpha");
        let beta = long_multibyte_dimension("beta");
        let expected_alpha = format!(
            "{}~07bf6586e3295261f78ac2a06f5565f3db36d2e01800888e2a356b650dd061c0",
            "界".repeat(63)
        );

        let first = ChargebackTracker::with_limits(4, 4, 4);
        UsageSink::record(&first, &usage_event(Some(&alpha), Some(&alpha), 1.0));
        UsageSink::record(&first, &usage_event(Some(&beta), Some(&beta), 1.0));

        let reversed = ChargebackTracker::with_limits(4, 4, 4);
        UsageSink::record(&reversed, &usage_event(Some(&beta), Some(&beta), 1.0));
        UsageSink::record(&reversed, &usage_event(Some(&alpha), Some(&alpha), 1.0));

        let first_snapshot = first.snapshot();
        let reversed_snapshot = reversed.snapshot();
        assert_eq!(
            workspace_values(&first_snapshot),
            workspace_values(&reversed_snapshot)
        );
        assert_eq!(
            team_values(&first_snapshot),
            team_values(&reversed_snapshot)
        );
        assert!(workspace_values(&first_snapshot).contains(&expected_alpha));
        assert!(team_values(&first_snapshot).contains(&expected_alpha));
        assert_eq!(expected_alpha.len(), 254);
    }

    #[test]
    fn group_f_provider_model_digests_are_stable_and_project_is_contained(
    ) -> Result<(), serde_json::Error> {
        let provider_alpha = long_ascii_dimension("provider-alpha");
        let provider_beta = long_ascii_dimension("provider-beta");
        let model_alpha = long_ascii_dimension("model-alpha");
        let model_beta = long_ascii_dimension("model-beta");
        let project = long_ascii_dimension("project-alpha");
        let expected_provider_alpha = format!(
            "{}~c0104aeca7087166ead283fc4d6c8f74fb16042e938e148be393b3b96adebb4d",
            "x".repeat(191)
        );
        let expected_model_alpha = format!(
            "{}~9df9822fb045e57a5b8a1c9ca6614ff9174f8e4d1ddeb8b89e094f18497c0339",
            "x".repeat(191)
        );

        let record_pair = |tracker: &ChargebackTracker, reversed: bool| {
            let mut alpha = entry("team-a", 1.0);
            alpha.project = project.clone();
            alpha.provider = provider_alpha.clone();
            alpha.model = model_alpha.clone();
            let mut beta = entry("team-b", 2.0);
            beta.project = project.clone();
            beta.provider = provider_beta.clone();
            beta.model = model_beta.clone();
            if reversed {
                assert_eq!(tracker.try_record(Some("workspace-b"), beta), Ok(()));
                assert_eq!(tracker.try_record(Some("workspace-a"), alpha), Ok(()));
            } else {
                assert_eq!(tracker.try_record(Some("workspace-a"), alpha), Ok(()));
                assert_eq!(tracker.try_record(Some("workspace-b"), beta), Ok(()));
            }
        };

        let first = ChargebackTracker::with_limits(4, 4, 4);
        record_pair(&first, false);
        let reversed = ChargebackTracker::with_limits(4, 4, 4);
        record_pair(&reversed, true);

        let normalized = |snapshot: &ChargebackSnapshot| {
            let mut values: Vec<(String, String, String)> = snapshot
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.provider.clone(),
                        entry.model.clone(),
                        entry.project.clone(),
                    )
                })
                .collect();
            values.sort();
            values
        };
        let first_snapshot = first.snapshot();
        let reversed_snapshot = reversed.snapshot();
        assert_eq!(normalized(&first_snapshot), normalized(&reversed_snapshot));
        assert!(first_snapshot
            .entries
            .iter()
            .any(|entry| entry.provider.as_str() == expected_provider_alpha.as_str()));
        let normalized_alpha = first_snapshot
            .entries
            .iter()
            .find(|entry| entry.cost == 1.0)
            .expect("the alpha finance row must remain identifiable");
        assert_eq!(
            normalized_alpha.provider.as_str(),
            expected_provider_alpha.as_str()
        );
        assert_eq!(
            normalized_alpha.model.as_str(),
            expected_model_alpha.as_str()
        );
        assert_ne!(
            normalized_alpha.model, normalized_alpha.provider,
            "model normalization must hash the model source, not reuse provider identity"
        );
        assert_eq!(
            first_snapshot
                .entries
                .iter()
                .map(|entry| entry.provider.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
        assert_eq!(
            first_snapshot
                .entries
                .iter()
                .map(|entry| entry.model.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
        assert!(first_snapshot
            .entries
            .iter()
            .all(|entry| entry.project.len() <= 256));
        let wire = serde_json::to_string(&first_snapshot)?;
        assert!(!wire.contains(&provider_alpha));
        assert!(!wire.contains(&provider_beta));
        assert!(!wire.contains(&model_alpha));
        assert!(!wire.contains(&model_beta));
        assert!(!wire.contains(&project));
        Ok(())
    }

    #[test]
    fn group_f_out_of_order_evictions_keep_min_and_max_watermarks() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-10T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-05T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-20T00:00:00Z",
                1.0,
            ),
            Ok(())
        );

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.evicted_entries, 2);
        assert_eq!(
            snapshot.eviction_watermark.min_timestamp.as_deref(),
            Some("2026-08-05T00:00:00Z")
        );
        assert_eq!(
            snapshot.eviction_watermark.max_timestamp.as_deref(),
            Some("2026-08-10T00:00:00Z")
        );
        assert!(!snapshot.eviction_watermark.poisoned);
        assert_eq!(
            snapshot.earliest_retained_timestamp.as_deref(),
            Some("2026-08-20T00:00:00Z")
        );
        assert_eq!(
            snapshot.latest_retained_timestamp.as_deref(),
            Some("2026-08-20T00:00:00Z")
        );
    }

    /// The bounded-retention drop is the only writer of
    /// `sbproxy_ai_chargeback_entries_evicted_total`. The metric registry
    /// names `record_chargeback_entry_evicted` as that writer, and the
    /// drift guard proves the symbol has a production call site; this
    /// proves the call site is the eviction itself and that the counter
    /// actually moves when a row is dropped.
    ///
    /// The counter is process-global and other tests in this binary evict
    /// too, so the assertion is on the delta rather than on an absolute
    /// value.
    #[test]
    fn group_f_evicting_a_raw_entry_increments_the_eviction_counter() {
        fn evicted_total() -> u64 {
            counter_total("sbproxy_ai_chargeback_entries_evicted_total", &[])
        }

        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-01T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        assert_eq!(tracker.snapshot().evicted_entries, 0, "nothing dropped yet");

        let before = evicted_total();
        // `max_entries` is 1, so this row displaces the first.
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-02T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        let after = evicted_total();

        assert_eq!(tracker.snapshot().evicted_entries, 1, "one row was dropped");
        assert!(
            after > before,
            "sbproxy_ai_chargeback_entries_evicted_total must move on an eviction, \
             saw {before} then {after}"
        );
    }

    #[test]
    fn group_f_retained_extrema_are_independent_without_eviction() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        for timestamp in [
            "2026-08-20T00:00:00Z",
            "2026-08-05T00:00:00Z",
            "2026-08-30T00:00:00Z",
            "2026-08-10T00:00:00Z",
        ] {
            assert_eq!(
                record_at(&tracker, Some("workspace-a"), "team-a", timestamp, 1.0,),
                Ok(())
            );
        }

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.entries.len(), 4);
        assert_eq!(snapshot.evicted_entries, 0);
        assert_eq!(snapshot.eviction_watermark.min_timestamp, None);
        assert_eq!(snapshot.eviction_watermark.max_timestamp, None);
        assert!(!snapshot.eviction_watermark.poisoned);
        assert_eq!(
            snapshot.earliest_retained_timestamp.as_deref(),
            Some("2026-08-05T00:00:00Z")
        );
        assert_eq!(
            snapshot.latest_retained_timestamp.as_deref(),
            Some("2026-08-30T00:00:00Z")
        );
    }

    #[test]
    fn group_f_eviction_evidence_advances_when_the_telemetry_counter_is_saturated() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-10T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        tracker.state.lock().evicted_entries = u64::MAX;
        for timestamp in [
            "2026-08-20T00:00:00Z",
            "2026-08-05T00:00:00Z",
            "2026-08-30T00:00:00Z",
        ] {
            assert_eq!(
                record_at(&tracker, Some("workspace-a"), "team-a", timestamp, 1.0,),
                Ok(())
            );
        }
        let valid = tracker.snapshot();
        assert_eq!(valid.evicted_entries, u64::MAX);
        assert_eq!(
            valid.eviction_watermark.min_timestamp.as_deref(),
            Some("2026-08-05T00:00:00Z")
        );
        assert_eq!(
            valid.eviction_watermark.max_timestamp.as_deref(),
            Some("2026-08-20T00:00:00Z")
        );
        assert!(!valid.eviction_watermark.poisoned);

        let malformed = ChargebackTracker::with_limits(1, 4, 4);
        {
            let mut state = malformed.state.lock();
            state.entries.push_back(snapshot_entry(
                DimensionKey::Missing,
                value_key("legacy-team"),
                "not-a-timestamp",
            ));
            state.recorded_entries = 1;
            state.evicted_entries = u64::MAX;
        }
        assert_eq!(
            record_at(
                &malformed,
                Some("workspace-a"),
                "team-a",
                "2026-08-20T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        let poisoned = malformed.snapshot();
        assert_eq!(poisoned.evicted_entries, u64::MAX);
        assert!(poisoned.eviction_watermark.poisoned);
        assert!(!poisoned.complete);
    }

    #[test]
    fn group_f_malformed_legacy_eviction_poisons_the_watermark() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        {
            let mut state = tracker.state.lock();
            state.entries.push_back(snapshot_entry(
                DimensionKey::Missing,
                value_key("legacy-team"),
                "not-a-timestamp",
            ));
            state.recorded_entries = 1;
        }

        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-20T00:00:00Z",
                1.0,
            ),
            Ok(())
        );

        let poisoned = tracker.snapshot();
        assert_eq!(poisoned.evicted_entries, 1);
        assert!(poisoned.eviction_watermark.poisoned);
        assert_eq!(poisoned.eviction_watermark.min_timestamp, None);
        assert_eq!(poisoned.eviction_watermark.max_timestamp, None);
        assert!(!poisoned.complete);
        assert_eq!(poisoned.refused_entries, 0);

        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-b"),
                "team-b",
                "2026-08-25T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        let after_valid_eviction = tracker.snapshot();
        assert_eq!(after_valid_eviction.evicted_entries, 2);
        assert!(
            after_valid_eviction.eviction_watermark.poisoned,
            "a later valid eviction must never clear malformed legacy evidence"
        );
        assert_eq!(
            after_valid_eviction
                .eviction_watermark
                .min_timestamp
                .as_deref(),
            Some("2026-08-20T00:00:00Z")
        );
        assert_eq!(
            after_valid_eviction
                .eviction_watermark
                .max_timestamp
                .as_deref(),
            Some("2026-08-20T00:00:00Z")
        );
        assert!(!after_valid_eviction.complete);
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
        assert_eq!(
            workspace_rollup(&snapshot, &value_key("workspace-a"))
                .map(|totals| totals.request_count),
            Some(10)
        );
        assert_eq!(
            team_rollup(&snapshot, &value_key("team-a")).map(|totals| totals.request_count),
            Some(10)
        );
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
        assert!(snapshot.workspace_rollups.len() <= 2);
        assert!(snapshot.team_rollups.len() <= 2);
        assert!(workspace_rollup(&snapshot, &DimensionKey::Overflow).is_some());
        assert!(team_rollup(&snapshot, &DimensionKey::Overflow).is_some());
        assert!(snapshot.collapsed_workspace_events > 0);
        assert!(snapshot.collapsed_team_events > 0);
        assert_eq!(
            snapshot
                .workspace_rollups
                .iter()
                .map(|rollup| rollup.totals.request_count)
                .sum::<u64>(),
            snapshot.recorded_entries
        );
    }

    #[test]
    fn group_f_long_parseable_timestamp_is_refused_or_retained_bounded_and_parseable() {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        let mut input = entry("team-a", 1.0);
        input.timestamp = format!("2026-08-10T00:00:00.{}Z", "1".repeat(300));
        assert!(
            DateTime::parse_from_rfc3339(&input.timestamp).is_ok(),
            "the boundary fixture must be syntactically valid before it reaches chargeback"
        );
        let before = tracker.snapshot();

        match tracker.try_record(Some("workspace-a"), input) {
            Err(ChargebackRecordError::InvalidTimestamp) => {
                let after = tracker.snapshot();
                assert_financial_state_unchanged(&before, &after);
                assert_refusal_delta(&before, &after, &ChargebackRecordError::InvalidTimestamp);
            }
            Ok(()) => {
                let snapshot = tracker.snapshot();
                assert!(snapshot.complete);
                assert_eq!(snapshot.refused_entries, 0);
                let stored = &snapshot.entries[0].timestamp;
                assert!(
                    stored.len() <= 256,
                    "an accepted timestamp must remain inside the retained byte ceiling"
                );
                assert!(
                    DateTime::parse_from_rfc3339(stored).is_ok(),
                    "normalization must not turn an accepted timestamp into invalid text"
                );
                assert_eq!(
                    snapshot.earliest_retained_timestamp.as_deref(),
                    Some(stored.as_str())
                );
                assert_eq!(
                    snapshot.latest_retained_timestamp.as_deref(),
                    Some(stored.as_str())
                );
                let bill = crate::billing::unified::generate_bill_from_snapshot(
                    &snapshot,
                    "2026-08-01",
                    "2026-09-01",
                )
                .expect("an accepted timestamp must survive extrema and billing parsers");
                assert_eq!(bill.line_items.len(), 1);
                assert_eq!(bill.line_items[0].requests, 1);
                assert_eq!(bill.total, 1.0);
            }
            Err(other) => panic!("unexpected long-timestamp refusal: {other:?}"),
        }
    }

    #[test]
    fn group_f_hash_shaped_literal_does_not_alias_its_long_source_identity() {
        let long_source = long_ascii_dimension("provider-alpha");
        let hash_shaped_literal = format!(
            "{}~c0104aeca7087166ead283fc4d6c8f74fb16042e938e148be393b3b96adebb4d",
            "x".repeat(191)
        );
        assert_eq!(hash_shaped_literal.len(), 256);

        let record_pair = |reversed: bool| {
            let tracker = ChargebackTracker::with_limits(4, 8, 8);
            let make_entry = |identity: &str, cost: f64, timestamp: &str| {
                let mut input = entry(identity, cost);
                input.provider = identity.to_string();
                input.model = identity.to_string();
                input.timestamp = timestamp.to_string();
                input
            };
            let source_entry = make_entry(&long_source, 1.0, "2026-08-10T00:00:00Z");
            let literal_entry = make_entry(&hash_shaped_literal, 2.0, "2026-08-11T00:00:00Z");
            if reversed {
                assert_eq!(
                    tracker.try_record(Some(&hash_shaped_literal), literal_entry),
                    Ok(())
                );
                assert_eq!(tracker.try_record(Some(&long_source), source_entry), Ok(()));
            } else {
                assert_eq!(tracker.try_record(Some(&long_source), source_entry), Ok(()));
                assert_eq!(
                    tracker.try_record(Some(&hash_shaped_literal), literal_entry),
                    Ok(())
                );
            }
            tracker.snapshot()
        };

        let snapshot = record_pair(false);
        let reversed = record_pair(true);
        assert_ne!(snapshot.entries[0].workspace, snapshot.entries[1].workspace);
        assert_ne!(snapshot.entries[0].team, snapshot.entries[1].team);
        assert_ne!(snapshot.entries[0].provider, snapshot.entries[1].provider);
        assert_ne!(snapshot.entries[0].model, snapshot.entries[1].model);
        assert_eq!(workspace_values(&snapshot).len(), 2);
        assert_eq!(team_values(&snapshot).len(), 2);
        for cost in [1.0, 2.0] {
            let first = snapshot
                .entries
                .iter()
                .find(|entry| entry.cost == cost)
                .expect("cost identifies one source identity");
            let second = reversed
                .entries
                .iter()
                .find(|entry| entry.cost == cost)
                .expect("reversed tracker retains the same source identity");
            assert_eq!(first.workspace, second.workspace);
            assert_eq!(first.team, second.team);
            assert_eq!(first.provider, second.provider);
            assert_eq!(first.model, second.model);
        }
        assert!(snapshot.entries.iter().all(|entry| {
            entry.provider.len() <= 256
                && entry.model.len() <= 256
                && !entry.provider.contains(&long_source)
                && !entry.model.contains(&long_source)
        }));

        let bill = crate::billing::unified::generate_bill_from_snapshot(
            &snapshot,
            "2026-08-01",
            "2026-09-01",
        )
        .expect("a complete retained snapshot bills");
        assert_eq!(bill.line_items.len(), 2);
        assert_eq!(bill.total, 3.0);
    }

    #[test]
    fn group_f_present_empty_dimensions_remain_distinct_from_missing() {
        let tracker = ChargebackTracker::with_limits(4, 8, 8);
        UsageSink::record(&tracker, &usage_event(None, None, 1.0));
        UsageSink::record(&tracker, &usage_event(Some(""), Some(""), 2.0));

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.entries[0].workspace, DimensionKey::Missing);
        assert_eq!(snapshot.entries[0].team, DimensionKey::Missing);
        assert_eq!(
            snapshot.entries[1].workspace,
            DimensionKey::Value(String::new())
        );
        assert_eq!(snapshot.entries[1].team, DimensionKey::Value(String::new()));
        assert_eq!(
            workspace_rollup(&snapshot, &DimensionKey::Missing).map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            workspace_rollup(&snapshot, &DimensionKey::Value(String::new()))
                .map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            team_rollup(&snapshot, &DimensionKey::Missing).map(|totals| totals.request_count),
            Some(1)
        );
        assert_eq!(
            team_rollup(&snapshot, &DimensionKey::Value(String::new()))
                .map(|totals| totals.request_count),
            Some(1)
        );
    }

    #[test]
    fn export_view_pages_exact_and_plus_one_counts_without_cloning_retained_rows() {
        let tracker = ChargebackTracker::with_limits(8, 8, 8);
        for (workspace, team, timestamp) in [
            ("workspace-a", "team-a", "2026-08-20T00:00:00Z"),
            ("workspace-b", "team-b", "2026-08-21T00:00:00Z"),
            ("workspace-c", "team-c", "2026-08-22T00:00:00Z"),
        ] {
            assert_eq!(
                record_at(&tracker, Some(workspace), team, timestamp, 1.0),
                Ok(())
            );
        }

        let probe = ChargebackCallsiteProbe::install_for_current_thread();
        tracker.with_export_view(|view| {
            assert_eq!(view.entries_len(), 3);
            assert_eq!(view.entries(0, 3).count(), 3, "exact page");
            assert_eq!(view.entries(0, 4).count(), 3, "plus-one page");
            assert_eq!(view.entries(2, 2).count(), 1, "tail page");
        });
        let counters = probe.counters();
        assert_eq!(counters.snapshot_entry_clones, 0);
        assert_eq!(counters.accepted_timestamp_parses, 0);
        assert_eq!(counters.accepted_commits, 0);
    }

    #[test]
    fn group_f_full_retention_hot_path_does_not_reparse_or_clone_retained_rows() {
        const FULL_RETENTION_SHAPE: usize = 512;
        for (
            label,
            evicted,
            retained_even,
            retained_odd,
            incoming,
            expected_earliest,
            expected_latest,
        ) in [
            (
                "non-extreme eviction",
                "2026-08-20T00:00:00Z",
                "2026-08-10T00:00:00Z",
                "2026-08-30T00:00:00Z",
                "2026-08-15T00:00:00Z",
                "2026-08-10T00:00:00Z",
                "2026-08-30T00:00:00Z",
            ),
            (
                "sole-minimum eviction",
                "2026-08-01T00:00:00Z",
                "2026-08-20T00:00:00Z",
                "2026-08-30T00:00:00Z",
                "2026-08-25T00:00:00Z",
                "2026-08-20T00:00:00Z",
                "2026-08-30T00:00:00Z",
            ),
            (
                "sole-maximum eviction",
                "2026-08-31T00:00:00Z",
                "2026-08-10T00:00:00Z",
                "2026-08-20T00:00:00Z",
                "2026-08-15T00:00:00Z",
                "2026-08-10T00:00:00Z",
                "2026-08-20T00:00:00Z",
            ),
            (
                "incoming row becomes the new minimum",
                "2026-08-20T00:00:00Z",
                "2026-08-10T00:00:00Z",
                "2026-08-30T00:00:00Z",
                "2026-08-05T00:00:00Z",
                "2026-08-05T00:00:00Z",
                "2026-08-30T00:00:00Z",
            ),
            (
                "incoming row becomes the new maximum",
                "2026-08-20T00:00:00Z",
                "2026-08-10T00:00:00Z",
                "2026-08-30T00:00:00Z",
                "2026-09-05T00:00:00Z",
                "2026-08-10T00:00:00Z",
                "2026-09-05T00:00:00Z",
            ),
        ] {
            let tracker = ChargebackTracker::with_limits(FULL_RETENTION_SHAPE, 4, 4);
            for index in 0..FULL_RETENTION_SHAPE {
                let timestamp = if index == 0 {
                    evicted
                } else if index % 2 == 0 {
                    retained_even
                } else {
                    retained_odd
                };
                assert_eq!(
                    record_at(&tracker, Some("workspace-a"), "team-a", timestamp, 1.0,),
                    Ok(()),
                    "{label} setup"
                );
            }
            assert_eq!(
                tracker.entries_count(),
                FULL_RETENTION_SHAPE,
                "{label} setup"
            );

            let probe = ChargebackCallsiteProbe::install_for_current_thread();
            assert_eq!(
                record_at(&tracker, Some("workspace-a"), "team-a", incoming, 1.0,),
                Ok(()),
                "{label} accepted record"
            );
            let counters = probe.counters();
            assert_eq!(counters.accepted_timestamp_parses, 1, "{label}");
            assert_eq!(counters.snapshot_entry_clones, 0, "{label}");
            assert_eq!(counters.accepted_commits, 1, "{label}");
            drop(probe);

            let state = tracker.state.lock();
            assert_eq!(
                state.earliest_retained_timestamp.as_deref(),
                Some(expected_earliest),
                "{label} lower bound"
            );
            assert_eq!(
                state.latest_retained_timestamp.as_deref(),
                Some(expected_latest),
                "{label} upper bound"
            );
            assert_eq!(state.entries.len(), FULL_RETENTION_SHAPE, "{label}");
        }
    }

    #[test]
    fn group_f_live_usage_sink_refusal_signal_is_closed_and_non_flooding() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let tracker = std::sync::Arc::new(ChargebackTracker::with_limits(8, 8, 8));
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", f64::MAX)),
            Ok(())
        );
        let signals = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let layer = ChargebackRefusalSignalLayer {
            tracker: std::sync::Arc::clone(&tracker),
            signals: std::sync::Arc::clone(&signals),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..64 {
                UsageSink::record(
                    tracker.as_ref(),
                    &usage_event(
                        Some("private-workspace-must-not-be-signaled"),
                        Some("private-team-must-not-be-signaled"),
                        -7.25,
                    ),
                );
            }
            for _ in 0..64 {
                UsageSink::record(
                    tracker.as_ref(),
                    &usage_event(Some("workspace-a"), Some("team-b"), f64::MAX),
                );
            }
        });

        let signals = signals
            .lock()
            .expect("chargeback refusal signal capture mutex poisoned");
        assert_eq!(
            signals
                .iter()
                .map(|signal| signal.reason.clone())
                .collect::<Vec<_>>(),
            vec![
                format!("{:?}", ChargebackRecordError::InvalidCost),
                format!(
                    "{:?}",
                    ChargebackRecordError::ArithmeticOverflow {
                        scope: ChargebackOverflowScope::Workspace,
                        field: ChargebackOverflowField::Cost,
                    }
                ),
            ],
            "each closed refusal reason emits only its first observable signal"
        );
        assert!(
            signals.iter().all(|signal| signal.state_lock_available),
            "the observable signal must be emitted after releasing finance state"
        );
        let rendered = signals
            .iter()
            .flat_map(|signal| signal.rendered_fields.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!rendered.contains("private-workspace-must-not-be-signaled"));
        assert!(!rendered.contains("private-team-must-not-be-signaled"));
        assert!(!rendered.contains("7.25"));
    }

    #[test]
    fn group_f_live_refusal_metrics_count_each_refusal_but_only_the_first_incomplete_transition() {
        let tracker = ChargebackTracker::with_limits(8, 8, 8);
        let refusal_before = counter_total(
            "sbproxy_ai_chargeback_refusals_total",
            &[("reason", "invalid_cost")],
        );
        let incomplete_before = counter_total(
            "sbproxy_ai_chargeback_incomplete_total",
            &[("reason", "refused_row")],
        );

        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", -1.0)),
            Err(ChargebackRecordError::InvalidCost)
        );
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", -2.0)),
            Err(ChargebackRecordError::InvalidCost)
        );

        assert_eq!(
            counter_total(
                "sbproxy_ai_chargeback_refusals_total",
                &[("reason", "invalid_cost")]
            ),
            refusal_before + 2
        );
        assert_eq!(
            counter_total(
                "sbproxy_ai_chargeback_incomplete_total",
                &[("reason", "refused_row")]
            ),
            incomplete_before + 1
        );
    }

    #[test]
    fn group_f_finance_metrics_are_published_after_releasing_tracker_state() {
        let tracker = ChargebackTracker::with_limits(1, 1, 1);
        let poisoned_tracker = ChargebackTracker::with_limits(1, 4, 4);
        {
            let mut state = poisoned_tracker.state.lock();
            state.entries.push_back(snapshot_entry(
                DimensionKey::Missing,
                value_key("legacy-team"),
                "not-a-timestamp",
            ));
            state.recorded_entries = 1;
        }

        let probe = ChargebackCallsiteProbe::install_for_current_thread();
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-20T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-b"),
                "team-b",
                "2026-08-21T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", -1.0)),
            Err(ChargebackRecordError::InvalidCost)
        );
        assert_eq!(
            tracker.try_record(Some("workspace-a"), entry("team-a", -2.0)),
            Err(ChargebackRecordError::InvalidCost)
        );
        assert_eq!(
            record_at(
                &poisoned_tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-22T00:00:00Z",
                1.0,
            ),
            Ok(())
        );

        let counters = probe.counters();
        drop(probe);
        assert_eq!(
            counters.finance_metric_publications, 10,
            "two initial collapses, one eviction, two more collapses, three refusal metrics, and eviction plus poison metrics"
        );
        assert_eq!(
            counters.finance_metric_publications_with_state_lock_held, 0,
            "metrics registration/publication must not run inside the finance transaction mutex"
        );
    }

    #[test]
    fn group_f_watermark_poison_metric_counts_once_on_first_poisoned_eviction() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        {
            let mut state = tracker.state.lock();
            state.entries.push_back(snapshot_entry(
                DimensionKey::Missing,
                value_key("legacy-team"),
                "not-a-timestamp",
            ));
            state.recorded_entries = 1;
        }
        let before = counter_total(
            "sbproxy_ai_chargeback_incomplete_total",
            &[("reason", "eviction_watermark_poisoned")],
        );

        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-a"),
                "team-a",
                "2026-08-20T00:00:00Z",
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                Some("workspace-b"),
                "team-b",
                "2026-08-21T00:00:00Z",
                1.0,
            ),
            Ok(())
        );

        assert_eq!(
            counter_total(
                "sbproxy_ai_chargeback_incomplete_total",
                &[("reason", "eviction_watermark_poisoned")]
            ),
            before + 1
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
                .workspace_rollups
                .iter()
                .map(|rollup| rollup.totals.request_count)
                .sum::<u64>();
            let team_requests = snapshot
                .team_rollups
                .iter()
                .map(|rollup| rollup.totals.request_count)
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
