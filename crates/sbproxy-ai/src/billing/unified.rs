//! Unified billing report generation (WOR-2672 port of
//! `sbproxy-enterprise-ai::billing::unified`).
//!
//! Aggregates chargeback entries into a single bill covering a billing period.
//! Line items are grouped by (provider, model) pair so the output matches the
//! format expected by external finance systems.

use super::chargeback::{
    checked_money_add, ChargebackEntry, ChargebackRollup, ChargebackSnapshot, DimensionKey,
    CHARGEBACK_SNAPSHOT_SCHEMA_VERSION,
};
use chrono::{DateTime, NaiveDate, Utc};
use thiserror::Error;

/// A single line in a unified bill, grouped by provider and model.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BillLineItem {
    /// AI provider name.
    pub provider: String,
    /// Model identifier.
    pub model: String,
    /// Total number of requests in this line.
    pub requests: u64,
    /// Total tokens consumed.
    pub tokens: u64,
    /// Total cost in USD.
    pub cost: f64,
}

/// A unified billing statement covering a specific time period.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnifiedBill {
    /// ISO 8601 start of the billing period (inclusive).
    pub period_start: String,
    /// ISO 8601 end of the billing period (exclusive).
    pub period_end: String,
    /// Itemised charges grouped by provider and model.
    pub line_items: Vec<BillLineItem>,
    /// Sum of all `line_items[i].cost`.
    pub total: f64,
}

/// Validation failures at the billing-period boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialPeriodReason {
    /// One or more rows were refused or completeness was otherwise lost.
    IncompleteSnapshot,
    /// Evicted timestamps may overlap the requested half-open period.
    EvictedRange,
    /// Malformed retained history prevents a trustworthy eviction interval.
    PoisonedEvictionWatermark,
}

impl std::fmt::Display for PartialPeriodReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::IncompleteSnapshot => "incomplete snapshot",
            Self::EvictedRange => "evicted range intersects the billing period",
            Self::PoisonedEvictionWatermark => "poisoned eviction watermark",
        })
    }
}

/// Validation failures at the billing-period boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BillError {
    /// The inclusive period start was not an RFC 3339 timestamp or ISO date.
    #[error("invalid billing period start {value:?}; expected RFC 3339 or YYYY-MM-DD")]
    InvalidPeriodStart {
        /// Rejected caller value.
        value: String,
    },
    /// The exclusive period end was not an RFC 3339 timestamp or ISO date.
    #[error("invalid billing period end {value:?}; expected RFC 3339 or YYYY-MM-DD")]
    InvalidPeriodEnd {
        /// Rejected caller value.
        value: String,
    },
    /// The half-open period was empty or reversed.
    #[error("invalid billing period [{start}, {end}); end must be after start")]
    InvalidPeriod {
        /// Inclusive caller-provided start.
        start: String,
        /// Exclusive caller-provided end.
        end: String,
    },
    /// A supplied usage row did not carry a parseable timestamp.
    #[error(
        "invalid chargeback timestamp at entry {index}: {value:?}; expected RFC 3339 or YYYY-MM-DD"
    )]
    InvalidEntryTimestamp {
        /// Zero-based index in the supplied entry slice.
        index: usize,
        /// Rejected entry value.
        value: String,
    },
    /// A supplied usage row carried a negative or non-finite cost.
    #[error("invalid chargeback cost at entry {index}: {value}")]
    InvalidEntryCost {
        /// Zero-based index in the supplied entry slice.
        index: usize,
        /// Rejected cost rendered without placing an `f64` in this Eq error.
        value: String,
    },
    /// A numeric aggregate exceeded the type used by the bill format.
    #[error("billing arithmetic overflow while summing {field}")]
    ArithmeticOverflow {
        /// Aggregate that could not represent the exact result.
        field: &'static str,
    },
    /// A tracker snapshot cannot prove the requested period complete.
    #[error("cannot generate a complete bill: {reason}")]
    PartialPeriod {
        /// Evidence that makes the requested bill partial.
        reason: PartialPeriodReason,
    },
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SnapshotBillingCallsiteCounters {
    borrowed_entries_aggregated: usize,
    legacy_entries_materialized: usize,
    snapshot_entry_clones: usize,
}

#[cfg(test)]
std::thread_local! {
    static SNAPSHOT_BILLING_CALLSITE_COUNTERS: std::cell::RefCell<
        Option<SnapshotBillingCallsiteCounters>,
    > = const { std::cell::RefCell::new(None) };
}

/// Scoped test observation of the snapshot billing conversion path.
#[cfg(test)]
struct SnapshotBillingCallsiteProbe;

#[cfg(test)]
impl SnapshotBillingCallsiteProbe {
    fn install_for_current_thread() -> Self {
        SNAPSHOT_BILLING_CALLSITE_COUNTERS.with(|slot| {
            let previous = slot.replace(Some(SnapshotBillingCallsiteCounters::default()));
            assert!(
                previous.is_none(),
                "snapshot billing probe already installed"
            );
        });
        Self
    }

    fn counters(&self) -> SnapshotBillingCallsiteCounters {
        SNAPSHOT_BILLING_CALLSITE_COUNTERS.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("snapshot billing probe is installed")
                .clone()
        })
    }
}

#[cfg(test)]
impl Drop for SnapshotBillingCallsiteProbe {
    fn drop(&mut self) {
        SNAPSHOT_BILLING_CALLSITE_COUNTERS.with(|slot| {
            let _ = slot.replace(None);
        });
    }
}

#[cfg(test)]
fn observe_snapshot_billing_callsite(update: impl FnOnce(&mut SnapshotBillingCallsiteCounters)) {
    SNAPSHOT_BILLING_CALLSITE_COUNTERS.with(|slot| {
        if let Some(counters) = slot.borrow_mut().as_mut() {
            update(counters);
        }
    });
}

/// Called by the test-only manual `Clone` implementation on the real public
/// snapshot row. A restored `.cloned()` conversion therefore changes this
/// probe without relying on a production author to maintain a side counter.
#[cfg(test)]
pub(super) fn observe_snapshot_entry_clone() {
    observe_snapshot_billing_callsite(|counters| counters.snapshot_entry_clones += 1);
}

/// Called by the real lower-level v2-to-v1 entry conversion. The positive
/// retained-slice control proves the writer is live, while snapshot-aware
/// billing requires it to remain unused.
#[cfg(test)]
pub(super) fn observe_legacy_entry_materialization() {
    observe_snapshot_billing_callsite(|counters| counters.legacy_entries_materialized += 1);
}

/// Build a `UnifiedBill` from a slice of raw chargeback entries.
///
/// Both bounds accept RFC 3339 timestamps or `YYYY-MM-DD` (UTC midnight).
/// Entries are filtered to the explicit half-open interval
/// `[period_start, period_end)`: the start is inclusive and the end is
/// exclusive. Every supplied entry timestamp is validated, including rows
/// outside the requested interval, so malformed retained data cannot hide in
/// a finance export.
pub fn generate_bill(
    entries: &[ChargebackEntry],
    period_start: &str,
    period_end: &str,
) -> Result<UnifiedBill, BillError> {
    let (start, end) = validated_period(period_start, period_end)?;
    aggregate_bill(
        entries.iter().map(|entry| BillableEntry {
            provider: &entry.provider,
            model: &entry.model,
            tokens: entry.tokens,
            cost: entry.cost,
            timestamp: &entry.timestamp,
        }),
        period_start,
        period_end,
        start,
        end,
    )
}

#[derive(Debug, Clone, Copy)]
struct BillableEntry<'a> {
    provider: &'a str,
    model: &'a str,
    tokens: u64,
    cost: f64,
    timestamp: &'a str,
}

fn validated_period(
    period_start: &str,
    period_end: &str,
) -> Result<(DateTime<Utc>, DateTime<Utc>), BillError> {
    let start = parse_timestamp(period_start).ok_or_else(|| BillError::InvalidPeriodStart {
        value: period_start.to_string(),
    })?;
    let end = parse_timestamp(period_end).ok_or_else(|| BillError::InvalidPeriodEnd {
        value: period_end.to_string(),
    })?;
    if end <= start {
        return Err(BillError::InvalidPeriod {
            start: period_start.to_string(),
            end: period_end.to_string(),
        });
    }
    Ok((start, end))
}

fn aggregate_bill<'a>(
    entries: impl IntoIterator<Item = BillableEntry<'a>>,
    period_start: &str,
    period_end: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<UnifiedBill, BillError> {
    use std::collections::HashMap;

    // Aggregate by (provider, model).
    let mut map: HashMap<(String, String), BillLineItem> = HashMap::new();

    for (index, entry) in entries.into_iter().enumerate() {
        let timestamp =
            parse_timestamp(entry.timestamp).ok_or_else(|| BillError::InvalidEntryTimestamp {
                index,
                value: entry.timestamp.to_string(),
            })?;
        if !entry.cost.is_finite() || entry.cost < 0.0 {
            return Err(BillError::InvalidEntryCost {
                index,
                value: entry.cost.to_string(),
            });
        }
        if timestamp < start || timestamp >= end {
            continue;
        }
        let key = (entry.provider.to_string(), entry.model.to_string());
        let item = map.entry(key).or_insert_with(|| BillLineItem {
            provider: entry.provider.to_string(),
            model: entry.model.to_string(),
            requests: 0,
            tokens: 0,
            cost: 0.0,
        });
        item.requests = item
            .requests
            .checked_add(1)
            .ok_or(BillError::ArithmeticOverflow { field: "requests" })?;
        item.tokens = item
            .tokens
            .checked_add(entry.tokens)
            .ok_or(BillError::ArithmeticOverflow { field: "tokens" })?;
        let cost = checked_money_add(item.cost, entry.cost)
            .ok_or(BillError::ArithmeticOverflow { field: "cost" })?;
        item.cost = cost;
    }

    let mut line_items: Vec<BillLineItem> = map.into_values().collect();
    // Sort for deterministic output.
    line_items.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.model.cmp(&b.model)));

    let mut total = 0.0;
    for item in &line_items {
        total = checked_money_add(total, item.cost).ok_or(BillError::ArithmeticOverflow {
            field: "total cost",
        })?;
    }

    Ok(UnifiedBill {
        period_start: period_start.to_string(),
        period_end: period_end.to_string(),
        line_items,
        total,
    })
}

fn consistent_rollup_token_total(
    rows: &[ChargebackRollup],
    limit: usize,
    recorded_entries: u64,
    collapsed_events: u64,
) -> Option<u64> {
    if limit == 0
        || rows.len() > limit
        || collapsed_events > recorded_entries
        || rows
            .windows(2)
            .any(|pair| pair[0].dimension >= pair[1].dimension)
    {
        return None;
    }

    let mut requests = 0u64;
    let mut tokens = 0u64;
    let mut overflow_requests = None;
    for row in rows {
        if row.totals.request_count == 0
            || !row.totals.cost_usd.is_finite()
            || row.totals.cost_usd < 0.0
        {
            return None;
        }
        requests = requests.checked_add(row.totals.request_count)?;
        tokens = tokens.checked_add(row.totals.tokens)?;
        if row.dimension == DimensionKey::Overflow {
            overflow_requests = Some(row.totals.request_count);
        }
    }

    (requests == recorded_entries
        && match (collapsed_events, overflow_requests) {
            (0, None) => true,
            (0, Some(_)) | (_, None) => false,
            (collapsed, Some(overflow)) => overflow == collapsed,
        })
    .then_some(tokens)
}

fn retained_extrema_are_consistent(snapshot: &ChargebackSnapshot) -> bool {
    let Some(first) = snapshot.entries.first() else {
        return snapshot.earliest_retained_timestamp.is_none()
            && snapshot.latest_retained_timestamp.is_none();
    };
    let Some(first_time) = parse_timestamp(&first.timestamp) else {
        return false;
    };
    let mut earliest = (first_time, first.timestamp.as_str());
    let mut latest = earliest;
    for entry in snapshot.entries.iter().skip(1) {
        let Some(timestamp) = parse_timestamp(&entry.timestamp) else {
            return false;
        };
        if timestamp < earliest.0 {
            earliest = (timestamp, entry.timestamp.as_str());
        }
        if timestamp > latest.0 {
            latest = (timestamp, entry.timestamp.as_str());
        }
    }
    snapshot.earliest_retained_timestamp.as_deref() == Some(earliest.1)
        && snapshot.latest_retained_timestamp.as_deref() == Some(latest.1)
}

fn snapshot_shape_is_consistent(snapshot: &ChargebackSnapshot) -> bool {
    if snapshot.max_entries == 0 || snapshot.entries.len() > snapshot.max_entries {
        return false;
    }
    let Ok(retained_entries) = u64::try_from(snapshot.entries.len()) else {
        return false;
    };
    if snapshot.evicted_entries.checked_add(retained_entries) != Some(snapshot.recorded_entries) {
        return false;
    }
    let Some(workspace_tokens) = consistent_rollup_token_total(
        &snapshot.workspace_rollups,
        snapshot.max_workspaces,
        snapshot.recorded_entries,
        snapshot.collapsed_workspace_events,
    ) else {
        return false;
    };
    let Some(team_tokens) = consistent_rollup_token_total(
        &snapshot.team_rollups,
        snapshot.max_teams,
        snapshot.recorded_entries,
        snapshot.collapsed_team_events,
    ) else {
        return false;
    };
    workspace_tokens == team_tokens && retained_extrema_are_consistent(snapshot)
}

/// Build a bill only when a tracker snapshot proves the period complete.
///
/// Unlike [`generate_bill`], this boundary evaluates sticky refusal evidence
/// and the timestamp interval of evicted rows before using retained entries.
pub fn generate_bill_from_snapshot(
    snapshot: &ChargebackSnapshot,
    period_start: &str,
    period_end: &str,
) -> Result<UnifiedBill, BillError> {
    let (start, end) = validated_period(period_start, period_end)?;

    if snapshot.schema_version != CHARGEBACK_SNAPSHOT_SCHEMA_VERSION {
        return Err(BillError::PartialPeriod {
            reason: PartialPeriodReason::IncompleteSnapshot,
        });
    }

    if snapshot.eviction_watermark.poisoned {
        return Err(BillError::PartialPeriod {
            reason: PartialPeriodReason::PoisonedEvictionWatermark,
        });
    }

    if !snapshot.complete || snapshot.refused_entries != 0 || !snapshot.refusal_counts.is_empty() {
        return Err(BillError::PartialPeriod {
            reason: PartialPeriodReason::IncompleteSnapshot,
        });
    }

    let eviction_interval = match (
        snapshot.evicted_entries,
        snapshot.eviction_watermark.min_timestamp.as_deref(),
        snapshot.eviction_watermark.max_timestamp.as_deref(),
    ) {
        (0, None, None) => None,
        (0, _, _) | (_, None, _) | (_, _, None) => {
            return Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::PoisonedEvictionWatermark,
            });
        }
        (_, Some(minimum), Some(maximum)) => {
            let (Some(minimum), Some(maximum)) =
                (parse_timestamp(minimum), parse_timestamp(maximum))
            else {
                return Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::PoisonedEvictionWatermark,
                });
            };
            if minimum > maximum {
                return Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::PoisonedEvictionWatermark,
                });
            }
            Some((minimum, maximum))
        }
    };
    if !snapshot_shape_is_consistent(snapshot) {
        return Err(BillError::PartialPeriod {
            reason: PartialPeriodReason::IncompleteSnapshot,
        });
    }
    if let Some((minimum, maximum)) = eviction_interval {
        if maximum >= start && minimum < end {
            return Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::EvictedRange,
            });
        }
    }

    aggregate_bill(
        snapshot.entries.iter().map(|entry| {
            #[cfg(test)]
            observe_snapshot_billing_callsite(|counters| {
                counters.borrowed_entries_aggregated += 1;
            });
            BillableEntry {
                provider: &entry.provider,
                model: &entry.model,
                tokens: entry.tokens,
                cost: entry.cost,
                timestamp: &entry.timestamp,
            }
        }),
        period_start,
        period_end,
        start,
        end,
    )
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::chargeback::{
        ChargebackEntry, ChargebackRecordError, ChargebackRefusalCount, ChargebackRollup,
        ChargebackTracker, DimensionKey, WorkspaceTotals,
    };

    fn entry(provider: &str, model: &str, tokens: u64, cost: f64) -> ChargebackEntry {
        ChargebackEntry {
            team: "eng".to_string(),
            project: "p1".to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            tokens,
            cost,
            timestamp: "2026-04-16T00:00:00Z".to_string(),
        }
    }

    fn record_at(
        tracker: &ChargebackTracker,
        timestamp: &str,
        provider: &str,
        model: &str,
        tokens: u64,
        cost: f64,
    ) -> Result<(), ChargebackRecordError> {
        let mut input = entry(provider, model, tokens, cost);
        input.timestamp = timestamp.to_string();
        tracker.try_record(Some("workspace-a"), input)
    }

    fn complete_snapshot_with_two_rows() -> ChargebackSnapshot {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-20T00:00:00Z",
                "openai",
                "gpt-4o",
                10,
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-10T00:00:00Z",
                "anthropic",
                "claude-3-5-sonnet",
                20,
                2.0,
            ),
            Ok(())
        );
        tracker.snapshot()
    }

    #[test]
    fn empty_entries_produces_empty_bill() {
        let bill = generate_bill(&[], "2026-04-01", "2026-05-01").expect("valid period");
        assert!(bill.line_items.is_empty());
        assert_eq!(bill.total, 0.0);
        assert_eq!(bill.period_start, "2026-04-01");
        assert_eq!(bill.period_end, "2026-05-01");
    }

    #[test]
    fn single_entry_becomes_single_line_item() {
        let entries = vec![entry("openai", "gpt-4o", 1000, 2.5)];
        let bill = generate_bill(&entries, "2026-04-01", "2026-05-01").expect("valid period");
        assert_eq!(bill.line_items.len(), 1);
        assert_eq!(bill.line_items[0].provider, "openai");
        assert_eq!(bill.line_items[0].model, "gpt-4o");
        assert_eq!(bill.line_items[0].requests, 1);
        assert_eq!(bill.line_items[0].tokens, 1000);
        assert!((bill.total - 2.5).abs() < 0.001);
    }

    #[test]
    fn same_provider_model_aggregated() {
        let entries = vec![
            entry("openai", "gpt-4o", 1000, 1.0),
            entry("openai", "gpt-4o", 2000, 2.0),
        ];
        let bill = generate_bill(&entries, "2026-04-01", "2026-05-01").expect("valid period");
        assert_eq!(bill.line_items.len(), 1);
        assert_eq!(bill.line_items[0].requests, 2);
        assert_eq!(bill.line_items[0].tokens, 3000);
        assert!((bill.line_items[0].cost - 3.0).abs() < 0.001);
    }

    #[test]
    fn different_providers_produce_separate_line_items() {
        let entries = vec![
            entry("openai", "gpt-4o", 500, 1.0),
            entry("anthropic", "claude-3-5-sonnet", 600, 1.5),
        ];
        let bill = generate_bill(&entries, "2026-04-01", "2026-05-01").expect("valid period");
        assert_eq!(bill.line_items.len(), 2);
    }

    #[test]
    fn total_is_sum_of_line_items() {
        let entries = vec![
            entry("openai", "gpt-4o", 100, 1.0),
            entry("anthropic", "claude-3-haiku", 200, 0.5),
            entry("openai", "gpt-3.5-turbo", 300, 0.2),
        ];
        let bill = generate_bill(&entries, "2026-04-01", "2026-05-01").expect("valid period");
        assert!(
            (bill.total - 1.7).abs() < 0.001,
            "expected 1.7, got {}",
            bill.total
        );
    }

    #[test]
    fn period_fields_are_preserved() {
        let bill = generate_bill(&[], "2026-03-01", "2026-04-01").expect("valid period");
        assert_eq!(bill.period_start, "2026-03-01");
        assert_eq!(bill.period_end, "2026-04-01");
    }

    #[test]
    fn bill_filters_entries_to_half_open_period() {
        let mut before = entry("openai", "gpt-4o", 10, 1.0);
        before.timestamp = "2026-07-31T23:59:59Z".to_string();
        let mut first = entry("openai", "gpt-4o", 20, 2.0);
        first.timestamp = "2026-08-01T00:00:00Z".to_string();
        let mut last = entry("openai", "gpt-4o", 30, 3.0);
        last.timestamp = "2026-08-31T23:59:59Z".to_string();
        let mut exclusive_end = entry("openai", "gpt-4o", 40, 4.0);
        exclusive_end.timestamp = "2026-09-01T00:00:00Z".to_string();

        let bill = generate_bill(
            &[before, first, last, exclusive_end],
            "2026-08-01",
            "2026-09-01",
        )
        .expect("valid period");
        assert_eq!(bill.line_items[0].requests, 2);
        assert_eq!(bill.line_items[0].tokens, 50);
        assert!((bill.total - 5.0).abs() < 0.001);
    }

    #[test]
    fn bill_rejects_invalid_or_reversed_periods() {
        assert!(matches!(
            generate_bill(&[], "not-a-date", "2026-09-01"),
            Err(BillError::InvalidPeriodStart { .. })
        ));
        assert!(matches!(
            generate_bill(&[], "2026-09-01", "2026-08-01"),
            Err(BillError::InvalidPeriod { .. })
        ));
        assert!(matches!(
            generate_bill(&[], "2026-08-01", "2026-08-01"),
            Err(BillError::InvalidPeriod { .. })
        ));
    }

    #[test]
    fn bill_rejects_an_invalid_entry_timestamp() {
        let mut invalid = entry("openai", "gpt-4o", 10, 1.0);
        invalid.timestamp = "yesterday-ish".to_string();
        assert!(matches!(
            generate_bill(&[invalid], "2026-08-01", "2026-09-01"),
            Err(BillError::InvalidEntryTimestamp { index: 0, .. })
        ));
    }

    #[test]
    fn bill_rejects_invalid_costs_and_numeric_overflow() {
        let invalid_cost = entry("openai", "gpt-4o", 10, -1.0);
        assert!(matches!(
            generate_bill(&[invalid_cost], "2026-04-01", "2026-05-01"),
            Err(BillError::InvalidEntryCost { index: 0, .. })
        ));

        let entries = vec![
            entry("openai", "gpt-4o", u64::MAX, 1.0),
            entry("openai", "gpt-4o", 1, 1.0),
        ];
        assert!(matches!(
            generate_bill(&entries, "2026-04-01", "2026-05-01"),
            Err(BillError::ArithmeticOverflow { field: "tokens" })
        ));
    }

    #[test]
    fn group_f_bill_refuses_positive_cost_absorption_inside_each_line_item() {
        assert_eq!(
            f64::MAX + 0.5,
            f64::MAX,
            "the fixture must exercise finite positive monetary absorption"
        );
        for entries in [
            vec![
                entry("openai", "gpt-4o", 10, f64::MAX),
                entry("openai", "gpt-4o", 20, 0.5),
            ],
            vec![
                entry("openai", "gpt-4o", 10, 0.5),
                entry("openai", "gpt-4o", 20, f64::MAX),
            ],
        ] {
            assert_eq!(
                generate_bill(&entries, "2026-04-01", "2026-05-01"),
                Err(BillError::ArithmeticOverflow { field: "cost" }),
                "a positive in-period amount may not disappear in either input order"
            );
        }
    }

    #[test]
    fn group_f_bill_refuses_positive_cost_absorption_in_final_total() {
        assert_eq!(
            f64::MAX + 0.5,
            f64::MAX,
            "the fixture must exercise finite positive monetary absorption"
        );
        let entries = vec![
            entry("openai", "gpt-4o", 10, f64::MAX),
            entry("anthropic", "claude-3-5-sonnet", 20, 0.5),
        ];

        assert_eq!(
            generate_bill(&entries, "2026-04-01", "2026-05-01"),
            Err(BillError::ArithmeticOverflow {
                field: "total cost",
            }),
            "separate exact line items may not lose a positive amount in the bill total"
        );
    }

    #[test]
    fn retained_slice_bill_remains_a_caller_asserted_complete_lower_level_boundary(
    ) -> Result<(), BillError> {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        let mut first = entry("openai", "gpt-4o", 10, 1.0);
        first.timestamp = "2026-08-01T00:00:00Z".to_string();
        let mut second = entry("openai", "gpt-4o", 20, 2.0);
        second.timestamp = "2026-08-02T00:00:00Z".to_string();
        let mut third = entry("openai", "gpt-4o", 30, 3.0);
        third.timestamp = "2026-08-03T00:00:00Z".to_string();

        tracker.record(first);
        tracker.record(second);
        tracker.record(third);

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.recorded_entries, 3);
        assert_eq!(snapshot.evicted_entries, 1);
        assert_eq!(snapshot.entries.len(), 2);

        let probe = SnapshotBillingCallsiteProbe::install_for_current_thread();
        let retained_entries = tracker.entries_snapshot();
        let counters = probe.counters();
        drop(probe);
        assert_eq!(counters.legacy_entries_materialized, 2);
        assert_eq!(counters.borrowed_entries_aggregated, 0);
        assert_eq!(counters.snapshot_entry_clones, 0);
        let retained_only = generate_bill(&retained_entries, "2026-08-01", "2026-09-01")?;
        assert_eq!(retained_only.line_items[0].requests, 2);
        assert_eq!(retained_only.line_items[0].tokens, 50);
        assert_eq!(retained_only.total, 5.0);
        Ok(())
    }

    #[test]
    fn group_f_tracker_bill_refuses_evicted_in_period_spend() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-01T00:00:00Z",
                "openai",
                "gpt-4o",
                10,
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-02T00:00:00Z",
                "openai",
                "gpt-4o",
                20,
                2.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-03T00:00:00Z",
                "openai",
                "gpt-4o",
                30,
                3.0,
            ),
            Ok(())
        );

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.recorded_entries, 3);
        assert_eq!(snapshot.evicted_entries, 1);
        assert_eq!(snapshot.entries.len(), 2);
        assert!(matches!(
            generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::EvictedRange
            })
        ));
    }

    #[test]
    fn group_f_snapshot_bill_without_eviction_is_complete() -> Result<(), BillError> {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-10T00:00:00Z",
                "openai",
                "gpt-4o",
                10,
                1.0,
            ),
            Ok(())
        );
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.evicted_entries, 0);
        assert_eq!(snapshot.eviction_watermark.min_timestamp, None);
        assert_eq!(snapshot.eviction_watermark.max_timestamp, None);
        assert!(!snapshot.eviction_watermark.poisoned);

        let bill = generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01")?;
        assert_eq!(bill.line_items.len(), 1);
        assert_eq!(bill.line_items[0].requests, 1);
        assert_eq!(bill.total, 1.0);
        Ok(())
    }

    #[test]
    fn group_f_legitimate_empty_and_collapsed_overflow_snapshots_are_complete(
    ) -> Result<(), BillError> {
        let empty = ChargebackTracker::with_limits(4, 4, 4).snapshot();
        let empty_bill = generate_bill_from_snapshot(&empty, "2026-08-01", "2026-09-01")?;
        assert_eq!(empty.recorded_entries, 0);
        assert_eq!(empty.evicted_entries, 0);
        assert!(empty.entries.is_empty());
        assert!(empty.workspace_rollups.is_empty());
        assert!(empty.team_rollups.is_empty());
        assert_eq!(empty.earliest_retained_timestamp, None);
        assert_eq!(empty.latest_retained_timestamp, None);
        assert!(empty_bill.line_items.is_empty());
        assert_eq!(empty_bill.total, 0.0);

        let tracker = ChargebackTracker::with_limits(4, 2, 2);
        let mut first = entry("openai", "gpt-4o", 10, 1.0);
        first.team = "team-a".to_string();
        first.timestamp = "2026-08-10T00:00:00Z".to_string();
        assert_eq!(tracker.try_record(Some("workspace-a"), first), Ok(()));
        let mut collapsed = entry("anthropic", "claude-3-5-sonnet", 20, 2.0);
        collapsed.team = "team-b".to_string();
        collapsed.timestamp = "2026-08-11T00:00:00Z".to_string();
        assert_eq!(tracker.try_record(Some("workspace-b"), collapsed), Ok(()));

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.recorded_entries, 2);
        assert_eq!(snapshot.evicted_entries, 0);
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.workspace_rollups.len(), 2);
        assert_eq!(snapshot.team_rollups.len(), 2);
        assert_eq!(snapshot.collapsed_workspace_events, 1);
        assert_eq!(snapshot.collapsed_team_events, 1);
        assert!(snapshot
            .workspace_rollups
            .iter()
            .any(|rollup| rollup.dimension == DimensionKey::Overflow));
        assert!(snapshot
            .team_rollups
            .iter()
            .any(|rollup| rollup.dimension == DimensionKey::Overflow));

        let bill = generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01")?;
        assert_eq!(
            bill.line_items
                .iter()
                .map(|item| item.requests)
                .sum::<u64>(),
            2
        );
        assert_eq!(bill.total, 3.0);
        Ok(())
    }

    #[test]
    fn group_f_snapshot_bill_allows_evictions_strictly_before_period() -> Result<(), BillError> {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-07-01T00:00:00Z",
                "openai",
                "gpt-4o",
                10,
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-07-31T23:59:59Z",
                "openai",
                "gpt-4o",
                20,
                2.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-10T00:00:00Z",
                "openai",
                "gpt-4o",
                30,
                3.0,
            ),
            Ok(())
        );
        let snapshot = tracker.snapshot();
        assert_eq!(
            snapshot.eviction_watermark.max_timestamp.as_deref(),
            Some("2026-07-31T23:59:59Z")
        );

        let bill = generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01")?;
        assert_eq!(bill.line_items[0].requests, 1);
        assert_eq!(bill.line_items[0].tokens, 30);
        assert_eq!(bill.total, 3.0);
        Ok(())
    }

    #[test]
    fn group_f_snapshot_bill_refuses_eviction_at_start_or_inside_period() {
        for evicted_at in ["2026-08-01T00:00:00Z", "2026-08-15T12:00:00Z"] {
            let tracker = ChargebackTracker::with_limits(1, 4, 4);
            assert_eq!(
                record_at(&tracker, evicted_at, "openai", "gpt-4o", 10, 1.0,),
                Ok(())
            );
            assert_eq!(
                record_at(
                    &tracker,
                    "2026-08-20T00:00:00Z",
                    "openai",
                    "gpt-4o",
                    20,
                    2.0,
                ),
                Ok(())
            );

            assert!(matches!(
                generate_bill_from_snapshot(&tracker.snapshot(), "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::EvictedRange
                })
            ));
        }
    }

    #[test]
    fn group_f_snapshot_bill_allows_a_sole_eviction_at_or_after_exclusive_end(
    ) -> Result<(), BillError> {
        for evicted_at in ["2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"] {
            let tracker = ChargebackTracker::with_limits(1, 4, 4);
            assert_eq!(
                record_at(&tracker, evicted_at, "openai", "gpt-4o", 10, 1.0,),
                Ok(())
            );
            assert_eq!(
                record_at(
                    &tracker,
                    "2026-08-15T00:00:00Z",
                    "openai",
                    "gpt-4o",
                    20,
                    2.0,
                ),
                Ok(())
            );
            let snapshot = tracker.snapshot();
            assert_eq!(
                snapshot.eviction_watermark.min_timestamp.as_deref(),
                Some(evicted_at)
            );
            assert_eq!(
                snapshot.eviction_watermark.max_timestamp.as_deref(),
                Some(evicted_at)
            );

            let bill = generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01")?;
            assert_eq!(bill.line_items[0].requests, 1);
            assert_eq!(bill.line_items[0].tokens, 20);
            assert_eq!(bill.total, 2.0);
        }
        Ok(())
    }

    #[test]
    fn group_f_out_of_order_eviction_interval_is_conservatively_partial() {
        let tracker = ChargebackTracker::with_limits(1, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-07-01T00:00:00Z",
                "openai",
                "gpt-4o",
                10,
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-10-01T00:00:00Z",
                "openai",
                "gpt-4o",
                20,
                2.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-15T00:00:00Z",
                "openai",
                "gpt-4o",
                30,
                3.0,
            ),
            Ok(())
        );
        let snapshot = tracker.snapshot();
        assert_eq!(
            snapshot.eviction_watermark.min_timestamp.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            snapshot.eviction_watermark.max_timestamp.as_deref(),
            Some("2026-10-01T00:00:00Z")
        );
        assert!(matches!(
            generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::EvictedRange
            })
        ));
    }

    #[test]
    fn group_f_refusal_poisoned_snapshot_is_partial_for_every_period() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-01T00:00:00Z",
                "openai",
                "gpt-4o",
                10,
                -1.0,
            ),
            Err(ChargebackRecordError::InvalidCost)
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-10T00:00:00Z",
                "openai",
                "gpt-4o",
                20,
                2.0,
            ),
            Ok(())
        );
        let snapshot = tracker.snapshot();
        assert!(!snapshot.complete);
        assert_eq!(snapshot.refused_entries, 1);
        assert!(matches!(
            generate_bill_from_snapshot(&snapshot, "2030-01-01", "2030-02-01"),
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::IncompleteSnapshot
            })
        ));
    }

    #[test]
    fn group_f_unknown_incomplete_snapshot_is_partial_without_counter_evidence() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        let mut snapshot = tracker.snapshot();
        assert!(snapshot.complete);
        assert_eq!(snapshot.refused_entries, 0);
        assert!(snapshot.refusal_counts.is_empty());
        assert_eq!(snapshot.evicted_entries, 0);
        assert_eq!(snapshot.eviction_watermark.min_timestamp, None);
        assert_eq!(snapshot.eviction_watermark.max_timestamp, None);
        assert!(!snapshot.eviction_watermark.poisoned);

        snapshot.complete = false;
        assert!(matches!(
            generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::IncompleteSnapshot
            })
        ));
    }

    #[test]
    fn group_f_poisoned_eviction_watermark_is_partial() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-10T00:00:00Z",
                "openai",
                "gpt-4o",
                20,
                2.0,
            ),
            Ok(())
        );
        let mut snapshot = tracker.snapshot();
        snapshot.eviction_watermark.poisoned = true;

        assert!(matches!(
            generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::PoisonedEvictionWatermark
            })
        ));
    }

    #[test]
    fn group_f_snapshot_bill_keeps_distinct_digest_suffixed_provider_model_groups(
    ) -> Result<(), BillError> {
        let provider_alpha = format!("{}-provider-alpha", "x".repeat(270));
        let provider_beta = format!("{}-provider-beta", "x".repeat(270));
        let model_alpha = format!("{}-model-alpha", "x".repeat(270));
        let model_beta = format!("{}-model-beta", "x".repeat(270));
        let expected_provider_alpha = format!(
            "{}~c0104aeca7087166ead283fc4d6c8f74fb16042e938e148be393b3b96adebb4d",
            "x".repeat(191)
        );
        let expected_model_alpha = format!(
            "{}~9df9822fb045e57a5b8a1c9ca6614ff9174f8e4d1ddeb8b89e094f18497c0339",
            "x".repeat(191)
        );
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-10T00:00:00Z",
                &provider_alpha,
                &model_alpha,
                10,
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &tracker,
                "2026-08-11T00:00:00Z",
                &provider_beta,
                &model_beta,
                20,
                2.0,
            ),
            Ok(())
        );

        let bill = generate_bill_from_snapshot(&tracker.snapshot(), "2026-08-01", "2026-09-01")?;
        assert_eq!(bill.line_items.len(), 2);
        assert!(bill
            .line_items
            .iter()
            .all(|item| item.provider.len() <= 256 && item.model.len() <= 256));
        assert!(bill
            .line_items
            .iter()
            .all(|item| item.provider != provider_alpha && item.provider != provider_beta));
        assert!(bill
            .line_items
            .iter()
            .all(|item| item.model != model_alpha && item.model != model_beta));
        assert!(bill.line_items.iter().any(|item| {
            item.provider == expected_provider_alpha && item.model == expected_model_alpha
        }));
        assert_eq!(bill.total, 3.0);
        Ok(())
    }

    #[test]
    fn group_f_snapshot_bill_rejects_unsupported_snapshot_schema() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        let mut snapshot = tracker.snapshot();
        assert_eq!(
            snapshot.schema_version, 2,
            "control is the supported v2 shape"
        );
        snapshot.schema_version = 99;

        assert_eq!(
            generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::IncompleteSnapshot,
            })
        );
    }

    #[test]
    fn group_f_snapshot_bill_rejects_inverted_missing_and_impossible_eviction_evidence() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        let base = tracker.snapshot();
        let mut missing_minimum = base.clone();
        missing_minimum.evicted_entries = 1;
        missing_minimum.eviction_watermark.max_timestamp = Some("2026-07-20T00:00:00Z".to_string());

        let mut missing_maximum = base.clone();
        missing_maximum.evicted_entries = 1;
        missing_maximum.eviction_watermark.min_timestamp = Some("2026-07-20T00:00:00Z".to_string());

        let mut inverted = base.clone();
        inverted.evicted_entries = 2;
        inverted.eviction_watermark.min_timestamp = Some("2026-09-10T00:00:00Z".to_string());
        inverted.eviction_watermark.max_timestamp = Some("2026-07-10T00:00:00Z".to_string());

        let mut evidence_without_eviction = base;
        evidence_without_eviction.eviction_watermark.min_timestamp =
            Some("2026-07-10T00:00:00Z".to_string());
        evidence_without_eviction.eviction_watermark.max_timestamp =
            Some("2026-07-20T00:00:00Z".to_string());

        for (label, snapshot, reason) in [
            (
                "missing minimum",
                missing_minimum,
                PartialPeriodReason::PoisonedEvictionWatermark,
            ),
            (
                "missing maximum",
                missing_maximum,
                PartialPeriodReason::PoisonedEvictionWatermark,
            ),
            (
                "inverted extrema",
                inverted,
                PartialPeriodReason::PoisonedEvictionWatermark,
            ),
            (
                "watermark without an eviction",
                evidence_without_eviction,
                PartialPeriodReason::PoisonedEvictionWatermark,
            ),
        ] {
            assert_eq!(
                generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod { reason }),
                "{label} must never certify a complete period"
            );
        }
    }

    #[test]
    fn group_f_snapshot_bill_rejects_contradictory_refusal_evidence() {
        let tracker = ChargebackTracker::with_limits(2, 4, 4);
        let base = tracker.snapshot();
        let refusal = ChargebackRefusalCount {
            reason: ChargebackRecordError::InvalidCost,
            count: 1,
        };

        let mut complete_with_refusal = base.clone();
        complete_with_refusal.refused_entries = 1;
        complete_with_refusal.refusal_counts = vec![refusal.clone()];

        let mut count_without_total = base.clone();
        count_without_total.refusal_counts = vec![refusal.clone()];

        let mut total_without_count = base.clone();
        total_without_count.refused_entries = 1;

        let mut mismatched_total = base;
        mismatched_total.refused_entries = 2;
        mismatched_total.refusal_counts = vec![refusal.clone()];

        let mut zero_count_row = tracker.snapshot();
        zero_count_row.refusal_counts = vec![ChargebackRefusalCount {
            reason: ChargebackRecordError::InvalidTimestamp,
            count: 0,
        }];

        let mut duplicate_reason_rows = tracker.snapshot();
        duplicate_reason_rows.refused_entries = 2;
        duplicate_reason_rows.refusal_counts = vec![refusal.clone(), refusal];

        for (label, snapshot) in [
            ("complete bit with a refusal", complete_with_refusal),
            ("reason count without aggregate", count_without_total),
            ("aggregate without reason count", total_without_count),
            ("aggregate and reason-count mismatch", mismatched_total),
            ("zero-count refusal row", zero_count_row),
            ("duplicate refusal reason rows", duplicate_reason_rows),
        ] {
            assert_eq!(
                generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::IncompleteSnapshot,
                }),
                "{label} must not be interpreted as complete finance evidence"
            );
        }
    }

    #[test]
    fn group_f_snapshot_bill_rejects_retention_accounting_contradictions() {
        let base = complete_snapshot_with_two_rows();
        let valid = generate_bill_from_snapshot(&base, "2026-08-01", "2026-09-01")
            .expect("the unmodified snapshot is the positive control");
        assert_eq!(
            valid
                .line_items
                .iter()
                .map(|item| item.requests)
                .sum::<u64>(),
            2
        );
        assert_eq!(valid.total, 3.0);

        let mut empty_with_recorded_row = ChargebackTracker::with_limits(4, 4, 4).snapshot();
        empty_with_recorded_row.recorded_entries = 1;

        let mut fewer_recorded_than_retained = base.clone();
        fewer_recorded_than_retained.recorded_entries = 1;

        let mut more_recorded_without_eviction = base.clone();
        more_recorded_without_eviction.recorded_entries = 3;

        let mut zero_retention_limit = base.clone();
        zero_retention_limit.max_entries = 0;

        let mut retained_rows_exceed_limit = base.clone();
        retained_rows_exceed_limit.max_entries = 1;

        let mut eviction_count_breaks_partition = base;
        eviction_count_breaks_partition.evicted_entries = 1;
        eviction_count_breaks_partition
            .eviction_watermark
            .min_timestamp = Some("2026-07-01T00:00:00Z".to_string());
        eviction_count_breaks_partition
            .eviction_watermark
            .max_timestamp = Some("2026-07-01T00:00:00Z".to_string());

        let mut wrapping_partition_forgery = complete_snapshot_with_two_rows();
        wrapping_partition_forgery.recorded_entries = 1;
        wrapping_partition_forgery.evicted_entries = u64::MAX;
        wrapping_partition_forgery.workspace_rollups[0]
            .totals
            .request_count = 1;
        wrapping_partition_forgery.team_rollups[0]
            .totals
            .request_count = 1;
        wrapping_partition_forgery.eviction_watermark.min_timestamp =
            Some("2026-07-01T00:00:00Z".to_string());
        wrapping_partition_forgery.eviction_watermark.max_timestamp =
            Some("2026-07-01T00:00:00Z".to_string());

        let mut saturating_partition_forgery = complete_snapshot_with_two_rows();
        saturating_partition_forgery.recorded_entries = u64::MAX;
        saturating_partition_forgery.evicted_entries = u64::MAX;
        saturating_partition_forgery.workspace_rollups[0]
            .totals
            .request_count = u64::MAX;
        saturating_partition_forgery.team_rollups[0]
            .totals
            .request_count = u64::MAX;
        saturating_partition_forgery
            .eviction_watermark
            .min_timestamp = Some("2026-07-01T00:00:00Z".to_string());
        saturating_partition_forgery
            .eviction_watermark
            .max_timestamp = Some("2026-07-01T00:00:00Z".to_string());

        for (label, snapshot) in [
            ("wrapping partition arithmetic", &wrapping_partition_forgery),
            (
                "saturating partition arithmetic",
                &saturating_partition_forgery,
            ),
        ] {
            let probe = SnapshotBillingCallsiteProbe::install_for_current_thread();
            let result = generate_bill_from_snapshot(snapshot, "2026-08-01", "2026-09-01");
            let counters = probe.counters();
            drop(probe);
            assert_eq!(counters.borrowed_entries_aggregated, 0, "{label}");
            assert_eq!(counters.legacy_entries_materialized, 0, "{label}");
            assert_eq!(counters.snapshot_entry_clones, 0, "{label}");
            assert_eq!(
                result,
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::IncompleteSnapshot,
                }),
                "{label} must be refused before retained billing"
            );
        }

        for (label, snapshot) in [
            ("recorded row with empty retention", empty_with_recorded_row),
            (
                "fewer recorded rows than retained rows",
                fewer_recorded_than_retained,
            ),
            ("unexplained recorded row", more_recorded_without_eviction),
            ("zero public retention limit", zero_retention_limit),
            (
                "retained rows exceed public limit",
                retained_rows_exceed_limit,
            ),
            (
                "recorded/evicted/retained partition mismatch",
                eviction_count_breaks_partition,
            ),
            (
                "wrapping partition arithmetic aliases one accepted row",
                wrapping_partition_forgery,
            ),
            (
                "saturating partition arithmetic aliases the maximum count",
                saturating_partition_forgery,
            ),
        ] {
            assert_eq!(
                generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::IncompleteSnapshot,
                }),
                "{label} must never yield a complete bill"
            );
        }
    }

    #[test]
    fn group_f_snapshot_bill_rejects_request_rollup_and_cardinality_contradictions() {
        let base = complete_snapshot_with_two_rows();

        let mut missing_workspace_rollup = base.clone();
        missing_workspace_rollup.workspace_rollups.clear();

        let mut missing_team_rollup = base.clone();
        missing_team_rollup.team_rollups.clear();

        let mut wrong_workspace_requests = base.clone();
        wrong_workspace_requests.workspace_rollups[0]
            .totals
            .request_count = 1;

        let mut wrong_team_requests = base.clone();
        wrong_team_requests.team_rollups[0].totals.request_count = 1;

        let mut overflowing_workspace_sum = base.clone();
        overflowing_workspace_sum
            .workspace_rollups
            .push(ChargebackRollup {
                dimension: DimensionKey::Value("workspace-overflow-fixture".to_string()),
                totals: WorkspaceTotals {
                    tokens: 0,
                    cost_usd: 0.0,
                    request_count: u64::MAX,
                },
            });

        let mut overflowing_team_sum = base.clone();
        overflowing_team_sum.team_rollups.push(ChargebackRollup {
            dimension: DimensionKey::Value("team-overflow-fixture".to_string()),
            totals: WorkspaceTotals {
                tokens: 0,
                cost_usd: 0.0,
                request_count: u64::MAX,
            },
        });

        let mut duplicate_workspace_dimension = base.clone();
        duplicate_workspace_dimension.workspace_rollups[0]
            .totals
            .request_count = 1;
        let mut duplicate_workspace_row =
            duplicate_workspace_dimension.workspace_rollups[0].clone();
        duplicate_workspace_row.totals.request_count = 1;
        duplicate_workspace_dimension
            .workspace_rollups
            .push(duplicate_workspace_row);

        let mut duplicate_team_dimension = base.clone();
        duplicate_team_dimension.team_rollups[0]
            .totals
            .request_count = 1;
        let mut duplicate_team_row = duplicate_team_dimension.team_rollups[0].clone();
        duplicate_team_row.totals.request_count = 1;
        duplicate_team_dimension
            .team_rollups
            .push(duplicate_team_row);

        let mut impossible_workspace_collapse_count = base.clone();
        impossible_workspace_collapse_count.collapsed_workspace_events = 3;

        let mut impossible_team_collapse_count = base.clone();
        impossible_team_collapse_count.collapsed_team_events = 3;

        let one_request_totals = || WorkspaceTotals {
            tokens: 0,
            cost_usd: 0.0,
            request_count: 1,
        };

        let mut positive_workspace_limit_too_small = base.clone();
        positive_workspace_limit_too_small.workspace_rollups[0]
            .totals
            .request_count = 1;
        positive_workspace_limit_too_small
            .workspace_rollups
            .push(ChargebackRollup {
                dimension: DimensionKey::Value("workspace-z".to_string()),
                totals: one_request_totals(),
            });
        positive_workspace_limit_too_small.max_workspaces = 1;

        let mut positive_team_limit_too_small = base.clone();
        positive_team_limit_too_small.team_rollups[0]
            .totals
            .request_count = 1;
        positive_team_limit_too_small
            .team_rollups
            .push(ChargebackRollup {
                dimension: DimensionKey::Value("team-z".to_string()),
                totals: one_request_totals(),
            });
        positive_team_limit_too_small.max_teams = 1;

        let non_adjacent_rows = || {
            vec![
                ChargebackRollup {
                    dimension: DimensionKey::Value("a".to_string()),
                    totals: one_request_totals(),
                },
                ChargebackRollup {
                    dimension: DimensionKey::Value("b".to_string()),
                    totals: one_request_totals(),
                },
                ChargebackRollup {
                    dimension: DimensionKey::Value("a".to_string()),
                    totals: one_request_totals(),
                },
            ]
        };
        let mut non_adjacent_workspace_duplicate = base.clone();
        non_adjacent_workspace_duplicate.recorded_entries = 3;
        non_adjacent_workspace_duplicate.evicted_entries = 1;
        non_adjacent_workspace_duplicate.workspace_rollups = non_adjacent_rows();
        non_adjacent_workspace_duplicate.team_rollups[0]
            .totals
            .request_count = 3;
        non_adjacent_workspace_duplicate
            .eviction_watermark
            .min_timestamp = Some("2026-07-01T00:00:00Z".to_string());
        non_adjacent_workspace_duplicate
            .eviction_watermark
            .max_timestamp = Some("2026-07-01T00:00:00Z".to_string());

        let mut non_adjacent_team_duplicate = base.clone();
        non_adjacent_team_duplicate.recorded_entries = 3;
        non_adjacent_team_duplicate.evicted_entries = 1;
        non_adjacent_team_duplicate.team_rollups = non_adjacent_rows();
        non_adjacent_team_duplicate.workspace_rollups[0]
            .totals
            .request_count = 3;
        non_adjacent_team_duplicate.eviction_watermark.min_timestamp =
            Some("2026-07-01T00:00:00Z".to_string());
        non_adjacent_team_duplicate.eviction_watermark.max_timestamp =
            Some("2026-07-01T00:00:00Z".to_string());

        let reverse_canonical_rows = || {
            vec![
                ChargebackRollup {
                    dimension: DimensionKey::Value("z".to_string()),
                    totals: one_request_totals(),
                },
                ChargebackRollup {
                    dimension: DimensionKey::Value("a".to_string()),
                    totals: one_request_totals(),
                },
            ]
        };
        let mut noncanonical_workspace_order = base.clone();
        noncanonical_workspace_order.workspace_rollups = reverse_canonical_rows();

        let mut noncanonical_team_order = base.clone();
        noncanonical_team_order.team_rollups = reverse_canonical_rows();

        let mut workspace_rows_exceed_limit = base.clone();
        workspace_rows_exceed_limit.max_workspaces = 0;

        let mut team_rows_exceed_limit = base;
        team_rows_exceed_limit.max_teams = 0;

        for (label, snapshot) in [
            ("missing workspace rollup", missing_workspace_rollup),
            ("missing team rollup", missing_team_rollup),
            ("workspace request sum mismatch", wrong_workspace_requests),
            ("team request sum mismatch", wrong_team_requests),
            ("workspace request sum overflow", overflowing_workspace_sum),
            ("team request sum overflow", overflowing_team_sum),
            (
                "duplicate workspace dimension",
                duplicate_workspace_dimension,
            ),
            ("duplicate team dimension", duplicate_team_dimension),
            (
                "workspace collapse count exceeds accepted rows",
                impossible_workspace_collapse_count,
            ),
            (
                "team collapse count exceeds accepted rows",
                impossible_team_collapse_count,
            ),
            (
                "positive workspace row limit is too small",
                positive_workspace_limit_too_small,
            ),
            (
                "positive team row limit is too small",
                positive_team_limit_too_small,
            ),
            (
                "non-adjacent workspace A/B/A duplicate",
                non_adjacent_workspace_duplicate,
            ),
            (
                "non-adjacent team A/B/A duplicate",
                non_adjacent_team_duplicate,
            ),
            (
                "workspace rollups are not in canonical order",
                noncanonical_workspace_order,
            ),
            (
                "team rollups are not in canonical order",
                noncanonical_team_order,
            ),
            (
                "workspace rows exceed declared limit",
                workspace_rows_exceed_limit,
            ),
            ("team rows exceed declared limit", team_rows_exceed_limit),
        ] {
            assert_eq!(
                generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::IncompleteSnapshot,
                }),
                "{label} must never yield a complete bill"
            );
        }
    }

    #[test]
    fn group_f_snapshot_bill_requires_exact_overflow_collapse_accounting() {
        let tracker = ChargebackTracker::with_limits(4, 1, 1);
        for (workspace, team, timestamp, tokens, cost) in [
            ("workspace-a", "team-a", "2026-08-10T00:00:00Z", 10, 1.0),
            ("workspace-b", "team-b", "2026-08-20T00:00:00Z", 20, 2.0),
        ] {
            let mut row = entry("openai", "gpt-4o", tokens, cost);
            row.team = team.to_string();
            row.timestamp = timestamp.to_string();
            assert_eq!(tracker.try_record(Some(workspace), row), Ok(()));
        }

        let base = tracker.snapshot();
        assert_eq!(base.collapsed_workspace_events, 2);
        assert_eq!(base.collapsed_team_events, 2);
        assert_eq!(base.workspace_rollups.len(), 1);
        assert_eq!(base.team_rollups.len(), 1);
        assert_eq!(base.workspace_rollups[0].dimension, DimensionKey::Overflow);
        assert_eq!(base.team_rollups[0].dimension, DimensionKey::Overflow);
        assert_eq!(base.workspace_rollups[0].totals.request_count, 2);
        assert_eq!(base.team_rollups[0].totals.request_count, 2);
        generate_bill_from_snapshot(&base, "2026-08-01", "2026-09-01")
            .expect("the unmodified overflow snapshot is the positive control");

        let mut workspace_understates_collapse = base.clone();
        workspace_understates_collapse.collapsed_workspace_events = 1;
        let mut team_understates_collapse = base;
        team_understates_collapse.collapsed_team_events = 1;

        for (label, snapshot) in [
            (
                "workspace overflow requests exceed the collapse counter",
                workspace_understates_collapse,
            ),
            (
                "team overflow requests exceed the collapse counter",
                team_understates_collapse,
            ),
        ] {
            assert_eq!(
                generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::IncompleteSnapshot,
                }),
                "{label} must never yield a complete bill"
            );
        }
    }

    #[test]
    fn group_f_snapshot_bill_requires_cross_dimension_token_parity() {
        let base = complete_snapshot_with_two_rows();
        let expected_tokens = base.entries.iter().map(|entry| entry.tokens).sum::<u64>();
        assert_eq!(
            base.workspace_rollups
                .iter()
                .map(|rollup| rollup.totals.tokens)
                .sum::<u64>(),
            expected_tokens
        );
        assert_eq!(
            base.team_rollups
                .iter()
                .map(|rollup| rollup.totals.tokens)
                .sum::<u64>(),
            expected_tokens
        );

        let mut workspace_token_mismatch = base.clone();
        workspace_token_mismatch.workspace_rollups[0].totals.tokens += 1;
        let mut team_token_mismatch = base;
        team_token_mismatch.team_rollups[0].totals.tokens += 1;

        for (label, snapshot) in [
            ("workspace token total", workspace_token_mismatch),
            ("team token total", team_token_mismatch),
        ] {
            assert_eq!(
                generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::IncompleteSnapshot,
                }),
                "a mismatched {label} must never yield a complete bill"
            );
        }
    }

    #[test]
    fn group_f_snapshot_bill_rejects_retained_timestamp_extrema_contradictions() {
        let base = complete_snapshot_with_two_rows();
        assert_eq!(
            base.earliest_retained_timestamp.as_deref(),
            Some("2026-08-10T00:00:00Z")
        );
        assert_eq!(
            base.latest_retained_timestamp.as_deref(),
            Some("2026-08-20T00:00:00Z")
        );

        let offset_tracker = ChargebackTracker::with_limits(4, 4, 4);
        assert_eq!(
            record_at(
                &offset_tracker,
                "2026-08-10T00:00:00+14:00",
                "openai",
                "gpt-4o",
                10,
                1.0,
            ),
            Ok(())
        );
        assert_eq!(
            record_at(
                &offset_tracker,
                "2026-08-09T23:00:00-12:00",
                "anthropic",
                "claude-3-5-sonnet",
                20,
                2.0,
            ),
            Ok(())
        );
        let offset_base = offset_tracker.snapshot();
        assert_eq!(
            offset_base.earliest_retained_timestamp.as_deref(),
            Some("2026-08-10T00:00:00+14:00"),
            "chronological minimum is lexically later"
        );
        assert_eq!(
            offset_base.latest_retained_timestamp.as_deref(),
            Some("2026-08-09T23:00:00-12:00"),
            "chronological maximum is lexically earlier"
        );
        let offset_control = generate_bill_from_snapshot(&offset_base, "2026-08-01", "2026-09-01")
            .expect("offset extrema from a real tracker remain complete");
        assert_eq!(offset_control.total, 3.0);

        let mut missing_earliest = base.clone();
        missing_earliest.earliest_retained_timestamp = None;

        let mut missing_latest = base.clone();
        missing_latest.latest_retained_timestamp = None;

        let mut inverted = base.clone();
        inverted.earliest_retained_timestamp = Some("2026-08-21T00:00:00Z".to_string());
        inverted.latest_retained_timestamp = Some("2026-08-09T00:00:00Z".to_string());

        let mut inexact_earliest = base.clone();
        inexact_earliest.earliest_retained_timestamp = Some("2026-08-11T00:00:00Z".to_string());

        let mut inexact_latest = base.clone();
        inexact_latest.latest_retained_timestamp = Some("2026-08-19T00:00:00Z".to_string());

        let mut lexical_instead_of_chronological = offset_base;
        lexical_instead_of_chronological.earliest_retained_timestamp =
            Some("2026-08-09T23:00:00-12:00".to_string());
        lexical_instead_of_chronological.latest_retained_timestamp =
            Some("2026-08-10T00:00:00+14:00".to_string());

        let mut malformed_earliest = base.clone();
        malformed_earliest.earliest_retained_timestamp = Some("not-a-timestamp".to_string());

        assert!(matches!(
            generate_bill_from_snapshot(&malformed_earliest, "not-a-period-start", "2026-09-01"),
            Err(BillError::InvalidPeriodStart { .. })
        ));
        let mut poisoned_precedes_retained_extrema = malformed_earliest.clone();
        poisoned_precedes_retained_extrema
            .eviction_watermark
            .poisoned = true;
        assert_eq!(
            generate_bill_from_snapshot(
                &poisoned_precedes_retained_extrema,
                "2026-08-01",
                "2026-09-01"
            ),
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::PoisonedEvictionWatermark,
            }),
            "period admission and explicit eviction poison keep their established precedence"
        );

        let mut extrema_without_rows = ChargebackTracker::with_limits(4, 4, 4).snapshot();
        extrema_without_rows.earliest_retained_timestamp = Some("2026-08-10T00:00:00Z".to_string());
        extrema_without_rows.latest_retained_timestamp = Some("2026-08-20T00:00:00Z".to_string());

        for (label, snapshot) in [
            ("missing retained minimum", missing_earliest),
            ("missing retained maximum", missing_latest),
            ("inverted retained extrema", inverted),
            ("inexact retained minimum", inexact_earliest),
            ("inexact retained maximum", inexact_latest),
            (
                "lexical extrema disagree with chronological offset order",
                lexical_instead_of_chronological,
            ),
            ("malformed retained minimum", malformed_earliest),
            ("retained extrema without rows", extrema_without_rows),
        ] {
            assert_eq!(
                generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01"),
                Err(BillError::PartialPeriod {
                    reason: PartialPeriodReason::IncompleteSnapshot,
                }),
                "{label} must never yield a complete bill"
            );
        }
    }

    #[test]
    fn group_f_invalid_snapshot_is_refused_before_billing_rows_are_touched_or_cloned() {
        let allocator_control = allocation_counter::measure(|| {
            let allocated = std::hint::black_box("allocator-positive-control".repeat(2));
            let _ = std::hint::black_box(&allocated);
        });
        assert!(
            allocator_control.count_total > 0 && allocator_control.bytes_total > 0,
            "the thread-local allocator observer must detect a real heap allocation"
        );

        let mut snapshot = complete_snapshot_with_two_rows();
        snapshot.recorded_entries = 3;
        let probe = SnapshotBillingCallsiteProbe::install_for_current_thread();
        let mut result = None;
        let validation_allocations = allocation_counter::measure(|| {
            result = Some(generate_bill_from_snapshot(
                &snapshot,
                "2026-08-01",
                "2026-09-01",
            ));
        });
        let counters = probe.counters();
        drop(probe);
        let result = result.expect("the measured validation call stores its result");

        assert_eq!(validation_allocations.count_total, 0);
        assert_eq!(validation_allocations.bytes_total, 0);
        assert_eq!(validation_allocations.count_max, 0);
        assert_eq!(validation_allocations.bytes_max, 0);
        assert_eq!(counters.borrowed_entries_aggregated, 0);
        assert_eq!(counters.legacy_entries_materialized, 0);
        assert_eq!(counters.snapshot_entry_clones, 0);
        assert_eq!(
            result,
            Err(BillError::PartialPeriod {
                reason: PartialPeriodReason::IncompleteSnapshot,
            })
        );
        assert_eq!(
            snapshot.entries.len(),
            2,
            "the caller-owned graph remains intact"
        );
    }

    #[test]
    fn group_f_primary_guide_and_example_use_snapshot_aware_billing() {
        const GUIDE: &str = include_str!("../../../../docs/ai-chargeback.md");
        const EXAMPLE: &str = include_str!("../../examples/ai_chargeback_billing.rs");

        const PRIMARY_HEADING: &str = "## Unified billing statements";
        const SECONDARY_HEADING: &str = "### Caller-asserted-complete retained slices";
        let primary_heading = GUIDE
            .find(PRIMARY_HEADING)
            .expect("the guide has one named unified-billing section");
        let after_primary_heading = &GUIDE[primary_heading + PRIMARY_HEADING.len()..];
        let primary_end = after_primary_heading
            .find("\n## ")
            .expect("a following level-two heading bounds the billing section");
        let billing_section = &after_primary_heading[..primary_end];
        let secondary_heading = billing_section
            .find(SECONDARY_HEADING)
            .expect("the lower-level API has one explicit secondary section");
        let safe_primary = &billing_section[..secondary_heading];
        let after_secondary_heading =
            &billing_section[secondary_heading + SECONDARY_HEADING.len()..];
        let secondary_end = after_secondary_heading
            .find("\n### ")
            .unwrap_or(after_secondary_heading.len());
        let asserted_complete_secondary = &after_secondary_heading[..secondary_end];
        let after_secondary = &after_secondary_heading[secondary_end..];

        let safe_snapshot = safe_primary
            .find("let snapshot = tracker.snapshot();")
            .expect("the primary guide snippet acquires one atomic snapshot");
        let safe_bill = safe_primary
            .find("generate_bill_from_snapshot(&snapshot")
            .expect("the primary guide snippet uses snapshot-aware billing");
        assert!(
            safe_snapshot < safe_bill,
            "the primary guide must acquire the snapshot before billing it"
        );
        assert!(!safe_primary.contains("entries_snapshot()"));
        assert!(!safe_primary.contains("generate_bill("));

        let lower_entries = asserted_complete_secondary
            .find("let entries = tracker.entries_snapshot();")
            .expect("the secondary section demonstrates the retained-slice API");
        let lower_bill = asserted_complete_secondary
            .find("generate_bill(&entries")
            .expect("the secondary section demonstrates caller-asserted billing");
        assert!(
            lower_entries < lower_bill,
            "the explicit lower-level example acquires its slice before billing"
        );
        assert!(!after_secondary.contains("entries_snapshot()"));
        assert!(!after_secondary.contains("generate_bill("));
        assert!(!GUIDE[..primary_heading].contains("entries_snapshot()"));
        assert!(!GUIDE[..primary_heading].contains("generate_bill("));
        let after_billing_section = &after_primary_heading[primary_end..];
        assert!(!after_billing_section.contains("entries_snapshot()"));
        assert!(!after_billing_section.contains("generate_bill("));

        const EXAMPLE_PRIMARY_START: &str = "    println!(\"\\nUnified bill for the period:\");";
        const EXAMPLE_PRIMARY_END: &str = "    // Project the next 30 days";
        let example_start = EXAMPLE
            .find(EXAMPLE_PRIMARY_START)
            .expect("the runnable example has one primary billing block");
        let after_example_start = &EXAMPLE[example_start + EXAMPLE_PRIMARY_START.len()..];
        let example_end = after_example_start
            .find(EXAMPLE_PRIMARY_END)
            .expect("the forecasting block bounds primary billing");
        let example_primary = &after_example_start[..example_end];
        let example_snapshot = example_primary
            .find("let snapshot = tracker.snapshot();")
            .expect("the runnable primary block acquires one atomic snapshot");
        let example_bill = example_primary
            .find("generate_bill_from_snapshot(&snapshot")
            .expect("the runnable primary block uses snapshot-aware billing");
        assert!(
            example_snapshot < example_bill,
            "the runnable example must acquire the snapshot before billing it"
        );
        assert!(!example_primary.contains("entries_snapshot()"));
        assert!(!example_primary.contains("generate_bill("));
        assert!(!EXAMPLE.contains("entries_snapshot()"));
        assert!(!EXAMPLE.contains("generate_bill("));
    }

    #[test]
    fn group_f_snapshot_billing_borrows_v2_rows_without_materializing_legacy_entries(
    ) -> Result<(), BillError> {
        let tracker = ChargebackTracker::with_limits(4, 4, 4);
        for (timestamp, provider, model, tokens, cost) in [
            ("2026-08-10T00:00:00Z", "openai", "gpt-4o", 10, 1.0),
            ("2026-08-11T00:00:00Z", "openai", "gpt-4o", 20, 2.0),
            (
                "2026-08-12T00:00:00Z",
                "anthropic",
                "claude-3-5-sonnet",
                30,
                3.0,
            ),
        ] {
            assert_eq!(
                record_at(&tracker, timestamp, provider, model, tokens, cost),
                Ok(())
            );
        }
        let snapshot = tracker.snapshot();
        let probe = SnapshotBillingCallsiteProbe::install_for_current_thread();

        let bill = generate_bill_from_snapshot(&snapshot, "2026-08-01", "2026-09-01")?;
        let counters = probe.counters();
        assert_eq!(counters.borrowed_entries_aggregated, 3);
        assert_eq!(counters.legacy_entries_materialized, 0);
        assert_eq!(counters.snapshot_entry_clones, 0);
        drop(probe);

        assert_eq!(
            snapshot.entries.len(),
            3,
            "the borrowed source remains usable"
        );
        assert_eq!(bill.line_items.len(), 2);
        assert_eq!(
            bill.line_items
                .iter()
                .map(|item| item.requests)
                .sum::<u64>(),
            3
        );
        assert_eq!(bill.total, 6.0);
        Ok(())
    }
}
