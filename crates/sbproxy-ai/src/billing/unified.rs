//! Unified billing report generation (WOR-2672 port of
//! `sbproxy-enterprise-ai::billing::unified`).
//!
//! Aggregates chargeback entries into a single bill covering a billing period.
//! Line items are grouped by (provider, model) pair so the output matches the
//! format expected by external finance systems.

use super::chargeback::ChargebackEntry;
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
    use std::collections::HashMap;

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

    // Aggregate by (provider, model).
    let mut map: HashMap<(String, String), BillLineItem> = HashMap::new();

    for (index, entry) in entries.iter().enumerate() {
        let timestamp =
            parse_timestamp(&entry.timestamp).ok_or_else(|| BillError::InvalidEntryTimestamp {
                index,
                value: entry.timestamp.clone(),
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
        let key = (entry.provider.clone(), entry.model.clone());
        let item = map.entry(key).or_insert_with(|| BillLineItem {
            provider: entry.provider.clone(),
            model: entry.model.clone(),
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
        let cost = item.cost + entry.cost;
        if !cost.is_finite() {
            return Err(BillError::ArithmeticOverflow { field: "cost" });
        }
        item.cost = cost;
    }

    let mut line_items: Vec<BillLineItem> = map.into_values().collect();
    // Sort for deterministic output.
    line_items.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.model.cmp(&b.model)));

    let mut total = 0.0;
    for item in &line_items {
        total += item.cost;
        if !total.is_finite() {
            return Err(BillError::ArithmeticOverflow {
                field: "total cost",
            });
        }
    }

    Ok(UnifiedBill {
        period_start: period_start.to_string(),
        period_end: period_end.to_string(),
        line_items,
        total,
    })
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
    use crate::billing::chargeback::ChargebackEntry;

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
}
