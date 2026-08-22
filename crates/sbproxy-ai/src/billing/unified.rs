//! Unified billing report generation (WOR-2672 port of
//! `sbproxy-enterprise-ai::billing::unified`).
//!
//! Aggregates chargeback entries into a single bill covering a billing period.
//! Line items are grouped by (provider, model) pair so the output matches the
//! format expected by external finance systems.

use super::chargeback::ChargebackEntry;

/// A single line in a unified bill, grouped by provider and model.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct UnifiedBill {
    /// ISO 8601 start of the billing period (inclusive).
    pub period_start: String,
    /// ISO 8601 end of the billing period (inclusive).
    pub period_end: String,
    /// Itemised charges grouped by provider and model.
    pub line_items: Vec<BillLineItem>,
    /// Sum of all `line_items[i].cost`.
    pub total: f64,
}

/// Build a `UnifiedBill` from a slice of raw chargeback entries.
///
/// Entries outside `[period_start, period_end]` are included regardless
/// of timestamp – filtering by date is the responsibility of the caller
/// when extracting entries from the `ChargebackTracker`.
pub fn generate_bill(
    entries: &[ChargebackEntry],
    period_start: &str,
    period_end: &str,
) -> UnifiedBill {
    use std::collections::HashMap;

    // Aggregate by (provider, model).
    let mut map: HashMap<(String, String), BillLineItem> = HashMap::new();

    for entry in entries {
        let key = (entry.provider.clone(), entry.model.clone());
        let item = map.entry(key).or_insert_with(|| BillLineItem {
            provider: entry.provider.clone(),
            model: entry.model.clone(),
            requests: 0,
            tokens: 0,
            cost: 0.0,
        });
        item.requests += 1;
        item.tokens += entry.tokens;
        item.cost += entry.cost;
    }

    let mut line_items: Vec<BillLineItem> = map.into_values().collect();
    // Sort for deterministic output.
    line_items.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.model.cmp(&b.model)));

    let total = line_items.iter().map(|li| li.cost).sum();

    UnifiedBill {
        period_start: period_start.to_string(),
        period_end: period_end.to_string(),
        line_items,
        total,
    }
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
        let bill = generate_bill(&[], "2026-04-01", "2026-04-30");
        assert!(bill.line_items.is_empty());
        assert_eq!(bill.total, 0.0);
        assert_eq!(bill.period_start, "2026-04-01");
        assert_eq!(bill.period_end, "2026-04-30");
    }

    #[test]
    fn single_entry_becomes_single_line_item() {
        let entries = vec![entry("openai", "gpt-4o", 1000, 2.5)];
        let bill = generate_bill(&entries, "2026-04-01", "2026-04-30");
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
        let bill = generate_bill(&entries, "2026-04-01", "2026-04-30");
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
        let bill = generate_bill(&entries, "2026-04-01", "2026-04-30");
        assert_eq!(bill.line_items.len(), 2);
    }

    #[test]
    fn total_is_sum_of_line_items() {
        let entries = vec![
            entry("openai", "gpt-4o", 100, 1.0),
            entry("anthropic", "claude-3-haiku", 200, 0.5),
            entry("openai", "gpt-3.5-turbo", 300, 0.2),
        ];
        let bill = generate_bill(&entries, "2026-04-01", "2026-04-30");
        assert!(
            (bill.total - 1.7).abs() < 0.001,
            "expected 1.7, got {}",
            bill.total
        );
    }

    #[test]
    fn period_fields_are_preserved() {
        let bill = generate_bill(&[], "2026-03-01", "2026-03-31");
        assert_eq!(bill.period_start, "2026-03-01");
        assert_eq!(bill.period_end, "2026-03-31");
    }
}
