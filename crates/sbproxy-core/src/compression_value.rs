//! Success-path bridge for prompt-free AI compression value.

/// Record a prompt-free pending compression value into the process-wide admin
/// ledger and bounded value metrics.
///
/// The request path must call this exactly once, after the terminal provider
/// response is known to be successful and billable. Pricing is intentionally
/// deferred until this point so failed upstream attempts do not claim value.
pub fn record_pending_compression_value(
    tenant_id: &str,
    origin: &str,
    pending: &sbproxy_ai::PendingCompressionValue,
) {
    let ledger = sbproxy_ai::value_ledger::value_ledger_or_init_memory();
    record_pending_compression_value_to(&ledger, tenant_id, origin, pending);
}

fn record_pending_compression_value_to(
    ledger: &sbproxy_ai::ValueLedger,
    tenant_id: &str,
    origin: &str,
    pending: &sbproxy_ai::PendingCompressionValue,
) {
    for record in pending.priced_records() {
        ledger.record_compression(
            pending.target_model(),
            record.lever(),
            record.tokens_saved(),
            record.gross_cost_saved_micros(),
        );
        sbproxy_observe::metrics::record_compression_value(
            tenant_id,
            origin,
            pending.target_model(),
            record.lever().as_str(),
            record.tokens_saved(),
            record.gross_cost_saved_micros(),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sbproxy_ai::compression::{CompressionRun, LeverKind, LeverOutcome, LeverResult};

    use super::*;

    #[test]
    fn records_every_pending_lever_without_counting_a_completion() {
        let ledger = sbproxy_ai::ValueLedger::open("").expect("memory ledger");
        let run = CompressionRun {
            messages: Vec::new(),
            initial_tokens: 1_500_000,
            final_tokens: 0,
            tokens_saved: 1_500_000,
            lever_results: vec![
                LeverResult {
                    lever: LeverKind::SummaryBuffer,
                    backend: None,
                    outcome: LeverOutcome::Applied,
                    before_tokens: 1_500_000,
                    after_tokens: 1_000_000,
                    tokens_saved: 500_000,
                    duration: Duration::from_millis(1),
                },
                LeverResult {
                    lever: LeverKind::WindowFit,
                    backend: None,
                    outcome: LeverOutcome::Applied,
                    before_tokens: 1_000_000,
                    after_tokens: 0,
                    tokens_saved: 1_000_000,
                    duration: Duration::from_millis(1),
                },
            ],
        };
        let pending =
            sbproxy_ai::PendingCompressionValue::from_run("wor-1921-unpriced-core-test", &run)
                .expect("pending value");

        record_pending_compression_value_to(&ledger, "tenant", "origin", &pending);

        let report = ledger.report();
        assert_eq!(report.total_local_completions, 0);
        assert_eq!(report.total_cloud_completions, 0);
        assert_eq!(report.total_compression_tokens_saved, 1_500_000);
        assert_eq!(
            report.compression_totals["summary_buffer"].gross_cost_saved_micros,
            2_500_000
        );
        assert_eq!(
            report.compression_totals["window_fit"].gross_cost_saved_micros,
            5_000_000
        );
    }
}
