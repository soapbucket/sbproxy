// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cluster-shared AI budget counters (WOR-1722).
//!
//! AI budgets are enforced per-instance by default: the tracker in
//! `sbproxy-ai` is an in-process `DashMap`, so a "global $X" budget is
//! really N times X across N replicas. When a shared store (Redis) is
//! installed here, spend is also accumulated into shared per-scope
//! counters, and the enforcement path reads the shared total so the
//! fleet enforces one budget.
//!
//! The store is optional. Without it, `record_shared_spend` is a no-op
//! and `read_shared_spend` returns `None`, so callers fall back to the
//! per-instance tracker unchanged. Every store call fails open (logs and
//! continues) so a Redis blip never blocks or wrongly blocks a request;
//! the local tracker remains the floor.
//!
//! Counters are keyed `sbproxy:budget:{scope_key}:tok` (tokens) and
//! `:usdm` (micro-USD), where `scope_key` is the already-windowed key
//! from the budget tracker, so each budget period gets its own counters
//! and the store's TTL expires them with the window.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use sbproxy_ai::UsageRecord;
use sbproxy_platform::storage::AsyncKVStore;

/// Process-global shared budget store, installed at startup when the
/// operator runs clustered (see `key_plane`). Absent means per-instance
/// budgets only.
static SHARED_BUDGET: OnceLock<Arc<dyn AsyncKVStore>> = OnceLock::new();

/// Install the shared budget counter store. First install wins; a second
/// call is ignored (the store is process-global and set once at boot).
pub(crate) fn install_shared_budget(store: Arc<dyn AsyncKVStore>) {
    if SHARED_BUDGET.set(store).is_err() {
        tracing::warn!("shared budget store already installed; keeping the first");
    }
}

/// The installed shared budget store, if cluster-shared budgets are on.
pub(crate) fn shared_budget() -> Option<&'static Arc<dyn AsyncKVStore>> {
    SHARED_BUDGET.get()
}

/// Set once a shared-store read or write fails, cleared once one
/// succeeds. Gates the WARN/INFO transition logs below so a flapping
/// Redis link logs one degrade line and one recovery line, not one per
/// request (WOR-2474).
static DEGRADED: AtomicBool = AtomicBool::new(false);

fn tokens_key(scope_key: &str) -> Vec<u8> {
    format!("sbproxy:budget:{scope_key}:tok").into_bytes()
}

fn micros_key(scope_key: &str) -> Vec<u8> {
    format!("sbproxy:budget:{scope_key}:usdm").into_bytes()
}

/// Accumulate spend into the shared counters for `scope_key`, if a shared
/// store is installed. No-op otherwise. Fails open.
pub(crate) async fn record_shared_spend(
    scope_key: &str,
    tokens: u64,
    cost_usd: f64,
    ttl_secs: u64,
) {
    if let Some(store) = shared_budget() {
        record_shared_spend_to(store, scope_key, tokens, cost_usd, ttl_secs).await;
    }
}

/// The cluster-wide spend total for `scope_key`, if a shared store is
/// installed and readable. `None` means "no shared view available" so
/// the caller enforces against the local tracker instead.
pub(crate) async fn read_shared_spend(scope_key: &str) -> Option<UsageRecord> {
    read_shared_spend_from(shared_budget()?, scope_key).await
}

/// Store-parameterized accumulate (testable without the global).
async fn record_shared_spend_to(
    store: &Arc<dyn AsyncKVStore>,
    scope_key: &str,
    tokens: u64,
    cost_usd: f64,
    ttl_secs: u64,
) {
    if tokens > 0 {
        match store
            .incr_by_with_ttl(&tokens_key(scope_key), tokens as i64, ttl_secs)
            .await
        {
            Ok(_) => {
                sbproxy_observe::metrics::set_budget_share_unavailable(0);
                if DEGRADED.swap(false, Ordering::Relaxed) {
                    tracing::info!(
                        target: "sbproxy::budget",
                        "shared budget store recovered; cluster-wide enforcement resumed"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, scope = scope_key, "shared budget: token incr failed (fail-open)");
                sbproxy_observe::metrics::record_budget_share_fail_open("write");
                if !DEGRADED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        target: "sbproxy::budget",
                        error = %e,
                        "shared budget store unreachable; enforcement degraded to per-instance tracking (fail-open)"
                    );
                }
            }
        }
    }
    // Cost is stored as micro-USD to keep the shared counter integral.
    let micros = (cost_usd * 1_000_000.0).round() as i64;
    if micros > 0 {
        match store
            .incr_by_with_ttl(&micros_key(scope_key), micros, ttl_secs)
            .await
        {
            Ok(_) => {
                sbproxy_observe::metrics::set_budget_share_unavailable(0);
                if DEGRADED.swap(false, Ordering::Relaxed) {
                    tracing::info!(
                        target: "sbproxy::budget",
                        "shared budget store recovered; cluster-wide enforcement resumed"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, scope = scope_key, "shared budget: cost incr failed (fail-open)");
                sbproxy_observe::metrics::record_budget_share_fail_open("write");
                if !DEGRADED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        target: "sbproxy::budget",
                        error = %e,
                        "shared budget store unreachable; enforcement degraded to per-instance tracking (fail-open)"
                    );
                }
            }
        }
    }
}

/// Store-parameterized read (testable without the global). Returns `None`
/// on a store error so the caller falls back to local enforcement.
async fn read_shared_spend_from(
    store: &Arc<dyn AsyncKVStore>,
    scope_key: &str,
) -> Option<UsageRecord> {
    let tokens = read_counter(store, &tokens_key(scope_key)).await?;
    let micros = read_counter(store, &micros_key(scope_key))
        .await
        .unwrap_or(0);
    Some(UsageRecord {
        tokens,
        cost_usd: micros as f64 / 1_000_000.0,
        request_count: 0,
    })
}

/// Pre-fetch the cluster-shared spend for each budget key so
/// `budget_preflight` enforces against the fleet total. Empty map when no
/// shared store is installed or nothing reads back, in which case
/// enforcement falls back to the local tracker per key.
pub(crate) async fn read_shared_for_keys(keys: &[(usize, String)]) -> HashMap<String, UsageRecord> {
    let mut map = HashMap::new();
    if shared_budget().is_none() {
        return map;
    }
    for (_idx, key) in keys {
        if let Some(usage) = read_shared_spend(key).await {
            map.insert(key.clone(), usage);
        }
    }
    map
}

/// Accumulate a completed request's spend into the shared counters for
/// each budget key, TTL set to each limit's window so the counter expires
/// with the budget period. No-op without a shared store or on zero spend.
pub(crate) async fn record_shared_budget_usage(
    cfg: &sbproxy_ai::BudgetConfig,
    keys: &[(usize, String)],
    model: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
) {
    if shared_budget().is_none() || (prompt_tokens == 0 && completion_tokens == 0) {
        return;
    }
    let total = prompt_tokens + completion_tokens;
    let cost = sbproxy_ai::estimate_cost(model, prompt_tokens, completion_tokens);
    for (limit_idx, key) in keys {
        // TTL = the limit's window in seconds; "total" (no window) uses 0
        // (no expiry). The key is already period-bucketed, so the TTL only
        // governs cleanup of stale buckets, not correctness.
        let ttl = cfg
            .limits
            .get(*limit_idx)
            .and_then(|l| l.window())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        record_shared_spend(key, total, cost, ttl).await;
    }
}

/// Read an integer counter. `Some(0)` on a miss, `None` on a store or
/// parse error (so the caller fails open to the local tracker).
async fn read_counter(store: &Arc<dyn AsyncKVStore>, key: &[u8]) -> Option<u64> {
    match store.get(key).await {
        Ok(value) => {
            sbproxy_observe::metrics::set_budget_share_unavailable(0);
            if DEGRADED.swap(false, Ordering::Relaxed) {
                tracing::info!(
                    target: "sbproxy::budget",
                    "shared budget store recovered; cluster-wide enforcement resumed"
                );
            }
            match value {
                Some(bytes) => std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok()),
                None => Some(0),
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "shared budget: read failed (fail-open)");
            sbproxy_observe::metrics::record_budget_share_fail_open("read");
            if !DEGRADED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    target: "sbproxy::budget",
                    error = %e,
                    "shared budget store unreachable; enforcement degraded to per-instance tracking (fail-open)"
                );
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory `AsyncKVStore` mock: stores integer counters as their
    /// decimal-string bytes, exactly as Redis `INCRBY` would leave them.
    #[derive(Default)]
    struct MockKv {
        map: Mutex<HashMap<Vec<u8>, i64>>,
    }

    #[async_trait]
    impl AsyncKVStore for MockKv {
        async fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .get(key)
                .map(|n| Bytes::from(n.to_string())))
        }
        async fn put(&self, _key: &[u8], _value: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn put_with_ttl(&self, _key: &[u8], _value: &[u8], _ttl: u64) -> Result<()> {
            Ok(())
        }
        async fn incr_with_ttl(&self, key: &[u8], _ttl: u64) -> Result<i64> {
            self.incr_by_with_ttl(key, 1, _ttl).await
        }
        async fn incr_by_with_ttl(&self, key: &[u8], amount: i64, _ttl: u64) -> Result<i64> {
            let mut m = self.map.lock().unwrap();
            let e = m.entry(key.to_vec()).or_insert(0);
            *e += amount;
            Ok(*e)
        }
        async fn delete(&self, _key: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    /// An `AsyncKVStore` whose every operation fails, for exercising the
    /// fail-open counters at the store seam (WOR-2474).
    struct FailingStore;

    #[async_trait]
    impl AsyncKVStore for FailingStore {
        async fn get(&self, _key: &[u8]) -> Result<Option<Bytes>> {
            Err(anyhow::anyhow!("simulated shared budget store outage"))
        }
        async fn put(&self, _key: &[u8], _value: &[u8]) -> Result<()> {
            Err(anyhow::anyhow!("simulated shared budget store outage"))
        }
        async fn put_with_ttl(&self, _key: &[u8], _value: &[u8], _ttl: u64) -> Result<()> {
            Err(anyhow::anyhow!("simulated shared budget store outage"))
        }
        async fn incr_with_ttl(&self, _key: &[u8], _ttl: u64) -> Result<i64> {
            Err(anyhow::anyhow!("simulated shared budget store outage"))
        }
        async fn incr_by_with_ttl(&self, _key: &[u8], _amount: i64, _ttl: u64) -> Result<i64> {
            Err(anyhow::anyhow!("simulated shared budget store outage"))
        }
        async fn delete(&self, _key: &[u8]) -> Result<()> {
            Err(anyhow::anyhow!("simulated shared budget store outage"))
        }
    }

    /// Every label of a gathered family, as `name=value` pairs joined by
    /// commas, one entry per series, with the series value appended.
    /// Copied from the identical helper in `key_plane.rs`.
    fn gathered_series(family_name: &str) -> Vec<(String, f64)> {
        let mut out = Vec::new();
        for family in prometheus::gather() {
            if family.name() != family_name {
                continue;
            }
            for metric in family.get_metric() {
                let labels: Vec<String> = metric
                    .get_label()
                    .iter()
                    .map(|pair| format!("{}={}", pair.name(), pair.value()))
                    .collect();
                let value = match family.get_field_type() {
                    prometheus::proto::MetricType::COUNTER => metric.get_counter().value(),
                    prometheus::proto::MetricType::GAUGE => metric.get_gauge().value(),
                    // Nothing calls this for a histogram or a summary, and
                    // silently returning 0 for one would make a wrong
                    // assertion pass rather than fail.
                    other => {
                        unreachable!("{family_name} is a {other:?}, not a counter or a gauge")
                    }
                };
                out.push((labels.join(","), value));
            }
        }
        out
    }

    #[tokio::test]
    async fn record_then_read_roundtrips() {
        let store: Arc<dyn AsyncKVStore> = Arc::new(MockKv::default());
        record_shared_spend_to(&store, "tenant:acme", 100, 0.50, 3600).await;
        let usage = read_shared_spend_from(&store, "tenant:acme").await.unwrap();
        assert_eq!(usage.tokens, 100);
        assert!(
            (usage.cost_usd - 0.50).abs() < 1e-9,
            "cost {}",
            usage.cost_usd
        );
    }

    #[tokio::test]
    async fn spend_accumulates_across_calls() {
        let store: Arc<dyn AsyncKVStore> = Arc::new(MockKv::default());
        record_shared_spend_to(&store, "k", 40, 0.10, 60).await;
        record_shared_spend_to(&store, "k", 60, 0.15, 60).await;
        let usage = read_shared_spend_from(&store, "k").await.unwrap();
        assert_eq!(usage.tokens, 100);
        assert!(
            (usage.cost_usd - 0.25).abs() < 1e-9,
            "cost {}",
            usage.cost_usd
        );
    }

    #[tokio::test]
    async fn missing_scope_reads_zero() {
        let store: Arc<dyn AsyncKVStore> = Arc::new(MockKv::default());
        let usage = read_shared_spend_from(&store, "never-seen").await.unwrap();
        assert_eq!(usage.tokens, 0);
        assert_eq!(usage.cost_usd, 0.0);
    }

    #[tokio::test]
    async fn zero_spend_is_not_written() {
        let store: Arc<dyn AsyncKVStore> = Arc::new(MockKv::default());
        // A zero-token, zero-cost record must not create counters.
        record_shared_spend_to(&store, "z", 0, 0.0, 60).await;
        assert!(store.get(&tokens_key("z")).await.unwrap().is_none());
    }

    /// A store that errors on every call must fire the fail-open counter
    /// for both the read and write paths and raise the unavailable gauge;
    /// once a healthy store answers, the gauge must fall back to 0
    /// (WOR-2474).
    #[tokio::test]
    async fn store_errors_fire_fail_open_metrics_and_the_unavailable_gauge() {
        let failing: Arc<dyn AsyncKVStore> = Arc::new(FailingStore);

        // Drive the write path: both the token and cost increments error.
        record_shared_spend_to(&failing, "tenant:broken", 10, 0.01, 60).await;
        let write_count: f64 = gathered_series("sbproxy_budget_share_fail_open_total")
            .into_iter()
            .filter(|(labels, _)| labels.contains("op=write"))
            .map(|(_, value)| value)
            .sum();
        assert!(
            write_count >= 1.0,
            "sbproxy_budget_share_fail_open_total{{op=\"write\"}} did not rise"
        );

        // Drive the read path.
        let usage = read_shared_spend_from(&failing, "tenant:broken").await;
        assert!(
            usage.is_none(),
            "a failing store must fail open to None, not a partial reading"
        );
        let read_count: f64 = gathered_series("sbproxy_budget_share_fail_open_total")
            .into_iter()
            .filter(|(labels, _)| labels.contains("op=read"))
            .map(|(_, value)| value)
            .sum();
        assert!(
            read_count >= 1.0,
            "sbproxy_budget_share_fail_open_total{{op=\"read\"}} did not rise"
        );

        let degraded_gauge = gathered_series("sbproxy_budget_share_unavailable");
        assert_eq!(
            degraded_gauge.first().map(|(_, value)| *value),
            Some(1.0),
            "sbproxy_budget_share_unavailable should read 1 while the store is unreachable: {degraded_gauge:?}"
        );

        // Now drive the good mock store; the gauge must clear.
        let healthy: Arc<dyn AsyncKVStore> = Arc::new(MockKv::default());
        record_shared_spend_to(&healthy, "tenant:ok", 5, 0.01, 60).await;
        let recovered_gauge = gathered_series("sbproxy_budget_share_unavailable");
        assert_eq!(
            recovered_gauge.first().map(|(_, value)| *value),
            Some(0.0),
            "sbproxy_budget_share_unavailable should fall back to 0 once the store answers: {recovered_gauge:?}"
        );
    }
}
