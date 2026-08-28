//! The one Prometheus family the embedded stores emit.
//!
//! `sbproxy_embedded_store_operations_total{store,op,outcome}` is deliberately
//! a single family across every subsystem that opens an embedded store, not
//! one family per subsystem. An operator asking "is the agent registry's
//! store healthy" and an operator asking "is the notifier's deadletter store
//! healthy" are asking the same question of the same code, and a family per
//! caller would need a panel per caller to answer it.
//!
//! # Cardinality
//!
//! All three labels are closed sets fixed at compile time.
//!
//! * `store` is the `&'static str` the subsystem passes when it opens the
//!   store. It is never a path, never a tenant, and never derived from a
//!   request; the type demands a `'static` string precisely so a caller
//!   cannot hand it a `format!`.
//! * `op` is `get`, `list`, `put`, `insert`, `cas`, `delete`, or `evict`.
//! * `outcome` is `ok`, `error`, or `rejected`.
//!
//! # What `rejected` means, and why it is not `error`
//!
//! A bounded ephemeral store at its entry cap refuses a write. That is the
//! cap working, not a fault, so it is counted separately from `error` and
//! separately from `ok`. Folding it into either is the failure rubric section
//! 4 names: a refusal that reads as a success is invisible, and a refusal
//! that reads as a fault trains operators to ignore the channel.

use std::sync::LazyLock;

use prometheus::{register_int_counter_vec, IntCounterVec, Opts};

/// Operations against an embedded store, by store, operation, and outcome.
static EMBEDDED_STORE_OPERATIONS: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_embedded_store_operations_total",
            "Embedded key-value store operations by store, operation, and outcome"
        ),
        &["store", "op", "outcome"]
    )
    .map_err(|error| {
        // Only a duplicate or malformed name reaches here, and both are
        // bugs in this file. An `expect` would turn one into a panic
        // inside whichever request first touched the new code path,
        // which is a larger failure than a family that does not record.
        tracing::error!(family = "sbproxy_embedded_store_operations_total", error = %error, "metric family would not register");
    })
    .ok()
});

/// Count one operation.
pub(crate) fn record_kv_op(store: &'static str, op: &'static str, outcome: &'static str) {
    if let Some(family) = EMBEDDED_STORE_OPERATIONS.as_ref() {
        family.with_label_values(&[store, op, outcome]).inc();
    }
}

/// Count `count` operations at once. Used by the ephemeral sweep, which
/// reclaims many entries in one pass and would otherwise report one eviction
/// where many happened.
pub(crate) fn record_kv_op_count(
    store: &'static str,
    op: &'static str,
    outcome: &'static str,
    count: u64,
) {
    if let Some(family) = EMBEDDED_STORE_OPERATIONS.as_ref() {
        family
            .with_label_values(&[store, op, outcome])
            .inc_by(count);
    }
}

/// Map a fallible outcome onto the `outcome` label.
pub(crate) fn outcome_label<T, E>(result: &Result<T, E>) -> &'static str {
    if result.is_ok() {
        "ok"
    } else {
        "error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The label arity is what Prometheus panics on at runtime when it is
    /// wrong, and the panic lands in whichever request first reaches the new
    /// path. Exercising every helper here means a mismatch is a test failure
    /// rather than a production one.
    #[test]
    fn every_recorder_matches_the_declared_label_arity() {
        record_kv_op("test_metrics", "get", "ok");
        record_kv_op("test_metrics", "put", "rejected");
        record_kv_op_count("test_metrics", "evict", "ok", 3);
        assert_eq!(
            EMBEDDED_STORE_OPERATIONS
                .as_ref()
                .expect("the family registers in a fresh process")
                .with_label_values(&["test_metrics", "evict", "ok"])
                .get(),
            3
        );
    }

    #[test]
    fn outcome_label_separates_ok_from_error() {
        assert_eq!(outcome_label::<(), ()>(&Ok(())), "ok");
        assert_eq!(outcome_label::<(), ()>(&Err(())), "error");
    }
}
