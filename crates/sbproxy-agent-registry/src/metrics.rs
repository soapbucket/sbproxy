//! The two families the agent registry emits.
//!
//! # Cardinality
//!
//! `op` and `outcome` are both closed sets fixed at compile time. `op` is
//! the handful of things an operator or a submitter can ask for; `outcome`
//! comes from [`crate::error::RegistryError::outcome`] plus `applied`, so a
//! new refusal cannot reach a label without going through the error enum.
//!
//! Nothing here is labeled by agent id, vendor, or slug. Those are
//! submitter-controlled and unbounded, which is the rule
//! `docs/observability.md` states and the one a registration endpoint is
//! most tempting to break.
//!
//! # Why a gauge for the catalog
//!
//! A catalog that silently emptied is indistinguishable from one that was
//! never configured, from the counter alone: both show no refresh traffic.
//! The gauge separates them, because a configured registry publishes it at
//! zero the moment it boots.

use std::sync::LazyLock;

use prometheus::{
    register_int_counter_vec, register_int_gauge_vec, IntCounterVec, IntGaugeVec, Opts,
};

/// Agent registry operations, by operation and outcome.
static AGENT_REGISTRY_OPERATIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_agent_registry_operations_total",
            "Agent registry and registration-queue operations by operation and outcome"
        ),
        &["op", "outcome"]
    )
    .expect("register sbproxy_agent_registry_operations_total")
});

/// Size of the live catalog and of each registration-queue state.
static AGENT_REGISTRY_ENTRIES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        Opts::new(
            "sbproxy_agent_registry_entries",
            "Agents the registry currently knows about, by collection (the verified catalog, or a registration-queue state)"
        ),
        &["collection"]
    )
    .expect("register sbproxy_agent_registry_entries")
});

/// Count one operation.
pub(crate) fn record_registry_op(op: &'static str, outcome: &'static str) {
    AGENT_REGISTRY_OPERATIONS
        .with_label_values(&[op, outcome])
        .inc();
}

/// Publish the size of one collection.
pub(crate) fn set_registry_entries(collection: &'static str, count: i64) {
    AGENT_REGISTRY_ENTRIES
        .with_label_values(&[collection])
        .set(count);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prometheus panics at runtime on a label-arity mismatch, in whichever
    /// request first reaches the new path. Driving both recorders here makes
    /// that a test failure instead.
    #[test]
    fn every_recorder_matches_the_declared_label_arity() {
        record_registry_op("register", "applied");
        set_registry_entries("catalog", 7);
        assert_eq!(
            AGENT_REGISTRY_ENTRIES.with_label_values(&["catalog"]).get(),
            7
        );
    }
}
