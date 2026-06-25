// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Prometheus metrics shared by every storage backend.
//!
//! Wave 6A registers the metric scaffolding so 6B / 6C backends only
//! have to wrap their I/O in [`observe_op`]. All metrics use the same
//! `op` / `backend` / `kind` label set so dashboards can slice across
//! backends without rebuilding queries per crate.
//!
//! # Cardinality
//!
//! All three labels draw from small fixed enums:
//!
//! * `op`: `get | put | take | delete | publish | subscribe | list_prefix`
//! * `backend`: `in_memory | redis | mesh | postgres`
//! * `kind`: `ephemeral | persistent | pubsub`
//! * `error_kind` (errors counter only): the variant returned by
//!   [`StorageError::kind`].
//!
//! Operators should add an alert on `storage_op_errors_total` grouped
//! by `error_kind` so disconnected backends surface immediately.

use std::future::Future;
use std::sync::LazyLock;
use std::time::Instant;

use prometheus::{
    register_histogram_vec, register_int_counter_vec, HistogramOpts, HistogramVec, IntCounterVec,
    Opts,
};

use crate::error::StorageError;

/// Latency histogram for storage operations, in seconds.
///
/// Buckets are tuned for KV access (sub-millisecond up to a few
/// hundred milliseconds). Slow operations beyond 1s bucket into the
/// `+Inf` overflow.
pub static STORAGE_OP_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "storage_op_duration_seconds",
            "Latency of storage backend operations"
        )
        .buckets(vec![
            0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
        ]),
        &["op", "backend", "kind"]
    )
    .expect("register storage_op_duration_seconds")
});

/// Total errors returned by storage backends, partitioned by error
/// variant. Mirrors [`STORAGE_OP_DURATION_SECONDS`] for joins.
pub static STORAGE_OP_ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "storage_op_errors_total",
            "Errors returned by storage backend operations"
        ),
        &["op", "backend", "kind", "error_kind"]
    )
    .expect("register storage_op_errors_total")
});

/// Wrap a backend call so latency and error variant are recorded
/// automatically.
///
/// Backends call this around every public trait method:
///
/// ```ignore
/// observe_op("get", "redis", "ephemeral", async {
///     conn.get::<_, Option<Vec<u8>>>(key).await
///         .map(|opt| opt.map(Bytes::from))
///         .map_err(|e| StorageError::Backend(e.to_string()))
/// }).await
/// ```
///
/// The histogram observes total elapsed time including the future
/// poll overhead. The error counter increments only on `Err`.
pub async fn observe_op<F, T>(
    op: &'static str,
    backend: &'static str,
    kind: &'static str,
    fut: F,
) -> Result<T, StorageError>
where
    F: Future<Output = Result<T, StorageError>>,
{
    let start = Instant::now();
    let result = fut.await;
    let elapsed = start.elapsed().as_secs_f64();
    STORAGE_OP_DURATION_SECONDS
        .with_label_values(&[op, backend, kind])
        .observe(elapsed);
    if let Err(ref e) = result {
        STORAGE_OP_ERRORS_TOTAL
            .with_label_values(&[op, backend, kind, e.kind()])
            .inc();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn observe_op_records_success() {
        let value: Result<i32, StorageError> =
            observe_op("get", "in_memory", "ephemeral", async { Ok(42) }).await;
        assert_eq!(value.unwrap(), 42);
    }

    #[tokio::test]
    async fn observe_op_records_error() {
        let result: Result<(), StorageError> = observe_op("put", "in_memory", "ephemeral", async {
            Err(StorageError::Disconnected)
        })
        .await;
        assert!(matches!(result, Err(StorageError::Disconnected)));
    }
}
