//! Metrics and content-free summary events for AI context compression.

use prometheus::{
    register_histogram_vec, register_int_counter_vec, HistogramOpts, HistogramVec, IntCounterVec,
    Opts,
};
use sbproxy_ai::compression::{
    CompressionBackend, CompressionLeverConfig, CompressionPolicy, CompressionRun, LeverOutcome,
    RequestOutcome,
};
use std::sync::LazyLock;
use tracing::Level;

const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const TOKEN_BUCKETS: &[f64] = &[
    0.0,
    1.0,
    16.0,
    64.0,
    256.0,
    1_024.0,
    4_096.0,
    16_384.0,
    65_536.0,
    262_144.0,
    1_048_576.0,
];

static COMPRESSION_LEVER_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_ai_compression_lever_total",
            "AI context compression lever invocations by closed outcome"
        ),
        &[
            "tenant_id",
            "api_key_id",
            "lever",
            "outcome",
            "reason",
            "backend"
        ]
    )
    .expect("AI compression lever counter registers")
});

static COMPRESSION_TOKENS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_ai_compression_tokens_total",
            "SBproxy model-aware token estimates before and after an applied AI context compression lever"
        ),
        &["tenant_id", "api_key_id", "lever", "direction"]
    )
    .expect("AI compression token counter registers")
});

static COMPRESSION_TOKENS_SAVED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_ai_compression_tokens_saved_total",
            "Reduction in SBproxy's model-aware token estimate from applied AI context compression levers"
        ),
        &["tenant_id", "api_key_id", "lever"]
    )
    .expect("AI compression saved-token counter registers")
});

static COMPRESSION_RATIO: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_compression_ratio",
            "Final-to-initial SBproxy token-estimate ratio for applied AI context compression levers"
        )
        .buckets(vec![0.05, 0.1, 0.2, 0.35, 0.5, 0.65, 0.8, 0.9, 1.0]),
        &["tenant_id", "api_key_id", "lever"]
    )
    .expect("AI compression ratio histogram registers")
});

static COMPRESSION_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_compression_duration_seconds",
            "AI context compression lever duration in seconds"
        )
        .buckets(DURATION_BUCKETS.to_vec()),
        &["tenant_id", "api_key_id", "lever", "outcome", "backend"]
    )
    .expect("AI compression duration histogram registers")
});

static COMPRESSION_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_ai_compression_requests_total",
            "Requests that executed a non-empty AI context compression pipeline"
        ),
        &[
            "tenant_id",
            "api_key_id",
            "outcome",
            "backend",
            "cache_bypass"
        ]
    )
    .expect("AI compression request counter registers")
});

static COMPRESSION_SELECTION_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_ai_compression_selection_total",
            "AI request compression policy resolutions by closed source and outcome"
        ),
        &["tenant_id", "source", "outcome"]
    )
    .expect("AI compression selection counter registers")
});

static COMPRESSION_REQUEST_TOKENS_SAVED: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_compression_request_tokens_saved",
            "Initial-to-final reduction in SBproxy's model-aware token estimate once per compression request"
        )
        .buckets(TOKEN_BUCKETS.to_vec()),
        &["tenant_id", "api_key_id", "outcome", "backend"]
    )
    .expect("AI compression request saved-token histogram registers")
});

static COMPRESSION_REQUEST_LEVERS_RUN: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_compression_request_levers_run",
            "Number of context compression levers executed per request"
        )
        .buckets(vec![0.0, 1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0]),
        &["tenant_id", "api_key_id", "outcome", "backend"]
    )
    .expect("AI compression request lever-count histogram registers")
});

static COMPRESSION_STATE_OPERATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_ai_compression_state_operations_total",
            "External AI compression state operations by backend and closed outcome"
        ),
        &["backend", "operation", "outcome"]
    )
    .expect("AI compression state operation counter registers")
});

static COMPRESSION_STATE_OPERATION_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_compression_state_operation_duration_seconds",
            "External AI compression state operation duration in seconds"
        )
        .buckets(DURATION_BUCKETS.to_vec()),
        &["backend", "operation", "outcome"]
    )
    .expect("AI compression state duration histogram registers")
});

static COMPRESSION_REDIS_COORDINATION_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "sbproxy_ai_compression_redis_coordination_total",
            "Redis compression coordination contention and rejected updates"
        ),
        &["event"]
    )
    .expect("AI compression Redis coordination counter registers")
});

/// Closed external state operation names emitted by both adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompressionStateOperation {
    /// Load one opaque session record.
    Get,
    /// Commit one versioned session record.
    Commit,
    /// Delete one opaque session record.
    Delete,
    /// List one bounded metadata page.
    List,
    /// Purge one bounded metadata page.
    Purge,
}

/// Record one request's policy resolution using closed source and outcome labels.
pub(crate) fn record_compression_selection(
    tenant_id: &str,
    source: &'static str,
    outcome: &'static str,
) {
    let tenant_id = sbproxy_observe::metrics::sanitize_label_budget(
        "sbproxy_ai_compression_selection_total",
        "tenant_id",
        tenant_id,
    );
    COMPRESSION_SELECTION_TOTAL
        .with_label_values(&[&tenant_id, source, outcome])
        .inc();
}

impl CompressionStateOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Commit => "commit",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Purge => "purge",
        }
    }
}

/// Closed state operation outcomes independent of adapter error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompressionStateOutcome {
    /// The operation completed and found or changed state.
    Ok,
    /// The requested record was absent or already deleted.
    Missing,
    /// The operation failed or rejected an update.
    Error,
}

impl CompressionStateOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Error => "error",
        }
    }
}

/// Closed Redis coordination events, never raw Redis error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedisCompressionCoordinationEvent {
    /// An active lease prevented a bounded update attempt.
    Contention,
    /// Lease ownership was gone when the writer attempted to commit.
    LeaseExpiry,
    /// The canonical logical version advanced before commit.
    StaleVersion,
    /// A newer delete or writer fence rejected the commit.
    FenceRejection,
}

impl RedisCompressionCoordinationEvent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Contention => "contention",
            Self::LeaseExpiry => "lease_expiry",
            Self::StaleVersion => "stale_version",
            Self::FenceRejection => "fence_rejection",
        }
    }
}

/// Record one timed external state operation with closed labels.
pub(crate) fn record_compression_state_operation(
    backend: CompressionBackend,
    operation: CompressionStateOperation,
    outcome: CompressionStateOutcome,
    duration: std::time::Duration,
) {
    let labels = [
        backend_label(Some(backend)),
        operation.as_str(),
        outcome.as_str(),
    ];
    COMPRESSION_STATE_OPERATIONS_TOTAL
        .with_label_values(&labels)
        .inc();
    COMPRESSION_STATE_OPERATION_DURATION
        .with_label_values(&labels)
        .observe(duration.as_secs_f64());
}

/// Record one closed Redis coordination event.
pub(crate) fn record_redis_compression_coordination(event: RedisCompressionCoordinationEvent) {
    COMPRESSION_REDIS_COORDINATION_TOTAL
        .with_label_values(&[event.as_str()])
        .inc();
}

fn bounded_identity(metric: &str, tenant_id: &str, api_key_id: Option<&str>) -> (String, String) {
    let api_key_id = sbproxy_observe::metrics::sanitize_label_budget_tenant(
        metric,
        "api_key_id",
        api_key_id.unwrap_or_default(),
        tenant_id,
    );
    let tenant_id = sbproxy_observe::metrics::sanitize_label_budget(metric, "tenant_id", tenant_id);
    (tenant_id, api_key_id)
}

const fn backend_label(backend: Option<CompressionBackend>) -> &'static str {
    match backend {
        Some(CompressionBackend::Redis) => "redis",
        Some(CompressionBackend::Mesh) => "mesh",
        None => "none",
    }
}

fn request_backend(run: &CompressionRun) -> Option<CompressionBackend> {
    run.lever_results.iter().find_map(|result| result.backend)
}

fn outcome_labels(outcome: LeverOutcome) -> (&'static str, &'static str) {
    match outcome {
        LeverOutcome::Applied => ("applied", ""),
        LeverOutcome::Skipped { reason } => ("skipped", reason.as_str()),
        LeverOutcome::Failed { reason } => ("failed", reason.as_str()),
    }
}

fn consistency_label(backend: Option<CompressionBackend>) -> &'static str {
    match backend {
        Some(CompressionBackend::Redis) => "serialized",
        Some(CompressionBackend::Mesh) => "eventual_lww",
        None => "none",
    }
}

fn target_log(policy: &CompressionPolicy) -> String {
    let targets = policy
        .levers
        .iter()
        .map(|lever| match lever {
            CompressionLeverConfig::SummaryBuffer(config) => serde_json::json!({
                "lever": "summary_buffer",
                "min_tokens": config.min_tokens,
                "retain_recent_messages": config.retain_recent_messages,
                "target_summary_tokens": config.target_summary_tokens,
                "timeout_ms": config.summarizer.timeout_secs.saturating_mul(1_000),
            }),
            CompressionLeverConfig::WindowFit(config) => serde_json::json!({
                "lever": "window_fit",
                "completion_reserve_tokens": config.completion_reserve_tokens,
                "input_budget_tokens": config.input_budget_tokens,
            }),
        })
        .collect::<Vec<_>>();
    serde_json::Value::Array(targets).to_string()
}

fn outcome_log(run: &CompressionRun) -> String {
    let outcomes = run
        .lever_results
        .iter()
        .map(|result| {
            let (outcome, reason) = outcome_labels(result.outcome);
            serde_json::json!({
                "lever": result.lever.as_str(),
                "outcome": outcome,
                "reason": reason,
                "backend": backend_label(result.backend),
                "before_tokens": result.before_tokens,
                "after_tokens": result.after_tokens,
                "tokens_saved": result.tokens_saved,
                "duration_ms": u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
            })
        })
        .collect::<Vec<_>>();
    serde_json::Value::Array(outcomes).to_string()
}

fn emit_compression_summary(
    policy: &CompressionPolicy,
    tenant_id: &str,
    api_key_id: &str,
    cache_bypass: bool,
    selection_source: &'static str,
    selection_outcome: &'static str,
    run: &CompressionRun,
) {
    let backend = request_backend(run);
    let outcome = run.outcome();
    let lever_outcomes = outcome_log(run);
    let targets = target_log(policy);
    let levers_applied = run
        .lever_results
        .iter()
        .filter(|result| matches!(result.outcome, LeverOutcome::Applied))
        .count();
    let latency_ms = run.lever_results.iter().fold(0_u64, |total, result| {
        total.saturating_add(u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX))
    });
    macro_rules! emit {
        ($level:expr) => {{
            tracing::event!(
                target: "ai_compression",
                $level,
                event = "ai_compression_summary",
                tenant_id,
                api_key_id,
                outcome = outcome.as_str(),
                initial_tokens = run.initial_tokens,
                final_tokens = run.final_tokens,
                tokens_saved = run.tokens_saved,
                levers_run = run.lever_results.len(),
                levers_applied,
                latency_ms,
                backend = backend_label(backend),
                consistency = consistency_label(backend),
                cache_bypass,
                selection_source,
                selection_outcome,
                lever_outcomes,
                targets,
                "AI context compression pipeline summary"
            );
        }};
    }
    match outcome {
        RequestOutcome::Failed => emit!(Level::WARN),
        RequestOutcome::Applied => emit!(Level::INFO),
        RequestOutcome::Skipped => emit!(Level::DEBUG),
    }
}

/// Record one non-empty compression pipeline without observing message content.
pub(crate) fn record_compression_run(
    policy: &CompressionPolicy,
    tenant_id: &str,
    api_key_id: Option<&str>,
    cache_bypass: bool,
    selection_source: &'static str,
    selection_outcome: &'static str,
    run: &CompressionRun,
) {
    if run.lever_results.is_empty() {
        return;
    }

    for result in &run.lever_results {
        let lever = result.lever.as_str();
        let backend = backend_label(result.backend);
        let (outcome, reason) = outcome_labels(result.outcome);
        let (tenant, key) =
            bounded_identity("sbproxy_ai_compression_lever_total", tenant_id, api_key_id);
        COMPRESSION_LEVER_TOTAL
            .with_label_values(&[&tenant, &key, lever, outcome, reason, backend])
            .inc();

        let (tenant, key) = bounded_identity(
            "sbproxy_ai_compression_duration_seconds",
            tenant_id,
            api_key_id,
        );
        COMPRESSION_DURATION
            .with_label_values(&[&tenant, &key, lever, outcome, backend])
            .observe(result.duration.as_secs_f64());

        if !matches!(result.outcome, LeverOutcome::Applied) {
            continue;
        }

        let (tenant, key) =
            bounded_identity("sbproxy_ai_compression_tokens_total", tenant_id, api_key_id);
        COMPRESSION_TOKENS_TOTAL
            .with_label_values(&[&tenant, &key, lever, "input"])
            .inc_by(result.before_tokens);
        COMPRESSION_TOKENS_TOTAL
            .with_label_values(&[&tenant, &key, lever, "output"])
            .inc_by(result.after_tokens);

        let (tenant, key) = bounded_identity(
            "sbproxy_ai_compression_tokens_saved_total",
            tenant_id,
            api_key_id,
        );
        COMPRESSION_TOKENS_SAVED_TOTAL
            .with_label_values(&[&tenant, &key, lever])
            .inc_by(result.tokens_saved);

        if result.before_tokens > 0 {
            let (tenant, key) =
                bounded_identity("sbproxy_ai_compression_ratio", tenant_id, api_key_id);
            COMPRESSION_RATIO
                .with_label_values(&[&tenant, &key, lever])
                .observe(result.after_tokens as f64 / result.before_tokens as f64);
        }
    }

    let outcome = run.outcome().as_str();
    let backend = backend_label(request_backend(run));
    let cache_bypass = if cache_bypass { "true" } else { "false" };
    let (tenant, key) = bounded_identity(
        "sbproxy_ai_compression_requests_total",
        tenant_id,
        api_key_id,
    );
    COMPRESSION_REQUESTS_TOTAL
        .with_label_values(&[&tenant, &key, outcome, backend, cache_bypass])
        .inc();

    let (tenant, key) = bounded_identity(
        "sbproxy_ai_compression_request_tokens_saved",
        tenant_id,
        api_key_id,
    );
    COMPRESSION_REQUEST_TOKENS_SAVED
        .with_label_values(&[&tenant, &key, outcome, backend])
        .observe(run.tokens_saved as f64);

    let (tenant, key) = bounded_identity(
        "sbproxy_ai_compression_request_levers_run",
        tenant_id,
        api_key_id,
    );
    COMPRESSION_REQUEST_LEVERS_RUN
        .with_label_values(&[&tenant, &key, outcome, backend])
        .observe(run.lever_results.len() as f64);

    let (log_tenant, log_key) = bounded_identity(
        "sbproxy_ai_compression_requests_total",
        tenant_id,
        api_key_id,
    );
    emit_compression_summary(
        policy,
        &log_tenant,
        &log_key,
        cache_bypass == "true",
        selection_source,
        selection_outcome,
        run,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        record_compression_run, record_compression_selection, record_compression_state_operation,
        record_redis_compression_coordination, CompressionStateOperation, CompressionStateOutcome,
        RedisCompressionCoordinationEvent,
    };
    use sbproxy_ai::compression::{
        CompressionBackend, CompressionLeverConfig, CompressionPolicy, CompressionRun,
        CompressionStateBackend, CompressionStateConfig, FailureReason, LeverKind, LeverOutcome,
        LeverResult, SkipReason, SummarizerConfig, SummaryBufferConfig, WindowFitConfig,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Clone)]
    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    struct SharedLogGuard(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogWriter {
        type Writer = SharedLogGuard;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogGuard(Arc::clone(&self.0))
        }
    }

    impl std::io::Write for SharedLogGuard {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture_summary(run: &CompressionRun) -> String {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(SharedLogWriter(Arc::clone(&captured)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            record_compression_run(
                &policy(),
                "compression-log-tenant",
                Some("compression-log-key"),
                true,
                "governed_key",
                "selected",
                run,
            );
        });
        let bytes = captured.lock().expect("log capture").clone();
        String::from_utf8(bytes).expect("compression log is UTF-8")
    }

    fn policy() -> CompressionPolicy {
        CompressionPolicy {
            state: Some(CompressionStateConfig {
                backend: CompressionStateBackend::Redis,
                ttl_secs: 3_600,
            }),
            allow_admin_content_inspection: false,
            levers: vec![
                CompressionLeverConfig::SummaryBuffer(SummaryBufferConfig {
                    min_tokens: 100,
                    retain_recent_messages: 2,
                    target_summary_tokens: 20,
                    summarizer: SummarizerConfig {
                        provider: "provider-not-for-telemetry".to_string(),
                        model: "model-not-for-telemetry".to_string(),
                        timeout_secs: 5,
                    },
                }),
                CompressionLeverConfig::WindowFit(WindowFitConfig {
                    completion_reserve_tokens: 1_024,
                    input_budget_tokens: Some(8_192),
                }),
            ],
            profiles: std::collections::BTreeMap::new(),
        }
    }

    fn applied_run() -> CompressionRun {
        CompressionRun {
            messages: vec![serde_json::json!({
                "role": "user",
                "content": "secret message must never reach telemetry"
            })],
            initial_tokens: 100,
            final_tokens: 50,
            tokens_saved: 50,
            token_count_precision: sbproxy_ai::TokenCountPrecision::ModelTokenizer,
            lever_results: vec![
                LeverResult {
                    lever: LeverKind::SummaryBuffer,
                    backend: Some(CompressionBackend::Redis),
                    outcome: LeverOutcome::Applied,
                    before_tokens: 100,
                    after_tokens: 60,
                    tokens_saved: 40,
                    duration: Duration::from_millis(12),
                },
                LeverResult {
                    lever: LeverKind::WindowFit,
                    backend: None,
                    outcome: LeverOutcome::Applied,
                    before_tokens: 60,
                    after_tokens: 50,
                    tokens_saved: 10,
                    duration: Duration::from_millis(3),
                },
            ],
        }
    }

    #[allow(deprecated)]
    fn metric_sample(name: &str, labels: &[(&str, &str)]) -> (f64, u64, f64) {
        for family in prometheus::gather() {
            if family.get_name() != name {
                continue;
            }
            for metric in family.get_metric() {
                let matches = labels.iter().all(|(wanted_name, wanted_value)| {
                    metric.get_label().iter().any(|pair| {
                        pair.get_name() == *wanted_name && pair.get_value() == *wanted_value
                    })
                });
                if !matches {
                    continue;
                }
                if family.get_field_type() == prometheus::proto::MetricType::COUNTER {
                    return (metric.get_counter().value(), 0, 0.0);
                }
                if family.get_field_type() == prometheus::proto::MetricType::HISTOGRAM {
                    return (
                        0.0,
                        metric.get_histogram().get_sample_count(),
                        metric.get_histogram().get_sample_sum(),
                    );
                }
            }
        }
        (0.0, 0, 0.0)
    }

    #[test]
    fn applied_run_records_exact_per_lever_and_request_savings_once() {
        let tenant = "compression-metrics-applied-tenant";
        let key = "compression-metrics-applied-key";
        let run = applied_run();

        record_compression_run(
            &policy(),
            tenant,
            Some(key),
            false,
            "route_default",
            "default",
            &run,
        );

        let summary_labels = [
            ("tenant_id", tenant),
            ("api_key_id", key),
            ("lever", "summary_buffer"),
        ];
        assert_eq!(
            metric_sample(
                "sbproxy_ai_compression_tokens_total",
                &[
                    summary_labels[0],
                    summary_labels[1],
                    summary_labels[2],
                    ("direction", "input"),
                ],
            )
            .0,
            100.0
        );
        assert_eq!(
            metric_sample(
                "sbproxy_ai_compression_tokens_total",
                &[
                    summary_labels[0],
                    summary_labels[1],
                    summary_labels[2],
                    ("direction", "output"),
                ],
            )
            .0,
            60.0
        );
        assert_eq!(
            metric_sample("sbproxy_ai_compression_tokens_saved_total", &summary_labels,).0,
            40.0
        );

        let request_labels = [
            ("tenant_id", tenant),
            ("api_key_id", key),
            ("outcome", "applied"),
            ("backend", "redis"),
        ];
        let saved = metric_sample(
            "sbproxy_ai_compression_request_tokens_saved",
            &request_labels,
        );
        assert_eq!(saved.1, 1);
        assert_eq!(saved.2, 50.0);
        let levers = metric_sample("sbproxy_ai_compression_request_levers_run", &request_labels);
        assert_eq!(levers.1, 1);
        assert_eq!(levers.2, 2.0);
    }

    #[test]
    fn policy_selection_metric_uses_only_bounded_dimensions() {
        let tenant = "compression-selection-tenant";
        let labels = [
            ("tenant_id", tenant),
            ("source", "governed_key"),
            ("outcome", "disabled"),
        ];
        let before = metric_sample("sbproxy_ai_compression_selection_total", &labels).0;

        record_compression_selection(tenant, "governed_key", "disabled");

        let after = metric_sample("sbproxy_ai_compression_selection_total", &labels).0;
        assert_eq!(after - before, 1.0);
    }

    #[test]
    fn skipped_and_failed_levers_never_record_token_savings() {
        let tenant = "compression-metrics-no-savings-tenant";
        let key = "compression-metrics-no-savings-key";
        let run = CompressionRun {
            messages: Vec::new(),
            initial_tokens: 80,
            final_tokens: 80,
            tokens_saved: 0,
            token_count_precision: sbproxy_ai::TokenCountPrecision::ModelTokenizer,
            lever_results: vec![
                LeverResult {
                    lever: LeverKind::SummaryBuffer,
                    backend: Some(CompressionBackend::Redis),
                    outcome: LeverOutcome::Skipped {
                        reason: SkipReason::BelowThreshold,
                    },
                    before_tokens: 80,
                    after_tokens: 80,
                    tokens_saved: 0,
                    duration: Duration::from_millis(1),
                },
                LeverResult {
                    lever: LeverKind::WindowFit,
                    backend: None,
                    outcome: LeverOutcome::Failed {
                        reason: FailureReason::Internal,
                    },
                    before_tokens: 80,
                    after_tokens: 80,
                    tokens_saved: 0,
                    duration: Duration::from_millis(2),
                },
            ],
        };

        record_compression_run(
            &policy(),
            tenant,
            Some(key),
            true,
            "route_default",
            "default",
            &run,
        );

        for lever in ["summary_buffer", "window_fit"] {
            assert_eq!(
                metric_sample(
                    "sbproxy_ai_compression_tokens_saved_total",
                    &[("tenant_id", tenant), ("api_key_id", key), ("lever", lever),],
                )
                .0,
                0.0
            );
        }
        let request = metric_sample(
            "sbproxy_ai_compression_request_tokens_saved",
            &[
                ("tenant_id", tenant),
                ("api_key_id", key),
                ("outcome", "failed"),
                ("backend", "redis"),
            ],
        );
        assert_eq!(request.1, 1);
        assert_eq!(request.2, 0.0);
        assert_eq!(
            metric_sample(
                "sbproxy_ai_compression_requests_total",
                &[
                    ("tenant_id", tenant),
                    ("api_key_id", key),
                    ("outcome", "failed"),
                    ("backend", "redis"),
                    ("cache_bypass", "true"),
                ],
            )
            .0,
            1.0
        );
    }

    #[test]
    fn state_and_coordination_metrics_use_only_closed_labels() {
        let state_labels = [
            ("backend", "redis"),
            ("operation", "get"),
            ("outcome", "missing"),
        ];
        let before_total = metric_sample(
            "sbproxy_ai_compression_state_operations_total",
            &state_labels,
        )
        .0;
        let before_duration = metric_sample(
            "sbproxy_ai_compression_state_operation_duration_seconds",
            &state_labels,
        );
        record_compression_state_operation(
            CompressionBackend::Redis,
            CompressionStateOperation::Get,
            CompressionStateOutcome::Missing,
            Duration::from_millis(7),
        );
        let after_total = metric_sample(
            "sbproxy_ai_compression_state_operations_total",
            &state_labels,
        )
        .0;
        let after_duration = metric_sample(
            "sbproxy_ai_compression_state_operation_duration_seconds",
            &state_labels,
        );
        assert_eq!(after_total - before_total, 1.0);
        assert_eq!(after_duration.1 - before_duration.1, 1);
        assert!((after_duration.2 - before_duration.2 - 0.007).abs() < 0.000_001);

        let redis_before = metric_sample(
            "sbproxy_ai_compression_redis_coordination_total",
            &[("event", "fence_rejection")],
        )
        .0;
        record_redis_compression_coordination(RedisCompressionCoordinationEvent::FenceRejection);
        let redis_after = metric_sample(
            "sbproxy_ai_compression_redis_coordination_total",
            &[("event", "fence_rejection")],
        )
        .0;
        assert_eq!(redis_after - redis_before, 1.0);
    }

    #[test]
    fn one_content_free_summary_event_uses_failure_first_log_levels() {
        let applied = capture_summary(&applied_run());
        assert_eq!(applied.matches("ai_compression_summary").count(), 1);
        assert!(applied.contains(" INFO "), "{applied}");
        assert!(applied.contains("tokens_saved=50"), "{applied}");
        assert!(applied.contains("min_tokens"), "{applied}");
        assert!(applied.contains("completion_reserve_tokens"), "{applied}");
        assert!(applied.contains("input_budget_tokens"), "{applied}");
        assert!(applied.contains("8192"), "{applied}");
        assert!(
            applied.contains("selection_source=\"governed_key\""),
            "{applied}"
        );
        assert!(
            applied.contains("selection_outcome=\"selected\""),
            "{applied}"
        );
        assert!(!applied.contains("secret message"), "{applied}");
        assert!(!applied.contains("provider-not-for-telemetry"), "{applied}");
        assert!(!applied.contains("model-not-for-telemetry"), "{applied}");

        let skipped = CompressionRun {
            messages: vec![serde_json::json!({"content": "another secret"})],
            initial_tokens: 40,
            final_tokens: 40,
            tokens_saved: 0,
            token_count_precision: sbproxy_ai::TokenCountPrecision::ModelTokenizer,
            lever_results: vec![LeverResult {
                lever: LeverKind::WindowFit,
                backend: None,
                outcome: LeverOutcome::Skipped {
                    reason: SkipReason::NotNeeded,
                },
                before_tokens: 40,
                after_tokens: 40,
                tokens_saved: 0,
                duration: Duration::from_millis(1),
            }],
        };
        let skipped = capture_summary(&skipped);
        assert_eq!(skipped.matches("ai_compression_summary").count(), 1);
        assert!(skipped.contains("DEBUG"), "{skipped}");
        assert!(!skipped.contains("another secret"), "{skipped}");

        let failed = CompressionRun {
            messages: Vec::new(),
            initial_tokens: 40,
            final_tokens: 40,
            tokens_saved: 0,
            token_count_precision: sbproxy_ai::TokenCountPrecision::ModelTokenizer,
            lever_results: vec![LeverResult {
                lever: LeverKind::SummaryBuffer,
                backend: Some(CompressionBackend::Redis),
                outcome: LeverOutcome::Failed {
                    reason: FailureReason::StateUnavailable,
                },
                before_tokens: 40,
                after_tokens: 40,
                tokens_saved: 0,
                duration: Duration::from_millis(1),
            }],
        };
        let failed = capture_summary(&failed);
        assert_eq!(failed.matches("ai_compression_summary").count(), 1);
        assert!(failed.contains(" WARN "), "{failed}");

        let empty = CompressionRun {
            messages: Vec::new(),
            initial_tokens: 0,
            final_tokens: 0,
            tokens_saved: 0,
            token_count_precision: sbproxy_ai::TokenCountPrecision::Heuristic,
            lever_results: Vec::new(),
        };
        let empty_labels = [
            ("tenant_id", "compression-log-tenant"),
            ("api_key_id", "compression-log-key"),
            ("outcome", "skipped"),
            ("backend", "none"),
            ("cache_bypass", "true"),
        ];
        let before = metric_sample("sbproxy_ai_compression_requests_total", &empty_labels).0;
        assert!(capture_summary(&empty).is_empty());
        let after = metric_sample("sbproxy_ai_compression_requests_total", &empty_labels).0;
        assert_eq!(after, before, "empty pipelines must not emit metrics");
    }
}
