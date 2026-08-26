//! Prometheus metrics for this sidecar's own `/metrics` endpoint.
//!
//! New for this port (the enterprise crate registered its own metrics
//! through `metrics` + `metrics-exporter-prometheus`; this file registers
//! the same *kind* of signal through the `prometheus` crate instead, which
//! is what the rest of this workspace, `sbproxy-observe`, standardizes on).
//! Using a second metrics stack for one binary would mean patching,
//! licensing, and keeping two Prometheus client libraries in sync for no
//! reason; `prometheus` already does the job.
//!
//! These families are registered on the process-global default registry
//! (`prometheus::default_registry()`), the same one `prometheus::gather()`
//! reads in [`crate::health`]'s `/metrics` handler. This binary runs as its
//! own process, so there is no risk of colliding with the main proxy's own
//! metric families the way there would be if this were linked into it.
//!
//! Every family here is scraped by `dashboards/grafana/sbproxy-classifier.json`;
//! see `docs/classifier-sidecar.md#metrics` for the panel-to-family mapping
//! and `scripts/check-metric-visibility.sh`'s docstring for why a metric
//! with nowhere to be seen is treated as undone.

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts};
use std::sync::OnceLock;

#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use tokio::sync::{Mutex, OwnedMutexGuard};

// Every metric constructor below still uses hardcoded names and label sets,
// never request-derived input. Constructor and registration failures are
// logged and degrade to missing metrics rather than panicking the process.

static REQUESTS_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static ERRORS_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static TENANTS: OnceLock<Option<IntGauge>> = OnceLock::new();
static QUALITY_SCORE: OnceLock<Option<HistogramVec>> = OnceLock::new();
static SAFETY_VERDICTS_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static ADMISSION_REFUSALS_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static ADMISSION_QUEUE: OnceLock<Option<IntGaugeVec>> = OnceLock::new();
static ATTEMPTS_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static COMPLETIONS_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static TERMINAL_OUTCOMES_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static STARTUP_OWNER_INFO: OnceLock<Option<IntGaugeVec>> = OnceLock::new();

#[cfg(test)]
static OUTCOME_PROBE_LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Transport {
    Tcp,
    AdminTcp,
    Grpc,
    Http,
}

impl Transport {
    fn as_label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::AdminTcp => "admin_tcp",
            Self::Grpc => "grpc",
            Self::Http => "http",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Command {
    Classify,
    Embed,
    Compress,
    ModelInfo,
    Quality,
    QualityScore,
    Register,
    Delete,
    List,
    Version,
    IntentDetect,
    StreamSafety,
    StreamingSafety,
    ContentTypeDetect,
    Decode,
    Tenants,
    Healthz,
    Readyz,
    Metrics,
    Unknown,
}

impl Command {
    fn as_label(self) -> &'static str {
        match self {
            Self::Classify => "classify",
            Self::Embed => "embed",
            Self::Compress => "compress",
            Self::ModelInfo => "model_info",
            Self::Quality => "quality",
            Self::QualityScore => "quality_score",
            Self::Register => "register",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Version => "version",
            Self::IntentDetect => "intent_detect",
            Self::StreamSafety => "stream_safety",
            Self::StreamingSafety => "streaming_safety",
            Self::ContentTypeDetect => "content_type_detect",
            Self::Decode => "decode",
            Self::Tenants => "tenants",
            Self::Healthz => "healthz",
            Self::Readyz => "readyz",
            Self::Metrics => "metrics",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Stage {
    Admission,
    Authorize,
    Cancellation,
    Decode,
    Encode,
    Handler,
    Limit,
    Model,
    Read,
    Route,
    Worker,
    Write,
}

impl Stage {
    fn as_label(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Authorize => "authorize",
            Self::Cancellation => "cancellation",
            Self::Decode => "decode",
            Self::Encode => "encode",
            Self::Handler => "handler",
            Self::Limit => "limit",
            Self::Model => "model",
            Self::Read => "read",
            Self::Route => "route",
            Self::Worker => "worker",
            Self::Write => "write",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Reason {
    Cancelled,
    Deadline,
    Forbidden,
    InferenceFailed,
    Internal,
    InvalidConfig,
    Io,
    MalformedFrame,
    MissingField,
    ModelNotFound,
    NotFound,
    QueueFull,
    ResourceLimit,
    TenantNotFound,
    Unauthorized,
    Unavailable,
    Unimplemented,
    UnknownCommand,
}

impl Reason {
    fn as_label(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Deadline => "deadline",
            Self::Forbidden => "forbidden",
            Self::InferenceFailed => "inference_failed",
            Self::Internal => "internal",
            Self::InvalidConfig => "invalid_config",
            Self::Io => "io",
            Self::MalformedFrame => "malformed_frame",
            Self::MissingField => "missing_field",
            Self::ModelNotFound => "model_not_found",
            Self::NotFound => "not_found",
            Self::QueueFull => "queue_full",
            Self::ResourceLimit => "resource_limit",
            Self::TenantNotFound => "tenant_not_found",
            Self::Unauthorized => "unauthorized",
            Self::Unavailable => "unavailable",
            Self::Unimplemented => "unimplemented",
            Self::UnknownCommand => "unknown_command",
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutcomeExpectation {
    transport: Transport,
    command: Command,
    stage: Option<Stage>,
    reason: Option<Reason>,
}

#[cfg(test)]
impl OutcomeExpectation {
    pub(crate) fn success(transport: Transport, command: Command) -> Self {
        Self {
            transport,
            command,
            stage: None,
            reason: None,
        }
    }

    pub(crate) fn failure(
        transport: Transport,
        command: Command,
        stage: Stage,
        reason: Reason,
    ) -> Self {
        Self {
            transport,
            command,
            stage: Some(stage),
            reason: Some(reason),
        }
    }
}

fn normalize_transport(transport: &str) -> &'static str {
    match transport {
        "tcp" => "tcp",
        "admin_tcp" => "admin_tcp",
        "grpc" => "grpc",
        "http" => "http",
        _ => "unknown",
    }
}

fn normalize_command(command: &str) -> &'static str {
    match command {
        "" | "classify" => "classify",
        "embed" => "embed",
        "compress" => "compress",
        "model_info" => "model_info",
        "quality" => "quality",
        "quality_score" => "quality_score",
        "register" => "register",
        "delete" => "delete",
        "list" => "list",
        "version" => "version",
        "intent_detect" => "intent_detect",
        "stream_safety" => "stream_safety",
        "streaming_safety" => "streaming_safety",
        "content_type_detect" => "content_type_detect",
        "decode" => "decode",
        "tenants" => "tenants",
        "healthz" => "healthz",
        "readyz" => "readyz",
        "metrics" => "metrics",
        _ => "unknown",
    }
}

fn normalize_reason(reason: &str) -> &'static str {
    match reason {
        "malformed_frame" => "malformed_frame",
        "unknown_command" => "unknown_command",
        "tenant_not_registered" => "tenant_not_registered",
        "invalid_config" => "invalid_config",
        "inference_failed" => "inference_failed",
        "unauthorized" => "unauthorized",
        "forbidden" => "forbidden",
        "queue_full" => "queue_full",
        "deadline" => "deadline",
        "resource_limit" => "resource_limit",
        "cancelled" => "cancelled",
        "internal" => "internal",
        "io" => "io",
        "missing_field" => "missing_field",
        "model_not_found" => "model_not_found",
        "not_found" => "not_found",
        "tenant_not_found" => "tenant_not_found",
        "unavailable" => "unavailable",
        "unimplemented" => "unimplemented",
        _ => "unknown",
    }
}

fn requests_total() -> Option<&'static IntCounterVec> {
    REQUESTS_TOTAL
        .get_or_init(|| {
            build_counter_vec(
                "sbproxy_classifier_requests_total",
                "Requests handled by the rich classifier sidecar, by transport and command.",
                &["transport", "cmd"],
            )
        })
        .as_ref()
}

fn errors_total() -> Option<&'static IntCounterVec> {
    ERRORS_TOTAL.get_or_init(|| {
        build_counter_vec(
            "sbproxy_classifier_errors_total",
            "Requests the rich classifier sidecar could not complete, by transport, command, and reason.",
            &["transport", "cmd", "reason"],
        )
    })
    .as_ref()
}

fn tenants_gauge() -> Option<&'static IntGauge> {
    TENANTS
        .get_or_init(|| {
            build_gauge(
                "sbproxy_classifier_tenants",
                "Tenants currently registered with the rich classifier sidecar.",
            )
        })
        .as_ref()
}

fn quality_score_histogram() -> Option<&'static HistogramVec> {
    QUALITY_SCORE.get_or_init(|| {
        build_histogram_vec(
            HistogramOpts::new(
                "sbproxy_classifier_quality_score",
                "Heuristic quality scores returned by the Quality RPC/command, 0.0 (poor) to 1.0 (excellent).",
            )
            .buckets(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]),
            "sbproxy_classifier_quality_score",
            &["transport"],
        )
    })
    .as_ref()
}

fn safety_verdicts_total() -> Option<&'static IntCounterVec> {
    SAFETY_VERDICTS_TOTAL
        .get_or_init(|| {
            build_counter_vec(
                "sbproxy_classifier_safety_verdicts_total",
                "Per-token streaming safety verdicts, by outcome (safe / blocked / unsafe_continued).",
                &["verdict"],
            )
        })
        .as_ref()
}

fn admission_refusals_total() -> Option<&'static IntCounterVec> {
    ADMISSION_REFUSALS_TOTAL
        .get_or_init(|| {
            match IntCounterVec::new(
                Opts::new(
                    "sbproxy_classifier_admission_refusals_total",
                    "Rich-sidecar requests refused by bounded admission, by command and reason.",
                ),
                &["cmd", "reason"],
            ) {
                Ok(counter) => Some(register_collector_or_log(
                    counter,
                    "sbproxy_classifier_admission_refusals_total",
                )),
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        metric = "sbproxy_classifier_admission_refusals_total",
                        "failed to construct classifier admission metric"
                    );
                    None
                }
            }
        })
        .as_ref()
}

fn admission_queue() -> Option<&'static IntGaugeVec> {
    ADMISSION_QUEUE
        .get_or_init(|| {
            match IntGaugeVec::new(
                Opts::new(
                    "sbproxy_classifier_admission_queue",
                    "Rich-sidecar requests currently waiting for a bounded inference slot.",
                ),
                &["cmd"],
            ) {
                Ok(gauge) => Some(register_collector_or_log(
                    gauge,
                    "sbproxy_classifier_admission_queue",
                )),
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        metric = "sbproxy_classifier_admission_queue",
                        "failed to construct classifier admission metric"
                    );
                    None
                }
            }
        })
        .as_ref()
}

fn attempts_total() -> Option<&'static IntCounterVec> {
    ATTEMPTS_TOTAL
        .get_or_init(|| {
            build_counter_vec(
                "sbproxy_classifier_attempts_total",
                "Observed terminal request attempts by transport and command.",
                &["transport", "cmd"],
            )
        })
        .as_ref()
}

fn completions_total() -> Option<&'static IntCounterVec> {
    COMPLETIONS_TOTAL
        .get_or_init(|| {
            build_counter_vec(
                "sbproxy_classifier_completions_total",
                "Observed successful request completions by transport and command.",
                &["transport", "cmd"],
            )
        })
        .as_ref()
}

fn terminal_outcomes_total() -> Option<&'static IntCounterVec> {
    TERMINAL_OUTCOMES_TOTAL
        .get_or_init(|| {
            build_counter_vec(
                "sbproxy_classifier_terminal_outcomes_total",
                "Observed terminal request failures by transport, command, stage, and reason.",
                &["transport", "cmd", "stage", "reason"],
            )
        })
        .as_ref()
}

fn startup_owner_info() -> Option<&'static IntGaugeVec> {
    STARTUP_OWNER_INFO
        .get_or_init(|| {
            match IntGaugeVec::new(
                Opts::new(
                    "sbproxy_classifier_startup_owner_info",
                    "Release entrypoint ownership of the prepared classifier runtime capability.",
                ),
                &["entrypoint", "owner"],
            ) {
                Ok(gauge) => Some(register_collector_or_log(
                    gauge,
                    "sbproxy_classifier_startup_owner_info",
                )),
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        metric = "sbproxy_classifier_startup_owner_info",
                        "failed to construct classifier startup-owner metric"
                    );
                    None
                }
            }
        })
        .as_ref()
}

fn build_counter_vec(
    name: &'static str,
    help: &'static str,
    labels: &[&str],
) -> Option<IntCounterVec> {
    let counter = match IntCounterVec::new(Opts::new(name, help), labels) {
        Ok(counter) => counter,
        Err(error) => {
            tracing::error!(error = %error, metric = name, "failed to construct classifier metric");
            return None;
        }
    };
    Some(register_collector_or_log(counter, name))
}

fn build_gauge(name: &'static str, help: &'static str) -> Option<IntGauge> {
    let gauge = match IntGauge::new(name, help) {
        Ok(gauge) => gauge,
        Err(error) => {
            tracing::error!(error = %error, metric = name, "failed to construct classifier metric");
            return None;
        }
    };
    Some(register_collector_or_log(gauge, name))
}

fn build_histogram_vec(
    opts: HistogramOpts,
    name: &'static str,
    labels: &[&str],
) -> Option<HistogramVec> {
    let histogram = match HistogramVec::new(opts, labels) {
        Ok(histogram) => histogram,
        Err(error) => {
            tracing::error!(error = %error, metric = name, "failed to construct classifier metric");
            return None;
        }
    };
    Some(register_collector_or_log(histogram, name))
}

fn register_collector_or_log<C>(collector: C, name: &'static str) -> C
where
    C: prometheus::core::Collector + Clone + Send + Sync + 'static,
{
    if let Err(error) = prometheus::register(Box::new(collector.clone())) {
        tracing::error!(error = %error, metric = name, "failed to register classifier metric");
    }
    collector
}

fn record_attempt(transport: Transport, command: Command) {
    if let Some(counter) = attempts_total() {
        counter
            .with_label_values(&[transport.as_label(), command.as_label()])
            .inc();
    }
}

fn record_completion(transport: Transport, command: Command) {
    if let Some(counter) = completions_total() {
        counter
            .with_label_values(&[transport.as_label(), command.as_label()])
            .inc();
    }
}

fn record_terminal_failure(transport: Transport, command: Command, stage: Stage, reason: Reason) {
    if let Some(counter) = terminal_outcomes_total() {
        counter
            .with_label_values(&[
                transport.as_label(),
                command.as_label(),
                stage.as_label(),
                reason.as_label(),
            ])
            .inc();
    }
}

pub(crate) struct OutcomeGuard {
    transport: Transport,
    command: Command,
    finished: bool,
}

impl OutcomeGuard {
    pub(crate) fn begin(transport: Transport, command: Command) -> Self {
        record_attempt(transport, command);
        Self {
            transport,
            command,
            finished: false,
        }
    }

    pub(crate) fn success(mut self) {
        self.finished = true;
        record_completion(self.transport, self.command);
        record_request(self.transport.as_label(), self.command.as_label());
    }

    pub(crate) fn failure(mut self, stage: Stage, reason: Reason) {
        self.finished = true;
        record_terminal_failure(self.transport, self.command, stage, reason);
        if let Some(counter) = errors_total() {
            counter
                .with_label_values(&[
                    self.transport.as_label(),
                    self.command.as_label(),
                    reason.as_label(),
                ])
                .inc();
        }
    }
}

impl Drop for OutcomeGuard {
    fn drop(&mut self) {
        if !self.finished {
            record_terminal_failure(
                self.transport,
                self.command,
                Stage::Cancellation,
                Reason::Cancelled,
            );
            if let Some(counter) = errors_total() {
                counter
                    .with_label_values(&[
                        self.transport.as_label(),
                        self.command.as_label(),
                        Reason::Cancelled.as_label(),
                    ])
                    .inc();
            }
        }
    }
}

pub(crate) fn begin_outcome(transport: Transport, command: Command) -> OutcomeGuard {
    OutcomeGuard::begin(transport, command)
}

/// Attest that the shipped release entrypoint owns the prepared runtime
/// capability used by all listener owners. The closed labels prevent a test
/// mirror or helper path from masquerading as the release assembly.
pub(crate) fn record_release_startup_owner() {
    if let Some(gauge) = startup_owner_info() {
        gauge
            .with_label_values(&["release_main", "prepared_capability"])
            .set(1);
    }
}

/// Record one handled request for `(transport, cmd)` on
/// `sbproxy_classifier_requests_total`.
///
/// `transport` is `"tcp"`, `"admin_tcp"`, `"grpc"`, or `"http"`; `cmd` is
/// the command/RPC name. Both are normalized to the closed label
/// vocabularies below, so an unrecognized spelling lands on `unknown`
/// rather than opening the label space.
///
/// `OutcomeGuard::success` is the production caller: every listener
/// finalizes through the guard, which is what keeps this family and
/// `sbproxy_classifier_terminal_outcomes_total` counting the same
/// requests. It was `#[cfg(test)]` and inlined into the guard, which left
/// the writer the metric registry names existing only in test builds.
pub fn record_request(transport: &str, cmd: &str) {
    let normalized_transport = normalize_transport(transport);
    let normalized_command = normalize_command(cmd);
    if let Some(counter) = requests_total() {
        counter
            .with_label_values(&[normalized_transport, normalized_command])
            .inc();
    }
}

/// Record one failed request for `(transport, cmd, reason)`.
pub fn record_error(transport: &str, cmd: &str, reason: &str) {
    let normalized_transport = normalize_transport(transport);
    let normalized_command = normalize_command(cmd);
    let normalized_reason = normalize_reason(reason);
    if let Some(counter) = errors_total() {
        counter
            .with_label_values(&[normalized_transport, normalized_command, normalized_reason])
            .inc();
    }
}

/// Set the current tenant count (called after every register/delete).
pub fn set_tenant_count(count: usize) {
    if let Some(gauge) = tenants_gauge() {
        gauge.set(count as i64);
    }
}

/// Record a `Quality` score observation for `transport` (`"tcp"` or
/// `"grpc"`).
pub fn record_quality_score(transport: &str, score: f64) {
    if let Some(histogram) = quality_score_histogram() {
        histogram
            .with_label_values(&[normalize_transport(transport)])
            .observe(score);
    }
}

/// Record one streaming-safety verdict. `verdict` is `"safe"`, `"blocked"`,
/// or `"unsafe_continued"`.
pub fn record_safety_verdict(verdict: &str) {
    let verdict = match verdict {
        "safe" => "safe",
        "blocked" => "blocked",
        "unsafe_continued" => "unsafe_continued",
        _ => "unknown",
    };
    if let Some(counter) = safety_verdicts_total() {
        counter.with_label_values(&[verdict]).inc();
    }
}

#[cfg(test)]
pub(crate) fn safety_verdict_count(verdict: &str) -> u64 {
    safety_verdicts_total()
        .map(|counter| counter.with_label_values(&[verdict]).get())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn error_count(transport: &str, command: &str, reason: &str) -> u64 {
    errors_total()
        .map(|counter| {
            counter
                .with_label_values(&[transport, command, reason])
                .get()
        })
        .unwrap_or(0)
}

/// Record an admission refusal with closed command/reason labels.
pub fn record_admission_refusal(command: &str, reason: &str) {
    if let Some(counter) = admission_refusals_total() {
        counter
            .with_label_values(&[normalize_command(command), normalize_reason(reason)])
            .inc();
    }
}

/// Adjust the current queue depth for a closed command label.
pub fn adjust_admission_queue(command: &str, delta: i64) {
    if let Some(gauge) = admission_queue() {
        gauge
            .with_label_values(&[normalize_command(command)])
            .add(delta);
    }
}

#[cfg(test)]
pub(crate) struct OutcomeProbe {
    _guard: OwnedMutexGuard<()>,
}

#[cfg(test)]
impl OutcomeProbe {
    pub(crate) async fn acquire_unique() -> Self {
        let guard = OUTCOME_PROBE_LOCK
            .get_or_init(|| Arc::new(Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let _ = attempts_total();
        let _ = completions_total();
        let _ = terminal_outcomes_total();
        Self { _guard: guard }
    }

    pub(crate) fn snapshot(&self) -> OutcomeProbeSnapshot {
        OutcomeProbeSnapshot::capture()
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct OutcomeProbeSnapshot {
    attempts: BTreeMap<(Transport, Command), u64>,
    completions: BTreeMap<(Transport, Command), u64>,
    failures: BTreeMap<(Transport, Command, Stage, Reason), u64>,
}

#[cfg(test)]
impl OutcomeProbeSnapshot {
    fn capture() -> Self {
        let mut snapshot = Self::default();
        for family in prometheus::gather() {
            match family.name() {
                "sbproxy_classifier_attempts_total" => {
                    for metric in family.get_metric() {
                        let Some((transport, command)) = parse_transport_command_labels(metric)
                        else {
                            continue;
                        };
                        snapshot.attempts.insert(
                            (transport, command),
                            metric
                                .counter
                                .as_ref()
                                .map(|counter| counter.value())
                                .unwrap_or_default() as u64,
                        );
                    }
                }
                "sbproxy_classifier_completions_total" => {
                    for metric in family.get_metric() {
                        let Some((transport, command)) = parse_transport_command_labels(metric)
                        else {
                            continue;
                        };
                        snapshot.completions.insert(
                            (transport, command),
                            metric
                                .counter
                                .as_ref()
                                .map(|counter| counter.value())
                                .unwrap_or_default() as u64,
                        );
                    }
                }
                "sbproxy_classifier_terminal_outcomes_total" => {
                    for metric in family.get_metric() {
                        let Some((transport, command, stage, reason)) =
                            parse_failure_labels(metric)
                        else {
                            continue;
                        };
                        snapshot.failures.insert(
                            (transport, command, stage, reason),
                            metric
                                .counter
                                .as_ref()
                                .map(|counter| counter.value())
                                .unwrap_or_default() as u64,
                        );
                    }
                }
                _ => {}
            }
        }
        snapshot
    }

    fn attempt_delta(&self, after: &Self, transport: Transport, command: Command) -> u64 {
        after
            .attempts
            .get(&(transport, command))
            .copied()
            .unwrap_or(0)
            - self
                .attempts
                .get(&(transport, command))
                .copied()
                .unwrap_or(0)
    }

    fn completion_delta(&self, after: &Self, transport: Transport, command: Command) -> u64 {
        after
            .completions
            .get(&(transport, command))
            .copied()
            .unwrap_or(0)
            - self
                .completions
                .get(&(transport, command))
                .copied()
                .unwrap_or(0)
    }

    fn failure_delta(
        &self,
        after: &Self,
        transport: Transport,
        command: Command,
        stage: Stage,
        reason: Reason,
    ) -> u64 {
        after
            .failures
            .get(&(transport, command, stage, reason))
            .copied()
            .unwrap_or(0)
            - self
                .failures
                .get(&(transport, command, stage, reason))
                .copied()
                .unwrap_or(0)
    }

    fn assert_exact_terminal_multiset_delta_with_after(
        &self,
        after: &Self,
        expected: &[(OutcomeExpectation, u64)],
        case_name: &str,
    ) {
        let mut expected_attempts = BTreeMap::new();
        let mut expected_completions = BTreeMap::new();
        let mut expected_failures = BTreeMap::new();
        for (outcome, count) in expected {
            *expected_attempts
                .entry((outcome.transport, outcome.command))
                .or_insert(0) += *count;
            match (outcome.stage, outcome.reason) {
                (None, None) => {
                    *expected_completions
                        .entry((outcome.transport, outcome.command))
                        .or_insert(0) += *count;
                }
                (Some(stage), Some(reason)) => {
                    *expected_failures
                        .entry((outcome.transport, outcome.command, stage, reason))
                        .or_insert(0) += *count;
                }
                _ => panic!("invalid expected terminal shape for {case_name}: {outcome:?}"),
            }
        }

        let attempt_keys = self
            .attempts
            .keys()
            .chain(after.attempts.keys())
            .chain(expected_attempts.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for command_key in attempt_keys {
            let (transport, command) = command_key;
            let actual_attempts = self.attempt_delta(after, transport, command);
            let expected_attempts = expected_attempts.get(&command_key).copied().unwrap_or(0);
            assert_eq!(
                actual_attempts, expected_attempts,
                "unexpected attempt delta for {case_name}: {command_key:?}"
            );

            let actual_completions = self.completion_delta(after, transport, command);
            let expected_completions = expected_completions.get(&command_key).copied().unwrap_or(0);
            assert_eq!(
                actual_completions, expected_completions,
                "unexpected completion delta for {case_name}: {command_key:?}"
            );
        }

        let failure_keys = self
            .failures
            .keys()
            .chain(after.failures.keys())
            .chain(expected_failures.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for failure_key in failure_keys {
            let (transport, command, stage, reason) = failure_key;
            let actual = self.failure_delta(after, transport, command, stage, reason);
            let expected = expected_failures.get(&failure_key).copied().unwrap_or(0);
            assert_eq!(
                actual, expected,
                "unexpected failure delta for {case_name}: {failure_key:?}"
            );
        }
    }

    fn matches_exact_terminal_multiset_delta(
        &self,
        after: &Self,
        expected: &[(OutcomeExpectation, u64)],
    ) -> bool {
        let mut expected_attempts = BTreeMap::new();
        let mut expected_completions = BTreeMap::new();
        let mut expected_failures = BTreeMap::new();
        for (outcome, count) in expected {
            *expected_attempts
                .entry((outcome.transport, outcome.command))
                .or_insert(0) += *count;
            match (outcome.stage, outcome.reason) {
                (None, None) => {
                    *expected_completions
                        .entry((outcome.transport, outcome.command))
                        .or_insert(0) += *count;
                }
                (Some(stage), Some(reason)) => {
                    *expected_failures
                        .entry((outcome.transport, outcome.command, stage, reason))
                        .or_insert(0) += *count;
                }
                _ => return false,
            }
        }

        let attempt_keys = self
            .attempts
            .keys()
            .chain(after.attempts.keys())
            .chain(expected_attempts.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for command_key in attempt_keys {
            let (transport, command) = command_key;
            if self.attempt_delta(after, transport, command)
                != expected_attempts.get(&command_key).copied().unwrap_or(0)
            {
                return false;
            }
            if self.completion_delta(after, transport, command)
                != expected_completions.get(&command_key).copied().unwrap_or(0)
            {
                return false;
            }
        }

        let failure_keys = self
            .failures
            .keys()
            .chain(after.failures.keys())
            .chain(expected_failures.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for failure_key in failure_keys {
            let (transport, command, stage, reason) = failure_key;
            if self.failure_delta(after, transport, command, stage, reason)
                != expected_failures.get(&failure_key).copied().unwrap_or(0)
            {
                return false;
            }
        }

        true
    }

    pub(crate) fn assert_exact_terminal_delta(
        &self,
        expected: OutcomeExpectation,
        case_name: &str,
    ) {
        let after = Self::capture();
        self.assert_exact_terminal_multiset_delta_with_after(&after, &[(expected, 1)], case_name);
    }

    pub(crate) async fn wait_for_exact_terminal_delta(
        &self,
        expected: OutcomeExpectation,
        case_name: &str,
        timeout: std::time::Duration,
    ) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let after = Self::capture();
            let expected_once = [(expected, 1)];
            if self.matches_exact_terminal_multiset_delta(&after, &expected_once) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                self.assert_exact_terminal_multiset_delta_with_after(
                    &after,
                    &expected_once,
                    case_name,
                );
                unreachable!("terminal delta assertion panicked");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    pub(crate) fn assert_exact_terminal_multiset_delta(
        &self,
        expected: &[(OutcomeExpectation, u64)],
        case_name: &str,
    ) {
        let after = Self::capture();
        self.assert_exact_terminal_multiset_delta_with_after(&after, expected, case_name);
    }

    pub(crate) fn assert_no_terminal_delta(&self, case_name: &str) {
        self.assert_exact_terminal_multiset_delta(&[], case_name);
    }
}

#[cfg(test)]
fn parse_transport_command_labels(
    metric: &prometheus::proto::Metric,
) -> Option<(Transport, Command)> {
    let mut transport = None;
    let mut command = None;
    for label in metric.get_label() {
        match label.name() {
            "transport" => transport = parse_transport_label(label.value()),
            "cmd" => command = parse_command_label(label.value()),
            _ => {}
        }
    }
    Some((transport?, command?))
}

#[cfg(test)]
fn parse_failure_labels(
    metric: &prometheus::proto::Metric,
) -> Option<(Transport, Command, Stage, Reason)> {
    let mut transport = None;
    let mut command = None;
    let mut stage = None;
    let mut reason = None;
    for label in metric.get_label() {
        match label.name() {
            "transport" => transport = parse_transport_label(label.value()),
            "cmd" => command = parse_command_label(label.value()),
            "stage" => stage = parse_stage_label(label.value()),
            "reason" => reason = parse_reason_label(label.value()),
            _ => {}
        }
    }
    Some((transport?, command?, stage?, reason?))
}

#[cfg(test)]
fn parse_transport_label(value: &str) -> Option<Transport> {
    match value {
        "tcp" => Some(Transport::Tcp),
        "admin_tcp" => Some(Transport::AdminTcp),
        "grpc" => Some(Transport::Grpc),
        "http" => Some(Transport::Http),
        _ => None,
    }
}

#[cfg(test)]
fn parse_command_label(value: &str) -> Option<Command> {
    match value {
        "classify" => Some(Command::Classify),
        "embed" => Some(Command::Embed),
        "compress" => Some(Command::Compress),
        "model_info" => Some(Command::ModelInfo),
        "quality" => Some(Command::Quality),
        "quality_score" => Some(Command::QualityScore),
        "register" => Some(Command::Register),
        "delete" => Some(Command::Delete),
        "list" => Some(Command::List),
        "version" => Some(Command::Version),
        "intent_detect" => Some(Command::IntentDetect),
        "stream_safety" => Some(Command::StreamSafety),
        "streaming_safety" => Some(Command::StreamingSafety),
        "content_type_detect" => Some(Command::ContentTypeDetect),
        "decode" => Some(Command::Decode),
        "tenants" => Some(Command::Tenants),
        "healthz" => Some(Command::Healthz),
        "readyz" => Some(Command::Readyz),
        "metrics" => Some(Command::Metrics),
        "unknown" => Some(Command::Unknown),
        _ => None,
    }
}

#[cfg(test)]
fn parse_stage_label(value: &str) -> Option<Stage> {
    match value {
        "admission" => Some(Stage::Admission),
        "authorize" => Some(Stage::Authorize),
        "cancellation" => Some(Stage::Cancellation),
        "decode" => Some(Stage::Decode),
        "encode" => Some(Stage::Encode),
        "handler" => Some(Stage::Handler),
        "limit" => Some(Stage::Limit),
        "model" => Some(Stage::Model),
        "read" => Some(Stage::Read),
        "route" => Some(Stage::Route),
        "worker" => Some(Stage::Worker),
        "write" => Some(Stage::Write),
        _ => None,
    }
}

#[cfg(test)]
fn parse_reason_label(value: &str) -> Option<Reason> {
    match value {
        "cancelled" => Some(Reason::Cancelled),
        "deadline" => Some(Reason::Deadline),
        "forbidden" => Some(Reason::Forbidden),
        "inference_failed" => Some(Reason::InferenceFailed),
        "internal" => Some(Reason::Internal),
        "invalid_config" => Some(Reason::InvalidConfig),
        "io" => Some(Reason::Io),
        "malformed_frame" => Some(Reason::MalformedFrame),
        "missing_field" => Some(Reason::MissingField),
        "model_not_found" => Some(Reason::ModelNotFound),
        "not_found" => Some(Reason::NotFound),
        "queue_full" => Some(Reason::QueueFull),
        "resource_limit" => Some(Reason::ResourceLimit),
        "tenant_not_found" => Some(Reason::TenantNotFound),
        "unauthorized" => Some(Reason::Unauthorized),
        "unavailable" => Some(Reason::Unavailable),
        "unimplemented" => Some(Reason::Unimplemented),
        "unknown_command" => Some(Reason::UnknownCommand),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_commands_collapse_to_one_unknown_label() {
        for index in 0..10_000 {
            assert_eq!(normalize_command(&format!("attacker-{index}")), "unknown");
        }
        assert_eq!(normalize_command("classify"), "classify");
        assert_eq!(normalize_command(""), "classify");
    }

    #[test]
    fn recording_a_request_increments_the_counter() {
        record_request("tcp", "classify_test_marker");
        let value = requests_total()
            .map(|counter| counter.with_label_values(&["tcp", "unknown"]).get())
            .unwrap_or(0);
        assert!(value >= 1);
    }

    #[test]
    fn tenant_gauge_reflects_the_last_set_value() {
        set_tenant_count(3);
        assert_eq!(tenants_gauge().map(IntGauge::get).unwrap_or(0), 3);
        set_tenant_count(0);
        assert_eq!(tenants_gauge().map(IntGauge::get).unwrap_or(0), 0);
    }

    #[test]
    fn safety_verdict_counters_are_independent_per_label() {
        record_safety_verdict("safe");
        record_safety_verdict("blocked");
        record_safety_verdict("unsafe_continued");
        assert!(
            safety_verdicts_total()
                .map(|counter| counter.with_label_values(&["safe"]).get())
                .unwrap_or(0)
                >= 1
        );
        assert!(
            safety_verdicts_total()
                .map(|counter| counter.with_label_values(&["blocked"]).get())
                .unwrap_or(0)
                >= 1
        );
        assert!(
            safety_verdicts_total()
                .map(|counter| counter.with_label_values(&["unsafe_continued"]).get())
                .unwrap_or(0)
                >= 1
        );
    }
}
