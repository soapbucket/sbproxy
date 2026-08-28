// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The soak window a newly applied config revision must survive before
//! it is promoted to last known good (WOR-2458).
//!
//! # The defect this fixes
//!
//! Before this module existed, a config was promoted the moment it
//! applied. `ConfigSubscriber::apply` logs at ERROR that a reload came
//! up degraded and persists that same bundle as the boot config twenty
//! lines later, and the reload transaction records every applied
//! revision into the ring the same way. Compiling is not evidence that a
//! config works: a dead upstream URL, a rate limit of 10 that should
//! have been 10000, an auth block that rejects the caller carrying most
//! of the traffic, and a WAF rule that matches everything all compile
//! cleanly. So a committed reload arms a window here, four signals
//! report into it, and only a window that closes on a passing verdict
//! moves the last-known-good pointer.
//!
//! # The four signals
//!
//! | Signal | Source | Catches |
//! | -- | -- | -- |
//! | [`SoakSignal::DegradedSubsystems`] | [`crate::server::ReloadOutcome::degraded`] | A pipeline that published while the key plane, a sink, or the model runtime stayed on prior state. Immediate, no traffic needed. |
//! | [`SoakSignal::UpstreamHealth`] | The live pipeline's circuit breakers | A config that repointed an origin at a dead address, on a node with almost no traffic. |
//! | [`SoakSignal::RequestOutcome`] | `sbproxy_requests_total` by status class, plus the upstream retry and timeout counters | A policy that denies everything, an auth block that rejects every caller, a transform that corrupts bodies. |
//! | [`SoakSignal::OperatorProbe`] | `proxy.config_history.soak.probe`, and the synthetic-transaction driver when it is on | Whatever the operator knows and this proxy does not. |
//!
//! # The verdict is three-way, not two
//!
//! Argo Rollouts has the state this needs: an AnalysisRun completes
//! `Successful`, `Failed`, or **`Inconclusive`**, and `Inconclusive`
//! pauses the rollout rather than promoting or aborting it. A node that
//! took four requests overnight and 500'd one of them has a 25% error
//! rate and no information, so the request-outcome signal **abstains**
//! below `min_requests` rather than reporting a failure.
//!
//! | Signals | Verdict | Effect on the pointer |
//! | -- | -- | -- |
//! | Any non-abstaining failure | [`SoakVerdict::Failed`] | Does not move |
//! | At least one non-abstaining pass, no failures | [`SoakVerdict::Successful`] | Advances |
//! | Every signal abstained | [`SoakVerdict::Inconclusive`] | Does not move; the entry stays `applied` |
//!
//! One abstaining signal never fails a soak and never blocks a
//! promotion. Every signal abstaining is different, and promoting on it
//! would be promote-on-apply wearing a timer.
//!
//! # Low traffic is the common cause of a spurious rollback
//!
//! Flagger's field experience is the warning: a canary that receives no
//! traffic fails its metric check with "no values found for metric
//! request-success-rate" and eventually rolls back, and insufficient
//! traffic is documented as the single most common cause of spurious
//! Flagger rollbacks. Flagger's answer is a companion load tester that
//! generates traffic during analysis. This proxy already ships one:
//! [`crate::synthetic`] fires an in-process request through the compiled
//! handler chain on a fixed cadence. The operator-probe signal reads its
//! outcome rather than introducing a second probe shape.
//!
//! Be precise about what a passing synthetic run proves. The synthetic
//! origin is required to be a non-network action, so a pass proves the
//! compiled chain executes and proves **nothing** about whether any
//! upstream is reachable. That is why it sits alongside the upstream
//! health signal instead of replacing it, and why an operator who wants
//! a real upstream exercised still declares
//! `proxy.config_history.soak.probe`.
//!
//! # Confirming early
//!
//! `POST /admin/config/confirm` short-circuits the window and promotes
//! immediately. That is the Junos `commit confirmed` ergonomic, and it
//! is what a deployment pipeline calls after its own smoke test instead
//! of sleeping for two minutes.
//!
//! # Nothing here reverts
//!
//! A failed soak records its verdict and leaves the pointer alone. It
//! does not roll the node back; auto-revert is its own change.

use std::sync::{Mutex, OnceLock};

use sbproxy_config::{ConfigSoakConfig, ConfigSoakProbeConfig, SoakVerdict};

/// One signal's report into a soak window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalOutcome {
    /// The signal measured something and it was fine.
    Pass,
    /// The signal measured something and it was not fine. Carries what
    /// it saw, which reaches the log, the decision event, and the admin
    /// surface.
    Fail(String),
    /// The signal had too little information to say anything. Carries
    /// why, because "the soak is not measuring anything" is itself worth
    /// surfacing.
    Abstain(String),
}

impl SignalOutcome {
    /// Stable metric label for this outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "passed",
            Self::Fail(_) => "failed",
            Self::Abstain(_) => "abstain",
        }
    }

    /// The explanation, when there is one.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Pass => None,
            Self::Fail(detail) | Self::Abstain(detail) => Some(detail),
        }
    }
}

/// Which of the four signals reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoakSignal {
    /// Subsystems that stayed on prior state while the pipeline
    /// published.
    DegradedSubsystems,
    /// Upstream reachability, as the live pipeline's circuit breakers
    /// see it.
    UpstreamHealth,
    /// The request-outcome delta against the instant the window armed.
    RequestOutcome,
    /// The operator's declared probe, and the synthetic-transaction
    /// driver when it is running.
    OperatorProbe,
}

impl SoakSignal {
    /// Stable metric label. Never changes for a given variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DegradedSubsystems => "degraded_subsystems",
            Self::UpstreamHealth => "upstream_health",
            Self::RequestOutcome => "request_outcome",
            Self::OperatorProbe => "operator_probe",
        }
    }
}

/// Monotonic request counters, sampled from the metric registry.
///
/// `errors` counts every request that finished at `400` or above, not
/// just `5xx`: an auth block that rejects the caller carrying most of
/// the traffic answers `401`, and a soak that only watched `5xx` would
/// call that a healthy config. The upstream status-retry and
/// timeout-retry counters are folded in for the same reason, so a
/// config that repointed an origin somewhere slow shows up here even
/// while the retries are still succeeding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestCounts {
    /// Requests completed since process start.
    pub requests: u64,
    /// Requests that finished at `400` or above, plus upstream status
    /// and timeout retries.
    pub errors: u64,
}

impl RequestCounts {
    /// Difference between a later sample and an earlier one, saturating
    /// at zero so a counter reset cannot produce a negative rate.
    #[must_use]
    pub fn since(self, baseline: Self) -> Self {
        Self {
            requests: self.requests.saturating_sub(baseline.requests),
            errors: self.errors.saturating_sub(baseline.errors),
        }
    }

    /// Error rate over this window, or `None` when it observed nothing.
    #[must_use]
    pub fn error_rate(self) -> Option<f64> {
        if self.requests == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some(self.errors as f64 / self.requests as f64)
    }
}

/// Sample the request counters from the process metric registry.
///
/// Reads the families by name rather than holding handles to them: the
/// counters are registered lazily by whichever code path increments them
/// first, so a node that has served no traffic yet has no family to hold
/// a handle to, and the absence is a zero rather than an error.
#[must_use]
pub fn observe_request_counts() -> RequestCounts {
    let mut counts = RequestCounts::default();
    for family in prometheus::gather() {
        let name = family.name();
        let is_requests = name == "sbproxy_requests_total";
        let is_retry = name == "sbproxy_upstream_status_retries_total"
            || name == "sbproxy_upstream_timeout_retries_total";
        if !is_requests && !is_retry {
            continue;
        }
        for metric in family.get_metric() {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let value = metric.get_counter().value().max(0.0) as u64;
            if is_retry {
                counts.errors = counts.errors.saturating_add(value);
                continue;
            }
            counts.requests = counts.requests.saturating_add(value);
            let failed = metric
                .get_label()
                .iter()
                .find(|pair| pair.name() == "status")
                .and_then(|pair| pair.value().parse::<u16>().ok())
                .is_some_and(|status| status >= 400);
            if failed {
                counts.errors = counts.errors.saturating_add(value);
            }
        }
    }
    counts
}

/// The degraded-subsystem signal.
///
/// A **veto**, not a promoter: it can fail a soak and it can never pass
/// one. A reload that published with every subsystem intact has proved
/// that it compiled and constructed, and "compiling is not evidence that
/// a config works" is the sentence this whole module exists to enforce.
/// So a clean reload abstains here, and something that actually observed
/// traffic, an upstream, or a probe has to be what promotes it.
///
/// The failing case reports immediately and needs no traffic, which is
/// why an armed window whose reload came up degraded never waits: the
/// evidence is already in hand.
#[must_use]
pub fn degraded_signal(degraded: &[String], require_none: bool) -> SignalOutcome {
    if !require_none {
        return SignalOutcome::Abstain(
            "require_no_degraded_subsystems is off for this node".to_string(),
        );
    }
    if degraded.is_empty() {
        return SignalOutcome::Abstain(
            "no subsystem stayed on prior state, which is not by itself evidence that this              config works"
                .to_string(),
        );
    }
    SignalOutcome::Fail(format!(
        "the reload published with {} subsystem(s) on prior state: {}",
        degraded.len(),
        degraded.join(", ")
    ))
}

/// The upstream-health signal, from the states the caller sampled off
/// the live pipeline's circuit breakers.
///
/// Abstains when the running config declares no breakers at all: there
/// is nothing to observe, and reporting a pass would let a node with no
/// upstream instrumentation promote on the strength of a signal that
/// measured nothing.
#[must_use]
pub fn upstream_health_signal(
    open_breakers: &[String],
    observed: usize,
    require: bool,
) -> SignalOutcome {
    if !require {
        return SignalOutcome::Abstain("require_upstream_health is off for this node".to_string());
    }
    if observed == 0 {
        return SignalOutcome::Abstain(
            "the running config declares no circuit breakers to observe".to_string(),
        );
    }
    if open_breakers.is_empty() {
        return SignalOutcome::Pass;
    }
    SignalOutcome::Fail(format!(
        "{} of {observed} upstream circuit breaker(s) are open or half-open: {}",
        open_breakers.len(),
        open_breakers.join(", ")
    ))
}

/// The request-outcome signal.
///
/// Three-way on purpose. Below `min_requests` this **abstains**: a
/// window that saw four requests and one failure has a 25% error rate
/// and no information, and treating that as a failure is the single most
/// common cause of a spurious rollback in the systems that got this
/// wrong before us.
#[must_use]
pub fn request_outcome_signal(
    baseline: RequestCounts,
    current: RequestCounts,
    min_requests: u64,
    max_error_rate_delta: f64,
    baseline_error_rate: Option<f64>,
) -> SignalOutcome {
    let window = current.since(baseline);
    if window.requests < min_requests {
        return SignalOutcome::Abstain(format!(
            "the window observed {} request(s), under the min_requests of {min_requests}",
            window.requests
        ));
    }
    let Some(rate) = window.error_rate() else {
        return SignalOutcome::Abstain("the window observed no requests".to_string());
    };
    // Compared against the rate this node was already running at, not
    // against zero: a node whose steady state is 2% 404s from a scanner
    // has not got worse because the new config kept doing that.
    let previous = baseline_error_rate.unwrap_or(0.0);
    if rate - previous > max_error_rate_delta {
        return SignalOutcome::Fail(format!(
            "the error rate rose from {:.1}% to {:.1}% over {} request(s), past the \
             max_error_rate_delta of {:.1}%",
            previous * 100.0,
            rate * 100.0,
            window.requests,
            max_error_rate_delta * 100.0
        ));
    }
    SignalOutcome::Pass
}

/// What one probe tick observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeObservation {
    /// The probe ran and got what it expected.
    Ok,
    /// The probe ran and got something else. Carries what.
    Unexpected(String),
    /// The probe could not be reached or ran out of time. Distinct from
    /// [`Self::Unexpected`] because "your probe URL is wrong" and "the
    /// thing your probe watches is down" send an operator to different
    /// places.
    Unreachable(String),
}

/// The operator-probe signal.
///
/// A probe that timed out or could not be reached **fails** the soak
/// rather than abstaining, and says which. An abstention there would
/// mean a probe an operator deliberately configured could go silently
/// missing and still let a bad config be promoted, which is the opposite
/// of why they configured it.
///
/// Absent both a declared probe and a running synthetic driver, this
/// abstains: there is nothing to observe.
#[must_use]
pub fn probe_signal(observation: Option<&ProbeObservation>) -> SignalOutcome {
    match observation {
        None => SignalOutcome::Abstain(
            "no operator probe is declared and no synthetic driver is running".to_string(),
        ),
        Some(ProbeObservation::Ok) => SignalOutcome::Pass,
        Some(ProbeObservation::Unexpected(detail)) => {
            SignalOutcome::Fail(format!("the probe answered unexpectedly: {detail}"))
        }
        Some(ProbeObservation::Unreachable(detail)) => SignalOutcome::Fail(format!(
            "the probe timed out or could not be reached: {detail}"
        )),
    }
}

/// Fold every signal's report into one verdict.
///
/// The whole promotion rule, in eight lines, kept pure so it can be
/// tested without a proxy:
///
/// * any non-abstaining failure wins outright, whatever else passed;
/// * otherwise a single non-abstaining pass is enough to promote;
/// * an empty report set, or one where every signal abstained, is
///   [`SoakVerdict::Inconclusive`].
#[must_use]
pub fn aggregate(reports: &[(SoakSignal, SignalOutcome)]) -> SoakVerdict {
    if reports
        .iter()
        .any(|(_, outcome)| matches!(outcome, SignalOutcome::Fail(_)))
    {
        return SoakVerdict::Failed;
    }
    if reports
        .iter()
        .any(|(_, outcome)| matches!(outcome, SignalOutcome::Pass))
    {
        return SoakVerdict::Successful;
    }
    SoakVerdict::Inconclusive
}

/// Stable metric label for a verdict.
#[must_use]
pub const fn verdict_label(verdict: SoakVerdict) -> &'static str {
    match verdict {
        SoakVerdict::Successful => "passed",
        SoakVerdict::Failed => "failed",
        SoakVerdict::Inconclusive => "inconclusive",
    }
}

/// One soak window in flight.
#[derive(Debug, Clone)]
pub struct SoakWindow {
    /// Ring revision this window is judging.
    pub revision: u64,
    /// Content digest of that revision, carried so a log line and a
    /// decision event can name it without another ring read.
    pub digest: String,
    /// Unix milliseconds the window closes at.
    pub closes_at_ms: u64,
    /// Request counters at the instant the window armed.
    pub baseline: RequestCounts,
    /// Error rate this node was running at before the window armed,
    /// when it was running enough traffic to have one.
    pub baseline_error_rate: Option<f64>,
    /// Subsystems the reload published without.
    pub degraded: Vec<String>,
    /// The soak block in force for this window.
    pub config: ConfigSoakConfig,
    /// The most recent probe tick's observation, when a probe has run.
    pub probe: Option<ProbeObservation>,
}

/// The process-wide slot holding the window in flight, if any.
static IN_FLIGHT: OnceLock<Mutex<Option<SoakWindow>>> = OnceLock::new();

fn in_flight() -> &'static Mutex<Option<SoakWindow>> {
    IN_FLIGHT.get_or_init(|| Mutex::new(None))
}

/// Host wall clock in unix milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Arm a soak window for a revision that has just applied.
///
/// Returns the verdict when one is reached immediately, which happens
/// for exactly two reasons: the reload came up degraded (the evidence is
/// already in hand and no traffic is needed to confirm it), or the soak
/// is switched off for this node (in which case the revision is promoted
/// on apply, deliberately, because that is what the operator asked for).
///
/// A window already in flight is **superseded**: it is dropped without a
/// verdict, so it can never later promote a revision that is no longer
/// running. The superseded revision's entry stays `applied`, which is
/// the honest record of what happened to it.
pub fn arm(
    revision: u64,
    digest: &str,
    degraded: &[String],
    config: &ConfigSoakConfig,
) -> Option<SoakVerdict> {
    if !config.enabled {
        // Promote on apply, because the operator turned the soak off.
        // Loudly enough that it is not a surprise, once per reload.
        tracing::warn!(
            revision,
            "proxy.config_history.soak is disabled: this revision is promoted to last known \
             good on apply, without being judged against traffic",
        );
        return Some(SoakVerdict::Successful);
    }

    let mut slot = in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(previous) = slot.take() {
        sbproxy_observe::metrics::record_config_soak_verdict("superseded", "window");
        tracing::info!(
            superseded_revision = previous.revision,
            revision,
            "a newer config revision applied mid-soak; the superseded window is dropped \
             without a verdict rather than promoting a revision that is no longer running",
        );
    }

    // Reported before the window is stored, so a degraded reload fails
    // now rather than after `window_secs`.
    let degraded_outcome = degraded_signal(degraded, config.require_no_degraded_subsystems);
    record_signal(SoakSignal::DegradedSubsystems, &degraded_outcome);
    if let SignalOutcome::Fail(detail) = &degraded_outcome {
        tracing::error!(
            revision,
            detail = %detail,
            "the applied config revision failed its soak immediately; the last-known-good \
             pointer does not move",
        );
        return Some(SoakVerdict::Failed);
    }

    let baseline = observe_request_counts();
    *slot = Some(SoakWindow {
        revision,
        digest: digest.to_string(),
        closes_at_ms: now_ms().saturating_add(config.window_secs.saturating_mul(1_000)),
        baseline,
        baseline_error_rate: baseline.error_rate(),
        degraded: degraded.to_vec(),
        config: config.clone(),
        probe: None,
    });
    None
}

/// The revision the window in flight is judging, if any.
#[must_use]
pub fn in_flight_revision() -> Option<u64> {
    in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(|window| window.revision)
}

/// Drop the window in flight without reaching a verdict. Used by tests
/// and by the boot fallback, which must not inherit a window armed by
/// the configuration it just replaced.
pub fn clear() {
    *in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// Record the most recent probe observation against the window in
/// flight. A no-op when no window is armed.
pub fn record_probe(observation: ProbeObservation) {
    if let Some(window) = in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        window.probe = Some(observation);
    }
}

/// Judge one window against the signals available right now.
///
/// Split from [`close_due`] so a test can drive the decision with
/// sampled inputs rather than a live pipeline, and so the aggregate and
/// per-signal metrics are emitted in exactly one place.
#[must_use]
pub fn judge(
    window: &SoakWindow,
    current: RequestCounts,
    open_breakers: &[String],
    observed_breakers: usize,
) -> (SoakVerdict, Vec<(SoakSignal, SignalOutcome)>) {
    let reports = vec![
        (
            SoakSignal::DegradedSubsystems,
            degraded_signal(
                &window.degraded,
                window.config.require_no_degraded_subsystems,
            ),
        ),
        (
            SoakSignal::UpstreamHealth,
            upstream_health_signal(
                open_breakers,
                observed_breakers,
                window.config.require_upstream_health,
            ),
        ),
        (
            SoakSignal::RequestOutcome,
            request_outcome_signal(
                window.baseline,
                current,
                window.config.min_requests,
                window.config.max_error_rate_delta,
                window.baseline_error_rate,
            ),
        ),
        (
            SoakSignal::OperatorProbe,
            probe_signal(window.probe.as_ref()),
        ),
    ];
    (aggregate(&reports), reports)
}

/// Count one signal's report.
fn record_signal(signal: SoakSignal, outcome: &SignalOutcome) {
    sbproxy_observe::metrics::record_config_soak_verdict(outcome.as_str(), signal.as_str());
}

/// Close the window in flight if it is due, returning the revision and
/// the verdict it reached.
///
/// `None` when no window is armed or the window has not closed yet.
pub fn close_due() -> Option<(u64, SoakVerdict, Vec<(SoakSignal, SignalOutcome)>)> {
    let window = {
        let mut slot = in_flight()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let due = slot
            .as_ref()
            .is_some_and(|window| now_ms() >= window.closes_at_ms);
        if !due {
            return None;
        }
        slot.take()?
    };
    Some(finish(&window))
}

/// Close the window in flight immediately, whatever its deadline says:
/// the `POST /admin/config/confirm` path.
///
/// `None` when no window is in flight, which is what makes that route
/// answer `409` rather than pretending to promote something.
pub fn confirm_now() -> Option<(u64, SoakVerdict, Vec<(SoakSignal, SignalOutcome)>)> {
    let window = in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()?;
    tracing::info!(
        revision = window.revision,
        "an operator confirmed the config revision before its soak window closed",
    );
    Some(finish(&window))
}

/// Judge `window` against the live signals, record the verdict onto the
/// ring and the metrics, and publish the decision event.
fn finish(window: &SoakWindow) -> (u64, SoakVerdict, Vec<(SoakSignal, SignalOutcome)>) {
    let (open_breakers, observed_breakers) = sample_circuit_breakers();
    let (verdict, reports) = judge(
        window,
        observe_request_counts(),
        &open_breakers,
        observed_breakers,
    );
    for (signal, outcome) in &reports {
        record_signal(*signal, outcome);
    }
    sbproxy_observe::metrics::record_config_soak_verdict(verdict_label(verdict), "window");
    if let Some(recorder) = crate::config_history::current_config_history_recorder() {
        recorder.record_soak_verdict(window.revision, verdict);
    }
    publish_soak_event(window, verdict, &reports);
    match verdict {
        SoakVerdict::Successful => tracing::info!(
            revision = window.revision,
            digest = %window.digest,
            "config revision survived its soak window and is now this node's last known good",
        ),
        SoakVerdict::Failed => tracing::error!(
            revision = window.revision,
            digest = %window.digest,
            detail = %first_failure(&reports).unwrap_or_default(),
            "config revision failed its soak window; the last-known-good pointer does not move",
        ),
        SoakVerdict::Inconclusive => tracing::warn!(
            revision = window.revision,
            digest = %window.digest,
            "every soak signal abstained, so this window measured nothing: the revision is \
             neither promoted nor failed. enable the synthetic probe driver or declare a \
             soak probe on a node this quiet",
        ),
    }
    (window.revision, verdict, reports)
}

/// The first failing signal's detail, for the log line and the event.
fn first_failure(reports: &[(SoakSignal, SignalOutcome)]) -> Option<String> {
    reports.iter().find_map(|(signal, outcome)| match outcome {
        SignalOutcome::Fail(detail) => Some(format!("{}: {detail}", signal.as_str())),
        _ => None,
    })
}

/// Publish the soak verdict onto the configured event sink.
///
/// Reuses [`sbproxy_observe::EventType::ConfigSoakVerdict`] rather than
/// introducing a sink of its own, so an operator who already routes
/// `config_reloaded` somewhere gets this in the same place. The payload
/// is the revision, the digest, the verdict, and one row per signal with
/// its outcome and explanation: bounded metadata, never a config value
/// and never a secret.
fn publish_soak_event(
    window: &SoakWindow,
    verdict: SoakVerdict,
    reports: &[(SoakSignal, SignalOutcome)],
) {
    sbproxy_observe::publish_proxy_event(sbproxy_observe::EventType::ConfigSoakVerdict, || {
        soak_event(window, verdict, reports)
    });
}

/// Build the soak-verdict event.
///
/// Split from [`publish_soak_event`] so the payload's shape is testable
/// without installing a process-wide sink, which is set-once and so
/// cannot be staged per test.
#[must_use]
pub fn soak_event(
    window: &SoakWindow,
    verdict: SoakVerdict,
    reports: &[(SoakSignal, SignalOutcome)],
) -> sbproxy_observe::ProxyEvent {
    let signals: Vec<serde_json::Value> = reports
        .iter()
        .map(|(signal, outcome)| {
            serde_json::json!({
                "signal": signal.as_str(),
                "outcome": outcome.as_str(),
                "detail": outcome.detail().unwrap_or_default(),
            })
        })
        .collect();
    sbproxy_observe::ProxyEvent::new(
        sbproxy_observe::EventType::ConfigSoakVerdict,
        String::new(),
        String::new(),
        serde_json::json!({
            "revision": window.revision,
            "digest": window.digest,
            "verdict": verdict_label(verdict),
            "signals": signals,
        }),
    )
}

/// Circuit breakers on the running pipeline: the identifiers of the ones
/// that are not closed, and how many exist at all.
///
/// The identifier is the origin's `workspace/origin#target-N`, the same
/// bounded shape the alert engine already uses for a breaker reading, so
/// nothing here puts a target URL into a log line.
fn sample_circuit_breakers() -> (Vec<String>, usize) {
    let pipeline = crate::reload::current_pipeline();
    let mut open = Vec::new();
    let mut observed = 0usize;
    for (index, action) in pipeline.actions.iter().enumerate() {
        let sbproxy_modules::Action::LoadBalancer(load_balancer) = action else {
            continue;
        };
        let Some(breakers) = load_balancer.circuit_breakers.as_ref() else {
            continue;
        };
        let identity = pipeline.config.origins.get(index).map_or_else(
            || format!("action-{index}"),
            |origin| format!("{}/{}", origin.workspace_id, origin.origin_id),
        );
        for (target, breaker) in breakers.iter().enumerate() {
            observed += 1;
            if !matches!(breaker.state(), sbproxy_platform::CircuitState::Closed) {
                open.push(format!("{identity}#target-{target}"));
            }
        }
    }
    (open, observed)
}

/// Run the operator probe once, and record what it saw against the
/// window in flight.
///
/// Failure modes are kept apart on purpose: a connect error or a timeout
/// is [`ProbeObservation::Unreachable`], an answer with the wrong status
/// is [`ProbeObservation::Unexpected`], and both fail the soak while
/// sending an operator to different places.
async fn run_operator_probe(probe: &ConfigSoakProbeConfig, client: &reqwest::Client) {
    let observation = match client
        .get(&probe.url)
        .timeout(std::time::Duration::from_millis(probe.timeout_ms))
        .send()
        .await
    {
        Ok(response) if response.status().as_u16() == probe.expect_status => ProbeObservation::Ok,
        Ok(response) => ProbeObservation::Unexpected(format!(
            "expected {} and got {}",
            probe.expect_status,
            response.status().as_u16()
        )),
        Err(error) if error.is_timeout() => {
            ProbeObservation::Unreachable(format!("no answer within {}ms", probe.timeout_ms))
        }
        Err(error) => ProbeObservation::Unreachable(format!("{error}")),
    };
    record_probe(observation);
}

/// Read the running synthetic-transaction driver's most recent outcome,
/// when one is installed.
///
/// This is the Flagger lesson applied: on a node with no organic traffic
/// the request-outcome signal abstains, and without something else
/// reporting the window would be `Inconclusive` forever. The synthetic
/// driver is that something else, and it is a driver this proxy already
/// ships rather than a second probe shape invented here.
fn synthetic_observation() -> Option<ProbeObservation> {
    let (status, detail) = crate::synthetic::current_process_probe_outcome()?;
    Some(match status {
        sbproxy_observe::ComponentStatus::Healthy => ProbeObservation::Ok,
        _ => ProbeObservation::Unexpected(format!(
            "the synthetic transaction driver reports {}",
            detail.unwrap_or_else(|| "unhealthy".to_string())
        )),
    })
}

/// Start the soak supervisor: one task that ticks the window in flight,
/// runs the operator probe on its cadence, and closes the window when it
/// is due.
///
/// A no-op when no window is ever armed, which is every node that has
/// not enabled `proxy.config_history`.
pub fn spawn() {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(
                error = %error,
                "config soak: could not build the probe HTTP client; the operator-probe \
                 signal will abstain for the life of this process",
            );
            return;
        }
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_probe_ms: u64 = 0;
        loop {
            ticker.tick().await;
            let armed = {
                let slot = in_flight()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                slot.as_ref()
                    .map(|window| (window.config.probe.clone(), window.config.enabled))
            };
            let Some((probe, _)) = armed else {
                continue;
            };
            // The synthetic driver's outcome first: it needs no I/O of
            // our own, and an operator who declared both gets the
            // explicit probe's answer on top.
            if let Some(observation) = synthetic_observation() {
                record_probe(observation);
            }
            if let Some(probe) = probe {
                let due = now_ms().saturating_sub(last_probe_ms)
                    >= probe.interval_secs.saturating_mul(1_000);
                if due {
                    last_probe_ms = now_ms();
                    run_operator_probe(&probe, &client).await;
                }
            }
            let _ = close_due();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soak(min_requests: u64) -> ConfigSoakConfig {
        ConfigSoakConfig {
            min_requests,
            window_secs: 1,
            ..ConfigSoakConfig::default()
        }
    }

    fn window(config: ConfigSoakConfig, degraded: Vec<String>) -> SoakWindow {
        SoakWindow {
            revision: 7,
            digest: "abc123".to_string(),
            closes_at_ms: 0,
            baseline: RequestCounts::default(),
            baseline_error_rate: None,
            degraded,
            config,
            probe: None,
        }
    }

    /// A reload that reports any degraded subsystem fails immediately,
    /// without waiting the window out.
    #[test]
    fn a_degraded_reload_fails_its_soak_at_arm_time() {
        clear();
        let verdict = arm(7, "abc123", &["key_plane".to_string()], &soak(50));
        assert_eq!(verdict, Some(SoakVerdict::Failed));
        assert_eq!(
            in_flight_revision(),
            None,
            "a window that already failed must not sit armed waiting to be closed",
        );
        clear();
    }

    /// A clean reload arms a window and reaches no verdict yet.
    #[test]
    fn a_clean_reload_arms_a_window_without_a_verdict() {
        clear();
        let verdict = arm(8, "def456", &[], &soak(50));
        assert_eq!(verdict, None);
        assert_eq!(in_flight_revision(), Some(8));
        clear();
    }

    /// A second reload mid-soak supersedes the first. The superseded
    /// window must not later promote a revision that is no longer
    /// running.
    #[test]
    fn a_second_reload_supersedes_the_window_in_flight() {
        clear();
        assert_eq!(arm(1, "one", &[], &soak(50)), None);
        assert_eq!(arm(2, "two", &[], &soak(50)), None);
        assert_eq!(
            in_flight_revision(),
            Some(2),
            "only the newest revision is under judgement",
        );
        clear();
    }

    /// Below `min_requests` the request-outcome signal abstains rather
    /// than reporting a failure on four requests and one 500.
    #[test]
    fn the_request_outcome_signal_abstains_below_min_requests() {
        let outcome = request_outcome_signal(
            RequestCounts::default(),
            RequestCounts {
                requests: 4,
                errors: 1,
            },
            50,
            0.05,
            None,
        );
        assert!(
            matches!(outcome, SignalOutcome::Abstain(_)),
            "a 25% error rate over four requests is no information: {outcome:?}",
        );
        assert!(outcome
            .detail()
            .expect("an abstention explains itself")
            .contains("min_requests"));
    }

    /// One abstaining signal never blocks a promotion: a soak with a
    /// passing signal and an abstaining one passes.
    #[test]
    fn an_abstaining_signal_does_not_block_a_promotion() {
        let verdict = aggregate(&[
            (SoakSignal::UpstreamHealth, SignalOutcome::Pass),
            (
                SoakSignal::RequestOutcome,
                SignalOutcome::Abstain("too few requests".to_string()),
            ),
        ]);
        assert_eq!(verdict, SoakVerdict::Successful);
    }

    /// Abstention does not rescue a real failure.
    #[test]
    fn an_abstaining_signal_does_not_rescue_a_failing_one() {
        let verdict = aggregate(&[
            (
                SoakSignal::RequestOutcome,
                SignalOutcome::Abstain("too few requests".to_string()),
            ),
            (
                SoakSignal::UpstreamHealth,
                SignalOutcome::Fail("a breaker is open".to_string()),
            ),
        ]);
        assert_eq!(verdict, SoakVerdict::Failed);
    }

    /// Every signal abstaining is Inconclusive, not a pass. Promoting on
    /// a soak that measured nothing is the defect wearing a timer.
    #[test]
    fn every_signal_abstaining_is_inconclusive() {
        let verdict = aggregate(&[
            (
                SoakSignal::DegradedSubsystems,
                SignalOutcome::Abstain("off".to_string()),
            ),
            (
                SoakSignal::UpstreamHealth,
                SignalOutcome::Abstain("no breakers".to_string()),
            ),
            (
                SoakSignal::RequestOutcome,
                SignalOutcome::Abstain("too few requests".to_string()),
            ),
            (
                SoakSignal::OperatorProbe,
                SignalOutcome::Abstain("no probe".to_string()),
            ),
        ]);
        assert_eq!(verdict, SoakVerdict::Inconclusive);
        assert_eq!(verdict_label(verdict), "inconclusive");
    }

    /// A clean reload is not evidence: the degraded signal vetoes, it
    /// never promotes. Without this, `require_no_degraded_subsystems`
    /// would make every reload that constructed cleanly pass its soak,
    /// which is promote-on-apply with two extra minutes attached.
    #[test]
    fn a_clean_reload_abstains_on_the_degraded_signal_rather_than_passing() {
        let outcome = degraded_signal(&[], true);
        assert!(
            matches!(outcome, SignalOutcome::Abstain(_)),
            "compiling is not evidence that a config works: {outcome:?}",
        );
        let outcome = degraded_signal(&["model_runtime".to_string()], true);
        assert!(matches!(outcome, SignalOutcome::Fail(_)), "{outcome:?}");
    }

    /// An empty report set is Inconclusive too, for the same reason.
    #[test]
    fn no_reports_at_all_is_inconclusive() {
        assert_eq!(aggregate(&[]), SoakVerdict::Inconclusive);
    }

    /// A window on a quiet node with a running synthetic driver reaches
    /// a real verdict rather than Inconclusive. This is the Flagger
    /// failure mode, closed.
    #[test]
    fn a_synthetic_probe_pass_rescues_a_quiet_node_from_inconclusive() {
        let mut quiet = window(soak(50), Vec::new());
        // Nothing to observe anywhere: no breakers, four requests, no
        // probe. That is Inconclusive.
        let (verdict, _) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &[],
            0,
        );
        assert_eq!(
            verdict,
            SoakVerdict::Inconclusive,
            "a quiet node with nothing reporting must not promote",
        );

        // The same node with the synthetic driver running.
        quiet.probe = Some(ProbeObservation::Ok);
        let (verdict, _) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &[],
            0,
        );
        assert_eq!(verdict, SoakVerdict::Successful);
    }

    /// A passing synthetic run proves the compiled chain executes. It
    /// proves nothing about whether any upstream is reachable, and must
    /// not be allowed to mask one that is not.
    #[test]
    fn a_passing_probe_does_not_mask_an_unreachable_upstream() {
        let mut quiet = window(soak(50), Vec::new());
        quiet.probe = Some(ProbeObservation::Ok);
        let (verdict, reports) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &["shop/api#target-0".to_string()],
            2,
        );
        assert_eq!(
            verdict,
            SoakVerdict::Failed,
            "an open breaker fails the soak whatever the synthetic driver says",
        );
        let health = reports
            .iter()
            .find(|(signal, _)| *signal == SoakSignal::UpstreamHealth)
            .map(|(_, outcome)| outcome.clone())
            .expect("the health signal reports");
        assert!(matches!(health, SignalOutcome::Fail(_)), "{health:?}");
    }

    /// Below `min_requests` with a failing health signal, the soak
    /// fails. Abstention does not rescue a real failure, driven through
    /// the same seam the window uses.
    #[test]
    fn a_quiet_window_with_an_open_breaker_fails() {
        let quiet = window(soak(50), Vec::new());
        let (verdict, _) = judge(
            &quiet,
            RequestCounts {
                requests: 3,
                errors: 0,
            },
            &["shop/api#target-1".to_string()],
            1,
        );
        assert_eq!(verdict, SoakVerdict::Failed);
    }

    /// A probe that times out fails the soak rather than abstaining, and
    /// says which of the two failure shapes it was.
    #[test]
    fn an_unreachable_probe_fails_and_says_so() {
        let timed_out = probe_signal(Some(&ProbeObservation::Unreachable(
            "no answer within 2000ms".to_string(),
        )));
        assert!(matches!(timed_out, SignalOutcome::Fail(_)), "{timed_out:?}");
        assert!(timed_out
            .detail()
            .expect("a failure explains itself")
            .contains("timed out or could not be reached"));

        let wrong_status = probe_signal(Some(&ProbeObservation::Unexpected(
            "expected 200 and got 503".to_string(),
        )));
        assert!(matches!(wrong_status, SignalOutcome::Fail(_)));
        assert!(wrong_status
            .detail()
            .expect("a failure explains itself")
            .contains("answered unexpectedly"));

        assert!(
            matches!(probe_signal(None), SignalOutcome::Abstain(_)),
            "no probe at all is an abstention, not a failure",
        );
    }

    /// The error rate is judged against what this node was already
    /// running at, not against zero.
    #[test]
    fn the_error_rate_is_a_delta_not_an_absolute() {
        // Steady state 10% errors, unchanged by the new config.
        let outcome = request_outcome_signal(
            RequestCounts::default(),
            RequestCounts {
                requests: 100,
                errors: 10,
            },
            50,
            0.05,
            Some(0.10),
        );
        assert_eq!(outcome, SignalOutcome::Pass);

        // The same node, now failing a third of its requests.
        let outcome = request_outcome_signal(
            RequestCounts::default(),
            RequestCounts {
                requests: 100,
                errors: 33,
            },
            50,
            0.05,
            Some(0.10),
        );
        assert!(matches!(outcome, SignalOutcome::Fail(_)), "{outcome:?}");
    }

    /// `POST /admin/config/confirm` promotes immediately, and is refused
    /// when no soak is in flight.
    #[test]
    fn confirm_now_closes_the_window_and_is_refused_when_none_is_armed() {
        clear();
        assert!(
            confirm_now().is_none(),
            "confirming with no window in flight must not invent one",
        );
        assert_eq!(arm(11, "digest", &[], &soak(50)), None);
        let (revision, _verdict, reports) = confirm_now().expect("a window was in flight");
        assert_eq!(revision, 11);
        assert_eq!(reports.len(), 4, "all four signals report");
        assert!(
            confirm_now().is_none(),
            "the window is consumed by the confirmation",
        );
        clear();
    }

    /// A soak switched off promotes on apply, deliberately and loudly.
    #[test]
    fn a_disabled_soak_promotes_on_apply() {
        clear();
        let config = ConfigSoakConfig {
            enabled: false,
            ..ConfigSoakConfig::default()
        };
        assert_eq!(
            arm(3, "digest", &[], &config),
            Some(SoakVerdict::Successful)
        );
        assert_eq!(in_flight_revision(), None);
        clear();
    }

    /// Apply, promote, and fail all reach the shared event sink rather
    /// than a sink of this module's own: one declared
    /// [`sbproxy_observe::EventType`], published through the same
    /// `publish_proxy_event` funnel every other typed event uses, with a
    /// payload of bounded metadata and no config value in it.
    #[test]
    fn the_soak_verdict_event_carries_the_revision_and_every_signal() {
        let mut judged = window(soak(50), Vec::new());
        judged.probe = Some(ProbeObservation::Ok);
        let (verdict, reports) = judge(
            &judged,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &[],
            0,
        );
        let event = soak_event(&judged, verdict, &reports);

        assert_eq!(
            event.event_type,
            sbproxy_observe::EventType::ConfigSoakVerdict,
        );
        assert_eq!(
            sbproxy_observe::EventType::ConfigSoakVerdict.as_str(),
            "config_soak_verdict",
        );
        assert!(
            sbproxy_observe::EventType::ConfigSoakVerdict.has_emitter(),
            "this module is that emitter; the registry has to know it",
        );
        assert_eq!(event.data["revision"], 7);
        assert_eq!(event.data["digest"], "abc123");
        assert_eq!(event.data["verdict"], "passed");
        let signals = event.data["signals"].as_array().expect("signals array");
        assert_eq!(signals.len(), 4, "one row per signal: {signals:?}");
        let named: Vec<&str> = signals
            .iter()
            .map(|row| row["signal"].as_str().expect("signal name"))
            .collect();
        assert_eq!(
            named,
            vec![
                "degraded_subsystems",
                "upstream_health",
                "request_outcome",
                "operator_probe",
            ],
        );
        assert_eq!(
            event.data["signals"][3]["outcome"], "passed",
            "the probe is what promoted this window",
        );
    }

    /// A counter reset cannot produce a negative window.
    #[test]
    fn a_counter_reset_saturates_rather_than_wrapping() {
        let window = RequestCounts {
            requests: 5,
            errors: 1,
        }
        .since(RequestCounts {
            requests: 900,
            errors: 90,
        });
        assert_eq!(window, RequestCounts::default());
        assert_eq!(window.error_rate(), None);
    }
}
