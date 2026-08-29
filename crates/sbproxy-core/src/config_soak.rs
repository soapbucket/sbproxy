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
//! # Reverting is off by default
//!
//! A failed soak records its verdict and leaves the last-known-good
//! pointer alone. Whether it also puts the node back on that pointer is
//! `proxy.config_history.soak.auto_revert`, which ships **off**
//! (WOR-2461): with it off the soak still runs, still promotes, and
//! still alerts, and nothing about what is serving changes without an
//! operator. With it on, [`crate::config_rollback::auto_revert_after_failed_soak`]
//! carries the four gates a revert has to pass, including the
//! blast-radius arming rule and the no-loop rule.

use std::sync::{Mutex, OnceLock};

use sbproxy_config::{ConfigSoakConfig, ConfigSoakProbeConfig, SoakVerdict};

/// One signal's report into a soak window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignalOutcome {
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
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "passed",
            Self::Fail(_) => "failed",
            Self::Abstain(_) => "abstain",
        }
    }

    /// The explanation, when there is one.
    #[must_use]
    pub(crate) fn detail(&self) -> Option<&str> {
        match self {
            Self::Pass => None,
            Self::Fail(detail) | Self::Abstain(detail) => Some(detail),
        }
    }
}

/// Which of the four signals reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SoakSignal {
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
    pub(crate) const fn as_str(self) -> &'static str {
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
pub(crate) struct RequestCounts {
    /// Requests completed since process start.
    pub(crate) requests: u64,
    /// Requests that finished at `400` or above, plus upstream status
    /// and timeout retries.
    pub(crate) errors: u64,
}

impl RequestCounts {
    /// Difference between a later sample and an earlier one, saturating
    /// at zero so a counter reset cannot produce a negative rate.
    #[must_use]
    pub(crate) fn since(self, baseline: Self) -> Self {
        Self {
            requests: self.requests.saturating_sub(baseline.requests),
            errors: self.errors.saturating_sub(baseline.errors),
        }
    }

    /// Error rate over this window, or `None` when it observed nothing.
    #[must_use]
    pub(crate) fn error_rate(self) -> Option<f64> {
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
pub(crate) fn observe_request_counts() -> RequestCounts {
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
pub(crate) fn degraded_signal(degraded: &[String], require_none: bool) -> SignalOutcome {
    if !require_none {
        return SignalOutcome::Abstain(
            "require_no_degraded_subsystems is off for this node".to_string(),
        );
    }
    if degraded.is_empty() {
        return SignalOutcome::Abstain(
            "no subsystem stayed on prior state, which is not by itself evidence that this \
             config works"
                .to_string(),
        );
    }
    SignalOutcome::Fail(format!(
        "the reload published with {} subsystem(s) on prior state: {}",
        degraded.len(),
        degraded.join(", ")
    ))
}

/// What the upstream-health sampler saw across every origin the running
/// config declares.
///
/// `unobserved` is the field that keeps this signal honest. It claims to
/// catch "an upstream repointed at a dead address", and it can only make
/// that claim about origins it can actually see: a `type: proxy` origin
/// with no health check, no circuit breaker, and no outlier detector
/// exposes nothing, and reporting a pass beside it would be a guard
/// narrower than its own claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UpstreamHealthSample {
    /// Identifiers of upstreams observed to be unhealthy: an open or
    /// half-open circuit breaker, a failed active health check, or an
    /// outlier ejection.
    pub(crate) unhealthy: Vec<String>,
    /// How many upstream targets exposed a health signal of any kind.
    pub(crate) observed: usize,
    /// Origins that expose no health signal at all.
    pub(crate) unobserved: Vec<String>,
}

/// The upstream-health signal, over the whole sample.
///
/// Three outcomes, and the middle one is the fix for a signal that used
/// to pass while blind:
///
/// * any unhealthy upstream fails outright, whatever else was seen;
/// * an origin nothing could observe abstains, because a pass would
///   claim health for an origin this never looked at;
/// * every origin observable and healthy passes.
#[must_use]
pub(crate) fn upstream_health_signal(
    config: &ConfigSoakConfig,
    sample: &UpstreamHealthSample,
) -> SignalOutcome {
    if !config.require_upstream_health {
        return SignalOutcome::Abstain("require_upstream_health is off for this node".to_string());
    }
    if !sample.unhealthy.is_empty() {
        return SignalOutcome::Fail(format!(
            "{} of {} observed upstream(s) are unhealthy, ejected, or on an open breaker: {}",
            sample.unhealthy.len(),
            sample.observed,
            sample.unhealthy.join(", ")
        ));
    }
    if !sample.unobserved.is_empty() {
        return SignalOutcome::Abstain(format!(
            "{} origin(s) expose no health signal, so this cannot say their upstreams are \
             reachable: {}. declare a health_check, a circuit_breaker, or an outlier detector \
             on them, or a soak probe that exercises them",
            sample.unobserved.len(),
            sample.unobserved.join(", ")
        ));
    }
    if sample.observed == 0 {
        // No forwarding origin at all: an emptied `origins:` map, or an
        // all-`static` maintenance config. Tempting to call vacuously
        // healthy, and wrong, because in this module a pass *promotes*.
        // Passing here would make a revision this signal never examined
        // the node's last known good and WOR-2459's boot target, which
        // is promote-on-compile wearing the soak's name and the exact
        // thing `degraded_signal` abstains to avoid (verification
        // residual R1).
        return SignalOutcome::Abstain(
            "the running config declares no upstream at all, so this signal examined nothing"
                .to_string(),
        );
    }
    // Every forwarding origin was observable and none was unhealthy.
    SignalOutcome::Pass
}

/// Whether one action forwards to an upstream at all.
///
/// Exhaustive by construction, so a new [`sbproxy_modules::Action`]
/// variant cannot be added without deciding which side of this line it
/// falls on. The distinction matters because the two answers are not
/// "observed" and "unobserved" but "there is an upstream I cannot see"
/// and "there is no upstream": only the first may make this signal
/// abstain.
#[must_use]
pub(crate) fn bears_an_upstream(action: &sbproxy_modules::Action) -> bool {
    use sbproxy_modules::Action;
    match action {
        // Forwards somewhere.
        Action::Proxy(_)
        | Action::LoadBalancer(_)
        | Action::AiProxy(_)
        | Action::WebSocket(_)
        | Action::Grpc(_)
        | Action::GraphQL(_)
        | Action::Storage(_)
        | Action::A2a(_)
        | Action::Mcp(_)
        // A plugin is dynamic dispatch into third-party code: this
        // cannot see what it dials, and "I cannot see" is exactly the
        // unobserved answer.
        | Action::Plugin(_) => true,
        // Answers from this process. No upstream exists, so none can be
        // unhealthy. `proxy.synthetic_probe` requires its origin to be
        // one of these.
        Action::Redirect(_)
        | Action::Static(_)
        | Action::Echo(_)
        | Action::Mock(_)
        | Action::Beacon(_)
        | Action::Noop => false,
    }
}

/// The request-outcome signal.
///
/// Three-way on purpose. Below `min_requests` this **abstains**: a
/// window that saw four requests and one failure has a 25% error rate
/// and no information, and treating that as a failure is the single most
/// common cause of a spurious rollback in the systems that got this
/// wrong before us.
#[must_use]
pub(crate) fn request_outcome_signal(
    config: &ConfigSoakConfig,
    baseline: RequestCounts,
    current: RequestCounts,
    baseline_error_rate: Option<f64>,
) -> SignalOutcome {
    let min_requests = config.min_requests;
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
    if rate - previous > config.max_error_rate_delta {
        return SignalOutcome::Fail(format!(
            "the error rate rose from {:.1}% to {:.1}% over {} request(s), past the \
             max_error_rate_delta of {:.1}%",
            previous * 100.0,
            rate * 100.0,
            window.requests,
            config.max_error_rate_delta * 100.0
        ));
    }
    SignalOutcome::Pass
}

/// Why an operator probe could not complete.
///
/// A closed set, and the only thing about a probe failure that reaches a
/// detail string besides the redacted origin. `reqwest::Error`'s
/// `Display` ends `" for url ({url})"` with the **post-interpolation**
/// URL, so formatting one into a detail puts whatever
/// `soak.probe.url`'s userinfo or query carried into an ERROR line, the
/// `ConfigSoakVerdict` event, and the `POST /admin/config/confirm` body
/// (WOR-2458 fix round, Blocker 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeFailureKind {
    /// The request did not complete inside `probe.timeout_ms`.
    Timeout,
    /// The connection could not be established.
    Connect,
    /// The request failed for any other reason.
    Request,
}

impl ProbeFailureKind {
    /// Stable, bounded label.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Request => "request",
        }
    }
}

/// Build a probe-failure detail from the URL's origin and a bounded
/// kind, and nothing else.
///
/// [`sbproxy_security::url_redact::redacted_url`] is the workspace's one
/// answer for this: it keeps scheme, host, and a non-default port, drops
/// username, password, path, query, and fragment, and renders an
/// unparseable value as a constant rather than echoing it back. A Slack
/// or PagerDuty webhook puts the whole secret in the path, which is why
/// the path goes too.
#[must_use]
pub(crate) fn probe_failure_detail(url: &str, kind: ProbeFailureKind) -> String {
    format!(
        "{} to {}",
        kind.as_str(),
        sbproxy_security::url_redact::redacted_url(url)
    )
}

/// What one probe tick observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeObservation {
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

/// Which probe produced an observation.
///
/// Kept apart on the window rather than folded into one slot. The
/// supervisor reads the synthetic driver on every tick and the operator
/// probe only on its own `interval_secs`, so a single slot would let the
/// next synthetic pass erase an operator-probe failure a few seconds
/// after it was recorded, which is the one observation an operator
/// configured the probe to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeKind {
    /// `proxy.config_history.soak.probe`: an HTTP GET the operator
    /// declared.
    Operator,
    /// The synthetic-transaction driver `proxy.synthetic_probe` starts.
    Synthetic,
}

/// The operator-probe signal, over both probes that can feed it.
///
/// A probe that timed out or could not be reached **fails** the soak
/// rather than abstaining, and says which. An abstention there would
/// mean a probe an operator deliberately configured could go silently
/// missing and still let a bad config be promoted, which is the opposite
/// of why they configured it. Either probe failing fails the signal;
/// a synthetic pass never covers for an operator probe that is failing.
///
/// Absent both a declared probe and a running synthetic driver, this
/// abstains: there is nothing to observe.
#[must_use]
pub(crate) fn probe_signal(
    operator: Option<&ProbeObservation>,
    synthetic: Option<&ProbeObservation>,
) -> SignalOutcome {
    let observations = [
        (ProbeKind::Operator, operator),
        (ProbeKind::Synthetic, synthetic),
    ];
    for (kind, observation) in observations {
        let label = match kind {
            ProbeKind::Operator => "the operator probe",
            ProbeKind::Synthetic => "the synthetic transaction driver",
        };
        match observation {
            Some(ProbeObservation::Unexpected(detail)) => {
                return SignalOutcome::Fail(format!("{label} answered unexpectedly: {detail}"))
            }
            Some(ProbeObservation::Unreachable(detail)) => {
                return SignalOutcome::Fail(format!(
                    "{label} timed out or could not be reached: {detail}"
                ))
            }
            _ => {}
        }
    }
    if observations
        .iter()
        .any(|(_, observation)| matches!(observation, Some(ProbeObservation::Ok)))
    {
        return SignalOutcome::Pass;
    }
    SignalOutcome::Abstain(
        "no operator probe is declared and no synthetic driver is running".to_string(),
    )
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
pub(crate) fn aggregate(reports: &[(SoakSignal, SignalOutcome)]) -> SoakVerdict {
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
pub(crate) const fn verdict_label(verdict: SoakVerdict) -> &'static str {
    match verdict {
        SoakVerdict::Successful => "passed",
        SoakVerdict::Failed => "failed",
        SoakVerdict::Inconclusive => "inconclusive",
    }
}

/// What one closed soak window produced: the revision it judged, the
/// verdict it reached, and what every signal said.
///
/// A named type rather than a tuple because three callers destructure it
/// (the supervisor's timed close, `POST /admin/config/confirm`, and the
/// tests), and a caller that swapped the verdict and the reports would
/// still compile against a tuple.
#[derive(Debug, Clone)]
pub(crate) struct SoakOutcome {
    /// Ring revision this window judged.
    pub(crate) revision: u64,
    /// That revision's content digest, carried so the auto-revert's
    /// no-loop rule can compare content rather than revision numbers
    /// without a second ring read (WOR-2461).
    pub(crate) digest: String,
    /// The verdict it reached.
    pub(crate) verdict: SoakVerdict,
    /// One entry per signal, in the order they are evaluated.
    pub(crate) reports: Vec<(SoakSignal, SignalOutcome)>,
    /// Whether `soak.auto_revert` was armed for the window that reached
    /// this verdict.
    ///
    /// Carried on the outcome rather than re-read from the running
    /// config by whoever handles it: by the time a caller acts on a
    /// failed verdict the pipeline may already have moved, and the
    /// question is what the operator armed for *this* revision.
    pub(crate) auto_revert: bool,
}

/// One soak window in flight.
#[derive(Debug, Clone)]
pub(crate) struct SoakWindow {
    /// Ring revision this window is judging.
    pub(crate) revision: u64,
    /// Content digest of that revision, carried so a log line and a
    /// decision event can name it without another ring read.
    pub(crate) digest: String,
    /// Unix milliseconds the window closes at.
    pub(crate) closes_at_ms: u64,
    /// Request counters at the instant the window armed.
    pub(crate) baseline: RequestCounts,
    /// Error rate this node was running at before the window armed,
    /// when it was running enough traffic to have one.
    pub(crate) baseline_error_rate: Option<f64>,
    /// Subsystems the reload published without.
    pub(crate) degraded: Vec<String>,
    /// The soak block in force for this window.
    pub(crate) config: ConfigSoakConfig,
    /// The most recent operator-probe tick, when one has run.
    pub(crate) operator_probe: Option<ProbeObservation>,
    /// The most recent synthetic-driver reading, when one is running.
    pub(crate) synthetic_probe: Option<ProbeObservation>,
}

/// The process-wide slot holding the window in flight, if any.
static IN_FLIGHT: OnceLock<Mutex<Option<SoakWindow>>> = OnceLock::new();

fn in_flight() -> &'static Mutex<Option<SoakWindow>> {
    IN_FLIGHT.get_or_init(|| Mutex::new(None))
}

/// A verdict reached before a window could be stored, waiting for the
/// supervisor to act on it (WOR-2461).
///
/// [`arm`] runs inside the reload transaction, which holds
/// `CONFIG_RELOAD_LOCK`, and an automatic revert re-enters that
/// transaction to publish the restored document. So a verdict reached
/// at arm time cannot act where it is discovered: it would deadlock
/// against the lock its own caller is holding. It is left here instead,
/// and [`drive_verdicts`] picks it up on the supervisor's next tick,
/// outside the lock.
///
/// One slot, last writer wins, because a newer revision supersedes an
/// unhandled failure for the same reason [`arm`] supersedes a window in
/// flight: reverting on account of a revision that is no longer serving
/// would undo a change nothing has judged.
static PENDING_VERDICT: OnceLock<Mutex<Option<SoakOutcome>>> = OnceLock::new();

fn pending_verdict() -> &'static Mutex<Option<SoakOutcome>> {
    PENDING_VERDICT.get_or_init(|| Mutex::new(None))
}

/// Take the verdict [`arm`] left behind, if it left one.
///
/// Taking rather than reading: a verdict is acted on once. A second
/// supervisor tick a second later must not revert again on the strength
/// of the same failure.
pub(crate) fn take_pending_verdict() -> Option<SoakOutcome> {
    pending_verdict()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
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
/// the honest record of what happened to it. A failure this function
/// left in [`PENDING_VERDICT`] and the supervisor has not reached yet is
/// superseded on the same grounds and for the same reason.
///
/// The caller records the returned verdict on the ring entry. A `Failed`
/// verdict is additionally left in [`PENDING_VERDICT`] for the
/// supervisor, because this runs under the reload lock and an automatic
/// revert cannot be taken from here; see that slot's documentation.
pub(crate) fn arm(
    revision: u64,
    digest: &str,
    degraded: &[String],
    config: &ConfigSoakConfig,
) -> Option<SoakVerdict> {
    // Before the disabled-soak early return below, not after: a node
    // whose next revision switches the soak off is still a node whose
    // previous revision is no longer serving.
    if let Some(superseded) = take_pending_verdict() {
        tracing::info!(
            superseded_revision = superseded.revision,
            revision,
            "a newer config revision applied before the supervisor acted on an immediate soak \
             failure; the failure is dropped rather than reverting a revision that is no \
             longer running",
        );
    }

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
        // Handed to the supervisor rather than acted on here: this runs
        // under the reload lock and a revert re-enters the reload
        // transaction (WOR-2461).
        *pending_verdict()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(SoakOutcome {
            revision,
            digest: digest.to_string(),
            verdict: SoakVerdict::Failed,
            reports: vec![(SoakSignal::DegradedSubsystems, degraded_outcome.clone())],
            auto_revert: config.auto_revert,
        });
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
        operator_probe: None,
        synthetic_probe: None,
    });
    None
}

/// The revision the window in flight is judging, if any.
#[must_use]
pub(crate) fn in_flight_revision() -> Option<u64> {
    in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(|window| window.revision)
}

/// Drop the window in flight, and any verdict waiting for the
/// supervisor, without reaching or acting on either.
///
/// Tests only. Both slots are process-global, so one test's armed
/// window would otherwise be judged by the next test's `confirm_now`
/// and one test's immediate failure would revert during the next
/// test's reload. No production path drops a window without a verdict:
/// the two ways one ends are the timer and an operator's confirmation,
/// and a third reload supersedes it through [`arm`] rather than through
/// this.
#[cfg(test)]
pub(crate) fn clear() {
    *in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let _ = take_pending_verdict();
}

/// Record the most recent observation from one probe against the window
/// in flight. A no-op when no window is armed.
pub(crate) fn record_probe(kind: ProbeKind, observation: ProbeObservation) {
    if let Some(window) = in_flight()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        match kind {
            ProbeKind::Operator => window.operator_probe = Some(observation),
            ProbeKind::Synthetic => window.synthetic_probe = Some(observation),
        }
    }
}

/// Judge one window against the signals available right now.
///
/// Split from [`close_due`] so a test can drive the decision with
/// sampled inputs rather than a live pipeline, and so the aggregate and
/// per-signal metrics are emitted in exactly one place.
#[must_use]
pub(crate) fn judge(
    window: &SoakWindow,
    current: RequestCounts,
    health: &UpstreamHealthSample,
) -> (SoakVerdict, Vec<(SoakSignal, SignalOutcome)>) {
    // Bound once, and by type: every read below is a read of a
    // `ConfigSoakConfig` field, which is what `check-config-readers.sh`
    // and its `key_registry` test look for when they prove that every
    // key the schema accepts is one production code actually consults.
    let config = &window.config;
    // A synthetic-driver pass is the one passing reading that provably
    // says nothing about upstreams: the synthetic origin is required to
    // be a non-network action, so a pass proves the compiled chain
    // executes and nothing more. While the health signal is blind to an
    // origin, letting that pass promote is exactly the "a passing
    // synthetic run masks an unreachable upstream" hole the ticket names,
    // one level up from the signal it is tested at. So the reading
    // downgrades to an absence here, and an operator-declared probe,
    // which dials a real URL the operator chose, is unaffected
    // (WOR-2458 fix round, Blocker 3).
    // Computed first, because whether a synthetic pass may promote
    // depends on it. Keyed on the signal's own verdict rather than on
    // `unobserved` alone: it abstains for two reasons, an origin it
    // cannot see *and* a config with no upstream at all, and both mean
    // the same thing here, that nothing has established the upstreams
    // are reachable (verification residual R1).
    let upstream = upstream_health_signal(config, health);
    // An operator who set `require_upstream_health: false` has said they
    // are not judging on upstream health, so there is nothing for a
    // synthetic pass to be masking and the downgrade does not apply.
    let synthetic = match window.synthetic_probe.as_ref() {
        Some(ProbeObservation::Ok)
            if config.require_upstream_health && matches!(upstream, SignalOutcome::Abstain(_)) =>
        {
            None
        }
        other => other,
    };
    let reports = vec![
        (
            SoakSignal::DegradedSubsystems,
            degraded_signal(&window.degraded, config.require_no_degraded_subsystems),
        ),
        (SoakSignal::UpstreamHealth, upstream),
        (
            SoakSignal::RequestOutcome,
            request_outcome_signal(config, window.baseline, current, window.baseline_error_rate),
        ),
        (
            SoakSignal::OperatorProbe,
            probe_signal(window.operator_probe.as_ref(), synthetic),
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
pub(crate) fn close_due() -> Option<SoakOutcome> {
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
pub(crate) fn confirm_now() -> Option<SoakOutcome> {
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
fn finish(window: &SoakWindow) -> SoakOutcome {
    let health = sample_upstream_health();
    let (verdict, reports) = judge(window, observe_request_counts(), &health);
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
            abstentions = %reports
                .iter()
                .map(|(signal, outcome)| format!(
                    "{}: {}",
                    signal.as_str(),
                    outcome.detail().unwrap_or("no detail")
                ))
                .collect::<Vec<_>>()
                .join("; "),
            "every soak signal abstained, so this window measured nothing: the revision is \
             neither promoted nor failed and this node still has no rollback target. the \
             abstentions above say which kind of nothing it is. if upstream_health abstained, \
             the synthetic probe driver alone cannot fix it: its origin is a non-network \
             action, so its pass says nothing about your upstreams and is discarded while \
             this signal is blind. declare soak.probe.url against a real upstream, or give \
             the origin a health_check, circuit_breaker, or outlier_detection block, or set \
             require_upstream_health: false to judge without it",
        ),
    }
    SoakOutcome {
        revision: window.revision,
        digest: window.digest.clone(),
        verdict,
        reports,
        auto_revert: window.config.auto_revert,
    }
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
pub(crate) fn soak_event(
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
fn sample_upstream_health() -> UpstreamHealthSample {
    let pipeline = crate::reload::current_pipeline();
    sample_upstream_health_of(&pipeline.actions, &pipeline.config.origins)
}

/// The sampler proper, over the running pipeline's actions and the
/// origins they were compiled from.
///
/// Split from [`sample_upstream_health`] so a test can drive it against a
/// real published pipeline without a process global in the way, and so
/// the walk over origin types is readable in one screen.
///
/// Every origin is visited, not only the load balancers. Three health
/// signals are read per load-balancer target, in the order the ticket's
/// signal table names them:
///
/// * the per-target circuit breaker, when a `circuit_breaker:` block
///   declared one;
/// * the active health-check flag, when a `health_check:` block declared
///   one, which is the `sbproxy-platform` health map for this action;
/// * the outlier detector's ejection set, when an `outlier_detection:`
///   block declared one.
///
/// An origin that exposes none of the three lands in
/// [`UpstreamHealthSample::unobserved`] rather than being skipped
/// silently. Skipping it is what let one healthy load balancer report
/// "upstreams healthy" for a whole config that also carried a `type:
/// proxy` origin pointed at a dead address (WOR-2458 fix round,
/// Blocker 3).
#[must_use]
pub(crate) fn sample_upstream_health_of(
    actions: &[sbproxy_modules::Action],
    origins: &[sbproxy_config::CompiledOrigin],
) -> UpstreamHealthSample {
    let mut sample = UpstreamHealthSample::default();
    for (index, action) in actions.iter().enumerate() {
        let identity = origins.get(index).map_or_else(
            || format!("action-{index}"),
            |origin| format!("{}/{}", origin.workspace_id, origin.origin_id),
        );
        let sbproxy_modules::Action::LoadBalancer(load_balancer) = action else {
            if bears_an_upstream(action) {
                // A `proxy`, `ai_proxy`, `grpc`, ... origin forwards
                // somewhere and carries no health instrumentation, so
                // this signal has something to be blind to and must say
                // so.
                sample.unobserved.push(identity);
            }
            // A non-network action has no upstream at all: it cannot be
            // unhealthy and it hides nothing, so it belongs in neither
            // column. Counting one as unobserved was not a rounding
            // error, it was the ticket's own scenario breaking:
            // `proxy.synthetic_probe` *requires* its origin to be one of
            // these, so every node running the driver had the very
            // signal the driver feeds poisoned by the driver's own
            // origin (re-review, WOR-2458 coverage).
            continue;
        };
        let breakers = load_balancer.circuit_breakers.as_ref();
        let outlier = load_balancer.outlier_detector.as_ref();
        let mut observed_here = 0usize;
        for (target_index, target) in load_balancer.targets.iter().enumerate() {
            let name = format!("{identity}#target-{target_index}");
            let mut observed_target = false;
            if let Some(breaker) = breakers.and_then(|breakers| breakers.get(target_index)) {
                observed_target = true;
                if !matches!(breaker.state(), sbproxy_platform::CircuitState::Closed) {
                    sample.unhealthy.push(format!("{name} (breaker open)"));
                }
            }
            if target.health_check.is_some() {
                observed_target = true;
                if !load_balancer.target_is_healthy(target_index) {
                    sample
                        .unhealthy
                        .push(format!("{name} (health check failing)"));
                }
            }
            if let Some(outlier) = outlier {
                observed_target = true;
                if outlier.is_ejected(&target.url) {
                    sample
                        .unhealthy
                        .push(format!("{name} (ejected by outlier detection)"));
                }
            }
            if observed_target {
                observed_here += 1;
            }
        }
        if observed_here == 0 {
            // A load balancer with no breaker, no health check, and no
            // outlier detector is as opaque as a `type: proxy` origin.
            sample.unobserved.push(identity);
        } else {
            sample.observed += observed_here;
        }
    }
    sample
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
        // The error's own `Display` is deliberately never formatted:
        // it ends `" for url ({url})"` with the resolved URL. Only the
        // classification survives, and the URL reaches the detail
        // through `probe_failure_detail`'s redaction.
        Err(error) => {
            let kind = if error.is_timeout() {
                ProbeFailureKind::Timeout
            } else if error.is_connect() {
                ProbeFailureKind::Connect
            } else {
                ProbeFailureKind::Request
            };
            ProbeObservation::Unreachable(probe_failure_detail(&probe.url, kind))
        }
    };
    record_probe(ProbeKind::Operator, observation);
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
    synthetic_probe_observation(status, detail)
}

/// Map one driver reading onto a probe observation, or `None` when the
/// reading is an absence of evidence rather than evidence.
///
/// `/readyz` treats "the driver has not run yet" and "the last outcome
/// is stale" as unhealthy and drains the node, which is the right answer
/// for readiness. It is the wrong answer here. A driver that has not
/// reported has said nothing about the config that just applied, and
/// failing a soak on it meant a deployment pipeline that reloaded,
/// smoke-tested, and confirmed inside the driver's first interval got
/// `{"verdict":"failed"}` for a perfectly good config, with the entry
/// written `RevisionState::Failed` (WOR-2458 fix round, Blocker 4).
///
/// A driver that ran and reported a real failure is still a failure.
#[must_use]
pub(crate) fn synthetic_probe_observation(
    status: sbproxy_observe::ComponentStatus,
    detail: Option<String>,
) -> Option<ProbeObservation> {
    if status == sbproxy_observe::ComponentStatus::Healthy {
        return Some(ProbeObservation::Ok);
    }
    let detail = detail.unwrap_or_default();
    if detail == sbproxy_observe::SYNTHETIC_NO_OUTCOME_DETAIL
        || detail.starts_with(sbproxy_observe::SYNTHETIC_STALE_DETAIL_PREFIX)
    {
        return None;
    }
    Some(ProbeObservation::Unexpected(format!(
        "the synthetic transaction driver reports {detail}"
    )))
}

/// Start the soak supervisor: one task that ticks the window in flight,
/// runs the operator probe on its cadence, and closes the window when it
/// is due.
///
/// A no-op when no window is ever armed, which is every node that has
/// not enabled `proxy.config_history`.
pub(crate) fn spawn(config_path: String) {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(
                error = %error,
                "config soak: could not build the probe HTTP client, so the soak supervisor \
                 did not start. for the life of this process the operator-probe signal \
                 abstains and nothing closes a soak window on its timer, so no revision is \
                 promoted to last known good and auto_revert never fires on its own. \
                 POST /admin/config/confirm still works and is the way out: it closes the \
                 window in flight, records the verdict, promotes on a pass, and reverts on a \
                 failure when auto_revert is armed",
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
            last_probe_ms = supervisor_tick(&config_path, &client, last_probe_ms).await;
        }
    });
}

/// One tick of the supervisor: read the probes, then act on whatever
/// verdict is waiting. Returns the updated operator-probe cursor.
///
/// Split out of the loop above so a test can drive a whole tick rather
/// than the halves of it, which is what caught both of the bugs the
/// shape below exists to avoid.
///
/// # Verdict handling is outside the armed-window gate
///
/// The probes only mean anything while a window is in flight, so their
/// work is gated on one. Verdict handling is not, and that is
/// deliberate (WOR-2461): [`arm`] reaches a `Failed` verdict for a
/// degraded reload **without storing a window at all**, so gating this
/// on an armed window would drop exactly the failure that needs it, and
/// leave `auto_revert` looking like a feature that works until the most
/// common failure it has arrives.
///
/// The pending slot is drained before [`close_due`] so a failure and a
/// later window close are handled in the order they happened.
pub(crate) async fn supervisor_tick(
    config_path: &str,
    client: &reqwest::Client,
    last_probe_ms: u64,
) -> u64 {
    let mut last_probe_ms = last_probe_ms;
    // Cloned out under the lock and dropped before any await: the slot
    // is a `std::sync::Mutex`, and holding one across the probe's
    // `await` is what `clippy::await_holding_lock` exists to stop.
    let armed = {
        let slot = in_flight()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.as_ref().map(|window| window.config.probe.clone())
    };
    if let Some(probe) = armed {
        // The synthetic driver's outcome first: it needs no I/O of our
        // own, and it is what keeps a quiet node's window out of
        // `Inconclusive`. Recorded into its own slot, so an operator
        // probe that failed a moment ago is not erased by it.
        if let Some(observation) = synthetic_observation() {
            record_probe(ProbeKind::Synthetic, observation);
        }
        if let Some(probe) = probe {
            let due =
                now_ms().saturating_sub(last_probe_ms) >= probe.interval_secs.saturating_mul(1_000);
            if due {
                last_probe_ms = now_ms();
                run_operator_probe(&probe, client).await;
            }
        }
    }
    if let Some(outcome) = take_pending_verdict() {
        react_to_verdict(config_path, outcome).await;
    }
    if let Some(outcome) = close_due() {
        react_to_verdict(config_path, outcome).await;
    }
    last_probe_ms
}

/// Hand a closed window's verdict to the auto-revert decision
/// (WOR-2461).
///
/// Only a `Failed` verdict can revert. `Inconclusive` deliberately
/// cannot: a window where every signal abstained measured nothing, and
/// reverting on "no information" is the 3am false positive that gets
/// this feature switched off. That is Argo Rollouts' own position on an
/// inconclusive analysis run, which pauses rather than aborting.
///
/// `spawn_blocking` because the revert drives the reload transaction,
/// which compiles a configuration and constructs a pipeline while
/// holding a `std::sync::Mutex`. Running that on the supervisor's
/// current-thread runtime would stall the probe ticker and the admin
/// server that shares it. Awaited rather than detached, so two reverts
/// cannot overlap and one tick cannot outrun the apply it asked for.
async fn react_to_verdict(config_path: &str, outcome: SoakOutcome) {
    if outcome.verdict != SoakVerdict::Failed {
        return;
    }
    let config_path = config_path.to_string();
    let handle = tokio::task::spawn_blocking(move || {
        crate::config_rollback::auto_revert_after_failed_soak(
            Some(&config_path),
            outcome.revision,
            &outcome.digest,
            outcome.auto_revert,
        );
    });
    if let Err(error) = handle.await {
        tracing::error!(
            error = %error,
            "the automatic config revert task did not complete; the running configuration is \
             whatever the failed soak left serving",
        );
    }
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

    /// A sample in which every origin is observable and healthy.
    fn healthy(observed: usize) -> UpstreamHealthSample {
        UpstreamHealthSample {
            unhealthy: Vec::new(),
            observed,
            unobserved: Vec::new(),
        }
    }

    /// A sample in which nothing could be observed at all: the shape a
    /// node whose only origin is `type: proxy` produces.
    fn opaque(origin: &str) -> UpstreamHealthSample {
        UpstreamHealthSample {
            unhealthy: Vec::new(),
            observed: 0,
            unobserved: vec![origin.to_string()],
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
            operator_probe: None,
            synthetic_probe: None,
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
            "only the newest revision is under judgment",
        );
        clear();
    }

    /// Below `min_requests` the request-outcome signal abstains rather
    /// than reporting a failure on four requests and one 500.
    #[test]
    fn the_request_outcome_signal_abstains_below_min_requests() {
        let outcome = request_outcome_signal(
            &soak(50),
            RequestCounts::default(),
            RequestCounts {
                requests: 4,
                errors: 1,
            },
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
            &healthy(2),
        );
        assert_eq!(
            verdict,
            SoakVerdict::Successful,
            "observable healthy upstreams are evidence even with no traffic",
        );

        // The same node with the synthetic driver running, and with no
        // upstream this soak can see. The driver's pass proves the
        // compiled chain executes and nothing about the upstreams, so it
        // must not promote on its own.
        quiet.synthetic_probe = Some(ProbeObservation::Ok);
        let (verdict, _) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &opaque("shop/api"),
        );
        assert_eq!(
            verdict,
            SoakVerdict::Inconclusive,
            "a synthetic pass beside an origin nothing can observe measures nothing",
        );

        // An operator-declared probe dials a real URL the operator
        // chose, so it does promote.
        quiet.operator_probe = Some(ProbeObservation::Ok);
        let (verdict, _) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &opaque("shop/api"),
        );
        assert_eq!(verdict, SoakVerdict::Successful);
    }

    /// Verification residual R1. `observed == 0` with nothing
    /// unobserved is a config that declares no forwarding origin at all:
    /// an emptied `origins:` map, or an all-`static` maintenance page.
    /// Passing there promotes a revision on a signal that examined
    /// nothing, which is promote-on-compile wearing the soak's name and
    /// contradicts this module's own rule that a clean construction is
    /// not evidence. It abstains.
    #[test]
    fn a_config_with_no_upstream_at_all_abstains_rather_than_passing() {
        let empty = UpstreamHealthSample::default();
        let outcome = upstream_health_signal(&soak(50), &empty);
        assert!(
            matches!(outcome, SignalOutcome::Abstain(_)),
            "a signal that examined nothing must not promote: {outcome:?}",
        );
        assert!(
            outcome
                .detail()
                .expect("an abstention explains itself")
                .contains("no upstream"),
            "{outcome:?}",
        );

        // And it must not be rescued into a promotion by a synthetic
        // pass either: an all-static config plus the driver is exactly
        // the shape that would otherwise become WOR-2459's boot target
        // on no evidence at all.
        let mut quiet = window(soak(50), Vec::new());
        quiet.synthetic_probe = Some(ProbeObservation::Ok);
        let (verdict, _) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &empty,
        );
        assert_eq!(
            verdict,
            SoakVerdict::Inconclusive,
            "nothing measured anything, so nothing is promoted",
        );
    }

    /// The documented escape from a permanently inconclusive node: an
    /// operator who turns the upstream-health signal off has said they
    /// are not judging on it, so there is nothing for a synthetic pass
    /// to mask and it promotes again.
    #[test]
    fn turning_the_upstream_signal_off_lets_the_synthetic_driver_promote_again() {
        let mut quiet = window(
            ConfigSoakConfig {
                require_upstream_health: false,
                ..soak(50)
            },
            Vec::new(),
        );
        quiet.synthetic_probe = Some(ProbeObservation::Ok);
        let (verdict, _) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &opaque("shop/api"),
        );
        assert_eq!(verdict, SoakVerdict::Successful);
    }

    /// A passing synthetic run proves the compiled chain executes. It
    /// proves nothing about whether any upstream is reachable, and must
    /// not be allowed to mask one that is not.
    #[test]
    fn a_passing_probe_does_not_mask_an_unreachable_upstream() {
        let mut quiet = window(soak(50), Vec::new());
        quiet.synthetic_probe = Some(ProbeObservation::Ok);
        let (verdict, reports) = judge(
            &quiet,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &UpstreamHealthSample {
                unhealthy: vec!["shop/api#target-0 (breaker open)".to_string()],
                observed: 2,
                unobserved: Vec::new(),
            },
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
            &UpstreamHealthSample {
                unhealthy: vec!["shop/api#target-1 (breaker open)".to_string()],
                observed: 1,
                unobserved: Vec::new(),
            },
        );
        assert_eq!(verdict, SoakVerdict::Failed);
    }

    /// A probe that times out fails the soak rather than abstaining, and
    /// says which of the two failure shapes it was.
    #[test]
    fn an_unreachable_probe_fails_and_says_so() {
        let timed_out = probe_signal(
            Some(&ProbeObservation::Unreachable(
                "no answer within 2000ms".to_string(),
            )),
            None,
        );
        assert!(matches!(timed_out, SignalOutcome::Fail(_)), "{timed_out:?}");
        assert!(timed_out
            .detail()
            .expect("a failure explains itself")
            .contains("timed out or could not be reached"));

        let wrong_status = probe_signal(
            Some(&ProbeObservation::Unexpected(
                "expected 200 and got 503".to_string(),
            )),
            None,
        );
        assert!(matches!(wrong_status, SignalOutcome::Fail(_)));
        assert!(wrong_status
            .detail()
            .expect("a failure explains itself")
            .contains("answered unexpectedly"));

        assert!(
            matches!(probe_signal(None, None), SignalOutcome::Abstain(_)),
            "no probe at all is an abstention, not a failure",
        );
    }

    /// A synthetic pass on the next tick must not erase an operator
    /// probe that is failing. The supervisor reads the driver every
    /// second and the operator probe only on its own interval, so a
    /// single slot would have lost exactly the observation an operator
    /// configured the probe to catch.
    #[test]
    fn a_synthetic_pass_does_not_cover_for_a_failing_operator_probe() {
        let outcome = probe_signal(
            Some(&ProbeObservation::Unreachable(
                "connection refused".to_string(),
            )),
            Some(&ProbeObservation::Ok),
        );
        assert!(matches!(outcome, SignalOutcome::Fail(_)), "{outcome:?}");
        assert!(outcome
            .detail()
            .expect("a failure explains itself")
            .contains("operator probe"));

        // And the other way round: a failing synthetic driver is a
        // failure whatever the operator's own probe says.
        let outcome = probe_signal(
            Some(&ProbeObservation::Ok),
            Some(&ProbeObservation::Unexpected("unhealthy".to_string())),
        );
        assert!(matches!(outcome, SignalOutcome::Fail(_)), "{outcome:?}");
        assert!(outcome
            .detail()
            .expect("a failure explains itself")
            .contains("synthetic transaction driver"));
    }

    /// The error rate is judged against what this node was already
    /// running at, not against zero.
    #[test]
    fn the_error_rate_is_a_delta_not_an_absolute() {
        // Steady state 10% errors, unchanged by the new config.
        let outcome = request_outcome_signal(
            &soak(50),
            RequestCounts::default(),
            RequestCounts {
                requests: 100,
                errors: 10,
            },
            Some(0.10),
        );
        assert_eq!(outcome, SignalOutcome::Pass);

        // The same node, now failing a third of its requests.
        let outcome = request_outcome_signal(
            &soak(50),
            RequestCounts::default(),
            RequestCounts {
                requests: 100,
                errors: 33,
            },
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
        let closed = confirm_now().expect("a window was in flight");
        assert_eq!(closed.revision, 11);
        assert_eq!(closed.reports.len(), 4, "all four signals report");
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
        judged.operator_probe = Some(ProbeObservation::Ok);
        let (verdict, reports) = judge(
            &judged,
            RequestCounts {
                requests: 4,
                errors: 0,
            },
            &healthy(1),
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

    // --- fix round: Blocker regressions ---

    /// B1 red-first. `reqwest::Error`'s Display ends `" for url ({url})"`,
    /// and the URL is the post-interpolation value, so a
    /// `soak.probe.url` carrying `${HEALTH_TOKEN}` in its userinfo puts a
    /// live credential into an ERROR line, the `ConfigSoakVerdict` SIEM
    /// event, and the `POST /admin/config/confirm` body. Only scheme,
    /// host, port, and a bounded kind may survive.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unreachable_probe_never_echoes_the_url_userinfo_or_query() {
        const SENTINEL: &str = "sb-probe-sentinel-do-not-log";
        clear();
        assert_eq!(arm(21, "digest", &[], &soak(50)), None);

        let probe = ConfigSoakProbeConfig {
            // Port 1 is refused immediately on every platform the gate
            // runs on, so this needs no listener and no network.
            url: format!("http://svc:{SENTINEL}@127.0.0.1:1/healthz?token={SENTINEL}"),
            expect_status: 200,
            interval_secs: 10,
            timeout_ms: 250,
        };
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        run_operator_probe(&probe, &client).await;

        let observed = in_flight()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|window| window.operator_probe.clone())
            .expect("the probe recorded an observation");
        let detail = probe_signal(Some(&observed), None)
            .detail()
            .expect("a failure explains itself")
            .to_string();

        assert!(
            !detail.contains(SENTINEL),
            "the probe URL's userinfo and query must never reach a detail string: {detail}",
        );
        assert!(
            detail.contains("http://127.0.0.1:1"),
            "scheme, host, and port are what an operator needs: {detail}",
        );
        assert!(
            !detail.contains("/healthz"),
            "the path is a credential carrier for webhook-shaped URLs: {detail}",
        );
        clear();
    }

    /// B1 red-first, the pure half: the redaction is a function of the
    /// URL and a bounded kind, so no `reqwest::Error` Display can reach a
    /// detail string by any route.
    #[test]
    fn the_probe_failure_detail_is_built_from_a_redacted_url_and_a_bounded_kind() {
        let detail = probe_failure_detail(
            "https://svc:hunter2@internal-lb.corp:8443/healthz?token=abc",
            ProbeFailureKind::Connect,
        );
        assert!(!detail.contains("hunter2"), "{detail}");
        assert!(!detail.contains("token=abc"), "{detail}");
        assert!(!detail.contains("/healthz"), "{detail}");
        assert!(detail.contains("https://internal-lb.corp:8443"), "{detail}");
        assert!(detail.contains("connect"), "{detail}");

        // An unparseable URL renders as a constant rather than echoing
        // whatever an operator pasted into the key.
        let detail = probe_failure_detail("hunter2", ProbeFailureKind::Timeout);
        assert!(!detail.contains("hunter2"), "{detail}");
    }

    /// B4 red-first. A driver that has not produced an outcome yet, or
    /// whose outcome the soak considers stale, is an absence of evidence
    /// rather than evidence against the config. Mapping it to a failure
    /// meant a deployment pipeline that confirmed inside the driver's
    /// first interval got `{"verdict":"failed"}` for a good config.
    #[test]
    fn a_synthetic_driver_with_no_outcome_yet_abstains_rather_than_failing() {
        use sbproxy_observe::ComponentStatus;

        let absent = synthetic_probe_observation(
            ComponentStatus::Unhealthy,
            Some(sbproxy_observe::SYNTHETIC_NO_OUTCOME_DETAIL.to_string()),
        );
        assert_eq!(absent, None, "no outcome yet is an absence, not a failure");

        let stale = synthetic_probe_observation(
            ComponentStatus::Unhealthy,
            Some(format!(
                "{}: last_outcome_age_secs=400",
                sbproxy_observe::SYNTHETIC_STALE_DETAIL_PREFIX
            )),
        );
        assert_eq!(stale, None, "a stale reading is an absence too");

        // A driver that ran and genuinely failed is still a failure.
        let failed = synthetic_probe_observation(
            ComponentStatus::Unhealthy,
            Some("upstream_status_503".to_string()),
        );
        assert!(
            matches!(failed, Some(ProbeObservation::Unexpected(_))),
            "{failed:?}",
        );
        assert_eq!(
            synthetic_probe_observation(ComponentStatus::Healthy, Some("latency_ms=3".to_string())),
            Some(ProbeObservation::Ok),
        );
    }

    /// B4 red-first, the staleness window. `/readyz` uses the driver's
    /// own `effective_stale_after_secs()` (default `interval_secs * 3`);
    /// a hard-coded 60s meant a legal `interval_secs: 120` made every
    /// reading stale by the soak's clock and fresh by the probe's, so
    /// every verdict was `Failed` forever.
    #[test]
    fn the_soak_reads_the_drivers_own_staleness_window() {
        let config = sbproxy_config::SyntheticProbeConfig {
            enabled: true,
            interval_secs: 120,
            ..sbproxy_config::SyntheticProbeConfig::default()
        };
        assert_eq!(
            config.effective_stale_after_secs(),
            360,
            "the default is interval_secs * 3",
        );
        crate::synthetic::install_process_synthetic_state_for_test(
            sbproxy_observe::SyntheticProbeState::new(),
            std::time::Duration::from_secs(config.effective_stale_after_secs()),
        );
        assert_eq!(
            crate::synthetic::process_probe_stale_after(),
            Some(std::time::Duration::from_secs(360)),
            "the soak must not invent a window of its own",
        );
    }

    /// B3 red-first. The signal claims it catches an upstream repointed
    /// at a dead address. It may only pass when it actually looked at
    /// every origin: one observable healthy load balancer beside one
    /// `type: proxy` origin it cannot see is not evidence of health.
    #[test]
    fn an_origin_with_no_health_signal_abstains_rather_than_passing() {
        let sample = UpstreamHealthSample {
            unhealthy: Vec::new(),
            observed: 1,
            unobserved: vec!["shop/api".to_string()],
        };
        let outcome = upstream_health_signal(&soak(50), &sample);
        assert!(
            matches!(outcome, SignalOutcome::Abstain(_)),
            "a signal that could not see an origin must not report health: {outcome:?}",
        );
        assert!(
            outcome
                .detail()
                .expect("explains itself")
                .contains("shop/api"),
            "and it names the origin it could not see: {outcome:?}",
        );

        // Every origin observable and healthy is the only shape that
        // passes.
        let sample = UpstreamHealthSample {
            unhealthy: Vec::new(),
            observed: 2,
            unobserved: Vec::new(),
        };
        assert_eq!(
            upstream_health_signal(&soak(50), &sample),
            SignalOutcome::Pass
        );

        // An unhealthy upstream still wins outright, even beside an
        // origin nothing could observe.
        let sample = UpstreamHealthSample {
            unhealthy: vec!["shop/api#target-0".to_string()],
            observed: 1,
            unobserved: vec!["shop/web".to_string()],
        };
        let outcome = upstream_health_signal(&soak(50), &sample);
        assert!(matches!(outcome, SignalOutcome::Fail(_)), "{outcome:?}");
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

    /// WOR-2461. An immediate failure is reached inside the reload
    /// transaction, which holds the reload lock, and a revert re-enters
    /// that transaction. So the failure cannot act where it is
    /// discovered; it is left here for the supervisor, which runs
    /// outside the lock. Dropping it instead is what
    /// `auto_revert` silently missing the one failure the soak reaches
    /// with no traffic at all looks like.
    #[test]
    fn an_immediate_failure_is_left_for_the_supervisor_rather_than_dropped() {
        clear();
        let armed = ConfigSoakConfig {
            auto_revert: true,
            ..soak(50)
        };
        assert_eq!(
            arm(11, "digest-11", &["key_plane".to_string()], &armed),
            Some(SoakVerdict::Failed),
        );
        let pending = take_pending_verdict().expect("the failure is handed on, not dropped");
        assert_eq!(pending.revision, 11);
        assert_eq!(pending.digest, "digest-11");
        assert_eq!(pending.verdict, SoakVerdict::Failed);
        assert!(
            pending.auto_revert,
            "and it carries what the operator armed for this revision, not what the pipeline \
             declares by the time the supervisor gets to it",
        );
        assert!(
            take_pending_verdict().is_none(),
            "handed on once, acted on once: a second tick must not revert twice",
        );
        clear();
    }

    /// WOR-2461. A newer revision supersedes a pending immediate
    /// failure for exactly the reason it supersedes a window in flight:
    /// reverting because of a revision that is no longer serving would
    /// undo a change nothing has judged.
    #[test]
    fn a_newer_revision_supersedes_a_pending_immediate_failure() {
        clear();
        let armed = ConfigSoakConfig {
            auto_revert: true,
            ..soak(50)
        };
        assert_eq!(
            arm(11, "digest-11", &["key_plane".to_string()], &armed),
            Some(SoakVerdict::Failed),
        );
        assert_eq!(
            arm(12, "digest-12", &[], &armed),
            None,
            "a clean reload arms a window rather than reaching a verdict",
        );
        assert!(
            take_pending_verdict().is_none(),
            "revision 11 is not what this node is serving any more",
        );
        clear();
    }

    /// A node whose operator switched the soak off promotes on apply
    /// and reaches no failure, so it can never queue one, whatever a
    /// previous revision left behind.
    #[test]
    fn a_disabled_soak_leaves_nothing_pending() {
        clear();
        let armed = ConfigSoakConfig {
            auto_revert: true,
            ..soak(50)
        };
        assert_eq!(
            arm(11, "digest-11", &["key_plane".to_string()], &armed),
            Some(SoakVerdict::Failed),
        );
        let off = ConfigSoakConfig {
            enabled: false,
            ..armed
        };
        assert_eq!(
            arm(12, "digest-12", &[], &off),
            Some(SoakVerdict::Successful)
        );
        assert!(take_pending_verdict().is_none());
        clear();
    }
}
