// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The alert evaluation engine.
//!
//! [`channels`](super::channels) can deliver an alert and the rule modules can
//! decide whether a single reading breaches a threshold, but until now nothing
//! connected the two: the evaluators had no caller and no memory, so a
//! configured PagerDuty routing key opened no incident and a cleared condition
//! never resolved one. This module is the missing middle.
//!
//! [`AlertEngine::evaluate`] runs the built-in rules against a [`MetricReadings`]
//! snapshot and returns the alerts to dispatch this tick. It fires a rule the
//! first time it breaches, stays silent while it keeps breaching (so one
//! incident is opened, not one per tick), and emits exactly one `resolved`
//! alert when the condition clears. The engine is a pure state machine: the
//! caller does the sampling and the dispatching, which keeps the fire/recover
//! logic testable without a runtime or a live registry.
//!
//! [`sample_registry`] reads metric-backed inputs from both Prometheus
//! registries. Certificate expiry and circuit-breaker state stay explicit
//! fields on [`MetricReadings`], so the process that owns those resources can
//! inject clean snapshots without this crate reaching into runtime globals.

use std::collections::{HashMap, HashSet, VecDeque};

use super::burn_rate::{peak_availability_burn_rate, replay_and_evaluate, MinuteSample};
use super::channels::Alert;
use super::error_rate::{check_error_rate_spike, ErrorRateRule};
use super::rate_limit::{check_rate_limit_approaching, RateLimitRule};
use super::rules::{check_budget_exhaustion, check_cert_expiry, check_circuit_breaker_trip};
use super::slo::{check_slo_violation, SloRule};

/// Origin label for the aggregate provider-error-burn rule. The rule spans
/// every provider rather than one upstream origin, so it carries a fixed scope
/// name instead of a hostname.
pub const PROVIDER_ERROR_SCOPE: &str = "ai_providers";
/// Origin label for proxy-wide latency and rate-limit rules.
pub const PROXY_SCOPE: &str = "proxy";
const BUDGET_FIRING_KEY: &str = "budget_exhaustion";
const PROVIDER_ERROR_FIRING_KEY: &str = "error_rate_spike:origin=ai_providers";
const SLO_FIRING_KEY: &str = "latency_slo:origin=proxy";
const RATE_LIMIT_FIRING_KEY: &str = "rate_limit_approaching:origin=proxy";
const BURN_RATE_FIRING_KEY: &str = "burn_rate:scope=substrate";
const BURN_RATE_HISTORY_CAPACITY: usize = 24 * 60;

/// Earliest ACME certificate expiry supplied by the process runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertExpiryReading {
    /// Certificate hostname.
    pub hostname: String,
    /// Whole days until expiry, rounded up by the ACME input seam.
    pub days_remaining: u32,
}

/// Runtime-neutral circuit-breaker states supplied by the owning process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Requests flow normally.
    Closed,
    /// Requests are rejected while the upstream recovers.
    Open,
    /// Probe requests are testing recovery.
    HalfOpen,
}

impl CircuitBreakerState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// One configured circuit breaker's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerReading {
    /// Stable target identity.
    pub origin: String,
    /// Current breaker state.
    pub state: CircuitBreakerState,
}

/// Live metric values the built-in rules evaluate against.
///
/// A field left `None` disables its rule for that tick, which is how a
/// deployment with channels configured but nothing breaching stays silent.
#[derive(Debug, Clone, Default)]
pub struct MetricReadings {
    /// Highest budget utilization across every budget scope, in `[0, 1]`.
    pub budget_utilization: Option<f64>,
    /// Fraction of AI provider attempts in the last interval that errored, in
    /// `[0, 1]`. `None` when no attempts were made in the window, so a quiet
    /// gateway does not read as 0% and does not recover a real alert.
    pub provider_error_rate: Option<f64>,
    /// Provider attempts observed in the same interval as
    /// [`Self::provider_error_rate`]. Windows below the configured floor are
    /// inactive and cannot fire or resolve the provider-error rule.
    pub provider_attempts: u64,
    /// Aggregate request p99 latency for the latest sampling window, in
    /// milliseconds.
    pub p99_latency_ms: Option<f64>,
    /// Rate-limit rejections observed in the latest sampling window. `None`
    /// when no rate-limit decision series is available.
    pub rate_limit_rejections: Option<u64>,
    /// All rate-limit decisions observed in the same window as
    /// [`Self::rate_limit_rejections`].
    pub rate_limit_decisions: u64,
    /// Soonest certificate expiry in the active ACME store.
    pub cert_expiry: Option<CertExpiryReading>,
    /// Complete snapshot of configured circuit breakers. `None` means the
    /// input source was unavailable; an empty vector means no breakers are
    /// configured.
    pub circuit_breakers: Option<Vec<CircuitBreakerReading>>,
    /// One complete minute of proxy request traffic. The engine retains a
    /// process-local 24-hour ring and does not persist it across restart.
    pub minute_sample: Option<MinuteSample>,
}

/// Thresholds for the built-in rules.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Budget utilization thresholds, ascending; the last is critical.
    pub budget_thresholds: Vec<f64>,
    /// Provider error-burn threshold in `[0, 1]`. A window whose error
    /// fraction exceeds this fires; twice this is critical.
    pub provider_error_threshold: f64,
    /// Minimum provider attempts required before an error-rate window is
    /// active. This prevents sparse traffic from paging on noisy fractions.
    pub provider_error_min_attempts: u64,
    /// Proxy-wide p99 latency threshold, in milliseconds.
    pub slo_p99_threshold_ms: f64,
    /// Fraction of rate-limit decisions that may reject before alerting.
    pub rate_limit_rejection_threshold: f64,
    /// Certificate-expiry warning tiers, from least to most urgent.
    pub cert_expiry_warn_days: Vec<u32>,
    /// Availability target used to turn error ratios into burn rates.
    pub burn_rate_slo_target: f64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            budget_thresholds: vec![0.80, 0.95],
            provider_error_threshold: 0.10,
            provider_error_min_attempts: 10,
            slo_p99_threshold_ms: 200.0,
            rate_limit_rejection_threshold: 0.80,
            cert_expiry_warn_days: vec![30, 7],
            burn_rate_slo_target: 0.99,
        }
    }
}

/// Current state of one rule's latest evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEvaluationState {
    /// No usable reading was available or the minimum sample floor was not met.
    Inactive,
    /// The rule evaluated against an active sample and did not breach.
    Ok,
    /// The rule evaluated against an active sample and is breaching.
    Firing,
}

/// Latest evaluation details published for operator-facing runtime state.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuleEvaluation {
    /// Stable rule name.
    pub rule: String,
    /// Latest state.
    pub state: RuleEvaluationState,
    /// Latest metric reading, when one was available.
    pub reading: Option<f64>,
    /// Samples contributing to the reading, when the rule has a sample floor.
    pub sample_count: Option<u64>,
    /// RFC 3339 evaluation time.
    pub evaluated_at: String,
}

/// Evaluates the built-in rules and tracks per-rule firing state so each
/// condition fires once and recovers once.
#[derive(Debug)]
pub struct AlertEngine {
    config: EngineConfig,
    /// Rule instances currently firing, keyed by a stable identity, holding the
    /// alert exactly as first fired so the recovery notification carries the
    /// same labels (and therefore the same PagerDuty deduplication key).
    firing: HashMap<String, Alert>,
    latest_evaluations: Vec<RuleEvaluation>,
    /// Minute-resolution history is deliberately process-local: restarting
    /// begins a fresh observation window. The hard cap prevents alerting from
    /// growing with process uptime.
    burn_rate_samples: VecDeque<MinuteSample>,
}

impl AlertEngine {
    /// Build an engine with the given thresholds.
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            firing: HashMap::new(),
            latest_evaluations: Vec::new(),
            burn_rate_samples: VecDeque::with_capacity(BURN_RATE_HISTORY_CAPACITY),
        }
    }

    /// Evaluate every built-in rule against `readings` and return the alerts to
    /// dispatch this tick: one per rule that has just started breaching, plus a
    /// `resolved` alert for each rule that was firing and has now cleared.
    ///
    /// The caller passes the returned alerts to an
    /// [`AlertDispatcher`](super::channels::AlertDispatcher). Calling this again
    /// with the same breaching reading returns nothing, which is what holds a
    /// single incident open instead of reopening one every interval.
    pub fn evaluate(&mut self, readings: &MetricReadings) -> Vec<Alert> {
        let mut to_fire = Vec::new();
        let evaluated_at = chrono::Utc::now().to_rfc3339();
        let mut evaluations = Vec::with_capacity(7);

        match readings.budget_utilization {
            Some(utilization) => {
                let alert = check_budget_exhaustion(utilization, &self.config.budget_thresholds);
                let state = if alert.is_some() {
                    RuleEvaluationState::Firing
                } else {
                    RuleEvaluationState::Ok
                };
                self.apply_active_rule(BUDGET_FIRING_KEY, alert, &mut to_fire);
                evaluations.push(RuleEvaluation {
                    rule: "budget_exhaustion".to_string(),
                    state,
                    reading: Some(utilization),
                    sample_count: None,
                    evaluated_at: evaluated_at.clone(),
                });
            }
            None => evaluations.push(RuleEvaluation {
                rule: "budget_exhaustion".to_string(),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                evaluated_at: evaluated_at.clone(),
            }),
        }

        let provider_active = readings.provider_attempts >= self.config.provider_error_min_attempts;
        match (readings.provider_error_rate, provider_active) {
            (Some(rate), true) => {
                let rule = ErrorRateRule {
                    origin: PROVIDER_ERROR_SCOPE.to_string(),
                    threshold: self.config.provider_error_threshold,
                };
                let alert = check_error_rate_spike(&rule, rate);
                let state = if alert.is_some() {
                    RuleEvaluationState::Firing
                } else {
                    RuleEvaluationState::Ok
                };
                self.apply_active_rule(PROVIDER_ERROR_FIRING_KEY, alert, &mut to_fire);
                evaluations.push(RuleEvaluation {
                    rule: "error_rate_spike".to_string(),
                    state,
                    reading: Some(rate),
                    sample_count: Some(readings.provider_attempts),
                    evaluated_at: evaluated_at.clone(),
                });
            }
            (reading, false) | (reading @ None, true) => evaluations.push(RuleEvaluation {
                rule: "error_rate_spike".to_string(),
                state: RuleEvaluationState::Inactive,
                reading,
                sample_count: Some(readings.provider_attempts),
                evaluated_at: evaluated_at.clone(),
            }),
        }

        match readings.minute_sample {
            Some(sample) => {
                if self.burn_rate_samples.len() == BURN_RATE_HISTORY_CAPACITY {
                    self.burn_rate_samples.pop_front();
                }
                self.burn_rate_samples.push_back(sample);
                let samples: Vec<MinuteSample> = self.burn_rate_samples.iter().copied().collect();
                let snapshot = replay_and_evaluate(&samples, self.config.burn_rate_slo_target);
                let objectives: Vec<String> = snapshot
                    .fired_names()
                    .into_iter()
                    .filter(|name| name.starts_with("SBPROXY-SUBSTRATE-AVAIL-"))
                    .collect();
                let alert = (!objectives.is_empty()).then(|| Alert {
                    rule: "burn_rate".to_string(),
                    severity: "critical".to_string(),
                    message: format!(
                        "Availability error budget is burning across {}",
                        objectives.join(", ")
                    ),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    labels: HashMap::from([
                        ("scope".to_string(), "substrate".to_string()),
                        ("objectives".to_string(), objectives.join(",")),
                    ]),
                    resolved: false,
                });
                let state = if alert.is_some() {
                    RuleEvaluationState::Firing
                } else {
                    RuleEvaluationState::Ok
                };
                self.apply_active_rule(BURN_RATE_FIRING_KEY, alert, &mut to_fire);
                evaluations.push(RuleEvaluation {
                    rule: "burn_rate".to_string(),
                    state,
                    reading: Some(peak_availability_burn_rate(
                        &samples,
                        self.config.burn_rate_slo_target,
                    )),
                    sample_count: Some(samples.len() as u64),
                    evaluated_at: evaluated_at.clone(),
                });
            }
            None => evaluations.push(RuleEvaluation {
                rule: "burn_rate".to_string(),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: Some(self.burn_rate_samples.len() as u64),
                evaluated_at: evaluated_at.clone(),
            }),
        }

        match readings.p99_latency_ms {
            Some(p99_ms) => {
                let alert = check_slo_violation(
                    &SloRule {
                        origin: PROXY_SCOPE.to_string(),
                        p99_threshold_ms: self.config.slo_p99_threshold_ms,
                    },
                    p99_ms,
                );
                let state = if alert.is_some() {
                    RuleEvaluationState::Firing
                } else {
                    RuleEvaluationState::Ok
                };
                self.apply_active_rule(SLO_FIRING_KEY, alert, &mut to_fire);
                evaluations.push(RuleEvaluation {
                    rule: "latency_slo".to_string(),
                    state,
                    reading: Some(p99_ms),
                    sample_count: None,
                    evaluated_at: evaluated_at.clone(),
                });
            }
            None => evaluations.push(RuleEvaluation {
                rule: "latency_slo".to_string(),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                evaluated_at: evaluated_at.clone(),
            }),
        }

        match (
            readings.rate_limit_rejections,
            readings.rate_limit_decisions,
        ) {
            (Some(rejections), decisions) if decisions > 0 => {
                let rejection_fraction =
                    (rejections.min(decisions) as f64 / decisions as f64).clamp(0.0, 1.0);
                let alert = check_rate_limit_approaching(
                    &RateLimitRule {
                        origin: PROXY_SCOPE.to_string(),
                        warn_threshold: self.config.rate_limit_rejection_threshold,
                    },
                    rejection_fraction,
                );
                let state = if alert.is_some() {
                    RuleEvaluationState::Firing
                } else {
                    RuleEvaluationState::Ok
                };
                self.apply_active_rule(RATE_LIMIT_FIRING_KEY, alert, &mut to_fire);
                evaluations.push(RuleEvaluation {
                    rule: "rate_limit_approaching".to_string(),
                    state,
                    reading: Some(rejection_fraction),
                    sample_count: Some(decisions),
                    evaluated_at: evaluated_at.clone(),
                });
            }
            (rejections, decisions) => evaluations.push(RuleEvaluation {
                rule: "rate_limit_approaching".to_string(),
                state: RuleEvaluationState::Inactive,
                reading: rejections.map(|_| 0.0),
                sample_count: Some(decisions),
                evaluated_at: evaluated_at.clone(),
            }),
        }

        match &readings.cert_expiry {
            Some(cert) => {
                let mut alert =
                    check_cert_expiry(cert.days_remaining, &self.config.cert_expiry_warn_days);
                if let Some(alert) = alert.as_mut() {
                    alert
                        .labels
                        .insert("origin".to_string(), cert.hostname.clone());
                }
                let key = format!("cert_expiry:origin={}", cert.hostname);
                let stale_keys: Vec<String> = self
                    .firing
                    .keys()
                    .filter(|firing_key| firing_key.starts_with("cert_expiry:origin="))
                    .filter(|firing_key| *firing_key != &key)
                    .cloned()
                    .collect();
                for stale_key in stale_keys {
                    self.apply_active_rule(&stale_key, None, &mut to_fire);
                }
                let state = if alert.is_some() {
                    RuleEvaluationState::Firing
                } else {
                    RuleEvaluationState::Ok
                };
                self.apply_active_rule(&key, alert, &mut to_fire);
                evaluations.push(RuleEvaluation {
                    rule: "cert_expiry".to_string(),
                    state,
                    reading: Some(f64::from(cert.days_remaining)),
                    sample_count: None,
                    evaluated_at: evaluated_at.clone(),
                });
            }
            None => evaluations.push(RuleEvaluation {
                rule: "cert_expiry".to_string(),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                evaluated_at: evaluated_at.clone(),
            }),
        }

        match &readings.circuit_breakers {
            Some(breakers) => {
                let mut observed_keys = HashSet::with_capacity(breakers.len());
                let mut tripped_count = 0_u64;
                for breaker in breakers {
                    let key = format!("circuit_breaker_trip:origin={}", breaker.origin);
                    observed_keys.insert(key.clone());
                    let alert = match breaker.state {
                        CircuitBreakerState::Closed => None,
                        CircuitBreakerState::Open => {
                            tripped_count += 1;
                            check_circuit_breaker_trip(
                                &breaker.origin,
                                CircuitBreakerState::Closed.as_str(),
                                breaker.state.as_str(),
                            )
                        }
                        CircuitBreakerState::HalfOpen => {
                            tripped_count += 1;
                            check_circuit_breaker_trip(
                                &breaker.origin,
                                CircuitBreakerState::Open.as_str(),
                                breaker.state.as_str(),
                            )
                        }
                    };
                    self.apply_active_rule(&key, alert, &mut to_fire);
                }

                // A full snapshot also tells us when a breaker disappeared on
                // reload. Resolve any incident for an identity no longer
                // present rather than leaking it forever.
                let stale_keys: Vec<String> = self
                    .firing
                    .keys()
                    .filter(|key| key.starts_with("circuit_breaker_trip:origin="))
                    .filter(|key| !observed_keys.contains(*key))
                    .cloned()
                    .collect();
                for key in stale_keys {
                    self.apply_active_rule(&key, None, &mut to_fire);
                }

                evaluations.push(RuleEvaluation {
                    rule: "circuit_breaker_trip".to_string(),
                    state: if tripped_count > 0 {
                        RuleEvaluationState::Firing
                    } else {
                        RuleEvaluationState::Ok
                    },
                    reading: Some(tripped_count as f64),
                    sample_count: Some(breakers.len() as u64),
                    evaluated_at: evaluated_at.clone(),
                });
            }
            None => evaluations.push(RuleEvaluation {
                rule: "circuit_breaker_trip".to_string(),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                evaluated_at: evaluated_at.clone(),
            }),
        }

        self.latest_evaluations = evaluations;
        to_fire
    }

    fn apply_active_rule(&mut self, key: &str, alert: Option<Alert>, to_fire: &mut Vec<Alert>) {
        match alert {
            Some(alert) => {
                debug_assert_eq!(firing_key(&alert), key);
                if !self.firing.contains_key(key) {
                    to_fire.push(alert.clone());
                    self.firing.insert(key.to_string(), alert);
                }
            }
            None => {
                if let Some(mut alert) = self.firing.remove(key) {
                    alert.resolved = true;
                    alert.timestamp = chrono::Utc::now().to_rfc3339();
                    to_fire.push(alert);
                }
            }
        }
    }

    /// Latest state for each built-in rule, in stable display order.
    pub fn latest_evaluations(&self) -> &[RuleEvaluation] {
        &self.latest_evaluations
    }

    /// Number of rule instances currently held open. For tests and diagnostics.
    pub fn firing_count(&self) -> usize {
        self.firing.len()
    }

    /// Number of process-local minute samples retained for burn-rate replay.
    pub fn burn_rate_sample_count(&self) -> usize {
        self.burn_rate_samples.len()
    }
}

/// Stable identity for a firing rule instance.
///
/// The rule name plus its entity labels, deliberately excluding the fluctuating
/// value labels (`utilization`, `observed_rate`, `threshold`). Those change on
/// every sample; keying on them would treat each tick as a fresh instance and
/// reopen an incident every interval instead of holding one open to recovery.
fn firing_key(alert: &Alert) -> String {
    let mut key = alert.rule.clone();
    for label in ["origin", "provider", "tenant", "workspace", "scope"] {
        if let Some(value) = alert.labels.get(label) {
            key.push(':');
            key.push_str(label);
            key.push('=');
            key.push_str(value);
        }
    }
    key
}

/// The two monotonic provider counters, snapshotted so a burn rate can be taken
/// as a delta between ticks.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ProviderCounters {
    /// Cumulative `sbproxy_ai_provider_errors_total` across every label set.
    pub errors: f64,
    /// Cumulative `sbproxy_ai_provider_attempts_total` across every label set.
    pub attempts: f64,
}

/// Monotonic proxy request counters used to build one-minute burn samples.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RequestCounters {
    /// All completed proxy requests.
    pub requests: f64,
    /// Completed requests with a 5xx status.
    pub errors: f64,
}

/// Monotonic rate-limit decision counters.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RateLimitCounters {
    /// All middleware rate-limit decisions.
    pub decisions: f64,
    /// Route- or tenant-throttling decisions.
    pub rejections: f64,
}

/// One cumulative histogram bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct HistogramBucket {
    /// Inclusive bucket ceiling in seconds.
    pub upper_bound_seconds: f64,
    /// Cumulative observations at or below the ceiling.
    pub cumulative_count: u64,
}

/// Cumulative histogram state retained across alert-loop ticks.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HistogramCounters {
    /// Total observations across every label set.
    pub sample_count: u64,
    /// Aggregated cumulative buckets ordered by ceiling.
    pub buckets: Vec<HistogramBucket>,
}

/// One scrape of every live input available from the metric registries.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RegistrySnapshot {
    /// AI provider attempts and failures.
    pub provider_counters: ProviderCounters,
    /// Highest active budget utilization.
    pub budget_utilization: Option<f64>,
    /// Whether the proxy request counter family is available. This separates
    /// a real idle minute from an absent input source.
    pub request_metrics_present: bool,
    /// Proxy requests and 5xx responses.
    pub request_counters: RequestCounters,
    /// Aggregate p99 request latency in milliseconds.
    pub p99_latency_ms: Option<f64>,
    /// Cumulative latency buckets used to derive a windowed p99.
    pub request_latency: HistogramCounters,
    /// Rate-limit decisions and rejections.
    pub rate_limit_counters: RateLimitCounters,
}

/// Read every metric-backed alert input from both Prometheus registries.
///
/// `ProxyMetrics` owns request counters and latency in its private registry;
/// ad-hoc AI and rate-limit metrics use the process-global default registry.
/// Sampling both mirrors the `/metrics` renderer and prevents either family
/// from silently appearing absent to alerting.
pub fn sample_registry() -> RegistrySnapshot {
    let mut snapshot = RegistrySnapshot::default();
    let mut families = crate::metrics::metrics().registry.gather();
    families.extend(prometheus::gather());

    for family in families {
        match family.name() {
            "sbproxy_ai_provider_errors_total" => {
                snapshot.provider_counters.errors = sum_counter(&family);
            }
            "sbproxy_ai_provider_attempts_total" => {
                snapshot.provider_counters.attempts = sum_counter(&family);
            }
            "sbproxy_ai_budget_utilization_ratio" => {
                snapshot.budget_utilization = Some(max_gauge(&family));
            }
            "sbproxy_requests_total" => {
                snapshot.request_metrics_present = true;
                for metric in family.get_metric() {
                    let count = metric.get_counter().value();
                    snapshot.request_counters.requests += count;
                    if label_value(metric, "status")
                        .and_then(|status| status.parse::<u16>().ok())
                        .is_some_and(|status| status >= 500)
                    {
                        snapshot.request_counters.errors += count;
                    }
                }
            }
            "sbproxy_origin_request_duration_seconds" => {
                snapshot.request_latency = histogram_counters(&family);
                snapshot.p99_latency_ms =
                    histogram_quantile_cumulative_ms(&snapshot.request_latency, 0.99);
            }
            "sbproxy_rate_limit_decisions_total" => {
                for metric in family.get_metric() {
                    let count = metric.get_counter().value();
                    snapshot.rate_limit_counters.decisions += count;
                    if matches!(
                        label_value(metric, "result"),
                        Some("throttle_route" | "throttle_tenant")
                    ) {
                        snapshot.rate_limit_counters.rejections += count;
                    }
                }
            }
            _ => {}
        }
    }

    snapshot
}

fn label_value<'a>(metric: &'a prometheus::proto::Metric, name: &str) -> Option<&'a str> {
    metric
        .get_label()
        .iter()
        .find(|label| label.name() == name)
        .map(|label| label.value())
}

fn histogram_counters(family: &prometheus::proto::MetricFamily) -> HistogramCounters {
    let sample_count: u64 = family
        .get_metric()
        .iter()
        .map(|metric| metric.get_histogram().sample_count())
        .sum();

    let mut buckets: HashMap<u64, (f64, u64)> = HashMap::new();
    for metric in family.get_metric() {
        for bucket in metric.get_histogram().get_bucket() {
            let upper_bound = bucket.upper_bound();
            buckets
                .entry(upper_bound.to_bits())
                .and_modify(|(_, count)| *count += bucket.cumulative_count())
                .or_insert((upper_bound, bucket.cumulative_count()));
        }
    }
    let mut buckets: Vec<(f64, u64)> = buckets.into_values().collect();
    buckets.sort_by(|left, right| left.0.total_cmp(&right.0));
    HistogramCounters {
        sample_count,
        buckets: buckets
            .into_iter()
            .map(|(upper_bound_seconds, cumulative_count)| HistogramBucket {
                upper_bound_seconds,
                cumulative_count,
            })
            .collect(),
    }
}

fn histogram_quantile_cumulative_ms(counters: &HistogramCounters, quantile: f64) -> Option<f64> {
    histogram_quantile_from_buckets_ms(counters.sample_count, &counters.buckets, quantile)
}

/// Approximate a histogram quantile from observations added since `previous`.
///
/// Counter resets and idle windows return `None`. Bucket deltas are clamped so
/// a label series disappearing between scrapes cannot underflow.
pub fn histogram_quantile_delta_ms(
    previous: &HistogramCounters,
    now: &HistogramCounters,
    quantile: f64,
) -> Option<f64> {
    let sample_count = now.sample_count.checked_sub(previous.sample_count)?;
    if sample_count == 0 {
        return None;
    }
    let previous_buckets: HashMap<u64, u64> = previous
        .buckets
        .iter()
        .map(|bucket| {
            (
                bucket.upper_bound_seconds.to_bits(),
                bucket.cumulative_count,
            )
        })
        .collect();
    let buckets: Vec<HistogramBucket> = now
        .buckets
        .iter()
        .map(|bucket| HistogramBucket {
            upper_bound_seconds: bucket.upper_bound_seconds,
            cumulative_count: bucket.cumulative_count.saturating_sub(
                previous_buckets
                    .get(&bucket.upper_bound_seconds.to_bits())
                    .copied()
                    .unwrap_or_default(),
            ),
        })
        .collect();
    histogram_quantile_from_buckets_ms(sample_count, &buckets, quantile)
}

fn histogram_quantile_from_buckets_ms(
    sample_count: u64,
    buckets: &[HistogramBucket],
    quantile: f64,
) -> Option<f64> {
    if sample_count == 0 {
        return None;
    }
    let rank = (sample_count as f64 * quantile.clamp(0.0, 1.0)).ceil() as u64;
    buckets
        .iter()
        .find(|bucket| bucket.cumulative_count >= rank)
        .or_else(|| buckets.last())
        .map(|bucket| bucket.upper_bound_seconds * 1_000.0)
}

fn sum_counter(family: &prometheus::proto::MetricFamily) -> f64 {
    family
        .get_metric()
        .iter()
        .map(|m| m.get_counter().value())
        .sum()
}

fn max_gauge(family: &prometheus::proto::MetricFamily) -> f64 {
    family
        .get_metric()
        .iter()
        .map(|m| m.get_gauge().value())
        .fold(0.0_f64, f64::max)
}

/// Turn two counter snapshots into the error-burn fraction for the interval
/// between them.
///
/// Returns `None` when no attempts were made in the window: a gateway that
/// served nothing has no error rate, and reporting 0% there would resolve a
/// real alert the moment traffic paused.
pub fn error_burn(prev: ProviderCounters, now: ProviderCounters) -> Option<f64> {
    let attempts = now.attempts - prev.attempts;
    if attempts <= 0.0 {
        return None;
    }
    let errors = (now.errors - prev.errors).max(0.0);
    Some((errors / attempts).clamp(0.0, 1.0))
}

/// Number of provider attempts observed between two monotonic-counter
/// snapshots. Counter resets clamp to zero.
pub fn provider_attempt_delta(prev: ProviderCounters, now: ProviderCounters) -> u64 {
    (now.attempts - prev.attempts).max(0.0) as u64
}

/// Turn monotonic request counters into one complete minute of burn history.
///
/// Idle windows return a zero-request sample so the bounded ring advances with
/// wall-clock minutes and old failures eventually age out. Counter resets
/// return `None`; a missing latency histogram does not discard availability
/// data and records `0ms` for the unused latency field.
pub fn minute_sample_delta(
    prev: RequestCounters,
    now: RequestCounters,
    p99_latency_ms: Option<f64>,
) -> Option<MinuteSample> {
    let requests = now.requests - prev.requests;
    if requests < 0.0 {
        return None;
    }
    let requests = requests as u64;
    let errors = (now.errors - prev.errors).max(0.0) as u64;
    Some(MinuteSample {
        requests,
        errors: errors.min(requests),
        p99_ms: p99_latency_ms.unwrap_or_default(),
    })
}

/// Rate-limit rejection and decision deltas for the latest window.
///
/// Returns `(rejections, decisions)`, or `None` for an idle/reset window.
pub fn rate_limit_delta(prev: RateLimitCounters, now: RateLimitCounters) -> Option<(u64, u64)> {
    let decisions = now.decisions - prev.decisions;
    if decisions <= 0.0 {
        return None;
    }
    let decisions = decisions as u64;
    let rejections = (now.rejections - prev.rejections).max(0.0) as u64;
    Some((rejections.min(decisions), decisions))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readings(budget: Option<f64>, errors: Option<f64>) -> MetricReadings {
        MetricReadings {
            budget_utilization: budget,
            provider_error_rate: errors,
            provider_attempts: errors.map(|_| 10).unwrap_or(0),
            p99_latency_ms: None,
            rate_limit_rejections: None,
            rate_limit_decisions: 0,
            cert_expiry: None,
            circuit_breakers: None,
            minute_sample: None,
        }
    }

    fn provider_readings(rate: f64, attempts: u64) -> MetricReadings {
        MetricReadings {
            budget_utilization: None,
            provider_error_rate: Some(rate),
            provider_attempts: attempts,
            p99_latency_ms: None,
            rate_limit_rejections: None,
            rate_limit_decisions: 0,
            cert_expiry: None,
            circuit_breakers: None,
            minute_sample: None,
        }
    }

    #[test]
    fn a_breaching_rule_fires_once_then_stays_quiet() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        // First breach fires.
        let fired = engine.evaluate(&readings(Some(0.97), None));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "budget_exhaustion");
        assert_eq!(fired[0].severity, "critical");
        assert!(!fired[0].resolved);

        // Still breaching: no new alert.
        assert!(engine.evaluate(&readings(Some(0.98), None)).is_empty());
        assert_eq!(engine.firing_count(), 1);
    }

    #[test]
    fn a_cleared_rule_emits_exactly_one_resolved_alert() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        engine.evaluate(&readings(Some(0.97), None));

        let recovered = engine.evaluate(&readings(Some(0.10), None));
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].resolved);
        assert_eq!(recovered[0].rule, "budget_exhaustion");
        assert_eq!(engine.firing_count(), 0);

        // Recovery is emitted once, not on every subsequent quiet tick.
        assert!(engine.evaluate(&readings(Some(0.10), None)).is_empty());
    }

    #[test]
    fn config_with_no_breaching_reading_does_nothing() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        assert!(engine.evaluate(&readings(Some(0.10), Some(0.0))).is_empty());
        assert!(engine.evaluate(&readings(None, None)).is_empty());
        assert_eq!(engine.firing_count(), 0);
    }

    #[test]
    fn absent_inputs_publish_all_seven_rules_as_inactive_without_firing() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        assert!(engine.evaluate(&MetricReadings::default()).is_empty());
        assert_eq!(
            engine
                .latest_evaluations()
                .iter()
                .map(|evaluation| (evaluation.rule.as_str(), evaluation.state))
                .collect::<Vec<_>>(),
            vec![
                ("budget_exhaustion", RuleEvaluationState::Inactive),
                ("error_rate_spike", RuleEvaluationState::Inactive),
                ("burn_rate", RuleEvaluationState::Inactive),
                ("latency_slo", RuleEvaluationState::Inactive),
                ("rate_limit_approaching", RuleEvaluationState::Inactive),
                ("cert_expiry", RuleEvaluationState::Inactive),
                ("circuit_breaker_trip", RuleEvaluationState::Inactive),
            ]
        );
        assert_eq!(engine.firing_count(), 0);
    }

    #[test]
    fn latency_slo_fires_once_and_resolves_once() {
        let mut engine = AlertEngine::new(EngineConfig {
            slo_p99_threshold_ms: 100.0,
            ..EngineConfig::default()
        });
        let breach = MetricReadings {
            p99_latency_ms: Some(250.0),
            ..MetricReadings::default()
        };

        let fired = engine.evaluate(&breach);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "latency_slo");
        assert!(engine.evaluate(&breach).is_empty());

        let healthy = MetricReadings {
            p99_latency_ms: Some(50.0),
            ..MetricReadings::default()
        };
        let resolved = engine.evaluate(&healthy);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].rule, "latency_slo");
        assert!(resolved[0].resolved);
        assert!(engine.evaluate(&healthy).is_empty());
    }

    #[test]
    fn rate_limit_rejections_fire_once_and_resolve_once() {
        let mut engine = AlertEngine::new(EngineConfig {
            rate_limit_rejection_threshold: 0.80,
            ..EngineConfig::default()
        });
        let breach = MetricReadings {
            rate_limit_rejections: Some(9),
            rate_limit_decisions: 10,
            ..MetricReadings::default()
        };

        let fired = engine.evaluate(&breach);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "rate_limit_approaching");
        assert!(engine.evaluate(&breach).is_empty());

        let healthy = MetricReadings {
            rate_limit_rejections: Some(1),
            rate_limit_decisions: 10,
            ..MetricReadings::default()
        };
        let resolved = engine.evaluate(&healthy);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
        assert_eq!(resolved[0].rule, "rate_limit_approaching");
        assert!(engine.evaluate(&healthy).is_empty());
    }

    #[test]
    fn rate_limit_rule_is_inactive_without_decisions() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let no_decisions = MetricReadings {
            rate_limit_rejections: Some(0),
            rate_limit_decisions: 0,
            ..MetricReadings::default()
        };

        assert!(engine.evaluate(&no_decisions).is_empty());
        let evaluation = engine
            .latest_evaluations()
            .iter()
            .find(|evaluation| evaluation.rule == "rate_limit_approaching")
            .unwrap();
        assert_eq!(evaluation.state, RuleEvaluationState::Inactive);
    }

    #[test]
    fn near_expiry_certificate_fires_once_and_resolves_once() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let near_expiry = MetricReadings {
            cert_expiry: Some(CertExpiryReading {
                hostname: "near-expiry.example".to_string(),
                days_remaining: 6,
            }),
            ..MetricReadings::default()
        };

        let fired = engine.evaluate(&near_expiry);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "cert_expiry");
        assert_eq!(fired[0].labels["origin"], "near-expiry.example");
        assert!(engine.evaluate(&near_expiry).is_empty());

        let renewed = MetricReadings {
            cert_expiry: Some(CertExpiryReading {
                hostname: "near-expiry.example".to_string(),
                days_remaining: 90,
            }),
            ..MetricReadings::default()
        };
        let resolved = engine.evaluate(&renewed);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
        assert_eq!(resolved[0].labels["origin"], "near-expiry.example");
        assert!(engine.evaluate(&renewed).is_empty());
    }

    #[test]
    fn absent_certificate_input_is_inactive_and_preserves_an_open_incident() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let near_expiry = MetricReadings {
            cert_expiry: Some(CertExpiryReading {
                hostname: "near-expiry.example".to_string(),
                days_remaining: 6,
            }),
            ..MetricReadings::default()
        };
        assert_eq!(engine.evaluate(&near_expiry).len(), 1);

        assert!(engine.evaluate(&MetricReadings::default()).is_empty());
        assert_eq!(engine.firing_count(), 1);
        let evaluation = engine
            .latest_evaluations()
            .iter()
            .find(|evaluation| evaluation.rule == "cert_expiry")
            .unwrap();
        assert_eq!(evaluation.state, RuleEvaluationState::Inactive);
    }

    #[test]
    fn a_new_earliest_certificate_resolves_the_previous_identity() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let first = MetricReadings {
            cert_expiry: Some(CertExpiryReading {
                hostname: "old.example".to_string(),
                days_remaining: 6,
            }),
            ..MetricReadings::default()
        };
        assert_eq!(engine.evaluate(&first).len(), 1);

        let after_renewal = MetricReadings {
            cert_expiry: Some(CertExpiryReading {
                hostname: "next.example".to_string(),
                days_remaining: 90,
            }),
            ..MetricReadings::default()
        };
        let resolved = engine.evaluate(&after_renewal);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
        assert_eq!(resolved[0].labels["origin"], "old.example");
        assert_eq!(engine.firing_count(), 0);
    }

    #[test]
    fn open_circuit_breaker_fires_once_and_closed_resolves_once() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let open = MetricReadings {
            circuit_breakers: Some(vec![CircuitBreakerReading {
                origin: "https://upstream.example#0".to_string(),
                state: CircuitBreakerState::Open,
            }]),
            ..MetricReadings::default()
        };

        let fired = engine.evaluate(&open);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "circuit_breaker_trip");
        assert_eq!(fired[0].labels["origin"], "https://upstream.example#0");
        assert!(engine.evaluate(&open).is_empty());

        let closed = MetricReadings {
            circuit_breakers: Some(vec![CircuitBreakerReading {
                origin: "https://upstream.example#0".to_string(),
                state: CircuitBreakerState::Closed,
            }]),
            ..MetricReadings::default()
        };
        let resolved = engine.evaluate(&closed);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
        assert_eq!(resolved[0].rule, "circuit_breaker_trip");
        assert!(engine.evaluate(&closed).is_empty());
    }

    #[test]
    fn half_open_breaker_stays_firing_without_resolve_retrigger_flapping() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let reading = |state| MetricReadings {
            circuit_breakers: Some(vec![CircuitBreakerReading {
                origin: "workspace/origin#target-0".to_string(),
                state,
            }]),
            ..MetricReadings::default()
        };

        let fired = engine.evaluate(&reading(CircuitBreakerState::Open));
        assert_eq!(fired.len(), 1);
        assert!(!fired[0].resolved);

        assert!(engine
            .evaluate(&reading(CircuitBreakerState::HalfOpen))
            .is_empty());
        assert_eq!(engine.firing_count(), 1);
        let evaluation = engine
            .latest_evaluations()
            .iter()
            .find(|evaluation| evaluation.rule == "circuit_breaker_trip")
            .unwrap();
        assert_eq!(evaluation.state, RuleEvaluationState::Firing);

        assert!(engine
            .evaluate(&reading(CircuitBreakerState::Open))
            .is_empty());
        assert_eq!(engine.firing_count(), 1);

        let resolved = engine.evaluate(&reading(CircuitBreakerState::Closed));
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
        assert_eq!(engine.firing_count(), 0);
    }

    #[test]
    fn absent_breaker_input_is_inactive_and_preserves_an_open_incident() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        let open = MetricReadings {
            circuit_breakers: Some(vec![CircuitBreakerReading {
                origin: "https://upstream.example#0".to_string(),
                state: CircuitBreakerState::Open,
            }]),
            ..MetricReadings::default()
        };
        assert_eq!(engine.evaluate(&open).len(), 1);

        assert!(engine.evaluate(&MetricReadings::default()).is_empty());
        assert_eq!(engine.firing_count(), 1);
        let evaluation = engine
            .latest_evaluations()
            .iter()
            .find(|evaluation| evaluation.rule == "circuit_breaker_trip")
            .unwrap();
        assert_eq!(evaluation.state, RuleEvaluationState::Inactive);
    }

    #[test]
    fn burn_rate_uses_the_existing_multi_window_condition_and_recovers_once() {
        let mut engine = AlertEngine::new(EngineConfig {
            burn_rate_slo_target: 0.99,
            ..EngineConfig::default()
        });
        let clean = MinuteSample {
            requests: 100,
            errors: 0,
            p99_ms: 20.0,
        };
        let burning = MinuteSample {
            requests: 100,
            errors: 10,
            p99_ms: 20.0,
        };

        for _ in 0..30 {
            assert!(engine
                .evaluate(&MetricReadings {
                    minute_sample: Some(clean),
                    ..MetricReadings::default()
                })
                .is_empty());
        }
        let mut fired = Vec::new();
        for _ in 0..30 {
            fired.extend(engine.evaluate(&MetricReadings {
                minute_sample: Some(burning),
                ..MetricReadings::default()
            }));
        }
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "burn_rate");
        assert!(!fired[0].resolved);
        let evaluation = engine
            .latest_evaluations()
            .iter()
            .find(|evaluation| evaluation.rule == "burn_rate")
            .unwrap();
        assert_eq!(evaluation.state, RuleEvaluationState::Firing);
        assert_eq!(evaluation.sample_count, Some(60));
        assert!((evaluation.reading.unwrap() - 10.0).abs() < 1e-9);

        let mut recovered = Vec::new();
        for _ in 0..30 {
            recovered.extend(engine.evaluate(&MetricReadings {
                minute_sample: Some(clean),
                ..MetricReadings::default()
            }));
        }
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].rule, "burn_rate");
        assert!(recovered[0].resolved);
    }

    #[test]
    fn burn_rate_history_is_process_local_and_bounded_to_1440_minutes() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        for _ in 0..1_500 {
            engine.evaluate(&MetricReadings {
                minute_sample: Some(MinuteSample {
                    requests: 100,
                    errors: 0,
                    p99_ms: 20.0,
                }),
                ..MetricReadings::default()
            });
        }

        assert_eq!(engine.burn_rate_sample_count(), 1_440);
        assert_eq!(
            AlertEngine::new(EngineConfig::default()).burn_rate_sample_count(),
            0
        );
    }

    #[test]
    fn a_provider_error_burn_fires_and_recovers_independently() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        // 50% error rate against a 10% threshold: critical, and independent of
        // the budget rule, which is not breaching.
        let fired = engine.evaluate(&readings(Some(0.10), Some(0.50)));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "error_rate_spike");
        assert_eq!(fired[0].labels["origin"], PROVIDER_ERROR_SCOPE);

        // Error rate falls back under threshold: one recovery.
        let recovered = engine.evaluate(&readings(Some(0.10), Some(0.01)));
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].resolved);
    }

    #[test]
    fn provider_error_burn_is_inactive_below_the_minimum_attempts() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        assert!(engine.evaluate(&provider_readings(1.0, 9)).is_empty());
        let evaluation = engine
            .latest_evaluations()
            .iter()
            .find(|evaluation| evaluation.rule == "error_rate_spike")
            .unwrap();
        assert_eq!(evaluation.state, RuleEvaluationState::Inactive);
        assert_eq!(evaluation.reading, Some(1.0));
        assert_eq!(evaluation.sample_count, Some(9));
    }

    #[test]
    fn provider_error_burn_fires_at_the_minimum_attempts() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        let fired = engine.evaluate(&provider_readings(0.50, 10));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "error_rate_spike");
    }

    #[test]
    fn inactive_provider_sample_preserves_a_firing_alert() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        assert_eq!(engine.evaluate(&provider_readings(0.50, 10)).len(), 1);

        assert!(engine.evaluate(&provider_readings(0.0, 2)).is_empty());
        assert_eq!(engine.firing_count(), 1);
        let evaluation = engine
            .latest_evaluations()
            .iter()
            .find(|evaluation| evaluation.rule == "error_rate_spike")
            .unwrap();
        assert_eq!(evaluation.state, RuleEvaluationState::Inactive);

        let resolved = engine.evaluate(&provider_readings(0.0, 10));
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].resolved);
    }

    #[test]
    fn two_rules_breach_and_recover_on_their_own_schedules() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        // Both breach on the same tick: two distinct alerts.
        let fired = engine.evaluate(&readings(Some(0.99), Some(0.90)));
        assert_eq!(fired.len(), 2);
        assert_eq!(engine.firing_count(), 2);

        // Budget clears, provider error still burning: one recovery, and the
        // provider rule is not re-fired.
        let next = engine.evaluate(&readings(Some(0.10), Some(0.90)));
        assert_eq!(next.len(), 1);
        assert!(next[0].resolved);
        assert_eq!(next[0].rule, "budget_exhaustion");
        assert_eq!(engine.firing_count(), 1);
    }

    #[test]
    fn error_burn_is_a_delta_and_ignores_idle_windows() {
        let prev = ProviderCounters {
            errors: 10.0,
            attempts: 100.0,
        };
        // 5 more errors over 20 more attempts = 25% this window, not the
        // lifetime average.
        let now = ProviderCounters {
            errors: 15.0,
            attempts: 120.0,
        };
        assert_eq!(error_burn(prev, now), Some(0.25));
        assert_eq!(provider_attempt_delta(prev, now), 20);

        // No attempts in the window: no reading, so no alert and no recovery.
        assert_eq!(error_burn(now, now), None);
        assert_eq!(provider_attempt_delta(now, now), 0);
    }

    #[test]
    fn registry_sampler_reads_request_latency_and_rate_limit_rejections() {
        crate::metrics::record_request_with_labels(
            "alert-sampler.example",
            "GET",
            503,
            0.321,
            0,
            0,
            crate::agent_labels::AgentLabels::unset(),
        );
        crate::metrics::record_rate_limit_decision("/alert-sampler", "allow");
        crate::metrics::record_rate_limit_decision("/alert-sampler", "throttle_route");

        let snapshot = sample_registry();
        assert!(snapshot.request_metrics_present);
        assert!(snapshot.request_counters.requests >= 1.0);
        assert!(snapshot.request_counters.errors >= 1.0);
        assert!(snapshot.p99_latency_ms.is_some());
        assert!(snapshot.rate_limit_counters.decisions >= 2.0);
        assert!(snapshot.rate_limit_counters.rejections >= 1.0);
    }

    #[test]
    fn request_and_rate_limit_windows_are_counter_deltas() {
        let request_prev = RequestCounters {
            requests: 100.0,
            errors: 5.0,
        };
        let request_now = RequestCounters {
            requests: 200.0,
            errors: 15.0,
        };
        assert_eq!(
            minute_sample_delta(request_prev, request_now, Some(250.0)),
            Some(MinuteSample {
                requests: 100,
                errors: 10,
                p99_ms: 250.0,
            })
        );
        assert_eq!(
            minute_sample_delta(request_now, request_now, Some(250.0)),
            Some(MinuteSample {
                requests: 0,
                errors: 0,
                p99_ms: 250.0,
            })
        );

        let limit_prev = RateLimitCounters {
            decisions: 10.0,
            rejections: 1.0,
        };
        let limit_now = RateLimitCounters {
            decisions: 20.0,
            rejections: 10.0,
        };
        assert_eq!(rate_limit_delta(limit_prev, limit_now), Some((9, 10)));
        assert_eq!(rate_limit_delta(limit_now, limit_now), None);
    }

    #[test]
    fn latency_quantile_uses_only_the_latest_counter_window() {
        let previous = HistogramCounters {
            sample_count: 100,
            buckets: vec![
                HistogramBucket {
                    upper_bound_seconds: 0.1,
                    cumulative_count: 90,
                },
                HistogramBucket {
                    upper_bound_seconds: 0.5,
                    cumulative_count: 100,
                },
            ],
        };
        let now = HistogramCounters {
            sample_count: 200,
            buckets: vec![
                HistogramBucket {
                    upper_bound_seconds: 0.1,
                    cumulative_count: 91,
                },
                HistogramBucket {
                    upper_bound_seconds: 0.5,
                    cumulative_count: 200,
                },
            ],
        };

        assert_eq!(
            histogram_quantile_delta_ms(&previous, &now, 0.99),
            Some(500.0)
        );
        assert_eq!(histogram_quantile_delta_ms(&now, &now, 0.99), None);
    }
}
