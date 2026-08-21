// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Bounded, secret-free runtime state for the admin Alerts surface.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use sbproxy_security::url_redact::try_redacted_url;
use serde::Serialize;

use super::channels::{Alert, AlertChannelConfig};
use super::engine::{EngineConfig, RuleEvaluation, RuleEvaluationState, BURN_RATE_MIN_SAMPLES};

/// Maximum process-lifetime alert events retained for the admin console.
pub const ALERT_HISTORY_CAPACITY: usize = 200;
const DELIVERY_ERROR_MAX_CHARS: usize = 256;

/// Configuration authority for rules and channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertAuthority {
    /// The process configuration file is authoritative.
    File,
}

/// One built-in rule and its latest evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct AlertRuleSnapshot {
    /// Stable rule name, matching emitted alerts.
    pub rule: String,
    /// Human-readable rule purpose.
    pub description: String,
    /// Warning and critical thresholds in ascending order.
    pub thresholds: Vec<f64>,
    /// Minimum contributing samples, when the rule has a sample floor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_samples: Option<u64>,
    /// Latest evaluation state.
    pub state: RuleEvaluationState,
    /// Latest metric reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reading: Option<f64>,
    /// Samples contributing to the latest reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_count: Option<u64>,
    /// RFC 3339 time of the latest evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_evaluated_at: Option<String>,
}

/// Process-lifetime delivery status for one channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// No delivery has completed since process start.
    Untested,
    /// The latest delivery completed successfully.
    Healthy,
    /// The latest delivery failed.
    Failing,
}

/// Latest bounded delivery result for one channel.
#[derive(Debug, Clone, Serialize)]
pub struct DeliveryHealth {
    /// Current status.
    pub status: DeliveryStatus,
    /// RFC 3339 time of the latest completed attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    /// Bounded failure summary. Never contains channel credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for DeliveryHealth {
    fn default() -> Self {
        Self {
            status: DeliveryStatus::Untested,
            last_attempt_at: None,
            error: None,
        }
    }
}

/// Secret-free description and health for one configured channel.
#[derive(Debug, Clone, Serialize)]
pub struct AlertChannelSnapshot {
    /// Stable index used by the targeted channel-test route.
    pub index: usize,
    /// Configured channel type.
    #[serde(rename = "type")]
    pub channel_type: String,
    /// URL scheme, host, and port only for webhook and Slack channels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Whether PagerDuty has a routing key, without exposing its value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_key_configured: Option<bool>,
    /// Latest process-lifetime delivery result.
    pub health: DeliveryHealth,
}

/// Kind of event retained in bounded history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertHistoryEvent {
    /// A rule began firing.
    Fired,
    /// A previously firing rule recovered.
    Resolved,
    /// An operator requested a targeted channel test.
    Test,
}

/// One retained alert event.
#[derive(Debug, Clone, Serialize)]
pub struct AlertHistoryEntry {
    /// Event kind.
    pub event: AlertHistoryEvent,
    /// Targeted channel for a test event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_index: Option<usize>,
    /// Alert payload delivered or queued for delivery.
    pub alert: Alert,
}

/// Complete secret-free document returned by the admin API.
#[derive(Debug, Clone, Serialize)]
pub struct AlertRuntimeSnapshot {
    /// Whether an alert runtime is installed.
    pub enabled: bool,
    /// Source of truth for rule and channel configuration.
    pub authority: AlertAuthority,
    /// Always true while file configuration remains authoritative.
    pub read_only: bool,
    /// Built-in rules and their current evaluation state.
    pub rules: Vec<AlertRuleSnapshot>,
    /// Sanitized channels and process-lifetime health.
    pub channels: Vec<AlertChannelSnapshot>,
    /// Oldest-to-newest bounded event history.
    pub history: Vec<AlertHistoryEntry>,
}

impl AlertRuntimeSnapshot {
    /// Valid response document when alerting has no installed runtime.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            authority: AlertAuthority::File,
            read_only: true,
            rules: Vec::new(),
            channels: Vec::new(),
            history: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct AlertRuntimeState {
    rules: Vec<AlertRuleSnapshot>,
    channels: Vec<AlertChannelSnapshot>,
    history: VecDeque<AlertHistoryEntry>,
}

/// Shared bounded runtime state updated by the evaluation loop and dispatcher.
#[derive(Debug, Clone)]
pub struct AlertRuntime {
    inner: Arc<RwLock<AlertRuntimeState>>,
}

impl AlertRuntime {
    /// Build runtime state from the active engine and channel configuration.
    pub fn new(config: &EngineConfig, channels: &[AlertChannelConfig]) -> Self {
        let rules = vec![
            AlertRuleSnapshot {
                rule: "budget_exhaustion".to_string(),
                description: "Highest configured budget utilization".to_string(),
                thresholds: config.budget_thresholds.clone(),
                minimum_samples: None,
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
            AlertRuleSnapshot {
                rule: "error_rate_spike".to_string(),
                description: "Provider error rate over the latest evaluation window".to_string(),
                thresholds: vec![
                    config.provider_error_threshold,
                    (config.provider_error_threshold * 2.0).min(1.0),
                ],
                minimum_samples: Some(config.provider_error_min_attempts),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
            AlertRuleSnapshot {
                rule: "gateway_rejection_spike".to_string(),
                description: "AI requests rejected before provider dispatch".to_string(),
                thresholds: vec![
                    config.gateway_rejection_threshold,
                    (config.gateway_rejection_threshold * 2.0).min(1.0),
                ],
                minimum_samples: Some(config.gateway_rejection_min_decisions),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
            AlertRuleSnapshot {
                rule: "burn_rate".to_string(),
                description:
                    "Availability burn rate over the last 60 minutes of a process-local ring"
                        .to_string(),
                // One threshold, because there is one objective. The console
                // used to advertise 3x, 6x, and 14.4x for three tiers that
                // computed two distinct windows between them and opened one
                // shared incident. The 6x and 3x tiers are Prometheus rules
                // now; see deploy/alerts/alerting-rules.yml.
                thresholds: vec![14.4],
                // The console renders the sample column as "n / floor" only
                // for a rule that declares a floor, and prints "not gated" for
                // one that does not. Leaving this None put the words "not
                // gated" beside a reading taken from a ring that had been
                // filling for four minutes, which is the one place an operator
                // would have looked to find that out.
                minimum_samples: Some(BURN_RATE_MIN_SAMPLES),
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
            AlertRuleSnapshot {
                rule: "latency_slo".to_string(),
                description: "Proxy-wide request p99 latency".to_string(),
                thresholds: vec![
                    config.slo_p99_threshold_ms,
                    config.slo_p99_threshold_ms * 2.0,
                ],
                minimum_samples: None,
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
            AlertRuleSnapshot {
                rule: "rate_limit_approaching".to_string(),
                description: "Fraction of rate-limit decisions rejected in the latest window"
                    .to_string(),
                thresholds: vec![config.rate_limit_rejection_threshold, 0.95],
                minimum_samples: None,
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
            AlertRuleSnapshot {
                rule: "cert_expiry".to_string(),
                description: "Soonest active ACME certificate expiry, in days".to_string(),
                thresholds: config
                    .cert_expiry_warn_days
                    .iter()
                    .map(|days| f64::from(*days))
                    .collect(),
                minimum_samples: None,
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
            AlertRuleSnapshot {
                rule: "circuit_breaker_trip".to_string(),
                description:
                    "Configured upstream circuit breakers open or probing in half-open state"
                        .to_string(),
                thresholds: vec![1.0],
                minimum_samples: None,
                state: RuleEvaluationState::Inactive,
                reading: None,
                sample_count: None,
                last_evaluated_at: None,
            },
        ];
        let channels = channels
            .iter()
            .enumerate()
            .map(|(index, channel)| AlertChannelSnapshot {
                index,
                channel_type: channel.channel_type.clone(),
                target: sanitized_target(channel),
                routing_key_configured: (channel.channel_type == "pagerduty")
                    .then_some(channel.routing_key.is_some()),
                health: DeliveryHealth::default(),
            })
            .collect();
        Self {
            inner: Arc::new(RwLock::new(AlertRuntimeState {
                rules,
                channels,
                history: VecDeque::with_capacity(ALERT_HISTORY_CAPACITY),
            })),
        }
    }

    /// Clone a consistent, secret-free snapshot while holding only a read lock.
    pub fn snapshot(&self) -> AlertRuntimeSnapshot {
        let state = self.inner.read().unwrap_or_else(|error| error.into_inner());
        AlertRuntimeSnapshot {
            enabled: true,
            authority: AlertAuthority::File,
            read_only: true,
            rules: state.rules.clone(),
            channels: state.channels.clone(),
            history: state.history.iter().cloned().collect(),
        }
    }

    /// Number of configured channels.
    pub fn channel_count(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .channels
            .len()
    }

    /// Publish the engine's latest evaluation for each built-in rule.
    pub fn record_evaluations(&self, evaluations: &[RuleEvaluation]) {
        let mut state = self
            .inner
            .write()
            .unwrap_or_else(|error| error.into_inner());
        for evaluation in evaluations {
            if let Some(rule) = state
                .rules
                .iter_mut()
                .find(|rule| rule.rule == evaluation.rule)
            {
                rule.state = evaluation.state;
                rule.reading = evaluation.reading;
                rule.sample_count = evaluation.sample_count;
                rule.last_evaluated_at = Some(evaluation.evaluated_at.clone());
            }
        }
    }

    /// Append one rule-fired or rule-resolved event to bounded history.
    pub fn record_alert(&self, alert: &Alert) {
        let event = if alert.resolved {
            AlertHistoryEvent::Resolved
        } else {
            AlertHistoryEvent::Fired
        };
        self.push_history(AlertHistoryEntry {
            event,
            channel_index: None,
            alert: alert.clone(),
        });
    }

    /// Append one targeted channel-test event to bounded history.
    pub fn record_test_alert(&self, channel_index: usize, alert: &Alert) {
        self.push_history(AlertHistoryEntry {
            event: AlertHistoryEvent::Test,
            channel_index: Some(channel_index),
            alert: alert.clone(),
        });
    }

    fn push_history(&self, entry: AlertHistoryEntry) {
        let mut state = self
            .inner
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if state.history.len() == ALERT_HISTORY_CAPACITY {
            state.history.pop_front();
        }
        state.history.push_back(entry);
    }

    /// Record a completed successful delivery. Returns false for an invalid
    /// channel index.
    pub fn record_delivery_success(&self, channel_index: usize) -> bool {
        self.record_delivery(channel_index, DeliveryStatus::Healthy, None)
    }

    /// Record a completed failed delivery with a bounded summary. Returns
    /// false for an invalid channel index.
    pub fn record_delivery_failure(&self, channel_index: usize, error: &str) -> bool {
        self.record_delivery(
            channel_index,
            DeliveryStatus::Failing,
            Some(error.chars().take(DELIVERY_ERROR_MAX_CHARS).collect()),
        )
    }

    fn record_delivery(
        &self,
        channel_index: usize,
        status: DeliveryStatus,
        error: Option<String>,
    ) -> bool {
        let mut state = self
            .inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(channel) = state.channels.get_mut(channel_index) else {
            return false;
        };
        channel.health = DeliveryHealth {
            status,
            last_attempt_at: Some(chrono::Utc::now().to_rfc3339()),
            error,
        };
        true
    }
}

/// The delivery target as the health surface reports it: scheme, host, and
/// port, never the path a Slack or Teams webhook keeps its secret in.
///
/// This used to build `scheme://host` by hand and drop the port, so two
/// alert receivers on one host were indistinguishable on the health page
/// (WOR-2640). [`try_redacted_url`] keeps the port when the URL names one.
///
/// The `try_` form rather than `redacted_url`, because the shape of this
/// `Option` is part of the `/api/alerts` document: `target` is
/// `skip_serializing_if = "Option::is_none"`, and the console renders the
/// field verbatim when it is present and falls back to "target
/// unavailable" when it is not. A URL with no origin to render has to
/// stay an absence here rather than becoming the string `[invalid url]`
/// on an operator's alerts page.
fn sanitized_target(channel: &AlertChannelConfig) -> Option<String> {
    if !matches!(channel.channel_type.as_str(), "webhook" | "slack") {
        return None;
    }
    try_redacted_url(channel.url.as_deref()?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::alerting::burn_rate::MinuteSample;
    use crate::alerting::{Alert, AlertChannelConfig, AlertEngine, EngineConfig, MetricReadings};

    fn channel(channel_type: &str) -> AlertChannelConfig {
        AlertChannelConfig {
            channel_type: channel_type.to_string(),
            url: None,
            headers: vec![],
            secret: None,
            routing_key: None,
        }
    }

    fn alert(sequence: usize, resolved: bool) -> Alert {
        Alert {
            rule: "budget_exhaustion".to_string(),
            severity: "warning".to_string(),
            message: format!("alert {sequence}"),
            timestamp: format!("2026-07-21T00:00:{:02}Z", sequence % 60),
            labels: HashMap::new(),
            resolved,
        }
    }

    #[test]
    fn snapshot_contains_file_authority_and_current_rule_evaluations() {
        let config = EngineConfig::default();
        let runtime = AlertRuntime::new(&config, &[]);
        let mut engine = AlertEngine::new(config);
        engine.evaluate(&MetricReadings {
            budget_utilization: Some(0.50),
            provider_error_rate: Some(0.25),
            provider_attempts: 4,
            ..MetricReadings::default()
        });
        runtime.record_evaluations(engine.latest_evaluations());

        let snapshot = runtime.snapshot();
        assert!(snapshot.enabled);
        assert_eq!(snapshot.authority, AlertAuthority::File);
        assert!(snapshot.read_only);
        assert_eq!(snapshot.rules.len(), 8);
        let budget = snapshot
            .rules
            .iter()
            .find(|rule| rule.rule == "budget_exhaustion")
            .unwrap();
        assert_eq!(budget.state, RuleEvaluationState::Ok);
        assert_eq!(budget.reading, Some(0.50));
        let provider = snapshot
            .rules
            .iter()
            .find(|rule| rule.rule == "error_rate_spike")
            .unwrap();
        assert_eq!(provider.state, RuleEvaluationState::Inactive);
        assert_eq!(provider.minimum_samples, Some(10));
        assert_eq!(provider.sample_count, Some(4));
        assert!(provider.last_evaluated_at.is_some());
        let gateway = snapshot
            .rules
            .iter()
            .find(|rule| rule.rule == "gateway_rejection_spike")
            .unwrap();
        assert_eq!(gateway.state, RuleEvaluationState::Inactive);
        assert_eq!(gateway.minimum_samples, Some(10));
    }

    #[test]
    fn burn_rate_rule_advertises_the_history_its_reading_needs() {
        let config = EngineConfig::default();
        let runtime = AlertRuntime::new(&config, &[]);
        let mut engine = AlertEngine::new(config);
        for _ in 0..4 {
            engine.evaluate(&MetricReadings {
                minute_sample: Some(MinuteSample {
                    requests: 100,
                    errors: 50,
                    p99_ms: 20.0,
                }),
                ..MetricReadings::default()
            });
        }
        runtime.record_evaluations(engine.latest_evaluations());

        let snapshot = runtime.snapshot();
        let burn = snapshot
            .rules
            .iter()
            .find(|rule| rule.rule == "burn_rate")
            .map(|rule| (rule.state, rule.sample_count, rule.minimum_samples));
        // Without a declared floor the console prints "not gated" here, and a
        // reading taken from four minutes of history is indistinguishable from
        // one taken from a full day.
        assert_eq!(
            burn,
            Some((RuleEvaluationState::Inactive, Some(4), Some(60)))
        );
    }

    #[test]
    fn channel_descriptors_are_sanitized_and_health_is_bounded() {
        let mut webhook = channel("webhook");
        webhook.url = Some(
            "https://operator:password@hooks.example.com:8443/private?token=secret".to_string(),
        );
        webhook.headers = vec![("Authorization".to_string(), "Bearer private".to_string())];
        webhook.secret = Some("signing-secret".to_string());
        let mut slack = channel("slack");
        slack.url = Some("https://hooks.slack.com/services/T/B/private".to_string());
        let mut pagerduty = channel("pagerduty");
        pagerduty.routing_key = Some("pagerduty-private-key".to_string());
        let runtime = AlertRuntime::new(
            &EngineConfig::default(),
            &[webhook, slack, pagerduty, channel("log")],
        );

        let initial = runtime.snapshot();
        // The port is part of the target. This assertion used to expect
        // it missing, which is the dropped-port bug WOR-2640 fixed rather
        // than a property worth keeping.
        assert_eq!(
            initial.channels[0].target.as_deref(),
            Some("https://hooks.example.com:8443")
        );
        assert_eq!(
            initial.channels[1].target.as_deref(),
            Some("https://hooks.slack.com")
        );
        assert_eq!(initial.channels[2].routing_key_configured, Some(true));
        assert!(initial.channels[3].target.is_none());
        assert!(initial
            .channels
            .iter()
            .all(|channel| channel.health.status == DeliveryStatus::Untested));
        let json = serde_json::to_string(&initial).unwrap();
        for secret in [
            "password",
            "private?token=secret",
            "Bearer private",
            "signing-secret",
            "pagerduty-private-key",
        ] {
            assert!(!json.contains(secret), "snapshot leaked {secret}");
        }

        runtime.record_delivery_success(0);
        runtime.record_delivery_failure(1, &"x".repeat(400));
        let updated = runtime.snapshot();
        assert_eq!(updated.channels[0].health.status, DeliveryStatus::Healthy);
        assert!(updated.channels[0].health.last_attempt_at.is_some());
        assert!(updated.channels[0].health.error.is_none());
        assert_eq!(updated.channels[1].health.status, DeliveryStatus::Failing);
        assert!(updated.channels[1]
            .health
            .error
            .as_deref()
            .is_some_and(|error| error.chars().count() == 256));
    }

    #[test]
    fn history_records_fired_resolved_and_test_events_with_fifo_cap() {
        let runtime = AlertRuntime::new(&EngineConfig::default(), &[channel("log")]);
        for sequence in 0..205 {
            runtime.record_alert(&alert(sequence, false));
        }

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.history.len(), 200);
        assert_eq!(snapshot.history[0].alert.message, "alert 5");
        assert_eq!(snapshot.history[199].alert.message, "alert 204");
        assert_eq!(snapshot.history[199].event, AlertHistoryEvent::Fired);

        runtime.record_alert(&alert(205, true));
        runtime.record_test_alert(0, &alert(206, false));
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.history.len(), 200);
        assert_eq!(snapshot.history[198].event, AlertHistoryEvent::Resolved);
        assert_eq!(snapshot.history[199].event, AlertHistoryEvent::Test);
        assert_eq!(snapshot.history[199].channel_index, Some(0));
    }

    /// The health surface names the channel it could not reach. Before
    /// WOR-2640 it built `scheme://host` by hand, so a fleet running two
    /// receivers on one host saw one target for both.
    #[test]
    fn snapshot_target_keeps_the_port_and_drops_the_webhook_path() {
        let mut first = channel("webhook");
        first.url = Some("https://alerts.test:8443/hooks/path-secret".to_string());
        let mut second = channel("webhook");
        second.url = Some("https://alerts.test:9443/hooks/other-secret".to_string());

        let runtime = AlertRuntime::new(&EngineConfig::default(), &[first, second]);
        let snapshot = runtime.snapshot();
        let targets: Vec<_> = snapshot
            .channels
            .iter()
            .map(|entry| entry.target.clone())
            .collect();

        assert_eq!(
            targets,
            vec![
                Some("https://alerts.test:8443".to_string()),
                Some("https://alerts.test:9443".to_string()),
            ]
        );
        for target in targets.into_iter().flatten() {
            assert!(!target.contains("secret"), "path leaked: {target}");
        }
    }

    /// `target` is omitted rather than filled with a placeholder when
    /// there is no origin to render. The shared redactor is total and
    /// answers `[invalid url]` or `scheme://[no host]`, and both of those
    /// would reach an operator's alerts page as if they were the target;
    /// the console tests `if (channel.target)` and has its own "target
    /// unavailable" state for the absent case.
    ///
    /// A `log` channel is in the fixture too, because the type guard and
    /// the render are two separate reasons for the same answer and a test
    /// that only covered the first would pass with the render reverted.
    #[test]
    fn snapshot_omits_the_target_when_there_is_no_renderable_origin() {
        let mut scheme_less = channel("webhook");
        scheme_less.url = Some("hooks.example.com/hooks/path-secret".to_string());
        let mut no_authority = channel("webhook");
        no_authority.url = Some("mailto:ops@example.test".to_string());
        let mut unparseable = channel("slack");
        unparseable.url = Some("hunter2".to_string());

        let runtime = AlertRuntime::new(
            &EngineConfig::default(),
            &[scheme_less, no_authority, unparseable, channel("log")],
        );
        let snapshot = runtime.snapshot();

        for entry in &snapshot.channels {
            assert_eq!(
                entry.target, None,
                "a {} channel rendered a placeholder target",
                entry.channel_type
            );
        }

        // Absent from the document, not serialized as null: the field
        // carries `skip_serializing_if` and the console branches on the
        // key being there at all.
        let rendered =
            serde_json::to_string(&snapshot.channels[0]).expect("a channel snapshot serializes");
        assert!(!rendered.contains("target"), "got: {rendered}");
    }
}
