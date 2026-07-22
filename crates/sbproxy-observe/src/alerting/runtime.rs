// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Bounded, secret-free runtime state for the admin Alerts surface.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use serde::Serialize;

use super::channels::{Alert, AlertChannelConfig};
use super::engine::{EngineConfig, RuleEvaluation, RuleEvaluationState};

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
    /// URL scheme and host only for webhook and Slack channels.
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

fn sanitized_target(channel: &AlertChannelConfig) -> Option<String> {
    if !matches!(channel.channel_type.as_str(), "webhook" | "slack") {
        return None;
    }
    let url = reqwest::Url::parse(channel.url.as_deref()?).ok()?;
    let host = url.host_str()?;
    Some(format!("{}://{host}", url.scheme()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
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
        });
        runtime.record_evaluations(engine.latest_evaluations());

        let snapshot = runtime.snapshot();
        assert!(snapshot.enabled);
        assert_eq!(snapshot.authority, AlertAuthority::File);
        assert!(snapshot.read_only);
        assert_eq!(snapshot.rules.len(), 2);
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
        assert_eq!(
            initial.channels[0].target.as_deref(),
            Some("https://hooks.example.com")
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
}
