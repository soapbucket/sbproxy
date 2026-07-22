//! Alert channel configuration and dispatcher.
//!
//! An [`AlertDispatcher`] holds a list of [`AlertChannelConfig`] entries and
//! fans out fired alerts to every channel concurrently. Supported channel
//! types are `"webhook"`, `"slack"`, `"pagerduty"`, and `"log"`.
//!
//! The `slack` and `pagerduty` channels (WOR-1876) are formatters over
//! the same delivery transport as `webhook`, not new engines: `slack`
//! posts a Blocks-formatted message to an incoming-webhook URL, and
//! `pagerduty` sends an Events API v2 event with a deduplication key
//! derived from the rule identity plus labels, so repeated fires of the
//! same rule group into one incident and a `resolved` alert closes it.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use super::runtime::AlertRuntime;

// --- Data types ---

/// Configuration for a single alert notification channel.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertChannelConfig {
    /// Channel type: `"webhook"`, `"slack"`, `"pagerduty"`, or `"log"`.
    #[serde(rename = "type")]
    pub channel_type: String,
    /// Webhook URL. Required for `webhook` (any receiver) and `slack`
    /// (the incoming-webhook URL); unused by `pagerduty` and `log`.
    pub url: Option<String>,
    /// Additional HTTP headers to include with webhook delivery.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Optional shared secret used to HMAC-SHA256 sign the webhook
    /// payload. When set, the dispatcher emits `X-Sbproxy-Signature:
    /// v1=<hex>` so the receiver can verify the message wasn't forged.
    #[serde(default)]
    pub secret: Option<String>,
    /// PagerDuty Events API v2 routing key (required when
    /// `channel_type == "pagerduty"`).
    #[serde(default)]
    pub routing_key: Option<String>,
}

/// A fired alert payload sent to notification channels.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// The rule name that generated this alert.
    pub rule: String,
    /// Alert severity: `"warning"` or `"critical"`.
    pub severity: String,
    /// Human-readable description of the alert condition.
    pub message: String,
    /// RFC 3339 timestamp of when the alert was fired.
    pub timestamp: String,
    /// Arbitrary key/value labels for routing and grouping.
    pub labels: HashMap<String, String>,
    /// WOR-1876: `true` when this is a recovery notification for a
    /// previously fired rule. The `pagerduty` channel maps it to an
    /// Events API `resolve` (closing the incident opened by the
    /// trigger with the same deduplication key) and `slack` renders a
    /// recovered variant. Evaluators that do not track recovery keep
    /// the default `false`.
    #[serde(default)]
    pub resolved: bool,
}

// --- Dispatcher ---

/// Fans out alert payloads to all configured notification channels.
///
/// Webhook delivery runs on a Tokio task per channel. Each task is
/// registered with a `TaskTracker` so [`drain`](Self::drain) can wait
/// for in-flight deliveries during graceful shutdown instead of the
/// runtime aborting them and silently dropping alerts (an alert is most
/// likely to fire during the incident that triggers the shutdown). Log
/// delivery writes directly via `tracing`.
pub struct AlertDispatcher {
    channels: Vec<AlertChannelConfig>,
    client: reqwest::Client,
    tasks: tokio_util::task::TaskTracker,
    runtime: Option<AlertRuntime>,
    #[cfg(test)]
    allow_private_test_urls: bool,
}

/// Rejection from a targeted channel dispatch request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AlertDispatchError {
    /// No channel exists at the requested configuration index.
    #[error("unknown alert channel index {0}")]
    UnknownChannel(usize),
}

impl AlertDispatcher {
    /// Create a dispatcher with the given channel configurations.
    pub fn new(channels: Vec<AlertChannelConfig>) -> Self {
        Self::build(channels, None)
    }

    /// Create a dispatcher that publishes delivery health into `runtime`.
    pub fn with_runtime(channels: Vec<AlertChannelConfig>, runtime: AlertRuntime) -> Self {
        Self::build(channels, Some(runtime))
    }

    fn build(channels: Vec<AlertChannelConfig>, runtime: Option<AlertRuntime>) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("sbproxy-alerting/0.1")
            .build()
            .expect("failed to build reqwest client for alert dispatcher");

        Self {
            channels,
            client,
            tasks: tokio_util::task::TaskTracker::new(),
            runtime,
            #[cfg(test)]
            allow_private_test_urls: false,
        }
    }

    #[cfg(test)]
    fn with_runtime_for_test(channels: Vec<AlertChannelConfig>, runtime: AlertRuntime) -> Self {
        let mut dispatcher = Self::build(channels, Some(runtime));
        dispatcher.allow_private_test_urls = true;
        dispatcher
    }

    /// Wait for every in-flight webhook delivery to finish, then close the
    /// tracker. Call this from the graceful-shutdown driver before tearing
    /// down the runtime so alerts that fired late are not lost. After this
    /// returns, `fire` should not be called again.
    pub async fn drain(&self) {
        self.tasks.close();
        self.tasks.wait().await;
    }

    /// Fire an alert to all configured channels.
    ///
    /// For `"log"` channels the alert is written synchronously via `tracing`.
    /// For `"webhook"` channels a Tokio task is spawned for non-blocking
    /// HTTP delivery.
    pub fn fire(&self, alert: Alert) {
        for (index, channel) in self.channels.iter().cloned().enumerate() {
            self.dispatch_channel(index, channel, alert.clone());
        }
    }

    /// Fire an alert to exactly one configured channel.
    pub fn fire_channel(
        &self,
        channel_index: usize,
        alert: Alert,
    ) -> Result<(), AlertDispatchError> {
        let channel = self
            .channels
            .get(channel_index)
            .cloned()
            .ok_or(AlertDispatchError::UnknownChannel(channel_index))?;
        self.dispatch_channel(channel_index, channel, alert);
        Ok(())
    }

    fn dispatch_channel(&self, channel_index: usize, channel: AlertChannelConfig, alert: Alert) {
        match channel.channel_type.as_str() {
            "log" => {
                tracing::warn!(
                    target: "alerting",
                    rule = %alert.rule,
                    severity = %alert.severity,
                    message = %alert.message,
                    timestamp = %alert.timestamp,
                    "alert fired"
                );
                record_delivery_result(self.runtime.as_ref(), channel_index, &Ok(()));
            }
            "webhook" => {
                let Some(url) = channel.url else {
                    tracing::error!(target: "alerting", "webhook channel has no url configured");
                    record_delivery_result(
                        self.runtime.as_ref(),
                        channel_index,
                        &Err("channel URL is not configured".to_string()),
                    );
                    return;
                };
                let client = self.client.clone();
                let headers = channel.headers;
                let secret = channel.secret;
                let runtime = self.runtime.clone();
                #[cfg(test)]
                let allow_private_test_urls = self.allow_private_test_urls;
                #[cfg(not(test))]
                let allow_private_test_urls = false;
                self.tasks.spawn(async move {
                    let result = match validate_delivery_target(&url, allow_private_test_urls).await
                    {
                        Ok(()) => deliver_alert(client, url, headers, secret, alert).await,
                        Err(error) => Err(error),
                    };
                    record_delivery_result(runtime.as_ref(), channel_index, &result);
                });
            }
            "slack" => {
                let Some(url) = channel.url else {
                    tracing::error!(target: "alerting", "slack channel has no url configured");
                    record_delivery_result(
                        self.runtime.as_ref(),
                        channel_index,
                        &Err("channel URL is not configured".to_string()),
                    );
                    return;
                };
                let client = self.client.clone();
                let body = slack_payload(&alert);
                let runtime = self.runtime.clone();
                #[cfg(test)]
                let allow_private_test_urls = self.allow_private_test_urls;
                #[cfg(not(test))]
                let allow_private_test_urls = false;
                self.tasks.spawn(async move {
                    let result = match validate_delivery_target(&url, allow_private_test_urls).await
                    {
                        Ok(()) => deliver_json(client, url, body, "alert_slack").await,
                        Err(error) => {
                            crate::metrics::record_telemetry_dropped(
                                "alert_slack",
                                "ssrf_rejected",
                            );
                            Err(error)
                        }
                    };
                    record_delivery_result(runtime.as_ref(), channel_index, &result);
                });
            }
            "pagerduty" => {
                let Some(routing_key) = channel.routing_key else {
                    tracing::error!(
                        target: "alerting",
                        "pagerduty channel has no routing_key configured"
                    );
                    record_delivery_result(
                        self.runtime.as_ref(),
                        channel_index,
                        &Err("routing key is not configured".to_string()),
                    );
                    return;
                };
                let client = self.client.clone();
                let body = pagerduty_payload(&alert, &routing_key);
                let runtime = self.runtime.clone();
                self.tasks.spawn(async move {
                    let result = deliver_json(
                        client,
                        "https://events.pagerduty.com/v2/enqueue".to_string(),
                        body,
                        "alert_pagerduty",
                    )
                    .await;
                    record_delivery_result(runtime.as_ref(), channel_index, &result);
                });
            }
            unknown => {
                tracing::warn!(
                    target: "alerting",
                    channel_type = %unknown,
                    "unknown alert channel type - ignoring"
                );
                record_delivery_result(
                    self.runtime.as_ref(),
                    channel_index,
                    &Err("unsupported channel type".to_string()),
                );
            }
        }
    }
}

fn record_delivery_result(
    runtime: Option<&AlertRuntime>,
    channel_index: usize,
    result: &Result<(), String>,
) {
    let Some(runtime) = runtime else {
        return;
    };
    match result {
        Ok(()) => {
            runtime.record_delivery_success(channel_index);
        }
        Err(error) => {
            runtime.record_delivery_failure(channel_index, error);
        }
    }
}

async fn validate_delivery_target(url: &str, allow_private_test_urls: bool) -> Result<(), String> {
    if allow_private_test_urls {
        return Ok(());
    }
    let to_check = url.to_string();
    match tokio::task::spawn_blocking(move || webhook_url_allowed(&to_check)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(reason)) => {
            tracing::error!(
                target: "alerting",
                reason = %reason,
                "webhook url failed SSRF validation - skipping delivery"
            );
            Err("target rejected by SSRF policy".to_string())
        }
        Err(error) => {
            tracing::error!(
                target: "alerting",
                error = %error,
                "SSRF validation task failed - skipping delivery"
            );
            Err("target validation failed".to_string())
        }
    }
}

// --- Slack / PagerDuty formatting (WOR-1876) ---

/// Stable per-rule deduplication key: the rule name plus its sorted
/// labels. Repeated fires of the same rule instance carry the same
/// key, so PagerDuty groups them into one incident and a later
/// `resolve` with the key closes it.
fn alert_dedup_key(alert: &Alert) -> String {
    let mut labels: Vec<(&String, &String)> = alert.labels.iter().collect();
    labels.sort();
    let mut key = format!("sbproxy:{}", alert.rule);
    for (k, v) in labels {
        key.push(':');
        key.push_str(k);
        key.push('=');
        key.push_str(v);
    }
    key
}

/// Slack incoming-webhook payload (Blocks formatting): rule, severity,
/// current condition, labels, and the fired / recovered state.
fn slack_payload(alert: &Alert) -> serde_json::Value {
    let state = if alert.resolved {
        "Recovered"
    } else {
        "Firing"
    };
    let mut labels: Vec<(&String, &String)> = alert.labels.iter().collect();
    labels.sort();
    let label_text = if labels.is_empty() {
        "(no labels)".to_string()
    } else {
        labels
            .iter()
            .map(|(k, v)| format!("`{k}={v}`"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let headline = format!("{state}: {} ({})", alert.rule, alert.severity);
    serde_json::json!({
        "text": format!("{headline}: {}", alert.message),
        "blocks": [
            {
                "type": "header",
                "text": { "type": "plain_text", "text": headline, "emoji": false }
            },
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": alert.message }
            },
            {
                "type": "context",
                "elements": [
                    { "type": "mrkdwn", "text": label_text },
                    { "type": "mrkdwn", "text": format!("fired {}", alert.timestamp) }
                ]
            }
        ]
    })
}

/// PagerDuty Events API v2 payload. `trigger` opens (or re-groups
/// into) the incident keyed by [`alert_dedup_key`]; a resolved alert
/// sends `resolve` for the same key.
fn pagerduty_payload(alert: &Alert, routing_key: &str) -> serde_json::Value {
    if alert.resolved {
        return serde_json::json!({
            "routing_key": routing_key,
            "event_action": "resolve",
            "dedup_key": alert_dedup_key(alert),
        });
    }
    // PagerDuty accepts critical | warning | error | info; anything
    // outside our two-value vocabulary maps to warning.
    let severity = match alert.severity.as_str() {
        "critical" => "critical",
        _ => "warning",
    };
    serde_json::json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": alert_dedup_key(alert),
        "payload": {
            "summary": format!("{}: {}", alert.rule, alert.message),
            "source": instance_id(),
            "severity": severity,
            "timestamp": alert.timestamp,
            "custom_details": alert.labels,
        }
    })
}

/// POST a JSON payload for the slack / pagerduty channels. Best-effort
/// single attempt; a failed delivery increments the dropped-telemetry
/// counter under `kind` and never blocks the data plane (the alert
/// still reached any configured `log` channel).
async fn deliver_json(
    client: reqwest::Client,
    url: String,
    body: serde_json::Value,
    kind: &'static str,
) -> Result<(), String> {
    let req = client
        .post(&url)
        .timeout(Duration::from_secs(5))
        .header("Content-Type", "application/json")
        .header("User-Agent", format!("sbproxy/{}", version()))
        .json(&body);
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(target: "alerting", url = %url, kind = %kind, "alert delivered");
            Ok(())
        }
        Ok(resp) => {
            crate::metrics::record_telemetry_dropped(kind, "http_error");
            let status = resp.status();
            tracing::warn!(
                target: "alerting",
                url = %url,
                kind = %kind,
                status = %status,
                "alert delivery non-success"
            );
            Err(format!("HTTP {}", status.as_u16()))
        }
        Err(e) => {
            crate::metrics::record_telemetry_dropped(kind, "delivery_failed");
            tracing::warn!(
                target: "alerting",
                url = %url,
                kind = %kind,
                error = %e,
                "alert delivery failed"
            );
            Err(request_error_summary(&e))
        }
    }
}

// --- Internal webhook delivery ---

/// HMAC-SHA256 sign an alert payload. Format matches the on_request /
/// on_response webhooks (`v1=<hex>`, with `<timestamp>.<body>` signed).
fn sign_alert(secret: &str, body: &[u8], timestamp: i64) -> String {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts arbitrary key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    format!("v1={}", hex::encode(bytes))
}

/// SSRF guard for an alert webhook URL.
///
/// Wraps [`sbproxy_security::ssrf::validate_url`]: rejects non-`http(s)`
/// schemes and URLs whose host is (or resolves to) a loopback, link-local,
/// or otherwise private address. Returns `Err(reason)` when the URL must not
/// be used as an alert sink.
fn webhook_url_allowed(url: &str) -> Result<(), String> {
    sbproxy_security::ssrf::validate_url(url)
}

/// POST a single alert to a webhook URL. Best-effort, one attempt.
///
/// Adds `X-Sbproxy-*` identity headers so receivers can attribute the
/// alert to a specific proxy process and rule. When `secret` is set,
/// the body is HMAC-SHA256 signed so the receiver can reject forgeries.
async fn deliver_alert(
    client: reqwest::Client,
    url: String,
    headers: Vec<(String, String)>,
    secret: Option<String>,
    alert: Alert,
) -> Result<(), String> {
    // Wrap the alert in an envelope shape that matches the rest of the
    // proxy's webhook surface so receivers can use the same parser.
    let envelope = serde_json::json!({
        "event": "alert",
        "proxy": {
            "instance_id": instance_id(),
            "version": version(),
        },
        "alert": alert,
    });
    let body = match serde_json::to_vec(&envelope) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "alerting: failed to serialize alert");
            return Err("payload serialization failed".to_string());
        }
    };

    let timestamp = chrono::Utc::now().timestamp();
    let mut req = client
        .post(&url)
        .timeout(Duration::from_secs(5))
        .header("Content-Type", "application/json")
        .header("User-Agent", format!("sbproxy/{}", version()))
        .header("X-Sbproxy-Event", "alert")
        .header("X-Sbproxy-Instance", instance_id())
        .header("X-Sbproxy-Rule", alert.rule.as_str())
        .header("X-Sbproxy-Severity", alert.severity.as_str())
        .header("X-Sbproxy-Timestamp", timestamp.to_string())
        .body(body.clone());

    if let Some(s) = secret.as_deref() {
        req = req.header("X-Sbproxy-Signature", sign_alert(s, &body, timestamp));
    }

    for (name, value) in &headers {
        req = req.header(name.as_str(), value.as_str());
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(url = %url, "alerting: webhook delivered");
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            tracing::warn!(url = %url, status = %status, "alerting: webhook non-success");
            Err(format!("HTTP {}", status.as_u16()))
        }
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "alerting: webhook delivery failed");
            Err(request_error_summary(&e))
        }
    }
}

fn request_error_summary(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "request timed out".to_string()
    } else if error.is_connect() {
        "connection failed".to_string()
    } else {
        "request failed".to_string()
    }
}

/// Build version of the proxy, used in `User-Agent` and the alert envelope.
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Per-process instance identifier, lazily computed once per process.
/// Mirrors `sbproxy_core::identity::instance_id` so receivers see the
/// same value across all webhook surfaces (we duplicate the helper here
/// to avoid a cross-crate dep, since `sbproxy-core` already depends on us).
fn instance_id() -> &'static str {
    use std::sync::OnceLock;
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let host = std::env::var("HOSTNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "sbproxy".to_string())
            .replace('.', "-");
        let tag: u32 = rand::random();
        format!("{host}-{tag:08x}")
    })
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::runtime::{AlertRuntime, DeliveryStatus};
    use crate::alerting::EngineConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn local_http_server(status: u16) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 8 * 1024];
            let read = socket.read(&mut bytes).await.unwrap();
            let request = String::from_utf8_lossy(&bytes[..read]).into_owned();
            let _ = request_tx.send(request);
            let reason = if status < 400 { "OK" } else { "Error" };
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        (format!("http://{address}"), request_rx)
    }

    fn make_alert(severity: &str) -> Alert {
        let mut labels = HashMap::new();
        labels.insert("origin".to_string(), "api.example.com".to_string());

        Alert {
            rule: "test_rule".to_string(),
            severity: severity.to_string(),
            message: "Test alert message".to_string(),
            timestamp: "2026-04-16T12:00:00Z".to_string(),
            labels,
            resolved: false,
        }
    }

    #[test]
    fn test_alert_serialization() {
        let alert = make_alert("warning");
        let json = serde_json::to_string(&alert).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["rule"], "test_rule");
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["message"], "Test alert message");
        assert_eq!(v["timestamp"], "2026-04-16T12:00:00Z");
        assert_eq!(v["labels"]["origin"], "api.example.com");
    }

    #[test]
    fn test_critical_alert_serialization() {
        let alert = make_alert("critical");
        let json = serde_json::to_string(&alert).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["severity"], "critical");
    }

    #[test]
    fn test_alert_empty_labels() {
        let alert = Alert {
            rule: "no_labels".to_string(),
            severity: "warning".to_string(),
            message: "No labels".to_string(),
            timestamp: "2026-04-16T00:00:00Z".to_string(),
            labels: HashMap::new(),
            resolved: false,
        };

        let json = serde_json::to_string(&alert).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["labels"], serde_json::json!({}));
    }

    #[test]
    fn test_channel_config_deserialization_webhook() {
        let json = r#"{"type": "webhook", "url": "https://hooks.example.com/alert", "headers": [["X-Token", "abc"]]}"#;
        let config: AlertChannelConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.channel_type, "webhook");
        assert_eq!(
            config.url.as_deref(),
            Some("https://hooks.example.com/alert")
        );
        assert_eq!(config.headers.len(), 1);
        assert_eq!(config.headers[0].0, "X-Token");
    }

    #[test]
    fn test_channel_config_deserialization_log() {
        let json = r#"{"type": "log"}"#;
        let config: AlertChannelConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.channel_type, "log");
        assert!(config.url.is_none());
        assert!(config.headers.is_empty());
    }

    #[test]
    fn webhook_url_allowed_rejects_ssrf_targets() {
        // WOR-604: these are all IP-literal / non-http(s) targets, so the
        // check is deterministic (no DNS) and must reject every one.
        for bad in [
            "http://127.0.0.1/alert",
            "http://169.254.169.254/latest/meta-data",
            "file:///etc/passwd",
            "http://[::1]:6379/",
        ] {
            assert!(
                webhook_url_allowed(bad).is_err(),
                "expected {bad} to be rejected as an SSRF target"
            );
        }
        // A public IP-literal https URL passes (no DNS for a literal).
        assert!(webhook_url_allowed("https://8.8.8.8/alert").is_ok());
    }

    #[test]
    fn test_dispatcher_construction_no_channels() {
        let dispatcher = AlertDispatcher::new(vec![]);
        // Firing with no channels should not panic.
        dispatcher.fire(make_alert("warning"));
    }

    #[test]
    fn test_dispatcher_fires_log_channel() {
        let channels = vec![AlertChannelConfig {
            channel_type: "log".to_string(),
            url: None,
            headers: vec![],
            secret: None,
            routing_key: None,
        }];

        let dispatcher = AlertDispatcher::new(channels);
        // Should log without panicking.
        dispatcher.fire(make_alert("critical"));
    }

    #[test]
    fn test_dispatcher_webhook_without_url_does_not_panic() {
        let channels = vec![AlertChannelConfig {
            channel_type: "webhook".to_string(),
            url: None, // missing URL
            headers: vec![],
            secret: None,
            routing_key: None,
        }];

        let dispatcher = AlertDispatcher::new(channels);
        // Should log an error but not panic.
        dispatcher.fire(make_alert("warning"));
    }

    #[tokio::test]
    async fn drain_waits_for_in_flight_webhook_task() {
        // A webhook to a loopback target: the SSRF guard rejects it, so the
        // spawned delivery task runs and completes quickly without making a
        // real request. The point is that `drain` registers and waits for
        // that task rather than the runtime aborting it on shutdown.
        let channels = vec![AlertChannelConfig {
            channel_type: "webhook".to_string(),
            url: Some("http://127.0.0.1/alert".to_string()),
            headers: vec![],
            secret: None,
            routing_key: None,
        }];
        let dispatcher = AlertDispatcher::new(channels);
        dispatcher.fire(make_alert("critical"));
        // Returns once the tracked delivery task finishes.
        dispatcher.drain().await;
        assert!(dispatcher.tasks.is_closed());
        assert!(dispatcher.tasks.is_empty());
    }

    #[tokio::test]
    async fn targeted_delivery_invokes_only_the_selected_channel_and_marks_it_healthy() {
        let (base_url, request_rx) = local_http_server(204).await;
        let channels = vec![
            AlertChannelConfig {
                channel_type: "webhook".to_string(),
                url: Some(format!("{base_url}/first")),
                headers: vec![],
                secret: None,
                routing_key: None,
            },
            AlertChannelConfig {
                channel_type: "webhook".to_string(),
                url: Some(format!("{base_url}/second")),
                headers: vec![],
                secret: None,
                routing_key: None,
            },
        ];
        let runtime = AlertRuntime::new(&EngineConfig::default(), &channels);
        let dispatcher = AlertDispatcher::with_runtime_for_test(channels, runtime.clone());

        dispatcher.fire_channel(1, make_alert("warning")).unwrap();
        dispatcher.drain().await;

        let request = request_rx.await.unwrap();
        assert!(
            request.starts_with("POST /second "),
            "request was {request:?}"
        );
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.channels[0].health.status, DeliveryStatus::Untested);
        assert_eq!(snapshot.channels[1].health.status, DeliveryStatus::Healthy);
    }

    #[tokio::test]
    async fn targeted_delivery_reports_http_failure_and_rejects_unknown_index() {
        let (base_url, request_rx) = local_http_server(503).await;
        let channels = vec![AlertChannelConfig {
            channel_type: "webhook".to_string(),
            url: Some(format!("{base_url}/failing")),
            headers: vec![],
            secret: None,
            routing_key: None,
        }];
        let runtime = AlertRuntime::new(&EngineConfig::default(), &channels);
        let dispatcher = AlertDispatcher::with_runtime_for_test(channels, runtime.clone());

        assert_eq!(
            dispatcher.fire_channel(9, make_alert("warning")),
            Err(AlertDispatchError::UnknownChannel(9))
        );
        dispatcher.fire_channel(0, make_alert("warning")).unwrap();
        dispatcher.drain().await;
        let _ = request_rx.await.unwrap();

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.channels[0].health.status, DeliveryStatus::Failing);
        assert_eq!(
            snapshot.channels[0].health.error.as_deref(),
            Some("HTTP 503")
        );
    }

    #[test]
    fn slack_payload_formats_firing_and_recovered() {
        // WOR-1876: readable headline, message section, labels +
        // timestamp context, and a recovered variant.
        let alert = make_alert("critical");
        let v = slack_payload(&alert);
        assert!(v["text"]
            .as_str()
            .unwrap()
            .starts_with("Firing: test_rule (critical)"));
        assert_eq!(v["blocks"][0]["type"], "header");
        assert_eq!(v["blocks"][1]["text"]["text"], "Test alert message");
        assert!(v["blocks"][2]["elements"][0]["text"]
            .as_str()
            .unwrap()
            .contains("origin=api.example.com"));
        let mut recovered = make_alert("critical");
        recovered.resolved = true;
        let v = slack_payload(&recovered);
        assert!(v["text"].as_str().unwrap().starts_with("Recovered:"));
    }

    #[test]
    fn pagerduty_trigger_and_resolve_share_the_dedup_key() {
        // WOR-1876: recovery must close the incident the trigger
        // opened, which requires an identical deduplication key.
        let alert = make_alert("critical");
        let trigger = pagerduty_payload(&alert, "rk-123");
        assert_eq!(trigger["event_action"], "trigger");
        assert_eq!(trigger["routing_key"], "rk-123");
        assert_eq!(trigger["payload"]["severity"], "critical");
        assert_eq!(
            trigger["payload"]["custom_details"]["origin"],
            "api.example.com"
        );
        let dedup = trigger["dedup_key"].as_str().unwrap().to_string();
        assert!(dedup.starts_with("sbproxy:test_rule"));
        assert!(dedup.contains("origin=api.example.com"));

        let mut recovered = make_alert("critical");
        recovered.resolved = true;
        let resolve = pagerduty_payload(&recovered, "rk-123");
        assert_eq!(resolve["event_action"], "resolve");
        assert_eq!(resolve["dedup_key"].as_str().unwrap(), dedup);
        assert!(resolve.get("payload").is_none());
    }

    #[test]
    fn pagerduty_unknown_severity_maps_to_warning() {
        let alert = make_alert("weird");
        let v = pagerduty_payload(&alert, "rk");
        assert_eq!(v["payload"]["severity"], "warning");
    }

    #[test]
    fn channel_config_deserializes_pagerduty_and_slack() {
        let pd: AlertChannelConfig =
            serde_json::from_str(r#"{"type": "pagerduty", "routing_key": "rk-1"}"#).unwrap();
        assert_eq!(pd.channel_type, "pagerduty");
        assert_eq!(pd.routing_key.as_deref(), Some("rk-1"));
        let slack: AlertChannelConfig = serde_json::from_str(
            r#"{"type": "slack", "url": "https://hooks.slack.com/services/T0/B0/x"}"#,
        )
        .unwrap();
        assert_eq!(slack.channel_type, "slack");
        assert!(slack.routing_key.is_none());
    }

    #[test]
    fn test_alert_clone() {
        let alert = make_alert("warning");
        let cloned = alert.clone();
        assert_eq!(alert.rule, cloned.rule);
        assert_eq!(alert.severity, cloned.severity);
    }

    #[test]
    fn test_alert_multiple_labels() {
        let mut labels = HashMap::new();
        labels.insert("origin".to_string(), "api.example.com".to_string());
        labels.insert("region".to_string(), "us-east-1".to_string());
        labels.insert("env".to_string(), "production".to_string());

        let alert = Alert {
            rule: "multi_label".to_string(),
            severity: "warning".to_string(),
            message: "Multiple labels".to_string(),
            timestamp: "2026-04-16T00:00:00Z".to_string(),
            labels,
            resolved: false,
        };

        let json = serde_json::to_string(&alert).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["labels"]["origin"], "api.example.com");
        assert_eq!(v["labels"]["region"], "us-east-1");
        assert_eq!(v["labels"]["env"], "production");
    }
}
