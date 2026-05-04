//! Alert channel configuration and dispatcher.
//!
//! An [`AlertDispatcher`] holds a list of [`AlertChannelConfig`] entries and
//! fans out fired alerts to every channel concurrently. Supported channel
//! types are `"webhook"` and `"log"`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// --- Data types ---

/// Configuration for a single alert notification channel.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertChannelConfig {
    /// Channel type: `"webhook"` or `"log"`.
    #[serde(rename = "type")]
    pub channel_type: String,
    /// Webhook URL (required when `channel_type == "webhook"`).
    pub url: Option<String>,
    /// Additional HTTP headers to include with webhook delivery.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Optional shared secret used to HMAC-SHA256 sign the webhook
    /// payload. When set, the dispatcher emits `X-Sbproxy-Signature:
    /// v1=<hex>` so the receiver can verify the message wasn't forged.
    #[serde(default)]
    pub secret: Option<String>,
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
}

// --- Dispatcher ---

/// Fans out alert payloads to all configured notification channels.
///
/// Webhook delivery is fire-and-forget (Tokio task per channel). Log
/// delivery writes directly via `tracing`.
pub struct AlertDispatcher {
    channels: Vec<AlertChannelConfig>,
    client: reqwest::Client,
}

impl AlertDispatcher {
    /// Create a dispatcher with the given channel configurations.
    pub fn new(channels: Vec<AlertChannelConfig>) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("sbproxy-alerting/0.1")
            .build()
            .expect("failed to build reqwest client for alert dispatcher");

        Self { channels, client }
    }

    /// Fire an alert to all configured channels.
    ///
    /// For `"log"` channels the alert is written synchronously via `tracing`.
    /// For `"webhook"` channels a Tokio task is spawned for non-blocking
    /// HTTP delivery.
    pub fn fire(&self, alert: Alert) {
        for channel in &self.channels {
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
                }
                "webhook" => {
                    if let Some(url) = &channel.url {
                        let client = self.client.clone();
                        let url = url.clone();
                        let headers = channel.headers.clone();
                        let secret = channel.secret.clone();
                        let alert = alert.clone();

                        tokio::spawn(async move {
                            deliver_alert(client, url, headers, secret, alert).await;
                        });
                    } else {
                        tracing::error!(
                            target: "alerting",
                            "webhook channel has no url configured"
                        );
                    }
                }
                unknown => {
                    tracing::warn!(
                        target: "alerting",
                        channel_type = %unknown,
                        "unknown alert channel type - ignoring"
                    );
                }
            }
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
) {
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
            return;
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
        }
        Ok(resp) => {
            tracing::warn!(url = %url, status = %resp.status(), "alerting: webhook non-success");
        }
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "alerting: webhook delivery failed");
        }
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

    fn make_alert(severity: &str) -> Alert {
        let mut labels = HashMap::new();
        labels.insert("origin".to_string(), "api.example.com".to_string());

        Alert {
            rule: "test_rule".to_string(),
            severity: severity.to_string(),
            message: "Test alert message".to_string(),
            timestamp: "2026-04-16T12:00:00Z".to_string(),
            labels,
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
        }];

        let dispatcher = AlertDispatcher::new(channels);
        // Should log an error but not panic.
        dispatcher.fire(make_alert("warning"));
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
        };

        let json = serde_json::to_string(&alert).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["labels"]["origin"], "api.example.com");
        assert_eq!(v["labels"]["region"], "us-east-1");
        assert_eq!(v["labels"]["env"], "production");
    }
}
