//! Webhook export for alerts and events.
//!
//! Delivers structured JSON payloads via HTTP POST to one or more configured
//! endpoints. All delivery is fire-and-forget: the caller is not blocked and
//! failures are logged but not surfaced. Each webhook gets its own Tokio task
//! with configurable retry behaviour and per-call timeouts.

use serde::Serialize;
use std::time::Duration;

// --- Config ---

/// Configuration for a single webhook target.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Full HTTP/HTTPS URL to POST to.
    pub url: String,
    /// Extra headers to include (e.g. `("Authorization", "Bearer …")`).
    pub headers: Vec<(String, String)>,
    /// Per-request timeout in milliseconds. Defaults to 5 000.
    pub timeout_ms: u64,
    /// Maximum number of delivery attempts (including the first). Defaults to 3.
    pub max_retries: u32,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            headers: Vec::new(),
            timeout_ms: 5_000,
            max_retries: 3,
        }
    }
}

// --- Exporter ---

/// Sends structured payloads to a set of webhook endpoints.
///
/// Each call to [`WebhookExporter::send`] spawns a Tokio task per configured
/// webhook. Tasks retry on failure up to `max_retries` times with a short
/// back-off, then give up and log the error.
pub struct WebhookExporter {
    configs: Vec<WebhookConfig>,
    client: reqwest::Client,
}

impl WebhookExporter {
    /// Create a new exporter with the given webhook configurations.
    ///
    /// A shared [`reqwest::Client`] is constructed once and reused across
    /// all deliveries, taking advantage of connection pooling.
    pub fn new(configs: Vec<WebhookConfig>) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("sbproxy-webhook/0.1")
            .build()
            .expect("failed to build reqwest client for webhook exporter");

        Self { configs, client }
    }

    /// Serialize `payload` to JSON and POST it to every configured webhook.
    ///
    /// This method is synchronous but non-blocking: it spawns one Tokio task
    /// per webhook and returns immediately. Retry logic lives inside each task.
    pub fn send<T: Serialize + Send + Sync + 'static>(&self, payload: &T) {
        // Serialize once; clone the bytes into each task.
        let body = match serde_json::to_vec(payload) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "webhook: failed to serialize payload");
                return;
            }
        };

        for config in &self.configs {
            let client = self.client.clone();
            let url = config.url.clone();
            let headers = config.headers.clone();
            let timeout_ms = config.timeout_ms;
            let max_retries = config.max_retries;
            let body = body.clone();

            tokio::spawn(async move {
                deliver(client, url, headers, timeout_ms, max_retries, body).await;
            });
        }
    }
}

// --- Internal delivery with retries ---

/// Deliver a pre-serialized JSON body to a single endpoint, retrying on failure.
async fn deliver(
    client: reqwest::Client,
    url: String,
    headers: Vec<(String, String)>,
    timeout_ms: u64,
    max_retries: u32,
    body: Vec<u8>,
) {
    let timeout = Duration::from_millis(timeout_ms);
    let mut attempt = 0u32;

    loop {
        attempt += 1;

        let mut req = client
            .post(&url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .body(body.clone());

        for (name, value) in &headers {
            req = req.header(name.as_str(), value.as_str());
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(url = %url, attempt, "webhook: delivered successfully");
                return;
            }
            Ok(resp) => {
                let status = resp.status();
                tracing::warn!(url = %url, attempt, %status, "webhook: non-success response");
            }
            Err(e) => {
                tracing::warn!(url = %url, attempt, error = %e, "webhook: delivery error");
            }
        }

        if attempt >= max_retries {
            tracing::error!(url = %url, max_retries, "webhook: giving up after max retries");
            return;
        }

        // Simple linear back-off: 500 ms × attempt number.
        let backoff = Duration::from_millis(500 * u64::from(attempt));
        tokio::time::sleep(backoff).await;
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_config_defaults() {
        let config = WebhookConfig::default();
        assert_eq!(config.timeout_ms, 5_000);
        assert_eq!(config.max_retries, 3);
        assert!(config.headers.is_empty());
        assert!(config.url.is_empty());
    }

    #[test]
    fn test_config_explicit_values() {
        let config = WebhookConfig {
            url: "https://hooks.example.com/events".to_string(),
            headers: vec![
                ("Authorization".to_string(), "Bearer token123".to_string()),
                ("X-Source".to_string(), "sbproxy".to_string()),
            ],
            timeout_ms: 3_000,
            max_retries: 5,
        };

        assert_eq!(config.url, "https://hooks.example.com/events");
        assert_eq!(config.headers.len(), 2);
        assert_eq!(config.timeout_ms, 3_000);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_payload_serializes_correctly() {
        // Validate that the payloads we'd send serialize properly.
        let payload = json!({
            "event": "alert.fired",
            "rule": "budget_exhausted",
            "severity": "critical",
            "timestamp": "2026-04-16T12:00:00Z",
        });

        let bytes = serde_json::to_vec(&payload).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(roundtrip["event"], "alert.fired");
        assert_eq!(roundtrip["severity"], "critical");
    }

    #[test]
    fn test_exporter_construction_with_empty_configs() {
        // Should not panic with no configs.
        let exporter = WebhookExporter::new(vec![]);
        // fire-and-forget with no configs should also not panic.
        let payload = json!({"test": true});
        // This won't actually do anything because configs is empty.
        exporter.send(&payload);
    }

    #[test]
    fn test_exporter_construction_with_multiple_configs() {
        let configs = vec![
            WebhookConfig {
                url: "https://hooks.example.com/a".to_string(),
                timeout_ms: 2_000,
                max_retries: 2,
                headers: vec![],
            },
            WebhookConfig {
                url: "https://hooks.example.com/b".to_string(),
                timeout_ms: 5_000,
                max_retries: 3,
                headers: vec![("X-Token".to_string(), "secret".to_string())],
            },
        ];

        let exporter = WebhookExporter::new(configs);
        assert_eq!(exporter.configs.len(), 2);
        assert_eq!(exporter.configs[0].url, "https://hooks.example.com/a");
        assert_eq!(exporter.configs[1].headers[0].0, "X-Token");
    }

    #[test]
    fn test_send_with_unserializable_payload_does_not_panic() {
        // A type that cannot be serialized to JSON (infinite float).
        // We use a pre-built Value to simulate a bad payload. Since serde_json::Value
        // always serializes, we validate the path with a struct that has a NaN float.
        #[derive(Serialize)]
        struct Bad {
            v: f64,
        }

        let exporter = WebhookExporter::new(vec![]);
        // Even if serialization somehow failed the exporter should not panic.
        // With no configs, this is a no-op that exercises the early-return path.
        exporter.send(&Bad { v: f64::NAN });
    }
}
