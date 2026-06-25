//! Pluggable usage sinks for completed LLM calls.
//!
//! A usage sink forwards a record of every finished LLM request to an external
//! system (a log file, an HTTP collector, an observability backend). This is
//! the open-source seam that LiteLLM's `success_callback` / `failure_callback`
//! / `callbacks` map onto: sinks emit outward and hold no internal durable
//! state, so the persistence lives in the external system. Closed-source sinks
//! extend the same [`UsageSink`] trait via the plugin registry.
//!
//! Sinks must be non-blocking on the request hot path and must never propagate
//! a failure: a broken sink cannot fail the request it is logging.

use serde::{Deserialize, Serialize};

/// A record of one completed LLM call, handed to every configured sink.
#[derive(Debug, Clone, Serialize)]
pub struct LlmUsageEvent {
    /// Provider that served the request (e.g. `openai`).
    pub provider: String,
    /// Model that served the request.
    pub model: String,
    /// Prompt (input) tokens.
    pub prompt_tokens: u64,
    /// Completion (output) tokens.
    pub completion_tokens: u64,
    /// Total tokens billed.
    pub total_tokens: u64,
    /// Derived cost of the call in USD.
    pub cost_usd: f64,
    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,
    /// Final HTTP status returned to the client.
    pub status: u16,
    /// Authenticated key identifier, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// End-user identifier, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Team / tenant identifier, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
}

/// A destination for completed-call usage events.
///
/// Implementations must be non-blocking on the hot path and must never panic or
/// propagate an error: failures are logged and swallowed.
pub trait UsageSink: Send + Sync {
    /// Record one completed-call event. Best effort.
    fn record(&self, event: &LlmUsageEvent);
    /// A short, stable label for logs and metrics.
    fn name(&self) -> &str;
}

/// A sink that appends one JSON object per line to a file.
pub struct JsonlFileSink {
    path: std::path::PathBuf,
}

impl JsonlFileSink {
    /// Create a sink that appends events to `path`, creating it if absent.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl UsageSink for JsonlFileSink {
    fn record(&self, event: &LlmUsageEvent) {
        use std::io::Write as _;
        let line = match serde_json::to_string(event) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "usage sink: failed to serialize event");
                return;
            }
        };
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::warn!(error = %e, path = %self.path.display(), "usage sink: write failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %self.path.display(), "usage sink: open failed")
            }
        }
    }

    fn name(&self) -> &str {
        "jsonl_file"
    }
}

/// A sink that POSTs each event as JSON to a webhook URL, fire-and-forget.
pub struct WebhookSink {
    url: String,
    client: reqwest::Client,
}

impl WebhookSink {
    /// Create a webhook sink that POSTs events to `url`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }
}

impl UsageSink for WebhookSink {
    fn record(&self, event: &LlmUsageEvent) {
        let body = match serde_json::to_vec(event) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "usage sink: failed to serialize event");
                return;
            }
        };
        let url = self.url.clone();
        let client = self.client.clone();
        // Fire-and-forget so the request hot path is never blocked or failed by
        // the sink.
        tokio::spawn(async move {
            if let Err(e) = client
                .post(&url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
            {
                tracing::warn!(error = %e, "usage sink: webhook POST failed");
            }
        });
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

/// Declarative config for a usage sink, parsed from the action's
/// `usage_sinks` list.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UsageSinkConfig {
    /// Append events to a JSONL file.
    JsonlFile {
        /// Filesystem path to append to.
        path: String,
    },
    /// POST events to an HTTP collector.
    Webhook {
        /// Collector URL.
        url: String,
    },
}

impl UsageSinkConfig {
    /// Build the runtime sink for this config entry.
    pub fn build(&self) -> Box<dyn UsageSink> {
        match self {
            UsageSinkConfig::JsonlFile { path } => Box::new(JsonlFileSink::new(path)),
            UsageSinkConfig::Webhook { url } => Box::new(WebhookSink::new(url)),
        }
    }
}

/// Build the runtime sinks for a list of configs.
pub fn build_sinks(configs: &[UsageSinkConfig]) -> Vec<Box<dyn UsageSink>> {
    configs.iter().map(UsageSinkConfig::build).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cost_usd: 0.001,
            latency_ms: 200,
            status: 200,
            key_id: Some("k1".into()),
            user: None,
            team: None,
        }
    }

    #[test]
    fn jsonl_file_sink_appends_parseable_events() {
        let path = std::env::temp_dir().join(format!("sb-usage-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sink = JsonlFileSink::new(&path);
        sink.record(&sample_event());
        sink.record(&sample_event());

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per event");
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["model"], "gpt-4o-mini");
        assert_eq!(parsed["total_tokens"], 15);
        // None fields are omitted, not serialized as null.
        assert!(parsed.get("user").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_parses_and_builds_both_sink_types() {
        let cfgs: Vec<UsageSinkConfig> = serde_json::from_str(
            r#"[
                {"type":"jsonl_file","path":"/var/log/sb-usage.jsonl"},
                {"type":"webhook","url":"https://collector.example.com/ingest"}
            ]"#,
        )
        .unwrap();
        assert_eq!(cfgs.len(), 2);
        let sinks = build_sinks(&cfgs);
        assert_eq!(sinks[0].name(), "jsonl_file");
        assert_eq!(sinks[1].name(), "webhook");
    }
}
