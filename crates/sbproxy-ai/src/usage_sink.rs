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
///
/// Deserializable as well as serializable so the verifiable ledger
/// (see [`crate::usage_ledger`]) can replay a persisted chain and
/// re-derive its hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// End-user identifier, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Team / tenant identifier, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// Stable per-request identifier. The verifiable ledger uses it as
    /// the dedup key so an at-least-once delivery collapses to
    /// exactly-once on replay. `None` events are never deduplicated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional tag set by a `set_sink_tag` action from the AI policy
    /// plane (WOR-1542), so a policy decision is queryable in the spend
    /// record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// A destination for completed-call usage events.
///
/// Implementations must be non-blocking on the hot path and must never panic or
/// propagate an error: failures are logged and swallowed.
pub trait UsageSink: Send + Sync + std::fmt::Debug {
    /// Record one completed-call event. Best effort.
    fn record(&self, event: &LlmUsageEvent);
    /// A short, stable label for logs and metrics.
    fn name(&self) -> &str;
}

/// A sink that appends one JSON object per line to a file.
#[derive(Debug)]
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
#[derive(Debug)]
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

/// Build the Langfuse `/api/public/ingestion` request body for one event.
///
/// `event_id` is the batch event and observation id; `timestamp` is an
/// RFC-3339 string. Token counts go in `usage`; provider, cost, latency,
/// status, and identifiers go in `metadata`. Kept pure (no clock, no IO) so
/// the shape is unit-testable; the sink supplies the id and timestamp.
pub fn langfuse_ingestion_body(
    event: &LlmUsageEvent,
    event_id: &str,
    timestamp: &str,
) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert("provider".into(), serde_json::json!(event.provider));
    metadata.insert("cost_usd".into(), serde_json::json!(event.cost_usd));
    metadata.insert("latency_ms".into(), serde_json::json!(event.latency_ms));
    metadata.insert("status".into(), serde_json::json!(event.status));
    for (k, v) in [
        ("key_id", &event.key_id),
        ("user", &event.user),
        ("team", &event.team),
        ("tag", &event.tag),
    ] {
        if let Some(val) = v {
            metadata.insert(k.into(), serde_json::json!(val));
        }
    }
    serde_json::json!({
        "batch": [{
            "id": event_id,
            "type": "generation-create",
            "timestamp": timestamp,
            "body": {
                "id": event_id,
                "name": "sbproxy",
                "model": event.model,
                "usage": {
                    "input": event.prompt_tokens,
                    "output": event.completion_tokens,
                    "total": event.total_tokens,
                    "unit": "TOKENS",
                },
                "metadata": serde_json::Value::Object(metadata),
            },
        }],
    })
}

/// Build the Datadog logs-intake request body (an array of one log object)
/// for `event`, tagged with `service`. Pure (no clock, no IO); Datadog
/// stamps the ingestion time itself.
pub fn datadog_log_body(event: &LlmUsageEvent, service: &str) -> serde_json::Value {
    let mut log = serde_json::Map::new();
    log.insert("ddsource".into(), serde_json::json!("sbproxy"));
    log.insert("service".into(), serde_json::json!(service));
    log.insert(
        "message".into(),
        serde_json::json!(format!("llm call {}/{}", event.provider, event.model)),
    );
    log.insert("provider".into(), serde_json::json!(event.provider));
    log.insert("model".into(), serde_json::json!(event.model));
    log.insert(
        "prompt_tokens".into(),
        serde_json::json!(event.prompt_tokens),
    );
    log.insert(
        "completion_tokens".into(),
        serde_json::json!(event.completion_tokens),
    );
    log.insert("total_tokens".into(), serde_json::json!(event.total_tokens));
    log.insert("cost_usd".into(), serde_json::json!(event.cost_usd));
    log.insert("latency_ms".into(), serde_json::json!(event.latency_ms));
    log.insert("status".into(), serde_json::json!(event.status));
    for (k, v) in [
        ("key_id", &event.key_id),
        ("user", &event.user),
        ("team", &event.team),
        ("tag", &event.tag),
    ] {
        if let Some(val) = v {
            log.insert(k.into(), serde_json::json!(val));
        }
    }
    serde_json::Value::Array(vec![serde_json::Value::Object(log)])
}

/// A sink that POSTs each event to Langfuse's ingestion API, fire-and-forget.
#[derive(Debug)]
pub struct LangfuseSink {
    url: String,
    public_key: String,
    secret_key: String,
    client: reqwest::Client,
}

impl LangfuseSink {
    /// Create a Langfuse sink. `host` is the base URL (e.g.
    /// `https://cloud.langfuse.com`); auth uses the public/secret key pair.
    pub fn new(host: &str, public_key: impl Into<String>, secret_key: impl Into<String>) -> Self {
        Self {
            url: format!("{}/api/public/ingestion", host.trim_end_matches('/')),
            public_key: public_key.into(),
            secret_key: secret_key.into(),
            client: reqwest::Client::new(),
        }
    }
}

impl UsageSink for LangfuseSink {
    fn record(&self, event: &LlmUsageEvent) {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let id = event
            .request_id
            .clone()
            .unwrap_or_else(|| format!("sb-{}-{timestamp}", event.provider));
        let body = langfuse_ingestion_body(event, &id, &timestamp);
        let url = self.url.clone();
        let (pk, sk) = (self.public_key.clone(), self.secret_key.clone());
        let client = self.client.clone();
        tokio::spawn(async move {
            if let Err(e) = client
                .post(&url)
                .basic_auth(pk, Some(sk))
                .json(&body)
                .send()
                .await
            {
                tracing::warn!(error = %e, "usage sink: langfuse POST failed");
            }
        });
    }

    fn name(&self) -> &str {
        "langfuse"
    }
}

/// A sink that POSTs each event to Datadog's logs-intake API, fire-and-forget.
#[derive(Debug)]
pub struct DatadogSink {
    url: String,
    api_key: String,
    service: String,
    client: reqwest::Client,
}

impl DatadogSink {
    /// Create a Datadog logs sink. `site` is the DD site (e.g.
    /// `datadoghq.com`, `datadoghq.eu`); `service` tags the log source.
    pub fn new(site: &str, api_key: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            url: format!("https://http-intake.logs.{site}/api/v2/logs"),
            api_key: api_key.into(),
            service: service.into(),
            client: reqwest::Client::new(),
        }
    }
}

impl UsageSink for DatadogSink {
    fn record(&self, event: &LlmUsageEvent) {
        let body = datadog_log_body(event, &self.service);
        let url = self.url.clone();
        let key = self.api_key.clone();
        let client = self.client.clone();
        tokio::spawn(async move {
            if let Err(e) = client
                .post(&url)
                .header("DD-API-KEY", key)
                .json(&body)
                .send()
                .await
            {
                tracing::warn!(error = %e, "usage sink: datadog POST failed");
            }
        });
    }

    fn name(&self) -> &str {
        "datadog"
    }
}

fn default_dd_site() -> String {
    "datadoghq.com".to_string()
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
    /// Append events to a tamper-evident, optionally signed ledger.
    ///
    /// See [`crate::usage_ledger`]. Each event is hash-chained to the
    /// previous one; with `signing_seed_hex` set, each entry is also
    /// Ed25519-signed so spend is provable, not just logged.
    Ledger {
        /// Filesystem path of the ledger (a JSONL write-ahead log).
        path: String,
        /// Optional 32-byte Ed25519 seed as hex. When present, every
        /// entry is signed. Resolve from a secret via `${VAR}` or a
        /// vault reference in the surrounding config.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signing_seed_hex: Option<String>,
    },
    /// POST events to Langfuse's ingestion API as generation observations.
    Langfuse {
        /// Base URL, e.g. `https://cloud.langfuse.com`.
        host: String,
        /// Langfuse public key.
        public_key: String,
        /// Langfuse secret key. Resolve from a secret via `${VAR}` or a
        /// vault reference in the surrounding config.
        secret_key: String,
    },
    /// POST events to Datadog's logs-intake API.
    Datadog {
        /// Datadog API key. Resolve from a secret via `${VAR}` or a vault
        /// reference in the surrounding config.
        api_key: String,
        /// Datadog site. Defaults to `datadoghq.com`; set `datadoghq.eu`,
        /// `us3.datadoghq.com`, etc. for other regions.
        #[serde(default = "default_dd_site")]
        site: String,
        /// Optional `service` tag on the emitted logs. Defaults to
        /// `sbproxy` at build time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
    },
}

impl UsageSinkConfig {
    /// Build the runtime sink for this config entry. Returned as an `Arc` so a
    /// single instance is shared across every request for the origin.
    pub fn build(&self) -> std::sync::Arc<dyn UsageSink> {
        match self {
            UsageSinkConfig::JsonlFile { path } => std::sync::Arc::new(JsonlFileSink::new(path)),
            UsageSinkConfig::Webhook { url } => std::sync::Arc::new(WebhookSink::new(url)),
            UsageSinkConfig::Ledger {
                path,
                signing_seed_hex,
            } => crate::usage_ledger::LedgerSink::build(path, signing_seed_hex.as_deref()),
            UsageSinkConfig::Langfuse {
                host,
                public_key,
                secret_key,
            } => std::sync::Arc::new(LangfuseSink::new(host, public_key, secret_key)),
            UsageSinkConfig::Datadog {
                api_key,
                site,
                service,
            } => std::sync::Arc::new(DatadogSink::new(
                site,
                api_key,
                service.clone().unwrap_or_else(|| "sbproxy".to_string()),
            )),
        }
    }
}

/// Build the runtime sinks for a list of configs.
pub fn build_sinks(configs: &[UsageSinkConfig]) -> Vec<std::sync::Arc<dyn UsageSink>> {
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
            request_id: None,
            tag: None,
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

    #[test]
    fn ledger_sink_config_parses_with_and_without_seed() {
        let cfgs: Vec<UsageSinkConfig> = serde_json::from_str(
            r#"[
                {"type":"ledger","path":"/tmp/sb-x.jsonl"},
                {"type":"ledger","path":"/tmp/sb-y.jsonl","signing_seed_hex":"abcd"}
            ]"#,
        )
        .unwrap();
        assert_eq!(cfgs.len(), 2);
        match &cfgs[0] {
            UsageSinkConfig::Ledger {
                path,
                signing_seed_hex,
            } => {
                assert_eq!(path, "/tmp/sb-x.jsonl");
                assert!(signing_seed_hex.is_none(), "seed omitted parses as None");
            }
            other => panic!("expected ledger, got {other:?}"),
        }
        match &cfgs[1] {
            UsageSinkConfig::Ledger {
                signing_seed_hex, ..
            } => assert_eq!(signing_seed_hex.as_deref(), Some("abcd")),
            other => panic!("expected ledger, got {other:?}"),
        }
    }

    #[test]
    fn langfuse_body_shapes_a_generation_event() {
        let body = langfuse_ingestion_body(&sample_event(), "evt-1", "2026-06-26T00:00:00Z");
        let batch = body.get("batch").unwrap().as_array().unwrap();
        assert_eq!(batch.len(), 1);
        let item = &batch[0];
        assert_eq!(item["id"], "evt-1");
        assert_eq!(item["type"], "generation-create");
        assert_eq!(item["timestamp"], "2026-06-26T00:00:00Z");
        let b = &item["body"];
        assert_eq!(b["model"], "gpt-4o-mini");
        assert_eq!(b["usage"]["input"], 10);
        assert_eq!(b["usage"]["output"], 5);
        assert_eq!(b["usage"]["total"], 15);
        assert_eq!(b["usage"]["unit"], "TOKENS");
        assert_eq!(b["metadata"]["provider"], "openai");
        assert_eq!(b["metadata"]["key_id"], "k1");
    }

    #[test]
    fn datadog_body_carries_usage_attributes() {
        let body = datadog_log_body(&sample_event(), "sbproxy-ai");
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let log = &arr[0];
        assert_eq!(log["ddsource"], "sbproxy");
        assert_eq!(log["service"], "sbproxy-ai");
        assert_eq!(log["provider"], "openai");
        assert_eq!(log["model"], "gpt-4o-mini");
        assert_eq!(log["total_tokens"], 15);
        assert_eq!(log["status"], 200);
        assert_eq!(log["key_id"], "k1");
    }

    #[test]
    fn config_parses_and_builds_langfuse_and_datadog() {
        let cfgs: Vec<UsageSinkConfig> = serde_json::from_str(
            r#"[
                {"type":"langfuse","host":"https://cloud.langfuse.com","public_key":"pk","secret_key":"sk"},
                {"type":"datadog","api_key":"dd","site":"datadoghq.eu","service":"my-svc"}
            ]"#,
        )
        .unwrap();
        assert_eq!(cfgs.len(), 2);
        let sinks = build_sinks(&cfgs);
        assert_eq!(sinks[0].name(), "langfuse");
        assert_eq!(sinks[1].name(), "datadog");
    }

    #[test]
    fn datadog_site_and_service_default() {
        let cfgs: Vec<UsageSinkConfig> =
            serde_json::from_str(r#"[{"type":"datadog","api_key":"dd"}]"#).unwrap();
        match &cfgs[0] {
            UsageSinkConfig::Datadog { site, service, .. } => {
                assert_eq!(site, "datadoghq.com");
                assert!(service.is_none());
            }
            other => panic!("expected datadog, got {other:?}"),
        }
    }
}
