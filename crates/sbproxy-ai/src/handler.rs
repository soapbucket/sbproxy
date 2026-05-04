//! AI request handler configuration and path parsing.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::budget::BudgetConfig;
use crate::guardrails::GuardrailsConfig;
use crate::identity::VirtualKeyConfig;
use crate::provider::ProviderConfig;
use crate::ratelimit::ModelRateConfig;
use crate::routing::RoutingStrategy;

/// AI gateway handler configuration.
#[derive(Debug, Deserialize)]
pub struct AiHandlerConfig {
    /// Configured upstream AI providers eligible for routing.
    pub providers: Vec<ProviderConfig>,
    /// Strategy used to select a provider for each request.
    #[serde(default = "default_strategy", deserialize_with = "deserialize_routing")]
    pub routing: RoutingStrategy,
    /// Optional allow-list of model names; empty means allow all.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Block-list of model names that takes precedence over the allow-list.
    #[serde(default)]
    pub blocked_models: Vec<String>,
    /// Maximum request body size in bytes accepted by the gateway.
    #[serde(default)]
    pub max_body_size: Option<usize>,
    /// Optional input/output guardrails pipeline.
    #[serde(default)]
    pub guardrails: Option<GuardrailsConfig>,
    /// Optional budget enforcement configuration.
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
    /// Virtual API keys mapped to provider keys and scopes.
    #[serde(default)]
    pub virtual_keys: Vec<VirtualKeyConfig>,
    /// Per-model rate limit overrides keyed by model name.
    #[serde(default)]
    pub model_rate_limits: HashMap<String, ModelRateConfig>,
    /// Maximum concurrent in-flight requests per provider.
    #[serde(default)]
    pub max_concurrent: Option<HashMap<String, u32>>,
    /// Optional per-provider resilience policy (circuit breaker plus
    /// outlier detection plus active health probes). When set, the
    /// router skips providers whose state machine has tripped, the
    /// same way the proxy / load_balancer paths exclude unhealthy
    /// upstreams.
    #[serde(default)]
    pub resilience: Option<AiResilienceConfig>,
    /// Optional shadow / side-by-side eval. The primary response is
    /// served unchanged; a copy of every request goes to the shadow
    /// provider concurrently and metrics (TTFT, tokens, cost,
    /// finish_reason) are logged.
    #[serde(default)]
    pub shadow: Option<AiShadowConfig>,
    /// Optional pattern-aware PII redaction applied at the request
    /// and (optionally) response body boundary. When set the gateway
    /// scans the JSON body for the configured PII shapes and
    /// rewrites them to fixed markers before forwarding upstream.
    /// See `sbproxy_security::pii::PiiConfig` for the rule schema.
    #[serde(default)]
    pub pii: Option<sbproxy_security::pii::PiiConfig>,
    /// Opaque semantic-cache configuration block. The OSS proxy
    /// stores this verbatim and surfaces it through the stream cache
    /// recorder hook so the enterprise implementation can read its
    /// `streaming` sub-block (`enabled`, `replay_pacing`, ...) without
    /// the OSS pipeline having to validate or interpret any of those
    /// fields. Shape contract lives in the enterprise crate; OSS only
    /// passes the value through.
    #[serde(default)]
    pub semantic_cache: Option<serde_json::Value>,
    /// Selects the SSE usage parser for the streaming relay.
    /// Recognized values: `auto` (default; chooses by upstream URL,
    /// `Content-Type`, or response `X-Provider` header), `openai`,
    /// `anthropic`, `vertex`, `bedrock`, `cohere`, `ollama`,
    /// `generic`, or `none` (disable parsing). Unknown values warn
    /// and fall back to `generic` so a typo never silently disables
    /// budget recording.
    #[serde(default = "default_usage_parser")]
    pub usage_parser: String,
    /// Lazy-built compiled redactor cached on the per-origin
    /// config. Built on first use so config-load does not pay the
    /// regex-compile cost for origins that never serve a request.
    /// `None` value inside the OnceLock means "tried to build and
    /// either no config or invalid"; the request path treats both
    /// the same way (skip redaction).
    #[serde(skip)]
    pub(crate) pii_redactor: OnceLock<Option<sbproxy_security::pii::PiiRedactor>>,
}

fn default_usage_parser() -> String {
    "auto".to_string()
}

impl AiHandlerConfig {
    /// Return the compiled PII redactor for this handler, building
    /// it on first call. `None` when redaction is not configured
    /// or the configuration failed to compile (which is logged).
    pub fn pii_redactor(&self) -> Option<&sbproxy_security::pii::PiiRedactor> {
        self.pii_redactor
            .get_or_init(|| {
                let cfg = self.pii.as_ref()?;
                if !cfg.enabled {
                    return None;
                }
                match sbproxy_security::pii::PiiRedactor::from_config(cfg) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "AI handler: PII redactor failed to compile; redaction disabled"
                        );
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Apply PII redaction to a parsed request body. Returns whether
    /// any redactor ran. Tests use this to assert that the wiring
    /// the request handler relies on (PII config -> redactor ->
    /// in-place JSON walk) actually mutates the body the way the
    /// downstream forward path will see it.
    ///
    /// This mirrors the call site in
    /// `sbproxy-core/src/server.rs::handle_ai_proxy` and is the
    /// integration shim e2e tests exercise.
    pub fn apply_request_pii(&self, body: &mut serde_json::Value) -> bool {
        let cfg = match self.pii.as_ref() {
            Some(c) if c.enabled && c.redact_request => c,
            _ => return false,
        };
        // Touching `cfg` keeps clippy from flagging the binding as
        // unused; the actual gate is `pii_redactor()` which reads
        // `self.pii` directly.
        let _ = cfg;
        if let Some(redactor) = self.pii_redactor() {
            redactor.redact_json(body);
            return true;
        }
        false
    }
}

/// Per-provider resilience signals layered on top of the routing
/// strategy. Each signal independently ejects a provider; when every
/// provider is ejected, the router falls back to the unfiltered list
/// rather than returning no provider at all.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AiResilienceConfig {
    /// Formal Closed -> Open -> HalfOpen breaker per provider.
    #[serde(default)]
    pub circuit_breaker: Option<AiCircuitBreakerConfig>,
    /// Sliding-window failure-rate ejection.
    #[serde(default)]
    pub outlier_detection: Option<AiOutlierConfig>,
    /// Active health probe of the provider's `/v1/models` endpoint.
    #[serde(default)]
    pub health_check: Option<AiHealthCheckConfig>,
}

/// Circuit-breaker tuning shared with the load_balancer flavour.
#[derive(Debug, Deserialize, Clone)]
pub struct AiCircuitBreakerConfig {
    /// Consecutive failures (5xx or transport error) before the breaker opens.
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u32,
    /// Consecutive half-open successes required to close the breaker.
    #[serde(default = "default_cb_success_threshold")]
    pub success_threshold: u32,
    /// Cooldown in seconds after opening before a half-open probe is allowed.
    #[serde(default = "default_cb_open_duration_secs")]
    pub open_duration_secs: u64,
}

fn default_cb_failure_threshold() -> u32 {
    5
}
fn default_cb_success_threshold() -> u32 {
    2
}
fn default_cb_open_duration_secs() -> u64 {
    30
}

/// Outlier-detector tuning shared with the load_balancer flavour.
#[derive(Debug, Deserialize, Clone)]
pub struct AiOutlierConfig {
    /// Failure-rate threshold (0.0 to 1.0) over the window before ejection.
    #[serde(default = "default_outlier_threshold")]
    pub threshold: f64,
    /// Sliding window length in seconds.
    #[serde(default = "default_outlier_window")]
    pub window_secs: u64,
    /// Minimum sample count before the failure-rate is evaluated.
    #[serde(default = "default_outlier_min")]
    pub min_requests: u32,
    /// How long an ejected provider stays out of the rotation, in seconds.
    #[serde(default = "default_outlier_eject")]
    pub ejection_duration_secs: u64,
}

fn default_outlier_threshold() -> f64 {
    0.5
}
fn default_outlier_window() -> u64 {
    60
}
fn default_outlier_min() -> u32 {
    5
}
fn default_outlier_eject() -> u64 {
    30
}

/// Active probe of an AI provider. The probe is a `GET /models`
/// (or `path` if overridden); a 2xx response counts as success.
#[derive(Debug, Deserialize, Clone)]
pub struct AiHealthCheckConfig {
    /// Path probed on each provider's base URL. Defaults to `/models`.
    #[serde(default = "default_health_path")]
    pub path: String,
    /// How often to run the probe, in seconds.
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,
    /// Probe request timeout in milliseconds.
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    /// Consecutive probe failures required to mark the provider unhealthy.
    #[serde(default = "default_health_unhealthy")]
    pub unhealthy_threshold: u32,
    /// Consecutive probe successes required to mark the provider healthy.
    #[serde(default = "default_health_healthy")]
    pub healthy_threshold: u32,
}

fn default_health_path() -> String {
    "/models".to_string()
}
fn default_health_interval() -> u64 {
    30
}
fn default_health_timeout_ms() -> u64 {
    5000
}
fn default_health_unhealthy() -> u32 {
    3
}
fn default_health_healthy() -> u32 {
    2
}

/// Shadow / side-by-side eval: send the same request to a second
/// provider concurrently and log metadata. The shadow response is
/// drained and discarded; the primary's response goes to the client
/// unchanged.
///
/// Shadow tasks are supervised by a bounded queue. When the in-flight
/// queue fills up the new request is dropped (a counter ticks) instead
/// of being silently spawned, and each task has a hard wall-clock
/// timeout that, when exceeded, drops the future and ticks a separate
/// timeout counter. See `sbproxy_ai::client::AiClient` for the
/// supervisor implementation.
#[derive(Debug, Deserialize, Clone)]
pub struct AiShadowConfig {
    /// Provider name to shadow against. Must also appear in the
    /// `providers` list (so its API key, base URL, and rate limits
    /// resolve normally). Use a different model than the primary if
    /// you want to A/B different model versions.
    pub provider: String,
    /// Optional model override for the shadow request. Defaults to
    /// the same model the client sent.
    #[serde(default)]
    pub model: Option<String>,
    /// Sample rate in `[0.0, 1.0]`. Default `1.0` (mirror every
    /// request). Set lower to avoid doubling spend on every call.
    #[serde(default = "default_shadow_sample_rate")]
    pub sample_rate: f32,
    /// Per-shadow-request HTTP timeout in milliseconds. Default
    /// 30000. This is the upstream request timeout passed to reqwest.
    #[serde(default = "default_shadow_timeout_ms")]
    pub timeout_ms: u64,
    /// Wall-clock supervisor timeout in milliseconds. The supervisor
    /// drops the spawned shadow future and ticks
    /// `sbproxy_ai_shadow_timeout_total` once this elapses, even if
    /// reqwest is still mid-handshake. Defaults to 30000 and is
    /// independent of `timeout_ms` so the operator can guard against
    /// providers that hang inside DNS, TLS, or pre-body read paths.
    #[serde(default = "default_shadow_task_timeout_ms")]
    pub task_timeout_ms: u64,
}

fn default_shadow_sample_rate() -> f32 {
    1.0
}
fn default_shadow_timeout_ms() -> u64 {
    30_000
}
fn default_shadow_task_timeout_ms() -> u64 {
    30_000
}

fn default_strategy() -> RoutingStrategy {
    RoutingStrategy::RoundRobin
}

/// Deserialize routing from either:
/// - A flat string: `"round_robin"` (Rust format)
/// - A nested object: `{strategy: "round_robin", ...}` (Go format)
fn deserialize_routing<'de, D>(deserializer: D) -> Result<RoutingStrategy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct RoutingObject {
        strategy: RoutingStrategy,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RoutingFormat {
        Flat(RoutingStrategy),
        Nested(RoutingObject),
    }

    match RoutingFormat::deserialize(deserializer)? {
        RoutingFormat::Flat(s) => Ok(s),
        RoutingFormat::Nested(obj) => Ok(obj.strategy),
    }
}

impl AiResilienceConfig {
    /// Maximum total provider attempts when a request fails. Falls
    /// back to the count of enabled providers when no
    /// `circuit_breaker.failure_threshold` is configured (i.e. just
    /// "try every provider once" semantics).
    pub fn max_attempts(&self, num_providers: usize) -> usize {
        // Cap at provider count; the client also short-circuits when
        // it sees the same provider twice in a row.
        std::cmp::max(1, num_providers).min(num_providers.max(1))
    }
}

impl AiHandlerConfig {
    /// Build from a generic JSON value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Number of provider attempts allowed for one client request.
    /// Defaults to 1 (no retry) when no `resilience` block is set.
    /// Otherwise capped at the configured provider count so we never
    /// loop forever on a totally degraded fleet.
    pub fn resilience_max_attempts(&self) -> usize {
        if self.resilience.is_some() {
            std::cmp::min(self.providers.len().max(1), 5)
        } else {
            1
        }
    }

    /// Check if a model is allowed by the allow/block lists.
    pub fn is_model_allowed(&self, model: &str) -> bool {
        // Block list takes precedence
        if !self.blocked_models.is_empty() && self.blocked_models.iter().any(|m| m == model) {
            return false;
        }
        // If allow list is set, model must be in it
        if !self.allowed_models.is_empty() {
            return self.allowed_models.iter().any(|m| m == model);
        }
        true
    }
}

/// Detected AI API path type.
#[derive(Debug, PartialEq, Eq)]
pub enum AiApiPath {
    /// OpenAI-compatible chat completions endpoint.
    ChatCompletions,
    /// Model listing endpoint.
    Models,
    /// Embeddings creation endpoint.
    Embeddings,
    /// Path did not match any known AI endpoint.
    Unknown,
}

/// Parse a request path to determine the AI API endpoint type.
pub fn parse_ai_path(path: &str) -> AiApiPath {
    if path.ends_with("/chat/completions") {
        AiApiPath::ChatCompletions
    } else if path.ends_with("/models") {
        AiApiPath::Models
    } else if path.ends_with("/embeddings") {
        AiApiPath::Embeddings
    } else {
        AiApiPath::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ai_path_chat_completions() {
        assert_eq!(
            parse_ai_path("/v1/chat/completions"),
            AiApiPath::ChatCompletions
        );
        assert_eq!(
            parse_ai_path("/api/v1/chat/completions"),
            AiApiPath::ChatCompletions
        );
    }

    #[test]
    fn parse_ai_path_models() {
        assert_eq!(parse_ai_path("/v1/models"), AiApiPath::Models);
    }

    #[test]
    fn parse_ai_path_embeddings() {
        assert_eq!(parse_ai_path("/v1/embeddings"), AiApiPath::Embeddings);
    }

    #[test]
    fn parse_ai_path_unknown() {
        assert_eq!(parse_ai_path("/v1/completions"), AiApiPath::Unknown);
        assert_eq!(parse_ai_path("/health"), AiApiPath::Unknown);
    }

    #[test]
    fn model_allowed_no_lists() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: Vec::new(),
            blocked_models: Vec::new(),
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            semantic_cache: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
        };
        assert!(config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("anything"));
    }

    #[test]
    fn model_blocked() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: Vec::new(),
            blocked_models: vec!["gpt-4".to_string()],
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            semantic_cache: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
        };
        assert!(!config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("gpt-3.5-turbo"));
    }

    #[test]
    fn model_allowed_list() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()],
            blocked_models: Vec::new(),
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            semantic_cache: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
        };
        assert!(config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("gpt-3.5-turbo"));
        assert!(!config.is_model_allowed("claude-3"));
    }

    #[test]
    fn model_blocked_takes_precedence() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: vec!["gpt-4".to_string()],
            blocked_models: vec!["gpt-4".to_string()],
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            semantic_cache: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
        };
        // Block list wins
        assert!(!config.is_model_allowed("gpt-4"));
    }

    #[test]
    fn ai_handler_config_from_config() {
        let json = serde_json::json!({
            "providers": [
                {"name": "openai", "api_key": "sk-test", "weight": 3},
                {"name": "anthropic", "api_key": "sk-ant-test", "priority": 1}
            ],
            "routing": "weighted",
            "allowed_models": ["gpt-4"],
            "max_body_size": 1048576
        });
        let config = AiHandlerConfig::from_config(json).unwrap();
        assert_eq!(config.providers.len(), 2);
        assert_eq!(config.providers[0].name, "openai");
        assert_eq!(config.providers[0].weight, 3);
        assert_eq!(config.allowed_models, vec!["gpt-4"]);
        assert_eq!(config.max_body_size, Some(1048576));
    }

    #[test]
    fn ai_handler_config_defaults() {
        let json = serde_json::json!({
            "providers": [{"name": "openai"}]
        });
        let config = AiHandlerConfig::from_config(json).unwrap();
        assert!(config.allowed_models.is_empty());
        assert!(config.blocked_models.is_empty());
        assert!(config.max_body_size.is_none());
    }

    #[test]
    fn ai_handler_config_missing_providers() {
        let json = serde_json::json!({});
        assert!(AiHandlerConfig::from_config(json).is_err());
    }

    // --- PII redaction end-to-end wiring ---
    //
    // These tests exercise the same code path the AI request handler
    // takes when forwarding to an upstream: parse the inbound body,
    // call `apply_request_pii`, then read the mutated body. Together
    // with the rule-level coverage in `sbproxy_security::pii::tests`
    // they prove the user-facing acceptance shape from the Phase 3
    // requirements.

    #[test]
    fn pii_request_redaction_replaces_email_and_credit_card() {
        // The exact body shape from the acceptance criterion:
        // {"prompt": "Email me at alice@example.com about card 4111-1111-1111-1111"}
        // After the handler's redaction pass, the upstream provider
        // must see the email and card replaced with markers.
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": { "enabled": true }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();

        let mut body = serde_json::json!({
            "prompt": "Email me at alice@example.com about card 4111-1111-1111-1111"
        });
        let redacted = config.apply_request_pii(&mut body);
        assert!(redacted, "redactor should have run");

        let prompt = body["prompt"].as_str().unwrap();
        assert!(!prompt.contains("alice@example.com"), "got: {prompt}");
        assert!(!prompt.contains("4111-1111-1111-1111"), "got: {prompt}");
        assert!(prompt.contains("[REDACTED:EMAIL]"), "got: {prompt}");
        assert!(prompt.contains("[REDACTED:CARD]"), "got: {prompt}");
    }

    #[test]
    fn pii_redaction_disabled_when_no_config() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}]
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({"prompt": "alice@example.com"});
        let redacted = config.apply_request_pii(&mut body);
        assert!(!redacted, "no PII config = no redaction");
        assert_eq!(
            body["prompt"].as_str(),
            Some("alice@example.com"),
            "body must be untouched when PII is disabled"
        );
    }

    #[test]
    fn pii_redaction_skipped_when_request_redaction_off() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "redact_request": false,
                "redact_response": true
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({"prompt": "alice@example.com"});
        let redacted = config.apply_request_pii(&mut body);
        assert!(!redacted);
        assert_eq!(body["prompt"].as_str(), Some("alice@example.com"));
    }

    #[test]
    fn pii_redaction_walks_into_messages_array() {
        // Realistic OpenAI-style chat completions body.
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": { "enabled": true }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [
                { "role": "system", "content": "Operator email is ops@example.com." },
                { "role": "user", "content": "Card on file 5555-5555-5555-4444. SSN 123-45-6789." }
            ]
        });
        let redacted = config.apply_request_pii(&mut body);
        assert!(redacted);

        let sys = body["messages"][0]["content"].as_str().unwrap();
        let usr = body["messages"][1]["content"].as_str().unwrap();
        assert!(sys.contains("[REDACTED:EMAIL]"), "system: {sys}");
        assert!(usr.contains("[REDACTED:CARD]"), "user: {usr}");
        assert!(usr.contains("[REDACTED:SSN]"), "user: {usr}");
        // Model name (which happens to be schema-defined) must
        // remain untouched.
        assert_eq!(body["model"].as_str(), Some("gpt-4o"));
    }

    #[test]
    fn pii_custom_rule_appended_via_config() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "rules": [
                    {
                        "name": "internal_id",
                        "pattern": "INT-\\d{6}",
                        "replacement": "[REDACTED:INTERNAL]",
                        "anchor": "INT-"
                    }
                ]
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({
            "prompt": "Reference INT-987654 plus alice@example.com."
        });
        let redacted = config.apply_request_pii(&mut body);
        assert!(redacted);
        let prompt = body["prompt"].as_str().unwrap();
        assert!(prompt.contains("[REDACTED:INTERNAL]"), "{prompt}");
        // Defaults still active alongside the custom rule.
        assert!(prompt.contains("[REDACTED:EMAIL]"), "{prompt}");
    }
}
