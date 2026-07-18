//! Typed configuration and validation for the compression pipeline.

use crate::provider::ProviderConfig;
use anyhow::bail;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default completion capacity reserved by the legacy window-fit behavior.
pub const DEFAULT_COMPLETION_RESERVE_TOKENS: u64 = 1_024;

/// Ordered context-compression policy for one AI handler.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompressionPolicy {
    /// Shared-state backend used by stateful levers.
    #[serde(default)]
    pub state: Option<CompressionStateConfig>,
    /// Permit audited Admin-only summary-content inspection.
    #[serde(default)]
    pub allow_admin_content_inspection: bool,
    /// Compression levers executed in declaration order.
    #[serde(default)]
    pub levers: Vec<CompressionLeverConfig>,
}

/// External state selected for stateful compression levers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompressionStateConfig {
    /// Existing process-wide state subsystem to reuse.
    pub backend: CompressionBackend,
    /// Record lifetime, in seconds after deserialization.
    #[serde(
        rename = "ttl",
        deserialize_with = "sbproxy_config::duration::deserialize_secs"
    )]
    #[schemars(with = "DurationSchema")]
    pub ttl_secs: u64,
}

/// Supported external state backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompressionBackend {
    /// Strict Redis lease, fence, and compare-and-set storage.
    Redis,
    /// Eventual last-writer-wins mesh storage.
    Mesh,
}

/// One configured compression lever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompressionLeverConfig {
    /// Stateful running-summary compaction.
    SummaryBuffer(SummaryBufferConfig),
    /// Deterministic compatibility trimming to the target model window.
    WindowFit(WindowFitConfig),
}

/// Configuration for the stateful running-summary lever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryBufferConfig {
    /// Minimum request input tokens before summary buffering is eligible.
    pub min_tokens: u64,
    /// Number of most recent messages retained byte-for-byte.
    pub retain_recent_messages: usize,
    /// Maximum tokens requested from the dedicated summarizer.
    pub target_summary_tokens: u64,
    /// Dedicated provider and model used for internal summaries.
    pub summarizer: SummarizerConfig,
}

/// Dedicated internal summarizer selection and timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummarizerConfig {
    /// Provider name from the same AI handler.
    pub provider: String,
    /// Model sent to the selected provider.
    pub model: String,
    /// Hard request timeout, in seconds after deserialization.
    #[serde(
        rename = "timeout",
        deserialize_with = "sbproxy_config::duration::deserialize_secs"
    )]
    #[schemars(with = "DurationSchema")]
    pub timeout_secs: u64,
}

/// Configuration for deterministic model-window fitting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowFitConfig {
    /// Completion capacity excluded from the input-message budget.
    #[serde(default = "default_completion_reserve_tokens")]
    pub completion_reserve_tokens: u64,
}

impl Default for WindowFitConfig {
    fn default() -> Self {
        Self {
            completion_reserve_tokens: DEFAULT_COMPLETION_RESERVE_TOKENS,
        }
    }
}

impl CompressionPolicy {
    /// Construct the one-lever policy representing the legacy boolean.
    pub fn legacy_window_fit(completion_reserve_tokens: Option<u64>) -> Self {
        Self {
            state: None,
            allow_admin_content_inspection: false,
            levers: vec![CompressionLeverConfig::WindowFit(WindowFitConfig {
                completion_reserve_tokens: completion_reserve_tokens
                    .unwrap_or(DEFAULT_COMPLETION_RESERVE_TOKENS),
            })],
        }
    }

    /// Validate policy-local invariants and summarizer provider references.
    pub fn validate(&self, providers: &[ProviderConfig]) -> anyhow::Result<()> {
        if self.state.as_ref().is_some_and(|state| state.ttl_secs == 0) {
            bail!("compression.state.ttl must be greater than zero");
        }

        for (index, lever) in self.levers.iter().enumerate() {
            let CompressionLeverConfig::SummaryBuffer(summary) = lever else {
                continue;
            };
            if self.state.is_none() {
                bail!("compression.state is required for summary_buffer");
            }
            if summary.min_tokens == 0 {
                bail!("compression.levers[{index}].min_tokens must be greater than zero");
            }
            if summary.retain_recent_messages == 0 {
                bail!(
                    "compression.levers[{index}].retain_recent_messages must be greater than zero"
                );
            }
            if summary.target_summary_tokens == 0 {
                bail!(
                    "compression.levers[{index}].target_summary_tokens must be greater than zero"
                );
            }
            if summary.target_summary_tokens >= summary.min_tokens {
                bail!(
                    "compression.levers[{index}].target_summary_tokens must be smaller than min_tokens"
                );
            }
            if summary.summarizer.model.trim().is_empty() {
                bail!("compression.levers[{index}].summarizer.model must not be empty");
            }
            if summary.summarizer.timeout_secs == 0 {
                bail!("compression.levers[{index}].summarizer.timeout must be greater than zero");
            }
            if !providers
                .iter()
                .any(|provider| provider.name.as_str() == summary.summarizer.provider)
            {
                bail!(
                    "compression.levers[{index}].summarizer.provider {:?} is not configured on this AI handler",
                    summary.summarizer.provider
                );
            }
        }
        Ok(())
    }
}

fn default_completion_reserve_tokens() -> u64 {
    DEFAULT_COMPLETION_RESERVE_TOKENS
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
enum DurationSchema {
    Seconds(u64),
    Human(String),
}

#[cfg(test)]
mod tests {
    use super::{CompressionBackend, CompressionLeverConfig};
    use crate::handler::AiHandlerConfig;

    fn provider(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "api_key": "test-key",
            "models": ["gpt-test"]
        })
    }

    fn valid_config() -> serde_json::Value {
        serde_json::json!({
            "providers": [provider("openai"), provider("anthropic")],
            "compression": {
                "state": {
                    "backend": "redis",
                    "ttl": "24h"
                },
                "levers": [
                    {
                        "type": "summary_buffer",
                        "min_tokens": 12_000,
                        "retain_recent_messages": 8,
                        "target_summary_tokens": 2_048,
                        "summarizer": {
                            "provider": "anthropic",
                            "model": "gpt-test",
                            "timeout": "5s"
                        }
                    },
                    {
                        "type": "window_fit",
                        "completion_reserve_tokens": 1_024
                    }
                ]
            }
        })
    }

    #[test]
    fn parses_ordered_policy_and_human_durations() {
        let config = AiHandlerConfig::from_config(valid_config()).expect("compression parses");
        let policy = config.compression.as_ref().expect("explicit policy");

        let state = policy.state.as_ref().expect("state config");
        assert_eq!(state.backend, CompressionBackend::Redis);
        assert_eq!(state.ttl_secs, 24 * 60 * 60);
        assert!(!policy.allow_admin_content_inspection);
        assert_eq!(policy.levers.len(), 2);

        match &policy.levers[0] {
            CompressionLeverConfig::SummaryBuffer(summary) => {
                assert_eq!(summary.min_tokens, 12_000);
                assert_eq!(summary.retain_recent_messages, 8);
                assert_eq!(summary.target_summary_tokens, 2_048);
                assert_eq!(summary.summarizer.provider, "anthropic");
                assert_eq!(summary.summarizer.model, "gpt-test");
                assert_eq!(summary.summarizer.timeout_secs, 5);
            }
            other => panic!("expected summary_buffer first, got {other:?}"),
        }
        match &policy.levers[1] {
            CompressionLeverConfig::WindowFit(window) => {
                assert_eq!(window.completion_reserve_tokens, 1_024);
            }
            other => panic!("expected window_fit second, got {other:?}"),
        }
    }

    #[test]
    fn rejects_summary_buffer_without_state() {
        let mut value = valid_config();
        value["compression"]
            .as_object_mut()
            .unwrap()
            .remove("state");

        let error = AiHandlerConfig::from_config(value).unwrap_err().to_string();
        assert!(error.contains("compression.state is required for summary_buffer"));
    }

    #[test]
    fn rejects_unknown_summarizer_provider() {
        let mut value = valid_config();
        value["compression"]["levers"][0]["summarizer"]["provider"] =
            serde_json::json!("missing-provider");

        let error = AiHandlerConfig::from_config(value).unwrap_err().to_string();
        assert!(error.contains(
            "compression.levers[0].summarizer.provider \"missing-provider\" is not configured"
        ));
    }

    #[test]
    fn rejects_invalid_summary_buffer_numbers() {
        let cases = [
            ("min_tokens", 0, "min_tokens must be greater than zero"),
            (
                "retain_recent_messages",
                0,
                "retain_recent_messages must be greater than zero",
            ),
            (
                "target_summary_tokens",
                0,
                "target_summary_tokens must be greater than zero",
            ),
        ];

        for (field, value, expected) in cases {
            let mut config = valid_config();
            config["compression"]["levers"][0][field] = serde_json::json!(value);
            let error = AiHandlerConfig::from_config(config)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{field}: {error}");
        }
    }

    #[test]
    fn rejects_zero_state_ttl_and_summarizer_timeout() {
        let mut zero_ttl = valid_config();
        zero_ttl["compression"]["state"]["ttl"] = serde_json::json!(0);
        let error = AiHandlerConfig::from_config(zero_ttl)
            .unwrap_err()
            .to_string();
        assert!(error.contains("compression.state.ttl must be greater than zero"));

        let mut zero_timeout = valid_config();
        zero_timeout["compression"]["levers"][0]["summarizer"]["timeout"] = serde_json::json!(0);
        let error = AiHandlerConfig::from_config(zero_timeout)
            .unwrap_err()
            .to_string();
        assert!(error.contains("summarizer.timeout must be greater than zero"));
    }

    #[test]
    fn rejects_empty_model_and_non_reducing_summary_target() {
        let mut empty_model = valid_config();
        empty_model["compression"]["levers"][0]["summarizer"]["model"] = serde_json::json!("  ");
        let error = AiHandlerConfig::from_config(empty_model)
            .unwrap_err()
            .to_string();
        assert!(error.contains("summarizer.model must not be empty"));

        let mut target_too_large = valid_config();
        target_too_large["compression"]["levers"][0]["target_summary_tokens"] =
            serde_json::json!(12_000);
        let error = AiHandlerConfig::from_config(target_too_large)
            .unwrap_err()
            .to_string();
        assert!(error.contains("target_summary_tokens must be smaller than min_tokens"));
    }

    #[test]
    fn missing_compression_preserves_disabled_legacy_behavior() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")]
        }))
        .expect("base config");

        assert!(config.effective_compression_policy().is_none());
    }

    #[test]
    fn legacy_context_compress_maps_to_window_fit() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "resilience": {
                "llm_aware": {
                    "context_compress": true,
                    "completion_reserve_tokens": 2_048
                }
            }
        }))
        .expect("legacy config");

        let effective = config
            .effective_compression_policy()
            .expect("legacy policy");
        assert!(effective.state.is_none());
        assert_eq!(effective.levers.len(), 1);
        match &effective.levers[0] {
            CompressionLeverConfig::WindowFit(window) => {
                assert_eq!(window.completion_reserve_tokens, 2_048);
            }
            other => panic!("expected legacy window_fit, got {other:?}"),
        }
    }

    #[test]
    fn explicit_empty_policy_wins_over_legacy() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider("openai")],
            "resilience": {
                "llm_aware": {
                    "context_compress": true,
                    "completion_reserve_tokens": 2_048
                }
            },
            "compression": {
                "levers": []
            }
        }))
        .expect("explicit empty config");

        let effective = config
            .effective_compression_policy()
            .expect("explicit policy remains present");
        assert!(effective.levers.is_empty());
    }
}
