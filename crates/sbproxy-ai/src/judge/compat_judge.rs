//! Description-semantics judge for the MCP tool-versioning oracle.
//!
//! Implements [`sbproxy_extension::mcp::compat::Judge`] over the same
//! BYOK OpenAI-compatible provider surface the policy judge uses:
//! POST a chat-completions body to a configured endpoint, bearer
//! token from an environment variable, per-call timeout, and a
//! process-wide token budget so a churning upstream catalogue cannot
//! drain spend. Calls are counted on the existing
//! `sbproxy_judge_calls_total` family, so judge model spend is
//! visible alongside the policy judge's.
//!
//! The provider is asked to return `{"score": <number in [0,1]>}`,
//! either as a direct JSON body (a thin facilitator endpoint) or as
//! the content of the first chat-completions choice (a frontier model
//! in JSON mode).

use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use super::budget::BudgetTracker;
use super::telemetry::{record_budget_exhausted, record_judge_call, VERDICT_ERROR};

/// Configuration for one description-semantics judge.
#[derive(Debug, Clone)]
pub struct CompatJudgeConfig {
    /// Upstream chat-completions endpoint to POST to.
    pub endpoint: url::Url,
    /// Name of the environment variable holding the bearer API key.
    pub api_key_env: String,
    /// Optional `model` field for OpenAI-compatible endpoints. A
    /// facilitator endpoint that pins its own model omits it.
    pub model: Option<String>,
    /// Per-call timeout in milliseconds.
    pub timeout_ms: u32,
    /// Total token-equivalent budget before calls hard-fail.
    pub budget_tokens: u64,
}

/// A model-backed [`sbproxy_extension::mcp::compat::Judge`].
pub struct CompatJudge {
    config: CompatJudgeConfig,
    http: reqwest::Client,
    budget: Arc<BudgetTracker>,
    provider_label: String,
}

impl CompatJudge {
    /// Build a judge from its config. The HTTP client carries the
    /// per-call timeout; the budget is process-lifetime.
    pub fn new(config: CompatJudgeConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(
                config.timeout_ms,
            )))
            .build()
            .unwrap_or_default();
        let provider_label = config.endpoint.host_str().unwrap_or("unknown").to_string();
        let budget = Arc::new(BudgetTracker::new(config.budget_tokens));
        Self {
            config,
            http,
            budget,
            provider_label,
        }
    }

    /// Extract a `[0,1]` score from a provider response body: a
    /// direct `{"score": x}` object, or the first chat-completions
    /// choice whose content parses (possibly with surrounding prose)
    /// to that object.
    fn parse_score(body: &Value) -> Option<f64> {
        if let Some(score) = body.get("score").and_then(Value::as_f64) {
            return Some(score);
        }
        let content = body
            .get("choices")?
            .get(0)?
            .get("message")?
            .get("content")?
            .as_str()?;
        let parsed: Value = serde_json::from_str(content).ok().or_else(|| {
            // Tolerate prose around the JSON object.
            let start = content.find('{')?;
            let end = content.rfind('}')?;
            serde_json::from_str(&content[start..=end]).ok()
        })?;
        parsed.get("score").and_then(Value::as_f64)
    }
}

#[async_trait::async_trait]
impl sbproxy_extension::mcp::compat::Judge for CompatJudge {
    async fn score(
        &self,
        rubric: &str,
        old_surface: &Value,
        new_surface: &Value,
    ) -> anyhow::Result<f64> {
        let started = Instant::now();
        if self.budget.charge(1).is_err() {
            record_budget_exhausted("");
            record_judge_call(&self.provider_label, VERDICT_ERROR, false, 0.0, 0.0);
            anyhow::bail!("compat judge budget exhausted");
        }

        let system = format!(
            "{rubric}\n\nReturn strictly a JSON object {{\"score\": <number in [0,1]>}} and nothing else."
        );
        let mut body = json!({
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json!({
                    "old": old_surface,
                    "new": new_surface,
                }).to_string()},
            ],
        });
        if let Some(model) = &self.config.model {
            body["model"] = Value::String(model.clone());
        }

        let api_key = std::env::var(&self.config.api_key_env).unwrap_or_default();
        let response = self
            .http
            .post(self.config.endpoint.as_str())
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {api_key}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                record_judge_call(
                    &self.provider_label,
                    VERDICT_ERROR,
                    false,
                    started.elapsed().as_secs_f64(),
                    0.0,
                );
                anyhow::anyhow!("compat judge transport error: {e}")
            })?;

        let status = response.status();
        if !status.is_success() {
            record_judge_call(
                &self.provider_label,
                VERDICT_ERROR,
                false,
                started.elapsed().as_secs_f64(),
                0.0,
            );
            anyhow::bail!("compat judge provider returned {status}");
        }
        let parsed: Value = response.json().await.map_err(|e| {
            record_judge_call(
                &self.provider_label,
                VERDICT_ERROR,
                false,
                started.elapsed().as_secs_f64(),
                0.0,
            );
            anyhow::anyhow!("compat judge response unreadable: {e}")
        })?;
        let score = Self::parse_score(&parsed).ok_or_else(|| {
            record_judge_call(
                &self.provider_label,
                VERDICT_ERROR,
                false,
                started.elapsed().as_secs_f64(),
                0.0,
            );
            anyhow::anyhow!("compat judge response carried no score")
        })?;
        record_judge_call(
            &self.provider_label,
            "score",
            false,
            started.elapsed().as_secs_f64(),
            0.0,
        );
        Ok(score.clamp(0.0, 1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direct_score_body() {
        let body = json!({"score": 0.83});
        assert_eq!(CompatJudge::parse_score(&body), Some(0.83));
    }

    #[test]
    fn parses_chat_completions_content() {
        let body = json!({
            "choices": [{"message": {"content": "{\"score\": 0.4}"}}]
        });
        assert_eq!(CompatJudge::parse_score(&body), Some(0.4));
    }

    #[test]
    fn parses_content_with_surrounding_prose() {
        let body = json!({
            "choices": [{"message": {"content": "Here you go: {\"score\": 0.9} hope that helps"}}]
        });
        assert_eq!(CompatJudge::parse_score(&body), Some(0.9));
    }

    #[test]
    fn missing_score_is_none() {
        let body = json!({"choices": [{"message": {"content": "no json here"}}]});
        assert_eq!(CompatJudge::parse_score(&body), None);
    }
}
