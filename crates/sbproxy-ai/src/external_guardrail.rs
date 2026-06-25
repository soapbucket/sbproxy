//! External guardrail provider adapters.
//!
//! sbproxy ships strong built-in guardrails, but LiteLLM users often configure
//! external guardrail services (Presidio, Lakera, Aporia, AWS Bedrock
//! Guardrails, or a custom HTTP API). This module adds a generic HTTP adapter
//! that calls an external guardrail endpoint and acts on its verdict, plus the
//! LiteLLM `mode` mapping (`pre_call` / `post_call` / `during_call` /
//! `logging_only`). The trait stays open source so closed-source provider
//! adapters can extend it.

use serde::{Deserialize, Serialize};

/// When an external guardrail runs, mapped from LiteLLM's `mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailMode {
    /// Inspect the request before it reaches the provider (input guardrail).
    PreCall,
    /// Inspect the response after the provider returns (output guardrail).
    PostCall,
    /// Inspect during streaming.
    DuringCall,
    /// Run the check but never block; record the verdict only.
    LoggingOnly,
}

impl GuardrailMode {
    /// Whether this mode runs on the inbound request.
    pub fn is_input(self) -> bool {
        matches!(self, GuardrailMode::PreCall | GuardrailMode::DuringCall)
    }

    /// Whether this mode runs on the outbound response.
    pub fn is_output(self) -> bool {
        matches!(self, GuardrailMode::PostCall | GuardrailMode::DuringCall)
    }

    /// Whether a block verdict actually blocks (false for `logging_only`).
    pub fn blocks(self) -> bool {
        !matches!(self, GuardrailMode::LoggingOnly)
    }
}

/// Config for one external guardrail, parsed from the action's
/// `external_guardrails` list.
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalGuardrailConfig {
    /// Operator-facing name (for logs and the block reason).
    pub name: String,
    /// HTTP endpoint to POST the content to for a verdict.
    pub url: String,
    /// When the guardrail runs.
    pub mode: GuardrailMode,
    /// Apply to every request/response (LiteLLM `default_on`).
    #[serde(default)]
    pub default_on: bool,
    /// On a transport/parse error, allow the request (fail open) rather than
    /// block it (fail closed). Defaults to fail closed.
    #[serde(default)]
    pub fail_open: bool,
    /// Per-call timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    2_000
}

/// The verdict an external guardrail returns for a piece of content.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GuardrailVerdict {
    /// Whether the content is allowed through.
    pub allowed: bool,
    /// Optional human-readable reason for a block.
    pub reason: Option<String>,
}

impl GuardrailVerdict {
    /// An allow verdict.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }
}

/// Parse a verdict from an external guardrail's JSON response.
///
/// Accepts several common shapes: an explicit `allowed` boolean, a `flagged`
/// boolean (negated), or a `blocked` boolean (negated). A response with none of
/// these is treated as allow, so a guardrail that only returns analysis detail
/// does not accidentally block. The reason is taken from `reason` or `message`.
pub fn parse_verdict(body: &serde_json::Value) -> GuardrailVerdict {
    let reason = body
        .get("reason")
        .or_else(|| body.get("message"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let allowed = if let Some(a) = body.get("allowed").and_then(|v| v.as_bool()) {
        a
    } else if let Some(f) = body.get("flagged").and_then(|v| v.as_bool()) {
        !f
    } else if let Some(b) = body.get("blocked").and_then(|v| v.as_bool()) {
        !b
    } else {
        true
    };

    GuardrailVerdict { allowed, reason }
}

/// Call an external guardrail endpoint with `content` and return its verdict.
///
/// POSTs `{"input": content}` as JSON. On any transport, status, or parse
/// failure the result depends on [`ExternalGuardrailConfig::fail_open`]: a
/// fail-open guardrail allows the content (with a reason), a fail-closed one
/// blocks it. This never panics or propagates an error.
pub async fn check_external_guardrail(
    cfg: &ExternalGuardrailConfig,
    content: &str,
) -> GuardrailVerdict {
    let on_error = |what: &str| -> GuardrailVerdict {
        if cfg.fail_open {
            GuardrailVerdict {
                allowed: true,
                reason: Some(format!(
                    "external guardrail '{}' unavailable ({what}); fail-open",
                    cfg.name
                )),
            }
        } else {
            GuardrailVerdict {
                allowed: false,
                reason: Some(format!(
                    "external guardrail '{}' unavailable ({what}); fail-closed",
                    cfg.name
                )),
            }
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .build()
    {
        Ok(c) => c,
        Err(_) => return on_error("client build"),
    };
    let resp = match client
        .post(&cfg.url)
        .json(&serde_json::json!({ "input": content }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return on_error("request"),
    };
    if !resp.status().is_success() {
        return on_error("non-2xx");
    }
    match resp.json::<serde_json::Value>().await {
        Ok(body) => parse_verdict(&body),
        Err(_) => on_error("decode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_phase_and_block_mapping() {
        assert!(GuardrailMode::PreCall.is_input());
        assert!(!GuardrailMode::PreCall.is_output());
        assert!(GuardrailMode::PostCall.is_output());
        assert!(GuardrailMode::DuringCall.is_input() && GuardrailMode::DuringCall.is_output());
        assert!(GuardrailMode::PreCall.blocks());
        assert!(!GuardrailMode::LoggingOnly.blocks());
    }

    #[test]
    fn verdict_parses_common_response_shapes() {
        assert!(parse_verdict(&serde_json::json!({"allowed": true})).allowed);
        let blocked =
            parse_verdict(&serde_json::json!({"allowed": false, "reason": "pii detected"}));
        assert!(!blocked.allowed);
        assert_eq!(blocked.reason.as_deref(), Some("pii detected"));
        assert!(!parse_verdict(&serde_json::json!({"flagged": true})).allowed);
        assert!(parse_verdict(&serde_json::json!({"flagged": false})).allowed);
        assert!(!parse_verdict(&serde_json::json!({"blocked": true})).allowed);
        // No verdict field -> allow (analysis-only responses don't block).
        assert!(parse_verdict(&serde_json::json!({"detail": "x"})).allowed);
    }

    #[test]
    fn config_parses_with_defaults() {
        let cfg: ExternalGuardrailConfig = serde_json::from_str(
            r#"{"name":"my-presidio","url":"http://presidio:5002/analyze","mode":"pre_call"}"#,
        )
        .unwrap();
        assert_eq!(cfg.mode, GuardrailMode::PreCall);
        assert!(!cfg.default_on);
        assert!(!cfg.fail_open);
        assert_eq!(cfg.timeout_ms, 2_000);
    }

    #[tokio::test]
    async fn unreachable_endpoint_respects_fail_mode() {
        // Port 1 / loopback refuses the connection.
        let mut cfg: ExternalGuardrailConfig = serde_json::from_str(
            r#"{"name":"g","url":"http://127.0.0.1:1/","mode":"pre_call","fail_open":true,"timeout_ms":500}"#,
        )
        .unwrap();
        assert!(
            check_external_guardrail(&cfg, "hello").await.allowed,
            "fail-open allows"
        );
        cfg.fail_open = false;
        assert!(
            !check_external_guardrail(&cfg, "hello").await.allowed,
            "fail-closed blocks"
        );
    }
}
