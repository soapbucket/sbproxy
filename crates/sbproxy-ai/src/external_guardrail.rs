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

/// Which external guardrail provider an [`ExternalGuardrailConfig`] targets.
/// Selects the request-body shape and the response parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailProvider {
    /// A custom HTTP guardrail: POST `{"input": content}` and parse a common
    /// `allowed` / `flagged` / `blocked` verdict (default).
    #[default]
    Generic,
    /// Microsoft Presidio `/analyze`: POST `{"text", "language"}`; a
    /// non-empty findings array means content was flagged.
    Presidio,
    /// Lakera Guard: POST `{"input"}` with a bearer key; common verdict.
    Lakera,
    /// Aporia: POST `{"input"}` with a key; common verdict.
    Aporia,
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
    /// External provider preset selecting the request/response shape.
    #[serde(default)]
    pub provider: GuardrailProvider,
    /// Optional API key sent on the auth header for hosted providers.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Header the API key is sent on. Defaults to `Authorization`.
    #[serde(default = "default_auth_header")]
    pub auth_header: Option<String>,
    /// Prefix prepended to the API key value (a space separates it from the
    /// key). Defaults to `Bearer`; set to an empty string to send the bare
    /// key.
    #[serde(default = "default_auth_prefix")]
    pub auth_prefix: Option<String>,
}

fn default_timeout_ms() -> u64 {
    2_000
}

fn default_auth_header() -> Option<String> {
    Some("Authorization".to_string())
}

fn default_auth_prefix() -> Option<String> {
    Some("Bearer".to_string())
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
/// POSTs the provider-shaped request body (see [`provider_request_body`]),
/// attaching the API key on the configured auth header when set. On any
/// transport, status, or parse failure the result depends on
/// [`ExternalGuardrailConfig::fail_open`]: a
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
    let mut req = client
        .post(&cfg.url)
        .json(&provider_request_body(cfg.provider, content));
    if let Some(key) = &cfg.api_key {
        let header = cfg.auth_header.as_deref().unwrap_or("Authorization");
        let value = match cfg.auth_prefix.as_deref() {
            Some(p) if !p.is_empty() => format!("{p} {key}"),
            _ => key.clone(),
        };
        req = req.header(header, value);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(_) => return on_error("request"),
    };
    if !resp.status().is_success() {
        return on_error("non-2xx");
    }
    match resp.json::<serde_json::Value>().await {
        Ok(body) => parse_provider_verdict(cfg.provider, &body),
        Err(_) => on_error("decode"),
    }
}

/// Build the request body for `content` in the shape `provider` expects.
pub fn provider_request_body(provider: GuardrailProvider, content: &str) -> serde_json::Value {
    match provider {
        GuardrailProvider::Presidio => serde_json::json!({ "text": content, "language": "en" }),
        GuardrailProvider::Generic | GuardrailProvider::Lakera | GuardrailProvider::Aporia => {
            serde_json::json!({ "input": content })
        }
    }
}

/// Parse a verdict from `provider`'s response body.
///
/// Presidio returns an array of recognized entities, so a non-empty array is
/// a flag. The other providers return a common object shape handled by
/// [`parse_verdict`].
pub fn parse_provider_verdict(
    provider: GuardrailProvider,
    body: &serde_json::Value,
) -> GuardrailVerdict {
    match provider {
        GuardrailProvider::Presidio => {
            let entities = body.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
            if entities.is_empty() {
                return GuardrailVerdict::allow();
            }
            let kinds: Vec<String> = entities
                .iter()
                .filter_map(|e| e.get("entity_type").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .collect();
            let reason = if kinds.is_empty() {
                format!("presidio flagged {} entities", entities.len())
            } else {
                format!("presidio flagged: {}", kinds.join(", "))
            };
            GuardrailVerdict {
                allowed: false,
                reason: Some(reason),
            }
        }
        GuardrailProvider::Generic | GuardrailProvider::Lakera | GuardrailProvider::Aporia => {
            parse_verdict(body)
        }
    }
}

/// Whether a guardrail's verdict should block the request: only when the
/// mode actually blocks (not `logging_only`) and the content was disallowed.
pub fn verdict_blocks(cfg: &ExternalGuardrailConfig, verdict: &GuardrailVerdict) -> bool {
    cfg.mode.blocks() && !verdict.allowed
}

/// Shared driver for the input/output external-guardrail runners. Evaluates
/// the `default_on` guardrails whose mode matches the requested phase
/// (`on_input`), returning the `(name, reason)` of the first that blocks.
/// `logging_only` records a verdict but never blocks; transport or parse
/// errors honor each guardrail's `fail_open` flag in
/// [`check_external_guardrail`].
async fn run_external_guardrails(
    cfgs: &[ExternalGuardrailConfig],
    content: &str,
    on_input: bool,
) -> Option<(String, String)> {
    for cfg in cfgs {
        let applies = if on_input {
            cfg.mode.is_input()
        } else {
            cfg.mode.is_output()
        };
        if !cfg.default_on || !applies {
            continue;
        }
        let verdict = check_external_guardrail(cfg, content).await;
        if verdict_blocks(cfg, &verdict) {
            let reason = verdict
                .reason
                .unwrap_or_else(|| format!("blocked by external guardrail '{}'", cfg.name));
            return Some((cfg.name.clone(), reason));
        }
    }
    None
}

/// Run the input-side external guardrails (`pre_call` / `during_call`) over
/// the request `content`, returning the first block.
pub async fn run_input_external_guardrails(
    cfgs: &[ExternalGuardrailConfig],
    content: &str,
) -> Option<(String, String)> {
    run_external_guardrails(cfgs, content, true).await
}

/// Run the output-side external guardrails (`post_call` / `during_call`)
/// over the response `content`, returning the first block.
pub async fn run_output_external_guardrails(
    cfgs: &[ExternalGuardrailConfig],
    content: &str,
) -> Option<(String, String)> {
    run_external_guardrails(cfgs, content, false).await
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

    #[test]
    fn presidio_uses_text_language_request_and_array_verdict() {
        // Presidio's /analyze takes {text, language} and returns an array of
        // findings; a non-empty array means PII was detected -> block.
        let body = provider_request_body(GuardrailProvider::Presidio, "my ssn is 123");
        assert_eq!(
            body.get("text").and_then(|v| v.as_str()),
            Some("my ssn is 123")
        );
        assert_eq!(body.get("language").and_then(|v| v.as_str()), Some("en"));
        let found = parse_provider_verdict(
            GuardrailProvider::Presidio,
            &serde_json::json!([{"entity_type":"US_SSN"}]),
        );
        assert!(!found.allowed);
        assert!(
            parse_provider_verdict(GuardrailProvider::Presidio, &serde_json::json!([])).allowed
        );
    }

    #[test]
    fn generic_and_flagged_providers_use_input_request_and_common_verdict() {
        // Generic / Lakera / Aporia POST {input} and return a common verdict
        // shape (allowed / flagged / blocked).
        let body = provider_request_body(GuardrailProvider::Generic, "hi");
        assert_eq!(body.get("input").and_then(|v| v.as_str()), Some("hi"));
        assert!(
            !parse_provider_verdict(
                GuardrailProvider::Lakera,
                &serde_json::json!({"flagged": true})
            )
            .allowed
        );
        assert!(
            parse_provider_verdict(
                GuardrailProvider::Aporia,
                &serde_json::json!({"allowed": true})
            )
            .allowed
        );
    }

    #[test]
    fn verdict_blocks_only_for_blocking_modes_and_disallowed() {
        let pre = serde_json::from_str::<ExternalGuardrailConfig>(
            r#"{"name":"g","url":"http://x","mode":"pre_call"}"#,
        )
        .unwrap();
        let logging = serde_json::from_str::<ExternalGuardrailConfig>(
            r#"{"name":"g","url":"http://x","mode":"logging_only"}"#,
        )
        .unwrap();
        let blocked = GuardrailVerdict {
            allowed: false,
            reason: Some("pii".into()),
        };
        // pre_call + disallowed -> blocks; pre_call + allowed -> does not.
        assert!(verdict_blocks(&pre, &blocked));
        assert!(!verdict_blocks(&pre, &GuardrailVerdict::allow()));
        // logging_only never blocks even on a disallowed verdict.
        assert!(!verdict_blocks(&logging, &blocked));
    }

    #[test]
    fn config_parses_provider_and_auth_defaults() {
        let cfg: ExternalGuardrailConfig = serde_json::from_str(
            r#"{"name":"lakera","url":"http://lakera/guard","mode":"pre_call","provider":"lakera","api_key":"sk-test"}"#,
        )
        .unwrap();
        assert_eq!(cfg.provider, GuardrailProvider::Lakera);
        assert_eq!(cfg.api_key.as_deref(), Some("sk-test"));
        // Auth header/prefix default to bearer.
        assert_eq!(cfg.auth_header.as_deref(), Some("Authorization"));
        assert_eq!(cfg.auth_prefix.as_deref(), Some("Bearer"));
        // Provider defaults to generic when unset.
        let bare: ExternalGuardrailConfig =
            serde_json::from_str(r#"{"name":"g","url":"http://x","mode":"pre_call"}"#).unwrap();
        assert_eq!(bare.provider, GuardrailProvider::Generic);
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

    #[tokio::test]
    async fn run_output_skips_input_only_guardrails() {
        // A pre_call (input-only) guardrail is never evaluated on the output
        // path: it is skipped before any HTTP call, so the result is None even
        // though the URL is unreachable and fail-closed.
        let cfg: ExternalGuardrailConfig = serde_json::from_str(
            r#"{"name":"in","url":"http://127.0.0.1:1/","mode":"pre_call","default_on":true,"timeout_ms":300}"#,
        )
        .unwrap();
        assert!(run_output_external_guardrails(&[cfg], "x").await.is_none());
    }

    #[tokio::test]
    async fn run_output_evaluates_post_call_guardrails() {
        // post_call applies to the output path; the unreachable URL plus
        // fail-closed produces a block.
        let cfg: ExternalGuardrailConfig = serde_json::from_str(
            r#"{"name":"out","url":"http://127.0.0.1:1/","mode":"post_call","default_on":true,"timeout_ms":300}"#,
        )
        .unwrap();
        assert!(
            run_output_external_guardrails(&[cfg], "x").await.is_some(),
            "a fail-closed post_call guardrail must block"
        );
    }
}
