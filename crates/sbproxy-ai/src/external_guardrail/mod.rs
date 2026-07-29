//! Bounded, typed external guardrail integrations.
//!
//! This module owns the common safety boundary shared by every external
//! guardrail: configuration validation, SSRF-safe outbound clients, bounded
//! response reads, fail-mode handling, and closed-cardinality telemetry.

#![allow(missing_docs)]

mod generic;

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sbproxy_httpkit::OutboundClientBuilder;
use serde::Deserialize;
use serde_json::Value;

use crate::ai_metrics::record_external_guardrail_verdict;

pub const MAX_GUARDRAIL_RESPONSE_BYTES: usize = 64 * 1024;

/// The point in an AI request lifecycle at which a guardrail runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardrailPhase {
    /// Before the request is sent upstream.
    Input,
    /// After the upstream response is received.
    Output,
}

impl GuardrailPhase {
    /// Stable metric and trace label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }
}

/// The minimum information an external guardrail evaluates.
#[derive(Debug, Clone, Copy)]
pub struct ExternalGuardrailRequest<'a> {
    /// Text to inspect. It is never included in logs or metrics.
    pub content: &'a str,
    /// Selected model, used by provider adapters that need it.
    pub model: &'a str,
    /// Whether this is request or response content.
    pub phase: GuardrailPhase,
}

/// The normalized result of an external guardrail call.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GuardrailVerdict {
    /// Whether content may continue through the pipeline.
    pub allowed: bool,
    /// A safe provider-supplied reason, if one was available.
    pub reason: Option<String>,
    /// Normalized provider categories.
    pub categories: Vec<String>,
    /// Normalized provider scores.
    pub scores: BTreeMap<String, f64>,
}

impl GuardrailVerdict {
    /// Construct an allow verdict.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            ..Self::default()
        }
    }
}

/// When an external guardrail runs, mapped from LiteLLM's `mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailMode {
    PreCall,
    PostCall,
    DuringCall,
    LoggingOnly,
}

impl GuardrailMode {
    pub fn is_input(self) -> bool {
        matches!(self, Self::PreCall | Self::DuringCall)
    }

    pub fn is_output(self) -> bool {
        matches!(self, Self::PostCall | Self::DuringCall)
    }

    pub fn blocks(self) -> bool {
        !matches!(self, Self::LoggingOnly)
    }
}

/// Provider contracts supported by the external guardrail configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailProvider {
    #[default]
    Generic,
    Presidio,
    Lakera,
    Aporia,
    AzureContentSafety,
    Bedrock,
    CrowdStrike,
    Mistral,
    Pangea,
    Patronus,
}

impl GuardrailProvider {
    /// Stable metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Presidio => "presidio",
            Self::Lakera => "lakera",
            Self::Aporia => "aporia",
            Self::AzureContentSafety => "azure_content_safety",
            Self::Bedrock => "bedrock",
            Self::CrowdStrike => "crowdstrike",
            Self::Mistral => "mistral",
            Self::Pangea => "pangea",
            Self::Patronus => "patronus",
        }
    }
}

/// Deserialized wire configuration. Provider-specific fields remain optional
/// here so legacy generic configurations stay valid; `compile` makes their
/// requirements explicit before a handler is published.
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalGuardrailConfig {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    pub mode: GuardrailMode,
    #[serde(default)]
    pub default_on: bool,
    #[serde(default)]
    pub fail_open: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub provider: GuardrailProvider,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_auth_header")]
    pub auth_header: Option<String>,
    #[serde(default = "default_auth_prefix")]
    pub auth_prefix: Option<String>,
    #[serde(default)]
    pub allow_private_url: bool,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub application_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub guardrail_id: Option<String>,
    #[serde(default)]
    pub guardrail_version: Option<String>,
    #[serde(default)]
    pub severity_threshold: Option<u8>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub score_threshold: Option<f64>,
    #[serde(default)]
    pub input_recipe: Option<String>,
    #[serde(default)]
    pub output_recipe: Option<String>,
    #[serde(default)]
    pub evaluator: Option<String>,
    #[serde(default)]
    pub criteria: Option<String>,
    #[serde(skip)]
    client: OnceLock<reqwest::Client>,
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

macro_rules! provider_config {
    ($($name:ident),+ $(,)?) => { $(
        #[derive(Debug, Clone)]
        pub struct $name { pub url: String }
    )+ };
}
provider_config!(
    GenericConfig,
    PresidioConfig,
    LakeraConfig,
    AporiaConfig,
    AzureConfig,
    BedrockConfig,
    CrowdStrikeConfig,
    MistralConfig,
    PangeaConfig,
    PatronusConfig
);

/// A provider contract whose required fields were verified at load time.
#[derive(Debug, Clone)]
pub enum CompiledGuardrailProvider {
    Generic(GenericConfig),
    Presidio(PresidioConfig),
    Lakera(LakeraConfig),
    Aporia(AporiaConfig),
    AzureContentSafety(AzureConfig),
    Bedrock(BedrockConfig),
    CrowdStrike(CrowdStrikeConfig),
    Mistral(MistralConfig),
    Pangea(PangeaConfig),
    Patronus(PatronusConfig),
}

impl ExternalGuardrailConfig {
    /// Validate the wire document and compile its provider contract.
    pub fn validate(&self) -> Result<CompiledGuardrailProvider> {
        if self.name.trim().is_empty() {
            bail!("name must not be empty");
        }
        if !(1..=30_000).contains(&self.timeout_ms) {
            bail!("timeout_ms must be between 1 and 30000");
        }
        if self.severity_threshold.is_some_and(|value| value > 7) {
            bail!("severity_threshold must be between 0 and 7");
        }
        if self
            .score_threshold
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            bail!("score_threshold must be finite and between 0 and 1");
        }
        for value in [
            self.url.as_deref(),
            self.api_key.as_deref(),
            self.project_id.as_deref(),
            self.application_id.as_deref(),
            self.region.as_deref(),
            self.guardrail_id.as_deref(),
            self.guardrail_version.as_deref(),
            self.model.as_deref(),
            self.input_recipe.as_deref(),
            self.output_recipe.as_deref(),
            self.evaluator.as_deref(),
            self.criteria.as_deref(),
        ] {
            if value.is_some_and(|item| item.contains("${")) {
                bail!("contains unresolved variable reference");
            }
        }
        let url = self.effective_url()?;
        if self.allow_private_url {
            validate_http_url(&url)?;
        } else {
            sbproxy_security::validate_url(&url).map_err(anyhow::Error::msg)?;
        }
        self.required_fields()?;
        Ok(match self.provider {
            GuardrailProvider::Generic => CompiledGuardrailProvider::Generic(GenericConfig { url }),
            GuardrailProvider::Presidio => {
                CompiledGuardrailProvider::Presidio(PresidioConfig { url })
            }
            GuardrailProvider::Lakera => CompiledGuardrailProvider::Lakera(LakeraConfig { url }),
            GuardrailProvider::Aporia => CompiledGuardrailProvider::Aporia(AporiaConfig { url }),
            GuardrailProvider::AzureContentSafety => {
                CompiledGuardrailProvider::AzureContentSafety(AzureConfig { url })
            }
            GuardrailProvider::Bedrock => CompiledGuardrailProvider::Bedrock(BedrockConfig { url }),
            GuardrailProvider::CrowdStrike => {
                CompiledGuardrailProvider::CrowdStrike(CrowdStrikeConfig { url })
            }
            GuardrailProvider::Mistral => CompiledGuardrailProvider::Mistral(MistralConfig { url }),
            GuardrailProvider::Pangea => CompiledGuardrailProvider::Pangea(PangeaConfig { url }),
            GuardrailProvider::Patronus => {
                CompiledGuardrailProvider::Patronus(PatronusConfig { url })
            }
        })
    }

    fn effective_url(&self) -> Result<String> {
        if let Some(url) = &self.url {
            return Ok(url.clone());
        }
        let default = match self.provider {
            GuardrailProvider::Lakera => Some("https://api.lakera.ai/v2/guard"),
            GuardrailProvider::Mistral => Some("https://api.mistral.ai/v1/moderations"),
            GuardrailProvider::Pangea => Some("https://api.pangea.cloud/v1/text/guard"),
            _ => None,
        };
        default
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("missing url"))
    }

    fn required_fields(&self) -> Result<()> {
        let required = |field: &'static str, value: Option<&String>| -> Result<()> {
            if value.is_none_or(|item| item.trim().is_empty()) {
                bail!("missing {field}");
            }
            Ok(())
        };
        match self.provider {
            GuardrailProvider::Generic | GuardrailProvider::Presidio => Ok(()),
            GuardrailProvider::Lakera
            | GuardrailProvider::AzureContentSafety
            | GuardrailProvider::CrowdStrike
            | GuardrailProvider::Mistral
            | GuardrailProvider::Pangea
            | GuardrailProvider::Patronus => required("api_key", self.api_key.as_ref()),
            GuardrailProvider::Aporia => {
                required("api_key", self.api_key.as_ref())?;
                required("project_id", self.project_id.as_ref())
            }
            GuardrailProvider::Bedrock => {
                required("guardrail_id", self.guardrail_id.as_ref())?;
                required("guardrail_version", self.guardrail_version.as_ref())
            }
        }
    }

    /// Return the credential field so the AI configuration resolver can
    /// replace a `secret://` reference without knowing provider internals.
    pub fn credential_reference_mut(&mut self) -> Option<&mut String> {
        self.api_key.as_mut()
    }

    /// Build and cache the bounded client for this configuration. Public
    /// endpoints are resolved and pinned before the client is built.
    pub fn client(&self) -> Result<&reqwest::Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let url = self.effective_url()?;
        let builder = OutboundClientBuilder::new().no_redirects().into_inner();
        let builder = if self.allow_private_url {
            validate_http_url(&url)?;
            builder
        } else {
            let resolved =
                sbproxy_security::validate_url_resolved(&url, &[]).map_err(anyhow::Error::msg)?;
            builder.resolve_to_addrs(&resolved.host, &resolved.addrs)
        };
        let client = builder
            .build()
            .context("could not build external guardrail client")?;
        let _ = self.client.set(client);
        Ok(self
            .client
            .get()
            .expect("external guardrail client was inserted"))
    }
}

fn validate_http_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value).context("invalid URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("URL must be absolute http or https");
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum GuardrailCallError {
    #[error("request failed")]
    Request,
    #[error("guardrail returned non-success status")]
    Status,
    #[error("guardrail response exceeded the 64 KiB limit")]
    ResponseTooLarge,
    #[error("guardrail returned an invalid verdict")]
    InvalidVerdict,
    #[error("provider contract is not connected")]
    UnsupportedProvider,
}

/// Call an external guardrail. A transport or parse error is mapped through
/// the configured fail mode exactly once here.
pub async fn check_external_guardrail(
    config: &ExternalGuardrailConfig,
    request: ExternalGuardrailRequest<'_>,
) -> GuardrailVerdict {
    let started = std::time::Instant::now();
    let result = dispatch(config, request).await;
    let (verdict, outcome) = match result {
        Ok(verdict) if verdict.allowed => (verdict, "allow"),
        Ok(verdict) => (verdict, "block"),
        Err(_) if config.fail_open => (
            GuardrailVerdict {
                allowed: true,
                reason: Some("external guardrail unavailable; fail-open".to_string()),
                ..GuardrailVerdict::default()
            },
            "fail_open",
        ),
        Err(_) => (
            GuardrailVerdict {
                allowed: false,
                reason: Some("external guardrail unavailable; fail-closed".to_string()),
                ..GuardrailVerdict::default()
            },
            "fail_closed",
        ),
    };
    record_external_guardrail_verdict(config.provider.as_str(), request.phase.as_str(), outcome);
    tracing::debug!(guardrail = %config.name, provider = config.provider.as_str(), phase = request.phase.as_str(), latency_ms = started.elapsed().as_millis() as u64, categories = ?verdict.categories, outcome, "external guardrail evaluated");
    verdict
}

async fn dispatch(
    config: &ExternalGuardrailConfig,
    request: ExternalGuardrailRequest<'_>,
) -> std::result::Result<GuardrailVerdict, GuardrailCallError> {
    config.validate().map_err(|_| GuardrailCallError::Request)?;
    let url = config
        .effective_url()
        .map_err(|_| GuardrailCallError::Request)?;
    let body = match config.provider {
        GuardrailProvider::Generic | GuardrailProvider::Presidio => {
            generic::request_body(config, request)
        }
        _ => return Err(GuardrailCallError::UnsupportedProvider),
    };
    let mut call = config
        .client()
        .map_err(|_| GuardrailCallError::Request)?
        .post(url)
        .timeout(Duration::from_millis(config.timeout_ms))
        .json(&body);
    if let Some(key) = &config.api_key {
        let header = config.auth_header.as_deref().unwrap_or("Authorization");
        let value = match config.auth_prefix.as_deref() {
            Some(prefix) if !prefix.is_empty() => format!("{prefix} {key}"),
            _ => key.clone(),
        };
        call = call.header(header, value);
    }
    let mut response = call.send().await.map_err(|_| GuardrailCallError::Request)?;
    if !response.status().is_success() {
        return Err(GuardrailCallError::Status);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GuardrailCallError::Request)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_GUARDRAIL_RESPONSE_BYTES {
            return Err(GuardrailCallError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    let body =
        serde_json::from_slice::<Value>(&bytes).map_err(|_| GuardrailCallError::InvalidVerdict)?;
    generic::parse(config.provider, &body)
}

pub fn verdict_blocks(config: &ExternalGuardrailConfig, verdict: &GuardrailVerdict) -> bool {
    config.mode.blocks() && !verdict.allowed
}

async fn run_external_guardrails(
    configs: &[ExternalGuardrailConfig],
    content: &str,
    model: &str,
    phase: GuardrailPhase,
) -> Option<(String, String)> {
    for config in configs {
        let applies = matches!(phase, GuardrailPhase::Input) && config.mode.is_input()
            || matches!(phase, GuardrailPhase::Output) && config.mode.is_output();
        if !config.default_on || !applies {
            continue;
        }
        let verdict = check_external_guardrail(
            config,
            ExternalGuardrailRequest {
                content,
                model,
                phase,
            },
        )
        .await;
        if verdict_blocks(config, &verdict) {
            return Some((
                config.name.clone(),
                verdict
                    .reason
                    .unwrap_or_else(|| format!("blocked by external guardrail '{}'", config.name)),
            ));
        }
    }
    None
}

pub async fn run_input_external_guardrails(
    configs: &[ExternalGuardrailConfig],
    content: &str,
) -> Option<(String, String)> {
    run_external_guardrails(configs, content, "", GuardrailPhase::Input).await
}
pub async fn run_output_external_guardrails(
    configs: &[ExternalGuardrailConfig],
    content: &str,
) -> Option<(String, String)> {
    run_external_guardrails(configs, content, "", GuardrailPhase::Output).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_generic_config_defaults_provider() {
        let cfg: ExternalGuardrailConfig = serde_json::from_str(r#"{"name":"custom","url":"https://guard.example.test/check","mode":"pre_call","default_on":true,"api_key":"secret://guard-key"}"#).unwrap();
        assert_eq!(cfg.provider, GuardrailProvider::Generic);
    }
    #[test]
    fn timeout_must_be_between_one_and_thirty_seconds() {
        for timeout_ms in [0, 30_001] {
            let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({"name":"custom","url":"https://8.8.8.8/check","mode":"pre_call","timeout_ms":timeout_ms})).unwrap();
            assert!(cfg.validate().is_err());
        }
    }
    #[test]
    fn private_url_requires_explicit_opt_in() {
        let cfg: ExternalGuardrailConfig = serde_json::from_value(
            serde_json::json!({"name":"custom","url":"http://127.0.0.1/check","mode":"pre_call"}),
        )
        .unwrap();
        assert!(cfg.validate().is_err());
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({"name":"custom","url":"http://127.0.0.1/check","mode":"pre_call","allow_private_url":true})).unwrap();
        assert!(cfg.validate().is_ok());
    }
    #[test]
    fn provider_required_fields_fail_during_load() {
        let cfg: ExternalGuardrailConfig = serde_json::from_value(
            serde_json::json!({"name":"lakera","mode":"pre_call","provider":"lakera"}),
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn generic_response_without_verdict_is_an_error() {
        assert!(generic::parse(
            GuardrailProvider::Generic,
            &serde_json::json!({"analysis":{"risk":"unknown"}})
        )
        .is_err());
    }
    #[test]
    fn logging_only_records_but_never_blocks() {
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({"name":"custom","url":"https://8.8.8.8/check","mode":"logging_only"})).unwrap();
        assert!(!verdict_blocks(
            &cfg,
            &GuardrailVerdict {
                allowed: false,
                ..GuardrailVerdict::default()
            }
        ));
    }
    async fn fixture_server(body: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", body.len(), body);
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}/check")
    }
    #[tokio::test]
    async fn oversized_response_obeys_fail_mode() {
        let url = fixture_server(format!(
            r#"{{"allowed":true,"detail":"{}"}}"#,
            "x".repeat(MAX_GUARDRAIL_RESPONSE_BYTES)
        ))
        .await;
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({"name":"custom","url":url,"mode":"pre_call","allow_private_url":true})).unwrap();
        let verdict = check_external_guardrail(
            &cfg,
            ExternalGuardrailRequest {
                content: "prompt",
                model: "test",
                phase: GuardrailPhase::Input,
            },
        )
        .await;
        assert!(!verdict.allowed);
    }
    #[tokio::test]
    async fn malformed_response_obeys_fail_mode() {
        let url = fixture_server(r#"{"analysis":{"risk":"unknown"}}"#.to_string()).await;
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({"name":"custom","url":url,"mode":"pre_call","allow_private_url":true,"fail_open":true})).unwrap();
        assert!(
            check_external_guardrail(
                &cfg,
                ExternalGuardrailRequest {
                    content: "prompt",
                    model: "test",
                    phase: GuardrailPhase::Input
                }
            )
            .await
            .allowed
        );
        let url = fixture_server(r#"{"analysis":{"risk":"unknown"}}"#.to_string()).await;
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({"name":"custom","url":url,"mode":"pre_call","allow_private_url":true})).unwrap();
        assert!(
            !check_external_guardrail(
                &cfg,
                ExternalGuardrailRequest {
                    content: "prompt",
                    model: "test",
                    phase: GuardrailPhase::Input
                }
            )
            .await
            .allowed
        );
    }
}
