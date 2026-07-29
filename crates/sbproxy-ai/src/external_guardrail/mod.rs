//! Bounded, typed external guardrail integrations.
//!
//! This module owns the common safety boundary shared by every external
//! guardrail: configuration validation, SSRF-safe outbound clients, bounded
//! response reads, fail-mode handling, and closed-cardinality telemetry.

#![allow(missing_docs)]

mod aporia;
mod azure;
mod bedrock;
mod crowdstrike;
mod generic;
mod lakera;
mod mistral;
mod pangea;
mod patronus;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderName, HeaderValue};
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
    /// An operator-safe normalized reason. Raw provider text is never exposed.
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
        matches!(self, Self::PreCall | Self::DuringCall | Self::LoggingOnly)
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

#[derive(Clone)]
struct GuardrailAuth {
    header: HeaderName,
    value: HeaderValue,
}

impl std::fmt::Debug for GuardrailAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuardrailAuth")
            .field("header", &self.header)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct GenericConfig {
    pub url: String,
    auth: Option<GuardrailAuth>,
}

#[derive(Debug, Clone)]
pub struct PresidioConfig {
    pub url: String,
    pub language: String,
    auth: Option<GuardrailAuth>,
}

#[derive(Debug, Clone)]
pub struct LakeraConfig {
    pub url: String,
    pub project_id: Option<String>,
    auth: GuardrailAuth,
}

#[derive(Debug, Clone)]
pub struct AporiaConfig {
    pub url: String,
    pub project_id: String,
    auth: GuardrailAuth,
}

#[derive(Debug, Clone)]
pub struct AzureConfig {
    pub url: String,
    pub severity_threshold: u8,
    auth: GuardrailAuth,
}

#[derive(Debug, Clone)]
pub struct BedrockConfig {
    pub url: String,
    pub region: Option<String>,
    pub guardrail_id: String,
    pub guardrail_version: String,
    auth: GuardrailAuth,
}

#[derive(Debug, Clone)]
pub struct CrowdStrikeConfig {
    pub url: String,
    pub application_id: Option<String>,
    auth: GuardrailAuth,
}

#[derive(Debug, Clone)]
pub struct MistralConfig {
    pub url: String,
    pub model: String,
    pub score_threshold: Option<f64>,
    auth: GuardrailAuth,
}

#[derive(Debug, Clone)]
pub struct PangeaConfig {
    pub url: String,
    pub input_recipe: String,
    pub output_recipe: String,
    auth: GuardrailAuth,
}

#[derive(Debug, Clone)]
pub struct PatronusConfig {
    pub url: String,
    pub evaluator: String,
    pub criteria: Option<String>,
    auth: GuardrailAuth,
}

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

impl CompiledGuardrailProvider {
    /// Return the provider selected by this validated contract.
    pub fn provider(&self) -> GuardrailProvider {
        match self {
            Self::Generic(_) => GuardrailProvider::Generic,
            Self::Presidio(_) => GuardrailProvider::Presidio,
            Self::Lakera(_) => GuardrailProvider::Lakera,
            Self::Aporia(_) => GuardrailProvider::Aporia,
            Self::AzureContentSafety(_) => GuardrailProvider::AzureContentSafety,
            Self::Bedrock(_) => GuardrailProvider::Bedrock,
            Self::CrowdStrike(_) => GuardrailProvider::CrowdStrike,
            Self::Mistral(_) => GuardrailProvider::Mistral,
            Self::Pangea(_) => GuardrailProvider::Pangea,
            Self::Patronus(_) => GuardrailProvider::Patronus,
        }
    }

    fn url(&self) -> &str {
        match self {
            Self::Generic(config) => &config.url,
            Self::Presidio(config) => &config.url,
            Self::Lakera(config) => &config.url,
            Self::Aporia(config) => &config.url,
            Self::AzureContentSafety(config) => &config.url,
            Self::Bedrock(config) => &config.url,
            Self::CrowdStrike(config) => &config.url,
            Self::Mistral(config) => &config.url,
            Self::Pangea(config) => &config.url,
            Self::Patronus(config) => &config.url,
        }
    }

    fn auth(&self) -> Option<&GuardrailAuth> {
        match self {
            Self::Generic(config) => config.auth.as_ref(),
            Self::Presidio(config) => config.auth.as_ref(),
            Self::Lakera(config) => Some(&config.auth),
            Self::Aporia(config) => Some(&config.auth),
            Self::AzureContentSafety(config) => Some(&config.auth),
            Self::Bedrock(config) => Some(&config.auth),
            Self::CrowdStrike(config) => Some(&config.auth),
            Self::Mistral(config) => Some(&config.auth),
            Self::Pangea(config) => Some(&config.auth),
            Self::Patronus(config) => Some(&config.auth),
        }
    }
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
            Some(self.name.as_str()),
            self.url.as_deref(),
            self.api_key.as_deref(),
            self.auth_header.as_deref(),
            self.auth_prefix.as_deref(),
            self.language.as_deref(),
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
        self.validate_configured_auth()?;

        let compiled = match self.provider {
            GuardrailProvider::Generic => CompiledGuardrailProvider::Generic(GenericConfig {
                url: self.required_url()?,
                auth: self.configured_auth()?,
            }),
            GuardrailProvider::Presidio => CompiledGuardrailProvider::Presidio(PresidioConfig {
                url: self.required_url()?,
                language: self.language.clone().unwrap_or_else(|| "en".to_string()),
                auth: self.configured_auth()?,
            }),
            GuardrailProvider::Lakera => CompiledGuardrailProvider::Lakera(LakeraConfig {
                url: self
                    .url
                    .clone()
                    .unwrap_or_else(|| "https://api.lakera.ai/v2/guard".to_string()),
                project_id: self.project_id.clone(),
                auth: self.required_provider_auth("Authorization", "Bearer")?,
            }),
            GuardrailProvider::Aporia => {
                let project_id = self.required_string("project_id", self.project_id.as_ref())?;
                CompiledGuardrailProvider::Aporia(AporiaConfig {
                    url: self.url.clone().unwrap_or_else(|| {
                        format!("https://gr-prd.aporia.com/{project_id}/validate")
                    }),
                    project_id,
                    auth: self.required_provider_auth("X-APORIA-API-KEY", "")?,
                })
            }
            GuardrailProvider::AzureContentSafety => {
                CompiledGuardrailProvider::AzureContentSafety(AzureConfig {
                    url: azure_endpoint(&self.required_url()?)?,
                    severity_threshold: self.severity_threshold.unwrap_or(4),
                    auth: self.required_provider_auth("Ocp-Apim-Subscription-Key", "")?,
                })
            }
            GuardrailProvider::Bedrock => {
                let region = self.region.clone();
                let base_url = match (&self.url, &region) {
                    (Some(url), _) => url.clone(),
                    (None, Some(region)) if !region.trim().is_empty() => {
                        format!("https://bedrock-runtime.{region}.amazonaws.com")
                    }
                    (None, _) => bail!("missing region"),
                };
                let guardrail_id =
                    self.required_string("guardrail_id", self.guardrail_id.as_ref())?;
                let guardrail_version =
                    self.required_string("guardrail_version", self.guardrail_version.as_ref())?;
                CompiledGuardrailProvider::Bedrock(BedrockConfig {
                    url: bedrock_endpoint(&base_url, &guardrail_id, &guardrail_version)?,
                    region,
                    guardrail_id,
                    guardrail_version,
                    auth: self.required_provider_auth("Authorization", "Bearer")?,
                })
            }
            GuardrailProvider::CrowdStrike => {
                CompiledGuardrailProvider::CrowdStrike(CrowdStrikeConfig {
                    url: self.required_url()?,
                    application_id: self.application_id.clone(),
                    auth: self.required_provider_auth("Authorization", "Bearer")?,
                })
            }
            GuardrailProvider::Mistral => CompiledGuardrailProvider::Mistral(MistralConfig {
                url: self
                    .url
                    .clone()
                    .unwrap_or_else(|| "https://api.mistral.ai/v1/moderations".to_string()),
                model: self
                    .model
                    .clone()
                    .unwrap_or_else(|| "mistral-moderation-2603".to_string()),
                score_threshold: self.score_threshold,
                auth: self.required_provider_auth("Authorization", "Bearer")?,
            }),
            GuardrailProvider::Pangea => CompiledGuardrailProvider::Pangea(PangeaConfig {
                url: self.url.clone().unwrap_or_else(|| {
                    "https://ai-guard.aws.us.pangea.cloud/v1/text/guard".to_string()
                }),
                input_recipe: self
                    .input_recipe
                    .clone()
                    .unwrap_or_else(|| "pangea_prompt_guard".to_string()),
                output_recipe: self
                    .output_recipe
                    .clone()
                    .unwrap_or_else(|| "pangea_llm_response_guard".to_string()),
                auth: self.required_provider_auth("Authorization", "Bearer")?,
            }),
            GuardrailProvider::Patronus => CompiledGuardrailProvider::Patronus(PatronusConfig {
                url: self
                    .url
                    .clone()
                    .unwrap_or_else(|| "https://api.patronus.ai/v1/evaluate".to_string()),
                evaluator: self
                    .evaluator
                    .clone()
                    .unwrap_or_else(|| "prompt-injection".to_string()),
                criteria: self.criteria.clone(),
                auth: self.required_provider_auth("X-API-KEY", "")?,
            }),
        };
        self.validate_endpoint(compiled.url())?;
        Ok(compiled)
    }

    fn required_url(&self) -> Result<String> {
        self.required_string("url", self.url.as_ref())
    }

    fn required_string(&self, field: &'static str, value: Option<&String>) -> Result<String> {
        value
            .filter(|item| !item.trim().is_empty())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing {field}"))
    }

    fn validate_endpoint(&self, url: &str) -> Result<()> {
        if self.allow_private_url {
            validate_http_url(url)
        } else {
            sbproxy_security::validate_url(url).map_err(anyhow::Error::msg)
        }
    }

    fn validate_configured_auth(&self) -> Result<()> {
        let header = self.auth_header.as_deref().unwrap_or("Authorization");
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid auth_header"))?;
        if let Some(key) = &self.api_key {
            let prefix = self.auth_prefix.as_deref().unwrap_or("");
            build_auth(header, prefix, key)?;
        }
        Ok(())
    }

    fn configured_auth(&self) -> Result<Option<GuardrailAuth>> {
        self.api_key
            .as_ref()
            .map(|key| {
                build_auth(
                    self.auth_header.as_deref().unwrap_or("Authorization"),
                    self.auth_prefix.as_deref().unwrap_or(""),
                    key,
                )
            })
            .transpose()
    }

    fn required_provider_auth(&self, header: &str, prefix: &str) -> Result<GuardrailAuth> {
        let key = self.required_string("api_key", self.api_key.as_ref())?;
        build_auth(header, prefix, &key)
    }

    /// Return the credential field so the AI configuration resolver can
    /// replace a `secret://` reference without knowing provider internals.
    pub fn credential_reference_mut(&mut self) -> Option<&mut String> {
        self.api_key.as_mut()
    }

    /// Build and cache the bounded client for this configuration. Public
    /// endpoints are resolved and pinned before the client is built.
    pub fn client(&self) -> Result<&reqwest::Client> {
        let compiled = self.validate()?;
        self.client_for(compiled.url())
    }

    fn client_for(&self, url: &str) -> Result<&reqwest::Client> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let builder = OutboundClientBuilder::new().no_redirects().into_inner();
        let builder = if self.allow_private_url {
            validate_http_url(url)?;
            builder
        } else {
            let resolved =
                sbproxy_security::validate_url_resolved(url, &[]).map_err(anyhow::Error::msg)?;
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

fn build_auth(header: &str, prefix: &str, key: &str) -> Result<GuardrailAuth> {
    let header = HeaderName::from_bytes(header.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid auth_header"))?;
    let raw_value = if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix} {key}")
    };
    let mut value = HeaderValue::from_str(&raw_value)
        .map_err(|_| anyhow::anyhow!("invalid authentication value"))?;
    value.set_sensitive(true);
    Ok(GuardrailAuth { header, value })
}

fn validate_http_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value).context("invalid URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("URL must be absolute http or https");
    }
    Ok(())
}

fn azure_endpoint(base: &str) -> Result<String> {
    let mut url = url::Url::parse(base).context("invalid Azure Content Safety URL")?;
    url.set_query(Some("api-version=2024-09-01"));
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Azure Content Safety URL cannot be a base"))?;
    segments.pop_if_empty();
    segments.extend(["contentsafety", "text:analyze"]);
    drop(segments);
    Ok(url.into())
}

fn bedrock_endpoint(base: &str, guardrail_id: &str, guardrail_version: &str) -> Result<String> {
    let mut url = url::Url::parse(base).context("invalid Bedrock URL")?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Bedrock URL cannot be a base"))?;
    segments.pop_if_empty();
    segments.extend([
        "guardrail",
        guardrail_id,
        "version",
        guardrail_version,
        "apply",
    ]);
    drop(segments);
    Ok(url.into())
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
    let compiled = config.validate().map_err(|_| GuardrailCallError::Request)?;
    let body = match &compiled {
        CompiledGuardrailProvider::Generic(provider) => generic::generic_request(provider, request),
        CompiledGuardrailProvider::Presidio(provider) => {
            generic::presidio_request(provider, request)
        }
        CompiledGuardrailProvider::Lakera(provider) => lakera::lakera_request(provider, request),
        CompiledGuardrailProvider::Aporia(provider) => aporia::aporia_request(provider, request),
        CompiledGuardrailProvider::AzureContentSafety(provider) => {
            azure::azure_request(provider, request)
        }
        CompiledGuardrailProvider::Bedrock(provider) => bedrock::bedrock_request(provider, request),
        CompiledGuardrailProvider::CrowdStrike(provider) => {
            crowdstrike::crowdstrike_request(provider, request)
        }
        CompiledGuardrailProvider::Mistral(provider) => mistral::mistral_request(provider, request),
        CompiledGuardrailProvider::Pangea(provider) => pangea::pangea_request(provider, request),
        CompiledGuardrailProvider::Patronus(provider) => {
            patronus::patronus_request(provider, request)
        }
    };
    let mut call = config
        .client_for(compiled.url())
        .map_err(|_| GuardrailCallError::Request)?
        .post(compiled.url())
        .timeout(Duration::from_millis(config.timeout_ms))
        .json(&body);
    if let Some(auth) = compiled.auth() {
        call = call.header(auth.header.clone(), auth.value.clone());
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
    match &compiled {
        CompiledGuardrailProvider::Generic(_) => generic::parse_generic(&body),
        CompiledGuardrailProvider::Presidio(_) => generic::parse_presidio(&body),
        CompiledGuardrailProvider::Lakera(_) => lakera::parse_lakera(&body),
        CompiledGuardrailProvider::Aporia(_) => aporia::parse_aporia(&body),
        CompiledGuardrailProvider::AzureContentSafety(provider) => {
            azure::parse_azure(&body, provider)
        }
        CompiledGuardrailProvider::Bedrock(_) => bedrock::parse_bedrock(&body),
        CompiledGuardrailProvider::CrowdStrike(_) => crowdstrike::parse_crowdstrike(&body),
        CompiledGuardrailProvider::Mistral(provider) => mistral::parse_mistral(&body, provider),
        CompiledGuardrailProvider::Pangea(_) => pangea::parse_pangea(&body),
        CompiledGuardrailProvider::Patronus(_) => patronus::parse_patronus(&body),
    }
}

/// Parse the shared AIDR and AI Guard `result.blocked` and detector shape.
/// Provider output can contain transformed content, which is intentionally not
/// read or surfaced by this safety boundary.
pub(super) fn parse_blocked_detector_result(
    body: &Value,
    blocked_reason: &'static str,
) -> Result<GuardrailVerdict, GuardrailCallError> {
    let result = body
        .get("result")
        .and_then(Value::as_object)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let blocked = result
        .get("blocked")
        .and_then(Value::as_bool)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let detectors = result
        .get("detectors")
        .and_then(Value::as_object)
        .filter(|detectors| !detectors.is_empty())
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    if detectors.len() > 32 {
        return Err(GuardrailCallError::InvalidVerdict);
    }

    let mut categories = Vec::new();
    let mut scores = BTreeMap::new();
    let mut seen_categories = BTreeSet::new();
    for (name, detector) in detectors {
        let category =
            generic::normalize_category(name).ok_or(GuardrailCallError::InvalidVerdict)?;
        if !seen_categories.insert(category.clone()) {
            return Err(GuardrailCallError::InvalidVerdict);
        }
        let Some(detector) = detector.as_object() else {
            if detector.is_null() {
                continue;
            }
            return Err(GuardrailCallError::InvalidVerdict);
        };
        let detected = detector
            .get("detected")
            .and_then(Value::as_bool)
            .ok_or(GuardrailCallError::InvalidVerdict)?;
        let data = detector
            .get("data")
            .ok_or(GuardrailCallError::InvalidVerdict)?;
        let data = if data.is_null() {
            None
        } else {
            Some(data.as_object().ok_or(GuardrailCallError::InvalidVerdict)?)
        };
        if detected {
            if data.is_none() || categories.len() == 32 {
                return Err(GuardrailCallError::InvalidVerdict);
            }
            categories.push(category.clone());
        }
        let Some(analyzers) = data.and_then(|data| data.get("analyzer_responses")) else {
            continue;
        };
        let analyzers = analyzers
            .as_array()
            .filter(|analyzers| !analyzers.is_empty())
            .ok_or(GuardrailCallError::InvalidVerdict)?;
        for analyzer in analyzers {
            let analyzer = analyzer
                .as_object()
                .ok_or(GuardrailCallError::InvalidVerdict)?;
            let name = analyzer
                .get("analyzer")
                .and_then(Value::as_str)
                .and_then(generic::normalize_category)
                .ok_or(GuardrailCallError::InvalidVerdict)?;
            let confidence = analyzer
                .get("confidence")
                .and_then(Value::as_f64)
                .filter(|score| score.is_finite() && (0.0..=1.0).contains(score))
                .ok_or(GuardrailCallError::InvalidVerdict)?;
            if scores.len() == 32
                || scores
                    .insert(format!("{category}.{name}"), confidence)
                    .is_some()
            {
                return Err(GuardrailCallError::InvalidVerdict);
            }
        }
    }

    Ok(GuardrailVerdict {
        allowed: !blocked,
        reason: blocked.then(|| blocked_reason.to_string()),
        categories,
        scores,
    })
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
    fn compiled_provider_contract_retains_validated_fields() {
        let aporia: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"aporia", "provider":"aporia", "url":"https://8.8.8.8/validate",
            "mode":"pre_call", "api_key":"fixture-key", "project_id":"fixture-project"
        }))
        .unwrap();
        let CompiledGuardrailProvider::Aporia(aporia) = aporia.validate().unwrap() else {
            panic!("expected Aporia contract");
        };
        assert_eq!(aporia.project_id, "fixture-project");

        let mistral: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"mistral", "provider":"mistral", "url":"https://8.8.8.8/moderations",
            "mode":"pre_call", "api_key":"fixture-key", "model":"fixture-model",
            "score_threshold":0.75
        }))
        .unwrap();
        let CompiledGuardrailProvider::Mistral(mistral) = mistral.validate().unwrap() else {
            panic!("expected Mistral contract");
        };
        assert_eq!(mistral.model, "fixture-model");
        assert_eq!(mistral.score_threshold, Some(0.75));

        let pangea: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"pangea", "provider":"pangea", "url":"https://8.8.8.8/guard",
            "mode":"pre_call", "api_key":"fixture-key", "input_recipe":"input-recipe",
            "output_recipe":"output-recipe"
        }))
        .unwrap();
        let CompiledGuardrailProvider::Pangea(pangea) = pangea.validate().unwrap() else {
            panic!("expected Pangea contract");
        };
        assert_eq!(pangea.input_recipe, "input-recipe");
        assert_eq!(pangea.output_recipe, "output-recipe");
    }
    #[test]
    fn unresolved_and_invalid_auth_fields_fail_during_load() {
        let unresolved = |name: &str| format!("{}{{{name}}}", "$");
        for extra in [
            serde_json::json!({"language":unresolved("GUARD_LANGUAGE")}),
            serde_json::json!({"auth_header":unresolved("GUARD_HEADER")}),
            serde_json::json!({"auth_prefix":unresolved("GUARD_PREFIX")}),
            serde_json::json!({"auth_header":"bad header"}),
            serde_json::json!({"auth_prefix":"Bearer\nInjected:"}),
        ] {
            let mut document = serde_json::json!({
                "name":"custom", "url":"https://8.8.8.8/check",
                "mode":"pre_call", "api_key":"fixture-key"
            });
            document
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let cfg: ExternalGuardrailConfig = serde_json::from_value(document).unwrap();
            let error = cfg
                .validate()
                .expect_err("invalid auth/interpolation must fail");
            assert!(!error.to_string().contains("fixture-key"));
        }
    }
    #[test]
    fn generic_response_without_verdict_is_an_error() {
        assert!(
            generic::parse_generic(&serde_json::json!({"analysis":{"risk":"unknown"}})).is_err()
        );
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
    async fn logging_only_records_but_never_blocks() {
        let before =
            crate::ai_metrics::external_guardrail_verdict_value("generic", "input", "block");
        let url =
            fixture_server(r#"{"allowed":false,"reason":"do not expose me"}"#.to_string()).await;
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"audit", "url":url, "mode":"logging_only", "default_on":true,
            "allow_private_url":true
        }))
        .unwrap();
        assert!(run_input_external_guardrails(&[cfg], "prompt")
            .await
            .is_none());
        let after =
            crate::ai_metrics::external_guardrail_verdict_value("generic", "input", "block");
        assert!(after > before, "logging_only must record its verdict");
    }
    #[test]
    fn external_guardrail_metric_labels_are_bounded() {
        let before =
            crate::ai_metrics::external_guardrail_verdict_value("unknown", "unknown", "unknown");
        crate::ai_metrics::record_external_guardrail_verdict(
            "attacker-provider",
            "attacker-phase",
            "attacker-outcome",
        );
        let after =
            crate::ai_metrics::external_guardrail_verdict_value("unknown", "unknown", "unknown");
        assert!(after > before);
    }
    #[test]
    fn presidio_request_and_verdict_are_strict() {
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"presidio", "provider":"presidio", "url":"https://8.8.8.8/analyze",
            "mode":"pre_call", "language":"es"
        }))
        .unwrap();
        let CompiledGuardrailProvider::Presidio(presidio) = cfg.validate().unwrap() else {
            panic!("expected Presidio contract");
        };
        let request = generic::presidio_request(
            &presidio,
            ExternalGuardrailRequest {
                content: "fixture prompt",
                model: "fixture-model",
                phase: GuardrailPhase::Input,
            },
        );
        assert_eq!(
            request,
            serde_json::json!({"text":"fixture prompt","language":"es"})
        );
        assert!(
            generic::parse_presidio(&serde_json::json!([]))
                .unwrap()
                .allowed
        );
        assert!(
            !generic::parse_presidio(&serde_json::json!([{"entity_type":"PERSON"}]))
                .unwrap()
                .allowed
        );
        assert!(generic::parse_presidio(&serde_json::json!({"allowed":true})).is_err());
    }
    #[tokio::test]
    async fn provider_reason_is_never_exposed() {
        const SENTINEL: &str = "secret-prompt-SENTINEL-7359";
        let url = fixture_server(format!(r#"{{"allowed":false,"reason":"{SENTINEL}"}}"#)).await;
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"custom", "url":url, "mode":"pre_call", "default_on":true,
            "allow_private_url":true
        }))
        .unwrap();
        let (_, reason) = run_input_external_guardrails(&[cfg], "prompt")
            .await
            .expect("guardrail must block");
        assert!(!reason.contains(SENTINEL));
        assert_eq!(reason, "external guardrail blocked content");
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
        let url = fixture_server(format!(
            r#"{{"allowed":true,"detail":"{}"}}"#,
            "x".repeat(MAX_GUARDRAIL_RESPONSE_BYTES)
        ))
        .await;
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"custom", "url":url, "mode":"pre_call", "allow_private_url":true,
            "fail_open":true
        }))
        .unwrap();
        let verdict = check_external_guardrail(
            &cfg,
            ExternalGuardrailRequest {
                content: "prompt",
                model: "test",
                phase: GuardrailPhase::Input,
            },
        )
        .await;
        assert!(verdict.allowed);
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
