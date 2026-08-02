//! Bounded, typed external guardrail integrations.
//!
//! This module owns the common safety boundary shared by every external
//! guardrail: configuration validation, SSRF-safe outbound clients, bounded
//! response reads, failure-posture handling, and closed-cardinality
//! telemetry.
//!
//! Two independent axes govern what a guardrail does, and they are kept
//! apart on purpose. `mode` carries the enforcement axis: `logging_only`
//! records a verdict and never refuses. `failure_posture` (legacy
//! spelling: `fail_open`) carries the failure axis: what happens when the
//! provider could not be reached at all. Read them through
//! [`ExternalGuardrailConfig::enforcement`] and
//! `ExternalGuardrailConfig::failure_posture()` rather than off the raw
//! fields.

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
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::ai_metrics::record_external_guardrail_verdict;

/// The two shared posture vocabularies, re-exported here so a caller of
/// this module never has to reach into the config crate to name one.
///
/// They are different axes and this module is where that shows up most
/// plainly. [`EnforcementMode`] answers "the provider answered and it
/// said block, now what"; [`FailureMode`] answers "the provider never
/// answered at all, now what".
pub use sbproxy_config::{EnforcementMode, FailureMode};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
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
        matches!(self, Self::PostCall | Self::DuringCall | Self::LoggingOnly)
    }

    pub fn blocks(self) -> bool {
        !matches!(self, Self::LoggingOnly)
    }

    /// This mode's enforcement posture in the shared vocabulary.
    ///
    /// `mode` picks *when* a guardrail runs and, in the `logging_only`
    /// case, also says it must never refuse. That second half is the
    /// enforcement axis, which is a different question from the failure
    /// axis carried by `ExternalGuardrailConfig::failure_posture()`:
    /// `logging_only` is an [`EnforcementMode::Observe`] posture because
    /// the provider still runs and still records a verdict, it just
    /// never blocks on one.
    pub fn enforcement(self) -> EnforcementMode {
        if self.blocks() {
            EnforcementMode::Block
        } else {
            EnforcementMode::Observe
        }
    }
}

/// Provider contracts supported by the external guardrail configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, JsonSchema)]
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
/// here so legacy generic configurations stay valid; `validate` makes their
/// requirements explicit before a handler is published.
#[derive(Clone, Deserialize, JsonSchema)]
pub struct ExternalGuardrailConfig {
    /// Operator-defined identifier used in logs and client error codes.
    /// It must contain at least one non-whitespace character.
    #[schemars(regex(pattern = "\\S"))]
    pub name: String,
    /// Provider endpoint. Generic, Presidio, Azure, and CrowdStrike require it.
    /// Other providers supply a documented default or derive it from their fields.
    #[serde(default)]
    pub url: Option<String>,
    /// When to evaluate this provider: before a call, after a call, both, or logging only.
    pub mode: GuardrailMode,
    /// Enable this guardrail automatically for each matching phase on the route.
    #[serde(default)]
    pub default_on: bool,
    /// Allow traffic when this provider cannot be reached or returns an invalid response.
    ///
    /// Legacy spelling of the failure axis, kept because existing
    /// configurations use it. It still parses and still means exactly
    /// what it always did: `true` is [`FailureMode::Open`], `false` (and
    /// an omitted key) is [`FailureMode::Closed`]. Prefer
    /// `failure_posture`, because a boolean has no way to say
    /// `degraded`, which is what an admitted-but-unscanned request
    /// actually is.
    ///
    /// Never read this field directly; read
    /// `ExternalGuardrailConfig::failure_posture()`, which resolves the
    /// two spellings in one place. Setting both to values that disagree
    /// is a config-load error.
    #[serde(default)]
    pub fail_open: Option<bool>,
    /// Failure posture: what this guardrail does when its provider
    /// cannot be reached, answers with a non-success status, is too
    /// slow, or returns something that is not a verdict.
    ///
    /// This is the failure axis only. The enforcement axis lives in
    /// `mode`: `logging_only` never refuses anything even when the
    /// provider answers and says block. The two are independent, so a
    /// guardrail can be rolled out in `mode: logging_only` while still
    /// declaring `failure_posture: closed` for the day it starts
    /// enforcing.
    ///
    /// - `closed` refuses the request. The default, and the right
    ///   choice for a guardrail that is actually protecting something.
    /// - `open` admits the request and claims nothing.
    /// - `degraded` admits the request while recording that it was
    ///   never scanned. Prefer this over `open`: the behavior is the
    ///   same, and it is the truthful description of what happened.
    /// - `observe` is rejected here. There is no verdict to
    ///   shadow-record when the provider never answered; the
    ///   observe-shaped posture for this site is `mode: logging_only`,
    ///   on the other axis.
    ///
    /// When absent, the posture comes from the legacy `fail_open`
    /// boolean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_posture: Option<FailureMode>,
    /// Per-request provider deadline in milliseconds, from 1 through 30000.
    #[serde(default = "default_timeout_ms")]
    #[schemars(range(min = 1, max = 30_000))]
    pub timeout_ms: u64,
    /// Provider wire contract. Omit for the backward-compatible generic contract.
    #[serde(default)]
    pub provider: GuardrailProvider,
    /// Credential value or a resolved secret reference. Required by named hosted providers.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Header used with `api_key` for generic and Presidio requests.
    #[serde(default = "default_auth_header")]
    pub auth_header: Option<String>,
    /// Prefix inserted before `api_key` for generic and Presidio requests.
    #[serde(default = "default_auth_prefix")]
    pub auth_prefix: Option<String>,
    /// Permit a loopback or private endpoint after URL syntax validation.
    #[serde(default)]
    pub allow_private_url: bool,
    /// Presidio language code. Defaults to `en` for the Presidio provider.
    #[serde(default)]
    pub language: Option<String>,
    /// Aporia project identifier. Required for the Aporia provider.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Optional CrowdStrike application identifier.
    #[serde(default)]
    pub application_id: Option<String>,
    /// AWS region used to derive the Bedrock runtime endpoint when `url` is absent.
    #[serde(default)]
    pub region: Option<String>,
    /// Bedrock guardrail identifier. Required for the Bedrock provider.
    #[serde(default)]
    pub guardrail_id: Option<String>,
    /// Bedrock guardrail version. Required for the Bedrock provider.
    #[serde(default)]
    pub guardrail_version: Option<String>,
    /// Azure Content Safety block threshold from 0 through 7. Defaults to 4.
    #[serde(default)]
    #[schemars(range(max = 7))]
    pub severity_threshold: Option<u8>,
    /// Mistral moderation model. Defaults to `mistral-moderation-2603`.
    #[serde(default)]
    pub model: Option<String>,
    /// Mistral category score threshold from 0 through 1.
    #[serde(default)]
    #[schemars(range(min = 0.0, max = 1.0))]
    pub score_threshold: Option<f64>,
    /// Pangea recipe used for request content. Defaults to `pangea_prompt_guard`.
    #[serde(default)]
    pub input_recipe: Option<String>,
    /// Pangea recipe used for response content. Defaults to `pangea_llm_response_guard`.
    #[serde(default)]
    pub output_recipe: Option<String>,
    /// Patronus evaluator name. Defaults to `prompt-injection`.
    #[serde(default)]
    pub evaluator: Option<String>,
    /// Optional Patronus evaluator criteria.
    #[serde(default)]
    pub criteria: Option<String>,
    /// Compiled provider contract and pinned outbound client. This is runtime
    /// state, not configuration, and is populated only after credential
    /// resolution (or lazily by resolver-free validation/test callers).
    #[serde(skip)]
    #[schemars(skip)]
    prepared: OnceLock<std::result::Result<PreparedExternalGuardrail, String>>,
}

impl std::fmt::Debug for ExternalGuardrailConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self.url.as_deref().map(sanitized_debug_url);
        formatter
            .debug_struct("ExternalGuardrailConfig")
            .field("name", &self.name)
            .field("url", &url)
            .field("mode", &self.mode)
            .field("default_on", &self.default_on)
            .field("fail_open", &self.fail_open)
            .field("failure_posture", &self.failure_posture)
            .field("timeout_ms", &self.timeout_ms)
            .field("provider", &self.provider)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("auth_header", &self.auth_header)
            .field("auth_prefix", &self.auth_prefix)
            .field("allow_private_url", &self.allow_private_url)
            .field("language", &self.language)
            .field("project_id", &self.project_id)
            .field("application_id", &self.application_id)
            .field("region", &self.region)
            .field("guardrail_id", &self.guardrail_id)
            .field("guardrail_version", &self.guardrail_version)
            .field("severity_threshold", &self.severity_threshold)
            .field("model", &self.model)
            .field("score_threshold", &self.score_threshold)
            .field("input_recipe", &self.input_recipe)
            .field("output_recipe", &self.output_recipe)
            .field("evaluator", &self.evaluator)
            .field("criteria", &self.criteria)
            .field("prepared", &self.prepared.get().is_some())
            .finish()
    }
}

fn sanitized_debug_url(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        return "[INVALID URL]".to_string();
    };
    let _ = url.set_password(None);
    let _ = url.set_username("");
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
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

#[derive(Clone)]
struct PreparedExternalGuardrail {
    provider: CompiledGuardrailProvider,
    client: reqwest::Client,
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
    /// This guardrail's failure posture in the shared vocabulary.
    ///
    /// The one place the two spellings are resolved. An explicit
    /// `failure_posture` wins; otherwise the legacy `fail_open` boolean
    /// is converted, with an absent key meaning `false`, which is
    /// [`FailureMode::Closed`]. Request-path code reads this and never
    /// the raw fields, so the polarity conversion exists once instead of
    /// at every site that cares.
    pub fn failure_posture(&self) -> FailureMode {
        match self.failure_posture {
            Some(posture) => posture,
            None => FailureMode::from_fail_open(self.fail_open.unwrap_or(false)),
        }
    }

    /// This guardrail's enforcement posture in the shared vocabulary.
    ///
    /// Derived from `mode`, and deliberately separate from
    /// `Self::failure_posture()`. See [`GuardrailMode::enforcement`].
    pub fn enforcement(&self) -> EnforcementMode {
        self.mode.enforcement()
    }

    /// Reject a failure axis that says two things at once, or that says
    /// something meaningless for this site.
    fn validate_failure_posture(&self) -> Result<()> {
        let Some(posture) = self.failure_posture else {
            return Ok(());
        };
        if matches!(posture, FailureMode::Observe) {
            bail!(
                "failure_posture: observe is not meaningful on an external guardrail. The \
                 failure axis applies when the provider could not be reached, so there is no \
                 verdict to shadow-record. To roll this guardrail out without letting it \
                 refuse anything, set the enforcement axis instead (mode: logging_only), and \
                 pick closed, open, or degraded here"
            );
        }
        if let Some(fail_open) = self.fail_open {
            let legacy = FailureMode::from_fail_open(fail_open);
            if legacy != posture {
                let legacy_label = legacy.as_label();
                let posture_label = posture.as_label();
                bail!(
                    "fail_open: {fail_open} and failure_posture: {posture_label} disagree on \
                     this external guardrail; fail_open: {fail_open} means failure_posture: \
                     {legacy_label}. Remove fail_open and keep failure_posture"
                );
            }
        }
        Ok(())
    }

    /// Validate the wire document and compile its provider contract.
    pub fn validate(&self) -> Result<CompiledGuardrailProvider> {
        if self.name.trim().is_empty() {
            bail!("name must not be empty");
        }
        self.validate_failure_posture()?;
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
        validate_http_url(url)?;
        if self.allow_private_url {
            return Ok(());
        }

        // Structural validation must not perform DNS. Runtime preparation
        // resolves and pins the endpoint before publication; here we reject
        // the private targets that are knowable from the URL alone.
        let parsed = url::Url::parse(url).context("invalid URL")?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("URL has no host"))?;
        if host.eq_ignore_ascii_case("localhost")
            || host
                .to_ascii_lowercase()
                .strip_suffix(".localhost")
                .is_some()
        {
            bail!("blocked: hostname '{host}' is private/internal");
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if sbproxy_security::is_private_ip(&ip) {
                bail!("blocked: IP address {ip} is private/internal");
            }
        }
        Ok(())
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

    /// Compile the provider contract and build its bounded, DNS-pinned client.
    ///
    /// Production configuration calls this after resolving `api_key`, so the
    /// prepared authorization header can never capture a secret reference.
    pub fn prepare(&self) -> Result<()> {
        self.prepared_runtime().map(|_| ())
    }

    /// Whether this configuration already has prepared runtime state.
    pub fn is_prepared(&self) -> bool {
        self.prepared.get().is_some_and(|result| result.is_ok())
    }

    /// Return the prepared bounded client.
    pub fn client(&self) -> Result<&reqwest::Client> {
        Ok(&self.prepared_runtime()?.client)
    }

    fn prepared_runtime(&self) -> Result<&PreparedExternalGuardrail> {
        match self
            .prepared
            .get_or_init(|| self.build_prepared().map_err(|error| error.to_string()))
        {
            Ok(prepared) => Ok(prepared),
            Err(error) => Err(anyhow::anyhow!("{error}")),
        }
    }

    fn build_prepared(&self) -> Result<PreparedExternalGuardrail> {
        let provider = self.validate()?;
        let url = provider.url();
        let builder = OutboundClientBuilder::new().no_redirects().into_inner();
        let resolved = if self.allow_private_url {
            validate_http_url(url)?;
            let parsed = url::Url::parse(url).context("invalid URL")?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("URL has no host"))?
                .to_string();
            sbproxy_security::validate_url_resolved(url, &[host]).map_err(anyhow::Error::msg)?
        } else {
            sbproxy_security::validate_url_resolved(url, &[]).map_err(anyhow::Error::msg)?
        };
        if resolved.addrs.is_empty() {
            bail!("external guardrail endpoint resolved to no addresses");
        }
        let builder = builder.resolve_to_addrs(&resolved.host, &resolved.addrs);
        let client = builder
            .build()
            .context("could not build external guardrail client")?;
        Ok(PreparedExternalGuardrail { provider, client })
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

/// The verdict and metric outcome for a provider that could not be
/// reached, was too slow, or did not return a verdict.
///
/// Split out so the failure axis is interpreted in exactly one place.
/// Both admitting postures record `fail_open`, because that is the
/// bounded outcome vocabulary
/// `sbproxy_ai_external_guardrail_verdicts_total` already publishes; the
/// log line carries the posture itself, so `open` and `degraded` stay
/// distinguishable there.
fn unavailable_verdict(posture: FailureMode) -> (GuardrailVerdict, &'static str) {
    match posture {
        FailureMode::Open => (
            GuardrailVerdict {
                allowed: true,
                reason: Some("external guardrail unavailable; fail-open".to_string()),
                ..GuardrailVerdict::default()
            },
            "fail_open",
        ),
        FailureMode::Degraded => (
            GuardrailVerdict {
                allowed: true,
                reason: Some("external guardrail unavailable; content was not scanned".to_string()),
                ..GuardrailVerdict::default()
            },
            "fail_open",
        ),
        // `observe` cannot reach here from a loaded configuration:
        // `ExternalGuardrailConfig::validate` rejects it. A hand-built
        // config that skipped validation gets the safe posture rather
        // than an invented behavior.
        FailureMode::Closed | FailureMode::Observe => (
            GuardrailVerdict {
                allowed: false,
                reason: Some("external guardrail unavailable; fail-closed".to_string()),
                ..GuardrailVerdict::default()
            },
            "fail_closed",
        ),
    }
}

/// Call an external guardrail. A transport or parse error is mapped through
/// the configured failure posture exactly once here.
pub async fn check_external_guardrail(
    config: &ExternalGuardrailConfig,
    request: ExternalGuardrailRequest<'_>,
) -> GuardrailVerdict {
    let started = std::time::Instant::now();
    let posture = config.failure_posture();
    let result = dispatch(config, request).await;
    let (verdict, outcome) = match result {
        Ok(verdict) if verdict.allowed => (verdict, "allow"),
        Ok(verdict) => (verdict, "block"),
        Err(_) => unavailable_verdict(posture),
    };
    record_external_guardrail_verdict(config.provider.as_str(), request.phase.as_str(), outcome);
    tracing::debug!(guardrail = %config.name, provider = config.provider.as_str(), phase = request.phase.as_str(), latency_ms = started.elapsed().as_millis() as u64, categories = ?verdict.categories, enforcement = config.enforcement().as_label(), posture = posture.as_label(), outcome, "external guardrail evaluated");
    verdict
}

async fn dispatch(
    config: &ExternalGuardrailConfig,
    request: ExternalGuardrailRequest<'_>,
) -> std::result::Result<GuardrailVerdict, GuardrailCallError> {
    let prepared = config
        .prepared_runtime()
        .map_err(|_| GuardrailCallError::Request)?;
    let compiled = &prepared.provider;
    let body = match compiled {
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
    let mut call = prepared
        .client
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
    match compiled {
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
    model: &str,
) -> Option<(String, String)> {
    run_external_guardrails(configs, content, model, GuardrailPhase::Input).await
}
pub async fn run_output_external_guardrails(
    configs: &[ExternalGuardrailConfig],
    content: &str,
    model: &str,
) -> Option<(String, String)> {
    run_external_guardrails(configs, content, model, GuardrailPhase::Output).await
}

/// Apply input guardrail failure postures when request content is
/// unavailable.
pub fn run_input_external_guardrails_without_content(
    configs: &[ExternalGuardrailConfig],
) -> Option<(String, String)> {
    run_external_guardrails_without_content(configs, GuardrailPhase::Input)
}

/// Apply output guardrail failure postures when the upstream response
/// cannot be represented as text. The raw bytes are deliberately not
/// converted or sent to an external service. A guardrail that does not
/// enforce (`mode: logging_only`) records the skip and admits whatever its
/// failure posture says, and so does one whose posture admits (`open` or
/// `degraded`); the first entry that both enforces and fails closed blocks
/// with a fixed operator-safe reason.
pub fn run_output_external_guardrails_without_content(
    configs: &[ExternalGuardrailConfig],
) -> Option<(String, String)> {
    run_external_guardrails_without_content(configs, GuardrailPhase::Output)
}

fn run_external_guardrails_without_content(
    configs: &[ExternalGuardrailConfig],
    phase: GuardrailPhase,
) -> Option<(String, String)> {
    let reason = match phase {
        GuardrailPhase::Input => "external input guardrail could not inspect request content",
        GuardrailPhase::Output => "external output guardrail could not inspect response content",
    };

    for config in configs {
        let applies = match phase {
            GuardrailPhase::Input => config.mode.is_input(),
            GuardrailPhase::Output => config.mode.is_output(),
        };
        if !config.default_on || !applies {
            continue;
        }

        // Two axes, and this is the one line in the request path that
        // needs both. `enforcement` is what this guardrail does when it
        // reaches a verdict: `logging_only` never refuses, whatever the
        // provider says. `posture` is what it does when it cannot reach
        // one at all, which is the case here because there is no text to
        // send. Only a guardrail that both enforces and refuses on
        // failure can block. Spelling them apart is what stops the two
        // from being read as one knob.
        let enforcement = config.enforcement();
        let posture = config.failure_posture();
        let blocks = enforcement.blocks() && !posture.admits();
        let outcome = if blocks { "fail_closed" } else { "fail_open" };
        record_external_guardrail_verdict(config.provider.as_str(), phase.as_str(), outcome);
        tracing::debug!(
            guardrail = %config.name,
            provider = config.provider.as_str(),
            phase = phase.as_str(),
            enforcement = enforcement.as_label(),
            posture = posture.as_label(),
            outcome,
            "external guardrail skipped because content is unavailable"
        );

        if blocks {
            return Some((config.name.clone(), reason.to_string()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_rejects_blank_external_guardrail_names() {
        let schema = serde_json::to_value(schemars::schema_for!(ExternalGuardrailConfig))
            .expect("external guardrail schema serializes");
        assert_eq!(
            schema.pointer("/properties/name/pattern"),
            Some(&serde_json::json!("\\S"))
        );

        let validator =
            jsonschema::JSONSchema::compile(&schema).expect("external guardrail schema compiles");
        for name in ["", " \t\n"] {
            let document = serde_json::json!({"name": name, "mode": "pre_call"});
            assert!(
                validator.validate(&document).is_err(),
                "schema must reject blank name {name:?}"
            );
        }
        let document = serde_json::json!({"name": "local-policy", "mode": "pre_call"});
        assert!(validator.validate(&document).is_ok());
    }

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
    fn validation_does_not_freeze_credentials_and_prepared_runtime_is_reused() {
        let mut cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name": "custom",
            "url": "https://8.8.8.8/check",
            "mode": "pre_call",
            "api_key": "secret://guardrails/customer-policy"
        }))
        .unwrap();

        cfg.validate().expect("structural validation");
        assert!(
            !cfg.is_prepared(),
            "validation must not compile an unresolved credential into runtime state"
        );
        assert!(
            !format!("{cfg:?}").contains("secret://guardrails/customer-policy"),
            "Debug must redact unresolved credential references"
        );
        *cfg.credential_reference_mut().unwrap() = "resolved-fixture-key".to_string();
        cfg.prepare().expect("prepare resolved configuration");

        let first = cfg.prepared_runtime().unwrap();
        let second = cfg.prepared_runtime().unwrap();
        assert!(
            std::ptr::eq(first, second),
            "request dispatch must reuse one prepared provider/client"
        );
        let auth = first.provider.auth().expect("compiled authorization");
        assert_eq!(auth.value.to_str().unwrap(), "Bearer resolved-fixture-key");
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("resolved-fixture-key"));
        assert!(!debug.contains("secret://guardrails/customer-policy"));
    }

    #[test]
    fn structural_validation_does_not_resolve_dns() {
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name": "custom",
            "url": "https://guardrail-does-not-exist.invalid/check",
            "mode": "pre_call"
        }))
        .unwrap();

        cfg.validate()
            .expect("structural validation must not depend on DNS");
        assert!(!cfg.is_prepared());
    }

    #[test]
    fn debug_redacts_url_credentials_query_and_fragment() {
        let cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name": "custom",
            "url": "https://webhook-user:webhook-password@guard.example.test/hooks/path-secret?token=query-secret#fragment-secret",
            "mode": "pre_call"
        }))
        .unwrap();

        let debug = format!("{cfg:?}");
        assert!(debug.contains("https://guard.example.test/"));
        for secret in [
            "webhook-user",
            "webhook-password",
            "path-secret",
            "query-secret",
            "fragment-secret",
        ] {
            assert!(!debug.contains(secret), "{secret} leaked through Debug");
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
    async fn dispatch_uses_prepared_runtime_without_request_path_revalidation() {
        let url = fixture_server(r#"{"allowed":true}"#.to_string()).await;
        let mut cfg: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name": "prepared-policy",
            "url": url,
            "mode": "pre_call",
            "allow_private_url": true
        }))
        .unwrap();
        cfg.prepare().expect("prepare runtime before publication");

        // This would make structural validation fail. Dispatch still succeeds
        // because the published request path only reads prepared state.
        cfg.name.clear();
        let verdict = check_external_guardrail(
            &cfg,
            ExternalGuardrailRequest {
                content: "fixture prompt",
                model: "fixture-model",
                phase: GuardrailPhase::Input,
            },
        )
        .await;
        assert!(verdict.allowed);
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
        assert!(
            run_input_external_guardrails(&[cfg], "prompt", "fixture-model")
                .await
                .is_none()
        );
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
        let (_, reason) = run_input_external_guardrails(&[cfg], "prompt", "fixture-model")
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

    fn unavailable_output_config(mode: &str, fail_open: bool) -> ExternalGuardrailConfig {
        serde_json::from_value(serde_json::json!({
            "name": "binary-policy",
            "url": "https://8.8.8.8/check",
            "mode": mode,
            "default_on": true,
            "fail_open": fail_open
        }))
        .unwrap()
    }

    /// The same fixture spelled on the new axis, so the two-axis tests
    /// can set enforcement and failure independently.
    fn unavailable_posture_config(mode: &str, posture: &str) -> ExternalGuardrailConfig {
        serde_json::from_value(serde_json::json!({
            "name": "posture-policy",
            "url": "https://8.8.8.8/check",
            "mode": mode,
            "default_on": true,
            "failure_posture": posture
        }))
        .unwrap()
    }

    fn guardrail_document(extra: serde_json::Value) -> ExternalGuardrailConfig {
        let mut document = serde_json::json!({
            "name": "custom",
            "url": "https://8.8.8.8/check",
            "mode": "pre_call"
        });
        document
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(document).unwrap()
    }

    #[test]
    fn legacy_fail_open_boolean_still_selects_the_posture() {
        // An absent key, an explicit false, and an explicit true keep
        // the exact meanings they had before `failure_posture` existed.
        let absent = guardrail_document(serde_json::json!({}));
        assert_eq!(absent.fail_open, None);
        assert_eq!(absent.failure_posture(), FailureMode::Closed);
        assert!(absent.validate().is_ok());

        let closed = guardrail_document(serde_json::json!({"fail_open": false}));
        assert_eq!(closed.failure_posture(), FailureMode::Closed);
        assert!(closed.validate().is_ok());

        let open = guardrail_document(serde_json::json!({"fail_open": true}));
        assert_eq!(open.failure_posture(), FailureMode::Open);
        assert!(open.validate().is_ok());
    }

    #[test]
    fn explicit_failure_posture_overrides_the_legacy_boolean() {
        for (posture, expected) in [
            ("closed", FailureMode::Closed),
            ("open", FailureMode::Open),
            ("degraded", FailureMode::Degraded),
        ] {
            let config = guardrail_document(serde_json::json!({"failure_posture": posture}));
            assert_eq!(config.failure_posture(), expected, "{posture}");
            config.validate().expect("posture alone is valid");
        }

        // Precedence: the explicit posture wins over a legacy boolean
        // that agrees with it, and the legacy field is still readable.
        let document = serde_json::json!({"fail_open": true, "failure_posture": "open"});
        let config = guardrail_document(document);
        assert_eq!(config.fail_open, Some(true));
        assert_eq!(config.failure_posture(), FailureMode::Open);
        config
            .validate()
            .expect("a redundant but consistent pair stays valid");
    }

    #[test]
    fn conflicting_fail_open_and_failure_posture_is_a_config_error() {
        for (fail_open, posture) in [
            (true, "closed"),
            (true, "degraded"),
            (false, "open"),
            (false, "degraded"),
        ] {
            let document = serde_json::json!({"fail_open": fail_open, "failure_posture": posture});
            let config = guardrail_document(document);
            let error = config
                .validate()
                .expect_err("disagreeing spellings must fail at config load")
                .to_string();
            assert!(error.contains("external guardrail"), "{error}");
            assert!(error.contains("fail_open"), "{error}");
            assert!(error.contains("failure_posture"), "{error}");
        }
    }

    #[test]
    fn observe_is_rejected_on_the_failure_axis() {
        let error = guardrail_document(serde_json::json!({"failure_posture": "observe"}))
            .validate()
            .expect_err("observe is meaningless when the provider never answered")
            .to_string();
        assert!(error.contains("external guardrail"), "{error}");
        assert!(error.contains("logging_only"), "{error}");
    }

    #[test]
    fn degraded_admits_and_is_labelled_apart_from_a_plain_open() {
        let (open, open_outcome) = unavailable_verdict(FailureMode::Open);
        let (degraded, degraded_outcome) = unavailable_verdict(FailureMode::Degraded);
        let (closed, closed_outcome) = unavailable_verdict(FailureMode::Closed);

        assert!(open.allowed && degraded.allowed && !closed.allowed);
        assert_eq!(open_outcome, "fail_open");
        assert_eq!(degraded_outcome, "fail_open");
        assert_eq!(closed_outcome, "fail_closed");
        assert_ne!(
            open.reason, degraded.reason,
            "degraded must not read as a plain open"
        );
        assert_eq!(
            degraded.reason.as_deref(),
            Some("external guardrail unavailable; content was not scanned")
        );
    }

    #[test]
    fn enforcement_and_failure_axes_are_independently_settable() {
        // The point of the split: `mode` says whether a verdict can
        // refuse, `failure_posture` says whether a missing verdict can.
        // Only the guardrail that answers yes to both blocks here.
        let _metric_lock = unavailable_content_metric_lock();
        for (mode, posture, expected_block) in [
            ("post_call", "closed", true),
            ("post_call", "degraded", false),
            ("logging_only", "closed", false),
            ("logging_only", "degraded", false),
        ] {
            let config = unavailable_posture_config(mode, posture);
            assert_eq!(config.enforcement().blocks(), mode != "logging_only");
            assert_eq!(config.failure_posture().admits(), posture != "closed");

            let blocked = run_output_external_guardrails_without_content(&[config]).is_some();
            assert_eq!(
                blocked, expected_block,
                "mode={mode} failure_posture={posture}"
            );
        }
    }

    #[test]
    fn posture_spelled_configs_match_their_legacy_boolean_equivalents() {
        let _metric_lock = unavailable_content_metric_lock();
        for (fail_open, posture) in [(false, "closed"), (true, "open")] {
            let legacy = unavailable_output_config("post_call", fail_open);
            let modern = unavailable_posture_config("post_call", posture);
            assert_eq!(
                run_output_external_guardrails_without_content(&[legacy]).is_some(),
                run_output_external_guardrails_without_content(&[modern]).is_some(),
                "fail_open={fail_open} vs {posture}"
            );
        }
    }

    fn unavailable_content_metric_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn unavailable_output_content_fails_closed_without_exposing_bytes() {
        let _metric_lock = unavailable_content_metric_lock();
        let blocked = run_output_external_guardrails_without_content(&[unavailable_output_config(
            "post_call",
            false,
        )])
        .expect("fail-closed output guardrail must block");

        assert_eq!(blocked.0, "binary-policy");
        assert_eq!(
            blocked.1,
            "external output guardrail could not inspect response content"
        );
    }

    #[test]
    fn unavailable_output_content_honors_fail_open_and_logging_only_once() {
        let _metric_lock = unavailable_content_metric_lock();
        let fail_open_before =
            crate::ai_metrics::external_guardrail_verdict_value("generic", "output", "fail_open");
        assert!(run_output_external_guardrails_without_content(&[
            unavailable_output_config("post_call", true),
            unavailable_output_config("logging_only", false),
        ])
        .is_none());
        let fail_open_after =
            crate::ai_metrics::external_guardrail_verdict_value("generic", "output", "fail_open");

        assert_eq!(fail_open_after - fail_open_before, 2.0);
    }

    #[test]
    fn unavailable_output_content_ignores_disabled_and_input_only_guardrails() {
        let _metric_lock = unavailable_content_metric_lock();
        let fail_closed_before =
            crate::ai_metrics::external_guardrail_verdict_value("generic", "output", "fail_closed");
        let mut disabled = unavailable_output_config("post_call", false);
        disabled.default_on = false;
        assert!(run_output_external_guardrails_without_content(&[
            disabled,
            unavailable_output_config("pre_call", false),
        ])
        .is_none());
        let fail_closed_after =
            crate::ai_metrics::external_guardrail_verdict_value("generic", "output", "fail_closed");

        assert_eq!(fail_closed_after, fail_closed_before);
    }

    #[test]
    fn unavailable_input_content_honors_fail_modes() {
        let _metric_lock = unavailable_content_metric_lock();
        let blocked = run_input_external_guardrails_without_content(&[unavailable_output_config(
            "pre_call", false,
        )])
        .expect("fail-closed input guardrail must block");
        assert_eq!(blocked.0, "binary-policy");
        assert_eq!(
            blocked.1,
            "external input guardrail could not inspect request content"
        );

        assert!(run_input_external_guardrails_without_content(&[
            unavailable_output_config("pre_call", true),
            unavailable_output_config("logging_only", false),
        ])
        .is_none());
    }
}
