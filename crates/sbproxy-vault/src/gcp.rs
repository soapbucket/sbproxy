// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! GCP Secret Manager backend.
//!
//! Implements [`crate::manager::VaultBackend`] against Google Cloud
//! Secret Manager's `AccessSecretVersion` REST API. The backend keeps
//! the same synchronous trait surface as the other vault backends:
//! token acquisition and HTTP calls run inside the caller's blocking
//! resolver path.
//!
//! ## Scope
//!
//! * Auth methods:
//!   - Application Default Credentials through `gcp_auth` for
//!     service-account keys, gcloud ADC, metadata service accounts,
//!     and gcloud CLI fallback.
//!   - Explicit service-account key file or JSON.
//!   - External-account ADC / Workload Identity Federation for
//!     file- or URL-sourced subject tokens, including optional service
//!     account impersonation.
//! * Path shapes:
//!   - `projects/<project>/secrets/<secret>/versions/<version>`.
//!   - `projects/<project>/secrets/<secret>` with the parsed
//!     `?version=` or `latest`.
//!   - `<secret>` using the configured / ADC / environment project and
//!     the parsed `?version=` or `latest`.
//! * In-process TTL cache (5 minutes by default, configurable per
//!   backend).
//! * Text secret payloads only; the Secret Manager API returns base64
//!   bytes which this backend decodes as UTF-8.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use gcp_auth::{CustomServiceAccount, TokenProvider as GcpAuthTokenProvider};
use parking_lot::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::manager::VaultBackend;
use crate::secret_string::SecretString;
use crate::vault_ref::VaultRef;

/// Default TTL on a cached Secret Manager value.
pub const DEFAULT_GCP_CACHE_TTL: Duration = Duration::from_secs(300);

const DEFAULT_SECRET_MANAGER_ENDPOINT: &str = "https://secretmanager.googleapis.com";
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Read-only GCP Secret Manager client.
pub struct GcpSecretManagerBackend {
    inner: BackendInner,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct BackendInner {
    token_provider: Arc<dyn GcpAccessTokenProvider>,
    transport: Arc<dyn GcpSecretManagerTransport>,
    endpoint: String,
    default_project_id: Option<String>,
    cache_ttl: Duration,
}

struct CacheEntry {
    payload: String,
    expires_at: Instant,
}

/// Operator-facing GCP Secret Manager config.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct GcpSecretManagerConfig {
    /// Default Google Cloud project for short references such as
    /// `gcpsm://primary/openai-api-key`.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Secret Manager API endpoint. Defaults to
    /// `https://secretmanager.googleapis.com`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Authentication method. Defaults to Application Default
    /// Credentials.
    #[serde(default)]
    pub auth: GcpSecretManagerAuth,
    /// Cache TTL in seconds for successful reads. Defaults to
    /// [`DEFAULT_GCP_CACHE_TTL`].
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,
}

/// Operator-facing GCP authentication method.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GcpSecretManagerAuth {
    /// Application Default Credentials. This includes service-account
    /// keys via `GOOGLE_APPLICATION_CREDENTIALS`, gcloud ADC, metadata
    /// service accounts, gcloud CLI fallback, and external-account ADC
    /// files for common Workload Identity Federation deployments.
    #[default]
    ApplicationDefault,
    /// Read a service-account key JSON file.
    ServiceAccountKeyFile {
        /// Path to the service-account key JSON file.
        path: String,
    },
    /// Read service-account key material from an inline JSON string.
    ServiceAccountKeyJson {
        /// Service-account key JSON string.
        json: String,
    },
    /// Read an external-account credential config file for Workload
    /// Identity Federation.
    ExternalAccountFile {
        /// Path to the external-account ADC JSON file.
        path: String,
    },
}

impl GcpSecretManagerBackend {
    /// Build a backend from operator config.
    pub fn new(cfg: GcpSecretManagerConfig) -> Result<Self> {
        let token_provider = build_access_token_provider(cfg.auth.clone())?;
        Self::with_parts(cfg, token_provider, Arc::new(UreqSecretManagerTransport))
    }

    fn with_parts(
        cfg: GcpSecretManagerConfig,
        token_provider: Arc<dyn GcpAccessTokenProvider>,
        transport: Arc<dyn GcpSecretManagerTransport>,
    ) -> Result<Self> {
        let endpoint = cfg
            .endpoint
            .unwrap_or_else(|| DEFAULT_SECRET_MANAGER_ENDPOINT.to_string())
            .trim_end_matches('/')
            .to_string();
        if endpoint.is_empty() {
            anyhow::bail!("GCP Secret Manager: `endpoint` must not be empty");
        }

        let default_project_id = cfg
            .project_id
            .filter(|p| !p.trim().is_empty())
            .or_else(env_project_id)
            .or_else(|| token_provider.project_id().ok().flatten());

        Ok(Self {
            inner: BackendInner {
                token_provider,
                transport,
                endpoint,
                default_project_id,
                cache_ttl: cfg
                    .cache_ttl_secs
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_GCP_CACHE_TTL),
            },
            cache: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    fn new_for_test(
        cfg: GcpSecretManagerConfig,
        token_provider: Arc<dyn GcpAccessTokenProvider>,
        transport: Arc<dyn GcpSecretManagerTransport>,
    ) -> Result<Self> {
        Self::with_parts(cfg, token_provider, transport)
    }

    fn resolve_secret_name(&self, path: &str, version_override: Option<&str>) -> Result<String> {
        let cleaned = path.trim_matches('/');
        if cleaned.is_empty() {
            anyhow::bail!("GCP Secret Manager: empty path after normalisation");
        }
        if cleaned
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        {
            anyhow::bail!("GCP Secret Manager: path `{path}` contains an invalid segment");
        }

        let parts: Vec<&str> = cleaned.split('/').collect();
        match parts.as_slice() {
            ["projects", project, "secrets", secret] => {
                let version = clean_version(version_override)?;
                Ok(format!(
                    "projects/{project}/secrets/{secret}/versions/{version}"
                ))
            }
            ["projects", project, "secrets", secret, "versions", version] => {
                if let Some(override_version) = version_override {
                    if override_version != *version {
                        anyhow::bail!(
                            "GCP Secret Manager: path version `{version}` conflicts with query version `{override_version}`"
                        );
                    }
                }
                let version = clean_version(Some(version))?;
                Ok(format!(
                    "projects/{project}/secrets/{secret}/versions/{version}"
                ))
            }
            [secret] => {
                let project = self.inner.default_project_id.as_deref().ok_or_else(|| {
                    anyhow!(
                        "GCP Secret Manager: short reference `{secret}` requires `project_id`, GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT, or ADC project id"
                    )
                })?;
                let version = clean_version(version_override)?;
                Ok(format!(
                    "projects/{project}/secrets/{secret}/versions/{version}"
                ))
            }
            _ => anyhow::bail!(
                "GCP Secret Manager: path `{path}` must be `<secret>`, `projects/<project>/secrets/<secret>`, or `projects/<project>/secrets/<secret>/versions/<version>`"
            ),
        }
    }

    fn get_resolved(&self, path: &str, version_override: Option<&str>) -> Result<Option<String>> {
        let name = self.resolve_secret_name(path, version_override)?;
        if let Some(hit) = self.cache_hit(&name) {
            return Ok(Some(hit));
        }

        let token = self.inner.token_provider.access_token()?;
        let response =
            self.inner
                .transport
                .access_secret_version(&self.inner.endpoint, &name, &token)?;
        match response.status {
            200 => {
                let payload = decode_access_secret_response(&response.body, &name)?;
                self.cache_store(name, payload.clone());
                Ok(Some(payload))
            }
            404 => Ok(None),
            401 | 403 => Err(anyhow!(
                "GCP Secret Manager: cannot access {name} (HTTP {}): {}",
                response.status,
                gcp_error_detail(&response.body)
            )),
            status => Err(anyhow!(
                "GCP Secret Manager: AccessSecretVersion {name} failed (HTTP {status}): {}",
                gcp_error_detail(&response.body)
            )),
        }
    }

    fn cache_hit(&self, key: &str) -> Option<String> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.payload.clone());
            }
            cache.remove(key);
        }
        None
    }

    fn cache_store(&self, key: String, payload: String) {
        let mut cache = self.cache.lock();
        cache.insert(
            key,
            CacheEntry {
                payload,
                expires_at: Instant::now() + self.inner.cache_ttl,
            },
        );
    }

    /// Drop every cached entry. Tests use this to verify behaviour;
    /// production resets the cache by restarting the process.
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }
}

impl VaultBackend for GcpSecretManagerBackend {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.get_resolved(key, None)
    }

    fn get_ref(&self, reference: &VaultRef) -> Result<Option<String>> {
        self.get_resolved(&reference.path, reference.version.as_deref())
    }

    fn set(&self, _key: &str, _value: &str) -> Result<()> {
        anyhow::bail!(
            "GCP Secret Manager: write path is not supported; add secret versions through Google Secret Manager APIs or infrastructure automation"
        )
    }
}

trait GcpAccessTokenProvider: Send + Sync {
    fn access_token(&self) -> Result<String>;
    fn project_id(&self) -> Result<Option<String>>;
}

struct DefaultGcpTokenProvider {
    provider: Arc<dyn GcpAuthTokenProvider>,
    rt: Runtime,
}

impl GcpAccessTokenProvider for DefaultGcpTokenProvider {
    fn access_token(&self) -> Result<String> {
        let token = self
            .rt
            .block_on(self.provider.token(&[CLOUD_PLATFORM_SCOPE]))
            .context("GCP Secret Manager: failed to acquire access token")?;
        Ok(token.as_str().to_string())
    }

    fn project_id(&self) -> Result<Option<String>> {
        self.rt
            .block_on(self.provider.project_id())
            .map(|p| Some(p.to_string()))
            .context("GCP Secret Manager: failed to discover ADC project id")
    }
}

fn build_access_token_provider(
    auth: GcpSecretManagerAuth,
) -> Result<Arc<dyn GcpAccessTokenProvider>> {
    match auth {
        GcpSecretManagerAuth::ExternalAccountFile { path } => {
            if path.is_empty() {
                anyhow::bail!(
                    "GCP Secret Manager: external-account auth requires a non-empty `path`"
                );
            }
            Ok(Arc::new(ExternalAccountTokenProvider::from_file(path)?))
        }
        GcpSecretManagerAuth::ApplicationDefault => {
            if let Some(path) = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS") {
                if is_external_account_credentials_file(&path) {
                    return Ok(Arc::new(ExternalAccountTokenProvider::from_file(path)?));
                }
            }
            build_gcp_auth_provider(GcpSecretManagerAuth::ApplicationDefault)
        }
        other => build_gcp_auth_provider(other),
    }
}

fn build_gcp_auth_provider(auth: GcpSecretManagerAuth) -> Result<Arc<dyn GcpAccessTokenProvider>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("GCP Secret Manager: failed to build per-backend tokio runtime")?;

    let provider: Arc<dyn GcpAuthTokenProvider> = match auth {
        GcpSecretManagerAuth::ApplicationDefault => rt
            .block_on(gcp_auth::provider())
            .context("GCP Secret Manager: ADC provider construction failed")?,
        GcpSecretManagerAuth::ServiceAccountKeyFile { path } => {
            if path.is_empty() {
                anyhow::bail!(
                    "GCP Secret Manager: service-account file auth requires a non-empty `path`"
                );
            }
            Arc::new(
                CustomServiceAccount::from_file(path)
                    .context("GCP Secret Manager: loading service-account key file failed")?,
            )
        }
        GcpSecretManagerAuth::ServiceAccountKeyJson { json } => {
            if json.is_empty() {
                anyhow::bail!(
                    "GCP Secret Manager: service-account JSON auth requires non-empty `json`"
                );
            }
            Arc::new(
                CustomServiceAccount::from_json(&json)
                    .context("GCP Secret Manager: loading service-account key JSON failed")?,
            )
        }
        GcpSecretManagerAuth::ExternalAccountFile { .. } => {
            unreachable!("external-account auth is handled before gcp_auth provider construction")
        }
    };

    Ok(Arc::new(DefaultGcpTokenProvider { provider, rt }))
}

trait GcpSecretManagerTransport: Send + Sync {
    fn access_secret_version(
        &self,
        endpoint: &str,
        name: &str,
        bearer_token: &str,
    ) -> Result<GcpHttpResponse>;
}

struct GcpHttpResponse {
    status: u16,
    body: String,
}

struct UreqSecretManagerTransport;

impl GcpSecretManagerTransport for UreqSecretManagerTransport {
    fn access_secret_version(
        &self,
        endpoint: &str,
        name: &str,
        bearer_token: &str,
    ) -> Result<GcpHttpResponse> {
        let url = format!("{endpoint}/v1/{name}:access");
        let authorization = format!("Bearer {bearer_token}");
        ureq_response(
            "GCP Secret Manager: AccessSecretVersion transport error",
            ureq::get(&url).set("Authorization", &authorization).call(),
        )
        .with_context(|| format!("GCP Secret Manager: GET {url}"))
    }
}

#[derive(Debug, Deserialize)]
struct AccessSecretVersionResponse {
    payload: Option<AccessSecretPayload>,
}

#[derive(Debug, Deserialize)]
struct AccessSecretPayload {
    data: String,
}

fn decode_access_secret_response(body: &str, name: &str) -> Result<String> {
    let response: AccessSecretVersionResponse = serde_json::from_str(body).with_context(|| {
        format!("GCP Secret Manager: AccessSecretVersion {name} response was not JSON")
    })?;
    let data = response
        .payload
        .ok_or_else(|| {
            anyhow!("GCP Secret Manager: AccessSecretVersion {name} response missing `.payload`")
        })?
        .data;
    let mut decoded = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .with_context(|| {
            format!("GCP Secret Manager: AccessSecretVersion {name} payload was not valid base64")
        })?;
    let text = std::str::from_utf8(&decoded)
        .with_context(|| {
            format!("GCP Secret Manager: AccessSecretVersion {name} payload was not UTF-8")
        })?
        .to_string();
    decoded.fill(0);

    let secret = SecretString::new(&text);
    Ok(secret.expose().to_string())
}

fn clean_version(version: Option<&str>) -> Result<&str> {
    let version = version.unwrap_or("latest");
    if version.trim().is_empty() || version.contains('/') {
        anyhow::bail!("GCP Secret Manager: invalid secret version `{version}`");
    }
    Ok(version)
}

fn env_project_id() -> Option<String> {
    std::env::var("GOOGLE_CLOUD_PROJECT")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .or_else(|| {
            std::env::var("GCLOUD_PROJECT")
                .ok()
                .filter(|p| !p.trim().is_empty())
        })
}

fn body_excerpt(body: &str) -> String {
    const MAX: usize = 512;
    let trimmed = body.trim();
    if trimmed.len() <= MAX {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..MAX])
    }
}

/// Turn a GCP JSON error body into a readable error detail instead of dumping
/// the raw JSON. Returns GCP's `error.message`, and when the failure is a
/// disabled Secret Manager API (a common first-run trap that GCP reports as a
/// 403, not a 404) prefixes an actionable hint so the operator enables the API
/// rather than chasing an IAM permission that is not the problem. Falls back to
/// a short body excerpt when the body is not the expected shape.
fn gcp_error_detail(body: &str) -> String {
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        error: Option<ErrorDetail>,
    }
    #[derive(serde::Deserialize)]
    struct ErrorDetail {
        message: Option<String>,
        #[serde(default)]
        details: Vec<serde_json::Value>,
    }
    let Ok(ErrorBody {
        error: Some(detail),
    }) = serde_json::from_str::<ErrorBody>(body)
    else {
        return body_excerpt(body);
    };
    let message = detail.message.unwrap_or_default();
    let api_disabled = detail
        .details
        .iter()
        .any(|d| d.get("reason").and_then(|r| r.as_str()) == Some("SERVICE_DISABLED"))
        || message.contains("has not been used")
        || message.contains("it is disabled");
    if api_disabled {
        format!(
            "the Secret Manager API is not enabled for this project; enable it \
             (gcloud services enable secretmanager.googleapis.com) and retry. GCP said: {message}"
        )
    } else if message.is_empty() {
        body_excerpt(body)
    } else {
        message
    }
}

fn ureq_response(
    context: &'static str,
    result: Result<ureq::Response, ureq::Error>,
) -> Result<GcpHttpResponse> {
    match result {
        Ok(response) => response_to_http(response),
        Err(ureq::Error::Status(status, response)) => {
            response_to_http_with_status(status, response)
        }
        Err(e) => Err(anyhow!(e)).context(context),
    }
}

fn response_to_http(response: ureq::Response) -> Result<GcpHttpResponse> {
    let status = response.status();
    response_to_http_with_status(status, response)
}

fn response_to_http_with_status(status: u16, response: ureq::Response) -> Result<GcpHttpResponse> {
    let body = response
        .into_string()
        .context("GCP Secret Manager: response body could not be read as text")?;
    Ok(GcpHttpResponse { status, body })
}

#[derive(Debug)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

struct ExternalAccountTokenProvider {
    config: ExternalAccountConfig,
    cache: Mutex<Option<CachedAccessToken>>,
}

impl ExternalAccountTokenProvider {
    fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "GCP Secret Manager: reading external-account credentials at {}",
                path.as_ref().display()
            )
        })?;
        let config: ExternalAccountConfig = serde_json::from_str(&contents).with_context(|| {
            format!(
                "GCP Secret Manager: parsing external-account credentials at {}",
                path.as_ref().display()
            )
        })?;
        if config.credential_type != "external_account" {
            anyhow::bail!(
                "GCP Secret Manager: expected external-account credentials, found `{}`",
                config.credential_type
            );
        }
        Ok(Self {
            config,
            cache: Mutex::new(None),
        })
    }

    fn fetch_fresh_token(&self) -> Result<CachedAccessToken> {
        let subject_token = self.load_subject_token()?;
        let sts_token = self.exchange_subject_token(&subject_token)?;
        if let Some(url) = &self.config.service_account_impersonation_url {
            self.impersonate_service_account(url, &sts_token.token)
        } else {
            Ok(sts_token)
        }
    }

    fn load_subject_token(&self) -> Result<String> {
        let raw = match (
            self.config.credential_source.file.as_deref(),
            self.config.credential_source.url.as_deref(),
        ) {
            (Some(path), None) => std::fs::read_to_string(path).with_context(|| {
                format!("GCP Secret Manager: reading WIF subject token file {path}")
            })?,
            (None, Some(url)) => {
                let mut req = ureq::get(url);
                for (name, value) in &self.config.credential_source.headers {
                    req = req.set(name, value);
                }
                let response = ureq_response(
                    "GCP Secret Manager: WIF credential_source URL transport error",
                    req.call(),
                )
                .with_context(|| format!("GCP Secret Manager: GET WIF credential_source {url}"))?;
                if response.status != 200 {
                    anyhow::bail!(
                        "GCP Secret Manager: WIF credential_source URL {url} returned HTTP {}: {}",
                        response.status,
                        body_excerpt(&response.body)
                    );
                }
                response.body
            }
            (Some(_), Some(_)) => {
                anyhow::bail!(
                    "GCP Secret Manager: external-account credential_source must declare only one of `file` or `url`"
                );
            }
            (None, None) => {
                anyhow::bail!(
                    "GCP Secret Manager: external-account credential_source must declare `file` or `url`; AWS and executable sources are not supported by this backend"
                );
            }
        };

        match self.config.credential_source.format.kind.as_deref() {
            None | Some("text") => Ok(raw.trim().to_string()),
            Some("json") => {
                let value: serde_json::Value = serde_json::from_str(&raw).context(
                    "GCP Secret Manager: WIF subject token source declared JSON but was not JSON",
                )?;
                let field = self
                    .config
                    .credential_source
                    .format
                    .subject_token_field_name
                    .as_deref()
                    .ok_or_else(|| {
                        anyhow!(
                            "GCP Secret Manager: JSON WIF subject token source requires `subject_token_field_name`"
                        )
                    })?;
                value
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        anyhow!(
                            "GCP Secret Manager: JSON WIF subject token source missing string field `{field}`"
                        )
                    })
            }
            Some(kind) => {
                anyhow::bail!("GCP Secret Manager: unsupported WIF subject token format `{kind}`")
            }
        }
    }

    fn exchange_subject_token(&self, subject_token: &str) -> Result<CachedAccessToken> {
        let scope = CLOUD_PLATFORM_SCOPE.to_string();
        let form = [
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("audience", self.config.audience.as_str()),
            ("requested_token_type", ACCESS_TOKEN_TYPE),
            (
                "subject_token_type",
                self.config.subject_token_type.as_str(),
            ),
            ("subject_token", subject_token),
            ("scope", scope.as_str()),
        ];
        let response = ureq_response(
            "GCP Secret Manager: WIF token exchange transport error",
            ureq::post(&self.config.token_url).send_form(&form),
        )
        .with_context(|| {
            format!(
                "GCP Secret Manager: POST WIF token exchange {}",
                self.config.token_url
            )
        })?;
        if response.status != 200 {
            anyhow::bail!(
                "GCP Secret Manager: WIF token exchange returned HTTP {}: {}",
                response.status,
                body_excerpt(&response.body)
            );
        }
        let token: StsTokenResponse = serde_json::from_str(&response.body)
            .context("GCP Secret Manager: WIF token exchange response was not JSON")?;
        if token.access_token.is_empty() {
            anyhow::bail!("GCP Secret Manager: WIF token exchange returned an empty access token");
        }
        Ok(CachedAccessToken {
            token: token.access_token,
            expires_at: Instant::now()
                + Duration::from_secs(token.expires_in.unwrap_or(3600).saturating_sub(30)),
        })
    }

    fn impersonate_service_account(
        &self,
        url: &str,
        federated_token: &str,
    ) -> Result<CachedAccessToken> {
        let authorization = format!("Bearer {federated_token}");
        let body = serde_json::json!({
            "scope": [CLOUD_PLATFORM_SCOPE],
            "lifetime": "3600s",
        });
        let response = ureq_response(
            "GCP Secret Manager: service-account impersonation transport error",
            ureq::post(url)
                .set("Authorization", &authorization)
                .send_json(body),
        )
        .with_context(|| format!("GCP Secret Manager: POST service-account impersonation {url}"))?;
        if response.status != 200 {
            anyhow::bail!(
                "GCP Secret Manager: service-account impersonation returned HTTP {}: {}",
                response.status,
                body_excerpt(&response.body)
            );
        }
        let token: ImpersonationResponse = serde_json::from_str(&response.body)
            .context("GCP Secret Manager: service-account impersonation response was not JSON")?;
        if token.access_token.is_empty() {
            anyhow::bail!(
                "GCP Secret Manager: service-account impersonation returned an empty access token"
            );
        }
        Ok(CachedAccessToken {
            token: token.access_token,
            expires_at: Instant::now() + Duration::from_secs(3570),
        })
    }
}

impl GcpAccessTokenProvider for ExternalAccountTokenProvider {
    fn access_token(&self) -> Result<String> {
        let now = Instant::now();
        {
            let cache = self.cache.lock();
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > now + Duration::from_secs(30) {
                    return Ok(cached.token.clone());
                }
            }
        }

        let fresh = self.fetch_fresh_token()?;
        let token = fresh.token.clone();
        *self.cache.lock() = Some(fresh);
        Ok(token)
    }

    fn project_id(&self) -> Result<Option<String>> {
        Ok(env_project_id())
    }
}

#[derive(Debug, Deserialize)]
struct ExternalAccountConfig {
    #[serde(rename = "type")]
    credential_type: String,
    audience: String,
    subject_token_type: String,
    token_url: String,
    #[serde(default)]
    service_account_impersonation_url: Option<String>,
    credential_source: ExternalCredentialSource,
}

#[derive(Debug, Deserialize)]
struct ExternalCredentialSource {
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    format: ExternalCredentialFormat,
}

#[derive(Debug, Default, Deserialize)]
struct ExternalCredentialFormat {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    subject_token_field_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StsTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ImpersonationResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
}

fn is_external_account_credentials_file(path: impl AsRef<OsStr>) -> bool {
    let path = PathBuf::from(path.as_ref());
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };
    value.get("type").and_then(serde_json::Value::as_str) == Some("external_account")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::manager::VaultManager;
    use crate::vault_ref::VaultProviderType;

    #[derive(Default)]
    struct MockTokenProvider {
        token: String,
        project_id: Option<String>,
        token_calls: AtomicUsize,
        project_calls: AtomicUsize,
    }

    impl MockTokenProvider {
        fn new(token: &str, project_id: Option<&str>) -> Self {
            Self {
                token: token.to_string(),
                project_id: project_id.map(str::to_string),
                token_calls: AtomicUsize::new(0),
                project_calls: AtomicUsize::new(0),
            }
        }
    }

    impl GcpAccessTokenProvider for MockTokenProvider {
        fn access_token(&self) -> Result<String> {
            self.token_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.token.clone())
        }

        fn project_id(&self) -> Result<Option<String>> {
            self.project_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.project_id.clone())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedAccess {
        endpoint: String,
        name: String,
        bearer_token: String,
    }

    #[derive(Default)]
    struct MockSecretManagerTransport {
        requests: Mutex<Vec<RecordedAccess>>,
        responses: Mutex<Vec<GcpHttpResponse>>,
    }

    impl MockSecretManagerTransport {
        fn with_response(status: u16, body: impl Into<String>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(vec![GcpHttpResponse {
                    status,
                    body: body.into(),
                }]),
            }
        }

        fn requests(&self) -> Vec<RecordedAccess> {
            self.requests.lock().clone()
        }
    }

    impl GcpSecretManagerTransport for MockSecretManagerTransport {
        fn access_secret_version(
            &self,
            endpoint: &str,
            name: &str,
            bearer_token: &str,
        ) -> Result<GcpHttpResponse> {
            self.requests.lock().push(RecordedAccess {
                endpoint: endpoint.to_string(),
                name: name.to_string(),
                bearer_token: bearer_token.to_string(),
            });
            self.responses
                .lock()
                .pop()
                .ok_or_else(|| anyhow!("mock response queue exhausted"))
        }
    }

    fn encoded_payload(value: &str) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        format!(r#"{{"payload":{{"data":"{encoded}"}}}}"#)
    }

    fn test_cfg(project_id: Option<&str>) -> GcpSecretManagerConfig {
        GcpSecretManagerConfig {
            project_id: project_id.map(str::to_string),
            endpoint: Some("https://secretmanager.test".to_string()),
            auth: GcpSecretManagerAuth::ApplicationDefault,
            cache_ttl_secs: Some(60),
        }
    }

    fn backend(
        project_id: Option<&str>,
        token_provider: Arc<MockTokenProvider>,
        transport: Arc<MockSecretManagerTransport>,
    ) -> GcpSecretManagerBackend {
        GcpSecretManagerBackend::new_for_test(test_cfg(project_id), token_provider, transport)
            .unwrap()
    }

    #[test]
    fn resolves_full_secret_version_path() {
        let b = backend(
            None,
            Arc::new(MockTokenProvider::new("token", None)),
            Arc::new(MockSecretManagerTransport::default()),
        );

        assert_eq!(
            b.resolve_secret_name("projects/acme/secrets/openai/versions/7", None)
                .unwrap(),
            "projects/acme/secrets/openai/versions/7"
        );
    }

    #[test]
    fn resolves_full_secret_path_with_latest_default() {
        let b = backend(
            None,
            Arc::new(MockTokenProvider::new("token", None)),
            Arc::new(MockSecretManagerTransport::default()),
        );

        assert_eq!(
            b.resolve_secret_name("projects/acme/secrets/openai", None)
                .unwrap(),
            "projects/acme/secrets/openai/versions/latest"
        );
    }

    #[test]
    fn resolves_short_secret_from_config_project() {
        let b = backend(
            Some("configured-project"),
            Arc::new(MockTokenProvider::new("token", None)),
            Arc::new(MockSecretManagerTransport::default()),
        );

        assert_eq!(
            b.resolve_secret_name("openai", Some("5")).unwrap(),
            "projects/configured-project/secrets/openai/versions/5"
        );
    }

    #[test]
    fn resolves_short_secret_from_adc_project() {
        let token = Arc::new(MockTokenProvider::new("token", Some("adc-project")));
        let b = backend(
            None,
            token.clone(),
            Arc::new(MockSecretManagerTransport::default()),
        );

        assert_eq!(
            b.resolve_secret_name("openai", None).unwrap(),
            "projects/adc-project/secrets/openai/versions/latest"
        );
        assert_eq!(token.project_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn access_secret_version_decodes_and_caches_payload() {
        let token = Arc::new(MockTokenProvider::new("test-token", Some("acme")));
        let transport = Arc::new(MockSecretManagerTransport::with_response(
            200,
            encoded_payload("sk-test"),
        ));
        let b = backend(None, token.clone(), transport.clone());

        assert_eq!(b.get("openai").unwrap(), Some("sk-test".to_string()));
        assert_eq!(b.get("openai").unwrap(), Some("sk-test".to_string()));
        assert_eq!(token.token_calls.load(Ordering::SeqCst), 1);

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].name,
            "projects/acme/secrets/openai/versions/latest"
        );
        assert_eq!(requests[0].bearer_token, "test-token");
    }

    #[test]
    fn manager_passes_version_to_gcp_backend_and_extracts_json_key() {
        let token = Arc::new(MockTokenProvider::new("test-token", Some("acme")));
        let transport = Arc::new(MockSecretManagerTransport::with_response(
            200,
            encoded_payload(r#"{"api_key":"sk-gcp","limit":5}"#),
        ));
        let b = backend(None, token, transport.clone());
        let mut mgr = VaultManager::new();
        mgr.register_backend(VaultProviderType::GcpSecretManager, "primary", Box::new(b));

        let reference = VaultRef::parse("gcpsm://primary/openai?version=7&key=api_key").unwrap();
        assert_eq!(
            mgr.get_from_ref(&reference).unwrap(),
            Some("sk-gcp".to_string())
        );

        let requests = transport.requests();
        assert_eq!(requests[0].name, "projects/acme/secrets/openai/versions/7");
    }

    #[test]
    fn not_found_status_returns_none() {
        let b = backend(
            Some("acme"),
            Arc::new(MockTokenProvider::new("token", None)),
            Arc::new(MockSecretManagerTransport::with_response(404, "{}")),
        );

        assert_eq!(b.get("missing").unwrap(), None);
    }

    #[test]
    fn denied_status_is_classifiable() {
        let b = backend(
            Some("acme"),
            Arc::new(MockTokenProvider::new("token", None)),
            Arc::new(MockSecretManagerTransport::with_response(
                403,
                r#"{"error":{"code":403,"message":"Permission 'secretmanager.versions.access' denied on resource.","status":"PERMISSION_DENIED"}}"#,
            )),
        );

        let err = b.get("denied").expect_err("403 should error");
        let msg = format!("{err:#}").to_ascii_lowercase();
        // The 403 surfaces as an access failure carrying GCP's own message,
        // not a raw JSON dump.
        assert!(msg.contains("cannot access"), "got: {msg}");
        assert!(
            msg.contains("permission") && msg.contains("denied"),
            "got: {msg}"
        );
        assert!(!msg.contains('{'), "should not dump raw JSON: {msg}");
    }

    #[test]
    fn rejects_invalid_path_segments() {
        let b = backend(
            Some("acme"),
            Arc::new(MockTokenProvider::new("token", None)),
            Arc::new(MockSecretManagerTransport::default()),
        );

        assert!(b.resolve_secret_name("../other", None).is_err());
        assert!(b
            .resolve_secret_name("projects/acme/secrets/s/versions/..", None)
            .is_err());
    }

    #[test]
    fn external_account_subject_token_reads_text_file() {
        let subject = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(subject.path(), "subject-token\n").unwrap();
        let config = ExternalAccountConfig {
            credential_type: "external_account".to_string(),
            audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/provider".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            token_url: "https://sts.googleapis.com/v1/token".to_string(),
            service_account_impersonation_url: None,
            credential_source: ExternalCredentialSource {
                file: Some(subject.path().display().to_string()),
                url: None,
                headers: HashMap::new(),
                format: ExternalCredentialFormat {
                    kind: Some("text".to_string()),
                    subject_token_field_name: None,
                },
            },
        };
        let provider = ExternalAccountTokenProvider {
            config,
            cache: Mutex::new(None),
        };

        assert_eq!(provider.load_subject_token().unwrap(), "subject-token");
    }

    #[test]
    fn external_account_subject_token_reads_json_field() {
        let subject = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(subject.path(), r#"{"id_token":"subject-token"}"#).unwrap();
        let config = ExternalAccountConfig {
            credential_type: "external_account".to_string(),
            audience: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/provider".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            token_url: "https://sts.googleapis.com/v1/token".to_string(),
            service_account_impersonation_url: None,
            credential_source: ExternalCredentialSource {
                file: Some(subject.path().display().to_string()),
                url: None,
                headers: HashMap::new(),
                format: ExternalCredentialFormat {
                    kind: Some("json".to_string()),
                    subject_token_field_name: Some("id_token".to_string()),
                },
            },
        };
        let provider = ExternalAccountTokenProvider {
            config,
            cache: Mutex::new(None),
        };

        assert_eq!(provider.load_subject_token().unwrap(), "subject-token");
    }

    #[test]
    fn gcp_error_detail_extracts_message_not_raw_json() {
        let body = r#"{"error":{"code":403,"message":"Permission 'secretmanager.versions.access' denied on resource.","status":"PERMISSION_DENIED"}}"#;
        let out = gcp_error_detail(body);
        assert_eq!(
            out,
            "Permission 'secretmanager.versions.access' denied on resource."
        );
        assert!(!out.contains('{'), "should not dump raw JSON");
    }

    #[test]
    fn gcp_error_detail_flags_disabled_api_by_reason() {
        let body = r#"{"error":{"code":403,"message":"Secret Manager API has not been used in project foo before or it is disabled.","status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED"}]}}"#;
        let out = gcp_error_detail(body);
        assert!(
            out.contains("the Secret Manager API is not enabled"),
            "got: {out}"
        );
        assert!(out.contains("gcloud services enable secretmanager.googleapis.com"));
    }

    #[test]
    fn gcp_error_detail_flags_disabled_api_by_message() {
        // Some responses omit the details[] ErrorInfo; fall back to the text.
        let body = r#"{"error":{"code":403,"message":"Cloud Secret Manager API has not been used in project 42."}}"#;
        assert!(gcp_error_detail(body).contains("not enabled"));
    }

    #[test]
    fn gcp_error_detail_falls_back_on_non_json() {
        let body = "upstream proxy error, not json";
        assert_eq!(gcp_error_detail(body), "upstream proxy error, not json");
    }
}
