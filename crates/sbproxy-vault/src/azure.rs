// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Azure Key Vault backend.
//!
//! Implements [`crate::manager::VaultBackend`] against Azure Key
//! Vault's `GetSecret` REST API. The backend keeps the same
//! synchronous trait surface as the other vault backends: token
//! acquisition and HTTP calls run inside the caller's blocking
//! resolver path.
//!
//! ## Scope
//!
//! * Auth methods:
//!   - Managed identity, system-assigned or user-assigned. App
//!     Service / Container Apps identity endpoints are used when the
//!     `IDENTITY_ENDPOINT` / `IDENTITY_HEADER` environment variables
//!     are present; otherwise the IMDS token endpoint is used.
//!   - Service-principal client credentials against Microsoft Entra
//!     ID, with an optional authority override for sovereign clouds.
//!   - The logged-in Azure CLI (`az account get-access-token`) for
//!     local development.
//! * Path shapes:
//!   - `<secret-name>` with the parsed `?version=` or the current
//!     version.
//!   - `<secret-name>/<version>`.
//!   - `secrets/<secret-name>[/<version>]`, matching the Key Vault
//!     resource URL.
//! * In-process TTL cache (5 minutes by default, configurable per
//!   backend).
//! * Text secret payloads only; Key Vault secrets are strings already,
//!   no transport encoding applies.
//!
//! The token audience is derived from the vault URL's DNS suffix, so
//! sovereign-cloud vaults (`*.vault.azure.cn`,
//! `*.vault.usgovcloudapi.net`) request matching tokens without extra
//! configuration.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::manager::VaultBackend;
use crate::secret_string::SecretString;
use crate::vault_ref::VaultRef;

/// Default TTL on a cached Key Vault value.
pub const DEFAULT_AZURE_CACHE_TTL: Duration = Duration::from_secs(300);

const KEY_VAULT_API_VERSION: &str = "7.4";
const DEFAULT_KEY_VAULT_RESOURCE: &str = "https://vault.azure.net";
const DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com";
const IMDS_TOKEN_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
const IMDS_API_VERSION: &str = "2018-02-01";
const APP_SERVICE_API_VERSION: &str = "2019-08-01";
const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;
const TOKEN_EXPIRY_SKEW_SECS: u64 = 30;

/// Read-only Azure Key Vault client.
pub struct AzureKeyVaultBackend {
    inner: BackendInner,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct BackendInner {
    token_provider: Arc<dyn AzureAccessTokenProvider>,
    transport: Arc<dyn AzureKeyVaultTransport>,
    vault_url: String,
    cache_ttl: Duration,
}

struct CacheEntry {
    payload: String,
    expires_at: Instant,
}

/// Operator-facing Azure Key Vault config.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct AzureKeyVaultConfig {
    /// Key Vault URL, e.g. `https://acme-prod.vault.azure.net`.
    pub vault_url: String,
    /// Authentication method. Defaults to system-assigned managed
    /// identity.
    #[serde(default)]
    pub auth: AzureKeyVaultAuth,
    /// Cache TTL in seconds for successful reads. Defaults to
    /// [`DEFAULT_AZURE_CACHE_TTL`].
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,
}

/// Operator-facing Azure authentication method.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AzureKeyVaultAuth {
    /// System-assigned managed identity (default). Uses the App
    /// Service identity endpoint when `IDENTITY_ENDPOINT` /
    /// `IDENTITY_HEADER` are set, the IMDS endpoint otherwise.
    #[default]
    ManagedIdentity,
    /// User-assigned managed identity, selected by client id.
    UserAssignedIdentity {
        /// Client id of the user-assigned identity.
        client_id: String,
    },
    /// Service-principal client credentials.
    ServicePrincipal {
        /// Microsoft Entra tenant id.
        tenant_id: String,
        /// App registration client id.
        client_id: String,
        /// App registration client secret.
        client_secret: String,
        /// Authority host override for sovereign clouds. Defaults to
        /// `https://login.microsoftonline.com`.
        #[serde(default)]
        authority: Option<String>,
    },
    /// The logged-in Azure CLI (`az account get-access-token`).
    /// Intended for local development, not production deployments.
    AzureCli,
}

impl AzureKeyVaultBackend {
    /// Build a backend from operator config.
    pub fn new(cfg: AzureKeyVaultConfig) -> Result<Self> {
        let token_provider = build_access_token_provider(&cfg)?;
        Self::with_parts(cfg, token_provider, Arc::new(UreqKeyVaultTransport))
    }

    fn with_parts(
        cfg: AzureKeyVaultConfig,
        token_provider: Arc<dyn AzureAccessTokenProvider>,
        transport: Arc<dyn AzureKeyVaultTransport>,
    ) -> Result<Self> {
        let vault_url = cfg.vault_url.trim_end_matches('/').to_string();
        if vault_url.is_empty() {
            anyhow::bail!("Azure Key Vault: `vault_url` must not be empty");
        }
        if !vault_url.starts_with("https://") {
            anyhow::bail!(
                "Azure Key Vault: `vault_url` must be an https URL such as \
                 https://<vault-name>.vault.azure.net; Key Vault is https-only, and a \
                 plaintext URL would expose the bearer token and secret material on the wire"
            );
        }

        Ok(Self {
            inner: BackendInner {
                token_provider,
                transport,
                vault_url,
                cache_ttl: cfg
                    .cache_ttl_secs
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_AZURE_CACHE_TTL),
            },
            cache: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    fn new_for_test(
        cfg: AzureKeyVaultConfig,
        token_provider: Arc<dyn AzureAccessTokenProvider>,
        transport: Arc<dyn AzureKeyVaultTransport>,
    ) -> Result<Self> {
        Self::with_parts(cfg, token_provider, transport)
    }

    fn get_resolved(&self, path: &str, version_override: Option<&str>) -> Result<Option<String>> {
        let (name, version) = resolve_secret_ref(path, version_override)?;
        let cache_key = match version.as_deref() {
            Some(v) => format!("{name}/{v}"),
            None => format!("{name}/latest"),
        };
        if let Some(hit) = self.cache_hit(&cache_key) {
            return Ok(Some(hit));
        }

        let token = self.inner.token_provider.access_token()?;
        let response = self.inner.transport.get_secret(
            &self.inner.vault_url,
            &name,
            version.as_deref(),
            &token,
        )?;
        match response.status {
            200 => {
                let payload = decode_get_secret_response(&response.body, &name)?;
                self.cache_store(cache_key, payload.clone());
                Ok(Some(payload))
            }
            404 => Ok(None),
            401 | 403 => Err(anyhow!(
                "Azure Key Vault: cannot access secret {name} (HTTP {}): {}",
                response.status,
                azure_error_detail(&response.body)
            )),
            status => Err(anyhow!(
                "Azure Key Vault: GetSecret {name} failed (HTTP {status}): {}",
                azure_error_detail(&response.body)
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

impl VaultBackend for AzureKeyVaultBackend {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.get_resolved(key, None)
    }

    fn get_ref(&self, reference: &VaultRef) -> Result<Option<String>> {
        self.get_resolved(&reference.path, reference.version.as_deref())
    }

    fn set(&self, _key: &str, _value: &str) -> Result<()> {
        anyhow::bail!(
            "Azure Key Vault: write path is not supported; add secret versions through Azure Key Vault APIs or infrastructure automation"
        )
    }
}

/// Resolve a reference path plus optional query version into a Key
/// Vault secret name and optional version pin. The `latest` version
/// spelling used by the other cloud backends maps to no pin: Key
/// Vault serves the current version when the version segment is
/// omitted.
fn resolve_secret_ref(
    path: &str,
    version_override: Option<&str>,
) -> Result<(String, Option<String>)> {
    let cleaned = path.trim_matches('/');
    if cleaned.is_empty() {
        anyhow::bail!("Azure Key Vault: empty path after normalisation");
    }
    if cleaned
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        anyhow::bail!("Azure Key Vault: path `{path}` contains an invalid segment");
    }

    let parts: Vec<&str> = cleaned.split('/').collect();
    let (name, path_version) = match parts.as_slice() {
        ["secrets", name] => (*name, None),
        ["secrets", name, version] => (*name, Some(*version)),
        [name] => (*name, None),
        [name, version] => (*name, Some(*version)),
        _ => anyhow::bail!(
            "Azure Key Vault: path `{path}` must be `<secret>`, `<secret>/<version>`, or `secrets/<secret>[/<version>]`"
        ),
    };

    if let (Some(path_version), Some(override_version)) = (path_version, version_override) {
        if override_version != path_version {
            anyhow::bail!(
                "Azure Key Vault: path version `{path_version}` conflicts with query version `{override_version}`"
            );
        }
    }

    validate_secret_name(name)?;
    let version = clean_version(path_version.or(version_override))?;
    Ok((name.to_string(), version))
}

/// Key Vault secret names are letters, digits, and dashes (1 to 127
/// characters). Rejecting anything else here surfaces typos at
/// resolve time with the reference quoted, before an HTTP call.
fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 127
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        anyhow::bail!(
            "Azure Key Vault: invalid secret name `{name}`; names use letters, digits, and dashes"
        );
    }
    Ok(())
}

fn clean_version(version: Option<&str>) -> Result<Option<String>> {
    let Some(version) = version else {
        return Ok(None);
    };
    // Parity with the `?version=latest` spelling the awssm / gcpsm
    // references use for the current version.
    if version == "latest" {
        return Ok(None);
    }
    if version.trim().is_empty() || !version.chars().all(|c| c.is_ascii_alphanumeric()) {
        anyhow::bail!("Azure Key Vault: invalid secret version `{version}`");
    }
    Ok(Some(version.to_string()))
}

/// Derive the token audience from the vault URL's DNS suffix, so a
/// sovereign-cloud vault such as `acme.vault.azure.cn` requests a
/// `https://vault.azure.cn` token. Hosts that do not look like a Key
/// Vault DNS name (local test servers) fall back to the public-cloud
/// resource.
fn token_resource_for_vault_url(vault_url: &str) -> String {
    let host = vault_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split(['/', ':']).next().unwrap_or("");
    let mut labels = host.split('.');
    let first = labels.next();
    let suffix: Vec<&str> = labels.collect();
    if first.is_some_and(|f| !f.is_empty())
        && suffix.len() >= 2
        && suffix[0].eq_ignore_ascii_case("vault")
    {
        format!("https://{}", suffix.join("."))
    } else {
        DEFAULT_KEY_VAULT_RESOURCE.to_string()
    }
}

trait AzureAccessTokenProvider: Send + Sync {
    fn access_token(&self) -> Result<String>;
}

trait AzureKeyVaultTransport: Send + Sync {
    fn get_secret(
        &self,
        vault_url: &str,
        name: &str,
        version: Option<&str>,
        bearer_token: &str,
    ) -> Result<AzureHttpResponse>;
}

struct AzureHttpResponse {
    status: u16,
    body: String,
}

struct UreqKeyVaultTransport;

impl AzureKeyVaultTransport for UreqKeyVaultTransport {
    fn get_secret(
        &self,
        vault_url: &str,
        name: &str,
        version: Option<&str>,
        bearer_token: &str,
    ) -> Result<AzureHttpResponse> {
        let url = secret_url(vault_url, name, version);
        let authorization = format!("Bearer {bearer_token}");
        azure_http_response(
            "Azure Key Vault: GetSecret transport error",
            ureq::get(&url).set("Authorization", &authorization).call(),
        )
        .with_context(|| format!("Azure Key Vault: GET {url}"))
    }
}

fn secret_url(vault_url: &str, name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) => {
            format!("{vault_url}/secrets/{name}/{version}?api-version={KEY_VAULT_API_VERSION}")
        }
        None => format!("{vault_url}/secrets/{name}?api-version={KEY_VAULT_API_VERSION}"),
    }
}

#[derive(Debug, Deserialize)]
struct GetSecretResponse {
    value: Option<String>,
}

fn decode_get_secret_response(body: &str, name: &str) -> Result<String> {
    let response: GetSecretResponse = serde_json::from_str(body)
        .with_context(|| format!("Azure Key Vault: GetSecret {name} response was not JSON"))?;
    let value = response
        .value
        .ok_or_else(|| anyhow!("Azure Key Vault: GetSecret {name} response missing `.value`"))?;

    let secret = SecretString::new(&value);
    let mut raw = value.into_bytes();
    raw.fill(0);
    Ok(secret.expose().to_string())
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

/// Turn an Azure JSON error body into a readable error detail instead
/// of dumping the raw JSON. Returns Key Vault's `error.code` and
/// `error.message`; falls back to a short body excerpt when the body
/// is not the expected shape.
fn azure_error_detail(body: &str) -> String {
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        error: Option<ErrorDetail>,
    }
    #[derive(serde::Deserialize)]
    struct ErrorDetail {
        code: Option<String>,
        message: Option<String>,
    }
    let Ok(ErrorBody {
        error: Some(detail),
    }) = serde_json::from_str::<ErrorBody>(body)
    else {
        return body_excerpt(body);
    };
    match (
        detail.code.filter(|c| !c.is_empty()),
        detail.message.filter(|m| !m.is_empty()),
    ) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code,
        (None, Some(message)) => message,
        (None, None) => body_excerpt(body),
    }
}

fn azure_http_response(
    context: &'static str,
    result: Result<ureq::Response, ureq::Error>,
) -> Result<AzureHttpResponse> {
    match result {
        Ok(response) => response_to_http(response),
        Err(ureq::Error::Status(status, response)) => {
            response_to_http_with_status(status, response)
        }
        Err(e) => Err(anyhow!(e)).context(context),
    }
}

fn response_to_http(response: ureq::Response) -> Result<AzureHttpResponse> {
    let status = response.status();
    response_to_http_with_status(status, response)
}

fn response_to_http_with_status(
    status: u16,
    response: ureq::Response,
) -> Result<AzureHttpResponse> {
    let body = response
        .into_string()
        .context("Azure Key Vault: response body could not be read as text")?;
    Ok(AzureHttpResponse { status, body })
}

// --- token acquisition -------------------------------------------------

#[derive(Debug)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

/// One token fetch against an identity source. Implementations do the
/// network or process call; [`CachedTokenProvider`] adds the shared
/// expiry cache on top.
trait TokenFetch: Send + Sync {
    fn fetch_fresh_token(&self) -> Result<CachedAccessToken>;
}

struct CachedTokenProvider<F: TokenFetch> {
    fetcher: F,
    cache: Mutex<Option<CachedAccessToken>>,
}

impl<F: TokenFetch> CachedTokenProvider<F> {
    fn new(fetcher: F) -> Self {
        Self {
            fetcher,
            cache: Mutex::new(None),
        }
    }
}

impl<F: TokenFetch> AzureAccessTokenProvider for CachedTokenProvider<F> {
    fn access_token(&self) -> Result<String> {
        let now = Instant::now();
        {
            let cache = self.cache.lock();
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > now {
                    return Ok(cached.token.clone());
                }
            }
        }

        let fresh = self.fetcher.fetch_fresh_token()?;
        let token = fresh.token.clone();
        *self.cache.lock() = Some(fresh);
        Ok(token)
    }
}

fn build_access_token_provider(
    cfg: &AzureKeyVaultConfig,
) -> Result<Arc<dyn AzureAccessTokenProvider>> {
    let resource = token_resource_for_vault_url(&cfg.vault_url);
    match &cfg.auth {
        AzureKeyVaultAuth::ManagedIdentity => Ok(Arc::new(CachedTokenProvider::new(
            ManagedIdentityFetcher::from_environment(None, resource),
        ))),
        AzureKeyVaultAuth::UserAssignedIdentity { client_id } => {
            if client_id.is_empty() {
                anyhow::bail!(
                    "Azure Key Vault: user-assigned identity auth requires a non-empty `client_id`"
                );
            }
            Ok(Arc::new(CachedTokenProvider::new(
                ManagedIdentityFetcher::from_environment(Some(client_id.clone()), resource),
            )))
        }
        AzureKeyVaultAuth::ServicePrincipal {
            tenant_id,
            client_id,
            client_secret,
            authority,
        } => {
            if tenant_id.is_empty() || client_id.is_empty() || client_secret.is_empty() {
                anyhow::bail!(
                    "Azure Key Vault: service-principal auth requires `tenant_id`, `client_id`, and `client_secret`"
                );
            }
            Ok(Arc::new(CachedTokenProvider::new(
                ServicePrincipalFetcher {
                    token_url: service_principal_token_url(authority.as_deref(), tenant_id),
                    client_id: client_id.clone(),
                    client_secret: SecretString::new(client_secret),
                    scope: format!("{resource}/.default"),
                },
            )))
        }
        AzureKeyVaultAuth::AzureCli => Ok(Arc::new(CachedTokenProvider::new(AzureCliFetcher {
            resource,
        }))),
    }
}

/// Where a managed-identity token comes from.
enum ManagedIdentitySource {
    /// App Service / Functions / Container Apps identity endpoint,
    /// authenticated with the platform-injected header.
    AppService {
        endpoint: String,
        header_value: String,
    },
    /// The instance metadata service on Azure VMs and VM scale sets.
    Imds { endpoint: String },
}

struct ManagedIdentityFetcher {
    source: ManagedIdentitySource,
    client_id: Option<String>,
    resource: String,
}

impl ManagedIdentityFetcher {
    fn from_environment(client_id: Option<String>, resource: String) -> Self {
        Self {
            source: managed_identity_source(
                std::env::var("IDENTITY_ENDPOINT").ok(),
                std::env::var("IDENTITY_HEADER").ok(),
            ),
            client_id,
            resource,
        }
    }
}

fn managed_identity_source(
    endpoint: Option<String>,
    header: Option<String>,
) -> ManagedIdentitySource {
    match (endpoint, header) {
        (Some(endpoint), Some(header_value))
            if !endpoint.trim().is_empty() && !header_value.trim().is_empty() =>
        {
            ManagedIdentitySource::AppService {
                endpoint,
                header_value,
            }
        }
        _ => ManagedIdentitySource::Imds {
            endpoint: IMDS_TOKEN_ENDPOINT.to_string(),
        },
    }
}

/// Agent for managed-identity token endpoints with redirect-following
/// disabled. A redirect from IMDS or the App Service identity endpoint
/// means the request has left the trusted metadata plane (Microsoft's
/// guidance is to treat it as a hijack attempt), so the fetch must fail
/// there rather than follow.
fn no_redirect_agent() -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(0).build()
}

impl TokenFetch for ManagedIdentityFetcher {
    fn fetch_fresh_token(&self) -> Result<CachedAccessToken> {
        let agent = no_redirect_agent();
        let response = match &self.source {
            ManagedIdentitySource::Imds { endpoint } => {
                let mut req = agent
                    .get(endpoint)
                    .set("Metadata", "true")
                    .query("api-version", IMDS_API_VERSION)
                    .query("resource", &self.resource);
                if let Some(client_id) = &self.client_id {
                    req = req.query("client_id", client_id);
                }
                azure_http_response(
                    "Azure Key Vault: IMDS managed-identity transport error",
                    req.call(),
                )
                .with_context(|| {
                    format!("Azure Key Vault: GET managed-identity token {endpoint}")
                })?
            }
            ManagedIdentitySource::AppService {
                endpoint,
                header_value,
            } => {
                let mut req = agent
                    .get(endpoint)
                    .set("X-IDENTITY-HEADER", header_value)
                    .query("api-version", APP_SERVICE_API_VERSION)
                    .query("resource", &self.resource);
                if let Some(client_id) = &self.client_id {
                    req = req.query("client_id", client_id);
                }
                azure_http_response(
                    "Azure Key Vault: App Service managed-identity transport error",
                    req.call(),
                )
                .with_context(|| {
                    format!("Azure Key Vault: GET managed-identity token {endpoint}")
                })?
            }
        };
        if response.status != 200 {
            anyhow::bail!(
                "Azure Key Vault: managed-identity token request returned HTTP {}: {}",
                response.status,
                azure_error_detail(&response.body)
            );
        }
        parse_token_response("Azure Key Vault: managed-identity", &response.body)
    }
}

struct ServicePrincipalFetcher {
    token_url: String,
    client_id: String,
    client_secret: SecretString,
    scope: String,
}

impl TokenFetch for ServicePrincipalFetcher {
    fn fetch_fresh_token(&self) -> Result<CachedAccessToken> {
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose()),
            ("scope", self.scope.as_str()),
        ];
        let response = azure_http_response(
            "Azure Key Vault: service-principal token transport error",
            ureq::post(&self.token_url).send_form(&form),
        )
        .with_context(|| {
            format!(
                "Azure Key Vault: POST service-principal token {}",
                self.token_url
            )
        })?;
        if response.status != 200 {
            anyhow::bail!(
                "Azure Key Vault: service-principal token request returned HTTP {}: {}",
                response.status,
                aad_error_detail(&response.body)
            );
        }
        parse_token_response("Azure Key Vault: service-principal", &response.body)
    }
}

fn service_principal_token_url(authority: Option<&str>, tenant_id: &str) -> String {
    let authority = authority.unwrap_or(DEFAULT_AUTHORITY).trim_end_matches('/');
    format!("{authority}/{tenant_id}/oauth2/v2.0/token")
}

/// Microsoft Entra token-endpoint errors use `error` /
/// `error_description` fields rather than the Key Vault `error`
/// object shape.
fn aad_error_detail(body: &str) -> String {
    #[derive(serde::Deserialize)]
    struct AadError {
        error: Option<String>,
        error_description: Option<String>,
    }
    let Ok(detail) = serde_json::from_str::<AadError>(body) else {
        return body_excerpt(body);
    };
    match (
        detail.error.filter(|e| !e.is_empty()),
        detail.error_description.filter(|d| !d.is_empty()),
    ) {
        (Some(error), Some(description)) => format!("{error}: {description}"),
        (Some(error), None) => error,
        (None, Some(description)) => description,
        (None, None) => body_excerpt(body),
    }
}

struct AzureCliFetcher {
    resource: String,
}

impl TokenFetch for AzureCliFetcher {
    fn fetch_fresh_token(&self) -> Result<CachedAccessToken> {
        let output = std::process::Command::new("az")
            .args([
                "account",
                "get-access-token",
                "--resource",
                &self.resource,
                "--output",
                "json",
            ])
            .output()
            .context(
                "Azure Key Vault: failed to run `az account get-access-token`; is the Azure CLI installed and logged in?",
            )?;
        if !output.status.success() {
            anyhow::bail!(
                "Azure Key Vault: `az account get-access-token` failed: {}",
                body_excerpt(&String::from_utf8_lossy(&output.stderr))
            );
        }
        parse_cli_token_output(&String::from_utf8_lossy(&output.stdout))
    }
}

/// Parse a token-endpoint response body. IMDS reports `expires_in` as
/// a JSON string; the Entra v2 endpoint reports it as a number. Both
/// are accepted; a missing or malformed field falls back to one hour.
fn parse_token_response(context: &str, body: &str) -> Result<CachedAccessToken> {
    let value: serde_json::Value = serde_json::from_str(body)
        .with_context(|| format!("{context} token response was not JSON"))?;
    let token = value
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if token.is_empty() {
        anyhow::bail!("{context} token response is missing `access_token`");
    }
    let expires_in = match value.get("expires_in") {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(DEFAULT_TOKEN_TTL_SECS),
        Some(serde_json::Value::String(s)) => s.parse().unwrap_or(DEFAULT_TOKEN_TTL_SECS),
        _ => DEFAULT_TOKEN_TTL_SECS,
    };
    Ok(CachedAccessToken {
        token: token.to_string(),
        expires_at: Instant::now()
            + Duration::from_secs(expires_in.saturating_sub(TOKEN_EXPIRY_SKEW_SECS)),
    })
}

/// Parse `az account get-access-token --output json`. The `expires_on`
/// epoch field is used for the cache lifetime when present; otherwise
/// the token is assumed to last one hour.
fn parse_cli_token_output(stdout: &str) -> Result<CachedAccessToken> {
    let value: serde_json::Value = serde_json::from_str(stdout)
        .context("Azure Key Vault: `az account get-access-token` output was not JSON")?;
    let token = value
        .get("accessToken")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if token.is_empty() {
        anyhow::bail!(
            "Azure Key Vault: `az account get-access-token` output is missing `accessToken`"
        );
    }
    let ttl = value
        .get("expires_on")
        .and_then(serde_json::Value::as_u64)
        .and_then(|epoch| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            epoch.checked_sub(now)
        })
        .unwrap_or(DEFAULT_TOKEN_TTL_SECS);
    Ok(CachedAccessToken {
        token: token.to_string(),
        expires_at: Instant::now()
            + Duration::from_secs(ttl.saturating_sub(TOKEN_EXPIRY_SKEW_SECS)),
    })
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
        token_calls: AtomicUsize,
    }

    impl MockTokenProvider {
        fn new(token: &str) -> Self {
            Self {
                token: token.to_string(),
                token_calls: AtomicUsize::new(0),
            }
        }
    }

    impl AzureAccessTokenProvider for MockTokenProvider {
        fn access_token(&self) -> Result<String> {
            self.token_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.token.clone())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedGet {
        vault_url: String,
        name: String,
        version: Option<String>,
        bearer_token: String,
    }

    #[derive(Default)]
    struct MockKeyVaultTransport {
        requests: Mutex<Vec<RecordedGet>>,
        responses: Mutex<Vec<AzureHttpResponse>>,
    }

    impl MockKeyVaultTransport {
        fn with_response(status: u16, body: impl Into<String>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(vec![AzureHttpResponse {
                    status,
                    body: body.into(),
                }]),
            }
        }

        fn requests(&self) -> Vec<RecordedGet> {
            self.requests.lock().clone()
        }
    }

    impl AzureKeyVaultTransport for MockKeyVaultTransport {
        fn get_secret(
            &self,
            vault_url: &str,
            name: &str,
            version: Option<&str>,
            bearer_token: &str,
        ) -> Result<AzureHttpResponse> {
            self.requests.lock().push(RecordedGet {
                vault_url: vault_url.to_string(),
                name: name.to_string(),
                version: version.map(str::to_string),
                bearer_token: bearer_token.to_string(),
            });
            self.responses
                .lock()
                .pop()
                .ok_or_else(|| anyhow!("mock response queue exhausted"))
        }
    }

    fn secret_body(value: &str) -> String {
        format!(
            r#"{{"value":"{value}","id":"https://acme.vault.azure.net/secrets/openai/abc","attributes":{{"enabled":true}}}}"#
        )
    }

    fn test_cfg() -> AzureKeyVaultConfig {
        AzureKeyVaultConfig {
            vault_url: "https://acme.vault.azure.net".to_string(),
            auth: AzureKeyVaultAuth::ManagedIdentity,
            cache_ttl_secs: Some(60),
        }
    }

    fn backend(
        token_provider: Arc<MockTokenProvider>,
        transport: Arc<MockKeyVaultTransport>,
    ) -> AzureKeyVaultBackend {
        AzureKeyVaultBackend::new_for_test(test_cfg(), token_provider, transport).unwrap()
    }

    // --- reference resolution ---

    #[test]
    fn resolves_bare_secret_name_to_current_version() {
        assert_eq!(
            resolve_secret_ref("openai-prod", None).unwrap(),
            ("openai-prod".to_string(), None)
        );
    }

    #[test]
    fn resolves_query_version_pin() {
        assert_eq!(
            resolve_secret_ref("openai-prod", Some("abc123def456")).unwrap(),
            ("openai-prod".to_string(), Some("abc123def456".to_string()))
        );
    }

    #[test]
    fn resolves_path_version_pin() {
        assert_eq!(
            resolve_secret_ref("openai-prod/abc123def456", None).unwrap(),
            ("openai-prod".to_string(), Some("abc123def456".to_string()))
        );
    }

    #[test]
    fn resolves_resource_style_path() {
        assert_eq!(
            resolve_secret_ref("secrets/openai-prod", None).unwrap(),
            ("openai-prod".to_string(), None)
        );
        assert_eq!(
            resolve_secret_ref("secrets/openai-prod/abc123", None).unwrap(),
            ("openai-prod".to_string(), Some("abc123".to_string()))
        );
    }

    #[test]
    fn version_latest_means_no_pin() {
        assert_eq!(
            resolve_secret_ref("openai-prod", Some("latest")).unwrap(),
            ("openai-prod".to_string(), None)
        );
    }

    #[test]
    fn matching_path_and_query_versions_are_accepted() {
        assert_eq!(
            resolve_secret_ref("openai-prod/abc123", Some("abc123")).unwrap(),
            ("openai-prod".to_string(), Some("abc123".to_string()))
        );
    }

    #[test]
    fn conflicting_path_and_query_versions_are_rejected() {
        let err = resolve_secret_ref("openai-prod/abc123", Some("def456"))
            .expect_err("conflicting versions should be rejected");
        assert!(format!("{err}").contains("conflicts"));
    }

    #[test]
    fn rejects_invalid_path_segments() {
        assert!(resolve_secret_ref("../other", None).is_err());
        assert!(resolve_secret_ref("secrets/openai/..", None).is_err());
        assert!(resolve_secret_ref("a/b/c/d", None).is_err());
        assert!(resolve_secret_ref("///", None).is_err());
    }

    #[test]
    fn rejects_invalid_secret_name() {
        let err = resolve_secret_ref("openai_prod", None).expect_err("underscore is invalid");
        assert!(format!("{err}").contains("invalid secret name"));
    }

    #[test]
    fn rejects_invalid_version() {
        let err =
            resolve_secret_ref("openai-prod", Some("v!1")).expect_err("punctuation is invalid");
        assert!(format!("{err}").contains("invalid secret version"));
    }

    // --- URL and token-endpoint composition ---

    #[test]
    fn rejects_plaintext_http_vault_url() {
        let cfg = AzureKeyVaultConfig {
            vault_url: "http://acme.vault.azure.net".to_string(),
            ..test_cfg()
        };
        let err = match AzureKeyVaultBackend::new_for_test(
            cfg,
            Arc::new(MockTokenProvider::default()),
            Arc::new(MockKeyVaultTransport::default()),
        ) {
            Ok(_) => panic!("Key Vault is https-only; a plaintext URL must fail at construction"),
            Err(err) => err,
        };
        assert!(format!("{err}").contains("https-only"));
    }

    #[test]
    fn secret_url_omits_version_segment_for_current_version() {
        assert_eq!(
            secret_url("https://acme.vault.azure.net", "openai", None),
            "https://acme.vault.azure.net/secrets/openai?api-version=7.4"
        );
    }

    #[test]
    fn secret_url_pins_version_segment() {
        assert_eq!(
            secret_url("https://acme.vault.azure.net", "openai", Some("abc123")),
            "https://acme.vault.azure.net/secrets/openai/abc123?api-version=7.4"
        );
    }

    #[test]
    fn token_resource_follows_vault_dns_suffix() {
        assert_eq!(
            token_resource_for_vault_url("https://acme.vault.azure.net"),
            "https://vault.azure.net"
        );
        assert_eq!(
            token_resource_for_vault_url("https://acme.vault.azure.cn"),
            "https://vault.azure.cn"
        );
        assert_eq!(
            token_resource_for_vault_url("https://acme.vault.usgovcloudapi.net"),
            "https://vault.usgovcloudapi.net"
        );
    }

    #[test]
    fn token_resource_falls_back_for_non_vault_hosts() {
        assert_eq!(
            token_resource_for_vault_url("http://localhost:8200"),
            DEFAULT_KEY_VAULT_RESOURCE
        );
        assert_eq!(
            token_resource_for_vault_url("https://example.com"),
            DEFAULT_KEY_VAULT_RESOURCE
        );
    }

    #[test]
    fn service_principal_token_url_uses_default_authority() {
        assert_eq!(
            service_principal_token_url(None, "my-tenant"),
            "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token"
        );
    }

    #[test]
    fn service_principal_token_url_accepts_authority_override() {
        assert_eq!(
            service_principal_token_url(Some("https://login.chinacloudapi.cn/"), "my-tenant"),
            "https://login.chinacloudapi.cn/my-tenant/oauth2/v2.0/token"
        );
    }

    #[test]
    fn managed_identity_source_prefers_app_service_endpoint() {
        let source = managed_identity_source(
            Some("http://169.254.130.4:8081/msi/token".to_string()),
            Some("header-secret".to_string()),
        );
        match source {
            ManagedIdentitySource::AppService {
                endpoint,
                header_value,
            } => {
                assert_eq!(endpoint, "http://169.254.130.4:8081/msi/token");
                assert_eq!(header_value, "header-secret");
            }
            ManagedIdentitySource::Imds { .. } => panic!("expected the App Service source"),
        }
    }

    #[test]
    fn managed_identity_source_falls_back_to_imds() {
        let source = managed_identity_source(None, None);
        assert!(matches!(
            source,
            ManagedIdentitySource::Imds { endpoint } if endpoint == IMDS_TOKEN_ENDPOINT
        ));
        // A dangling endpoint without its header is not usable.
        let source = managed_identity_source(Some("http://x".to_string()), None);
        assert!(matches!(source, ManagedIdentitySource::Imds { .. }));
    }

    // --- construction validation ---

    #[test]
    fn construction_validates_required_fields() {
        let mut c = test_cfg();
        c.vault_url = String::new();
        assert!(AzureKeyVaultBackend::new(c).is_err());

        let mut c = test_cfg();
        c.vault_url = "acme.vault.azure.net".to_string();
        assert!(AzureKeyVaultBackend::new(c).is_err());
    }

    #[test]
    fn construction_rejects_empty_service_principal_material() {
        let mut c = test_cfg();
        c.auth = AzureKeyVaultAuth::ServicePrincipal {
            tenant_id: "tenant".to_string(),
            client_id: String::new(),
            client_secret: "secret".to_string(),
            authority: None,
        };
        let err = AzureKeyVaultBackend::new(c)
            .err()
            .expect("construction should reject empty client_id");
        assert!(format!("{err}").contains("client_id"));
    }

    #[test]
    fn construction_rejects_empty_user_assigned_client_id() {
        let mut c = test_cfg();
        c.auth = AzureKeyVaultAuth::UserAssignedIdentity {
            client_id: String::new(),
        };
        assert!(AzureKeyVaultBackend::new(c).is_err());
    }

    // --- resolve path against the mock transport ---

    #[test]
    fn get_secret_decodes_and_caches_payload() {
        let token = Arc::new(MockTokenProvider::new("test-token"));
        let transport = Arc::new(MockKeyVaultTransport::with_response(
            200,
            secret_body("sk-azure"),
        ));
        let b = backend(token.clone(), transport.clone());

        assert_eq!(b.get("openai").unwrap(), Some("sk-azure".to_string()));
        assert_eq!(b.get("openai").unwrap(), Some("sk-azure".to_string()));
        assert_eq!(token.token_calls.load(Ordering::SeqCst), 1);

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].vault_url, "https://acme.vault.azure.net");
        assert_eq!(requests[0].name, "openai");
        assert_eq!(requests[0].version, None);
        assert_eq!(requests[0].bearer_token, "test-token");
    }

    #[test]
    fn manager_passes_version_to_azure_backend_and_extracts_json_key() {
        let token = Arc::new(MockTokenProvider::new("test-token"));
        let transport = Arc::new(MockKeyVaultTransport::with_response(
            200,
            r#"{"value":"{\"api_key\":\"sk-azure\",\"limit\":5}"}"#,
        ));
        let b = backend(token, transport.clone());
        let mut mgr = VaultManager::new();
        mgr.register_backend(VaultProviderType::AzureKeyVault, "primary", Box::new(b));

        let reference =
            VaultRef::parse("azurekv://primary/openai?version=abc123&key=api_key").unwrap();
        assert_eq!(
            mgr.get_from_ref(&reference).unwrap(),
            Some("sk-azure".to_string())
        );

        let requests = transport.requests();
        assert_eq!(requests[0].name, "openai");
        assert_eq!(requests[0].version.as_deref(), Some("abc123"));
    }

    #[test]
    fn not_found_status_returns_none() {
        let b = backend(
            Arc::new(MockTokenProvider::new("token")),
            Arc::new(MockKeyVaultTransport::with_response(
                404,
                r#"{"error":{"code":"SecretNotFound","message":"A secret with (name/id) missing was not found in this key vault."}}"#,
            )),
        );

        assert_eq!(b.get("missing").unwrap(), None);
    }

    #[test]
    fn denied_status_is_classifiable() {
        let b = backend(
            Arc::new(MockTokenProvider::new("token")),
            Arc::new(MockKeyVaultTransport::with_response(
                403,
                r#"{"error":{"code":"Forbidden","message":"The user, group or application does not have secrets get permission on key vault 'acme'.","innererror":{"code":"AccessDenied"}}}"#,
            )),
        );

        let err = b.get("denied").expect_err("403 should error");
        let msg = format!("{err:#}").to_ascii_lowercase();
        // The 403 surfaces as an access failure carrying Azure's own
        // message, not a raw JSON dump.
        assert!(msg.contains("cannot access"), "got: {msg}");
        assert!(msg.contains("permission"), "got: {msg}");
        assert!(!msg.contains('{'), "should not dump raw JSON: {msg}");
    }

    #[test]
    fn server_error_status_carries_detail() {
        let b = backend(
            Arc::new(MockTokenProvider::new("token")),
            Arc::new(MockKeyVaultTransport::with_response(
                500,
                r#"{"error":{"code":"InternalServerError","message":"Something went wrong."}}"#,
            )),
        );

        let err = b.get("broken").expect_err("500 should error");
        let msg = format!("{err:#}");
        assert!(msg.contains("InternalServerError"), "got: {msg}");
    }

    #[test]
    fn clear_cache_drops_every_entry() {
        let b = backend(
            Arc::new(MockTokenProvider::new("token")),
            Arc::new(MockKeyVaultTransport::default()),
        );
        b.cache_store("k1/latest".into(), "v1".into());
        b.cache_store("k2/latest".into(), "v2".into());
        b.clear_cache();
        assert!(b.cache_hit("k1/latest").is_none());
        assert!(b.cache_hit("k2/latest").is_none());
    }

    #[test]
    fn expired_cache_entry_is_dropped_on_read() {
        let b = backend(
            Arc::new(MockTokenProvider::new("token")),
            Arc::new(MockKeyVaultTransport::default()),
        );
        {
            let mut cache = b.cache.lock();
            cache.insert(
                "stale/latest".to_string(),
                CacheEntry {
                    payload: "v".to_string(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        assert!(b.cache_hit("stale/latest").is_none());
        assert_eq!(b.cache.lock().len(), 0);
    }

    #[test]
    fn write_path_is_rejected() {
        let b = backend(
            Arc::new(MockTokenProvider::new("token")),
            Arc::new(MockKeyVaultTransport::default()),
        );
        let err = b
            .set("openai", "value")
            .expect_err("set should be rejected");
        assert!(format!("{err}").contains("not supported"));
    }

    // --- response decoding ---

    #[test]
    fn decode_rejects_response_without_value() {
        let err = decode_get_secret_response(r#"{"id":"x"}"#, "openai")
            .expect_err("missing value should error");
        assert!(format!("{err}").contains("missing `.value`"));
    }

    #[test]
    fn decode_rejects_non_json_response() {
        assert!(decode_get_secret_response("plain text", "openai").is_err());
    }

    #[test]
    fn azure_error_detail_extracts_code_and_message() {
        let body = r#"{"error":{"code":"SecretNotFound","message":"A secret with (name/id) x was not found in this key vault."}}"#;
        let out = azure_error_detail(body);
        assert_eq!(
            out,
            "SecretNotFound: A secret with (name/id) x was not found in this key vault."
        );
        assert!(!out.contains('{'), "should not dump raw JSON");
    }

    #[test]
    fn azure_error_detail_falls_back_on_non_json() {
        let body = "upstream proxy error, not json";
        assert_eq!(azure_error_detail(body), "upstream proxy error, not json");
    }

    #[test]
    fn aad_error_detail_extracts_oauth_error_fields() {
        let body = r#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#;
        assert_eq!(
            aad_error_detail(body),
            "invalid_client: AADSTS7000215: Invalid client secret provided."
        );
    }

    // --- token response parsing ---

    #[test]
    fn parse_token_response_accepts_numeric_expires_in() {
        let parsed =
            parse_token_response("ctx", r#"{"access_token":"tok","expires_in":3599}"#).unwrap();
        assert_eq!(parsed.token, "tok");
        assert!(parsed.expires_at > Instant::now() + Duration::from_secs(3000));
    }

    #[test]
    fn parse_token_response_accepts_string_expires_in() {
        // The IMDS endpoint reports expires_in as a JSON string.
        let parsed =
            parse_token_response("ctx", r#"{"access_token":"tok","expires_in":"3599"}"#).unwrap();
        assert_eq!(parsed.token, "tok");
        assert!(parsed.expires_at > Instant::now() + Duration::from_secs(3000));
    }

    #[test]
    fn parse_token_response_defaults_missing_expires_in() {
        let parsed = parse_token_response("ctx", r#"{"access_token":"tok"}"#).unwrap();
        assert_eq!(parsed.token, "tok");
        assert!(parsed.expires_at > Instant::now());
    }

    #[test]
    fn parse_token_response_rejects_missing_token() {
        assert!(parse_token_response("ctx", r#"{"expires_in":3599}"#).is_err());
        assert!(parse_token_response("ctx", "not json").is_err());
    }

    #[test]
    fn parse_cli_token_output_reads_access_token_and_expiry() {
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1800;
        let body = format!(
            r#"{{"accessToken":"cli-tok","expires_on":{far_future},"tokenType":"Bearer"}}"#
        );
        let parsed = parse_cli_token_output(&body).unwrap();
        assert_eq!(parsed.token, "cli-tok");
        assert!(parsed.expires_at > Instant::now() + Duration::from_secs(1000));
    }

    #[test]
    fn parse_cli_token_output_rejects_missing_access_token() {
        assert!(parse_cli_token_output(r#"{"tokenType":"Bearer"}"#).is_err());
        assert!(parse_cli_token_output("az: command failed").is_err());
    }

    // --- token cache ---

    struct CountingFetcher {
        calls: AtomicUsize,
        ttl: Duration,
    }

    impl TokenFetch for CountingFetcher {
        fn fetch_fresh_token(&self) -> Result<CachedAccessToken> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(CachedAccessToken {
                token: format!("tok-{n}"),
                expires_at: Instant::now() + self.ttl,
            })
        }
    }

    #[test]
    fn cached_token_provider_reuses_unexpired_token() {
        let provider = CachedTokenProvider::new(CountingFetcher {
            calls: AtomicUsize::new(0),
            ttl: Duration::from_secs(300),
        });
        assert_eq!(provider.access_token().unwrap(), "tok-0");
        assert_eq!(provider.access_token().unwrap(), "tok-0");
        assert_eq!(provider.fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cached_token_provider_refetches_expired_token() {
        let provider = CachedTokenProvider::new(CountingFetcher {
            calls: AtomicUsize::new(0),
            ttl: Duration::ZERO,
        });
        assert_eq!(provider.access_token().unwrap(), "tok-0");
        assert_eq!(provider.access_token().unwrap(), "tok-1");
        assert_eq!(provider.fetcher.calls.load(Ordering::SeqCst), 2);
    }
}
