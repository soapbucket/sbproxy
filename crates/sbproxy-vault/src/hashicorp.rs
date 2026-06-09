// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! HashiCorp Vault backend.
//!
//! Full-feature client backed by `ureq` (blocking HTTP). Implements
//! the [`crate::manager::VaultBackend`] trait so the manager can fan
//! lookups out to a registered HashiCorp instance.
//!
//! ## Scope
//!
//! * Auth methods: `token`, `approle` (role_id + secret_id), and
//!   `kubernetes` (service-account JWT exchange).
//! * Engine support: KV v1 and KV v2, selected per backend.
//! * Read and write paths through the `VaultBackend` trait.
//! * In-process TTL cache (5 minutes by default, configurable per
//!   backend) so the hot path does not roundtrip to Vault on every
//!   resolution.
//! * Tenant-isolated mount enforcement: the backend is constructed
//!   with a mount prefix (e.g. `secret/tenants/acme-corp/`) and
//!   rejects reads whose resolved path escapes that prefix. A typo
//!   in the operator's config that would otherwise pull from a
//!   sibling tenant's namespace surfaces as `permission_denied`.
//! * Token-renewal on 403 / `permission_denied`: AppRole and
//!   Kubernetes auth re-exchange their credentials and retry the
//!   read once. Token auth surfaces the error.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;

use crate::manager::VaultBackend;

/// Default TTL on a cached secret. Matches the Portkey precedent
/// cited in the credentials-epic notes; operators tune it per
/// backend when they need fresher reads or larger windows.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Read-only HashiCorp Vault client.
///
/// `Backend` is the type registered with [`crate::manager::VaultManager`]
/// under the operator-chosen name (`hashi`, `hashi-acme`, ...). The
/// backend is cheap to clone-by-reference through the trait object
/// the manager owns.
pub struct HashiCorpVaultBackend {
    inner: BackendInner,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct BackendInner {
    /// Vault server URL without trailing slash (`https://vault.example/v1`).
    /// The KV v2 read path is composed as `{addr}/{mount}/data/{path}`
    /// when `mount` does not already include `/data/`.
    addr: String,
    /// Auth source. Token-auth backends hold the bare token. AppRole
    /// and Kubernetes backends hold the exchange material; the live
    /// token is in [`Self::token`] and gets refreshed on 403.
    auth: AuthSource,
    /// The currently-active client token. Held behind a `Mutex` so
    /// the refresh-on-403 path can swap it atomically without taking
    /// `&mut self`.
    token: Mutex<String>,
    /// Operator-chosen mount prefix. Resolved paths must start with
    /// this prefix; reads outside it return `permission_denied`.
    /// For KV v2 mounts the prefix is the bare mount (`secret`); the
    /// `data/` segment is interpolated by [`Self::build_url`].
    mount_prefix: String,
    /// KV engine version. Selects the URL shape and the response
    /// payload extraction strategy.
    engine: KvEngine,
    /// Time a cache entry is considered fresh.
    cache_ttl: Duration,
    /// `Vault-Namespace` header (HashiCorp Vault Enterprise).
    /// Optional; absent for OSS deployments.
    namespace: Option<String>,
}

/// Where the backend gets its client token. `Token` is static (the
/// operator wrote the token directly into config). `AppRole` exchanges
/// `role_id + secret_id` for a token. `Kubernetes` exchanges the
/// pod's service-account JWT for a token under the configured role.
#[derive(Debug, Clone)]
enum AuthSource {
    Token,
    AppRole {
        role_id: String,
        secret_id: String,
        /// Auth endpoint mount (defaults to `approle`).
        mount: String,
    },
    Kubernetes {
        role: String,
        /// Path to the SA JWT on disk (defaults to
        /// `/var/run/secrets/kubernetes.io/serviceaccount/token`).
        jwt_path: String,
        /// Auth endpoint mount (defaults to `kubernetes`).
        mount: String,
    },
}

/// Which Vault KV engine the configured mount serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvEngine {
    /// Legacy KV v1. URL shape: `<mount>/<path>`. Payload at `.data`.
    V1,
    /// KV v2 (the default for new Vault deployments). URL shape:
    /// `<mount>/data/<path>` for reads, `<mount>/data/<path>` for
    /// writes wrapped under `{"data": {...}}`. Payload at `.data.data`.
    V2,
}

struct CacheEntry {
    payload: String,
    expires_at: Instant,
}

/// Configuration the operator supplies under
/// `proxy.vault[]` / `tenants[].vault[]` for a HashiCorp backend.
#[derive(Debug, Clone)]
pub struct HashiCorpConfig {
    /// Vault server address (`https://vault.example/v1`). Trailing
    /// slash is stripped at construction.
    pub addr: String,
    /// Auth method. One of token / approle / kubernetes; see
    /// [`HashiCorpAuth`].
    pub auth: HashiCorpAuth,
    /// KV mount path (defaults to `secret`). When the operator
    /// declares a tenant-isolated mount (`secret/tenants/acme-corp`),
    /// every read through the backend must stay inside that prefix.
    pub mount: String,
    /// KV engine version. Defaults to V2 (the current Vault default).
    pub engine: KvEngine,
    /// Cache TTL on a successful read. Defaults to
    /// [`DEFAULT_CACHE_TTL`].
    pub cache_ttl: Option<Duration>,
    /// Optional `X-Vault-Namespace` header (Vault Enterprise).
    pub namespace: Option<String>,
}

/// Operator-facing auth method enum.
#[derive(Debug, Clone)]
pub enum HashiCorpAuth {
    /// Static token. The operator resolves it from the config's
    /// secret reference (env var, file, vault://env/...).
    Token {
        /// Vault client token. Resolved by the operator from a
        /// secret reference at config-load.
        token: String,
    },
    /// AppRole: exchange `role_id + secret_id` for a token at the
    /// Vault `/v1/auth/<mount>/login` endpoint.
    AppRole {
        /// Role identifier. Typically created by an operator via the
        /// `vault write auth/approle/role/<role>` workflow.
        role_id: String,
        /// Secret identifier. Pair with `role_id` to log in.
        secret_id: String,
        /// AppRole mount path (defaults to `approle`).
        mount: Option<String>,
    },
    /// Kubernetes service-account JWT auth. Reads the pod's
    /// service-account JWT from `jwt_path` and exchanges it for a
    /// token at `/v1/auth/<mount>/login` against the configured role.
    Kubernetes {
        /// Operator-configured Vault role name.
        role: String,
        /// Path to the SA JWT (defaults to the standard kubelet path).
        jwt_path: Option<String>,
        /// Kubernetes auth mount path (defaults to `kubernetes`).
        mount: Option<String>,
    },
}

impl HashiCorpVaultBackend {
    /// Build a backend from operator config. Strips the trailing
    /// slash from `addr` so URL composition is unambiguous; rejects
    /// an empty mount or empty auth material at construction so a
    /// misconfig fails at config-load rather than at the first
    /// request.
    pub fn new(cfg: HashiCorpConfig) -> Result<Self> {
        if cfg.addr.is_empty() {
            anyhow::bail!("HashiCorp vault: `addr` must not be empty");
        }
        if cfg.mount.is_empty() {
            anyhow::bail!("HashiCorp vault: `mount` must not be empty");
        }
        let addr = cfg.addr.trim_end_matches('/').to_string();
        let mount_prefix = cfg.mount.trim_matches('/').to_string();

        let (auth, initial_token) = match cfg.auth {
            HashiCorpAuth::Token { token } => {
                if token.is_empty() {
                    anyhow::bail!("HashiCorp vault: `token` must not be empty");
                }
                (AuthSource::Token, token)
            }
            HashiCorpAuth::AppRole {
                role_id,
                secret_id,
                mount,
            } => {
                if role_id.is_empty() || secret_id.is_empty() {
                    anyhow::bail!(
                        "HashiCorp vault: AppRole auth requires `role_id` and `secret_id`"
                    );
                }
                let token = login_approle(
                    &addr,
                    &role_id,
                    &secret_id,
                    mount.as_deref().unwrap_or("approle"),
                    cfg.namespace.as_deref(),
                )?;
                (
                    AuthSource::AppRole {
                        role_id,
                        secret_id,
                        mount: mount.unwrap_or_else(|| "approle".to_string()),
                    },
                    token,
                )
            }
            HashiCorpAuth::Kubernetes {
                role,
                jwt_path,
                mount,
            } => {
                if role.is_empty() {
                    anyhow::bail!("HashiCorp vault: Kubernetes auth requires `role`");
                }
                let path = jwt_path.clone().unwrap_or_else(|| {
                    "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
                });
                let token = login_kubernetes(
                    &addr,
                    &role,
                    &path,
                    mount.as_deref().unwrap_or("kubernetes"),
                    cfg.namespace.as_deref(),
                )?;
                (
                    AuthSource::Kubernetes {
                        role,
                        jwt_path: path,
                        mount: mount.unwrap_or_else(|| "kubernetes".to_string()),
                    },
                    token,
                )
            }
        };

        Ok(Self {
            inner: BackendInner {
                addr,
                auth,
                token: Mutex::new(initial_token),
                mount_prefix,
                engine: cfg.engine,
                cache_ttl: cfg.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL),
                namespace: cfg.namespace,
            },
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Construct a backend for tests without performing an HTTP
    /// login. Used by the unit tests to exercise URL composition and
    /// cache behaviour without standing up a Vault instance.
    #[cfg(test)]
    fn new_for_test(
        addr: &str,
        token: &str,
        mount: &str,
        engine: KvEngine,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            inner: BackendInner {
                addr: addr.trim_end_matches('/').to_string(),
                auth: AuthSource::Token,
                token: Mutex::new(token.to_string()),
                mount_prefix: mount.trim_matches('/').to_string(),
                engine,
                cache_ttl,
                namespace: None,
            },
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Refresh the active token by re-running the configured auth
    /// exchange. No-op for `Token` (which has no fresh material). The
    /// `get` / `set` hot paths call this on a 403 / `permission_denied`
    /// and retry the request once.
    fn refresh_token(&self) -> Result<()> {
        match &self.inner.auth {
            AuthSource::Token => {
                // No way to refresh; the operator's static token is
                // either valid or it isn't.
                anyhow::bail!(
                    "HashiCorp vault: token auth received `permission_denied`; \
                     operator must rotate the configured token"
                );
            }
            AuthSource::AppRole {
                role_id,
                secret_id,
                mount,
            } => {
                let fresh = login_approle(
                    &self.inner.addr,
                    role_id,
                    secret_id,
                    mount,
                    self.inner.namespace.as_deref(),
                )?;
                *self.inner.token.lock() = fresh;
                Ok(())
            }
            AuthSource::Kubernetes {
                role,
                jwt_path,
                mount,
            } => {
                let fresh = login_kubernetes(
                    &self.inner.addr,
                    role,
                    jwt_path,
                    mount,
                    self.inner.namespace.as_deref(),
                )?;
                *self.inner.token.lock() = fresh;
                Ok(())
            }
        }
    }

    /// Stamp the active token and optional namespace header on a
    /// `ureq::Request`. Centralised so the same header logic applies
    /// to read, write, and login retries.
    fn stamp_headers(&self, mut req: ureq::Request) -> ureq::Request {
        req = req.set("X-Vault-Token", &self.inner.token.lock());
        if let Some(ns) = &self.inner.namespace {
            req = req.set("X-Vault-Namespace", ns);
        }
        req
    }

    /// Compose a KV read URL from a resolved secret path. KV v2
    /// interpolates the canonical `/data/` segment between the mount
    /// and the sub-path; KV v1 (legacy) uses `<mount>/<sub>` directly.
    ///
    /// Tenant-isolation guard: a path that, after normalisation,
    /// does not start with the configured mount prefix is rejected.
    /// This stops a `path: "../other-tenant/secret"` reference from
    /// pulling another tenant's namespace.
    fn build_url(&self, path: &str) -> Result<String> {
        let cleaned = path.trim_matches('/');
        if cleaned.is_empty() {
            anyhow::bail!("HashiCorp vault: empty path after normalisation");
        }
        // Reject `..` segments outright. A tenant mount prefix that
        // includes the directory `secret/tenants/acme-corp/` could
        // otherwise be escaped by a `../beta-corp/...` reference.
        if cleaned.split('/').any(|seg| seg == "..") {
            anyhow::bail!(
                "HashiCorp vault: path `{path}` contains a `..` segment; rejecting to keep tenant prefix"
            );
        }

        // Decide which segment is the mount and which is the
        // sub-path. Two shapes are valid:
        //
        //   1. The reference path already starts with the configured
        //      mount (`secret/data/acme/openai-prod`). We interpret
        //      it verbatim and use the rest as the KV v2 path.
        //   2. The reference path is relative to the mount
        //      (`acme/openai-prod`). We prepend `<mount>/data/`.
        //
        // Either way the resolved URL is sandboxed to the configured
        // mount prefix.
        let resolved = if cleaned.starts_with(&self.inner.mount_prefix) {
            // The reference already encodes the mount. Confirm it
            // stays inside the prefix (the starts_with check above
            // is necessary but not sufficient when the prefix is a
            // partial directory match like `secret` vs `secrets`).
            let after_mount = &cleaned[self.inner.mount_prefix.len()..];
            if !(after_mount.is_empty() || after_mount.starts_with('/')) {
                anyhow::bail!(
                    "HashiCorp vault: path `{path}` escapes mount prefix `{}`",
                    self.inner.mount_prefix
                );
            }
            cleaned.to_string()
        } else {
            // Sub-path under the configured mount. The URL shape
            // depends on the KV engine version: KV v2 interpolates
            // `/data/`; KV v1 lays out `<mount>/<sub>`.
            let sub = cleaned;
            match self.inner.engine {
                KvEngine::V2 => format!("{}/data/{}", self.inner.mount_prefix, sub),
                KvEngine::V1 => format!("{}/{}", self.inner.mount_prefix, sub),
            }
        };

        Ok(format!("{}/{}", self.inner.addr, resolved))
    }

    /// Compose a KV write URL. KV v2 uses the same `data/` segment
    /// for reads and writes; KV v1 also uses `<mount>/<sub>`.
    fn build_write_url(&self, path: &str) -> Result<String> {
        // Reuse build_url; the URL shape is identical for read and
        // write in both v1 and v2.
        self.build_url(path)
    }

    /// Whether a cached entry is fresh.
    fn cache_hit(&self, key: &str) -> Option<String> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.payload.clone());
            }
            // Expired; drop to force a fresh fetch.
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

    /// Drop every cached entry. Used by tests to verify cache
    /// behaviour; operators reset the cache by restarting the
    /// process. A future `health_check` lands a hot-reset on
    /// 403/expired-token responses.
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }
}

impl VaultBackend for HashiCorpVaultBackend {
    fn get(&self, key: &str) -> Result<Option<String>> {
        if let Some(hit) = self.cache_hit(key) {
            return Ok(Some(hit));
        }

        let url = self.build_url(key)?;
        // Blocking HTTP. The vault resolver path runs inside
        // `spawn_blocking` (see `crate::resolver`), so this does
        // not block the tokio runtime. A 403 on the first call
        // triggers a token refresh and a single retry.
        let response = match self.call_with_retry(|| self.stamp_headers(ureq::get(&url)), &url)? {
            Some(r) => r,
            None => return Ok(None),
        };

        let body: serde_json::Value = response
            .into_json()
            .context("HashiCorp vault: response body was not JSON")?;

        // Engine selects payload shape: KV v2 wraps under
        // `data.data`; KV v1 ships a flat `data`.
        let payload = match self.inner.engine {
            KvEngine::V2 => body
                .get("data")
                .and_then(|d| d.get("data"))
                .cloned()
                .ok_or_else(|| {
                    anyhow!("HashiCorp vault: KV v2 response from {url} missing `.data.data`")
                })?,
            KvEngine::V1 => body.get("data").cloned().ok_or_else(|| {
                anyhow!("HashiCorp vault: KV v1 response from {url} missing `.data`")
            })?,
        };

        let rendered = serde_json::to_string(&payload)
            .context("HashiCorp vault: failed to render payload as JSON")?;

        self.cache_store(key.to_string(), rendered.clone());
        Ok(Some(rendered))
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        let url = self.build_write_url(key)?;
        // The body shape depends on the engine. KV v2 wraps the
        // payload under `{"data": {...}}`; KV v1 takes the bare
        // object. A string fallback wraps a non-JSON value as
        // `{"value": "<value>"}` so operators do not have to think
        // about the engine when storing a single string secret.
        let body_value = parse_or_wrap_string(value);
        let envelope = match self.inner.engine {
            KvEngine::V2 => serde_json::json!({ "data": body_value }),
            KvEngine::V1 => body_value,
        };

        let mut tried = false;
        loop {
            let req = self.stamp_headers(ureq::post(&url).set("Content-Type", "application/json"));
            match req.send_json(envelope.clone()) {
                Ok(_) => {
                    // Invalidate the cached read so a follow-up `get`
                    // sees the new value.
                    self.cache.lock().remove(key);
                    return Ok(());
                }
                Err(ureq::Error::Status(403, _)) if !tried => {
                    tried = true;
                    self.refresh_token().with_context(|| {
                        format!("HashiCorp vault: refresh after 403 on write to {url} failed")
                    })?;
                    continue;
                }
                Err(ureq::Error::Status(s, r)) => {
                    return Err(anyhow!(
                        "HashiCorp vault: write {} {} on {}",
                        s,
                        r.status_text(),
                        url
                    ));
                }
                Err(e) => {
                    return Err(anyhow!(e)).with_context(|| {
                        format!("HashiCorp vault: transport error writing to {url}")
                    });
                }
            }
        }
    }
}

impl HashiCorpVaultBackend {
    /// Issue an HTTP call against `build_req()` and retry once on a
    /// 403 / `permission_denied` after refreshing the auth token.
    /// Returns `Ok(None)` on a 404 (caller treats that as a miss).
    fn call_with_retry<F>(&self, build_req: F, url: &str) -> Result<Option<ureq::Response>>
    where
        F: Fn() -> ureq::Request,
    {
        let mut tried = false;
        loop {
            match build_req().call() {
                Ok(r) => return Ok(Some(r)),
                Err(ureq::Error::Status(404, _)) => return Ok(None),
                Err(ureq::Error::Status(403, _)) if !tried => {
                    tried = true;
                    self.refresh_token().with_context(|| {
                        format!("HashiCorp vault: refresh after 403 on {url} failed")
                    })?;
                    continue;
                }
                Err(ureq::Error::Status(s, r)) => {
                    return Err(anyhow!(
                        "HashiCorp vault: {} {} on {}",
                        s,
                        r.status_text(),
                        url
                    ));
                }
                Err(e) => {
                    return Err(anyhow!(e)).with_context(|| {
                        format!("HashiCorp vault: transport error against {url}")
                    });
                }
            }
        }
    }
}

/// Try to parse `value` as a JSON object; if it isn't, wrap it as
/// `{"value": "<value>"}` so the KV write always sends a JSON object
/// rather than a bare string.
fn parse_or_wrap_string(value: &str) -> serde_json::Value {
    if let Ok(v @ serde_json::Value::Object(_)) = serde_json::from_str::<serde_json::Value>(value) {
        return v;
    }
    serde_json::json!({ "value": value })
}

// --- Auth-exchange helpers ---

/// AppRole login: POST `/v1/auth/<mount>/login` with `{role_id, secret_id}`,
/// pluck `.auth.client_token` from the response.
fn login_approle(
    addr: &str,
    role_id: &str,
    secret_id: &str,
    mount: &str,
    namespace: Option<&str>,
) -> Result<String> {
    let url = format!("{addr}/auth/{mount}/login");
    let mut req = ureq::post(&url).set("Content-Type", "application/json");
    if let Some(ns) = namespace {
        req = req.set("X-Vault-Namespace", ns);
    }
    let body = serde_json::json!({
        "role_id": role_id,
        "secret_id": secret_id,
    });
    let resp = req
        .send_json(body)
        .with_context(|| format!("HashiCorp vault AppRole login transport error against {url}"))?;
    let v: serde_json::Value = resp
        .into_json()
        .context("HashiCorp vault AppRole login: response was not JSON")?;
    let token = v
        .get("auth")
        .and_then(|a| a.get("client_token"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| {
            anyhow!("HashiCorp vault AppRole login response from {url} missing auth.client_token")
        })?;
    Ok(token.to_string())
}

/// Kubernetes login: read SA JWT from disk, POST it to
/// `/v1/auth/<mount>/login` with the configured role, pluck
/// `.auth.client_token` from the response.
fn login_kubernetes(
    addr: &str,
    role: &str,
    jwt_path: &str,
    mount: &str,
    namespace: Option<&str>,
) -> Result<String> {
    let jwt = std::fs::read_to_string(jwt_path).with_context(|| {
        format!("HashiCorp vault Kubernetes login: reading SA JWT from {jwt_path}")
    })?;
    let url = format!("{addr}/auth/{mount}/login");
    let mut req = ureq::post(&url).set("Content-Type", "application/json");
    if let Some(ns) = namespace {
        req = req.set("X-Vault-Namespace", ns);
    }
    let body = serde_json::json!({
        "role": role,
        "jwt": jwt.trim(),
    });
    let resp = req.send_json(body).with_context(|| {
        format!("HashiCorp vault Kubernetes login transport error against {url}")
    })?;
    let v: serde_json::Value = resp
        .into_json()
        .context("HashiCorp vault Kubernetes login: response was not JSON")?;
    let token = v
        .get("auth")
        .and_then(|a| a.get("client_token"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| {
            anyhow!(
                "HashiCorp vault Kubernetes login response from {url} missing auth.client_token"
            )
        })?;
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(addr: &str, mount: &str, token: &str) -> HashiCorpConfig {
        HashiCorpConfig {
            addr: addr.to_string(),
            auth: HashiCorpAuth::Token {
                token: token.to_string(),
            },
            mount: mount.to_string(),
            engine: KvEngine::V2,
            cache_ttl: Some(Duration::from_secs(60)),
            namespace: None,
        }
    }

    /// Construction rejects an empty addr / token / mount so a
    /// misconfig fails at config-load rather than at first read.
    #[test]
    fn construction_validates_required_fields() {
        let mut c = cfg("https://vault.example/v1", "secret", "root");
        c.addr = String::new();
        assert!(HashiCorpVaultBackend::new(c).is_err());
        let mut c = cfg("https://vault.example/v1", "secret", "root");
        c.auth = HashiCorpAuth::Token {
            token: String::new(),
        };
        assert!(HashiCorpVaultBackend::new(c).is_err());
        let mut c = cfg("https://vault.example/v1", "secret", "root");
        c.mount = String::new();
        assert!(HashiCorpVaultBackend::new(c).is_err());
    }

    /// Construction rejects an empty AppRole role_id / secret_id at
    /// config-load so the misconfig surfaces before any HTTP call.
    /// We do not exercise a real AppRole login here (that requires a
    /// live Vault instance); the unit test asserts the input
    /// validation path. The HTTP exchange is covered by the integration
    /// suite under `e2e/tests/vault_hashi.rs` once the Docker harness
    /// lands in a follow-up commit.
    #[test]
    fn construction_rejects_empty_approle_material() {
        let c = HashiCorpConfig {
            addr: "https://vault.example/v1".to_string(),
            auth: HashiCorpAuth::AppRole {
                role_id: String::new(),
                secret_id: "secret-id".to_string(),
                mount: None,
            },
            mount: "secret".to_string(),
            engine: KvEngine::V2,
            cache_ttl: Some(Duration::from_secs(60)),
            namespace: None,
        };
        let err = HashiCorpVaultBackend::new(c)
            .err()
            .expect("construction should reject the misconfig");
        assert!(
            format!("{err}").contains("AppRole"),
            "unhelpful error: {err}"
        );
    }

    /// Construction rejects an empty Kubernetes role at config-load
    /// without trying to read the SA JWT.
    #[test]
    fn construction_rejects_empty_kubernetes_role() {
        let c = HashiCorpConfig {
            addr: "https://vault.example/v1".to_string(),
            auth: HashiCorpAuth::Kubernetes {
                role: String::new(),
                jwt_path: None,
                mount: None,
            },
            mount: "secret".to_string(),
            engine: KvEngine::V2,
            cache_ttl: Some(Duration::from_secs(60)),
            namespace: None,
        };
        let err = HashiCorpVaultBackend::new(c)
            .err()
            .expect("construction should reject the misconfig");
        assert!(
            format!("{err}").contains("Kubernetes"),
            "unhelpful error: {err}"
        );
    }

    /// `parse_or_wrap_string` round-trips JSON objects verbatim and
    /// wraps plain strings under `value`. KV v1 sees the wrapped form
    /// directly; KV v2 nests it under `data` in the impl.
    #[test]
    fn parse_or_wrap_string_handles_both_shapes() {
        let obj = parse_or_wrap_string(r#"{"api_key":"sk-test"}"#);
        assert_eq!(obj["api_key"], "sk-test");
        let wrapped = parse_or_wrap_string("plain-string-secret");
        assert_eq!(wrapped["value"], "plain-string-secret");
    }

    /// KV v1 URL composition skips the `/data/` segment so the read
    /// hits `<mount>/<sub>` directly.
    #[test]
    fn build_url_kv_v1_skips_data_segment() {
        let b = HashiCorpVaultBackend::new_for_test(
            "https://vault.example/v1",
            "root",
            "secret",
            KvEngine::V1,
            Duration::from_secs(60),
        );
        let url = b.build_url("acme/openai-prod").unwrap();
        assert_eq!(url, "https://vault.example/v1/secret/acme/openai-prod");
    }

    /// Trailing slash on `addr` is normalised at construction so URL
    /// composition is deterministic.
    #[test]
    fn addr_trailing_slash_is_trimmed() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1/", "secret", "root")).unwrap();
        let url = b.build_url("acme/openai-prod").unwrap();
        assert_eq!(url, "https://vault.example/v1/secret/data/acme/openai-prod");
    }

    /// A relative path (no mount prefix) is interpolated under the
    /// mount with the canonical KV v2 `/data/` segment.
    #[test]
    fn build_url_interpolates_kv_v2_data_segment() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1", "secret", "root")).unwrap();
        let url = b.build_url("acme/openai-prod").unwrap();
        assert_eq!(url, "https://vault.example/v1/secret/data/acme/openai-prod");
    }

    /// A path that already names the mount is taken verbatim so
    /// operators with `vault://hashi/secret/data/acme/openai-prod`
    /// references get the same URL as the relative form.
    #[test]
    fn build_url_accepts_explicit_mount_prefix() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1", "secret", "root")).unwrap();
        let url = b.build_url("secret/data/acme/openai-prod").unwrap();
        assert_eq!(url, "https://vault.example/v1/secret/data/acme/openai-prod");
    }

    /// Multi-segment mount prefix (`secret/tenants/acme-corp/`)
    /// works the same way: relative paths land under the prefix.
    #[test]
    fn build_url_supports_tenant_isolated_mount() {
        let b = HashiCorpVaultBackend::new(cfg(
            "https://vault.example/v1",
            "secret/tenants/acme-corp",
            "root",
        ))
        .unwrap();
        let url = b.build_url("openai-prod").unwrap();
        assert_eq!(
            url,
            "https://vault.example/v1/secret/tenants/acme-corp/data/openai-prod"
        );
    }

    /// A `..` segment is rejected so a malicious or typo'd
    /// reference cannot escape the configured mount prefix.
    #[test]
    fn build_url_rejects_directory_traversal() {
        let b = HashiCorpVaultBackend::new(cfg(
            "https://vault.example/v1",
            "secret/tenants/acme-corp",
            "root",
        ))
        .unwrap();
        let err = b.build_url("../beta-corp/openai-prod").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains(".."), "unhelpful error: {msg}");
    }

    /// A path that starts with a partial prefix match
    /// (`secrets/...` against mount `secret`) is rejected so an
    /// operator typo cannot pull from a sibling mount.
    #[test]
    fn build_url_rejects_partial_prefix_collision() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1", "secret", "root")).unwrap();
        let err = b.build_url("secrets/data/acme/openai-prod").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("escapes mount prefix"),
            "unhelpful error: {msg}"
        );
    }

    /// An empty resolved path (just slashes) is rejected at URL build.
    #[test]
    fn build_url_rejects_empty_path() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1", "secret", "root")).unwrap();
        let err = b.build_url("///").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty path"), "unhelpful error: {msg}");
    }

    /// The cache short-circuits subsequent reads of the same key
    /// within the TTL window. We verify this without an HTTP call by
    /// seeding the cache directly.
    #[test]
    fn cache_short_circuits_within_ttl() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1", "secret", "root")).unwrap();
        b.cache_store(
            "acme/openai-prod".to_string(),
            "{\"api_key\":\"sk-test\"}".to_string(),
        );
        let hit = b.cache_hit("acme/openai-prod");
        assert_eq!(hit.as_deref(), Some("{\"api_key\":\"sk-test\"}"));
    }

    /// Clearing the cache forces the next lookup back through HTTP.
    #[test]
    fn clear_cache_drops_every_entry() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1", "secret", "root")).unwrap();
        b.cache_store("k1".into(), "v1".into());
        b.cache_store("k2".into(), "v2".into());
        b.clear_cache();
        assert!(b.cache_hit("k1").is_none());
        assert!(b.cache_hit("k2").is_none());
    }

    /// An expired cache entry is removed on read so the next call
    /// roundtrips.
    #[test]
    fn expired_cache_entry_is_dropped_on_read() {
        let b =
            HashiCorpVaultBackend::new(cfg("https://vault.example/v1", "secret", "root")).unwrap();
        // Bypass cache_store to seed an already-expired entry.
        {
            let mut cache = b.cache.lock();
            cache.insert(
                "stale".to_string(),
                CacheEntry {
                    payload: "v".to_string(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        assert!(b.cache_hit("stale").is_none());
        // And the entry was evicted in the process.
        assert_eq!(b.cache.lock().len(), 0);
    }
}
