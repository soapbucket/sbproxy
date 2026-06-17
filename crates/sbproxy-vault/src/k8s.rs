// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Kubernetes Secrets backend.
//!
//! Implements [`crate::manager::VaultBackend`] against the in-cluster
//! Kubernetes API via the official `kube` crate. Reads `Secret`
//! objects, base64-decodes their `data` field, and serves a single
//! key out of the secret per resolved path.
//!
//! ## Scope
//!
//! * Auth methods:
//!   - In-cluster service-account (default; reads the pod's SA token
//!     from `/var/run/secrets/kubernetes.io/serviceaccount/`).
//!   - Explicit kubeconfig path (for out-of-cluster operators).
//! * Per-namespace tenant isolation: a tenant declares
//!   `namespace: <ns>`; reads outside that namespace are rejected at
//!   URL composition.
//! * Path shape: `<secret-name>/<data-key>` (relative) or
//!   `<namespace>/<secret-name>/<data-key>` (when the operator's
//!   `vault://k8s/...` reference encodes the namespace explicitly).
//! * Cache TTL: 5 minutes default, configurable per backend.
//! * Honours the secret's `data` (base64-encoded) and `stringData`
//!   (plaintext) shapes; `data` keys are decoded automatically.
//!
//! Watch-based cache invalidation is a planned follow-up; today the
//! TTL bounds the staleness window.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::config::KubeConfigOptions;
use kube::{Api, Client, Config};
use parking_lot::Mutex;
use tokio::runtime::Runtime;

use crate::manager::VaultBackend;

/// Default TTL on a cached secret read.
pub const DEFAULT_K8S_CACHE_TTL: Duration = Duration::from_secs(300);

/// Read-only Kubernetes Secrets client.
pub struct KubernetesSecretsBackend {
    inner: BackendInner,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct BackendInner {
    client: Option<Client>,
    /// Namespace the backend is scoped to. Every read must stay
    /// inside this namespace; absent reads use this as the default.
    namespace: String,
    cache_ttl: Duration,
    rt: Runtime,
}

struct CacheEntry {
    payload: String,
    expires_at: Instant,
}

/// Operator-facing config.
#[derive(Debug, Clone)]
pub struct KubernetesSecretsConfig {
    /// How the client authenticates.
    pub auth: KubernetesAuth,
    /// Namespace this backend is bound to. Every secret read must
    /// resolve to a key inside this namespace; cross-namespace reads
    /// are rejected at URL composition.
    pub namespace: String,
    /// Cache TTL on a successful read. Defaults to
    /// [`DEFAULT_K8S_CACHE_TTL`].
    pub cache_ttl: Option<Duration>,
}

/// Operator-facing auth method.
#[derive(Debug, Clone)]
pub enum KubernetesAuth {
    /// In-cluster service-account auth. The kube client picks up
    /// `/var/run/secrets/kubernetes.io/serviceaccount/{token, ca.crt}`
    /// and `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT`. The
    /// recommended choice for in-cluster sbproxy deployments.
    InCluster,
    /// Explicit kubeconfig path. Used by out-of-cluster operators
    /// (e.g. running sbproxy on a bastion against a cluster).
    Kubeconfig {
        /// Path to the kubeconfig file.
        path: String,
        /// Optional context name to select inside the kubeconfig.
        context: Option<String>,
    },
}

impl KubernetesSecretsBackend {
    /// Build a backend. Validates config, instantiates the kube
    /// client, and stashes a dedicated tokio runtime so the sync
    /// `VaultBackend` trait can drive the async client via
    /// `Runtime::block_on`.
    pub fn new(cfg: KubernetesSecretsConfig) -> Result<Self> {
        // rustls 0.23 requires a process-global CryptoProvider before
        // any TLS handshake; `install_default()` is idempotent across
        // backends (the second call returns Err, which we discard).
        let _ = rustls::crypto::ring::default_provider().install_default();

        if cfg.namespace.is_empty() {
            anyhow::bail!("Kubernetes Secrets: `namespace` must not be empty");
        }
        if let KubernetesAuth::Kubeconfig { path, .. } = &cfg.auth {
            if path.is_empty() {
                anyhow::bail!("Kubernetes Secrets: kubeconfig auth requires a non-empty `path`");
            }
        }

        let cache_ttl = cfg.cache_ttl.unwrap_or(DEFAULT_K8S_CACHE_TTL);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Kubernetes Secrets: failed to build per-backend tokio runtime")?;

        let client = rt
            .block_on(async { build_client(cfg.auth).await })
            .context("Kubernetes Secrets: client construction failed")?;

        Ok(Self {
            inner: BackendInner {
                client: Some(client),
                namespace: cfg.namespace.trim_matches('/').to_string(),
                cache_ttl,
                rt,
            },
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Resolve a path into `(namespace, secret_name, data_key)`. The
    /// reference path can be:
    ///
    /// * Relative: `<secret-name>/<data-key>` (uses the configured
    ///   namespace).
    /// * Absolute: `<namespace>/<secret-name>/<data-key>` (must match
    ///   the configured namespace).
    /// * Single key: `<secret-name>` (returns the whole secret as a
    ///   JSON map of `{key: value}` decoded entries).
    fn resolve_path(&self, path: &str) -> Result<(String, String, Option<String>)> {
        let cleaned = path.trim_matches('/');
        if cleaned.is_empty() {
            anyhow::bail!("Kubernetes Secrets: empty path after normalisation");
        }
        if cleaned.split('/').any(|seg| seg == "..") {
            anyhow::bail!("Kubernetes Secrets: path `{path}` contains a `..` segment; rejecting");
        }

        let parts: Vec<&str> = cleaned.split('/').collect();
        let ns_configured = self.inner.namespace.as_str();
        match parts.len() {
            // <secret>
            1 => Ok((ns_configured.to_string(), parts[0].to_string(), None)),
            // <secret>/<key> OR <namespace>/<secret>
            2 => {
                // Disambiguate by whether the first segment matches the
                // configured namespace. If it does, treat it as
                // `<ns>/<secret>` and return the whole secret. If not,
                // treat it as `<secret>/<key>` under the configured
                // namespace. The first interpretation is preferred
                // because operators most often write the explicit
                // namespace shape.
                if parts[0] == ns_configured {
                    Ok((parts[0].to_string(), parts[1].to_string(), None))
                } else {
                    Ok((
                        ns_configured.to_string(),
                        parts[0].to_string(),
                        Some(parts[1].to_string()),
                    ))
                }
            }
            // <namespace>/<secret>/<key>
            3 => {
                if parts[0] != ns_configured {
                    anyhow::bail!(
                        "Kubernetes Secrets: path `{path}` references namespace `{}` but backend is bound to `{ns_configured}`",
                        parts[0]
                    );
                }
                Ok((
                    parts[0].to_string(),
                    parts[1].to_string(),
                    Some(parts[2].to_string()),
                ))
            }
            _ => anyhow::bail!(
                "Kubernetes Secrets: path `{path}` has too many segments; expected `<secret>[/<key>]` or `<ns>/<secret>[/<key>]`"
            ),
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

    /// Drop every cached entry. Used by tests; production resets the
    /// cache by restarting the process. A future watch-based variant
    /// invalidates entries on every observed Secret update.
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }

    /// Fetch a Secret object and decode the requested key (or the
    /// entire secret when `key` is `None`). Honours both `data`
    /// (base64-encoded) and `stringData` (plaintext) fields.
    async fn fetch_and_decode(
        client: &Client,
        namespace: &str,
        name: &str,
        key: Option<&str>,
    ) -> Result<Option<String>> {
        let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
        let secret = match api.get(name).await {
            Ok(s) => s,
            Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(None),
            Err(e) => {
                return Err(anyhow!(e))
                    .with_context(|| format!("Kubernetes Secrets: GET {namespace}/{name}"));
            }
        };

        // Merge `stringData` (plaintext) and base64-decoded `data`.
        use base64::Engine;
        let mut merged: HashMap<String, String> = HashMap::new();
        if let Some(string_data) = &secret.string_data {
            for (k, v) in string_data {
                merged.insert(k.clone(), v.clone());
            }
        }
        if let Some(data) = &secret.data {
            for (k, v) in data {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(v.0.as_slice())
                    .with_context(|| {
                        format!(
                            "Kubernetes Secrets: secret `{namespace}/{name}` field `{k}` is not valid base64"
                        )
                    })?;
                let text = String::from_utf8(decoded).with_context(|| {
                    format!(
                        "Kubernetes Secrets: secret `{namespace}/{name}` field `{k}` is not valid UTF-8"
                    )
                })?;
                merged.insert(k.clone(), text);
            }
        }

        match key {
            Some(k) => Ok(merged.remove(k)),
            None => {
                let payload = serde_json::to_string(&merged).with_context(|| {
                    format!("Kubernetes Secrets: serialise merged payload for `{namespace}/{name}`")
                })?;
                Ok(Some(payload))
            }
        }
    }
}

impl VaultBackend for KubernetesSecretsBackend {
    fn get(&self, key: &str) -> Result<Option<String>> {
        if let Some(hit) = self.cache_hit(key) {
            return Ok(Some(hit));
        }
        let (ns, name, field_key) = self.resolve_path(key)?;
        let client = self.inner.client.clone().ok_or_else(|| {
            anyhow!("Kubernetes Secrets: client is not initialised for this backend")
        })?;
        let resolved_ns = ns.clone();
        let resolved_name = name.clone();
        let resolved_key = field_key.clone();
        let value = self.inner.rt.block_on(async move {
            Self::fetch_and_decode(
                &client,
                &resolved_ns,
                &resolved_name,
                resolved_key.as_deref(),
            )
            .await
        })?;

        let payload = match value {
            Some(p) => p,
            None => return Ok(None),
        };
        self.cache_store(key.to_string(), payload.clone());
        Ok(Some(payload))
    }

    fn set(&self, _key: &str, _value: &str) -> Result<()> {
        // Writing to a Kubernetes Secret needs RBAC `update`
        // permissions and is best handled by the operator's
        // GitOps / SealedSecrets workflow. The read path covers the
        // resolver use case; explicit write requires the operator
        // wire through the kube client directly.
        anyhow::bail!(
            "Kubernetes Secrets: write path is not implemented; operators write Secrets through the cluster's GitOps / SealedSecrets workflow"
        )
    }
}

/// Build a kube `Client` from the configured auth method.
async fn build_client(auth: KubernetesAuth) -> Result<Client> {
    match auth {
        KubernetesAuth::InCluster => {
            // Order: env-based first (KUBERNETES_SERVICE_HOST), then
            // service-account files. `Config::infer` walks both,
            // matching the standard kube behaviour.
            let cfg = Config::infer()
                .await
                .context("Kubernetes Secrets: failed to infer in-cluster config")?;
            Ok(Client::try_from(cfg)?)
        }
        KubernetesAuth::Kubeconfig { path, context } => {
            std::env::set_var("KUBECONFIG", &path);
            let options = KubeConfigOptions {
                context,
                cluster: None,
                user: None,
            };
            let cfg = Config::from_kubeconfig(&options)
                .await
                .context("Kubernetes Secrets: failed to load kubeconfig")?;
            Ok(Client::try_from(cfg)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> KubernetesSecretsConfig {
        KubernetesSecretsConfig {
            auth: KubernetesAuth::Kubeconfig {
                path: "/dev/null".to_string(),
                context: None,
            },
            namespace: "tenant-acme".to_string(),
            cache_ttl: Some(Duration::from_secs(60)),
        }
    }

    /// Build a backend WITHOUT performing the kube client init.
    /// `KubernetesSecretsBackend::new` tries to load the cluster
    /// config which fails outside a cluster; this test helper
    /// constructs the inner fields directly.
    fn test_backend(namespace: &str) -> KubernetesSecretsBackend {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        KubernetesSecretsBackend {
            inner: BackendInner {
                client: None,
                namespace: namespace.to_string(),
                cache_ttl: Duration::from_secs(60),
                rt,
            },
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn construction_rejects_empty_namespace() {
        let mut c = base_cfg();
        c.namespace = String::new();
        assert!(KubernetesSecretsBackend::new(c).is_err());
    }

    #[test]
    fn construction_rejects_empty_kubeconfig_path() {
        let mut c = base_cfg();
        c.auth = KubernetesAuth::Kubeconfig {
            path: String::new(),
            context: None,
        };
        assert!(KubernetesSecretsBackend::new(c).is_err());
    }

    #[test]
    fn resolve_path_single_segment_is_whole_secret() {
        let b = test_backend("tenant-acme");
        let (ns, name, key) = b.resolve_path("openai").unwrap();
        assert_eq!(ns, "tenant-acme");
        assert_eq!(name, "openai");
        assert!(key.is_none());
    }

    #[test]
    fn resolve_path_two_segments_is_secret_plus_key() {
        let b = test_backend("tenant-acme");
        let (ns, name, key) = b.resolve_path("openai/api_key").unwrap();
        assert_eq!(ns, "tenant-acme");
        assert_eq!(name, "openai");
        assert_eq!(key.as_deref(), Some("api_key"));
    }

    #[test]
    fn resolve_path_explicit_namespace_match_returns_whole_secret() {
        let b = test_backend("tenant-acme");
        let (ns, name, key) = b.resolve_path("tenant-acme/openai").unwrap();
        assert_eq!(ns, "tenant-acme");
        assert_eq!(name, "openai");
        assert!(key.is_none());
    }

    #[test]
    fn resolve_path_three_segments_is_ns_secret_key() {
        let b = test_backend("tenant-acme");
        let (ns, name, key) = b.resolve_path("tenant-acme/openai/api_key").unwrap();
        assert_eq!(ns, "tenant-acme");
        assert_eq!(name, "openai");
        assert_eq!(key.as_deref(), Some("api_key"));
    }

    #[test]
    fn resolve_path_rejects_cross_namespace_read() {
        let b = test_backend("tenant-acme");
        let err = b
            .resolve_path("tenant-beta/openai/api_key")
            .expect_err("cross-namespace read should be rejected");
        assert!(format!("{err}").contains("namespace"));
    }

    #[test]
    fn resolve_path_rejects_directory_traversal() {
        let b = test_backend("tenant-acme");
        let err = b
            .resolve_path("../tenant-beta/openai")
            .expect_err("traversal should be rejected");
        assert!(format!("{err}").contains(".."));
    }

    #[test]
    fn resolve_path_rejects_too_many_segments() {
        let b = test_backend("tenant-acme");
        let err = b
            .resolve_path("tenant-acme/openai/api_key/extra")
            .expect_err("4 segments should fail");
        assert!(format!("{err}").contains("too many"));
    }

    #[test]
    fn resolve_path_rejects_empty() {
        let b = test_backend("tenant-acme");
        let err = b.resolve_path("///").expect_err("empty path");
        assert!(format!("{err}").contains("empty path"));
    }

    #[test]
    fn cache_short_circuits_within_ttl() {
        let b = test_backend("tenant-acme");
        b.cache_store("openai/api_key".to_string(), "sk-test".to_string());
        assert_eq!(b.cache_hit("openai/api_key").as_deref(), Some("sk-test"));
    }

    #[test]
    fn expired_cache_entry_is_dropped_on_read() {
        let b = test_backend("tenant-acme");
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
        assert_eq!(b.cache.lock().len(), 0);
    }

    #[test]
    fn clear_cache_drops_every_entry() {
        let b = test_backend("tenant-acme");
        b.cache_store("k1".into(), "v1".into());
        b.cache_store("k2".into(), "v2".into());
        b.clear_cache();
        assert!(b.cache_hit("k1").is_none());
        assert!(b.cache_hit("k2").is_none());
    }

    /// Set requires a write path that is explicitly not implemented.
    /// Verify the helpful error surfaces.
    #[test]
    fn set_is_not_implemented() {
        let b = test_backend("tenant-acme");
        let err = b
            .set("k", "v")
            .expect_err("set should fail with not-implemented");
        assert!(format!("{err}").contains("not implemented"));
    }
}
