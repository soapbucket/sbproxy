// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! AWS Secrets Manager backend.
//!
//! Implements the [`crate::manager::VaultBackend`] trait against AWS
//! Secrets Manager via the official `aws-sdk-secretsmanager` SDK.
//!
//! ## Scope
//!
//! * Auth methods:
//!   - Static access keys (`access_key_id + secret_access_key +
//!     optional session_token`).
//!   - Default credential chain (env vars, instance profile, SSO,
//!     web identity, etc.) for service-role deployments.
//!   - Assumed IAM role via STS for cross-account access. The
//!     backend opens a session at construction; refreshing on
//!     expiry is left to the SDK's built-in credential cache.
//! * Region selectable per backend.
//! * In-process TTL cache (5 minutes by default, configurable per
//!   backend) shared with the HashiCorp backend's cache shape.
//! * Tenant-isolated path prefix: a tenant declares
//!   `mount: prod/sbproxy/tenants/acme-corp/` and the backend
//!   rejects reads whose resolved path escapes that prefix. Pairs
//!   with the recommended AWS IAM pattern of scoping
//!   `secretsmanager:GetSecretValue` to `arn:aws:secretsmanager:*:*:secret:prod/sbproxy/tenants/${aws:PrincipalTag/sbproxy-tenant}/*`.
//!
//! The SDK is async; the trait surface is sync because the legacy
//! resolver path runs inside `spawn_blocking`. We hold a dedicated
//! single-threaded tokio runtime on the backend and `block_on` each
//! call. The runtime is small (a few hundred KiB) and lives for the
//! process lifetime alongside the backend.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_secretsmanager as smc;
use aws_sdk_sts as sts;
use parking_lot::Mutex;
use tokio::runtime::Runtime;

use crate::manager::VaultBackend;

/// Default TTL on a cached secret. Matches the HashiCorp backend
/// default; operators tune per-backend when they need fresher reads.
pub const DEFAULT_AWS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Read / write AWS Secrets Manager client.
pub struct AwsSecretsManagerBackend {
    inner: BackendInner,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct BackendInner {
    client: Option<smc::Client>,
    mount_prefix: String,
    cache_ttl: Duration,
    /// Dedicated runtime driving the SDK's async calls from the
    /// trait's sync surface. Lives behind an `Arc` because the
    /// trait's `&self` is `Sync`; tokio's `Runtime` is `Sync`
    /// already, so the inner field is plain.
    rt: Runtime,
}

struct CacheEntry {
    payload: String,
    expires_at: Instant,
}

/// Operator-facing config.
#[derive(Debug, Clone)]
pub struct AwsSecretsManagerConfig {
    /// AWS region (e.g. `us-east-1`).
    pub region: String,
    /// How the backend authenticates.
    pub auth: AwsAuth,
    /// Path prefix every read must stay inside. A tenant-isolated
    /// deployment sets this to `prod/sbproxy/tenants/<tenant>/`.
    pub mount_prefix: String,
    /// Cache TTL on a successful read. Defaults to
    /// [`DEFAULT_AWS_CACHE_TTL`].
    pub cache_ttl: Option<Duration>,
}

/// Operator-facing auth method.
#[derive(Debug, Clone)]
pub enum AwsAuth {
    /// Static access keys. Operator resolves them from the config's
    /// secret reference, such as `${ENV_VAR}` or `file:`.
    StaticKeys {
        /// AWS access key id.
        access_key_id: String,
        /// AWS secret access key. Resolved from a secret reference.
        secret_access_key: String,
        /// Optional session token (set when the operator already has
        /// short-lived STS credentials they want to reuse verbatim).
        session_token: Option<String>,
    },
    /// Default credential provider chain. Picks up env vars,
    /// EC2 instance profile, ECS task role, SSO, web identity, etc.
    /// The recommended choice for in-AWS deployments.
    DefaultChain,
    /// Assume an IAM role via STS at backend construction. Used for
    /// cross-account access where the proxy's identity is in one
    /// account and the tenant's secrets are in another.
    AssumedRole {
        /// Role ARN to assume.
        role_arn: String,
        /// External id required by the trust policy (optional).
        external_id: Option<String>,
        /// Session name (defaults to `sbproxy`).
        session_name: Option<String>,
    },
}

impl AwsSecretsManagerBackend {
    /// Build a backend. Resolves credentials, opens an STS session
    /// when needed, constructs the SDK client. Validation failures
    /// (empty region, empty mount, empty role ARN) surface at
    /// config-load rather than at the first read.
    pub fn new(cfg: AwsSecretsManagerConfig) -> Result<Self> {
        if cfg.region.is_empty() {
            anyhow::bail!("AWS Secrets Manager: `region` must not be empty");
        }
        if cfg.mount_prefix.is_empty() {
            anyhow::bail!("AWS Secrets Manager: `mount_prefix` must not be empty");
        }
        if let AwsAuth::StaticKeys {
            access_key_id,
            secret_access_key,
            ..
        } = &cfg.auth
        {
            if access_key_id.is_empty() || secret_access_key.is_empty() {
                anyhow::bail!(
                    "AWS Secrets Manager: static keys auth requires both `access_key_id` and `secret_access_key`"
                );
            }
        }
        if let AwsAuth::AssumedRole { role_arn, .. } = &cfg.auth {
            if role_arn.is_empty() {
                anyhow::bail!(
                    "AWS Secrets Manager: assumed-role auth requires a non-empty `role_arn`"
                );
            }
        }

        let mount_prefix = cfg.mount_prefix.trim_matches('/').to_string();
        let cache_ttl = cfg.cache_ttl.unwrap_or(DEFAULT_AWS_CACHE_TTL);

        // Dedicated single-threaded runtime so the sync trait surface
        // can `block_on` without colliding with an outer runtime.
        // `spawn_blocking` callers have already moved off the outer
        // worker thread, so this runtime owns its own thread.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AWS Secrets Manager: failed to build per-backend tokio runtime")?;

        let region = cfg.region.clone();
        let client = rt.block_on(async move { build_client(region, cfg.auth).await })?;

        Ok(Self {
            inner: BackendInner {
                client: Some(client),
                mount_prefix,
                cache_ttl,
                rt,
            },
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Compose the canonical Secrets Manager name from a resolved
    /// path. Same prefix-guard logic as the HashiCorp backend: the
    /// resolved name must stay inside the configured `mount_prefix`,
    /// `..` segments are rejected outright, partial-prefix collisions
    /// (`secrets/...` against mount `secret`) are rejected.
    fn resolve_name(&self, path: &str) -> Result<String> {
        let cleaned = path.trim_matches('/');
        if cleaned.is_empty() {
            anyhow::bail!("AWS Secrets Manager: empty path after normalisation");
        }
        if cleaned.split('/').any(|seg| seg == "..") {
            anyhow::bail!(
                "AWS Secrets Manager: path `{path}` contains a `..` segment; rejecting to keep tenant prefix"
            );
        }
        let resolved = if cleaned.starts_with(&self.inner.mount_prefix) {
            let after = &cleaned[self.inner.mount_prefix.len()..];
            if !(after.is_empty() || after.starts_with('/')) {
                anyhow::bail!(
                    "AWS Secrets Manager: path `{path}` escapes mount prefix `{}`",
                    self.inner.mount_prefix
                );
            }
            cleaned.to_string()
        } else {
            format!("{}/{}", self.inner.mount_prefix, cleaned)
        };
        Ok(resolved)
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

    /// Drop every cached entry. Tests use this to verify
    /// behaviour; production resets the cache by restarting the
    /// process.
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }
}

impl VaultBackend for AwsSecretsManagerBackend {
    fn get(&self, key: &str) -> Result<Option<String>> {
        if let Some(hit) = self.cache_hit(key) {
            return Ok(Some(hit));
        }
        let name = self.resolve_name(key)?;
        let client = self.inner.client.clone().ok_or_else(|| {
            anyhow!("AWS Secrets Manager: client is not initialised for this backend")
        })?;
        let name_for_call = name.clone();
        let secret = self
            .inner
            .rt
            .block_on(async move {
                client
                    .get_secret_value()
                    .secret_id(&name_for_call)
                    .send()
                    .await
            })
            .map_err(|e| anyhow!("AWS Secrets Manager: GetSecretValue {name}: {e}"))?;

        // Prefer `secret_string`. Binary secrets (`secret_binary`) are
        // returned as base64-encoded strings so the on-wire shape
        // matches the HashiCorp backend's text-only contract.
        let payload = match (secret.secret_string(), secret.secret_binary()) {
            (Some(s), _) => s.to_string(),
            (None, Some(b)) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(b.as_ref())
            }
            (None, None) => return Ok(None),
        };
        self.cache_store(key.to_string(), payload.clone());
        Ok(Some(payload))
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        let name = self.resolve_name(key)?;
        let client = self.inner.client.clone().ok_or_else(|| {
            anyhow!("AWS Secrets Manager: client is not initialised for this backend")
        })?;
        let value = value.to_string();
        self.inner
            .rt
            .block_on(async move {
                client
                    .put_secret_value()
                    .secret_id(&name)
                    .secret_string(value)
                    .send()
                    .await
            })
            .map_err(|e| anyhow!("AWS Secrets Manager: PutSecretValue {key}: {e}"))?;
        // Invalidate so the next get sees the new value.
        self.cache.lock().remove(key);
        Ok(())
    }
}

/// Build the SDK client from the resolved auth method. Sits behind
/// the constructor so the sync `new` path stays readable.
async fn build_client(region: String, auth: AwsAuth) -> Result<smc::Client> {
    let region_obj = aws_types::region::Region::new(region.clone());
    let cfg_builder = aws_config::defaults(BehaviorVersion::latest()).region(region_obj.clone());

    let sdk_config = match auth {
        AwsAuth::DefaultChain => cfg_builder.load().await,
        AwsAuth::StaticKeys {
            access_key_id,
            secret_access_key,
            session_token,
        } => {
            let creds = Credentials::new(
                access_key_id,
                secret_access_key,
                session_token,
                None,
                "sbproxy-static",
            );
            cfg_builder.credentials_provider(creds).load().await
        }
        AwsAuth::AssumedRole {
            role_arn,
            external_id,
            session_name,
        } => {
            // Build a base config (default chain) to drive STS, then
            // assume the requested role.
            let base = aws_config::defaults(BehaviorVersion::latest())
                .region(region_obj.clone())
                .load()
                .await;
            let sts_client = sts::Client::new(&base);
            let mut assume = sts_client
                .assume_role()
                .role_arn(&role_arn)
                .role_session_name(session_name.unwrap_or_else(|| "sbproxy".to_string()));
            if let Some(eid) = external_id {
                assume = assume.external_id(eid);
            }
            let response = assume.send().await.with_context(|| {
                format!("AWS Secrets Manager: STS AssumeRole `{role_arn}` failed")
            })?;
            let stsc = response.credentials().ok_or_else(|| {
                anyhow!("AWS Secrets Manager: STS AssumeRole returned no credentials")
            })?;
            let creds = Credentials::new(
                stsc.access_key_id().to_string(),
                stsc.secret_access_key().to_string(),
                Some(stsc.session_token().to_string()),
                None,
                "sbproxy-sts",
            );
            cfg_builder.credentials_provider(creds).load().await
        }
    };

    Ok(smc::Client::new(&sdk_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> AwsSecretsManagerConfig {
        AwsSecretsManagerConfig {
            region: "us-east-1".to_string(),
            auth: AwsAuth::StaticKeys {
                access_key_id: "AKIA".repeat(5),
                secret_access_key: "x".repeat(40),
                session_token: None,
            },
            mount_prefix: "prod/sbproxy".to_string(),
            cache_ttl: Some(Duration::from_secs(60)),
        }
    }

    /// Construction rejects an empty region / mount / auth material so
    /// a misconfig fails at config-load.
    #[test]
    fn construction_validates_required_fields() {
        let mut c = base_cfg();
        c.region = String::new();
        assert!(AwsSecretsManagerBackend::new(c).is_err());

        let mut c = base_cfg();
        c.mount_prefix = String::new();
        assert!(AwsSecretsManagerBackend::new(c).is_err());

        let mut c = base_cfg();
        c.auth = AwsAuth::StaticKeys {
            access_key_id: String::new(),
            secret_access_key: "x".to_string(),
            session_token: None,
        };
        assert!(AwsSecretsManagerBackend::new(c).is_err());
    }

    /// Empty role ARN is rejected at config-load.
    #[test]
    fn construction_rejects_empty_assumed_role_arn() {
        let cfg = AwsSecretsManagerConfig {
            region: "us-east-1".to_string(),
            auth: AwsAuth::AssumedRole {
                role_arn: String::new(),
                external_id: None,
                session_name: None,
            },
            mount_prefix: "prod/sbproxy".to_string(),
            cache_ttl: None,
        };
        let err = AwsSecretsManagerBackend::new(cfg)
            .err()
            .expect("construction should reject empty role_arn");
        assert!(format!("{err}").contains("role_arn"));
    }

    /// Build a backend for URL / cache / prefix testing without
    /// performing any AWS calls. Bypasses the constructor so we
    /// don't initialise the platform TLS roots for a client that will
    /// never send traffic.
    fn test_backend(mount: &str, ttl: Duration) -> AwsSecretsManagerBackend {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        AwsSecretsManagerBackend {
            inner: BackendInner {
                client: None,
                mount_prefix: mount.trim_matches('/').to_string(),
                cache_ttl: ttl,
                rt,
            },
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// A relative path lands under the configured prefix.
    #[test]
    fn resolve_name_prepends_mount_prefix() {
        let b = test_backend("prod/sbproxy", Duration::from_secs(60));
        let name = b.resolve_name("openai-prod").unwrap();
        assert_eq!(name, "prod/sbproxy/openai-prod");
    }

    /// A path that already encodes the mount is taken verbatim.
    #[test]
    fn resolve_name_accepts_explicit_prefix() {
        let b = test_backend("prod/sbproxy", Duration::from_secs(60));
        let name = b.resolve_name("prod/sbproxy/team-a/openai").unwrap();
        assert_eq!(name, "prod/sbproxy/team-a/openai");
    }

    /// Tenant-isolated multi-segment prefix.
    #[test]
    fn resolve_name_supports_tenant_isolated_prefix() {
        let b = test_backend("prod/sbproxy/tenants/acme-corp", Duration::from_secs(60));
        let name = b.resolve_name("openai-prod").unwrap();
        assert_eq!(name, "prod/sbproxy/tenants/acme-corp/openai-prod");
    }

    /// `..` segments are rejected outright.
    #[test]
    fn resolve_name_rejects_directory_traversal() {
        let b = test_backend("prod/sbproxy/tenants/acme-corp", Duration::from_secs(60));
        let err = b
            .resolve_name("../beta-corp/openai")
            .expect_err("traversal should be rejected");
        assert!(format!("{err}").contains(".."));
    }

    /// Partial-prefix collision (`prods/...` against mount `prod`) is
    /// rejected by the suffix guard.
    #[test]
    fn resolve_name_rejects_partial_prefix_collision() {
        let b = test_backend("prod", Duration::from_secs(60));
        let err = b
            .resolve_name("prods/sbproxy/openai")
            .expect_err("partial collision should be rejected");
        assert!(format!("{err}").contains("escapes mount prefix"));
    }

    /// Empty path after normalisation is rejected.
    #[test]
    fn resolve_name_rejects_empty_path() {
        let b = test_backend("prod/sbproxy", Duration::from_secs(60));
        let err = b.resolve_name("///").expect_err("empty path");
        assert!(format!("{err}").contains("empty path"));
    }

    /// Cache short-circuits subsequent reads of the same key within
    /// the TTL window. Verifies the cache hit path without an HTTP
    /// call.
    #[test]
    fn cache_short_circuits_within_ttl() {
        let b = test_backend("prod/sbproxy", Duration::from_secs(60));
        b.cache_store(
            "team-a/openai".to_string(),
            "{\"api_key\":\"sk-test\"}".to_string(),
        );
        assert_eq!(
            b.cache_hit("team-a/openai").as_deref(),
            Some("{\"api_key\":\"sk-test\"}")
        );
    }

    /// Clearing the cache drops every entry.
    #[test]
    fn clear_cache_drops_every_entry() {
        let b = test_backend("prod/sbproxy", Duration::from_secs(60));
        b.cache_store("k1".into(), "v1".into());
        b.cache_store("k2".into(), "v2".into());
        b.clear_cache();
        assert!(b.cache_hit("k1").is_none());
        assert!(b.cache_hit("k2").is_none());
    }

    /// An already-expired cache entry is evicted on read so the
    /// next call goes through to the SDK.
    #[test]
    fn expired_cache_entry_is_dropped_on_read() {
        let b = test_backend("prod/sbproxy", Duration::from_secs(60));
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
}
