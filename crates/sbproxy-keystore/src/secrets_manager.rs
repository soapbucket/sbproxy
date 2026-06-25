//! Secrets-manager-direct [`KeyStore`] backend.
//!
//! Wraps any [`sbproxy_vault::VaultBackend`] (HashiCorp, AWS/GCP Secrets
//! Manager, ...) so the secrets manager itself is the system of record for keys
//! and credentials, for operators who want exactly one place secrets live.
//!
//! The `VaultBackend` surface is `get` / `set` only (no list, no delete), so
//! this backend keeps an index secret per record kind (a JSON array of ids) to
//! enumerate, and tombstones on delete. The trait is synchronous; calls run on
//! `spawn_blocking` because some backends do blocking network I/O. This store
//! sits behind the [`TtlCache`](crate::cache::TtlCache), so the round trips are
//! off the hot path.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use sbproxy_vault::VaultBackend;

use crate::record::{CredentialRecord, KeyRecord};
use crate::KeyStore;

/// Sentinel written in place of a deleted secret, since the backend has no
/// delete. A `get` returning this is treated as absent.
const TOMBSTONE: &str = "\u{0}__sbproxy_keystore_deleted__";

/// A `KeyStore` whose system of record is an external secrets manager.
pub struct SecretsManagerKeyStore {
    backend: Arc<dyn VaultBackend>,
    prefix: String,
}

/// Which writable external secrets manager backs the store. Only backends with
/// a real `set` are usable as a mutable system of record (AWS Secrets Manager,
/// HashiCorp Vault, and the in-memory local store for dev/tests); GCP, file, and
/// Kubernetes backends are read-only and not offered here.
#[derive(Debug, Clone)]
pub enum SecretsManagerProvider {
    /// In-memory, non-persistent. For dev and tests only.
    Local,
    /// HashiCorp Vault KV. Token auth; the token is read from the named env var.
    Hashicorp {
        /// Vault address, e.g. `https://vault.example/v1`.
        addr: String,
        /// KV mount path (e.g. `secret`).
        mount: String,
        /// Use KV engine v2 (the modern default) vs v1.
        kv_v2: bool,
        /// Environment variable holding the Vault token.
        token_env: String,
        /// Optional `X-Vault-Namespace` (Vault Enterprise).
        namespace: Option<String>,
    },
    /// AWS Secrets Manager via the default credential chain (IAM role, env,
    /// instance/task profile).
    Aws {
        /// AWS region, e.g. `us-east-1`.
        region: String,
        /// Path prefix every secret stays inside.
        mount_prefix: String,
    },
}

/// A build spec for a secrets-manager-direct store, lowered from config.
#[derive(Debug, Clone)]
pub struct SecretsManagerSpec {
    /// The external manager.
    pub provider: SecretsManagerProvider,
    /// Namespace prefix for all keystore records.
    pub prefix: String,
}

impl SecretsManagerKeyStore {
    /// Wrap a vault backend, namespacing all secrets under `prefix` (for
    /// example `sbproxy/keystore`).
    pub fn new(backend: Arc<dyn VaultBackend>, prefix: impl Into<String>) -> Self {
        Self {
            backend,
            prefix: prefix.into(),
        }
    }

    /// Build a store from a [`SecretsManagerSpec`], constructing the underlying
    /// writable vault backend. HashiCorp reads its token from the configured
    /// environment variable; AWS uses the default credential chain.
    pub fn from_spec(spec: SecretsManagerSpec) -> anyhow::Result<Self> {
        let backend: Arc<dyn VaultBackend> = match spec.provider {
            SecretsManagerProvider::Local => Arc::new(sbproxy_vault::LocalVault::new()),
            SecretsManagerProvider::Hashicorp {
                addr,
                mount,
                kv_v2,
                token_env,
                namespace,
            } => {
                let token = std::env::var(&token_env).with_context(|| {
                    format!("read HashiCorp token from env '{token_env}' for the secrets-manager keystore")
                })?;
                let cfg = sbproxy_vault::HashiCorpConfig {
                    addr,
                    auth: sbproxy_vault::HashiCorpAuth::Token { token },
                    mount,
                    engine: if kv_v2 {
                        sbproxy_vault::KvEngine::V2
                    } else {
                        sbproxy_vault::KvEngine::V1
                    },
                    cache_ttl: None,
                    namespace,
                };
                Arc::new(
                    sbproxy_vault::HashiCorpVaultBackend::new(cfg).context(
                        "build HashiCorp Vault backend for the secrets-manager keystore",
                    )?,
                )
            }
            SecretsManagerProvider::Aws {
                region,
                mount_prefix,
            } => {
                let cfg = sbproxy_vault::AwsSecretsManagerConfig {
                    region,
                    auth: sbproxy_vault::AwsAuth::DefaultChain,
                    mount_prefix,
                    cache_ttl: None,
                };
                Arc::new(sbproxy_vault::AwsSecretsManagerBackend::new(cfg).context(
                    "build AWS Secrets Manager backend for the secrets-manager keystore",
                )?)
            }
        };
        Ok(Self::new(backend, spec.prefix))
    }

    fn key_path(&self, key_id: &str) -> String {
        format!("{}/key/{key_id}", self.prefix)
    }
    fn cred_path(&self, id: &str) -> String {
        format!("{}/cred/{id}", self.prefix)
    }
    fn key_index_path(&self) -> String {
        format!("{}/key-index", self.prefix)
    }
    fn cred_index_path(&self) -> String {
        format!("{}/cred-index", self.prefix)
    }
    fn revision_path(&self) -> String {
        format!("{}/revision", self.prefix)
    }

    async fn get_raw(&self, path: String) -> Result<Option<String>> {
        let backend = self.backend.clone();
        let value = tokio::task::spawn_blocking(move || backend.get(&path))
            .await
            .context("vault get task")??;
        Ok(value.filter(|v| v != TOMBSTONE))
    }

    async fn set_raw(&self, path: String, value: String) -> Result<()> {
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || backend.set(&path, &value))
            .await
            .context("vault set task")?
    }

    async fn read_index(&self, path: String) -> Result<Vec<String>> {
        match self.get_raw(path).await? {
            Some(json) => serde_json::from_str(&json).context("decode index"),
            None => Ok(Vec::new()),
        }
    }

    async fn write_index(&self, path: String, ids: &[String]) -> Result<()> {
        let json = serde_json::to_string(ids).context("encode index")?;
        self.set_raw(path, json).await
    }

    async fn index_insert(&self, path: String, id: &str) -> Result<()> {
        let mut ids = self.read_index(path.clone()).await?;
        if !ids.iter().any(|i| i == id) {
            ids.push(id.to_string());
            self.write_index(path, &ids).await?;
        }
        Ok(())
    }

    async fn index_remove(&self, path: String, id: &str) -> Result<()> {
        let mut ids = self.read_index(path.clone()).await?;
        let before = ids.len();
        ids.retain(|i| i != id);
        if ids.len() != before {
            self.write_index(path, &ids).await?;
        }
        Ok(())
    }

    async fn bump_revision(&self) -> Result<()> {
        let path = self.revision_path();
        let current: u64 = match self.get_raw(path.clone()).await? {
            Some(s) => s.parse().unwrap_or(0),
            None => 0,
        };
        self.set_raw(path, (current + 1).to_string()).await
    }
}

#[async_trait]
impl KeyStore for SecretsManagerKeyStore {
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        match self.get_raw(self.key_path(key_id)).await? {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).context("decode key record")?,
            )),
            None => Ok(None),
        }
    }

    async fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        let ids = self.read_index(self.key_index_path()).await?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(rec) = self.get_key(&id).await? {
                out.push(rec);
            }
        }
        Ok(out)
    }

    async fn put_key(&self, record: KeyRecord) -> Result<()> {
        let json = serde_json::to_string(&record).context("encode key record")?;
        self.set_raw(self.key_path(&record.key_id), json).await?;
        self.index_insert(self.key_index_path(), &record.key_id)
            .await?;
        self.bump_revision().await
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        self.set_raw(self.key_path(key_id), TOMBSTONE.to_string())
            .await?;
        self.index_remove(self.key_index_path(), key_id).await?;
        self.bump_revision().await
    }

    async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        match self.get_raw(self.cred_path(id)).await? {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).context("decode credential record")?,
            )),
            None => Ok(None),
        }
    }

    async fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        let ids = self.read_index(self.cred_index_path()).await?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(rec) = self.get_credential(&id).await? {
                out.push(rec);
            }
        }
        Ok(out)
    }

    async fn put_credential(&self, record: CredentialRecord) -> Result<()> {
        let json = serde_json::to_string(&record).context("encode credential record")?;
        self.set_raw(self.cred_path(&record.id), json).await?;
        self.index_insert(self.cred_index_path(), &record.id)
            .await?;
        self.bump_revision().await
    }

    async fn delete_credential(&self, id: &str) -> Result<()> {
        self.set_raw(self.cred_path(id), TOMBSTONE.to_string())
            .await?;
        self.index_remove(self.cred_index_path(), id).await?;
        self.bump_revision().await
    }

    async fn revision(&self) -> Result<u64> {
        Ok(match self.get_raw(self.revision_path()).await? {
            Some(s) => s.parse().unwrap_or(0),
            None => 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{CredentialMaterial, RecordStatus};
    use chrono::{DateTime, Utc};
    use sbproxy_vault::LocalVault;

    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn store() -> SecretsManagerKeyStore {
        let backend: Arc<dyn VaultBackend> = Arc::new(LocalVault::new());
        SecretsManagerKeyStore::new(backend, "sbproxy/keystore")
    }

    #[tokio::test]
    async fn from_spec_local_builds_a_working_store() {
        let s = SecretsManagerKeyStore::from_spec(SecretsManagerSpec {
            provider: SecretsManagerProvider::Local,
            prefix: "sbproxy/keystore".into(),
        })
        .expect("build local secrets-manager store");
        s.put_key(KeyRecord::new("k1", "h1", ts())).await.unwrap();
        assert!(s.get_key("k1").await.unwrap().is_some());
        assert_eq!(s.revision().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn key_crud_via_vault_backend() {
        let s = store();
        assert_eq!(s.revision().await.unwrap(), 0);
        assert!(s.list_keys().await.unwrap().is_empty());

        let mut rec = KeyRecord::new("k1", "h1", ts());
        rec.name = Some("one".into());
        s.put_key(rec).await.unwrap();
        assert_eq!(s.revision().await.unwrap(), 1);

        let got = s.get_key("k1").await.unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("one"));

        s.put_key(KeyRecord::new("k2", "h2", ts())).await.unwrap();
        assert_eq!(s.list_keys().await.unwrap().len(), 2);

        s.delete_key("k1").await.unwrap();
        assert!(s.get_key("k1").await.unwrap().is_none());
        assert_eq!(s.list_keys().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn credential_crud_via_vault_backend() {
        let s = store();
        let cred = CredentialRecord {
            id: "c1".into(),
            name: "openai".into(),
            provider: Some("openai".into()),
            kind: "ai_provider".into(),
            material: CredentialMaterial::VaultRef {
                reference: "vault://openai".into(),
            },
            status: RecordStatus::Active,
            tenant_id: None,
            metadata: Default::default(),
            created_at: ts(),
            updated_at: ts(),
            source: Default::default(),
        };
        s.put_credential(cred.clone()).await.unwrap();
        assert_eq!(s.get_credential("c1").await.unwrap().unwrap(), cred);
        assert_eq!(s.list_credentials().await.unwrap().len(), 1);
        s.delete_credential("c1").await.unwrap();
        assert!(s.get_credential("c1").await.unwrap().is_none());
    }
}
