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
//!
//! # Concurrent mutation
//!
//! One mutation is several round trips (index, record, revision) with no
//! transaction and no rollback around them, and two of those touch a secret
//! shared by every record of that kind. Three things keep that from losing
//! writes, and none of them is a real compare-and-set:
//!
//! * Mutations are serialized within the process by a lock, so two admin
//!   requests on one replica cannot interleave.
//! * The index and revision writes read back what they wrote and re-apply on
//!   a mismatch, which narrows (does not close) the window against a writer
//!   this process cannot see: a second replica on the same prefix, or an
//!   operator editing the secret by hand.
//! * The order within a mutation is chosen so the half-applied states are
//!   the survivable ones. An index entry with no record behind it is skipped
//!   by `list_keys`; a record with no index entry is a key that
//!   authenticates and that nothing can enumerate or revoke.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use sbproxy_vault::VaultBackend;

use crate::record::{CredentialRecord, KeyRecord};
use crate::{KeyPolicyCasResult, KeyStore};

/// Sentinel written in place of a deleted secret, since the backend has no
/// delete. A `get` returning this is treated as absent.
const TOMBSTONE: &str = "\u{0}__sbproxy_keystore_deleted__";

/// Read-modify-write attempts before a shared-secret update gives up.
///
/// `VaultBackend` is `get` / `set` with no conditional write, so the index
/// and revision secrets are updated by reading, editing, and writing back.
/// Two writers that read the same pre-image both write, and the second one
/// wins: an id vanishes from the index (a live key that `list_keys` cannot
/// see and the console cannot revoke) or a revision bump is lost (peer
/// caches never learn a record changed). Reading back after the write turns
/// that silent loss into a retry.
const RMW_ATTEMPTS: usize = 5;

/// A `KeyStore` whose system of record is an external secrets manager.
pub struct SecretsManagerKeyStore {
    backend: Arc<dyn VaultBackend>,
    prefix: String,
    /// Serializes every mutation so the read-modify-write sequences on the
    /// shared index and revision secrets cannot interleave.
    ///
    /// This covers one process. It does not cover a second sbproxy replica
    /// pointed at the same vault prefix, an operator editing the secret by
    /// hand, or any other external writer. Against those, the read-back
    /// retry governed by `RMW_ATTEMPTS` is the whole defense, and it
    /// narrows the race rather than closing it. Closing it needs a
    /// conditional write, which is exactly the primitive
    /// `put_key_if_revision` reports as [`KeyPolicyCasResult::Unsupported`]
    /// on this backend.
    mutation_lock: tokio::sync::Mutex<()>,
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
            mutation_lock: tokio::sync::Mutex::new(()),
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

    /// Add `id` to the index at `path`, re-applying if a concurrent writer
    /// clobbered the write. See [`RMW_ATTEMPTS`] for why the read-back is
    /// not optional: an id missing from the index is a key that
    /// authenticates and that nothing can list or revoke.
    async fn index_insert(&self, path: String, id: &str) -> Result<()> {
        for _ in 0..RMW_ATTEMPTS {
            let mut ids = self.read_index(path.clone()).await?;
            if ids.iter().any(|i| i == id) {
                return Ok(());
            }
            ids.push(id.to_string());
            self.write_index(path.clone(), &ids).await?;
            if self.read_index(path.clone()).await?.iter().any(|i| i == id) {
                return Ok(());
            }
        }
        anyhow::bail!(
            "index '{path}' lost the insert of '{id}' to a concurrent writer \
             {RMW_ATTEMPTS} times; the record was not written"
        )
    }

    /// Drop `id` from the index at `path`, re-applying if a concurrent
    /// writer put it back.
    async fn index_remove(&self, path: String, id: &str) -> Result<()> {
        for _ in 0..RMW_ATTEMPTS {
            let mut ids = self.read_index(path.clone()).await?;
            let before = ids.len();
            ids.retain(|i| i != id);
            if ids.len() == before {
                return Ok(());
            }
            self.write_index(path.clone(), &ids).await?;
            if !self.read_index(path.clone()).await?.iter().any(|i| i == id) {
                return Ok(());
            }
        }
        anyhow::bail!(
            "index '{path}' lost the removal of '{id}' to a concurrent writer \
             {RMW_ATTEMPTS} times"
        )
    }

    async fn read_revision(&self) -> Result<u64> {
        Ok(match self.get_raw(self.revision_path()).await? {
            Some(s) => s.parse().unwrap_or(0),
            None => 0,
        })
    }

    /// Move the fleet-visible revision forward.
    ///
    /// Peers only compare this value for change, so any observed value at or
    /// above the one we wrote means the bump landed, whether it was ours or
    /// a concurrent writer's larger one. A bump that is silently lost is a
    /// revoke that no peer's `TtlCache` ever notices.
    async fn bump_revision(&self) -> Result<()> {
        for _ in 0..RMW_ATTEMPTS {
            let next = self.read_revision().await? + 1;
            self.set_raw(self.revision_path(), next.to_string()).await?;
            if self.read_revision().await? >= next {
                return Ok(());
            }
        }
        anyhow::bail!(
            "keystore revision bump lost to a concurrent writer {RMW_ATTEMPTS} times; \
             peer caches will not see this mutation until their TTL lapses"
        )
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
        let _guard = self.mutation_lock.lock().await;
        // Index first, record second. There is no rollback across three
        // separate vault round trips, so the ordering decides which
        // half-applied state a mid-sequence failure leaves behind. A
        // dangling index entry is harmless: `list_keys` skips an id whose
        // record reads as absent. A committed record that never reached the
        // index is a key that authenticates and that nobody can list or
        // revoke.
        self.index_insert(self.key_index_path(), &record.key_id)
            .await?;
        self.set_raw(self.key_path(&record.key_id), json).await?;
        self.bump_revision().await
    }

    async fn put_key_if_revision(
        &self,
        _record: KeyRecord,
        _expected_revision: u64,
    ) -> Result<KeyPolicyCasResult> {
        // VaultBackend exposes get/set but no conditional write or version
        // precondition shared by every provider. A read-then-set sequence would
        // lose concurrent updates, so policy mutation fails closed.
        Ok(KeyPolicyCasResult::Unsupported)
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        let _guard = self.mutation_lock.lock().await;
        // Tombstone first. Once the record reads as absent the key stops
        // authenticating, which is the part of a revoke that must not be
        // left half-done; a leftover index entry only makes `list_keys`
        // skip an id.
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
        let _guard = self.mutation_lock.lock().await;
        // Index before record, for the reason spelled out on `put_key`.
        self.index_insert(self.cred_index_path(), &record.id)
            .await?;
        self.set_raw(self.cred_path(&record.id), json).await?;
        self.bump_revision().await
    }

    async fn delete_credential(&self, id: &str) -> Result<()> {
        let _guard = self.mutation_lock.lock().await;
        self.set_raw(self.cred_path(id), TOMBSTONE.to_string())
            .await?;
        self.index_remove(self.cred_index_path(), id).await?;
        self.bump_revision().await
    }

    async fn revision(&self) -> Result<u64> {
        self.read_revision().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{CredentialMaterial, RecordStatus};
    use crate::KeyPolicyCasResult;
    use chrono::{DateTime, Utc};
    use sbproxy_vault::LocalVault;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A vault whose index writes always fail, standing in for a 503 or an
    /// expired token that arrives partway through a mutation.
    struct IndexWriteRefused {
        inner: LocalVault,
    }

    impl VaultBackend for IndexWriteRefused {
        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }
        fn set(&self, key: &str, value: &str) -> Result<()> {
            if key.ends_with("/key-index") {
                anyhow::bail!("vault unavailable");
            }
            self.inner.set(key, value)
        }
    }

    /// A vault that overwrites the key index once, immediately after it is
    /// written, standing in for a second writer that read the same
    /// pre-image and wrote its own array over ours.
    struct ClobbersTheIndexOnce {
        inner: LocalVault,
        clobbered: AtomicBool,
    }

    impl VaultBackend for ClobbersTheIndexOnce {
        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }
        fn set(&self, key: &str, value: &str) -> Result<()> {
            self.inner.set(key, value)?;
            if key.ends_with("/key-index") && !self.clobbered.swap(true, Ordering::SeqCst) {
                self.inner.set(key, r#"["other"]"#)?;
            }
            Ok(())
        }
    }

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
            header: crate::record::default_cred_header(),
            scheme: crate::record::default_cred_scheme(),
            material: CredentialMaterial::VaultRef {
                reference: "vault://openai".into(),
            },
            status: RecordStatus::Active,
            tenant_id: None,
            metadata: Default::default(),
            created_at: ts(),
            updated_at: ts(),
            source: Default::default(),
            rotated_at: None,
            prev_material: None,
            prev_material_expires_at: None,
        };
        s.put_credential(cred.clone()).await.unwrap();
        assert_eq!(s.get_credential("c1").await.unwrap().unwrap(), cred);
        assert_eq!(s.list_credentials().await.unwrap().len(), 1);
        s.delete_credential("c1").await.unwrap();
        assert!(s.get_credential("c1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_record_the_index_refused_is_never_committed() {
        // The seam: the order of the three writes inside `put_key`. Writing
        // the record first meant a failing index write returned Err to the
        // caller with the record already committed and unlisted, which is a
        // key that authenticates while `list_keys`, the admin console, and
        // reload precedence cannot see it.
        let backend: Arc<dyn VaultBackend> = Arc::new(IndexWriteRefused {
            inner: LocalVault::new(),
        });
        let s = SecretsManagerKeyStore::new(backend, "sbproxy/keystore");

        assert!(
            s.put_key(KeyRecord::new("k1", "h1", ts())).await.is_err(),
            "a refused index write must fail the mutation"
        );
        assert!(
            s.get_key("k1").await.unwrap().is_none(),
            "an unindexed record must not be left behind: it would authenticate \
             while nothing could list or revoke it"
        );
        assert!(s.list_keys().await.unwrap().is_empty());
        assert_eq!(
            s.revision().await.unwrap(),
            0,
            "a mutation that did not land must not move the fleet revision"
        );
    }

    #[tokio::test]
    async fn an_index_write_lost_to_a_concurrent_writer_is_re_applied() {
        // The seam: `index_insert`'s read-modify-write. Without the
        // read-back, the losing writer's id is gone from the index forever
        // while its record stays live and authenticating.
        let backend: Arc<dyn VaultBackend> = Arc::new(ClobbersTheIndexOnce {
            inner: LocalVault::new(),
            clobbered: AtomicBool::new(false),
        });
        let s = SecretsManagerKeyStore::new(backend, "sbproxy/keystore");

        s.put_key(KeyRecord::new("k1", "h1", ts())).await.unwrap();

        let ids = s.read_index(s.key_index_path()).await.unwrap();
        assert!(
            ids.iter().any(|i| i == "k1"),
            "the clobbered insert must be re-applied; index was {ids:?}"
        );
        assert!(
            ids.iter().any(|i| i == "other"),
            "re-applying must merge onto the winner's array, not overwrite it; \
             index was {ids:?}"
        );
        assert_eq!(s.list_keys().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn key_policy_cas_fails_closed_when_backend_has_no_atomic_primitive() {
        let s = store();
        s.put_key(KeyRecord::new("k1", "hash", ts())).await.unwrap();
        let mut candidate = s.get_key("k1").await.unwrap().unwrap();
        candidate.name = Some("unsafe update".into());

        assert_eq!(
            s.put_key_if_revision(candidate, 1).await.unwrap(),
            KeyPolicyCasResult::Unsupported
        );
        let stored = s.get_key("k1").await.unwrap().unwrap();
        assert_eq!(stored.policy_revision, 1);
        assert!(stored.name.is_none());
        assert_eq!(s.revision().await.unwrap(), 1);
    }
}
