//! In-memory [`KeyStore`] backend.
//!
//! Holds records in two `parking_lot::RwLock`-guarded maps. Used by tests and
//! as an ephemeral store when no durable backend is configured. Not persisted:
//! a restart starts empty (so the config seed is re-applied on boot).

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::record::{CredentialRecord, KeyRecord};
use crate::{KeyPolicyCasResult, KeyStore};

/// An in-memory, non-persistent key store.
#[derive(Default)]
pub struct MemoryKeyStore {
    keys: RwLock<HashMap<String, KeyRecord>>,
    credentials: RwLock<HashMap<String, CredentialRecord>>,
    revision: AtomicU64,
}

impl MemoryKeyStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn bump(&self) {
        self.revision.fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        Ok(self.keys.read().get(key_id).cloned())
    }

    async fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        Ok(self.keys.read().values().cloned().collect())
    }

    async fn put_key(&self, record: KeyRecord) -> Result<()> {
        self.keys.write().insert(record.key_id.clone(), record);
        self.bump();
        Ok(())
    }

    async fn put_key_if_revision(
        &self,
        mut record: KeyRecord,
        expected_revision: u64,
    ) -> Result<KeyPolicyCasResult> {
        let mut keys = self.keys.write();
        let Some(current) = keys.get(&record.key_id) else {
            return Ok(KeyPolicyCasResult::NotFound);
        };
        if current.policy_revision != expected_revision {
            return Ok(KeyPolicyCasResult::Conflict {
                actual_revision: current.policy_revision,
            });
        }

        let policy_revision = crate::next_policy_revision(expected_revision)?;
        record.policy_revision = policy_revision;
        keys.insert(record.key_id.clone(), record);
        self.bump();
        Ok(KeyPolicyCasResult::Applied { policy_revision })
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        self.keys.write().remove(key_id);
        self.bump();
        Ok(())
    }

    async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        Ok(self.credentials.read().get(id).cloned())
    }

    async fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        Ok(self.credentials.read().values().cloned().collect())
    }

    async fn put_credential(&self, record: CredentialRecord) -> Result<()> {
        self.credentials.write().insert(record.id.clone(), record);
        self.bump();
        Ok(())
    }

    async fn delete_credential(&self, id: &str) -> Result<()> {
        self.credentials.write().remove(id);
        self.bump();
        Ok(())
    }

    async fn revision(&self) -> Result<u64> {
        Ok(self.revision.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{CredentialMaterial, RecordStatus};
    use crate::KeyPolicyCasResult;
    use chrono::{DateTime, Utc};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[tokio::test]
    async fn key_crud_roundtrip_and_revision() {
        let store = MemoryKeyStore::new();
        assert_eq!(store.revision().await.unwrap(), 0);

        let rec = KeyRecord::new("abc", "hash", now());
        store.put_key(rec.clone()).await.unwrap();
        assert_eq!(store.revision().await.unwrap(), 1);

        let got = store.get_key("abc").await.unwrap().unwrap();
        assert_eq!(got.key_id, "abc");
        assert_eq!(store.list_keys().await.unwrap().len(), 1);

        store.delete_key("abc").await.unwrap();
        assert!(store.get_key("abc").await.unwrap().is_none());
        assert_eq!(store.revision().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn credential_crud_roundtrip() {
        let store = MemoryKeyStore::new();
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
            created_at: now(),
            updated_at: now(),
            source: Default::default(),
        };
        store.put_credential(cred.clone()).await.unwrap();
        let got = store.get_credential("c1").await.unwrap().unwrap();
        assert_eq!(got, cred);
        assert_eq!(store.list_credentials().await.unwrap().len(), 1);
        store.delete_credential("c1").await.unwrap();
        assert!(store.get_credential("c1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn key_policy_cas_is_monotonic_and_rejects_stale_writes() {
        let store = MemoryKeyStore::new();
        store
            .put_key(KeyRecord::new("k1", "hash", now()))
            .await
            .unwrap();

        let mut first = store.get_key("k1").await.unwrap().unwrap();
        first.name = Some("first".into());
        assert_eq!(
            store.put_key_if_revision(first, 1).await.unwrap(),
            KeyPolicyCasResult::Applied { policy_revision: 2 }
        );

        let mut stale = store.get_key("k1").await.unwrap().unwrap();
        stale.name = Some("stale".into());
        assert_eq!(
            store.put_key_if_revision(stale, 1).await.unwrap(),
            KeyPolicyCasResult::Conflict { actual_revision: 2 }
        );

        let stored = store.get_key("k1").await.unwrap().unwrap();
        assert_eq!(stored.policy_revision, 2);
        assert_eq!(stored.name.as_deref(), Some("first"));
        assert_eq!(store.revision().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn key_policy_cas_reports_missing_without_creating_a_record() {
        let store = MemoryKeyStore::new();
        let candidate = KeyRecord::new("missing", "hash", now());

        assert_eq!(
            store.put_key_if_revision(candidate, 1).await.unwrap(),
            KeyPolicyCasResult::NotFound
        );
        assert!(store.get_key("missing").await.unwrap().is_none());
        assert_eq!(store.revision().await.unwrap(), 0);
    }
}
