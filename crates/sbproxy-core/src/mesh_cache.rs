//! WOR-1562: mesh distributed-cache tier for the key plane's [`TtlCache`].
//!
//! Wraps a mesh [`DistributedCache<Bytes>`] as a key-plane
//! [`CacheTier`](sbproxy_keystore::CacheTier). Records are serialized to JSON
//! and stored on the local shard with a TTL; the mesh gossip loop replicates
//! shard state across the cluster, and the consistent-hash ring makes a key's
//! owner deterministic, so a record cached on one replica is visible to the
//! others. When the cache is not attached to a running mesh node it degrades to
//! a local-only second tier with a background sweeper.
//!
//! [`TtlCache`]: sbproxy_keystore::TtlCache

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use sbproxy_keystore::record::{CredentialRecord, KeyRecord};
use sbproxy_keystore::CacheTier;
use sbproxy_mesh::state::distributed_cache::DistributedCache;

/// Default virtual nodes for the key-plane mesh ring.
const MESH_VNODES: usize = 128;

const KEY_PREFIX: &str = "keymgmt:key:";
const CRED_PREFIX: &str = "keymgmt:cred:";

/// A [`CacheTier`] backed by the mesh distributed cache.
pub struct MeshCacheTier {
    cache: Arc<DistributedCache<Bytes>>,
}

impl MeshCacheTier {
    /// Wrap an existing distributed cache (for example a running mesh node's
    /// `distributed_cache()`).
    pub fn new(cache: Arc<DistributedCache<Bytes>>) -> Self {
        Self { cache }
    }

    /// Build a standalone single-node distributed cache for `node_id` with a
    /// background sweeper, then wrap it. The cache replicates clusterwide once
    /// the node joins a mesh; on its own it is a local sweeping tier.
    pub fn standalone(node_id: &str) -> Self {
        let cache = DistributedCache::<Bytes>::new_with_sweeper(
            node_id,
            MESH_VNODES,
            sbproxy_mesh::state::distributed_cache::DEFAULT_SWEEP_INTERVAL_SECS,
        );
        Self { cache }
    }
}

#[async_trait]
impl CacheTier for MeshCacheTier {
    async fn get_key(&self, key_id: &str) -> Option<KeyRecord> {
        let raw = self.cache.get_local(&format!("{KEY_PREFIX}{key_id}"))?;
        serde_json::from_slice(&raw).ok()
    }

    async fn put_key(&self, record: &KeyRecord, ttl: Duration) {
        if let Ok(json) = serde_json::to_vec(record) {
            self.cache.put_local_with_ttl(
                &format!("{KEY_PREFIX}{}", record.key_id),
                Bytes::from(json),
                ttl.as_secs().max(1),
            );
        }
    }

    async fn get_credential(&self, id: &str) -> Option<CredentialRecord> {
        let raw = self.cache.get_local(&format!("{CRED_PREFIX}{id}"))?;
        serde_json::from_slice(&raw).ok()
    }

    async fn put_credential(&self, record: &CredentialRecord, ttl: Duration) {
        if let Ok(json) = serde_json::to_vec(record) {
            self.cache.put_local_with_ttl(
                &format!("{CRED_PREFIX}{}", record.id),
                Bytes::from(json),
                ttl.as_secs().max(1),
            );
        }
    }

    async fn invalidate(&self, id: &str) {
        self.cache.delete_local(&format!("{KEY_PREFIX}{id}"));
        self.cache.delete_local(&format!("{CRED_PREFIX}{id}"));
    }

    async fn invalidate_all(&self) {
        self.cache.purge_all_local();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn mesh_tier_round_trips_a_key_record() {
        let tier = MeshCacheTier::standalone("node-a");
        let rec = KeyRecord::new("k1", "h1", Utc::now());
        assert!(tier.get_key("k1").await.is_none());

        tier.put_key(&rec, Duration::from_secs(60)).await;
        let got = tier.get_key("k1").await.expect("present after put");
        assert_eq!(got.key_id, "k1");

        tier.invalidate("k1").await;
        assert!(tier.get_key("k1").await.is_none(), "invalidate drops it");
    }

    #[tokio::test]
    async fn mesh_tier_round_trips_a_credential_and_purges_all() {
        let tier = MeshCacheTier::standalone("node-b");
        let cred = CredentialRecord {
            id: "c1".into(),
            name: "openai".into(),
            provider: Some("openai".into()),
            kind: "ai_provider".into(),
            material: sbproxy_keystore::record::CredentialMaterial::VaultRef {
                reference: "vault://openai".into(),
            },
            status: sbproxy_keystore::record::RecordStatus::Active,
            tenant_id: None,
            metadata: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            source: Default::default(),
        };
        tier.put_credential(&cred, Duration::from_secs(60)).await;
        assert!(tier.get_credential("c1").await.is_some());

        tier.invalidate_all().await;
        assert!(
            tier.get_credential("c1").await.is_none(),
            "purge_all clears it"
        );
    }
}
