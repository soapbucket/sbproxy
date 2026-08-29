//! WOR-1562 / WOR-1565: mesh distributed-cache tier for the key plane's `TtlCache`.
//!
//! Wraps a mesh `DistributedCache<Bytes>` as a key-plane
//! [`CacheTier`](sbproxy_keystore::CacheTier). Records are serialized to JSON.
//!
//! Two modes:
//!
//! * **Standalone** (single node): local-shard get/put/delete with a background
//!   sweeper. Useful without a cluster.
//! * **Clustered**: backed by a bootstrapped [`MeshNode`](sbproxy_mesh::MeshNode), reads and writes go
//!   through the consistent-hash ring via routed RPCs (the node's transport pool
//!   plus its peer-address lookup), so a record cached on one replica is
//!   reachable from the others.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use sbproxy_keystore::record::{CredentialRecord, KeyRecord};
use sbproxy_keystore::CacheTier;
use sbproxy_mesh::state::distributed_cache::DistributedCache;
use sbproxy_mesh::transport::client::TransportClientPool;
use sbproxy_mesh::MeshNode;

/// Default virtual nodes for the key-plane mesh ring.
const MESH_VNODES: usize = 128;

const KEY_PREFIX: &str = "keymgmt:key:";
const CRED_PREFIX: &str = "keymgmt:cred:";

/// Maps a peer node id to its transport address for routed RPCs.
type PeerAddr = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

enum Backing {
    /// Single-node: operate on the local shard only.
    Local(Arc<DistributedCache<Bytes>>),
    /// Clustered: route by consistent hash to the owning node.
    Clustered {
        cache: Arc<DistributedCache<Bytes>>,
        pool: Arc<TransportClientPool>,
        peer_addr: PeerAddr,
        /// Peer addresses captured at bootstrap, for operations that are
        /// cluster-wide rather than consistent-hash-routed. Purge is the
        /// only one: every node may hold a copy of any key-plane record, so
        /// a bulk purge has to reach all of them rather than one owner.
        peers: Vec<String>,
    },
}

/// A [`CacheTier`] backed by the mesh distributed cache.
pub struct MeshCacheTier {
    backing: Backing,
}

impl MeshCacheTier {
    /// Wrap an existing local distributed cache (single node).
    pub fn new(cache: Arc<DistributedCache<Bytes>>) -> Self {
        Self {
            backing: Backing::Local(cache),
        }
    }

    /// Build a standalone single-node distributed cache for `node_id` with a
    /// background sweeper, then wrap it. Local-only until joined to a mesh.
    pub fn standalone(node_id: &str) -> Self {
        let cache = DistributedCache::<Bytes>::new_with_sweeper(
            node_id,
            MESH_VNODES,
            sbproxy_mesh::state::distributed_cache::DEFAULT_SWEEP_INTERVAL_SECS,
        );
        Self {
            backing: Backing::Local(cache),
        }
    }

    /// Build a clustered tier from a bootstrapped [`MeshNode`]. Reads and writes
    /// route through the consistent-hash ring, so the cache is coherent across
    /// the cluster.
    pub fn clustered(node: &MeshNode) -> Self {
        Self {
            backing: Backing::Clustered {
                cache: node.distributed_cache(),
                pool: node.transport_pool(),
                peer_addr: Arc::new(node.peer_addr_lookup()),
                peers: node.peers().to_vec(),
            },
        }
    }

    async fn get_raw(&self, key: &str) -> Option<Bytes> {
        match &self.backing {
            Backing::Local(c) => c.get_local(key),
            Backing::Clustered {
                cache,
                pool,
                peer_addr,
                ..
            } => {
                cache
                    .get_routed(key, pool.as_ref(), peer_addr.as_ref())
                    .await
            }
        }
    }

    async fn put_raw(&self, key: &str, value: Bytes, ttl_secs: u64) {
        match &self.backing {
            Backing::Local(c) => c.put_local_with_ttl(key, value, ttl_secs),
            Backing::Clustered {
                cache,
                pool,
                peer_addr,
                ..
            } => {
                let _ = cache
                    .put_routed_with_ttl(key, value, ttl_secs, pool.as_ref(), peer_addr.as_ref())
                    .await;
            }
        }
    }

    /// Delete one key, reporting whether the delete actually landed.
    ///
    /// The routed form can fail: the owning node may be unreachable. A
    /// swallowed failure there is a revoked record still answering L2
    /// lookups on whichever node owns its slot, so the result is returned
    /// rather than dropped.
    async fn delete_raw(&self, key: &str) -> anyhow::Result<()> {
        match &self.backing {
            Backing::Local(c) => {
                c.delete_local(key);
                Ok(())
            }
            Backing::Clustered {
                cache,
                pool,
                peer_addr,
                ..
            } => cache
                .delete_routed(key, pool.as_ref(), peer_addr.as_ref())
                .await
                .map_err(|error| anyhow::anyhow!("mesh cache delete for '{key}' failed: {error}")),
        }
    }
}

#[async_trait]
impl CacheTier for MeshCacheTier {
    async fn get_key(&self, key_id: &str) -> Option<KeyRecord> {
        let raw = self.get_raw(&format!("{KEY_PREFIX}{key_id}")).await?;
        serde_json::from_slice(&raw).ok()
    }

    async fn put_key(&self, record: &KeyRecord, ttl: Duration) {
        if let Ok(json) = serde_json::to_vec(record) {
            self.put_raw(
                &format!("{KEY_PREFIX}{}", record.key_id),
                Bytes::from(json),
                ttl.as_secs().max(1),
            )
            .await;
        }
    }

    async fn get_credential(&self, id: &str) -> Option<CredentialRecord> {
        let raw = self.get_raw(&format!("{CRED_PREFIX}{id}")).await?;
        serde_json::from_slice(&raw).ok()
    }

    async fn put_credential(&self, record: &CredentialRecord, ttl: Duration) {
        if let Ok(json) = serde_json::to_vec(record) {
            self.put_raw(
                &format!("{CRED_PREFIX}{}", record.id),
                Bytes::from(json),
                ttl.as_secs().max(1),
            )
            .await;
        }
    }

    /// Drop both of this id's cached records.
    ///
    /// Both deletes are attempted even when the first fails, because they
    /// are independent records and dropping one of them is better than
    /// dropping neither. The first error is what the caller sees.
    async fn invalidate(&self, id: &str) -> anyhow::Result<()> {
        let key = self.delete_raw(&format!("{KEY_PREFIX}{id}")).await;
        let cred = self.delete_raw(&format!("{CRED_PREFIX}{id}")).await;
        key.and(cred)
    }

    /// Purge every key-plane record, cluster-wide.
    ///
    /// Scoped to the key-plane prefixes rather than clearing everything. In
    /// clustered mode the backing cache is the node's shared distributed
    /// cache, so a blanket purge would also discard unrelated entries such as
    /// compression sessions.
    ///
    /// Purge is cluster-wide rather than consistent-hash-routed, because any
    /// node may hold a cached copy of any record. A peer that cannot be
    /// reached keeps its stale entries until they expire, which is why the
    /// failure is logged and returned rather than swallowed: the caller
    /// asked for a cluster-wide purge and did not fully get one.
    ///
    /// The fan-out runs to completion before the first failure is returned.
    /// Stopping at the first unreachable peer would leave the reachable ones
    /// behind it holding records the operator asked to be gone.
    async fn invalidate_all(&self) -> anyhow::Result<()> {
        let mut unreached: Vec<String> = Vec::new();
        for prefix in [KEY_PREFIX, CRED_PREFIX] {
            match &self.backing {
                Backing::Local(c) => {
                    c.purge_prefix_local(prefix);
                }
                Backing::Clustered {
                    cache, pool, peers, ..
                } => {
                    cache.purge_prefix_local(prefix);
                    for addr in peers.iter() {
                        let client = pool.client_for(addr);
                        if let Err(error) = client.purge_prefix(prefix.to_string()).await {
                            tracing::warn!(
                                peer = %addr,
                                %prefix,
                                %error,
                                "mesh cache purge fan-out failed for a peer, which will serve \
                                 stale key-plane records until they expire"
                            );
                            unreached.push(format!("{addr} ({prefix})"));
                        }
                    }
                }
            }
        }
        if unreached.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "mesh cache purge did not reach {} peer prefixes: {}",
                unreached.len(),
                unreached.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn invalidate_all_purges_key_plane_prefixes_without_nuking_the_shared_cache() {
        // In clustered mode the backing cache is the node-wide distributed
        // cache, shared with compression sessions and anything else that uses
        // it. A bulk credential purge must not take those with it.
        let node = MeshNode::new("purge-a".into(), vec![], MESH_VNODES);
        let cache = node.distributed_cache();
        cache.put_local_with_ttl("compression:session:s1", Bytes::from("keep"), 60);

        let tier = MeshCacheTier::clustered(&node);
        let rec = KeyRecord::new("k1", "h1", Utc::now());
        tier.put_key(&rec, Duration::from_secs(60)).await;
        assert!(tier.get_key("k1").await.is_some(), "cached before purge");

        tier.invalidate_all()
            .await
            .expect("purge must report success");

        assert!(
            tier.get_key("k1").await.is_none(),
            "the key-plane record is purged"
        );
        assert!(
            cache.get_local("compression:session:s1").is_some(),
            "invalidate_all must not discard unrelated entries in the shared cache"
        );
    }

    #[tokio::test]
    async fn standalone_invalidate_all_still_clears_key_plane_records() {
        let tier = MeshCacheTier::standalone("purge-b");
        let rec = KeyRecord::new("k2", "h2", Utc::now());
        tier.put_key(&rec, Duration::from_secs(60)).await;
        tier.invalidate_all()
            .await
            .expect("purge must report success");
        assert!(tier.get_key("k2").await.is_none());
    }

    #[tokio::test]
    async fn standalone_round_trips_a_key_record() {
        let tier = MeshCacheTier::standalone("node-a");
        let rec = KeyRecord::new("k1", "h1", Utc::now());
        assert!(tier.get_key("k1").await.is_none());

        tier.put_key(&rec, Duration::from_secs(60)).await;
        let got = tier.get_key("k1").await.expect("present after put");
        assert_eq!(got.key_id, "k1");

        tier.invalidate("k1")
            .await
            .expect("invalidate must report success");
        assert!(tier.get_key("k1").await.is_none(), "invalidate drops it");
    }

    #[tokio::test]
    async fn standalone_round_trips_a_credential_and_purges_all() {
        let tier = MeshCacheTier::standalone("node-b");
        let cred = CredentialRecord {
            id: "c1".into(),
            name: "openai".into(),
            provider: Some("openai".into()),
            kind: "ai_provider".into(),
            header: sbproxy_keystore::record::default_cred_header(),
            scheme: sbproxy_keystore::record::default_cred_scheme(),
            material: sbproxy_keystore::record::CredentialMaterial::VaultRef {
                reference: "vault://openai".into(),
            },
            status: sbproxy_keystore::record::RecordStatus::Active,
            tenant_id: None,
            metadata: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            source: Default::default(),
            rotated_at: None,
            prev_material: None,
            prev_material_expires_at: None,
        };
        tier.put_credential(&cred, Duration::from_secs(60)).await;
        assert!(tier.get_credential("c1").await.is_some());

        tier.invalidate_all()
            .await
            .expect("purge must report success");
        assert!(
            tier.get_credential("c1").await.is_none(),
            "purge_all clears it"
        );
    }

    #[tokio::test]
    async fn clustered_single_node_round_trips_through_routed_ops() {
        // A clustered tier over a one-node mesh owns every key locally, so the
        // routed get/put/delete path resolves to the local shard with no
        // network. This exercises the Clustered backing without binding ports.
        let node = MeshNode::new("clust-a".into(), vec![], MESH_VNODES);
        let tier = MeshCacheTier::clustered(&node);

        let rec = KeyRecord::new("k9", "h9", Utc::now());
        assert!(tier.get_key("k9").await.is_none());

        tier.put_key(&rec, Duration::from_secs(60)).await;
        let got = tier.get_key("k9").await.expect("present after routed put");
        assert_eq!(got.key_id, "k9");

        tier.invalidate("k9")
            .await
            .expect("invalidate must report success");
        assert!(tier.get_key("k9").await.is_none(), "routed delete drops it");
    }
}
