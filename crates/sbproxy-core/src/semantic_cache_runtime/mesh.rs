//! Mesh semantic-cache adapter over the current OSS cluster node.
//!
//! This module is deliberately thin. It owns no gossip loop, no listener,
//! and no membership of its own: it borrows the process cluster handle's
//! mesh node, its distributed cache, its authenticated transport pool, its
//! peer-address resolver, and its isolation observer. Nothing here reads
//! `CompiledConfig.mesh` and nothing here starts a second transport.
//!
//! # Why a capability gate exists
//!
//! Candidate lookup needs one bounded routed-prefix snapshot per LSH
//! bucket, which is an appended postcard variant on the mesh cache wire.
//! Postcard enum variants are not self-describing, so a peer on an older
//! binary cannot answer "I do not know that operation"; it decodes the
//! appended discriminant as garbage. The gate therefore refuses to build a
//! mesh binding at all unless every live member currently publishes an
//! authenticated `semantic_cache_snapshot_v1` declaration through typed
//! cluster state. An older binary publishes nothing, and that absence is
//! the fail-closed signal. Unknown, mixed, suspect, or unreachable
//! membership refuses for the same reason.
//!
//! A bound store keeps checking. Before every lookup, write, and purge it
//! compares the live membership and incarnation map against the map that
//! was verified at construction. Any added, removed, restarted, suspect, or
//! unreachable member fails the operation before an appended-variant
//! operation or a semantic write leaves this node. Binding a new membership
//! view intentionally requires a successful pipeline reload, so a joining
//! old binary, including one that reused a node ID with a new incarnation,
//! cannot be handed the appended variant by an already-running pipeline.
//!
//! # What this backend does not promise
//!
//! Mesh owner failure is not durable cache replication. A failed owner
//! produces a miss, not a served stale value. After membership removes that
//! owner, the next write routes to the new owner and warms the new shard.
//! Nothing here replicates a cached response to a second holder.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt as _;

use sbproxy_ai::semantic_cache::{
    decode_entry, encode_entry, semantic_entry_key, semantic_purge_prefix, SemanticCacheBackend,
    SemanticCacheStore, SemanticClock, SemanticExactSelector, SemanticHealthState,
    SemanticPurgeReport, SemanticPurgeScope, SemanticStoreCounters, SemanticStoreError,
    SemanticStoreHealth, SemanticStoreLookup, SemanticStoreLookupQuery, SemanticStoreStats,
    SemanticStoreWrite, SystemSemanticClock,
};
use sbproxy_mesh::isolation::IsolationObserver;
use sbproxy_mesh::state::distributed_cache::DistributedCache;
use sbproxy_mesh::transport::TransportClientPool;
use sbproxy_mesh::{ClusterHandle, ClusterMember, ClusterMemberState, ClusterStateRead};

use crate::key_capability::{
    CapabilityAnnouncement, CAPABILITY_NAMESPACE, CAPABILITY_SCHEMA_VERSION,
    CAP_SEMANTIC_CACHE_SNAPSHOT_V1,
};

/// Maximum bucket snapshots in flight for one lookup.
///
/// Matches the Redis manifest fan-out bound. The LSH table count is already
/// capped at 16, so this is the whole fan-out in the worst case.
const MAX_BUCKET_SNAPSHOTS_IN_FLIGHT: usize = 16;

/// Maximum routed payload reads in flight for one lookup.
///
/// Matches the Redis payload fan-out bound. A worst-case 4,096-candidate
/// configuration must not enqueue unbounded peer work or retain every
/// maximum-size response at once.
const MAX_PAYLOAD_READS_IN_FLIGHT: usize = 8;

/// Maximum peer purge operations in flight for one cluster-wide purge.
const MAX_PEER_PURGES_IN_FLIGHT: usize = 16;

/// Fixed one-byte value stored under a bucket membership key.
///
/// The key carries the entire meaning. The value exists only so the record
/// is present, which is why candidate lookup rebuilds the payload key from
/// the key suffix and never trusts a value.
const MEMBERSHIP_MARKER: &[u8] = b"1";

/// Fixed hex length of a SHA-256 prompt digest suffix.
const PROMPT_DIGEST_HEX_LEN: usize = 64;

/// Upper bound the routed snapshot accepts for one page.
const MAX_BUCKET_PAGE: usize = 4_096;

/// Health reason: the isolation observer reports this node quarantined.
const REASON_ISOLATED: &str = "isolated";
/// Health reason: this node has no bound peer transport.
const REASON_TRANSPORT_UNAVAILABLE: &str = "transport_unavailable";
/// Health reason: the fleet capability proof can no longer be established.
const REASON_CAPABILITY_UNVERIFIED: &str = "capability_unverified";
/// Health reason: live membership no longer matches the verified evidence.
const REASON_MEMBERSHIP_CHANGED: &str = "membership_changed";

/// Why a mesh semantic binding was refused.
///
/// Display text is a closed set of three fixed strings. It never carries a
/// node ID, an address, a capability payload, or a transport error, because
/// this text reaches operator-facing configuration errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SemanticMeshCapabilityError {
    /// A live member published a valid declaration that omits this
    /// capability.
    #[error("mesh semantic cache capability is missing")]
    Missing,
    /// A live member's support could not be proven at all: no record, an
    /// expired record, an incompatible schema, a malformed record, an
    /// unreachable owner, a publisher mismatch, or an unusable membership
    /// snapshot.
    #[error("mesh semantic cache capability is unknown")]
    Unknown,
    /// Live membership no longer matches the map that was verified.
    #[error("mesh semantic cache membership changed after verification")]
    MembershipChanged,
}

/// Proof that every live member currently declares the snapshot capability.
///
/// Holds the exact sorted `node_id -> incarnation` map that was verified.
/// The type deliberately has no `Debug`, `Serialize`, `Display`, admin, or
/// logging surface: it exists only to fence later operations against a
/// membership view that has moved.
pub(crate) struct SemanticMeshCapabilityEvidence {
    /// Sorted live members and their observed incarnations at proof time.
    live_members: BTreeMap<String, u64>,
}

impl SemanticMeshCapabilityEvidence {
    /// Whether a freshly sampled live membership map still matches.
    fn matches(&self, current: &BTreeMap<String, u64>) -> bool {
        self.live_members == *current
    }

    /// Build evidence directly for tests that do not run a gossip loop.
    #[cfg(test)]
    fn for_members(members: &[(&str, u64)]) -> Self {
        Self {
            live_members: members
                .iter()
                .map(|(node_id, incarnation)| ((*node_id).to_string(), *incarnation))
                .collect(),
        }
    }
}

/// Reduce a membership snapshot to the live `node_id -> incarnation` map.
///
/// `Dead` members are ignored: SWIM has already decided they are gone, and
/// they cannot receive an operation. `Suspect` and `Unreachable` refuse the
/// whole snapshot, because a member whose state is in question cannot be
/// proven to understand an appended wire variant. An empty snapshot refuses
/// too: "nobody reported" and "nobody stale exists" are different claims.
fn live_membership_snapshot(
    members: &[ClusterMember],
) -> Result<BTreeMap<String, u64>, SemanticMeshCapabilityError> {
    let mut live = BTreeMap::new();
    for member in members {
        match member.state {
            ClusterMemberState::Dead => continue,
            ClusterMemberState::Alive => {
                live.insert(member.node_id.clone(), member.incarnation);
            }
            ClusterMemberState::Suspect | ClusterMemberState::Unreachable => {
                return Err(SemanticMeshCapabilityError::Unknown);
            }
        }
    }
    if live.is_empty() {
        return Err(SemanticMeshCapabilityError::Unknown);
    }
    Ok(live)
}

/// Sample the current live membership through one handle.
fn live_membership(
    cluster: &ClusterHandle,
) -> Result<BTreeMap<String, u64>, SemanticMeshCapabilityError> {
    live_membership_snapshot(&cluster.membership())
}

/// Judge one member's capability record.
///
/// Only a current `Present` record published by that exact node counts.
/// When the record carries authenticated enrolled claims, the claimed node
/// ID has to match too. `ClusterHandle::read_state` already refuses a
/// missing or invalid identity proof when an enrolled authenticator is
/// configured, so this check rides on that verification instead of adding a
/// parallel verifier.
fn evaluate_capability_record(
    node_id: &str,
    read: &ClusterStateRead<CapabilityAnnouncement>,
) -> Result<(), SemanticMeshCapabilityError> {
    let ClusterStateRead::Present(record) = read else {
        // Missing, Expired, IncompatibleSchema, Unreachable, and Malformed
        // are all the same claim here: this member's support cannot be
        // proven right now.
        return Err(SemanticMeshCapabilityError::Unknown);
    };
    if record.publisher_node_id != node_id {
        return Err(SemanticMeshCapabilityError::Unknown);
    }
    if let Some(identity) = record.authenticated_identity.as_deref() {
        if identity.node_id != node_id {
            return Err(SemanticMeshCapabilityError::Unknown);
        }
    }
    if record
        .payload
        .caps
        .iter()
        .any(|cap| cap.as_str() == CAP_SEMANTIC_CACHE_SNAPSHOT_V1)
    {
        Ok(())
    } else {
        // A valid declaration that simply does not list this capability is
        // the one case where the fleet's answer is genuinely known.
        Err(SemanticMeshCapabilityError::Missing)
    }
}

/// Require an authenticated snapshot-capability declaration from every live
/// member, and return the membership view that was proven.
///
/// Reuses the existing `key_capability` typed-state namespace, schema
/// version, TTL, and announcement record. Nothing is added to the postcard
/// gossip or cache-operation enums, so an old binary participates by
/// publishing no declaration at all.
pub(crate) async fn require_semantic_mesh_capability(
    cluster: &ClusterHandle,
) -> Result<SemanticMeshCapabilityEvidence, SemanticMeshCapabilityError> {
    let live_members = live_membership(cluster)?;
    for node_id in live_members.keys() {
        let read = cluster
            .read_state::<CapabilityAnnouncement>(
                CAPABILITY_NAMESPACE,
                node_id,
                CAPABILITY_SCHEMA_VERSION,
            )
            .await;
        evaluate_capability_record(node_id, &read)?;
    }
    Ok(SemanticMeshCapabilityEvidence { live_members })
}

/// Resolves a peer node ID to its transport address.
type PeerAddr = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Semantic-cache backend that stores payloads and bucket membership on the
/// current OSS mesh.
pub(crate) struct MeshSemanticCacheStore {
    /// Process cluster handle, resampled to fence a moved membership.
    cluster: ClusterHandle,
    /// Membership view proven to understand the snapshot operation.
    capability: SemanticMeshCapabilityEvidence,
    /// Shared consistent-hash cache borrowed from the mesh node.
    cache: Arc<DistributedCache<Bytes>>,
    /// Shared authenticated transport pool borrowed from the mesh node.
    pool: Arc<TransportClientPool>,
    /// Peer node ID to transport address resolver.
    peer_addr: PeerAddr,
    /// Isolation observer, when gossip started.
    isolation: Option<Arc<IsolationObserver>>,
    /// Counters returned through admin.
    stats: SemanticStoreCounters,
}

impl MeshSemanticCacheStore {
    /// Bind a store to the running mesh node behind `cluster`.
    ///
    /// Rechecks membership against `capability` before extracting anything,
    /// so a view that moved between the preflight proof and construction
    /// refuses rather than binding a stale fleet picture.
    pub(crate) fn from_cluster(
        cluster: &ClusterHandle,
        capability: SemanticMeshCapabilityEvidence,
    ) -> anyhow::Result<Arc<Self>> {
        let current = live_membership(cluster).map_err(|error| anyhow::anyhow!("{error}"))?;
        if !capability.matches(&current) {
            anyhow::bail!("{}", SemanticMeshCapabilityError::MembershipChanged);
        }
        let mesh = cluster
            .mesh_node()
            .ok_or_else(|| anyhow::anyhow!("mesh semantic cache requires a distributed cluster"))?;
        if !mesh.has_transport() {
            anyhow::bail!("mesh semantic cache requires a bound cluster transport");
        }
        let lookup = mesh.peer_addr_lookup();
        Ok(Arc::new(Self {
            cluster: cluster.clone(),
            capability,
            cache: mesh.distributed_cache(),
            pool: mesh.transport_pool(),
            peer_addr: Arc::new(lookup),
            isolation: mesh.isolation_observer(),
            stats: SemanticStoreCounters::default(),
        }))
    }

    /// Assemble a store from already-built parts.
    ///
    /// Test seam only. Production always goes through
    /// [`Self::from_cluster`], which is the path that proves the transport
    /// is bound and the membership still matches the capability evidence.
    #[cfg(test)]
    fn from_parts(
        cluster: ClusterHandle,
        capability: SemanticMeshCapabilityEvidence,
        cache: Arc<DistributedCache<Bytes>>,
        pool: Arc<TransportClientPool>,
        peer_addr: PeerAddr,
        isolation: Option<Arc<IsolationObserver>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cluster,
            capability,
            cache,
            pool,
            peer_addr,
            isolation,
            stats: SemanticStoreCounters::default(),
        })
    }

    /// Whether the gossip loop currently considers this node quarantined.
    fn is_isolated(&self) -> bool {
        self.isolation
            .as_ref()
            .is_some_and(|observer| observer.is_isolated())
    }

    /// Refuse the operation when live membership has moved off the verified
    /// view.
    ///
    /// This runs before every lookup, write, and purge. It is the fence that
    /// keeps a newly joined old binary from receiving an appended postcard
    /// variant through a pipeline that was compiled against a different
    /// fleet.
    fn fence_membership(&self) -> Result<(), SemanticStoreError> {
        match live_membership(&self.cluster) {
            Ok(current) if self.capability.matches(&current) => Ok(()),
            _ => Err(SemanticStoreError::Unavailable),
        }
    }

    /// Fetch one payload from its consistent-hash owner, strictly.
    ///
    /// `Ok(None)` means the owner cleanly holds nothing, which is a safe
    /// dangling-membership rejection. Every other failure, including a
    /// missing owner identity, a missing address, an untrusted node ID, or
    /// a peer transport error, is a closed store error.
    ///
    /// [`DistributedCache::get_routed`] is deliberately not used here: that
    /// compatibility API collapses transport failures into `None`, which
    /// would let a lookup's answer depend on which owner happened to fail.
    async fn strict_payload_get(&self, key: &str) -> Result<Option<Bytes>, SemanticStoreError> {
        let Some(owner) = self.cache.responsible_node(key) else {
            // Empty ring: the local shard is the whole cluster.
            return Ok(self.cache.get_local(key));
        };
        if owner == self.cache.local_node_id() {
            return Ok(self.cache.get_local(key));
        }
        let address = (self.peer_addr.as_ref())(&owner).ok_or(SemanticStoreError::Unavailable)?;
        let client = self
            .pool
            .try_client_for_node(&owner, &address)
            .ok_or(SemanticStoreError::Unavailable)?;
        client
            .get(key.to_string())
            .await
            .map_err(|_| SemanticStoreError::OperationFailed)
    }

    /// Read every bucket manifest and return the deduplicated prompt
    /// digests plus whether any bucket page was truncated.
    async fn candidate_digests(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<(BTreeSet<[u8; 32]>, bool), SemanticStoreError> {
        let page = query.maximum_per_bucket.clamp(1, MAX_BUCKET_PAGE);
        // Own the routing pair before the stream. Mapping straight off the
        // borrowed indexes makes the closure return a future that borrows
        // its argument, which no higher-ranked bound can satisfy.
        let bucket_plans: Vec<(String, String)> = query
            .keys
            .bucket_indexes
            .iter()
            .map(|index| (index.routing_key.clone(), index.member_prefix.clone()))
            .collect();
        let snapshots = futures::stream::iter(bucket_plans.into_iter().map(
            |(routing_key, member_prefix)| {
                let cache = Arc::clone(&self.cache);
                let pool = Arc::clone(&self.pool);
                let peer_addr = Arc::clone(&self.peer_addr);
                async move {
                    let snapshot = cache
                        .snapshot_prefix_routed(
                            &routing_key,
                            &member_prefix,
                            page,
                            pool.as_ref(),
                            peer_addr.as_ref(),
                        )
                        .await;
                    (member_prefix, snapshot)
                }
            },
        ))
        .buffer_unordered(MAX_BUCKET_SNAPSHOTS_IN_FLIGHT)
        .collect::<Vec<_>>()
        .await;

        let mut digests: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut truncated = false;
        for (member_prefix, snapshot) in snapshots {
            // One unreachable bucket owner fails the whole lookup. Using
            // only the reachable subset would make hit behavior depend on
            // which owner happened to be down during the lookup.
            let snapshot = snapshot.map_err(|_| SemanticStoreError::OperationFailed)?;
            truncated |= snapshot.truncated;
            for (key, _) in &snapshot.entries {
                if let Some(digest) = parse_member_digest(&member_prefix, key) {
                    digests.insert(digest);
                }
            }
        }
        Ok((digests, truncated))
    }
}

/// Recover a prompt digest from one bucket membership key.
///
/// The suffix is the only thing trusted, and only when it is exactly 64
/// lowercase hex characters. The stored value is never consulted, so a
/// hostile or corrupt record cannot steer a payload read at an arbitrary
/// key.
fn parse_member_digest(member_prefix: &str, key: &str) -> Option<[u8; 32]> {
    let suffix = key.strip_prefix(member_prefix)?;
    if suffix.len() != PROMPT_DIGEST_HEX_LEN
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut digest = [0u8; 32];
    hex::decode_to_slice(suffix, &mut digest).ok()?;
    Some(digest)
}

#[async_trait]
impl SemanticCacheStore for MeshSemanticCacheStore {
    fn backend(&self) -> SemanticCacheBackend {
        SemanticCacheBackend::Mesh
    }

    async fn lookup(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<SemanticStoreLookup, SemanticStoreError> {
        self.fence_membership()?;
        if self.is_isolated() {
            // A quarantined node cannot see the fleet's shards, so every
            // answer it could give is unsound. Miss quietly rather than
            // reporting a backend failure.
            self.stats.record_candidate_read(true);
            return Ok(SemanticStoreLookup::default());
        }

        let now = SystemSemanticClock.now_unix_ms();
        let mut selector = SemanticExactSelector::new(
            Arc::clone(&query.embedding),
            query.threshold,
            query.namespace.clone(),
            now,
        )
        .map_err(|_| {
            // The orchestrator validates the query before calling a store,
            // so this is an impossible store-side invariant rather than an
            // operator-visible embedding problem.
            self.stats.record_candidate_read(false);
            SemanticStoreError::InvalidState
        })?;

        let (digests, truncated) = match self.candidate_digests(query).await {
            Ok(found) => found,
            Err(error) => {
                self.stats.record_candidate_read(false);
                return Err(error);
            }
        };

        let mut payloads = futures::stream::iter(digests.into_iter().map(|digest| {
            let key = semantic_entry_key(&query.namespace, &digest);
            async move { self.strict_payload_get(&key).await }
        }))
        .buffer_unordered(MAX_PAYLOAD_READS_IN_FLIGHT);

        // Rejections counted here never reach the selector, so they are
        // added to its closed counts at the end. A value that fails to
        // decode is counted as incompatible; the selector owns expiry
        // classification for everything that does decode.
        let mut undecodable: u64 = 0;
        while let Some(result) = payloads.next().await {
            match result {
                Ok(Some(bytes)) => match decode_entry(&bytes, &query.namespace, now) {
                    Ok(entry) => selector.consider(Arc::new(entry)),
                    Err(_) => undecodable = undecodable.saturating_add(1),
                },
                // A membership record with no payload is a safe dangling
                // reference, not an error.
                Ok(None) => {}
                Err(error) => {
                    // Returning here drops the bounded stream, cancels the
                    // in-flight reads, and discards any partial winner. A
                    // lookup answered from only the reachable subset would
                    // replay a different response depending on which owner
                    // happened to fail.
                    self.stats.record_candidate_read(false);
                    return Err(error);
                }
            }
        }

        let mut lookup = selector.finish();
        lookup.incompatible = lookup.incompatible.saturating_add(undecodable);
        lookup.rejected = lookup.rejected.saturating_add(undecodable);
        lookup.truncated = truncated;
        self.stats.record_candidate_read(true);
        self.stats.record_rejected(lookup.rejected);
        Ok(lookup)
    }

    async fn put(&self, write: &SemanticStoreWrite) -> Result<(), SemanticStoreError> {
        if let Err(error) = self.fence_membership() {
            self.stats.record_write(false);
            return Err(error);
        }
        if self.is_isolated() {
            // Never fall back to a local write while isolated. Such a write
            // could land on the wrong owner and later surface as an
            // ambiguous duplicate once the partition heals.
            self.stats.record_write(false);
            return Err(SemanticStoreError::Unavailable);
        }

        let payload = match encode_entry(&write.entry) {
            Ok(payload) => payload,
            Err(_) => {
                self.stats.record_write(false);
                return Err(SemanticStoreError::InvalidWrite);
            }
        };

        // Payload first. A crash between the payload and its bucket
        // membership leaves an unreachable payload, which is safe; the
        // reverse order would leave a membership record pointing at a
        // response that was never stored.
        if self
            .cache
            .put_routed_with_ttl(
                &write.keys.entry_key,
                payload,
                write.ttl_secs,
                self.pool.as_ref(),
                self.peer_addr.as_ref(),
            )
            .await
            .is_err()
        {
            self.stats.record_write(false);
            return Err(SemanticStoreError::OperationFailed);
        }

        // One small membership record per bucket, routed by the bucket's
        // routing key so every member beneath one bucket shares an owner
        // and a single bounded snapshot can read them all. The key carries
        // the prompt digest; the value is a fixed marker.
        let digest_hex = hex::encode(write.entry.prompt_digest);
        // Owned before the stream, for the same higher-ranked lifetime
        // reason as the lookup path above.
        let ttl_secs = write.ttl_secs;
        let member_writes: Vec<(String, String)> = write
            .keys
            .bucket_indexes
            .iter()
            .map(|index| {
                (
                    index.routing_key.clone(),
                    format!("{}{digest_hex}", index.member_prefix),
                )
            })
            .collect();
        let results =
            futures::stream::iter(member_writes.into_iter().map(|(routing_key, member_key)| {
                let cache = Arc::clone(&self.cache);
                let pool = Arc::clone(&self.pool);
                let peer_addr = Arc::clone(&self.peer_addr);
                async move {
                    cache
                        .put_routed_by(
                            &routing_key,
                            &member_key,
                            Bytes::from_static(MEMBERSHIP_MARKER),
                            ttl_secs,
                            pool.as_ref(),
                            peer_addr.as_ref(),
                        )
                        .await
                }
            }))
            .buffer_unordered(MAX_BUCKET_SNAPSHOTS_IN_FLIGHT)
            .collect::<Vec<_>>()
            .await;

        if results.iter().any(|result| result.is_err()) {
            // A partial index write leaves an unreachable payload, never a
            // false hit, but the caller must not be told the record is
            // discoverable.
            self.stats.record_write(false);
            return Err(SemanticStoreError::OperationFailed);
        }
        self.stats.record_write(true);
        Ok(())
    }

    async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError> {
        self.fence_membership()?;
        let prefix = semantic_purge_prefix(scope);
        let mut removed = self.cache.purge_prefix_local(&prefix) as u64;

        let local_node = self.cache.local_node_id().to_string();
        let peers: Vec<String> = self
            .cache
            .member_nodes()
            .into_iter()
            .filter(|node_id| *node_id != local_node)
            .collect();
        let peers_attempted = peers.len() as u64;

        let results = futures::stream::iter(peers.into_iter().map(|node_id| {
            let pool = Arc::clone(&self.pool);
            let peer_addr = Arc::clone(&self.peer_addr);
            let prefix = prefix.clone();
            async move {
                let address = (peer_addr.as_ref())(&node_id).ok_or(())?;
                let client = pool.try_client_for_node(&node_id, &address).ok_or(())?;
                client.purge_prefix(prefix).await.map_err(|_| ())
            }
        }))
        .buffer_unordered(MAX_PEER_PURGES_IN_FLIGHT)
        .collect::<Vec<_>>()
        .await;

        let mut nodes_failed = 0u64;
        for result in results {
            match result {
                Ok(count) => removed = removed.saturating_add(count),
                // Missing identity, missing address, transport failure, and
                // a refused reply are all a failed node, never a successful
                // removal of zero records.
                Err(()) => nodes_failed = nodes_failed.saturating_add(1),
            }
        }

        let mut nodes_attempted = peers_attempted.saturating_add(1);
        if self.is_isolated() {
            // An isolated node cannot claim its membership view was
            // complete, even if every node it could still see answered.
            nodes_failed = nodes_failed.max(1);
            nodes_attempted = nodes_attempted.max(nodes_failed);
        }

        let report = SemanticPurgeReport {
            removed,
            nodes_attempted,
            nodes_failed,
            complete: nodes_failed == 0,
        };
        self.stats.record_purge(&report);
        Ok(report)
    }

    async fn health(&self) -> SemanticStoreHealth {
        let backend = SemanticCacheBackend::Mesh;
        let unavailable = |reason: &'static str| SemanticStoreHealth {
            backend,
            state: SemanticHealthState::Unavailable,
            reason: Some(reason),
        };
        if !self.cluster.has_peer_transport() {
            return unavailable(REASON_TRANSPORT_UNAVAILABLE);
        }
        match live_membership(&self.cluster) {
            Err(_) => return unavailable(REASON_CAPABILITY_UNVERIFIED),
            Ok(current) if !self.capability.matches(&current) => {
                return unavailable(REASON_MEMBERSHIP_CHANGED)
            }
            Ok(_) => {}
        }
        if self.is_isolated() {
            return SemanticStoreHealth {
                backend,
                state: SemanticHealthState::Degraded,
                reason: Some(REASON_ISOLATED),
            };
        }
        SemanticStoreHealth {
            backend,
            state: SemanticHealthState::Healthy,
            reason: None,
        }
    }

    fn stats(&self) -> SemanticStoreStats {
        // The local shard is shared with every other mesh consumer, so a
        // count taken here would not describe the semantic keyspace.
        self.stats.snapshot(None)
    }
}

#[cfg(test)]
mod tests {

    /// `Result::expect_err` requires `Debug` on the success value, and a
    /// bound semantic store would print cached prompts and model output.
    /// Deriving `Debug` for a test assertion would put that content one
    /// `{:?}` from a log line, so unwrap the error side explicitly.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
    use super::*;

    use std::collections::HashMap;
    use std::sync::RwLock;
    use std::time::Duration;

    use sbproxy_ai::semantic_cache::{
        semantic_entry_keys, semantic_prompt_digest, CachedHttpResponse, RandomProjectionLsh,
        SemanticEntryKeys, SemanticLshConfig, SemanticNamespace, SemanticNamespaceInput,
        StoredSemanticEntry, SEMANTIC_CACHE_SCHEMA_VERSION,
    };
    use sbproxy_mesh::transport::TransportServer;
    use sbproxy_mesh::{ClusterIdentity, ClusterNodeRole, ClusterStateRecord, MeshNode};

    /// Virtual nodes per real node in every fixture ring.
    const VNODES: usize = 128;
    /// Exact cosine threshold every fixture lookup uses.
    const THRESHOLD: f32 = 0.99;
    /// Candidate bound every fixture lookup uses.
    const PER_BUCKET: usize = 32;

    // --- Fixture construction ---

    fn identity(node_id: &str) -> ClusterIdentity {
        ClusterIdentity {
            cluster_id: "semantic-mesh".to_string(),
            node_id: node_id.to_string(),
            roles: [ClusterNodeRole::Gateway].into_iter().collect(),
            labels: Default::default(),
            peer_address: None,
            model_endpoint: None,
        }
    }

    /// A distributed cluster handle over a mesh node with a bound transport
    /// and no gossip loop, so `membership()` reports exactly one live
    /// member: this node. The transport server is owned by the mesh node
    /// and shuts down when the handle drops.
    async fn bound_cluster(node_id: &str) -> ClusterHandle {
        let mesh = MeshNode::new(node_id.to_string(), Vec::new(), VNODES);
        let server = TransportServer::start(0, mesh.distributed_cache())
            .await
            .expect("transport binds");
        let mesh = mesh.with_transport(
            Some(server),
            Arc::new(TransportClientPool::new()),
            Arc::new(RwLock::new(HashMap::new())),
        );
        ClusterHandle::distributed(identity(node_id), Arc::new(mesh)).expect("distributed handle")
    }

    /// A peer resolver over a shared, mutable address table, so a test can
    /// take a node away without rebuilding the store.
    fn peer_addr_from(map: Arc<RwLock<HashMap<String, String>>>) -> PeerAddr {
        Arc::new(move |node_id: &str| {
            map.read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(node_id)
                .cloned()
        })
    }

    fn no_peers() -> PeerAddr {
        peer_addr_from(Arc::new(RwLock::new(HashMap::new())))
    }

    fn namespace(tenant: &str, origin_route: &str) -> SemanticNamespace {
        namespace_with_dims(tenant, origin_route, 3)
    }

    /// A namespace over `dimensions`-wide embeddings.
    ///
    /// Most fixtures here use three dimensions because it keeps the vectors
    /// readable. One test needs every LSH bucket of a key to route to the
    /// same node, and that is geometrically out of reach in three
    /// dimensions: eight buckets over a two-node ring wants roughly one
    /// candidate in 256, but three dimensions leave only two free
    /// directions, so a sweep of 4000 vectors tops out at seven of eight.
    /// Widening the vector restores the search space (measured: 23 of 4000
    /// at eight dimensions).
    fn namespace_with_dims(
        tenant: &str,
        origin_route: &str,
        dimensions: usize,
    ) -> SemanticNamespace {
        SemanticNamespace::derive(SemanticNamespaceInput {
            origin_route,
            request_host: "api.example.com",
            tenant_id: tenant,
            credential_identity: "api-key:mesh",
            requested_model: "gpt-4o-mini",
            api_surface: "openai.chat",
            request_context_digest: &[7u8; 32],
            embedding_identity: "provider/openai/text-embedding-3-small",
            embedding_dimensions: dimensions,
            semantic_config_digest: &[9u8; 32],
            response_policy_digest: &[11u8; 32],
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
        })
    }

    fn normalize(values: &[f32]) -> Vec<f32> {
        let norm = values
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>()
            .sqrt();
        values
            .iter()
            .map(|value| (f64::from(*value) / norm) as f32)
            .collect()
    }

    fn keys_for(
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
    ) -> SemanticEntryKeys {
        let lsh = RandomProjectionLsh::from_config(&SemanticLshConfig::default())
            .expect("default lsh configuration builds");
        let buckets = lsh.buckets(embedding).expect("fixture vector projects");
        semantic_entry_keys(namespace, &semantic_prompt_digest(prompt), &buckets)
    }

    fn entry_for(
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        body: &str,
        ttl_secs: u64,
    ) -> Arc<StoredSemanticEntry> {
        let now = SystemSemanticClock.now_unix_ms();
        Arc::new(StoredSemanticEntry {
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
            namespace: namespace.clone(),
            prompt_digest: semantic_prompt_digest(prompt),
            embedding: normalize(embedding),
            response: Arc::new(CachedHttpResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: Bytes::from(body.as_bytes().to_vec()),
            }),
            stored_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(ttl_secs.saturating_mul(1_000).max(1)),
        })
    }

    fn write_for(
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        body: &str,
        ttl_secs: u64,
    ) -> SemanticStoreWrite {
        SemanticStoreWrite {
            entry: entry_for(namespace, prompt, embedding, body, ttl_secs),
            keys: keys_for(namespace, prompt, embedding),
            ttl_secs,
            maximum_per_bucket: PER_BUCKET,
        }
    }

    fn query_for(
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
    ) -> SemanticStoreLookupQuery {
        SemanticStoreLookupQuery {
            namespace: namespace.clone(),
            keys: keys_for(namespace, prompt, embedding),
            embedding: Arc::from(normalize(embedding).as_slice()),
            threshold: THRESHOLD,
            maximum_per_bucket: PER_BUCKET,
        }
    }

    /// Membership key a bucket index holds for one record.
    fn member_key(prefix: &str, prompt_digest: &[u8; 32]) -> String {
        format!("{prefix}{}", hex::encode(prompt_digest))
    }

    /// One embedding whose every bucket routing key is owned by `owner`.
    ///
    /// Pinning bucket ownership lets a test move payload ownership on its
    /// own, which is how the payload-failure case is isolated from the
    /// manifest-failure case.
    fn embedding_with_buckets_on(
        cache: &DistributedCache<Bytes>,
        namespace: &SemanticNamespace,
        owner: &str,
        dimensions: usize,
    ) -> Vec<f32> {
        for step in 0..4_000u32 {
            // Vary the direction rather than one component's magnitude:
            // walking a single axis converges toward it, so the projections
            // stop changing and the sweep explores far fewer distinct
            // bucket sets than its length suggests. SplitMix64 over the
            // step spreads candidates and stays deterministic.
            let mut z = (step as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut next = || {
                z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut x = z;
                x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                x ^= x >> 31;
                (x >> 11) as f32 / (1u64 << 52) as f32 * 2.0 - 1.0
            };
            let embedding: Vec<f32> = (0..dimensions).map(|_| next()).collect();
            let keys = keys_for(namespace, "bucket-probe", &embedding);
            if keys
                .bucket_indexes
                .iter()
                .all(|index| cache.responsible_node(&index.routing_key).as_deref() == Some(owner))
            {
                return embedding;
            }
        }
        panic!("no fixture embedding placed every bucket on {owner}");
    }

    /// One prompt whose generated payload key is owned by `owner`.
    fn prompt_with_payload_on(
        cache: &DistributedCache<Bytes>,
        namespace: &SemanticNamespace,
        owner: &str,
    ) -> String {
        for step in 0..4_000u32 {
            let prompt = format!("payload-probe-{step}");
            let key = semantic_entry_key(namespace, &semantic_prompt_digest(&prompt));
            if cache.responsible_node(&key).as_deref() == Some(owner) {
                return prompt;
            }
        }
        panic!("no fixture prompt placed a payload on {owner}");
    }

    // --- One-node contract ---

    #[tokio::test]
    async fn mesh_constructor_requires_a_bound_transport_for_distributed_mode() {
        let mesh = Arc::new(MeshNode::new("node-a".to_string(), Vec::new(), VNODES));
        assert!(!mesh.has_transport());
        let cluster = ClusterHandle::distributed(identity("node-a"), mesh).expect("handle");
        let evidence = SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0)]);
        let error = expect_error(
            MeshSemanticCacheStore::from_cluster(&cluster, evidence),
            "an unbound transport must refuse the binding",
        );
        assert!(error.to_string().contains("bound cluster transport"));
    }

    /// One-node store: every key is local and no peer is reachable.
    async fn one_node_store() -> (Arc<MeshSemanticCacheStore>, Arc<DistributedCache<Bytes>>) {
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-a", VNODES));
        let store = MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0)]),
            Arc::clone(&cache),
            Arc::new(TransportClientPool::new()),
            no_peers(),
            None,
        );
        (store, cache)
    }

    #[tokio::test]
    async fn one_node_mesh_put_and_candidate_read_round_trip() {
        let (store, _cache) = one_node_store().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];

        store
            .put(&write_for(
                &namespace,
                "refund policy",
                &embedding,
                "cached-body",
                600,
            ))
            .await
            .expect("write is accepted");

        let lookup = store
            .lookup(&query_for(&namespace, "refund policy", &embedding))
            .await
            .expect("lookup answers");
        let hit = lookup.exact_hit.expect("stored record is replayed");
        assert_eq!(hit.entry.response.body, Bytes::from_static(b"cached-body"));

        let health = store.health().await;
        assert_eq!(health.state, SemanticHealthState::Healthy);
        assert_eq!(health.reason, None);
        let stats = store.stats();
        assert_eq!(stats.writes, 1);
        assert_eq!(stats.write_errors, 0);
        assert_eq!(stats.candidate_reads, 1);
    }

    #[tokio::test]
    async fn one_node_mesh_ttl_expires_payload_and_membership() {
        let (store, cache) = one_node_store().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let write = write_for(&namespace, "short lived", &embedding, "body", 1);
        let member = member_key(
            &write.keys.bucket_indexes[0].member_prefix,
            &write.entry.prompt_digest,
        );

        store.put(&write).await.expect("write is accepted");
        assert!(store
            .lookup(&query_for(&namespace, "short lived", &embedding))
            .await
            .expect("lookup answers")
            .exact_hit
            .is_some());

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        cache.sweep_expired();
        assert!(cache.get_local(&write.keys.entry_key).is_none());
        assert!(cache.get_local(&member).is_none());

        let lookup = store
            .lookup(&query_for(&namespace, "short lived", &embedding))
            .await
            .expect("lookup answers");
        assert!(
            lookup.exact_hit.is_none(),
            "an expired record cannot be replayed"
        );
    }

    #[tokio::test]
    async fn mesh_candidate_read_deduplicates_entry_ids_across_tables() {
        // One record lands in every configured table, so the same prompt
        // digest is discoverable once per bucket. Candidate generation must
        // collapse that to exactly one payload read.
        let (store, cache) = one_node_store().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let write = write_for(&namespace, "duplicated", &embedding, "body", 600);
        assert!(
            write.keys.bucket_indexes.len() > 1,
            "the fixture needs more than one LSH table"
        );

        store.put(&write).await.expect("write is accepted");

        let query = query_for(&namespace, "duplicated", &embedding);
        let (digests, truncated) = store
            .candidate_digests(&query)
            .await
            .expect("bucket snapshots answer");
        assert_eq!(digests.len(), 1, "one prompt digest across every table");
        assert!(!truncated);
        assert!(cache.get_local(&write.keys.entry_key).is_some());
    }

    #[test]
    fn mesh_payload_fetch_concurrency_never_exceeds_eight() {
        // Fixed closed bounds matching the Redis fan-out. A worst-case
        // 4,096-candidate configuration must not enqueue unbounded peer
        // work or retain every maximum-size response at once.
        assert_eq!(MAX_PAYLOAD_READS_IN_FLIGHT, 8);
        assert_eq!(MAX_BUCKET_SNAPSHOTS_IN_FLIGHT, 16);
        assert_eq!(MAX_PEER_PURGES_IN_FLIGHT, 16);
    }

    #[tokio::test]
    async fn mesh_corrupt_payload_is_rejected_without_failing_other_candidates() {
        let (store, cache) = one_node_store().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];

        store
            .put(&write_for(&namespace, "good", &embedding, "good-body", 600))
            .await
            .expect("write is accepted");
        let corrupt = write_for(&namespace, "corrupt", &embedding, "never-read", 600);
        store.put(&corrupt).await.expect("write is accepted");
        cache.put_local(
            &corrupt.keys.entry_key,
            Bytes::from_static(b"not-a-semantic-record"),
        );

        let lookup = store
            .lookup(&query_for(&namespace, "good", &embedding))
            .await
            .expect("one bad value cannot fail the lookup");
        let hit = lookup.exact_hit.expect("the healthy record still replays");
        assert_eq!(hit.entry.response.body, Bytes::from_static(b"good-body"));
        assert!(lookup.rejected >= 1, "the corrupt record is counted");
    }

    #[tokio::test]
    async fn mesh_payload_transport_error_discards_a_partial_exact_hit() {
        // Two records share one bucket. Bucket ownership is pinned local so
        // the manifest read succeeds, then one payload is placed on a peer
        // that cannot be reached.
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-a", VNODES));
        cache.add_node("node-b");
        // Eight dimensions, not the usual three: see namespace_with_dims.
        let namespace = namespace_with_dims("tenant-secret-a", "origin-a.example", 8);
        let embedding = embedding_with_buckets_on(&cache, &namespace, "node-a", 8);
        let local_prompt = prompt_with_payload_on(&cache, &namespace, "node-a");
        let remote_prompt = prompt_with_payload_on(&cache, &namespace, "node-b");

        let addresses = Arc::new(RwLock::new(HashMap::from([(
            "node-b".to_string(),
            // A port with nothing listening.
            "127.0.0.1:1".to_string(),
        )])));
        let store = MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0)]),
            Arc::clone(&cache),
            Arc::new(TransportClientPool::new()),
            peer_addr_from(addresses),
            None,
        );

        // The local record on its own would be a perfect hit.
        let local = write_for(&namespace, &local_prompt, &embedding, "local-body", 600);
        cache.put_local(
            &local.keys.entry_key,
            encode_entry(&local.entry).expect("fixture record encodes"),
        );
        for index in &local.keys.bucket_indexes {
            cache.put_local(
                &member_key(&index.member_prefix, &local.entry.prompt_digest),
                Bytes::from_static(MEMBERSHIP_MARKER),
            );
        }
        // The second record's membership row is local but its payload is
        // not, so the payload read has to cross a dead transport.
        let remote = write_for(&namespace, &remote_prompt, &embedding, "remote-body", 600);
        for index in &remote.keys.bucket_indexes {
            cache.put_local(
                &member_key(&index.member_prefix, &remote.entry.prompt_digest),
                Bytes::from_static(MEMBERSHIP_MARKER),
            );
        }

        let error = expect_error(
            store
                .lookup(&query_for(&namespace, &local_prompt, &embedding))
                .await,
            "a failed payload read discards the partial winner",
        );
        assert_eq!(error, SemanticStoreError::OperationFailed);
    }

    #[tokio::test]
    async fn mesh_health_reports_degraded_while_isolated() {
        let store = isolated_store().await;
        let health = store.health().await;
        assert_eq!(health.state, SemanticHealthState::Degraded);
        assert_eq!(health.reason, Some(REASON_ISOLATED));
    }

    #[tokio::test]
    async fn mesh_health_reports_unavailable_after_membership_moves() {
        let store = MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            // Evidence names a peer the live membership no longer reports.
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0), ("node-b", 3)]),
            Arc::new(DistributedCache::new("node-a", VNODES)),
            Arc::new(TransportClientPool::new()),
            no_peers(),
            None,
        );
        let health = store.health().await;
        assert_eq!(health.state, SemanticHealthState::Unavailable);
        assert_eq!(health.reason, Some(REASON_MEMBERSHIP_CHANGED));
    }

    #[tokio::test]
    async fn mesh_health_reports_unavailable_without_a_peer_transport() {
        let store = MeshSemanticCacheStore::from_parts(
            ClusterHandle::local(identity("node-a")).expect("local handle"),
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0)]),
            Arc::new(DistributedCache::new("node-a", VNODES)),
            Arc::new(TransportClientPool::new()),
            no_peers(),
            None,
        );
        let health = store.health().await;
        assert_eq!(health.state, SemanticHealthState::Unavailable);
        assert_eq!(health.reason, Some(REASON_TRANSPORT_UNAVAILABLE));
    }

    /// A store whose isolation observer reports quarantine.
    async fn isolated_store() -> Arc<MeshSemanticCacheStore> {
        let observer = Arc::new(IsolationObserver::new("node-a", 1));
        observer.update(0);
        assert!(observer.is_isolated());
        MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0)]),
            Arc::new(DistributedCache::new("node-a", VNODES)),
            Arc::new(TransportClientPool::new()),
            no_peers(),
            Some(observer),
        )
    }

    #[tokio::test]
    async fn mesh_lookup_while_isolated_returns_a_miss() {
        let store = isolated_store().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let lookup = store
            .lookup(&query_for(&namespace, "anything", &embedding))
            .await
            .expect("an isolated lookup is a quiet miss");
        assert!(lookup.exact_hit.is_none());
    }

    #[tokio::test]
    async fn mesh_write_while_isolated_returns_a_sanitized_error() {
        let store = isolated_store().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let error = expect_error(
            store
                .put(&write_for(&namespace, "anything", &embedding, "body", 600))
                .await,
            "an isolated write must not land on the wrong owner",
        );
        assert_eq!(error, SemanticStoreError::Unavailable);
        assert_eq!(error.to_string(), "semantic cache backend unavailable");
    }

    #[tokio::test]
    async fn mesh_purge_while_isolated_never_reports_complete() {
        let store = isolated_store().await;
        let report = store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge still reports");
        assert!(!report.complete);
        assert!(report.nodes_failed >= 1);
    }

    #[test]
    fn capability_error_display_never_contains_node_id_address_or_state_payload() {
        let rendered: Vec<String> = [
            SemanticMeshCapabilityError::Missing,
            SemanticMeshCapabilityError::Unknown,
            SemanticMeshCapabilityError::MembershipChanged,
        ]
        .iter()
        .map(|error| error.to_string())
        .collect();
        assert_eq!(
            rendered,
            vec![
                "mesh semantic cache capability is missing".to_string(),
                "mesh semantic cache capability is unknown".to_string(),
                "mesh semantic cache membership changed after verification".to_string(),
            ]
        );
        for text in &rendered {
            assert!(!text.contains("node-"), "{text}");
            assert!(!text.contains("127.0.0.1"), "{text}");
            assert!(!text.contains(CAP_SEMANTIC_CACHE_SNAPSHOT_V1), "{text}");
        }
    }

    // --- Capability evaluation ---

    fn member(node_id: &str, state: ClusterMemberState, incarnation: u64) -> ClusterMember {
        ClusterMember {
            node_id: node_id.to_string(),
            address: None,
            state,
            last_ack_age: Duration::ZERO,
            incarnation,
        }
    }

    fn present(publisher: &str, caps: &[&str]) -> ClusterStateRead<CapabilityAnnouncement> {
        ClusterStateRead::Present(ClusterStateRecord {
            publisher_node_id: publisher.to_string(),
            schema_version: CAPABILITY_SCHEMA_VERSION,
            generation: 1,
            published_at_unix_ms: 1,
            expires_at_unix_ms: u64::MAX,
            authenticated_identity: None,
            payload: CapabilityAnnouncement {
                caps: caps.iter().map(|cap| (*cap).to_string()).collect(),
            },
        })
    }

    #[test]
    fn two_node_old_binary_without_snapshot_capability_is_rejected_before_store_construction() {
        // The old binary publishes a valid declaration for the capability
        // it does know about, and nothing for this one.
        let read = present("node-b", &[crate::key_capability::CAP_CREDENTIAL_BINDING]);
        assert_eq!(
            evaluate_capability_record("node-b", &read),
            Err(SemanticMeshCapabilityError::Missing)
        );
        // A binary that publishes nothing at all is the same refusal, under
        // the closed unknown class.
        assert_eq!(
            evaluate_capability_record("node-b", &ClusterStateRead::Missing),
            Err(SemanticMeshCapabilityError::Unknown)
        );
    }

    #[test]
    fn two_node_missing_or_expired_capability_is_unknown_and_rejected() {
        for read in [
            ClusterStateRead::<CapabilityAnnouncement>::Missing,
            ClusterStateRead::Expired {
                generation: 4,
                expires_at_unix_ms: 1,
            },
            ClusterStateRead::IncompatibleSchema {
                expected: CAPABILITY_SCHEMA_VERSION,
                actual: CAPABILITY_SCHEMA_VERSION + 1,
                generation: 4,
            },
            ClusterStateRead::Unreachable {
                owner: "node-b".to_string(),
            },
            ClusterStateRead::Malformed {
                reason: "bad envelope".to_string(),
            },
        ] {
            assert_eq!(
                evaluate_capability_record("node-b", &read),
                Err(SemanticMeshCapabilityError::Unknown)
            );
        }
    }

    #[test]
    fn two_node_capability_publisher_mismatch_is_unknown_and_rejected() {
        let read = present("node-c", &[CAP_SEMANTIC_CACHE_SNAPSHOT_V1]);
        assert_eq!(
            evaluate_capability_record("node-b", &read),
            Err(SemanticMeshCapabilityError::Unknown)
        );
    }

    #[test]
    fn two_node_homogeneous_capability_is_accepted_before_store_construction() {
        let read = present(
            "node-b",
            &[
                crate::key_capability::CAP_CREDENTIAL_BINDING,
                CAP_SEMANTIC_CACHE_SNAPSHOT_V1,
            ],
        );
        assert_eq!(evaluate_capability_record("node-b", &read), Ok(()));

        let members = vec![
            member("node-a", ClusterMemberState::Alive, 0),
            member("node-b", ClusterMemberState::Alive, 4),
        ];
        let live = live_membership_snapshot(&members).expect("two alive members");
        assert_eq!(live.len(), 2);
        assert_eq!(live.get("node-b"), Some(&4));
        assert!(SemanticMeshCapabilityEvidence {
            live_members: live.clone()
        }
        .matches(&live));
    }

    #[test]
    fn unknown_mixed_suspect_or_unreachable_membership_fails_closed() {
        for state in [ClusterMemberState::Suspect, ClusterMemberState::Unreachable] {
            let members = vec![
                member("node-a", ClusterMemberState::Alive, 0),
                member("node-b", state, 1),
            ];
            assert_eq!(
                live_membership_snapshot(&members),
                Err(SemanticMeshCapabilityError::Unknown)
            );
        }
        assert_eq!(
            live_membership_snapshot(&[]),
            Err(SemanticMeshCapabilityError::Unknown)
        );
        assert_eq!(
            live_membership_snapshot(&[member("node-a", ClusterMemberState::Dead, 0)]),
            Err(SemanticMeshCapabilityError::Unknown)
        );
    }

    #[test]
    fn an_incarnation_change_alone_moves_the_verified_membership_view() {
        // A restarted node that reuses its ID is exactly the case the
        // incarnation guards against.
        let evidence = SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0), ("node-b", 1)]);
        let restarted = live_membership_snapshot(&[
            member("node-a", ClusterMemberState::Alive, 0),
            member("node-b", ClusterMemberState::Alive, 2),
        ])
        .expect("both alive");
        assert!(!evidence.matches(&restarted));
    }

    #[tokio::test]
    async fn two_node_membership_or_incarnation_change_blocks_snapshot_before_transport() {
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-a", VNODES));
        cache.add_node("node-b");
        let pool = Arc::new(TransportClientPool::new());
        let addresses = Arc::new(RwLock::new(HashMap::from([(
            "node-b".to_string(),
            "127.0.0.1:1".to_string(),
        )])));
        let store = MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            // Evidence names a peer the live membership no longer reports.
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0), ("node-b", 7)]),
            cache,
            Arc::clone(&pool),
            peer_addr_from(addresses),
            None,
        );
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];

        assert_eq!(
            expect_error(
                store
                    .lookup(&query_for(&namespace, "anything", &embedding))
                    .await,
                "a moved membership blocks the snapshot"
            ),
            SemanticStoreError::Unavailable
        );
        assert_eq!(
            expect_error(
                store
                    .put(&write_for(&namespace, "anything", &embedding, "b", 600))
                    .await,
                "a moved membership blocks the write"
            ),
            SemanticStoreError::Unavailable
        );
        assert_eq!(
            expect_error(
                store.purge(&SemanticPurgeScope::All).await,
                "a moved membership blocks the purge"
            ),
            SemanticStoreError::Unavailable
        );
        assert!(
            pool.is_empty(),
            "the fence must run before any transport is opened"
        );
    }

    // --- Two-node data path ---

    /// Two caches on one two-node ring, node B backed by a real transport
    /// server, plus a store bound to node A.
    struct TwoNode {
        store: Arc<MeshSemanticCacheStore>,
        cache_a: Arc<DistributedCache<Bytes>>,
        cache_b: Arc<DistributedCache<Bytes>>,
        addresses: Arc<RwLock<HashMap<String, String>>>,
        server_b: TransportServer,
    }

    impl TwoNode {
        /// Take node B away by pointing its address at a dead port.
        ///
        /// Repointing the address rather than only stopping the listener
        /// forces the pool to build a fresh client, so an already-open
        /// connection cannot keep answering after the owner is gone.
        fn fail_node_b(&self) {
            self.addresses
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert("node-b".to_string(), "127.0.0.1:1".to_string());
        }
    }

    async fn two_node() -> TwoNode {
        let cache_b: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("node-b", VNODES));
        cache_b.add_node("node-a");
        let server_b = TransportServer::start(0, Arc::clone(&cache_b))
            .await
            .expect("node B transport binds");
        let addresses = Arc::new(RwLock::new(HashMap::from([(
            "node-b".to_string(),
            format!("127.0.0.1:{}", server_b.local_port()),
        )])));

        let cache_a: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("node-a", VNODES));
        cache_a.add_node("node-b");
        let store = MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0)]),
            Arc::clone(&cache_a),
            Arc::new(TransportClientPool::new()),
            peer_addr_from(Arc::clone(&addresses)),
            None,
        );
        TwoNode {
            store,
            cache_a,
            cache_b,
            addresses,
            server_b,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_remote_semantic_hit_uses_the_common_cache_contract() {
        let fixture = two_node().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let prompt = prompt_with_payload_on(&fixture.cache_a, &namespace, "node-b");

        fixture
            .store
            .put(&write_for(
                &namespace,
                &prompt,
                &embedding,
                "remote-body",
                600,
            ))
            .await
            .expect("write is accepted");

        // Fixture placement only: the payload really did land on node B.
        let entry_key = semantic_entry_key(&namespace, &semantic_prompt_digest(&prompt));
        assert!(fixture.cache_a.get_local(&entry_key).is_none());
        assert!(fixture.cache_b.get_local(&entry_key).is_some());

        // The behavioral assertion runs through the public contract.
        let lookup = fixture
            .store
            .lookup(&query_for(&namespace, &prompt, &embedding))
            .await
            .expect("lookup answers");
        let hit = lookup.exact_hit.expect("the remote record replays");
        assert_eq!(hit.entry.response.body, Bytes::from_static(b"remote-body"));
        fixture.server_b.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_remote_entry_expires_on_the_owner() {
        let fixture = two_node().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let prompt = prompt_with_payload_on(&fixture.cache_a, &namespace, "node-b");

        fixture
            .store
            .put(&write_for(&namespace, &prompt, &embedding, "body", 1))
            .await
            .expect("write is accepted");
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        fixture.cache_a.sweep_expired();
        fixture.cache_b.sweep_expired();

        let lookup = fixture
            .store
            .lookup(&query_for(&namespace, &prompt, &embedding))
            .await
            .expect("lookup answers");
        assert!(lookup.exact_hit.is_none());
        fixture.server_b.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_owner_failure_returns_a_miss() {
        // A failed owner is not covered by replication. The contract is
        // only that no stale or foreign value is replayed.
        let fixture = two_node().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let prompt = prompt_with_payload_on(&fixture.cache_a, &namespace, "node-b");

        fixture
            .store
            .put(&write_for(&namespace, &prompt, &embedding, "body", 600))
            .await
            .expect("write is accepted");
        fixture.fail_node_b();

        let hit = fixture
            .store
            .lookup(&query_for(&namespace, &prompt, &embedding))
            .await
            .ok()
            .and_then(|lookup| lookup.exact_hit);
        assert!(hit.is_none(), "a failed owner must never replay a value");
        fixture.server_b.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_membership_handoff_rewarms_the_new_owner() {
        let fixture = two_node().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let prompt = prompt_with_payload_on(&fixture.cache_a, &namespace, "node-b");
        let entry_key = semantic_entry_key(&namespace, &semantic_prompt_digest(&prompt));

        // 1. Store an entry whose payload owner is node B, then 2. read it
        // back remotely.
        fixture
            .store
            .put(&write_for(&namespace, &prompt, &embedding, "body", 600))
            .await
            .expect("write is accepted");
        assert!(fixture
            .store
            .lookup(&query_for(&namespace, &prompt, &embedding))
            .await
            .expect("lookup answers")
            .exact_hit
            .is_some());

        // 3. Stop node B and observe a miss.
        fixture.fail_node_b();
        assert!(fixture
            .store
            .lookup(&query_for(&namespace, &prompt, &embedding))
            .await
            .ok()
            .and_then(|lookup| lookup.exact_hit)
            .is_none());

        // 4. Remove node B from node A's ring, then 5. prove the old store
        // rejects the changed membership before any transport.
        fixture.cache_a.remove_node("node-b");
        let stale = MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0), ("node-b", 1)]),
            Arc::clone(&fixture.cache_a),
            Arc::new(TransportClientPool::new()),
            no_peers(),
            None,
        );
        assert_eq!(
            expect_error(
                stale
                    .put(&write_for(&namespace, &prompt, &embedding, "body", 600))
                    .await,
                "a stale membership binding must refuse"
            ),
            SemanticStoreError::Unavailable
        );

        // 6. Verify the new one-node capability view and construct the
        // replacement store, which is what a successful reload does.
        let replacement = MeshSemanticCacheStore::from_parts(
            bound_cluster("node-a").await,
            SemanticMeshCapabilityEvidence::for_members(&[("node-a", 0)]),
            Arc::clone(&fixture.cache_a),
            Arc::new(TransportClientPool::new()),
            no_peers(),
            None,
        );

        // 7. Write the same logical entry, then 8. prove the next lookup
        // hits node A.
        replacement
            .put(&write_for(&namespace, &prompt, &embedding, "rewarmed", 600))
            .await
            .expect("the new owner accepts the write");
        assert!(
            fixture.cache_a.get_local(&entry_key).is_some(),
            "the surviving node now owns the shard"
        );
        let hit = replacement
            .lookup(&query_for(&namespace, &prompt, &embedding))
            .await
            .expect("lookup answers")
            .exact_hit
            .expect("the rewarmed record replays");
        assert_eq!(hit.entry.response.body, Bytes::from_static(b"rewarmed"));
        fixture.server_b.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_tenant_isolation_never_returns_a_foreign_candidate() {
        let fixture = two_node().await;
        let tenant_a = namespace("tenant-secret-a", "origin-a.example");
        let tenant_b = namespace("tenant-secret-b", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];

        fixture
            .store
            .put(&write_for(
                &tenant_a,
                "shared prompt",
                &embedding,
                "a-body",
                600,
            ))
            .await
            .expect("write is accepted");

        let lookup = fixture
            .store
            .lookup(&query_for(&tenant_b, "shared prompt", &embedding))
            .await
            .expect("lookup answers");
        assert!(
            lookup.exact_hit.is_none(),
            "an identical prompt and vector in another tenant must not hit"
        );
        fixture.server_b.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_cluster_purge_clears_every_shard() {
        let fixture = two_node().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        let remote_prompt = prompt_with_payload_on(&fixture.cache_a, &namespace, "node-b");
        let local_prompt = prompt_with_payload_on(&fixture.cache_a, &namespace, "node-a");

        for prompt in [&remote_prompt, &local_prompt] {
            fixture
                .store
                .put(&write_for(&namespace, prompt, &embedding, "body", 600))
                .await
                .expect("write is accepted");
        }

        let report = fixture
            .store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge reports");
        assert!(report.complete, "both shards answered");
        assert_eq!(report.nodes_attempted, 2);
        assert_eq!(report.nodes_failed, 0);
        assert!(report.removed >= 2);

        for prompt in [&remote_prompt, &local_prompt] {
            let lookup = fixture
                .store
                .lookup(&query_for(&namespace, prompt, &embedding))
                .await
                .expect("lookup answers");
            assert!(lookup.exact_hit.is_none(), "every shard was cleared");
        }
        fixture.server_b.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_partial_purge_reports_the_failed_peer() {
        let fixture = two_node().await;
        let namespace = namespace("tenant-secret-a", "origin-a.example");
        let embedding = vec![0.9f32, 0.1, 0.2];
        fixture
            .store
            .put(&write_for(
                &namespace,
                "local only",
                &embedding,
                "body",
                600,
            ))
            .await
            .expect("write is accepted");

        // Take node B away before purging. Its records are unreachable, so
        // the report must not claim the purge was complete.
        fixture.fail_node_b();

        let report = fixture
            .store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge still reports");
        assert!(!report.complete);
        assert_eq!(report.nodes_attempted, 2);
        assert_eq!(report.nodes_failed, 1);
        fixture.server_b.shutdown();
    }
}
