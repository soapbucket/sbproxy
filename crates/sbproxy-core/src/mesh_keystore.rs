//! WOR-2064: mesh keystore backend over the replicated cluster substrate.
//!
//! Selected by `proxy.key_management.store.backend: mesh`. Key and
//! credential records live on the cluster's durable replicated state
//! substrate (`proxy.cluster.replication`), so a key minted on one node
//! resolves on its peers with no Redis and no external secrets manager.
//!
//! # Consistency, pinned
//!
//! Writes and reads run at `Consistency::Quorum`, full stop. The levels
//! are not operator-configurable: the config surface is the backend
//! selector alone, and only the replication factor (plus the maintenance
//! cadence and GC grace) comes from the cluster's existing `replication`
//! block. An acknowledged mint therefore survives any minority failure,
//! and a partitioned minority cannot mint.
//!
//! # Revocation is terminal, and it must win
//!
//! Revocation is a status transition on a live record, not a tombstone,
//! and it is written at `Consistency::One` so a partitioned minority can
//! still revoke; anti-entropy carries it outward. On its own the
//! substrate's causal merge would let a higher-version live record
//! displace the revoked one, so [`install_revocation_fence`] registers a
//! merge fence on the replica shard: no candidate ever moves a record
//! out of `Revoked`, at any version, and a revoked record displaces a
//! non-revoked one regardless of version ordering. The fence runs on
//! every replica apply and inside read reconciliation, which is what
//! makes the terminal state absorbing rather than advisory. Rotating a
//! compromised key id means minting a new id; there is no un-revocation.
//!
//! The revoking node's request path denies immediately because the admin
//! mutation path invalidates the local `TtlCache` entry synchronously
//! after the store write and before responding; peers deny after
//! anti-entropy delivers the record and their cache entry expires, so
//! the cluster-wide bound is `anti_entropy_interval_secs` plus the cache
//! TTL. An operator who needs synchronous cluster-wide denial needs the
//! Redis backend, whose pub/sub invalidation is push-based.
//!
//! # Compare-and-swap is write-then-verify
//!
//! [`KeyStore::put_key_if_revision`] has no distributed lock to lean on.
//! It reads at quorum (revision mismatch is a `Conflict`), writes the
//! record at the observed register version plus one, then reads back at
//! quorum and reports `Applied` only if this node's exact register won
//! the deterministic merge. A losing concurrent writer sees `Conflict`.
//! A false `Conflict` is possible and the caller retries; a false
//! `Applied` is not. This backend never returns
//! [`KeyPolicyCasResult::Unsupported`].
//!
//! # Plaintext refuses to replicate
//!
//! [`sbproxy_keystore::record::CredentialMaterial::Plaintext`] is
//! refused at mint: the substrate copies records to every replica shard
//! on disk, and a raw secret has no business being multiplied that way.
//! Envelope and vault-reference material replicate fine, and key records
//! are unaffected because they only ever store an HMAC of the secret.
//!
//! # Readiness after quarantine
//!
//! A node offline longer than the tombstone GC grace rejoins with a
//! wiped (quarantined) shard. Until its first complete anti-entropy
//! round finishes, this backend refuses reads with an error instead of
//! answering from a shard it knows is unrepopulated; the request path
//! turns that into the operator's configured `failure_posture` (closed
//! by default). The admin health registry surfaces the same signal
//! through the `keystore` probe.
//!
//! # Failed mints are accepted litter
//!
//! A mint that failed below quorum may still have landed on some
//! replicas, and anti-entropy will happily propagate it later. That is
//! deliberate: the bearer never received the secret, so the orphan
//! record is inert. The operational consequence is documented where
//! operators look: a mint that returned an error must not be assumed
//! not-to-have-happened; reconcile by listing.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use base64::Engine as _;
use sbproxy_keystore::record::{CredentialRecord, KeyRecord, RecordStatus};
use sbproxy_keystore::{KeyPolicyCasResult, KeyStore};
use sbproxy_mesh::state::register::VersionedLwwRegister;
use sbproxy_mesh::state::replicated::{
    Consistency, MergeFenceFn, ReplicaShard, ReplicatedStore, StateError,
};

/// Namespace shared by every record this backend stores on the substrate.
const KEY_PREFIX: &str = "keystore:v1:key:";
/// Credential-record namespace.
const CRED_PREFIX: &str = "keystore:v1:cred:";

/// Fleet-listing page size. Bounded by the substrate anyway; kept modest
/// so a listing never holds a large buffer.
const LIST_PAGE: usize = 512;

fn key_state_key(key_id: &str) -> String {
    format!("{KEY_PREFIX}{key_id}")
}

fn cred_state_key(id: &str) -> String {
    format!("{CRED_PREFIX}{id}")
}

/// Decode a live register's application value as a [`KeyRecord`].
/// Tombstones and undecodable values are `None`.
fn decode_key_register(register: &VersionedLwwRegister) -> Option<KeyRecord> {
    if register.is_tombstone() {
        return None;
    }
    let encoded = register.value()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Install the no-un-revocation merge fence for keystore key records on
/// `shard` (idempotent; reinstalling replaces the previous fence).
///
/// The fence makes `Revoked` absorbing between live records: a stored
/// revoked record repels every non-revoked live candidate whatever its
/// version, and a revoked candidate displaces a non-revoked live record
/// the same way. Tombstones are left to the substrate's own rules, so a
/// deliberate delete of a revoked key still works. The verdict is
/// symmetric under argument swap, which the substrate requires so that
/// replicas and read reconciliation converge in any order.
pub fn install_revocation_fence(shard: &ReplicaShard) {
    let fence: MergeFenceFn = Arc::new(|current, candidate| {
        if current.is_tombstone() || candidate.is_tombstone() {
            return None;
        }
        let current_revoked = decode_key_register(current)
            .is_some_and(|record| record.status == RecordStatus::Revoked);
        let candidate_revoked = decode_key_register(candidate)
            .is_some_and(|record| record.status == RecordStatus::Revoked);
        match (current_revoked, candidate_revoked) {
            (true, false) => Some(false),
            (false, true) => Some(true),
            _ => None,
        }
    });
    shard.install_merge_fence(KEY_PREFIX, fence);
}

/// Post-quarantine readiness view shared by the backend and the admin
/// health registry's `keystore` probe.
pub struct MeshKeystoreReadiness {
    substrate: Arc<ReplicatedStore>,
    quarantined_at_boot: bool,
}

impl MeshKeystoreReadiness {
    fn new(substrate: Arc<ReplicatedStore>) -> Self {
        let quarantined_at_boot = substrate.shard().quarantined();
        Self {
            substrate,
            quarantined_at_boot,
        }
    }

    /// Whether the backend may serve authentication. A node whose shard
    /// was quarantined on open stays unready until the maintenance loop
    /// completes one full anti-entropy round.
    pub fn ready(&self) -> bool {
        !self.quarantined_at_boot || self.substrate.complete_anti_entropy_rounds() > 0
    }
}

fn readiness_slot() -> &'static ArcSwapOption<MeshKeystoreReadiness> {
    static SLOT: OnceLock<ArcSwapOption<MeshKeystoreReadiness>> = OnceLock::new();
    SLOT.get_or_init(|| ArcSwapOption::from(None))
}

/// The active mesh keystore's readiness view, or `None` when the mesh
/// backend is not running. Read by the `keystore` health probe.
pub fn current_readiness() -> Option<Arc<MeshKeystoreReadiness>> {
    readiness_slot().load_full()
}

/// Publish `readiness` as the process-wide view the health probe reads.
/// Called when a key-plane generation with the mesh backend is built.
pub fn install_readiness(readiness: Arc<MeshKeystoreReadiness>) {
    readiness_slot().store(Some(readiness));
}

/// Clear the published readiness view. Called when a committed key-plane
/// generation does not run the mesh backend.
pub fn clear_readiness() {
    readiness_slot().store(None);
}

/// What a CAS attempt observed before writing. Produced by the quorum
/// read step and consumed by the write-and-verify step; split so the
/// deterministic loser-construction test can interleave a competing
/// writer between the two.
struct CasObservation {
    current: KeyRecord,
    register_version: u64,
}

/// [`KeyStore`] over the cluster's replicated state substrate.
pub struct MeshKeyStore {
    /// Pinned quorum coordinator: every read and every non-terminal write.
    quorum: Arc<ReplicatedStore>,
    /// Pinned one-ack coordinator: terminal revocation writes, and the
    /// read fallback that lets a partitioned minority still revoke.
    one: Arc<ReplicatedStore>,
    readiness: Arc<MeshKeystoreReadiness>,
    /// Node-local mutation counter backing [`KeyStore::revision`]. The
    /// substrate has no cluster-wide atomic counter to lend; cross-node
    /// coherence rides anti-entropy plus cache TTL, not revision polls,
    /// so a per-node counter that moves on every local mutation is the
    /// honest value.
    revision: AtomicU64,
}

impl MeshKeyStore {
    /// Bind the keystore to the node's replicated substrate.
    ///
    /// The consistency pin happens here: coordinators are cloned from
    /// `substrate` with quorum (and one-ack, for revocation) levels,
    /// whatever `proxy.cluster.replication` configured for other
    /// consumers. The revocation fence is (re)installed on the shared
    /// shard as well, though the cluster bootstrap already installs it
    /// early so the boot window before any key plane exists is covered.
    pub fn new(substrate: Arc<ReplicatedStore>) -> Self {
        install_revocation_fence(&substrate.shard());
        let quorum = Arc::new(substrate.with_consistency(Consistency::Quorum, Consistency::Quorum));
        let one = Arc::new(substrate.with_consistency(Consistency::One, Consistency::One));
        let readiness = Arc::new(MeshKeystoreReadiness::new(substrate));
        Self {
            quorum,
            one,
            readiness,
            revision: AtomicU64::new(0),
        }
    }

    /// The readiness view for this backend instance, shared with the
    /// health probe via [`install_readiness`].
    pub fn readiness(&self) -> Arc<MeshKeystoreReadiness> {
        self.readiness.clone()
    }

    fn bump(&self) {
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    fn ensure_ready(&self) -> Result<()> {
        if self.readiness.ready() {
            return Ok(());
        }
        anyhow::bail!(
            "mesh keystore is not ready: this node rejoined after exceeding the tombstone GC \
             grace period, its replica shard was quarantined, and the first complete \
             anti-entropy round has not finished yet; refusing to serve authentication from \
             an unrepopulated shard"
        )
    }

    fn read_error(op: &str, error: StateError) -> anyhow::Error {
        anyhow::anyhow!("mesh keystore {op}: {error}")
    }

    fn write_error(op: &str, error: StateError) -> anyhow::Error {
        match error {
            StateError::QuorumFailed { acked, required } => anyhow::anyhow!(
                "mesh keystore {op} failed below quorum ({acked}/{required} acks). The record \
                 may still exist on some replicas and propagate through anti-entropy later, so \
                 a failed mint must not be assumed not-to-have-happened; reconcile by listing"
            ),
            other => anyhow::anyhow!("mesh keystore {op}: {other}"),
        }
    }

    /// Quorum-read one key record. `Ok(None)` for missing keys and
    /// tombstones.
    async fn read_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        let outcome = self
            .quorum
            .get_versioned(&key_state_key(key_id))
            .await
            .map_err(|error| Self::read_error("key read", error))?;
        let Some(register) = outcome.register else {
            return Ok(None);
        };
        if register.is_tombstone() {
            return Ok(None);
        }
        let bytes = outcome
            .value
            .context("mesh keystore key read: live register without a value")?;
        let record = serde_json::from_slice::<KeyRecord>(&bytes)
            .context("mesh keystore key read: undecodable record")?;
        Ok(Some(record))
    }

    async fn read_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        let outcome = self
            .quorum
            .get_versioned(&cred_state_key(id))
            .await
            .map_err(|error| Self::read_error("credential read", error))?;
        let Some(register) = outcome.register else {
            return Ok(None);
        };
        if register.is_tombstone() {
            return Ok(None);
        }
        let bytes = outcome
            .value
            .context("mesh keystore credential read: live register without a value")?;
        let record = serde_json::from_slice::<CredentialRecord>(&bytes)
            .context("mesh keystore credential read: undecodable record")?;
        Ok(Some(record))
    }

    /// Every distinct record id under `prefix`, gathered fleet-wide.
    ///
    /// An unreachable member fails the listing loudly rather than
    /// returning a silently partial page: listing is the reconciliation
    /// tool for failed mints, so "complete" has to be verifiable.
    async fn list_ids(&self, prefix: &str) -> Result<Vec<String>> {
        let mut ids: BTreeSet<String> = BTreeSet::new();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .quorum
                .fleet_state_page(prefix, token.as_deref(), LIST_PAGE)
                .await;
            if !page.unreachable.is_empty() {
                anyhow::bail!(
                    "mesh keystore listing is incomplete: unreachable cluster members {:?}; \
                     retry when the fleet is reachable, because a partial listing cannot be \
                     used to reconcile mints",
                    page.unreachable
                );
            }
            for entry in &page.entries {
                if let Some(id) = entry.key.strip_prefix(prefix) {
                    ids.insert(id.to_string());
                }
            }
            match page.next_page_token {
                Some(next) => token = Some(next),
                None => break,
            }
        }
        Ok(ids.into_iter().collect())
    }

    /// Terminal revocation write at `Consistency::One`.
    ///
    /// One acknowledgement is enough on purpose: a node cut off in the
    /// minority of a partition must still be able to revoke. The merge
    /// fence keeps the record terminal on every replica that ever sees
    /// it, and anti-entropy carries it across the heal.
    async fn write_revoked(&self, record: &KeyRecord, register_version: Option<u64>) -> Result<()> {
        let payload = serde_json::to_vec(record).context("encode revoked key record")?;
        let key = key_state_key(&record.key_id);
        match register_version {
            Some(observed) => {
                self.one
                    .put_versioned(&key, &payload, 0, observed + 1, Some(observed))
                    .await
                    .map_err(|error| Self::write_error("revocation", error))?;
            }
            None => {
                self.one
                    .put(&key, &payload, 0)
                    .await
                    .map_err(|error| Self::write_error("revocation", error))?;
            }
        }
        Ok(())
    }

    /// CAS step 1: observe the current record and its register version.
    ///
    /// Reads at quorum. For a revocation the read falls back to one-ack
    /// when the quorum is unreachable, so a partitioned minority can
    /// still observe (its own replica of) the record it is revoking.
    async fn observe_for_cas(
        &self,
        key_id: &str,
        revoking: bool,
    ) -> Result<Option<CasObservation>> {
        let key = key_state_key(key_id);
        let outcome = match self.quorum.get_versioned(&key).await {
            Ok(outcome) => outcome,
            Err(error) if revoking => self
                .one
                .get_versioned(&key)
                .await
                .map_err(|_| Self::read_error("revocation read", error))?,
            Err(error) => return Err(Self::read_error("key CAS read", error)),
        };
        let Some(register) = outcome.register else {
            return Ok(None);
        };
        if register.is_tombstone() {
            return Ok(None);
        }
        let bytes = outcome
            .value
            .context("mesh keystore key CAS read: live register without a value")?;
        let current = serde_json::from_slice::<KeyRecord>(&bytes)
            .context("mesh keystore key CAS read: undecodable record")?;
        Ok(Some(CasObservation {
            current,
            register_version: register.logical_version(),
        }))
    }

    /// CAS steps 2 and 3: write at the observed version plus one, read
    /// back, and report `Applied` only if this node's register won.
    async fn cas_commit(
        &self,
        mut record: KeyRecord,
        expected_revision: u64,
        observation: &CasObservation,
    ) -> Result<KeyPolicyCasResult> {
        if observation.current.policy_revision != expected_revision {
            return Ok(KeyPolicyCasResult::Conflict {
                actual_revision: observation.current.policy_revision,
            });
        }
        let policy_revision = expected_revision
            .checked_add(1)
            .context("key policy revision overflow")?;
        record.policy_revision = policy_revision;
        let revoking = record.status == RecordStatus::Revoked;
        let payload = serde_json::to_vec(&record).context("encode key record for CAS")?;
        let key = key_state_key(&record.key_id);
        let next_version = observation.register_version + 1;

        if revoking {
            // Terminal transition: written at one ack so a minority can
            // revoke. The fence makes revocation absorbing, so once any
            // replica committed it the outcome cannot be lost; verify at
            // one-ack that a revoked record is what now stands.
            self.write_revoked(&record, Some(observation.register_version))
                .await?;
            let verify = self
                .one
                .get_versioned(&key)
                .await
                .map_err(|error| Self::read_error("revocation verify", error))?;
            let revoked_stands = verify
                .register
                .as_ref()
                .and_then(decode_key_register)
                .is_some_and(|stored| stored.status == RecordStatus::Revoked);
            if revoked_stands {
                self.bump();
                return Ok(KeyPolicyCasResult::Applied { policy_revision });
            }
            return Ok(KeyPolicyCasResult::Conflict {
                actual_revision: observation.current.policy_revision,
            });
        }

        let receipt = self
            .quorum
            .put_versioned(
                &key,
                &payload,
                0,
                next_version,
                Some(observation.register_version),
            )
            .await
            .map_err(|error| Self::write_error("key CAS write", error))?;

        // Verify: the fan-out acknowledges applies, not victories, so a
        // concurrent equal-version writer may have won the deterministic
        // merge instead. Applied only when the reconciled winner is this
        // exact register; anything else is a Conflict the caller retries.
        // A false Conflict is acceptable; a false Applied never is.
        let verify = self
            .quorum
            .get_versioned(&key)
            .await
            .map_err(|error| Self::read_error("key CAS verify", error))?;
        let ours = &receipt.register;
        let won = verify.register.as_ref().is_some_and(|winner| {
            !winner.is_tombstone()
                && winner.logical_version() == ours.logical_version()
                && winner.node_id() == ours.node_id()
                && winner.timestamp_ms() == ours.timestamp_ms()
                && winner.value() == ours.value()
        });
        if won {
            self.bump();
            return Ok(KeyPolicyCasResult::Applied { policy_revision });
        }
        let actual_revision = verify
            .register
            .as_ref()
            .and_then(decode_key_register)
            .map_or(observation.current.policy_revision, |winner| {
                winner.policy_revision
            });
        Ok(KeyPolicyCasResult::Conflict { actual_revision })
    }
}

#[async_trait]
impl KeyStore for MeshKeyStore {
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        self.ensure_ready()?;
        self.read_key(key_id).await
    }

    async fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        self.ensure_ready()?;
        let mut out = Vec::new();
        for id in self.list_ids(KEY_PREFIX).await? {
            if let Some(record) = self.read_key(&id).await? {
                out.push(record);
            }
        }
        Ok(out)
    }

    async fn put_key(&self, record: KeyRecord) -> Result<()> {
        if record.status == RecordStatus::Revoked {
            self.write_revoked(&record, None).await?;
        } else {
            let payload = serde_json::to_vec(&record).context("encode key record")?;
            self.quorum
                .put(&key_state_key(&record.key_id), &payload, 0)
                .await
                .map_err(|error| Self::write_error("key write", error))?;
        }
        self.bump();
        Ok(())
    }

    async fn put_key_if_revision(
        &self,
        record: KeyRecord,
        expected_revision: u64,
    ) -> Result<KeyPolicyCasResult> {
        self.ensure_ready()?;
        let revoking = record.status == RecordStatus::Revoked;
        let Some(observation) = self.observe_for_cas(&record.key_id, revoking).await? else {
            return Ok(KeyPolicyCasResult::NotFound);
        };
        self.cas_commit(record, expected_revision, &observation)
            .await
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        self.quorum
            .delete(&key_state_key(key_id))
            .await
            .map_err(|error| Self::write_error("key delete", error))?;
        self.bump();
        Ok(())
    }

    async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        self.ensure_ready()?;
        self.read_credential(id).await
    }

    async fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        self.ensure_ready()?;
        let mut out = Vec::new();
        for id in self.list_ids(CRED_PREFIX).await? {
            if let Some(record) = self.read_credential(&id).await? {
                out.push(record);
            }
        }
        Ok(out)
    }

    async fn put_credential(&self, record: CredentialRecord) -> Result<()> {
        // The record, not the field: a rotation leaves the pre-rotation
        // material in `prev_material`, and a guard that only reads
        // `material` would replicate a plaintext secret that moved one
        // slot to the left (WOR-2567).
        if record.carries_plaintext() {
            anyhow::bail!(
                "mesh keystore refuses credential '{}': plaintext material would replicate \
                 the raw secret onto every replica shard's disk. Store it as an AEAD envelope \
                 (hand the admin API or the config seed a 'secret', which is sealed under the \
                 master key) or as a vault reference ('vault_ref'), neither of which \
                 replicates plaintext. This covers the material a rotation retired as well as \
                 the current one",
                record.id
            );
        }
        let payload = serde_json::to_vec(&record).context("encode credential record")?;
        self.quorum
            .put(&cred_state_key(&record.id), &payload, 0)
            .await
            .map_err(|error| Self::write_error("credential write", error))?;
        self.bump();
        Ok(())
    }

    async fn delete_credential(&self, id: &str) -> Result<()> {
        self.quorum
            .delete(&cred_state_key(id))
            .await
            .map_err(|error| Self::write_error("credential delete", error))?;
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
    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use sbproxy_mesh::state::distributed_cache::DistributedCache;
    use sbproxy_mesh::state::replicated::{MeshClock, ReplicationSettings, ShardLimits};
    use sbproxy_mesh::transport::TransportClientPool;

    /// Single-node replicated substrate: the local shard is the whole
    /// replica set, so quorum semantics are exercised without transport.
    fn substrate() -> Arc<ReplicatedStore> {
        let clock: MeshClock = Arc::new(|| 1_000_000);
        let shard = Arc::new(ReplicaShard::in_memory(ShardLimits::default(), 0, clock));
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-a", 128));
        Arc::new(ReplicatedStore::new(
            shard,
            cache,
            Arc::new(TransportClientPool::new()),
            Arc::new(|_| None),
            Arc::new(|| false),
            ReplicationSettings {
                replication_factor: 1,
                write_consistency: Consistency::One,
                read_consistency: Consistency::One,
                anti_entropy_interval_secs: 3_600,
                tombstone_gc_grace_secs: 0,
            },
        ))
    }

    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn key_record(id: &str) -> KeyRecord {
        KeyRecord::new(id, "hash", ts())
    }

    fn credential(id: &str, material: serde_json::Value) -> CredentialRecord {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": id,
            "material": material,
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        }))
        .expect("credential fixture")
    }

    fn encoded(record: &KeyRecord) -> String {
        base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(record).expect("encode fixture"))
    }

    #[tokio::test]
    async fn key_and_credential_crud_roundtrip_with_local_revision_bumps() {
        let store = MeshKeyStore::new(substrate());
        assert_eq!(store.revision().await.unwrap(), 0);

        let mut rec = key_record("k1");
        rec.name = Some("first".into());
        store.put_key(rec).await.unwrap();
        assert_eq!(store.revision().await.unwrap(), 1);

        let got = store.get_key("k1").await.unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("first"));
        assert_eq!(got.policy_revision, 1);
        assert_eq!(store.list_keys().await.unwrap().len(), 1);

        store.delete_key("k1").await.unwrap();
        assert!(store.get_key("k1").await.unwrap().is_none());
        assert!(store.list_keys().await.unwrap().is_empty());
        assert_eq!(store.revision().await.unwrap(), 2);

        store
            .put_credential(credential(
                "c1",
                serde_json::json!({"kind": "vault_ref", "reference": "vault://openai"}),
            ))
            .await
            .unwrap();
        assert!(store.get_credential("c1").await.unwrap().is_some());
        assert_eq!(store.list_credentials().await.unwrap().len(), 1);
        store.delete_credential("c1").await.unwrap();
        assert!(store.get_credential("c1").await.unwrap().is_none());
        assert_eq!(store.revision().await.unwrap(), 4);
    }

    #[tokio::test]
    async fn cas_applies_then_rejects_stale_revisions() {
        let store = MeshKeyStore::new(substrate());
        store.put_key(key_record("k1")).await.unwrap();

        let mut first = store.get_key("k1").await.unwrap().unwrap();
        first.name = Some("first".into());
        assert_eq!(
            store.put_key_if_revision(first, 1).await.unwrap(),
            KeyPolicyCasResult::Applied { policy_revision: 2 }
        );

        let mut stale = key_record("k1");
        stale.name = Some("stale".into());
        assert_eq!(
            store.put_key_if_revision(stale, 1).await.unwrap(),
            KeyPolicyCasResult::Conflict { actual_revision: 2 }
        );

        let stored = store.get_key("k1").await.unwrap().unwrap();
        assert_eq!(stored.policy_revision, 2);
        assert_eq!(stored.name.as_deref(), Some("first"));

        assert_eq!(
            store
                .put_key_if_revision(key_record("missing"), 1)
                .await
                .unwrap(),
            KeyPolicyCasResult::NotFound
        );
        assert!(store.get_key("missing").await.unwrap().is_none());
    }

    /// The deterministic loser construction from the design: a competing
    /// register lands at the same version between this writer's read and
    /// its write. The competitor's node id sorts above this node's, so
    /// the causal merge picks it on every replica, and the verify step
    /// must report Conflict, never Applied.
    #[tokio::test]
    async fn a_losing_concurrent_writer_never_observes_applied() {
        let substrate = substrate();
        let store = MeshKeyStore::new(substrate.clone());
        store.put_key(key_record("k1")).await.unwrap();

        let observation = store.observe_for_cas("k1", false).await.unwrap().unwrap();
        assert_eq!(observation.current.policy_revision, 1);
        assert_eq!(observation.register_version, 1);

        // The concurrent writer: same next version, higher node id,
        // applied to the shard exactly as a peer's fan-out would.
        let mut competing = key_record("k1");
        competing.policy_revision = 2;
        competing.name = Some("competitor".into());
        let register =
            VersionedLwwRegister::live(encoded(&competing), "node-z", 1_000_000, 2, Some(1));
        substrate
            .shard()
            .apply(&key_state_key("k1"), &register, 0)
            .unwrap();

        let mut ours = key_record("k1");
        ours.name = Some("loser".into());
        let outcome = store.cas_commit(ours, 1, &observation).await.unwrap();
        assert_eq!(
            outcome,
            KeyPolicyCasResult::Conflict { actual_revision: 2 },
            "the loser of the deterministic merge must never see Applied"
        );
        let stored = store.get_key("k1").await.unwrap().unwrap();
        assert_eq!(stored.name.as_deref(), Some("competitor"));

        // The mirror construction: a competitor whose node id sorts
        // below ours loses the merge, and only then is Applied reported.
        store.put_key(key_record("k2")).await.unwrap();
        let observation = store.observe_for_cas("k2", false).await.unwrap().unwrap();
        let mut competing = key_record("k2");
        competing.policy_revision = 2;
        competing.name = Some("underdog".into());
        let register =
            VersionedLwwRegister::live(encoded(&competing), "node-0", 1_000_000, 2, Some(1));
        substrate
            .shard()
            .apply(&key_state_key("k2"), &register, 0)
            .unwrap();
        let mut ours = key_record("k2");
        ours.name = Some("winner".into());
        assert_eq!(
            store.cas_commit(ours, 1, &observation).await.unwrap(),
            KeyPolicyCasResult::Applied { policy_revision: 2 }
        );
        let stored = store.get_key("k2").await.unwrap().unwrap();
        assert_eq!(stored.name.as_deref(), Some("winner"));
    }

    /// The no-un-revocation fence: a stale replica pushing an active
    /// record at a higher register version cannot resurrect a revoked
    /// key, on the shard or through a read.
    #[tokio::test]
    async fn a_stale_higher_version_candidate_cannot_resurrect_a_revoked_record() {
        let substrate = substrate();
        let store = MeshKeyStore::new(substrate.clone());
        store.put_key(key_record("k1")).await.unwrap();

        let mut revoked = store.get_key("k1").await.unwrap().unwrap();
        revoked.status = RecordStatus::Revoked;
        assert_eq!(
            store.put_key_if_revision(revoked, 1).await.unwrap(),
            KeyPolicyCasResult::Applied { policy_revision: 2 }
        );

        // Without the fence, merge_after_tombstone_fence would install
        // this candidate: it is live and carries a higher version.
        let mut zombie = key_record("k1");
        zombie.policy_revision = 9;
        zombie.name = Some("zombie".into());
        let register =
            VersionedLwwRegister::live(encoded(&zombie), "node-z", 2_000_000, 9, Some(8));
        substrate
            .shard()
            .apply(&key_state_key("k1"), &register, 0)
            .unwrap();

        let stored = store.get_key("k1").await.unwrap().unwrap();
        assert_eq!(stored.status, RecordStatus::Revoked);
        assert_ne!(stored.name.as_deref(), Some("zombie"));
        assert!(!stored.is_usable(Utc::now()));
    }

    /// Seam M, replaced, half two: the mesh enforcer.
    ///
    /// A rotation moves the pre-rotation material into `prev_material`, so
    /// a record whose current slot is a harmless vault reference can still
    /// be carrying a plaintext secret. `put_credential` reading only
    /// `record.material` would replicate that secret onto every replica
    /// shard's disk while the record looked clean.
    ///
    /// Reverting `mesh_keystore.rs`'s guard to
    /// `record.material.is_plaintext()` reddens this and leaves the
    /// predicate test in `record.rs` green, which is the whole point of
    /// having this one.
    #[tokio::test]
    async fn a_rotated_records_retired_plaintext_is_refused_at_mint() {
        let store = MeshKeyStore::new(substrate());
        let mut rotated = credential(
            "rotated-cred",
            serde_json::json!({"kind": "vault_ref", "reference": "vault://new"}),
        );
        rotated.prev_material = Some(sbproxy_keystore::record::CredentialMaterial::Plaintext {
            value: "sk-retired-but-still-on-disk".to_string(),
        });
        rotated.prev_material_expires_at =
            Some(Utc::now() + chrono::Duration::try_seconds(300).expect("representable"));
        // The current slot must look clean, or this test cannot tell the
        // two guards apart. Asserted through the public shape because
        // `is_plaintext` is deliberately crate-private to `sbproxy-keystore`
        // now, which is itself the fix: no out-of-crate caller can reach
        // the one-slot answer, this test included.
        assert!(matches!(
            rotated.material,
            sbproxy_keystore::record::CredentialMaterial::VaultRef { .. }
        ));

        let error = store
            .put_credential(rotated)
            .await
            .expect_err("a retired plaintext must not replicate either");
        let message = format!("{error:#}");
        assert!(
            message.contains("rotated-cred"),
            "names the credential: {message}"
        );
        assert!(
            !message.contains("sk-retired-but-still-on-disk"),
            "the refusal must not echo the retired secret: {message}"
        );
        assert!(store
            .get_credential("rotated-cred")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn plaintext_credential_material_is_refused_at_mint() {
        let store = MeshKeyStore::new(substrate());
        let error = store
            .put_credential(credential(
                "raw-cred",
                serde_json::json!({"kind": "plaintext", "value": "sk-super-secret"}),
            ))
            .await
            .expect_err("plaintext must not replicate");
        let message = format!("{error:#}");
        assert!(
            message.contains("raw-cred"),
            "names the credential: {message}"
        );
        assert!(
            message.contains("envelope") && message.contains("vault"),
            "points at the sealed alternatives: {message}"
        );
        assert!(
            !message.contains("sk-super-secret"),
            "the refusal must not echo the secret: {message}"
        );
        assert!(store.get_credential("raw-cred").await.unwrap().is_none());

        // Sealed material replicates fine; key records were never
        // affected because they store only the HMAC of the secret.
        store
            .put_credential(credential(
                "sealed",
                serde_json::json!({"kind": "vault_ref", "reference": "vault://x"}),
            ))
            .await
            .unwrap();
        assert!(store.get_credential("sealed").await.unwrap().is_some());
        store.put_key(key_record("hmac-key")).await.unwrap();
    }

    #[tokio::test]
    async fn a_quarantined_node_refuses_reads_until_its_first_complete_round() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shard.redb");
        let clock_cell = Arc::new(AtomicU64::new(10_000));
        let clock: MeshClock = {
            let cell = clock_cell.clone();
            Arc::new(move || cell.load(Ordering::Relaxed))
        };
        let shard = ReplicaShard::open(&path, ShardLimits::default(), 60_000, clock.clone())
            .expect("open shard");
        drop(shard);

        // Rejoin after longer than the 60 second grace: quarantined.
        clock_cell.store(10_000 + 61_000, Ordering::Relaxed);
        let shard = Arc::new(
            ReplicaShard::open(&path, ShardLimits::default(), 60_000, clock).expect("reopen"),
        );
        assert!(shard.quarantined());
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-a", 128));
        let substrate = Arc::new(ReplicatedStore::new(
            shard,
            cache,
            Arc::new(TransportClientPool::new()),
            Arc::new(|_| None),
            Arc::new(|| false),
            ReplicationSettings {
                replication_factor: 1,
                write_consistency: Consistency::One,
                read_consistency: Consistency::One,
                anti_entropy_interval_secs: 3_600,
                tombstone_gc_grace_secs: 60,
            },
        ));
        let store = MeshKeyStore::new(substrate.clone());
        assert!(!store.readiness().ready());
        let error = store
            .get_key("any")
            .await
            .expect_err("an unrepopulated shard must not serve authentication");
        assert!(
            format!("{error:#}").contains("not ready"),
            "unexpected error: {error:#}"
        );

        // With no peers the first maintenance round is trivially
        // complete, and the backend opens up.
        substrate.maintenance_round().await;
        assert!(store.readiness().ready());
        assert!(store.get_key("any").await.unwrap().is_none());
    }

    /// The revoking node denies immediately even with a warm cache: the
    /// admin mutation path invalidates the local TtlCache entry
    /// synchronously after the store write and before it responds.
    #[test]
    fn a_revoke_through_the_admin_api_denies_immediately_with_a_warm_cache() {
        let _guard = crate::key_plane::test_plane_guard();
        let store: Arc<dyn KeyStore> = Arc::new(MeshKeyStore::new(substrate()));
        let cache = Arc::new(sbproxy_keystore::TtlCache::new(
            store,
            sbproxy_keystore::TtlCacheConfig::default(),
        ));
        let crypto =
            sbproxy_keystore::crypto::KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts(
            crypto, cache, false, false, None,
        ));
        crate::key_plane::install_key_plane_for_test(plane.clone());

        let resp = crate::admin_keys::dispatch("POST", "/admin/keys", Some(r#"{"name":"warm"}"#))
            .expect("keys route");
        assert_eq!(resp.0, 201, "{}", resp.2);
        let created: serde_json::Value = serde_json::from_str(&resp.2).expect("mint response");
        let key_id = created["key"]["key_id"]
            .as_str()
            .expect("key id")
            .to_string();

        // Warm the cache on the minting node.
        let warmed = crate::key_plane::block_on_keystore(plane.cache().resolve_key(&key_id))
            .expect("resolve")
            .expect("record present");
        assert_eq!(warmed.status, RecordStatus::Active);

        let resp =
            crate::admin_keys::dispatch("POST", &format!("/admin/keys/{key_id}/revoke"), None)
                .expect("revoke route");
        assert_eq!(resp.0, 200, "{}", resp.2);

        // No TTL wait: the very next resolve already sees the terminal
        // record because the mutation path invalidated the entry.
        let resolved = crate::key_plane::block_on_keystore(plane.cache().resolve_key(&key_id))
            .expect("resolve after revoke")
            .expect("record present");
        assert_eq!(resolved.status, RecordStatus::Revoked);
        assert!(!resolved.is_usable(Utc::now()));
    }

    /// WOR-2225: installing the live key plane is more than writing the
    /// slot, and `activate_key_plane` is the only thing that does it.
    ///
    /// A committed generation that does not run the mesh backend has to
    /// retract the published readiness view, or `/readyz` goes on
    /// reporting a `keystore` backend that is gone. A bare store into the
    /// plane slot skips that step, which is what the old
    /// `install_key_plane` wrapper was, and the reason it is now
    /// `cfg(test)` and named for it. Asserted in both directions, because
    /// removing a plane runs through the same seam rather than a second
    /// one.
    #[test]
    fn activating_a_non_mesh_generation_retracts_the_published_readiness() {
        let _guard = crate::key_plane::test_plane_guard();
        let backend = MeshKeyStore::new(substrate());
        install_readiness(backend.readiness());
        assert!(
            current_readiness().is_some(),
            "the mesh backend publishes readiness when it is built"
        );

        let store: Arc<dyn KeyStore> = Arc::new(backend);
        let cache = Arc::new(sbproxy_keystore::TtlCache::new(
            store,
            sbproxy_keystore::TtlCacheConfig::default(),
        ));
        let crypto =
            sbproxy_keystore::crypto::KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts(
            crypto, cache, false, false, None,
        ));

        crate::key_plane::activate_key_plane(Some(plane), None);
        assert!(
            crate::key_plane::current_key_plane().is_some(),
            "the generation's plane is published"
        );
        assert!(
            current_readiness().is_none(),
            "a non-mesh generation must retract the readiness view it did not build"
        );

        crate::key_plane::activate_key_plane(None, None);
        assert!(
            crate::key_plane::current_key_plane().is_none(),
            "removing the plane is the same seam, not a second one"
        );
    }
}
