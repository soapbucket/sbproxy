// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! A durable, node-local, content-addressed ring of applied config
//! revisions: the history a rollback reads to find the last known good
//! document and the audit trail an operator reads to see what changed.
//!
//! # On-disk layout
//!
//! ```text
//! <dir>/
//!   index.json               ring index: lineage, lkg pointer, entries
//!   blobs/<sha256>.yaml.zst  pre-resolution document bytes, content addressed
//!   rejected/<sha256>.json   refused candidates and why (populated by a later change)
//! ```
//!
//! Every file is written to a temporary name in its own directory,
//! flushed, then renamed over the target, so a crash mid-write leaves the
//! old file or the new one and never a truncated one a later boot would
//! choke on. This mirrors [`crate::config_authority::AuthorityStore`];
//! see that module's header for the fuller "why" of the temp-write and
//! repair-at-open pattern this one reuses.
//!
//! # Pre-resolution bytes only
//!
//! A stored blob is the document exactly as it was read, before
//! `${VAR}` / `vault://` / `secret://` interpolation. A ring that stored
//! resolved documents would be a ring of decrypted secrets on disk; this
//! one is never that, by construction, because callers only ever hand it
//! the bytes that existed before resolution ran.
//!
//! # Repair at open is deliberately more forgiving than the config
//! # authority's
//!
//! [`AuthorityStore`](crate::config_authority::AuthorityStore) treats a
//! state file that fails to decode as fatal, because that file is a
//! subscriber credential registry: silently discarding it would silently
//! revoke every subscriber's access. This ring is a diagnostic and
//! rollback aid, not a security boundary, and every entry it names is
//! independently recoverable from `blobs/` (the content-addressed digest
//! is right there in the file name). So a malformed or truncated
//! `index.json` is *repaired* at [`RevisionStore::open`] rather than
//! refused: the index is reinitialized to an empty ring (a fresh
//! `lineage`, no entries, no `lkg`) and the repair is persisted before
//! `open` returns, so a second open is a no-op rather than a second
//! repair. Existing blobs on disk are untouched by this and simply
//! become unnamed until something appends over them again.
//!
//! The one shape of corruption this module still refuses outright is an
//! index that parses cleanly but names a digest with no blob on disk, or
//! an `lkg` pointer naming a digest no live entry carries. Both are
//! stronger signals than a truncated file: something deleted data this
//! store was told still existed, and guessing at a repair would hide
//! that rather than surface it.
//!
//! # Lineage
//!
//! `lineage` is a UUID minted the first time a ring is created. It
//! stays stable across every later [`RevisionStore::open`], including
//! across a `source:` repoint (a repoint changes where documents come
//! from, tracked per entry as [`BaseOrigin`], not what installation this
//! ring belongs to). It is re-minted whenever the caller-supplied
//! [`ClusterRestartFingerprint`] changes, because that fingerprint names
//! the process-owned identity (cluster id, node id, roles, ports, ...)
//! that makes one installation's history meaningless to another's: a
//! ring recorded under one node identity is not a rollback candidate for
//! a different one wearing the same directory path. The store never
//! computes this fingerprint; it only compares what the caller hands it
//! against what the caller handed it last time.
//!
//! # Eviction never drops the last known good entry
//!
//! [`RevisionStore::append`] evicts the oldest entries once the ring
//! holds more than `keep`, but an entry named by the `lkg` pointer is
//! never evicted, however far behind it has fallen. A rollback target
//! that eviction quietly deleted would be worse than no bound at all.
//!
//! # The lkg pointer is written, never auto-advanced, here
//!
//! [`RevisionStore::mark_good`] is the only thing that moves the `lkg`
//! pointer, and nothing in this crate calls it outside a test. Promoting
//! a revision to last-known-good is a soak-window decision (a later
//! change), not something appending a revision does on its own.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cluster::ClusterRestartFingerprint;
use crate::config_bundle::MAX_CONFIG_YAML_BYTES;
use crate::config_merge::BaseOrigin;
use crate::plan::BlastRadius;

/// Current on-disk schema version for `index.json`.
const REVISION_INDEX_SCHEMA_VERSION: u32 = 1;

/// Index file name inside the store directory.
const INDEX_FILE: &str = "index.json";

/// Subdirectory holding content-addressed document blobs.
const BLOBS_DIR: &str = "blobs";

/// Subdirectory holding refused candidates. Created here; populated by a
/// later change.
const REJECTED_DIR: &str = "rejected";

/// Suffix appended to a digest to name its blob file.
const BLOB_SUFFIX: &str = ".yaml.zst";

/// zstd compression level for stored blobs. The default level: these are
/// short-lived config documents measured in kilobytes, not a bulk data
/// path where a higher level's extra ratio would be worth its extra CPU.
const BLOB_ZSTD_LEVEL: i32 = 3;

/// Largest accepted `index.json`, in bytes. Ten mebibytes comfortably
/// covers a large ring's worth of entries while still being small enough
/// that a corrupt or hostile file cannot exhaust memory at boot.
const MAX_INDEX_BYTES: u64 = 10 * 1024 * 1024;

/// Largest accepted stored blob file, in bytes. Compression should
/// shrink, not grow, but the bound is sized against the uncompressed
/// document limit plus headroom rather than assumed to always shrink.
const MAX_BLOB_FILE_BYTES: u64 = MAX_CONFIG_YAML_BYTES as u64 + 65_536;

/// Lifecycle state of one ring entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionState {
    /// Applied to the running process. The default state for every
    /// freshly appended entry.
    Applied,
    /// Soaked successfully and eligible as a rollback target. Set only
    /// by [`RevisionStore::mark_good`].
    Good,
    /// Soak determined this revision should not be trusted.
    Failed,
    /// Rolled back away from.
    Reverted,
}

/// Outcome of a soak window for one revision.
///
/// Three-way rather than pass/fail, matching Argo Rollouts' analysis
/// model: an inconclusive result (every signal abstained, for example on
/// a node with too little traffic to measure) is a distinct outcome from
/// a measured failure, and a caller that folded it into "failed" would
/// roll back a change nothing actually disproved.
///
/// Nothing in this crate sets this today; every entry [`RevisionStore::append`]
/// creates carries `soak_verdict: None`. A later change wires the soak
/// evaluator that fills it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoakVerdict {
    /// The soak window's signals passed.
    Successful,
    /// The soak window's signals failed.
    Failed,
    /// Every signal abstained; no verdict could be reached.
    Inconclusive,
}

/// Everything a caller supplies about one revision at append time.
///
/// `state`, `soak_verdict`, and `boot_attempts` are deliberately absent
/// here: every entry [`RevisionStore::append`] creates starts as
/// [`RevisionState::Applied`] with no soak verdict and zero boot
/// attempts. Only [`RevisionStore::mark_good`] moves an entry out of
/// `Applied`, and nothing in this crate sets a soak verdict or
/// increments boot attempts yet.
#[derive(Debug, Clone)]
pub struct AppendMetadata {
    /// Where the underlying document came from.
    pub provenance: BaseOrigin,
    /// Blast radius against the previous ring entry, when the caller has
    /// already computed one (typically via [`crate::plan::plan`]). `None`
    /// for the first entry in a ring, or when the caller has not computed
    /// one.
    pub blast_radius: Option<BlastRadius>,
    /// Fingerprint of the secrets material in force when this revision
    /// applied, when the caller has one.
    pub secrets_fingerprint: Option<String>,
    /// Who or what produced this revision: an operator id, `"boot"`, the
    /// config authority's identity, and so on, when known.
    pub actor: Option<String>,
    /// When this revision applied, in unix milliseconds.
    pub applied_at: u64,
}

/// One node-local, monotonic entry in the ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionEntry {
    /// Content-addressed digest (lowercase hex SHA-256) of the
    /// pre-resolution document bytes.
    pub digest: String,
    /// Node-local monotonic revision number. Durable across restart and
    /// never reused, even when the same content is applied again (see
    /// `digest` for that case).
    pub revision: u64,
    /// Where the underlying document came from.
    pub provenance: BaseOrigin,
    /// Lifecycle state.
    pub state: RevisionState,
    /// Blast radius against the previous ring entry, when known.
    #[serde(default)]
    pub blast_radius: Option<BlastRadius>,
    /// Fingerprint of the secrets material in force when this revision
    /// applied, when known.
    #[serde(default)]
    pub secrets_fingerprint: Option<String>,
    /// Who or what produced this revision, when known.
    #[serde(default)]
    pub actor: Option<String>,
    /// When this revision applied, in unix milliseconds.
    pub applied_at: u64,
    /// Soak verdict, once a soak window completes. Unset by every code
    /// path in this crate today.
    #[serde(default)]
    pub soak_verdict: Option<SoakVerdict>,
    /// How many boot attempts have been made against this specific
    /// revision. Zero until boot-fallback logic starts incrementing it.
    #[serde(default)]
    pub boot_attempts: u32,
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum RevisionStoreError {
    /// One bounded semantic rule failed.
    #[error("invalid config revision store operation: {0}")]
    Invalid(String),
    /// Durable state on disk failed validation and was not overwritten.
    #[error("config revision store state is corrupt: {0}")]
    Corrupt(String),
    /// Filesystem access failed.
    #[error("config revision store file access failed: {0}")]
    Io(#[from] std::io::Error),
    /// Strict JSON processing failed.
    #[error("config revision store JSON {operation} failed: {source}")]
    Json {
        /// Stable operation label.
        operation: &'static str,
        /// JSON parser or encoder failure.
        source: serde_json::Error,
    },
}

impl RevisionStoreError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    fn json(operation: &'static str, source: serde_json::Error) -> Self {
        Self::Json { operation, source }
    }
}

/// Durable ring index, as persisted to `index.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionIndex {
    /// On-disk schema version.
    schema_version: u32,
    /// Identity of this ring, stable across reopen and a `source:`
    /// repoint, re-minted when the cluster restart fingerprint changes.
    lineage: String,
    /// Highest revision ever assigned. Never decreases, so eviction
    /// removing old entries never lets a revision number be reissued.
    high_water_revision: u64,
    /// Digest of the entry currently pointed to as last known good, if
    /// any has been marked.
    #[serde(default)]
    lkg: Option<String>,
    /// Digest of the [`ClusterRestartFingerprint`] this ring was last
    /// opened with, used to detect a fingerprint change across restarts.
    /// `None` when the ring has never been opened with a fingerprint.
    #[serde(default)]
    fingerprint_digest: Option<String>,
    /// Ring entries, oldest first.
    #[serde(default)]
    entries: Vec<RevisionEntry>,
}

impl RevisionIndex {
    fn fresh(fingerprint_digest: Option<String>) -> Self {
        Self {
            schema_version: REVISION_INDEX_SCHEMA_VERSION,
            lineage: new_lineage(),
            high_water_revision: 0,
            lkg: None,
            fingerprint_digest,
            entries: Vec::new(),
        }
    }
}

/// A durable, node-local, content-addressed ring of applied config
/// revisions. See the module documentation for the on-disk layout and
/// the reasoning behind its repair, lineage, and eviction rules.
///
/// Not internally synchronized: one process owns one store directory.
#[derive(Debug)]
pub struct RevisionStore {
    directory: PathBuf,
    keep: usize,
    index: RevisionIndex,
}

impl RevisionStore {
    /// Open, or create, the ring directory at `directory`.
    ///
    /// Creates `blobs/` and `rejected/` when absent, so a first boot
    /// needs no provisioning step. `keep` bounds how many entries survive
    /// eviction after each append, except the entry the `lkg` pointer
    /// names, which is never evicted.
    ///
    /// `fingerprint` is compared against what the ring was last opened
    /// with (nothing here computes one): a first-ever open or a changed
    /// fingerprint mints a new `lineage`, and an unchanged one preserves
    /// it. See the module documentation for why.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Corrupt`] when the index names a
    /// digest with no blob on disk, or an `lkg` pointer naming a digest
    /// no live entry carries. Returns [`RevisionStoreError::Io`] when the
    /// directory cannot be created or read. A malformed or truncated
    /// `index.json` is repaired rather than treated as an error; see the
    /// module documentation.
    pub fn open(
        directory: impl AsRef<Path>,
        keep: usize,
        fingerprint: Option<&ClusterRestartFingerprint>,
    ) -> Result<Self, RevisionStoreError> {
        let directory = directory.as_ref().to_path_buf();
        create_private_dir_all(&directory)?;
        create_private_dir_all(&directory.join(BLOBS_DIR))?;
        create_private_dir_all(&directory.join(REJECTED_DIR))?;

        let fingerprint_digest = fingerprint.map(fingerprint_digest_of);
        let index_path = directory.join(INDEX_FILE);
        let mut changed = false;

        let mut index = match read_bounded(&index_path, MAX_INDEX_BYTES)? {
            Some(bytes) => match serde_json::from_slice::<RevisionIndex>(&bytes) {
                Ok(index) => index,
                Err(source) => {
                    tracing::warn!(
                        path = %index_path.display(),
                        error = %source,
                        "config revision index failed to parse; reinitializing an empty ring. \
                         existing content-addressed blobs are untouched and become adoptable by \
                         a future append",
                    );
                    changed = true;
                    RevisionIndex::fresh(fingerprint_digest.clone())
                }
            },
            None => {
                changed = true;
                RevisionIndex::fresh(fingerprint_digest.clone())
            }
        };

        if index.fingerprint_digest != fingerprint_digest {
            index.lineage = new_lineage();
            index.fingerprint_digest = fingerprint_digest;
            changed = true;
        }

        for entry in &index.entries {
            let blob = blob_path(&directory, &entry.digest);
            if !blob.is_file() {
                return Err(RevisionStoreError::Corrupt(format!(
                    "index names revision {} (digest {}) but {} is missing",
                    entry.revision,
                    entry.digest,
                    blob.display()
                )));
            }
        }
        if let Some(lkg) = &index.lkg {
            if !index.entries.iter().any(|entry| &entry.digest == lkg) {
                return Err(RevisionStoreError::Corrupt(format!(
                    "lkg pointer names digest {lkg:?}, which is not a live index entry"
                )));
            }
        }

        let store = Self {
            directory,
            keep,
            index,
        };
        if changed {
            let index = store.index.clone();
            store.save_index(&index)?;
        }
        Ok(store)
    }

    /// Append pre-resolution document bytes as a new revision.
    ///
    /// Content-addressed: identical bytes reuse the existing blob and
    /// only add a new index entry. The new entry always starts as
    /// [`RevisionState::Applied`] with no soak verdict and zero boot
    /// attempts. Evicts the oldest entries down to `keep` afterward,
    /// except the entry the `lkg` pointer names.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when `content` exceeds
    /// [`MAX_CONFIG_YAML_BYTES`] or the revision counter has overflowed,
    /// and [`RevisionStoreError::Io`] or [`RevisionStoreError::Json`]
    /// when the blob or index cannot be persisted. Nothing is recorded
    /// unless it was persisted first.
    pub fn append(
        &mut self,
        content: &[u8],
        metadata: AppendMetadata,
    ) -> Result<RevisionEntry, RevisionStoreError> {
        if content.len() > MAX_CONFIG_YAML_BYTES {
            return Err(RevisionStoreError::invalid(format!(
                "revision content is {} bytes, over the {MAX_CONFIG_YAML_BYTES} byte limit",
                content.len()
            )));
        }
        let digest = sha256_hex(content);
        self.write_blob_if_absent(&digest, content)?;

        let revision = self
            .index
            .high_water_revision
            .checked_add(1)
            .ok_or_else(|| RevisionStoreError::invalid("revision counter overflowed"))?;
        let entry = RevisionEntry {
            digest,
            revision,
            provenance: metadata.provenance,
            state: RevisionState::Applied,
            blast_radius: metadata.blast_radius,
            secrets_fingerprint: metadata.secrets_fingerprint,
            actor: metadata.actor,
            applied_at: metadata.applied_at,
            soak_verdict: None,
            boot_attempts: 0,
        };

        let mut next = self.index.clone();
        next.high_water_revision = revision;
        next.entries.push(entry.clone());
        self.evict(&mut next);
        self.save_index(&next)?;
        self.index = next;
        Ok(entry)
    }

    /// Mark the entry holding `revision` as [`RevisionState::Good`] and
    /// move the `lkg` pointer to it.
    ///
    /// The only way the `lkg` pointer moves in this crate: nothing here
    /// calls this on its own. See the module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when no entry holds
    /// `revision`, and [`RevisionStoreError::Io`] or
    /// [`RevisionStoreError::Json`] when the index cannot be persisted.
    pub fn mark_good(&mut self, revision: u64) -> Result<(), RevisionStoreError> {
        let mut next = self.index.clone();
        let Some(entry) = next
            .entries
            .iter_mut()
            .find(|entry| entry.revision == revision)
        else {
            return Err(RevisionStoreError::invalid(format!(
                "no ring entry holds revision {revision}"
            )));
        };
        entry.state = RevisionState::Good;
        let digest = entry.digest.clone();
        next.lkg = Some(digest);
        self.save_index(&next)?;
        self.index = next;
        Ok(())
    }

    /// Every ring entry, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[RevisionEntry] {
        &self.index.entries
    }

    /// The entry the `lkg` pointer names, if any has been marked good.
    #[must_use]
    pub fn lkg(&self) -> Option<&RevisionEntry> {
        let digest = self.index.lkg.as_deref()?;
        self.index
            .entries
            .iter()
            .find(|entry| entry.digest == digest)
    }

    /// This ring's lineage identity: a UUID stable across reopen and a
    /// `source:` repoint, re-minted when the cluster restart fingerprint
    /// changes.
    #[must_use]
    pub fn lineage(&self) -> &str {
        &self.index.lineage
    }

    /// Read back and decompress the pre-resolution bytes for `digest`.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Corrupt`] when no blob exists for
    /// `digest`, and [`RevisionStoreError::Io`] when it cannot be read or
    /// fails to decompress.
    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>, RevisionStoreError> {
        let path = blob_path(&self.directory, digest);
        let compressed = read_bounded(&path, MAX_BLOB_FILE_BYTES)?
            .ok_or_else(|| RevisionStoreError::Corrupt(format!("{} is missing", path.display())))?;
        let content = zstd::decode_all(&compressed[..])?;
        Ok(content)
    }

    /// Evict the oldest non-`lkg` entries in `next` until at most
    /// `self.keep` of those remain. The entry `next.lkg` names is not
    /// part of that budget: it survives as an addition to it, however far
    /// behind it has fallen, so `keep` bounds how much *browsable* history
    /// is retained without ever costing the ring its rollback target.
    /// Removes the blob for an evicted digest only when no remaining
    /// entry still references it, which is what keeps an A-to-B-to-A
    /// flap's shared blob alive.
    fn evict(&self, next: &mut RevisionIndex) {
        let lkg = next.lkg.clone();
        let is_lkg = |entry: &RevisionEntry| Some(entry.digest.as_str()) == lkg.as_deref();
        loop {
            let non_lkg_count = next.entries.iter().filter(|entry| !is_lkg(entry)).count();
            if non_lkg_count <= self.keep {
                break;
            }
            let Some(victim) = next.entries.iter().position(|entry| !is_lkg(entry)) else {
                // Every remaining entry is the lkg entry; nothing more can
                // be evicted without dropping the rollback target.
                break;
            };
            let removed = next.entries.remove(victim);
            let still_referenced = next
                .entries
                .iter()
                .any(|entry| entry.digest == removed.digest);
            if !still_referenced {
                let _ = std::fs::remove_file(blob_path(&self.directory, &removed.digest));
            }
        }
    }

    fn write_blob_if_absent(&self, digest: &str, content: &[u8]) -> Result<(), RevisionStoreError> {
        let path = blob_path(&self.directory, digest);
        if path.is_file() {
            return Ok(());
        }
        let compressed = zstd::encode_all(content, BLOB_ZSTD_LEVEL)?;
        write_atomically(&path, &compressed)
    }

    fn save_index(&self, index: &RevisionIndex) -> Result<(), RevisionStoreError> {
        let mut body = serde_json::to_vec_pretty(index)
            .map_err(|source| RevisionStoreError::json("encode revision index", source))?;
        body.push(b'\n');
        write_atomically(&self.directory.join(INDEX_FILE), &body)
    }
}

/// Path of one blob file for `digest`.
fn blob_path(directory: &Path, digest: &str) -> PathBuf {
    directory
        .join(BLOBS_DIR)
        .join(format!("{digest}{BLOB_SUFFIX}"))
}

/// A fresh, randomly minted lineage identity.
fn new_lineage() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A stable digest of a [`ClusterRestartFingerprint`], used to detect a
/// change across restarts without this crate needing the type to
/// implement `Serialize`. The type's `Debug` output is deterministic
/// (its collections are all ordered), so this is stable for as long as
/// the type's field set and `Debug` derive do not change; a false-positive
/// lineage remint on an unrelated internal change is an acceptable cost
/// for not needing a hand-maintained canonical encoding here.
fn fingerprint_digest_of(fingerprint: &ClusterRestartFingerprint) -> String {
    sha256_hex(format!("{fingerprint:?}").as_bytes())
}

/// Read a bounded file. `Ok(None)` means it does not exist yet.
fn read_bounded(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>, RevisionStoreError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(RevisionStoreError::Corrupt(format!(
            "{} is empty, not a regular file, or larger than {maximum} bytes",
            path.display()
        )));
    }
    Ok(Some(std::fs::read(path)?))
}

/// Write `body` to `path` through a temporary file and a rename, so a
/// crash mid-write leaves the old file or the new one, never a truncated
/// one. The temporary file is created with owner-only permissions
/// directly, rather than created then chmodded, so there is no window
/// where it is readable beyond the owner.
fn write_atomically(path: &Path, body: &[u8]) -> Result<(), RevisionStoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(INDEX_FILE);
    // Pid plus nanoseconds keeps two writers in one directory from
    // colliding. The rename is the atomic step, not the create.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let temporary = parent.join(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));
    let result = (|| {
        let mut file = create_private_file(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(RevisionStoreError::from)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(unix)]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::EffectiveClusterSecurity;
    use crate::types::MeshKeyDerivation;
    use std::collections::{BTreeMap, BTreeSet};

    fn metadata(applied_at: u64) -> AppendMetadata {
        AppendMetadata {
            provenance: BaseOrigin::Local,
            blast_radius: Some(BlastRadius::Reload),
            secrets_fingerprint: Some("sha256:deadbeef".to_string()),
            actor: Some("test-operator".to_string()),
            applied_at,
        }
    }

    fn fingerprint(cluster_id: &str) -> ClusterRestartFingerprint {
        ClusterRestartFingerprint {
            cluster_id: cluster_id.to_string(),
            node_id: None,
            roles: BTreeSet::new(),
            labels: BTreeMap::new(),
            seeds: Vec::new(),
            gossip_port: 0,
            transport_port: 0,
            advertise_addr: None,
            transport_advertise_addr: None,
            model_bind: None,
            model_endpoint: None,
            state_dir: None,
            dead_peer_gc_secs: 0,
            security: EffectiveClusterSecurity::LegacyPlaintext,
            key_derivation: MeshKeyDerivation::Sha256,
            enrollment: None,
            deployment_authority: None,
            replication: None,
        }
    }

    fn store(dir: &Path, keep: usize) -> RevisionStore {
        RevisionStore::open(dir, keep, None).expect("open store")
    }

    #[test]
    fn open_append_and_read_round_trip_against_a_temp_dir() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path(), 10);
        assert!(store.entries().is_empty());

        let first = store
            .append(b"origins: {}\n# one\n", metadata(1_000))
            .expect("append");
        assert_eq!(first.revision, 1);
        assert_eq!(first.state, RevisionState::Applied);
        assert_eq!(first.soak_verdict, None);
        assert_eq!(first.boot_attempts, 0);

        let second = store
            .append(b"origins: {}\n# two\n", metadata(2_000))
            .expect("append");
        assert_eq!(second.revision, 2);
        assert_ne!(second.digest, first.digest);

        assert_eq!(store.entries().len(), 2);
        assert_eq!(
            store.read_blob(&first.digest).expect("read blob"),
            b"origins: {}\n# one\n"
        );
        assert_eq!(
            store.read_blob(&second.digest).expect("read blob"),
            b"origins: {}\n# two\n"
        );
    }

    #[test]
    fn a_truncated_index_is_repaired_on_the_first_open() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path(), 10);
            store
                .append(b"origins: {}\n", metadata(1_000))
                .expect("append");
        }
        let index_path = temp.path().join(INDEX_FILE);
        let original = std::fs::read(&index_path).expect("read index");
        // Simulate a truncated write: keep only the first half of the
        // bytes, which is not valid JSON.
        std::fs::write(&index_path, &original[..original.len() / 2]).expect("truncate index");

        // The repair must be the effect of `open` itself: no other store
        // call happens before this assertion.
        let reopened = RevisionStore::open(temp.path(), 10, None).expect("open repairs");
        assert!(
            reopened.entries().is_empty(),
            "a truncated index is reinitialized to an empty ring rather than refused",
        );

        // And the repair was persisted immediately, so a second open finds
        // valid JSON rather than repairing again.
        let on_disk = std::fs::read(&index_path).expect("read repaired index");
        serde_json::from_slice::<serde_json::Value>(&on_disk)
            .expect("repaired index is valid json");
    }

    #[test]
    fn an_orphan_blob_not_named_by_the_index_is_adopted_at_open() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(store(temp.path(), 10));
        let blobs_dir = temp.path().join(BLOBS_DIR);
        std::fs::write(blobs_dir.join("deadbeef.yaml.zst"), b"not indexed")
            .expect("write orphan blob");

        let reopened = RevisionStore::open(temp.path(), 10, None)
            .expect("an unnamed blob is adopted, not refused");
        assert!(reopened.entries().is_empty());
        assert!(
            blobs_dir.join("deadbeef.yaml.zst").is_file(),
            "the orphan blob is left in place",
        );
    }

    #[test]
    fn eviction_is_oldest_first_and_never_evicts_the_lkg_entry() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let keep = 3usize;
        let mut store = store(temp.path(), keep);

        let good = store
            .append(b"origins: {}\n# good\n", metadata(1))
            .expect("append");
        store.mark_good(good.revision).expect("mark good");

        for revision in 0..(keep + 5) {
            let content = format!("origins: {{}}\n# after-{revision}\n");
            store
                .append(content.as_bytes(), metadata(2 + revision as u64))
                .expect("append");
        }

        let entries = store.entries();
        assert!(
            entries.iter().any(|entry| entry.digest == good.digest),
            "the lkg entry must survive eviction however far behind it has fallen",
        );
        assert_eq!(
            entries.len(),
            keep + 1,
            "keep newest entries plus the protected lkg entry",
        );
        let revisions: Vec<u64> = entries.iter().map(|entry| entry.revision).collect();
        let mut sorted = revisions.clone();
        sorted.sort_unstable();
        assert_eq!(revisions, sorted, "entries stay oldest-first");
        assert_eq!(
            store.lkg().expect("lkg").digest,
            good.digest,
            "the lkg pointer itself is untouched by eviction",
        );
    }

    #[test]
    fn identical_content_stored_twice_across_an_a_b_a_flap_produces_one_blob() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path(), 10);

        let a1 = store.append(b"content-a\n", metadata(1)).expect("append a");
        let b = store.append(b"content-b\n", metadata(2)).expect("append b");
        let a2 = store
            .append(b"content-a\n", metadata(3))
            .expect("append a again");

        assert_eq!(a1.digest, a2.digest, "identical content shares a digest");
        assert_ne!(a1.digest, b.digest);
        assert_eq!(
            vec![a1.revision, b.revision, a2.revision],
            vec![1, 2, 3],
            "each append still mints its own monotonic revision",
        );
        assert_eq!(
            store.entries().len(),
            3,
            "two entries name the shared digest"
        );

        let blob_count = std::fs::read_dir(temp.path().join(BLOBS_DIR))
            .expect("read blobs dir")
            .count();
        assert_eq!(blob_count, 2, "the flap back to A writes no second blob");
    }

    #[cfg(unix)]
    #[test]
    fn directory_and_file_modes_are_owner_only_on_a_created_store() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path(), 10);
        let entry = store.append(b"origins: {}\n", metadata(1)).expect("append");

        let mode_of =
            |path: &Path| std::fs::metadata(path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode_of(temp.path()), 0o700, "store root");
        assert_eq!(mode_of(&temp.path().join(BLOBS_DIR)), 0o700, "blobs dir");
        assert_eq!(
            mode_of(&temp.path().join(REJECTED_DIR)),
            0o700,
            "rejected dir"
        );
        assert_eq!(mode_of(&temp.path().join(INDEX_FILE)), 0o600, "index.json");
        assert_eq!(
            mode_of(&blob_path(temp.path(), &entry.digest)),
            0o600,
            "blob file",
        );
    }

    #[test]
    fn lineage_is_stable_across_reopen_and_a_source_repoint_but_reminted_on_a_fingerprint_change() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let fp = fingerprint("cluster-a");

        let lineage_at_creation = {
            let mut opened = RevisionStore::open(temp.path(), 10, Some(&fp)).expect("open");
            opened
                .append(b"origins: {}\n# local\n", metadata(1))
                .expect("append local");
            opened.lineage().to_string()
        };

        // Reopening with an equal (but distinct) fingerprint value keeps
        // the lineage stable.
        let same_fp = fingerprint("cluster-a");
        let mut reopened =
            RevisionStore::open(temp.path(), 10, Some(&same_fp)).expect("reopen same fingerprint");
        assert_eq!(reopened.lineage(), lineage_at_creation);

        // A `source:` repoint changes provenance on a newly appended
        // entry, not the ring's identity.
        reopened
            .append(
                b"origins: {}\n# from-git\n",
                AppendMetadata {
                    provenance: BaseOrigin::Git {
                        repo: "git@example.com:org/repo.git".to_string(),
                        reference: "main".to_string(),
                        commit: "abc123".to_string(),
                    },
                    ..metadata(2)
                },
            )
            .expect("append from git source");
        assert_eq!(reopened.lineage(), lineage_at_creation);
        assert_eq!(reopened.entries().len(), 2);
        drop(reopened);

        // A changed cluster restart fingerprint mints a new lineage, but
        // leaves the existing entries in place and readable.
        let different_fp = fingerprint("cluster-b");
        let remented = RevisionStore::open(temp.path(), 10, Some(&different_fp))
            .expect("reopen new fingerprint");
        assert_ne!(remented.lineage(), lineage_at_creation);
        assert_eq!(
            remented.entries().len(),
            2,
            "prior entries stay readable across a lineage remint",
        );
    }
}
