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
//!   index.json.bak           backup of the index, written before the primary
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
//! refused. Repair rebuilds from the backup copy every index save
//! maintains (`index.json.bak`, written before the primary): the
//! entries whose blob files survive are kept, together with the
//! recorded `high_water_revision`, `lkg` pointer, and `lineage`, so
//! history, the rollback target, and the never-reuse-a-revision
//! invariant all outlive the truncation. Only when the backup is
//! unreadable too does repair fall back to reinitializing an empty
//! ring (a fresh `lineage`, no entries, no `lkg`, revision numbering
//! restarted), and the warning says so plainly. Either way the repair
//! is persisted before `open` returns, so a second open is a no-op
//! rather than a second repair, and existing blobs on disk are
//! untouched by it.
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
//! Eviction persists the shrunk index before it unlinks any blob. Doing
//! it the other way round would reopen the same crash window this
//! module's repair story exists to close: a blob deleted first, then a
//! crash before the index that stopped naming it is durable, leaves
//! `index.json` naming a digest with no file, which `open` refuses as
//! corrupt. Persisting first means the only possible crash-window
//! residue is an index that no longer names an entry plus a blob
//! nothing names, an ordinary orphan `open` already tolerates.
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

/// Backup index file name inside the store directory. [`RevisionStore`]
/// writes it before the primary on every index save, so an `index.json`
/// lost to external truncation is recoverable with its
/// `high_water_revision`, `lkg` pointer, and `lineage` intact.
const INDEX_BACKUP_FILE: &str = "index.json.bak";

/// Subdirectory holding content-addressed document blobs.
const BLOBS_DIR: &str = "blobs";

/// Subdirectory holding refused candidates. Created here; populated by a
/// later change.
const REJECTED_DIR: &str = "rejected";

/// Suffix appended to a digest to name its blob file.
const BLOB_SUFFIX: &str = ".yaml.zst";

/// How many refused candidates `rejected/` retains when a caller never
/// calls [`RevisionStore::with_keep_rejected`]. Matches
/// `proxy.config_history.keep_rejected`'s own default, so a store opened
/// without the builder behaves like one opened with the shipped config.
pub const DEFAULT_KEEP_REJECTED: usize = 10;

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
    /// Subsystems that did not apply cleanly, when this revision came up
    /// degraded. Empty for a fully applied revision. A degraded revision
    /// is still recorded as [`RevisionState::Applied`]: the pipeline did
    /// publish, so the entry belongs in the ring the same as a clean
    /// apply, and this field is what tells the two apart on inspection.
    pub degraded: Vec<String>,
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
    /// `digest` for that case). One repair exception exists: when both
    /// `index.json` and its backup are lost or corrupted, `open`
    /// reinitializes the ring and numbering restarts at 1.
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
    /// Subsystems that did not apply cleanly when this revision applied.
    /// Empty for a fully applied revision. See
    /// [`AppendMetadata::degraded`] for why this does not become a
    /// distinct [`RevisionState`].
    #[serde(default)]
    pub degraded: Vec<String>,
    /// Whether a boot fallback has given up on this entry.
    ///
    /// Set by [`RevisionStore::retire_unbootable`] once `boot_attempts`
    /// reaches the configured ceiling, and never cleared. Distinct from
    /// [`RevisionState::Failed`], which is a soak verdict about how the
    /// revision behaved under traffic: an entry can soak perfectly and
    /// still fail to construct months later, after an upgrade tightened
    /// validation, and an operator reading the two together needs to see
    /// which of the two happened.
    #[serde(default)]
    pub boot_retired: bool,
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
    /// How many refused candidates `rejected/` retains. Set through
    /// [`RevisionStore::with_keep_rejected`]; see that method for why it
    /// is a builder rather than an `open` parameter.
    keep_rejected: usize,
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
                    changed = true;
                    recover_index(
                        &directory,
                        &index_path,
                        Some(&source),
                        fingerprint_digest.clone(),
                    )
                }
            },
            None => {
                changed = true;
                recover_index(&directory, &index_path, None, fingerprint_digest.clone())
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
            keep_rejected: DEFAULT_KEEP_REJECTED,
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
            degraded: metadata.degraded,
            boot_retired: false,
        };

        let mut next = self.index.clone();
        next.high_water_revision = revision;
        next.entries.push(entry.clone());
        let orphaned = evict_entries(self.keep, &mut next);
        // The index that stops naming `orphaned`'s digests must be durable
        // before those blobs are unlinked: unlinking first would leave a
        // crash window where `index.json` (still the old, pre-persist
        // version on disk) names a digest whose blob is already gone, and
        // this store's own `open` would then refuse a directory its own
        // eviction damaged. Persisting first means the only crash-window
        // residue possible is an index that no longer names an entry plus
        // a blob nothing names, which `open` already tolerates as an
        // ordinary orphan.
        self.save_index(&next)?;
        self.index = next;
        self.remove_orphaned_blobs(&orphaned);
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

    /// Unlink blob files for digests no live entry references any more.
    ///
    /// Call only after the index that stopped naming `digests` has been
    /// durably persisted (see the ordering note in [`Self::append`]).
    /// Best-effort: a failed unlink here just leaves an ordinary orphan
    /// blob behind, which [`Self::open`] already tolerates.
    fn remove_orphaned_blobs(&self, digests: &[String]) {
        for digest in digests {
            let _ = std::fs::remove_file(blob_path(&self.directory, digest));
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
        // Backup first, primary second. A crash between the two leaves
        // the primary one save behind the backup, never ahead of it, so
        // an index later recovered from the backup carries an equal or
        // higher `high_water_revision` - the direction that preserves
        // the never-reuse-a-revision invariant.
        write_atomically(&self.directory.join(INDEX_BACKUP_FILE), &body)?;
        write_atomically(&self.directory.join(INDEX_FILE), &body)
    }
}

/// Path of one blob file for `digest`.
fn blob_path(directory: &Path, digest: &str) -> PathBuf {
    directory
        .join(BLOBS_DIR)
        .join(format!("{digest}{BLOB_SUFFIX}"))
}

/// Evict the oldest non-`lkg` entries in `next` until at most `keep` of
/// those remain, and return the digests no surviving entry references any
/// more. Touches only `next`, never the filesystem: the caller unlinks
/// the returned digests' blobs itself, and only after `next` is durable
/// (see the ordering note in [`RevisionStore::append`]).
///
/// The entry `next.lkg` names is not part of the `keep` budget: it
/// survives as an addition to it, however far behind it has fallen, so
/// `keep` bounds how much *browsable* history is retained without ever
/// costing the ring its rollback target. A digest is reported orphaned
/// only when no remaining entry still references it, which is what keeps
/// an A-to-B-to-A flap's shared blob alive.
fn evict_entries(keep: usize, next: &mut RevisionIndex) -> Vec<String> {
    let lkg = next.lkg.clone();
    let is_lkg = |entry: &RevisionEntry| Some(entry.digest.as_str()) == lkg.as_deref();
    let mut orphaned = Vec::new();
    loop {
        let non_lkg_count = next.entries.iter().filter(|entry| !is_lkg(entry)).count();
        if non_lkg_count <= keep {
            break;
        }
        let Some(victim) = next.entries.iter().position(|entry| !is_lkg(entry)) else {
            // Every remaining entry is the lkg entry; nothing more can be
            // evicted without dropping the rollback target.
            break;
        };
        let removed = next.entries.remove(victim);
        let still_referenced = next
            .entries
            .iter()
            .any(|entry| entry.digest == removed.digest);
        if !still_referenced {
            orphaned.push(removed.digest);
        }
    }
    orphaned
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
/// implement `Serialize`. Hashes
/// [`ClusterRestartFingerprint::stable_lineage_key`] rather than the
/// type's `Debug` output: `Debug` follows declaration order, so a
/// routine field reorder in that actively developed struct would
/// silently remint every node's lineage on upgrade, and
/// `stable_lineage_key`'s exhaustive destructure exists specifically to
/// close that gap.
fn fingerprint_digest_of(fingerprint: &ClusterRestartFingerprint) -> String {
    sha256_hex(fingerprint.stable_lineage_key().as_bytes())
}

/// Rebuild the ring index after the primary `index.json` was missing or
/// failed to parse. Prefers the backup copy [`RevisionStore`] maintains
/// on every save: entries whose blob files survive are kept, with the
/// recorded `high_water_revision`, `lkg` pointer, and `lineage`;
/// entries whose blobs are gone are dropped, and an `lkg` pointer left
/// naming no surviving entry is cleared so `open`'s consistency checks
/// hold. When no readable backup exists either, falls back to a fresh
/// empty ring, which restarts revision numbering and loses the
/// last-known-good pointer - the warning says so.
fn recover_index(
    directory: &Path,
    index_path: &Path,
    parse_error: Option<&serde_json::Error>,
    fingerprint_digest: Option<String>,
) -> RevisionIndex {
    let backup_path = directory.join(INDEX_BACKUP_FILE);
    let backup = match read_bounded(&backup_path, MAX_INDEX_BYTES) {
        Ok(Some(bytes)) => serde_json::from_slice::<RevisionIndex>(&bytes).ok(),
        _ => None,
    };
    if let Some(mut recovered) = backup {
        let named = recovered.entries.len();
        recovered
            .entries
            .retain(|entry| blob_path(directory, &entry.digest).is_file());
        if let Some(lkg) = &recovered.lkg {
            if !recovered.entries.iter().any(|entry| &entry.digest == lkg) {
                recovered.lkg = None;
            }
        }
        tracing::warn!(
            path = %index_path.display(),
            backup = %backup_path.display(),
            error = parse_error.map(tracing::field::display),
            recovered_entries = recovered.entries.len(),
            dropped_entries = named - recovered.entries.len(),
            lkg_recovered = recovered.lkg.is_some(),
            "config revision index was missing or failed to parse; rebuilt it from the backup \
             copy, keeping the entries whose blob files survive and the recorded \
             high_water_revision, so revision numbers are not reused",
        );
        return recovered;
    }
    if parse_error.is_some() || backup_path.exists() {
        tracing::warn!(
            path = %index_path.display(),
            error = parse_error.map(tracing::field::display),
            "config revision index was missing or failed to parse and no readable backup \
             exists; reinitializing an empty ring. revision numbering restarts at 1 and any \
             last-known-good pointer is lost. existing content-addressed blobs are untouched \
             and become adoptable by a future append",
        );
    }
    RevisionIndex::fresh(fingerprint_digest)
}

/// Read a bounded file. `Ok(None)` means it does not exist yet.
///
/// An existing file that is zero-length is read as `Ok(Some(vec![]))`
/// rather than refused outright as [`RevisionStoreError::Corrupt`]:
/// `index.json` can reach zero bytes through paths outside
/// [`write_atomically`]'s own crash guarantees - external truncation by
/// a backup or sync tool, filesystem repair after power loss, an
/// operator's stray shell redirection - and that is a truncation like
/// any other, not a distinct failure mode. Feeding empty bytes to
/// [`RevisionStore::open`]'s existing `serde_json::from_slice` call
/// fails to parse exactly the way a half-written file does, so it
/// takes the same repair-and-reinitialize path already documented
/// there, rather than bricking the ring (`open` returning `Err` here is
/// what moves `sbproxy-core`'s process-wide config-history slot to its
/// `Failed` state, which 503s every history route until someone
/// deletes the file by hand). A zero-length *blob* still fails
/// downstream, in [`RevisionStore::read_blob`]'s `zstd::decode_all`
/// call: there is no valid zstd frame in zero bytes, so that path
/// errors too, just with a less specific message than this function
/// used to give it directly.
fn read_bounded(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>, RevisionStoreError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(RevisionStoreError::Corrupt(format!(
            "{} is not a regular file, or is larger than {maximum} bytes",
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
    let result: std::io::Result<()> = (|| {
        let mut file = create_private_file(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        // The rename is atomic but not durable until the parent
        // directory's entry is flushed; without this, a crash right
        // after the rename can forget it and resurface the old file.
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
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

/// Current on-disk schema version for one `rejected/<digest>.json`.
const REJECTED_SCHEMA_VERSION: u32 = 1;

/// Suffix appended to a digest to name one rejected-candidate file.
const REJECTED_SUFFIX: &str = ".json";

/// Largest accepted `rejected/<digest>.json`, in bytes. The document it
/// carries is bounded by [`MAX_CONFIG_YAML_BYTES`] before it is written;
/// the headroom covers JSON escaping of that text plus the metadata
/// around it.
const MAX_REJECTED_FILE_BYTES: u64 = (MAX_CONFIG_YAML_BYTES as u64) * 2 + 65_536;

/// Why a candidate document was refused before it could apply.
///
/// One variant per refusal in the config subscriber's failure table
/// (`sbproxy_core::config_subscriber`'s module documentation), with one
/// deliberate absence: a `reload_busy` cycle has no variant here and
/// cannot be constructed. A busy cycle is a deferral, not a refusal, and
/// nothing was even examined; recording it as a rejection would bury the
/// real ones under a row that repeats every poll interval on a healthy
/// node. Leaving it unrepresentable is stronger than a `continue` in the
/// caller, because a caller cannot record one by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Signature, schema, digest, expiry, declared-mode, or replay
    /// refusal.
    VerifyFailed,
    /// The document did not compile, could not be merged, or carried an
    /// unresolved `${VAR}` reference.
    CompileFailed,
    /// The candidate named a config path this node owns outright.
    DeniedPath,
    /// The candidate reached for a host resource this node owns: an
    /// environment variable, a secret, or a file path.
    ConfinementRefused,
}

impl RejectionReason {
    /// Stable wire and metric label. Never changes for a given variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyFailed => "verify_failed",
            Self::CompileFailed => "compile_failed",
            Self::DeniedPath => "denied_path",
            Self::ConfinementRefused => "confinement_refused",
        }
    }
}

/// Everything a caller supplies about one refusal.
#[derive(Debug, Clone)]
pub struct RejectionMetadata {
    /// Which refusal in the failure table this was.
    pub reason: RejectionReason,
    /// Which stage refused it. Three values are written today:
    ///
    /// * `"config_authority"`, for a bundle the subscriber refused;
    /// * `"file_watcher"`, for a local document that did not apply. The
    ///   SIGHUP path shares this label because both triggers converge on
    ///   one reload function and one audit label, which WOR-2486 already
    ///   settled.
    /// * `"rollback"`, for a stored revision this node tried to restore
    ///   and could not: a document that published cleanly months ago and
    ///   no longer constructs on this binary. Both rollback triggers
    ///   share it, the admin route and the soak's auto-revert, because
    ///   both converge on one reload function; the `actor` on the ring
    ///   entry a *successful* rollback appends is what tells them apart
    ///   (WOR-2460, WOR-2461).
    ///
    /// Two refusal paths are **not** covered yet and so never appear
    /// here: the `source:` refresh poller's own `CompileFailed` branch,
    /// and `POST /admin/reload`, which keeps its own audit entry with an
    /// actor this ring does not carry.
    pub stage: String,
    /// Human-readable detail, as the refusing stage logged it. Bounded
    /// by [`RevisionStore::record_rejection`] before it is stored.
    pub detail: String,
    /// Where the refused document came from.
    pub provenance: BaseOrigin,
    /// When the refusal happened, in unix milliseconds.
    pub rejected_at: u64,
}

/// One refused candidate, as persisted to `rejected/<digest>.json`.
///
/// Content addressed by the same digest scheme the ring's blobs use, so
/// a candidate refused on every poll cycle is one file whose `count`
/// climbs rather than one file per cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedCandidate {
    /// On-disk schema version.
    pub schema_version: u32,
    /// Content-addressed digest (lowercase hex SHA-256) of the refused
    /// pre-resolution document bytes.
    pub digest: String,
    /// Which refusal this was.
    pub reason: RejectionReason,
    /// Which stage refused it, as of the most recent refusal.
    pub stage: String,
    /// Detail from the most recent refusal, bounded to
    /// [`MAX_REJECTION_DETAIL_CHARS`] characters.
    pub detail: String,
    /// Where the refused document came from.
    pub provenance: BaseOrigin,
    /// The refused document, exactly as it was read, with `${VAR}` /
    /// `vault://` / `secret://` references unresolved. The same
    /// pre-resolution discipline the ring's blobs keep, and for the same
    /// reason: a resolved snapshot would write live credentials into a
    /// file kept for as long as the refusal matters.
    pub document: String,
    /// Unix milliseconds of the first refusal of this content.
    pub first_seen_at: u64,
    /// Unix milliseconds of the most recent refusal of this content.
    pub last_seen_at: u64,
    /// How many times this exact content has been refused.
    pub count: u64,
}

/// Longest `detail` string one stored rejection keeps.
///
/// A refusal message is produced by a compiler or a verifier and can
/// carry an arbitrarily long span of the offending document; bounding it
/// keeps one pathological candidate from filling the directory the
/// `keep_rejected` bound is supposed to hold.
pub const MAX_REJECTION_DETAIL_CHARS: usize = 512;

impl RevisionStore {
    /// Set how many refused candidates `rejected/` retains.
    ///
    /// A builder rather than a fourth [`Self::open`] parameter: the
    /// rejected directory is bounded independently of the applied ring
    /// (`proxy.config_history.keep_rejected` against
    /// `proxy.config_history.keep`), and a caller that never records a
    /// rejection should not have to name a bound for one. Defaults to
    /// [`DEFAULT_KEEP_REJECTED`].
    #[must_use]
    pub fn with_keep_rejected(mut self, keep_rejected: usize) -> Self {
        self.keep_rejected = keep_rejected;
        self
    }

    /// Record one soak verdict against `revision`, and move the `lkg`
    /// pointer if, and only if, the verdict is
    /// [`SoakVerdict::Successful`].
    ///
    /// This is where the epic's root defect is fixed, so the rule lives
    /// here rather than in a caller that could get it wrong:
    ///
    /// | Verdict | Entry state | `lkg` pointer |
    /// | -- | -- | -- |
    /// | [`SoakVerdict::Successful`] | [`RevisionState::Good`] | Advances to this entry |
    /// | [`SoakVerdict::Failed`] | [`RevisionState::Failed`] | Unchanged |
    /// | [`SoakVerdict::Inconclusive`] | Unchanged (stays [`RevisionState::Applied`]) | Unchanged |
    ///
    /// Inconclusive deliberately does not mark the entry failed. Every
    /// signal abstaining means the soak measured nothing, which is a
    /// configuration problem worth surfacing, not evidence against the
    /// revision. It also deliberately does not promote: promoting on a
    /// soak that measured nothing is promote-on-apply wearing a timer.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when no live entry holds
    /// `revision` (it was evicted, or the caller has the wrong number),
    /// and [`RevisionStoreError::Io`] or [`RevisionStoreError::Json`]
    /// when the index cannot be persisted.
    pub fn record_soak_verdict(
        &mut self,
        revision: u64,
        verdict: SoakVerdict,
    ) -> Result<(), RevisionStoreError> {
        let mut next = self.index.clone();
        let entry = find_entry_mut(&mut next, revision)?;
        entry.soak_verdict = Some(verdict);
        match verdict {
            SoakVerdict::Successful => {
                entry.state = RevisionState::Good;
                let digest = entry.digest.clone();
                next.lkg = Some(digest);
            }
            SoakVerdict::Failed => entry.state = RevisionState::Failed,
            SoakVerdict::Inconclusive => {}
        }
        self.save_index(&next)?;
        self.index = next;
        Ok(())
    }

    /// Mark the entry holding `revision` as [`RevisionState::Reverted`]:
    /// this node rolled away from it (WOR-2460, WOR-2461).
    ///
    /// The `lkg` pointer is deliberately **not** touched. A rollback
    /// away from a revision says nothing about which revision is good;
    /// what is good is whatever a soak promoted, and the rollback's own
    /// candidate soaks like any other before it can become that. A
    /// version of this that repointed `lkg` at the rollback target would
    /// promote it on apply, which is the epic's root defect wearing a
    /// different hat.
    ///
    /// History stays append-only: the successful rollback appends a
    /// **new** entry carrying the restored document, and this only
    /// annotates the entry that was rolled away from, so reading the
    /// ring top to bottom still tells the whole story in order.
    ///
    /// Distinct from [`RevisionState::Failed`], which is a soak verdict:
    /// an operator can roll away from a revision that soaked perfectly,
    /// a change that worked but was not wanted.
    ///
    /// An automatic revert reaches a revision that is already `Failed`,
    /// and `state` is one field, so this **overwrites** that mark rather
    /// than adding to it. The soak's own answer is not lost: it lives on
    /// `soak_verdict`, which nothing here touches, and that is the field
    /// [`Self::boot_candidates`] reads when it decides what may boot.
    /// Anything else that needs to know whether a soak condemned a
    /// revision must read `soak_verdict` too, for the same reason.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when no live entry holds
    /// `revision`, and [`RevisionStoreError::Io`] or
    /// [`RevisionStoreError::Json`] when the index cannot be persisted.
    pub fn mark_reverted(&mut self, revision: u64) -> Result<(), RevisionStoreError> {
        let mut next = self.index.clone();
        let entry = find_entry_mut(&mut next, revision)?;
        entry.state = RevisionState::Reverted;
        self.save_index(&next)?;
        self.index = next;
        Ok(())
    }

    /// Increment and persist `boot_attempts` on `revision`, returning
    /// the new count.
    ///
    /// Called *before* the attempt, never after, and persisted before it
    /// returns: the failure this counter exists to survive is a boot
    /// that dies partway through, taking any in-memory count with it.
    /// Borrowed from systemd-boot's boot counting, which renames the
    /// entry file on disk before handing control to it for exactly this
    /// reason.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when no live entry holds
    /// `revision`, and [`RevisionStoreError::Io`] or
    /// [`RevisionStoreError::Json`] when the index cannot be persisted.
    pub fn begin_boot_attempt(&mut self, revision: u64) -> Result<u32, RevisionStoreError> {
        let mut next = self.index.clone();
        let entry = find_entry_mut(&mut next, revision)?;
        entry.boot_attempts = entry.boot_attempts.saturating_add(1);
        let attempts = entry.boot_attempts;
        self.save_index(&next)?;
        self.index = next;
        Ok(attempts)
    }

    /// Clear `boot_attempts` on `revision`: this entry booted and served
    /// long enough to count as working.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when no live entry holds
    /// `revision`, and [`RevisionStoreError::Io`] or
    /// [`RevisionStoreError::Json`] when the index cannot be persisted.
    pub fn confirm_boot_success(&mut self, revision: u64) -> Result<(), RevisionStoreError> {
        let mut next = self.index.clone();
        let entry = find_entry_mut(&mut next, revision)?;
        entry.boot_attempts = 0;
        self.save_index(&next)?;
        self.index = next;
        Ok(())
    }

    /// Retire `revision` from the boot walk: it has failed to boot too
    /// many times to keep trying.
    ///
    /// Recorded on the entry rather than by deleting it. The entry is
    /// still history an operator wants to see, and still a document the
    /// admin surface can show; what changes is only that
    /// [`Self::boot_candidates`] stops offering it.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when no live entry holds
    /// `revision`, and [`RevisionStoreError::Io`] or
    /// [`RevisionStoreError::Json`] when the index cannot be persisted.
    pub fn retire_unbootable(&mut self, revision: u64) -> Result<(), RevisionStoreError> {
        let mut next = self.index.clone();
        let entry = find_entry_mut(&mut next, revision)?;
        entry.boot_retired = true;
        self.save_index(&next)?;
        self.index = next;
        Ok(())
    }

    /// Entries a boot fallback may try, in the order it should try them:
    /// the entry the `lkg` pointer names first, then every other live
    /// entry newest-first.
    ///
    /// Retired entries ([`Self::retire_unbootable`]) are excluded, which
    /// is what makes the walk terminate: the ring is finite and each
    /// exhausted candidate leaves it permanently.
    ///
    /// The order, and why:
    ///
    /// 1. the entry the `lkg` pointer names, because it is the only one
    ///    a soak window ever judged against real traffic;
    /// 2. every other entry no soak measured as bad, newest first,
    ///    because a more recent applied revision is closer to what the
    ///    operator meant than an older one;
    /// 3. the entries a soak measured as bad, newest first, last.
    ///
    /// The demotion keys on `soak_verdict`, **not** on
    /// [`RevisionState::Failed`], and that distinction is load bearing.
    /// There is one `state` field and two writers:
    /// [`Self::record_soak_verdict`] writes `Failed` and
    /// [`Self::mark_reverted`] writes `Reverted` over it. An automatic
    /// revert is exactly the sequence that does both to one revision,
    /// so reading `state` here let the revision a soak had just
    /// measured as breaking traffic climb back out of this group.
    /// `soak_verdict` survives both writes.
    ///
    /// Step 3 is the part worth reading twice. A `Failed` entry is one a
    /// soak window watched under real traffic and judged bad; the epic's
    /// whole success criterion is that a config which compiles cleanly
    /// and breaks traffic does not become the boot config. Offering one
    /// ahead of an older healthy entry inverted that. They are kept in
    /// the walk rather than dropped from it because an exhausted ring
    /// exits the process, and a revision that broke traffic is still a
    /// better outcome than no configuration at all: it is the last
    /// resort, not the first.
    #[must_use]
    pub fn boot_candidates(&self) -> Vec<RevisionEntry> {
        let lkg = self.index.lkg.clone();
        let mut candidates = Vec::new();
        if let Some(digest) = lkg.as_deref() {
            if let Some(entry) = self
                .index
                .entries
                .iter()
                .find(|entry| entry.digest == digest && !entry.boot_retired)
            {
                candidates.push(entry.clone());
            }
        }
        let mut measured_bad = Vec::new();
        for entry in self.index.entries.iter().rev() {
            if entry.boot_retired {
                continue;
            }
            if candidates
                .iter()
                .any(|chosen| chosen.revision == entry.revision)
            {
                continue;
            }
            if entry.soak_verdict == Some(SoakVerdict::Failed) {
                measured_bad.push(entry.clone());
            } else {
                candidates.push(entry.clone());
            }
        }
        candidates.extend(measured_bad);
        candidates
    }

    /// Record one refused candidate under `rejected/<digest>.json`,
    /// returning what was stored.
    ///
    /// Content addressed: a byte-identical candidate refused again
    /// updates the existing file's `count`, `last_seen_at`, `reason`,
    /// `stage`, and `detail` rather than writing a second file. An
    /// authority serving a broken bundle every poll interval otherwise
    /// evicts every other rejection within minutes, which is exactly
    /// when an operator needs the others.
    ///
    /// Takes `&self`, not `&mut self`: nothing here touches the ring
    /// index, so recording a refusal cannot disturb the applied history
    /// or the `lkg` pointer.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Invalid`] when `content` exceeds
    /// [`MAX_CONFIG_YAML_BYTES`] or is not UTF-8, and
    /// [`RevisionStoreError::Io`] or [`RevisionStoreError::Json`] when
    /// the file cannot be written.
    pub fn record_rejection(
        &self,
        content: &[u8],
        metadata: RejectionMetadata,
    ) -> Result<RejectedCandidate, RevisionStoreError> {
        if content.len() > MAX_CONFIG_YAML_BYTES {
            return Err(RevisionStoreError::invalid(format!(
                "rejected candidate is {} bytes, over the {MAX_CONFIG_YAML_BYTES} byte limit",
                content.len()
            )));
        }
        let document = std::str::from_utf8(content)
            .map_err(|error| {
                RevisionStoreError::invalid(format!("rejected candidate is not UTF-8: {error}"))
            })?
            .to_string();
        let digest = sha256_hex(content);
        let path = rejected_path(&self.directory, &digest);
        let existing = read_rejection(&path).ok().flatten();
        let candidate = RejectedCandidate {
            schema_version: REJECTED_SCHEMA_VERSION,
            digest,
            reason: metadata.reason,
            stage: metadata.stage,
            detail: metadata
                .detail
                .chars()
                .take(MAX_REJECTION_DETAIL_CHARS)
                .collect(),
            provenance: metadata.provenance,
            document,
            first_seen_at: existing
                .as_ref()
                .map_or(metadata.rejected_at, |prior| prior.first_seen_at),
            last_seen_at: metadata.rejected_at,
            count: existing.as_ref().map_or(0, |prior| prior.count) + 1,
        };
        let mut body = serde_json::to_vec_pretty(&candidate)
            .map_err(|source| RevisionStoreError::json("encode rejected candidate", source))?;
        body.push(b'\n');
        write_atomically(&path, &body)?;
        self.evict_rejections();
        Ok(candidate)
    }

    /// Refuse this ring when any file in it is readable or writable by
    /// anyone but its owner.
    ///
    /// The boot fallback is the first thing in the process that turns
    /// ring content into *executing* configuration, and the ring is
    /// trusted purely by filesystem location: the blobs are unsigned and
    /// `index.json` is unauthenticated. Two properties carry that trust.
    ///
    /// **Ownership.** [`Self::open`] runs `create_private_dir_all`,
    /// which `chmod`s the directory to `0700`. On every Unix only the
    /// file's owner or root may `chmod` it, so an open that succeeded has
    /// already proved the process owns the directory. That is why there
    /// is no `geteuid` here and why only the permission half is left.
    ///
    /// **Exclusivity.** Any group or other bit on `index.json`, its
    /// backup, or a blob means somebody else could have written the
    /// document this node is about to boot on. This store never creates
    /// a file that way (`create_private_file` opens at `0600`), so a
    /// bit set here was set from outside, and refusing is the only safe
    /// reading of it.
    ///
    /// Lives on the store rather than in the caller so it reads the same
    /// `INDEX_FILE`, `INDEX_BACKUP_FILE`, and `BLOBS_DIR` constants the
    /// writer uses: a layout rename moves both together instead of
    /// quietly turning the guard into a no-op. Non-Unix targets have no
    /// mode to inspect and this is a no-op there, stated rather than
    /// silently true.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Corrupt`] naming the offending file
    /// and its mode.
    #[cfg(unix)]
    pub fn refuse_shared_files(&self) -> Result<(), RevisionStoreError> {
        use std::os::unix::fs::PermissionsExt as _;

        let mut checked = vec![
            self.directory.join(INDEX_FILE),
            self.directory.join(INDEX_BACKUP_FILE),
        ];
        if let Ok(listing) = std::fs::read_dir(self.directory.join(BLOBS_DIR)) {
            checked.extend(listing.flatten().map(|entry| entry.path()));
        }
        for path in checked {
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(RevisionStoreError::Corrupt(format!(
                    "{} is mode {mode:o}; a ring a node is about to boot from must be \
                     readable and writable by its owner only, and this one is not, so its \
                     contents cannot be trusted as configuration",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// No mode to inspect on a non-Unix target. See the Unix version for
    /// what this checks and why.
    #[cfg(not(unix))]
    pub fn refuse_shared_files(&self) -> Result<(), RevisionStoreError> {
        Ok(())
    }

    /// Every stored rejected candidate, oldest refusal first.
    ///
    /// Ordered by `last_seen_at`, the same key eviction uses: a
    /// candidate an authority is still serving, and this node is still
    /// refusing every poll interval, is the one an operator is looking
    /// for right now. A file that fails to parse is skipped rather than
    /// failing the whole read: one unreadable rejection must not hide
    /// the others during the incident they were kept for.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionStoreError::Io`] when the directory cannot be
    /// listed.
    pub fn rejections(&self) -> Result<Vec<RejectedCandidate>, RevisionStoreError> {
        let mut out = Vec::new();
        let directory = self.directory.join(REJECTED_DIR);
        let listing = match std::fs::read_dir(&directory) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(error) => return Err(error.into()),
        };
        for entry in listing.flatten() {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            if let Ok(Some(candidate)) = read_rejection(&path) {
                out.push(candidate);
            }
        }
        out.sort_by(|left, right| {
            left.last_seen_at
                .cmp(&right.last_seen_at)
                .then_with(|| left.digest.cmp(&right.digest))
        });
        Ok(out)
    }

    /// Unlink the oldest stored rejections until at most
    /// `keep_rejected` remain.
    ///
    /// Ordered by `last_seen_at`, not `first_seen_at`: a candidate an
    /// authority is still serving, and this node is still refusing every
    /// poll interval, is the one an operator is looking for right now,
    /// and evicting it because its first refusal was a while ago would
    /// delete exactly the live incident. For a candidate refused once
    /// the two timestamps are equal, so this is plain oldest-first.
    ///
    /// Best effort: a failed unlink leaves one extra file behind, which
    /// [`Self::rejections`] reads like any other.
    fn evict_rejections(&self) {
        let Ok(stored) = self.rejections() else {
            return;
        };
        let Some(excess) = stored.len().checked_sub(self.keep_rejected) else {
            return;
        };
        for candidate in stored.iter().take(excess) {
            let _ = std::fs::remove_file(rejected_path(&self.directory, &candidate.digest));
        }
    }
}

/// Find one live entry by revision, or say which revision was missing.
fn find_entry_mut(
    index: &mut RevisionIndex,
    revision: u64,
) -> Result<&mut RevisionEntry, RevisionStoreError> {
    index
        .entries
        .iter_mut()
        .find(|entry| entry.revision == revision)
        .ok_or_else(|| {
            RevisionStoreError::invalid(format!("no ring entry holds revision {revision}"))
        })
}

/// Path of one rejected-candidate file for `digest`.
fn rejected_path(directory: &Path, digest: &str) -> PathBuf {
    directory
        .join(REJECTED_DIR)
        .join(format!("{digest}{REJECTED_SUFFIX}"))
}

/// Read one rejected-candidate file. `Ok(None)` when it does not exist.
fn read_rejection(path: &Path) -> Result<Option<RejectedCandidate>, RevisionStoreError> {
    let Some(bytes) = read_bounded(path, MAX_REJECTED_FILE_BYTES)? else {
        return Ok(None);
    };
    let candidate = serde_json::from_slice::<RejectedCandidate>(&bytes)
        .map_err(|source| RevisionStoreError::json("decode rejected candidate", source))?;
    Ok(Some(candidate))
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
            degraded: Vec::new(),
        }
    }

    /// WOR-2460, WOR-2461. Marking a revision reverted annotates that
    /// entry and touches nothing else. The last-known-good pointer in
    /// particular does not move: a rollback away from a revision says
    /// nothing about which revision is good, and a version of this that
    /// repointed `lkg` at the rollback target would promote it on apply,
    /// which is the defect the soak exists to fix.
    #[test]
    fn marking_a_revision_reverted_annotates_it_without_moving_the_pointer() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 10, None).expect("open");
        let first = store
            .append(b"proxy: {}\n# one\n", metadata(1))
            .expect("append");
        let second = store
            .append(b"proxy: {}\n# two\n", metadata(2))
            .expect("append");
        store.mark_good(first.revision).expect("promote");

        store.mark_reverted(second.revision).expect("annotate");
        assert_eq!(store.entries()[1].state, RevisionState::Reverted);
        assert_eq!(
            store.entries()[0].state,
            RevisionState::Good,
            "the entry that was rolled back to keeps its own verdict",
        );
        assert_eq!(
            store.lkg().map(|entry| entry.revision),
            Some(first.revision),
            "and the pointer does not move: only a soak moves it",
        );
        assert_eq!(
            store.entries().len(),
            2,
            "annotating is not removing; the ring is append-only",
        );

        let error = store
            .mark_reverted(999)
            .expect_err("a revision that is not in the ring cannot be annotated");
        assert!(error.to_string().contains("999"), "{error}");

        // Durable: an operator reading history after a restart has to
        // see that this node rolled away from something.
        drop(store);
        let reopened = RevisionStore::open(temp.path(), 10, None).expect("reopen");
        assert_eq!(reopened.entries()[1].state, RevisionState::Reverted);
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
    fn a_degraded_append_stays_applied_with_its_degradation_captured() {
        // A degraded reload still published a pipeline: the entry
        // belongs in the ring exactly like a clean apply, distinguished
        // only by which subsystems it names as not having applied.
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut ring = store(temp.path(), 10);
        let degraded_metadata = AppendMetadata {
            degraded: vec!["key plane".to_string(), "sink dispatcher".to_string()],
            ..metadata(1_000)
        };
        let entry = ring
            .append(b"origins: {}\n# degraded\n", degraded_metadata)
            .expect("append a degraded revision");
        assert_eq!(entry.state, RevisionState::Applied);
        assert_eq!(entry.degraded, vec!["key plane", "sink dispatcher"]);

        // Persisted, not just held in memory: a fresh open must read the
        // same degradation back off disk.
        drop(ring);
        let reopened = store(temp.path(), 10);
        assert_eq!(
            reopened.entries()[0].degraded,
            vec!["key plane", "sink dispatcher"]
        );
    }

    #[test]
    fn a_truncated_index_is_repaired_from_the_backup_on_the_first_open() {
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
        // call happens before this assertion. Every index save also
        // wrote the backup copy, so the repair recovers the history
        // instead of reinitializing an empty ring.
        let reopened = RevisionStore::open(temp.path(), 10, None).expect("open repairs");
        assert_eq!(
            reopened.entries().len(),
            1,
            "a truncated index is rebuilt from the backup rather than emptied or refused",
        );

        // And the repair was persisted immediately, so a second open finds
        // valid JSON rather than repairing again.
        let on_disk = std::fs::read(&index_path).expect("read repaired index");
        serde_json::from_slice::<serde_json::Value>(&on_disk)
            .expect("repaired index is valid json");
    }

    /// When the backup copy is gone or corrupt too, repair falls back
    /// to the pre-backup behavior: reinitialize an empty ring rather
    /// than refuse to open, with the loss named in the warning.
    #[test]
    fn a_ring_with_both_index_copies_corrupted_reinitializes_empty() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path(), 10);
            store
                .append(b"origins: {}\n", metadata(1_000))
                .expect("append");
        }
        std::fs::write(temp.path().join(INDEX_FILE), []).expect("zero the index");
        std::fs::write(temp.path().join(INDEX_BACKUP_FILE), b"{not json")
            .expect("corrupt the backup");

        let reopened = RevisionStore::open(temp.path(), 10, None)
            .expect("open still repairs rather than refusing");
        assert!(
            reopened.entries().is_empty(),
            "nothing is recoverable without a readable index copy",
        );
        let on_disk = std::fs::read(temp.path().join(INDEX_FILE)).expect("read repaired index");
        serde_json::from_slice::<serde_json::Value>(&on_disk)
            .expect("repaired index is valid json");
    }

    /// External truncation can leave `index.json` at exactly zero
    /// bytes, not just a half-written fragment: the case the test
    /// above covers. Before this test's fix, a zero-length file took a
    /// different path than a truncated-but-nonempty one --
    /// `read_bounded` refused it outright as `Corrupt` -- so `open`
    /// returned `Err` instead of repairing, which bricks the ring
    /// (`sbproxy-core`'s process-wide slot moves to its `Failed` state
    /// and every history route 503s) until an operator deletes the file
    /// by hand. Repair now recovers from the backup copy, so the ring
    /// keeps its history too.
    #[test]
    fn a_zero_byte_index_is_repaired_on_the_first_open_exactly_like_a_truncated_one() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path(), 10);
            store
                .append(b"origins: {}\n", metadata(1_000))
                .expect("append");
        }
        let index_path = temp.path().join(INDEX_FILE);
        assert!(
            std::fs::metadata(&index_path).expect("index exists").len() > 0,
            "the fixture must start non-empty so truncating it to zero is a real change",
        );
        std::fs::write(&index_path, []).expect("truncate index to zero bytes");
        assert_eq!(
            std::fs::metadata(&index_path)
                .expect("index still exists")
                .len(),
            0
        );

        // The repair must be the effect of `open` itself: no other store
        // call happens before this assertion.
        let reopened = RevisionStore::open(temp.path(), 10, None)
            .expect("a zero-byte index must be repaired, not refused");
        assert_eq!(
            reopened.entries().len(),
            1,
            "a zero-byte index is rebuilt from the backup rather than emptied or refused",
        );

        // And the repair was persisted immediately, so a second open
        // finds valid JSON rather than repairing again.
        let on_disk = std::fs::read(&index_path).expect("read repaired index");
        assert!(
            !on_disk.is_empty(),
            "the repair must have written something"
        );
        serde_json::from_slice::<serde_json::Value>(&on_disk)
            .expect("repaired index is valid json");
    }

    /// Phase-2 review: a zeroed `index.json` must not cost the ring
    /// its history. `save_index` writes a backup alongside the
    /// primary, and the repair path rebuilds from it, keeping only
    /// entries whose blob files survive - so `high_water_revision` and
    /// the last-known-good pointer outlive the truncation, and
    /// revision numbers are still never reused.
    #[test]
    fn a_zeroed_index_recovers_entries_high_water_and_lkg_from_the_backup() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path(), 10);
            store
                .append(b"origins: {}\n# one\n", metadata(1_000))
                .expect("append");
            let second = store
                .append(b"origins: {}\n# two\n", metadata(2_000))
                .expect("append");
            store.mark_good(second.revision).expect("mark lkg");
        }
        std::fs::write(temp.path().join(INDEX_FILE), []).expect("zero the index");

        let mut reopened = RevisionStore::open(temp.path(), 10, None).expect("open repairs");
        assert_eq!(
            reopened.entries().len(),
            2,
            "both applied revisions must survive a zeroed index"
        );
        assert_eq!(
            reopened.lkg().map(|entry| entry.revision),
            Some(2),
            "the last-known-good pointer must survive a zeroed index"
        );
        // `high_water_revision` survived too: the next append continues
        // the sequence instead of reusing revision 1.
        let third = reopened
            .append(b"origins: {}\n# three\n", metadata(3_000))
            .expect("append after repair");
        assert_eq!(
            third.revision, 3,
            "revision numbers are never reused, repair included"
        );
    }

    /// The other half of `read_bounded`'s zero-length change: a blob
    /// still errors on zero bytes, just one step further downstream
    /// than before (there is no valid zstd frame in zero bytes, so
    /// `zstd::decode_all` is what refuses it now, not `read_bounded`
    /// itself). A blob silently "succeeding" with empty content would
    /// be far worse than either error shape: it would hand a caller an
    /// empty document instead of failing loudly.
    #[test]
    fn a_zero_byte_blob_still_fails_to_read_rather_than_succeeding_silently() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path(), 10);
        let entry = store.append(b"origins: {}\n", metadata(1)).expect("append");
        let blob = blob_path(temp.path(), &entry.digest);
        std::fs::write(&blob, []).expect("truncate blob to zero bytes");

        let result = store.read_blob(&entry.digest);
        assert!(
            result.is_err(),
            "a zero-byte blob must still fail to read, not decode to empty content: {result:?}",
        );
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
    fn an_orphan_blob_is_reused_rather_than_overwritten_by_a_matching_append() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(store(temp.path(), 10));

        // Plant an orphan under the exact digest a later append of this
        // content will land on, but with bytes that are NOT a real
        // compressed encoding of it, so any overwrite is detectable.
        let content: &[u8] = b"origins: {}\n# would-be-appended-later\n";
        let digest = sha256_hex(content);
        let orphan_path = blob_path(temp.path(), &digest);
        let marker: &[u8] = b"not a real compressed blob, just a marker";
        std::fs::write(&orphan_path, marker).expect("write orphan blob");

        let mut reopened = RevisionStore::open(temp.path(), 10, None)
            .expect("an unnamed blob is adopted, not refused");
        assert!(reopened.entries().is_empty());

        // Appending the same content must find the blob already there
        // by digest and skip the write, not overwrite the orphan with a
        // fresh compression.
        reopened
            .append(content, metadata(1))
            .expect("append matching the orphan's digest");
        let on_disk = std::fs::read(&orphan_path).expect("read blob after append");
        assert_eq!(
            on_disk, marker,
            "matching content must reuse the adopted blob's bytes untouched",
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
    fn the_store_reopens_cleanly_after_an_eviction_triggering_append() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let keep = 1usize;
        {
            let mut store = store(temp.path(), keep);
            store
                .append(b"origins: {}\n# one\n", metadata(1))
                .expect("append");
            store
                .append(b"origins: {}\n# two\n", metadata(2))
                .expect("append triggers eviction");
        }
        let reopened = RevisionStore::open(temp.path(), keep, None)
            .expect("a store that just evicted must still reopen cleanly");
        assert_eq!(reopened.entries().len(), 1);
        assert_eq!(reopened.entries()[0].applied_at, 2);
    }

    #[test]
    fn a_failed_index_persist_during_an_evicting_append_leaves_every_previously_named_blob_untouched(
    ) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let keep = 1usize;
        let mut store = store(temp.path(), keep);
        let first = store
            .append(b"origins: {}\n# one\n", metadata(1))
            .expect("append");

        // Force the next index persist to fail deterministically and
        // portably: renaming a regular file onto an existing directory
        // always fails regardless of permission bits, unlike chmod-ing
        // the store directory read-only, which `create_private_dir_all`
        // would self-heal back to 0700 before the write even attempts to
        // run.
        let index_path = temp.path().join(INDEX_FILE);
        std::fs::remove_file(&index_path).expect("remove index.json");
        std::fs::create_dir(&index_path).expect("shadow index.json with a directory");

        let result = store.append(b"origins: {}\n# two\n", metadata(2));
        assert!(
            result.is_err(),
            "a shadowed index.json must fail the persist, not silently succeed",
        );
        assert!(
            blob_path(temp.path(), &first.digest).is_file(),
            "the previously named blob must survive a failed persist untouched: \
             eviction only unlinks a blob after the index that stops naming it \
             is durable",
        );
        assert_eq!(
            store.entries().len(),
            1,
            "the in-memory index must not advance past what is actually on disk",
        );
    }

    #[test]
    fn a_crash_between_persisting_the_evicted_index_and_unlinking_orphans_leaves_an_adoptable_blob()
    {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let keep = 1usize;
        let mut store = store(temp.path(), keep);
        let first = store
            .append(b"origins: {}\n# one\n", metadata(1))
            .expect("append");

        // Manually drive the same sequence `append` uses, stopping right
        // after the index persists and before the orphaned blob is
        // unlinked: that gap is the crash window this test proves is
        // safe to land in.
        let second_content: &[u8] = b"origins: {}\n# two\n";
        let second_digest = sha256_hex(second_content);
        store
            .write_blob_if_absent(&second_digest, second_content)
            .expect("write second blob");
        let mut next = store.index.clone();
        next.high_water_revision += 1;
        next.entries.push(RevisionEntry {
            digest: second_digest.clone(),
            revision: next.high_water_revision,
            provenance: BaseOrigin::Local,
            state: RevisionState::Applied,
            blast_radius: None,
            secrets_fingerprint: None,
            actor: None,
            applied_at: 2,
            soak_verdict: None,
            boot_attempts: 0,
            degraded: Vec::new(),
            boot_retired: false,
        });
        let orphaned = evict_entries(store.keep, &mut next);
        assert_eq!(
            orphaned,
            vec![first.digest.clone()],
            "the first entry is the only eviction candidate here",
        );
        store.save_index(&next).expect("persist the evicted index");
        // Simulate the crash: the blob-unlink step never runs.

        assert!(
            blob_path(temp.path(), &first.digest).is_file(),
            "the crash window leaves the orphaned blob in place",
        );

        let reopened = RevisionStore::open(temp.path(), keep, None)
            .expect("a dangling orphan blob must open cleanly, not refuse");
        assert_eq!(reopened.entries().len(), 1);
        assert_eq!(reopened.entries()[0].digest, second_digest);
        // This module adopts an orphan (leaves it in place) rather than
        // sweeping it at open; a later GC pass, not open itself, is the
        // right place to reclaim it, matching every other blob nothing
        // names.
        assert!(
            blob_path(temp.path(), &first.digest).is_file(),
            "the orphan left by the crash window is adopted, not swept, at open",
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

    // --- WOR-2458 / WOR-2459 / WOR-2462 ---

    fn rejection(reason: RejectionReason, stage: &str, at: u64) -> RejectionMetadata {
        RejectionMetadata {
            reason,
            stage: stage.to_string(),
            detail: "refused for the test".to_string(),
            provenance: BaseOrigin::Local,
            rejected_at: at,
        }
    }

    /// WOR-2458. The promotion rule lives in the store, not in a caller:
    /// only a `Successful` verdict may move the `lkg` pointer.
    #[test]
    fn a_successful_soak_verdict_advances_the_lkg_pointer_once() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        let entry = store.append(b"a: 1\n", metadata(1)).expect("append");
        assert!(store.lkg().is_none(), "appending never promotes");

        store
            .record_soak_verdict(entry.revision, SoakVerdict::Successful)
            .expect("verdict");

        let lkg = store.lkg().expect("a successful soak promotes").clone();
        assert_eq!(lkg.revision, entry.revision);
        assert_eq!(lkg.state, RevisionState::Good);
        assert_eq!(lkg.soak_verdict, Some(SoakVerdict::Successful));
    }

    /// WOR-2458. A failed soak records the verdict and marks the entry
    /// failed, and the pointer stays exactly where it was.
    #[test]
    fn a_failed_soak_verdict_never_moves_the_lkg_pointer() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        let good = store.append(b"a: 1\n", metadata(1)).expect("append");
        store
            .record_soak_verdict(good.revision, SoakVerdict::Successful)
            .expect("verdict");
        let bad = store.append(b"a: 2\n", metadata(2)).expect("append");

        store
            .record_soak_verdict(bad.revision, SoakVerdict::Failed)
            .expect("verdict");

        assert_eq!(
            store.lkg().expect("still the first entry").revision,
            good.revision,
            "a failed soak must not advance the pointer"
        );
        let failed = store
            .entries()
            .iter()
            .find(|entry| entry.revision == bad.revision)
            .expect("entry survives");
        assert_eq!(failed.state, RevisionState::Failed);
        assert_eq!(failed.soak_verdict, Some(SoakVerdict::Failed));
    }

    /// WOR-2458. Inconclusive is the third state, and it is neither a
    /// promotion nor a failure: the entry stays `applied` and the
    /// pointer does not move.
    #[test]
    fn an_inconclusive_soak_verdict_leaves_the_entry_applied() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        let entry = store.append(b"a: 1\n", metadata(1)).expect("append");

        store
            .record_soak_verdict(entry.revision, SoakVerdict::Inconclusive)
            .expect("verdict");

        assert!(store.lkg().is_none(), "inconclusive never promotes");
        let stored = store.entries().last().expect("entry");
        assert_eq!(stored.state, RevisionState::Applied);
        assert_eq!(stored.soak_verdict, Some(SoakVerdict::Inconclusive));
    }

    /// WOR-2458. A verdict for a revision the ring no longer holds is a
    /// caller bug, not a silent no-op.
    #[test]
    fn a_soak_verdict_for_an_unknown_revision_is_refused() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        let error = store
            .record_soak_verdict(99, SoakVerdict::Successful)
            .expect_err("unknown revision");
        assert!(format!("{error}").contains("99"), "{error}");
    }

    /// WOR-2459. `boot_attempts` is on disk, not in memory: a hard kill
    /// between the increment and the crash must not lose the count.
    #[test]
    fn boot_attempts_survive_a_reopen() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let revision = {
            let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
            let entry = store.append(b"a: 1\n", metadata(1)).expect("append");
            assert_eq!(
                store.begin_boot_attempt(entry.revision).expect("attempt"),
                1
            );
            assert_eq!(
                store.begin_boot_attempt(entry.revision).expect("attempt"),
                2
            );
            entry.revision
        };

        let mut store = RevisionStore::open(temp.path(), 8, None).expect("reopen");
        assert_eq!(
            store
                .entries()
                .iter()
                .find(|entry| entry.revision == revision)
                .expect("entry")
                .boot_attempts,
            2,
            "the counter is durable, not process-local"
        );
        assert_eq!(
            store.begin_boot_attempt(revision).expect("attempt"),
            3,
            "a reopen continues the count rather than restarting it"
        );
        store.confirm_boot_success(revision).expect("confirm");
        assert_eq!(
            store
                .entries()
                .iter()
                .find(|entry| entry.revision == revision)
                .expect("entry")
                .boot_attempts,
            0,
            "serving for the success window clears the counter"
        );
    }

    /// WOR-2459 fix round, Major 10. A revision a soak measured as bad
    /// under real traffic must not be offered ahead of an older healthy
    /// one: "a config that compiles cleanly and breaks traffic does not
    /// become the boot config" is the epic's success criterion.
    #[test]
    fn a_soak_failed_revision_sinks_below_every_healthy_one_in_the_boot_walk() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        let old_healthy = store.append(b"a: 1\n", metadata(1)).expect("append");
        let newer_broken = store.append(b"a: 2\n", metadata(2)).expect("append");
        store
            .record_soak_verdict(newer_broken.revision, SoakVerdict::Failed)
            .expect("verdict");

        let order: Vec<u64> = store
            .boot_candidates()
            .iter()
            .map(|entry| entry.revision)
            .collect();
        assert_eq!(
            order,
            vec![old_healthy.revision, newer_broken.revision],
            "the measured-bad revision is the last resort, not the first",
        );

        // It stays in the walk rather than being dropped: an exhausted
        // ring exits the process, and a revision that broke traffic
        // still beats no configuration at all.
        assert!(
            store
                .boot_candidates()
                .iter()
                .any(|entry| entry.revision == newer_broken.revision),
            "a failed revision is demoted, not deleted",
        );
    }

    /// Review Major 3. The demotion above read `entry.state`, and
    /// `mark_reverted` writes the same single field, so an automatic
    /// revert overwrote `Failed` with `Reverted` and the revision a soak
    /// measured as breaking traffic climbed back out of the last-resort
    /// group. That is the epic's success criterion inverted by the
    /// feature meant to uphold it: `auto_revert` is the only thing that
    /// writes both marks to one revision.
    ///
    /// `soak_verdict` survives both writes, which is what the demotion
    /// keys on now.
    #[test]
    fn a_soak_failed_revision_stays_last_resort_after_an_auto_revert_annotates_it() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        let old_healthy = store.append(b"a: 1\n", metadata(1)).expect("append");
        let newer_broken = store.append(b"a: 2\n", metadata(2)).expect("append");
        store
            .record_soak_verdict(newer_broken.revision, SoakVerdict::Failed)
            .expect("verdict");
        // What an automatic revert does next, and the whole of the bug:
        // one `state` field, two writers, second write wins.
        store
            .mark_reverted(newer_broken.revision)
            .expect("annotate the revision reverted away from");

        let entry = store
            .entries()
            .iter()
            .find(|entry| entry.revision == newer_broken.revision)
            .cloned()
            .expect("the entry is still there");
        assert_eq!(
            entry.state,
            RevisionState::Reverted,
            "the annotation is the newer fact and still lands",
        );
        assert_eq!(
            entry.soak_verdict,
            Some(SoakVerdict::Failed),
            "and the verdict survives it, which is what the boot walk has to read",
        );

        let order: Vec<u64> = store
            .boot_candidates()
            .iter()
            .map(|entry| entry.revision)
            .collect();
        assert_eq!(
            order,
            vec![old_healthy.revision, newer_broken.revision],
            "a revision a soak measured as bad stays the last resort after it is reverted \
             away from, or an auto-revert turns the boot walk into a way back onto it",
        );
    }

    /// Re-review, new Major 1. The Major-12 security control shipped with
    /// no test on its refusal path: nothing had ever watched it fire. It
    /// also hard-coded this module's file names across a crate boundary,
    /// where a layout rename would have turned it into a silent no-op.
    /// It lives here now, beside the constants it reads.
    #[cfg(unix)]
    #[test]
    fn a_ring_whose_index_anyone_can_read_is_refused_as_untrusted() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        store.append(b"a: 1\n", metadata(1)).expect("append");

        // An ordinary ring, exactly as this store writes it, boots.
        store
            .refuse_shared_files()
            .expect("a 0600/0700 ring is the shape this store creates");

        // Someone widened the index. The store never creates a file that
        // way, so the bit was set from outside and the contents cannot be
        // trusted as configuration.
        let index = temp.path().join(INDEX_FILE);
        std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = store
            .refuse_shared_files()
            .expect_err("a world-readable index must refuse the walk");
        let rendered = format!("{error}");
        assert!(rendered.contains(INDEX_FILE), "{rendered}");
        assert!(rendered.contains("644"), "the mode is named: {rendered}");
        std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o600)).expect("restore");
        store.refuse_shared_files().expect("restored");

        // The same for the backup copy...
        let backup = temp.path().join(INDEX_BACKUP_FILE);
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        let error = store
            .refuse_shared_files()
            .expect_err("a group-readable backup must refuse the walk");
        assert!(format!("{error}").contains(INDEX_BACKUP_FILE), "{error}");
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600)).expect("restore");

        // ... and for a blob, which is the document that would actually
        // be compiled and served.
        let digest = store.entries()[0].digest.clone();
        let blob = blob_path(temp.path(), &digest);
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let error = store
            .refuse_shared_files()
            .expect_err("a world-writable blob must refuse the walk");
        assert!(format!("{error}").contains(&digest), "{error}");
    }

    /// WOR-2459. A retired entry drops out of the boot walk, and the
    /// walk continues to the next candidate rather than stopping.
    #[test]
    fn boot_candidates_put_the_lkg_first_and_skip_retired_entries() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
        let first = store.append(b"a: 1\n", metadata(1)).expect("append");
        let second = store.append(b"a: 2\n", metadata(2)).expect("append");
        let third = store.append(b"a: 3\n", metadata(3)).expect("append");
        store
            .record_soak_verdict(second.revision, SoakVerdict::Successful)
            .expect("verdict");

        let order: Vec<u64> = store
            .boot_candidates()
            .iter()
            .map(|entry| entry.revision)
            .collect();
        assert_eq!(
            order,
            vec![second.revision, third.revision, first.revision],
            "the last known good is tried first, then the rest newest-first"
        );

        store.retire_unbootable(second.revision).expect("retire");
        let order: Vec<u64> = store
            .boot_candidates()
            .iter()
            .map(|entry| entry.revision)
            .collect();
        assert_eq!(
            order,
            vec![third.revision, first.revision],
            "a retired entry leaves the walk and the walk continues"
        );
        assert!(
            store
                .entries()
                .iter()
                .find(|entry| entry.revision == second.revision)
                .expect("entry survives")
                .boot_retired,
            "retirement is recorded on the entry, not by deleting it"
        );
    }

    /// WOR-2459. Retirement is durable for the same reason the counter
    /// is: the next boot must not re-try an entry this one proved dead.
    #[test]
    fn retirement_survives_a_reopen() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let revision = {
            let mut store = RevisionStore::open(temp.path(), 8, None).expect("open");
            let entry = store.append(b"a: 1\n", metadata(1)).expect("append");
            store.retire_unbootable(entry.revision).expect("retire");
            entry.revision
        };
        let store = RevisionStore::open(temp.path(), 8, None).expect("reopen");
        assert!(
            store.boot_candidates().is_empty(),
            "an exhausted ring stays exhausted across a restart"
        );
        assert!(store
            .entries()
            .iter()
            .any(|entry| entry.revision == revision && entry.boot_retired));
    }

    /// WOR-2462. Every reason in the subscriber's failure table lands as
    /// its own stored entry, named by that reason.
    #[test]
    fn each_refusal_reason_is_stored_under_its_own_name() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = RevisionStore::open(temp.path(), 8, None)
            .expect("open")
            .with_keep_rejected(10);

        for (index, reason) in [
            RejectionReason::VerifyFailed,
            RejectionReason::CompileFailed,
            RejectionReason::DeniedPath,
            RejectionReason::ConfinementRefused,
        ]
        .into_iter()
        .enumerate()
        {
            let document = format!("a: {index}\n");
            store
                .record_rejection(
                    document.as_bytes(),
                    rejection(reason, "config_authority", 100 + index as u64),
                )
                .expect("record");
        }

        let stored = store.rejections().expect("read back");
        assert_eq!(stored.len(), 4, "one entry per reason: {stored:?}");
        let reasons: Vec<RejectionReason> = stored.iter().map(|entry| entry.reason).collect();
        assert!(reasons.contains(&RejectionReason::VerifyFailed));
        assert!(reasons.contains(&RejectionReason::CompileFailed));
        assert!(reasons.contains(&RejectionReason::DeniedPath));
        assert!(reasons.contains(&RejectionReason::ConfinementRefused));
        for entry in &stored {
            assert_eq!(entry.stage, "config_authority");
            assert_eq!(entry.count, 1);
        }
    }

    /// WOR-2462. A repeat refusal of byte-identical content updates the
    /// one entry rather than filling the directory with copies.
    #[test]
    fn a_repeated_refusal_updates_the_count_and_last_seen() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = RevisionStore::open(temp.path(), 8, None)
            .expect("open")
            .with_keep_rejected(10);
        let document = b"a: 1\n";

        store
            .record_rejection(
                document,
                rejection(RejectionReason::CompileFailed, "file_watcher", 100),
            )
            .expect("record");
        store
            .record_rejection(
                document,
                rejection(RejectionReason::CompileFailed, "sighup", 250),
            )
            .expect("record");

        let stored = store.rejections().expect("read back");
        assert_eq!(stored.len(), 1, "one entry, not two: {stored:?}");
        assert_eq!(stored[0].count, 2);
        assert_eq!(stored[0].first_seen_at, 100);
        assert_eq!(stored[0].last_seen_at, 250);
        assert_eq!(
            stored[0].stage, "sighup",
            "the most recent refusal names the stage that refused it"
        );
    }

    /// WOR-2462. `keep_rejected` bounds the directory and eviction is
    /// oldest-first.
    #[test]
    fn keep_rejected_bounds_the_directory_oldest_first() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = RevisionStore::open(temp.path(), 8, None)
            .expect("open")
            .with_keep_rejected(3);

        for index in 0..6u64 {
            let document = format!("a: {index}\n");
            store
                .record_rejection(
                    document.as_bytes(),
                    rejection(RejectionReason::CompileFailed, "file_watcher", 100 + index),
                )
                .expect("record");
        }

        let stored = store.rejections().expect("read back");
        assert_eq!(stored.len(), 3, "bounded to keep_rejected: {stored:?}");
        let seen: Vec<u64> = stored.iter().map(|entry| entry.last_seen_at).collect();
        assert_eq!(
            seen,
            vec![103, 104, 105],
            "the three oldest were evicted, oldest first"
        );
        let on_disk = std::fs::read_dir(temp.path().join(REJECTED_DIR))
            .expect("read dir")
            .count();
        assert_eq!(on_disk, 3, "eviction unlinks the files, not just the view");
    }

    /// WOR-2462. The stored candidate keeps the document as written, so
    /// an operator can see what was refused.
    #[test]
    fn a_stored_rejection_keeps_the_pre_resolution_document() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = RevisionStore::open(temp.path(), 8, None)
            .expect("open")
            .with_keep_rejected(4);
        let document = "api_key: ${OPENAI_API_KEY}\n";

        store
            .record_rejection(
                document.as_bytes(),
                rejection(RejectionReason::CompileFailed, "file_watcher", 7),
            )
            .expect("record");

        let stored = store.rejections().expect("read back");
        assert_eq!(stored[0].document, document);
        assert!(
            stored[0].document.contains("${OPENAI_API_KEY}"),
            "the reference is kept unresolved, exactly as the ring's blobs are"
        );
    }

    /// WOR-2462. Owner-only, like every other file this store writes.
    #[cfg(unix)]
    #[test]
    fn a_stored_rejection_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = RevisionStore::open(temp.path(), 8, None)
            .expect("open")
            .with_keep_rejected(4);
        let candidate = store
            .record_rejection(
                b"a: 1\n",
                rejection(RejectionReason::VerifyFailed, "config_authority", 1),
            )
            .expect("record");
        let path = temp
            .path()
            .join(REJECTED_DIR)
            .join(format!("{}.json", candidate.digest));
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{path:?} is {mode:o}");
    }
}
