// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The process-owned handle onto [`sbproxy_config::RevisionStore`]: the
//! durable, content-addressed ring of every config this process has
//! applied.
//!
//! # Lifecycle
//!
//! [`ConfigHistoryRecorder::from_config`] opens the ring named by
//! `proxy.config_history` once, at boot. [`install_config_history_recorder`]
//! publishes it into a process-wide slot; the reload transaction in
//! `crate::server::lifecycle` appends to it through
//! [`current_config_history_recorder`], and the admin history routes (a
//! later change) read it back the same way. A block that is absent or
//! carries `enabled: false` means `from_config` returns `None`, nothing
//! is ever installed, and every downstream call site treats an empty
//! slot as a silent no-op: recording is opt-in, and an operator who
//! never opted in pays nothing for it.
//!
//! # Never advances the last-known-good pointer
//!
//! Nothing in this module calls [`sbproxy_config::RevisionStore::mark_good`].
//! Promoting a revision to last-known-good is a soak-window decision (a
//! later change), not something recording an applied revision does on
//! its own; see that method's own documentation.
//!
//! # A known gap: lineage is not re-minted on a cluster identity change
//!
//! [`sbproxy_config::RevisionStore::open`] accepts an optional
//! [`sbproxy_config::ClusterRestartFingerprint`] so a ring's `lineage`
//! can be re-minted when the process-owned cluster identity it belongs
//! to changes. `from_config` always opens with `None`. The installed
//! cluster identity used to reconcile a reload is process-internal
//! state (`sbproxy_core::cluster`'s own `InstalledCluster`) with no
//! public accessor today, and threading one through was out of scope
//! for wiring the recorder itself. The cost of this gap is narrow: a
//! ring's `lineage` never changes across a cluster identity change on
//! the same store directory, so a rollback tool that keys off `lineage`
//! to detect "does this history still describe the same installation"
//! cannot detect that one case. Every other repair, eviction, and
//! dedup guarantee [`sbproxy_config::RevisionStore`] documents is
//! unaffected.

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use sbproxy_config::{
    AppendMetadata, ConfigHistoryConfig, RevisionEntry, RevisionStore, RevisionStoreError,
};

/// The process-owned config revision ring.
///
/// [`sbproxy_config::RevisionStore`] documents itself as single-owner
/// (every mutator takes `&mut self`; "not internally synchronized: one
/// process owns one store directory"). The reload transaction and the
/// admin history routes (a later change) both reach this recorder from
/// their own task, so this wraps the store in a [`Mutex`] to serialize
/// that access rather than assuming a single owning task the way the
/// store's own contract permits.
pub struct ConfigHistoryRecorder {
    store: Mutex<RevisionStore>,
    /// `proxy.config_history.keep_rejected`. Nothing in this crate
    /// writes to the store's `rejected/` directory yet, so this field
    /// has no reader other than carrying the value forward for the
    /// rejected-candidate retention writer to come.
    keep_rejected: usize,
}

impl ConfigHistoryRecorder {
    /// Open the ring `history` names, or return `None` when the block is
    /// absent or `enabled: false`.
    ///
    /// # Errors
    ///
    /// Returns an error when the block is present and enabled but the
    /// ring cannot be opened: an unwritable directory, or an
    /// `index.json` in the one shape
    /// [`sbproxy_config::RevisionStore::open`] refuses outright rather
    /// than repairs (a named digest with no blob, or an `lkg` pointer
    /// naming a digest no entry carries). A boot that cannot open its
    /// own audit trail fails loudly rather than silently running
    /// without one.
    pub fn from_config(history: Option<&ConfigHistoryConfig>) -> anyhow::Result<Option<Self>> {
        let Some(history) = history else {
            return Ok(None);
        };
        if !history.enabled {
            return Ok(None);
        }
        let store = RevisionStore::open(&history.dir, history.keep, None).map_err(|error| {
            anyhow::anyhow!("open config history store '{}': {error}", history.dir)
        })?;
        Ok(Some(Self {
            store: Mutex::new(store),
            keep_rejected: history.keep_rejected,
        }))
    }

    /// Append one applied revision.
    ///
    /// A no-op, deliberately, when `content` is byte-identical to the
    /// ring's current most recent entry: two consecutive reloads of the
    /// same document are one applied revision, not two. This is
    /// distinct from [`sbproxy_config::RevisionStore::append`]'s own
    /// content-addressed dedup, which reuses a matching blob across two
    /// *non-adjacent* entries (an A-to-B-to-A flap) but still records a
    /// fresh index entry each time; skipping the append entirely, here,
    /// only when the immediately preceding entry already names the same
    /// content is what keeps a reload loop that repeatedly re-applies an
    /// unchanged file from growing the ring on every tick.
    ///
    /// Also logs and swallows a write failure rather than propagating
    /// it: this ring is a diagnostic and rollback aid, not a gate the
    /// running proxy's own request path depends on, so a full disk or a
    /// permissions problem here must not fail a reload transaction that
    /// otherwise succeeded and already published.
    pub fn record(&self, content: &[u8], metadata: AppendMetadata) {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(last) = store.entries().last() {
            if let Ok(previous_bytes) = store.read_blob(&last.digest) {
                if previous_bytes.as_slice() == content {
                    return;
                }
            }
        }
        if let Err(error) = store.append(content, metadata) {
            tracing::error!(
                error = %error,
                "config history: failed to record an applied config revision"
            );
        }
    }

    /// Every ring entry, oldest first.
    #[must_use]
    pub fn entries(&self) -> Vec<RevisionEntry> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.entries().to_vec()
    }

    /// The entry the last-known-good pointer names, if any has been
    /// marked good.
    ///
    /// Nothing in this module (or in `crate::server::lifecycle`'s
    /// reload transaction) ever moves this pointer: recording an
    /// applied revision is not promoting one to last-known-good. See
    /// [`sbproxy_config::RevisionStore::mark_good`]'s own documentation
    /// for why that is a separate, later decision.
    #[must_use]
    pub fn lkg(&self) -> Option<RevisionEntry> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.lkg().cloned()
    }

    /// This ring's lineage identity: a UUID stable across reopen and a
    /// `source:` repoint. See
    /// [`sbproxy_config::RevisionStore::lineage`]'s own documentation.
    #[must_use]
    pub fn lineage(&self) -> String {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.lineage().to_string()
    }

    /// Read back the pre-resolution bytes stored for one entry's digest.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as
    /// [`sbproxy_config::RevisionStore::read_blob`].
    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>, RevisionStoreError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.read_blob(digest)
    }

    /// `proxy.config_history.keep_rejected`, carried forward for the
    /// rejected-candidate writer to come. See the field's own doc.
    #[must_use]
    pub const fn keep_rejected(&self) -> usize {
        self.keep_rejected
    }

    /// Blast radius of `content` against this ring's most recent entry,
    /// via [`sbproxy_config::plan`].
    ///
    /// `None` for an empty ring (nothing to diff against, matching
    /// [`AppendMetadata::blast_radius`]'s own documented meaning for a
    /// ring's first entry) or when either document fails to parse as a
    /// [`sbproxy_config::ConfigFile`]. Best-effort and diagnostic only:
    /// a parse failure here must not block recording the revision it
    /// would have described, so it is swallowed into `None` rather than
    /// propagated.
    #[must_use]
    pub fn blast_radius_for(&self, content: &[u8]) -> Option<sbproxy_config::BlastRadius> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous_digest = store.entries().last()?.digest.clone();
        let previous_bytes = store.read_blob(&previous_digest).ok()?;
        drop(store);
        let baseline_text = std::str::from_utf8(&previous_bytes).ok()?;
        let baseline = serde_yaml::from_str::<sbproxy_config::ConfigFile>(baseline_text).ok()?;
        let content_text = std::str::from_utf8(content).ok()?;
        let proposed = serde_yaml::from_str::<sbproxy_config::ConfigFile>(content_text).ok()?;
        Some(sbproxy_config::plan(&baseline, &proposed).max_blast_radius)
    }
}

/// The process-wide recorder, when this node has one.
///
/// A swap slot rather than a set-once cell so a test can install one,
/// and so a later change can rebuild the recorder without the process
/// having to restart. Mirrors the `PROCESS_AUTHORITY` slot in
/// `crate::config_authority`.
static PROCESS_CONFIG_HISTORY: ArcSwapOption<ConfigHistoryRecorder> = ArcSwapOption::const_empty();

/// Install the process-wide recorder, replacing any previous one.
pub fn install_config_history_recorder(recorder: Arc<ConfigHistoryRecorder>) {
    PROCESS_CONFIG_HISTORY.store(Some(recorder));
}

/// The process-wide recorder, when `proxy.config_history.enabled` is
/// true on this node. `None` is not an error: it is what an operator
/// who never opted in sees, and every call site here treats it as a
/// no-op.
#[must_use]
pub fn current_config_history_recorder() -> Option<Arc<ConfigHistoryRecorder>> {
    PROCESS_CONFIG_HISTORY.load_full()
}

/// Drop the process-wide recorder. Used by tests that must not leak one
/// into the next case.
#[cfg(test)]
pub(crate) fn clear_config_history_recorder() {
    PROCESS_CONFIG_HISTORY.store(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_block_opens_no_recorder() {
        let recorder =
            ConfigHistoryRecorder::from_config(None).expect("no error for an absent block");
        assert!(recorder.is_none());
    }

    #[test]
    fn disabled_block_opens_no_recorder() {
        let history = ConfigHistoryConfig {
            enabled: false,
            ..Default::default()
        };
        let recorder = ConfigHistoryRecorder::from_config(Some(&history))
            .expect("no error for a disabled block");
        assert!(recorder.is_none());
    }

    #[test]
    fn enabled_block_opens_a_recorder_against_its_dir() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = ConfigHistoryConfig {
            enabled: true,
            dir: temp.path().to_string_lossy().to_string(),
            keep: 5,
            keep_rejected: 3,
        };
        let recorder = ConfigHistoryRecorder::from_config(Some(&history))
            .expect("no error")
            .expect("an enabled block opens a recorder");
        assert_eq!(recorder.keep_rejected(), 3);
        assert!(recorder.entries().is_empty());
    }

    #[test]
    fn lineage_is_a_stable_non_empty_identity() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let recorder = recorder_at(temp.path());
        let lineage = recorder.lineage();
        assert!(!lineage.is_empty());
        recorder.record(b"origins: {}\n", metadata("test"));
        assert_eq!(
            recorder.lineage(),
            lineage,
            "recording an entry must not change the ring's identity"
        );
    }

    #[test]
    fn install_and_current_round_trip_through_the_process_slot() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let history = ConfigHistoryConfig {
            enabled: true,
            dir: temp.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        let recorder = ConfigHistoryRecorder::from_config(Some(&history))
            .expect("no error")
            .expect("an enabled block opens a recorder");
        install_config_history_recorder(Arc::new(recorder));
        assert!(current_config_history_recorder().is_some());
        clear_config_history_recorder();
        assert!(current_config_history_recorder().is_none());
    }

    fn metadata(actor: &str) -> AppendMetadata {
        AppendMetadata {
            provenance: sbproxy_config::BaseOrigin::Local,
            blast_radius: None,
            secrets_fingerprint: None,
            actor: Some(actor.to_string()),
            applied_at: 1,
            degraded: Vec::new(),
        }
    }

    fn recorder_at(dir: &std::path::Path) -> ConfigHistoryRecorder {
        let history = ConfigHistoryConfig {
            enabled: true,
            dir: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        ConfigHistoryRecorder::from_config(Some(&history))
            .expect("no error")
            .expect("an enabled block opens a recorder")
    }

    #[test]
    fn record_appends_and_a_write_failure_never_panics_the_caller() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let recorder = recorder_at(temp.path());
        recorder.record(b"origins: {}\n# one\n", metadata("test"));
        let entries = recorder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].actor.as_deref(), Some("test"));

        // Oversized content is a write failure `record` must swallow
        // rather than propagate; the caller has no `Result` to inspect.
        let oversized = vec![0u8; sbproxy_config::config_bundle::MAX_CONFIG_YAML_BYTES + 1];
        recorder.record(&oversized, metadata("test"));
        assert_eq!(
            recorder.entries().len(),
            1,
            "a failed append must not add a second entry"
        );
    }

    #[test]
    fn a_byte_identical_consecutive_record_is_not_a_second_entry() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let recorder = recorder_at(temp.path());
        recorder.record(b"origins: {}\n# same\n", metadata("first"));
        // A second reload of the exact same document, as a config-watch
        // loop that woke on an unrelated event would produce, must not
        // grow the ring: two consecutive reloads of byte-identical
        // config are one applied revision.
        recorder.record(b"origins: {}\n# same\n", metadata("second"));
        let entries = recorder.entries();
        assert_eq!(
            entries.len(),
            1,
            "byte-identical back-to-back reloads must collapse to one entry"
        );
        assert_eq!(
            entries[0].actor.as_deref(),
            Some("first"),
            "the skipped second record must not overwrite the first entry's metadata"
        );

        // A genuinely different document after the repeat is still
        // recorded normally.
        recorder.record(b"origins: {}\n# different\n", metadata("third"));
        assert_eq!(recorder.entries().len(), 2);
    }

    #[test]
    fn blast_radius_for_is_none_against_an_empty_ring_and_some_after_a_first_entry() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let recorder = recorder_at(temp.path());
        assert_eq!(recorder.blast_radius_for(b"proxy: {}\n"), None);

        recorder.record(b"proxy: {}\n", metadata("test"));
        let radius = recorder.blast_radius_for(b"proxy:\n  http_bind_port: 9999\n");
        assert_eq!(radius, Some(sbproxy_config::BlastRadius::Restart));
    }

    #[test]
    fn recording_applied_revisions_never_moves_the_lkg_pointer() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let recorder = recorder_at(temp.path());
        assert!(recorder.lkg().is_none());

        recorder.record(b"origins: {}\n# one\n", metadata("a"));
        recorder.record(b"origins: {}\n# two\n", metadata("b"));
        recorder.record(b"origins: {}\n# three\n", metadata("c"));
        assert_eq!(recorder.entries().len(), 3);
        assert!(
            recorder.lkg().is_none(),
            "recording three applied revisions must not mint a last-known-good pointer"
        );
    }
}
