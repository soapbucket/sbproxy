// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The process-owned handle onto [`sbproxy_config::RevisionStore`]: the
//! durable, content-addressed ring of every config this process has
//! applied.
//!
//! # Lifecycle
//!
//! [`ConfigHistoryRecorder::from_config`](crate::config_history::ConfigHistoryRecorder::from_config) opens the ring named by
//! `proxy.config_history` once, at boot. [`install_config_history_recorder`](crate::config_history::install_config_history_recorder)
//! publishes it into a process-wide slot as [`ConfigHistoryState::Open`](crate::config_history::ConfigHistoryState::Open);
//! the reload transaction in `crate::server::lifecycle` appends to it
//! through [`current_config_history_recorder`](crate::config_history::current_config_history_recorder), and the admin history
//! routes (`GET /admin/config/history` and its `/{digest}` sibling)
//! read [`current_config_history_state`](crate::config_history::current_config_history_state) directly so they can tell all
//! three states apart. A block that is absent or carries `enabled:
//! false` means `from_config` returns `None`, nothing is ever
//! installed, and the slot stays at its default
//! [`ConfigHistoryState::Disabled`](crate::config_history::ConfigHistoryState::Disabled): recording is opt-in, and an
//! operator who never opted in pays nothing for it. A block that is
//! enabled but whose store fails to open (an unwritable directory, or a
//! ring shape [`sbproxy_config::RevisionStore::open`] refuses to
//! repair) moves the slot to [`ConfigHistoryState::Failed`](crate::config_history::ConfigHistoryState::Failed) instead:
//! the boot itself still succeeds (see [`ConfigHistoryRecorder::from_config`](crate::config_history::ConfigHistoryRecorder::from_config)'s
//! own documentation for why), but the admin routes surface that
//! failure explicitly rather than answering as though the operator
//! never turned the feature on.
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

use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;
use sbproxy_config::{
    AppendMetadata, BaseOrigin, ConfigHistoryConfig, RevisionEntry, RevisionStore,
    RevisionStoreError,
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
    /// naming a digest no entry carries). The caller
    /// (`crate::server::lifecycle`'s boot path) does not fail the boot
    /// over this: it logs the error and marks the process-wide slot
    /// [`ConfigHistoryState::Failed`], so the proxy boots and serves
    /// traffic without a history ring rather than refusing to start
    /// over its own audit trail. The admin history routes surface that
    /// failure explicitly (`503`) instead of answering as though the
    /// feature were never turned on; see `GET /admin/config/history` in
    /// `crate::admin`.
    pub fn from_config(history: Option<&ConfigHistoryConfig>) -> anyhow::Result<Option<Self>> {
        let Some(history) = history else {
            return Ok(None);
        };
        if !history.enabled {
            return Ok(None);
        }
        let store = RevisionStore::open(&history.dir, history.keep, None)
            .map_err(|error| {
                anyhow::anyhow!("open config history store '{}': {error}", history.dir)
            })?
            .with_keep_rejected(history.keep_rejected);
        Self::publish_metrics(&store);
        Ok(Some(Self {
            store: Mutex::new(store),
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
    /// Returns the entry it appended, or `None` when the content was a
    /// byte-identical repeat of the ring's most recent entry or the
    /// write failed. The caller uses it to arm a soak window against the
    /// revision that was actually recorded (WOR-2458); `None` means
    /// there is no new revision to judge.
    pub fn record(&self, content: &[u8], metadata: AppendMetadata) -> Option<RevisionEntry> {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(last) = store.entries().last() {
            if let Ok(previous_bytes) = store.read_blob(&last.digest) {
                if previous_bytes.as_slice() == content {
                    return None;
                }
            }
        }
        let entry = match store.append(content, metadata) {
            Ok(entry) => entry,
            Err(error) => {
                // Counted, not only logged. The caller cannot tell a
                // failed write from a byte-identical repeat through the
                // `None` either returns, and both skip the soak, so a
                // full disk would otherwise stop every promotion on this
                // node with nothing but an ERROR line to say so
                // (WOR-2458 fix round, Minor 21).
                sbproxy_observe::metrics::record_config_rejection("ring_write_failed");
                tracing::error!(
                    error = %error,
                    "config history: failed to record an applied config revision; no soak \
                     window will be armed for it and the last-known-good pointer cannot \
                     advance past it"
                );
                return None;
            }
        };
        Self::publish_metrics(&store);
        Some(entry)
    }

    /// Publish `sbproxy_config_revision_info` and
    /// `sbproxy_config_history_entries` from `store`'s current state.
    ///
    /// Called both at construction, against the freshly opened store
    /// before it moves into `Self::store` (so a restart reports the
    /// truth before the first reload), and after every successful
    /// [`Self::record`]. `sbproxy_config_history_entries` is set
    /// unconditionally; [`sbproxy_observe::metrics::set_config_revision_info`]
    /// only when the ring carries at least one entry, since an empty ring
    /// has no revision to report and no "unset" value stands in for one.
    fn publish_metrics(store: &RevisionStore) {
        let entries = store.entries();
        sbproxy_observe::metrics::set_config_history_entries(
            i64::try_from(entries.len()).unwrap_or(i64::MAX),
        );
        if let Some(last) = entries.last() {
            sbproxy_observe::metrics::set_config_revision_info(
                last.revision,
                &last.digest,
                provenance_label(&last.provenance),
            );
        }
        // Published unconditionally, with `-1` standing in for "this ring
        // has no last-known-good entry yet". A ring whose pointer has
        // never moved is exactly the state an operator asking "can this
        // node roll back?" needs to see, and leaving the series absent
        // would answer that question with silence.
        sbproxy_observe::metrics::set_config_lkg_revision(store.lkg().map_or(-1, |entry| {
            i64::try_from(entry.revision).unwrap_or(i64::MAX)
        }));
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

    /// Blast radius of `content` against this ring's most recent entry,
    /// via [`sbproxy_config::plan()`].
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

    /// Record one refused candidate into the ring's `rejected/`
    /// directory (WOR-2462).
    ///
    /// Logs and swallows a write failure for the same reason
    /// [`Self::record`] does: keeping refused candidates is a diagnostic
    /// aid, and a full disk here must not turn a rejection this node
    /// already survived into a second failure.
    pub fn record_rejection(&self, content: &[u8], metadata: sbproxy_config::RejectionMetadata) {
        let reason = metadata.reason;
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match store.record_rejection(content, metadata) {
            Ok(candidate) => {
                sbproxy_observe::metrics::record_config_rejection(reason.as_str());
                tracing::debug!(
                    digest = %candidate.digest,
                    reason = reason.as_str(),
                    count = candidate.count,
                    "config history: recorded a refused config candidate"
                );
            }
            Err(error) => tracing::error!(
                error = %error,
                reason = reason.as_str(),
                "config history: failed to record a refused config candidate"
            ),
        }
    }

    /// Every stored rejected candidate, oldest refusal first.
    ///
    /// Empty, rather than an error, when the directory cannot be read:
    /// the admin surface that calls this would rather show the applied
    /// history with no rejections than fail the whole response over
    /// them.
    #[must_use]
    pub fn rejections(&self) -> Vec<sbproxy_config::RejectedCandidate> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.rejections().unwrap_or_else(|error| {
            tracing::error!(
                error = %error,
                "config history: failed to read stored rejected candidates"
            );
            Vec::new()
        })
    }

    /// Record one soak verdict against `revision`, moving the
    /// last-known-good pointer if, and only if, the verdict is
    /// [`sbproxy_config::SoakVerdict::Successful`] (WOR-2458).
    ///
    /// The rule itself lives in
    /// [`sbproxy_config::RevisionStore::record_soak_verdict`]; this
    /// forwards to it, publishes the resulting pointer onto
    /// `sbproxy_config_lkg_revision`, and swallows a write failure the
    /// way every other write on this type does.
    pub fn record_soak_verdict(&self, revision: u64, verdict: sbproxy_config::SoakVerdict) {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = store.record_soak_verdict(revision, verdict) {
            tracing::error!(
                error = %error,
                revision,
                "config history: failed to record a soak verdict"
            );
            return;
        }
        if let Some(lkg) = store.lkg() {
            sbproxy_observe::metrics::set_config_lkg_revision(
                i64::try_from(lkg.revision).unwrap_or(i64::MAX),
            );
        }
    }

    /// Clear one entry's boot counter: it booted and served long enough
    /// to count as working (WOR-2459).
    ///
    /// The **only** way a boot counter is cleared in this process.
    /// `RevisionStore` is single-owner and every mutator rewrites the
    /// whole index from the handle's own snapshot, so a second handle
    /// opened on this directory does not merge with this one, it
    /// overwrites it: a timer that cleared the counter through its own
    /// store had that write reverted by the recorder's very next append
    /// (WOR-2459 fix round, Blocker 2). `crate::config_boot`'s
    /// `confirm_boot_success_now` is the caller.
    pub fn confirm_boot_success(&self, revision: u64) {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = store.confirm_boot_success(revision) {
            tracing::error!(
                error = %error,
                revision,
                "config history: failed to clear a boot attempt counter"
            );
        }
    }
}

/// The closed label [`sbproxy_observe::metrics::set_config_revision_info`]
/// carries for `provenance`: `"local"` or `"git"`. Deliberately coarser
/// than [`BaseOrigin`] itself, which carries the repository, reference,
/// and resolved commit for the `Git` variant; those are exactly the
/// unbounded strings a metric label must never carry; the digest and
/// revision already say which document this is.
fn provenance_label(provenance: &BaseOrigin) -> &'static str {
    match provenance {
        BaseOrigin::Local => "local",
        BaseOrigin::Git { .. } => "git",
    }
}

/// Tri-state view of the process-wide config-history slot.
///
/// A plain `Option<Arc<ConfigHistoryRecorder>>` cannot tell an operator
/// who never opted in ([`Self::Disabled`]) apart from one whose
/// `proxy.config_history.enabled: true` node failed to open its own
/// ring at boot ([`Self::Failed`]): both looked identical as `None`
/// before this type existed, so `GET /admin/config/history` answered a
/// boot-time open failure with the exact same `{"error":"config
/// history is not enabled"}` body a node that never turned the feature
/// on gets, silently hiding a real failure behind the opt-in empty
/// state.
#[derive(Clone)]
pub enum ConfigHistoryState {
    /// `proxy.config_history` is absent or `enabled: false`.
    Disabled,
    /// The store opened successfully at boot and is recording.
    Open(Arc<ConfigHistoryRecorder>),
    /// The block is enabled but [`ConfigHistoryRecorder::from_config`]
    /// failed to open the store at boot (an unwritable directory, or a
    /// ring shape [`sbproxy_config::RevisionStore::open`] refuses to
    /// repair). The proxy still boots and serves traffic; this ring's
    /// history is simply unavailable for the life of the process.
    Failed {
        /// The open error's `Display`, bounded to 256 characters so a
        /// pathological error message cannot inflate an admin response
        /// without bound.
        reason: String,
    },
}

/// The process-wide config-history slot.
///
/// Lazily initialized to [`ConfigHistoryState::Disabled`] rather than
/// given a `const` initializer directly: [`ArcSwap::from_pointee`]
/// allocates, so it cannot run at const-eval time the way
/// `ArcSwapOption::const_empty()` (this slot's shape before it needed a
/// third state) could. Mirrors the lazily-initialized `PIPELINE` slot
/// in `crate::reload`.
static PROCESS_CONFIG_HISTORY: OnceLock<ArcSwap<ConfigHistoryState>> = OnceLock::new();

fn process_config_history_slot() -> &'static ArcSwap<ConfigHistoryState> {
    PROCESS_CONFIG_HISTORY.get_or_init(|| ArcSwap::from_pointee(ConfigHistoryState::Disabled))
}

/// Install the process-wide recorder, replacing whatever state (open,
/// failed, or disabled) was there before.
pub fn install_config_history_recorder(recorder: Arc<ConfigHistoryRecorder>) {
    process_config_history_slot().store(Arc::new(ConfigHistoryState::Open(recorder)));
}

/// Mark the process-wide slot [`ConfigHistoryState::Failed`]: the block
/// was enabled, but [`ConfigHistoryRecorder::from_config`] could not
/// open the store. Called once, from `crate::server::lifecycle`'s boot
/// path, when that open fails.
pub fn install_config_history_failure(reason: &str) {
    let bounded: String = reason.chars().take(256).collect();
    process_config_history_slot().store(Arc::new(ConfigHistoryState::Failed { reason: bounded }));
}

/// The process-wide slot's current state: disabled, open, or failed to
/// open at boot. The admin history routes read this directly so they
/// can distinguish all three; [`current_config_history_recorder`]
/// below collapses `Failed` and `Disabled` together for the one caller
/// (the reload transaction) that only ever needs "is there a ring to
/// append to".
#[must_use]
pub fn current_config_history_state() -> Arc<ConfigHistoryState> {
    process_config_history_slot().load_full()
}

/// The process-wide recorder, when the slot is
/// [`ConfigHistoryState::Open`]. `None` for both `Disabled` and
/// `Failed`: the reload transaction that calls this only ever needs to
/// know whether there is a ring to append to, not why there might not
/// be one. See [`current_config_history_state`] for the distinction the
/// admin routes need.
#[must_use]
pub fn current_config_history_recorder() -> Option<Arc<ConfigHistoryRecorder>> {
    match &*current_config_history_state() {
        ConfigHistoryState::Open(recorder) => Some(Arc::clone(recorder)),
        ConfigHistoryState::Disabled | ConfigHistoryState::Failed { .. } => None,
    }
}

/// Record one refused config candidate into the process-wide ring
/// (WOR-2462).
///
/// A no-op when no ring is open, exactly like the applied-revision path:
/// keeping refused candidates is opt-in with the rest of
/// `proxy.config_history`.
///
/// `content` must be the candidate's **pre-resolution** bytes, the same
/// discipline the applied ring keeps. For a config-authority refusal
/// that is the bundle's own document; for a local-file refusal it is the
/// file as read.
pub fn record_rejected_candidate(content: &[u8], metadata: sbproxy_config::RejectionMetadata) {
    let Some(recorder) = current_config_history_recorder() else {
        return;
    };
    recorder.record_rejection(content, metadata);
}

/// Build the metadata for one refusal, stamping it with the host wall
/// clock.
///
/// A helper rather than five call sites repeating the same struct
/// literal, and the one place the `detail` a refusing stage logged is
/// carried into the ring.
#[must_use]
pub fn rejection_metadata(
    reason: sbproxy_config::RejectionReason,
    stage: &str,
    detail: &str,
    provenance: sbproxy_config::BaseOrigin,
) -> sbproxy_config::RejectionMetadata {
    sbproxy_config::RejectionMetadata {
        reason,
        stage: stage.to_string(),
        detail: detail.to_string(),
        provenance,
        rejected_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0),
    }
}

/// Drop the process-wide recorder, resetting the slot to `Disabled`.
/// Used by tests that must not leak state into the next case.
#[cfg(test)]
pub(crate) fn clear_config_history_recorder() {
    process_config_history_slot().store(Arc::new(ConfigHistoryState::Disabled));
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
            ..ConfigHistoryConfig::default()
        };
        let recorder = ConfigHistoryRecorder::from_config(Some(&history))
            .expect("no error")
            .expect("an enabled block opens a recorder");
        assert!(recorder.entries().is_empty());
        // `keep_rejected` reaches the store rather than being parked on
        // the recorder: four refusals against a bound of three leave
        // three files (WOR-2462).
        for index in 0..4u64 {
            recorder.record_rejection(
                format!("a: {index}\n").as_bytes(),
                rejection_metadata(
                    sbproxy_config::RejectionReason::CompileFailed,
                    "file_watcher",
                    "test",
                    BaseOrigin::Local,
                ),
            );
        }
        assert_eq!(
            recorder.rejections().len(),
            3,
            "the configured keep_rejected bounds the directory",
        );
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

    #[test]
    fn the_slot_defaults_to_disabled() {
        clear_config_history_recorder();
        assert!(matches!(
            &*current_config_history_state(),
            ConfigHistoryState::Disabled
        ));
        assert!(current_config_history_recorder().is_none());
    }

    #[test]
    fn a_boot_failure_marks_the_slot_failed_distinctly_from_disabled() {
        clear_config_history_recorder();
        install_config_history_failure("open config history store 'x': permission denied");
        match &*current_config_history_state() {
            ConfigHistoryState::Failed { reason } => {
                assert!(reason.contains("permission denied"));
            }
            other => panic!("expected Failed, not {}", failed_variant_name(other)),
        }
        // The one caller that only needs "is there a ring to append to"
        // must not be able to tell Failed and Disabled apart: both are
        // `None` there. Only `current_config_history_state` carries the
        // distinction the admin routes need.
        assert!(
            current_config_history_recorder().is_none(),
            "a failed-to-open store must not look like an open one to the reload transaction"
        );
        clear_config_history_recorder();
    }

    #[test]
    fn a_failure_reason_is_bounded_to_256_characters() {
        clear_config_history_recorder();
        let huge_reason = "x".repeat(10_000);
        install_config_history_failure(&huge_reason);
        match &*current_config_history_state() {
            ConfigHistoryState::Failed { reason } => {
                assert_eq!(reason.chars().count(), 256);
            }
            other => panic!("expected Failed, not {}", failed_variant_name(other)),
        }
        clear_config_history_recorder();
    }

    fn failed_variant_name(state: &ConfigHistoryState) -> &'static str {
        match state {
            ConfigHistoryState::Disabled => "Disabled",
            ConfigHistoryState::Open(_) => "Open",
            ConfigHistoryState::Failed { .. } => "Failed",
        }
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

    /// Every label of a gathered Prometheus family, as `name=value` pairs
    /// joined by commas, one entry per series, with the series value
    /// appended.
    ///
    /// A local copy of the helper `sbproxy-observe`'s own metric tests
    /// use (`crates/sbproxy-observe/src/metrics.rs`); `prometheus::gather()`
    /// reads the same process-global registry regardless of which crate
    /// registered the family, so the same shape works here.
    fn gathered_series(family_name: &str) -> Vec<(String, f64)> {
        let mut out = Vec::new();
        for family in prometheus::gather() {
            if family.name() != family_name {
                continue;
            }
            for metric in family.get_metric() {
                let labels: Vec<String> = metric
                    .get_label()
                    .iter()
                    .map(|pair| format!("{}={}", pair.name(), pair.value()))
                    .collect();
                let value = match family.get_field_type() {
                    prometheus::proto::MetricType::COUNTER => metric.get_counter().value(),
                    prometheus::proto::MetricType::GAUGE => metric.get_gauge().value(),
                    other => {
                        unreachable!("{family_name} is a {other:?}, not a counter or a gauge")
                    }
                };
                out.push((labels.join(","), value));
            }
        }
        out
    }

    /// `record` must publish the newly recorded entry onto
    /// `sbproxy_config_revision_info`, and a second record with different
    /// provenance must replace that series rather than add a second one:
    /// the reset half of the info-gauge idiom, exercised through the real
    /// hookup rather than the metric function directly.
    #[test]
    fn record_publishes_the_revision_info_gauge_as_a_single_series() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let recorder = recorder_at(temp.path());

        recorder.record(b"origins: {}\n# one\n", metadata("a"));
        let first = recorder.entries().first().cloned().expect("one entry");
        let series = gathered_series("sbproxy_config_revision_info");
        assert_eq!(
            series.len(),
            1,
            "one recorded entry must publish exactly one series: {series:?}"
        );
        assert!(
            series[0]
                .0
                .contains(&format!("revision={}", first.revision))
                && series[0].0.contains(&format!("digest={}", first.digest))
                && series[0].0.contains("provenance=local"),
            "the recorded entry's labels were not published: {series:?}"
        );

        let git_metadata = AppendMetadata {
            provenance: BaseOrigin::Git {
                repo: "https://example.invalid/repo".to_string(),
                reference: "main".to_string(),
                commit: "deadbeef".to_string(),
            },
            blast_radius: None,
            secrets_fingerprint: None,
            actor: Some("b".to_string()),
            applied_at: 2,
            degraded: Vec::new(),
        };
        recorder.record(b"origins: {}\n# two\n", git_metadata);
        let second = recorder.entries().last().cloned().expect("two entries");
        let series = gathered_series("sbproxy_config_revision_info");
        assert_eq!(
            series.len(),
            1,
            "a second record must remove the first entry's series rather than \
             adding a second one: {series:?}"
        );
        assert!(
            series[0]
                .0
                .contains(&format!("revision={}", second.revision))
                && series[0].0.contains(&format!("digest={}", second.digest))
                && series[0].0.contains("provenance=git"),
            "the second record's labels were not published: {series:?}"
        );
    }

    /// `record` must publish the ring's current entry count onto
    /// `sbproxy_config_history_entries` after every successful append,
    /// and leave it alone across a skipped byte-identical repeat.
    #[test]
    fn record_publishes_the_history_entries_gauge_matching_the_ring_count() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let recorder = recorder_at(temp.path());

        recorder.record(b"origins: {}\n# one\n", metadata("a"));
        assert_eq!(
            gathered_series("sbproxy_config_history_entries")
                .last()
                .map(|(_, value)| *value),
            Some(1.0)
        );

        recorder.record(b"origins: {}\n# two\n", metadata("b"));
        assert_eq!(
            gathered_series("sbproxy_config_history_entries")
                .last()
                .map(|(_, value)| *value),
            Some(2.0)
        );

        // A byte-identical repeat is a skipped append and must not move
        // the gauge either.
        recorder.record(b"origins: {}\n# two\n", metadata("c"));
        assert_eq!(
            gathered_series("sbproxy_config_history_entries")
                .last()
                .map(|(_, value)| *value),
            Some(2.0),
            "a skipped byte-identical record must not change the entries gauge"
        );
    }

    /// A restart must report the ring's real state before the first
    /// reload: `from_config` publishes both gauges from the store it just
    /// opened, not only `record` does.
    ///
    /// Both gauges are forced to a value the real ring does not carry
    /// before the reopen, so the assertions below cannot pass on state
    /// left over from the first recorder; only a fresh publish at
    /// construction can correct them.
    #[test]
    fn from_config_publishes_existing_ring_state_at_construction() {
        let temp = tempfile::TempDir::new().expect("tempdir");

        {
            let recorder = recorder_at(temp.path());
            recorder.record(b"origins: {}\n# one\n", metadata("a"));
            recorder.record(b"origins: {}\n# two\n", metadata("b"));
            recorder.record(b"origins: {}\n# three\n", metadata("c"));
        }

        sbproxy_observe::metrics::set_config_history_entries(999);
        sbproxy_observe::metrics::set_config_revision_info(999, "not-a-real-digest", "git");

        let recorder = recorder_at(temp.path());
        let entries = recorder.entries();
        assert_eq!(
            entries.len(),
            3,
            "the reopened ring must see the prior process's entries"
        );
        let last = entries.last().expect("three entries were recorded");

        assert_eq!(
            gathered_series("sbproxy_config_history_entries")
                .last()
                .map(|(_, value)| *value),
            Some(3.0),
            "construction must publish the ring's real entry count, not the forced value"
        );
        let series = gathered_series("sbproxy_config_revision_info");
        assert_eq!(series.len(), 1, "{series:?}");
        assert!(
            series[0].0.contains(&format!("revision={}", last.revision))
                && series[0].0.contains(&format!("digest={}", last.digest))
                && series[0].0.contains("provenance=local"),
            "construction must publish the ring's real last entry, not the forced \
             fixture: {series:?}"
        );
    }
}
