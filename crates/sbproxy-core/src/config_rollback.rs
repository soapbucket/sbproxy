// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Re-applying a config revision this node already stored: the manual
//! rollback (WOR-2460) and the automatic revert a failed soak arms
//! (WOR-2461).
//!
//! # One engine, two triggers
//!
//! Both triggers reach [`rollback`], and the only difference between
//! them is the [`RollbackTrigger`] they carry. That is deliberate: the
//! automatic path must not be able to do anything the operator-driven
//! path cannot, because the automatic path is the one that acts without
//! anybody watching. Everything below applies to both.
//!
//! # A rollback is an ordinary candidate
//!
//! It resolves, it compiles, it publishes through the same reload
//! transaction, and **it soaks**. Rolling back into a second bad config
//! is a real thing that happens under pressure, and treating rollback as
//! a privileged path that skips validation is how it becomes the
//! incident. The publisher side already took this position:
//! `AuthorityStore::rollback` revalidates the payload on the way through
//! rather than trusting that it published once, because a payload that
//! published cleanly before an upgrade need not still construct after
//! one.
//!
//! Argo Rollouts goes the other way and it is worth saying why we do
//! not. Its rollback window lets a promotion back to a recently running
//! ReplicaSet skip every analysis step, on the reasoning that the thing
//! being rolled back to was running minutes ago. That reasoning holds
//! for a container image and does not hold here: this ring keeps
//! revisions for weeks, the environment around a config moves
//! underneath it (an upstream that has since been decommissioned, a
//! credential that has since rotated), and a rollback target from
//! October is not evidence about now.
//!
//! # History stays append-only
//!
//! A successful rollback appends a **new** entry carrying the restored
//! document rather than rewinding the ring, so a rollback is itself
//! visible in history and a second rollback can undo it. The entry that
//! was rolled away from is annotated
//! [`sbproxy_config::RevisionState::Reverted`] and otherwise left alone.
//!
//! # What this deliberately does not do
//!
//! It does not write the node's config **file**. The ring stores what
//! this node applied, and on an authority-owned or git-sourced node the
//! local file is a pointer rather than the document. Rewriting it would
//! break the relationship the operator configured. The consequence is
//! stated in every response
//! ([`RollbackOutcome::config_file_unchanged`]) rather than left for an
//! operator to discover: the next filesystem event, SIGHUP, `source:`
//! poll, or authority bundle re-applies whatever the source of truth
//! still says, so fixing the source of truth is the second half of the
//! recovery.
//!
//! # Optimistic concurrency
//!
//! [`RollbackRequest::expected_current`] is the HAProxy Data Plane API's
//! discipline: it stamps a version onto the configuration and requires
//! every mutating call to carry the version it expects, erroring on a
//! mismatch rather than taking last-writer-wins. Two operators reaching
//! for rollback during the same incident is not hypothetical, and
//! without this the second one silently undoes the first. Absent is
//! accepted, so an existing caller keeps working.

use sbproxy_config::{BlastRadius, RevisionEntry};

/// Which stored revision to restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RollbackTarget {
    /// Whatever the ring's `lkg` pointer names: the newest revision a
    /// soak window actually promoted. The default, and the only target
    /// the automatic revert ever uses.
    LastKnownGood,
    /// A specific ring revision number, as `sbproxy config history`
    /// prints it.
    Revision(u64),
    /// A specific content digest. Distinct from a revision number
    /// because the same document can be applied twice under two
    /// revisions, and an operator who copied a digest out of a
    /// deployment record means the content.
    Digest(String),
}

impl RollbackTarget {
    /// How this target names itself in a response and a log line.
    fn describe(&self) -> String {
        match self {
            Self::LastKnownGood => "last-known-good".to_string(),
            Self::Revision(revision) => format!("revision {revision}"),
            Self::Digest(digest) => format!("digest {digest}"),
        }
    }
}

/// Who asked for this rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RollbackTrigger {
    /// An operator, through `POST /admin/config/rollback` or the CLI.
    Manual,
    /// The node itself, after a soak failed with
    /// `proxy.config_history.soak.auto_revert` armed.
    AutoRevert,
}

impl RollbackTrigger {
    /// Stable label for the event payload and the log line.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::AutoRevert => "auto_revert",
        }
    }

    /// The `sbproxy_config_apply_total{outcome}` label a success on this
    /// trigger counts under.
    ///
    /// Disjoint by construction, so "did anything roll this fleet back
    /// without an operator" is one query rather than a subtraction.
    const fn success_outcome(self) -> &'static str {
        match self {
            Self::Manual => "applied",
            Self::AutoRevert => "reverted",
        }
    }
}

/// One rollback ask.
#[derive(Debug, Clone)]
pub(crate) struct RollbackRequest {
    /// Which revision to restore.
    pub(crate) target: RollbackTarget,
    /// The revision the caller believes is running. Refused on a
    /// mismatch; absent proceeds.
    pub(crate) expected_current: Option<u64>,
    /// The ring lineage the caller believes it is talking to. A
    /// `source:` repoint preserves lineage and is an ordinary rollback;
    /// a node-identity change re-mints it, and a revision number copied
    /// from before that change names a different node's history.
    pub(crate) expected_lineage: Option<String>,
    /// The revision number the caller typed back to confirm a
    /// restart-class or breaking rollback. Ignored for a `Hitless` or
    /// `Reload` diff.
    pub(crate) confirm_revision: Option<u64>,
    /// Proceed across a lineage break anyway.
    pub(crate) force: bool,
    /// The operator's identity, when an HTTP layer has one.
    pub(crate) actor: Option<String>,
    /// Which trigger this is.
    pub(crate) trigger: RollbackTrigger,
}

impl RollbackRequest {
    /// A manual rollback to the last known good, with nothing else set.
    #[cfg(test)]
    pub(crate) fn to_last_known_good() -> Self {
        Self {
            target: RollbackTarget::LastKnownGood,
            expected_current: None,
            expected_lineage: None,
            confirm_revision: None,
            force: false,
            actor: None,
            trigger: RollbackTrigger::Manual,
        }
    }

    /// The `actor` string the appended ring entry carries.
    ///
    /// `rollback:<operator>` keeps the history column specific without
    /// widening the closed `config_audit` source vocabulary, which stays
    /// the flat `rollback`.
    fn ring_actor(&self) -> String {
        match (self.trigger, self.actor.as_deref()) {
            (RollbackTrigger::AutoRevert, _) => "auto_revert".to_string(),
            (RollbackTrigger::Manual, Some(actor)) if !actor.is_empty() => {
                format!("rollback:{actor}")
            }
            (RollbackTrigger::Manual, _) => "rollback".to_string(),
        }
    }
}

/// Why a rollback did not happen.
///
/// Every variant is a refusal **before** anything was applied except
/// [`Self::ApplyFailed`], which is a refusal by the reload transaction
/// itself and therefore also leaves the running pipeline untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RollbackRefusal {
    /// `proxy.config_history` is off or its store did not open, so there
    /// is no ring to roll back into.
    HistoryUnavailable,
    /// The ring holds no revision a soak has promoted yet, so
    /// `last-known-good` names nothing.
    NoLastKnownGood,
    /// No live entry holds the named revision. Carries what is
    /// available, because "404" without the alternatives sends an
    /// operator back to a second call mid-incident.
    UnknownRevision {
        /// What was asked for.
        requested: u64,
        /// Every revision currently in the ring, oldest first.
        available: Vec<u64>,
    },
    /// No live entry holds the named digest.
    UnknownDigest {
        /// What was asked for.
        requested: String,
        /// Every digest currently in the ring, oldest first.
        available: Vec<String>,
    },
    /// The caller's `expected_current` is not what is running: somebody
    /// else moved this node between the read and the write.
    StaleExpectedCurrent {
        /// What the caller expected to be running.
        expected: u64,
        /// What is actually running.
        actual: u64,
    },
    /// The caller named a lineage this ring is not. Both are named
    /// because a revision number means nothing without one.
    LineageMismatch {
        /// The lineage the caller expected.
        expected: String,
        /// This ring's lineage.
        actual: String,
    },
    /// The diff between what is running and the target is `Restart` or
    /// `Breaking`, and the caller did not confirm it by naming the
    /// revision back.
    RestartNotConfirmed {
        /// The revision that needed confirming.
        revision: u64,
        /// The radius that made it need confirming.
        radius: BlastRadius,
    },
    /// The stored blob could not be read back.
    ReadFailed(String),
    /// The stored document no longer applies on this binary. The
    /// running pipeline keeps serving.
    ApplyFailed(String),
    /// This process has no config path wired, which is the unit-test
    /// shape rather than a served one.
    NoConfigPath,
}

impl RollbackRefusal {
    /// A stable, bounded reason label for the log line and the event.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::HistoryUnavailable => "history_unavailable",
            Self::NoLastKnownGood => "no_last_known_good",
            Self::UnknownRevision { .. } => "unknown_revision",
            Self::UnknownDigest { .. } => "unknown_digest",
            Self::StaleExpectedCurrent { .. } => "stale_expected_current",
            Self::LineageMismatch { .. } => "lineage_mismatch",
            Self::RestartNotConfirmed { .. } => "restart_not_confirmed",
            Self::ReadFailed(_) => "read_failed",
            Self::ApplyFailed(_) => "apply_failed",
            Self::NoConfigPath => "no_config_path",
        }
    }

    /// The HTTP status `POST /admin/config/rollback` answers with.
    ///
    /// `404` only for a target that is genuinely not there, which is the
    /// acceptance line's "clear 404 naming what is available, not a
    /// 500". `409` for every precondition the caller can fix by reading
    /// the current state and asking again, which is what a conflict is.
    pub(crate) const fn http_status(&self) -> u16 {
        match self {
            Self::HistoryUnavailable => 404,
            Self::NoLastKnownGood | Self::UnknownRevision { .. } | Self::UnknownDigest { .. } => {
                404
            }
            Self::StaleExpectedCurrent { .. }
            | Self::LineageMismatch { .. }
            | Self::RestartNotConfirmed { .. } => 409,
            // The target existed and the document is what is wrong, so
            // this is the caller's request meeting a broken artifact
            // rather than a server fault. `422` says exactly that, and
            // keeps a rollback refusal out of the 5xx alerts a node's
            // own health is graphed on.
            Self::ApplyFailed(_) => 422,
            Self::ReadFailed(_) | Self::NoConfigPath => 500,
        }
    }
}

impl std::fmt::Display for RollbackRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HistoryUnavailable => write!(
                formatter,
                "config history is not enabled on this node, so there is no revision ring to \
                 roll back into"
            ),
            Self::NoLastKnownGood => write!(
                formatter,
                "no config revision has been promoted to last known good on this node yet, so \
                 there is no last-known-good target. name a revision from \
                 GET /admin/config/history instead, or wait for a soak window to close passing"
            ),
            Self::UnknownRevision {
                requested,
                available,
            } => write!(
                formatter,
                "revision {requested} is not in this node's config revision ring. available: {}",
                render_available(available)
            ),
            Self::UnknownDigest {
                requested,
                available,
            } => write!(
                formatter,
                "digest {requested} is not in this node's config revision ring. available: {}",
                render_available(available)
            ),
            Self::StaleExpectedCurrent { expected, actual } => write!(
                formatter,
                "expected_current names revision {expected} but this node is running revision \
                 {actual}; another operator moved it. re-read GET /admin/config/history and \
                 decide again rather than overwriting their change"
            ),
            Self::LineageMismatch { expected, actual } => write!(
                formatter,
                "this ring's lineage is {actual} and the request names {expected}; a revision \
                 number from one lineage does not mean the same document in another. pass \
                 force to roll back anyway"
            ),
            Self::RestartNotConfirmed { revision, radius } => write!(
                formatter,
                "rolling back to revision {revision} is a {} change, which an in-process swap \
                 cannot fully apply; confirm it by naming the revision back in \
                 confirm_revision, and plan to restart this node",
                blast_radius_label(*radius)
            ),
            Self::ReadFailed(detail) => {
                write!(formatter, "read the stored revision: {detail}")
            }
            Self::ApplyFailed(detail) => write!(
                formatter,
                "the stored revision no longer applies on this build and was refused; the \
                 running configuration is untouched: {detail}"
            ),
            Self::NoConfigPath => write!(
                formatter,
                "no config path is wired on this node, so a reload cannot be driven"
            ),
        }
    }
}

/// Render an availability list without letting a large ring produce an
/// unbounded error string.
fn render_available<T: std::fmt::Display>(available: &[T]) -> String {
    /// How many entries an availability list names before it stops.
    const LIMIT: usize = 20;
    if available.is_empty() {
        return "the ring is empty".to_string();
    }
    let shown: Vec<String> = available
        .iter()
        .take(LIMIT)
        .map(std::string::ToString::to_string)
        .collect();
    if available.len() > LIMIT {
        format!(
            "{} (and {} more)",
            shown.join(", "),
            available.len() - LIMIT
        )
    } else {
        shown.join(", ")
    }
}

/// The stable lowercase label for one blast radius, matching the one
/// `GET /admin/config/history` already renders.
pub(crate) const fn blast_radius_label(radius: BlastRadius) -> &'static str {
    match radius {
        BlastRadius::Hitless => "hitless",
        BlastRadius::Reload => "reload",
        BlastRadius::Restart => "restart",
        BlastRadius::Breaking => "breaking",
    }
}

/// Whether an in-process arc-swap can undo a diff of this radius
/// (WOR-2461).
///
/// # The arming rule, and the overlap that was measured rather than assumed
///
/// `Hitless` and `Reload` diffs are undone by publishing the previous
/// pipeline: that is what the reload transaction does, and it is why
/// those two radii are the whole of what auto-revert arms for. A
/// `Restart` or `Breaking` diff is not, and half-reverting one would
/// leave the process in a state neither config describes: the listener
/// still bound to the port the failing config asked for, the admin
/// server still holding credentials from the config that was rolled
/// away from, an origin's clients still holding connections whose auth
/// type just changed underneath them.
///
/// WOR-2461 asks for the overlap with `ClusterRestartFingerprint` to be
/// measured rather than assumed, because a `Restart` diff that the
/// reload path already refuses outright never reaches a soak and so is
/// not part of this decision at all. Measured against
/// `sbproxy_config::BLAST_RADIUS_MATRIX` at 67 rules:
///
/// * **24 rules** classify `Restart` or `Breaking`.
/// * **2 of those 24** are covered by the fingerprint:
///   `proxy.cluster` and `proxy.cluster.**`.
///   `crate::cluster::reconcile_process_cluster` runs inside
///   `reload_compiled_config_locked` and returns `Err` naming the
///   changed fields, so such a document never publishes, never reaches
///   the ring, and never arms a soak. Three further keys are refused the
///   same way by `reconcile_boot_only_blocks`
///   (`proxy.agent_registry`, `proxy.notifications`, `request_events`),
///   and none of those three is in the matrix's restart set either, so
///   they subtract nothing from the 24.
/// * **22 rules remain**, and they are the whole of what this predicate
///   is for: the five listener-bind keys
///   (`proxy.http_bind_port`, `proxy.https_bind_port`,
///   `proxy.http2_cleartext`, `proxy.http3`, `proxy.http3.**`), the four
///   `proxy.admin` keys, `proxy.config_authority` and its subtree,
///   `proxy.compression_state` and its subtree, the three storage-driver
///   keys, `proxy.config_history` and its subtree, `agent_classes` and
///   its subtree, and the two `Breaking` origin rules
///   (`origins.*.authentication.type`, `origins.*.action.type`).
///
/// So the fingerprint covers 2 of 24 and the arming gate is load
/// bearing for the other 22. Re-measure this list rather than trusting
/// it if `BLAST_RADIUS_MATRIX` grows a restart-class rule.
pub(crate) const fn arc_swap_can_undo(radius: BlastRadius) -> bool {
    match radius {
        BlastRadius::Hitless | BlastRadius::Reload => true,
        BlastRadius::Restart | BlastRadius::Breaking => false,
    }
}

/// What a successful rollback did.
#[derive(Debug, Clone)]
pub(crate) struct RollbackOutcome {
    /// The ring revision whose document is now serving.
    pub(crate) restored_revision: u64,
    /// That revision's content digest.
    pub(crate) restored_digest: String,
    /// The revision that was running before, when the ring had one.
    pub(crate) previous_revision: Option<u64>,
    /// The diff's blast radius, when both documents parsed.
    pub(crate) blast_radius: Option<BlastRadius>,
    /// The new ring entry this rollback appended, when one was
    /// appended. `None` when the restored document is byte identical to
    /// what was already running, which the ring deduplicates.
    pub(crate) appended_revision: Option<u64>,
    /// Subsystems that stayed on prior state through this apply.
    pub(crate) degraded: Vec<String>,
    /// Whether the restored revision's secrets fingerprint differs from
    /// the one that was running. A warning rather than a refusal: the
    /// secret backends moved since this document applied, so a
    /// `vault://` reference in it may resolve to something else now.
    pub(crate) secrets_fingerprint_changed: bool,
    /// Always `true`, and returned rather than assumed. See the module
    /// documentation: this applies a document, it does not rewrite the
    /// node's config file, so the source of truth still needs fixing.
    pub(crate) config_file_unchanged: bool,
}

/// Restore a stored config revision (WOR-2460, WOR-2461).
///
/// The order of the checks is the contract, not an implementation
/// detail. Cheapest and most-informative first: a caller who is talking
/// to the wrong node's history (`LineageMismatch`) is told that before
/// being told their revision number is unknown, because in that case the
/// revision number is not the problem. `expected_current` is checked
/// before the blob is read, so a losing writer in a two-operator
/// incident costs no I/O. The blast-radius confirmation is checked last
/// of the preconditions, because it needs both documents in hand.
///
/// # Errors
///
/// Returns [`RollbackRefusal`], which
/// [`RollbackRefusal::http_status`] maps onto the admin route's status.
/// Every refusal leaves the running pipeline exactly as it was.
pub(crate) fn rollback(
    config_path: Option<&str>,
    request: &RollbackRequest,
) -> Result<RollbackOutcome, RollbackRefusal> {
    let outcome = rollback_inner(config_path, request);
    match &outcome {
        Ok(applied) => {
            sbproxy_observe::metrics::record_config_apply(request.trigger.success_outcome());
            publish_rollback_event(request, Ok(applied));
        }
        Err(refusal) => {
            sbproxy_observe::metrics::record_config_apply("rejected");
            publish_rollback_event(request, Err(refusal));
        }
    }
    outcome
}

/// The decision body, without the metric and the event.
///
/// Split so every early return is counted and published exactly once,
/// at one place, rather than at each of the nine refusal sites.
fn rollback_inner(
    config_path: Option<&str>,
    request: &RollbackRequest,
) -> Result<RollbackOutcome, RollbackRefusal> {
    let Some(recorder) = crate::config_history::current_config_history_recorder() else {
        return Err(RollbackRefusal::HistoryUnavailable);
    };

    if let Some(expected) = request.expected_lineage.as_deref() {
        let actual = recorder.lineage();
        if expected != actual && !request.force {
            return Err(RollbackRefusal::LineageMismatch {
                expected: expected.to_string(),
                actual,
            });
        }
    }

    let entries = recorder.entries();
    // The newest entry is what is serving: the reload transaction
    // appends exactly once per applied document, so the last row is the
    // last apply. `blast_radius_for` already reads it the same way.
    let running = entries.last().cloned();
    if let (Some(expected), Some(running)) = (request.expected_current, running.as_ref()) {
        if expected != running.revision {
            return Err(RollbackRefusal::StaleExpectedCurrent {
                expected,
                actual: running.revision,
            });
        }
    }

    let target = resolve_target(&recorder, &entries, &request.target)?;
    let document = match recorder.read_blob(&target.digest) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => return Err(RollbackRefusal::ReadFailed(error.to_string())),
    };

    // Computed from the two stored documents rather than from the live
    // file: the ring's own entries are what both triggers have, the
    // auto-revert path has no admin state to read a file through, and
    // this is the same pair `ConfigHistoryRecorder::blast_radius_for`
    // diffs when it stamps a radius onto an entry, so the number here
    // and the number in the history listing are computed the same way.
    let blast_radius = running
        .as_ref()
        .and_then(|running| recorder.read_blob(&running.digest).ok())
        .and_then(|bytes| plan_radius(&String::from_utf8_lossy(&bytes), &document));
    if let Some(radius) = blast_radius {
        if !arc_swap_can_undo(radius) && request.confirm_revision != Some(target.revision) {
            return Err(RollbackRefusal::RestartNotConfirmed {
                revision: target.revision,
                radius,
            });
        }
    }

    // Checked last of the preconditions, and deliberately: every gate
    // above answers a question about the *request*, and an operator who
    // named a revision that is not in the ring is better served by
    // hearing that than by hearing about this process's own wiring. This
    // one is only in the way at the moment something is about to apply.
    let Some(config_path) = config_path else {
        return Err(RollbackRefusal::NoConfigPath);
    };
    let ring_actor = request.ring_actor();
    let applied =
        match crate::server::reload_from_stored_revision(config_path, &document, &ring_actor) {
            Ok(applied) => applied,
            Err(error) => {
                return Err(RollbackRefusal::ApplyFailed(
                    crate::path_redact::sanitise_path_in_error(
                        &format!("{error:#}"),
                        std::path::Path::new(config_path),
                    ),
                ))
            }
        };

    // Read back after the apply: the transaction appended the new entry
    // itself, through the one recording site every reload path shares,
    // so this is a read of what happened rather than a second write.
    let appended = recorder
        .entries()
        .last()
        .filter(|entry| {
            running
                .as_ref()
                .is_none_or(|before| entry.revision != before.revision)
        })
        .map(|entry| entry.revision);
    if let Some(before) = running.as_ref() {
        recorder.mark_reverted(before.revision);
    }

    let secrets_fingerprint_changed = match (
        target.secrets_fingerprint.as_deref(),
        running
            .as_ref()
            .and_then(|entry| entry.secrets_fingerprint.as_deref()),
    ) {
        (Some(restored), Some(current)) => restored != current,
        // One side unknown is not a difference anyone can act on, and
        // warning on it would fire on every node that predates the
        // fingerprint being recorded.
        _ => false,
    };

    tracing::warn!(
        trigger = request.trigger.as_str(),
        actor = %ring_actor,
        restored_revision = target.revision,
        digest = %target.digest,
        previous_revision = running.as_ref().map(|entry| entry.revision),
        appended_revision = appended,
        blast_radius = blast_radius.map(blast_radius_label),
        "this node rolled back to a stored config revision. the revision it rolled away from \
         is marked reverted, the restored document was appended as a new ring entry, and it \
         soaks like any other candidate. the node's config file is unchanged, so fix the \
         source of truth before the next reload trigger re-applies it",
    );

    Ok(RollbackOutcome {
        restored_revision: target.revision,
        restored_digest: target.digest.clone(),
        previous_revision: running.as_ref().map(|entry| entry.revision),
        blast_radius,
        appended_revision: appended,
        degraded: applied
            .degraded()
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        secrets_fingerprint_changed,
        config_file_unchanged: true,
    })
}

/// What the auto-revert arming decision concluded (WOR-2461).
///
/// Every variant except [`Self::Reverted`] means the running
/// configuration was not touched.
#[derive(Debug, Clone)]
pub(crate) enum AutoRevertDecision {
    /// `soak.auto_revert` is off, which is the default. The soak still
    /// ran, the verdict is still recorded, the metric still moved, and
    /// nothing about what is serving changed.
    Disarmed,
    /// The failing diff was `Restart` or `Breaking`, so an arc-swap
    /// cannot undo it. Boot fallback and manual rollback are the answer.
    NotArcSwappable(BlastRadius),
    /// The failing revision carries no blast radius: it is the ring's
    /// first entry, or one of the two documents did not parse when the
    /// radius was computed. Treated as "not known to be undoable",
    /// because the one slice that acts without an operator does not get
    /// to guess.
    RadiusUnknown,
    /// This is the revision a previous auto-revert restored, and it has
    /// now failed its own soak. Reverting again would revert to itself.
    /// Escalated instead.
    WouldLoop,
    /// The ring's last known good is what is already running, so there
    /// is nothing to revert to.
    AlreadyOnLastKnownGood,
    /// The revert ran and the node is serving the last known good.
    Reverted(Box<RollbackOutcome>),
    /// The revert was attempted and refused. The running pipeline keeps
    /// serving; nothing is retried.
    Refused(RollbackRefusal),
}

/// The digest the most recent auto-revert restored, if any.
///
/// The whole of the no-loop rule, and it is deliberately a digest rather
/// than a revision number: a rollback appends a **new** ring entry with
/// a new number carrying the old content, so the number changes on every
/// revert and the content does not. Comparing numbers would let the
/// cycle "r5 fails, revert to r3's content as r6, r6 fails, revert to
/// r3's content as r7" run forever.
static LAST_AUTO_REVERT_DIGEST: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
    std::sync::OnceLock::new();

fn last_auto_revert_digest() -> &'static std::sync::Mutex<Option<String>> {
    LAST_AUTO_REVERT_DIGEST.get_or_init(|| std::sync::Mutex::new(None))
}

/// Forget the last auto-revert target. Tests only: the slot is process
/// global, so one test's revert would otherwise decide the next test's
/// loop question.
#[cfg(test)]
pub(crate) fn clear_auto_revert_memory() {
    *last_auto_revert_digest()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// Decide whether a failed soak re-applies the last known good, and do
/// it when the answer is yes (WOR-2461).
///
/// Blocking: it drives the reload transaction. The soak supervisor is an
/// async task, so it calls this inside `spawn_blocking`; the
/// `POST /admin/config/confirm` handler is already on a blocking thread
/// and calls it directly.
///
/// # The four gates, in order
///
/// 1. **Armed at all.** `soak.auto_revert` is off by default and most
///    nodes should leave it off; see
///    [`sbproxy_config::ConfigSoakConfig::auto_revert`].
/// 2. **Undoable by an arc-swap.** [`arc_swap_can_undo`] carries the
///    rule and the measured overlap with `ClusterRestartFingerprint`.
/// 3. **Not a loop.** A revision an earlier auto-revert restored, now
///    failing its own soak, does not revert again. The node has now
///    demonstrated that both its new config and its last known good fail
///    the same signals, which is an operator's problem and not something
///    a second swap fixes.
/// 4. **Somewhere to go.** The last known good being what is already
///    running is not an error, it is a no-op said out loud.
pub(crate) fn auto_revert_after_failed_soak(
    config_path: Option<&str>,
    failed_revision: u64,
    failed_digest: &str,
    armed: bool,
) -> AutoRevertDecision {
    if !armed {
        tracing::info!(
            revision = failed_revision,
            "a config revision failed its soak and proxy.config_history.soak.auto_revert is \
             off, so nothing about what is serving changed. the last-known-good pointer did \
             not move and this node is still running the revision that failed. roll back with \
             POST /admin/config/rollback when you have decided to",
        );
        return AutoRevertDecision::Disarmed;
    }

    let Some(recorder) = crate::config_history::current_config_history_recorder() else {
        return AutoRevertDecision::Refused(RollbackRefusal::HistoryUnavailable);
    };

    {
        let seen = last_auto_revert_digest()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.as_deref() == Some(failed_digest) {
            tracing::error!(
                revision = failed_revision,
                digest = %failed_digest,
                "the config revision this node auto-reverted to has now failed its own soak. \
                 escalating rather than reverting again: a second swap would restore the same \
                 document under a new revision number and fail the same way. both this node's \
                 new configuration and its last known good are failing the same signals, which \
                 needs an operator",
            );
            return AutoRevertDecision::WouldLoop;
        }
    }

    let radius = recorder
        .entries()
        .iter()
        .find(|entry| entry.revision == failed_revision)
        .and_then(|entry| entry.blast_radius);
    match radius {
        None => {
            tracing::warn!(
                revision = failed_revision,
                "a config revision failed its soak with auto_revert armed, but this node has \
                 no blast radius recorded for it (the ring's first entry, or a document that \
                 did not parse when the radius was computed). not reverting: an in-process \
                 swap can only undo a change it knows is hitless or reload class. use \
                 POST /admin/config/rollback",
            );
            return AutoRevertDecision::RadiusUnknown;
        }
        Some(radius) if !arc_swap_can_undo(radius) => {
            tracing::warn!(
                revision = failed_revision,
                blast_radius = blast_radius_label(radius),
                "a config revision failed its soak with auto_revert armed, and its change is \
                 not one an in-process swap can undo. not reverting: swapping the pipeline \
                 pointer back would leave listeners, the admin server, or client connections \
                 in a state neither configuration describes. boot fallback and \
                 POST /admin/config/rollback are the answer for this class",
            );
            return AutoRevertDecision::NotArcSwappable(radius);
        }
        Some(_) => {}
    }

    let Some(lkg) = recorder.lkg() else {
        tracing::warn!(
            revision = failed_revision,
            "a config revision failed its soak with auto_revert armed, but no revision has \
             ever been promoted to last known good on this node, so there is nothing to \
             revert to",
        );
        return AutoRevertDecision::Refused(RollbackRefusal::NoLastKnownGood);
    };
    if lkg.digest == failed_digest {
        tracing::warn!(
            revision = failed_revision,
            "a config revision failed its soak with auto_revert armed, and this node's last \
             known good is the same document, so there is nothing to revert to",
        );
        return AutoRevertDecision::AlreadyOnLastKnownGood;
    }

    // Deliberately no `confirm_revision`: the stored-radius gate above
    // is the arming decision, and the engine's own restart gate is the
    // backstop. Handing it a confirmation here would disable that
    // backstop for the one caller that has nobody watching.
    let request = RollbackRequest {
        target: RollbackTarget::LastKnownGood,
        expected_current: None,
        expected_lineage: None,
        confirm_revision: None,
        force: false,
        actor: None,
        trigger: RollbackTrigger::AutoRevert,
    };
    match rollback(config_path, &request) {
        Ok(outcome) => {
            *last_auto_revert_digest()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(outcome.restored_digest.clone());
            AutoRevertDecision::Reverted(Box::new(outcome))
        }
        Err(refusal) => {
            tracing::error!(
                revision = failed_revision,
                reason = refusal.as_str(),
                detail = %refusal,
                "an automatic revert was refused. the running configuration is untouched and \
                 this node is still serving the revision that failed its soak. nothing is \
                 retried: a revert that cannot apply once will not apply on a timer, and \
                 looping on it would turn one bad config into a reload storm. this needs an \
                 operator",
            );
            AutoRevertDecision::Refused(refusal)
        }
    }
}

/// Resolve a [`RollbackTarget`] to the ring entry it names.
fn resolve_target(
    recorder: &crate::config_history::ConfigHistoryRecorder,
    entries: &[RevisionEntry],
    target: &RollbackTarget,
) -> Result<RevisionEntry, RollbackRefusal> {
    match target {
        RollbackTarget::LastKnownGood => recorder.lkg().ok_or(RollbackRefusal::NoLastKnownGood),
        RollbackTarget::Revision(revision) => entries
            .iter()
            .find(|entry| entry.revision == *revision)
            .cloned()
            .ok_or_else(|| RollbackRefusal::UnknownRevision {
                requested: *revision,
                available: entries.iter().map(|entry| entry.revision).collect(),
            }),
        RollbackTarget::Digest(digest) => entries
            .iter()
            .find(|entry| entry.digest == *digest)
            .cloned()
            .ok_or_else(|| RollbackRefusal::UnknownDigest {
                requested: digest.clone(),
                available: entries.iter().map(|entry| entry.digest.clone()).collect(),
            }),
    }
}

/// The largest blast radius between two stored documents, or `None`
/// when either fails to parse.
///
/// A parse failure is `None` rather than an error: an unparseable stored
/// document is refused a few lines later by the reload transaction with
/// a message that names the actual problem, and turning it into "the
/// blast radius is unknown" here would refuse it with the wrong reason.
pub(crate) fn plan_radius(baseline: &str, proposed: &str) -> Option<BlastRadius> {
    let baseline = serde_yaml::from_str::<sbproxy_config::ConfigFile>(baseline).ok()?;
    let proposed = serde_yaml::from_str::<sbproxy_config::ConfigFile>(proposed).ok()?;
    Some(sbproxy_config::plan(&baseline, &proposed).max_blast_radius)
}

/// Publish one `config_rollback` decision event.
///
/// "Who rolled the gateway back and to what" is an audit question, which
/// is why both outcomes publish rather than only the successful one: a
/// refused rollback during an incident is exactly as interesting as an
/// accepted one, and a feed that carries only successes cannot answer
/// "did anyone try".
fn publish_rollback_event(
    request: &RollbackRequest,
    outcome: Result<&RollbackOutcome, &RollbackRefusal>,
) {
    sbproxy_observe::publish_proxy_event(sbproxy_observe::EventType::ConfigRollback, || {
        rollback_event(request, outcome)
    });
}

/// Build the `config_rollback` event payload.
///
/// Split from [`publish_rollback_event`] so the payload's shape is
/// testable without installing a process-wide sink, which is set-once
/// and so cannot be staged per test. Bounded metadata only: revision
/// numbers, digests, closed labels, and the refusal's stable reason
/// string. Never a config value, and never the refusal's free text,
/// which can quote the offending YAML.
pub(crate) fn rollback_event(
    request: &RollbackRequest,
    outcome: Result<&RollbackOutcome, &RollbackRefusal>,
) -> sbproxy_observe::ProxyEvent {
    let data = match outcome {
        Ok(applied) => serde_json::json!({
            "trigger": request.trigger.as_str(),
            "actor": request.actor.clone().unwrap_or_default(),
            "target": request.target.describe(),
            "outcome": "applied",
            "restored_revision": applied.restored_revision,
            "restored_digest": applied.restored_digest,
            "previous_revision": applied.previous_revision,
            "appended_revision": applied.appended_revision,
            "blast_radius": applied.blast_radius.map(blast_radius_label),
            "degraded": applied.degraded,
            "secrets_fingerprint_changed": applied.secrets_fingerprint_changed,
        }),
        Err(refusal) => serde_json::json!({
            "trigger": request.trigger.as_str(),
            "actor": request.actor.clone().unwrap_or_default(),
            "target": request.target.describe(),
            "outcome": "rejected",
            "reason": refusal.as_str(),
        }),
    };
    sbproxy_observe::ProxyEvent::new(
        sbproxy_observe::EventType::ConfigRollback,
        String::new(),
        String::new(),
        data,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::{AppendMetadata, BaseOrigin, RevisionState, SoakVerdict};

    /// A ring directory with a recorder installed as this process's.
    ///
    /// Returned rather than dropped so the caller can read entries back;
    /// the `TempDir` has to outlive it or the ring vanishes underneath.
    fn install_ring(
        dir: &std::path::Path,
    ) -> std::sync::Arc<crate::config_history::ConfigHistoryRecorder> {
        let history = sbproxy_config::ConfigHistoryConfig {
            enabled: true,
            dir: dir.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let recorder = crate::config_history::ConfigHistoryRecorder::from_config(Some(&history))
            .expect("an enabled block opens")
            .expect("a recorder");
        let recorder = std::sync::Arc::new(recorder);
        crate::config_history::install_config_history_recorder(recorder.clone());
        recorder
    }

    /// Seed a ring by hand, before any recorder is installed, so a test
    /// can control the fields the reload path fills in for itself:
    /// blast radius, secrets fingerprint, and state.
    fn seed(
        dir: &std::path::Path,
        documents: &[(&str, Option<sbproxy_config::BlastRadius>, Option<&str>)],
        promote_index: Option<usize>,
    ) {
        let mut store = sbproxy_config::RevisionStore::open(dir, 20, None).expect("open ring");
        let mut revisions = Vec::new();
        for (index, (yaml, radius, fingerprint)) in documents.iter().enumerate() {
            let entry = store
                .append(
                    yaml.as_bytes(),
                    AppendMetadata {
                        provenance: BaseOrigin::Local,
                        blast_radius: *radius,
                        secrets_fingerprint: fingerprint.map(str::to_string),
                        actor: Some("seed".to_string()),
                        applied_at: 1_700_000_000_000 + index as u64,
                        degraded: Vec::new(),
                    },
                )
                .expect("append");
            revisions.push(entry.revision);
        }
        if let Some(index) = promote_index {
            store.mark_good(revisions[index]).expect("promote");
        }
    }

    /// Apply one document through the real reload transaction, the way
    /// the file watcher does.
    fn apply(config_path: &std::path::Path, yaml: &str) {
        crate::server::reload_from_config_yaml(config_path.to_str().expect("utf-8"), yaml)
            .expect("the fixture document publishes");
    }

    fn counter(name: &str, label: &str, value: &str) -> f64 {
        for family in prometheus::gather() {
            if family.name() != name {
                continue;
            }
            for metric in family.get_metric() {
                if metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == label && pair.value() == value)
                {
                    return metric.get_counter().value();
                }
            }
        }
        0.0
    }

    /// WOR-2460. The whole happy path in one place, because these five
    /// acceptance lines are one behavior seen from five angles: the
    /// target is named, the document is restored, the ring gains a new
    /// entry rather than losing one, the revision rolled away from is
    /// annotated, and the restored document soaks.
    #[test]
    fn rollback_to_last_known_good_restores_the_document_and_appends_a_new_entry() {
        crate::config_soak::clear();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        let recorder = install_ring(&ring_dir);

        apply(&config_path, "proxy: {}\n# the good one\n");
        apply(&config_path, "proxy: {}\n# the bad one\n");
        let entries = recorder.entries();
        assert_eq!(entries.len(), 2, "two applies, two entries");
        recorder.record_soak_verdict(entries[0].revision, SoakVerdict::Successful);

        crate::config_soak::clear();
        let outcome = rollback(config_path.to_str(), &RollbackRequest::to_last_known_good())
            .expect("the last known good is restorable");

        assert_eq!(outcome.restored_revision, entries[0].revision);
        assert_eq!(outcome.restored_digest, entries[0].digest);
        assert_eq!(outcome.previous_revision, Some(entries[1].revision));
        assert!(
            outcome.config_file_unchanged,
            "the route applies a document, it does not rewrite the file",
        );

        let after = recorder.entries();
        assert_eq!(after.len(), 3, "history is append-only: a rollback adds");
        assert_eq!(
            after[2].digest, entries[0].digest,
            "and the appended entry carries the restored document",
        );
        assert_eq!(outcome.appended_revision, Some(after[2].revision));
        assert_eq!(
            after[1].state,
            RevisionState::Reverted,
            "the revision rolled away from is annotated",
        );
        assert_eq!(
            recorder.lkg().map(|entry| entry.revision),
            Some(entries[0].revision),
            "and the pointer does not jump to the rollback's own new entry: only a soak moves it",
        );
        assert_eq!(
            crate::config_soak::in_flight_revision(),
            Some(after[2].revision),
            "a rollback is an ordinary candidate and soaks like one",
        );
        assert_eq!(
            counter("sbproxy_config_apply_total", "outcome", "applied"),
            1.0
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460. Three ways to name a target, each of which has to work
    /// and each of which names what it restored.
    #[test]
    fn a_revision_a_digest_and_last_known_good_all_name_a_target() {
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        seed(
            &ring_dir,
            &[
                ("proxy: {}\n# one\n", None, None),
                ("proxy: {}\n# two\n", Some(BlastRadius::Reload), None),
            ],
            Some(0),
        );
        let recorder = install_ring(&ring_dir);
        let entries = recorder.entries();

        let by_revision = resolve_target(
            &recorder,
            &entries,
            &RollbackTarget::Revision(entries[0].revision),
        )
        .expect("a revision resolves");
        let by_digest = resolve_target(
            &recorder,
            &entries,
            &RollbackTarget::Digest(entries[0].digest.clone()),
        )
        .expect("a digest resolves");
        let by_pointer = resolve_target(&recorder, &entries, &RollbackTarget::LastKnownGood)
            .expect("the pointer resolves");
        assert_eq!(by_revision.digest, entries[0].digest);
        assert_eq!(by_digest.revision, entries[0].revision);
        assert_eq!(by_pointer.revision, entries[0].revision);
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460: "returns a clear 404 naming what is available, not a
    /// 500". The status and the availability list are both the contract.
    #[test]
    fn a_revision_that_is_not_in_the_ring_names_what_is() {
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        seed(&ring_dir, &[("proxy: {}\n# one\n", None, None)], Some(0));
        let _recorder = install_ring(&ring_dir);

        let refusal = rollback(
            Some("/nonexistent/sb.yml"),
            &RollbackRequest {
                target: RollbackTarget::Revision(99),
                ..RollbackRequest::to_last_known_good()
            },
        )
        .expect_err("revision 99 was never applied here");
        assert_eq!(refusal.http_status(), 404);
        assert_eq!(refusal.as_str(), "unknown_revision");
        let message = refusal.to_string();
        assert!(message.contains("available: 1"), "{message}");
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460. The HAProxy Data Plane API's discipline: a mutating
    /// call carries the version it expects and errors on a mismatch,
    /// rather than taking last-writer-wins. All three arms, because the
    /// backwards-compatible one is as load bearing as the refusal.
    #[test]
    fn expected_current_refuses_a_stale_caller_and_lets_an_absent_one_through() {
        crate::config_soak::clear();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        seed(
            &ring_dir,
            &[
                ("proxy: {}\n# one\n", None, None),
                ("proxy: {}\n# two\n", Some(BlastRadius::Reload), None),
            ],
            Some(0),
        );
        let _recorder = install_ring(&ring_dir);

        let refusal = rollback(
            Some("/nonexistent/sb.yml"),
            &RollbackRequest {
                expected_current: Some(1),
                ..RollbackRequest::to_last_known_good()
            },
        )
        .expect_err("revision 2 is running, not 1");
        assert_eq!(refusal.http_status(), 409);
        let message = refusal.to_string();
        assert!(message.contains('1') && message.contains('2'), "{message}");

        // A matching one proceeds. The rollback appends revision 3, so
        // what is running afterwards is 3, which is what the absent case
        // below then rolls back from.
        crate::config_soak::clear();
        let matched = rollback(
            Some("/nonexistent/sb.yml"),
            &RollbackRequest {
                expected_current: Some(2),
                ..RollbackRequest::to_last_known_good()
            },
        )
        .expect("naming the revision that is running proceeds");
        assert_eq!(matched.previous_revision, Some(2));

        // And an absent one proceeds too, which is the backwards
        // compatibility the acceptance line asks for: a caller written
        // before this field existed keeps working.
        crate::config_soak::clear();
        rollback(
            Some("/nonexistent/sb.yml"),
            &RollbackRequest::to_last_known_good(),
        )
        .expect("an absent expected_current proceeds");
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460. A revision number from one lineage does not mean the
    /// same document in another, so the refusal names both. Forcing it
    /// gets through.
    #[test]
    fn a_lineage_break_is_refused_naming_both_lineages_and_force_gets_past_it() {
        crate::config_soak::clear();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        seed(&ring_dir, &[("proxy: {}\n# one\n", None, None)], Some(0));
        let recorder = install_ring(&ring_dir);
        let ours = recorder.lineage();

        let refusal = rollback(
            Some("/nonexistent/sb.yml"),
            &RollbackRequest {
                expected_lineage: Some("00000000-0000-0000-0000-000000000000".to_string()),
                ..RollbackRequest::to_last_known_good()
            },
        )
        .expect_err("a different lineage is refused");
        assert_eq!(refusal.as_str(), "lineage_mismatch");
        let message = refusal.to_string();
        assert!(
            message.contains(&ours),
            "names this ring's lineage: {message}"
        );
        assert!(
            message.contains("00000000-0000-0000-0000-000000000000"),
            "and the one the caller asked for: {message}",
        );

        crate::config_soak::clear();
        let forced = rollback(
            Some("/nonexistent/sb.yml"),
            &RollbackRequest {
                expected_lineage: Some("00000000-0000-0000-0000-000000000000".to_string()),
                force: true,
                ..RollbackRequest::to_last_known_good()
            },
        )
        .expect("forcing it succeeds");
        assert_eq!(forced.restored_revision, 1);
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460. A restart-class rollback is refused until the caller
    /// types the revision back, the way a destructive action should be.
    /// Computed from the two stored documents, so the CLI and the UI
    /// both get the same answer without carrying the matrix themselves.
    #[test]
    fn a_restart_class_rollback_is_refused_until_the_revision_is_typed_back() {
        crate::config_soak::clear();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        let recorder = install_ring(&ring_dir);

        // `proxy.http_bind_port` is restart class: the listener socket
        // is bound once at startup and there is no graceful re-bind.
        apply(&config_path, "proxy:\n  http_bind_port: 8080\n");
        apply(&config_path, "proxy:\n  http_bind_port: 8081\n");
        let entries = recorder.entries();
        recorder.record_soak_verdict(entries[0].revision, SoakVerdict::Successful);
        crate::config_soak::clear();

        let refusal = rollback(config_path.to_str(), &RollbackRequest::to_last_known_good())
            .expect_err("a restart-class rollback needs confirming");
        assert_eq!(refusal.as_str(), "restart_not_confirmed");
        assert_eq!(refusal.http_status(), 409);
        assert!(refusal.to_string().contains("restart"), "{refusal}");
        assert_eq!(
            counter("sbproxy_config_apply_total", "outcome", "rejected"),
            1.0,
        );

        let outcome = rollback(
            config_path.to_str(),
            &RollbackRequest {
                confirm_revision: Some(entries[0].revision),
                ..RollbackRequest::to_last_known_good()
            },
        )
        .expect("naming the revision back accepts it");
        assert_eq!(outcome.restored_revision, entries[0].revision);
        assert_eq!(outcome.blast_radius, Some(BlastRadius::Restart));
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460. A stored document that no longer constructs on this
    /// binary is refused with the error, and the pipeline pointer does
    /// not move. This is the case rollback exists for and the one where
    /// a privileged path that skipped validation would take the node
    /// down during an incident.
    #[test]
    fn a_target_that_no_longer_compiles_is_refused_and_the_pipeline_keeps_serving() {
        crate::config_soak::clear();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        // Seeded by hand, because the reload path would never have
        // accepted it: that is exactly the "published cleanly before an
        // upgrade tightened validation" case.
        seed(
            &ring_dir,
            &[("proxy:\n  not_a_real_key_at_all: 1\n", None, None)],
            Some(0),
        );
        let recorder = install_ring(&ring_dir);
        apply(&config_path, "proxy: {}\n# what is serving\n");
        crate::config_soak::clear();
        let serving = crate::reload::current_pipeline_full();

        let refusal = rollback(config_path.to_str(), &RollbackRequest::to_last_known_good())
            .expect_err("the stored document does not compile");
        assert_eq!(refusal.as_str(), "apply_failed");
        assert_eq!(
            refusal.http_status(),
            422,
            "a broken artifact is not a server fault, and must not land in the 5xx alerts",
        );
        assert!(
            refusal.to_string().contains("not_a_real_key_at_all"),
            "the compile error reaches the caller: {refusal}",
        );
        assert!(
            std::sync::Arc::ptr_eq(&serving, &crate::reload::current_pipeline_full()),
            "the pipeline pointer must not move on a refused rollback",
        );
        assert_eq!(
            recorder
                .rejections()
                .iter()
                .filter(|candidate| candidate.stage == "rollback")
                .count(),
            1,
            "and the refused candidate is kept with `rollback` as its stage",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2460. The secret backends moved since this document applied,
    /// so a `vault://` reference inside it may resolve to something
    /// else. A warning rather than a refusal: the operator asked.
    #[test]
    fn a_secrets_fingerprint_change_is_reported_rather_than_refused() {
        crate::config_soak::clear();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        seed(
            &ring_dir,
            &[
                ("proxy: {}\n# older secrets\n", None, Some("fingerprint-a")),
                (
                    "proxy: {}\n# newer secrets\n",
                    Some(BlastRadius::Hitless),
                    Some("fingerprint-b"),
                ),
            ],
            Some(0),
        );
        let _recorder = install_ring(&ring_dir);

        let outcome = rollback(config_path.to_str(), &RollbackRequest::to_last_known_good())
            .expect("it still rolls back");
        assert!(
            outcome.secrets_fingerprint_changed,
            "the two fingerprints differ, so the response has to say so",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2461, the default. A failed soak with `auto_revert` off
    /// logs, records, and changes nothing about what is serving.
    #[test]
    fn a_failed_soak_with_auto_revert_off_leaves_the_pipeline_pointer_alone() {
        crate::config_soak::clear();
        clear_auto_revert_memory();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        let recorder = install_ring(&ring_dir);
        apply(&config_path, "proxy: {}\n# the good one\n");
        apply(&config_path, "proxy: {}\n# the bad one\n");
        let entries = recorder.entries();
        recorder.record_soak_verdict(entries[0].revision, SoakVerdict::Successful);
        crate::config_soak::clear();
        let serving = crate::reload::current_pipeline_full();

        let decision = auto_revert_after_failed_soak(
            config_path.to_str(),
            entries[1].revision,
            &entries[1].digest,
            false,
        );
        assert!(
            matches!(decision, AutoRevertDecision::Disarmed),
            "{decision:?}"
        );
        assert!(
            std::sync::Arc::ptr_eq(&serving, &crate::reload::current_pipeline_full()),
            "off by default means the pipeline pointer is untouched",
        );
        assert_eq!(
            counter("sbproxy_config_apply_total", "outcome", "reverted"),
            0.0,
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2461, armed. A `Reload`-class diff is one an arc-swap can
    /// undo, so the node re-applies its last known good and the entry
    /// is recorded as reverted.
    #[test]
    fn a_failed_soak_with_auto_revert_on_re_applies_the_last_known_good() {
        crate::config_soak::clear();
        clear_auto_revert_memory();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        let recorder = install_ring(&ring_dir);
        apply(&config_path, "proxy: {}\n# the good one\n");
        apply(&config_path, "proxy: {}\n# the bad one\n");
        let entries = recorder.entries();
        recorder.record_soak_verdict(entries[0].revision, SoakVerdict::Successful);
        crate::config_soak::clear();
        let serving = crate::reload::current_pipeline_full();

        let decision = auto_revert_after_failed_soak(
            config_path.to_str(),
            entries[1].revision,
            &entries[1].digest,
            true,
        );
        let AutoRevertDecision::Reverted(outcome) = decision else {
            panic!("an arc-swappable failure with auto_revert armed must revert: {decision:?}");
        };
        assert_eq!(outcome.restored_revision, entries[0].revision);
        assert!(
            !std::sync::Arc::ptr_eq(&serving, &crate::reload::current_pipeline_full()),
            "the node is now serving the restored document",
        );
        let after = recorder.entries();
        assert_eq!(after[1].state, RevisionState::Reverted);
        assert_eq!(
            counter("sbproxy_config_apply_total", "outcome", "reverted"),
            1.0,
            "an automatic revert counts under its own label, disjoint from a manual one",
        );
        assert_eq!(
            counter("sbproxy_config_apply_total", "outcome", "applied"),
            0.0,
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2461. A `Restart`-class diff is not one an arc-swap can undo,
    /// so the node does not revert and says so with the radius named.
    #[test]
    fn a_failed_soak_on_a_restart_class_diff_does_not_revert() {
        crate::config_soak::clear();
        clear_auto_revert_memory();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        let recorder = install_ring(&ring_dir);
        apply(&config_path, "proxy:\n  http_bind_port: 8080\n");
        apply(&config_path, "proxy:\n  http_bind_port: 8081\n");
        let entries = recorder.entries();
        assert_eq!(
            entries[1].blast_radius,
            Some(BlastRadius::Restart),
            "the fixture has to actually be restart class or this test proves nothing",
        );
        recorder.record_soak_verdict(entries[0].revision, SoakVerdict::Successful);
        crate::config_soak::clear();
        let serving = crate::reload::current_pipeline_full();

        let decision = auto_revert_after_failed_soak(
            config_path.to_str(),
            entries[1].revision,
            &entries[1].digest,
            true,
        );
        assert!(
            matches!(
                decision,
                AutoRevertDecision::NotArcSwappable(BlastRadius::Restart)
            ),
            "{decision:?}",
        );
        assert!(
            std::sync::Arc::ptr_eq(&serving, &crate::reload::current_pipeline_full()),
            "half-reverting a restart-class change would leave the process in a state neither \
             config describes",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2461: "a reverted-to config that then fails its own soak does
    /// not trigger a second revert to itself". The memory is keyed on
    /// the digest rather than the revision number, because a rollback
    /// appends a **new** number carrying the old content and comparing
    /// numbers would let the cycle run forever.
    #[test]
    fn a_reverted_to_config_that_fails_its_own_soak_does_not_revert_again() {
        crate::config_soak::clear();
        clear_auto_revert_memory();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        let recorder = install_ring(&ring_dir);
        apply(&config_path, "proxy: {}\n# the good one\n");
        apply(&config_path, "proxy: {}\n# the bad one\n");
        let entries = recorder.entries();
        recorder.record_soak_verdict(entries[0].revision, SoakVerdict::Successful);
        crate::config_soak::clear();

        let first = auto_revert_after_failed_soak(
            config_path.to_str(),
            entries[1].revision,
            &entries[1].digest,
            true,
        );
        assert!(
            matches!(first, AutoRevertDecision::Reverted(_)),
            "{first:?}"
        );
        crate::config_soak::clear();
        let serving = crate::reload::current_pipeline_full();

        // The restored document is now running under a new revision
        // number, and it fails its own soak. Reverting again would put
        // the same bytes back under a third number and fail the same
        // way.
        let restored = recorder.entries();
        let newest = restored.last().expect("the rollback appended one");
        let second = auto_revert_after_failed_soak(
            config_path.to_str(),
            newest.revision,
            &newest.digest,
            true,
        );
        assert!(
            matches!(second, AutoRevertDecision::WouldLoop),
            "{second:?}"
        );
        assert!(
            std::sync::Arc::ptr_eq(&serving, &crate::reload::current_pipeline_full()),
            "and nothing moved the second time",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2461. A revert that itself fails to compile leaves the
    /// current pipeline serving and escalates rather than looping.
    #[test]
    fn a_revert_that_cannot_compile_leaves_the_pipeline_serving() {
        crate::config_soak::clear();
        clear_auto_revert_memory();
        let temp = tempfile::tempdir().expect("temp");
        let ring_dir = temp.path().join("ring");
        let config_path = temp.path().join("sb.yml");
        seed(
            &ring_dir,
            &[
                ("proxy:\n  not_a_real_key_at_all: 1\n", None, None),
                (
                    "proxy: {}\n# the failing one\n",
                    Some(BlastRadius::Hitless),
                    None,
                ),
            ],
            Some(0),
        );
        let recorder = install_ring(&ring_dir);
        apply(&config_path, "proxy: {}\n# what is serving\n");
        crate::config_soak::clear();
        let serving = crate::reload::current_pipeline_full();
        let failing = recorder.entries()[1].clone();

        let decision = auto_revert_after_failed_soak(
            config_path.to_str(),
            failing.revision,
            &failing.digest,
            true,
        );
        assert!(
            matches!(
                decision,
                AutoRevertDecision::Refused(RollbackRefusal::ApplyFailed(_))
            ),
            "{decision:?}",
        );
        assert!(
            std::sync::Arc::ptr_eq(&serving, &crate::reload::current_pipeline_full()),
            "an unusable rescue target must not take the running pipeline with it",
        );
        crate::config_soak::clear();
        crate::config_history::clear_config_history_recorder();
    }

    /// WOR-2461's arming rule, stated once so a change to it is visible
    /// in a diff rather than only in behavior. The measured overlap with
    /// `ClusterRestartFingerprint` is on `arc_swap_can_undo`'s own
    /// rustdoc, and this pins the two radii the fingerprint does not
    /// cover.
    #[test]
    fn only_hitless_and_reload_diffs_arm_the_automatic_revert() {
        assert!(arc_swap_can_undo(BlastRadius::Hitless));
        assert!(arc_swap_can_undo(BlastRadius::Reload));
        assert!(!arc_swap_can_undo(BlastRadius::Restart));
        assert!(!arc_swap_can_undo(BlastRadius::Breaking));
    }

    /// WOR-2461. Two of the twenty-four restart-class rules in
    /// `BLAST_RADIUS_MATRIX` are the ones `ClusterRestartFingerprint`
    /// refuses outright, and the rest reach a soak. Counted here rather
    /// than asserted in prose, so the number in
    /// [`arc_swap_can_undo`]'s rustdoc cannot quietly go stale when a
    /// rule is added.
    #[test]
    fn the_measured_restart_class_overlap_is_two_of_twenty_four() {
        let restart_class: Vec<&str> = sbproxy_config::BLAST_RADIUS_MATRIX
            .iter()
            .filter(|rule| !arc_swap_can_undo(rule.radius))
            .map(|rule| rule.pattern)
            .collect();
        assert_eq!(
            restart_class.len(),
            24,
            "the rustdoc on arc_swap_can_undo says 24; re-measure it, do not edit this number \
             without re-reading the list: {restart_class:?}",
        );
        let covered_by_the_fingerprint: Vec<&&str> = restart_class
            .iter()
            .filter(|pattern| pattern.starts_with("proxy.cluster"))
            .collect();
        assert_eq!(
            covered_by_the_fingerprint.len(),
            2,
            "ClusterRestartFingerprint refuses proxy.cluster and proxy.cluster.** before they \
             can apply, so they never reach a soak: {covered_by_the_fingerprint:?}",
        );
    }

    /// WOR-2460. "Who rolled the gateway back and to what" is an audit
    /// question, so both outcomes publish and both carry the trigger.
    #[test]
    fn the_rollback_event_carries_the_trigger_the_actor_and_both_revisions() {
        let request = RollbackRequest {
            target: RollbackTarget::Revision(3),
            actor: Some("alice".to_string()),
            ..RollbackRequest::to_last_known_good()
        };
        let applied = RollbackOutcome {
            restored_revision: 3,
            restored_digest: "abc".to_string(),
            previous_revision: Some(5),
            blast_radius: Some(BlastRadius::Reload),
            appended_revision: Some(6),
            degraded: Vec::new(),
            secrets_fingerprint_changed: false,
            config_file_unchanged: true,
        };
        let event = rollback_event(&request, Ok(&applied));
        assert_eq!(event.data["trigger"], "manual");
        assert_eq!(event.data["actor"], "alice");
        assert_eq!(event.data["target"], "revision 3");
        assert_eq!(event.data["restored_revision"], 3);
        assert_eq!(event.data["previous_revision"], 5);
        assert_eq!(event.data["appended_revision"], 6);
        assert_eq!(event.data["blast_radius"], "reload");

        let refused = rollback_event(
            &RollbackRequest {
                trigger: RollbackTrigger::AutoRevert,
                ..RollbackRequest::to_last_known_good()
            },
            Err(&RollbackRefusal::NoLastKnownGood),
        );
        assert_eq!(refused.data["trigger"], "auto_revert");
        assert_eq!(refused.data["outcome"], "rejected");
        assert_eq!(refused.data["reason"], "no_last_known_good");
        assert!(
            refused.data.get("detail").is_none(),
            "the refusal's free text can quote YAML and stays out of the event",
        );
    }

    /// A ring with hundreds of entries must not produce an unbounded
    /// error string on the one path that names them all.
    #[test]
    fn the_availability_list_is_bounded() {
        let many: Vec<u64> = (1..=100).collect();
        let rendered = render_available(&many);
        assert!(rendered.contains("and 80 more"), "{rendered}");
        assert_eq!(render_available::<u64>(&[]), "the ring is empty");
    }
}
