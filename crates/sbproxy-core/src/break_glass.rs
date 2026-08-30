// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Break-glass emergency access for the key and credential admin API
//! (WOR-2573).
//!
//! # "Scoped" means declared, not enforced
//!
//! A grant's `scope` is what the requester said they needed and what the
//! reviewer reads afterwards. It is not compared against the record a
//! tagged action actually touches: [`tag_action`] matches on the actor and
//! the grant's state and nothing narrower. Enforcing it would mean a second
//! authorization model, which is precisely what this is not, so the honest
//! word for the field is "declared".
//!
//! # What this is, and what it deliberately is not
//!
//! It is not a new authorization model. A break-glass grant is a
//! time-boxed, scoped, heavily-audited *marker* on an admin session: it
//! records that a named operator claimed emergency access to a named set of
//! records, that a quorum of other operators agreed, and that everything
//! done under it is attributable to that one grant id. Authorization itself
//! is still the admin RBAC roles.
//!
//! Building it as an authorization model would have been the larger and
//! worse change: another way to be allowed to do something is another way
//! to be allowed to do something quietly, and the surveyed products all
//! converge on the opposite property. HashiCorp Vault's own emergency
//! guidance, AWS's break-glass role pattern, and every enterprise PAM
//! product reach the same shape: pre-staged, time-boxed at 15 to 60
//! minutes, scope-limited, two-person or quorum approved, session-captured,
//! and reviewed inside a fixed window. So the goal here is that a grant is
//! *expensive to use quietly and cheap to review after the fact*, and each
//! design choice below is checked against that sentence.
//!
//! # The state machine
//!
//! ```text
//!   request  --(N distinct approvers, never the requester)-->  active
//!      |                                                         |
//!      | (nobody approves before the TTL)                        | (TTL passes)
//!      v                                                         v
//!   expired ------------------------------------------------> awaiting review
//!                                                                |
//!                                                                | (reviewer signs off)
//!                                                                v
//!                                                             reviewed
//! ```
//!
//! # Expiry is computed on read, not swept
//!
//! There is no background sweeper. Every read of a grant recomputes its
//! state from `now`, which is the project's stated preference and is also
//! the safer half of the trade here: a sweeper that fails to run leaves a
//! grant active, while a read that fails to run leaves nothing usable. The
//! cost is that an expired grant occupies memory until something looks at
//! it, which is bounded by the number of grants ever requested in a process
//! lifetime.
//!
//! # Where the state lives
//!
//! In process memory, deliberately, and this is the honest limitation to
//! read before relying on it: grants do not survive a restart and do not
//! replicate across a fleet. A restart voids every active grant, which
//! fails in the safe direction. A fleet does not: an operator holding an
//! active grant on node A has no grant on node B, and a quorum approved on
//! node A is not visible on node B. `docs/key-management.md` states this,
//! and closing it means a store-backed grant record, which is scope this
//! change does not carry.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use sbproxy_config::types::BreakGlassConfig;

/// A break-glass grant's computed state at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GrantState {
    /// Requested, quorum not yet met.
    PendingApproval,
    /// Quorum met and the TTL has not run out. The only state under which
    /// actions are tagged with this grant.
    Active,
    /// The TTL ran out with no reviewer sign-off. Stays on the review queue
    /// and on the admin dashboard until somebody signs off.
    AwaitingReview,
    /// Reviewed and closed.
    Reviewed,
    /// Expired without ever reaching quorum. Nothing was done under it, so
    /// there is nothing to review.
    Denied,
}

impl GrantState {
    /// The label used on `sbproxy_break_glass_open{state}`.
    fn metric_label(self) -> Option<&'static str> {
        match self {
            Self::PendingApproval => Some("pending_approval"),
            Self::Active => Some("active"),
            Self::AwaitingReview => Some("awaiting_review"),
            Self::Reviewed | Self::Denied => None,
        }
    }
}

/// One break-glass grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Grant {
    /// Opaque grant id. The one key a reviewer pulls a whole session by.
    pub id: String,
    /// Operator who requested it.
    pub requested_by: String,
    /// Free-text justification, bounded. Never a secret; it is written by
    /// the requester and read by the reviewer.
    pub justification: String,
    /// Record ids or tenant names this grant covers. Empty is refused at
    /// request time: an unscoped break-glass grant is a standing admin
    /// credential with extra paperwork.
    pub scope: Vec<String>,
    /// When the request was made.
    pub requested_at: DateTime<Utc>,
    /// How long the grant runs once quorum is met.
    pub ttl_secs: u64,
    /// Distinct operators who have approved. Never contains
    /// [`Self::requested_by`].
    pub approvals: BTreeSet<String>,
    /// When quorum was met, if it was.
    pub activated_at: Option<DateTime<Utc>>,
    /// How many admin actions were tagged with this grant.
    pub actions_taken: u64,
    /// Operator who signed off after the fact, and when.
    pub reviewed_by: Option<String>,
    /// When the post-access review was recorded.
    pub reviewed_at: Option<DateTime<Utc>>,
    /// The reviewer's sign-off note.
    ///
    /// A field rather than only a line in the audit context string,
    /// because that string is capped at 256 bytes and shares its budget
    /// with `scope`, which is bounded two orders of magnitude higher. A
    /// grant with a large scope silently truncated `approvals=`,
    /// `ttl_secs=` and the note out of the record, which is to say it
    /// dropped the sign-off on exactly the grants most likely to want
    /// one. The note now rides the structured diff, where the
    /// justification already lives, and the context string carries only
    /// bounded counters.
    pub reviewed_note: Option<String>,
    /// Whether this grant's time-driven terminal transition has already
    /// been counted on `sbproxy_break_glass_grants_total`.
    ///
    /// Expiry is computed on read and has no transition to hang a counter
    /// on, which is why `expired` and `denied` were declared in the metric's
    /// vocabulary and never written: the runbook's `expired - reviewed`
    /// alert evaluated to `-reviewed` forever. This flag is the one-shot
    /// latch that lets a read emit the transition it observes, exactly once.
    #[serde(default)]
    pub terminal_counted: bool,
}

impl Grant {
    /// A `u64` seconds value as a `chrono::Duration`, refusing what chrono
    /// cannot represent instead of panicking on it.
    ///
    /// `Duration::seconds` is `expect(try_seconds(..))` and a bare
    /// `as i64` wraps negative on a large `u64`, which here would make a
    /// grant that reads as active expire in the past. Config validation
    /// bounds `max_ttl_secs` and `review_window_secs` in practice, but this
    /// type is the one that does the arithmetic and should not depend on
    /// that. `None` means "so long it is effectively unbounded", which the
    /// callers treat as never-reached rather than as immediately-reached.
    fn checked_duration(seconds: u64) -> Option<Duration> {
        i64::try_from(seconds).ok().and_then(Duration::try_seconds)
    }

    /// When the grant stops being usable, if it ever started.
    pub(crate) fn expires_at(&self) -> Option<DateTime<Utc>> {
        let ttl = Self::checked_duration(self.ttl_secs)?;
        self.activated_at.map(|at| at + ttl)
    }

    /// The grant's state at `now`, recomputed rather than stored.
    ///
    /// Stored state and a TTL are two sources of truth for one fact, and
    /// the one that is wrong is always the stored one, because it is the
    /// one that needs something to run in order to stay right.
    pub(crate) fn state(&self, now: DateTime<Utc>, quorum: usize) -> GrantState {
        if self.reviewed_by.is_some() {
            return GrantState::Reviewed;
        }
        // An unrepresentable TTL cannot expire, so such a grant stays in
        // its pre-terminal state rather than flipping to a terminal one on
        // an arithmetic accident.
        let Some(ttl) = Self::checked_duration(self.ttl_secs) else {
            return if self.activated_at.is_some() {
                GrantState::Active
            } else {
                GrantState::PendingApproval
            };
        };
        let Some(activated) = self.activated_at else {
            // Never activated. A request is only worth holding open for
            // as long as it could still be used, so the TTL bounds the
            // approval window too.
            return if now > self.requested_at + ttl {
                GrantState::Denied
            } else {
                GrantState::PendingApproval
            };
        };
        let _ = quorum;
        if now < activated + ttl {
            GrantState::Active
        } else {
            GrantState::AwaitingReview
        }
    }

    /// Whether the post-access review is overdue at `now`.
    pub(crate) fn review_overdue(&self, now: DateTime<Utc>, review_window_secs: u64) -> bool {
        if self.reviewed_by.is_some() {
            return false;
        }
        match (
            self.expires_at(),
            Self::checked_duration(review_window_secs),
        ) {
            (Some(at), Some(window)) => now > at + window,
            _ => false,
        }
    }

    /// The non-secret JSON view. Every field here is operator-authored or
    /// derived; nothing about a key or credential's material appears.
    pub(crate) fn view(&self, now: DateTime<Utc>, cfg: &BreakGlassConfig) -> serde_json::Value {
        json!({
            "id": self.id,
            "state": self.state(now, cfg.quorum),
            "requested_by": self.requested_by,
            "justification": self.justification,
            "scope": self.scope,
            "requested_at": self.requested_at,
            "ttl_secs": self.ttl_secs,
            "approvals": self.approvals,
            "approvals_needed": cfg.quorum.saturating_sub(self.approvals.len()),
            "activated_at": self.activated_at,
            "expires_at": self.expires_at(),
            "actions_taken": self.actions_taken,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "reviewed_note": self.reviewed_note,
            "review_overdue": self.review_overdue(now, cfg.review_window_secs),
        })
    }
}

/// Why a break-glass operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BreakGlassError {
    /// `key_management.break_glass.enabled` is false.
    Disabled,
    /// No admin operator was resolved for the request.
    NoActor,
    /// The requested TTL is above `max_ttl_secs`, or zero.
    TtlOutOfRange(u64),
    /// The request carried no scope.
    UnscopedRequest,
    /// The request carried no justification.
    NoJustification,
    /// No grant with that id.
    NotFound,
    /// The approver is the requester. Never permitted, whatever the roster
    /// says.
    SelfApproval,
    /// The reviewer is the requester. Never permitted, for the same reason:
    /// the post-access review is what makes the grant reviewable by
    /// somebody other than the person who used it.
    SelfReview,
    /// The approver is not on `key_management.break_glass.approvers`.
    NotAnApprover(String),
    /// This operator already approved.
    AlreadyApproved,
    /// The grant is not in a state where this operation makes sense.
    WrongState(GrantState),
    /// The retained-grant ceiling is full of grants that are still open or
    /// still awaiting review.
    RegistryFull(usize),
}

impl std::fmt::Display for BreakGlassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(
                f,
                "break-glass access is not configured; set key_management.break_glass.enabled and \
                 name at least one approver"
            ),
            Self::NoActor => write!(
                f,
                "break-glass requires an authenticated admin operator, and this request resolved \
                 none"
            ),
            Self::TtlOutOfRange(max) => write!(
                f,
                "break-glass ttl_secs must be between 1 and key_management.break_glass.max_ttl_secs \
                 ({max}). The request is refused rather than clamped, so the requester finds out \
                 now instead of when the grant expires early"
            ),
            Self::UnscopedRequest => write!(
                f,
                "break-glass requires a non-empty scope of key or credential ids, or tenant names. \
                 An unscoped grant is a standing admin credential with extra paperwork"
            ),
            Self::NoJustification => write!(
                f,
                "break-glass requires a justification; it is what the post-access review reads"
            ),
            Self::NotFound => write!(f, "no such break-glass grant"),
            Self::SelfApproval => write!(
                f,
                "a break-glass grant cannot be approved by the operator who requested it"
            ),
            Self::SelfReview => write!(
                f,
                "a break-glass grant cannot be reviewed by the operator who requested it; the \
                 post-access review exists to be somebody else's signature"
            ),
            Self::NotAnApprover(who) => write!(
                f,
                "'{who}' is not on key_management.break_glass.approvers"
            ),
            Self::AlreadyApproved => write!(f, "this operator has already approved this grant"),
            Self::WrongState(state) => {
                write!(f, "the grant is {state:?} and this operation does not apply")
            }
            Self::RegistryFull(max) => write!(
                f,
                "this process is holding {max} break-glass grants that are still open or still \
                 awaiting review, so a new one cannot be recorded. Review the open ones: a \
                 registry this full is itself the finding"
            ),
        }
    }
}

/// How many break-glass grants this process retains.
///
/// Grants are never deleted on expiry, because the review queue is the
/// feature: a grant that vanishes is a grant nobody reviewed. This is the
/// ceiling that keeps that from being a memory-growth knob an
/// authenticated admin can turn.
const MAX_TRACKED_GRANTS: usize = 1024;

/// How many scope entries one grant records. Each is separately capped at
/// 256 bytes where it is truncated.
const MAX_SCOPE_ENTRIES: usize = 64;

/// How long a reviewer's sign-off note is kept, in bytes.
const MAX_NOTE_BYTES: usize = 1024;

/// Appended when a note hits [`MAX_NOTE_BYTES`], so the record says a tail
/// was dropped instead of looking like a note that ended there. A sign-off
/// silently missing its last sentence is the same defect the note field
/// exists to fix, one order of magnitude up.
const NOTE_TRUNCATED_MARKER: &str = "... [truncated]";

/// Process-wide break-glass state.
#[derive(Default)]
struct Registry {
    grants: parking_lot::Mutex<Vec<Grant>>,
    /// Whether the "registry is full" refusal has already been recorded.
    ///
    /// The refusal is repeatable by an authenticated admin and its record
    /// is a keyed-HMAC append to the audit chain on disk, so recording
    /// every attempt turns a refused request into an unbounded write. The
    /// finding is that the registry filled, not that this request arrived.
    /// Cleared when a listing evicts a terminal grant and the registry
    /// drops back under the ceiling, so a second episode records again.
    registry_full_recorded: std::sync::atomic::AtomicBool,
}

fn registry() -> &'static Registry {
    static R: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    R.get_or_init(Registry::default)
}

/// The configured break-glass settings from the installed key plane, or
/// `None` when the key plane is off.
fn config() -> Option<BreakGlassConfig> {
    crate::key_plane::current_key_plane().map(|plane| plane.break_glass().clone())
}

/// Whether `operator` is on the configured approver roster.
///
/// A free function taking `&BreakGlassConfig` rather than a field read on
/// whatever binding the caller happens to hold: the config-reader guard
/// proves a key is wired by finding a typed field access, and it is right
/// to insist, because a roster nothing reads is a quorum that admits
/// anyone.
fn is_approver(cfg: &BreakGlassConfig, operator: &str) -> bool {
    cfg.approvers.iter().any(|approver| approver == operator)
}

/// Whether a requested TTL is inside the configured cap.
///
/// Zero is refused as well as over-cap. A zero-second grant would activate
/// and expire in the same instant, which reads as a grant that was denied
/// and is not.
fn ttl_within_cap(cfg: &BreakGlassConfig, ttl_secs: u64) -> bool {
    ttl_secs > 0 && ttl_secs <= cfg.max_ttl_secs
}

/// The configured TTL cap, for the refusal message.
fn ttl_cap(cfg: &BreakGlassConfig) -> u64 {
    cfg.max_ttl_secs
}

/// Request a grant. Returns the new grant.
///
/// # Errors
///
/// [`BreakGlassError`] for every refusal; each variant carries the reason
/// the caller is shown.
pub(crate) fn request(
    requested_by: &str,
    justification: &str,
    scope: Vec<String>,
    ttl_secs: u64,
) -> Result<Grant, BreakGlassError> {
    let cfg = config().ok_or(BreakGlassError::Disabled)?;
    if !cfg.enabled {
        return Err(BreakGlassError::Disabled);
    }
    if requested_by.trim().is_empty() {
        return Err(BreakGlassError::NoActor);
    }
    if justification.trim().is_empty() {
        return Err(BreakGlassError::NoJustification);
    }
    if scope.iter().all(|s| s.trim().is_empty()) {
        return Err(BreakGlassError::UnscopedRequest);
    }
    if !ttl_within_cap(&cfg, ttl_secs) {
        return Err(BreakGlassError::TtlOutOfRange(ttl_cap(&cfg)));
    }
    let grant = Grant {
        id: format!("bg_{}", sbproxy_keystore::crypto::random_id()),
        requested_by: requested_by.to_string(),
        justification: sbproxy_util::truncate_utf8(justification, 1024).to_owned(),
        // Bounded in count and element length. An authenticated admin can
        // hold up to MAX_TRACKED_GRANTS grants, so an unbounded scope list
        // is retained memory they control. Truncating silently rather than
        // refusing: a scope is a record of intent for the reviewer, not an
        // enforced filter, so friction here buys nothing on the exception
        // path.
        scope: scope
            .into_iter()
            .filter(|s| !s.trim().is_empty())
            .take(MAX_SCOPE_ENTRIES)
            .map(|s| sbproxy_util::truncate_utf8(&s, 256).to_owned())
            .collect(),
        requested_at: Utc::now(),
        ttl_secs,
        approvals: BTreeSet::new(),
        activated_at: None,
        actions_taken: 0,
        reviewed_by: None,
        reviewed_at: None,
        reviewed_note: None,
        terminal_counted: false,
    };
    {
        let mut grants = registry().grants.lock();
        // Bounded. Grants are never deleted, because the review queue is
        // the point and a grant that vanishes is a grant nobody reviewed.
        // But an authenticated admin can request them in a loop, so the
        // list needs a ceiling; the oldest *closed* grants go first, and
        // only when nothing open would be lost. A registry with that many
        // grants still open is itself the finding.
        if grants.len() >= MAX_TRACKED_GRANTS {
            let now = Utc::now();
            let quorum = cfg.quorum;
            grants.retain(|g| {
                !matches!(
                    g.state(now, quorum),
                    GrantState::Reviewed | GrantState::Denied
                )
            });
            if grants.len() < MAX_TRACKED_GRANTS {
                registry()
                    .registry_full_recorded
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
            if grants.len() >= MAX_TRACKED_GRANTS {
                drop(grants);
                // Once, not once per attempt. The refusal is repeatable by
                // an authenticated admin and each record is a keyed-HMAC
                // append to the audit chain on disk, so recording every
                // one turns a refusal into an unbounded write loop. The
                // finding is that the registry filled, which is a fact
                // about the registry rather than about this request; the
                // latch resets when a listing evicts a terminal grant and
                // the registry drops back under the ceiling.
                if registry()
                    .registry_full_recorded
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(BreakGlassError::RegistryFull(MAX_TRACKED_GRANTS));
                }
                // The one refusal whose own error text says "a registry
                // this full is itself the finding", which is worth
                // nothing if the finding reaches no record. The others
                // (`NotFound`, `WrongState`, `AlreadyApproved`) are
                // operator mistakes against a grant that exists and are
                // deliberately left to the HTTP status.
                RefusedGrant {
                    id: grant.id.clone(),
                    requested_by: grant.requested_by.clone(),
                    approvals: 0,
                }
                .audit("break_glass_request", &grant.requested_by, "registry_full");
                return Err(BreakGlassError::RegistryFull(MAX_TRACKED_GRANTS));
            }
        }
        grants.push(grant.clone());
    }
    sbproxy_observe::metrics::record_break_glass("requested");
    audit(&grant, "break_glass_request", "requested");
    refresh_gauges();
    Ok(grant)
}

/// Approve a grant on behalf of `approver`.
///
/// # Errors
///
/// Self-approval, an approver not on the roster, a duplicate approval, an
/// unknown id, or a grant that is no longer pending.
pub(crate) fn approve(id: &str, approver: &str) -> Result<Grant, BreakGlassError> {
    let cfg = config().ok_or(BreakGlassError::Disabled)?;
    if !cfg.enabled {
        return Err(BreakGlassError::Disabled);
    }
    if approver.trim().is_empty() {
        return Err(BreakGlassError::NoActor);
    }
    let now = Utc::now();
    let mut grants = registry().grants.lock();
    let grant = grants
        .iter_mut()
        .find(|g| g.id == id)
        .ok_or(BreakGlassError::NotFound)?;
    // Self-approval is refused before the roster check, and refused even
    // when the requester is on the roster. A two-person rule that one
    // person can satisfy is not a two-person rule, and the roster is the
    // place somebody would otherwise "fix" this by adding themselves.
    if grant.requested_by == approver {
        let refused = RefusedGrant::of(grant);
        drop(grants);
        refused.audit("break_glass_approve", approver, "self_approval");
        return Err(BreakGlassError::SelfApproval);
    }
    if !is_approver(&cfg, approver) {
        let refused = RefusedGrant::of(grant);
        drop(grants);
        refused.audit("break_glass_approve", approver, "not_an_approver");
        return Err(BreakGlassError::NotAnApprover(approver.to_string()));
    }
    let state = grant.state(now, cfg.quorum);
    if state != GrantState::PendingApproval {
        return Err(BreakGlassError::WrongState(state));
    }
    if !grant.approvals.insert(approver.to_string()) {
        return Err(BreakGlassError::AlreadyApproved);
    }
    sbproxy_observe::metrics::record_break_glass("approved");
    if grant.approvals.len() >= cfg.quorum {
        grant.activated_at = Some(now);
        sbproxy_observe::metrics::record_break_glass("activated");
    }
    let snapshot = grant.clone();
    drop(grants);
    audit(
        &snapshot,
        "break_glass_approve",
        if snapshot.activated_at.is_some() {
            "activated"
        } else {
            "approved"
        },
    );
    refresh_gauges();
    Ok(snapshot)
}

/// Record the post-access review.
///
/// # Errors
///
/// An unknown id, or a grant that never reached the review queue.
pub(crate) fn review(id: &str, reviewer: &str, note: &str) -> Result<Grant, BreakGlassError> {
    let cfg = config().ok_or(BreakGlassError::Disabled)?;
    // **No `enabled` guard here, and the asymmetry with `request`,
    // `approve`, and `tag_action` is deliberate.** Those three create or
    // extend access, so the kill switch has to stop them. This one closes
    // access out, and a kill switch that blocks the closing-out is not a
    // kill switch, it is a trap.
    //
    // A round of this branch added the guard for symmetry, on the reasoning
    // that "grants do not survive a reload that disables the block anyway".
    // That reasoning was simply wrong, and it is written down here because
    // it is the kind of wrong that reads as obviously true. `registry()` is
    // a process-global `OnceLock` that nothing outside `reset_for_test`
    // clears, and a config reload replaces the key plane, not the process,
    // so every grant survives it. `config()` returns `Some` whenever a
    // plane is installed, whatever `enabled` says.
    //
    // So the guard made every grant awaiting review **permanently
    // unreviewable**: no grant could reach `Reviewed`, `list()` has no such
    // guard and kept publishing the queue, and
    // `sbproxy_break_glass_open{state="awaiting_review"}` (the one alert
    // `docs/key-management.md` tells operators to build) stayed pinned above
    // zero forever.
    //
    // A first version of this comment added a third consequence, that the
    // registry then grew to its refusal ceiling. That was also wrong and is
    // corrected rather than deleted, because it is the same failure as the
    // one above: `MAX_TRACKED_GRANTS`' retain evicts `Reviewed` **and**
    // `Denied`, so the eviction class survived; and the retain runs only
    // inside `request()`, which the guard did block, so nothing could be
    // added either. Stranding was the whole harm, and it was enough.
    if reviewer.trim().is_empty() {
        return Err(BreakGlassError::NoActor);
    }
    let now = Utc::now();
    let mut grants = registry().grants.lock();
    let grant = grants
        .iter_mut()
        .find(|g| g.id == id)
        .ok_or(BreakGlassError::NotFound)?;
    // The same two checks `approve` makes, and for the same reason. The
    // post-access review is the accountability half of this design: a
    // requester who can close their own grant clears it off the review
    // queue and off `sbproxy_break_glass_open{state="awaiting_review"}`,
    // which is the one alert the whole feature is built around. Leaving
    // these off `review` while `approve` has them made the quorum
    // theatre for anyone willing to wait for their own grant to expire.
    if grant.requested_by == reviewer {
        let refused = RefusedGrant::of(grant);
        drop(grants);
        refused.audit("break_glass_review", reviewer, "self_review");
        return Err(BreakGlassError::SelfReview);
    }
    // The roster check, with one exception that exists so the queue
    // cannot strand.
    //
    // An empty roster only reaches here when the block is disabled or
    // absent: the config compiler refuses an empty `approvers` while
    // `enabled` is true. So `approvers: []` means an operator turned the
    // feature off, or deleted the block, while grants were still awaiting
    // review. With a plain roster check that is a permanent strand,
    // identical to the one removing `review`'s `enabled` guard fixed:
    // every operator is `NotAnApprover`, no grant can reach `Reviewed`,
    // and `sbproxy_break_glass_open{state="awaiting_review"}` stays pinned
    // above zero for the life of the process.
    //
    // So an empty roster falls back to "any admin who is not the
    // requester". That keeps the property the roster is there for, which
    // is that a grant its own subject can close is not a reviewed grant,
    // and gives up only the narrower "and that person was pre-named". The
    // audit record says which rule ran, so a reviewer reading the chain
    // can tell a roster sign-off from a fallback one.
    if !cfg.approvers.is_empty() && !is_approver(&cfg, reviewer) {
        let refused = RefusedGrant::of(grant);
        drop(grants);
        refused.audit("break_glass_review", reviewer, "not_an_approver");
        return Err(BreakGlassError::NotAnApprover(reviewer.to_string()));
    }
    let roster_was_empty = cfg.approvers.is_empty();
    let state = grant.state(now, cfg.quorum);
    if state != GrantState::AwaitingReview {
        return Err(BreakGlassError::WrongState(state));
    }
    grant.reviewed_by = Some(reviewer.to_string());
    grant.reviewed_at = Some(now);
    // With a marker, not silently. Dropping the tail of a sign-off with no
    // sign that anything was dropped is the same defect one order of
    // magnitude up from the one this field exists to fix.
    grant.reviewed_note = (!note.trim().is_empty()).then(|| {
        sbproxy_util::truncate_utf8_with_marker(note, MAX_NOTE_BYTES, NOTE_TRUNCATED_MARKER)
            .into_owned()
    });
    let snapshot = grant.clone();
    drop(grants);
    // A distinct outcome rather than a flag inside the context string, so
    // a SIEM rule can select these without parsing free text, and the same
    // value on the counter so the two agree. Recording `reviewed`
    // unconditionally here while four operator-facing surfaces, one of
    // them `docs/metrics-stability.md`, advertised the second value made
    // the label a promise nothing kept.
    let outcome = if roster_was_empty {
        "reviewed_without_roster"
    } else {
        "reviewed"
    };
    sbproxy_observe::metrics::record_break_glass(outcome);
    audit_with_note(&snapshot, "break_glass_review", outcome, note);
    refresh_gauges();
    Ok(snapshot)
}

/// The grant currently active for `actor`, if any, and count one action
/// against it.
///
/// Called from the admin key/credential mutation audit path, so every
/// action taken while a grant is active carries the grant id. That is what
/// makes a reviewer's job one query instead of a timestamp correlation.
pub(crate) fn tag_action(actor: &str) -> Option<String> {
    let cfg = config()?;
    if !cfg.enabled {
        return None;
    }
    let now = Utc::now();
    let mut grants = registry().grants.lock();
    let grant = grants
        .iter_mut()
        .find(|g| g.requested_by == actor && g.state(now, cfg.quorum) == GrantState::Active)?;
    grant.actions_taken += 1;
    let id = grant.id.clone();
    drop(grants);
    sbproxy_observe::metrics::record_break_glass("used");
    Some(id)
}

/// Every grant, newest first, as JSON views.
pub(crate) fn list(now: DateTime<Utc>) -> serde_json::Value {
    let Some(cfg) = config() else {
        // Publish before returning, not after: this early return is the
        // only path that runs when the block is gone, and `refresh_gauges`
        // reads `config()` itself, so leaving the call below the return
        // made its zero-publish arm unreachable from every caller.
        //
        // Without this, removing `key_management` from the config left
        // `sbproxy_break_glass_open{state="awaiting_review"}` frozen at
        // whatever the last transition wrote, for the life of the process,
        // with the queue hidden from the route and no path able to move
        // the number. That is worse than the strand this branch removed:
        // unclosable *and* invisible.
        refresh_gauges();
        return json!({ "enabled": false, "grants": [] });
    };
    // The review queue is time-driven and every other transition is not, so
    // this read is the only thing that ever observes a grant lapsing. It has
    // to publish, or the gauge the overdue alert reads stays on whatever the
    // last approval left behind.
    refresh_gauges();
    let grants = registry().grants.lock();
    let mut views: Vec<serde_json::Value> = grants.iter().map(|g| g.view(now, &cfg)).collect();
    views.reverse();
    let awaiting = grants
        .iter()
        .filter(|g| g.state(now, cfg.quorum) == GrantState::AwaitingReview)
        .count();
    let overdue = grants
        .iter()
        .filter(|g| g.review_overdue(now, cfg.review_window_secs))
        .count();
    json!({
        "enabled": cfg.enabled,
        "quorum": cfg.quorum,
        "approvers": cfg.approvers,
        "max_ttl_secs": cfg.max_ttl_secs,
        "review_window_secs": cfg.review_window_secs,
        "awaiting_review": awaiting,
        "review_overdue": overdue,
        "grants": views,
    })
}

/// Republish the open-grant gauges. Called after every transition rather
/// than on a timer, so the dashboard reflects the last thing that happened
/// instead of the last time something scraped.
fn refresh_gauges() {
    let Some(cfg) = config() else {
        // No plane, so no route can move these. Publishing zero is the
        // only honest reading: `list()` has already stopped showing the
        // queue, `review()` answers `Disabled`, and an early return here
        // left `awaiting_review` frozen at whatever the last transition
        // wrote, for the life of the process, with nothing able to move
        // it. A frozen alert is worse than a silent one, because it reads
        // as an open grant nobody is closing.
        //
        // The grants are still in memory and come back with the block, so
        // this is "not currently observable", not "gone".
        for label in ["pending_approval", "active", "awaiting_review"] {
            sbproxy_observe::metrics::record_break_glass_open(label, 0.0);
        }
        return;
    };
    let now = Utc::now();
    let mut grants = registry().grants.lock();
    // Emit the time-driven transitions this read just observed, once each.
    // Without this the `expired` and `denied` events are declared and never
    // written, and a grant that quietly ran out with nobody approving or
    // reviewing anything never reaches `awaiting_review` on the gauge,
    // which is precisely the abandonment case the dashboard alerts on.
    for grant in grants.iter_mut() {
        if grant.terminal_counted {
            continue;
        }
        let event = match grant.state(now, cfg.quorum) {
            GrantState::AwaitingReview => "expired",
            GrantState::Denied => "denied",
            _ => continue,
        };
        grant.terminal_counted = true;
        sbproxy_observe::metrics::record_break_glass(event);
    }
    for label in ["pending_approval", "active", "awaiting_review"] {
        let count = grants
            .iter()
            .filter(|g| g.state(now, cfg.quorum).metric_label() == Some(label))
            .count();
        sbproxy_observe::metrics::record_break_glass_open(label, count as f64);
    }
}

/// Write one break-glass transition to the key audit channel.
///
/// The key channel rather than a new one: a break-glass grant exists to
/// reach keys and credentials, and a reviewer pulling that grant's session
/// wants the request, the approvals, and the mutations in one file rather
/// than in two that have to be joined on a timestamp.
fn audit(grant: &Grant, op: &str, outcome: &str) {
    audit_with_note(grant, op, outcome, "");
}

fn audit_with_note(grant: &Grant, op: &str, outcome: &str, note: &str) {
    let (context, after) = audit_payload(grant, note);
    sbproxy_observe::KeyAuditEntry::new(op, "break_glass", grant.id.clone())
        .with_actor(grant.requested_by.clone())
        .with_outcome(outcome)
        .with_context(context)
        .with_diff(None, Some(after))
        .emit();
}

/// The context string and the structured diff for one break-glass record.
///
/// A pure function returning both halves, rather than the body of
/// [`audit_with_note`], because the property that matters here is a
/// relationship between them and nothing else could see it. `with_context`
/// truncates to 256 bytes and `scope` is bounded two orders of magnitude
/// higher, so a grant with a large scope used to evict `approvals=`,
/// `ttl_secs=` and the reviewer's note out of the record: it dropped the
/// sign-off on exactly the grants most likely to want one. The fix is the
/// split below, and putting `scope.join(",")` or ` note={note}` back into
/// the context reddens `the_context_string_carries_counters_and_the_note_rides_the_diff`.
/// The route-level test can only see the `Grant` field and stays green
/// through that revert, which is why this exists.
fn audit_payload(grant: &Grant, note: &str) -> (String, serde_json::Value) {
    // Bounded counters only. Everything variable-length rides the diff,
    // which is not competing for the 256-byte budget.
    let context = format!(
        "scope_entries={} approvals={} ttl_secs={} actions={}",
        grant.scope.len(),
        grant.approvals.len(),
        grant.ttl_secs,
        grant.actions_taken,
    );
    let mut after = json!({
        "justification": grant.justification,
        "scope": grant.scope,
        "approvals": grant.approvals,
        "actions_taken": grant.actions_taken,
    });
    // The sign-off is the artifact the review exists to produce, so it
    // goes where nothing can crowd it out.
    if let Some(recorded) = grant.reviewed_note.as_ref().filter(|n| !n.is_empty()) {
        after["review_note"] = json!(recorded);
    } else if !note.trim().is_empty() {
        after["review_note"] = json!(sbproxy_util::truncate_utf8_with_marker(
            note,
            MAX_NOTE_BYTES,
            NOTE_TRUNCATED_MARKER
        ));
    }
    if let Some(reviewer) = &grant.reviewed_by {
        after["reviewed_by"] = json!(reviewer);
    }
    (context, after)
}

/// The two non-secret fields a refusal record needs, lifted off the grant
/// so the audit sink runs without the registry lock.
///
/// `emit()` writes a tracing line, pushes the ring, and appends a
/// keyed-HMAC entry to the chain on disk. Holding the grants mutex across
/// that made a stalled audit sink block every break-glass operation
/// including `list()`, while the success paths two lines below had always
/// dropped the lock first.
struct RefusedGrant {
    id: String,
    requested_by: String,
    approvals: usize,
}

impl RefusedGrant {
    fn of(grant: &Grant) -> Self {
        Self {
            id: grant.id.clone(),
            requested_by: grant.requested_by.clone(),
            approvals: grant.approvals.len(),
        }
    }

    /// Record a **refused** approval or review on the key audit channel.
    ///
    /// The controls this feature is bought for are the two refusals: a
    /// requester cannot approve their own grant and cannot close it out.
    /// Both return before the success-path [`audit`] is reached and
    /// `record_break_glass` counts successes only, so an operator caught
    /// trying to self-review left an HTTP 403 and nothing else. That is
    /// precisely the event a security reviewer opens this feature to find,
    /// and it was the one event the feature did not record.
    ///
    /// `actor` is the operator who was refused, which is not
    /// [`Self::requested_by`] in the roster case, so it is passed rather
    /// than read off the grant.
    ///
    /// `requested_by` is an unbounded operator string, checked only for
    /// non-emptiness, and `with_context` truncates at 256 bytes: a long
    /// actor id would evict `approvals=` off the end. So it is bounded
    /// here, the same way the transition record's context carries counters
    /// rather than the scope. The full value is on the structured diff,
    /// which is not competing for that budget.
    fn audit(&self, op: &str, actor: &str, reason: &'static str) {
        let (context, after) = self.payload(actor, reason);
        sbproxy_observe::KeyAuditEntry::new(op, "break_glass", self.id.clone())
            .with_actor(actor.to_string())
            .with_outcome("refused")
            .with_context(context)
            .with_diff(None, Some(after))
            .emit();
        sbproxy_observe::metrics::record_break_glass("refused");
    }

    /// The context string and diff for a refusal, split out for the same
    /// reason [`audit_payload`] is: the in-memory audit ring renders a
    /// record with no `before` as `"{resource}: {outcome}"`, so the ring
    /// can prove the record was written and cannot show what is in it.
    /// The reason vocabulary is checked here instead of through a route.
    fn payload(&self, actor: &str, reason: &'static str) -> (String, serde_json::Value) {
        (
            format!(
                "reason={reason} requested_by_len={} approvals={}",
                self.requested_by.len(),
                self.approvals
            ),
            json!({
                "reason": reason,
                "requested_by": self.requested_by,
                "refused_actor": actor,
            }),
        )
    }
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    registry().grants.lock().clear();
    registry()
        .registry_full_recorded
        .store(false, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split the reviewer's note depends on, at the only level that
    /// can see it.
    ///
    /// `with_context` truncates to 256 bytes. `scope` is bounded at 64
    /// entries of 256 bytes each, so a grant with a large scope used to
    /// evict `approvals=`, `ttl_secs=`, and the note itself out of the
    /// record: the sign-off vanished on exactly the grants most likely to
    /// want one. The fix moved everything variable-length onto the diff
    /// and left counters in the context.
    ///
    /// Putting `scope.join(",")` or ` note={note}` back into the context
    /// reddens this. The route-level test
    /// (`admin_keys::tests::a_reviewers_note_survives_a_large_scope`)
    /// reads `grant.reviewed_note` off the JSON response and stays green
    /// through that revert, which is why this test exists beside it.
    #[test]
    fn the_context_string_carries_counters_and_the_note_rides_the_diff() {
        let mut grant = grant_at("alice", 900);
        grant.scope = (0..40)
            .map(|i| format!("cred-with-a-long-name-{i:03}"))
            .collect();
        grant.approvals.insert("bob".to_string());
        grant.reviewed_by = Some("dave".to_string());

        let note = "SENTINEL-NOTE-4f2a rotation confirmed, no other credential touched";
        let (context, after) = audit_payload(&grant, note);

        assert!(
            context.len() < 256,
            "the context has to fit the 256-byte budget whole, or the fields after the \
             overflowing one are simply gone: {context}"
        );
        assert_eq!(
            context, "scope_entries=40 approvals=1 ttl_secs=900 actions=0",
            "counters only: anything variable-length here evicts what follows it"
        );
        for evicted in ["cred-with-a-long-name-000", "SENTINEL-NOTE-4f2a"] {
            assert!(
                !context.contains(evicted),
                "'{evicted}' must not compete for the context budget: {context}"
            );
        }

        assert_eq!(
            after["review_note"], note,
            "the sign-off is the artifact the review exists to produce and must reach the \
             record whole: {after}"
        );
        assert_eq!(after["scope"].as_array().map(Vec::len), Some(40), "{after}");
        assert_eq!(after["reviewed_by"], "dave", "{after}");
    }

    /// A refusal record names which rule refused it, and its context
    /// stays inside the 256-byte budget whatever the operator is called.
    ///
    /// `requested_by` is an unbounded operator string checked only for
    /// non-emptiness, and `with_context` truncates at 256 bytes, so
    /// interpolating it whole would evict `approvals=` off the end for a
    /// long actor id. That is the same defect this round fixed one
    /// function over, so the context carries its length and the value
    /// itself rides the diff.
    #[test]
    fn a_refusal_record_names_its_rule_and_bounds_its_context() {
        let refused = RefusedGrant {
            id: "bg_test".to_string(),
            requested_by: "a".repeat(4096),
            approvals: 2,
        };
        let (context, after) = refused.payload("mallory", "self_review");

        assert!(context.len() < 256, "{}", context.len());
        assert_eq!(
            context,
            "reason=self_review requested_by_len=4096 approvals=2"
        );
        assert!(
            context.contains("approvals=2"),
            "a long actor id must not evict the counters after it: {context}"
        );
        assert_eq!(after["reason"], "self_review", "{after}");
        assert_eq!(after["refused_actor"], "mallory", "{after}");
        assert_eq!(after["requested_by"].as_str().map(str::len), Some(4096));
    }

    /// A note past the cap says so rather than ending mid-sentence.
    #[test]
    fn an_over_long_note_is_marked_rather_than_silently_cut() {
        let mut grant = grant_at("alice", 900);
        grant.reviewed_by = Some("dave".to_string());
        let note = "x".repeat(MAX_NOTE_BYTES + 500);

        let (_, after) = audit_payload(&grant, &note);
        let recorded = after["review_note"].as_str().expect("a note");
        assert!(recorded.len() <= MAX_NOTE_BYTES, "{}", recorded.len());
        assert!(
            recorded.ends_with(NOTE_TRUNCATED_MARKER),
            "a sign-off missing its tail with no sign of it is the same defect this field \
             exists to fix, one order of magnitude up"
        );
    }

    fn grant_at(requested_by: &str, ttl: u64) -> Grant {
        Grant {
            id: "bg_test".to_string(),
            requested_by: requested_by.to_string(),
            justification: "prod incident 4412".to_string(),
            scope: vec!["cred-openai".to_string()],
            requested_at: Utc::now(),
            ttl_secs: ttl,
            approvals: BTreeSet::new(),
            activated_at: None,
            actions_taken: 0,
            reviewed_by: None,
            reviewed_at: None,
            reviewed_note: None,
            terminal_counted: false,
        }
    }

    /// A grant that reached quorum and then ran out of time is not simply
    /// gone: it lands on the review queue, and stays there until a human
    /// signs off. The alternative, silently closing it, is how an
    /// emergency path stops being reviewed.
    #[test]
    fn an_expired_grant_awaits_review_rather_than_closing() {
        let mut g = grant_at("alice", 60);
        let now = Utc::now();
        assert_eq!(g.state(now, 2), GrantState::PendingApproval);

        g.activated_at = Some(now - Duration::seconds(10));
        assert_eq!(g.state(now, 2), GrantState::Active);

        g.activated_at = Some(now - Duration::seconds(3600));
        assert_eq!(g.state(now, 2), GrantState::AwaitingReview);
        assert!(g.review_overdue(now, 60));
        assert!(!g.review_overdue(now, 86_400));

        g.reviewed_by = Some("bob".to_string());
        assert_eq!(g.state(now, 2), GrantState::Reviewed);
        assert!(!g.review_overdue(now, 60));
    }

    /// A request nobody approves does not sit pending forever. The
    /// approval window is the TTL, so a stale request cannot be approved
    /// weeks later by somebody who no longer remembers the incident.
    #[test]
    fn an_unapproved_request_is_denied_once_its_window_passes() {
        let mut g = grant_at("alice", 60);
        g.requested_at = Utc::now() - Duration::seconds(3600);
        assert_eq!(g.state(Utc::now(), 2), GrantState::Denied);
    }
}
