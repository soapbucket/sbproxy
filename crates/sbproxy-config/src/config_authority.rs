// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Durable publication state for a config authority: the revision
//! counter, the last two signed bundles, and the subscriber registry.
//!
//! The HTTP surface lives in the proxy runtime. This module owns only
//! what has to survive a restart, so the rules that make a fleet safe are
//! testable without a listener.
//!
//! # On-disk layout
//!
//! ```text
//! <store_dir>/
//!   authority-state.json      revision counters + subscriber registry
//!   revisions/current.json    the signed bundle subscribers fetch
//!   revisions/previous.json   the one before it, kept for rollback
//!   revisions/archive/<n>.json  bounded ring of earlier signed bundles
//! ```
//!
//! Every file is written to a temporary name in its own directory,
//! flushed, then renamed over the target, so a crash mid-write leaves the
//! old file or the new one and never a truncated one a later boot would
//! refuse.
//!
//! # Why the counter is reserved before the bundle is written
//!
//! A revision number is a promise: a subscriber that has applied
//! revision 7 refuses a later bundle that calls itself 7 with different
//! content, and refuses one that calls itself 6 at all. So the number can
//! never be reissued, not even across a crash.
//!
//! [`AuthorityStore::reserve_revision`] therefore persists the new high
//! water mark *before* the bundle exists, and
//! [`AuthorityStore::commit`] persists the bundle afterwards. A crash
//! between the two burns a number: `high_water_revision` is 8 while
//! `revisions/current.json` still holds 7, and the next publication is 9.
//! Gaps are free, because a subscriber's cursor only requires that
//! revisions increase. Doing it the other way round would let a crash
//! reissue 8 with different content, which every subscriber that already
//! fetched the first 8 would then refuse forever.
//!
//! Validation runs before the reservation, so a config that does not
//! compile consumes no number at all.
//!
//! [`AuthorityStore::commit`] writes the bundle file before the state file
//! names it, so the other crash window leaves a bundle nothing points at.
//! That one is repaired at open rather than refused: the reservation
//! already covered the number, so nothing else can claim it, and the file
//! on disk is the one that was signed.
//!
//! # The archive ring sits beside the two slots, not in place of them
//!
//! `current.json` and `previous.json` are load bearing: the crash-repair
//! rules above and the reserve-before-commit ordering that makes a
//! revision number a promise are both written in terms of them. So
//! `revisions/archive/` is additive. [`AuthorityStore::commit`] writes
//! the same signed bundle bytes it puts in `current.json` into
//! `revisions/archive/<revision>.json`, and the two slots keep exactly
//! the contents they had before this ring existed.
//!
//! The ring exists so a fleet rollback can name a revision from further
//! back than one step. `previous.json` answers "undo the last publish";
//! the archive answers "go back to what we were running on Tuesday".
//! Rolling back to an archived revision is still a *forward* publish of
//! that revision's payload under a fresh number, for the same
//! anti-replay reason a one-step rollback is: see
//! [`AuthorityStore::archived`].
//!
//! `archive` in the state file names which revisions the ring holds, in
//! ascending order, and the write ordering matches the one
//! [`AuthorityStore::commit`] already uses: the archive file is written
//! before the state file names it, so the crash window leaves a file
//! nothing points at rather than a pointer at a file that is not there.
//! [`AuthorityStore::open`] repairs that window by adopting any archive
//! file whose revision was reserved, then trimming back to the bound.
//! Eviction persists the shrunk list before it unlinks anything, so the
//! only residue a crash can leave is a file the list no longer names,
//! which the next open adopts and evicts again.
//!
//! # Credentials
//!
//! A subscriber authenticates with a bearer token shaped
//! `sbca1.<credential_id>.<secret>`, the same three-part form the cluster
//! enrollment tokens use. Only `SHA-256` of the whole token is stored, and
//! the comparison is constant time, so the registry file is not a
//! credential store: an attacker who reads it cannot authenticate with
//! it.
//!
//! Unlike an enrollment token, a subscriber credential is long-lived and
//! reusable. Enrollment is a one-shot bootstrap; a subscriber presents its
//! credential on every poll for the life of the node, so there is no
//! consumption step. Revocation is the way one is retired.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use crate::config_bundle::{is_valid_bundle_identifier, SignedConfigBundle};

/// Current on-disk schema version for `authority-state.json`.
pub const AUTHORITY_STATE_SCHEMA_VERSION: u32 = 1;

/// Prefix on every subscriber credential, naming the token format.
///
/// Sits alongside the cluster enrollment prefix `sbce1`. A distinct prefix
/// means a token pasted into the wrong field is rejected on shape rather
/// than tried against the wrong store.
pub const SUBSCRIBER_TOKEN_PREFIX: &str = "sbca1";

/// Bytes of entropy in the credential identifier half of a token.
pub const CREDENTIAL_ID_BYTES: usize = 12;

/// Bytes of entropy in the secret half of a token.
pub const CREDENTIAL_SECRET_BYTES: usize = 32;

/// Most subscribers one authority may register.
///
/// A fleet larger than this wants a hosted control plane rather than one
/// process holding every credential in a JSON file, and the bound keeps a
/// runaway registration loop from growing the state file without limit.
pub const MAX_SUBSCRIBERS: usize = 10_000;

/// Largest accepted subscriber identifier, in bytes.
const MAX_SUBSCRIBER_ID_BYTES: usize = 128;

/// Largest accepted `authority-state.json`, in bytes.
///
/// Ten mebibytes is far above [`MAX_SUBSCRIBERS`] records and still small
/// enough that a corrupt or hostile file cannot exhaust memory at boot.
const MAX_STATE_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Largest accepted stored bundle file, in bytes. Matches the envelope
/// bound a subscriber applies on the wire.
const MAX_STORED_BUNDLE_BYTES: u64 =
    2 * crate::config_bundle::MAX_CONFIG_YAML_BYTES as u64 + 65_536;

/// Worst-case bytes the archive ring can occupy at [`MAX_ARCHIVE_KEEP`].
///
/// Written down rather than left to be discovered on a full disk. One
/// archived file is bounded by the same envelope limit a subscriber
/// applies on the wire, which is twice
/// [`MAX_CONFIG_YAML_BYTES`](crate::config_bundle::MAX_CONFIG_YAML_BYTES)
/// (4 MiB) plus 64 KiB of envelope, so 8.06 MiB. The ring holds one
/// file more than `archive_keep`, because the revision being served is
/// stored too and only becomes a rollback target once something else
/// publishes. At the 200-target ceiling that is 201 files, so 1.58
/// GiB, and at the [`DEFAULT_ARCHIVE_KEEP`] of 20 it is 21 files, so
/// 169 MiB. Those are ceilings for a configuration document at the
/// 4 MiB wire limit; a real `sb.yml` runs four orders of magnitude
/// smaller, so the default ring costs kilobytes in practice.
pub const MAX_ARCHIVE_BYTES: u64 =
    MAX_STORED_BUNDLE_BYTES * archive_files_for(MAX_ARCHIVE_KEEP) as u64;

/// State file name inside the store directory.
const STATE_FILE: &str = "authority-state.json";

/// Subdirectory holding the served bundles.
const REVISIONS_DIR: &str = "revisions";

/// The bundle subscribers currently fetch.
const CURRENT_BUNDLE_FILE: &str = "current.json";

/// The bundle before the current one, kept so a later change can offer a
/// one-step rollback without re-deriving it.
const PREVIOUS_BUNDLE_FILE: &str = "previous.json";

/// Subdirectory under `revisions/` holding the bounded archive ring.
const ARCHIVE_DIR: &str = "archive";

/// How many **earlier** revisions the archive ring keeps when nothing
/// says otherwise.
///
/// Twenty publications is roughly a busy month of platform changes, and
/// at the worst case one payload can reach it is well under a gigabyte
/// (see [`MAX_ARCHIVE_BYTES`]). An operator who wants a longer memory
/// raises `proxy.config_authority.publish.archive_keep`; one who wants
/// none sets it to zero and keeps the one-step rollback that
/// `previous.json` has always offered.
pub const DEFAULT_ARCHIVE_KEEP: usize = 20;

/// Largest accepted `archive_keep`.
///
/// The bound is a disk-footprint bound, not a correctness one: see
/// [`MAX_ARCHIVE_BYTES`] for the arithmetic it caps.
pub const MAX_ARCHIVE_KEEP: usize = 200;

/// Files the ring holds at a given `archive_keep`, which is one more
/// than the number of rollback targets.
///
/// `archive_keep` counts revisions an operator can roll *back to*, so
/// the revision currently being served does not count against it: a
/// rollback to what is already running is a no-op republish, and a
/// bound that counted it made `archive_keep: 1` advertise exactly one
/// target that could never do anything. The ring stores the current
/// revision anyway, because it becomes an earlier revision the moment
/// anything else publishes. `archive_keep: 0` keeps no ring at all and
/// never reaches this.
const fn archive_files_for(keep: usize) -> usize {
    keep + 1
}

/// Random material a caller supplies when minting one subscriber
/// credential.
///
/// Passed in rather than generated here so this crate needs no random
/// number generator, and so a test can mint a credential deterministically
/// and still exercise the real hashing and comparison.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSeed {
    credential_id: [u8; CREDENTIAL_ID_BYTES],
    secret: [u8; CREDENTIAL_SECRET_BYTES],
}

impl std::fmt::Debug for CredentialSeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialSeed")
            .field("credential_id", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl CredentialSeed {
    /// Build a seed from two independent pieces of random material.
    ///
    /// Both must come from a cryptographic random source. The identifier
    /// is not secret, but it must be unpredictable enough not to collide,
    /// and deriving it from the secret would leak the secret's entropy
    /// into a value the registry stores in the clear.
    #[must_use]
    pub const fn new(
        credential_id: [u8; CREDENTIAL_ID_BYTES],
        secret: [u8; CREDENTIAL_SECRET_BYTES],
    ) -> Self {
        Self {
            credential_id,
            secret,
        }
    }

    /// Clear-text credential identifier, as it appears in the token and
    /// in the registry.
    #[must_use]
    pub fn credential_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.credential_id)
    }

    /// The clear token this seed produces.
    fn token(&self) -> String {
        format!(
            "{SUBSCRIBER_TOKEN_PREFIX}.{}.{}",
            self.credential_id(),
            URL_SAFE_NO_PAD.encode(self.secret),
        )
    }
}

/// One freshly minted credential. The clear token exists only here and is
/// never stored, so it can be shown to an operator exactly once.
pub struct IssuedSubscriberCredential {
    token: String,
    record: SubscriberRecord,
}

impl std::fmt::Debug for IssuedSubscriberCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedSubscriberCredential")
            .field("token", &"<redacted>")
            .field("record", &self.record)
            .finish()
    }
}

impl IssuedSubscriberCredential {
    /// The clear token to hand to the subscriber. Not recoverable later.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Take the clear token, consuming the issue receipt.
    #[must_use]
    pub fn into_token(self) -> String {
        self.token
    }

    /// The durable record this credential created.
    #[must_use]
    pub const fn record(&self) -> &SubscriberRecord {
        &self.record
    }
}

/// One registered subscriber: its credential fingerprint, its revocation
/// state, and the revision it was last seen holding.
///
/// The credential fingerprint is deliberately private. This type is the
/// natural thing for an admin endpoint to render, and a public field would
/// make leaking the fingerprint into a response the default rather than a
/// mistake someone had to make.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriberRecord {
    /// Stable identity the subscriber presents in
    /// `x-sbproxy-subscriber-id`.
    subscriber_id: String,
    /// Clear-text identifier of this credential, the middle token field.
    credential_id: String,
    /// URL-safe base64 SHA-256 of the whole clear token.
    token_sha256: String,
    /// When the credential was minted, in unix milliseconds.
    created_at_unix_ms: u64,
    /// When it was revoked, if it was.
    #[serde(default)]
    revoked_at_unix_ms: Option<u64>,
    /// Highest revision this subscriber has been served. Persisted,
    /// because it is the answer to "did the fleet take the change?" and
    /// that answer must survive an authority restart.
    #[serde(default)]
    last_seen_revision: u64,
    /// When it last fetched, in unix milliseconds. In memory only: a poll
    /// that changes nothing must not cost a disk write, and a fleet of a
    /// thousand nodes polling every five seconds otherwise turns the state
    /// file into a write-amplifier.
    #[serde(default, skip_serializing)]
    last_seen_at_unix_ms: Option<u64>,
    /// What this subscriber last said it **applied** (WOR-2464), as
    /// distinct from what it was served. `None` for a subscriber that
    /// has never reported one: an older build, or one that has not
    /// polled since this authority started.
    #[serde(default)]
    applied: Option<SubscriberApplyReport>,
}

impl std::fmt::Debug for SubscriberRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubscriberRecord")
            .field("subscriber_id", &self.subscriber_id)
            .field("credential_id", &self.credential_id)
            .field("token_sha256", &"<redacted>")
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field("revoked_at_unix_ms", &self.revoked_at_unix_ms)
            .field("last_seen_revision", &self.last_seen_revision)
            .field("last_seen_at_unix_ms", &self.last_seen_at_unix_ms)
            .field("applied", &self.applied)
            .finish()
    }
}

impl SubscriberRecord {
    /// Stable identity the subscriber presents.
    #[must_use]
    pub fn subscriber_id(&self) -> &str {
        &self.subscriber_id
    }

    /// Clear-text identifier of this credential.
    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// When the credential was minted, in unix milliseconds.
    #[must_use]
    pub const fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    /// When the credential was revoked, in unix milliseconds.
    #[must_use]
    pub const fn revoked_at_unix_ms(&self) -> Option<u64> {
        self.revoked_at_unix_ms
    }

    /// Whether the credential has been revoked.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked_at_unix_ms.is_some()
    }

    /// Highest revision this subscriber has been served.
    #[must_use]
    pub const fn last_seen_revision(&self) -> u64 {
        self.last_seen_revision
    }

    /// When the subscriber last fetched, in unix milliseconds. `None`
    /// after an authority restart, because receipt times are not
    /// persisted.
    #[must_use]
    pub const fn last_seen_at_unix_ms(&self) -> Option<u64> {
        self.last_seen_at_unix_ms
    }

    /// What this subscriber last reported it applied (WOR-2464).
    ///
    /// `None` means **unknown**, not "applied". A subscriber on an older
    /// build sends no report and must not be rendered as healthy: a
    /// status page that showed "applied" for a node that has never said
    /// so is worse than one that says nothing, because it answers the
    /// rollout question wrongly with confidence.
    #[must_use]
    pub const fn applied(&self) -> Option<&SubscriberApplyReport> {
        self.applied.as_ref()
    }
}

/// How a subscriber's last apply attempt went, in OpenTelemetry OpAMP's
/// `RemoteConfigStatus` vocabulary (WOR-2464).
///
/// OpAMP settled this shape already: a last remote config hash, a status
/// of `APPLYING` / `APPLIED` / `FAILED`, and an error message. Reusing
/// those semantics rather than inventing a fourth spelling costs nothing
/// now and keeps the door open if this ever speaks OpAMP properly.
///
/// One value is ours: [`Self::AppliedDegraded`]. The node already
/// distinguishes a clean apply from one that published while a subsystem
/// stayed on prior state (`ReloadOutcome::is_fully_applied`), the two
/// counters are disjoint on the node, and folding them together on the
/// trip upstream would hide exactly the reload an operator most needs to
/// see. OpAMP has no such value, so a future OpAMP bridge maps this onto
/// `APPLIED` and carries the detail in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    /// A candidate is in flight: fetched and being applied.
    Applying,
    /// Applied cleanly.
    Applied,
    /// Published, with at least one subsystem left on prior state.
    AppliedDegraded,
    /// Refused. The node keeps serving what it had.
    Failed,
}

impl ApplyStatus {
    /// The wire label, identical to what serde writes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::AppliedDegraded => "applied_degraded",
            Self::Failed => "failed",
        }
    }

    /// Parse one wire label. `None` for anything else, which is how an
    /// unknown value from a newer or hostile subscriber is dropped
    /// rather than stored.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "applying" => Some(Self::Applying),
            "applied" => Some(Self::Applied),
            "applied_degraded" => Some(Self::AppliedDegraded),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Longest error message an authority stores from a subscriber
/// (WOR-2464).
///
/// The message is subscriber-supplied text that lands in an
/// admin-facing status page and in the authority's own state file, so it
/// is bounded at the trust boundary rather than trusted to be short. The
/// same 512-byte ceiling the decision-audit `reason` field and
/// `RejectionMetadata::detail` already use.
pub const MAX_APPLY_ERROR_CHARS: usize = 512;

/// What one subscriber last told this authority it applied (WOR-2464).
///
/// # Seen is not applied
///
/// Before this existed, the authority tracked only the revision each
/// subscriber was **served**. A fleet where three nodes fetched r42,
/// refused it on `compile_failed`, and kept serving r41 looked identical
/// from here to a fleet that applied it cleanly, and the operator found
/// out from a customer. This is the node's own answer coming back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriberApplyReport {
    /// How the last attempt went.
    pub status: ApplyStatus,
    /// The revision the node is **actually serving**. On a refusal this
    /// stays at the revision it kept serving rather than moving to the
    /// one it refused, which is the whole point.
    pub revision: u64,
    /// Content digest of that revision.
    pub config_hash: String,
    /// Why the last attempt failed, bounded to
    /// [`MAX_APPLY_ERROR_CHARS`]. Absent on every non-failure.
    #[serde(default)]
    pub error: Option<String>,
    /// The node's own soak verdict for what it is serving, when it runs
    /// a soak: `successful`, `failed`, or `inconclusive`. Absent on a
    /// node with `proxy.config_history` off, which is most of them.
    #[serde(default)]
    pub soak_verdict: Option<String>,
    /// Whether the node is serving a configuration its boot fallback
    /// rescued from its own ring rather than the one it was handed. A
    /// node in that state applies authority bundles but has a local
    /// document underneath that does not work, which is a different
    /// problem from a refusal and needs saying separately.
    #[serde(default)]
    pub fallback_active: bool,
    /// When this report arrived, in unix milliseconds.
    ///
    /// In memory only, like [`SubscriberRecord::last_seen_at_unix_ms`]
    /// and for the same reason: it changes on every poll, and a fleet of
    /// a thousand nodes polling every thirty seconds would otherwise
    /// turn the state file into a write amplifier. An authority restart
    /// therefore reports the applied revision it persisted with no
    /// arrival time, which the status page renders as an unknown poll
    /// state until the next poll.
    #[serde(default, skip_serializing)]
    pub reported_at_unix_ms: Option<u64>,
}

impl SubscriberApplyReport {
    /// Whether the durable half of two reports differs.
    ///
    /// The arrival time is deliberately excluded: it changes on every
    /// poll and persisting it is the write amplification this type's
    /// documentation refuses.
    #[must_use]
    pub fn durable_part_differs(&self, other: &Self) -> bool {
        self.status != other.status
            || self.revision != other.revision
            || self.config_hash != other.config_hash
            || self.error != other.error
            || self.soak_verdict != other.soak_verdict
            || self.fallback_active != other.fallback_active
    }

    /// Bound the free-text fields at the trust boundary.
    fn bounded(mut self) -> Self {
        self.error = self
            .error
            .map(|error| truncate_chars(&error, MAX_APPLY_ERROR_CHARS));
        self.soak_verdict = self
            .soak_verdict
            .map(|verdict| truncate_chars(&verdict, 32));
        self.config_hash = truncate_chars(&self.config_hash, 128);
        self
    }
}

/// Truncate on a character boundary, appending an ellipsis marker when
/// anything was dropped.
fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let kept: String = value.chars().take(limit).collect();
    format!("{kept}...")
}

/// Why a presented subscriber credential was refused.
///
/// Coarse on purpose where it has to be: [`Self::Invalid`] covers an
/// unparseable token, an unknown credential ID, and a wrong secret alike,
/// so a caller cannot use the response to learn which credential IDs
/// exist. [`Self::Revoked`] is distinguishable because reaching it
/// requires already holding a valid token, and telling that operator
/// "revoked" instead of "invalid" is what saves an hour of debugging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SubscriberAuthError {
    /// The token was malformed, unknown, or did not match.
    #[error("subscriber credential is invalid")]
    Invalid,
    /// The credential authenticated but has been revoked.
    #[error("subscriber credential has been revoked")]
    Revoked,
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityStoreError {
    /// One bounded semantic rule failed.
    #[error("invalid config authority store operation: {0}")]
    Invalid(String),
    /// Durable state on disk failed validation and was not overwritten.
    #[error("config authority store state is corrupt: {0}")]
    Corrupt(String),
    /// A bundle offered for commit did not match the reserved revision.
    #[error("config authority cannot commit revision {found}; revision {expected} was reserved. Reserve a revision and commit that same revision, so a number is never reissued")]
    RevisionMismatch {
        /// Revision the store reserved.
        expected: u64,
        /// Revision the offered bundle carries.
        found: u64,
    },
    /// The store already holds as many subscribers as it accepts.
    #[error("config authority already holds {MAX_SUBSCRIBERS} subscribers, the accepted maximum; revoke a credential before registering another")]
    TooManySubscribers,
    /// Filesystem access failed.
    #[error("config authority store file access failed: {0}")]
    Io(#[from] std::io::Error),
    /// Strict JSON processing failed.
    #[error("config authority store JSON {operation} failed: {source}")]
    Json {
        /// Stable operation label.
        operation: &'static str,
        /// JSON parser or encoder failure.
        source: serde_json::Error,
    },
}

impl AuthorityStoreError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    fn json(operation: &'static str, source: serde_json::Error) -> Self {
        Self::Json { operation, source }
    }
}

/// Durable counters and subscriber registry, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityState {
    /// On-disk schema version.
    schema_version: u32,
    /// Authority identity that owns this directory.
    authority_id: String,
    /// Highest revision ever reserved. Never decreases, so a crash
    /// between reservation and commit burns a number rather than reissuing
    /// one.
    high_water_revision: u64,
    /// Revision `revisions/current.json` holds. Zero means nothing has
    /// been published yet.
    current_revision: u64,
    /// Registered subscribers, keyed by clear-text credential ID.
    #[serde(default)]
    subscribers: BTreeMap<String, SubscriberRecord>,
    /// Revisions the archive ring holds, ascending.
    ///
    /// `#[serde(default)]` so a state file written before the ring
    /// existed opens as an empty archive rather than as a corrupt file.
    #[serde(default)]
    archive: Vec<u64>,
}

impl AuthorityState {
    fn new(authority_id: &str) -> Self {
        Self {
            schema_version: AUTHORITY_STATE_SCHEMA_VERSION,
            authority_id: authority_id.to_string(),
            high_water_revision: 0,
            current_revision: 0,
            subscribers: BTreeMap::new(),
            archive: Vec::new(),
        }
    }

    fn validate(&self, authority_id: &str) -> Result<(), AuthorityStoreError> {
        if self.schema_version != AUTHORITY_STATE_SCHEMA_VERSION {
            return Err(AuthorityStoreError::Corrupt(format!(
                "schema_version {} is not the supported {AUTHORITY_STATE_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.authority_id != authority_id {
            return Err(AuthorityStoreError::Corrupt(format!(
                "store belongs to authority {:?} but this node is {authority_id:?}; point \
                 publish.store_dir at this authority's own directory rather than reusing \
                 another's, or the revision counter and the subscriber registry belong to \
                 someone else",
                self.authority_id
            )));
        }
        if self.current_revision > self.high_water_revision {
            return Err(AuthorityStoreError::Corrupt(format!(
                "current_revision {} exceeds high_water_revision {}",
                self.current_revision, self.high_water_revision
            )));
        }
        if self.subscribers.len() > MAX_SUBSCRIBERS {
            return Err(AuthorityStoreError::Corrupt(format!(
                "{} subscribers exceeds the {MAX_SUBSCRIBERS} maximum",
                self.subscribers.len()
            )));
        }
        for (credential_id, record) in &self.subscribers {
            if record.credential_id != *credential_id {
                return Err(AuthorityStoreError::Corrupt(format!(
                    "subscriber record keyed {credential_id:?} carries credential_id {:?}",
                    record.credential_id
                )));
            }
            if record.token_sha256.is_empty() {
                return Err(AuthorityStoreError::Corrupt(format!(
                    "subscriber {credential_id:?} carries no credential fingerprint"
                )));
            }
        }
        // The archive names revisions this authority reserved, in
        // ascending order and each one once. A list that fails either
        // rule came from somewhere other than this store's own commit
        // path, and adopting it would let a rollback target a number the
        // counter never handed out.
        if self.archive.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(AuthorityStoreError::Corrupt(
                "the archive list is not strictly ascending".to_string(),
            ));
        }
        if let Some(highest) = self.archive.last() {
            if *highest > self.high_water_revision {
                return Err(AuthorityStoreError::Corrupt(format!(
                    "the archive names revision {highest} but only {} was ever reserved",
                    self.high_water_revision
                )));
            }
        }
        Ok(())
    }
}

/// Durable publication state and subscriber registry for one config
/// authority.
///
/// Not internally synchronized: one process owns one store directory, and
/// the runtime wraps this in a mutex. Two processes pointed at the same
/// directory would each hold their own copy of the counters and reissue
/// revisions, which is why [`Self::open`] pins the directory to an
/// `authority_id` and refuses a directory another authority wrote.
#[derive(Debug)]
pub struct AuthorityStore {
    directory: PathBuf,
    state: AuthorityState,
    current: Option<SignedConfigBundle>,
    previous: Option<SignedConfigBundle>,
    /// How many archived revisions the ring keeps. Clamped to
    /// [`MAX_ARCHIVE_KEEP`] at open.
    archive_keep: usize,
}

impl AuthorityStore {
    /// Open, or create, the store directory for `authority_id`.
    ///
    /// Creates the directory tree when it is absent, so a first boot needs
    /// no provisioning step. An existing directory is validated and its
    /// counters adopted; a directory written by a different authority is
    /// refused rather than adopted.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Invalid`] when `authority_id` is not
    /// a usable identifier, [`AuthorityStoreError::Corrupt`] when the
    /// state file fails validation, and [`AuthorityStoreError::Io`] or
    /// [`AuthorityStoreError::Json`] when the directory cannot be read or
    /// a file does not decode.
    pub fn open(
        directory: impl AsRef<Path>,
        authority_id: &str,
    ) -> Result<Self, AuthorityStoreError> {
        Self::open_with_archive_keep(directory, authority_id, DEFAULT_ARCHIVE_KEEP)
    }

    /// [`Self::open`] with an explicit archive ring bound.
    ///
    /// `archive_keep` is clamped to [`MAX_ARCHIVE_KEEP`]. Zero keeps no
    /// archive at all, which leaves the store behaving exactly as it did
    /// before the ring existed: `current.json`, `previous.json`, and a
    /// one-step rollback.
    ///
    /// # Errors
    ///
    /// As [`Self::open`], plus [`AuthorityStoreError::Corrupt`] when the
    /// archive directory holds a file the state file cannot account for.
    pub fn open_with_archive_keep(
        directory: impl AsRef<Path>,
        authority_id: &str,
        archive_keep: usize,
    ) -> Result<Self, AuthorityStoreError> {
        if !is_valid_bundle_identifier(authority_id) {
            return Err(AuthorityStoreError::invalid(
                "authority_id is empty, invalid, or oversized",
            ));
        }
        let directory = directory.as_ref().to_path_buf();
        create_private_dirs(&directory)?;
        let state_path = directory.join(STATE_FILE);
        let (state, claim_directory) = match read_bounded(&state_path, MAX_STATE_FILE_BYTES)? {
            Some(bytes) => {
                let state: AuthorityState = serde_json::from_slice(&bytes).map_err(|source| {
                    AuthorityStoreError::json("decode authority state", source)
                })?;
                state.validate(authority_id)?;
                (state, false)
            }
            // A directory with no state file has never been claimed. Write
            // the state out now rather than waiting for the first publish,
            // so the `authority_id` pin exists from the moment the
            // directory is opened. Otherwise two authorities can both open
            // the same empty directory and only discover the collision
            // later, once one of them has published into it.
            None => (AuthorityState::new(authority_id), true),
        };
        let current = read_bundle(&bundle_path(&directory, CURRENT_BUNDLE_FILE))?;
        let previous = read_bundle(&bundle_path(&directory, PREVIOUS_BUNDLE_FILE))?;
        let mut store = Self {
            directory,
            state,
            current,
            previous,
            archive_keep: archive_keep.min(MAX_ARCHIVE_KEEP),
        };
        store.reconcile_current_bundle()?;
        store.reconcile_archive()?;
        if claim_directory {
            let state = store.state.clone();
            store.save_state(&state)?;
        }
        Ok(store)
    }

    /// Reconcile the state file's archive list with the files actually in
    /// `revisions/archive/`.
    ///
    /// [`Self::commit`] writes the archive file before the state file
    /// names it, so a crash between the two leaves a file nothing points
    /// at. That is adopted rather than deleted: the reservation already
    /// covered the number, so nothing else can ever claim it, and the
    /// file on disk is the one that was signed. A listed revision whose
    /// file is gone is dropped from the list, because an archive is a
    /// convenience and an operator who deleted a file meant it, unlike
    /// `current.json`, which the authority is actively serving.
    ///
    /// The reconciled list is then trimmed to `archive_keep`, so lowering
    /// the bound takes effect at the next open rather than waiting for
    /// enough publications to push the old entries out.
    fn reconcile_archive(&mut self) -> Result<(), AuthorityStoreError> {
        let on_disk = self.scan_archive_dir()?;
        let mut adopted: Vec<u64> = Vec::new();
        for revision in &on_disk {
            if *revision > self.state.high_water_revision {
                // A file claiming a number this authority never reserved
                // did not come from this store. Refusing is the same call
                // `reconcile_current_bundle` makes for the same shape.
                return Err(AuthorityStoreError::Corrupt(format!(
                    "{} holds revision {revision} but only {} was ever reserved",
                    archive_path(&self.directory, *revision).display(),
                    self.state.high_water_revision
                )));
            }
            adopted.push(*revision);
        }
        let trimmed: Vec<u64> = adopted
            .iter()
            .rev()
            .take(archive_files_for(self.archive_keep))
            .rev()
            .copied()
            .collect();
        let evicted: Vec<u64> = adopted
            .iter()
            .filter(|revision| !trimmed.contains(revision))
            .copied()
            .collect();
        if trimmed == self.state.archive && evicted.is_empty() {
            return Ok(());
        }
        if adopted != self.state.archive {
            tracing::warn!(
                recorded = self.state.archive.len(),
                on_disk = adopted.len(),
                "config authority archive list did not match the files on disk; adopting the \
                 files, which are the ones that were signed",
            );
        }
        let mut next = self.state.clone();
        next.archive = trimmed;
        // Persist the shrunk list before unlinking, so the only residue a
        // crash here can leave is a file nothing names, which the next
        // open adopts and evicts again.
        self.save_state(&next)?;
        self.state = next;
        self.remove_archived(&evicted);
        Ok(())
    }

    /// Every `<revision>.json` in the archive directory, ascending.
    ///
    /// Anything that is not a decimal revision followed by `.json` is
    /// ignored rather than refused: the directory is on an operator's
    /// disk, and a stray editor swap file is not a corruption signal.
    fn scan_archive_dir(&self) -> Result<Vec<u64>, AuthorityStoreError> {
        let dir = self.directory.join(REVISIONS_DIR).join(ARCHIVE_DIR);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut revisions = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            let Ok(revision) = stem.parse::<u64>() else {
                continue;
            };
            // Only the canonical spelling. `007.json` and `+7.json`
            // both parse as 7, and a backup tool that zero-pads would
            // leave two files naming one revision: `reconcile_archive`
            // would adopt `[7, 7]`, persist it, and the next open would
            // refuse the state file this store wrote itself, because
            // the archive list has to be strictly ascending.
            if revision.to_string() != stem {
                continue;
            }
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            revisions.push(revision);
        }
        revisions.sort_unstable();
        // Belt and braces: the canonical-spelling filter above already
        // makes a duplicate unreachable, and an invariant the next open
        // refuses on is worth not depending on one filter alone.
        revisions.dedup();
        Ok(revisions)
    }

    /// Unlink archived bundles, logging rather than failing: an archive
    /// file that outlives its eviction is an orphan the next open cleans
    /// up, and failing a commit over it would be worse.
    fn remove_archived(&self, revisions: &[u64]) {
        for revision in revisions {
            let path = archive_path(&self.directory, *revision);
            if let Err(error) = std::fs::remove_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        error = %error,
                        path = %path.display(),
                        "could not evict an archived config revision; it will be evicted again \
                         at the next open",
                    );
                }
            }
        }
    }

    /// Reconcile the state file's `current_revision` with the bundle that is
    /// actually on disk.
    ///
    /// [`Self::commit`] writes the bundle file and then names it in the
    /// state file, so a crash between the two leaves a bundle nothing
    /// points at. That is recoverable rather than corrupt: the reservation
    /// already covered that number, so no other bundle can ever claim it,
    /// and the file on disk is the one that was signed. The counter is
    /// repaired to match it.
    ///
    /// The two directions that are not recoverable are a state file naming
    /// a bundle that is not there (someone deleted it, and the authority
    /// would otherwise report a current revision while answering `404`) and
    /// a bundle claiming a number that was never reserved (which means the
    /// state file and the bundle came from different stores).
    fn reconcile_current_bundle(&mut self) -> Result<(), AuthorityStoreError> {
        let current_path = bundle_path(&self.directory, CURRENT_BUNDLE_FILE);
        let Some(on_disk) = self.current.as_ref().map(|signed| signed.bundle.revision) else {
            if self.state.current_revision > 0 {
                return Err(AuthorityStoreError::Corrupt(format!(
                    "state claims revision {} is published but {} is missing",
                    self.state.current_revision,
                    current_path.display()
                )));
            }
            return Ok(());
        };
        if on_disk == self.state.current_revision {
            return Ok(());
        }
        if on_disk < self.state.current_revision || on_disk > self.state.high_water_revision {
            return Err(AuthorityStoreError::Corrupt(format!(
                "{} holds revision {on_disk} but the state file claims {} is current and {} is \
                 the highest ever reserved",
                current_path.display(),
                self.state.current_revision,
                self.state.high_water_revision
            )));
        }
        tracing::warn!(
            path = %current_path.display(),
            published = on_disk,
            recorded = self.state.current_revision,
            "config authority store was interrupted between writing a bundle and recording it; \
             adopting the bundle on disk, which is the one that was signed",
        );
        let mut next = self.state.clone();
        next.current_revision = on_disk;
        self.save_state(&next)?;
        self.state = next;
        Ok(())
    }

    /// Directory this store owns.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Authority identity this store is pinned to.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.state.authority_id
    }

    /// Revision currently served. Zero means nothing has been published.
    #[must_use]
    pub const fn current_revision(&self) -> u64 {
        self.state.current_revision
    }

    /// Highest revision ever reserved, published or burned by a crash.
    #[must_use]
    pub const fn high_water_revision(&self) -> u64 {
        self.state.high_water_revision
    }

    /// The signed bundle subscribers currently fetch.
    #[must_use]
    pub fn current(&self) -> Option<&SignedConfigBundle> {
        self.current.as_ref()
    }

    /// The signed bundle published before the current one.
    #[must_use]
    pub fn previous(&self) -> Option<&SignedConfigBundle> {
        self.previous.as_ref()
    }

    /// Revisions the archive ring holds, ascending.
    ///
    /// This is what a refusal lists when a rollback names a revision the
    /// ring no longer has, so an operator reading the error can pick a
    /// target that exists rather than guessing again.
    #[must_use]
    pub fn archived_revisions(&self) -> &[u64] {
        &self.state.archive
    }

    /// How many revisions this ring keeps.
    #[must_use]
    pub const fn archive_keep(&self) -> usize {
        self.archive_keep
    }

    /// Read one archived signed bundle back off disk.
    ///
    /// `Ok(None)` means the ring does not hold that revision, which is
    /// the ordinary answer for anything older than the ring bound. The
    /// bundle comes back exactly as it was signed; republishing its
    /// payload is [`crate::config_authority`]'s caller's job, and it goes
    /// out under a **new** revision number because a subscriber's cursor
    /// refuses a repeat of one it has already applied.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Corrupt`] when the file is there
    /// but does not decode, and [`AuthorityStoreError::Io`] when it
    /// cannot be read.
    pub fn archived(
        &self,
        revision: u64,
    ) -> Result<Option<SignedConfigBundle>, AuthorityStoreError> {
        if !self.state.archive.contains(&revision) {
            return Ok(None);
        }
        read_bundle(&archive_path(&self.directory, revision))
    }

    /// Reserve the next revision number and persist the reservation.
    ///
    /// Call this only after the payload has passed validation: a reserved
    /// number is spent whether or not the commit that follows succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Invalid`] when the counter would
    /// overflow, and [`AuthorityStoreError::Io`] or
    /// [`AuthorityStoreError::Json`] when the reservation cannot be
    /// persisted. A reservation that cannot be persisted is not returned,
    /// so a number is never handed out without being durable first.
    pub fn reserve_revision(&mut self) -> Result<u64, AuthorityStoreError> {
        let reserved = self
            .state
            .high_water_revision
            .checked_add(1)
            .ok_or_else(|| AuthorityStoreError::invalid("revision counter overflowed"))?;
        let mut next = self.state.clone();
        next.high_water_revision = reserved;
        self.save_state(&next)?;
        self.state = next;
        Ok(reserved)
    }

    /// Publish a signed bundle carrying the reserved revision.
    ///
    /// Rotates the current bundle into the previous slot, writes the new
    /// one, then records it as current. The bundle files are written
    /// before the state file names them, so a crash between the two leaves
    /// a bundle nothing points at rather than a state file pointing at a
    /// bundle that is not there.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::RevisionMismatch`] when the bundle's
    /// revision is not the reserved one, and
    /// [`AuthorityStoreError::Io`] or [`AuthorityStoreError::Json`] when a
    /// file cannot be written.
    pub fn commit(&mut self, signed: SignedConfigBundle) -> Result<(), AuthorityStoreError> {
        if signed.bundle.revision != self.state.high_water_revision {
            return Err(AuthorityStoreError::RevisionMismatch {
                expected: self.state.high_water_revision,
                found: signed.bundle.revision,
            });
        }
        let encoded = signed
            .to_json()
            .map_err(|error| AuthorityStoreError::invalid(error.to_string()))?;
        // The archive goes first, before either slot is rotated.
        //
        // This ordering is load bearing rather than tidy. The ring
        // doubles this store's write volume, so a filling volume hits
        // the archive write before anything else, and an `Err` here
        // must leave the published state exactly as it was: the two
        // slots untouched and `current_revision` unmoved. Writing the
        // archive after `current.json` would return `Err` with
        // `current.json` already holding the new revision and
        // `save_state` never reached, and the next `open` would see a
        // bundle inside `(current_revision, high_water]` and adopt it.
        // A publish the operator was told had failed, with
        // `"revision_consumed": false` on the wire, would become the
        // fleet's configuration after a restart.
        //
        // Failing forward is the safe direction here. An archive file
        // for a revision that never published is an orphan
        // `reconcile_archive` adopts and the ring later evicts; the
        // reverse is a served configuration nobody chose.
        //
        // Beside the two slots, never instead of them: the bytes are
        // the same ones `current.json` takes below, so both slots hold
        // exactly what they would have without the ring.
        let mut next = self.state.clone();
        if self.archive_keep > 0 {
            write_atomically(
                &archive_path(&self.directory, signed.bundle.revision),
                &encoded,
            )?;
            next.archive.push(signed.bundle.revision);
        }
        if let Some(current) = self.current.as_ref() {
            let body = current
                .to_json()
                .map_err(|error| AuthorityStoreError::invalid(error.to_string()))?;
            write_atomically(&bundle_path(&self.directory, PREVIOUS_BUNDLE_FILE), &body)?;
        }
        write_atomically(&bundle_path(&self.directory, CURRENT_BUNDLE_FILE), &encoded)?;
        let bound = archive_files_for(self.archive_keep);
        let evicted: Vec<u64> = if next.archive.len() > bound {
            next.archive.drain(..next.archive.len() - bound).collect()
        } else {
            Vec::new()
        };
        next.current_revision = signed.bundle.revision;
        self.save_state(&next)?;
        self.previous = self.current.take();
        self.state = next;
        self.current = Some(signed);
        // After the state that stopped naming them is durable.
        self.remove_archived(&evicted);
        Ok(())
    }

    /// Register a subscriber and mint its credential.
    ///
    /// A subscriber may hold several credentials at once, which is how one
    /// is rotated without a window where the node cannot fetch: register
    /// the new one, deploy it, then revoke the old one.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Invalid`] when `subscriber_id` is
    /// not a usable identifier or the seed collides with a registered
    /// credential ID, [`AuthorityStoreError::TooManySubscribers`] when the
    /// registry is full, and [`AuthorityStoreError::Io`] or
    /// [`AuthorityStoreError::Json`] when the registry cannot be
    /// persisted. Nothing is minted unless it was persisted first.
    pub fn register_subscriber(
        &mut self,
        subscriber_id: &str,
        seed: &CredentialSeed,
        now_unix_ms: u64,
    ) -> Result<IssuedSubscriberCredential, AuthorityStoreError> {
        if !valid_subscriber_id(subscriber_id) {
            return Err(AuthorityStoreError::invalid(
                "subscriber_id must be 1 to 128 printable ASCII characters limited to letters, \
                 digits, and `. - _ :`, matching the value the subscriber sends in \
                 x-sbproxy-subscriber-id",
            ));
        }
        if self.state.subscribers.len() >= MAX_SUBSCRIBERS {
            return Err(AuthorityStoreError::TooManySubscribers);
        }
        let credential_id = seed.credential_id();
        if self.state.subscribers.contains_key(&credential_id) {
            return Err(AuthorityStoreError::invalid(
                "credential identifier collision; retry with fresh random material",
            ));
        }
        let token = seed.token();
        let record = SubscriberRecord {
            subscriber_id: subscriber_id.to_string(),
            credential_id: credential_id.clone(),
            token_sha256: token_fingerprint(&token),
            created_at_unix_ms: now_unix_ms,
            revoked_at_unix_ms: None,
            last_seen_revision: 0,
            applied: None,
            last_seen_at_unix_ms: None,
        };
        let mut next = self.state.clone();
        next.subscribers.insert(credential_id, record.clone());
        self.save_state(&next)?;
        self.state = next;
        Ok(IssuedSubscriberCredential { token, record })
    }

    /// Revoke one credential by its identifier.
    ///
    /// Idempotent: revoking an already-revoked credential leaves the
    /// original revocation time in place and reports `false`, so a retried
    /// operator action does not rewrite history.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Io`] or
    /// [`AuthorityStoreError::Json`] when the registry cannot be
    /// persisted. Revocation is in force only once it is durable.
    pub fn revoke_credential(
        &mut self,
        credential_id: &str,
        now_unix_ms: u64,
    ) -> Result<bool, AuthorityStoreError> {
        let mut next = self.state.clone();
        let Some(record) = next.subscribers.get_mut(credential_id) else {
            return Ok(false);
        };
        if record.is_revoked() {
            return Ok(false);
        }
        record.revoked_at_unix_ms = Some(now_unix_ms);
        self.save_state(&next)?;
        self.state = next;
        Ok(true)
    }

    /// Revoke every live credential held by one subscriber, returning how
    /// many were revoked.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Io`] or
    /// [`AuthorityStoreError::Json`] when the registry cannot be
    /// persisted.
    pub fn revoke_subscriber(
        &mut self,
        subscriber_id: &str,
        now_unix_ms: u64,
    ) -> Result<usize, AuthorityStoreError> {
        let mut next = self.state.clone();
        let mut revoked = 0usize;
        for record in next.subscribers.values_mut() {
            if record.subscriber_id == subscriber_id && !record.is_revoked() {
                record.revoked_at_unix_ms = Some(now_unix_ms);
                revoked += 1;
            }
        }
        if revoked == 0 {
            return Ok(0);
        }
        self.save_state(&next)?;
        self.state = next;
        Ok(revoked)
    }

    /// Every registered credential, live and revoked, in credential-ID
    /// order.
    pub fn subscribers(&self) -> impl Iterator<Item = &SubscriberRecord> {
        self.state.subscribers.values()
    }

    /// How many credentials are registered, revoked ones included.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.state.subscribers.len()
    }

    /// How many credentials are registered and not revoked.
    #[must_use]
    pub fn live_subscriber_count(&self) -> usize {
        self.state
            .subscribers
            .values()
            .filter(|record| !record.is_revoked())
            .count()
    }

    /// Authenticate a presented bearer token.
    ///
    /// The credential ID selects a record and the whole token is then
    /// compared by fingerprint in constant time, so neither the lookup nor
    /// the comparison reveals by timing how much of a guess was right.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriberAuthError::Invalid`] for a malformed, unknown,
    /// or non-matching token, and [`SubscriberAuthError::Revoked`] for a
    /// token that matches a revoked credential.
    pub fn authenticate(&self, token: &str) -> Result<&SubscriberRecord, SubscriberAuthError> {
        let credential_id = parse_credential_id(token).ok_or(SubscriberAuthError::Invalid)?;
        let record = self
            .state
            .subscribers
            .get(credential_id)
            .ok_or(SubscriberAuthError::Invalid)?;
        let presented = token_fingerprint(token);
        if !bool::from(presented.as_bytes().ct_eq(record.token_sha256.as_bytes())) {
            return Err(SubscriberAuthError::Invalid);
        }
        if record.is_revoked() {
            return Err(SubscriberAuthError::Revoked);
        }
        Ok(record)
    }

    /// Record that one credential was served `revision` at
    /// `now_unix_ms`.
    ///
    /// The timestamp is kept in memory unconditionally and the revision is
    /// persisted only when it moves. A subscriber polling an unchanged
    /// revision therefore costs no disk write, which is what keeps a large
    /// fleet's steady-state polling free.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Io`] or
    /// [`AuthorityStoreError::Json`] when the advanced revision cannot be
    /// persisted. The in-memory value is advanced either way, because the
    /// subscriber was genuinely served.
    pub fn record_seen(
        &mut self,
        credential_id: &str,
        revision: u64,
        now_unix_ms: u64,
    ) -> Result<(), AuthorityStoreError> {
        let Some(record) = self.state.subscribers.get_mut(credential_id) else {
            return Ok(());
        };
        record.last_seen_at_unix_ms = Some(now_unix_ms);
        if revision <= record.last_seen_revision {
            return Ok(());
        }
        record.last_seen_revision = revision;
        let snapshot = self.state.clone();
        self.save_state(&snapshot)
    }

    /// Record what a subscriber says it **applied** (WOR-2464).
    ///
    /// `published_high_water` is the highest revision this authority has
    /// ever published. A report naming anything above it is refused
    /// rather than stored: a compromised or buggy node that could claim
    /// revision 9999 would make the fleet view say the rollout is
    /// complete, which is the one answer an operator acts on without
    /// checking. The refusal is the caller's to log; the previous report
    /// is left in place, because a stale true answer beats a fresh
    /// false one.
    ///
    /// Persisted only when the durable half changes, the same discipline
    /// [`Self::record_seen`] keeps and for the same reason: the arrival
    /// time moves on every poll, and a large fleet polling every thirty
    /// seconds would otherwise rewrite the state file constantly.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityStoreError::Invalid`] when the report claims a
    /// revision the authority has never published, and
    /// [`AuthorityStoreError::Io`] or [`AuthorityStoreError::Json`] when
    /// a changed report cannot be persisted. The in-memory value is
    /// updated before the write in the second case, because the
    /// subscriber genuinely said it.
    pub fn record_applied(
        &mut self,
        credential_id: &str,
        report: SubscriberApplyReport,
        published_high_water: u64,
        now_unix_ms: u64,
    ) -> Result<(), AuthorityStoreError> {
        if report.revision > published_high_water {
            return Err(AuthorityStoreError::invalid(format!(
                "subscriber reported applying revision {} but this authority has never \
                 published anything above revision {published_high_water}; the report \
                 is discarded",
                report.revision
            )));
        }
        let Some(record) = self.state.subscribers.get_mut(credential_id) else {
            return Ok(());
        };
        let mut report = report.bounded();
        report.reported_at_unix_ms = Some(now_unix_ms);
        let durable_change = record
            .applied
            .as_ref()
            .is_none_or(|previous| previous.durable_part_differs(&report));
        record.applied = Some(report);
        if !durable_change {
            return Ok(());
        }
        let snapshot = self.state.clone();
        self.save_state(&snapshot)
    }

    /// Look up one credential's record without authenticating.
    #[must_use]
    pub fn subscriber(&self, credential_id: &str) -> Option<&SubscriberRecord> {
        self.state.subscribers.get(credential_id)
    }

    fn save_state(&self, state: &AuthorityState) -> Result<(), AuthorityStoreError> {
        let mut body = serde_json::to_vec_pretty(state)
            .map_err(|source| AuthorityStoreError::json("encode authority state", source))?;
        body.push(b'\n');
        write_atomically(&self.directory.join(STATE_FILE), &body)
    }
}

/// Create the store's own directory tree, owner-only on unix.
///
/// `create_dir_all` alone takes `0777 & ~umask`, so a permissive umask
/// leaves the store's directories world-readable. The files inside are
/// owner-only (see [`write_atomically`]); the directories have to be
/// too, or a listing still tells an unprivileged local account which
/// revisions exist and when they published.
///
/// Exactly three directories are tightened, all of them this store's
/// own: `store_dir`, `store_dir/revisions`, and the archive beneath it.
/// Nothing above `store_dir` is touched. An operator who points
/// `store_dir` at a path whose parents they share is choosing that;
/// walking up and narrowing `/var/lib` on their behalf is not this
/// function's call to make, and on a bad path would be catastrophic.
///
/// A `set_permissions` failure is not fatal. The directory exists and
/// the store works; on a filesystem with no unix modes, or a path owned
/// by someone else, refusing to open would trade a working authority
/// for a hardening step the platform cannot provide.
fn create_private_dirs(store_dir: &Path) -> Result<(), AuthorityStoreError> {
    let revisions = store_dir.join(REVISIONS_DIR);
    let archive = revisions.join(ARCHIVE_DIR);
    std::fs::create_dir_all(&archive)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for directory in [store_dir, revisions.as_path(), archive.as_path()] {
            if let Err(error) =
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            {
                tracing::debug!(
                    error = %error,
                    path = %directory.display(),
                    "could not tighten a config authority store directory to owner-only",
                );
            }
        }
    }
    Ok(())
}

/// Path of one stored bundle file.
fn bundle_path(directory: &Path, name: &str) -> PathBuf {
    directory.join(REVISIONS_DIR).join(name)
}

/// Path of one archived bundle file.
fn archive_path(directory: &Path, revision: u64) -> PathBuf {
    directory
        .join(REVISIONS_DIR)
        .join(ARCHIVE_DIR)
        .join(format!("{revision}.json"))
}

/// Whether `value` is usable as a `subscriber_id`.
fn valid_subscriber_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SUBSCRIBER_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

/// URL-safe base64 SHA-256 of a clear token, the only form ever stored.
fn token_fingerprint(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// The credential ID inside a `sbca1.<id>.<secret>` token, or `None` when
/// the token is not that shape.
///
/// Bounds every field so an oversized or extra-segment token is refused on
/// shape rather than used as a map key.
fn parse_credential_id(token: &str) -> Option<&str> {
    let mut parts = token.split('.');
    if parts.next() != Some(SUBSCRIBER_TOKEN_PREFIX) {
        return None;
    }
    let credential_id = parts.next()?;
    let secret = parts.next()?;
    if parts.next().is_some()
        || credential_id.is_empty()
        || credential_id.len() > 64
        || secret.len() < 32
        || secret.len() > 128
    {
        return None;
    }
    Some(credential_id)
}

/// Read a bounded file. `Ok(None)` means it does not exist yet.
fn read_bounded(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>, AuthorityStoreError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(AuthorityStoreError::Corrupt(format!(
            "{} is empty, not a regular file, or larger than {maximum} bytes",
            path.display()
        )));
    }
    Ok(Some(std::fs::read(path)?))
}

/// Read one stored signed bundle. `Ok(None)` means the slot is empty.
fn read_bundle(path: &Path) -> Result<Option<SignedConfigBundle>, AuthorityStoreError> {
    let Some(bytes) = read_bounded(path, MAX_STORED_BUNDLE_BYTES)? else {
        return Ok(None);
    };
    SignedConfigBundle::from_json(&bytes)
        .map(Some)
        .map_err(|error| {
            AuthorityStoreError::Corrupt(format!("{} does not decode: {error}", path.display()))
        })
}

/// Write `body` to `path` through a temporary file and a rename, so a
/// crash mid-write leaves the old file or the new one, never a truncated
/// one.
fn write_atomically(path: &Path, body: &[u8]) -> Result<(), AuthorityStoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("authority-state.json");
    // Pid plus nanoseconds keeps two writers in one directory from
    // colliding. The rename is the atomic step, not the create.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let temporary = parent.join(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::File::create(&temporary)?;
        // Owner only, set on the temporary before any bytes are
        // written, so the mode is never observably 0644 even for the
        // instant between create and rename.
        //
        // Every file this writes is authority-private: the state file
        // is the subscriber registry, and each bundle is a whole signed
        // configuration for the fleet. The ring turned "two of those on
        // disk" into "twenty one", which is what made the default umask
        // worth stopping at rather than inheriting. The sibling bar in
        // this crate is already higher: `ConfigBundleSigner`'s seed
        // loader refuses a group- or world-readable signing key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(body)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(AuthorityStoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_bundle::{BundleMode, ConfigBundle, ConfigBundleSigner};

    const NOW: u64 = 1_700_000_000_000;
    const AUTHORITY: &str = "control-plane-test";
    const YAML: &str = "origins:\n  \"api.test\":\n    action:\n      type: static\n";

    fn signer() -> ConfigBundleSigner {
        ConfigBundleSigner::shared_secret("lab-shared", vec![9u8; 32]).expect("signer")
    }

    fn signed(revision: u64, yaml: &str) -> SignedConfigBundle {
        signer()
            .sign(
                ConfigBundle::new(AUTHORITY, revision, BundleMode::Overlay, yaml, NOW, None)
                    .expect("bundle"),
            )
            .expect("sign")
    }

    fn seed(tag: u8) -> CredentialSeed {
        CredentialSeed::new(
            [tag; CREDENTIAL_ID_BYTES],
            [tag ^ 0xff; CREDENTIAL_SECRET_BYTES],
        )
    }

    fn store(dir: &Path) -> AuthorityStore {
        AuthorityStore::open(dir, AUTHORITY).expect("open store")
    }

    #[test]
    fn an_empty_directory_opens_with_nothing_published() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = store(temp.path());
        assert_eq!(store.current_revision(), 0);
        assert_eq!(store.high_water_revision(), 0);
        assert!(store.current().is_none());
        assert!(store.previous().is_none());
        assert_eq!(store.subscriber_count(), 0);
        assert_eq!(store.authority_id(), AUTHORITY);
        assert!(temp.path().join(REVISIONS_DIR).is_dir());
    }

    #[test]
    fn revisions_are_monotonic_and_keep_one_predecessor() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path());

        for revision in 1..=3u64 {
            assert_eq!(store.reserve_revision().expect("reserve"), revision);
            store
                .commit(signed(revision, &format!("{YAML}# {revision}\n")))
                .expect("commit");
            assert_eq!(store.current_revision(), revision);
        }
        assert_eq!(
            store.current().expect("current").bundle.revision,
            3,
            "the newest publication is what subscribers fetch",
        );
        assert_eq!(
            store.previous().expect("previous").bundle.revision,
            2,
            "exactly one predecessor is retained for a one-step rollback",
        );
    }

    #[test]
    fn a_reopened_store_never_reissues_a_revision() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path());
            store.reserve_revision().expect("reserve");
            store.commit(signed(1, YAML)).expect("commit");
        }
        // The restart adopts the persisted counters rather than starting
        // over at one, which is what makes a subscriber's cursor safe.
        let mut restarted = store(temp.path());
        assert_eq!(restarted.current_revision(), 1);
        assert_eq!(restarted.high_water_revision(), 1);
        assert_eq!(restarted.current().expect("current").bundle.revision, 1);
        assert_eq!(restarted.reserve_revision().expect("reserve"), 2);
    }

    #[test]
    fn a_crash_between_reservation_and_commit_burns_the_number() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path());
            store.reserve_revision().expect("reserve");
            store.commit(signed(1, YAML)).expect("commit");
            // Reserved, then the process died before committing.
            assert_eq!(store.reserve_revision().expect("reserve"), 2);
        }
        let mut restarted = store(temp.path());
        assert_eq!(
            restarted.current_revision(),
            1,
            "revision 2 never published"
        );
        assert_eq!(restarted.high_water_revision(), 2);
        assert_eq!(
            restarted.reserve_revision().expect("reserve"),
            3,
            "the burned number is not reused, because a subscriber may already \
             have fetched a 2 this process cannot see",
        );
        restarted.commit(signed(3, YAML)).expect("commit");
        assert_eq!(restarted.current_revision(), 3);
    }

    #[test]
    fn committing_a_revision_other_than_the_reserved_one_is_refused() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path());
        assert_eq!(store.reserve_revision().expect("reserve"), 1);
        let error = store
            .commit(signed(7, YAML))
            .expect_err("only the reserved revision may be committed");
        assert!(
            matches!(
                error,
                AuthorityStoreError::RevisionMismatch {
                    expected: 1,
                    found: 7
                }
            ),
            "{error}"
        );
        assert_eq!(store.current_revision(), 0, "nothing was published");
    }

    #[test]
    fn a_store_directory_belonging_to_another_authority_is_refused() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(store(temp.path()));
        let error = AuthorityStore::open(temp.path(), "some-other-authority")
            .expect_err("a directory is pinned to the authority that created it");
        let message = error.to_string();
        assert!(message.contains("control-plane-test"), "{message}");
        assert!(message.contains("store_dir"), "{message}");
    }

    #[test]
    fn a_credential_authenticates_only_as_itself() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path());

        let issued = store
            .register_subscriber("edge-01", &seed(1), NOW)
            .expect("register");
        let token = issued.token().to_string();
        assert!(token.starts_with("sbca1."), "{token}");
        assert_eq!(issued.record().subscriber_id(), "edge-01");
        assert_eq!(store.subscriber_count(), 1);
        assert_eq!(store.live_subscriber_count(), 1);

        let record = store.authenticate(&token).expect("authenticate");
        assert_eq!(record.subscriber_id(), "edge-01");
        assert_eq!(record.last_seen_revision(), 0);

        // A different credential's token does not authenticate as this one.
        let other = store
            .register_subscriber("edge-02", &seed(2), NOW)
            .expect("register");
        assert_eq!(
            store
                .authenticate(other.token())
                .expect("authenticate")
                .subscriber_id(),
            "edge-02",
        );

        // Right credential ID, wrong secret.
        let forged = format!(
            "{SUBSCRIBER_TOKEN_PREFIX}.{}.{}",
            issued.record().credential_id(),
            URL_SAFE_NO_PAD.encode([0u8; CREDENTIAL_SECRET_BYTES]),
        );
        assert_eq!(
            store.authenticate(&forged),
            Err(SubscriberAuthError::Invalid)
        );

        // Shapes that are not tokens at all.
        for bad in [
            "",
            "sbca1",
            "sbca1.only-two-parts",
            "sbce1.a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sbca1.a.short",
            "sbca1.a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.extra",
        ] {
            assert_eq!(
                store.authenticate(bad),
                Err(SubscriberAuthError::Invalid),
                "{bad:?} must not authenticate",
            );
        }

        // The clear token is never written to disk.
        let state = std::fs::read_to_string(temp.path().join(STATE_FILE)).expect("read state");
        assert!(
            !state.contains(&token),
            "the registry must hold only a fingerprint",
        );
        assert!(state.contains(issued.record().credential_id()));
    }

    #[test]
    fn revocation_is_durable_idempotent_and_distinguishable() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let token = {
            let mut store = store(temp.path());
            let issued = store
                .register_subscriber("edge-01", &seed(1), NOW)
                .expect("register");
            let token = issued.token().to_string();
            let credential_id = issued.record().credential_id().to_string();
            assert!(store
                .revoke_credential(&credential_id, NOW + 1)
                .expect("revoke"));
            assert!(
                !store
                    .revoke_credential(&credential_id, NOW + 2)
                    .expect("revoke again"),
                "a repeated revocation is a no-op, not a rewritten history",
            );
            assert_eq!(
                store
                    .subscriber(&credential_id)
                    .expect("record")
                    .revoked_at_unix_ms(),
                Some(NOW + 1),
            );
            assert_eq!(store.live_subscriber_count(), 0);
            assert_eq!(store.subscriber_count(), 1, "the record is kept for audit");
            token
        };

        // Revocation survives the restart, and it is reported as revoked
        // rather than as merely invalid.
        let restarted = store(temp.path());
        assert_eq!(
            restarted.authenticate(&token),
            Err(SubscriberAuthError::Revoked)
        );
    }

    #[test]
    fn revoking_a_subscriber_revokes_every_credential_it_holds() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path());
        // Two live credentials is the rotation window: register the new
        // one, deploy it, then retire the old.
        let first = store
            .register_subscriber("edge-01", &seed(1), NOW)
            .expect("register");
        let second = store
            .register_subscriber("edge-01", &seed(2), NOW)
            .expect("register");
        let untouched = store
            .register_subscriber("edge-02", &seed(3), NOW)
            .expect("register");
        assert_eq!(store.live_subscriber_count(), 3);

        assert_eq!(
            store.revoke_subscriber("edge-01", NOW + 1).expect("revoke"),
            2
        );
        assert_eq!(
            store.revoke_subscriber("edge-01", NOW + 2).expect("revoke"),
            0,
            "nothing live is left to revoke",
        );
        for token in [first.token(), second.token()] {
            assert_eq!(store.authenticate(token), Err(SubscriberAuthError::Revoked));
        }
        assert!(store.authenticate(untouched.token()).is_ok());
    }

    #[test]
    fn a_malformed_subscriber_id_is_refused() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let mut store = store(temp.path());
        for bad in ["", " ", "edge 01", "edge/01", "edge\n01", &"e".repeat(129)] {
            let error = store
                .register_subscriber(bad, &seed(1), NOW)
                .expect_err("must be refused");
            assert!(
                matches!(error, AuthorityStoreError::Invalid(_)),
                "{bad:?}: {error}"
            );
        }
        assert_eq!(store.subscriber_count(), 0);
    }

    /// WOR-2464. The durable half of an apply report survives a restart,
    /// the arrival time does not, and the free-text fields are bounded
    /// at the trust boundary. All three are properties of a fleet view
    /// an operator makes a rollback decision on.
    #[test]
    fn an_apply_report_persists_its_durable_half_and_bounds_its_free_text() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let credential_id = {
            let mut store = store(temp.path());
            let issued = store
                .register_subscriber("edge-01", &seed(1), NOW)
                .expect("register");
            let credential_id = issued.record().credential_id().to_string();

            let report = SubscriberApplyReport {
                status: ApplyStatus::Failed,
                revision: 4,
                config_hash: "sha-4".to_string(),
                error: Some("x".repeat(MAX_APPLY_ERROR_CHARS + 200)),
                soak_verdict: Some("failed".to_string()),
                fallback_active: true,
                reported_at_unix_ms: None,
            };
            store
                .record_applied(&credential_id, report, 9, NOW)
                .expect("a revision at or below the high-water mark is accepted");
            let stored = store
                .subscriber(&credential_id)
                .expect("record")
                .applied()
                .expect("a report");
            assert_eq!(stored.status, ApplyStatus::Failed);
            assert_eq!(stored.reported_at_unix_ms, Some(NOW));
            let error = stored.error.as_deref().expect("an error");
            assert!(
                error.chars().count() <= MAX_APPLY_ERROR_CHARS + 3,
                "subscriber-supplied text is bounded before it reaches a state file and an \
                 admin page: {} chars",
                error.chars().count(),
            );
            assert!(error.ends_with("..."), "and it says it was cut");

            // A revision above the high-water mark is refused, and the
            // previous report is left in place: a stale true answer
            // beats a fresh false one.
            let error = store
                .record_applied(
                    &credential_id,
                    SubscriberApplyReport {
                        status: ApplyStatus::Applied,
                        revision: 9_999,
                        config_hash: "sha-forged".to_string(),
                        error: None,
                        soak_verdict: None,
                        fallback_active: false,
                        reported_at_unix_ms: None,
                    },
                    9,
                    NOW + 1,
                )
                .expect_err("a node cannot claim a revision that was never published");
            assert!(error.to_string().contains("9999"), "{error}");
            assert_eq!(
                store
                    .subscriber(&credential_id)
                    .expect("record")
                    .applied()
                    .expect("still the old report")
                    .status,
                ApplyStatus::Failed,
            );

            // An unknown credential is ignored rather than fabricating a
            // record, the same way `record_seen` treats one.
            store
                .record_applied(
                    "not-registered",
                    SubscriberApplyReport {
                        status: ApplyStatus::Applied,
                        revision: 1,
                        config_hash: String::new(),
                        error: None,
                        soak_verdict: None,
                        fallback_active: false,
                        reported_at_unix_ms: None,
                    },
                    9,
                    NOW,
                )
                .expect("ignored");
            assert_eq!(store.subscriber_count(), 1);
            credential_id
        };

        let restarted = store(temp.path());
        let stored = restarted
            .subscriber(&credential_id)
            .expect("record")
            .applied()
            .expect("the durable half survives");
        assert_eq!(stored.status, ApplyStatus::Failed);
        assert_eq!(stored.revision, 4);
        assert_eq!(stored.config_hash, "sha-4");
        assert!(
            stored.reported_at_unix_ms.is_none(),
            "the arrival time is in memory only, so the status page says the poll state is \
             unknown after a restart rather than claiming the node just reported",
        );
    }

    /// WOR-2464. The durable comparison ignores the arrival time, which
    /// is the whole of what keeps a thousand nodes polling every thirty
    /// seconds from rewriting the state file constantly.
    #[test]
    fn only_the_durable_half_of_an_apply_report_counts_as_a_change() {
        let base = SubscriberApplyReport {
            status: ApplyStatus::Applied,
            revision: 4,
            config_hash: "sha".to_string(),
            error: None,
            soak_verdict: None,
            fallback_active: false,
            reported_at_unix_ms: Some(NOW),
        };
        let later = SubscriberApplyReport {
            reported_at_unix_ms: Some(NOW + 60_000),
            ..base.clone()
        };
        assert!(
            !base.durable_part_differs(&later),
            "a re-report of the same state is not a write",
        );
        let moved = SubscriberApplyReport {
            revision: 5,
            ..base.clone()
        };
        assert!(base.durable_part_differs(&moved));
        let degraded = SubscriberApplyReport {
            status: ApplyStatus::AppliedDegraded,
            ..base.clone()
        };
        assert!(
            base.durable_part_differs(&degraded),
            "and a clean apply turning degraded is a change worth persisting",
        );
    }

    /// WOR-2464. The wire labels are a closed set that round-trips, so a
    /// node and an authority on different builds cannot disagree about
    /// what `applied_degraded` means.
    #[test]
    fn every_apply_status_round_trips_through_its_wire_label() {
        for status in [
            ApplyStatus::Applying,
            ApplyStatus::Applied,
            ApplyStatus::AppliedDegraded,
            ApplyStatus::Failed,
        ] {
            assert_eq!(ApplyStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(ApplyStatus::parse("teleported"), None);
        assert_eq!(
            ApplyStatus::parse("APPLIED"),
            None,
            "the labels are lowercase"
        );
    }

    #[test]
    fn last_seen_revision_is_persisted_only_when_it_advances() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let credential_id = {
            let mut store = store(temp.path());
            let issued = store
                .register_subscriber("edge-01", &seed(1), NOW)
                .expect("register");
            let credential_id = issued.record().credential_id().to_string();

            store.record_seen(&credential_id, 4, NOW).expect("seen");
            let record = store.subscriber(&credential_id).expect("record");
            assert_eq!(record.last_seen_revision(), 4);
            assert_eq!(record.last_seen_at_unix_ms(), Some(NOW));

            // A re-fetch of the same revision moves the timestamp but not
            // the revision, so the steady state costs no write.
            store.record_seen(&credential_id, 4, NOW + 5).expect("seen");
            let record = store.subscriber(&credential_id).expect("record");
            assert_eq!(record.last_seen_revision(), 4);
            assert_eq!(record.last_seen_at_unix_ms(), Some(NOW + 5));

            // A stale report cannot walk the high-water mark backwards.
            store.record_seen(&credential_id, 2, NOW + 6).expect("seen");
            assert_eq!(
                store
                    .subscriber(&credential_id)
                    .expect("record")
                    .last_seen_revision(),
                4
            );

            // An unknown credential is silently ignored rather than
            // fabricating a record for it.
            store.record_seen("not-registered", 9, NOW).expect("seen");
            assert_eq!(store.subscriber_count(), 1);
            credential_id
        };

        let restarted = store(temp.path());
        let record = restarted.subscriber(&credential_id).expect("record");
        assert_eq!(
            record.last_seen_revision(),
            4,
            "the answer to 'did the fleet take the change' has to survive a restart",
        );
        assert_eq!(
            record.last_seen_at_unix_ms(),
            None,
            "receipt times are in-memory only, so they are absent after a restart",
        );
    }

    #[test]
    fn a_crash_between_writing_a_bundle_and_naming_it_is_repaired_at_open() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path());
            store.reserve_revision().expect("reserve");
            store.commit(signed(1, YAML)).expect("commit");
            // Reserve 2 and write its bundle by hand, without recording it.
            // That is exactly the state `commit` leaves behind when the
            // process dies between its second and third write.
            assert_eq!(store.reserve_revision().expect("reserve"), 2);
            let encoded = signed(2, "origins: {}\n").to_json().expect("encode");
            write_atomically(&bundle_path(temp.path(), CURRENT_BUNDLE_FILE), &encoded)
                .expect("write the interrupted bundle");
        }

        // The bundle on disk is the one that was signed and the reservation
        // already covered its number, so it is adopted rather than refused:
        // an authority that crashed mid-publish has to be able to boot.
        let mut reopened = store(temp.path());
        assert_eq!(reopened.current_revision(), 2);
        assert_eq!(reopened.high_water_revision(), 2);
        assert_eq!(reopened.current().expect("current").bundle.revision, 2);
        // And the repair was persisted, so a second open is a no-op rather
        // than a second repair.
        let again = store(temp.path());
        assert_eq!(again.current_revision(), 2);
        // Publication carries on from there.
        assert_eq!(reopened.reserve_revision().expect("reserve"), 3);
    }

    #[test]
    fn a_bundle_claiming_a_revision_that_was_never_reserved_is_refused() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path());
            store.reserve_revision().expect("reserve");
            store.commit(signed(1, YAML)).expect("commit");
        }
        // Revision 9 was never reserved here, so this bundle and this state
        // file came from different stores. Adopting it would let the
        // authority reissue 2 through 9 with different content.
        let encoded = signed(9, YAML).to_json().expect("encode");
        write_atomically(&bundle_path(temp.path(), CURRENT_BUNDLE_FILE), &encoded).expect("write");
        let error = AuthorityStore::open(temp.path(), AUTHORITY)
            .expect_err("a bundle past the high-water mark is not this store's");
        let message = error.to_string();
        assert!(message.contains("highest ever reserved"), "{message}");
    }

    #[test]
    fn a_state_file_naming_a_bundle_that_is_not_there_is_refused() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        {
            let mut store = store(temp.path());
            store.reserve_revision().expect("reserve");
            store.commit(signed(1, YAML)).expect("commit");
        }
        std::fs::remove_file(bundle_path(temp.path(), CURRENT_BUNDLE_FILE)).expect("remove");
        let error = AuthorityStore::open(temp.path(), AUTHORITY)
            .expect_err("a state file pointing at nothing is corruption, not an empty store");
        assert!(matches!(error, AuthorityStoreError::Corrupt(_)), "{error}");
    }

    // --- The archive ring (WOR-2463) ---

    /// Publish `count` revisions into a store opened with `keep`, and hand
    /// back the directory so the files can be inspected.
    fn published(temp: &Path, keep: usize, count: u64) -> AuthorityStore {
        let mut store =
            AuthorityStore::open_with_archive_keep(temp, AUTHORITY, keep).expect("open store");
        for revision in 1..=count {
            assert_eq!(store.reserve_revision().expect("reserve"), revision);
            store
                .commit(signed(revision, &format!("{YAML}# {revision}\n")))
                .expect("commit");
        }
        store
    }

    #[test]
    fn the_archive_keeps_the_newest_entries_up_to_its_bound() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = published(temp.path(), 3, 6);
        assert_eq!(
            store.archived_revisions(),
            &[3, 4, 5, 6],
            "archive_keep counts rollback targets, so a ring of three holds three earlier \
             revisions plus the one being served",
        );
        for revision in [1u64, 2] {
            assert!(
                !archive_path(temp.path(), revision).exists(),
                "revision {revision} was evicted, so its file is gone too",
            );
        }
        for revision in [3u64, 4, 5, 6] {
            assert!(
                archive_path(temp.path(), revision).is_file(),
                "revision {revision} is in the ring, so its file is on disk",
            );
        }

        let fewer = tempfile::TempDir::new().expect("tempdir");
        let shallow = published(fewer.path(), 10, 2);
        assert_eq!(
            shallow.archived_revisions(),
            &[1, 2],
            "fewer publications than the bound keep all of them",
        );
    }

    /// The off-by-one this fixes: `archive_keep` counts revisions an
    /// operator can roll *back to*, so the one being served must not
    /// eat a slot. With the current revision counted, `archive_keep: 1`
    /// advertised exactly one target, `current_revision` itself, whose
    /// rollback is a no-op republish of what is already running. That
    /// made `1` behave identically to `0` while the status page said
    /// otherwise.
    #[test]
    fn a_ring_of_one_offers_one_real_rollback_target() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = published(temp.path(), 1, 4);
        assert_eq!(store.archived_revisions(), &[3, 4]);
        let current = store.current_revision();
        let targets: Vec<u64> = store
            .archived_revisions()
            .iter()
            .copied()
            .filter(|revision| *revision != current)
            .collect();
        assert_eq!(
            targets,
            vec![3],
            "one configured target means one revision that is not the one already serving",
        );
    }

    #[test]
    fn the_archive_leaves_the_current_and_previous_slots_byte_identical() {
        // The whole design constraint of this ticket, asserted rather than
        // asserted about: the same publications into a ring-less store and
        // a ringed one leave the two durability-critical files identical.
        let without = tempfile::TempDir::new().expect("tempdir");
        let with = tempfile::TempDir::new().expect("tempdir");
        drop(published(without.path(), 0, 4));
        drop(published(with.path(), 3, 4));
        for slot in [CURRENT_BUNDLE_FILE, PREVIOUS_BUNDLE_FILE] {
            let plain = std::fs::read(bundle_path(without.path(), slot)).expect("read");
            let ringed = std::fs::read(bundle_path(with.path(), slot)).expect("read");
            assert_eq!(plain, ringed, "{slot} differs once the archive is on");
        }
        assert!(
            !without
                .path()
                .join(REVISIONS_DIR)
                .join(ARCHIVE_DIR)
                .join("1.json")
                .exists(),
            "archive_keep of zero writes no ring at all",
        );
    }

    #[test]
    fn an_archived_revision_reads_back_the_bundle_that_was_signed() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = published(temp.path(), 5, 3);
        let archived = store
            .archived(2)
            .expect("read archive")
            .expect("revision 2 is in the ring");
        assert_eq!(archived.bundle.revision, 2);
        assert_eq!(archived.bundle.config_yaml, format!("{YAML}# 2\n"));
        assert!(
            store.archived(9).expect("read archive").is_none(),
            "a revision the ring never held is absent, not an error",
        );
    }

    #[test]
    fn a_crash_between_the_archive_write_and_the_state_write_is_repaired_at_open() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(published(temp.path(), 5, 2));
        // Reserve 3 and write its archive file, then die before the state
        // file names it. This is exactly the window `commit` leaves.
        {
            let mut store =
                AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("open");
            assert_eq!(store.reserve_revision().expect("reserve"), 3);
            let encoded = signed(3, YAML).to_json().expect("encode");
            write_atomically(&archive_path(temp.path(), 3), &encoded).expect("write archive");
        }
        let repaired =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("open");
        assert_eq!(
            repaired.archived_revisions(),
            &[1, 2, 3],
            "the orphaned archive file is adopted on the first open",
        );
        assert_eq!(
            repaired.current_revision(),
            2,
            "adopting an archive file never moves what subscribers fetch",
        );
        // A second open is a no-op rather than a second repair.
        let again =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("open");
        assert_eq!(again.archived_revisions(), &[1, 2, 3]);
    }

    #[test]
    fn a_listed_archive_file_that_was_deleted_drops_out_of_the_list() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(published(temp.path(), 5, 3));
        std::fs::remove_file(archive_path(temp.path(), 2)).expect("remove");
        let reopened =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("open");
        assert_eq!(
            reopened.archived_revisions(),
            &[1, 3],
            "an archive is a convenience: a deleted file is dropped, not refused",
        );
    }

    #[test]
    fn lowering_the_ring_bound_trims_the_archive_at_the_next_open() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(published(temp.path(), 10, 6));
        let trimmed =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 2).expect("open");
        assert_eq!(trimmed.archived_revisions(), &[4, 5, 6]);
        assert!(
            !archive_path(temp.path(), 3).exists(),
            "trimming unlinks the files it stopped naming",
        );
    }

    /// A zero-padded or sign-prefixed file name is not a revision.
    ///
    /// `007.json` parses as 7 exactly as `7.json` does, so a backup tool
    /// that pads would have the ring adopt `[7, 7]`, persist it, and
    /// then refuse the state file it wrote itself at the next open,
    /// because the archive list has to be strictly ascending.
    #[test]
    fn an_archive_file_with_a_non_canonical_name_is_ignored() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(published(temp.path(), 5, 2));
        let encoded = signed(2, YAML).to_json().expect("encode");
        for name in ["002.json", "+2.json"] {
            let path = temp.path().join(REVISIONS_DIR).join(ARCHIVE_DIR).join(name);
            write_atomically(&path, &encoded).expect("write");
        }
        let reopened =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("open");
        assert_eq!(
            reopened.archived_revisions(),
            &[1, 2],
            "only the canonical spelling names a revision",
        );
        // And the state it just persisted opens again rather than
        // failing the strictly-ascending check.
        let again =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("reopen");
        assert_eq!(again.archived_revisions(), &[1, 2]);
    }

    /// Every file this store writes is authority-private: the state
    /// file is the subscriber registry and each bundle is a whole
    /// signed configuration for the fleet. The ring took that from two
    /// files to twenty one at the default.
    #[cfg(unix)]
    #[test]
    fn the_store_writes_owner_only_files_and_directories() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(published(temp.path(), 5, 2));

        let mode = |path: &Path| -> u32 {
            std::fs::metadata(path)
                .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
                .permissions()
                .mode()
                & 0o777
        };
        for file in [
            temp.path().join(STATE_FILE),
            bundle_path(temp.path(), CURRENT_BUNDLE_FILE),
            bundle_path(temp.path(), PREVIOUS_BUNDLE_FILE),
            archive_path(temp.path(), 1),
            archive_path(temp.path(), 2),
        ] {
            assert_eq!(mode(&file), 0o600, "{} is not owner-only", file.display());
        }
        for directory in [
            temp.path().to_path_buf(),
            temp.path().join(REVISIONS_DIR),
            temp.path().join(REVISIONS_DIR).join(ARCHIVE_DIR),
        ] {
            assert_eq!(
                mode(&directory),
                0o700,
                "{} is not owner-only",
                directory.display(),
            );
        }
    }

    /// A Blocker from the WOR-2463 review: an archive write that fails
    /// must not leave `current.json` ahead of the state file.
    ///
    /// The ring doubles this store's write volume, so a filling volume
    /// hits the archive write first. With the archive written *after*
    /// `current.json`, an ENOSPC or EACCES returned `Err` with the new
    /// revision already in `current.json` and `save_state` never
    /// reached, and the next `open` adopted it: a publish reported as
    /// failed, with `"revision_consumed": false` on the wire, became
    /// the fleet's configuration after a restart.
    #[cfg(unix)]
    #[test]
    fn an_archive_write_that_fails_leaves_the_published_revision_exactly_where_it_was() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(published(temp.path(), 5, 2));

        let archive_dir = temp.path().join(REVISIONS_DIR).join(ARCHIVE_DIR);
        let original = std::fs::metadata(&archive_dir)
            .expect("archive dir")
            .permissions();

        // Opened *before* the directory is locked down: `open` creates
        // the store's tree and tightens it to 0700, which would undo
        // the mode this test is setting.
        let mut store =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("open");

        // Read and traverse, but not write: the shape ENOSPC and EACCES
        // both present to `write_atomically`.
        std::fs::set_permissions(&archive_dir, std::fs::Permissions::from_mode(0o500))
            .expect("make the archive unwritable");

        // Root bypasses the mode bits, and so do some filesystems, so
        // check that the directory really is unwritable before
        // asserting on what happens when it is. Skipping is honest;
        // asserting a refusal that never happened is not.
        let probe = archive_dir.join(".writability-probe");
        if std::fs::write(&probe, b"x").is_ok() {
            let _ = std::fs::remove_file(&probe);
            std::fs::set_permissions(&archive_dir, original).expect("restore permissions");
            return;
        }

        assert_eq!(store.reserve_revision().expect("reserve"), 3);
        let error = store
            .commit(signed(3, &format!("{YAML}# 3\n")))
            .expect_err("an unwritable archive must fail the commit");
        assert!(matches!(error, AuthorityStoreError::Io(_)), "{error}");

        std::fs::set_permissions(&archive_dir, original).expect("restore permissions");

        // Nothing rotated. This is the assertion the ordering exists for.
        assert_eq!(
            store.current_revision(),
            2,
            "a failed commit must leave the served revision untouched",
        );
        assert_eq!(
            read_bundle(&bundle_path(temp.path(), CURRENT_BUNDLE_FILE))
                .expect("read current")
                .expect("a current bundle")
                .bundle
                .revision,
            2,
            "current.json must still hold revision 2 on disk",
        );
        assert_eq!(
            read_bundle(&bundle_path(temp.path(), PREVIOUS_BUNDLE_FILE))
                .expect("read previous")
                .expect("a previous bundle")
                .bundle
                .revision,
            1,
            "and previous.json must not have been rotated either",
        );

        // And a restart does not adopt the revision that never published.
        let reopened =
            AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5).expect("reopen");
        assert_eq!(
            reopened.current_revision(),
            2,
            "the next open must not promote a revision the commit refused",
        );
        assert_eq!(reopened.archived_revisions(), &[1, 2]);
    }

    #[test]
    fn an_archive_file_claiming_an_unreserved_revision_is_refused() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        drop(published(temp.path(), 5, 2));
        let encoded = signed(9, YAML).to_json().expect("encode");
        write_atomically(&archive_path(temp.path(), 9), &encoded).expect("write");
        let error = AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, 5)
            .expect_err("an archive file past the high-water mark is not this store's");
        assert!(error.to_string().contains("was ever reserved"), "{error}");
    }

    #[test]
    fn the_archive_bound_is_clamped_and_its_worst_case_is_written_down() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let store = AuthorityStore::open_with_archive_keep(temp.path(), AUTHORITY, usize::MAX)
            .expect("open");
        assert_eq!(store.archive_keep(), MAX_ARCHIVE_KEEP);
        // One archived file is bounded by the same envelope bound a
        // subscriber applies on the wire, so the ring's worst case is that
        // bound times the ceiling. Asserted so a change to either constant
        // has to restate the disk cost rather than move it silently.
        assert_eq!(
            MAX_ARCHIVE_BYTES,
            MAX_STORED_BUNDLE_BYTES * archive_files_for(MAX_ARCHIVE_KEEP) as u64,
            "the ring holds one file more than archive_keep: the revision being served",
        );
        assert_eq!(MAX_ARCHIVE_BYTES, 1_699_282_944, "1.58 GiB at the ceiling");
    }
}
