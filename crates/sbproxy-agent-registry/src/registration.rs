//! Agent self-registration: what a submitter sends, what is minted for
//! them, and the owner-approval state machine that decides it.
//!
//! # The shape, in one paragraph
//!
//! A submitter sends metadata describing the agent. The queue mints a
//! kebab-case slug, an OAuth-style `client_id`, a one-time `client_secret`,
//! and a registration access token, stores Argon2id hashes of the two
//! secrets, and parks the record in `Pending`. An operator approves or
//! rejects it. Approval is what makes the agent eligible to appear in a
//! published catalog. A reviewer's decision is durable and is stored
//! against the fingerprint of the description they decided about, so a
//! rejected submitter cannot resubmit the same description and get a
//! different answer from a different reviewer, and an approved agent's
//! description cannot become a second agent with its own credentials.
//!
//! # Which store holds what, and why it matters
//!
//! The registration records are [`PersistentKv`]: a restart that forgot a
//! pending queue would silently re-open decisions an operator already made,
//! and a restart that forgot an approval would revoke an agent nobody
//! revoked.
//!
//! The duplicate-detection window is [`EphemeralKv`]: it exists to collapse
//! a submitter's retry into one queue entry over the following hour, and a
//! restart genuinely should forget it. Storing it durably would keep a
//! fingerprint alive past the window it describes and turn a legitimate
//! resubmission into a permanent refusal.
//!
//! # Secrets
//!
//! Plaintext secrets exist exactly once, in the response to the call that
//! minted them. What is stored is an Argon2id hash at OWASP's recommended
//! parameters (19 MiB, two iterations, one lane). [`RegistrationView`] is
//! the shape every read path returns and it has no field a hash could
//! occupy, so a listing endpoint cannot leak one by forgetting to strip it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use sbproxy_platform::storage::{CasOutcome, EphemeralKv, KvNamespace, PersistentKv};

use crate::error::{RegistryError, Result};
use crate::metrics::record_registry_op;

/// Prefix on a minted client secret, so an operator reading a log or a
/// paste can tell one from a registration access token at a glance.
const CLIENT_SECRET_PREFIX: &str = "sk_agent_";

/// Prefix on a minted registration access token.
const REGISTRATION_ACCESS_TOKEN_PREFIX: &str = "rat_";

/// Longest vendor string a submission may carry.
const MAX_VENDOR_BYTES: usize = 128;

/// Longest operator-supplied reason on a decision.
const MAX_REASON_BYTES: usize = 4 * 1024;

/// Most list entries any one metadata array may carry.
const MAX_LIST_ENTRIES: usize = 16;

/// Longest single list entry, in bytes.
const MAX_LIST_ENTRY_BYTES: usize = 253;

/// Purpose taxonomy a submission declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Collecting training data.
    Training,
    /// Building a search index.
    Search,
    /// Answering a user's question right now.
    Assistant,
    /// Research crawling.
    Research,
    /// Archival and preservation.
    Archival,
    /// Declined to say.
    Unknown,
}

/// What a submission is asking to be allowed to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RequestedScope {
    /// Ordinary crawling of public routes.
    #[serde(rename = "crawl:public")]
    CrawlPublic,
    /// Crawling routes behind a paywall or a membership.
    #[serde(rename = "crawl:gated")]
    CrawlGated,
    /// Embedding or quoting public content.
    #[serde(rename = "embed:public")]
    EmbedPublic,
    /// Invoking MCP tools.
    #[serde(rename = "mcp:tools")]
    McpTools,
}

/// What a submitter describes their agent as.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMetadata {
    /// Display name of the operator behind the agent.
    pub vendor: String,
    /// Purpose bucket.
    pub purpose: Purpose,
    /// The submitter's published abuse or documentation URL. HTTPS only.
    pub contact_url: String,
    /// User-Agent fragments the agent will send. At least one.
    pub expected_user_agents: Vec<String>,
    /// Reverse-DNS suffixes a forward-confirmed lookup should land in.
    #[serde(default)]
    pub expected_reverse_dns_suffixes: Vec<String>,
    /// Web Bot Auth thumbprints, `<alg>:<thumbprint>`.
    #[serde(default)]
    pub expected_keyids: Vec<String>,
    /// Scopes being asked for. At least one.
    pub requested_scopes: Vec<RequestedScope>,
}

impl AgentMetadata {
    /// Refuse anything outside the documented ranges before a slug is
    /// minted or a queue slot is taken.
    ///
    /// Ordering matters: validation runs before any store write, so a
    /// malformed submission costs one parse rather than a durable record
    /// somebody has to clean up.
    pub fn validate(&self) -> Result<()> {
        bounded("vendor", &self.vendor, 1, MAX_VENDOR_BYTES)?;
        if self.vendor.trim().is_empty() {
            return Err(RegistryError::Invalid {
                field: "vendor",
                detail: "must not be blank".into(),
            });
        }
        bounded("contact_url", &self.contact_url, 1, 512)?;
        // Parsed rather than prefix-matched: `https://` also opens
        // `https://` with no host, which a `starts_with` accepts and a
        // reviewer following the link discovers.
        let contact =
            url::Url::parse(&self.contact_url).map_err(|error| RegistryError::Invalid {
                field: "contact_url",
                detail: format!("is not a URL: {error}"),
            })?;
        if contact.scheme() != "https" {
            return Err(RegistryError::Invalid {
                field: "contact_url",
                detail: "must be an https:// URL".into(),
            });
        }
        if contact.host_str().is_none_or(str::is_empty) {
            return Err(RegistryError::Invalid {
                field: "contact_url",
                detail: "must name a host".into(),
            });
        }
        bounded_list(
            "expected_user_agents",
            &self.expected_user_agents,
            1,
            MAX_LIST_ENTRIES,
        )?;
        bounded_list(
            "expected_reverse_dns_suffixes",
            &self.expected_reverse_dns_suffixes,
            0,
            MAX_LIST_ENTRIES,
        )?;
        bounded_list(
            "expected_keyids",
            &self.expected_keyids,
            0,
            MAX_LIST_ENTRIES,
        )?;
        for keyid in &self.expected_keyids {
            if !keyid.contains(':') {
                return Err(RegistryError::Invalid {
                    field: "expected_keyids",
                    detail: "each thumbprint must be <alg>:<thumbprint>".into(),
                });
            }
        }
        if self.requested_scopes.is_empty() || self.requested_scopes.len() > 8 {
            return Err(RegistryError::Invalid {
                field: "requested_scopes",
                detail: "must name between one and eight scopes".into(),
            });
        }
        Ok(())
    }
}

fn bounded(field: &'static str, value: &str, min: usize, max: usize) -> Result<()> {
    if value.len() < min || value.len() > max {
        return Err(RegistryError::Invalid {
            field,
            detail: format!("must be {min}..={max} bytes, got {}", value.len()),
        });
    }
    Ok(())
}

fn bounded_list(field: &'static str, values: &[String], min: usize, max: usize) -> Result<()> {
    if values.len() < min || values.len() > max {
        return Err(RegistryError::Invalid {
            field,
            detail: format!("must hold {min}..={max} entries, got {}", values.len()),
        });
    }
    for value in values {
        bounded(field, value, 1, MAX_LIST_ENTRY_BYTES)?;
        if value.trim().is_empty() {
            return Err(RegistryError::Invalid {
                field,
                detail: "entries must not be blank".into(),
            });
        }
    }
    Ok(())
}

/// Where a registration is in its life.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Submitted, waiting on a human.
    Pending,
    /// A reviewer approved it.
    Approved,
    /// A reviewer refused it. Terminal, and the description stays refused.
    Rejected,
    /// An approved registration was later withdrawn. Terminal, and the
    /// description stays refused.
    Revoked,
}

impl ApprovalState {
    /// Wire label, and the value the metrics recorder uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
        }
    }

    /// Whether no further transition is possible from here.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Rejected | Self::Revoked)
    }
}

/// The stored record. Never returned to a caller: see [`RegistrationView`].
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistrationRecord {
    agent_id: String,
    /// Tenant this registration belongs to. Absent in records written
    /// before tenant scoping landed, which read back as
    /// [`DEFAULT_TENANT`]: an existing single-tenant deployment keeps
    /// working and its records stay visible to its deployment-wide
    /// operator.
    #[serde(default = "default_tenant")]
    tenant: String,
    client_id: String,
    client_secret_hash: String,
    previous_client_secret_hash: Option<String>,
    previous_secret_valid_until: Option<DateTime<Utc>>,
    registration_access_token_hash: String,
    metadata_hash: String,
    metadata: AgentMetadata,
    state: ApprovalState,
    reason: Option<String>,
    decided_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    rotated_at: Option<DateTime<Utc>>,
}

/// Tenant a registration is recorded under when the acting operator is
/// deployment-wide.
///
/// Matches the capture envelope's `workspace_id` default, so a
/// single-tenant deployment reads the same word in both places.
pub const DEFAULT_TENANT: &str = "default";

/// Which registrations an operator may see and act on.
///
/// The enterprise queue scoped every operation by `workspace_id` and keyed
/// its records on `(workspace_id, agent_id)`; this port had dropped that
/// dimension entirely, which gave a tenant-scoped admin operator read and
/// write over every tenant's registrations. This is that dimension back,
/// named for the thing this workspace already calls it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantScope {
    /// A deployment-wide operator. Sees and acts on every tenant, and
    /// records its own submissions under [`DEFAULT_TENANT`].
    All,
    /// An operator narrowed to one tenant by `proxy.admin.operators`.
    Only(String),
}

impl TenantScope {
    /// Build a scope from the resolved principal's tenant.
    pub fn from_principal(tenant: Option<&str>) -> Self {
        match tenant {
            Some(tenant) => Self::Only(tenant.to_string()),
            None => Self::All,
        }
    }

    /// Whether this scope covers `tenant`.
    pub fn admits(&self, tenant: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(scoped) => scoped == tenant,
        }
    }

    /// The tenant a submission made under this scope is recorded against.
    ///
    /// `pub(crate)`: the only caller is `register`, and a scope's owning
    /// tenant is an implementation detail of how a record is keyed rather
    /// than something a caller holding a scope needs to ask about.
    pub(crate) fn owning_tenant(&self) -> &str {
        match self {
            Self::All => DEFAULT_TENANT,
            Self::Only(tenant) => tenant.as_str(),
        }
    }

    /// Whether this scope is narrowed to one tenant.
    pub fn is_scoped(&self) -> bool {
        matches!(self, Self::Only(_))
    }
}

fn default_tenant() -> String {
    DEFAULT_TENANT.to_string()
}

/// The tenant half of a replay-index key: a fixed-length digest of the
/// tenant name.
///
/// A hash rather than a sanitized spelling, because sanitizing is
/// many-to-one: collapsing everything outside `[A-Za-z0-9_-]` to `_` maps
/// `acme.corp` and `acme corp` onto one key, and that key is the boundary
/// between two tenants' replay indexes. One tenant's rejection would then
/// refuse the other tenant's identical description, which is exactly the
/// property the key exists to keep apart. The digest is injective in
/// practice and fixed-length, so the `:` that separates it from the
/// fingerprint is never ambiguous.
///
/// Not a security boundary and not secret: tenants come from
/// `proxy.admin.operators[].tenant` and this is a key-composition
/// question, not an authorization one.
fn tenant_index_key(tenant: &str) -> String {
    hex::encode(Sha256::digest(tenant.as_bytes()))
}

/// One decided metadata fingerprint, and what was decided about it.
///
/// Keyed on the fingerprint rather than on the slug, because the slug is
/// minted fresh on every submission and is therefore never what a
/// resubmission reuses.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct MetadataIndexEntry {
    agent_id: String,
    state: ApprovalState,
}

/// What every read path returns.
///
/// This type has no field a credential hash could occupy, which is the
/// point: a listing endpoint cannot leak one by forgetting to strip it,
/// because there is nowhere for it to go.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistrationView {
    /// The minted slug.
    pub agent_id: String,
    /// Tenant this registration belongs to.
    pub tenant: String,
    /// The OAuth-style identifier, stable across secret rotations.
    pub client_id: String,
    /// What the submitter said about the agent.
    pub metadata: AgentMetadata,
    /// Where the registration is in its life.
    pub state: ApprovalState,
    /// Operator-supplied justification on the last decision.
    pub reason: Option<String>,
    /// Who made the last decision, when an admin session identified one.
    pub decided_by: Option<String>,
    /// When it was submitted.
    pub created_at: DateTime<Utc>,
    /// When it last changed.
    pub updated_at: DateTime<Utc>,
    /// When its secret was last rotated.
    pub rotated_at: Option<DateTime<Utc>>,
}

impl From<&RegistrationRecord> for RegistrationView {
    fn from(record: &RegistrationRecord) -> Self {
        Self {
            agent_id: record.agent_id.clone(),
            tenant: record.tenant.clone(),
            client_id: record.client_id.clone(),
            metadata: record.metadata.clone(),
            state: record.state,
            reason: record.reason.clone(),
            decided_by: record.decided_by.clone(),
            created_at: record.created_at,
            updated_at: record.updated_at,
            rotated_at: record.rotated_at,
        }
    }
}

/// What a submitter gets back, once.
///
/// `Debug` is hand written: a derived one would print both secrets, and
/// this value is the return of a handler that logs its own outcome.
#[derive(Clone, Serialize)]
#[non_exhaustive]
pub struct RegistrationSecrets {
    /// The minted slug.
    pub agent_id: String,
    /// The OAuth-style identifier.
    pub client_id: String,
    /// The plaintext client secret. Not stored, and never returned again.
    pub client_secret: String,
    /// The plaintext registration access token, which is what authenticates
    /// a later self-service rotation. Not stored, never returned again.
    pub registration_access_token: String,
    /// Always true at creation: an approval is a human decision.
    pub pending_approval: bool,
    /// When the registration was accepted into the queue.
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for RegistrationSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrationSecrets")
            .field("agent_id", &self.agent_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("registration_access_token", &"<redacted>")
            .field("pending_approval", &self.pending_approval)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// What a rotation returns.
#[derive(Clone, Serialize)]
#[non_exhaustive]
pub struct RotatedSecret {
    /// The slug whose secret rotated.
    pub agent_id: String,
    /// The fresh plaintext client secret.
    pub client_secret: String,
    /// When the previous secret stops being accepted.
    pub previous_secret_valid_until: DateTime<Utc>,
    /// When the rotation happened.
    pub rotated_at: DateTime<Utc>,
}

impl std::fmt::Debug for RotatedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RotatedSecret")
            .field("agent_id", &self.agent_id)
            .field("client_secret", &"<redacted>")
            .field(
                "previous_secret_valid_until",
                &self.previous_secret_valid_until,
            )
            .field("rotated_at", &self.rotated_at)
            .finish()
    }
}

/// Argon2id at OWASP's recommended parameters: 19 MiB, two iterations, one
/// lane.
fn hasher() -> Result<Argon2<'static>> {
    let params = Params::new(19 * 1024, 2, 1, None)
        .map_err(|error| RegistryError::Backend(format!("argon2 parameters rejected: {error}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash a plaintext credential into a PHC string, off the executor.
///
/// Argon2id at these parameters is roughly 100 ms of CPU and 19 MiB of
/// allocation. Run inline on an `async fn` it holds an executor thread for
/// that long, and `register` does two of them back to back; ten concurrent
/// submissions would stall unrelated admin requests scheduled behind them.
async fn hash_credential_off_thread(plaintext: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_credential(&plaintext))
        .await
        .map_err(|error| RegistryError::Backend(format!("argon2 task failed: {error}")))?
}

/// Constant-time verify, off the executor, for the same reason.
async fn verify_credential_off_thread(plaintext: String, encoded: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || verify_credential(&plaintext, &encoded))
        .await
        .map_err(|error| RegistryError::Backend(format!("argon2 task failed: {error}")))?
}

/// Hash a plaintext credential into a PHC string.
fn hash_credential(plaintext: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()?
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|error| RegistryError::Backend(format!("argon2 hash failed: {error}")))?;
    Ok(hash.to_string())
}

/// Constant-time verify a plaintext credential against a stored PHC string.
fn verify_credential(plaintext: &str, encoded: &str) -> Result<bool> {
    let parsed = PasswordHash::new(encoded)
        .map_err(|error| RegistryError::Backend(format!("stored hash unreadable: {error}")))?;
    Ok(hasher()?
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok())
}

/// Collapse a vendor name to a kebab-case slug prefix.
///
/// ASCII only, non-alphanumerics collapse to one hyphen, and an empty
/// result becomes `agent` rather than an empty prefix, so the composed slug
/// is always a legal store key.
fn vendor_slug(vendor: &str) -> String {
    let mut out = String::with_capacity(vendor.len());
    let mut previous_was_dash = false;
    for character in vendor.chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character.to_ascii_lowercase());
            previous_was_dash = false;
        } else if !previous_was_dash {
            out.push('-');
            previous_was_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "agent".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Mint `<vendor-slug>-<ulid>`. The ULID is what makes two simultaneous
/// registrations of the same vendor name two distinct agents.
fn mint_agent_id(vendor: &str) -> String {
    format!("{}-{}", vendor_slug(vendor), Ulid::new())
}

fn mint_secret(prefix: &str) -> String {
    let mut buffer = [0u8; 32];
    OsRng.fill_bytes(&mut buffer);
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buffer)
    )
}

/// Fingerprint metadata for the duplicate-detection window.
///
/// Canonical JSON over the sorted arrays, so the same submission in a
/// different array order fingerprints identically and a retry with the
/// fields shuffled is still recognized as a retry.
fn metadata_fingerprint(metadata: &AgentMetadata) -> Result<String> {
    let mut canonical = metadata.clone();
    canonical.expected_user_agents.sort();
    canonical.expected_reverse_dns_suffixes.sort();
    canonical.expected_keyids.sort();
    canonical.requested_scopes.sort_by_key(|scope| *scope as u8);
    let bytes = serde_json_canonicalizer::to_vec(&canonical).map_err(|error| {
        RegistryError::Backend(format!("could not canonicalize metadata: {error}"))
    })?;
    let mut digest = Sha256::new();
    digest.update(&bytes);
    Ok(hex::encode(digest.finalize()))
}

/// The registration queue, over the shared embedded store.
pub struct RegistrationQueue {
    store: Arc<dyn PersistentKv>,
    dedup: Arc<dyn EphemeralKv>,
    registrations: KvNamespace,
    metadata_index: KvNamespace,
    dedup_window: KvNamespace,
    duplicate_window: Duration,
    rotation_grace: Duration,
    /// Live count per state, in [`ApprovalState`] declaration order.
    ///
    /// Seeded once by [`Self::seed_gauge_counts`] and adjusted by every
    /// mutation afterwards. The alternative, re-listing and re-parsing
    /// every record to publish a gauge after every write, is quadratic in
    /// queue depth and pays a full-table read and a JSON parse per record
    /// for four numbers. [`Self::counts`] still scans, because it answers
    /// per tenant and an admin summary is not on any hot path.
    gauge_counts: [AtomicUsize; 4],
}

/// Most pending registrations the queue holds before it refuses new ones.
///
/// A queue with no bound is a disk-exhaustion primitive, and the deployment
/// `docs/agent-registry.md` describes (an operator fronting the submission
/// route for public self-service) is the one where whoever fills it is a
/// stranger. Terminal records are not counted against it: they are the audit
/// trail, they cannot be resubmitted, and evicting them would be evicting
/// the durable replay refusal itself.
///
/// `pub(crate)`: the refusal carries the number, so a caller reading the
/// error does not need the constant, and nothing outside this crate decides
/// the cap.
pub(crate) const MAX_PENDING_REGISTRATIONS: usize = 5_000;

/// One decision, as a value, so the four things that vary between approve,
/// reject, and revoke travel together instead of as a row of positional
/// arguments nobody can read at the call site.
struct DecisionRequest<'a> {
    scope: &'a TenantScope,
    agent_id: &'a str,
    action: &'static str,
    target: ApprovalState,
    from: &'static [ApprovalState],
    reason: Option<String>,
    decided_by: Option<String>,
    now: DateTime<Utc>,
}

impl RegistrationQueue {
    /// Namespace holding one JSON record per registration.
    const REGISTRATIONS: &'static str = "agent_registrations";
    /// Namespace holding one entry per decided metadata fingerprint,
    /// keyed on the fingerprint rather than on the minted slug.
    ///
    /// The slug is `<vendor>-<ULID>`, freshly minted on every submission,
    /// so a slug is never the thing a resubmission reuses and a burn keyed
    /// on one can never fire. The fingerprint is: a submitter who sends
    /// the same description twice produces the same hash both times, which
    /// is what makes this the reachable half of the enterprise queue's two
    /// durable replay checks.
    const METADATA_INDEX: &'static str = "agent_metadata_index";
    /// Namespace holding the duplicate-detection window.
    const DEDUP: &'static str = "agent_registration_dedup";

    /// Build a queue over a durable store and an ephemeral dedup window.
    pub fn new(
        store: Arc<dyn PersistentKv>,
        dedup: Arc<dyn EphemeralKv>,
        duplicate_window: Duration,
        rotation_grace: Duration,
    ) -> Result<Self> {
        let namespace = |name: &'static str| {
            KvNamespace::new(name).map_err(|error| RegistryError::Backend(error.to_string()))
        };
        Ok(Self {
            store,
            dedup,
            registrations: namespace(Self::REGISTRATIONS)?,
            metadata_index: namespace(Self::METADATA_INDEX)?,
            dedup_window: namespace(Self::DEDUP)?,
            duplicate_window,
            rotation_grace,
            gauge_counts: Default::default(),
        })
    }

    /// Index into [`Self::gauge_counts`] for one state.
    fn gauge_slot(state: ApprovalState) -> usize {
        match state {
            ApprovalState::Pending => 0,
            ApprovalState::Approved => 1,
            ApprovalState::Rejected => 2,
            ApprovalState::Revoked => 3,
        }
    }

    /// Read the store once and seed the live counts from it.
    ///
    /// Called at boot. Everything after that is incremental, so the full
    /// scan happens once per process rather than once per write.
    pub async fn seed_gauge_counts(&self) -> Result<()> {
        for (state, count) in self.counts(&TenantScope::All).await? {
            self.gauge_counts[Self::gauge_slot(state)].store(count, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Move one record between two count slots.
    fn adjust_gauge_counts(&self, from: Option<ApprovalState>, to: ApprovalState) {
        if let Some(from) = from {
            let slot = &self.gauge_counts[Self::gauge_slot(from)];
            // Saturating: a count seeded before a sibling process wrote the
            // same store could otherwise wrap to `usize::MAX` and render a
            // gauge nobody can read.
            let _ = slot.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
        }
        self.gauge_counts[Self::gauge_slot(to)].fetch_add(1, Ordering::Relaxed);
    }

    /// The live per-state counts, without touching the store.
    pub fn gauge_counts(&self) -> Vec<(ApprovalState, usize)> {
        [
            ApprovalState::Pending,
            ApprovalState::Approved,
            ApprovalState::Rejected,
            ApprovalState::Revoked,
        ]
        .into_iter()
        .map(|state| {
            (
                state,
                self.gauge_counts[Self::gauge_slot(state)].load(Ordering::Relaxed),
            )
        })
        .collect()
    }

    /// Read one record, refusing one another tenant owns.
    ///
    /// A record outside the scope answers `NotFound` rather than a
    /// forbidden, on purpose: a distinct refusal would make this route an
    /// oracle for which agent ids exist in other tenants, and the caller
    /// cannot act on the difference either way.
    async fn load(&self, scope: &TenantScope, agent_id: &str) -> Result<(RegistrationRecord, u64)> {
        let entry = self
            .store
            .get(&self.registrations, agent_id)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?
            .ok_or_else(|| RegistryError::NotFound(agent_id.to_string()))?;
        let record: RegistrationRecord = serde_json::from_slice(&entry.value).map_err(|error| {
            RegistryError::Backend(format!("stored registration is unreadable: {error}"))
        })?;
        if !scope.admits(&record.tenant) {
            return Err(RegistryError::NotFound(agent_id.to_string()));
        }
        Ok((record, entry.revision))
    }

    /// Write a record back only if nothing else has changed it since it was
    /// read, so two reviewers deciding the same registration at once cannot
    /// both win.
    async fn store_if_unchanged(
        &self,
        record: &RegistrationRecord,
        expected_revision: u64,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|error| {
            RegistryError::Backend(format!("could not encode registration: {error}"))
        })?;
        match self
            .store
            .put_if_revision(
                &self.registrations,
                &record.agent_id,
                &bytes,
                expected_revision,
            )
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?
        {
            CasOutcome::Applied { .. } => Ok(()),
            CasOutcome::Conflict { .. } => Err(RegistryError::Conflict(record.agent_id.clone())),
            CasOutcome::NotFound => Err(RegistryError::NotFound(record.agent_id.clone())),
        }
    }

    /// Record what a reviewer decided about this metadata, keyed on the
    /// fingerprint, so the decision outlives the record's own key and the
    /// process.
    /// Compose the metadata index key.
    ///
    /// Tenant-qualified, so one tenant's rejection does not refuse another
    /// tenant's identical description. Both halves are hex, so a `:`
    /// cannot appear in either and the tenant is always the part before
    /// the first one.
    fn index_key(tenant: &str, fingerprint: &str) -> String {
        format!("{}:{fingerprint}", tenant_index_key(tenant))
    }

    async fn index_decision(&self, record: &RegistrationRecord) -> Result<()> {
        let entry = MetadataIndexEntry {
            agent_id: record.agent_id.clone(),
            state: record.state,
        };
        let bytes = serde_json::to_vec(&entry).map_err(|error| {
            RegistryError::Backend(format!("could not encode metadata index entry: {error}"))
        })?;
        self.store
            .put(
                &self.metadata_index,
                &Self::index_key(&record.tenant, &record.metadata_hash),
                &bytes,
            )
            .await
            .map(|_| ())
            .map_err(|error| RegistryError::Backend(error.to_string()))
    }

    /// What a reviewer has already decided about this metadata, if
    /// anything.
    async fn indexed_decision(
        &self,
        tenant: &str,
        fingerprint: &str,
    ) -> Result<Option<MetadataIndexEntry>> {
        let Some(entry) = self
            .store
            .get(&self.metadata_index, &Self::index_key(tenant, fingerprint))
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&entry.value)
            .map(Some)
            .map_err(|error| {
                RegistryError::Backend(format!(
                    "stored metadata index entry is unreadable: {error}"
                ))
            })
    }

    /// Accept a submission into the queue.
    ///
    /// The order is validate, fingerprint, check both replay guards, mint,
    /// insert. Minting after the checks means a recognized retry costs no
    /// Argon2id work and produces no new slug.
    ///
    /// # Two replay guards, and the different questions they answer
    ///
    /// The durable one is the metadata index. A reviewer's decision is
    /// stored against the fingerprint of what they decided about, so
    /// resubmitting an identical description gets the reviewer's answer
    /// back rather than a fresh queue slot: a rejection or a revocation is
    /// terminal, and an approved agent's description cannot become a
    /// second agent with its own credentials. That is the enterprise
    /// queue's durable half, which this port originally kept the shape of
    /// and dropped the query.
    ///
    /// The ephemeral one is the window, and it owns exactly one case the
    /// index does not: a submission nobody has decided yet. Keeping that
    /// case out of the durable index is deliberate. A pending submission
    /// that a reviewer never gets to should not block its submitter
    /// forever, so it expires after `duplicate_window_secs` and a
    /// resubmission then takes a fresh slot.
    pub async fn register(
        &self,
        scope: &TenantScope,
        metadata: AgentMetadata,
        now: DateTime<Utc>,
    ) -> Result<(RegistrationSecrets, RegistrationView)> {
        metadata.validate()?;
        let tenant = scope.owning_tenant().to_string();
        let fingerprint = metadata_fingerprint(&metadata)?;

        // Checked before the replay guards rather than after, so a full
        // queue costs one atomic load rather than two store reads.
        let pending =
            self.gauge_counts[Self::gauge_slot(ApprovalState::Pending)].load(Ordering::Relaxed);
        if pending >= MAX_PENDING_REGISTRATIONS {
            return Err(RegistryError::QueueFull {
                limit: MAX_PENDING_REGISTRATIONS,
            });
        }

        if let Some(decided) = self.indexed_decision(&tenant, &fingerprint).await? {
            match decided.state {
                ApprovalState::Rejected | ApprovalState::Revoked => {
                    return Err(RegistryError::MetadataBurned {
                        agent_id: decided.agent_id,
                        decision: decided.state.as_str(),
                    })
                }
                ApprovalState::Approved => {
                    return Err(RegistryError::DuplicateMetadata(decided.agent_id))
                }
                // An indexed Pending entry cannot occur: only a decision
                // writes the index. Treated as no decision rather than as a
                // refusal, so a future writer that broadens the index does
                // not silently become a permanent block.
                ApprovalState::Pending => {}
            }
        }

        if let Some(existing) = self
            .dedup
            .get(&self.dedup_window, &Self::index_key(&tenant, &fingerprint))
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?
        {
            let agent_id = String::from_utf8_lossy(&existing).to_string();
            // A window entry that outlived its record is stale rather than
            // a duplicate: fall through and let the resubmission take a
            // fresh slot. A decided record is the index's business, not
            // this one's, and the index was already consulted above.
            if let Ok((record, _)) = self.load(scope, &agent_id).await {
                if record.state == ApprovalState::Pending {
                    return Err(RegistryError::DuplicateMetadata(agent_id));
                }
            }
        }

        let agent_id = mint_agent_id(&metadata.vendor);

        let client_secret = mint_secret(CLIENT_SECRET_PREFIX);
        let registration_access_token = mint_secret(REGISTRATION_ACCESS_TOKEN_PREFIX);
        let record = RegistrationRecord {
            agent_id: agent_id.clone(),
            tenant: tenant.clone(),
            client_id: Ulid::new().to_string(),
            client_secret_hash: hash_credential_off_thread(client_secret.clone()).await?,
            previous_client_secret_hash: None,
            previous_secret_valid_until: None,
            registration_access_token_hash: hash_credential_off_thread(
                registration_access_token.clone(),
            )
            .await?,
            metadata_hash: fingerprint.clone(),
            metadata,
            state: ApprovalState::Pending,
            reason: None,
            decided_by: None,
            created_at: now,
            updated_at: now,
            rotated_at: None,
        };

        let bytes = serde_json::to_vec(&record).map_err(|error| {
            RegistryError::Backend(format!("could not encode registration: {error}"))
        })?;
        let landed = self
            .store
            .insert_if_absent(&self.registrations, &agent_id, &bytes)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?;
        if landed.is_none() {
            return Err(RegistryError::Conflict(agent_id));
        }
        self.adjust_gauge_counts(None, ApprovalState::Pending);

        let window = self
            .duplicate_window
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(0));
        if !window.is_zero() {
            let recorded = self
                .dedup
                .put_with_ttl(
                    &self.dedup_window,
                    &Self::index_key(&tenant, &fingerprint),
                    agent_id.as_bytes(),
                    window,
                )
                .await
                .map_err(|error| RegistryError::Backend(error.to_string()))?;
            if !recorded {
                // The window store is at its cap and refused the write, so
                // this fingerprint is not in the window and the next
                // identical submission will not be suppressed by it. Not a
                // refusal of the registration, which has already landed,
                // and not silence either: the durable index still catches
                // every decided description, and what is lost is only the
                // undecided case.
                record_registry_op("register", "dedup_window_full");
                tracing::warn!(
                    "the registration duplicate-detection window is at its capacity; an \
                     identical resubmission of an undecided registration will take a fresh \
                     slot until the window drains"
                );
            }
        }

        Ok((
            RegistrationSecrets {
                agent_id: record.agent_id.clone(),
                client_id: record.client_id.clone(),
                client_secret,
                registration_access_token,
                pending_approval: true,
                created_at: now,
            },
            RegistrationView::from(&record),
        ))
    }

    /// Read one registration.
    pub async fn get(&self, scope: &TenantScope, agent_id: &str) -> Result<RegistrationView> {
        Ok(RegistrationView::from(&self.load(scope, agent_id).await?.0))
    }

    /// List every registration, newest submission last, optionally filtered
    /// to one state.
    pub async fn list(
        &self,
        scope: &TenantScope,
        state: Option<ApprovalState>,
    ) -> Result<Vec<RegistrationView>> {
        let stored = self
            .store
            .list(&self.registrations)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?;
        let mut out = Vec::with_capacity(stored.len());
        for (_, entry) in stored {
            let record: RegistrationRecord = serde_json::from_slice(&entry.value).map_err(|e| {
                RegistryError::Backend(format!("stored registration is unreadable: {e}"))
            })?;
            if scope.admits(&record.tenant) && state.is_none_or(|wanted| wanted == record.state) {
                out.push(RegistrationView::from(&record));
            }
        }
        out.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.agent_id.cmp(&right.agent_id))
        });
        Ok(out)
    }

    /// Apply a decision to a pending or approved registration.
    ///
    /// The three decisions differ only in the four fields of
    /// [`DecisionRequest`], so they share one implementation: the read, the
    /// legality check, the compare-and-swap write, and the index write are
    /// the same four steps in the same order every time, and a copy per
    /// decision is where a missing index write or a missing legality check
    /// comes from.
    async fn decide(&self, request: DecisionRequest<'_>) -> Result<RegistrationView> {
        if let Some(reason) = request.reason.as_deref() {
            bounded("reason", reason, 0, MAX_REASON_BYTES)?;
        }
        let (mut record, revision) = self.load(request.scope, request.agent_id).await?;
        if record.state == request.target {
            // The compare-and-swap landed and the index write did not, or
            // the same decision is being retried. Re-index and answer
            // success: leaving a terminal record whose description is not
            // indexed would let the submitter resubmit it, and there is no
            // other route that would ever repair it.
            self.index_decision(&record).await?;
            return Ok(RegistrationView::from(&record));
        }
        if !request.from.contains(&record.state) {
            return Err(RegistryError::InvalidTransition {
                action: request.action,
                state: record.state.as_str(),
            });
        }
        let previous = record.state;
        record.state = request.target;
        record.reason = request.reason;
        record.decided_by = request.decided_by;
        record.updated_at = request.now;
        self.store_if_unchanged(&record, revision).await?;
        self.adjust_gauge_counts(Some(previous), request.target);
        // Every decision is indexed, not only the terminal ones: an
        // approval has to stop the same description becoming a second
        // agent with its own credentials, which is the case the enterprise
        // queue refused with `Pending | Approved` and this port dropped.
        self.index_decision(&record).await?;
        Ok(RegistrationView::from(&record))
    }

    /// Approve a pending registration.
    pub async fn approve(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        reason: Option<String>,
        decided_by: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationView> {
        self.decide(DecisionRequest {
            scope,
            agent_id,
            action: "approve",
            target: ApprovalState::Approved,
            from: &[ApprovalState::Pending],
            reason,
            decided_by,
            now,
        })
        .await
    }

    /// Reject a pending registration. The description is refused for good.
    pub async fn reject(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        reason: String,
        decided_by: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationView> {
        self.decide(DecisionRequest {
            scope,
            agent_id,
            action: "reject",
            target: ApprovalState::Rejected,
            from: &[ApprovalState::Pending],
            reason: Some(reason),
            decided_by,
            now,
        })
        .await
    }

    /// Revoke a registration. The description is refused for good.
    pub async fn revoke(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        reason: Option<String>,
        decided_by: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<RegistrationView> {
        self.decide(DecisionRequest {
            scope,
            agent_id,
            action: "revoke",
            target: ApprovalState::Revoked,
            from: &[ApprovalState::Pending, ApprovalState::Approved],
            reason,
            decided_by,
            now,
        })
        .await
    }

    /// Rotate a registration's client secret, authenticated by the
    /// registration access token the submitter was given.
    ///
    /// The previous secret keeps working until the grace window ends, which
    /// is what lets a fleet of workers pick the new one up without a
    /// synchronized restart. A registration that is not approved cannot
    /// rotate: there is nothing yet for the secret to authenticate against.
    pub async fn rotate_secret(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        registration_access_token: &str,
        now: DateTime<Utc>,
    ) -> Result<RotatedSecret> {
        let (mut record, revision) = match self.load(scope, agent_id).await {
            Ok(loaded) => loaded,
            // An unknown id and a wrong token answer identically, so the
            // endpoint is not an oracle for which slugs exist.
            Err(RegistryError::NotFound(_)) => return Err(RegistryError::Unauthorized),
            Err(other) => return Err(other),
        };
        if !verify_credential_off_thread(
            registration_access_token.to_string(),
            record.registration_access_token_hash.clone(),
        )
        .await?
        {
            return Err(RegistryError::Unauthorized);
        }
        if record.state != ApprovalState::Approved {
            return Err(RegistryError::InvalidTransition {
                action: "rotate",
                state: record.state.as_str(),
            });
        }

        let client_secret = mint_secret(CLIENT_SECRET_PREFIX);
        let previous_secret_valid_until = now + self.rotation_grace;
        record.previous_client_secret_hash = Some(record.client_secret_hash.clone());
        record.previous_secret_valid_until = Some(previous_secret_valid_until);
        record.client_secret_hash = hash_credential_off_thread(client_secret.clone()).await?;
        record.rotated_at = Some(now);
        record.updated_at = now;
        self.store_if_unchanged(&record, revision).await?;

        Ok(RotatedSecret {
            agent_id: agent_id.to_string(),
            client_secret,
            previous_secret_valid_until,
            rotated_at: now,
        })
    }

    /// Whether `presented` is this agent's current secret, or its previous
    /// one inside the rotation grace window.
    ///
    /// Only an approved registration authenticates. A pending one has not
    /// been allowed yet and a terminal one has been withdrawn, and treating
    /// either as valid would make the approval gate decorative.
    pub async fn verify_client_secret(
        &self,
        scope: &TenantScope,
        agent_id: &str,
        presented: &str,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let Ok((record, _)) = self.load(scope, agent_id).await else {
            return Ok(false);
        };
        if record.state != ApprovalState::Approved {
            return Ok(false);
        }
        if verify_credential_off_thread(presented.to_string(), record.client_secret_hash.clone())
            .await?
        {
            return Ok(true);
        }
        match (
            record.previous_client_secret_hash.as_deref(),
            record.previous_secret_valid_until,
        ) {
            (Some(previous), Some(valid_until)) if now < valid_until => {
                verify_credential_off_thread(presented.to_string(), previous.to_string()).await
            }
            _ => Ok(false),
        }
    }

    /// How many registrations sit in each state, for the admin summary and
    /// the gauge.
    pub async fn counts(&self, scope: &TenantScope) -> Result<Vec<(ApprovalState, usize)>> {
        let all = self.list(scope, None).await?;
        let mut counts = Vec::new();
        for state in [
            ApprovalState::Pending,
            ApprovalState::Approved,
            ApprovalState::Rejected,
            ApprovalState::Revoked,
        ] {
            counts.push((state, all.iter().filter(|view| view.state == state).count()));
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_platform::storage::{EmbeddedKvStore, MemoryKv};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed instant")
    }

    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}/sbproxy_agent_registry_test_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n
        )
    }

    fn queue(path: &str) -> RegistrationQueue {
        let store = EmbeddedKvStore::open(path, "agent_registry").expect("open store");
        RegistrationQueue::new(
            Arc::new(store),
            Arc::new(MemoryKv::new("agent_registry")),
            Duration::hours(1),
            Duration::days(30),
        )
        .expect("queue")
    }

    fn metadata() -> AgentMetadata {
        AgentMetadata {
            vendor: "Acme Research Labs".into(),
            purpose: Purpose::Research,
            contact_url: "https://acme.example.com/bots".into(),
            expected_user_agents: vec!["AcmeBot/1.0".into()],
            expected_reverse_dns_suffixes: vec![".bots.acme.example.com".into()],
            expected_keyids: vec!["ed25519:THUMBPRINT".into()],
            requested_scopes: vec![RequestedScope::CrawlPublic],
        }
    }

    /// Argon2id at these parameters is roughly 100 ms of CPU and 19 MiB of
    /// allocation per call. Every one has to go to the blocking pool: run
    /// inline on an `async fn` it holds an executor thread for that long,
    /// and this crate's routes are on the admin connection task. The round
    /// that moved the other four call sites left `rotate_secret`'s verify
    /// behind while its commit message claimed all of them had moved, so
    /// this reads the file rather than trusting the claim.
    #[test]
    fn every_argon2_call_goes_through_the_blocking_pool() {
        // Split so this test's own source cannot match itself.
        let hash = concat!("hash_", "credential(");
        let verify = concat!("verify_", "credential(");
        let mut inline = Vec::new();
        for (offset, line) in include_str!("registration.rs").lines().enumerate() {
            let trimmed = line.trim_start();
            // The two definitions, and the two `spawn_blocking` wrappers
            // that are the only legitimate callers of them.
            if trimmed.starts_with("fn ")
                || trimmed.starts_with("async fn ")
                || trimmed.starts_with("tokio::task::spawn_blocking")
            {
                continue;
            }
            if (trimmed.contains(hash) || trimmed.contains(verify))
                && !trimmed.contains("_off_thread")
            {
                inline.push(offset + 1);
            }
        }
        assert!(
            inline.is_empty(),
            "registration.rs calls the synchronous Argon2 helpers on the executor at lines \
             {inline:?}; use hash_credential_off_thread / verify_credential_off_thread"
        );
    }

    /// The replay index's tenant half used to be a sanitized spelling,
    /// which collapses everything outside `[A-Za-z0-9_-]` onto `_`. Two
    /// tenant names one keystroke apart shared one index, so one tenant
    /// rejecting a description refused the other tenant's identical one:
    /// the exact property the tenant qualifier exists to provide.
    #[test]
    fn two_tenants_that_sanitize_alike_do_not_share_a_replay_index() {
        let fingerprint = "abc123";
        assert_ne!(
            RegistrationQueue::index_key("acme.corp", fingerprint),
            RegistrationQueue::index_key("acme corp", fingerprint)
        );
        assert_ne!(
            RegistrationQueue::index_key("acme/corp", fingerprint),
            RegistrationQueue::index_key("acme_corp", fingerprint)
        );

        // Same tenant, same key, every time.
        assert_eq!(
            RegistrationQueue::index_key("acme.corp", fingerprint),
            RegistrationQueue::index_key("acme.corp", fingerprint)
        );

        // The separator stays unambiguous: both halves are hex.
        let key = RegistrationQueue::index_key("acme.corp", fingerprint);
        assert_eq!(key.matches(':').count(), 1);
        let (tenant, tail) = key.split_once(':').expect("one separator");
        assert!(tenant.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(tail, fingerprint);
    }

    /// The queue had no bound at all, and `docs/agent-registry.md` tells an
    /// operator to front the submission route for public self-service, so
    /// whoever fills it need not be anybody they know. Terminal records are
    /// deliberately not counted against the cap: they are the durable
    /// replay refusal and the audit trail.
    #[tokio::test]
    async fn a_full_pending_queue_refuses_rather_than_growing() {
        let path = temp_path();
        let queue = queue(&path);

        // Reaching the cap through 5,000 Argon2id submissions would cost
        // minutes, so the counter the production check reads is set
        // directly. The refusal below is the shipped path.
        queue.gauge_counts[RegistrationQueue::gauge_slot(ApprovalState::Pending)]
            .store(MAX_PENDING_REGISTRATIONS, Ordering::Relaxed);
        match queue.register(&TenantScope::All, metadata(), now()).await {
            Err(RegistryError::QueueFull { limit }) => {
                assert_eq!(limit, MAX_PENDING_REGISTRATIONS)
            }
            other => panic!("a full queue must refuse, got {other:?}"),
        }

        // A reviewer working one record off the queue makes room again.
        queue.gauge_counts[RegistrationQueue::gauge_slot(ApprovalState::Pending)]
            .store(MAX_PENDING_REGISTRATIONS - 1, Ordering::Relaxed);
        queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("room was made");

        std::fs::remove_file(&path).ok();
    }

    /// The gauge counts are maintained incrementally rather than by
    /// re-listing and re-parsing every record after every write, so they
    /// have to agree with a full scan after a mixed run of mutations.
    #[tokio::test]
    async fn the_incremental_gauge_counts_agree_with_a_full_scan() {
        let path = temp_path();
        let live = queue(&path);

        let (first, _) = live
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("first");
        let mut second_meta = metadata();
        second_meta.vendor = "Globex".into();
        let (second, _) = live
            .register(&TenantScope::All, second_meta, now())
            .await
            .expect("second");
        let mut third_meta = metadata();
        third_meta.vendor = "Initech".into();
        live.register(&TenantScope::All, third_meta, now())
            .await
            .expect("third");

        live.approve(&TenantScope::All, &first.agent_id, None, None, now())
            .await
            .expect("approve");
        live.reject(
            &TenantScope::All,
            &second.agent_id,
            "no".into(),
            None,
            now(),
        )
        .await
        .expect("reject");
        live.revoke(&TenantScope::All, &first.agent_id, None, None, now())
            .await
            .expect("revoke");

        assert_eq!(
            live.gauge_counts(),
            live.counts(&TenantScope::All).await.expect("scan")
        );

        // And a restart re-seeds them from the store rather than starting
        // at zero and reporting an empty queue an operator would read as a
        // drained one.
        drop(live);
        let reopened = queue(&path);
        reopened.seed_gauge_counts().await.expect("seed");
        assert_eq!(
            reopened.gauge_counts(),
            reopened.counts(&TenantScope::All).await.expect("scan")
        );
        assert_eq!(
            reopened.gauge_counts()[RegistrationQueue::gauge_slot(ApprovalState::Pending)].1,
            1
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn vendor_slug_collapses_and_trims() {
        assert_eq!(vendor_slug("Acme Research Labs"), "acme-research-labs");
        assert_eq!(vendor_slug("  acme!@#labs  "), "acme-labs");
        assert_eq!(vendor_slug(""), "agent");
        assert_eq!(vendor_slug("!!!"), "agent");
    }

    #[test]
    fn the_fingerprint_ignores_array_order_and_notices_a_real_change() {
        let mut a = metadata();
        let mut b = metadata();
        a.expected_user_agents = vec!["AcmeBot/1.0".into(), "AcmeBot/2.0".into()];
        b.expected_user_agents = vec!["AcmeBot/2.0".into(), "AcmeBot/1.0".into()];
        assert_eq!(
            metadata_fingerprint(&a).expect("a"),
            metadata_fingerprint(&b).expect("b")
        );

        b.vendor = "Different Inc".into();
        assert_ne!(
            metadata_fingerprint(&a).expect("a"),
            metadata_fingerprint(&b).expect("b")
        );
    }

    #[test]
    fn metadata_validation_refuses_the_shapes_the_docs_forbid() {
        let mut meta = metadata();
        meta.contact_url = "http://acme.example.com".into();
        assert!(matches!(
            meta.validate(),
            Err(RegistryError::Invalid {
                field: "contact_url",
                ..
            })
        ));

        let mut meta = metadata();
        meta.expected_user_agents.clear();
        assert!(meta.validate().is_err());

        let mut meta = metadata();
        meta.vendor = "v".repeat(MAX_VENDOR_BYTES + 1);
        assert!(meta.validate().is_err());

        let mut meta = metadata();
        meta.expected_keyids = vec!["no-colon".into()];
        assert!(meta.validate().is_err());

        // A prefix match accepts these; a parse does not.
        for bad in ["https://", "not a url", "https://?a=b"] {
            let mut meta = metadata();
            meta.contact_url = bad.into();
            assert!(meta.validate().is_err(), "{bad} must be refused");
        }
        let mut meta = metadata();
        meta.vendor = "   ".into();
        assert!(meta.validate().is_err(), "a blank vendor must be refused");
        let mut meta = metadata();
        meta.expected_user_agents = vec!["  ".into()];
        assert!(
            meta.validate().is_err(),
            "a blank user agent must be refused"
        );

        let mut meta = metadata();
        meta.requested_scopes.clear();
        assert!(meta.validate().is_err());
    }

    /// A minted secret exists once. What the store keeps is a hash, and the
    /// only way back is a verify, so a store file that leaks does not hand
    /// anyone a usable credential.
    #[tokio::test]
    async fn a_minted_secret_is_stored_only_as_a_hash() {
        let path = temp_path();
        let queue = queue(&path);
        let (secrets, _) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");

        queue
            .approve(
                &TenantScope::All,
                &secrets.agent_id,
                None,
                Some("casey".into()),
                now(),
            )
            .await
            .expect("approve");

        assert!(queue
            .verify_client_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &secrets.client_secret,
                now()
            )
            .await
            .expect("verify"));
        assert!(!queue
            .verify_client_secret(
                &TenantScope::All,
                &secrets.agent_id,
                "sk_agent_wrong",
                now()
            )
            .await
            .expect("verify"));

        // Nothing readable in the store is the plaintext secret.
        let raw = std::fs::read(&path).expect("read store file");
        assert!(
            !raw.windows(secrets.client_secret.len())
                .any(|window| window == secrets.client_secret.as_bytes()),
            "the plaintext client secret must never reach the store file"
        );
        assert!(
            !raw.windows(secrets.registration_access_token.len())
                .any(|window| window == secrets.registration_access_token.as_bytes()),
            "the plaintext registration access token must never reach the store file"
        );

        std::fs::remove_file(&path).ok();
    }

    /// The window is what turns a submitter's retry into one queue entry.
    #[tokio::test]
    async fn an_identical_resubmission_inside_the_window_is_refused() {
        let path = temp_path();
        let queue = queue(&path);
        let (first, _) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("first");

        match queue.register(&TenantScope::All, metadata(), now()).await {
            Err(RegistryError::DuplicateMetadata(existing)) => {
                assert_eq!(existing, first.agent_id);
            }
            other => panic!("expected a duplicate refusal, got {other:?}"),
        }

        // The window owns only the undecided case. Once a reviewer has
        // decided, the durable index owns the answer, and it is the same
        // answer forever.
        queue
            .reject(
                &TenantScope::All,
                &first.agent_id,
                "not a real crawler".into(),
                None,
                now(),
            )
            .await
            .expect("reject");
        assert!(matches!(
            queue.register(&TenantScope::All, metadata(), now()).await,
            Err(RegistryError::MetadataBurned { .. })
        ));

        // A submission nobody ever decided expires out of the window, so a
        // submitter is not blocked forever by a queue entry a reviewer
        // never reached.
        let mut fresh = metadata();
        fresh.vendor = "Globex".into();
        let short = RegistrationQueue::new(
            Arc::new(EmbeddedKvStore::open(temp_path(), "agent_registry").expect("store")),
            Arc::new(MemoryKv::new("agent_registry")),
            // 300ms, not 30. Both `register` calls below write through an
            // embedded redb store, and the duplicate assertion only holds
            // while the second one lands inside this window. At 30ms that
            // was a wall-clock race against two durable writes: green
            // alone and on an idle machine, red under a loaded full-suite
            // run, where the disk is contended. Nothing about the property
            // needs the window to be tight, so it is not. The `sleep`
            // below moves with it, or the expiry half of this test stops
            // proving anything.
            Duration::milliseconds(300),
            Duration::days(30),
        )
        .expect("queue");
        let (pending, _) = short
            .register(&TenantScope::All, fresh.clone(), now())
            .await
            .expect("first");
        assert!(matches!(
            short
                .register(&TenantScope::All, fresh.clone(), now())
                .await,
            Err(RegistryError::DuplicateMetadata(_))
        ));
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let (second, _) = short
            .register(&TenantScope::All, fresh, now())
            .await
            .expect("an undecided submission expires out of the window");
        assert_ne!(second.agent_id, pending.agent_id);

        std::fs::remove_file(&path).ok();
    }

    /// A rejection is final for that description. This is the durable half
    /// of the enterprise queue's replay protection, and the port had
    /// dropped it: the slug burn it shipped instead was keyed on a
    /// freshly minted ULID and could never fire, so a rejected submitter
    /// could re-POST byte-identical metadata and land a second pending row
    /// for a different reviewer to approve.
    #[tokio::test]
    async fn a_rejected_description_cannot_be_resubmitted() {
        let path = temp_path();
        let first_boot = queue(&path);
        let (first, _) = first_boot
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");

        first_boot
            .reject(
                &TenantScope::All,
                &first.agent_id,
                "unverifiable".into(),
                Some("casey".into()),
                now(),
            )
            .await
            .expect("reject");

        match first_boot
            .register(&TenantScope::All, metadata(), now())
            .await
        {
            Err(RegistryError::MetadataBurned { agent_id, decision }) => {
                assert_eq!(agent_id, first.agent_id);
                assert_eq!(decision, "rejected");
            }
            other => panic!("a rejected description must stay rejected, got {other:?}"),
        }

        // The refusal survives a restart, which is the whole point of it
        // being durable rather than a one-hour window.
        drop(first_boot);
        let reopened = queue(&path);
        assert!(matches!(
            reopened
                .register(&TenantScope::All, metadata(), now())
                .await,
            Err(RegistryError::MetadataBurned { .. })
        ));

        // A different description from the same vendor is a different
        // question and is still accepted.
        let mut other = metadata();
        other.expected_user_agents = vec!["AcmeBot/2.0".into()];
        assert!(reopened
            .register(&TenantScope::All, other, now())
            .await
            .is_ok());

        std::fs::remove_file(&path).ok();
    }

    /// An approved agent's description cannot become a second agent with
    /// its own credentials. Without this, revoking one of the pair leaves
    /// the other live and revocation stops being the control it is
    /// documented as.
    #[tokio::test]
    async fn an_approved_description_cannot_be_registered_twice() {
        let path = temp_path();
        let queue = queue(&path);
        let (first, _) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");
        queue
            .approve(
                &TenantScope::All,
                &first.agent_id,
                None,
                Some("casey".into()),
                now(),
            )
            .await
            .expect("approve");

        match queue.register(&TenantScope::All, metadata(), now()).await {
            Err(RegistryError::DuplicateMetadata(agent_id)) => {
                assert_eq!(agent_id, first.agent_id);
            }
            other => panic!("an approved description must not be registered twice, got {other:?}"),
        }

        // Revoking it does not reopen the description either: a withdrawn
        // agent's operator does not get to re-onboard the same one by
        // resubmitting.
        queue
            .revoke(
                &TenantScope::All,
                &first.agent_id,
                Some("key compromised".into()),
                None,
                now(),
            )
            .await
            .expect("revoke");
        assert!(matches!(
            queue.register(&TenantScope::All, metadata(), now()).await,
            Err(RegistryError::MetadataBurned {
                decision: "revoked",
                ..
            })
        ));

        std::fs::remove_file(&path).ok();
    }

    /// The state machine's own transitions, kept separate from the replay
    /// guards above.
    #[tokio::test]
    async fn a_terminal_registration_refuses_every_further_transition() {
        let path = temp_path();
        let queue = queue(&path);
        let (secrets, _) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");

        queue
            .reject(
                &TenantScope::All,
                &secrets.agent_id,
                "unverifiable".into(),
                None,
                now(),
            )
            .await
            .expect("reject");

        assert!(matches!(
            queue
                .approve(&TenantScope::All, &secrets.agent_id, None, None, now())
                .await,
            Err(RegistryError::InvalidTransition {
                action: "approve",
                state: "rejected"
            })
        ));
        assert!(matches!(
            queue
                .revoke(&TenantScope::All, &secrets.agent_id, None, None, now())
                .await,
            Err(RegistryError::InvalidTransition { .. })
        ));

        std::fs::remove_file(&path).ok();
    }

    /// Two reviewers deciding the same registration at once is the reason
    /// the store carries revisions. Whichever lands first wins, and the
    /// second is told rather than silently overwriting a terminal state.
    #[tokio::test]
    async fn a_second_reviewer_cannot_overwrite_a_decision_it_did_not_see() {
        let path = temp_path();
        let queue = queue(&path);
        let (secrets, _) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");

        // Both reviewers read the pending record.
        let (record, stale_revision) = queue
            .load(&TenantScope::All, &secrets.agent_id)
            .await
            .expect("load");
        assert_eq!(record.state, ApprovalState::Pending);

        // The first decision lands.
        queue
            .reject(
                &TenantScope::All,
                &secrets.agent_id,
                "unverifiable".into(),
                None,
                now(),
            )
            .await
            .expect("reject");

        // The second reviewer writes back against the revision it read.
        let mut stale = record;
        stale.state = ApprovalState::Approved;
        assert!(matches!(
            queue.store_if_unchanged(&stale, stale_revision).await,
            Err(RegistryError::Conflict(_))
        ));
        assert_eq!(
            queue
                .get(&TenantScope::All, &secrets.agent_id)
                .await
                .expect("get")
                .state,
            ApprovalState::Rejected
        );

        std::fs::remove_file(&path).ok();
    }

    /// Rotation is self-service and the registration access token is what
    /// authenticates it. A wrong token and an unknown id answer the same,
    /// so the endpoint cannot be used to enumerate slugs.
    #[tokio::test]
    async fn rotation_needs_the_registration_access_token_and_keeps_the_old_secret_working() {
        let path = temp_path();
        let queue = queue(&path);
        let (secrets, _) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");
        queue
            .approve(&TenantScope::All, &secrets.agent_id, None, None, now())
            .await
            .expect("approve");

        assert!(matches!(
            queue
                .rotate_secret(&TenantScope::All, &secrets.agent_id, "rat_wrong", now())
                .await,
            Err(RegistryError::Unauthorized)
        ));
        assert!(matches!(
            queue
                .rotate_secret(&TenantScope::All, "no-such-agent", "rat_wrong", now())
                .await,
            Err(RegistryError::Unauthorized)
        ));

        let rotated = queue
            .rotate_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &secrets.registration_access_token,
                now(),
            )
            .await
            .expect("rotate");
        assert_ne!(rotated.client_secret, secrets.client_secret);

        // Inside the grace window both secrets authenticate.
        assert!(queue
            .verify_client_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &rotated.client_secret,
                now()
            )
            .await
            .expect("new secret"));
        assert!(queue
            .verify_client_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &secrets.client_secret,
                now()
            )
            .await
            .expect("old secret inside grace"));

        // Past it, only the new one does.
        let after = rotated.previous_secret_valid_until + Duration::seconds(1);
        assert!(queue
            .verify_client_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &rotated.client_secret,
                after
            )
            .await
            .expect("new secret"));
        assert!(!queue
            .verify_client_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &secrets.client_secret,
                after
            )
            .await
            .expect("old secret past grace"));

        std::fs::remove_file(&path).ok();
    }

    /// An approval gate that a pending or revoked agent can authenticate
    /// through is decorative.
    #[tokio::test]
    async fn only_an_approved_registration_authenticates() {
        let path = temp_path();
        let queue = queue(&path);
        let (secrets, _) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");

        assert!(
            !queue
                .verify_client_secret(
                    &TenantScope::All,
                    &secrets.agent_id,
                    &secrets.client_secret,
                    now()
                )
                .await
                .expect("pending"),
            "a pending registration must not authenticate"
        );

        queue
            .approve(&TenantScope::All, &secrets.agent_id, None, None, now())
            .await
            .expect("approve");
        assert!(queue
            .verify_client_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &secrets.client_secret,
                now()
            )
            .await
            .expect("approved"));

        queue
            .revoke(
                &TenantScope::All,
                &secrets.agent_id,
                Some("key compromised".into()),
                None,
                now(),
            )
            .await
            .expect("revoke");
        assert!(
            !queue
                .verify_client_secret(
                    &TenantScope::All,
                    &secrets.agent_id,
                    &secrets.client_secret,
                    now()
                )
                .await
                .expect("revoked"),
            "a revoked registration must stop authenticating immediately"
        );

        std::fs::remove_file(&path).ok();
    }

    /// The queue is the operator's record of decisions they made. A restart
    /// that forgot it would re-open every one of them.
    #[tokio::test]
    async fn the_queue_survives_a_restart() {
        let path = temp_path();
        let agent_id = {
            let queue = queue(&path);
            let (secrets, _) = queue
                .register(&TenantScope::All, metadata(), now())
                .await
                .expect("register");
            queue
                .approve(
                    &TenantScope::All,
                    &secrets.agent_id,
                    Some("looks real".into()),
                    Some("casey".into()),
                    now(),
                )
                .await
                .expect("approve");
            secrets.agent_id
        };

        let queue = queue(&path);
        let view = queue
            .get(&TenantScope::All, &agent_id)
            .await
            .expect("get after restart");
        assert_eq!(view.state, ApprovalState::Approved);
        assert_eq!(view.decided_by.as_deref(), Some("casey"));
        assert_eq!(
            queue
                .list(&TenantScope::All, Some(ApprovalState::Approved))
                .await
                .expect("list")
                .len(),
            1
        );
        assert!(queue
            .list(&TenantScope::All, Some(ApprovalState::Pending))
            .await
            .expect("list")
            .is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_view_carries_no_credential_material() {
        let path = temp_path();
        let queue = queue(&path);
        let (secrets, view) = queue
            .register(&TenantScope::All, metadata(), now())
            .await
            .expect("register");
        let json = serde_json::to_string(&view).expect("serialize view");
        assert!(!json.contains("hash"), "no hash field reaches a read path");
        assert!(!json.contains(&secrets.client_secret));
        assert!(!json.contains(&secrets.registration_access_token));

        // The two shapes that do carry plaintext refuse to print it.
        let debug = format!("{secrets:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&secrets.client_secret));
        assert!(!debug.contains(&secrets.registration_access_token));

        queue
            .approve(&TenantScope::All, &secrets.agent_id, None, None, now())
            .await
            .expect("approve");
        let rotated = queue
            .rotate_secret(
                &TenantScope::All,
                &secrets.agent_id,
                &secrets.registration_access_token,
                now(),
            )
            .await
            .expect("rotate");
        let debug = format!("{rotated:?}");
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains(&rotated.client_secret),
            "a rotated secret must not reach a Debug either"
        );

        std::fs::remove_file(&path).ok();
    }
}
