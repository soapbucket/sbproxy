//! The two record kinds the key store holds.
//!
//! A [`KeyRecord`] is an inbound virtual key (hashed at rest, governs what a
//! caller may do). A [`CredentialRecord`] is an upstream provider credential
//! (encrypted at rest or a vault reference, used to authenticate outbound).
//! Both are runtime records, not config types, so they carry no `JsonSchema`
//! derive; the `key_management:` config seed lowers into them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto::{self, Envelope};

/// Lifecycle status shared by both record kinds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    /// Usable.
    #[default]
    Active,
    /// Temporarily disabled; can be unblocked back to `Active`.
    Blocked,
    /// Permanently disabled; terminal.
    Revoked,
}

/// Where a record came from, which drives reload precedence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordSource {
    /// Lowered from the `key_management:` config seed. Authoritative on reload
    /// unless the operator set `allow_api_override`.
    Config,
    /// Created at runtime through the admin API.
    #[default]
    Api,
}

/// Per-key budget caps. Kept independent of `sbproxy-ai::KeyBudget` so this
/// crate has no dependency on the AI gateway; the AI layer maps between them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RecordBudget {
    /// Maximum total tokens for this key over its budget window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Maximum total cost in USD for this key over its budget window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,
}

/// A temporary, auto-expiring raise on top of a key's base budget (WOR-2561).
///
/// The override never replaces the base [`RecordBudget`]: while
/// `expires_at` is in the future the effective cap is the base cap plus the
/// increase, and once the instant passes the base cap applies again with no
/// operator action and no background sweeper. Expiry is evaluated wherever
/// the budget is read (see [`KeyRecord::effective_budget`]), so a restart
/// changes nothing: an unexpired persisted override keeps applying and an
/// expired one is ignored.
///
/// An older node that replicates this record as JSON drops the field it does
/// not know, which here fails closed: the key falls back to its tighter base
/// cap. That is why this field needs no fleet capability gate the way
/// `credential_id` does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetOverride {
    /// Extra total tokens granted on top of `budget.max_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens_increase: Option<u64>,
    /// Extra USD granted on top of `budget.max_cost_usd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_usd_increase: Option<f64>,
    /// Instant the raise stops applying. Compared lazily at read time.
    pub expires_at: DateTime<Utc>,
    /// Audit identity of the operator who granted the raise. Never a secret.
    pub granted_by: String,
    /// When the raise was granted.
    pub granted_at: DateTime<Utc>,
    /// Optional operator note ("launch-day spike", a ticket id, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl BudgetOverride {
    /// Whether the raise still applies at `now`.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now
    }
}

fn default_hash_alg() -> String {
    "hmac-sha256.v1".to_string()
}

fn default_policy_revision() -> u64 {
    1
}

/// An inbound virtual-key record. The plaintext secret is never stored: only
/// `secret_hash` (and, during a rotation grace window, `prev_secret_hash`) is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Stable public identifier and the token prefix (`sbp_<key_id>_<secret>`).
    pub key_id: String,
    /// Monotonic revision of this key's policy, starting at one.
    #[serde(default = "default_policy_revision")]
    pub policy_revision: u64,
    /// `HMAC-SHA256(secret, pepper)`, hex. The at-rest verifier.
    pub secret_hash: String,
    /// A second hash accepted during a rotation grace window (the prior secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_secret_hash: Option<String>,
    /// When this key's secret was last replaced by a rotation (WOR-2567).
    ///
    /// Distinct from `updated_at`, which any policy patch moves. Rotation
    /// age is what an operator alerts on against
    /// `key_management.crypto.rotation.inbound_key_days`, and a key whose
    /// budget was edited last week has not been rotated. The credential
    /// side carries the same field for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    /// When the `prev_secret_hash` stops being accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash_expires_at: Option<DateTime<Utc>>,
    /// Hash scheme tag, for forward migration.
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
    /// Human-readable name, surfaced on access logs (never the secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Lifecycle status.
    #[serde(default)]
    pub status: RecordStatus,
    /// Max requests per minute (None = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_minute: Option<u64>,
    /// Max tokens (input + output) per minute (None = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens_per_minute: Option<u64>,
    /// SLO priority lane: `interactive`, `standard`, or `batch`.
    /// Validated at the admin boundary and re-validated at the AI-gateway
    /// seam (like `principal_selectors`) so this leaf crate stays free of
    /// the gateway's enum. `None` behaves as `standard`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Per-key budget caps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<RecordBudget>,
    /// Temporary, auto-expiring raise on top of [`Self::budget`] (WOR-2561).
    /// Granted and cleared through the admin API, never by the config seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_override: Option<BudgetOverride>,
    /// Models this key may use (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_models: Vec<String>,
    /// Models this key may not use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_models: Vec<String>,
    /// Providers this key may use (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_providers: Vec<String>,
    /// Providers this key may not use. Blocks take precedence over allows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_providers: Vec<String>,
    /// Named PII redaction rules that must be active on the request body before
    /// this key can dispatch upstream (empty = none required).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_pii_redaction: Vec<String>,
    /// Inbound principal selectors allowed to present this key (empty = any
    /// principal). Each entry is a `PrincipalSelectorConfig`-shaped JSON object,
    /// kept opaque here so this leaf crate stays free of the AI gateway types;
    /// the auth path deserializes it at use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_selectors: Vec<serde_json::Value>,
    /// Pin a model for requests on this key. When set, the gateway overwrites
    /// the request body `model` before routing, so the caller cannot pick a
    /// different one. `None` leaves the client's choice unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_to_model: Option<String>,
    /// Route-local compression selector (`on`, `off`, or a named profile).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_profile: Option<String>,
    /// Tool names this key may expose. None is unrestricted, an empty list
    /// denies every caller-supplied tool, and a non-empty list is an allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    /// Provider tool definitions injected into the request when this key
    /// authenticates, replacing any client-supplied tools. Opaque,
    /// provider-shaped JSON. Empty leaves the request's tools untouched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inject_tools: Vec<serde_json::Value>,
    /// Reference to a federated MCP gateway whose live catalogue is
    /// injected as this key's tool surface. Opaque JSON (the AI
    /// gateway's `InjectMcpRef` shape: `{"ref": ..., "format": ...,
    /// "filter": [...]}`), kept unvalidated here like
    /// `principal_selectors`; the AI seam deserializes it at use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_mcp: Option<serde_json::Value>,
    /// Skip the body-aware prompt-injection scan for this key. Default false
    /// (every key is scanned). Set true for trusted callers (eval, red-team)
    /// that legitimately submit injection-shaped prompts.
    #[serde(default)]
    pub bypass_prompt_injection: bool,
    /// WOR-2096: allow the origin's opt-in content capture to retain a
    /// redacted sample of this key's prompt and response text for
    /// console inspection. Default false; capture happens only when the
    /// origin also enables `capture_content`, so both the operator and
    /// the key owner have said yes.
    #[serde(default)]
    pub allow_content_capture: bool,
    /// Project attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// User attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Free-form grouping tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Free-form metadata, surfaced on access logs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Owning tenant, if multi-tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Upstream credential this key presents, naming a [`CredentialRecord`] by
    /// id.
    ///
    /// `None` leaves the origin's own `outbound_credential` in charge. When
    /// set, the bound credential is the only upstream identity this key may
    /// reach an origin with: a missing, revoked, or unresolvable credential
    /// refuses the request rather than falling back, because that fallback
    /// would grant the key an identity it was never bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// Expiry; past this instant the key is unusable regardless of status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Provenance, for reload precedence.
    #[serde(default)]
    pub source: RecordSource,
}

impl KeyRecord {
    /// Construct an active record from a freshly minted hash. Callers stamp
    /// policy/attribution fields afterward.
    pub fn new(
        key_id: impl Into<String>,
        secret_hash: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            policy_revision: default_policy_revision(),
            secret_hash: secret_hash.into(),
            rotated_at: None,
            prev_secret_hash: None,
            prev_hash_expires_at: None,
            hash_alg: default_hash_alg(),
            name: None,
            status: RecordStatus::Active,
            max_requests_per_minute: None,
            max_tokens_per_minute: None,
            priority: None,
            budget: None,
            budget_override: None,
            allowed_models: Vec::new(),
            blocked_models: Vec::new(),
            allowed_providers: Vec::new(),
            blocked_providers: Vec::new(),
            require_pii_redaction: Vec::new(),
            principal_selectors: Vec::new(),
            route_to_model: None,
            compression_profile: None,
            allowed_tools: None,
            inject_tools: Vec::new(),
            inject_mcp: None,
            bypass_prompt_injection: false,
            allow_content_capture: false,
            project: None,
            user: None,
            tags: Vec::new(),
            metadata: BTreeMap::new(),
            tenant_id: None,
            credential_id: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
            source: RecordSource::Api,
        }
    }

    /// Whether the record is `Active` and not past its expiry at `now`.
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.status == RecordStatus::Active && self.expires_at.is_none_or(|exp| exp > now)
    }

    /// Constant-time check that `secret` matches this record's current hash, or
    /// its `prev_secret_hash` if a rotation grace window is still open at `now`.
    /// Does not consider status/expiry; callers gate on [`Self::is_usable`].
    pub fn verify_secret(&self, secret: &str, pepper: &[u8], now: DateTime<Utc>) -> bool {
        if crypto::verify_secret(secret, pepper, &self.secret_hash) {
            return true;
        }
        if let (Some(prev), Some(exp)) =
            (self.prev_secret_hash.as_deref(), self.prev_hash_expires_at)
        {
            if exp > now && crypto::verify_secret(secret, pepper, prev) {
                return true;
            }
        }
        false
    }

    /// The budget override, if one is present and unexpired at `now`.
    pub fn active_budget_override(&self, now: DateTime<Utc>) -> Option<&BudgetOverride> {
        self.budget_override
            .as_ref()
            .filter(|grant| grant.is_active(now))
    }

    /// The budget the enforcement path must compare against at `now`
    /// (WOR-2561).
    ///
    /// This is the one choke point for override arithmetic: the request-path
    /// policy lowering, the admin usage snapshot, and the effective-policy
    /// preview all read the budget through here, so the cap an operator
    /// previews and the cap a request is held to cannot disagree.
    ///
    /// With no override, or an expired one, this is the base
    /// [`Self::budget`] unchanged. While an override is active, each capped
    /// axis of the base budget is raised by the override's increase for that
    /// axis (saturating). An axis the base budget leaves uncapped stays
    /// uncapped: unlimited plus an increase is still unlimited, and a raise
    /// must never introduce a cap that was not there. A record with no base
    /// budget at all has nothing to raise, so the result stays `None`; the
    /// admin API refuses to grant such an override in the first place.
    pub fn effective_budget(&self, now: DateTime<Utc>) -> Option<RecordBudget> {
        let base = self.budget.clone()?;
        let Some(grant) = self.active_budget_override(now) else {
            return Some(base);
        };
        Some(RecordBudget {
            max_tokens: base
                .max_tokens
                .map(|tokens| tokens.saturating_add(grant.max_tokens_increase.unwrap_or_default())),
            max_cost_usd: base
                .max_cost_usd
                .map(|usd| usd + grant.max_cost_usd_increase.unwrap_or_default()),
        })
    }

    /// Whether `model` is permitted by this record's allow/block lists.
    pub fn is_model_allowed(&self, model: &str) -> bool {
        if self.blocked_models.iter().any(|m| m == model) {
            return false;
        }
        if !self.allowed_models.is_empty() {
            return self.allowed_models.iter().any(|m| m == model);
        }
        true
    }
}

/// How an upstream credential's secret is held at rest.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialMaterial {
    /// A secret reference resolved by `sbproxy-vault` at use time (`vault://`,
    /// `awssm://`, `gcpsm://`, `k8ssecret://`, ...). The first-class path; the
    /// secret never lives in the store.
    VaultRef {
        /// The scheme-prefixed reference string.
        reference: String,
    },
    /// An AEAD envelope: encrypted at rest, decrypted at dispatch.
    Envelope {
        /// The sealed envelope.
        envelope: Envelope,
    },
    /// Plaintext. Only for config-seeded credentials where the operator opted
    /// out of encryption; discouraged and never produced by the admin API.
    Plaintext {
        /// The raw secret.
        value: String,
    },
    /// A credential minted on demand by a dynamic-secrets engine, valid only
    /// for its lease (WOR-2569).
    ///
    /// Nothing static is stored: the record holds the mount that mints the
    /// credential, not a credential. Every resolution that cannot be served
    /// from cache mints a fresh one, and the cache is never allowed to
    /// outlive the lease.
    ///
    /// The scope is cloud IAM and Vault-fronted database credentials, and it
    /// is a scope rather than a limitation of this implementation. Most AI
    /// provider API keys, OpenAI's and Anthropic's included, have no
    /// short-TTL issuance to lease against: there is no STS equivalent, so
    /// there is nothing to mint. `docs/key-management.md` states that up
    /// front rather than implying blanket dynamic-secrets support the
    /// provider ecosystem does not allow.
    Leased {
        /// Secret reference naming the dynamic-secrets mount that mints the
        /// credential, for example `vault://aws/creds/sbproxy-bedrock`.
        /// Read through the same resolver every other reference uses.
        reference: String,
        /// Which platform the lease is against. Recorded so a credential
        /// bound to a provider that cannot lease is refused rather than
        /// silently degrading to a static read.
        platform: LeasePlatform,
        /// The mount's configured lease lifetime, in seconds. sbproxy never
        /// caches resolved material past this, and does not learn it from
        /// the mount: set it to match what the mount is configured for.
        lease_duration_secs: u64,
    },
}

/// Platforms whose credentials can actually be leased (WOR-2569).
///
/// A closed set, and the closure is the point. `leased` on a provider whose
/// platform has no lease concept is refused with the limitation named,
/// rather than accepted and quietly turned into a static read that never
/// expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePlatform {
    /// AWS IAM, through Vault's AWS secrets engine or an STS role
    /// assumption the mount performs. Covers Bedrock.
    Aws,
    /// Google Cloud IAM, through Vault's GCP secrets engine. Covers Vertex.
    Gcp,
    /// Azure AD, through Vault's Azure secrets engine. Covers Azure OpenAI
    /// and Foundry.
    Azure,
    /// A Vault-fronted database credential. Not an AI provider at all, and
    /// accepted for any provider label because the platform's own lease is
    /// what bounds it.
    Database,
}

impl LeasePlatform {
    /// Whether a credential bound to `provider` can be leased against this
    /// platform.
    ///
    /// The match is on the provider label an operator wrote, so it is a
    /// prefix test rather than an exhaustive catalog: the AI provider
    /// catalog has dozens of entries and enumerating the ones that
    /// *cannot* lease would be a list that goes stale the day a provider
    /// is added. Naming the few that can, and refusing the rest, goes
    /// stale in the safe direction.
    ///
    /// [`Self::Database`] accepts anything: a Vault-fronted database
    /// credential is not an AI provider credential, and the provider label
    /// on such a record is whatever the operator found useful.
    pub fn accepts_provider(self, provider: Option<&str>) -> bool {
        if self == Self::Database {
            return true;
        }
        let Some(provider) = provider.map(str::to_ascii_lowercase) else {
            // No provider label means nothing to contradict. The platform
            // still bounds the lease.
            return true;
        };
        let provider = provider.as_str();
        match self {
            Self::Aws => {
                provider.starts_with("aws")
                    || provider.contains("bedrock")
                    || provider == "sagemaker"
            }
            Self::Gcp => {
                provider.starts_with("gcp")
                    || provider.starts_with("google")
                    || provider.contains("vertex")
            }
            Self::Azure => provider.starts_with("azure") || provider.contains("foundry"),
            Self::Database => true,
        }
    }

    /// The operator-facing name, for an error message and the admin view.
    pub fn label(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::Database => "database",
        }
    }
}

/// Redacted `Debug` (WOR-2640). Only [`Self::Plaintext`] holds a
/// reusable secret: a `VaultRef` is a reference an operator has to be
/// able to read to fix a typo in it, and an `Envelope` is already
/// sealed. Redacting the one that matters keeps every container of this
/// type, [`CredentialRecord`] included, safe to format without each of
/// them needing an impl of its own.
impl std::fmt::Debug for CredentialMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VaultRef { reference } => f
                .debug_struct("VaultRef")
                .field("reference", reference)
                .finish(),
            Self::Envelope { envelope } => f
                .debug_struct("Envelope")
                .field("envelope", envelope)
                .finish(),
            Self::Plaintext { .. } => f
                .debug_struct("Plaintext")
                .field("value", &"[REDACTED]")
                .finish(),
            // A mount reference is not a secret, for the same reason a
            // `VaultRef` reference is not: an operator has to be able to
            // read it to fix a typo in it.
            Self::Leased {
                reference,
                platform,
                lease_duration_secs,
            } => f
                .debug_struct("Leased")
                .field("reference", reference)
                .field("platform", platform)
                .field("lease_duration_secs", lease_duration_secs)
                .finish(),
        }
    }
}

impl CredentialMaterial {
    /// Whether this material carries a raw, unsealed secret.
    ///
    /// [`Self::VaultRef`] holds only a reference and [`Self::Envelope`] is
    /// already sealed, so both are safe to hand onward; [`Self::Plaintext`]
    /// is the secret itself.
    ///
    /// Crate-private on purpose. Callers outside this crate want
    /// [`CredentialRecord::carries_plaintext`], which asks the *record*
    /// rather than one of its material slots: a record has carried two
    /// since WOR-2567, and a guard that reads one slot is a guard a
    /// rotation walks past.
    pub(crate) fn is_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext { .. })
    }
}

/// An upstream provider credential record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Stable identifier.
    pub id: String,
    /// Operator-facing name.
    pub name: String,
    /// Provider this credential authenticates to (e.g. `openai`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Credential kind (`ai_provider`, `bearer`, `api_key`, ...).
    #[serde(default = "default_cred_kind")]
    pub kind: String,
    /// Header this credential is written to on the upstream request.
    ///
    /// Presentation belongs to the credential rather than to the key that
    /// binds it, because it is a property of the upstream: one credential
    /// shared by many keys then presents identically every time. Defaults to
    /// `authorization`.
    #[serde(default = "default_cred_header")]
    pub header: String,
    /// Scheme prefix on the header value. Defaults to `Bearer `. Set to an
    /// empty string for raw-value headers such as `x-api-key`.
    #[serde(default = "default_cred_scheme")]
    pub scheme: String,
    /// How the secret is held at rest.
    pub material: CredentialMaterial,
    /// Lifecycle status.
    #[serde(default)]
    pub status: RecordStatus,
    /// Owning tenant, if multi-tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Free-form metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Provenance, for reload precedence.
    #[serde(default)]
    pub source: RecordSource,
    /// When this credential's material was last replaced by a rotation, as
    /// opposed to any other update (WOR-2567).
    ///
    /// Distinct from `updated_at`, which any metadata patch moves. Rotation
    /// age is what an operator alerts on against the named crypto period in
    /// `key_management.crypto.rotation`, and a record whose name was edited
    /// last week has not been rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    /// The material this credential carried before the most recent
    /// rotation, kept usable for a bounded overlap (WOR-2567).
    ///
    /// `rotate_key` has given inbound keys a dual-validity window since
    /// WOR-1554; this is the same idea from the other side. sbproxy
    /// *presents* an upstream credential rather than validating one, so
    /// the overlap is not about accepting an old value: it is about the
    /// window between installing a new provider key here and that key
    /// becoming live at the provider. Inside the window, material that
    /// will not resolve or is refused falls back to this one instead of
    /// failing the request.
    ///
    /// Cleared by [`Self::retire_expired_prev_material`] once
    /// [`Self::prev_material_expires_at`] passes, so the old secret does
    /// not sit in the store indefinitely.
    ///
    /// Retirement is read-driven, not swept: `GET /admin/credentials`
    /// retires up to a bounded number of lapsed overlaps per listing, and
    /// a rotation retires this record's own before installing a new one.
    /// A deployment that never lists never retires. What is *not*
    /// read-driven is the refusal to serve it, which
    /// [`Self::usable_prev_material`] enforces from the record itself on
    /// every resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_material: Option<CredentialMaterial>,
    /// When [`Self::prev_material`] stops being usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_material_expires_at: Option<DateTime<Utc>>,
}

fn default_cred_kind() -> String {
    "ai_provider".to_string()
}

/// Default upstream header a credential is presented in. Matches the
/// `outbound_credential` resolver's default so there is one spelling.
pub fn default_cred_header() -> String {
    "authorization".to_string()
}

/// Default scheme prefix on the credential's header value.
pub fn default_cred_scheme() -> String {
    "Bearer ".to_string()
}

impl KeyRecord {
    /// Days since this key's secret was last rotated, or since it was
    /// minted when it never has been (WOR-2567).
    pub fn rotation_age_days(&self, now: DateTime<Utc>) -> i64 {
        let since = self.rotated_at.unwrap_or(self.created_at);
        (now - since).num_days()
    }
}

impl CredentialRecord {
    /// Whether the credential is `Active`.
    pub fn is_usable(&self) -> bool {
        self.status == RecordStatus::Active
    }

    /// Drop the retired material once its overlap window has closed,
    /// reporting whether anything was dropped (WOR-2567).
    ///
    /// The field doc promises the store does not keep the old secret
    /// indefinitely, and until this existed nothing made that true:
    /// `usable_prev_material` merely declined to *return* it, so a
    /// credential rotated because its old provider key leaked kept that
    /// key on disk for the life of the record, openable by anyone with the
    /// store and the master key. On a mesh store it was worse than
    /// untidy: `carries_plaintext` correctly still saw a retired plaintext,
    /// so a rotated plaintext-seeded credential could never be written
    /// again.
    ///
    /// Retiring on read rather than on a timer, which is this project's
    /// stated preference and the same shape the lapsed budget-override
    /// retirement in `list_keys` already uses.
    pub fn retire_expired_prev_material(&mut self, now: DateTime<Utc>) -> bool {
        let lapsed = self
            .prev_material_expires_at
            .is_some_and(|expires| expires <= now);
        if !lapsed && self.prev_material_expires_at.is_some() {
            return false;
        }
        // Also covers the inconsistent shape where material was left
        // behind with no expiry: it can never be served, so it is only a
        // secret sitting on disk.
        if self.prev_material.is_none() && self.prev_material_expires_at.is_none() {
            return false;
        }
        self.prev_material = None;
        self.prev_material_expires_at = None;
        true
    }

    /// The previous material, if a rotation left one and its window is
    /// still open at `now` (WOR-2567).
    ///
    /// A method rather than two field reads at the call site because the
    /// window has to be checked everywhere the material is: a caller that
    /// reads `prev_material` and forgets `prev_material_expires_at` is a
    /// caller that presents a retired provider key forever.
    ///
    /// This only declines to *return* the retired material. Removing it
    /// from the record is [`Self::retire_expired_prev_material`], which the
    /// credential listing calls.
    pub fn usable_prev_material(&self, now: DateTime<Utc>) -> Option<&CredentialMaterial> {
        let expires = self.prev_material_expires_at?;
        (expires > now)
            .then_some(self.prev_material.as_ref())
            .flatten()
    }

    /// Whether this record carries a raw, unsealed secret in *any* of its
    /// material slots.
    ///
    /// `CredentialMaterial::is_plaintext` answers the question for one slot,
    /// and is crate-private precisely so that this is the only answer
    /// reachable from outside. This one asks the record, and the difference
    /// is load bearing: WOR-2567 gave a record a second slot, and
    /// the two guards that keep plaintext off shared surfaces (the mesh
    /// keystore's `put_credential` and the TTL cache's second-tier
    /// publish) were both written when there was only one. A rotation of a
    /// plaintext-seeded credential would have moved that plaintext into
    /// `prev_material`, where both guards would have looked straight past
    /// it and replicated the raw secret onto every replica shard's disk.
    ///
    /// So the guards ask the record, not the field. A third slot added
    /// later is covered here, in one place, rather than by remembering to
    /// widen two call sites in another crate.
    pub fn carries_plaintext(&self) -> bool {
        self.material.is_plaintext()
            || self
                .prev_material
                .as_ref()
                .is_some_and(CredentialMaterial::is_plaintext)
    }

    /// Days since this credential's material was last rotated, or since it
    /// was created when it never has been (WOR-2567).
    pub fn rotation_age_days(&self, now: DateTime<Utc>) -> i64 {
        let since = self.rotated_at.unwrap_or(self.created_at);
        (now - since).num_days()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mint_key;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn usable_gates_status_and_expiry() {
        let mut r = KeyRecord::new("id", "hash", now());
        assert!(r.is_usable(now()));

        r.status = RecordStatus::Blocked;
        assert!(!r.is_usable(now()));

        r.status = RecordStatus::Active;
        r.expires_at = Some(now() - Duration::seconds(1));
        assert!(!r.is_usable(now()));

        r.expires_at = Some(now() + Duration::seconds(60));
        assert!(r.is_usable(now()));
    }

    #[test]
    fn verify_secret_accepts_current_and_graced_prev() {
        let pepper = b"pep";
        let minted = mint_key(pepper);
        let (_, secret) = crate::crypto::parse_minted_token(&minted.token).unwrap();
        let mut r = KeyRecord::new(&minted.key_id, &minted.secret_hash, now());
        assert!(r.verify_secret(secret, pepper, now()));

        // Rotate: the old secret becomes prev with a grace window.
        let rotated = mint_key(pepper);
        let (_, new_secret) = crate::crypto::parse_minted_token(&rotated.token).unwrap();
        r.prev_secret_hash = Some(r.secret_hash.clone());
        r.prev_hash_expires_at = Some(now() + Duration::seconds(60));
        r.secret_hash = rotated.secret_hash.clone();

        // Both work inside the grace window.
        assert!(r.verify_secret(new_secret, pepper, now()));
        assert!(r.verify_secret(secret, pepper, now()));
        // After grace, only the new one works.
        let later = now() + Duration::seconds(61);
        assert!(r.verify_secret(new_secret, pepper, later));
        assert!(!r.verify_secret(secret, pepper, later));
    }

    #[test]
    fn model_allow_block_lists() {
        let mut r = KeyRecord::new("id", "hash", now());
        assert!(r.is_model_allowed("gpt-4"));
        r.allowed_models = vec!["gpt-4".into()];
        assert!(r.is_model_allowed("gpt-4"));
        assert!(!r.is_model_allowed("claude-3"));
        r.blocked_models = vec!["gpt-4".into()];
        assert!(!r.is_model_allowed("gpt-4"));
    }

    #[test]
    fn key_record_serde_roundtrips_minimal() {
        let json = serde_json::json!({
            "key_id": "abcd",
            "secret_hash": "deadbeef",
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let r: KeyRecord = serde_json::from_value(json).unwrap();
        assert_eq!(r.key_id, "abcd");
        assert_eq!(r.status, RecordStatus::Active);
        assert_eq!(r.source, RecordSource::Api);
        assert_eq!(r.hash_alg, "hmac-sha256.v1");
    }

    #[test]
    fn key_policy_contract_defaults_are_backward_compatible() {
        let created = KeyRecord::new("abcd", "deadbeef", now());
        assert_eq!(created.policy_revision, 1);
        assert!(created.blocked_providers.is_empty());
        assert!(created.allowed_tools.is_none());

        let legacy_json = serde_json::json!({
            "key_id": "abcd",
            "secret_hash": "deadbeef",
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let restored: KeyRecord = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(restored.policy_revision, 1);
        assert!(restored.blocked_providers.is_empty());
        assert!(restored.allowed_tools.is_none());
    }

    #[test]
    fn key_policy_contract_fields_roundtrip() {
        let mut record = KeyRecord::new("abcd", "deadbeef", now());
        record.policy_revision = 9;
        record.blocked_providers = vec!["vertex".into(), "bedrock".into()];
        record.allowed_tools = Some(vec!["search".into(), "calculator".into()]);

        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["policy_revision"], 9);
        assert_eq!(
            json["blocked_providers"],
            serde_json::json!(["vertex", "bedrock"])
        );
        assert_eq!(
            json["allowed_tools"],
            serde_json::json!(["search", "calculator"])
        );

        let restored: KeyRecord = serde_json::from_value(json).unwrap();
        assert_eq!(restored.policy_revision, 9);
        assert_eq!(restored.blocked_providers, ["vertex", "bedrock"]);
        assert_eq!(
            restored.allowed_tools,
            Some(vec!["search".to_string(), "calculator".to_string()])
        );
    }

    #[test]
    fn credential_presentation_defaults_to_bearer_authorization() {
        let json = serde_json::json!({
            "id": "c1",
            "name": "n",
            "material": {"kind": "vault_ref", "reference": "vault://x"},
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let r: CredentialRecord = serde_json::from_value(json).unwrap();
        assert_eq!(r.header, "authorization");
        assert_eq!(r.scheme, "Bearer ");
    }

    #[test]
    fn credential_presentation_round_trips_a_raw_value_header() {
        let json = serde_json::json!({
            "id": "c1",
            "name": "n",
            "header": "x-api-key",
            "scheme": "",
            "material": {"kind": "vault_ref", "reference": "vault://x"},
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let r: CredentialRecord = serde_json::from_value(json).unwrap();
        assert_eq!(r.header, "x-api-key");
        assert_eq!(r.scheme, "");
        let back: CredentialRecord =
            serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn key_credential_binding_defaults_to_none_and_round_trips() {
        let created = KeyRecord::new("abcd", "hash", now());
        assert!(created.credential_id.is_none());

        let mut record = created.clone();
        record.credential_id = Some("cred-1".to_string());
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["credential_id"], "cred-1");
        let restored: KeyRecord = serde_json::from_value(json).unwrap();
        assert_eq!(restored.credential_id.as_deref(), Some("cred-1"));
    }

    #[test]
    fn a_legacy_record_without_the_new_fields_still_deserializes() {
        // Mixed-version fleets replicate records as plain JSON, so an older
        // node's record must keep loading here.
        let legacy = serde_json::json!({
            "key_id": "abcd",
            "secret_hash": "deadbeef",
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let r: KeyRecord = serde_json::from_value(legacy).unwrap();
        assert!(r.credential_id.is_none());
    }

    fn override_grant(expires_at: DateTime<Utc>) -> BudgetOverride {
        BudgetOverride {
            max_tokens_increase: Some(5_000),
            max_cost_usd_increase: Some(10.0),
            expires_at,
            granted_by: "casey".into(),
            granted_at: now(),
            reason: Some("launch-day spike".into()),
        }
    }

    #[test]
    fn an_active_override_raises_each_capped_axis_and_expiry_restores_the_base() {
        let mut r = KeyRecord::new("id", "hash", now());
        r.budget = Some(RecordBudget {
            max_tokens: Some(1_000),
            max_cost_usd: Some(5.0),
        });
        r.budget_override = Some(override_grant(now() + Duration::seconds(60)));

        // Inside the window: base plus the increase, on both axes.
        let raised = r.effective_budget(now()).unwrap();
        assert_eq!(raised.max_tokens, Some(6_000));
        assert_eq!(raised.max_cost_usd, Some(15.0));
        assert!(r.active_budget_override(now()).is_some());

        // At and past the expiry instant: the base resumes, with no
        // mutation and no sweeper involved.
        for later in [
            now() + Duration::seconds(60),
            now() + Duration::seconds(3600),
        ] {
            let base = r.effective_budget(later).unwrap();
            assert_eq!(base.max_tokens, Some(1_000));
            assert_eq!(base.max_cost_usd, Some(5.0));
            assert!(r.active_budget_override(later).is_none());
        }
    }

    #[test]
    fn an_override_never_caps_an_uncapped_axis_and_needs_a_base_budget() {
        let mut r = KeyRecord::new("id", "hash", now());
        // No base budget: nothing to raise.
        r.budget_override = Some(override_grant(now() + Duration::seconds(60)));
        assert_eq!(r.effective_budget(now()), None);

        // A base that caps only tokens: the cost axis stays unlimited even
        // though the grant names a cost increase.
        r.budget = Some(RecordBudget {
            max_tokens: Some(1_000),
            max_cost_usd: None,
        });
        let raised = r.effective_budget(now()).unwrap();
        assert_eq!(raised.max_tokens, Some(6_000));
        assert_eq!(raised.max_cost_usd, None);
    }

    #[test]
    fn a_token_raise_near_the_integer_ceiling_saturates_instead_of_wrapping() {
        let mut r = KeyRecord::new("id", "hash", now());
        r.budget = Some(RecordBudget {
            max_tokens: Some(u64::MAX - 1),
            max_cost_usd: None,
        });
        r.budget_override = Some(override_grant(now() + Duration::seconds(60)));
        let raised = r.effective_budget(now()).unwrap();
        assert_eq!(raised.max_tokens, Some(u64::MAX));
    }

    #[test]
    fn a_budget_override_round_trips_and_a_legacy_record_still_loads() {
        let mut r = KeyRecord::new("id", "hash", now());
        r.budget = Some(RecordBudget {
            max_tokens: Some(1_000),
            max_cost_usd: None,
        });
        r.budget_override = Some(override_grant(now() + Duration::seconds(60)));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["budget_override"]["granted_by"], "casey");
        let back: KeyRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);

        // Mixed-version fleets replicate records as plain JSON; a record
        // written before WOR-2561 must keep loading, with no override.
        let legacy = serde_json::json!({
            "key_id": "abcd",
            "secret_hash": "deadbeef",
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        });
        let restored: KeyRecord = serde_json::from_value(legacy).unwrap();
        assert!(restored.budget_override.is_none());
    }

    #[test]
    fn credential_material_tagged_serde() {
        let r = CredentialRecord {
            id: "c1".into(),
            name: "openai-prod".into(),
            provider: Some("openai".into()),
            kind: "ai_provider".into(),
            header: default_cred_header(),
            scheme: default_cred_scheme(),
            material: CredentialMaterial::VaultRef {
                reference: "vault://openai".into(),
            },
            status: RecordStatus::Active,
            tenant_id: None,
            metadata: BTreeMap::new(),
            created_at: now(),
            updated_at: now(),
            source: RecordSource::Config,
            rotated_at: None,
            prev_material: None,
            prev_material_expires_at: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"kind\":\"vault_ref\""), "{json}");
        let back: CredentialRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    /// WOR-2640: `Plaintext` is the only material variant that holds a
    /// reusable secret, and redacting it there is what keeps every
    /// container of it safe without an impl per container.
    #[test]
    fn debug_never_renders_plaintext_credential_material() {
        let material = CredentialMaterial::Plaintext {
            value: "SENTINEL-SECRET-9f3a".to_string(),
        };
        let rendered = format!("{material:?}");
        assert!(
            !rendered.contains("SENTINEL-SECRET-9f3a"),
            "plaintext credential material reached Debug: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));

        // A reference is not a secret: an operator has to be able to
        // read it to fix a typo in it.
        let by_ref = CredentialMaterial::VaultRef {
            reference: "vault://prod/openai".to_string(),
        };
        assert!(format!("{by_ref:?}").contains("vault://prod/openai"));
    }

    /// WOR-2569: the closed platform set, and the direction it goes stale.
    ///
    /// Naming the providers that *can* lease and refusing the rest means a
    /// provider added to the catalog tomorrow is refused until somebody
    /// looks at it. The other direction, enumerating what cannot lease,
    /// would accept it silently.
    #[test]
    fn only_platforms_that_mint_short_lived_credentials_accept_a_provider() {
        assert!(LeasePlatform::Aws.accepts_provider(Some("bedrock")));
        assert!(LeasePlatform::Aws.accepts_provider(Some("aws-bedrock")));
        assert!(LeasePlatform::Gcp.accepts_provider(Some("vertex")));
        assert!(LeasePlatform::Gcp.accepts_provider(Some("google-vertex")));
        assert!(LeasePlatform::Azure.accepts_provider(Some("azure-openai")));
        // A Vault-fronted database credential is not an AI provider at
        // all, so its provider label is whatever the operator found
        // useful and nothing here has an opinion.
        assert!(LeasePlatform::Database.accepts_provider(Some("postgres-analytics")));

        // The refusals. Each of these would otherwise be a record that
        // reads "leased" and never expires.
        for provider in ["openai", "anthropic", "mistral", "cohere", "groq"] {
            for platform in [LeasePlatform::Aws, LeasePlatform::Gcp, LeasePlatform::Azure] {
                assert!(
                    !platform.accepts_provider(Some(provider)),
                    "{provider} has no short-TTL issuance to lease against {}",
                    platform.label()
                );
            }
        }
    }

    /// WOR-2567: the rotation overlap gave a record a second material
    /// slot, and the two guards that keep plaintext off shared surfaces
    /// were both written when there was only one.
    ///
    /// The failure this pins is a rotation of a plaintext-seeded
    /// credential: the plaintext moves from `material` into
    /// `prev_material`, where a guard reading only `material` sees an
    /// envelope and replicates the raw secret onto every replica shard's
    /// disk and into the shared cache tier. The record answers, not the
    /// field, so a third slot is covered here rather than by remembering
    /// to widen two call sites in another crate.
    #[test]
    fn a_rotation_cannot_hide_plaintext_in_the_previous_material_slot() {
        let now = now();
        let mut record = CredentialRecord {
            id: "cred-rot".to_string(),
            name: "cred-rot".to_string(),
            provider: None,
            kind: default_cred_kind(),
            header: default_cred_header(),
            scheme: default_cred_scheme(),
            material: CredentialMaterial::Plaintext {
                value: "sk-seeded-in-the-clear".to_string(),
            },
            status: RecordStatus::Active,
            tenant_id: None,
            metadata: BTreeMap::new(),
            created_at: now,
            updated_at: now,
            source: RecordSource::Config,
            rotated_at: None,
            prev_material: None,
            prev_material_expires_at: None,
        };
        assert!(record.carries_plaintext(), "the pre-rotation state");

        // Rotate: the plaintext moves one slot to the left, and the
        // current slot becomes a vault reference that looks perfectly
        // safe on its own.
        record.prev_material = Some(std::mem::replace(
            &mut record.material,
            CredentialMaterial::VaultRef {
                reference: "vault://secret/cred-rot".to_string(),
            },
        ));
        record.prev_material_expires_at = Some(now + Duration::seconds(300));
        record.rotated_at = Some(now);

        assert!(
            !record.material.is_plaintext(),
            "the field-level check is exactly what stops seeing it, which is the point"
        );
        assert!(
            record.carries_plaintext(),
            "a rotation must not launder plaintext into a slot the guards do not read"
        );

        // Once the overlap is dropped, nothing is in the clear again.
        record.prev_material = None;
        record.prev_material_expires_at = None;
        assert!(!record.carries_plaintext());
    }
}
