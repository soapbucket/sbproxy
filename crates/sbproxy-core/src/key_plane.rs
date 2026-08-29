//! WOR-1546: assembly and publication for the dynamic key plane.
//!
//! The `key_management:` config block is lowered here into a live `KeyPlane`:
//! a `KeyCrypto` handle (pepper + master), a `KeyStore` backend, and a
//! fail-closed `TtlCache` in front of it. Each compiled pipeline owns its exact
//! plane generation for request processing. A global `ArcSwapOption` follows
//! the published generation for admin and cluster control-plane consumers.
//!
//! Async work (seeding the config records, the Redis invalidation subscriber)
//! runs on a dedicated, process-lifetime runtime so it is independent of the
//! pingora server runtime and survives for the life of the process. Request-time
//! resolves run on the server runtime against the same store and cache.

use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};
use sbproxy_ai::governance::{
    GovernanceBackendHealth, GovernanceConsistency as RuntimeGovernanceConsistency,
    GovernanceStore, InMemoryGovernanceConfig, InMemoryGovernanceStore,
};
use sbproxy_ai::governance_redis::{RedisGovernanceConfig, RedisGovernanceStore};
use sbproxy_config::types::{
    FailureMode, GovernanceBackendConfig, GovernanceConsistency as ConfigGovernanceConsistency,
    KeyCacheTier, KeyGovernanceConfig, KeyManagementConfig, KeyStoreBackend, SeedCredentialConfig,
    SeedKeyConfig,
};
use sbproxy_keystore::crypto::{KeyCrypto, RootOfTrust as _};
use sbproxy_keystore::record::{
    CredentialMaterial, CredentialRecord, KeyRecord, RecordBudget, RecordSource, RecordStatus,
};
use sbproxy_keystore::{EmbeddedKeyStore, KeyStore, TtlCache, TtlCacheConfig};

/// The live, installed key plane.
pub struct KeyPlane {
    crypto: KeyCrypto,
    cache: Arc<TtlCache>,
    resolved_credentials: ResolvedCredentialCache,
    failure_posture: FailureMode,
    allow_api_override: bool,
    oidc_claim_field: Option<String>,
    governance: KeyGovernanceConfig,
    governance_store: Arc<dyn GovernanceStore>,
    approximate_store: Option<Arc<InMemoryGovernanceStore>>,
    inbound: sbproxy_config::types::KeyInboundConfig,
    /// WOR-2570: read/access audit settings for credential resolution.
    read_audit: sbproxy_config::types::KeyReadAuditConfig,
    /// Last time a read-audit detail record was emitted for each
    /// credential id, so the detail cadence is bounded per credential
    /// rather than per request. Holds one `Instant` per credential the
    /// plane has resolved, which is bounded by credential count.
    read_audit_last: parking_lot::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// WOR-2567: named crypto periods and the credential rotation grace
    /// window.
    rotation: sbproxy_config::types::KeyRotationCadenceConfig,
    /// WOR-2573: break-glass emergency access settings.
    break_glass: sbproxy_config::types::BreakGlassConfig,
}

impl KeyPlane {
    /// Assemble a test plane from already-built key-store parts.
    #[cfg(test)]
    pub(crate) fn from_parts(
        crypto: KeyCrypto,
        cache: Arc<TtlCache>,
        failure_mode_allow: bool,
        allow_api_override: bool,
        oidc_claim_field: Option<String>,
    ) -> Self {
        let governance = KeyGovernanceConfig::default();
        let (governance_store, approximate_store) = build_governance_store(&governance)
            .expect("default governance store configuration is valid");
        Self::from_parts_with_governance(
            crypto,
            cache,
            failure_mode_allow,
            allow_api_override,
            oidc_claim_field,
            governance,
            governance_store,
            approximate_store,
        )
    }

    /// Assemble a plane with explicit governed key runtime controls.
    ///
    /// `approximate_store` carries the concrete in-memory counter store when
    /// `governance_store` is backed by it (approximate consistency mode), so
    /// cross-node dissemination can be spawned against the concrete type.
    /// Pass `None` for strict (Redis) governance or when `governance_store`
    /// is not actually an `InMemoryGovernanceStore` (for example, a test
    /// double).
    // Wide by design: the key plane wires several independent subsystems in one place.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts_with_governance(
        crypto: KeyCrypto,
        cache: Arc<TtlCache>,
        failure_mode_allow: bool,
        allow_api_override: bool,
        oidc_claim_field: Option<String>,
        governance: KeyGovernanceConfig,
        governance_store: Arc<dyn GovernanceStore>,
        approximate_store: Option<Arc<InMemoryGovernanceStore>>,
    ) -> Self {
        Self {
            crypto,
            cache,
            resolved_credentials: parking_lot::Mutex::new(std::collections::HashMap::new()),
            // The legacy boolean's own conversion, kept identical to
            // `KeyManagementConfig::failure_posture`: `true` admits, but it
            // admits by falling through with no per-key policy, budget, or
            // attribution, which is a waived guarantee rather than an open
            // door. `prepare_key_plane` overrides this with the resolved
            // posture; the bool parameter stays so callers that only have
            // the legacy value keep compiling.
            failure_posture: if failure_mode_allow {
                FailureMode::Degraded
            } else {
                FailureMode::Closed
            },
            allow_api_override,
            oidc_claim_field,
            governance,
            governance_store,
            approximate_store,
            inbound: sbproxy_config::types::KeyInboundConfig::default(),
            read_audit: sbproxy_config::types::KeyReadAuditConfig::default(),
            read_audit_last: parking_lot::Mutex::new(std::collections::HashMap::new()),
            rotation: sbproxy_config::types::KeyRotationCadenceConfig::default(),
            break_glass: sbproxy_config::types::BreakGlassConfig::default(),
        }
    }

    /// Pin the posture resolved from `key_management.failure_posture`,
    /// replacing whatever the legacy `failure_mode_allow` boolean implied.
    pub(crate) fn with_failure_posture(mut self, posture: FailureMode) -> Self {
        self.failure_posture = posture;
        self
    }

    /// Attach the inbound header-sweep settings.
    ///
    /// Held on the plane rather than read from the pipeline per request, so the
    /// request path reaches them through one already-cloned `Arc`.
    pub(crate) fn with_inbound(mut self, inbound: sbproxy_config::types::KeyInboundConfig) -> Self {
        self.inbound = inbound;
        self
    }

    /// Attach the read/access audit settings (WOR-2570).
    pub(crate) fn with_read_audit(
        mut self,
        read_audit: sbproxy_config::types::KeyReadAuditConfig,
    ) -> Self {
        self.read_audit = read_audit;
        self
    }

    /// Attach the break-glass settings (WOR-2573).
    pub(crate) fn with_break_glass(
        mut self,
        break_glass: sbproxy_config::types::BreakGlassConfig,
    ) -> Self {
        self.break_glass = break_glass;
        self
    }

    /// Attach the named crypto periods and the credential rotation grace
    /// window (WOR-2567).
    pub(crate) fn with_rotation(
        mut self,
        rotation: sbproxy_config::types::KeyRotationCadenceConfig,
    ) -> Self {
        self.rotation = rotation;
        self
    }

    /// The default overlap window a credential rotation opens, in seconds
    /// (WOR-2567).
    ///
    /// One accessor per field rather than one that hands out the whole
    /// block. The config-reader guard proves a key is read by finding a
    /// typed field access, and a `&KeyRotationCadenceConfig` handed across
    /// a crate boundary hides every read behind it. Reading each field
    /// here, where the type is nameable, is what makes "this key is wired"
    /// checkable rather than asserted.
    pub fn credential_rotation_grace_secs(&self) -> u64 {
        self.rotation.credential_grace_secs
    }

    /// The named crypto period for upstream provider credentials, in days.
    pub fn credential_crypto_period_days(&self) -> u32 {
        self.rotation.credential_days
    }

    /// The named crypto period for inbound virtual keys, in days.
    pub fn inbound_key_crypto_period_days(&self) -> u32 {
        self.rotation.inbound_key_days
    }

    /// The named crypto period for the envelope master key, in days.
    pub fn master_key_crypto_period_days(&self) -> u32 {
        self.rotation.master_key_days
    }

    /// The configured read/access audit settings.
    pub fn read_audit(&self) -> &sbproxy_config::types::KeyReadAuditConfig {
        &self.read_audit
    }

    /// The configured break-glass settings (WOR-2573).
    pub fn break_glass(&self) -> &sbproxy_config::types::BreakGlassConfig {
        &self.break_glass
    }

    /// Which inbound headers carry a minted key, and whether one is required.
    pub fn inbound(&self) -> &sbproxy_config::types::KeyInboundConfig {
        &self.inbound
    }

    /// The shared crypto handle (pepper for inbound hashing, master for the
    /// upstream-credential envelope).
    pub fn crypto(&self) -> &KeyCrypto {
        &self.crypto
    }

    /// The fail-closed policy cache in front of the store.
    pub fn cache(&self) -> &Arc<TtlCache> {
        &self.cache
    }

    /// What this plane does when the key store cannot be reached.
    ///
    /// Resolved once at plane construction from
    /// `key_management.failure_posture`, falling back to the legacy
    /// `failure_mode_allow` boolean. Every store-outage decision in the
    /// request path reads this and nothing else.
    ///
    /// [`FailureMode::Closed`] (the default) denies with 503.
    /// [`FailureMode::Degraded`] and [`FailureMode::Open`] both fall
    /// through to the origin's configured auth, which is not a blanket
    /// admit; they differ only in whether the lost per-key policy, budget,
    /// and attribution are recorded as lost.
    pub fn failure_posture(&self) -> FailureMode {
        self.failure_posture
    }

    /// When true, the admin API may override config-seeded records on reload.
    pub fn allow_api_override(&self) -> bool {
        self.allow_api_override
    }

    /// The OIDC/JWT claim whose value names a virtual-key record, if mapping is
    /// configured.
    pub fn oidc_claim_field(&self) -> Option<&str> {
        self.oidc_claim_field.as_deref()
    }

    /// Governed key admission and caller-introspection controls installed with
    /// this key-plane snapshot.
    pub fn governance(&self) -> &KeyGovernanceConfig {
        &self.governance
    }

    /// Shared admission and accounting store for governed requests.
    pub fn governance_store(&self) -> Arc<dyn GovernanceStore> {
        Arc::clone(&self.governance_store)
    }

    /// The concrete approximate counter store, present only in approximate
    /// consistency mode. Used to spawn cross-node dissemination.
    pub fn approximate_store(&self) -> Option<Arc<InMemoryGovernanceStore>> {
        self.approximate_store.clone()
    }

    /// Runtime consistency guarantee mapped explicitly from operator config.
    pub fn governance_consistency(&self) -> RuntimeGovernanceConsistency {
        runtime_governance_consistency(self.governance.consistency)
    }

    /// Secret-free health information from the active governance backend.
    pub async fn governance_health(&self) -> GovernanceBackendHealth {
        self.governance_store.health().await
    }
}

/// The five inbound-key entrypoints that read
/// [`KeyPlane::failure_posture`], as metric label values.
///
/// A closed set of compile-time constants, which is what keeps
/// `sbproxy_key_store_outage_total` bounded. Nothing derived from a
/// credential, a key id, a hostname, or a resolved config value belongs
/// on that family; the id that failed to resolve goes in the log line and
/// the audit record instead, where the storage cost is one row and the
/// lookup is by id.
pub(crate) mod key_store_entrypoint {
    /// The pre-auth sweep over the configured inbound key headers.
    pub(crate) const HEADER_SWEEP: &str = "header_sweep";
    /// The admin playground's loopback impersonation ticket.
    pub(crate) const IMPERSONATION_TICKET: &str = "impersonation_ticket";
    /// The AI gateway's `Authorization: Bearer sbp_...` path.
    pub(crate) const BEARER: &str = "bearer";
    /// The OIDC claim that names a stored virtual-key record.
    pub(crate) const OIDC_CLAIM: &str = "oidc_claim";
    /// Native-provider-key admission, which does not read the store
    /// itself and instead honours a decision an earlier entrypoint made.
    pub(crate) const NATIVE_KEY: &str = "native_key";
}

/// Note that an inbound-key resolution reached a verdict without needing
/// the failure posture, clearing `sbproxy_key_store_unavailable`.
///
/// Takes the whole `Result` and ignores the `Err` arm rather than being
/// called from an `Ok` branch, because the `Err` branch already routes
/// through one of the two outage helpers and counting it twice would put
/// the gauge and the counter into different stories.
///
/// "Reached a verdict" is deliberately weaker than "reached the store". A
/// resolution served out of the TTL cache during an outage kept its
/// per-key policy, budget, and attribution, so nothing was waived for it
/// and the gauge is right to read 0. The counter beside the gauge is what
/// survives that flap.
pub(crate) fn note_key_store_reachable<T>(plane: &KeyPlane, result: &anyhow::Result<T>) {
    if result.is_ok() {
        sbproxy_observe::metrics::record_key_store_reachable(plane.failure_posture().as_label());
    }
}

/// Count one store-outage decision the failure posture made.
///
/// `outcome` is derived here rather than passed in so the counter cannot
/// disagree with [`FailureMode::admits`], which is the function the
/// request path actually branches on.
pub(crate) fn note_key_store_outage(plane: &KeyPlane, entrypoint: &'static str) {
    let posture = plane.failure_posture();
    let outcome = if posture.admits() {
        "admitted"
    } else {
        "denied"
    };
    sbproxy_observe::metrics::record_key_store_outage(entrypoint, posture.as_label(), outcome);
}

/// An upstream credential resolved into the exact header the proxy writes.
///
/// `Debug` is hand-written and redacts, because `value` is the full header
/// value and `material` is the bare decrypted upstream secret: this type is
/// the plaintext, not a reference to it. Nothing formats it today, which is
/// exactly the state every one of this workspace's `Debug` leaks was in the
/// day before it was formatted. It is the type at the centre of the
/// customer-managed claim, since `resolved_credentials` is the cache a
/// failed liveness probe exists to purge, so it gets the same treatment as
/// the five types in `scripts/secret-debug-registry.txt` and a line of its
/// own there.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedCredential {
    /// Lowercase header name to set on the upstream request.
    pub header: String,
    /// Full header value, scheme prefix already applied.
    pub value: String,
    /// The bare secret, with no header name and no scheme prefix.
    ///
    /// Carried alongside [`Self::value`] rather than derived from it,
    /// for the callers that write the credential somewhere other than
    /// this record's own header: an AI provider entry, for one, whose
    /// vendor decides both the header name and whether a scheme prefix
    /// belongs there at all (`x-api-key` bare for Anthropic, `Bearer `
    /// for OpenAI). Stripping the scheme back off `value` at the call
    /// site would make every such caller re-derive a fact this
    /// resolution already had.
    pub material: String,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("header", &self.header)
            .field(
                "value",
                &format_args!("[REDACTED] ({} bytes)", self.value.len()),
            )
            .field(
                "material",
                &format_args!("[REDACTED] ({} bytes)", self.material.len()),
            )
            .finish()
    }
}

/// Why a key's bound credential could not be presented.
///
/// Every variant refuses the request. None falls back to the origin's own
/// `outbound_credential`, because that would hand the key an upstream identity
/// it was never bound to. That is the one failure mode this whole path exists
/// to prevent, so it is encoded in the type rather than left to a caller's
/// `unwrap_or_default`.
#[derive(Debug, Clone)]
pub enum CredentialResolveError {
    /// No credential with that id.
    NotFound,
    /// Present but blocked or revoked.
    NotUsable,
    /// The credential belongs to a different tenant than the key that binds it.
    TenantMismatch,
    /// Present and usable, but the secret could not be obtained: a vault
    /// outage, an unsupported reference scheme, or an envelope sealed under a
    /// master key this process does not hold.
    Unresolvable(String),
}

impl std::fmt::Display for CredentialResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "credential not found"),
            Self::NotUsable => write!(f, "credential is not active"),
            Self::TenantMismatch => write!(f, "credential belongs to another tenant"),
            Self::Unresolvable(reason) => write!(f, "credential unresolvable: {reason}"),
        }
    }
}

/// How long a resolved credential secret stays cached, and how long a
/// stale one may still be served when the backend is unreachable.
///
/// Vault resolution is a network round-trip and must not run per request.
/// Dropped by [`KeyPlane::invalidate_resolved_credential`] on any admin
/// mutation, so a rotation takes effect on the same signal that drops the
/// record itself.
///
/// WOR-2327: this used to be a bare 60 second constant, and
/// `proxy.secrets.rotation.re_resolve_interval_secs` parsed into nothing.
/// It is now that key's value, with 60 seconds as the default so a config
/// without the block behaves exactly as before.
fn rotation_policy() -> sbproxy_vault::RotationPolicy {
    sbproxy_vault::process_rotation()
}

/// How many credentials the read audit tracks a detail-record window for
/// (WOR-2570).
///
/// A deployment with more distinct credentials than this in one window gets
/// detail records more often than the configured cadence for the excess,
/// never fewer. Sized well above what a key plane realistically holds; it
/// is a bound on a process-lifetime map, not a tuning knob.
const READ_AUDIT_TRACKED_CREDENTIALS: usize = 4096;

/// One entry in a plane generation's resolved-secret cache: when the value
/// was resolved, the value itself, and whether the stale-serving episode
/// this entry is currently in has already been announced.
///
/// `stale_announced` is what keeps a grace-window serve announcing once per
/// outage instead of once per request. The grace arm deliberately does not
/// re-stamp `at`, because a re-stamp would make the value look fresh and
/// defeat `stale_serve_deadline` entirely. So `at.elapsed()` keeps growing
/// for as long as the backend is down, and every request retries the full
/// path and lands back in the grace arm. Without this flag that arm would
/// log a line and publish a `credential_resolved` event per request for the
/// whole grace window, which on a busy origin is tens of thousands of events
/// into a queue shared with `key_revoked`.
///
/// The flag lives on the entry rather than in a second map so it cannot fall
/// out of step with the value it describes: a successful resolution replaces
/// the whole entry and an invalidation drops it, and both clear the flag as a
/// side effect. A later outage therefore announces again.
#[derive(Clone)]
struct ResolvedCredentialEntry {
    at: std::time::Instant,
    value: ResolvedCredential,
    /// Hard ceiling on how long this entry may be served, whatever
    /// `proxy.secrets.rotation` says (WOR-2568, WOR-2569).
    ///
    /// `None` is the ordinary case and means the rotation policy alone
    /// decides. `Some` is set where holding the material longer would
    /// break a promise made elsewhere: a customer-managed envelope may
    /// not be served past the root of trust's stated revocation window,
    /// and a leased credential may not be served past its lease.
    ///
    /// One field rather than two because both are the same statement -
    /// this plaintext has an expiry the cache did not choose - and
    /// because a second field is a second thing for the next return path
    /// to forget. It is applied on both serving paths, the fresh hit and
    /// the grace-window stale serve, since the stale path is the one that
    /// would otherwise extend a revocation window by the whole grace
    /// period.
    max_hold: Option<std::time::Duration>,
    stale_announced: bool,
    /// The tenant the underlying record was bound to when it resolved,
    /// `None` for a shared credential.
    ///
    /// Carried here because the cache is keyed by credential id alone
    /// and the tenant refusal lives past the two paths that serve from
    /// it. Without it the first tenant to warm an entry hands every
    /// later tenant the same upstream identity, which is the exact
    /// refusal `resolve_credential_secret` advertises.
    tenant_id: Option<String>,
}

type ResolvedCredentialCache =
    parking_lot::Mutex<std::collections::HashMap<String, ResolvedCredentialEntry>>;

/// Why one attempt to open a credential's material failed, and whether the
/// grace window in `proxy.secrets.rotation` applies to it.
///
/// The distinction was previously spelled out at each `return` in
/// [`KeyPlane::resolve_credential_secret_inner`]; naming it makes the two
/// classes checkable in one place, which matters now that the rotation
/// fallback (WOR-2567) is a second consumer of the same classification.
#[derive(Debug)]
enum MaterialError {
    /// A backend blip. The last known-good cached value may still be
    /// served inside the grace window.
    Transient(String),
    /// A fault that will not fix itself while a grace window runs down: a
    /// master key that no longer opens the envelope, a revoked root of
    /// trust, material that is not utf-8, a vault-referenced credential
    /// with no resolver installed. Serving a stale value here would hide a
    /// rotation or config error behind an availability feature.
    Permanent(String),
}

/// How long an entry may actually be served: the rotation policy's own
/// interval, or the entry's hard ceiling when it has one and that ceiling
/// is shorter (WOR-2568, WOR-2569).
///
/// `min` rather than "the ceiling wins": a deployment that configures a
/// shorter `re_resolve_interval_secs` than the root of trust's revocation
/// window should get the shorter one, and a ceiling that lengthened the
/// hold would be a ceiling in name only.
fn effective_hold(
    policy_window: std::time::Duration,
    max_hold: Option<std::time::Duration>,
) -> std::time::Duration {
    match max_hold {
        Some(ceiling) => policy_window.min(ceiling),
        None => policy_window,
    }
}

/// Whether a credential bound to `record_tenant` may be presented for a
/// request scoped to `request_tenant`.
///
/// A credential with no tenant is shared and any request may present it.
/// One with a tenant may only be presented by a request of that same
/// tenant, and an unscoped request is not a wildcard.
///
/// A free function rather than an inline comparison because the same
/// rule has to hold on three return paths: the record read, the fresh
/// resolved-secret cache hit, and the grace-window stale serve. The
/// first of those is where it was originally written, and the other two
/// return before it.
fn tenant_binding_permits(record_tenant: Option<&str>, request_tenant: Option<&str>) -> bool {
    match record_tenant {
        None => true,
        Some(bound) => request_tenant == Some(bound),
    }
}

/// Drop any cached resolved secret for `id`. Called from the admin mutation
/// path alongside the record-cache invalidation.
pub fn invalidate_resolved_credential(id: &str) {
    if let Some(plane) = current_key_plane() {
        plane.invalidate_resolved_credential(id);
    }
}

/// Drop every cached resolved secret. **Test-only.**
///
/// It has no production caller and is `#[cfg(test)]` so it cannot acquire
/// one by accident. Its survival as a `pub` "drop everything" hammer is
/// exactly what made the liveness-probe test vacuous for a whole round:
/// the test called this by hand, so it asserted a function that already
/// worked rather than the arm the round existed to add. The production
/// purge is [`invalidate_root_backed_resolved_credentials`], which is
/// scoped, and the arm that calls it is `key_root_of_trust::probe_once`.
#[cfg(test)]
pub(crate) fn invalidate_all_resolved_credentials() {
    if let Some(plane) = current_key_plane() {
        plane.invalidate_all_resolved_credentials();
    }
}

/// Drop every cached resolved secret that carries an externally imposed
/// deadline, and leave the rest alone.
///
/// This is what a failed root-of-trust liveness probe calls. The
/// distinction is the whole point, and getting it wrong costs an outage.
///
/// An entry's `max_hold` is `Some` exactly when something outside this
/// cache set its expiry: a customer-managed envelope carrying the time left
/// on the data key that opened it, or a leased credential carrying its
/// lease. Every credential the customer's root ever opened is in that set,
/// so purging it keeps the published clause "or at the next failed liveness
/// probe" true.
///
/// `None` covers plaintext, `vault_ref`, and locally-sealed credentials, and
/// those are also the entries `proxy.secrets.rotation`'s grace window serves
/// stale from. Dropping them on a Transit failure would discard the
/// stale-serve safety net for credentials the customer's root never touched,
/// and the two outages coincide: a Vault outage usually takes the Transit
/// mount and the KV backend down together, which is precisely the outage the
/// grace window exists for. A global purge turns "serve stale inside the
/// grace window" into a hard fail for the whole process, on the tick of a
/// probe that has nothing to say about those credentials.
///
/// The set is a superset of "root-backed" rather than exactly it, because a
/// lease has a `Some` too. Over-purging a leased entry costs one re-lease;
/// under-purging a root-backed one costs the product claim. The superset is
/// the safe side of that.
pub fn invalidate_root_backed_resolved_credentials() {
    if let Some(plane) = current_key_plane() {
        plane.invalidate_root_backed_resolved_credentials();
    }
}

impl KeyPlane {
    /// Drop one resolved upstream secret from this plane generation.
    pub(crate) fn invalidate_resolved_credential(&self, id: &str) {
        self.resolved_credentials.lock().remove(id);
    }

    /// How many decrypted upstream credentials this generation is holding.
    ///
    /// Exists for the tests that assert a purge actually emptied the cache
    /// rather than that a function was called: the difference is what
    /// makes the revocation clause checkable.
    #[cfg(test)]
    pub(crate) fn resolved_credential_count(&self) -> usize {
        self.resolved_credentials.lock().len()
    }

    /// Whether `id` is currently in the resolved-credential cache.
    ///
    /// A count is not enough and that is not a hypothetical. The purge
    /// test warmed one root-backed entry and one plaintext entry and
    /// asserted the survivor count was 1, which is equally true when the
    /// predicate is inverted and exactly the wrong one survives. Nor does
    /// re-resolving the survivor prove anything: a miss falls through to
    /// the store, re-opens the material, and re-inserts, so the call
    /// returns `Ok` whether the entry survived or was rebuilt. Survival
    /// has to be read off the map by name.
    #[cfg(test)]
    pub(crate) fn resolved_credential_is_cached(&self, id: &str) -> bool {
        self.resolved_credentials.lock().contains_key(id)
    }

    /// Drop every resolved upstream secret from this plane generation.
    /// Test-only; see the free function of the same name.
    #[cfg(test)]
    pub(crate) fn invalidate_all_resolved_credentials(&self) {
        self.resolved_credentials.lock().clear();
    }

    /// Drop the resolved secrets whose expiry was set outside this cache.
    /// See [`invalidate_root_backed_resolved_credentials`].
    pub(crate) fn invalidate_root_backed_resolved_credentials(&self) {
        self.resolved_credentials
            .lock()
            .retain(|_, entry| entry.max_hold.is_none());
    }

    /// Claim the right to announce one stale-serving episode for `id`.
    ///
    /// Returns `true` for the first request that falls into the grace window
    /// and `false` for every later request riding the same stale value, so
    /// the warn line and the `credential_resolved` event are bounded by
    /// outages rather than by request rate. The read and the set happen under
    /// one lock acquisition, so two concurrent requests cannot both claim the
    /// same episode.
    ///
    /// A `false` for a missing entry is deliberate: an entry that was
    /// invalidated between this request reading the cache and reaching here
    /// has no episode left to announce, and the value being served is the
    /// clone this request already holds.
    fn claim_stale_announcement(&self, id: &str) -> bool {
        let mut cache = self.resolved_credentials.lock();
        match cache.get_mut(id) {
            Some(entry) if !entry.stale_announced => {
                entry.stale_announced = true;
                true
            }
            _ => false,
        }
    }

    /// Resolve a key's bound credential into the header the upstream carries.
    ///
    /// `tenant_id` is the owning tenant of the key that names this credential.
    /// A cross-tenant binding is refused here as well as at the admin
    /// boundary, because either record's tenant can be patched after the
    /// binding was made.
    ///
    /// # Errors
    ///
    /// Every [`CredentialResolveError`] variant means "refuse the request".
    /// There is deliberately no success path that omits the credential.
    pub async fn resolve_credential_secret(
        &self,
        id: &str,
        tenant_id: Option<&str>,
    ) -> std::result::Result<ResolvedCredential, CredentialResolveError> {
        // WOR-2572: one wrapper, so every return path of the inner
        // resolution lands on the histogram exactly once, with `outcome`
        // read off the one `Result` every caller sees rather than
        // re-derived at each `return`. `cache_layer` reports which layer
        // answered: `hit` (fresh resolved-secret cache), `stale` (grace
        // window served the last known-good value), `miss` (full path).
        //
        // The wrapper deliberately publishes nothing. WOR-2571's typed
        // `credential_resolved` events stay inside the inner function, at
        // the two sites that actually read or serve material, because the
        // two instrumentations have different widths on purpose: the
        // histogram observes every call including the per-request cache
        // hit, the typed feed carries only real reads plus the
        // transition into each grace-window episode.
        // Hoisting either one to the other's site is the merge defect to
        // watch for; see the return-path table on the inner function.
        let started = std::time::Instant::now();
        let mut cache_layer: &'static str = "miss";
        let result = self
            .resolve_credential_secret_inner(id, tenant_id, &mut cache_layer)
            .await;
        let outcome = match &result {
            Ok(_) => "ok",
            Err(
                CredentialResolveError::NotFound
                | CredentialResolveError::NotUsable
                | CredentialResolveError::TenantMismatch,
            ) => "refused",
            Err(CredentialResolveError::Unresolvable(_)) => "error",
        };
        sbproxy_observe::metrics::record_credential_resolution(
            cache_layer,
            outcome,
            started.elapsed().as_secs_f64(),
        );
        // WOR-2570: the read/access audit rides the wrapper rather than
        // the inner function on purpose. `audit.key_path` answers who
        // *changed* a credential; this answers who *read* one, and a read
        // that was served from cache is still a use of the material. So
        // the counter is as wide as the histogram, every return path
        // included, and only the chained detail record is rate limited.
        self.record_credential_read(id, tenant_id, outcome, cache_layer);
        result
    }

    /// Resolve a credential into its bare secret, with no header name
    /// and no scheme prefix.
    ///
    /// For callers that present the material under a header the
    /// *destination* names rather than the one the credential record
    /// carries. The AI provider fallback is the case: the vendor's
    /// wire shape belongs to `sbproxy_ai::ProviderConfig::auth_header`,
    /// and a record seeded with `Bearer ` would otherwise send
    /// `x-api-key: Bearer sk-...` to Anthropic.
    ///
    /// This is a projection of [`Self::resolve_credential_secret`] and
    /// deliberately not a second resolution path: it calls the same
    /// entry point, so the resolution histogram is observed once, the
    /// resolved-secret cache is read and written once, and
    /// `credential_resolved` publishes exactly as the return-path table
    /// on the inner function says. A copy of the resolution body here
    /// would double the typed event for one request.
    ///
    /// # Errors
    ///
    /// Every [`CredentialResolveError`] variant means "refuse". Same
    /// set, same meanings, including the cross-tenant refusal.
    pub async fn resolve_credential_material(
        &self,
        id: &str,
        tenant_id: Option<&str>,
    ) -> std::result::Result<String, CredentialResolveError> {
        self.resolve_credential_secret(id, tenant_id)
            .await
            .map(|resolved| resolved.material)
    }

    /// Open the previous material of a credential that was rotated inside
    /// the overlap window (WOR-2567).
    ///
    /// Returns `None` when the record was never rotated, when the window
    /// has closed, or when the previous material will not open either.
    /// Never called before the current material has already failed, so a
    /// successful rotation never presents the retired secret.
    ///
    /// The overlap is announced once per resolution rather than counted
    /// silently: presenting a retired provider key is a fact an operator
    /// wants in front of them while the rotation is still reversible, and
    /// a rotation that stays in overlap is one where the new key never
    /// went live at the provider.
    async fn open_rotation_grace_material(
        &self,
        record: &CredentialRecord,
    ) -> Option<(String, &'static str, Option<std::time::Duration>)> {
        let now = Utc::now();
        let previous = record.usable_prev_material(now)?;
        let (secret, _, ceiling) = self.open_material(&record.id, previous).await.ok()?;
        let expires_in = record
            .prev_material_expires_at
            .map(|at| (at - now).num_seconds().max(0))
            .unwrap_or_default();
        tracing::warn!(
            credential_id = %record.id,
            overlap_expires_in_secs = expires_in,
            "an upstream credential's current material could not be presented, so the material it \
             carried before its last rotation is being used for the remainder of \
             key_management.crypto.rotation.credential_grace_secs. Confirm the new secret is live \
             at the provider before the window closes."
        );
        sbproxy_observe::publish_proxy_event(
            sbproxy_observe::EventType::CredentialResolved,
            || {
                credential_resolved_event(
                    &record.id,
                    record.tenant_id.as_deref(),
                    "rotation_overlap",
                    Some("prev_material"),
                )
            },
        );
        // The overlap secret is held no longer than the window itself, so
        // the retired key stops being presented when the window closes
        // rather than at the end of whatever cache entry it landed in.
        let overlap_ceiling = std::time::Duration::from_secs(expires_in.max(0) as u64);
        let ceiling = Some(match ceiling {
            Some(existing) => existing.min(overlap_ceiling),
            None => overlap_ceiling,
        });
        Some((secret, "prev_material", ceiling))
    }

    /// Record one credential read for the read/access audit (WOR-2570).
    ///
    /// Two instrumentations with deliberately different widths, the same
    /// split HashiCorp Vault's audit devices make between an unconditional
    /// request record and what a deployment can afford to keep:
    ///
    /// * the counter moves on every call, including the ones that ride the
    ///   per-request cache, because "how often was this credential used" is
    ///   a question about traffic;
    /// * the chained detail record fires at most once per credential per
    ///   `key_management.read_audit.detail_window_secs`, because a record
    ///   per request at gateway volume is a tax on the hot path and a
    ///   chain nobody can read.
    ///
    /// The two diverging under load is the design. `docs/key-management.md`
    /// states it in those words rather than claiming every read is
    /// recorded, because the honest claim is "volume unconditionally,
    /// detail on a bounded cadence".
    ///
    /// Field posture follows Vault's selective hash: the credential id is
    /// HMAC'd under the key-audit fingerprint key when
    /// `hash_identifiers` is on, and the timestamp, outcome, tenant, and
    /// cache layer pass through readable. Nothing here is the secret, the
    /// header value, or the vault reference.
    fn record_credential_read(
        &self,
        id: &str,
        tenant_id: Option<&str>,
        outcome: &'static str,
        cache_layer: &'static str,
    ) {
        sbproxy_observe::metrics::record_credential_read(outcome);
        if !self.read_audit.enabled {
            return;
        }
        if !self.claim_read_audit_window(id) {
            sbproxy_observe::metrics::record_credential_read_audit("suppressed");
            return;
        }
        let recorded_id = if self.read_audit.hash_identifiers {
            match sbproxy_observe::audit_chain::fingerprint_key_audit_value("id", id) {
                Some(hashed) => hashed,
                None => {
                    // No fingerprint key means no way to hash, and
                    // falling back to the clear id would quietly turn
                    // `hash_identifiers: true` into a lie. Refusing to
                    // emit is the fail-closed direction: the volume
                    // counter still moved, so the read is not lost.
                    sbproxy_observe::metrics::record_credential_read_audit("failed");
                    return;
                }
            }
        } else {
            id.to_string()
        };
        let mut entry =
            sbproxy_observe::audit::KeyAuditEntry::new("resolve", "credential", recorded_id)
                .with_outcome(outcome)
                .with_context(format!(
                    "cache={cache_layer} epoch={}",
                    sbproxy_observe::audit_chain::fingerprint_epoch()
                ));
        if let Some(tenant) = tenant_id {
            entry = entry.with_tenant_id(tenant);
        }
        entry.emit();
        sbproxy_observe::metrics::record_credential_read_audit("emitted");
    }

    /// Claim the right to emit one read-audit detail record for `id`.
    ///
    /// Returns `true` for the first read of each credential in each
    /// window and `false` for the rest. Read and set under one lock
    /// acquisition, so two concurrent resolutions cannot both claim the
    /// same window, which is the same construction
    /// [`Self::claim_stale_announcement`] already uses one field over.
    fn claim_read_audit_window(&self, id: &str) -> bool {
        let window = std::time::Duration::from_secs(self.read_audit.detail_window_secs);
        let now = std::time::Instant::now();
        let mut last = self.read_audit_last.lock();
        if let Some(at) = last.get(id) {
            if now.duration_since(*at) < window {
                return false;
            }
        }
        // Bounded, and the bound is why this drops lapsed entries before
        // inserting rather than growing. The key is a credential id, which
        // is operator-set today and reaches here from a key record's
        // binding, so it is not caller-controlled. That is a fact about
        // today's call sites rather than a property of this map, and a
        // process-lifetime map whose safety rests on "no future caller
        // passes an id from a header" is a map that grows the day one
        // does. Sweeping the lapsed entries at the cap costs one pass over
        // a map that only reaches this size on a deployment with that many
        // credentials.
        if last.len() >= READ_AUDIT_TRACKED_CREDENTIALS {
            last.retain(|_, at| now.duration_since(*at) < window);
            if last.len() >= READ_AUDIT_TRACKED_CREDENTIALS {
                // Every entry is still inside its window, so nothing can be
                // dropped without losing a claim somebody already made.
                // Emit rather than suppress: the detail record is the
                // investigative half, and a deployment past this bound has
                // more credentials than the cadence was sized for, which is
                // a thing to see in the record rather than to hide by
                // silently suppressing.
                return true;
            }
        }
        last.insert(id.to_string(), now);
        true
    }

    /// Open one credential material into its bare secret, naming where the
    /// material came from and any hard ceiling on how long the result may
    /// be cached.
    ///
    /// Split out of [`Self::resolve_credential_secret_inner`] because two
    /// callers now need it: the record's current material, and its
    /// previous material inside a rotation grace window (WOR-2567). A
    /// second copy of this body at the fallback site is how the two would
    /// drift, and the fallback is the path nobody exercises daily.
    ///
    /// # Errors
    ///
    /// [`MaterialError::Transient`] when the secret backend could not
    /// answer, [`MaterialError::Permanent`] for everything that will not
    /// fix itself.
    async fn open_material(
        &self,
        record_id: &str,
        material: &CredentialMaterial,
    ) -> std::result::Result<(String, &'static str, Option<std::time::Duration>), MaterialError>
    {
        match material {
            CredentialMaterial::Plaintext { value } => Ok((value.clone(), "plaintext", None)),
            CredentialMaterial::Envelope { envelope } => {
                // WOR-2568: `open_async`, not `open`. A customer-managed
                // envelope names its root of trust and needs the external
                // key service; a locally-wrapped one still opens locally,
                // and the envelope decides which, not the config.
                let opened: sbproxy_keystore::crypto::OpenedEnvelope = self
                    .crypto()
                    .open_async(record_id, envelope)
                    .await
                    .map_err(|e| {
                        // Distinct message: after a master-key rotation
                        // every existing envelope stops opening, and that
                        // is otherwise very hard to tell apart from a
                        // corrupt store.
                        MaterialError::Permanent(format!(
                            "envelope did not open under the configured root of trust: {e:#}"
                        ))
                    })?;
                let secret = String::from_utf8(opened.plaintext)
                    .map_err(|_| MaterialError::Permanent("secret is not utf-8".to_string()))?;
                // WOR-2568: the ceiling is the time *left* on the data key
                // that opened this envelope, handed back by the root of
                // trust, not a fresh copy of the configured window.
                //
                // Reading `root.revocation_window()` here instead is the
                // bug this shipped with once. The unwrap cache's clock
                // starts at the Vault round trip and this cache's clock
                // starts at the resolution, so two caches each clamped to
                // W hold the secret for up to 2W and the published number
                // is half the truth. Inheriting the remaining window makes
                // the total exposure one W by construction, with no second
                // site to keep in step.
                Ok((secret, "envelope", opened.hold_for))
            }
            CredentialMaterial::VaultRef { reference } => {
                let Some(resolver) = sbproxy_vault::process_resolver() else {
                    // A missing resolver is a config fault, not an
                    // outage, so grace does not apply: it will not fix
                    // itself and serving a stale value would hide it.
                    return Err(MaterialError::Permanent(
                        "no secret resolver is installed for a vault-referenced credential"
                            .to_string(),
                    ));
                };
                // The case grace exists for. Everything above this point
                // reads local state; this is the network round-trip to the
                // secret backend, so this is where a vault blip turns a
                // working deployment into 503s.
                match resolver.resolve_async(reference.clone()).await {
                    Ok(secret) => Ok((secret, "vault_ref", None)),
                    Err(e) => Err(MaterialError::Transient(e.to_string())),
                }
            }
            // WOR-2569. Read like a `VaultRef`, because on the wire it is
            // one: a dynamic-secrets mount answers a read by minting. The
            // difference is entirely in the ceiling, which is what makes
            // the credential leased rather than merely fetched.
            CredentialMaterial::Leased {
                reference,
                platform,
                lease_duration_secs,
            } => {
                let Some(resolver) = sbproxy_vault::process_resolver() else {
                    return Err(MaterialError::Permanent(format!(
                        "no secret resolver is installed to lease a {} credential; declare the \
                         dynamic-secrets mount under proxy.secrets.backends",
                        platform.label()
                    )));
                };
                match resolver.resolve_async(reference.clone()).await {
                    Ok(secret) => Ok((
                        secret,
                        "leased",
                        // The whole point. A leased credential is not
                        // cached past its lease, whatever
                        // `proxy.secrets.rotation.re_resolve_interval_secs`
                        // says, so the material stops being presented when
                        // the platform stops honouring it rather than at
                        // whatever the cache felt like.
                        Some(std::time::Duration::from_secs(*lease_duration_secs)),
                    )),
                    Err(e) => Err(MaterialError::Transient(e.to_string())),
                }
            }
        }
    }

    /// [`Self::resolve_credential_secret`] minus the metrics wrapper.
    /// `cache_layer` starts at `miss` and is overwritten by the two
    /// early-return paths that did not run the full resolution.
    ///
    /// Every return path, with what each one reports (WOR-2572) and
    /// publishes (WOR-2571). The two columns are not the same set, and
    /// that is the contract:
    ///
    /// | return path | `cache` / `outcome` | typed event |
    /// |---|---|---|
    /// | fresh resolved-secret cache | `hit` / `ok` | none |
    /// | grace window serves last known-good | `stale` / `ok` | `credential_resolved`, `outcome: stale_served`, once per episode |
    /// | record absent | `miss` / `refused` | none |
    /// | record revoked or blocked | `miss` / `refused` | none |
    /// | credential bound across tenants | `miss` / `refused` | none |
    /// | store or vault down, outside the grace window | `miss` / `error` | none |
    /// | envelope will not open under the master key | `miss` / `error` | none |
    /// | resolved material is not utf-8 | `miss` / `error` | none |
    /// | vault-referenced credential with no resolver installed | `miss` / `error` | none |
    /// | full resolution succeeds | `miss` / `ok` | `credential_resolved`, `outcome: resolved` |
    /// | current material fails, rotation overlap serves | `miss` / `ok` | `credential_resolved`, `outcome: rotation_overlap`, once per serve |
    /// | leased credential minted from its mount | `miss` / `ok` | `credential_resolved`, `outcome: resolved`, `source: leased` |
    ///
    /// Twelve rows for twelve returns, and the last three of the `error` rows
    /// are the ones worth naming rather than folding into "the backend is
    /// down". None of them reaches `serve_stale_on_failure` at all, and
    /// that is a ruling, not an oversight: a master key that no longer
    /// opens the envelopes, material that is not utf-8, and a
    /// vault-referenced credential with no resolver installed are all
    /// faults that will not fix themselves while a grace window runs
    /// down. Serving a stale value there would hide a rotation or config
    /// error behind an availability feature bought for a briefly
    /// unreachable backend.
    ///
    /// The histogram is observed once per call by the wrapper, on every
    /// row. The typed feed carries only the two rows where material was
    /// actually read or served, which is why ordinary per-request
    /// traffic riding the cache publishes nothing at all, and why an
    /// outage that spans a five-minute grace window publishes once
    /// rather than once per request.
    async fn resolve_credential_secret_inner(
        &self,
        id: &str,
        tenant_id: Option<&str>,
        cache_layer: &mut &'static str,
    ) -> std::result::Result<ResolvedCredential, CredentialResolveError> {
        let policy = rotation_policy();
        // One read of the cache, kept for both purposes: a fresh entry is
        // served immediately, and a stale one is held so the grace window
        // below has something to fall back to when the backend is down.
        let cached = self.resolved_credentials.lock().get(id).cloned();
        // The tenant refusal is re-applied here, not only after the
        // record is read below: this cache is keyed by credential id
        // alone, and both paths that serve from it (fresh hit and the
        // grace-window stale serve) return before the record's own
        // `tenant_id` is consulted. A caller resolving one credential id
        // under whichever tenant's request arrived would otherwise be
        // served the first tenant's material for the life of the entry.
        let cached =
            cached.filter(|entry| tenant_binding_permits(entry.tenant_id.as_deref(), tenant_id));
        if let Some(entry) = &cached {
            if entry.at.elapsed() < effective_hold(policy.re_resolve_interval(), entry.max_hold) {
                *cache_layer = "hit";
                return Ok(entry.value.clone());
            }
        }
        // Serve the last known-good value when re-resolution fails and the
        // entry is still inside the grace window.
        //
        // This is the availability half of `proxy.secrets.rotation`. It is
        // not credential overlap: the proxy presents this credential
        // upstream rather than validating one, so there is no old-value
        // acceptance to do. What it prevents is a briefly unreachable
        // vault turning every request carrying a bound credential into a
        // 503 when a good value was resolved seconds ago.
        //
        // Grace defaults to zero, so this is opt-in and the closure is
        // never reached by a config that did not ask for it.
        let serve_stale_on_failure =
            |cache_layer: &mut &'static str, err: CredentialResolveError| match &cached {
                Some(entry)
                    if entry.at.elapsed()
                        < effective_hold(policy.stale_serve_deadline(), entry.max_hold) =>
                {
                    *cache_layer = "stale";
                    // The two instrumentations part company here, on
                    // purpose. `cache_layer = "stale"` is per serve,
                    // because a rate is what an operator alerts on and a
                    // histogram costs nothing per observation. The warn
                    // line and the typed event are per *episode*: this arm
                    // does not re-stamp the entry (a re-stamp would make
                    // the value look fresh and defeat
                    // `stale_serve_deadline`), so every request for the
                    // whole grace window retries the full path and lands
                    // back here. Announcing per request would put one log
                    // line and one `credential_resolved` on the wire per
                    // request carrying this credential, and the events
                    // queue is shared with `key_revoked`, so the noise
                    // would crowd out the signal during exactly the
                    // incident the grace window exists for.
                    if self.claim_stale_announcement(id) {
                        tracing::warn!(
                            credential_id = %id,
                            error = %err,
                            age_secs = entry.at.elapsed().as_secs(),
                            grace_secs = policy.grace_period().as_secs(),
                            "could not re-resolve a bound credential; serving the last known-good \
                             value for the remainder of proxy.secrets.rotation.grace_period_secs"
                        );
                        // WOR-2571: a stale serve is still an actual use
                        // of resolved material, and it is the one a SIEM
                        // most wants to see, because it means the backend
                        // was down and the credential kept working
                        // anyway. One event marks the transition into
                        // stale serving; the next successful resolution
                        // clears the flag, so a second outage is a second
                        // event.
                        sbproxy_observe::publish_proxy_event(
                            sbproxy_observe::EventType::CredentialResolved,
                            || credential_resolved_event(id, tenant_id, "stale_served", None),
                        );
                    }
                    Ok(entry.value.clone())
                }
                _ => Err(err),
            };

        let record = match self.cache().resolve_credential(id).await {
            Ok(Some(record)) => record,
            // A record that is genuinely absent is not a backend failure,
            // so grace does not apply: the credential was deleted and
            // continuing to present it would be wrong.
            Ok(None) => return Err(CredentialResolveError::NotFound),
            Err(e) => {
                return serve_stale_on_failure(
                    cache_layer,
                    CredentialResolveError::Unresolvable(e.to_string()),
                )
            }
        };

        if !record.is_usable() {
            return Err(CredentialResolveError::NotUsable);
        }
        // A credential with no tenant is shared; one with a tenant may only be
        // bound by a key of that same tenant.
        if !tenant_binding_permits(record.tenant_id.as_deref(), tenant_id) {
            return Err(CredentialResolveError::TenantMismatch);
        }

        // WOR-2567: the rotation overlap. The current material is tried
        // first; only when it will not open does the previous material
        // get a turn, and only while its window is open. That ordering is
        // the whole safety property: a rotation that worked never
        // presents the retired secret, and one that has not taken effect
        // at the provider yet does not take the deployment down.
        let (secret, source, max_hold) =
            match self.open_material(&record.id, &record.material).await {
                Ok(opened) => opened,
                Err(primary) => match self.open_rotation_grace_material(&record).await {
                    Some(opened) => opened,
                    None => {
                        return match primary {
                            MaterialError::Permanent(message) => {
                                Err(CredentialResolveError::Unresolvable(message))
                            }
                            MaterialError::Transient(message) => serve_stale_on_failure(
                                cache_layer,
                                CredentialResolveError::Unresolvable(message),
                            ),
                        }
                    }
                },
            };

        let resolved = ResolvedCredential {
            header: record.header.trim().to_ascii_lowercase(),
            value: format!("{}{}", record.scheme, secret),
            material: secret,
        };
        self.resolved_credentials.lock().insert(
            id.to_string(),
            ResolvedCredentialEntry {
                at: std::time::Instant::now(),
                value: resolved.clone(),
                max_hold,
                // A fresh resolution ends whatever stale-serving episode
                // was running, so the next outage announces again.
                stale_announced: false,
                tenant_id: record.tenant_id.clone(),
            },
        );
        // WOR-2571: one typed event per actual resolution. The cached
        // fast path above returns before this point, so a request that
        // rode the cache publishes nothing; see
        // [`credential_resolved_event`] for the cardinality ruling.
        //
        // The overlap path is the one exception and publishes its own
        // `rotation_overlap` event inside `open_rotation_grace_material`,
        // because what a SIEM wants to see there is that a retired secret
        // was presented, not that a resolution happened. Publishing here
        // too would put two events on the wire for one read and describe
        // the same serve twice, once as `resolved` and once as
        // `rotation_overlap`.
        if source != "prev_material" {
            sbproxy_observe::publish_proxy_event(
                sbproxy_observe::EventType::CredentialResolved,
                || credential_resolved_event(id, tenant_id, "resolved", Some(source)),
            );
        }
        Ok(resolved)
    }
}

/// Build the `credential_resolved` typed event for one actual
/// resolution of an upstream credential (WOR-2571).
///
/// Split from [`KeyPlane::resolve_credential_secret`] so the field set
/// is testable without a running event egress, the same shape as
/// `budget_exceeded_event` in `server::ai_support`. The payload mirrors
/// the key-lifecycle mutation events (`op`, `resource`, `id`,
/// `outcome`) so one SIEM rule vocabulary covers the whole family; it
/// never carries the resolved secret, the header value, or a vault
/// reference. `tenant_id` is the tenant scope the resolution was
/// performed under: the tenant of the key that bound this credential,
/// or empty for a shared credential resolved with no tenant scope.
///
/// `outcome` is `resolved` for a fresh resolution and `stale_served`
/// when the backend failed and the last known-good value was served
/// inside `proxy.secrets.rotation.grace_period_secs`. `source` names
/// where fresh material came from (`plaintext`, `envelope`, `vault_ref`,
/// `leased`, or `prev_material` for a rotation overlap) and is absent on
/// the stale path, where nothing was freshly read. The per-request cache hit publishes nothing: this
/// event marks material actually being read, not every request that
/// rode the cached value, the same cardinality ruling that keeps
/// `cache_hit` unwired on the typed feed. Resolution refusals publish
/// nothing here either; the refusal surface is WOR-2567's.
///
/// `stale_served` holds the same line from the other side. A grace
/// window can run for minutes while every request in it re-tries and
/// falls back, so one event marks the *transition* into stale serving
/// and the next successful resolution arms the next one. The
/// per-serve count is on
/// `sbproxy_credential_resolution_duration_seconds{cache="stale"}`,
/// where a rate costs one histogram observation instead of an NDJSON
/// line on a webhook.
fn credential_resolved_event(
    id: &str,
    tenant_id: Option<&str>,
    outcome: &'static str,
    source: Option<&'static str>,
) -> sbproxy_observe::ProxyEvent {
    let mut data = serde_json::json!({
        "op": "resolve",
        "resource": "credential",
        "id": id,
        "outcome": outcome,
    });
    if let Some(source) = source {
        data["source"] = serde_json::json!(source);
    }
    sbproxy_observe::ProxyEvent::new(
        sbproxy_observe::EventType::CredentialResolved,
        String::new(),
        tenant_id.unwrap_or_default().to_string(),
        data,
    )
}

fn runtime_governance_consistency(
    consistency: ConfigGovernanceConsistency,
) -> RuntimeGovernanceConsistency {
    match consistency {
        ConfigGovernanceConsistency::Approximate => RuntimeGovernanceConsistency::Approximate,
        ConfigGovernanceConsistency::Strict => RuntimeGovernanceConsistency::Strict,
    }
}

fn plane_slot() -> &'static ArcSwapOption<KeyPlane> {
    static SLOT: OnceLock<ArcSwapOption<KeyPlane>> = OnceLock::new();
    SLOT.get_or_init(|| ArcSwapOption::from(None))
}

/// The currently installed key plane, or `None` when the dynamic key plane is
/// disabled.
pub fn current_key_plane() -> Option<Arc<KeyPlane>> {
    plane_slot().load_full()
}

/// Publish a bare key plane for a test that only needs the admin routes to
/// find one.
///
/// [`activate_key_plane`] is the only way a running proxy installs or
/// removes a plane, and it does more than write this slot: it clears the
/// mesh readiness view when the committed generation is not mesh-backed,
/// starts the cross-replica invalidation subscriber, and hands a Redis key
/// store to the shared budget counters. A test that wants none of that
/// still needs the slot populated, so this writes it and nothing else.
///
/// Gated to `cfg(test)` and named for it, because a second entry point
/// spelled `install_key_plane` reads like the production installer and is
/// the shape where a later invariant lands on one path only. There is no
/// uninstall counterpart: [`TestPlaneGuard`] clears the slot on drop, so a
/// test cannot leave one behind for the next one to find.
#[cfg(test)]
pub(crate) fn install_key_plane_for_test(plane: Arc<KeyPlane>) {
    plane_slot().store(Some(plane));
}

/// A dedicated, process-lifetime runtime that hosts key-plane async work
/// (seeding, the Redis invalidation subscriber). Kept alive for the whole
/// process so any Redis connection driver it spawns stays running.
fn key_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("sbproxy-keystore")
            .build()
            .expect("build keystore runtime")
    })
}

/// Run a future to completion on the dedicated key runtime, blocking the
/// caller. Driven on a fresh thread so it is safe to call from anywhere,
/// including the admin server's `spawn_blocking` pool and the reload path,
/// without risking a nested-runtime panic. Use for the admin key/credential
/// mutations, which are off the hot path.
pub fn block_on_keystore<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| key_runtime().block_on(fut))
            .join()
            .expect("keystore op thread panicked")
    })
}

/// Resolve a crypto secret reference into raw bytes.
///
/// Delegates to the installed process secret resolver (WOR-2285), so
/// `env:NAME`, `file:PATH`, `${VAR}`, and every provider URI resolve the
/// same way they do everywhere else in the config. Without a resolver
/// installed (`sbproxy validate`, unit tests, a run whose config declares no
/// `proxy.secrets` backends), only `env:NAME`, `file:PATH`, and an inline
/// literal value resolve; a provider URI is refused rather than becoming key
/// material.
fn resolve_secret_material(reference: &str) -> Result<Vec<u8>> {
    if let Some(resolver) = sbproxy_vault::process_resolver() {
        return Ok(resolver
            .resolve(reference)
            .with_context(|| format!("key_management.crypto references '{reference}'"))?
            .into_bytes());
    }
    if let Some(name) = reference.strip_prefix("env:") {
        return Ok(std::env::var(name)
            .with_context(|| format!("environment variable '{name}' for key crypto"))?
            .into_bytes());
    }
    if let Some(path) = reference.strip_prefix("file:") {
        return std::fs::read(path).with_context(|| format!("read crypto material file '{path}'"));
    }
    // A provider URI this site cannot resolve without an installed resolver
    // is an error, never key material.
    //
    // Without this, a mistyped or unsupported reference became the secret: set
    // `key_management.crypto.pepper` to `awssm://prod/pepper` and the pepper
    // was the 19-character ASCII string `awssm://prod/pepper`, published in our
    // own docs and identical for every deployment that pasted it. A pepper's
    // whole job is to make a leaked `password_hash` non-crackable offline, so
    // the failure was silent and total. WOR-1767 established this rule for the
    // central resolver; this site predates it, and now delegates to that same
    // resolver above instead of re-implementing a subset of its parsing.
    if sbproxy_vault::looks_like_secret_reference_uri(reference) {
        anyhow::bail!(
            "key_management.crypto references the secret '{reference}' but no secret backend \
             is installed to resolve it; declare one under proxy.secrets.backends. Without one, \
             this field resolves only `env:NAME`, `file:PATH`, and inline literal values."
        );
    }
    Ok(reference.as_bytes().to_vec())
}

/// Fixed fallback pepper for admin-operator password hashing, used when no
/// `key_management.crypto.pepper` is configured. Lets
/// `proxy.admin.operators` and `sbproxy admin hash-password` work with no
/// `key_management:` block at all, which is the common case. It is a
/// fixed, source-visible constant, so it offers no real secrecy: a leaked
/// `password_hash` is offline-crackable unless a real pepper is pinned.
/// Unlike [`build_crypto`]'s ephemeral-random fallback (fine for the dynamic
/// key plane, whose hashes are computed and verified within the same
/// process lifetime), this pepper must be stable across a restart and
/// across the separate `hash-password` CLI invocation, so it cannot be
/// random. Pin `key_management.crypto.pepper` for anything beyond a single
/// trusted node; that value always takes precedence over this default.
const DEFAULT_ADMIN_OPERATOR_PEPPER: &[u8] = b"sbproxy-admin-operator-default-pepper-v1";

/// The fallback pepper [`resolve_admin_operator_pepper`] uses when no
/// `key_management.crypto.pepper` is configured. Exposed separately so
/// `AdminState::new` has an infallible default to start from.
pub fn default_admin_operator_pepper() -> Vec<u8> {
    DEFAULT_ADMIN_OPERATOR_PEPPER.to_vec()
}

/// Resolve the pepper used to hash and verify `AdminOperator.password_hash`.
///
/// Independent of whether the dynamic key plane is enabled: reads
/// `key_management.crypto.pepper` directly from config when set (the same
/// `env:`/`file:`/inline resolution `build_crypto` uses for the key plane's
/// own pepper), so the running server and the offline `sbproxy admin
/// hash-password` CLI agree without either needing a live installed key
/// plane. Falls back to [`default_admin_operator_pepper`] when
/// `key_management` is `None` or carries no pepper, so admin login works
/// with no `key_management:` block configured at all.
pub fn resolve_admin_operator_pepper(
    key_management: Option<&KeyManagementConfig>,
) -> Result<Vec<u8>> {
    match key_management.and_then(|cfg| cfg.crypto.pepper.as_ref()) {
        Some(reference) => resolve_secret_material(reference),
        None => Ok(default_admin_operator_pepper()),
    }
}

/// Hash a password for `AdminOperator.password_hash`. Thin wrapper over
/// `sbproxy_keystore::crypto::hash_secret` so callers outside
/// this crate (the `sbproxy admin hash-password` CLI) do not need their own
/// `sbproxy-keystore` dependency for this one call.
pub fn hash_admin_operator_password(password: &str, pepper: &[u8]) -> String {
    sbproxy_keystore::crypto::hash_secret(password, pepper)
}

/// Warn when provider hints will recognize a native credential that nothing
/// admits, so enabling `key_management` cannot silently start refusing all
/// caller-supplied provider keys.
///
/// `provider_hints` defaults to a non-empty set and `native_key_policy`
/// defaults to absent, so this combination is what an operator gets by simply
/// switching `key_management.enabled` on. The result is a 403 on every native
/// credential, which is deliberate and fail-closed, but was previously
/// silent: nothing in validation or at boot said the recognition was armed
/// with no policy behind it.
///
/// The message names both opt-ins. Admission needs the proxy-wide policy
/// *and* a per-provider `accept_native_credentials_for` destination binding,
/// and a config carrying only the first is the more confusing state of the
/// two because the policy looks finished.
fn warn_on_ungoverned_provider_hints(cfg: &KeyManagementConfig) {
    let inbound = &cfg.inbound;
    if inbound.provider_hints.is_empty() || inbound.native_key_policy.is_some() {
        return;
    }
    let mut providers: Vec<&str> = inbound
        .provider_hints
        .iter()
        .map(|hint| hint.provider.as_str())
        .collect();
    providers.sort_unstable();
    providers.dedup();
    tracing::warn!(
        providers = providers.join(", "),
        "key_management.inbound.provider_hints recognizes native provider \
         credentials but no inbound.native_key_policy admits any of them, so \
         every one is refused with 403. Declare \
         inbound.native_key_policy.allowed_providers, and on each ai_proxy \
         provider that may receive a caller credential set \
         accept_native_credentials_for; or set provider_hints: [] to stop \
         recognizing them."
    );
}

/// Resolve one crypto-sensitive field, refusing a resolution that gave back
/// the reference it was asked about (WOR-2567).
///
/// The incident this closes: an operator set `pepper: awssm://prod/pepper`,
/// nothing dereferenced it, and the pepper became the 19-character ASCII
/// string `awssm://prod/pepper`, identical on every deployment that copied
/// the config example and offline-crackable by anyone who had read the
/// docs. [`resolve_secret_material`] closed the one instance by refusing a
/// provider URI it cannot resolve. This closes the *class*: whatever the
/// resolver is, whatever the scheme is, a resolved value byte-identical to
/// the reference that named it is not a secret, and a crypto-sensitive
/// field must not accept one.
///
/// It is a separate check rather than a rule inside the resolver because
/// the resolver is shared with fields where a value equal to its own
/// reference is merely odd. On a pepper or a master key it is fatal, and
/// this is the only place that knows that.
///
/// Inline literals are exempt and have to be: `pepper: a-literal-pepper` is
/// the documented way to pin one in a test or a single-node deployment, and
/// there the value *is* the reference. The exemption is narrow on purpose:
/// it applies only when the reference carries no scheme at all, so
/// `env:PEPPER` resolving to the string `env:PEPPER` is still refused.
///
/// # Errors
///
/// Propagates the resolver's own failure, or reports a resolution that
/// returned its own reference.
fn resolve_crypto_field(field: &str, reference: &str) -> Result<Vec<u8>> {
    let resolved = resolve_secret_material(reference)
        .with_context(|| format!("resolve key_management.crypto.{field}"))?;
    let looks_like_a_reference = sbproxy_vault::looks_like_secret_reference_uri(reference)
        || reference.starts_with("env:")
        || reference.starts_with("file:")
        || reference.starts_with("${");
    if looks_like_a_reference && resolved == reference.as_bytes() {
        anyhow::bail!(
            "key_management.crypto.{field} resolved to the literal text of its own reference \
             rather than to a secret. That is not a secret: it is source-visible, identical on \
             every deployment that copied the same config, and defeats the whole purpose of the \
             field. Check that the backend named by the reference is declared under \
             proxy.secrets.backends and actually holds a value."
        );
    }
    Ok(resolved)
}

/// Build the `KeyCrypto` handle from config.
///
/// # What changed, and why the default is now a refusal (WOR-2567)
///
/// This used to mint an ephemeral pepper and master key with a `warn!` when
/// the operator pinned neither. A restart then silently invalidated every
/// stored key hash and every stored envelope, and the deployment found out
/// through a flood of 401s and unopenable credentials rather than through a
/// boot that refused to come up. A warning at boot is read once, by
/// whoever was watching; a refusal is read by whoever caused it.
///
/// Vault and comparable key-management products refuse to start without a
/// resolvable root key rather than minting one, and NIST SP 800-57 Part 1
/// Rev 5 treats key generation and activation as steps an operator owns
/// rather than side effects of a process starting. So: an enabled key plane
/// with no pinned `pepper` or `master_key` fails the boot, naming the
/// missing key, unless `key_management.crypto.allow_ephemeral_secrets` is
/// explicitly true.
///
/// # Errors
///
/// A missing pepper or master key with no explicit opt-in; a resolution
/// failure on either; a resolution that returned its own reference; or an
/// unbuildable customer-managed root of trust.
fn build_crypto(cfg: &KeyManagementConfig) -> Result<KeyCrypto> {
    let pepper = match &cfg.crypto.pepper {
        Some(r) => resolve_crypto_field("pepper", r)?,
        None => ephemeral_or_refuse(cfg, "pepper")?,
    };
    let master = match &cfg.crypto.master_key {
        Some(r) => resolve_crypto_field("master_key", r)?,
        None => ephemeral_or_refuse(cfg, "master_key")?,
    };
    // WOR-2478: derive the key-audit chain's fingerprint key from this same
    // master secret, under a dedicated HKDF purpose, before `master` moves
    // into the `KeyCrypto` handle below. `sbproxy-observe` never sees the
    // master key itself, only the 32 bytes this call derives from it and
    // retains; see that function's docs for why a later call (a hot
    // reload) does not replace an already-installed key.
    sbproxy_observe::audit_chain::install_key_audit_fingerprint_key(&master);
    let crypto = KeyCrypto::new(pepper, master);
    // WOR-2568. Built last so a broken root of trust reports after the two
    // locally-held secrets have already been validated, which keeps the
    // three failure messages from arriving in an order that depends on
    // which one an operator happened to get wrong.
    let Some(root_cfg) = &cfg.crypto.root_of_trust else {
        return Ok(crypto);
    };
    let token = String::from_utf8(
        resolve_crypto_field("root_of_trust.token", &root_cfg.token)
            .context("resolve the customer-managed root-of-trust token")?,
    )
    .context("the customer-managed root-of-trust token is not utf-8")?;
    let root = Arc::new(crate::key_root_of_trust::CustomerManagedRoot::new(
        root_cfg, token,
    )?);
    tracing::info!(
        kek = %root.kek_name(),
        revocation_window_secs = root.revocation_window().as_secs(),
        "customer-managed root of trust installed; upstream-credential envelopes sealed from now \
         on are unreadable without the external key service"
    );
    Ok(crypto.with_root_of_trust(root))
}

/// The old ephemeral-secret behavior, now behind an explicit opt-in.
///
/// # Errors
///
/// When `allow_ephemeral_secrets` is false, which is the default.
fn ephemeral_or_refuse(cfg: &KeyManagementConfig, field: &str) -> Result<Vec<u8>> {
    if !cfg.crypto.allow_ephemeral_secrets {
        anyhow::bail!(
            "key_management is enabled but key_management.crypto.{field} is unset. A process that \
             mints its own {field} loses it on restart: stored key hashes stop verifying and \
             stored credential envelopes stop opening, and the first sign of it is a flood of \
             401s rather than a failed boot. Pin it to a secret reference (env:, file:, vault://, \
             awssm://, ...), or set key_management.crypto.allow_ephemeral_secrets: true for a \
             local development run where a key plane that does not outlive the process is what \
             you want."
        );
    }
    tracing::warn!(
        field,
        "key_management.crypto.{field} is unset and allow_ephemeral_secrets is on; generating an \
         ephemeral value. Stored key hashes and credential envelopes will not survive a restart \
         or a successful config reload.",
    );
    Ok(sbproxy_security::random_aes256_key().to_vec())
}

/// Build the configured store backend: embedded (redb), Redis, or
/// secrets-manager-direct (HashiCorp / AWS / local, via the writable vault
/// backends).
fn build_store(cfg: &KeyManagementConfig) -> Result<Arc<dyn KeyStore>> {
    match cfg.store.backend {
        KeyStoreBackend::Embedded => {
            if let Some(parent) = std::path::Path::new(&cfg.store.path).parent() {
                // Owner-only: this directory holds the redb database of
                // encrypted upstream credentials, and a directory a stranger
                // can traverse discloses the database's name and size even
                // when the file itself is 0o600. Directories that already
                // exist keep the mode their operator chose.
                sbproxy_util::secure_fs::create_dir_all_owner_only(parent)
                    .with_context(|| format!("create keystore directory '{}'", parent.display()))?;
            }
            // `open_shared`, not `open`: reload builds this candidate while
            // the live generation still holds its handle, and redb locks the
            // database file exclusively. An unconditional re-open failed
            // every reload of a config carrying an embedded keystore, which
            // is the default backend, and left the node on the old config.
            let store: Arc<dyn KeyStore> = EmbeddedKeyStore::open_shared(&cfg.store.path)
                .with_context(|| format!("open embedded keystore at '{}'", cfg.store.path))?;
            Ok(store)
        }
        KeyStoreBackend::Redis => {
            let url = cfg
                .store
                .url
                .as_deref()
                .context("key_management.store.url is required for the redis backend")?;
            Ok(Arc::new(sbproxy_keystore::redis_store::RedisKeyStore::new(
                url,
            )))
        }
        KeyStoreBackend::SecretsManager => {
            let spec = build_secrets_manager_spec(cfg)?;
            Ok(Arc::new(
                sbproxy_keystore::secrets_manager::SecretsManagerKeyStore::from_spec(spec)
                    .context("build secrets-manager keystore")?,
            ))
        }
        KeyStoreBackend::Mesh => {
            // WOR-2064: the cluster's replicated state substrate is the
            // system of record. Config compile already refuses this
            // backend without proxy.cluster and its replication block;
            // this is the runtime end of the same guard, for the case
            // where the substrate failed to come up.
            let substrate = crate::cluster::current_cluster_handle()
                .and_then(|handle| handle.mesh_node())
                .and_then(|node| node.replicated_store())
                .context(
                    "key_management.store.backend is 'mesh' but no cluster replication \
                     substrate is running. A mesh keystore on a node with no mesh is an \
                     embedded keystore with extra steps; configure proxy.cluster with a \
                     replication block",
                )?;
            let store = crate::mesh_keystore::MeshKeyStore::new(substrate);
            // Publish the readiness view the `keystore` health probe
            // reads; a later committed generation without the mesh
            // backend clears it again in activate_key_plane.
            crate::mesh_keystore::install_readiness(store.readiness());
            Ok(Arc::new(store))
        }
    }
}

/// Lower the `key_management.store.secrets_manager:` config into a keystore
/// [`SecretsManagerSpec`](sbproxy_keystore::secrets_manager::SecretsManagerSpec),
/// validating the per-provider required fields.
fn build_secrets_manager_spec(
    cfg: &KeyManagementConfig,
) -> Result<sbproxy_keystore::secrets_manager::SecretsManagerSpec> {
    use sbproxy_config::types::SecretsManagerProvider as CfgProvider;
    use sbproxy_keystore::secrets_manager::{SecretsManagerProvider, SecretsManagerSpec};

    let sm = &cfg.store.secrets_manager;
    let provider = match sm.provider {
        CfgProvider::Local => SecretsManagerProvider::Local,
        CfgProvider::Hashicorp => {
            let addr = sm.address.clone().context(
                "key_management.store.secrets_manager.address is required for the hashicorp provider",
            )?;
            let mount = sm.mount.clone().unwrap_or_else(|| "secret".to_string());
            SecretsManagerProvider::Hashicorp {
                addr,
                mount,
                kv_v2: sm.kv_v2,
                token_env: sm.token_env.clone(),
                namespace: sm.namespace.clone(),
            }
        }
        CfgProvider::Aws => {
            let region = sm.region.clone().context(
                "key_management.store.secrets_manager.region is required for the aws provider",
            )?;
            let mount_prefix = sm.mount.clone().unwrap_or_default();
            SecretsManagerProvider::Aws {
                region,
                mount_prefix,
            }
        }
    };
    Ok(SecretsManagerSpec {
        provider,
        prefix: cfg.store.prefix.clone(),
    })
}

/// Build the `TtlCache` wrapping `store`, attaching a Redis L2 tier when
/// configured.
fn build_cache(cfg: &KeyManagementConfig, store: Arc<dyn KeyStore>) -> Arc<TtlCache> {
    // No `fail_closed` here any more (WOR-2121). It was `!failure_mode_allow`,
    // an inverted second spelling of the same operator knob that nothing ever
    // read: the cache propagates a store error unconditionally and the
    // admission decision belongs to the request path, which reads
    // `KeyPlane::failure_posture`.
    let cache_cfg = TtlCacheConfig {
        ttl: std::time::Duration::from_secs(cfg.cache.ttl_secs),
        negative_ttl: std::time::Duration::from_secs(cfg.cache.negative_ttl_secs),
        max_entries: cfg.cache.max_entries,
    };
    let mut cache = TtlCache::new(store, cache_cfg)
        // WOR-2572: every TTL-cache lookup lands on
        // `sbproxy_key_lookup_cache_total{kind, outcome}`. Installed here
        // because this is the one production construction site, and the
        // keystore crate deliberately depends on no metrics stack; the
        // non-capturing closure coerces to the cache's plain `fn` hook.
        .with_lookup_observer(|kind, outcome| {
            sbproxy_observe::metrics::record_key_lookup_cache(kind, outcome)
        });
    match cfg.cache.tier {
        KeyCacheTier::None => {}
        KeyCacheTier::Redis => {
            let url = cfg
                .cache
                .redis_url
                .clone()
                .or_else(|| cfg.store.url.clone());
            if let Some(url) = url {
                cache = cache.with_tier(Arc::new(
                    sbproxy_keystore::redis_store::RedisCacheTier::new(url),
                ));
            } else {
                tracing::warn!(
                    "key_management.cache.tier = redis but no redis_url (or store url) is set; \
                     running with the in-memory tier only"
                );
            }
        }
        KeyCacheTier::Mesh => {
            // Reuse the process-owned cluster substrate. The key plane never
            // opens a second gossip or transport listener.
            let cluster = crate::cluster::current_cluster_handle();
            let node_id = cluster
                .as_ref()
                .map(|handle| handle.identity().node_id.clone())
                .or_else(|| cfg.cache.mesh_node_id.clone())
                .unwrap_or_else(default_node_id);
            let tier: Arc<dyn sbproxy_keystore::CacheTier> = if let Some(node) = cluster
                .as_ref()
                .and_then(sbproxy_mesh::ClusterHandle::mesh_node)
            {
                Arc::new(crate::mesh_cache::MeshCacheTier::clustered(&node))
            } else {
                Arc::new(crate::mesh_cache::MeshCacheTier::standalone(&node_id))
            };
            cache = cache.with_tier(tier);
        }
    }
    Arc::new(cache)
}

/// Build the governance accounting backend without opening a network
/// connection. The Redis client connects lazily on the first operation.
///
/// Returns both the trait-object handle used for admission/accounting and,
/// only in approximate consistency mode, the concrete `InMemoryGovernanceStore`
/// (WOR-1835: needed to spawn cross-node counter dissemination, which applies
/// solely to the approximate tier; strict/Redis governance owns its own
/// coherence and the second element is `None`).
// The trait-object store plus, in approximate mode, the concrete store used to
// spawn dissemination; the tuple is documented above.
#[allow(clippy::type_complexity)]
fn build_governance_store(
    cfg: &KeyGovernanceConfig,
) -> Result<(
    Arc<dyn GovernanceStore>,
    Option<Arc<InMemoryGovernanceStore>>,
)> {
    cfg.validate()
        .map_err(|error| anyhow::anyhow!("validate key_management.governance: {error}"))?;
    let reservation_ttl_millis = cfg
        .lease_ttl_millis()
        .context("convert governance lease TTL")?;
    let terminal_retention_millis = cfg
        .terminal_retention_millis()
        .context("convert governance terminal retention")?;

    match cfg.consistency {
        ConfigGovernanceConsistency::Approximate => {
            let store = Arc::new(
                InMemoryGovernanceStore::new(InMemoryGovernanceConfig {
                    reservation_ttl_millis,
                    terminal_retention_millis,
                })
                .context("build approximate governance store")?,
            );
            Ok((store.clone(), Some(store)))
        }
        ConfigGovernanceConsistency::Strict => {
            let url = match cfg.backend.as_ref() {
                Some(GovernanceBackendConfig::Redis { url }) => url,
                None => anyhow::bail!("strict governance requires an explicit redis backend"),
            };
            let redis = sbproxy_platform::storage::AsyncRedisKVStore::new(
                sbproxy_platform::storage::AsyncRedisConfig::new(url),
            );
            let store = RedisGovernanceStore::new(
                redis,
                RedisGovernanceConfig {
                    reservation_ttl_millis,
                    terminal_retention_millis,
                    ..RedisGovernanceConfig::default()
                },
            )
            .context("build strict Redis governance store")?;
            Ok((Arc::new(store), None))
        }
    }
}

/// The default mesh node id: the `HOSTNAME` environment variable (set per pod
/// in most container schedulers), falling back to a fixed name. Operators set
/// `key_management.cache.mesh_node_id` for an explicit, unique id.
fn default_node_id() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "sbproxy-node".to_string())
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Lower a seed key into a [`KeyRecord`].
fn lower_seed_key(
    seed: &SeedKeyConfig,
    crypto: &KeyCrypto,
    now: DateTime<Utc>,
) -> Option<KeyRecord> {
    let secret_hash = match (&seed.secret, &seed.secret_hash) {
        (Some(secret), _) => crypto.hash_secret(secret),
        (None, Some(hash)) => hash.clone(),
        (None, None) => {
            tracing::warn!(
                key_id = %seed.key_id,
                "seed key has neither secret nor secret_hash; skipping"
            );
            return None;
        }
    };
    let mut rec = KeyRecord::new(seed.key_id.clone(), secret_hash, now);
    rec.source = RecordSource::Config;
    rec.name = seed.name.clone();
    rec.max_requests_per_minute = seed.max_requests_per_minute;
    rec.max_tokens_per_minute = seed.max_tokens_per_minute;
    rec.priority = seed.priority.clone();
    if seed.max_budget_tokens.is_some() || seed.max_budget_usd.is_some() {
        rec.budget = Some(RecordBudget {
            max_tokens: seed.max_budget_tokens,
            max_cost_usd: seed.max_budget_usd,
        });
    }
    rec.allowed_models = seed.allowed_models.clone();
    rec.blocked_models = seed.blocked_models.clone();
    rec.allowed_providers = seed.allowed_providers.clone();
    rec.blocked_providers = seed.blocked_providers.clone();
    rec.allowed_tools = seed.allowed_tools.clone();
    rec.require_pii_redaction = seed.require_pii_redaction.clone();
    rec.principal_selectors = seed.principal_selectors.clone();
    rec.route_to_model = seed.route_to_model.clone();
    rec.compression_profile = seed.compression_profile.clone();
    rec.inject_tools = seed.inject_tools.clone();
    rec.inject_mcp = seed.inject_mcp.clone();
    rec.bypass_prompt_injection = seed.bypass_prompt_injection;
    rec.allow_content_capture = seed.allow_content_capture;
    rec.project = seed.project.clone();
    rec.user = seed.user.clone();
    rec.tags = seed.tags.clone();
    rec.metadata = seed.metadata.clone();
    rec.tenant_id = seed.tenant.clone();
    rec.expires_at = seed.expires_at.as_deref().and_then(parse_rfc3339);
    Some(rec)
}

/// Lower a seed credential into a [`CredentialRecord`], envelope-encrypting an
/// inline secret under whichever root of trust is configured.
///
/// `async` because the seal may be a network call. WOR-2568 made the
/// synchronous `KeyCrypto::seal` refuse outright under a customer-managed
/// root, deliberately, so that no call site can quietly produce a
/// locally-wrapped envelope while the config claims a customer-held root.
/// This site was left on the synchronous path when the admin path moved,
/// which turned that refusal into "every config-seeded `secret:` credential
/// is logged and skipped at boot" the moment an operator enabled
/// `root_of_trust`. Boot still succeeded and the records were simply
/// absent, so the first symptom was a `NotFound` at request time.
async fn lower_seed_credential(
    seed: &SeedCredentialConfig,
    crypto: &KeyCrypto,
    now: DateTime<Utc>,
) -> Option<CredentialRecord> {
    let material = if let Some(reference) = &seed.vault_ref {
        CredentialMaterial::VaultRef {
            reference: reference.clone(),
        }
    } else if let Some(secret) = &seed.secret {
        match crypto.seal_async(&seed.id, secret.as_bytes()).await {
            Ok(envelope) => CredentialMaterial::Envelope { envelope },
            Err(e) => {
                tracing::error!(id = %seed.id, error = %e, "failed to seal seed credential; skipping");
                return None;
            }
        }
    } else {
        tracing::warn!(id = %seed.id, "seed credential has neither vault_ref nor secret; skipping");
        return None;
    };
    Some(CredentialRecord {
        id: seed.id.clone(),
        name: seed.name.clone().unwrap_or_else(|| seed.id.clone()),
        provider: seed.provider.clone(),
        kind: seed
            .kind
            .clone()
            .unwrap_or_else(|| "ai_provider".to_string()),
        header: sbproxy_keystore::record::default_cred_header(),
        scheme: sbproxy_keystore::record::default_cred_scheme(),
        material,
        status: RecordStatus::Active,
        tenant_id: seed.tenant.clone(),
        metadata: Default::default(),
        created_at: now,
        updated_at: now,
        source: RecordSource::Config,
        rotated_at: None,
        prev_material: None,
        prev_material_expires_at: None,
    })
}

/// Apply the declarative seed to the store. Config records are authoritative:
/// they overwrite, unless `allow_api_override` is set and a record already
/// exists (in which case a runtime change is preserved).
async fn seed_records(
    store: &Arc<dyn KeyStore>,
    crypto: &KeyCrypto,
    cfg: &KeyManagementConfig,
    now: DateTime<Utc>,
) -> Result<()> {
    for seed in &cfg.seed.keys {
        if cfg.allow_api_override && store.get_key(&seed.key_id).await?.is_some() {
            continue;
        }
        if let Some(rec) = lower_seed_key(seed, crypto, now) {
            store.put_key(rec).await?;
        }
    }
    for seed in &cfg.seed.credentials {
        if cfg.allow_api_override && store.get_credential(&seed.id).await?.is_some() {
            continue;
        }
        if let Some(rec) = lower_seed_credential(seed, crypto, now).await {
            store.put_credential(rec).await?;
        }
    }
    Ok(())
}

/// Build a candidate key plane without changing process-global or store state.
pub(crate) fn prepare_key_plane(
    cfg: Option<&KeyManagementConfig>,
) -> Result<Option<Arc<KeyPlane>>> {
    // Checked before the `enabled` filter on purpose: a posture this site
    // cannot honour is an operator mistake whether or not the block is
    // switched on, and finding out at the moment it is switched on is the
    // worst time to find out.
    if let Some(cfg) = cfg {
        cfg.validate_failure_posture()
            .map_err(|error| anyhow::anyhow!("config compile: {error}"))?;
    }
    let Some(cfg) = cfg.filter(|cfg| cfg.enabled) else {
        return Ok(None);
    };
    warn_on_ungoverned_provider_hints(cfg);
    let (governance_store, approximate_store) = build_governance_store(&cfg.governance)?;
    let crypto = build_crypto(cfg)?;
    let store = build_store(cfg)?;
    let cache = build_cache(cfg, store.clone());

    let plane = Arc::new(
        KeyPlane::from_parts_with_governance(
            crypto,
            cache.clone(),
            cfg.failure_mode_allow,
            cfg.allow_api_override,
            cfg.oidc_claim_map.as_ref().map(|m| m.claim_field.clone()),
            cfg.governance.clone(),
            governance_store,
            approximate_store,
        )
        .with_failure_posture(cfg.failure_posture())
        .with_inbound(cfg.inbound.clone())
        .with_read_audit(cfg.read_audit.clone())
        .with_rotation(cfg.crypto.rotation.clone())
        .with_break_glass(cfg.break_glass.clone()),
    );
    Ok(Some(plane))
}

/// Apply declarative seeds after every other candidate preflight succeeds.
///
/// Keeping this separate from [`prepare_key_plane`] prevents a later model or
/// pipeline preflight failure from exposing candidate records through
/// generation A's shared store. The generic `KeyStore` contract has no
/// cross-backend batch transaction, so reload treats an error here as a
/// degraded generation B after all reject-only work has passed; boot still
/// returns the error.
pub(crate) fn seed_prepared_key_plane(
    plane: Option<&Arc<KeyPlane>>,
    cfg: Option<&KeyManagementConfig>,
) -> Result<()> {
    let Some((plane, cfg)) = plane.zip(cfg.filter(|cfg| cfg.enabled)) else {
        return Ok(());
    };
    let store = plane.cache().store().clone();
    let now = Utc::now();
    std::thread::scope(|scope| {
        scope
            .spawn(|| key_runtime().block_on(seed_records(&store, plane.crypto(), cfg, now)))
            .join()
            .expect("key-plane seed thread panicked")
    })
    .context("seed key_management records")
}

/// Install a prepared key plane as the process-global admin and cluster view.
///
/// Request paths do not read this slot. They use the plane pinned to their
/// [`crate::pipeline::CompiledPipeline`] generation, so this back-to-back
/// control-plane swap cannot change an in-flight request.
pub(crate) fn activate_key_plane(plane: Option<Arc<KeyPlane>>, cfg: Option<&KeyManagementConfig>) {
    plane_slot().store(plane.clone());

    // WOR-2064: the `keystore` readiness probe follows the committed
    // generation. Clear the published view when this generation does not
    // run the mesh backend, so /readyz stops reporting a backend that is
    // gone. (Installation happens when the backend is built, in
    // `build_store`.)
    let mesh_active =
        cfg.is_some_and(|cfg| cfg.enabled && cfg.store.backend == KeyStoreBackend::Mesh);
    if !mesh_active {
        crate::mesh_keystore::clear_readiness();
    }

    let Some((plane, cfg)) = plane.zip(cfg.filter(|cfg| cfg.enabled)) else {
        return;
    };

    // Cross-replica invalidation: subscribe to the Redis channel so a peer's
    // mutation drops the matching local cache entry. Runs forever on the key
    // runtime, reconnecting on error.
    let subscribe_url = match cfg.store.backend {
        KeyStoreBackend::Redis => cfg.store.url.clone(),
        _ if cfg.cache.tier == KeyCacheTier::Redis => cfg
            .cache
            .redis_url
            .clone()
            .or_else(|| cfg.store.url.clone()),
        _ => None,
    };
    // WOR-1722: when a Redis key store is configured (clustered mode),
    // reuse the same Redis for cluster-shared AI budget counters so a
    // fleet enforces one budget instead of N times the per-instance cap.
    // Absent a Redis key store, budgets stay per-instance (the floor).
    if let Some(url) = subscribe_url.clone() {
        let store = sbproxy_platform::storage::AsyncRedisKVStore::new(
            sbproxy_platform::storage::AsyncRedisConfig::new(&url),
        );
        crate::server::budget_share::install_shared_budget(store);
        tracing::info!("cluster-shared AI budgets enabled (Redis key store)");
    }

    if let Some(url) = subscribe_url {
        let cache = plane.cache().clone();
        key_runtime().spawn(async move {
            loop {
                if let Err(e) =
                    sbproxy_keystore::redis_store::subscribe_invalidations(url.clone(), cache.clone())
                        .await
                {
                    tracing::warn!(error = %e, "keystore invalidation subscriber ended; retrying in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        });
    }

    // WOR-2568: the customer-managed root's liveness probe. Driven on the
    // key plane's own runtime, the same one the invalidation subscriber
    // above uses, so it outlives whichever request thread happened to
    // install the plane.
    if let Some(root_cfg) = cfg.crypto.root_of_trust.as_ref() {
        if let Some(root) = plane.crypto().root_of_trust().cloned() {
            let interval = crate::key_root_of_trust::liveness_interval(root_cfg);
            key_runtime().spawn(crate::key_root_of_trust::run_liveness_probe(root, interval));
        }
    }

    tracing::info!(
        backend = ?cfg.store.backend,
        cache_tier = ?cfg.cache.tier,
        "dynamic key plane installed"
    );
}

/// Build, seed, and immediately install a key plane.
///
/// Boot and reload use the crate-internal `prepare_key_plane`,
/// `seed_prepared_key_plane`, and `activate_key_plane` steps directly so the
/// plane can be committed with its matching pipeline. This wrapper remains for
/// callers and tests that intentionally manage only the process-global admin
/// view.
pub fn init_key_plane(cfg: &KeyManagementConfig) -> Result<()> {
    let plane = prepare_key_plane(Some(cfg))?;
    seed_prepared_key_plane(plane.as_ref(), Some(cfg))?;
    activate_key_plane(plane, Some(cfg));
    Ok(())
}

/// Serialize tests that install the process-global key plane so they do not
/// clobber each other's installed instance when run in parallel.
#[cfg(test)]
fn test_serialize_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// RAII guard for global-key-plane tests: holds the serialize lock for the
/// test's duration and uninstalls the plane on drop (even on panic) so a
/// leftover plane cannot leak into another test.
#[cfg(test)]
pub(crate) struct TestPlaneGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for TestPlaneGuard {
    fn drop(&mut self) {
        plane_slot().store(None);
    }
}

/// Acquire the global-plane test guard.
#[cfg(test)]
pub(crate) fn test_plane_guard() -> TestPlaneGuard {
    TestPlaneGuard(test_serialize_lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_uri_never_becomes_crypto_material() {
        // `key_management.crypto.pepper` set to a provider URI used to become
        // the URI text itself as the pepper: source-visible, identical for
        // every deployment that copied the line, and silently defeating the
        // one property a pepper exists to provide.
        for reference in [
            "vault://hashi/pepper",
            "awssm://prod/pepper",
            "gcpsm://prod/pepper",
            "azurekv://prod/pepper",
            "k8ssecret://ns/pepper",
            "secretfile://file/pepper",
            "secret://local/pepper",
        ] {
            let error = resolve_secret_material(reference)
                .expect_err("a provider URI must never become crypto material");
            assert!(
                error.to_string().contains("resolves only"),
                "{reference} must be refused with the supported forms named, got: {error}"
            );
        }
    }

    #[test]
    fn inline_crypto_material_and_env_still_resolve() {
        // The guard must reject references it cannot resolve without
        // rejecting a legitimate inline secret, which is the documented way
        // to pin a pepper in a test or a single-node deployment.
        let inline = "a-literal-pepper-value";
        assert_eq!(
            resolve_secret_material(inline).expect("inline material is allowed"),
            inline.as_bytes().to_vec()
        );
        // A bare word that merely contains a colon is not a provider URI.
        assert!(resolve_secret_material("not:a-scheme").is_ok());
    }

    #[test]
    fn installed_resolver_delegates_env_and_provider_uri_forms() {
        // WOR-2285: this site used to hand-roll env:/file: parsing and
        // refuse every provider URI outright, even with a resolver
        // installed. It must now delegate to the process resolver, so
        // `env:NAME` and a provider URI both resolve through the one
        // shared code path the rest of the config uses.
        sbproxy_vault::reset_process_resolver_for_test();
        let env = crate::test_env::EnvVarGuard::set(&[(
            "SB_TEST_KEY_PLANE_PEPPER",
            Some("env-delegated-pepper"),
        )]);

        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("pepper", "vault-delegated-pepper")
            .expect("fixture secret");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture", Box::new(vault));
        sbproxy_vault::install_process_resolver(Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(Arc::new(manager)),
        ));

        assert_eq!(
            resolve_secret_material("env:SB_TEST_KEY_PLANE_PEPPER").expect("env:NAME delegates"),
            b"env-delegated-pepper".to_vec()
        );
        assert_eq!(
            resolve_secret_material("secret://fixture/pepper")
                .expect("provider URI delegates once a resolver is installed"),
            b"vault-delegated-pepper".to_vec()
        );

        drop(env);
        sbproxy_vault::reset_process_resolver_for_test();
    }
    use sbproxy_config::types::{
        KeyCryptoConfig, KeySeedConfig, KeyStoreConfig, NativeKeyPolicyConfig,
        SecretsManagerProvider, SecretsManagerStoreConfig,
    };
    use std::sync::Mutex;

    fn temp_db() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!(
            "{}/sbproxy_keyplane_test_{}_{}_{:x}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n,
            nanos
        )
    }

    fn base_cfg(path: &str) -> KeyManagementConfig {
        KeyManagementConfig {
            enabled: true,
            store: KeyStoreConfig {
                backend: KeyStoreBackend::Embedded,
                path: path.to_string(),
                ..Default::default()
            },
            crypto: KeyCryptoConfig {
                pepper: Some("test-pepper".to_string()),
                master_key: Some("test-master".to_string()),
                allow_ephemeral_secrets: false,
                root_of_trust: None,
                rotation: Default::default(),
            },
            ..Default::default()
        }
    }

    /// WOR-2572: `sbproxy_key_lookup_cache_total` is wired through
    /// `build_cache`, not merely covered by keystore unit tests. A plane
    /// built the way production builds one carries the lookup observer,
    /// so a resolve through its cache moves the counter; without the
    /// install in `build_cache` this test is red while every keystore
    /// unit test stays green.
    #[test]
    fn the_key_lookup_cache_counter_is_wired_through_build_cache() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let plane = prepare_key_plane(Some(&base_cfg(&path)))
            .expect("plane builds")
            .expect("an enabled config yields a plane");

        fn lookup_total() -> f64 {
            gathered("sbproxy_key_lookup_cache_total")
                .into_iter()
                .filter(|(labels, _)| labels.contains("kind=key"))
                .map(|(_, value)| value)
                .sum()
        }

        let before = lookup_total();
        let resolved = block_on_keystore(plane.cache().resolve_key("w2572-wired"))
            .expect("embedded store answers");
        assert!(resolved.is_none(), "the id was never minted");
        assert!(
            lookup_total() >= before + 1.0,
            "a resolve through the production-built cache must move \
             sbproxy_key_lookup_cache_total"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn strict_governance_without_redis_fails_before_installing_the_plane() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.governance.consistency = sbproxy_config::GovernanceConsistency::Strict;

        let error = init_key_plane(&cfg).expect_err("strict governance needs Redis");
        assert!(
            error
                .to_string()
                .contains("strict governance requires an explicit redis backend"),
            "unexpected error: {error}"
        );
        assert!(current_key_plane().is_none());
    }

    #[test]
    fn candidate_preparation_does_not_seed_the_live_store_before_commit() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.seed.keys.push(
            serde_json::from_value(serde_json::json!({
                "key_id": "candidate-only",
                "secret": "candidate-secret"
            }))
            .expect("seed fixture"),
        );

        let plane = prepare_key_plane(Some(&cfg))
            .expect("prepare candidate")
            .expect("enabled plane");
        let store = plane.cache().store().clone();
        assert!(
            key_runtime()
                .block_on(store.get_key("candidate-only"))
                .expect("read candidate store")
                .is_none(),
            "candidate construction must not mutate the store before commit",
        );

        seed_prepared_key_plane(Some(&plane), Some(&cfg)).expect("seed at commit boundary");
        assert!(
            key_runtime()
                .block_on(store.get_key("candidate-only"))
                .expect("read committed store")
                .is_some(),
            "the explicit commit step applies declarative seeds",
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn approximate_governance_installs_a_healthy_process_local_store() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.governance.lease_ttl_secs = 2;
        cfg.governance.terminal_retention_secs = 7;

        init_key_plane(&cfg).expect("install approximate governance");
        let plane = current_key_plane().expect("plane installed");

        assert_eq!(plane.governance().lease_ttl_secs, 2);
        assert_eq!(plane.governance().terminal_retention_secs, 7);
        assert_eq!(
            plane.governance_consistency(),
            sbproxy_ai::governance::GovernanceConsistency::Approximate
        );
        let direct_health = key_runtime().block_on(plane.governance_store().health());
        assert_eq!(direct_health.backend, "memory");
        assert_eq!(
            direct_health.status,
            sbproxy_ai::governance::GovernanceBackendStatus::Healthy
        );
        let plane_health = key_runtime().block_on(plane.governance_health());
        assert_eq!(plane_health.consistency, direct_health.consistency);
        assert_eq!(plane_health.backend, direct_health.backend);

        // WOR-1835: approximate mode retains the concrete counter store so
        // cross-node dissemination can be spawned against it.
        assert!(
            plane.approximate_store().is_some(),
            "approximate consistency must expose the concrete in-memory store"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn disabling_key_management_uninstalls_the_live_plane() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);

        init_key_plane(&cfg).expect("install enabled key plane");
        assert!(current_key_plane().is_some());

        cfg.enabled = false;
        init_key_plane(&cfg).expect("disable key plane");
        assert!(
            current_key_plane().is_none(),
            "disabled key management must not leave stale governance state installed"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn strict_governance_constructs_a_lazy_dedicated_redis_store() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.governance.consistency = sbproxy_config::GovernanceConsistency::Strict;
        cfg.governance.backend = Some(sbproxy_config::GovernanceBackendConfig::Redis {
            url: "redis://governance.invalid:6379/4".to_string(),
        });
        cfg.governance.lease_ttl_secs = 3;
        cfg.governance.terminal_retention_secs = 9;

        init_key_plane(&cfg).expect("Redis connection must remain lazy during installation");
        let plane = current_key_plane().expect("plane installed");
        assert_eq!(
            plane.governance_consistency(),
            sbproxy_ai::governance::GovernanceConsistency::Strict
        );
        assert_eq!(plane.governance().lease_ttl_secs, 3);
        assert_eq!(plane.governance().terminal_retention_secs, 9);

        // WOR-1835: strict (Redis) governance owns its own coherence and
        // must not expose a concrete store for dissemination to spawn.
        assert!(
            plane.approximate_store().is_none(),
            "strict consistency must not expose an in-memory store"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn init_seeds_keys_and_credentials_into_embedded_store() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.governance.key_introspection = true;
        cfg.governance.require_governed_key = true;
        cfg.seed = KeySeedConfig {
            keys: vec![SeedKeyConfig {
                key_id: "seed1".into(),
                secret: Some("s3cr3t".into()),
                secret_hash: None,
                name: Some("seeded".into()),
                max_requests_per_minute: Some(10),
                max_tokens_per_minute: Some(2_000),
                priority: Some("interactive".into()),
                max_budget_tokens: Some(1000),
                max_budget_usd: None,
                allowed_models: vec![],
                blocked_models: vec![],
                allowed_providers: vec!["openai".into(), "vertex".into()],
                blocked_providers: vec!["vertex".into()],
                allowed_tools: Some(vec!["search".into()]),
                require_pii_redaction: vec![],
                principal_selectors: vec![],
                route_to_model: None,
                compression_profile: Some("coding-agent".into()),
                inject_tools: vec![],
                inject_mcp: Some(serde_json::json!({ "ref": "toolhub" })),
                bypass_prompt_injection: false,
                allow_content_capture: false,
                project: None,
                user: None,
                tags: vec!["production".into()],
                metadata: [("cost_center".into(), "cc-42".into())]
                    .into_iter()
                    .collect(),
                tenant: None,
                expires_at: None,
            }],
            credentials: vec![SeedCredentialConfig {
                id: "cred1".into(),
                name: Some("openai".into()),
                provider: Some("openai".into()),
                kind: None,
                vault_ref: None,
                secret: Some("sk-upstream".into()),
                tenant: None,
            }],
        };

        init_key_plane(&cfg).unwrap();
        let plane = current_key_plane().expect("plane installed");
        assert!(plane.governance().key_introspection);
        assert!(plane.governance().require_governed_key);

        // The seeded key resolves and verifies the seeded secret.
        let rec = key_runtime()
            .block_on(plane.cache().resolve_key("seed1"))
            .unwrap()
            .expect("seeded key present");
        assert_eq!(rec.name.as_deref(), Some("seeded"));
        assert_eq!(rec.max_requests_per_minute, Some(10));
        assert_eq!(rec.max_tokens_per_minute, Some(2_000));
        assert_eq!(rec.priority.as_deref(), Some("interactive"));
        assert_eq!(rec.allowed_providers, ["openai", "vertex"]);
        assert_eq!(rec.blocked_providers, ["vertex"]);
        assert_eq!(rec.compression_profile.as_deref(), Some("coding-agent"));
        assert_eq!(rec.allowed_tools, Some(vec!["search".to_string()]));
        assert_eq!(
            rec.inject_mcp,
            Some(serde_json::json!({ "ref": "toolhub" }))
        );
        assert_eq!(rec.tags, ["production"]);
        assert_eq!(
            rec.metadata.get("cost_center").map(String::as_str),
            Some("cc-42")
        );
        assert!(rec.verify_secret("s3cr3t", b"test-pepper", Utc::now()));
        assert_eq!(rec.source, RecordSource::Config);

        // The seeded credential is envelope-encrypted and decrypts to plaintext.
        let cred = key_runtime()
            .block_on(plane.cache().resolve_credential("cred1"))
            .unwrap()
            .expect("seeded credential present");
        match &cred.material {
            CredentialMaterial::Envelope { envelope } => {
                let opened = plane.crypto().open("cred1", envelope).unwrap();
                assert_eq!(opened, b"sk-upstream");
            }
            other => panic!("expected envelope material, got {other:?}"),
        }

        std::fs::remove_file(&path).ok();
    }

    /// A config written before `failure_posture` existed must reach the
    /// plane with exactly the behaviour it always had. That is the whole
    /// promise of this migration, so it is pinned in both directions.
    #[test]
    fn a_legacy_failure_mode_allow_config_resolves_to_the_same_admission() {
        let _guard = test_plane_guard();
        // A separate store file per plane: redb takes an exclusive lock, so
        // two live planes cannot share one path.
        let closed_path = temp_db();
        let admitting_path = temp_db();

        let closed_cfg = base_cfg(&closed_path);
        assert!(!closed_cfg.failure_mode_allow, "the legacy default is deny");
        let closed = prepare_key_plane(Some(&closed_cfg))
            .expect("prepare closed plane")
            .expect("enabled plane");
        assert_eq!(closed.failure_posture(), FailureMode::Closed);
        assert!(!closed.failure_posture().admits());
        drop(closed);

        let mut admitting_cfg = base_cfg(&admitting_path);
        admitting_cfg.failure_mode_allow = true;
        let admitting = prepare_key_plane(Some(&admitting_cfg))
            .expect("prepare admitting plane")
            .expect("enabled plane");
        assert!(admitting.failure_posture().admits());
        // `true` has always meant "fall through with no per-key policy,
        // budget, or attribution". That is a waived guarantee, and it is
        // recorded as one rather than as a plain open.
        assert_eq!(admitting.failure_posture(), FailureMode::Degraded);
        assert!(admitting.failure_posture().guarantee_waived());
        drop(admitting);

        std::fs::remove_file(&closed_path).ok();
        std::fs::remove_file(&admitting_path).ok();
    }

    /// An explicit posture wins over the legacy boolean, including when the
    /// two disagree, and `degraded` stays distinguishable from `open`.
    #[test]
    fn an_explicit_failure_posture_overrides_the_legacy_boolean() {
        let _guard = test_plane_guard();
        let closed_path = temp_db();
        let open_path = temp_db();

        let mut closed_cfg = base_cfg(&closed_path);
        closed_cfg.failure_mode_allow = true;
        closed_cfg.failure_posture = Some(FailureMode::Closed);
        let plane = prepare_key_plane(Some(&closed_cfg))
            .expect("prepare plane")
            .expect("enabled plane");
        assert_eq!(
            plane.failure_posture(),
            FailureMode::Closed,
            "the explicit key wins even when the legacy boolean says admit"
        );
        drop(plane);

        let mut open_cfg = base_cfg(&open_path);
        open_cfg.failure_mode_allow = false;
        open_cfg.failure_posture = Some(FailureMode::Open);
        let plane = prepare_key_plane(Some(&open_cfg))
            .expect("prepare plane")
            .expect("enabled plane");
        assert_eq!(plane.failure_posture(), FailureMode::Open);
        assert!(plane.failure_posture().admits());
        assert!(
            !plane.failure_posture().guarantee_waived(),
            "a plain open claims nothing, which is what separates it from degraded"
        );
        assert_eq!(plane.failure_posture().as_label(), "open");
        drop(plane);

        std::fs::remove_file(&closed_path).ok();
        std::fs::remove_file(&open_path).ok();
    }

    /// `observe` has no meaning for an unreachable store, so it is refused
    /// before anything is built, and refused even with the block disabled.
    #[test]
    fn an_observe_posture_is_refused_before_the_plane_is_built() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.failure_posture = Some(FailureMode::Observe);

        let error = prepare_key_plane(Some(&cfg))
            .map(|_| ())
            .expect_err("observe must not build a plane");
        assert!(
            error
                .to_string()
                .contains("key_management.failure_posture: `observe` is meaningless"),
            "the error must name the site: {error}"
        );

        cfg.enabled = false;
        let error = prepare_key_plane(Some(&cfg))
            .map(|_| ())
            .expect_err("a disabled block still rejects the typo");
        assert!(
            error.to_string().contains("key_management.failure_posture"),
            "unexpected error: {error}"
        );

        let mut governed = base_cfg(&path);
        governed.governance.failure_posture = Some(FailureMode::Observe);
        let error = prepare_key_plane(Some(&governed))
            .map(|_| ())
            .expect_err("observe must not build a governance store either");
        assert!(
            error
                .to_string()
                .contains("key_management.governance.failure_posture"),
            "the nested site names itself: {error}"
        );

        std::fs::remove_file(&path).ok();
    }

    /// Every series of `family`, as `(sorted label pairs, value)`.
    fn gathered(family_name: &str) -> Vec<(String, f64)> {
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
                    other => panic!("{family_name} is a {other:?}"),
                };
                out.push((labels.join(","), value));
            }
        }
        out
    }

    fn counter_value(labels: &[&str]) -> f64 {
        gathered("sbproxy_key_store_outage_total")
            .into_iter()
            .find(|(rendered, _)| labels.iter().all(|label| rendered.contains(label)))
            .map(|(_, value)| value)
            .unwrap_or(0.0)
    }

    /// A key-store outage has to leave something an alert can read.
    ///
    /// It was the widest-blast-radius degradation in the matrix and the
    /// only trace of it was a WARN line: `failure_posture` decides whether
    /// an unreachable store refuses the request or hands it to the
    /// origin's own auth carrying no per-key policy, budget, or
    /// attribution, and an operator could only find out which by grepping
    /// logs after the fact.
    ///
    /// Both postures run here because `outcome` is the label that
    /// separates them, and a counter that recorded the outage without
    /// distinguishing a refusal from an ungoverned admission would answer
    /// the wrong half of the question.
    ///
    /// The gauge is asserted only on presence, not on value. Other tests
    /// in this binary resolve keys through planes of their own without
    /// holding the plane guard, and a successful resolution now clears the
    /// gauge, so a value assertion here would be testing the scheduler.
    /// The value transitions are pinned in isolation by
    /// `key_store_outage_is_counted_and_its_posture_gauge_tracks_the_current_state`
    /// in `sbproxy-observe`, where nothing else writes the family.
    #[test]
    fn a_key_store_outage_is_counted_with_the_verdict_its_posture_reached() {
        let _guard = test_plane_guard();
        let closed_path = temp_db();
        let degraded_path = temp_db();

        let closed = prepare_key_plane(Some(&base_cfg(&closed_path)))
            .expect("prepare closed plane")
            .expect("enabled plane");
        assert_eq!(closed.failure_posture(), FailureMode::Closed);

        let denial = ["entrypoint=bearer", "posture=closed", "outcome=denied"];
        let before = counter_value(&denial);
        note_key_store_outage(&closed, key_store_entrypoint::BEARER);
        assert!(
            counter_value(&denial) > before,
            "a closed-posture outage must count as a denial"
        );
        assert!(
            !gathered("sbproxy_key_store_unavailable").is_empty(),
            "the outage site must publish the posture gauge, not just the counter"
        );
        drop(closed);

        let mut degraded_cfg = base_cfg(&degraded_path);
        degraded_cfg.failure_posture = Some(FailureMode::Degraded);
        let degraded = prepare_key_plane(Some(&degraded_cfg))
            .expect("prepare degraded plane")
            .expect("enabled plane");

        let admission = [
            "entrypoint=native_key",
            "posture=degraded",
            "outcome=admitted",
        ];
        let before = counter_value(&admission);
        note_key_store_outage(&degraded, key_store_entrypoint::NATIVE_KEY);
        assert!(
            counter_value(&admission) > before,
            "a degraded-posture outage must count as an admission, on its own entrypoint"
        );

        // An Err carries no claim that the store came back. Without this
        // the two helpers would fight over one series on every failure.
        let before = counter_value(&admission);
        note_key_store_reachable(
            &degraded,
            &Err::<(), anyhow::Error>(anyhow::anyhow!("store down")),
        );
        assert_eq!(
            counter_value(&admission),
            before,
            "a failed resolution must not touch the outage counter"
        );
        drop(degraded);

        std::fs::remove_file(&closed_path).ok();
        std::fs::remove_file(&degraded_path).ok();
    }

    #[test]
    fn disabled_block_installs_nothing() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.enabled = false;
        // A fresh slot would be None anyway; assert init is a no-op error-free.
        init_key_plane(&cfg).unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn secrets_manager_local_backend_builds_and_seeds() {
        // The secrets-manager store backend wires from config (local provider:
        // an in-memory writable vault, exercising the full build_store path).
        let _guard = test_plane_guard();
        let mut cfg = KeyManagementConfig {
            enabled: true,
            store: KeyStoreConfig {
                backend: KeyStoreBackend::SecretsManager,
                secrets_manager: SecretsManagerStoreConfig {
                    provider: SecretsManagerProvider::Local,
                    ..Default::default()
                },
                ..Default::default()
            },
            crypto: KeyCryptoConfig {
                pepper: Some("test-pepper".to_string()),
                master_key: Some("test-master".to_string()),
                allow_ephemeral_secrets: false,
                root_of_trust: None,
                rotation: Default::default(),
            },
            ..Default::default()
        };
        cfg.seed = KeySeedConfig {
            keys: vec![SeedKeyConfig {
                key_id: "sm1".into(),
                secret: Some("s".into()),
                secret_hash: None,
                name: Some("sm-seeded".into()),
                max_requests_per_minute: None,
                max_tokens_per_minute: None,
                priority: None,
                max_budget_tokens: None,
                max_budget_usd: None,
                allowed_models: vec![],
                blocked_models: vec![],
                allowed_providers: vec![],
                blocked_providers: vec![],
                allowed_tools: None,
                require_pii_redaction: vec![],
                principal_selectors: vec![],
                route_to_model: None,
                compression_profile: None,
                inject_tools: vec![],
                inject_mcp: None,
                bypass_prompt_injection: false,
                allow_content_capture: false,
                project: None,
                user: None,
                tags: vec![],
                metadata: Default::default(),
                tenant: None,
                expires_at: None,
            }],
            credentials: vec![],
        };

        init_key_plane(&cfg).unwrap();
        let plane = current_key_plane().expect("plane installed");
        let rec = key_runtime()
            .block_on(plane.cache().resolve_key("sm1"))
            .unwrap()
            .expect("seeded key present in secrets-manager store");
        assert_eq!(rec.name.as_deref(), Some("sm-seeded"));
    }

    #[test]
    fn admin_operator_pepper_falls_back_to_the_default_with_no_key_management() {
        // Admin login must work with no `key_management:` block at all,
        // since that's the common case.
        assert_eq!(
            resolve_admin_operator_pepper(None).unwrap(),
            default_admin_operator_pepper()
        );
        let cfg = KeyManagementConfig::default();
        assert_eq!(
            resolve_admin_operator_pepper(Some(&cfg)).unwrap(),
            default_admin_operator_pepper()
        );
    }

    #[test]
    fn admin_operator_pepper_prefers_a_pinned_key_management_pepper() {
        let cfg = KeyManagementConfig {
            crypto: KeyCryptoConfig {
                pepper: Some("pinned-pepper".to_string()),
                master_key: None,
                allow_ephemeral_secrets: false,
                root_of_trust: None,
                rotation: Default::default(),
            },
            ..Default::default()
        };
        assert_eq!(
            resolve_admin_operator_pepper(Some(&cfg)).unwrap(),
            b"pinned-pepper".to_vec()
        );
    }

    #[test]
    fn admin_operator_pepper_reports_an_unresolvable_reference() {
        let cfg = KeyManagementConfig {
            crypto: KeyCryptoConfig {
                pepper: Some("env:SBPROXY_TEST_ADMIN_PEPPER_DOES_NOT_EXIST".to_string()),
                master_key: None,
                allow_ephemeral_secrets: false,
                root_of_trust: None,
                rotation: Default::default(),
            },
            ..Default::default()
        };
        assert!(resolve_admin_operator_pepper(Some(&cfg)).is_err());
    }

    #[test]
    fn hash_admin_operator_password_matches_the_keystore_primitive() {
        let pepper = b"p";
        assert_eq!(
            hash_admin_operator_password("pw", pepper),
            sbproxy_keystore::crypto::hash_secret("pw", pepper)
        );
    }

    #[derive(Clone)]
    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    struct SharedLogGuard(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogWriter {
        type Writer = SharedLogGuard;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogGuard(Arc::clone(&self.0))
        }
    }

    impl std::io::Write for SharedLogGuard {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// WOR-2293: `provider_hints` defaults to non-empty and `native_key_policy`
    /// defaults to absent, so simply switching `key_management.enabled` on
    /// arms recognition of native provider credentials with nothing behind it
    /// to admit them. Every one of those recognized credentials is refused
    /// with 403, and until this warning existed nothing said so at boot or
    /// reload. Driven through `prepare_key_plane` (not the private warning
    /// function) so the assertion also proves the call site is still wired.
    #[test]
    fn ungoverned_provider_hints_warn_when_prepared() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let cfg = base_cfg(&path);
        assert!(
            !cfg.inbound.provider_hints.is_empty(),
            "the default config must still recognize native provider credentials"
        );
        assert!(
            cfg.inbound.native_key_policy.is_none(),
            "the default config must still leave native_key_policy unset"
        );

        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(SharedLogWriter(Arc::clone(&captured)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            prepare_key_plane(Some(&cfg)).expect("prepare candidate plane");
        });

        let output =
            String::from_utf8(captured.lock().expect("log capture").clone()).expect("UTF-8 log");
        assert!(
            output.contains("provider_hints recognizes native provider"),
            "{output}"
        );
        assert!(output.contains("openai"), "{output}");
        assert!(output.contains("anthropic"), "{output}");

        std::fs::remove_file(&path).ok();
    }

    /// Regression guard: once an operator adds the admitting policy block,
    /// the warning must stop firing even though `provider_hints` is still
    /// non-empty.
    #[test]
    fn native_key_policy_silences_the_ungoverned_provider_hints_warning() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.inbound.native_key_policy = Some(NativeKeyPolicyConfig {
            allowed_providers: vec!["openai".into()],
            ..Default::default()
        });

        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(SharedLogWriter(Arc::clone(&captured)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            prepare_key_plane(Some(&cfg)).expect("prepare candidate plane");
        });

        let output =
            String::from_utf8(captured.lock().expect("log capture").clone()).expect("UTF-8 log");
        assert!(
            output.is_empty(),
            "declaring inbound.native_key_policy must silence the warning: {output}"
        );

        std::fs::remove_file(&path).ok();
    }

    /// `provider_hints: []` is the documented way to stop recognizing native
    /// provider credentials entirely, and must not warn either.
    #[test]
    fn empty_provider_hints_do_not_warn() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.inbound.provider_hints = vec![];

        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(SharedLogWriter(Arc::clone(&captured)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            prepare_key_plane(Some(&cfg)).expect("prepare candidate plane");
        });

        let output =
            String::from_utf8(captured.lock().expect("log capture").clone()).expect("UTF-8 log");
        assert!(
            output.is_empty(),
            "provider_hints: [] must disable the warning along with recognition: {output}"
        );

        std::fs::remove_file(&path).ok();
    }

    // --- WOR-2567: boot refuses to mint its own crypto material ---

    /// The seam: an enabled key plane with no pinned pepper does not boot.
    ///
    /// Before this, `build_crypto` minted a random pepper and logged a
    /// warning. Every stored key hash then stopped verifying at the next
    /// restart, and the deployment learned about it through a flood of
    /// 401s. The refusal has to name the field, because the operator
    /// reading it is looking at a config with two crypto keys in it and
    /// needs to know which one is missing.
    #[test]
    fn boot_refuses_when_no_pepper_is_pinned() {
        let mut cfg = base_cfg(&temp_db());
        cfg.crypto.pepper = None;
        let error = match prepare_key_plane(Some(&cfg)) {
            Err(error) => error,
            Ok(_) => panic!("an enabled key plane with no pinned pepper must not boot"),
        };
        let text = format!("{error:#}");
        assert!(
            text.contains("key_management.crypto.pepper"),
            "the refusal must name the missing key: {text}"
        );
        assert!(
            text.contains("allow_ephemeral_secrets"),
            "the refusal must name the opt-out a developer needs: {text}"
        );

        // Same for the master key, named separately.
        let mut cfg = base_cfg(&temp_db());
        cfg.crypto.master_key = None;
        let error = match prepare_key_plane(Some(&cfg)) {
            Err(error) => error,
            Ok(_) => panic!("no master key, no boot"),
        };
        assert!(
            format!("{error:#}").contains("key_management.crypto.master_key"),
            "{error:#}"
        );
    }

    /// The explicit opt-out still works, because a local development run
    /// with a key plane that does not outlive the process is a real thing
    /// to want. It is just not the default any more.
    #[test]
    fn the_ephemeral_opt_in_still_boots() {
        let _guard = test_plane_guard();
        let mut cfg = base_cfg(&temp_db());
        cfg.crypto.pepper = None;
        cfg.crypto.master_key = None;
        cfg.crypto.allow_ephemeral_secrets = true;
        assert!(
            prepare_key_plane(Some(&cfg))
                .expect("the explicit opt-in boots")
                .is_some(),
            "an enabled config with the opt-in must still yield a plane"
        );
    }

    /// A resolution that hands back the text of its own reference is not a
    /// secret, and a crypto-sensitive field must refuse it whatever the
    /// resolver was.
    ///
    /// [`resolve_secret_material`] already refuses a provider URI it
    /// cannot resolve, which closed the one instance of this bug. This
    /// closes the class: a backend that echoes, a file whose contents are
    /// the reference that named it, a `${VAR}` whose value is the literal
    /// `${VAR}`. Each of those produces a source-visible pepper identical
    /// on every deployment that copied the same config, which is exactly
    /// the failure the original incident had.
    #[test]
    fn a_crypto_field_refuses_a_resolution_that_echoes_its_own_reference() {
        // A `file:` reference whose contents are the reference text is
        // the cheapest reproduction of the class and needs no resolver
        // and no environment mutation. The same check covers every other
        // scheme, because it compares the resolved bytes to the reference
        // rather than inspecting the scheme.
        let path = format!(
            "{}/sbproxy_echoing_pepper_{}.txt",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let reference = format!("file:{path}");
        std::fs::write(&path, reference.as_bytes()).expect("write fixture");
        let error = resolve_crypto_field("pepper", &reference)
            .expect_err("a resolution that returns its own reference is not a secret");
        let text = format!("{error:#}");
        assert!(
            text.contains("literal text of its own reference"),
            "the refusal must say what went wrong: {text}"
        );
        assert!(
            text.contains("key_management.crypto.pepper"),
            "the refusal must name the field: {text}"
        );

        // A real value through the same path still resolves, so the guard
        // is not simply refusing every `file:` reference.
        std::fs::write(&path, b"a-real-pepper-value").expect("write fixture");
        assert_eq!(
            resolve_crypto_field("pepper", &reference).expect("a real value resolves"),
            b"a-real-pepper-value".to_vec()
        );
        let _ = std::fs::remove_file(&path);
    }

    // --- WOR-2568: the revocation window bounds the credential cache ---

    /// The seam: a customer-managed envelope's plaintext may not be
    /// served past the root of trust's stated revocation window, whatever
    /// `proxy.secrets.rotation` says.
    ///
    /// Without the ceiling the honest revocation bound would be the
    /// unwrap-cache TTL *plus* `re_resolve_interval_secs` on the fresh
    /// path, plus `grace_period_secs` again on the stale path. The admin
    /// surface prints one number, so one number has to be true.
    #[test]
    fn a_ceiling_shortens_the_hold_and_never_lengthens_it() {
        use std::time::Duration;
        // No ceiling: the policy window is the answer.
        assert_eq!(
            effective_hold(Duration::from_secs(60), None),
            Duration::from_secs(60)
        );
        // A shorter ceiling wins, which is the revocation bound doing its
        // job.
        assert_eq!(
            effective_hold(Duration::from_secs(60), Some(Duration::from_secs(5))),
            Duration::from_secs(5)
        );
        // A longer ceiling does not extend the hold. A ceiling that could
        // lengthen a window is not a ceiling.
        assert_eq!(
            effective_hold(Duration::from_secs(10), Some(Duration::from_secs(600))),
            Duration::from_secs(10)
        );
    }

    // --- WOR-2570: the read/access audit ---

    /// The seam: the volume counter moves on every credential read
    /// including the cached ones, while the chained detail record fires
    /// at most once per credential per window. The two diverging under
    /// load is the whole design, and this is the test that says so.
    #[tokio::test]
    async fn credential_reads_count_unconditionally_and_detail_on_a_bounded_cadence() {
        let _guard = test_plane_guard();
        let mut cfg = base_cfg(&temp_db());
        cfg.read_audit.enabled = true;
        // Wide enough that the second and third reads in this test land
        // inside the same window as the first.
        cfg.read_audit.detail_window_secs = 3600;
        cfg.read_audit.hash_identifiers = false;
        let plane = prepare_key_plane(Some(&cfg))
            .expect("plane builds")
            .expect("an enabled config yields a plane");

        fn reads() -> f64 {
            gathered("sbproxy_credential_read_total")
                .into_iter()
                .map(|(_, value)| value)
                .sum()
        }
        fn details(outcome: &str) -> f64 {
            gathered("sbproxy_credential_read_audit_records_total")
                .into_iter()
                .filter(|(labels, _)| labels.contains(&format!("outcome={outcome}")))
                .map(|(_, value)| value)
                .sum()
        }

        let envelope = plane
            .crypto()
            .seal("cred-read-audit", b"upstream-secret")
            .expect("seal");
        let now = Utc::now();
        let record = CredentialRecord {
            id: "cred-read-audit".to_string(),
            name: "cred-read-audit".to_string(),
            provider: None,
            kind: "api_key".to_string(),
            header: sbproxy_keystore::record::default_cred_header(),
            scheme: sbproxy_keystore::record::default_cred_scheme(),
            material: CredentialMaterial::Envelope { envelope },
            status: RecordStatus::Active,
            tenant_id: None,
            metadata: Default::default(),
            created_at: now,
            updated_at: now,
            source: RecordSource::Api,
            rotated_at: None,
            prev_material: None,
            prev_material_expires_at: None,
        };
        plane
            .cache()
            .store()
            .put_credential(record)
            .await
            .expect("seed the credential");

        let reads_before = reads();
        let emitted_before = details("emitted");
        let suppressed_before = details("suppressed");

        for _ in 0..3 {
            plane
                .resolve_credential_secret("cred-read-audit", None)
                .await
                .expect("resolves");
        }

        assert_eq!(
            reads() - reads_before,
            3.0,
            "every read moves the volume counter, including the two that rode the cache"
        );
        assert_eq!(
            details("emitted") - emitted_before,
            1.0,
            "exactly one detail record per credential per window"
        );
        assert_eq!(
            details("suppressed") - suppressed_before,
            2.0,
            "the reads that did not get a detail record are counted as suppressed, so the \
             divergence is visible rather than silent"
        );
    }
}

#[cfg(test)]
mod resolve_credential_secret_tests {
    use super::*;
    use sbproxy_keystore::MemoryKeyStore;

    fn plane() -> KeyPlane {
        let crypto = KeyCrypto::new(b"pep".to_vec(), b"master".to_vec());
        let store = Arc::new(MemoryKeyStore::new());
        let cache = Arc::new(TtlCache::new(
            store as Arc<dyn KeyStore>,
            TtlCacheConfig::default(),
        ));
        KeyPlane::from_parts(crypto, cache, false, false, None)
    }

    fn credential(id: &str, material: CredentialMaterial) -> CredentialRecord {
        let now = Utc::now();
        CredentialRecord {
            id: id.to_string(),
            name: id.to_string(),
            provider: None,
            kind: "api_key".to_string(),
            header: sbproxy_keystore::record::default_cred_header(),
            scheme: sbproxy_keystore::record::default_cred_scheme(),
            material,
            status: RecordStatus::Active,
            tenant_id: None,
            metadata: Default::default(),
            created_at: now,
            updated_at: now,
            source: RecordSource::Api,
            rotated_at: None,
            prev_material: None,
            prev_material_expires_at: None,
        }
    }

    async fn put(plane: &KeyPlane, rec: CredentialRecord) {
        plane.cache().store().put_credential(rec).await.unwrap();
    }

    #[tokio::test]
    async fn resolves_an_envelope_credential_into_a_presentable_header() {
        invalidate_all_resolved_credentials();
        let p = plane();
        let envelope = p.crypto().seal("c1", b"upstream-secret").unwrap();
        let mut rec = credential("c1", CredentialMaterial::Envelope { envelope });
        rec.header = "x-api-key".to_string();
        rec.scheme = String::new();
        put(&p, rec).await;

        let resolved = p.resolve_credential_secret("c1", None).await.unwrap();
        assert_eq!(resolved.header, "x-api-key");
        assert_eq!(resolved.value, "upstream-secret");
    }

    #[tokio::test]
    async fn applies_the_scheme_prefix_when_one_is_configured() {
        invalidate_all_resolved_credentials();
        let p = plane();
        put(
            &p,
            credential(
                "c2",
                CredentialMaterial::Plaintext {
                    value: "abc123".into(),
                },
            ),
        )
        .await;

        let resolved = p.resolve_credential_secret("c2", None).await.unwrap();
        assert_eq!(resolved.header, "authorization");
        assert_eq!(resolved.value, "Bearer abc123");
    }

    /// WOR-2655: the AI provider fallback presents this material under
    /// the *vendor's* header, not the credential record's, so it needs
    /// the secret with the record's scheme stripped back off. The
    /// fixture deliberately uses the default `Bearer ` scheme, which is
    /// exactly the prefix that would arrive as
    /// `x-api-key: Bearer sk-...` at Anthropic if this projection were
    /// wrong.
    #[tokio::test]
    async fn resolve_credential_material_yields_the_secret_without_the_scheme() {
        invalidate_all_resolved_credentials();
        let p = plane();
        put(
            &p,
            credential(
                "c-material",
                CredentialMaterial::Plaintext {
                    value: "sk-house-openai".into(),
                },
            ),
        )
        .await;

        let presented = p
            .resolve_credential_secret("c-material", None)
            .await
            .expect("resolves");
        assert_eq!(
            presented.value, "Bearer sk-house-openai",
            "the header form keeps the record's scheme"
        );

        invalidate_all_resolved_credentials();
        let material = p
            .resolve_credential_material("c-material", None)
            .await
            .expect("resolves");
        assert_eq!(material, "sk-house-openai");
    }

    /// WOR-2655: the cross-tenant refusal is inherited from the shared
    /// inner resolution rather than re-implemented, so this proves it
    /// survived the projection. A fallback credential that leaked
    /// across tenants would hand one tenant's requests another tenant's
    /// upstream identity and their bill.
    #[tokio::test]
    async fn resolve_credential_material_refuses_across_tenants() {
        invalidate_all_resolved_credentials();
        let p = plane();
        let mut rec = credential(
            "c-tenant-bound",
            CredentialMaterial::Plaintext {
                value: "sk-acme-only".into(),
            },
        );
        rec.tenant_id = Some("acme".to_string());
        put(&p, rec).await;

        assert!(matches!(
            p.resolve_credential_material("c-tenant-bound", Some("globex"))
                .await,
            Err(CredentialResolveError::TenantMismatch)
        ));
        // And an unscoped request is not a wildcard either.
        assert!(matches!(
            p.resolve_credential_material("c-tenant-bound", None).await,
            Err(CredentialResolveError::TenantMismatch)
        ));
        assert_eq!(
            p.resolve_credential_material("c-tenant-bound", Some("acme"))
                .await
                .expect("the owning tenant resolves it"),
            "sk-acme-only"
        );
    }

    /// The resolved-secret cache is keyed by credential id alone, so the
    /// tenant binding has to be re-checked on the cache-hit path as well
    /// as on the resolution path. The AI provider-key fallback resolves
    /// one `fallback_credential_id` under whichever tenant's request
    /// arrives, so without this the first tenant to warm the cache hands
    /// every other tenant the same upstream identity and the same bill.
    #[tokio::test]
    async fn a_warm_cache_entry_is_still_refused_across_tenants() {
        invalidate_all_resolved_credentials();
        let p = plane();
        let mut rec = credential(
            "c-warm-tenant-bound",
            CredentialMaterial::Plaintext {
                value: "sk-acme-only-warm".into(),
            },
        );
        rec.tenant_id = Some("acme".to_string());
        put(&p, rec).await;

        assert_eq!(
            p.resolve_credential_material("c-warm-tenant-bound", Some("acme"))
                .await
                .expect("the owning tenant resolves it and warms the cache"),
            "sk-acme-only-warm"
        );
        assert!(
            matches!(
                p.resolve_credential_material("c-warm-tenant-bound", Some("globex"))
                    .await,
                Err(CredentialResolveError::TenantMismatch)
            ),
            "a warm cache entry must not serve another tenant's credential"
        );
        assert!(
            matches!(
                p.resolve_credential_material("c-warm-tenant-bound", None)
                    .await,
                Err(CredentialResolveError::TenantMismatch)
            ),
            "and an unscoped request is not a wildcard on the cache path either"
        );
    }

    #[tokio::test]
    async fn a_missing_credential_is_an_error_not_a_fallback() {
        invalidate_all_resolved_credentials();
        let p = plane();
        assert!(matches!(
            p.resolve_credential_secret("nope", None).await,
            Err(CredentialResolveError::NotFound)
        ));
    }

    #[tokio::test]
    async fn a_revoked_credential_is_not_usable() {
        invalidate_all_resolved_credentials();
        let p = plane();
        let mut rec = credential("c3", CredentialMaterial::Plaintext { value: "x".into() });
        rec.status = RecordStatus::Revoked;
        put(&p, rec).await;
        assert!(matches!(
            p.resolve_credential_secret("c3", None).await,
            Err(CredentialResolveError::NotUsable)
        ));
    }

    #[tokio::test]
    async fn a_cross_tenant_binding_is_refused_at_resolution() {
        // Checked here as well as at the admin boundary, because either
        // record's tenant can be patched after the binding was made.
        invalidate_all_resolved_credentials();
        let p = plane();
        let mut rec = credential("c4", CredentialMaterial::Plaintext { value: "x".into() });
        rec.tenant_id = Some("tenant-a".to_string());
        put(&p, rec).await;

        assert!(matches!(
            p.resolve_credential_secret("c4", Some("tenant-b")).await,
            Err(CredentialResolveError::TenantMismatch)
        ));
        assert!(p
            .resolve_credential_secret("c4", Some("tenant-a"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn an_envelope_sealed_under_another_master_key_is_unresolvable() {
        // A master-key rotation stops every existing envelope opening. That
        // must be a loud, distinct error, never a silent fallback.
        invalidate_all_resolved_credentials();
        let sealer = KeyCrypto::new(b"pep".to_vec(), b"a-different-master".to_vec());
        let envelope = sealer.seal("c5", b"secret").unwrap();
        let p = plane();
        put(
            &p,
            credential("c5", CredentialMaterial::Envelope { envelope }),
        )
        .await;

        match p.resolve_credential_secret("c5", None).await {
            Err(CredentialResolveError::Unresolvable(reason)) => {
                // WOR-2568 widened this message from "master key" to
                // "root of trust", because the envelope may now be
                // wrapped by an external key service and "the configured
                // master key" would be the wrong thing to go and check.
                assert!(reason.contains("root of trust"), "{reason}");
            }
            other => panic!("expected Unresolvable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_resolved_secret_is_cached_and_dropped_on_invalidation() {
        invalidate_all_resolved_credentials();
        let p = plane();
        put(
            &p,
            credential(
                "c6",
                CredentialMaterial::Plaintext {
                    value: "first".into(),
                },
            ),
        )
        .await;
        assert_eq!(
            p.resolve_credential_secret("c6", None).await.unwrap().value,
            "Bearer first"
        );

        // Rotate the stored secret. The cache still holds the old one, which
        // is the behaviour that makes invalidation load-bearing.
        put(
            &p,
            credential(
                "c6",
                CredentialMaterial::Plaintext {
                    value: "second".into(),
                },
            ),
        )
        .await;
        assert_eq!(
            p.resolve_credential_secret("c6", None).await.unwrap().value,
            "Bearer first",
            "served from cache until invalidated"
        );

        p.invalidate_resolved_credential("c6");
        p.cache()
            .invalidate("c6")
            .await
            .expect("no tier attached in this test");
        assert_eq!(
            p.resolve_credential_secret("c6", None).await.unwrap().value,
            "Bearer second",
            "invalidation drops the resolved secret, not just the record"
        );
    }

    #[tokio::test]
    async fn resolved_credential_cache_is_isolated_per_key_plane_generation() {
        // The same record id can legitimately resolve differently after reload.
        invalidate_all_resolved_credentials();
        let plane_a = plane();
        let plane_b = plane();
        put(
            &plane_a,
            credential(
                "shared-id",
                CredentialMaterial::Plaintext {
                    value: "generation-a".into(),
                },
            ),
        )
        .await;
        put(
            &plane_b,
            credential(
                "shared-id",
                CredentialMaterial::Plaintext {
                    value: "generation-b".into(),
                },
            ),
        )
        .await;

        assert_eq!(
            plane_a
                .resolve_credential_secret("shared-id", None)
                .await
                .unwrap()
                .value,
            "Bearer generation-a",
        );
        assert_eq!(
            plane_b
                .resolve_credential_secret("shared-id", None)
                .await
                .unwrap()
                .value,
            "Bearer generation-b",
            "a newer plane must not reuse a resolved secret cached by an older plane",
        );
    }

    // --- WOR-2327: proxy.secrets.rotation is consumed ---
    //
    // Both keys parsed, validated, and reached nothing. These drive
    // `resolve_credential_secret`, the production path, rather than the
    // policy type on its own, so they fail if the policy stops being read
    // even while `RotationPolicy`'s own tests still pass.

    /// Serializes the four rotation tests below.
    ///
    /// They drive two process-wide singletons, the secret resolver and the
    /// rotation policy, and each one installs a different value. Under
    /// nextest's process-per-test they would be isolated anyway, but
    /// `cargo test` runs them as threads in one process and they then
    /// clobber each other: the interval test observed another test's
    /// still-working resolver and saw a success where it required a
    /// failure. Relying on the runner's isolation model would leave a test
    /// that is green in CI and red in the documented inner loop.
    ///
    /// `tokio::sync::Mutex` rather than a sync one: each test awaits
    /// inside the guarded region, and holding a sync guard across an await
    /// is what `clippy::await_holding_lock` exists to catch. It also does
    /// not poison, so a panicking assertion in one test does not cascade
    /// into the other three.
    static ROTATION_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Install a working `secret://fixture/upstream-key` backend.
    fn install_working_vault() {
        sbproxy_vault::reset_process_resolver_for_test();
        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("upstream-key", "live-secret")
            .expect("fixture secret");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture", Box::new(vault));
        sbproxy_vault::install_process_resolver(Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(Arc::new(manager)),
        ));
    }

    /// Replace the resolver with one that has no backends, so the same
    /// reference now fails the way an unreachable vault does.
    fn break_the_vault() {
        sbproxy_vault::reset_process_resolver_for_test();
        sbproxy_vault::install_process_resolver(Arc::new(sbproxy_vault::SecretResolver::new()));
    }

    async fn vault_backed_plane() -> KeyPlane {
        let p = plane();
        put(
            &p,
            credential(
                "rotating",
                CredentialMaterial::VaultRef {
                    reference: "secret://fixture/upstream-key".to_string(),
                },
            ),
        )
        .await;
        p
    }

    #[tokio::test]
    async fn re_resolve_interval_governs_how_long_a_credential_is_cached() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        // The wiring assertion. A zero interval means every lookup is
        // stale, so the second call must reach the backend again. Under
        // the old hardcoded 60 second constant this config could not be
        // expressed at all.
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(0, 0)));
        install_working_vault();
        let p = vault_backed_plane().await;

        assert_eq!(
            p.resolve_credential_secret("rotating", None)
                .await
                .expect("first resolution succeeds")
                .value,
            "Bearer live-secret"
        );

        // Nothing was invalidated. With a 60 second window this would be
        // served from cache; with a zero window it has to go back out, and
        // a broken backend proves it did.
        break_the_vault();
        assert!(
            p.resolve_credential_secret("rotating", None).await.is_err(),
            "a zero re_resolve_interval must send the next lookup back to the backend"
        );
    }

    #[tokio::test]
    async fn grace_serves_the_last_known_good_value_when_the_vault_is_down() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        // The availability half. A vault blip used to turn every request
        // carrying a bound credential into a 503 even though a good value
        // had been resolved moments earlier.
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(
            0, 300,
        )));
        install_working_vault();
        let p = vault_backed_plane().await;

        assert_eq!(
            p.resolve_credential_secret("rotating", None)
                .await
                .expect("first resolution succeeds")
                .value,
            "Bearer live-secret"
        );

        break_the_vault();
        assert_eq!(
            p.resolve_credential_secret("rotating", None)
                .await
                .expect("grace must serve the last known-good value")
                .value,
            "Bearer live-secret",
            "inside the grace window an unreachable vault must not fail the request"
        );
    }

    #[tokio::test]
    async fn grace_is_off_by_default_so_a_dead_vault_still_fails_closed() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        // The other half of the contract. Serving a stale credential is an
        // availability-over-freshness trade, so it has to be asked for. A
        // config with no rotation block must keep failing closed.
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(0, 0)));
        install_working_vault();
        let p = vault_backed_plane().await;
        let _ = p.resolve_credential_secret("rotating", None).await;

        break_the_vault();
        assert!(
            matches!(
                p.resolve_credential_secret("rotating", None).await,
                Err(CredentialResolveError::Unresolvable(_))
            ),
            "with grace at zero a failed re-resolution must refuse the request"
        );
    }

    #[tokio::test]
    async fn a_deleted_credential_is_never_covered_by_grace() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        // Grace exists for backend outages. A record that is genuinely
        // gone was deleted on purpose, and continuing to present it would
        // turn a revocation into a five minute window where the
        // credential still works.
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(
            0, 300,
        )));
        install_working_vault();
        let p = vault_backed_plane().await;
        let _ = p.resolve_credential_secret("rotating", None).await;

        p.cache()
            .store()
            .delete_credential("rotating")
            .await
            .expect("delete the record");
        p.cache()
            .invalidate("rotating")
            .await
            .expect("no tier attached in this test");
        assert!(
            matches!(
                p.resolve_credential_secret("rotating", None).await,
                Err(CredentialResolveError::NotFound)
            ),
            "a revoked credential must not be served out of the grace window"
        );
    }

    /// WOR-2572: observation count for one `{cache, outcome}` series of
    /// the credential-resolution histogram. Other tests in this process
    /// can also resolve credentials, so callers assert on deltas.
    fn resolution_count(cache: &str, outcome: &str) -> u64 {
        let want = [format!("cache={cache}"), format!("outcome={outcome}")];
        let mut total = 0;
        for family in prometheus::gather() {
            if family.name() != "sbproxy_credential_resolution_duration_seconds" {
                continue;
            }
            for metric in family.get_metric() {
                let labels: Vec<String> = metric
                    .get_label()
                    .iter()
                    .map(|pair| format!("{}={}", pair.name(), pair.value()))
                    .collect();
                if want.iter().all(|label| labels.contains(label)) {
                    total += metric.get_histogram().get_sample_count();
                }
            }
        }
        total
    }

    /// WOR-2572: every resolution lands on the histogram with the layer
    /// that answered and the real outcome. `hit` and `miss` are what the
    /// derivable cache-hit-ratio panel divides; `refused` is asserted as
    /// its own value so an absent credential can never inflate `error`
    /// (or disappear into `ok`).
    #[tokio::test]
    async fn resolution_latency_reports_cache_disposition_and_outcome() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();
        // A real re-resolve interval, so the second lookup is a fresh hit.
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(
            300, 0,
        )));

        let p = plane();
        put(
            &p,
            credential(
                "w2572-plain",
                CredentialMaterial::Plaintext {
                    value: "sk-w2572".to_string(),
                },
            ),
        )
        .await;

        let before_miss_ok = resolution_count("miss", "ok");
        let before_hit_ok = resolution_count("hit", "ok");
        let before_miss_refused = resolution_count("miss", "refused");

        p.resolve_credential_secret("w2572-plain", None)
            .await
            .expect("first resolution runs the full path");
        assert!(
            resolution_count("miss", "ok") > before_miss_ok,
            "the first resolution is a miss with outcome=ok"
        );

        p.resolve_credential_secret("w2572-plain", None)
            .await
            .expect("second resolution is served from the resolved cache");
        assert!(
            resolution_count("hit", "ok") > before_hit_ok,
            "a fresh resolved-cache serve must be labeled cache=hit"
        );

        assert!(matches!(
            p.resolve_credential_secret("w2572-absent", None).await,
            Err(CredentialResolveError::NotFound)
        ));
        assert!(
            resolution_count("miss", "refused") > before_miss_refused,
            "an absent credential is a refusal, its own outcome value"
        );
    }

    /// WOR-2572: a grace-window serve is `stale`, deliberately not folded
    /// into `hit`, and a backend that stays down past grace is `error`,
    /// never `refused`. Both come from the one `Result` the wrapper sees.
    #[tokio::test]
    async fn stale_grace_serves_and_backend_failures_get_their_own_labels() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(
            0, 300,
        )));
        install_working_vault();
        let p = vault_backed_plane().await;

        let before_stale_ok = resolution_count("stale", "ok");
        let before_miss_error = resolution_count("miss", "error");

        p.resolve_credential_secret("rotating", None)
            .await
            .expect("first resolution succeeds");

        break_the_vault();
        p.resolve_credential_secret("rotating", None)
            .await
            .expect("grace serves the last known-good value");
        assert!(
            resolution_count("stale", "ok") > before_stale_ok,
            "a grace serve is cache=stale outcome=ok: a backend failure wearing a grace period"
        );

        // Same broken backend, no grace: the failure is an error.
        sbproxy_vault::reset_process_rotation_for_test();
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(0, 0)));
        assert!(matches!(
            p.resolve_credential_secret("rotating", None).await,
            Err(CredentialResolveError::Unresolvable(_))
        ));
        assert!(
            resolution_count("miss", "error") > before_miss_error,
            "an unreachable backend is outcome=error, never refused"
        );
    }

    // --- WOR-2571: the `credential_resolved` typed event ---

    #[test]
    fn credential_resolved_event_carries_the_allowlisted_fields() {
        let event = super::credential_resolved_event(
            "cred-shape",
            Some("acme"),
            "resolved",
            Some("envelope"),
        );
        assert_eq!(
            event.event_type,
            sbproxy_observe::EventType::CredentialResolved
        );
        assert_eq!(event.tenant_id, "acme");
        assert_eq!(event.hostname, "");
        assert_eq!(event.data["op"], "resolve");
        assert_eq!(event.data["resource"], "credential");
        assert_eq!(event.data["id"], "cred-shape");
        assert_eq!(event.data["outcome"], "resolved");
        assert_eq!(event.data["source"], "envelope");

        let stale = super::credential_resolved_event("cred-shape", None, "stale_served", None);
        assert_eq!(stale.tenant_id, "");
        assert_eq!(stale.data["outcome"], "stale_served");
        let object = stale.data.as_object().expect("payload is an object");
        assert!(
            !object.contains_key("source"),
            "the stale path read nothing fresh, so it must not claim a source: {:?}",
            stale.data
        );
    }

    /// Poll `path` until `predicate` matches an NDJSON line or five
    /// seconds pass. The file egress flushes per drained batch on its
    /// own OS thread, so a plain read races the worker.
    fn poll_events_file(
        path: &std::path::Path,
        predicate: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some(line) = content.lines().find(|line| predicate(line)) {
                    return Some(line.to_string());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        None
    }

    /// WOR-2571, the resolution seam, red-first: before the publish
    /// call in [`KeyPlane::resolve_credential_secret`], this test timed
    /// out polling for `credential_resolved` because a resolution left
    /// no trace on the typed feed at all. One egress install per
    /// process, which nextest's process-per-test model guarantees.
    #[tokio::test]
    async fn resolving_a_credential_publishes_one_credential_resolved_event() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("credential-resolved-events.ndjson");
        let egress = sbproxy_observe::EventEgress::start(
            sbproxy_observe::EventSinkTarget::File { path: path.clone() },
            sbproxy_observe::EventTypeMask::from_types(&[
                sbproxy_observe::EventType::CredentialResolved,
            ]),
            64,
        )
        .expect("file egress starts");
        sbproxy_observe::install_event_egress(egress)
            .expect("this test's own event egress installs exactly once in its own process");

        let p = plane();
        let secret_material = "upstream-secret-material-that-must-not-cross";
        let envelope = p
            .crypto()
            .seal("cred-siem", secret_material.as_bytes())
            .unwrap();
        let mut rec = credential("cred-siem", CredentialMaterial::Envelope { envelope });
        rec.tenant_id = Some("acme".to_string());
        put(&p, rec).await;
        put(
            &p,
            credential(
                "cred-marker",
                CredentialMaterial::Plaintext {
                    value: "marker-value".into(),
                },
            ),
        )
        .await;

        p.resolve_credential_secret("cred-siem", Some("acme"))
            .await
            .expect("the envelope credential resolves");
        // Ride the cache: this second call must not publish again.
        p.resolve_credential_secret("cred-siem", Some("acme"))
            .await
            .expect("the cached credential resolves");
        // The marker resolves after both, so once its event is on disk
        // a second `cred-siem` event had every chance to arrive.
        p.resolve_credential_secret("cred-marker", None)
            .await
            .expect("the marker credential resolves");

        poll_events_file(&path, |line| line.contains("cred-marker"))
            .expect("the marker resolution must reach the egress");

        let content = std::fs::read_to_string(&path).expect("events file is readable");
        let siem_lines: Vec<&str> = content
            .lines()
            .filter(|line| line.contains("cred-siem"))
            .collect();
        assert_eq!(
            siem_lines.len(),
            1,
            "one actual resolution, one event; the cache hit must not publish: {content}"
        );
        let event: serde_json::Value =
            serde_json::from_str(siem_lines[0]).expect("event line parses");
        assert_eq!(event["event_type"], "credential_resolved");
        assert_eq!(event["tenant_id"], "acme");
        assert_eq!(event["data"]["op"], "resolve");
        assert_eq!(event["data"]["resource"], "credential");
        assert_eq!(event["data"]["id"], "cred-siem");
        assert_eq!(event["data"]["outcome"], "resolved");
        assert_eq!(event["data"]["source"], "envelope");
        assert!(
            !content.contains(secret_material),
            "resolved material must never reach the typed feed: {content}"
        );
        assert!(
            !content.contains("marker-value"),
            "resolved material must never reach the typed feed: {content}"
        );
    }

    /// WOR-2655, guarding the invariant the material projection
    /// threatens. `resolve_credential_material` is a projection of
    /// `resolve_credential_secret`, not a second resolution path, and
    /// the reason is here: a copied resolution body would publish a
    /// second `credential_resolved` for the same read, and a
    /// per-request AI fallback would then put one event on the SIEM
    /// feed per request instead of one per rotation.
    ///
    /// Red if the projection is ever reimplemented: two lines for one
    /// credential, or a cached second call that publishes. One egress
    /// install per process, which nextest's process-per-test model
    /// guarantees.
    #[tokio::test]
    async fn resolve_credential_material_publishes_exactly_one_event() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("credential-material-events.ndjson");
        let egress = sbproxy_observe::EventEgress::start(
            sbproxy_observe::EventSinkTarget::File { path: path.clone() },
            sbproxy_observe::EventTypeMask::from_types(&[
                sbproxy_observe::EventType::CredentialResolved,
            ]),
            64,
        )
        .expect("file egress starts");
        sbproxy_observe::install_event_egress(egress)
            .expect("this test's own event egress installs exactly once in its own process");

        let p = plane();
        let secret_material = "sk-house-material-that-must-not-cross";
        put(
            &p,
            credential(
                "cred-material-feed",
                CredentialMaterial::Plaintext {
                    value: secret_material.into(),
                },
            ),
        )
        .await;
        put(
            &p,
            credential(
                "cred-material-marker",
                CredentialMaterial::Plaintext {
                    value: "material-marker-value".into(),
                },
            ),
        )
        .await;

        assert_eq!(
            p.resolve_credential_material("cred-material-feed", None)
                .await
                .expect("resolves"),
            secret_material
        );
        // Ride the cache: this second call must publish nothing.
        p.resolve_credential_material("cred-material-feed", None)
            .await
            .expect("the cached credential resolves");
        // The marker resolves last, so once its event is on disk a
        // second event for the first credential had every chance.
        p.resolve_credential_material("cred-material-marker", None)
            .await
            .expect("the marker credential resolves");

        poll_events_file(&path, |line| line.contains("cred-material-marker"))
            .expect("the marker resolution must reach the egress");

        let content = std::fs::read_to_string(&path).expect("events file is readable");
        let lines: Vec<&str> = content
            .lines()
            .filter(|line| line.contains("cred-material-feed"))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "one actual resolution, one event; the projection must not add a second: {content}"
        );
        assert!(
            !content.contains(secret_material),
            "resolved material must never reach the typed feed: {content}"
        );
    }

    // --- The seam WOR-2571 and WOR-2572 share ---

    /// Neither ticket's own tests could reach this, because each was
    /// written against a tree without the other. WOR-2572 wraps the
    /// resolution in a metrics wrapper; WOR-2571 publishes typed events
    /// from two sites inside it; the two are deliberately different
    /// widths. One credential, one process, six claims:
    ///
    /// - a full resolution is `cache=miss outcome=ok` and publishes one
    ///   `credential_resolved` with `outcome: resolved`;
    /// - the per-request cached serve is `cache=hit outcome=ok` and
    ///   publishes nothing, which is the property a publish hoisted into
    ///   the wrapper would silently destroy, turning every request
    ///   carrying a bound credential into a SIEM event;
    /// - a grace-window serve is `cache=stale outcome=ok` and publishes
    ///   one `credential_resolved` with `outcome: stale_served`, which is
    ///   the property a wrapper that swallowed the closure's early return
    ///   would silently destroy in the other direction;
    /// - five serves inside one grace window are five histogram
    ///   observations and still one event, because the grace arm does not
    ///   re-stamp the entry, so without the episode gate every request
    ///   for the length of the window publishes;
    /// - a refusal (absent record, cross-tenant binding) is on the
    ///   histogram and publishes nothing at all, which is the half of the
    ///   contract a later "alert me when a revoked credential is still
    ///   being presented" change would quietly widen;
    /// - and no resolved material reaches the feed on any of them.
    ///
    /// One egress install per process, the same shape as the two tests
    /// above, which nextest's process-per-test model guarantees.
    #[tokio::test]
    async fn the_metrics_wrapper_and_the_typed_feed_agree_on_every_resolution_path() {
        let _serialized = ROTATION_TEST_LOCK.lock().await;
        invalidate_all_resolved_credentials();
        sbproxy_vault::reset_process_rotation_for_test();
        // A real re-resolve interval, so the second call is a cache hit.
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(
            300, 300,
        )));
        install_working_vault();

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("resolution-seam-events.ndjson");
        let egress = sbproxy_observe::EventEgress::start(
            sbproxy_observe::EventSinkTarget::File { path: path.clone() },
            sbproxy_observe::EventTypeMask::from_types(&[
                sbproxy_observe::EventType::CredentialResolved,
            ]),
            64,
        )
        .expect("file egress starts");
        sbproxy_observe::install_event_egress(egress)
            .expect("this test's own event egress installs exactly once in its own process");

        let p = vault_backed_plane().await;
        let before_miss_ok = resolution_count("miss", "ok");
        let before_hit_ok = resolution_count("hit", "ok");
        let before_stale_ok = resolution_count("stale", "ok");

        // A full resolution: the vault is read, so both instruments fire.
        p.resolve_credential_secret("rotating", None)
            .await
            .expect("the first resolution runs the full path");
        assert_eq!(
            resolution_count("miss", "ok"),
            before_miss_ok + 1,
            "the full path is one cache=miss outcome=ok observation"
        );

        // The cached serve: the metric fires, the feed must not.
        p.resolve_credential_secret("rotating", None)
            .await
            .expect("the second resolution is served from the resolved cache");
        assert_eq!(
            resolution_count("hit", "ok"),
            before_hit_ok + 1,
            "a cached serve is still observed, at cache=hit"
        );
        assert_eq!(
            resolution_count("miss", "ok"),
            before_miss_ok + 1,
            "a cached serve must not be counted as a fresh resolution"
        );

        // The grace window: the backend is gone, the last known-good
        // value is served, and both instruments fire on their own labels.
        sbproxy_vault::reset_process_rotation_for_test();
        sbproxy_vault::install_process_rotation(Arc::new(sbproxy_vault::RotationPolicy::new(
            0, 300,
        )));
        break_the_vault();
        p.resolve_credential_secret("rotating", None)
            .await
            .expect("grace serves the last known-good value");
        assert_eq!(
            resolution_count("stale", "ok"),
            before_stale_ok + 1,
            "a grace serve is cache=stale outcome=ok, never folded into hit"
        );

        // Still inside the same outage. The grace arm does not re-stamp
        // the entry, so each of these re-runs the full path, fails, and
        // falls back again: the shape that published one event per
        // request for the whole grace window before the episode gate.
        for _ in 0..4 {
            p.resolve_credential_secret("rotating", None)
                .await
                .expect("grace keeps serving the last known-good value");
        }
        assert_eq!(
            resolution_count("stale", "ok"),
            before_stale_ok + 5,
            "the histogram stays per serve: a rate is what an operator alerts on"
        );

        // The other half of the two-column contract, stated in this
        // function's return-path table and in `credential_resolved_event`'s
        // rustdoc and pinned nowhere until now: a refusal publishes
        // nothing on the feed. An absent record and a cross-tenant
        // binding are the two refusals reachable without the vault.
        let mut cross = credential(
            "seam-cross-tenant",
            CredentialMaterial::Plaintext {
                value: "seam-cross-tenant-value".into(),
            },
        );
        cross.tenant_id = Some("other-tenant".to_string());
        put(&p, cross).await;
        assert!(matches!(
            p.resolve_credential_secret("seam-no-such-credential", None)
                .await,
            Err(CredentialResolveError::NotFound)
        ));
        assert!(matches!(
            p.resolve_credential_secret("seam-cross-tenant", Some("acme"))
                .await,
            Err(CredentialResolveError::TenantMismatch)
        ));

        // A plaintext marker resolves without the vault, so once its
        // event is on disk every earlier publish had its chance to land.
        put(
            &p,
            credential(
                "seam-marker",
                CredentialMaterial::Plaintext {
                    value: "seam-marker-value".into(),
                },
            ),
        )
        .await;
        p.resolve_credential_secret("seam-marker", None)
            .await
            .expect("the marker credential resolves");
        poll_events_file(&path, |line| line.contains("seam-marker"))
            .expect("the marker resolution must reach the egress");

        let content = std::fs::read_to_string(&path).expect("events file is readable");
        let rotating: Vec<&str> = content
            .lines()
            .filter(|line| line.contains("\"rotating\""))
            .collect();
        assert_eq!(
            rotating.len(),
            2,
            "one fresh resolution and one grace-window episode, and nothing \
             at all from the cached serve between them or from the four \
             further requests inside the same episode: {content}"
        );
        assert_eq!(
            content.lines().count(),
            3,
            "two `rotating` events and the marker, and nothing from either \
             refusal: a resolution the plane refuses publishes nothing at \
             all on this feed: {content}"
        );

        let fresh: serde_json::Value =
            serde_json::from_str(rotating[0]).expect("the first event line parses");
        assert_eq!(fresh["event_type"], "credential_resolved");
        assert_eq!(fresh["data"]["outcome"], "resolved");
        assert_eq!(fresh["data"]["source"], "vault_ref");

        let stale: serde_json::Value =
            serde_json::from_str(rotating[1]).expect("the second event line parses");
        assert_eq!(stale["event_type"], "credential_resolved");
        assert_eq!(stale["data"]["outcome"], "stale_served");
        assert!(
            stale["data"].get("source").is_none(),
            "the grace serve read nothing fresh, so it must not claim a source: {stale}"
        );

        assert!(
            !content.contains("live-secret"),
            "resolved material must never reach the typed feed: {content}"
        );
        assert!(
            !content.contains("seam-marker-value"),
            "resolved material must never reach the typed feed: {content}"
        );
    }

    // --- WOR-2567: the rotation overlap on the resolution path ---

    /// The seam: when the material a rotation installed will not open,
    /// the material it replaced is presented instead, but only while the
    /// overlap window is open.
    ///
    /// The ordering is the safety property. A rotation that worked never
    /// reaches the previous material at all, which this test pins by
    /// resolving a record whose *current* material is good and asserting
    /// the current value comes back even though a usable previous one is
    /// sitting right there.
    #[tokio::test]
    async fn a_rotation_overlap_serves_the_previous_material_only_when_the_new_one_fails() {
        invalidate_all_resolved_credentials();
        let p = plane();

        // A working rotation: current material opens, so the overlap is
        // never consulted.
        let mut healthy = credential(
            "c-rot-ok",
            CredentialMaterial::Plaintext {
                value: "new-secret".into(),
            },
        );
        healthy.prev_material = Some(CredentialMaterial::Plaintext {
            value: "old-secret".into(),
        });
        healthy.prev_material_expires_at = Some(Utc::now() + chrono::Duration::seconds(300));
        put(&p, healthy).await;
        let resolved = p
            .resolve_credential_secret("c-rot-ok", None)
            .await
            .expect("the current material resolves");
        assert_eq!(
            resolved.material, "new-secret",
            "a rotation whose new material works must never present the retired one"
        );

        // A rotation whose new material will not open: the overlap
        // carries the request.
        invalidate_all_resolved_credentials();
        let mut broken = credential(
            "c-rot-fallback",
            // Sealed under a master this plane does not hold, which is
            // the shape of "the new material is not usable here".
            CredentialMaterial::Envelope {
                envelope: KeyCrypto::new(b"pep".to_vec(), b"another-master".to_vec())
                    .seal("c-rot-fallback", b"unopenable")
                    .expect("seal"),
            },
        );
        broken.prev_material = Some(CredentialMaterial::Plaintext {
            value: "still-good".into(),
        });
        broken.prev_material_expires_at = Some(Utc::now() + chrono::Duration::seconds(300));
        put(&p, broken.clone()).await;
        let resolved = p
            .resolve_credential_secret("c-rot-fallback", None)
            .await
            .expect("the overlap carries the request");
        assert_eq!(resolved.material, "still-good");

        // Once the window has closed, the same record fails rather than
        // presenting a retired secret indefinitely.
        invalidate_all_resolved_credentials();
        let mut expired = broken;
        expired.id = "c-rot-expired".to_string();
        expired.material = CredentialMaterial::Envelope {
            envelope: KeyCrypto::new(b"pep".to_vec(), b"another-master".to_vec())
                .seal("c-rot-expired", b"unopenable")
                .expect("seal"),
        };
        expired.prev_material_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        put(&p, expired).await;
        match p.resolve_credential_secret("c-rot-expired", None).await {
            Err(CredentialResolveError::Unresolvable(reason)) => {
                assert!(reason.contains("root of trust"), "{reason}");
            }
            other => panic!("a closed overlap window must not serve the old material: {other:?}"),
        }
    }

    /// A root of trust whose data keys carry a deliberately short remaining
    /// window, so a test can tell "inherited the deadline" from "started a
    /// fresh one" without waiting.
    #[derive(Debug)]
    struct ShortWindowRoot {
        window: std::time::Duration,
        remaining: std::time::Duration,
        unwraps: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl sbproxy_keystore::crypto::RootOfTrust for ShortWindowRoot {
        fn kek_name(&self) -> &str {
            "stub/short-window"
        }
        async fn wrap_dek(&self, dek: &[u8]) -> anyhow::Result<String> {
            Ok(format!("stub:v1:{}", hex::encode(dek)))
        }
        async fn unwrap_dek(
            &self,
            wrapped: &str,
        ) -> anyhow::Result<sbproxy_keystore::crypto::UnwrappedDek> {
            self.unwraps
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = wrapped
                .strip_prefix("stub:v1:")
                .ok_or_else(|| anyhow::anyhow!("not a stub ciphertext"))?;
            Ok(sbproxy_keystore::crypto::UnwrappedDek {
                dek: hex::decode(body)?,
                // The point: a data key most of whose window has already
                // been spent in the root's own cache.
                valid_for: self.remaining,
            })
        }
        fn revocation_window(&self) -> std::time::Duration {
            self.window
        }
        // The liveness five are required on the trait, so this double
        // states its trivial answers instead of inheriting them. It runs
        // no probe and holds no cache of its own, and it says the first
        // half out loud: `Ok(())` beside `last_liveness_ok() == false` is
        // a probe that succeeded and recorded nothing, which is the exact
        // wrong-trivial-answer shape whose removal from the trait was the
        // point of the round.
        async fn probe_liveness(&self) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("this double runs no probe"))
        }
        fn last_liveness_unix(&self) -> Option<u64> {
            None
        }
        fn last_liveness_ok(&self) -> bool {
            false
        }
        fn cached_dek_count(&self) -> usize {
            0
        }
        fn purge_cache(&self) {}
    }

    /// Seam G, replaced. The old test asserted `effective_hold(60, Some(5))
    /// == 5`, which proves `min` and nothing about the wiring, and the
    /// revocation bound is exactly what lived in that gap: two caches each
    /// clamped to the same window hold a secret for up to twice it.
    ///
    /// This drives the real `open_material` and asserts the ceiling it
    /// returns is the time *left* on the data key, not a fresh copy of the
    /// configured window. Reverting that line to
    /// `root.revocation_window()` reddens this and leaves the `min` unit
    /// test green, which is the difference between the two tests.
    #[tokio::test]
    async fn a_customer_managed_open_inherits_the_data_keys_remaining_window() {
        let root = Arc::new(ShortWindowRoot {
            window: std::time::Duration::from_secs(600),
            remaining: std::time::Duration::from_secs(7),
            unwraps: std::sync::atomic::AtomicUsize::new(0),
        });
        let crypto =
            KeyCrypto::new(b"pep".to_vec(), b"master".to_vec()).with_root_of_trust(root.clone());
        let store = Arc::new(MemoryKeyStore::new());
        let cache = Arc::new(TtlCache::new(
            store as Arc<dyn KeyStore>,
            TtlCacheConfig::default(),
        ));
        let plane = KeyPlane::from_parts(crypto, cache, false, false, None);

        let envelope = plane
            .crypto()
            .seal_async("cred-cmk-ceiling", b"upstream-secret")
            .await
            .expect("seal under the customer-managed root");
        assert!(
            envelope.kek.is_some(),
            "the envelope must name its root, or this test is not exercising the CMK path"
        );

        let (secret, source, ceiling) = plane
            .open_material(
                "cred-cmk-ceiling",
                &CredentialMaterial::Envelope { envelope },
            )
            .await
            .expect("opens through the external root");
        assert_eq!(secret, "upstream-secret");
        assert_eq!(source, "envelope");
        assert_eq!(
            ceiling,
            Some(std::time::Duration::from_secs(7)),
            "the ceiling must be the time left on the data key. Taking the configured window \
             here instead is how two caches clamped to W end up holding a secret for 2W, which \
             is the number the admin surface prints"
        );
        assert_ne!(
            ceiling,
            Some(std::time::Duration::from_secs(600)),
            "a fresh copy of the configured window is exactly the bug"
        );
    }

    /// The other half of the same seam: a locally-wrapped envelope is
    /// bounded by no external service, so it must carry no ceiling at all.
    /// Returning one would clamp a local deployment's cache to a window it
    /// never opted into.
    #[tokio::test]
    async fn a_locally_wrapped_envelope_carries_no_ceiling() {
        let plane = plane();
        let envelope = plane
            .crypto()
            .seal("cred-local-ceiling", b"local-secret")
            .expect("local seal");
        assert!(envelope.kek.is_none());
        let (secret, source, ceiling) = plane
            .open_material(
                "cred-local-ceiling",
                &CredentialMaterial::Envelope { envelope },
            )
            .await
            .expect("opens locally");
        assert_eq!(secret, "local-secret");
        assert_eq!(source, "envelope");
        assert_eq!(ceiling, None);
    }

    /// `ResolvedCredential` is the plaintext, not a handle to it: `value`
    /// is the whole header and `material` is the bare upstream secret.
    /// Nothing formats it today, which is the state every `Debug` leak in
    /// `scripts/secret-debug-registry.txt` was in the day before something
    /// did, and it is the type the customer-managed claim is about.
    ///
    /// Restoring `#[derive(Debug)]` reddens this on both fields.
    #[test]
    fn debug_never_renders_a_resolved_credential() {
        let rendered = format!(
            "{:?}",
            ResolvedCredential {
                header: "authorization".to_string(),
                value: "Bearer RESOLVEDMUSTNOTAPPEAR".to_string(),
                material: "RESOLVEDMUSTNOTAPPEAR".to_string(),
            }
        );
        assert!(
            !rendered.contains("RESOLVEDMUSTNOTAPPEAR"),
            "a resolved credential leaked its secret: {rendered}"
        );
        assert!(
            rendered.contains("ResolvedCredential") && rendered.contains("[REDACTED]"),
            "the identifier and the mask both have to survive, or a log line stops naming \
             what failed: {rendered}"
        );
        assert!(
            rendered.contains("authorization"),
            "the header name is not a secret and is what makes the line useful: {rendered}"
        );
    }

    /// A root of trust whose probe always fails, and which counts its own
    /// purges, so a test can assert the probe's failure arm rather than
    /// assert that a function it called by hand exists.
    #[derive(Debug)]
    struct FailingProbeRoot {
        window: std::time::Duration,
        purged: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl sbproxy_keystore::crypto::RootOfTrust for FailingProbeRoot {
        fn kek_name(&self) -> &str {
            "stub/failing-probe"
        }
        async fn wrap_dek(&self, dek: &[u8]) -> anyhow::Result<String> {
            Ok(format!("stub:v1:{}", hex::encode(dek)))
        }
        async fn unwrap_dek(
            &self,
            wrapped: &str,
        ) -> anyhow::Result<sbproxy_keystore::crypto::UnwrappedDek> {
            let body = wrapped
                .strip_prefix("stub:v1:")
                .ok_or_else(|| anyhow::anyhow!("not a stub ciphertext"))?;
            Ok(sbproxy_keystore::crypto::UnwrappedDek {
                dek: hex::decode(body)?,
                valid_for: self.window,
            })
        }
        fn revocation_window(&self) -> std::time::Duration {
            self.window
        }
        // The point of the double: the customer revoked, so the probe
        // fails. Everything else answers honestly.
        async fn probe_liveness(&self) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("grant revoked"))
        }
        fn last_liveness_unix(&self) -> Option<u64> {
            None
        }
        fn last_liveness_ok(&self) -> bool {
            false
        }
        fn cached_dek_count(&self) -> usize {
            0
        }
        fn purge_cache(&self) {
            self.purged
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The published clause "or at the next failed liveness probe,
    /// whichever comes first" has to be true of the cache the customer is
    /// actually testing, and false of the credentials that root never
    /// opened.
    ///
    /// `purge_cache` drops wrapped data keys. The resolved-credential
    /// cache holds credentials this process already decrypted and serves
    /// them upstream without consulting the root of trust at all, so
    /// purging only the first leaves a revoked deployment serving
    /// plaintext for its full inherited deadline while
    /// `GET /admin/crypto/root-of-trust` reports `cached_data_keys: 0`.
    /// Three published sentences and a runnable walkthrough are built on
    /// that clause.
    ///
    /// This test drives `key_root_of_trust::probe_once`, which is the
    /// real failure arm, with a root whose probe returns `Err`. The
    /// version it replaces called `invalidate_all_resolved_credentials()`
    /// by hand: that function was `pub` and pre-existing, so the test
    /// asserted something that already worked and deleting the line the
    /// whole round exists to add left it green.
    ///
    /// Two assertions, and the second is not decoration. A customer-managed
    /// entry must go, and a plaintext entry must **stay**: it is what
    /// `proxy.secrets.rotation`'s grace window serves stale from, the
    /// customer's root never opened it, and a Vault outage takes the
    /// Transit mount and the KV backend down together, so a global purge
    /// cancels the grace window at exactly the moment it is needed.
    #[tokio::test]
    async fn a_failed_liveness_probe_drops_the_credentials_the_root_opened() {
        let _guard = crate::key_plane::test_plane_guard();
        let root = Arc::new(FailingProbeRoot {
            window: std::time::Duration::from_secs(600),
            purged: std::sync::atomic::AtomicUsize::new(0),
        });
        let crypto =
            KeyCrypto::new(b"pep".to_vec(), b"master".to_vec()).with_root_of_trust(root.clone());
        let store = Arc::new(MemoryKeyStore::new());
        let cache = Arc::new(TtlCache::new(
            store as Arc<dyn KeyStore>,
            TtlCacheConfig::default(),
        ));
        let plane = Arc::new(KeyPlane::from_parts(crypto, cache, false, false, None));
        crate::key_plane::install_key_plane_for_test(plane.clone());

        // One credential the customer's root opened, and one it never
        // touched.
        let envelope = plane
            .crypto()
            .seal_async("cred-cmk", b"cmk-secret")
            .await
            .expect("seal under the customer-managed root");
        assert!(
            envelope.kek.is_some(),
            "the envelope must name its root, or this test is not exercising the CMK path"
        );
        put(
            &plane,
            credential("cred-cmk", CredentialMaterial::Envelope { envelope }),
        )
        .await;
        put(
            &plane,
            credential(
                "cred-plain",
                CredentialMaterial::Plaintext {
                    value: "local-secret".into(),
                },
            ),
        )
        .await;

        // Warm both through the real resolution path.
        assert_eq!(
            plane
                .resolve_credential_secret("cred-cmk", None)
                .await
                .expect("resolves through the root")
                .material,
            "cmk-secret"
        );
        assert_eq!(
            plane
                .resolve_credential_secret("cred-plain", None)
                .await
                .expect("resolves locally")
                .material,
            "local-secret"
        );
        assert_eq!(
            plane.resolved_credential_count(),
            2,
            "both entries must be warm, or this test proves nothing"
        );

        // The real arm, with a real failing probe behind it.
        let dyn_root: Arc<dyn sbproxy_keystore::crypto::RootOfTrust> = root.clone();
        crate::key_root_of_trust::probe_once(&dyn_root).await;

        assert_eq!(
            root.purged.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the failure arm must purge the wrapped data keys"
        );
        // By name, not by count, and not by re-resolving. A count of 1 is
        // equally true when the predicate is inverted and exactly the
        // wrong entry survives, and a re-resolve returns `Ok` either way
        // because a miss falls through to the store and rebuilds.
        assert!(
            !plane.resolved_credential_is_cached("cred-cmk"),
            "a failed probe must drop every credential the root opened. Purging only the \
             wrapped data keys leaves the credential the customer is testing being served from \
             a cache the probe never touched, which is the published clause being false"
        );
        assert!(
            plane.resolved_credential_is_cached("cred-plain"),
            "the plaintext entry must survive: the customer's root never opened it, it is what \
             the stale-serve grace window serves from during the same outage, and a Vault \
             outage takes the Transit mount and the KV backend down together"
        );
        assert_eq!(plane.resolved_credential_count(), 1);
    }

    /// Blocker 3's seam: a config-seeded `secret:` credential must still
    /// be created when a customer-managed root of trust is configured.
    ///
    /// `KeyCrypto::seal` refuses outright under a customer-managed root,
    /// deliberately, so that no call site can quietly produce a
    /// locally-wrapped envelope while the config claims a customer-held
    /// root. `lower_seed_credential` was left on that synchronous path
    /// when the admin path moved to `seal_async`, which turned the
    /// refusal into "every seeded credential is logged and skipped at
    /// boot": the boot succeeded, the records were simply absent, and the
    /// first symptom was a `NotFound` at request time.
    ///
    /// The existing seeding test cannot see this, because it runs with no
    /// root of trust, where `seal_async` falls through to the local seal
    /// and reverting it to `seal` is invisible. This one installs a root,
    /// so reverting `key_plane.rs`'s `seal_async` back to `seal` reddens
    /// it.
    #[tokio::test]
    async fn a_seeded_credential_survives_a_customer_managed_root() {
        let crypto = KeyCrypto::new(b"pep".to_vec(), b"master".to_vec())
            .with_root_of_trust(Arc::new(SeedStubRoot));
        let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());

        let mut cfg = sbproxy_config::types::KeyManagementConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.seed.credentials = vec![sbproxy_config::types::SeedCredentialConfig {
            id: "seed-cred".into(),
            name: None,
            provider: None,
            kind: None,
            vault_ref: None,
            secret: Some("sk-seeded".into()),
            tenant: None,
        }];

        seed_records(&store, &crypto, &cfg, Utc::now())
            .await
            .expect("seeding succeeds under a customer-managed root");

        let stored = store
            .get_credential("seed-cred")
            .await
            .expect("store read")
            .expect(
                "the seeded credential must exist. Under a customer-managed root the synchronous \
                 seal refuses, so a seed path still on it logs and skips every credential and the \
                 boot succeeds with the records simply absent",
            );
        match &stored.material {
            CredentialMaterial::Envelope { envelope } => assert_eq!(
                envelope.kek.as_deref(),
                Some("stub/seed-root"),
                "the seeded envelope must name the customer-managed root that wrapped it, not be \
                 locally wrapped behind its back"
            ),
            other => panic!("expected an envelope, got {other:?}"),
        }
    }

    /// A root of trust for the seeding test. Wrapping is reversible so the
    /// envelope is well formed; what matters is that it is reached at all.
    #[derive(Debug)]
    struct SeedStubRoot;

    #[async_trait::async_trait]
    impl sbproxy_keystore::crypto::RootOfTrust for SeedStubRoot {
        fn kek_name(&self) -> &str {
            "stub/seed-root"
        }
        async fn wrap_dek(&self, dek: &[u8]) -> anyhow::Result<String> {
            Ok(format!("stub:v1:{}", hex::encode(dek)))
        }
        async fn unwrap_dek(
            &self,
            wrapped: &str,
        ) -> anyhow::Result<sbproxy_keystore::crypto::UnwrappedDek> {
            let body = wrapped
                .strip_prefix("stub:v1:")
                .ok_or_else(|| anyhow::anyhow!("not a stub ciphertext"))?;
            Ok(sbproxy_keystore::crypto::UnwrappedDek {
                dek: hex::decode(body)?,
                valid_for: std::time::Duration::from_secs(60),
            })
        }
        fn revocation_window(&self) -> std::time::Duration {
            std::time::Duration::from_secs(60)
        }
        // Same reason as `ShortWindowRoot`: no defaults to inherit, so the
        // double writes down that it neither probes nor caches, and says
        // so with an `Err` that matches the `false` below it.
        async fn probe_liveness(&self) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("this double runs no probe"))
        }
        fn last_liveness_unix(&self) -> Option<u64> {
            None
        }
        fn last_liveness_ok(&self) -> bool {
            false
        }
        fn cached_dek_count(&self) -> usize {
            0
        }
        fn purge_cache(&self) {}
    }
}
