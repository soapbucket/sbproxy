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
use sbproxy_keystore::crypto::KeyCrypto;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCredential {
    /// Lowercase header name to set on the upstream request.
    pub header: String,
    /// Full header value, scheme prefix already applied.
    pub value: String,
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

type ResolvedCredentialCache =
    parking_lot::Mutex<std::collections::HashMap<String, (std::time::Instant, ResolvedCredential)>>;

/// Drop any cached resolved secret for `id`. Called from the admin mutation
/// path alongside the record-cache invalidation.
pub fn invalidate_resolved_credential(id: &str) {
    if let Some(plane) = current_key_plane() {
        plane.invalidate_resolved_credential(id);
    }
}

/// Drop every cached resolved secret.
pub fn invalidate_all_resolved_credentials() {
    if let Some(plane) = current_key_plane() {
        plane.invalidate_all_resolved_credentials();
    }
}

impl KeyPlane {
    /// Drop one resolved upstream secret from this plane generation.
    pub(crate) fn invalidate_resolved_credential(&self, id: &str) {
        self.resolved_credentials.lock().remove(id);
    }

    /// Drop every resolved upstream secret from this plane generation.
    pub(crate) fn invalidate_all_resolved_credentials(&self) {
        self.resolved_credentials.lock().clear();
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
        // hit, the typed feed carries only real reads and grace serves.
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
        result
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
    /// | grace window serves last known-good | `stale` / `ok` | `credential_resolved`, `outcome: stale_served` |
    /// | record absent | `miss` / `refused` | none |
    /// | record revoked or blocked | `miss` / `refused` | none |
    /// | credential bound across tenants | `miss` / `refused` | none |
    /// | store or vault down, no grace | `miss` / `error` | none |
    /// | full resolution succeeds | `miss` / `ok` | `credential_resolved`, `outcome: resolved` |
    ///
    /// The histogram is observed once per call by the wrapper, on every
    /// row. The typed feed carries only the two rows where material was
    /// actually read or served, which is why ordinary per-request
    /// traffic riding the cache publishes nothing at all.
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
        if let Some((at, value)) = &cached {
            if at.elapsed() < policy.re_resolve_interval() {
                *cache_layer = "hit";
                return Ok(value.clone());
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
                Some((at, value)) if at.elapsed() < policy.stale_serve_deadline() => {
                    *cache_layer = "stale";
                    tracing::warn!(
                        credential_id = %id,
                        error = %err,
                        age_secs = at.elapsed().as_secs(),
                        grace_secs = policy.grace_period().as_secs(),
                        "could not re-resolve a bound credential; serving the last known-good \
                         value for the remainder of proxy.secrets.rotation.grace_period_secs"
                    );
                    // WOR-2571: a stale serve is still an actual use of
                    // resolved material, and it is the one a SIEM most
                    // wants to see, because it means the backend was down
                    // and the credential kept working anyway. It sits
                    // inside the grace arm, next to WOR-2572's
                    // `cache_layer = "stale"`, so the two instrumentations
                    // describe exactly the same set of serves: every
                    // `cache=stale` observation has one `stale_served`
                    // event and no other path publishes one.
                    sbproxy_observe::publish_proxy_event(
                        sbproxy_observe::EventType::CredentialResolved,
                        || credential_resolved_event(id, tenant_id, "stale_served", None),
                    );
                    Ok(value.clone())
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
        if record.tenant_id.is_some() && record.tenant_id.as_deref() != tenant_id {
            return Err(CredentialResolveError::TenantMismatch);
        }

        // WOR-2571: named before the material is opened so the typed
        // event below can say where fresh material came from without
        // holding anything secret.
        let source = match &record.material {
            CredentialMaterial::Plaintext { .. } => "plaintext",
            CredentialMaterial::Envelope { .. } => "envelope",
            CredentialMaterial::VaultRef { .. } => "vault_ref",
        };
        let secret = match &record.material {
            CredentialMaterial::Plaintext { value } => value.clone(),
            CredentialMaterial::Envelope { envelope } => {
                let bytes = self.crypto().open(&record.id, envelope).map_err(|e| {
                    // Distinct message: after a master-key rotation every
                    // existing envelope stops opening, and that is otherwise
                    // very hard to tell apart from a corrupt store.
                    CredentialResolveError::Unresolvable(format!(
                        "envelope did not open under the configured master key: {e}"
                    ))
                })?;
                String::from_utf8(bytes).map_err(|_| {
                    CredentialResolveError::Unresolvable("secret is not utf-8".to_string())
                })?
            }
            CredentialMaterial::VaultRef { reference } => {
                let Some(resolver) = sbproxy_vault::process_resolver() else {
                    // A missing resolver is a config fault, not an
                    // outage, so grace does not apply: it will not fix
                    // itself and serving a stale value would hide it.
                    return Err(CredentialResolveError::Unresolvable(
                        "no secret resolver is installed for a vault-referenced credential"
                            .to_string(),
                    ));
                };
                // The case grace exists for. Everything above this point
                // reads local state; this is the network round-trip to the
                // secret backend, so this is where a vault blip turns a
                // working deployment into 503s.
                match resolver.resolve_async(reference.clone()).await {
                    Ok(secret) => secret,
                    Err(e) => {
                        return serve_stale_on_failure(
                            cache_layer,
                            CredentialResolveError::Unresolvable(e.to_string()),
                        )
                    }
                }
            }
        };

        let resolved = ResolvedCredential {
            header: record.header.trim().to_ascii_lowercase(),
            value: format!("{}{}", record.scheme, secret),
        };
        self.resolved_credentials.lock().insert(
            id.to_string(),
            (std::time::Instant::now(), resolved.clone()),
        );
        // WOR-2571: one typed event per actual resolution. The cached
        // fast path above returns before this point, so a request that
        // rode the cache publishes nothing; see
        // [`credential_resolved_event`] for the cardinality ruling.
        sbproxy_observe::publish_proxy_event(
            sbproxy_observe::EventType::CredentialResolved,
            || credential_resolved_event(id, tenant_id, "resolved", Some(source)),
        );
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
/// where fresh material came from (`plaintext`, `envelope`,
/// `vault_ref`) and is absent on the stale path, where nothing was
/// freshly read. The per-request cache hit publishes nothing: this
/// event marks material actually being read, not every request that
/// rode the cached value, the same cardinality ruling that keeps
/// `cache_hit` unwired on the typed feed. Resolution refusals publish
/// nothing here either; the refusal surface is WOR-2567's.
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

/// Build the `KeyCrypto` handle from config, generating ephemeral secrets
/// with a warning when the operator did not pin them.
fn build_crypto(cfg: &KeyManagementConfig) -> Result<KeyCrypto> {
    let pepper = match &cfg.crypto.pepper {
        Some(r) => resolve_secret_material(r)?,
        None => {
            tracing::warn!(
                "key_management.crypto.pepper is unset; generating an ephemeral pepper. \
                 Stored key hashes will not survive a restart or successful config reload. \
                 Set a stable pepper in production."
            );
            sbproxy_security::random_aes256_key().to_vec()
        }
    };
    let master = match &cfg.crypto.master_key {
        Some(r) => resolve_secret_material(r)?,
        None => {
            tracing::warn!(
                "key_management.crypto.master_key is unset; generating an ephemeral master key. \
                 Encrypted upstream credentials will not be decryptable after a restart or \
                 successful config reload."
            );
            sbproxy_security::random_aes256_key().to_vec()
        }
    };
    // WOR-2478: derive the key-audit chain's fingerprint key from this same
    // master secret, under a dedicated HKDF purpose, before `master` moves
    // into the `KeyCrypto` handle below. `sbproxy-observe` never sees the
    // master key itself, only the 32 bytes this call derives from it and
    // retains; see that function's docs for why a later call (a hot
    // reload) does not replace an already-installed key.
    sbproxy_observe::audit_chain::install_key_audit_fingerprint_key(&master);
    Ok(KeyCrypto::new(pepper, master))
}

/// Build the configured store backend: embedded (redb), Redis, or
/// secrets-manager-direct (HashiCorp / AWS / local, via the writable vault
/// backends).
fn build_store(cfg: &KeyManagementConfig) -> Result<Arc<dyn KeyStore>> {
    match cfg.store.backend {
        KeyStoreBackend::Embedded => {
            if let Some(parent) = std::path::Path::new(&cfg.store.path).parent() {
                std::fs::create_dir_all(parent)
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
/// inline secret under the master key.
fn lower_seed_credential(
    seed: &SeedCredentialConfig,
    crypto: &KeyCrypto,
    now: DateTime<Utc>,
) -> Option<CredentialRecord> {
    let material = if let Some(reference) = &seed.vault_ref {
        CredentialMaterial::VaultRef {
            reference: reference.clone(),
        }
    } else if let Some(secret) = &seed.secret {
        match crypto.seal(&seed.id, secret.as_bytes()) {
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
        if let Some(rec) = lower_seed_credential(seed, crypto, now) {
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
        .with_inbound(cfg.inbound.clone()),
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
                assert!(reason.contains("master key"), "{reason}");
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
        p.cache().invalidate("c6").await;
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
        p.cache().invalidate("rotating").await;
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

    // --- The seam WOR-2571 and WOR-2572 share ---

    /// Neither ticket's own tests could reach this, because each was
    /// written against a tree without the other. WOR-2572 wraps the
    /// resolution in a metrics wrapper; WOR-2571 publishes typed events
    /// from two sites inside it; the two are deliberately different
    /// widths. One credential, one process, four claims:
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
            "one fresh resolution and one grace serve, and nothing at all \
             from the cached serve between them: {content}"
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
}
