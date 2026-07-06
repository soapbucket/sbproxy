//! WOR-1546: assembly and process-global handle for the dynamic key plane.
//!
//! The `key_management:` config block is lowered here into a live `KeyPlane`:
//! a `KeyCrypto` handle (pepper + master), a `KeyStore` backend, and a
//! fail-closed `TtlCache` in front of it. The plane is held in a global
//! `ArcSwapOption` (like the rate-limit registry and the compiled pipeline) so
//! the auth dispatch and the admin API resolve against one shared instance.
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
use sbproxy_config::types::{
    KeyCacheTier, KeyManagementConfig, KeyStoreBackend, MeshClusterConfig, SeedCredentialConfig,
    SeedKeyConfig,
};
use sbproxy_keystore::crypto::KeyCrypto;
use sbproxy_keystore::record::{
    CredentialMaterial, CredentialRecord, KeyRecord, RecordBudget, RecordSource, RecordStatus,
};
use sbproxy_keystore::{EmbeddedKeyStore, KeyStore, TtlCache, TtlCacheConfig};
use sbproxy_mesh::bootstrap::{bootstrap, BootstrapConfig, PeerTlsParams};
use sbproxy_mesh::discovery::{seeds::SeedDiscovery, Discovery};
use sbproxy_mesh::MeshNode;

/// The live, installed key plane.
pub struct KeyPlane {
    crypto: KeyCrypto,
    cache: Arc<TtlCache>,
    failure_mode_allow: bool,
    allow_api_override: bool,
    oidc_claim_field: Option<String>,
}

impl KeyPlane {
    /// Assemble a plane from already-built parts. Used by the config-driven
    /// [`init_key_plane`] and by tests that wire a store directly.
    pub(crate) fn from_parts(
        crypto: KeyCrypto,
        cache: Arc<TtlCache>,
        failure_mode_allow: bool,
        allow_api_override: bool,
        oidc_claim_field: Option<String>,
    ) -> Self {
        Self {
            crypto,
            cache,
            failure_mode_allow,
            allow_api_override,
            oidc_claim_field,
        }
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

    /// When true, a store outage allows the request through (degraded) instead
    /// of denying. Default false.
    pub fn failure_mode_allow(&self) -> bool {
        self.failure_mode_allow
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

/// Install (or replace) the live key plane.
pub fn install_key_plane(plane: Arc<KeyPlane>) {
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

/// Resolve a crypto secret reference into raw bytes. Supports `env:NAME`,
/// `file:PATH`, and inline values. Vault scheme references are not resolved
/// here; use `env:`/`file:` to point at a vault-injected value.
fn resolve_secret_material(reference: &str) -> Result<Vec<u8>> {
    if let Some(name) = reference.strip_prefix("env:") {
        return Ok(std::env::var(name)
            .with_context(|| format!("environment variable '{name}' for key crypto"))?
            .into_bytes());
    }
    if let Some(path) = reference.strip_prefix("file:") {
        return std::fs::read(path).with_context(|| format!("read crypto material file '{path}'"));
    }
    Ok(reference.as_bytes().to_vec())
}

/// Build the `KeyCrypto` handle from config, generating ephemeral secrets
/// with a warning when the operator did not pin them.
fn build_crypto(cfg: &KeyManagementConfig) -> Result<KeyCrypto> {
    let pepper = match &cfg.crypto.pepper {
        Some(r) => resolve_secret_material(r)?,
        None => {
            tracing::warn!(
                "key_management.crypto.pepper is unset; generating an ephemeral pepper. \
                 Stored key hashes will not survive a restart. Set a stable pepper in production."
            );
            sbproxy_security::random_aes256_key().to_vec()
        }
    };
    let master = match &cfg.crypto.master_key {
        Some(r) => resolve_secret_material(r)?,
        None => {
            tracing::warn!(
                "key_management.crypto.master_key is unset; generating an ephemeral master key. \
                 Encrypted upstream credentials will not be decryptable after a restart."
            );
            sbproxy_security::random_aes256_key().to_vec()
        }
    };
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
            let store = EmbeddedKeyStore::open(&cfg.store.path)
                .with_context(|| format!("open embedded keystore at '{}'", cfg.store.path))?;
            Ok(Arc::new(store))
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
    let cache_cfg = TtlCacheConfig {
        ttl: std::time::Duration::from_secs(cfg.cache.ttl_secs),
        negative_ttl: std::time::Duration::from_secs(cfg.cache.negative_ttl_secs),
        max_entries: cfg.cache.max_entries,
        fail_closed: !cfg.failure_mode_allow,
    };
    let mut cache = TtlCache::new(store, cache_cfg);
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
            // When a mesh cluster was bootstrapped (seeds configured), route
            // through it so the cache is coherent across the fleet; otherwise a
            // single-node standalone cache. Node id defaults to the hostname.
            let node_id = cfg
                .cache
                .mesh_node_id
                .clone()
                .unwrap_or_else(default_node_id);
            let tier: Arc<dyn sbproxy_keystore::CacheTier> = if let Some(node) = current_mesh_node()
            {
                Arc::new(crate::mesh_cache::MeshCacheTier::clustered(node))
            } else {
                Arc::new(crate::mesh_cache::MeshCacheTier::standalone(&node_id))
            };
            cache = cache.with_tier(tier);
        }
    }
    Arc::new(cache)
}

/// Process-global handle to the bootstrapped mesh node (gossip + transport),
/// kept alive for the process lifetime so its background tasks run. Set once; a
/// reload does not re-bootstrap, since cluster membership is stable across
/// config reloads.
fn mesh_node_slot() -> &'static OnceLock<MeshNode> {
    static SLOT: OnceLock<MeshNode> = OnceLock::new();
    &SLOT
}

/// The bootstrapped mesh node, if the mesh cache tier is clustered.
pub(crate) fn current_mesh_node() -> Option<&'static MeshNode> {
    mesh_node_slot().get()
}

/// Bootstrap and install the mesh node for the cache tier, once. Joins the seed
/// peers, binds gossip + transport, and runs the background tasks on the key
/// runtime. A no-op if already bootstrapped.
fn ensure_mesh_node(node_id: &str, mc: &MeshClusterConfig) -> Result<()> {
    if mesh_node_slot().get().is_some() {
        return Ok(());
    }
    let shared_key = match &mc.shared_key {
        Some(r) => Some(
            String::from_utf8(resolve_secret_material(r)?)
                .context("mesh shared_key must be valid UTF-8")?,
        ),
        None => None,
    };
    let discoveries: Vec<Box<dyn Discovery>> = vec![Box::new(SeedDiscovery::new(mc.seeds.clone()))];
    // Peer mTLS: read the configured cert/key/CA into PEM (fail-closed on a
    // read error) so the bootstrap can build the rustls acceptor/connector.
    let peer_tls = match &mc.peer_tls {
        Some(t) => Some(PeerTlsParams {
            tls: sbproxy_mesh::transport::tls::MeshTlsConfig {
                cert_pem: std::fs::read_to_string(&t.cert_file)
                    .with_context(|| format!("read mesh peer_tls cert_file '{}'", t.cert_file))?,
                key_pem: std::fs::read_to_string(&t.key_file)
                    .with_context(|| format!("read mesh peer_tls key_file '{}'", t.key_file))?,
                ca_pem: std::fs::read_to_string(&t.ca_file)
                    .with_context(|| format!("read mesh peer_tls ca_file '{}'", t.ca_file))?,
            },
            server_name: t.server_name.clone(),
        }),
        None => None,
    };
    let boot = BootstrapConfig {
        gossip_port: mc.gossip_port,
        transport_port: mc.transport_port,
        shared_key,
        peer_tls,
        ..Default::default()
    };
    let node_id = node_id.to_string();
    // Bootstrap on the dedicated key runtime via a fresh thread (block_on is
    // safe off any runtime), so the gossip + transport tasks live on the key
    // runtime for the process lifetime.
    let node = std::thread::scope(|scope| {
        scope
            .spawn(|| key_runtime().block_on(bootstrap(&discoveries, &boot, node_id)))
            .join()
            .expect("mesh bootstrap thread panicked")
    })
    .context("bootstrap mesh cluster")?;
    let _ = mesh_node_slot().set(node);
    Ok(())
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
    if seed.max_budget_tokens.is_some() || seed.max_budget_usd.is_some() {
        rec.budget = Some(RecordBudget {
            max_tokens: seed.max_budget_tokens,
            max_cost_usd: seed.max_budget_usd,
        });
    }
    rec.allowed_models = seed.allowed_models.clone();
    rec.blocked_models = seed.blocked_models.clone();
    rec.allowed_providers = seed.allowed_providers.clone();
    rec.require_pii_redaction = seed.require_pii_redaction.clone();
    rec.principal_selectors = seed.principal_selectors.clone();
    rec.route_to_model = seed.route_to_model.clone();
    rec.inject_tools = seed.inject_tools.clone();
    rec.bypass_prompt_injection = seed.bypass_prompt_injection;
    rec.project = seed.project.clone();
    rec.user = seed.user.clone();
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

/// Build, seed, and install the key plane from config. Idempotent across
/// reloads: re-seeds config records and replaces the installed plane. A no-op
/// when the block is disabled.
///
/// Synchronous: runs async seeding on the dedicated key runtime and returns once
/// the seed is applied, so seeded keys are usable as soon as the server accepts
/// traffic.
pub fn init_key_plane(cfg: &KeyManagementConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    let crypto = build_crypto(cfg)?;
    let store = build_store(cfg)?;
    // Bootstrap the mesh cluster before building the cache so the mesh tier can
    // route through it. A bootstrap failure logs and falls back to single-node.
    if cfg.cache.tier == KeyCacheTier::Mesh {
        if let Some(mc) = &cfg.cache.mesh {
            let node_id = cfg
                .cache
                .mesh_node_id
                .clone()
                .unwrap_or_else(default_node_id);
            if let Err(e) = ensure_mesh_node(&node_id, mc) {
                tracing::error!(error = %e, "failed to bootstrap mesh cluster for the key cache tier; using single-node");
            }
        }
    }
    let cache = build_cache(cfg, store.clone());

    let now = Utc::now();
    // Seed on a fresh thread driving the dedicated key runtime. A fresh thread
    // is never already inside a runtime, so `block_on` is safe whether
    // `init_key_plane` is called at boot (no runtime) or on reload (which may
    // run on a tokio worker, where a nested `block_on` would otherwise panic).
    std::thread::scope(|scope| {
        scope
            .spawn(|| key_runtime().block_on(seed_records(&store, &crypto, cfg, now)))
            .join()
            .expect("key-plane seed thread panicked")
    })
    .context("seed key_management records")?;

    let plane = Arc::new(KeyPlane::from_parts(
        crypto,
        cache.clone(),
        cfg.failure_mode_allow,
        cfg.allow_api_override,
        cfg.oidc_claim_map.as_ref().map(|m| m.claim_field.clone()),
    ));
    install_key_plane(plane);

    // WOR-1563: with the mesh tier, install cross-replica per-key spend + rate
    // counters (CRDTs coherent across the fleet via gossip).
    if cfg.cache.tier == KeyCacheTier::Mesh {
        let node_id = cfg
            .cache
            .mesh_node_id
            .clone()
            .unwrap_or_else(default_node_id);
        crate::mesh_counters::install_mesh_counters(Arc::new(
            crate::mesh_counters::MeshKeyCounters::new(node_id),
        ));
    }

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
    use sbproxy_config::types::{
        KeyCryptoConfig, KeySeedConfig, KeyStoreConfig, SecretsManagerProvider,
        SecretsManagerStoreConfig,
    };

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

    #[test]
    fn init_seeds_keys_and_credentials_into_embedded_store() {
        let _guard = test_plane_guard();
        let path = temp_db();
        let mut cfg = base_cfg(&path);
        cfg.seed = KeySeedConfig {
            keys: vec![SeedKeyConfig {
                key_id: "seed1".into(),
                secret: Some("s3cr3t".into()),
                secret_hash: None,
                name: Some("seeded".into()),
                max_requests_per_minute: Some(10),
                max_tokens_per_minute: None,
                max_budget_tokens: Some(1000),
                max_budget_usd: None,
                allowed_models: vec![],
                blocked_models: vec![],
                allowed_providers: vec![],
                require_pii_redaction: vec![],
                principal_selectors: vec![],
                route_to_model: None,
                inject_tools: vec![],
                bypass_prompt_injection: false,
                project: None,
                user: None,
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

        // The seeded key resolves and verifies the seeded secret.
        let rec = key_runtime()
            .block_on(plane.cache().resolve_key("seed1"))
            .unwrap()
            .expect("seeded key present");
        assert_eq!(rec.name.as_deref(), Some("seeded"));
        assert_eq!(rec.max_requests_per_minute, Some(10));
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
                max_budget_tokens: None,
                max_budget_usd: None,
                allowed_models: vec![],
                blocked_models: vec![],
                allowed_providers: vec![],
                require_pii_redaction: vec![],
                principal_selectors: vec![],
                route_to_model: None,
                inject_tools: vec![],
                bypass_prompt_injection: false,
                project: None,
                user: None,
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
}
