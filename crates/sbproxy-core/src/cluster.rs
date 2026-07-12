//! Process ownership for the shared local or distributed cluster handle.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sbproxy_config::{
    ClusterConfigSource, ClusterRestartFingerprint, ClusterRole, EffectiveClusterConfig,
    EffectiveClusterSecurity, ProxyServerConfig,
};
use sbproxy_mesh::bootstrap::{BootstrapConfig, PeerTlsParams};
use sbproxy_mesh::discovery::{seeds::SeedDiscovery, Discovery};
use sbproxy_mesh::enrollment::EnrollmentAuthority;
use sbproxy_mesh::{ClusterHandle, ClusterIdentity, ClusterNodeRole};

const LOCAL_CLUSTER_ID: &str = "local";
const DEFAULT_SNAPSHOT_TTL_SECS: u64 = 30;
const DEFAULT_PUBLISH_INTERVAL_SECS: u64 = 5;

/// Injectable boundary used to construct the one distributed handle.
pub trait ClusterBootstrap: Send + Sync {
    /// Bootstrap a mesh for one completely validated identity and config.
    fn bootstrap(
        &self,
        identity: ClusterIdentity,
        config: &EffectiveClusterConfig,
    ) -> Result<ClusterHandle>;
}

/// Reloadable settings that do not replace process identity or listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterSettings {
    /// Node snapshot lifetime.
    pub snapshot_ttl_secs: u64,
    /// Node snapshot publication cadence.
    pub publish_interval_secs: u64,
    /// Whether configuration requested a distributed cluster.
    pub distributed_requested: bool,
}

struct ReloadableClusterSettings {
    snapshot_ttl_secs: AtomicU64,
    publish_interval_secs: AtomicU64,
    distributed_requested: bool,
}

struct SnapshotPublicationState {
    enabled: bool,
    generation_directory: Option<PathBuf>,
    ephemeral_generation: AtomicU64,
    last_success_unix_ms: AtomicU64,
    publish_lock: Arc<tokio::sync::Mutex<()>>,
}

impl SnapshotPublicationState {
    fn new(enabled: bool, generation_directory: Option<PathBuf>) -> Self {
        Self {
            enabled,
            generation_directory,
            ephemeral_generation: AtomicU64::new(0),
            last_success_unix_ms: AtomicU64::new(0),
            publish_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn next_generation(&self) -> Result<u64> {
        if let Some(directory) = self.generation_directory.as_ref() {
            return sbproxy_model_host::node_snapshot::NodeSnapshotGeneration::open(directory)
                .context("open durable node snapshot generation")?
                .next()
                .context("reserve durable node snapshot generation");
        }
        self.ephemeral_generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |generation| {
                generation.checked_add(1)
            })
            .map(|generation| generation + 1)
            .map_err(|_| anyhow::anyhow!("node snapshot generation overflowed"))
    }
}

impl ReloadableClusterSettings {
    fn new(settings: ClusterSettings) -> Self {
        Self {
            snapshot_ttl_secs: AtomicU64::new(settings.snapshot_ttl_secs),
            publish_interval_secs: AtomicU64::new(settings.publish_interval_secs),
            distributed_requested: settings.distributed_requested,
        }
    }

    fn update(&self, settings: ClusterSettings) {
        self.snapshot_ttl_secs
            .store(settings.snapshot_ttl_secs, Ordering::SeqCst);
        self.publish_interval_secs
            .store(settings.publish_interval_secs, Ordering::SeqCst);
    }

    fn snapshot(&self) -> ClusterSettings {
        ClusterSettings {
            snapshot_ttl_secs: self.snapshot_ttl_secs.load(Ordering::SeqCst),
            publish_interval_secs: self.publish_interval_secs.load(Ordering::SeqCst),
            distributed_requested: self.distributed_requested,
        }
    }
}

struct InstalledCluster {
    handle: ClusterHandle,
    enrollment_authority: Option<Arc<EnrollmentAuthority>>,
    restart_fingerprint: Option<ClusterRestartFingerprint>,
    settings: Arc<ReloadableClusterSettings>,
    snapshot_publication: Arc<SnapshotPublicationState>,
}

/// Exclusive publication reservation for one node model snapshot.
pub struct NodeSnapshotPublication {
    handle: ClusterHandle,
    state: Arc<SnapshotPublicationState>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
    generation: u64,
    published_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl std::fmt::Debug for NodeSnapshotPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeSnapshotPublication")
            .field("node_id", &self.handle.identity().node_id)
            .field("generation", &self.generation)
            .field("published_at_unix_ms", &self.published_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}

impl NodeSnapshotPublication {
    /// Installed cluster identity that owns this publication.
    pub fn identity(&self) -> &ClusterIdentity {
        self.handle.identity()
    }

    /// Reserved monotonic generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Snapshot publication time in Unix milliseconds.
    pub const fn published_at_unix_ms(&self) -> u64 {
        self.published_at_unix_ms
    }

    /// Snapshot expiry time in Unix milliseconds.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Validate and publish the exact reserved snapshot into typed cluster state.
    pub async fn publish(
        self,
        snapshot: sbproxy_model_host::node_snapshot::NodeModelSnapshot,
    ) -> Result<()> {
        if snapshot.node.node_id != self.handle.identity().node_id
            || snapshot.generation != self.generation
            || snapshot.published_at_unix_ms != self.published_at_unix_ms
            || snapshot.expires_at_unix_ms != self.expires_at_unix_ms
        {
            anyhow::bail!("node snapshot does not match its publication reservation");
        }
        snapshot
            .to_json()
            .context("validate node snapshot publication")?;
        if unix_time_ms()? >= self.expires_at_unix_ms {
            anyhow::bail!("node snapshot expired before publication completed");
        }
        let ttl_ms = self
            .expires_at_unix_ms
            .checked_sub(self.published_at_unix_ms)
            .ok_or_else(|| anyhow::anyhow!("node snapshot publication expiry underflowed"))?;
        self.handle
            .publish_state(
                sbproxy_model_host::node_snapshot::NODE_MODEL_SNAPSHOT_NAMESPACE,
                &snapshot.node.node_id,
                sbproxy_model_host::node_snapshot::NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
                snapshot.generation,
                Duration::from_millis(ttl_ms),
                &snapshot,
            )
            .await
            .context("publish node model snapshot")?;
        self.state
            .last_success_unix_ms
            .store(self.published_at_unix_ms, Ordering::SeqCst);
        Ok(())
    }
}

/// Serialized owner that installs once and validates later reloads.
pub struct ClusterOwner {
    bootstrap: Arc<dyn ClusterBootstrap>,
    installed: Mutex<Option<InstalledCluster>>,
}

impl std::fmt::Debug for ClusterOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClusterOwner")
            .finish_non_exhaustive()
    }
}

impl ClusterOwner {
    /// Create an owner around an injected bootstrap implementation.
    pub fn new(bootstrap: Arc<dyn ClusterBootstrap>) -> Self {
        Self {
            bootstrap,
            installed: Mutex::new(None),
        }
    }

    /// Install the first handle or validate and apply a reloadable cadence.
    pub fn reconcile(&self, server: &ProxyServerConfig) -> Result<ClusterHandle> {
        let effective = sbproxy_config::resolve_effective_cluster(server)
            .context("resolve effective cluster configuration")?
            .map(resolve_legacy_node_id);
        let (identity, fingerprint, settings) = desired_installation(effective.as_ref())?;

        let mut installed = self
            .installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(current) = installed.as_ref() {
            if current.restart_fingerprint != fingerprint {
                anyhow::bail!(
                    "cluster identity, roles, labels, discovery, listeners, endpoints, or peer security changed; restart sbproxy to apply the new process-owned cluster configuration"
                );
            }
            current.settings.update(settings);
            return Ok(current.handle.clone());
        }

        let enrollment_authority = effective
            .as_ref()
            .and_then(|config| {
                config
                    .enrollment
                    .as_ref()
                    .map(|enrollment| (config, enrollment))
            })
            .map(|(config, enrollment)| {
                let authority = EnrollmentAuthority::open(&enrollment.authority_dir)
                    .context("open configured cluster enrollment authority")?;
                validate_authority_identity(&authority, &identity, &config.security)?;
                Ok::<_, anyhow::Error>(Arc::new(authority))
            })
            .transpose()?;
        let handle = match effective.as_ref() {
            None => ClusterHandle::local(identity).map_err(anyhow::Error::from)?,
            Some(config) => match self.bootstrap.bootstrap(identity.clone(), config) {
                Ok(handle) => handle,
                Err(error) if config.source == ClusterConfigSource::LegacyMesh => {
                    tracing::error!(
                        %error,
                        "legacy key-cache mesh bootstrap failed; retaining local compatibility fallback"
                    );
                    ClusterHandle::local(identity).map_err(anyhow::Error::from)?
                }
                Err(error) => {
                    anyhow::bail!("bootstrap canonical proxy.cluster: {error:#}");
                }
            },
        };
        let snapshot_publication = Arc::new(SnapshotPublicationState::new(
            model_snapshot_publication_enabled(effective.as_ref()),
            snapshot_generation_directory(effective.as_ref()),
        ));
        *installed = Some(InstalledCluster {
            handle: handle.clone(),
            enrollment_authority,
            restart_fingerprint: fingerprint,
            settings: Arc::new(ReloadableClusterSettings::new(settings)),
            snapshot_publication,
        });
        Ok(handle)
    }

    /// Currently installed handle, if initial reconciliation completed.
    pub fn current(&self) -> Option<ClusterHandle> {
        self.installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|installed| installed.handle.clone())
    }

    /// Current reloadable settings, if installed.
    pub fn settings(&self) -> Option<ClusterSettings> {
        self.installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|installed| installed.settings.snapshot())
    }

    /// Configured enrollment authority, only on an authority node.
    pub fn enrollment_authority(&self) -> Option<Arc<EnrollmentAuthority>> {
        self.installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(|installed| installed.enrollment_authority.clone())
    }

    /// Reserve a due node-snapshot generation and hold publication serialization.
    pub async fn begin_node_snapshot_publication(
        &self,
        force: bool,
    ) -> Result<Option<NodeSnapshotPublication>> {
        let Some((handle, settings, state)) = self
            .installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|installed| {
                (
                    installed.handle.clone(),
                    Arc::clone(&installed.settings),
                    Arc::clone(&installed.snapshot_publication),
                )
            })
        else {
            return Ok(None);
        };
        if !state.enabled {
            return Ok(None);
        }
        let guard = Arc::clone(&state.publish_lock).lock_owned().await;
        let now = unix_time_ms()?;
        let cadence_ms = settings
            .publish_interval_secs
            .load(Ordering::SeqCst)
            .checked_mul(1_000)
            .ok_or_else(|| anyhow::anyhow!("node snapshot cadence overflowed"))?;
        let last_success = state.last_success_unix_ms.load(Ordering::SeqCst);
        if !force && last_success != 0 && now.saturating_sub(last_success) < cadence_ms {
            return Ok(None);
        }
        let ttl_ms = settings
            .snapshot_ttl_secs
            .load(Ordering::SeqCst)
            .checked_mul(1_000)
            .ok_or_else(|| anyhow::anyhow!("node snapshot TTL overflowed"))?;
        let expires_at_unix_ms = now
            .checked_add(ttl_ms)
            .ok_or_else(|| anyhow::anyhow!("node snapshot expiry overflowed"))?;
        let generation = state.next_generation()?;
        Ok(Some(NodeSnapshotPublication {
            handle,
            state,
            _guard: guard,
            generation,
            published_at_unix_ms: now,
            expires_at_unix_ms,
        }))
    }
}

fn model_snapshot_publication_enabled(config: Option<&EffectiveClusterConfig>) -> bool {
    config.is_some_and(|config| {
        config.source != ClusterConfigSource::LegacyMesh
            && config.roles.contains(&ClusterRole::Worker)
    })
}

fn snapshot_generation_directory(config: Option<&EffectiveClusterConfig>) -> Option<PathBuf> {
    let config = config?;
    if let Some(state_dir) = config.state_dir.as_ref() {
        return Some(PathBuf::from(state_dir));
    }
    if let Some(enrollment) = config.enrollment.as_ref() {
        return Some(PathBuf::from(&enrollment.authority_dir));
    }
    match &config.security {
        EffectiveClusterSecurity::Mtls { cert_file, .. } => Some(
            Path::new(cert_file)
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        ),
        EffectiveClusterSecurity::SharedKey { .. } | EffectiveClusterSecurity::LegacyPlaintext => {
            None
        }
    }
}

fn validate_authority_identity(
    authority: &EnrollmentAuthority,
    installed: &ClusterIdentity,
    security: &EffectiveClusterSecurity,
) -> Result<()> {
    let authority = &authority.identity().document;
    if authority.cluster_id != installed.cluster_id
        || authority.node_id != installed.node_id
        || authority.roles != installed.roles
        || authority.labels != installed.labels
    {
        anyhow::bail!(
            "configured cluster identity does not match the signed enrollment authority identity"
        );
    }
    if let EffectiveClusterSecurity::Mtls {
        cert_file,
        server_name,
        ..
    } = security
    {
        if authority.server_name != *server_name {
            anyhow::bail!(
                "configured cluster mTLS server name does not match the signed enrollment authority identity"
            );
        }
        let certificate_pem = std::fs::read_to_string(cert_file)
            .with_context(|| format!("read configured authority certificate {cert_file:?}"))?;
        let certificate_sha256 =
            sbproxy_mesh::enrollment::certificate_sha256_from_pem(&certificate_pem)
                .context("fingerprint configured authority certificate")?;
        if authority.certificate_sha256 != certificate_sha256 {
            anyhow::bail!(
                "configured cluster mTLS certificate does not match the signed enrollment authority identity"
            );
        }
    }
    Ok(())
}

fn resolve_legacy_node_id(mut config: EffectiveClusterConfig) -> EffectiveClusterConfig {
    if config.node_id.is_none() {
        config.node_id = Some(default_node_id());
    }
    config
}

fn desired_installation(
    effective: Option<&EffectiveClusterConfig>,
) -> Result<(
    ClusterIdentity,
    Option<ClusterRestartFingerprint>,
    ClusterSettings,
)> {
    let Some(effective) = effective else {
        return Ok((
            ClusterIdentity {
                cluster_id: LOCAL_CLUSTER_ID.to_string(),
                node_id: default_node_id(),
                roles: BTreeSet::from([ClusterNodeRole::Gateway, ClusterNodeRole::Worker]),
                labels: BTreeMap::new(),
                peer_address: None,
                model_endpoint: None,
            },
            None,
            ClusterSettings {
                snapshot_ttl_secs: DEFAULT_SNAPSHOT_TTL_SECS,
                publish_interval_secs: DEFAULT_PUBLISH_INTERVAL_SECS,
                distributed_requested: false,
            },
        ));
    };
    let node_id = effective
        .node_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("effective cluster has no node ID"))?;
    let identity = ClusterIdentity {
        cluster_id: effective.cluster_id.clone(),
        node_id,
        roles: effective.roles.iter().copied().map(lower_role).collect(),
        labels: effective.labels.clone(),
        peer_address: effective.advertise_addr.clone(),
        model_endpoint: effective.model_endpoint.clone(),
    };
    identity.validate().map_err(anyhow::Error::from)?;
    Ok((
        identity,
        Some(effective.restart_fingerprint()),
        ClusterSettings {
            snapshot_ttl_secs: effective.snapshot_ttl_secs,
            publish_interval_secs: effective.publish_interval_secs,
            distributed_requested: true,
        },
    ))
}

const fn lower_role(role: ClusterRole) -> ClusterNodeRole {
    match role {
        ClusterRole::Gateway => ClusterNodeRole::Gateway,
        ClusterRole::Worker => ClusterNodeRole::Worker,
        ClusterRole::Authority => ClusterNodeRole::Authority,
    }
}

fn default_node_id() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "sbproxy-node".to_string())
}

fn unix_time_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("cluster clock is before the Unix epoch")?
        .as_millis();
    u64::try_from(millis).context("cluster Unix time overflowed u64")
}

/// Production bootstrap using the existing SWIM and typed-state mesh.
#[derive(Debug, Default)]
pub struct SystemClusterBootstrap;

impl ClusterBootstrap for SystemClusterBootstrap {
    fn bootstrap(
        &self,
        identity: ClusterIdentity,
        config: &EffectiveClusterConfig,
    ) -> Result<ClusterHandle> {
        let (shared_key, peer_tls) = resolve_security(&config.security)?;
        let discoveries: Vec<Box<dyn Discovery>> =
            vec![Box::new(SeedDiscovery::new(config.seeds.clone()))];
        let bootstrap = BootstrapConfig {
            gossip_port: config.gossip_port,
            transport_port: config.transport_port,
            gossip_advertise_addr: config.advertise_addr.clone(),
            transport_advertise_addr: config.transport_advertise_addr.clone(),
            shared_key,
            peer_tls,
            ..Default::default()
        };
        let node_id = identity.node_id.clone();
        let node = block_on_cluster(sbproxy_mesh::bootstrap::bootstrap(
            &discoveries,
            &bootstrap,
            node_id,
        ))
        .context("bootstrap shared mesh node")?;
        if config.source != ClusterConfigSource::LegacyMesh {
            if node.peer_table().is_none() {
                anyhow::bail!("canonical cluster gossip listener failed to bind");
            }
            if !node.has_transport() {
                anyhow::bail!("canonical cluster typed-state transport failed to bind");
            }
        }
        ClusterHandle::distributed(identity, Arc::new(node)).map_err(anyhow::Error::from)
    }
}

fn resolve_security(
    security: &EffectiveClusterSecurity,
) -> Result<(Option<String>, Option<PeerTlsParams>)> {
    match security {
        EffectiveClusterSecurity::Mtls {
            cert_file,
            key_file,
            ca_file,
            server_name,
            shared_key,
        } => {
            let shared_key = resolve_secret_material(
                shared_key
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("mTLS cluster has no UDP gossip key"))?,
            )?;
            let peer_tls = PeerTlsParams {
                tls: sbproxy_mesh::transport::tls::MeshTlsConfig {
                    cert_pem: std::fs::read_to_string(cert_file)
                        .with_context(|| format!("read cluster certificate {cert_file:?}"))?,
                    key_pem: std::fs::read_to_string(key_file)
                        .with_context(|| format!("read cluster private key {key_file:?}"))?,
                    ca_pem: std::fs::read_to_string(ca_file)
                        .with_context(|| format!("read cluster CA {ca_file:?}"))?,
                },
                server_name: server_name.clone(),
            };
            Ok((Some(shared_key), Some(peer_tls)))
        }
        EffectiveClusterSecurity::SharedKey { reference, .. } => {
            Ok((Some(resolve_secret_material(reference)?), None))
        }
        EffectiveClusterSecurity::LegacyPlaintext => Ok((None, None)),
    }
}

fn resolve_secret_material(reference: &str) -> Result<String> {
    let bytes = if let Some(name) = reference.strip_prefix("env:") {
        std::env::var(name)
            .with_context(|| format!("read cluster secret environment variable {name:?}"))?
            .into_bytes()
    } else if let Some(path) = reference.strip_prefix("file:") {
        std::fs::read(path).with_context(|| format!("read cluster secret file {path:?}"))?
    } else if reference.starts_with("vault://") {
        anyhow::bail!(
            "cluster peer secrets do not resolve vault:// directly; inject the secret with env: or file:"
        );
    } else {
        reference.as_bytes().to_vec()
    };
    if bytes.len() < 16 {
        anyhow::bail!("resolved cluster shared key must contain at least 16 bytes");
    }
    String::from_utf8(bytes).context("cluster shared key must be valid UTF-8")
}

fn cluster_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("sbproxy-cluster")
            .build()
            .expect("build cluster runtime")
    })
}

fn block_on_cluster<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| cluster_runtime().block_on(future))
            .join()
            .expect("cluster bootstrap thread panicked")
    })
}

fn process_owner() -> &'static ClusterOwner {
    static OWNER: OnceLock<ClusterOwner> = OnceLock::new();
    OWNER.get_or_init(|| ClusterOwner::new(Arc::new(SystemClusterBootstrap)))
}

/// Install or reload-validate the permanent process cluster.
pub fn reconcile_process_cluster(server: &ProxyServerConfig) -> Result<ClusterHandle> {
    let handle = process_owner().reconcile(server)?;
    start_cluster_metrics(&handle);
    Ok(handle)
}

/// Currently installed permanent process cluster.
pub fn current_cluster_handle() -> Option<ClusterHandle> {
    process_owner().current()
}

/// Current reloadable process cluster settings.
pub fn current_cluster_settings() -> Option<ClusterSettings> {
    process_owner().settings()
}

/// Reserve a due process node-snapshot publication.
pub async fn begin_process_node_snapshot_publication(
    force: bool,
) -> Result<Option<NodeSnapshotPublication>> {
    process_owner().begin_node_snapshot_publication(force).await
}

/// Configured process enrollment authority, if this node owns one.
pub fn current_enrollment_authority() -> Option<Arc<EnrollmentAuthority>> {
    process_owner().enrollment_authority()
}

fn start_cluster_metrics(handle: &ClusterHandle) {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if handle.mesh_node().is_none() {
        return;
    }
    if STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    crate::cluster_metrics::install_cluster_metrics(Arc::new(
        sbproxy_mesh::cluster_metrics::ClusterMetrics::new(),
    ));
    cluster_runtime().spawn(crate::cluster_metrics::run_loop(handle.clone(), 15));
}
