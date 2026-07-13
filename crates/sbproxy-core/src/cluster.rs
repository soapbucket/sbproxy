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
const DIRECTORY_COLLECT_INTERVAL_MS: u64 = 1_000;
const DEPLOYMENT_BUNDLE_NAMESPACE: &str = "model-deployments";
const DEPLOYMENT_BUNDLE_CURRENT_KEY: &str = "current";
const DEPLOYMENT_BUNDLE_SCHEMA_VERSION: u32 = 1;
const DEPLOYMENT_BUNDLE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

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
    /// Whether canonical cluster model publication and placement are enabled.
    pub model_control_enabled: bool,
}

struct ReloadableClusterSettings {
    snapshot_ttl_secs: AtomicU64,
    publish_interval_secs: AtomicU64,
    distributed_requested: bool,
    model_control_enabled: bool,
}

struct SnapshotPublicationState {
    enabled: bool,
    generation_directory: Option<PathBuf>,
    reserved_generation: Mutex<Option<u64>>,
    ephemeral_generation: AtomicU64,
    last_success_unix_ms: AtomicU64,
    publish_lock: Arc<tokio::sync::Mutex<()>>,
    directory: Arc<sbproxy_ai::model_directory::ModelDirectory>,
    last_collect_unix_ms: AtomicU64,
    collect_lock: Arc<tokio::sync::Mutex<()>>,
}

impl SnapshotPublicationState {
    fn new(enabled: bool, generation_directory: Option<PathBuf>) -> Result<Self> {
        let reserved_generation = if enabled {
            let directory = generation_directory.as_ref().ok_or_else(|| {
                anyhow::anyhow!("canonical cluster model publication requires a durable state_dir")
            })?;
            Some(
                sbproxy_model_host::node_snapshot::NodeSnapshotGeneration::open(directory)
                    .context("open durable node snapshot generation at startup")?
                    .next()
                    .context("validate durable node snapshot generation at startup")?,
            )
        } else {
            None
        };
        Ok(Self {
            enabled,
            generation_directory,
            reserved_generation: Mutex::new(reserved_generation),
            ephemeral_generation: AtomicU64::new(0),
            last_success_unix_ms: AtomicU64::new(0),
            publish_lock: Arc::new(tokio::sync::Mutex::new(())),
            directory: Arc::new(sbproxy_ai::model_directory::ModelDirectory::new()),
            last_collect_unix_ms: AtomicU64::new(0),
            collect_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    fn next_generation(&self) -> Result<u64> {
        if let Some(generation) = self
            .reserved_generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Ok(generation);
        }
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
            model_control_enabled: settings.model_control_enabled,
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
            model_control_enabled: self.model_control_enabled,
        }
    }
}

struct InstalledCluster {
    handle: ClusterHandle,
    enrollment_authority: Option<Arc<EnrollmentAuthority>>,
    restart_fingerprint: Option<ClusterRestartFingerprint>,
    settings: Arc<ReloadableClusterSettings>,
    snapshot_publication: Arc<SnapshotPublicationState>,
    deployment_authority: Option<ClusterDeploymentAuthority>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentBundlePointer {
    revision: u64,
    content_digest: String,
    signer_node_id: String,
    signer_key_id: String,
}

struct DeploymentAuthorityState {
    verifying_key: sbproxy_model_host::DeploymentVerifyingKey,
    signing_key: Option<sbproxy_model_host::DeploymentSigningKey>,
    cursor_store: Option<sbproxy_model_host::FileDeploymentBundleCursorStore>,
    cursor: Mutex<Option<sbproxy_model_host::DeploymentBundleCursor>>,
    active: Mutex<Option<sbproxy_model_host::VerifiedDeploymentBundle>>,
    last_publication_unix_ms: AtomicU64,
}

/// Installed signed deployment-authority adapter over the shared cluster state.
#[derive(Clone)]
pub struct ClusterDeploymentAuthority {
    handle: ClusterHandle,
    state: Arc<DeploymentAuthorityState>,
}

impl std::fmt::Debug for ClusterDeploymentAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClusterDeploymentAuthority")
            .field("node_id", &self.handle.identity().node_id)
            .field("key_id", &self.state.verifying_key.key_id())
            .field("can_publish", &self.can_publish())
            .finish_non_exhaustive()
    }
}

/// Signed deployment publication or read failure.
#[derive(Debug, thiserror::Error)]
pub enum ClusterDeploymentAuthorityError {
    /// This node has no configured authority role and private signing key.
    #[error("cluster deployment authority is read-only on this node")]
    ReadOnly,
    /// Bundle construction, signing, or verification failed.
    #[error(transparent)]
    Bundle(#[from] sbproxy_model_host::DeploymentAuthorityError),
    /// Typed cluster-state publication or lookup failed.
    #[error("cluster deployment authority state failed: {0}")]
    State(String),
    /// Pointer publisher or content did not match the signed authority.
    #[error("cluster deployment authority identity failed: {0}")]
    Identity(String),
}

impl ClusterDeploymentAuthority {
    /// Whether this installed node can sign and publish persistent desired state.
    pub fn can_publish(&self) -> bool {
        self.handle
            .identity()
            .roles
            .contains(&ClusterNodeRole::Authority)
            && self.state.signing_key.is_some()
    }

    /// Configured verification-key ID shared by every node.
    pub fn verifying_key_id(&self) -> &str {
        self.state.verifying_key.key_id()
    }

    /// Last bundle committed by the local runtime.
    pub fn active(&self) -> Option<sbproxy_model_host::VerifiedDeploymentBundle> {
        self.state
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Sign and publish content first, followed by its current pointer.
    pub async fn publish(
        &self,
        bundle: sbproxy_model_host::RestrictedDeploymentBundle,
    ) -> Result<sbproxy_model_host::SignedDeploymentBundle, ClusterDeploymentAuthorityError> {
        let signing_key = self
            .state
            .signing_key
            .as_ref()
            .ok_or(ClusterDeploymentAuthorityError::ReadOnly)?;
        if !self
            .handle
            .identity()
            .roles
            .contains(&ClusterNodeRole::Authority)
        {
            return Err(ClusterDeploymentAuthorityError::ReadOnly);
        }
        let signed = sbproxy_model_host::SignedDeploymentBundle::sign(
            bundle,
            &self.handle.identity().node_id,
            signing_key,
        )?;
        let current = self
            .state
            .cursor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        signed.verify(&self.state.verifying_key, current.as_ref())?;
        let pointer = DeploymentBundlePointer {
            revision: signed.bundle.revision,
            content_digest: signed.bundle.content_digest.clone(),
            signer_node_id: signed.signer_node_id.clone(),
            signer_key_id: signed.signer_key_id.clone(),
        };
        self.handle
            .publish_state(
                DEPLOYMENT_BUNDLE_NAMESPACE,
                &signed.bundle.content_key(),
                DEPLOYMENT_BUNDLE_SCHEMA_VERSION,
                signed.bundle.revision,
                DEPLOYMENT_BUNDLE_TTL,
                &signed,
            )
            .await
            .map_err(|error| ClusterDeploymentAuthorityError::State(error.to_string()))?;
        self.handle
            .publish_state(
                DEPLOYMENT_BUNDLE_NAMESPACE,
                DEPLOYMENT_BUNDLE_CURRENT_KEY,
                DEPLOYMENT_BUNDLE_SCHEMA_VERSION,
                signed.bundle.revision,
                DEPLOYMENT_BUNDLE_TTL,
                &pointer,
            )
            .await
            .map_err(|error| ClusterDeploymentAuthorityError::State(error.to_string()))?;
        self.state
            .last_publication_unix_ms
            .store(unix_time_ms().unwrap_or(0), Ordering::SeqCst);
        Ok(signed)
    }

    /// Refresh the active pointer and content before their bounded TTL expires.
    pub async fn republish_active_if_due(
        &self,
        interval: Duration,
    ) -> Result<bool, ClusterDeploymentAuthorityError> {
        if !self.can_publish() || interval.is_zero() {
            return Ok(false);
        }
        let Some(active) = self.active() else {
            return Ok(false);
        };
        let now = unix_time_ms()
            .map_err(|error| ClusterDeploymentAuthorityError::State(error.to_string()))?;
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        let last = self.state.last_publication_unix_ms.load(Ordering::SeqCst);
        if last != 0 && now.saturating_sub(last) < interval_ms {
            return Ok(false);
        }
        self.publish(active.bundle().clone()).await?;
        Ok(true)
    }

    /// Synchronous adapter for the hand-written admin listener.
    pub fn publish_blocking(
        &self,
        bundle: sbproxy_model_host::RestrictedDeploymentBundle,
    ) -> Result<sbproxy_model_host::SignedDeploymentBundle, ClusterDeploymentAuthorityError> {
        let authority = self.clone();
        block_on_cluster(async move { authority.publish(bundle).await })
    }

    /// Fetch and verify a newer current bundle without advancing local state.
    pub async fn read_candidate(
        &self,
    ) -> Result<Option<sbproxy_model_host::VerifiedDeploymentBundle>, ClusterDeploymentAuthorityError>
    {
        let pointer_record = match self
            .handle
            .read_state::<DeploymentBundlePointer>(
                DEPLOYMENT_BUNDLE_NAMESPACE,
                DEPLOYMENT_BUNDLE_CURRENT_KEY,
                DEPLOYMENT_BUNDLE_SCHEMA_VERSION,
            )
            .await
        {
            sbproxy_mesh::ClusterStateRead::Present(record) => record,
            sbproxy_mesh::ClusterStateRead::Missing => return Ok(None),
            other => {
                return Err(ClusterDeploymentAuthorityError::State(format!(
                    "current pointer is unavailable: {other:?}"
                )))
            }
        };
        validate_enrolled_authority_publisher(&pointer_record)
            .map_err(ClusterDeploymentAuthorityError::Identity)?;
        let pointer = pointer_record.payload;
        if pointer.revision == 0
            || pointer_record.generation != pointer.revision
            || pointer.content_digest.len() != 64
            || !pointer
                .content_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ClusterDeploymentAuthorityError::Identity(
                "current pointer identity or generation is invalid".to_string(),
            ));
        }
        if pointer_record.publisher_node_id != pointer.signer_node_id {
            return Err(ClusterDeploymentAuthorityError::Identity(
                "current pointer publisher differs from signer node".to_string(),
            ));
        }
        if pointer.signer_key_id != self.state.verifying_key.key_id() {
            return Err(ClusterDeploymentAuthorityError::Identity(
                "current pointer key differs from configured authority".to_string(),
            ));
        }
        let current = self
            .state
            .cursor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if self.active().as_ref().is_some_and(|active| {
            active.bundle().revision == pointer.revision
                && active.bundle().content_digest == pointer.content_digest
        }) {
            return Ok(None);
        }
        let bundle_record = match self
            .handle
            .read_state::<sbproxy_model_host::SignedDeploymentBundle>(
                DEPLOYMENT_BUNDLE_NAMESPACE,
                &pointer.content_digest,
                DEPLOYMENT_BUNDLE_SCHEMA_VERSION,
            )
            .await
        {
            sbproxy_mesh::ClusterStateRead::Present(record) => record,
            other => {
                return Err(ClusterDeploymentAuthorityError::State(format!(
                    "content bundle is unavailable: {other:?}"
                )))
            }
        };
        validate_enrolled_authority_publisher(&bundle_record)
            .map_err(ClusterDeploymentAuthorityError::Identity)?;
        let signed = bundle_record.payload;
        if bundle_record.generation != pointer.revision
            || bundle_record.publisher_node_id != pointer.signer_node_id
            || signed.signer_node_id != pointer.signer_node_id
            || signed.signer_key_id != pointer.signer_key_id
            || signed.bundle.revision != pointer.revision
            || signed.bundle.content_digest != pointer.content_digest
        {
            return Err(ClusterDeploymentAuthorityError::Identity(
                "current pointer does not match its signed content".to_string(),
            ));
        }
        Ok(Some(
            signed.verify(&self.state.verifying_key, current.as_ref())?,
        ))
    }

    /// Synchronous candidate read for startup and file-watch reconciliation.
    pub fn read_candidate_blocking(
        &self,
    ) -> Result<Option<sbproxy_model_host::VerifiedDeploymentBundle>, ClusterDeploymentAuthorityError>
    {
        let authority = self.clone();
        block_on_cluster(async move { authority.read_candidate().await })
    }

    /// Durably fence a verified candidate before the prepared runtime is committed.
    pub(crate) fn persist(
        &self,
        verified: &sbproxy_model_host::VerifiedDeploymentBundle,
    ) -> Result<(), ClusterDeploymentAuthorityError> {
        let cursor = verified.cursor();
        if let Some(store) = self.state.cursor_store.as_ref() {
            store.commit(&cursor)?;
        }
        *self
            .state
            .cursor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(cursor);
        Ok(())
    }

    /// Mark a durably fenced candidate active after the runtime commit succeeds.
    pub(crate) fn activate(&self, verified: sbproxy_model_host::VerifiedDeploymentBundle) {
        *self
            .state
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(verified);
    }

    /// Durably fence and activate a candidate whose runtime is already committed.
    pub fn commit(
        &self,
        verified: sbproxy_model_host::VerifiedDeploymentBundle,
    ) -> Result<(), ClusterDeploymentAuthorityError> {
        self.persist(&verified)?;
        self.activate(verified);
        Ok(())
    }
}

fn validate_enrolled_authority_publisher<T>(
    record: &sbproxy_mesh::ClusterStateRecord<T>,
) -> Result<(), String> {
    if record
        .authenticated_identity
        .as_ref()
        .is_some_and(|identity| {
            identity.node_id != record.publisher_node_id
                || !identity.roles.contains(&ClusterNodeRole::Authority)
        })
    {
        return Err("deployment state publisher lacks its enrolled authority role".to_string());
    }
    Ok(())
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
        )?);
        let deployment_authority = effective
            .as_ref()
            .and_then(|effective| {
                effective
                    .deployment_authority
                    .as_ref()
                    .map(|authority| (authority, effective.state_dir.as_deref()))
            })
            .map(|(config, state_dir)| load_deployment_authority(&handle, config, state_dir))
            .transpose()?;
        *installed = Some(InstalledCluster {
            handle: handle.clone(),
            enrollment_authority,
            restart_fingerprint: fingerprint,
            settings: Arc::new(ReloadableClusterSettings::new(settings)),
            snapshot_publication,
            deployment_authority,
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

    fn state_directory(&self) -> Option<PathBuf> {
        self.installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(|installed| installed.snapshot_publication.generation_directory.clone())
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

    /// Configured signed deployment authority reader and optional publisher.
    pub fn deployment_authority(&self) -> Option<ClusterDeploymentAuthority> {
        self.installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(|installed| installed.deployment_authority.clone())
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

    /// Collect membership and schema-agnostic snapshots into the immutable directory.
    pub async fn collect_model_directory(
        &self,
        force: bool,
    ) -> Result<Option<Arc<sbproxy_ai::model_directory::ModelDirectoryView>>> {
        use sbproxy_ai::model_directory::{
            DirectoryMember, DirectoryMemberState, DirectorySnapshotRead,
        };

        let Some((handle, state)) = self
            .installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|installed| {
                (
                    installed.handle.clone(),
                    Arc::clone(&installed.snapshot_publication),
                )
            })
        else {
            return Ok(None);
        };
        if !state.enabled {
            return Ok(None);
        }
        let _guard = Arc::clone(&state.collect_lock).lock_owned().await;
        let now = unix_time_ms()?;
        let last_collect = state.last_collect_unix_ms.load(Ordering::SeqCst);
        if !force
            && last_collect != 0
            && now.saturating_sub(last_collect) < DIRECTORY_COLLECT_INTERVAL_MS
        {
            return Ok(None);
        }
        let membership = handle.membership();
        let mut members = Vec::with_capacity(membership.len());
        let mut reads = BTreeMap::new();
        let mut alive_node_ids = Vec::new();
        for member in membership {
            let state = match member.state {
                sbproxy_mesh::ClusterMemberState::Alive => DirectoryMemberState::Alive,
                sbproxy_mesh::ClusterMemberState::Suspect => DirectoryMemberState::Suspect,
                sbproxy_mesh::ClusterMemberState::Dead => DirectoryMemberState::Dead,
                sbproxy_mesh::ClusterMemberState::Unreachable => DirectoryMemberState::Unreachable,
            };
            let node_id = member.node_id.clone();
            members.push(DirectoryMember {
                node_id: node_id.clone(),
                address: member.address,
                state,
                last_ack_age_ms: u64::try_from(member.last_ack_age.as_millis()).unwrap_or(u64::MAX),
                incarnation: member.incarnation,
            });
            if state == DirectoryMemberState::Alive {
                alive_node_ids.push(node_id);
            } else {
                reads.insert(node_id, DirectorySnapshotRead::Missing);
            }
        }
        use futures::StreamExt as _;
        let observations = futures::stream::iter(alive_node_ids.into_iter().map(|node_id| {
            let handle = handle.clone();
            async move {
                let read = handle
                    .read_state_value(
                        sbproxy_model_host::node_snapshot::NODE_MODEL_SNAPSHOT_NAMESPACE,
                        &node_id,
                    )
                    .await;
                (node_id, directory_snapshot_read(read))
            }
        }))
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await;
        for (node_id, read) in observations {
            reads.insert(node_id, read);
        }
        let view = state
            .directory
            .refresh(now, members, reads)
            .context("refresh live model directory")?;
        state.last_collect_unix_ms.store(now, Ordering::SeqCst);
        Ok(Some(view))
    }

    /// Current lock-free live model directory.
    pub fn model_directory(&self) -> Option<Arc<sbproxy_ai::model_directory::ModelDirectory>> {
        self.installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|installed| Arc::clone(&installed.snapshot_publication.directory))
    }
}

fn directory_snapshot_read(
    read: sbproxy_mesh::ClusterStateRead<serde_json::Value>,
) -> sbproxy_ai::model_directory::DirectorySnapshotRead {
    use sbproxy_ai::model_directory::{
        DirectoryAuthenticatedIdentity, DirectorySnapshotEnvelope, DirectorySnapshotRead,
    };

    match read {
        sbproxy_mesh::ClusterStateRead::Present(record) => {
            DirectorySnapshotRead::Present(DirectorySnapshotEnvelope {
                publisher_node_id: record.publisher_node_id,
                schema_version: record.schema_version,
                generation: record.generation,
                published_at_unix_ms: record.published_at_unix_ms,
                expires_at_unix_ms: record.expires_at_unix_ms,
                authenticated_identity: record.authenticated_identity.map(|identity| {
                    let identity = *identity;
                    DirectoryAuthenticatedIdentity {
                        node_id: identity.node_id,
                        roles: identity
                            .roles
                            .into_iter()
                            .map(lower_snapshot_role)
                            .collect(),
                        labels: identity.labels,
                    }
                }),
                payload: record.payload,
            })
        }
        sbproxy_mesh::ClusterStateRead::Missing => DirectorySnapshotRead::Missing,
        sbproxy_mesh::ClusterStateRead::Expired {
            generation,
            expires_at_unix_ms,
        } => DirectorySnapshotRead::Expired {
            generation,
            expires_at_unix_ms,
        },
        sbproxy_mesh::ClusterStateRead::Unreachable { .. } => DirectorySnapshotRead::Unreachable,
        sbproxy_mesh::ClusterStateRead::Malformed { .. } => DirectorySnapshotRead::Malformed,
        sbproxy_mesh::ClusterStateRead::IncompatibleSchema {
            actual, generation, ..
        } => DirectorySnapshotRead::IncompatibleSchema {
            schema_version: actual,
            generation,
        },
    }
}

const fn lower_snapshot_role(
    role: sbproxy_mesh::ClusterNodeRole,
) -> sbproxy_model_host::node_snapshot::NodeRole {
    match role {
        sbproxy_mesh::ClusterNodeRole::Gateway => {
            sbproxy_model_host::node_snapshot::NodeRole::Gateway
        }
        sbproxy_mesh::ClusterNodeRole::Worker => {
            sbproxy_model_host::node_snapshot::NodeRole::Worker
        }
        sbproxy_mesh::ClusterNodeRole::Authority => {
            sbproxy_model_host::node_snapshot::NodeRole::Authority
        }
    }
}

fn model_snapshot_publication_enabled(config: Option<&EffectiveClusterConfig>) -> bool {
    config.is_some_and(|config| config.source != ClusterConfigSource::LegacyMesh)
}

fn load_deployment_authority(
    handle: &ClusterHandle,
    config: &sbproxy_config::ClusterDeploymentAuthorityConfig,
    state_dir: Option<&str>,
) -> Result<ClusterDeploymentAuthority> {
    let verifying_key =
        sbproxy_model_host::DeploymentVerifyingKey::from_file(&config.verifying_key_file)
            .context("load cluster deployment verification key")?;
    let signing_key = config
        .signing_key_file
        .as_ref()
        .map(|path| {
            sbproxy_model_host::DeploymentSigningKey::from_file(path)
                .context("load cluster deployment signing key")
        })
        .transpose()?;
    if signing_key
        .as_ref()
        .is_some_and(|signing| signing.verifying_key().key_id() != verifying_key.key_id())
    {
        anyhow::bail!("cluster deployment signing and verification keys do not match");
    }
    let cursor_store = state_dir
        .map(|directory| {
            sbproxy_model_host::FileDeploymentBundleCursorStore::open(
                Path::new(directory).join("deployment-authority-cursor.json"),
            )
            .context("open cluster deployment authority cursor")
        })
        .transpose()?;
    let cursor = cursor_store
        .as_ref()
        .map(sbproxy_model_host::FileDeploymentBundleCursorStore::load)
        .transpose()
        .context("load cluster deployment authority cursor")?
        .flatten();
    Ok(ClusterDeploymentAuthority {
        handle: handle.clone(),
        state: Arc::new(DeploymentAuthorityState {
            verifying_key,
            signing_key,
            cursor_store,
            cursor: Mutex::new(cursor),
            active: Mutex::new(None),
            last_publication_unix_ms: AtomicU64::new(0),
        }),
    })
}

fn snapshot_generation_directory(config: Option<&EffectiveClusterConfig>) -> Option<PathBuf> {
    config?.state_dir.as_ref().map(PathBuf::from)
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
                model_control_enabled: false,
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
            model_control_enabled: effective.source != ClusterConfigSource::LegacyMesh,
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
        let (shared_key, peer_tls) = resolve_security(config, &identity)?;
        let discoveries: Vec<Box<dyn Discovery>> =
            vec![Box::new(SeedDiscovery::new(config.seeds.clone()))];
        let bootstrap = BootstrapConfig {
            gossip_port: config.gossip_port,
            transport_port: config.transport_port,
            gossip_advertise_addr: config.advertise_addr.clone(),
            transport_advertise_addr: config.transport_advertise_addr.clone(),
            dead_peer_gc_secs: config.dead_peer_gc_secs,
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
    config: &EffectiveClusterConfig,
    identity: &ClusterIdentity,
) -> Result<(Option<String>, Option<PeerTlsParams>)> {
    match &config.security {
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
            let tls = sbproxy_mesh::transport::tls::MeshTlsConfig {
                cert_pem: std::fs::read_to_string(cert_file)
                    .with_context(|| format!("read cluster certificate {cert_file:?}"))?,
                key_pem: std::fs::read_to_string(key_file)
                    .with_context(|| format!("read cluster private key {key_file:?}"))?,
                ca_pem: std::fs::read_to_string(ca_file)
                    .with_context(|| format!("read cluster CA {ca_file:?}"))?,
            };
            let identity_authenticator = if config.source == ClusterConfigSource::LegacyMesh {
                None
            } else {
                let state_dir = config.state_dir.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("canonical mTLS cluster has no durable identity state_dir")
                })?;
                let identity_file = std::path::Path::new(state_dir).join("identity.json");
                let authority_key = std::path::Path::new(state_dir).join("authority-verifying.key");
                let authenticator = match (identity_file.is_file(), authority_key.is_file()) {
                    (true, true) => {
                        sbproxy_mesh::peer_identity::PeerIdentityAuthenticator::load_installed(
                            state_dir,
                            identity,
                            server_name,
                            &tls,
                        )
                        .context("load enrolled cluster identity")?
                    }
                    (false, false) => {
                        sbproxy_mesh::peer_identity::PeerIdentityAuthenticator::load_manual(
                            state_dir,
                            identity,
                            server_name,
                            &tls,
                        )
                        .context("load manual PKI cluster identity")?
                    }
                    _ => anyhow::bail!(
                        "canonical mTLS state_dir has an incomplete enrolled identity installation"
                    ),
                };
                Some(Arc::new(authenticator))
            };
            let peer_tls = PeerTlsParams {
                tls,
                server_name: server_name.clone(),
                identity_authenticator,
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

/// Durable state directory for canonical cluster model control.
pub(crate) fn current_cluster_state_directory() -> Option<PathBuf> {
    process_owner().state_directory()
}

/// Reserve a due process node-snapshot publication.
pub async fn begin_process_node_snapshot_publication(
    force: bool,
) -> Result<Option<NodeSnapshotPublication>> {
    process_owner().begin_node_snapshot_publication(force).await
}

/// Refresh the process live model directory when its collector cadence is due.
pub async fn collect_process_model_directory(
    force: bool,
) -> Result<Option<Arc<sbproxy_ai::model_directory::ModelDirectoryView>>> {
    process_owner().collect_model_directory(force).await
}

/// Current process live model directory.
pub fn current_model_directory() -> Option<Arc<sbproxy_ai::model_directory::ModelDirectory>> {
    process_owner().model_directory()
}

/// Configured process enrollment authority, if this node owns one.
pub fn current_enrollment_authority() -> Option<Arc<EnrollmentAuthority>> {
    process_owner().enrollment_authority()
}

/// Configured signed deployment authority adapter, if installed.
pub fn current_deployment_authority() -> Option<ClusterDeploymentAuthority> {
    process_owner().deployment_authority()
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
