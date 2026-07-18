//! Shared local or distributed cluster handle.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::gossip_loop::{PeerEntry, PeerState};
use crate::isolation::IsolationObserver;
use crate::state::distributed_cache::DistributedCache;
use crate::state::register::{VersionedLwwMergeOutcome, VersionedLwwRegister};
use crate::MeshNode;

const STATE_KEY_PREFIX: &str = "sbproxy:cluster-state:v1";
const MAX_STATE_COMPONENT_LEN: usize = 128;
const MAX_STATE_BYTES: usize = 1024 * 1024;
const MAX_STATE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_IDENTITY_LEN: usize = 128;
const MAX_LABELS: usize = 64;
const MAX_LABEL_KEY_LEN: usize = 128;
const MAX_LABEL_VALUE_LEN: usize = 256;

/// Stable role assigned to one installed cluster identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterNodeRole {
    /// Accept public traffic and apply gateway policy.
    Gateway,
    /// Host managed model replicas.
    Worker,
    /// Enroll nodes or sign deployment revisions.
    Authority,
}

/// Immutable identity installed for this process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterIdentity {
    /// Logical cluster ID shared by every member.
    pub cluster_id: String,
    /// Stable unique node ID.
    pub node_id: String,
    /// Process roles bound to this identity.
    pub roles: BTreeSet<ClusterNodeRole>,
    /// Bounded placement and failure-domain labels.
    pub labels: BTreeMap<String, String>,
    /// Address advertised for peer gossip.
    pub peer_address: Option<String>,
    /// Private model-plane endpoint advertised by a worker.
    pub model_endpoint: Option<String>,
}

impl ClusterIdentity {
    /// Validate identity bounds before installing a handle.
    pub fn validate(&self) -> Result<(), ClusterStateError> {
        for (field, value) in [
            ("cluster_id", self.cluster_id.as_str()),
            ("node_id", self.node_id.as_str()),
        ] {
            if value.is_empty()
                || value.len() > MAX_IDENTITY_LEN
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            {
                return Err(ClusterStateError::InvalidIdentity(format!(
                    "{field} is empty, invalid, or exceeds {MAX_IDENTITY_LEN} bytes"
                )));
            }
        }
        if self.roles.is_empty() {
            return Err(ClusterStateError::InvalidIdentity(
                "at least one node role is required".to_string(),
            ));
        }
        if self.labels.len() > MAX_LABELS {
            return Err(ClusterStateError::InvalidIdentity(format!(
                "identity may contain at most {MAX_LABELS} labels"
            )));
        }
        for (key, value) in &self.labels {
            if key.is_empty()
                || key.len() > MAX_LABEL_KEY_LEN
                || !key.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
                })
                || value.is_empty()
                || value.len() > MAX_LABEL_VALUE_LEN
                || value.chars().any(char::is_control)
            {
                return Err(ClusterStateError::InvalidIdentity(format!(
                    "identity label {key:?} is empty, invalid, or exceeds its bound"
                )));
            }
        }
        if let Some(address) = self.peer_address.as_deref() {
            let valid = address.rsplit_once(':').is_some_and(|(host, port)| {
                !host.is_empty()
                    && port.parse::<u16>().is_ok_and(|port| port > 0)
                    && !address.chars().any(char::is_whitespace)
            });
            if !valid {
                return Err(ClusterStateError::InvalidIdentity(format!(
                    "peer_address {address:?} must use host:port form"
                )));
            }
        }
        if let Some(endpoint) = self.model_endpoint.as_deref() {
            let valid = url::Url::parse(endpoint).is_ok_and(|url| {
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
            });
            if !valid || endpoint.len() > 2048 || endpoint.chars().any(char::is_control) {
                return Err(ClusterStateError::InvalidIdentity(
                    "model_endpoint must be a bounded absolute HTTP origin".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Runtime implementation selected for a cluster handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMode {
    /// One-node, zero-network state.
    Local,
    /// Existing SWIM and typed-state mesh.
    Distributed,
}

/// Membership state exposed to cluster consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMemberState {
    /// SWIM considers the member live and its transport address is known.
    Alive,
    /// SWIM is probing a member that recently failed direct and indirect checks.
    Suspect,
    /// SWIM declared the member dead.
    Dead,
    /// The member is live but has no usable typed-state transport address.
    Unreachable,
}

/// One immutable point-in-time membership entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMember {
    /// Stable member node ID.
    pub node_id: String,
    /// Last known peer address.
    pub address: Option<String>,
    /// Local membership state.
    pub state: ClusterMemberState,
    /// Time since the last acknowledged probe.
    pub last_ack_age: Duration,
    /// Highest SWIM incarnation observed for this member.
    pub incarnation: u64,
}

/// Typed state publication or construction failure.
#[derive(Debug, thiserror::Error)]
pub enum ClusterStateError {
    /// Installed identity is invalid or does not match the wrapped mesh.
    #[error("invalid cluster identity: {0}")]
    InvalidIdentity(String),
    /// Namespace or key violates the bounded state-key grammar.
    #[error("invalid cluster state key: {0}")]
    InvalidKey(String),
    /// State expiry is zero or exceeds the supported maximum.
    #[error("invalid cluster state expiry: {0}")]
    InvalidTtl(String),
    /// Typed payload serialization failed.
    #[error("serialize cluster state: {0}")]
    Serialize(String),
    /// Serialized envelope exceeded the transport bound.
    #[error("cluster state payload is {size} bytes; maximum is {maximum}")]
    PayloadTooLarge {
        /// Serialized envelope size.
        size: usize,
        /// Maximum accepted envelope size.
        maximum: usize,
    },
    /// Distributed owner could not be reached for a write.
    #[error("cluster state transport: {0}")]
    Transport(String),
    /// A publisher attempted to replace a newer generation.
    #[error("stale cluster state generation {attempted}; current is {current}")]
    StaleGeneration {
        /// Current stored generation.
        current: u64,
        /// Attempted older generation.
        attempted: u64,
    },
    /// One generation was reused for different immutable contents.
    #[error("cluster state generation {generation} was reused with different contents")]
    GenerationConflict {
        /// Reused generation.
        generation: u64,
    },
    /// System clock could not produce a Unix timestamp.
    #[error("cluster state clock is before the Unix epoch")]
    Clock,
    /// This handle has no enrolled peer identity authenticator.
    #[error("cluster peer authentication is unavailable")]
    AuthenticationUnavailable,
    /// A peer identity payload could not be signed or verified.
    #[error("cluster peer authentication failed: {0}")]
    Authentication(String),
}

/// Validated typed state and its transport metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterStateRecord<T> {
    /// Publisher node ID.
    pub publisher_node_id: String,
    /// Payload schema version.
    pub schema_version: u32,
    /// Publisher-monotonic generation.
    pub generation: u64,
    /// Unix publication time in milliseconds.
    pub published_at_unix_ms: u64,
    /// Unix expiry time in milliseconds.
    pub expires_at_unix_ms: u64,
    /// Authority-signed enrolled publisher claims when canonical mTLS is active.
    pub authenticated_identity: Option<Box<crate::peer_identity::AuthenticatedPeerIdentity>>,
    /// Decoded typed payload.
    pub payload: T,
}

/// Result of reading one typed cluster-state key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterStateRead<T> {
    /// A current compatible value was decoded.
    Present(ClusterStateRecord<T>),
    /// The state key has no value.
    Missing,
    /// The stored value passed its absolute expiry.
    Expired {
        /// Expired generation.
        generation: u64,
        /// Absolute expiry time in Unix milliseconds.
        expires_at_unix_ms: u64,
    },
    /// The stored payload uses a schema this consumer cannot normalize.
    IncompatibleSchema {
        /// Schema requested by the consumer.
        expected: u32,
        /// Schema carried by the stored envelope.
        actual: u32,
        /// Stored generation.
        generation: u64,
    },
    /// Membership named an owner but its transport was unavailable.
    Unreachable {
        /// State owner selected by the distributed hash ring.
        owner: String,
    },
    /// Envelope metadata or typed payload was malformed.
    Malformed {
        /// Bounded decode or validation reason.
        reason: String,
    },
}

/// Live state or a deletion marker in a versioned mesh register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterVersionedStateKind {
    /// Application payload may be consumed normally.
    Live,
    /// Application payload represents a retained deletion marker.
    Tombstone,
}

/// Validated value and convergence metadata from a versioned mesh register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterVersionedStateRecord<T> {
    /// Publisher node ID authenticated by the inner state envelope.
    pub publisher_node_id: String,
    /// Payload schema version.
    pub schema_version: u32,
    /// Monotonic application version.
    pub logical_version: u64,
    /// Logical version extended by this update.
    pub parent_logical_version: Option<u64>,
    /// Unix publication time in milliseconds.
    pub published_at_unix_ms: u64,
    /// Unix expiry time in milliseconds.
    pub expires_at_unix_ms: u64,
    /// Authority-signed enrolled publisher claims when canonical mTLS is active.
    pub authenticated_identity: Option<Box<crate::peer_identity::AuthenticatedPeerIdentity>>,
    /// Live state or a retained deletion marker.
    pub kind: ClusterVersionedStateKind,
    /// Whether deterministic merge observed competing equal-version updates.
    pub conflict_detected: bool,
    /// Decoded application payload.
    pub payload: T,
}

/// Result of reading one versioned typed cluster-state key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterVersionedStateRead<T> {
    /// A current compatible value was decoded.
    Present(ClusterVersionedStateRecord<T>),
    /// The state key has no value.
    Missing,
    /// The stored value passed its absolute expiry.
    Expired {
        /// Expired logical version.
        logical_version: u64,
        /// Absolute expiry time in Unix milliseconds.
        expires_at_unix_ms: u64,
    },
    /// The stored payload uses a schema this consumer cannot normalize.
    IncompatibleSchema {
        /// Schema requested by the consumer.
        expected: u32,
        /// Schema carried by the stored envelope.
        actual: u32,
        /// Stored logical version.
        logical_version: u64,
    },
    /// Membership named an owner but its transport was unavailable.
    Unreachable {
        /// State owner selected by the distributed hash ring.
        owner: String,
    },
    /// Register, envelope metadata, or typed payload was malformed.
    Malformed {
        /// Bounded decode or validation reason.
        reason: String,
    },
}

/// Bounded deterministic list of keys currently owned by this mesh node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterStateKeySnapshot {
    /// Namespace-relative keys in lexicographic order.
    pub keys: Vec<String>,
    /// Whether additional local keys were excluded by the requested bound.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClusterStateEnvelope {
    namespace: String,
    key: String,
    publisher_node_id: String,
    schema_version: u32,
    generation: u64,
    published_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_proof: Option<crate::peer_identity::PeerIdentityProof>,
}

const CLUSTER_STATE_PROOF_CONTEXT: &str = "sbproxy.cluster-state.v1";

#[derive(Serialize)]
struct ClusterStateSigningPayload<'a> {
    namespace: &'a str,
    key: &'a str,
    publisher_node_id: &'a str,
    schema_version: u32,
    generation: u64,
    published_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    payload: &'a serde_json::Value,
}

fn cluster_state_signing_bytes(envelope: &ClusterStateEnvelope) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&ClusterStateSigningPayload {
        namespace: &envelope.namespace,
        key: &envelope.key,
        publisher_node_id: &envelope.publisher_node_id,
        schema_version: envelope.schema_version,
        generation: envelope.generation,
        published_at_unix_ms: envelope.published_at_unix_ms,
        expires_at_unix_ms: envelope.expires_at_unix_ms,
        payload: &envelope.payload,
    })
}

enum ClusterBackend {
    Local { state: Arc<DistributedCache<Bytes>> },
    Distributed { mesh: Arc<MeshNode> },
}

struct ClusterInner {
    identity: ClusterIdentity,
    backend: ClusterBackend,
    publish_lock: tokio::sync::Mutex<()>,
}

/// Cloneable process-wide cluster substrate.
#[derive(Clone)]
pub struct ClusterHandle {
    inner: Arc<ClusterInner>,
}

impl std::fmt::Debug for ClusterHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClusterHandle")
            .field("identity", &self.inner.identity)
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl ClusterHandle {
    /// Create a one-node handle with no network or background tasks.
    pub fn local(identity: ClusterIdentity) -> Result<Self, ClusterStateError> {
        identity.validate()?;
        let state = Arc::new(DistributedCache::new(&identity.node_id, 1));
        Ok(Self {
            inner: Arc::new(ClusterInner {
                identity,
                backend: ClusterBackend::Local { state },
                publish_lock: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Wrap one already-bootstrapped mesh node.
    pub fn distributed(
        identity: ClusterIdentity,
        mesh: Arc<MeshNode>,
    ) -> Result<Self, ClusterStateError> {
        identity.validate()?;
        if identity.node_id != mesh.node_id() {
            return Err(ClusterStateError::InvalidIdentity(format!(
                "installed node ID {:?} does not match mesh node ID {:?}",
                identity.node_id,
                mesh.node_id()
            )));
        }
        Ok(Self {
            inner: Arc::new(ClusterInner {
                identity,
                backend: ClusterBackend::Distributed { mesh },
                publish_lock: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Whether two handles refer to the same process-owned allocation.
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        Arc::ptr_eq(&left.inner, &right.inner)
    }

    /// Immutable installed identity.
    pub fn identity(&self) -> &ClusterIdentity {
        &self.inner.identity
    }

    /// Sign a domain-separated application payload with this node's enrolled identity.
    pub fn sign_peer_payload(
        &self,
        context: &str,
        payload: &[u8],
    ) -> Result<crate::peer_identity::PeerIdentityProof, ClusterStateError> {
        self.identity_authenticator()
            .ok_or(ClusterStateError::AuthenticationUnavailable)?
            .sign(context, payload)
            .map_err(|error| ClusterStateError::Authentication(error.to_string()))
    }

    /// Verify a domain-separated application payload and return enrolled peer claims.
    pub fn verify_peer_payload(
        &self,
        context: &str,
        payload: &[u8],
        expected_node_id: Option<&str>,
        proof: &crate::peer_identity::PeerIdentityProof,
    ) -> Result<crate::peer_identity::AuthenticatedPeerIdentity, ClusterStateError> {
        self.identity_authenticator()
            .ok_or(ClusterStateError::AuthenticationUnavailable)?
            .verify(context, payload, expected_node_id, proof)
            .map_err(|error| ClusterStateError::Authentication(error.to_string()))
    }

    /// Selected local or distributed implementation.
    pub fn mode(&self) -> ClusterMode {
        match &self.inner.backend {
            ClusterBackend::Local { .. } => ClusterMode::Local,
            ClusterBackend::Distributed { .. } => ClusterMode::Distributed,
        }
    }

    /// Wrapped mesh node, only in distributed mode.
    pub fn mesh_node(&self) -> Option<Arc<MeshNode>> {
        match &self.inner.backend {
            ClusterBackend::Local { .. } => None,
            ClusterBackend::Distributed { mesh } => Some(Arc::clone(mesh)),
        }
    }

    /// Existing isolation observer, only when distributed gossip started.
    pub fn isolation_observer(&self) -> Option<Arc<IsolationObserver>> {
        self.mesh_node().and_then(|mesh| mesh.isolation_observer())
    }

    /// Whether the distributed peer transport bound successfully.
    pub fn has_peer_transport(&self) -> bool {
        self.mesh_node().is_some_and(|mesh| mesh.has_transport())
    }

    /// Point-in-time membership with deterministic node ordering.
    pub fn membership(&self) -> Vec<ClusterMember> {
        let mut members = vec![ClusterMember {
            node_id: self.inner.identity.node_id.clone(),
            address: self.inner.identity.peer_address.clone(),
            state: ClusterMemberState::Alive,
            last_ack_age: Duration::ZERO,
            incarnation: 0,
        }];
        let Some(mesh) = self.mesh_node() else {
            return members;
        };
        let Some(table) = mesh.peer_table() else {
            return members;
        };
        let reachable = {
            let addresses = mesh.peer_addr_map();
            let addresses = addresses
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            addresses.keys().cloned().collect::<BTreeSet<_>>()
        };
        let table = table
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        members.extend(table.iter().filter_map(|peer| {
            if peer.node_id.is_empty() || peer.node_id == self.inner.identity.node_id {
                return None;
            }
            Some(member_from_peer(peer, reachable.contains(&peer.node_id)))
        }));
        members.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        members
    }

    /// Publish one namespaced typed value with generation and expiry fencing.
    pub async fn publish_state<T: Serialize>(
        &self,
        namespace: &str,
        key: &str,
        schema_version: u32,
        generation: u64,
        ttl: Duration,
        payload: &T,
    ) -> Result<(), ClusterStateError> {
        validate_state_component("namespace", namespace)?;
        validate_state_component("key", key)?;
        if ttl.is_zero() || ttl > MAX_STATE_TTL {
            return Err(ClusterStateError::InvalidTtl(format!(
                "TTL must be in the range 1ms through {}s",
                MAX_STATE_TTL.as_secs()
            )));
        }
        let payload = serde_json::to_value(payload)
            .map_err(|error| ClusterStateError::Serialize(error.to_string()))?;
        let _publish_guard = self.inner.publish_lock.lock().await;
        let now = unix_time_ms()?;
        let ttl_ms = u64::try_from(ttl.as_millis()).map_err(|_| {
            ClusterStateError::InvalidTtl("TTL millisecond value overflowed".to_string())
        })?;
        let expires_at_unix_ms = now.checked_add(ttl_ms.max(1)).ok_or_else(|| {
            ClusterStateError::InvalidTtl("absolute expiry overflowed".to_string())
        })?;
        let storage_key = storage_key(namespace, key);

        if let RawStateRead::Present(bytes) = self.read_raw(&storage_key).await {
            if let Ok(current) = serde_json::from_slice::<ClusterStateEnvelope>(&bytes) {
                let current_is_ours = current.publisher_node_id == self.inner.identity.node_id;
                let current_is_authenticated = self.verify_envelope_identity(&current).is_ok();
                if current_is_ours
                    && current_is_authenticated
                    && current.generation > generation
                    && current.expires_at_unix_ms > now
                {
                    return Err(ClusterStateError::StaleGeneration {
                        current: current.generation,
                        attempted: generation,
                    });
                }
                if current_is_ours
                    && current_is_authenticated
                    && current.generation == generation
                    && current.expires_at_unix_ms > now
                    && (current.namespace != namespace
                        || current.key != key
                        || current.publisher_node_id != self.inner.identity.node_id
                        || current.schema_version != schema_version
                        || current.payload != payload)
                {
                    return Err(ClusterStateError::GenerationConflict { generation });
                }
            }
        }

        let mut envelope = ClusterStateEnvelope {
            namespace: namespace.to_string(),
            key: key.to_string(),
            publisher_node_id: self.inner.identity.node_id.clone(),
            schema_version,
            generation,
            published_at_unix_ms: now,
            expires_at_unix_ms,
            payload,
            identity_proof: None,
        };
        if let Some(authenticator) = self.identity_authenticator() {
            let signing_bytes = cluster_state_signing_bytes(&envelope)
                .map_err(|error| ClusterStateError::Serialize(error.to_string()))?;
            envelope.identity_proof = Some(
                authenticator
                    .sign(CLUSTER_STATE_PROOF_CONTEXT, &signing_bytes)
                    .map_err(|error| ClusterStateError::Serialize(error.to_string()))?,
            );
        }
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|error| ClusterStateError::Serialize(error.to_string()))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ClusterStateError::PayloadTooLarge {
                size: bytes.len(),
                maximum: MAX_STATE_BYTES,
            });
        }
        self.write_raw(
            &storage_key,
            Bytes::from(bytes),
            ttl.as_secs()
                .saturating_add(u64::from(ttl.subsec_nanos() > 0)),
        )
        .await
    }

    /// Atomically merge one typed value through the version-aware LWW owner.
    #[allow(clippy::too_many_arguments)]
    pub async fn merge_versioned_state<T: Serialize>(
        &self,
        namespace: &str,
        key: &str,
        schema_version: u32,
        logical_version: u64,
        parent_logical_version: Option<u64>,
        kind: ClusterVersionedStateKind,
        ttl: Duration,
        payload: &T,
    ) -> Result<VersionedLwwMergeOutcome, ClusterStateError> {
        validate_state_component("namespace", namespace)?;
        validate_state_component("key", key)?;
        if ttl.is_zero() || ttl > MAX_STATE_TTL {
            return Err(ClusterStateError::InvalidTtl(format!(
                "TTL must be in the range 1ms through {}s",
                MAX_STATE_TTL.as_secs()
            )));
        }
        let payload = serde_json::to_value(payload)
            .map_err(|error| ClusterStateError::Serialize(error.to_string()))?;
        let now = unix_time_ms()?;
        let ttl_ms = u64::try_from(ttl.as_millis()).map_err(|_| {
            ClusterStateError::InvalidTtl("TTL millisecond value overflowed".to_string())
        })?;
        let expires_at_unix_ms = now.checked_add(ttl_ms.max(1)).ok_or_else(|| {
            ClusterStateError::InvalidTtl("absolute expiry overflowed".to_string())
        })?;
        let mut envelope = ClusterStateEnvelope {
            namespace: namespace.to_string(),
            key: key.to_string(),
            publisher_node_id: self.inner.identity.node_id.clone(),
            schema_version,
            generation: logical_version,
            published_at_unix_ms: now,
            expires_at_unix_ms,
            payload,
            identity_proof: None,
        };
        if let Some(authenticator) = self.identity_authenticator() {
            let signing_bytes = cluster_state_signing_bytes(&envelope)
                .map_err(|error| ClusterStateError::Serialize(error.to_string()))?;
            envelope.identity_proof = Some(
                authenticator
                    .sign(CLUSTER_STATE_PROOF_CONTEXT, &signing_bytes)
                    .map_err(|error| ClusterStateError::Serialize(error.to_string()))?,
            );
        }
        let envelope = serde_json::to_string(&envelope)
            .map_err(|error| ClusterStateError::Serialize(error.to_string()))?;
        let register = match kind {
            ClusterVersionedStateKind::Live => VersionedLwwRegister::live(
                envelope,
                &self.inner.identity.node_id,
                now,
                logical_version,
                parent_logical_version,
            ),
            ClusterVersionedStateKind::Tombstone => VersionedLwwRegister::tombstone(
                envelope,
                &self.inner.identity.node_id,
                now,
                logical_version,
                parent_logical_version,
            ),
        };
        let bytes = serde_json::to_vec(&register)
            .map_err(|error| ClusterStateError::Serialize(error.to_string()))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ClusterStateError::PayloadTooLarge {
                size: bytes.len(),
                maximum: MAX_STATE_BYTES,
            });
        }
        let storage_key = storage_key(namespace, key);
        let ttl_secs = ttl
            .as_secs()
            .saturating_add(u64::from(ttl.subsec_nanos() > 0));
        match &self.inner.backend {
            ClusterBackend::Local { state } => state
                .merge_versioned_local_with_ttl(&storage_key, Bytes::from(bytes), ttl_secs)
                .map_err(|error| ClusterStateError::Transport(error.to_string())),
            ClusterBackend::Distributed { mesh } => mesh
                .distributed_cache()
                .merge_versioned_routed_with_ttl(
                    &storage_key,
                    Bytes::from(bytes),
                    ttl_secs,
                    &mesh.transport_pool(),
                    mesh.peer_addr_lookup(),
                )
                .await
                .map_err(|error| ClusterStateError::Transport(error.to_string())),
        }
    }

    /// Read and decode one versioned typed value.
    pub async fn read_versioned_state<T: DeserializeOwned>(
        &self,
        namespace: &str,
        key: &str,
        expected_schema: u32,
    ) -> ClusterVersionedStateRead<T> {
        match self.read_versioned_state_value(namespace, key).await {
            ClusterVersionedStateRead::Present(record)
                if record.schema_version != expected_schema =>
            {
                ClusterVersionedStateRead::IncompatibleSchema {
                    expected: expected_schema,
                    actual: record.schema_version,
                    logical_version: record.logical_version,
                }
            }
            ClusterVersionedStateRead::Present(record) => {
                let payload = match serde_json::from_value(record.payload) {
                    Ok(payload) => payload,
                    Err(_) => {
                        return ClusterVersionedStateRead::Malformed {
                            reason: "decode typed payload failed".to_string(),
                        };
                    }
                };
                ClusterVersionedStateRead::Present(ClusterVersionedStateRecord {
                    publisher_node_id: record.publisher_node_id,
                    schema_version: record.schema_version,
                    logical_version: record.logical_version,
                    parent_logical_version: record.parent_logical_version,
                    published_at_unix_ms: record.published_at_unix_ms,
                    expires_at_unix_ms: record.expires_at_unix_ms,
                    authenticated_identity: record.authenticated_identity,
                    kind: record.kind,
                    conflict_detected: record.conflict_detected,
                    payload,
                })
            }
            ClusterVersionedStateRead::Missing => ClusterVersionedStateRead::Missing,
            ClusterVersionedStateRead::Expired {
                logical_version,
                expires_at_unix_ms,
            } => ClusterVersionedStateRead::Expired {
                logical_version,
                expires_at_unix_ms,
            },
            ClusterVersionedStateRead::IncompatibleSchema { .. } => unreachable!(
                "schema-agnostic versioned state reads never return an incompatibility"
            ),
            ClusterVersionedStateRead::Unreachable { owner } => {
                ClusterVersionedStateRead::Unreachable { owner }
            }
            ClusterVersionedStateRead::Malformed { reason } => {
                ClusterVersionedStateRead::Malformed { reason }
            }
        }
    }

    /// Read one versioned state register without imposing a payload schema.
    pub async fn read_versioned_state_value(
        &self,
        namespace: &str,
        key: &str,
    ) -> ClusterVersionedStateRead<serde_json::Value> {
        if let Err(error) = validate_state_component("namespace", namespace)
            .and_then(|_| validate_state_component("key", key))
        {
            return ClusterVersionedStateRead::Malformed {
                reason: error.to_string(),
            };
        }
        let storage_key = storage_key(namespace, key);
        let bytes = match self.read_raw(&storage_key).await {
            RawStateRead::Present(bytes) => bytes,
            RawStateRead::Missing => return ClusterVersionedStateRead::Missing,
            RawStateRead::Unreachable(owner) => {
                return ClusterVersionedStateRead::Unreachable { owner };
            }
        };
        if bytes.len() > MAX_STATE_BYTES {
            return ClusterVersionedStateRead::Malformed {
                reason: format!(
                    "versioned register is {} bytes; maximum is {MAX_STATE_BYTES}",
                    bytes.len()
                ),
            };
        }
        let register = match serde_json::from_slice::<VersionedLwwRegister>(&bytes) {
            Ok(register) => register,
            Err(_) => {
                return ClusterVersionedStateRead::Malformed {
                    reason: "decode versioned register failed".to_string(),
                };
            }
        };
        let envelope = match register
            .value()
            .and_then(|value| serde_json::from_str::<ClusterStateEnvelope>(value).ok())
        {
            Some(envelope) => envelope,
            None => {
                return ClusterVersionedStateRead::Malformed {
                    reason: "decode versioned state envelope failed".to_string(),
                };
            }
        };
        if envelope.namespace != namespace
            || envelope.key != key
            || envelope.publisher_node_id != register.node_id()
            || envelope.generation != register.logical_version()
            || envelope.published_at_unix_ms != register.timestamp_ms()
        {
            return ClusterVersionedStateRead::Malformed {
                reason: "versioned register metadata does not match its signed envelope"
                    .to_string(),
            };
        }
        if envelope.publisher_node_id.is_empty()
            || envelope.publisher_node_id.len() > MAX_IDENTITY_LEN
        {
            return ClusterVersionedStateRead::Malformed {
                reason: "publisher node ID is empty or oversized".to_string(),
            };
        }
        let authenticated_identity = match self.verify_envelope_identity(&envelope) {
            Ok(identity) => identity.map(Box::new),
            Err(reason) => return ClusterVersionedStateRead::Malformed { reason },
        };
        let now = match unix_time_ms() {
            Ok(now) => now,
            Err(error) => {
                return ClusterVersionedStateRead::Malformed {
                    reason: error.to_string(),
                };
            }
        };
        if envelope.expires_at_unix_ms <= now {
            return ClusterVersionedStateRead::Expired {
                logical_version: register.logical_version(),
                expires_at_unix_ms: envelope.expires_at_unix_ms,
            };
        }
        if envelope.published_at_unix_ms > envelope.expires_at_unix_ms {
            return ClusterVersionedStateRead::Malformed {
                reason: "publication time is after expiry".to_string(),
            };
        }
        ClusterVersionedStateRead::Present(ClusterVersionedStateRecord {
            publisher_node_id: envelope.publisher_node_id,
            schema_version: envelope.schema_version,
            logical_version: register.logical_version(),
            parent_logical_version: register.parent_logical_version(),
            published_at_unix_ms: envelope.published_at_unix_ms,
            expires_at_unix_ms: envelope.expires_at_unix_ms,
            authenticated_identity,
            kind: if register.is_tombstone() {
                ClusterVersionedStateKind::Tombstone
            } else {
                ClusterVersionedStateKind::Live
            },
            conflict_detected: register.conflict_detected(),
            payload: envelope.payload,
        })
    }

    /// Snapshot a bounded, sorted set of keys currently owned by this node.
    pub fn local_state_key_snapshot(
        &self,
        namespace: &str,
        maximum: usize,
    ) -> Result<ClusterStateKeySnapshot, ClusterStateError> {
        validate_state_component("namespace", namespace)?;
        let prefix = format!("{STATE_KEY_PREFIX}:{namespace}:");
        let snapshot = self
            .state_cache()
            .snapshot_prefix_local(&prefix, maximum)
            .map_err(|_| {
                ClusterStateError::InvalidKey(
                    "local state snapshot limit must be in the range 1 through 4096".to_string(),
                )
            })?;
        let keys = snapshot
            .entries
            .into_iter()
            .map(|(storage_key, _)| {
                storage_key
                    .strip_prefix(&prefix)
                    .expect("snapshot prefix already matched")
                    .to_string()
            })
            .collect();
        Ok(ClusterStateKeySnapshot {
            keys,
            truncated: snapshot.truncated,
        })
    }

    /// Read and decode one namespaced typed value.
    pub async fn read_state<T: DeserializeOwned>(
        &self,
        namespace: &str,
        key: &str,
        expected_schema: u32,
    ) -> ClusterStateRead<T> {
        match self.read_state_value(namespace, key).await {
            ClusterStateRead::Present(record) if record.schema_version != expected_schema => {
                ClusterStateRead::IncompatibleSchema {
                    expected: expected_schema,
                    actual: record.schema_version,
                    generation: record.generation,
                }
            }
            ClusterStateRead::Present(record) => {
                let payload = match serde_json::from_value(record.payload) {
                    Ok(payload) => payload,
                    Err(_) => {
                        return ClusterStateRead::Malformed {
                            reason: "decode typed payload failed".to_string(),
                        };
                    }
                };
                ClusterStateRead::Present(ClusterStateRecord {
                    publisher_node_id: record.publisher_node_id,
                    schema_version: record.schema_version,
                    generation: record.generation,
                    published_at_unix_ms: record.published_at_unix_ms,
                    expires_at_unix_ms: record.expires_at_unix_ms,
                    authenticated_identity: record.authenticated_identity,
                    payload,
                })
            }
            ClusterStateRead::Missing => ClusterStateRead::Missing,
            ClusterStateRead::Expired {
                generation,
                expires_at_unix_ms,
            } => ClusterStateRead::Expired {
                generation,
                expires_at_unix_ms,
            },
            ClusterStateRead::Unreachable { owner } => ClusterStateRead::Unreachable { owner },
            ClusterStateRead::Malformed { reason } => ClusterStateRead::Malformed { reason },
            ClusterStateRead::IncompatibleSchema { .. } => {
                unreachable!("schema-agnostic cluster state reads never return an incompatibility")
            }
        }
    }

    /// Read one current state envelope without imposing a payload schema.
    pub async fn read_state_value(
        &self,
        namespace: &str,
        key: &str,
    ) -> ClusterStateRead<serde_json::Value> {
        if let Err(error) = validate_state_component("namespace", namespace)
            .and_then(|_| validate_state_component("key", key))
        {
            return ClusterStateRead::Malformed {
                reason: error.to_string(),
            };
        }
        let storage_key = storage_key(namespace, key);
        let bytes = match self.read_raw(&storage_key).await {
            RawStateRead::Present(bytes) => bytes,
            RawStateRead::Missing => return ClusterStateRead::Missing,
            RawStateRead::Unreachable(owner) => {
                return ClusterStateRead::Unreachable { owner };
            }
        };
        if bytes.len() > MAX_STATE_BYTES {
            return ClusterStateRead::Malformed {
                reason: format!(
                    "envelope is {} bytes; maximum is {MAX_STATE_BYTES}",
                    bytes.len()
                ),
            };
        }
        let envelope = match serde_json::from_slice::<ClusterStateEnvelope>(&bytes) {
            Ok(envelope) => envelope,
            Err(_) => {
                return ClusterStateRead::Malformed {
                    reason: "decode envelope failed".to_string(),
                };
            }
        };
        if envelope.namespace != namespace || envelope.key != key {
            return ClusterStateRead::Malformed {
                reason: "envelope namespace or key does not match its storage key".to_string(),
            };
        }
        if envelope.publisher_node_id.is_empty()
            || envelope.publisher_node_id.len() > MAX_IDENTITY_LEN
        {
            return ClusterStateRead::Malformed {
                reason: "publisher node ID is empty or oversized".to_string(),
            };
        }
        let authenticated_identity = match self.verify_envelope_identity(&envelope) {
            Ok(identity) => identity.map(Box::new),
            Err(reason) => return ClusterStateRead::Malformed { reason },
        };
        let now = match unix_time_ms() {
            Ok(now) => now,
            Err(error) => {
                return ClusterStateRead::Malformed {
                    reason: error.to_string(),
                };
            }
        };
        if envelope.expires_at_unix_ms <= now {
            return ClusterStateRead::Expired {
                generation: envelope.generation,
                expires_at_unix_ms: envelope.expires_at_unix_ms,
            };
        }
        if envelope.published_at_unix_ms > envelope.expires_at_unix_ms {
            return ClusterStateRead::Malformed {
                reason: "publication time is after expiry".to_string(),
            };
        }
        ClusterStateRead::Present(ClusterStateRecord {
            publisher_node_id: envelope.publisher_node_id,
            schema_version: envelope.schema_version,
            generation: envelope.generation,
            published_at_unix_ms: envelope.published_at_unix_ms,
            expires_at_unix_ms: envelope.expires_at_unix_ms,
            authenticated_identity,
            payload: envelope.payload,
        })
    }

    fn identity_authenticator(
        &self,
    ) -> Option<Arc<crate::peer_identity::PeerIdentityAuthenticator>> {
        self.mesh_node()
            .and_then(|mesh| mesh.identity_authenticator())
    }

    fn verify_envelope_identity(
        &self,
        envelope: &ClusterStateEnvelope,
    ) -> Result<Option<crate::peer_identity::AuthenticatedPeerIdentity>, String> {
        let Some(authenticator) = self.identity_authenticator() else {
            return Ok(None);
        };
        let proof = envelope.identity_proof.as_ref().ok_or_else(|| {
            "canonical mTLS state is missing its enrolled identity proof".to_string()
        })?;
        let signing_bytes = cluster_state_signing_bytes(envelope)
            .map_err(|_| "encode state identity proof payload failed".to_string())?;
        authenticator
            .verify(
                CLUSTER_STATE_PROOF_CONTEXT,
                &signing_bytes,
                Some(&envelope.publisher_node_id),
                proof,
            )
            .map(Some)
            .map_err(|error| format!("verify enrolled state publisher failed: {error}"))
    }

    fn state_cache(&self) -> Arc<DistributedCache<Bytes>> {
        match &self.inner.backend {
            ClusterBackend::Local { state } => Arc::clone(state),
            ClusterBackend::Distributed { mesh } => mesh.distributed_cache(),
        }
    }

    async fn read_raw(&self, storage_key: &str) -> RawStateRead {
        let cache = self.state_cache();
        let owner = cache
            .responsible_node(storage_key)
            .unwrap_or_else(|| self.inner.identity.node_id.clone());
        if owner == cache.local_node_id() {
            return cache
                .get_local(storage_key)
                .map_or(RawStateRead::Missing, RawStateRead::Present);
        }
        let Some(mesh) = self.mesh_node() else {
            return RawStateRead::Unreachable(owner);
        };
        let address = {
            let addresses = mesh.peer_addr_map();
            let guard = addresses
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.get(&owner).cloned()
        };
        let Some(address) = address else {
            return RawStateRead::Unreachable(owner);
        };
        let Some(client) = mesh.transport_pool().try_client_for_node(&owner, &address) else {
            return RawStateRead::Unreachable(owner);
        };
        match client.get(storage_key.to_string()).await {
            Ok(Some(bytes)) => RawStateRead::Present(bytes),
            Ok(None) => RawStateRead::Missing,
            Err(_) => RawStateRead::Unreachable(owner),
        }
    }

    async fn write_raw(
        &self,
        storage_key: &str,
        value: Bytes,
        ttl_secs: u64,
    ) -> Result<(), ClusterStateError> {
        match &self.inner.backend {
            ClusterBackend::Local { state } => {
                state.put_local_with_ttl(storage_key, value, ttl_secs);
                Ok(())
            }
            ClusterBackend::Distributed { mesh } => mesh
                .distributed_cache()
                .put_routed_with_ttl(
                    storage_key,
                    value,
                    ttl_secs,
                    &mesh.transport_pool(),
                    mesh.peer_addr_lookup(),
                )
                .await
                .map_err(|error| ClusterStateError::Transport(error.to_string())),
        }
    }
}

enum RawStateRead {
    Present(Bytes),
    Missing,
    Unreachable(String),
}

fn member_from_peer(peer: &PeerEntry, reachable: bool) -> ClusterMember {
    let state = match peer.state {
        PeerState::Alive if reachable => ClusterMemberState::Alive,
        PeerState::Alive => ClusterMemberState::Unreachable,
        PeerState::Suspect { .. } => ClusterMemberState::Suspect,
        PeerState::Dead => ClusterMemberState::Dead,
    };
    ClusterMember {
        node_id: peer.node_id.clone(),
        address: Some(peer.addr.clone()),
        state,
        last_ack_age: peer.last_ack.elapsed(),
        incarnation: peer.incarnation,
    }
}

fn validate_state_component(field: &str, value: &str) -> Result<(), ClusterStateError> {
    if value.is_empty()
        || value.len() > MAX_STATE_COMPONENT_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ClusterStateError::InvalidKey(format!(
            "{field} must contain at most {MAX_STATE_COMPONENT_LEN} ASCII letters, digits, dots, dashes, or underscores"
        )));
    }
    Ok(())
}

fn storage_key(namespace: &str, key: &str) -> String {
    format!("{STATE_KEY_PREFIX}:{namespace}:{key}")
}

fn unix_time_ms() -> Result<u64, ClusterStateError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClusterStateError::Clock)?
        .as_millis();
    u64::try_from(millis).map_err(|_| ClusterStateError::Clock)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Instant;

    use super::*;

    fn enrolled_handle() -> (tempfile::TempDir, ClusterHandle) {
        use crate::enrollment::{AuthorityInit, EnrollmentAuthority};
        use crate::transport::tls::MeshTlsConfig;

        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("authority");
        let authority = EnrollmentAuthority::initialize(
            &directory,
            AuthorityInit {
                cluster_id: "cluster-a".to_string(),
                node_id: "authority-a".to_string(),
                roles: BTreeSet::from([ClusterNodeRole::Authority, ClusterNodeRole::Gateway]),
                labels: BTreeMap::from([("zone".to_string(), "west-a".to_string())]),
                server_name: "sbproxy-mesh".to_string(),
            },
        )
        .unwrap();
        let identity = authority.identity().document.to_cluster_identity().unwrap();
        let tls = MeshTlsConfig {
            cert_pem: std::fs::read_to_string(directory.join("node.pem")).unwrap(),
            key_pem: std::fs::read_to_string(directory.join("node-key.pem")).unwrap(),
            ca_pem: std::fs::read_to_string(directory.join("ca.pem")).unwrap(),
        };
        let authenticator = crate::peer_identity::PeerIdentityAuthenticator::load_installed(
            &directory,
            &identity,
            "sbproxy-mesh",
            &tls,
        )
        .unwrap();
        let mesh = MeshNode::new(identity.node_id.clone(), Vec::new(), 16)
            .with_identity_authenticator(Some(Arc::new(authenticator)));
        let handle = ClusterHandle::distributed(identity, Arc::new(mesh)).unwrap();
        (temp, handle)
    }

    #[test]
    fn peer_membership_maps_every_liveness_state() {
        let now = Instant::now();
        let mut peer = PeerEntry::new("worker-b", "127.0.0.1:7947", now);
        assert_eq!(
            member_from_peer(&peer, true).state,
            ClusterMemberState::Alive
        );
        assert_eq!(
            member_from_peer(&peer, false).state,
            ClusterMemberState::Unreachable
        );
        peer.state = PeerState::Suspect { since: now };
        assert_eq!(
            member_from_peer(&peer, true).state,
            ClusterMemberState::Suspect
        );
        peer.state = PeerState::Dead;
        assert_eq!(
            member_from_peer(&peer, true).state,
            ClusterMemberState::Dead
        );
    }

    #[test]
    fn model_endpoint_identity_must_be_an_absolute_origin() {
        for endpoint in [
            "https://worker-a.internal:9443/models",
            "https://worker-a.internal:9443?debug=1",
            "https://worker-a.internal:9443#fragment",
        ] {
            let identity = ClusterIdentity {
                cluster_id: "cluster-a".to_string(),
                node_id: "worker-a".to_string(),
                roles: BTreeSet::from([ClusterNodeRole::Worker]),
                labels: BTreeMap::new(),
                peer_address: None,
                model_endpoint: Some(endpoint.to_string()),
            };

            assert!(identity.validate().is_err(), "{endpoint}");
        }
    }

    #[tokio::test]
    async fn malformed_envelope_is_reported_without_raw_bytes() {
        let handle = ClusterHandle::local(ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "worker-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        })
        .expect("local handle");
        handle.state_cache().put_local(
            &storage_key("model-snapshots", "worker-a"),
            Bytes::from_static(b"not-json"),
        );
        let read = handle
            .read_state::<serde_json::Value>("model-snapshots", "worker-a", 1)
            .await;
        let ClusterStateRead::Malformed { reason } = read else {
            panic!("expected malformed state");
        };
        assert_eq!(reason, "decode envelope failed");
        assert!(!reason.contains("not-json"));
    }

    #[tokio::test]
    async fn canonical_state_binds_payload_and_publisher_to_enrolled_identity() {
        let (_temp, handle) = enrolled_handle();
        handle
            .publish_state(
                "model-snapshots",
                "authority-a",
                1,
                7,
                Duration::from_secs(30),
                &serde_json::json!({"health": "ready"}),
            )
            .await
            .unwrap();
        let present = handle
            .read_state::<serde_json::Value>("model-snapshots", "authority-a", 1)
            .await;
        let ClusterStateRead::Present(record) = present else {
            panic!("expected authenticated state");
        };
        let identity = record.authenticated_identity.expect("enrolled claims");
        assert_eq!(identity.node_id, "authority-a");
        assert!(identity.roles.contains(&ClusterNodeRole::Authority));

        let key = storage_key("model-snapshots", "authority-a");
        let bytes = handle.state_cache().get_local(&key).unwrap();
        let mut envelope: ClusterStateEnvelope = serde_json::from_slice(&bytes).unwrap();
        envelope.payload = serde_json::json!({"health": "forged"});
        envelope.generation = 100;
        handle
            .state_cache()
            .put_local(&key, Bytes::from(serde_json::to_vec(&envelope).unwrap()));
        let tampered = handle
            .read_state::<serde_json::Value>("model-snapshots", "authority-a", 1)
            .await;
        assert!(matches!(tampered, ClusterStateRead::Malformed { .. }));
        handle
            .publish_state(
                "model-snapshots",
                "authority-a",
                1,
                8,
                Duration::from_secs(30),
                &serde_json::json!({"health": "recovered"}),
            )
            .await
            .expect("invalid higher generation cannot suppress an authenticated retry");
        let recovered = handle
            .read_state::<serde_json::Value>("model-snapshots", "authority-a", 1)
            .await;
        assert!(matches!(
            recovered,
            ClusterStateRead::Present(ClusterStateRecord { generation: 8, .. })
        ));
    }

    #[test]
    fn handle_signs_and_verifies_a_domain_separated_peer_payload() {
        let (_temp, handle) = enrolled_handle();
        let proof = handle
            .sign_peer_payload("sbproxy.model-dispatch.v1", b"payload")
            .expect("sign peer payload");
        let identity = handle
            .verify_peer_payload(
                "sbproxy.model-dispatch.v1",
                b"payload",
                Some("authority-a"),
                &proof,
            )
            .expect("verify peer payload");
        assert!(identity.roles.contains(&ClusterNodeRole::Gateway));
        assert!(handle
            .verify_peer_payload(
                "sbproxy.other-context.v1",
                b"payload",
                Some("authority-a"),
                &proof,
            )
            .is_err());

        let local = ClusterHandle::local(ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "worker-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        })
        .expect("local handle");
        assert!(matches!(
            local.sign_peer_payload("sbproxy.model-dispatch.v1", b"payload"),
            Err(ClusterStateError::AuthenticationUnavailable)
        ));
    }
}
