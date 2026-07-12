// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Bounded, versioned worker truth published into cluster state.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AcceleratorKind, ArtifactCacheState, ArtifactFormat, DeploymentRuntimeState,
    DeploymentRuntimeStatus, EngineAvailability, EngineCapabilities, EngineDetection, EngineKind,
    GpuDescriptor, GpuVendor,
};

/// Current node model snapshot schema.
pub const NODE_MODEL_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
/// Typed cluster-state namespace used for node snapshots.
pub const NODE_MODEL_SNAPSHOT_NAMESPACE: &str = "model-snapshots";
/// Maximum accepted serialized snapshot size.
pub const MAX_NODE_MODEL_SNAPSHOT_BYTES: usize = 512 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 256;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_LABELS: usize = 64;
const MAX_ENGINES: usize = 16;
const MAX_DEVICES: usize = 64;
const MAX_ARTIFACTS: usize = 512;
const MAX_REPLICAS: usize = 1_024;
const MAX_ADAPTERS: usize = 64;
const MAX_REASON_CODES: usize = 16;
const MAX_REASON_CODE_BYTES: usize = 64;
const MAX_REQUEST_COUNT: u64 = 1_000_000;
const MAX_PLACEMENT_WEIGHT: u32 = 1_000_000;
const MAX_SNAPSHOT_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const COUNTER_SCHEMA_VERSION: u32 = 1;
const COUNTER_FILE: &str = "node-snapshot-generation.json";
const COUNTER_LOCK_FILE: &str = ".node-snapshot-generation.lock";

/// Snapshot validation, encoding, or durable-generation failure.
#[derive(Debug, thiserror::Error)]
pub enum NodeSnapshotError {
    /// One bounded semantic rule failed.
    #[error("invalid node model snapshot: {0}")]
    Invalid(String),
    /// Strict JSON encoding or decoding failed.
    #[error("node model snapshot JSON {operation} failed: {source}")]
    Json {
        /// Operation that failed.
        operation: &'static str,
        /// JSON failure.
        source: serde_json::Error,
    },
    /// Durable generation storage failed.
    #[error("node model snapshot storage failed: {0}")]
    Io(#[from] std::io::Error),
    /// Durable generation reached its numeric limit.
    #[error("node model snapshot generation overflowed")]
    GenerationOverflow,
}

/// Stable role copied from an authenticated cluster identity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Accept public gateway traffic.
    Gateway,
    /// Host managed model replicas.
    Worker,
    /// Enroll nodes or sign deployment revisions.
    Authority,
}

/// Bounded cluster identity fields needed by placement and routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentitySnapshot {
    /// Stable installed node ID.
    pub node_id: String,
    /// Roles bound to the installed identity.
    pub roles: BTreeSet<NodeRole>,
    /// Placement and failure-domain labels.
    pub labels: BTreeMap<String, String>,
    /// Authenticated private inference endpoint.
    pub model_endpoint: Option<String>,
}

/// Worker-reported health before membership and freshness are joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeHealthState {
    /// Worker is ready for its currently assigned work.
    Ready,
    /// Worker is serving but has an actionable impairment.
    Degraded,
    /// Worker cannot safely receive new model work.
    Unhealthy,
}

/// Worker health and stable redacted reason codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeHealthSnapshot {
    /// Current worker-reported state.
    pub state: NodeHealthState,
    /// Machine-stable reasons, never raw error text.
    pub reason_codes: Vec<String>,
}

/// Engine availability and placement capabilities visible to peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeEngineSnapshot {
    /// Managed engine kind.
    pub engine: EngineKind,
    /// Current driver availability.
    pub availability: EngineAvailability,
    /// Detected or pinned version.
    pub version: Option<String>,
    /// Immutable artifact formats accepted by this driver.
    pub artifact_formats: Vec<ArtifactFormat>,
    /// Accelerators accepted by this driver.
    pub accelerators: BTreeSet<AcceleratorKind>,
    /// Whether an isolated container launch is implemented.
    pub supports_container: bool,
    /// Whether managed uv provisioning is implemented.
    pub supports_uv: bool,
    /// Stable redacted reason for non-availability.
    pub reason_code: Option<String>,
}

/// One complete path-free worker inventory used to build a node snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeSnapshotInventory {
    /// Managed engine capabilities and current availability.
    pub engines: Vec<NodeEngineSnapshot>,
    /// Model-serving hardware.
    pub devices: Vec<NodeDeviceSnapshot>,
    /// Fully inspected local artifact cache entries.
    pub artifacts: Vec<NodeArtifactSnapshot>,
}

impl NodeEngineSnapshot {
    /// Project runtime detection and static capabilities without raw diagnostics.
    pub fn from_runtime(
        detection: &EngineDetection,
        capabilities: &EngineCapabilities,
        reason_code: Option<String>,
    ) -> Result<Self, NodeSnapshotError> {
        let mut artifact_formats = capabilities.artifact_formats.clone();
        artifact_formats.sort_by_key(|format| artifact_format_order(*format));
        artifact_formats.dedup();
        let snapshot = Self {
            engine: detection.kind,
            availability: detection.availability,
            version: detection.version.clone(),
            artifact_formats,
            accelerators: capabilities.accelerators.iter().copied().collect(),
            supports_container: capabilities.supports_container,
            supports_uv: capabilities.supports_uv,
            reason_code,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), NodeSnapshotError> {
        if self.artifact_formats.is_empty() || self.artifact_formats.len() > 8 {
            return invalid("engine artifact formats must contain between 1 and 8 values");
        }
        if has_duplicates(&self.artifact_formats) {
            return invalid("engine artifact formats contain duplicates");
        }
        if self.accelerators.is_empty() || self.accelerators.len() > 4 {
            return invalid("engine accelerators must contain between 1 and 4 values");
        }
        validate_optional_text("engine version", self.version.as_deref(), MAX_TEXT_BYTES)?;
        validate_optional_reason_code(self.reason_code.as_deref())?;
        if self.availability == EngineAvailability::Available && self.reason_code.is_some() {
            return invalid("available engine cannot carry a failure reason");
        }
        if self.availability != EngineAvailability::Available && self.reason_code.is_none() {
            return invalid("non-available engine requires a stable reason code");
        }
        Ok(())
    }
}

/// Comparable compute capability without accepting unknown nested fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeComputeCapability {
    /// Major capability number.
    pub major: u32,
    /// Minor capability number.
    pub minor: u32,
}

/// One model-serving device with no local path or driver handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeDeviceSnapshot {
    /// Worker-local device index.
    pub index: u32,
    /// Hardware vendor.
    pub vendor: GpuVendor,
    /// Catalog accelerator class, absent for an unsupported vendor.
    pub accelerator: Option<AcceleratorKind>,
    /// Bounded operator-facing device name.
    pub name: String,
    /// Total model-serving memory in bytes.
    pub total_memory_bytes: u64,
    /// Available model-serving memory in bytes.
    pub available_memory_bytes: u64,
    /// CUDA compute capability when reported.
    pub compute_capability: Option<NodeComputeCapability>,
    /// Whether the device supports usable FP8 kernels.
    pub supports_fp8: bool,
}

impl TryFrom<GpuDescriptor> for NodeDeviceSnapshot {
    type Error = NodeSnapshotError;

    fn try_from(value: GpuDescriptor) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&GpuDescriptor> for NodeDeviceSnapshot {
    type Error = NodeSnapshotError;

    fn try_from(value: &GpuDescriptor) -> Result<Self, Self::Error> {
        let accelerator = match value.vendor {
            GpuVendor::Nvidia => Some(AcceleratorKind::Cuda),
            GpuVendor::Apple => Some(AcceleratorKind::Metal),
            GpuVendor::Cpu => Some(AcceleratorKind::Cpu),
            GpuVendor::Amd => None,
        };
        let snapshot = Self {
            index: value.index,
            vendor: value.vendor,
            accelerator,
            name: value.name.clone(),
            total_memory_bytes: value.total_vram_bytes,
            available_memory_bytes: value.free_vram_bytes,
            compute_capability: value
                .compute_capability
                .map(|(major, minor)| NodeComputeCapability { major, minor }),
            supports_fp8: value.supports_fp8,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

impl NodeDeviceSnapshot {
    fn validate(&self) -> Result<(), NodeSnapshotError> {
        validate_text("device name", &self.name, MAX_TEXT_BYTES)?;
        if self.total_memory_bytes == 0 || self.available_memory_bytes > self.total_memory_bytes {
            return invalid("device memory totals are invalid");
        }
        let expected_accelerator = match self.vendor {
            GpuVendor::Nvidia => Some(AcceleratorKind::Cuda),
            GpuVendor::Apple => Some(AcceleratorKind::Metal),
            GpuVendor::Cpu => Some(AcceleratorKind::Cpu),
            GpuVendor::Amd => None,
        };
        if self.accelerator != expected_accelerator {
            return invalid("device vendor and accelerator class do not match");
        }
        if self.compute_capability.is_some() && self.vendor != GpuVendor::Nvidia {
            return invalid("compute capability is valid only for NVIDIA devices");
        }
        Ok(())
    }
}

/// Public cache state for one immutable artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeArtifactState {
    /// No cache bytes are present.
    Missing,
    /// Partial safe bytes are retained.
    Partial,
    /// Every declared file was verified.
    Ready,
    /// Ready-looking cache state failed validation.
    Corrupt,
}

impl NodeArtifactState {
    /// Stable snake-case state label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Partial => "partial",
            Self::Ready => "ready",
            Self::Corrupt => "corrupt",
        }
    }
}

/// Path-free local cache truth for one catalog artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeArtifactSnapshot {
    /// Lowercase SHA-256 artifact identity.
    pub artifact_digest: String,
    /// Logical catalog model ID.
    pub model: String,
    /// Exact catalog variant ID.
    pub variant: String,
    /// Current cache state.
    pub state: NodeArtifactState,
    /// Retained or verified bytes.
    pub completed_bytes: u64,
    /// Exact total bytes when the artifact is ready.
    pub total_bytes: Option<u64>,
    /// Last verified access time when ready.
    pub last_accessed_unix_ms: Option<u64>,
    /// Stable redacted cache failure reason.
    pub reason_code: Option<String>,
}

impl NodeArtifactSnapshot {
    /// Project an artifact cache inspection result without retaining its path or raw error.
    pub fn from_cache(
        artifact_digest: &str,
        model: &str,
        variant: &str,
        cache: &ArtifactCacheState,
    ) -> Result<Self, NodeSnapshotError> {
        let (state, completed_bytes, total_bytes, last_accessed_unix_ms, reason_code) = match cache
        {
            ArtifactCacheState::Missing => (NodeArtifactState::Missing, 0, None, None, None),
            ArtifactCacheState::Partial { completed_bytes } => (
                NodeArtifactState::Partial,
                *completed_bytes,
                None,
                None,
                None,
            ),
            ArtifactCacheState::Ready {
                total_size_bytes,
                last_accessed_ms,
                ..
            } => (
                NodeArtifactState::Ready,
                *total_size_bytes,
                Some(*total_size_bytes),
                Some(*last_accessed_ms),
                None,
            ),
            ArtifactCacheState::Corrupt { .. } => (
                NodeArtifactState::Corrupt,
                0,
                None,
                None,
                Some("artifact_corrupt".to_string()),
            ),
        };
        let snapshot = Self {
            artifact_digest: artifact_digest.to_string(),
            model: model.to_string(),
            variant: variant.to_string(),
            state,
            completed_bytes,
            total_bytes,
            last_accessed_unix_ms,
            reason_code,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), NodeSnapshotError> {
        validate_sha256("artifact digest", &self.artifact_digest)?;
        validate_text("artifact model", &self.model, MAX_IDENTIFIER_BYTES)?;
        validate_text("artifact variant", &self.variant, MAX_IDENTIFIER_BYTES)?;
        validate_optional_reason_code(self.reason_code.as_deref())?;
        match self.state {
            NodeArtifactState::Missing => {
                if self.completed_bytes != 0
                    || self.total_bytes.is_some()
                    || self.last_accessed_unix_ms.is_some()
                    || self.reason_code.is_some()
                {
                    return invalid("missing artifact contains ready or failure metadata");
                }
            }
            NodeArtifactState::Partial => {
                if self.completed_bytes == 0
                    || self.total_bytes.is_some()
                    || self.last_accessed_unix_ms.is_some()
                    || self.reason_code.is_some()
                {
                    return invalid("partial artifact metadata is inconsistent");
                }
            }
            NodeArtifactState::Ready => {
                if self.total_bytes != Some(self.completed_bytes)
                    || self.completed_bytes == 0
                    || self.last_accessed_unix_ms.is_none()
                    || self.reason_code.is_some()
                {
                    return invalid("ready artifact metadata is incomplete");
                }
            }
            NodeArtifactState::Corrupt => {
                if self.reason_code.is_none() || self.last_accessed_unix_ms.is_some() {
                    return invalid("corrupt artifact requires a stable reason code only");
                }
            }
        }
        Ok(())
    }
}

/// Immutable model identity used to project a local runtime status.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeReplicaIdentity<'a> {
    /// Logical catalog model ID.
    pub model: &'a str,
    /// Exact selected catalog variant.
    pub variant: Option<&'a str>,
    /// Authenticated private inference endpoint.
    pub endpoint: Option<&'a str>,
    /// Public adapter names served by this generation.
    pub adapters: &'a [String],
}

/// Operational truth for one local deployment generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeReplicaSnapshot {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Monotonic deployment generation.
    pub deployment_generation: u64,
    /// Logical catalog model ID.
    pub model: String,
    /// Exact selected variant, when resolved.
    pub variant: Option<String>,
    /// Resolved managed engine, when assigned.
    pub engine: Option<EngineKind>,
    /// Exact lifecycle state.
    pub state: DeploymentRuntimeState,
    /// Authenticated model-plane endpoint.
    pub endpoint: Option<String>,
    /// Verified artifact digest, when selected.
    pub artifact_digest: Option<String>,
    /// Worker-local devices assigned to this generation.
    pub selected_devices: Vec<u32>,
    /// Total memory reserved for this generation.
    pub reserved_memory_bytes: Option<u64>,
    /// Requests holding an active permit.
    pub active_requests: u64,
    /// Requests waiting in the admission queue.
    pub queue_depth: u64,
    /// Public adapter names without source paths.
    pub adapters: Vec<String>,
    /// Stable bounded failure reason, never raw error text.
    pub reason_code: Option<String>,
}

impl NodeReplicaSnapshot {
    /// Project exact runtime counters and lifecycle while dropping raw errors and job IDs.
    pub fn from_runtime(
        status: &DeploymentRuntimeStatus,
        identity: RuntimeReplicaIdentity<'_>,
    ) -> Result<Self, NodeSnapshotError> {
        let snapshot = Self {
            deployment: status.deployment.clone(),
            deployment_generation: status.generation,
            model: identity.model.to_string(),
            variant: identity.variant.map(str::to_string),
            engine: status.engine,
            state: status.state,
            endpoint: identity.endpoint.map(str::to_string),
            artifact_digest: status.artifact_digest.clone(),
            selected_devices: status.selected_devices.clone(),
            reserved_memory_bytes: status.memory.as_ref().map(|memory| memory.total_bytes),
            active_requests: u64::try_from(status.active_requests).map_err(|_| {
                NodeSnapshotError::Invalid("active request count overflowed".into())
            })?,
            queue_depth: u64::try_from(status.queued_requests)
                .map_err(|_| NodeSnapshotError::Invalid("queue depth overflowed".into()))?,
            adapters: identity.adapters.to_vec(),
            reason_code: status.reason_code.clone(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), NodeSnapshotError> {
        validate_identifier("deployment", &self.deployment)?;
        if self.deployment_generation == 0 {
            return invalid("replica deployment generation must be positive");
        }
        validate_text("replica model", &self.model, MAX_IDENTIFIER_BYTES)?;
        validate_optional_text(
            "replica variant",
            self.variant.as_deref(),
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_optional_endpoint(self.endpoint.as_deref())?;
        if let Some(digest) = self.artifact_digest.as_deref() {
            validate_sha256("replica artifact digest", digest)?;
        }
        if self.selected_devices.len() > MAX_DEVICES {
            return invalid("replica selected-device list exceeds its bound");
        }
        let selected = self
            .selected_devices
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if selected.len() != self.selected_devices.len() {
            return invalid("replica selected-device list contains duplicates");
        }
        if self.active_requests > MAX_REQUEST_COUNT || self.queue_depth > MAX_REQUEST_COUNT {
            return invalid("replica request counters exceed their bounds");
        }
        if self.adapters.len() > MAX_ADAPTERS {
            return invalid("replica adapter list exceeds its bound");
        }
        let mut adapters = BTreeSet::new();
        for adapter in &self.adapters {
            validate_text("adapter", adapter, MAX_IDENTIFIER_BYTES)?;
            if !adapters.insert(adapter) {
                return invalid("replica adapter list contains duplicates");
            }
        }
        validate_optional_reason_code(self.reason_code.as_deref())
    }
}

/// Complete bounded worker truth published under the installed node ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeModelSnapshot {
    /// Snapshot wire schema.
    pub schema_version: u32,
    /// Authenticated cluster identity projection.
    pub node: NodeIdentitySnapshot,
    /// Worker-reported model health.
    pub health: NodeHealthSnapshot,
    /// Managed engine availability and capabilities.
    pub engines: Vec<NodeEngineSnapshot>,
    /// Model-serving hardware and current availability.
    pub devices: Vec<NodeDeviceSnapshot>,
    /// Path-free local artifact cache truth.
    pub artifacts: Vec<NodeArtifactSnapshot>,
    /// Current local deployment generations.
    pub replicas: Vec<NodeReplicaSnapshot>,
    /// Bounded positive placement weight for worker nodes.
    pub placement_weight: u32,
    /// Active desired-state digest in file-managed mode.
    pub active_deployment_digest: Option<String>,
    /// Monotonic generation persisted with this node identity.
    pub generation: u64,
    /// Unix publication time in milliseconds.
    pub published_at_unix_ms: u64,
    /// Unix expiry time in milliseconds.
    pub expires_at_unix_ms: u64,
}

impl NodeModelSnapshot {
    /// Validate every nested bound and cross-reference.
    pub fn validate(&self) -> Result<(), NodeSnapshotError> {
        if self.schema_version != NODE_MODEL_SNAPSHOT_SCHEMA_VERSION {
            return invalid("unsupported node model snapshot schema");
        }
        validate_identifier("node ID", &self.node.node_id)?;
        if self.node.roles.is_empty() || self.node.roles.len() > 3 {
            return invalid("node roles must contain between 1 and 3 values");
        }
        validate_labels(&self.node.labels)?;
        validate_optional_endpoint(self.node.model_endpoint.as_deref())?;
        validate_health(&self.health)?;

        if self.engines.len() > MAX_ENGINES {
            return invalid("engine snapshot list exceeds its bound");
        }
        let mut engine_kinds = BTreeSet::new();
        for engine in &self.engines {
            engine.validate()?;
            if !engine_kinds.insert(engine.engine) {
                return invalid("engine snapshot list contains duplicate kinds");
            }
        }

        if self.devices.len() > MAX_DEVICES {
            return invalid("device snapshot list exceeds its bound");
        }
        let mut device_ids = BTreeSet::new();
        for device in &self.devices {
            device.validate()?;
            if !device_ids.insert(device.index) {
                return invalid("device snapshot list contains duplicate indices");
            }
        }

        if self.artifacts.len() > MAX_ARTIFACTS {
            return invalid("artifact snapshot list exceeds its bound");
        }
        let mut artifact_digests = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_digests.insert(artifact.artifact_digest.as_str()) {
                return invalid("artifact snapshot list contains duplicate digests");
            }
        }

        if self.replicas.len() > MAX_REPLICAS {
            return invalid("replica snapshot list exceeds its bound");
        }
        let mut deployments = BTreeSet::new();
        for replica in &self.replicas {
            replica.validate()?;
            if !deployments.insert(replica.deployment.as_str()) {
                return invalid("replica snapshot list contains duplicate deployments");
            }
            if let Some(digest) = replica.artifact_digest.as_deref() {
                if !artifact_digests.contains(digest) {
                    return invalid("replica artifact is absent from the artifact snapshot list");
                }
            }
            if replica.endpoint.is_some() && replica.endpoint != self.node.model_endpoint {
                return invalid("replica endpoint does not match the node model endpoint");
            }
        }

        let is_worker = self.node.roles.contains(&NodeRole::Worker);
        if self.placement_weight > MAX_PLACEMENT_WEIGHT
            || (is_worker
                && self.health.state != NodeHealthState::Unhealthy
                && self.placement_weight == 0)
            || (!is_worker && self.placement_weight != 0)
        {
            return invalid("placement weight is invalid for the node role");
        }
        if let Some(digest) = self.active_deployment_digest.as_deref() {
            validate_sha256("active deployment digest", digest)?;
        }
        if self.generation == 0 {
            return invalid("snapshot generation must be positive");
        }
        if self.published_at_unix_ms >= self.expires_at_unix_ms
            || self
                .expires_at_unix_ms
                .saturating_sub(self.published_at_unix_ms)
                > MAX_SNAPSHOT_TTL_MS
        {
            return invalid("snapshot expiry must follow publication within the TTL bound");
        }
        Ok(())
    }

    /// Validate and encode strict bounded JSON.
    pub fn to_json(&self) -> Result<Vec<u8>, NodeSnapshotError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|source| NodeSnapshotError::Json {
            operation: "encode",
            source,
        })?;
        if bytes.len() > MAX_NODE_MODEL_SNAPSHOT_BYTES {
            return invalid(format!(
                "serialized snapshot is {} bytes; maximum is {MAX_NODE_MODEL_SNAPSHOT_BYTES}",
                bytes.len()
            ));
        }
        Ok(bytes)
    }

    /// Decode strict bounded JSON and revalidate every semantic field.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeSnapshotError> {
        if bytes.len() > MAX_NODE_MODEL_SNAPSHOT_BYTES {
            return invalid(format!(
                "encoded snapshot is {} bytes; maximum is {MAX_NODE_MODEL_SNAPSHOT_BYTES}",
                bytes.len()
            ));
        }
        let snapshot: Self =
            serde_json::from_slice(bytes).map_err(|source| NodeSnapshotError::Json {
                operation: "decode",
                source,
            })?;
        snapshot.validate()?;
        Ok(snapshot)
    }
}

/// Cross-process durable monotonic generation owned by one installed node identity.
#[derive(Debug, Clone)]
pub struct NodeSnapshotGeneration {
    directory: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredGeneration {
    schema_version: u32,
    generation: u64,
}

impl NodeSnapshotGeneration {
    /// Open a generation store, creating its directory when absent.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, NodeSnapshotError> {
        let directory = directory.as_ref().to_path_buf();
        std::fs::create_dir_all(&directory)?;
        if !directory.is_dir() {
            return invalid("snapshot generation path is not a directory");
        }
        Ok(Self { directory })
    }

    /// Atomically reserve and persist the next positive generation.
    pub fn next(&self) -> Result<u64, NodeSnapshotError> {
        let lock_path = self.directory.join(COUNTER_LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        set_owner_only(&lock)?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let counter_path = self.directory.join(COUNTER_FILE);
            let current = match std::fs::read(&counter_path) {
                Ok(bytes) => {
                    if bytes.len() > 1_024 {
                        return invalid("snapshot generation file exceeds 1024 bytes");
                    }
                    let stored: StoredGeneration =
                        serde_json::from_slice(&bytes).map_err(|source| {
                            NodeSnapshotError::Json {
                                operation: "decode generation",
                                source,
                            }
                        })?;
                    if stored.schema_version != COUNTER_SCHEMA_VERSION {
                        return invalid("unsupported snapshot generation schema");
                    }
                    stored.generation
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(error) => return Err(NodeSnapshotError::Io(error)),
            };
            let generation = current
                .checked_add(1)
                .ok_or(NodeSnapshotError::GenerationOverflow)?;
            let bytes = serde_json::to_vec(&StoredGeneration {
                schema_version: COUNTER_SCHEMA_VERSION,
                generation,
            })
            .map_err(|source| NodeSnapshotError::Json {
                operation: "encode generation",
                source,
            })?;
            atomic_write(&counter_path, &bytes)?;
            Ok(generation)
        })();
        let unlock_result = FileExt::unlock(&lock);
        match (result, unlock_result) {
            (Ok(generation), Ok(())) => Ok(generation),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(NodeSnapshotError::Io(error)),
        }
    }
}

fn validate_health(health: &NodeHealthSnapshot) -> Result<(), NodeSnapshotError> {
    if health.reason_codes.len() > MAX_REASON_CODES {
        return invalid("node health reason-code list exceeds its bound");
    }
    let mut reasons = BTreeSet::new();
    for reason in &health.reason_codes {
        validate_reason_code(reason)?;
        if !reasons.insert(reason) {
            return invalid("node health reason-code list contains duplicates");
        }
    }
    if health.state == NodeHealthState::Ready && !health.reason_codes.is_empty() {
        return invalid("ready node health cannot carry failure reasons");
    }
    if health.state != NodeHealthState::Ready && health.reason_codes.is_empty() {
        return invalid("degraded or unhealthy node health requires a reason code");
    }
    Ok(())
}

fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), NodeSnapshotError> {
    if labels.len() > MAX_LABELS {
        return invalid("node labels exceed their bound");
    }
    for (key, value) in labels {
        if key.is_empty()
            || key.len() > MAX_IDENTIFIER_BYTES
            || !key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
            })
        {
            return invalid("node label key is empty, invalid, or oversized");
        }
        validate_text("node label value", value, MAX_TEXT_BYTES)?;
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), NodeSnapshotError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return invalid(format!(
            "{field} is empty, invalid, or exceeds {MAX_IDENTIFIER_BYTES} bytes"
        ));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, maximum: usize) -> Result<(), NodeSnapshotError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return invalid(format!(
            "{field} is empty, contains control characters, or exceeds {maximum} bytes"
        ));
    }
    Ok(())
}

fn validate_optional_text(
    field: &str,
    value: Option<&str>,
    maximum: usize,
) -> Result<(), NodeSnapshotError> {
    if let Some(value) = value {
        validate_text(field, value, maximum)?;
    }
    Ok(())
}

fn validate_optional_endpoint(endpoint: Option<&str>) -> Result<(), NodeSnapshotError> {
    let Some(endpoint) = endpoint else {
        return Ok(());
    };
    if endpoint.len() > MAX_ENDPOINT_BYTES || endpoint.chars().any(char::is_control) {
        return invalid("model endpoint is oversized or contains control characters");
    }
    let endpoint = url::Url::parse(endpoint)
        .map_err(|_| NodeSnapshotError::Invalid("model endpoint is not an absolute URL".into()))?;
    if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
        return invalid("model endpoint must be an absolute HTTP URL");
    }
    Ok(())
}

fn validate_sha256(field: &str, digest: &str) -> Result<(), NodeSnapshotError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_optional_reason_code(reason: Option<&str>) -> Result<(), NodeSnapshotError> {
    if let Some(reason) = reason {
        validate_reason_code(reason)?;
    }
    Ok(())
}

fn validate_reason_code(reason: &str) -> Result<(), NodeSnapshotError> {
    if reason.is_empty()
        || reason.len() > MAX_REASON_CODE_BYTES
        || !reason.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
    {
        return invalid("reason code is empty, invalid, or oversized");
    }
    Ok(())
}

fn artifact_format_order(format: ArtifactFormat) -> u8 {
    match format {
        ArtifactFormat::Safetensors => 0,
        ArtifactFormat::Gguf => 1,
        ArtifactFormat::Pickle => 2,
    }
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn invalid<T>(message: impl Into<String>) -> Result<T, NodeSnapshotError> {
    Err(NodeSnapshotError::Invalid(message.into()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), NodeSnapshotError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for attempt in 0..16u8 {
        let temp = parent.join(format!(
            ".{COUNTER_FILE}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(mut file) => {
                set_owner_only(&file)?;
                let result = (|| {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&temp, path)?;
                    sync_directory(parent)?;
                    Ok::<_, std::io::Error>(())
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&temp);
                }
                result?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(NodeSnapshotError::Io(error)),
        }
    }
    invalid("could not allocate a generation temporary file")
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(file: &File) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_file: &File) -> Result<(), std::io::Error> {
    Ok(())
}
