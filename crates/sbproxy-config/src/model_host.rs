//! Public configuration for SBproxy-managed model serving.
//!
//! These data-transfer types intentionally live in the public configuration
//! crate. Runtime types stay in `sbproxy-model-host`, which lets configuration
//! parsing remain independent from the internal serving implementation.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// System that owns the model-host desired state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelHostAuthority {
    /// The active `sb.yml` file is authoritative.
    #[default]
    FileManaged,
    /// The authenticated admin API and its revision store are authoritative.
    AdminManaged,
    /// A configured cluster authority publishes the desired-state revision.
    ClusterAuthority,
}

/// Model artifact download policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPullPolicy {
    /// Pull and verify artifacts during startup reconciliation.
    OnBoot,
    /// Pull and verify artifacts when the first request needs them.
    #[default]
    OnDemand,
    /// Never pull automatically; require an explicit lifecycle command.
    Manual,
}

/// Engine selection for one managed deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEngineChoice {
    /// Select a compatible engine from the artifact format and worker.
    #[default]
    Auto,
    /// Use vLLM.
    Vllm,
    /// Use llama.cpp.
    LlamaCpp,
}

/// Replacement behavior when a deployment changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRolloutPolicy {
    /// Prepare the replacement before draining the prior generation.
    #[default]
    Rolling,
    /// Drain the prior generation before preparing the replacement.
    Recreate,
}

/// One desired local model deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ManagedDeploymentConfig {
    /// Logical ID from the certified model catalog.
    pub model: String,
    /// Exact artifact variant pin. Omission enables worker-compatible selection.
    #[serde(default)]
    pub variant: Option<String>,
    /// Allow replicas to choose different compatible artifact variants.
    #[serde(default)]
    pub heterogeneous_variants: bool,
    /// Desired local replica count.
    #[serde(default = "one_replica")]
    pub replicas: u32,
    /// Worker labels required by this deployment.
    #[serde(default)]
    pub required_labels: BTreeMap<String, String>,
    /// Ordered failure-domain label keys used to spread replicas.
    #[serde(default)]
    pub spread_by: Vec<String>,
    /// Artifact download policy.
    #[serde(default)]
    pub pull: ManagedPullPolicy,
    /// Prepare the deployment during startup or reload.
    #[serde(default)]
    pub warm: bool,
    /// Idle lifetime in seconds after the last completed request.
    #[serde(default)]
    pub keep_alive_secs: Option<u64>,
    /// Per-replica in-flight request cap.
    #[serde(default)]
    pub max_concurrency: Option<u32>,
    /// Maximum requests waiting behind active capacity.
    #[serde(default = "default_max_queue_depth")]
    pub max_queue_depth: usize,
    /// Maximum queue wait in milliseconds.
    #[serde(default = "default_queue_timeout_ms")]
    pub queue_timeout_ms: u64,
    /// Inference engine selection.
    #[serde(default)]
    pub engine: ManagedEngineChoice,
    /// Replica replacement behavior.
    #[serde(default)]
    pub rollout: ManagedRolloutPolicy,
}

const fn one_replica() -> u32 {
    1
}

const fn default_queue_timeout_ms() -> u64 {
    30_000
}

const fn default_max_queue_depth() -> usize {
    128
}

/// Supported managed inference engines.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEngineKind {
    /// vLLM's OpenAI-compatible server.
    Vllm,
    /// llama.cpp's `llama-server`.
    LlamaCpp,
}

/// How a managed engine process is provisioned and launched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEngineLaunch {
    /// Resolve an installed binary or acquire a pinned binary release.
    #[default]
    Binary,
    /// Run a digest-pinned OCI container.
    Container,
    /// Run vLLM from a managed, version-pinned uv environment.
    Uv,
}

/// Hardware acceleration requested for a managed engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEngineAcceleration {
    /// Select from the detected worker hardware.
    #[default]
    Auto,
    /// NVIDIA CUDA.
    Cuda,
    /// Apple Metal.
    Metal,
    /// Vulkan.
    Vulkan,
    /// CPU-only execution.
    Cpu,
}

/// Provisioning policy for one managed inference engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ManagedEngineConfig {
    /// Launch mechanism.
    #[serde(default)]
    pub launch: ManagedEngineLaunch,
    /// Immutable OCI image reference for container launch.
    #[serde(default)]
    pub image: Option<String>,
    /// Explicit allowlisted engine binary path.
    #[serde(default)]
    pub path: Option<String>,
    /// Pinned engine or release version.
    #[serde(default)]
    pub version: Option<String>,
    /// Expected SHA-256 for a downloaded binary or source archive.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Requested acceleration backend.
    #[serde(default)]
    pub acceleration: ManagedEngineAcceleration,
    /// Shared-memory size in GiB for container launch.
    #[serde(default)]
    pub shm_size_gib: Option<u64>,
}

/// Content-addressed model cache policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModelHostCacheConfig {
    /// Cache directory. Omission uses the platform default.
    #[serde(default)]
    pub directory: Option<String>,
    /// Disk budget in GiB. Omission leaves capacity operator-managed.
    #[serde(default)]
    pub budget_gib: Option<f64>,
    /// Maximum simultaneously resident models.
    #[serde(default)]
    pub max_resident_models: Option<usize>,
}

/// Canonical model-host desired state under `proxy.model_host`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModelHostControlConfig {
    /// System authoritative for desired-state mutations.
    #[serde(default)]
    pub authority: ModelHostAuthority,
    /// Revision store path required by admin-managed authority.
    #[serde(default)]
    pub store_path: Option<String>,
    /// Optional operator catalog file replacing the built-in model catalog.
    #[serde(default)]
    pub catalog_file: Option<String>,
    /// Maximum artifact and engine preparations that may run concurrently.
    #[serde(default = "default_max_parallel_prepares")]
    pub max_parallel_prepares: usize,
    /// Fraction of each device's usable memory reserved as headroom.
    #[serde(default = "default_safety_margin")]
    pub safety_margin: f64,
    /// Maximum graceful drain time during shutdown.
    #[serde(default = "default_shutdown_deadline_ms")]
    pub shutdown_deadline_ms: u64,
    /// Maximum rolling placement handoff time while prior replicas are retained.
    #[serde(default = "default_handoff_timeout_ms")]
    pub handoff_timeout_ms: u64,
    /// Artifact cache and residency policy.
    #[serde(default)]
    pub cache: ModelHostCacheConfig,
    /// Per-engine provisioning policy.
    #[serde(default)]
    pub engines: BTreeMap<ManagedEngineKind, ManagedEngineConfig>,
    /// Deployment ID to desired local model.
    #[serde(default)]
    pub deployments: BTreeMap<String, ManagedDeploymentConfig>,
}

impl Default for ModelHostControlConfig {
    fn default() -> Self {
        Self {
            authority: ModelHostAuthority::default(),
            store_path: None,
            catalog_file: None,
            max_parallel_prepares: default_max_parallel_prepares(),
            safety_margin: default_safety_margin(),
            shutdown_deadline_ms: default_shutdown_deadline_ms(),
            handoff_timeout_ms: default_handoff_timeout_ms(),
            cache: ModelHostCacheConfig::default(),
            engines: BTreeMap::new(),
            deployments: BTreeMap::new(),
        }
    }
}

const fn default_max_parallel_prepares() -> usize {
    2
}

const fn default_safety_margin() -> f64 {
    0.10
}

const fn default_shutdown_deadline_ms() -> u64 {
    30_000
}

const fn default_handoff_timeout_ms() -> u64 {
    60_000
}

/// Validation failure for canonical model-host configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid model-host configuration: {message}")]
pub struct ModelHostConfigError {
    message: String,
}

impl ModelHostConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl ModelHostControlConfig {
    /// Validate the complete canonical desired state before startup or reload.
    pub fn validate(&self) -> Result<(), ModelHostConfigError> {
        if self.max_parallel_prepares == 0 {
            return Err(ModelHostConfigError::new(
                "max_parallel_prepares must be positive",
            ));
        }
        if self.catalog_file.as_ref().is_some_and(|path| {
            path.trim().is_empty() || path.len() > 4_096 || path.chars().any(char::is_control)
        }) {
            return Err(ModelHostConfigError::new(
                "catalog_file must be a bounded nonempty path without control characters",
            ));
        }
        if !self.safety_margin.is_finite() || self.safety_margin < 0.0 || self.safety_margin >= 1.0
        {
            return Err(ModelHostConfigError::new(
                "safety_margin must be finite and in the range [0, 1)",
            ));
        }
        if self.shutdown_deadline_ms == 0 {
            return Err(ModelHostConfigError::new(
                "shutdown_deadline_ms must be positive",
            ));
        }
        if self.handoff_timeout_ms == 0 || self.handoff_timeout_ms > 24 * 60 * 60 * 1_000 {
            return Err(ModelHostConfigError::new(
                "handoff_timeout_ms must be between 1 and 86400000",
            ));
        }
        if self.authority == ModelHostAuthority::AdminManaged
            && self
                .store_path
                .as_deref()
                .is_none_or(|path| path.trim().is_empty())
        {
            return Err(ModelHostConfigError::new(
                "store_path is required for admin_managed authority",
            ));
        }
        if matches!(self.cache.budget_gib, Some(value) if !value.is_finite() || value <= 0.0) {
            return Err(ModelHostConfigError::new(
                "cache budget_gib must be finite and positive",
            ));
        }
        if matches!(self.cache.max_resident_models, Some(0)) {
            return Err(ModelHostConfigError::new(
                "cache max_resident_models must be positive",
            ));
        }

        for (kind, engine) in &self.engines {
            validate_engine(*kind, engine)?;
        }
        for (id, deployment) in &self.deployments {
            validate_deployment(id, deployment)?;
        }
        Ok(())
    }
}

fn validate_engine(
    kind: ManagedEngineKind,
    engine: &ManagedEngineConfig,
) -> Result<(), ModelHostConfigError> {
    if engine.launch == ManagedEngineLaunch::Container {
        let image = engine.image.as_deref().ok_or_else(|| {
            ModelHostConfigError::new(format!(
                "engine {kind:?} container launch requires an image"
            ))
        })?;
        if !is_digest_pinned_image(image) {
            return Err(ModelHostConfigError::new(format!(
                "engine {kind:?} container image must use an immutable sha256 digest"
            )));
        }
    } else if engine.image.is_some() {
        return Err(ModelHostConfigError::new(format!(
            "engine {kind:?} image is only valid for container launch"
        )));
    }
    if engine.launch == ManagedEngineLaunch::Uv && kind != ManagedEngineKind::Vllm {
        return Err(ModelHostConfigError::new(
            "uv launch is supported only for vllm",
        ));
    }
    if engine.version.as_deref() == Some("latest") {
        return Err(ModelHostConfigError::new(format!(
            "engine {kind:?} version must be pinned, not latest"
        )));
    }
    if matches!(engine.shm_size_gib, Some(0)) {
        return Err(ModelHostConfigError::new(format!(
            "engine {kind:?} shm_size_gib must be positive"
        )));
    }
    if let Some(sha256) = engine.sha256.as_deref() {
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelHostConfigError::new(format!(
                "engine {kind:?} sha256 must contain 64 hexadecimal characters"
            )));
        }
    }
    Ok(())
}

fn validate_deployment(
    id: &str,
    deployment: &ManagedDeploymentConfig,
) -> Result<(), ModelHostConfigError> {
    if !valid_identifier(id) {
        return Err(ModelHostConfigError::new(format!(
            "deployment ID {id:?} is invalid"
        )));
    }
    if deployment.model.trim().is_empty() {
        return Err(ModelHostConfigError::new(format!(
            "deployment {id:?} model must not be empty"
        )));
    }
    if deployment.replicas == 0 {
        return Err(ModelHostConfigError::new(format!(
            "deployment {id:?} replicas must be positive"
        )));
    }
    if matches!(deployment.max_concurrency, Some(0)) {
        return Err(ModelHostConfigError::new(format!(
            "deployment {id:?} max_concurrency must be positive"
        )));
    }
    if deployment.queue_timeout_ms == 0 {
        return Err(ModelHostConfigError::new(format!(
            "deployment {id:?} queue_timeout_ms must be positive"
        )));
    }
    if let Some(variant) = deployment.variant.as_deref() {
        if !valid_identifier(variant) {
            return Err(ModelHostConfigError::new(format!(
                "deployment {id:?} variant {variant:?} is invalid"
            )));
        }
    }
    if deployment.replicas > 1 && deployment.variant.is_none() && !deployment.heterogeneous_variants
    {
        return Err(ModelHostConfigError::new(format!(
            "deployment {id:?} must pin a variant or allow heterogeneous variants for multiple replicas"
        )));
    }
    if deployment
        .required_labels
        .iter()
        .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
    {
        return Err(ModelHostConfigError::new(format!(
            "deployment {id:?} required labels must have nonempty keys and values"
        )));
    }
    if deployment.spread_by.len() > 8 {
        return Err(ModelHostConfigError::new(format!(
            "deployment {id:?} spread_by may contain at most 8 label keys"
        )));
    }
    let mut spread_keys = std::collections::BTreeSet::new();
    for key in &deployment.spread_by {
        if key.is_empty()
            || key.len() > 128
            || !key.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '/')
            })
            || !spread_keys.insert(key)
        {
            return Err(ModelHostConfigError::new(format!(
                "deployment {id:?} spread_by contains an invalid or duplicate label key"
            )));
        }
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

fn is_digest_pinned_image(image: &str) -> bool {
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}
