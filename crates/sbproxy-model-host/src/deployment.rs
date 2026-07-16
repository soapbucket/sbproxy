// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Canonical desired-state revisions shared by every authority mode.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EngineChoice, PullPolicy};

/// Current canonical deployment document schema.
pub const DEPLOYMENT_SCHEMA_VERSION: u32 = 1;

/// Largest integer emitted through JavaScript-admin JSON contracts without
/// losing exactness.
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// System that owns persistent model desired state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentSourceMode {
    /// SBproxy's versioned deployment store is authoritative.
    AdminManaged,
    /// Operator-managed configuration or GitOps files are authoritative.
    FileManaged,
    /// One configured cluster authority publishes signed revisions.
    ClusterAuthority,
}

/// How a changed deployment replaces its active replica generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPolicy {
    /// Replace replicas incrementally while preserving availability.
    #[default]
    Rolling,
    /// Stop the prior generation before starting the new generation.
    Recreate,
}

/// Concrete request behavior when a deployment has no ready replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColdStartPolicy {
    /// Queue on an assigned replica and share its coordinated engine start.
    #[default]
    Wait,
    /// Return a retryable refusal without launching an engine.
    Reject,
    /// Advance to another provider without launching an engine.
    Fallback,
}

/// Desired state for one public model deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ModelDeployment {
    /// Logical catalog model ID.
    pub model: String,
    /// Exact catalog variant pin.
    #[serde(default)]
    pub variant: Option<String>,
    /// Permit each replica to resolve a different compatible variant.
    #[serde(default)]
    pub heterogeneous_variants: bool,
    /// Desired replica count.
    #[serde(default = "one_replica")]
    pub replicas: u32,
    /// Fixed tensor-parallel degree per replica: the exact number of
    /// devices each replica spans. `None` lets the fit planner pick the
    /// smallest degree that fits. When set, N replicas need N disjoint
    /// device sets of this size, so `replicas * tensor_parallel` must not
    /// exceed the node's device count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tensor_parallel: Option<u32>,
    /// Node labels required by placement.
    #[serde(default)]
    pub required_labels: BTreeMap<String, String>,
    /// Ordered failure-domain label keys used to spread replicas.
    #[serde(default)]
    pub spread_by: Vec<String>,
    /// Artifact acquisition policy.
    #[serde(default)]
    pub pull: PullPolicy,
    /// Warm the deployment before it receives traffic.
    #[serde(default)]
    pub warm: bool,
    /// Concrete behavior when no current replica is ready.
    #[serde(default)]
    pub cold_start: ColdStartPolicy,
    /// Idle lifetime override in seconds.
    #[serde(default)]
    pub keep_alive_secs: Option<u64>,
    /// Per-replica request concurrency cap.
    #[serde(default)]
    pub max_concurrency: Option<u32>,
    /// Maximum requests waiting behind active capacity.
    #[serde(default = "default_max_queue_depth")]
    pub max_queue_depth: usize,
    /// Maximum queue wait in milliseconds.
    #[serde(default = "default_queue_timeout_ms")]
    pub queue_timeout_ms: u64,
    /// Engine selection policy.
    #[serde(default)]
    pub engine: EngineChoice,
    /// Replica replacement policy.
    #[serde(default)]
    pub rollout: RolloutPolicy,
    /// Extra engine command-line arguments appended after the runtime's own,
    /// validated against the resolved engine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
    /// Chunked-prefill settings (vLLM). `None` uses the engine default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunked_prefill: Option<crate::ChunkedPrefill>,
    /// vLLM tool-call parser enabling auto tool-choice. `None` leaves tool
    /// calling off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_parser: Option<String>,
    /// CPU KV-cache tier size in GiB (vLLM `--swap-space`). `None` uses the
    /// engine default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_space_gib: Option<u64>,
    /// GiB of model weights to keep in CPU RAM (vLLM `--cpu-offload-gb`).
    /// `None` disables offload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_offload_gib: Option<u64>,
    /// Per-deployment engine version pin, overriding the node-wide engine
    /// policy so one model can run a different backend version than another.
    /// Never `latest`. `None` inherits the node policy or the built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// Per-deployment engine container image, overriding the node policy.
    /// Must be tag- or digest-pinned. `None` inherits the node policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_image: Option<String>,
    /// Expected SHA-256 for the pinned engine binary or image digest.
    /// `None` inherits the node policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_sha256: Option<String>,
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

/// Validated immutable desired-state revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentRevision {
    /// Deployment document schema version.
    pub schema_version: u32,
    /// Monotonic authority-local revision number.
    pub revision: u64,
    /// Persistent authority for this revision.
    pub source_mode: DeploymentSourceMode,
    /// Authority-specific immutable source identity.
    pub source_revision: String,
    /// Catalog revision used to resolve logical models.
    pub catalog_revision: String,
    /// Public deployment ID to desired model state.
    #[serde(deserialize_with = "deserialize_unique_deployments")]
    pub deployments: BTreeMap<String, ModelDeployment>,
    /// SHA-256 of canonical revision contents excluding this field.
    pub content_digest: String,
}

/// Desired-state candidate before an authority assigns its revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentRevisionDraft {
    /// Persistent authority for this revision.
    pub source_mode: DeploymentSourceMode,
    /// Authority-specific immutable source identity.
    pub source_revision: String,
    /// Catalog revision used to resolve logical models.
    pub catalog_revision: String,
    /// Public deployment ID to desired model state.
    #[serde(deserialize_with = "deserialize_unique_deployments")]
    pub deployments: BTreeMap<String, ModelDeployment>,
}

/// Semantic or digest failure in a deployment revision.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeploymentError {
    /// One desired-state field violates the deployment contract.
    #[error("invalid deployment revision: {0}")]
    Invalid(String),
    /// Canonical JSON generation failed.
    #[error("canonicalize deployment revision: {0}")]
    Canonical(String),
}

#[derive(Serialize)]
struct DeploymentDigestMaterial<'a> {
    schema_version: u32,
    revision: u64,
    source_mode: DeploymentSourceMode,
    source_revision: &'a str,
    catalog_revision: &'a str,
    deployments: &'a BTreeMap<String, ModelDeployment>,
}

impl DeploymentRevisionDraft {
    /// Validate the complete candidate without assigning a revision.
    pub fn validate(&self) -> Result<(), DeploymentError> {
        validate_common(
            self.source_revision.as_str(),
            self.catalog_revision.as_str(),
            &self.deployments,
        )
    }

    /// Assign a monotonic revision and compute its canonical digest.
    pub fn into_revision(self, revision: u64) -> Result<DeploymentRevision, DeploymentError> {
        self.validate()?;
        if revision == 0 {
            return Err(DeploymentError::Invalid(
                "revision number must be at least 1".to_string(),
            ));
        }
        let mut result = DeploymentRevision {
            schema_version: DEPLOYMENT_SCHEMA_VERSION,
            revision,
            source_mode: self.source_mode,
            source_revision: self.source_revision,
            catalog_revision: self.catalog_revision,
            deployments: self.deployments,
            content_digest: String::new(),
        };
        result.content_digest = result.recompute_digest()?;
        result.validate()?;
        Ok(result)
    }
}

impl DeploymentRevision {
    /// Validate schema, desired state, and the stored canonical digest.
    pub fn validate(&self) -> Result<(), DeploymentError> {
        if self.schema_version != DEPLOYMENT_SCHEMA_VERSION {
            return Err(DeploymentError::Invalid(format!(
                "unsupported schema_version {}; expected {DEPLOYMENT_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.revision == 0 {
            return Err(DeploymentError::Invalid(
                "revision number must be at least 1".to_string(),
            ));
        }
        validate_common(
            self.source_revision.as_str(),
            self.catalog_revision.as_str(),
            &self.deployments,
        )?;
        let expected = self.recompute_digest()?;
        if self.content_digest != expected {
            return Err(DeploymentError::Invalid(format!(
                "content digest mismatch: stored {}, computed {expected}",
                self.content_digest
            )));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Result<String, DeploymentError> {
        let material = DeploymentDigestMaterial {
            schema_version: self.schema_version,
            revision: self.revision,
            source_mode: self.source_mode,
            source_revision: &self.source_revision,
            catalog_revision: &self.catalog_revision,
            deployments: &self.deployments,
        };
        let canonical = serde_json_canonicalizer::to_vec(&material)
            .map_err(|error| DeploymentError::Canonical(error.to_string()))?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }
}

fn validate_common(
    source_revision: &str,
    catalog_revision: &str,
    deployments: &BTreeMap<String, ModelDeployment>,
) -> Result<(), DeploymentError> {
    if source_revision.trim().is_empty() {
        return Err(DeploymentError::Invalid(
            "source revision must not be empty".to_string(),
        ));
    }
    if catalog_revision.trim().is_empty() {
        return Err(DeploymentError::Invalid(
            "catalog revision must not be empty".to_string(),
        ));
    }
    for (id, deployment) in deployments {
        if !crate::artifact_spec::valid_identifier(id) {
            return Err(DeploymentError::Invalid(format!(
                "deployment ID '{id}' is invalid"
            )));
        }
        if deployment.model.trim().is_empty() {
            return Err(DeploymentError::Invalid(format!(
                "deployment '{id}' has an empty model"
            )));
        }
        if deployment.replicas == 0 {
            return Err(DeploymentError::Invalid(format!(
                "deployment '{id}' must request at least one replica"
            )));
        }
        if let Some(variant) = &deployment.variant {
            if !crate::artifact_spec::valid_identifier(variant) {
                return Err(DeploymentError::Invalid(format!(
                    "deployment '{id}' has an invalid variant '{variant}'"
                )));
            }
        }
        if deployment.replicas > 1
            && deployment.variant.is_none()
            && !deployment.heterogeneous_variants
        {
            return Err(DeploymentError::Invalid(format!(
                "deployment '{id}' has {} replicas; pin a variant or enable heterogeneous_variants",
                deployment.replicas
            )));
        }
        if matches!(deployment.max_concurrency, Some(0)) {
            return Err(DeploymentError::Invalid(format!(
                "deployment '{id}' max_concurrency must be positive"
            )));
        }
        if deployment.queue_timeout_ms == 0 {
            return Err(DeploymentError::Invalid(format!(
                "deployment '{id}' queue_timeout_ms must be positive"
            )));
        }
        for (key, value) in &deployment.required_labels {
            if key.trim().is_empty() || value.trim().is_empty() {
                return Err(DeploymentError::Invalid(format!(
                    "deployment '{id}' required labels must have nonempty keys and values"
                )));
            }
        }
        if deployment.spread_by.len() > 8 {
            return Err(DeploymentError::Invalid(format!(
                "deployment '{id}' spread_by may contain at most 8 label keys"
            )));
        }
        let mut spread_keys = std::collections::BTreeSet::new();
        for key in &deployment.spread_by {
            if key.is_empty()
                || key.len() > 128
                || !key.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/')
                })
                || !spread_keys.insert(key)
            {
                return Err(DeploymentError::Invalid(format!(
                    "deployment '{id}' spread_by contains an invalid or duplicate label key"
                )));
            }
        }
    }
    Ok(())
}

fn deserialize_unique_deployments<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, ModelDeployment>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueDeployments;

    impl<'de> Visitor<'de> for UniqueDeployments {
        type Value = BTreeMap<String, ModelDeployment>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map with unique deployment IDs")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut deployments = BTreeMap::new();
            while let Some((id, deployment)) = map.next_entry::<String, ModelDeployment>()? {
                if deployments.insert(id.clone(), deployment).is_some() {
                    return Err(A::Error::custom(format!("duplicate deployment ID '{id}'")));
                }
            }
            Ok(deployments)
        }
    }

    deserializer.deserialize_map(UniqueDeployments)
}
