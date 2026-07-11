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
    /// Node labels required by placement.
    #[serde(default)]
    pub required_labels: BTreeMap<String, String>,
    /// Artifact acquisition policy.
    #[serde(default)]
    pub pull: PullPolicy,
    /// Warm the deployment before it receives traffic.
    #[serde(default)]
    pub warm: bool,
    /// Idle lifetime override in seconds.
    #[serde(default)]
    pub keep_alive_secs: Option<u64>,
    /// Per-replica request concurrency cap.
    #[serde(default)]
    pub max_concurrency: Option<u32>,
    /// Maximum queue wait in milliseconds.
    #[serde(default = "default_queue_timeout_ms")]
    pub queue_timeout_ms: u64,
    /// Engine selection policy.
    #[serde(default)]
    pub engine: EngineChoice,
    /// Replica replacement policy.
    #[serde(default)]
    pub rollout: RolloutPolicy,
}

const fn one_replica() -> u32 {
    1
}

const fn default_queue_timeout_ms() -> u64 {
    30_000
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
        for (key, value) in &deployment.required_labels {
            if key.trim().is_empty() || value.trim().is_empty() {
                return Err(DeploymentError::Invalid(format!(
                    "deployment '{id}' required labels must have nonempty keys and values"
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
