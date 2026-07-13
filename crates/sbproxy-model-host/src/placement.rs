// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Deterministic model replica filtering and weighted rendezvous placement.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::node_snapshot::{
    NodeArtifactSnapshot, NodeArtifactState, NodeDeviceSnapshot, NodeEngineSnapshot,
    NodeHealthState, NodeModelSnapshot, NodeRole,
};
use crate::{
    AcceleratorKind, ArtifactFormat, ArtifactVariant, Catalog, ComputeCapability,
    EngineAvailability, EngineChoice, EngineKind, ModelDeployment, PullPolicy, SupportLevel,
};

const MAX_PLACEMENT_NODES: usize = 1_024;
const UNKNOWN_DOMAIN: &str = "unknown";

/// One directory node normalized for pure placement decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementNode {
    /// Stable cluster node ID.
    pub node_id: String,
    /// Authenticated node roles.
    pub roles: BTreeSet<NodeRole>,
    /// Worker-reported model health.
    pub health: NodeHealthState,
    /// Placement and failure-domain labels.
    pub labels: BTreeMap<String, String>,
    /// Authenticated private model endpoint.
    pub model_endpoint: Option<String>,
    /// Bounded capacity weight.
    pub placement_weight: u32,
    /// Managed engine capabilities and availability.
    pub engines: Vec<NodeEngineSnapshot>,
    /// Model-serving hardware.
    pub devices: Vec<NodeDeviceSnapshot>,
    /// Path-free local artifact cache truth.
    pub artifacts: Vec<NodeArtifactSnapshot>,
}

impl PlacementNode {
    /// Project one already validated snapshot into placement input.
    pub fn from_snapshot(snapshot: &NodeModelSnapshot) -> Result<Self, PlacementError> {
        snapshot
            .validate()
            .map_err(|error| PlacementError::InvalidInput(error.to_string()))?;
        Ok(Self {
            node_id: snapshot.node.node_id.clone(),
            roles: snapshot.node.roles.clone(),
            health: snapshot.health.state,
            labels: snapshot.node.labels.clone(),
            model_endpoint: snapshot.node.model_endpoint.clone(),
            placement_weight: snapshot.placement_weight,
            engines: snapshot.engines.clone(),
            devices: snapshot.devices.clone(),
            artifacts: snapshot.artifacts.clone(),
        })
    }
}

/// Complete pure placement input for one deployment revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementRequest {
    /// Canonical deployment ID.
    pub deployment_id: String,
    /// Monotonic deployment revision generation.
    pub deployment_generation: u64,
    /// Desired deployment policy.
    pub deployment: ModelDeployment,
    /// Current eligible-directory nodes. Input order is ignored.
    pub nodes: Vec<PlacementNode>,
}

/// Stable reason one node was filtered before rendezvous ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementRejectionReason {
    /// Authenticated identity lacks the worker role.
    NotWorker,
    /// Worker explicitly reported an unhealthy model plane.
    NodeUnhealthy,
    /// Required labels do not match.
    RequiredLabels,
    /// No authenticated model endpoint is available.
    MissingEndpoint,
    /// Placement weight is zero.
    NoCapacity,
    /// No compatible variant exists on this worker.
    VariantIncompatible,
    /// Worker has no compatible accelerator or compute capability.
    AcceleratorIncompatible,
    /// Compatible devices lack required free memory.
    InsufficientMemory,
    /// Required managed engine is unavailable or incapable.
    EngineUnavailable,
    /// Manual pull policy requires a verified local artifact.
    ArtifactNotReady,
}

/// One exact deterministic replica assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementAssignment {
    /// Assigned worker node ID.
    pub node_id: String,
    /// Authenticated private model endpoint.
    pub model_endpoint: String,
    /// Selected catalog variant.
    pub variant_id: String,
    /// Canonical immutable artifact digest.
    pub artifact_digest: String,
    /// Selected managed engine.
    pub engine: EngineKind,
    /// Selected accelerator family.
    pub accelerator: AcceleratorKind,
    /// Worker-local device index.
    pub device_index: u32,
    /// Memory required by the artifact contract.
    pub required_memory_bytes: u64,
    /// Free memory observed on the selected device.
    pub available_memory_bytes: u64,
    /// Whether the exact artifact is already verified locally.
    pub artifact_cached: bool,
    /// Requested failure-domain values, including explicit unknown values.
    pub failure_domains: BTreeMap<String, String>,
}

/// Complete deterministic plan for one deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPlan {
    /// Canonical deployment ID.
    pub deployment_id: String,
    /// Deployment generation used in rendezvous hashing.
    pub deployment_generation: u64,
    /// Desired replica count.
    pub desired_replicas: u32,
    /// Selected assignments in deterministic selection order.
    pub assignments: Vec<PlacementAssignment>,
    /// Replicas that could not be placed.
    pub unplaced_replicas: u32,
    /// Stable per-node rejection diagnostics.
    pub rejections: BTreeMap<String, PlacementRejectionReason>,
}

/// Invalid placement input or catalog contract.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlacementError {
    /// Request violates a bounded semantic rule.
    #[error("invalid placement input: {0}")]
    InvalidInput(String),
    /// Logical model is absent from the selected catalog.
    #[error("placement model {0:?} is absent from the catalog")]
    UnknownModel(String),
    /// Exact requested variant is absent.
    #[error("placement variant {variant:?} is absent from model {model:?}")]
    UnknownVariant {
        /// Logical model ID.
        model: String,
        /// Requested variant.
        variant: String,
    },
    /// Catalog artifact identity could not be canonicalized.
    #[error("build placement artifact identity: {0}")]
    ArtifactIdentity(String),
}

struct Candidate {
    assignment: PlacementAssignment,
    score: u128,
}

/// Compute one deterministic placement plan from normalized inputs.
pub fn plan_placement(
    catalog: &Catalog,
    mut request: PlacementRequest,
) -> Result<PlacementPlan, PlacementError> {
    validate_request(&request)?;
    let entry = catalog
        .get(&request.deployment.model)
        .ok_or_else(|| PlacementError::UnknownModel(request.deployment.model.clone()))?;
    if entry.variants.is_empty() {
        return Err(PlacementError::InvalidInput(format!(
            "catalog model {:?} has no immutable variants",
            request.deployment.model
        )));
    }
    let variants = if let Some(pinned) = request.deployment.variant.as_deref() {
        vec![entry
            .variants
            .iter()
            .find(|variant| variant.id == pinned)
            .ok_or_else(|| PlacementError::UnknownVariant {
                model: request.deployment.model.clone(),
                variant: pinned.to_string(),
            })?]
    } else {
        entry.variants.iter().collect::<Vec<_>>()
    };
    request
        .nodes
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));

    let mut candidates = Vec::new();
    let mut rejections = BTreeMap::new();
    for node in &request.nodes {
        match candidate_for_node(catalog, entry, &request, node, &variants) {
            Ok(candidate) => candidates.push(candidate),
            Err(reason) => {
                rejections.insert(node.node_id.clone(), reason);
            }
        }
    }
    let desired_count = usize::try_from(request.deployment.replicas)
        .unwrap_or(usize::MAX)
        .min(candidates.len());
    let selected = select_candidates(candidates, desired_count, &request.deployment.spread_by);
    let assignments = selected
        .into_iter()
        .map(|candidate| candidate.assignment)
        .collect::<Vec<_>>();
    let placed = u32::try_from(assignments.len()).unwrap_or(u32::MAX);
    Ok(PlacementPlan {
        deployment_id: request.deployment_id,
        deployment_generation: request.deployment_generation,
        desired_replicas: request.deployment.replicas,
        assignments,
        unplaced_replicas: request.deployment.replicas.saturating_sub(placed),
        rejections,
    })
}

fn validate_request(request: &PlacementRequest) -> Result<(), PlacementError> {
    if !crate::artifact_spec::valid_identifier(&request.deployment_id) {
        return Err(PlacementError::InvalidInput(
            "deployment ID is empty, invalid, or oversized".to_string(),
        ));
    }
    if request.deployment_generation == 0 {
        return Err(PlacementError::InvalidInput(
            "deployment generation must be positive".to_string(),
        ));
    }
    if request.deployment.replicas == 0 {
        return Err(PlacementError::InvalidInput(
            "deployment must request at least one replica".to_string(),
        ));
    }
    if request.deployment.replicas > 1
        && request.deployment.variant.is_none()
        && !request.deployment.heterogeneous_variants
    {
        return Err(PlacementError::InvalidInput(
            "multi-replica deployment must pin a variant or allow heterogeneous variants"
                .to_string(),
        ));
    }
    if request.nodes.len() > MAX_PLACEMENT_NODES {
        return Err(PlacementError::InvalidInput(format!(
            "placement node count exceeds {MAX_PLACEMENT_NODES}"
        )));
    }
    let mut node_ids = BTreeSet::new();
    for node in &request.nodes {
        if !crate::artifact_spec::valid_identifier(&node.node_id) || !node_ids.insert(&node.node_id)
        {
            return Err(PlacementError::InvalidInput(
                "placement nodes contain an invalid or duplicate node ID".to_string(),
            ));
        }
    }
    Ok(())
}

fn candidate_for_node(
    catalog: &Catalog,
    entry: &crate::CatalogEntry,
    request: &PlacementRequest,
    node: &PlacementNode,
    variants: &[&ArtifactVariant],
) -> Result<Candidate, PlacementRejectionReason> {
    if !node.roles.contains(&NodeRole::Worker) {
        return Err(PlacementRejectionReason::NotWorker);
    }
    if node.health == NodeHealthState::Unhealthy {
        return Err(PlacementRejectionReason::NodeUnhealthy);
    }
    if !request
        .deployment
        .required_labels
        .iter()
        .all(|(key, value)| node.labels.get(key) == Some(value))
    {
        return Err(PlacementRejectionReason::RequiredLabels);
    }
    let endpoint = node
        .model_endpoint
        .as_ref()
        .ok_or(PlacementRejectionReason::MissingEndpoint)?;
    if node.placement_weight == 0 {
        return Err(PlacementRejectionReason::NoCapacity);
    }

    let mut best_rejection = PlacementRejectionReason::VariantIncompatible;
    for variant in variants {
        match evaluate_variant(catalog, entry, request, node, endpoint, variant) {
            Ok(candidate) => return Ok(candidate),
            Err(reason) if rejection_rank(reason) > rejection_rank(best_rejection) => {
                best_rejection = reason;
            }
            Err(_) => {}
        }
    }
    Err(best_rejection)
}

fn evaluate_variant(
    catalog: &Catalog,
    entry: &crate::CatalogEntry,
    request: &PlacementRequest,
    node: &PlacementNode,
    endpoint: &str,
    variant: &ArtifactVariant,
) -> Result<Candidate, PlacementRejectionReason> {
    if matches!(
        variant.stability,
        SupportLevel::ConfigOnly | SupportLevel::Unsupported
    ) || (variant.format == ArtifactFormat::Pickle && !entry.allow_pickle)
    {
        return Err(PlacementRejectionReason::VariantIncompatible);
    }
    let required_memory = variant
        .files
        .iter()
        .try_fold(0u64, |total, file| total.checked_add(file.size_bytes))
        .unwrap_or(u64::MAX)
        .max(variant.requirements.min_memory_bytes);
    let (device, accelerator) = select_device(node, variant, required_memory)?;
    let engine = select_engine(node, request.deployment.engine, variant, accelerator)?;
    let resolved = crate::ResolvedArtifact::from_variant(
        &catalog.catalog_revision,
        &request.deployment.model,
        variant,
        engine,
        entry.context_length,
        &entry.license,
        entry.allow_pickle,
    )
    .map_err(|_| PlacementRejectionReason::VariantIncompatible)?;
    let artifact_cached = node.artifacts.iter().any(|artifact| {
        artifact.artifact_digest == resolved.artifact_digest
            && artifact.state == NodeArtifactState::Ready
    });
    if request.deployment.pull == PullPolicy::Manual && !artifact_cached {
        return Err(PlacementRejectionReason::ArtifactNotReady);
    }
    let failure_domains = request
        .deployment
        .spread_by
        .iter()
        .map(|key| {
            (
                key.clone(),
                node.labels
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| UNKNOWN_DOMAIN.to_string()),
            )
        })
        .collect();
    let score = rendezvous_score(
        &request.deployment_id,
        request.deployment_generation,
        &node.node_id,
        &variant.id,
        node.placement_weight,
    );
    Ok(Candidate {
        assignment: PlacementAssignment {
            node_id: node.node_id.clone(),
            model_endpoint: endpoint.to_string(),
            variant_id: variant.id.clone(),
            artifact_digest: resolved.artifact_digest,
            engine,
            accelerator,
            device_index: device.index,
            required_memory_bytes: required_memory,
            available_memory_bytes: device.available_memory_bytes,
            artifact_cached,
            failure_domains,
        },
        score,
    })
}

fn select_device<'a>(
    node: &'a PlacementNode,
    variant: &ArtifactVariant,
    required_memory: u64,
) -> Result<(&'a NodeDeviceSnapshot, AcceleratorKind), PlacementRejectionReason> {
    let mut accelerator_compatible = false;
    let mut capability_compatible = false;
    let mut candidates = Vec::new();
    for device in &node.devices {
        let Some(accelerator) = device.accelerator else {
            continue;
        };
        if !variant.requirements.accelerators.contains(&accelerator) {
            continue;
        }
        accelerator_compatible = true;
        if !compute_capability_satisfies(
            device.compute_capability.as_ref(),
            variant.requirements.min_compute_capability.as_ref(),
        ) {
            continue;
        }
        capability_compatible = true;
        if device.available_memory_bytes >= required_memory {
            candidates.push((device, accelerator));
        }
    }
    candidates
        .into_iter()
        .max_by(|(left, _), (right, _)| {
            left.available_memory_bytes
                .cmp(&right.available_memory_bytes)
                .then_with(|| right.index.cmp(&left.index))
        })
        .ok_or(if accelerator_compatible && capability_compatible {
            PlacementRejectionReason::InsufficientMemory
        } else {
            PlacementRejectionReason::AcceleratorIncompatible
        })
}

fn compute_capability_satisfies(
    actual: Option<&crate::node_snapshot::NodeComputeCapability>,
    required: Option<&ComputeCapability>,
) -> bool {
    match required {
        None => true,
        Some(required) => actual
            .is_some_and(|actual| (actual.major, actual.minor) >= (required.major, required.minor)),
    }
}

fn select_engine(
    node: &PlacementNode,
    choice: EngineChoice,
    variant: &ArtifactVariant,
    accelerator: AcceleratorKind,
) -> Result<EngineKind, PlacementRejectionReason> {
    let explicit = match choice {
        EngineChoice::Auto => None,
        EngineChoice::Vllm => Some(EngineKind::Vllm),
        EngineChoice::LlamaCpp => Some(EngineKind::LlamaCpp),
        EngineChoice::Embedded => Some(EngineKind::Embedded),
    };
    let mut engines = variant.engines.clone();
    engines.sort();
    engines.dedup();
    engines
        .into_iter()
        .filter(|engine| explicit.is_none_or(|explicit| *engine == explicit))
        .find(|engine| {
            node.engines.iter().any(|available| {
                available.engine == *engine
                    && matches!(
                        available.availability,
                        EngineAvailability::Available | EngineAvailability::Acquirable
                    )
                    && available.artifact_formats.contains(&variant.format)
                    && available.accelerators.contains(&accelerator)
            })
        })
        .ok_or(PlacementRejectionReason::EngineUnavailable)
}

fn rejection_rank(reason: PlacementRejectionReason) -> u8 {
    match reason {
        PlacementRejectionReason::VariantIncompatible => 0,
        PlacementRejectionReason::AcceleratorIncompatible => 1,
        PlacementRejectionReason::InsufficientMemory => 2,
        PlacementRejectionReason::EngineUnavailable => 3,
        PlacementRejectionReason::ArtifactNotReady => 4,
        PlacementRejectionReason::NotWorker
        | PlacementRejectionReason::NodeUnhealthy
        | PlacementRejectionReason::RequiredLabels
        | PlacementRejectionReason::MissingEndpoint
        | PlacementRejectionReason::NoCapacity => 5,
    }
}

fn rendezvous_score(
    deployment_id: &str,
    deployment_generation: u64,
    node_id: &str,
    variant_id: &str,
    weight: u32,
) -> u128 {
    let mut hash = Sha256::new();
    let generation = deployment_generation.to_string();
    for component in [
        deployment_id.as_bytes(),
        generation.as_bytes(),
        node_id.as_bytes(),
        variant_id.as_bytes(),
    ] {
        hash.update(component);
        hash.update([0]);
    }
    let digest = hash.finalize();
    // Keep 32 headroom bits so every bounded capacity multiplication remains
    // exact. Saturating a full-width digest would collapse almost every
    // weighted node to the same score.
    let mut high = [0u8; 16];
    high[4..].copy_from_slice(&digest[..12]);
    u128::from_be_bytes(high) * u128::from(weight.max(1))
}

fn select_candidates(
    mut candidates: Vec<Candidate>,
    count: usize,
    spread_by: &[String],
) -> Vec<Candidate> {
    let mut selected = Vec::with_capacity(count);
    let mut seen = spread_by
        .iter()
        .map(|key| (key.clone(), BTreeSet::new()))
        .collect::<BTreeMap<String, BTreeSet<String>>>();
    while selected.len() < count && !candidates.is_empty() {
        let best = candidates
            .iter()
            .enumerate()
            .max_by(|(_, left), (_, right)| compare_candidates(left, right, spread_by, &seen))
            .map(|(index, _)| index)
            .expect("nonempty candidate set has a maximum");
        let candidate = candidates.remove(best);
        for (key, values) in &mut seen {
            values.insert(
                candidate
                    .assignment
                    .failure_domains
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| UNKNOWN_DOMAIN.to_string()),
            );
        }
        selected.push(candidate);
    }
    selected
}

fn compare_candidates(
    left: &Candidate,
    right: &Candidate,
    spread_by: &[String],
    seen: &BTreeMap<String, BTreeSet<String>>,
) -> Ordering {
    for key in spread_by {
        let left_domain = left
            .assignment
            .failure_domains
            .get(key)
            .map(String::as_str)
            .unwrap_or(UNKNOWN_DOMAIN);
        let right_domain = right
            .assignment
            .failure_domains
            .get(key)
            .map(String::as_str)
            .unwrap_or(UNKNOWN_DOMAIN);
        let values = &seen[key];
        let novelty = (!values.contains(left_domain)).cmp(&!values.contains(right_domain));
        if novelty != Ordering::Equal {
            return novelty;
        }
    }
    left.score
        .cmp(&right.score)
        .then_with(|| right.assignment.node_id.cmp(&left.assignment.node_id))
}
