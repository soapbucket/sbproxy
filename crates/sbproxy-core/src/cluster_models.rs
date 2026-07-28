// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Adapters between the live directory and pure model placement contracts.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

/// Process identity and role used by the cluster model controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterModelContext {
    /// Installed stable node ID.
    pub node_id: String,
    /// Whether this node owns worker-local model assignments.
    pub is_worker: bool,
}

/// Pure placement and rollout inputs normalized from one directory view.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryPlacementInput {
    /// Eligible worker capability snapshots.
    pub nodes: Vec<sbproxy_model_host::PlacementNode>,
    /// Exact replica observations grouped by deployment.
    pub observations: BTreeMap<String, Vec<sbproxy_model_host::RolloutReplicaObservation>>,
    /// Fleet observations and local reservations with provenance preserved.
    pub generation_fences: sbproxy_model_host::DeploymentGenerationFences,
}

/// Return canonical cluster model context, excluding local and legacy mesh modes.
pub fn current_cluster_model_context() -> Option<ClusterModelContext> {
    let settings = crate::cluster::current_cluster_settings()?;
    if !settings.model_control_enabled {
        return None;
    }
    let handle = crate::cluster::current_cluster_handle()?;
    Some(ClusterModelContext {
        node_id: handle.identity().node_id.clone(),
        is_worker: handle
            .identity()
            .roles
            .contains(&sbproxy_mesh::ClusterNodeRole::Worker),
    })
}

/// Normalize a lock-free directory view into pure placement input.
pub fn placement_input_from_directory(
    view: &sbproxy_ai::model_directory::ModelDirectoryView,
) -> Result<DirectoryPlacementInput> {
    let mut nodes = Vec::new();
    let mut observations =
        BTreeMap::<String, Vec<sbproxy_model_host::RolloutReplicaObservation>>::new();
    for node in view.nodes.iter().filter(|node| node.model_eligible) {
        let snapshot = node.snapshot.as_ref().with_context(|| {
            format!("eligible directory node {:?} has no snapshot", node.node_id)
        })?;
        nodes.push(sbproxy_model_host::PlacementNode::from_snapshot(snapshot)?);
        for replica in &node.replicas {
            observations
                .entry(replica.deployment.clone())
                .or_default()
                .push(sbproxy_model_host::RolloutReplicaObservation {
                    node_id: node.node_id.clone(),
                    deployment_generation: replica.deployment_generation,
                    variant_id: replica.variant.clone(),
                    artifact_digest: replica.artifact_digest.clone(),
                    state: replica.state,
                });
        }
    }
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    for replicas in observations.values_mut() {
        replicas.sort_by(|left, right| {
            left.node_id
                .cmp(&right.node_id)
                .then_with(|| left.deployment_generation.cmp(&right.deployment_generation))
        });
    }
    let local_generation_fences = deployment_generation_store()?
        .map(|store| store.load())
        .transpose()?
        .unwrap_or_default();
    let generation_fences = sbproxy_model_host::DeploymentGenerationFences::from_sources(
        view.deployment_generation_fences.clone(),
        local_generation_fences,
    );
    Ok(DirectoryPlacementInput {
        nodes,
        observations,
        generation_fences,
    })
}

/// Persist target generation high-water marks before a placement commit.
///
/// Also records newly-observed per-node placement rejections in the
/// just-computed plan, by deployment and bounded reason. Every commit
/// runs the full planner, so this sees the plan's complete, final
/// rejection set rather than one candidate rejection mid-evaluation.
pub fn persist_deployment_generations(
    placement: &sbproxy_model_host::ClusterPlacementState,
) -> Result<()> {
    record_new_placement_rejections(placement);
    if let Some(store) = deployment_generation_store()? {
        store.persist(placement)?;
    }
    Ok(())
}

type RejectionKey = (String, String);

/// The (deployment, node) -> reason rejection set observed on the
/// previous commit, so [`record_new_placement_rejections`] can tell a
/// fresh rejection from one that is still standing.
fn previous_placement_rejections(
) -> &'static std::sync::Mutex<BTreeMap<RejectionKey, sbproxy_model_host::PlacementRejectionReason>>
{
    static PREVIOUS: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<RejectionKey, sbproxy_model_host::PlacementRejectionReason>>,
    > = std::sync::OnceLock::new();
    PREVIOUS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Record only rejections that are new since the last commit: a
/// (deployment, node) pair that was not rejected before, or one whose
/// reason changed. `persist_deployment_generations` runs on every
/// reconcile commit, and a node can stay rejected for the same reason
/// across many consecutive commits (e.g. persistently unhealthy); counting
/// every commit's full standing rejection set would make this Counter
/// measure reconcile-loop frequency rather than actual rejection events.
fn record_new_placement_rejections(placement: &sbproxy_model_host::ClusterPlacementState) {
    let mut previous = previous_placement_rejections()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut current = BTreeMap::new();
    for (deployment_id, status) in placement.deployments() {
        for (node_id, reason) in &status.target.rejections {
            current.insert((deployment_id.clone(), node_id.clone()), *reason);
        }
    }
    for ((deployment_id, _node_id), reason) in new_rejections_since(&previous, &current) {
        sbproxy_observe::metrics::record_model_host_placement_rejection(
            &deployment_id,
            reason.as_str(),
        );
    }
    *previous = current;
}

/// Pure diff: every entry in `current` that is absent from `previous`, or
/// present there under a different reason. Split out from
/// [`record_new_placement_rejections`] so the actual dedupe-on-transition
/// logic is unit-testable without constructing a full
/// `ClusterPlacementState` (which has no public builder outside the
/// planner).
fn new_rejections_since(
    previous: &BTreeMap<RejectionKey, sbproxy_model_host::PlacementRejectionReason>,
    current: &BTreeMap<RejectionKey, sbproxy_model_host::PlacementRejectionReason>,
) -> Vec<(RejectionKey, sbproxy_model_host::PlacementRejectionReason)> {
    current
        .iter()
        .filter(|(key, reason)| previous.get(*key) != Some(*reason))
        .map(|(key, reason)| (key.clone(), *reason))
        .collect()
}

#[cfg(test)]
mod placement_rejection_dedupe_tests {
    use super::*;
    use sbproxy_model_host::PlacementRejectionReason;

    fn key(deployment: &str, node: &str) -> RejectionKey {
        (deployment.to_string(), node.to_string())
    }

    #[test]
    fn a_standing_rejection_with_the_same_reason_is_not_reported_again() {
        let previous = BTreeMap::from([(
            key("qwen3-32b", "worker-a"),
            PlacementRejectionReason::NoCapacity,
        )]);
        let current = previous.clone();
        assert!(new_rejections_since(&previous, &current).is_empty());
    }

    #[test]
    fn a_brand_new_rejection_is_reported() {
        let previous = BTreeMap::new();
        let current = BTreeMap::from([(
            key("qwen3-32b", "worker-a"),
            PlacementRejectionReason::NoCapacity,
        )]);
        assert_eq!(
            new_rejections_since(&previous, &current),
            vec![(
                key("qwen3-32b", "worker-a"),
                PlacementRejectionReason::NoCapacity
            )]
        );
    }

    #[test]
    fn a_reason_change_on_the_same_node_is_reported_as_new() {
        let previous = BTreeMap::from([(
            key("qwen3-32b", "worker-a"),
            PlacementRejectionReason::NoCapacity,
        )]);
        let current = BTreeMap::from([(
            key("qwen3-32b", "worker-a"),
            PlacementRejectionReason::NodeUnhealthy,
        )]);
        assert_eq!(
            new_rejections_since(&previous, &current),
            vec![(
                key("qwen3-32b", "worker-a"),
                PlacementRejectionReason::NodeUnhealthy
            )]
        );
    }

    #[test]
    fn a_cleared_rejection_reports_nothing_and_is_not_treated_as_new_later() {
        // Cleared entirely (the node stopped being rejected): current has
        // no entry for it at all, so nothing about it is reported, and it
        // must not resurrect as "new" if it never reappears.
        let previous = BTreeMap::from([(
            key("qwen3-32b", "worker-a"),
            PlacementRejectionReason::NoCapacity,
        )]);
        let current = BTreeMap::new();
        assert!(new_rejections_since(&previous, &current).is_empty());
    }
}

fn deployment_generation_store() -> Result<Option<sbproxy_model_host::FileDeploymentGenerationStore>>
{
    crate::cluster::current_cluster_state_directory()
        .map(sbproxy_model_host::FileDeploymentGenerationStore::open)
        .transpose()
        .map_err(anyhow::Error::from)
}
