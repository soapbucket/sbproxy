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
    Ok(DirectoryPlacementInput {
        nodes,
        observations,
    })
}
