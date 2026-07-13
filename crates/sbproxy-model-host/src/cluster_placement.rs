// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Fleet placement state and worker-local desired-state projection.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    filter_desired_state_for_assignments, plan_placement, plan_rollout, AssignedModelDeployment,
    Catalog, CompiledDeployment, EngineKind, PlacementNode, PlacementPlan, PlacementRequest,
    RolloutDecision, RolloutError, RolloutReplicaObservation, RolloutRequest, RuntimeDesiredState,
};

/// Prior placement retained while a replacement converges or drains.
#[derive(Debug, Clone, PartialEq)]
pub struct PriorDeploymentPlacement {
    /// Prior compiled deployment policy.
    pub deployment: CompiledDeployment,
    /// Prior exact placement plan.
    pub plan: PlacementPlan,
    /// Whether recreate has already emitted its mandatory drain-only step.
    pub recreate_drain_issued: bool,
}

/// Current placement and rollout status for one deployment.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterDeploymentPlacement {
    /// Current compiled global deployment policy.
    pub deployment: CompiledDeployment,
    /// Current target placement.
    pub target: PlacementPlan,
    /// Prior placement retained for safe handoff.
    pub previous: Option<PriorDeploymentPlacement>,
    /// Current pure rollout decision.
    pub rollout: RolloutDecision,
}

/// Complete committed fleet placement state for one global desired revision.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterPlacementState {
    global: RuntimeDesiredState,
    deployments: BTreeMap<String, ClusterDeploymentPlacement>,
}

/// Generation fences grouped by where this controller learned them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentGenerationFences {
    observed: BTreeMap<String, crate::DeploymentGenerationFence>,
    local: BTreeMap<String, crate::DeploymentGenerationFence>,
}

impl DeploymentGenerationFences {
    /// Build fences from authenticated fleet observations and local reservations.
    pub fn from_sources(
        observed: BTreeMap<String, crate::DeploymentGenerationFence>,
        local: BTreeMap<String, crate::DeploymentGenerationFence>,
    ) -> Self {
        Self { observed, local }
    }

    /// Build fences learned only from authenticated fleet observations.
    pub fn observed(observed: BTreeMap<String, crate::DeploymentGenerationFence>) -> Self {
        Self {
            observed,
            local: BTreeMap::new(),
        }
    }

    /// Build fences reserved only by this controller.
    pub fn local(local: BTreeMap<String, crate::DeploymentGenerationFence>) -> Self {
        Self {
            observed: BTreeMap::new(),
            local,
        }
    }
}

impl ClusterPlacementState {
    /// Global desired state from which every worker projection is derived.
    pub const fn global(&self) -> &RuntimeDesiredState {
        &self.global
    }

    /// Deterministic deployment placement status.
    pub const fn deployments(&self) -> &BTreeMap<String, ClusterDeploymentPlacement> {
        &self.deployments
    }

    /// Build the exact warm, pinned desired state owned by one worker.
    pub fn local_desired(
        &self,
        node_id: &str,
    ) -> Result<RuntimeDesiredState, ClusterPlacementError> {
        Ok(filter_desired_state_for_assignments(
            &self.global,
            &self.local_assignments(node_id),
        )?)
    }

    /// Exact locally active assignment metadata keyed by deployment ID.
    pub fn local_assignments(&self, node_id: &str) -> BTreeMap<String, AssignedModelDeployment> {
        let mut local = BTreeMap::new();
        for (deployment_id, placement) in &self.deployments {
            if let Some(target) = placement
                .rollout
                .start
                .iter()
                .find(|candidate| candidate.assignment.node_id == node_id)
            {
                local.insert(
                    deployment_id.clone(),
                    AssignedModelDeployment {
                        deployment_generation: target.deployment_generation,
                        assignment: target.assignment.clone(),
                        deployment: placement.deployment.clone(),
                    },
                );
                continue;
            }
            let Some(retained) = placement
                .rollout
                .retain
                .iter()
                .find(|candidate| candidate.assignment.node_id == node_id)
            else {
                continue;
            };
            let Some(previous) = placement.previous.as_ref() else {
                continue;
            };
            local.insert(
                deployment_id.clone(),
                AssignedModelDeployment {
                    deployment_generation: retained.deployment_generation,
                    assignment: retained.assignment.clone(),
                    deployment: previous.deployment.clone(),
                },
            );
        }
        local
    }
}

/// Invalid catalog, placement, rollout, or generation transition.
#[derive(Debug, thiserror::Error)]
pub enum ClusterPlacementError {
    /// Global desired-state identity could not be encoded.
    #[error("cluster desired-state identity failed: {0}")]
    DesiredIdentity(String),
    /// Deterministic placement failed.
    #[error("cluster placement failed: {0}")]
    Placement(#[from] crate::PlacementError),
    /// Readiness-gated rollout failed.
    #[error("cluster rollout failed: {0}")]
    Rollout(#[from] RolloutError),
    /// Deployment generation or deadline overflowed.
    #[error("cluster placement counter overflowed")]
    CounterOverflow,
}

/// Recompute every deployment from one immutable reachable-directory view.
///
/// Observed fences come from authenticated fleet snapshots, while local fences
/// are pre-commit reservations made by this controller. Keeping their
/// provenance separate prevents another controller's in-progress revision from
/// being mistaken for a locally failed commit.
pub fn reconcile_cluster_placement(
    catalog: &Catalog,
    previous: Option<&ClusterPlacementState>,
    global: RuntimeDesiredState,
    nodes: Vec<PlacementNode>,
    observations: &BTreeMap<String, Vec<RolloutReplicaObservation>>,
    generation_fences: &DeploymentGenerationFences,
    now_unix_ms: u64,
) -> Result<ClusterPlacementState, ClusterPlacementError> {
    let handoff_deadline = now_unix_ms
        .checked_add(global.control.handoff_timeout_ms)
        .ok_or(ClusterPlacementError::CounterOverflow)?;
    let desired_revision_digest = global
        .revision_digest()
        .map_err(|error| ClusterPlacementError::DesiredIdentity(error.to_string()))?;
    let previous_revision_digest = previous
        .map(|state| state.global.revision_digest())
        .transpose()
        .map_err(|error| ClusterPlacementError::DesiredIdentity(error.to_string()))?;
    let global_changed = previous_revision_digest
        .as_deref()
        .is_some_and(|digest| digest != desired_revision_digest);
    let mut deployments = BTreeMap::new();
    for (deployment_id, deployment) in &global.deployments {
        let prior_state = previous.and_then(|state| state.deployments.get(deployment_id));
        let observed = observations
            .get(deployment_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let replica_generation = observed
            .iter()
            .map(|observation| observation.deployment_generation)
            .max()
            .unwrap_or(0);
        let observed_fence = generation_fences.observed.get(deployment_id);
        let local_fence = generation_fences.local.get(deployment_id);
        let high_water_generation = replica_generation
            .max(
                observed_fence
                    .map(|fence| fence.deployment_generation)
                    .unwrap_or(0),
            )
            .max(
                local_fence
                    .map(|fence| fence.deployment_generation)
                    .unwrap_or(0),
            );
        let current_observed_generation = [observed_fence, local_fence]
            .into_iter()
            .flatten()
            .filter(|fence| {
                fence.desired_revision_digest.as_deref() == Some(desired_revision_digest.as_str())
            })
            .map(|fence| fence.deployment_generation)
            .max();
        let local_failed_reservation = local_fence
            .filter(|fence| {
                fence.desired_revision_digest.as_deref() != Some(desired_revision_digest.as_str())
            })
            .map(|fence| fence.deployment_generation);
        let config_changed = prior_state.is_some_and(|_| global_changed);
        let deployment_generation = match (prior_state, current_observed_generation) {
            (Some(prior), observed) if !config_changed => {
                let current = prior
                    .target
                    .deployment_generation
                    .max(observed.unwrap_or(0));
                match local_failed_reservation.filter(|reserved| *reserved >= current) {
                    Some(reserved) => reserved
                        .checked_add(1)
                        .ok_or(ClusterPlacementError::CounterOverflow)?,
                    None => current,
                }
            }
            (None, Some(observed)) => observed,
            (Some(prior), Some(observed)) if observed > prior.target.deployment_generation => {
                observed
            }
            (Some(prior), _) => prior
                .target
                .deployment_generation
                .max(high_water_generation)
                .checked_add(1)
                .ok_or(ClusterPlacementError::CounterOverflow)?,
            (None, None) if high_water_generation > 0 => high_water_generation
                .checked_add(1)
                .ok_or(ClusterPlacementError::CounterOverflow)?,
            (None, None) => 1,
        };
        let target = plan_placement(
            catalog,
            PlacementRequest {
                deployment_id: deployment_id.clone(),
                deployment_generation,
                deployment: deployment.desired.clone(),
                nodes: nodes.clone(),
            },
        )?;
        let target_changed = prior_state.is_some_and(|prior| {
            config_changed || !same_assignment_identity(&prior.target, &target)
        });
        let (mut prior, deadline) = match prior_state {
            Some(state) if target_changed => (
                Some(PriorDeploymentPlacement {
                    deployment: state.deployment.clone(),
                    plan: state.target.clone(),
                    recreate_drain_issued: false,
                }),
                handoff_deadline,
            ),
            Some(state) => (
                state.previous.clone(),
                state.rollout.handoff_deadline_unix_ms,
            ),
            None => (None, handoff_deadline),
        };
        let mut rollout = plan_rollout(RolloutRequest {
            policy: deployment.desired.rollout,
            target: target.clone(),
            previous: prior.as_ref().map(|previous| previous.plan.clone()),
            observations: observed.to_vec(),
            prior_drain_issued: prior
                .as_ref()
                .is_some_and(|previous| previous.recreate_drain_issued),
            now_unix_ms,
            handoff_deadline_unix_ms: deadline,
        })?;
        if rollout.phase == crate::RolloutPhase::DrainingPrior {
            if let Some(previous) = prior.as_mut() {
                previous.recreate_drain_issued = true;
            }
        } else if should_clear_previous(prior.as_ref(), &rollout, observed) {
            prior = None;
            rollout = plan_rollout(RolloutRequest {
                policy: deployment.desired.rollout,
                target: target.clone(),
                previous: None,
                observations: observed.to_vec(),
                prior_drain_issued: false,
                now_unix_ms,
                handoff_deadline_unix_ms: deadline,
            })?;
        }
        deployments.insert(
            deployment_id.clone(),
            ClusterDeploymentPlacement {
                deployment: deployment.clone(),
                target,
                previous: prior,
                rollout,
            },
        );
    }
    Ok(ClusterPlacementState {
        global,
        deployments,
    })
}

fn same_assignment_identity(left: &PlacementPlan, right: &PlacementPlan) -> bool {
    assignment_identities(left) == assignment_identities(right)
        && left.desired_replicas == right.desired_replicas
        && left.unplaced_replicas == right.unplaced_replicas
}

fn assignment_identities(
    plan: &PlacementPlan,
) -> BTreeSet<(
    String,
    String,
    String,
    String,
    EngineKind,
    crate::AcceleratorKind,
    u32,
)> {
    plan.assignments
        .iter()
        .map(|assignment| {
            (
                assignment.node_id.clone(),
                assignment.model_endpoint.clone(),
                assignment.variant_id.clone(),
                assignment.artifact_digest.clone(),
                assignment.engine,
                assignment.accelerator,
                assignment.device_index,
            )
        })
        .collect()
}

fn should_clear_previous(
    previous: Option<&PriorDeploymentPlacement>,
    rollout: &RolloutDecision,
    observations: &[RolloutReplicaObservation],
) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    if rollout.phase == crate::RolloutPhase::WaitingForReadiness
        || rollout.phase == crate::RolloutPhase::DrainingPrior
    {
        return false;
    }
    !previous.plan.assignments.iter().any(|assignment| {
        observations.iter().any(|observation| {
            observation.node_id == assignment.node_id
                && observation.deployment_generation == previous.plan.deployment_generation
                && !matches!(
                    observation.state,
                    crate::DeploymentRuntimeState::Stopped | crate::DeploymentRuntimeState::Failed
                )
        })
    })
}
