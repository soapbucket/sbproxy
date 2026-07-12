// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Pure readiness-gated handoff decisions between placement plans.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    CompiledDeployment, DeploymentRuntimeState, EngineChoice, EngineKind, PlacementAssignment,
    PlacementPlan, RolloutPolicy, RuntimeDesiredState,
};

const MAX_ROLLOUT_OBSERVATIONS: usize = 4_096;

/// One exact replica observation from the immutable model directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutReplicaObservation {
    /// Worker publishing the replica.
    pub node_id: String,
    /// Cluster deployment generation, not a process-local runtime counter.
    pub deployment_generation: u64,
    /// Exact resolved catalog variant when known.
    pub variant_id: Option<String>,
    /// Exact immutable artifact digest when known.
    pub artifact_digest: Option<String>,
    /// Current worker-local lifecycle state.
    pub state: DeploymentRuntimeState,
}

/// Pure handoff input for one deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutRequest {
    /// Requested replacement behavior.
    pub policy: RolloutPolicy,
    /// New deterministic target plan.
    pub target: PlacementPlan,
    /// Previously committed target, when this is a replacement.
    pub previous: Option<PlacementPlan>,
    /// Replica truth from the current reachable directory.
    pub observations: Vec<RolloutReplicaObservation>,
    /// Whether recreate has already published one drain-only decision.
    pub prior_drain_issued: bool,
    /// Decision time in Unix milliseconds.
    pub now_unix_ms: u64,
    /// Bounded rolling handoff deadline in Unix milliseconds.
    pub handoff_deadline_unix_ms: u64,
}

/// Stable rollout phase rendered in placement and admin status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    /// Every target assignment reports ready and no prior assignment remains.
    Stable,
    /// Target assignments may start and are still converging.
    Starting,
    /// Rolling replacements started while losing assignments remain retained.
    WaitingForReadiness,
    /// Recreate policy is removing the prior generation before target start.
    DrainingPrior,
    /// Rolling readiness missed its deadline and prior losers must drain.
    TimedOut,
}

/// One assignment paired with its cluster deployment generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedPlacementAssignment {
    /// Cluster deployment generation.
    pub deployment_generation: u64,
    /// Exact node, variant, engine, and artifact assignment.
    pub assignment: PlacementAssignment,
}

/// One worker-local deployment selected from either target or retained state.
#[derive(Debug, Clone, PartialEq)]
pub struct AssignedModelDeployment {
    /// Cluster deployment generation published in replica truth.
    pub deployment_generation: u64,
    /// Exact placement assignment for this worker.
    pub assignment: PlacementAssignment,
    /// Complete compiled deployment policy for this generation.
    pub deployment: CompiledDeployment,
}

/// Complete deterministic handoff decision for one deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutDecision {
    /// Deployment whose assignments are changing.
    pub deployment_id: String,
    /// Current target generation.
    pub target_generation: u64,
    /// Current operator-facing rollout phase.
    pub phase: RolloutPhase,
    /// Whether every required target assignment reports exact readiness.
    pub target_ready: bool,
    /// Whether rolling handoff exhausted its deadline before readiness.
    pub timed_out: bool,
    /// Target assignments allowed to start or remain active.
    pub start: Vec<VersionedPlacementAssignment>,
    /// Losing prior assignments temporarily retained for availability.
    pub retain: Vec<VersionedPlacementAssignment>,
    /// Prior assignments that must reject new work and drain.
    pub drain: Vec<VersionedPlacementAssignment>,
    /// Deadline used for this decision.
    pub handoff_deadline_unix_ms: u64,
}

/// Invalid placement-plan or observation contract.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RolloutError {
    /// One bounded semantic rule failed.
    #[error("invalid rollout input: {0}")]
    Invalid(String),
}

/// Filter one complete global desired state to exact assignments owned locally.
///
/// Assigned replicas are always warm and exact-variant pinned. This makes a
/// placement commit prepare the replacement before the local runtime swaps its
/// request route, while the returned revision remains internally consistent.
pub fn filter_desired_state_for_assignments(
    global: &RuntimeDesiredState,
    assignments: &BTreeMap<String, AssignedModelDeployment>,
) -> Result<RuntimeDesiredState, RolloutError> {
    let mut deployments = BTreeMap::new();
    let mut revision_deployments = BTreeMap::new();
    for (deployment_id, assigned) in assignments {
        if !crate::artifact_spec::valid_identifier(deployment_id)
            || assigned.deployment_generation == 0
            || assigned.assignment.node_id.is_empty()
        {
            return Err(RolloutError::Invalid(
                "local assignment identity or generation is invalid".to_string(),
            ));
        }
        let mut compiled = assigned.deployment.clone();
        compiled.desired.variant = Some(assigned.assignment.variant_id.clone());
        compiled.desired.heterogeneous_variants = false;
        compiled.desired.replicas = 1;
        compiled.desired.warm = true;
        compiled.desired.engine = engine_choice(assigned.assignment.engine);
        revision_deployments.insert(deployment_id.clone(), compiled.desired.clone());
        deployments.insert(deployment_id.clone(), compiled);
    }
    let mut revision = global.revision.clone();
    revision.source_mode = crate::DeploymentSourceMode::ClusterAuthority;
    revision.deployments = revision_deployments;
    revision
        .validate()
        .map_err(|error| RolloutError::Invalid(error.to_string()))?;
    let routes = global
        .routes
        .iter()
        .filter(|route| deployments.contains_key(&route.deployment))
        .cloned()
        .collect();
    Ok(RuntimeDesiredState {
        revision,
        deployments,
        routes,
        control: global.control.clone(),
        legacy_host_policy: global.legacy_host_policy.clone(),
    })
}

const fn engine_choice(engine: EngineKind) -> EngineChoice {
    match engine {
        EngineKind::Vllm => EngineChoice::Vllm,
        EngineKind::LlamaCpp => EngineChoice::LlamaCpp,
        EngineKind::Embedded => EngineChoice::Embedded,
    }
}

/// Decide which target and prior assignments may run at this instant.
pub fn plan_rollout(request: RolloutRequest) -> Result<RolloutDecision, RolloutError> {
    validate_request(&request)?;
    let target_ready = target_is_ready(&request.target, &request.observations);
    let target = versioned_assignments(&request.target);
    let Some(previous) = request.previous.as_ref() else {
        return Ok(RolloutDecision {
            deployment_id: request.target.deployment_id,
            target_generation: request.target.deployment_generation,
            phase: if target_ready {
                RolloutPhase::Stable
            } else {
                RolloutPhase::Starting
            },
            target_ready,
            timed_out: false,
            start: target,
            retain: Vec::new(),
            drain: Vec::new(),
            handoff_deadline_unix_ms: request.handoff_deadline_unix_ms,
        });
    };

    match request.policy {
        RolloutPolicy::Rolling => rolling_decision(&request, previous, target, target_ready),
        RolloutPolicy::Recreate => recreate_decision(&request, previous, target, target_ready),
    }
}

fn rolling_decision(
    request: &RolloutRequest,
    previous: &PlacementPlan,
    target: Vec<VersionedPlacementAssignment>,
    target_ready: bool,
) -> Result<RolloutDecision, RolloutError> {
    let target_nodes = request
        .target
        .assignments
        .iter()
        .map(|assignment| assignment.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let losers = versioned_assignments(previous)
        .into_iter()
        .filter(|assignment| !target_nodes.contains(assignment.assignment.node_id.as_str()))
        .collect::<Vec<_>>();
    let timed_out = !target_ready && request.now_unix_ms >= request.handoff_deadline_unix_ms;
    let (phase, retain, drain) = if target_ready {
        (RolloutPhase::Stable, Vec::new(), losers)
    } else if timed_out {
        (RolloutPhase::TimedOut, Vec::new(), losers)
    } else if losers.is_empty() {
        (RolloutPhase::Starting, Vec::new(), Vec::new())
    } else {
        (RolloutPhase::WaitingForReadiness, losers, Vec::new())
    };
    Ok(RolloutDecision {
        deployment_id: request.target.deployment_id.clone(),
        target_generation: request.target.deployment_generation,
        phase,
        target_ready,
        timed_out,
        start: target,
        retain,
        drain,
        handoff_deadline_unix_ms: request.handoff_deadline_unix_ms,
    })
}

fn recreate_decision(
    request: &RolloutRequest,
    previous: &PlacementPlan,
    target: Vec<VersionedPlacementAssignment>,
    target_ready: bool,
) -> Result<RolloutDecision, RolloutError> {
    let previous_assignments = versioned_assignments(previous);
    let prior_active = !request.prior_drain_issued
        || previous.assignments.iter().any(|assignment| {
            request.observations.iter().any(|observation| {
                observation.node_id == assignment.node_id
                    && observation.deployment_generation == previous.deployment_generation
                    && !matches!(
                        observation.state,
                        DeploymentRuntimeState::Stopped | DeploymentRuntimeState::Failed
                    )
            })
        });
    let (phase, start, drain) = if prior_active {
        (
            RolloutPhase::DrainingPrior,
            Vec::new(),
            previous_assignments,
        )
    } else {
        (
            if target_ready {
                RolloutPhase::Stable
            } else {
                RolloutPhase::Starting
            },
            target,
            Vec::new(),
        )
    };
    Ok(RolloutDecision {
        deployment_id: request.target.deployment_id.clone(),
        target_generation: request.target.deployment_generation,
        phase,
        target_ready,
        timed_out: false,
        start,
        retain: Vec::new(),
        drain,
        handoff_deadline_unix_ms: request.handoff_deadline_unix_ms,
    })
}

fn target_is_ready(target: &PlacementPlan, observations: &[RolloutReplicaObservation]) -> bool {
    target.unplaced_replicas == 0
        && target.assignments.len()
            == usize::try_from(target.desired_replicas).unwrap_or(usize::MAX)
        && target.assignments.iter().all(|assignment| {
            observations.iter().any(|observation| {
                observation.node_id == assignment.node_id
                    && observation.deployment_generation == target.deployment_generation
                    && observation.state == DeploymentRuntimeState::Ready
                    && observation.variant_id.as_deref() == Some(assignment.variant_id.as_str())
                    && observation.artifact_digest.as_deref()
                        == Some(assignment.artifact_digest.as_str())
            })
        })
}

fn versioned_assignments(plan: &PlacementPlan) -> Vec<VersionedPlacementAssignment> {
    plan.assignments
        .iter()
        .cloned()
        .map(|assignment| VersionedPlacementAssignment {
            deployment_generation: plan.deployment_generation,
            assignment,
        })
        .collect()
}

fn validate_request(request: &RolloutRequest) -> Result<(), RolloutError> {
    validate_plan(&request.target)?;
    if request.handoff_deadline_unix_ms == 0 {
        return Err(RolloutError::Invalid(
            "handoff deadline must be positive".to_string(),
        ));
    }
    if request.observations.len() > MAX_ROLLOUT_OBSERVATIONS {
        return Err(RolloutError::Invalid(format!(
            "rollout observations exceed {MAX_ROLLOUT_OBSERVATIONS}"
        )));
    }
    let mut observations = BTreeSet::new();
    for observation in &request.observations {
        if !crate::artifact_spec::valid_identifier(&observation.node_id)
            || observation.deployment_generation == 0
            || !observations.insert((
                observation.node_id.as_str(),
                observation.deployment_generation,
            ))
        {
            return Err(RolloutError::Invalid(
                "observations contain an invalid or duplicate node generation".to_string(),
            ));
        }
    }
    if let Some(previous) = request.previous.as_ref() {
        validate_plan(previous)?;
        if previous.deployment_id != request.target.deployment_id {
            return Err(RolloutError::Invalid(
                "previous and target deployment IDs differ".to_string(),
            ));
        }
        if previous.deployment_generation > request.target.deployment_generation {
            return Err(RolloutError::Invalid(
                "previous generation is newer than the target".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_plan(plan: &PlacementPlan) -> Result<(), RolloutError> {
    if !crate::artifact_spec::valid_identifier(&plan.deployment_id)
        || plan.deployment_generation == 0
        || plan.desired_replicas == 0
    {
        return Err(RolloutError::Invalid(
            "placement plan identity or generation is invalid".to_string(),
        ));
    }
    let assigned = u32::try_from(plan.assignments.len())
        .map_err(|_| RolloutError::Invalid("placement assignment count overflowed".to_string()))?;
    if assigned.saturating_add(plan.unplaced_replicas) != plan.desired_replicas {
        return Err(RolloutError::Invalid(
            "placement assignment and unplaced counts are inconsistent".to_string(),
        ));
    }
    let mut nodes = BTreeSet::new();
    for assignment in &plan.assignments {
        if !crate::artifact_spec::valid_identifier(&assignment.node_id)
            || !nodes.insert(assignment.node_id.as_str())
        {
            return Err(RolloutError::Invalid(
                "placement assignments contain an invalid or duplicate node".to_string(),
            ));
        }
    }
    Ok(())
}
