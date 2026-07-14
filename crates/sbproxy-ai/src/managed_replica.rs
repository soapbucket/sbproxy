// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Deterministic policy for selecting current managed-model replicas.

use std::cmp::Reverse;

use sbproxy_model_host::node_snapshot::ModelPlaneHealth;
use sbproxy_model_host::DeploymentRuntimeState;
use sha2::{Digest, Sha256};

use crate::model_directory::{ModelDirectoryReplica, ModelDirectoryView};

/// Request-scoped facts used to order managed replica candidates.
#[derive(Debug, Clone, Copy)]
pub struct ManagedReplicaInput<'a> {
    /// Stable node ID of the gateway making the routing decision.
    pub local_node_id: &'a str,
    /// Adapter that must already be declared by the replica, when requested.
    pub requested_adapter: Option<&'a str>,
    /// Preferred region label for locality-aware routing.
    pub preferred_region: Option<&'a str>,
    /// Stable tenant or prompt-prefix affinity key.
    pub prefix_key: &'a [u8],
    /// Whether assigned, cached, or preparing replicas may be selected.
    pub allow_cold: bool,
}

/// Whether a selected replica can be invoked directly or needs a peer hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedRouteClass {
    /// The selected replica belongs to this process's node identity.
    Local,
    /// The selected replica belongs to another authenticated cluster node.
    Peer,
}

/// One ordered replica together with its required transport class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedReplicaCandidate {
    /// Immutable directory candidate.
    pub replica: ModelDirectoryReplica,
    /// Local direct invocation or authenticated peer dispatch.
    pub route_class: ManagedRouteClass,
}

/// Bounded, non-sensitive counters explaining a replica selection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaSelectionTrace {
    /// Current directory candidates considered for the deployment.
    pub total_candidates: usize,
    /// Candidates remaining after every safety and policy filter.
    pub eligible_candidates: usize,
    /// Candidates rejected by the monotonic generation fence.
    pub excluded_generation: usize,
    /// Candidates rejected because the private model plane is unavailable.
    pub excluded_health: usize,
    /// Remote candidates rejected because no authenticated endpoint exists.
    pub excluded_endpoint: usize,
    /// Candidates rejected by ready-only or cold-start policy.
    pub excluded_state: usize,
    /// Candidates rejected because they lack the requested adapter.
    pub excluded_adapter: usize,
    /// Stable reason describing the first ordered candidate.
    pub selected_reason: Option<&'static str>,
}

/// Ordered candidates and the bounded trace for one decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedReplicaSelection {
    /// Safe candidates in deterministic preference order.
    pub candidates: Vec<ManagedReplicaCandidate>,
    /// Aggregate filter counts and selected reason.
    pub trace: ReplicaSelectionTrace,
}

/// Stateless deterministic managed-replica routing policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManagedReplicaRouter;

impl ManagedReplicaRouter {
    /// Filter and order current-generation candidates for one deployment.
    pub fn ordered_candidates(
        view: &ModelDirectoryView,
        deployment: &str,
        input: ManagedReplicaInput<'_>,
    ) -> ManagedReplicaSelection {
        let replicas = view
            .candidate_replicas
            .get(deployment)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let active_generation = view
            .deployment_generation_fences
            .get(deployment)
            .map(|fence| fence.deployment_generation);
        let mut trace = ReplicaSelectionTrace {
            total_candidates: replicas.len(),
            ..ReplicaSelectionTrace::default()
        };
        let mut scored = Vec::with_capacity(replicas.len());

        for replica in replicas {
            if active_generation != Some(replica.deployment_generation) {
                trace.excluded_generation += 1;
                continue;
            }
            if replica.model_plane_health == ModelPlaneHealth::Unavailable {
                trace.excluded_health += 1;
                continue;
            }
            let route_class = if replica.node_id == input.local_node_id {
                ManagedRouteClass::Local
            } else {
                ManagedRouteClass::Peer
            };
            if route_class == ManagedRouteClass::Peer && replica.endpoint.is_none() {
                trace.excluded_endpoint += 1;
                continue;
            }
            if !state_allowed(replica.state, input.allow_cold) {
                trace.excluded_state += 1;
                continue;
            }
            if input.requested_adapter.is_some_and(|adapter| {
                !replica
                    .adapters
                    .iter()
                    .any(|candidate| candidate == adapter)
            }) {
                trace.excluded_adapter += 1;
                continue;
            }

            scored.push(ScoredCandidate {
                candidate: ManagedReplicaCandidate {
                    replica: replica.clone(),
                    route_class,
                },
                prefix_score: prefix_score(input.prefix_key, deployment, &replica.node_id),
            });
        }

        scored.sort_by_key(|scored| {
            let replica = &scored.candidate.replica;
            (
                state_rank(replica.state),
                health_rank(replica.model_plane_health),
                region_rank(replica, input.preferred_region),
                replica.queue_depth,
                replica.active_requests,
                utilization_rank(replica.compute_utilization_millis),
                utilization_rank(replica.memory_occupancy_millis),
                scored.candidate.route_class != ManagedRouteClass::Local,
                Reverse(scored.prefix_score),
                replica.node_id.clone(),
            )
        });

        let candidates = scored
            .into_iter()
            .map(|scored| scored.candidate)
            .collect::<Vec<_>>();
        trace.eligible_candidates = candidates.len();
        trace.selected_reason = candidates.first().map(|candidate| {
            if candidate.route_class == ManagedRouteClass::Local {
                "local_fast_path"
            } else if candidate.replica.state != DeploymentRuntimeState::Ready {
                "cold_start"
            } else {
                "ready_low_queue"
            }
        });

        ManagedReplicaSelection { candidates, trace }
    }
}

struct ScoredCandidate {
    candidate: ManagedReplicaCandidate,
    prefix_score: u64,
}

fn state_allowed(state: DeploymentRuntimeState, allow_cold: bool) -> bool {
    state == DeploymentRuntimeState::Ready
        || (allow_cold
            && matches!(
                state,
                DeploymentRuntimeState::Assigned
                    | DeploymentRuntimeState::Cached
                    | DeploymentRuntimeState::Preparing
            ))
}

const fn state_rank(state: DeploymentRuntimeState) -> u8 {
    match state {
        DeploymentRuntimeState::Ready => 0,
        DeploymentRuntimeState::Preparing => 1,
        DeploymentRuntimeState::Cached => 2,
        DeploymentRuntimeState::Assigned => 3,
        DeploymentRuntimeState::Configured
        | DeploymentRuntimeState::Draining
        | DeploymentRuntimeState::Stopped
        | DeploymentRuntimeState::Failed => 4,
    }
}

const fn health_rank(health: ModelPlaneHealth) -> u8 {
    match health {
        ModelPlaneHealth::Ready => 0,
        ModelPlaneHealth::Degraded => 1,
        ModelPlaneHealth::Unavailable => 2,
    }
}

fn region_rank(replica: &ModelDirectoryReplica, preferred_region: Option<&str>) -> bool {
    let Some(preferred_region) = preferred_region else {
        return false;
    };
    !["region", "topology.kubernetes.io/region"]
        .iter()
        .filter_map(|label| replica.node_labels.get(*label))
        .any(|region| region == preferred_region)
}

const fn utilization_rank(value: Option<u16>) -> (bool, u16) {
    match value {
        Some(value) => (false, value),
        None => (true, u16::MAX),
    }
}

fn prefix_score(prefix_key: &[u8], deployment: &str, node_id: &str) -> u64 {
    let mut hash = Sha256::new();
    hash.update(b"sbproxy-managed-replica-v1\0");
    hash.update(prefix_key);
    hash.update(b"\0");
    hash.update(deployment.as_bytes());
    hash.update(b"\0");
    hash.update(node_id.as_bytes());
    let digest = hash.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"))
}
