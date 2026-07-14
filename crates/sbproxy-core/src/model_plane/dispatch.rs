use async_trait::async_trait;
use sbproxy_ai::managed_replica::{
    ManagedReplicaCandidate, ManagedReplicaSelection, ManagedRouteClass, ReplicaSelectionTrace,
};

use super::{ModelPlaneError, ModelPlaneRetryClass};
use crate::server::model_host::ManagedModelPermit;

const MAX_REPLICA_ATTEMPTS: usize = 8;
const MAX_ROUTE_IDENTIFIER_BYTES: usize = 128;
const MAX_ROUTE_POLICY_REVISION_BYTES: usize = 256;

/// Result of applying one deployment's concrete cold-start policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedColdStartDecision {
    /// Dispatch through the contained ready or explicitly cold candidates.
    Dispatch(ManagedReplicaSelection),
    /// Return a retryable refusal without executing a candidate.
    Reject(ManagedReplicaSelection),
    /// Advance to another provider without executing a candidate.
    Fallback(ManagedReplicaSelection),
    /// No ready or cold current candidate exists.
    Unavailable(ManagedReplicaSelection),
}

/// Apply a concrete deployment policy to ready-only and cold-capable selections.
pub fn choose_cold_start_candidates(
    ready: ManagedReplicaSelection,
    with_cold: ManagedReplicaSelection,
    policy: sbproxy_model_host::ColdStartPolicy,
) -> ManagedColdStartDecision {
    if !ready.candidates.is_empty() {
        return ManagedColdStartDecision::Dispatch(ready);
    }
    match policy {
        sbproxy_model_host::ColdStartPolicy::Wait if !with_cold.candidates.is_empty() => {
            ManagedColdStartDecision::Dispatch(with_cold)
        }
        sbproxy_model_host::ColdStartPolicy::Wait => {
            ManagedColdStartDecision::Unavailable(with_cold)
        }
        sbproxy_model_host::ColdStartPolicy::Reject if !with_cold.candidates.is_empty() => {
            ManagedColdStartDecision::Reject(with_cold)
        }
        sbproxy_model_host::ColdStartPolicy::Reject => {
            ManagedColdStartDecision::Unavailable(with_cold)
        }
        sbproxy_model_host::ColdStartPolicy::Fallback => {
            ManagedColdStartDecision::Fallback(with_cold)
        }
    }
}

/// Result of opening one local or authenticated peer response.
#[derive(Debug)]
pub struct ManagedAttemptResponse {
    /// Response headers and backpressured body.
    pub response: reqwest::Response,
    /// Local admission ownership, absent for peer responses.
    pub local_permit: Option<ManagedModelPermit>,
}

impl ManagedAttemptResponse {
    /// Build an attempt response whose capacity is owned elsewhere.
    pub fn without_permit(response: reqwest::Response) -> Self {
        Self {
            response,
            local_permit: None,
        }
    }

    /// Build a local attempt response and retain its admission permit.
    pub fn with_local_permit(
        response: reqwest::Response,
        local_permit: ManagedModelPermit,
    ) -> Self {
        Self {
            response,
            local_permit: Some(local_permit),
        }
    }
}

/// One injectable local or peer attempt implementation.
#[async_trait]
pub trait ManagedReplicaExecutor: Send + Sync {
    /// Open a response from the exact current-generation candidate.
    async fn execute(
        &self,
        candidate: &ManagedReplicaCandidate,
    ) -> Result<ManagedAttemptResponse, ModelPlaneError>;
}

/// Non-sensitive result of one replica attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedAttemptTrace {
    /// Stable worker identity, never its endpoint or certificate.
    pub node_id: String,
    /// Direct local call or authenticated peer hop.
    pub route_class: ManagedRouteClass,
    /// Stable outcome code such as `selected`, `queue_full`, or `http_503`.
    pub outcome: String,
    /// Retry classification when the attempt did not win.
    pub retry_class: Option<ModelPlaneRetryClass>,
}

/// Bounded route explanation safe for logs and request traces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRouteTrace {
    /// Bounded tenant boundary evaluated by the ingress gateway.
    pub tenant_id: String,
    /// Immutable, non-secret governed credential identifier.
    pub governed_key_id: String,
    /// Bounded effective policy revision evaluated at ingress.
    pub policy_revision: String,
    /// Candidate filtering and ordering summary.
    pub selection: ReplicaSelectionTrace,
    /// At most eight attempt results in dispatch order.
    pub attempts: Vec<ManagedAttemptTrace>,
    /// Number of safe pre-output handovers.
    pub failovers: usize,
    /// Ordered candidates omitted by the hard attempt bound.
    pub truncated_candidates: usize,
}

impl ManagedRouteTrace {
    fn new(
        selection: ReplicaSelectionTrace,
        attempts: Vec<ManagedAttemptTrace>,
        failovers: usize,
        truncated_candidates: usize,
        tenant_id: &str,
        governed_key_id: &str,
        policy_revision: &str,
    ) -> Self {
        Self {
            tenant_id: bounded_route_identifier(tenant_id, "tenant"),
            governed_key_id: bounded_route_identifier(governed_key_id, "anonymous"),
            policy_revision: bounded_route_policy_revision(policy_revision),
            selection,
            attempts,
            failovers,
            truncated_candidates,
        }
    }

    pub(crate) fn empty(
        selection: ManagedReplicaSelection,
        tenant_id: &str,
        governed_key_id: &str,
        policy_revision: &str,
    ) -> Self {
        let truncated_candidates = selection
            .candidates
            .len()
            .saturating_sub(MAX_REPLICA_ATTEMPTS);
        Self::new(
            selection.trace,
            Vec::new(),
            0,
            truncated_candidates,
            tenant_id,
            governed_key_id,
            policy_revision,
        )
    }
}

/// Selected response and the route that owns it.
#[derive(Debug)]
pub struct ManagedDispatchOutcome {
    /// Response returned by the local engine or authenticated peer.
    pub response: reqwest::Response,
    /// Selected worker identity.
    pub selected_node_id: String,
    /// Selected direct or peer route class.
    pub route_class: ManagedRouteClass,
    /// Local admission ownership retained through the public response stream.
    pub local_permit: Option<ManagedModelPermit>,
    /// Bounded non-sensitive decision trace.
    pub trace: ManagedRouteTrace,
}

/// Terminal failure after zero or more safe pre-output attempts.
#[derive(Debug, thiserror::Error)]
#[error("managed replica dispatch failed: {source}")]
pub struct ManagedDispatchFailure {
    /// Stable underlying model-plane failure.
    #[source]
    pub source: ModelPlaneError,
    /// Bounded non-sensitive decision trace.
    pub trace: ManagedRouteTrace,
}

/// Try ordered current-generation replicas without ever replaying a body stream.
///
/// Retry decisions are made from an error or response status before this function
/// returns a response to the public relay. Once a response is returned, its body
/// is owned by the caller and a later stream error cannot reach this coordinator.
pub async fn dispatch_managed_candidates(
    selection: ManagedReplicaSelection,
    executor: &dyn ManagedReplicaExecutor,
    tenant_id: &str,
    governed_key_id: &str,
    policy_revision: &str,
) -> Result<ManagedDispatchOutcome, ManagedDispatchFailure> {
    let attempted = selection.candidates.len().min(MAX_REPLICA_ATTEMPTS);
    let truncated_candidates = selection.candidates.len().saturating_sub(attempted);
    let mut trace = ManagedRouteTrace::new(
        selection.trace,
        Vec::with_capacity(attempted),
        0,
        truncated_candidates,
        tenant_id,
        governed_key_id,
        policy_revision,
    );
    if attempted == 0 {
        return Err(ManagedDispatchFailure {
            source: ModelPlaneError::NoEligibleReplica,
            trace,
        });
    }

    for (index, candidate) in selection.candidates.iter().take(attempted).enumerate() {
        let has_next = index + 1 < attempted;
        match executor.execute(candidate).await {
            Ok(attempt) => {
                let status = attempt.response.status().as_u16();
                if retryable_pre_output_status(status) && has_next {
                    trace.attempts.push(ManagedAttemptTrace {
                        node_id: candidate.replica.node_id.clone(),
                        route_class: candidate.route_class,
                        outcome: format!("http_{status}"),
                        retry_class: Some(retry_class_for_status(status)),
                    });
                    trace.failovers += 1;
                    continue;
                }
                trace.attempts.push(ManagedAttemptTrace {
                    node_id: candidate.replica.node_id.clone(),
                    route_class: candidate.route_class,
                    outcome: "selected".to_string(),
                    retry_class: None,
                });
                return Ok(ManagedDispatchOutcome {
                    response: attempt.response,
                    selected_node_id: candidate.replica.node_id.clone(),
                    route_class: candidate.route_class,
                    local_permit: attempt.local_permit,
                    trace,
                });
            }
            Err(source) => {
                let retry_class = source.retry_class();
                trace.attempts.push(ManagedAttemptTrace {
                    node_id: candidate.replica.node_id.clone(),
                    route_class: candidate.route_class,
                    outcome: source.code().to_string(),
                    retry_class: Some(retry_class),
                });
                if source.retryable() && has_next {
                    trace.failovers += 1;
                    continue;
                }
                return Err(ManagedDispatchFailure { source, trace });
            }
        }
    }

    unreachable!("bounded non-empty candidate loop always returns")
}

fn bounded_route_identifier(value: &str, fallback: &str) -> String {
    let candidate = if value.is_empty() { fallback } else { value };
    if candidate.len() <= MAX_ROUTE_IDENTIFIER_BYTES
        && candidate.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'@' | b'/')
        })
    {
        candidate.to_string()
    } else {
        use sha2::{Digest as _, Sha256};
        format!("id:{}", hex::encode(Sha256::digest(candidate.as_bytes())))
    }
}

fn bounded_route_policy_revision(value: &str) -> String {
    if !value.is_empty()
        && value.len() <= MAX_ROUTE_POLICY_REVISION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        value.to_string()
    } else {
        bounded_route_identifier(value, "unversioned")
    }
}

fn retryable_pre_output_status(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

fn retry_class_for_status(status: u16) -> ModelPlaneRetryClass {
    if status == 429 || status == 503 {
        ModelPlaneRetryClass::Capacity
    } else {
        ModelPlaneRetryClass::Transport
    }
}
