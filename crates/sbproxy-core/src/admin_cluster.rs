// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cluster status, metrics, artifact-usage, and one-time enrollment
//! admin adapters.

use sbproxy_mesh::enrollment::{EnrollmentError, EnrollmentRequest};
use sbproxy_mesh::metrics::{
    ENROLLMENT_OUTCOME_ERROR, ENROLLMENT_OUTCOME_OK, ENROLLMENT_REASON_OK, MESH_ENROLLMENT,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Public one-time enrollment endpoint.
pub const ENROLL_PATH: &str = "/admin/cluster/enroll";
/// Authenticated cluster and node health endpoint.
pub const STATUS_PATH: &str = "/admin/cluster/status";
/// Authenticated signed cluster deployment read and publication endpoint.
pub const DEPLOYMENTS_PATH: &str = "/admin/cluster/deployments";
const METRICS_PATH: &str = "/admin/cluster/metrics";
const ARTIFACTS_PATH: &str = "/admin/cluster/artifacts";
/// Authenticated replicated-state listing and replicated delete (WOR-1947).
const STATE_PATH: &str = "/admin/cluster/state";
/// Authenticated bounded replicated-state purge (WOR-1947).
const STATE_PURGE_PATH: &str = "/admin/cluster/state/purge";
/// Authenticated single-record read and write on the replicated substrate.
const STATE_KEY_PATH: &str = "/admin/cluster/state/key";

#[derive(Debug, Clone, Serialize)]
struct ClusterStatusResponse {
    schema_version: u32,
    configured: bool,
    mode: &'static str,
    cluster_id: String,
    local_node_id: String,
    generated_at_unix_ms: u64,
    directory_collected_at_unix_ms: Option<u64>,
    directory_age_ms: Option<u64>,
    summary: ClusterStatusSummary,
    deployment_authority: ClusterDeploymentAuthorityStatus,
    deployments: Vec<ClusterDeploymentStatus>,
    nodes: Vec<ClusterStatusNode>,
    unhealthy_nodes: Vec<ClusterNodeAlert>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ClusterDeploymentAuthorityStatus {
    configured: bool,
    read_only: bool,
    verifying_key_id: Option<String>,
    active_revision: Option<u64>,
    active_content_digest: Option<String>,
    signer_node_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ClusterStatusSummary {
    total_nodes: usize,
    healthy_nodes: usize,
    degraded_nodes: usize,
    unhealthy_nodes: usize,
    eligible_workers: usize,
    eligible_replicas: usize,
    deployment_digest_mismatch: bool,
    deployments: usize,
    ready_deployments: usize,
    rollouts_in_progress: usize,
    unplaced_replicas: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterDeploymentStatus {
    deployment_id: String,
    model: String,
    generation: u64,
    desired_replicas: u32,
    placed_replicas: usize,
    unplaced_replicas: u32,
    phase: sbproxy_model_host::RolloutPhase,
    target_ready: bool,
    timed_out: bool,
    handoff_deadline_unix_ms: u64,
    assignments: Vec<sbproxy_model_host::PlacementAssignment>,
    retained: Vec<sbproxy_model_host::VersionedPlacementAssignment>,
    draining: Vec<sbproxy_model_host::VersionedPlacementAssignment>,
    rejections: BTreeMap<String, sbproxy_model_host::PlacementRejectionReason>,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterStatusNode {
    node_id: String,
    local: bool,
    membership_state: &'static str,
    address: Option<String>,
    last_ack_age_ms: u64,
    incarnation: u64,
    health: &'static str,
    unhealthy: bool,
    unhealthy_reasons: Vec<String>,
    roles: BTreeSet<sbproxy_model_host::node_snapshot::NodeRole>,
    labels: BTreeMap<String, String>,
    model_endpoint: Option<String>,
    model_eligible: bool,
    exclusion_reason: Option<String>,
    snapshot_age_ms: Option<u64>,
    snapshot_generation: Option<u64>,
    observed_schema_version: Option<u32>,
    normalized_schema_version: Option<u32>,
    reported_health: Option<sbproxy_model_host::node_snapshot::NodeHealthSnapshot>,
    engine_count: usize,
    device_count: usize,
    ready_artifact_count: usize,
    replicas: Vec<sbproxy_model_host::node_snapshot::NodeReplicaSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterNodeAlert {
    node_id: String,
    health: &'static str,
    reasons: Vec<String>,
    membership_state: &'static str,
    last_ack_age_ms: u64,
    snapshot_age_ms: Option<u64>,
    model_endpoint: Option<String>,
}

/// Whether a path uses its enrollment token instead of admin credentials.
pub fn is_public_enrollment_path(path: &str) -> bool {
    path.split('?').next() == Some(ENROLL_PATH)
}

/// Dispatch cluster-owned admin requests.
pub fn dispatch(
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Option<(u16, &'static str, String)> {
    let query = path.split_once('?').map(|(_, query)| query);
    let path = path.split('?').next().unwrap_or(path);
    match path {
        STATUS_PATH => Some(dispatch_status(method)),
        DEPLOYMENTS_PATH => Some(dispatch_deployments(method, body)),
        METRICS_PATH => Some(dispatch_metrics(method)),
        ARTIFACTS_PATH => Some(dispatch_artifacts(method)),
        ENROLL_PATH => Some(dispatch_enrollment(method, body)),
        STATE_PATH => Some(dispatch_state(method, query)),
        STATE_PURGE_PATH => Some(dispatch_state_purge(method, body)),
        STATE_KEY_PATH => Some(dispatch_state_key(method, query, body)),
        _ => None,
    }
}

/// Single-record read and write through the replicated quorum paths.
fn dispatch_state_key(
    method: &str,
    query: Option<&str>,
    body: Option<&str>,
) -> (u16, &'static str, String) {
    let store = match replicated_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let Some(key) = query_param(query, "key").filter(|key| !key.is_empty()) else {
        return json(
            400,
            serde_json::json!({"error": "missing key query parameter", "code": "bad_request"}),
        );
    };
    if method.eq_ignore_ascii_case("GET") {
        return match crate::cluster::block_on_cluster(store.get(&key)) {
            Ok(outcome) => {
                let value_base64 = outcome.value.as_ref().map(|value| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(value)
                });
                let value_utf8 = outcome
                    .value
                    .as_ref()
                    .and_then(|value| std::str::from_utf8(value).ok().map(str::to_string));
                json(
                    if outcome.value.is_some() { 200 } else { 404 },
                    serde_json::json!({
                        "schema_version": 1,
                        "key": key,
                        "found": outcome.value.is_some(),
                        "value_base64": value_base64,
                        "value_utf8": value_utf8,
                        "replicas_answered": outcome.responses,
                        "repaired": outcome.repaired,
                    }),
                )
            }
            Err(error) => json(
                502,
                serde_json::json!({
                    "error": format!("replicated read failed: {error}"),
                    "code": "replication_read_failed",
                }),
            ),
        };
    }
    if method.eq_ignore_ascii_case("PUT") {
        let Some(value) = body else {
            return json(
                400,
                serde_json::json!({"error": "request body is the record value", "code": "bad_request"}),
            );
        };
        let ttl_secs = query_param(query, "ttl_secs")
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(0);
        return match crate::cluster::block_on_cluster(store.put(&key, value.as_bytes(), ttl_secs)) {
            Ok(receipt) => json(
                200,
                serde_json::json!({
                    "schema_version": 1,
                    "key": key,
                    "acked_replicas": receipt.acked,
                    "logical_version": receipt.register.logical_version(),
                }),
            ),
            Err(error) => json(
                502,
                serde_json::json!({
                    "error": format!("replicated write failed: {error}"),
                    "code": "replication_write_failed",
                }),
            ),
        };
    }
    json(405, serde_json::json!({"error": "method not allowed"}))
}

// --- WOR-1947 replicated-state admin ---

/// Resolve the replicated store, or the standard "not enabled" error.
fn replicated_store(
) -> Result<Arc<sbproxy_mesh::state::replicated::ReplicatedStore>, (u16, &'static str, String)> {
    crate::cluster::current_cluster_handle()
        .and_then(|handle| handle.mesh_node())
        .and_then(|node| node.replicated_store())
        .ok_or_else(|| {
            json(
                404,
                serde_json::json!({
                    "error": "replicated state substrate not enabled",
                    "code": "replication_disabled",
                }),
            )
        })
}

/// Minimal percent-decoder for admin query parameters. Replicated keys
/// and opaque page tokens can carry characters that URL syntax reserves.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).and_then(|pair| {
                    std::str::from_utf8(pair)
                        .ok()
                        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                });
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| percent_decode(value))
}

fn dispatch_state(method: &str, query: Option<&str>) -> (u16, &'static str, String) {
    let store = match replicated_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    if method.eq_ignore_ascii_case("GET") {
        let prefix = query_param(query, "prefix").unwrap_or_default();
        let page_token = query_param(query, "page_token");
        let limit = query_param(query, "limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(200);
        let page = crate::cluster::block_on_cluster(store.fleet_state_page(
            &prefix,
            page_token.as_deref(),
            limit,
        ));
        return json(
            200,
            serde_json::json!({
                "schema_version": 1,
                "entries": page.entries,
                "next_page_token": page.next_page_token,
                "unreachable": page.unreachable,
            }),
        );
    }
    if method.eq_ignore_ascii_case("DELETE") {
        let Some(key) = query_param(query, "key").filter(|key| !key.is_empty()) else {
            return json(
                400,
                serde_json::json!({"error": "missing key query parameter", "code": "bad_request"}),
            );
        };
        return match crate::cluster::block_on_cluster(store.delete(&key)) {
            Ok(receipt) => json(
                200,
                serde_json::json!({
                    "schema_version": 1,
                    "deleted": key,
                    "acked_replicas": receipt.acked,
                }),
            ),
            Err(error) => json(
                502,
                serde_json::json!({
                    "error": format!("replicated delete failed: {error}"),
                    "code": "replication_write_failed",
                }),
            ),
        };
    }
    json(405, serde_json::json!({"error": "method not allowed"}))
}

fn dispatch_state_purge(method: &str, body: Option<&str>) -> (u16, &'static str, String) {
    if !method.eq_ignore_ascii_case("POST") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    let store = match replicated_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    #[derive(serde::Deserialize)]
    struct PurgeRequest {
        prefix: String,
        #[serde(default = "default_purge_max")]
        max: usize,
    }
    fn default_purge_max() -> usize {
        1_000
    }
    let request = match body.map(serde_json::from_str::<PurgeRequest>) {
        Some(Ok(request)) => request,
        _ => {
            return json(
                400,
                serde_json::json!({"error": "body must be {\"prefix\": string, \"max\": number}", "code": "bad_request"}),
            )
        }
    };
    let outcome = crate::cluster::block_on_cluster(store.fleet_purge(&request.prefix, request.max));
    json(
        200,
        serde_json::json!({
            "schema_version": 1,
            "deleted": outcome.deleted,
            "failed": outcome.failed,
            "truncated": outcome.truncated,
        }),
    )
}

fn dispatch_deployments(method: &str, body: Option<&str>) -> (u16, &'static str, String) {
    let authority = crate::cluster::current_deployment_authority();
    dispatch_deployments_with(method, body, authority.as_ref())
}

fn dispatch_deployments_with(
    method: &str,
    body: Option<&str>,
    authority: Option<&crate::cluster::ClusterDeploymentAuthority>,
) -> (u16, &'static str, String) {
    if method.eq_ignore_ascii_case("GET") {
        let Some(active) = authority.and_then(|authority| authority.active()) else {
            return json(
                404,
                serde_json::json!({"error": "no active cluster deployment bundle", "code": "deployment_bundle_missing"}),
            );
        };
        let bundle = match active.bundle().to_json().and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|source| {
                sbproxy_model_host::DeploymentAuthorityError::Json {
                    operation: "render admin response",
                    source,
                }
            })
        }) {
            Ok(bundle) => bundle,
            Err(error) => {
                tracing::error!(%error, "render active cluster deployment bundle");
                return json(
                    500,
                    serde_json::json!({"error": "cluster deployment read failed", "code": "internal"}),
                );
            }
        };
        return json(
            200,
            serde_json::json!({
                "schema_version": 1,
                "bundle": bundle,
                "signer_node_id": active.signer_node_id(),
                "signer_key_id": active.signer_key_id(),
                "read_only": authority.is_none_or(|authority| !authority.can_publish()),
            }),
        );
    }
    if !method.eq_ignore_ascii_case("POST") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    let Some(authority) = authority.filter(|authority| authority.can_publish()) else {
        return json(
            403,
            serde_json::json!({"error": "cluster deployment authority is read-only on this node", "code": "deployment_authority_read_only"}),
        );
    };
    let Some(body) = body.filter(|body| !body.is_empty()) else {
        return json(
            400,
            serde_json::json!({"error": "deployment bundle body is required", "code": "invalid_bundle"}),
        );
    };
    let bundle =
        match sbproxy_model_host::RestrictedDeploymentBundleDraft::from_json(body.as_bytes())
            .and_then(sbproxy_model_host::RestrictedDeploymentBundleDraft::into_bundle)
        {
            Ok(bundle) => bundle,
            Err(error) => {
                return json(
                    400,
                    serde_json::json!({"error": error.to_string(), "code": "invalid_bundle"}),
                )
            }
        };
    if let Some(active) = authority.active() {
        if bundle.revision < active.bundle().revision {
            return json(
                409,
                serde_json::json!({"error": "deployment revision is stale", "code": "stale_revision"}),
            );
        }
        if bundle.revision == active.bundle().revision
            && bundle.content_digest != active.bundle().content_digest
        {
            return json(
                409,
                serde_json::json!({"error": "deployment revision conflicts with active content", "code": "revision_conflict"}),
            );
        }
    }
    match authority.publish_blocking(bundle) {
        Ok(signed) => json(
            202,
            serde_json::json!({
                "schema_version": 1,
                "revision": signed.bundle.revision,
                "content_digest": signed.bundle.content_digest,
                "signer_node_id": signed.signer_node_id,
                "signer_key_id": signed.signer_key_id,
                "status": "published",
            }),
        ),
        Err(crate::cluster::ClusterDeploymentAuthorityError::ReadOnly) => json(
            403,
            serde_json::json!({"error": "cluster deployment authority is read-only on this node", "code": "deployment_authority_read_only"}),
        ),
        Err(error) => {
            tracing::error!(%error, "publish signed cluster deployment bundle");
            json(
                500,
                serde_json::json!({"error": "cluster deployment publication failed", "code": "internal"}),
            )
        }
    }
}

fn dispatch_status(method: &str) -> (u16, &'static str, String) {
    if !method.eq_ignore_ascii_case("GET") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    let Some(handle) = crate::cluster::current_cluster_handle() else {
        return json(
            503,
            serde_json::json!({"error": "cluster owner is not initialized"}),
        );
    };
    let settings =
        crate::cluster::current_cluster_settings().unwrap_or(crate::cluster::ClusterSettings {
            snapshot_ttl_secs: 30,
            publish_interval_secs: 5,
            distributed_requested: false,
            model_control_enabled: false,
        });
    let view = crate::cluster::current_model_directory().map(|directory| directory.load());
    let placement = crate::server::model_host::model_runtime_manager().cluster_placement_state();
    let authority = crate::cluster::current_deployment_authority();
    dispatch_status_with_placement(
        method,
        handle,
        settings,
        view,
        placement.as_ref(),
        authority.as_ref(),
        unix_time_ms(),
    )
}

#[cfg(test)]
fn dispatch_status_with(
    method: &str,
    handle: sbproxy_mesh::ClusterHandle,
    settings: crate::cluster::ClusterSettings,
    view: Option<Arc<sbproxy_ai::model_directory::ModelDirectoryView>>,
    now: u64,
) -> (u16, &'static str, String) {
    dispatch_status_with_placement(method, handle, settings, view, None, None, now)
}

fn dispatch_status_with_placement(
    method: &str,
    handle: sbproxy_mesh::ClusterHandle,
    settings: crate::cluster::ClusterSettings,
    view: Option<Arc<sbproxy_ai::model_directory::ModelDirectoryView>>,
    placement: Option<&sbproxy_model_host::ClusterPlacementState>,
    authority: Option<&crate::cluster::ClusterDeploymentAuthority>,
    now: u64,
) -> (u16, &'static str, String) {
    if !method.eq_ignore_ascii_case("GET") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    let response = cluster_status_response(
        &handle,
        settings,
        view.as_deref(),
        placement,
        authority,
        now,
    );
    match serde_json::to_string(&response) {
        Ok(body) => (200, "application/json", body),
        Err(error) => {
            tracing::error!(%error, "serialize cluster status response");
            json(500, serde_json::json!({"error": "cluster status failed"}))
        }
    }
}

fn cluster_status_response(
    handle: &sbproxy_mesh::ClusterHandle,
    settings: crate::cluster::ClusterSettings,
    view: Option<&sbproxy_ai::model_directory::ModelDirectoryView>,
    placement: Option<&sbproxy_model_host::ClusterPlacementState>,
    authority: Option<&crate::cluster::ClusterDeploymentAuthority>,
    now: u64,
) -> ClusterStatusResponse {
    let configured = settings.distributed_requested;
    let mode = match handle.mode() {
        sbproxy_mesh::ClusterMode::Local => "local",
        sbproxy_mesh::ClusterMode::Distributed => "distributed",
    };
    let directory_collected_at_unix_ms = view
        .filter(|view| view.collected_at_unix_ms > 0)
        .map(|view| view.collected_at_unix_ms);
    let directory_age_ms =
        directory_collected_at_unix_ms.map(|collected| now.saturating_sub(collected));
    let directory_stale = configured
        && directory_age_ms
            .is_some_and(|age| age >= settings.snapshot_ttl_secs.saturating_mul(1_000));
    let mut nodes = if let Some(view) = view.filter(|view| !view.nodes.is_empty()) {
        view.nodes
            .iter()
            .map(|node| {
                status_node_from_directory(
                    node,
                    handle.identity(),
                    now,
                    directory_age_ms.unwrap_or(0),
                    directory_stale,
                )
            })
            .collect::<Vec<_>>()
    } else {
        handle
            .membership()
            .into_iter()
            .map(|member| status_node_from_membership(member, handle.identity(), configured))
            .collect::<Vec<_>>()
    };
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let eligible_replicas = nodes
        .iter()
        .filter(|node| node.model_eligible)
        .map(|node| {
            node.replicas
                .iter()
                .filter(|replica| {
                    replica.state == sbproxy_model_host::DeploymentRuntimeState::Ready
                })
                .count()
        })
        .sum();
    let deployments = placement.map_or_else(Vec::new, deployment_statuses);
    let summary = ClusterStatusSummary {
        total_nodes: nodes.len(),
        healthy_nodes: nodes.iter().filter(|node| node.health == "healthy").count(),
        degraded_nodes: nodes
            .iter()
            .filter(|node| node.health == "degraded")
            .count(),
        unhealthy_nodes: nodes.iter().filter(|node| node.unhealthy).count(),
        eligible_workers: nodes.iter().filter(|node| node.model_eligible).count(),
        eligible_replicas,
        deployment_digest_mismatch: view
            .is_some_and(|view| view.summary.deployment_digest_mismatch),
        deployments: deployments.len(),
        ready_deployments: deployments
            .iter()
            .filter(|deployment| deployment.target_ready)
            .count(),
        rollouts_in_progress: deployments
            .iter()
            .filter(|deployment| deployment.phase != sbproxy_model_host::RolloutPhase::Stable)
            .count(),
        unplaced_replicas: deployments
            .iter()
            .map(|deployment| u64::from(deployment.unplaced_replicas))
            .sum(),
    };
    let unhealthy_nodes = nodes
        .iter()
        .filter(|node| node.unhealthy)
        .map(|node| ClusterNodeAlert {
            node_id: node.node_id.clone(),
            health: node.health,
            reasons: node.unhealthy_reasons.clone(),
            membership_state: node.membership_state,
            last_ack_age_ms: node.last_ack_age_ms,
            snapshot_age_ms: node.snapshot_age_ms,
            model_endpoint: node.model_endpoint.clone(),
        })
        .collect();
    let deployment_authority =
        authority.map_or_else(ClusterDeploymentAuthorityStatus::default, |authority| {
            let active = authority.active();
            ClusterDeploymentAuthorityStatus {
                configured: true,
                read_only: !authority.can_publish(),
                verifying_key_id: Some(authority.verifying_key_id().to_string()),
                active_revision: active.as_ref().map(|active| active.bundle().revision),
                active_content_digest: active
                    .as_ref()
                    .map(|active| active.bundle().content_digest.clone()),
                signer_node_id: active
                    .as_ref()
                    .map(|active| active.signer_node_id().to_string()),
            }
        });
    ClusterStatusResponse {
        schema_version: 1,
        configured,
        mode,
        cluster_id: handle.identity().cluster_id.clone(),
        local_node_id: handle.identity().node_id.clone(),
        generated_at_unix_ms: now,
        directory_collected_at_unix_ms,
        directory_age_ms,
        summary,
        deployment_authority,
        deployments,
        nodes,
        unhealthy_nodes,
    }
}

fn deployment_statuses(
    placement: &sbproxy_model_host::ClusterPlacementState,
) -> Vec<ClusterDeploymentStatus> {
    placement
        .deployments()
        .iter()
        .map(|(deployment_id, deployment)| ClusterDeploymentStatus {
            deployment_id: deployment_id.clone(),
            model: deployment.deployment.desired.model.clone(),
            generation: deployment.target.deployment_generation,
            desired_replicas: deployment.target.desired_replicas,
            placed_replicas: deployment.target.assignments.len(),
            unplaced_replicas: deployment.target.unplaced_replicas,
            phase: deployment.rollout.phase,
            target_ready: deployment.rollout.target_ready,
            timed_out: deployment.rollout.timed_out,
            handoff_deadline_unix_ms: deployment.rollout.handoff_deadline_unix_ms,
            assignments: deployment.target.assignments.clone(),
            retained: deployment.rollout.retain.clone(),
            draining: deployment.rollout.drain.clone(),
            rejections: deployment.target.rejections.clone(),
        })
        .collect()
}

fn status_node_from_directory(
    node: &sbproxy_ai::model_directory::ModelDirectoryNode,
    local: &sbproxy_mesh::ClusterIdentity,
    now: u64,
    directory_age_ms: u64,
    directory_stale: bool,
) -> ClusterStatusNode {
    use sbproxy_ai::model_directory::ModelDirectoryHealth;

    let mut health = match node.health {
        ModelDirectoryHealth::Healthy => "healthy",
        ModelDirectoryHealth::Degraded => "degraded",
        ModelDirectoryHealth::Unhealthy => "unhealthy",
    };
    let mut reasons = node.unhealthy_reasons.clone();
    let mut model_eligible = node.model_eligible;
    let mut exclusion_reason = node
        .exclusion_reason
        .map(|reason| reason.as_str().to_string());
    if directory_stale {
        health = "unhealthy";
        model_eligible = false;
        exclusion_reason = Some("directory_stale".to_string());
        if !reasons.iter().any(|reason| reason == "directory_stale") {
            reasons.push("directory_stale".to_string());
            reasons.sort();
        }
    }
    let directory_age = node
        .snapshot
        .as_ref()
        .map(|snapshot| now.saturating_sub(snapshot.published_at_unix_ms))
        .or(node.snapshot_age_ms);
    ClusterStatusNode {
        node_id: node.node_id.clone(),
        local: node.node_id == local.node_id,
        membership_state: member_state_str(node.membership_state),
        address: node.address.clone(),
        last_ack_age_ms: node.last_ack_age_ms.saturating_add(directory_age_ms),
        incarnation: node.incarnation,
        health,
        unhealthy: health == "unhealthy",
        unhealthy_reasons: reasons,
        roles: node.roles.clone(),
        labels: node.labels.clone(),
        model_endpoint: node.model_endpoint.clone(),
        model_eligible,
        exclusion_reason,
        snapshot_age_ms: directory_age,
        snapshot_generation: node.snapshot_generation,
        observed_schema_version: node.observed_schema_version,
        normalized_schema_version: node.normalized_schema_version,
        reported_health: node.reported_health.clone(),
        engine_count: node.engine_count,
        device_count: node.device_count,
        ready_artifact_count: node.ready_artifact_count,
        replicas: node.replicas.clone(),
    }
}

fn status_node_from_membership(
    member: sbproxy_mesh::ClusterMember,
    local: &sbproxy_mesh::ClusterIdentity,
    configured: bool,
) -> ClusterStatusNode {
    let local_member = member.node_id == local.node_id;
    let (membership_state, mut reasons) = match member.state {
        sbproxy_mesh::ClusterMemberState::Alive => ("alive", Vec::new()),
        sbproxy_mesh::ClusterMemberState::Suspect => {
            ("suspect", vec!["membership_suspect".to_string()])
        }
        sbproxy_mesh::ClusterMemberState::Dead => ("dead", vec!["membership_dead".to_string()]),
        sbproxy_mesh::ClusterMemberState::Unreachable => {
            ("unreachable", vec!["membership_unreachable".to_string()])
        }
    };
    if configured && reasons.is_empty() {
        reasons.push("directory_not_collected".to_string());
    }
    let unhealthy = !reasons.is_empty();
    let exclusion_reason = reasons.first().cloned();
    ClusterStatusNode {
        node_id: member.node_id,
        local: local_member,
        membership_state,
        address: member.address,
        last_ack_age_ms: u64::try_from(member.last_ack_age.as_millis()).unwrap_or(u64::MAX),
        incarnation: member.incarnation,
        health: if unhealthy { "unhealthy" } else { "healthy" },
        unhealthy,
        unhealthy_reasons: reasons,
        roles: if local_member {
            local.roles.iter().copied().map(status_role).collect()
        } else {
            BTreeSet::new()
        },
        labels: if local_member {
            local.labels.clone()
        } else {
            BTreeMap::new()
        },
        model_endpoint: if local_member {
            local.model_endpoint.clone()
        } else {
            None
        },
        model_eligible: false,
        exclusion_reason,
        snapshot_age_ms: None,
        snapshot_generation: None,
        observed_schema_version: None,
        normalized_schema_version: None,
        reported_health: None,
        engine_count: 0,
        device_count: 0,
        ready_artifact_count: 0,
        replicas: Vec::new(),
    }
}

const fn status_role(
    role: sbproxy_mesh::ClusterNodeRole,
) -> sbproxy_model_host::node_snapshot::NodeRole {
    match role {
        sbproxy_mesh::ClusterNodeRole::Gateway => {
            sbproxy_model_host::node_snapshot::NodeRole::Gateway
        }
        sbproxy_mesh::ClusterNodeRole::Worker => {
            sbproxy_model_host::node_snapshot::NodeRole::Worker
        }
        sbproxy_mesh::ClusterNodeRole::Authority => {
            sbproxy_model_host::node_snapshot::NodeRole::Authority
        }
    }
}

const fn member_state_str(
    state: sbproxy_ai::model_directory::DirectoryMemberState,
) -> &'static str {
    match state {
        sbproxy_ai::model_directory::DirectoryMemberState::Alive => "alive",
        sbproxy_ai::model_directory::DirectoryMemberState::Suspect => "suspect",
        sbproxy_ai::model_directory::DirectoryMemberState::Dead => "dead",
        sbproxy_ai::model_directory::DirectoryMemberState::Unreachable => "unreachable",
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn dispatch_metrics(method: &str) -> (u16, &'static str, String) {
    if !method.eq_ignore_ascii_case("GET") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    match crate::cluster_metrics::fleet_metrics_json() {
        Some(body) => (200, "application/json", body),
        None => json(
            404,
            serde_json::json!({
                "error": "cluster metrics not enabled; configure a distributed cluster or use external Prometheus"
            }),
        ),
    }
}

#[derive(Debug, Clone, Serialize)]
struct ClusterArtifactsResponse {
    schema_version: u32,
    nodes: Vec<ClusterArtifactsNode>,
    models: Vec<ClusterArtifactsModel>,
    partial: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterArtifactsNode {
    node_id: String,
    total_bytes: u64,
    artifact_count: usize,
    snapshot_age_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ClusterArtifactsModel {
    logical_model: String,
    total_bytes: u64,
    node_count: usize,
}

// WOR-1910: fleet artifact disk usage aggregated from the node snapshots
// already collected in the cluster model directory. Without a configured
// cluster the local verified cache is the whole fleet, reported as one
// "local" node.
fn dispatch_artifacts(method: &str) -> (u16, &'static str, String) {
    if !method.eq_ignore_ascii_case("GET") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    match crate::cluster::current_model_directory() {
        // The process-wide directory exists even without a configured
        // cluster; an empty membership means this node is the fleet, so
        // report the local cache rather than an empty aggregate.
        Some(directory) => {
            let view = directory.load();
            if view.nodes.is_empty() {
                local_artifacts_response()
            } else {
                artifacts_response_from_directory(&view, unix_time_ms())
            }
        }
        None => local_artifacts_response(),
    }
}

fn artifacts_response_from_directory(
    view: &sbproxy_ai::model_directory::ModelDirectoryView,
    now: u64,
) -> (u16, &'static str, String) {
    let mut partial = false;
    let mut nodes = Vec::with_capacity(view.nodes.len());
    let mut models: BTreeMap<String, (u64, BTreeSet<String>)> = BTreeMap::new();
    for node in &view.nodes {
        let Some(snapshot) = node.snapshot.as_ref() else {
            // A member without an accepted snapshot has unknown cache
            // truth, so the aggregate is explicitly partial.
            partial = true;
            continue;
        };
        let mut total_bytes: u64 = 0;
        let mut artifact_count = 0usize;
        for artifact in &snapshot.artifacts {
            // Snapshots include synthesized zero-byte "missing" rows for
            // runtime digests absent from the inventory; only bytes on
            // disk count toward usage.
            if artifact.completed_bytes == 0 {
                continue;
            }
            total_bytes = total_bytes.saturating_add(artifact.completed_bytes);
            artifact_count += 1;
            let entry = models.entry(artifact.model.clone()).or_default();
            entry.0 = entry.0.saturating_add(artifact.completed_bytes);
            entry.1.insert(node.node_id.clone());
        }
        nodes.push(ClusterArtifactsNode {
            node_id: node.node_id.clone(),
            total_bytes,
            artifact_count,
            snapshot_age_ms: now.saturating_sub(snapshot.published_at_unix_ms),
        });
    }
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    render_artifacts_response(nodes, models, partial)
}

fn local_artifacts_response() -> (u16, &'static str, String) {
    let runtime = crate::server::model_host::model_runtime_manager();
    let mut total_bytes: u64 = 0;
    let mut artifact_count = 0usize;
    let mut models: BTreeMap<String, (u64, BTreeSet<String>)> = BTreeMap::new();
    match runtime.cached_artifacts() {
        // No model host is configured, so no artifact cache is open and
        // the single-node inventory is honestly empty.
        None => {}
        Some(Ok(artifacts)) => {
            for artifact in artifacts {
                total_bytes = total_bytes.saturating_add(artifact.total_size_bytes);
                artifact_count += 1;
                let entry = models.entry(artifact.logical_model).or_default();
                entry.0 = entry.0.saturating_add(artifact.total_size_bytes);
                entry.1.insert("local".to_string());
            }
        }
        Some(Err(error)) => {
            tracing::error!(%error, "list local artifact inventory for cluster aggregate");
            return json(
                502,
                serde_json::json!({"error": "artifact inventory unavailable; inspect server logs"}),
            );
        }
    }
    let nodes = vec![ClusterArtifactsNode {
        node_id: "local".to_string(),
        total_bytes,
        artifact_count,
        snapshot_age_ms: 0,
    }];
    render_artifacts_response(nodes, models, false)
}

fn render_artifacts_response(
    nodes: Vec<ClusterArtifactsNode>,
    models: BTreeMap<String, (u64, BTreeSet<String>)>,
    partial: bool,
) -> (u16, &'static str, String) {
    let models = models
        .into_iter()
        .map(
            |(logical_model, (total_bytes, model_nodes))| ClusterArtifactsModel {
                logical_model,
                total_bytes,
                node_count: model_nodes.len(),
            },
        )
        .collect();
    let response = ClusterArtifactsResponse {
        schema_version: 1,
        nodes,
        models,
        partial,
    };
    match serde_json::to_string(&response) {
        Ok(body) => (200, "application/json", body),
        Err(error) => {
            tracing::error!(%error, "serialize cluster artifacts response");
            json(
                500,
                serde_json::json!({"error": "cluster artifacts failed"}),
            )
        }
    }
}

fn dispatch_enrollment(method: &str, body: Option<&str>) -> (u16, &'static str, String) {
    dispatch_enrollment_with(method, body, crate::cluster::current_enrollment_authority())
}

fn dispatch_enrollment_with(
    method: &str,
    body: Option<&str>,
    authority: Option<Arc<sbproxy_mesh::enrollment::EnrollmentAuthority>>,
) -> (u16, &'static str, String) {
    if !method.eq_ignore_ascii_case("POST") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    let Some(body) = body.filter(|body| !body.is_empty() && body.len() <= 64 * 1024) else {
        MESH_ENROLLMENT
            .with_label_values(&[ENROLLMENT_OUTCOME_ERROR, "invalid_request"])
            .inc();
        return json(
            400,
            serde_json::json!({"error": "invalid enrollment request", "code": "invalid_request"}),
        );
    };
    let request: EnrollmentRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(_) => {
            MESH_ENROLLMENT
                .with_label_values(&[ENROLLMENT_OUTCOME_ERROR, "invalid_request"])
                .inc();
            return json(
                400,
                serde_json::json!({"error": "invalid enrollment request", "code": "invalid_request"}),
            );
        }
    };
    let Some(authority) = authority else {
        MESH_ENROLLMENT
            .with_label_values(&[ENROLLMENT_OUTCOME_ERROR, "authority_unavailable"])
            .inc();
        return json(
            503,
            serde_json::json!({"error": "this node is not an enrollment authority", "code": "authority_unavailable"}),
        );
    };
    match authority.enroll(request) {
        Ok(response) => {
            // The authority accepted the request and consumed the token,
            // so the attempt counts as ok even if response serialization
            // fails below.
            MESH_ENROLLMENT
                .with_label_values(&[ENROLLMENT_OUTCOME_OK, ENROLLMENT_REASON_OK])
                .inc();
            match serde_json::to_string(&response) {
                Ok(body) => (200, "application/json", body),
                Err(error) => {
                    tracing::error!(%error, "serialize cluster enrollment response");
                    json(
                        500,
                        serde_json::json!({"error": "cluster enrollment failed", "code": "internal"}),
                    )
                }
            }
        }
        Err(error) => enrollment_error_response(error),
    }
}

/// Bounded `reason` label for `mesh_enrollment_total`, mapped explicitly
/// from the [`EnrollmentError`] variant.
fn enrollment_error_reason(error: &EnrollmentError) -> &'static str {
    match error {
        EnrollmentError::InvalidRequest(_) => "invalid_request",
        EnrollmentError::AlreadyExists(_) => "already_exists",
        EnrollmentError::AuthorityMissing(_) => "authority_missing",
        EnrollmentError::Corrupt(_) => "corrupt",
        EnrollmentError::TokenRejected(_) => "token_rejected",
        EnrollmentError::Io(_) => "io",
        EnrollmentError::Json(_) => "json",
        EnrollmentError::Crypto(_) => "crypto",
    }
}

fn enrollment_error_response(error: EnrollmentError) -> (u16, &'static str, String) {
    MESH_ENROLLMENT
        .with_label_values(&[ENROLLMENT_OUTCOME_ERROR, enrollment_error_reason(&error)])
        .inc();
    match error {
        EnrollmentError::TokenRejected(_) => json(
            401,
            serde_json::json!({"error": "enrollment denied", "code": "enrollment_denied"}),
        ),
        EnrollmentError::InvalidRequest(_) => json(
            400,
            serde_json::json!({"error": "invalid enrollment request", "code": "invalid_request"}),
        ),
        error => {
            tracing::error!(%error, "cluster enrollment authority failed");
            json(
                500,
                serde_json::json!({"error": "cluster enrollment failed", "code": "internal"}),
            )
        }
    }
}

fn json(status: u16, value: serde_json::Value) -> (u16, &'static str, String) {
    (status, "application/json", value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use sbproxy_mesh::enrollment::{
        AuthorityInit, EnrollmentAuthority, EnrollmentTokenConstraints, WorkerEnrollment,
    };
    use sbproxy_mesh::{ClusterHandle, ClusterIdentity, ClusterNodeRole};

    #[test]
    fn non_matching_path_returns_none() {
        assert!(dispatch("GET", "/metrics", None).is_none());
        assert!(dispatch("GET", "/admin/model-host/status", None).is_none());
    }

    #[test]
    fn metrics_contract_is_method_aware() {
        assert_eq!(
            dispatch("POST", METRICS_PATH, None).expect("matched").0,
            405
        );
        let (status, content_type, _) = dispatch("GET", METRICS_PATH, None).expect("matched");
        assert!(status == 200 || status == 404, "status {status}");
        assert_eq!(content_type, "application/json");
    }

    #[test]
    fn artifacts_contract_is_method_aware() {
        assert_eq!(
            dispatch("POST", ARTIFACTS_PATH, None).expect("matched").0,
            405
        );
    }

    #[test]
    fn artifacts_contract_reports_the_single_node_equivalent_without_a_cluster() {
        // Without a configured cluster the local verified cache is the
        // whole fleet: one "local" node, zero snapshot age, not partial.
        let (status, content_type, body) = local_artifacts_response();
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let body: serde_json::Value = serde_json::from_str(&body).expect("artifacts JSON");
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["partial"], false);
        assert_eq!(body["nodes"].as_array().expect("nodes array").len(), 1);
        assert_eq!(body["nodes"][0]["node_id"], "local");
        assert_eq!(body["nodes"][0]["snapshot_age_ms"], 0);
        assert!(body["nodes"][0]["total_bytes"].is_u64());
        assert!(body["nodes"][0]["artifact_count"].is_u64());
        assert!(body["models"].is_array());
    }

    #[test]
    fn artifacts_contract_aggregates_node_snapshots_and_marks_missing_ones_partial() {
        use sbproxy_ai::model_directory::{
            DirectoryMember, DirectoryMemberState, DirectorySnapshotEnvelope,
            DirectorySnapshotRead, ModelDirectory,
        };
        use sbproxy_model_host::node_snapshot::{
            ModelPlaneHealth, NodeArtifactSnapshot, NodeArtifactState, NodeHealthSnapshot,
            NodeHealthState, NodeIdentitySnapshot, NodeModelSnapshot, NodeRole,
            NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
        };

        let snapshot = NodeModelSnapshot {
            schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
            node: NodeIdentitySnapshot {
                node_id: "worker-a".to_string(),
                roles: BTreeSet::from([NodeRole::Worker]),
                labels: BTreeMap::new(),
                model_endpoint: Some("https://worker-a.internal:9443".to_string()),
            },
            health: NodeHealthSnapshot {
                state: NodeHealthState::Unhealthy,
                reason_codes: vec!["engine_unhealthy".to_string()],
                model_plane: ModelPlaneHealth::Unavailable,
            },
            engines: Vec::new(),
            devices: Vec::new(),
            artifacts: vec![
                NodeArtifactSnapshot {
                    artifact_digest: "a".repeat(64),
                    model: "qwen2.5-0.5b-instruct".to_string(),
                    variant: "q4_k_m".to_string(),
                    state: NodeArtifactState::Ready,
                    completed_bytes: 1_000,
                    total_bytes: Some(1_000),
                    last_accessed_unix_ms: Some(900),
                    reason_code: None,
                },
                NodeArtifactSnapshot {
                    artifact_digest: "b".repeat(64),
                    model: "qwen3-8b".to_string(),
                    variant: "q8_0".to_string(),
                    state: NodeArtifactState::Partial,
                    completed_bytes: 250,
                    total_bytes: None,
                    last_accessed_unix_ms: None,
                    reason_code: None,
                },
                // Synthesized zero-byte rows carry no disk usage and
                // must not count as cached artifacts.
                NodeArtifactSnapshot {
                    artifact_digest: "c".repeat(64),
                    model: "qwen3-8b".to_string(),
                    variant: "q8_0".to_string(),
                    state: NodeArtifactState::Missing,
                    completed_bytes: 0,
                    total_bytes: None,
                    last_accessed_unix_ms: None,
                    reason_code: None,
                },
            ],
            replicas: Vec::new(),
            placement_weight: 0,
            active_deployment_digest: Some("d".repeat(64)),
            generation: 4,
            published_at_unix_ms: 1_000,
            expires_at_unix_ms: 31_000,
        };
        let directory = ModelDirectory::new();
        let view = directory
            .refresh(
                1_100,
                vec![
                    DirectoryMember {
                        node_id: "worker-a".to_string(),
                        address: Some("10.0.0.12:7946".to_string()),
                        state: DirectoryMemberState::Alive,
                        last_ack_age_ms: 25,
                        incarnation: 2,
                    },
                    DirectoryMember {
                        node_id: "worker-b".to_string(),
                        address: Some("10.0.0.13:7946".to_string()),
                        state: DirectoryMemberState::Alive,
                        last_ack_age_ms: 25,
                        incarnation: 1,
                    },
                ],
                BTreeMap::from([(
                    "worker-a".to_string(),
                    DirectorySnapshotRead::Present(DirectorySnapshotEnvelope {
                        publisher_node_id: "worker-a".to_string(),
                        schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
                        generation: 4,
                        published_at_unix_ms: 1_000,
                        expires_at_unix_ms: 31_000,
                        authenticated_identity: None,
                        payload: serde_json::to_value(snapshot).expect("snapshot JSON"),
                    }),
                )]),
            )
            .expect("directory view");

        let (status, _, body) = artifacts_response_from_directory(&view, 1_200);

        assert_eq!(status, 200);
        let body: serde_json::Value = serde_json::from_str(&body).expect("artifacts JSON");
        assert_eq!(body["schema_version"], 1);
        // worker-b has no accepted snapshot, so its cache truth is
        // unknown and the aggregate says so.
        assert_eq!(body["partial"], true);
        assert_eq!(body["nodes"].as_array().expect("nodes array").len(), 1);
        assert_eq!(body["nodes"][0]["node_id"], "worker-a");
        assert_eq!(body["nodes"][0]["total_bytes"], 1_250);
        assert_eq!(body["nodes"][0]["artifact_count"], 2);
        assert_eq!(body["nodes"][0]["snapshot_age_ms"], 200);
        let models = body["models"].as_array().expect("models array");
        assert_eq!(models.len(), 2);
        assert_eq!(models[0]["logical_model"], "qwen2.5-0.5b-instruct");
        assert_eq!(models[0]["total_bytes"], 1_000);
        assert_eq!(models[0]["node_count"], 1);
        assert_eq!(models[1]["logical_model"], "qwen3-8b");
        assert_eq!(models[1]["total_bytes"], 250);
        assert_eq!(models[1]["node_count"], 1);
    }

    #[test]
    fn status_contract_lists_every_node_and_explicit_unhealthy_callouts() {
        use sbproxy_ai::model_directory::{
            DirectoryMember, DirectoryMemberState, DirectorySnapshotEnvelope,
            DirectorySnapshotRead, ModelDirectory,
        };
        use sbproxy_model_host::node_snapshot::{
            ModelPlaneHealth, NodeHealthSnapshot, NodeHealthState, NodeIdentitySnapshot,
            NodeModelSnapshot, NodeRole, NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
        };

        let identity = ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "worker-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::from([("zone".to_string(), "a".to_string())]),
            peer_address: Some("10.0.0.12:7946".to_string()),
            model_endpoint: Some("https://worker-a.internal:9443".to_string()),
        };
        let handle = ClusterHandle::local(identity).expect("cluster handle");
        let snapshot = NodeModelSnapshot {
            schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
            node: NodeIdentitySnapshot {
                node_id: "worker-a".to_string(),
                roles: BTreeSet::from([NodeRole::Worker]),
                labels: BTreeMap::from([("zone".to_string(), "a".to_string())]),
                model_endpoint: Some("https://worker-a.internal:9443".to_string()),
            },
            health: NodeHealthSnapshot {
                state: NodeHealthState::Unhealthy,
                reason_codes: vec!["engine_unhealthy".to_string()],
                model_plane: ModelPlaneHealth::Unavailable,
            },
            engines: Vec::new(),
            devices: Vec::new(),
            artifacts: Vec::new(),
            replicas: Vec::new(),
            placement_weight: 0,
            active_deployment_digest: Some("a".repeat(64)),
            generation: 4,
            published_at_unix_ms: 1_000,
            expires_at_unix_ms: 31_000,
        };
        let directory = ModelDirectory::new();
        let view = directory
            .refresh(
                1_100,
                vec![DirectoryMember {
                    node_id: "worker-a".to_string(),
                    address: Some("10.0.0.12:7946".to_string()),
                    state: DirectoryMemberState::Alive,
                    last_ack_age_ms: 25,
                    incarnation: 2,
                }],
                BTreeMap::from([(
                    "worker-a".to_string(),
                    DirectorySnapshotRead::Present(DirectorySnapshotEnvelope {
                        publisher_node_id: "worker-a".to_string(),
                        schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
                        generation: 4,
                        published_at_unix_ms: 1_000,
                        expires_at_unix_ms: 31_000,
                        authenticated_identity: None,
                        payload: serde_json::to_value(snapshot).expect("snapshot JSON"),
                    }),
                )]),
            )
            .expect("directory view");
        let settings = crate::cluster::ClusterSettings {
            snapshot_ttl_secs: 30,
            publish_interval_secs: 5,
            distributed_requested: true,
            model_control_enabled: true,
        };

        let (status, _, body) =
            dispatch_status_with("GET", handle.clone(), settings, Some(view), 1_200);
        assert_eq!(status, 200);
        let body: serde_json::Value = serde_json::from_str(&body).expect("status JSON");
        assert_eq!(body["summary"]["total_nodes"], 1);
        assert_eq!(body["summary"]["unhealthy_nodes"], 1);
        assert_eq!(body["nodes"][0]["node_id"], "worker-a");
        assert_eq!(body["nodes"][0]["last_ack_age_ms"], 125);
        assert_eq!(
            body["nodes"][0]["model_endpoint"],
            "https://worker-a.internal:9443"
        );
        assert_eq!(body["unhealthy_nodes"][0]["node_id"], "worker-a");
        assert_eq!(body["unhealthy_nodes"][0]["reasons"][0], "engine_unhealthy");
        assert_eq!(
            dispatch_status_with("POST", handle, settings, None, 1_200).0,
            405
        );
    }

    #[test]
    fn status_contract_exposes_placement_and_unplaced_replica_state() {
        let global = sbproxy_model_host::compile_desired_state(
            sbproxy_model_host::RuntimeDesiredInput {
                source_revision: "admin-placement-1".to_string(),
                canonical: Some(
                    serde_yaml::from_str(
                        r#"
deployments:
  coder:
    model: qwen2.5-0.5b-instruct
    variant: q4_k_m
"#,
                    )
                    .expect("model-host config"),
                ),
                managed_providers: Vec::new(),
                legacy_providers: Vec::new(),
            },
            &sbproxy_model_host::Catalog::builtin(),
        )
        .expect("global desired");
        let placement = sbproxy_model_host::reconcile_cluster_placement(
            &sbproxy_model_host::Catalog::builtin(),
            None,
            global,
            Vec::new(),
            &BTreeMap::new(),
            &sbproxy_model_host::DeploymentGenerationFences::default(),
            1_000,
        )
        .expect("unplaced status remains valid");
        let identity = ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "gateway-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Gateway]),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        };
        let handle = ClusterHandle::local(identity).expect("cluster handle");
        let settings = crate::cluster::ClusterSettings {
            snapshot_ttl_secs: 30,
            publish_interval_secs: 5,
            distributed_requested: true,
            model_control_enabled: true,
        };

        let (status, _, body) = dispatch_status_with_placement(
            "GET",
            handle,
            settings,
            None,
            Some(&placement),
            None,
            1_200,
        );

        assert_eq!(status, 200);
        let body: serde_json::Value = serde_json::from_str(&body).expect("status JSON");
        assert_eq!(body["summary"]["deployments"], 1);
        assert_eq!(body["summary"]["unplaced_replicas"], 1);
        assert_eq!(body["deployments"][0]["deployment_id"], "coder");
        assert_eq!(body["deployments"][0]["phase"], "starting");
        assert_eq!(body["deployments"][0]["unplaced_replicas"], 1);
    }

    #[test]
    fn enrollment_is_public_but_bounded_and_authority_scoped() {
        assert!(is_public_enrollment_path(ENROLL_PATH));
        assert!(is_public_enrollment_path(&format!("{ENROLL_PATH}?trace=1")));
        assert!(!is_public_enrollment_path(METRICS_PATH));
        assert_eq!(dispatch("GET", ENROLL_PATH, None).expect("matched").0, 405);
        assert_eq!(dispatch("POST", ENROLL_PATH, None).expect("matched").0, 400);
        assert_eq!(
            dispatch("POST", ENROLL_PATH, Some("{}"))
                .expect("matched")
                .0,
            400
        );
    }

    #[test]
    fn deployment_writes_are_explicitly_read_only_without_authority_material() {
        let (status, _, body) = dispatch_deployments_with("POST", Some("{}"), None);
        assert_eq!(status, 403);
        let body: serde_json::Value = serde_json::from_str(&body).expect("error JSON");
        assert_eq!(body["code"], "deployment_authority_read_only");
        assert_eq!(dispatch_deployments_with("GET", None, None).0, 404);
        assert_eq!(dispatch_deployments_with("DELETE", None, None).0, 405);
        assert!(!is_public_enrollment_path(DEPLOYMENTS_PATH));
    }

    #[test]
    fn enrollment_adapter_issues_once_without_echoing_private_key() {
        let temp = tempfile::tempdir().expect("temp dir");
        let authority = Arc::new(
            EnrollmentAuthority::initialize(
                temp.path().join("authority"),
                AuthorityInit {
                    cluster_id: "dev-a".to_string(),
                    node_id: "authority-a".to_string(),
                    roles: BTreeSet::from([ClusterNodeRole::Authority]),
                    labels: BTreeMap::new(),
                    server_name: "sbproxy-mesh".to_string(),
                },
            )
            .expect("authority"),
        );
        let constraints = EnrollmentTokenConstraints {
            allowed_roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::from([("zone".to_string(), "b".to_string())]),
        };
        let token = authority
            .create_token(constraints.clone(), Duration::from_secs(60))
            .expect("token")
            .into_token();
        let worker = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").expect("worker");
        let request = worker.request(token, constraints.allowed_roles, constraints.labels);
        let body = serde_json::to_string(&request).expect("request JSON");

        let first = dispatch_enrollment_with("POST", Some(&body), Some(Arc::clone(&authority)));
        assert_eq!(first.0, 200, "{}", first.2);
        assert!(!first.2.contains("PRIVATE KEY"));
        let second = dispatch_enrollment_with("POST", Some(&body), Some(authority));
        assert_eq!(second.0, 401);
        assert!(second.2.contains("enrollment_denied"));
    }
}
