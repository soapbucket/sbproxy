// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cluster status, metrics, and one-time enrollment admin adapters.

use sbproxy_mesh::enrollment::{EnrollmentError, EnrollmentRequest};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Public one-time enrollment endpoint.
pub const ENROLL_PATH: &str = "/admin/cluster/enroll";
/// Authenticated cluster and node health endpoint.
pub const STATUS_PATH: &str = "/admin/cluster/status";
const METRICS_PATH: &str = "/admin/cluster/metrics";

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
    nodes: Vec<ClusterStatusNode>,
    unhealthy_nodes: Vec<ClusterNodeAlert>,
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
    let path = path.split('?').next().unwrap_or(path);
    match path {
        STATUS_PATH => Some(dispatch_status(method)),
        METRICS_PATH => Some(dispatch_metrics(method)),
        ENROLL_PATH => Some(dispatch_enrollment(method, body)),
        _ => None,
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
        });
    let view = crate::cluster::current_model_directory().map(|directory| directory.load());
    dispatch_status_with(method, handle, settings, view, unix_time_ms())
}

fn dispatch_status_with(
    method: &str,
    handle: sbproxy_mesh::ClusterHandle,
    settings: crate::cluster::ClusterSettings,
    view: Option<Arc<sbproxy_ai::model_directory::ModelDirectoryView>>,
    now: u64,
) -> (u16, &'static str, String) {
    if !method.eq_ignore_ascii_case("GET") {
        return json(405, serde_json::json!({"error": "method not allowed"}));
    }
    let response = cluster_status_response(&handle, settings, view.as_deref(), now);
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
        nodes,
        unhealthy_nodes,
    }
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
        return json(
            400,
            serde_json::json!({"error": "invalid enrollment request", "code": "invalid_request"}),
        );
    };
    let request: EnrollmentRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(_) => {
            return json(
                400,
                serde_json::json!({"error": "invalid enrollment request", "code": "invalid_request"}),
            )
        }
    };
    let Some(authority) = authority else {
        return json(
            503,
            serde_json::json!({"error": "this node is not an enrollment authority", "code": "authority_unavailable"}),
        );
    };
    match authority.enroll(request) {
        Ok(response) => match serde_json::to_string(&response) {
            Ok(body) => (200, "application/json", body),
            Err(error) => {
                tracing::error!(%error, "serialize cluster enrollment response");
                json(
                    500,
                    serde_json::json!({"error": "cluster enrollment failed", "code": "internal"}),
                )
            }
        },
        Err(error) => enrollment_error_response(error),
    }
}

fn enrollment_error_response(error: EnrollmentError) -> (u16, &'static str, String) {
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
    fn status_contract_lists_every_node_and_explicit_unhealthy_callouts() {
        use sbproxy_ai::model_directory::{
            DirectoryMember, DirectoryMemberState, DirectorySnapshotEnvelope,
            DirectorySnapshotRead, ModelDirectory,
        };
        use sbproxy_model_host::node_snapshot::{
            NodeHealthSnapshot, NodeHealthState, NodeIdentitySnapshot, NodeModelSnapshot, NodeRole,
            NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
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
                        payload: serde_json::to_value(snapshot).expect("snapshot JSON"),
                    }),
                )]),
            )
            .expect("directory view");
        let settings = crate::cluster::ClusterSettings {
            snapshot_ttl_secs: 30,
            publish_interval_secs: 5,
            distributed_requested: true,
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
