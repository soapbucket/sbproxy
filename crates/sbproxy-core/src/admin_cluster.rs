// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cluster metrics and one-time enrollment admin adapters.

use sbproxy_mesh::enrollment::{EnrollmentError, EnrollmentRequest};
use std::sync::Arc;

/// Public one-time enrollment endpoint.
pub const ENROLL_PATH: &str = "/admin/cluster/enroll";
const METRICS_PATH: &str = "/admin/cluster/metrics";

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
        METRICS_PATH => Some(dispatch_metrics(method)),
        ENROLL_PATH => Some(dispatch_enrollment(method, body)),
        _ => None,
    }
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
    use sbproxy_mesh::ClusterNodeRole;

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
