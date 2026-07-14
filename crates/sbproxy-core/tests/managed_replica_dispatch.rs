use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::{stream, StreamExt};
use sbproxy_ai::managed_replica::{
    ManagedReplicaCandidate, ManagedReplicaSelection, ManagedRouteClass, ReplicaSelectionTrace,
};
use sbproxy_core::model_discovery::{
    logical_model_listing, managed_error_body, safe_route_headers, ManagedDeploymentAvailability,
    PublicRouteClass,
};
use sbproxy_core::model_plane::{
    choose_cold_start_candidates, dispatch_managed_candidates, ManagedAttemptResponse,
    ManagedColdStartDecision, ManagedReplicaExecutor, ModelPlaneError, ModelPlaneRetryClass,
};
use sbproxy_model_host::node_snapshot::ModelPlaneHealth;
use sbproxy_model_host::ColdStartPolicy;
use sbproxy_model_host::DeploymentRuntimeState;

enum ScriptedResult {
    Response(u16),
    Error(ModelPlaneError),
    StreamError,
}

struct ScriptedExecutor {
    results: Mutex<VecDeque<ScriptedResult>>,
    attempted_nodes: Mutex<Vec<String>>,
}

impl ScriptedExecutor {
    fn new(results: impl IntoIterator<Item = ScriptedResult>) -> Self {
        Self {
            results: Mutex::new(results.into_iter().collect()),
            attempted_nodes: Mutex::new(Vec::new()),
        }
    }

    fn attempted_nodes(&self) -> Vec<String> {
        self.attempted_nodes.lock().expect("attempt lock").clone()
    }
}

#[async_trait]
impl ManagedReplicaExecutor for ScriptedExecutor {
    async fn execute(
        &self,
        candidate: &ManagedReplicaCandidate,
    ) -> Result<ManagedAttemptResponse, ModelPlaneError> {
        self.attempted_nodes
            .lock()
            .expect("attempt lock")
            .push(candidate.replica.node_id.clone());
        let result = self
            .results
            .lock()
            .expect("result lock")
            .pop_front()
            .expect("scripted result");
        match result {
            ScriptedResult::Response(status) => Ok(ManagedAttemptResponse::without_permit(
                http::Response::builder()
                    .status(status)
                    .body("ok")
                    .expect("response")
                    .into(),
            )),
            ScriptedResult::Error(error) => Err(error),
            ScriptedResult::StreamError => {
                let chunks = stream::iter(vec![
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"first")),
                    Err(std::io::Error::other("stream failed")),
                ]);
                let response = http::Response::builder()
                    .status(200)
                    .body(reqwest::Body::wrap_stream(chunks))
                    .expect("stream response")
                    .into();
                Ok(ManagedAttemptResponse::without_permit(response))
            }
        }
    }
}

fn candidate(node_id: &str, route_class: ManagedRouteClass) -> ManagedReplicaCandidate {
    candidate_with_state(node_id, route_class, DeploymentRuntimeState::Ready)
}

fn candidate_with_state(
    node_id: &str,
    route_class: ManagedRouteClass,
    state: DeploymentRuntimeState,
) -> ManagedReplicaCandidate {
    ManagedReplicaCandidate {
        replica: sbproxy_ai::model_directory::ModelDirectoryReplica {
            node_id: node_id.to_string(),
            deployment: "coder".to_string(),
            deployment_generation: 7,
            model: "logical/coder".to_string(),
            variant: None,
            endpoint: (route_class == ManagedRouteClass::Peer)
                .then(|| format!("https://{node_id}:9443")),
            state,
            active_requests: 0,
            queue_depth: 0,
            adapters: Vec::new(),
            node_labels: BTreeMap::new(),
            compute_utilization_millis: Some(100),
            memory_occupancy_millis: Some(200),
            model_plane_health: ModelPlaneHealth::Ready,
        },
        route_class,
    }
}

#[test]
fn cold_start_policy_waits_rejects_or_falls_back_without_execution() {
    let cold = || {
        selection(vec![candidate_with_state(
            "worker-a",
            ManagedRouteClass::Peer,
            DeploymentRuntimeState::Assigned,
        )])
    };
    let ready = || selection(Vec::new());

    assert!(matches!(
        choose_cold_start_candidates(ready(), cold(), ColdStartPolicy::Wait),
        ManagedColdStartDecision::Dispatch(_)
    ));
    assert!(matches!(
        choose_cold_start_candidates(ready(), cold(), ColdStartPolicy::Reject),
        ManagedColdStartDecision::Reject(_)
    ));
    assert!(matches!(
        choose_cold_start_candidates(ready(), cold(), ColdStartPolicy::Fallback),
        ManagedColdStartDecision::Fallback(_)
    ));
}

fn selection(candidates: Vec<ManagedReplicaCandidate>) -> ManagedReplicaSelection {
    ManagedReplicaSelection {
        trace: ReplicaSelectionTrace {
            total_candidates: candidates.len(),
            eligible_candidates: candidates.len(),
            selected_reason: Some("ready_low_queue"),
            ..ReplicaSelectionTrace::default()
        },
        candidates,
    }
}

#[tokio::test]
async fn retries_capacity_failure_on_the_next_current_replica() {
    let executor = Arc::new(ScriptedExecutor::new([
        ScriptedResult::Error(ModelPlaneError::Remote {
            code: "queue_full".to_string(),
            retryable: true,
        }),
        ScriptedResult::Response(200),
    ]));
    let outcome = dispatch_managed_candidates(
        selection(vec![
            candidate("worker-a", ManagedRouteClass::Local),
            candidate("worker-b", ManagedRouteClass::Peer),
        ]),
        executor.as_ref(),
    )
    .await
    .expect("peer succeeds");

    assert_eq!(outcome.selected_node_id, "worker-b");
    assert_eq!(outcome.route_class, ManagedRouteClass::Peer);
    assert_eq!(outcome.trace.failovers, 1);
    assert_eq!(outcome.trace.attempts.len(), 2);
    assert_eq!(executor.attempted_nodes(), ["worker-a", "worker-b"]);
}

#[tokio::test]
async fn security_failure_never_moves_to_another_replica() {
    let executor = Arc::new(ScriptedExecutor::new([
        ScriptedResult::Error(ModelPlaneError::Tls("wrong peer".to_string())),
        ScriptedResult::Response(200),
    ]));
    let failure = dispatch_managed_candidates(
        selection(vec![
            candidate("worker-a", ManagedRouteClass::Peer),
            candidate("worker-b", ManagedRouteClass::Peer),
        ]),
        executor.as_ref(),
    )
    .await
    .expect_err("security failure is terminal");

    assert_eq!(failure.source.retry_class(), ModelPlaneRetryClass::Security);
    assert_eq!(failure.trace.failovers, 0);
    assert_eq!(executor.attempted_nodes(), ["worker-a"]);
}

#[tokio::test]
async fn retryable_status_fails_over_before_output() {
    let executor = Arc::new(ScriptedExecutor::new([
        ScriptedResult::Response(503),
        ScriptedResult::Response(200),
    ]));
    let outcome = dispatch_managed_candidates(
        selection(vec![
            candidate("worker-a", ManagedRouteClass::Peer),
            candidate("worker-b", ManagedRouteClass::Peer),
        ]),
        executor.as_ref(),
    )
    .await
    .expect("second replica succeeds");

    assert_eq!(outcome.response.status(), 200);
    assert_eq!(outcome.trace.failovers, 1);
    assert_eq!(executor.attempted_nodes(), ["worker-a", "worker-b"]);
}

#[tokio::test]
async fn stream_failure_after_response_selection_is_never_replayed() {
    let executor = Arc::new(ScriptedExecutor::new([
        ScriptedResult::StreamError,
        ScriptedResult::Response(200),
    ]));
    let outcome = dispatch_managed_candidates(
        selection(vec![
            candidate("worker-a", ManagedRouteClass::Peer),
            candidate("worker-b", ManagedRouteClass::Peer),
        ]),
        executor.as_ref(),
    )
    .await
    .expect("headers select the first response");

    let mut stream = outcome.response.bytes_stream();
    assert_eq!(
        stream.next().await.expect("first chunk").expect("bytes"),
        bytes::Bytes::from_static(b"first")
    );
    assert!(stream.next().await.expect("stream error").is_err());
    assert_eq!(executor.attempted_nodes(), ["worker-a"]);
}

#[tokio::test]
async fn route_trace_is_bounded_and_contains_no_endpoint() {
    let candidates = (0..12)
        .map(|index| candidate(&format!("worker-{index}"), ManagedRouteClass::Peer))
        .collect::<Vec<_>>();
    let executor = Arc::new(ScriptedExecutor::new(
        (0..8).map(|_| ScriptedResult::Response(503)),
    ));
    let outcome = dispatch_managed_candidates(selection(candidates), executor.as_ref())
        .await
        .expect("last bounded response is returned");

    assert_eq!(outcome.trace.attempts.len(), 8);
    assert_eq!(outcome.trace.truncated_candidates, 4);
    let trace = format!("{:?}", outcome.trace);
    assert!(!trace.contains("https://"));
    assert!(!trace.contains(":9443"));
}

#[test]
fn managed_models_listing_contains_availability_but_no_topology() {
    let config = sbproxy_ai::handler::AiHandlerConfig::from_config(serde_json::json!({
        "providers": [
            {
                "name": "managed",
                "provider_type": "managed_model",
                "deployment": "coder",
                "models": ["qwen"]
            },
            {
                "name": "openai",
                "api_key": "test",
                "models": ["qwen", "cloud-only"]
            }
        ],
        "allowed_models": ["qwen"]
    }))
    .expect("AI config");
    let availability = BTreeMap::from([(
        "coder".to_string(),
        ManagedDeploymentAvailability {
            ready_replicas: 0,
            cold_replicas: 1,
            desired_replicas: 2,
        },
    )]);

    let response =
        logical_model_listing(&config, &["managed".to_string()], &[], &[], &availability);

    assert_eq!(response["object"], "list");
    assert_eq!(response["data"][0]["id"], "qwen");
    assert_eq!(response["data"][0]["availability"]["state"], "cold");
    assert_eq!(response["data"][0]["availability"]["ready_replicas"], 0);
    assert_eq!(response["data"][0]["availability"]["desired_replicas"], 2);
    assert!(response["data"][0]["capabilities"].is_array());
    let encoded = response.to_string();
    assert!(!encoded.contains("worker-a"));
    assert!(!encoded.contains("model_endpoint"));
    assert!(!encoded.contains(":9443"));
    assert!(!encoded.contains("cloud-only"));
}

#[test]
fn route_headers_and_managed_errors_are_stable_and_allowlisted() {
    let headers = safe_route_headers("qwen", PublicRouteClass::Peer);
    assert_eq!(
        headers,
        [
            ("x-sbproxy-logical-model".to_string(), "qwen".to_string()),
            ("x-sbproxy-route-class".to_string(), "peer".to_string()),
        ]
    );
    assert!(headers.iter().all(|(name, _)| name != "x-sbproxy-worker"));

    let body = managed_error_body("req_123", "no_ready_replica", true);
    let error: serde_json::Value = serde_json::from_slice(&body).expect("managed error JSON");
    assert_eq!(error["error"]["type"], "managed_model_error");
    assert_eq!(error["error"]["code"], "no_ready_replica");
    assert_eq!(error["error"]["request_id"], "req_123");
    assert_eq!(error["error"]["retryable"], true);
    assert_eq!(error["error"]["sbproxy_reason"], "no_ready_replica");
}
