use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
async fn every_dispatch_outcome_carries_governed_route_attribution() {
    let success = dispatch_managed_candidates(
        selection(vec![candidate("worker-a", ManagedRouteClass::Local)]),
        &ScriptedExecutor::new([ScriptedResult::Response(200)]),
        "tenant-a",
        "key-public-id",
        "r7:0123456789abcdef",
    )
    .await
    .expect("managed dispatch succeeds");

    assert_eq!(success.trace.tenant_id, "tenant-a");
    assert_eq!(success.trace.governed_key_id, "key-public-id");
    assert_eq!(success.trace.policy_revision, "r7:0123456789abcdef");

    let failure = dispatch_managed_candidates(
        selection(vec![candidate("worker-b", ManagedRouteClass::Peer)]),
        &ScriptedExecutor::new([ScriptedResult::Error(ModelPlaneError::Tls(
            "wrong peer".to_string(),
        ))]),
        "tenant-a",
        "key-public-id",
        "r7:0123456789abcdef",
    )
    .await
    .expect_err("managed dispatch fails");

    assert_eq!(failure.trace.tenant_id, "tenant-a");
    assert_eq!(failure.trace.governed_key_id, "key-public-id");
    assert_eq!(failure.trace.policy_revision, "r7:0123456789abcdef");
    let trace = format!("{:?}", failure.trace);
    assert!(!trace.contains("secret"));
    assert!(!trace.contains("tags"));
    assert!(!trace.contains("metadata"));
}

#[tokio::test]
async fn managed_route_attribution_is_bounded_and_control_free() {
    let tenant_id = format!("tenant\n{}", "x".repeat(256));
    let governed_key_id = format!("key id {}", "y".repeat(256));
    let policy_revision = format!("revision\n{}", "z".repeat(512));
    let outcome = dispatch_managed_candidates(
        selection(vec![candidate("worker-a", ManagedRouteClass::Local)]),
        &ScriptedExecutor::new([ScriptedResult::Response(200)]),
        &tenant_id,
        &governed_key_id,
        &policy_revision,
    )
    .await
    .expect("managed dispatch succeeds");

    assert!(outcome.trace.tenant_id.len() <= 128);
    assert!(outcome.trace.governed_key_id.len() <= 128);
    assert!(outcome.trace.policy_revision.len() <= 256);
    for value in [
        &outcome.trace.tenant_id,
        &outcome.trace.governed_key_id,
        &outcome.trace.policy_revision,
    ] {
        assert!(!value.is_empty());
        assert!(value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control()));
    }
    assert_ne!(outcome.trace.tenant_id, tenant_id);
    assert_ne!(outcome.trace.governed_key_id, governed_key_id);
    assert_ne!(outcome.trace.policy_revision, policy_revision);
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
        "tenant-a",
        "key-public-id",
        "r7:0123456789abcdef",
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
        "tenant-a",
        "key-public-id",
        "r7:0123456789abcdef",
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
        "tenant-a",
        "key-public-id",
        "r7:0123456789abcdef",
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
        "tenant-a",
        "key-public-id",
        "r7:0123456789abcdef",
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
    let outcome = dispatch_managed_candidates(
        selection(candidates),
        executor.as_ref(),
        "tenant-a",
        "key-public-id",
        "r7:0123456789abcdef",
    )
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

/// Read the first listed model's capability array as a set of names.
fn listed_capabilities(response: &serde_json::Value) -> BTreeSet<String> {
    response["data"][0]["capabilities"]
        .as_array()
        .expect("capabilities array")
        .iter()
        .map(|name| name.as_str().expect("capability name").to_string())
        .collect()
}

/// One provider entry serving one model, keyed on `provider_type`.
fn single_provider_config(provider_type: &str) -> sbproxy_ai::handler::AiHandlerConfig {
    serde_json::from_value(serde_json::json!({
        "providers": [
            {
                "name": "entry",
                "provider_type": provider_type,
                "api_key": "test",
                "models": ["m"]
            }
        ]
    }))
    .expect("AI config")
}

/// WOR-2647: the listing never advertises a surface the enforcer
/// refuses, for any entry in the shipped catalog.
///
/// `GET /v1/models` publishes a per-model `capabilities` array, and the
/// request path answers a surface it does not handle with 501. The two
/// used to read different tables: the array came from the provider
/// catalog's `supports_chat` / `supports_embeddings` booleans in
/// `crates/sbproxy-ai/data/ai_providers.yml`, and the refusal came from
/// `provider_supports_surface`. They disagreed on 43 of the 72 shipped
/// catalog entries, in both directions. `bedrock` declares
/// `supports_embeddings: true`, so a bedrock-only origin advertised
/// `embeddings` on its own listing and then answered `POST
/// /v1/embeddings` with 501.
///
/// This is one-directional on purpose. `provider_supports_surface` keys
/// on the wire format, so it says yes to every surface for the 66
/// entries with `format: openai`; asserting equality here would demand
/// that a DeepSeek listing advertise `audio_speech`. The listing is the
/// narrower of the two, and
/// `an_openai_format_deployment_does_not_advertise_the_whole_format`
/// below pins that it really is narrower rather than trivially equal.
///
/// The sweep covers the whole catalog rather than the two entries that
/// were noticed, because a per-entry assertion is narrower than the
/// enforcer it is meant to track.
#[test]
fn model_listing_never_advertises_a_surface_the_enforcer_refuses() {
    use sbproxy_ai::api_routes::provider_supports_surface;
    use sbproxy_ai::handler::AiSurface;

    let mut checked = 0usize;
    for provider_type in sbproxy_ai::providers::list_providers() {
        let config = single_provider_config(&provider_type);
        let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());
        let advertised = listed_capabilities(&listing);
        assert!(
            !advertised.is_empty(),
            "{provider_type}: every catalog entry serves something"
        );

        for surface in &AiSurface::ALL {
            if !advertised.contains(surface.label()) {
                continue;
            }
            assert!(
                provider_supports_surface(&provider_type, surface),
                "{provider_type}: the listing advertises {} and the \
                 request path answers 501",
                surface.label()
            );
            checked += 1;
        }
    }
    assert!(checked >= 200, "the catalog sweep ran: {checked} checks");
}

/// The finding-3 regression, through the real listing rather than the
/// helper: an openai-format vendor does not inherit OpenAI's surface
/// set.
///
/// Deriving the array from the format-wide matrix alone gave 64 of the
/// 72 catalog entries the same thirteen names, so a DeepSeek origin's
/// own `/v1/models` offered `audio_speech` and `image_generation`. The
/// gateway forwards both (the second half of the assertion), so the
/// caller was not refused here; the request reached
/// `api.deepseek.com/v1/audio/speech` and 404'd, on a path this listing
/// named.
#[test]
fn an_openai_format_deployment_does_not_advertise_the_whole_format() {
    use sbproxy_ai::api_routes::provider_supports_surface;
    use sbproxy_ai::handler::AiSurface;

    let listing = logical_model_listing(
        &single_provider_config("deepseek"),
        &[],
        &[],
        &[],
        &BTreeMap::new(),
    );
    let advertised = listed_capabilities(&listing);
    assert_eq!(
        advertised,
        ["chat_completions", "messages", "responses", "streaming"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
    );

    // The 501 gate stays wide. Narrowing it would refuse an
    // openai-format aggregator that does serve the surface, so the fix
    // is to stop advertising, not to stop forwarding.
    assert!(provider_supports_surface(
        "deepseek",
        &AiSurface::AudioSpeech
    ));
}

/// WOR-2647: a model group reports the union across its deployments,
/// not the last one the loop happened to visit.
///
/// The two operands are chosen to be disjoint, so the union is neither
/// of them and an intersection would be empty: `voyage` is an
/// embeddings-only vendor (`supports_chat: false`) and `anthropic`
/// serves the chat surfaces and no embeddings. Replacing the `extend`
/// in `logical_model_listing` with an assignment fails here.
/// `model_group_info_unions_capabilities_across_deployments` in
/// `crates/sbproxy-core/src/server/ai_dispatch.rs` covers the second
/// union site, the one behind `/model_group/info`.
#[test]
fn managed_model_group_capabilities_are_the_union() {
    let config: sbproxy_ai::handler::AiHandlerConfig = serde_json::from_value(serde_json::json!({
        "providers": [
            {
                "name": "embedder",
                "provider_type": "voyage",
                "api_key": "test",
                "models": ["shared"]
            },
            {
                "name": "chat",
                "provider_type": "anthropic",
                "api_key": "test",
                "models": ["shared"]
            }
        ]
    }))
    .expect("AI config");

    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());
    assert_eq!(
        listing["data"].as_array().map(|data| data.len()),
        Some(1),
        "both entries declare the same public name"
    );
    let advertised = listed_capabilities(&listing);

    let voyage_only = listed_capabilities(&logical_model_listing(
        &single_provider_config("voyage"),
        &[],
        &[],
        &[],
        &BTreeMap::new(),
    ));
    let anthropic_only = listed_capabilities(&logical_model_listing(
        &single_provider_config("anthropic"),
        &[],
        &[],
        &[],
        &BTreeMap::new(),
    ));
    assert!(
        voyage_only.is_disjoint(&anthropic_only),
        "the two operands have to differ for this test to mean anything: \
         {voyage_only:?} vs {anthropic_only:?}"
    );

    let union: BTreeSet<String> = voyage_only.union(&anthropic_only).cloned().collect();
    assert_eq!(
        advertised, union,
        "the group is the union, not either deployment"
    );
    assert!(advertised.len() > voyage_only.len());
    assert!(advertised.len() > anthropic_only.len());
}

/// The bedrock case named in the ticket, pinned on its own so a
/// regression names the provider rather than a sweep index.
#[test]
fn bedrock_listing_does_not_advertise_the_embeddings_it_refuses() {
    use sbproxy_ai::api_routes::provider_supports_surface;
    use sbproxy_ai::handler::AiSurface;

    assert!(
        !provider_supports_surface("bedrock", &AiSurface::Embeddings),
        "the enforcer answers 501 for bedrock embeddings"
    );
    let listing = logical_model_listing(
        &single_provider_config("bedrock"),
        &[],
        &[],
        &[],
        &BTreeMap::new(),
    );
    let advertised = listed_capabilities(&listing);
    assert!(
        !advertised.contains("embeddings"),
        "bedrock advertised embeddings it will 501: {advertised:?}"
    );
    assert!(advertised.contains("chat_completions"));
}

/// The other direction: vertex serves embeddings and must say so.
#[test]
fn vertex_listing_advertises_the_embeddings_it_serves() {
    use sbproxy_ai::api_routes::provider_supports_surface;
    use sbproxy_ai::handler::AiSurface;

    assert!(provider_supports_surface("vertex", &AiSurface::Embeddings));
    let listing = logical_model_listing(
        &single_provider_config("vertex"),
        &[],
        &[],
        &[],
        &BTreeMap::new(),
    );
    assert!(listed_capabilities(&listing).contains("embeddings"));
}
