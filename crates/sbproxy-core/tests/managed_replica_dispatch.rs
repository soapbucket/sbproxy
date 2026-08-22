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

// --- Model capability metadata on the listing (WOR-2647) ---

/// Read one listed entry by id.
fn listed_entry<'a>(response: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    response["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap_or_else(|| panic!("{id} is listed: {response}"))
}

/// The OpenAI `Model` object declares `created` required, so an
/// SDK-shaped client refuses a list without it. Red on main, where
/// nothing emits the field.
#[test]
fn every_listed_model_carries_the_fields_an_openai_sdk_requires() {
    let config = single_provider_config("openai");
    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());
    let entry = listed_entry(&listing, "m");
    for field in ["id", "object", "created", "owned_by"] {
        assert!(
            entry.get(field).is_some(),
            "the OpenAI Model object requires {field}: {entry}"
        );
    }
    assert!(entry["created"].is_u64(), "created must be an integer");
    assert_eq!(entry["object"], "model");
}

/// A model the process knows a window for publishes it; one it knows
/// nothing about omits the field rather than guessing a default, which
/// is the same rule the routing base data applies. Red on main: the
/// listing carried no token limits at all.
#[test]
fn the_listing_publishes_a_known_context_window_and_omits_an_unknown_one() {
    let config: sbproxy_ai::handler::AiHandlerConfig = serde_json::from_value(serde_json::json!({
        "providers": [{
            "name": "entry",
            "provider_type": "openai",
            "api_key": "test",
            "models": ["gpt-4o-mini", "listing-unknown-model"]
        }]
    }))
    .expect("provider fixture");
    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());

    assert_eq!(
        listed_entry(&listing, "gpt-4o-mini")["context_window"],
        serde_json::json!(128_000),
        "the static window table is the source, and it knows this model"
    );
    let unknown = listed_entry(&listing, "listing-unknown-model");
    assert!(
        unknown.get("context_window").is_none(),
        "an unknown window is absent, not null and not a guessed default: {unknown}"
    );
    assert!(
        unknown.get("max_output_tokens").is_none(),
        "nothing in this process holds a completion cap without a rate card: {unknown}"
    );
}

/// A `model_aliases:` entry is a name a caller may send as `model`, so a
/// client reading the listing has to see it. Red on main: aliases were
/// invisible, and only the upstream ids appeared.
#[test]
fn an_alias_is_listed_under_its_own_name_with_its_targets_facts() {
    let config: sbproxy_ai::handler::AiHandlerConfig = serde_json::from_value(serde_json::json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "test",
            "models": ["gpt-4o-mini"]
        }],
        "model_aliases": [{"alias": "fast", "provider": "openai", "model_id": "gpt-4o-mini"}]
    }))
    .expect("alias fixture");
    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());

    let fast = listed_entry(&listing, "fast");
    assert_eq!(fast["context_window"], serde_json::json!(128_000));
    assert_eq!(fast["availability"]["state"], "ready");
    assert!(fast["capabilities"]
        .as_array()
        .expect("capabilities")
        .contains(&serde_json::json!("chat_completions")));
    // The upstream id is still listed on its own.
    assert_eq!(listed_entry(&listing, "gpt-4o-mini")["id"], "gpt-4o-mini");
}

/// An alias is gated on the id it resolves to, which is exactly what the
/// dispatch path gates: the alias resolves before every model gate, so a
/// `blocked_models` entry naming the upstream id blocks the alias too.
/// Listing it would advertise a name that answers 403.
#[test]
fn an_alias_whose_target_is_blocked_is_not_listed() {
    let config: sbproxy_ai::handler::AiHandlerConfig = serde_json::from_value(serde_json::json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "test",
            "models": ["gpt-4o-mini", "gpt-4o"]
        }],
        "blocked_models": ["gpt-4o-mini"],
        "model_aliases": [
            {"alias": "fast", "provider": "openai", "model_id": "gpt-4o-mini"},
            {"alias": "smart", "provider": "openai", "model_id": "gpt-4o"}
        ]
    }))
    .expect("alias fixture");
    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());
    let ids: Vec<&str> = listing["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|entry| entry["id"].as_str().expect("id"))
        .collect();

    assert!(
        !ids.contains(&"fast"),
        "an alias must not be a way around blocked_models: {ids:?}"
    );
    assert!(ids.contains(&"smart"));
    assert!(!ids.contains(&"gpt-4o-mini"));
}

/// A named model group is a third kind of callable `model` name. Its
/// entry reports the union of its members' capabilities and the floor of
/// their windows, because a caller's prompt has to fit whichever member
/// serves it. Red on main: groups do not exist in the listing.
#[test]
fn a_model_group_is_listed_with_the_union_of_capabilities_and_the_floor_window() {
    let config: sbproxy_ai::handler::AiHandlerConfig = serde_json::from_value(serde_json::json!({
        "providers": [
            {"name": "big", "provider_type": "openai", "api_key": "t", "models": ["gpt-4o-mini"]},
            {"name": "small", "provider_type": "openai", "api_key": "t", "models": ["gpt-4"]}
        ],
        "model_groups": [{
            "name": "pool",
            "members": [
                {"provider": "big", "model": "gpt-4o-mini"},
                {"provider": "small", "model": "gpt-4"}
            ]
        }]
    }))
    .expect("group fixture");
    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());

    let pool = listed_entry(&listing, "pool");
    // gpt-4o-mini is 128k and gpt-4 is 8_192. Publishing the larger
    // would let a caller build a prompt the smaller member rejects.
    assert_eq!(
        pool["context_window"],
        serde_json::json!(8_192),
        "a group reports the floor across its members, not the maximum"
    );
    assert_eq!(pool["availability"]["ready_replicas"], 2);
    assert!(pool["capabilities"]
        .as_array()
        .expect("capabilities")
        .contains(&serde_json::json!("chat_completions")));
}

/// A group member whose model the block list refuses contributes
/// nothing, and a group with no surviving member is left off entirely.
#[test]
fn a_group_with_every_member_blocked_is_not_listed() {
    let config: sbproxy_ai::handler::AiHandlerConfig = serde_json::from_value(serde_json::json!({
        "providers": [
            {"name": "big", "provider_type": "openai", "api_key": "t", "models": ["gpt-4o-mini"]}
        ],
        "blocked_models": ["gpt-4o-mini"],
        "model_groups": [{
            "name": "pool",
            "members": [{"provider": "big", "model": "gpt-4o-mini"}]
        }]
    }))
    .expect("group fixture");
    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());
    assert!(
        listing["data"]
            .as_array()
            .expect("data")
            .iter()
            .all(|entry| entry["id"] != "pool"),
        "a group whose every member is refused must not be advertised: {listing}"
    );
}

/// `max_output_tokens` has exactly one source in this process: the
/// operator's LiteLLM rate card. The parser used to read the two cost
/// keys and discard the two limit keys, so the field could never be
/// emitted no matter what the listing asked for. This drives the whole
/// operator path, `rate_card:` file -> price table -> `model_facts` ->
/// the wire.
///
/// The card names one model nothing else in this binary looks up, so
/// installing the process-global price table here cannot change another
/// test's answer: every other model still resolves its window from the
/// static table exactly as before.
#[test]
fn a_rate_card_puts_max_output_tokens_on_the_wire() {
    // Named per process: two lanes building this workspace at once run
    // this file concurrently, and a fixed name has one run deleting the
    // card the other is about to read.
    let card = std::env::temp_dir().join(format!(
        "sbproxy-listing-rate-card-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &card,
        r#"{
            "ratecard-only-model": {
                "input_cost_per_token": 0.000001,
                "output_cost_per_token": 0.000002,
                "max_input_tokens": 64000,
                "max_output_tokens": 4096
            }
        }"#,
    )
    .expect("the rate card fixture is written");

    // `from_config` installs the process-global price table, which is
    // the seam an operator reaches through `rate_card:`.
    let config = sbproxy_ai::handler::AiHandlerConfig::from_config(serde_json::json!({
        "providers": [{
            "name": "entry",
            "provider_type": "openai",
            "api_key": "test",
            "models": ["ratecard-only-model"]
        }],
        "rate_card": card.to_string_lossy(),
    }))
    .expect("provider fixture");
    let listing = logical_model_listing(&config, &[], &[], &[], &BTreeMap::new());

    let entry = listed_entry(&listing, "ratecard-only-model");
    assert_eq!(entry["max_output_tokens"], serde_json::json!(4_096));
    assert_eq!(
        entry["context_window"],
        serde_json::json!(64_000),
        "the static table does not know this model, so the card's max_input_tokens answers"
    );
    let _ = std::fs::remove_file(&card);
}

/// A credential's `allowed_models` names upstream ids, and the dispatch
/// path judges it on the id an alias or group resolves to. The listing
/// has to gate the same way. Filtering on the alias or group name
/// instead would hide names the caller can in fact use, which is a
/// listing narrower than the gate rather than wider.
#[test]
fn a_credential_allowlist_of_upstream_ids_still_lists_the_alias_and_the_group() {
    let config: sbproxy_ai::handler::AiHandlerConfig = serde_json::from_value(serde_json::json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "test",
            "models": ["gpt-4o-mini"]
        }],
        "model_aliases": [{"alias": "fast", "provider": "openai", "model_id": "gpt-4o-mini"}],
        "model_groups": [{
            "name": "pool",
            "members": [{"provider": "openai", "model": "gpt-4o-mini"}]
        }]
    }))
    .expect("alias + group fixture");

    // The credential may use `gpt-4o-mini` and nothing else. It has never
    // heard of `fast` or `pool`, and does not need to: both resolve to
    // the id it allows before any credential gate runs.
    let allowed = vec!["gpt-4o-mini".to_string()];
    let listing = logical_model_listing(&config, &[], &allowed, &[], &BTreeMap::new());
    let ids: Vec<&str> = listing["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|entry| entry["id"].as_str().expect("id"))
        .collect();

    assert!(ids.contains(&"fast"), "{ids:?}");
    assert!(ids.contains(&"pool"), "{ids:?}");
    assert!(ids.contains(&"gpt-4o-mini"), "{ids:?}");

    // The other direction still holds: blocking the resolved id removes
    // every name that fronts it.
    let blocked = vec!["gpt-4o-mini".to_string()];
    let blocked_listing = logical_model_listing(&config, &[], &[], &blocked, &BTreeMap::new());
    assert_eq!(
        blocked_listing["data"].as_array().expect("data").len(),
        0,
        "blocking the upstream id must remove the alias and the group with it: {blocked_listing}"
    );
}
