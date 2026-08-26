use super::*;
use crate::evaluation::DatasetEntry;
use crate::prompt_versioning::WeightedPromptVersion;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use sbproxy_security::egress::{EgressAuthorizer, EgressConfig, EgressPurpose, PurposeAllowlist};

fn scope() -> ToolkitScope {
    ToolkitScope::new("origin-a", "tenant-a").expect("valid scope")
}

fn runtime_with_dataset() -> std::sync::Arc<AiToolkitRuntime> {
    let mut input = AiToolkitConfigInput::default();
    input.allowed_scopes.push(scope());
    input.datasets.push(ToolkitDatasetInput {
        scope: scope(),
        dataset: crate::evaluation::Dataset::new(
            "answers",
            1,
            vec![
                DatasetEntry::with_expected("one", "1"),
                DatasetEntry::with_expected("two", "2"),
            ],
        )
        .expect("valid dataset"),
    });
    AiToolkitRuntime::try_new(input).expect("runtime")
}

struct TestReply {
    delay: Duration,
    body: Vec<u8>,
}

async fn loopback_server(
    replies: Vec<TestReply>,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("local address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let auth_ok = Arc::new(AtomicBool::new(true));
    let accepted_for_task = Arc::clone(&accepted);
    let auth_for_task = Arc::clone(&auth_ok);
    let task = tokio::spawn(async move {
        let mut replies: VecDeque<TestReply> = replies.into();
        while let Some(reply) = replies.pop_front() {
            let (stream, _) = listener.accept().await.expect("accept loopback");
            accepted_for_task.fetch_add(1, Ordering::SeqCst);
            let auth = Arc::clone(&auth_for_task);
            tokio::spawn(async move {
                serve_agent(stream, reply, auth).await;
            });
        }
    });
    (address, accepted, auth_ok, task)
}

async fn serve_agent(
    mut stream: tokio::net::TcpStream,
    reply: TestReply,
    auth_ok: Arc<AtomicBool>,
) {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    let mut expected_bytes = None;
    loop {
        let read = match stream.read(&mut buffer).await {
            Ok(read) => read,
            Err(_) => return,
        };
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 64 * 1024 {
            auth_ok.store(false, Ordering::SeqCst);
            return;
        }
        if expected_bytes.is_none() {
            if let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let header_end = header_end + 4;
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let expected_token =
                    crate::agent_orchestration::generate_agent_token("agent-a", "shared-secret");
                let expected_authorization = format!("Bearer {expected_token}");
                let authorization = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim())
                });
                let agent_id = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("x-sbproxy-agent-id")
                        .then(|| value.trim())
                });
                if authorization != Some(expected_authorization.as_str())
                    || agent_id != Some("agent-a")
                {
                    auth_ok.store(false, Ordering::SeqCst);
                }
                expected_bytes = Some(header_end.saturating_add(content_length));
            }
        }
        if expected_bytes.is_some_and(|expected| request.len() >= expected) {
            break;
        }
    }
    tokio::time::sleep(reply.delay).await;
    let headers = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reply.body.len()
    );
    let _ = stream.write_all(headers.as_bytes()).await;
    let _ = stream.write_all(&reply.body).await;
    let _ = stream.shutdown().await;
}

fn workflow_runtime(
    address: SocketAddr,
    allow_destination: bool,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    response_cap: usize,
    timeout_ms: u64,
    concurrency: usize,
) -> Arc<AiToolkitRuntime> {
    workflow_runtime_with_transitions(
        address,
        allow_destination,
        input_schema,
        output_schema,
        response_cap,
        timeout_ms,
        concurrency,
        HashMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn workflow_runtime_with_transitions(
    address: SocketAddr,
    allow_destination: bool,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    response_cap: usize,
    timeout_ms: u64,
    concurrency: usize,
    transitions: HashMap<String, String>,
) -> Arc<AiToolkitRuntime> {
    let mut allowlist = PurposeAllowlist::default();
    allowlist.schemes.insert("http".into());
    allowlist.ports.insert(address.port());
    allowlist.allow_private = true;
    allowlist.hosts.insert(if allow_destination {
        "127.0.0.1".into()
    } else {
        "not-the-agent.invalid".into()
    });
    let mut purposes = HashMap::new();
    purposes.insert(EgressPurpose::AgentOrchestration, allowlist);

    let mut input = AiToolkitConfigInput::default();
    input.limits.max_response_bytes = response_cap;
    input.limits.agent_concurrency = concurrency;
    input.agent_egress = Some(AgentEgressInput {
        authorizer: EgressAuthorizer::new(EgressConfig { purposes }),
        purpose: EgressPurpose::AgentOrchestration,
    });
    input.agents.push(ToolkitAgentInput {
        scope: scope(),
        id: "agent-a".into(),
        endpoint: format!("http://{address}/invoke"),
        shared_secret: sbproxy_vault::SecretString::new("shared-secret"),
        capabilities: vec![ToolkitCapabilityInput {
            name: "answer".into(),
            description: "bounded test capability".into(),
            input_schema,
            output_schema,
        }],
    });
    input.workflows.push(ToolkitWorkflowInput {
        scope: scope(),
        name: "flow".into(),
        initial_state: "invoke".into(),
        states: vec![crate::agent_orchestration::FsmState {
            name: "invoke".into(),
            action: "answer".into(),
            transitions,
        }],
        max_steps: 1,
        timeout_ms,
    });
    AiToolkitRuntime::try_new(input).expect("workflow runtime")
}

fn workflow_request(input: serde_json::Value) -> WorkflowRunRequest {
    WorkflowRunRequest {
        scope: scope(),
        workflow: "flow".into(),
        input,
    }
}

#[test]
fn validation_rejects_invalid_capability_schema_before_publication() {
    let mut input = AiToolkitConfigInput::default();
    input.agents.push(ToolkitAgentInput {
        scope: scope(),
        id: "agent-a".into(),
        endpoint: "https://agent.invalid/invoke".into(),
        shared_secret: sbproxy_vault::SecretString::new("do-not-print"),
        capabilities: vec![ToolkitCapabilityInput {
            name: "answer".into(),
            description: "answer a question".into(),
            input_schema: json!({"type": 3}),
            output_schema: json!({"type": "object"}),
        }],
    });

    let error = AiToolkitRuntime::validate(&input).expect_err("invalid schema");
    assert!(matches!(error, ToolkitError::InvalidSchema { .. }));
    assert!(!error.to_string().contains("do-not-print"));
}

#[test]
fn evaluation_uses_the_requested_dataset_version_and_all_metric_families() {
    let runtime = runtime_with_dataset();
    let result = runtime
        .run_evaluation(EvaluationRunRequest {
            scope: scope(),
            experiment_id: "run-1".into(),
            experiment_name: "exact-version".into(),
            dataset: DatasetRef {
                name: "answers".into(),
                version: 1,
            },
            model: "offline-model".into(),
            prompt_version: Some("prompt-v1".into()),
            parameters: json!({"private_parameter": "must-not-be-retained"}),
            responses: vec!["1".into(), r#"{"answer":"2"}"#.into()],
            judge: Some(OfflineJudgeInput {
                judge_model: "recorded-judge".into(),
                criteria: vec!["accuracy".into(), "clarity".into()],
                responses: vec![
                    r#"{"scores":{"accuracy":10,"clarity":8},"reasoning":"secret rationale"}"#
                        .into(),
                    r#"{"scores":{"accuracy":6,"clarity":8},"reasoning":"secret rationale"}"#
                        .into(),
                ],
            }),
            metrics: vec![
                MetricSpec::Regex {
                    pattern: ".+".into(),
                },
                MetricSpec::JsonSchema { schema: json!({}) },
                MetricSpec::LengthRange { min: 1, max: 64 },
                MetricSpec::ContainsKeywords { keywords: vec![] },
            ],
        })
        .expect("offline evaluation");

    assert_eq!(result.dataset.version, 1);
    assert_eq!(result.cases, 2);
    assert_eq!(result.judge_score, Some(8.0));
    assert_eq!(result.criteria_scores["accuracy"], 8.0);
    let snapshot = runtime
        .snapshot(ToolkitSnapshotRequest {
            scope: scope(),
            limit: Some(16),
        })
        .expect("snapshot");
    let snapshot = serde_json::to_string(&snapshot).expect("snapshot JSON");
    assert!(!snapshot.contains("must-not-be-retained"));
    assert!(!snapshot.contains("secret rationale"));
}

#[test]
fn missing_dataset_version_fails_instead_of_falling_back_to_latest() {
    let runtime = runtime_with_dataset();
    let error = runtime
        .run_evaluation(EvaluationRunRequest {
            scope: scope(),
            experiment_id: "run-missing".into(),
            experiment_name: "exact-version".into(),
            dataset: DatasetRef {
                name: "answers".into(),
                version: 2,
            },
            model: "offline-model".into(),
            prompt_version: None,
            parameters: json!({}),
            responses: vec![],
            judge: None,
            metrics: vec![],
        })
        .expect_err("no fallback");
    assert!(matches!(
        error,
        ToolkitError::NotFound {
            resource: "dataset"
        }
    ));
}

#[test]
fn weighted_selection_is_stable_and_snapshot_redacts_content_and_cohort() {
    let secret_content = "private-system-prompt";
    let mut input = AiToolkitConfigInput::default();
    input.prompt_rollouts.push(PromptRolloutInput {
        scope: scope(),
        name: "system".into(),
        salt: "stable-salt".into(),
        versions: vec![
            WeightedPromptVersion::new("system", 1, secret_content, 1.0).unwrap(),
            WeightedPromptVersion::new("system", 2, "also-private", 3.0).unwrap(),
        ],
    });
    let runtime = AiToolkitRuntime::try_new(input).expect("runtime");
    assert!(runtime
        .has_prompt_rollout(&scope(), "system")
        .expect("valid lookup"));
    assert!(!runtime
        .has_prompt_rollout(&scope(), "missing")
        .expect("valid lookup"));
    let request = PromptSelectionRequest {
        scope: scope(),
        name: "system".into(),
        cohort: "private-user-key".into(),
    };
    let first = runtime.select_prompt(request.clone()).expect("selection");
    let second = runtime.select_prompt(request).expect("selection");
    assert_eq!(first.version, second.version);
    assert_eq!(first.cohort_digest.len(), 64);
    assert!(first
        .cohort_digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

    let snapshot = runtime
        .snapshot(ToolkitSnapshotRequest {
            scope: scope(),
            limit: Some(100),
        })
        .expect("snapshot");
    let serialized = serde_json::to_string(&snapshot).expect("serialize");
    assert!(!serialized.contains(secret_content));
    assert!(!serialized.contains("also-private"));
    assert!(!serialized.contains("private-user-key"));
    assert!(!serialized.contains("stable-salt"));
}

#[test]
fn registration_and_retention_are_fallible_and_bounded() {
    let mut input = AiToolkitConfigInput::default();
    input.allowed_scopes.push(scope());
    input.limits.max_dataset_entries = 1;
    let runtime = AiToolkitRuntime::try_new(input).expect("runtime");
    let error = runtime
        .register_dataset(DatasetRegistrationRequest {
            scope: scope(),
            name: "too-large".into(),
            version: 1,
            entries: vec![DatasetEntry::new("a"), DatasetEntry::new("b")],
        })
        .expect_err("bounded");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "dataset_entries",
            ..
        }
    ));
}

#[test]
fn dataset_scope_inventory_rejects_unknown_seed_and_registration_without_mutation() {
    let unknown_scope = ToolkitScope::new("origin-b", "tenant-b").expect("valid unknown scope");
    let dataset = crate::evaluation::Dataset::new(
        "answers",
        1,
        vec![DatasetEntry::with_expected("one", "1")],
    )
    .expect("valid dataset");

    let mut seeded = AiToolkitConfigInput::default();
    seeded.allowed_scopes.push(scope());
    seeded.datasets.push(ToolkitDatasetInput {
        scope: unknown_scope.clone(),
        dataset,
    });
    assert!(matches!(
        AiToolkitRuntime::validate(&seeded),
        Err(ToolkitError::InvalidConfiguration {
            field: "dataset.scope"
        })
    ));

    let mut input = AiToolkitConfigInput::default();
    input.allowed_scopes.push(scope());
    let runtime = AiToolkitRuntime::try_new(input).expect("runtime");
    let error = runtime
        .register_dataset(DatasetRegistrationRequest {
            scope: unknown_scope,
            name: "answers".into(),
            version: 1,
            entries: vec![DatasetEntry::with_expected("one", "1")],
        })
        .expect_err("unknown scope is refused");
    assert!(matches!(
        error,
        ToolkitError::NotFound {
            resource: "dataset_scope"
        }
    ));
    let datasets = runtime.datasets.lock();
    assert!(datasets.versions.is_empty());
    assert_eq!(datasets.retained_bytes, 0);
}

#[test]
fn global_dataset_version_limit_covers_seed_and_atomic_registration() {
    fn dataset(dataset_scope: ToolkitScope, case: &str) -> ToolkitDatasetInput {
        ToolkitDatasetInput {
            scope: dataset_scope,
            dataset: crate::evaluation::Dataset::new("answers", 1, vec![DatasetEntry::new(case)])
                .expect("valid dataset"),
        }
    }

    let second_scope = ToolkitScope::new("origin-b", "tenant-b").expect("second scope");
    let third_scope = ToolkitScope::new("origin-c", "tenant-c").expect("third scope");
    let mut seeded = AiToolkitConfigInput {
        allowed_scopes: vec![scope(), second_scope.clone(), third_scope.clone()],
        ..Default::default()
    };
    seeded.limits.max_dataset_versions_total = 2;
    seeded.datasets.extend([
        dataset(scope(), "case-1"),
        dataset(second_scope.clone(), "case-2"),
    ]);
    AiToolkitRuntime::validate(&seeded).expect("the exact global version limit is valid");
    seeded.datasets.push(dataset(third_scope.clone(), "case-3"));
    let error = AiToolkitRuntime::validate(&seeded).expect_err("global version limit plus one");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "dataset_versions_total",
            limit: 2,
            observed: 3
        }
    ));

    let mut input = AiToolkitConfigInput {
        allowed_scopes: vec![scope(), second_scope.clone(), third_scope.clone()],
        ..Default::default()
    };
    input.limits.max_dataset_versions_total = 2;
    let runtime = AiToolkitRuntime::try_new(input).expect("runtime");
    for (dataset_scope, case) in [(scope(), "case-1"), (second_scope, "case-2")] {
        runtime
            .register_dataset(DatasetRegistrationRequest {
                scope: dataset_scope,
                name: "answers".into(),
                version: 1,
                entries: vec![DatasetEntry::new(case)],
            })
            .expect("registration at or below the global limit");
    }
    let retained_before = runtime.datasets.lock().retained_bytes;
    let error = runtime
        .register_dataset(DatasetRegistrationRequest {
            scope: third_scope.clone(),
            name: "answers".into(),
            version: 1,
            entries: vec![DatasetEntry::new("case-3")],
        })
        .expect_err("global version limit plus one");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "dataset_versions_total",
            limit: 2,
            observed: 3
        }
    ));
    let datasets = runtime.datasets.lock();
    assert_eq!(datasets.versions.len(), 2);
    assert_eq!(datasets.retained_bytes, retained_before);
    assert!(!datasets
        .versions
        .contains_key(&(third_scope, "answers".into(), 1)));
}

#[test]
fn global_dataset_byte_limit_covers_seed_and_atomic_registration() {
    let second_scope = ToolkitScope::new("origin-b", "tenant-b").expect("second scope");
    let first_entries = vec![DatasetEntry::with_expected("one", "1")];
    let second_entries = vec![DatasetEntry::with_expected("two!", "2")];
    let first_bytes = serde_json::to_vec(&first_entries)
        .expect("dataset entries serialize")
        .len();
    let second_bytes = serde_json::to_vec(&second_entries)
        .expect("dataset entries serialize")
        .len();
    let serialized_bytes = first_bytes
        .checked_add(second_bytes)
        .expect("small fixture total");

    let mut seeded = AiToolkitConfigInput {
        allowed_scopes: vec![scope(), second_scope.clone()],
        ..Default::default()
    };
    seeded.limits.max_dataset_bytes_total = serialized_bytes;
    seeded.datasets.extend([
        ToolkitDatasetInput {
            scope: scope(),
            dataset: crate::evaluation::Dataset::new("answers", 1, first_entries.clone())
                .expect("valid dataset"),
        },
        ToolkitDatasetInput {
            scope: second_scope.clone(),
            dataset: crate::evaluation::Dataset::new("answers", 1, second_entries.clone())
                .expect("valid dataset"),
        },
    ]);
    AiToolkitRuntime::validate(&seeded).expect("the exact global byte limit is valid");
    seeded.limits.max_dataset_bytes_total = serialized_bytes - 1;
    let error = AiToolkitRuntime::validate(&seeded).expect_err("global byte limit plus one");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "dataset_bytes_total",
            limit,
            observed
        } if limit + 1 == observed && observed == serialized_bytes
    ));

    let mut exact = AiToolkitConfigInput {
        allowed_scopes: vec![scope(), second_scope.clone()],
        ..Default::default()
    };
    exact.limits.max_dataset_bytes_total = serialized_bytes;
    let exact = AiToolkitRuntime::try_new(exact).expect("runtime at exact byte limit");
    for (dataset_scope, entries) in [
        (scope(), first_entries.clone()),
        (second_scope.clone(), second_entries.clone()),
    ] {
        exact
            .register_dataset(DatasetRegistrationRequest {
                scope: dataset_scope,
                name: "answers".into(),
                version: 1,
                entries,
            })
            .expect("registration at the exact aggregate byte limit");
    }
    assert_eq!(exact.datasets.lock().retained_bytes, serialized_bytes);

    let mut over = AiToolkitConfigInput {
        allowed_scopes: vec![scope(), second_scope.clone()],
        ..Default::default()
    };
    over.limits.max_dataset_bytes_total = serialized_bytes - 1;
    let over = AiToolkitRuntime::try_new(over).expect("runtime below the dataset byte size");
    over.register_dataset(DatasetRegistrationRequest {
        scope: scope(),
        name: "answers".into(),
        version: 1,
        entries: first_entries,
    })
    .expect("first registration remains below the aggregate limit");
    let error = over
        .register_dataset(DatasetRegistrationRequest {
            scope: second_scope.clone(),
            name: "answers".into(),
            version: 1,
            entries: second_entries,
        })
        .expect_err("global byte limit plus one");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "dataset_bytes_total",
            limit,
            observed
        } if limit + 1 == observed && observed == serialized_bytes
    ));
    let datasets = over.datasets.lock();
    assert_eq!(datasets.versions.len(), 1);
    assert_eq!(datasets.retained_bytes, first_bytes);
    assert!(!datasets
        .versions
        .contains_key(&(second_scope, "answers".into(), 1)));
}

#[test]
fn global_dataset_limit_defaults_and_hard_maxima_are_stable() {
    let defaults = AiToolkitLimits::default();
    assert_eq!(defaults.max_dataset_versions_total, 256);
    assert_eq!(defaults.max_dataset_bytes_total, 64 * 1024 * 1024);

    let mut input = AiToolkitConfigInput::default();
    input.limits.max_dataset_versions_total = 16_385;
    assert!(matches!(
        AiToolkitRuntime::validate(&input),
        Err(ToolkitError::InvalidConfiguration {
            field: "limits.max_dataset_versions_total"
        })
    ));

    input.limits.max_dataset_versions_total = 256;
    input.limits.max_dataset_bytes_total = 512 * 1024 * 1024 + 1;
    assert!(matches!(
        AiToolkitRuntime::validate(&input),
        Err(ToolkitError::InvalidConfiguration {
            field: "limits.max_dataset_bytes_total"
        })
    ));
}

#[test]
fn non_payload_limit_outcomes_are_invalid_instead_of_internal() {
    let result: Result<(), ToolkitError> = Err(ToolkitError::LimitExceeded {
        resource: "dataset_entries",
        limit: 1,
        observed: 2,
    });
    assert_eq!(
        super::runtime::metric_outcome(&result),
        crate::ai_metrics::AiToolkitOutcome::Invalid
    );
}

#[test]
fn generation_validation_bounds_agent_endpoints_before_parsing() {
    let mut input = AiToolkitConfigInput::default();
    input.agents.push(ToolkitAgentInput {
        scope: scope(),
        id: "agent-a".into(),
        endpoint: format!("https://agent.invalid/{}", "x".repeat(600)),
        shared_secret: sbproxy_vault::SecretString::new("bounded"),
        capabilities: vec![],
    });

    let error = AiToolkitRuntime::validate(&input).expect_err("endpoint is bounded");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "agent_endpoint_bytes",
            ..
        }
    ));
}

#[test]
fn generation_validation_rejects_plaintext_agents_off_loopback() {
    let mut purposes = HashMap::new();
    purposes.insert(
        EgressPurpose::AgentOrchestration,
        PurposeAllowlist::default(),
    );
    let mut input = AiToolkitConfigInput {
        agent_egress: Some(AgentEgressInput {
            authorizer: EgressAuthorizer::new(EgressConfig { purposes }),
            purpose: EgressPurpose::AgentOrchestration,
        }),
        ..Default::default()
    };
    input.agents.push(ToolkitAgentInput {
        scope: scope(),
        id: "agent-a".into(),
        endpoint: "http://agents.example.test/invoke".into(),
        shared_secret: sbproxy_vault::SecretString::new("bounded"),
        capabilities: vec![],
    });

    let error = AiToolkitRuntime::validate(&input).expect_err("plaintext leaves loopback");
    assert!(matches!(
        &error,
        ToolkitError::InvalidConfiguration {
            field: "agent.endpoint"
        }
    ));
    assert!(!error.to_string().contains("agents.example.test"));
}

#[test]
fn generation_validation_allows_https_and_plaintext_loopback_agents() {
    for endpoint in [
        "http://127.0.0.1:4317/invoke",
        "http://[::1]:4317/invoke",
        "http://localhost:4317/invoke",
        "https://agents.example.test/invoke",
    ] {
        let mut purposes = HashMap::new();
        purposes.insert(
            EgressPurpose::AgentOrchestration,
            PurposeAllowlist::default(),
        );
        let mut input = AiToolkitConfigInput {
            agent_egress: Some(AgentEgressInput {
                authorizer: EgressAuthorizer::new(EgressConfig { purposes }),
                purpose: EgressPurpose::AgentOrchestration,
            }),
            ..Default::default()
        };
        input.agents.push(ToolkitAgentInput {
            scope: scope(),
            id: "agent-a".into(),
            endpoint: endpoint.into(),
            shared_secret: sbproxy_vault::SecretString::new("bounded"),
            capabilities: vec![],
        });

        AiToolkitRuntime::validate(&input)
            .unwrap_or_else(|error| panic!("{endpoint} must remain valid: {error}"));
    }
}

#[test]
fn generation_validation_bounds_aggregate_rollout_content() {
    let mut input = AiToolkitConfigInput::default();
    input.limits.max_request_bytes = 32;
    input.prompt_rollouts.push(PromptRolloutInput {
        scope: scope(),
        name: "system".into(),
        salt: "stable-salt".into(),
        versions: vec![
            WeightedPromptVersion::new("system", 1, "a".repeat(20), 1.0).unwrap(),
            WeightedPromptVersion::new("system", 2, "b".repeat(20), 1.0).unwrap(),
        ],
    });

    let error = AiToolkitRuntime::validate(&input).expect_err("rollout aggregate is bounded");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "prompt_rollout_content_bytes",
            ..
        }
    ));
}

#[test]
fn generation_validation_rejects_rollout_names_that_look_version_pinned() {
    let mut input = AiToolkitConfigInput::default();
    input.prompt_rollouts.push(PromptRolloutInput {
        scope: scope(),
        name: "system@v1".into(),
        salt: "stable-salt".into(),
        versions: vec![WeightedPromptVersion::new("system@v1", 1, "bounded", 1.0).unwrap()],
    });

    let error = AiToolkitRuntime::validate(&input).expect_err("rollout name is unambiguous");
    assert!(matches!(
        error,
        ToolkitError::InvalidConfiguration {
            field: "rollout.name"
        }
    ));
}

#[test]
fn generation_validation_keeps_workflow_deadlines_within_cli_budget() {
    let mut input = AiToolkitConfigInput::default();
    input.limits.max_workflow_timeout_ms = 60_001;

    let error = AiToolkitRuntime::validate(&input).expect_err("hard deadline ceiling");
    assert!(matches!(
        error,
        ToolkitError::InvalidConfiguration {
            field: "limits.workflow_timeout_ms"
        }
    ));
}

#[test]
fn discovery_and_snapshot_enforce_the_public_response_cap() {
    let address = SocketAddr::from(([127, 0, 0, 1], 1));
    let runtime = workflow_runtime(
        address,
        true,
        json!({"type":"object"}),
        json!({"type":"object"}),
        32,
        1_000,
        1,
    );
    let discovery = runtime
        .discover_agents(AgentDiscoveryRequest {
            scope: scope(),
            capability: None,
        })
        .expect_err("discovery result exceeds the configured cap");
    assert!(matches!(
        discovery,
        ToolkitError::LimitExceeded {
            resource: "agent_discovery_response_bytes",
            ..
        }
    ));

    let snapshot = runtime
        .snapshot(ToolkitSnapshotRequest {
            scope: scope(),
            limit: Some(16),
        })
        .expect_err("snapshot exceeds the configured cap");
    assert!(matches!(
        snapshot,
        ToolkitError::LimitExceeded {
            resource: "toolkit_snapshot_response_bytes",
            ..
        }
    ));
}

#[test]
fn retention_is_per_scope_and_a_noisy_tenant_cannot_evict_another() {
    let mut input = AiToolkitConfigInput::default();
    input.limits.max_retained_operations = 2;
    let runtime = AiToolkitRuntime::try_new(input).expect("runtime");
    let quiet = ToolkitScope::new("quiet-origin", "quiet-tenant").expect("quiet scope");
    let noisy = ToolkitScope::new("noisy-origin", "noisy-tenant").expect("noisy scope");

    runtime.record_operation(quiet.clone(), "toolkit_snapshot", "success");
    for _ in 0..4 {
        runtime.record_operation(noisy.clone(), "toolkit_snapshot", "success");
    }

    let operations = runtime.operations.lock();
    assert_eq!(
        operations
            .iter()
            .filter(|(candidate, _)| candidate == &quiet)
            .count(),
        1
    );
    assert_eq!(
        operations
            .iter()
            .filter(|(candidate, _)| candidate == &noisy)
            .count(),
        2
    );
}

#[test]
fn experiment_retention_refuses_instead_of_reporting_a_dropped_success() {
    fn row(id: String) -> EvaluationRunResult {
        EvaluationRunResult {
            experiment_id: id,
            experiment_name: "bounded".into(),
            dataset: DatasetRef {
                name: "answers".into(),
                version: 1,
            },
            model: "offline".into(),
            prompt_version: None,
            cases: 1,
            expected_match_rate: None,
            metric_pass_rate: 1.0,
            judge_score: None,
            criteria_scores: Default::default(),
            recorded_at: "2026-08-25T00:00:00Z".into(),
        }
    }

    let runtime = AiToolkitRuntime::try_new(AiToolkitConfigInput::default()).expect("runtime");
    {
        let mut experiments = runtime.experiments.lock();
        for index in 0..super::runtime::MAX_TOTAL_RETAINED_ROWS {
            let existing_scope =
                ToolkitScope::new(format!("origin-{index}"), format!("tenant-{index}"))
                    .expect("bounded unique scope");
            experiments.push_back((existing_scope, row(format!("existing-{index}"))));
        }
    }

    let error = runtime
        .retain_experiment(scope(), row("new-experiment".into()))
        .expect_err("a full cross-scope ring cannot silently drop the result");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "experiment_retention_total",
            limit: super::runtime::MAX_TOTAL_RETAINED_ROWS,
            ..
        }
    ));
    assert!(!runtime
        .experiments
        .lock()
        .iter()
        .any(|(_, existing)| existing.experiment_id == "new-experiment"));
}

/// A polling dashboard must not evict a scope's decision history.
///
/// `snapshot` and `discover_agents` are read paths an admin console hits on
/// a timer. They used to call `record_operation` unconditionally, so a
/// console polling once a second filled the bounded ring with its own reads
/// and pushed out the workflow and evaluation rows the ring exists to keep.
/// Restoring either unconditional call fails this test.
#[test]
fn successful_toolkit_reads_stay_out_of_the_bounded_operations_ring() {
    let address = SocketAddr::from(([127, 0, 0, 1], 1));
    let runtime = workflow_runtime(
        address,
        true,
        json!({"type": "object"}),
        json!({"type": "object"}),
        1_000_000,
        1_000,
        1,
    );

    for _ in 0..4 {
        runtime
            .discover_agents(AgentDiscoveryRequest {
                scope: scope(),
                capability: None,
            })
            .expect("discovery succeeds for the configured scope");
        runtime
            .snapshot(ToolkitSnapshotRequest {
                scope: scope(),
                limit: Some(16),
            })
            .expect("snapshot succeeds for the configured scope");
    }

    let retained: Vec<String> = runtime
        .operations
        .lock()
        .iter()
        .map(|(_, row)| row.operation.clone())
        .collect();
    assert!(
        retained.is_empty(),
        "successful reads must not retain a row: {retained:?}"
    );
}

/// The other half of the bargain, and what keeps the test above from
/// passing because the recorder is simply unreachable from these paths: a
/// *failed* read is still worth a row.
#[test]
fn failed_toolkit_reads_are_still_retained() {
    let address = SocketAddr::from(([127, 0, 0, 1], 1));
    let runtime = workflow_runtime(
        address,
        true,
        json!({"type": "object"}),
        json!({"type": "object"}),
        1_000_000,
        1_000,
        1,
    );
    // A well-formed scope that owns no agents: past `validate_scope`, so
    // the row is retainable, and refused by the registry lookup.
    let empty = ToolkitScope::new("origin-b", "tenant-b").expect("valid scope");

    runtime
        .discover_agents(AgentDiscoveryRequest {
            scope: empty.clone(),
            capability: None,
        })
        .expect_err("no agent is registered in this scope");

    let operations = runtime.operations.lock();
    assert_eq!(
        operations
            .iter()
            .filter(|(candidate, row)| candidate == &empty && row.operation == "agent_discovery")
            .count(),
        1,
        "a refused discovery is still worth a row"
    );
}

#[test]
fn invalid_deserialized_scope_is_never_retained() {
    let runtime = AiToolkitRuntime::try_new(AiToolkitConfigInput::default()).expect("runtime");
    let invalid = ToolkitScope {
        origin_id: "x".repeat(4_096),
        tenant_id: "tenant".into(),
    };

    runtime.record_operation(invalid, "toolkit_snapshot", "invalid");

    assert!(runtime.operations.lock().is_empty());
}

#[tokio::test]
async fn governed_loopback_workflow_authenticates_and_validates_both_schemas() {
    let response = br#"{"outcome":"done","output":{"ok":true}}"#.to_vec();
    let (address, accepted, auth_ok, server) = loopback_server(vec![TestReply {
        delay: Duration::ZERO,
        body: response,
    }])
    .await;
    let runtime = workflow_runtime(
        address,
        true,
        json!({"type":"object","required":["question"]}),
        json!({"type":"object","required":["ok"]}),
        1024,
        1_000,
        1,
    );

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.run_workflow(workflow_request(json!({"question":"safe"}))),
    )
    .await
    .expect("test deadline")
    .expect("workflow succeeds");
    assert_eq!(result.output, json!({"ok": true}));
    assert_eq!(result.steps.len(), 1);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert!(auth_ok.load(Ordering::SeqCst));
    let snapshot = runtime
        .snapshot(ToolkitSnapshotRequest {
            scope: scope(),
            limit: Some(16),
        })
        .expect("snapshot");
    let snapshot = serde_json::to_string(&snapshot).expect("snapshot JSON");
    assert!(!snapshot.contains("shared-secret"));
    assert!(!snapshot.contains(&address.to_string()));
    server.await.expect("server task");
}

#[tokio::test]
async fn workflow_step_budget_prevents_a_second_agent_connection() {
    let reply = TestReply {
        delay: Duration::ZERO,
        body: br#"{"outcome":"again","output":{}}"#.to_vec(),
    };
    let (address, accepted, auth_ok, server) = loopback_server(vec![
        TestReply {
            delay: reply.delay,
            body: reply.body.clone(),
        },
        reply,
    ])
    .await;
    let runtime = workflow_runtime_with_transitions(
        address,
        true,
        json!({"type":"object"}),
        json!({"type":"object"}),
        1024,
        1_000,
        1,
        HashMap::from([("again".into(), "invoke".into())]),
    );

    let error = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.run_workflow(workflow_request(json!({}))),
    )
    .await
    .expect("test deadline")
    .expect_err("the one-step cyclic workflow exhausts its budget");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "workflow_steps",
            limit: 1,
            observed: 2,
        }
    ));
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the rejected second step must not reach the transport"
    );
    assert!(auth_ok.load(Ordering::SeqCst));
    server.abort();
}

#[tokio::test]
async fn denied_egress_never_reaches_the_transport() {
    let (address, accepted, _auth_ok, server) = loopback_server(vec![TestReply {
        delay: Duration::ZERO,
        body: br#"{"outcome":"done","output":{}}"#.to_vec(),
    }])
    .await;
    let runtime = workflow_runtime(
        address,
        false,
        json!({"type":"object"}),
        json!({"type":"object"}),
        1024,
        500,
        1,
    );
    let error = runtime
        .run_workflow(workflow_request(json!({})))
        .await
        .expect_err("egress is denied");
    assert!(matches!(error, ToolkitError::GovernedEgress { .. }));
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn agent_response_cap_plus_one_fails_closed() {
    let cap = 64usize;
    let (address, accepted, _auth_ok, server) = loopback_server(vec![TestReply {
        delay: Duration::ZERO,
        body: vec![b'x'; cap + 1],
    }])
    .await;
    let runtime = workflow_runtime(
        address,
        true,
        json!({"type":"object"}),
        json!({"type":"object"}),
        cap,
        1_000,
        1,
    );
    let error = runtime
        .run_workflow(workflow_request(json!({})))
        .await
        .expect_err("response is capped");
    assert!(matches!(
        error,
        ToolkitError::GovernedEgress {
            reason: "response_too_large"
        }
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    server.await.expect("server task");
}

#[tokio::test]
async fn complete_workflow_result_is_bounded_before_success() {
    let body = br#"{"outcome":"done","output":{}}"#.to_vec();
    assert!(body.len() < 64);
    let (address, accepted, _auth_ok, server) = loopback_server(vec![TestReply {
        delay: Duration::ZERO,
        body,
    }])
    .await;
    let runtime = workflow_runtime(
        address,
        true,
        json!({"type":"object"}),
        json!({"type":"object"}),
        64,
        1_000,
        1,
    );

    let error = runtime
        .run_workflow(workflow_request(json!({})))
        .await
        .expect_err("the complete public result exceeds the cap");
    assert!(matches!(
        error,
        ToolkitError::LimitExceeded {
            resource: "workflow_response_bytes",
            ..
        }
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    server.await.expect("server task");
}

#[tokio::test]
async fn schema_rejections_happen_on_the_correct_side_of_transport() {
    let (input_address, input_accepted, _, input_server) = loopback_server(vec![TestReply {
        delay: Duration::ZERO,
        body: br#"{"outcome":"done","output":{}}"#.to_vec(),
    }])
    .await;
    let input_runtime = workflow_runtime(
        input_address,
        true,
        json!({"type":"object","required":["allowed"]}),
        json!({"type":"object"}),
        1024,
        500,
        1,
    );
    let input_error = input_runtime
        .run_workflow(workflow_request(json!({"blocked":true})))
        .await
        .expect_err("input schema rejects");
    assert!(matches!(
        input_error,
        ToolkitError::SchemaViolation {
            boundary: "agent_input"
        }
    ));
    assert_eq!(input_accepted.load(Ordering::SeqCst), 0);
    input_server.abort();

    let (output_address, output_accepted, _, output_server) = loopback_server(vec![TestReply {
        delay: Duration::ZERO,
        body: br#"{"outcome":"done","output":{"wrong":true}}"#.to_vec(),
    }])
    .await;
    let output_runtime = workflow_runtime(
        output_address,
        true,
        json!({"type":"object"}),
        json!({"type":"object","required":["ok"]}),
        1024,
        500,
        1,
    );
    let output_error = output_runtime
        .run_workflow(workflow_request(json!({})))
        .await
        .expect_err("output schema rejects");
    assert!(matches!(
        output_error,
        ToolkitError::SchemaViolation {
            boundary: "agent_output"
        }
    ));
    assert_eq!(output_accepted.load(Ordering::SeqCst), 1);
    output_server.await.expect("server task");
}

#[tokio::test]
async fn absolute_deadline_releases_the_only_workflow_permit_for_recovery() {
    let success = br#"{"outcome":"done","output":{"ok":true}}"#.to_vec();
    let (address, accepted, auth_ok, server) = loopback_server(vec![
        TestReply {
            delay: Duration::from_millis(250),
            body: success.clone(),
        },
        TestReply {
            delay: Duration::ZERO,
            body: success,
        },
    ])
    .await;
    let runtime = workflow_runtime(
        address,
        true,
        json!({"type":"object"}),
        json!({"type":"object","required":["ok"]}),
        1024,
        50,
        1,
    );

    let started = std::time::Instant::now();
    let first = runtime
        .run_workflow(workflow_request(json!({"attempt":1})))
        .await
        .expect_err("slow response times out");
    assert!(started.elapsed() < Duration::from_millis(200));
    assert!(matches!(
        first,
        ToolkitError::Deadline {
            operation: "agent_workflow"
        }
    ));

    let second = tokio::time::timeout(
        Duration::from_secs(1),
        runtime.run_workflow(workflow_request(json!({"attempt":2}))),
    )
    .await
    .expect("recovery test deadline")
    .expect("permit was released");
    assert_eq!(second.output, json!({"ok": true}));
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    assert!(auth_ok.load(Ordering::SeqCst));
    server.await.expect("server task");
}

#[test]
fn busy_maps_to_its_own_closed_outcome_not_internal() {
    // A concurrency-admission refusal is capacity signal, not an internal
    // fault: alerting on `outcome="internal"` must not page for saturation.
    let busy = ToolkitError::Busy {
        operation: "agent_workflow",
    };
    let outcome = error_metric_outcome(&busy);
    assert_eq!(outcome, crate::ai_metrics::AiToolkitOutcome::Busy);
    assert_eq!(outcome.as_label(), "busy");
    assert_eq!(
        error_metric_outcome(&ToolkitError::InvalidAgentResponse).as_label(),
        "invalid"
    );
}
