use sbproxy_ai::external_guardrail::{
    check_external_guardrail, CompiledGuardrailProvider, ExternalGuardrailConfig,
    ExternalGuardrailRequest, GuardrailPhase, GuardrailProvider,
};
use std::time::Duration;

async fn fixture_server(
    status: u16,
    body: &'static str,
    delay: Duration,
) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    let received = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept fixture request");
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream
                .read(&mut buffer)
                .await
                .expect("read fixture request");
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            let header_end = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4);
            let Some(header_end) = header_end else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_default();
            if bytes.len() >= header_end + content_length {
                break;
            }
        }
        tokio::time::sleep(delay).await;
        let reason = if status == 200 { "OK" } else { "Bad Gateway" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write fixture response");
        String::from_utf8(bytes).expect("fixture request is utf-8")
    });
    (format!("http://{address}"), received)
}

fn request(phase: GuardrailPhase) -> ExternalGuardrailRequest<'static> {
    ExternalGuardrailRequest {
        content: "fixture prompt",
        model: "fixture-model",
        phase,
    }
}

fn provider_config(
    provider: &str,
    url: String,
    fail_open: bool,
    timeout_ms: u64,
) -> ExternalGuardrailConfig {
    serde_json::from_value(serde_json::json!({
        "name": provider,
        "provider": provider,
        "url": url,
        "mode": "during_call",
        "api_key": "fixture-key",
        "project_id": "fixture-project",
        "allow_private_url": true,
        "fail_open": fail_open,
        "timeout_ms": timeout_ms
    }))
    .expect("provider fixture config")
}

#[test]
fn legacy_generic_config_defaults_provider() {
    let config: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
        "name": "custom",
        "url": "https://guard.example.test/check",
        "mode": "pre_call",
        "default_on": true,
        "api_key": "secret://guard-key"
    }))
    .expect("legacy generic document must deserialize");

    assert_eq!(config.provider, GuardrailProvider::Generic);
}

#[test]
fn external_request_carries_phase_and_model_without_exposing_content() {
    let request = ExternalGuardrailRequest {
        content: "test prompt",
        model: "test-model",
        phase: GuardrailPhase::Input,
    };

    assert_eq!(request.model, "test-model");
    assert_eq!(request.phase.as_str(), "input");
}

#[tokio::test]
async fn lakera_input_contract_allows_and_sends_exact_wire_format() {
    let (base_url, received) =
        fixture_server(200, r#"{"flagged":false,"breakdown":[]}"#, Duration::ZERO).await;
    let config = provider_config("lakera", format!("{base_url}/v2/guard"), false, 2_000);

    let verdict = check_external_guardrail(&config, request(GuardrailPhase::Input)).await;

    assert!(verdict.allowed);
    let request = received.await.expect("fixture task");
    assert!(request.starts_with("POST /v2/guard HTTP/1.1\r\n"));
    assert!(request.contains("authorization: Bearer fixture-key\r\n"));
    assert!(request.ends_with(
        r#"{"breakdown":true,"messages":[{"content":"fixture prompt","role":"user"}],"project_id":"fixture-project"}"#
    ));
}

#[tokio::test]
async fn lakera_block_malformed_status_timeout_and_fail_modes_are_safe() {
    let (base_url, received) = fixture_server(
        200,
        r#"{"flagged":true,"breakdown":[{"detected":true,"detector_type":"PROMPT_INJECTION"}]}"#,
        Duration::ZERO,
    )
    .await;
    let config = provider_config("lakera", format!("{base_url}/v2/guard"), false, 2_000);
    let verdict = check_external_guardrail(&config, request(GuardrailPhase::Output)).await;
    assert!(!verdict.allowed);
    assert_eq!(verdict.reason.as_deref(), Some("lakera blocked content"));
    assert_eq!(verdict.categories, ["prompt_injection"]);
    assert!(received
        .await
        .expect("fixture task")
        .contains("POST /v2/guard HTTP/1.1"));

    for (status, body, delay, fail_open, expected_allowed) in [
        (200, "{not json", Duration::ZERO, false, false),
        (200, r#"{"breakdown":[]}"#, Duration::ZERO, false, false),
        (502, r#"{}"#, Duration::ZERO, true, true),
        (
            200,
            r#"{"flagged":false}"#,
            Duration::from_millis(50),
            true,
            true,
        ),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        let config = provider_config(
            "lakera",
            format!("{base_url}/v2/guard"),
            fail_open,
            timeout_ms,
        );
        assert_eq!(
            check_external_guardrail(&config, request(GuardrailPhase::Input))
                .await
                .allowed,
            expected_allowed
        );
        let _ = received.await;
    }
}

#[tokio::test]
async fn aporia_input_and_output_contracts_allow_and_send_exact_wire_format() {
    let (base_url, received) =
        fixture_server(200, r#"{"action":"passthrough"}"#, Duration::ZERO).await;
    let config = provider_config(
        "aporia",
        format!("{base_url}/fixture-project/validate"),
        false,
        2_000,
    );
    assert!(
        check_external_guardrail(&config, request(GuardrailPhase::Input))
            .await
            .allowed
    );
    let wire_request = received.await.expect("fixture task");
    assert!(wire_request.starts_with("POST /fixture-project/validate HTTP/1.1\r\n"));
    assert!(wire_request.contains("x-aporia-api-key: fixture-key\r\n"));
    assert!(wire_request.ends_with(
        r#"{"explain":true,"messages":[{"content":"fixture prompt","role":"user"}],"validation_target":"prompt"}"#
    ));

    let (base_url, received) =
        fixture_server(200, r#"{"action":"passthrough"}"#, Duration::ZERO).await;
    let config = provider_config(
        "aporia",
        format!("{base_url}/fixture-project/validate"),
        false,
        2_000,
    );
    assert!(
        check_external_guardrail(&config, request(GuardrailPhase::Output))
            .await
            .allowed
    );
    let wire_request = received.await.expect("fixture task");
    assert!(wire_request.ends_with(
        r#"{"explain":true,"messages":[{"content":"fixture prompt","role":"user"}],"response":"fixture prompt","validation_target":"response"}"#
    ));
}

#[tokio::test]
async fn aporia_block_malformed_status_timeout_and_fail_modes_are_safe() {
    let (base_url, received) = fixture_server(200, r#"{"action":"block"}"#, Duration::ZERO).await;
    let config = provider_config(
        "aporia",
        format!("{base_url}/fixture-project/validate"),
        false,
        2_000,
    );
    let verdict = check_external_guardrail(&config, request(GuardrailPhase::Input)).await;
    assert!(!verdict.allowed);
    assert_eq!(verdict.reason.as_deref(), Some("aporia blocked content"));
    let _ = received.await;

    for (status, body, delay, fail_open, expected_allowed) in [
        (200, "{not json", Duration::ZERO, true, true),
        (200, r#"{}"#, Duration::ZERO, false, false),
        (200, r#"{"action":true}"#, Duration::ZERO, false, false),
        (200, r#"{"action":"unknown"}"#, Duration::ZERO, true, true),
        (502, r#"{}"#, Duration::ZERO, false, false),
        (
            200,
            r#"{"action":"passthrough"}"#,
            Duration::from_millis(50),
            false,
            false,
        ),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        let config = provider_config(
            "aporia",
            format!("{base_url}/fixture-project/validate"),
            fail_open,
            timeout_ms,
        );
        assert_eq!(
            check_external_guardrail(&config, request(GuardrailPhase::Input))
                .await
                .allowed,
            expected_allowed
        );
        let _ = received.await;
    }
}

#[tokio::test]
async fn aporia_modify_and_rephrase_obey_both_fail_modes() {
    for (action, fail_open, expected_allowed, expected_reason) in [
        (
            "modify",
            false,
            false,
            "external guardrail unavailable; fail-closed",
        ),
        (
            "modify",
            true,
            true,
            "external guardrail unavailable; fail-open",
        ),
        (
            "rephrase",
            false,
            false,
            "external guardrail unavailable; fail-closed",
        ),
        (
            "rephrase",
            true,
            true,
            "external guardrail unavailable; fail-open",
        ),
    ] {
        let response = match action {
            "modify" => r#"{"action":"modify","revised_response":"vendor controlled"}"#,
            "rephrase" => r#"{"action":"rephrase","revised_response":"vendor controlled"}"#,
            _ => unreachable!("fixture action is fixed"),
        };
        let (base_url, received) = fixture_server(200, response, Duration::ZERO).await;
        let config = provider_config(
            "aporia",
            format!("{base_url}/fixture-project/validate"),
            fail_open,
            2_000,
        );

        let verdict = check_external_guardrail(&config, request(GuardrailPhase::Output)).await;

        assert_eq!(verdict.allowed, expected_allowed);
        assert_eq!(verdict.reason.as_deref(), Some(expected_reason));
        assert!(
            !verdict
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("vendor controlled"),
            "vendor response text must not become an operator reason"
        );
        let _ = received.await;
    }
}

fn azure_config(url: String, fail_open: bool, timeout_ms: u64) -> ExternalGuardrailConfig {
    serde_json::from_value(serde_json::json!({
        "name": "azure",
        "provider": "azure_content_safety",
        "url": url,
        "mode": "during_call",
        "api_key": "fixture-key",
        "allow_private_url": true,
        "fail_open": fail_open,
        "timeout_ms": timeout_ms
    }))
    .expect("Azure fixture config")
}

const AZURE_ALL_CLEAR: &str = r#"{"categoriesAnalysis":[{"category":"Hate","severity":0},{"category":"SelfHarm","severity":0},{"category":"Sexual","severity":0},{"category":"Violence","severity":0}],"blocklistsMatch":[]}"#;

fn bedrock_config(url: String, fail_open: bool, timeout_ms: u64) -> ExternalGuardrailConfig {
    serde_json::from_value(serde_json::json!({
        "name": "bedrock",
        "provider": "bedrock",
        "url": url,
        "mode": "during_call",
        "api_key": "fixture-key",
        "guardrail_id": "fixture-guardrail",
        "guardrail_version": "1",
        "allow_private_url": true,
        "fail_open": fail_open,
        "timeout_ms": timeout_ms
    }))
    .expect("Bedrock fixture config")
}

fn crowdstrike_config(
    url: String,
    fail_open: bool,
    timeout_ms: u64,
    application_id: Option<&str>,
) -> ExternalGuardrailConfig {
    serde_json::from_value(serde_json::json!({
        "name": "crowdstrike",
        "provider": "crowd_strike",
        "url": url,
        "mode": "during_call",
        "api_key": "fixture-key",
        "application_id": application_id,
        "allow_private_url": true,
        "fail_open": fail_open,
        "timeout_ms": timeout_ms
    }))
    .expect("CrowdStrike fixture config")
}

fn pangea_config(url: String, fail_open: bool, timeout_ms: u64) -> ExternalGuardrailConfig {
    serde_json::from_value(serde_json::json!({
        "name": "pangea",
        "provider": "pangea",
        "url": url,
        "mode": "during_call",
        "api_key": "fixture-key",
        "input_recipe": "fixture-input-recipe",
        "output_recipe": "fixture-output-recipe",
        "allow_private_url": true,
        "fail_open": fail_open,
        "timeout_ms": timeout_ms
    }))
    .expect("Pangea fixture config")
}

fn mistral_config(
    url: String,
    fail_open: bool,
    timeout_ms: u64,
    model: Option<&str>,
    score_threshold: Option<f64>,
) -> ExternalGuardrailConfig {
    serde_json::from_value(serde_json::json!({
        "name": "mistral",
        "provider": "mistral",
        "url": url,
        "mode": "during_call",
        "api_key": "fixture-key",
        "model": model,
        "score_threshold": score_threshold,
        "allow_private_url": true,
        "fail_open": fail_open,
        "timeout_ms": timeout_ms
    }))
    .expect("Mistral fixture config")
}

fn patronus_config(
    url: String,
    fail_open: bool,
    timeout_ms: u64,
    criteria: Option<&str>,
) -> ExternalGuardrailConfig {
    serde_json::from_value(serde_json::json!({
        "name": "patronus",
        "provider": "patronus",
        "url": url,
        "mode": "during_call",
        "api_key": "fixture-key",
        "evaluator": "prompt-injection",
        "criteria": criteria,
        "allow_private_url": true,
        "fail_open": fail_open,
        "timeout_ms": timeout_ms
    }))
    .expect("Patronus fixture config")
}

const MISTRAL_ALLOW: &str = r#"{"results":[{"categories":{"hate":false,"pii":false},"category_scores":{"hate":0.01,"pii":0.02}}]}"#;

#[tokio::test]
async fn mistral_contract_uses_documented_path_bearer_default_and_override_models() {
    let (base_url, received) = fixture_server(200, MISTRAL_ALLOW, Duration::ZERO).await;
    let verdict = check_external_guardrail(
        &mistral_config(
            format!("{base_url}/v1/moderations"),
            false,
            2_000,
            None,
            None,
        ),
        request(GuardrailPhase::Input),
    )
    .await;
    assert!(verdict.allowed);
    let wire_request = received.await.expect("fixture task");
    assert!(wire_request.starts_with("POST /v1/moderations HTTP/1.1\r\n"));
    assert!(wire_request.contains("authorization: Bearer fixture-key\r\n"));
    assert!(
        wire_request.ends_with(r#"{"input":["fixture prompt"],"model":"mistral-moderation-2603"}"#)
    );

    let (base_url, received) = fixture_server(200, MISTRAL_ALLOW, Duration::ZERO).await;
    assert!(
        check_external_guardrail(
            &mistral_config(
                format!("{base_url}/v1/moderations"),
                false,
                2_000,
                Some("fixture-moderation-model"),
                None,
            ),
            request(GuardrailPhase::Output),
        )
        .await
        .allowed
    );
    assert!(received
        .await
        .expect("fixture task")
        .ends_with(r#"{"input":["fixture prompt"],"model":"fixture-moderation-model"}"#));
}

#[tokio::test]
async fn mistral_blocks_true_categories_and_configured_score_thresholds() {
    let (base_url, received) = fixture_server(
        200,
        r#"{"results":[{"categories":{"hate":true,"pii":false},"category_scores":{"hate":0.01,"pii":0.02}}]}"#,
        Duration::ZERO,
    )
    .await;
    let verdict = check_external_guardrail(
        &mistral_config(
            format!("{base_url}/v1/moderations"),
            false,
            2_000,
            None,
            None,
        ),
        request(GuardrailPhase::Input),
    )
    .await;
    assert!(!verdict.allowed);
    assert_eq!(verdict.reason.as_deref(), Some("mistral blocked content"));
    assert_eq!(verdict.categories, ["hate", "pii"]);
    assert_eq!(verdict.scores.get("hate"), Some(&0.01));
    let _ = received.await;

    let (base_url, received) = fixture_server(
        200,
        r#"{"results":[{"categories":{"hate":false,"pii":false},"category_scores":{"hate":0.8,"pii":0.02}}]}"#,
        Duration::ZERO,
    )
    .await;
    let verdict = check_external_guardrail(
        &mistral_config(
            format!("{base_url}/v1/moderations"),
            false,
            2_000,
            None,
            Some(0.8),
        ),
        request(GuardrailPhase::Output),
    )
    .await;
    assert!(!verdict.allowed, "threshold equality must block");
    assert_eq!(verdict.reason.as_deref(), Some("mistral blocked content"));
    let _ = received.await;
}

#[tokio::test]
async fn mistral_rejects_invalid_verdicts_and_obeys_both_fail_modes() {
    for (body, fail_open, expected_allowed) in [
        ("{not json", false, false),
        (r#"{"results":[]}"#, true, true),
        (
            r#"{"results":[{"categories":{},"category_scores":{}}]}"#,
            false,
            false,
        ),
        (r#"{"results":[{"categories":{"hate":false}}]}"#, true, true),
        (
            r#"{"results":[{"categories":{"hate":false},"category_scores":{"pii":0.01}}]}"#,
            false,
            false,
        ),
        (
            r#"{"results":[{"categories":{"hate":false},"category_scores":{"hate":0.01}},{"categories":{"hate":false},"category_scores":{"hate":0.01}}]}"#,
            true,
            true,
        ),
        (
            r#"{"results":[{"categories":{"hate":"false"},"category_scores":{"hate":0.01}}]}"#,
            true,
            true,
        ),
        (
            r#"{"results":[{"categories":{"hate":false},"category_scores":{"hate":1.1}}]}"#,
            false,
            false,
        ),
        (
            r#"{"results":[{"categories":{"hate":false},"category_scores":{"hate":1e999}}]}"#,
            true,
            true,
        ),
    ] {
        let (base_url, received) = fixture_server(200, body, Duration::ZERO).await;
        assert_eq!(
            check_external_guardrail(
                &mistral_config(
                    format!("{base_url}/v1/moderations"),
                    fail_open,
                    2_000,
                    None,
                    None,
                ),
                request(GuardrailPhase::Input),
            )
            .await
            .allowed,
            expected_allowed
        );
        let _ = received.await;
    }

    for (status, body, delay, fail_open, expected_allowed) in [
        (502, r#"{}"#, Duration::ZERO, false, false),
        (200, MISTRAL_ALLOW, Duration::from_millis(50), true, true),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        assert_eq!(
            check_external_guardrail(
                &mistral_config(
                    format!("{base_url}/v1/moderations"),
                    fail_open,
                    timeout_ms,
                    None,
                    None,
                ),
                request(GuardrailPhase::Input),
            )
            .await
            .allowed,
            expected_allowed
        );
        let _ = received.await;
    }
}

const PATRONUS_ALLOW: &str =
    r#"{"results":[{"status":"success","evaluation_result":{"pass":true}}]}"#;

#[tokio::test]
async fn patronus_contract_disables_capture_for_input_output_and_optional_criteria() {
    let (base_url, received) = fixture_server(200, PATRONUS_ALLOW, Duration::ZERO).await;
    assert!(
        check_external_guardrail(
            &patronus_config(format!("{base_url}/v1/evaluate"), false, 2_000, None),
            request(GuardrailPhase::Input),
        )
        .await
        .allowed
    );
    let wire_request = received.await.expect("fixture task");
    assert!(wire_request.starts_with("POST /v1/evaluate HTTP/1.1\r\n"));
    assert!(wire_request.contains("x-api-key: fixture-key\r\n"));
    assert!(wire_request.ends_with(
        r#"{"capture":"none","evaluators":[{"evaluator":"prompt-injection"}],"task_input":"fixture prompt"}"#
    ));

    let (base_url, received) = fixture_server(200, PATRONUS_ALLOW, Duration::ZERO).await;
    assert!(
        check_external_guardrail(
            &patronus_config(
                format!("{base_url}/v1/evaluate"),
                false,
                2_000,
                Some("block adversarial prompts"),
            ),
            request(GuardrailPhase::Output),
        )
        .await
        .allowed
    );
    assert!(received.await.expect("fixture task").ends_with(
        r#"{"capture":"none","evaluators":[{"criteria":"block adversarial prompts","evaluator":"prompt-injection"}],"task_output":"fixture prompt"}"#
    ));
}

#[tokio::test]
async fn patronus_blocks_failed_evaluations_and_rejects_invalid_result_sets() {
    let (base_url, received) = fixture_server(
        200,
        r#"{"results":[{"status":"success","evaluation_result":{"pass":false}}]}"#,
        Duration::ZERO,
    )
    .await;
    let verdict = check_external_guardrail(
        &patronus_config(format!("{base_url}/v1/evaluate"), false, 2_000, None),
        request(GuardrailPhase::Input),
    )
    .await;
    assert!(!verdict.allowed);
    assert_eq!(verdict.reason.as_deref(), Some("patronus blocked content"));
    let _ = received.await;

    for (body, fail_open, expected_allowed) in [
        ("{not json", false, false),
        (r#"{"results":[]}"#, true, true),
        (
            r#"{"results":[{"status":"success","evaluation_result":{"pass":true}},{"status":"success","evaluation_result":{"pass":true}}]}"#,
            false,
            false,
        ),
        (
            r#"{"results":[{"status":"failed","evaluation_result":{"pass":true}}]}"#,
            false,
            false,
        ),
        (r#"{"results":[{"status":"success"}]}"#, true, true),
        (
            r#"{"results":[{"status":"success","evaluation_result":{"pass":"true"}}]}"#,
            false,
            false,
        ),
    ] {
        let (base_url, received) = fixture_server(200, body, Duration::ZERO).await;
        assert_eq!(
            check_external_guardrail(
                &patronus_config(format!("{base_url}/v1/evaluate"), fail_open, 2_000, None),
                request(GuardrailPhase::Output),
            )
            .await
            .allowed,
            expected_allowed
        );
        let _ = received.await;
    }

    for (status, body, delay, fail_open, expected_allowed) in [
        (502, r#"{}"#, Duration::ZERO, true, true),
        (200, PATRONUS_ALLOW, Duration::from_millis(50), false, false),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        assert_eq!(
            check_external_guardrail(
                &patronus_config(
                    format!("{base_url}/v1/evaluate"),
                    fail_open,
                    timeout_ms,
                    None,
                ),
                request(GuardrailPhase::Input),
            )
            .await
            .allowed,
            expected_allowed
        );
        let _ = received.await;
    }
}

#[test]
fn pangea_defaults_compile_to_documented_endpoint_and_recipes() {
    let config: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
        "name": "pangea",
        "provider": "pangea",
        "mode": "during_call",
        "api_key": "fixture-key"
    }))
    .expect("Pangea default config");

    let CompiledGuardrailProvider::Pangea(config) =
        config.validate().expect("Pangea defaults compile")
    else {
        panic!("expected Pangea provider");
    };

    assert_eq!(
        config.url,
        "https://ai-guard.aws.us.pangea.cloud/v1/text/guard"
    );
    assert_eq!(config.input_recipe, "pangea_prompt_guard");
    assert_eq!(config.output_recipe, "pangea_llm_response_guard");
}

const GUARDRAIL_DETECTORS: &str = r#"{"prompt_injection":{"detected":true,"data":{"analyzer_responses":[{"analyzer":"PA4002","confidence":0.99}]}},"pii_entity":{"detected":false,"data":null}}"#;

#[tokio::test]
async fn crowdstrike_input_contract_sends_documented_shape_and_normalizes_verdict_data() {
    let response = format!(r#"{{"result":{{"blocked":false,"detectors":{GUARDRAIL_DETECTORS}}}}}"#);
    let (base_url, received) =
        fixture_server(200, Box::leak(response.into_boxed_str()), Duration::ZERO).await;
    let verdict = check_external_guardrail(
        &crowdstrike_config(
            format!("{base_url}/aidr/aiguard/v1/guard_chat_completions"),
            false,
            2_000,
            Some("fixture-app"),
        ),
        request(GuardrailPhase::Input),
    )
    .await;

    assert!(verdict.allowed);
    assert_eq!(verdict.categories, ["prompt_injection"]);
    assert_eq!(verdict.scores.get("prompt_injection.pa4002"), Some(&0.99));
    let wire_request = received.await.expect("fixture task");
    assert!(wire_request.starts_with("POST /aidr/aiguard/v1/guard_chat_completions HTTP/1.1\r\n"));
    assert!(wire_request.contains("authorization: Bearer fixture-key\r\n"));
    assert!(wire_request.ends_with(
        r#"{"app_id":"fixture-app","guard_input":{"messages":[{"content":"fixture prompt","role":"user"}]}}"#
    ));
}

#[tokio::test]
async fn crowdstrike_block_malformed_unknown_status_timeout_and_fail_modes_are_safe() {
    let blocked = format!(r#"{{"result":{{"blocked":true,"detectors":{GUARDRAIL_DETECTORS}}}}}"#);
    let (base_url, received) =
        fixture_server(200, Box::leak(blocked.into_boxed_str()), Duration::ZERO).await;
    let verdict = check_external_guardrail(
        &crowdstrike_config(
            format!("{base_url}/aidr/aiguard/v1/guard_chat_completions"),
            false,
            2_000,
            None,
        ),
        request(GuardrailPhase::Output),
    )
    .await;
    assert!(!verdict.allowed);
    assert_eq!(
        verdict.reason.as_deref(),
        Some("crowdstrike blocked content")
    );
    let wire_request = received.await.expect("fixture task");
    assert!(wire_request.ends_with(
        r#"{"event_type":"output","guard_input":{"messages":[{"content":"fixture prompt","role":"user"}]}}"#
    ));

    for (status, body, delay, fail_open, expected_allowed) in [
        (200, r#"{}"#, Duration::ZERO, false, false),
        (
            200,
            r#"{"result":{"blocked":false}}"#,
            Duration::ZERO,
            true,
            true,
        ),
        (
            200,
            r#"{"result":{"blocked":"false","detectors":{}}}"#,
            Duration::ZERO,
            false,
            false,
        ),
        (
            200,
            r#"{"result":{"blocked":false,"detectors":{"unknown":true}}}"#,
            Duration::ZERO,
            true,
            true,
        ),
        (502, r#"{}"#, Duration::ZERO, false, false),
        (
            200,
            r#"{"result":{"blocked":false,"detectors":{}}}"#,
            Duration::from_millis(50),
            true,
            true,
        ),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        let verdict = check_external_guardrail(
            &crowdstrike_config(
                format!("{base_url}/aidr/aiguard/v1/guard_chat_completions"),
                fail_open,
                timeout_ms,
                None,
            ),
            request(GuardrailPhase::Input),
        )
        .await;
        assert_eq!(verdict.allowed, expected_allowed);
        let _ = received.await;
    }
}

#[tokio::test]
async fn pangea_input_and_output_contracts_select_recipes_and_normalize_scores() {
    for (phase, recipe) in [
        (GuardrailPhase::Input, "fixture-input-recipe"),
        (GuardrailPhase::Output, "fixture-output-recipe"),
    ] {
        let response = format!(
            r#"{{"status":"Success","result":{{"blocked":false,"detectors":{GUARDRAIL_DETECTORS}}}}}"#
        );
        let (base_url, received) =
            fixture_server(200, Box::leak(response.into_boxed_str()), Duration::ZERO).await;
        let verdict = check_external_guardrail(
            &pangea_config(format!("{base_url}/v1/text/guard"), false, 2_000),
            request(phase),
        )
        .await;

        assert!(verdict.allowed);
        assert_eq!(verdict.categories, ["prompt_injection"]);
        assert_eq!(verdict.scores.get("prompt_injection.pa4002"), Some(&0.99));
        let wire_request = received.await.expect("fixture task");
        assert!(wire_request.starts_with("POST /v1/text/guard HTTP/1.1\r\n"));
        assert!(wire_request.contains("authorization: Bearer fixture-key\r\n"));
        assert!(wire_request.ends_with(&format!(
            r#"{{"debug":true,"recipe":"{recipe}","text":"fixture prompt"}}"#
        )));
    }
}

#[tokio::test]
async fn pangea_block_malformed_unknown_non_finite_status_timeout_and_fail_modes_are_safe() {
    let blocked = format!(r#"{{"result":{{"blocked":true,"detectors":{GUARDRAIL_DETECTORS}}}}}"#);
    let (base_url, received) =
        fixture_server(200, Box::leak(blocked.into_boxed_str()), Duration::ZERO).await;
    let verdict = check_external_guardrail(
        &pangea_config(format!("{base_url}/v1/text/guard"), false, 2_000),
        request(GuardrailPhase::Input),
    )
    .await;
    assert!(!verdict.allowed);
    assert_eq!(verdict.reason.as_deref(), Some("pangea blocked content"));
    let _ = received.await;

    for (status, body, delay, fail_open, expected_allowed) in [
        (200, r#"{}"#, Duration::ZERO, false, false),
        (
            200,
            r#"{"result":{"blocked":false,"detectors":{}}}"#,
            Duration::ZERO,
            true,
            true,
        ),
        (
            200,
            r#"{"result":{"blocked":false,"detectors":{"prompt_injection":{"detected":true,"data":{"analyzer_responses":[{"analyzer":"PA","confidence":"bad"}]}}}}}"#,
            Duration::ZERO,
            false,
            false,
        ),
        (
            200,
            r#"{"result":{"blocked":false,"detectors":{"prompt_injection":{"detected":true,"data":{"analyzer_responses":[{"analyzer":"PA","confidence":2.0}]}}}}}"#,
            Duration::ZERO,
            true,
            true,
        ),
        (502, r#"{}"#, Duration::ZERO, false, false),
        (
            200,
            r#"{"result":{"blocked":false,"detectors":{}}}"#,
            Duration::from_millis(50),
            true,
            true,
        ),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        let verdict = check_external_guardrail(
            &pangea_config(format!("{base_url}/v1/text/guard"), fail_open, timeout_ms),
            request(GuardrailPhase::Output),
        )
        .await;
        assert_eq!(verdict.allowed, expected_allowed);
        let _ = received.await;
    }
}

#[tokio::test]
async fn azure_content_safety_contract_uses_subscription_key_and_eight_level_output() {
    let (base_url, received) = fixture_server(200, AZURE_ALL_CLEAR, Duration::ZERO).await;

    let verdict = check_external_guardrail(
        &azure_config(base_url, false, 2_000),
        request(GuardrailPhase::Input),
    )
    .await;

    assert!(verdict.allowed);
    let wire_request = received.await.expect("fixture task");
    assert!(wire_request
        .starts_with("POST /contentsafety/text:analyze?api-version=2024-09-01 HTTP/1.1\r\n"));
    assert!(wire_request.contains("ocp-apim-subscription-key: fixture-key\r\n"));
    assert!(
        wire_request.ends_with(r#"{"outputType":"EightSeverityLevels","text":"fixture prompt"}"#)
    );
}

#[tokio::test]
async fn azure_content_safety_blocks_severity_or_blocklist_match() {
    for body in [
        r#"{"categoriesAnalysis":[{"category":"Hate","severity":0},{"category":"SelfHarm","severity":0},{"category":"Sexual","severity":0},{"category":"Violence","severity":4}],"blocklistsMatch":[]}"#,
        r#"{"categoriesAnalysis":[{"category":"Hate","severity":0},{"category":"SelfHarm","severity":0},{"category":"Sexual","severity":0},{"category":"Violence","severity":0}],"blocklistsMatch":[{"blocklistName":"fixture","blocklistItemId":"item","blocklistItemText":"prompt"}]}"#,
    ] {
        let (base_url, received) = fixture_server(200, body, Duration::ZERO).await;
        let verdict = check_external_guardrail(
            &azure_config(base_url, false, 2_000),
            request(GuardrailPhase::Output),
        )
        .await;
        assert!(!verdict.allowed);
        assert_eq!(
            verdict.reason.as_deref(),
            Some("azure content safety blocked content")
        );
        let _ = received.await;
    }
}

#[tokio::test]
async fn azure_content_safety_rejects_empty_missing_and_duplicate_category_sets() {
    for (body, fail_open, expected_allowed, expected_reason) in [
        (
            r#"{"categoriesAnalysis":[],"blocklistsMatch":[]}"#,
            false,
            false,
            "external guardrail unavailable; fail-closed",
        ),
        (
            r#"{"categoriesAnalysis":[],"blocklistsMatch":[]}"#,
            true,
            true,
            "external guardrail unavailable; fail-open",
        ),
        (
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0},{"category":"SelfHarm","severity":0},{"category":"Sexual","severity":0}],"blocklistsMatch":[]}"#,
            false,
            false,
            "external guardrail unavailable; fail-closed",
        ),
        (
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0},{"category":"Hate","severity":0},{"category":"SelfHarm","severity":0},{"category":"Sexual","severity":0}],"blocklistsMatch":[]}"#,
            true,
            true,
            "external guardrail unavailable; fail-open",
        ),
    ] {
        let (base_url, received) = fixture_server(200, body, Duration::ZERO).await;
        let verdict = check_external_guardrail(
            &azure_config(base_url, fail_open, 2_000),
            request(GuardrailPhase::Input),
        )
        .await;
        assert_eq!(verdict.allowed, expected_allowed);
        assert_eq!(verdict.reason.as_deref(), Some(expected_reason));
        let _ = received.await;
    }
}

#[test]
fn azure_content_safety_threshold_defaults_to_four_and_is_bounded() {
    let default: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
        "name":"azure", "provider":"azure_content_safety", "url":"https://8.8.8.8",
        "mode":"pre_call", "api_key":"fixture-key"
    }))
    .expect("valid Azure configuration");
    let CompiledGuardrailProvider::AzureContentSafety(default) = default
        .validate()
        .expect("valid Azure configuration compiles")
    else {
        panic!("expected Azure configuration");
    };
    assert_eq!(default.severity_threshold, 4);
    for severity_threshold in [8, 255] {
        let config: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
            "name":"azure", "provider":"azure_content_safety", "url":"https://8.8.8.8",
            "mode":"pre_call", "api_key":"fixture-key", "severity_threshold":severity_threshold
        }))
        .expect("configuration deserializes before validation");
        assert!(config.validate().is_err());
    }
}

#[tokio::test]
async fn azure_content_safety_malformed_status_timeout_and_fail_modes_are_safe() {
    for (status, body, delay, fail_open, expected_allowed) in [
        (200, r#"{}"#, Duration::ZERO, false, false),
        (
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":1.5}],"blocklistsMatch":[]}"#,
            Duration::ZERO,
            true,
            true,
        ),
        (
            200,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":8}],"blocklistsMatch":[]}"#,
            Duration::ZERO,
            false,
            false,
        ),
        (
            200,
            r#"{"categoriesAnalysis":[{"category":"Unknown","severity":0}],"blocklistsMatch":[]}"#,
            Duration::ZERO,
            false,
            false,
        ),
        (
            200,
            r#"{"categoriesAnalysis":[],"blocklistsMatch":[{}]}"#,
            Duration::ZERO,
            true,
            true,
        ),
        (502, r#"{}"#, Duration::ZERO, false, false),
        (200, AZURE_ALL_CLEAR, Duration::from_millis(50), true, true),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        let verdict = check_external_guardrail(
            &azure_config(base_url, fail_open, timeout_ms),
            request(GuardrailPhase::Input),
        )
        .await;
        assert_eq!(verdict.allowed, expected_allowed);
        let _ = received.await;
    }
}

#[tokio::test]
async fn bedrock_guardrail_contract_uses_apply_guardrail_input_and_output_shapes() {
    for (phase, source) in [
        (GuardrailPhase::Input, "INPUT"),
        (GuardrailPhase::Output, "OUTPUT"),
    ] {
        let (base_url, received) =
            fixture_server(200, r#"{"action":"NONE"}"#, Duration::ZERO).await;
        let verdict =
            check_external_guardrail(&bedrock_config(base_url, false, 2_000), request(phase)).await;
        assert!(verdict.allowed);
        let wire_request = received.await.expect("fixture task");
        assert!(wire_request
            .starts_with("POST /guardrail/fixture-guardrail/version/1/apply HTTP/1.1\r\n"));
        assert!(wire_request.contains("authorization: Bearer fixture-key\r\n"));
        assert!(wire_request.ends_with(&format!(
            r#"{{"content":[{{"text":{{"text":"fixture prompt"}}}}],"source":"{source}"}}"#
        )));
    }
}

#[tokio::test]
async fn bedrock_guardrail_blocks_intervention_and_rejects_unknown_actions_safely() {
    let (base_url, received) = fixture_server(
        200,
        r#"{"action":"GUARDRAIL_INTERVENED","actionReason":"raw vendor detail"}"#,
        Duration::ZERO,
    )
    .await;
    let verdict = check_external_guardrail(
        &bedrock_config(base_url, false, 2_000),
        request(GuardrailPhase::Input),
    )
    .await;
    assert!(!verdict.allowed);
    assert_eq!(
        verdict.reason.as_deref(),
        Some("bedrock guardrail intervened")
    );
    let _ = received.await;

    for (status, body, delay, fail_open, expected_allowed) in [
        (200, r#"{}"#, Duration::ZERO, false, false),
        (200, r#"{"action":"UNKNOWN"}"#, Duration::ZERO, true, true),
        (200, r#"{"action":false}"#, Duration::ZERO, false, false),
        (502, r#"{}"#, Duration::ZERO, true, true),
        (
            200,
            r#"{"action":"NONE"}"#,
            Duration::from_millis(50),
            false,
            false,
        ),
    ] {
        let (base_url, received) = fixture_server(status, body, delay).await;
        let timeout_ms = if delay.is_zero() { 2_000 } else { 1 };
        let verdict = check_external_guardrail(
            &bedrock_config(base_url, fail_open, timeout_ms),
            request(GuardrailPhase::Input),
        )
        .await;
        assert_eq!(verdict.allowed, expected_allowed);
        let _ = received.await;
    }
}
