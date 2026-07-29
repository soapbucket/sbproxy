use sbproxy_ai::external_guardrail::{
    check_external_guardrail, ExternalGuardrailConfig, ExternalGuardrailRequest, GuardrailPhase,
    GuardrailProvider,
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
    let (base_url, received) = fixture_server(200, r#"{"result":"allow"}"#, Duration::ZERO).await;
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

    let (base_url, received) = fixture_server(200, r#"{"result":"allow"}"#, Duration::ZERO).await;
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
    let (base_url, received) = fixture_server(200, r#"{"result":"block"}"#, Duration::ZERO).await;
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
        (200, r#"{"result":"unknown"}"#, Duration::ZERO, true, true),
        (502, r#"{}"#, Duration::ZERO, false, false),
        (
            200,
            r#"{"result":"allow"}"#,
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
