//! WOR-2096: opt-in deep capture of redacted prompt/response samples.
//!
//! The gate is two-sided: the AI origin must set `capture_content: true`
//! AND the governed key's policy must set `allow_content_capture`. Both
//! sides of the matrix that leave one flag off must produce no sample.
//! A retained sample is redacted (a planted provider token never
//! survives) and every read is audited with the operator's name.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

/// A minimal OpenAI-shaped chat upstream: answers every request with a
/// fixed chat completion so output capture has text to retain.
struct ChatStub {
    port: u16,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ChatStub {
    fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let body = serde_json::json!({
                "id": "chatcmpl-e2e",
                "object": "chat.completion",
                "model": "gpt-test",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello from the stub"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 7, "completion_tokens": 4, "total_tokens": 11}
            })
            .to_string();
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        // Drain the request enough to answer politely.
                        let mut buf = [0u8; 8192];
                        let _ = stream.read(&mut buf);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stop,
            join: Some(join),
        })
    }
}

impl Drop for ChatStub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral listener")
        .local_addr()
        .expect("listener address")
        .port()
}

fn config(
    admin_port: u16,
    upstream_port: u16,
    capture_content: bool,
    key_store_path: &Path,
) -> String {
    let key_store_path = serde_json::to_string(&key_store_path.display().to_string())
        .expect("serialize key store path as a YAML string");
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  key_management:
    enabled: true
    store:
      backend: embedded
      path: {key_store_path}
    crypto:
      pepper: e2e-pepper-value-not-a-real-secret
      master_key: e2e-master-value-not-a-real-secret
    inbound:
      headers:
        - name: x-sb-api
          scheme: ""
      require: false

origins:
  ai.local:
    action:
      type: ai_proxy
      capture_content: {capture_content}
      providers:
        - name: stub-openai
          provider_type: openai
          api_key: operator-key
          base_url: http://127.0.0.1:{upstream_port}
          allow_private_base_url: true
          models: [gpt-test]
"#
    )
}

fn mint_key(admin_port: u16, allow_content_capture: bool) -> (String, String) {
    let response = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{admin_port}/admin/keys"))
        .basic_auth("admin", Some("secret"))
        .json(&serde_json::json!({
            "name": "capture-matrix",
            "allow_content_capture": allow_content_capture,
        }))
        .send()
        .expect("mint request")
        .json::<serde_json::Value>()
        .expect("mint response json");
    (
        response["token"].as_str().expect("token").to_string(),
        response["key"]["key_id"]
            .as_str()
            .expect("key id")
            .to_string(),
    )
}

fn chat(harness: &ProxyHarness, token: &str, prompt: &str) -> u16 {
    reqwest::blocking::Client::new()
        .post(format!("{}/v1/chat/completions", harness.base_url()))
        .header("Host", "ai.local")
        .header("x-sb-api", token)
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": prompt}]
        }))
        .send()
        .expect("chat response")
        .status()
        .as_u16()
}

fn ring_request_id(admin_port: u16, key_id: &str) -> Option<String> {
    for _ in 0..50 {
        let rows = reqwest::blocking::Client::new()
            .get(format!(
                "http://127.0.0.1:{admin_port}/api/requests?api_key_id={key_id}"
            ))
            .basic_auth("admin", Some("secret"))
            .send()
            .expect("ring query")
            .json::<Vec<serde_json::Value>>()
            .expect("ring rows");
        if let Some(request_id) = rows
            .first()
            .and_then(|row| row["request_id"].as_str())
            .map(str::to_string)
        {
            return Some(request_id);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn fetch_content(admin_port: u16, request_id: &str) -> (u16, serde_json::Value) {
    let response = reqwest::blocking::Client::new()
        .get(format!(
            "http://127.0.0.1:{admin_port}/api/requests/{request_id}/content"
        ))
        .basic_auth("admin", Some("secret"))
        .send()
        .expect("content fetch");
    let status = response.status().as_u16();
    let body = response
        .json::<serde_json::Value>()
        .unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[test]
fn both_gates_on_captures_a_redacted_sample_and_audits_the_read() {
    let admin_port = free_port();
    let state = tempfile::tempdir().expect("isolated content-capture key store");
    let stub = ChatStub::start().expect("chat stub");
    let harness = ProxyHarness::start_with_yaml(&config(
        admin_port,
        stub.port,
        true,
        &state.path().join("keys.redb"),
    ))
    .expect("proxy starts");
    harness
        .wait_for_secondary_port(admin_port, Duration::from_secs(5))
        .expect("admin listener starts");

    let (token, key_id) = mint_key(admin_port, true);
    let planted = "please use sk-ant-api03-planted-e2e-secret-0123456789abcdef for auth";
    assert_eq!(chat(&harness, &token, planted), 200);

    let request_id = ring_request_id(admin_port, &key_id).expect("attributed ring row");
    let (status, sample) = fetch_content(admin_port, &request_id);
    assert_eq!(status, 200, "sample retrievable: {sample}");
    assert_eq!(sample["api_key_id"], key_id.as_str());
    let serialized = sample.to_string();
    assert!(
        !serialized.contains("sk-ant-api03-planted"),
        "a planted provider token must never survive into a sample: {serialized}"
    );
    assert!(
        serialized.contains("please use"),
        "the non-secret prompt text is retained: {serialized}"
    );
    assert_eq!(
        sample["output_text"], "Hello from the stub",
        "the redacted response text rides the same sample: {sample}"
    );

    // The read itself is on the audit sample, naming the operator.
    let audits = reqwest::blocking::Client::new()
        .get(format!(
            "http://127.0.0.1:{admin_port}/api/audit/events?channel=admin&kind=inspect_request_content"
        ))
        .basic_auth("admin", Some("secret"))
        .send()
        .expect("audit query")
        .json::<Vec<serde_json::Value>>()
        .expect("audit rows");
    assert!(
        audits.iter().any(|event| {
            event["actor"] == "admin" && event["request_id"] == request_id.as_str()
        }),
        "content inspection must be audited: {audits:?}"
    );
}

#[test]
fn a_key_without_consent_produces_no_sample_even_when_the_origin_opts_in() {
    let admin_port = free_port();
    let state = tempfile::tempdir().expect("isolated content-capture key store");
    let stub = ChatStub::start().expect("chat stub");
    let harness = ProxyHarness::start_with_yaml(&config(
        admin_port,
        stub.port,
        true,
        &state.path().join("keys.redb"),
    ))
    .expect("proxy starts");
    harness
        .wait_for_secondary_port(admin_port, Duration::from_secs(5))
        .expect("admin listener starts");

    let (token, key_id) = mint_key(admin_port, false);
    assert_eq!(chat(&harness, &token, "no consent from this key"), 200);

    let request_id = ring_request_id(admin_port, &key_id).expect("attributed ring row");
    let (status, _) = fetch_content(admin_port, &request_id);
    assert_eq!(status, 404, "no key consent, no sample");
}

#[test]
fn an_origin_without_the_flag_produces_no_sample_even_when_the_key_consents() {
    let admin_port = free_port();
    let state = tempfile::tempdir().expect("isolated content-capture key store");
    let stub = ChatStub::start().expect("chat stub");
    let harness = ProxyHarness::start_with_yaml(&config(
        admin_port,
        stub.port,
        false,
        &state.path().join("keys.redb"),
    ))
    .expect("proxy starts");
    harness
        .wait_for_secondary_port(admin_port, Duration::from_secs(5))
        .expect("admin listener starts");

    let (token, key_id) = mint_key(admin_port, true);
    assert_eq!(chat(&harness, &token, "origin never opted in"), 200);

    let request_id = ring_request_id(admin_port, &key_id).expect("attributed ring row");
    let (status, _) = fetch_content(admin_port, &request_id);
    assert_eq!(status, 404, "no origin flag, no sample");
}
