//! End-to-end coverage for bounded AI shadow evaluation (WOR-1973).

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use sbproxy_e2e::{CapturedRequest, MockUpstream, ProxyHarness};
use serde_json::{json, Value};

fn chat_reply(provider: &str, prompt_tokens: u64, completion_tokens: u64) -> Value {
    json!({
        "id": format!("chatcmpl-{provider}"),
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": provider},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
    })
}

fn shadow_config(primary_url: &str, shadow_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: "primary-key"
          base_url: "{primary_url}"
          allow_private_base_url: true
          no_prompt_training: true
          models: [gpt-4o]
        - name: shadow
          provider_type: openai
          api_key: "shadow-key"
          base_url: "{shadow_url}"
          allow_private_base_url: true
          enabled: false
          models: [gpt-4o]
      routing:
        strategy: round_robin
      shadow:
        provider: shadow
        sample_rate: 1.0
        timeout_ms: 30000
        task_timeout_ms: 30000
"#
    )
}

fn shadow_accounting_config(
    primary_url: &str,
    shadow_url: &str,
    usage_path: &std::path::Path,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      usage_sinks:
        - type: jsonl_file
          path: "{usage_path}"
      budget:
        on_exceed: block
        limits:
          - scope: workspace
            max_tokens: 10
      providers:
        - name: primary
          provider_type: openai
          api_key: "primary-key"
          base_url: "{primary_url}"
          allow_private_base_url: true
          models: [gpt-4o]
        - name: shadow
          provider_type: openai
          api_key: "shadow-key"
          base_url: "{shadow_url}"
          allow_private_base_url: true
          enabled: false
          models: [gpt-4o]
      routing:
        strategy: round_robin
      shadow:
        provider: shadow
        sample_rate: 1.0
        timeout_ms: 5000
        task_timeout_ms: 5000
"#,
        usage_path = usage_path.display(),
    )
}

fn governed_shadow_config(
    admin_port: u16,
    store_path: &Path,
    primary_url: &str,
    shadow_url: &str,
) -> String {
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
      path: "{store_path}"
    cache:
      ttl_secs: 60
    crypto:
      pepper: ai-shadow-e2e-pepper
      master_key: ai-shadow-e2e-master-key
    failure_mode_allow: false
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: primary
          provider_type: openai
          api_key: "primary-key"
          base_url: "{primary_url}"
          allow_private_base_url: true
          models: [gpt-4o]
        - name: shadow
          provider_type: openai
          api_key: "shadow-key"
          base_url: "{shadow_url}"
          allow_private_base_url: true
          enabled: false
          models: [gpt-4o]
      routing:
        strategy: round_robin
      shadow:
        provider: shadow
        sample_rate: 1.0
        timeout_ms: 5000
        task_timeout_ms: 5000
"#,
        store_path = store_path.display(),
    )
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral admin listener")
        .local_addr()
        .expect("admin listener address")
        .port()
}

fn mint_governed_token(admin_port: u16, policy: Value) -> String {
    let response = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{admin_port}/admin/keys"))
        .basic_auth("admin", Some("secret"))
        .json(&policy)
        .send()
        .expect("mint governed key");
    let status = response.status();
    let text = response.text().expect("mint response body");
    assert_eq!(status.as_u16(), 201, "mint governed key: {text}");
    serde_json::from_str::<Value>(&text).expect("mint response JSON")["token"]
        .as_str()
        .expect("one-time token")
        .to_string()
}

fn wait_for_usage_rows(path: &std::path::Path, count: usize) -> Vec<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let rows = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect::<Vec<_>>();
        if rows.len() >= count {
            return rows;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expected {count} usage rows, found {}: {rows:?}",
            rows.len()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct BlockingShadow {
    port: u16,
    captured: Receiver<CapturedRequest>,
    release: Sender<()>,
    join: Option<JoinHandle<()>>,
}

impl BlockingShadow {
    fn start(reply: Value) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let (captured_tx, captured) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let reply = serde_json::to_vec(&reply)?;
        let join = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(request) = read_request(&mut stream) else {
                return;
            };
            if captured_tx.send(request).is_err() {
                return;
            }
            if release_rx.recv().is_err() {
                return;
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&reply);
            let _ = stream.flush();
        });
        Ok(Self {
            port,
            captured,
            release,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for BlockingShadow {
    fn drop(&mut self) {
        let _ = self.release.send(());
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset;
        }
    };

    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    let mut headers = HashMap::new();
    let mut content_length = 0_usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or_default();
            }
            headers.insert(name, value);
        }
    }

    let body_start = header_end + 4;
    let mut body = bytes[body_start..].to_vec();
    while body.len() < content_length {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..count]);
    }
    body.truncate(content_length);
    Ok(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

#[test]
fn copied_shadow_request_cannot_delay_the_primary_response() {
    let primary = MockUpstream::start(chat_reply("primary", 1, 1)).expect("primary upstream");
    let shadow =
        BlockingShadow::start(chat_reply("shadow", 2, 3)).expect("blocking shadow upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&shadow_config(&primary.base_url(), &shadow.base_url()))
            .expect("proxy");
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "compare this"}]
    });

    let proxy_url = proxy.base_url();
    let request_for_thread = request.clone();
    let (primary_tx, primary_rx) = mpsc::channel();
    let request_thread = std::thread::spawn(move || {
        let response = reqwest::blocking::Client::new()
            .post(format!("{proxy_url}/v1/chat/completions"))
            .header("host", "ai.localhost")
            .json(&request_for_thread)
            .send()
            .and_then(|response| {
                let status = response.status().as_u16();
                response.bytes().map(|body| (status, body))
            });
        let _ = primary_tx.send(response);
    });

    let copied = shadow
        .captured
        .recv_timeout(Duration::from_secs(5))
        .expect("configured shadow target must receive a copied request");
    assert_eq!(copied.method, "POST");
    assert_eq!(copied.path, "/v1/chat/completions");
    assert_eq!(
        copied.headers.get("x-sbproxy-shadow").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&copied.body).expect("shadow JSON"),
        request
    );

    let primary_response = primary_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("primary must finish while the shadow response remains blocked")
        .expect("primary HTTP response");
    assert_eq!(primary_response.0, 200);

    shadow.release.send(()).expect("release shadow response");
    request_thread.join().expect("request thread");
}

#[test]
fn shadow_usage_is_separate_and_never_debits_primary_budget() {
    let primary = MockUpstream::start(chat_reply("primary", 1, 1)).expect("primary upstream");
    let shadow = MockUpstream::start(chat_reply("shadow", 1_000, 1_000)).expect("shadow upstream");
    let temp = tempfile::tempdir().expect("usage workspace");
    let usage_path = temp.path().join("usage.jsonl");
    let proxy = ProxyHarness::start_with_yaml(&shadow_accounting_config(
        &primary.base_url(),
        &shadow.base_url(),
        &usage_path,
    ))
    .expect("proxy");
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "account independently"}]
    });

    let first = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &request, &[])
        .expect("first primary response");
    assert_eq!(first.status, 200);
    let rows = wait_for_usage_rows(&usage_path, 2);
    let primary_row = rows
        .iter()
        .find(|row| row["provider"] == "primary")
        .expect("primary usage row");
    let shadow_row = rows
        .iter()
        .find(|row| row["provider"] == "shadow")
        .expect("shadow usage row");

    assert_eq!(primary_row["total_tokens"], 2);
    assert_ne!(primary_row["tag"], "shadow");
    assert_eq!(shadow_row["total_tokens"], 2_000);
    assert_eq!(shadow_row["tag"], "shadow");
    assert!(
        primary_row["cost_usd"]
            .as_f64()
            .is_some_and(|cost| cost > 0.0),
        "primary usage must retain priced spend"
    );
    assert!(
        shadow_row["cost_usd"]
            .as_f64()
            .is_some_and(|cost| cost > 0.0),
        "shadow usage must estimate its spend independently"
    );
    assert_ne!(
        primary_row["request_id"], shadow_row["request_id"],
        "primary and shadow ledger identities must never deduplicate each other"
    );
    assert!(
        shadow_row["request_id"]
            .as_str()
            .is_some_and(|request_id| request_id.ends_with(":shadow")),
        "shadow rows need a generated, collision-free request id"
    );

    // The 2,000-token shadow result is already recorded. If it touched the
    // primary workspace budget, this second primary request would return 402.
    let second = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &request, &[])
        .expect("second primary response");
    assert_eq!(
        second.status, 200,
        "shadow spend must not consume or reject the primary budget"
    );
}

#[test]
fn streaming_requests_are_not_shadowed() {
    let primary = MockUpstream::start(chat_reply("primary", 1, 1)).expect("primary upstream");
    let shadow = MockUpstream::start(chat_reply("shadow", 2, 2)).expect("shadow upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&shadow_config(&primary.base_url(), &shadow.base_url()))
            .expect("proxy");
    let request = json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "stream this"}]
    });

    let response = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &request, &[])
        .expect("streaming primary response");
    assert_eq!(response.status, 200);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(primary.captured().len(), 1);
    assert_eq!(
        shadow.captured().len(),
        0,
        "streaming requests are intentionally excluded from shadow dispatch"
    );
}

#[test]
fn mutating_ai_surfaces_are_not_shadowed() {
    let primary = MockUpstream::start(chat_reply("primary", 1, 1)).expect("primary upstream");
    let shadow = MockUpstream::start(chat_reply("shadow", 2, 2)).expect("shadow upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&shadow_config(&primary.base_url(), &shadow.base_url()))
            .expect("proxy");
    let request = json!({
        "model": "gpt-4o",
        "name": "do not duplicate this assistant"
    });

    let response = proxy
        .post_json("/v1/assistants", "ai.localhost", &request, &[])
        .expect("primary assistants response");
    assert_eq!(response.status, 200);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(primary.captured().len(), 1);
    assert_eq!(
        shadow.captured().len(),
        0,
        "shadow eval v1 must never replay mutating AI APIs"
    );
}

#[test]
fn prompt_training_opt_out_suppresses_only_the_shadow() {
    let primary = MockUpstream::start(chat_reply("primary", 1, 1)).expect("primary upstream");
    let shadow = MockUpstream::start(chat_reply("shadow", 2, 2)).expect("shadow upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&shadow_config(&primary.base_url(), &shadow.base_url()))
            .expect("proxy");
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "do not train on this"}]
    });

    let response = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &request,
            &[("x-sbproxy-disallow-prompt-training", "true")],
        )
        .expect("primary response");
    assert_eq!(response.status, 200);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(primary.captured().len(), 1);
    assert_eq!(
        shadow.captured().len(),
        0,
        "prompt-training opt-out must fail closed for a non-compliant shadow"
    );
}

#[test]
fn governed_provider_policy_suppresses_only_the_shadow() {
    let primary = MockUpstream::start(chat_reply("primary", 1, 1)).expect("primary upstream");
    let shadow = MockUpstream::start(chat_reply("shadow", 2, 2)).expect("shadow upstream");
    let temp = tempfile::tempdir().expect("governed key workspace");
    let admin_port = pick_port();
    let config = governed_shadow_config(
        admin_port,
        &temp.path().join("keys.redb"),
        &primary.base_url(),
        &shadow.base_url(),
    );
    let proxy =
        ProxyHarness::start_with_workspace(&config, &[]).expect("start governed shadow proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin listener ready");
    let primary_only = mint_governed_token(
        admin_port,
        json!({"name": "primary-only", "allowed_providers": ["primary"]}),
    );
    let shadow_blocked = mint_governed_token(
        admin_port,
        json!({"name": "shadow-blocked", "blocked_providers": ["shadow"]}),
    );
    let request = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "govern this copy"}]
    });

    for token in [primary_only, shadow_blocked] {
        let authorization = format!("Bearer {token}");
        let response = proxy
            .post_json(
                "/v1/chat/completions",
                "ai.localhost",
                &request,
                &[("authorization", authorization.as_str())],
            )
            .expect("governed primary response");
        assert_eq!(response.status, 200);
    }

    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(primary.captured().len(), 2);
    assert_eq!(
        shadow.captured().len(),
        0,
        "both credential allowlists and blocklists must constrain shadow dispatch"
    );
}
