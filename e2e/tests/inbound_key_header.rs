//! End-to-end drills for minted keys presented in an arbitrary inbound header.
//!
//! These exercise the real request path, which the unit tests cannot: the sweep
//! runs pre-auth, policies run before the upstream filter, and the strip and
//! credential injection happen in `upstream_request_filter`. Several of the
//! behaviours here fail *silently* when broken (a key that stops governing, a
//! secret that reaches an origin), so each one asserts on what the upstream
//! actually received rather than on a status code alone.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

/// Headers the stub upstream saw, lowercased.
#[derive(Debug, Default, Clone)]
struct SeenHeaders {
    headers: Vec<(String, String)>,
}

impl SeenHeaders {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    fn contains_value(&self, needle: &str) -> bool {
        self.headers.iter().any(|(_, value)| value.contains(needle))
    }
}

/// A one-shot upstream that records the request it was given and answers 200.
struct StubUpstream {
    port: u16,
    seen: mpsc::Receiver<SeenHeaders>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl StubUpstream {
    fn start() -> anyhow::Result<Self> {
        Self::start_failing_first(0)
    }

    /// Answer a retryable 503 to the first `failures` requests, then 200.
    ///
    /// Used to prove the bound credential is re-injected on a retry. Pingora
    /// re-runs `upstream_request_filter` for each attempt, which is why the
    /// injection lives there; a first-attempt-only assertion would still pass
    /// if someone moved it into `request_filter`, where the retry would reach
    /// the origin with no credential at all.
    fn start_failing_first(failures: usize) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let (tx, seen) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let mut served = 0_usize;
        let join = std::thread::spawn(move || {
            // Serve until dropped so a retry lands on the same stub. The stop
            // flag is checked after every accept: `Drop` sets it and then makes
            // one throwaway connection purely to wake this blocking accept, and
            // without the check the loop would go straight back to accept and
            // the join would never return.
            while let Ok((mut stream, _)) = listener.accept() {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(seen) = read_headers(&mut stream) else {
                    continue;
                };
                let _ = tx.send(seen);
                let retryable = served < failures;
                served += 1;
                let body: &[u8] = if retryable {
                    b"{\"retry\":true}"
                } else {
                    b"{\"ok\":true}"
                };
                let status = if retryable {
                    "503 Service Unavailable"
                } else {
                    "200 OK"
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });
        Ok(Self {
            port,
            seen,
            stop,
            join: Some(join),
        })
    }

    fn next_request(&self) -> SeenHeaders {
        self.seen
            .recv_timeout(Duration::from_secs(10))
            .expect("the upstream received a request")
    }

    fn assert_no_request(&self, reason: &str) {
        assert!(
            self.seen.recv_timeout(Duration::from_millis(250)).is_err(),
            "{reason}"
        );
    }
}

impl Drop for StubUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept so the thread observes the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_headers(stream: &mut TcpStream) -> std::io::Result<SeenHeaders> {
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
        if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break offset;
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut headers = Vec::new();
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok(SeenHeaders { headers })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral listener")
        .local_addr()
        .expect("listener address")
        .port()
}

/// Config with the key sweep on and a plain proxy origin at the stub.
fn config(admin_port: u16, upstream_port: u16, extra_origin: &str) -> String {
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
      path: /tmp/sbproxy-e2e-inbound-key-{admin_port}.redb
    crypto:
      pepper: e2e-pepper-value-not-a-real-secret
      master_key: e2e-master-value-not-a-real-secret
    inbound:
      headers:
        - name: authorization
          scheme: "Bearer "
        - name: x-api-key
          scheme: ""
        - name: x-sb-api
          scheme: ""
      require: false
      native_key_policy:
        allowed_providers:
          - anthropic
          - openai

origins:
  tools.local:
    action:
      type: proxy
      url: http://127.0.0.1:{upstream_port}
{extra_origin}
"#
    )
}

fn mint(admin_port: u16, body: serde_json::Value) -> String {
    let response = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{admin_port}/admin/keys"))
        .basic_auth("admin", Some("secret"))
        .json(&body)
        .send()
        .expect("mint request");
    let status = response.status().as_u16();
    let text = response.text().unwrap_or_default();
    assert_eq!(status, 201, "mint refused: {text}");
    serde_json::from_str::<serde_json::Value>(&text)
        .unwrap_or_else(|e| panic!("mint response is json: {e}: {text}"))["token"]
        .as_str()
        .unwrap_or_else(|| panic!("mint response carries a token: {text}"))
        .to_string()
}

fn create_credential(admin_port: u16, body: serde_json::Value) -> u16 {
    reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{admin_port}/admin/credentials"))
        .basic_auth("admin", Some("secret"))
        .json(&body)
        .send()
        .expect("credential request")
        .status()
        .as_u16()
}

#[test]
fn the_key_header_is_consumed_and_never_reaches_the_upstream() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let token = mint(admin_port, serde_json::json!({"name": "sdk"}));

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", &token)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert!(
        !seen.has("x-api-key"),
        "the proxy's own key must not reach the origin: {seen:?}"
    );
}

#[test]
fn a_sidecar_key_leaves_the_callers_own_credential_untouched() {
    // The governance-without-custody shape: the tool keeps sending its real
    // upstream secret and the minted key rides alongside.
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let token = mint(admin_port, serde_json::json!({"name": "sidecar"}));

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("authorization", "Bearer the-callers-own-upstream-secret")
        .header("x-sb-api", &token)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("authorization"),
        Some("Bearer the-callers-own-upstream-secret"),
        "a pass-through credential must survive untouched"
    );
    assert!(
        !seen.has("x-sb-api"),
        "the minted key is consumed: {seen:?}"
    );
}

#[test]
fn a_bound_credential_replaces_the_key_on_the_same_header() {
    // Substitution: the tool sends a minted key in the header it already uses,
    // and the origin sees its own real secret there instead.
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    assert_eq!(
        create_credential(
            admin_port,
            serde_json::json!({
                "id": "anthropic-prod",
                "secret": "the-real-upstream-secret",
                "header": "x-api-key",
                "scheme": ""
            })
        ),
        201
    );
    let token = mint(
        admin_port,
        serde_json::json!({"name": "bound", "credential_id": "anthropic-prod"}),
    );

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", &token)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("x-api-key"),
        Some("the-real-upstream-secret"),
        "the bound credential replaces the minted key: {seen:?}"
    );
}

#[test]
fn two_conflicting_tokens_are_refused_rather_than_silently_resolved() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let first = mint(admin_port, serde_json::json!({"name": "a"}));
    let second = mint(admin_port, serde_json::json!({"name": "b"}));

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", &first)
        .header("x-sb-api", &second)
        .send()
        .expect("proxied request");
    assert_eq!(
        response.status().as_u16(),
        400,
        "configuration order must not decide which key governs"
    );
}

#[test]
fn a_callers_own_provider_key_still_reaches_the_upstream() {
    // The parallel-operation guarantee. A tool presenting its real Anthropic
    // key must not collect a 401 from us just because key management is on.
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", "sk-ant-api03-not-one-of-ours")
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("x-api-key"),
        Some("sk-ant-api03-not-one-of-ours"),
        "a key that is not ours passes through untouched: {seen:?}"
    );
}

#[test]
fn a_generic_native_key_is_not_replaced_by_an_origin_credential() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let yaml = config(admin_port, upstream.port, "").replace(
        &format!("      url: http://127.0.0.1:{}", upstream.port),
        &format!(
            r#"      url: http://127.0.0.1:{}
    outbound_credential:
      type: vault_secret
      secret: operator-secret-must-not-replace-native
      header: x-api-key
      scheme: """#,
            upstream.port
        ),
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", "sk-ant-api03-caller-owned")
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("x-api-key"),
        Some("sk-ant-api03-caller-owned"),
        "generic pass-through must preserve the caller-owned native credential: {seen:?}"
    );
}

#[test]
fn native_provider_shape_does_not_bypass_configured_origin_auth() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let yaml = config(admin_port, upstream.port, "").replace(
        &format!("      url: http://127.0.0.1:{}", upstream.port),
        &format!(
            r#"      url: http://127.0.0.1:{}
    authentication:
      type: basic_auth
      users:
        - username: admin
          password: s3cret"#,
            upstream.port
        ),
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", "sk-ant-api03-caller-owned")
        .send()
        .expect("proxy response");
    assert_eq!(
        response.status().as_u16(),
        401,
        "provider-key shape is attribution, not proof of origin identity"
    );
    upstream.assert_no_request("configured origin auth must still fail closed");
}

#[test]
fn a_native_provider_key_is_refused_without_an_operator_policy() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let yaml = config(admin_port, upstream.port, "").replace(
        "      native_key_policy:\n        allowed_providers:\n          - anthropic\n          - openai\n",
        "",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", "sk-ant-api03-caller-owned")
        .send()
        .expect("proxy response");

    assert_eq!(response.status().as_u16(), 403);
    assert!(
        upstream
            .seen
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "a native key without a resolvable policy must fail before upstream dispatch"
    );
}

#[test]
fn a_native_provider_key_is_refused_when_its_provider_is_not_allowed() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("api-key", "caller-owned-azure-key")
        .send()
        .expect("proxy response");

    assert_eq!(response.status().as_u16(), 403);
    assert!(
        upstream
            .seen
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "a provider outside the native-key allowlist must fail before upstream dispatch"
    );
}

#[test]
fn an_ai_route_uses_the_callers_native_key_instead_of_the_operator_key() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let ai_origin = format!(
        r#"  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          accept_native_credentials_for: openai
          api_key: operator-key-must-not-be-billed
          base_url: http://127.0.0.1:{}
          allow_private_base_url: true
          models: [gpt-test]
"#,
        upstream.port
    );
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, &ai_origin))
        .expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .post(format!("{}/v1/chat/completions", harness.base_url()))
        .header("Host", "ai.local")
        .header("authorization", "Bearer sk-caller-owned-ai")
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .expect("AI proxy response");
    assert_eq!(response.status().as_u16(), 200);

    let seen = upstream.next_request();
    assert_eq!(
        seen.get("authorization"),
        Some("Bearer sk-caller-owned-ai"),
        "the caller owns the native provider key and must remain the billed upstream identity"
    );
    assert!(
        !seen
            .get("authorization")
            .is_some_and(|value| value.contains("operator-key")),
        "the operator credential must never silently replace a caller-owned native key"
    );
}

#[test]
fn an_unbound_custom_ai_destination_never_receives_a_callers_native_key() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let ai_origin = format!(
        r#"  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: custom-openai-wire
          provider_type: openai
          api_key: operator-key
          base_url: http://127.0.0.1:{}
          allow_private_base_url: true
          models: [gpt-test]
"#,
        upstream.port
    );
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, &ai_origin))
        .expect("proxy starts");

    let response = native_ai_request(&harness, "gpt-test");
    assert_eq!(response.status().as_u16(), 403);
    assert!(
        upstream
            .seen
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "wire format and a custom base URL must not authorize caller-secret forwarding"
    );
}

fn native_ai_request(harness: &ProxyHarness, model: &str) -> reqwest::blocking::Response {
    reqwest::blocking::Client::new()
        .post(format!("{}/v1/chat/completions", harness.base_url()))
        .header("Host", "ai.local")
        .header("authorization", "Bearer sk-caller-owned-ai")
        .json(&serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .expect("AI proxy response")
}

fn openai_origin(upstream_port: u16, action_extra: &str) -> String {
    format!(
        r#"  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          accept_native_credentials_for: openai
          api_key: operator-key-must-not-be-billed
          base_url: http://127.0.0.1:{upstream_port}
          allow_private_base_url: true
          models: [gpt-test]
{action_extra}
"#
    )
}

fn add_native_policy_fields(yaml: String, fields: &str) -> String {
    yaml.replace(
        "          - openai\n",
        &format!("          - openai\n{fields}"),
    )
}

fn without_native_key_policy(yaml: String) -> String {
    yaml.replace(
        "      native_key_policy:\n        allowed_providers:\n          - anthropic\n          - openai\n",
        "",
    )
}

fn legacy_token_from_minted(token: &str) -> String {
    let rest = token
        .strip_prefix("sbp_")
        .expect("admin minted canonical token");
    let (key_id, secret) = rest.split_once('_').expect("canonical token separator");
    format!("sk-{key_id}-{secret}")
}

fn ai_request_with_bearer(
    harness: &ProxyHarness,
    bearer: &str,
    model: &str,
) -> reqwest::blocking::Response {
    reqwest::blocking::Client::new()
        .post(format!("{}/v1/chat/completions", harness.base_url()))
        .header("Host", "ai.local")
        .header("authorization", format!("Bearer {bearer}"))
        .json(&serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .expect("AI proxy response")
}

fn ai_request_with_credential_header(
    harness: &ProxyHarness,
    header: &str,
    value: &str,
    model: &str,
) -> reqwest::blocking::Response {
    reqwest::blocking::Client::new()
        .post(format!("{}/v1/chat/completions", harness.base_url()))
        .header("Host", "ai.local")
        .header(header, value)
        .json(&serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .expect("AI proxy response")
}

#[test]
fn stored_legacy_key_beats_native_hint_with_policy_absent_or_permissive() {
    for native_policy_present in [false, true] {
        let upstream = StubUpstream::start().expect("stub upstream");
        let admin_port = free_port();
        let mut yaml = config(admin_port, upstream.port, &openai_origin(upstream.port, ""));
        if !native_policy_present {
            yaml = without_native_key_policy(yaml);
        }
        let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");
        let minted = mint(
            admin_port,
            serde_json::json!({
                "name": "stored-legacy",
                "allowed_models": ["gpt-test"]
            }),
        );
        let legacy = legacy_token_from_minted(&minted);

        let response = ai_request_with_bearer(&harness, &legacy, "gpt-test");
        assert_eq!(
            response.status().as_u16(),
            200,
            "stored legacy resolution must precede native admission"
        );
        let seen = upstream.next_request();
        assert_eq!(
            seen.get("authorization"),
            Some("Bearer operator-key-must-not-be-billed"),
            "the stored key governs the request while the configured provider credential is used"
        );
        assert!(
            !seen
                .get("authorization")
                .is_some_and(|value| value.contains(&legacy)),
            "the caller's legacy virtual-key secret must not reach the provider"
        );
    }
}

#[test]
fn wrong_or_unknown_legacy_keys_deny_before_native_fallback() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let harness = ProxyHarness::start_with_yaml(&config(
        admin_port,
        upstream.port,
        &openai_origin(upstream.port, ""),
    ))
    .expect("proxy starts");
    let minted = mint(admin_port, serde_json::json!({"name": "known-legacy"}));
    let legacy = legacy_token_from_minted(&minted);
    let (known_id, _) = legacy
        .strip_prefix("sk-")
        .and_then(|rest| rest.split_once('-'))
        .expect("legacy token parts");
    let attempts = [
        format!("sk-{known_id}-{}", "0".repeat(64)),
        format!("sk-{}-{}", "f".repeat(16), "e".repeat(64)),
    ];

    for attempt in attempts {
        assert_eq!(
            ai_request_with_bearer(&harness, &attempt, "gpt-test")
                .status()
                .as_u16(),
            401,
            "a conforming legacy virtual-key attempt must never degrade to native traffic"
        );
    }
    upstream.assert_no_request("invalid legacy virtual keys must fail before provider dispatch");
}

#[test]
fn minted_denials_emit_secret_free_mode_metrics_and_audit() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let yaml = format!(
        "{}\nobservability:\n  log:\n    sinks:\n      - name: stdout\n        format: json\n        profile: internal\n  metrics:\n    enabled: true\n",
        config(admin_port, upstream.port, "")
    );
    let harness =
        ProxyHarness::start_with_workspace(&yaml, &[]).expect("proxy with captured logs starts");
    let denied_token = format!("sbp_{}_{}", "f".repeat(16), "deadbeef".repeat(8));
    assert_eq!(denied_token.len(), 4 + 16 + 1 + 64);

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/denied", harness.base_url()))
        .header("Host", "tools.local")
        .header("authorization", format!("Bearer {denied_token}"))
        .send()
        .expect("denied response");
    assert_eq!(response.status().as_u16(), 401);
    upstream.assert_no_request("an unknown minted key must not reach the origin");

    std::thread::sleep(Duration::from_millis(100));
    let metrics = harness
        .get("/metrics", "tools.local")
        .expect("metrics response")
        .text()
        .expect("metrics UTF-8");
    assert!(
        metrics.contains(
            "sbproxy_inbound_key_requests_total{api_key_id=\"\",key_mode=\"minted\",provider=\"\""
        ),
        "denied minted attempts must retain minted mode without provider attribution: {metrics}"
    );
    let logs = harness.stdout_contents();
    assert!(logs.contains("\"event_type\":\"auth_denied\""), "{logs}");
    assert!(logs.contains("\"key_mode\":\"minted\""), "{logs}");
    assert!(
        !logs.contains("\"key_provider\":"),
        "minted denials must not invent provider attribution: {logs}"
    );
    assert!(
        !logs.contains(&denied_token),
        "audit leaked the bearer secret"
    );
    assert!(
        !metrics.contains(&denied_token),
        "metrics leaked the bearer secret"
    );
}

#[test]
fn wildcard_access_logs_exclude_custom_native_provider_carriers() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let yaml = config(admin_port, upstream.port, "")
        .replace(
            "      require: false\n",
            "      require: false\n      provider_hints:\n        - provider: custom\n          header: x-opaque-native-carrier\n          value_prefix: opaque-\n",
        )
        .replace(
            "          - openai\n",
            "          - openai\n          - custom\n",
        );
    let yaml = format!(
        "{yaml}\naccess_log:\n  enabled: true\n  capture_headers:\n    request: [\"*\"]\nobservability:\n  log:\n    sinks:\n      - name: stdout\n        format: json\n        profile: internal\n"
    );
    let harness =
        ProxyHarness::start_with_workspace(&yaml, &[]).expect("proxy with captured logs starts");
    let canary = "opaque-caller-secret-canary";

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/native", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-opaque-native-carrier", canary)
        .send()
        .expect("native request");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        upstream.next_request().get("x-opaque-native-carrier"),
        Some(canary),
        "generic proxying preserves caller-owned provider credentials"
    );

    std::thread::sleep(Duration::from_millis(100));
    let logs = harness.stdout_contents();
    assert!(logs.contains("request_headers"), "{logs}");
    assert!(
        !logs.contains(canary),
        "wildcard header capture leaked the custom native credential: {logs}"
    );
}

fn openai_origin_with_configured_key(upstream_port: u16) -> String {
    format!(
        r#"  ai.local:
    credentials:
      - name: documented-configured-key
        type: ai_provider
        provider: openai
        key: sk-your-virtual-key
        models:
          allow: [gpt-configured]
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: operator-configured-provider-key
          base_url: http://127.0.0.1:{upstream_port}
          allow_private_base_url: true
          models: [gpt-configured, gpt-test]
"#
    )
}

#[test]
fn exact_configured_ai_provider_key_beats_native_hint_without_forwarding_the_secret() {
    for native_policy_present in [false, true] {
        for (header, value) in [
            ("authorization", "Bearer sk-your-virtual-key"),
            ("x-api-key", "sk-your-virtual-key"),
            ("x-sb-api", "sk-your-virtual-key"),
        ] {
            let upstream = StubUpstream::start().expect("stub upstream");
            let admin_port = free_port();
            let mut yaml = config(
                admin_port,
                upstream.port,
                &openai_origin_with_configured_key(upstream.port),
            );
            if !native_policy_present {
                yaml = without_native_key_policy(yaml);
            }
            let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

            let response =
                ai_request_with_credential_header(&harness, header, value, "gpt-configured");
            assert_eq!(
                response.status().as_u16(),
                200,
                "exact configured credentials on {header} must resolve before native admission"
            );
            let seen = upstream.next_request();
            assert_eq!(
                seen.get("authorization"),
                Some("Bearer operator-configured-provider-key")
            );
            assert!(
                !seen.contains_value("sk-your-virtual-key"),
                "the configured caller secret from {header} must not be forwarded"
            );
            assert_eq!(
                ai_request_with_credential_header(&harness, header, value, "gpt-test")
                    .status()
                    .as_u16(),
                403,
                "configured governance from {header} must be applied, not merely authenticated"
            );
            upstream.assert_no_request(
                "a model denied by the configured credential must not reach the provider",
            );
        }
    }
}

#[test]
fn genuine_openai_project_key_falls_through_to_native_governance() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let harness = ProxyHarness::start_with_yaml(&config(
        admin_port,
        upstream.port,
        &openai_origin(upstream.port, ""),
    ))
    .expect("proxy starts");
    let native = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";

    assert_eq!(
        ai_request_with_bearer(&harness, native, "gpt-test")
            .status()
            .as_u16(),
        200
    );
    let seen = upstream.next_request();
    let expected_authorization = format!("Bearer {native}");
    assert_eq!(
        seen.get("authorization"),
        Some(expected_authorization.as_str()),
        "a genuine provider key must remain caller-owned native traffic"
    );
}

#[test]
fn native_policy_enforces_model_and_pii_requirements_before_dispatch() {
    let upstream = StubUpstream::start().expect("stub upstream");

    let model_admin = free_port();
    let model_yaml = add_native_policy_fields(
        config(
            model_admin,
            upstream.port,
            &openai_origin(upstream.port, ""),
        ),
        "        allowed_models: [gpt-allowed]\n",
    );
    let model_harness = ProxyHarness::start_with_yaml(&model_yaml).expect("model proxy starts");
    assert_eq!(
        native_ai_request(&model_harness, "gpt-test")
            .status()
            .as_u16(),
        403
    );
    upstream.assert_no_request("native model denial must happen before dispatch");
    drop(model_harness);

    let pii_admin = free_port();
    let pii_yaml = add_native_policy_fields(
        config(pii_admin, upstream.port, &openai_origin(upstream.port, "")),
        "        require_pii_redaction: [email]\n",
    );
    let pii_harness = ProxyHarness::start_with_yaml(&pii_yaml).expect("PII proxy starts");
    assert_eq!(
        native_ai_request(&pii_harness, "gpt-test")
            .status()
            .as_u16(),
        500
    );
    upstream.assert_no_request("missing required PII redaction must fail before dispatch");
}

#[test]
fn native_policy_enforces_rate_and_budget_limits() {
    let rate_upstream = StubUpstream::start().expect("rate upstream");
    let rate_admin = free_port();
    let rate_yaml = add_native_policy_fields(
        config(
            rate_admin,
            rate_upstream.port,
            &openai_origin(rate_upstream.port, ""),
        ),
        "        max_requests_per_minute: 1\n",
    );
    let rate_harness = ProxyHarness::start_with_yaml(&rate_yaml).expect("rate proxy starts");
    assert_eq!(
        native_ai_request(&rate_harness, "gpt-test")
            .status()
            .as_u16(),
        200
    );
    let _ = rate_upstream.next_request();
    assert_eq!(
        native_ai_request(&rate_harness, "gpt-test")
            .status()
            .as_u16(),
        429
    );
    rate_upstream.assert_no_request("exhausted native RPM must block the second dispatch");

    let budget_upstream = StubUpstream::start().expect("budget upstream");
    let budget_admin = free_port();
    let budget_yaml = add_native_policy_fields(
        config(
            budget_admin,
            budget_upstream.port,
            &openai_origin(budget_upstream.port, ""),
        ),
        "        max_budget_tokens: 0\n",
    );
    let budget_harness = ProxyHarness::start_with_yaml(&budget_yaml).expect("budget proxy starts");
    assert_eq!(
        native_ai_request(&budget_harness, "gpt-test")
            .status()
            .as_u16(),
        402
    );
    budget_upstream.assert_no_request("exhausted native token budget must block dispatch");
}

#[test]
fn model_limiter_shares_resolved_identity_across_native_carriers_without_leaking_secrets() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let model = "gpt-model-limiter-carrier-regression";
    let action_extra =
        format!("      model_rate_limits:\n        {model}:\n          requests_per_minute: 1\n");
    let origin = openai_origin(upstream.port, &action_extra)
        .replace("models: [gpt-test]", &format!("models: [{model}]"));
    let yaml = config(admin_port, upstream.port, &origin)
        .replace(
            "      require: false\n",
            "      require: false\n      provider_hints:\n        - provider: openai\n          header: authorization\n          scheme: \"Bearer \"\n          value_prefix: \"sk-\"\n        - provider: openai\n          header: x-opaque-native-carrier\n          value_prefix: \"opaque-\"\n",
        );
    let yaml = format!("{yaml}\nobservability:\n  metrics:\n    enabled: true\n");
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

    assert_eq!(native_ai_request(&harness, model).status().as_u16(), 200);
    let _ = upstream.next_request();

    let canary = "opaque-caller-secret-canary";
    let response = reqwest::blocking::Client::new()
        .post(format!("{}/v1/chat/completions", harness.base_url()))
        .header("Host", "ai.local")
        .header("x-opaque-native-carrier", canary)
        .json(&serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .expect("AI proxy response");
    assert_eq!(
        response.status().as_u16(),
        429,
        "one resolved native identity must share its model bucket across carriers"
    );
    upstream.assert_no_request("the shared model RPM bucket must block the second dispatch");

    let metrics = harness
        .get("/metrics", "tools.local")
        .expect("metrics response")
        .text()
        .expect("metrics UTF-8");
    assert!(
        metrics.contains("sbproxy_ai_ratelimit_rejected_total"),
        "{metrics}"
    );
    assert!(
        metrics.contains("native:") && metrics.contains(":ai.local:openai"),
        "the rendered metric must expose only the immutable native key id: {metrics}"
    );
    assert!(
        !metrics.contains(canary),
        "metrics leaked {canary}: {metrics}"
    );
    assert!(
        !metrics.contains("sk-caller-owned-ai"),
        "metrics leaked the authorization credential: {metrics}"
    );
}

#[test]
fn native_policy_enforces_rpm_on_generic_proxy_traffic() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let yaml = add_native_policy_fields(
        config(admin_port, upstream.port, ""),
        "        max_requests_per_minute: 2\n",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");
    let client = reqwest::blocking::Client::new();
    let send = || {
        client
            .get(format!("{}/resource", harness.base_url()))
            .header("Host", "tools.local")
            .header(
                "authorization",
                "Bearer sk-proj-generic-native-rate-test-0123456789",
            )
            .send()
            .expect("generic proxy response")
    };

    assert_eq!(send().status().as_u16(), 200);
    let _ = upstream.next_request();
    assert_eq!(
        send().status().as_u16(),
        200,
        "max_rpm=2 must admit two requests; native RPM may be charged only once per request"
    );
    let _ = upstream.next_request();
    assert_eq!(
        send().status().as_u16(),
        429,
        "native RPM must govern generic proxy traffic as well as AI traffic"
    );
    upstream.assert_no_request("exhausted native RPM must block generic dispatch");
}

#[test]
fn native_model_policy_fails_closed_on_method_aware_requests() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let yaml = add_native_policy_fields(
        config(admin_port, upstream.port, &openai_origin(upstream.port, "")),
        "        allowed_models: [gpt-allowed]\n",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");
    let client = reqwest::blocking::Client::new();
    let native = "Bearer sk-proj-method-policy-test-0123456789";

    let blocked_model = client
        .put(format!("{}/v1/fine_tuning/jobs/job-1", harness.base_url()))
        .header("Host", "ai.local")
        .header("authorization", native)
        .json(&serde_json::json!({"model": "gpt-denied", "metadata": {"owner": "team"}}))
        .send()
        .expect("method-aware response");
    assert_eq!(
        blocked_model.status().as_u16(),
        403,
        "an interpretable PUT model must be checked against native policy"
    );

    let missing_model = client
        .delete(format!("{}/v1/files/file-1", harness.base_url()))
        .header("Host", "ai.local")
        .header("authorization", native)
        .send()
        .expect("method-aware response");
    assert_eq!(
        missing_model.status().as_u16(),
        403,
        "a method with no interpretable model must fail closed when model policy is required"
    );

    let missing_get_model = client
        .get(format!("{}/v1/files/file-1", harness.base_url()))
        .header("Host", "ai.local")
        .header("authorization", native)
        .send()
        .expect("GET method-aware response");
    assert_eq!(
        missing_get_model.status().as_u16(),
        403,
        "a forwarded GET must fail closed when credential model policy cannot be interpreted"
    );
    upstream.assert_no_request("native method policy denials must happen before dispatch");
}

#[test]
fn native_required_pii_redaction_fails_closed_for_multipart() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let action_extra = r#"      pii:
        enabled: true
        defaults: true
        redact_request: true
"#;
    let yaml = add_native_policy_fields(
        config(
            admin_port,
            upstream.port,
            &openai_origin(upstream.port, action_extra),
        ),
        "        require_pii_redaction: [email]\n",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");
    let boundary = "sbproxy-native-pii";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-test\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"alice@example.com.wav\"\r\nContent-Type: audio/wav\r\n\r\nfixture\r\n--{boundary}--\r\n"
    );

    let response = reqwest::blocking::Client::new()
        .post(format!("{}/v1/audio/transcriptions", harness.base_url()))
        .header("Host", "ai.local")
        .header(
            "authorization",
            "Bearer sk-proj-multipart-pii-test-0123456789",
        )
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .expect("multipart response");
    assert_eq!(
        response.status().as_u16(),
        403,
        "required PII policy must not claim multipart redaction it cannot perform"
    );
    upstream.assert_no_request("unsupported required multipart PII must fail before dispatch");
}

#[test]
fn native_keys_fail_closed_for_confidence_cascade() {
    let upstream = StubUpstream::start().expect("stub upstream");
    let admin_port = free_port();
    let action_extra = r#"      routing:
        strategy: cascade
        tiers:
          - provider_id: openai
            model: gpt-test
            quality_threshold: 0.8
"#;
    let yaml = config(
        admin_port,
        upstream.port,
        &openai_origin(upstream.port, action_extra),
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("cascade proxy starts");

    assert_eq!(
        native_ai_request(&harness, "gpt-test").status().as_u16(),
        503
    );
    upstream.assert_no_request("native confidence cascade must fail before dispatch");
}

#[test]
fn native_keys_suppress_shadow_copies_without_affecting_primary() {
    let primary = StubUpstream::start().expect("primary upstream");
    let shadow = StubUpstream::start().expect("shadow upstream");
    let admin_port = free_port();
    let ai_origin = format!(
        r#"  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          accept_native_credentials_for: openai
          api_key: operator-primary-key
          base_url: http://127.0.0.1:{}
          allow_private_base_url: true
          models: [gpt-test]
        - name: shadow
          provider_type: openai
          api_key: operator-shadow-key
          base_url: http://127.0.0.1:{}
          allow_private_base_url: true
          enabled: false
          models: [gpt-test]
      routing:
        strategy: round_robin
      shadow:
        provider: shadow
        sample_rate: 1.0
        timeout_ms: 5000
        task_timeout_ms: 5000
"#,
        primary.port, shadow.port
    );
    let yaml = config(admin_port, primary.port, &ai_origin);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("shadow proxy starts");

    assert_eq!(
        native_ai_request(&harness, "gpt-test").status().as_u16(),
        200
    );
    let seen = primary.next_request();
    assert_eq!(seen.get("authorization"), Some("Bearer sk-caller-owned-ai"));
    shadow.assert_no_request("native caller credentials must never be copied to a shadow");
}

#[test]
fn an_ai_route_refuses_a_native_key_for_a_different_provider() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let ai_origin = format!(
        r#"  ai.local:
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: operator-key-must-not-be-billed
          base_url: http://127.0.0.1:{}
          allow_private_base_url: true
          models: [gpt-test]
"#,
        upstream.port
    );
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, &ai_origin))
        .expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .post(format!("{}/v1/chat/completions", harness.base_url()))
        .header("Host", "ai.local")
        .header("authorization", "Bearer sk-caller-owned-ai")
        .json(&serde_json::json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .expect("AI proxy response");

    assert_eq!(response.status().as_u16(), 403);
    assert!(
        upstream
            .seen
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "provider mismatch must fail before an operator credential can be dispatched"
    );
}

#[test]
fn an_unknown_minted_key_is_refused() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let harness = ProxyHarness::start_with_yaml(&config(admin_port, upstream.port, ""))
        .expect("proxy starts");

    let unknown = format!("sbp_{}_{}", "f".repeat(16), "e".repeat(64));
    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", unknown)
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 401);
}

#[test]
fn requiring_a_key_refuses_a_request_that_carries_none() {
    let admin_port = free_port();
    let upstream = StubUpstream::start().expect("stub upstream");
    let yaml = config(admin_port, upstream.port, "")
        .replace("      require: false", "      require: true");
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .send()
        .expect("proxied request");
    assert_eq!(response.status().as_u16(), 401);
}

#[test]
fn a_bound_credential_is_re_injected_on_an_upstream_retry() {
    // Pingora re-runs `upstream_request_filter` for each attempt, which is
    // why the credential injection lives there rather than in
    // `request_filter`. Asserting only on the first attempt would still pass
    // if someone moved it earlier, and the retry would then reach the origin
    // carrying no credential at all.
    let admin_port = free_port();
    let upstream = StubUpstream::start_failing_first(1).expect("stub upstream");
    let yaml = config(admin_port, upstream.port, "").replace(
        "      url: http://127.0.0.1:",
        "      retry:\n        max_attempts: 2\n        retry_on: [503]\n        backoff_ms: 0\n      url: http://127.0.0.1:",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy starts");

    assert_eq!(
        create_credential(
            admin_port,
            serde_json::json!({
                "id": "retry-cred",
                "secret": "the-real-upstream-secret",
                "header": "x-api-key",
                "scheme": ""
            })
        ),
        201
    );
    let token = mint(
        admin_port,
        serde_json::json!({"name": "retried", "credential_id": "retry-cred"}),
    );

    let response = reqwest::blocking::Client::new()
        .get(format!("{}/anything", harness.base_url()))
        .header("Host", "tools.local")
        .header("x-api-key", &token)
        .send()
        .expect("proxied request");
    assert_eq!(
        response.status().as_u16(),
        200,
        "the retry should have succeeded"
    );

    let first = upstream.next_request();
    assert_eq!(
        first.get("x-api-key"),
        Some("the-real-upstream-secret"),
        "first attempt carries the bound credential: {first:?}"
    );

    let retried = upstream.next_request();
    assert_eq!(
        retried.get("x-api-key"),
        Some("the-real-upstream-secret"),
        "the RETRY must carry it too, not just the first attempt: {retried:?}"
    );
    assert!(
        !retried
            .get("x-api-key")
            .is_some_and(|v| v.starts_with("sbp_")),
        "and it must be the credential, never the caller's minted key"
    );
}
