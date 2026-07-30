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
