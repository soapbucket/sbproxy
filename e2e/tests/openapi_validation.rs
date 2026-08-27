//! OpenAPI 3.0 schema validation policy (F1.2).
//!
//! Spins up the proxy in front of a mock upstream and confirms that
//! valid bodies pass through, invalid bodies are rejected with the
//! configured status, out-of-scope routes are forwarded unchanged,
//! and `mode: log` warns instead of blocking.
//!
//! Half of this file runs against `MockUpstream`, which is plaintext
//! HTTP/1.1, and half against a loopback HTTPS upstream that
//! negotiates h2. The split is the point (WOR-2687). `tune_peer` sets
//! `ALPN::H2H1` on every peer, so h2 is what any `https://` backend
//! that offers it actually gets, and pingora handles a body-filter
//! error differently on the two protocols: the h1 loop propagates it
//! to `fail_to_proxy`, the h2 loop logs `Upstream h2 body send error`
//! and forwards the upstream response anyway. Every test in this file
//! was green against the h1 mock while the documented refusal did not
//! hold on the default configuration, which is why the h2 upstream is
//! here rather than a second h1 one.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use tokio::sync::Mutex;

fn enforce_yaml(upstream: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{upstream}"
    policies:
      - type: openapi_validation
        mode: enforce
        status: 422
        spec:
          openapi: "3.0.3"
          info: {{title: t, version: "1"}}
          paths:
            "/users/{{id}}":
              post:
                requestBody:
                  required: true
                  content:
                    application/json:
                      schema:
                        type: object
                        required: [name]
                        additionalProperties: false
                        properties:
                          name: {{type: string, minLength: 1}}
                          age:  {{type: integer, minimum: 0, maximum: 150}}
"#
    )
}

fn log_yaml(upstream: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{upstream}"
    policies:
      - type: openapi_validation
        mode: log
        spec:
          openapi: "3.0.3"
          info: {{title: t, version: "1"}}
          paths:
            "/users/{{id}}":
              post:
                requestBody:
                  required: true
                  content:
                    application/json:
                      schema:
                        type: object
                        required: [name]
                        properties:
                          name: {{type: string}}
"#
    )
}

#[test]
fn valid_body_passes_through() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json(
            "/users/42",
            "api.localhost",
            &json!({"name": "alice", "age": 30}),
            &[],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "upstream should see exactly one request");
}

#[test]
fn missing_required_field_is_rejected() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json("/users/42", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");
    assert_eq!(resp.status, 422);
    let text = resp.text().expect("utf-8");
    assert!(
        text.contains("openapi validation failed"),
        "expected validation error body, got: {text}"
    );
    // The proxy connects to the upstream before validation finishes,
    // so the upstream may see the request line + headers. What we
    // care about is that the rejected body is not forwarded.
    let captured = upstream.captured();
    if let Some(req) = captured.first() {
        assert!(
            req.body.is_empty() || !std::str::from_utf8(&req.body).unwrap_or("").contains("age"),
            "rejected body must not be forwarded upstream, got: {:?}",
            std::str::from_utf8(&req.body).unwrap_or("<bytes>")
        );
    }
}

// WOR-2687: the header-phase policy dispatcher runs before the body
// is buffered, so `OpenApiValidationEnforcer::enforce` always returns
// `Allow` there (see `builtin_enforcers::openapi_validation`) and the
// bus used to get a `policy_verdict_event` saying "allow" for this
// policy_id before the request body had even arrived. That was the
// only record this request's `openapi_validation` decision ever got,
// regardless of the 422 the client received. The phase that actually
// decides now publishes the verdict, and the header phase publishes
// nothing for this policy, so a refused request leaves one record and
// it says "deny".
#[test]
fn missing_required_field_publishes_a_deny_verdict() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json("/users/42", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");
    assert_eq!(resp.status, 422);

    // The audit bus drains asynchronously (see
    // `sbproxy_core::policy_bus::drain_to_stderr`), so the record can
    // land a beat after the HTTP response does. Poll on the deny
    // itself rather than on a line count: a count assertion would pin
    // whatever number of records the implementation happens to emit
    // today as required behavior, and the count changed here once
    // already.
    let openapi_line = |line: &str| {
        line.contains("policy_verdict_event")
            && line.contains("\"policy_id\":\"openapi_validation\"")
    };
    let stderr = stderr_until(&harness, |line| {
        openapi_line(line) && line.contains("\"verdict\":\"deny\"")
    });

    let lines: Vec<&str> = stderr.lines().filter(|line| openapi_line(line)).collect();
    assert_eq!(
        lines.len(),
        1,
        "one decision gets one record, got {} line(s): {lines:?}",
        lines.len()
    );
    assert!(
        lines[0].contains("\"verdict\":\"deny\""),
        "the openapi_validation record for a rejected request must report \"deny\", \
         got: {}\nfull stderr: {stderr}",
        lines[0]
    );
}

#[test]
fn additional_property_is_rejected() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json(
            "/users/42",
            "api.localhost",
            &json!({"name": "alice", "rogue": "field"}),
            &[],
        )
        .expect("send");
    assert_eq!(resp.status, 422);
}

#[test]
fn out_of_scope_path_passes() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json(
            "/widgets/42",
            "api.localhost",
            &json!({"anything": "goes"}),
            &[],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn log_mode_does_not_block_invalid_bodies() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&log_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json("/users/42", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert_eq!(
        captured.len(),
        1,
        "log mode must forward invalid bodies upstream"
    );
}

// --- WOR-2687: the same refusals against an h2 upstream ---

/// What the mock upstream recorded about the requests it answered.
#[derive(Default)]
struct H2State {
    /// HTTP version of every request head that reached the upstream.
    ///
    /// The assertion that makes these tests mean anything: if the
    /// proxy fell back to HTTP/1.1 the leak this file exists to catch
    /// cannot happen, and a green run would be proving nothing.
    versions: Mutex<Vec<String>>,
}

/// A loopback HTTPS upstream that negotiates h2 and answers **without
/// reading the request body**.
///
/// That last part is the whole repro. `request_body_filter` refuses the
/// body, so the request stream is never completed; a backend that waits
/// for the body would simply hang and the leak would never appear. The
/// backend in the original report (`httpbin.org`) answered 404 off the
/// request head alone, which is ordinary behavior for a router that
/// does not recognize the path, and that answer is what reached the
/// client in place of the configured refusal.
struct H2Upstream {
    addr: SocketAddr,
    state: Arc<H2State>,
    /// The private CA the proxy is pointed at with `SSL_CERT_FILE`.
    ///
    /// pingora builds its upstream rustls root store from
    /// `rustls_native_certs::load_native_certs`, which reads
    /// `SSL_CERT_FILE` when it is set instead of the platform store. It
    /// is the only seam this workspace has for making the proxy trust a
    /// test certificate on an upstream hop: nothing in the origin
    /// schema disables upstream certificate verification, and it should
    /// stay that way.
    ca_file: tempfile::NamedTempFile,
}

impl H2Upstream {
    fn base_url(&self) -> String {
        format!("https://{}", self.addr)
    }

    fn ca_path(&self) -> String {
        self.ca_file.path().to_string_lossy().into_owned()
    }

    /// The request versions the upstream recorded, polled until the
    /// upstream has actually logged one.
    ///
    /// The client's response can land before the upstream's handler
    /// finishes recording, so reading this straight after the request
    /// races the mock rather than the proxy.
    fn observed_versions(&self, runtime: &tokio::runtime::Runtime) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = runtime.block_on(async { self.state.versions.lock().await.clone() });
            if !seen.is_empty() || Instant::now() >= deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Tokio runtime for the mock. The TLS accept loop has to keep making
/// progress while the test thread blocks in the synchronous harness.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// Answer immediately, off the request head, without touching the body.
async fn answer_without_reading_body(
    State(state): State<Arc<H2State>>,
    req: Request,
) -> impl IntoResponse {
    state
        .versions
        .lock()
        .await
        .push(format!("{:?}", req.version()));
    (
        StatusCode::OK,
        Json(json!({"upstream": "answered without reading the request body"})),
    )
}

/// Start the HTTPS/2 upstream on `127.0.0.1:0` behind a fresh private
/// CA whose leaf carries an IP SAN for the loopback address.
async fn spawn_h2_upstream() -> H2Upstream {
    use std::io::Write as _;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let state = Arc::new(H2State::default());
    let app = Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .fallback(answer_without_reading_body)
        .with_state(state.clone());

    let ca_key = KeyPair::generate().expect("generate test CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "sbproxy openapi h2 test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign test CA");

    let leaf_key = KeyPair::generate().expect("generate TLS key");
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "sbproxy openapi h2 test upstream");
    leaf_params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign TLS certificate");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // `RustlsConfig::from_pem` advertises `h2` ahead of `http/1.1`, and
    // axum-server serves the connection through hyper's auto builder,
    // so an ALPN-negotiated h2 connection is served as h2.
    let tls_config = RustlsConfig::from_pem(
        leaf_cert.pem().into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("rustls config");
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls_config)
            .serve(app.into_make_service())
            .await;
    });

    let root_pem = ca_cert.pem();
    let mut ca_file = tempfile::NamedTempFile::new().expect("ca tempfile");
    ca_file
        .write_all(root_pem.as_bytes())
        .expect("write test CA");
    ca_file.flush().expect("flush test CA");

    let root = reqwest::Certificate::from_pem(root_pem.as_bytes()).expect("parse test CA");
    let probe = reqwest::Client::builder()
        .add_root_certificate(root)
        .build()
        .expect("readiness client");
    let health_url = format!("https://{addr}/healthz");
    let mut ready = false;
    for _ in 0..200 {
        if probe
            .get(&health_url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready, "HTTPS/2 mock upstream did not become ready");

    H2Upstream {
        addr,
        state,
        ca_file,
    }
}

fn request_validator_yaml(upstream: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{upstream}"
    policies:
      - type: request_validator
        content_types:
          - application/json
        status: 400
        error_content_type: application/json
        schema:
          type: object
          required:
            - name
          properties:
            name: {{type: string, minLength: 1}}
          additionalProperties: false
"#
    )
}

/// Poll the proxy's stderr until `matches` finds a line, or the
/// deadline passes. The audit bus drains asynchronously
/// (`policy_bus::drain_to_stderr`), so a record can land a beat after
/// the HTTP response.
fn stderr_until(harness: &ProxyHarness, matches: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let stderr = harness.stderr_contents();
        if stderr.lines().any(&matches) || Instant::now() >= deadline {
            return stderr;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// WOR-2687, the ticket's own repro: a schema-violating body against an
/// h2 upstream must answer with the configured status, not with the
/// upstream's answer to a request the proxy refused.
///
/// Red before the fix. `request_body_filter` returns `Err`, pingora's
/// h2 loop logs `Upstream h2 body send error` and continues, and the
/// mock's 200 is filtered and written downstream, so the assertion on
/// `422` sees `200` and the malformed body has been admitted.
#[test]
fn h2_upstream_missing_required_field_is_rejected() {
    let runtime = rt();
    let upstream = runtime.block_on(spawn_h2_upstream());
    let ca_path = upstream.ca_path();
    let harness = ProxyHarness::start_with_yaml_and_env(
        &enforce_yaml(&upstream.base_url()),
        &[("SSL_CERT_FILE", ca_path.as_str())],
    )
    .expect("start proxy");

    let resp = harness
        .post_json("/users/42", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");

    let versions = upstream.observed_versions(&runtime);
    assert!(
        !versions.is_empty(),
        "the upstream never saw the request head, so this test proves nothing about h2"
    );
    assert!(
        versions.iter().all(|version| version == "HTTP/2.0"),
        "this test only means something over h2, got {versions:?}"
    );

    assert_eq!(
        resp.status,
        422,
        "the client must get the policy's configured status, not the upstream's answer \
         to a body the proxy refused to forward; body: {}",
        resp.text().unwrap_or_default()
    );
    let text = resp.text().expect("utf-8");
    assert!(
        text.contains("openapi validation failed"),
        "expected the configured rejection body, got: {text}"
    );
    assert!(
        !text.contains("answered without reading the request body"),
        "the upstream's own response body reached the client: {text}"
    );
}

/// WOR-2687: and the audit trail for that request says `deny`, exactly
/// once.
///
/// Two failures met on this policy. The header-phase dispatcher
/// published an `allow` before the body existed, and the body phase
/// published nothing, so the only record of a refused request said
/// "allow". The header-phase record is now suppressed for this policy
/// (`emits_own_verdict_in_body_phase`) and the phase that decides
/// publishes instead, so the count is asserted as well as the verdict:
/// one decision, one record.
#[test]
fn h2_upstream_rejection_publishes_exactly_one_deny_verdict() {
    let runtime = rt();
    let upstream = runtime.block_on(spawn_h2_upstream());
    let ca_path = upstream.ca_path();
    let harness = ProxyHarness::start_with_yaml_and_env(
        &enforce_yaml(&upstream.base_url()),
        &[("SSL_CERT_FILE", ca_path.as_str())],
    )
    .expect("start proxy");

    let resp = harness
        .post_json("/users/42", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");
    assert_eq!(resp.status, 422);

    let openapi_line = |line: &str| {
        line.contains("policy_verdict_event")
            && line.contains("\"policy_id\":\"openapi_validation\"")
    };
    let stderr = stderr_until(&harness, openapi_line);
    let lines: Vec<&str> = stderr.lines().filter(|line| openapi_line(line)).collect();
    assert_eq!(
        lines.len(),
        1,
        "one decision gets one record: a second row keyed on the same \
         (request_id, policy_id) makes the natural SIEM query for \"which requests did \
         openapi_validation admit\" match every request it denied. Got: {lines:?}"
    );
    assert!(
        lines[0].contains("\"verdict\":\"deny\""),
        "the record for a refused request must say deny, got: {}",
        lines[0]
    );
}

/// WOR-2687: the sibling policies share the failure and share the fix.
///
/// `request_validator`, `content_digest`, `body_threat_protection`,
/// `prompt_injection_v2`'s body scan and the A2A push-notification
/// check all refuse through the same `validator_failed` slot and the
/// same `Err` return, so all of them leaked against an h2 upstream and
/// all of them are covered by the one guard in `response_filter`. This
/// is `request_validator` standing for the class.
#[test]
fn h2_upstream_request_validator_is_also_enforced() {
    let runtime = rt();
    let upstream = runtime.block_on(spawn_h2_upstream());
    let ca_path = upstream.ca_path();
    let harness = ProxyHarness::start_with_yaml_and_env(
        &request_validator_yaml(&upstream.base_url()),
        &[("SSL_CERT_FILE", ca_path.as_str())],
    )
    .expect("start proxy");

    let resp = harness
        .post_json("/anything", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");

    let versions = upstream.observed_versions(&runtime);
    assert!(
        !versions.is_empty(),
        "the upstream never saw the request head, so this test proves nothing about h2"
    );
    assert!(
        versions.iter().all(|version| version == "HTTP/2.0"),
        "this test only means something over h2, got {versions:?}"
    );
    assert_eq!(
        resp.status,
        400,
        "request_validator's configured status, not the upstream's answer; body: {}",
        resp.text().unwrap_or_default()
    );
    let text = resp.text().expect("utf-8");
    assert!(
        !text.contains("answered without reading the request body"),
        "the upstream's own response body reached the client: {text}"
    );
}

/// WOR-2687: a body the schema accepts still reaches the h2 upstream
/// and still gets the upstream's answer.
///
/// The guard reads `validator_failed`, which is only ever set by a
/// phase that has already refused the request, so an admitted request
/// must be untouched by it. Without this, a guard that fired on the
/// wrong condition would turn every h2 origin into a 422 machine and
/// the three tests above would not notice.
#[test]
fn h2_upstream_valid_body_still_reaches_the_upstream() {
    let runtime = rt();
    let upstream = runtime.block_on(spawn_h2_upstream());
    let ca_path = upstream.ca_path();
    let harness = ProxyHarness::start_with_yaml_and_env(
        &enforce_yaml(&upstream.base_url()),
        &[("SSL_CERT_FILE", ca_path.as_str())],
    )
    .expect("start proxy");

    let resp = harness
        .post_json(
            "/users/42",
            "api.localhost",
            &json!({"name": "alice", "age": 30}),
            &[],
        )
        .expect("send");

    let versions = upstream.observed_versions(&runtime);
    assert!(
        !versions.is_empty(),
        "the upstream never saw the request head, so this test proves nothing about h2"
    );
    assert!(
        versions.iter().all(|version| version == "HTTP/2.0"),
        "this test only means something over h2, got {versions:?}"
    );
    assert_eq!(resp.status, 200, "a valid body is proxied normally");
    let text = resp.text().expect("utf-8");
    assert!(
        text.contains("answered without reading the request body"),
        "the client gets the upstream's own response: {text}"
    );
}
