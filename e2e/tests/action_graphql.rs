//! End-to-end coverage for the `graphql` action.
//!
//! The `graphql` action proxies a GraphQL POST body to an upstream
//! HTTP endpoint. We stand up a [`MockUpstream`] that returns a
//! canned `{ "data": { "hello": "world" } }` response and verify
//! the client sees the same payload after the proxy round-trip.

use base64::Engine as _;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn get_with_body(
    proxy: &ProxyHarness,
    path: &str,
    host: &str,
    body: Vec<u8>,
) -> anyhow::Result<u16> {
    Ok(reqwest::blocking::Client::new()
        .request(
            reqwest::Method::GET,
            format!("{}{}", proxy.base_url(), path),
        )
        .header("host", host)
        .header("content-type", "application/json")
        .body(body)
        .send()?
        .status()
        .as_u16())
}

fn pick_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral loopback port")
        .local_addr()
        .expect("read ephemeral loopback port")
        .port()
}

struct RedisGuard {
    child: Child,
    port: u16,
}

impl RedisGuard {
    fn spawn() -> Option<Self> {
        let port = pick_loopback_port();
        let child = match Command::new("redis-server")
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("spawn redis-server: {error}"),
        };
        let guard = Self { child, port };
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(guard);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("redis-server did not accept connections on port {port}");
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.port)
    }
}

impl Drop for RedisGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn post_admin_reload(admin_port: u16) -> (u16, String) {
    let credentials = base64::engine::general_purpose::STANDARD.encode("admin:secret");
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build admin client")
        .post(format!("http://127.0.0.1:{admin_port}/admin/reload"))
        .header("authorization", format!("Basic {credentials}"))
        .send()
        .expect("reload proxy");
    (
        response.status().as_u16(),
        response.text().unwrap_or_default(),
    )
}

fn graphql_reload_config(
    admin_port: u16,
    redis_url: &str,
    upstream_url: &str,
    strict: bool,
) -> String {
    let validation = if strict {
        r#"
      validate_queries: true
      allow_introspection: false
      max_depth: 1"#
    } else {
        ""
    };
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  l2_cache:
    driver: redis
    params:
      dsn: "{redis_url}"
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{upstream_url}/graphql"{validation}
    idempotency:
      enabled: true
      header_name: Idempotency-Key
      ttl_secs: 60
      methods: [POST]
      backend: redis
"#
    )
}

fn sha256_digest_header(body: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    let raw = Sha256::digest(body);
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    format!("sha-256=:{encoded}:")
}

fn wait_for_access_log_bytes(path: &Path, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        if contents.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .is_some_and(|row| {
                    row["origin"] == "gql.localhost" && row["bytes_in"].as_u64() == Some(expected)
                })
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "access log never recorded {expected} authoritative request bytes; got: {contents}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn graphql_content_digest_config(
    upstream_url: &str,
    access_log_path: &Path,
    replacement_source: &str,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
access_log:
  enabled: true
  sample_rate: 1.0
  status_codes: [200]
  methods: [POST]
  output:
    type: file
    path: "{}"
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{upstream_url}/graphql"
      validate_queries: true
      allow_introspection: false
    request_modifiers:
      - body:
          replace_json:
            query: "{{safeName{{id}}}}"
            source: {replacement_source}
    policies:
      - type: content_digest
      - type: request_validator
        status: 422
        content_types:
          - application/json
        schema:
          type: object
          required:
            - query
            - source
          properties:
            query:
              type: string
            source:
              type: string
              enum: [{replacement_source}]
          additionalProperties: false
"#,
        access_log_path.display()
    )
}

#[test]
fn graphql_query_round_trips_via_proxy() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
"#,
        upstream.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!({ "query": "{ hello }" }),
            &[("content-type", "application/json")],
        )
        .expect("send graphql query");

    assert_eq!(resp.status, 200, "graphql proxy should return 200");
    let body = resp.json().expect("decode JSON body");
    assert_eq!(body["data"]["hello"], "world");

    let captured = upstream.captured();
    assert_eq!(
        captured.len(),
        1,
        "upstream must observe exactly one request"
    );
    let req = &captured[0];
    assert_eq!(req.method, "POST", "graphql is POST-only");
    let upstream_body = std::str::from_utf8(&req.body).expect("upstream body must be UTF-8 JSON");
    assert!(
        upstream_body.contains("hello"),
        "upstream body should carry the GraphQL query: {upstream_body}"
    );
}

#[test]
fn graphql_rejects_nested_aliased_introspection_before_upstream() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      allow_introspection: false
"#,
        upstream.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!({
                "query": "{ viewer { hidden: __type(name: \"User\") { name } } }"
            }),
            &[("content-type", "application/json")],
        )
        .expect("send graphql query");

    assert_eq!(resp.status, 400);
    assert!(
        upstream.captured().is_empty(),
        "rejected GraphQL requests must not reach the upstream"
    );
}

#[test]
fn graphql_validates_the_body_after_request_modifiers() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      allow_introspection: false
    request_modifiers:
      - body:
          replace_json:
            query: "{{ __schema {{ queryType {{ name }} }} }}"
"#,
        upstream.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!({"query": "{ hello }"}),
            &[("content-type", "application/json")],
        )
        .expect("send benign GraphQL query");

    assert_eq!(resp.status, 400);
    assert!(
        upstream.captured().is_empty(),
        "a request modifier must not introduce a GraphQL validation bypass"
    );
}

#[test]
fn graphql_request_validator_forwards_the_exact_validated_replacement_body() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let forbidden_original = br#"{"query":"{__schema{id}}","source":"original"}"#.to_vec();
    let safe_replacement =
        serde_json::to_vec(&json!({"query": "{safeName{id}}", "source": "replacement"}))
            .expect("serialize replacement");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      allow_introspection: false
    request_modifiers:
      - body:
          replace_json:
            query: "{{safeName{{id}}}}"
            source: replacement
    policies:
      - type: request_validator
        content_types:
          - application/json
        schema:
          type: object
          required:
            - query
            - source
          properties:
            query:
              type: string
            source:
              type: string
              enum: [replacement]
          additionalProperties: false
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            forbidden_original,
            &[],
        )
        .expect("send forbidden GraphQL body");

    assert_eq!(response.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].body, safe_replacement,
        "the body that passed GraphQL validation must be the body sent upstream"
    );
}

#[test]
fn graphql_request_validator_rejects_invalid_replacement_even_when_original_is_valid() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
    request_modifiers:
      - body:
          replace_json:
            query: "{{safeName{{id}}}}"
            source: replacement
    policies:
      - type: request_validator
        status: 422
        content_types:
          - application/json
        schema:
          type: object
          required:
            - query
            - source
          properties:
            query:
              type: string
            source:
              type: string
              enum: [original]
          additionalProperties: false
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            br#"{"query":"{safeName{id}}","source":"original"}"#.to_vec(),
            &[],
        )
        .expect("send body whose replacement violates the schema");

    assert_eq!(response.status, 422);
    let captured = upstream.captured();
    assert!(
        captured.len() <= 1,
        "body rejection must not retry the upstream request"
    );
    assert!(
        captured.iter().all(|request| request.body.is_empty()),
        "a replacement rejected by the body policy must emit no upstream body bytes"
    );
}

#[test]
fn graphql_content_digest_authenticates_original_while_consumers_see_replacement() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let access_log = NamedTempFile::new().expect("create access log");
    let original =
        br#"{"query":"{__schema{id}}","source":"client-original-with-more-bytes"}"#.to_vec();
    let replacement =
        serde_json::to_vec(&json!({"query": "{safeName{id}}", "source": "replacement"}))
            .expect("serialize replacement");
    assert_ne!(original.len(), replacement.len());
    let digest = sha256_digest_header(&original);
    let yaml =
        graphql_content_digest_config(&upstream.base_url(), access_log.path(), "replacement");
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            original,
            &[("content-digest", digest.as_str())],
        )
        .expect("send GraphQL replacement with original digest");

    assert_eq!(
        response.status, 200,
        "the digest must authenticate the inbound representation"
    );
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].body, replacement,
        "downstream body policy and upstream must use the validated replacement"
    );
    wait_for_access_log_bytes(access_log.path(), replacement.len() as u64);
}

#[test]
fn graphql_content_digest_authenticates_empty_original_before_replacement() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let access_log = NamedTempFile::new().expect("create access log");
    let replacement =
        serde_json::to_vec(&json!({"query": "{safeName{id}}", "source": "replacement"}))
            .expect("serialize replacement");
    let empty_digest = sha256_digest_header(b"");
    let yaml =
        graphql_content_digest_config(&upstream.base_url(), access_log.path(), "replacement");
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            Vec::new(),
            &[("content-digest", empty_digest.as_str())],
        )
        .expect("send GraphQL replacement with empty original digest");

    assert_eq!(
        response.status, 200,
        "an empty inbound representation must verify before replacement"
    );
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].body, replacement);
}

#[test]
fn graphql_content_digest_of_replacement_cannot_authenticate_different_original() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let access_log = NamedTempFile::new().expect("create access log");
    let original =
        br#"{"query":"{safeName{id}}","source":"different-client-representation"}"#.to_vec();
    let replacement =
        serde_json::to_vec(&json!({"query": "{safeName{id}}", "source": "replacement"}))
            .expect("serialize replacement");
    let replacement_digest = sha256_digest_header(&replacement);
    let yaml =
        graphql_content_digest_config(&upstream.base_url(), access_log.path(), "replacement");
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            original,
            &[("content-digest", replacement_digest.as_str())],
        )
        .expect("send different original with replacement digest");

    assert_eq!(
        response.status, 400,
        "a digest of transformed bytes must not authenticate the inbound representation"
    );
    assert!(
        upstream
            .captured()
            .iter()
            .all(|request| request.body.is_empty()),
        "a falsely attested request must emit no upstream body bytes"
    );
}

#[test]
fn graphql_idempotency_keys_and_hashes_use_validated_replacement_body() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let forbidden_original = br#"{"query":"{__schema{id}}"}"#.to_vec();
    let different_original = br#"{"query":"{malformed(}"}"#.to_vec();
    let safe_replacement = br#"{"query":"{safeName{id}}"}"#.to_vec();

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      allow_introspection: false
    request_modifiers:
      - body:
          replace_json:
            query: "{{safeName{{id}}}}"
    idempotency:
      enabled: true
      header_name: Idempotency-Key
      ttl_secs: 60
      methods: [POST]
      backend: memory
"#,
        upstream.base_url()
    );
    // Keep this stateful cache test's config watcher isolated from temp-file
    // events created by parallel harnesses, which would trigger a reload.
    let proxy =
        ProxyHarness::start_with_workspace(&yaml, &[]).expect("start isolated-workspace proxy");

    let first = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            forbidden_original,
            &[("Idempotency-Key", "graphql-replacement-miss")],
        )
        .expect("send idempotency cache miss");

    assert_eq!(first.status, 200);
    assert!(
        !first.headers.contains_key("x-sbproxy-idempotency"),
        "the first request must populate, not replay, the cache"
    );

    let replay = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            different_original.clone(),
            &[("Idempotency-Key", "graphql-replacement-miss")],
        )
        .expect("replay with different discarded bytes");
    assert_eq!(replay.status, 200);
    assert_eq!(
        replay
            .headers
            .get("x-sbproxy-idempotency")
            .map(String::as_str),
        Some("HIT"),
        "equal authoritative replacements must share one body hash"
    );

    let distinct_key = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            different_original,
            &[("Idempotency-Key", "graphql-replacement-distinct-key")],
        )
        .expect("send the same replacement under a distinct key");
    assert_eq!(distinct_key.status, 200);
    assert!(
        !distinct_key.headers.contains_key("x-sbproxy-idempotency"),
        "a distinct key must remain a cache miss even for equal replacement bytes"
    );

    let captured = upstream.captured();
    assert_eq!(captured.len(), 2, "only the two distinct keys may execute");
    assert!(captured
        .iter()
        .all(|request| request.body == safe_replacement));
}

#[test]
fn graphql_validates_percent_encoded_get_queries_before_upstream() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      allow_introspection: false
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let valid = proxy
        .get(
            "/graphql?query=%7Bviewer%7Bid%7D%7D&variables=%7B%7D",
            "gql.localhost",
        )
        .expect("send valid GraphQL GET");
    assert_eq!(valid.status, 200);

    let resp = proxy
        .get(
            "/graphql?query=%7Bviewer%7Bhidden%3A__schema%7BqueryType%7Bname%7D%7D%7D%7D",
            "gql.localhost",
        )
        .expect("send GraphQL GET");

    assert_eq!(resp.status, 400);
    assert_eq!(
        upstream.captured().len(),
        1,
        "only the valid GraphQL GET request may reach the upstream"
    );
}

#[test]
fn graphql_validated_get_rejects_nonempty_inbound_body() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let status = get_with_body(
        &proxy,
        "/graphql?query=%7Bhello%7D",
        "gql.localhost",
        br#"{"query":"{ __schema { queryType { name } } }"}"#.to_vec(),
    )
    .expect("send GraphQL GET with a body");

    assert_eq!(status, 400);
    assert!(
        upstream.captured().is_empty(),
        "validated GraphQL GET bodies must not reach the upstream"
    );
}

#[test]
fn graphql_validated_get_rejects_inbound_body_even_with_empty_replacement() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
    request_modifiers:
      - body:
          replace: ""
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let status = get_with_body(
        &proxy,
        "/graphql?query=%7Bhello%7D",
        "gql.localhost",
        br#"{"query":"{ hello }"}"#.to_vec(),
    )
    .expect("send GraphQL GET with inbound body and empty replacement");

    assert_eq!(status, 400);
    assert!(
        upstream.captured().is_empty(),
        "an empty replacement must not mask a nonempty inbound GET body"
    );
}

#[test]
fn graphql_validated_get_rejects_body_replacement_modifier() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
    request_modifiers:
      - body:
          replace_json:
            query: "{{ __schema {{ queryType {{ name }} }} }}"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .get("/graphql?query=%7Bhello%7D", "gql.localhost")
        .expect("send bodyless GraphQL GET");

    assert_eq!(response.status, 400);
    assert!(
        upstream.captured().is_empty(),
        "a body modifier must not add a body to a validated GraphQL GET"
    );
}

#[test]
fn graphql_validated_get_rejects_body_retained_by_post_to_get_modifier() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
    request_modifiers:
      - method: GET
        query:
          set:
            query: "{{ hello }}"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!({"query": "{ __schema { queryType { name } } }"}),
            &[("content-type", "application/json")],
        )
        .expect("send GraphQL POST rewritten to GET");

    assert_eq!(response.status, 400);
    assert!(
        upstream.captured().is_empty(),
        "a POST body retained by a GET method modifier must not reach the upstream"
    );
}

#[test]
fn graphql_validation_fails_closed_for_unsupported_multipart_post() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "multipart/form-data; boundary=graphql",
            br#"{"query":"{ hello }"}"#.to_vec(),
            &[],
        )
        .expect("send unsupported GraphQL multipart request");

    assert_eq!(resp.status, 400);
    assert!(
        upstream.captured().is_empty(),
        "unsupported validated GraphQL transports must fail closed"
    );
}

#[test]
fn graphql_validation_rejects_body_larger_than_replay_buffer() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let oversized = json!({
        "query": "{ hello }",
        "variables": {"padding": "x".repeat(70 * 1024)}
    });

    let resp = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &oversized,
            &[("content-type", "application/json")],
        )
        .expect("send oversized GraphQL request");

    assert_eq!(resp.status, 413);
    assert!(
        upstream.captured().is_empty(),
        "an unreplayable validated body must not reach the upstream"
    );
}

#[test]
fn graphql_validation_replays_body_consumed_by_threat_protection() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
    threat_protection:
      enabled: true
      json:
        max_depth: 4
        max_keys: 8
        max_string_length: 128
        max_array_size: 4
        max_total_size: 1024
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let request_body = br#"{"query":"{viewer{id}}"}"#.to_vec();

    let response = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            request_body.clone(),
            &[],
        )
        .expect("send GraphQL body through threat protection");

    assert_eq!(response.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].body, request_body,
        "GraphQL must validate and replay bytes consumed by earlier middleware"
    );
}

#[test]
fn graphql_max_depth_allows_exact_limit_and_rejects_excess() {
    let upstream = MockUpstream::start(json!({"data": {"viewer": {"id": "1"}}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      max_depth: 2
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let exact = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!({"query": "{ viewer { id } }"}),
            &[("content-type", "application/json")],
        )
        .expect("send exact-depth query");
    assert_eq!(exact.status, 200);

    let too_deep = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!({"query": "{ viewer { profile { id } } }"}),
            &[("content-type", "application/json")],
        )
        .expect("send over-depth query");
    assert_eq!(too_deep.status, 400);
    assert_eq!(
        upstream.captured().len(),
        1,
        "only the exact-limit query may reach the upstream"
    );
}

#[test]
fn graphql_validates_malformed_and_batched_post_documents() {
    let upstream = MockUpstream::start(json!({"data": {"ok": true}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
      validate_queries: true
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let malformed = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!({"query": "{ viewer( }"}),
            &[("content-type", "application/json")],
        )
        .expect("send malformed query");
    assert_eq!(malformed.status, 400);
    assert_eq!(
        malformed.headers.get("connection").map(String::as_str),
        Some("close"),
        "a rejection after upstream selection must advertise that HTTP/1.1 cannot be reused"
    );

    let valid_batch_body = json!([
        {"query": "{ viewer { id } }"},
        {"query": "mutation { updateName(name: \"Ada\") { id } }"}
    ]);
    let expected_batch_bytes =
        serde_json::to_vec(&valid_batch_body).expect("serialize expected batch bytes");
    let valid_batch = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &valid_batch_body,
            &[("content-type", "application/json")],
        )
        .expect("send valid batch");
    assert_eq!(valid_batch.status, 200);

    let invalid_batch = proxy
        .post_json(
            "/graphql",
            "gql.localhost",
            &json!([
                {"query": "{ viewer { id } }"},
                {"query": "{ broken( }"}
            ]),
            &[("content-type", "application/json")],
        )
        .expect("send invalid batch");
    assert_eq!(invalid_batch.status, 400);
    let captured = upstream.captured();
    assert_eq!(
        captured.len(),
        1,
        "only the valid batch may reach the upstream"
    );
    assert_eq!(
        captured[0].body, expected_batch_bytes,
        "validated batch bytes must be replayed upstream unchanged"
    );
}

#[test]
fn graphql_default_config_remains_a_transparent_proxy() {
    let upstream = MockUpstream::start(json!({"data": {"ok": true}})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gql.localhost":
    action:
      type: graphql
      url: "{}/graphql"
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "multipart/form-data; boundary=graphql",
            b"not a supported GraphQL transport".to_vec(),
            &[],
        )
        .expect("send unvalidated body");

    assert_eq!(resp.status, 200);
    assert_eq!(
        upstream.captured().len(),
        1,
        "default GraphQL configuration must not parse or reject the request"
    );
}

#[test]
fn graphql_revalidates_persisted_idempotency_hits_after_rules_tighten() {
    let Some(redis) = RedisGuard::spawn() else {
        eprintln!(
            "SKIP action_graphql::graphql_revalidates_persisted_idempotency_hits_after_rules_tighten: redis-server not found on PATH"
        );
        return;
    };
    let admin_port = pick_loopback_port();
    let upstream = MockUpstream::start(json!({"data": {"cached": true}})).expect("upstream");
    let permissive = graphql_reload_config(admin_port, &redis.url(), &upstream.base_url(), false);
    let proxy = ProxyHarness::start_with_yaml(&permissive).expect("start permissive proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5))
        .expect("admin listener to bind");

    let cached_requests = [
        (
            "cached-introspection",
            json!({"query": "{ __schema { queryType { name } } }"}),
        ),
        (
            "cached-depth",
            json!({"query": "{ viewer { profile { id } } }"}),
        ),
        ("cached-malformed", json!({"query": "{ viewer( }"})),
    ];
    for (key, body) in &cached_requests {
        let response = proxy
            .post_json(
                "/graphql",
                "gql.localhost",
                body,
                &[("Idempotency-Key", key)],
            )
            .expect("prime permissive idempotency cache");
        assert_eq!(response.status, 200);
    }
    assert_eq!(upstream.captured().len(), cached_requests.len());

    let strict = graphql_reload_config(admin_port, &redis.url(), &upstream.base_url(), true);
    proxy.rewrite_config(&strict).expect("write strict config");
    let (reload_status, reload_body) = post_admin_reload(admin_port);
    assert_eq!(reload_status, 200, "reload failed: {reload_body}");

    for (key, body) in &cached_requests {
        let response = proxy
            .post_json(
                "/graphql",
                "gql.localhost",
                body,
                &[("Idempotency-Key", key)],
            )
            .expect("retry cached body under strict validation");
        assert_eq!(
            response.status, 400,
            "current GraphQL rules must reject cached request {key}"
        );
        assert!(
            !response.headers.contains_key("x-sbproxy-idempotency"),
            "a rejected request must not replay the permissive cached response"
        );
    }
    assert_eq!(
        upstream.captured().len(),
        cached_requests.len(),
        "strict retries must neither replay a cached 200 nor reach upstream"
    );
}
