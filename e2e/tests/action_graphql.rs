//! End-to-end coverage for the `graphql` action.
//!
//! The `graphql` action proxies a GraphQL POST body to an upstream
//! HTTP endpoint. We stand up a [`MockUpstream`] that returns a
//! canned `{ "data": { "hello": "world" } }` response and verify
//! the client sees the same payload after the proxy round-trip.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

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
    let forbidden_original = br#"{"query":"{__schema{id}}"}"#.to_vec();
    let safe_replacement = br#"{"query":"{safeName{id}}"}"#.to_vec();
    assert_eq!(
        forbidden_original.len(),
        safe_replacement.len(),
        "the regression must not depend on content-length changing"
    );

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
    policies:
      - type: request_validator
        content_types:
          - application/json
        schema:
          type: object
          required:
            - query
          properties:
            query:
              type: string
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
fn graphql_idempotency_miss_forwards_the_exact_validated_replacement_body() {
    let upstream = MockUpstream::start(json!({"data": {"hello": "world"}})).expect("upstream");
    let forbidden_original = br#"{"query":"{__schema{id}}"}"#.to_vec();
    let safe_replacement = br#"{"query":"{safeName{id}}"}"#.to_vec();
    assert_eq!(
        forbidden_original.len(),
        safe_replacement.len(),
        "the regression must not depend on content-length changing"
    );

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
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let response = proxy
        .post_bytes(
            "/graphql",
            "gql.localhost",
            "application/json",
            forbidden_original,
            &[("Idempotency-Key", "graphql-replacement-miss")],
        )
        .expect("send idempotency cache miss");

    assert_eq!(response.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].body, safe_replacement,
        "an idempotency miss must forward the GraphQL-validated replacement"
    );
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
