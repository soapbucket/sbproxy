//! End-to-end coverage for the `graphql` action.
//!
//! The `graphql` action proxies a GraphQL POST body to an upstream
//! HTTP endpoint. We stand up a [`MockUpstream`] that returns a
//! canned `{ "data": { "hello": "world" } }` response and verify
//! the client sees the same payload after the proxy round-trip.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

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
