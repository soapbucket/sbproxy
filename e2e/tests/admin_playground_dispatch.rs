//! End-to-end coverage for the admin playground's success path (WOR-2042).
//!
//! The playground shipped in PR #797 exercising the real production
//! dispatch path via impersonation tickets. Its error paths had unit
//! coverage; the success path, mint a ticket, redeem it, dispatch a
//! completion, read the result, had none, so nothing in CI would have
//! noticed the playground breaking end to end.
//!
//! Two constraints shape this as an e2e rather than a unit test, both
//! named on the ticket:
//!
//! 1. A successful completion needs a live engine behind the proxy.
//!    `handle_dispatch` mints a single-use ticket and then makes a
//!    genuine loopback HTTP call into this server's own data-plane
//!    listener, so there is no seam to stub: the whole point of the
//!    route is that key policy, governance, routing, and guardrails run
//!    for real. A `MockUpstream` stands in for the model provider, which
//!    is the only part that is not sbproxy.
//! 2. TLS origins answer `501` by design, so the success case has to run
//!    against a plain-HTTP origin. That boundary gets its own case here
//!    rather than a comment, because "the playground does not support
//!    this" and "the playground broke" look identical from the console.
//!
//! Lives in the e2e suite, which the required gate excludes per repo
//! convention.

use std::net::TcpListener;
use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// The seeded virtual key this suite impersonates. Seeded in config so
/// the test is self-contained: minting through `POST /admin/keys` would
/// add a second failure mode to a test about the dispatch path.
const KEY_ID: &str = "a1b2c3d4e5f60789";

/// A per-test redb path. The key store has no in-memory backend, and
/// two tests sharing one file would race on it.
fn store_path(tag: &str) -> String {
    format!(
        "{}/sbproxy-playground-e2e-{}-{}.redb",
        std::env::temp_dir().display(),
        tag,
        std::process::id()
    )
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A config with key management on, one seeded key, and one plain-HTTP
/// AI origin pointed at the mock provider.
///
/// `force_ssl` is deliberately absent here: the TLS case below builds
/// its own config with it set, so the two differ in exactly the field
/// under test.
fn config_yaml(admin_port: u16, upstream_base: &str, force_ssl: bool, store_path: &str) -> String {
    let ssl = if force_ssl {
        "    force_ssl: true\n"
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
  key_management:
    enabled: true
    store:
      backend: embedded
      path: {store_path}
    cache:
      ttl_secs: 60
    crypto:
      pepper: "e2e-playground-pepper-not-a-real-secret"
      master_key: "e2e-playground-master-not-a-real-secret"
    failure_posture: closed
    seed:
      keys:
        - key_id: {KEY_ID}
          secret: e2e-playground-secret
          name: playground-e2e-key
          max_requests_per_minute: 600
          allowed_models:
            - gpt-4o-mini
origins:
  "ai.localhost":
{ssl}    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
          default_model: gpt-4o-mini
          models: [gpt-4o-mini]
"#
    )
}

/// An OpenAI-shaped reply carrying a `usage` block. The dispatch route
/// reports token usage and cost back to the console, and asserting on
/// those is what makes this a test of attribution rather than of "a 200
/// came back".
fn reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-playground-e2e",
        "object": "chat.completion",
        "created": 1_700_000_000u64,
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "pong"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    })
}

fn admin_post(port: u16, path: &str, body: &serde_json::Value) -> (u16, String) {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .basic_auth("admin", Some("secret"))
        .json(body)
        .send()
        .expect("admin POST");
    let status = resp.status().as_u16();
    (status, resp.text().unwrap_or_default())
}

#[test]
fn playground_dispatch_completes_against_a_plain_http_origin() {
    let upstream = MockUpstream::start(reply()).unwrap();
    let admin_port = pick_port();
    let harness = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &upstream.base_url(),
        false,
        &store_path("ok"),
    ))
    .unwrap();
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(10)).expect("admin port to bind");

    let (status, body) = admin_post(
        admin_port,
        "/admin/api/playground/dispatch",
        &json!({
            "key_id": KEY_ID,
            "origin": "ai.localhost",
            "request": {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}]
            }
        }),
    );

    assert_eq!(
        status, 200,
        "playground dispatch should complete against a plain-HTTP origin: {body}"
    );

    let parsed: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("dispatch response should be JSON ({e}): {body}"));

    // The completion actually happened, and the content came from the
    // upstream rather than from an error envelope the console would
    // render as a reply.
    assert_eq!(
        parsed
            .pointer("/response/choices/0/message/content")
            .and_then(|v| v.as_str()),
        Some("pong"),
        "the upstream completion should reach the caller: {body}"
    );

    // Usage attribution is the other half of the acceptance line. A
    // dispatch that returns the text but charges nothing is the failure
    // this catches: the console shows a working playground while the
    // ledger records nothing.
    assert_eq!(
        parsed
            .pointer("/usage/input_tokens")
            .and_then(|v| v.as_u64()),
        Some(11),
        "input tokens should be attributed from the upstream usage block: {body}"
    );
    assert_eq!(
        parsed
            .pointer("/usage/output_tokens")
            .and_then(|v| v.as_u64()),
        Some(7),
        "output tokens should be attributed: {body}"
    );
    // The route resolves the model off the upstream reply and prices the
    // call from it. A dispatch that loses the model reports a zero cost
    // for every call, which reads as a free playground rather than a bug.
    assert_eq!(
        parsed.get("model").and_then(|v| v.as_str()),
        Some("gpt-4o-mini"),
        "the model should be resolved from the upstream reply: {body}"
    );
    assert!(
        parsed.get("cost_usd").is_some(),
        "the response should carry a cost attribution: {body}"
    );

    // The request reached the mock provider through the real data plane,
    // not through a shortcut. One request, carrying the model asked for.
    let captured = upstream.captured();
    assert_eq!(
        captured.len(),
        1,
        "exactly one upstream call should have been made: {captured:?}"
    );
    let sent = String::from_utf8_lossy(&captured[0].body);
    assert!(
        sent.contains("gpt-4o-mini"),
        "the dispatched request should name the model: {sent}"
    );

    drop(harness);
}

#[test]
fn playground_dispatch_refuses_a_tls_origin_with_501() {
    // The documented boundary. Trusting this process's own certificate
    // and SNI identity for a loopback call into a `force_ssl` origin
    // needs plumbing the route deliberately does not implement, so it
    // refuses rather than guessing. Asserted here so that "not
    // supported" cannot quietly become "broken".
    let upstream = MockUpstream::start(reply()).unwrap();
    let admin_port = pick_port();
    let harness = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &upstream.base_url(),
        true,
        &store_path("tls"),
    ))
    .unwrap();
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(10)).expect("admin port to bind");

    let (status, body) = admin_post(
        admin_port,
        "/admin/api/playground/dispatch",
        &json!({
            "key_id": KEY_ID,
            "origin": "ai.localhost",
            "request": {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}]
            }
        }),
    );

    assert_eq!(
        status, 501,
        "a force_ssl origin should refuse with 501: {body}"
    );
    assert!(
        body.contains("plain-HTTP"),
        "the refusal should name the boundary rather than read as a fault: {body}"
    );

    drop(harness);
}

#[test]
fn playground_dispatch_denies_an_unknown_key_before_minting_a_ticket() {
    // The negative case that proves impersonation is gated on a real,
    // active key rather than on whatever the console sent. A ticket
    // minted for an unknown key would be an admin-authenticated path to
    // dispatching as a key that does not exist.
    let upstream = MockUpstream::start(reply()).unwrap();
    let admin_port = pick_port();
    let harness = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &upstream.base_url(),
        false,
        &store_path("unknown-key"),
    ))
    .unwrap();
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(10)).expect("admin port to bind");

    let (status, body) = admin_post(
        admin_port,
        "/admin/api/playground/dispatch",
        &json!({
            "key_id": "ffffffffffffffff",
            "origin": "ai.localhost",
            "request": {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}]
            }
        }),
    );

    assert_eq!(status, 404, "an unknown key should be refused: {body}");
    assert!(
        upstream.captured().is_empty(),
        "no upstream call should happen for an unknown key"
    );

    drop(harness);
}
