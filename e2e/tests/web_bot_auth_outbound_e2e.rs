//! Outbound Web Bot Auth signing (WOR-805 PR2b).
//!
//! When an origin opts into `outbound_web_bot_auth` and the proxy has a
//! `web_bot_auth` key, SBproxy signs the request it sends upstream
//! (RFC 9421, `tag=web-bot-auth`) so an upstream that demands Web Bot
//! Auth accepts SBproxy as a verified agent. The signature crypto is
//! unit-tested in `sbproxy-middleware` (signer/verifier round-trip);
//! this e2e validates the wiring: the opt-in origin's outbound request
//! carries the signature headers and a control origin's does not.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const SEED_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn config(signer_url: &str, plain_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  web_bot_auth:
    key_id: sbproxy-test-2026
    ed25519_seed_hex: "{SEED_HEX}"
    directory_url: "https://gw.example/.well-known/http-message-signatures-directory"
origins:
  "signer.localhost":
    outbound_web_bot_auth: true
    action:
      type: proxy
      url: "{signer_url}"
  "plain.localhost":
    action:
      type: proxy
      url: "{plain_url}"
"#
    )
}

#[test]
fn outbound_request_is_signed_when_origin_opts_in() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let plain = MockUpstream::start(json!({"ok": true})).expect("plain");
    let proxy = ProxyHarness::start_with_yaml(&config(&upstream.base_url(), &plain.base_url()))
        .expect("proxy");

    let resp = proxy.get("/v1/items", "signer.localhost").expect("send");
    assert!((200..300).contains(&resp.status), "status {}", resp.status);

    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "upstream received exactly one request");
    let h = &captured[0].headers;

    let sig_input = h
        .get("signature-input")
        .expect("outbound request must carry signature-input");
    assert!(
        sig_input.contains("tag=\"web-bot-auth\""),
        "signature-input must carry the web-bot-auth tag: {sig_input}"
    );
    assert!(
        sig_input.contains("expires="),
        "signature-input must carry an expires param: {sig_input}"
    );
    assert!(
        h.contains_key("signature"),
        "outbound request must carry a signature header"
    );
    assert_eq!(
        h.get("signature-agent").map(String::as_str),
        Some("https://gw.example/.well-known/http-message-signatures-directory"),
        "Signature-Agent must point at the configured directory"
    );
}

#[test]
fn outbound_request_is_unsigned_without_opt_in() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let plain = MockUpstream::start(json!({"ok": true})).expect("plain");
    let proxy = ProxyHarness::start_with_yaml(&config(&upstream.base_url(), &plain.base_url()))
        .expect("proxy");

    let resp = proxy.get("/v1/items", "plain.localhost").expect("send");
    assert!((200..300).contains(&resp.status), "status {}", resp.status);

    let captured = plain.captured();
    assert_eq!(captured.len(), 1, "upstream received exactly one request");
    let h = &captured[0].headers;
    assert!(
        !h.contains_key("signature"),
        "no signature header without the opt-in"
    );
    assert!(
        !h.contains_key("signature-input"),
        "no signature-input header without the opt-in"
    );
}
