//! Unit and regression tests for the server module.
//!
//! Relocated from `server.rs`. `use super::*` resolves to
//! the `server` module exactly as the inline `mod tests` did.

use super::*;

// --- WOR-168: mirror state drift no-panic regression ---

/// Pre-WOR-168, `request_body_filter` called
/// `ctx.mirror_pending.take().unwrap()` after matching the slot via
/// `as_ref` / `as_mut`. A future refactor that cleared the slot
/// between the match and the take would panic the worker. The
/// fix replaced the unwrap with `if let Some(...)` and bumped a
/// drift counter in the else branch. We can't reach the inner
/// path from a unit test (it lives inside an async trait method),
/// but `fire_pending_mirror` shares the same pattern (it does a
/// `match take()` on the slot) and is the helper the body-filter
/// re-uses. This test pins the no-panic shape: if the slot is
/// empty, the helper returns without firing or panicking.
#[test]
fn fire_pending_mirror_no_panic_when_slot_empty() {
    // Drive a tokio current-thread runtime so the helper's
    // `tokio::spawn` (in the Some branch) wouldn't fail the
    // build, even though we exercise only the None branch.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut ctx = crate::context::RequestContext::new();
        assert!(ctx.mirror_pending.is_none(), "precondition: slot empty");
        // Must not panic.
        fire_pending_mirror(&mut ctx);
        assert!(ctx.mirror_pending.is_none(), "slot stays empty");
    });
}

// --- resolve_override parsing ---

#[test]
fn resolve_override_ipv4_only_uses_default_port() {
    assert_eq!(resolve_addr_override("203.0.113.7", 443), "203.0.113.7:443");
}

#[test]
fn resolve_override_ipv4_with_port_pins_both() {
    assert_eq!(
        resolve_addr_override("203.0.113.7:8443", 443),
        "203.0.113.7:8443"
    );
}

#[test]
fn resolve_override_ipv6_bracketed_with_port() {
    assert_eq!(
        resolve_addr_override("[2001:db8::1]:8443", 443),
        "[2001:db8::1]:8443"
    );
}

#[test]
fn resolve_override_ipv6_bracketed_without_port() {
    assert_eq!(
        resolve_addr_override("[2001:db8::1]", 443),
        "[2001:db8::1]:443"
    );
}

#[test]
fn resolve_override_ipv6_unbracketed_is_bracketed_at_default_port() {
    assert_eq!(
        resolve_addr_override("2001:db8::1", 443),
        "[2001:db8::1]:443"
    );
}

#[test]
fn resolve_override_hostname_with_port() {
    assert_eq!(
        resolve_addr_override("internal.svc:9000", 443),
        "internal.svc:9000"
    );
}

#[test]
fn resolve_override_hostname_only_uses_default_port() {
    assert_eq!(
        resolve_addr_override("internal.svc", 443),
        "internal.svc:443"
    );
}

// --- RFC 7239 Forwarded `for=`/`by=` IPv6 bracketing ---

#[test]
fn forwarded_node_ipv4_is_bare() {
    assert_eq!(forwarded_node("203.0.113.7"), "203.0.113.7");
}

#[test]
fn forwarded_node_ipv6_is_quoted_and_bracketed() {
    // RFC 7239 §6: IPv6 addresses must be enclosed in square brackets
    // and the whole token quoted because the brackets are not allowed
    // in an unquoted token.
    assert_eq!(forwarded_node("2001:db8::1"), "\"[2001:db8::1]\"");
}

#[test]
fn forwarded_node_ipv6_loopback() {
    assert_eq!(forwarded_node("::1"), "\"[::1]\"");
}

#[test]
fn forwarded_node_ipv4_mapped_ipv6() {
    // ::ffff:192.0.2.1 contains a colon so we treat it as v6 and bracket.
    assert_eq!(forwarded_node("::ffff:192.0.2.1"), "\"[::ffff:192.0.2.1]\"");
}

// --- Webhook envelope shape ---

#[test]
fn webhook_envelope_includes_proxy_and_request() {
    let env = webhook_envelope(
        "on_request",
        "test-req-id",
        "abc123",
        serde_json::json!({"host": "api.example.com"}),
    );
    assert_eq!(env["event"], "on_request");
    assert_eq!(env["proxy"]["config_revision"], "abc123");
    assert_eq!(env["request"]["id"], "test-req-id");
    assert_eq!(env["host"], "api.example.com");
    // Identity fields must be populated, not empty.
    assert!(!env["proxy"]["instance_id"].as_str().unwrap().is_empty());
    assert!(!env["proxy"]["version"].as_str().unwrap().is_empty());
}

#[test]
fn webhook_signature_is_stable_per_input() {
    let s1 = sign_webhook("secret", b"hello", 1700000000).unwrap();
    let s2 = sign_webhook("secret", b"hello", 1700000000).unwrap();
    assert_eq!(s1, s2);
    assert!(s1.starts_with("v1="));
    // Different timestamp -> different signature (replay protection).
    let s3 = sign_webhook("secret", b"hello", 1700000001).unwrap();
    assert_ne!(s1, s3);
}

// --- WOR-189: AI hook header snapshot + redaction ---
//
// The two AI-side hook surfaces (`ClassifyRequest::headers`,
// `LookupRequest::request_headers`) used to ship as empty maps with
// a TODO. They now carry a snapshot of the inbound request headers
// produced by `snapshot_request_headers_from`. This test pins the
// contract: representative headers round-trip lower-cased, and the
// three credential carriers in `REDACTED_REQUEST_HEADERS`
// (Authorization, Cookie, Proxy-Authorization) are dropped before
// any classifier or semantic-cache hook sees them.
fn test_request_header(headers: &[(&str, &str)]) -> pingora_http::RequestHeader {
    let mut req = pingora_http::RequestHeader::build("GET", b"/v1/chat/completions", None)
        .expect("build request header");
    for (name, value) in headers {
        req.insert_header(name.to_string(), *value)
            .expect("insert header");
    }
    req
}

#[test]
fn snapshot_request_headers_round_trips_non_credential_headers() {
    let req = test_request_header(&[
        ("X-Request-Id", "req-123"),
        ("Content-Type", "application/json"),
        ("X-Customer-Id", "tenant-7"),
    ]);
    let snap = snapshot_request_headers_from(&req);
    // Names land lower-cased to match HTTP/2 + HTTP/3 framing.
    assert_eq!(
        snap.get("x-request-id").map(String::as_str),
        Some("req-123")
    );
    assert_eq!(
        snap.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        snap.get("x-customer-id").map(String::as_str),
        Some("tenant-7")
    );
}

#[test]
fn snapshot_request_headers_drops_authorization() {
    let req = test_request_header(&[
        ("Authorization", "Bearer sk-secret"),
        ("X-Request-Id", "req-123"),
    ]);
    let snap = snapshot_request_headers_from(&req);
    assert!(
        !snap.contains_key("authorization"),
        "Authorization must be redacted before reaching hook surfaces"
    );
    // Mixed-case spellings still get caught: Pingora lower-cases
    // the header name on insertion, and we additionally lower-case
    // on the read side.
    assert!(
        !snap.contains_key("Authorization"),
        "no mixed-case Authorization survives either"
    );
    assert_eq!(
        snap.get("x-request-id").map(String::as_str),
        Some("req-123")
    );
}

#[test]
fn snapshot_request_headers_drops_cookie_and_proxy_authorization() {
    let req = test_request_header(&[
        ("Cookie", "session=abc123"),
        ("Proxy-Authorization", "Basic dXNlcjpwYXNz"),
        ("X-Trace-Id", "trace-7"),
    ]);
    let snap = snapshot_request_headers_from(&req);
    assert!(!snap.contains_key("cookie"));
    assert!(!snap.contains_key("proxy-authorization"));
    assert_eq!(snap.get("x-trace-id").map(String::as_str), Some("trace-7"));
}

// --- BotAuth target-uri propagation tests ---
//
// These tests guard the F1.6 fix where `check_auth` reconstructs
// `@target-uri` from the live request path-and-query. Before the
// fix, BotAuth used a hardcoded `/`, which let signatures bound to
// a path other than `/` slip through (or, conversely, let valid
// signatures over the real path get rejected when they covered
// `@target-uri`).

fn build_bot_auth_provider(key_id: &str, secret_hex: &str) -> sbproxy_modules::Auth {
    let provider = sbproxy_modules::auth::BotAuthProvider::from_config(serde_json::json!({
        "agents": [
            {
                "name": "test-agent",
                "key_id": key_id,
                "algorithm": "hmac_sha256",
                "public_key": secret_hex,
                "required_components": ["@method", "@target-uri"],
            }
        ]
    }))
    .expect("provider builds");
    sbproxy_modules::Auth::BotAuth(provider)
}

fn build_directory_bot_auth_provider(directory_url: &str) -> sbproxy_modules::Auth {
    let provider = sbproxy_modules::auth::BotAuthProvider::from_config(serde_json::json!({
        "agents": [],
        "directory": {
            "url": directory_url,
            "signature_agents_allow": [directory_url]
        }
    }))
    .expect("directory provider builds");
    sbproxy_modules::Auth::BotAuth(provider)
}

fn sign_for_path(secret_hex: &str, key_id: &str, target_uri: &str) -> (String, String) {
    use base64::Engine;
    use hmac::{KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = hmac::Hmac<Sha256>;

    let raw_input = format!(
            "sig1=(\"@method\" \"@target-uri\");created=1700000000;keyid=\"{key_id}\";alg=\"hmac-sha256\""
        );
    let entry = sbproxy_middleware::signatures::parse_signature_input(&raw_input)
        .unwrap()
        .pop()
        .unwrap()
        .1;
    let req_for_signing = http::Request::builder()
        .method("GET")
        .uri(target_uri)
        .body(bytes::Bytes::new())
        .unwrap();
    let base =
        sbproxy_middleware::signatures::build_signature_base(&req_for_signing, &entry).unwrap();
    let key_bytes = hex::decode(secret_hex).unwrap();
    let mut mac = HmacSha256::new_from_slice(&key_bytes).unwrap();
    mac.update(base.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    (raw_input, format!("sig1=:{}:", sig_b64))
}

#[tokio::test]
async fn bot_auth_accepts_signature_bound_to_real_request_path() {
    // Sign for "/api/foo", then ask check_auth to verify a request
    // whose path is "/api/foo". The reconstructed @target-uri must
    // match what the signer covered.
    let secret_hex = "00112233445566778899aabbccddeeff";
    let key_id = "test-bot-key";
    let auth = build_bot_auth_provider(key_id, secret_hex);
    let (sig_input, sig_value) = sign_for_path(secret_hex, key_id, "/api/foo");

    let mut headers = http::HeaderMap::new();
    headers.insert("signature-input", sig_input.parse().unwrap());
    headers.insert("signature", sig_value.parse().unwrap());

    let result = check_auth(&auth, &headers, None, "GET", "/api/foo").await;
    assert!(
        matches!(result, AuthResult::Allow { .. }),
        "expected Allow when path matches signed @target-uri"
    );
}

#[tokio::test]
async fn bot_auth_rejects_signature_bound_to_different_path() {
    // Sign for "/", but the live request path is "/api/foo". The
    // verifier must reject because @target-uri changed under it.
    // Before the fix this passed because check_auth always
    // reconstructed the URI as "/".
    let secret_hex = "00112233445566778899aabbccddeeff";
    let key_id = "test-bot-key";
    let auth = build_bot_auth_provider(key_id, secret_hex);
    let (sig_input, sig_value) = sign_for_path(secret_hex, key_id, "/");

    let mut headers = http::HeaderMap::new();
    headers.insert("signature-input", sig_input.parse().unwrap());
    headers.insert("signature", sig_value.parse().unwrap());

    let result = check_auth(&auth, &headers, None, "GET", "/api/foo").await;
    assert!(
        matches!(result, AuthResult::Deny(401, _)),
        "expected Deny(401) when @target-uri does not match signed path; got {:?}",
        match result {
            AuthResult::Allow { .. } => "Allow",
            AuthResult::Deny(s, _) => Box::leak(format!("Deny({s})").into_boxed_str()),
            AuthResult::DenyWithHeaders(s, _, _) => {
                Box::leak(format!("DenyWithHeaders({s})").into_boxed_str())
            }
            AuthResult::DigestChallenge(_) => "DigestChallenge",
        }
    );
}

#[tokio::test]
async fn bot_auth_includes_query_string_in_target_uri() {
    // Sign for "/api/foo?x=1"; verify that check_auth assembles the
    // same path-and-query when the query is passed in.
    let secret_hex = "00112233445566778899aabbccddeeff";
    let key_id = "test-bot-key";
    let auth = build_bot_auth_provider(key_id, secret_hex);
    let (sig_input, sig_value) = sign_for_path(secret_hex, key_id, "/api/foo?x=1");

    let mut headers = http::HeaderMap::new();
    headers.insert("signature-input", sig_input.parse().unwrap());
    headers.insert("signature", sig_value.parse().unwrap());

    let result = check_auth(&auth, &headers, Some("x=1"), "GET", "/api/foo").await;
    assert!(
        matches!(result, AuthResult::Allow { .. }),
        "expected Allow when path+query matches signed @target-uri"
    );
}

#[tokio::test]
async fn bot_auth_signature_agent_uses_async_directory_path() {
    let auth = build_directory_bot_auth_provider("https://directory.example/.well-known/bot-auth");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "signature-agent",
        "https://other.example/.well-known/bot-auth"
            .parse()
            .unwrap(),
    );
    headers.insert(
            "signature-input",
            "sig1=(\"@method\" \"@target-uri\");created=1700000000;keyid=\"dynamic-key\";alg=\"ed25519\""
                .parse()
                .unwrap(),
        );
    headers.insert("signature", "sig1=:AAAA:".parse().unwrap());

    let result = check_auth(&auth, &headers, None, "GET", "/api/foo").await;

    assert!(
            matches!(result, AuthResult::Deny(401, ref msg) if msg == "bot_auth: directory unavailable"),
            "Signature-Agent should route through verify_async and surface directory unavailable; got {}",
            auth_result_label(&result)
        );
}

// --- Auth plugin dispatch tests ---
//
// These guard the OSS gap fixed in this commit: the
// `Auth::Plugin(_)` arm of `check_auth` previously short-circuited
// to `AuthResult::Allow`, which made every enterprise auth provider
// (oauth jwks/introspection, biscuit, saml, ext_authz,
// mcp_resource_server, ...) inert at request time. The arm now
// dispatches into the boxed `AuthProvider` and translates the
// returned `AuthDecision` into an `AuthResult`.

use sbproxy_plugin::{AuthDecision, AuthProvider};
use std::future::Future;
use std::pin::Pin;

/// Test double that records every authenticate call and returns a
/// configured [`AuthDecision`].
struct StubAuthProvider {
    type_name: &'static str,
    decision: AuthDecision,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AuthProvider for StubAuthProvider {
    fn auth_type(&self) -> &'static str {
        self.type_name
    }

    fn authenticate(
        &self,
        _req: &http::Request<bytes::Bytes>,
        _ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<AuthDecision>> + Send + '_>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let d = self.decision.clone();
        Box::pin(async move { Ok(d) })
    }
}

/// Provider that always returns an error from authenticate(). Used
/// to verify the engine treats a misbehaving plugin as a 500 deny
/// rather than letting the request through.
struct ErrorAuthProvider;

impl AuthProvider for ErrorAuthProvider {
    fn auth_type(&self) -> &'static str {
        "stub-error"
    }

    fn authenticate(
        &self,
        _req: &http::Request<bytes::Bytes>,
        _ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<AuthDecision>> + Send + '_>> {
        Box::pin(async move { Err(anyhow::anyhow!("upstream auth server unreachable").into()) })
    }
}

fn auth_result_label(r: &AuthResult) -> String {
    match r {
        AuthResult::Allow { .. } => "Allow".to_string(),
        AuthResult::Deny(s, m) => format!("Deny({s}, {m:?})"),
        AuthResult::DenyWithHeaders(s, m, h) => {
            format!("DenyWithHeaders({s}, {m:?}, {} headers)", h.len())
        }
        AuthResult::DigestChallenge(_) => "DigestChallenge".to_string(),
    }
}

#[tokio::test]
async fn plugin_allow_decision_maps_to_auth_result_allow() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider = StubAuthProvider {
        type_name: "stub-allow",
        decision: AuthDecision::allow_anonymous(),
        calls: calls.clone(),
    };
    let auth = sbproxy_modules::Auth::Plugin(Box::new(provider));
    let headers = http::HeaderMap::new();

    let result = check_auth(&auth, &headers, None, "GET", "/").await;
    assert!(
        matches!(result, AuthResult::Allow { .. }),
        "Allow decision must map to AuthResult::Allow; got {}",
        auth_result_label(&result)
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "provider must be invoked exactly once"
    );
}

#[tokio::test]
async fn plugin_deny_decision_maps_to_auth_result_deny() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider = StubAuthProvider {
        type_name: "stub-deny",
        decision: AuthDecision::Deny {
            status: 403,
            message: "policy says no".to_string(),
        },
        calls: calls.clone(),
    };
    let auth = sbproxy_modules::Auth::Plugin(Box::new(provider));
    let headers = http::HeaderMap::new();

    let result = check_auth(&auth, &headers, None, "POST", "/api/x").await;
    match result {
        AuthResult::Deny(status, msg) => {
            assert_eq!(status, 403);
            assert_eq!(msg, "policy says no");
        }
        other => panic!("expected Deny(403,...); got {}", auth_result_label(&other)),
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn plugin_deny_with_headers_propagates_custom_response_headers() {
    // Simulates the RFC 9728 path: an MCP resource server denies
    // with a 401 plus a `WWW-Authenticate: Bearer
    // resource_metadata="..."` header so clients can discover the
    // authorization server.
    let www_auth =
        "Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource\"";
    let provider = StubAuthProvider {
        type_name: "stub-deny-headers",
        decision: AuthDecision::DenyWithHeaders {
            status: 401,
            message: "missing token".to_string(),
            headers: vec![("WWW-Authenticate".to_string(), www_auth.to_string())],
        },
        calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };
    let auth = sbproxy_modules::Auth::Plugin(Box::new(provider));
    let headers = http::HeaderMap::new();

    let result = check_auth(&auth, &headers, None, "GET", "/").await;
    match result {
        AuthResult::DenyWithHeaders(status, msg, hdrs) => {
            assert_eq!(status, 401);
            assert_eq!(msg, "missing token");
            assert_eq!(hdrs.len(), 1);
            assert_eq!(hdrs[0].0, "WWW-Authenticate");
            assert_eq!(hdrs[0].1, www_auth);
        }
        other => panic!(
            "expected DenyWithHeaders; got {}",
            auth_result_label(&other)
        ),
    }
}

#[tokio::test]
async fn plugin_authenticate_error_denies_with_500() {
    // A plugin that returns Err must NOT fall through to Allow;
    // the engine must surface a generic 500 deny so a flaky
    // enterprise auth provider can never silently pass requests.
    let auth = sbproxy_modules::Auth::Plugin(Box::new(ErrorAuthProvider));
    let headers = http::HeaderMap::new();

    let result = check_auth(&auth, &headers, None, "GET", "/").await;
    match result {
        AuthResult::Deny(status, msg) => {
            assert_eq!(status, 500);
            assert!(
                msg.contains("stub-error"),
                "expected message to mention plugin name; got {msg:?}"
            );
        }
        other => panic!("expected Deny(500,...); got {}", auth_result_label(&other)),
    }
}

#[tokio::test]
async fn plugin_receives_method_path_query_and_headers() {
    // Provider that records the request handed to it so we can
    // assert the engine reconstructed the URI components.
    struct RecordingProvider {
        captured: std::sync::Mutex<Option<(String, String, http::HeaderMap)>>,
    }

    impl AuthProvider for RecordingProvider {
        fn auth_type(&self) -> &'static str {
            "recording"
        }

        fn authenticate(
            &self,
            req: &http::Request<bytes::Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<AuthDecision>> + Send + '_>>
        {
            let method = req.method().as_str().to_string();
            let uri = req.uri().to_string();
            let hdrs = req.headers().clone();
            *self.captured.lock().unwrap() = Some((method, uri, hdrs));
            Box::pin(async move { Ok(AuthDecision::allow_anonymous()) })
        }
    }

    // Newtype shim so the recording provider can be both stored in
    // an Arc (for assertion access) and registered as a
    // `Box<dyn AuthProvider>` inside `Auth::Plugin`.
    struct RecordingProviderShim {
        inner: std::sync::Arc<RecordingProvider>,
    }

    impl AuthProvider for RecordingProviderShim {
        fn auth_type(&self) -> &'static str {
            self.inner.auth_type()
        }

        fn authenticate(
            &self,
            req: &http::Request<bytes::Bytes>,
            ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<AuthDecision>> + Send + '_>>
        {
            self.inner.authenticate(req, ctx)
        }
    }

    let provider = std::sync::Arc::new(RecordingProvider {
        captured: std::sync::Mutex::new(None),
    });
    let auth = sbproxy_modules::Auth::Plugin(Box::new(RecordingProviderShim {
        inner: provider.clone(),
    }));

    let mut headers = http::HeaderMap::new();
    headers.insert("authorization", "Bearer test-token".parse().unwrap());
    headers.insert("x-trace-id", "abc123".parse().unwrap());

    let _ = check_auth(&auth, &headers, Some("foo=bar&baz=1"), "POST", "/api/v1/x").await;

    let guard = provider.captured.lock().unwrap();
    let (method, uri, hdrs) = guard.as_ref().expect("provider was invoked");
    assert_eq!(method, "POST");
    assert_eq!(uri, "/api/v1/x?foo=bar&baz=1");
    assert_eq!(
        hdrs.get("authorization").and_then(|v| v.to_str().ok()),
        Some("Bearer test-token")
    );
    assert_eq!(
        hdrs.get("x-trace-id").and_then(|v| v.to_str().ok()),
        Some("abc123")
    );
}

// --- Auth plugin registry tests ---
//
// Smoke-test the inventory-based registration channel that
// `compile_auth` uses to build `Auth::Plugin(...)` from a config
// type name. Registers a stub provider via `inventory::submit!`
// and verifies it round-trips through `build_auth_plugin`.

inventory::submit! {
    sbproxy_plugin::AuthPluginRegistration {
        name: "test-dispatch-plugin",
        factory: |_config| Ok(Box::new(StubAuthProvider {
            type_name: "test-dispatch-plugin",
            decision: AuthDecision::allow_anonymous(),
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })),
    }
}

#[tokio::test]
async fn registered_auth_plugin_is_discoverable_by_name() {
    let names = sbproxy_plugin::list_auth_plugins();
    assert!(
        names.contains(&"test-dispatch-plugin"),
        "test plugin must be visible via list_auth_plugins; got {names:?}",
    );

    let built = sbproxy_plugin::build_auth_plugin("test-dispatch-plugin", serde_json::Value::Null)
        .expect("plugin name resolves")
        .expect("factory succeeds");

    // Wrap in Auth::Plugin and verify dispatch works end to end.
    let auth = sbproxy_modules::Auth::Plugin(built);
    let headers = http::HeaderMap::new();
    let result = check_auth(&auth, &headers, None, "GET", "/").await;
    assert!(
        matches!(result, AuthResult::Allow { .. }),
        "registered plugin must dispatch to Allow; got {}",
        auth_result_label(&result)
    );
}

#[test]
fn unknown_auth_plugin_name_is_rejected_at_compile_time() {
    // Belt-and-braces check on the OSS guarantee: an unknown
    // `type:` value never produces an `Auth::Plugin(...)` at
    // request time. compile_auth errors before the pipeline ever
    // sees it, so `Auth::Plugin(name="<not registered>")` is
    // unreachable in production. This pins that property so a
    // future refactor cannot regress it.
    let json = serde_json::json!({"type": "this-plugin-does-not-exist"});
    let err = sbproxy_modules::compile::compile_auth(&json)
        .expect_err("unknown plugin name must error at compile time");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown auth type") || msg.contains("this-plugin-does-not-exist"),
        "error message must mention the unknown type; got {msg:?}",
    );
}

// --- SSE usage scanner tests ---
//
// These cover the deprecated `SseUsageScanner` shim (a thin
// wrapper over the generic parser). The pluggable parser family
// has its own tests under `sbproxy-ai/src/usage_parser/` and
// `e2e/tests/ai_streaming_usage.rs`.

#[allow(deprecated)]
#[test]
fn sse_scanner_captures_openai_terminal_usage() {
    let mut s = SseUsageScanner::new();
    let body = b"data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
                     data: {\"id\":\"x\",\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":34,\"total_tokens\":46}}\n\n\
                     data: [DONE]\n\n";
    s.feed(body);
    assert_eq!(s.totals(), (12, 34));
}

#[allow(deprecated)]
#[test]
fn sse_scanner_captures_anthropic_message_delta_usage() {
    // Anthropic emits a partial usage on `message_start` and the
    // final usage on `message_delta`. The scanner must surface
    // the larger output_tokens from the second event.
    let mut s = SseUsageScanner::new();
    let body = b"event: message_start\n\
                     data: {\"type\":\"message_start\",\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}\n\n\
                     event: content_block_delta\n\
                     data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n\
                     event: message_delta\n\
                     data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n";
    s.feed(body);
    assert_eq!(s.totals(), (7, 42));
}

#[allow(deprecated)]
#[test]
fn sse_scanner_handles_chunks_split_mid_line() {
    // Real upstreams flush chunks at TCP boundaries; the scanner
    // must rejoin partial JSON across `feed` calls.
    let mut s = SseUsageScanner::new();
    s.feed(b"data: {\"usage\":{\"prompt_tokens\":");
    // Mid-line: nothing recorded yet.
    assert_eq!(s.totals(), (0, 0));
    s.feed(b"5,\"completion_tokens\":9}}\n\n");
    assert_eq!(s.totals(), (5, 9));
}

#[allow(deprecated)]
#[test]
fn sse_scanner_ignores_done_and_keepalive() {
    let mut s = SseUsageScanner::new();
    s.feed(b": ping\n\ndata: [DONE]\n\ndata: not-json\n\n");
    assert_eq!(s.totals(), (0, 0));
}

// --- Error page content negotiation tests ---

fn page(status: u16, ct: &str, body: &str) -> sbproxy_config::ErrorPageEntry {
    sbproxy_config::ErrorPageEntry {
        status: sbproxy_config::StatusSpec::Multi(vec![status]),
        content_type: ct.to_string(),
        body: body.to_string(),
        template: false,
    }
}

#[test]
fn accept_parse_simple() {
    let ranges = parse_accept_ranges("text/html");
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].typ, "text");
    assert_eq!(ranges[0].subtype, "html");
    assert!((ranges[0].q - 1.0).abs() < f32::EPSILON);
}

#[test]
fn accept_parse_with_q_and_wildcards() {
    let ranges = parse_accept_ranges("text/html;q=0.9, application/json;q=1.0, */*;q=0.1");
    assert_eq!(ranges.len(), 3);
    assert!((ranges[0].q - 0.9).abs() < f32::EPSILON);
    assert!((ranges[1].q - 1.0).abs() < f32::EPSILON);
    assert_eq!(ranges[2].typ, "*");
    assert_eq!(ranges[2].subtype, "*");
}

#[test]
fn accept_parse_is_capped_against_flood() {
    // WOR-608: a header with tens of thousands of entries must not produce
    // an unbounded Vec. The parse is capped at MAX_ACCEPT_RANGES.
    let flood = vec!["application/json"; 10_000].join(", ");
    let started = std::time::Instant::now();
    let ranges = parse_accept_ranges(&flood);
    let elapsed = started.elapsed();
    assert!(
        ranges.len() <= MAX_ACCEPT_RANGES,
        "parsed {} entries, expected <= {MAX_ACCEPT_RANGES}",
        ranges.len()
    );
    assert!(
        elapsed < std::time::Duration::from_millis(50),
        "capped parse should be fast, took {elapsed:?}"
    );
}

#[test]
fn match_accept_q_respects_wildcards() {
    let ranges = parse_accept_ranges("text/*;q=0.5, application/json");
    assert!((match_accept_q(&ranges, "application/json") - 1.0).abs() < f32::EPSILON);
    assert!((match_accept_q(&ranges, "text/html") - 0.5).abs() < f32::EPSILON);
    assert_eq!(match_accept_q(&ranges, "image/png"), 0.0);
}

#[test]
fn match_accept_q_ignores_charset_suffix() {
    let ranges = parse_accept_ranges("text/html");
    assert!((match_accept_q(&ranges, "text/html; charset=utf-8") - 1.0).abs() < f32::EPSILON);
}

#[test]
fn select_prefers_higher_q_match() {
    let html = page(404, "text/html", "<h1>nope</h1>");
    let json = page(404, "application/json", r#"{"e":"nope"}"#);
    let candidates = vec![&html, &json];

    // Browser-style Accept: HTML wins.
    let chosen = select_error_page(
        &candidates,
        "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    );
    assert_eq!(chosen.content_type, "text/html");

    // API-style Accept: JSON wins.
    let chosen = select_error_page(&candidates, "application/json");
    assert_eq!(chosen.content_type, "application/json");
}

#[test]
fn select_falls_back_to_json_when_accept_is_silent() {
    // `*/*` with no preference, or no Accept header: JSON preferred.
    let html = page(404, "text/html", "<h1>nope</h1>");
    let json = page(404, "application/json", r#"{"e":"nope"}"#);
    let candidates = vec![&html, &json];

    let chosen = select_error_page(&candidates, "*/*");
    assert_eq!(chosen.content_type, "application/json");

    let chosen = select_error_page(&candidates, "");
    assert_eq!(chosen.content_type, "application/json");
}

#[test]
fn select_falls_back_to_html_when_no_json() {
    // No JSON entry; HTML preferred when Accept doesn't match anything.
    let html = page(404, "text/html", "<h1>nope</h1>");
    let plain = page(404, "text/plain", "nope");
    let candidates = vec![&plain, &html];

    let chosen = select_error_page(&candidates, "image/png");
    assert_eq!(chosen.content_type, "text/html");
}

#[test]
fn page_matches_status_both_shapes() {
    // StatusSpec covers the same two authored shapes the JSON form
    // used to support: a single int (`status: 404`) and a list
    // (`status: [401, 403, 404]`).
    let single = sbproxy_config::StatusSpec::Single(404);
    let list = sbproxy_config::StatusSpec::Multi(vec![401, 403, 404]);
    let none = sbproxy_config::StatusSpec::Multi(vec![500]);
    assert!(single.matches(404));
    assert!(list.matches(403));
    assert!(!none.matches(404));
}

// --- Session cookie format tests ---

#[test]
fn session_cookie_default_config() {
    let config = sbproxy_config::SessionConfig {
        cookie_name: Some("sbproxy_sid".to_string()),
        max_age: Some(3600),
        http_only: false,
        secure: false,
        same_site: Some("Lax".to_string()),
        allow_non_ssl: true,
    };
    let cookie = build_session_cookie(&config, "test-uuid-123");
    assert!(cookie.starts_with("sbproxy_sid=test-uuid-123"));
    assert!(cookie.contains("Path=/"));
    assert!(cookie.contains("Max-Age=3600"));
    assert!(cookie.contains("SameSite=Lax"));
    // allow_non_ssl=true and http_only=false, so no HttpOnly
    assert!(!cookie.contains("HttpOnly"));
    assert!(!cookie.contains("Secure"));
}

#[test]
fn session_cookie_httponly_when_not_allow_non_ssl() {
    let config = sbproxy_config::SessionConfig {
        cookie_name: Some("sid".to_string()),
        max_age: Some(7200),
        http_only: false,
        secure: false,
        same_site: None,
        allow_non_ssl: false,
    };
    let cookie = build_session_cookie(&config, "abc");
    assert!(cookie.starts_with("sid=abc"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax")); // default
}

#[test]
fn session_cookie_secure_flag() {
    let config = sbproxy_config::SessionConfig {
        cookie_name: None,
        max_age: None,
        http_only: true,
        secure: true,
        same_site: Some("Strict".to_string()),
        allow_non_ssl: false,
    };
    let cookie = build_session_cookie(&config, "xyz");
    assert!(cookie.starts_with("sbproxy_sid=xyz")); // default name
    assert!(cookie.contains("Max-Age=3600")); // default max_age
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
}

#[test]
fn session_cookie_uuid_format() {
    let sid = uuid::Uuid::new_v4().to_string();
    // UUID v4 format: 8-4-4-4-12 hex chars
    assert_eq!(sid.len(), 36);
    assert_eq!(sid.chars().filter(|c| *c == '-').count(), 4);
}

// --- Callback URL parsing tests ---

#[test]
fn callback_url_extraction_from_go_format() {
    let configs = vec![
        serde_json::json!({
            "url": "http://127.0.0.1:18888/callback/on-request",
            "method": "POST",
            "timeout": 5,
            "on_error": "ignore"
        }),
        serde_json::json!({
            "url": "http://127.0.0.1:18888/callback/on-response",
            "method": "POST",
            "timeout": 5,
            "async": true,
            "on_error": "ignore"
        }),
    ];
    for cfg in &configs {
        let url = cfg.get("url").and_then(|v| v.as_str());
        assert!(url.is_some());
        assert!(url.unwrap().starts_with("http://"));
    }
}

#[test]
fn callback_method_defaults_to_post() {
    let cfg = serde_json::json!({
        "url": "http://example.com/callback"
    });
    let method = cfg.get("method").and_then(|v| v.as_str()).unwrap_or("POST");
    assert_eq!(method, "POST");
}

// --- Prompt extraction tests ---

#[test]
fn extract_prompt_text_openai_chat() {
    let body = serde_json::json!({
        "messages": [
            {"role": "system", "content": "be helpful"},
            {"role": "user", "content": "hello world"},
        ]
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("hello world"));
    assert!(out.contains("be helpful"));
}

#[test]
fn extract_prompt_text_multimodal_parts() {
    let body = serde_json::json!({
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "describe this"},
                {"type": "image_url", "image_url": {"url": "..."}},
                {"type": "text", "text": "please"},
            ]},
        ]
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("describe this"));
    assert!(out.contains("please"));
}

#[test]
fn extract_prompt_text_legacy_prompt_field() {
    let body = serde_json::json!({ "prompt": "once upon a time" });
    assert_eq!(extract_prompt_text(&body), "once upon a time");
}

#[test]
fn extract_prompt_text_anthropic_system_string() {
    let body = serde_json::json!({
        "system": "you are an expert",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("you are an expert"), "{out}");
    assert!(out.contains("hi"), "{out}");
}

#[test]
fn extract_prompt_text_anthropic_system_block_array() {
    let body = serde_json::json!({
        "system": [
            {"type": "text", "text": "follow the rules"},
            {"type": "text", "text": "stay terse"}
        ],
        "messages": []
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("follow the rules"), "{out}");
    assert!(out.contains("stay terse"), "{out}");
}

#[test]
fn extract_prompt_text_image_block_emits_placeholder() {
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "data:..."}},
            {"type": "text", "text": "what is this"}
        ]}]
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("[image]"), "{out}");
    assert!(out.contains("what is this"), "{out}");
}

#[test]
fn extract_prompt_text_anthropic_tool_use_serialises_input() {
    let body = serde_json::json!({
        "messages": [{"role": "assistant", "content": [
            {"type": "tool_use", "name": "search", "input": {"q": "rust async"}}
        ]}]
    });
    let out = extract_prompt_text(&body);
    // The tool's input JSON should be present so classifiers see it.
    assert!(out.contains("rust async"), "{out}");
}

#[test]
fn extract_prompt_text_anthropic_tool_result_extracts_content() {
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"type": "tool_result", "content": "search returned 3 hits"}
        ]}]
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("search returned 3 hits"), "{out}");
}

#[test]
fn extract_prompt_text_openai_tool_calls_arguments() {
    let body = serde_json::json!({
        "messages": [{
            "role": "assistant",
            "tool_calls": [{
                "id": "1",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{\"sku\":\"A123\"}"}
            }]
        }]
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("A123"), "tool_call args missing: {out}");
}

#[test]
fn extract_prompt_text_responses_api_input_string() {
    let body = serde_json::json!({ "input": "responses api prompt" });
    assert_eq!(extract_prompt_text(&body), "responses api prompt");
}

#[test]
fn extract_prompt_text_responses_api_input_array() {
    let body = serde_json::json!({
        "input": [
            {"type": "text", "text": "first"},
            {"type": "text", "text": "second"}
        ]
    });
    let out = extract_prompt_text(&body);
    assert!(out.contains("first") && out.contains("second"), "{out}");
}

#[test]
fn extract_prompt_text_empty_body_returns_empty() {
    let body = serde_json::json!({});
    assert_eq!(extract_prompt_text(&body), "");
}

// --- Access log emission tests ---
//
// These exercise `emit_access_log_entry` (the pure builder + sampler)
// under a minimal `tracing::Subscriber` that captures lines targeted
// at `access_log`. Avoids a Pingora `Session` and avoids the full
// `tracing-subscriber` dependency surface, so the test stays a unit
// test and ships nothing new through the dependency tree.

use std::sync::{Arc, Mutex};

/// Captures `access_log`-targeted events into a shared vec. Implements
/// `tracing::Subscriber` directly so this stays in `[dev-dependencies]`
/// without the `tracing-subscriber` crate.
struct CapturingSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

impl CapturingSubscriber {
    fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                lines: lines.clone(),
            },
            lines,
        )
    }
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "access_log"
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() != "access_log" {
            return;
        }
        struct Visitor<'a>(&'a mut Option<String>);
        impl tracing::field::Visit for Visitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    *self.0 = Some(value.to_string());
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    *self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut msg: Option<String> = None;
        event.record(&mut Visitor(&mut msg));
        if let Some(m) = msg {
            // The redactor wraps unknown payload in quotes via Debug; strip
            // a single surrounding pair if present so callers see the raw
            // JSON line they expect.
            let trimmed = if m.starts_with('"') && m.ends_with('"') {
                m[1..m.len() - 1].replace("\\\"", "\"")
            } else {
                m
            };
            self.lines.lock().unwrap().push(trimmed);
        }
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn make_cfg(sample_rate: f64) -> sbproxy_config::AccessLogConfig {
    sbproxy_config::AccessLogConfig {
        enabled: true,
        sample_rate,
        status_codes: vec![],
        methods: vec![],
        capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        ..Default::default()
    }
}

/// Drive the emit path under a captured subscriber and return the
/// recorded lines. Helper keeps each test focused on its assertion.
fn run_with_capture<F: FnOnce()>(f: F) -> Vec<String> {
    let (sub, lines) = CapturingSubscriber::new();
    tracing::subscriber::with_default(sub, f);
    let v = lines.lock().unwrap().clone();
    v
}

#[test]
fn access_log_emits_json_line_when_enabled() {
    let cfg = make_cfg(1.0);
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "GET",
            "api.example.com",
            "/health",
            0.012,
            "req-001".to_string(),
            "10.0.0.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
    });
    assert_eq!(lines.len(), 1, "expected one line, got: {lines:?}");
    let parsed: serde_json::Value = serde_json::from_str(&lines[0])
        .unwrap_or_else(|e| panic!("emitted line not JSON: {e}: {}", lines[0]));
    assert_eq!(parsed["request_id"], "req-001");
    assert_eq!(parsed["origin"], "api.example.com");
    assert_eq!(parsed["method"], "GET");
    assert_eq!(parsed["path"], "/health");
    assert_eq!(parsed["status"], 200);
    assert_eq!(parsed["client_ip"], "10.0.0.1");
    assert!((parsed["latency_ms"].as_f64().unwrap() - 12.0).abs() < 1e-6);
}

#[test]
fn access_log_skips_when_disabled() {
    let cfg = sbproxy_config::AccessLogConfig {
        enabled: false,
        sample_rate: 1.0,
        status_codes: vec![],
        methods: vec![],
        capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        ..Default::default()
    };
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "GET",
            "api.example.com",
            "/",
            0.001,
            "req".to_string(),
            "1.1.1.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
    });
    assert!(lines.is_empty(), "no line should be emitted when disabled");
}

#[test]
fn access_log_status_filter_drops_unmatched() {
    let cfg = sbproxy_config::AccessLogConfig {
        enabled: true,
        sample_rate: 1.0,
        status_codes: vec![500],
        methods: vec![],
        capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        ..Default::default()
    };
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "GET",
            "api.example.com",
            "/",
            0.001,
            "r1".to_string(),
            "1.1.1.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
        emit_access_log_entry(
            &cfg,
            500,
            "GET",
            "api.example.com",
            "/",
            0.001,
            "r2".to_string(),
            "1.1.1.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
    });
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(parsed["request_id"], "r2");
}

#[test]
fn access_log_method_filter_drops_unmatched() {
    let cfg = sbproxy_config::AccessLogConfig {
        enabled: true,
        sample_rate: 1.0,
        status_codes: vec![],
        methods: vec!["POST".to_string()],
        capture_headers: sbproxy_config::CaptureHeadersConfig::default(),
        ..Default::default()
    };
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "GET",
            "api.example.com",
            "/",
            0.001,
            "r1".to_string(),
            "1.1.1.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
        emit_access_log_entry(
            &cfg,
            201,
            "post",
            "api.example.com",
            "/",
            0.001,
            "r2".to_string(),
            "1.1.1.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
    });
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(parsed["request_id"], "r2");
}

#[test]
fn access_log_sampling_emits_roughly_target_fraction() {
    // Drive 1000 calls at sample_rate=0.9. Expected ~900 lines; allow a
    // healthy margin so this stays stable across rand seeds.
    let cfg = make_cfg(0.9);
    let lines = run_with_capture(|| {
        for i in 0..1000 {
            emit_access_log_entry(
                &cfg,
                200,
                "GET",
                "api.example.com",
                "/",
                0.001,
                format!("r{i}"),
                "1.1.1.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
        }
    });
    let n = lines.len();
    assert!(
        (820..=970).contains(&n),
        "expected ~900 lines at sample_rate=0.9, got {n}"
    );
}

#[test]
fn access_log_zero_sample_rate_drops_all() {
    let cfg = make_cfg(0.0);
    let lines = run_with_capture(|| {
        for i in 0..50 {
            emit_access_log_entry(
                &cfg,
                200,
                "GET",
                "api.example.com",
                "/",
                0.001,
                format!("r{i}"),
                "1.1.1.1".to_string(),
                None,
                AccessLogContext::empty(),
            );
        }
    });
    assert!(lines.is_empty(), "sample_rate=0.0 should drop everything");
}

#[test]
fn access_log_slow_request_bypasses_sampler() {
    let mut cfg = make_cfg(0.0);
    cfg.slow_request_threshold_ms = Some(1000.0);
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "GET",
            "api.example.com",
            "/slow",
            1.2,
            "slow".to_string(),
            "1.1.1.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
    });
    assert_eq!(lines.len(), 1, "slow request should force emit");
}

#[test]
fn access_log_error_bypasses_sampler() {
    let mut cfg = make_cfg(0.0);
    cfg.always_log_errors = true;
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            503,
            "GET",
            "api.example.com",
            "/error",
            0.001,
            "err".to_string(),
            "1.1.1.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
    });
    assert_eq!(lines.len(), 1, "5xx should force emit");
}

#[test]
fn access_log_file_output_writes_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("access.log");
    let mut cfg = make_cfg(1.0);
    cfg.output = sbproxy_config::AccessLogOutputConfig {
        output_type: "file".to_string(),
        path: Some(path.to_string_lossy().into_owned()),
        max_size_mb: 1,
        max_backups: 2,
        compress: false,
    };

    emit_access_log_entry(
        &cfg,
        200,
        "GET",
        "api.example.com",
        "/file",
        0.001,
        "file".to_string(),
        "1.1.1.1".to_string(),
        None,
        AccessLogContext::empty(),
    );

    let contents = std::fs::read_to_string(path).unwrap();
    assert!(contents.contains("\"request_id\":\"file\""));
}

#[test]
fn access_log_propagates_trace_id_when_present() {
    let cfg = make_cfg(1.0);
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "GET",
            "api.example.com",
            "/",
            0.001,
            "req".to_string(),
            "1.1.1.1".to_string(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            AccessLogContext::empty(),
        );
    });
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(parsed["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
}

// --- WOR-118: PII redaction across non-header fields ---

/// Build a context populated with PII payloads in every typed slot
/// the WOR-118 redactor touches: `user_id`, `model`, and a couple
/// of `properties` values (the keys are deliberately benign so we
/// can assert they survive untouched).
fn ctx_with_pii() -> AccessLogContext {
    let mut ctx = AccessLogContext::empty();
    ctx.user_id = Some("user alice@example.com".to_string());
    ctx.model = Some("gpt-4 trained for jane@corp.com".to_string());
    let mut props = std::collections::BTreeMap::new();
    props.insert(
        "contact".to_string(),
        "reach me at bob@example.com".to_string(),
    );
    props.insert("ssn".to_string(), "id 123-45-6789".to_string());
    ctx.properties = props;
    ctx
}

#[test]
fn wor_118_redacts_path_when_other_fields_knob_is_on() {
    let mut cfg = make_cfg(1.0);
    cfg.capture_headers.redact_pii_other_fields = true;
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "GET",
            "api.example.com",
            "/users/alice@example.com/profile",
            0.001,
            "req-path".to_string(),
            "10.0.0.1".to_string(),
            None,
            AccessLogContext::empty(),
        );
    });
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let path = parsed["path"].as_str().unwrap().to_string();
    assert!(
        !path.contains("alice@example.com"),
        "email leaked into path: {path}"
    );
    assert!(
        path.contains("[REDACTED:EMAIL]"),
        "redactor token marker missing from path: {path}"
    );
    // Surrounding path structure should survive so log analytics
    // can still group by route shape.
    assert!(path.starts_with("/users/"));
    assert!(path.ends_with("/profile"));
}

#[test]
fn wor_118_redacts_user_id_model_and_properties_when_knob_is_on() {
    let mut cfg = make_cfg(1.0);
    cfg.capture_headers.redact_pii_other_fields = true;
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "POST",
            "api.example.com",
            "/v1/chat",
            0.002,
            "req-other".to_string(),
            "10.0.0.1".to_string(),
            None,
            ctx_with_pii(),
        );
    });
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let line = &lines[0];

    // No raw PII anywhere on the line.
    assert!(!line.contains("alice@example.com"), "user_id leaked");
    assert!(!line.contains("jane@corp.com"), "model leaked");
    assert!(!line.contains("bob@example.com"), "properties value leaked");
    assert!(!line.contains("123-45-6789"), "SSN in properties leaked");

    // Properties keys are intentionally untouched.
    assert!(parsed["properties"].get("contact").is_some());
    assert!(parsed["properties"].get("ssn").is_some());
    // Properties values are scrubbed.
    let contact = parsed["properties"]["contact"].as_str().unwrap();
    let ssn = parsed["properties"]["ssn"].as_str().unwrap();
    assert!(contact.contains("[REDACTED:EMAIL]"));
    assert!(ssn.contains("[REDACTED:SSN]"));
    // user_id and model carry the marker too.
    assert!(parsed["user_id"]
        .as_str()
        .unwrap()
        .contains("[REDACTED:EMAIL]"));
    assert!(parsed["model"]
        .as_str()
        .unwrap()
        .contains("[REDACTED:EMAIL]"));
}

#[test]
fn wor_118_default_off_leaves_typed_fields_alone() {
    // Default behaviour: knob is false. The cheap `redact_secrets`
    // pass still runs at emit time, but it does NOT match emails or
    // bare SSNs, so the typed fields survive verbatim. This is the
    // backward-compat regression case for WOR-118.
    let cfg = make_cfg(1.0);
    assert!(
        !cfg.capture_headers.redact_pii_other_fields,
        "default-off precondition for WOR-118"
    );
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "POST",
            "api.example.com",
            "/users/alice@example.com/profile",
            0.002,
            "req-default".to_string(),
            "10.0.0.1".to_string(),
            None,
            ctx_with_pii(),
        );
    });
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    // Email / SSN classes are NOT in the cheap secret-key regex
    // set, so they should appear verbatim with the knob off.
    assert!(line.contains("alice@example.com"));
    assert!(line.contains("jane@corp.com"));
    assert!(line.contains("bob@example.com"));
    assert!(line.contains("123-45-6789"));
}

#[test]
fn wor_118_scoped_rules_only_redact_matching_fields() {
    // With `redact_pii_rules: ["email"]`, emails are scrubbed but
    // SSNs are not. Confirms the same rule list flows from the
    // header-scope knob into the new other-fields scope.
    let mut cfg = make_cfg(1.0);
    cfg.capture_headers.redact_pii_other_fields = true;
    cfg.capture_headers.redact_pii_rules = vec!["email".to_string()];
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "POST",
            "api.example.com",
            "/v1/chat",
            0.002,
            "req-scoped".to_string(),
            "10.0.0.1".to_string(),
            None,
            ctx_with_pii(),
        );
    });
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let line = &lines[0];
    assert!(
        !line.contains("alice@example.com"),
        "email rule should fire"
    );
    // SSN should still appear: it is not in the scoped rule list.
    assert!(
        line.contains("123-45-6789"),
        "ssn rule was not enabled but SSN was redacted: {line}"
    );
    assert!(parsed["user_id"]
        .as_str()
        .unwrap()
        .contains("[REDACTED:EMAIL]"));
}

#[test]
fn wor_118_unknown_rule_names_are_a_safe_noop() {
    // No rule name matches: the redactor is not built and the
    // typed fields fall through unchanged. The cheap secret-key
    // pass still runs at emit time (covered by `redact_secrets`).
    let mut cfg = make_cfg(1.0);
    cfg.capture_headers.redact_pii_other_fields = true;
    cfg.capture_headers.redact_pii_rules = vec!["does_not_exist".to_string()];
    let lines = run_with_capture(|| {
        emit_access_log_entry(
            &cfg,
            200,
            "POST",
            "api.example.com",
            "/v1/chat",
            0.002,
            "req-noop".to_string(),
            "10.0.0.1".to_string(),
            None,
            ctx_with_pii(),
        );
    });
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert!(line.contains("alice@example.com"));
    assert!(line.contains("123-45-6789"));
}

// --- Wave 4 day-5: stamp_content_negotiation ---

#[test]
fn stamp_content_negotiation_with_markdown_accept_picks_markdown() {
    // auto_content_negotiate set, agent prefers markdown.
    let cfg = serde_json::json!({"type": "content_negotiate"});
    let mut ctx = RequestContext::new();
    stamp_content_negotiation(&mut ctx, Some(&cfg), Some("text/markdown"));
    assert_eq!(
        ctx.content_shape_transform,
        Some(sbproxy_modules::ContentShape::Markdown)
    );
    assert_eq!(
        ctx.content_shape_pricing,
        Some(sbproxy_modules::ContentShape::Markdown)
    );
}

#[test]
fn stamp_content_negotiation_wildcard_accept_uses_default_shape() {
    // Default shape is Json; wildcard Accept falls back to it.
    let cfg = serde_json::json!({
        "type": "content_negotiate",
        "default_content_shape": "json"
    });
    let mut ctx = RequestContext::new();
    stamp_content_negotiation(&mut ctx, Some(&cfg), Some("*/*"));
    assert_eq!(
        ctx.content_shape_transform,
        Some(sbproxy_modules::ContentShape::Json)
    );
}

#[test]
fn stamp_content_negotiation_legacy_origin_leaves_ctx_alone() {
    // No auto_content_negotiate => no-op; ctx fields stay None.
    let mut ctx = RequestContext::new();
    stamp_content_negotiation(&mut ctx, None, Some("text/markdown"));
    assert!(ctx.content_shape_pricing.is_none());
    assert!(ctx.content_shape_transform.is_none());
}

// --- Wave 4 day-5: apply_transform_with_ctx (Item 2 gating) ---

fn compiled_html_to_markdown() -> sbproxy_modules::CompiledTransform {
    let inner =
        sbproxy_modules::transform::HtmlToMarkdownTransform::from_config(serde_json::json!({}))
            .expect("default html_to_markdown");
    sbproxy_modules::CompiledTransform {
        transform: sbproxy_modules::Transform::HtmlToMarkdown(inner),
        content_types: vec![],
        fail_on_error: false,
        max_body_size: 10 * 1024 * 1024,
    }
}

fn compiled_boilerplate() -> sbproxy_modules::CompiledTransform {
    sbproxy_modules::CompiledTransform {
        transform: sbproxy_modules::Transform::Boilerplate(
            sbproxy_modules::BoilerplateTransform::default(),
        ),
        content_types: vec![],
        fail_on_error: false,
        max_body_size: 10 * 1024 * 1024,
    }
}

#[test]
fn apply_transform_html_pass_through_when_shape_is_html() {
    // Agent asked for text/html on an ai_crawl_control origin.
    // The Markdown projection must NOT run; body stays as raw HTML.
    let html = b"<html><body><h1>Hi</h1><p>Body</p></body></html>";
    let mut buf = bytes::BytesMut::from(&html[..]);
    let mut ctx = RequestContext::new();
    ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Html);

    let compiled = compiled_html_to_markdown();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

    // Body unchanged.
    assert_eq!(&buf[..], html);
    // Projection NOT stamped.
    assert!(ctx.markdown_projection.is_none());
    assert!(ctx.markdown_token_estimate.is_none());
}

#[test]
fn apply_transform_html_to_markdown_runs_when_shape_is_markdown() {
    let html = b"<html><body><h1>Hi</h1><p>Body</p></body></html>";
    let mut buf = bytes::BytesMut::from(&html[..]);
    let mut ctx = RequestContext::new();
    ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Markdown);

    let compiled = compiled_html_to_markdown();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

    // Projection stamped.
    assert!(ctx.markdown_projection.is_some());
    assert!(ctx.markdown_token_estimate.is_some());
    // Body is now Markdown (no HTML tags).
    let body_str = std::str::from_utf8(&buf).unwrap();
    assert!(!body_str.contains("<html>"));
    assert!(body_str.contains("Body"));
}

#[test]
fn apply_transform_legacy_origin_runs_html_to_markdown() {
    // Legacy origin: shape == None. Operator may have explicitly
    // wired `html_to_markdown` so we still run it.
    let html = b"<p>Hello</p>";
    let mut buf = bytes::BytesMut::from(&html[..]);
    let mut ctx = RequestContext::new();
    // ctx.content_shape_transform stays None.

    let compiled = compiled_html_to_markdown();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

    assert!(ctx.markdown_projection.is_some());
}

#[test]
fn apply_transform_boilerplate_stamps_stripped_bytes() {
    // Boilerplate stripping reports the byte count it removed.
    let html = br#"<html><body><nav>nav stuff</nav><main>real content</main></body></html>"#;
    let mut buf = bytes::BytesMut::from(&html[..]);
    let mut ctx = RequestContext::new();

    let compiled = compiled_boilerplate();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

    // The boilerplate transform removes nav/footer/aside chrome.
    assert!(
        ctx.metrics.stripped_bytes > 0,
        "boilerplate.apply should report stripped bytes onto ctx.metrics"
    );
}

// --- Wave 4 day-5 Item 3: JsonEnvelope typed dispatch ---

fn compiled_json_envelope() -> sbproxy_modules::CompiledTransform {
    sbproxy_modules::CompiledTransform {
        transform: sbproxy_modules::Transform::JsonEnvelope(
            sbproxy_modules::JsonEnvelopeTransform::default(),
        ),
        content_types: vec![],
        fail_on_error: false,
        max_body_size: 10 * 1024 * 1024,
    }
}

#[test]
fn apply_transform_json_envelope_writes_v1_envelope() {
    // Shape=Json + projection set => transform writes envelope.
    let mut buf = bytes::BytesMut::from(&b"<p>upstream html</p>"[..]);
    let mut ctx = RequestContext::new();
    ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Json);
    ctx.markdown_projection = Some(sbproxy_modules::MarkdownProjection {
        body: "# Hi\n\nBody.".to_string(),
        title: Some("Hi".to_string()),
        token_estimate: 5,
    });
    ctx.canonical_url = Some("https://example.com/foo".to_string());
    ctx.citation_required = Some(true);

    let compiled = compiled_json_envelope();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

    let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(parsed["schema_version"], "1");
    assert_eq!(parsed["title"], "Hi");
    assert_eq!(parsed["url"], "https://example.com/foo");
    assert_eq!(parsed["citation_required"], true);
}

#[test]
fn apply_transform_json_envelope_falls_through_when_projection_missing() {
    // Shape=Json but no projection => transform falls through;
    // body unchanged.
    let original = b"<p>upstream</p>";
    let mut buf = bytes::BytesMut::from(&original[..]);
    let mut ctx = RequestContext::new();
    ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Json);
    // ctx.markdown_projection stays None.

    let compiled = compiled_json_envelope();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/html"), &mut ctx).unwrap();

    assert_eq!(&buf[..], original);
}

// --- Wave 4 day-5 Item 4: CitationBlock typed dispatch ---

fn compiled_citation_block() -> sbproxy_modules::CompiledTransform {
    sbproxy_modules::CompiledTransform {
        transform: sbproxy_modules::Transform::CitationBlock(
            sbproxy_modules::CitationBlockTransform::default(),
        ),
        content_types: vec![],
        fail_on_error: false,
        max_body_size: 10 * 1024 * 1024,
    }
}

#[test]
fn apply_transform_citation_block_prepends_when_required() {
    let original = b"# Title\n\nBody.";
    let mut buf = bytes::BytesMut::from(&original[..]);
    let mut ctx = RequestContext::new();
    ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Markdown);
    ctx.canonical_url = Some("https://example.com/x".to_string());
    ctx.citation_required = Some(true);

    let compiled = compiled_citation_block();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/markdown"), &mut ctx).unwrap();

    let s = std::str::from_utf8(&buf).unwrap();
    assert!(
        s.starts_with("> Citation required for AI training and inference."),
        "expected citation prefix; got: {s}"
    );
    assert!(s.contains("# Title"));
}

#[test]
fn apply_transform_citation_block_skipped_when_not_required() {
    let original = b"# Title\n\nBody.";
    let mut buf = bytes::BytesMut::from(&original[..]);
    let mut ctx = RequestContext::new();
    ctx.content_shape_transform = Some(sbproxy_modules::ContentShape::Markdown);
    ctx.citation_required = Some(false);

    let compiled = compiled_citation_block();
    apply_transform_with_ctx(&compiled, &mut buf, Some("text/markdown"), &mut ctx).unwrap();

    // Body unchanged.
    assert_eq!(&buf[..], original);
}

// --- Wave 4 day-5 Item 5: x-markdown-tokens header ---

#[test]
fn x_markdown_tokens_uses_cached_estimate_when_available() {
    let n = x_markdown_tokens_header_value(
        Some(sbproxy_modules::ContentShape::Markdown),
        Some(42),
        Some(800),
    );
    // Cached estimate wins over the body-len fallback.
    assert_eq!(n, Some(42));
}

#[test]
fn x_markdown_tokens_uses_body_len_fallback_when_no_estimate() {
    // 400 bytes * 0.25 ratio = 100 tokens.
    let n = x_markdown_tokens_header_value(
        Some(sbproxy_modules::ContentShape::Markdown),
        None,
        Some(400),
    );
    assert_eq!(n, Some(100));
}

#[test]
fn x_markdown_tokens_skipped_for_html_shape() {
    let n = x_markdown_tokens_header_value(
        Some(sbproxy_modules::ContentShape::Html),
        Some(42),
        Some(800),
    );
    assert_eq!(n, None);
}

#[test]
fn x_markdown_tokens_skipped_for_legacy_origin() {
    // Shape == None => legacy origin, no header.
    let n = x_markdown_tokens_header_value(None, Some(42), Some(800));
    assert_eq!(n, None);
}

// --- Content-Signal decision matrix (Wave 4 / G4.5) ---

#[test]
fn content_signal_ai_train_stamps_when_origin_sets_value() {
    let decision = resolve_content_signal_decision(true, Some("ai-train"), None);
    assert_eq!(decision, ContentSignalDecision::Stamp("ai-train".into()));
}

#[test]
fn content_signal_absent_origin_no_projection_skips() {
    // Legacy origin with neither the validated field nor the
    // projection cache enrolment: no header stamped.
    let decision = resolve_content_signal_decision(true, None, None);
    assert_eq!(decision, ContentSignalDecision::Skip);
}

#[test]
fn content_signal_skipped_for_non_2xx_responses() {
    // 402/406/etc. negotiation failures must not advertise the
    // signal because the body the agent sees may not be the
    // licensed content.
    let decision = resolve_content_signal_decision(false, Some("ai-train"), None);
    assert_eq!(decision, ContentSignalDecision::Skip);
}

#[test]
fn content_signal_falls_back_to_tdm_reservation_when_projection_enrolled_no_signal() {
    // Origin is enrolled (has ai_crawl_control) but asserts no
    // signal: TDM-Reservation: 1 fallback per A4.1 § "tdmrep.json".
    let decision = resolve_content_signal_decision(true, None, Some(None));
    assert_eq!(decision, ContentSignalDecision::TdmReservationFallback);
}

#[test]
fn content_signal_legacy_extensions_path_still_stamps() {
    // Older configs set content_signal via the projection cache
    // (extensions["content_signal"]). The fallback path resolves
    // the value when CompiledOrigin.content_signal is None.
    let decision = resolve_content_signal_decision(true, None, Some(Some("search")));
    assert_eq!(decision, ContentSignalDecision::Stamp("search".into()));
}

// --- G4.5..G4.8 follow-up: projection routes ---

#[test]
fn projection_kind_recognises_all_four_well_known_paths() {
    assert_eq!(projection_kind_for_path("/robots.txt"), Some("robots"));
    assert_eq!(projection_kind_for_path("/llms.txt"), Some("llms"));
    assert_eq!(
        projection_kind_for_path("/llms-full.txt"),
        Some("llms-full")
    );
    assert_eq!(projection_kind_for_path("/licenses.xml"), Some("licenses"));
    assert_eq!(
        projection_kind_for_path("/.well-known/tdmrep.json"),
        Some("tdmrep"),
    );
}

#[test]
fn projection_kind_returns_none_for_unrelated_paths() {
    assert_eq!(projection_kind_for_path("/"), None);
    assert_eq!(projection_kind_for_path("/articles/foo"), None);
    // Trailing slash, query, or capitalisation are not the
    // canonical paths and must not match.
    assert_eq!(projection_kind_for_path("/robots.txt/"), None);
    assert_eq!(projection_kind_for_path("/Robots.txt"), None);
}

#[test]
fn projection_content_type_matches_each_kind() {
    // Robots / llms: text/plain per IETF draft-koster-rep-ai +
    // Anthropic / Mistral convention.
    assert_eq!(
        projection_content_type("robots"),
        "text/plain; charset=utf-8"
    );
    assert_eq!(projection_content_type("llms"), "text/plain; charset=utf-8");
    assert_eq!(
        projection_content_type("llms-full"),
        "text/plain; charset=utf-8"
    );
    // Licenses: application/xml per RSL 1.0.
    assert_eq!(projection_content_type("licenses"), "application/xml");
    // Tdmrep: application/json per W3C TDMRep.
    assert_eq!(projection_content_type("tdmrep"), "application/json");
}

#[test]
fn projection_content_type_unknown_kind_falls_back_to_text_plain() {
    // Defensive default: unrecognised kinds (only possible from a
    // future code path that adds a new kind without a Content-Type
    // mapping) get a safe text/plain fallback.
    assert_eq!(projection_content_type("future-kind"), "text/plain");
}

// --- A4.2 follow-up: token_bytes_ratio override threading ---

#[test]
fn x_markdown_tokens_uses_per_origin_ratio_when_overriden() {
    // Cached estimate absent -> fallback uses the per-origin
    // ratio. Doubled ratio (0.5) over a 1000-byte body should
    // produce 500 tokens; default 0.25 produces 250.
    let with_override = x_markdown_tokens_header_value_with_ratio(
        Some(sbproxy_modules::ContentShape::Markdown),
        None,
        Some(1000),
        Some(0.5),
    );
    assert_eq!(with_override, Some(500));

    let without_override = x_markdown_tokens_header_value_with_ratio(
        Some(sbproxy_modules::ContentShape::Markdown),
        None,
        Some(1000),
        None,
    );
    assert_eq!(without_override, Some(250));
}

// --- Wave 5 day-4 plugin-trait wiring tests ---
//
// Pin the per-call-site contract for the IdentityResolverHook,
// MlClassifierHook, and AnomalyDetectorHook trait wires. These do
// not exercise the request_filter end-to-end (that lives in the
// e2e suite); they pin the small mapping helpers and the registry
// iteration semantics so a future refactor of the call site cannot
// silently regress the contract.

#[cfg(feature = "agent-class")]
#[test]
fn agent_id_source_label_round_trips_for_kya() {
    // Compile-time guard: the label string the IdentityResolverHook
    // emits must round-trip back to the closed
    // `sbproxy_classifiers::AgentIdSource::Kya` variant. The wire
    // does this mapping inline; this test pins the canonical
    // string.
    let src = sbproxy_classifiers::AgentIdSource::Kya;
    assert_eq!(src.as_str(), "kya");
}

#[cfg(feature = "agent-class")]
#[test]
fn agent_id_source_label_round_trips_for_ml_override() {
    let src = sbproxy_classifiers::AgentIdSource::MlOverride;
    assert_eq!(src.as_str(), "ml_override");
}

#[tokio::test]
async fn identity_hook_registry_iterates_registered_hooks() {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct CountingHook {
        calls: Arc<Mutex<u32>>,
    }
    impl sbproxy_plugin::IdentityResolverHook for CountingHook {
        fn resolve<'a>(
            &'a self,
            _req: &'a sbproxy_plugin::IdentityRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Option<sbproxy_plugin::IdentityVerdict>> + Send + 'a>>
        {
            *self.calls.lock().unwrap() += 1;
            Box::pin(async move { None })
        }
    }

    let calls = Arc::new(Mutex::new(0_u32));
    sbproxy_plugin::register_identity_hook(Arc::new(CountingHook {
        calls: calls.clone(),
    }));

    // Drive the iteration through the same registry the wire uses.
    struct EmptyHeaders;
    impl sbproxy_plugin::IdentityHeaderLookup for EmptyHeaders {
        fn get(&self, _name: &str) -> Option<&str> {
            None
        }
    }
    let headers = EmptyHeaders;
    let req = sbproxy_plugin::IdentityRequest {
        headers: &headers,
        hostname: "test.example.com",
        prior_agent_id: None,
    };
    let hooks = sbproxy_plugin::identity_hooks();
    for hook in hooks.iter() {
        let _ = hook.resolve(&req).await;
    }
    // Our hook ran at least once.
    assert!(*calls.lock().unwrap() >= 1);
    // Suppress unused import warning.
    let _ = HashMap::<&str, &str>::new();
}

#[cfg(feature = "agent-classifier")]
#[tokio::test]
async fn ml_classifier_hook_registry_iterates_registered_hooks() {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct CountingHook {
        calls: Arc<Mutex<u32>>,
    }
    impl sbproxy_plugin::MlClassifierHook for CountingHook {
        fn classify<'a>(
            &'a self,
            _snap: &'a sbproxy_plugin::RequestSnapshotView<'a>,
        ) -> Pin<Box<dyn Future<Output = Option<sbproxy_plugin::MlClassificationResult>> + Send + 'a>>
        {
            *self.calls.lock().unwrap() += 1;
            Box::pin(async move { None })
        }
    }

    let calls = Arc::new(Mutex::new(0_u32));
    sbproxy_plugin::register_ml_classifier_hook(Arc::new(CountingHook {
        calls: calls.clone(),
    }));
    let snap = sbproxy_plugin::RequestSnapshotView {
        method: "GET",
        path: "/",
        query: "",
        header_count: 0,
        body_size_bytes: None,
        accept_header: "",
        user_agent: "",
        cookie_present: false,
        ja4_fingerprint: None,
        ja4_trustworthy: false,
        known_headless: false,
        agent_id_source: None,
        client_ip: None,
    };
    for hook in sbproxy_plugin::ml_classifier_hooks().iter() {
        let _ = hook.classify(&snap).await;
    }
    assert!(*calls.lock().unwrap() >= 1);
}

#[tokio::test]
async fn anomaly_hook_registry_iterates_registered_hooks() {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct CountingHook {
        calls: Arc<Mutex<u32>>,
    }
    impl sbproxy_plugin::AnomalyDetectorHook for CountingHook {
        fn analyze<'a>(
            &'a self,
            _ctx: &'a sbproxy_plugin::RequestContextView<'a>,
        ) -> Pin<Box<dyn Future<Output = Vec<sbproxy_plugin::AnomalyVerdict>> + Send + 'a>>
        {
            *self.calls.lock().unwrap() += 1;
            Box::pin(async move { Vec::new() })
        }
    }

    let calls = Arc::new(Mutex::new(0_u32));
    sbproxy_plugin::register_anomaly_hook(Arc::new(CountingHook {
        calls: calls.clone(),
    }));
    let view = sbproxy_plugin::RequestContextView {
        hostname: "test.example.com",
        method: "GET",
        path: "/",
        query: "",
        agent_id: None,
        agent_id_source: None,
        ja4_fingerprint: None,
        ja4_trustworthy: false,
        headless_library: None,
        client_ip: None,
    };
    for hook in sbproxy_plugin::anomaly_hooks().iter() {
        let _ = hook.analyze(&view).await;
    }
    assert!(*calls.lock().unwrap() >= 1);
}

#[test]
fn missing_hooks_are_no_op() {
    // The pipeline already runs without registered hooks (the OSS
    // build registers none). This test pins the contract: an empty
    // registry returns Vec::new() / None and never panics.
    // Iteration over an empty Vec is a no-op.
    let identity = sbproxy_plugin::identity_hooks();
    let _: Vec<_> = identity.iter().collect();
    let ml = sbproxy_plugin::ml_classifier_hooks();
    let _: Vec<_> = ml.iter().collect();
    let anomaly = sbproxy_plugin::anomaly_hooks();
    let _: Vec<_> = anomaly.iter().collect();
}

// --- Wave 5 day-6 Item 4: reload_from_config_path idempotence ---

#[test]
fn reload_from_config_path_is_idempotent_under_repeat_invocation() {
    use std::io::Write as _;
    // Bootstrap install function must produce the same observable
    // pipeline state when invoked multiple times against the same
    // unchanged config file. This pins the day-6 SIGHUP contract:
    // an operator who fires `kill -HUP` twice in a row gets the
    // same active pipeline as a single call (the second swap is
    // a no-op functionally; the ArcSwap accepts a fresh Arc but
    // the contents are equivalent).
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "reload.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#;
    tmp.write_all(yaml.as_bytes()).unwrap();
    tmp.flush().unwrap();

    // First reload populates the pipeline.
    reload_from_config_path(tmp.path().to_str().unwrap()).expect("first reload");
    let revision_one = reload::current_pipeline().config_revision.clone();

    // Second reload against the same file MUST succeed and MUST
    // produce the same revision (the revision is derived from
    // the host_map content so it is byte-stable for an unchanged
    // config).
    reload_from_config_path(tmp.path().to_str().unwrap()).expect("second reload");
    let revision_two = reload::current_pipeline().config_revision.clone();
    assert_eq!(
        revision_one, revision_two,
        "two reloads against the same config must yield the same revision",
    );

    // Third reload after a config rewrite must produce a DIFFERENT
    // revision so the operator-driven SIGHUP path is observable.
    let yaml_two = r#"
proxy:
  http_bind_port: 0
origins:
  "reload.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
  "second.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok-2"
"#;
    std::fs::write(tmp.path(), yaml_two).unwrap();
    reload_from_config_path(tmp.path().to_str().unwrap()).expect("third reload");
    let revision_three = reload::current_pipeline().config_revision.clone();
    assert_ne!(
        revision_two, revision_three,
        "a reload after a config change must yield a fresh revision",
    );
}

#[test]
fn reload_from_config_path_propagates_compile_errors() {
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    // Hard-broken YAML: missing colon, bad indent.
    tmp.write_all(b"proxy: !! no\n  origins ....\n").unwrap();
    tmp.flush().unwrap();
    let err = reload_from_config_path(tmp.path().to_str().unwrap()).expect_err("expected err");
    let _ = format!("{err}");
}

// --- WOR-43: CSP report redaction ---

#[test]
fn csp_report_redacts_query_string_in_document_uri() {
    let body = br#"{
            "csp-report": {
                "document-uri": "https://example.com/page?token=abc&user=42",
                "violated-directive": "script-src 'self'",
                "blocked-uri": "https://evil.example/inject.js?session=xyz",
                "effective-directive": "script-src",
                "original-policy": "default-src 'self'; script-src 'self'"
            }
        }"#;
    let r = redact_csp_report(body);
    let doc = r.document_uri.expect("document_uri");
    assert!(
        doc.contains("?[redacted]"),
        "query string must be redacted, got: {doc}"
    );
    assert!(!doc.contains("token=abc"), "token must not appear: {doc}");
    let blocked = r.blocked_uri.expect("blocked_uri");
    assert!(
        blocked.contains("?[redacted]"),
        "blocked_uri query must be redacted, got: {blocked}"
    );
    assert!(!blocked.contains("session=xyz"));
    assert_eq!(r.violated_directive.as_deref(), Some("script-src 'self'"));
    assert_eq!(r.effective_directive.as_deref(), Some("script-src"));
}

#[test]
fn csp_report_handles_reporting_api_envelope() {
    let body = br#"[{
            "type": "csp-violation",
            "body": {
                "documentURL": "https://example.com/page?id=abc",
                "blockedURL": "https://cdn.example/script.js"
            }
        }]"#;
    let r = redact_csp_report(body);
    let doc = r.document_uri.expect("document_uri");
    assert!(doc.contains("?[redacted]"), "got: {doc}");
    assert_eq!(
        r.blocked_uri.as_deref(),
        Some("https://cdn.example/script.js"),
    );
}

#[test]
fn csp_report_caps_long_field_values() {
    // Build a directive value longer than the redaction cap.
    let long = "a".repeat(1024);
    let body = format!(
        r#"{{"csp-report":{{"violated-directive":"{long}"}}}}"#,
        long = long
    );
    let r = redact_csp_report(body.as_bytes());
    let v = r.violated_directive.expect("violated_directive");
    assert!(
        v.len() <= REDACTED_FIELD_CAP + 3, // "..." suffix
        "expected truncation, got len {}",
        v.len()
    );
    assert!(v.ends_with("..."));
}

#[test]
fn csp_report_unknown_fields_are_dropped() {
    let body = br#"{
            "csp-report": {
                "secret-field": "should not appear",
                "violated-directive": "script-src"
            }
        }"#;
    let r = redact_csp_report(body);
    // Only the known allowlist comes through.
    assert!(r.violated_directive.is_some());
    assert!(r.document_uri.is_none());
    assert!(r.blocked_uri.is_none());
}

#[test]
fn csp_report_invalid_json_returns_empty() {
    let r = redact_csp_report(b"not json {");
    assert_eq!(r, RedactedCspReport::default());
}

// --- WOR-45: SSRF guard ---

#[test]
fn ssrf_guard_rejects_metadata_ip_literal() {
    let err = guard_upstream("169.254.169.254", 80, false, &[])
        .expect_err("metadata endpoint must be blocked");
    let s = format!("{err}");
    assert!(s.contains("SSRF") || s.contains("private"), "got: {s}");
}

#[test]
fn ssrf_guard_allows_public_ip() {
    // 1.1.1.1 is a global anycast address; the validator's
    // private/loopback/link-local checks must not flag it.
    guard_upstream("1.1.1.1", 443, true, &[]).expect("public ip ok");
}

#[test]
fn ssrf_guard_allowlist_permits_metadata_range() {
    // Operator opted in to 169.254.0.0/16 (e.g. for a trusted IMDS
    // sidecar). The same URL that fails the default check now
    // passes when the resolved IP falls inside the allowlist.
    let allow: Vec<ipnetwork::IpNetwork> = vec!["169.254.0.0/16".parse().expect("cidr")];
    guard_upstream("169.254.169.254", 80, false, &allow).expect("allowlisted private IP must pass");
}

#[test]
fn ssrf_guard_rejects_loopback_v6() {
    let err = guard_upstream("::1", 80, false, &[]).expect_err("loopback v6 blocked");
    let _ = format!("{err}");
}

// --- WOR-46: trust-bounded X-Forwarded-Proto ---

#[test]
fn https_decision_listener_tls_wins() {
    // Direct TLS handshake: HTTPS regardless of XFP or peer trust.
    assert!(is_request_https(true, false, None));
    assert!(is_request_https(true, false, Some("http")));
    assert!(is_request_https(true, true, Some("https")));
}

#[test]
fn https_decision_xfp_ignored_from_untrusted_peer() {
    // Direct HTTP client claiming X-Forwarded-Proto: https must
    // NOT bypass the force_ssl redirect. This is the regression
    // test for WOR-46.
    assert!(!is_request_https(false, false, Some("https")));
    assert!(!is_request_https(false, false, Some("HTTPS")));
    assert!(!is_request_https(false, false, None));
}

#[test]
fn https_decision_xfp_honoured_from_trusted_peer() {
    // Peer is in trusted_proxies (CDN, ALB, sidecar): we honour
    // the forwarded scheme.
    assert!(is_request_https(false, true, Some("https")));
    assert!(is_request_https(false, true, Some("HTTPS")));
    assert!(!is_request_https(false, true, Some("http")));
    assert!(!is_request_https(false, true, None));
}

#[test]
fn problem_details_defaults_to_about_blank_type() {
    let pd = sbproxy_config::ProblemDetailsConfig {
        enabled: true,
        type_base_uri: None,
        include_detail: true,
    };
    let body = super::render_problem_details(503, "upstream timeout", &pd, "/v1/orders");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["type"], "about:blank");
    assert_eq!(v["title"], "Service Unavailable");
    assert_eq!(v["status"], 503);
    assert_eq!(v["detail"], "upstream timeout");
    assert_eq!(v["instance"], "/v1/orders");
}

#[test]
fn problem_details_uses_type_base_uri_and_strips_trailing_slash() {
    let pd = sbproxy_config::ProblemDetailsConfig {
        enabled: true,
        type_base_uri: Some("https://api.example.com/errors/".to_string()),
        include_detail: true,
    };
    let body = super::render_problem_details(404, "not found", &pd, "/missing");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["type"], "https://api.example.com/errors/404");
}

#[test]
fn problem_details_suppresses_detail_when_disabled() {
    let pd = sbproxy_config::ProblemDetailsConfig {
        enabled: true,
        type_base_uri: None,
        include_detail: false,
    };
    let body = super::render_problem_details(500, "internal: db driver panicked", &pd, "/health");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.get("detail").is_none(), "detail must be suppressed");
    assert_eq!(v["status"], 500);
    assert_eq!(v["instance"], "/health");
}

#[test]
fn problem_details_unknown_status_falls_back_to_generic_title() {
    // A non-standard status code with no canonical reason should
    // still produce valid JSON with a default title.
    let pd = sbproxy_config::ProblemDetailsConfig {
        enabled: true,
        type_base_uri: None,
        include_detail: true,
    };
    let body = super::render_problem_details(599, "weird", &pd, "/x");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    // 599 is not a registered IANA status: hyper's `http` crate
    // resolves no canonical reason, so we fall back to "Error".
    assert_eq!(v["title"], "Error");
    assert_eq!(v["status"], 599);
}

#[test]
fn map_upstream_failure_translates_pingora_etype_to_status_and_token() {
    use pingora_error::{Error, ErrorType};
    // Connect-phase timeouts surface as 504 / connection_timeout.
    let e = Error::new(ErrorType::ConnectTimedout);
    assert_eq!(
        super::map_upstream_failure(&e),
        (504, Some("connection_timeout"))
    );
    let e = Error::new(ErrorType::ReadTimedout);
    assert_eq!(
        super::map_upstream_failure(&e),
        (504, Some("connection_timeout"))
    );
    // Refused / no route -> 502 / connection_refused.
    let e = Error::new(ErrorType::ConnectRefused);
    assert_eq!(
        super::map_upstream_failure(&e),
        (502, Some("connection_refused"))
    );
    // TLS errors -> 502 / tls_protocol_error.
    let e = Error::new(ErrorType::TLSHandshakeFailure);
    assert_eq!(
        super::map_upstream_failure(&e),
        (502, Some("tls_protocol_error"))
    );
    let e = Error::new(ErrorType::InvalidCert);
    assert_eq!(
        super::map_upstream_failure(&e),
        (502, Some("tls_protocol_error"))
    );
    // Mid-stream loss -> 502 / connection_terminated.
    let e = Error::new(ErrorType::ConnectionClosed);
    assert_eq!(
        super::map_upstream_failure(&e),
        (502, Some("connection_terminated"))
    );
    let e = Error::new(ErrorType::ReadError);
    assert_eq!(
        super::map_upstream_failure(&e),
        (502, Some("connection_terminated"))
    );
    // Generic ConnectError -> 502 / http_request_error catch-all.
    let e = Error::new(ErrorType::ConnectError);
    assert_eq!(
        super::map_upstream_failure(&e),
        (502, Some("http_request_error"))
    );
    // HTTPStatus(N) -> (N, mapping). 504 maps back via proxy_status_error_token.
    let e = Error::new(ErrorType::HTTPStatus(504));
    assert_eq!(
        super::map_upstream_failure(&e),
        (504, Some("connection_timeout"))
    );
    // Unknown / catch-all -> 502 / http_request_error.
    let e = Error::new(ErrorType::UnknownError);
    assert_eq!(
        super::map_upstream_failure(&e),
        (502, Some("http_request_error"))
    );
}

// --- WOR-229: native bypass body helper ---

#[test]
fn wor_229_bypass_body_empty_model_returns_original_bytes() {
    let original = bytes::Bytes::from_static(
        br#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hi"}]}"#,
    );
    let out = super::make_native_bypass_body(&original, "").unwrap();
    // Empty resolved_model means the router did not map; passing
    // the original bytes through verbatim preserves the byte
    // forward guarantee of the bypass.
    assert_eq!(out.as_ref(), original.as_ref());
}

#[test]
fn wor_229_bypass_body_same_model_returns_original_bytes() {
    let original = bytes::Bytes::from_static(
        br#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hi"}]}"#,
    );
    let out = super::make_native_bypass_body(&original, "claude-3-5-sonnet").unwrap();
    // No mutation needed when the resolved model already matches
    // the body's model. The original bytes flow through.
    assert_eq!(out.as_ref(), original.as_ref());
}

#[test]
fn wor_229_bypass_body_remaps_model_when_router_chose_different() {
    let original = bytes::Bytes::from_static(
        br#"{"model":"sonnet-alias","messages":[{"role":"user","content":"hi"}]}"#,
    );
    let out = super::make_native_bypass_body(&original, "claude-3-5-sonnet-20241022").unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed["model"].as_str().unwrap(),
        "claude-3-5-sonnet-20241022"
    );
    assert_eq!(parsed["messages"][0]["role"].as_str().unwrap(), "user");
}

#[test]
fn wor_229_bypass_body_propagates_parse_errors() {
    let invalid = bytes::Bytes::from_static(b"{not valid json");
    let err = super::make_native_bypass_body(&invalid, "claude-3-5-sonnet").unwrap_err();
    assert!(err.is_syntax() || err.is_data());
}

// --- WOR-525: ARDP discovery JSON shape ---

#[test]
fn ardp_discovery_emits_required_top_level_keys() {
    let body =
        super::render_ardp_discovery("ws-1", "https", Some("agent.example.com"), true, true, true);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["schema_version"], "1");
    assert_eq!(v["agent_id"], "ws-1");
    assert!(v["endpoints"].is_object());
    assert!(v["capabilities"].is_array());
    assert_eq!(v["publisher"]["name"], "sbproxy");
    assert_eq!(v["publisher"]["url"], "https://sbproxy.dev");
}

#[test]
fn ardp_discovery_lists_all_endpoints_when_all_enabled() {
    let body =
        super::render_ardp_discovery("ws-1", "https", Some("agent.example.com"), true, true, true);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["endpoints"]["mcp"], "https://agent.example.com/mcp");
    assert_eq!(
        v["endpoints"]["agent_skills"],
        "https://agent.example.com/.well-known/agent-skills/index.json"
    );
    assert_eq!(
        v["endpoints"]["openapi"],
        "https://agent.example.com/.well-known/openapi.json"
    );
    let caps: Vec<String> = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(caps.contains(&"mcp.tools".to_string()));
    assert!(caps.contains(&"agent_skills.v0_2".to_string()));
    assert!(caps.contains(&"openapi".to_string()));
}

#[test]
fn ardp_discovery_omits_endpoint_keys_when_capability_off() {
    // Only MCP is configured; agent_skills and openapi keys must
    // not appear, and the capabilities array tracks the same set.
    let body = super::render_ardp_discovery(
        "ws-1",
        "https",
        Some("agent.example.com"),
        true,
        false,
        false,
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let endpoints = v["endpoints"].as_object().unwrap();
    assert!(endpoints.contains_key("mcp"));
    assert!(!endpoints.contains_key("agent_skills"));
    assert!(!endpoints.contains_key("openapi"));
    let caps: Vec<String> = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(caps, vec!["mcp.tools".to_string()]);
}

#[test]
fn ardp_discovery_emits_empty_endpoints_when_nothing_configured() {
    let body = super::render_ardp_discovery(
        "ws-1",
        "https",
        Some("agent.example.com"),
        false,
        false,
        false,
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["endpoints"].as_object().unwrap().is_empty());
    assert!(v["capabilities"].as_array().unwrap().is_empty());
}

#[test]
fn ardp_discovery_uses_relative_urls_when_host_authority_missing() {
    // Spec lets the client fill in the host when the proxy can't
    // resolve the inbound `Host` header; a path-absolute URL is
    // the safest fallback.
    let body = super::render_ardp_discovery("ws-1", "https", None, true, true, false);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["endpoints"]["mcp"], "/mcp");
    assert_eq!(
        v["endpoints"]["agent_skills"],
        "/.well-known/agent-skills/index.json"
    );
}

#[test]
fn ardp_discovery_respects_http_scheme() {
    let body = super::render_ardp_discovery(
        "ws-1",
        "http",
        Some("agent.example.com"),
        true,
        false,
        false,
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["endpoints"]["mcp"], "http://agent.example.com/mcp");
}

// --- WOR-636 graceful-shutdown grace period parser ---

#[test]
fn resolve_shutdown_grace_ms_preferred_over_seconds() {
    // The canonical spelling (`SBPROXY_SHUTDOWN_GRACE_MS`) wins
    // when both are set so the new env var fully supersedes the
    // legacy `SB_GRACE_TIME`.
    assert_eq!(
        super::resolve_shutdown_grace_seconds(Some("30000"), Some("5")),
        30
    );
}

#[test]
fn resolve_shutdown_grace_ms_rounds_up_to_seconds() {
    // 500ms must produce 1 second so partial seconds still give
    // in-flight requests at least one full second to drain.
    assert_eq!(super::resolve_shutdown_grace_seconds(Some("500"), None), 1);
    assert_eq!(super::resolve_shutdown_grace_seconds(Some("1001"), None), 2);
    // Zero stays zero (instant shutdown).
    assert_eq!(super::resolve_shutdown_grace_seconds(Some("0"), None), 0);
}

#[test]
fn resolve_shutdown_grace_falls_back_to_legacy_seconds() {
    // No SBPROXY_SHUTDOWN_GRACE_MS: read SB_GRACE_TIME.
    assert_eq!(super::resolve_shutdown_grace_seconds(None, Some("12")), 12);
}

#[test]
fn resolve_shutdown_grace_default_zero_when_both_unset() {
    // Both env vars unset: the in-process default is zero so the
    // Go e2e runner can rebind the listener between cases. The
    // binary wrapper overlays a 30s default before calling here.
    assert_eq!(super::resolve_shutdown_grace_seconds(None, None), 0);
}

#[test]
fn resolve_shutdown_grace_malformed_ms_falls_through() {
    // A non-numeric `SBPROXY_SHUTDOWN_GRACE_MS` is ignored (with
    // a warning the test cannot easily capture); the legacy
    // seconds value still wins.
    assert_eq!(
        super::resolve_shutdown_grace_seconds(Some("not-a-number"), Some("7")),
        7
    );
}

#[test]
fn resolve_shutdown_grace_malformed_seconds_falls_through_to_default() {
    // Both malformed: default to zero.
    assert_eq!(
        super::resolve_shutdown_grace_seconds(Some("nope"), Some("also-nope")),
        0
    );
}
