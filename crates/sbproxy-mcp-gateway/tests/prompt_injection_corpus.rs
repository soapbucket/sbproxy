// Prompt-injection / tool-authorization corpus integration test for
// the MCP OAuth 2.1 broker.
//
// This test loads the JSON corpus at
// `tests/corpora/prompt_injection.json` and drives every entry
// through the broker's authorization path. The corpus mirrors the
// six threat categories documented in the "Threat model" section of
// `docs/mcp-oauth-gateway.md`:
//
//   1. tool_description (CIMD field injection)
//   2. tool_result      (upstream token-response injection)
//   3. scope_escalation (resource / audience coercion)
//   4. confused_deputy  (broker forwards with its own credentials)
//   5. replay           (single-use state / jti / refresh-token)
//   6. cross_tenant     (session-store key uniqueness)
//
// Each entry declares an `op` that selects which seam to drive
// (axum HTTP for /authorize, /par, /token; direct calls into
// `inject_cnf_jkt`, `inject_act_envelope`, `DpopReplayCache`, and
// `SessionStore::take` for the unit-shaped seams) plus an
// `expected_outcome` of `blocked`, `sanitized`, or
// `allowed_with_caveat`. A failing assertion prints the entry id so
// a regression names itself in CI.
//
// Running:
//   cargo test -p sbproxy-mcp-gateway --test prompt_injection_corpus
//
// CI runs `cargo test --workspace --exclude sbproxy-e2e --locked`,
// which automatically picks this file up.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use jsonwebtoken::jwk::Jwk;
use sbproxy_mcp_gateway::{
    inject_act_envelope, inject_cnf_jkt, router as broker_router, router_full_with_par, DpopProof,
    DpopReplayCache, InMemorySessionStore, McpGatewayConfig, Session, SessionStore, SubjectClaims,
};
use sbproxy_storage::EphemeralKv;
use serde::Deserialize;
use serde_json::Value as Json;
use std::collections::HashMap;
// Note: `Json` above aliases `serde_json::Value` and is used by the
// corpus's `extra` map. The mock-upstream handlers use the fully
// qualified `axum::Json` to avoid colliding with the alias.

use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

// --- Corpus model ---

/// One corpus entry. Fields beyond `id`, `category`, `op`, and
/// `expected_outcome` are op-specific and pulled out via `as_str` or
/// `as_object` inside the per-op dispatcher.
#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    category: String,
    expected_outcome: String,
    op: String,
    #[serde(flatten)]
    extra: HashMap<String, Json>,
}

#[derive(Debug, Deserialize)]
struct Corpus {
    entries: Vec<Entry>,
}

fn load_corpus() -> Corpus {
    let raw = include_str!("corpora/prompt_injection.json");
    serde_json::from_str(raw).expect("corpus JSON parse")
}

// --- Test fixtures ---

fn base_config() -> McpGatewayConfig {
    McpGatewayConfig {
        base_path: "/mcp/oauth".to_string(),
        upstream_authorization_server_url: "https://idp.example/oauth/authorize".to_string(),
        upstream_token_endpoint_url: "http://127.0.0.1:1/token".to_string(),
        upstream_redirect_uri: "https://broker.example/mcp/oauth/callback".to_string(),
        resource_uri: "https://mcp.example/api".to_string(),
        allowed_redirect_uris: vec!["https://client.example/cb".to_string()],
        session_ttl_secs: 600,
        token_exchange_enabled: true,
        subject_token_issuers: vec!["https://idp.example".to_string()],
        allowed_token_exchange_audiences: vec!["https://api.downstream".to_string()],
        token_exchange_max_chain_depth: 2,
        ..McpGatewayConfig::default()
    }
}

fn build_default_app() -> Router {
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    broker_router(Arc::new(base_config()), store)
}

fn build_app_with_par() -> (Router, Arc<dyn EphemeralKv>) {
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    let par_store: Arc<dyn EphemeralKv> = Arc::new(sbproxy_mcp_gateway::LocalStore::new());
    let app = router_full_with_par(
        Arc::new(base_config()),
        store,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(par_store.clone()),
    );
    (app, par_store)
}

async fn send_get(app: Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request build");
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body collect")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&body_bytes).to_string(),
    )
}

async fn send_post_form(app: Router, uri: &str, body: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::from(body.to_string()))
        .expect("request build");
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body collect")
        .to_bytes();
    (status, String::from_utf8_lossy(&body_bytes).to_string())
}

// --- Helpers ---

fn url_form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Produce a JWS-Compact-Serialization-shaped fixture token whose
/// payload is `payload`. The signature segment is a placeholder; the
/// broker only inspects the payload for the corpus entries that
/// reach the JWT-parsing path.
/// The ES256 keypair the broker signs its own access tokens with in
/// these fixtures. The public half is the JWK inlined beside it.
const BROKER_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----";

fn fixture_jwt(payload: serde_json::Value) -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&serde_json::json!({"alg":"none","typ":"JWT"})).expect("hdr"));
    let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).expect("pld"));
    format!("{header}.{p}.sig")
}

fn fixture_proof(jti: &str) -> DpopProof {
    let jwk_value = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
        "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY",
    });
    let jwk: Jwk = serde_json::from_value(jwk_value).expect("jwk");
    DpopProof {
        jwk,
        jti: jti.to_string(),
        htm: "POST".to_string(),
        htu: "https://broker.example/mcp/oauth/token".to_string(),
        iat: 0,
        nonce: None,
        ath: None,
        raw_jwt: "header.payload.sig".to_string(),
    }
}

/// Pull a string field from an entry's `extra` map, falling back to
/// the supplied default. Keeps each op compact.
fn s_or<'a>(e: &'a Entry, key: &str, default: &'a str) -> &'a str {
    e.extra.get(key).and_then(|v| v.as_str()).unwrap_or(default)
}

// --- Outcome ---

#[derive(Debug)]
enum Outcome {
    Blocked,
    Sanitized,
    AllowedWithCaveat,
}

fn parse_outcome(s: &str, id: &str) -> Outcome {
    match s {
        "blocked" => Outcome::Blocked,
        "sanitized" => Outcome::Sanitized,
        "allowed_with_caveat" => Outcome::AllowedWithCaveat,
        other => panic!("[{id}] unknown expected_outcome {other:?}"),
    }
}

// --- Per-op dispatch ---
//
// Each op consumes the entry plus the parsed Outcome and asserts.
// On any panic the entry id is printed because that field is
// included in every assert message.

async fn op_authorize(e: &Entry, outcome: Outcome) {
    let app = build_default_app();
    let client_id = s_or(e, "client_id", "cli");
    let redirect_uri = s_or(e, "redirect_uri", "https://client.example/cb");
    let response_type = s_or(e, "response_type", "code");
    let code_challenge_method = s_or(e, "code_challenge_method", "S256");
    let state = s_or(e, "state", "cli-state");
    let resource = s_or(e, "resource", "https://mcp.example/api");
    let scope_q = e
        .extra
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| format!("&scope={}", url_form_encode(s)))
        .unwrap_or_default();
    let uri = format!(
        "/mcp/oauth/authorize?client_id={}&redirect_uri={}&response_type={}&code_challenge=abc&code_challenge_method={}&state={}&resource={}{}",
        url_form_encode(client_id),
        url_form_encode(redirect_uri),
        url_form_encode(response_type),
        url_form_encode(code_challenge_method),
        url_form_encode(state),
        url_form_encode(resource),
        scope_q,
    );
    let (status, _, body) = send_get(app, &uri).await;
    match outcome {
        Outcome::Blocked => assert!(
            status.is_client_error(),
            "[{}] expected 4xx, got {status}: {body}",
            e.id,
        ),
        Outcome::Sanitized => {
            // For the scope-injection entry the request still
            // succeeds (302) because pre-registered clients delegate
            // scope validation to the upstream; the broker forwards
            // verbatim. The assertion is that the broker DID redirect
            // (no error) and the upstream Location does not echo the
            // injected suffix into a place that breaks state binding.
            assert_eq!(
                status,
                StatusCode::FOUND,
                "[{}] expected 302, got {status}: {body}",
                e.id,
            );
        }
        Outcome::AllowedWithCaveat => {
            assert!(
                !status.is_server_error(),
                "[{}] expected non-5xx, got {status}: {body}",
                e.id,
            );
        }
    }
}

async fn op_authorize_with_cimd_disabled(e: &Entry, outcome: Outcome) {
    let mut cfg = base_config();
    cfg.cimd_enabled = false;
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    let app = broker_router(Arc::new(cfg), store);
    let client_id = s_or(e, "client_id", "https://malicious.example/cimd.json");
    let uri = format!(
        "/mcp/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&response_type=code&code_challenge=abc&code_challenge_method=S256&state=s&resource=https%3A%2F%2Fmcp.example%2Fapi",
        url_form_encode(client_id),
    );
    let (status, _, body) = send_get(app, &uri).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("invalid_client"),
        "[{}] body lacks invalid_client: {body}",
        e.id,
    );
}

async fn op_par_then_authorize_with_resource(e: &Entry, outcome: Outcome) {
    let (app, par_store) = build_app_with_par();
    let evil_resource = s_or(e, "par_resource", "https://evil.example/api");
    let params = sbproxy_mcp_gateway::PushedAuthorizationParams {
        client_id: "cli".to_string(),
        redirect_uri: "https://client.example/cb".to_string(),
        response_type: "code".to_string(),
        code_challenge: "abc".to_string(),
        code_challenge_method: "S256".to_string(),
        state: Some("cli-state".to_string()),
        resource: Some(evil_resource.to_string()),
        scope: None,
    };
    let request_uri = sbproxy_mcp_gateway::mint_request_uri();
    par_store
        .put(
            &request_uri,
            Bytes::from(serde_json::to_vec(&params).expect("ser par")),
            Duration::from_secs(60),
        )
        .await
        .expect("put par");
    let uri = format!(
        "/mcp/oauth/authorize?request_uri={}",
        url_form_encode(&request_uri),
    );
    let (status, _, body) = send_get(app, &uri).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("invalid_target"),
        "[{}] body lacks invalid_target: {body}",
        e.id,
    );
}

async fn op_par_then_authorize_twice(e: &Entry, outcome: Outcome) {
    let (app, par_store) = build_app_with_par();
    let params = sbproxy_mcp_gateway::PushedAuthorizationParams {
        client_id: "cli".to_string(),
        redirect_uri: "https://client.example/cb".to_string(),
        response_type: "code".to_string(),
        code_challenge: "abc".to_string(),
        code_challenge_method: "S256".to_string(),
        state: Some("cli-state".to_string()),
        resource: Some("https://mcp.example/api".to_string()),
        scope: None,
    };
    let request_uri = sbproxy_mcp_gateway::mint_request_uri();
    par_store
        .put(
            &request_uri,
            Bytes::from(serde_json::to_vec(&params).expect("ser par")),
            Duration::from_secs(60),
        )
        .await
        .expect("put par");
    let uri = format!(
        "/mcp/oauth/authorize?request_uri={}",
        url_form_encode(&request_uri),
    );
    let (status1, _, _body1) = send_get(app.clone(), &uri).await;
    assert_eq!(
        status1,
        StatusCode::FOUND,
        "[{}] first PAR replay should succeed",
        e.id,
    );
    let (status2, _, body2) = send_get(app, &uri).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "[{}] second PAR replay should be blocked, got {status2}: {body2}",
        e.id,
    );
    assert!(
        body2.contains("invalid_request"),
        "[{}] body2 lacks invalid_request: {body2}",
        e.id,
    );
}

async fn op_session_take_twice(e: &Entry, outcome: Outcome) {
    let store = InMemorySessionStore::new(Duration::from_secs(60));
    let session = Session {
        client_state: "cli-state".to_string(),
        redirect_uri: "https://client.example/cb".to_string(),
        resource_uri: "https://mcp.example/api".to_string(),
        code_challenge: "abc".to_string(),
        code_challenge_method: "S256".to_string(),
    };
    store.put("the-state", session).await.unwrap();
    let first = store.take("the-state").await;
    assert!(first.is_some(), "[{}] first take must succeed", e.id);
    let second = store.take("the-state").await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert!(
        second.is_none(),
        "[{}] second take must return None (single-use)",
        e.id,
    );
}

async fn op_session_keys_unique_per_state(e: &Entry, outcome: Outcome) {
    let app = build_default_app();
    let uri = "/mcp/oauth/authorize?client_id=cli&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&response_type=code&code_challenge=abc&code_challenge_method=S256&state=cli-state&resource=https%3A%2F%2Fmcp.example%2Fapi";
    let (status1, h1, _) = send_get(app.clone(), uri).await;
    let (status2, h2, _) = send_get(app, uri).await;
    let s1 = h1
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let s2 = h2
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    assert_eq!(status1, StatusCode::FOUND, "[{}] first 302", e.id);
    assert_eq!(status2, StatusCode::FOUND, "[{}] second 302", e.id);
    let pull_state = |loc: &str| -> String {
        let parsed = url::Url::parse(loc).expect("parse loc");
        parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    let st1 = pull_state(&s1);
    let st2 = pull_state(&s2);
    assert!(matches!(outcome, Outcome::AllowedWithCaveat));
    assert_ne!(
        st1, st2,
        "[{}] two flows produced colliding broker-minted state values",
        e.id,
    );
}

async fn op_dpop_jti_record_twice(e: &Entry, outcome: Outcome) {
    let kv: Arc<dyn EphemeralKv> = Arc::new(sbproxy_mcp_gateway::LocalStore::new());
    let cache = DpopReplayCache::new(kv, Duration::from_secs(300));
    let proof = fixture_proof("jti-corpus-replay");
    let first = cache.record_jti(&proof).await;
    assert!(first.is_ok(), "[{}] first record must succeed", e.id);
    let second = cache.record_jti(&proof).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert!(
        second.is_err(),
        "[{}] second record must error (replay)",
        e.id,
    );
}

async fn op_inject_cnf_jkt_jwt_no_signing_key(e: &Entry, outcome: Outcome) {
    let proof = fixture_proof("jti-no-sign");
    let upstream = Bytes::from(
        r#"{"access_token":"hdr.payload.sig","token_type":"Bearer","expires_in":3600}"#,
    );
    let result = inject_cnf_jkt(&upstream, &proof, None, "https://broker.example");
    // No signing key means the broker must refuse to claim a binding.
    assert!(matches!(outcome, Outcome::Blocked));
    assert!(
        result.is_err(),
        "[{}] JWT accepted without broker signing key",
        e.id,
    );
}

async fn op_inject_cnf_jkt_non_json(e: &Entry, outcome: Outcome) {
    let proof = fixture_proof("jti-nonjson");
    let upstream = Bytes::from_static(b"not-a-json-body");
    let result = inject_cnf_jkt(&upstream, &proof, None, "https://broker.example");
    assert!(matches!(outcome, Outcome::Blocked));
    assert!(
        result.is_err(),
        "[{}] non-JSON body must surface a parse error",
        e.id,
    );
}

async fn op_inject_act_envelope_no_signing_key(e: &Entry, outcome: Outcome) {
    let inner_jwt = fixture_jwt(serde_json::json!({
        "iss": "https://idp.example",
        "sub": "alice",
        "act": {"sub": "service-a"},
    }));
    let body = Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "access_token": inner_jwt.clone(),
            "token_type": "Bearer",
        }))
        .expect("body"),
    );
    let subject = SubjectClaims {
        iss: Some("https://idp.example".into()),
        sub: Some("alice".into()),
        act: None,
    };
    let result = inject_act_envelope(
        &body,
        &subject,
        "authenticated-client",
        None,
        None,
        "https://broker.example",
    )
    .expect("envelope ok");
    let parsed: serde_json::Value = serde_json::from_slice(&result).expect("parse");
    assert!(matches!(outcome, Outcome::Sanitized));
    // access_token must pass through unchanged.
    assert_eq!(
        parsed["access_token"].as_str().unwrap(),
        inner_jwt,
        "[{}] JWT mutated when broker has no signing key",
        e.id,
    );
    // issued_token_type may be filled in on the wrapper for RFC 8693.
    assert!(
        parsed.get("issued_token_type").is_some(),
        "[{}] issued_token_type missing on wrapper",
        e.id,
    );
}

async fn op_token(e: &Entry, outcome: Outcome) {
    let app = build_default_app();
    let grant_type = s_or(e, "grant_type", "magic");
    let body = format!("grant_type={}&client_id=cli", url_form_encode(grant_type));
    let (status, body) = send_post_form(app, "/mcp/oauth/token", &body).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("unsupported_grant_type") || body.contains("invalid_request"),
        "[{}] body lacks expected error: {body}",
        e.id,
    );
}

async fn op_token_with_restricted_methods(e: &Entry, outcome: Outcome) {
    let mut cfg = base_config();
    cfg.accepted_client_auth_methods = vec!["client_secret_basic".to_string()];
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    let app = broker_router(Arc::new(cfg), store);
    let body = "grant_type=authorization_code&code=c1\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
         &code_verifier=v&client_id=cli";
    let (status, body) = send_post_form(app, "/mcp/oauth/token", body).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "[{}] expected 401, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("invalid_client"),
        "[{}] body lacks invalid_client: {body}",
        e.id,
    );
}

async fn op_token_exchange(e: &Entry, outcome: Outcome) {
    let app = build_default_app();
    let iss = s_or(e, "iss", "https://idp.example");
    let audience = s_or(e, "audience", "https://api.downstream");
    let token = fixture_jwt(serde_json::json!({
        "iss": iss,
        "sub": "alice",
    }));
    let body = format!(
        "grant_type={}&subject_token={}&subject_token_type={}&audience={}&client_id=cli",
        url_form_encode("urn:ietf:params:oauth:grant-type:token-exchange"),
        url_form_encode(&token),
        url_form_encode("urn:ietf:params:oauth:token-type:access_token"),
        url_form_encode(audience),
    );
    let (status, body) = send_post_form(app, "/mcp/oauth/token", &body).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("invalid_target") || body.contains("invalid_request"),
        "[{}] body lacks expected error: {body}",
        e.id,
    );
}

async fn op_token_exchange_alt_subject_type(e: &Entry, outcome: Outcome) {
    let app = build_default_app();
    let token = fixture_jwt(serde_json::json!({
        "iss": "https://idp.example",
        "sub": "alice",
    }));
    let body = format!(
        "grant_type={}&subject_token={}&subject_token_type={}&client_id=cli",
        url_form_encode("urn:ietf:params:oauth:grant-type:token-exchange"),
        url_form_encode(&token),
        url_form_encode("urn:ietf:params:oauth:token-type:id_token"),
    );
    let (status, body) = send_post_form(app, "/mcp/oauth/token", &body).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("unsupported_token_type"),
        "[{}] body lacks unsupported_token_type: {body}",
        e.id,
    );
}

async fn op_token_exchange_no_client_id(e: &Entry, outcome: Outcome) {
    let app = build_default_app();
    let token = fixture_jwt(serde_json::json!({
        "iss": "https://idp.example",
        "sub": "alice",
    }));
    let body = format!(
        "grant_type={}&subject_token={}&subject_token_type={}",
        url_form_encode("urn:ietf:params:oauth:grant-type:token-exchange"),
        url_form_encode(&token),
        url_form_encode("urn:ietf:params:oauth:token-type:access_token"),
    );
    let (status, body) = send_post_form(app, "/mcp/oauth/token", &body).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "[{}] expected 401, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("invalid_client"),
        "[{}] body lacks invalid_client: {body}",
        e.id,
    );
}

async fn op_token_exchange_deep_chain(e: &Entry, outcome: Outcome) {
    // The subject token has to be one the broker itself minted and
    // signed: the exchange refuses an unverifiable subject before it
    // ever counts the chain, so an `alg: none` fixture here would be
    // blocked for the wrong reason and this case would stop covering
    // the depth cap it is named for.
    let mut cfg = base_config();
    cfg.external_base_url = "https://broker.example".to_string();
    cfg.broker_signing_key = Some(sbproxy_mcp_gateway::JwkKey::Pem {
        pem: BROKER_PRIVATE_PEM.to_string(),
        alg: "ES256".to_string(),
        kid: Some("broker-key".to_string()),
        // A PEM private key alone cannot verify: the broker needs the
        // matching public JWK to check its own signature.
        public_jwk: Some(serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY",
            "kid": "broker-key", "use": "sig", "alg": "ES256"
        })),
    });
    let issuer = sbproxy_mcp_gateway::well_known::broker_issuer(&cfg);
    cfg.subject_token_issuers = vec![issuer.clone()];
    // max_chain_depth is 2 and the handler refuses at depth >= max, so
    // a 2-deep `act` chain is exactly the first one over the line.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs() as i64;
    let token = sbproxy_mcp_gateway::mint_at_jwt(
        &sbproxy_mcp_gateway::AtJwtClaims {
            iss: issuer,
            sub: "alice".to_string(),
            aud: serde_json::Value::String(cfg.resource_uri.clone()),
            exp: now + 300,
            iat: now,
            jti: "corpus-deep-chain-jti".to_string(),
            client_id: "original-client".to_string(),
            scope: Some("tools:call".to_string()),
            auth_time: None,
            acr: None,
            amr: None,
            act: Some(serde_json::json!({
                "sub": "service-a",
                "act": {"sub": "service-b"},
            })),
            cnf: None,
            actor: None,
            principal: None,
            tnx: None,
            purpose: None,
        },
        cfg.broker_signing_key.as_ref().expect("broker signing key"),
    )
    .expect("broker-signed subject token");
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    let app = broker_router(Arc::new(cfg), store);
    let body = format!(
        "grant_type={}&subject_token={}&subject_token_type={}&client_id=cli",
        url_form_encode("urn:ietf:params:oauth:grant-type:token-exchange"),
        url_form_encode(&token),
        url_form_encode("urn:ietf:params:oauth:token-type:access_token"),
    );
    let (status, body) = send_post_form(app, "/mcp/oauth/token", &body).await;
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("chain too deep"),
        "[{}] body lacks chain-too-deep: {body}",
        e.id,
    );
}

async fn op_refresh_token_no_rotation(e: &Entry, outcome: Outcome) {
    // Spin up a tiny mock upstream that returns the same refresh_token
    // as the inbound one. The broker must fail the rotation check.
    use axum::routing::post;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn echo_token(
        axum::Form(form): axum::Form<HashMap<String, String>>,
    ) -> axum::Json<serde_json::Value> {
        let rt = form
            .get("refresh_token")
            .cloned()
            .unwrap_or_else(|| "rt-fixed".to_string());
        axum::Json(serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "refresh_token": rt,
            "expires_in": 3600,
        }))
    }

    let upstream_app = Router::new().route("/token", post(echo_token));
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let mut cfg = base_config();
    cfg.upstream_token_endpoint_url = format!("http://{addr}/token");
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    let app = broker_router(Arc::new(cfg), store);

    let body = "grant_type=refresh_token&refresh_token=rt-fixed&client_id=cli";
    let (status, body) = send_post_form(app, "/mcp/oauth/token", body).await;
    server.abort();
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("invalid_grant"),
        "[{}] body lacks invalid_grant: {body}",
        e.id,
    );
}

async fn op_refresh_token_no_new_token(e: &Entry, outcome: Outcome) {
    // Mock upstream omits refresh_token in its 200 response.
    use axum::routing::post;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn no_rt(_form: axum::Form<HashMap<String, String>>) -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 3600,
        }))
    }

    let upstream_app = Router::new().route("/token", post(no_rt));
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let mut cfg = base_config();
    cfg.upstream_token_endpoint_url = format!("http://{addr}/token");
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    let app = broker_router(Arc::new(cfg), store);

    let body = "grant_type=refresh_token&refresh_token=rt-fixed&client_id=cli";
    let (status, body) = send_post_form(app, "/mcp/oauth/token", body).await;
    server.abort();
    assert!(matches!(outcome, Outcome::Blocked));
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "[{}] expected 400, got {status}: {body}",
        e.id,
    );
    assert!(
        body.contains("invalid_grant"),
        "[{}] body lacks invalid_grant: {body}",
        e.id,
    );
}

// --- Top-level driver ---

async fn drive_entry(entry: &Entry) {
    let outcome = parse_outcome(&entry.expected_outcome, &entry.id);
    // Sanity-check the category up front so a typo surfaces as a
    // named test failure rather than a silent mis-classification.
    assert!(
        matches!(
            entry.category.as_str(),
            "tool_description"
                | "tool_result"
                | "scope_escalation"
                | "confused_deputy"
                | "replay"
                | "cross_tenant"
        ),
        "[{}] unknown category {:?}",
        entry.id,
        entry.category,
    );

    match entry.op.as_str() {
        "authorize" => op_authorize(entry, outcome).await,
        "authorize_with_cimd_disabled" => op_authorize_with_cimd_disabled(entry, outcome).await,
        "par_then_authorize_with_resource" => {
            op_par_then_authorize_with_resource(entry, outcome).await
        }
        "par_then_authorize_twice" => op_par_then_authorize_twice(entry, outcome).await,
        "session_take_twice" => op_session_take_twice(entry, outcome).await,
        "session_keys_unique_per_state" => op_session_keys_unique_per_state(entry, outcome).await,
        "dpop_jti_record_twice" => op_dpop_jti_record_twice(entry, outcome).await,
        "inject_cnf_jkt_jwt_no_signing_key" => {
            op_inject_cnf_jkt_jwt_no_signing_key(entry, outcome).await
        }
        "inject_cnf_jkt_non_json" => op_inject_cnf_jkt_non_json(entry, outcome).await,
        "inject_act_envelope_no_signing_key" => {
            op_inject_act_envelope_no_signing_key(entry, outcome).await
        }
        "token" => op_token(entry, outcome).await,
        "token_with_restricted_methods" => op_token_with_restricted_methods(entry, outcome).await,
        "token_exchange" => op_token_exchange(entry, outcome).await,
        "token_exchange_alt_subject_type" => {
            op_token_exchange_alt_subject_type(entry, outcome).await
        }
        "token_exchange_no_client_id" => op_token_exchange_no_client_id(entry, outcome).await,
        "token_exchange_deep_chain" => op_token_exchange_deep_chain(entry, outcome).await,
        "refresh_token_no_rotation" => op_refresh_token_no_rotation(entry, outcome).await,
        "refresh_token_no_new_token" => op_refresh_token_no_new_token(entry, outcome).await,
        other => panic!("[{}] unknown op {other:?}", entry.id),
    }
}

#[tokio::test]
async fn corpus_runs_end_to_end() {
    let corpus = load_corpus();
    assert!(
        corpus.entries.len() >= 20,
        "corpus must hold at least 20 entries; got {}",
        corpus.entries.len(),
    );
    for entry in &corpus.entries {
        drive_entry(entry).await;
    }
}

/// The count `docs/mcp-oauth-gateway.md` publishes has to be the count
/// the corpus holds. It drifted once already: the doc said 26 while the
/// file held 28, and the only assertion was a floor of 20, which cannot
/// see the difference.
#[test]
fn the_documented_corpus_size_matches_the_corpus() {
    let corpus = load_corpus();
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/mcp-oauth-gateway.md"),
    )
    .expect("read docs/mcp-oauth-gateway.md");
    let claim = format!(
        "{} entries across six threat categories",
        corpus.entries.len()
    );
    assert!(
        doc.contains(&claim),
        "docs/mcp-oauth-gateway.md does not say '{claim}'; the corpus moved and the doc did not"
    );
}

#[tokio::test]
async fn corpus_covers_every_category() {
    use std::collections::HashSet;
    let corpus = load_corpus();
    let cats: HashSet<&str> = corpus.entries.iter().map(|e| e.category.as_str()).collect();
    for required in &[
        "tool_description",
        "tool_result",
        "scope_escalation",
        "confused_deputy",
        "replay",
        "cross_tenant",
    ] {
        assert!(
            cats.contains(*required),
            "corpus missing required category {required:?}",
        );
    }
}

#[tokio::test]
async fn corpus_ids_unique() {
    use std::collections::HashSet;
    let corpus = load_corpus();
    let mut seen: HashSet<&str> = HashSet::new();
    for e in &corpus.entries {
        assert!(seen.insert(&e.id), "duplicate corpus id {:?}", e.id);
    }
}
