// E2E coverage for the MCP OAuth 2.1 broker (Wave 4B.3).
//
// The broker is an axum router that proxies between an MCP client
// (user agent) and an upstream Authorization Server. The OSS Pingora
// request path does not yet host axum routers, so this suite stands
// both halves up inside the same process: a tokio-bound mock AS on
// one ephemeral port, and the broker on another. The flow exercises
// the same code paths the production binary will mount once the
// integration shim lands.
//
// Tests:
//
//   * full_pkce_flow_happy_path
//       /authorize -> mock AS -> broker /callback -> client redirect
//       -> client POST /token -> broker forwards -> mock AS returns
//       access token. End-to-end timing budget is generous (5s) so
//       slow CI runners do not flake on the two TCP hops.
//
//   * authorize_rejects_implicit_grant
//       OAuth 2.1 forbids `response_type=token`. Broker must return
//       400 + `unsupported_response_type` without redirecting.
//
//   * authorize_rejects_missing_pkce
//       Broker must reject a missing `code_challenge` with 400 +
//       `invalid_request` so a downgrade attack cannot strip PKCE.
//
//   * well_known_returns_expected_fields
//       GET /.well-known/oauth-authorization-server must list the
//       broker-served endpoints, advertise S256 only, and list the
//       broker's accepted client-auth methods.
//
//   * token_rejects_password_grant
//       Broker must return 400 + `unsupported_grant_type` for the
//       OAuth 2.1-forbidden `password` grant.

use axum::{
    extract::{Form, Query},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use sbproxy_mcp_gateway::{router as broker_router, InMemorySessionStore, McpGatewayConfig};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

// --- Mock upstream Authorization Server -------------------------------------
//
// Implements the four endpoints the broker calls into:
//
//   GET  /authorize  -> immediately redirects back to the broker's
//                       callback URL with a synthetic `code` and the
//                       state the broker minted.
//   POST /token      -> issues a fixed access token. We assert the
//                       broker forwarded `code_verifier`, `resource`,
//                       and `client_id` correctly.
//   GET  /jwks.json  -> returns an empty JWKS body. The broker only
//                       needs this for ID-token verification, which
//                       is not exercised here.
//   GET  /.well-known/oauth-authorization-server -> static doc
//                       describing this fake AS, just so the broker's
//                       metadata cache has something real to read.

#[derive(Deserialize, Debug)]
struct UpstreamAuthorizeQuery {
    redirect_uri: String,
    state: String,
    #[allow(dead_code)]
    client_id: String,
    #[allow(dead_code)]
    code_challenge: String,
    #[allow(dead_code)]
    code_challenge_method: String,
    #[allow(dead_code)]
    response_type: String,
    #[allow(dead_code)]
    resource: String,
}

async fn mock_upstream_authorize(Query(q): Query<UpstreamAuthorizeQuery>) -> Response {
    // Bounce the user agent back to the broker callback with a
    // deterministic authorization code and the broker-minted state.
    let target = format!(
        "{}?code=upstream-code-7&state={}",
        q.redirect_uri,
        urlencoding_encode(&q.state),
    );
    Redirect::temporary(&target).into_response()
}

async fn mock_upstream_token(Form(form): Form<HashMap<String, String>>) -> Response {
    // Verify the broker forwarded the OAuth 2.1 + RFC 8707 envelope.
    let grant = form.get("grant_type").cloned().unwrap_or_default();
    if grant != "authorization_code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unsupported_grant_type"})),
        )
            .into_response();
    }
    if form.get("code").map(String::as_str) != Some("upstream-code-7") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    // PKCE verifier MUST be on the wire (even though this mock AS does
    // not actually verify it against the original challenge).
    if form
        .get("code_verifier")
        .map(String::as_str)
        .unwrap_or("")
        .is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_request"})),
        )
            .into_response();
    }
    // RFC 8707 binding: the broker must always inject a `resource`
    // when the config supplies one. The token response carries it back
    // via `audience` so the e2e assertion can confirm round-trip.
    let resource = form.get("resource").cloned().unwrap_or_default();
    Json(serde_json::json!({
        "access_token": "mock-access-token-abc",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "mock-refresh-token-xyz-1",
        "audience": resource,
    }))
    .into_response()
}

async fn mock_upstream_jwks() -> Response {
    Json(serde_json::json!({"keys": []})).into_response()
}

async fn mock_upstream_metadata() -> Response {
    Json(serde_json::json!({
        "issuer": "https://upstream.invalid",
        "authorization_endpoint": "https://upstream.invalid/authorize",
        "token_endpoint": "https://upstream.invalid/token",
        "jwks_uri": "https://upstream.invalid/jwks.json",
        "registration_endpoint": "https://upstream.invalid/register",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
    }))
    .into_response()
}

fn build_mock_upstream_router() -> Router {
    Router::new()
        .route("/authorize", get(mock_upstream_authorize))
        .route("/token", post(mock_upstream_token))
        .route("/jwks.json", get(mock_upstream_jwks))
        .route(
            "/.well-known/oauth-authorization-server",
            get(mock_upstream_metadata),
        )
}

// --- Test harness -----------------------------------------------------------

/// Pair of (broker base URL, upstream base URL) plus shutdown handles.
/// Drop runs both shutdowns. Single ownership keeps the test functions
/// short.
struct Pair {
    broker_url: String,
    #[allow(dead_code)]
    upstream_url: String,
    broker_shutdown: Option<oneshot::Sender<()>>,
    upstream_shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for Pair {
    fn drop(&mut self) {
        if let Some(tx) = self.broker_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.upstream_shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn spawn_router(router: Router) -> (String, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    spawn_router_on(listener, router)
}

fn spawn_router_on(listener: TcpListener, router: Router) -> (String, oneshot::Sender<()>) {
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async {
            let _ = rx.await;
        });
        if let Err(e) = server.await {
            eprintln!("axum serve exited: {e}");
        }
    });
    (format!("http://{addr}"), tx)
}

async fn start_pair() -> Pair {
    let (upstream_url, upstream_shutdown) = spawn_router(build_mock_upstream_router()).await;
    let broker_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind broker listener");
    let broker_url = format!(
        "http://{}",
        broker_listener.local_addr().expect("broker local_addr")
    );

    // Use struct update syntax so test fixtures don't break when new
    // optional fields are added to McpGatewayConfig. Only override the
    // fields this test actually cares about; everything else picks up
    // the well-tested Default values.
    let cfg = McpGatewayConfig {
        base_path: "/mcp/oauth".to_string(),
        allow_insecure_loopback: true,
        external_base_url: broker_url.clone(),
        upstream_redirect_uri: format!("{broker_url}/mcp/oauth/callback"),
        upstream_authorization_server_url: format!("{upstream_url}/authorize"),
        resource_uri: "https://mcp.example/api".to_string(),
        allowed_redirect_uris: vec!["https://client.example/cb".to_string()],
        session_ttl_secs: 600,
        upstream_token_endpoint_url: format!("{upstream_url}/token"),
        upstream_registration_endpoint_url: Some(format!("{upstream_url}/register")),
        metadata_refresh_secs: 300,
        max_metadata_staleness_secs: 3600,
        accepted_client_auth_methods: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "none".to_string(),
        ],
        client_jwt_signing_key: None,
        dcr_upstream_shape: None,
        ..McpGatewayConfig::default()
    };
    let store = InMemorySessionStore::arc(Duration::from_secs(60));
    let router = broker_router(Arc::new(cfg), store);
    let (bound_broker_url, broker_shutdown) = spawn_router_on(broker_listener, router);
    assert_eq!(bound_broker_url, broker_url);

    Pair {
        broker_url,
        upstream_url,
        broker_shutdown: Some(broker_shutdown),
        upstream_shutdown: Some(upstream_shutdown),
    }
}

// Minimal percent-encoder for the values we need to round trip via the
// mock upstream's redirect. Avoids pulling `url` solely for the
// fragment-free encode-this-once helper.
fn urlencoding_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let b = byte as char;
        let safe = b.is_ascii_alphanumeric() || matches!(b, '-' | '_' | '.' | '~');
        if safe {
            out.push(b);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

// --- Tests -----------------------------------------------------------------

#[tokio::test]
async fn full_pkce_flow_happy_path() {
    let pair = start_pair().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");

    // --- Step 1: /authorize -> 302 to upstream AS ---
    let authorize_url = format!(
        "{}/mcp/oauth/authorize?\
         client_id=cli\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
         &response_type=code\
         &code_challenge=test-challenge-123\
         &code_challenge_method=S256\
         &state=cli-state-original\
         &resource=https%3A%2F%2Fmcp.example%2Fapi",
        pair.broker_url,
    );
    let resp = client.get(&authorize_url).send().await.expect("authorize");
    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    let upstream_loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("Location on /authorize")
        .to_str()
        .expect("Location utf-8")
        .to_string();
    assert!(
        upstream_loc.contains("/authorize"),
        "redirect should point at upstream /authorize, got {upstream_loc}"
    );
    assert!(upstream_loc.contains("code_challenge=test-challenge-123"));
    assert!(upstream_loc.contains("code_challenge_method=S256"));
    assert!(upstream_loc.contains("resource=https%3A%2F%2Fmcp.example%2Fapi"));
    // Broker minted its own state for the upstream hop.
    let parsed = url::Url::parse(&upstream_loc).expect("parse upstream loc");
    let upstream_state = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state in upstream URL");
    assert_ne!(upstream_state, "cli-state-original");

    // --- Step 2: client follows to mock AS, AS bounces to broker /callback ---
    let resp = client.get(&upstream_loc).send().await.expect("upstream");
    assert_eq!(resp.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    let callback_loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("Location on upstream /authorize")
        .to_str()
        .expect("utf-8")
        .to_string();
    assert!(
        callback_loc.contains("code=upstream-code-7"),
        "upstream did not bounce with the synthetic code: {callback_loc}"
    );

    // The callback URL the broker handed to upstream points at the
    // broker's own /callback. The mock used that as `redirect_uri`,
    // and the bounce target replaces the broker_url path with that
    // same value, but the mock has no idea what the broker URL is.
    // We constructed `callback_loc` as the relative `/mcp/oauth/callback`
    // path (because that is what the broker put in the upstream
    // request as `redirect_uri`). Resolve it against the broker.
    let callback_full = if callback_loc.starts_with("http") {
        callback_loc.clone()
    } else {
        format!("{}{}", pair.broker_url, callback_loc)
    };
    let resp = client.get(&callback_full).send().await.expect("callback");
    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    let client_redirect = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("Location on /callback")
        .to_str()
        .expect("utf-8")
        .to_string();
    assert!(
        client_redirect.starts_with("https://client.example/cb?"),
        "broker should redirect to client redirect_uri, got {client_redirect}"
    );
    assert!(client_redirect.contains("code=upstream-code-7"));
    // Client receives its ORIGINAL state, not the broker's.
    assert!(client_redirect.contains("state=cli-state-original"));

    // --- Step 3: client POSTs /token to broker ---
    let token_body = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", "upstream-code-7"),
        ("redirect_uri", "https://client.example/cb"),
        ("code_verifier", "the-verifier"),
        ("client_id", "cli"),
    ])
    .expect("urlencode token body");
    let resp = client
        .post(format!("{}/mcp/oauth/token", pair.broker_url))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(token_body)
        .send()
        .await
        .expect("token");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("token JSON");
    assert_eq!(body["access_token"], "mock-access-token-abc");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["audience"], "https://mcp.example/api");
}

#[tokio::test]
async fn authorize_rejects_implicit_grant() {
    let pair = start_pair().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest");

    let url = format!(
        "{}/mcp/oauth/authorize?\
         client_id=cli\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
         &response_type=token\
         &code_challenge=abc\
         &code_challenge_method=S256\
         &state=s\
         &resource=https%3A%2F%2Fmcp.example%2Fapi",
        pair.broker_url,
    );
    let resp = client.get(&url).send().await.expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.expect("text");
    assert!(body.contains("unsupported_response_type"));
}

#[tokio::test]
async fn authorize_rejects_missing_pkce() {
    let pair = start_pair().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest");

    let url = format!(
        "{}/mcp/oauth/authorize?\
         client_id=cli\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
         &response_type=code\
         &state=s\
         &resource=https%3A%2F%2Fmcp.example%2Fapi",
        pair.broker_url,
    );
    let resp = client.get(&url).send().await.expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.expect("text");
    assert!(body.contains("invalid_request"));
    assert!(body.contains("code_challenge"));
}

#[tokio::test]
async fn well_known_returns_expected_fields() {
    let pair = start_pair().await;
    let url = format!(
        "{}/mcp/oauth/.well-known/oauth-authorization-server",
        pair.broker_url
    );
    let resp = reqwest::get(&url).await.expect("well-known");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let cache = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    assert!(
        cache.contains("max-age=300"),
        "Cache-Control should be public+5min, got {cache}"
    );
    let body: serde_json::Value = resp.json().await.expect("well-known JSON");
    let issuer = body["issuer"].as_str().unwrap_or("");
    assert!(
        issuer.ends_with("/mcp/oauth"),
        "issuer must end with broker base path, got {issuer}"
    );
    let authz = body["authorization_endpoint"].as_str().unwrap_or("");
    assert!(authz.ends_with("/mcp/oauth/authorize"));
    let token = body["token_endpoint"].as_str().unwrap_or("");
    assert!(token.ends_with("/mcp/oauth/token"));
    // Registration listed because the test config sets a non-None
    // upstream_registration_endpoint_url.
    let reg = body["registration_endpoint"].as_str().unwrap_or("");
    assert!(reg.ends_with("/mcp/oauth/register"));
    let pkce = body["code_challenge_methods_supported"]
        .as_array()
        .expect("code_challenge_methods_supported array");
    assert_eq!(pkce.len(), 1);
    assert_eq!(pkce[0], "S256");
    let methods = body["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods array");
    assert!(methods.iter().any(|m| m == "client_secret_basic"));
    assert!(methods.iter().any(|m| m == "none"));
    let response_types = body["response_types_supported"]
        .as_array()
        .expect("response_types array");
    assert_eq!(response_types.len(), 1);
    assert_eq!(response_types[0], "code");
}

#[tokio::test]
async fn token_rejects_password_grant() {
    let pair = start_pair().await;
    let client = reqwest::Client::new();
    let body = serde_urlencoded::to_string([
        ("grant_type", "password"),
        ("username", "alice"),
        ("password", "hunter2"),
        ("client_id", "cli"),
    ])
    .expect("urlencode");
    let resp = client
        .post(format!("{}/mcp/oauth/token", pair.broker_url))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let text = resp.text().await.expect("text");
    assert!(text.contains("unsupported_grant_type"));
}
