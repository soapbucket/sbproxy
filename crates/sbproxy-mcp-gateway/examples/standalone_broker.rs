//! Runnable MCP OAuth 2.1 broker with every optional collaborator
//! wired up, backed entirely by the in-process [`LocalStore`] default
//! (no Redis, no external database), plus a second tiny router showing
//! the [`resource_server`](sbproxy_mcp_gateway::resource_server)
//! companion protecting a stand-in MCP tool endpoint with the tokens
//! this same broker issues.
//!
//! ```text
//! cargo run -p sbproxy-mcp-gateway --example standalone_broker
//! ```
//!
//! Then, in another terminal:
//!
//! ```text
//! curl -s http://127.0.0.1:8089/mcp/oauth/.well-known/oauth-authorization-server | jq
//! curl -s http://127.0.0.1:8089/mcp/oauth/admin/status | jq
//! curl -s http://127.0.0.1:8089/metrics | grep sbproxy_mcp_gateway
//!
//! # Resource-server half: no token -> 401 with an RFC 6750 challenge
//! # naming the RFC 9728 metadata document.
//! curl -i http://127.0.0.1:8090/.well-known/oauth-protected-resource
//! curl -i http://127.0.0.1:8090/tools/ping
//! ```
//!
//! Export `MCP_GATEWAY_BASE_URL=http://127.0.0.1:8089` (or your own
//! bind address) before running: the well-known route and the DPoP
//! `htu` check both read that variable at request time, and this
//! example does not set it for you (this workspace's
//! `scripts/check-env-mutation.sh` refuses production code that calls
//! `std::env::set_var`, on purpose, since it is process-global mutable
//! state; see that script's header). `UPSTREAM_AUTHORIZATION_SERVER_URL`
//! and `UPSTREAM_TOKEN_ENDPOINT_URL` default to a placeholder upstream
//! that will refuse real traffic: point them at a real Authorization
//! Server (or `docs/mcp-oauth-gateway.md`'s mock-AS snippet) to drive
//! the `/authorize` -> `/callback` -> `/token` flow end to end.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sbproxy_mcp_gateway::config::{
    DEFAULT_DPOP_JTI_TTL_SECS, DEFAULT_DPOP_NONCE_TTL_SECS, DEFAULT_METADATA_MAX_STALENESS_SECS,
    DEFAULT_METADATA_REFRESH_SECS,
};
use sbproxy_mcp_gateway::device_code::DeviceCodeStore;
use sbproxy_mcp_gateway::dpop::{DpopNonceIssuer, DpopReplayCache};
use sbproxy_mcp_gateway::resource_server::{
    AudienceConfig, McpResourceServerConfig, McpResourceServerProvider,
};
use sbproxy_mcp_gateway::{
    router_full_with_par, InMemoryCimdCache, InMemorySessionStore, LocalStore, McpGatewayConfig,
};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8089";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8089";
const RESOURCE_SERVER_LISTEN_ADDR: &str = "127.0.0.1:8090";

#[tokio::main]
async fn main() {
    tracing_subscriber_init();

    let base_url = match std::env::var("MCP_GATEWAY_BASE_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "MCP_GATEWAY_BASE_URL is not set; the well-known route and the DPoP \
                 `htu` check will not know this broker's own origin. Re-run as:\n\n  \
                 MCP_GATEWAY_BASE_URL={DEFAULT_BASE_URL} cargo run -p sbproxy-mcp-gateway \
                 --example standalone_broker\n"
            );
            DEFAULT_BASE_URL.to_string()
        }
    };

    let config = Arc::new(McpGatewayConfig {
        base_path: "/mcp/oauth".to_string(),
        upstream_authorization_server_url: std::env::var("UPSTREAM_AUTHORIZATION_SERVER_URL")
            .unwrap_or_else(|_| "https://idp.example.com/oauth/authorize".to_string()),
        upstream_token_endpoint_url: std::env::var("UPSTREAM_TOKEN_ENDPOINT_URL")
            .unwrap_or_else(|_| "https://idp.example.com/oauth/token".to_string()),
        resource_uri: "https://mcp.example.com".to_string(),
        allowed_redirect_uris: vec!["https://client.example.com/callback".to_string()],
        session_ttl_secs: 600,
        dpop_supported: true,
        dpop_require_nonce: false,
        dpop_jti_ttl_secs: DEFAULT_DPOP_JTI_TTL_SECS,
        dpop_nonce_ttl_secs: DEFAULT_DPOP_NONCE_TTL_SECS,
        device_code_enabled: true,
        metadata_refresh_secs: DEFAULT_METADATA_REFRESH_SECS,
        max_metadata_staleness_secs: DEFAULT_METADATA_MAX_STALENESS_SECS,
        ..McpGatewayConfig::default()
    });

    if let Err(e) = sbproxy_mcp_gateway::config::validate_startup(&config) {
        eprintln!("startup config invalid: {e}");
        std::process::exit(1);
    }

    let session_store = InMemorySessionStore::arc(Duration::from_secs(config.session_ttl_secs));
    let cimd_cache = InMemoryCimdCache::arc(Duration::from_secs(3600));
    let dpop_replay_kv: Arc<dyn sbproxy_storage::EphemeralKv> = LocalStore::arc();
    let dpop_replay = Arc::new(DpopReplayCache::new(
        dpop_replay_kv,
        Duration::from_secs(config.dpop_jti_ttl_secs),
    ));
    let dpop_nonce_kv: Arc<dyn sbproxy_storage::EphemeralKv> = LocalStore::arc();
    let dpop_nonce = Arc::new(DpopNonceIssuer::new(
        dpop_nonce_kv,
        Duration::from_secs(config.dpop_nonce_ttl_secs),
    ));
    let device_code_kv: Arc<dyn sbproxy_storage::EphemeralKv> = LocalStore::arc();
    let device_code_store = DeviceCodeStore::arc(device_code_kv);
    let par_store: Arc<dyn sbproxy_storage::EphemeralKv> = LocalStore::arc();

    let app = router_full_with_par(
        config,
        session_store,
        None, // as_metadata: no upstream reachable in this standalone example
        Some(cimd_cache),
        None,
        Some(dpop_replay),
        Some(dpop_nonce),
        Some(device_code_store),
        Some(par_store),
    )
    .route("/metrics", get(metrics_handler));

    // --- Resource-server half ---
    //
    // A second, independent router standing in for the actual MCP
    // origin: it validates the Bearer/DPoP tokens the broker above
    // issues (in a real deployment the two would run as separate
    // processes; here they share one binary for a self-contained
    // demo). Its JWKS URL points at nothing reachable, so every real
    // request fails signature verification; the point of this demo is
    // the 401 + `WWW-Authenticate` shape and the RFC 9728 metadata
    // document, not a live-signed token round trip.
    let resource_server = Arc::new(
        McpResourceServerProvider::new(McpResourceServerConfig {
            resource_uri: "https://mcp.example.com".to_string(),
            authorization_servers: vec!["https://idp.example.com".to_string()],
            jwks_url: "https://idp.example.com/.well-known/jwks.json".to_string(),
            audience: AudienceConfig::Single("https://mcp.example.com".to_string()),
            issuer: None,
            jwks_cache_ttl_secs: 300,
            scopes_supported: vec!["mcp:tools".to_string()],
            resource_documentation: Some("https://mcp.example.com/docs".to_string()),
            metadata_path: "/.well-known/oauth-protected-resource".to_string(),
            dpop_enforce_binding: false,
            dpop_max_clock_skew_secs: 30,
        })
        .expect("resource server config is valid"),
    );
    let resource_app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route("/tools/ping", get(resource_protected_ping))
        .with_state(resource_server);

    let broker_listener = tokio::net::TcpListener::bind(DEFAULT_LISTEN_ADDR)
        .await
        .unwrap_or_else(|e| panic!("bind {DEFAULT_LISTEN_ADDR}: {e}"));
    let resource_listener = tokio::net::TcpListener::bind(RESOURCE_SERVER_LISTEN_ADDR)
        .await
        .unwrap_or_else(|e| panic!("bind {RESOURCE_SERVER_LISTEN_ADDR}: {e}"));
    println!("MCP OAuth broker listening on http://{DEFAULT_LISTEN_ADDR}");
    println!("  well-known: {base_url}/mcp/oauth/.well-known/oauth-authorization-server");
    println!("  admin:      {base_url}/mcp/oauth/admin/status");
    println!("  metrics:    {base_url}/metrics");
    println!("MCP resource server listening on http://{RESOURCE_SERVER_LISTEN_ADDR}");
    println!(
        "  well-known: http://{RESOURCE_SERVER_LISTEN_ADDR}/.well-known/oauth-protected-resource"
    );
    println!("  protected:  http://{RESOURCE_SERVER_LISTEN_ADDR}/tools/ping");

    tokio::join!(
        async {
            axum::serve(broker_listener, app)
                .await
                .unwrap_or_else(|e| panic!("broker serve: {e}"));
        },
        async {
            axum::serve(resource_listener, resource_app)
                .await
                .unwrap_or_else(|e| panic!("resource server serve: {e}"));
        }
    );
}

/// `GET /.well-known/oauth-protected-resource`: RFC 9728, unauthenticated.
async fn resource_metadata(State(rs): State<Arc<McpResourceServerProvider>>) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        rs.metadata_document_json(),
    )
        .into_response()
}

/// `GET /tools/ping`: a stand-in protected MCP tool call. Demonstrates
/// [`McpResourceServerProvider::authenticate`] and the RFC 6750
/// `WWW-Authenticate` challenge this crate builds on a rejection.
async fn resource_protected_ping(
    State(rs): State<Arc<McpResourceServerProvider>>,
    headers: HeaderMap,
) -> Response {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());
    let url = url::Url::parse(&format!("http://{RESOURCE_SERVER_LISTEN_ADDR}/tools/ping"))
        .expect("static URL parses");
    match rs.authenticate(auth_header, dpop_header, "GET", &url).await {
        Ok(verified) => {
            Json(serde_json::json!({"pong": true, "sub": verified.sub})).into_response()
        }
        Err(err) => {
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": err.rfc6750_error_code()})),
            )
                .into_response();
            if let Ok(value) = rs.www_authenticate_header(&err).parse() {
                resp.headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
            resp
        }
    }
}

/// Render every registered Prometheus family as the standard text
/// exposition format, including this crate's `sbproxy_mcp_gateway_*`
/// families (`dashboards/grafana/sbproxy-mcp-oauth-gateway.json` draws
/// them from an endpoint shaped exactly like this one).
async fn metrics_handler() -> String {
    use prometheus::Encoder;
    let families = prometheus::gather();
    let mut buf = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&families, &mut buf)
        .unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}

/// Minimal stderr logging so the example's own request handling is
/// visible without pulling a logging framework choice into a docs
/// example. Real deployments should install their own
/// `tracing_subscriber` configuration before calling into this crate.
fn tracing_subscriber_init() {
    use std::io::Write;
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = writeln!(
            std::io::stderr(),
            "sbproxy-mcp-gateway example: structured logs go to tracing; \
             install a subscriber (e.g. tracing_subscriber::fmt::init()) \
             in a real deployment to see them"
        );
    });
}
