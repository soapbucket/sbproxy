//! Operator-facing status surface for the MCP OAuth 2.1 broker.
//!
//! This crate ships as an independent axum router rather than a
//! module inside the main `sbproxy` binary (see the crate-level docs),
//! so it does not have a page in `ui/`, which is the admin console for
//! that binary's own request pipeline. `GET {base_path}/admin/status`
//! is this crate's own equivalent: a small JSON surface an operator
//! (or a script, or a future `ui/` integration once this broker is
//! wired behind the main proxy) can poll to see which optional
//! collaborators are configured and read the same counters
//! `dashboards/grafana/sbproxy-mcp-oauth-gateway.json` draws, without
//! needing a Prometheus query client.
//!
//! The route is unauthenticated by design, matching the
//! `/.well-known/*` routes this broker already mounts unauthenticated:
//! it reveals only which features are turned on, never a secret or a
//! token.

use axum::{extract::State, response::Json};
use serde::Serialize;

use crate::AppState;

/// Which optional collaborators are wired into this deployment.
#[derive(Debug, Serialize)]
pub(crate) struct FeatureStatus {
    /// `app.as_metadata` is configured: the well-known route mirrors
    /// upstream AS metadata fields.
    pub as_metadata_cache: bool,
    /// `app.cimd_cache` is configured: URL-shaped `client_id` values
    /// are resolved as Client ID Metadata Documents.
    pub cimd: bool,
    /// `app.cimd_to_dcr` is configured: CIMD clients are translated
    /// into upstream RFC 7591 registrations.
    pub cimd_to_dcr_translation: bool,
    /// `app.dpop_replay` is configured: DPoP proofs get single-use
    /// jti enforcement rather than best-effort verification only.
    pub dpop_replay_cache: bool,
    /// `app.dpop_nonce` is configured: the broker can issue and
    /// validate the optional `DPoP-Nonce` challenge.
    pub dpop_nonce_issuer: bool,
    /// `app.device_code_store` is configured: RFC 8628 device-code
    /// grant is available.
    pub device_code_grant: bool,
    /// `app.par_store` is configured: `POST /par` is mounted.
    pub pushed_authorization_requests: bool,
    /// `upstream_revocation_endpoint_url` is configured: `POST
    /// /revoke` is mounted.
    pub revocation: bool,
    /// `upstream_introspection_endpoint_url` is configured: `POST
    /// /introspect` is mounted.
    pub introspection: bool,
    /// `token_exchange_enabled` in config.
    pub token_exchange: bool,
    /// `broker_signing_key` is configured: the broker can mint its
    /// own RFC 9068 access tokens and serves a non-empty JWKS.
    pub broker_signing_key: bool,
}

/// `GET {base_path}/admin/status` response body.
#[derive(Debug, Serialize)]
pub(crate) struct StatusResponse {
    /// Configured base path this router is mounted under.
    pub base_path: String,
    /// Which optional collaborators are wired in.
    pub features: FeatureStatus,
}

/// `GET {base_path}/admin/status` handler.
pub(crate) async fn status(State(app): State<AppState>) -> Json<StatusResponse> {
    let cfg = &app.config;
    Json(StatusResponse {
        base_path: cfg.base_path.clone(),
        features: FeatureStatus {
            as_metadata_cache: app.as_metadata.is_some(),
            cimd: app.cimd_cache.is_some(),
            cimd_to_dcr_translation: app.cimd_to_dcr.is_some(),
            dpop_replay_cache: app.dpop_replay.is_some(),
            dpop_nonce_issuer: app.dpop_nonce.is_some(),
            device_code_grant: app.device_code_store.is_some(),
            pushed_authorization_requests: app.par_store.is_some(),
            revocation: cfg.upstream_revocation_endpoint_url.is_some(),
            introspection: cfg.upstream_introspection_endpoint_url.is_some(),
            token_exchange: cfg.token_exchange_enabled,
            broker_signing_key: cfg.broker_signing_key.is_some(),
        },
    })
}

#[cfg(test)]
mod tests {
    use crate::config::McpGatewayConfig;
    use crate::session::InMemorySessionStore;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    #[tokio::test]
    async fn status_reports_no_optional_collaborators_by_default() {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let app = crate::router(Arc::new(McpGatewayConfig::default()), store);
        let req = Request::builder()
            .uri("/mcp/oauth/admin/status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["base_path"], "/mcp/oauth");
        assert_eq!(v["features"]["pushed_authorization_requests"], false);
        assert_eq!(v["features"]["device_code_grant"], false);
    }

    #[tokio::test]
    async fn status_reports_par_when_configured() {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let par_store: Arc<dyn sbproxy_storage::EphemeralKv> = crate::LocalStore::arc();
        let app = crate::router_full_with_par(
            Arc::new(McpGatewayConfig::default()),
            store,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(par_store),
        );
        let req = Request::builder()
            .uri("/mcp/oauth/admin/status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["features"]["pushed_authorization_requests"], true);
    }
}
