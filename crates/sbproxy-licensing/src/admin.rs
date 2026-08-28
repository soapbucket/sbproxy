//! Operator-facing status surface for a standalone marketplace host.
//!
//! `GET /admin/status`, mounted by [`crate::router`]: a small JSON
//! surface an operator or a script can poll to see what a running
//! marketplace bridge currently publishes and how healthy its signing
//! key rotation looks, without a Prometheus query client or decoding a
//! quote signature by hand.
//!
//! This is the route for a process that mounts this crate's axum
//! router. `sbproxy` is not that process: it serves the CoMP endpoints
//! off its own request path, so this router is never mounted there and
//! this route never answers. The equivalent under the proxy's own
//! authenticated admin API is `GET /admin/licensing`
//! (`crates/sbproxy-core/src/admin_licensing.rs`), which reports the
//! same fields per origin. A console page for it is separate scope
//! under the admin console epic; `docs/admin-api-reference.md` says so
//! beside the route.
//!
//! The route is unauthenticated by design, matching
//! `GET /.well-known/iab-comp/manifest.json` itself: everything it
//! reveals (the publisher domain, tier count, and how many CoMP
//! signing keys are currently trusted) is already public in the
//! manifest this bridge serves. No private key material or buyer PII
//! ever appears in the response.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use serde::Serialize;

use crate::comp::CompMarketplace;

/// `GET /admin/status` response body.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    /// Publisher domain this marketplace's manifest advertises.
    pub publisher_domain: String,
    /// Number of tiers the manifest currently publishes.
    pub tier_count: usize,
    /// Active CoMP quote-signing kid, or `null` if
    /// [`crate::keys::KeyManager::set_active`] has not been called
    /// yet (quote requests would fail closed until it is).
    pub active_signing_kid: Option<String>,
    /// Number of CoMP kids currently trusted for verification
    /// (active plus any retained rotation-window keys).
    pub trusted_kid_count: usize,
}

impl StatusResponse {
    /// Project one marketplace's operator-visible state.
    ///
    /// Shared with `sbproxy`'s own `GET /admin/licensing` so the two
    /// surfaces cannot report different field sets for the same bridge.
    pub fn of(marketplace: &CompMarketplace) -> Self {
        let manifest = marketplace.manifest();
        Self {
            publisher_domain: manifest.publisher.domain.clone(),
            tier_count: manifest.tiers.len(),
            active_signing_kid: marketplace.active_signing_kid(),
            trusted_kid_count: marketplace.trusted_kid_count(),
        }
    }
}

/// `GET /admin/status` handler.
pub async fn status(State(mp): State<Arc<CompMarketplace>>) -> Json<StatusResponse> {
    Json(StatusResponse::of(&mp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comp::marketplace::InMemoryBuyerKeyRegistry;
    use crate::comp::olp_bridge::OlpBridgeSigner;
    use crate::comp::types::{CompEndpoints, CompManifest, CompPublisher};
    use crate::keys::{KeyManager, MasterKey};
    use crate::revocation::{InMemoryRevocation, Revocation};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn build_marketplace() -> Arc<CompMarketplace> {
        let keys = KeyManager::new(MasterKey::new(vec![0x11u8; 32]).unwrap());
        keys.set_active("2026-q2-001").unwrap();
        let manifest = Arc::new(CompManifest {
            comp_version: "1.0".into(),
            publisher: CompPublisher {
                name: "Example".into(),
                domain: "api.example.com".into(),
                contact: "licensing@example.com".into(),
                verified_at: None,
            },
            tiers: vec![],
            endpoints: CompEndpoints {
                manifest: "https://api.example.com/.well-known/iab-comp/manifest.json".into(),
                quote: "https://api.example.com/.well-known/iab-comp/quote".into(),
                redeem: "https://api.example.com/.well-known/iab-comp/redeem".into(),
            },
            robots_url: "https://api.example.com/robots.txt".into(),
            llms_url: "https://api.example.com/llms.txt".into(),
            rsl_url: "https://api.example.com/licenses.xml".into(),
            generated_at: "2026-05-02T14:00:00Z".into(),
            manifest_hash: "sha256:placeholder".into(),
        });
        let revocation: Arc<dyn Revocation> = Arc::new(InMemoryRevocation::new());
        let bridge = Arc::new(OlpBridgeSigner::new(
            [0x22u8; 32],
            "olp-2026-q2-001",
            "https://api.example.com",
            "ai-input",
            3600,
        ));
        let buyer_keys = Arc::new(InMemoryBuyerKeyRegistry::new());
        Arc::new(CompMarketplace::new(
            keys, manifest, revocation, bridge, buyer_keys,
        ))
    }

    #[tokio::test]
    async fn status_reports_configured_marketplace() {
        let mp = build_marketplace();
        let app = Router::new()
            .route("/admin/status", get(status))
            .with_state(mp);
        let req = Request::builder()
            .uri("/admin/status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["publisher_domain"], "api.example.com");
        assert_eq!(v["tier_count"], 0);
        assert_eq!(v["active_signing_kid"], "comp-2026-q2-001");
        assert_eq!(v["trusted_kid_count"], 1);
    }
}
