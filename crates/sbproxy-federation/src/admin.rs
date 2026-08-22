//! Operator-facing status surface for this crate.
//!
//! This crate ships as an independent set of axum handlers rather
//! than a module inside the main `sbproxy` binary, so it does not
//! have a page in `ui/`, which is the admin console for that
//! binary's own request pipeline. `GET /admin/status` (mounted by
//! [`crate::router`]) is this crate's own equivalent: a small JSON
//! surface an operator (or a script, or a future `ui/` integration
//! once a federation-aware feature is wired behind the main proxy)
//! can poll to see what this entity currently publishes, without
//! needing a Prometheus query client or decoding the well-known JWS
//! by hand.
//!
//! The route is unauthenticated by design, matching
//! `/.well-known/openid-federation` itself: everything it reveals
//! (the entity id, the signing algorithm and `kid`, how many keys,
//! authority hints, and trust marks are configured, and how much
//! cache lifetime remains) is already public in the well-known
//! document this entity serves. No private key material or JWS
//! signature ever appears in the response.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use serde::Serialize;

use crate::well_known::WellKnownIssuer;

/// `GET /admin/status` response body.
#[derive(Debug, Serialize)]
pub(crate) struct StatusResponse {
    /// Entity URL this issuer publishes as both `iss` and `sub`.
    pub entity_id: String,
    /// JWS algorithm the issuer signs with.
    pub signing_algorithm: String,
    /// `kid` stamped on every signed entity configuration.
    pub signing_kid: String,
    /// Number of public keys published under `jwks`.
    pub published_keys: usize,
    /// Number of `authority_hints` this entity advertises. Zero
    /// means this entity has no configured superior and can only
    /// ever be resolved as a trust anchor itself.
    pub authority_hints: usize,
    /// Number of trust marks this entity claims.
    pub trust_marks: usize,
    /// Whether a `metadata_policy` block is configured for this
    /// entity's subordinates (only meaningful for an intermediate,
    /// not a leaf).
    pub metadata_policy_configured: bool,
    /// Configured lifetime of each signed configuration, in seconds.
    pub lifetime_secs: u64,
    /// Configured refresh margin, in seconds.
    pub refresh_margin_secs: u64,
    /// Seconds remaining on the currently cached document, or `null`
    /// when producing it failed (surfaced instead of a 500 so an
    /// operator polling this route still gets the rest of the
    /// static config back).
    pub cache_remaining_secs: Option<u64>,
}

/// `GET /admin/status` handler.
pub(crate) async fn status(State(issuer): State<Arc<WellKnownIssuer>>) -> Json<StatusResponse> {
    let cfg = issuer.config();
    let cache_remaining_secs = issuer
        .current()
        .ok()
        .map(|doc| doc.cache_max_age_secs(chrono::Utc::now()));
    Json(StatusResponse {
        entity_id: cfg.entity_id.clone(),
        signing_algorithm: format!("{:?}", cfg.signing_key.algorithm),
        signing_kid: cfg.signing_key.kid.clone(),
        published_keys: cfg.published_jwks.keys.len(),
        authority_hints: cfg.authority_hints.len(),
        trust_marks: cfg.trust_marks.len(),
        metadata_policy_configured: cfg.metadata_policy.is_some(),
        lifetime_secs: cfg.lifetime.as_secs(),
        refresh_margin_secs: cfg.refresh_margin.as_secs(),
        cache_remaining_secs,
    })
}

#[cfg(test)]
mod tests {
    use crate::entity_statement::{EntityMetadata, FederationEntityMetadata};
    use crate::well_known::{FederationServerConfig, SigningKeyConfig, WellKnownIssuer};
    use crate::FederationKeySet;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use http_body_util::BodyExt;
    use jsonwebtoken::Algorithm;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn build_issuer() -> Arc<WellKnownIssuer> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;
        let signing = SigningKey::random(&mut rand::thread_rng());
        let pem = signing.to_pkcs8_pem(Default::default()).unwrap();
        let verifying = signing.verifying_key();
        let point = verifying.to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            "kid": "test-key",
        });
        let mut keys = FederationKeySet::empty();
        keys.push(jwk);
        let cfg = FederationServerConfig {
            entity_id: "https://gateway.acme.example".to_string(),
            signing_key: SigningKeyConfig {
                pem: pem.as_bytes().to_vec(),
                algorithm: Algorithm::ES256,
                kid: "test-key".to_string(),
            },
            published_jwks: keys,
            metadata: EntityMetadata {
                federation_entity: Some(FederationEntityMetadata::default()),
                other: Default::default(),
            },
            authority_hints: vec!["https://trust-anchor.example".to_string()],
            trust_marks: vec![],
            metadata_policy: None,
            lifetime: Duration::from_secs(3600),
            refresh_margin: Duration::from_secs(360),
        };
        Arc::new(WellKnownIssuer::new(cfg).unwrap())
    }

    /// The route reports the static config an operator would
    /// otherwise have to decode from the well-known JWS by hand, and
    /// never a 500 even before the first `current()` call primes the
    /// cache (the handler calls `current()` itself).
    #[tokio::test]
    async fn status_reports_configured_entity() {
        let issuer = build_issuer();
        let app = crate::router(issuer);
        let req = Request::builder()
            .uri("/admin/status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["entity_id"], "https://gateway.acme.example");
        assert_eq!(v["signing_algorithm"], "ES256");
        assert_eq!(v["published_keys"], 1);
        assert_eq!(v["authority_hints"], 1);
        assert_eq!(v["metadata_policy_configured"], false);
        assert!(v["cache_remaining_secs"].as_u64().unwrap() > 0);
    }
}
