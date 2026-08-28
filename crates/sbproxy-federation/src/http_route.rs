//! Axum route handler for the §9 well-known endpoint.
//!
//! Exposes a single function a host router registers at
//! [`crate::WELL_KNOWN_FEDERATION_PATH`]
//! (`/.well-known/openid-federation`). The handler calls
//! [`crate::WellKnownIssuer::current`] and serves the compact JWS
//! with the spec-defined media type
//! ([`crate::ENTITY_STATEMENT_CONTENT_TYPE`]) and a
//! `Cache-Control: public, max-age=N` header reflecting the
//! document's remaining lifetime.
//!
//! ## Why a thin axum wrapper, not "the router"
//!
//! A host that embeds this crate (an MCP gateway, a control-plane
//! HTTP server, or the standalone example) already has its own
//! router, state struct, and middleware stack. This module ships
//! just the handler so a host slots it into its existing router with
//! one line:
//!
//! ```ignore
//! use axum::{routing::get, Router};
//! use sbproxy_federation::{
//!     entity_configuration_handler, WellKnownIssuer, WELL_KNOWN_FEDERATION_PATH,
//! };
//! let issuer = std::sync::Arc::new(WellKnownIssuer::new(cfg)?);
//! let router: Router = Router::new()
//!     .route(WELL_KNOWN_FEDERATION_PATH, get(entity_configuration_handler))
//!     .with_state(issuer);
//! ```
//!
//! A deployment that has no router of its own yet can call
//! [`crate::router`] instead, which mounts this handler alongside the
//! `/admin/status` surface.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::well_known::WellKnownIssuer;
use crate::ENTITY_STATEMENT_CONTENT_TYPE;

/// Axum handler for `GET /.well-known/openid-federation`.
///
/// Returns the cached entity configuration as the response body
/// with `Content-Type: application/entity-statement+jwt` and a
/// `Cache-Control: public, max-age=<remaining-lifetime>` header.
///
/// Returns `503 Service Unavailable` (with no body) when the
/// issuer fails to produce a fresh configuration. The handler does
/// not leak the underlying [`crate::FederationError`] to the wire:
/// a peer that probes the well-known endpoint should not see
/// internal error categories. Operators observe the failure via the
/// `tracing::error!` event the handler emits on the error path and
/// the `sbproxy_federation_well_known_serves_total{outcome="unavailable"}`
/// counter; see `docs/federation.md`.
pub async fn entity_configuration_handler(State(issuer): State<Arc<WellKnownIssuer>>) -> Response {
    let served = serve_entity_configuration(&issuer);
    let Some(body) = served.body else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut response = (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(ENTITY_STATEMENT_CONTENT_TYPE),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_str(&served.cache_control)
                    .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=0")),
            ),
        ],
        body,
    )
        .into_response();
    response
        .headers_mut()
        .entry(header::VARY)
        .or_insert(HeaderValue::from_static("Accept"));
    response
}

/// The well-known handler's whole body, minus the axum plumbing.
///
/// This is where the two metric writers, the `Cache-Control` value, and
/// the decision log lines live, so a host that does not speak axum
/// serves the same document with the same instrumentation. sbproxy's
/// own request path is one of those hosts: it is Pingora, and while it
/// hand-rolled this response the five `sbproxy_federation_*` families
/// read flat zero on the only binary that ships the crate, and peers
/// got no cache directive at all.
///
/// `body` is `None` when the issuer could not produce a configuration,
/// which is the caller's cue to answer 503 with no body: a peer probing
/// the well-known endpoint must not learn the error category.
pub fn serve_entity_configuration(issuer: &WellKnownIssuer) -> ServedEntityConfiguration {
    let now = chrono::Utc::now();
    match issuer.current_at(now) {
        Ok(doc) => {
            let max_age = doc.cache_max_age_secs(now);
            crate::metrics::record_well_known_serve("served");
            crate::metrics::record_well_known_cache_remaining(
                i64::try_from(max_age).unwrap_or(i64::MAX),
            );
            // Stamp a structured tracing field so operators can
            // grep for federation-config serves alongside the
            // other gateway access logs.
            tracing::debug!(
                target: "sbproxy_federation::http_route",
                entity_id = %issuer.config().entity_id,
                cache_max_age_secs = max_age,
                "served well-known entity configuration"
            );
            ServedEntityConfiguration {
                status: 200,
                cache_control: format!("public, max-age={max_age}"),
                body: Some(doc.compact_jws.clone()),
            }
        }
        Err(err) => {
            crate::metrics::record_well_known_serve("unavailable");
            tracing::error!(
                target: "sbproxy_federation::http_route",
                error = %err,
                "failed to produce entity configuration; returning 503"
            );
            ServedEntityConfiguration {
                status: 503,
                cache_control: "no-store".to_string(),
                body: None,
            }
        }
    }
}

/// What [`serve_entity_configuration`] decided, in transport-neutral
/// form.
#[derive(Debug, Clone)]
pub struct ServedEntityConfiguration {
    /// HTTP status to answer with.
    pub status: u16,
    /// `Cache-Control` value. Peers and CDNs refetch on every use
    /// without one, and the remaining lifetime is the only honest
    /// number to give them.
    pub cache_control: String,
    /// The compact JWS, or `None` when the issuer could not produce
    /// one.
    pub body: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_statement::{EntityMetadata, FederationEntityMetadata};
    use crate::well_known::{FederationServerConfig, SigningKeyConfig, WellKnownIssuer};
    use crate::FederationKeySet;
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::StatusCode;
    use base64::Engine;
    use jsonwebtoken::Algorithm;
    use std::sync::Arc;
    use std::time::Duration;

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
            authority_hints: vec![],
            trust_marks: vec![],
            metadata_policy: None,
            lifetime: Duration::from_secs(3600),
            refresh_margin: Duration::from_secs(360),
        };
        Arc::new(WellKnownIssuer::new(cfg).unwrap())
    }

    /// Happy path: handler returns 200 OK with the spec
    /// Content-Type and a Cache-Control header.
    #[tokio::test]
    async fn handler_serves_signed_jws_with_spec_headers() {
        let issuer = build_issuer();
        let response = entity_configuration_handler(State(issuer.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers.get(http::header::CONTENT_TYPE).unwrap(),
            ENTITY_STATEMENT_CONTENT_TYPE
        );
        let cc = headers
            .get(http::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cc.starts_with("public, max-age="));
        // Vary: Accept stamped so an upstream CDN's negotiation
        // doesn't collapse responses across the OIDF media type
        // and a future JSON envelope.
        assert_eq!(headers.get(http::header::VARY).unwrap(), "Accept");

        let body = response.into_body();
        let body_bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        // Three base64url-encoded segments separated by dots.
        let parts: Vec<&str> = body_str.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS must have 3 segments");
    }

    /// Body type sanity: the handler returns an axum::Response
    /// whose body is the compact JWS string, not a JSON wrapper.
    #[tokio::test]
    async fn body_is_raw_compact_jws_not_json() {
        let issuer = build_issuer();
        let response = entity_configuration_handler(State(issuer)).await;
        let body = response.into_body();
        let body_bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let s = std::str::from_utf8(&body_bytes).unwrap();
        // Not JSON-wrapped: no leading `{` or `"`.
        assert!(!s.starts_with('{'));
        assert!(!s.starts_with('"'));
    }
}
