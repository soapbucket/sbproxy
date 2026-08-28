//! Axum router for the CoMP `/.well-known/iab-comp/*` endpoints.
//!
//! Mounts three routes:
//! * `GET  /.well-known/iab-comp/manifest.json`
//! * `POST /.well-known/iab-comp/quote`
//! * `POST /.well-known/iab-comp/redeem`
//!
//! All requests are validated against [`CompMarketplace`]; any
//! [`LicensingError`] is mapped to the appropriate HTTP status. Every
//! request also increments a [`crate::metrics`] counter and logs a
//! structured decision event, so `docs/comp-marketplace.md`'s Grafana
//! panel and access-log guidance both have something to point at.

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

use super::marketplace::CompMarketplace;
use super::types::{
    CompQuoteRequest, CompRedeemRequest, COMP_MANIFEST_CACHE_CONTROL, COMP_MANIFEST_CONTENT_TYPE,
    COMP_NO_STORE_CACHE_CONTROL, COMP_QUOTE_CONTENT_TYPE, COMP_VERSION,
};
use crate::error::LicensingError;
use crate::metrics;

/// Build the CoMP router for a marketplace bridge instance.
pub fn comp_router(marketplace: Arc<CompMarketplace>) -> Router {
    Router::new()
        .route("/.well-known/iab-comp/manifest.json", get(manifest))
        .route("/.well-known/iab-comp/quote", post(quote))
        .route("/.well-known/iab-comp/redeem", post(redeem))
        .with_state(marketplace)
}

// --- Handlers ---

async fn manifest(State(mp): State<Arc<CompMarketplace>>) -> Response {
    let body = match serde_json::to_vec(&*mp.manifest()) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "comp.manifest.encode_failed");
            metrics::record_manifest_serve("error");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "encode_failed");
        }
    };
    metrics::record_manifest_serve("ok");
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(COMP_MANIFEST_CONTENT_TYPE),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(COMP_MANIFEST_CACHE_CONTROL),
    );
    response
        .headers_mut()
        .insert("x-comp-version", HeaderValue::from_static(COMP_VERSION));
    response
}

/// Make a caller-supplied string safe to put in a log line.
///
/// `tier_id`, `quote_id`, and the error text derived from them come
/// out of a POST body on an unauthenticated endpoint. A newline in one
/// of them forges a whole log line in any collector that reads
/// newline-delimited records, which is how a fabricated "quoted"
/// decision gets into an audit trail. Control characters go, and the
/// value is capped so one request cannot write a megabyte into the log.
///
/// This is a deliberate duplicate of `sbproxy_observe::log_safe`, which
/// is what the federation peer-trust decision calls for the same
/// reason. This crate depends on `sbproxy-storage` and nothing else in
/// the workspace, and it is unlinked from every binary (WOR-2673), so
/// pulling in `sbproxy-observe` for ten lines would be the larger
/// mistake. If a third caller appears, move this to a crate all three
/// already depend on rather than adding a fourth copy. The two
/// implementations are kept byte-identical on purpose.
fn log_safe(value: &str) -> String {
    const MAX: usize = 200;
    let mut out: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX)
        .collect();
    if value.chars().count() > MAX {
        out.push_str("...");
    }
    out
}

async fn quote(
    State(mp): State<Arc<CompMarketplace>>,
    Json(req): Json<CompQuoteRequest>,
) -> Response {
    let tier_id = req.tier_id.clone();
    match mp.quote(req) {
        Ok(resp) => {
            tracing::info!(
                event = "comp_quote_decision",
                outcome = "quoted",
                tier_id = %log_safe(&tier_id),
                quote_id = %log_safe(&resp.quote_id),
                amount_micros = resp.pricing.amount_micros,
                "comp.quote.issued"
            );
            metrics::record_quote("ok");
            let body = match serde_json::to_vec(&resp) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "comp.quote.encode_failed");
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, "encode_failed");
                }
            };
            let mut response = (StatusCode::OK, body).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(COMP_QUOTE_CONTENT_TYPE),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(COMP_NO_STORE_CACHE_CONTROL),
            );
            response
        }
        Err(e) => {
            tracing::info!(
                event = "comp_quote_decision",
                outcome = "rejected",
                tier_id = %log_safe(&tier_id),
                reason = %log_safe(&e.to_string()),
                "comp.quote.rejected"
            );
            metrics::record_quote("rejected");
            map_error(e)
        }
    }
}

async fn redeem(
    State(mp): State<Arc<CompMarketplace>>,
    Json(req): Json<CompRedeemRequest>,
) -> Response {
    let quote_id = req.quote_id.clone();
    match mp.redeem(req).await {
        Ok(resp) => {
            tracing::info!(
                event = "comp_redeem_decision",
                outcome = "minted",
                quote_id = %log_safe(&quote_id),
                license = %resp.license,
                agent_id = %resp.agent_id,
                "comp.redeem.minted"
            );
            metrics::record_redeem("ok");
            let mut response = (StatusCode::OK, Json(resp)).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(COMP_NO_STORE_CACHE_CONTROL),
            );
            response
        }
        Err(e) => {
            tracing::info!(
                event = "comp_redeem_decision",
                outcome = "rejected",
                quote_id = %log_safe(&quote_id),
                reason = %log_safe(&e.to_string()),
                "comp.redeem.rejected"
            );
            metrics::record_redeem("rejected");
            map_error(e)
        }
    }
}

// --- Error mapping ---

fn map_error(err: LicensingError) -> Response {
    let (status, code) = match &err {
        LicensingError::Malformed(_) => (StatusCode::BAD_REQUEST, "malformed"),
        LicensingError::UnsupportedAlg(_) => (StatusCode::BAD_REQUEST, "unsupported_alg"),
        LicensingError::UnsupportedType(_) => (StatusCode::BAD_REQUEST, "unsupported_type"),
        LicensingError::SignatureInvalid => (StatusCode::UNAUTHORIZED, "signature_invalid"),
        LicensingError::UnknownKey(_) => (StatusCode::UNAUTHORIZED, "unknown_key"),
        LicensingError::Expired { .. } => (StatusCode::FORBIDDEN, "expired"),
        LicensingError::Revoked(_) => (StatusCode::FORBIDDEN, "revoked"),
        LicensingError::RevocationBackend(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "revocation_backend")
        }
        LicensingError::UnknownTier(_) => (StatusCode::NOT_FOUND, "unknown_tier"),
        LicensingError::Encode(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode_error"),
    };
    tracing::warn!(error = %log_safe(&err.to_string()), code = %code, status = %status.as_u16(), "comp.error");
    error_response(status, code)
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    let body = serde_json::json!({ "error": code });
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(COMP_NO_STORE_CACHE_CONTROL),
    );
    response
}
