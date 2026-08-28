//! Axum router for the CoMP `/.well-known/iab-comp/*` endpoints.
//!
//! Mounts three routes:
//! * `GET  /.well-known/iab-comp/manifest.json`
//! * `POST /.well-known/iab-comp/quote`
//! * `POST /.well-known/iab-comp/redeem`
//!
//! Every handler here is a thin adapter: it reads the request body,
//! hands it to the matching [`super::serve`] function, and writes that
//! function's [`super::serve::CompResponse`] out as an
//! axum response. The status, the headers, the [`crate::metrics`]
//! counter, and the decision-event log line are all decided there, so
//! a host that serves these URLs off some other transport (the sbproxy
//! request path does) gets identical behavior rather than a second
//! hand-rolled copy that drifts.
//!
//! `sbproxy` itself is that other host. This router is what a
//! standalone marketplace process mounts; see
//! `examples/standalone_marketplace.rs`.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

use super::marketplace::CompMarketplace;
use super::serve::{self, CompResponse};

/// Build the CoMP router for a marketplace bridge instance.
pub fn comp_router(marketplace: Arc<CompMarketplace>) -> Router {
    Router::new()
        .route("/.well-known/iab-comp/manifest.json", get(manifest))
        .route("/.well-known/iab-comp/quote", post(quote))
        .route("/.well-known/iab-comp/redeem", post(redeem))
        .with_state(marketplace)
}

/// Largest CoMP request body this router will buffer.
///
/// Quote and redeem bodies are a few hundred bytes of JSON. The cap is
/// generous by two orders of magnitude and still refuses an
/// unauthenticated caller that tries to make the process buffer.
/// `sbproxy`'s own request path applies the same limit at its own read
/// loop; see `COMP_REQUEST_BODY_LIMIT` there.
pub const COMP_REQUEST_BODY_LIMIT: usize = 64 * 1024;

// --- Handlers ---

async fn manifest(State(marketplace): State<Arc<CompMarketplace>>) -> Response {
    into_response(serve::serve_manifest(&marketplace))
}

async fn quote(State(marketplace): State<Arc<CompMarketplace>>, body: Bytes) -> Response {
    if body.len() > COMP_REQUEST_BODY_LIMIT {
        return oversize();
    }
    into_response(serve::serve_quote(&marketplace, &body))
}

async fn redeem(State(marketplace): State<Arc<CompMarketplace>>, body: Bytes) -> Response {
    if body.len() > COMP_REQUEST_BODY_LIMIT {
        return oversize();
    }
    into_response(serve::serve_redeem(&marketplace, &body).await)
}

// --- Rendering ---

/// Write a [`CompResponse`] out as an axum response.
fn into_response(rendered: CompResponse) -> Response {
    let status = StatusCode::from_u16(rendered.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, rendered.body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(rendered.content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(rendered.cache_control),
    );
    if let Some(version) = rendered.comp_version {
        headers.insert("x-comp-version", HeaderValue::from_static(version));
    }
    response
}

/// The refusal for a body past [`COMP_REQUEST_BODY_LIMIT`].
fn oversize() -> Response {
    into_response(CompResponse {
        status: 413,
        content_type: "application/json",
        cache_control: super::types::COMP_NO_STORE_CACHE_CONTROL,
        comp_version: None,
        body: br#"{"error":"body_too_large"}"#.to_vec(),
    })
}
