//! Axum router for the CoMP `/.well-known/iab-comp/*` endpoints.
//!
//! Mounts three routes:
//! * `GET  /.well-known/iab-comp/manifest.json`
//! * `POST /.well-known/iab-comp/quote`
//! * `POST /.well-known/iab-comp/redeem`
//!
//! Every handler here is a thin adapter: it reads the request body up
//! to [`COMP_REQUEST_BODY_LIMIT`], hands it to the matching
//! [`super::serve`] function, and writes that function's
//! [`super::serve::CompResponse`] out as an axum response. A body past
//! the cap is [`super::serve::oversize`], which is also a
//! `CompResponse`, so there is no response on this transport that does
//! not come from that module. The status, the headers, the [`crate::metrics`]
//! counter, and the decision-event log line are all decided there, so
//! a host that serves these URLs off some other transport (the sbproxy
//! request path does) gets identical behavior rather than a second
//! hand-rolled copy that drifts.
//!
//! `sbproxy` itself is that other host. This router is what a
//! standalone marketplace process mounts; see
//! `examples/standalone_marketplace.rs`.

use axum::body::{to_bytes, Body, Bytes};
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
        // Each route's `fallback` is what answers a method this
        // endpoint does not serve (WOR-2673 re-review N8). Without it
        // axum answers its own bodyless 405, which is the same class of
        // gap the `DefaultBodyLimit` layer opened for the oversize
        // refusal: a response on this transport that did not come from
        // [`super::serve`], with no counter and no decision event.
        .route(
            "/.well-known/iab-comp/manifest.json",
            get(manifest).fallback(manifest_method_not_allowed),
        )
        .route(
            "/.well-known/iab-comp/quote",
            post(quote).fallback(quote_method_not_allowed),
        )
        .route(
            "/.well-known/iab-comp/redeem",
            post(redeem).fallback(redeem_method_not_allowed),
        )
        .with_state(marketplace)
}

/// Largest CoMP request body this router will buffer.
///
/// Quote and redeem bodies are a few hundred bytes of JSON. The cap is
/// generous by two orders of magnitude and still refuses an
/// unauthenticated caller that tries to make the process buffer.
/// `sbproxy`'s own request path applies the same limit at its own read
/// loop; see `COMP_REQUEST_BODY_LIMIT` there.
///
/// Enforced by [`axum::body::to_bytes`] inside each POST handler, not
/// by a `DefaultBodyLimit` layer (WOR-2673 re-review N1). Both bound
/// the allocation the same way, and `to_bytes` stops reading at the
/// same point the layer does. The difference is what answers: the
/// layer rejects inside the `Bytes` extractor before the handler runs,
/// which returned axum's own `text/plain` "Failed to buffer the
/// request body" with no `Cache-Control`, no
/// `sbproxy_comp_marketplace_*` counter, and no decision event, on a
/// transport whose whole contract is that every response comes from
/// [`super::serve`]. Refusing in the handler keeps the one shared body.
pub const COMP_REQUEST_BODY_LIMIT: usize = 64 * 1024;

// --- Handlers ---

async fn manifest(State(marketplace): State<Arc<CompMarketplace>>) -> Response {
    into_response(serve::serve_manifest(&marketplace))
}

async fn quote(State(marketplace): State<Arc<CompMarketplace>>, body: Body) -> Response {
    let body = match read_capped(body, serve::CompEndpoint::Quote).await {
        Ok(body) => body,
        Err(refused) => return refused,
    };
    into_response(serve::serve_quote(&marketplace, &body))
}

async fn redeem(State(marketplace): State<Arc<CompMarketplace>>, body: Body) -> Response {
    let body = match read_capped(body, serve::CompEndpoint::Redeem).await {
        Ok(body) => body,
        Err(refused) => return refused,
    };
    into_response(serve::serve_redeem(&marketplace, &body).await)
}

/// Read a request body, refusing past [`COMP_REQUEST_BODY_LIMIT`].
///
/// `to_bytes` fails for two unrelated reasons, and they must not be
/// counted as one: a body past the cap, and a body the transport could
/// not finish delivering (the client hung up mid-send, the connection
/// reset). Mapping both to `oversize` wrote
/// `reason = "body_too_large"` into the audit trail for a client that
/// simply disconnected, which is a false record of what happened.
///
/// The two are told apart by reading one byte past the cap. A body that
/// comes back longer than `COMP_REQUEST_BODY_LIMIT` tripped it; an
/// `Err` at that limit could only have come from the transport, because
/// the size ceiling has not been reached yet. Exact, and it needs
/// neither a size hint (which a chunked body may not carry) nor an
/// `http-body` dependency this crate does not otherwise have.
///
/// Reading one extra byte is what the cap already tolerated: the
/// previous shape buffered the whole body and then measured it.
// An axum `Response` is over `result_large_err`'s threshold, and boxing it
// would buy nothing: the `Err` here is the response both callers return
// unchanged, so a box would be unwrapped at each of them and dropped.
#[allow(clippy::result_large_err)]
async fn read_capped(body: Body, endpoint: serve::CompEndpoint) -> Result<Bytes, Response> {
    match to_bytes(body, COMP_REQUEST_BODY_LIMIT + 1).await {
        Ok(body) if body.len() > COMP_REQUEST_BODY_LIMIT => {
            Err(into_response(serve::oversize(endpoint)))
        }
        Ok(body) => Ok(body),
        Err(error) => {
            // Not a refusal the marketplace made, so it moves no
            // decision counter: nothing was decided. A truncated body is
            // a transport event, and the one line says so.
            tracing::debug!(
                error = %error,
                "comp.body.incomplete: the client did not finish sending"
            );
            Err(into_response(serve::CompResponse {
                status: 400,
                content_type: "application/json",
                cache_control: super::types::COMP_NO_STORE_CACHE_CONTROL,
                comp_version: None,
                body: br#"{"error":"incomplete_body"}"#.to_vec(),
            }))
        }
    }
}

async fn manifest_method_not_allowed() -> Response {
    into_response(serve::method_not_allowed(serve::CompEndpoint::Manifest))
}

async fn quote_method_not_allowed() -> Response {
    into_response(serve::method_not_allowed(serve::CompEndpoint::Quote))
}

async fn redeem_method_not_allowed() -> Response {
    into_response(serve::method_not_allowed(serve::CompEndpoint::Redeem))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comp::serve::tests::{counter, marketplace};
    use crate::metrics;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    /// Drive one request through the real router and return its status,
    /// its headers, and its body.
    async fn through_the_transport(
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let app = comp_router(Arc::new(marketplace()));
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("request builds");
        let response = app.oneshot(request).await.expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }

    /// WOR-2673 re-review N1: the oversize refusal has to be reachable
    /// on this transport, not just callable.
    ///
    /// The previous round added `serve::oversize` and called it from a
    /// `body.len()` check inside the handler, then added a
    /// `DefaultBodyLimit` layer on the same routes with the same
    /// threshold. The layer rejects inside axum's extractor before the
    /// handler runs, so the handler branch became unreachable and this
    /// transport reverted to axum's own refusal: `text/plain`, the body
    /// `Failed to buffer the request body`, no `Cache-Control`, no
    /// counter, and no decision event. Two metric descriptions,
    /// `docs/comp-marketplace.md`, and a change fragment all assert the
    /// opposite.
    ///
    /// Every assertion below fails against that shape, which is what
    /// makes this the test the previous round was missing: the one
    /// beside it in `serve.rs` calls `oversize` directly and is blind to
    /// which transport can reach it.
    #[tokio::test]
    async fn an_oversize_quote_is_refused_by_this_transport_in_the_shared_shape() {
        let before = counter(&metrics::QUOTE_REQUESTS_TOTAL, "rejected");
        let oversize_body = vec![b'x'; COMP_REQUEST_BODY_LIMIT + 1];
        let (status, headers, body) =
            through_the_transport("POST", "/.well-known/iab-comp/quote", oversize_body).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json"),
            "the refusal must be the shared JSON shape, not axum's text/plain"
        );
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some(super::super::types::COMP_NO_STORE_CACHE_CONTROL),
            "`CompResponse::cache_control` exists so a transport cannot forget this"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("the refusal body is JSON");
        assert_eq!(parsed["error"], "body_too_large");
        assert!(
            counter(&metrics::QUOTE_REQUESTS_TOTAL, "rejected") > before,
            "an oversize flood must move the same family every other refusal moves"
        );
    }

    /// The redeem half of the same property. Both routes carried the
    /// layer, so both reverted.
    #[tokio::test]
    async fn an_oversize_redeem_is_refused_by_this_transport_in_the_shared_shape() {
        let before = counter(&metrics::REDEEM_REQUESTS_TOTAL, "rejected");
        let oversize_body = vec![b'x'; COMP_REQUEST_BODY_LIMIT + 1];
        let (status, headers, body) =
            through_the_transport("POST", "/.well-known/iab-comp/redeem", oversize_body).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some(super::super::types::COMP_NO_STORE_CACHE_CONTROL)
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("the refusal body is JSON");
        assert_eq!(parsed["error"], "body_too_large");
        assert!(counter(&metrics::REDEEM_REQUESTS_TOTAL, "rejected") > before);
    }

    /// A body at the cap is not oversize. Without this the fix could be
    /// an off-by-one that refuses the largest legal request.
    #[tokio::test]
    async fn a_body_exactly_at_the_cap_still_reaches_the_handler() {
        // Not valid JSON, so the marketplace refuses it as `malformed`.
        // That refusal is the proof it got past the size check: an
        // oversize answer would have been `body_too_large` instead.
        let at_the_cap = vec![b'x'; COMP_REQUEST_BODY_LIMIT];
        let (status, _, body) =
            through_the_transport("POST", "/.well-known/iab-comp/quote", at_the_cap).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("the refusal body is JSON");
        assert_eq!(parsed["error"], "malformed");
    }

    /// WOR-2673 re-review N8: a method this endpoint does not serve is
    /// a refusal like any other, from the same shared body.
    ///
    /// Axum answers its own bodyless 405 for a method mismatch on a
    /// matched route unless the route carries a `fallback`, which is the
    /// same shape as the `DefaultBodyLimit` trap in N1: a response on
    /// this transport that did not come from `serve`, with no counter
    /// and no decision event.
    #[tokio::test]
    async fn a_wrong_method_is_refused_in_the_shared_shape_and_counted() {
        let before = counter(&metrics::REDEEM_REQUESTS_TOTAL, "rejected");
        let (status, headers, body) =
            through_the_transport("GET", "/.well-known/iab-comp/redeem", Vec::new()).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json"),
            "axum's own 405 is bodyless; this must be the shared shape"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("the refusal body is JSON");
        assert_eq!(parsed["error"], "method_not_allowed");
        assert!(counter(&metrics::REDEEM_REQUESTS_TOTAL, "rejected") > before);
    }

    /// The manifest route through the transport, so the headers the
    /// shared body sets are proved to survive the adapter.
    #[tokio::test]
    async fn the_manifest_route_carries_its_headers_through_the_transport() {
        let (status, headers, _) =
            through_the_transport("GET", "/.well-known/iab-comp/manifest.json", Vec::new()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get("x-comp-version")
                .and_then(|value| value.to_str().ok()),
            Some(super::super::types::COMP_VERSION)
        );
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some(super::super::types::COMP_MANIFEST_CACHE_CONTROL)
        );
    }
}
