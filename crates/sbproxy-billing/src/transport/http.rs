//! Shared bounded outbound HTTP for the provider transports.
//!
//! One place owns client construction and the body read, so the x402
//! facilitator, the Stripe settlement surface, and the Stripe meter surface
//! cannot drift apart on redirect policy, connection bounds, or the byte cap.
//! Adapters shape requests and parse responses; nothing above this module
//! touches `reqwest`.
//!
//! # Why the status is returned rather than checked
//!
//! [`bounded_body`] hands back the status code and the bytes, and treats a
//! non-2xx as a normal answer. That is deliberate. A Stripe 402 carries the
//! decline code that decides whether an attempt is terminal or retryable, and
//! an x402 facilitator states its refusal in the body of a non-2xx too.
//! Rejecting those here would throw away the only evidence the adapter has
//! and turn an authoritative refusal into an ambiguous transport failure,
//! which is the wrong direction: it would leave money in reconciliation that
//! the provider already told us about.
//!
//! # What this module does not do
//!
//! It performs no DNS resolution of its own and pins no addresses. The RAG
//! provider client does both through `sbproxy_security`, and this crate
//! cannot: it depends on no sbproxy crate except the HTTP kit, which is what
//! keeps the crate graph acyclic. The URL policy that would otherwise live
//! here is enforced earlier and more strictly instead, by
//! [`crate::x402::FacilitatorEndpoints`] and
//! [`crate::stripe_payment::StripeEndpoints`], which accept only an absolute
//! HTTPS root with no userinfo, query, or fragment, and by the configuration
//! crate, which rejects the same shapes at load. Every endpoint reachable
//! from a configuration document is therefore a public provider API root
//! chosen by the operator, not a payer-supplied value.

use std::time::Duration;

use sbproxy_httpkit::OutboundClientBuilder;

use crate::error::BillingError;

/// Budget for establishing a connection to a provider.
///
/// Separate from the per-call budget so a provider that accepts a connection
/// and then stalls is bounded by the caller's deadline, while one that never
/// accepts at all fails fast enough to leave room inside it.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Idle connections kept per provider host.
///
/// Small on purpose. A settlement path makes at most two calls per request,
/// so a large pool buys nothing and holds sockets open against a provider
/// that would rather close them.
const MAX_IDLE_PER_HOST: usize = 4;

/// How long an idle connection is kept before it is dropped.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a provider call did not produce a response.
///
/// The three shapes every adapter's own transport failure enum carries, so
/// each one maps this across without inventing a fourth case. Carries no URL,
/// header, body, or credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpFailure {
    /// The send and body read did not finish inside the budget.
    Timeout,
    /// The connection could not be established or was lost.
    Connection,
    /// The body exceeded the caller's cap.
    TooLarge,
}

/// One provider response, already bounded.
pub(crate) struct BoundedResponse {
    /// The status code, including a non-2xx the adapter will parse.
    pub(crate) status: u16,
    /// The body bytes, at most the caller's cap.
    pub(crate) body: Vec<u8>,
}

/// Builds the redirect-free, bounded client one transport reuses.
///
/// Redirects are refused rather than followed. A 30x on a payment write would
/// otherwise re-send the request body, and the idempotency key with it, to a
/// host the operator never configured.
///
/// `max_request_timeout` is the ceiling any single call may ask for. Each call
/// still applies its own budget on top, so this is a backstop against a
/// caller passing something unbounded, not the operative deadline.
///
/// # Errors
///
/// Returns [`BillingError::ProviderUnavailable`]. The underlying error is
/// dropped rather than wrapped: it can name the endpoint, and this error text
/// reaches startup logs.
pub(crate) fn build_client(max_request_timeout: Duration) -> Result<reqwest::Client, BillingError> {
    OutboundClientBuilder::new()
        .no_redirects()
        .connect_timeout(CONNECT_TIMEOUT)
        .request_timeout(max_request_timeout)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .max_idle_per_host(MAX_IDLE_PER_HOST)
        .build()
        .map_err(|_| BillingError::ProviderUnavailable)
}

/// Sends one request and reads its body under one deadline and one cap.
///
/// `tokio::time::timeout` wraps the complete send and body read, so a
/// provider that accepts the connection and then stalls mid-body cannot hold
/// a paid request past its budget. The body is read chunk by chunk and the
/// read stops as soon as the accumulated size would exceed `cap`, so an
/// oversized answer is refused rather than buffered.
pub(crate) async fn send_bounded(
    request: reqwest::RequestBuilder,
    timeout: Duration,
    cap: usize,
) -> Result<BoundedResponse, HttpFailure> {
    match tokio::time::timeout(timeout, async {
        let response = request.send().await.map_err(map_send_failure)?;
        bounded_body(response, cap).await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HttpFailure::Timeout),
    }
}

/// Reads a response body under a byte cap, keeping the status.
async fn bounded_body(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<BoundedResponse, HttpFailure> {
    let status = response.status().as_u16();
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_send_failure)? {
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(HttpFailure::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(BoundedResponse { status, body })
}

/// Maps a send or read failure onto a non-secret transport failure.
fn map_send_failure(error: reqwest::Error) -> HttpFailure {
    if error.is_timeout() {
        HttpFailure::Timeout
    } else {
        HttpFailure::Connection
    }
}
