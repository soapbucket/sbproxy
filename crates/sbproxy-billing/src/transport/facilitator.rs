//! The outbound client the x402 rail reaches its facilitator through.
//!
//! [`X402ExactSettler`](crate::x402::X402ExactSettler) owns the protocol: the
//! verify-then-settle order, the deadline, the breaker, and every rule about
//! what an answer has to say before it authorizes. This type owns one socket
//! and nothing else. It posts the bytes it is given to the URL it is given
//! and hands back the status and the bounded body.
//!
//! There is no credential here because x402 has none. A facilitator call
//! carries the payer's signed payload and the exact requirement, both of
//! which the settler built; the proxy holds no key the facilitator would
//! authenticate.

use std::time::Duration;

use crate::error::BillingError;
use crate::transport::http::{build_client, send_bounded, HttpFailure};
use crate::x402::{
    FacilitatorHttpResponse, FacilitatorTransport, TransportFailure,
    MAX_FACILITATOR_RESPONSE_BYTES, MAX_TOTAL_DEADLINE_MS,
};

/// Content type on every facilitator request.
const JSON_CONTENT_TYPE: &str = "application/json";

/// The bounded HTTP client the x402 rail posts through.
///
/// `Clone` shares the underlying connection pool rather than building a
/// second one, which is what lets one adapter hold a settler per configured
/// facilitator without opening a separate pool for each. The breaker is not
/// shared: it belongs to the settler, so each facilitator still fails
/// independently.
#[derive(Clone)]
pub struct HttpFacilitatorTransport {
    client: reqwest::Client,
}

impl HttpFacilitatorTransport {
    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ProviderUnavailable`] when the client cannot
    /// be constructed.
    pub fn new() -> Result<Self, BillingError> {
        Ok(Self {
            client: build_client(Duration::from_millis(MAX_TOTAL_DEADLINE_MS))?,
        })
    }
}

impl std::fmt::Debug for HttpFacilitatorTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HttpFacilitatorTransport").finish()
    }
}

#[async_trait::async_trait]
impl FacilitatorTransport for HttpFacilitatorTransport {
    async fn post_json(
        &self,
        url: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<FacilitatorHttpResponse, TransportFailure> {
        let request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, JSON_CONTENT_TYPE)
            .body(body.to_vec());

        let response = send_bounded(request, timeout, MAX_FACILITATOR_RESPONSE_BYTES)
            .await
            .map_err(map_failure)?;
        Ok(FacilitatorHttpResponse {
            status: response.status,
            body: response.body,
        })
    }
}

/// Maps the shared failure onto the x402 adapter's own enum.
const fn map_failure(failure: HttpFailure) -> TransportFailure {
    match failure {
        HttpFailure::Timeout => TransportFailure::Timeout,
        HttpFailure::Connection => TransportFailure::Connection,
        HttpFailure::TooLarge => TransportFailure::TooLarge,
    }
}
