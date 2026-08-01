//! The outbound client both Stripe surfaces reach the API through.
//!
//! One type implements both [`StripeTransport`] and [`StripeMeterTransport`],
//! because both talk to the same host with the same key over the same
//! connection pool. That is a fact about the socket, not about authority: the
//! two traits stay separate, so a settlement call cannot be handed a meter
//! request or the other way round, and
//! [`StripeMeterReporter`](crate::stripe_meter::StripeMeterReporter) still has
//! no way to build a receipt. Sharing a client does not share a permission.
//!
//! # The key lives here and only here
//!
//! Nothing above this module holds the Stripe secret key. It is attached as
//! the `Authorization` header at send time and is never a field on a settler,
//! a request struct, an error, or a durable column, so there is no path from
//! a settlement failure back to a credential. The header value is marked
//! sensitive as well, which keeps it out of anything that formats a
//! `HeaderMap`.
//!
//! Cloning shares the key rather than copying it: the `Arc` means the settler
//! and the reporter hold the same bytes, and those bytes are wiped once when
//! the last holder drops.

use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::BillingError;
use crate::stripe_meter::{StripeMeterRequest, StripeMeterTransport, MAX_METER_RESPONSE_BYTES};
use crate::stripe_payment::{
    StripeHttpMethod, StripeHttpResponse, StripeRequest, StripeTransport, StripeTransportFailure,
    IDEMPOTENCY_KEY_HEADER, MAX_STRIPE_RESPONSE_BYTES, MAX_TOTAL_DEADLINE_MS,
    STRIPE_VERSION_HEADER,
};
use crate::transport::http::{build_client, send_bounded, HttpFailure};

/// Content type on every Stripe write.
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// The bounded HTTP client for one Stripe account.
///
/// Deliberately carries no derived `Debug`: it owns the secret key, and a
/// derived `Debug` is how a key reaches a panic message.
#[derive(Clone)]
pub struct HttpStripeTransport {
    client: reqwest::Client,
    api_key: Arc<Zeroizing<String>>,
}

impl HttpStripeTransport {
    /// Builds the client around a resolved secret key.
    ///
    /// The key is taken as already resolved and already checked. The runtime
    /// validates that `proxy.payments.rails.stripe.api_key` resolved to
    /// something usable before it gets here, in the same place it validates
    /// the recovery key, so this constructor has no opinion about the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ProviderUnavailable`] when the client cannot
    /// be constructed. The endpoint is not echoed.
    pub fn new(api_key: Zeroizing<String>) -> Result<Self, BillingError> {
        Ok(Self {
            client: build_client(Duration::from_millis(MAX_TOTAL_DEADLINE_MS))?,
            api_key: Arc::new(api_key),
        })
    }

    /// Attaches the credential and the pinned API version.
    ///
    /// The authorization header is marked sensitive so it is redacted by
    /// anything that formats the header map.
    fn authorized(
        &self,
        builder: reqwest::RequestBuilder,
        api_version: &str,
    ) -> reqwest::RequestBuilder {
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.api_key.as_str()))
                .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("Bearer"));
        authorization.set_sensitive(true);
        builder
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(STRIPE_VERSION_HEADER, api_version)
    }
}

impl std::fmt::Debug for HttpStripeTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HttpStripeTransport").finish()
    }
}

#[async_trait::async_trait]
impl StripeTransport for HttpStripeTransport {
    async fn send(
        &self,
        request: StripeRequest<'_>,
        timeout: Duration,
    ) -> Result<StripeHttpResponse, StripeTransportFailure> {
        let mut builder = match request.method {
            StripeHttpMethod::Get => self.client.get(request.url),
            StripeHttpMethod::Post => self.client.post(request.url),
        };
        builder = self.authorized(builder, request.api_version);
        if let Some(key) = request.idempotency_key {
            builder = builder.header(IDEMPOTENCY_KEY_HEADER, key);
        }
        if let Some(body) = request.form_body {
            builder = builder
                .header(reqwest::header::CONTENT_TYPE, FORM_CONTENT_TYPE)
                .body(body.to_vec());
        }

        let response = send_bounded(builder, timeout, MAX_STRIPE_RESPONSE_BYTES)
            .await
            .map_err(map_failure)?;
        Ok(StripeHttpResponse {
            status: response.status,
            body: response.body,
        })
    }
}

#[async_trait::async_trait]
impl StripeMeterTransport for HttpStripeTransport {
    async fn send_meter_event(
        &self,
        request: StripeMeterRequest<'_>,
        timeout: Duration,
    ) -> Result<StripeHttpResponse, StripeTransportFailure> {
        let builder = self
            .authorized(self.client.post(request.url), request.api_version)
            .header(IDEMPOTENCY_KEY_HEADER, request.idempotency_key)
            .header(reqwest::header::CONTENT_TYPE, FORM_CONTENT_TYPE)
            .body(request.form_body.to_vec());

        let response = send_bounded(builder, timeout, MAX_METER_RESPONSE_BYTES)
            .await
            .map_err(map_failure)?;
        Ok(StripeHttpResponse {
            status: response.status,
            body: response.body,
        })
    }
}

/// Maps the shared failure onto the Stripe adapters' own enum.
const fn map_failure(failure: HttpFailure) -> StripeTransportFailure {
    match failure {
        HttpFailure::Timeout => StripeTransportFailure::Timeout,
        HttpFailure::Connection => StripeTransportFailure::Connection,
        HttpFailure::TooLarge => StripeTransportFailure::TooLarge,
    }
}
