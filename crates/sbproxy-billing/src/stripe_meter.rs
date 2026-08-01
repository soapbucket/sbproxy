//! Stripe Meter Events: usage accounting, and never proof of payment.
//!
//! This module reports usage. It cannot settle anything, and that is enforced
//! by the type system rather than by a comment. [`StripeMeterReporter`]
//! implements [`UsageReporter`], which has no way to build a
//! [`crate::types::SettlementReceipt`], no way to reach
//! [`crate::store::SettlementStore::mark_succeeded`], and no way to move an
//! intent to [`crate::types::IntentStatus::Succeeded`]. A successful meter
//! event therefore cannot authorize a request no matter what a caller does
//! with it.
//!
//! The separation is complete on purpose:
//!
//! - a different trait, [`UsageReporter`] rather than
//!   [`crate::registry::PaymentMethodAdapter`];
//! - a different transport, [`StripeMeterTransport`];
//! - a different endpoint type, [`StripeMeterEndpoints`], which can build
//!   [`METER_EVENTS_PATH`] and nothing else;
//! - a different error enum, [`StripeMeterError`];
//! - a different durable table, the store's usage queue rather than the
//!   payment attempt tables.
//!
//! The retired Usage Records endpoint is not reachable from here. There is no
//! constant for it, no path builder that could produce it, and a contract test
//! asserts that the only path this module ever sends is
//! [`METER_EVENTS_PATH`].
//!
//! # Idempotency and duplicates
//!
//! Every POST carries the durable provider idempotency key the dispatch gate
//! persisted, and every event carries the caller's stable `identifier`. Stripe
//! deduplicates meter events on that identifier, so a replay after a lost
//! response records one unit of usage rather than two. That is why this module
//! needs no encrypted recovery envelope: the request is safe to repeat by
//! construction, which a charge never is.
//!
//! The reporter shares one bounded, redacting HTTP client with the settlement
//! module in the runtime, and shares its form encoder here, because a second
//! percent encoder is a second place to get escaping wrong. Nothing else is
//! shared.

use std::time::Duration;

use serde::Deserialize;

use crate::dispatch::DispatchContext;
use crate::error::BillingError;
use crate::registry::{UsageEvent, UsageReportReceipt, UsageReporter};
use crate::stripe_payment::{
    normalize_api_root, FormBody, StripeError, StripeHttpMethod, StripeHttpResponse,
    StripeTransportFailure, STRIPE_API_VERSION,
};

/// The only path this module ever sends.
pub const METER_EVENTS_PATH: &str = "/v1/billing/meter_events";

/// The stable name this reporter registers under.
pub const STRIPE_METER_REPORTER: &str = "stripe_meter";

/// The event attribute naming the Stripe customer usage is billed to.
pub const ATTRIBUTE_STRIPE_CUSTOMER_ID: &str = "stripe_customer_id";

/// The payload member carrying the customer identifier.
pub const PAYLOAD_CUSTOMER_ID: &str = "payload[stripe_customer_id]";

/// The payload member carrying the integer quantity.
pub const PAYLOAD_VALUE: &str = "payload[value]";

/// Largest meter event response this module will read, in bytes.
pub const MAX_METER_RESPONSE_BYTES: usize = 64 * 1024;

/// Longest event name accepted.
const MAX_EVENT_NAME_LEN: usize = 200;

/// Longest deduplication identifier accepted.
const MAX_IDENTIFIER_LEN: usize = 200;

/// Longest customer identifier accepted.
const MAX_CUSTOMER_ID_LEN: usize = 255;

/// Required prefix on a Stripe customer identifier.
const CUSTOMER_ID_PREFIX: &str = "cus_";

// A duplicate identifier is deliberately not special-cased by error code.
//
// Stripe publishes no error code for one. Its documented meter codes are
// namespaced (`meter_event_no_customer_defined`,
// `meter_event_value_too_many_digits`), the v1 endpoint this module calls
// enforces identifier uniqueness by deduplicating server-side rather than by
// refusing, and its published error-code list contains nothing for the case.
// An earlier revision matched a guessed `duplicate_identifier` string, which
// could only ever be wrong in the expensive direction: a guess that
// accidentally matched some other refusal would record a usage report that
// genuinely failed as accepted, and under-bill silently.
//
// Nothing is lost by dropping it, because every retry this reporter issues
// carries the same durable `Idempotency-Key`. Stripe's idempotency contract
// replays the original response for a repeated key, so a retried event comes
// back as the original 200 and takes the success path before any
// deduplication error could arise. A duplicate identifier reaching a 4xx
// therefore means a different request reused an identifier, which is a bug
// worth surfacing rather than an outcome worth accepting.

// --- Errors ---

/// Everything the usage reporter refuses locally.
///
/// Separate from the settlement error enum on purpose. A usage failure and a
/// settlement failure must never be able to be confused for one another at a
/// call site, in a metric, or in a durable column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StripeMeterError {
    /// The configured API root is not a usable HTTPS root.
    #[error("stripe meter API root is not a usable https root")]
    ApiRoot,

    /// The event name was empty or oversized.
    #[error("stripe meter event name is not usable")]
    EventName,

    /// The deduplication identifier was empty or oversized.
    #[error("stripe meter identifier is not usable")]
    Identifier,

    /// The event carried no usable Stripe customer identifier.
    #[error("stripe meter event has no usable customer identifier")]
    CustomerId,

    /// The quantity was zero, so there was no usage to report.
    #[error("stripe meter quantity must be a positive whole number")]
    Quantity,

    /// The event time was not representable as a Unix second.
    #[error("stripe meter event time is not representable")]
    Timestamp,

    /// A response did not parse as the pinned contract.
    #[error("stripe meter response does not match the pinned contract")]
    Malformed,

    /// A response exceeded [`MAX_METER_RESPONSE_BYTES`].
    #[error("stripe meter response exceeds its size bound")]
    TooLarge,

    /// The configured call budget is not usable.
    #[error("stripe meter call budget is not usable")]
    Deadline,
}

impl From<StripeMeterError> for BillingError {
    fn from(error: StripeMeterError) -> Self {
        match error {
            StripeMeterError::ApiRoot => Self::InvalidRequirement("stripe_meter_api_root"),
            StripeMeterError::Deadline => Self::InvalidRequirement("stripe_meter_deadline"),
            StripeMeterError::EventName
            | StripeMeterError::Identifier
            | StripeMeterError::CustomerId
            | StripeMeterError::Quantity
            | StripeMeterError::Timestamp => Self::InvalidRequirement("stripe_meter_event"),
            StripeMeterError::Malformed | StripeMeterError::TooLarge => Self::ProviderMalformed,
        }
    }
}

impl From<StripeError> for StripeMeterError {
    fn from(error: StripeError) -> Self {
        // Only two shared pieces can fail here: root normalization, and the
        // form encoder's duplicate-key refusal, which this module's fixed set
        // of literal keys cannot trigger.
        match error {
            StripeError::ApiRoot => Self::ApiRoot,
            _ => Self::Malformed,
        }
    }
}

// --- Endpoints ---

/// The one endpoint the usage surface serves.
///
/// This type can build [`METER_EVENTS_PATH`] and nothing else. A settlement
/// call cannot reach a meter URL and a meter call cannot reach a PaymentIntent
/// URL, because neither type can express the other's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeMeterEndpoints {
    root: String,
}

impl StripeMeterEndpoints {
    /// Normalizes a configured HTTPS API root.
    ///
    /// # Errors
    ///
    /// Returns [`StripeMeterError::ApiRoot`].
    pub fn from_api_root(root: &str) -> Result<Self, StripeMeterError> {
        Ok(Self {
            root: normalize_api_root(root, false)?,
        })
    }

    /// Builds endpoints for a cleartext loopback fixture.
    ///
    /// Test only. Nothing reachable from a configuration document calls this.
    ///
    /// # Errors
    ///
    /// Returns [`StripeMeterError::ApiRoot`].
    pub fn loopback_http_for_test(root: &str) -> Result<Self, StripeMeterError> {
        Ok(Self {
            root: normalize_api_root(root, true)?,
        })
    }

    /// Returns the normalized API root.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Returns the meter events URL.
    #[must_use]
    pub fn meter_events_url(&self) -> String {
        format!("{}{METER_EVENTS_PATH}", self.root)
    }
}

// --- Transport ---

/// One outbound meter event call, minus every credential.
///
/// The API key is owned by the transport implementation, so it is not a field
/// here and cannot reach a log, an error, or a durable column. Deliberately
/// carries no `Debug`: the body names a Stripe customer, which is a payer
/// identifier.
pub struct StripeMeterRequest<'a> {
    /// The HTTP method. Always [`StripeHttpMethod::Post`].
    pub method: StripeHttpMethod,
    /// The absolute URL, already built from a normalized root.
    pub url: &'a str,
    /// The pinned API version to send as
    /// [`crate::stripe_payment::STRIPE_VERSION_HEADER`].
    pub api_version: &'a str,
    /// The durable provider idempotency key, sent as
    /// [`crate::stripe_payment::IDEMPOTENCY_KEY_HEADER`].
    pub idempotency_key: &'a str,
    /// The rendered form body.
    pub form_body: &'a [u8],
}

/// The bounded outbound client this module reports usage through.
///
/// Deliberately a different trait from the settlement transport. One runtime
/// type may implement both, but a caller cannot pass a meter request to the
/// settlement surface or the other way round.
#[async_trait::async_trait]
pub trait StripeMeterTransport: Send + Sync {
    /// Sends one meter event and returns the bounded response.
    async fn send_meter_event(
        &self,
        request: StripeMeterRequest<'_>,
        timeout: Duration,
    ) -> Result<StripeHttpResponse, StripeTransportFailure>;
}

// --- Wire contract ---

/// The parts of a meter event answer this module reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeterEventAck {
    /// The identifier Stripe echoed back, when it echoed one.
    pub identifier: Option<String>,
    /// The event name Stripe echoed back, when it echoed one.
    pub event_name: Option<String>,
}

/// The wire form of a meter event answer.
#[derive(Deserialize)]
struct MeterEventAckWire {
    #[serde(default)]
    identifier: Option<String>,
    #[serde(default)]
    event_name: Option<String>,
}

/// Parses a bounded meter event answer.
///
/// # Errors
///
/// Returns [`StripeMeterError::TooLarge`] above
/// [`MAX_METER_RESPONSE_BYTES`] and [`StripeMeterError::Malformed`] when the
/// body is not the pinned shape.
pub fn parse_meter_ack(body: &[u8]) -> Result<MeterEventAck, StripeMeterError> {
    if body.len() > MAX_METER_RESPONSE_BYTES {
        return Err(StripeMeterError::TooLarge);
    }
    let wire: MeterEventAckWire =
        serde_json::from_slice(body).map_err(|_| StripeMeterError::Malformed)?;
    Ok(MeterEventAck {
        identifier: wire.identifier,
        event_name: wire.event_name,
    })
}

/// What a non-2xx meter answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterFailure {
    /// The call may succeed later.
    Retry,
    /// The call will never succeed as written.
    Terminal,
}

/// Reads a non-2xx meter answer.
///
/// A 429 and a 5xx are retried, because usage accounting is allowed to be
/// eventually consistent in a way a charge is not. Every other status is a
/// request this reporter will never fix by repeating it, so it stops rather
/// than queueing forever.
///
/// The classification is by status alone. Stripe's meter error codes are not
/// enumerated in a contract this crate can pin, and guessing one would make a
/// refusal readable as an acceptance. See the note beside the constants above
/// for why a duplicate identifier needs no branch of its own.
#[must_use]
pub const fn classify_meter_failure(status: u16) -> MeterFailure {
    match status {
        429 | 500..=599 => MeterFailure::Retry,
        _ => MeterFailure::Terminal,
    }
}

// --- Reporter ---

/// The Stripe Meter Events usage reporter.
///
/// It reports usage. It never settles, never creates an intent, never emits a
/// receipt an origin could be unlocked with, and never touches a payment
/// table.
pub struct StripeMeterReporter<T: StripeMeterTransport> {
    endpoints: StripeMeterEndpoints,
    transport: T,
    api_version: String,
    call_timeout: Duration,
}

impl<T: StripeMeterTransport> StripeMeterReporter<T> {
    /// Builds a reporter.
    ///
    /// # Errors
    ///
    /// Returns [`StripeMeterError::ApiRoot`] for anything but the pinned API
    /// version, and [`StripeMeterError::Deadline`] for a zero call budget.
    /// The version check reuses the settlement pin so one build can never
    /// report usage under a different contract than it settles under.
    pub fn new(
        endpoints: StripeMeterEndpoints,
        transport: T,
        api_version: &str,
        call_timeout_ms: u64,
    ) -> Result<Self, StripeMeterError> {
        if api_version != STRIPE_API_VERSION {
            return Err(StripeMeterError::ApiRoot);
        }
        if call_timeout_ms == 0 {
            return Err(StripeMeterError::Deadline);
        }
        Ok(Self {
            endpoints,
            transport,
            api_version: api_version.to_string(),
            call_timeout: Duration::from_millis(call_timeout_ms),
        })
    }

    /// Returns the endpoint this reporter is bound to.
    #[must_use]
    pub fn endpoints(&self) -> &StripeMeterEndpoints {
        &self.endpoints
    }

    /// Returns the pinned API version every request carries.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }
}

/// Renders one usage event as a meter event form body.
///
/// Every field is checked before a byte leaves: an empty event name, a missing
/// or malformed customer identifier, a zero quantity, and a time that is not
/// representable as a Unix second are all refused here rather than becoming a
/// Stripe 400 on the worker's next pass.
///
/// # Errors
///
/// Returns the matching [`StripeMeterError`].
pub fn build_meter_body(event: &UsageEvent) -> Result<FormBody, StripeMeterError> {
    if event.event_name.trim().is_empty() || event.event_name.len() > MAX_EVENT_NAME_LEN {
        return Err(StripeMeterError::EventName);
    }
    if event.usage_identifier.trim().is_empty() || event.usage_identifier.len() > MAX_IDENTIFIER_LEN
    {
        return Err(StripeMeterError::Identifier);
    }
    if event.quantity == 0 {
        return Err(StripeMeterError::Quantity);
    }
    let customer = event
        .attributes
        .get(ATTRIBUTE_STRIPE_CUSTOMER_ID)
        .map(String::as_str)
        .ok_or(StripeMeterError::CustomerId)?;
    if !customer.starts_with(CUSTOMER_ID_PREFIX)
        || customer.len() <= CUSTOMER_ID_PREFIX.len()
        || customer.len() > MAX_CUSTOMER_ID_LEN
        || !customer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(StripeMeterError::CustomerId);
    }
    if event.occurred_at_ms <= 0 {
        return Err(StripeMeterError::Timestamp);
    }
    let timestamp = event.occurred_at_ms / 1_000;

    let mut body = FormBody::new();
    body.set("event_name", &event.event_name)?;
    body.set("identifier", &event.usage_identifier)?;
    body.set(PAYLOAD_CUSTOMER_ID, customer)?;
    body.set_u64(PAYLOAD_VALUE, event.quantity)?;
    body.set("timestamp", &timestamp.to_string())?;
    Ok(body)
}

#[async_trait::async_trait]
impl<T: StripeMeterTransport> UsageReporter for StripeMeterReporter<T> {
    fn reporter_name(&self) -> &'static str {
        STRIPE_METER_REPORTER
    }

    async fn report(
        &self,
        event: &UsageEvent,
        dispatch: &DispatchContext,
    ) -> Result<UsageReportReceipt, BillingError> {
        let body = build_meter_body(event)?;
        let rendered = body.to_bytes();
        let url = self.endpoints.meter_events_url();
        let key = dispatch.provider_idempotency_key().to_string();
        let reported_at_ms = dispatch.now_ms();

        // The reporter drives the gate itself and calls it exactly once. The
        // service does not wrap this: a second wrapper would make this
        // `run_write` lose its compare exchange, the POST would be skipped,
        // and every usage report would come back terminal with nothing sent.
        dispatch
            .run_write(|| async {
                let response = self
                    .transport
                    .send_meter_event(
                        StripeMeterRequest {
                            method: StripeHttpMethod::Post,
                            url: &url,
                            api_version: &self.api_version,
                            idempotency_key: &key,
                            form_body: rendered.as_slice(),
                        },
                        self.call_timeout,
                    )
                    .await
                    .map_err(meter_transport_error)?;

                if !(200..300).contains(&response.status) {
                    return match classify_meter_failure(response.status) {
                        MeterFailure::Retry => Err(BillingError::ProviderUnavailable),
                        MeterFailure::Terminal => Err(BillingError::ProviderRejected),
                    };
                }

                if response.body.len() > MAX_METER_RESPONSE_BYTES {
                    return Err(BillingError::ProviderMalformed);
                }
                let ack = parse_meter_ack(&response.body)?;
                Ok(UsageReportReceipt {
                    reporter: event.reporter.clone(),
                    usage_identifier: event.usage_identifier.clone(),
                    provider_reference: ack.identifier,
                    reported_at_ms,
                })
            })
            .await
    }
}

/// Maps a meter transport failure onto a durable failure.
///
/// A lost meter write is retried rather than reconciled: the identifier makes
/// the request safe to repeat, which is the whole reason usage reporting needs
/// no encrypted recovery envelope.
const fn meter_transport_error(failure: StripeTransportFailure) -> BillingError {
    match failure {
        StripeTransportFailure::Timeout => BillingError::ProviderTimeout,
        StripeTransportFailure::Connection => BillingError::ProviderUnavailable,
        StripeTransportFailure::TooLarge => BillingError::ProviderMalformed,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// `unwrap_err` requires `Debug` on the success type, and [`FormBody`]
    /// deliberately does not carry one. Errors are unwrapped through this
    /// helper rather than widening a derive to suit a test.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    /// Builds a usage event with one attribute set.
    fn event_fixture(quantity: u64, customer: Option<&str>) -> UsageEvent {
        let mut attributes = BTreeMap::new();
        if let Some(customer) = customer {
            attributes.insert(
                ATTRIBUTE_STRIPE_CUSTOMER_ID.to_string(),
                customer.to_string(),
            );
        }
        UsageEvent {
            reporter: STRIPE_METER_REPORTER.to_string(),
            usage_identifier: "usage-0001".to_string(),
            tenant_id: "tenant-1".to_string(),
            origin_id: "origin-1".to_string(),
            event_name: "ai_tokens".to_string(),
            quantity,
            occurred_at_ms: 1_770_000_000_000,
            attributes,
        }
    }

    #[test]
    fn the_only_path_is_the_meter_events_path() {
        let endpoints =
            StripeMeterEndpoints::from_api_root("https://api.stripe.com").expect("a usable root");
        let url = endpoints.meter_events_url();
        assert_eq!(url, "https://api.stripe.com/v1/billing/meter_events");
        // The retired Usage Records endpoint is not reachable from this type.
        assert!(!url.contains("usage_records"));
        assert!(!url.contains("subscription_items"));
    }

    #[test]
    fn the_body_carries_the_pinned_members() {
        let body = build_meter_body(&event_fixture(7, Some("cus_abc123")))
            .expect("a complete event renders");
        assert_eq!(body.get("event_name"), Some("ai_tokens"));
        assert_eq!(body.get("identifier"), Some("usage-0001"));
        assert_eq!(body.get(PAYLOAD_CUSTOMER_ID), Some("cus_abc123"));
        assert_eq!(body.get(PAYLOAD_VALUE), Some("7"));
        assert_eq!(body.get("timestamp"), Some("1770000000"));
        // Nothing that could be read as a settlement is present.
        assert!(!body.contains("amount"));
        assert!(!body.contains("currency"));
        assert!(!body.contains("confirm"));
    }

    #[test]
    fn incomplete_events_are_refused_before_a_byte_leaves() {
        assert_eq!(
            expect_error(
                build_meter_body(&event_fixture(0, Some("cus_abc123"))),
                "a zero quantity must be refused"
            ),
            StripeMeterError::Quantity
        );
        assert_eq!(
            expect_error(
                build_meter_body(&event_fixture(1, None)),
                "a missing customer must be refused"
            ),
            StripeMeterError::CustomerId
        );
        assert_eq!(
            expect_error(
                build_meter_body(&event_fixture(1, Some("acct_abc"))),
                "a non-customer identifier must be refused"
            ),
            StripeMeterError::CustomerId
        );
    }

    #[test]
    fn retryable_and_terminal_answers_are_told_apart() {
        assert_eq!(classify_meter_failure(429), MeterFailure::Retry);
        assert_eq!(classify_meter_failure(503), MeterFailure::Retry);
        assert_eq!(classify_meter_failure(500), MeterFailure::Retry);
        assert_eq!(classify_meter_failure(400), MeterFailure::Terminal);
        assert_eq!(classify_meter_failure(401), MeterFailure::Terminal);
        assert_eq!(classify_meter_failure(404), MeterFailure::Terminal);
    }

    /// A refusal this crate cannot name must never read as an acceptance.
    ///
    /// The guard is on the enum rather than on any one code: `MeterFailure`
    /// has no variant that turns a non-2xx into a recorded unit of usage, so
    /// there is no error body Stripe could send that silently under-bills.
    /// An earlier revision matched a guessed `duplicate_identifier` string
    /// that Stripe does not publish, and its test built the fixture from the
    /// same constant, so it asserted only that the code agreed with itself.
    #[test]
    fn no_error_body_can_be_read_as_recorded_usage() {
        for body in [
            &br#"{"error":{"type":"invalid_request_error","code":"duplicate_identifier"}}"#[..],
            &br#"{"error":{"type":"invalid_request_error","code":"meter_event_no_customer_defined"}}"#[..],
            &br#"{"error":{"type":"invalid_request_error","code":"anything_at_all"}}"#[..],
            &b"{}"[..],
        ] {
            // The body is parseable and carries a code, and none of it can
            // change the verdict: only the status decides.
            let _ = crate::stripe_payment::parse_api_error(body);
            assert_eq!(
                classify_meter_failure(400),
                MeterFailure::Terminal,
                "a 400 stays terminal whatever the error body claims"
            );
        }
    }

    #[test]
    fn a_meter_answer_is_not_a_settlement_receipt() {
        let ack = parse_meter_ack(br#"{"identifier":"usage-0001","event_name":"ai_tokens"}"#)
            .expect("the answer parses");
        assert_eq!(ack.identifier.as_deref(), Some("usage-0001"));
        // `MeterEventAck` has no rail, no intent, no amount, and no settled
        // time, so there is nothing here a receipt could be built from.
        assert_eq!(ack.event_name.as_deref(), Some("ai_tokens"));
    }
}
