//! Contract tests for Stripe Meter Events.
//!
//! The point of this file is the separation. A meter event is usage
//! accounting: it must reach exactly one endpoint, it must never reach the
//! retired Usage Records endpoint, and it must never be able to produce
//! anything an origin could be unlocked with.

#![cfg(feature = "stripe")]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use sbproxy_billing::registry::{UsageEvent, UsageReportReceipt};
use sbproxy_billing::stripe_meter::{
    build_meter_body, classify_meter_failure, parse_meter_ack, MeterFailure, StripeMeterEndpoints,
    StripeMeterError, StripeMeterReporter, StripeMeterRequest, StripeMeterTransport,
    ATTRIBUTE_STRIPE_CUSTOMER_ID, MAX_METER_RESPONSE_BYTES, METER_EVENTS_PATH, PAYLOAD_CUSTOMER_ID,
    PAYLOAD_VALUE, STRIPE_METER_REPORTER,
};
use sbproxy_billing::stripe_payment::{
    StripeHttpMethod, StripeHttpResponse, StripeTransportFailure, STRIPE_API_VERSION,
};

/// `unwrap_err` requires `Debug` on the success type, and the form body
/// deliberately does not carry one. Errors are unwrapped through this helper
/// rather than widening a derive to suit a test.
#[track_caller]
fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Builds a usage event.
fn usage_event(quantity: u64) -> UsageEvent {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        ATTRIBUTE_STRIPE_CUSTOMER_ID.to_string(),
        "cus_fixture0001".to_string(),
    );
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
fn the_reporter_addresses_one_endpoint_and_never_the_retired_one() {
    assert_eq!(METER_EVENTS_PATH, "/v1/billing/meter_events");
    let endpoints =
        StripeMeterEndpoints::from_api_root("https://api.stripe.com").expect("a usable root");
    let url = endpoints.meter_events_url();
    assert_eq!(url, "https://api.stripe.com/v1/billing/meter_events");
    assert!(
        !url.contains("usage_records"),
        "the retired endpoint is gone"
    );
    assert!(!url.contains("subscription_items"));
    // The meter endpoint type cannot address a PaymentIntent either.
    assert!(!url.contains("payment_intents"));
}

#[test]
fn the_body_carries_the_pinned_members_and_nothing_that_reads_as_a_charge() {
    let body = build_meter_body(&usage_event(7)).expect("a complete event renders");
    assert_eq!(body.get("event_name"), Some("ai_tokens"));
    assert_eq!(body.get("identifier"), Some("usage-0001"));
    assert_eq!(body.get(PAYLOAD_CUSTOMER_ID), Some("cus_fixture0001"));
    assert_eq!(body.get(PAYLOAD_VALUE), Some("7"), "an integer value");
    assert_eq!(body.get("timestamp"), Some("1770000000"), "unix seconds");

    for forbidden in [
        "amount",
        "currency",
        "confirm",
        "capture_method",
        "shared_payment_granted_token",
    ] {
        assert!(
            !body.contains(forbidden),
            "a meter event must not carry {forbidden}"
        );
    }
}

#[test]
fn an_event_that_cannot_be_billed_is_refused_before_a_byte_leaves() {
    assert_eq!(
        expect_error(
            build_meter_body(&usage_event(0)),
            "a zero quantity must be refused"
        ),
        StripeMeterError::Quantity
    );

    let mut no_customer = usage_event(1);
    no_customer.attributes.clear();
    assert_eq!(
        expect_error(
            build_meter_body(&no_customer),
            "a missing customer must be refused"
        ),
        StripeMeterError::CustomerId
    );

    let mut empty_name = usage_event(1);
    empty_name.event_name = String::new();
    assert_eq!(
        expect_error(
            build_meter_body(&empty_name),
            "an empty event name must be refused"
        ),
        StripeMeterError::EventName
    );

    let mut empty_identifier = usage_event(1);
    empty_identifier.usage_identifier = String::new();
    assert_eq!(
        expect_error(
            build_meter_body(&empty_identifier),
            "an empty identifier must be refused"
        ),
        StripeMeterError::Identifier
    );
}

#[test]
fn rate_limits_and_server_errors_retry_while_client_errors_stop() {
    assert_eq!(classify_meter_failure(429), MeterFailure::Retry);
    assert_eq!(classify_meter_failure(500), MeterFailure::Retry);
    assert_eq!(classify_meter_failure(503), MeterFailure::Retry);
    assert_eq!(classify_meter_failure(400), MeterFailure::Terminal);
    assert_eq!(
        classify_meter_failure(402),
        MeterFailure::Terminal,
        "a refusal this reporter cannot fix by repeating it must stop"
    );
}

#[test]
fn responses_are_bounded() {
    let oversized = vec![b'a'; MAX_METER_RESPONSE_BYTES + 1];
    assert_eq!(
        expect_error(
            parse_meter_ack(&oversized),
            "an oversized answer must be refused"
        ),
        StripeMeterError::TooLarge
    );
    let ack = parse_meter_ack(br#"{"identifier":"usage-0001","event_name":"ai_tokens"}"#)
        .expect("a bounded answer parses");
    assert_eq!(ack.identifier.as_deref(), Some("usage-0001"));
}

#[test]
fn a_usage_receipt_carries_nothing_a_settlement_receipt_would() {
    let receipt = UsageReportReceipt {
        reporter: STRIPE_METER_REPORTER.to_string(),
        usage_identifier: "usage-0001".to_string(),
        provider_reference: Some("usage-0001".to_string()),
        reported_at_ms: 1_770_000_000_000,
    };
    // There is no rail, no intent, no amount, and no settled time on this
    // type, so there is nothing here a settlement receipt could be built out
    // of and nothing that could authorize a request.
    let debug = format!("{receipt:?}");
    assert!(!debug.contains("rail"));
    assert!(!debug.contains("intent_id"));
    assert!(!debug.contains("settled_at_ms"));
}

/// Records the requests a meter transport is handed.
#[derive(Default)]
struct RecordingMeterTransport {
    seen: Mutex<Vec<(String, String, String, String)>>,
}

#[async_trait::async_trait]
impl StripeMeterTransport for RecordingMeterTransport {
    async fn send_meter_event(
        &self,
        request: StripeMeterRequest<'_>,
        _timeout: Duration,
    ) -> Result<StripeHttpResponse, StripeTransportFailure> {
        self.seen.lock().expect("not poisoned").push((
            request.method.as_str().to_string(),
            request.url.to_string(),
            request.api_version.to_string(),
            request.idempotency_key.to_string(),
        ));
        Ok(StripeHttpResponse {
            status: 200,
            body: br#"{"identifier":"usage-0001"}"#.to_vec(),
        })
    }
}

#[tokio::test]
async fn a_meter_request_carries_the_pinned_version_and_the_persisted_key() {
    let transport = RecordingMeterTransport::default();
    let endpoints =
        StripeMeterEndpoints::from_api_root("https://api.stripe.com").expect("a usable root");
    let url = endpoints.meter_events_url();
    let body = build_meter_body(&usage_event(3)).expect("the body builds");
    let rendered = body.to_bytes();

    let response = transport
        .send_meter_event(
            StripeMeterRequest {
                method: StripeHttpMethod::Post,
                url: &url,
                api_version: STRIPE_API_VERSION,
                idempotency_key: "sbp1_persisted_key",
                form_body: rendered.as_slice(),
            },
            Duration::from_millis(800),
        )
        .await
        .expect("the recording transport answers");
    assert_eq!(response.status, 200);

    let seen = transport.seen.lock().expect("not poisoned");
    let (method, seen_url, version, key) = seen.first().expect("one request");
    assert_eq!(method, "POST");
    assert_eq!(seen_url, &url);
    assert_eq!(version, STRIPE_API_VERSION);
    assert_eq!(key, "sbp1_persisted_key");
}

#[test]
fn the_reporter_registers_under_its_own_name_and_pins_the_api_version() {
    let reporter = StripeMeterReporter::new(
        StripeMeterEndpoints::from_api_root("https://api.stripe.com").expect("a usable root"),
        RecordingMeterTransport::default(),
        STRIPE_API_VERSION,
        800,
    )
    .expect("the reporter builds");
    assert_eq!(reporter.api_version(), STRIPE_API_VERSION);

    // Any other version is refused at construction.
    assert!(StripeMeterReporter::new(
        StripeMeterEndpoints::from_api_root("https://api.stripe.com").expect("a usable root"),
        RecordingMeterTransport::default(),
        "2024-06-20",
        800,
    )
    .is_err());
    // So is a zero call budget.
    assert!(StripeMeterReporter::new(
        StripeMeterEndpoints::from_api_root("https://api.stripe.com").expect("a usable root"),
        RecordingMeterTransport::default(),
        STRIPE_API_VERSION,
        0,
    )
    .is_err());
}
