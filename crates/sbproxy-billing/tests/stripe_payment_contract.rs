//! Contract tests for Stripe PaymentIntent settlement.
//!
//! The wire shapes come from `tests/fixtures/stripe/payment_intents.json`.
//! Request shapes are asserted against the exact bytes the settler builds, so
//! the pinned API version, the exact amount, the lowercase currency, the
//! server owned metadata, and the absence of any account-override header are
//! all observable without a socket.

#![cfg(feature = "stripe")]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use sbproxy_billing::money::Money;
use sbproxy_billing::stripe_payment::{
    build_capture_form, build_direct_create_form, build_payment_auth_create_form, classify_failure,
    parse_api_error, parse_payment_intent, require_settled, server_metadata,
    validate_payment_intent_id, write_metadata, FormBody, PaymentIntentStatus, SettlementBinding,
    StripeEndpoints, StripeError, StripeHttpMethod, StripeHttpResponse, StripeRequest,
    StripeTransport, StripeTransportFailure, DIRECT_RETRY_HEADER, IDEMPOTENCY_KEY_HEADER,
    METADATA_ACCOUNT_CONTEXT, METADATA_CHALLENGE_ID, METADATA_ORIGIN_ID, METADATA_QUOTE_ID,
    METADATA_REQUIREMENT_DIGEST, METADATA_REQUIREMENT_DRAFT_DIGEST, METADATA_TENANT_ID,
    PAYMENT_INTENTS_PATH, STRIPE_API_VERSION, STRIPE_VERSION_HEADER,
};
use sbproxy_billing::types::{
    AdvertisedRail, PaymentProtocol, PaymentRequirementDraft, RequirementTerms, SettlementRail,
};
use sbproxy_billing::BillingError;

/// The frozen PaymentIntent shapes.
const FIXTURE: &str = include_str!("fixtures/stripe/payment_intents.json");

/// The durable intent every test settles.
const INTENT_ID: &str = "sbpi_fixture_intent_0001";

/// The account context every test charges under.
const ACCOUNT_CONTEXT: &str = "acct_platform";

/// `unwrap_err` requires `Debug` on the success type, and several Stripe
/// types deliberately do not carry one because they hold client secrets and
/// single use payment tokens. Errors are unwrapped through this helper rather
/// than widening a derive to suit a test.
#[track_caller]
fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Reads one sub-document out of the frozen fixture.
#[track_caller]
fn part(name: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("the frozen fixture is valid JSON");
    parsed
        .get(name)
        .unwrap_or_else(|| panic!("fixture part {name} is missing"))
        .clone()
}

/// Serializes a fixture part to the bytes Stripe would return.
#[track_caller]
fn body(name: &str) -> Vec<u8> {
    serde_json::to_vec(&part(name)).expect("a fixture part serializes")
}

/// Builds a Stripe draft. `terms` chooses direct or Payment Auth mode.
fn draft(terms: RequirementTerms) -> PaymentRequirementDraft {
    let protocol = match terms {
        RequirementTerms::PaymentAuthStripeCharge { .. } => PaymentProtocol::PaymentAuthDraft01,
        _ => PaymentProtocol::StripePaymentIntentV1,
    };
    let advertised = match terms {
        RequirementTerms::PaymentAuthStripeCharge { .. } => AdvertisedRail::Mpp,
        _ => AdvertisedRail::Stripe,
    };
    PaymentRequirementDraft {
        requirement_id: "requirement_0123456789".to_string(),
        protocol,
        advertised_rail: advertised,
        settlement_rail: SettlementRail::Stripe,
        method: "stripe".to_string(),
        intent: "charge".to_string(),
        network: None,
        asset: None,
        pay_to: None,
        amount: Money {
            amount_micros: 12_500_000,
            currency: "USD".to_string(),
        },
        settlement_amount: "1250".to_string(),
        settlement_decimals: 2,
        terms,
        quote_id: "quote-1".to_string(),
        tenant_id: "tenant-1".to_string(),
        origin_id: "origin-1".to_string(),
        route: "/paid".to_string(),
        expires_at_ms: 2_000,
        request_digest: None,
    }
}

/// The direct rail's terms.
fn direct_terms() -> RequirementTerms {
    RequirementTerms::StripePaymentIntent {
        payment_method_types: vec!["card".to_string()],
        capture_method: "manual".to_string(),
        account_context: ACCOUNT_CONTEXT.to_string(),
    }
}

/// The Payment Auth charge's terms.
fn payment_auth_terms() -> RequirementTerms {
    RequirementTerms::PaymentAuthStripeCharge {
        business_network_id: "bn_fixture".to_string(),
        payment_method_types: vec!["card".to_string()],
        account_context: ACCOUNT_CONTEXT.to_string(),
    }
}

/// Renders a form body as a lossless string for assertions.
fn rendered(form: &FormBody) -> String {
    String::from_utf8(form.to_bytes().as_slice().to_vec()).expect("form bodies are ascii")
}

// --- Step 1: version and request shape ---

#[test]
fn every_request_carries_the_pinned_api_version() {
    assert_eq!(STRIPE_API_VERSION, "2026-06-24.dahlia");
    assert_eq!(STRIPE_VERSION_HEADER, "Stripe-Version");
    assert_eq!(IDEMPOTENCY_KEY_HEADER, "Idempotency-Key");
}

#[test]
fn the_settlement_endpoints_are_the_only_ones_built() {
    let endpoints =
        StripeEndpoints::from_api_root("https://api.stripe.com").expect("a usable root");
    assert_eq!(
        endpoints.payment_intents_url(),
        format!("https://api.stripe.com{PAYMENT_INTENTS_PATH}")
    );
    let retrieve = endpoints
        .payment_intent_url("pi_fixture0000000001")
        .expect("a usable identifier");
    let capture = endpoints
        .capture_url("pi_fixture0000000001")
        .expect("a usable identifier");
    assert!(retrieve.ends_with("/v1/payment_intents/pi_fixture0000000001"));
    assert!(capture.ends_with("/pi_fixture0000000001/capture"));

    // Settlement never addresses the usage surface.
    for url in [endpoints.payment_intents_url(), retrieve, capture] {
        assert!(!url.contains("meter_events"), "settlement must not meter");
        assert!(!url.contains("usage_records"), "no retired endpoint");
    }
}

#[test]
fn a_provider_identifier_cannot_steer_a_path() {
    for bad in ["", "pi_", "ch_abc", "pi_a/../b", "pi_a b", "pi_a?b"] {
        assert_eq!(
            expect_error(
                validate_payment_intent_id(bad),
                "an unusable identifier must be refused"
            ),
            StripeError::PaymentIntentId,
            "expected {bad:?} to be refused"
        );
    }
}

#[test]
fn the_direct_create_body_is_exact() {
    let draft = draft(direct_terms());
    let digest = draft.digest().expect("the draft hashes");
    let (form, metadata) = build_direct_create_form(
        INTENT_ID,
        &draft,
        &digest,
        &["card".to_string()],
        "manual",
        ACCOUNT_CONTEXT,
    )
    .expect("the direct create body builds");

    assert_eq!(form.get("amount"), Some("1250"), "exact minor units");
    assert_eq!(form.get("currency"), Some("usd"), "lowercase currency");
    assert_eq!(form.get("capture_method"), Some("manual"));
    assert_eq!(form.get("confirmation_method"), Some("automatic"));
    assert_eq!(form.get("confirm"), Some("false"));
    assert_eq!(form.get("payment_method_types[0]"), Some("card"));

    // Stripe treats the two method selectors as alternatives, so the direct
    // rail sends exactly one of them.
    let text = rendered(&form);
    assert!(
        !text.contains("automatic_payment_methods"),
        "the two selectors are alternatives"
    );

    // Server owned bindings, including the account context and the draft
    // digest that direct mode binds because an identifier cannot bind itself.
    assert_eq!(form.get("metadata[sbproxy_quote_id]"), Some("quote-1"));
    assert_eq!(form.get("metadata[sbproxy_challenge_id]"), Some(INTENT_ID));
    assert_eq!(form.get("metadata[sbproxy_tenant_id]"), Some("tenant-1"));
    assert_eq!(form.get("metadata[sbproxy_origin_id]"), Some("origin-1"));
    assert_eq!(
        form.get("metadata[sbproxy_account_context]"),
        Some(ACCOUNT_CONTEXT)
    );
    assert_eq!(
        form.get("metadata[sbproxy_requirement_draft_digest]"),
        Some(hex::encode(digest).as_str())
    );
    assert!(
        !form.contains("metadata[sbproxy_requirement_digest]"),
        "direct mode binds the draft digest, not the final one"
    );
    assert!(metadata.contains_key(METADATA_REQUIREMENT_DRAFT_DIGEST));
}

#[test]
fn the_payment_auth_create_body_is_exact() {
    let draft = draft(payment_auth_terms());
    let requirement_digest = [0x5au8; 32];
    let (form, metadata) = build_payment_auth_create_form(
        INTENT_ID,
        &draft,
        &requirement_digest,
        ACCOUNT_CONTEXT,
        "spt_fixture_token",
    )
    .expect("the payment auth create body builds");

    assert_eq!(form.get("amount"), Some("1250"));
    assert_eq!(form.get("currency"), Some("usd"));
    assert_eq!(
        form.get("shared_payment_granted_token"),
        Some("spt_fixture_token")
    );
    assert_eq!(form.get("confirm"), Some("true"));
    assert_eq!(form.get("automatic_payment_methods[enabled]"), Some("true"));
    assert_eq!(
        form.get("automatic_payment_methods[allow_redirects]"),
        Some("never")
    );
    // Payment Auth creates its intent after the challenge is final, so it
    // binds the final requirement digest.
    assert_eq!(
        form.get("metadata[sbproxy_requirement_digest]"),
        Some(hex::encode(requirement_digest).as_str())
    );
    assert!(!form.contains("metadata[sbproxy_requirement_draft_digest]"));
    assert!(metadata.contains_key(METADATA_REQUIREMENT_DIGEST));
    let text = rendered(&form);
    assert!(
        !text.contains("payment_method_types"),
        "automatic payment methods is the selector here"
    );
}

#[test]
fn no_client_metadata_can_override_a_server_binding() {
    let draft = draft(direct_terms());
    let digest = draft.digest().expect("the draft hashes");
    let server = server_metadata(
        INTENT_ID,
        &draft,
        METADATA_REQUIREMENT_DRAFT_DIGEST,
        &digest,
        ACCOUNT_CONTEXT,
    );
    for key in [
        METADATA_QUOTE_ID,
        METADATA_CHALLENGE_ID,
        METADATA_TENANT_ID,
        METADATA_ORIGIN_ID,
        METADATA_ACCOUNT_CONTEXT,
        METADATA_REQUIREMENT_DRAFT_DIGEST,
        METADATA_REQUIREMENT_DIGEST,
        "sbproxy_anything_at_all",
    ] {
        let client: BTreeMap<String, String> = [(key.to_string(), "hostile".to_string())]
            .into_iter()
            .collect();
        let mut form = FormBody::new();
        assert_eq!(
            expect_error(
                write_metadata(&mut form, &server, &client),
                "a server namespace key must be refused"
            ),
            StripeError::MetadataConflict,
            "expected {key} to be refused"
        );
    }
}

#[test]
fn the_capture_body_names_the_exact_amount() {
    let form = build_capture_form(1_250).expect("the capture body builds");
    assert_eq!(rendered(&form), "amount_to_capture=1250");
}

// --- Step 2 and 3: what does and does not authorize ---

#[test]
fn only_a_bound_succeeded_intent_becomes_a_receipt() {
    let draft = draft(direct_terms());
    let digest = draft.digest().expect("the draft hashes");
    let mut metadata = server_metadata(
        INTENT_ID,
        &draft,
        METADATA_REQUIREMENT_DRAFT_DIGEST,
        &digest,
        ACCOUNT_CONTEXT,
    );
    // The fixture carries a placeholder digest, so bind against that value.
    metadata.insert(
        METADATA_REQUIREMENT_DRAFT_DIGEST.to_string(),
        "DRAFT_DIGEST".to_string(),
    );

    let intent = parse_payment_intent(&body("succeeded")).expect("the fixture parses");
    let binding = SettlementBinding {
        intent_id: INTENT_ID,
        minor_units: 1_250,
        currency: "usd",
        metadata: &metadata,
        method: "stripe",
        now_ms: 1_000,
    };
    let receipt = require_settled(&intent, &binding).expect("a bound success settles");
    assert_eq!(receipt.provider_reference, "pi_fixture0000000001");
    assert_eq!(receipt.rail, SettlementRail::Stripe);
    assert_eq!(receipt.intent_id, INTENT_ID);
}

#[test]
fn every_unsettled_state_denies_access() {
    let metadata = BTreeMap::new();
    let binding = SettlementBinding {
        intent_id: INTENT_ID,
        minor_units: 1_250,
        currency: "usd",
        metadata: &metadata,
        method: "stripe",
        now_ms: 1_000,
    };
    for (name, expected) in [
        ("requires_capture", BillingError::NotSettled),
        ("requires_action", BillingError::NotSettled),
        ("processing", BillingError::NotSettled),
        ("canceled", BillingError::ProviderRejected),
        ("unknown_status", BillingError::ProviderMalformed),
    ] {
        let intent = parse_payment_intent(&body(name)).expect("the fixture parses");
        assert_eq!(
            expect_error(
                require_settled(&intent, &binding),
                "an unsettled state must deny"
            ),
            expected,
            "expected {name} to deny"
        );
    }
}

#[test]
fn a_mismatched_amount_currency_or_binding_denies_access() {
    let intent = parse_payment_intent(&body("succeeded")).expect("the fixture parses");
    let metadata = BTreeMap::new();
    let base = SettlementBinding {
        intent_id: INTENT_ID,
        minor_units: 1_250,
        currency: "usd",
        metadata: &metadata,
        method: "stripe",
        now_ms: 1_000,
    };
    assert!(require_settled(&intent, &base).is_ok());

    let wrong_amount = SettlementBinding {
        minor_units: 1_251,
        ..base
    };
    assert_eq!(
        expect_error(
            require_settled(&intent, &wrong_amount),
            "an amount mismatch must deny"
        ),
        BillingError::RequirementMismatch
    );

    let wrong_currency = SettlementBinding {
        currency: "eur",
        ..base
    };
    assert_eq!(
        expect_error(
            require_settled(&intent, &wrong_currency),
            "a currency mismatch must deny"
        ),
        BillingError::RequirementMismatch
    );

    let hostile: BTreeMap<String, String> =
        [(METADATA_QUOTE_ID.to_string(), "quote-2".to_string())]
            .into_iter()
            .collect();
    let wrong_metadata = SettlementBinding {
        metadata: &hostile,
        ..base
    };
    assert_eq!(
        expect_error(
            require_settled(&intent, &wrong_metadata),
            "a metadata mismatch must deny"
        ),
        BillingError::RequirementMismatch
    );
}

#[test]
fn a_partial_success_is_ambiguous_rather_than_settled() {
    // A success that omits `amount_received` states nothing about capture.
    let intent = parse_payment_intent(
        br#"{"id":"pi_abc123","status":"succeeded","amount":1250,"currency":"usd"}"#,
    )
    .expect("a partial body parses");
    let metadata = BTreeMap::new();
    let binding = SettlementBinding {
        intent_id: INTENT_ID,
        minor_units: 1_250,
        currency: "usd",
        metadata: &metadata,
        method: "stripe",
        now_ms: 1_000,
    };
    assert_eq!(
        expect_error(
            require_settled(&intent, &binding),
            "a partial success is not a receipt"
        ),
        BillingError::RequirementMismatch
    );
}

// --- Step 4: ambiguity ---

#[test]
fn ambiguity_and_refusal_are_told_apart() {
    assert_eq!(
        classify_failure(402, &body("card_declined")),
        BillingError::ProviderRejected,
        "a decline is authoritative"
    );
    assert_eq!(
        classify_failure(400, &body("idempotency_conflict")),
        BillingError::NeedsReconciliation,
        "a key reuse leaves the write outstanding"
    );
    assert_eq!(
        classify_failure(429, &body("rate_limited")),
        BillingError::ProviderUnavailable
    );
    assert_eq!(
        classify_failure(409, b"{}"),
        BillingError::NeedsReconciliation
    );
    assert_eq!(
        classify_failure(500, b"{}"),
        BillingError::ProviderUnavailable
    );
    assert_eq!(
        classify_failure(503, b"{}"),
        BillingError::ProviderUnavailable
    );
}

#[test]
fn only_the_machine_readable_half_of_an_error_is_kept() {
    let parsed = parse_api_error(&body("card_declined"));
    assert_eq!(parsed.error_type.as_deref(), Some("card_error"));
    assert_eq!(parsed.code.as_deref(), Some("card_declined"));
    assert_eq!(parsed.decline_code.as_deref(), Some("generic_decline"));
    // The free-text message is dropped, because free text is how provider
    // prose ends up in a durable column.
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("Your card was declined"));
}

// --- Privacy ---

#[test]
fn a_client_secret_never_reaches_a_request_or_a_binding() {
    let intent = parse_payment_intent(&body("requires_capture")).expect("the fixture parses");
    let secret = intent
        .client_secret
        .as_ref()
        .expect("the fixture carries one")
        .clone();
    assert!(secret.contains("_secret_"));

    // Nothing the settler sends, and nothing it binds, can carry it.
    let draft = draft(direct_terms());
    let digest = draft.digest().expect("the draft hashes");
    let (form, metadata) = build_direct_create_form(
        INTENT_ID,
        &draft,
        &digest,
        &["card".to_string()],
        "manual",
        ACCOUNT_CONTEXT,
    )
    .expect("the direct create body builds");
    assert!(!rendered(&form).contains(secret.as_str()));
    for value in metadata.values() {
        assert!(!value.contains("_secret_"));
    }
}

// --- Transport shape ---

/// Records the exact requests a transport is handed.
#[derive(Default)]
struct RecordingTransport {
    seen: Mutex<Vec<(String, String, String, Option<String>, usize)>>,
}

#[async_trait::async_trait]
impl StripeTransport for RecordingTransport {
    async fn send(
        &self,
        request: StripeRequest<'_>,
        _timeout: Duration,
    ) -> Result<StripeHttpResponse, StripeTransportFailure> {
        self.seen.lock().expect("not poisoned").push((
            request.method.as_str().to_string(),
            request.url.to_string(),
            request.api_version.to_string(),
            request.idempotency_key.map(str::to_string),
            request.form_body.map_or(0, <[u8]>::len),
        ));
        Ok(StripeHttpResponse {
            status: 200,
            body: body("succeeded"),
        })
    }
}

#[tokio::test]
async fn a_request_carries_the_pinned_version_and_the_persisted_key_and_no_account_override() {
    let transport = RecordingTransport::default();
    let endpoints =
        StripeEndpoints::from_api_root("https://api.stripe.com").expect("a usable root");
    let url = endpoints.payment_intents_url();
    let form = build_capture_form(1_250).expect("a body builds");
    let rendered_bytes = form.to_bytes();

    let response = transport
        .send(
            StripeRequest {
                method: StripeHttpMethod::Post,
                url: &url,
                api_version: STRIPE_API_VERSION,
                idempotency_key: Some("sbp1_persisted_key"),
                form_body: Some(rendered_bytes.as_slice()),
            },
            Duration::from_millis(800),
        )
        .await
        .expect("the recording transport answers");
    assert_eq!(response.status, 200);

    let seen = transport.seen.lock().expect("not poisoned");
    let (method, seen_url, version, key, body_len) = seen.first().expect("one request");
    assert_eq!(method, "POST");
    assert_eq!(seen_url, &url);
    assert_eq!(version, STRIPE_API_VERSION);
    assert_eq!(key.as_deref(), Some("sbp1_persisted_key"));
    assert!(*body_len > 0);
    // `StripeRequest` has no field that could carry a `Stripe-Account`
    // header, so the platform account is the only one a request can charge
    // on. That is a structural guarantee, not a policy.
}

#[test]
fn the_direct_rail_names_its_retry_header() {
    assert_eq!(DIRECT_RETRY_HEADER, "Crawler-Payment");
}

#[test]
fn statuses_parse_only_into_states_this_build_knows() {
    assert_eq!(
        PaymentIntentStatus::parse("succeeded"),
        Some(PaymentIntentStatus::Succeeded)
    );
    assert_eq!(PaymentIntentStatus::parse("requires_review"), None);
    assert!(PaymentIntentStatus::Succeeded.is_settled());
    assert!(!PaymentIntentStatus::RequiresCapture.is_settled());
}
