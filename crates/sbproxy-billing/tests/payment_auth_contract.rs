//! Frozen byte contract for `draft-ryan-httpauth-payment-01`.
//!
//! Every assertion here is against bytes that are pinned in
//! `tests/fixtures/payment_auth_draft01.json`. If a change to the codec
//! moves one of them, the change moved the protocol, and this file is
//! meant to be the thing that notices.
//!
//! The negative half is the more important half: a malformed, expired,
//! replayed, or wrong scope credential must be refused, never repaired.

#![cfg(feature = "mpp")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use sbproxy_billing::payment_auth::{
    body_digest_sha256, decode_credential, encode_jcs_base64url, parse_accept_payment,
    parse_rfc3339_utc, select_payment_credential, ChallengeBinder, ChallengeOpaque,
    PaymentAuthError, PaymentAuthProblemCode, PaymentAuthReceipt, PaymentChallenge,
    StripeChargeMethodDetails, StripeChargeRequest, CACHE_CONTROL_CHALLENGE, CACHE_CONTROL_PAID,
    PROBLEM_CONTENT_TYPE,
};

/// The frozen wire artifacts.
const FIXTURE: &str = include_str!("fixtures/payment_auth_draft01.json");

/// `unwrap_err` requires `Debug` on the success type, and the credential
/// types deliberately do not carry one because they hold a single-use
/// payment token. Errors are unwrapped through this helper rather than
/// widening a derive to suit a test.
#[track_caller]
fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Reads one string field out of the frozen fixture.
#[track_caller]
fn fixture(field: &str) -> String {
    let parsed: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("the frozen fixture is valid JSON");
    parsed
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("fixture field {field} is missing"))
        .to_string()
}

/// Rebuilds the exact request object the fixture froze.
fn fixture_request() -> StripeChargeRequest {
    StripeChargeRequest {
        amount: "1000".to_string(),
        currency: "usd".to_string(),
        external_id: "quote_01".to_string(),
        method_details: StripeChargeMethodDetails {
            metadata: [("quote_id".to_string(), "quote_01".to_string())]
                .into_iter()
                .collect(),
            network_id: "profile_test_123".to_string(),
            payment_method_types: vec!["card".to_string()],
        },
    }
}

/// Rebuilds the exact opaque object the fixture froze.
fn fixture_opaque() -> ChallengeOpaque {
    ChallengeOpaque {
        intent_id: "stl_01".to_string(),
        provider: "stripe".to_string(),
    }
}

/// A binder over the fixture realm and binding key.
fn fixture_binder() -> ChallengeBinder {
    ChallengeBinder::new(&fixture("realm"), fixture("binding_key").as_bytes())
        .expect("the fixture realm and key are usable")
}

/// The challenge the binder issues for the frozen inputs.
fn fixture_challenge() -> PaymentChallenge {
    let expires = parse_rfc3339_utc(&fixture("expires")).expect("the frozen expiry parses");
    fixture_binder()
        .issue(
            &fixture_request(),
            Some(&fixture_opaque()),
            Some(fixture("body").as_bytes()),
            expires,
        )
        .expect("the frozen inputs produce a challenge")
}

/// One millisecond before the frozen challenge expires.
fn just_before_expiry() -> i64 {
    parse_rfc3339_utc(&fixture("expires")).expect("the frozen expiry parses") - 1
}

/// Canonicalizes a value the way every wire slot in this module does.
#[track_caller]
fn jcs(value: &impl serde::Serialize) -> String {
    String::from_utf8(serde_json_canonicalizer::to_vec(value).expect("the value canonicalizes"))
        .expect("canonical JSON is UTF-8")
}

#[test]
fn jcs_slots_encode_to_the_frozen_bytes() {
    assert_eq!(jcs(&fixture_request()), fixture("request_jcs"));
    assert_eq!(
        encode_jcs_base64url(&fixture_request()).unwrap(),
        fixture("request_b64")
    );

    assert_eq!(jcs(&fixture_opaque()), fixture("opaque_jcs"));
    assert_eq!(
        encode_jcs_base64url(&fixture_opaque()).unwrap(),
        fixture("opaque_b64")
    );
}

#[test]
fn the_body_digest_is_the_frozen_rfc_9530_parameter() {
    assert_eq!(
        body_digest_sha256(fixture("body").as_bytes()),
        fixture("body_digest")
    );
}

#[test]
fn the_seven_slot_binding_produces_the_frozen_challenge_id() {
    let challenge = fixture_challenge();
    assert_eq!(challenge.binding_input(), fixture("binding_input"));
    assert_eq!(challenge.id, fixture("challenge_id"));
}

#[test]
fn absent_optional_slots_are_empty_strings_not_skipped_separators() {
    // Same inputs, no body and no opaque. Both slots must still be
    // present in the binding input, so the separator count is fixed at
    // six for every challenge this codec ever issues.
    let expires = parse_rfc3339_utc(&fixture("expires")).unwrap();
    let challenge = fixture_binder()
        .issue(&fixture_request(), None, None, expires)
        .expect("a bodyless challenge issues");
    assert_eq!(challenge.binding_input().matches('|').count(), 6);
    assert!(challenge.binding_input().ends_with("||"));
    assert!(challenge.digest.is_none());
    assert!(challenge.opaque.is_none());
    // A different binding input must produce a different identifier.
    assert_ne!(challenge.id, fixture("challenge_id"));
}

#[test]
fn the_challenge_serializes_to_the_frozen_field_value() {
    let rendered = fixture_challenge()
        .to_header_value()
        .expect("the frozen challenge renders");
    assert_eq!(rendered, fixture("www_authenticate"));
    assert!(rendered.len() < 8 * 1024);

    let reparsed = PaymentChallenge::parse_header_value(&rendered)
        .expect("the rendered challenge parses back");
    assert_eq!(reparsed, fixture_challenge());
}

#[test]
fn each_offered_challenge_is_its_own_field() {
    // Two rails, two separate WWW-Authenticate field values. Nothing in
    // this codec ever folds two challenges into one comma separated
    // field, because a client that split on commas would then have to
    // guess which quoted value belonged to which offer.
    let expires = parse_rfc3339_utc(&fixture("expires")).unwrap();
    let first = fixture_challenge();
    let mut other_request = fixture_request();
    other_request.external_id = "quote_02".to_string();
    let second = fixture_binder()
        .issue(
            &other_request,
            Some(&fixture_opaque()),
            Some(fixture("body").as_bytes()),
            expires,
        )
        .unwrap();

    let fields = [
        first.to_header_value().unwrap(),
        second.to_header_value().unwrap(),
    ];
    assert_eq!(fields.len(), 2);
    assert_ne!(fields[0], fields[1]);
    for field in &fields {
        assert!(field.starts_with("Payment id=\""));
    }
}

#[test]
fn the_credential_encodes_to_the_frozen_authorization_value() {
    let credential_json = fixture("credential_json");
    assert_eq!(
        URL_SAFE_NO_PAD.encode(credential_json.as_bytes()),
        fixture("authorization_b64")
    );
}

#[test]
fn the_frozen_credential_verifies_against_the_frozen_challenge() {
    let verified = fixture_binder()
        .verify_credential(
            &format!("Payment {}", fixture("authorization_b64")),
            Some(fixture("body").as_bytes()),
            just_before_expiry(),
        )
        .expect("the frozen credential verifies");

    assert_eq!(verified.challenge.id, fixture("challenge_id"));
    assert_eq!(verified.payload.expose_spt(), fixture("spt"));
    assert_eq!(verified.payload.external_id(), None);
    assert_eq!(verified.request, fixture_request());
    assert_eq!(verified.opaque, Some(fixture_opaque()));
    // The proof digest is what the durable store reserves, so it has to
    // be a pure function of the credential bytes.
    let again = fixture_binder()
        .verify_credential(
            &format!("Payment {}", fixture("authorization_b64")),
            Some(fixture("body").as_bytes()),
            just_before_expiry(),
        )
        .expect("the frozen credential verifies twice");
    assert_eq!(verified.proof.digest(), again.proof.digest());
    assert!(verified.proof.matches_digest(&again.proof.digest()));
}

#[test]
fn the_scheme_token_is_required_and_case_insensitive() {
    let binder = fixture_binder();
    let token = fixture("authorization_b64");
    assert!(binder
        .verify_credential(
            &format!("payment {token}"),
            Some(fixture("body").as_bytes()),
            just_before_expiry()
        )
        .is_ok());
    for bad in [
        format!("Payment{token}"),
        format!("Payment  {token}"),
        format!("Bearer {token}"),
        token.clone(),
    ] {
        assert_eq!(
            expect_error(
                binder.verify_credential(
                    &bad,
                    Some(fixture("body").as_bytes()),
                    just_before_expiry()
                ),
                "a mis-framed credential must be refused"
            ),
            PaymentAuthError::MalformedCredential,
            "expected {bad:?} to be refused"
        );
    }
}

#[test]
fn two_payment_credentials_are_a_four_hundred() {
    let error = expect_error(
        select_payment_credential(["Payment aaa", "Payment bbb"]),
        "two payment credentials must be refused",
    );
    assert_eq!(error, PaymentAuthError::DuplicateCredential);
    assert_eq!(error.status(), 400);

    let missing = expect_error(
        select_payment_credential(["Bearer only"]),
        "a request with no payment credential is a payment problem",
    );
    assert_eq!(missing, PaymentAuthError::CredentialMissing);
    assert_eq!(missing.status(), 402);
    assert!(missing.offers_fresh_challenge());
}

#[test]
fn an_expired_challenge_is_refused_not_renewed() {
    let expires = parse_rfc3339_utc(&fixture("expires")).unwrap();
    let error = expect_error(
        fixture_binder().verify_credential(
            &format!("Payment {}", fixture("authorization_b64")),
            Some(fixture("body").as_bytes()),
            expires,
        ),
        "an expired challenge must be refused",
    );
    assert_eq!(error, PaymentAuthError::Expired);
    assert_eq!(
        error.problem_code(),
        Some(PaymentAuthProblemCode::PaymentExpired)
    );
    assert_eq!(error.status(), 402);
}

/// Re-encodes the frozen credential after mutating one challenge slot.
#[track_caller]
fn credential_with_challenge_slot(slot: &str, value: serde_json::Value) -> String {
    let mut document: serde_json::Value =
        serde_json::from_str(&fixture("credential_json")).expect("the frozen credential parses");
    document["challenge"][slot] = value;
    let bytes = serde_json::to_vec(&document).expect("the mutated credential serializes");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn a_tampered_challenge_echo_is_refused() {
    let binder = fixture_binder();
    // Each of these edits leaves a syntactically perfect credential
    // whose challenge no longer recomputes its own identifier. The
    // amount lives inside the base64url request slot, so the last case
    // re-encodes a cheaper obligation the way a real attacker would.
    let mut cheaper = fixture_request();
    cheaper.amount = "1".to_string();
    let cases = [
        (
            "realm",
            serde_json::Value::from("attacker.example"),
            PaymentAuthError::MethodUnsupported,
        ),
        (
            "expires",
            serde_json::Value::from("2036-07-29T20:05:00Z"),
            PaymentAuthError::InvalidChallenge,
        ),
        (
            "opaque",
            serde_json::Value::from(
                encode_jcs_base64url(&ChallengeOpaque {
                    intent_id: "stl_other".to_string(),
                    provider: "stripe".to_string(),
                })
                .unwrap(),
            ),
            PaymentAuthError::InvalidChallenge,
        ),
        (
            "request",
            serde_json::Value::from(encode_jcs_base64url(&cheaper).unwrap()),
            PaymentAuthError::InvalidChallenge,
        ),
        (
            "digest",
            serde_json::Value::from(body_digest_sha256(b"{\"prompt\":\"goodbye\"}")),
            PaymentAuthError::InvalidChallenge,
        ),
    ];
    for (slot, value, expected) in cases {
        let token = credential_with_challenge_slot(slot, value);
        let error = expect_error(
            binder.verify_credential(
                &format!("Payment {token}"),
                Some(fixture("body").as_bytes()),
                just_before_expiry(),
            ),
            "a tampered challenge must be refused",
        );
        assert_eq!(error, expected, "tampering with {slot} produced {error:?}");
    }
}

#[test]
fn a_body_that_does_not_match_the_bound_digest_is_refused() {
    let error = expect_error(
        fixture_binder().verify_credential(
            &format!("Payment {}", fixture("authorization_b64")),
            Some(br#"{"prompt":"goodbye"}"#),
            just_before_expiry(),
        ),
        "a body outside the bound digest must be refused",
    );
    assert_eq!(error, PaymentAuthError::InvalidChallenge);

    // A challenge that bound a body cannot be presented without one,
    // and a request carrying a body cannot present a challenge that
    // bound none.
    let error = expect_error(
        fixture_binder().verify_credential(
            &format!("Payment {}", fixture("authorization_b64")),
            None,
            just_before_expiry(),
        ),
        "a bound body must be presented",
    );
    assert_eq!(error, PaymentAuthError::InvalidChallenge);
}

#[test]
fn base64_near_misses_are_refused() {
    let binder = fixture_binder();
    let token = fixture("authorization_b64");
    let mut with_plus = token.clone();
    with_plus.replace_range(0..1, "+");
    let mut with_slash = token.clone();
    with_slash.replace_range(0..1, "/");
    let cases = [
        format!("{token}="),
        format!("{token}=="),
        with_plus,
        with_slash,
        String::new(),
    ];
    for bad in cases {
        let error = expect_error(
            binder.verify_credential(
                &format!("Payment {bad}"),
                Some(fixture("body").as_bytes()),
                just_before_expiry(),
            ),
            "a base64 near miss must be refused",
        );
        assert_eq!(error, PaymentAuthError::MalformedCredential);
    }
}

#[test]
fn duplicate_json_keys_and_invalid_utf8_are_refused() {
    let duplicated = fixture("credential_json").replace(
        r#""payload":{"spt""#,
        r#""payload":{"spt":"spt_other","spt""#,
    );
    let token = URL_SAFE_NO_PAD.encode(duplicated.as_bytes());
    assert_eq!(
        expect_error(
            decode_credential(&token),
            "a duplicate JSON key must be refused"
        ),
        PaymentAuthError::MalformedCredential
    );

    let token = URL_SAFE_NO_PAD.encode([0xff, 0xfe, 0xfd]);
    assert_eq!(
        expect_error(decode_credential(&token), "invalid UTF-8 must be refused"),
        PaymentAuthError::MalformedCredential
    );
}

#[test]
fn the_payload_schema_is_pinned() {
    // An unknown payload member, a token without the required prefix,
    // and an empty token are each refused. The payload is the one part
    // of the credential where draft-01's ignore-unknown rule does not
    // apply, because it is a registered method schema.
    for tampered in [
        fixture("credential_json").replace(
            r#"{"spt":"spt_test_123"}"#,
            r#"{"spt":"spt_test_123","destination":"acct_attacker"}"#,
        ),
        fixture("credential_json").replace("spt_test_123", "tok_test_123"),
        fixture("credential_json").replace("spt_test_123", "spt_"),
        fixture("credential_json").replace(r#""spt":"spt_test_123""#, r#""spt":""#),
    ] {
        let token = URL_SAFE_NO_PAD.encode(tampered.as_bytes());
        assert_eq!(
            expect_error(
                decode_credential(&token),
                "a payload outside the pinned schema must be refused"
            ),
            PaymentAuthError::MalformedCredential
        );
    }
}

#[test]
fn unknown_challenge_parameters_and_credential_members_are_ignored() {
    // draft-01 requires forward compatibility outside the pinned
    // payload, so an unknown member must not break an otherwise valid
    // credential.
    let extended = fixture("credential_json")
        .replace(r#"{"challenge":{"#, r#"{"future":"ignored","challenge":{"#);
    let token = URL_SAFE_NO_PAD.encode(extended.as_bytes());
    let verified = fixture_binder()
        .verify_credential(
            &format!("Payment {token}"),
            Some(fixture("body").as_bytes()),
            just_before_expiry(),
        )
        .expect("an unknown top-level member is ignored");
    assert_eq!(verified.challenge.id, fixture("challenge_id"));

    let rendered = format!("{}, future=\"ignored\"", fixture("www_authenticate"));
    let parsed = PaymentChallenge::parse_header_value(&rendered)
        .expect("an unknown challenge parameter is ignored");
    assert_eq!(parsed.id, fixture("challenge_id"));
}

#[test]
fn a_repeated_challenge_parameter_is_refused() {
    let rendered = format!("{}, realm=\"other.example\"", fixture("www_authenticate"));
    assert_eq!(
        expect_error(
            PaymentChallenge::parse_header_value(&rendered),
            "a repeated challenge parameter must be refused"
        ),
        PaymentAuthError::InvalidChallenge
    );
}

#[test]
fn an_unoffered_method_or_intent_is_a_method_unsupported() {
    let binder = fixture_binder();
    for tampered in [
        fixture("credential_json").replace(r#""method":"stripe""#, r#""method":"paypal""#),
        fixture("credential_json").replace(r#""intent":"charge""#, r#""intent":"subscribe""#),
    ] {
        let token = URL_SAFE_NO_PAD.encode(tampered.as_bytes());
        let error = expect_error(
            binder.verify_credential(
                &format!("Payment {token}"),
                Some(fixture("body").as_bytes()),
                just_before_expiry(),
            ),
            "an unoffered method or intent must be refused",
        );
        assert_eq!(error, PaymentAuthError::MethodUnsupported);
        assert_eq!(error.status(), 400);
        assert!(!error.offers_fresh_challenge());
    }
}

#[test]
fn a_credential_from_another_proxy_key_is_refused() {
    let other = ChallengeBinder::new(&fixture("realm"), b"a-different-binding-key")
        .expect("a second binder is usable");
    let error = expect_error(
        other.verify_credential(
            &format!("Payment {}", fixture("authorization_b64")),
            Some(fixture("body").as_bytes()),
            just_before_expiry(),
        ),
        "a challenge bound by another key must be refused",
    );
    assert_eq!(error, PaymentAuthError::InvalidChallenge);
}

#[test]
fn the_receipt_encodes_to_the_frozen_bytes() {
    let settled = parse_rfc3339_utc(&fixture("settled_at")).unwrap();
    let receipt = PaymentAuthReceipt::success("stripe", &fixture("provider_reference"), settled)
        .expect("a provider-backed receipt is buildable");

    assert_eq!(jcs(&receipt), fixture("receipt_json"));
    assert_eq!(receipt.to_header_value().unwrap(), fixture("receipt_b64"));
    assert_eq!(receipt.status, PaymentAuthReceipt::STATUS_SUCCESS);
}

#[test]
fn a_receipt_cannot_be_fabricated_without_a_provider_reference() {
    let settled = parse_rfc3339_utc(&fixture("settled_at")).unwrap();
    for (method, reference) in [("stripe", ""), ("stripe", "   "), ("", "pi_test_123")] {
        assert_eq!(
            expect_error(
                PaymentAuthReceipt::success(method, reference, settled),
                "an empty provider reference must be refused"
            ),
            PaymentAuthError::Internal
        );
    }
}

#[test]
fn every_registered_problem_has_its_exact_code_and_status() {
    let table = [
        (
            "payment-required",
            402,
            PaymentAuthProblemCode::PaymentRequired,
        ),
        (
            "payment-insufficient",
            402,
            PaymentAuthProblemCode::PaymentInsufficient,
        ),
        (
            "payment-expired",
            402,
            PaymentAuthProblemCode::PaymentExpired,
        ),
        (
            "verification-failed",
            402,
            PaymentAuthProblemCode::VerificationFailed,
        ),
        (
            "method-unsupported",
            400,
            PaymentAuthProblemCode::MethodUnsupported,
        ),
        (
            "malformed-credential",
            402,
            PaymentAuthProblemCode::MalformedCredential,
        ),
        (
            "invalid-challenge",
            402,
            PaymentAuthProblemCode::InvalidChallenge,
        ),
    ];
    for (token, status, code) in table {
        assert_eq!(code.as_str(), token);
        assert_eq!(code.registered_status(), status);
        assert_eq!(
            code.type_uri(),
            format!("https://paymentauth.org/problems/{token}")
        );
    }
}

#[test]
fn problem_documents_are_shaped_for_the_response_writer() {
    let document = PaymentAuthError::MalformedCredential
        .problem_document()
        .expect("a payment problem renders a document");
    assert_eq!(
        document["type"],
        "https://paymentauth.org/problems/malformed-credential"
    );
    assert_eq!(document["status"], 402);
    assert_eq!(PROBLEM_CONTENT_TYPE, "application/problem+json");
    assert_eq!(CACHE_CONTROL_CHALLENGE, "no-store");
    assert_eq!(CACHE_CONTROL_PAID, "private");

    // A transport refusal is not a payment problem, so it renders no
    // document and never invites a payment retry.
    assert!(PaymentAuthError::BodyTooLarge.problem_document().is_none());
    assert!(PaymentAuthError::InsecureTransport
        .problem_document()
        .is_none());
}

#[test]
fn accept_payment_selects_a_challenge_and_carries_nothing_else() {
    let preferences = parse_accept_payment("stripe;intent=charge;q=1.0, x402;q=0.5");
    assert_eq!(preferences[0].method, "stripe");
    assert_eq!(preferences[0].intent.as_deref(), Some("charge"));
    assert_eq!(preferences[1].method, "x402");

    // Anything that looks like credential material invalidates its own
    // preference rather than being carried anywhere.
    assert!(parse_accept_payment("stripe;spt=spt_test_123").is_empty());
    assert!(parse_accept_payment("stripe;quote=eyJhIjoxfQ").is_empty());
    assert!(parse_accept_payment("stripe;q=1.0;q=1.0").is_empty());
    assert!(parse_accept_payment("stripe;intent=charge;intent=charge").is_empty());
}
