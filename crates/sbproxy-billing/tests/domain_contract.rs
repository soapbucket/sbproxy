//! The normalized domain contract, with no features enabled.
//!
//! These tests run on the default build, which compiles only money,
//! requirements, proofs, and receipts. They pin the properties every later
//! slice depends on: exact money, stable canonical digests, a proof that
//! cannot be printed, and a receipt that cannot be invented.

use std::collections::BTreeMap;

use sbproxy_billing::money::{CurrencyCode, Money};
use sbproxy_billing::types::{
    digests_equal, provider_idempotency_key, AdvertisedRail, AttemptOperation, IntentStatus,
    PaymentProof, PaymentProtocol, PaymentRequirement, PaymentRequirementDraft, RequirementTerms,
    SettlementRail, SettlementReceipt,
};
use sbproxy_billing::BillingError;

/// Fails the test rather than requiring `Debug` on a type holding a credential.
#[track_caller]
fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

fn draft() -> PaymentRequirementDraft {
    let mut draft = PaymentRequirementDraft {
        requirement_id: "req-1".to_string(),
        protocol: PaymentProtocol::X402V2,
        advertised_rail: AdvertisedRail::X402,
        settlement_rail: SettlementRail::X402,
        method: "exact".to_string(),
        intent: "charge".to_string(),
        network: Some("base-sepolia".to_string()),
        asset: Some("usdc".to_string()),
        pay_to: Some("0xrecipient".to_string()),
        amount: Money::new(10_000, "usd").expect("valid money"),
        settlement_amount: String::new(),
        settlement_decimals: 6,
        terms: RequirementTerms::X402Exact {
            facilitator_url: "https://facilitator.test.sbproxy.dev".to_string(),
            max_timeout_seconds: 60,
            extra: BTreeMap::new(),
        },
        quote_id: "quote-1".to_string(),
        tenant_id: "tenant-1".to_string(),
        origin_id: "origin-1".to_string(),
        route: "/paid".to_string(),
        expires_at_ms: 1_700_000_600_000,
        request_digest: None,
    };
    draft.canonicalize().expect("canonical draft");
    draft
}

#[test]
fn money_is_positive_and_bounded() {
    let error = expect_error(Money::new(0, "USD"), "zero must not be a price");
    assert_eq!(error, BillingError::InvalidAmount);

    let money = Money {
        amount_micros: u64::MAX,
        currency: "USD".to_string(),
    };
    assert_eq!(
        expect_error(money.validate(), "an unstorable amount must fail"),
        BillingError::InvalidAmount
    );
}

#[test]
fn currency_is_stored_uppercase_and_sent_lowercase() {
    let money = Money::new(2_500_000, "usd").expect("valid money");
    assert_eq!(money.currency, "USD");
    assert_eq!(money.provider_currency().expect("provider currency"), "usd");

    let code = CurrencyCode::parse("Eur").expect("valid currency");
    assert_eq!(code.as_str(), "EUR");
    assert_eq!(code.to_provider_string(), "eur");

    for bad in ["US", "USDD", "US1", " USD"] {
        assert_eq!(
            expect_error(CurrencyCode::parse(bad), "malformed currency must fail"),
            BillingError::InvalidCurrency
        );
    }
}

#[test]
fn base_unit_conversion_is_checked_in_both_directions() {
    let money = Money::new(2_500_000, "USD").expect("valid money");
    assert_eq!(money.to_base_units(2).expect("cents"), 250);
    assert_eq!(money.to_base_units(6).expect("micros"), 2_500_000);
    assert_eq!(money.to_base_unit_string(2).expect("string"), "250");

    // A price of 0.0000005 USD is exact in micros and has no representation
    // in cents, so it fails rather than rounding into a different price.
    let fractional = Money::new(1, "USD").expect("valid money");
    assert_eq!(
        expect_error(fractional.to_base_units(2), "a remainder must not round"),
        BillingError::AmountNotRepresentable
    );
    assert_eq!(
        expect_error(fractional.to_base_units(19), "precision must be bounded"),
        BillingError::InvalidPrecision
    );

    let rebuilt = Money::from_base_units(250, 2, "USD").expect("round trip");
    assert_eq!(rebuilt, money);
}

#[test]
fn advertised_mpp_settles_on_stripe_without_an_mpp_rail() {
    assert_eq!(
        AdvertisedRail::Mpp.settlement_rail(None).expect("rail"),
        SettlementRail::Stripe
    );
    assert_eq!(
        AdvertisedRail::Stripe.settlement_rail(None).expect("rail"),
        SettlementRail::Stripe
    );
    assert_eq!(
        AdvertisedRail::Lightning
            .settlement_rail(Some("CLN"))
            .expect("rail"),
        SettlementRail::LightningCln
    );
    assert_eq!(
        expect_error(
            AdvertisedRail::Lightning.settlement_rail(None),
            "a backendless lightning rail must fail",
        ),
        BillingError::UnsupportedRail
    );
    // Every settlement rail names the feature that compiles it, so startup can
    // tell an operator what to build with.
    assert_eq!(SettlementRail::Stripe.cargo_feature(), "payment-stripe");
}

#[test]
fn terms_canonicalize_into_one_spelling() {
    let mut terms = RequirementTerms::StripePaymentIntent {
        payment_method_types: vec![
            "  Card ".to_string(),
            "card".to_string(),
            "ACH_DEBIT".to_string(),
        ],
        capture_method: "MANUAL".to_string(),
        account_context: "acct-context".to_string(),
    };
    terms.canonicalize().expect("canonical terms");
    let RequirementTerms::StripePaymentIntent {
        payment_method_types,
        capture_method,
        ..
    } = &terms
    else {
        panic!("terms changed shape");
    };
    assert_eq!(payment_method_types, &["ach_debit", "card"]);
    assert_eq!(capture_method, "manual");
    assert_eq!(
        terms.settlement_rail().expect("rail"),
        SettlementRail::Stripe
    );
}

#[test]
fn draft_digest_is_stable_across_serialization() {
    let draft = draft();
    let digest = draft.digest().expect("digest");
    let json = serde_json::to_string(&draft).expect("serialize");
    let restored: PaymentRequirementDraft = serde_json::from_str(&json).expect("deserialize");
    assert!(digests_equal(&restored.digest().expect("digest"), &digest));
    assert_eq!(draft.settlement_amount, "10000");
}

#[test]
fn a_provider_handle_changes_only_the_final_digest() {
    let draft = draft();
    let draft_digest = draft.digest().expect("draft digest");

    let bare = PaymentRequirement::new(draft.clone());
    let bare_digest = bare.digest().expect("requirement digest");

    let bound = PaymentRequirement {
        draft,
        provider_handle: Some("pi_123".to_string()),
    };
    let bound_digest = bound.digest().expect("requirement digest");

    assert!(digests_equal(
        &bound.draft.digest().expect("draft digest"),
        &draft_digest
    ));
    assert!(!digests_equal(&bare_digest, &bound_digest));
}

#[test]
fn a_mismatched_rail_is_rejected_before_any_adapter_sees_it() {
    let mut draft = draft();
    draft.settlement_rail = SettlementRail::Stripe;
    assert_eq!(
        expect_error(draft.canonicalize(), "a rail mismatch must fail"),
        BillingError::UnsupportedRail
    );

    let mut wrong_amount = self::draft();
    wrong_amount.settlement_amount = "1".to_string();
    assert_eq!(
        expect_error(wrong_amount.canonicalize(), "a restated amount must match"),
        BillingError::InvalidRequirement("settlement_amount")
    );
}

#[test]
fn a_proof_never_prints_its_credential() {
    let proof = PaymentProof::new("Payment", "spt_super_secret_value".to_string()).expect("proof");
    let debug = format!("{proof:?}");
    let display = format!("{proof}");
    assert!(!debug.contains("spt_super_secret_value"), "{debug}");
    assert!(!display.contains("spt_super_secret_value"), "{display}");
    assert!(debug.contains("redacted"));
    assert_eq!(proof.expose_credential(), "spt_super_secret_value");

    let same = PaymentProof::new("Payment", "spt_super_secret_value".to_string()).expect("proof");
    assert!(proof.matches_digest(&same.digest()));

    let other = PaymentProof::new("Payment", "spt_other".to_string()).expect("proof");
    assert!(!proof.matches_digest(&other.digest()));

    assert_eq!(
        expect_error(
            PaymentProof::new("Payment", String::new()),
            "an empty credential must fail",
        ),
        BillingError::InvalidProof
    );
}

#[test]
fn an_idempotency_key_binds_the_generation_and_the_proof() {
    let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
    let digest = proof.digest();
    let first = provider_idempotency_key(
        SettlementRail::Stripe,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        0,
        Some(&digest),
    );
    let same = provider_idempotency_key(
        SettlementRail::Stripe,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        0,
        Some(&digest),
    );
    let next_generation = provider_idempotency_key(
        SettlementRail::Stripe,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        1,
        Some(&digest),
    );

    assert_eq!(first, same, "a pre-dispatch retry must reuse the key");
    assert_ne!(first, next_generation);
    assert!(first.starts_with("sbp1_"));
    // The credential must not be recoverable from a key a provider displays.
    assert!(!first.contains("spt_value"));
}

#[test]
fn only_succeeded_authorizes_the_origin() {
    for status in [
        IntentStatus::Pending,
        IntentStatus::Processing,
        IntentStatus::RetryWait,
        IntentStatus::Terminal,
        IntentStatus::NeedsReconciliation,
        IntentStatus::Stranded,
    ] {
        assert!(!status.authorizes_origin(), "{status} must not authorize");
    }
    assert!(IntentStatus::Succeeded.authorizes_origin());
    assert!(!IntentStatus::NeedsReconciliation.allows_provider_write());
    // WOR-2317. `Stranded` releases a route gate and nothing else. It is not
    // a settlement, so it authorizes nothing, and it is not a resolution, so
    // it opens no new provider write: the outstanding dispatch it was
    // retired with is still outstanding.
    assert!(!IntentStatus::Stranded.allows_provider_write());
    assert!(IntentStatus::Stranded.is_unresolved());
    assert!(IntentStatus::NeedsReconciliation.is_unresolved());
    assert!(
        !IntentStatus::Terminal.is_unresolved(),
        "terminal asserts no funds moved; stranded asserts nothing at all, \
         and collapsing the two would hide unaccounted money",
    );
    assert_eq!(IntentStatus::Stranded.as_str(), "stranded");
    assert_eq!(
        IntentStatus::parse("stranded").expect("stranded parses"),
        IntentStatus::Stranded,
    );
    assert!(!AttemptOperation::MeterReport.can_settle());
    assert!(!AttemptOperation::PrepareChallenge.can_settle());
    assert!(AttemptOperation::Settle.can_settle());
}

#[test]
fn a_receipt_cannot_be_fabricated() {
    assert_eq!(
        expect_error(
            SettlementReceipt::new("intent", SettlementRail::X402, "exact", "  ", 1),
            "an empty provider reference must fail",
        ),
        BillingError::InvalidRequirement("provider_reference")
    );
    assert_eq!(
        expect_error(
            SettlementReceipt::new("intent", SettlementRail::X402, "exact", "tx_1", 0),
            "an unset settlement time must fail",
        ),
        BillingError::InvalidRequirement("settled_at_ms")
    );

    let mut receipt = SettlementReceipt::new("intent", SettlementRail::X402, "exact", "tx_1", 42)
        .expect("receipt");
    receipt.validate().expect("a real receipt validates");
    receipt.provider_reference = "tx_2".to_string();
    assert_eq!(
        expect_error(receipt.validate(), "an edited receipt must fail"),
        BillingError::DigestMismatch
    );
}
