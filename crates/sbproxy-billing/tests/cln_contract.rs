//! Contract tests for Core Lightning settlement.
//!
//! The fixture is a newline-delimited Unix JSON-RPC transcript, so the byte
//! framing the runtime writes to the socket and the bytes these tests decode
//! are the same bytes.

#![cfg(feature = "lightning-cln")]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_billing::lightning::cln::{
    check_socket_path, decode_jsonrpc_response, encode_jsonrpc_request, parse_cln_version,
    parse_msat_field, read_invoice, require_supported_version, select_labeled_invoice,
    verify_paid_invoice, ClnInvoiceStatus, ClnSettler, ClnTransport, CHALLENGE_FIELD_BOLT11,
    CHALLENGE_FIELD_LABEL, CHALLENGE_FIELD_PAYMENT_HASH, CLN_JSONRPC_VERSION, MIN_CLN_MAJOR,
    MIN_CLN_MINOR,
};
use sbproxy_billing::lightning::{
    check_bolt11, invoice_label, payment_label, LightningError, LightningTransportFailure,
    PaymentHash,
};
use sbproxy_billing::registry::RailRegistry;
use sbproxy_billing::service::{AuthorizationDecision, BillingService, RedemptionRequest};
use sbproxy_billing::sqlite::SqliteSettlementStore;
use sbproxy_billing::store::BillingClock;
use sbproxy_billing::types::{
    AdvertisedRail, IntentStatus, PaymentProof, PaymentProtocol, PaymentRequirementDraft,
    RequirementTerms, SettlementRail,
};
use sbproxy_billing::{Money, NoOpPaymentLifecycleObserver};

mod common;

use common::{sign_draft, FixtureSigner, TestClock};

/// The frozen Core Lightning transcript.
const FIXTURE: &str = include_str!("fixtures/lightning/cln_rpc.json");

/// The durable intent every test settles.
const INTENT_ID: &str = "sbpi_fixture_intent_0001";

/// The payment hash the fixture invoice commits to.
const FIXTURE_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// `unwrap_err` requires `Debug` on the success type, which several types in
/// this crate deliberately lack. Errors are unwrapped through this helper
/// rather than widening a derive to suit a test.
#[track_caller]
fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Reads one sub-document out of the frozen transcript.
#[track_caller]
fn part(name: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("the frozen transcript is valid JSON");
    parsed
        .get(name)
        .unwrap_or_else(|| panic!("fixture part {name} is missing"))
        .clone()
}

/// Renders one fixture part exactly as the socket would deliver it: compact
/// JSON followed by a newline.
#[track_caller]
fn newline_delimited(name: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&part(name)).expect("a fixture part serializes");
    bytes.push(b'\n');
    bytes
}

/// Decodes one fixture part's `result`.
#[track_caller]
fn result_of(name: &str) -> serde_json::Value {
    decode_jsonrpc_response(&newline_delimited(name)).expect("the fixture decodes")
}

// --- Startup version gate ---

#[test]
fn the_pinned_floor_is_v26_06() {
    assert_eq!((MIN_CLN_MAJOR, MIN_CLN_MINOR), (26, 6));
    let version = result_of("getinfo")["version"]
        .as_str()
        .expect("the fixture reports a version")
        .to_string();
    assert_eq!(
        require_supported_version(&version).expect("v26.06"),
        (26, 6)
    );
}

#[test]
fn a_node_below_the_floor_is_refused_at_startup() {
    let version = result_of("getinfo_too_old")["version"]
        .as_str()
        .expect("the fixture reports a version")
        .to_string();
    assert_eq!(
        expect_error(
            require_supported_version(&version),
            "an older node must be refused"
        ),
        LightningError::NodeVersion
    );
}

#[test]
fn a_missing_or_malformed_version_is_refused_rather_than_assumed() {
    assert!(
        result_of("getinfo_no_version").get("version").is_none(),
        "the fixture omits the version"
    );
    for bad in ["", "v", "v26", "twentysix.06", "26.x"] {
        assert_eq!(
            expect_error(
                parse_cln_version(bad),
                "a malformed version must be refused"
            ),
            LightningError::VersionMalformed,
            "expected {bad:?} to be refused"
        );
    }
}

#[test]
fn an_optional_leading_v_is_accepted_and_a_patch_is_ignored() {
    assert_eq!(parse_cln_version("26.06").expect("no v"), (26, 6));
    assert_eq!(parse_cln_version("v26.06").expect("leading v"), (26, 6));
    assert_eq!(parse_cln_version("v26.06.1").expect("patch"), (26, 6));
}

// --- Byte framing ---

#[test]
fn requests_are_newline_delimited_json_rpc_2_0() {
    let bytes = encode_jsonrpc_request("getinfo", "getinfo", &serde_json::json!({}), None)
        .expect("the request encodes");
    assert_eq!(bytes.last().copied(), Some(b'\n'), "newline delimited");
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("valid json");
    assert_eq!(parsed["jsonrpc"], CLN_JSONRPC_VERSION);
    assert_eq!(parsed["method"], "getinfo");
    assert!(
        parsed.get("rune").is_none(),
        "no rune slot when unconfigured"
    );
}

#[test]
fn a_configured_rune_reaches_the_request_and_nothing_else() {
    let bytes = encode_jsonrpc_request(
        "listinvoices",
        "listinvoices",
        &serde_json::json!({ "label": "sbproxy-invoice-a" }),
        Some("rune-fixture-value"),
    )
    .expect("the request encodes");
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("valid json");
    assert_eq!(parsed["rune"], "rune-fixture-value");

    // No error this module can produce carries it, and none of the typed
    // errors has a field it could be put in.
    for error in [
        LightningError::NodeVersion,
        LightningError::Malformed,
        LightningError::AmbiguousLabel,
        LightningError::BindingMismatch,
    ] {
        assert!(!format!("{error}").contains("rune-fixture-value"));
        assert!(!format!("{error:?}").contains("rune-fixture-value"));
    }
}

#[test]
fn a_json_rpc_error_never_decodes_as_a_result() {
    assert_eq!(
        expect_error(
            decode_jsonrpc_response(&newline_delimited("method_not_found")),
            "an error object must not decode as a result"
        ),
        LightningError::Malformed
    );
}

// --- Invoice acceptance ---

#[test]
fn the_label_is_derived_from_the_durable_intent() {
    let label = invoice_label(INTENT_ID).expect("a usable label");
    assert_eq!(label, "sbproxy-invoice-sbpi_fixture_intent_0001");
    // A replacement process derives the same label and finds the invoice
    // rather than creating a second one.
    assert_eq!(invoice_label(INTENT_ID).expect("a usable label"), label);
    assert_ne!(payment_label(INTENT_ID).expect("a usable label"), label);

    let listed = result_of("listinvoices_paid");
    let invoice = select_labeled_invoice(&listed, &label).expect("the fixture holds the label");
    assert_eq!(invoice.label.as_deref(), Some(label.as_str()));
}

#[test]
fn only_a_documented_paid_status_authorizes() {
    let label = invoice_label(INTENT_ID).expect("a usable label");

    let paid = select_labeled_invoice(&result_of("listinvoices_paid"), &label)
        .expect("the fixture holds the label");
    assert_eq!(paid.status, Some(ClnInvoiceStatus::Paid));
    let hash = verify_paid_invoice(&paid, 100_000, Some(FIXTURE_HASH)).expect("a bound payment");
    assert_eq!(hash.to_hex(), FIXTURE_HASH);

    for name in ["listinvoices_unpaid", "listinvoices_expired"] {
        let invoice =
            select_labeled_invoice(&result_of(name), &label).expect("the fixture holds the label");
        assert_ne!(
            invoice.status,
            Some(ClnInvoiceStatus::Paid),
            "{name} must not authorize"
        );
    }
}

#[test]
fn a_missing_or_duplicated_label_denies_rather_than_guessing() {
    let label = invoice_label(INTENT_ID).expect("a usable label");
    assert_eq!(
        expect_error(
            select_labeled_invoice(&result_of("listinvoices_missing"), &label),
            "a missing invoice must be refused"
        ),
        LightningError::Malformed
    );
    assert_eq!(
        expect_error(
            select_labeled_invoice(&result_of("listinvoices_duplicate"), &label),
            "a duplicate label must be refused"
        ),
        LightningError::AmbiguousLabel
    );
}

#[test]
fn a_malformed_result_is_not_a_silent_success() {
    assert_eq!(
        expect_error(
            select_labeled_invoice(&serde_json::json!({ "invoices": "not a list" }), "any"),
            "a non list must be refused"
        ),
        LightningError::Malformed
    );
    let unknown_status = read_invoice(&serde_json::json!({
        "label": "sbproxy-invoice-a",
        "status": "held"
    }));
    assert_eq!(
        unknown_status.status, None,
        "an unknown status is not coerced onto a known one"
    );
}

#[test]
fn millisatoshi_fields_are_read_in_both_published_shapes() {
    let label = invoice_label(INTENT_ID).expect("a usable label");
    let stringly = select_labeled_invoice(&result_of("listinvoices_string_msat"), &label)
        .expect("the fixture holds the label");
    assert_eq!(stringly.amount_msat, Some(100_000));
    assert_eq!(stringly.amount_received_msat, Some(100_000));
    assert!(verify_paid_invoice(&stringly, 100_000, Some(FIXTURE_HASH)).is_ok());

    assert_eq!(parse_msat_field(&serde_json::json!(1)), Some(1));
    assert_eq!(parse_msat_field(&serde_json::json!("1msat")), Some(1));
    assert_eq!(parse_msat_field(&serde_json::json!("a lot")), None);
}

#[test]
fn an_underpayment_or_a_hash_mismatch_denies() {
    let label = invoice_label(INTENT_ID).expect("a usable label");
    let paid = select_labeled_invoice(&result_of("listinvoices_paid"), &label)
        .expect("the fixture holds the label");
    assert_eq!(
        expect_error(
            verify_paid_invoice(&paid, 100_001, Some(FIXTURE_HASH)),
            "an amount mismatch must deny"
        ),
        LightningError::BindingMismatch
    );
    assert_eq!(
        expect_error(
            verify_paid_invoice(&paid, 100_000, Some(&"22".repeat(32))),
            "a hash mismatch must deny"
        ),
        LightningError::BindingMismatch
    );
}

#[test]
fn the_generated_invoice_is_a_usable_bolt11_and_hash() {
    let created = result_of("invoice");
    let bolt11 = created["bolt11"].as_str().expect("the fixture has one");
    check_bolt11(bolt11).expect("the fixture invoice is usable");
    let hash = PaymentHash::parse_hex(created["payment_hash"].as_str().expect("a hash"))
        .expect("the fixture hash parses");
    assert_eq!(hash.to_hex(), FIXTURE_HASH);
}

#[test]
fn the_challenge_field_names_are_pinned() {
    assert_eq!(CHALLENGE_FIELD_BOLT11, "bolt11");
    assert_eq!(CHALLENGE_FIELD_PAYMENT_HASH, "payment_hash");
    assert_eq!(CHALLENGE_FIELD_LABEL, "label");
    // The challenge carries no preimage and no rune slot.
    for field in [
        CHALLENGE_FIELD_BOLT11,
        CHALLENGE_FIELD_PAYMENT_HASH,
        CHALLENGE_FIELD_LABEL,
    ] {
        assert!(!field.contains("preimage"));
        assert!(!field.contains("rune"));
    }
}

// --- Configuration ---

#[test]
fn only_an_absolute_socket_path_is_accepted() {
    check_socket_path(Path::new("/run/lightning/lightning-rpc")).expect("absolute is usable");
    assert_eq!(
        expect_error(
            check_socket_path(Path::new("lightning-rpc")),
            "a relative path must be refused"
        ),
        LightningError::Endpoint
    );
}

/// A shared record of every request a fixture transport was handed.
#[derive(Clone, Default)]
struct CallLog(Arc<Mutex<Vec<Vec<u8>>>>);

impl CallLog {
    /// Returns every recorded request.
    fn requests(&self) -> Vec<Vec<u8>> {
        self.0.lock().expect("not poisoned").clone()
    }
}

/// Answers every call with one fixture part, recording what it was asked.
struct FixtureTransport {
    log: CallLog,
    reply: &'static str,
}

#[async_trait::async_trait]
impl ClnTransport for FixtureTransport {
    async fn call(
        &self,
        request: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, LightningTransportFailure> {
        self.log
            .0
            .lock()
            .expect("not poisoned")
            .push(request.to_vec());
        Ok(newline_delimited(self.reply))
    }
}

#[tokio::test]
async fn startup_asks_getinfo_and_registers_only_above_the_floor() {
    let log = CallLog::default();
    let settler = ClnSettler::new(
        FixtureTransport {
            log: log.clone(),
            reply: "getinfo",
        },
        Some("rune-fixture-value".to_string()),
        "sbproxy paid request",
        400,
        2_000,
    )
    .expect("the settler builds");
    assert_eq!(
        settler.probe_version().await.expect("the floor is met"),
        (26, 6)
    );

    // The rune reached the request bytes and only the request bytes.
    let requests = log.requests();
    assert_eq!(requests.len(), 1, "startup makes exactly one call");
    let sent = String::from_utf8(requests[0].clone()).expect("ascii");
    assert!(sent.ends_with('\n'), "newline delimited");
    assert!(sent.contains("\"method\":\"getinfo\""));
    assert!(sent.contains("rune-fixture-value"));
}

#[tokio::test]
async fn a_node_below_the_floor_never_registers() {
    let settler = ClnSettler::new(
        FixtureTransport {
            log: CallLog::default(),
            reply: "getinfo_too_old",
        },
        None,
        "sbproxy paid request",
        400,
        2_000,
    )
    .expect("the settler builds");
    assert!(
        settler.probe_version().await.is_err(),
        "an older node must not register"
    );
}

#[tokio::test]
async fn a_getinfo_without_a_version_never_registers() {
    let settler = ClnSettler::new(
        FixtureTransport {
            log: CallLog::default(),
            reply: "getinfo_no_version",
        },
        None,
        "sbproxy paid request",
        400,
        2_000,
    )
    .expect("the settler builds");
    assert!(
        settler.probe_version().await.is_err(),
        "a node with no version must not register"
    );
}

#[test]
fn deadlines_that_do_not_bound_their_calls_are_refused() {
    let build = |call_ms: u64, total_ms: u64| {
        ClnSettler::new(
            FixtureTransport {
                log: CallLog::default(),
                reply: "getinfo",
            },
            None,
            "sbproxy paid request",
            call_ms,
            total_ms,
        )
    };
    // A per-call budget larger than the total deadline is not a deadline.
    assert!(build(3_000, 2_000).is_err());
    // Above the hard ceiling.
    assert!(build(400, 2_001).is_err());
    assert!(build(400, 2_000).is_ok());
}

/// A transport that answers `listinvoices` with one invoice under a given
/// label and status, and nothing else, since this is the only method
/// [`ClnSettler::authorize_and_settle`] calls.
struct StatusTransport {
    label: String,
    status: &'static str,
}

#[async_trait::async_trait]
impl ClnTransport for StatusTransport {
    async fn call(
        &self,
        _request: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, LightningTransportFailure> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "listinvoices",
            "result": {
                "invoices": [{
                    "label": self.label,
                    "status": self.status,
                    "payment_hash": FIXTURE_HASH,
                    "amount_msat": 100_000,
                    "amount_received_msat": 100_000,
                    "bolt11": "lnbc1u1pfixtureinvoicedatafixture",
                }],
            },
        });
        let mut bytes = serde_json::to_vec(&body).expect("the fixture body serializes");
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Builds the durable intent every phase of
/// [`an_unpaid_invoice_never_stamps_a_dispatch_and_a_later_payment_still_settles`]
/// redeems against.
fn lightning_draft() -> PaymentRequirementDraft {
    PaymentRequirementDraft {
        requirement_id: "requirement_0123456789".to_string(),
        protocol: PaymentProtocol::LightningInvoice,
        advertised_rail: AdvertisedRail::Lightning,
        settlement_rail: SettlementRail::LightningCln,
        method: "lightning".to_string(),
        intent: "charge".to_string(),
        network: Some("bitcoin".to_string()),
        asset: None,
        pay_to: None,
        amount: Money {
            amount_micros: 1,
            currency: "BTC".to_string(),
        },
        settlement_amount: "100000".to_string(),
        settlement_decimals: 11, // millisatoshi precision
        terms: RequirementTerms::LightningInvoice {
            backend: "cln".to_string(),
            invoice_expiry_seconds: 600,
        },
        quote_id: "quote-1".to_string(),
        tenant_id: "tenant-1".to_string(),
        origin_id: "origin-1".to_string(),
        route: "/paid".to_string(),
        expires_at_ms: 60_000,
        request_digest: None,
    }
}

/// WOR-2229: an early redemption against an unpaid invoice must not poison
/// the intent. Before this fix, `authorize_and_settle` stamped a dispatch
/// on the plain `listinvoices` read, so a merely-unpaid answer landed the
/// intent in `NeedsReconciliation`, unreachable by the request path until a
/// background worker swept it. This proves both halves: the unpaid read
/// leaves the intent retryable, and a genuinely paid follow-up on the very
/// next request settles without any worker involved.
#[tokio::test]
async fn an_unpaid_invoice_never_stamps_a_dispatch_and_a_later_payment_still_settles() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(1_000);
    let store = SqliteSettlementStore::open(&path)
        .expect("open settlement store")
        .with_clock(Arc::clone(&clock) as Arc<dyn BillingClock>)
        .shared();

    let draft = lightning_draft();
    let digest = draft.digest().expect("draft digest");
    let created = store
        .create_or_get_challenge(&draft, digest, "cln-request-key")
        .await
        .expect("create challenge");
    let signed = sign_draft(&draft, Some(FIXTURE_HASH));
    store
        .finalize_requirement(&created.intent_id, &signed)
        .await
        .expect("finalize");
    let label = invoice_label(&created.intent_id).expect("label");

    let redeem = |store: sbproxy_billing::store::SharedSettlementStore,
                  clock: Arc<TestClock>,
                  status: &'static str,
                  label: String,
                  signed: sbproxy_billing::types::SignedPaymentRequirement| async move {
        let mut registry = RailRegistry::new();
        let settler = ClnSettler::new(
            StatusTransport { label, status },
            None,
            "sbproxy paid request",
            400,
            2_000,
        )
        .expect("the settler builds");
        registry
            .register_adapter(Arc::new(settler))
            .expect("register adapter");
        let service = BillingService::builder(store)
            .adapters(registry)
            .clock(Arc::clone(&clock) as Arc<dyn BillingClock>)
            .payment_observer(Arc::new(NoOpPaymentLifecycleObserver))
            .deadline(Duration::from_millis(500))
            .expect("deadline inside the ceiling")
            .signer(Arc::new(FixtureSigner))
            .build();
        service
            .authorize(RedemptionRequest {
                signed,
                request_idempotency_key: "cln-request-key".to_string(),
                proof: PaymentProof::new("Payment", "lightning-proof".to_string()).expect("proof"),
            })
            .await
            .expect("authorize")
    };

    // Phase 1: the invoice is not paid yet.
    let decision = redeem(
        Arc::clone(&store),
        Arc::clone(&clock),
        "unpaid",
        label.clone(),
        signed.clone(),
    )
    .await;
    assert!(
        matches!(decision, AuthorizationDecision::Unavailable { .. }),
        "an unpaid invoice must not authorize origin access, got {decision:?}"
    );

    let intent = store
        .load_intent(&created.intent_id)
        .await
        .expect("read")
        .expect("intent");
    assert_eq!(
        intent.status,
        IntentStatus::RetryWait,
        "an unpaid invoice must leave the intent retryable, not stuck in reconciliation"
    );

    // Phase 2: the same invoice is now paid, presented again on the very
    // next request, with no worker sweep in between.
    let decision = redeem(store, clock, "paid", label, signed).await;
    assert!(
        matches!(decision, AuthorizationDecision::Settled(_)),
        "a genuinely paid invoice must settle on the next request, got {decision:?}"
    );
}
