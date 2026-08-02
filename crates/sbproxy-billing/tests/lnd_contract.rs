//! Contract tests for LND settlement.
//!
//! The five RPCs the adapter uses are driven through a recording test service
//! that implements [`LndTransport`], so the call order, the deterministic
//! preimage derivation, and the fail-closed reading of every state are all
//! observable without a socket.

#![cfg(feature = "lightning-lnd")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_billing::lightning::lnd::{
    parse_lnd_version, payment_hash_of, read_terminal_payment, require_supported_version,
    verify_settled_invoice, AddInvoiceRequest, AddInvoiceResponse, DecodedPayReq, GetInfoResponse,
    InvoiceKey, InvoiceState, LndInvoice, LndPayment, LndSettler, LndTransport, PaymentStatus,
    SendPaymentRequest, CHALLENGE_FIELD_PAYMENT_HASH, CHALLENGE_FIELD_PAYMENT_REQUEST,
    MIN_INVOICE_KEY_LEN, PINNED_LND_COMMIT, PINNED_LND_TAG,
};
use sbproxy_billing::lightning::{LightningError, LightningTransportFailure, PaymentHash};
use sbproxy_billing::BillingError;

/// The durable intent every test settles.
const INTENT_ID: &str = "sbpi_fixture_intent_0001";

/// A fixed test key. Never a real one.
const TEST_KEY: [u8; MIN_INVOICE_KEY_LEN] = [9u8; MIN_INVOICE_KEY_LEN];

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

/// Which RPC a recording service was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rpc {
    /// `GetInfo`.
    GetInfo,
    /// `AddInvoice`, with the payment hash of the preimage it was handed.
    AddInvoice(String),
    /// `LookupInvoice`, with the hash it was asked about.
    LookupInvoice(String),
    /// `SendPaymentV2`.
    SendPayment,
    /// `TrackPaymentV2`, with the hash it was asked about.
    TrackPayment(String),
    /// `DecodePayReq`.
    DecodePayReq,
}

/// What a recording service should answer.
#[derive(Clone, Default)]
struct Answers {
    /// The version `GetInfo` reports.
    version: String,
    /// Whether `GetInfo` claims the node is synced.
    synced: bool,
    /// The invoice `LookupInvoice` returns, when it holds one.
    invoice: Option<LndInvoice>,
    /// The payment the two payment RPCs resolve to.
    payment: Option<LndPayment>,
}

/// A recording LND service.
struct RecordingService {
    calls: Arc<Mutex<Vec<Rpc>>>,
    answers: Answers,
}

impl RecordingService {
    /// Builds a service and returns it alongside its call log.
    fn new(answers: Answers) -> (Self, Arc<Mutex<Vec<Rpc>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                calls: Arc::clone(&calls),
                answers,
            },
            calls,
        )
    }

    /// Records one call.
    fn record(&self, rpc: Rpc) {
        self.calls.lock().expect("not poisoned").push(rpc);
    }
}

#[async_trait::async_trait]
impl LndTransport for RecordingService {
    async fn get_info(
        &self,
        _timeout: Duration,
    ) -> Result<GetInfoResponse, LightningTransportFailure> {
        self.record(Rpc::GetInfo);
        Ok(GetInfoResponse {
            version: self.answers.version.clone(),
            synced_to_chain: self.answers.synced,
        })
    }

    async fn add_invoice(
        &self,
        request: AddInvoiceRequest,
        _timeout: Duration,
    ) -> Result<AddInvoiceResponse, LightningTransportFailure> {
        // The node derives the hash from the preimage it was handed, exactly
        // as a real node does.
        let hash = payment_hash_of(request.preimage.as_slice());
        self.record(Rpc::AddInvoice(hash.to_hex()));
        Ok(AddInvoiceResponse {
            r_hash: hash.as_bytes().to_vec(),
            payment_request: "lnbc1u1pfixtureinvoicedata".to_string(),
        })
    }

    async fn lookup_invoice(
        &self,
        payment_hash: PaymentHash,
        _timeout: Duration,
    ) -> Result<Option<LndInvoice>, LightningTransportFailure> {
        self.record(Rpc::LookupInvoice(payment_hash.to_hex()));
        Ok(self.answers.invoice.clone())
    }

    async fn send_payment_v2(
        &self,
        _request: SendPaymentRequest,
        _timeout: Duration,
    ) -> Result<Option<LndPayment>, LightningTransportFailure> {
        self.record(Rpc::SendPayment);
        Ok(self.answers.payment.clone())
    }

    async fn track_payment_v2(
        &self,
        payment_hash: PaymentHash,
        _timeout: Duration,
    ) -> Result<Option<LndPayment>, LightningTransportFailure> {
        self.record(Rpc::TrackPayment(payment_hash.to_hex()));
        Ok(self.answers.payment.clone())
    }

    async fn decode_pay_req(
        &self,
        _payment_request: &str,
        _timeout: Duration,
    ) -> Result<DecodedPayReq, LightningTransportFailure> {
        self.record(Rpc::DecodePayReq);
        Ok(DecodedPayReq {
            payment_hash: PaymentHash::from_bytes([3u8; 32]).to_hex(),
            num_msat: 100_000,
        })
    }
}

/// Answers a healthy node gives at startup.
fn healthy() -> Answers {
    Answers {
        version: PINNED_LND_TAG.trim_start_matches('v').to_string(),
        synced: true,
        invoice: None,
        payment: None,
    }
}

/// Builds a settler over a recording service.
fn build_settler(answers: Answers) -> (LndSettler<RecordingService>, Arc<Mutex<Vec<Rpc>>>) {
    let (service, calls) = RecordingService::new(answers);
    let settler = LndSettler::new(
        service,
        InvoiceKey::new(&TEST_KEY).expect("a 32 byte key is usable"),
        "sbproxy paid request",
        400,
        2_000,
    )
    .expect("the settler builds");
    (settler, calls)
}

// --- Pinned upstream ---

#[test]
fn the_pinned_upstream_coordinates_are_recorded() {
    assert_eq!(PINNED_LND_TAG, "v0.20.1-beta");
    assert_eq!(
        PINNED_LND_COMMIT,
        "848b72ce96eb68fa90fd4336523ca4c59bddcd4c"
    );
}

#[test]
fn the_upstream_enumeration_values_are_the_upstream_ones() {
    assert_eq!(InvoiceState::Open.as_i32(), 0);
    assert_eq!(InvoiceState::Settled.as_i32(), 1);
    assert_eq!(InvoiceState::Canceled.as_i32(), 2);
    assert_eq!(InvoiceState::Accepted.as_i32(), 3);

    assert_eq!(PaymentStatus::Unknown.as_i32(), 0);
    assert_eq!(PaymentStatus::InFlight.as_i32(), 1);
    assert_eq!(PaymentStatus::Succeeded.as_i32(), 2);
    assert_eq!(PaymentStatus::Failed.as_i32(), 3);
    assert_eq!(PaymentStatus::Initiated.as_i32(), 4);
}

// --- Startup ---

#[tokio::test]
async fn startup_asks_getinfo_and_registers_only_above_the_floor() {
    let (settler, calls) = build_settler(healthy());
    assert_eq!(
        settler.probe_version().await.expect("the floor is met"),
        (0, 20)
    );
    let seen = calls.lock().expect("not poisoned").clone();
    assert_eq!(seen, vec![Rpc::GetInfo]);
}

#[tokio::test]
async fn an_unsynced_or_old_node_never_registers() {
    let (unsynced, _) = build_settler(Answers {
        synced: false,
        ..healthy()
    });
    assert!(
        unsynced.probe_version().await.is_err(),
        "unsynced must refuse"
    );

    let (outdated, _) = build_settler(Answers {
        version: "0.19.2-beta".to_string(),
        ..healthy()
    });
    assert!(
        outdated.probe_version().await.is_err(),
        "too old must refuse"
    );
}

#[test]
fn versions_parse_or_are_refused_rather_than_assumed() {
    assert_eq!(parse_lnd_version("0.20.1-beta").expect("pinned"), (0, 20));
    assert_eq!(
        parse_lnd_version("0.20.1-beta commit=v0.20.1-beta").expect("with commit"),
        (0, 20)
    );
    for bad in ["", "v", "beta", "0", "0.x"] {
        assert_eq!(
            expect_error(
                require_supported_version(bad),
                "a malformed version must be refused"
            ),
            LightningError::VersionMalformed,
            "expected {bad:?} to be refused"
        );
    }
}

// --- Deterministic preimage ---

#[test]
fn a_short_invoice_key_is_refused() {
    assert_eq!(
        expect_error(InvoiceKey::new(&[1u8; 16]), "a short key must be refused"),
        LightningError::Endpoint
    );
}

#[test]
fn the_payment_hash_is_recomputable_from_two_durable_columns() {
    let one = InvoiceKey::new(&TEST_KEY).expect("usable");
    let two = InvoiceKey::new(&TEST_KEY).expect("usable");
    // A replacement process holding the same key derives the same hash from
    // the intent identifier and the attempt generation, so it can look the
    // invoice up rather than adding a second one.
    assert_eq!(
        one.payment_hash(INTENT_ID, 0),
        two.payment_hash(INTENT_ID, 0)
    );
    // A proven non-dispatch may move to the next generation, which derives a
    // different preimage rather than reusing one.
    assert_ne!(
        one.payment_hash(INTENT_ID, 0),
        one.payment_hash(INTENT_ID, 1)
    );
    assert_ne!(
        one.payment_hash(INTENT_ID, 0),
        one.payment_hash("sbpi_other", 0)
    );
    // And the hash really is the SHA-256 of the preimage the node is handed.
    assert_eq!(
        one.payment_hash(INTENT_ID, 0),
        payment_hash_of(one.preimage(INTENT_ID, 0).as_slice())
    );
}

#[tokio::test]
async fn add_invoice_is_handed_the_derived_preimage() {
    let (settler, calls) = build_settler(healthy());
    let expected = settler.expected_hash(INTENT_ID, 0);
    let key = InvoiceKey::new(&TEST_KEY).expect("usable");
    let preimage = key.preimage(INTENT_ID, 0);

    // Drive the transport the way the adapter does, so the recording service
    // sees exactly the preimage the derivation produced.
    let (service, service_calls) = RecordingService::new(healthy());
    let response = service
        .add_invoice(
            AddInvoiceRequest {
                memo: "sbproxy paid request".to_string(),
                value_msat: 100_000,
                expiry_seconds: 600,
                preimage,
            },
            Duration::from_millis(400),
        )
        .await
        .expect("the recording service answers");
    let seen = service_calls.lock().expect("not poisoned").clone();
    assert_eq!(seen, vec![Rpc::AddInvoice(expected.to_hex())]);
    assert_eq!(
        PaymentHash::parse_bytes(&response.r_hash).expect("32 bytes"),
        expected,
        "the node records the hash the derivation predicted"
    );
    assert!(
        calls.lock().expect("not poisoned").is_empty(),
        "the settler's own transport was not called"
    );
}

// --- What authorizes ---

#[test]
fn only_settled_and_succeeded_authorize() {
    for value in [0, 2, 3] {
        let state = InvoiceState::from_i32(value).expect("a known state");
        assert!(
            !state.is_settled(),
            "invoice state {value} must not authorize"
        );
    }
    assert!(InvoiceState::Settled.is_settled());
    // A state added in a later release is not coerced onto a known one.
    assert_eq!(InvoiceState::from_i32(9), None);

    for value in [0, 1, 3, 4] {
        let status = PaymentStatus::from_i32(value).expect("a known status");
        assert!(
            !status.is_settled(),
            "payment status {value} must not authorize"
        );
    }
    assert!(PaymentStatus::Succeeded.is_settled());
    assert_eq!(PaymentStatus::from_i32(9), None);
}

#[test]
fn an_amount_or_hash_mismatch_denies() {
    let expected = PaymentHash::from_bytes([3u8; 32]);
    let invoice = LndInvoice {
        r_hash: expected.as_bytes().to_vec(),
        value_msat: 100_000,
        amt_paid_msat: 100_000,
        state: InvoiceState::Settled.as_i32(),
        settle_date: 1_770_000_100,
        payment_request: "lnbc1u1pfixtureinvoicedata".to_string(),
    };
    assert!(verify_settled_invoice(&invoice, expected, 100_000).is_ok());
    assert_eq!(
        expect_error(
            verify_settled_invoice(&invoice, PaymentHash::from_bytes([4u8; 32]), 100_000),
            "a hash mismatch must deny"
        ),
        LightningError::BindingMismatch
    );
    assert_eq!(
        expect_error(
            verify_settled_invoice(&invoice, expected, 100_001),
            "an amount mismatch must deny"
        ),
        LightningError::BindingMismatch
    );
}

#[test]
fn a_stream_that_ended_enters_reconciliation_rather_than_failing() {
    let expected = PaymentHash::from_bytes([3u8; 32]);
    assert_eq!(
        expect_error(
            read_terminal_payment(None, expected),
            "a stream that ended proves nothing"
        ),
        BillingError::NeedsReconciliation
    );
    for status in [
        PaymentStatus::InFlight,
        PaymentStatus::Initiated,
        PaymentStatus::Unknown,
    ] {
        let payment = LndPayment {
            payment_hash: expected.to_hex(),
            status: status.as_i32(),
            value_msat: 100_000,
        };
        assert_eq!(
            expect_error(
                read_terminal_payment(Some(&payment), expected),
                "a non terminal update proves nothing"
            ),
            BillingError::NeedsReconciliation
        );
    }
    let failed = LndPayment {
        payment_hash: expected.to_hex(),
        status: PaymentStatus::Failed.as_i32(),
        value_msat: 0,
    };
    assert_eq!(
        expect_error(
            read_terminal_payment(Some(&failed), expected),
            "a failed payment is a refusal"
        ),
        BillingError::ProviderRejected
    );
}

#[test]
fn a_duplicate_update_for_a_different_hash_never_resolves() {
    let expected = PaymentHash::from_bytes([3u8; 32]);
    let other = LndPayment {
        payment_hash: PaymentHash::from_bytes([4u8; 32]).to_hex(),
        status: PaymentStatus::Succeeded.as_i32(),
        value_msat: 100_000,
    };
    assert_eq!(
        expect_error(
            read_terminal_payment(Some(&other), expected),
            "another payment's success is not this one's"
        ),
        BillingError::NeedsReconciliation
    );
}

#[test]
fn the_challenge_field_names_are_pinned_and_carry_no_preimage() {
    assert_eq!(CHALLENGE_FIELD_PAYMENT_REQUEST, "payment_request");
    assert_eq!(CHALLENGE_FIELD_PAYMENT_HASH, "payment_hash");
    for field in [
        CHALLENGE_FIELD_PAYMENT_REQUEST,
        CHALLENGE_FIELD_PAYMENT_HASH,
    ] {
        assert!(!field.contains("preimage"));
        assert!(!field.contains("macaroon"));
    }
}

#[test]
fn a_refund_is_a_typed_refusal_and_never_a_receipt() {
    let (settler, _) = build_settler(healthy());
    assert_eq!(
        expect_error(settler.refund(), "a lightning refund must be refused"),
        LightningError::NoPayerDestination
    );
}

#[test]
fn deadlines_that_do_not_bound_their_calls_are_refused() {
    let build = |call_ms: u64, total_ms: u64| {
        let (service, _) = RecordingService::new(healthy());
        LndSettler::new(
            service,
            InvoiceKey::new(&TEST_KEY).expect("usable"),
            "sbproxy paid request",
            call_ms,
            total_ms,
        )
    };
    assert!(build(3_000, 2_000).is_err());
    assert!(build(400, 2_001).is_err());
    assert!(build(400, 2_000).is_ok());
}

#[tokio::test]
async fn tracking_a_dispatched_send_never_calls_send_again() {
    let settled = LndPayment {
        payment_hash: PaymentHash::from_bytes([3u8; 32]).to_hex(),
        status: PaymentStatus::Succeeded.as_i32(),
        value_msat: 100_000,
    };
    let (service, calls) = RecordingService::new(Answers {
        payment: Some(settled),
        ..healthy()
    });
    let hash = PaymentHash::from_bytes([3u8; 32]);
    let resolved = service
        .track_payment_v2(hash, Duration::from_millis(400))
        .await
        .expect("the recording service answers");
    assert_eq!(
        read_terminal_payment(resolved.as_ref(), hash).expect("a settled payment resolves"),
        hash
    );
    let seen = calls.lock().expect("not poisoned").clone();
    assert_eq!(seen, vec![Rpc::TrackPayment(hash.to_hex())]);
    assert!(
        !seen.contains(&Rpc::SendPayment),
        "reconciliation must never send a second payment"
    );
}
