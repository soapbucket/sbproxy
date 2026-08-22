//! Contract tests for x402 v2 `exact`.
//!
//! The wire shapes come from `tests/fixtures/x402/exact_envelope.json`
//! and the published extension schema from
//! `tests/fixtures/x402/sbproxy-requirement.schema.json`. The
//! authorization tests run against a recording facilitator so the exact
//! set of endpoints, the order of the calls, and the fail-closed
//! behavior are all observable without a socket.

#![cfg(feature = "x402")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_billing::x402::{
    decode_x402_json, encode_x402_header, validate_echoed_payload, FacilitatorBreaker,
    FacilitatorEndpoints, FacilitatorEntry, FacilitatorHttpResponse, FacilitatorPool,
    FacilitatorTransport, PaymentPayload, PaymentRequired, RequirementExtension,
    SettleDispatchGate, SettleResponse, SignedX402Challenge, TransportFailure,
    X402AuthorizationRequest, X402Error, X402ExactSettler, X402QueryResult,
    REQUIREMENT_EXTENSION_KEY, REQUIREMENT_EXTENSION_SCHEMA,
};
use sbproxy_billing::{
    derive_intent_id, BillingClock, BillingService, IntentStatus, PaymentLifecycleEvent,
    PaymentLifecycleObserver, PaymentProof, RailRegistry, RedemptionRequest, RequirementInput,
    SharedSettlementStore, SignedPaymentRequirement, SqliteSettlementStore, X402Adapter,
};
use sbproxy_billing::{
    BillingError, PaymentLifecycleDecision, PaymentLifecycleOutcome, PaymentLifecyclePhase,
};

mod common;

use common::{sample_draft, FixtureSigner, TestClock};

/// The frozen envelope shapes.
const ENVELOPE: &str = include_str!("fixtures/x402/exact_envelope.json");

/// The checked-in extension schema.
const SCHEMA_FIXTURE: &str = include_str!("fixtures/x402/sbproxy-requirement.schema.json");

/// The durable intent every authorization test settles.
const INTENT_ID: &str = "sbpi_fixture_intent_0001";

/// Per-call and total budgets, scaled down so the tests stay fast while
/// keeping the same ordering the shipped 700, 1200, and 2000 ms budgets
/// produce.
const VERIFY_MS: u64 = 50;
/// Settle budget for the scaled-down tests.
const SETTLE_MS: u64 = 60;
/// Total deadline for the scaled-down tests.
const TOTAL_MS: u64 = 150;

/// `unwrap_err` requires `Debug` on the success type, and the x402 wire
/// types deliberately do not carry one because they hold payer
/// identifiers and signed payloads. Errors are unwrapped through this
/// helper rather than widening a derive to suit a test.
#[track_caller]
fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

/// Reads one sub-document out of the frozen envelope fixture.
#[track_caller]
fn part(name: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(ENVELOPE).expect("the frozen envelope is valid JSON");
    parsed
        .get(name)
        .unwrap_or_else(|| panic!("fixture part {name} is missing"))
        .clone()
}

/// Serializes a fixture part to the bytes a facilitator would return.
#[track_caller]
fn body(name: &str) -> Vec<u8> {
    serde_json::to_vec(&part(name)).expect("a fixture part serializes")
}

/// Decodes the frozen 402 envelope.
#[track_caller]
fn frozen_required() -> PaymentRequired {
    decode_x402_json(&body("payment_required")).expect("the frozen 402 envelope decodes")
}

/// Decodes the frozen retry envelope.
#[track_caller]
fn frozen_payload() -> PaymentPayload {
    decode_x402_json(&body("payment_payload")).expect("the frozen retry envelope decodes")
}

/// The challenge the proxy signed, borrowed from the frozen 402.
fn challenge(required: &PaymentRequired) -> SignedX402Challenge<'_> {
    SignedX402Challenge {
        intent_id: INTENT_ID,
        resource: &required.resource,
        accepted: &required.accepts[0],
        extensions: &required.extensions,
    }
}

/// How the recording facilitator answers one endpoint.
#[derive(Clone)]
enum Reply {
    /// Answer after a delay, or time out when the delay exceeds the
    /// caller's budget.
    Body {
        status: u16,
        body: Vec<u8>,
        delay_ms: u64,
    },
    /// Fail at the transport layer.
    Fail(TransportFailure),
}

/// A facilitator that records every URL it is asked for.
struct RecordingFacilitator {
    calls: Arc<Mutex<Vec<String>>>,
    verify: Reply,
    settle: Reply,
}

#[async_trait::async_trait]
impl FacilitatorTransport for RecordingFacilitator {
    async fn post_json(
        &self,
        url: &str,
        _body: &[u8],
        timeout: Duration,
    ) -> Result<FacilitatorHttpResponse, TransportFailure> {
        self.calls
            .lock()
            .expect("the call log is usable")
            .push(url.to_string());
        let reply = if url.ends_with("/verify") {
            self.verify.clone()
        } else {
            self.settle.clone()
        };
        match reply {
            Reply::Fail(failure) => Err(failure),
            Reply::Body {
                status,
                body,
                delay_ms,
            } => {
                let delay = Duration::from_millis(delay_ms);
                if delay >= timeout {
                    tokio::time::sleep(timeout).await;
                    return Err(TransportFailure::Timeout);
                }
                tokio::time::sleep(delay).await;
                Ok(FacilitatorHttpResponse { status, body })
            }
        }
    }
}

/// A dispatch gate that counts the stamps it commits.
struct RecordingGate {
    stamps: Arc<AtomicUsize>,
    delay_ms: u64,
}

struct LifecycleGate {
    events: Arc<Mutex<Vec<(PaymentLifecyclePhase, PaymentLifecycleOutcome)>>>,
    stamps: Arc<AtomicUsize>,
}

struct RejectPhaseObserver {
    reject: Option<PaymentLifecyclePhase>,
    events: Mutex<Vec<(PaymentLifecyclePhase, PaymentLifecycleOutcome)>>,
}

#[async_trait::async_trait]
impl PaymentLifecycleObserver for RejectPhaseObserver {
    async fn started(&self, event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision {
        self.events
            .lock()
            .unwrap()
            .push((event.phase(), event.outcome()));
        if Some(event.phase()) == self.reject {
            PaymentLifecycleDecision::Reject
        } else {
            PaymentLifecycleDecision::Continue
        }
    }

    fn terminal(&self, event: PaymentLifecycleEvent) {
        self.events
            .lock()
            .unwrap()
            .push((event.phase(), event.outcome()));
    }
}

#[async_trait::async_trait]
impl SettleDispatchGate for LifecycleGate {
    async fn stamp_settle_dispatch(&self) -> Result<(), BillingError> {
        self.stamps.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn payment_started(&self, phase: PaymentLifecyclePhase) -> PaymentLifecycleDecision {
        self.events
            .lock()
            .unwrap()
            .push((phase, PaymentLifecycleOutcome::Started));
        PaymentLifecycleDecision::Continue
    }

    fn payment_terminal(&self, phase: PaymentLifecyclePhase, outcome: PaymentLifecycleOutcome) {
        self.events.lock().unwrap().push((phase, outcome));
    }
}

#[async_trait::async_trait]
impl SettleDispatchGate for RecordingGate {
    async fn stamp_settle_dispatch(&self) -> Result<(), BillingError> {
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        self.stamps.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Builds a settler over the recording facilitator.
fn settler(
    verify: Reply,
    settle: Reply,
    calls: Arc<Mutex<Vec<String>>>,
    breaker: Arc<FacilitatorBreaker>,
) -> X402ExactSettler<RecordingFacilitator> {
    let endpoints = FacilitatorEndpoints::from_api_root("https://facilitator.example/base")
        .expect("the fixture API root is usable");
    X402ExactSettler::new(
        endpoints,
        RecordingFacilitator {
            calls,
            verify,
            settle,
        },
        breaker,
        VERIFY_MS,
        SETTLE_MS,
        TOTAL_MS,
    )
    .expect("the scaled-down budgets are within the ceiling")
}

/// A closed breaker with the shipped bounds.
fn breaker() -> Arc<FacilitatorBreaker> {
    Arc::new(FacilitatorBreaker::new(3, 100, 1).expect("bounded breaker"))
}

/// A reply that answers 200 with a fixture body and no delay.
fn ok(name: &str) -> Reply {
    Reply::Body {
        status: 200,
        body: body(name),
        delay_ms: 0,
    }
}

struct ServiceLifecycleFixture {
    service: BillingService,
    signed: SignedPaymentRequirement,
    observer: Arc<RejectPhaseObserver>,
    calls: Arc<Mutex<Vec<String>>>,
    store: SharedSettlementStore,
    intent_id: String,
    _directory: tempfile::TempDir,
}

impl ServiceLifecycleFixture {
    /// The durable state of the one intent these fixtures settle.
    async fn intent_status(&self) -> IntentStatus {
        self.store
            .load_intent(&self.intent_id)
            .await
            .expect("the intent reads back")
            .expect("the intent exists")
            .status
    }

    /// The attempts the recovery sweep would pick up on its next tick.
    ///
    /// This is what makes an ambiguous settle reconcilable later: an
    /// attempt that is not on this queue is one no sweep will ever ask
    /// the facilitator about.
    async fn reconciliation_queue(&self) -> Vec<String> {
        self.store
            .claim_reconciliation(1_700_000_000_000, 30_000, 8)
            .await
            .expect("the reconciliation queue reads back")
            .into_iter()
            .map(|claimed| claimed.attempt.intent_id)
            .collect()
    }
}

async fn service_lifecycle_fixture(
    reject: Option<PaymentLifecyclePhase>,
    settle: Reply,
) -> ServiceLifecycleFixture {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observer = Arc::new(RejectPhaseObserver {
        reject,
        events: Mutex::new(Vec::new()),
    });
    let exact = Arc::new(settler(
        ok("verify_response"),
        settle,
        calls.clone(),
        breaker(),
    ));
    let mut registry = RailRegistry::new();
    registry
        .register_adapter(Arc::new(X402Adapter::new(vec![exact]).unwrap()))
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let clock = TestClock::new(1_700_000_000_000);
    let store = SqliteSettlementStore::open(&directory.path().join("settlement.sqlite3"))
        .unwrap()
        .with_clock(Arc::clone(&clock) as Arc<dyn BillingClock>)
        .shared();
    let service = BillingService::builder(Arc::clone(&store))
        .adapters(registry)
        .clock(clock as Arc<dyn BillingClock>)
        .signer(Arc::new(FixtureSigner))
        .payment_observer(observer.clone())
        .build();
    let mut draft = sample_draft("tenant-1", "sbpr_fixture_req_0001", 1_700_000_600_000);
    let sbproxy_billing::RequirementTerms::X402Exact {
        facilitator_url, ..
    } = &mut draft.terms
    else {
        unreachable!()
    };
    *facilitator_url = "https://facilitator.example/base".to_owned();
    let prepared = service
        .prepare_requirement(RequirementInput {
            draft,
            request_idempotency_key: "request-key".to_owned(),
            payer_hash: None,
        })
        .await
        .expect("challenge prepares");
    observer.events.lock().unwrap().clear();
    calls.lock().unwrap().clear();

    ServiceLifecycleFixture {
        service,
        signed: prepared.signed,
        observer,
        calls,
        store,
        intent_id: derive_intent_id("tenant-1", "request-key"),
        _directory: directory,
    }
}

async fn authorize_fixture(
    fixture: &ServiceLifecycleFixture,
) -> sbproxy_billing::AuthorizationDecision {
    fixture
        .service
        .authorize(RedemptionRequest {
            signed: fixture.signed.clone(),
            request_idempotency_key: "request-key".to_owned(),
            proof: PaymentProof::new("Payment", r#"{"signature":"secret"}"#.to_owned()).unwrap(),
        })
        .await
        .unwrap()
}

#[test]
fn the_published_schema_matches_the_checked_in_fixture() {
    let from_source: serde_json::Value = serde_json::from_str(REQUIREMENT_EXTENSION_SCHEMA)
        .expect("the published schema constant parses");
    let from_fixture: serde_json::Value =
        serde_json::from_str(SCHEMA_FIXTURE).expect("the checked-in schema fixture parses");
    assert_eq!(from_source, from_fixture);

    // The constant is already in canonical form, so the bytes a client
    // echoes and the bytes the proxy compares are the same bytes.
    let canonical =
        serde_json_canonicalizer::to_vec(&from_source).expect("the schema canonicalizes");
    assert_eq!(
        String::from_utf8(canonical).unwrap(),
        REQUIREMENT_EXTENSION_SCHEMA
    );
}

#[test]
fn the_frozen_envelopes_decode_into_the_pinned_shapes() {
    let required = frozen_required();
    assert_eq!(required.x402_version, 2);
    assert_eq!(required.accepts.len(), 1);
    assert_eq!(required.accepts[0].scheme, "exact");
    assert_eq!(required.accepts[0].network, "eip155:84532");
    assert_eq!(required.accepts[0].amount, "1000");
    assert_eq!(required.accepts[0].max_timeout_seconds, 60);
    assert_eq!(required.extensions.len(), 1);
    assert!(required.extensions.contains_key(REQUIREMENT_EXTENSION_KEY));

    let payload = frozen_payload();
    assert_eq!(payload.x402_version, 2);
    assert_eq!(payload.accepted, required.accepts[0]);
    assert_eq!(payload.extensions, required.extensions);

    // The scheme payload is opaque and is only ever hashed.
    let proof = payload.proof().expect("the scheme payload hashes");
    let again = frozen_payload().proof().expect("the digest is stable");
    assert!(proof.matches_digest(&again.digest()));
}

#[test]
fn the_extension_is_built_from_the_signed_requirement() {
    let extension = RequirementExtension::new(
        "sbpr_fixture_requirement_0001",
        "eyJhbGciOiJFZERTQSJ9.ZmluZ2VycHJpbnQ.c2lnbmF0dXJl",
    )
    .expect("the fixture identifiers are within the published schema");
    let map = extension
        .to_extensions_map()
        .expect("the extension renders one map entry");
    assert_eq!(map, frozen_required().extensions);
}

#[test]
fn a_matching_payload_passes_local_validation() {
    let required = frozen_required();
    validate_echoed_payload(&frozen_payload(), &challenge(&required))
        .expect("the frozen payload echoes the frozen challenge");
}

#[test]
fn every_requirement_field_is_compared_exactly() {
    let required = frozen_required();
    for (pointer, replacement) in [
        ("/accepted/amount", serde_json::json!("1")),
        ("/accepted/network", serde_json::json!("eip155:1")),
        ("/accepted/asset", serde_json::json!("0xdeadbeef")),
        (
            "/accepted/payTo",
            serde_json::json!("0x9999999999999999999999999999999999999999"),
        ),
        ("/accepted/maxTimeoutSeconds", serde_json::json!(600)),
        ("/accepted/extra/version", serde_json::json!("3")),
        (
            "/resource/url",
            serde_json::json!("https://api.example.com/v1/other"),
        ),
    ] {
        let mut document = part("payment_payload");
        *document
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("fixture pointer {pointer} exists")) = replacement;
        let payload: PaymentPayload = decode_x402_json(&serde_json::to_vec(&document).unwrap())
            .expect("the mutated payload still parses");
        assert_eq!(
            expect_error(
                validate_echoed_payload(&payload, &challenge(&required)),
                "a changed obligation must be refused"
            ),
            X402Error::RequirementMismatch,
            "expected {pointer} to be compared exactly"
        );
    }
}

#[test]
fn a_changed_or_extra_extension_is_refused() {
    let required = frozen_required();

    // A changed quote inside the echoed extension.
    let mut document = part("payment_payload");
    *document
        .pointer_mut("/extensions/sbproxy-requirement/info/quote")
        .expect("the quote pointer exists") = serde_json::json!("forged.quote.token");
    let payload: PaymentPayload =
        decode_x402_json(&serde_json::to_vec(&document).unwrap()).expect("it still parses");
    assert_eq!(
        expect_error(
            validate_echoed_payload(&payload, &challenge(&required)),
            "a changed extension must be refused"
        ),
        X402Error::RequirementMismatch
    );

    // A second extension beside the published one.
    let mut document = part("payment_payload");
    document["extensions"]["vendor-extra"] = serde_json::json!({"anything": true});
    let payload: PaymentPayload =
        decode_x402_json(&serde_json::to_vec(&document).unwrap()).expect("it still parses");
    assert_eq!(
        expect_error(
            validate_echoed_payload(&payload, &challenge(&required)),
            "an added extension must be refused"
        ),
        X402Error::ExtensionInvalid
    );
}

#[test]
fn an_unknown_top_level_field_or_wrong_version_is_refused() {
    let mut document = part("payment_payload");
    document["surprise"] = serde_json::json!(true);
    assert_eq!(
        expect_error(
            decode_x402_json::<PaymentPayload>(&serde_json::to_vec(&document).unwrap()),
            "an unknown top-level field must be refused"
        ),
        X402Error::Malformed
    );

    let required = frozen_required();
    let mut document = part("payment_payload");
    document["x402Version"] = serde_json::json!(1);
    let payload: PaymentPayload =
        decode_x402_json(&serde_json::to_vec(&document).unwrap()).expect("it still parses");
    assert_eq!(
        expect_error(
            validate_echoed_payload(&payload, &challenge(&required)),
            "a foreign protocol version must be refused"
        ),
        X402Error::UnsupportedVersion
    );
}

#[test]
fn header_values_use_standard_base64_with_padding() {
    let encoded = encode_x402_header(&frozen_required()).expect("the 402 envelope encodes");
    assert_eq!(encoded.len() % 4, 0);
    assert!(!encoded.contains('-'));
    assert!(!encoded.contains('_'));
}

#[tokio::test]
async fn verify_then_settle_commits_a_receipt_from_real_values() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let stamps = Arc::new(AtomicUsize::new(0));
    let settler = settler(
        ok("verify_response"),
        ok("settle_response"),
        calls.clone(),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let settlement = settler
        .authorize_and_settle(
            X402AuthorizationRequest {
                challenge: challenge(&required),
                payload: &payload,
                now_ms: 1_800_000_000_000,
            },
            &RecordingGate {
                stamps: stamps.clone(),
                delay_ms: 0,
            },
        )
        .await
        .expect("a verified and settled payment authorizes");

    assert_eq!(settlement.receipt.intent_id, INTENT_ID);
    assert_eq!(settlement.receipt.method, "exact");
    assert_eq!(
        settlement.receipt.provider_reference,
        "0x3333333333333333333333333333333333333333333333333333333333333333"
    );
    settlement
        .receipt
        .validate()
        .expect("the receipt keys the values it claims to key");
    assert!(settlement.response_header_value().is_ok());

    // Exactly the two protocol-required calls, in order, against the
    // one facilitator the requirement selected.
    let calls = calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            "https://facilitator.example/base/verify".to_string(),
            "https://facilitator.example/base/settle".to_string(),
        ]
    );
    assert_eq!(stamps.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn x402_lifecycle_events_follow_verify_then_settle_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let settler = settler(
        ok("verify_response"),
        ok("settle_response"),
        Arc::new(Mutex::new(Vec::new())),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    settler
        .authorize_and_settle(
            X402AuthorizationRequest {
                challenge: challenge(&required),
                payload: &payload,
                now_ms: 1_800_000_000_000,
            },
            &LifecycleGate {
                events: events.clone(),
                stamps: Arc::new(AtomicUsize::new(0)),
            },
        )
        .await
        .expect("payment settles");

    assert_eq!(
        *events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Succeeded,
            ),
            (
                PaymentLifecyclePhase::Settle,
                PaymentLifecycleOutcome::Started,
            ),
        ]
    );
}

#[tokio::test]
async fn x402_verify_rejection_emits_rejected_without_settle_start() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let settler = settler(
        ok("verify_rejection"),
        ok("settle_response"),
        calls.clone(),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &LifecycleGate {
                    events: events.clone(),
                    stamps: Arc::new(AtomicUsize::new(0)),
                },
            )
            .await,
        "verify rejection must stop settlement",
    );

    assert_eq!(error, BillingError::ProviderRejected);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(
        *events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Rejected,
            ),
        ]
    );
}

#[tokio::test]
async fn x402_verify_failure_emits_failed_without_settle_start() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let settler = settler(
        Reply::Fail(TransportFailure::Connection),
        ok("settle_response"),
        Arc::new(Mutex::new(Vec::new())),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &LifecycleGate {
                    events: events.clone(),
                    stamps: Arc::new(AtomicUsize::new(0)),
                },
            )
            .await,
        "verify transport failure must stop settlement",
    );

    assert_eq!(error, BillingError::ProviderUnavailable);
    assert_eq!(
        *events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Failed,
            ),
        ]
    );
}

#[tokio::test]
async fn x402_verify_started_rejection_prevents_facilitator_access() {
    let fixture =
        service_lifecycle_fixture(Some(PaymentLifecyclePhase::Verify), ok("settle_response")).await;

    let decision = authorize_fixture(&fixture).await;

    assert!(
        matches!(
            decision,
            sbproxy_billing::AuthorizationDecision::PaymentRequired(_)
        ),
        "decision={decision:?} events={:?}",
        fixture.observer.events.lock().unwrap()
    );
    assert!(fixture.calls.lock().unwrap().is_empty());
    assert_eq!(
        *fixture.observer.events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Rejected,
            ),
        ]
    );
}

#[tokio::test]
async fn x402_settle_started_rejection_prevents_provider_write() {
    let fixture =
        service_lifecycle_fixture(Some(PaymentLifecyclePhase::Settle), ok("settle_response")).await;

    let decision = authorize_fixture(&fixture).await;

    assert!(matches!(
        decision,
        sbproxy_billing::AuthorizationDecision::PaymentRequired(_)
    ));
    assert_eq!(
        *fixture.calls.lock().unwrap(),
        ["https://facilitator.example/base/verify"]
    );
    assert_eq!(
        *fixture.observer.events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Succeeded,
            ),
            (
                PaymentLifecyclePhase::Settle,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Settle,
                PaymentLifecycleOutcome::Rejected,
            ),
        ]
    );
}

#[tokio::test]
async fn x402_service_emits_succeeded_after_durable_settlement() {
    let settle = Reply::Body {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({
            "success": true,
            "transaction": "tx_fixture_1",
            "network": "base-sepolia",
            "amount": "10000",
            "payer": "0x2222222222222222222222222222222222222222"
        }))
        .unwrap(),
        delay_ms: 0,
    };
    let fixture = service_lifecycle_fixture(None, settle).await;

    let decision = authorize_fixture(&fixture).await;

    let sbproxy_billing::AuthorizationDecision::Settled(receipt) = decision else {
        panic!("payment did not settle");
    };
    assert_eq!(receipt.provider_reference, "tx_fixture_1");
    assert_eq!(
        *fixture.calls.lock().unwrap(),
        [
            "https://facilitator.example/base/verify",
            "https://facilitator.example/base/settle",
        ]
    );
    assert_eq!(
        *fixture.observer.events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Succeeded,
            ),
            (
                PaymentLifecyclePhase::Settle,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Settle,
                PaymentLifecycleOutcome::Succeeded,
            ),
        ]
    );
}

/// The events one authorization emits, verify leg through settle leg.
fn legs(
    settle_outcome: PaymentLifecycleOutcome,
) -> [(PaymentLifecyclePhase, PaymentLifecycleOutcome); 4] {
    [
        (
            PaymentLifecyclePhase::Verify,
            PaymentLifecycleOutcome::Started,
        ),
        (
            PaymentLifecyclePhase::Verify,
            PaymentLifecycleOutcome::Succeeded,
        ),
        (
            PaymentLifecyclePhase::Settle,
            PaymentLifecycleOutcome::Started,
        ),
        (PaymentLifecyclePhase::Settle, settle_outcome),
    ]
}

#[tokio::test]
async fn a_settle_answering_five_hundred_lands_on_the_reconciliation_queue() {
    // The whole seam for the unknown class, not just the settler's return
    // value. The dispatch stamp is committed, the facilitator answers 500
    // with a body saying `success: false`, and the durable record must
    // stay open and claimable rather than asserting that no funds moved.
    let settle = Reply::Body {
        status: 500,
        body: body("settle_rejection"),
        delay_ms: 0,
    };
    let fixture = service_lifecycle_fixture(None, settle).await;

    let decision = authorize_fixture(&fixture).await;

    // Fail closed to the payer, but as "outstanding", never as "refused".
    assert!(matches!(
        decision,
        sbproxy_billing::AuthorizationDecision::Unavailable { .. }
    ));
    // `IntentStatus::Terminal` asserts that no funds moved. Nothing here
    // proved that, so the intent may not carry it.
    assert_eq!(
        fixture.intent_status().await,
        IntentStatus::NeedsReconciliation
    );
    // And it is on the queue, so a sweep will keep asking. An ambiguous
    // settle that leaves no claimable row is unreconcilable forever.
    assert_eq!(
        fixture.reconciliation_queue().await,
        [fixture.intent_id.as_str()]
    );
    assert_eq!(
        *fixture.observer.events.lock().unwrap(),
        legs(PaymentLifecycleOutcome::Ambiguous)
    );
}

#[tokio::test]
async fn a_two_hundred_refusal_still_closes_the_intent_terminal() {
    // The counterpart, and the reason the fix is a status test rather
    // than "treat every settle failure as unknown": a facilitator that
    // answers 200 in its own protocol saying the payment is not valid has
    // refused it, and that answer still closes the record and bills the
    // payer nothing.
    let fixture = service_lifecycle_fixture(None, ok("settle_rejection")).await;

    let decision = authorize_fixture(&fixture).await;

    assert!(matches!(
        decision,
        sbproxy_billing::AuthorizationDecision::PaymentRequired(_)
    ));
    assert_eq!(fixture.intent_status().await, IntentStatus::Terminal);
    // Nothing to reconcile: the facilitator already answered.
    assert!(fixture.reconciliation_queue().await.is_empty());
    assert_eq!(
        *fixture.observer.events.lock().unwrap(),
        legs(PaymentLifecycleOutcome::Rejected)
    );
}

#[tokio::test]
async fn a_verify_rejection_never_prepares_or_calls_settle() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let stamps = Arc::new(AtomicUsize::new(0));
    let settler = settler(
        ok("verify_rejection"),
        ok("settle_response"),
        calls.clone(),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: stamps.clone(),
                    delay_ms: 0,
                },
            )
            .await,
        "an invalid payment must not authorize",
    );
    assert_eq!(error, BillingError::ProviderRejected);
    assert_eq!(
        calls.lock().unwrap().clone(),
        vec!["https://facilitator.example/base/verify".to_string()]
    );
    assert_eq!(stamps.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_settle_without_an_authoritative_success_does_not_authorize() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let settler = settler(
        ok("verify_response"),
        ok("settle_ambiguous"),
        calls.clone(),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: Arc::new(AtomicUsize::new(0)),
                    delay_ms: 0,
                },
            )
            .await,
        "an ambiguous settle must not authorize",
    );
    assert_eq!(error, BillingError::NeedsReconciliation);
    // Still exactly two calls. Nothing retried and nothing guessed.
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn an_authoritative_settle_failure_is_terminal_not_ambiguous() {
    let settler = settler(
        ok("verify_response"),
        ok("settle_rejection"),
        Arc::new(Mutex::new(Vec::new())),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: Arc::new(AtomicUsize::new(0)),
                    delay_ms: 0,
                },
            )
            .await,
        "an authoritative settle failure must not authorize",
    );
    assert_eq!(error, BillingError::ProviderRejected);
}

/// Runs one authorization whose settle answers with `status` and the
/// named fixture body, and returns the error and the number of stamps.
async fn settle_answered(status: u16, fixture: &str) -> (BillingError, usize, usize) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let stamps = Arc::new(AtomicUsize::new(0));
    let settler = settler(
        ok("verify_response"),
        Reply::Body {
            status,
            body: body(fixture),
            delay_ms: 0,
        },
        calls.clone(),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: stamps.clone(),
                    delay_ms: 0,
                },
            )
            .await,
        "a settle outside 2xx must not authorize",
    );
    let total_calls = calls.lock().unwrap().len();
    (error, stamps.load(Ordering::SeqCst), total_calls)
}

#[tokio::test]
async fn a_five_hundred_saying_success_false_is_not_an_authoritative_refusal() {
    // The facilitator broadcast the settlement and then its own handler
    // faulted, so its framework rendered the house error envelope, which
    // for an API whose responses always carry `success` says `false`. The
    // funds may well have moved. Reading the body here would close the
    // attempt terminal and assert that they did not.
    let (error, stamps, calls) = settle_answered(500, "settle_rejection").await;

    assert_eq!(error, BillingError::NeedsReconciliation);
    assert_eq!(stamps, 1);
    // Still exactly two calls. Nothing retried and no second facilitator.
    assert_eq!(calls, 2);
}

#[tokio::test]
async fn a_foreign_error_envelope_never_speaks_for_the_facilitator() {
    // A 502 from a gateway in front of the facilitator. The hazard is
    // real rather than theoretical: `SettleResponse` is deliberately not
    // `deny_unknown_fields`, so this body decodes as a settle answer and
    // its `success: false` would read as the facilitator's own verdict.
    let decoded: SettleResponse =
        decode_x402_json(&body("settle_foreign_error")).expect("the foreign envelope decodes");
    assert_eq!(decoded.success, Some(false));

    // The status is what says it is not the facilitator's verdict.
    let (error, stamps, _calls) = settle_answered(502, "settle_foreign_error").await;

    assert_eq!(error, BillingError::NeedsReconciliation);
    assert_eq!(stamps, 1);
}

#[tokio::test]
async fn a_conflict_status_saying_success_false_is_not_an_authoritative_refusal() {
    // The status where reading the body is exactly backwards: a 409 on a
    // replayed idempotency key means the facilitator has seen this
    // settlement before, which is evidence that funds moved rather than
    // that they did not.
    let (error, stamps, _calls) = settle_answered(409, "settle_rejection").await;

    assert_eq!(error, BillingError::NeedsReconciliation);
    assert_eq!(stamps, 1);
}

#[tokio::test]
async fn a_five_hundred_saying_success_true_is_not_a_settlement() {
    // The other direction of the same rule. A body claiming success is no
    // more authoritative outside 2xx than a body claiming refusal, and it
    // must never mint a receipt.
    let (error, stamps, _calls) = settle_answered(503, "settle_response").await;

    assert_eq!(error, BillingError::NeedsReconciliation);
    assert_eq!(stamps, 1);
}

#[tokio::test]
async fn connection_loss_after_settle_dispatch_needs_reconciliation() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let stamps = Arc::new(AtomicUsize::new(0));
    let settler = settler(
        ok("verify_response"),
        Reply::Fail(TransportFailure::Connection),
        calls.clone(),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: stamps.clone(),
                    delay_ms: 0,
                },
            )
            .await,
        "a lost connection after dispatch must not authorize",
    );
    assert_eq!(error, BillingError::NeedsReconciliation);
    assert_eq!(stamps.load(Ordering::SeqCst), 1);
    // No second facilitator, and no retry of the settle.
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_verify_timeout_fails_closed_before_any_dispatch() {
    let stamps = Arc::new(AtomicUsize::new(0));
    let settler = settler(
        Reply::Body {
            status: 200,
            body: body("verify_response"),
            delay_ms: VERIFY_MS * 4,
        },
        ok("settle_response"),
        Arc::new(Mutex::new(Vec::new())),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: stamps.clone(),
                    delay_ms: 0,
                },
            )
            .await,
        "a verify timeout must not authorize",
    );
    assert_eq!(error, BillingError::ProviderTimeout);
    assert_eq!(stamps.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn blowing_the_total_deadline_after_dispatch_needs_reconciliation() {
    // The durable stamp itself is slow enough to exhaust the total
    // deadline. The settle may or may not have happened, so the only
    // safe answer is reconciliation.
    let settler = settler(
        ok("verify_response"),
        ok("settle_response"),
        Arc::new(Mutex::new(Vec::new())),
        breaker(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: Arc::new(AtomicUsize::new(0)),
                    delay_ms: TOTAL_MS * 4,
                },
            )
            .await,
        "a blown total deadline must not authorize",
    );
    assert_eq!(error, BillingError::NeedsReconciliation);
}

#[tokio::test]
async fn an_open_breaker_returns_immediately_with_no_call() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let shared = breaker();
    // Three consecutive transport failures is the configured threshold.
    for _ in 0..3 {
        shared.record_transport_failure(1_800_000_000_000);
    }
    let settler = settler(
        ok("verify_response"),
        ok("settle_response"),
        calls.clone(),
        shared.clone(),
    );
    let required = frozen_required();
    let payload = frozen_payload();

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: Arc::new(AtomicUsize::new(0)),
                    delay_ms: 0,
                },
            )
            .await,
        "an open breaker must not authorize",
    );
    assert_eq!(error, BillingError::ProviderUnavailable);
    assert!(calls.lock().unwrap().is_empty());

    // Once the window elapses, the half-open probe is admitted and one
    // success closes the breaker again.
    let settlement = settler
        .authorize_and_settle(
            X402AuthorizationRequest {
                challenge: challenge(&required),
                payload: &payload,
                now_ms: 1_800_000_000_100,
            },
            &RecordingGate {
                stamps: Arc::new(AtomicUsize::new(0)),
                delay_ms: 0,
            },
        )
        .await
        .expect("the half-open probe is admitted");
    assert_eq!(settlement.receipt.rail.as_str(), "x402");
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_mismatched_payload_never_reaches_the_facilitator() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let settler = settler(
        ok("verify_response"),
        ok("settle_response"),
        calls.clone(),
        breaker(),
    );
    let required = frozen_required();
    let mut document = part("payment_payload");
    document["accepted"]["amount"] = serde_json::json!("1");
    let payload: PaymentPayload =
        decode_x402_json(&serde_json::to_vec(&document).unwrap()).expect("it still parses");

    let error = expect_error(
        settler
            .authorize_and_settle(
                X402AuthorizationRequest {
                    challenge: challenge(&required),
                    payload: &payload,
                    now_ms: 1_800_000_000_000,
                },
                &RecordingGate {
                    stamps: Arc::new(AtomicUsize::new(0)),
                    delay_ms: 0,
                },
            )
            .await,
        "a cheaper obligation must not reach the facilitator",
    );
    assert_eq!(error, BillingError::RequirementMismatch);
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn an_ambiguous_settle_has_no_status_query_to_ask() {
    let settler = settler(
        ok("verify_response"),
        ok("settle_response"),
        Arc::new(Mutex::new(Vec::new())),
        breaker(),
    );
    assert_eq!(settler.query_attempt(), X402QueryResult::Unsupported);
    // The only two URLs this adapter can ever build.
    assert_eq!(
        settler.endpoints().verify_url(),
        "https://facilitator.example/base/verify"
    );
    assert_eq!(
        settler.endpoints().settle_url(),
        "https://facilitator.example/base/settle"
    );
}

#[test]
fn fallback_happens_at_challenge_time_and_only_at_challenge_time() {
    let first = FacilitatorEntry {
        endpoints: FacilitatorEndpoints::from_api_root("https://one.example/api").unwrap(),
        breaker: FacilitatorBreaker::new(1, 100, 1).unwrap(),
    };
    let second = FacilitatorEntry {
        endpoints: FacilitatorEndpoints::from_api_root("https://two.example/api").unwrap(),
        breaker: FacilitatorBreaker::new(1, 100, 1).unwrap(),
    };
    let pool = FacilitatorPool::new(vec![first, second]).expect("a non-empty pool");

    assert_eq!(
        pool.select_for_challenge(0).unwrap().endpoints.root(),
        "https://one.example/api"
    );
    pool.entries()[0].breaker.record_transport_failure(0);
    assert_eq!(
        pool.select_for_challenge(0).unwrap().endpoints.root(),
        "https://two.example/api"
    );

    // A signed requirement resolves to exactly the facilitator it
    // named, open breaker or not. Fallback is a challenge-time decision.
    let bound = pool
        .entry_for_root("https://one.example/api")
        .expect("the named facilitator is found");
    assert_eq!(
        bound.endpoints.verify_url(),
        "https://one.example/api/verify"
    );
    assert!(pool.entry_for_root("https://three.example/api").is_none());
}

#[test]
fn a_settle_response_round_trips_through_the_response_header() {
    let response: SettleResponse =
        decode_x402_json(&body("settle_response")).expect("the frozen settle response decodes");
    let encoded = encode_x402_header(&response).expect("it encodes");
    let decoded: SettleResponse =
        sbproxy_billing::x402::decode_x402_header(&encoded).expect("it decodes");
    assert_eq!(decoded.success, Some(true));
    assert_eq!(decoded.network.as_deref(), Some("eip155:84532"));
}
