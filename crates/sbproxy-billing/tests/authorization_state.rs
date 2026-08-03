//! The authorization state table, enforced end to end.
//!
//! Every case here asserts the same four things about a non-success outcome:
//! the adapter reported no settlement, the origin callback never fired, the
//! decision was not a paid success, and no receipt exists. A payment either
//! reaches a durable `Succeeded` or the request does not reach the origin.

#![cfg(feature = "runtime")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::registry::RailRegistry;
use sbproxy_billing::service::{
    AuthorizationDecision, BillingService, PaymentProblemCode, RedemptionRequest, RequirementInput,
};
use sbproxy_billing::sqlite::SqliteSettlementStore;
use sbproxy_billing::store::{BillingClock, SharedSettlementStore};
use sbproxy_billing::types::{
    IntentStatus, PaymentProof, PaymentRequirement, SettlementRail, SignedPaymentRequirement,
};
use sbproxy_billing::{
    NoOpPaymentLifecycleObserver, PaymentLifecycleDecision, PaymentLifecycleEvent,
    PaymentLifecycleObserver, PaymentLifecycleOutcome, PaymentLifecyclePhase,
};

mod common;

use common::{
    sample_draft, sign_draft, Behavior, FixtureAdapter, FixtureSigner, FixtureState, TestClock,
};

/// A fixed instant every test starts from.
const START_MS: i64 = 1_700_000_000_000;

/// A challenge expiry comfortably after the start instant.
const EXPIRY_MS: i64 = 1_700_000_600_000;

/// Counts how many times a decision would have released the origin.
#[derive(Debug, Default)]
struct OriginGate {
    releases: AtomicUsize,
}

impl OriginGate {
    /// Records one decision and reports whether the origin was released.
    fn observe(&self, decision: &AuthorizationDecision) -> bool {
        if decision.authorizes_origin() {
            self.releases.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Returns how many times the origin was released.
    fn releases(&self) -> usize {
        self.releases.load(Ordering::SeqCst)
    }
}

/// One assembled world: a store, a service, and the fixture's recording state.
struct World {
    store: SharedSettlementStore,
    service: BillingService,
    state: Arc<FixtureState>,
    clock: Arc<TestClock>,
    gate: OriginGate,
    _directory: tempfile::TempDir,
}

impl World {
    /// Builds a world with a fixture x402 adapter and a fifty millisecond
    /// deadline, so a hanging provider does not slow the suite down.
    fn new() -> Self {
        Self::with_payment_observer(Arc::new(NoOpPaymentLifecycleObserver))
    }

    /// Builds a world with an explicit payment lifecycle observer.
    fn with_payment_observer(observer: Arc<dyn PaymentLifecycleObserver>) -> Self {
        Self::with_payment_observer_and_signer(observer, true)
    }

    /// Builds a world that can omit its signer to exercise a pre-provider
    /// challenge failure.
    fn with_payment_observer_and_signer(
        observer: Arc<dyn PaymentLifecycleObserver>,
        install_signer: bool,
    ) -> Self {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("settlement.sqlite3");
        let clock = TestClock::new(START_MS);
        let state = FixtureState::new();
        let store = SqliteSettlementStore::open(&path)
            .expect("open settlement store")
            .with_clock(Arc::clone(&clock) as Arc<dyn BillingClock>)
            .shared();

        let mut registry = RailRegistry::new();
        registry
            .register_adapter(FixtureAdapter::new(
                SettlementRail::X402,
                Arc::clone(&state),
            ))
            .expect("register adapter");
        let mut service = BillingService::builder(Arc::clone(&store))
            .adapters(registry)
            .clock(Arc::clone(&clock) as Arc<dyn BillingClock>)
            .payment_observer(observer)
            .deadline(Duration::from_millis(50))
            .expect("deadline inside the ceiling");
        if install_signer {
            service = service.signer(Arc::new(FixtureSigner));
        }
        let service = service.build();

        Self {
            store,
            service,
            state,
            clock,
            gate: OriginGate::default(),
            _directory: directory,
        }
    }

    /// Creates and finalizes one challenge, returning its signed requirement.
    async fn challenge(&self, requirement_id: &str, request_key: &str) -> SignedPaymentRequirement {
        let draft = sample_draft("tenant-1", requirement_id, EXPIRY_MS);
        let digest = draft.digest().expect("draft digest");
        let created = self
            .store
            .create_or_get_challenge(&draft, digest, request_key)
            .await
            .expect("create challenge");
        let signed = sign_draft(&draft, Some("pi_handle"));
        self.store
            .finalize_requirement(&created.intent_id, &signed)
            .await
            .expect("finalize");
        signed
    }

    /// Redeems a credential and records what the decision did to the origin.
    async fn redeem(
        &self,
        signed: &SignedPaymentRequirement,
        request_key: &str,
        credential: &str,
    ) -> AuthorizationDecision {
        let decision = self
            .service
            .authorize(RedemptionRequest {
                signed: signed.clone(),
                request_idempotency_key: request_key.to_string(),
                proof: PaymentProof::new("Payment", credential.to_string()).expect("proof"),
            })
            .await
            .expect("authorize");
        self.gate.observe(&decision);
        decision
    }

    /// Returns the durable state of one intent.
    async fn status(&self, request_key: &str) -> IntentStatus {
        let intent_id = sbproxy_billing::derive_intent_id("tenant-1", request_key);
        self.store
            .load_intent(&intent_id)
            .await
            .expect("read")
            .expect("intent")
            .status
    }

    /// Returns whether an access receipt exists for one request.
    async fn has_receipt(&self, request_key: &str) -> bool {
        let intent_id = sbproxy_billing::derive_intent_id("tenant-1", request_key);
        self.store
            .load_access_receipt(&intent_id)
            .await
            .expect("read")
            .is_some()
    }
}

#[derive(Default)]
struct RejectSettlementObserver {
    events: Mutex<Vec<(PaymentLifecyclePhase, PaymentLifecycleOutcome)>>,
}

#[derive(Default)]
struct RecordingObserver {
    events: Mutex<Vec<(PaymentLifecyclePhase, PaymentLifecycleOutcome)>>,
}

#[derive(Default)]
struct RejectChallengeObserver {
    events: Mutex<Vec<(PaymentLifecyclePhase, PaymentLifecycleOutcome)>>,
}

#[derive(Default)]
struct PayloadRecordingObserver {
    events: Mutex<Vec<PaymentLifecycleEvent>>,
}

#[async_trait::async_trait]
impl PaymentLifecycleObserver for PayloadRecordingObserver {
    async fn started(&self, event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision {
        self.events.lock().unwrap().push(event.clone());
        PaymentLifecycleDecision::Continue
    }

    fn terminal(&self, event: PaymentLifecycleEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[async_trait::async_trait]
impl PaymentLifecycleObserver for RejectChallengeObserver {
    async fn started(&self, event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision {
        self.events
            .lock()
            .unwrap()
            .push((event.phase(), event.outcome()));
        if event.phase() == PaymentLifecyclePhase::Challenge {
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
impl PaymentLifecycleObserver for RecordingObserver {
    async fn started(&self, event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision {
        self.events
            .lock()
            .unwrap()
            .push((event.phase(), event.outcome()));
        PaymentLifecycleDecision::Continue
    }

    fn terminal(&self, event: PaymentLifecycleEvent) {
        self.events
            .lock()
            .unwrap()
            .push((event.phase(), event.outcome()));
    }
}

#[async_trait::async_trait]
impl PaymentLifecycleObserver for RejectSettlementObserver {
    async fn started(&self, event: &PaymentLifecycleEvent) -> PaymentLifecycleDecision {
        self.events
            .lock()
            .unwrap()
            .push((event.phase(), event.outcome()));
        if event.phase() == PaymentLifecyclePhase::Settle {
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

#[tokio::test]
async fn a_committed_receipt_is_the_only_thing_that_opens_the_origin() {
    let world = World::new();
    let signed = world.challenge("req-1", "request-key").await;
    world.state.set_behavior(Behavior::Settle);

    let decision = world.redeem(&signed, "request-key", "spt_value").await;
    let AuthorizationDecision::Settled(receipt) = decision else {
        panic!("a settled payment must authorize");
    };
    assert_eq!(receipt.provider_reference, "pi_fixture_1");
    assert_eq!(world.gate.releases(), 1);
    assert_eq!(world.status("request-key").await, IntentStatus::Succeeded);
    assert!(world.has_receipt("request-key").await);
    assert_eq!(world.state.provider_writes(), 1);
}

#[tokio::test]
async fn started_settlement_rejection_prevents_provider_write() {
    let observer = Arc::new(RejectSettlementObserver::default());
    let world = World::with_payment_observer(observer.clone());
    let signed = world.challenge("req-1", "request-key").await;

    let decision = world
        .redeem(&signed, "request-key", "spt_secret_value")
        .await;

    assert!(matches!(
        decision,
        AuthorizationDecision::PaymentRequired(ref problem)
            if problem.code == PaymentProblemCode::Rejected
    ));
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.provider_writes(), 0);
    assert_eq!(world.gate.releases(), 0);
    assert_eq!(
        *observer.events.lock().unwrap(),
        [
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
async fn started_challenge_rejection_happens_before_intent_or_provider_write() {
    let observer = Arc::new(RejectChallengeObserver::default());
    let world = World::with_payment_observer(observer.clone());
    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);

    let error = match world
        .service
        .prepare_requirement(RequirementInput {
            draft,
            request_idempotency_key: "challenge-key".to_owned(),
        })
        .await
    {
        Ok(_) => panic!("challenge extension rejection must stop the response"),
        Err(error) => error,
    };

    assert_eq!(error, BillingError::ExtensionRejected);
    let intent_id = sbproxy_billing::derive_intent_id("tenant-1", "challenge-key");
    assert!(world.store.load_intent(&intent_id).await.unwrap().is_none());
    assert_eq!(world.state.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(world.state.provider_writes(), 0);
    assert_eq!(
        *observer.events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Challenge,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Challenge,
                PaymentLifecycleOutcome::Rejected,
            ),
        ]
    );
}

#[tokio::test]
async fn challenge_success_is_observed_after_durable_finalization() {
    let observer = Arc::new(RecordingObserver::default());
    let world = World::with_payment_observer(observer.clone());
    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);

    let prepared = world
        .service
        .prepare_requirement(RequirementInput {
            draft,
            request_idempotency_key: "challenge-key".to_owned(),
        })
        .await
        .expect("challenge prepares");

    let intent = world
        .store
        .load_intent(&prepared.intent_id)
        .await
        .unwrap()
        .unwrap();
    assert!(intent.requirement_digest.is_some());
    assert_eq!(world.state.provider_writes(), 1);
    assert_eq!(
        *observer.events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Challenge,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Challenge,
                PaymentLifecycleOutcome::Succeeded,
            ),
        ]
    );
}

#[tokio::test]
async fn challenge_failure_emits_terminal_without_provider_write() {
    let observer = Arc::new(RecordingObserver::default());
    let world = World::with_payment_observer_and_signer(observer.clone(), false);
    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);

    let error = match world
        .service
        .prepare_requirement(RequirementInput {
            draft,
            request_idempotency_key: "challenge-key".to_owned(),
        })
        .await
    {
        Ok(_) => panic!("a challenge without a signer must fail"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        BillingError::InvalidRequirement("requirement_signer_not_configured")
    );
    assert_eq!(world.state.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(world.state.provider_writes(), 0);
    assert_eq!(
        *observer.events.lock().unwrap(),
        [
            (
                PaymentLifecyclePhase::Challenge,
                PaymentLifecycleOutcome::Started,
            ),
            (
                PaymentLifecyclePhase::Challenge,
                PaymentLifecycleOutcome::Failed,
            ),
        ]
    );
}

#[tokio::test]
async fn settlement_terminal_events_follow_durable_outcomes() {
    for (behavior, expected) in [
        (Behavior::Settle, PaymentLifecycleOutcome::Succeeded),
        (Behavior::Reject, PaymentLifecycleOutcome::Rejected),
        (Behavior::BreakerOpen, PaymentLifecycleOutcome::Failed),
        (Behavior::Malformed, PaymentLifecycleOutcome::Ambiguous),
    ] {
        let observer = Arc::new(RecordingObserver::default());
        let world = World::with_payment_observer(observer.clone());
        let signed = world.challenge("req-1", "request-key").await;
        world.state.set_behavior(behavior);

        let _decision = world
            .redeem(&signed, "request-key", "spt_secret_value")
            .await;

        assert_eq!(
            *observer.events.lock().unwrap(),
            [
                (
                    PaymentLifecyclePhase::Settle,
                    PaymentLifecycleOutcome::Started,
                ),
                (PaymentLifecyclePhase::Settle, expected),
            ],
            "wrong lifecycle for {behavior:?}"
        );
    }
}

#[tokio::test]
async fn payment_lifecycle_events_exclude_credentials_and_recipient_data() {
    let observer = Arc::new(PayloadRecordingObserver::default());
    let world = World::with_payment_observer(observer.clone());
    let signed = world.challenge("req-1", "request-key").await;

    let _decision = world
        .redeem(&signed, "request-key", "PAYMENT-SIGNATURE_raw-proof-secret")
        .await;

    let events = observer.events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].rail(), "x402");
    assert_eq!(events[0].method(), Some("exact"));
    assert_eq!(events[0].network(), Some("base-sepolia"));
    assert_eq!(events[0].asset(), Some("usdc"));
    assert_eq!(events[0].amount_micros(), 10_000);
    assert_eq!(events[0].currency(), "USD");
    assert!(events[0].intent_id().starts_with("sbpi_"));
    assert_eq!(events[0].request_id(), Some("req-1"));
    assert_eq!(events[0].provider_reference(), None);
    assert_eq!(events[1].provider_reference(), Some("pi_fixture_1"));

    let exposed = format!("{events:?}");
    for forbidden in [
        "PAYMENT-SIGNATURE_raw-proof-secret",
        "0xrecipient",
        "facilitator.test.sbproxy.dev",
        "fixture-signature",
    ] {
        assert!(
            !exposed.contains(forbidden),
            "leaked {forbidden}: {exposed}"
        );
    }
}

#[tokio::test]
async fn no_failing_provider_outcome_opens_the_origin() {
    // Each case names the behavior, the state it must leave behind, and
    // whether the client is told to pay again or to wait.
    let cases = [
        (Behavior::Reject, IntentStatus::Terminal, false),
        (
            Behavior::NotSettled,
            IntentStatus::NeedsReconciliation,
            true,
        ),
        (Behavior::Malformed, IntentStatus::NeedsReconciliation, true),
        (Behavior::Hang, IntentStatus::NeedsReconciliation, true),
        (Behavior::BreakerOpen, IntentStatus::RetryWait, true),
        (
            Behavior::ForeignReceipt,
            IntentStatus::NeedsReconciliation,
            true,
        ),
    ];

    for (behavior, expected_status, expect_unavailable) in cases {
        let world = World::new();
        let signed = world.challenge("req-1", "request-key").await;
        world.state.set_behavior(behavior);

        let decision = world.redeem(&signed, "request-key", "spt_value").await;
        assert!(
            !decision.authorizes_origin(),
            "{behavior:?} must not authorize",
        );
        if expect_unavailable {
            assert!(
                matches!(decision, AuthorizationDecision::Unavailable { .. }),
                "{behavior:?} asserts nothing about the funds",
            );
        } else {
            assert!(
                matches!(decision, AuthorizationDecision::PaymentRequired(_)),
                "{behavior:?} is an authoritative refusal",
            );
        }

        assert_eq!(world.gate.releases(), 0, "{behavior:?} released the origin");
        assert_eq!(
            world.status("request-key").await,
            expected_status,
            "{behavior:?} left the wrong durable state",
        );
        assert!(
            !world.has_receipt("request-key").await,
            "{behavior:?} produced a receipt",
        );
    }
}

#[tokio::test]
async fn a_credential_can_never_create_a_challenge() {
    let world = World::new();
    // A perfectly well formed requirement that was never persisted.
    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);
    let signed = sign_draft(&draft, Some("pi_handle"));

    let decision = world.redeem(&signed, "never-issued", "spt_value").await;
    let AuthorizationDecision::PaymentRequired(problem) = decision else {
        panic!("a missing challenge must be a refusal");
    };
    assert_eq!(problem.code, PaymentProblemCode::ChallengeMissing);
    assert_eq!(world.state.settle_calls(), 0, "no provider was contacted");
    assert_eq!(world.gate.releases(), 0);
}

#[tokio::test]
async fn an_unfinalized_or_expired_challenge_fails_before_the_provider() {
    let world = World::new();

    // Persisted but never finalized.
    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);
    let digest = draft.digest().expect("draft digest");
    world
        .store
        .create_or_get_challenge(&draft, digest, "unfinalized")
        .await
        .expect("create challenge");
    let signed = sign_draft(&draft, Some("pi_handle"));
    let decision = world.redeem(&signed, "unfinalized", "spt_one").await;
    let AuthorizationDecision::PaymentRequired(problem) = decision else {
        panic!("an unfinalized challenge must be a refusal");
    };
    assert_eq!(problem.code, PaymentProblemCode::ChallengeNotFinalized);

    // Finalized, then left too long.
    let expired = world.challenge("req-2", "expired").await;
    world.clock.advance(700_000);
    let decision = world.redeem(&expired, "expired", "spt_two").await;
    let AuthorizationDecision::PaymentRequired(problem) = decision else {
        panic!("an expired challenge must be a refusal");
    };
    assert_eq!(problem.code, PaymentProblemCode::ChallengeExpired);

    assert_eq!(world.state.settle_calls(), 0, "no provider was contacted");
    assert_eq!(world.gate.releases(), 0);
}

#[tokio::test]
async fn a_stranded_payment_waits_however_old_its_challenge_is() {
    // WOR-2230. Nothing expires an intent whose settle attempt is
    // outstanding: `expire_stale_challenges` sweeps `Pending` only, and skips
    // any intent with a dispatched, unanswered attempt. So the challenge's own
    // expiry is the only clock that moves here, and reading it first turned
    // the 503 into a 402 `challenge_expired`. The payer, whose money may
    // already have gone, was then handed a fresh invoice for the same content.
    let world = World::new();
    let signed = world.challenge("req-1", "request-key").await;
    world.state.set_behavior(Behavior::NotSettled);

    // The payer retries a little early. The rail verifies and does not
    // settle, which is exactly the state that must not be retried from here.
    let early = world.redeem(&signed, "request-key", "spt_value").await;
    assert!(
        matches!(early, AuthorizationDecision::Unavailable { .. }),
        "an outstanding write asserts nothing about the funds",
    );
    assert_eq!(
        world.status("request-key").await,
        IntentStatus::NeedsReconciliation,
    );

    // The payer pays. The provider stays unreachable, and the challenge ages
    // out underneath both facts.
    world.clock.advance(700_000);
    assert!(
        signed.requirement.draft.is_expired(world.clock.now_ms()),
        "the challenge has to be expired for this to test anything",
    );

    let stranded = world.redeem(&signed, "request-key", "spt_value").await;
    assert!(
        matches!(stranded, AuthorizationDecision::Unavailable { .. }),
        "a stranded payment waits however old its challenge is; a refusal here \
         sends the payer back for a second invoice",
    );
    assert_eq!(world.gate.releases(), 0);
    assert!(!world.has_receipt("request-key").await);
    assert_eq!(
        world.state.settle_calls(),
        1,
        "the stranded intent was never dispatched again",
    );
}

#[tokio::test]
async fn a_refused_payment_that_aged_out_still_reads_as_expired() {
    // The other half of the ordering WOR-2230 touched, pinned so a later
    // reorder has to argue with it. The sweep collapses an expired `Pending`
    // intent into `Terminal` with an `Expired` category, so the wall clock is
    // the only thing that can tell a challenge that simply aged out from a
    // payment a provider refused. Expiry therefore outranks `Terminal`, and
    // only the reconciliation branch moved above it.
    let world = World::new();
    let signed = world.challenge("req-1", "request-key").await;
    world.state.set_behavior(Behavior::Reject);

    let refused = world.redeem(&signed, "request-key", "spt_value").await;
    assert!(matches!(refused, AuthorizationDecision::PaymentRequired(_)));
    assert_eq!(world.status("request-key").await, IntentStatus::Terminal);

    world.clock.advance(700_000);
    let expired = world.redeem(&signed, "request-key", "spt_value").await;
    let AuthorizationDecision::PaymentRequired(problem) = expired else {
        panic!("an expired challenge must be a refusal");
    };
    assert_eq!(problem.code, PaymentProblemCode::ChallengeExpired);
    assert_eq!(world.gate.releases(), 0);
}

#[tokio::test]
async fn a_requirement_that_was_not_advertised_is_refused() {
    let world = World::new();
    let signed = world.challenge("req-1", "request-key").await;

    // Same intent, different provider handle, so a different final digest.
    let mut tampered = signed.clone();
    tampered.requirement = PaymentRequirement {
        draft: signed.requirement.draft.clone(),
        provider_handle: Some("pi_attacker".to_string()),
    };
    tampered.requirement_digest = tampered.requirement.digest().expect("digest");
    tampered.quote_token = FixtureSigner::token_for(&tampered.requirement_digest);

    let decision = world.redeem(&tampered, "request-key", "spt_value").await;
    let AuthorizationDecision::PaymentRequired(problem) = decision else {
        panic!("a substituted requirement must be a refusal");
    };
    assert_eq!(problem.code, PaymentProblemCode::RequirementMismatch);
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.status("request-key").await, IntentStatus::Pending);
}

#[tokio::test]
async fn a_repeat_of_a_settled_request_returns_the_stored_receipt() {
    let world = World::new();
    let signed = world.challenge("req-1", "request-key").await;
    world.state.set_behavior(Behavior::Settle);

    let first = world.redeem(&signed, "request-key", "spt_value").await;
    let second = world.redeem(&signed, "request-key", "spt_value").await;
    assert_eq!(first, second, "a repeat returns the same receipt");
    assert_eq!(
        world.state.settle_calls(),
        1,
        "a repeat must not settle again",
    );
    assert_eq!(world.state.provider_writes(), 1);
}

#[tokio::test]
async fn a_credential_cannot_be_replayed_onto_another_intent() {
    let world = World::new();
    let first = world.challenge("req-1", "request-key").await;
    let second = world.challenge("req-2", "second-key").await;
    world.state.set_behavior(Behavior::Settle);

    let decision = world.redeem(&first, "request-key", "spt_value").await;
    assert!(decision.authorizes_origin());

    let replay = world.redeem(&second, "second-key", "spt_value").await;
    let AuthorizationDecision::PaymentRequired(problem) = replay else {
        panic!("a replayed credential must be a refusal");
    };
    assert_eq!(problem.code, PaymentProblemCode::ProofReplayed);
    assert_eq!(world.gate.releases(), 1, "one payment, one release");
    assert_eq!(world.state.settle_calls(), 1);
    assert!(!world.has_receipt("second-key").await);
}

#[tokio::test]
async fn two_simultaneous_retries_settle_once() {
    let world = Arc::new(World::new());
    let signed = world.challenge("req-1", "request-key").await;
    world.state.set_behavior(Behavior::Settle);

    let left = {
        let world = Arc::clone(&world);
        let signed = signed.clone();
        async move { world.redeem(&signed, "request-key", "spt_value").await }
    };
    let right = {
        let world = Arc::clone(&world);
        let signed = signed.clone();
        async move { world.redeem(&signed, "request-key", "spt_value").await }
    };
    let (left, right) = tokio::join!(left, right);

    // One provider write, whichever task got there first, and every permission
    // that came back names that one settlement.
    assert_eq!(world.state.provider_writes(), 1);
    assert_eq!(world.state.settle_calls(), 1);
    for decision in [&left, &right] {
        if let AuthorizationDecision::Settled(receipt) = decision {
            assert_eq!(receipt.provider_reference, "pi_fixture_1");
        }
    }
    assert!(
        left.authorizes_origin() || right.authorizes_origin(),
        "one of the two retries must have settled",
    );
    assert_eq!(world.status("request-key").await, IntentStatus::Succeeded);
}

#[tokio::test]
async fn the_authorization_deadline_has_a_hard_ceiling() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let store = SqliteSettlementStore::open(&path)
        .expect("open settlement store")
        .shared();
    let error = BillingService::builder(store)
        .deadline(Duration::from_millis(2_001))
        .err()
        .expect("an over-long deadline must be refused");
    assert_eq!(error, BillingError::DeadlineTooLong);
}
