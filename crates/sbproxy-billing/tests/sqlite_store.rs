//! Durable transitions, across two handles on one database file.
//!
//! Every test here uses an on-disk database and, where it matters, two
//! independent [`SqliteSettlementStore`] handles, because the guarantees this
//! crate makes are about two processes rather than two tasks.

#![cfg(feature = "runtime")]

use std::sync::Arc;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::registry::{RailRegistry, UsageEvent};
use sbproxy_billing::sqlite::{SqliteSettlementStore, SqliteStoreConfig};
use sbproxy_billing::store::{BillingClock, ProofReservation, SharedSettlementStore};
use sbproxy_billing::types::{
    provider_idempotency_key, AttemptOperation, AttemptStatus, FailureCategory, IntentStatus,
    PaymentProof, SafeFailure, SettlementRail, SettlementReceipt, SignedPaymentRequirement,
};

mod common;

use common::{
    expect_error, sample_draft, sign_draft, FixtureAdapter, FixtureReporter, FixtureState,
    TestClock,
};

/// A fixed instant every test starts from.
const START_MS: i64 = 1_700_000_000_000;

/// A challenge expiry comfortably after the start instant.
const EXPIRY_MS: i64 = 1_700_000_600_000;

/// Opens a store handle on `path` driven by `clock`.
fn handle(path: &std::path::Path, clock: &Arc<TestClock>) -> SharedSettlementStore {
    let store = SqliteSettlementStore::open_with_config(
        path,
        SqliteStoreConfig {
            lease_ttl_ms: 30_000,
            busy_timeout_ms: 5_000,
        },
    )
    .expect("open settlement store");
    store
        .with_clock(Arc::clone(clock) as Arc<dyn BillingClock>)
        .shared()
}

/// Creates a finalized challenge and returns its intent identifier.
async fn finalized_intent(
    store: &SharedSettlementStore,
    tenant: &str,
    requirement_id: &str,
    request_key: &str,
) -> (String, SignedPaymentRequirement) {
    let draft = sample_draft(tenant, requirement_id, EXPIRY_MS);
    let digest = draft.digest().expect("draft digest");
    let created = store
        .create_or_get_challenge(&draft, digest, request_key, None)
        .await
        .expect("create challenge");
    let signed = sign_draft(&draft, Some("pi_handle"));
    store
        .finalize_requirement(&created.intent_id, &signed)
        .await
        .expect("finalize requirement");
    (created.intent_id, signed)
}

/// Prepares and dispatches a settle attempt, returning the leased attempt.
async fn dispatched_attempt(
    store: &SharedSettlementStore,
    intent_id: &str,
    proof_digest: &[u8; 32],
    generation: u32,
    now_ms: i64,
) -> sbproxy_billing::store::PreparedAttempt {
    let key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        generation,
        Some(proof_digest),
    );
    let prepared = store
        .prepare_attempt(
            intent_id,
            AttemptOperation::Settle,
            &key,
            Some("pi_handle"),
            now_ms,
        )
        .await
        .expect("prepare attempt");
    store
        .mark_dispatch_started(prepared.attempt_id(), prepared.lease_token(), now_ms)
        .await
        .expect("stamp dispatch");
    prepared
}

#[tokio::test]
async fn one_idempotency_key_creates_one_intent() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let first = handle(&path, &clock);
    let second = handle(&path, &clock);

    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);
    let digest = draft.digest().expect("draft digest");

    let created = first
        .create_or_get_challenge(&draft, digest, "request-key", None)
        .await
        .expect("create challenge");
    assert!(created.created);
    assert_eq!(created.status, IntentStatus::Pending);

    // A second handle sees the same row rather than making another one.
    let resumed = second
        .create_or_get_challenge(&draft, digest, "request-key", None)
        .await
        .expect("resume challenge");
    assert!(!resumed.created);
    assert_eq!(resumed.intent_id, created.intent_id);
    assert!(resumed.receipt.is_none());
}

#[tokio::test]
async fn a_reused_key_with_different_terms_is_rejected() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);
    let digest = draft.digest().expect("draft digest");
    store
        .create_or_get_challenge(&draft, digest, "request-key", None)
        .await
        .expect("create challenge");

    let other = sample_draft("tenant-1", "req-2", EXPIRY_MS);
    let other_digest = other.digest().expect("draft digest");
    let error = expect_error(
        store
            .create_or_get_challenge(&other, other_digest, "request-key", None)
            .await,
        "different terms under one key must fail",
    );
    assert_eq!(error, BillingError::IntentConflict);

    // A digest that does not describe the draft it arrives with is refused
    // before any row is touched.
    let error = expect_error(
        store
            .create_or_get_challenge(&draft, other_digest, "another-key", None)
            .await,
        "a mismatched draft digest must fail",
    );
    assert_eq!(error, BillingError::DigestMismatch);
}

#[tokio::test]
async fn one_quote_nonce_binds_one_requirement() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let (_intent, signed) = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;

    let second_draft = sample_draft("tenant-1", "req-2", EXPIRY_MS);
    let second_digest = second_draft.digest().expect("draft digest");
    let created = store
        .create_or_get_challenge(&second_draft, second_digest, "second-key", None)
        .await
        .expect("create second challenge");

    // A second requirement presenting the first one's quote token collides on
    // the unique nonce, so one signed quote can only ever bind once.
    let mut stolen = sign_draft(&second_draft, Some("pi_handle_2"));
    stolen.quote_token = signed.quote_token.clone();
    let error = expect_error(
        store
            .finalize_requirement(&created.intent_id, &stolen)
            .await,
        "a reused quote token must fail",
    );
    assert_eq!(error, BillingError::IntentConflict);
}

#[tokio::test]
async fn finalizing_twice_requires_the_same_final_value() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);
    let digest = draft.digest().expect("draft digest");
    let created = store
        .create_or_get_challenge(&draft, digest, "request-key", None)
        .await
        .expect("create challenge");

    let signed = sign_draft(&draft, Some("pi_handle"));
    store
        .finalize_requirement(&created.intent_id, &signed)
        .await
        .expect("finalize");
    store
        .finalize_requirement(&created.intent_id, &signed)
        .await
        .expect("finalizing the same value again is a no-op");

    let different = sign_draft(&draft, Some("pi_other_handle"));
    let error = expect_error(
        store
            .finalize_requirement(&created.intent_id, &different)
            .await,
        "a second final requirement must fail",
    );
    assert_eq!(error, BillingError::IntentConflict);
}

#[tokio::test]
async fn a_proof_digest_is_unique_per_tenant() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let (first_intent, _) = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;
    let (second_intent, _) = finalized_intent(&store, "tenant-1", "req-2", "second-key").await;

    let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
    let digest = proof.digest();

    assert_eq!(
        store
            .reserve_proof(&first_intent, digest, START_MS)
            .await
            .expect("reserve"),
        ProofReservation::Reserved
    );
    // The same intent presenting the same credential is a resume.
    assert_eq!(
        store
            .reserve_proof(&first_intent, digest, START_MS)
            .await
            .expect("resume"),
        ProofReservation::AlreadyReservedForIntent
    );
    // Another intent presenting it is a replay.
    assert_eq!(
        expect_error(
            store.reserve_proof(&second_intent, digest, START_MS).await,
            "a replayed credential must fail",
        ),
        BillingError::ProofReplayed
    );
    // The first intent presenting a different credential is a conflict.
    let other = PaymentProof::new("Payment", "spt_other".to_string()).expect("proof");
    assert_eq!(
        expect_error(
            store
                .reserve_proof(&first_intent, other.digest(), START_MS)
                .await,
            "a second credential on one intent must fail",
        ),
        BillingError::ProofConflict
    );
}

#[tokio::test]
async fn no_state_but_succeeded_yields_an_access_receipt() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let (intent_id, _) = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;
    let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
    let digest = proof.digest();
    store
        .reserve_proof(&intent_id, digest, START_MS)
        .await
        .expect("reserve");

    // Pending.
    assert!(store
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .is_none());

    let prepared = dispatched_attempt(&store, &intent_id, &digest, 0, START_MS).await;

    // Processing, with a dispatch outstanding.
    assert!(store
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .is_none());

    store
        .mark_needs_reconciliation(
            prepared.attempt_id(),
            prepared.lease_token(),
            SafeFailure::category(FailureCategory::Ambiguous, true),
        )
        .await
        .expect("reconcile");

    // NeedsReconciliation, which is the state most likely to be mistaken for
    // success. It authorizes nothing.
    let intent = store
        .load_intent(&intent_id)
        .await
        .expect("read")
        .expect("intent");
    assert_eq!(intent.status, IntentStatus::NeedsReconciliation);
    assert!(store
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .is_none());
}

#[tokio::test]
async fn a_dispatched_attempt_can_never_return_to_retry_wait() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let (intent_id, _) = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;
    let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
    let digest = proof.digest();
    store
        .reserve_proof(&intent_id, digest, START_MS)
        .await
        .expect("reserve");

    let key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        0,
        Some(&digest),
    );
    let prepared = store
        .prepare_attempt(&intent_id, AttemptOperation::Settle, &key, None, START_MS)
        .await
        .expect("prepare");

    // Before the stamp a retry is safe.
    store
        .mark_retry_wait_before_dispatch(
            prepared.attempt_id(),
            prepared.lease_token(),
            START_MS + 1_000,
            SafeFailure::category(FailureCategory::Unavailable, true),
        )
        .await
        .expect("retry wait");

    let resumed = store
        .prepare_attempt(&intent_id, AttemptOperation::Settle, &key, None, START_MS)
        .await
        .expect("resume");
    assert!(!resumed.created, "a pre-dispatch retry reuses the attempt");
    assert_eq!(resumed.provider_idempotency_key(), key);
    assert_eq!(resumed.attempt.attempt_generation, 0);

    store
        .mark_dispatch_started(resumed.attempt_id(), resumed.lease_token(), START_MS)
        .await
        .expect("stamp dispatch");

    // After the stamp it is not.
    assert_eq!(
        expect_error(
            store
                .mark_retry_wait_before_dispatch(
                    resumed.attempt_id(),
                    resumed.lease_token(),
                    START_MS + 1_000,
                    SafeFailure::category(FailureCategory::Timeout, true),
                )
                .await,
            "a dispatched attempt must not retry",
        ),
        BillingError::AlreadyDispatched
    );
}

#[tokio::test]
async fn a_receipt_is_unique_by_intent_and_provider_reference() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let first = handle(&path, &clock);
    let second = handle(&path, &clock);

    let (intent_id, _) = finalized_intent(&first, "tenant-1", "req-1", "request-key").await;
    let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
    let digest = proof.digest();
    first
        .reserve_proof(&intent_id, digest, START_MS)
        .await
        .expect("reserve");

    let prepared = dispatched_attempt(&first, &intent_id, &digest, 0, START_MS).await;

    // The first handle's write is outstanding, so the second handle is told to
    // reconcile rather than handed a fresh attempt and a fresh key.
    assert_eq!(
        expect_error(
            second
                .prepare_attempt(
                    &intent_id,
                    AttemptOperation::Settle,
                    "sbp1_other",
                    None,
                    START_MS,
                )
                .await,
            "an outstanding write must block a second writer",
        ),
        BillingError::NeedsReconciliation
    );

    let receipt =
        SettlementReceipt::new(&intent_id, SettlementRail::X402, "exact", "tx_1", START_MS)
            .expect("receipt");
    first
        .mark_succeeded(
            prepared.attempt_id(),
            prepared.lease_token(),
            receipt.clone(),
        )
        .await
        .expect("settle");

    let committed = second
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .expect("receipt");
    assert_eq!(committed, receipt);

    // A settled intent refuses a second attempt outright.
    assert_eq!(
        expect_error(
            second
                .prepare_attempt(
                    &intent_id,
                    AttemptOperation::Settle,
                    "sbp1_other",
                    None,
                    START_MS,
                )
                .await,
            "a settled intent must not settle again",
        ),
        BillingError::InvalidStateTransition {
            from: IntentStatus::Succeeded,
            to: IntentStatus::Processing,
        }
    );

    // One provider reference cannot settle two intents on one rail.
    let (other_intent, _) = finalized_intent(&first, "tenant-1", "req-2", "second-key").await;
    let other_proof = PaymentProof::new("Payment", "spt_other".to_string()).expect("proof");
    let other_digest = other_proof.digest();
    first
        .reserve_proof(&other_intent, other_digest, START_MS)
        .await
        .expect("reserve");
    let other_attempt = dispatched_attempt(&first, &other_intent, &other_digest, 0, START_MS).await;
    let duplicate = SettlementReceipt::new(
        &other_intent,
        SettlementRail::X402,
        "exact",
        "tx_1",
        START_MS,
    )
    .expect("receipt");
    let error = expect_error(
        first
            .mark_succeeded(
                other_attempt.attempt_id(),
                other_attempt.lease_token(),
                duplicate,
            )
            .await,
        "a reused provider reference must fail",
    );
    assert!(matches!(error, BillingError::Storage(_)), "{error}");
}

#[tokio::test]
async fn a_stale_lease_forks_on_the_dispatch_stamp() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    // One intent stops before its dispatch, the other after it.
    let (undispatched, _) = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;
    let (dispatched, _) = finalized_intent(&store, "tenant-1", "req-2", "second-key").await;

    let quiet = PaymentProof::new("Payment", "spt_quiet".to_string()).expect("proof");
    let loud = PaymentProof::new("Payment", "spt_loud".to_string()).expect("proof");
    store
        .reserve_proof(&undispatched, quiet.digest(), START_MS)
        .await
        .expect("reserve");
    store
        .reserve_proof(&dispatched, loud.digest(), START_MS)
        .await
        .expect("reserve");

    let quiet_key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        0,
        Some(&quiet.digest()),
    );
    let quiet_attempt = store
        .prepare_attempt(
            &undispatched,
            AttemptOperation::Settle,
            &quiet_key,
            None,
            START_MS,
        )
        .await
        .expect("prepare");
    let loud_attempt = dispatched_attempt(&store, &dispatched, &loud.digest(), 0, START_MS).await;

    clock.advance(60_000);
    let recovery = store
        .recover_stale_leases(clock.now_ms(), 100)
        .await
        .expect("recover");
    assert_eq!(recovery.returned_to_retry_wait, 1);
    assert_eq!(recovery.moved_to_needs_reconciliation, 1);

    let quiet_row = store
        .load_attempt(quiet_attempt.attempt_id())
        .await
        .expect("read")
        .expect("attempt");
    assert_eq!(quiet_row.status, AttemptStatus::RetryWait);
    assert!(quiet_row.dispatch_started_at_ms.is_none());

    let loud_row = store
        .load_attempt(loud_attempt.attempt_id())
        .await
        .expect("read")
        .expect("attempt");
    assert_eq!(loud_row.status, AttemptStatus::NeedsReconciliation);
    assert!(loud_row.is_dispatched_unresolved());

    assert_eq!(
        store
            .load_intent(&dispatched)
            .await
            .expect("read")
            .expect("intent")
            .status,
        IntentStatus::NeedsReconciliation
    );
    assert!(store
        .load_access_receipt(&dispatched)
        .await
        .expect("read")
        .is_none());
}

#[tokio::test]
async fn expired_challenges_are_swept_but_outstanding_writes_are_not() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let (quiet, _) = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;
    let (busy, _) = finalized_intent(&store, "tenant-1", "req-2", "second-key").await;

    // The busy intent has a challenge preparation still outstanding, so its
    // expiry must not be swept away underneath the provider.
    let key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::PrepareChallenge,
        "tenant-1",
        "req-2",
        0,
        None,
    );
    let attempt = store
        .prepare_attempt(
            &busy,
            AttemptOperation::PrepareChallenge,
            &key,
            None,
            START_MS,
        )
        .await
        .expect("prepare");
    store
        .mark_dispatch_started(attempt.attempt_id(), attempt.lease_token(), START_MS)
        .await
        .expect("stamp");

    clock.advance(700_000);
    let expired = store
        .expire_stale_challenges(clock.now_ms(), 100)
        .await
        .expect("expire");
    assert_eq!(expired, 1);
    assert_eq!(
        store
            .load_intent(&quiet)
            .await
            .expect("read")
            .expect("intent")
            .status,
        IntentStatus::Terminal
    );
    assert_eq!(
        store
            .load_intent(&busy)
            .await
            .expect("read")
            .expect("intent")
            .status,
        IntentStatus::Pending
    );
}

#[tokio::test]
async fn usage_events_deduplicate_and_never_touch_an_intent() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let event = UsageEvent {
        reporter: "fixture_meter".to_string(),
        usage_identifier: "usage-1".to_string(),
        tenant_id: "tenant-1".to_string(),
        origin_id: "origin-1".to_string(),
        event_name: "tokens".to_string(),
        quantity: 42,
        occurred_at_ms: START_MS,
        attributes: Default::default(),
    };
    assert!(store.enqueue_usage_event(&event).await.expect("queue"));
    assert!(
        !store.enqueue_usage_event(&event).await.expect("queue"),
        "one identifier queues once",
    );

    let claimed = store
        .claim_usage_events(clock.now_ms(), 30_000, 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert!(claimed[0].provider_idempotency_key.starts_with("sbp1_"));
    assert!(!claimed[0].previously_dispatched);

    // A claimed event is not claimed twice.
    let again = store
        .claim_usage_events(clock.now_ms(), 30_000, 10)
        .await
        .expect("claim");
    assert!(again.is_empty());
}

#[tokio::test]
async fn duplicate_registrations_fail_in_separate_namespaces() {
    let state = FixtureState::new();
    let mut registry = RailRegistry::new();

    registry
        .register_adapter(FixtureAdapter::new(
            SettlementRail::X402,
            Arc::clone(&state),
        ))
        .expect("first adapter");
    assert_eq!(
        expect_error(
            registry.register_adapter(FixtureAdapter::new(
                SettlementRail::X402,
                Arc::clone(&state)
            )),
            "a duplicate rail must fail",
        ),
        BillingError::DuplicateAdapter(SettlementRail::X402)
    );
    // A different rail is a different slot.
    registry
        .register_adapter(FixtureAdapter::new(
            SettlementRail::Stripe,
            Arc::clone(&state),
        ))
        .expect("second adapter");

    // Reporter names live in their own namespace, so a reporter may share a
    // name with a rail without colliding.
    registry
        .register_reporter(FixtureReporter::new(Arc::clone(&state)))
        .expect("first reporter");
    assert_eq!(
        expect_error(
            registry.register_reporter(FixtureReporter::new(Arc::clone(&state))),
            "a duplicate reporter must fail",
        ),
        BillingError::DuplicateReporter
    );

    assert_eq!(
        registry.rails(),
        vec![SettlementRail::Stripe, SettlementRail::X402]
    );
    assert_eq!(registry.reporter_names(), vec!["fixture_meter".to_string()]);
    assert_eq!(
        expect_error(
            registry.require_adapter(SettlementRail::LightningLnd),
            "an uncompiled rail must fail",
        ),
        BillingError::AdapterNotRegistered(SettlementRail::LightningLnd)
    );
}

// --- WOR-2238: the unresolved-intent guard is scoped to a payer ---

/// Drives one intent for `origin-1` `/paid` into `NeedsReconciliation`.
///
/// That is the only state the guard reads, and the only one nothing ever
/// expires, so it is what the query has to be exercised against.
async fn stranded_intent(
    store: &SharedSettlementStore,
    requirement_id: &str,
    request_key: &str,
    payer_hash: Option<&str>,
) -> String {
    let draft = sample_draft("tenant-1", requirement_id, EXPIRY_MS);
    let digest = draft.digest().expect("draft digest");
    let created = store
        .create_or_get_challenge(&draft, digest, request_key, payer_hash)
        .await
        .expect("create challenge");
    let signed = sign_draft(&draft, Some("pi_handle"));
    store
        .finalize_requirement(&created.intent_id, &signed)
        .await
        .expect("finalize requirement");

    // A distinct proof per intent, so two stranded intents in one test do
    // not collide on the per-tenant proof digest or on the provider
    // idempotency key derived from it.
    let proof = PaymentProof::new("Payment", format!("spt_{request_key}")).expect("proof");
    let proof_digest = proof.digest();
    store
        .reserve_proof(&created.intent_id, proof_digest, START_MS)
        .await
        .expect("reserve");
    let prepared = dispatched_attempt(store, &created.intent_id, &proof_digest, 0, START_MS).await;
    store
        .mark_needs_reconciliation(
            prepared.attempt_id(),
            prepared.lease_token(),
            SafeFailure::category(FailureCategory::Ambiguous, true),
        )
        .await
        .expect("reconcile");
    created.intent_id
}

/// The guard's answer for one payer.
async fn guard(store: &SharedSettlementStore, payer_hash: Option<&str>) -> Option<String> {
    store
        .unresolved_intent_for_route("tenant-1", "origin-1", "/paid", payer_hash)
        .await
        .expect("guard query answers")
}

#[tokio::test]
async fn an_unresolved_intent_only_withholds_from_the_payer_it_belongs_to() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let stuck = stranded_intent(&store, "req-a", "key-a", Some("payer-a")).await;

    assert_eq!(
        guard(&store, Some("payer-a")).await,
        Some(stuck.clone()),
        "the payer whose money may already be gone keeps waiting",
    );
    assert_eq!(
        guard(&store, Some("payer-b")).await,
        None,
        "a different payer owes this intent nothing and is still billable",
    );
    assert_eq!(
        guard(&store, None).await,
        None,
        "WOR-2302: an attributed intent no longer withholds from unidentified callers",
    );
}

#[tokio::test]
async fn an_intent_with_no_payer_scope_withholds_from_everyone() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    // `None` is what a row written before this landed carries, and what a
    // row minted for an unidentifiable caller carries now. Both mean the
    // store cannot say whose payment is stuck, so it has to assume anyone's.
    let legacy = stranded_intent(&store, "req-legacy", "key-legacy", None).await;

    for payer in [Some("payer-a"), Some("payer-b"), None] {
        assert_eq!(
            guard(&store, payer).await,
            Some(legacy.clone()),
            "a legacy row names nobody, so it withholds from everybody",
        );
    }

    // A second handle on the same file re-runs the open path, which is what
    // proves the schema-2 `ALTER TABLE` is guarded by the stamped version
    // rather than attempted on every open.
    let reopened = handle(&path, &clock);
    assert_eq!(guard(&reopened, Some("payer-a")).await, Some(legacy));
}

#[tokio::test]
async fn attributing_an_x402_payer_stops_unidentified_callers_waiting_on_it() {
    // WOR-2302: after `/verify` names a payer, the stranded intent is no
    // longer "could be anyone". Other anonymous x402 callers of the same
    // route are billable. The first-ever stall (the row still NULL) still
    // withholds everyone, which `an_intent_with_no_payer_scope_withholds_from_everyone`
    // pins.
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let stuck = stranded_intent(&store, "req-x402", "key-x402", None).await;
    let hash = sbproxy_billing::x402_facilitator_payer_hash("tenant-1", "0xabc");
    store
        .attribute_payer_hash(&stuck, &hash)
        .await
        .expect("attribute");

    assert_eq!(
        guard(&store, None).await,
        None,
        "an attributed x402 intent must not stall other anonymous payers",
    );
    assert_eq!(
        guard(&store, Some(&hash)).await,
        Some(stuck.clone()),
        "the hashed payer still waits on their own stuck payment",
    );
    store
        .attribute_payer_hash(&stuck, "another-hash")
        .await
        .expect("restamp is a no-op");
    assert_eq!(
        guard(&store, Some(&hash)).await,
        Some(stuck),
        "a later attribute must not move the row onto a different payer",
    );
}

// --- WOR-2317: the unattributable hold has a deadline ---
//
// The guard above is right and, for an intent nobody can be attributed to,
// unbounded: on a rail with no status endpoint nothing ever resolves it, so
// one stuck payment takes a route's revenue to zero for as long as the
// provider stays unreachable. The deadline is the challenge's own expiry plus
// a grace window, because the quote token signs `exp` from that same column
// and the verifier refuses an expired one: past it the stranded payer cannot
// redeem this intent whatever the funds did, so the hold protects nobody.

/// The grace window past a challenge's expiry these tests use.
const GRACE_MS: i64 = 900_000;

/// Runs the deadline sweep once and reports how many intents it retired.
async fn strand_sweep(store: &SharedSettlementStore, clock: &Arc<TestClock>) -> u64 {
    store
        .strand_unattributable_intents(clock.now_ms(), GRACE_MS, 100)
        .await
        .expect("deadline sweep runs")
}

/// The durable state of one intent.
async fn intent_status(store: &SharedSettlementStore, intent_id: &str) -> IntentStatus {
    store
        .load_intent(intent_id)
        .await
        .expect("read")
        .expect("intent")
        .status
}

#[tokio::test]
async fn an_unattributable_intent_stops_withholding_once_past_its_deadline() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let stuck = stranded_intent(&store, "req-a", "key-a", None).await;
    assert_eq!(
        guard(&store, None).await,
        Some(stuck.clone()),
        "the whole route is withheld while the hold stands",
    );

    // The challenge has expired, and the grace window has not. Nothing moves:
    // the deadline is anchored on the payment, so the reconciliation sweep
    // gets its full run at resolving this honestly first.
    clock.advance(EXPIRY_MS - clock.now_ms() + 1);
    assert_eq!(strand_sweep(&store, &clock).await, 0);
    assert_eq!(
        intent_status(&store, &stuck).await,
        IntentStatus::NeedsReconciliation,
    );
    assert_eq!(
        guard(&store, None).await,
        Some(stuck.clone()),
        "inside the grace window the route is still withheld",
    );

    // Past it.
    clock.advance(GRACE_MS);
    assert_eq!(strand_sweep(&store, &clock).await, 1);
    assert_eq!(intent_status(&store, &stuck).await, IntentStatus::Stranded);
    assert_eq!(
        guard(&store, None).await,
        None,
        "a retired hold stops gating the route, for every caller",
    );
    assert_eq!(
        guard(&store, Some("payer-a")).await,
        None,
        "and for an identified one too",
    );

    // Exactly once per intent: the sweep matches `NeedsReconciliation`, and
    // this row is not in it any more.
    assert_eq!(
        strand_sweep(&store, &clock).await,
        0,
        "one payment ages out one time, however often the worker sweeps",
    );
    assert_eq!(intent_status(&store, &stuck).await, IntentStatus::Stranded);
}

#[tokio::test]
async fn a_payer_scoped_intent_has_no_deadline() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let stuck = stranded_intent(&store, "req-a", "key-a", Some("payer-a")).await;

    // Far past any deadline an unattributable intent would have.
    clock.advance(EXPIRY_MS - clock.now_ms() + GRACE_MS * 10);
    assert_eq!(
        strand_sweep(&store, &clock).await,
        0,
        "an intent that names its payer withholds from that payer alone, which \
         is a bounded cost, and that payer is somebody this deployment can \
         concretely owe money to",
    );
    assert_eq!(
        intent_status(&store, &stuck).await,
        IntentStatus::NeedsReconciliation,
    );

    // WOR-2238's answers, unchanged by the deadline existing.
    assert_eq!(
        guard(&store, Some("payer-a")).await,
        Some(stuck.clone()),
        "the payer whose money may already be gone keeps waiting",
    );
    assert_eq!(
        guard(&store, Some("payer-b")).await,
        None,
        "a different payer is still billable",
    );
    assert_eq!(
        guard(&store, None).await,
        None,
        "WOR-2302: an attributed hold no longer stalls unidentified callers",
    );
}

#[tokio::test]
async fn a_retired_hold_is_not_a_settlement() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let stuck = stranded_intent(&store, "req-a", "key-a", None).await;
    clock.advance(EXPIRY_MS - clock.now_ms() + GRACE_MS);
    assert_eq!(strand_sweep(&store, &clock).await, 1);

    let intent = store
        .load_intent(&stuck)
        .await
        .expect("read")
        .expect("intent");
    assert_eq!(intent.status, IntentStatus::Stranded);
    assert!(
        !intent.authorizes_origin(),
        "giving up on a payment must never be a way of admitting one",
    );
    assert!(
        store
            .load_access_receipt(&stuck)
            .await
            .expect("read")
            .is_none(),
        "the one read the request path authorizes on must stay empty",
    );

    // Not discarded either. The attempt is still on the reconciliation queue,
    // so the sweep keeps asking the provider what happened.
    let claimed = store
        .claim_reconciliation(clock.now_ms(), 30_000, 10)
        .await
        .expect("claim");
    assert_eq!(
        claimed.len(),
        1,
        "a retired intent's dispatch is still outstanding and still queryable",
    );
    assert_eq!(claimed[0].attempt.intent_id, stuck);
    assert_eq!(
        claimed[0].attempt.status,
        AttemptStatus::NeedsReconciliation,
    );
}

#[tokio::test]
async fn a_lease_sweep_does_not_resurrect_a_retired_hold() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);

    let stuck = stranded_intent(&store, "req-a", "key-a", None).await;
    clock.advance(EXPIRY_MS - clock.now_ms() + GRACE_MS);
    assert_eq!(strand_sweep(&store, &clock).await, 1);

    // Lease recovery propagates attempt state onto intents, and this intent's
    // attempt is deliberately still `needs_reconciliation`. Without the
    // exclusion for `Stranded` the next sweep would drag the intent back and
    // the deadline would hold for exactly one worker interval.
    store
        .recover_stale_leases(clock.now_ms(), 100)
        .await
        .expect("recover leases");
    assert_eq!(intent_status(&store, &stuck).await, IntentStatus::Stranded);
    assert_eq!(guard(&store, None).await, None);
}

#[cfg(feature = "recovery-crypto")]
mod recovery {
    use super::*;

    use sbproxy_billing::recovery_crypto::{RecoveryBinding, RecoveryCipher, MAX_RECOVERY_AGE_MS};

    /// The exact request bytes a replay would have to reproduce.
    const PLAINTEXT: &[u8] = b"amount=1000&currency=usd&secret_marker=NEVER_ON_DISK";

    fn binding(attempt_id: &str) -> RecoveryBinding {
        RecoveryBinding::new(
            SettlementRail::Stripe,
            attempt_id,
            AttemptOperation::Settle,
            "sbp1_key",
            [7u8; 32],
        )
    }

    #[tokio::test]
    async fn an_envelope_round_trips_only_under_its_exact_binding() {
        let cipher = RecoveryCipher::new("key-1", &[3u8; 32]).expect("cipher");
        let binding = binding("sbpa_1");
        let envelope = cipher
            .seal(&binding, PLAINTEXT, START_MS, 60_000)
            .expect("seal");

        let opened = cipher.open(&envelope, &binding, START_MS).expect("open");
        assert_eq!(opened.as_slice(), PLAINTEXT);

        // A different attempt, operation, key, or amount cannot open it.
        let other = RecoveryBinding::new(
            SettlementRail::Stripe,
            "sbpa_1",
            AttemptOperation::Settle,
            "sbp1_key",
            [8u8; 32],
        );
        assert_eq!(
            expect_error(
                cipher.open(&envelope, &other, START_MS),
                "a different binding must not open the envelope",
            ),
            BillingError::RecoveryEnvelopeAuthFailed
        );

        // A tampered ciphertext fails closed.
        let mut tampered = envelope.clone();
        tampered.ciphertext[0] ^= 0xFF;
        assert_eq!(
            expect_error(
                cipher.open(&tampered, &binding, START_MS),
                "a tampered envelope must not open",
            ),
            BillingError::RecoveryEnvelopeAuthFailed
        );

        // A different key fails closed, and never falls back to a new key.
        let rotated = RecoveryCipher::new("key-2", &[4u8; 32]).expect("cipher");
        assert_eq!(
            expect_error(
                rotated.open(&envelope, &binding, START_MS),
                "a rotated key must not open an old envelope",
            ),
            BillingError::RecoveryKeyMismatch
        );

        // Past the hard expiry the provider is no longer documented to
        // deduplicate, so a replay would be a second charge.
        assert_eq!(
            expect_error(
                cipher.open(&envelope, &binding, START_MS + 60_001),
                "an expired envelope must not open",
            ),
            BillingError::RecoveryEnvelopeExpired
        );
        assert!(!cipher.is_replayable(&envelope, START_MS + MAX_RECOVERY_AGE_MS));
        assert_eq!(
            expect_error(
                RecoveryCipher::new("key-1", &[0u8; 16]),
                "a short key must fail",
            ),
            BillingError::RecoveryKeyLength
        );
    }

    #[tokio::test]
    async fn envelope_plaintext_never_reaches_the_database() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("settlement.sqlite3");
        let clock = TestClock::new(START_MS);
        let store = handle(&path, &clock);

        let (intent_id, _) = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;
        let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
        let digest = proof.digest();
        store
            .reserve_proof(&intent_id, digest, START_MS)
            .await
            .expect("reserve");
        let prepared = dispatched_attempt(&store, &intent_id, &digest, 0, START_MS).await;

        let cipher = RecoveryCipher::new("key-1", &[3u8; 32]).expect("cipher");
        let binding = binding(prepared.attempt_id());
        let envelope = cipher
            .seal(&binding, PLAINTEXT, START_MS, 60_000)
            .expect("seal");
        store
            .put_recovery_envelope(&envelope)
            .await
            .expect("store envelope");

        // Neither the record nor the database file may contain the plaintext.
        let rendered = format!("{envelope:?}");
        assert!(!rendered.contains("NEVER_ON_DISK"), "{rendered}");
        assert_no_plaintext(directory.path(), b"NEVER_ON_DISK");

        let loaded = store
            .load_recovery_envelope(prepared.attempt_id())
            .await
            .expect("read")
            .expect("envelope");
        assert_eq!(loaded, envelope);

        // Recording the answer purges the envelope, and so does expiry.
        clock.advance(1);
        store
            .mark_succeeded(
                prepared.attempt_id(),
                prepared.lease_token(),
                SettlementReceipt::new(
                    &intent_id,
                    SettlementRail::X402,
                    "exact",
                    "tx_1",
                    clock.now_ms(),
                )
                .expect("receipt"),
            )
            .await
            .expect("settle");
        assert!(store
            .load_recovery_envelope(prepared.attempt_id())
            .await
            .expect("read")
            .is_none());
    }

    /// Asserts no file under `directory` contains `needle`.
    fn assert_no_plaintext(directory: &std::path::Path, needle: &[u8]) {
        for entry in std::fs::read_dir(directory).expect("read dir") {
            let entry = entry.expect("dir entry");
            if !entry.path().is_file() {
                continue;
            }
            let bytes = std::fs::read(entry.path()).expect("read file");
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "plaintext reached {}",
                entry.path().display(),
            );
        }
    }
}

/// WOR-2626: the settlement database and both WAL sidecars must be
/// owner-only.
///
/// The database is pre-created world-readable rather than left to the
/// ambient umask, so this is red before the fix whatever the runner's
/// umask is: without the pre-creation step in `open_with_config` the
/// mode stays `0o644`, and SQLite copies the main database's mode onto
/// the `-wal` and `-shm` files it opens, so all three land wide.
///
/// The sidecars are the point. They are the only place a committed but
/// uncheckpointed settlement row lives, and nothing else in the code
/// path can reach them: SQLite creates them, so the only lever is the
/// mode of the file it derives them from.
#[cfg(unix)]
#[tokio::test]
async fn the_database_and_its_wal_sidecars_are_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    drop(std::fs::File::create(&path).expect("pre-create the database"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("loosen the pre-created database");

    let clock = TestClock::new(START_MS);
    let store = handle(&path, &clock);
    // A committed write, so the WAL is really in play and both
    // sidecars exist while the handle is open.
    let _ = finalized_intent(&store, "tenant-1", "req-1", "request-key").await;

    for suffix in ["", "-wal", "-shm"] {
        let candidate = directory.path().join(format!("settlement.sqlite3{suffix}"));
        let mode = std::fs::metadata(&candidate)
            .unwrap_or_else(|error| panic!("stat {}: {error}", candidate.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{} is {mode:o}, not owner-only",
            candidate.display()
        );
    }
    drop(store);
}
