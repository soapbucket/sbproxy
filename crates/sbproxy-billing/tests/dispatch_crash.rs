//! A process that stops between the dispatch stamp and the response.
//!
//! This is the test the whole dispatch gate exists for. Handle A stamps a
//! dispatch, the provider records the call, and then A disappears without
//! writing down what happened. Handle B opens the same database and must reach
//! exactly one conclusion: a write may have landed, so ask the provider rather
//! than send another one.

#![cfg(feature = "runtime")]

use std::sync::Arc;
use std::time::Duration;

use sbproxy_billing::dispatch::{DispatchContext, DispatchOutcome};
use sbproxy_billing::registry::{AuthoritativePayment, PaymentMethodAdapter, RailRegistry};
use sbproxy_billing::service::BillingService;
use sbproxy_billing::sqlite::SqliteSettlementStore;
use sbproxy_billing::store::{
    BillingClock, ReconciliationOutcome, SettlementStore, SharedSettlementStore,
};
use sbproxy_billing::types::{
    provider_idempotency_key, AttemptOperation, AttemptStatus, IntentStatus, PaymentProof,
    SettlementRail,
};

mod common;

use common::{
    sample_draft, sign_draft, Behavior, FixtureAdapter, FixtureState, QueryPlan, TestClock,
};

/// A fixed instant every test starts from.
const START_MS: i64 = 1_700_000_000_000;

/// A challenge expiry comfortably after the start instant.
const EXPIRY_MS: i64 = 1_700_000_600_000;

/// Opens a store handle on `path` driven by `clock`.
fn handle(path: &std::path::Path, clock: &Arc<TestClock>) -> SharedSettlementStore {
    SqliteSettlementStore::open(path)
        .expect("open settlement store")
        .with_clock(Arc::clone(clock) as Arc<dyn BillingClock>)
        .shared()
}

/// Builds a service over one handle and one fixture rail.
fn service(
    store: &SharedSettlementStore,
    clock: &Arc<TestClock>,
    state: &Arc<FixtureState>,
) -> Arc<BillingService> {
    let mut registry = RailRegistry::new();
    registry
        .register_adapter(FixtureAdapter::new(SettlementRail::X402, Arc::clone(state)))
        .expect("register adapter");
    Arc::new(
        BillingService::builder(Arc::clone(store))
            .adapters(registry)
            .clock(Arc::clone(clock) as Arc<dyn BillingClock>)
            .build(),
    )
}

/// Runs the crash: stamp a dispatch, let the provider see it, then vanish.
///
/// Returns the attempt identifier and the provider idempotency key that were
/// persisted before anything was sent.
async fn crash_after_dispatch(
    path: &std::path::Path,
    clock: &Arc<TestClock>,
    state: &Arc<FixtureState>,
) -> (String, String, String) {
    let store = handle(path, clock);
    let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);
    let digest = draft.digest().expect("draft digest");
    let created = store
        .create_or_get_challenge(&draft, digest, "request-key")
        .await
        .expect("create challenge");
    let signed = sign_draft(&draft, Some("pi_handle"));
    store
        .finalize_requirement(&created.intent_id, &signed)
        .await
        .expect("finalize");

    let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
    let proof_digest = proof.digest();
    store
        .reserve_proof(&created.intent_id, proof_digest, START_MS)
        .await
        .expect("reserve proof");

    let key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        0,
        Some(&proof_digest),
    );
    let prepared = store
        .prepare_attempt(
            &created.intent_id,
            AttemptOperation::Settle,
            &key,
            Some("pi_handle"),
            START_MS,
        )
        .await
        .expect("prepare attempt");

    let adapter = FixtureAdapter::new(SettlementRail::X402, Arc::clone(state));
    state.set_behavior(Behavior::Hang);
    let dispatch = DispatchContext::for_attempt(
        Arc::clone(&store),
        Arc::clone(clock) as Arc<dyn BillingClock>,
        prepared.clone(),
    );
    let payment = AuthoritativePayment {
        intent_id: created.intent_id.clone(),
        requirement: signed.requirement.clone(),
        requirement_digest: signed.requirement_digest,
        proof,
        now_ms: START_MS,
    };

    // The provider takes the call and this process never hears the answer.
    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        adapter.authorize_and_settle(payment, &dispatch),
    )
    .await;
    assert!(outcome.is_err(), "the fixture must not answer");
    assert_eq!(
        dispatch.outcome(),
        DispatchOutcome::Ambiguous,
        "a dropped future after a stamp is ambiguous",
    );

    // Everything this process knew goes away without a recorded response.
    let attempt_id = prepared.attempt_id().to_string();
    let intent_id = created.intent_id.clone();
    drop(dispatch);
    drop(prepared);
    drop(store);
    (intent_id, attempt_id, key)
}

#[tokio::test]
async fn a_lost_dispatch_becomes_reconciliation_and_never_a_second_write() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let state = FixtureState::new();

    let (intent_id, attempt_id, key) = crash_after_dispatch(&path, &clock, &state).await;
    assert_eq!(state.provider_writes(), 1, "the provider was called once");
    assert_eq!(state.settle_calls(), 1);

    // A different process opens the same database.
    let store = handle(&path, &clock);
    let service = service(&store, &clock, &state);

    clock.advance(60_000);
    let recovered = service.recover_leases(100).await.expect("recover leases");
    assert_eq!(recovered.moved_to_needs_reconciliation, 1);
    assert_eq!(recovered.returned_to_retry_wait, 0);

    let attempt = store
        .load_attempt(&attempt_id)
        .await
        .expect("read")
        .expect("attempt");
    assert_eq!(attempt.status, AttemptStatus::NeedsReconciliation);
    assert!(attempt.is_dispatched_unresolved());
    assert_eq!(
        store
            .load_intent(&intent_id)
            .await
            .expect("read")
            .expect("intent")
            .status,
        IntentStatus::NeedsReconciliation,
    );
    assert!(
        store
            .load_access_receipt(&intent_id)
            .await
            .expect("read")
            .is_none(),
        "no receipt exists before a provider proves one",
    );

    // A rail that cannot answer leaves the record exactly where it is.
    state.set_query_plan(QueryPlan::Unsupported);
    let claimed = store
        .claim_reconciliation(clock.now_ms(), 30_000, 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    let outcome = service
        .reconcile_attempt(claimed.into_iter().next().expect("claimed attempt"))
        .await
        .expect("reconcile");
    assert!(matches!(outcome, ReconciliationOutcome::Unresolved(_)));
    assert_eq!(
        store
            .load_intent(&intent_id)
            .await
            .expect("read")
            .expect("intent")
            .status,
        IntentStatus::NeedsReconciliation,
    );
    assert!(store
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .is_none());

    // The query used the persisted handle and the persisted key, and it did
    // not settle anything.
    assert_eq!(state.query_calls(), 1);
    assert_eq!(state.settle_calls(), 1, "recovery must never settle");
    assert_eq!(state.provider_writes(), 1, "recovery must never write");
    assert_eq!(
        state.queried_handles(),
        vec![Some("pi_handle".to_string())],
        "the query addresses the object the lost write may have created",
    );
    assert_eq!(state.keys(), vec![key.clone(), key.clone()]);

    // Only a provider proving success commits the receipt.
    state.set_query_plan(QueryPlan::Settled);
    let claimed = store
        .claim_reconciliation(clock.now_ms(), 30_000, 10)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    let outcome = service
        .reconcile_attempt(claimed.into_iter().next().expect("claimed attempt"))
        .await
        .expect("reconcile");
    assert!(matches!(outcome, ReconciliationOutcome::ProvenSucceeded(_)));

    let receipt = store
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .expect("receipt");
    assert_eq!(receipt.provider_reference, "pi_fixture_1");
    assert_eq!(
        store
            .load_intent(&intent_id)
            .await
            .expect("read")
            .expect("intent")
            .status,
        IntentStatus::Succeeded,
    );
    assert_eq!(state.settle_calls(), 1, "still exactly one settlement call");
    assert_eq!(
        state.provider_writes(),
        1,
        "still exactly one provider write"
    );
}

#[tokio::test]
async fn a_client_retry_during_reconciliation_sends_nothing() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let state = FixtureState::new();

    let (intent_id, _attempt_id, _key) = crash_after_dispatch(&path, &clock, &state).await;

    let store = handle(&path, &clock);
    clock.advance(60_000);
    store
        .recover_stale_leases(clock.now_ms(), 100)
        .await
        .expect("recover");

    // The client comes back while the write is still outstanding. Preparing a
    // new attempt here is exactly how a double charge happens.
    let key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        1,
        None,
    );
    let error = store
        .prepare_attempt(
            &intent_id,
            AttemptOperation::Settle,
            &key,
            None,
            clock.now_ms(),
        )
        .await
        .expect_err("an outstanding write must block a new attempt");
    assert!(matches!(
        error,
        sbproxy_billing::BillingError::InvalidStateTransition { .. }
            | sbproxy_billing::BillingError::NeedsReconciliation
    ));
    assert_eq!(state.provider_writes(), 1);
}

#[tokio::test]
async fn a_proven_non_dispatch_lets_the_next_attempt_use_a_new_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("settlement.sqlite3");
    let clock = TestClock::new(START_MS);
    let state = FixtureState::new();

    let (intent_id, _attempt_id, first_key) = crash_after_dispatch(&path, &clock, &state).await;

    let store = handle(&path, &clock);
    let service = service(&store, &clock, &state);
    clock.advance(60_000);
    service.recover_leases(100).await.expect("recover");

    // The provider proves the write never landed, which is the only thing that
    // may increase an attempt generation.
    state.set_query_plan(QueryPlan::NotDispatched);
    let claimed = store
        .claim_reconciliation(clock.now_ms(), 30_000, 10)
        .await
        .expect("claim");
    let outcome = service
        .reconcile_attempt(claimed.into_iter().next().expect("claimed attempt"))
        .await
        .expect("reconcile");
    assert!(matches!(
        outcome,
        ReconciliationOutcome::ProvenNotDispatched(_)
    ));
    assert_eq!(
        store
            .load_intent(&intent_id)
            .await
            .expect("read")
            .expect("intent")
            .status,
        IntentStatus::RetryWait,
    );

    let latest = store
        .latest_attempt(&intent_id, AttemptOperation::Settle)
        .await
        .expect("read")
        .expect("attempt");
    assert_eq!(latest.status, AttemptStatus::Terminal);

    let proof = PaymentProof::new("Payment", "spt_value".to_string()).expect("proof");
    let next_key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::Settle,
        "tenant-1",
        "req-1",
        1,
        Some(&proof.digest()),
    );
    assert_ne!(next_key, first_key, "a new generation is a new key");
    let prepared = store
        .prepare_attempt(
            &intent_id,
            AttemptOperation::Settle,
            &next_key,
            None,
            clock.now_ms(),
        )
        .await
        .expect("prepare a fresh attempt");
    assert!(prepared.created);
    assert_eq!(prepared.attempt.attempt_generation, 1);
    assert_eq!(prepared.provider_idempotency_key(), next_key);
}
