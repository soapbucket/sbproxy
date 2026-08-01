//! Reconciliation is a read, and only a provider's proof settles anything.
//!
//! Every test here starts from the one state that cannot resolve itself: a
//! write was dispatched and no authoritative response was recorded. From
//! there, the rules the durable model has to keep are all negative ones.
//!
//! - A rail that cannot answer leaves the attempt outstanding. It does not
//!   become a retry and it does not become a success.
//! - A dispatched attempt never returns to normal settlement, so the client
//!   coming back with the same credential sends nothing.
//! - A proven failure refuses the request and keeps refusing it.
//! - A proven settlement, and nothing else, lets a later retry through, and
//!   it does so by reading a committed receipt rather than by trusting the
//!   query's return value.
//!
//! The fixture adapter counts settlement calls and guarded provider writes
//! separately, so each test can assert the thing that is easy to lose in a
//! refactor: reconciliation asked a question and did not move any money.

#![cfg(feature = "runtime")]

use std::sync::Arc;
use std::time::Duration;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::registry::RailRegistry;
use sbproxy_billing::service::{AuthorizationDecision, BillingService, RedemptionRequest};
use sbproxy_billing::sqlite::SqliteSettlementStore;
use sbproxy_billing::store::{
    BillingClock, PreparedAttempt, SettlementStore, SharedSettlementStore,
};
use sbproxy_billing::types::{
    provider_idempotency_key, AttemptOperation, IntentStatus, PaymentProof,
    PaymentRequirementDraft, SettlementRail,
};
use sbproxy_billing::worker::{SettlementWorker, WorkerConfig};

mod common;

use common::{
    expect_error, sample_draft, sign_draft, FixtureAdapter, FixtureState, QueryPlan, TestClock,
};

/// A fixed instant every test starts from.
const START_MS: i64 = 1_700_000_000_000;

/// A challenge expiry comfortably after the start instant.
const EXPIRY_MS: i64 = 1_700_000_600_000;

/// The client idempotency key that addresses the durable intent.
const REQUEST_KEY: &str = "request-key";

/// The credential the client presents, and re-presents on every retry.
const CREDENTIAL: &str = "credential-value";

/// The provider handle the challenge persisted before any write.
const PROVIDER_HANDLE: &str = "pi_handle";

/// One assembled world with a finalized challenge already in the store.
struct World {
    store: SharedSettlementStore,
    service: Arc<BillingService>,
    state: Arc<FixtureState>,
    clock: Arc<TestClock>,
    draft: PaymentRequirementDraft,
    intent_id: String,
    _directory: tempfile::TempDir,
}

impl World {
    /// Builds a world whose challenge is created, finalized, and signed.
    async fn new() -> Self {
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
        let service = Arc::new(
            BillingService::builder(Arc::clone(&store))
                .adapters(registry)
                .clock(Arc::clone(&clock) as Arc<dyn BillingClock>)
                .signer(Arc::new(common::FixtureSigner))
                .build(),
        );

        let draft = sample_draft("tenant-1", "req-1", EXPIRY_MS);
        let digest = draft.digest().expect("draft digest");
        let created = store
            .create_or_get_challenge(&draft, digest, REQUEST_KEY)
            .await
            .expect("create challenge");
        let signed = sign_draft(&draft, Some(PROVIDER_HANDLE));
        store
            .finalize_requirement(&created.intent_id, &signed)
            .await
            .expect("finalize");

        Self {
            store,
            service,
            state,
            clock,
            draft,
            intent_id: created.intent_id,
            _directory: directory,
        }
    }

    /// Builds a worker with a test-sized configuration.
    fn worker(&self) -> SettlementWorker {
        SettlementWorker::new(
            Arc::clone(&self.service),
            WorkerConfig {
                tick_interval_ms: 5,
                lease_ttl_ms: 30_000,
                reconciliation_batch: 8,
                expiry_batch: 8,
                usage_batch: 8,
                lease_batch: 8,
                shutdown_deadline_ms: 2_000,
            },
        )
        .expect("build worker")
    }

    /// Reserves the proof, prepares a settle attempt, and stamps dispatch.
    ///
    /// The dispatch stamp is the whole point: after it commits, nothing may
    /// conclude the write did not happen without asking the provider.
    async fn dispatched_attempt(&self) -> PreparedAttempt {
        let proof = PaymentProof::new("Payment", CREDENTIAL.to_string()).expect("proof");
        let digest = proof.digest();
        self.store
            .reserve_proof(&self.intent_id, digest, self.clock.now_ms())
            .await
            .expect("reserve proof");
        let key = provider_idempotency_key(
            SettlementRail::X402,
            AttemptOperation::Settle,
            "tenant-1",
            CREDENTIAL,
            0,
            Some(&digest),
        );
        let prepared = self
            .store
            .prepare_attempt(
                &self.intent_id,
                AttemptOperation::Settle,
                &key,
                Some(PROVIDER_HANDLE),
                self.clock.now_ms(),
            )
            .await
            .expect("prepare attempt");
        self.store
            .mark_dispatch_started(
                prepared.attempt_id(),
                prepared.lease_token(),
                self.clock.now_ms(),
            )
            .await
            .expect("stamp dispatch");
        prepared
    }

    /// Presents the credential again, exactly as a client retry would.
    async fn authorize(&self) -> AuthorizationDecision {
        let proof = PaymentProof::new("Payment", CREDENTIAL.to_string()).expect("proof");
        self.service
            .authorize(RedemptionRequest {
                signed: sign_draft(&self.draft, Some(PROVIDER_HANDLE)),
                request_idempotency_key: REQUEST_KEY.to_string(),
                proof,
            })
            .await
            .expect("authorize")
    }

    /// The durable state of the intent.
    async fn status(&self) -> IntentStatus {
        self.store
            .load_intent(&self.intent_id)
            .await
            .expect("read")
            .expect("intent")
            .status
    }

    /// Whether a receipt that authorizes origin access exists.
    async fn has_access_receipt(&self) -> bool {
        self.store
            .load_access_receipt(&self.intent_id)
            .await
            .expect("read")
            .is_some()
    }
}

#[tokio::test]
async fn a_rail_that_cannot_answer_leaves_the_attempt_outstanding() {
    // x402 has no versioned query extension, so its adapter answers
    // `Unsupported`. That has to stay outstanding. The tempting shortcuts
    // are both wrong: treating it as a retry can charge twice, and treating
    // it as a success gives away the resource for free.
    let world = World::new().await;
    world.dispatched_attempt().await;
    let worker = world.worker();

    world.clock.advance(60_000);
    world.state.set_query_plan(QueryPlan::Unsupported);
    let status = worker.run_once().await.expect("tick");

    assert_eq!(status.leases_moved_to_needs_reconciliation, 1);
    assert_eq!(status.reconciliations_attempted, 1);
    assert_eq!(status.reconciliations_unresolved, 1);
    assert_eq!(status.reconciliations_succeeded, 0);
    assert_eq!(world.status().await, IntentStatus::NeedsReconciliation);
    assert!(!world.has_access_receipt().await);
    assert_eq!(
        world.state.settle_calls(),
        0,
        "reconciliation never settles"
    );
    assert_eq!(world.state.provider_writes(), 0, "a query is never a write");

    // Asking again does not turn "cannot answer" into an answer.
    let status = worker.run_once().await.expect("tick");
    assert_eq!(status.reconciliations_succeeded, 0);
    assert_eq!(world.status().await, IntentStatus::NeedsReconciliation);
    assert!(!world.has_access_receipt().await);
}

#[tokio::test]
async fn a_dispatched_attempt_never_returns_to_normal_settlement() {
    let world = World::new().await;
    world.dispatched_attempt().await;
    let worker = world.worker();

    world.clock.advance(60_000);
    world.state.set_query_plan(QueryPlan::StillPending);
    worker.run_once().await.expect("tick");
    assert_eq!(world.status().await, IntentStatus::NeedsReconciliation);

    // The client comes back holding the same credential. The request path
    // must answer without sending anything, because the first write may
    // still land.
    let decision = world.authorize().await;
    assert!(
        matches!(decision, AuthorizationDecision::Unavailable { .. }),
        "an outstanding write must not be retried: {decision:?}",
    );
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.provider_writes(), 0);

    // And the store refuses a fresh attempt outright, so a caller that
    // skipped the service could not reach the provider either.
    let key = provider_idempotency_key(
        SettlementRail::X402,
        AttemptOperation::Settle,
        "tenant-1",
        CREDENTIAL,
        1,
        None,
    );
    let error = expect_error(
        world
            .store
            .prepare_attempt(
                &world.intent_id,
                AttemptOperation::Settle,
                &key,
                Some(PROVIDER_HANDLE),
                world.clock.now_ms(),
            )
            .await,
        "a reconciling intent must refuse a new provider write",
    );
    assert!(
        matches!(
            error,
            BillingError::NeedsReconciliation
                | BillingError::InvalidStateTransition { .. }
                | BillingError::LeaseHeld
        ),
        "the refusal must be a refusal to write, not a new attempt: {error:?}",
    );
}

#[tokio::test]
async fn a_proven_failure_refuses_the_request_and_keeps_refusing_it() {
    let world = World::new().await;
    world.dispatched_attempt().await;
    let worker = world.worker();

    world.clock.advance(60_000);
    world.state.set_query_plan(QueryPlan::Failed);
    worker.run_once().await.expect("tick");

    let status = world.status().await;
    assert!(
        !status.authorizes_origin(),
        "a proven failure must not authorize the request: {status}",
    );
    assert!(!world.has_access_receipt().await);

    let decision = world.authorize().await;
    assert!(
        !decision.authorizes_origin(),
        "a proven failure must not authorize a later retry: {decision:?}",
    );
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.provider_writes(), 0);
}

#[tokio::test]
async fn only_a_provider_proof_settles_and_a_later_retry_observes_it() {
    let world = World::new().await;
    world.dispatched_attempt().await;
    let worker = world.worker();

    world.clock.advance(60_000);
    world.state.set_query_plan(QueryPlan::StillPending);
    worker.run_once().await.expect("tick");

    let decision = world.authorize().await;
    assert!(
        !decision.authorizes_origin(),
        "an unresolved query authorizes nothing: {decision:?}",
    );

    // The provider now proves it settled. That, and only that, commits a
    // receipt.
    world.state.set_query_plan(QueryPlan::Settled);
    let status = worker.run_once().await.expect("tick");
    assert_eq!(status.reconciliations_succeeded, 1);
    assert_eq!(world.status().await, IntentStatus::Succeeded);
    assert!(world.has_access_receipt().await);

    let decision = world.authorize().await;
    match decision {
        AuthorizationDecision::Settled(receipt) => {
            assert_eq!(receipt.intent_id, world.intent_id);
        }
        other => panic!("a proven settlement must authorize the retry: {other:?}"),
    }
    assert_eq!(
        world.state.settle_calls(),
        0,
        "the settled receipt came from reconciliation, not from a second charge",
    );
    assert_eq!(world.state.provider_writes(), 0, "a query is never a write");
}

#[tokio::test]
async fn a_query_addresses_the_object_the_lost_write_may_have_created() {
    let world = World::new().await;
    let prepared = world.dispatched_attempt().await;
    let worker = world.worker();

    world.clock.advance(60_000);
    world.state.set_query_plan(QueryPlan::StillPending);
    worker.run_once().await.expect("tick");

    // The query is pointed at the handle and the idempotency key that were
    // persisted before the write. A freshly minted key would address an
    // object the provider has never seen, which makes a lost write look
    // exactly like no write at all.
    assert_eq!(
        world.state.queried_handles(),
        vec![Some(PROVIDER_HANDLE.to_string())],
    );
    assert!(world
        .state
        .keys()
        .contains(&prepared.provider_idempotency_key().to_string()));
    assert_eq!(world.state.provider_writes(), 0);
}

#[tokio::test]
async fn shutdown_stops_claiming_and_reports_the_drain_truthfully() {
    let world = World::new().await;
    let handle = world.worker().spawn();

    tokio::time::sleep(Duration::from_millis(40)).await;
    let started = std::time::Instant::now();
    let status = handle.shutdown().await;
    let elapsed = started.elapsed();

    assert!(
        status.clean_shutdown,
        "the loop drained inside its deadline"
    );
    assert!(status.ticks >= 1, "the loop ran at least one tick");
    // The wait is finite and bounded by the configured deadline, not by
    // whatever the current tick happens to be doing.
    assert!(
        elapsed < Duration::from_millis(2_000),
        "shutdown waited past the configured deadline: {elapsed:?}",
    );
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.provider_writes(), 0);
}
