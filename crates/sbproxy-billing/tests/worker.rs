//! The worker's scope, proved by what it never does.
//!
//! The worker sweeps, recovers, queries, and reports. It does not settle. Every
//! test here asserts the fixture's settlement counter is still zero afterwards,
//! because a background task that can settle is a background task that can
//! charge somebody twice.

#![cfg(feature = "runtime")]

use std::sync::Arc;
use std::time::Duration;

use sbproxy_billing::registry::{RailRegistry, UsageEvent};
use sbproxy_billing::service::BillingService;
use sbproxy_billing::sqlite::SqliteSettlementStore;
use sbproxy_billing::store::{BillingClock, SharedSettlementStore};
use sbproxy_billing::types::{
    provider_idempotency_key, AttemptOperation, AttemptStatus, IntentStatus, PaymentProof,
    SettlementRail,
};
use sbproxy_billing::worker::{SettlementWorker, WorkerConfig};

mod common;

use common::{
    sample_draft, sign_draft, FixtureAdapter, FixtureReporter, FixtureState, QueryPlan, TestClock,
};

/// A fixed instant every test starts from.
const START_MS: i64 = 1_700_000_000_000;

/// A challenge expiry comfortably after the start instant.
const EXPIRY_MS: i64 = 1_700_000_600_000;

/// One assembled world: a store, a service, a worker, and recording state.
struct World {
    store: SharedSettlementStore,
    service: Arc<BillingService>,
    state: Arc<FixtureState>,
    clock: Arc<TestClock>,
    _directory: tempfile::TempDir,
}

impl World {
    /// Builds a world with a fixture rail and a fixture usage reporter.
    fn new() -> Self {
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
        registry
            .register_reporter(FixtureReporter::new(Arc::clone(&state)))
            .expect("register reporter");
        let service = Arc::new(
            BillingService::builder(Arc::clone(&store))
                .adapters(registry)
                .clock(Arc::clone(&clock) as Arc<dyn BillingClock>)
                .build(),
        );

        Self {
            store,
            service,
            state,
            clock,
            _directory: directory,
        }
    }

    /// Builds a worker over this world with a test-sized configuration.
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

    /// Creates and finalizes one challenge, returning its intent identifier.
    async fn challenge(&self, requirement_id: &str, request_key: &str) -> String {
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
        created.intent_id
    }

    /// Prepares a settle attempt and optionally stamps its dispatch.
    async fn attempt(
        &self,
        intent_id: &str,
        credential: &str,
        dispatch: bool,
    ) -> sbproxy_billing::store::PreparedAttempt {
        let proof = PaymentProof::new("Payment", credential.to_string()).expect("proof");
        let digest = proof.digest();
        self.store
            .reserve_proof(intent_id, digest, self.clock.now_ms())
            .await
            .expect("reserve proof");
        let key = provider_idempotency_key(
            SettlementRail::X402,
            AttemptOperation::Settle,
            "tenant-1",
            credential,
            0,
            Some(&digest),
        );
        let prepared = self
            .store
            .prepare_attempt(
                intent_id,
                AttemptOperation::Settle,
                &key,
                Some("pi_handle"),
                self.clock.now_ms(),
            )
            .await
            .expect("prepare attempt");
        if dispatch {
            self.store
                .mark_dispatch_started(
                    prepared.attempt_id(),
                    prepared.lease_token(),
                    self.clock.now_ms(),
                )
                .await
                .expect("stamp dispatch");
        }
        prepared
    }

    /// Returns the durable state of one intent.
    async fn status(&self, intent_id: &str) -> IntentStatus {
        self.store
            .load_intent(intent_id)
            .await
            .expect("read")
            .expect("intent")
            .status
    }
}

#[tokio::test]
async fn the_worker_expires_challenges_nobody_redeemed() {
    let world = World::new();
    let intent_id = world.challenge("req-1", "request-key").await;
    let worker = world.worker();

    world.clock.advance(700_000);
    let status = worker.run_once().await.expect("tick");

    assert_eq!(status.challenges_expired, 1);
    assert_eq!(world.status(&intent_id).await, IntentStatus::Terminal);
    assert_eq!(world.state.settle_calls(), 0, "the worker must not settle");
    assert_eq!(world.state.provider_writes(), 0);
}

#[tokio::test]
async fn the_worker_recovers_an_undispatched_attempt_without_settling() {
    let world = World::new();
    let intent_id = world.challenge("req-1", "request-key").await;
    let prepared = world.attempt(&intent_id, "spt_value", false).await;
    let worker = world.worker();

    world.clock.advance(60_000);
    let status = worker.run_once().await.expect("tick");

    assert_eq!(status.leases_returned_to_retry_wait, 1);
    assert_eq!(status.leases_moved_to_needs_reconciliation, 0);
    assert_eq!(status.reconciliations_attempted, 0);
    assert_eq!(
        world
            .store
            .load_attempt(prepared.attempt_id())
            .await
            .expect("read")
            .expect("attempt")
            .status,
        AttemptStatus::RetryWait,
    );
    assert_eq!(world.status(&intent_id).await, IntentStatus::RetryWait);
    // A `RetryWait` intent still belongs to the client, so the worker leaves
    // it alone rather than settling it in the background.
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.query_calls(), 0);
}

#[tokio::test]
async fn the_worker_queries_reconciliation_and_only_a_proof_settles_it() {
    let world = World::new();
    let intent_id = world.challenge("req-1", "request-key").await;
    world.attempt(&intent_id, "spt_value", true).await;
    let worker = world.worker();

    world.clock.advance(60_000);
    world.state.set_query_plan(QueryPlan::StillPending);
    let status = worker.run_once().await.expect("tick");

    assert_eq!(status.leases_moved_to_needs_reconciliation, 1);
    assert_eq!(status.reconciliations_attempted, 1);
    assert_eq!(status.reconciliations_unresolved, 1);
    assert_eq!(status.reconciliations_succeeded, 0);
    assert_eq!(
        world.status(&intent_id).await,
        IntentStatus::NeedsReconciliation
    );
    assert!(world
        .store
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .is_none());
    assert_eq!(world.state.settle_calls(), 0, "the worker must not settle");

    // Once the provider proves it settled, and only then, a receipt exists.
    world.state.set_query_plan(QueryPlan::Settled);
    let status = worker.run_once().await.expect("tick");
    assert_eq!(status.reconciliations_succeeded, 1);
    assert_eq!(world.status(&intent_id).await, IntentStatus::Succeeded);
    assert!(world
        .store
        .load_access_receipt(&intent_id)
        .await
        .expect("read")
        .is_some());
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.provider_writes(), 0, "a query is never a write",);
}

#[tokio::test]
async fn the_worker_reports_queued_usage() {
    let world = World::new();
    let event = UsageEvent {
        reporter: "fixture_meter".to_string(),
        usage_identifier: "usage-1".to_string(),
        tenant_id: "tenant-1".to_string(),
        origin_id: "origin-1".to_string(),
        event_name: "tokens".to_string(),
        quantity: 128,
        occurred_at_ms: START_MS,
        attributes: Default::default(),
    };
    assert!(world
        .store
        .enqueue_usage_event(&event)
        .await
        .expect("queue"));

    let worker = world.worker();
    let status = worker.run_once().await.expect("tick");
    assert_eq!(status.usage_reports_sent, 1);
    assert_eq!(status.usage_reports_failed, 0);

    // A reported event is not reported twice, and reporting never settles.
    let status = worker.run_once().await.expect("tick");
    assert_eq!(status.usage_reports_sent, 1);
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.provider_writes(), 1, "one meter write");
}

#[tokio::test]
async fn a_pending_intent_is_never_claimed_for_settlement() {
    let world = World::new();
    let intent_id = world.challenge("req-1", "request-key").await;
    let worker = world.worker();

    // Well inside the challenge expiry, so there is nothing to sweep.
    let status = worker.run_once().await.expect("tick");
    assert_eq!(status.challenges_expired, 0);
    assert_eq!(status.reconciliations_attempted, 0);
    assert_eq!(status.leases_returned_to_retry_wait, 0);
    assert_eq!(world.status(&intent_id).await, IntentStatus::Pending);
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.query_calls(), 0);
    assert_eq!(world.state.provider_writes(), 0);
}

#[tokio::test]
async fn the_worker_stops_claiming_and_drains_on_shutdown() {
    let world = World::new();
    let handle = world.worker().spawn();

    tokio::time::sleep(Duration::from_millis(40)).await;
    let status = handle.shutdown().await;

    assert!(
        status.clean_shutdown,
        "the loop drained inside its deadline"
    );
    assert!(status.ticks >= 1, "the loop ran at least one tick");
    assert_eq!(world.state.settle_calls(), 0);
    assert_eq!(world.state.provider_writes(), 0);
}
