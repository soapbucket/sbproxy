//! The recovery-only background worker.
//!
//! The worker exists because processes stop at inconvenient moments. It
//! expires challenges nobody redeemed, takes back leases whose holder went
//! away, asks providers what happened to writes that were left outstanding,
//! and drains queued usage accounting.
//!
//! # What it deliberately cannot do
//!
//! It never settles a payment. There is no call to
//! [`crate::registry::PaymentMethodAdapter::authorize_and_settle`] anywhere in
//! this module, and no way to reach one: the worker only ever calls
//! [`BillingService::reconcile_attempt`], which is restricted to
//! [`crate::registry::PaymentMethodAdapter::query_attempt`], plus the sweep
//! and usage helpers. A `Pending` or `RetryWait` intent is never claimed here,
//! because the client still owns it; if the client comes back, the request
//! path retries it under the same attempt, the same generation, and the same
//! provider idempotency key.
//!
//! That restriction is what keeps enqueueing separate from authorizing. Work
//! moving through this worker never causes a request to be let through; only
//! a committed receipt does, and reconciliation can commit one only when a
//! provider proves the payment settled.
//!
//! # Scheduling
//!
//! Each tick drains four bounded queues in a fixed order: expiry, lease
//! recovery, reconciliation, then usage. Every queue has its own batch size so
//! a backlog in one cannot starve the others, and every claim takes a lease so
//! two workers on one database do not duplicate provider calls.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::BillingError;
use crate::service::BillingService;
use crate::store::{ReconciliationOutcome, UsageOutcome};

/// How the worker is scheduled and bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerConfig {
    /// How long the worker sleeps between ticks.
    pub tick_interval_ms: u64,
    /// How long a lease taken by a claim stays live.
    pub lease_ttl_ms: i64,
    /// Most reconciliation records claimed per tick.
    pub reconciliation_batch: u32,
    /// Most expired challenges swept per tick.
    pub expiry_batch: u32,
    /// Most usage events claimed per tick.
    pub usage_batch: u32,
    /// Most stale leases recovered per tick.
    pub lease_batch: u32,
    /// How long shutdown waits for the current tick to drain.
    pub shutdown_deadline_ms: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            tick_interval_ms: 1_000,
            lease_ttl_ms: 30_000,
            reconciliation_batch: 32,
            expiry_batch: 256,
            usage_batch: 64,
            lease_batch: 128,
            shutdown_deadline_ms: 5_000,
        }
    }
}

impl WorkerConfig {
    /// Rejects a configuration the worker cannot honor.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`] naming the zero field.
    pub fn validate(&self) -> Result<(), BillingError> {
        if self.tick_interval_ms == 0 {
            return Err(BillingError::InvalidRequirement("tick_interval_ms"));
        }
        if self.lease_ttl_ms <= 0 {
            return Err(BillingError::InvalidRequirement("lease_ttl_ms"));
        }
        if self.shutdown_deadline_ms == 0 {
            return Err(BillingError::InvalidRequirement("shutdown_deadline_ms"));
        }
        Ok(())
    }
}

/// A snapshot of everything the worker has done.
///
/// Every counter is a fact about durable rows, not about intentions. There is
/// no settlement counter because the worker cannot settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkerStatus {
    /// Completed ticks.
    pub ticks: u64,
    /// Pending challenges moved to their terminal state after expiry.
    pub challenges_expired: u64,
    /// Undispatched attempts whose stale lease returned them to `RetryWait`.
    pub leases_returned_to_retry_wait: u64,
    /// Dispatched attempts whose stale lease made them reconcilable.
    pub leases_moved_to_needs_reconciliation: u64,
    /// Provider status queries performed.
    pub reconciliations_attempted: u64,
    /// Reconciliations where a provider proved the payment settled.
    pub reconciliations_succeeded: u64,
    /// Reconciliations that proved nothing and stayed outstanding.
    pub reconciliations_unresolved: u64,
    /// Usage events a reporter accepted.
    pub usage_reports_sent: u64,
    /// Usage events that failed and were requeued or dropped.
    pub usage_reports_failed: u64,
    /// Recovery envelopes deleted after their hard expiry.
    pub envelopes_purged: u64,
    /// Whether the loop drained inside the configured shutdown deadline.
    pub clean_shutdown: bool,
}

/// The shared counters the loop increments and a handle reads.
#[derive(Debug, Default)]
struct WorkerCounters {
    ticks: AtomicU64,
    challenges_expired: AtomicU64,
    leases_returned_to_retry_wait: AtomicU64,
    leases_moved_to_needs_reconciliation: AtomicU64,
    reconciliations_attempted: AtomicU64,
    reconciliations_succeeded: AtomicU64,
    reconciliations_unresolved: AtomicU64,
    usage_reports_sent: AtomicU64,
    usage_reports_failed: AtomicU64,
    envelopes_purged: AtomicU64,
}

impl WorkerCounters {
    /// Adds to one counter.
    fn add(counter: &AtomicU64, amount: u64) {
        counter.fetch_add(amount, Ordering::Relaxed);
    }

    /// Reads every counter into a snapshot.
    fn snapshot(&self) -> WorkerStatus {
        WorkerStatus {
            ticks: self.ticks.load(Ordering::Relaxed),
            challenges_expired: self.challenges_expired.load(Ordering::Relaxed),
            leases_returned_to_retry_wait: self
                .leases_returned_to_retry_wait
                .load(Ordering::Relaxed),
            leases_moved_to_needs_reconciliation: self
                .leases_moved_to_needs_reconciliation
                .load(Ordering::Relaxed),
            reconciliations_attempted: self.reconciliations_attempted.load(Ordering::Relaxed),
            reconciliations_succeeded: self.reconciliations_succeeded.load(Ordering::Relaxed),
            reconciliations_unresolved: self.reconciliations_unresolved.load(Ordering::Relaxed),
            usage_reports_sent: self.usage_reports_sent.load(Ordering::Relaxed),
            usage_reports_failed: self.usage_reports_failed.load(Ordering::Relaxed),
            envelopes_purged: self.envelopes_purged.load(Ordering::Relaxed),
            clean_shutdown: false,
        }
    }
}

/// The recovery-only worker.
pub struct SettlementWorker {
    service: Arc<BillingService>,
    config: WorkerConfig,
    counters: Arc<WorkerCounters>,
}

impl SettlementWorker {
    /// Builds a worker over an authoritative service.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`] for a configuration with a
    /// zero interval, lease lifetime, or shutdown deadline.
    pub fn new(service: Arc<BillingService>, config: WorkerConfig) -> Result<Self, BillingError> {
        config.validate()?;
        Ok(Self {
            service,
            config,
            counters: Arc::new(WorkerCounters::default()),
        })
    }

    /// Returns a snapshot of what the worker has done so far.
    pub fn status(&self) -> WorkerStatus {
        self.counters.snapshot()
    }

    /// Runs one full tick.
    ///
    /// Tests drive this directly so a scheduling interval never has to be
    /// slept through. Every queue is bounded, so this returns promptly even
    /// with a large backlog.
    ///
    /// # Errors
    ///
    /// Returns whatever the store returns. A provider that cannot answer is an
    /// outcome rather than an error, so it does not stop the tick.
    pub async fn run_once(&self) -> Result<WorkerStatus, BillingError> {
        let expired = self
            .service
            .expire_challenges(self.config.expiry_batch)
            .await?;
        WorkerCounters::add(&self.counters.challenges_expired, expired);

        let recovered = self.service.recover_leases(self.config.lease_batch).await?;
        WorkerCounters::add(
            &self.counters.leases_returned_to_retry_wait,
            recovered.returned_to_retry_wait,
        );
        WorkerCounters::add(
            &self.counters.leases_moved_to_needs_reconciliation,
            recovered.moved_to_needs_reconciliation,
        );

        self.drain_reconciliation().await?;
        self.drain_usage().await?;

        let purged = self.service.purge_expired_envelopes().await?;
        WorkerCounters::add(&self.counters.envelopes_purged, purged);

        WorkerCounters::add(&self.counters.ticks, 1);
        Ok(self.counters.snapshot())
    }

    /// Spawns the loop and returns a handle that can stop it.
    pub fn spawn(self) -> SettlementWorkerHandle {
        let (sender, mut receiver) = watch::channel(false);
        let counters = Arc::clone(&self.counters);
        let interval = Duration::from_millis(self.config.tick_interval_ms);
        let shutdown_deadline = Duration::from_millis(self.config.shutdown_deadline_ms);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = receiver.changed() => {
                        // A closed channel means the handle went away, which
                        // is also a reason to stop claiming work.
                        if changed.is_err() || *receiver.borrow() {
                            break;
                        }
                    }
                    () = tokio::time::sleep(interval) => {}
                }
                if let Err(error) = self.run_once().await {
                    tracing::warn!(
                        category = %error.failure_category(),
                        "settlement worker tick did not complete",
                    );
                }
            }
            self.counters.snapshot()
        });

        SettlementWorkerHandle {
            counters,
            shutdown: sender,
            task,
            shutdown_deadline,
        }
    }

    /// Queries every claimed reconciliation record once.
    async fn drain_reconciliation(&self) -> Result<(), BillingError> {
        let now_ms = self.service.clock().now_ms();
        let claimed = self
            .service
            .store()
            .claim_reconciliation(
                now_ms,
                self.config.lease_ttl_ms,
                self.config.reconciliation_batch,
            )
            .await?;
        for attempt in claimed {
            WorkerCounters::add(&self.counters.reconciliations_attempted, 1);
            match self.service.reconcile_attempt(attempt).await {
                Ok(ReconciliationOutcome::ProvenSucceeded(_)) => {
                    WorkerCounters::add(&self.counters.reconciliations_succeeded, 1);
                }
                Ok(ReconciliationOutcome::Unresolved(_)) => {
                    WorkerCounters::add(&self.counters.reconciliations_unresolved, 1);
                }
                Ok(_) => {}
                Err(error) => {
                    WorkerCounters::add(&self.counters.reconciliations_unresolved, 1);
                    tracing::warn!(
                        category = %error.failure_category(),
                        "could not record a reconciliation outcome",
                    );
                }
            }
        }
        Ok(())
    }

    /// Reports every claimed usage event once.
    async fn drain_usage(&self) -> Result<(), BillingError> {
        let now_ms = self.service.clock().now_ms();
        let claimed = self
            .service
            .store()
            .claim_usage_events(now_ms, self.config.lease_ttl_ms, self.config.usage_batch)
            .await?;
        for event in claimed {
            match self.service.report_usage_event(event).await {
                Ok(UsageOutcome::Reported(_)) => {
                    WorkerCounters::add(&self.counters.usage_reports_sent, 1);
                }
                Ok(_) => {
                    WorkerCounters::add(&self.counters.usage_reports_failed, 1);
                }
                Err(error) => {
                    WorkerCounters::add(&self.counters.usage_reports_failed, 1);
                    tracing::warn!(
                        category = %error.failure_category(),
                        "could not record a usage report outcome",
                    );
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for SettlementWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettlementWorker")
            .field("config", &self.config)
            .field("status", &self.status())
            .finish()
    }
}

/// A handle to a running worker.
pub struct SettlementWorkerHandle {
    counters: Arc<WorkerCounters>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<WorkerStatus>,
    shutdown_deadline: Duration,
}

impl SettlementWorkerHandle {
    /// Returns a snapshot of what the worker has done so far.
    pub fn status(&self) -> WorkerStatus {
        self.counters.snapshot()
    }

    /// Stops new claims and waits for the current tick to drain.
    ///
    /// The returned status reports `clean_shutdown` truthfully: `false` means
    /// the deadline elapsed and the loop was aborted mid-tick. An aborted tick
    /// cannot corrupt anything, because every transition it was performing is
    /// its own committed transaction, but the operator should know it
    /// happened.
    pub async fn shutdown(self) -> WorkerStatus {
        let _ = self.shutdown.send(true);
        match tokio::time::timeout(self.shutdown_deadline, self.task).await {
            Ok(Ok(mut status)) => {
                status.clean_shutdown = true;
                status
            }
            Ok(Err(_join_error)) => self.counters.snapshot(),
            Err(_elapsed) => {
                tracing::warn!("settlement worker did not drain inside its shutdown deadline");
                self.counters.snapshot()
            }
        }
    }
}

impl std::fmt::Debug for SettlementWorkerHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SettlementWorkerHandle")
            .field("status", &self.status())
            .finish()
    }
}
