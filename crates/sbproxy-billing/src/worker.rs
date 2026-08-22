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
//! It also cannot resolve an ambiguity by giving up on it. The one sweep
//! that moves an intent without a provider answer,
//! [`BillingService::strand_unattributable_intents`], retires an
//! unattributable intent's hold on its route once the quote token that
//! payment was made under can no longer be redeemed by anybody. It writes no
//! receipt, it leaves the attempt on the reconciliation queue, and the state
//! it commits authorizes nothing.
//!
//! # Scheduling
//!
//! Each tick drains six bounded queues in a fixed order: expiry, lease
//! recovery, the reconciliation deadline, reconciliation, usage, then
//! recovery-envelope purge. Every queue has its own batch size so a backlog
//! in one cannot starve the others, and every claim takes a lease so two
//! workers on one database do not duplicate provider calls.
//!
//! The stages are also independent in failure. A store error in one stage
//! does not skip the stages below it: every stage is attempted, the stage
//! that failed is named in its own log line and counted in
//! [`WorkerStatus::stage_failures`], and the tick reports the first error
//! once all six have run. That matters because the sweeps are not
//! interchangeable. `strand_unattributable_intents` retires a payment's hold
//! on its route and `claim_reconciliation` is the only sweep that can still
//! resolve that payment honestly, so a tick that ran the first and skipped
//! the second would keep retiring unresolved payments while never asking a
//! provider what happened to them.

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
    /// How long an unattributable unresolved intent keeps withholding its
    /// route after its challenge expired, in milliseconds.
    ///
    /// Measured from the intent's own `expires_at_ms`, not from now, so the
    /// deadline is a property of the payment rather than of when the sweep
    /// happens to run. See
    /// [`crate::store::SettlementStore::strand_unattributable_intents`] for
    /// why the challenge expiry is the right anchor.
    ///
    /// Not an operator knob today, for the reason the batch sizes are not:
    /// the right value follows from the reconciliation cadence rather than
    /// from the deployment, and every deployment gets the same cadence
    /// defaults.
    pub reconciliation_grace_ms: i64,
    /// Most unattributable intents retired per tick.
    pub strand_batch: u32,
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
            // Fifteen minutes past the challenge's own expiry. Three times
            // the five-minute challenge TTL, and nine hundred sweeps at the
            // default one-second cadence, which is a generous run at
            // resolving the intent honestly before it is retired. Longer buys
            // nothing: past `expires_at_ms` the payer cannot redeem this
            // intent whatever the provider says, so every extra minute is a
            // minute the route earns nothing and nobody is protected.
            reconciliation_grace_ms: 900_000,
            strand_batch: 256,
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
        // Zero would retire an intent the instant its challenge expired,
        // which is the one value that gives reconciliation no run at all.
        // Negative would retire it before the challenge expired, which is the
        // double charge this deadline is built not to be.
        if self.reconciliation_grace_ms <= 0 {
            return Err(BillingError::InvalidRequirement("reconciliation_grace_ms"));
        }
        if self.shutdown_deadline_ms == 0 {
            return Err(BillingError::InvalidRequirement("shutdown_deadline_ms"));
        }
        Ok(())
    }
}

/// Sweep stages that returned a store error and therefore moved nothing.
///
/// One counter per stage rather than one total, because the stages are not
/// interchangeable: an operator reading "the tick failed" cannot tell
/// whether reconciliation stopped asking providers what happened or whether
/// expired recovery ciphertext stopped being deleted, and those are
/// different pages.
///
/// A stage that fails does not stop the stages below it, so several of these
/// can move on one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkerStageFailures {
    /// Failed challenge-expiry sweeps.
    pub expire_challenges: u64,
    /// Failed lease-recovery sweeps.
    pub recover_leases: u64,
    /// Failed unattributable-intent sweeps.
    pub strand_intents: u64,
    /// Failed reconciliation claims.
    ///
    /// A provider that cannot answer is an outcome, not a failure, so this
    /// only moves when the claim itself could not be read from the store.
    pub reconciliation: u64,
    /// Failed usage-event claims.
    ///
    /// As with reconciliation, a reporter that rejects an event is an
    /// outcome; this counts a claim the store could not serve.
    pub usage: u64,
    /// Failed recovery-envelope purges.
    pub purge_envelopes: u64,
}

/// A snapshot of everything the worker has done.
///
/// Every counter is a fact about durable rows, not about intentions. There is
/// no settlement counter because the worker cannot settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkerStatus {
    /// Ticks on which every stage completed.
    ///
    /// A tick where any stage returned a store error is not counted here,
    /// even though the other stages still ran, so this stays readable as
    /// "the worker got all the way round" and the partial passes show up in
    /// `stage_failures` instead.
    pub ticks: u64,
    /// Pending challenges moved to their terminal state after expiry.
    pub challenges_expired: u64,
    /// Unattributable unresolved intents that stopped withholding their
    /// route after the reconciliation deadline passed.
    ///
    /// Not a settlement counter and not a failure counter. Each one is a
    /// payment whose fate is still unknown and which nothing is going to
    /// resolve on its own, which is exactly the condition worth waking
    /// somebody for.
    pub intents_stranded: u64,
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
    /// Sweep stages that returned a store error, by stage.
    pub stage_failures: WorkerStageFailures,
    /// Whether the loop drained inside the configured shutdown deadline.
    pub clean_shutdown: bool,
}

/// The shared counters the loop increments and a handle reads.
#[derive(Debug, Default)]
struct WorkerCounters {
    ticks: AtomicU64,
    challenges_expired: AtomicU64,
    intents_stranded: AtomicU64,
    leases_returned_to_retry_wait: AtomicU64,
    leases_moved_to_needs_reconciliation: AtomicU64,
    reconciliations_attempted: AtomicU64,
    reconciliations_succeeded: AtomicU64,
    reconciliations_unresolved: AtomicU64,
    usage_reports_sent: AtomicU64,
    usage_reports_failed: AtomicU64,
    envelopes_purged: AtomicU64,
    stage_expire_challenges_failed: AtomicU64,
    stage_recover_leases_failed: AtomicU64,
    stage_strand_intents_failed: AtomicU64,
    stage_reconciliation_failed: AtomicU64,
    stage_usage_failed: AtomicU64,
    stage_purge_envelopes_failed: AtomicU64,
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
            intents_stranded: self.intents_stranded.load(Ordering::Relaxed),
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
            stage_failures: WorkerStageFailures {
                expire_challenges: self.stage_expire_challenges_failed.load(Ordering::Relaxed),
                recover_leases: self.stage_recover_leases_failed.load(Ordering::Relaxed),
                strand_intents: self.stage_strand_intents_failed.load(Ordering::Relaxed),
                reconciliation: self.stage_reconciliation_failed.load(Ordering::Relaxed),
                usage: self.stage_usage_failed.load(Ordering::Relaxed),
                purge_envelopes: self.stage_purge_envelopes_failed.load(Ordering::Relaxed),
            },
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
    /// zero interval, lease lifetime, reconciliation grace window, or
    /// shutdown deadline.
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
    /// Every stage is attempted, whatever the stages before it did. A store
    /// error in one sweep is recorded against that sweep and the tick carries
    /// on, because the sweeps recover different things and skipping the rest
    /// of the tick is how a contended database turns one slow queue into a
    /// stalled reconciliation queue and retained recovery ciphertext.
    ///
    /// # Errors
    ///
    /// Returns the first store error any stage produced, after all six stages
    /// have run. A provider that cannot answer is an outcome rather than an
    /// error, so it does not fail a stage. Callers that want to know which
    /// stage failed should read [`WorkerStatus::stage_failures`] or the
    /// per-stage warn log, because the returned error names a category and
    /// not a queue.
    pub async fn run_once(&self) -> Result<WorkerStatus, BillingError> {
        let mut first_error: Option<BillingError> = None;

        match self
            .service
            .expire_challenges(self.config.expiry_batch)
            .await
        {
            Ok(expired) => WorkerCounters::add(&self.counters.challenges_expired, expired),
            Err(error) => self.record_stage_failure(
                "expire_challenge",
                &self.counters.stage_expire_challenges_failed,
                error,
                &mut first_error,
            ),
        }

        match self.service.recover_leases(self.config.lease_batch).await {
            Ok(recovered) => {
                WorkerCounters::add(
                    &self.counters.leases_returned_to_retry_wait,
                    recovered.returned_to_retry_wait,
                );
                WorkerCounters::add(
                    &self.counters.leases_moved_to_needs_reconciliation,
                    recovered.moved_to_needs_reconciliation,
                );
            }
            Err(error) => self.record_stage_failure(
                "recover_lease",
                &self.counters.stage_recover_leases_failed,
                error,
                &mut first_error,
            ),
        }

        // After lease recovery, because recovery is what puts an abandoned
        // dispatch into `NeedsReconciliation` in the first place. An intent
        // whose deadline passed while its holder was gone is therefore
        // retired in the same tick it becomes reconcilable, rather than
        // gating the route for one extra interval.
        //
        // Safe in the other direction too: recovery's propagation query
        // excludes `Stranded`, so an intent retired on one tick is not
        // dragged back to `NeedsReconciliation` on the next.
        match self
            .service
            .strand_unattributable_intents(
                self.config.reconciliation_grace_ms,
                self.config.strand_batch,
            )
            .await
        {
            Ok(stranded) => {
                if stranded > 0 {
                    // Warn rather than info: every row here is money the
                    // deployment may owe and cannot account for, and the
                    // route it was holding has just started billing other
                    // callers again. No intent id, no route, and no payer:
                    // this is a count across the whole sweep, and the
                    // per-intent detail is already in the durable rows.
                    tracing::warn!(
                        stranded,
                        "unattributable payments outlived their reconciliation deadline; their \
                         routes are challengeable again and the payments themselves are still \
                         unresolved. Reconcile them with the provider by hand and refund or \
                         credit anything that settled",
                    );
                }
                WorkerCounters::add(&self.counters.intents_stranded, stranded);
            }
            Err(error) => self.record_stage_failure(
                "strand_intent",
                &self.counters.stage_strand_intents_failed,
                error,
                &mut first_error,
            ),
        }

        if let Err(error) = self.drain_reconciliation().await {
            self.record_stage_failure(
                "reconcile",
                &self.counters.stage_reconciliation_failed,
                error,
                &mut first_error,
            );
        }

        if let Err(error) = self.drain_usage().await {
            self.record_stage_failure(
                "report_usage",
                &self.counters.stage_usage_failed,
                error,
                &mut first_error,
            );
        }

        match self.service.purge_expired_envelopes().await {
            Ok(purged) => WorkerCounters::add(&self.counters.envelopes_purged, purged),
            Err(error) => self.record_stage_failure(
                "purge_envelope",
                &self.counters.stage_purge_envelopes_failed,
                error,
                &mut first_error,
            ),
        }

        if let Some(error) = first_error {
            return Err(error);
        }

        // Only a tick that got all the way round counts. A partial pass is
        // visible in the per-stage failure counters instead, so the tick rate
        // keeps meaning "the worker completed a full sweep" and an operator
        // can still tell a stalled worker from a degraded one.
        WorkerCounters::add(&self.counters.ticks, 1);
        Ok(self.counters.snapshot())
    }

    /// Records one stage that could not run, and keeps the first error.
    ///
    /// The stage name is the same `operation` label value
    /// `sbproxy_payment_recovery_total` uses for the rows that stage moves,
    /// so a failure line and the flat series it explains can be read
    /// together.
    fn record_stage_failure(
        &self,
        stage: &'static str,
        counter: &AtomicU64,
        error: BillingError,
        first_error: &mut Option<BillingError>,
    ) {
        WorkerCounters::add(counter, 1);
        tracing::warn!(
            stage,
            category = %error.failure_category(),
            "settlement worker sweep stage failed; the remaining stages still ran",
        );
        if first_error.is_none() {
            *first_error = Some(error);
        }
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
                    // Every stage still ran; this is the first error of
                    // however many there were. The stage that produced it was
                    // already logged by name, so this line only says the tick
                    // was not clean.
                    tracing::warn!(
                        category = %error.failure_category(),
                        "settlement worker tick had a stage that could not run",
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
