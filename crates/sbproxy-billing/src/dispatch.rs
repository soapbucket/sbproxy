//! The only gate a provider network write may pass through.
//!
//! An adapter cannot open a socket on its own. Every write is wrapped in
//! [`DispatchContext::run_write`], which commits `dispatch_started_at_ms` in
//! its own transaction *before* the closure is polled. That ordering is the
//! whole point: if this process stops at any instant after the stamp commits,
//! the durable record already says a write may have landed, so no replacement
//! process can conclude that it is safe to send the request again under a new
//! idempotency key.
//!
//! The gate records one of three conclusions:
//!
//! - [`DispatchOutcome::NeverDispatched`]: the stamp was never committed, so
//!   nothing left the process and a retry is provably safe.
//! - [`DispatchOutcome::Resolved`]: the stamp is committed and the provider
//!   gave an authoritative answer, success or refusal.
//! - [`DispatchOutcome::Ambiguous`]: the stamp is committed and no
//!   authoritative answer was recorded. This is where a timeout, a dropped
//!   future, an unreachable provider, and an unparseable response all land.
//!
//! The conclusion is written before the closure is polled and only narrowed
//! afterwards, so dropping the future mid-call, which is exactly what
//! `tokio::time::timeout` does, leaves [`DispatchOutcome::Ambiguous`] behind
//! rather than losing the fact of the dispatch. The caller reads
//! [`DispatchContext::outcome`] after the call and picks the matching durable
//! transition. Ambiguity can never become a retry, and it can never become a
//! success without a provider proving it.
//!
//! Read-only provider calls use [`DispatchContext::run_query`], which never
//! stamps anything. A query is not a write and must never make an intent look
//! as though funds may have moved.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

use crate::error::BillingError;
use crate::lifecycle::{
    PaymentLifecycleDecision, PaymentLifecycleEvent, PaymentLifecycleObserver,
    PaymentLifecycleOutcome, PaymentLifecyclePhase,
};
use crate::store::{BillingClock, PreparedAttempt, ProviderAttempt, SharedSettlementStore};
use crate::types::SettlementRail;

/// The gate has not stamped anything yet.
const OUTCOME_NEVER_DISPATCHED: u8 = 0;
/// The gate stamped a dispatch and has no authoritative answer for it.
const OUTCOME_AMBIGUOUS: u8 = 1;
/// The gate stamped a dispatch and the provider answered authoritatively.
const OUTCOME_RESOLVED: u8 = 2;

/// One queued usage report, with everything a dispatch needs.
///
/// Usage reporting is accounting, never proof of payment, so this subject can
/// never reach a settlement receipt. It is dispatched through the same gate
/// purely so a lost meter write is as visible as a lost payment write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageDispatch {
    /// The reporter that owns the event.
    pub reporter: String,
    /// The caller's deduplication identifier, unique per reporter.
    pub usage_identifier: String,
    /// The lease token that authorizes transitions on the queued row.
    pub lease_token: String,
    /// The provider idempotency key, persisted before any write.
    pub provider_idempotency_key: String,
    /// Whether a previous dispatch stamp is already outstanding.
    pub previously_dispatched: bool,
}

/// What one dispatch context is guarding.
#[derive(Debug, Clone, PartialEq, Eq)]
// Boxing the large variant would put an allocation and an indirection on the
// settlement path to save stack bytes that are never the bottleneck: exactly
// one of these exists per provider interaction, and that interaction is a
// network round trip.
#[allow(clippy::large_enum_variant)]
pub enum DispatchSubject {
    /// A payment attempt against a settlement rail.
    Attempt(PreparedAttempt),
    /// A usage report against a reporter.
    Usage(UsageDispatch),
}

impl DispatchSubject {
    /// Returns the lease token every durable transition on this subject needs.
    pub fn lease_token(&self) -> &str {
        match self {
            Self::Attempt(attempt) => attempt.lease_token(),
            Self::Usage(usage) => &usage.lease_token,
        }
    }

    /// Returns the provider idempotency key persisted before any write.
    pub fn provider_idempotency_key(&self) -> &str {
        match self {
            Self::Attempt(attempt) => attempt.provider_idempotency_key(),
            Self::Usage(usage) => &usage.provider_idempotency_key,
        }
    }

    /// Returns the payment attempt, when this subject is one.
    pub fn attempt(&self) -> Option<&ProviderAttempt> {
        match self {
            Self::Attempt(attempt) => Some(&attempt.attempt),
            Self::Usage(_) => None,
        }
    }
}

/// What the gate concluded about one guarded provider write.
///
/// The variants are ordered by how much the caller is allowed to assume.
/// [`DispatchOutcome::NeverDispatched`] is the only one that permits a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DispatchOutcome {
    /// No stamp was committed, so no bytes left the process.
    #[default]
    NeverDispatched,
    /// A stamp is committed and the provider answered authoritatively.
    Resolved,
    /// A stamp is committed and no authoritative answer was recorded.
    Ambiguous,
}

impl DispatchOutcome {
    /// Returns the stable wire spelling used in logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverDispatched => "never_dispatched",
            Self::Resolved => "resolved",
            Self::Ambiguous => "ambiguous",
        }
    }

    /// Reports whether a fresh provider write would be safe after this.
    pub const fn permits_retry(self) -> bool {
        matches!(self, Self::NeverDispatched)
    }
}

impl std::fmt::Display for DispatchOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The gate that stands between an adapter and the network.
///
/// The context is owned by the service or the worker and handed to the
/// adapter by reference, so a deadline that drops the adapter's future does
/// not drop the record of what the gate did.
pub struct DispatchContext {
    store: SharedSettlementStore,
    clock: Arc<dyn BillingClock>,
    subject: DispatchSubject,
    outcome: AtomicU8,
    payment_lifecycle: Option<PaymentLifecycleDispatch>,
    settle_started: AtomicBool,
}

struct PaymentLifecycleDispatch {
    observer: Arc<dyn PaymentLifecycleObserver>,
    event: PaymentLifecycleEvent,
}

impl DispatchContext {
    /// Builds a gate for one payment attempt.
    pub fn for_attempt(
        store: SharedSettlementStore,
        clock: Arc<dyn BillingClock>,
        attempt: PreparedAttempt,
    ) -> Self {
        Self::new(store, clock, DispatchSubject::Attempt(attempt))
    }

    /// Builds a payment gate with generation-scoped lifecycle observation.
    pub fn for_payment_attempt(
        store: SharedSettlementStore,
        clock: Arc<dyn BillingClock>,
        attempt: PreparedAttempt,
        observer: Arc<dyn PaymentLifecycleObserver>,
        event: PaymentLifecycleEvent,
    ) -> Self {
        let mut context = Self::new(store, clock, DispatchSubject::Attempt(attempt));
        context.payment_lifecycle = Some(PaymentLifecycleDispatch { observer, event });
        context
    }

    /// Builds a gate for one usage report.
    pub fn for_usage(
        store: SharedSettlementStore,
        clock: Arc<dyn BillingClock>,
        usage: UsageDispatch,
    ) -> Self {
        Self::new(store, clock, DispatchSubject::Usage(usage))
    }

    /// Builds a gate for an arbitrary subject.
    pub fn new(
        store: SharedSettlementStore,
        clock: Arc<dyn BillingClock>,
        subject: DispatchSubject,
    ) -> Self {
        Self {
            store,
            clock,
            subject,
            outcome: AtomicU8::new(OUTCOME_NEVER_DISPATCHED),
            payment_lifecycle: None,
            settle_started: AtomicBool::new(false),
        }
    }

    /// Inspect a lifecycle `started` event before its protected effect.
    pub async fn payment_started(&self, phase: PaymentLifecyclePhase) -> PaymentLifecycleDecision {
        if phase == PaymentLifecyclePhase::Settle {
            self.settle_started.store(true, Ordering::Release);
        }
        let Some(lifecycle) = &self.payment_lifecycle else {
            return PaymentLifecycleDecision::Continue;
        };
        let event = lifecycle
            .event
            .clone()
            .with_phase(phase)
            .with_outcome(PaymentLifecycleOutcome::Started);
        lifecycle.observer.started(&event).await
    }

    /// Observe one terminal lifecycle event without awaiting extension work.
    pub fn payment_terminal(&self, phase: PaymentLifecyclePhase, outcome: PaymentLifecycleOutcome) {
        if let Some(lifecycle) = &self.payment_lifecycle {
            lifecycle.observer.terminal(
                lifecycle
                    .event
                    .clone()
                    .with_phase(phase)
                    .with_outcome(outcome),
            );
        }
    }

    /// Report whether this adapter emitted `settle.started`.
    pub fn settlement_lifecycle_started(&self) -> bool {
        self.settle_started.load(Ordering::Acquire)
    }

    /// Returns the subject being guarded.
    pub fn subject(&self) -> &DispatchSubject {
        &self.subject
    }

    /// Returns the payment attempt, when the subject is one.
    pub fn attempt(&self) -> Option<&ProviderAttempt> {
        self.subject.attempt()
    }

    /// Returns the rail this dispatch talks to, when the subject is a payment.
    pub fn rail(&self) -> Option<SettlementRail> {
        self.subject.attempt().map(|attempt| attempt.rail)
    }

    /// Returns the provider idempotency key persisted before any write.
    ///
    /// An adapter must send exactly this value where the provider accepts a
    /// full-length key, or the checked shortening of it where the provider
    /// documents a tighter limit. It must never mint its own.
    pub fn provider_idempotency_key(&self) -> &str {
        self.subject.provider_idempotency_key()
    }

    /// Returns the durable store, for envelope writes an adapter must make.
    pub fn store(&self) -> &SharedSettlementStore {
        &self.store
    }

    /// Persists a hashed facilitator payer on the intent (WOR-2302).
    ///
    /// `payer` is the raw address from `VerifyResponse`. It is hashed
    /// immediately and never stored, logged, or returned. An empty value
    /// is a no-op so a facilitator that omits the field leaves the first-ever
    /// stall route-wide, which is the residual this ticket accepts.
    ///
    /// # Errors
    ///
    /// Returns the store's error. Callers must fail closed before stamping
    /// a settle: a payment we cannot attribute should not become a
    /// route-wide hold we then cannot explain.
    pub async fn attribute_x402_payer(
        &self,
        intent_id: &str,
        payer: &str,
    ) -> Result<(), BillingError> {
        let payer = payer.trim();
        if payer.is_empty() {
            return Ok(());
        }
        let Some(attempt) = self.attempt() else {
            return Err(BillingError::InvalidRequirement("intent_id"));
        };
        let hash = crate::types::x402_facilitator_payer_hash(&attempt.tenant_id, payer);
        self.store.attribute_payer_hash(intent_id, &hash).await
    }

    /// Returns the current time in milliseconds since the Unix epoch.
    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    /// Returns what the gate concluded so far.
    pub fn outcome(&self) -> DispatchOutcome {
        match self.outcome.load(Ordering::Acquire) {
            OUTCOME_RESOLVED => DispatchOutcome::Resolved,
            OUTCOME_AMBIGUOUS => DispatchOutcome::Ambiguous,
            _ => DispatchOutcome::NeverDispatched,
        }
    }

    /// Reports whether a dispatch stamp was committed.
    pub fn was_dispatched(&self) -> bool {
        !self.outcome().permits_retry()
    }

    /// Runs one provider write behind the dispatch stamp.
    ///
    /// The stamp commits first and the conclusion is set to
    /// [`DispatchOutcome::Ambiguous`] before the closure is polled, so a
    /// dropped future leaves the record that a write may have landed. A
    /// second call on the same context is refused, because one attempt gets
    /// one write.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::AlreadyDispatched`] when this context already
    /// stamped a write, whatever the store returns from the stamp
    /// transaction, and whatever the closure returns.
    pub async fn run_write<T, F, Fut>(&self, operation: F) -> Result<T, BillingError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, BillingError>>,
    {
        self.stamp_write().await?;
        let result = operation().await;
        self.conclude_write(&result);
        result
    }

    /// Commits the dispatch stamp for a write the caller performs itself.
    ///
    /// The two halves of [`Self::run_write`], exposed separately for the one
    /// shape a closure cannot express: a rail whose protocol requires a read
    /// before its write. x402 must call `verify` and inspect the answer
    /// before it may call `settle`, and only `settle` moves money. Wrapping
    /// both in `run_write` would stamp a dispatch before the read, which
    /// would put an attempt into reconciliation every time a facilitator
    /// merely declined to verify.
    ///
    /// A caller that uses this owes the matching [`Self::conclude_write`].
    /// Between the two calls the attempt reads as ambiguous, which is the
    /// correct state for a write that is genuinely in flight: a process that
    /// dies in that window leaves a record saying the write may have landed.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::AlreadyDispatched`] when this context already
    /// stamped a write, and whatever the store returns from the stamp
    /// transaction. A stamp that fails to commit rolls the conclusion back,
    /// because nothing was sent and the caller may still retry safely.
    pub async fn stamp_write(&self) -> Result<(), BillingError> {
        self.outcome
            .compare_exchange(
                OUTCOME_NEVER_DISPATCHED,
                OUTCOME_AMBIGUOUS,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| BillingError::AlreadyDispatched)?;

        if let Err(error) = self.commit_dispatch_stamp().await {
            // The stamp did not commit, so nothing was sent. Roll the
            // conclusion back so the caller may still retry safely.
            self.outcome
                .store(OUTCOME_NEVER_DISPATCHED, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }

    /// Records what a completed write proved.
    ///
    /// Success resolves the attempt. A failure resolves it only when the
    /// error proves the provider refused, which is what
    /// [`is_authoritative_negative`] decides; anything else leaves the
    /// attempt ambiguous and therefore bound for reconciliation.
    ///
    /// Calling this without a preceding [`Self::stamp_write`] is harmless: a
    /// context that never dispatched stays never-dispatched, because the
    /// conclusion only moves off ambiguous.
    pub fn conclude_write<T>(&self, result: &Result<T, BillingError>) {
        match result {
            Ok(_) => self.resolve_if_dispatched(),
            Err(error) => {
                if is_authoritative_negative(error) {
                    self.resolve_if_dispatched();
                }
            }
        }
    }

    /// Moves an ambiguous conclusion to resolved, and nothing else.
    fn resolve_if_dispatched(&self) {
        let _ = self.outcome.compare_exchange(
            OUTCOME_AMBIGUOUS,
            OUTCOME_RESOLVED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Runs one read-only provider call.
    ///
    /// No stamp is committed and the conclusion is untouched, because a query
    /// cannot move funds. Reconciliation uses this and nothing else.
    ///
    /// # Errors
    ///
    /// Returns whatever the closure returns.
    pub async fn run_query<T, F, Fut>(&self, operation: F) -> Result<T, BillingError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, BillingError>>,
    {
        operation().await
    }

    /// Commits the dispatch stamp for whichever subject this gate holds.
    async fn commit_dispatch_stamp(&self) -> Result<(), BillingError> {
        let now_ms = self.clock.now_ms();
        match &self.subject {
            DispatchSubject::Attempt(attempt) => {
                self.store
                    .mark_dispatch_started(attempt.attempt_id(), attempt.lease_token(), now_ms)
                    .await
            }
            DispatchSubject::Usage(usage) => {
                self.store
                    .mark_usage_dispatch_started(
                        &usage.reporter,
                        &usage.usage_identifier,
                        &usage.lease_token,
                        now_ms,
                    )
                    .await
            }
        }
    }
}

impl std::fmt::Debug for DispatchContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DispatchContext")
            .field("subject", &self.subject)
            .field("outcome", &self.outcome())
            .finish()
    }
}

/// Reports whether a failure proves the provider refused the payment.
///
/// The bar is deliberately high. Only a provider that answered, and answered
/// that it will not settle, counts. A timeout, an unreachable host, and a
/// response that did not parse as the pinned contract all leave the write
/// outstanding: the request may well have been applied, and only a documented
/// status query or an idempotent response replay can say.
const fn is_authoritative_negative(error: &BillingError) -> bool {
    matches!(error, BillingError::ProviderRejected)
}
