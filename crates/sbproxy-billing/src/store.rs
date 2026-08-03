//! The durable settlement contract.
//!
//! Every transition that can authorize a request, move funds, or forget that
//! funds may already have moved goes through [`SettlementStore`]. The trait
//! is deliberately narrow and deliberately explicit about time: callers pass
//! `now_ms`, so a test can drive expiry and lease recovery without sleeping.
//!
//! # The rule the trait exists to enforce
//!
//! An attempt carries `dispatch_started_at_ms`. It is `NULL` until the
//! instant before a provider write leaves the process, and it is committed
//! in its own transaction. Everything downstream reads it:
//!
//! - [`SettlementStore::mark_retry_wait_before_dispatch`] refuses any
//!   attempt whose stamp is set. A retry is only safe when the write
//!   provably never happened.
//! - A dispatched attempt with no authoritative recorded response can move
//!   only to [`IntentStatus::NeedsReconciliation`]. Not to `RetryWait`, not
//!   to `Terminal`, and certainly not to `Succeeded`.
//! - Recovery of a stale lease follows the same fork: no stamp means the
//!   attempt returns to `RetryWait`; a stamp means it becomes
//!   `NeedsReconciliation`.
//!
//! Only a documented provider status query, or a documented idempotent
//! response replay, can resolve a reconciliation record. Ambiguity never
//! resolves itself and never increases an attempt generation.

use std::sync::Arc;

use crate::error::BillingError;
use crate::registry::{UsageEvent, UsageReportReceipt};
use crate::types::{
    AttemptOperation, AttemptStatus, IntentStatus, PaymentProtocol, PaymentRequirement,
    PaymentRequirementDraft, RecoveryEnvelopeRecord, SafeFailure, SettlementRail,
    SettlementReceipt, SignedPaymentRequirement,
};

/// A source of wall-clock time in milliseconds since the Unix epoch.
///
/// The store, the service, and the worker all read time through this trait
/// so tests can advance expiry and lease deadlines deterministically instead
/// of sleeping.
pub trait BillingClock: Send + Sync {
    /// Returns the current time in milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

/// The process clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl BillingClock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0)
    }
}

/// The result of creating or resuming a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateIntent {
    /// The durable intent identifier.
    pub intent_id: String,
    /// The intent's current state.
    pub status: IntentStatus,
    /// Whether this call inserted the row, as opposed to resuming one.
    pub created: bool,
    /// Digest of the immutable draft the row holds.
    pub draft_digest: [u8; 32],
    /// Digest of the final requirement, once one was finalized.
    pub requirement_digest: Option<[u8; 32]>,
    /// The committed receipt, present only when the intent already succeeded.
    pub receipt: Option<SettlementReceipt>,
}

/// A durable settlement intent, read back in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRecord {
    /// The durable intent identifier.
    pub intent_id: String,
    /// The tenant that owns the intent.
    pub tenant_id: String,
    /// The origin the paid request targets.
    pub origin_id: String,
    /// The route the paid request targets.
    pub route: String,
    /// The quote this intent prices.
    pub quote_id: String,
    /// The client idempotency key that created the intent.
    pub request_idempotency_key: String,
    /// The wire protocol.
    pub protocol: PaymentProtocol,
    /// The rail that settles.
    pub settlement_rail: SettlementRail,
    /// The intent's current state.
    pub status: IntentStatus,
    /// The immutable draft.
    pub draft: PaymentRequirementDraft,
    /// Digest of the immutable draft.
    pub draft_digest: [u8; 32],
    /// The final requirement, once finalized.
    pub requirement: Option<PaymentRequirement>,
    /// Digest of the final requirement, once finalized.
    pub requirement_digest: Option<[u8; 32]>,
    /// The signed quote token bound to the final requirement.
    pub quote_token: Option<String>,
    /// The unique nonce that quote token occupies.
    pub quote_nonce: Option<String>,
    /// The single proof digest this intent is bound to, once one arrived.
    pub reserved_proof_digest: Option<[u8; 32]>,
    /// Challenge expiry, in milliseconds since the epoch.
    pub expires_at_ms: i64,
    /// Creation time, in milliseconds since the epoch.
    pub created_at_ms: i64,
    /// Last transition time, in milliseconds since the epoch.
    pub updated_at_ms: i64,
}

impl IntentRecord {
    /// Reports whether this intent may authorize origin access right now.
    pub fn authorizes_origin(&self) -> bool {
        self.status.authorizes_origin()
    }

    /// Returns the finalized requirement, or fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::IntentNotFinalized`] when the challenge was
    /// never finalized and signed.
    pub fn finalized_requirement(&self) -> Result<&PaymentRequirement, BillingError> {
        self.requirement
            .as_ref()
            .ok_or(BillingError::IntentNotFinalized)
    }
}

/// One provider attempt, read back in full.
///
/// This is what a rail adapter receives when reconciliation asks it what
/// happened. It carries the provider handle and the idempotency key that
/// were persisted before the write, so the adapter can address the exact
/// object the lost dispatch may have created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAttempt {
    /// The durable attempt identifier.
    pub attempt_id: String,
    /// The intent this attempt belongs to.
    pub intent_id: String,
    /// The tenant that owns the intent.
    pub tenant_id: String,
    /// The rail this attempt talks to.
    pub rail: SettlementRail,
    /// The operation this attempt performs.
    pub operation: AttemptOperation,
    /// The generation, which only a proven non-dispatch may increase.
    pub attempt_generation: u32,
    /// The provider idempotency key, persisted before any write.
    pub provider_idempotency_key: String,
    /// The non-secret provider handle, when one is known.
    pub provider_handle: Option<String>,
    /// When the dispatch stamp was committed, if it was.
    pub dispatch_started_at_ms: Option<i64>,
    /// When an authoritative response was recorded, if one was.
    pub response_recorded_at_ms: Option<i64>,
    /// The attempt's current state.
    pub status: AttemptStatus,
    /// The finalized requirement, when the intent has one.
    pub requirement: Option<PaymentRequirement>,
}

impl ProviderAttempt {
    /// Reports whether a write may have landed with no recorded response.
    ///
    /// This is the exact condition that forbids a new write attempt and
    /// forbids a new idempotency key.
    pub const fn is_dispatched_unresolved(&self) -> bool {
        self.dispatch_started_at_ms.is_some() && self.response_recorded_at_ms.is_none()
    }
}

/// An attempt with a live lease held by the caller.
///
/// The lease token is required by every transition. A caller whose lease
/// expired and was recovered by someone else gets
/// [`BillingError::LeaseLost`] instead of silently racing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAttempt {
    /// The attempt itself.
    pub attempt: ProviderAttempt,
    /// The lease token that authorizes transitions on it.
    pub lease_token: String,
    /// When the lease expires, in milliseconds since the epoch.
    pub lease_expires_at_ms: i64,
    /// Whether this call inserted the attempt row, as opposed to resuming it.
    pub created: bool,
}

impl PreparedAttempt {
    /// Returns the durable attempt identifier.
    pub fn attempt_id(&self) -> &str {
        &self.attempt.attempt_id
    }

    /// Returns the lease token every transition on this attempt requires.
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }

    /// Returns the provider idempotency key persisted before any write.
    pub fn provider_idempotency_key(&self) -> &str {
        &self.attempt.provider_idempotency_key
    }

    /// Returns the rail this attempt talks to.
    pub fn rail(&self) -> SettlementRail {
        self.attempt.rail
    }

    /// Returns the operation this attempt performs.
    pub fn operation(&self) -> AttemptOperation {
        self.attempt.operation
    }
}

/// An attempt claimed by the recovery worker.
///
/// Structurally identical to [`PreparedAttempt`]: a claim is a lease, and a
/// lease is what authorizes transitions. The separate name marks intent at
/// the call site, because a claimed attempt may only ever be queried.
pub type ClaimedAttempt = PreparedAttempt;

/// The outcome of reserving a proof digest against an intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofReservation {
    /// The digest was newly reserved for this intent.
    Reserved,
    /// The digest was already reserved for this same intent, so the caller
    /// is resuming its own retry rather than replaying someone else's.
    AlreadyReservedForIntent,
    /// The intent already settled under this digest; here is the receipt.
    AlreadySettled(SettlementReceipt),
}

/// What a stale-lease sweep did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseRecovery {
    /// Attempts with no dispatch stamp, returned to `RetryWait`.
    pub returned_to_retry_wait: u64,
    /// Attempts with a dispatch stamp, moved to `NeedsReconciliation`.
    pub moved_to_needs_reconciliation: u64,
}

/// What reconciliation proved about an outstanding attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// The provider proved the payment settled; here is the real receipt.
    ProvenSucceeded(SettlementReceipt),
    /// The provider proved the write never landed, so a client retry may
    /// create a fresh attempt at the next generation.
    ProvenNotDispatched(SafeFailure),
    /// The provider proved the payment failed and no funds moved.
    ProvenFailed(SafeFailure),
    /// Nothing was proved. The record stays in reconciliation.
    Unresolved(SafeFailure),
}

/// What happened to one queued usage report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageOutcome {
    /// The reporter accepted the event; here is its receipt.
    Reported(UsageReportReceipt),
    /// The report failed and may be retried at the given time.
    Retry {
        /// When the next attempt becomes eligible.
        retry_at_ms: i64,
        /// The redacted failure.
        failure: SafeFailure,
    },
    /// The report failed definitively and will not be retried.
    Terminal(SafeFailure),
}

/// A queued usage event with a live lease and its idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedUsageEvent {
    /// The event to report.
    pub event: UsageEvent,
    /// The lease token that authorizes transitions on it.
    pub lease_token: String,
    /// The provider idempotency key, persisted before any write.
    pub provider_idempotency_key: String,
    /// Whether a previous dispatch stamp is outstanding for this event.
    pub previously_dispatched: bool,
}

/// The durable transitions that decide whether a request may be paid for.
///
/// Implementations must be safe across processes sharing one database file,
/// not merely across tasks in one process. Every method that mutates uses an
/// immediate transaction, and every conditional transition is a
/// compare-and-set rather than a read followed by a write.
#[async_trait::async_trait]
pub trait SettlementStore: Send + Sync {
    /// Creates the pending challenge, or resumes the existing one.
    ///
    /// The intent identifier is derived from the tenant and the request
    /// idempotency key, so a retry of the same logical request addresses the
    /// same row. Resuming requires the same draft bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::IntentConflict`] when the same idempotency
    /// key arrives with a different draft digest.
    async fn create_or_get_challenge(
        &self,
        draft: &PaymentRequirementDraft,
        draft_digest: [u8; 32],
        request_idempotency_key: &str,
    ) -> Result<CreateIntent, BillingError>;

    /// Commits the final requirement, its digest, and the signed quote.
    ///
    /// This is a compare-and-set against the stored draft digest, and it
    /// rejects a second, different final value. The quote nonce it derives
    /// is unique across the store, so one signed quote can bind to exactly
    /// one requirement.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::IntentNotFound`],
    /// [`BillingError::IntentConflict`], or [`BillingError::DigestMismatch`].
    async fn finalize_requirement(
        &self,
        intent_id: &str,
        signed: &SignedPaymentRequirement,
    ) -> Result<(), BillingError>;

    /// Returns the newest attempt for one intent and operation.
    ///
    /// The caller needs this before [`SettlementStore::prepare_attempt`],
    /// because the provider idempotency key is derived from the attempt
    /// generation and the generation is a durable fact rather than a guess. A
    /// caller that skips this and assumes generation zero is not wrong so much
    /// as stale: the store still resumes the row it finds, and the key it
    /// returns on the [`PreparedAttempt`] is the one that was persisted.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] when a stored row does not
    /// decode into the domain contract.
    async fn latest_attempt(
        &self,
        intent_id: &str,
        operation: AttemptOperation,
    ) -> Result<Option<ProviderAttempt>, BillingError>;

    /// Creates or resumes the attempt for one operation, and takes its lease.
    ///
    /// The provider idempotency key and any locally computable provider
    /// handle, such as an LND payment hash, are persisted in the same
    /// transaction as the attempt and before any dispatch. The returned
    /// attempt always has `dispatch_started_at_ms = NULL` on creation.
    ///
    /// The key argument is used when this call inserts a row. When it resumes
    /// one, the persisted key wins and is returned on the
    /// [`PreparedAttempt`], because changing the key of an outstanding attempt
    /// is exactly how a retry turns into a second charge.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseHeld`] when another holder has a live
    /// lease, [`BillingError::IntentNotFound`] when the intent is gone, and
    /// [`BillingError::InvalidStateTransition`] when the intent's state
    /// forbids a new provider write.
    async fn prepare_attempt(
        &self,
        intent_id: &str,
        operation: AttemptOperation,
        provider_idempotency_key: &str,
        known_provider_handle: Option<&str>,
        now_ms: i64,
    ) -> Result<PreparedAttempt, BillingError>;

    /// Commits the dispatch stamp immediately before a provider write.
    ///
    /// This is its own transaction on purpose. After it commits, no code
    /// path may conclude the write did not happen without asking the
    /// provider.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`] when the lease is no longer held.
    async fn mark_dispatch_started(
        &self,
        attempt_id: &str,
        lease_token: &str,
        now_ms: i64,
    ) -> Result<(), BillingError>;

    /// Commits the receipt and the `Succeeded` transition in one transaction.
    ///
    /// The attempt must be dispatched and its operation must be one that can
    /// settle, so a challenge preparation or a meter report can never reach
    /// this state.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`],
    /// [`BillingError::UnsupportedOperation`] for a non-settling operation,
    /// and [`BillingError::InvalidStateTransition`] when the attempt was
    /// never dispatched.
    async fn mark_succeeded(
        &self,
        attempt_id: &str,
        lease_token: &str,
        receipt: SettlementReceipt,
    ) -> Result<(), BillingError>;

    /// Returns an undispatched attempt to `RetryWait`.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::AlreadyDispatched`] when the dispatch stamp
    /// is set, and [`BillingError::LeaseLost`] when the lease is gone.
    async fn mark_retry_wait_before_dispatch(
        &self,
        attempt_id: &str,
        lease_token: &str,
        retry_at_ms: i64,
        failure: SafeFailure,
    ) -> Result<(), BillingError>;

    /// Records a definitive failure in which no funds moved.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`] when the lease is gone.
    async fn mark_terminal(
        &self,
        attempt_id: &str,
        lease_token: &str,
        failure: SafeFailure,
    ) -> Result<(), BillingError>;

    /// Records that a dispatch is outstanding with no authoritative response.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`] when the lease is gone.
    async fn mark_needs_reconciliation(
        &self,
        attempt_id: &str,
        lease_token: &str,
        failure: SafeFailure,
    ) -> Result<(), BillingError>;

    /// Records a successful challenge preparation and its provider handle.
    ///
    /// The intent stays `Pending`: preparing a challenge is not a payment,
    /// so this can never authorize anything.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`] or
    /// [`BillingError::UnsupportedOperation`] when the attempt is not a
    /// challenge preparation.
    async fn mark_challenge_prepared(
        &self,
        attempt_id: &str,
        lease_token: &str,
        provider_handle: Option<&str>,
        now_ms: i64,
    ) -> Result<(), BillingError>;

    /// Loads one intent in full.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] when a stored row does not
    /// decode into the domain contract.
    async fn load_intent(&self, intent_id: &str) -> Result<Option<IntentRecord>, BillingError>;

    /// Loads one attempt in full.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] when a stored row does not
    /// decode into the domain contract.
    async fn load_attempt(&self, attempt_id: &str)
        -> Result<Option<ProviderAttempt>, BillingError>;

    /// Loads the receipt that authorizes origin access, if there is one.
    ///
    /// Returns `None` for every state except [`IntentStatus::Succeeded`],
    /// including `NeedsReconciliation`. This is the single read the request
    /// path uses to decide access, so the state check lives inside it rather
    /// than at each call site.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] when a stored receipt does
    /// not decode or does not match its own key.
    async fn load_access_receipt(
        &self,
        intent_id: &str,
    ) -> Result<Option<SettlementReceipt>, BillingError>;

    /// Returns the oldest unresolved intent covering one route, if any.
    ///
    /// Unresolved means [`IntentStatus::NeedsReconciliation`] and nothing
    /// else. Those are the intents whose funds may already have moved and
    /// which no sweep will ever expire, so they are the only ones whose
    /// existence should stop a fresh bill for the same content.
    ///
    /// The request path reads this before pricing a new challenge. The key is
    /// the content, not the payer: nothing durable identifies who is paying,
    /// and a second challenge for a route whose first payment is unresolved is
    /// the shape of a double charge whoever presents it.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the query fails.
    async fn unresolved_intent_for_route(
        &self,
        tenant_id: &str,
        origin_id: &str,
        route: &str,
    ) -> Result<Option<String>, BillingError>;

    /// Reserves a proof digest for one intent, or reports the replay.
    ///
    /// The digest is unique per tenant, and one intent binds exactly one
    /// digest. The same idempotency key presenting the same proof resumes;
    /// anything else is a replay.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ProofReplayed`] when the digest already
    /// belongs to another intent, and [`BillingError::ProofConflict`] when
    /// this intent is already bound to a different digest.
    async fn reserve_proof(
        &self,
        intent_id: &str,
        proof_digest: [u8; 32],
        now_ms: i64,
    ) -> Result<ProofReservation, BillingError>;

    /// Stores the encrypted recovery envelope for a replayable write.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the write fails.
    async fn put_recovery_envelope(
        &self,
        envelope: &RecoveryEnvelopeRecord,
    ) -> Result<(), BillingError>;

    /// Loads the recovery envelope for one attempt.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] when the stored row is not a
    /// well-formed envelope.
    async fn load_recovery_envelope(
        &self,
        attempt_id: &str,
    ) -> Result<Option<RecoveryEnvelopeRecord>, BillingError>;

    /// Deletes the recovery envelope for one attempt.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the delete fails.
    async fn purge_recovery_envelope(&self, attempt_id: &str) -> Result<(), BillingError>;

    /// Deletes every recovery envelope past its hard expiry.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the delete fails.
    async fn purge_expired_recovery_envelopes(&self, now_ms: i64) -> Result<u64, BillingError>;

    /// Moves expired pending challenges to `Terminal`.
    ///
    /// A challenge that expired never dispatched anything, so this can never
    /// forget an outstanding write.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the sweep fails.
    async fn expire_stale_challenges(&self, now_ms: i64, limit: u32) -> Result<u64, BillingError>;

    /// Recovers attempts whose lease expired.
    ///
    /// Undispatched attempts return to `RetryWait`. Dispatched attempts
    /// become `NeedsReconciliation`, because their write may have landed.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the sweep fails.
    async fn recover_stale_leases(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<LeaseRecovery, BillingError>;

    /// Claims reconciliation work, taking a lease on each attempt.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the claim fails.
    async fn claim_reconciliation(
        &self,
        now_ms: i64,
        lease_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<ClaimedAttempt>, BillingError>;

    /// Records what reconciliation proved.
    ///
    /// [`ReconciliationOutcome::ProvenSucceeded`] commits the receipt and
    /// the `Succeeded` transition. Everything else leaves the intent unable
    /// to authorize a request, and only `ProvenNotDispatched` permits a
    /// later client retry to create a fresh attempt generation.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`] when the lease is gone.
    async fn record_reconciliation(
        &self,
        attempt_id: &str,
        lease_token: &str,
        outcome: ReconciliationOutcome,
        now_ms: i64,
    ) -> Result<(), BillingError>;

    /// Queues one usage event, deduplicated by reporter and identifier.
    ///
    /// Returns `false` when the identifier was already queued or reported.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the write fails.
    async fn enqueue_usage_event(&self, event: &UsageEvent) -> Result<bool, BillingError>;

    /// Claims queued usage events, taking a lease on each.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the claim fails.
    async fn claim_usage_events(
        &self,
        now_ms: i64,
        lease_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<ClaimedUsageEvent>, BillingError>;

    /// Commits the dispatch stamp for one usage report.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`] when the lease is gone.
    async fn mark_usage_dispatch_started(
        &self,
        reporter: &str,
        usage_identifier: &str,
        lease_token: &str,
        now_ms: i64,
    ) -> Result<(), BillingError>;

    /// Records what happened to one usage report.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::LeaseLost`] when the lease is gone.
    async fn record_usage_outcome(
        &self,
        reporter: &str,
        usage_identifier: &str,
        lease_token: &str,
        outcome: UsageOutcome,
        now_ms: i64,
    ) -> Result<(), BillingError>;
}

/// A boxed, shareable settlement store.
pub type SharedSettlementStore = Arc<dyn SettlementStore>;
