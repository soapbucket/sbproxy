//! The authoritative path from a credential to origin access.
//!
//! [`BillingService::authorize`] is the only function in this crate that can
//! return permission to reach the origin, and it returns
//! [`AuthorizationDecision::Settled`] from exactly one place: a receipt that
//! [`SettlementStore::mark_succeeded`] committed and that
//! [`SettlementStore::load_access_receipt`] read back. Not the adapter's
//! return value, not a verification result, and not an optimistic guess.
//!
//! # Ordering
//!
//! The credential path is fixed, and each step exists because skipping it
//! would allow a double charge or an unpaid request:
//!
//! 1. Verify the signed requirement locally, digests first.
//! 2. Load the durable intent. A credential can never create one, so a
//!    request with no challenge fails closed before any provider call.
//! 3. Reserve the proof digest against that one intent. A replay of another
//!    intent's credential stops here.
//! 4. Prepare the attempt and persist its provider idempotency key.
//! 5. Call the adapter under a bounded deadline, through the dispatch gate.
//! 6. Record the durable result: success, definite failure, safe retry, or
//!    reconciliation.
//! 7. Read the committed receipt back, and only then return `Settled`.
//!
//! # What the failure modes map to
//!
//! | Situation | Durable transition | Decision |
//! | --- | --- | --- |
//! | Adapter settled and the receipt committed | `Succeeded` | `Settled` |
//! | Provider refused | `Terminal` | `PaymentRequired` |
//! | Deadline elapsed before any dispatch | `RetryWait` | `Unavailable` |
//! | Deadline elapsed after dispatch | `NeedsReconciliation` | `Unavailable` |
//! | Malformed or unparseable provider success | `NeedsReconciliation` | `Unavailable` |
//! | Verified but not settled | `NeedsReconciliation` | `Unavailable` |
//!
//! There is no row in that table where a request reaches the origin without a
//! committed receipt.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::dispatch::{DispatchContext, DispatchOutcome, UsageDispatch};
use crate::error::BillingError;
use crate::registry::{
    AuthoritativePayment, ChallengePreparation, ProviderQueryResult, RailRegistry,
};
use crate::store::{
    BillingClock, ClaimedAttempt, ClaimedUsageEvent, IntentRecord, LeaseRecovery, ProofReservation,
    ReconciliationOutcome, SettlementStore, SharedSettlementStore, SystemClock, UsageOutcome,
};
use crate::types::{
    digests_equal, provider_idempotency_key, AttemptOperation, FailureCategory, IntentStatus,
    PaymentProof, PaymentRequirement, PaymentRequirementDraft, SafeFailure, SettlementReceipt,
    SignedPaymentRequirement,
};

#[cfg(feature = "recovery-crypto")]
use crate::recovery_crypto::RecoveryCipher;

/// The hard ceiling on the synchronous authorization deadline.
///
/// Every pinned rail contract fits inside two seconds, and a request path that
/// waits longer than this is holding a connection open for a payment that
/// should have moved to reconciliation.
pub const MAX_AUTHORIZATION_DEADLINE_MS: u64 = 2_000;

/// Signs and verifies the quote token bound to a final requirement.
///
/// This crate does not own the signing key. The proxy does, so the signing
/// step is injected and this crate never sees key material.
pub trait RequirementSigner: Send + Sync {
    /// Signs the final requirement digest into a quote token.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] describing the redacted failure.
    fn sign(
        &self,
        requirement: &PaymentRequirement,
        requirement_digest: &[u8; 32],
    ) -> Result<String, BillingError>;

    /// Verifies that a presented quote token signs the digest it carries.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] describing the redacted failure.
    fn verify(&self, signed: &SignedPaymentRequirement) -> Result<(), BillingError>;
}

/// What the proxy hands over to have a challenge prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementInput {
    /// The compiled draft, which this call canonicalizes and hashes.
    pub draft: PaymentRequirementDraft,
    /// The client's idempotency key for this logical request.
    pub request_idempotency_key: String,
}

/// A prepared 402 challenge.
///
/// This struct has no `Debug` because a rail may have issued a one-shot client
/// secret. That value belongs in the immediate response and nowhere else: it
/// is never persisted, never hashed, and never logged.
pub struct PreparedPaymentResponse {
    /// The durable intent this challenge belongs to.
    pub intent_id: String,
    /// The finalized, signed requirement.
    pub signed: SignedPaymentRequirement,
    /// Non-secret fields the protocol codec renders onto the wire.
    pub challenge_fields: BTreeMap<String, String>,
    /// A one-shot client secret, when the rail issued one.
    pub client_secret: Option<Zeroizing<String>>,
}

/// A credential presented against a previously issued challenge.
///
/// This struct has no `Debug` because it carries a live payment credential.
pub struct RedemptionRequest {
    /// The requirement the client is redeeming.
    pub signed: SignedPaymentRequirement,
    /// The client's idempotency key, which addresses the durable intent.
    pub request_idempotency_key: String,
    /// The credential.
    pub proof: PaymentProof,
}

/// The closed set of reasons a payment did not authorize a request.
///
/// Cardinality is fixed so this can be a metric label and a problem-document
/// code without leaking provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymentProblemCode {
    /// No durable challenge exists for this request.
    ChallengeMissing,
    /// The challenge exists but was never finalized and signed.
    ChallengeNotFinalized,
    /// The challenge passed its expiry.
    ChallengeExpired,
    /// The presented requirement is not the one that was advertised.
    RequirementMismatch,
    /// The credential was malformed or used an unknown scheme.
    ProofInvalid,
    /// The credential already settled a different intent.
    ProofReplayed,
    /// The provider refused the payment.
    Rejected,
    /// The rail reached a verified but not settled state.
    NotSettled,
    /// No adapter is compiled and registered for this rail.
    RailUnsupported,
    /// This crate got something wrong.
    Internal,
}

impl PaymentProblemCode {
    /// Returns the stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChallengeMissing => "challenge_missing",
            Self::ChallengeNotFinalized => "challenge_not_finalized",
            Self::ChallengeExpired => "challenge_expired",
            Self::RequirementMismatch => "requirement_mismatch",
            Self::ProofInvalid => "proof_invalid",
            Self::ProofReplayed => "proof_replayed",
            Self::Rejected => "rejected",
            Self::NotSettled => "not_settled",
            Self::RailUnsupported => "rail_unsupported",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for PaymentProblemCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redacted description of why a payment did not authorize a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentProblem {
    /// The closed-cardinality reason.
    pub code: PaymentProblemCode,
    /// The redacted durable failure behind it.
    pub failure: SafeFailure,
    /// How long the client should wait, when waiting could help.
    pub retry_after_seconds: Option<u32>,
}

impl PaymentProblem {
    /// Builds a problem from a code and a redacted failure.
    pub fn new(code: PaymentProblemCode, failure: SafeFailure) -> Self {
        Self {
            code,
            failure,
            retry_after_seconds: None,
        }
    }
}

/// What the authoritative path decided.
///
/// Only [`AuthorizationDecision::Settled`] permits origin access, and it
/// carries the committed receipt rather than a promise of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    /// A receipt is committed and the request may reach the origin.
    Settled(SettlementReceipt),
    /// The payment did not settle. The client owes another attempt.
    PaymentRequired(PaymentProblem),
    /// The payment is outstanding or the rail is unreachable. Nothing about
    /// the funds is asserted here, which is why it is not a refusal.
    Unavailable {
        /// How long the client should wait before trying again.
        retry_after_seconds: u32,
    },
}

impl AuthorizationDecision {
    /// Reports whether this decision lets the request reach the origin.
    pub const fn authorizes_origin(&self) -> bool {
        matches!(self, Self::Settled(_))
    }
}

/// Builds a [`BillingService`].
pub struct BillingServiceBuilder {
    store: SharedSettlementStore,
    adapters: RailRegistry,
    clock: Arc<dyn BillingClock>,
    signer: Option<Arc<dyn RequirementSigner>>,
    deadline: Duration,
    retry_after_seconds: u32,
    retry_backoff_ms: i64,
    #[cfg(feature = "recovery-crypto")]
    recovery_cipher: Option<RecoveryCipher>,
}

impl BillingServiceBuilder {
    /// Starts a builder over a durable store.
    pub fn new(store: SharedSettlementStore) -> Self {
        Self {
            store,
            adapters: RailRegistry::new(),
            clock: Arc::new(SystemClock),
            signer: None,
            deadline: Duration::from_millis(MAX_AUTHORIZATION_DEADLINE_MS),
            retry_after_seconds: 2,
            retry_backoff_ms: 1_000,
            #[cfg(feature = "recovery-crypto")]
            recovery_cipher: None,
        }
    }

    /// Installs the compiled rail and reporter registry.
    #[must_use]
    pub fn adapters(mut self, adapters: RailRegistry) -> Self {
        self.adapters = adapters;
        self
    }

    /// Replaces the clock, which tests use to drive expiry without sleeping.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn BillingClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Installs the quote signer.
    #[must_use]
    pub fn signer(mut self, signer: Arc<dyn RequirementSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Sets how long the client should wait after an unavailable decision.
    #[must_use]
    pub const fn retry_after_seconds(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = seconds;
        self
    }

    /// Sets how long an undispatched attempt waits before it may retry.
    #[must_use]
    pub const fn retry_backoff_ms(mut self, backoff_ms: i64) -> Self {
        self.retry_backoff_ms = backoff_ms;
        self
    }

    /// Installs the recovery cipher for replayable provider writes.
    #[cfg(feature = "recovery-crypto")]
    #[must_use]
    pub fn recovery_cipher(mut self, cipher: RecoveryCipher) -> Self {
        self.recovery_cipher = Some(cipher);
        self
    }

    /// Sets the total synchronous authorization deadline.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::DeadlineTooLong`] above
    /// [`MAX_AUTHORIZATION_DEADLINE_MS`], and
    /// [`BillingError::InvalidRequirement`] for a zero deadline.
    pub fn deadline(mut self, deadline: Duration) -> Result<Self, BillingError> {
        if deadline.is_zero() {
            return Err(BillingError::InvalidRequirement("authorization_deadline"));
        }
        if deadline > Duration::from_millis(MAX_AUTHORIZATION_DEADLINE_MS) {
            return Err(BillingError::DeadlineTooLong);
        }
        self.deadline = deadline;
        Ok(self)
    }

    /// Finishes the service.
    pub fn build(self) -> BillingService {
        BillingService {
            store: self.store,
            adapters: self.adapters,
            clock: self.clock,
            signer: self.signer,
            deadline: self.deadline,
            retry_after_seconds: self.retry_after_seconds,
            retry_backoff_ms: self.retry_backoff_ms,
            #[cfg(feature = "recovery-crypto")]
            recovery_cipher: self.recovery_cipher,
        }
    }
}

/// The authoritative billing service.
pub struct BillingService {
    store: SharedSettlementStore,
    adapters: RailRegistry,
    clock: Arc<dyn BillingClock>,
    signer: Option<Arc<dyn RequirementSigner>>,
    deadline: Duration,
    retry_after_seconds: u32,
    retry_backoff_ms: i64,
    #[cfg(feature = "recovery-crypto")]
    recovery_cipher: Option<RecoveryCipher>,
}

impl BillingService {
    /// Starts a builder over a durable store.
    pub fn builder(store: SharedSettlementStore) -> BillingServiceBuilder {
        BillingServiceBuilder::new(store)
    }

    /// Returns the durable store, which the worker schedules against.
    pub fn store(&self) -> &SharedSettlementStore {
        &self.store
    }

    /// Returns the compiled rail and reporter registry.
    pub fn adapters(&self) -> &RailRegistry {
        &self.adapters
    }

    /// Returns the clock every durable stamp is taken from.
    pub fn clock(&self) -> &Arc<dyn BillingClock> {
        &self.clock
    }

    /// Returns the recovery cipher, when one is configured.
    #[cfg(feature = "recovery-crypto")]
    pub fn recovery_cipher(&self) -> Option<&RecoveryCipher> {
        self.recovery_cipher.as_ref()
    }

    /// Prepares and signs one challenge, persisting it before it is returned.
    ///
    /// The order is durable first: the canonical draft and its digest are
    /// persisted, then the challenge attempt and its idempotency key, then the
    /// provider object is created through the dispatch gate, and only then is
    /// the complete requirement hashed, signed, and finalized. A crash at any
    /// point leaves a record that names the provider object rather than a
    /// reason to create a second one.
    ///
    /// This never captures funds, never calls the origin, and never emits a
    /// receipt.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`] for a draft that does not
    /// canonicalize, [`BillingError::AdapterNotRegistered`] when the rail was
    /// not compiled in, and whatever the store or the adapter returns.
    pub async fn prepare_requirement(
        &self,
        input: RequirementInput,
    ) -> Result<PreparedPaymentResponse, BillingError> {
        let RequirementInput {
            mut draft,
            request_idempotency_key,
        } = input;
        draft.canonicalize()?;
        let draft_digest = draft.digest()?;
        let now_ms = self.clock.now_ms();

        let created = self
            .store
            .create_or_get_challenge(&draft, draft_digest, &request_idempotency_key)
            .await?;

        // A challenge that was already finalized is re-issued as it stands.
        // Signing a second one would put two live requirements on one intent.
        if created.requirement_digest.is_some() {
            let intent = self
                .store
                .load_intent(&created.intent_id)
                .await?
                .ok_or(BillingError::IntentNotFound)?;
            return Ok(PreparedPaymentResponse {
                intent_id: created.intent_id,
                signed: rebuild_signed(&intent)?,
                challenge_fields: BTreeMap::new(),
                client_secret: None,
            });
        }

        let signer = self.signer.clone().ok_or(BillingError::InvalidRequirement(
            "requirement_signer_not_configured",
        ))?;
        let rail = draft.settlement_rail;
        let adapter = self.adapters.require_adapter(rail)?;

        // A process that stopped between creating the provider object and
        // signing the quote already has a provider object. Reuse its handle
        // rather than creating a second one under a second key.
        if let Some(previous) = self
            .store
            .latest_attempt(&created.intent_id, AttemptOperation::PrepareChallenge)
            .await?
        {
            if previous.status == crate::types::AttemptStatus::Succeeded {
                let requirement = PaymentRequirement {
                    draft,
                    provider_handle: previous.provider_handle,
                };
                let requirement_digest = requirement.digest()?;
                let quote_token = signer.sign(&requirement, &requirement_digest)?;
                let signed = SignedPaymentRequirement {
                    requirement,
                    draft_digest,
                    requirement_digest,
                    quote_token,
                };
                self.store
                    .finalize_requirement(&created.intent_id, &signed)
                    .await?;
                return Ok(PreparedPaymentResponse {
                    intent_id: created.intent_id,
                    signed,
                    challenge_fields: BTreeMap::new(),
                    client_secret: None,
                });
            }
        }

        let key = provider_idempotency_key(
            rail,
            AttemptOperation::PrepareChallenge,
            &draft.tenant_id,
            &draft.requirement_id,
            0,
            None,
        );
        let prepared = self
            .store
            .prepare_attempt(
                &created.intent_id,
                AttemptOperation::PrepareChallenge,
                &key,
                None,
                now_ms,
            )
            .await?;

        let dispatch = DispatchContext::for_attempt(
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
            prepared.clone(),
        );
        let request = ChallengePreparation {
            intent_id: created.intent_id.clone(),
            draft: draft.clone(),
            draft_digest,
            now_ms,
        };
        let material = match adapter.prepare_challenge(request, &dispatch).await {
            Ok(material) => material,
            Err(error) => {
                self.record_failed_attempt(&prepared, &dispatch, &error)
                    .await;
                return Err(error);
            }
        };

        self.store
            .mark_challenge_prepared(
                prepared.attempt_id(),
                prepared.lease_token(),
                material.provider_handle.as_deref(),
                self.clock.now_ms(),
            )
            .await?;

        let requirement = PaymentRequirement {
            draft,
            provider_handle: material.provider_handle,
        };
        let requirement_digest = requirement.digest()?;
        let quote_token = signer.sign(&requirement, &requirement_digest)?;
        let signed = SignedPaymentRequirement {
            requirement,
            draft_digest,
            requirement_digest,
            quote_token,
        };
        self.store
            .finalize_requirement(&created.intent_id, &signed)
            .await?;

        Ok(PreparedPaymentResponse {
            intent_id: created.intent_id,
            signed,
            challenge_fields: material.challenge_fields,
            client_secret: material.client_secret,
        })
    }

    /// Authorizes one credential against its durable challenge.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] only when the store itself could not answer.
    /// Every payment outcome, including refusal, is an
    /// [`AuthorizationDecision`] rather than an error, because the caller has
    /// to render a response either way.
    pub async fn authorize(
        &self,
        request: RedemptionRequest,
    ) -> Result<AuthorizationDecision, BillingError> {
        let RedemptionRequest {
            signed,
            request_idempotency_key,
            proof,
        } = request;

        if let Err(error) = signed.verify_digests() {
            return Ok(refuse(PaymentProblemCode::RequirementMismatch, &error));
        }
        if let Some(signer) = &self.signer {
            if let Err(error) = signer.verify(&signed) {
                return Ok(refuse(PaymentProblemCode::RequirementMismatch, &error));
            }
        }

        let draft = &signed.requirement.draft;
        let intent_id = crate::types::derive_intent_id(&draft.tenant_id, &request_idempotency_key);
        let Some(intent) = self.store.load_intent(&intent_id).await? else {
            return Ok(refuse(
                PaymentProblemCode::ChallengeMissing,
                &BillingError::IntentNotFound,
            ));
        };

        // The presented requirement must be the one the store finalized.
        let Some(stored_digest) = intent.requirement_digest else {
            return Ok(refuse(
                PaymentProblemCode::ChallengeNotFinalized,
                &BillingError::IntentNotFinalized,
            ));
        };
        if !digests_equal(&stored_digest, &signed.requirement_digest)
            || !digests_equal(&intent.draft_digest, &signed.draft_digest)
        {
            return Ok(refuse(
                PaymentProblemCode::RequirementMismatch,
                &BillingError::RequirementMismatch,
            ));
        }

        let now_ms = self.clock.now_ms();
        let proof_digest = proof.digest();

        // Binding the credential comes before any expiry or state judgement,
        // so a repeat of a settled request returns its stored receipt and a
        // replayed credential is caught even after the challenge expired.
        let reservation = match self
            .store
            .reserve_proof(&intent_id, proof_digest, now_ms)
            .await
        {
            Ok(reservation) => reservation,
            Err(error @ (BillingError::ProofReplayed | BillingError::ProofConflict)) => {
                return Ok(refuse(PaymentProblemCode::ProofReplayed, &error));
            }
            Err(error) => return Err(error),
        };
        if let ProofReservation::AlreadySettled(receipt) = reservation {
            return Ok(AuthorizationDecision::Settled(receipt));
        }

        if intent.status == IntentStatus::Succeeded {
            // Belt and braces: a succeeded intent must present its receipt or
            // authorize nothing at all.
            return match self.store.load_access_receipt(&intent_id).await? {
                Some(receipt) => Ok(AuthorizationDecision::Settled(receipt)),
                None => Ok(unavailable(self.retry_after_seconds)),
            };
        }
        if intent.draft.is_expired(now_ms) {
            return Ok(refuse(
                PaymentProblemCode::ChallengeExpired,
                &BillingError::IntentExpired,
            ));
        }
        if intent.status == IntentStatus::Terminal {
            return Ok(refuse(
                PaymentProblemCode::Rejected,
                &BillingError::ProviderRejected,
            ));
        }
        if intent.status == IntentStatus::NeedsReconciliation {
            // A write is outstanding. Trying again here is how a double charge
            // happens, so the client waits for the worker instead.
            return Ok(unavailable(self.retry_after_seconds));
        }

        let rail = intent.settlement_rail;
        let adapter = match self.adapters.require_adapter(rail) {
            Ok(adapter) => adapter,
            Err(error) => return Ok(refuse(PaymentProblemCode::RailUnsupported, &error)),
        };

        let generation = self
            .store
            .latest_attempt(&intent_id, AttemptOperation::Settle)
            .await?
            .map_or(0, |attempt| {
                if attempt.status == crate::types::AttemptStatus::Terminal {
                    attempt.attempt_generation + 1
                } else {
                    attempt.attempt_generation
                }
            });
        let key = provider_idempotency_key(
            rail,
            AttemptOperation::Settle,
            &intent.tenant_id,
            &intent.draft.requirement_id,
            generation,
            Some(&proof_digest),
        );
        let prepared = match self
            .store
            .prepare_attempt(
                &intent_id,
                AttemptOperation::Settle,
                &key,
                signed.requirement.provider_handle.as_deref(),
                now_ms,
            )
            .await
        {
            Ok(prepared) => prepared,
            // Someone else is already settling this exact intent, or a write
            // is outstanding. Both mean this request must not send anything.
            Err(BillingError::LeaseHeld | BillingError::NeedsReconciliation) => {
                return Ok(unavailable(self.retry_after_seconds));
            }
            Err(BillingError::InvalidStateTransition { .. }) => {
                return match self.store.load_access_receipt(&intent_id).await? {
                    Some(receipt) => Ok(AuthorizationDecision::Settled(receipt)),
                    None => Ok(unavailable(self.retry_after_seconds)),
                };
            }
            Err(error) => return Err(error),
        };

        let dispatch = DispatchContext::for_attempt(
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
            prepared.clone(),
        );
        let payment = AuthoritativePayment {
            intent_id: intent_id.clone(),
            requirement: signed.requirement.clone(),
            requirement_digest: signed.requirement_digest,
            proof,
            now_ms,
        };

        let settled = match tokio::time::timeout(
            self.deadline,
            adapter.authorize_and_settle(payment, &dispatch),
        )
        .await
        {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) => {
                let decision = self
                    .record_failed_attempt(&prepared, &dispatch, &error)
                    .await;
                return Ok(decision);
            }
            Err(_elapsed) => {
                let decision = self
                    .record_failed_attempt(&prepared, &dispatch, &BillingError::ProviderTimeout)
                    .await;
                return Ok(decision);
            }
        };

        if settled.intent_id != intent_id || settled.validate().is_err() {
            // A receipt that does not describe this intent, or does not match
            // its own key, is not evidence of anything. It is also not
            // evidence that nothing happened: the write went out, so this is
            // reconciliation rather than a refusal.
            let failure = SafeFailure::category(FailureCategory::Malformed, false);
            let recorded = if dispatch.was_dispatched() {
                self.store
                    .mark_needs_reconciliation(
                        prepared.attempt_id(),
                        prepared.lease_token(),
                        failure,
                    )
                    .await
            } else {
                self.store
                    .mark_retry_wait_before_dispatch(
                        prepared.attempt_id(),
                        prepared.lease_token(),
                        self.clock.now_ms().saturating_add(self.retry_backoff_ms),
                        failure,
                    )
                    .await
            };
            if let Err(error) = recorded {
                tracing::warn!(
                    attempt_id = prepared.attempt_id(),
                    category = %SafeFailure::from(&error).category,
                    "could not record a malformed provider receipt",
                );
            }
            return Ok(unavailable(self.retry_after_seconds));
        }

        self.store
            .mark_succeeded(prepared.attempt_id(), prepared.lease_token(), settled)
            .await?;

        // The decision comes from the committed row, never from the adapter.
        match self.store.load_access_receipt(&intent_id).await? {
            Some(receipt) => Ok(AuthorizationDecision::Settled(receipt)),
            None => Ok(unavailable(self.retry_after_seconds)),
        }
    }

    /// Asks a provider what happened to one outstanding attempt.
    ///
    /// This is the only path that can resolve reconciliation, and it can only
    /// call [`crate::registry::PaymentMethodAdapter::query_attempt`]. It never
    /// settles, never confirms, and never captures.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] when the durable record could not be
    /// written. An unresolved query is an outcome, not an error.
    pub async fn reconcile_attempt(
        &self,
        claimed: ClaimedAttempt,
    ) -> Result<ReconciliationOutcome, BillingError> {
        let now_ms = self.clock.now_ms();
        let attempt = claimed.attempt.clone();
        let dispatch = DispatchContext::for_attempt(
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
            claimed.clone(),
        );

        let outcome = match self.adapters.adapter(attempt.rail) {
            None => ReconciliationOutcome::Unresolved(SafeFailure::category(
                FailureCategory::Unsupported,
                false,
            )),
            Some(adapter) => {
                match dispatch
                    .run_query(|| adapter.query_attempt(&attempt, &dispatch))
                    .await
                {
                    Ok(ProviderQueryResult::Settled(receipt)) => {
                        ReconciliationOutcome::ProvenSucceeded(receipt)
                    }
                    Ok(ProviderQueryResult::NotDispatched) => {
                        ReconciliationOutcome::ProvenNotDispatched(SafeFailure::category(
                            FailureCategory::Unavailable,
                            true,
                        ))
                    }
                    Ok(ProviderQueryResult::Failed(failure)) => {
                        ReconciliationOutcome::ProvenFailed(failure)
                    }
                    Ok(ProviderQueryResult::StillPending) => ReconciliationOutcome::Unresolved(
                        SafeFailure::category(FailureCategory::Ambiguous, true),
                    ),
                    Ok(ProviderQueryResult::Unsupported) => ReconciliationOutcome::Unresolved(
                        SafeFailure::category(FailureCategory::Unsupported, false),
                    ),
                    Err(error) => ReconciliationOutcome::Unresolved(SafeFailure::from(&error)),
                }
            }
        };

        self.store
            .record_reconciliation(
                claimed.attempt_id(),
                claimed.lease_token(),
                outcome.clone(),
                now_ms,
            )
            .await?;
        Ok(outcome)
    }

    /// Reports one queued usage event.
    ///
    /// Usage accounting never authorizes anything. The reporter cannot build a
    /// [`SettlementReceipt`], and this method never touches an intent.
    ///
    /// # Errors
    ///
    /// Returns a [`BillingError`] when the durable record could not be
    /// written.
    pub async fn report_usage_event(
        &self,
        claimed: ClaimedUsageEvent,
    ) -> Result<UsageOutcome, BillingError> {
        let now_ms = self.clock.now_ms();
        let Some(reporter) = self.adapters.reporter(&claimed.event.reporter) else {
            let outcome =
                UsageOutcome::Terminal(SafeFailure::category(FailureCategory::Unsupported, false));
            self.store
                .record_usage_outcome(
                    &claimed.event.reporter,
                    &claimed.event.usage_identifier,
                    &claimed.lease_token,
                    outcome.clone(),
                    now_ms,
                )
                .await?;
            return Ok(outcome);
        };

        let dispatch = DispatchContext::for_usage(
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
            UsageDispatch {
                reporter: claimed.event.reporter.clone(),
                usage_identifier: claimed.event.usage_identifier.clone(),
                lease_token: claimed.lease_token.clone(),
                provider_idempotency_key: claimed.provider_idempotency_key.clone(),
                previously_dispatched: claimed.previously_dispatched,
            },
        );
        let event = claimed.event.clone();
        // The reporter drives the gate itself, exactly as a settlement
        // adapter does in `authorize`. Wrapping the call here too made the
        // reporter's own `run_write` lose its compare-exchange, so the
        // provider call was skipped and every usage report came back as a
        // terminal ambiguous failure with nothing ever sent.
        let outcome = match reporter.report(&event, &dispatch).await {
            Ok(receipt) => UsageOutcome::Reported(receipt),
            Err(error) if error.is_retryable() => UsageOutcome::Retry {
                retry_at_ms: now_ms.saturating_add(self.retry_backoff_ms),
                failure: SafeFailure::from(&error),
            },
            Err(error) => UsageOutcome::Terminal(SafeFailure::from(&error)),
        };

        self.store
            .record_usage_outcome(
                &claimed.event.reporter,
                &claimed.event.usage_identifier,
                &claimed.lease_token,
                outcome.clone(),
                now_ms,
            )
            .await?;
        Ok(outcome)
    }

    /// Moves expired pending challenges to their terminal state.
    ///
    /// # Errors
    ///
    /// Returns whatever the store returns.
    pub async fn expire_challenges(&self, limit: u32) -> Result<u64, BillingError> {
        self.store
            .expire_stale_challenges(self.clock.now_ms(), limit)
            .await
    }

    /// Recovers attempts whose lease expired.
    ///
    /// # Errors
    ///
    /// Returns whatever the store returns.
    pub async fn recover_leases(&self, limit: u32) -> Result<LeaseRecovery, BillingError> {
        self.store
            .recover_stale_leases(self.clock.now_ms(), limit)
            .await
    }

    /// Deletes every recovery envelope past its hard expiry.
    ///
    /// # Errors
    ///
    /// Returns whatever the store returns.
    pub async fn purge_expired_envelopes(&self) -> Result<u64, BillingError> {
        self.store
            .purge_expired_recovery_envelopes(self.clock.now_ms())
            .await
    }

    /// Returns the configured synchronous authorization deadline.
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Records the durable consequence of a failed provider call.
    ///
    /// The fork is the dispatch gate's conclusion, never the error text: an
    /// attempt that never dispatched may retry, an attempt that dispatched and
    /// was refused is terminal, and everything else is reconciliation.
    async fn record_failed_attempt(
        &self,
        prepared: &crate::store::PreparedAttempt,
        dispatch: &DispatchContext,
        error: &BillingError,
    ) -> AuthorizationDecision {
        let failure = SafeFailure::from(error);
        let now_ms = self.clock.now_ms();
        let recorded = match dispatch.outcome() {
            DispatchOutcome::NeverDispatched => {
                let result = self
                    .store
                    .mark_retry_wait_before_dispatch(
                        prepared.attempt_id(),
                        prepared.lease_token(),
                        now_ms.saturating_add(self.retry_backoff_ms),
                        failure.clone(),
                    )
                    .await;
                result.map(|()| unavailable(self.retry_after_seconds))
            }
            DispatchOutcome::Resolved => {
                let result = self
                    .store
                    .mark_terminal(
                        prepared.attempt_id(),
                        prepared.lease_token(),
                        failure.clone(),
                    )
                    .await;
                result.map(|()| refuse(PaymentProblemCode::Rejected, error))
            }
            DispatchOutcome::Ambiguous => {
                let result = self
                    .store
                    .mark_needs_reconciliation(
                        prepared.attempt_id(),
                        prepared.lease_token(),
                        failure.clone(),
                    )
                    .await;
                result.map(|()| unavailable(self.retry_after_seconds))
            }
        };

        match recorded {
            Ok(decision) => decision,
            Err(store_error) => {
                // The durable record is what authorizes, so a store failure
                // here can only ever produce a refusal to authorize.
                tracing::warn!(
                    attempt_id = prepared.attempt_id(),
                    outcome = dispatch.outcome().as_str(),
                    category = %SafeFailure::from(&store_error).category,
                    "could not record payment attempt failure",
                );
                unavailable(self.retry_after_seconds)
            }
        }
    }
}

impl std::fmt::Debug for BillingService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BillingService")
            .field("adapters", &self.adapters)
            .field("deadline_ms", &self.deadline.as_millis())
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

/// Builds a refusal from a redacted error.
fn refuse(code: PaymentProblemCode, error: &BillingError) -> AuthorizationDecision {
    AuthorizationDecision::PaymentRequired(PaymentProblem::new(code, SafeFailure::from(error)))
}

/// Builds an unavailable decision, which asserts nothing about the funds.
const fn unavailable(retry_after_seconds: u32) -> AuthorizationDecision {
    AuthorizationDecision::Unavailable {
        retry_after_seconds,
    }
}

/// Rebuilds the signed requirement a finalized intent already committed.
fn rebuild_signed(intent: &IntentRecord) -> Result<SignedPaymentRequirement, BillingError> {
    let requirement = intent.finalized_requirement()?.clone();
    let requirement_digest = intent
        .requirement_digest
        .ok_or(BillingError::IntentNotFinalized)?;
    let quote_token = intent
        .quote_token
        .clone()
        .ok_or(BillingError::IntentNotFinalized)?;
    let signed = SignedPaymentRequirement {
        requirement,
        draft_digest: intent.draft_digest,
        requirement_digest,
        quote_token,
    };
    signed.verify_digests()?;
    Ok(signed)
}
