//! Typed, non-secret settlement errors.
//!
//! Every variant is safe to log, safe to return through the access log, and
//! safe to embed in a problem document. No variant carries an authorization
//! header, a payment credential, a Stripe client secret, a macaroon, a rune,
//! a payer address, a raw provider body, or recovery-envelope plaintext.
//! When a provider or the storage layer produces a detailed message, this
//! crate discards it and keeps only a fixed category plus, where the
//! provider publishes a stable machine-readable code, that code after
//! character-class sanitization.

use crate::types::{FailureCategory, IntentStatus, SettlementRail};

/// A settlement failure with no secret material in it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BillingError {
    /// A currency was not exactly three ASCII letters.
    #[error("payment currency must be three ASCII letters")]
    InvalidCurrency,

    /// An amount was zero, or larger than the durable store can hold.
    #[error("payment amount is not a positive representable value")]
    InvalidAmount,

    /// Converting micros to a provider base unit would truncate or overflow.
    #[error("payment amount is not exactly representable in the target base unit")]
    AmountNotRepresentable,

    /// A declared base-unit precision was outside the supported range.
    #[error("payment base-unit precision is out of range")]
    InvalidPrecision,

    /// Canonical JSON generation failed for a requirement or a draft.
    #[error("canonicalize payment requirement: {0}")]
    Canonical(String),

    /// A required requirement, draft, or terms field was empty or malformed.
    #[error("payment requirement field is invalid: {0}")]
    InvalidRequirement(&'static str),

    /// A recomputed digest did not match the digest carried alongside it.
    #[error("payment requirement digest mismatch")]
    DigestMismatch,

    /// The presented requirement did not match the durable challenge.
    #[error("presented payment requirement does not match the stored challenge")]
    RequirementMismatch,

    /// The advertised rail cannot be normalized to a settlement rail.
    #[error("advertised payment rail has no settlement rail")]
    UnsupportedRail,

    /// No adapter is registered for the rail this intent settles on.
    #[error("no settlement adapter registered for rail {0}")]
    AdapterNotRegistered(SettlementRail),

    /// No usage reporter is registered under the requested name.
    #[error("no usage reporter registered under that name")]
    ReporterNotRegistered,

    /// Two adapters claimed the same settlement rail.
    #[error("duplicate settlement adapter for rail {0}")]
    DuplicateAdapter(SettlementRail),

    /// Two usage reporters claimed the same reporter name.
    #[error("duplicate usage reporter name")]
    DuplicateReporter,

    /// The operation is not valid for this attempt or this rail.
    #[error("payment operation is not supported here")]
    UnsupportedOperation,

    /// A payment proof was empty or used an unknown scheme.
    #[error("payment proof is malformed")]
    InvalidProof,

    /// The proof digest already settled a different intent.
    #[error("payment proof was already used")]
    ProofReplayed,

    /// The intent is already bound to a different proof digest.
    #[error("payment intent is bound to a different proof")]
    ProofConflict,

    /// No durable challenge exists for this tenant and idempotency key.
    #[error("no payment challenge exists for this request")]
    IntentNotFound,

    /// The challenge exists but was never finalized and signed.
    #[error("payment challenge was never finalized")]
    IntentNotFinalized,

    /// The challenge expired before the credential arrived.
    #[error("payment challenge expired")]
    IntentExpired,

    /// The same idempotency key was reused with different requirement bytes.
    #[error("payment idempotency key was reused with different terms")]
    IntentConflict,

    /// A durable transition was refused because the current state forbids it.
    #[error("payment intent cannot move from {from} to {to}")]
    InvalidStateTransition {
        /// The state the intent is in now.
        from: IntentStatus,
        /// The state the caller asked for.
        to: IntentStatus,
    },

    /// A pre-dispatch transition was attempted after the dispatch stamp.
    #[error("payment attempt was already dispatched")]
    AlreadyDispatched,

    /// The caller's lease on the attempt expired or was taken over.
    #[error("payment attempt lease is no longer held")]
    LeaseLost,

    /// Another worker or request holds a live lease on this attempt.
    #[error("payment attempt is leased by another holder")]
    LeaseHeld,

    /// A provider write is outstanding with no authoritative recorded result.
    #[error("payment attempt requires reconciliation")]
    NeedsReconciliation,

    /// The provider did not answer inside the bounded deadline.
    #[error("payment provider call timed out")]
    ProviderTimeout,

    /// The provider was unreachable, or its breaker is open.
    #[error("payment provider is unavailable")]
    ProviderUnavailable,

    /// The provider answered, but the answer did not parse as its contract.
    #[error("payment provider returned a malformed response")]
    ProviderMalformed,

    /// The provider answered authoritatively that the payment did not settle.
    #[error("payment provider rejected the payment")]
    ProviderRejected,

    /// The rail reached a verified but not settled state.
    #[error("payment was verified but not settled")]
    NotSettled,

    /// The rail cannot answer this question at all.
    #[error("payment rail does not support this query")]
    QueryUnsupported,

    /// The configured authorization deadline exceeds the hard ceiling.
    #[error("authorization deadline exceeds the 2000 ms ceiling")]
    DeadlineTooLong,

    /// No recovery key is configured, so no envelope can be sealed or opened.
    #[error("no recovery encryption key is configured")]
    RecoveryKeyMissing,

    /// The stored envelope was sealed under a different key identifier.
    #[error("recovery envelope was sealed under a different key")]
    RecoveryKeyMismatch,

    /// The envelope failed authentication, so its bytes cannot be trusted.
    #[error("recovery envelope failed authentication")]
    RecoveryEnvelopeAuthFailed,

    /// The envelope is older than the configured hard expiry.
    #[error("recovery envelope expired")]
    RecoveryEnvelopeExpired,

    /// A recovery key was not exactly 32 bytes.
    #[error("recovery encryption key must be 32 bytes")]
    RecoveryKeyLength,

    /// The durable store could not complete the operation.
    #[error("payment store operation failed: {0}")]
    Storage(&'static str),

    /// The durable store is unreachable or its worker thread went away.
    #[error("payment store is unavailable")]
    StoreUnavailable,

    /// The durable store holds a schema this build does not understand.
    #[error("payment store schema is not supported by this build")]
    UnsupportedSchema,

    /// Stored JSON did not round-trip back into the domain contract.
    #[error("payment store holds a record this build cannot decode")]
    CorruptRecord,
}

impl BillingError {
    /// Returns the redacted failure category this error records durably.
    ///
    /// The mapping is deliberately coarse. It is what lands in the attempt's
    /// failure columns and in closed-cardinality metrics, so it must never
    /// grow a variant derived from provider text.
    pub fn failure_category(&self) -> FailureCategory {
        match self {
            Self::ProviderTimeout => FailureCategory::Timeout,
            Self::ProviderUnavailable | Self::StoreUnavailable => FailureCategory::Unavailable,
            Self::ProviderMalformed | Self::CorruptRecord => FailureCategory::Malformed,
            Self::ProviderRejected | Self::NotSettled => FailureCategory::Rejected,
            Self::NeedsReconciliation | Self::AlreadyDispatched => FailureCategory::Ambiguous,
            Self::IntentExpired | Self::RecoveryEnvelopeExpired => FailureCategory::Expired,
            Self::UnsupportedRail
            | Self::UnsupportedOperation
            | Self::QueryUnsupported
            | Self::AdapterNotRegistered(_)
            | Self::ReporterNotRegistered => FailureCategory::Unsupported,
            Self::InvalidProof | Self::ProofReplayed | Self::ProofConflict => {
                FailureCategory::Rejected
            }
            _ => FailureCategory::Internal,
        }
    }

    /// Reports whether a later client retry could still succeed.
    ///
    /// This is advisory only. It never widens what the durable state machine
    /// allows: an ambiguous dispatch stays in reconciliation no matter what
    /// this returns.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ProviderTimeout
                | Self::ProviderUnavailable
                | Self::StoreUnavailable
                | Self::LeaseHeld
                | Self::NeedsReconciliation
        )
    }
}
