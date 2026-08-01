//! Authoritative payment settlement for the proxy.
//!
//! The crate owns one normalized payment domain and the durable machinery
//! that decides whether a paid request may reach the origin. It is
//! deliberately independent of the request pipeline: the proxy translates
//! its existing 402 policy output into a [`PaymentRequirementDraft`], and
//! this crate turns that draft into a durable settlement intent, a signed
//! challenge, and eventually a provider-backed [`SettlementReceipt`].
//!
//! # The authorization invariant
//!
//! Only a durable [`IntentStatus::Succeeded`] transition authorizes origin
//! access. Verified is not settled. A timeout, an open breaker, a malformed
//! provider response, an unpaid invoice, an ambiguous write, or a
//! reconciliation requirement all fail closed before the origin. The rule is
//! encoded on the type: [`IntentStatus::authorizes_origin`] returns `true`
//! for exactly one variant, and the store refuses to hand back an access
//! receipt for any other state.
//!
//! # Money is exact
//!
//! Amounts are integer micros of a major unit paired with an explicit ISO
//! currency, and every conversion to a provider base unit is checked. There
//! is no floating point anywhere in this crate. A conversion that would
//! truncate a remainder or overflow is an error, never a rounded value.
//!
//! # No fabricated success
//!
//! A rail either returns real provider-backed data or an explicit
//! `ProviderQueryResult::Unsupported`. There are no synthesized provider
//! references, no empty reconciliation reports, and no receipt without a
//! provider reference the operator can look up.
//!
//! # Feature layout
//!
//! The default feature set is empty and compiles only the domain contract.
//!
//! | Feature | Adds |
//! | --- | --- |
//! | `runtime` | Durable store, dispatch gate, registry, service, recovery worker |
//! | `recovery-crypto` | AES-256-GCM recovery envelopes for replayable provider writes |
//! | `x402` | x402 v2 `exact` settlement |
//! | `mpp` | Payment HTTP Authentication codec |
//! | `stripe` | Stripe PaymentIntent settlement and separate meter reporting |
//! | `lightning-cln` | Core Lightning Unix JSON-RPC settlement |
//! | `lightning-lnd` | LND gRPC settlement |
//!
//! Every rail sits behind its own feature and compiles to nothing without
//! it. A module that is never declared compiles to nothing with no error at
//! all, which has bitten this crate before, so each `pub mod` below carries
//! the exact cfg its feature implies.
//!
//! Stripe settlement and Stripe usage reporting are separate surfaces behind
//! one feature. [`stripe_payment`] can settle a payment and therefore
//! authorize origin access; [`stripe_meter`] reports usage and cannot. A
//! meter event is never proof that money moved.
//!
//! The Payment Auth Stripe charge path additionally needs `mpp`, because the
//! single use payment token is carried in the pinned draft-01 credential and
//! this crate will not guess a token shape it cannot decode. With `stripe`
//! alone, the direct PaymentIntent rail works and the Payment Auth charge
//! path refuses.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod money;
pub mod types;

#[cfg(feature = "runtime")]
pub mod dispatch;
#[cfg(feature = "runtime")]
pub mod registry;
#[cfg(feature = "runtime")]
pub mod service;
#[cfg(feature = "runtime")]
pub mod sqlite;
#[cfg(feature = "runtime")]
pub mod store;
#[cfg(feature = "runtime")]
pub mod worker;

#[cfg(feature = "recovery-crypto")]
pub mod recovery_crypto;

// Wire codecs and rail adapters. Each sits behind its own feature and
// depends on nothing the other one compiles, so a build that enables one
// never has to compile the other.
#[cfg(feature = "mpp")]
pub mod payment_auth;
#[cfg(feature = "x402")]
pub mod x402;

#[cfg(feature = "stripe")]
pub mod stripe_meter;
#[cfg(feature = "stripe")]
pub mod stripe_payment;

// One module for both Lightning backends. The shared half compiles under
// either gate; `lightning::cln` and `lightning::lnd` are declared inside it
// behind their own gates.
#[cfg(any(feature = "lightning-cln", feature = "lightning-lnd"))]
pub mod lightning;

pub use error::BillingError;
pub use money::{CurrencyCode, Money};
pub use types::{
    derive_attempt_id, derive_intent_id, derive_receipt_key, provider_idempotency_key,
    AdvertisedRail, AttemptOperation, AttemptStatus, FailureCategory, IntentStatus, PaymentProof,
    PaymentProtocol, PaymentRequirement, PaymentRequirementDraft, RecoveryEnvelopeRecord,
    RequirementTerms, SafeFailure, SettlementRail, SettlementReceipt, SignedPaymentRequirement,
};

#[cfg(feature = "runtime")]
pub use dispatch::{DispatchContext, DispatchOutcome, DispatchSubject, UsageDispatch};
#[cfg(feature = "runtime")]
pub use registry::{
    AuthoritativePayment, ChallengeMaterial, ChallengePreparation, PaymentMethodAdapter,
    ProviderQueryResult, RailRegistry, UsageEvent, UsageReportReceipt, UsageReporter,
};
#[cfg(feature = "runtime")]
pub use service::{
    AuthorizationDecision, BillingService, BillingServiceBuilder, PaymentProblem,
    PaymentProblemCode, PreparedPaymentResponse, RedemptionRequest, RequirementInput,
    RequirementSigner, MAX_AUTHORIZATION_DEADLINE_MS,
};
#[cfg(feature = "runtime")]
pub use sqlite::{SqliteSettlementStore, SqliteStoreConfig, SCHEMA_VERSION};
#[cfg(feature = "runtime")]
pub use store::{
    BillingClock, ClaimedAttempt, ClaimedUsageEvent, CreateIntent, IntentRecord, LeaseRecovery,
    PreparedAttempt, ProofReservation, ProviderAttempt, ReconciliationOutcome, SettlementStore,
    SharedSettlementStore, SystemClock, UsageOutcome,
};
#[cfg(feature = "runtime")]
pub use worker::{SettlementWorker, SettlementWorkerHandle, WorkerConfig, WorkerStatus};

#[cfg(feature = "recovery-crypto")]
pub use recovery_crypto::{RecoveryBinding, RecoveryCipher};

#[cfg(feature = "stripe")]
pub use stripe_meter::{
    StripeMeterEndpoints, StripeMeterError, StripeMeterReporter, StripeMeterRequest,
    StripeMeterTransport, METER_EVENTS_PATH, STRIPE_METER_REPORTER,
};
#[cfg(feature = "stripe")]
pub use stripe_payment::{
    PaymentIntent, PaymentIntentStatus, StripeEndpoints, StripeError, StripeHttpResponse,
    StripePaymentIntentSettler, StripeRequest, StripeSettlerConfig, StripeTransport,
    STRIPE_API_VERSION,
};

#[cfg(feature = "lightning-cln")]
pub use lightning::cln::{ClnInvoice, ClnInvoiceStatus, ClnSettler, ClnTransport};
#[cfg(feature = "lightning-lnd")]
pub use lightning::lnd::{
    InvoiceKey, InvoiceState, LndSettler, LndTransport, PaymentStatus, PINNED_LND_TAG,
};
#[cfg(any(feature = "lightning-cln", feature = "lightning-lnd"))]
pub use lightning::{LightningError, LightningTransportFailure, PaymentHash};
