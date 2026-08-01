//! The normalized payment domain.
//!
//! Everything here compiles with the default, empty feature set. It is the
//! contract the proxy, the durable store, and every rail adapter agree on,
//! and it is deliberately free of provider vocabulary: a rail adapter reads
//! a [`PaymentRequirement`] and nothing else. There is no second price, no
//! second recipient, and no second expiry source anywhere in the crate.
//!
//! Preparation is two phase for rails whose provider object does not exist
//! until the challenge is created. The immutable [`PaymentRequirementDraft`]
//! is hashed and persisted first, the provider object is created under a
//! durable idempotency key, and only then is the non-secret provider handle
//! folded into the final [`PaymentRequirement`] and hashed again. Stripe
//! direct mode binds the draft digest because a PaymentIntent identifier
//! cannot be part of its own create request; Payment Auth Stripe, which
//! creates its PaymentIntent on the credential retry, binds the final
//! requirement digest directly.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::BillingError;
use crate::money::Money;

/// Domain separator for the immutable draft digest.
const DRAFT_DIGEST_DOMAIN: &[u8] = b"sbproxy-payment-draft-v1";
/// Domain separator for the final, provider-bound requirement digest.
const REQUIREMENT_DIGEST_DOMAIN: &[u8] = b"sbproxy-payment-requirement-v1";
/// Domain separator for the payment proof digest.
const PROOF_DIGEST_DOMAIN: &[u8] = b"sbproxy-payment-proof-v1";
/// Domain separator for durable intent identifiers.
const INTENT_ID_DOMAIN: &[u8] = b"sbproxy-settlement-intent-v1";
/// Domain separator for durable attempt identifiers.
const ATTEMPT_ID_DOMAIN: &[u8] = b"sbproxy-settlement-attempt-v1";
/// Domain separator for durable receipt keys.
const RECEIPT_KEY_DOMAIN: &[u8] = b"sbproxy-settlement-receipt-v1";
/// Domain separator for the quote nonce derived from a signed quote token.
const QUOTE_NONCE_DOMAIN: &[u8] = b"sbproxy-settlement-quote-nonce-v1";

/// Prefix on every provider idempotency key this crate mints.
pub const PROVIDER_IDEMPOTENCY_KEY_PREFIX: &str = "sbp1_";

/// Longest provider error code kept in a durable failure column.
const MAX_PROVIDER_CODE_LEN: usize = 64;

/// A payment rail as advertised to the client in a 402 challenge.
///
/// This is the client-facing vocabulary. `Mpp` names the Payment HTTP
/// Authentication scheme, which is a transport for a method rather than a
/// settlement network of its own; it normalizes onto a real settlement rail
/// through [`AdvertisedRail::settlement_rail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvertisedRail {
    /// The x402 v2 `exact` scheme.
    X402,
    /// Payment HTTP Authentication, carrying a registered method and intent.
    Mpp,
    /// A Stripe PaymentIntent advertised directly.
    Stripe,
    /// A Lightning invoice.
    Lightning,
}

impl AdvertisedRail {
    /// Returns the stable wire spelling used in configuration and storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X402 => "x402",
            Self::Mpp => "mpp",
            Self::Stripe => "stripe",
            Self::Lightning => "lightning",
        }
    }

    /// Parses the stable wire spelling.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::UnsupportedRail`] for an unknown spelling.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        match input {
            "x402" => Ok(Self::X402),
            "mpp" => Ok(Self::Mpp),
            "stripe" => Ok(Self::Stripe),
            "lightning" => Ok(Self::Lightning),
            _ => Err(BillingError::UnsupportedRail),
        }
    }

    /// Normalizes the advertised rail onto the rail that actually settles.
    ///
    /// `lightning_backend` is read only for [`AdvertisedRail::Lightning`],
    /// where the backend decides between the Core Lightning and LND
    /// adapters. Payment HTTP Authentication maps onto the settlement rail
    /// of its registered method; this build registers only `stripe` plus
    /// `charge`, so `Mpp` settles on [`SettlementRail::Stripe`] and no `Mpp`
    /// settlement rail exists.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::UnsupportedRail`] when a Lightning rail
    /// arrives without a recognized backend.
    pub fn settlement_rail(
        self,
        lightning_backend: Option<&str>,
    ) -> Result<SettlementRail, BillingError> {
        match self {
            Self::X402 => Ok(SettlementRail::X402),
            Self::Mpp | Self::Stripe => Ok(SettlementRail::Stripe),
            Self::Lightning => match lightning_backend {
                Some(backend) if backend.eq_ignore_ascii_case("cln") => {
                    Ok(SettlementRail::LightningCln)
                }
                Some(backend) if backend.eq_ignore_ascii_case("lnd") => {
                    Ok(SettlementRail::LightningLnd)
                }
                _ => Err(BillingError::UnsupportedRail),
            },
        }
    }
}

impl std::fmt::Display for AdvertisedRail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The rail that performs the authoritative settlement.
///
/// One adapter registers per variant. There is no `Mpp` variant on purpose:
/// Payment HTTP Authentication is a credential transport, not a network that
/// moves funds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRail {
    /// x402 v2 `exact`, verified and settled through a facilitator.
    X402,
    /// Stripe PaymentIntents.
    Stripe,
    /// Core Lightning over its Unix domain JSON-RPC socket.
    LightningCln,
    /// LND over gRPC.
    LightningLnd,
}

impl SettlementRail {
    /// Returns the stable wire spelling used in configuration and storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X402 => "x402",
            Self::Stripe => "stripe",
            Self::LightningCln => "lightning_cln",
            Self::LightningLnd => "lightning_lnd",
        }
    }

    /// Returns the cargo feature that compiles this rail's adapter.
    ///
    /// Startup uses this to name the missing feature when configuration
    /// advertises a rail the binary was not built with.
    pub const fn cargo_feature(self) -> &'static str {
        match self {
            Self::X402 => "payment-x402",
            Self::Stripe => "payment-stripe",
            Self::LightningCln => "payment-lightning-cln",
            Self::LightningLnd => "payment-lightning-lnd",
        }
    }

    /// Parses the stable wire spelling.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::UnsupportedRail`] for an unknown spelling.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        match input {
            "x402" => Ok(Self::X402),
            "stripe" => Ok(Self::Stripe),
            "lightning_cln" => Ok(Self::LightningCln),
            "lightning_lnd" => Ok(Self::LightningLnd),
            _ => Err(BillingError::UnsupportedRail),
        }
    }
}

impl std::fmt::Display for SettlementRail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The wire protocol a challenge and its credential speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentProtocol {
    /// x402 version 2.
    X402V2,
    /// Payment HTTP Authentication, draft-ryan-httpauth-payment-01.
    PaymentAuthDraft01,
    /// A Stripe PaymentIntent advertised and redeemed directly.
    StripePaymentIntentV1,
    /// A Lightning BOLT 11 invoice.
    LightningInvoice,
}

impl PaymentProtocol {
    /// Returns the stable wire spelling used in configuration and storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X402V2 => "x402_v2",
            Self::PaymentAuthDraft01 => "payment_auth_draft_01",
            Self::StripePaymentIntentV1 => "stripe_payment_intent_v1",
            Self::LightningInvoice => "lightning_invoice",
        }
    }

    /// Parses the stable wire spelling.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::UnsupportedRail`] for an unknown spelling.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        match input {
            "x402_v2" => Ok(Self::X402V2),
            "payment_auth_draft_01" => Ok(Self::PaymentAuthDraft01),
            "stripe_payment_intent_v1" => Ok(Self::StripePaymentIntentV1),
            "lightning_invoice" => Ok(Self::LightningInvoice),
            _ => Err(BillingError::UnsupportedRail),
        }
    }
}

impl std::fmt::Display for PaymentProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The durable state of one settlement intent.
///
/// This enum is the authorization invariant. Exactly one variant lets a
/// request reach the origin, and [`IntentStatus::authorizes_origin`] is the
/// only place that decision is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    /// A challenge exists, or is being prepared, and no credential arrived.
    Pending,
    /// One bounded authoritative operation is in flight.
    Processing,
    /// A retry is waiting, and it is proven not to have been dispatched.
    RetryWait,
    /// The rail settled and a receipt is committed.
    Succeeded,
    /// The intent failed definitively and no funds moved.
    Terminal,
    /// A dispatch happened with no authoritative recorded response.
    NeedsReconciliation,
}

impl IntentStatus {
    /// Returns the stable wire spelling used in storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::RetryWait => "retry_wait",
            Self::Succeeded => "succeeded",
            Self::Terminal => "terminal",
            Self::NeedsReconciliation => "needs_reconciliation",
        }
    }

    /// Parses the stable wire spelling.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] for an unknown spelling,
    /// because the only way one reaches this function is a stored row this
    /// build cannot decode.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        match input {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "retry_wait" => Ok(Self::RetryWait),
            "succeeded" => Ok(Self::Succeeded),
            "terminal" => Ok(Self::Terminal),
            "needs_reconciliation" => Ok(Self::NeedsReconciliation),
            _ => Err(BillingError::CorruptRecord),
        }
    }

    /// Reports whether this state may let a request reach the origin.
    ///
    /// Only [`IntentStatus::Succeeded`] returns `true`. Verified, processing,
    /// waiting, ambiguous, and terminal all fail closed.
    pub const fn authorizes_origin(self) -> bool {
        matches!(self, Self::Succeeded)
    }

    /// Reports whether the intent can still change state.
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Succeeded | Self::Terminal)
    }

    /// Reports whether a new provider write may be started from this state.
    ///
    /// [`IntentStatus::NeedsReconciliation`] deliberately returns `false`:
    /// that state permits a provider status query and nothing else.
    pub const fn allows_provider_write(self) -> bool {
        matches!(self, Self::Pending | Self::Processing | Self::RetryWait)
    }
}

impl std::fmt::Display for IntentStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The provider operation one attempt performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOperation {
    /// Create the provider object a challenge needs, capturing no funds.
    PrepareChallenge,
    /// Verify a credential without moving funds.
    Verify,
    /// Move funds.
    Settle,
    /// Confirm a provider object that was created earlier.
    Confirm,
    /// Capture an authorized but uncaptured provider object.
    Capture,
    /// Read provider state. Never a write.
    Query,
    /// Report usage. Never proves payment.
    MeterReport,
}

impl AttemptOperation {
    /// Returns the stable wire spelling used in storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrepareChallenge => "prepare_challenge",
            Self::Verify => "verify",
            Self::Settle => "settle",
            Self::Confirm => "confirm",
            Self::Capture => "capture",
            Self::Query => "query",
            Self::MeterReport => "meter_report",
        }
    }

    /// Parses the stable wire spelling.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] for an unknown spelling.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        match input {
            "prepare_challenge" => Ok(Self::PrepareChallenge),
            "verify" => Ok(Self::Verify),
            "settle" => Ok(Self::Settle),
            "confirm" => Ok(Self::Confirm),
            "capture" => Ok(Self::Capture),
            "query" => Ok(Self::Query),
            "meter_report" => Ok(Self::MeterReport),
            _ => Err(BillingError::CorruptRecord),
        }
    }

    /// Reports whether this operation may commit an access receipt.
    ///
    /// Challenge preparation, reads, and meter reports never can. This is
    /// what stops a usage reporter from moving an intent to
    /// [`IntentStatus::Succeeded`].
    pub const fn can_settle(self) -> bool {
        matches!(self, Self::Settle | Self::Confirm | Self::Capture)
    }

    /// Reports whether this operation performs a provider write.
    pub const fn is_write(self) -> bool {
        !matches!(self, Self::Query | Self::Verify)
    }
}

impl std::fmt::Display for AttemptOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The durable state of one provider attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    /// The attempt row and its idempotency key exist; nothing was sent.
    Prepared,
    /// The dispatch stamp is committed; a provider write may have landed.
    Dispatched,
    /// The provider returned an authoritative success.
    Succeeded,
    /// The attempt is proven not to have been dispatched and may retry.
    RetryWait,
    /// The attempt failed definitively and no funds moved.
    Terminal,
    /// A dispatch happened with no authoritative recorded response.
    NeedsReconciliation,
}

impl AttemptStatus {
    /// Returns the stable wire spelling used in storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Dispatched => "dispatched",
            Self::Succeeded => "succeeded",
            Self::RetryWait => "retry_wait",
            Self::Terminal => "terminal",
            Self::NeedsReconciliation => "needs_reconciliation",
        }
    }

    /// Parses the stable wire spelling.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] for an unknown spelling.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        match input {
            "prepared" => Ok(Self::Prepared),
            "dispatched" => Ok(Self::Dispatched),
            "succeeded" => Ok(Self::Succeeded),
            "retry_wait" => Ok(Self::RetryWait),
            "terminal" => Ok(Self::Terminal),
            "needs_reconciliation" => Ok(Self::NeedsReconciliation),
            _ => Err(BillingError::CorruptRecord),
        }
    }
}

impl std::fmt::Display for AttemptStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The closed set of failure categories that reach durable columns.
///
/// Cardinality is fixed on purpose. Metrics label on this, and provider
/// text never becomes a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    /// The bounded deadline elapsed.
    Timeout,
    /// The provider or the store was unreachable, or a breaker was open.
    Unavailable,
    /// A response arrived but did not parse as the pinned contract.
    Malformed,
    /// The provider answered authoritatively that the payment did not settle.
    Rejected,
    /// A write is outstanding with no authoritative recorded response.
    Ambiguous,
    /// A challenge, envelope, or invoice passed its expiry.
    Expired,
    /// The rail cannot perform the requested operation at all.
    Unsupported,
    /// Anything this crate got wrong itself.
    #[default]
    Internal,
}

impl FailureCategory {
    /// Returns the stable wire spelling used in storage and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Malformed => "malformed",
            Self::Rejected => "rejected",
            Self::Ambiguous => "ambiguous",
            Self::Expired => "expired",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }

    /// Parses the stable wire spelling.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::CorruptRecord`] for an unknown spelling.
    pub fn parse(input: &str) -> Result<Self, BillingError> {
        match input {
            "timeout" => Ok(Self::Timeout),
            "unavailable" => Ok(Self::Unavailable),
            "malformed" => Ok(Self::Malformed),
            "rejected" => Ok(Self::Rejected),
            "ambiguous" => Ok(Self::Ambiguous),
            "expired" => Ok(Self::Expired),
            "unsupported" => Ok(Self::Unsupported),
            "internal" => Ok(Self::Internal),
            _ => Err(BillingError::CorruptRecord),
        }
    }
}

impl std::fmt::Display for FailureCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A failure description that is safe to persist and safe to log.
///
/// The provider code is sanitized at construction: anything outside a
/// conservative identifier character class, or longer than 64 characters, is
/// dropped rather than truncated, so a provider cannot smuggle a client
/// secret into a durable column by putting it in an error string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeFailure {
    /// The closed-cardinality category.
    pub category: FailureCategory,
    /// A stable provider error code, or `None` when there was none to keep.
    pub provider_code: Option<String>,
    /// Whether a later client retry could still succeed.
    pub retryable: bool,
}

impl SafeFailure {
    /// Builds a sanitized failure record.
    ///
    /// `provider_code` is kept only when it is a non-empty run of at most 64
    /// ASCII alphanumerics, underscores, hyphens, or dots.
    pub fn new(category: FailureCategory, provider_code: Option<&str>, retryable: bool) -> Self {
        Self {
            category,
            provider_code: provider_code.and_then(sanitize_provider_code),
            retryable,
        }
    }

    /// Builds a failure record with no provider code at all.
    pub fn category(category: FailureCategory, retryable: bool) -> Self {
        Self {
            category,
            provider_code: None,
            retryable,
        }
    }
}

impl From<&BillingError> for SafeFailure {
    fn from(error: &BillingError) -> Self {
        Self::category(error.failure_category(), error.is_retryable())
    }
}

/// Keeps a provider code only when it is plainly not secret material.
fn sanitize_provider_code(code: &str) -> Option<String> {
    if code.is_empty() || code.len() > MAX_PROVIDER_CODE_LEN {
        return None;
    }
    let acceptable = code
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if acceptable {
        Some(code.to_string())
    } else {
        None
    }
}

/// Rail-specific terms, carried in exactly one place.
///
/// Every value a challenge or a provider call needs beyond the common fields
/// lives here. An adapter that wants a facilitator URL, a business network
/// identifier, a payment-method list, a capture mode, a Lightning backend,
/// or an invoice expiry reads it from this enum. It may not consult
/// configuration a second time, because the requirement is what the quote
/// signed and configuration may have reloaded since.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequirementTerms {
    /// x402 v2 `exact` terms.
    X402Exact {
        /// Facilitator base URL that performs `verify` and `settle`.
        facilitator_url: String,
        /// The scheme's advertised maximum timeout, in seconds.
        max_timeout_seconds: u32,
        /// Scheme `extra` fields, passed through verbatim and canonically.
        extra: BTreeMap<String, serde_json::Value>,
    },
    /// Payment HTTP Authentication with method `stripe` and intent `charge`.
    PaymentAuthStripeCharge {
        /// The business network identifier the draft registers under.
        business_network_id: String,
        /// Accepted payment-method types, lowercased, sorted, deduplicated.
        payment_method_types: Vec<String>,
        /// Opaque, non-secret account context the adapter charges under.
        account_context: String,
    },
    /// A Stripe PaymentIntent advertised directly.
    StripePaymentIntent {
        /// Accepted payment-method types, lowercased, sorted, deduplicated.
        payment_method_types: Vec<String>,
        /// Either `automatic` or `manual`.
        capture_method: String,
        /// Opaque, non-secret account context the adapter charges under.
        account_context: String,
    },
    /// A Lightning invoice on a named backend.
    LightningInvoice {
        /// Either `cln` or `lnd`.
        backend: String,
        /// Invoice expiry in seconds.
        invoice_expiry_seconds: u32,
    },
}

impl RequirementTerms {
    /// Returns the Lightning backend, when these terms name one.
    pub fn lightning_backend(&self) -> Option<&str> {
        match self {
            Self::LightningInvoice { backend, .. } => Some(backend.as_str()),
            _ => None,
        }
    }

    /// Returns the settlement rail these terms imply.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::UnsupportedRail`] when a Lightning backend is
    /// not one of the two supported spellings.
    pub fn settlement_rail(&self) -> Result<SettlementRail, BillingError> {
        match self {
            Self::X402Exact { .. } => Ok(SettlementRail::X402),
            Self::PaymentAuthStripeCharge { .. } | Self::StripePaymentIntent { .. } => {
                Ok(SettlementRail::Stripe)
            }
            Self::LightningInvoice { backend, .. } => {
                AdvertisedRail::Lightning.settlement_rail(Some(backend.as_str()))
            }
        }
    }

    /// Normalizes the terms into their one canonical spelling.
    ///
    /// Method lists are lowercased, sorted, and deduplicated; capture modes
    /// and backends are lowercased. Two configurations that mean the same
    /// thing therefore hash the same, which is what makes the draft digest a
    /// usable idempotency identity.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`] when a required term is
    /// empty, zero, or outside its allowed set.
    pub fn canonicalize(&mut self) -> Result<(), BillingError> {
        match self {
            Self::X402Exact {
                facilitator_url,
                max_timeout_seconds,
                extra: _,
            } => {
                if facilitator_url.trim().is_empty()
                    || facilitator_url.trim().len() != facilitator_url.len()
                {
                    return Err(BillingError::InvalidRequirement("facilitator_url"));
                }
                if *max_timeout_seconds == 0 {
                    return Err(BillingError::InvalidRequirement("max_timeout_seconds"));
                }
            }
            Self::PaymentAuthStripeCharge {
                business_network_id,
                payment_method_types,
                account_context,
            } => {
                if business_network_id.trim().is_empty() {
                    return Err(BillingError::InvalidRequirement("business_network_id"));
                }
                if account_context.trim().is_empty() {
                    return Err(BillingError::InvalidRequirement("account_context"));
                }
                canonicalize_method_types(payment_method_types)?;
            }
            Self::StripePaymentIntent {
                payment_method_types,
                capture_method,
                account_context,
            } => {
                if account_context.trim().is_empty() {
                    return Err(BillingError::InvalidRequirement("account_context"));
                }
                *capture_method = capture_method.to_ascii_lowercase();
                if capture_method.as_str() != "automatic" && capture_method.as_str() != "manual" {
                    return Err(BillingError::InvalidRequirement("capture_method"));
                }
                canonicalize_method_types(payment_method_types)?;
            }
            Self::LightningInvoice {
                backend,
                invoice_expiry_seconds,
            } => {
                *backend = backend.to_ascii_lowercase();
                if backend.as_str() != "cln" && backend.as_str() != "lnd" {
                    return Err(BillingError::InvalidRequirement("backend"));
                }
                if *invoice_expiry_seconds == 0 {
                    return Err(BillingError::InvalidRequirement("invoice_expiry_seconds"));
                }
            }
        }
        Ok(())
    }
}

/// Lowercases, sorts, and deduplicates a payment-method list in place.
fn canonicalize_method_types(types: &mut Vec<String>) -> Result<(), BillingError> {
    if types.is_empty() {
        return Err(BillingError::InvalidRequirement("payment_method_types"));
    }
    for entry in types.iter_mut() {
        *entry = entry.trim().to_ascii_lowercase();
        if entry.is_empty() {
            return Err(BillingError::InvalidRequirement("payment_method_types"));
        }
    }
    types.sort();
    types.dedup();
    Ok(())
}

/// The immutable half of a payment requirement.
///
/// Everything here is known before any provider is contacted, so the draft
/// can be hashed and persisted before a single byte leaves the process. The
/// digest of this struct is the identity a Stripe direct-mode PaymentIntent
/// binds in its metadata, because a PaymentIntent identifier cannot appear
/// inside its own create request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirementDraft {
    /// Stable identifier for this requirement within the tenant.
    pub requirement_id: String,
    /// The wire protocol the challenge and credential speak.
    pub protocol: PaymentProtocol,
    /// The rail as advertised to the client.
    pub advertised_rail: AdvertisedRail,
    /// The rail that actually settles.
    pub settlement_rail: SettlementRail,
    /// The protocol method name, for example `stripe`.
    pub method: String,
    /// The protocol intent name, for example `charge`.
    pub intent: String,
    /// The settlement network, when the rail names one.
    pub network: Option<String>,
    /// The settlement asset, when the rail names one.
    pub asset: Option<String>,
    /// The recipient, when the rail names one.
    pub pay_to: Option<String>,
    /// The quoted price, in exact micros of a major unit.
    pub amount: Money,
    /// The advertised amount in provider base units, as a decimal string.
    pub settlement_amount: String,
    /// The declared precision `settlement_amount` was rendered at.
    pub settlement_decimals: u8,
    /// Rail-specific terms.
    pub terms: RequirementTerms,
    /// The quote this requirement prices.
    pub quote_id: String,
    /// The tenant the intent belongs to.
    pub tenant_id: String,
    /// The origin the paid request targets.
    pub origin_id: String,
    /// The route the paid request targets.
    pub route: String,
    /// Wall-clock expiry of the challenge, in milliseconds since the epoch.
    pub expires_at_ms: i64,
    /// A digest binding the challenge to the request body, when required.
    pub request_digest: Option<String>,
}

impl PaymentRequirementDraft {
    /// Normalizes the draft and rejects anything a rail could not honor.
    ///
    /// Canonicalization runs first so the digest computed afterwards is over
    /// the normalized bytes. The advertised rail, the settlement rail, and
    /// the terms must agree; a draft that advertises Lightning and carries
    /// Stripe terms is rejected here rather than confusing an adapter later.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`],
    /// [`BillingError::InvalidAmount`], [`BillingError::InvalidCurrency`],
    /// [`BillingError::AmountNotRepresentable`], or
    /// [`BillingError::UnsupportedRail`].
    pub fn canonicalize(&mut self) -> Result<(), BillingError> {
        for (value, field) in [
            (&self.requirement_id, "requirement_id"),
            (&self.method, "method"),
            (&self.intent, "intent"),
            (&self.quote_id, "quote_id"),
            (&self.tenant_id, "tenant_id"),
            (&self.origin_id, "origin_id"),
            (&self.route, "route"),
        ] {
            if value.trim().is_empty() {
                return Err(BillingError::InvalidRequirement(field));
            }
        }
        if self.expires_at_ms <= 0 {
            return Err(BillingError::InvalidRequirement("expires_at_ms"));
        }
        self.amount.validate()?;
        self.terms.canonicalize()?;

        let implied = self.terms.settlement_rail()?;
        let advertised = self
            .advertised_rail
            .settlement_rail(self.terms.lightning_backend())?;
        if implied != advertised || implied != self.settlement_rail {
            return Err(BillingError::UnsupportedRail);
        }

        let expected = self.amount.to_base_unit_string(self.settlement_decimals)?;
        if self.settlement_amount.is_empty() {
            self.settlement_amount = expected;
        } else if self.settlement_amount != expected {
            return Err(BillingError::InvalidRequirement("settlement_amount"));
        }
        Ok(())
    }

    /// Computes the immutable draft digest over canonical JSON.
    ///
    /// The bytes hashed are RFC 8785 canonical JSON of this struct under a
    /// fixed domain separator, so key order and whitespace cannot change the
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Canonical`] when the struct cannot be
    /// canonicalized.
    pub fn digest(&self) -> Result<[u8; 32], BillingError> {
        let canonical = serde_json_canonicalizer::to_vec(self)
            .map_err(|error| BillingError::Canonical(error.to_string()))?;
        Ok(domain_digest(DRAFT_DIGEST_DOMAIN, &[&canonical]))
    }

    /// Reports whether the challenge has passed its expiry.
    pub const fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

/// A payment requirement, complete once its provider handle is known.
///
/// For rails whose provider object is created at challenge time, such as
/// Stripe direct mode and Lightning, `provider_handle` is filled in after
/// the provider returns and before the quote is signed. For rails that
/// create nothing until the credential arrives, such as Payment Auth Stripe
/// charge, it stays `None` and the final digest equals the digest of a
/// requirement with no handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirement {
    /// The immutable half.
    pub draft: PaymentRequirementDraft,
    /// The non-secret provider handle, for example a PaymentIntent ID or a
    /// payment hash. Client secrets never appear here.
    pub provider_handle: Option<String>,
}

impl PaymentRequirement {
    /// Wraps a draft with no provider handle yet.
    pub fn new(draft: PaymentRequirementDraft) -> Self {
        Self {
            draft,
            provider_handle: None,
        }
    }

    /// Computes the final requirement digest over canonical JSON.
    ///
    /// Adding a provider handle changes this digest and leaves the draft
    /// digest untouched, which is what lets Stripe direct mode bind an
    /// identity in metadata before the identity it will be given exists.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Canonical`] when the struct cannot be
    /// canonicalized.
    pub fn digest(&self) -> Result<[u8; 32], BillingError> {
        let canonical = serde_json_canonicalizer::to_vec(self)
            .map_err(|error| BillingError::Canonical(error.to_string()))?;
        Ok(domain_digest(REQUIREMENT_DIGEST_DOMAIN, &[&canonical]))
    }
}

/// A requirement bound to a signed quote.
///
/// The quote token signs `requirement_digest`, so a client cannot present a
/// requirement whose amount, recipient, route, or provider handle differ
/// from what the proxy advertised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPaymentRequirement {
    /// The complete requirement.
    pub requirement: PaymentRequirement,
    /// Digest of the immutable draft.
    pub draft_digest: [u8; 32],
    /// Digest of the complete requirement.
    pub requirement_digest: [u8; 32],
    /// The signed quote token that binds `requirement_digest`.
    pub quote_token: String,
}

impl SignedPaymentRequirement {
    /// Recomputes both digests and compares them in constant time.
    ///
    /// This is a local check only. It proves the digests match the bytes
    /// they claim to cover; it does not verify the quote token's signature,
    /// which is the caller's job because this crate does not own the signing
    /// key.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::DigestMismatch`] when either digest is wrong,
    /// [`BillingError::InvalidRequirement`] when the quote token is empty,
    /// and [`BillingError::Canonical`] when canonicalization fails.
    pub fn verify_digests(&self) -> Result<(), BillingError> {
        if self.quote_token.is_empty() {
            return Err(BillingError::InvalidRequirement("quote_token"));
        }
        let draft = self.requirement.draft.digest()?;
        let requirement = self.requirement.digest()?;
        if !digests_equal(&draft, &self.draft_digest)
            || !digests_equal(&requirement, &self.requirement_digest)
        {
            return Err(BillingError::DigestMismatch);
        }
        Ok(())
    }

    /// Derives the unique nonce this quote token occupies.
    ///
    /// The store enforces that one nonce binds to one requirement, and a
    /// digest of the token is a faithful per-token identity that does not
    /// require this crate to parse a JWS it does not own the key for.
    pub fn quote_nonce(&self) -> String {
        let digest = domain_digest(QUOTE_NONCE_DOMAIN, &[self.quote_token.as_bytes()]);
        URL_SAFE_NO_PAD.encode(digest)
    }
}

/// A payment credential presented by a client.
///
/// The credential itself is held in a zeroizing buffer, is never derived
/// into an idempotency key in plaintext, and never appears in `Debug`,
/// `Display`, an error, a log line, or a durable column. Only the digest is
/// persisted, and comparisons against it run in constant time.
pub struct PaymentProof {
    scheme: String,
    credential: Zeroizing<String>,
    digest: [u8; 32],
}

impl PaymentProof {
    /// Builds a proof and computes its digest.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidProof`] when the scheme or the
    /// credential is empty.
    pub fn new(scheme: &str, credential: String) -> Result<Self, BillingError> {
        if scheme.trim().is_empty() || credential.is_empty() {
            return Err(BillingError::InvalidProof);
        }
        let scheme = scheme.to_string();
        let digest = domain_digest(
            PROOF_DIGEST_DOMAIN,
            &[scheme.as_bytes(), credential.as_bytes()],
        );
        Ok(Self {
            scheme,
            credential: Zeroizing::new(credential),
            digest,
        })
    }

    /// Returns the authentication scheme the credential arrived under.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the replay-protection digest.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the digest as lowercase hex, for durable columns and logs.
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// Compares this proof's digest against another in constant time.
    pub fn matches_digest(&self, other: &[u8; 32]) -> bool {
        digests_equal(&self.digest, other)
    }

    /// Borrows the raw credential so a rail adapter can send it upstream.
    ///
    /// This is the one way out of the zeroizing buffer, and it is named
    /// loudly so a call site that leaks it is obvious in review. The
    /// returned string must go to the pinned provider endpoint and nowhere
    /// else: not to a log, not to an error, not to a durable column, and not
    /// into an idempotency key.
    pub fn expose_credential(&self) -> &str {
        self.credential.as_str()
    }
}

impl Clone for PaymentProof {
    fn clone(&self) -> Self {
        Self {
            scheme: self.scheme.clone(),
            credential: Zeroizing::new(self.credential.as_str().to_string()),
            digest: self.digest,
        }
    }
}

impl std::fmt::Debug for PaymentProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaymentProof")
            .field("scheme", &self.scheme)
            .field("credential", &"<redacted>")
            .field("digest", &self.digest_hex())
            .finish()
    }
}

impl std::fmt::Display for PaymentProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PaymentProof({}, <redacted>)", self.scheme)
    }
}

/// Proof that a rail settled, and the provider reference to look it up by.
///
/// A receipt is only ever created from a provider response that carried a
/// real reference. There is no constructor that invents one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    /// Deterministic durable key for this receipt.
    pub receipt_key: String,
    /// The intent this receipt settles.
    pub intent_id: String,
    /// The rail that settled it.
    pub rail: SettlementRail,
    /// The protocol method name that settled it.
    pub method: String,
    /// The provider's own reference, for example a PaymentIntent ID, a
    /// settlement transaction hash, or a payment preimage hash.
    pub provider_reference: String,
    /// When the provider reported settlement, in milliseconds since the epoch.
    pub settled_at_ms: i64,
}

impl SettlementReceipt {
    /// Builds a receipt from real provider-backed values.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`] when the provider
    /// reference, the method, or the intent identifier is empty, and
    /// [`BillingError::InvalidRequirement`] when the settlement time is not
    /// positive. An empty provider reference is the shape a fabricated
    /// receipt takes, so it fails here rather than reaching an operator.
    pub fn new(
        intent_id: &str,
        rail: SettlementRail,
        method: &str,
        provider_reference: &str,
        settled_at_ms: i64,
    ) -> Result<Self, BillingError> {
        if intent_id.trim().is_empty() {
            return Err(BillingError::InvalidRequirement("intent_id"));
        }
        if method.trim().is_empty() {
            return Err(BillingError::InvalidRequirement("method"));
        }
        if provider_reference.trim().is_empty() {
            return Err(BillingError::InvalidRequirement("provider_reference"));
        }
        if settled_at_ms <= 0 {
            return Err(BillingError::InvalidRequirement("settled_at_ms"));
        }
        Ok(Self {
            receipt_key: derive_receipt_key(intent_id, rail, provider_reference),
            intent_id: intent_id.to_string(),
            rail,
            method: method.to_string(),
            provider_reference: provider_reference.to_string(),
            settled_at_ms,
        })
    }

    /// Rechecks a receipt that came back out of storage or off the wire.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`] when a field is empty or
    /// [`BillingError::DigestMismatch`] when the receipt key does not match
    /// the values it claims to key.
    pub fn validate(&self) -> Result<(), BillingError> {
        let rebuilt = Self::new(
            &self.intent_id,
            self.rail,
            &self.method,
            &self.provider_reference,
            self.settled_at_ms,
        )?;
        if rebuilt.receipt_key != self.receipt_key {
            return Err(BillingError::DigestMismatch);
        }
        Ok(())
    }
}

/// An encrypted write-ahead record of one replayable provider request.
///
/// The record holds ciphertext only. Plaintext exists in a zeroizing buffer
/// for the duration of a seal or an open and is never persisted, never
/// logged, and never carried in an error. The envelope exists so that a
/// process that stopped between the dispatch stamp and the response record
/// can replay the byte-identical request under the same provider
/// idempotency key purely to recover the original response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryEnvelopeRecord {
    /// The attempt this envelope belongs to.
    pub attempt_id: String,
    /// The configured key identifier the envelope was sealed under.
    pub key_id: String,
    /// The AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Ciphertext followed by the authentication tag.
    pub ciphertext: Vec<u8>,
    /// Digest of the additional authenticated data, for fast mismatch
    /// detection before an AEAD open is attempted.
    pub aad_digest: [u8; 32],
    /// When the envelope was sealed, in milliseconds since the epoch.
    pub created_at_ms: i64,
    /// Hard expiry, in milliseconds since the epoch.
    pub expires_at_ms: i64,
}

impl std::fmt::Debug for RecoveryEnvelopeRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryEnvelopeRecord")
            .field("attempt_id", &self.attempt_id)
            .field("key_id", &self.key_id)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl RecoveryEnvelopeRecord {
    /// Reports whether the envelope passed its hard expiry.
    pub const fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

/// Compares two digests in constant time.
pub fn digests_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.as_slice().ct_eq(right.as_slice()))
}

/// Hashes length-prefixed parts under a domain separator.
///
/// Every part is prefixed with its big-endian length so no reshuffling of
/// the boundaries between parts can produce the same digest.
fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Derives the durable intent identifier for a tenant and request key.
///
/// The identifier is a pure function of its inputs, so a retry of the same
/// logical request addresses the same row without a lookup table.
pub fn derive_intent_id(tenant_id: &str, request_idempotency_key: &str) -> String {
    let digest = domain_digest(
        INTENT_ID_DOMAIN,
        &[tenant_id.as_bytes(), request_idempotency_key.as_bytes()],
    );
    format!("sbpi_{}", URL_SAFE_NO_PAD.encode(digest))
}

/// Derives the durable attempt identifier.
///
/// Attempts are identified by intent, operation, and generation, which is
/// exactly the unique constraint the store enforces, so a crashed process
/// and its replacement compute the same identifier.
pub fn derive_attempt_id(
    intent_id: &str,
    operation: AttemptOperation,
    attempt_generation: u32,
) -> String {
    let digest = domain_digest(
        ATTEMPT_ID_DOMAIN,
        &[
            intent_id.as_bytes(),
            operation.as_str().as_bytes(),
            attempt_generation.to_string().as_bytes(),
        ],
    );
    format!("sbpa_{}", URL_SAFE_NO_PAD.encode(digest))
}

/// Derives the durable receipt key.
pub fn derive_receipt_key(
    intent_id: &str,
    rail: SettlementRail,
    provider_reference: &str,
) -> String {
    let digest = domain_digest(
        RECEIPT_KEY_DOMAIN,
        &[
            intent_id.as_bytes(),
            rail.as_str().as_bytes(),
            provider_reference.as_bytes(),
        ],
    );
    format!("sbpr_{}", URL_SAFE_NO_PAD.encode(digest))
}

/// Derives the provider idempotency key for one attempt.
///
/// The material is fixed by the settlement contract:
///
/// ```text
/// material = "sbproxy-settlement-v1\0" || rail || "\0" || operation || "\0" ||
///            tenant_id || "\0" || requirement_id || "\0" || attempt_generation ||
///            "\0" || proof_digest_or_empty
/// provider_idempotency_key = "sbp1_" || base64url_nopad(SHA-256(material))
/// ```
///
/// `attempt_generation` is rendered in decimal and `proof_digest_or_empty`
/// in lowercase hex, or as the empty string when there is no proof yet. The
/// credential itself never appears: only its digest does, so no plaintext
/// credential can be recovered from a key that shows up in a provider's
/// dashboard.
///
/// A pre-dispatch retry reuses the same generation, the same body, and
/// therefore the same key. The generation may increase only after a
/// documented provider query proves the prior dispatch did not occur.
pub fn provider_idempotency_key(
    rail: SettlementRail,
    operation: AttemptOperation,
    tenant_id: &str,
    requirement_id: &str,
    attempt_generation: u32,
    proof_digest: Option<&[u8; 32]>,
) -> String {
    let generation = attempt_generation.to_string();
    let proof = proof_digest.map(hex::encode).unwrap_or_default();
    let mut material = Vec::new();
    material.extend_from_slice(b"sbproxy-settlement-v1\0");
    material.extend_from_slice(rail.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(operation.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(tenant_id.as_bytes());
    material.push(0);
    material.extend_from_slice(requirement_id.as_bytes());
    material.push(0);
    material.extend_from_slice(generation.as_bytes());
    material.push(0);
    material.extend_from_slice(proof.as_bytes());
    let digest: [u8; 32] = Sha256::digest(material.as_slice()).into();
    format!(
        "{PROVIDER_IDEMPOTENCY_KEY_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(digest)
    )
}

/// Shortens a provider idempotency key for a rail with a tighter label limit.
///
/// The full key stays in storage. What goes on the wire is the longest
/// unambiguous prefix that fits, plus a four-character checksum over the
/// full key so two different keys cannot collapse onto one label.
///
/// # Errors
///
/// Returns [`BillingError::InvalidRequirement`] when `max_len` leaves no
/// room for the prefix and the checksum.
pub fn provider_label_for_key(key: &str, max_len: usize) -> Result<String, BillingError> {
    const CHECKSUM_LEN: usize = 4;
    if key.len() <= max_len {
        return Ok(key.to_string());
    }
    if max_len <= PROVIDER_IDEMPOTENCY_KEY_PREFIX.len() + CHECKSUM_LEN + 1 {
        return Err(BillingError::InvalidRequirement("provider_label_len"));
    }
    let checksum = URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()));
    let checksum: String = checksum.chars().take(CHECKSUM_LEN).collect();
    let keep = max_len - CHECKSUM_LEN;
    let prefix: String = key.chars().take(keep).collect();
    Ok(format!("{prefix}{checksum}"))
}
