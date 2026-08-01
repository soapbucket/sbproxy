//! LND settlement over a bounded gRPC channel, pinned to `v0.20.1-beta`.
//!
//! # What makes this adapter deterministic
//!
//! An LND invoice is created with a preimage the payee chooses, and the
//! payment hash is the SHA-256 of that preimage. A randomly generated preimage
//! has to be persisted before the `AddInvoice` dispatch or a crash loses the
//! only handle on the invoice. This adapter derives the preimage instead:
//!
//! ```text
//! preimage = HMAC-SHA256(invoice_key, "sbproxy-lnd-preimage-v1" || 0x00 ||
//!                        intent_id || 0x00 || attempt_generation)
//! payment_hash = SHA-256(preimage)
//! ```
//!
//! Both inputs are already durable: the intent identifier and the attempt
//! generation are columns the store owns. So a process that stopped between
//! `AddInvoice` and recording its answer recomputes the same preimage, the
//! same hash, and finds the invoice with `LookupInvoice`. It never calls
//! `AddInvoice` a second time, and no plaintext preimage is ever persisted or
//! logged. The key is the secret; it lives in a zeroizing buffer with no
//! accessor and no `Debug`.
//!
//! If the lookup proves the hash is absent, the dispatch never landed, the
//! attempt is reported [`ProviderQueryResult::NotDispatched`], and the next
//! generation safely derives a different preimage.
//!
//! # What authorizes
//!
//! Only [`InvoiceState::Settled`] for an incoming payment and only
//! [`PaymentStatus::Succeeded`] for an outgoing one. A stream that ended, a
//! disconnect, a duplicate update, `Open`, `Accepted`, `InFlight`, `Failed`,
//! an amount mismatch, a payment-hash mismatch, and an expired deadline all
//! deny access or enter reconciliation. An unrecognized numeric state parses
//! to `None` rather than to a nearby variant, so a future LND state can never
//! be read as settled.
//!
//! # Transport
//!
//! Provider calls go through [`LndTransport`], exactly as the x402 rail goes
//! through its facilitator transport. The runtime binds it to a bounded TLS
//! gRPC channel that owns the certificate and attaches the macaroon as call
//! metadata. No type here holds a macaroon or a certificate, so none can reach
//! a log, an error, or a durable column, and the contract tests drive the five
//! RPCs deterministically without a socket.

use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::dispatch::DispatchContext;
use crate::error::BillingError;
use crate::lightning::{
    check_bolt11, msat_amount, transport_error, LightningError, LightningTransportFailure,
    PaymentHash, MAX_TOTAL_DEADLINE_MS, PAYMENT_HASH_LEN,
};
use crate::registry::{
    AuthoritativePayment, ChallengeMaterial, ChallengePreparation, PaymentMethodAdapter,
    ProviderQueryResult,
};
use crate::store::ProviderAttempt;
use crate::types::{
    AttemptOperation, FailureCategory, RequirementTerms, SafeFailure, SettlementRail,
    SettlementReceipt,
};

/// HMAC-SHA256, the one MAC the preimage derivation uses.
type HmacSha256 = Hmac<Sha256>;

/// Domain separator for the deterministic invoice preimage.
const PREIMAGE_DOMAIN: &[u8] = b"sbproxy-lnd-preimage-v1";

/// Smallest invoice key this adapter will accept, in bytes.
pub const MIN_INVOICE_KEY_LEN: usize = 32;

/// Smallest supported LND major version.
pub const MIN_LND_MAJOR: u32 = 0;

/// Smallest supported LND minor version at [`MIN_LND_MAJOR`].
pub const MIN_LND_MINOR: u32 = 20;

/// The upstream tag the wire contract in this module is pinned to.
pub const PINNED_LND_TAG: &str = "v0.20.1-beta";

/// The upstream commit the wire contract in this module is pinned to.
pub const PINNED_LND_COMMIT: &str = "848b72ce96eb68fa90fd4336523ca4c59bddcd4c";

/// The challenge field carrying the BOLT 11 payment request.
pub const CHALLENGE_FIELD_PAYMENT_REQUEST: &str = "payment_request";

/// The challenge field carrying the payment hash.
pub const CHALLENGE_FIELD_PAYMENT_HASH: &str = "payment_hash";

// --- Keys and preimages ---

/// The secret the deterministic invoice preimage is derived under.
///
/// Deliberately carries no `Debug`, no `Display`, no serialization, and no
/// accessor. The key never leaves this type, and the preimages it derives
/// never leave a zeroizing buffer.
pub struct InvoiceKey {
    key: Zeroizing<Vec<u8>>,
}

impl InvoiceKey {
    /// Builds a key.
    ///
    /// # Errors
    ///
    /// Returns [`LightningError::Endpoint`] for a key shorter than
    /// [`MIN_INVOICE_KEY_LEN`]. A short key would make a preimage guessable,
    /// and a guessable preimage is a forgeable proof of payment.
    pub fn new(key: &[u8]) -> Result<Self, LightningError> {
        if key.len() < MIN_INVOICE_KEY_LEN {
            return Err(LightningError::Endpoint);
        }
        Ok(Self {
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// Derives the preimage for one intent and attempt generation.
    ///
    /// The result stays in a zeroizing buffer. It goes to the node and
    /// nowhere else: not to a log, not to an error, not to a durable column,
    /// and not into an idempotency key.
    #[must_use]
    pub fn preimage(&self, intent_id: &str, attempt_generation: u32) -> Zeroizing<Vec<u8>> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC-SHA256 accepts a key of any length");
        mac.update(PREIMAGE_DOMAIN);
        mac.update(&[0u8]);
        mac.update(intent_id.as_bytes());
        mac.update(&[0u8]);
        mac.update(attempt_generation.to_string().as_bytes());
        Zeroizing::new(mac.finalize().into_bytes().to_vec())
    }

    /// Derives the payment hash for one intent and attempt generation.
    ///
    /// This is the value that addresses the invoice, and it is recomputable
    /// after a crash from two columns the store already holds.
    #[must_use]
    pub fn payment_hash(&self, intent_id: &str, attempt_generation: u32) -> PaymentHash {
        let preimage = self.preimage(intent_id, attempt_generation);
        payment_hash_of(preimage.as_slice())
    }
}

/// Returns the payment hash of a preimage.
///
/// # Panics
///
/// Never. SHA-256 always produces [`PAYMENT_HASH_LEN`] bytes.
#[must_use]
pub fn payment_hash_of(preimage: &[u8]) -> PaymentHash {
    let digest: [u8; PAYMENT_HASH_LEN] = Sha256::digest(preimage).into();
    PaymentHash::from_bytes(digest)
}

// --- Version ---

/// Parses an LND version string into its major and minor parts.
///
/// LND reports values such as `0.20.1-beta commit=v0.20.1-beta`. Everything
/// after the minor component is ignored. Nothing is coerced: a value without
/// two numeric components is refused rather than treated as zero.
///
/// # Errors
///
/// Returns [`LightningError::VersionMalformed`].
pub fn parse_lnd_version(value: &str) -> Result<(u32, u32), LightningError> {
    let trimmed = value.trim();
    let trimmed = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let mut parts = trimmed.split(['.', '-']);
    let major = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or(LightningError::VersionMalformed)?;
    let minor = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or(LightningError::VersionMalformed)?;
    let major: u32 = major
        .parse()
        .map_err(|_| LightningError::VersionMalformed)?;
    let minor: u32 = minor
        .parse()
        .map_err(|_| LightningError::VersionMalformed)?;
    Ok((major, minor))
}

/// Checks a reported version against the pinned floor.
///
/// # Errors
///
/// Returns [`LightningError::VersionMalformed`] for an unparseable value and
/// [`LightningError::NodeVersion`] below the floor.
pub fn require_supported_version(value: &str) -> Result<(u32, u32), LightningError> {
    let (major, minor) = parse_lnd_version(value)?;
    if (major, minor) < (MIN_LND_MAJOR, MIN_LND_MINOR) {
        return Err(LightningError::NodeVersion);
    }
    Ok((major, minor))
}

// --- Wire contract ---

/// The `Invoice.InvoiceState` enumeration at the pinned tag.
///
/// The numeric values are the upstream ones. An unrecognized number parses to
/// `None`, so a state added in a later LND release can never be read as
/// settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceState {
    /// The invoice exists and no payment arrived.
    Open,
    /// The invoice was paid and the preimage was released. The only state
    /// that authorizes.
    Settled,
    /// The invoice was cancelled and can never be paid.
    Canceled,
    /// A hold invoice is accepted but not settled. Funds have not moved.
    Accepted,
}

impl InvoiceState {
    /// Returns the upstream numeric value.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Open => 0,
            Self::Settled => 1,
            Self::Canceled => 2,
            Self::Accepted => 3,
        }
    }

    /// Parses an upstream numeric value, or returns `None`.
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Open),
            1 => Some(Self::Settled),
            2 => Some(Self::Canceled),
            3 => Some(Self::Accepted),
            _ => None,
        }
    }

    /// Reports whether this state means funds moved.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Settled)
    }
}

/// The `Payment.PaymentStatus` enumeration at the pinned tag.
///
/// An unrecognized number parses to `None` for the same reason
/// [`InvoiceState::from_i32`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// The node has no opinion yet.
    Unknown,
    /// The payment is in flight and may still fail.
    InFlight,
    /// The payment settled. The only state that proves an outgoing payment.
    Succeeded,
    /// The payment failed definitively and no funds moved.
    Failed,
    /// The payment was accepted for sending but has not left yet.
    Initiated,
}

impl PaymentStatus {
    /// Returns the upstream numeric value.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Unknown => 0,
            Self::InFlight => 1,
            Self::Succeeded => 2,
            Self::Failed => 3,
            Self::Initiated => 4,
        }
    }

    /// Parses an upstream numeric value, or returns `None`.
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::InFlight),
            2 => Some(Self::Succeeded),
            3 => Some(Self::Failed),
            4 => Some(Self::Initiated),
            _ => None,
        }
    }

    /// Reports whether this status proves an outgoing payment settled.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

/// The `GetInfo` fields this adapter reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GetInfoResponse {
    /// The node's reported version.
    pub version: String,
    /// Whether the node considers itself synced to the chain.
    pub synced_to_chain: bool,
}

/// The `AddInvoice` request this adapter sends.
///
/// Deliberately carries no `Debug`: `preimage` is the proof of payment and
/// must never be printed.
pub struct AddInvoiceRequest {
    /// The invoice memo. Non-secret.
    pub memo: String,
    /// The invoiced amount, in millisatoshi.
    pub value_msat: u64,
    /// How long the invoice stays payable, in seconds.
    pub expiry_seconds: i64,
    /// The locally derived preimage, in a zeroizing buffer.
    pub preimage: Zeroizing<Vec<u8>>,
}

/// The `AddInvoice` fields this adapter reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddInvoiceResponse {
    /// The payment hash the node recorded, as raw bytes.
    pub r_hash: Vec<u8>,
    /// The BOLT 11 payment request the node generated.
    pub payment_request: String,
}

/// The `LookupInvoice` fields this adapter reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LndInvoice {
    /// The payment hash, as raw bytes.
    pub r_hash: Vec<u8>,
    /// The invoiced amount, in millisatoshi.
    pub value_msat: u64,
    /// The amount actually paid, in millisatoshi.
    pub amt_paid_msat: u64,
    /// The raw `InvoiceState` value.
    pub state: i32,
    /// When the invoice settled, in seconds since the epoch.
    pub settle_date: i64,
    /// The BOLT 11 payment request.
    pub payment_request: String,
}

/// The `SendPaymentV2` request this adapter sends.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SendPaymentRequest {
    /// The BOLT 11 invoice to pay.
    pub payment_request: String,
    /// The node-side timeout, in seconds.
    pub timeout_seconds: i32,
    /// The routing fee ceiling, in millisatoshi.
    pub fee_limit_msat: i64,
}

/// The `Payment` fields this adapter reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LndPayment {
    /// The payment hash, as lowercase hex.
    pub payment_hash: String,
    /// The raw `PaymentStatus` value.
    pub status: i32,
    /// The amount sent, in millisatoshi.
    pub value_msat: i64,
}

/// The `DecodePayReq` fields this adapter reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecodedPayReq {
    /// The payment hash the invoice commits to, as lowercase hex.
    pub payment_hash: String,
    /// The invoiced amount, in millisatoshi.
    pub num_msat: i64,
}

/// The bounded gRPC channel this adapter talks to a node through.
///
/// The implementation owns the TLS certificate and the macaroon and attaches
/// the macaroon as call metadata. Nothing in this module holds either.
///
/// The two streaming RPCs are modeled as their resolved outcome: the
/// implementation consumes the stream inside the caller's budget and yields
/// the terminal update. A stream that ends, disconnects, or repeats without
/// reaching a terminal update yields `None`, which this adapter reads as
/// ambiguous rather than as a failure.
#[async_trait::async_trait]
pub trait LndTransport: Send + Sync {
    /// Calls `GetInfo`.
    async fn get_info(
        &self,
        timeout: Duration,
    ) -> Result<GetInfoResponse, LightningTransportFailure>;

    /// Calls `AddInvoice` with a locally derived preimage.
    async fn add_invoice(
        &self,
        request: AddInvoiceRequest,
        timeout: Duration,
    ) -> Result<AddInvoiceResponse, LightningTransportFailure>;

    /// Calls `LookupInvoice` by payment hash.
    ///
    /// `Ok(None)` means the node proved it holds no invoice for that hash.
    async fn lookup_invoice(
        &self,
        payment_hash: PaymentHash,
        timeout: Duration,
    ) -> Result<Option<LndInvoice>, LightningTransportFailure>;

    /// Calls `SendPaymentV2` and resolves its stream.
    async fn send_payment_v2(
        &self,
        request: SendPaymentRequest,
        timeout: Duration,
    ) -> Result<Option<LndPayment>, LightningTransportFailure>;

    /// Calls `TrackPaymentV2` and resolves its stream.
    ///
    /// `Ok(None)` means no terminal update arrived, which is ambiguous.
    async fn track_payment_v2(
        &self,
        payment_hash: PaymentHash,
        timeout: Duration,
    ) -> Result<Option<LndPayment>, LightningTransportFailure>;

    /// Calls `DecodePayReq`.
    async fn decode_pay_req(
        &self,
        payment_request: &str,
        timeout: Duration,
    ) -> Result<DecodedPayReq, LightningTransportFailure>;
}

/// Checks a settled invoice against the hash and amount the quote signed.
///
/// # Errors
///
/// Returns [`LightningError::BindingMismatch`] when the hash or the paid
/// amount does not match, and [`LightningError::PaymentHash`] when the node
/// answered with a hash that is not 32 bytes.
pub fn verify_settled_invoice(
    invoice: &LndInvoice,
    expected_hash: PaymentHash,
    expected_msat: u64,
) -> Result<PaymentHash, LightningError> {
    let answered = PaymentHash::parse_bytes(&invoice.r_hash)?;
    if answered != expected_hash {
        return Err(LightningError::BindingMismatch);
    }
    if invoice.value_msat != expected_msat {
        return Err(LightningError::BindingMismatch);
    }
    // An overpayment is still a settlement of this obligation. Less is not.
    if invoice.amt_paid_msat < expected_msat {
        return Err(LightningError::BindingMismatch);
    }
    Ok(answered)
}

/// Returns the invoice expiry a set of Lightning terms names.
///
/// # Errors
///
/// Returns [`LightningError::TermsMismatch`] for terms that are not a
/// Lightning invoice.
pub fn invoice_expiry_seconds(terms: &RequirementTerms) -> Result<i64, LightningError> {
    match terms {
        RequirementTerms::LightningInvoice {
            invoice_expiry_seconds,
            ..
        } => Ok(i64::from(*invoice_expiry_seconds)),
        _ => Err(LightningError::TermsMismatch),
    }
}

// --- Settler ---

/// The LND settlement adapter.
///
/// Deliberately carries no `Debug`: it owns the invoice key the deterministic
/// preimages are derived under.
pub struct LndSettler<T: LndTransport> {
    transport: T,
    invoice_key: InvoiceKey,
    memo: String,
    call_timeout: Duration,
    total_deadline: Duration,
}

impl<T: LndTransport> LndSettler<T> {
    /// Builds a settler.
    ///
    /// # Errors
    ///
    /// Returns [`LightningError::Deadline`] when the total deadline is zero,
    /// above [`MAX_TOTAL_DEADLINE_MS`], or smaller than the per-call budget it
    /// is supposed to bound.
    pub fn new(
        transport: T,
        invoice_key: InvoiceKey,
        memo: &str,
        call_timeout_ms: u64,
        total_deadline_ms: u64,
    ) -> Result<Self, LightningError> {
        if total_deadline_ms == 0
            || total_deadline_ms > MAX_TOTAL_DEADLINE_MS
            || call_timeout_ms == 0
            || call_timeout_ms > total_deadline_ms
        {
            return Err(LightningError::Deadline);
        }
        Ok(Self {
            transport,
            invoice_key,
            memo: memo.to_string(),
            call_timeout: Duration::from_millis(call_timeout_ms),
            total_deadline: Duration::from_millis(total_deadline_ms),
        })
    }

    /// Returns the total request-path deadline.
    #[must_use]
    pub const fn total_deadline(&self) -> Duration {
        self.total_deadline
    }

    /// Asks `GetInfo` and proves the node meets the pinned version floor.
    ///
    /// The runtime calls this before registering the rail.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ProviderUnavailable`] for a node below the
    /// floor, a version this build cannot parse, or a node that is not synced
    /// to the chain.
    pub async fn probe_version(&self) -> Result<(u32, u32), BillingError> {
        let info = self
            .transport
            .get_info(self.call_timeout)
            .await
            .map_err(transport_error)?;
        if !info.synced_to_chain {
            return Err(BillingError::ProviderUnavailable);
        }
        Ok(require_supported_version(&info.version)?)
    }

    /// Refuses a refund.
    ///
    /// An LND invoice records no payer destination, so there is nobody to pay
    /// back. This returns a typed error rather than a receipt for money that
    /// did not move. Paying a destination an operator supplied is a payout,
    /// and it is [`LndSettler::pay_invoice`].
    ///
    /// # Errors
    ///
    /// Always returns [`LightningError::NoPayerDestination`].
    pub fn refund(&self) -> Result<SettlementReceipt, LightningError> {
        Err(LightningError::NoPayerDestination)
    }

    /// Returns the payment hash one intent and generation addresses.
    #[must_use]
    pub fn expected_hash(&self, intent_id: &str, attempt_generation: u32) -> PaymentHash {
        self.invoice_key.payment_hash(intent_id, attempt_generation)
    }

    /// Decodes a BOLT 11 invoice through the node.
    ///
    /// The payment hash an outgoing payment is persisted under comes from
    /// here, never from a local parse, so nothing this crate guessed can end
    /// up addressing a payment.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ProviderMalformed`] when the node answers with
    /// an unusable hash.
    pub async fn decode_invoice_hash(
        &self,
        payment_request: &str,
    ) -> Result<PaymentHash, BillingError> {
        check_bolt11(payment_request)?;
        let decoded = self
            .transport
            .decode_pay_req(payment_request, self.call_timeout)
            .await
            .map_err(transport_error)?;
        Ok(PaymentHash::parse_hex(&decoded.payment_hash)?)
    }

    /// Sends an outgoing payment with `SendPaymentV2`.
    ///
    /// `persisted_hash` must already be durable: the caller decodes the
    /// invoice with [`LndSettler::decode_invoice_hash`], persists that hash,
    /// and only then calls this. A crash after dispatch is resolved by
    /// [`LndSettler::track_payment`], never by sending a second payment.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::NeedsReconciliation`] for a stream that ended
    /// without a terminal update or a payment hash that does not match, and
    /// [`BillingError::ProviderRejected`] for a definite failure.
    pub async fn pay_invoice(
        &self,
        dispatch: &DispatchContext,
        payment_request: &str,
        persisted_hash: PaymentHash,
        fee_limit_msat: i64,
    ) -> Result<PaymentHash, BillingError> {
        check_bolt11(payment_request)?;
        let request = SendPaymentRequest {
            payment_request: payment_request.to_string(),
            timeout_seconds: i32::try_from(self.total_deadline.as_secs())
                .unwrap_or(i32::MAX)
                .max(1),
            fee_limit_msat,
        };
        let resolved = dispatch
            .run_write(|| async {
                self.transport
                    .send_payment_v2(request, self.call_timeout)
                    .await
                    .map_err(transport_error)
            })
            .await?;
        read_terminal_payment(resolved.as_ref(), persisted_hash)
    }

    /// Resolves a dispatched outgoing payment with `TrackPaymentV2`.
    ///
    /// This is a read. It never sends a second payment, which is the whole
    /// reason it exists.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::NeedsReconciliation`] when the node has no
    /// terminal update and [`BillingError::ProviderRejected`] for a definite
    /// failure.
    pub async fn track_payment(
        &self,
        dispatch: &DispatchContext,
        persisted_hash: PaymentHash,
    ) -> Result<PaymentHash, BillingError> {
        let resolved = dispatch
            .run_query(|| async {
                self.transport
                    .track_payment_v2(persisted_hash, self.call_timeout)
                    .await
                    .map_err(transport_error)
            })
            .await?;
        read_terminal_payment(resolved.as_ref(), persisted_hash)
    }
}

/// Reads a resolved payment update, refusing anything short of success.
///
/// # Errors
///
/// Returns [`BillingError::NeedsReconciliation`] for a missing terminal
/// update, an unrecognized status, an in-flight payment, or a hash that does
/// not match, and [`BillingError::ProviderRejected`] for a definite failure.
pub fn read_terminal_payment(
    payment: Option<&LndPayment>,
    expected_hash: PaymentHash,
) -> Result<PaymentHash, BillingError> {
    // A stream that ended without a terminal update leaves the send
    // outstanding. It is never read as a failure and never retried.
    let payment = payment.ok_or(BillingError::NeedsReconciliation)?;
    let answered = PaymentHash::parse_hex(&payment.payment_hash)?;
    if answered != expected_hash {
        return Err(BillingError::NeedsReconciliation);
    }
    match PaymentStatus::from_i32(payment.status) {
        Some(PaymentStatus::Succeeded) => Ok(answered),
        Some(PaymentStatus::Failed) => Err(BillingError::ProviderRejected),
        Some(PaymentStatus::InFlight | PaymentStatus::Initiated | PaymentStatus::Unknown) => {
            Err(BillingError::NeedsReconciliation)
        }
        None => Err(BillingError::ProviderMalformed),
    }
}

#[async_trait::async_trait]
impl<T: LndTransport> PaymentMethodAdapter for LndSettler<T> {
    fn rail(&self) -> SettlementRail {
        SettlementRail::LightningLnd
    }

    async fn prepare_challenge(
        &self,
        request: ChallengePreparation,
        dispatch: &DispatchContext,
    ) -> Result<ChallengeMaterial, BillingError> {
        let attempt = dispatch
            .attempt()
            .ok_or(BillingError::UnsupportedOperation)?;
        let generation = attempt.attempt_generation;
        let value_msat = msat_amount(&request.draft)?;
        let expiry_seconds = invoice_expiry_seconds(&request.draft.terms)?;
        let expected = self.expected_hash(&request.intent_id, generation);

        // The preimage exists only for the duration of the call and is wiped
        // when this buffer drops. It is recomputable, so nothing is lost by
        // never persisting it.
        let preimage = self.invoice_key.preimage(&request.intent_id, generation);
        let add = AddInvoiceRequest {
            memo: self.memo.clone(),
            value_msat,
            expiry_seconds,
            preimage,
        };

        let inner = dispatch.run_write(|| async {
            self.transport
                .add_invoice(add, self.call_timeout)
                .await
                .map_err(transport_error)
        });
        let response = match tokio::time::timeout(self.total_deadline, inner).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(deadline_error(dispatch)),
        };

        let answered = PaymentHash::parse_bytes(&response.r_hash)?;
        if answered != expected {
            // The node recorded a different hash than the preimage this crate
            // derived. Nothing about that is safe to build a challenge on.
            return Err(BillingError::NeedsReconciliation);
        }
        check_bolt11(&response.payment_request)?;

        Ok(ChallengeMaterial::new(Some(expected.to_hex()))
            .with_field(CHALLENGE_FIELD_PAYMENT_REQUEST, &response.payment_request)
            .with_field(CHALLENGE_FIELD_PAYMENT_HASH, &expected.to_hex()))
    }

    async fn authorize_and_settle(
        &self,
        request: AuthoritativePayment,
        dispatch: &DispatchContext,
    ) -> Result<SettlementReceipt, BillingError> {
        let draft = &request.requirement.draft;
        let value_msat = msat_amount(draft)?;
        // The hash comes from the signed requirement, which recorded it at
        // challenge time. It is never recomputed from this attempt's
        // generation, which is a different generation entirely.
        let handle = request
            .requirement
            .provider_handle
            .as_deref()
            .ok_or(BillingError::IntentNotFinalized)?;
        let expected = PaymentHash::parse_hex(handle)?;

        // The lookup is this rail's authoritative settlement operation, so it
        // runs inside the one write gate call. See the module documentation
        // for why an incoming Lightning settlement is stamped at all.
        let inner = dispatch.run_write(|| async {
            let found = self
                .transport
                .lookup_invoice(expected, self.call_timeout)
                .await
                .map_err(transport_error)?;
            let invoice = found.ok_or(BillingError::ProviderMalformed)?;
            match InvoiceState::from_i32(invoice.state) {
                Some(InvoiceState::Settled) => {}
                Some(InvoiceState::Canceled) => return Err(BillingError::ProviderRejected),
                // Open and Accepted both mean funds have not moved. The
                // worker keeps asking, and a payment that lands a moment
                // later is proved by the same lookup.
                Some(InvoiceState::Open | InvoiceState::Accepted) => {
                    return Err(BillingError::NotSettled)
                }
                None => return Err(BillingError::ProviderMalformed),
            }
            let hash = verify_settled_invoice(&invoice, expected, value_msat)?;
            SettlementReceipt::new(
                &request.intent_id,
                SettlementRail::LightningLnd,
                draft.method.as_str(),
                &hash.to_hex(),
                request.now_ms,
            )
        });

        match tokio::time::timeout(self.total_deadline, inner).await {
            Ok(result) => result,
            Err(_elapsed) => Err(deadline_error(dispatch)),
        }
    }

    async fn query_attempt(
        &self,
        attempt: &ProviderAttempt,
        dispatch: &DispatchContext,
    ) -> Result<ProviderQueryResult, BillingError> {
        let Some(requirement) = attempt.requirement.as_ref() else {
            return Ok(ProviderQueryResult::Unsupported);
        };
        let value_msat = msat_amount(&requirement.draft)?;
        let now_ms = dispatch.now_ms();

        // A lost `AddInvoice` leaves no persisted handle. The deterministic
        // derivation recomputes the same hash from two durable columns, so the
        // lookup addresses the exact invoice that dispatch may have created.
        let expected = match attempt.provider_handle.as_deref() {
            Some(handle) => PaymentHash::parse_hex(handle)?,
            None => self.expected_hash(&attempt.intent_id, attempt.attempt_generation),
        };

        let found = dispatch
            .run_query(|| async {
                self.transport
                    .lookup_invoice(expected, self.call_timeout)
                    .await
                    .map_err(transport_error)
            })
            .await?;

        let Some(invoice) = found else {
            // The node proved it holds no invoice for this hash, so the
            // dispatch never landed. A later challenge preparation may safely
            // derive a new preimage at the next generation.
            return Ok(if attempt.operation == AttemptOperation::PrepareChallenge {
                ProviderQueryResult::NotDispatched
            } else {
                ProviderQueryResult::Failed(SafeFailure::category(FailureCategory::Rejected, false))
            });
        };

        match InvoiceState::from_i32(invoice.state) {
            Some(InvoiceState::Settled) => {
                let hash = verify_settled_invoice(&invoice, expected, value_msat)?;
                if !attempt.operation.can_settle() {
                    // A settled invoice under a challenge-preparation attempt
                    // is a real payment, but that attempt cannot commit a
                    // receipt. It stays unresolved until the client redeems.
                    return Ok(ProviderQueryResult::StillPending);
                }
                Ok(ProviderQueryResult::Settled(SettlementReceipt::new(
                    &attempt.intent_id,
                    SettlementRail::LightningLnd,
                    requirement.draft.method.as_str(),
                    &hash.to_hex(),
                    now_ms,
                )?))
            }
            Some(InvoiceState::Canceled) => Ok(ProviderQueryResult::Failed(SafeFailure::category(
                FailureCategory::Rejected,
                false,
            ))),
            Some(InvoiceState::Open | InvoiceState::Accepted) => {
                Ok(ProviderQueryResult::StillPending)
            }
            None => Err(BillingError::ProviderMalformed),
        }
    }
}

/// Maps an elapsed deadline onto the durable transition the gate permits.
fn deadline_error(dispatch: &DispatchContext) -> BillingError {
    if dispatch.was_dispatched() {
        BillingError::NeedsReconciliation
    } else {
        BillingError::ProviderTimeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unwrap_err` requires `Debug` on the success type, which several types
    /// in this crate deliberately lack. Errors are unwrapped through this
    /// helper rather than widening a derive to suit a test.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    /// A fixed test key. Never a real one.
    fn test_key() -> InvoiceKey {
        InvoiceKey::new(&[9u8; 32]).expect("a 32 byte key is usable")
    }

    #[test]
    fn a_short_invoice_key_is_refused() {
        assert_eq!(
            expect_error(InvoiceKey::new(&[1u8; 16]), "a short key must be refused"),
            LightningError::Endpoint
        );
        assert!(InvoiceKey::new(&[1u8; 32]).is_ok());
    }

    #[test]
    fn the_preimage_is_deterministic_across_processes() {
        let first = test_key();
        let second = test_key();
        assert_eq!(
            first.payment_hash("sbpi_abc", 0),
            second.payment_hash("sbpi_abc", 0),
            "a replacement process derives the same hash"
        );
        assert_eq!(
            first.preimage("sbpi_abc", 0).as_slice(),
            second.preimage("sbpi_abc", 0).as_slice()
        );
    }

    #[test]
    fn a_new_generation_derives_a_different_preimage() {
        let key = test_key();
        assert_ne!(
            key.payment_hash("sbpi_abc", 0),
            key.payment_hash("sbpi_abc", 1),
            "a later generation must not reuse a preimage"
        );
        assert_ne!(
            key.payment_hash("sbpi_abc", 0),
            key.payment_hash("sbpi_abd", 0),
            "a different intent must not reuse a preimage"
        );
    }

    #[test]
    fn a_different_key_derives_a_different_preimage() {
        let one = InvoiceKey::new(&[1u8; 32]).expect("usable");
        let two = InvoiceKey::new(&[2u8; 32]).expect("usable");
        assert_ne!(
            one.payment_hash("sbpi_abc", 0),
            two.payment_hash("sbpi_abc", 0)
        );
    }

    #[test]
    fn the_payment_hash_is_the_sha256_of_the_preimage() {
        let key = test_key();
        let preimage = key.preimage("sbpi_abc", 0);
        assert_eq!(preimage.len(), PAYMENT_HASH_LEN);
        assert_eq!(
            key.payment_hash("sbpi_abc", 0),
            payment_hash_of(preimage.as_slice())
        );
    }

    #[test]
    fn only_settled_and_succeeded_are_read_as_terminal_success() {
        assert_eq!(InvoiceState::from_i32(1), Some(InvoiceState::Settled));
        assert!(InvoiceState::from_i32(1).expect("settled").is_settled());
        for value in [0, 2, 3] {
            let state = InvoiceState::from_i32(value).expect("a known state");
            assert!(!state.is_settled(), "state {value} must not authorize");
        }
        // A state added in a later LND release is not coerced onto a known one.
        assert_eq!(InvoiceState::from_i32(4), None);
        assert_eq!(InvoiceState::from_i32(-1), None);

        assert_eq!(PaymentStatus::from_i32(2), Some(PaymentStatus::Succeeded));
        for value in [0, 1, 3, 4] {
            let status = PaymentStatus::from_i32(value).expect("a known status");
            assert!(!status.is_settled(), "status {value} must not authorize");
        }
        assert_eq!(PaymentStatus::from_i32(5), None);
    }

    #[test]
    fn the_upstream_numeric_values_round_trip() {
        for state in [
            InvoiceState::Open,
            InvoiceState::Settled,
            InvoiceState::Canceled,
            InvoiceState::Accepted,
        ] {
            assert_eq!(InvoiceState::from_i32(state.as_i32()), Some(state));
        }
        for status in [
            PaymentStatus::Unknown,
            PaymentStatus::InFlight,
            PaymentStatus::Succeeded,
            PaymentStatus::Failed,
            PaymentStatus::Initiated,
        ] {
            assert_eq!(PaymentStatus::from_i32(status.as_i32()), Some(status));
        }
    }

    #[test]
    fn a_settled_invoice_must_match_its_hash_and_amount() {
        let expected = PaymentHash::from_bytes([3u8; PAYMENT_HASH_LEN]);
        let invoice = LndInvoice {
            r_hash: expected.as_bytes().to_vec(),
            value_msat: 100_000,
            amt_paid_msat: 100_000,
            state: InvoiceState::Settled.as_i32(),
            settle_date: 1,
            payment_request: "lnbc1abc".to_string(),
        };
        assert!(verify_settled_invoice(&invoice, expected, 100_000).is_ok());

        let other = PaymentHash::from_bytes([4u8; PAYMENT_HASH_LEN]);
        assert_eq!(
            expect_error(
                verify_settled_invoice(&invoice, other, 100_000),
                "a hash mismatch must deny"
            ),
            LightningError::BindingMismatch
        );
        assert_eq!(
            expect_error(
                verify_settled_invoice(&invoice, expected, 100_001),
                "an amount mismatch must deny"
            ),
            LightningError::BindingMismatch
        );

        let underpaid = LndInvoice {
            amt_paid_msat: 99_999,
            ..invoice
        };
        assert_eq!(
            expect_error(
                verify_settled_invoice(&underpaid, expected, 100_000),
                "an underpayment must deny"
            ),
            LightningError::BindingMismatch
        );
    }

    #[test]
    fn a_stream_that_ended_is_ambiguous_and_never_a_failure() {
        let expected = PaymentHash::from_bytes([5u8; PAYMENT_HASH_LEN]);
        assert_eq!(
            expect_error(
                read_terminal_payment(None, expected),
                "a missing terminal update must not resolve"
            ),
            BillingError::NeedsReconciliation
        );

        let in_flight = LndPayment {
            payment_hash: expected.to_hex(),
            status: PaymentStatus::InFlight.as_i32(),
            value_msat: 1,
        };
        assert_eq!(
            expect_error(
                read_terminal_payment(Some(&in_flight), expected),
                "an in flight payment must not resolve"
            ),
            BillingError::NeedsReconciliation
        );

        let mismatched = LndPayment {
            payment_hash: PaymentHash::from_bytes([6u8; PAYMENT_HASH_LEN]).to_hex(),
            status: PaymentStatus::Succeeded.as_i32(),
            value_msat: 1,
        };
        assert_eq!(
            expect_error(
                read_terminal_payment(Some(&mismatched), expected),
                "a hash mismatch must not resolve"
            ),
            BillingError::NeedsReconciliation
        );

        let failed = LndPayment {
            payment_hash: expected.to_hex(),
            status: PaymentStatus::Failed.as_i32(),
            value_msat: 0,
        };
        assert_eq!(
            expect_error(
                read_terminal_payment(Some(&failed), expected),
                "a failed payment is a refusal"
            ),
            BillingError::ProviderRejected
        );

        let settled = LndPayment {
            payment_hash: expected.to_hex(),
            status: PaymentStatus::Succeeded.as_i32(),
            value_msat: 1,
        };
        assert_eq!(
            read_terminal_payment(Some(&settled), expected).expect("a settled payment resolves"),
            expected
        );
    }

    #[test]
    fn the_version_floor_matches_the_pinned_tag() {
        assert_eq!(
            require_supported_version("0.20.1-beta").expect("floor"),
            (0, 20)
        );
        assert_eq!(
            require_supported_version("0.20.1-beta commit=v0.20.1-beta").expect("commit suffix"),
            (0, 20)
        );
        assert_eq!(
            require_supported_version("v0.21.0-beta").expect("newer"),
            (0, 21)
        );
        assert_eq!(
            expect_error(
                require_supported_version("0.19.2-beta"),
                "an older minor must be refused"
            ),
            LightningError::NodeVersion
        );
        for bad in ["", "v", "beta", "0", "0.x"] {
            assert_eq!(
                expect_error(
                    require_supported_version(bad),
                    "a malformed version must be refused"
                ),
                LightningError::VersionMalformed,
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn the_pinned_upstream_coordinates_are_recorded() {
        assert_eq!(PINNED_LND_TAG, "v0.20.1-beta");
        assert_eq!(
            PINNED_LND_COMMIT,
            "848b72ce96eb68fa90fd4336523ca4c59bddcd4c"
        );
    }
}
