//! Lightning settlement, shared between the Core Lightning and LND adapters.
//!
//! This module owns everything the two backends agree on: exact millisatoshi
//! arithmetic, durable labels, payment hashes, the typed error set, and the
//! one design decision that shapes both adapters.
//!
//! # Why an incoming Lightning settlement runs through the write gate
//!
//! Nothing is written to a node when a Lightning payment is redeemed. The
//! payer paid the invoice out of band and the proxy only asks the node whether
//! that happened. The durable model still requires the dispatch stamp before a
//! settlement can be committed, so both adapters wrap the authoritative
//! invoice lookup in a single [`crate::dispatch::DispatchContext::run_write`].
//!
//! The consequence is deliberate and is the safe direction: an ambiguous
//! lookup leaves the attempt needing reconciliation rather than free to retry.
//! The recovery worker performs the same lookup, so an invoice that is paid a
//! moment later is proved settled by
//! [`crate::registry::ProviderQueryResult::Settled`] and the client's next
//! retry is let through. Nothing is ever inferred from RPC transport success.
//!
//! # What is authoritative
//!
//! Core Lightning: `listinvoices` by the exact durable label, and only the
//! documented `status = "paid"`. LND: `LookupInvoice` by the payment hash, and
//! only `InvoiceState::Settled`. An unpaid, expired, missing, duplicated,
//! malformed, or timed out answer denies access. There is no path from an RPC
//! that merely returned to a receipt.
//!
//! # Refunds
//!
//! A Lightning invoice records no payer destination. There is nobody to pay
//! back, so both adapters refuse a refund with
//! [`LightningError::NoPayerDestination`] rather than returning a receipt for
//! money that did not move. Sending to a keysend destination an operator typed
//! in is a payout, not a refund, and it is a separate, explicitly named call.
//!
//! # Redaction
//!
//! Runes, macaroons, TLS material, and preimages never appear in a type here,
//! in an error, in a log line, or in a durable column. Payment hashes do: a
//! hash is published in the invoice and is the operator's only handle on a
//! payment.

#[cfg(feature = "lightning-cln")]
pub mod cln;
#[cfg(feature = "lightning-lnd")]
pub mod lnd;

use crate::error::BillingError;
use crate::money::Money;
use crate::types::PaymentRequirementDraft;

/// Hard ceiling on the total request-path deadline, in milliseconds.
pub const MAX_TOTAL_DEADLINE_MS: u64 = 2_000;

/// Millisatoshi in one satoshi.
pub const MSAT_PER_SAT: u64 = 1_000;

/// Declared precision that means the advertised amount counts satoshi.
pub const SAT_DECIMALS: u8 = 8;

/// Declared precision that means the advertised amount counts millisatoshi.
pub const MSAT_DECIMALS: u8 = 11;

/// Prefix on every durable label this crate gives a node.
pub const LABEL_PREFIX: &str = "sbproxy-";

/// Longest label either backend is asked to store.
pub const MAX_LABEL_LEN: usize = 128;

/// Bytes in a payment hash and in a preimage.
pub const PAYMENT_HASH_LEN: usize = 32;

// --- Errors ---

/// Everything the Lightning adapters refuse, as a typed, non-secret reason.
///
/// Every message is a fixed string. No variant carries a rune, a macaroon, a
/// preimage, a node address, or an RPC body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LightningError {
    /// The configured socket path or endpoint is not usable.
    #[error("lightning node endpoint is not usable")]
    Endpoint,

    /// The node runs a version below the pinned floor.
    #[error("lightning node version is below the supported floor")]
    NodeVersion,

    /// A version string did not parse.
    #[error("lightning node version string is malformed")]
    VersionMalformed,

    /// The requirement terms are not a Lightning invoice.
    #[error("lightning requirement terms do not name a lightning invoice")]
    TermsMismatch,

    /// The advertised amount is not a whole millisatoshi count.
    #[error("lightning amount is not an exact millisatoshi count")]
    Amount,

    /// The currency is not the one Lightning settles in.
    #[error("lightning settles only in bitcoin")]
    Currency,

    /// A payment hash was not 32 bytes of lowercase hex.
    #[error("lightning payment hash is malformed")]
    PaymentHash,

    /// A durable label would exceed [`MAX_LABEL_LEN`].
    #[error("lightning label exceeds its size bound")]
    Label,

    /// A response did not parse as the pinned contract.
    #[error("lightning response does not match the pinned contract")]
    Malformed,

    /// A response exceeded its size bound.
    #[error("lightning response exceeds its size bound")]
    TooLarge,

    /// The node returned more than one record for a unique label.
    #[error("lightning node returned an ambiguous label")]
    AmbiguousLabel,

    /// The invoice the node returned is not the one that was asked for.
    #[error("lightning invoice does not match the signed requirement")]
    BindingMismatch,

    /// A refund was requested on a rail that records no payer destination.
    #[error("a lightning invoice records no payer destination to refund")]
    NoPayerDestination,

    /// A BOLT 11 invoice was empty, oversized, or outside its character class.
    #[error("bolt11 invoice is not usable")]
    Bolt11,

    /// The configured deadlines do not bound the calls inside them.
    #[error("lightning deadlines are not usable")]
    Deadline,
}

impl From<LightningError> for BillingError {
    fn from(error: LightningError) -> Self {
        match error {
            LightningError::Endpoint | LightningError::Deadline => {
                Self::InvalidRequirement("lightning_endpoint")
            }
            LightningError::NodeVersion | LightningError::VersionMalformed => {
                Self::ProviderUnavailable
            }
            LightningError::TermsMismatch | LightningError::NoPayerDestination => {
                Self::UnsupportedOperation
            }
            LightningError::Amount => Self::AmountNotRepresentable,
            LightningError::Currency => Self::InvalidCurrency,
            LightningError::Label | LightningError::Bolt11 => {
                Self::InvalidRequirement("lightning_label")
            }
            LightningError::BindingMismatch => Self::RequirementMismatch,
            LightningError::PaymentHash
            | LightningError::Malformed
            | LightningError::TooLarge
            | LightningError::AmbiguousLabel => Self::ProviderMalformed,
        }
    }
}

/// Why a node call did not produce a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightningTransportFailure {
    /// The call did not complete inside its budget.
    Timeout,
    /// The socket or channel could not be established or was lost.
    Connection,
    /// The response exceeded its size bound.
    TooLarge,
}

/// Maps a transport failure onto a durable failure.
#[must_use]
pub const fn transport_error(failure: LightningTransportFailure) -> BillingError {
    match failure {
        LightningTransportFailure::Timeout => BillingError::ProviderTimeout,
        LightningTransportFailure::Connection => BillingError::ProviderUnavailable,
        LightningTransportFailure::TooLarge => BillingError::ProviderMalformed,
    }
}

// --- Money ---

/// Returns the exact millisatoshi amount a requirement prices.
///
/// The requirement's own declared precision decides the unit: eight decimals
/// means the advertised string counts satoshi and eleven means it counts
/// millisatoshi. Nothing else is accepted, no exponent is guessed from the
/// currency, and there is no floating point. A satoshi count is scaled by
/// exactly [`MSAT_PER_SAT`] with checked arithmetic.
///
/// # Errors
///
/// Returns [`BillingError::InvalidCurrency`] for a currency Lightning does not
/// settle, [`BillingError::InvalidPrecision`] for any other declared
/// precision, and [`BillingError::AmountNotRepresentable`] when the advertised
/// string and the exact conversion disagree or the scale overflows.
pub fn msat_amount(draft: &PaymentRequirementDraft) -> Result<u64, BillingError> {
    let currency = draft.amount.currency_code()?;
    if currency.as_str() != "BTC" && currency.as_str() != "XBT" {
        return Err(BillingError::InvalidCurrency);
    }
    let base = draft.amount.to_base_units(draft.settlement_decimals)?;
    if draft.settlement_amount != base.to_string() {
        return Err(BillingError::AmountNotRepresentable);
    }
    match draft.settlement_decimals {
        MSAT_DECIMALS => Ok(base),
        SAT_DECIMALS => base
            .checked_mul(MSAT_PER_SAT)
            .ok_or(BillingError::AmountNotRepresentable),
        _ => Err(BillingError::InvalidPrecision),
    }
}

/// Rebuilds an exact amount from a millisatoshi count.
///
/// Used when checking that a node's reported paid amount still means the price
/// that was quoted.
///
/// # Errors
///
/// Propagates the errors of [`Money::from_base_units`].
pub fn money_from_msat(msat: u64, currency: &str) -> Result<Money, BillingError> {
    Money::from_base_units(msat, MSAT_DECIMALS, currency)
}

// --- Labels ---

/// Derives the durable label an incoming invoice is created and queried under.
///
/// The label is a pure function of the durable intent, so a process that
/// crashed after creating the invoice recomputes the same label and finds the
/// invoice rather than creating a second one.
///
/// # Errors
///
/// Returns [`LightningError::Label`] when the rendered label would exceed
/// [`MAX_LABEL_LEN`].
pub fn invoice_label(intent_id: &str) -> Result<String, LightningError> {
    build_label("invoice", intent_id)
}

/// Derives the durable label an outgoing payment is sent under.
///
/// # Errors
///
/// Returns [`LightningError::Label`] when the rendered label would exceed
/// [`MAX_LABEL_LEN`].
pub fn payment_label(attempt_id: &str) -> Result<String, LightningError> {
    build_label("pay", attempt_id)
}

/// Renders one durable label and bounds it.
fn build_label(kind: &str, id: &str) -> Result<String, LightningError> {
    if id.trim().is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(LightningError::Label);
    }
    let label = format!("{LABEL_PREFIX}{kind}-{id}");
    if label.len() > MAX_LABEL_LEN {
        return Err(LightningError::Label);
    }
    Ok(label)
}

// --- Payment hashes ---

/// A 32-byte Lightning payment hash.
///
/// A payment hash is published in the invoice, so it is not secret and it is
/// the operator's handle on a payment. A preimage is the opposite and never
/// gets a type here that could be printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaymentHash([u8; PAYMENT_HASH_LEN]);

impl PaymentHash {
    /// Wraps raw hash bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PAYMENT_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses lowercase hex.
    ///
    /// # Errors
    ///
    /// Returns [`LightningError::PaymentHash`] for anything that is not
    /// exactly 64 hex characters.
    pub fn parse_hex(value: &str) -> Result<Self, LightningError> {
        let decoded = hex::decode(value).map_err(|_| LightningError::PaymentHash)?;
        let bytes: [u8; PAYMENT_HASH_LEN] = decoded
            .try_into()
            .map_err(|_| LightningError::PaymentHash)?;
        Ok(Self(bytes))
    }

    /// Parses raw bytes a gRPC field carried.
    ///
    /// # Errors
    ///
    /// Returns [`LightningError::PaymentHash`] unless the slice is exactly
    /// [`PAYMENT_HASH_LEN`] bytes.
    pub fn parse_bytes(value: &[u8]) -> Result<Self, LightningError> {
        let bytes: [u8; PAYMENT_HASH_LEN] =
            value.try_into().map_err(|_| LightningError::PaymentHash)?;
        Ok(Self(bytes))
    }

    /// Renders lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Borrows the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PAYMENT_HASH_LEN] {
        &self.0
    }
}

impl std::fmt::Display for PaymentHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

// --- BOLT 11 ---

/// Longest BOLT 11 invoice either adapter will hand to a node.
pub const MAX_BOLT11_LEN: usize = 2_048;

/// Checks that a BOLT 11 string is structurally usable before it is sent.
///
/// This is a bound and a character-class check, not a decode. The payment hash
/// an outgoing payment is persisted under comes from the node's own decode
/// call, never from a local guess, so a malformed invoice is refused by the
/// node rather than turned into a hash this crate invented.
///
/// # Errors
///
/// Returns [`LightningError::Bolt11`].
pub fn check_bolt11(invoice: &str) -> Result<(), LightningError> {
    if invoice.is_empty() || invoice.len() > MAX_BOLT11_LEN {
        return Err(LightningError::Bolt11);
    }
    let lower = invoice.to_ascii_lowercase();
    let prefixed = ["lnbc", "lntb", "lntbs", "lnbcrt", "lnsb"]
        .iter()
        .any(|prefix| lower.starts_with(prefix));
    if !prefixed {
        return Err(LightningError::Bolt11);
    }
    // Bech32 data is restricted to alphanumerics; anything else is not an
    // invoice this crate will forward.
    if !lower.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(LightningError::Bolt11);
    }
    Ok(())
}

/// Refuses a refund on a rail that records no payer destination.
///
/// This exists so the refusal is a named, typed value rather than a comment
/// nobody reads. There is no companion function that succeeds.
///
/// # Errors
///
/// Always returns [`LightningError::NoPayerDestination`].
pub const fn refuse_refund() -> Result<std::convert::Infallible, LightningError> {
    Err(LightningError::NoPayerDestination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AdvertisedRail, PaymentProtocol, RequirementTerms, SettlementRail};

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

    /// Builds a Lightning draft for the money tests.
    fn draft_fixture(
        amount_micros: u64,
        decimals: u8,
        settlement_amount: &str,
        currency: &str,
    ) -> PaymentRequirementDraft {
        PaymentRequirementDraft {
            requirement_id: "requirement_0123456789".to_string(),
            protocol: PaymentProtocol::LightningInvoice,
            advertised_rail: AdvertisedRail::Lightning,
            settlement_rail: SettlementRail::LightningCln,
            method: "lightning".to_string(),
            intent: "charge".to_string(),
            network: Some("bitcoin".to_string()),
            asset: None,
            pay_to: None,
            amount: Money {
                amount_micros,
                currency: currency.to_string(),
            },
            settlement_amount: settlement_amount.to_string(),
            settlement_decimals: decimals,
            terms: RequirementTerms::LightningInvoice {
                backend: "cln".to_string(),
                invoice_expiry_seconds: 600,
            },
            quote_id: "quote-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            origin_id: "origin-1".to_string(),
            route: "/paid".to_string(),
            expires_at_ms: 2_000,
            request_digest: None,
        }
    }

    #[test]
    fn millisatoshi_amounts_are_exact_at_both_declared_precisions() {
        // One micro-BTC is 100 satoshi, which is 100_000 millisatoshi.
        let msat = draft_fixture(1, MSAT_DECIMALS, "100000", "BTC");
        assert_eq!(msat_amount(&msat).expect("exact"), 100_000);

        let sat = draft_fixture(1, SAT_DECIMALS, "100", "BTC");
        assert_eq!(msat_amount(&sat).expect("exact"), 100_000);
    }

    #[test]
    fn a_non_bitcoin_currency_never_becomes_millisatoshi() {
        let usd = draft_fixture(1_000_000, MSAT_DECIMALS, "100000000000", "USD");
        assert_eq!(
            expect_error(msat_amount(&usd), "a fiat currency must be refused"),
            BillingError::InvalidCurrency
        );
    }

    #[test]
    fn an_unsupported_precision_is_refused_rather_than_rescaled() {
        let odd = draft_fixture(1, 6, "1", "BTC");
        assert_eq!(
            expect_error(
                msat_amount(&odd),
                "an unsupported precision must be refused"
            ),
            BillingError::InvalidPrecision
        );
    }

    #[test]
    fn labels_are_derived_bounded_and_distinct() {
        let invoice = invoice_label("sbpi_abc").expect("a usable label");
        let payment = payment_label("sbpa_abc").expect("a usable label");
        assert_eq!(invoice, "sbproxy-invoice-sbpi_abc");
        assert_eq!(payment, "sbproxy-pay-sbpa_abc");
        assert_ne!(invoice, payment);
        // The same durable identifier always yields the same label, which is
        // what makes a crashed process find its invoice again.
        assert_eq!(invoice_label("sbpi_abc").expect("a usable label"), invoice);

        assert_eq!(
            expect_error(invoice_label(""), "an empty identifier must be refused"),
            LightningError::Label
        );
        assert_eq!(
            expect_error(
                invoice_label("has spaces"),
                "an out of class identifier must be refused"
            ),
            LightningError::Label
        );
    }

    #[test]
    fn payment_hashes_round_trip_and_reject_short_values() {
        let hash = PaymentHash::from_bytes([7u8; PAYMENT_HASH_LEN]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(PaymentHash::parse_hex(&hex).expect("round trip"), hash);
        assert_eq!(
            expect_error(
                PaymentHash::parse_hex("0a0b"),
                "a short hash must be refused"
            ),
            LightningError::PaymentHash
        );
        assert_eq!(
            expect_error(
                PaymentHash::parse_bytes(&[0u8; 16]),
                "a short byte slice must be refused"
            ),
            LightningError::PaymentHash
        );
    }

    #[test]
    fn a_refund_is_a_typed_refusal_and_never_a_receipt() {
        assert_eq!(
            expect_error(refuse_refund(), "a lightning refund must be refused"),
            LightningError::NoPayerDestination
        );
    }

    #[test]
    fn bolt11_strings_are_bounded_before_they_are_forwarded() {
        assert!(check_bolt11("lnbc1pvjluezpp5abcdef").is_ok());
        assert_eq!(
            expect_error(check_bolt11(""), "an empty invoice must be refused"),
            LightningError::Bolt11
        );
        assert_eq!(
            expect_error(
                check_bolt11("bitcoin:bc1qxyz"),
                "a non bolt11 string must be refused"
            ),
            LightningError::Bolt11
        );
        assert_eq!(
            expect_error(
                check_bolt11("lnbc1pvj?luez"),
                "an out of class invoice must be refused"
            ),
            LightningError::Bolt11
        );
    }
}
