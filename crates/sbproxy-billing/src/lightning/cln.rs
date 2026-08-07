//! Core Lightning settlement over the Unix domain JSON-RPC socket.
//!
//! Pinned to Core Lightning v26.06 or newer, which is the release that
//! documents the `xpay` label. [`ClnSettler::probe_version`] asks `getinfo`
//! and must succeed before the rail is registered, so a node that is too old
//! fails startup instead of failing a paid request.
//!
//! # The four calls this adapter makes
//!
//! - `getinfo`, at startup only, to prove the version floor.
//! - `invoice`, once per challenge, under a label derived from the durable
//!   intent.
//! - `listinvoices` with that exact label, which is the only authoritative
//!   answer about whether a payment arrived.
//! - `xpay` and `xkeysend`, for outgoing payments, which are a separate
//!   explicitly named surface and never part of authorizing a request.
//!
//! Only the documented `status = "paid"` authorizes. `unpaid`, `expired`, a
//! missing record, a duplicated label, a malformed result, and a timeout all
//! deny. An RPC that merely returned proves nothing.
//!
//! # The rune
//!
//! When one is configured it is added to the JSON-RPC request object and
//! nowhere else. It lives in a zeroizing buffer with no accessor, this module
//! has no `Debug` that could print it, and no error variant can carry it.
//!
//! # Byte framing
//!
//! Requests and responses are newline-delimited JSON-RPC 2.0 objects.
//! [`encode_jsonrpc_request`] and [`decode_jsonrpc_response`] are the pinned
//! codec, so the fixture in the contract tests and the socket the runtime
//! opens agree byte for byte.

use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::dispatch::DispatchContext;
use crate::error::BillingError;
use crate::lightning::{
    check_bolt11, invoice_label, msat_amount, payment_label, transport_error, LightningError,
    LightningTransportFailure, PaymentHash, MAX_TOTAL_DEADLINE_MS,
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

/// The JSON-RPC version every request declares.
pub const CLN_JSONRPC_VERSION: &str = "2.0";

/// Smallest supported Core Lightning major version.
pub const MIN_CLN_MAJOR: u32 = 26;

/// Smallest supported Core Lightning minor version at [`MIN_CLN_MAJOR`].
pub const MIN_CLN_MINOR: u32 = 6;

/// Largest Core Lightning response this adapter will read, in bytes.
pub const MAX_CLN_RESPONSE_BYTES: usize = 256 * 1024;

/// Largest request this adapter will write, in bytes.
pub const MAX_CLN_REQUEST_BYTES: usize = 64 * 1024;

/// The challenge field carrying the BOLT 11 invoice.
pub const CHALLENGE_FIELD_BOLT11: &str = "bolt11";

/// The challenge field carrying the payment hash.
pub const CHALLENGE_FIELD_PAYMENT_HASH: &str = "payment_hash";

/// The challenge field carrying the durable label.
pub const CHALLENGE_FIELD_LABEL: &str = "label";

// --- Version ---

/// Parses a Core Lightning version string into its major and minor parts.
///
/// An optional leading `v` is accepted, as `getinfo` reports one. Anything
/// after the minor component is ignored, so `v26.06.1` and `26.06` compare
/// equal. Nothing is coerced: a value that does not start with two numeric
/// components is refused rather than treated as zero.
///
/// # Errors
///
/// Returns [`LightningError::VersionMalformed`].
pub fn parse_cln_version(value: &str) -> Result<(u32, u32), LightningError> {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let mut parts = trimmed.split(['.', '-', '~']);
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
/// [`LightningError::NodeVersion`] below v26.06.
pub fn require_supported_version(value: &str) -> Result<(u32, u32), LightningError> {
    let (major, minor) = parse_cln_version(value)?;
    if (major, minor) < (MIN_CLN_MAJOR, MIN_CLN_MINOR) {
        return Err(LightningError::NodeVersion);
    }
    Ok((major, minor))
}

/// Checks that a configured socket path is one this adapter will open.
///
/// The path must be absolute. A relative path resolves against whatever
/// directory the process happens to be in, which is not a property a payment
/// rail should depend on.
///
/// # Errors
///
/// Returns [`LightningError::Endpoint`].
pub fn check_socket_path(path: &Path) -> Result<(), LightningError> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(LightningError::Endpoint);
    }
    Ok(())
}

// --- Byte codec ---

/// Encodes one newline-delimited JSON-RPC 2.0 request.
///
/// The rune, when one is configured, is added here and only here. The rendered
/// bytes come back in a zeroizing buffer, so a request that carried a rune is
/// wiped as soon as the socket write is done with it.
///
/// # Errors
///
/// Returns [`LightningError::Malformed`] when the object cannot be serialized
/// and [`LightningError::TooLarge`] above [`MAX_CLN_REQUEST_BYTES`].
pub fn encode_jsonrpc_request(
    id: &str,
    method: &str,
    params: &serde_json::Value,
    rune: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, LightningError> {
    let mut request = serde_json::Map::new();
    request.insert(
        "jsonrpc".to_string(),
        serde_json::Value::String(CLN_JSONRPC_VERSION.to_string()),
    );
    request.insert("id".to_string(), serde_json::Value::String(id.to_string()));
    request.insert(
        "method".to_string(),
        serde_json::Value::String(method.to_string()),
    );
    request.insert("params".to_string(), params.clone());
    if let Some(rune) = rune {
        request.insert(
            "rune".to_string(),
            serde_json::Value::String(rune.to_string()),
        );
    }
    let mut bytes = Zeroizing::new(
        serde_json::to_vec(&serde_json::Value::Object(request))
            .map_err(|_| LightningError::Malformed)?,
    );
    if bytes.len() >= MAX_CLN_REQUEST_BYTES {
        return Err(LightningError::TooLarge);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decodes one newline-delimited JSON-RPC 2.0 response into its `result`.
///
/// A JSON-RPC `error` member is a refusal from the node, not a transport
/// failure, and it is reported as [`LightningError::Malformed`] so the caller
/// decides what that means for the operation it was performing.
///
/// # Errors
///
/// Returns [`LightningError::TooLarge`] above [`MAX_CLN_RESPONSE_BYTES`] and
/// [`LightningError::Malformed`] for anything that is not a JSON-RPC object
/// carrying a `result`.
pub fn decode_jsonrpc_response(bytes: &[u8]) -> Result<serde_json::Value, LightningError> {
    if bytes.len() > MAX_CLN_RESPONSE_BYTES {
        return Err(LightningError::TooLarge);
    }
    let trimmed = match bytes.iter().position(|byte| *byte == b'\n') {
        Some(position) => &bytes[..position],
        None => bytes,
    };
    let value: serde_json::Value =
        serde_json::from_slice(trimmed).map_err(|_| LightningError::Malformed)?;
    let object = value.as_object().ok_or(LightningError::Malformed)?;
    if object.contains_key("error") && !object["error"].is_null() {
        return Err(LightningError::Malformed);
    }
    object
        .get("result")
        .cloned()
        .ok_or(LightningError::Malformed)
}

/// Reads a Core Lightning millisatoshi field.
///
/// Core Lightning has published msat fields both as integers and as strings
/// with an `msat` suffix. Both are accepted, exactly; nothing else is, and no
/// value is rounded.
#[must_use]
pub fn parse_msat_field(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => {
            let text = text.strip_suffix("msat").unwrap_or(text);
            text.parse().ok()
        }
        _ => None,
    }
}

// --- Transport ---

/// The bounded Unix socket this adapter talks to a node through.
///
/// The implementation owns the socket. Keeping it a trait is what lets the
/// contract tests drive `getinfo`, `invoice`, and `listinvoices` from a
/// newline-delimited fixture without a socket at all.
#[async_trait::async_trait]
pub trait ClnTransport: Send + Sync {
    /// Writes one newline-delimited request and reads one response.
    ///
    /// Implementations must enforce `timeout` themselves as well: the
    /// adapter's outer deadline is a backstop, not the only bound.
    async fn call(
        &self,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, LightningTransportFailure>;
}

// --- Wire contract ---

/// The documented lifecycle of a Core Lightning invoice.
///
/// An unrecognized status parses to `None` rather than to a nearby variant, so
/// a future node state can never be read as paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClnInvoiceStatus {
    /// The invoice exists and no payment arrived.
    Unpaid,
    /// The invoice was paid. The only status that authorizes.
    Paid,
    /// The invoice passed its expiry and can no longer be paid.
    Expired,
}

impl ClnInvoiceStatus {
    /// Returns the wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unpaid => "unpaid",
            Self::Paid => "paid",
            Self::Expired => "expired",
        }
    }

    /// Parses the wire spelling, or returns `None` for anything unknown.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "unpaid" => Some(Self::Unpaid),
            "paid" => Some(Self::Paid),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// One invoice record, read out of a `listinvoices` result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClnInvoice {
    /// The durable label the record was found under.
    pub label: Option<String>,
    /// The parsed status, when it was one this build recognizes.
    pub status: Option<ClnInvoiceStatus>,
    /// The status string exactly as it arrived, for a redacted failure code.
    pub raw_status: Option<String>,
    /// The payment hash, as lowercase hex.
    pub payment_hash: Option<String>,
    /// The invoiced amount, in millisatoshi.
    pub amount_msat: Option<u64>,
    /// The amount actually received, in millisatoshi.
    pub amount_received_msat: Option<u64>,
    /// The BOLT 11 string the node generated.
    pub bolt11: Option<String>,
    /// When the payment arrived, in seconds since the epoch.
    pub paid_at: Option<i64>,
}

/// Reads one invoice object.
#[must_use]
pub fn read_invoice(value: &serde_json::Value) -> ClnInvoice {
    let text = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let raw_status = text("status");
    ClnInvoice {
        label: text("label"),
        status: raw_status.as_deref().and_then(ClnInvoiceStatus::parse),
        raw_status,
        payment_hash: text("payment_hash"),
        amount_msat: value.get("amount_msat").and_then(parse_msat_field),
        amount_received_msat: value.get("amount_received_msat").and_then(parse_msat_field),
        bolt11: text("bolt11"),
        paid_at: value.get("paid_at").and_then(serde_json::Value::as_i64),
    }
}

/// Selects the one invoice a `listinvoices` result holds for a label.
///
/// Exactly one is required. Zero means the invoice was never created, and more
/// than one is an ambiguity this adapter refuses to resolve rather than
/// guessing which payment a client meant.
///
/// # Errors
///
/// Returns [`LightningError::Malformed`] for a result that is not a list or
/// holds no matching record, and [`LightningError::AmbiguousLabel`] for more
/// than one.
pub fn select_labeled_invoice(
    result: &serde_json::Value,
    label: &str,
) -> Result<ClnInvoice, LightningError> {
    let invoices = result
        .get("invoices")
        .and_then(serde_json::Value::as_array)
        .ok_or(LightningError::Malformed)?;
    let mut matched = invoices
        .iter()
        .map(read_invoice)
        .filter(|invoice| invoice.label.as_deref() == Some(label));
    let first = matched.next().ok_or(LightningError::Malformed)?;
    if matched.next().is_some() {
        return Err(LightningError::AmbiguousLabel);
    }
    Ok(first)
}

/// Checks a paid invoice against the amount and hash the quote signed.
///
/// # Errors
///
/// Returns [`LightningError::BindingMismatch`] when the hash or the received
/// amount does not match, and [`LightningError::PaymentHash`] when the node
/// answered without a usable hash.
pub fn verify_paid_invoice(
    invoice: &ClnInvoice,
    expected_msat: u64,
    expected_hash: Option<&str>,
) -> Result<PaymentHash, LightningError> {
    let hash = invoice
        .payment_hash
        .as_deref()
        .ok_or(LightningError::PaymentHash)?;
    let parsed = PaymentHash::parse_hex(hash)?;
    if let Some(expected) = expected_hash {
        if !expected.eq_ignore_ascii_case(hash) {
            return Err(LightningError::BindingMismatch);
        }
    }
    if invoice.amount_msat != Some(expected_msat) {
        return Err(LightningError::BindingMismatch);
    }
    // A node may report more received than invoiced for an overpayment, which
    // is fine. Less is not a settlement of this obligation.
    match invoice.amount_received_msat {
        Some(received) if received >= expected_msat => Ok(parsed),
        _ => Err(LightningError::BindingMismatch),
    }
}

// --- Settler ---

/// The Core Lightning settlement adapter.
///
/// Deliberately carries no `Debug`: a configured rune is a bearer credential
/// and there is no formatting path that could print it.
pub struct ClnSettler<T: ClnTransport> {
    transport: T,
    rune: Option<Zeroizing<String>>,
    description: String,
    call_timeout: Duration,
    total_deadline: Duration,
}

impl<T: ClnTransport> ClnSettler<T> {
    /// Builds a settler.
    ///
    /// `rune` is optional and, when present, is added to the JSON-RPC request
    /// object and nowhere else.
    ///
    /// # Errors
    ///
    /// Returns [`LightningError::Deadline`] when the total deadline is zero,
    /// above [`MAX_TOTAL_DEADLINE_MS`], or smaller than the per-call budget it
    /// is supposed to bound.
    pub fn new(
        transport: T,
        rune: Option<String>,
        description: &str,
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
            rune: rune.map(Zeroizing::new),
            description: description.to_string(),
            call_timeout: Duration::from_millis(call_timeout_ms),
            total_deadline: Duration::from_millis(total_deadline_ms),
        })
    }

    /// Returns the total request-path deadline.
    #[must_use]
    pub const fn total_deadline(&self) -> Duration {
        self.total_deadline
    }

    /// Asks `getinfo` and proves the node meets the pinned version floor.
    ///
    /// The runtime calls this before registering the rail, so a node below
    /// v26.06 fails startup rather than a paid request.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ProviderUnavailable`] for a node below the
    /// floor or a version this build cannot parse, and
    /// [`BillingError::ProviderMalformed`] for a result with no version.
    pub async fn probe_version(&self) -> Result<(u32, u32), BillingError> {
        let result = self.call("getinfo", &serde_json::json!({})).await?;
        let version = result
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or(BillingError::ProviderMalformed)?;
        Ok(require_supported_version(version)?)
    }

    /// Refuses a refund.
    ///
    /// A Core Lightning invoice records no payer destination, so there is
    /// nobody to pay back. This returns a typed error rather than a receipt
    /// for money that did not move. Paying a destination an operator supplied
    /// is a payout, and it is [`ClnSettler::keysend`].
    ///
    /// # Errors
    ///
    /// Always returns [`LightningError::NoPayerDestination`].
    pub fn refund(&self) -> Result<SettlementReceipt, LightningError> {
        Err(LightningError::NoPayerDestination)
    }

    /// Performs one JSON-RPC call and returns its `result`.
    async fn call(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, BillingError> {
        let request = encode_jsonrpc_request(
            method,
            method,
            params,
            self.rune.as_ref().map(|rune| rune.as_str()),
        )?;
        let response = self
            .transport
            .call(request.as_slice(), self.call_timeout)
            .await
            .map_err(transport_error)?;
        Ok(decode_jsonrpc_response(&response)?)
    }

    /// Reads the one invoice a durable label names.
    async fn list_labeled_invoice(&self, label: &str) -> Result<ClnInvoice, BillingError> {
        let result = self
            .call("listinvoices", &serde_json::json!({ "label": label }))
            .await?;
        Ok(select_labeled_invoice(&result, label)?)
    }

    /// Decodes a BOLT 11 invoice through the node.
    ///
    /// The payment hash an outgoing payment is persisted under comes from
    /// here, never from a local guess, so nothing this crate invents can end
    /// up addressing a payment.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::ProviderMalformed`] when the node answers
    /// without a usable payment hash.
    pub async fn decode_invoice_hash(&self, bolt11: &str) -> Result<PaymentHash, BillingError> {
        check_bolt11(bolt11)?;
        let result = self
            .call("decode", &serde_json::json!({ "string": bolt11 }))
            .await?;
        let hash = result
            .get("payment_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or(BillingError::ProviderMalformed)?;
        Ok(PaymentHash::parse_hex(hash)?)
    }

    /// Pays a BOLT 11 invoice with `xpay`, under a durable label.
    ///
    /// `persisted_hash` must already be durable: the caller decodes the
    /// invoice with [`ClnSettler::decode_invoice_hash`], persists that hash,
    /// and only then calls this. A crash after dispatch is resolved by
    /// querying that hash, never by sending a second payment.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::AlreadyDispatched`] when the gate already
    /// stamped a write, and whatever the node or the transport returns.
    pub async fn pay_invoice(
        &self,
        dispatch: &DispatchContext,
        bolt11: &str,
        persisted_hash: PaymentHash,
        attempt_id: &str,
    ) -> Result<PaymentHash, BillingError> {
        check_bolt11(bolt11)?;
        let label = payment_label(attempt_id)?;
        let params = serde_json::json!({ "invstring": bolt11, "label": label });
        let result = dispatch
            .run_write(|| async { self.call("xpay", &params).await })
            .await?;
        let hash = result
            .get("payment_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or(BillingError::ProviderMalformed)?;
        let answered = PaymentHash::parse_hex(hash)?;
        if answered != persisted_hash {
            return Err(BillingError::NeedsReconciliation);
        }
        Ok(answered)
    }

    /// Sends a spontaneous payment with `xkeysend`, under a durable label.
    ///
    /// `persisted_hash` must already be durable for the same reason
    /// [`ClnSettler::pay_invoice`] requires one. This is a payout, never a
    /// refund of an invoice.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::AlreadyDispatched`] when the gate already
    /// stamped a write, and whatever the node or the transport returns.
    pub async fn keysend(
        &self,
        dispatch: &DispatchContext,
        destination: &str,
        amount_msat: u64,
        persisted_hash: PaymentHash,
        attempt_id: &str,
    ) -> Result<PaymentHash, BillingError> {
        if destination.trim().is_empty() || amount_msat == 0 {
            return Err(LightningError::Endpoint.into());
        }
        let label = payment_label(attempt_id)?;
        let params = serde_json::json!({
            "destination": destination,
            "amount_msat": amount_msat,
            "label": label,
        });
        let result = dispatch
            .run_write(|| async { self.call("xkeysend", &params).await })
            .await?;
        let hash = result
            .get("payment_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or(BillingError::ProviderMalformed)?;
        let answered = PaymentHash::parse_hex(hash)?;
        if answered != persisted_hash {
            return Err(BillingError::NeedsReconciliation);
        }
        Ok(answered)
    }
}

/// Returns the invoice expiry a set of Lightning terms names.
///
/// # Errors
///
/// Returns [`LightningError::TermsMismatch`] for terms that are not a
/// Lightning invoice.
pub fn invoice_expiry_seconds(terms: &RequirementTerms) -> Result<u32, LightningError> {
    match terms {
        RequirementTerms::LightningInvoice {
            invoice_expiry_seconds,
            ..
        } => Ok(*invoice_expiry_seconds),
        _ => Err(LightningError::TermsMismatch),
    }
}

#[async_trait::async_trait]
impl<T: ClnTransport> PaymentMethodAdapter for ClnSettler<T> {
    fn rail(&self) -> SettlementRail {
        SettlementRail::LightningCln
    }

    async fn prepare_challenge(
        &self,
        request: ChallengePreparation,
        dispatch: &DispatchContext,
    ) -> Result<ChallengeMaterial, BillingError> {
        let label = invoice_label(&request.intent_id)?;
        let amount_msat = msat_amount(&request.draft)?;
        let expiry = invoice_expiry_seconds(&request.draft.terms)?;
        let params = serde_json::json!({
            "amount_msat": amount_msat,
            "label": label,
            "description": self.description,
            "expiry": expiry,
        });

        let inner = dispatch.run_write(|| async { self.call("invoice", &params).await });
        let result = match tokio::time::timeout(self.total_deadline, inner).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(deadline_error(dispatch)),
        };

        let hash = result
            .get("payment_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or(BillingError::NeedsReconciliation)?;
        let hash = PaymentHash::parse_hex(hash)?;
        let bolt11 = result
            .get("bolt11")
            .and_then(serde_json::Value::as_str)
            .ok_or(BillingError::NeedsReconciliation)?;
        check_bolt11(bolt11)?;

        Ok(ChallengeMaterial::new(Some(hash.to_hex()))
            .with_field(CHALLENGE_FIELD_BOLT11, bolt11)
            .with_field(CHALLENGE_FIELD_PAYMENT_HASH, &hash.to_hex())
            .with_field(CHALLENGE_FIELD_LABEL, &label))
    }

    async fn authorize_and_settle(
        &self,
        request: AuthoritativePayment,
        dispatch: &DispatchContext,
    ) -> Result<SettlementReceipt, BillingError> {
        let draft = &request.requirement.draft;
        let label = invoice_label(&request.intent_id)?;
        let amount_msat = msat_amount(draft)?;
        let expected_hash = request.requirement.provider_handle.clone();

        // The lookup is a clean read first: whether this invoice has moved
        // funds is a settled fact regardless of how many times it is asked,
        // so a merely-unpaid answer never stamps a dispatch (WOR-2229). Only
        // an answer that ends the attempt, paid, expired, or a record this
        // build cannot parse, runs inside the one write gate call. See the
        // module documentation for why a Lightning settlement is stamped at
        // all once it reaches that point.
        let inner = async {
            let invoice = dispatch
                .run_query(|| self.list_labeled_invoice(&label))
                .await?;
            if matches!(invoice.status, Some(ClnInvoiceStatus::Unpaid)) {
                // Still unpaid is not a refusal and not a settlement, and it
                // costs the intent nothing to ask: no dispatch stamp means no
                // reconciliation, so a request presented before the invoice
                // is paid stays retryable the ordinary way instead of
                // waiting on a worker sweep. The worker keeps asking too,
                // and a payment that lands a moment later is proved by the
                // same query.
                return Err(BillingError::NotSettled);
            }
            dispatch
                .run_write(|| async {
                    match invoice.status {
                        Some(ClnInvoiceStatus::Paid) => {}
                        Some(ClnInvoiceStatus::Expired) => {
                            return Err(BillingError::ProviderRejected)
                        }
                        Some(ClnInvoiceStatus::Unpaid) => return Err(BillingError::NotSettled),
                        None => return Err(BillingError::ProviderMalformed),
                    }
                    let hash =
                        verify_paid_invoice(&invoice, amount_msat, expected_hash.as_deref())?;
                    SettlementReceipt::new(
                        &request.intent_id,
                        SettlementRail::LightningCln,
                        draft.method.as_str(),
                        &hash.to_hex(),
                        request.now_ms,
                    )
                })
                .await
        };

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
        let label = invoice_label(&attempt.intent_id)?;
        let amount_msat = msat_amount(&requirement.draft)?;
        let now_ms = dispatch.now_ms();

        let invoice = match dispatch
            .run_query(|| self.list_labeled_invoice(&label))
            .await
        {
            Ok(invoice) => invoice,
            // No record under the durable label proves the invoice was never
            // created, which is the one observation that lets a challenge
            // preparation be retried at a fresh generation.
            Err(BillingError::ProviderMalformed)
                if attempt.operation == AttemptOperation::PrepareChallenge =>
            {
                return Ok(ProviderQueryResult::NotDispatched)
            }
            Err(error) => return Err(error),
        };

        match invoice.status {
            Some(ClnInvoiceStatus::Paid) => {
                let hash = verify_paid_invoice(
                    &invoice,
                    amount_msat,
                    requirement.provider_handle.as_deref(),
                )?;
                // A paid invoice under a challenge-preparation attempt is a
                // real settlement, but the attempt that would carry it cannot
                // settle. It stays unresolved until the client redeems.
                if !attempt.operation.can_settle() {
                    return Ok(ProviderQueryResult::StillPending);
                }
                Ok(ProviderQueryResult::Settled(SettlementReceipt::new(
                    &attempt.intent_id,
                    SettlementRail::LightningCln,
                    requirement.draft.method.as_str(),
                    &hash.to_hex(),
                    now_ms,
                )?))
            }
            Some(ClnInvoiceStatus::Expired) => Ok(ProviderQueryResult::Failed(SafeFailure::new(
                FailureCategory::Expired,
                invoice.raw_status.as_deref(),
                false,
            ))),
            Some(ClnInvoiceStatus::Unpaid) => Ok(ProviderQueryResult::StillPending),
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

    #[test]
    fn the_version_floor_is_v26_06() {
        assert_eq!(require_supported_version("v26.06").expect("floor"), (26, 6));
        assert_eq!(require_supported_version("26.06").expect("no v"), (26, 6));
        assert_eq!(
            require_supported_version("v26.06.1").expect("patch is ignored"),
            (26, 6)
        );
        assert_eq!(require_supported_version("v27.02").expect("newer"), (27, 2));

        assert_eq!(
            expect_error(
                require_supported_version("v26.05"),
                "an older minor must be refused"
            ),
            LightningError::NodeVersion
        );
        assert_eq!(
            expect_error(
                require_supported_version("v24.11"),
                "an older major must be refused"
            ),
            LightningError::NodeVersion
        );
    }

    #[test]
    fn malformed_versions_are_refused_rather_than_read_as_zero() {
        for bad in ["", "v", "v26", "vtwentysix.06", "26.x", ".06"] {
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
    fn requests_are_newline_delimited_json_rpc_and_carry_the_rune_once() {
        let bytes = encode_jsonrpc_request(
            "getinfo",
            "getinfo",
            &serde_json::json!({}),
            Some("rune-value"),
        )
        .expect("the request encodes");
        assert_eq!(bytes.last().copied(), Some(b'\n'));
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("valid json");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["method"], "getinfo");
        assert_eq!(parsed["rune"], "rune-value");

        let without = encode_jsonrpc_request("getinfo", "getinfo", &serde_json::json!({}), None)
            .expect("the request encodes");
        let parsed: serde_json::Value =
            serde_json::from_slice(&without[..without.len() - 1]).expect("valid json");
        assert!(
            parsed.get("rune").is_none(),
            "no rune slot when unconfigured"
        );
    }

    #[test]
    fn a_json_rpc_error_is_not_a_result() {
        let ok =
            decode_jsonrpc_response(br#"{"jsonrpc":"2.0","id":"a","result":{"version":"v26.06"}}"#)
                .expect("a result decodes");
        assert_eq!(ok["version"], "v26.06");

        assert_eq!(
            expect_error(
                decode_jsonrpc_response(br#"{"jsonrpc":"2.0","id":"a","error":{"code":-32601}}"#),
                "an error object must not decode as a result"
            ),
            LightningError::Malformed
        );
        assert_eq!(
            expect_error(
                decode_jsonrpc_response(b"not json\n"),
                "garbage must not decode"
            ),
            LightningError::Malformed
        );
    }

    #[test]
    fn only_a_paid_status_authorizes() {
        assert_eq!(
            ClnInvoiceStatus::parse("paid"),
            Some(ClnInvoiceStatus::Paid)
        );
        assert_eq!(
            ClnInvoiceStatus::parse("unpaid"),
            Some(ClnInvoiceStatus::Unpaid)
        );
        assert_eq!(
            ClnInvoiceStatus::parse("expired"),
            Some(ClnInvoiceStatus::Expired)
        );
        // A future status is not coerced onto a nearby one.
        assert_eq!(ClnInvoiceStatus::parse("held"), None);
        assert_eq!(ClnInvoiceStatus::parse("PAID"), None);
    }

    #[test]
    fn a_duplicate_label_is_refused_rather_than_resolved() {
        let result = serde_json::json!({
            "invoices": [
                { "label": "sbproxy-invoice-a", "status": "paid" },
                { "label": "sbproxy-invoice-a", "status": "unpaid" }
            ]
        });
        assert_eq!(
            expect_error(
                select_labeled_invoice(&result, "sbproxy-invoice-a"),
                "a duplicate label must be refused"
            ),
            LightningError::AmbiguousLabel
        );
    }

    #[test]
    fn a_missing_label_is_not_a_silent_success() {
        let result = serde_json::json!({ "invoices": [] });
        assert_eq!(
            expect_error(
                select_labeled_invoice(&result, "sbproxy-invoice-a"),
                "a missing invoice must be refused"
            ),
            LightningError::Malformed
        );
        assert_eq!(
            expect_error(
                select_labeled_invoice(&serde_json::json!({}), "sbproxy-invoice-a"),
                "a result with no list must be refused"
            ),
            LightningError::Malformed
        );
    }

    #[test]
    fn millisatoshi_fields_are_read_in_both_published_shapes() {
        assert_eq!(parse_msat_field(&serde_json::json!(1_000)), Some(1_000));
        assert_eq!(
            parse_msat_field(&serde_json::json!("1000msat")),
            Some(1_000)
        );
        assert_eq!(parse_msat_field(&serde_json::json!("1000")), Some(1_000));
        assert_eq!(
            parse_msat_field(&serde_json::json!("about a thousand")),
            None
        );
        assert_eq!(parse_msat_field(&serde_json::json!(null)), None);
    }

    #[test]
    fn a_paid_invoice_must_match_its_amount_and_hash() {
        let hash = "11".repeat(32);
        let invoice = ClnInvoice {
            label: Some("sbproxy-invoice-a".to_string()),
            status: Some(ClnInvoiceStatus::Paid),
            raw_status: Some("paid".to_string()),
            payment_hash: Some(hash.clone()),
            amount_msat: Some(100_000),
            amount_received_msat: Some(100_000),
            bolt11: None,
            paid_at: Some(1),
        };
        assert!(verify_paid_invoice(&invoice, 100_000, Some(&hash)).is_ok());

        assert_eq!(
            expect_error(
                verify_paid_invoice(&invoice, 100_001, Some(&hash)),
                "an amount mismatch must deny"
            ),
            LightningError::BindingMismatch
        );
        assert_eq!(
            expect_error(
                verify_paid_invoice(&invoice, 100_000, Some(&"22".repeat(32))),
                "a hash mismatch must deny"
            ),
            LightningError::BindingMismatch
        );

        let underpaid = ClnInvoice {
            amount_received_msat: Some(99_999),
            ..invoice
        };
        assert_eq!(
            expect_error(
                verify_paid_invoice(&underpaid, 100_000, Some(&hash)),
                "an underpayment must deny"
            ),
            LightningError::BindingMismatch
        );
    }

    #[test]
    fn a_relative_socket_path_is_refused() {
        assert!(check_socket_path(Path::new("/run/lightning/lightning-rpc")).is_ok());
        assert_eq!(
            expect_error(
                check_socket_path(Path::new("lightning-rpc")),
                "a relative socket path must be refused"
            ),
            LightningError::Endpoint
        );
    }
}
