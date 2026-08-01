//! Stripe PaymentIntent settlement, pinned to API version `2026-06-24.dahlia`.
//!
//! This module settles payments. It never reports usage. Stripe Meter Events
//! live in [`crate::stripe_meter`] behind a different trait, a different
//! transport, a different error enum, and a different endpoint, because a
//! meter event is accounting and is never proof that money moved.
//!
//! # Two modes, one rail
//!
//! Both modes settle on [`SettlementRail::Stripe`] and both are chosen by the
//! requirement's own terms rather than by sniffing the credential:
//!
//! - [`RequirementTerms::StripePaymentIntent`] is the direct rail. The
//!   PaymentIntent is created at challenge time with `capture_method=manual`
//!   and `confirm=false`, the client confirms it with Stripe, and the retry
//!   captures it. Because a PaymentIntent identifier cannot appear inside its
//!   own create request, direct mode binds
//!   [`METADATA_REQUIREMENT_DRAFT_DIGEST`].
//! - [`RequirementTerms::PaymentAuthStripeCharge`] is
//!   `draft-stripe-charge-00`. Nothing is created at challenge time. The
//!   credential retry creates and confirms the PaymentIntent from the single
//!   use payment token, so the final requirement already exists and the
//!   metadata binds [`METADATA_REQUIREMENT_DIGEST`].
//!
//! # The dispatch gate
//!
//! Every provider write in this module goes through
//! [`DispatchContext::run_write`], and each entry point calls it at most once.
//! The service does not wrap the adapter: wrapping twice makes the inner
//! `run_write` lose its compare exchange, the provider call is skipped, and
//! the caller sees a terminal ambiguous failure with nothing sent. Reads go
//! through [`DispatchContext::run_query`], which stamps nothing.
//!
//! The retrieve that proves a capture landed runs *inside* the same
//! `run_write` closure as the capture itself. If it ran afterwards, a
//! transport failure on that retrieve would be reported against a gate that
//! had already concluded `Resolved`, and a captured payment would be recorded
//! as a definite failure.
//!
//! # What never leaves
//!
//! The API key is owned by the transport, so it is not a field of any type
//! here and cannot reach a log, an error, a digest, or a durable column. The
//! single use payment token exists only inside a zeroizing form body and the
//! sealed recovery envelope. Client secrets are returned to the immediate 402
//! response in a zeroizing buffer and are never persisted, never hashed, and
//! never logged. No type in this module that can hold either derives `Debug`.
//!
//! # No fabricated success
//!
//! There is no constructor for a PaymentIntent identifier and no path that
//! turns an incomplete answer into a receipt. Every authorization-deciding
//! field is `Option` on the wire, so an answer that omits one is ambiguous
//! rather than being read as a success or as an authoritative refusal.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use zeroize::{Zeroize as _, Zeroizing};

use crate::dispatch::DispatchContext;
use crate::error::BillingError;
use crate::recovery_crypto::{RecoveryBinding, RecoveryCipher, MAX_RECOVERY_AGE_MS};
use crate::registry::{
    AuthoritativePayment, ChallengeMaterial, ChallengePreparation, PaymentMethodAdapter,
    ProviderQueryResult,
};
use crate::store::ProviderAttempt;
use crate::types::{
    AttemptOperation, FailureCategory, PaymentProof, PaymentRequirement, PaymentRequirementDraft,
    RequirementTerms, SafeFailure, SettlementRail, SettlementReceipt,
};

/// The one Stripe API version every request in this crate sends.
///
/// Configuration rejects any other value. A gateway that silently follows a
/// provider's rolling default cannot keep a pinned contract test honest.
pub const STRIPE_API_VERSION: &str = "2026-06-24.dahlia";

/// The header carrying [`STRIPE_API_VERSION`].
pub const STRIPE_VERSION_HEADER: &str = "Stripe-Version";

/// The header carrying the durable provider idempotency key.
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// The PaymentIntents collection path.
pub const PAYMENT_INTENTS_PATH: &str = "/v1/payment_intents";

/// The header the direct rail tells a client to retry with.
pub const DIRECT_RETRY_HEADER: &str = "Crawler-Payment";

/// The challenge field naming the created PaymentIntent.
pub const CHALLENGE_FIELD_PAYMENT_INTENT: &str = "payment_intent_id";

/// The challenge field naming the retry header.
pub const CHALLENGE_FIELD_RETRY_HEADER: &str = "retry_header";

/// Prefix on every server owned metadata key.
///
/// Client supplied metadata may not use it. A collision is refused rather
/// than silently dropped, so a client cannot learn which bindings exist by
/// watching which of its keys survive.
pub const METADATA_PREFIX: &str = "sbproxy_";

/// Metadata key binding the quote this payment prices.
pub const METADATA_QUOTE_ID: &str = "sbproxy_quote_id";

/// Metadata key binding the durable challenge, which is the intent.
pub const METADATA_CHALLENGE_ID: &str = "sbproxy_challenge_id";

/// Metadata key binding the immutable draft digest, used by direct mode.
pub const METADATA_REQUIREMENT_DRAFT_DIGEST: &str = "sbproxy_requirement_draft_digest";

/// Metadata key binding the final requirement digest, used by Payment Auth.
pub const METADATA_REQUIREMENT_DIGEST: &str = "sbproxy_requirement_digest";

/// Metadata key binding the tenant the intent belongs to.
pub const METADATA_TENANT_ID: &str = "sbproxy_tenant_id";

/// Metadata key binding the origin the paid request targets.
pub const METADATA_ORIGIN_ID: &str = "sbproxy_origin_id";

/// Metadata key binding the non-secret account context.
pub const METADATA_ACCOUNT_CONTEXT: &str = "sbproxy_account_context";

/// Required prefix on a PaymentIntent identifier.
pub const PAYMENT_INTENT_ID_PREFIX: &str = "pi_";

/// Required prefix on a single use payment token.
pub const SHARED_PAYMENT_TOKEN_PREFIX: &str = "spt_";

/// Largest Stripe response body this module will read, in bytes.
pub const MAX_STRIPE_RESPONSE_BYTES: usize = 256 * 1024;

/// Hard ceiling on the total request-path deadline, in milliseconds.
pub const MAX_TOTAL_DEADLINE_MS: u64 = 2_000;

/// Longest configured API root this module will normalize.
const MAX_API_ROOT_LEN: usize = 1_024;

/// Longest PaymentIntent identifier accepted into a URL path.
const MAX_PAYMENT_INTENT_ID_LEN: usize = 255;

/// Uppercase hex digits, for percent encoding.
///
/// RFC 3986 section 2.1 says a producer should emit uppercase hex in a
/// percent-encoding, and normalizers uppercase it anyway, so emitting
/// lowercase here would mean the bytes we sign and the bytes a normalizer
/// forwards could differ.
const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

// --- Errors ---

/// Everything this module refuses locally, or reads as a refusal.
///
/// Every message is a fixed string. No variant can carry an API key, a client
/// secret, a single use payment token, a payer identifier, or a Stripe
/// response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StripeError {
    /// The configured API root is not a usable HTTPS root.
    #[error("stripe API root is not a usable https root")]
    ApiRoot,

    /// The configured API version is not the pinned one.
    #[error("stripe API version is not the pinned version")]
    ApiVersion,

    /// The requirement terms are not the ones this entry point settles.
    #[error("stripe requirement terms do not match this settlement mode")]
    TermsMismatch,

    /// The direct rail was configured with something other than manual capture.
    #[error("the direct stripe rail supports only manual capture")]
    CaptureMethod,

    /// A client supplied metadata key collided with a server owned binding.
    #[error("client metadata may not use the server owned key namespace")]
    MetadataConflict,

    /// A PaymentIntent identifier was absent or outside its character class.
    #[error("stripe payment intent identifier is not usable")]
    PaymentIntentId,

    /// A credential did not carry a usable single use payment token.
    #[error("stripe payment credential is malformed")]
    Credential,

    /// A response did not parse as the pinned contract.
    #[error("stripe response does not match the pinned contract")]
    Malformed,

    /// A response exceeded [`MAX_STRIPE_RESPONSE_BYTES`].
    #[error("stripe response exceeds its size bound")]
    TooLarge,

    /// A bound field on the retrieved PaymentIntent did not match.
    #[error("stripe payment intent does not match the signed requirement")]
    BindingMismatch,

    /// The configured deadlines do not bound the calls inside them.
    #[error("stripe deadlines are not usable")]
    Deadline,
}

impl From<StripeError> for BillingError {
    fn from(error: StripeError) -> Self {
        match error {
            StripeError::ApiRoot => Self::InvalidRequirement("stripe_api_root"),
            StripeError::ApiVersion => Self::InvalidRequirement("stripe_api_version"),
            StripeError::Deadline => Self::InvalidRequirement("stripe_deadline"),
            StripeError::TermsMismatch | StripeError::CaptureMethod => Self::UnsupportedOperation,
            StripeError::MetadataConflict | StripeError::BindingMismatch => {
                Self::RequirementMismatch
            }
            StripeError::Credential => Self::InvalidProof,
            StripeError::PaymentIntentId | StripeError::Malformed | StripeError::TooLarge => {
                Self::ProviderMalformed
            }
        }
    }
}

// --- Endpoints ---

/// Normalizes a configured API root into the exact prefix every path is
/// appended to.
///
/// Only trailing slashes are removed. Userinfo, a query, a fragment, an empty
/// segment, and a dot segment are all refused: each would either leak a
/// credential into a signed requirement or build a path Stripe does not serve,
/// and a paid request is the worst place to discover either.
///
/// # Errors
///
/// Returns [`StripeError::ApiRoot`].
pub fn normalize_api_root(root: &str, allow_loopback_http: bool) -> Result<String, StripeError> {
    let trimmed = root.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_API_ROOT_LEN
        || trimmed.chars().any(char::is_control)
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(StripeError::ApiRoot);
    }

    let rest = match trimmed.strip_prefix("https://") {
        Some(rest) => rest,
        None => {
            let rest = trimmed
                .strip_prefix("http://")
                .ok_or(StripeError::ApiRoot)?;
            let authority_end = rest.find('/').unwrap_or(rest.len());
            if !allow_loopback_http || !is_loopback_authority(&rest[..authority_end]) {
                return Err(StripeError::ApiRoot);
            }
            rest
        }
    };

    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return Err(StripeError::ApiRoot);
    }

    let path = rest[authority_end..].trim_end_matches('/');
    if path.contains("//")
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(StripeError::ApiRoot);
    }

    let scheme = if trimmed.starts_with("https://") {
        "https://"
    } else {
        "http://"
    };
    Ok(format!("{scheme}{authority}{path}"))
}

/// Whether an authority names the loopback interface.
fn is_loopback_authority(authority: &str) -> bool {
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(authority),
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// Checks that a PaymentIntent identifier is safe to place in a URL path.
///
/// # Errors
///
/// Returns [`StripeError::PaymentIntentId`] for a missing prefix, an
/// oversized value, or any byte outside the identifier character class. That
/// last check is what stops a provider response from steering a later request
/// at a different path.
pub fn validate_payment_intent_id(id: &str) -> Result<(), StripeError> {
    if !id.starts_with(PAYMENT_INTENT_ID_PREFIX)
        || id.len() <= PAYMENT_INTENT_ID_PREFIX.len()
        || id.len() > MAX_PAYMENT_INTENT_ID_LEN
    {
        return Err(StripeError::PaymentIntentId);
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(StripeError::PaymentIntentId);
    }
    Ok(())
}

/// The PaymentIntents endpoints one API root serves.
///
/// This type builds settlement paths and nothing else. It has no way to
/// address `/v1/billing/meter_events`, which is how the type system keeps a
/// settlement call out of the usage surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeEndpoints {
    root: String,
}

impl StripeEndpoints {
    /// Normalizes a configured HTTPS API root.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::ApiRoot`].
    pub fn from_api_root(root: &str) -> Result<Self, StripeError> {
        Ok(Self {
            root: normalize_api_root(root, false)?,
        })
    }

    /// Builds endpoints for a cleartext loopback fixture.
    ///
    /// Test only. Nothing reachable from a configuration document calls this.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::ApiRoot`] under the same rules, except that an
    /// `http://` loopback authority is accepted.
    pub fn loopback_http_for_test(root: &str) -> Result<Self, StripeError> {
        Ok(Self {
            root: normalize_api_root(root, true)?,
        })
    }

    /// Returns the normalized API root.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Returns the PaymentIntents collection URL.
    #[must_use]
    pub fn payment_intents_url(&self) -> String {
        format!("{}{PAYMENT_INTENTS_PATH}", self.root)
    }

    /// Returns the retrieve URL for one PaymentIntent.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::PaymentIntentId`] for an unusable identifier.
    pub fn payment_intent_url(&self, id: &str) -> Result<String, StripeError> {
        validate_payment_intent_id(id)?;
        Ok(format!("{}{PAYMENT_INTENTS_PATH}/{id}", self.root))
    }

    /// Returns the capture URL for one PaymentIntent.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::PaymentIntentId`] for an unusable identifier.
    pub fn capture_url(&self, id: &str) -> Result<String, StripeError> {
        validate_payment_intent_id(id)?;
        Ok(format!("{}{PAYMENT_INTENTS_PATH}/{id}/capture", self.root))
    }
}

// --- Form bodies ---

/// One `application/x-www-form-urlencoded` request body.
///
/// Deliberately carries no `Debug`: a Payment Auth create body holds the
/// single use payment token. Every value is wiped when the body drops, and
/// the rendered bytes live in a zeroizing buffer, so a token exists in
/// process memory only for as long as the request that sends it.
///
/// Keys are unique by construction, so a client supplied value cannot
/// overwrite a server owned binding, and the rendered bytes are sorted by key
/// so the same logical request always produces identical bytes. Byte
/// stability is what makes the sealed recovery envelope a faithful replay
/// rather than a second, differently shaped charge.
#[derive(Default)]
pub struct FormBody {
    pairs: Vec<(String, String)>,
}

impl Drop for FormBody {
    fn drop(&mut self) {
        for (_, value) in &mut self.pairs {
            value.zeroize();
        }
    }
}

impl FormBody {
    /// Builds an empty body.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets one field, refusing a duplicate key.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::MetadataConflict`] when the key is already set.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), StripeError> {
        if self.pairs.iter().any(|(existing, _)| existing == key) {
            return Err(StripeError::MetadataConflict);
        }
        self.pairs.push((key.to_string(), value.to_string()));
        Ok(())
    }

    /// Sets one integer field.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::MetadataConflict`] when the key is already set.
    pub fn set_u64(&mut self, key: &str, value: u64) -> Result<(), StripeError> {
        self.set(key, &value.to_string())
    }

    /// Sets one boolean field, rendered as Stripe spells it.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::MetadataConflict`] when the key is already set.
    pub fn set_bool(&mut self, key: &str, value: bool) -> Result<(), StripeError> {
        self.set(key, if value { "true" } else { "false" })
    }

    /// Reports whether a key is present.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.pairs.iter().any(|(existing, _)| existing == key)
    }

    /// Returns the value set for a key, when one is set.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value.as_str())
    }

    /// Renders the body into a zeroizing buffer.
    ///
    /// Pairs are sorted by key first, so two code paths that set the same
    /// fields in a different order still produce identical bytes. Only the
    /// index order is sorted, never a copy of the values, so no unwiped clone
    /// of a token is created on the way out.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut order: Vec<usize> = (0..self.pairs.len()).collect();
        order.sort_by(|left, right| self.pairs[*left].0.cmp(&self.pairs[*right].0));
        let mut rendered = Zeroizing::new(String::new());
        for (position, index) in order.iter().enumerate() {
            if position > 0 {
                rendered.push('&');
            }
            percent_encode(&self.pairs[*index].0, &mut rendered);
            rendered.push('=');
            percent_encode(&self.pairs[*index].1, &mut rendered);
        }
        Zeroizing::new(rendered.as_bytes().to_vec())
    }
}

/// Percent encodes one component into a form body.
///
/// Everything outside the RFC 3986 unreserved set is escaped, including the
/// space and the square brackets Stripe uses for nested fields. That is
/// always a valid encoding and removes any question of which characters a
/// given client library would have left alone.
fn percent_encode(input: &str, out: &mut String) {
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                out.push('%');
                out.push(HEX_DIGITS[usize::from(byte >> 4)]);
                out.push(HEX_DIGITS[usize::from(byte & 0x0f)]);
            }
        }
    }
}

// --- Transport ---

/// The HTTP methods this module uses. There are only two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeHttpMethod {
    /// Retrieve a PaymentIntent.
    Get,
    /// Create, confirm, or capture a PaymentIntent.
    Post,
}

impl StripeHttpMethod {
    /// Returns the wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// One outbound Stripe call, minus every credential.
///
/// Deliberately carries no `Debug`: `form_body` can hold a single use payment
/// token. There is no field for `Stripe-Account`, because every request in
/// this release charges on the platform account and a struct that cannot
/// express a value cannot accidentally send one.
pub struct StripeRequest<'a> {
    /// The HTTP method.
    pub method: StripeHttpMethod,
    /// The absolute URL, already built from a normalized root.
    pub url: &'a str,
    /// The pinned API version to send as [`STRIPE_VERSION_HEADER`].
    pub api_version: &'a str,
    /// The durable provider idempotency key, on every POST.
    pub idempotency_key: Option<&'a str>,
    /// The rendered form body, on every POST.
    pub form_body: Option<&'a [u8]>,
}

/// Why a Stripe call did not produce a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeTransportFailure {
    /// The call did not complete inside its budget.
    Timeout,
    /// The connection could not be established or was lost.
    Connection,
    /// The response exceeded [`MAX_STRIPE_RESPONSE_BYTES`].
    TooLarge,
}

/// One Stripe HTTP response.
///
/// Deliberately carries a redacted `Debug`: a PaymentIntent body holds a
/// client secret, so the derived form would print one into any log line that
/// formatted a transport error.
#[derive(Clone, PartialEq, Eq)]
pub struct StripeHttpResponse {
    /// The response status code.
    pub status: u16,
    /// The response body, already bounded by the transport.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for StripeHttpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StripeHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The bounded outbound client this module calls Stripe through.
///
/// The implementation owns the API key and attaches it as the `Authorization`
/// header. No type in this module holds one, so there is no path from a
/// settlement error, a log line, or a durable column back to a secret key.
///
/// The runtime binds this to the shared bounded outbound HTTP client so
/// timeouts, the connection pool, redirect policy, and TLS verification are
/// the workspace's rather than this module's. Keeping it a trait is also what
/// lets the contract tests drive create, capture, and retrieve
/// deterministically without a socket.
#[async_trait::async_trait]
pub trait StripeTransport: Send + Sync {
    /// Sends one request and returns the bounded response.
    ///
    /// Implementations must enforce `timeout` themselves as well: the
    /// settler's outer deadline is a backstop, not the only bound.
    async fn send(
        &self,
        request: StripeRequest<'_>,
        timeout: Duration,
    ) -> Result<StripeHttpResponse, StripeTransportFailure>;
}

// --- Wire contract ---

/// The PaymentIntent lifecycle, exactly as Stripe publishes it.
///
/// An unrecognized status parses to `None` rather than to a nearby variant, so
/// a future Stripe state can never be read as a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentIntentStatus {
    /// No payment method is attached yet.
    RequiresPaymentMethod,
    /// A payment method is attached and confirmation has not happened.
    RequiresConfirmation,
    /// The payer must complete an additional step.
    RequiresAction,
    /// Stripe is still working on it.
    Processing,
    /// Funds are authorized and awaiting capture.
    RequiresCapture,
    /// The intent was cancelled and will never settle.
    Canceled,
    /// Funds moved.
    Succeeded,
}

impl PaymentIntentStatus {
    /// Returns the wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequiresPaymentMethod => "requires_payment_method",
            Self::RequiresConfirmation => "requires_confirmation",
            Self::RequiresAction => "requires_action",
            Self::Processing => "processing",
            Self::RequiresCapture => "requires_capture",
            Self::Canceled => "canceled",
            Self::Succeeded => "succeeded",
        }
    }

    /// Parses the wire spelling, or returns `None` for anything unknown.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "requires_payment_method" => Some(Self::RequiresPaymentMethod),
            "requires_confirmation" => Some(Self::RequiresConfirmation),
            "requires_action" => Some(Self::RequiresAction),
            "processing" => Some(Self::Processing),
            "requires_capture" => Some(Self::RequiresCapture),
            "canceled" => Some(Self::Canceled),
            "succeeded" => Some(Self::Succeeded),
            _ => None,
        }
    }

    /// Reports whether this status means funds moved.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

impl std::fmt::Display for PaymentIntentStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A retrieved PaymentIntent.
///
/// Deliberately carries no `Debug`: `client_secret` is a secret. Every field
/// that decides authorization is optional, so an incomplete answer is
/// ambiguous rather than being read as a success or as a refusal.
pub struct PaymentIntent {
    /// The provider identifier, when the answer carried one.
    pub id: Option<String>,
    /// The parsed status, when it was one this build recognizes.
    pub status: Option<PaymentIntentStatus>,
    /// The status string exactly as it arrived, for a redacted failure code.
    pub raw_status: Option<String>,
    /// The intended amount, in the currency's minor units.
    pub amount: Option<u64>,
    /// The captured amount, in the currency's minor units.
    pub amount_received: Option<u64>,
    /// The amount still capturable, in the currency's minor units.
    pub amount_capturable: Option<u64>,
    /// The lowercase currency code.
    pub currency: Option<String>,
    /// The capture mode Stripe reports.
    pub capture_method: Option<String>,
    /// Whether the object lives on the live key.
    pub livemode: Option<bool>,
    /// The metadata Stripe echoes back.
    pub metadata: BTreeMap<String, String>,
    /// The one shot client secret, held in a zeroizing buffer.
    pub client_secret: Option<Zeroizing<String>>,
}

/// The wire form of a PaymentIntent.
///
/// Unknown members are ignored on purpose. Stripe adds fields without a
/// version bump, and refusing them would turn a routine provider change into
/// an outage on the paid path.
#[derive(Deserialize)]
struct PaymentIntentWire {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    amount: Option<u64>,
    #[serde(default)]
    amount_received: Option<u64>,
    #[serde(default)]
    amount_capturable: Option<u64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    capture_method: Option<String>,
    #[serde(default)]
    livemode: Option<bool>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Parses a bounded PaymentIntent body.
///
/// # Errors
///
/// Returns [`StripeError::TooLarge`] above [`MAX_STRIPE_RESPONSE_BYTES`] and
/// [`StripeError::Malformed`] when the body is not the pinned shape.
pub fn parse_payment_intent(body: &[u8]) -> Result<PaymentIntent, StripeError> {
    if body.len() > MAX_STRIPE_RESPONSE_BYTES {
        return Err(StripeError::TooLarge);
    }
    let wire: PaymentIntentWire =
        serde_json::from_slice(body).map_err(|_| StripeError::Malformed)?;
    Ok(PaymentIntent {
        id: wire.id,
        status: wire.status.as_deref().and_then(PaymentIntentStatus::parse),
        raw_status: wire.status,
        amount: wire.amount,
        amount_received: wire.amount_received,
        amount_capturable: wire.amount_capturable,
        currency: wire.currency,
        capture_method: wire.capture_method,
        livemode: wire.livemode,
        metadata: wire.metadata,
        client_secret: wire.client_secret.map(Zeroizing::new),
    })
}

/// The machine readable half of a Stripe error body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StripeApiError {
    /// Stripe's error type, for example `card_error`.
    pub error_type: Option<String>,
    /// Stripe's stable error code, when it published one.
    pub code: Option<String>,
    /// Stripe's decline code, when a card issuer supplied one.
    pub decline_code: Option<String>,
}

/// The wire form of a Stripe error body.
#[derive(Deserialize)]
struct StripeApiErrorEnvelope {
    #[serde(default)]
    error: Option<StripeApiErrorWire>,
}

/// The `error` member of a Stripe error body.
#[derive(Deserialize)]
struct StripeApiErrorWire {
    #[serde(default, rename = "type")]
    error_type: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    decline_code: Option<String>,
}

/// Parses the machine readable half of a Stripe error body.
///
/// The human readable `message` is deliberately dropped: it is the one field
/// Stripe fills with free text, and free text is how a provider string ends
/// up in a durable column.
#[must_use]
pub fn parse_api_error(body: &[u8]) -> StripeApiError {
    if body.len() > MAX_STRIPE_RESPONSE_BYTES {
        return StripeApiError::default();
    }
    let parsed: Result<StripeApiErrorEnvelope, _> = serde_json::from_slice(body);
    match parsed.ok().and_then(|envelope| envelope.error) {
        Some(error) => StripeApiError {
            error_type: error.error_type,
            code: error.code,
            decline_code: error.decline_code,
        },
        None => StripeApiError::default(),
    }
}

/// The Stripe error type that means a key was reused with different bytes.
pub const IDEMPOTENCY_ERROR_TYPE: &str = "idempotency_error";

/// Maps a non-2xx Stripe response onto a durable failure.
///
/// The distinction that matters is authoritative refusal against ambiguity. A
/// 4xx other than 409 and 429 means Stripe processed the request and refused
/// it, so no funds moved. A 429, a 409, a 5xx, and an idempotency error all
/// leave the write outstanding: the request may well have been applied, and
/// only a documented status query or an idempotent replay can say.
#[must_use]
pub fn classify_failure(status: u16, body: &[u8]) -> BillingError {
    let parsed = parse_api_error(body);
    if parsed.error_type.as_deref() == Some(IDEMPOTENCY_ERROR_TYPE) {
        return BillingError::NeedsReconciliation;
    }
    match status {
        409 => BillingError::NeedsReconciliation,
        429 => BillingError::ProviderUnavailable,
        400..=499 => BillingError::ProviderRejected,
        500..=599 => BillingError::ProviderUnavailable,
        _ => BillingError::ProviderMalformed,
    }
}

/// Maps a transport failure that happened before any dispatch stamp.
#[must_use]
pub const fn pre_dispatch_error(failure: StripeTransportFailure) -> BillingError {
    match failure {
        StripeTransportFailure::Timeout => BillingError::ProviderTimeout,
        StripeTransportFailure::Connection => BillingError::ProviderUnavailable,
        StripeTransportFailure::TooLarge => BillingError::ProviderMalformed,
    }
}

// --- Money ---

/// Returns the exact minor-unit amount a requirement prices.
///
/// Stripe amounts are already integer minor units, so nothing here re-scales
/// one. What this does is recompute the minor-unit count from the exact micro
/// amount at the requirement's own declared precision and check it against the
/// advertised string, so a settlement can never be sent at an amount the quote
/// did not sign. There is no floating point and no rounding: a conversion that
/// would drop a remainder is an error.
///
/// # Errors
///
/// Returns [`BillingError::AmountNotRepresentable`] when the advertised string
/// and the exact conversion disagree, and whatever
/// [`crate::money::Money::to_base_units`] returns otherwise.
pub fn stripe_minor_units(draft: &PaymentRequirementDraft) -> Result<u64, BillingError> {
    let exact = draft.amount.to_base_units(draft.settlement_decimals)?;
    if draft.settlement_amount != exact.to_string() {
        return Err(BillingError::AmountNotRepresentable);
    }
    Ok(exact)
}

// --- Metadata ---

/// Builds the server owned metadata a PaymentIntent binds.
///
/// `digest_key` is [`METADATA_REQUIREMENT_DRAFT_DIGEST`] for direct mode,
/// whose identifier cannot appear inside its own create request, and
/// [`METADATA_REQUIREMENT_DIGEST`] for Payment Auth, whose PaymentIntent is
/// created after the challenge is final.
#[must_use]
pub fn server_metadata(
    intent_id: &str,
    draft: &PaymentRequirementDraft,
    digest_key: &str,
    digest: &[u8; 32],
    account_context: &str,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(METADATA_QUOTE_ID.to_string(), draft.quote_id.clone());
    metadata.insert(METADATA_CHALLENGE_ID.to_string(), intent_id.to_string());
    metadata.insert(digest_key.to_string(), hex::encode(digest));
    metadata.insert(METADATA_TENANT_ID.to_string(), draft.tenant_id.clone());
    metadata.insert(METADATA_ORIGIN_ID.to_string(), draft.origin_id.clone());
    metadata.insert(
        METADATA_ACCOUNT_CONTEXT.to_string(),
        account_context.to_string(),
    );
    metadata
}

/// Writes metadata onto a form body under Stripe's bracket syntax.
///
/// Server owned keys are written first. A client supplied key that lands in
/// the [`METADATA_PREFIX`] namespace, or that repeats a key already written,
/// is refused rather than dropped.
///
/// # Errors
///
/// Returns [`StripeError::MetadataConflict`].
pub fn write_metadata(
    body: &mut FormBody,
    server: &BTreeMap<String, String>,
    client: &BTreeMap<String, String>,
) -> Result<(), StripeError> {
    for (key, value) in server {
        body.set(&format!("metadata[{key}]"), value)?;
    }
    for (key, value) in client {
        if key.starts_with(METADATA_PREFIX) {
            return Err(StripeError::MetadataConflict);
        }
        body.set(&format!("metadata[{key}]"), value)?;
    }
    Ok(())
}

/// Checks that a retrieved PaymentIntent still carries every server binding.
///
/// # Errors
///
/// Returns [`StripeError::BindingMismatch`] for a missing or altered value.
pub fn verify_metadata(
    intent: &PaymentIntent,
    expected: &BTreeMap<String, String>,
) -> Result<(), StripeError> {
    for (key, value) in expected {
        if intent.metadata.get(key).map(String::as_str) != Some(value.as_str()) {
            return Err(StripeError::BindingMismatch);
        }
    }
    Ok(())
}

// --- Request bodies ---

/// Builds the direct rail's create body and the metadata it binds.
///
/// The rail is manual capture only, so the create is explicitly
/// `capture_method=manual`, `confirmation_method=automatic`, and
/// `confirm=false`. It names its accepted methods with
/// `payment_method_types[]` and deliberately does not also send
/// `automatic_payment_methods`, which Stripe treats as an alternative
/// selector rather than an additional filter.
///
/// # Errors
///
/// Returns [`StripeError::CaptureMethod`] for anything but manual capture,
/// [`BillingError::AmountNotRepresentable`] for an amount that is not exact,
/// and [`StripeError::MetadataConflict`] for a duplicate key.
pub fn build_direct_create_form(
    intent_id: &str,
    draft: &PaymentRequirementDraft,
    draft_digest: &[u8; 32],
    payment_method_types: &[String],
    capture_method: &str,
    account_context: &str,
) -> Result<(FormBody, BTreeMap<String, String>), BillingError> {
    if capture_method != "manual" {
        return Err(StripeError::CaptureMethod.into());
    }
    let metadata = server_metadata(
        intent_id,
        draft,
        METADATA_REQUIREMENT_DRAFT_DIGEST,
        draft_digest,
        account_context,
    );
    let mut body = FormBody::new();
    body.set_u64("amount", stripe_minor_units(draft)?)?;
    body.set("currency", &draft.amount.provider_currency()?)?;
    body.set("capture_method", "manual")?;
    body.set("confirmation_method", "automatic")?;
    body.set_bool("confirm", false)?;
    for (index, method) in payment_method_types.iter().enumerate() {
        body.set(&format!("payment_method_types[{index}]"), method)?;
    }
    write_metadata(&mut body, &metadata, &BTreeMap::new())?;
    Ok((body, metadata))
}

/// Builds the Payment Auth charge's create body and the metadata it binds.
///
/// `draft-stripe-charge-00` creates and confirms in one call from the single
/// use payment token, with redirects refused, so the charge either succeeds
/// synchronously or does not authorize anything.
///
/// # Errors
///
/// Returns [`BillingError::AmountNotRepresentable`] for an amount that is not
/// exact and [`StripeError::MetadataConflict`] for a duplicate key.
pub fn build_payment_auth_create_form(
    intent_id: &str,
    draft: &PaymentRequirementDraft,
    requirement_digest: &[u8; 32],
    account_context: &str,
    shared_payment_token: &str,
) -> Result<(FormBody, BTreeMap<String, String>), BillingError> {
    let metadata = server_metadata(
        intent_id,
        draft,
        METADATA_REQUIREMENT_DIGEST,
        requirement_digest,
        account_context,
    );
    let mut body = FormBody::new();
    body.set_u64("amount", stripe_minor_units(draft)?)?;
    body.set("currency", &draft.amount.provider_currency()?)?;
    body.set("shared_payment_granted_token", shared_payment_token)?;
    body.set_bool("confirm", true)?;
    body.set_bool("automatic_payment_methods[enabled]", true)?;
    body.set("automatic_payment_methods[allow_redirects]", "never")?;
    write_metadata(&mut body, &metadata, &BTreeMap::new())?;
    Ok((body, metadata))
}

/// Builds the capture body for an exact minor-unit amount.
///
/// # Errors
///
/// Returns [`StripeError::MetadataConflict`] for a duplicate key, which this
/// fixed single-field body cannot produce.
pub fn build_capture_form(minor_units: u64) -> Result<FormBody, StripeError> {
    let mut body = FormBody::new();
    body.set_u64("amount_to_capture", minor_units)?;
    Ok(body)
}

// --- Settlement checks ---

/// Everything a retrieved PaymentIntent is checked against.
pub struct SettlementBinding<'a> {
    /// The durable intent the receipt will name.
    pub intent_id: &'a str,
    /// The exact minor-unit amount the quote signed.
    pub minor_units: u64,
    /// The lowercase currency the quote signed.
    pub currency: &'a str,
    /// Every server owned metadata binding.
    pub metadata: &'a BTreeMap<String, String>,
    /// The protocol method name the receipt records.
    pub method: &'a str,
    /// Wall clock, in milliseconds since the epoch.
    pub now_ms: i64,
}

/// Turns a retrieved PaymentIntent into a receipt, or explains why not.
///
/// Only `succeeded` with an exact amount, an exact `amount_received`, the
/// exact currency, and every metadata binding intact produces a receipt. The
/// identifier is Stripe's own, never one this crate invents.
///
/// # Errors
///
/// Returns [`BillingError::ProviderRejected`] for a cancelled intent,
/// [`BillingError::NotSettled`] for any state that has not moved funds,
/// [`BillingError::ProviderMalformed`] for a status this build does not
/// recognize or an answer missing an identifier, and
/// [`BillingError::RequirementMismatch`] when a bound field changed.
pub fn require_settled(
    intent: &PaymentIntent,
    binding: &SettlementBinding<'_>,
) -> Result<SettlementReceipt, BillingError> {
    match intent.status {
        Some(PaymentIntentStatus::Succeeded) => {}
        Some(PaymentIntentStatus::Canceled) => return Err(BillingError::ProviderRejected),
        Some(_) => return Err(BillingError::NotSettled),
        None => return Err(BillingError::ProviderMalformed),
    }

    let id = intent
        .id
        .as_deref()
        .ok_or(BillingError::ProviderMalformed)?;
    validate_payment_intent_id(id).map_err(BillingError::from)?;

    if intent.amount != Some(binding.minor_units) {
        return Err(BillingError::RequirementMismatch);
    }
    if intent.amount_received != Some(binding.minor_units) {
        return Err(BillingError::RequirementMismatch);
    }
    if intent.currency.as_deref() != Some(binding.currency) {
        return Err(BillingError::RequirementMismatch);
    }
    verify_metadata(intent, binding.metadata).map_err(BillingError::from)?;

    SettlementReceipt::new(
        binding.intent_id,
        SettlementRail::Stripe,
        binding.method,
        id,
        binding.now_ms,
    )
}

// --- Settler ---

/// The tunable bounds one settler runs under.
///
/// Kept as a struct so the constructor stays readable and so a new bound does
/// not silently change the meaning of a positional argument at a call site
/// that moves money.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripeSettlerConfig {
    /// Budget for one Stripe call, in milliseconds.
    pub call_timeout_ms: u64,
    /// Total request-path deadline, in milliseconds.
    pub total_deadline_ms: u64,
    /// How long a sealed recovery envelope stays replayable, in milliseconds.
    pub recovery_ttl_ms: i64,
}

impl Default for StripeSettlerConfig {
    fn default() -> Self {
        Self {
            call_timeout_ms: 800,
            total_deadline_ms: MAX_TOTAL_DEADLINE_MS,
            recovery_ttl_ms: MAX_RECOVERY_AGE_MS,
        }
    }
}

/// The Stripe PaymentIntent settlement adapter.
///
/// One settler serves both Stripe modes. Which one runs is decided by the
/// signed requirement's own terms, never by inspecting the credential, so a
/// client cannot talk the proxy onto the cheaper path.
pub struct StripePaymentIntentSettler<T: StripeTransport> {
    endpoints: StripeEndpoints,
    transport: T,
    cipher: RecoveryCipher,
    api_version: String,
    call_timeout: Duration,
    total_deadline: Duration,
    recovery_ttl_ms: i64,
}

impl<T: StripeTransport> StripePaymentIntentSettler<T> {
    /// Builds a settler.
    ///
    /// # Errors
    ///
    /// Returns [`StripeError::ApiVersion`] for anything but
    /// [`STRIPE_API_VERSION`], and [`StripeError::Deadline`] when the total
    /// deadline is zero, above [`MAX_TOTAL_DEADLINE_MS`], or smaller than the
    /// per-call budget it is supposed to bound.
    pub fn new(
        endpoints: StripeEndpoints,
        transport: T,
        cipher: RecoveryCipher,
        api_version: &str,
        config: StripeSettlerConfig,
    ) -> Result<Self, StripeError> {
        if api_version != STRIPE_API_VERSION {
            return Err(StripeError::ApiVersion);
        }
        if config.total_deadline_ms == 0
            || config.total_deadline_ms > MAX_TOTAL_DEADLINE_MS
            || config.call_timeout_ms == 0
            || config.call_timeout_ms > config.total_deadline_ms
            || config.recovery_ttl_ms <= 0
        {
            return Err(StripeError::Deadline);
        }
        Ok(Self {
            endpoints,
            transport,
            cipher,
            api_version: api_version.to_string(),
            call_timeout: Duration::from_millis(config.call_timeout_ms),
            total_deadline: Duration::from_millis(config.total_deadline_ms),
            recovery_ttl_ms: config.recovery_ttl_ms,
        })
    }

    /// Returns the endpoints this settler is bound to.
    #[must_use]
    pub fn endpoints(&self) -> &StripeEndpoints {
        &self.endpoints
    }

    /// Returns the pinned API version every request carries.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns the total request-path deadline.
    #[must_use]
    pub const fn total_deadline(&self) -> Duration {
        self.total_deadline
    }

    /// Retrieves one PaymentIntent. Always a read.
    async fn retrieve(&self, id: &str) -> Result<PaymentIntent, BillingError> {
        let url = self.endpoints.payment_intent_url(id)?;
        let response = self
            .transport
            .send(
                StripeRequest {
                    method: StripeHttpMethod::Get,
                    url: &url,
                    api_version: &self.api_version,
                    idempotency_key: None,
                    form_body: None,
                },
                self.call_timeout,
            )
            .await
            .map_err(pre_dispatch_error)?;
        if !(200..300).contains(&response.status) {
            return Err(classify_failure(response.status, &response.body));
        }
        parse_payment_intent(&response.body).map_err(BillingError::from)
    }

    /// Posts one form body under the durable idempotency key.
    async fn post(
        &self,
        url: &str,
        idempotency_key: &str,
        body: &[u8],
    ) -> Result<PaymentIntent, BillingError> {
        let response = self
            .transport
            .send(
                StripeRequest {
                    method: StripeHttpMethod::Post,
                    url,
                    api_version: &self.api_version,
                    idempotency_key: Some(idempotency_key),
                    form_body: Some(body),
                },
                self.call_timeout,
            )
            .await
            .map_err(pre_dispatch_error)?;
        if !(200..300).contains(&response.status) {
            return Err(classify_failure(response.status, &response.body));
        }
        parse_payment_intent(&response.body).map_err(BillingError::from)
    }

    /// Seals one request body and commits its envelope before any dispatch.
    ///
    /// The envelope is what lets a process that stopped between the dispatch
    /// stamp and the response record replay the byte-identical request under
    /// the same key purely to recover the original answer. It is committed
    /// first, because an envelope written after the write is an envelope that
    /// is missing exactly when it is needed.
    async fn seal_envelope(
        &self,
        dispatch: &DispatchContext,
        operation: AttemptOperation,
        requirement_digest: [u8; 32],
        body: &[u8],
    ) -> Result<(), BillingError> {
        let attempt = dispatch
            .attempt()
            .ok_or(BillingError::UnsupportedOperation)?;
        let binding = RecoveryBinding::new(
            SettlementRail::Stripe,
            &attempt.attempt_id,
            operation,
            dispatch.provider_idempotency_key(),
            requirement_digest,
        );
        let now_ms = dispatch.now_ms();
        let envelope = self
            .cipher
            .seal(&binding, body, now_ms, self.recovery_ttl_ms)?;
        dispatch.store().put_recovery_envelope(&envelope).await
    }

    /// Creates the manual-capture PaymentIntent the direct challenge names.
    async fn prepare_direct_challenge(
        &self,
        request: &ChallengePreparation,
        dispatch: &DispatchContext,
        payment_method_types: &[String],
        capture_method: &str,
        account_context: &str,
    ) -> Result<ChallengeMaterial, BillingError> {
        let draft = &request.draft;
        let (body, metadata) = build_direct_create_form(
            &request.intent_id,
            draft,
            &request.draft_digest,
            payment_method_types,
            capture_method,
            account_context,
        )?;
        let rendered = body.to_bytes();

        self.seal_envelope(
            dispatch,
            AttemptOperation::PrepareChallenge,
            request.draft_digest,
            rendered.as_slice(),
        )
        .await?;

        let url = self.endpoints.payment_intents_url();
        let key = dispatch.provider_idempotency_key().to_string();
        let intent = dispatch
            .run_write(|| async { self.post(&url, &key, rendered.as_slice()).await })
            .await?;

        // A create that answered without an identifier is ambiguous: the
        // object may well exist. It is never given an invented one.
        let id = intent.id.clone().ok_or(BillingError::NeedsReconciliation)?;
        validate_payment_intent_id(&id).map_err(BillingError::from)?;
        verify_metadata(&intent, &metadata).map_err(BillingError::from)?;
        if intent.amount != Some(stripe_minor_units(draft)?) {
            return Err(BillingError::RequirementMismatch);
        }

        // Only the identifier is persisted. The client secret goes into the
        // immediate TLS-protected 402 and nowhere else.
        let material = ChallengeMaterial {
            provider_handle: Some(id.clone()),
            client_secret: intent.client_secret,
            challenge_fields: BTreeMap::new(),
        };
        Ok(material
            .with_field(CHALLENGE_FIELD_PAYMENT_INTENT, &id)
            .with_field(CHALLENGE_FIELD_RETRY_HEADER, DIRECT_RETRY_HEADER))
    }

    /// Captures the challenge-bound PaymentIntent and proves it settled.
    async fn settle_direct(
        &self,
        request: &AuthoritativePayment,
        dispatch: &DispatchContext,
        capture_method: &str,
        account_context: &str,
    ) -> Result<SettlementReceipt, BillingError> {
        if capture_method != "manual" {
            return Err(StripeError::CaptureMethod.into());
        }
        let draft = &request.requirement.draft;
        let minor_units = stripe_minor_units(draft)?;
        let currency = draft.amount.provider_currency()?;
        // The identifier comes from the signed requirement, never from the
        // client. There is no code path here that reads a `pi_` value off a
        // request.
        let id = request
            .requirement
            .provider_handle
            .as_deref()
            .ok_or(BillingError::IntentNotFinalized)?;
        validate_payment_intent_id(id).map_err(BillingError::from)?;

        let draft_digest = draft.digest()?;
        let metadata = server_metadata(
            &request.intent_id,
            draft,
            METADATA_REQUIREMENT_DRAFT_DIGEST,
            &draft_digest,
            account_context,
        );
        let binding = SettlementBinding {
            intent_id: &request.intent_id,
            minor_units,
            currency: &currency,
            metadata: &metadata,
            method: draft.method.as_str(),
            now_ms: request.now_ms,
        };

        // Read first. A payment that is not authorized yet costs Stripe one
        // retrieve and leaves the gate at `NeverDispatched`, so the client
        // gets a retryable answer rather than a wedged intent.
        let current = dispatch.run_query(|| self.retrieve(id)).await?;
        verify_metadata(&current, &metadata).map_err(BillingError::from)?;
        if current.amount != Some(minor_units)
            || current.currency.as_deref() != Some(currency.as_str())
        {
            return Err(BillingError::RequirementMismatch);
        }
        match current.status {
            Some(PaymentIntentStatus::RequiresCapture) => {}
            // Already settled without this attempt capturing means an earlier
            // dispatch landed and was never recorded. That is exactly the
            // reconciliation case, and the worker's query proves it rather
            // than this path guessing.
            Some(PaymentIntentStatus::Succeeded) => return Err(BillingError::NeedsReconciliation),
            Some(PaymentIntentStatus::Canceled) => return Err(BillingError::ProviderRejected),
            Some(_) => return Err(BillingError::NotSettled),
            None => return Err(BillingError::ProviderMalformed),
        }

        let rendered = build_capture_form(minor_units)?.to_bytes();
        self.seal_envelope(
            dispatch,
            AttemptOperation::Capture,
            request.requirement_digest,
            rendered.as_slice(),
        )
        .await?;

        let capture_url = self.endpoints.capture_url(id)?;
        let key = dispatch.provider_idempotency_key().to_string();
        // The confirming retrieve runs inside the same gate call as the
        // capture. Outside it, a transport failure on the retrieve would be
        // judged against a gate that had already concluded `Resolved`, and a
        // captured payment would be recorded as a definite failure.
        dispatch
            .run_write(|| async {
                self.post(&capture_url, &key, rendered.as_slice()).await?;
                let settled = self.retrieve(id).await?;
                require_settled(&settled, &binding)
            })
            .await
    }

    /// Creates and confirms the Payment Auth charge from the presented token.
    ///
    /// The accepted method list is advertised in the challenge and is not sent
    /// alongside `automatic_payment_methods`, which Stripe treats as an
    /// alternative selector rather than an additional filter.
    async fn settle_payment_auth(
        &self,
        request: &AuthoritativePayment,
        dispatch: &DispatchContext,
        account_context: &str,
    ) -> Result<SettlementReceipt, BillingError> {
        let draft = &request.requirement.draft;
        let minor_units = stripe_minor_units(draft)?;
        let currency = draft.amount.provider_currency()?;

        let token = extract_shared_payment_token(&request.proof)?;
        let (body, metadata) = build_payment_auth_create_form(
            &request.intent_id,
            draft,
            &request.requirement_digest,
            account_context,
            token.as_str(),
        )?;
        drop(token);
        let rendered = body.to_bytes();

        self.seal_envelope(
            dispatch,
            AttemptOperation::Settle,
            request.requirement_digest,
            rendered.as_slice(),
        )
        .await?;

        let url = self.endpoints.payment_intents_url();
        let key = dispatch.provider_idempotency_key().to_string();
        let binding = SettlementBinding {
            intent_id: &request.intent_id,
            minor_units,
            currency: &currency,
            metadata: &metadata,
            method: draft.method.as_str(),
            now_ms: request.now_ms,
        };
        dispatch
            .run_write(|| async {
                let confirmed = self.post(&url, &key, rendered.as_slice()).await?;
                match confirmed.status {
                    // Anything that still needs an action can still settle
                    // later, so it is not a refusal. Recording it terminal
                    // here is how a proxy charges without serving.
                    Some(PaymentIntentStatus::Succeeded) => {}
                    Some(PaymentIntentStatus::Canceled) => {
                        return Err(BillingError::ProviderRejected)
                    }
                    Some(_) => return Err(BillingError::NeedsReconciliation),
                    None => return Err(BillingError::NeedsReconciliation),
                }
                require_settled(&confirmed, &binding)
            })
            .await
    }

    /// Resolves an outstanding attempt from Stripe's own record.
    async fn query_known_intent(
        &self,
        attempt: &ProviderAttempt,
        id: &str,
        now_ms: i64,
    ) -> Result<ProviderQueryResult, BillingError> {
        let Some(requirement) = attempt.requirement.as_ref() else {
            return Ok(ProviderQueryResult::Unsupported);
        };
        let intent = self.retrieve(id).await?;
        classify_queried_intent(attempt, requirement, &intent, now_ms)
    }

    /// Recovers a create whose response was lost, by replaying its bytes.
    ///
    /// This is the only replay in the crate, and it is a response recovery
    /// rather than a second charge: the same key with the same bytes returns
    /// Stripe's original answer. Every failure here leaves the attempt in
    /// reconciliation, and none of them falls back to a fresh key or to
    /// changed parameters.
    async fn recover_lost_create(
        &self,
        attempt: &ProviderAttempt,
        dispatch: &DispatchContext,
        now_ms: i64,
    ) -> Result<ProviderQueryResult, BillingError> {
        let Some(requirement) = attempt.requirement.as_ref() else {
            return Ok(ProviderQueryResult::Unsupported);
        };
        let Some(envelope) = dispatch
            .store()
            .load_recovery_envelope(&attempt.attempt_id)
            .await?
        else {
            return Ok(ProviderQueryResult::Unsupported);
        };
        if !self.cipher.is_replayable(&envelope, now_ms) {
            return Err(BillingError::RecoveryEnvelopeExpired);
        }
        let binding = RecoveryBinding::new(
            SettlementRail::Stripe,
            &attempt.attempt_id,
            attempt.operation,
            &attempt.provider_idempotency_key,
            requirement.digest()?,
        );
        // A wrong key identifier, a changed binding, a tampered ciphertext,
        // and an expired envelope all fail here and stay in reconciliation.
        let plaintext = self.cipher.open(&envelope, &binding, now_ms)?;
        let url = self.endpoints.payment_intents_url();
        let replayed = self
            .post(
                &url,
                &attempt.provider_idempotency_key,
                plaintext.as_slice(),
            )
            .await?;
        classify_queried_intent(attempt, requirement, &replayed, now_ms)
    }
}

/// Returns the non-secret account context a set of Stripe terms charges under.
///
/// # Errors
///
/// Returns [`StripeError::TermsMismatch`] for terms that are not Stripe's.
pub fn account_context_of(terms: &RequirementTerms) -> Result<&str, StripeError> {
    match terms {
        RequirementTerms::StripePaymentIntent {
            account_context, ..
        }
        | RequirementTerms::PaymentAuthStripeCharge {
            account_context, ..
        } => Ok(account_context.as_str()),
        _ => Err(StripeError::TermsMismatch),
    }
}

/// Returns the metadata key and digest one mode binds.
///
/// Direct mode binds the immutable draft digest, because a PaymentIntent
/// identifier cannot appear inside its own create request. Payment Auth binds
/// the final requirement digest, because its PaymentIntent is created after
/// the challenge is already final.
///
/// # Errors
///
/// Returns [`BillingError::Canonical`] when a digest cannot be computed and
/// [`BillingError::UnsupportedOperation`] for terms that are not Stripe's.
pub fn bound_digest(
    requirement: &PaymentRequirement,
) -> Result<(&'static str, [u8; 32]), BillingError> {
    match requirement.draft.terms {
        RequirementTerms::StripePaymentIntent { .. } => Ok((
            METADATA_REQUIREMENT_DRAFT_DIGEST,
            requirement.draft.digest()?,
        )),
        RequirementTerms::PaymentAuthStripeCharge { .. } => {
            Ok((METADATA_REQUIREMENT_DIGEST, requirement.digest()?))
        }
        _ => Err(StripeError::TermsMismatch.into()),
    }
}

/// Reads a retrieved or replayed PaymentIntent as a reconciliation answer.
///
/// There is no variant here that means "probably fine". Either Stripe's own
/// record proves the outcome or the attempt stays in reconciliation.
///
/// # Errors
///
/// Returns [`BillingError::ProviderMalformed`] for a status this build does
/// not recognize, and whatever [`require_settled`] returns when a settled
/// intent does not match its bindings.
pub fn classify_queried_intent(
    attempt: &ProviderAttempt,
    requirement: &PaymentRequirement,
    intent: &PaymentIntent,
    now_ms: i64,
) -> Result<ProviderQueryResult, BillingError> {
    let draft = &requirement.draft;
    let minor_units = stripe_minor_units(draft)?;
    let currency = draft.amount.provider_currency()?;
    let (digest_key, digest) = bound_digest(requirement)?;
    let account_context = account_context_of(&draft.terms)?;
    let metadata = server_metadata(
        &attempt.intent_id,
        draft,
        digest_key,
        &digest,
        account_context,
    );
    let binding = SettlementBinding {
        intent_id: &attempt.intent_id,
        minor_units,
        currency: &currency,
        metadata: &metadata,
        method: draft.method.as_str(),
        now_ms,
    };

    match intent.status {
        Some(PaymentIntentStatus::Succeeded) => Ok(ProviderQueryResult::Settled(require_settled(
            intent, &binding,
        )?)),
        Some(PaymentIntentStatus::Canceled) => Ok(ProviderQueryResult::Failed(SafeFailure::new(
            FailureCategory::Rejected,
            intent.raw_status.as_deref(),
            false,
        ))),
        // Awaiting capture proves the capture never landed, which is the one
        // observation that lets a later client retry create a fresh attempt
        // generation. It is never inferred from a transport failure.
        Some(PaymentIntentStatus::RequiresCapture)
            if matches!(
                attempt.operation,
                AttemptOperation::Capture | AttemptOperation::Settle
            ) =>
        {
            Ok(ProviderQueryResult::NotDispatched)
        }
        Some(_) => Ok(ProviderQueryResult::StillPending),
        None => Err(BillingError::ProviderMalformed),
    }
}

/// Pulls the single use payment token out of a Payment Auth credential.
///
/// The token is copied into a zeroizing buffer and never returned by value in
/// plaintext beyond the caller's own scope.
///
/// # Errors
///
/// Returns [`BillingError::InvalidProof`] when the credential does not decode
/// into the pinned Stripe charge payload or the token does not carry the
/// registered prefix.
#[cfg(feature = "mpp")]
fn extract_shared_payment_token(proof: &PaymentProof) -> Result<Zeroizing<String>, BillingError> {
    let credential = crate::payment_auth::decode_credential(proof.expose_credential())
        .map_err(|_| BillingError::InvalidProof)?;
    let token = credential.payload.expose_spt();
    if !token.starts_with(SHARED_PAYMENT_TOKEN_PREFIX) {
        return Err(BillingError::InvalidProof);
    }
    Ok(Zeroizing::new(token.to_string()))
}

/// Payment Auth charges need the pinned draft-01 codec, which is the `mpp`
/// feature. Without it this rail refuses rather than guessing a token shape.
///
/// # Errors
///
/// Always returns [`BillingError::UnsupportedOperation`].
#[cfg(not(feature = "mpp"))]
fn extract_shared_payment_token(_proof: &PaymentProof) -> Result<Zeroizing<String>, BillingError> {
    Err(BillingError::UnsupportedOperation)
}

#[async_trait::async_trait]
impl<T: StripeTransport> PaymentMethodAdapter for StripePaymentIntentSettler<T> {
    fn rail(&self) -> SettlementRail {
        SettlementRail::Stripe
    }

    async fn prepare_challenge(
        &self,
        request: ChallengePreparation,
        dispatch: &DispatchContext,
    ) -> Result<ChallengeMaterial, BillingError> {
        match request.draft.terms.clone() {
            RequirementTerms::StripePaymentIntent {
                payment_method_types,
                capture_method,
                account_context,
            } => {
                let inner = self.prepare_direct_challenge(
                    &request,
                    dispatch,
                    &payment_method_types,
                    &capture_method,
                    &account_context,
                );
                match tokio::time::timeout(self.total_deadline, inner).await {
                    Ok(result) => result,
                    Err(_elapsed) => Err(deadline_error(dispatch)),
                }
            }
            // `draft-stripe-charge-00` creates nothing until the credential
            // arrives, so challenge preparation contacts no provider at all.
            RequirementTerms::PaymentAuthStripeCharge { .. } => Ok(ChallengeMaterial::new(None)),
            _ => Err(StripeError::TermsMismatch.into()),
        }
    }

    async fn authorize_and_settle(
        &self,
        request: AuthoritativePayment,
        dispatch: &DispatchContext,
    ) -> Result<SettlementReceipt, BillingError> {
        let terms = request.requirement.draft.terms.clone();
        let inner = async {
            match terms {
                RequirementTerms::StripePaymentIntent {
                    capture_method,
                    account_context,
                    ..
                } => {
                    self.settle_direct(&request, dispatch, &capture_method, &account_context)
                        .await
                }
                RequirementTerms::PaymentAuthStripeCharge {
                    account_context, ..
                } => {
                    self.settle_payment_auth(&request, dispatch, &account_context)
                        .await
                }
                _ => Err(StripeError::TermsMismatch.into()),
            }
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
        let now_ms = dispatch.now_ms();
        match attempt.provider_handle.clone() {
            Some(id) => {
                dispatch
                    .run_query(|| self.query_known_intent(attempt, &id, now_ms))
                    .await
            }
            // No identifier means the create dispatch was lost before its
            // answer was recorded. The only documented way back is a
            // byte-identical replay under the same persisted key.
            None => {
                dispatch
                    .run_query(|| self.recover_lost_create(attempt, dispatch, now_ms))
                    .await
            }
        }
    }
}

/// Maps an elapsed deadline onto the durable transition the gate permits.
///
/// A deadline that fires after the dispatch stamp cannot be reported as a
/// timeout: the write may have landed, and only a documented status query can
/// say.
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
    use crate::money::Money;

    /// `unwrap_err` requires `Debug` on the success type, and several types
    /// here deliberately do not carry one because they hold client secrets
    /// and single use payment tokens. Errors are unwrapped through this
    /// helper rather than widening a derive to suit a test.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn the_api_root_keeps_its_prefix_and_gains_only_a_known_path() {
        let endpoints = StripeEndpoints::from_api_root("https://api.stripe.com/")
            .expect("a rooted https URL is usable");
        assert_eq!(
            endpoints.payment_intents_url(),
            "https://api.stripe.com/v1/payment_intents"
        );
        assert_eq!(
            endpoints
                .payment_intent_url("pi_abc123")
                .expect("a usable identifier"),
            "https://api.stripe.com/v1/payment_intents/pi_abc123"
        );
        assert_eq!(
            endpoints
                .capture_url("pi_abc123")
                .expect("a usable identifier"),
            "https://api.stripe.com/v1/payment_intents/pi_abc123/capture"
        );
    }

    #[test]
    fn unusable_api_roots_are_refused() {
        for bad in [
            "http://api.stripe.com",
            "https://user:pass@api.stripe.com",
            "https://api.stripe.com?v=1",
            "https://api.stripe.com#frag",
            "https://api.stripe.com/a/../b",
            "https://api.stripe.com/a//b",
            "api.stripe.com",
            "",
        ] {
            assert_eq!(
                expect_error(
                    StripeEndpoints::from_api_root(bad),
                    "an unusable API root must be refused"
                ),
                StripeError::ApiRoot,
                "expected {bad:?} to be refused"
            );
        }
        assert!(StripeEndpoints::loopback_http_for_test("http://127.0.0.1:9111").is_ok());
        assert_eq!(
            expect_error(
                StripeEndpoints::loopback_http_for_test("http://api.stripe.com"),
                "cleartext off loopback must be refused"
            ),
            StripeError::ApiRoot
        );
    }

    #[test]
    fn a_provider_identifier_cannot_steer_a_path() {
        let endpoints =
            StripeEndpoints::from_api_root("https://api.stripe.com").expect("a usable root");
        for bad in [
            "",
            "pi_",
            "ch_abc",
            "pi_../../charges",
            "pi_abc/def",
            "pi_a b",
        ] {
            assert_eq!(
                expect_error(
                    endpoints.payment_intent_url(bad),
                    "an unusable identifier must be refused"
                ),
                StripeError::PaymentIntentId,
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn the_pinned_api_version_is_the_only_one_accepted() {
        assert_eq!(STRIPE_API_VERSION, "2026-06-24.dahlia");
    }

    #[test]
    fn form_bodies_are_sorted_percent_encoded_and_duplicate_free() {
        let mut body = FormBody::new();
        body.set("currency", "usd").expect("first write");
        body.set_u64("amount", 1_250).expect("first write");
        body.set("metadata[sbproxy_quote_id]", "q/1 2")
            .expect("first write");
        assert_eq!(
            String::from_utf8(body.to_bytes().as_slice().to_vec()).expect("ascii"),
            "amount=1250&currency=usd&metadata%5Bsbproxy_quote_id%5D=q%2F1%202"
        );
        assert_eq!(
            expect_error(body.set("amount", "9"), "a duplicate key must be refused"),
            StripeError::MetadataConflict
        );
    }

    #[test]
    fn client_metadata_cannot_reach_the_server_namespace() {
        let server: BTreeMap<String, String> =
            [(METADATA_QUOTE_ID.to_string(), "quote-1".to_string())]
                .into_iter()
                .collect();
        let hostile: BTreeMap<String, String> =
            [(METADATA_QUOTE_ID.to_string(), "quote-2".to_string())]
                .into_iter()
                .collect();
        let mut body = FormBody::new();
        assert_eq!(
            expect_error(
                write_metadata(&mut body, &server, &hostile),
                "a colliding client key must be refused"
            ),
            StripeError::MetadataConflict
        );

        let benign: BTreeMap<String, String> = [("order".to_string(), "42".to_string())]
            .into_iter()
            .collect();
        let mut body = FormBody::new();
        write_metadata(&mut body, &server, &benign).expect("a benign key is written");
        assert_eq!(
            body.get("metadata[sbproxy_quote_id]"),
            Some("quote-1"),
            "the server value survives"
        );
        assert_eq!(body.get("metadata[order]"), Some("42"));
    }

    #[test]
    fn an_unknown_status_is_not_read_as_a_success() {
        assert_eq!(
            PaymentIntentStatus::parse("succeeded"),
            Some(PaymentIntentStatus::Succeeded)
        );
        assert_eq!(PaymentIntentStatus::parse("requires_review"), None);
        assert_eq!(PaymentIntentStatus::parse(""), None);
    }

    #[test]
    fn an_incomplete_answer_is_ambiguous_rather_than_settled() {
        let intent = parse_payment_intent(br#"{"id":"pi_abc","status":"succeeded"}"#)
            .expect("a partial body parses");
        let metadata = BTreeMap::new();
        let binding = SettlementBinding {
            intent_id: "sbpi_one",
            minor_units: 1_250,
            currency: "usd",
            metadata: &metadata,
            method: "stripe",
            now_ms: 1_000,
        };
        assert_eq!(
            expect_error(
                require_settled(&intent, &binding),
                "a success with no amount is not a receipt"
            ),
            BillingError::RequirementMismatch
        );
    }

    #[test]
    fn only_an_exact_settled_intent_becomes_a_receipt() {
        let body = br#"{
            "id":"pi_abc123","status":"succeeded","amount":1250,
            "amount_received":1250,"currency":"usd",
            "metadata":{"sbproxy_quote_id":"quote-1"}
        }"#;
        let intent = parse_payment_intent(body).expect("the body parses");
        let metadata: BTreeMap<String, String> =
            [(METADATA_QUOTE_ID.to_string(), "quote-1".to_string())]
                .into_iter()
                .collect();
        let binding = SettlementBinding {
            intent_id: "sbpi_one",
            minor_units: 1_250,
            currency: "usd",
            metadata: &metadata,
            method: "stripe",
            now_ms: 1_000,
        };
        let receipt = require_settled(&intent, &binding).expect("an exact intent settles");
        assert_eq!(receipt.provider_reference, "pi_abc123");
        assert_eq!(receipt.rail, SettlementRail::Stripe);

        let wrong = SettlementBinding {
            minor_units: 1_251,
            ..binding
        };
        assert_eq!(
            expect_error(
                require_settled(&intent, &wrong),
                "an amount mismatch must deny"
            ),
            BillingError::RequirementMismatch
        );
    }

    #[test]
    fn unsettled_states_deny_without_inventing_a_receipt() {
        for (status, expected) in [
            ("requires_action", BillingError::NotSettled),
            ("requires_payment_method", BillingError::NotSettled),
            ("requires_capture", BillingError::NotSettled),
            ("processing", BillingError::NotSettled),
            ("canceled", BillingError::ProviderRejected),
        ] {
            let body = format!(r#"{{"id":"pi_abc123","status":"{status}"}}"#);
            let intent = parse_payment_intent(body.as_bytes()).expect("the body parses");
            let metadata = BTreeMap::new();
            let binding = SettlementBinding {
                intent_id: "sbpi_one",
                minor_units: 1_250,
                currency: "usd",
                metadata: &metadata,
                method: "stripe",
                now_ms: 1_000,
            };
            assert_eq!(
                expect_error(
                    require_settled(&intent, &binding),
                    "an unsettled state must deny"
                ),
                expected,
                "expected {status} to deny"
            );
        }
    }

    #[test]
    fn ambiguity_and_refusal_are_told_apart() {
        assert_eq!(
            classify_failure(
                402,
                br#"{"error":{"type":"card_error","code":"card_declined"}}"#
            ),
            BillingError::ProviderRejected
        );
        assert_eq!(
            classify_failure(400, br#"{"error":{"type":"idempotency_error"}}"#),
            BillingError::NeedsReconciliation
        );
        assert_eq!(
            classify_failure(409, b"{}"),
            BillingError::NeedsReconciliation
        );
        assert_eq!(
            classify_failure(429, b"{}"),
            BillingError::ProviderUnavailable
        );
        assert_eq!(
            classify_failure(503, b"{}"),
            BillingError::ProviderUnavailable
        );
    }

    #[test]
    fn amounts_are_exact_minor_units_and_never_rescaled() {
        // 12_500_000 micros is USD 12.50, which is 1250 minor units.
        let draft = draft_fixture(12_500_000, 2, "1250");
        assert_eq!(stripe_minor_units(&draft).expect("exact"), 1_250);

        // An advertised string that disagrees with the exact conversion is a
        // refusal, not a re-scaling.
        let drifted = draft_fixture(12_500_000, 2, "1251");
        assert_eq!(
            expect_error(
                stripe_minor_units(&drifted),
                "a drifted amount must be refused"
            ),
            BillingError::AmountNotRepresentable
        );

        // Micros that do not land on a whole minor unit never round.
        let fractional = draft_fixture(12_500_500, 2, "");
        assert_eq!(
            expect_error(
                stripe_minor_units(&fractional),
                "a fractional minor unit must be refused"
            ),
            BillingError::AmountNotRepresentable
        );
    }

    /// Builds a Stripe direct-mode draft for the money tests.
    fn draft_fixture(
        amount_micros: u64,
        decimals: u8,
        settlement_amount: &str,
    ) -> PaymentRequirementDraft {
        PaymentRequirementDraft {
            requirement_id: "requirement_0123456789".to_string(),
            protocol: crate::types::PaymentProtocol::StripePaymentIntentV1,
            advertised_rail: crate::types::AdvertisedRail::Stripe,
            settlement_rail: SettlementRail::Stripe,
            method: "stripe".to_string(),
            intent: "charge".to_string(),
            network: None,
            asset: None,
            pay_to: None,
            amount: Money {
                amount_micros,
                currency: "USD".to_string(),
            },
            settlement_amount: settlement_amount.to_string(),
            settlement_decimals: decimals,
            terms: RequirementTerms::StripePaymentIntent {
                payment_method_types: vec!["card".to_string()],
                capture_method: "manual".to_string(),
                account_context: "acct_platform".to_string(),
            },
            quote_id: "quote-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            origin_id: "origin-1".to_string(),
            route: "/paid".to_string(),
            expires_at_ms: 2_000,
            request_digest: None,
        }
    }
}
