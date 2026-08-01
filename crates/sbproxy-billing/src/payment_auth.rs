//! Payment HTTP Authentication, `draft-ryan-httpauth-payment-01`.
//!
//! This module is the byte-level codec and the strict local gate. It
//! turns a priced obligation into exactly one `WWW-Authenticate: Payment`
//! challenge, and it turns exactly one `Authorization: Payment` field
//! back into a verified, replay-protected credential. It performs no
//! network work, opens no store, and authorizes nothing: it hands the
//! caller a [`PaymentProof`] whose digest the durable store reserves
//! before any provider is contacted.
//!
//! # What "strict" means here
//!
//! Every one of these is a refusal, never a coercion:
//!
//! - a value in a base64url slot that carries `=`, `+`, or `/`;
//! - bytes that are not valid UTF-8;
//! - JSON with a duplicate object key, or nested past
//!   [`MAX_JSON_DEPTH`];
//! - a challenge whose echoed parameters do not recompute its own `id`;
//! - a challenge past its `expires`;
//! - a body whose RFC 9530 digest is not the one the challenge bound;
//! - a method or intent other than the registered `stripe` plus
//!   `charge` pair;
//! - a payload that is not exactly the pinned Stripe charge schema.
//!
//! Unknown challenge parameters and unknown top-level credential fields
//! are ignored, because draft-01 requires that. The Stripe payload is
//! the exception: it is a pinned schema and rejects unknown members.
//!
//! # Redaction
//!
//! [`PaymentCredential`] and [`VerifiedCredential`] hold a single-use
//! Stripe payment token. Neither derives `Debug`, neither implements
//! `Display`, and the token leaves its zeroizing buffer through one
//! loudly named accessor. No error variant in this module carries
//! credential bytes, a payer identifier, or a provider payload; every
//! message is a fixed string.
//!
//! # Wire vocabulary
//!
//! The wire scheme is `Payment`. No protocol version appears on the
//! wire. The draft's own version is carried in configuration, checked
//! at load, and never negotiated with a client.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::BillingError;
use crate::types::PaymentProof;

/// HMAC-SHA256, the one MAC this draft profile uses.
type HmacSha256 = Hmac<Sha256>;

/// The authentication scheme token, exactly as it appears on the wire.
pub const PAYMENT_SCHEME: &str = "Payment";

/// The only registered method this release implements.
pub const METHOD_STRIPE: &str = "stripe";

/// The only registered intent this release implements.
pub const INTENT_CHARGE: &str = "charge";

/// The response header that carries a settlement receipt.
///
/// Emitted on a successful paid 2xx and on nothing else.
pub const RECEIPT_HEADER: &str = "Payment-Receipt";

/// The local, negotiation-only preference header.
pub const ACCEPT_PAYMENT_HEADER: &str = "Accept-Payment";

/// Media type of every payment problem document.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// Canonical prefix of every draft-01 problem type URI.
pub const PROBLEM_TYPE_PREFIX: &str = "https://paymentauth.org/problems/";

/// `Cache-Control` value on every challenge response.
pub const CACHE_CONTROL_CHALLENGE: &str = "no-store";

/// `Cache-Control` value on a successful paid response.
pub const CACHE_CONTROL_PAID: &str = "private";

/// Largest challenge field value this codec will generate, in bytes.
pub const MAX_CHALLENGE_BYTES: usize = 8 * 1024;

/// Largest credential field value this codec will accept, in bytes.
///
/// The draft requires implementations to support at least
/// [`MIN_SUPPORTED_CREDENTIAL_BYTES`]. This cap sits well above that so
/// a conforming client is never truncated, and well below anything that
/// would let an unauthenticated request pin real memory.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

/// Smallest credential size the draft requires an implementation to
/// accept.
pub const MIN_SUPPORTED_CREDENTIAL_BYTES: usize = 4 * 1024;

/// Deepest JSON nesting accepted in a challenge, credential, or receipt.
pub const MAX_JSON_DEPTH: usize = 16;

/// Longest single-use payment token accepted in a credential payload.
pub const MAX_SPT_BYTES: usize = 4 * 1024;

/// Longest client-supplied `externalId` accepted in a payload.
pub const MAX_EXTERNAL_ID_BYTES: usize = 255;

/// Required prefix on a Stripe single-use payment token.
pub const SPT_PREFIX: &str = "spt_";

/// Exact length of the RFC 3339 UTC instant this profile puts on the
/// wire, as in `2026-07-29T20:05:00Z`.
const RFC3339_UTC_LEN: usize = 20;

// --- Problems ---

/// The closed set of draft-01 problem codes.
///
/// The registry is fixed by the draft. Nothing in this module invents a
/// code, and no provider text ever becomes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaymentAuthProblemCode {
    /// No credential was presented for a resource that requires one.
    PaymentRequired,
    /// The credential settled less than the resource costs.
    PaymentInsufficient,
    /// The challenge the credential echoes has passed its expiry.
    PaymentExpired,
    /// The credential was well formed but did not verify.
    VerificationFailed,
    /// The requested method or intent is not offered here.
    MethodUnsupported,
    /// The credential could not be decoded into the pinned schema.
    MalformedCredential,
    /// The echoed challenge is not one this proxy issued.
    InvalidChallenge,
}

impl PaymentAuthProblemCode {
    /// Returns the registered code token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentRequired => "payment-required",
            Self::PaymentInsufficient => "payment-insufficient",
            Self::PaymentExpired => "payment-expired",
            Self::VerificationFailed => "verification-failed",
            Self::MethodUnsupported => "method-unsupported",
            Self::MalformedCredential => "malformed-credential",
            Self::InvalidChallenge => "invalid-challenge",
        }
    }

    /// Returns the status the draft registers for this code.
    ///
    /// Every code is 402 except `method-unsupported`, which is the one
    /// registered 400: a client asking for a method this resource does
    /// not offer has made a bad request, not an underpayment.
    #[must_use]
    pub const fn registered_status(self) -> u16 {
        match self {
            Self::MethodUnsupported => 400,
            Self::PaymentRequired
            | Self::PaymentInsufficient
            | Self::PaymentExpired
            | Self::VerificationFailed
            | Self::MalformedCredential
            | Self::InvalidChallenge => 402,
        }
    }

    /// Returns a fixed, non-secret title for the problem document.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::PaymentRequired => "Payment required",
            Self::PaymentInsufficient => "Payment insufficient",
            Self::PaymentExpired => "Payment challenge expired",
            Self::VerificationFailed => "Payment verification failed",
            Self::MethodUnsupported => "Payment method not supported",
            Self::MalformedCredential => "Malformed payment credential",
            Self::InvalidChallenge => "Invalid payment challenge",
        }
    }

    /// Returns the canonical problem type URI.
    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{PROBLEM_TYPE_PREFIX}{}", self.as_str())
    }
}

impl std::fmt::Display for PaymentAuthProblemCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Everything this codec refuses, as a typed, non-secret reason.
///
/// Each variant carries a fixed message. None of them can be widened to
/// include a credential, a token, a payer identifier, or a provider
/// body, which is why the request path can return them verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PaymentAuthError {
    /// No `Authorization: Payment` field was present.
    #[error("no payment credential was presented")]
    CredentialMissing,

    /// More than one `Authorization: Payment` field was present.
    #[error("more than one payment credential was presented")]
    DuplicateCredential,

    /// The field value did not decode into the pinned credential shape.
    #[error("payment credential is malformed")]
    MalformedCredential,

    /// The echoed challenge does not recompute its own identifier.
    #[error("payment challenge is not one this proxy issued")]
    InvalidChallenge,

    /// The echoed challenge has passed its expiry.
    #[error("payment challenge has expired")]
    Expired,

    /// The credential names a method or intent this resource does not
    /// offer.
    #[error("payment method or intent is not offered for this resource")]
    MethodUnsupported,

    /// The credential decoded and bound correctly but did not verify.
    #[error("payment verification failed")]
    VerificationFailed,

    /// The settled amount is below the price of the resource.
    #[error("payment is insufficient for this resource")]
    Insufficient,

    /// The request body is larger than the configured payment cap.
    ///
    /// This is a transport refusal rather than a payment problem: the
    /// proxy must hash the exact request bytes to bind a challenge, so
    /// a body it will not buffer can never be priced. It is answered
    /// before any challenge is issued and before any provider is
    /// contacted.
    #[error("request body exceeds the configured payment body limit")]
    BodyTooLarge,

    /// The generated challenge would exceed [`MAX_CHALLENGE_BYTES`].
    #[error("generated payment challenge exceeds its size bound")]
    ChallengeTooLarge,

    /// The flow was attempted over cleartext outside the test-only
    /// loopback path.
    #[error("payment authentication requires TLS")]
    InsecureTransport,

    /// A local invariant of this codec was violated.
    #[error("payment challenge could not be built")]
    Internal,
}

impl PaymentAuthError {
    /// Returns the draft problem code, when this refusal has one.
    ///
    /// [`Self::BodyTooLarge`], [`Self::ChallengeTooLarge`],
    /// [`Self::InsecureTransport`], and [`Self::Internal`] deliberately
    /// return `None`: none of them is a statement about the payment, so
    /// answering them with a payment problem document would tell a
    /// client to retry a payment that was never the issue.
    #[must_use]
    pub const fn problem_code(self) -> Option<PaymentAuthProblemCode> {
        match self {
            Self::CredentialMissing => Some(PaymentAuthProblemCode::PaymentRequired),
            Self::DuplicateCredential | Self::MalformedCredential => {
                Some(PaymentAuthProblemCode::MalformedCredential)
            }
            Self::InvalidChallenge => Some(PaymentAuthProblemCode::InvalidChallenge),
            Self::Expired => Some(PaymentAuthProblemCode::PaymentExpired),
            Self::MethodUnsupported => Some(PaymentAuthProblemCode::MethodUnsupported),
            Self::VerificationFailed => Some(PaymentAuthProblemCode::VerificationFailed),
            Self::Insufficient => Some(PaymentAuthProblemCode::PaymentInsufficient),
            Self::BodyTooLarge
            | Self::ChallengeTooLarge
            | Self::InsecureTransport
            | Self::Internal => None,
        }
    }

    /// Returns the HTTP status the request path answers with.
    ///
    /// This equals the registered status of the problem code in every
    /// case but one: two `Payment` credentials in one request is a
    /// malformed request rather than a malformed payment, so it is 400
    /// while the `malformed-credential` code keeps its registered 402.
    /// Modelling it this way keeps the registry table exact.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::DuplicateCredential => 400,
            Self::BodyTooLarge => 413,
            Self::ChallengeTooLarge | Self::Internal => 500,
            Self::InsecureTransport => 421,
            other => match other.problem_code() {
                Some(code) => code.registered_status(),
                None => 500,
            },
        }
    }

    /// Reports whether the response for this refusal carries a fresh
    /// challenge.
    ///
    /// Every 402 does, so a client that can pay is told exactly how.
    /// The 400, 413, 421, and 500 answers do not, because repeating the
    /// price would invite a retry that cannot succeed.
    #[must_use]
    pub const fn offers_fresh_challenge(self) -> bool {
        self.status() == 402
    }

    /// Renders the RFC 9457 problem document for this refusal.
    ///
    /// Returns `None` for the refusals that are not payment problems.
    #[must_use]
    pub fn problem_document(self) -> Option<serde_json::Value> {
        let code = self.problem_code()?;
        Some(serde_json::json!({
            "type": code.type_uri(),
            "title": code.title(),
            "status": self.status(),
        }))
    }
}

impl From<PaymentAuthError> for BillingError {
    fn from(error: PaymentAuthError) -> Self {
        match error {
            PaymentAuthError::Expired => Self::IntentExpired,
            PaymentAuthError::InvalidChallenge => Self::RequirementMismatch,
            PaymentAuthError::MethodUnsupported => Self::UnsupportedOperation,
            PaymentAuthError::VerificationFailed | PaymentAuthError::Insufficient => {
                Self::ProviderRejected
            }
            PaymentAuthError::Internal | PaymentAuthError::ChallengeTooLarge => {
                Self::InvalidRequirement("payment_auth_challenge")
            }
            PaymentAuthError::CredentialMissing
            | PaymentAuthError::DuplicateCredential
            | PaymentAuthError::MalformedCredential
            | PaymentAuthError::BodyTooLarge
            | PaymentAuthError::InsecureTransport => Self::InvalidProof,
        }
    }
}

// --- Pinned Stripe charge schema ---

/// The `draft-stripe-charge-00` request object.
///
/// These are the exact members the registration defines. The object is
/// JCS serialized and base64url encoded into the challenge's `request`
/// parameter, so its bytes are stable and the client can echo them
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StripeChargeRequest {
    /// Amount in the currency's atomic units, as a decimal string.
    pub amount: String,
    /// Lowercase ISO 4217 code, in the spelling the provider wants.
    pub currency: String,
    /// The proxy's own identifier for this obligation.
    #[serde(rename = "externalId")]
    pub external_id: String,
    /// Method-specific details.
    #[serde(rename = "methodDetails")]
    pub method_details: StripeChargeMethodDetails,
}

/// The `methodDetails` member of a Stripe charge request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StripeChargeMethodDetails {
    /// Non-secret metadata copied onto the resulting PaymentIntent.
    pub metadata: BTreeMap<String, String>,
    /// The business network identifier the charge registers under.
    #[serde(rename = "networkId")]
    pub network_id: String,
    /// Accepted payment method types.
    #[serde(rename = "paymentMethodTypes")]
    pub payment_method_types: Vec<String>,
}

/// The opaque state a challenge carries through the client.
///
/// It is signed into the challenge identifier, so a client cannot edit
/// it, and it holds only non-secret routing values: which durable intent
/// this challenge belongs to and which provider settles it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeOpaque {
    /// The durable settlement intent this challenge prepared.
    pub intent_id: String,
    /// The provider that will settle it.
    pub provider: String,
}

/// The typed payload half of a Payment credential.
///
/// The token is held in a zeroizing buffer and leaves it through one
/// accessor. This type derives no `Debug` and implements no `Display`,
/// so there is no formatting path that can print it by accident.
pub struct StripeChargePayload {
    spt: Zeroizing<String>,
    external_id: Option<String>,
}

impl StripeChargePayload {
    /// Borrows the single-use payment token so an adapter can send it
    /// to the pinned provider endpoint.
    ///
    /// This is the one way out of the zeroizing buffer. The returned
    /// string must go to Stripe and nowhere else: not to a log, not to
    /// an error, not to a durable column, and not into an idempotency
    /// key.
    #[must_use]
    pub fn expose_spt(&self) -> &str {
        self.spt.as_str()
    }

    /// Returns the client-supplied correlation identifier, when present.
    ///
    /// It is bounded and echoed for the client's own reconciliation. It
    /// is never treated as routing input: nothing selects an account, a
    /// rail, or a price from it.
    #[must_use]
    pub fn external_id(&self) -> Option<&str> {
        self.external_id.as_deref()
    }
}

/// The wire form of the payload, deserialized under the pinned schema.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StripeChargePayloadWire {
    spt: String,
    #[serde(default, rename = "externalId")]
    external_id: Option<String>,
}

// --- Challenge ---

/// One `WWW-Authenticate: Payment` challenge.
///
/// Every field is non-secret. The `id` is the MAC over the other seven
/// slots, which is what makes the challenge unforgeable without holding
/// the binding key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentChallenge {
    /// Unpadded base64url HMAC-SHA256 over the seven binding slots.
    pub id: String,
    /// Protection space.
    pub realm: String,
    /// Registered method token, lowercase.
    pub method: String,
    /// Registered intent token, lowercase.
    pub intent: String,
    /// Unpadded base64url of the JCS request object.
    pub request: String,
    /// RFC 3339 UTC instant, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub expires: String,
    /// RFC 9530 digest parameter over the exact request body, when the
    /// request carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Unpadded base64url of the JCS opaque object, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
}

impl PaymentChallenge {
    /// Serializes the exact `WWW-Authenticate` field value.
    ///
    /// Parameter order is fixed so the bytes are reproducible: `id`,
    /// `realm`, `method`, `intent`, `request`, `expires`, `digest`,
    /// `opaque`. Absent optional parameters are omitted rather than
    /// emitted empty.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::ChallengeTooLarge`] when the value
    /// would exceed [`MAX_CHALLENGE_BYTES`] and
    /// [`PaymentAuthError::Internal`] when a parameter holds a
    /// character that cannot appear in a quoted string.
    pub fn to_header_value(&self) -> Result<String, PaymentAuthError> {
        let mut parameters: Vec<(&str, &str)> = vec![
            ("id", self.id.as_str()),
            ("realm", self.realm.as_str()),
            ("method", self.method.as_str()),
            ("intent", self.intent.as_str()),
            ("request", self.request.as_str()),
            ("expires", self.expires.as_str()),
        ];
        if let Some(digest) = self.digest.as_deref() {
            parameters.push(("digest", digest));
        }
        if let Some(opaque) = self.opaque.as_deref() {
            parameters.push(("opaque", opaque));
        }

        let mut rendered = String::from(PAYMENT_SCHEME);
        for (index, (name, value)) in parameters.iter().copied().enumerate() {
            if value.is_empty() || value.contains('"') || value.contains('\\') {
                return Err(PaymentAuthError::Internal);
            }
            rendered.push_str(if index == 0 { " " } else { ", " });
            rendered.push_str(name);
            rendered.push_str("=\"");
            rendered.push_str(value);
            rendered.push('"');
        }
        if rendered.len() > MAX_CHALLENGE_BYTES {
            return Err(PaymentAuthError::ChallengeTooLarge);
        }
        Ok(rendered)
    }

    /// Parses a `WWW-Authenticate` field value back into a challenge.
    ///
    /// Unknown parameters are ignored, as draft-01 requires. A repeated
    /// parameter, an unquoted value, an empty value, or a missing
    /// required parameter is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::InvalidChallenge`].
    pub fn parse_header_value(value: &str) -> Result<Self, PaymentAuthError> {
        if value.len() > MAX_CHALLENGE_BYTES {
            return Err(PaymentAuthError::InvalidChallenge);
        }
        let rest = value
            .strip_prefix(PAYMENT_SCHEME)
            .and_then(|rest| rest.strip_prefix(' '))
            .ok_or(PaymentAuthError::InvalidChallenge)?;

        let mut found: BTreeMap<String, String> = BTreeMap::new();
        for part in split_challenge_parameters(rest)? {
            let (name, raw) = part
                .split_once('=')
                .ok_or(PaymentAuthError::InvalidChallenge)?;
            let name = name.trim().to_ascii_lowercase();
            let raw = raw.trim();
            let quoted = raw
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .ok_or(PaymentAuthError::InvalidChallenge)?;
            if quoted.is_empty() || quoted.contains('\\') {
                return Err(PaymentAuthError::InvalidChallenge);
            }
            if found.insert(name, quoted.to_string()).is_some() {
                return Err(PaymentAuthError::InvalidChallenge);
            }
        }

        let take = |key: &str| -> Result<String, PaymentAuthError> {
            found
                .get(key)
                .cloned()
                .ok_or(PaymentAuthError::InvalidChallenge)
        };
        Ok(Self {
            id: take("id")?,
            realm: take("realm")?,
            method: take("method")?,
            intent: take("intent")?,
            request: take("request")?,
            expires: take("expires")?,
            digest: found.get("digest").cloned(),
            opaque: found.get("opaque").cloned(),
        })
    }

    /// Decodes the `request` parameter into the pinned Stripe schema.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::MalformedCredential`] when the slot
    /// is not strict base64url of a JCS Stripe charge request.
    pub fn decode_request(&self) -> Result<StripeChargeRequest, PaymentAuthError> {
        let bytes = decode_base64url_strict(&self.request)?;
        let value = parse_strict_json(&bytes)?;
        serde_json::from_value(value).map_err(|_| PaymentAuthError::MalformedCredential)
    }

    /// Decodes the `opaque` parameter, when present.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::MalformedCredential`] when the slot
    /// is present but is not strict base64url of a JCS opaque object.
    pub fn decode_opaque(&self) -> Result<Option<ChallengeOpaque>, PaymentAuthError> {
        let Some(raw) = self.opaque.as_deref() else {
            return Ok(None);
        };
        let bytes = decode_base64url_strict(raw)?;
        let value = parse_strict_json(&bytes)?;
        serde_json::from_value(value)
            .map(Some)
            .map_err(|_| PaymentAuthError::MalformedCredential)
    }

    /// Returns the exact seven-slot binding input for this challenge.
    ///
    /// The slots are `realm|method|intent|request|expires|digest|opaque`
    /// and an absent optional slot is the empty string, never a skipped
    /// separator. None of the slot values can contain the separator:
    /// base64url has no `|`, the RFC 9530 parameter has no `|`, the
    /// instant format has no `|`, the method and intent are pinned
    /// tokens, and the realm is rejected at binder construction if it
    /// carries one.
    #[must_use]
    pub fn binding_input(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.realm,
            self.method,
            self.intent,
            self.request,
            self.expires,
            self.digest.as_deref().unwrap_or(""),
            self.opaque.as_deref().unwrap_or(""),
        )
    }

    /// Returns the challenge expiry in milliseconds since the epoch.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::MalformedCredential`] when `expires`
    /// is not the exact `YYYY-MM-DDTHH:MM:SSZ` form.
    pub fn expires_at_ms(&self) -> Result<i64, PaymentAuthError> {
        parse_rfc3339_utc(&self.expires)
    }
}

/// Splits a challenge parameter list on commas outside quoted strings.
fn split_challenge_parameters(input: &str) -> Result<Vec<String>, PaymentAuthError> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for character in input.chars() {
        match character {
            '"' => {
                in_quotes = !in_quotes;
                current.push(character);
            }
            ',' if !in_quotes => {
                parts.push(std::mem::take(&mut current));
            }
            other => current.push(other),
        }
    }
    if in_quotes {
        return Err(PaymentAuthError::InvalidChallenge);
    }
    parts.push(current);
    let parts: Vec<String> = parts
        .into_iter()
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return Err(PaymentAuthError::InvalidChallenge);
    }
    Ok(parts)
}

// --- Credential ---

/// A decoded, not yet verified Payment credential.
///
/// Deliberately carries no `Debug` and no `Display`: the payload holds a
/// single-use payment token. Tests that need to inspect a failure use an
/// `expect_error` helper rather than widening this type.
pub struct PaymentCredential {
    /// The challenge the client echoed back.
    pub challenge: PaymentChallenge,
    /// The pinned Stripe charge payload.
    pub payload: StripeChargePayload,
}

/// The wire form of a credential.
///
/// Unknown top-level members are ignored, as draft-01 requires. The
/// payload is the exception: it is a pinned schema.
#[derive(Deserialize)]
struct PaymentCredentialWire {
    challenge: PaymentChallenge,
    payload: StripeChargePayloadWire,
}

/// A credential that passed every local check.
///
/// Holding one of these means the bytes were well formed, the challenge
/// recomputed its own identifier under this proxy's binding key, it had
/// not expired, the method and intent were the offered pair, and the
/// body digest matched. It does not mean anything settled. The caller
/// reserves [`VerifiedCredential::proof`] in the durable store before
/// contacting a provider.
pub struct VerifiedCredential {
    /// The echoed challenge, now known to be one this proxy issued.
    pub challenge: PaymentChallenge,
    /// The decoded opaque routing state, when the challenge carried it.
    pub opaque: Option<ChallengeOpaque>,
    /// The pinned request object the challenge committed to.
    pub request: StripeChargeRequest,
    /// The verified payload.
    pub payload: StripeChargePayload,
    /// Replay-protection material derived from the whole credential.
    pub proof: PaymentProof,
}

// --- Binder ---

/// Issues and verifies challenges under one binding key.
///
/// The key never leaves this struct, is held in a zeroizing buffer, and
/// is not exposed by any accessor. The binder is pinned to one realm and
/// to the single registered method and intent pair, so a client cannot
/// negotiate its way onto a different profile.
pub struct ChallengeBinder {
    realm: String,
    method: String,
    intent: String,
    key: Zeroizing<Vec<u8>>,
}

impl ChallengeBinder {
    /// Builds a binder for one protection space.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::Internal`] when the realm is empty,
    /// carries a quote, a backslash, or the binding separator, or when
    /// the key is empty. All three would let a realm forge a parameter
    /// or collapse two binding inputs onto one MAC.
    pub fn new(realm: &str, key: &[u8]) -> Result<Self, PaymentAuthError> {
        if realm.is_empty()
            || realm.contains('"')
            || realm.contains('\\')
            || realm.contains('|')
            || key.is_empty()
        {
            return Err(PaymentAuthError::Internal);
        }
        Ok(Self {
            realm: realm.to_string(),
            method: METHOD_STRIPE.to_string(),
            intent: INTENT_CHARGE.to_string(),
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// Returns the protection space this binder issues under.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Returns the offered method token.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the offered intent token.
    #[must_use]
    pub fn intent(&self) -> &str {
        &self.intent
    }

    /// Issues one challenge for a priced obligation.
    ///
    /// `body` is the exact request body, already buffered and capped by
    /// the caller. A request with no body passes `None` and the
    /// challenge carries no `digest` slot.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::Internal`] when the request or
    /// opaque object cannot be canonicalized or the expiry is not
    /// representable, and [`PaymentAuthError::ChallengeTooLarge`] when
    /// the rendered field value would exceed [`MAX_CHALLENGE_BYTES`].
    pub fn issue(
        &self,
        request: &StripeChargeRequest,
        opaque: Option<&ChallengeOpaque>,
        body: Option<&[u8]>,
        expires_at_ms: i64,
    ) -> Result<PaymentChallenge, PaymentAuthError> {
        let request_slot = encode_jcs_base64url(request)?;
        let opaque_slot = match opaque {
            Some(value) => Some(encode_jcs_base64url(value)?),
            None => None,
        };
        let mut challenge = PaymentChallenge {
            id: String::new(),
            realm: self.realm.clone(),
            method: self.method.clone(),
            intent: self.intent.clone(),
            request: request_slot,
            expires: format_rfc3339_utc(expires_at_ms)?,
            digest: body.map(body_digest_sha256),
            opaque: opaque_slot,
        };
        challenge.id = URL_SAFE_NO_PAD.encode(self.tag(&challenge.binding_input()));
        // Rendering here rather than at response time so an oversized
        // challenge fails while there is still a caller to tell.
        challenge.to_header_value()?;
        Ok(challenge)
    }

    /// Checks that a challenge is one this binder issued.
    ///
    /// The identifier is recomputed from the challenge's own echoed
    /// slots and compared in constant time. Realm, method, and intent
    /// are checked separately so a mismatch is reported as an
    /// unsupported method rather than as a forged challenge.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::MethodUnsupported`] for a realm,
    /// method, or intent this binder does not offer, and
    /// [`PaymentAuthError::InvalidChallenge`] when the identifier does
    /// not recompute.
    pub fn verify_challenge(&self, challenge: &PaymentChallenge) -> Result<(), PaymentAuthError> {
        if challenge.realm != self.realm
            || challenge.method != self.method
            || challenge.intent != self.intent
        {
            return Err(PaymentAuthError::MethodUnsupported);
        }
        let presented = decode_base64url_strict(&challenge.id)
            .map_err(|_| PaymentAuthError::InvalidChallenge)?;
        let expected = self.tag(&challenge.binding_input());
        if !constant_time_eq(&presented, &expected) {
            return Err(PaymentAuthError::InvalidChallenge);
        }
        Ok(())
    }

    /// Decodes and fully checks one `Authorization` field value.
    ///
    /// The value is the complete field, including the `Payment ` scheme
    /// token. `body` is the exact buffered request body, or `None` for
    /// a request without one. `now_ms` is wall clock in milliseconds.
    ///
    /// The order is deliberate: shape, then binding, then expiry, then
    /// body, then payload. Every one of them runs on local material,
    /// before the caller performs any durable write and long before any
    /// provider is contacted.
    ///
    /// # Errors
    ///
    /// Returns the typed [`PaymentAuthError`] for the first check that
    /// fails. Nothing is coerced: an expired challenge is not renewed, a
    /// mismatched digest is not recomputed, and an unknown method is not
    /// mapped onto the offered one.
    pub fn verify_credential(
        &self,
        authorization_value: &str,
        body: Option<&[u8]>,
        now_ms: i64,
    ) -> Result<VerifiedCredential, PaymentAuthError> {
        let token = strip_payment_scheme(authorization_value)?;
        let credential = decode_credential(token)?;

        self.verify_challenge(&credential.challenge)?;

        if now_ms >= credential.challenge.expires_at_ms()? {
            return Err(PaymentAuthError::Expired);
        }

        match (credential.challenge.digest.as_deref(), body) {
            (Some(parameter), Some(bytes)) => verify_body_digest(bytes, parameter)?,
            // A request that carries a body must always be bound to it,
            // and a challenge that bound a body must be presented with
            // one. Either half alone is a challenge that does not
            // describe this request.
            (None, Some(_)) | (Some(_), None) => return Err(PaymentAuthError::InvalidChallenge),
            (None, None) => {}
        }

        let request = credential.challenge.decode_request()?;
        let opaque = credential.challenge.decode_opaque()?;
        let proof = PaymentProof::new(PAYMENT_SCHEME, token.to_string()).map_err(|_| {
            // The only way construction fails is an empty scheme or
            // an empty credential, both already rejected above.
            PaymentAuthError::MalformedCredential
        })?;

        Ok(VerifiedCredential {
            challenge: credential.challenge,
            opaque,
            request,
            payload: credential.payload,
            proof,
        })
    }

    /// Computes the MAC over one binding input.
    fn tag(&self, input: &str) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC-SHA256 accepts a key of any length");
        mac.update(input.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

/// Strips the `Payment ` scheme token from an `Authorization` value.
///
/// The scheme token is matched case insensitively, as HTTP requires,
/// but exactly one space must follow it and the remainder must be
/// non-empty and within [`MAX_CREDENTIAL_BYTES`].
///
/// # Errors
///
/// Returns [`PaymentAuthError::MalformedCredential`].
pub fn strip_payment_scheme(value: &str) -> Result<&str, PaymentAuthError> {
    if !has_payment_scheme(value) {
        return Err(PaymentAuthError::MalformedCredential);
    }
    // The byte at the scheme boundary is a space, so this index is a
    // character boundary and the slice cannot panic.
    let token = &value[PAYMENT_SCHEME.len() + 1..];
    if token.is_empty() || token.len() > MAX_CREDENTIAL_BYTES {
        return Err(PaymentAuthError::MalformedCredential);
    }
    Ok(token)
}

/// Whether a field value is framed as `Payment <token>`.
///
/// The scheme token is compared case insensitively, as HTTP requires,
/// and exactly one space must follow it. The comparison is over bytes so
/// a multi-byte character straddling the boundary cannot panic a slice.
fn has_payment_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > PAYMENT_SCHEME.len()
        && bytes[..PAYMENT_SCHEME.len()].eq_ignore_ascii_case(PAYMENT_SCHEME.as_bytes())
        && bytes[PAYMENT_SCHEME.len()] == b' '
}

/// Selects the one Payment credential from a request's `Authorization`
/// fields.
///
/// Exactly one is required. Zero is
/// [`PaymentAuthError::CredentialMissing`] and answered 402 with a fresh
/// challenge; two or more is [`PaymentAuthError::DuplicateCredential`]
/// and answered 400, because there is no safe way to choose which
/// payment the client meant.
///
/// Fields carrying another scheme are ignored, so a request that also
/// authenticates its caller is not broken by this rule.
///
/// # Errors
///
/// Returns [`PaymentAuthError::CredentialMissing`] or
/// [`PaymentAuthError::DuplicateCredential`].
pub fn select_payment_credential<'a, I>(values: I) -> Result<&'a str, PaymentAuthError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut selected: Option<&'a str> = None;
    for value in values {
        if !has_payment_scheme(value) {
            continue;
        }
        if selected.is_some() {
            return Err(PaymentAuthError::DuplicateCredential);
        }
        selected = Some(value);
    }
    selected.ok_or(PaymentAuthError::CredentialMissing)
}

/// Decodes a credential token into its typed halves.
///
/// # Errors
///
/// Returns [`PaymentAuthError::MalformedCredential`] for a value that is
/// not strict base64url of UTF-8 JSON matching the pinned shape, and for
/// a payload whose token is missing its required prefix or is oversized.
pub fn decode_credential(token: &str) -> Result<PaymentCredential, PaymentAuthError> {
    if token.len() > MAX_CREDENTIAL_BYTES {
        return Err(PaymentAuthError::MalformedCredential);
    }
    let bytes = decode_base64url_strict(token)?;
    if bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(PaymentAuthError::MalformedCredential);
    }
    let value = parse_strict_json(&bytes)?;
    let wire: PaymentCredentialWire =
        serde_json::from_value(value).map_err(|_| PaymentAuthError::MalformedCredential)?;

    if !wire.payload.spt.starts_with(SPT_PREFIX)
        || wire.payload.spt.len() <= SPT_PREFIX.len()
        || wire.payload.spt.len() > MAX_SPT_BYTES
    {
        return Err(PaymentAuthError::MalformedCredential);
    }
    if let Some(external) = wire.payload.external_id.as_deref() {
        if external.is_empty() || external.len() > MAX_EXTERNAL_ID_BYTES {
            return Err(PaymentAuthError::MalformedCredential);
        }
    }

    Ok(PaymentCredential {
        challenge: wire.challenge,
        payload: StripeChargePayload {
            spt: Zeroizing::new(wire.payload.spt),
            external_id: wire.payload.external_id,
        },
    })
}

// --- Receipt ---

/// The success receipt carried in `Payment-Receipt`.
///
/// It is emitted only on a paid 2xx. No error response ever carries one,
/// and no receipt is minted for a state other than a durable success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentAuthReceipt {
    /// The method that settled, lowercase.
    pub method: String,
    /// The provider's own reference, for example a PaymentIntent ID.
    pub reference: String,
    /// Fixed status token. Always `success`.
    pub status: String,
    /// RFC 3339 UTC instant of settlement.
    pub timestamp: String,
}

impl PaymentAuthReceipt {
    /// The only status token a receipt may carry.
    pub const STATUS_SUCCESS: &'static str = "success";

    /// Builds a success receipt from real provider-backed values.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::Internal`] when the method or the
    /// reference is empty, or the instant is not representable. An empty
    /// reference is the shape a fabricated receipt takes, so it fails
    /// here rather than reaching a client.
    pub fn success(
        method: &str,
        reference: &str,
        settled_at_ms: i64,
    ) -> Result<Self, PaymentAuthError> {
        if method.trim().is_empty() || reference.trim().is_empty() {
            return Err(PaymentAuthError::Internal);
        }
        Ok(Self {
            method: method.to_ascii_lowercase(),
            reference: reference.to_string(),
            status: Self::STATUS_SUCCESS.to_string(),
            timestamp: format_rfc3339_utc(settled_at_ms)?,
        })
    }

    /// Encodes the exact `Payment-Receipt` field value.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentAuthError::Internal`] when canonicalization
    /// fails.
    pub fn to_header_value(&self) -> Result<String, PaymentAuthError> {
        encode_jcs_base64url(self)
    }
}

// --- Accept-Payment preference ---

/// One parsed `Accept-Payment` preference.
///
/// Negotiation only. It carries no token, no PaymentIntent, no
/// signature, no quote, no address, no amount, and no credential, and it
/// authorizes nothing. All it does is choose which challenge is offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPreference {
    /// The requested method token, lowercase.
    pub method: String,
    /// The requested intent token, lowercase, when the client named one.
    pub intent: Option<String>,
    /// Quality value in thousandths, so ordering needs no float.
    pub quality: u16,
}

/// Parses an `Accept-Payment` field value.
///
/// The grammar is a comma separated list of `method` with an optional
/// `;intent=` and an optional `;q=`. A preference with a duplicate
/// `intent`, a duplicate `q`, an unknown parameter, an out of range
/// quality, or an empty method is dropped rather than failing the
/// request: this header is advisory, so a malformed entry must never be
/// the reason a payable request is refused.
///
/// The result is ordered by descending quality, preserving the client's
/// order within one quality.
#[must_use]
pub fn parse_accept_payment(value: &str) -> Vec<PaymentPreference> {
    let mut preferences: Vec<PaymentPreference> = Vec::new();
    for entry in value.split(',') {
        if let Some(preference) = parse_one_preference(entry) {
            preferences.push(preference);
        }
    }
    preferences.sort_by(|left, right| right.quality.cmp(&left.quality));
    preferences
}

/// Parses one comma separated `Accept-Payment` entry.
fn parse_one_preference(entry: &str) -> Option<PaymentPreference> {
    let mut parts = entry.split(';');
    let method = parts.next()?.trim().to_ascii_lowercase();
    if method.is_empty() || !is_token(&method) {
        return None;
    }
    let mut intent: Option<String> = None;
    let mut quality: Option<u16> = None;
    for part in parts {
        let (name, raw) = part.split_once('=')?;
        let raw = raw.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "intent" => {
                if intent.is_some() {
                    return None;
                }
                let value = raw.to_ascii_lowercase();
                if !is_token(&value) {
                    return None;
                }
                intent = Some(value);
            }
            "q" => {
                if quality.is_some() {
                    return None;
                }
                quality = Some(parse_quality(raw)?);
            }
            _ => return None,
        }
    }
    Some(PaymentPreference {
        method,
        intent,
        quality: quality.unwrap_or(1_000),
    })
}

/// Parses a quality value into thousandths.
fn parse_quality(raw: &str) -> Option<u16> {
    let (whole, fraction) = match raw.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (raw, ""),
    };
    if whole.is_empty() || fraction.len() > 3 || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let whole: u16 = whole.parse().ok()?;
    let mut padded = fraction.to_string();
    while padded.len() < 3 {
        padded.push('0');
    }
    let fraction: u16 = if padded.is_empty() {
        0
    } else {
        padded.parse().ok()?
    };
    let value = whole.checked_mul(1_000)?.checked_add(fraction)?;
    if value > 1_000 {
        return None;
    }
    Some(value)
}

/// Whether a string is a bounded HTTP token this parser accepts.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

// --- Transport policy ---

/// Refuses a Payment flow over cleartext.
///
/// `allow_loopback_cleartext` exists for the deterministic local test
/// fixtures only and is never set from a configuration document. A
/// cleartext flow to any non-loopback authority is refused regardless.
///
/// # Errors
///
/// Returns [`PaymentAuthError::InsecureTransport`].
pub fn require_secure_transport(
    is_tls: bool,
    host: &str,
    allow_loopback_cleartext: bool,
) -> Result<(), PaymentAuthError> {
    if is_tls {
        return Ok(());
    }
    if allow_loopback_cleartext && is_loopback_authority(host) {
        return Ok(());
    }
    Err(PaymentAuthError::InsecureTransport)
}

/// Whether an authority names the loopback interface.
fn is_loopback_authority(authority: &str) -> bool {
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(authority),
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

// --- Body digest ---

/// Refuses a body larger than the configured payment cap.
///
/// The payment path must hash the exact request bytes, so this check
/// runs before a challenge is issued and before any provider work.
///
/// # Errors
///
/// Returns [`PaymentAuthError::BodyTooLarge`].
pub fn check_body_within_cap(length: u64, max_body_bytes: u64) -> Result<(), PaymentAuthError> {
    if length > max_body_bytes {
        return Err(PaymentAuthError::BodyTooLarge);
    }
    Ok(())
}

/// Computes the RFC 9530 `sha-256` digest parameter over exact bytes.
///
/// The value is the structured-field byte sequence form:
/// `sha-256=:BASE64:` with standard base64 including padding, which is
/// what RFC 9530 specifies. Note that this is the one place in this
/// module that is not base64url.
#[must_use]
pub fn body_digest_sha256(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

/// Recomputes a body digest and compares it in constant time.
///
/// # Errors
///
/// Returns [`PaymentAuthError::InvalidChallenge`] when the parameter
/// does not describe these exact bytes. The digest is never recomputed
/// into the challenge: a mismatch means the challenge belongs to a
/// different request.
pub fn verify_body_digest(body: &[u8], parameter: &str) -> Result<(), PaymentAuthError> {
    let expected = body_digest_sha256(body);
    if constant_time_eq(expected.as_bytes(), parameter.as_bytes()) {
        Ok(())
    } else {
        Err(PaymentAuthError::InvalidChallenge)
    }
}

// --- Encoding helpers ---

/// JCS serializes a value and encodes it as unpadded base64url.
///
/// # Errors
///
/// Returns [`PaymentAuthError::Internal`] when the value cannot be
/// canonicalized.
pub fn encode_jcs_base64url<T: Serialize>(value: &T) -> Result<String, PaymentAuthError> {
    let canonical =
        serde_json_canonicalizer::to_vec(value).map_err(|_| PaymentAuthError::Internal)?;
    Ok(URL_SAFE_NO_PAD.encode(canonical))
}

/// Decodes an unpadded base64url slot, refusing every near miss.
///
/// Padding, the standard alphabet's `+` and `/`, whitespace, and an
/// empty value are all rejected rather than repaired.
///
/// # Errors
///
/// Returns [`PaymentAuthError::MalformedCredential`].
pub fn decode_base64url_strict(value: &str) -> Result<Vec<u8>, PaymentAuthError> {
    if value.is_empty() {
        return Err(PaymentAuthError::MalformedCredential);
    }
    let acceptable = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !acceptable {
        return Err(PaymentAuthError::MalformedCredential);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PaymentAuthError::MalformedCredential)
}

/// Parses JSON with duplicate keys and deep nesting refused.
///
/// # Errors
///
/// Returns [`PaymentAuthError::MalformedCredential`] for invalid UTF-8,
/// invalid JSON, a duplicate object key, or nesting past
/// [`MAX_JSON_DEPTH`].
pub fn parse_strict_json(bytes: &[u8]) -> Result<serde_json::Value, PaymentAuthError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PaymentAuthError::MalformedCredential)?;
    let StrictJson(value) =
        serde_json::from_str(text).map_err(|_| PaymentAuthError::MalformedCredential)?;
    if json_depth(&value) > MAX_JSON_DEPTH {
        return Err(PaymentAuthError::MalformedCredential);
    }
    Ok(value)
}

/// Returns the nesting depth of a parsed JSON value.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// A JSON value parsed with duplicate object keys refused.
///
/// `serde_json` keeps the last value for a repeated key. That is a
/// silent reinterpretation of an attacker-supplied document, so this
/// wrapper refuses it instead.
struct StrictJson(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

/// Visitor behind [`StrictJson`].
struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value whose objects have unique keys")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Null))
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::from(value)))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::String(value.to_string())))
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(StrictJson(item)) = access.next_element()? {
            items.push(item);
        }
        Ok(StrictJson(serde_json::Value::Array(items)))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let StrictJson(value) = access.next_value()?;
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            object.insert(key, value);
        }
        Ok(StrictJson(serde_json::Value::Object(object)))
    }
}

/// Compares two byte strings without an early exit on content.
///
/// Lengths are compared first, which is not secret: every value this
/// module compares has a fixed or client-visible length.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

// --- Time ---

/// Parses the exact `YYYY-MM-DDTHH:MM:SSZ` form into epoch
/// milliseconds.
///
/// Only this one spelling is accepted. Offsets, fractional seconds,
/// lowercase separators, and leap seconds are refused, because the
/// instant is a slot in a MAC input and two spellings of one instant
/// would be two different challenges.
///
/// # Errors
///
/// Returns [`PaymentAuthError::MalformedCredential`].
pub fn parse_rfc3339_utc(value: &str) -> Result<i64, PaymentAuthError> {
    let bytes = value.as_bytes();
    if bytes.len() != RFC3339_UTC_LEN
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(PaymentAuthError::MalformedCredential);
    }
    let field = |start: usize, end: usize| -> Result<i64, PaymentAuthError> {
        let text = &value[start..end];
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PaymentAuthError::MalformedCredential);
        }
        text.parse::<i64>()
            .map_err(|_| PaymentAuthError::MalformedCredential)
    };
    let year = field(0, 4)?;
    let month = field(5, 7)?;
    let day = field(8, 10)?;
    let hour = field(11, 13)?;
    let minute = field(14, 16)?;
    let second = field(17, 19)?;

    if !(1..=12).contains(&month)
        || day < 1
        || day > i64::from(days_in_month(year, month as u32))
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(PaymentAuthError::MalformedCredential);
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    seconds
        .checked_mul(1_000)
        .ok_or(PaymentAuthError::MalformedCredential)
}

/// Renders epoch milliseconds as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Sub-second precision is truncated deliberately: the wire format
/// carries whole seconds, so keeping milliseconds would produce an
/// instant that does not round-trip through its own MAC input.
///
/// # Errors
///
/// Returns [`PaymentAuthError::MalformedCredential`] for an instant
/// outside the four-digit year range this format can express.
pub fn format_rfc3339_utc(epoch_ms: i64) -> Result<String, PaymentAuthError> {
    let seconds = epoch_ms.div_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let remainder = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return Err(PaymentAuthError::MalformedCredential);
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60,
    ))
}

/// Days since the Unix epoch for a proleptic Gregorian civil date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era_numerator = if year >= 0 { year } else { year - 399 };
    let era = era_numerator / 400;
    let year_of_era = year - era * 400;
    let shifted = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * shifted + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian civil date for days since the Unix epoch.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era_numerator = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    };
    let era = era_numerator / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month_number = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    };
    let month = month_number as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Days in one civil month.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Whether a proleptic Gregorian year is a leap year.
const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unwrap_err` requires `Debug` on the success type, and several
    /// types here deliberately do not carry one because they hold a
    /// single-use payment token. Tests unwrap errors through this
    /// helper rather than widening a derive to suit a test.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn instants_round_trip_through_the_wire_format() {
        for text in [
            "1970-01-01T00:00:00Z",
            "2026-07-29T20:05:00Z",
            "2024-02-29T23:59:59Z",
            "2100-03-01T12:00:00Z",
        ] {
            let parsed = parse_rfc3339_utc(text).expect("a valid instant parses");
            assert_eq!(format_rfc3339_utc(parsed).unwrap(), text);
        }
    }

    #[test]
    fn instant_parser_refuses_every_near_miss() {
        for text in [
            "2026-07-29T20:05:00",
            "2026-07-29T20:05:00+00:00",
            "2026-07-29T20:05:00.000Z",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2026-07-29t20:05:00Z",
            "2026-07-29T24:00:00Z",
            "",
        ] {
            assert_eq!(
                expect_error(
                    parse_rfc3339_utc(text),
                    "a malformed instant must be refused"
                ),
                PaymentAuthError::MalformedCredential,
                "expected {text} to be refused"
            );
        }
    }

    #[test]
    fn base64url_slots_refuse_padding_and_the_standard_alphabet() {
        assert!(decode_base64url_strict("aGVsbG8").is_ok());
        for bad in ["aGVsbG8=", "a+b/c", "aGVsbG8 ", "", "!!!!"] {
            assert_eq!(
                expect_error(
                    decode_base64url_strict(bad),
                    "a non base64url slot must be refused"
                ),
                PaymentAuthError::MalformedCredential,
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn strict_json_refuses_duplicate_keys_and_deep_nesting() {
        assert!(parse_strict_json(br#"{"a":1,"b":2}"#).is_ok());
        assert_eq!(
            expect_error(
                parse_strict_json(br#"{"a":1,"a":2}"#),
                "a duplicate key must be refused"
            ),
            PaymentAuthError::MalformedCredential
        );
        assert_eq!(
            expect_error(
                parse_strict_json(&[0xff, 0xfe]),
                "invalid UTF-8 must be refused"
            ),
            PaymentAuthError::MalformedCredential
        );
        let deep = "[".repeat(MAX_JSON_DEPTH + 2) + &"]".repeat(MAX_JSON_DEPTH + 2);
        assert_eq!(
            expect_error(
                parse_strict_json(deep.as_bytes()),
                "excessive nesting must be refused"
            ),
            PaymentAuthError::MalformedCredential
        );
    }

    #[test]
    fn the_credential_cap_covers_the_draft_minimum() {
        assert!(MAX_CREDENTIAL_BYTES >= MIN_SUPPORTED_CREDENTIAL_BYTES);
    }

    #[test]
    fn accept_payment_is_ordered_and_drops_malformed_entries() {
        let parsed = parse_accept_payment("stripe;intent=charge;q=1.0, x402;q=0.5");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].method, "stripe");
        assert_eq!(parsed[0].intent.as_deref(), Some("charge"));
        assert_eq!(parsed[0].quality, 1_000);
        assert_eq!(parsed[1].method, "x402");
        assert_eq!(parsed[1].quality, 500);

        // A duplicate parameter, an unknown parameter, and an out of
        // range quality each invalidate only their own preference.
        let parsed = parse_accept_payment(
            "stripe;intent=charge;intent=charge, stripe;q=2, stripe;spt=secret, lightning;q=0.25",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].method, "lightning");
        assert_eq!(parsed[0].quality, 250);
    }

    #[test]
    fn transport_policy_refuses_cleartext_off_loopback() {
        assert!(require_secure_transport(true, "api.example.com", false).is_ok());
        assert!(require_secure_transport(false, "127.0.0.1:8080", true).is_ok());
        assert_eq!(
            expect_error(
                require_secure_transport(false, "api.example.com", true),
                "cleartext off loopback must be refused"
            ),
            PaymentAuthError::InsecureTransport
        );
        assert_eq!(
            expect_error(
                require_secure_transport(false, "127.0.0.1", false),
                "cleartext must be refused without the test-only opt in"
            ),
            PaymentAuthError::InsecureTransport
        );
    }

    #[test]
    fn problem_statuses_match_the_registered_table() {
        for (code, status) in [
            (PaymentAuthProblemCode::PaymentRequired, 402),
            (PaymentAuthProblemCode::PaymentInsufficient, 402),
            (PaymentAuthProblemCode::PaymentExpired, 402),
            (PaymentAuthProblemCode::VerificationFailed, 402),
            (PaymentAuthProblemCode::MethodUnsupported, 400),
            (PaymentAuthProblemCode::MalformedCredential, 402),
            (PaymentAuthProblemCode::InvalidChallenge, 402),
        ] {
            assert_eq!(code.registered_status(), status, "{code}");
            assert_eq!(
                code.type_uri(),
                format!("https://paymentauth.org/problems/{code}")
            );
        }
    }

    #[test]
    fn two_credentials_are_a_bad_request_not_a_payment_problem() {
        let error = expect_error(
            select_payment_credential(["Payment aaa", "Payment bbb"]),
            "two payment credentials must be refused",
        );
        assert_eq!(error, PaymentAuthError::DuplicateCredential);
        assert_eq!(error.status(), 400);
        assert!(!error.offers_fresh_challenge());
        // The registered code keeps its registered status even though
        // this particular refusal answers 400.
        assert_eq!(
            error
                .problem_code()
                .map(PaymentAuthProblemCode::registered_status),
            Some(402)
        );
    }

    #[test]
    fn a_bearer_field_beside_a_payment_field_is_not_a_duplicate() {
        let selected = select_payment_credential(["Bearer abc", "Payment xyz"])
            .expect("one payment credential is selected");
        assert_eq!(selected, "Payment xyz");
    }

    #[test]
    fn body_cap_is_refused_before_any_challenge_work() {
        assert!(check_body_within_cap(1_024, 1_024).is_ok());
        let error = expect_error(
            check_body_within_cap(1_025, 1_024),
            "an oversized body must be refused",
        );
        assert_eq!(error, PaymentAuthError::BodyTooLarge);
        assert_eq!(error.status(), 413);
        assert!(error.problem_document().is_none());
    }
}
