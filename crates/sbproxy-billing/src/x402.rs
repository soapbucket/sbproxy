//! x402 v2 `exact`: synchronous, authoritative settlement.
//!
//! This is the one rail whose authorization happens entirely on the
//! request path, so it is the one rail that has to carry a hard
//! deadline, a circuit breaker, and fail-closed behavior on every
//! ambiguous outcome.
//!
//! # The shape of one authorization
//!
//! 1. Decode the envelope and validate every local binding. The echoed
//!    `accepted` object, resource, and `sbproxy-requirement` extension
//!    must equal the ones the proxy signed, byte for byte, before a
//!    facilitator is contacted.
//! 2. Call `verify` on the facilitator the signed requirement selected.
//! 3. Require `isValid = true`. A rejection stops here: no settle
//!    attempt is prepared and no settle request is sent.
//! 4. Commit the durable dispatch stamp through [`SettleDispatchGate`].
//! 5. Call `settle` on the same facilitator.
//! 6. Require a 2xx status, then `success = true`, a non-empty
//!    transaction, the exact network, agreeing payer values when both
//!    responses carry them, and the exact amount whenever the settlement
//!    response states one.
//! 7. Only then does the caller commit `Succeeded` and let the request
//!    reach the origin.
//!
//! Steps 2 through 6 run inside one [`tokio::time::timeout`] whose
//! configured maximum is [`MAX_TOTAL_DEADLINE_MS`].
//!
//! # Three answers, not two
//!
//! A settle has three outcomes, and the middle one is the whole reason
//! this rail has a dispatch gate:
//!
//! - **Accepted.** A 2xx whose body is the pinned shape saying
//!   `success = true`, with a transaction and matching terms.
//! - **Refused.** A 2xx whose body is the pinned shape saying
//!   `success = false`. The facilitator answered, in its own protocol,
//!   that no funds moved. This is the only answer that concludes the
//!   dispatch, closes the attempt `Terminal`, and bills the payer
//!   nothing.
//! - **Unknown.** Everything else: a 5xx, a 4xx, a timeout, a dropped
//!   connection, a body that does not parse, an oversized body, a 2xx
//!   with `success` absent, or a 2xx success whose transaction, network,
//!   amount, or payer does not hold up. All of it is
//!   [`BillingError::NeedsReconciliation`].
//!
//! The status is read before the body, because the two failure
//! directions are not symmetric. Calling an unknown outcome a refusal
//! tells the payer their payment was declined and closes the record,
//! while the facilitator may have broadcast the settlement: the money is
//! gone, the service was not rendered, and nothing is left on the
//! reconciliation queue to ever ask about it. Calling a genuine refusal
//! unknown costs one row on that queue and a 503 instead of a 402. On a
//! rail whose status query is [`X402QueryResult::Unsupported`] that row
//! is an operator's work, which is the price this module pays
//! deliberately rather than closing a live payment on a guess.
//!
//! # What this adapter will not do
//!
//! - It never constructs a path other than `/verify` and `/settle`
//!   under the configured API root. There is no `/status`, no `/reorg`,
//!   and no guessed endpoint, because x402 v2 at the pinned revision
//!   publishes none.
//! - It never tries a second facilitator after a settle has been
//!   dispatched. Ordered fallback happens only by issuing a fresh
//!   challenge, before any settlement dispatch exists.
//! - It never retries a settle automatically. An ambiguous settle
//!   becomes [`BillingError::NeedsReconciliation`] and stays there
//!   until an operator resolves it.
//! - It never synthesizes a transaction, a payer, or a receipt. A
//!   response that does not state an authoritative success is ambiguous,
//!   not a success.
//!
//! # Chain reorganization
//!
//! A settled transaction can be reorganized out of a chain. x402 v2 at
//! the pinned revision defines no status or reorg query, so this
//! release does not pretend to detect one: [`X402ExactSettler::query_attempt`]
//! answers [`X402QueryResult::Unsupported`] and the record stays in
//! reconciliation. A reorg feed can be added later only as a separately
//! configured, versioned extension with its own contract fixture. What
//! this release will not do is guess an endpoint, poll a chain
//! explorer, or silently downgrade a committed `Succeeded`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::BillingError;
use crate::lifecycle::{PaymentLifecycleDecision, PaymentLifecycleOutcome, PaymentLifecyclePhase};
use crate::types::{PaymentProof, SettlementRail, SettlementReceipt};

/// The protocol version this adapter speaks. Never negotiated.
pub const X402_VERSION: u8 = 2;

/// The only scheme this release implements.
pub const X402_SCHEME_EXACT: &str = "exact";

/// The 402 header carrying the payment requirements.
pub const PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";

/// The retry header carrying the signed payment payload.
pub const PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";

/// The success header carrying the exact settle response.
pub const PAYMENT_RESPONSE_HEADER: &str = "PAYMENT-RESPONSE";

/// The one SBProxy extension key in the x402 envelope.
pub const REQUIREMENT_EXTENSION_KEY: &str = "sbproxy-requirement";

/// Hard ceiling on the total request-path deadline, in milliseconds.
pub const MAX_TOTAL_DEADLINE_MS: u64 = 2_000;

/// Largest facilitator response body this adapter will read, in bytes.
pub const MAX_FACILITATOR_RESPONSE_BYTES: usize = 64 * 1024;

/// Largest encoded x402 header value this adapter will decode, in bytes.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Deepest JSON nesting accepted in an x402 envelope.
pub const MAX_JSON_DEPTH: usize = 16;

/// The `verify` endpoint suffix. The only path this adapter appends.
const VERIFY_SUFFIX: &str = "/verify";

/// The `settle` endpoint suffix. The only other path this adapter
/// appends.
const SETTLE_SUFFIX: &str = "/settle";

/// The checked-in JSON Schema for the `sbproxy-requirement` extension.
///
/// Draft 2020-12. The client echoes this object unchanged, and
/// `tests/fixtures/x402/sbproxy-requirement.schema.json` gates these
/// bytes so the wire schema and the checked-in fixture cannot drift.
pub const REQUIREMENT_EXTENSION_SCHEMA: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"id":{"pattern":"^[A-Za-z0-9_-]{16,128}$","type":"string"},"quote":{"maxLength":4096,"minLength":1,"type":"string"}},"required":["id","quote"],"title":"sbproxy-requirement","type":"object"}"#;

/// Smallest accepted requirement identifier length.
const REQUIREMENT_ID_MIN: usize = 16;

/// Largest accepted requirement identifier length.
const REQUIREMENT_ID_MAX: usize = 128;

/// Largest accepted quote token length.
const QUOTE_MAX: usize = 4_096;

// --- Errors ---

/// Everything this adapter refuses locally, before or instead of a
/// facilitator call.
///
/// No variant carries a payer address, a signature, a scheme payload, or
/// a facilitator response body. Every message is a fixed string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum X402Error {
    /// The configured facilitator API root is unusable.
    #[error("x402 facilitator API root is not a usable https root")]
    FacilitatorUrl,

    /// A header value was not standard base64 with canonical padding.
    #[error("x402 header value is not standard base64")]
    HeaderEncoding,

    /// A header value or response body exceeded its size bound.
    #[error("x402 payload exceeds its size bound")]
    TooLarge,

    /// A document did not parse as the pinned v2 shape.
    #[error("x402 payload does not match the pinned v2 contract")]
    Malformed,

    /// The envelope declared a protocol version this build does not
    /// speak.
    #[error("x402 payload declares an unsupported protocol version")]
    UnsupportedVersion,

    /// The echoed requirement, resource, or extension differs from the
    /// one the proxy signed.
    #[error("x402 payload does not echo the signed requirement")]
    RequirementMismatch,

    /// The `sbproxy-requirement` extension values are outside the
    /// schema this proxy publishes for them.
    #[error("x402 requirement extension is outside its published schema")]
    ExtensionInvalid,
}

impl From<X402Error> for BillingError {
    fn from(error: X402Error) -> Self {
        match error {
            X402Error::FacilitatorUrl => Self::InvalidRequirement("facilitator_url"),
            X402Error::RequirementMismatch | X402Error::ExtensionInvalid => {
                Self::RequirementMismatch
            }
            X402Error::HeaderEncoding
            | X402Error::TooLarge
            | X402Error::Malformed
            | X402Error::UnsupportedVersion => Self::ProviderMalformed,
        }
    }
}

// --- Endpoints ---

/// The two endpoints one facilitator serves.
///
/// The configured value is the facilitator's complete API root, not a
/// host. Every configured path segment is preserved, only trailing
/// slashes are removed, and exactly one of `/verify` or `/settle` is
/// appended. No version segment, no protocol segment, and nothing else
/// is ever injected, so a facilitator that serves its API under
/// `/base/` gets `/base/verify` and `/base/settle` and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacilitatorEndpoints {
    root: String,
    verify: String,
    settle: String,
}

impl FacilitatorEndpoints {
    /// Normalizes a configured API root into its two endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::FacilitatorUrl`] for a non-HTTPS scheme,
    /// userinfo, a query, a fragment, an empty or dot path segment, or
    /// a root that already names an endpoint. Each of those would
    /// either leak a credential into a signed requirement or produce a
    /// path no facilitator serves, and a paid request is the worst
    /// possible place to discover either.
    pub fn from_api_root(root: &str) -> Result<Self, X402Error> {
        Self::normalize(root, false)
    }

    /// Builds endpoints for a cleartext loopback fixture.
    ///
    /// Test-only. Nothing reachable from a configuration document calls
    /// this: `proxy.payments.rails.x402.facilitators[].facilitator_url`
    /// rejects a non-HTTPS scheme at load.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::FacilitatorUrl`] under the same rules as
    /// [`Self::from_api_root`], except that an `http://` loopback
    /// authority is accepted.
    pub fn loopback_http_for_test(root: &str) -> Result<Self, X402Error> {
        Self::normalize(root, true)
    }

    /// Shared normalization for both constructors.
    fn normalize(root: &str, allow_loopback_http: bool) -> Result<Self, X402Error> {
        let trimmed = root.trim();
        if trimmed.is_empty()
            || trimmed.len() > 1_024
            || trimmed.chars().any(char::is_control)
            || trimmed.contains('?')
            || trimmed.contains('#')
        {
            return Err(X402Error::FacilitatorUrl);
        }

        let rest = match trimmed.strip_prefix("https://") {
            Some(rest) => rest,
            None => {
                let rest = trimmed
                    .strip_prefix("http://")
                    .ok_or(X402Error::FacilitatorUrl)?;
                let authority_end = rest.find('/').unwrap_or(rest.len());
                if !allow_loopback_http || !is_loopback_authority(&rest[..authority_end]) {
                    return Err(X402Error::FacilitatorUrl);
                }
                rest
            }
        };

        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return Err(X402Error::FacilitatorUrl);
        }

        let path = rest[authority_end..].trim_end_matches('/');
        if path.contains("//")
            || path
                .split('/')
                .any(|segment| segment == "." || segment == "..")
        {
            return Err(X402Error::FacilitatorUrl);
        }
        if path.ends_with(VERIFY_SUFFIX) || path.ends_with(SETTLE_SUFFIX) {
            return Err(X402Error::FacilitatorUrl);
        }

        let scheme = if trimmed.starts_with("https://") {
            "https://"
        } else {
            "http://"
        };
        let root = format!("{scheme}{authority}{path}");
        Ok(Self {
            verify: format!("{root}{VERIFY_SUFFIX}"),
            settle: format!("{root}{SETTLE_SUFFIX}"),
            root,
        })
    }

    /// Returns the normalized API root.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Returns the `verify` endpoint.
    #[must_use]
    pub fn verify_url(&self) -> &str {
        &self.verify
    }

    /// Returns the `settle` endpoint.
    #[must_use]
    pub fn settle_url(&self) -> &str {
        &self.settle
    }
}

/// Whether an authority names the loopback interface.
fn is_loopback_authority(authority: &str) -> bool {
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(authority),
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// An ordered set of facilitator candidates with their breakers.
///
/// Selection happens at challenge time and only at challenge time. The
/// selected root is written into the signed requirement, and the
/// credential retry uses exactly that one, because trying a second
/// facilitator after a settle has been dispatched is how one payment
/// becomes two.
pub struct FacilitatorPool {
    entries: Vec<FacilitatorEntry>,
}

/// One candidate and the breaker guarding it.
pub struct FacilitatorEntry {
    /// The candidate's normalized endpoints.
    pub endpoints: FacilitatorEndpoints,
    /// The breaker guarding this candidate.
    pub breaker: FacilitatorBreaker,
}

impl FacilitatorPool {
    /// Builds a pool from ordered candidates.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::FacilitatorUrl`] when the list is empty.
    pub fn new(entries: Vec<FacilitatorEntry>) -> Result<Self, X402Error> {
        if entries.is_empty() {
            return Err(X402Error::FacilitatorUrl);
        }
        Ok(Self { entries })
    }

    /// Picks the first candidate whose breaker is not open.
    ///
    /// Returns `None` when every candidate's breaker is open, which is a
    /// 503 with no challenge rather than a challenge nobody can redeem.
    /// Selection reads the breaker without claiming its half-open probe:
    /// the probe belongs to the call that actually happens, not to the
    /// challenge that might be redeemed minutes later.
    #[must_use]
    pub fn select_for_challenge(&self, now_ms: i64) -> Option<&FacilitatorEntry> {
        self.entries
            .iter()
            .find(|entry| !entry.breaker.is_open(now_ms))
    }

    /// Finds the candidate a signed requirement selected.
    ///
    /// The retry path uses this and never falls through to another
    /// candidate: a requirement is bound to the facilitator it named.
    #[must_use]
    pub fn entry_for_root(&self, root: &str) -> Option<&FacilitatorEntry> {
        self.entries
            .iter()
            .find(|entry| entry.endpoints.root() == root)
    }

    /// Returns every candidate, in configured order.
    #[must_use]
    pub fn entries(&self) -> &[FacilitatorEntry] {
        &self.entries
    }
}

// --- Breaker ---

/// What the breaker allows right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerVerdict {
    /// Normal operation.
    Closed,
    /// The single half-open probe was granted to this caller.
    HalfOpenProbe,
    /// The breaker is open and no call may be made.
    Open,
}

/// A bounded circuit breaker around one facilitator.
///
/// Only transport-level failures move it: a connection error, a
/// timeout, or a 5xx. An authoritative `isValid = false` or
/// `success = false` is the facilitator working correctly and never
/// opens the breaker.
///
/// `half_open_max` is 1 by configuration. A second concurrent probe
/// against a facilitator that is still unhealthy can dispatch a settle
/// whose response nobody is waiting to record, which is the one outcome
/// the state machine cannot resolve without a human.
pub struct FacilitatorBreaker {
    failure_threshold: u32,
    open_ms: i64,
    half_open_max: u32,
    state: Mutex<BreakerState>,
}

/// Mutable breaker bookkeeping.
#[derive(Debug, Default)]
struct BreakerState {
    consecutive_failures: u32,
    opened_at_ms: Option<i64>,
    probes_in_flight: u32,
}

impl FacilitatorBreaker {
    /// Builds a breaker.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::FacilitatorUrl`] for a zero threshold, an
    /// open window outside 100 through 60,000 milliseconds, or a
    /// half-open budget other than 1. The configuration crate enforces
    /// the same bounds at load; this is the runtime backstop.
    pub fn new(
        failure_threshold: u32,
        open_ms: u64,
        half_open_max: u32,
    ) -> Result<Self, X402Error> {
        if failure_threshold == 0 || !(100..=60_000).contains(&open_ms) || half_open_max != 1 {
            return Err(X402Error::FacilitatorUrl);
        }
        Ok(Self {
            failure_threshold,
            open_ms: open_ms as i64,
            half_open_max,
            state: Mutex::new(BreakerState::default()),
        })
    }

    /// Reports whether the breaker is currently refusing calls.
    ///
    /// Unlike [`Self::admit`] this claims nothing, so it is safe to ask
    /// from a selection path that may not go on to make a call.
    ///
    /// Private on purpose: the only caller is the candidate filter in
    /// this file, and a `pub` predicate nothing outside names is what
    /// the pub-item ratchet exists to catch.
    #[must_use]
    fn is_open(&self, now_ms: i64) -> bool {
        let state = self.lock();
        match state.opened_at_ms {
            None => false,
            Some(opened_at) => {
                now_ms.saturating_sub(opened_at) < self.open_ms
                    || state.probes_in_flight >= self.half_open_max
            }
        }
    }

    /// Asks whether a call may be made, and claims the half-open probe
    /// when one is available.
    #[must_use]
    pub fn admit(&self, now_ms: i64) -> BreakerVerdict {
        let mut state = self.lock();
        match state.opened_at_ms {
            None => BreakerVerdict::Closed,
            Some(opened_at) if now_ms.saturating_sub(opened_at) < self.open_ms => {
                BreakerVerdict::Open
            }
            Some(_) => {
                if state.probes_in_flight < self.half_open_max {
                    state.probes_in_flight += 1;
                    BreakerVerdict::HalfOpenProbe
                } else {
                    BreakerVerdict::Open
                }
            }
        }
    }

    /// Records a transport-level failure.
    pub fn record_transport_failure(&self, now_ms: i64) {
        let mut state = self.lock();
        if state.opened_at_ms.is_some() {
            // A failed half-open probe re-opens for a fresh window.
            state.opened_at_ms = Some(now_ms);
            state.probes_in_flight = 0;
            return;
        }
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.failure_threshold {
            state.opened_at_ms = Some(now_ms);
            state.probes_in_flight = 0;
        }
    }

    /// Records a completed call that reached the facilitator.
    pub fn record_success(&self) {
        let mut state = self.lock();
        state.consecutive_failures = 0;
        state.opened_at_ms = None;
        state.probes_in_flight = 0;
    }

    /// Locks the state, recovering from a poisoned mutex.
    ///
    /// A panic while a breaker lock is held would otherwise wedge the
    /// rail closed forever; the state it guards is three counters, and
    /// the conservative reading of a torn update is the one the caller
    /// already handles.
    fn lock(&self) -> std::sync::MutexGuard<'_, BreakerState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// --- Wire contract ---

/// The resource a challenge prices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDescriptor {
    /// Absolute URL of the priced resource.
    pub url: String,
    /// Human readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Media type the resource returns.
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Service name shown to a payer.
    #[serde(
        default,
        rename = "serviceName",
        skip_serializing_if = "Option::is_none"
    )]
    pub service_name: Option<String>,
    /// Free-form tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Icon URL shown to a payer.
    #[serde(default, rename = "iconUrl", skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// One `accepts` entry: the exact obligation a payer signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentRequirementsObject {
    /// Always [`X402_SCHEME_EXACT`] in this release.
    pub scheme: String,
    /// CAIP-2 chain identifier.
    pub network: String,
    /// Amount in the asset's atomic units, as a decimal string.
    pub amount: String,
    /// Asset contract address or identifier.
    pub asset: String,
    /// Recipient address.
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// The scheme's advertised maximum timeout, in seconds.
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u32,
    /// Scheme-specific extra fields, passed through verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, serde_json::Value>>,
}

/// The `info` half of the `sbproxy-requirement` extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementExtensionInfo {
    /// The durable requirement identifier.
    pub id: String,
    /// The signed quote token that binds the requirement digest.
    pub quote: String,
}

/// The one SBProxy extension carried in an x402 envelope.
///
/// It is a normal, declared extension with a published schema, not an
/// undocumented top-level field bolted onto the facilitator request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementExtension {
    /// The values the client echoes.
    pub info: RequirementExtensionInfo,
    /// The published schema those values conform to.
    pub schema: serde_json::Value,
}

impl RequirementExtension {
    /// Builds the extension for one signed requirement.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::ExtensionInvalid`] when the identifier is
    /// outside the published pattern or the quote is empty or oversized,
    /// and [`X402Error::Malformed`] when the published schema constant
    /// does not parse, which would be this crate's own bug.
    pub fn new(id: &str, quote: &str) -> Result<Self, X402Error> {
        if !(REQUIREMENT_ID_MIN..=REQUIREMENT_ID_MAX).contains(&id.len())
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(X402Error::ExtensionInvalid);
        }
        if quote.is_empty() || quote.len() > QUOTE_MAX {
            return Err(X402Error::ExtensionInvalid);
        }
        let schema: serde_json::Value =
            serde_json::from_str(REQUIREMENT_EXTENSION_SCHEMA).map_err(|_| X402Error::Malformed)?;
        Ok(Self {
            info: RequirementExtensionInfo {
                id: id.to_string(),
                quote: quote.to_string(),
            },
            schema,
        })
    }

    /// Renders the single-entry `extensions` map for an envelope.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::Malformed`] when the extension cannot be
    /// serialized.
    pub fn to_extensions_map(&self) -> Result<BTreeMap<String, serde_json::Value>, X402Error> {
        let value = serde_json::to_value(self).map_err(|_| X402Error::Malformed)?;
        Ok([(REQUIREMENT_EXTENSION_KEY.to_string(), value)]
            .into_iter()
            .collect())
    }
}

/// The 402 body and `PAYMENT-REQUIRED` header payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentRequired {
    /// Always [`X402_VERSION`].
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    /// Optional non-secret reason a previous attempt failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The priced resource.
    pub resource: ResourceDescriptor,
    /// The obligations a payer may choose between.
    pub accepts: Vec<PaymentRequirementsObject>,
    /// The `sbproxy-requirement` extension.
    pub extensions: BTreeMap<String, serde_json::Value>,
}

/// The `PAYMENT-SIGNATURE` payload a client returns.
///
/// Deliberately carries no `Debug`: `payload` is the payer's signed
/// object and carries payer identifiers and a signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentPayload {
    /// Always [`X402_VERSION`].
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    /// The exact challenged resource.
    pub resource: ResourceDescriptor,
    /// The exact selected obligation.
    pub accepted: PaymentRequirementsObject,
    /// The scheme-specific signed object. Opaque to this adapter.
    pub payload: serde_json::Value,
    /// The exact echoed extension map.
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl PaymentPayload {
    /// Derives replay-protection material from the scheme payload.
    ///
    /// The digest is over the canonical form of the opaque signed
    /// object. This is a local identity for the credential, not a
    /// verification of it: proving that the signature is good is the
    /// facilitator's job and this adapter does not pretend to do it.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Canonical`] when the payload cannot be
    /// canonicalized and [`BillingError::InvalidProof`] when it is
    /// empty.
    pub fn proof(&self) -> Result<PaymentProof, BillingError> {
        let canonical = serde_json_canonicalizer::to_vec(&self.payload)
            .map_err(|error| BillingError::Canonical(error.to_string()))?;
        let canonical = String::from_utf8(canonical).map_err(|_| BillingError::InvalidProof)?;
        PaymentProof::new(X402_SCHEME_EXACT, canonical)
    }
}

/// The body posted to `/verify` and `/settle`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacilitatorRequest {
    /// Always [`X402_VERSION`].
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    /// The decoded payload.
    #[serde(rename = "paymentPayload")]
    pub payment_payload: PaymentPayload,
    /// The exact selected obligation.
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirementsObject,
}

/// The `/verify` response.
///
/// `is_valid` is optional on the wire so an answer that omits it is
/// distinguishable from an answer that says `false`. Only `Some(true)`
/// permits a settle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Whether the facilitator considers the payment valid.
    #[serde(default, rename = "isValid")]
    pub is_valid: Option<bool>,
    /// Non-secret machine-readable rejection reason.
    #[serde(
        default,
        rename = "invalidReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub invalid_reason: Option<String>,
    /// The payer the facilitator resolved. Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Scheme-specific extra fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// The `/settle` response.
///
/// Every field that decides authorization is optional on the wire, so an
/// incomplete answer is ambiguous rather than being read as a success or
/// as an authoritative failure.
///
/// # Why this shape is not `deny_unknown_fields`
///
/// The request and challenge shapes in this module are strict, because
/// the proxy either builds them or compares an echo of one it signed
/// byte for byte. This one is a third party's answer, and strictness
/// here fails in the expensive direction: a facilitator that adds an
/// optional field would turn every settled payment into an unparseable
/// body, which this adapter reads as ambiguous, on a rail with no status
/// query to resolve it. The cost of the looser decode is that a foreign
/// error envelope carrying `"success"` deserializes cleanly, which is
/// why the settle path refuses anything outside 2xx on the status alone
/// and never lets such a body speak for the facilitator.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleResponse {
    /// Whether the settlement succeeded.
    #[serde(default)]
    pub success: Option<bool>,
    /// Non-secret machine-readable failure reason.
    #[serde(
        default,
        rename = "errorReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub error_reason: Option<String>,
    /// The payer the facilitator settled from. Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// The settlement transaction reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    /// The network the settlement landed on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// The settled amount, when the facilitator states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Scheme-specific extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

// --- Header codec ---

/// Encodes a document as an x402 header value.
///
/// Compact UTF-8 JSON, then standard RFC 4648 base64 including the
/// required padding. This is deliberately not base64url: the pinned v2
/// contract specifies standard base64 for all three headers.
///
/// # Errors
///
/// Returns [`X402Error::Malformed`] when the value cannot be serialized
/// and [`X402Error::TooLarge`] when the encoding exceeds
/// [`MAX_HEADER_BYTES`].
pub fn encode_x402_header<T: Serialize>(value: &T) -> Result<String, X402Error> {
    let json = serde_json::to_vec(value).map_err(|_| X402Error::Malformed)?;
    let encoded = STANDARD.encode(json);
    if encoded.len() > MAX_HEADER_BYTES {
        return Err(X402Error::TooLarge);
    }
    Ok(encoded)
}

/// Decodes an x402 header value into a pinned document.
///
/// Padding is required and canonical, the base64url alphabet is
/// rejected, duplicate JSON keys are rejected, unknown top-level fields
/// are rejected by the target type, and the decoded size is bounded.
///
/// # Errors
///
/// Returns [`X402Error::HeaderEncoding`], [`X402Error::TooLarge`], or
/// [`X402Error::Malformed`].
pub fn decode_x402_header<T: DeserializeOwned>(value: &str) -> Result<T, X402Error> {
    if value.is_empty() {
        return Err(X402Error::HeaderEncoding);
    }
    if value.len() > MAX_HEADER_BYTES {
        return Err(X402Error::TooLarge);
    }
    let acceptable = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='));
    if !acceptable {
        return Err(X402Error::HeaderEncoding);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| X402Error::HeaderEncoding)?;
    decode_x402_json(&bytes)
}

/// Decodes a pinned x402 document from raw JSON bytes.
///
/// # Errors
///
/// Returns [`X402Error::TooLarge`] or [`X402Error::Malformed`].
pub fn decode_x402_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, X402Error> {
    if bytes.len() > MAX_FACILITATOR_RESPONSE_BYTES {
        return Err(X402Error::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| X402Error::Malformed)?;
    let StrictJson(value) = serde_json::from_str(text).map_err(|_| X402Error::Malformed)?;
    if json_depth(&value) > MAX_JSON_DEPTH {
        return Err(X402Error::Malformed);
    }
    serde_json::from_value(value).map_err(|_| X402Error::Malformed)
}

/// Selects the one x402 header value from a request's fields.
///
/// Exactly one is required. A duplicate header is refused rather than
/// resolved, because there is no safe rule for choosing which payment a
/// client meant.
///
/// # Errors
///
/// Returns [`X402Error::Malformed`] for zero or more than one value.
pub fn select_single_header<'a, I>(values: I) -> Result<&'a str, X402Error>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut selected = None;
    for value in values {
        if selected.is_some() {
            return Err(X402Error::Malformed);
        }
        selected = Some(value);
    }
    selected.ok_or(X402Error::Malformed)
}

// --- Local validation ---

/// Everything the proxy signed, kept together so validation is one call.
pub struct SignedX402Challenge<'a> {
    /// The durable intent this challenge prepared.
    pub intent_id: &'a str,
    /// The exact resource the 402 described.
    pub resource: &'a ResourceDescriptor,
    /// The exact obligation the 402 offered and the quote signed.
    pub accepted: &'a PaymentRequirementsObject,
    /// The exact extension map the 402 carried.
    pub extensions: &'a BTreeMap<String, serde_json::Value>,
}

/// Checks an echoed payload against the challenge the proxy signed.
///
/// Every comparison is exact. Nothing is normalized, coerced, or
/// partially matched: a payload that differs in the amount, the
/// network, the asset, the recipient, the timeout, the `extra` object,
/// the resource, or the extension is a different obligation, and this
/// runs before any facilitator is contacted.
///
/// # Errors
///
/// Returns [`X402Error::UnsupportedVersion`] for a version other than
/// [`X402_VERSION`], [`X402Error::ExtensionInvalid`] when the extension
/// map is not the single published entry, [`X402Error::Malformed`] when
/// the scheme payload is absent, and [`X402Error::RequirementMismatch`]
/// for any other difference.
pub fn validate_echoed_payload(
    payload: &PaymentPayload,
    challenge: &SignedX402Challenge<'_>,
) -> Result<(), X402Error> {
    if payload.x402_version != X402_VERSION {
        return Err(X402Error::UnsupportedVersion);
    }
    if challenge.accepted.scheme != X402_SCHEME_EXACT {
        return Err(X402Error::RequirementMismatch);
    }
    if &payload.accepted != challenge.accepted || &payload.resource != challenge.resource {
        return Err(X402Error::RequirementMismatch);
    }
    // The complete info and schema objects must come back unchanged,
    // and nothing may be added beside them.
    if payload.extensions.len() != 1 || !payload.extensions.contains_key(REQUIREMENT_EXTENSION_KEY)
    {
        return Err(X402Error::ExtensionInvalid);
    }
    if &payload.extensions != challenge.extensions {
        return Err(X402Error::RequirementMismatch);
    }
    if payload.payload.is_null() {
        return Err(X402Error::Malformed);
    }
    Ok(())
}

// --- Transport ---

/// Why a facilitator call did not produce a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    /// The call did not complete inside its budget.
    Timeout,
    /// The connection could not be established or was lost.
    Connection,
    /// The response exceeded [`MAX_FACILITATOR_RESPONSE_BYTES`].
    TooLarge,
}

/// One facilitator HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacilitatorHttpResponse {
    /// The response status code.
    pub status: u16,
    /// The response body, already bounded by the transport.
    pub body: Vec<u8>,
}

/// The bounded outbound client this adapter posts through.
///
/// The runtime binds this to the shared bounded outbound HTTP client so
/// timeouts, the connection pool, redirect policy, and TLS verification
/// are the workspace's, not this module's. Keeping it a trait is also
/// what lets the contract tests drive verify and settle deterministically
/// without a socket.
#[async_trait::async_trait]
pub trait FacilitatorTransport: Send + Sync {
    /// Posts compact JSON and returns the bounded response.
    ///
    /// Implementations must enforce `timeout` themselves as well: the
    /// adapter's outer deadline is a backstop, not the only bound.
    async fn post_json(
        &self,
        url: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<FacilitatorHttpResponse, TransportFailure>;
}

/// Commits the durable dispatch stamp before a settle leaves the
/// process.
///
/// The runtime binds this to the dispatch context, which persists the
/// provider idempotency key first and commits `dispatch_started_at_ms`
/// in its own transaction immediately before the network write. An
/// adapter cannot perform a provider write without going through it.
#[async_trait::async_trait]
pub trait SettleDispatchGate: Send + Sync {
    /// Inspect a payment lifecycle `started` event before its protected effect.
    async fn payment_started(&self, _phase: PaymentLifecyclePhase) -> PaymentLifecycleDecision {
        PaymentLifecycleDecision::Continue
    }

    /// Observe a terminal payment lifecycle event without awaiting hook work.
    fn payment_terminal(&self, _phase: PaymentLifecyclePhase, _outcome: PaymentLifecycleOutcome) {}

    /// Commits the settle dispatch stamp.
    ///
    /// # Errors
    ///
    /// Returns the durable store's error. A failure here means no
    /// settle is sent at all, which is the safe direction.
    async fn stamp_settle_dispatch(&self) -> Result<(), BillingError>;

    /// Persists a hashed facilitator payer after `/verify` succeeds.
    ///
    /// `payer` is the raw address. Implementations must hash it before
    /// it reaches a column and must never log it. An empty value is a
    /// no-op. Default does nothing so a test gate that is not exercising
    /// WOR-2302 stays a stamp-only mock.
    ///
    /// # Errors
    ///
    /// Returns the durable store's error. The settler fails closed
    /// before stamping settle.
    async fn attribute_facilitator_payer(
        &self,
        _intent_id: &str,
        _payer: &str,
    ) -> Result<(), BillingError> {
        Ok(())
    }
}

// --- Settler ---

/// What a status query can prove for this rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X402QueryResult {
    /// x402 v2 at the pinned revision publishes no status or reorg
    /// query, so an ambiguous settle cannot be resolved by this
    /// adapter. It maps onto the registry's unsupported result and the
    /// record stays in reconciliation.
    Unsupported,
}

/// One completed, authoritative settlement.
pub struct X402Settlement {
    /// The receipt built from real facilitator-backed values.
    pub receipt: SettlementReceipt,
    /// The exact settle response, for the `PAYMENT-RESPONSE` header.
    ///
    /// x402 does not emit the Payment Auth `Payment-Receipt` header;
    /// this is the only header a settled x402 request adds.
    pub response: SettleResponse,
}

impl X402Settlement {
    /// Encodes the `PAYMENT-RESPONSE` header value.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::Malformed`] or [`X402Error::TooLarge`].
    pub fn response_header_value(&self) -> Result<String, X402Error> {
        encode_x402_header(&self.response)
    }
}

/// One authorization request against the selected facilitator.
pub struct X402AuthorizationRequest<'a> {
    /// Everything the proxy signed for this challenge.
    pub challenge: SignedX402Challenge<'a>,
    /// The payload the client echoed back.
    pub payload: &'a PaymentPayload,
    /// Wall clock, in milliseconds since the epoch.
    pub now_ms: i64,
}

/// The x402 v2 `exact` settlement adapter.
///
/// One settler is bound to one facilitator, which is the facilitator the
/// signed requirement selected. There is no fallback inside an
/// authorization by construction, not by policy.
pub struct X402ExactSettler<T: FacilitatorTransport> {
    endpoints: FacilitatorEndpoints,
    transport: T,
    breaker: Arc<FacilitatorBreaker>,
    verify_timeout: Duration,
    settle_timeout: Duration,
    total_deadline: Duration,
}

impl<T: FacilitatorTransport> X402ExactSettler<T> {
    /// Builds a settler for one facilitator.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::FacilitatorUrl`] when the total deadline is
    /// zero or above [`MAX_TOTAL_DEADLINE_MS`], or when the per-call
    /// budgets do not fit inside it. The configuration crate rejects the
    /// same shapes at load; this is the runtime backstop, because a
    /// deadline that does not bound the calls inside it is not a
    /// deadline.
    pub fn new(
        endpoints: FacilitatorEndpoints,
        transport: T,
        breaker: Arc<FacilitatorBreaker>,
        verify_timeout_ms: u64,
        settle_timeout_ms: u64,
        total_deadline_ms: u64,
    ) -> Result<Self, X402Error> {
        if total_deadline_ms == 0
            || total_deadline_ms > MAX_TOTAL_DEADLINE_MS
            || verify_timeout_ms == 0
            || settle_timeout_ms == 0
            || verify_timeout_ms.saturating_add(settle_timeout_ms) > total_deadline_ms
        {
            return Err(X402Error::FacilitatorUrl);
        }
        Ok(Self {
            endpoints,
            transport,
            breaker,
            verify_timeout: Duration::from_millis(verify_timeout_ms),
            settle_timeout: Duration::from_millis(settle_timeout_ms),
            total_deadline: Duration::from_millis(total_deadline_ms),
        })
    }

    /// Returns the rail this adapter settles.
    #[must_use]
    pub const fn rail(&self) -> SettlementRail {
        SettlementRail::X402
    }

    /// Returns the facilitator this settler is bound to.
    #[must_use]
    pub fn endpoints(&self) -> &FacilitatorEndpoints {
        &self.endpoints
    }

    /// Answers a status query for an ambiguous attempt.
    ///
    /// Always [`X402QueryResult::Unsupported`]. There is no endpoint to
    /// ask, so the record stays in reconciliation and the settle is
    /// never retried automatically.
    #[must_use]
    pub const fn query_attempt(&self) -> X402QueryResult {
        X402QueryResult::Unsupported
    }

    /// Verifies and settles inside one bounded deadline.
    ///
    /// Returns a settlement only when the facilitator stated an
    /// authoritative success with a real transaction reference on the
    /// exact expected network. Every other outcome is an error, and an
    /// outcome that is ambiguous after the settle was dispatched is
    /// [`BillingError::NeedsReconciliation`], never a retry and never a
    /// second facilitator.
    ///
    /// Local validation of the echoed payload runs first, inside this
    /// call, so there is no ordering for a caller to get wrong: a
    /// payload that does not match the signed challenge never reaches
    /// the facilitator.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::RequirementMismatch`] when the echoed
    /// payload is not the signed obligation,
    /// [`BillingError::ProviderUnavailable`] when the breaker is open or
    /// the facilitator is unreachable before dispatch,
    /// [`BillingError::ProviderTimeout`] when the deadline elapses
    /// before dispatch, [`BillingError::ProviderRejected`] for an
    /// authoritative failure, which on the settle leg means a 2xx body in
    /// the pinned shape saying `success = false` and nothing else,
    /// [`BillingError::ProviderMalformed`] for a response outside the
    /// pinned contract, and [`BillingError::NeedsReconciliation`] for
    /// anything ambiguous after the settle dispatch stamp is committed,
    /// which includes every settle status outside 2xx whatever its body
    /// deserializes to.
    pub async fn authorize_and_settle(
        &self,
        request: X402AuthorizationRequest<'_>,
        gate: &dyn SettleDispatchGate,
    ) -> Result<X402Settlement, BillingError> {
        let dispatched = Arc::new(AtomicBool::new(false));
        let started = tokio::time::Instant::now();
        let inner = self.run(&request, gate, &dispatched, started);
        match tokio::time::timeout(self.total_deadline, inner).await {
            Ok(result) => result,
            Err(_elapsed) => {
                // A deadline that fires after the dispatch stamp is
                // committed cannot be reported as a timeout: the settle
                // may have landed, and only a human can say.
                if dispatched.load(Ordering::SeqCst) {
                    Err(BillingError::NeedsReconciliation)
                } else {
                    Err(BillingError::ProviderTimeout)
                }
            }
        }
    }

    /// The authorization body, wrapped by the outer deadline.
    async fn run(
        &self,
        request: &X402AuthorizationRequest<'_>,
        gate: &dyn SettleDispatchGate,
        dispatched: &AtomicBool,
        started: tokio::time::Instant,
    ) -> Result<X402Settlement, BillingError> {
        if gate.payment_started(PaymentLifecyclePhase::Verify).await
            == PaymentLifecycleDecision::Reject
        {
            gate.payment_terminal(
                PaymentLifecyclePhase::Verify,
                PaymentLifecycleOutcome::Rejected,
            );
            return Err(BillingError::ExtensionRejected);
        }

        let (verified, body) = match self.verify(request, started).await {
            Ok(verified) => verified,
            Err(error) => {
                let outcome = if matches!(
                    error,
                    BillingError::ProviderRejected
                        | BillingError::RequirementMismatch
                        | BillingError::InvalidProof
                ) {
                    PaymentLifecycleOutcome::Rejected
                } else {
                    PaymentLifecycleOutcome::Failed
                };
                gate.payment_terminal(PaymentLifecyclePhase::Verify, outcome);
                return Err(error);
            }
        };
        gate.payment_terminal(
            PaymentLifecyclePhase::Verify,
            PaymentLifecycleOutcome::Succeeded,
        );

        if let Some(payer) = verified
            .payer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            gate.attribute_facilitator_payer(request.challenge.intent_id, payer)
                .await?;
        }

        if gate.payment_started(PaymentLifecyclePhase::Settle).await
            == PaymentLifecycleDecision::Reject
        {
            gate.payment_terminal(
                PaymentLifecyclePhase::Settle,
                PaymentLifecycleOutcome::Rejected,
            );
            return Err(BillingError::ExtensionRejected);
        }

        // The settle budget is computed before the stamp, so an already
        // exhausted deadline is a clean pre-dispatch timeout rather than
        // a durable stamp with nothing behind it.
        let settle_budget = self.remaining(started, self.settle_timeout)?;

        // Step 2: commit the durable dispatch stamp, then settle. The
        // flag is raised before the stamp is awaited, not after, because
        // a stamp that is cancelled mid-commit may still have landed.
        // From here on nothing may report a clean pre-dispatch failure.
        dispatched.store(true, Ordering::SeqCst);
        gate.stamp_settle_dispatch().await?;

        let response = match self
            .post(self.endpoints.settle_url(), &body, settle_budget)
            .await
        {
            Ok(response) => response,
            Err(TransportFailure::Timeout | TransportFailure::Connection) => {
                // The write may have landed. No retry, no second
                // facilitator, no guess.
                self.breaker.record_transport_failure(request.now_ms);
                return Err(BillingError::NeedsReconciliation);
            }
            Err(TransportFailure::TooLarge) => return Err(BillingError::NeedsReconciliation),
        };

        // The status decides what kind of answer this is, before the body
        // is allowed to say what the answer is. Only a 2xx is the pinned
        // `/settle` contract. x402 v2 at the pinned revision publishes no
        // error-response shape at all, and the configured facilitator root
        // is an operator-supplied URL that may sit behind a gateway, so a
        // non-2xx body is some other party's error page rather than a
        // settle answer. `SettleResponse` is deliberately not
        // `deny_unknown_fields` (see its type doc), so such a page carrying
        // `"success": false` deserializes cleanly. Reading that as a
        // refusal is the one direction that loses money: it concludes the
        // dispatch as authoritative, closes the attempt `Terminal`, and
        // takes it off the reconciliation queue for a settle the
        // facilitator may already have broadcast.
        if !(200..300).contains(&response.status) {
            if response.status >= 500 {
                // The same signal `verify` feeds the breaker for the same
                // status, so the write leg stops being the one leg whose
                // 5xx the breaker never hears about. It contributes rather
                // than decides: a facilitator whose `verify` still answers
                // 200 resets the consecutive-failure count on the leg
                // before this one, so settle 5xx alone does not open the
                // breaker.
                self.breaker.record_transport_failure(request.now_ms);
            }
            return Err(BillingError::NeedsReconciliation);
        }

        let settled: SettleResponse = match decode_x402_json(&response.body) {
            Ok(settled) => settled,
            Err(_) => return Err(BillingError::NeedsReconciliation),
        };
        if settled.success == Some(false) {
            // Authoritative, and only here: a 2xx answer in the pinned
            // shape whose own `success` field states that no funds moved.
            return Err(BillingError::ProviderRejected);
        }
        if settled.success != Some(true) {
            return Err(BillingError::NeedsReconciliation);
        }
        self.breaker.record_success();

        let receipt = self.receipt_from(request, &verified, &settled)?;
        Ok(X402Settlement {
            receipt,
            response: settled,
        })
    }

    async fn verify(
        &self,
        request: &X402AuthorizationRequest<'_>,
        started: tokio::time::Instant,
    ) -> Result<(VerifyResponse, Vec<u8>), BillingError> {
        // Everything local first. A payload that is not the signed
        // obligation costs the facilitator nothing.
        validate_echoed_payload(request.payload, &request.challenge)?;

        if self.breaker.admit(request.now_ms) == BreakerVerdict::Open {
            return Err(BillingError::ProviderUnavailable);
        }

        let body = serde_json::to_vec(&FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: request.payload.clone(),
            payment_requirements: request.challenge.accepted.clone(),
        })
        .map_err(|_| BillingError::ProviderMalformed)?;

        // Verify is a read, so it never commits a dispatch stamp.
        let response = self
            .post(
                self.endpoints.verify_url(),
                &body,
                self.remaining(started, self.verify_timeout)?,
            )
            .await
            .map_err(|failure| self.pre_dispatch_error(failure, request.now_ms))?;

        if response.status >= 500 {
            self.breaker.record_transport_failure(request.now_ms);
            return Err(BillingError::ProviderUnavailable);
        }
        if !(200..300).contains(&response.status) {
            return Err(BillingError::ProviderMalformed);
        }
        let verified: VerifyResponse =
            decode_x402_json(&response.body).map_err(BillingError::from)?;
        self.breaker.record_success();
        if verified.is_valid != Some(true) {
            return Err(BillingError::ProviderRejected);
        }
        Ok((verified, body))
    }

    /// Validates a settle response and builds the receipt from it.
    fn receipt_from(
        &self,
        request: &X402AuthorizationRequest<'_>,
        verified: &VerifyResponse,
        settled: &SettleResponse,
    ) -> Result<SettlementReceipt, BillingError> {
        let transaction = settled
            .transaction
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            // A success with no transaction is not a receipt this crate
            // will invent one for.
            .ok_or(BillingError::NeedsReconciliation)?;

        if settled.network.as_deref() != Some(request.challenge.accepted.network.as_str()) {
            return Err(BillingError::NeedsReconciliation);
        }
        if let Some(amount) = settled.amount.as_deref() {
            if amount != request.challenge.accepted.amount {
                return Err(BillingError::NeedsReconciliation);
            }
        }
        if let (Some(verify_payer), Some(settle_payer)) =
            (verified.payer.as_deref(), settled.payer.as_deref())
        {
            if verify_payer != settle_payer {
                return Err(BillingError::NeedsReconciliation);
            }
        }

        SettlementReceipt::new(
            request.challenge.intent_id,
            SettlementRail::X402,
            X402_SCHEME_EXACT,
            transaction,
            request.now_ms,
        )
    }

    /// Posts to one endpoint under the smaller of its budget and the
    /// remaining total deadline.
    async fn post(
        &self,
        url: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<FacilitatorHttpResponse, TransportFailure> {
        let response = self.transport.post_json(url, body, timeout).await?;
        if response.body.len() > MAX_FACILITATOR_RESPONSE_BYTES {
            return Err(TransportFailure::TooLarge);
        }
        Ok(response)
    }

    /// Maps a pre-dispatch transport failure and moves the breaker.
    ///
    /// A timeout or a lost connection is a health signal and counts
    /// toward opening the breaker. An oversized response is not: the
    /// facilitator answered, it just answered something this adapter
    /// will not read.
    fn pre_dispatch_error(&self, failure: TransportFailure, now_ms: i64) -> BillingError {
        match failure {
            TransportFailure::Timeout => {
                self.breaker.record_transport_failure(now_ms);
                BillingError::ProviderTimeout
            }
            TransportFailure::Connection => {
                self.breaker.record_transport_failure(now_ms);
                BillingError::ProviderUnavailable
            }
            TransportFailure::TooLarge => BillingError::ProviderMalformed,
        }
    }

    /// The budget one call gets: its own, capped by what is left of the
    /// total deadline.
    fn remaining(
        &self,
        started: tokio::time::Instant,
        call_budget: Duration,
    ) -> Result<Duration, BillingError> {
        let left = self.total_deadline.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(BillingError::ProviderTimeout);
        }
        Ok(call_budget.min(left))
    }
}

// --- Strict JSON ---
//
// Deliberately duplicated from the Payment Auth codec rather than
// shared. The two codecs sit behind independent Cargo features, and a
// build with only `x402` must not have to compile the Payment Auth
// module to get a strict parser.

/// Returns the nesting depth of a parsed JSON value.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// A JSON value parsed with duplicate object keys refused.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `unwrap_err` requires `Debug` on the success type, and several
    /// wire types here deliberately do not carry one because they hold
    /// payer identifiers and signed payloads. Errors are unwrapped
    /// through this helper rather than widening a derive to suit a test.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn the_api_root_keeps_its_prefix_and_gains_only_the_operation() {
        let endpoints = FacilitatorEndpoints::from_api_root("https://facilitator.example/base/")
            .expect("a rooted https URL is usable");
        assert_eq!(
            endpoints.verify_url(),
            "https://facilitator.example/base/verify"
        );
        assert_eq!(
            endpoints.settle_url(),
            "https://facilitator.example/base/settle"
        );
        assert_eq!(endpoints.root(), "https://facilitator.example/base");

        let bare = FacilitatorEndpoints::from_api_root("https://facilitator.example")
            .expect("a bare host is usable");
        assert_eq!(bare.verify_url(), "https://facilitator.example/verify");
        assert_eq!(bare.settle_url(), "https://facilitator.example/settle");
    }

    #[test]
    fn unusable_api_roots_are_refused() {
        for bad in [
            "http://facilitator.example",
            "https://user:pass@facilitator.example",
            "https://facilitator.example/api?v=2",
            "https://facilitator.example/api#frag",
            "https://facilitator.example/api/verify",
            "https://facilitator.example/api/settle/",
            "https://facilitator.example/api/../other",
            "https://facilitator.example/api//v2",
            "facilitator.example",
            "",
        ] {
            assert_eq!(
                expect_error(
                    FacilitatorEndpoints::from_api_root(bad),
                    "an unusable API root must be refused"
                ),
                X402Error::FacilitatorUrl,
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn cleartext_is_only_reachable_from_the_test_only_constructor() {
        assert!(FacilitatorEndpoints::loopback_http_for_test("http://127.0.0.1:9999").is_ok());
        assert!(FacilitatorEndpoints::loopback_http_for_test("http://localhost:9999/base").is_ok());
        // Even the test-only constructor refuses cleartext off loopback.
        assert_eq!(
            expect_error(
                FacilitatorEndpoints::loopback_http_for_test("http://facilitator.example"),
                "cleartext off loopback must be refused"
            ),
            X402Error::FacilitatorUrl
        );
    }

    #[test]
    fn the_adapter_never_builds_a_third_endpoint() {
        let endpoints = FacilitatorEndpoints::from_api_root("https://facilitator.example/base")
            .expect("a rooted https URL is usable");
        for forbidden in ["/status", "/reorg", "/health", "/v2"] {
            assert!(!endpoints.verify_url().contains(forbidden));
            assert!(!endpoints.settle_url().contains(forbidden));
        }
        assert!(endpoints.verify_url().ends_with("/verify"));
        assert!(endpoints.settle_url().ends_with("/settle"));
    }

    #[test]
    fn the_breaker_opens_holds_and_admits_one_probe() {
        let breaker = FacilitatorBreaker::new(3, 5_000, 1).expect("bounded breaker");
        assert_eq!(breaker.admit(0), BreakerVerdict::Closed);

        breaker.record_transport_failure(0);
        breaker.record_transport_failure(0);
        assert_eq!(breaker.admit(0), BreakerVerdict::Closed);
        breaker.record_transport_failure(0);
        assert_eq!(breaker.admit(0), BreakerVerdict::Open);
        assert_eq!(breaker.admit(4_999), BreakerVerdict::Open);

        // Exactly one probe once the window elapses.
        assert_eq!(breaker.admit(5_000), BreakerVerdict::HalfOpenProbe);
        assert_eq!(breaker.admit(5_000), BreakerVerdict::Open);

        // A failed probe re-opens for a fresh window.
        breaker.record_transport_failure(5_000);
        assert_eq!(breaker.admit(9_999), BreakerVerdict::Open);
        assert_eq!(breaker.admit(10_000), BreakerVerdict::HalfOpenProbe);
        breaker.record_success();
        assert_eq!(breaker.admit(10_000), BreakerVerdict::Closed);
    }

    #[test]
    fn breaker_bounds_are_enforced() {
        assert!(FacilitatorBreaker::new(0, 5_000, 1).is_err());
        assert!(FacilitatorBreaker::new(3, 99, 1).is_err());
        assert!(FacilitatorBreaker::new(3, 60_001, 1).is_err());
        assert!(FacilitatorBreaker::new(3, 5_000, 2).is_err());
    }

    #[test]
    fn the_deadline_ceiling_is_enforced_at_construction() {
        struct NoTransport;
        #[async_trait::async_trait]
        impl FacilitatorTransport for NoTransport {
            async fn post_json(
                &self,
                _url: &str,
                _body: &[u8],
                _timeout: Duration,
            ) -> Result<FacilitatorHttpResponse, TransportFailure> {
                Err(TransportFailure::Connection)
            }
        }
        let endpoints = FacilitatorEndpoints::from_api_root("https://facilitator.example").unwrap();
        let breaker = Arc::new(FacilitatorBreaker::new(3, 5_000, 1).unwrap());

        // Above the hard ceiling.
        assert!(X402ExactSettler::new(
            endpoints.clone(),
            NoTransport,
            breaker.clone(),
            700,
            1_200,
            2_001
        )
        .is_err());
        // Per-call budgets that do not fit inside the total.
        assert!(X402ExactSettler::new(
            endpoints.clone(),
            NoTransport,
            breaker.clone(),
            1_500,
            1_000,
            2_000
        )
        .is_err());
        assert!(X402ExactSettler::new(endpoints, NoTransport, breaker, 700, 1_200, 2_000).is_ok());
    }

    #[test]
    fn the_published_schema_is_valid_and_bounded() {
        let extension = RequirementExtension::new("requirement_0123456789", "quote-token")
            .expect("a well formed extension builds");
        assert_eq!(extension.info.id, "requirement_0123456789");
        assert_eq!(extension.schema["type"], "object");
        assert_eq!(extension.schema["additionalProperties"], false);

        for (id, quote) in [
            ("short", "quote"),
            ("requirement_0123456789", ""),
            ("bad id with spaces!!", "quote"),
        ] {
            assert_eq!(
                expect_error(
                    RequirementExtension::new(id, quote),
                    "an out of schema extension must be refused"
                ),
                X402Error::ExtensionInvalid
            );
        }
    }

    #[test]
    fn header_values_are_standard_base64_with_padding() {
        let response = SettleResponse {
            success: Some(true),
            error_reason: None,
            payer: None,
            transaction: Some("0xabc".to_string()),
            network: Some("eip155:84532".to_string()),
            amount: None,
            extensions: None,
        };
        let encoded = encode_x402_header(&response).expect("the response encodes");
        // Standard base64 pads to a multiple of four.
        assert_eq!(encoded.len() % 4, 0);
        let decoded: SettleResponse = decode_x402_header(&encoded).expect("the response decodes");
        assert_eq!(decoded.transaction.as_deref(), Some("0xabc"));

        // base64url is refused rather than accepted as a courtesy.
        assert_eq!(
            expect_error(
                decode_x402_header::<SettleResponse>("eyJhIjoxfQ-_"),
                "base64url must be refused"
            ),
            X402Error::HeaderEncoding
        );
        // So is a value stripped of its padding.
        let unpadded = encoded.trim_end_matches('=');
        if unpadded.len() != encoded.len() {
            assert_eq!(
                expect_error(
                    decode_x402_header::<SettleResponse>(unpadded),
                    "missing padding must be refused"
                ),
                X402Error::HeaderEncoding
            );
        }
    }

    #[test]
    fn duplicate_headers_are_refused_rather_than_resolved() {
        assert!(select_single_header(["one"]).is_ok());
        assert_eq!(
            expect_error(
                select_single_header(["one", "two"]),
                "a duplicate header must be refused"
            ),
            X402Error::Malformed
        );
        assert_eq!(
            expect_error(select_single_header([]), "a missing header must be refused"),
            X402Error::Malformed
        );
    }

    #[test]
    fn duplicate_json_keys_are_refused() {
        assert_eq!(
            expect_error(
                decode_x402_json::<serde_json::Value>(br#"{"success":true,"success":false}"#),
                "a duplicate key must be refused"
            ),
            X402Error::Malformed
        );
    }

    #[test]
    fn a_settle_response_without_an_authoritative_field_is_not_a_success() {
        // Absent `success` is ambiguous, not false and not true.
        let ambiguous: SettleResponse =
            decode_x402_json(br#"{"transaction":"0xabc","network":"eip155:84532"}"#)
                .expect("the response parses");
        assert_eq!(ambiguous.success, None);

        let rejected: SettleResponse =
            decode_x402_json(br#"{"success":false}"#).expect("an authoritative failure parses");
        assert_eq!(rejected.success, Some(false));
    }
}
