//! `proxy.payments`: the exact, typed settlement configuration.
//!
//! Everything a payment rail needs to advertise a price, prepare a
//! provider object, and authorize a request is declared here and
//! nowhere else. An adapter may not consult a second source for a
//! price, an address, a facilitator, a network id, a payment-method
//! list, a capture mode, a backend, or an expiry. That single-owner
//! rule is what lets the request path prove, locally, that the
//! challenge it signed and the credential it received describe the
//! same obligation.
//!
//! Three properties are load-bearing and are enforced by
//! [`PaymentsConfig::validate`] rather than deferred to first request:
//!
//! 1. Every advertised rail resolves to exactly one compiled adapter.
//!    A configured rail whose Cargo feature is absent from the running
//!    binary is a startup failure that names the missing feature. See
//!    [`PaymentsConfig::required_features`].
//! 2. Amount conversion is exact integer arithmetic. The compiler
//!    converts quote micros into the rail's declared settlement
//!    decimals and rejects any remainder, so the proxy never rounds a
//!    price and never performs an implicit currency conversion. See
//!    [`settlement_amount`].
//! 3. Credentials are named, never carried. Every key, rune, and
//!    macaroon field holds a secret reference; an inline token is
//!    rejected at load.
//!
//! This module owns shape and cross-field rules only. It never
//! resolves a secret, opens the SQLite state file, contacts a
//! provider, or starts a worker, so `sbproxy validate` runs against a
//! payments configuration on a machine that holds none of its
//! credentials.

use serde::{Deserialize, Serialize};

/// Longest accepted value for a bounded scalar such as a path, a
/// realm, or a provider identifier.
const MAX_VALUE_BYTES: usize = 1024;

/// Hard ceiling on `authorization_timeout_ms`.
///
/// The authorization invariant allows exactly one bounded synchronous
/// provider interaction on the request path. Two seconds is the budget
/// the pinned rail contracts are specified against; a larger value
/// would turn a paid request into an availability problem for the
/// origin behind it.
pub const MAX_AUTHORIZATION_TIMEOUT_MS: u32 = 2_000;

/// Largest request body the payment path will buffer, in bytes.
///
/// Payment Auth binds an RFC 9530 digest over the exact request bytes,
/// so a paid request with a body must be read once, in full, before
/// the challenge is issued or validated. The cap matches the
/// idempotency buffer's request ceiling so the two eager readers agree
/// on how much of a stream a single request may pin in memory.
pub const MAX_PAYMENT_BODY_BYTES: u64 = crate::types::DEFAULT_IDEMPOTENCY_MAX_REQUEST_BYTES as u64;

/// The only Stripe API version this release speaks.
///
/// Pinned rather than defaulted: a Stripe version bump changes
/// PaymentIntent semantics, and a settlement path that silently
/// followed the account's dashboard default would authorize requests
/// against a contract nobody reviewed.
pub const STRIPE_API_VERSION: &str = "2026-06-24.dahlia";

/// The only Payment Auth draft this release implements.
pub const PAYMENT_AUTH_DRAFT: &str = "draft-ryan-httpauth-payment-01";

/// The only Payment Auth method registered here.
pub const PAYMENT_AUTH_METHOD: &str = "stripe";

/// The only Payment Auth intent registered here.
pub const PAYMENT_AUTH_INTENT: &str = "charge";

/// The only x402 scheme this release implements.
pub const X402_SCHEME: &str = "exact";

/// Smallest Core Lightning release that carries the documented `xpay`
/// label and the `listinvoices` status this adapter reads, as
/// `(major, minor)`.
pub const MIN_CLN_VERSION: (u32, u32) = (26, 6);

/// Largest JCS encoding accepted for the x402 `extra` object.
pub const MAX_X402_EXTRA_JCS_BYTES: usize = 4 * 1024;

/// Inclusive bounds on `max_timeout_seconds` in an x402 requirement.
pub const X402_MAX_TIMEOUT_SECONDS_RANGE: (u32, u32) = (1, 3_600);

/// Inclusive bounds on a circuit breaker's open window, in
/// milliseconds.
pub const BREAKER_OPEN_MS_RANGE: (u64, u64) = (100, 60_000);

/// Inclusive bounds on a Lightning invoice expiry, in seconds.
pub const INVOICE_EXPIRY_SECONDS_RANGE: (u32, u32) = (30, 86_400);

/// Inclusive bounds on the recovery envelope's hard expiry, in hours.
///
/// The upper bound sits one hour below Stripe's documented 24-hour
/// idempotency-key retention so a same-key response recovery can never
/// race the provider forgetting the original request.
pub const RECOVERY_MAX_AGE_HOURS_RANGE: (u8, u8) = (1, 23);

// --- Top level ---

/// `proxy.payments`: durable settlement for paid requests.
///
/// Absent means the proxy keeps its existing non-settlement ledger
/// behaviour exactly. Present means a paid request reaches the origin
/// only after a durable intent has committed `Succeeded`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentsConfig {
    /// Absolute path to the SQLite database that owns intents,
    /// attempts, proofs, and receipts. Authoritative for this release:
    /// a request is authorized because a row in this file says so.
    pub state_path: String,
    /// Secret reference to the key that binds a challenge to its
    /// issuing proxy. Never an inline key.
    pub challenge_binding_key: String,
    /// Total budget for the one synchronous provider interaction a
    /// paid request is allowed, in milliseconds. Capped at
    /// [`MAX_AUTHORIZATION_TIMEOUT_MS`].
    #[serde(default = "default_authorization_timeout_ms")]
    pub authorization_timeout_ms: u32,
    /// Largest request body the payment path buffers, in bytes.
    /// Bounded by [`MAX_PAYMENT_BODY_BYTES`]; a larger body is
    /// answered 413 before any challenge or provider work.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,
    /// Encryption for the write-ahead recovery envelopes that make a
    /// crashed Stripe dispatch recoverable. Required whenever the
    /// Stripe settlement rail is enabled.
    #[serde(default)]
    pub recovery_encryption: Option<RecoveryEncryptionConfig>,
    /// Recovery-only background worker. It never performs the
    /// settlement that authorizes a request.
    #[serde(default)]
    pub worker: PaymentsWorkerConfig,
    /// Wire protocols offered on top of the rails.
    #[serde(default)]
    pub protocols: PaymentProtocolsConfig,
    /// Settlement rails and their provider credentials.
    #[serde(default)]
    pub rails: PaymentRailsConfig,
    /// Usage reporters. A reporter accounts for consumption and can
    /// never authorize a request or produce a settlement receipt.
    #[serde(default)]
    pub usage_reporters: UsageReportersConfig,
}

/// AES-256-GCM material for the Stripe write-ahead recovery envelope.
///
/// The envelope holds the exact bytes of a Stripe create request so a
/// process that crashed between stamping dispatch and recording the
/// response can replay the byte-equivalent POST under the same
/// idempotency key and recover the original response. It never holds
/// the API key or any authorization header.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEncryptionConfig {
    /// Identifier stored beside each ciphertext so a rotation can tell
    /// which key decrypts which envelope. Outstanding envelopes must
    /// be drained or expired before their key id is retired.
    pub key_id: String,
    /// Secret reference to the 32-byte key. Structural validation
    /// checks only that this names a secret; runtime resolution
    /// requires exactly 32 decoded bytes.
    pub key: String,
    /// Hard expiry for an envelope, in hours. Bounded by
    /// [`RECOVERY_MAX_AGE_HOURS_RANGE`].
    #[serde(default = "default_recovery_max_age_hours")]
    pub max_age_hours: u8,
}

/// Cadence and shutdown budget for the recovery-only worker.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PaymentsWorkerConfig {
    /// Delay between reconciliation sweeps, in milliseconds.
    pub reconcile_interval_ms: u64,
    /// Largest number of records claimed in one sweep.
    pub max_reconcile_batch: u32,
    /// Time the worker is given to stop claiming and drain in-flight
    /// queries at shutdown, in milliseconds.
    pub shutdown_timeout_ms: u64,
}

impl Default for PaymentsWorkerConfig {
    fn default() -> Self {
        Self {
            reconcile_interval_ms: 1_000,
            max_reconcile_batch: 32,
            shutdown_timeout_ms: 5_000,
        }
    }
}

/// Wire protocols the proxy speaks on top of its settlement rails.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PaymentProtocolsConfig {
    /// Payment HTTP Authentication. Absent means the proxy never
    /// emits a `WWW-Authenticate: Payment` challenge.
    pub payment_auth: Option<PaymentAuthProtocolConfig>,
}

/// Payment HTTP Authentication, pinned to one draft, one method, and
/// one intent.
///
/// The core draft's intent registry is empty, so the method-specific
/// registration supplies the exact request, credential, and receipt
/// semantics. This release implements only the registered `stripe`
/// plus `charge` pair; it does not invent a generic provider schema.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentAuthProtocolConfig {
    /// Draft identifier. Must equal [`PAYMENT_AUTH_DRAFT`]. Declared
    /// rather than assumed so a configuration written against a
    /// different draft fails loudly instead of producing bytes the
    /// client cannot parse.
    #[serde(default = "default_payment_auth_draft")]
    pub draft: String,
    /// Protection space echoed in every challenge and credential. It
    /// is the first slot of the challenge binding, so changing it
    /// invalidates outstanding challenges.
    pub realm: String,
    /// Payment method token. Must equal [`PAYMENT_AUTH_METHOD`].
    #[serde(default = "default_payment_auth_method")]
    pub method: String,
    /// Intent token. Must equal [`PAYMENT_AUTH_INTENT`].
    #[serde(default = "default_payment_auth_intent")]
    pub intent: String,
}

// --- Rails ---

/// Which settlement backend serves an advertised Lightning rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LightningBackend {
    /// Core Lightning over its Unix-socket JSON-RPC.
    Cln,
    /// LND over gRPC.
    Lnd,
}

impl LightningBackend {
    /// Stable string form used in errors and in the compiled
    /// requirement's typed terms.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            LightningBackend::Cln => "cln",
            LightningBackend::Lnd => "lnd",
        }
    }
}

/// Settlement rails and their provider credentials.
///
/// Every block is optional, but an advertised rail with no enabled
/// block, or a Lightning advertisement with two enabled backends and
/// no [`Self::lightning_backend`] selector, fails at load rather than
/// at first request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PaymentRailsConfig {
    /// x402 v2 `exact`.
    pub x402: Option<X402RailConfig>,
    /// Stripe PaymentIntents, used both directly and as the
    /// settlement half of Payment Auth `stripe` plus `charge`.
    pub stripe: Option<StripeRailConfig>,
    /// Core Lightning.
    pub lightning_cln: Option<LightningClnRailConfig>,
    /// LND.
    pub lightning_lnd: Option<LightningLndRailConfig>,
    /// Which backend an advertised Lightning rail resolves to.
    /// Required when both backends are configured; inferred when
    /// exactly one is.
    pub lightning_backend: Option<LightningBackend>,
}

/// One facilitator candidate for the x402 rail.
///
/// The URL is the facilitator's complete API root. The adapter
/// preserves every configured path segment, strips only trailing
/// slashes, and appends exactly `/verify` or `/settle`; it never
/// injects a version or protocol segment of its own.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct X402FacilitatorConfig {
    /// Absolute HTTPS API root. No userinfo, query, or fragment, and
    /// no endpoint suffix.
    pub facilitator_url: String,
}

/// Bounded circuit breaker around one provider endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct BreakerConfig {
    /// Consecutive transport failures that open the breaker.
    pub failure_threshold: u32,
    /// How long the breaker stays open, in milliseconds. Bounded by
    /// [`BREAKER_OPEN_MS_RANGE`].
    pub open_ms: u64,
    /// Probes admitted while half open. Exactly 1 in this release: a
    /// second concurrent probe against an unhealthy facilitator can
    /// dispatch a settlement nobody is waiting to record.
    pub half_open_max: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            open_ms: 5_000,
            half_open_max: 1,
        }
    }
}

/// x402 v2 `exact` rail.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct X402RailConfig {
    /// Scheme name. Must equal [`X402_SCHEME`].
    #[serde(default = "default_x402_scheme")]
    pub scheme: String,
    /// CAIP-2 chain identifier, for example `eip155:84532`. A short
    /// chain nickname is rejected: an authoritative payment
    /// requirement must not depend on a translation table.
    pub network: String,
    /// Asset contract address or identifier on `network`.
    pub asset: String,
    /// ISO-4217 code the quote is priced in. Every rail a single route
    /// advertises must share this value; the proxy performs no
    /// currency conversion.
    pub quote_currency: String,
    /// Decimal places in the asset's atomic unit. Used for the exact
    /// checked conversion from quote micros.
    pub asset_decimals: u8,
    /// Recipient address on `network`.
    pub pay_to: String,
    /// Value copied into the requirement's `maxTimeoutSeconds`.
    /// Bounded by [`X402_MAX_TIMEOUT_SECONDS_RANGE`].
    pub max_timeout_seconds: u32,
    /// Scheme-specific extra object copied verbatim into the
    /// requirement. Its JCS encoding is bounded by
    /// [`MAX_X402_EXTRA_JCS_BYTES`] and is byte-stable, so the client
    /// can echo it and the proxy can compare it exactly.
    #[serde(default)]
    #[schemars(with = "serde_json::Map<String, serde_json::Value>")]
    pub extra: serde_json::Map<String, serde_json::Value>,
    /// Ordered facilitator candidates. Fallback is allowed only by
    /// issuing a fresh challenge; a signed requirement is bound to the
    /// one facilitator it selected.
    pub facilitators: Vec<X402FacilitatorConfig>,
    /// Budget for the `verify` call, in milliseconds.
    #[serde(default = "default_x402_verify_timeout_ms")]
    pub verify_timeout_ms: u32,
    /// Budget for the `settle` call, in milliseconds.
    #[serde(default = "default_x402_settle_timeout_ms")]
    pub settle_timeout_ms: u32,
    /// Breaker around the facilitator.
    #[serde(default)]
    pub breaker: BreakerConfig,
}

/// Direct Stripe PaymentIntent mode.
///
/// The challenge creates a manual-capture PaymentIntent and the
/// credential retry captures it. Preparation must never capture funds
/// or deliver the resource, so `automatic` capture is not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectPaymentIntentConfig {
    /// Whether the direct PaymentIntent mode is offered.
    #[serde(default)]
    pub enabled: bool,
    /// Capture mode. Only `manual` is accepted.
    #[serde(default = "default_capture_method")]
    pub capture_method: String,
}

/// Stripe settlement rail.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StripeRailConfig {
    /// Secret reference to the Stripe secret key. Never inline.
    pub api_key: String,
    /// Stripe API version. Must equal [`STRIPE_API_VERSION`].
    #[serde(default = "default_stripe_api_version")]
    pub api_version: String,
    /// Account routing. Only `platform` is accepted in this release,
    /// and no `Stripe-Account` header is sent. Connect routing is
    /// deliberately not reachable from a challenge or a credential: a
    /// client-controlled destination account would let a payer choose
    /// who gets paid.
    #[serde(default = "default_account_context")]
    pub account_context: String,
    /// Business network identifier copied into the method details of
    /// a Payment Auth request.
    pub business_network_id: String,
    /// ISO-4217 code the quote is priced in.
    pub quote_currency: String,
    /// Declared minor-unit decimals for `quote_currency`. Checked
    /// against the built-in ISO-4217 table so a mis-declared currency
    /// cannot silently charge a hundred times the quoted price.
    pub currency_decimals: u8,
    /// Payment method types offered on the PaymentIntent.
    pub payment_method_types: Vec<String>,
    /// Optional direct PaymentIntent mode.
    #[serde(default)]
    pub direct_payment_intent: Option<DirectPaymentIntentConfig>,
}

/// Core Lightning rail, reached over its Unix-socket JSON-RPC.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LightningClnRailConfig {
    /// Absolute path to the `lightning-rpc` Unix socket.
    pub socket_path: String,
    /// Secret reference to the rune that authorizes the RPC calls.
    pub rune: String,
    /// Smallest accepted node version as `major.minor`. Cannot be set
    /// below [`MIN_CLN_VERSION`], whose `xpay` label and
    /// `listinvoices` status this adapter depends on. Startup checks
    /// the live version through `getinfo`.
    #[serde(default = "default_cln_minimum_version")]
    pub minimum_version: String,
    /// ISO-4217 or asset code the quote is priced in.
    pub quote_currency: String,
    /// Decimal places in the settlement unit. `11` prices BTC in
    /// millisatoshis.
    pub settlement_decimals: u8,
    /// Invoice lifetime, in seconds. Bounded by
    /// [`INVOICE_EXPIRY_SECONDS_RANGE`].
    #[serde(default = "default_invoice_expiry_seconds")]
    pub invoice_expiry_seconds: u32,
}

/// LND rail, reached over gRPC.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LightningLndRailConfig {
    /// gRPC endpoint URL. Must be absolute and TLS-bearing.
    pub endpoint: String,
    /// Absolute path to the node's TLS certificate.
    pub tls_certificate_path: String,
    /// Secret reference to the hex-encoded macaroon.
    pub macaroon: String,
    /// ISO-4217 or asset code the quote is priced in.
    pub quote_currency: String,
    /// Decimal places in the settlement unit.
    pub settlement_decimals: u8,
    /// Invoice lifetime, in seconds. Bounded by
    /// [`INVOICE_EXPIRY_SECONDS_RANGE`].
    #[serde(default = "default_invoice_expiry_seconds")]
    pub invoice_expiry_seconds: u32,
}

// --- Usage reporting ---

/// Usage reporters. Accounting only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UsageReportersConfig {
    /// Stripe Meter Events. Meter events record consumption; they
    /// never prove that a payment settled and can never move an
    /// access intent to `Succeeded`.
    pub stripe_meter: Option<StripeMeterReporterConfig>,
}

/// Stripe Meter Events reporter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StripeMeterReporterConfig {
    /// Meter event name registered in the Stripe dashboard.
    pub event_name: String,
    /// Field on the request context that carries the Stripe customer
    /// identifier.
    pub customer_field: String,
}

// --- Advertised rails ---

/// A rail name a route may advertise in a challenge.
///
/// Distinct from a settlement rail: `Mpp` is advertised and settles
/// through Stripe, so there is no `Mpp` settlement backend to
/// configure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AdvertisedRailName {
    /// x402 v2.
    X402,
    /// Payment HTTP Authentication, settling through Stripe.
    Mpp,
    /// Stripe PaymentIntents, advertised directly.
    Stripe,
    /// Lightning, resolved to CLN or LND.
    Lightning,
}

impl AdvertisedRailName {
    /// Stable string form used in errors, metric labels, and the
    /// `Accept-Payment` preference parser.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AdvertisedRailName::X402 => "x402",
            AdvertisedRailName::Mpp => "mpp",
            AdvertisedRailName::Stripe => "stripe",
            AdvertisedRailName::Lightning => "lightning",
        }
    }
}

// --- Errors ---

/// Every way a `proxy.payments` block can be rejected at load.
///
/// Each variant names the exact field so the operator does not have to
/// diff their document against the schema to find the offending key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaymentsConfigError {
    /// A bounded scalar was empty, oversized, or held a control
    /// character.
    #[error("proxy.payments.{field} must be a non-empty value of at most {MAX_VALUE_BYTES} bytes with no control characters")]
    Value {
        /// Dotted path of the offending field, relative to
        /// `proxy.payments`.
        field: String,
    },
    /// A path field was not absolute.
    #[error("proxy.payments.{field} must be an absolute path")]
    NotAbsolutePath {
        /// Dotted path of the offending field.
        field: String,
    },
    /// A credential field carried a value inline instead of naming a
    /// secret.
    #[error("proxy.payments.{field} must name a secret (for example `secret://env/NAME`, `env:NAME`, or `${{NAME}}`) rather than carrying the credential inline")]
    InlineSecret {
        /// Dotted path of the offending field.
        field: String,
    },
    /// A numeric field fell outside its allowed range.
    #[error("proxy.payments.{field} is {value}, outside the allowed range {min} through {max}")]
    OutOfRange {
        /// Dotted path of the offending field.
        field: String,
        /// Configured value.
        value: u64,
        /// Smallest accepted value.
        min: u64,
        /// Largest accepted value.
        max: u64,
    },
    /// A pinned constant was given a different value.
    #[error("proxy.payments.{field} is {actual:?}, but this release implements only {expected:?}")]
    Pinned {
        /// Dotted path of the offending field.
        field: String,
        /// Configured value.
        actual: String,
        /// The only accepted value.
        expected: String,
    },
    /// The network identifier was not CAIP-2.
    #[error("proxy.payments.rails.x402.network is {actual:?}, which is not a CAIP-2 identifier; use the `namespace:reference` form such as `eip155:84532` rather than a short chain name, because an authoritative payment requirement must not depend on a nickname translation")]
    NotCaip2 {
        /// Configured value.
        actual: String,
    },
    /// A facilitator API root was unusable.
    #[error(
        "proxy.payments.rails.x402.facilitators[{index}].facilitator_url is unusable: {reason}"
    )]
    FacilitatorUrl {
        /// Position in the configured candidate list.
        index: usize,
        /// Why the URL was rejected.
        reason: String,
    },
    /// The x402 `extra` object exceeded its JCS size bound.
    #[error("proxy.payments.rails.x402.extra encodes to {actual} JCS bytes, above the {MAX_X402_EXTRA_JCS_BYTES} byte limit")]
    ExtraTooLarge {
        /// Encoded size in bytes.
        actual: usize,
    },
    /// The x402 per-call timeouts exceeded the total authorization
    /// budget.
    #[error("proxy.payments.rails.x402 verify_timeout_ms + settle_timeout_ms is {sum} ms, above proxy.payments.authorization_timeout_ms of {budget} ms; the request path must finish verify and settle inside one deadline")]
    TimeoutSumExceedsBudget {
        /// Sum of the configured per-call budgets.
        sum: u64,
        /// Total authorization budget.
        budget: u64,
    },
    /// A declared currency was unknown to the built-in ISO-4217 table.
    #[error("proxy.payments.{field} is {actual:?}, which is not in the built-in ISO-4217 table; an unknown currency has no known minor unit, so the exact micros conversion cannot be proven")]
    UnknownCurrency {
        /// Dotted path of the offending field.
        field: String,
        /// Configured value.
        actual: String,
    },
    /// A declared decimal count disagreed with ISO-4217.
    #[error("proxy.payments.{field} declares {actual} decimals for {currency}, but ISO-4217 defines {expected}")]
    CurrencyDecimalsMismatch {
        /// Dotted path of the offending field.
        field: String,
        /// Currency code.
        currency: String,
        /// Configured decimals.
        actual: u8,
        /// Decimals ISO-4217 defines.
        expected: u8,
    },
    /// A Core Lightning minimum version was below the floor this
    /// adapter needs.
    #[error("proxy.payments.rails.lightning_cln.minimum_version is {actual:?}, below the {major}.{minor:02} this adapter requires for the documented `xpay` label and `listinvoices` status")]
    ClnVersionTooLow {
        /// Configured value.
        actual: String,
        /// Required major version.
        major: u32,
        /// Required minor version.
        minor: u32,
    },
    /// The Stripe rail was enabled without recovery encryption.
    #[error("proxy.payments.recovery_encryption is required when proxy.payments.rails.stripe is set, because a crashed create must be recoverable under the same idempotency key and the Payment Auth form of that request contains a single-use payment token")]
    RecoveryEncryptionRequired,
    /// A route advertised a rail with no enabled backend.
    #[error("advertised rail {rail:?} has no enabled backend under proxy.payments.rails")]
    RailNotConfigured {
        /// Advertised rail name.
        rail: String,
    },
    /// A Lightning advertisement had two backends and no selector.
    #[error("proxy.payments.rails configures both lightning_cln and lightning_lnd; set proxy.payments.rails.lightning_backend to `cln` or `lnd` so an advertised lightning rail resolves to exactly one adapter")]
    AmbiguousLightningBackend,
    /// A Lightning backend was selected but its block was absent.
    #[error("proxy.payments.rails.lightning_backend selects {backend:?} but proxy.payments.rails.lightning_{backend} is not configured")]
    LightningBackendNotConfigured {
        /// Selected backend.
        backend: String,
    },
    /// A single route advertised rails priced in different
    /// currencies.
    #[error("advertised rails {left:?} and {right:?} are priced in {left_currency} and {right_currency}; one challenge cannot mix currencies because the proxy performs no foreign-exchange conversion")]
    MixedQuoteCurrency {
        /// First rail.
        left: String,
        /// Currency of the first rail.
        left_currency: String,
        /// Second rail.
        right: String,
        /// Currency of the second rail.
        right_currency: String,
    },
    /// Payment Auth was configured without the Stripe rail that
    /// settles it.
    #[error("proxy.payments.protocols.payment_auth uses method `stripe`, which settles through proxy.payments.rails.stripe; configure that rail or remove the protocol")]
    PaymentAuthWithoutStripe,
    /// A usage reporter was configured without the provider it
    /// reports to.
    #[error("proxy.payments.usage_reporters.stripe_meter requires proxy.payments.rails.stripe for its API credentials")]
    MeterWithoutStripe,
    /// A configured surface has no compiled adapter in this binary.
    #[error("{surface} is configured, but this binary was not built with the `{feature}` cargo feature; rebuild with that feature or remove the block")]
    MissingFeature {
        /// Dotted path of the configured block.
        surface: String,
        /// The exact cargo feature that compiles it.
        feature: &'static str,
    },
    /// A resolved credential was not the length its algorithm requires.
    #[error("proxy.payments.recovery_encryption.key for key id {key_id:?} resolved to {actual} bytes, but AES-256-GCM requires exactly {expected}")]
    RecoveryKeyLength {
        /// Configured key identifier.
        key_id: String,
        /// Resolved length.
        actual: usize,
        /// Required length.
        expected: usize,
    },
    /// An exact amount conversion could not be performed.
    #[error("{0}")]
    Amount(#[from] AmountConversionError),
}

/// Why an exact micros-to-atomic-unit conversion failed.
///
/// Every variant is a refusal to round. A payment requirement states
/// an amount the payer is asked to authorize, so a conversion that
/// cannot be represented exactly is a configuration error, not a
/// value to be truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AmountConversionError {
    /// The micros amount does not divide evenly into the target unit.
    #[error("{amount_micros} micros does not convert exactly to {decimals} decimal places; the proxy refuses to round a price")]
    Inexact {
        /// Amount that could not be converted.
        amount_micros: u64,
        /// Target decimal places.
        decimals: u8,
    },
    /// The converted amount does not fit in 64 bits.
    #[error("{amount_micros} micros overflows 64 bits at {decimals} decimal places")]
    Overflow {
        /// Amount that could not be converted.
        amount_micros: u64,
        /// Target decimal places.
        decimals: u8,
    },
    /// The declared decimal count is not one this conversion
    /// supports.
    #[error("{decimals} decimal places is outside the supported range 0 through {MAX_SETTLEMENT_DECIMALS}")]
    UnsupportedDecimals {
        /// Configured decimals.
        decimals: u8,
    },
    /// A zero price cannot be settled.
    #[error("a payment requirement cannot be issued for a zero amount")]
    ZeroAmount,
}

/// Largest settlement decimal count the exact conversion supports.
///
/// Eleven covers BTC priced in millisatoshis, the deepest unit any
/// pinned rail uses, while keeping the multiplier inside `u64`.
pub const MAX_SETTLEMENT_DECIMALS: u8 = 11;

// --- Exact amount conversion ---

/// Convert a positive quote amount in micros into the atomic-unit
/// integer string a provider expects.
///
/// Micros are 1e-6 of the quote currency. `decimals` is the target
/// unit's depth: `2` yields cents, `6` yields micro-units, `11` yields
/// millisatoshis. The arithmetic is entirely integer and every step is
/// checked. A remainder is an error rather than a rounding, and an
/// overflow is an error rather than a wrap.
///
/// This is the only amount conversion in the configuration crate; the
/// billing crate owns the runtime copy that produces the same string
/// for the same inputs.
///
/// # Errors
///
/// Returns [`AmountConversionError`] when the amount is zero, the
/// decimals are unsupported, the conversion leaves a remainder, or the
/// result overflows 64 bits.
///
/// # Examples
///
/// ```
/// use sbproxy_config::payments::settlement_amount;
///
/// // Ten dollars, quoted in micros, converted to Stripe cents.
/// assert_eq!(settlement_amount(10_000_000, 2).unwrap(), "1000");
/// // A price finer than a cent is refused rather than rounded.
/// assert!(settlement_amount(10_000_001, 2).is_err());
/// ```
pub fn settlement_amount(
    amount_micros: u64,
    decimals: u8,
) -> Result<String, AmountConversionError> {
    if amount_micros == 0 {
        return Err(AmountConversionError::ZeroAmount);
    }
    if decimals > MAX_SETTLEMENT_DECIMALS {
        return Err(AmountConversionError::UnsupportedDecimals { decimals });
    }
    const MICRO_DECIMALS: u8 = 6;
    let units = if decimals <= MICRO_DECIMALS {
        let divisor = 10u64.pow(u32::from(MICRO_DECIMALS - decimals));
        if !amount_micros.is_multiple_of(divisor) {
            return Err(AmountConversionError::Inexact {
                amount_micros,
                decimals,
            });
        }
        amount_micros / divisor
    } else {
        let multiplier = 10u64.pow(u32::from(decimals - MICRO_DECIMALS));
        amount_micros
            .checked_mul(multiplier)
            .ok_or(AmountConversionError::Overflow {
                amount_micros,
                decimals,
            })?
    };
    Ok(units.to_string())
}

// --- ISO-4217 ---

/// Minor-unit decimals for the ISO-4217 codes this release prices in.
///
/// Deliberately a closed table. An unknown code has no known minor
/// unit, so the exact conversion above cannot be proven correct for
/// it, and a payment requirement that cannot be proven correct must
/// not be issued. Codes are stored uppercase.
const ISO_4217_DECIMALS: &[(&str, u8)] = &[
    ("AED", 2),
    ("AUD", 2),
    ("BHD", 3),
    ("BIF", 0),
    ("BRL", 2),
    ("CAD", 2),
    ("CHF", 2),
    ("CLP", 0),
    ("CNY", 2),
    ("COP", 2),
    ("CZK", 2),
    ("DKK", 2),
    ("DJF", 0),
    ("EUR", 2),
    ("GBP", 2),
    ("GNF", 0),
    ("HKD", 2),
    ("HUF", 2),
    ("IDR", 2),
    ("ILS", 2),
    ("INR", 2),
    ("IQD", 3),
    ("ISK", 0),
    ("JOD", 3),
    ("JPY", 0),
    ("KES", 2),
    ("KRW", 0),
    ("KWD", 3),
    ("LYD", 3),
    ("MXN", 2),
    ("MYR", 2),
    ("NGN", 2),
    ("NOK", 2),
    ("NZD", 2),
    ("OMR", 3),
    ("PHP", 2),
    ("PLN", 2),
    ("PYG", 0),
    ("RON", 2),
    ("RWF", 0),
    ("SAR", 2),
    ("SEK", 2),
    ("SGD", 2),
    ("THB", 2),
    ("TND", 3),
    ("TRY", 2),
    ("TWD", 2),
    ("UGX", 0),
    ("USD", 2),
    ("VND", 0),
    ("VUV", 0),
    ("XAF", 0),
    ("XOF", 0),
    ("XPF", 0),
    ("ZAR", 2),
];

/// Minor-unit decimals ISO-4217 defines for `code`, or `None` when the
/// code is outside the built-in table.
///
/// The lookup is case-insensitive; the caller normalizes storage.
#[must_use]
pub fn iso_4217_decimals(code: &str) -> Option<u8> {
    let upper = code.trim().to_ascii_uppercase();
    ISO_4217_DECIMALS
        .iter()
        .find(|(name, _)| *name == upper)
        .map(|(_, decimals)| *decimals)
}

// --- Validation ---

impl PaymentsConfig {
    /// The exact Cargo features this configuration needs from the
    /// running binary, in a stable order and with no duplicates.
    ///
    /// The configuration crate carries no `cfg` of its own, matching
    /// the rest of the schema: it always parses every block so
    /// `sbproxy validate` reads the same document on any build. The
    /// consumer compares this list against its own compiled feature
    /// set and fails startup naming the first missing entry, so a
    /// configured rail that was not compiled in is a boot failure
    /// rather than a first-request surprise.
    #[must_use]
    pub fn required_features(&self) -> Vec<&'static str> {
        let mut features: Vec<&'static str> = Vec::new();
        for (_, feature) in self.required_feature_surfaces() {
            if !features.contains(&feature) {
                features.push(feature);
            }
        }
        features
    }

    /// Every configured surface paired with the Cargo feature that
    /// compiles it, in a stable order.
    ///
    /// This is the mapping [`Self::check_compiled_features`] reports
    /// against, so a startup failure can name both the block the
    /// operator wrote and the feature the binary is missing.
    #[must_use]
    pub fn required_feature_surfaces(&self) -> Vec<(&'static str, &'static str)> {
        let mut surfaces = vec![("proxy.payments", "payments")];
        if self.protocols.payment_auth.is_some() {
            surfaces.push(("proxy.payments.protocols.payment_auth", "payment-mpp"));
        }
        if self.rails.x402.is_some() {
            surfaces.push(("proxy.payments.rails.x402", "payment-x402"));
        }
        if self.rails.stripe.is_some() {
            surfaces.push(("proxy.payments.rails.stripe", "payment-stripe"));
        }
        if self.usage_reporters.stripe_meter.is_some() {
            surfaces.push((
                "proxy.payments.usage_reporters.stripe_meter",
                "payment-stripe",
            ));
        }
        if self.rails.lightning_cln.is_some() {
            surfaces.push((
                "proxy.payments.rails.lightning_cln",
                "payment-lightning-cln",
            ));
        }
        if self.rails.lightning_lnd.is_some() {
            surfaces.push((
                "proxy.payments.rails.lightning_lnd",
                "payment-lightning-lnd",
            ));
        }
        surfaces
    }

    /// Check this configuration against the features the running binary
    /// was compiled with.
    ///
    /// The configuration crate carries no `cfg` of its own, so it cannot
    /// know what is compiled in; the consumer passes its own feature set
    /// here during runtime assembly and fails startup on the first gap.
    /// Doing it at startup rather than at first request is the whole
    /// point: a rail that was never compiled must not be discovered by a
    /// payer who is holding a challenge the proxy cannot honour.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::MissingFeature`] naming the first
    /// configured surface whose feature is absent.
    pub fn check_compiled_features(&self, compiled: &[&str]) -> Result<(), PaymentsConfigError> {
        for (surface, feature) in self.required_feature_surfaces() {
            if !compiled.contains(&feature) {
                return Err(PaymentsConfigError::MissingFeature {
                    surface: surface.to_string(),
                    feature,
                });
            }
        }
        Ok(())
    }

    /// Resolve which Lightning backend an advertised Lightning rail
    /// settles through.
    ///
    /// Returns `None` when neither backend is configured.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::AmbiguousLightningBackend`] when
    /// both backends are configured and no selector was set, and
    /// [`PaymentsConfigError::LightningBackendNotConfigured`] when the
    /// selector names an absent block.
    pub fn lightning_backend(&self) -> Result<Option<LightningBackend>, PaymentsConfigError> {
        let has_cln = self.rails.lightning_cln.is_some();
        let has_lnd = self.rails.lightning_lnd.is_some();
        match (self.rails.lightning_backend, has_cln, has_lnd) {
            (Some(LightningBackend::Cln), true, _) => Ok(Some(LightningBackend::Cln)),
            (Some(LightningBackend::Lnd), _, true) => Ok(Some(LightningBackend::Lnd)),
            (Some(backend), _, _) => Err(PaymentsConfigError::LightningBackendNotConfigured {
                backend: backend.as_str().to_string(),
            }),
            (None, true, true) => Err(PaymentsConfigError::AmbiguousLightningBackend),
            (None, true, false) => Ok(Some(LightningBackend::Cln)),
            (None, false, true) => Ok(Some(LightningBackend::Lnd)),
            (None, false, false) => Ok(None),
        }
    }

    /// The quote currency an advertised rail prices in, or `None`
    /// when the rail has no enabled backend.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::lightning_backend`] for the Lightning rail.
    pub fn quote_currency_for(
        &self,
        rail: AdvertisedRailName,
    ) -> Result<Option<&str>, PaymentsConfigError> {
        Ok(match rail {
            AdvertisedRailName::X402 => self.rails.x402.as_ref().map(|r| r.quote_currency.as_str()),
            AdvertisedRailName::Mpp | AdvertisedRailName::Stripe => self
                .rails
                .stripe
                .as_ref()
                .map(|r| r.quote_currency.as_str()),
            AdvertisedRailName::Lightning => match self.lightning_backend()? {
                Some(LightningBackend::Cln) => self
                    .rails
                    .lightning_cln
                    .as_ref()
                    .map(|r| r.quote_currency.as_str()),
                Some(LightningBackend::Lnd) => self
                    .rails
                    .lightning_lnd
                    .as_ref()
                    .map(|r| r.quote_currency.as_str()),
                None => None,
            },
        })
    }

    /// Check that a route's advertised rail list is servable.
    ///
    /// Every rail must resolve to exactly one enabled backend, and
    /// every rail in one challenge must be priced in the same
    /// currency. The proxy performs no foreign-exchange conversion, so
    /// a mixed-currency challenge would offer the payer a choice
    /// between two different prices for one resource.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::RailNotConfigured`] for a rail
    /// with no backend and [`PaymentsConfigError::MixedQuoteCurrency`]
    /// when two rails disagree on currency.
    pub fn validate_advertised_rails(
        &self,
        rails: &[AdvertisedRailName],
    ) -> Result<(), PaymentsConfigError> {
        let mut anchor: Option<(AdvertisedRailName, &str)> = None;
        for rail in rails {
            let currency = self.quote_currency_for(*rail)?.ok_or_else(|| {
                PaymentsConfigError::RailNotConfigured {
                    rail: rail.as_str().to_string(),
                }
            })?;
            match anchor {
                None => anchor = Some((*rail, currency)),
                Some((left, left_currency)) if !left_currency.eq_ignore_ascii_case(currency) => {
                    return Err(PaymentsConfigError::MixedQuoteCurrency {
                        left: left.as_str().to_string(),
                        left_currency: left_currency.to_string(),
                        right: rail.as_str().to_string(),
                        right_currency: currency.to_string(),
                    });
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// Validate the whole block: shapes, ranges, pins, and the rules
    /// that cross fields.
    ///
    /// Run from `compile_config`, so `sbproxy validate` reports every
    /// one of these before a node boots on them. Nothing here resolves
    /// a secret, touches the filesystem, or contacts a provider.
    ///
    /// # Errors
    ///
    /// Returns the first [`PaymentsConfigError`] the block violates.
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        bounded("state_path", &self.state_path)?;
        absolute_path("state_path", &self.state_path)?;
        secret_reference("challenge_binding_key", &self.challenge_binding_key)?;

        range_u64(
            "authorization_timeout_ms",
            u64::from(self.authorization_timeout_ms),
            1,
            u64::from(MAX_AUTHORIZATION_TIMEOUT_MS),
        )?;
        range_u64(
            "max_body_bytes",
            self.max_body_bytes,
            1,
            MAX_PAYMENT_BODY_BYTES,
        )?;

        self.worker.validate()?;

        if let Some(recovery) = &self.recovery_encryption {
            recovery.validate()?;
        }
        if let Some(protocol) = &self.protocols.payment_auth {
            protocol.validate()?;
            if self.rails.stripe.is_none() {
                return Err(PaymentsConfigError::PaymentAuthWithoutStripe);
            }
        }

        if let Some(x402) = &self.rails.x402 {
            x402.validate(self.authorization_timeout_ms)?;
        }
        if let Some(stripe) = &self.rails.stripe {
            stripe.validate()?;
            // A Stripe dispatch that crashed between the dispatch
            // stamp and the recorded response can only be resolved by
            // replaying the byte-identical create under the same
            // idempotency key. Those bytes contain a single-use
            // payment token in the Payment Auth form, so they are only
            // ever persisted encrypted, which makes the key material a
            // precondition for enabling the rail at all.
            if self.recovery_encryption.is_none() {
                return Err(PaymentsConfigError::RecoveryEncryptionRequired);
            }
        }
        if let Some(cln) = &self.rails.lightning_cln {
            cln.validate()?;
        }
        if let Some(lnd) = &self.rails.lightning_lnd {
            lnd.validate()?;
        }
        // A selector naming an absent block is always wrong. Two
        // configured backends with no selector is not: it becomes
        // ambiguous only when a route actually advertises `lightning`,
        // which is where [`Self::validate_advertised_rails`] catches it.
        // Rejecting it here would refuse a node that configures both
        // backends and advertises neither, which is a legitimate
        // migration state.
        if let Some(backend) = self.rails.lightning_backend {
            let configured = match backend {
                LightningBackend::Cln => self.rails.lightning_cln.is_some(),
                LightningBackend::Lnd => self.rails.lightning_lnd.is_some(),
            };
            if !configured {
                return Err(PaymentsConfigError::LightningBackendNotConfigured {
                    backend: backend.as_str().to_string(),
                });
            }
        }

        if let Some(meter) = &self.usage_reporters.stripe_meter {
            meter.validate()?;
            if self.rails.stripe.is_none() {
                return Err(PaymentsConfigError::MeterWithoutStripe);
            }
        }
        Ok(())
    }
}

impl PaymentsWorkerConfig {
    /// Validate the worker cadence and shutdown budget.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::OutOfRange`] for a zero or
    /// unbounded value.
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        range_u64(
            "worker.reconcile_interval_ms",
            self.reconcile_interval_ms,
            10,
            300_000,
        )?;
        range_u64(
            "worker.max_reconcile_batch",
            u64::from(self.max_reconcile_batch),
            1,
            1_024,
        )?;
        range_u64(
            "worker.shutdown_timeout_ms",
            self.shutdown_timeout_ms,
            100,
            120_000,
        )?;
        Ok(())
    }
}

impl RecoveryEncryptionConfig {
    /// Decoded key length AES-256-GCM requires, in bytes.
    pub const REQUIRED_KEY_BYTES: usize = 32;

    /// Check a resolved key before the rail is allowed to start.
    ///
    /// Structural validation can only see that the field names a
    /// secret. This is the other half, run once at startup after the
    /// secret resolver has produced bytes: a rail whose recovery key is
    /// the wrong length cannot seal an envelope, so it cannot recover a
    /// crashed dispatch, so it must not accept a payment at all.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::RecoveryKeyLength`] for any length
    /// other than [`Self::REQUIRED_KEY_BYTES`].
    pub fn validate_resolved_key(&self, key: &[u8]) -> Result<(), PaymentsConfigError> {
        if key.len() != Self::REQUIRED_KEY_BYTES {
            return Err(PaymentsConfigError::RecoveryKeyLength {
                key_id: self.key_id.clone(),
                actual: key.len(),
                expected: Self::REQUIRED_KEY_BYTES,
            });
        }
        Ok(())
    }

    /// Validate the key id, the secret reference, and the hard expiry.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError`] when the key id is unusable,
    /// the key is inline, or the expiry is outside
    /// [`RECOVERY_MAX_AGE_HOURS_RANGE`].
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        bounded("recovery_encryption.key_id", &self.key_id)?;
        secret_reference("recovery_encryption.key", &self.key)?;
        range_u64(
            "recovery_encryption.max_age_hours",
            u64::from(self.max_age_hours),
            u64::from(RECOVERY_MAX_AGE_HOURS_RANGE.0),
            u64::from(RECOVERY_MAX_AGE_HOURS_RANGE.1),
        )?;
        Ok(())
    }
}

impl PaymentAuthProtocolConfig {
    /// Validate the pinned draft, method, and intent, plus the realm.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::Pinned`] for any token outside
    /// the single registered pair.
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        pinned(
            "protocols.payment_auth.draft",
            &self.draft,
            PAYMENT_AUTH_DRAFT,
        )?;
        pinned(
            "protocols.payment_auth.method",
            &self.method,
            PAYMENT_AUTH_METHOD,
        )?;
        pinned(
            "protocols.payment_auth.intent",
            &self.intent,
            PAYMENT_AUTH_INTENT,
        )?;
        bounded("protocols.payment_auth.realm", &self.realm)?;
        // The realm is the first slot of the challenge binding and is
        // quoted verbatim into a header field value, so a quote or a
        // backslash in it would let a realm forge a second parameter.
        if self.realm.contains('"') || self.realm.contains('\\') {
            return Err(PaymentsConfigError::Value {
                field: "protocols.payment_auth.realm".to_string(),
            });
        }
        Ok(())
    }
}

impl X402RailConfig {
    /// Validate the x402 rail against the pinned v2 `exact` contract.
    ///
    /// `authorization_timeout_ms` is the total request-path budget the
    /// per-call timeouts must fit inside.
    ///
    /// # Errors
    ///
    /// Returns the first [`PaymentsConfigError`] the rail violates.
    pub fn validate(&self, authorization_timeout_ms: u32) -> Result<(), PaymentsConfigError> {
        pinned("rails.x402.scheme", &self.scheme, X402_SCHEME)?;
        if !is_caip2(&self.network) {
            return Err(PaymentsConfigError::NotCaip2 {
                actual: self.network.clone(),
            });
        }
        bounded("rails.x402.asset", &self.asset)?;
        bounded("rails.x402.pay_to", &self.pay_to)?;
        currency_code("rails.x402.quote_currency", &self.quote_currency)?;
        range_u64(
            "rails.x402.asset_decimals",
            u64::from(self.asset_decimals),
            0,
            u64::from(MAX_SETTLEMENT_DECIMALS),
        )?;
        range_u64(
            "rails.x402.max_timeout_seconds",
            u64::from(self.max_timeout_seconds),
            u64::from(X402_MAX_TIMEOUT_SECONDS_RANGE.0),
            u64::from(X402_MAX_TIMEOUT_SECONDS_RANGE.1),
        )?;

        // The extra object is copied verbatim into the signed
        // requirement and echoed back by the client, so its canonical
        // encoding has to be small enough to compare and store on the
        // request path.
        let encoded = serde_json_canonicalizer::to_vec(&self.extra).map_err(|_| {
            PaymentsConfigError::Value {
                field: "rails.x402.extra".to_string(),
            }
        })?;
        if encoded.len() > MAX_X402_EXTRA_JCS_BYTES {
            return Err(PaymentsConfigError::ExtraTooLarge {
                actual: encoded.len(),
            });
        }

        if self.facilitators.is_empty() {
            return Err(PaymentsConfigError::Value {
                field: "rails.x402.facilitators".to_string(),
            });
        }
        for (index, facilitator) in self.facilitators.iter().enumerate() {
            validate_facilitator_url(index, &facilitator.facilitator_url)?;
        }

        range_u64(
            "rails.x402.verify_timeout_ms",
            u64::from(self.verify_timeout_ms),
            1,
            u64::from(MAX_AUTHORIZATION_TIMEOUT_MS),
        )?;
        range_u64(
            "rails.x402.settle_timeout_ms",
            u64::from(self.settle_timeout_ms),
            1,
            u64::from(MAX_AUTHORIZATION_TIMEOUT_MS),
        )?;
        let sum = u64::from(self.verify_timeout_ms) + u64::from(self.settle_timeout_ms);
        if sum > u64::from(authorization_timeout_ms) {
            return Err(PaymentsConfigError::TimeoutSumExceedsBudget {
                sum,
                budget: u64::from(authorization_timeout_ms),
            });
        }
        self.breaker.validate("rails.x402.breaker")?;
        Ok(())
    }
}

impl BreakerConfig {
    /// Validate the breaker bounds.
    ///
    /// `field` is the dotted path this breaker sits at, so the error
    /// names the rail it belongs to.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::OutOfRange`] for a threshold of
    /// zero, an open window outside [`BREAKER_OPEN_MS_RANGE`], or a
    /// half-open budget other than 1.
    pub fn validate(&self, field: &str) -> Result<(), PaymentsConfigError> {
        range_u64(
            &format!("{field}.failure_threshold"),
            u64::from(self.failure_threshold),
            1,
            1_024,
        )?;
        range_u64(
            &format!("{field}.open_ms"),
            self.open_ms,
            BREAKER_OPEN_MS_RANGE.0,
            BREAKER_OPEN_MS_RANGE.1,
        )?;
        // Exactly one probe. A second concurrent probe against a
        // facilitator that is still unhealthy can dispatch a settle
        // whose response nobody is waiting to record, which is the one
        // outcome the state machine cannot resolve without a manual
        // reconciliation.
        range_u64(
            &format!("{field}.half_open_max"),
            u64::from(self.half_open_max),
            1,
            1,
        )?;
        Ok(())
    }
}

impl StripeRailConfig {
    /// Validate the Stripe rail against the pinned API version and
    /// account policy.
    ///
    /// # Errors
    ///
    /// Returns the first [`PaymentsConfigError`] the rail violates.
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        secret_reference("rails.stripe.api_key", &self.api_key)?;
        pinned(
            "rails.stripe.api_version",
            &self.api_version,
            STRIPE_API_VERSION,
        )?;
        pinned(
            "rails.stripe.account_context",
            &self.account_context,
            "platform",
        )?;
        bounded(
            "rails.stripe.business_network_id",
            &self.business_network_id,
        )?;
        currency_code("rails.stripe.quote_currency", &self.quote_currency)?;

        let expected = iso_4217_decimals(&self.quote_currency).ok_or_else(|| {
            PaymentsConfigError::UnknownCurrency {
                field: "rails.stripe.quote_currency".to_string(),
                actual: self.quote_currency.clone(),
            }
        })?;
        if expected != self.currency_decimals {
            return Err(PaymentsConfigError::CurrencyDecimalsMismatch {
                field: "rails.stripe.currency_decimals".to_string(),
                currency: self.quote_currency.to_ascii_uppercase(),
                actual: self.currency_decimals,
                expected,
            });
        }

        if self.payment_method_types.is_empty() {
            return Err(PaymentsConfigError::Value {
                field: "rails.stripe.payment_method_types".to_string(),
            });
        }
        for (index, method) in self.payment_method_types.iter().enumerate() {
            bounded(
                &format!("rails.stripe.payment_method_types[{index}]"),
                method,
            )?;
        }
        if let Some(direct) = &self.direct_payment_intent {
            pinned(
                "rails.stripe.direct_payment_intent.capture_method",
                &direct.capture_method,
                "manual",
            )?;
        }
        Ok(())
    }
}

impl LightningClnRailConfig {
    /// Validate the Core Lightning rail.
    ///
    /// # Errors
    ///
    /// Returns the first [`PaymentsConfigError`] the rail violates,
    /// including [`PaymentsConfigError::ClnVersionTooLow`] when the
    /// configured floor sits below the release whose documented
    /// behaviour this adapter reads.
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        bounded("rails.lightning_cln.socket_path", &self.socket_path)?;
        absolute_path("rails.lightning_cln.socket_path", &self.socket_path)?;
        secret_reference("rails.lightning_cln.rune", &self.rune)?;
        currency_code("rails.lightning_cln.quote_currency", &self.quote_currency)?;
        range_u64(
            "rails.lightning_cln.settlement_decimals",
            u64::from(self.settlement_decimals),
            0,
            u64::from(MAX_SETTLEMENT_DECIMALS),
        )?;
        range_u64(
            "rails.lightning_cln.invoice_expiry_seconds",
            u64::from(self.invoice_expiry_seconds),
            u64::from(INVOICE_EXPIRY_SECONDS_RANGE.0),
            u64::from(INVOICE_EXPIRY_SECONDS_RANGE.1),
        )?;

        let parsed =
            parse_major_minor(&self.minimum_version).ok_or_else(|| PaymentsConfigError::Value {
                field: "rails.lightning_cln.minimum_version".to_string(),
            })?;
        if parsed < MIN_CLN_VERSION {
            return Err(PaymentsConfigError::ClnVersionTooLow {
                actual: self.minimum_version.clone(),
                major: MIN_CLN_VERSION.0,
                minor: MIN_CLN_VERSION.1,
            });
        }
        Ok(())
    }
}

impl LightningLndRailConfig {
    /// Validate the LND rail.
    ///
    /// The endpoint, TLS certificate, and macaroon are all required:
    /// an LND connection without any one of them cannot be
    /// established, and discovering that at first payment would fail a
    /// paid request rather than a boot.
    ///
    /// # Errors
    ///
    /// Returns the first [`PaymentsConfigError`] the rail violates.
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        bounded("rails.lightning_lnd.endpoint", &self.endpoint)?;
        if !self.endpoint.starts_with("https://") {
            return Err(PaymentsConfigError::Value {
                field: "rails.lightning_lnd.endpoint".to_string(),
            });
        }
        bounded(
            "rails.lightning_lnd.tls_certificate_path",
            &self.tls_certificate_path,
        )?;
        absolute_path(
            "rails.lightning_lnd.tls_certificate_path",
            &self.tls_certificate_path,
        )?;
        secret_reference("rails.lightning_lnd.macaroon", &self.macaroon)?;
        currency_code("rails.lightning_lnd.quote_currency", &self.quote_currency)?;
        range_u64(
            "rails.lightning_lnd.settlement_decimals",
            u64::from(self.settlement_decimals),
            0,
            u64::from(MAX_SETTLEMENT_DECIMALS),
        )?;
        range_u64(
            "rails.lightning_lnd.invoice_expiry_seconds",
            u64::from(self.invoice_expiry_seconds),
            u64::from(INVOICE_EXPIRY_SECONDS_RANGE.0),
            u64::from(INVOICE_EXPIRY_SECONDS_RANGE.1),
        )?;
        Ok(())
    }
}

impl StripeMeterReporterConfig {
    /// Validate the meter event and customer field names.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentsConfigError::Value`] for an unusable name.
    pub fn validate(&self) -> Result<(), PaymentsConfigError> {
        bounded("usage_reporters.stripe_meter.event_name", &self.event_name)?;
        bounded(
            "usage_reporters.stripe_meter.customer_field",
            &self.customer_field,
        )?;
        Ok(())
    }
}

// --- Field helpers ---

/// Reject an empty, oversized, or control-character-bearing scalar.
fn bounded(field: &str, value: &str) -> Result<(), PaymentsConfigError> {
    if value.trim().is_empty()
        || value.len() > MAX_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(PaymentsConfigError::Value {
            field: field.to_string(),
        });
    }
    Ok(())
}

/// Reject a relative path.
fn absolute_path(field: &str, value: &str) -> Result<(), PaymentsConfigError> {
    if !std::path::Path::new(value.trim()).is_absolute() {
        return Err(PaymentsConfigError::NotAbsolutePath {
            field: field.to_string(),
        });
    }
    Ok(())
}

/// Reject a credential carried inline rather than named.
fn secret_reference(field: &str, value: &str) -> Result<(), PaymentsConfigError> {
    bounded(field, value)?;
    if !crate::types::is_secret_reference(value) {
        return Err(PaymentsConfigError::InlineSecret {
            field: field.to_string(),
        });
    }
    Ok(())
}

/// Reject a value outside an inclusive numeric range.
fn range_u64(field: &str, value: u64, min: u64, max: u64) -> Result<(), PaymentsConfigError> {
    if value < min || value > max {
        return Err(PaymentsConfigError::OutOfRange {
            field: field.to_string(),
            value,
            min,
            max,
        });
    }
    Ok(())
}

/// Reject any value other than the one this release implements.
fn pinned(field: &str, actual: &str, expected: &str) -> Result<(), PaymentsConfigError> {
    if actual != expected {
        return Err(PaymentsConfigError::Pinned {
            field: field.to_string(),
            actual: actual.to_string(),
            expected: expected.to_string(),
        });
    }
    Ok(())
}

/// Reject anything that is not a three-letter uppercase currency code.
fn currency_code(field: &str, value: &str) -> Result<(), PaymentsConfigError> {
    let trimmed = value.trim();
    if trimmed.len() != 3 || !trimmed.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(PaymentsConfigError::Value {
            field: field.to_string(),
        });
    }
    Ok(())
}

/// Parse a `major.minor` version, ignoring any further components.
fn parse_major_minor(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.trim().split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.trim_start_matches('0');
    let minor = if minor.is_empty() {
        0
    } else {
        minor.parse::<u32>().ok()?
    };
    Some((major, minor))
}

/// Whether `value` is a CAIP-2 chain identifier.
///
/// The grammar is `namespace:reference`, where the namespace is 3 to 8
/// lowercase alphanumerics or hyphens and the reference is 1 to 32
/// characters from the unreserved set. Anything looser would let a
/// short chain nickname through, and a nickname resolved by a
/// translation table is not something a signed payment requirement can
/// commit to.
fn is_caip2(value: &str) -> bool {
    let Some((namespace, reference)) = value.split_once(':') else {
        return false;
    };
    let namespace_ok = (3..=8).contains(&namespace.len())
        && namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let reference_ok = (1..=32).contains(&reference.len())
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    namespace_ok && reference_ok
}

/// Validate a facilitator API root.
///
/// The configured value is the facilitator's complete API root, not a
/// host. Every path segment is preserved and only trailing slashes are
/// stripped, so a provider that serves its API under `/base` gets
/// `/base/verify` and `/base/settle` and nothing else. A root that
/// already names an endpoint is rejected rather than normalized:
/// appending `/verify` to `.../verify` would silently produce a path
/// no facilitator serves, and the request would fail closed at the
/// worst possible moment.
fn validate_facilitator_url(index: usize, value: &str) -> Result<(), PaymentsConfigError> {
    let reject = |reason: &str| PaymentsConfigError::FacilitatorUrl {
        index,
        reason: reason.to_string(),
    };
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_VALUE_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err(reject("must be a bounded, non-empty value"));
    }
    let Some(rest) = trimmed.strip_prefix("https://") else {
        return Err(reject(
            "must be an absolute https:// URL; TLS 1.2 or newer is required for a public \
             facilitator endpoint",
        ));
    };
    if rest.is_empty() {
        return Err(reject("must name a host"));
    }
    if trimmed.contains('?') {
        return Err(reject("must not carry a query string"));
    }
    if trimmed.contains('#') {
        return Err(reject("must not carry a fragment"));
    }
    // Userinfo would put a credential in a value that is copied into
    // the signed requirement and echoed back by the client.
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        return Err(reject("must not carry userinfo"));
    }
    if authority.is_empty() {
        return Err(reject("must name a host"));
    }
    let path = &rest[authority_end..];
    let normalized = path.trim_end_matches('/');
    for endpoint in ["/verify", "/settle"] {
        if normalized.ends_with(endpoint) {
            return Err(reject(
                "is the facilitator's API root, not an endpoint; drop the trailing \
                 /verify or /settle segment",
            ));
        }
    }
    if normalized.contains("//") {
        return Err(reject("must not contain an empty path segment"));
    }
    if normalized
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(reject(
            "must not contain a relative path segment that could change the joined origin",
        ));
    }
    Ok(())
}

// --- serde defaults ---

const fn default_authorization_timeout_ms() -> u32 {
    MAX_AUTHORIZATION_TIMEOUT_MS
}

const fn default_max_body_bytes() -> u64 {
    MAX_PAYMENT_BODY_BYTES
}

const fn default_recovery_max_age_hours() -> u8 {
    RECOVERY_MAX_AGE_HOURS_RANGE.1
}

fn default_payment_auth_draft() -> String {
    PAYMENT_AUTH_DRAFT.to_string()
}

fn default_payment_auth_method() -> String {
    PAYMENT_AUTH_METHOD.to_string()
}

fn default_payment_auth_intent() -> String {
    PAYMENT_AUTH_INTENT.to_string()
}

fn default_x402_scheme() -> String {
    X402_SCHEME.to_string()
}

const fn default_x402_verify_timeout_ms() -> u32 {
    700
}

const fn default_x402_settle_timeout_ms() -> u32 {
    1_200
}

fn default_stripe_api_version() -> String {
    STRIPE_API_VERSION.to_string()
}

fn default_account_context() -> String {
    "platform".to_string()
}

fn default_capture_method() -> String {
    "manual".to_string()
}

fn default_cln_minimum_version() -> String {
    format!("{}.{:02}", MIN_CLN_VERSION.0, MIN_CLN_VERSION.1)
}

const fn default_invoice_expiry_seconds() -> u32 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `expect_err` requires `Debug` on the success type. Several
    /// values in this module deliberately do not carry a blanket
    /// `Debug` in the crates that consume them, so the tests unwrap
    /// errors through this helper rather than widening a derive to
    /// suit a test.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn exact_conversion_matches_each_pinned_settlement_unit() {
        // Ten dollars into Stripe cents.
        assert_eq!(settlement_amount(10_000_000, 2).unwrap(), "1000");
        // One micro-unit of a six-decimal stablecoin.
        assert_eq!(settlement_amount(1, 6).unwrap(), "1");
        // One BTC into millisatoshis.
        assert_eq!(settlement_amount(1_000_000, 11).unwrap(), "100000000000");
        // A zero-decimal currency.
        assert_eq!(settlement_amount(3_000_000, 0).unwrap(), "3");
    }

    #[test]
    fn conversion_refuses_to_round_or_wrap() {
        assert_eq!(
            expect_error(
                settlement_amount(10_000_001, 2),
                "a fractional cent must not round"
            ),
            AmountConversionError::Inexact {
                amount_micros: 10_000_001,
                decimals: 2,
            }
        );
        assert_eq!(
            expect_error(settlement_amount(1, 0), "a sub-unit price must not round"),
            AmountConversionError::Inexact {
                amount_micros: 1,
                decimals: 0,
            }
        );
        assert!(matches!(
            expect_error(
                settlement_amount(u64::MAX, 11),
                "an overflowing conversion must fail"
            ),
            AmountConversionError::Overflow { .. }
        ));
        assert!(matches!(
            expect_error(settlement_amount(1_000, 12), "12 decimals is unsupported"),
            AmountConversionError::UnsupportedDecimals { decimals: 12 }
        ));
        assert!(matches!(
            expect_error(settlement_amount(0, 2), "a zero price cannot settle"),
            AmountConversionError::ZeroAmount
        ));
    }

    #[test]
    fn iso_table_is_closed_and_case_insensitive() {
        assert_eq!(iso_4217_decimals("usd"), Some(2));
        assert_eq!(iso_4217_decimals("JPY"), Some(0));
        assert_eq!(iso_4217_decimals("KWD"), Some(3));
        // BTC is not an ISO-4217 code; the Lightning rails declare
        // their own settlement decimals instead.
        assert_eq!(iso_4217_decimals("BTC"), None);
        assert_eq!(iso_4217_decimals("ZZZ"), None);
    }

    #[test]
    fn caip2_rejects_short_chain_names() {
        assert!(is_caip2("eip155:84532"));
        assert!(is_caip2("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"));
        assert!(!is_caip2("base"));
        assert!(!is_caip2("eip155"));
        assert!(!is_caip2("EIP155:1"));
        assert!(!is_caip2("ab:1"));
        assert!(!is_caip2("eip155:"));
    }

    #[test]
    fn facilitator_root_preserves_prefix_and_rejects_endpoints() {
        assert!(validate_facilitator_url(0, "https://facilitator.example/base/").is_ok());
        assert!(validate_facilitator_url(0, "https://facilitator.example").is_ok());
        for bad in [
            "http://facilitator.example",
            "https://user:pass@facilitator.example",
            "https://facilitator.example/api?v=2",
            "https://facilitator.example/api#frag",
            "https://facilitator.example/api/verify",
            "https://facilitator.example/api/settle/",
            "https://facilitator.example/api/../other",
            "facilitator.example",
        ] {
            assert!(
                validate_facilitator_url(0, bad).is_err(),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn major_minor_parses_the_documented_cln_form() {
        assert_eq!(parse_major_minor("26.06"), Some((26, 6)));
        assert_eq!(parse_major_minor("26.11"), Some((26, 11)));
        assert_eq!(parse_major_minor("27.0"), Some((27, 0)));
        assert_eq!(parse_major_minor("26"), None);
        assert_eq!(parse_major_minor("v26.06"), None);
    }

    // --- Document-level suite ---
    //
    // Every case below starts from one reference document and changes
    // exactly one thing, so a failure names the rule that broke rather
    // than the document that drifted.

    /// The reference `proxy.payments` document.
    const REFERENCE: &str = r#"
state_path: /var/lib/sbproxy/payments.sqlite3
challenge_binding_key: secret://env/SBPROXY_PAYMENT_BINDING_KEY
authorization_timeout_ms: 2000
max_body_bytes: 1048576
recovery_encryption:
  key_id: payments-2026-07
  key: secret://env/SBPROXY_PAYMENT_RECOVERY_KEY
  max_age_hours: 23
worker:
  reconcile_interval_ms: 1000
  max_reconcile_batch: 32
  shutdown_timeout_ms: 5000
protocols:
  payment_auth:
    draft: draft-ryan-httpauth-payment-01
    realm: api.example.com
    method: stripe
    intent: charge
rails:
  x402:
    scheme: exact
    network: "eip155:84532"
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    quote_currency: USD
    asset_decimals: 6
    pay_to: "0x1111111111111111111111111111111111111111"
    max_timeout_seconds: 60
    extra:
      name: USDC
      version: "2"
    facilitators:
      - facilitator_url: https://facilitator.example/api
    verify_timeout_ms: 700
    settle_timeout_ms: 1200
    breaker:
      failure_threshold: 3
      open_ms: 5000
      half_open_max: 1
  stripe:
    api_key: secret://env/STRIPE_SECRET_KEY
    api_version: 2026-06-24.dahlia
    account_context: platform
    business_network_id: profile_test_example
    quote_currency: USD
    currency_decimals: 2
    payment_method_types: [card]
    direct_payment_intent:
      enabled: true
      capture_method: manual
  lightning_cln:
    socket_path: /run/lightning/lightning-rpc
    rune: secret://env/CLN_RUNE
    minimum_version: "26.06"
    quote_currency: BTC
    settlement_decimals: 11
    invoice_expiry_seconds: 300
  lightning_lnd:
    endpoint: https://lnd.internal:10009
    tls_certificate_path: /run/secrets/lnd/tls.cert
    macaroon: secret://env/LND_MACAROON_HEX
    quote_currency: BTC
    settlement_decimals: 11
    invoice_expiry_seconds: 300
usage_reporters:
  stripe_meter:
    event_name: sbproxy_ai_tokens
    customer_field: stripe_customer_id
"#;

    /// The reference document, parsed but not yet validated.
    #[track_caller]
    fn document() -> serde_yaml::Value {
        serde_yaml::from_str(REFERENCE).expect("the reference document parses")
    }

    /// Overwrites one nested key, creating nothing on the way.
    #[track_caller]
    fn set(document: &mut serde_yaml::Value, path: &[&str], value: serde_yaml::Value) {
        let (last, parents) = path.split_last().expect("a non-empty path");
        let mut cursor = document;
        for key in parents {
            cursor = cursor
                .get_mut(*key)
                .unwrap_or_else(|| panic!("path segment {key} exists in the reference"));
        }
        cursor
            .as_mapping_mut()
            .unwrap_or_else(|| panic!("path parent of {last} is a mapping"))
            .insert(serde_yaml::Value::String((*last).to_string()), value);
    }

    /// Parses a mutated document into a config, or reports why it could
    /// not be parsed at all.
    #[track_caller]
    fn parse(document: serde_yaml::Value) -> Result<PaymentsConfig, String> {
        serde_yaml::from_value(document).map_err(|error| error.to_string())
    }

    /// The reference config, parsed and known to validate.
    #[track_caller]
    fn reference_config() -> PaymentsConfig {
        let config = parse(document()).expect("the reference document deserializes");
        config.validate().expect("the reference document validates");
        config
    }

    /// Applies one change and returns the validation outcome.
    #[track_caller]
    fn validate_with(path: &[&str], value: serde_yaml::Value) -> Result<(), PaymentsConfigError> {
        let mut mutated = document();
        set(&mut mutated, path, value);
        match parse(mutated) {
            // A parse failure is also a load failure, and every case
            // below only cares that the document was refused. Mapping it
            // onto a typed value keeps the assertions uniform.
            Err(_) => Err(PaymentsConfigError::Value {
                field: path.join("."),
            }),
            Ok(config) => config.validate(),
        }
    }

    #[test]
    fn the_reference_document_covers_every_provider_and_validates() {
        let config = reference_config();
        assert!(config.protocols.payment_auth.is_some());
        assert!(config.rails.x402.is_some());
        assert!(config.rails.stripe.is_some());
        assert!(config.rails.lightning_cln.is_some());
        assert!(config.rails.lightning_lnd.is_some());
        assert!(config.usage_reporters.stripe_meter.is_some());
        assert_eq!(config.authorization_timeout_ms, 2_000);
        assert_eq!(config.max_body_bytes, 1_048_576);
    }

    #[test]
    fn absent_payments_leaves_the_proxy_block_unchanged() {
        // The whole point of the block being optional: a document that
        // never mentions payments keeps the existing ledger behaviour,
        // and nothing in this module runs at all.
        let proxy = crate::types::ProxyServerConfig::default();
        assert!(proxy.payments.is_none());
    }

    #[test]
    fn the_authorization_budget_stops_at_two_seconds() {
        assert!(validate_with(&["authorization_timeout_ms"], 2_000.into()).is_ok());
        assert!(matches!(
            expect_error(
                validate_with(&["authorization_timeout_ms"], 2_001.into()),
                "a budget above the ceiling must be refused"
            ),
            PaymentsConfigError::OutOfRange { .. }
        ));
        assert!(matches!(
            expect_error(
                validate_with(&["authorization_timeout_ms"], 0.into()),
                "a zero budget must be refused"
            ),
            PaymentsConfigError::OutOfRange { .. }
        ));
    }

    #[test]
    fn the_body_cap_is_positive_and_bounded() {
        assert!(matches!(
            expect_error(
                validate_with(&["max_body_bytes"], 0.into()),
                "a zero body cap must be refused"
            ),
            PaymentsConfigError::OutOfRange { .. }
        ));
        assert!(matches!(
            expect_error(
                validate_with(&["max_body_bytes"], (MAX_PAYMENT_BODY_BYTES + 1).into()),
                "a body cap above the proxy limit must be refused"
            ),
            PaymentsConfigError::OutOfRange { .. }
        ));
    }

    #[test]
    fn the_stripe_api_version_is_pinned() {
        assert!(matches!(
            expect_error(
                validate_with(
                    &["rails", "stripe", "api_version"],
                    "2025-01-01.acacia".into()
                ),
                "an unpinned Stripe version must be refused"
            ),
            PaymentsConfigError::Pinned { .. }
        ));
        assert_eq!(STRIPE_API_VERSION, "2026-06-24.dahlia");
    }

    #[test]
    fn stripe_connect_routing_is_not_reachable_from_configuration() {
        // Only `platform`. A destination account that could be selected
        // from anywhere other than server-owned config would let a payer
        // choose who gets paid.
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "stripe", "account_context"], "acct_1234".into()),
                "a Connect account context must be refused"
            ),
            PaymentsConfigError::Pinned { .. }
        ));
    }

    #[test]
    fn the_stripe_rail_requires_recoverable_dispatch_material() {
        assert!(matches!(
            expect_error(
                validate_with(&["recovery_encryption"], serde_yaml::Value::Null),
                "the Stripe rail without recovery encryption must be refused"
            ),
            PaymentsConfigError::RecoveryEncryptionRequired
        ));
        for hours in [0u64, 24, 255] {
            assert!(
                matches!(
                    expect_error(
                        validate_with(&["recovery_encryption", "max_age_hours"], hours.into()),
                        "an out of range recovery expiry must be refused"
                    ),
                    PaymentsConfigError::OutOfRange { .. }
                ),
                "expected {hours} hours to be refused"
            );
        }
        assert!(matches!(
            expect_error(
                validate_with(
                    &["recovery_encryption", "key"],
                    "sk_live_inline_not_a_reference".into()
                ),
                "an inline recovery key must be refused"
            ),
            PaymentsConfigError::InlineSecret { .. }
        ));
    }

    #[test]
    fn the_recovery_key_must_resolve_to_exactly_thirty_two_bytes() {
        let config = reference_config();
        let recovery = config
            .recovery_encryption
            .as_ref()
            .expect("the reference configures recovery encryption");
        assert!(recovery.validate_resolved_key(&[7u8; 32]).is_ok());
        for length in [0usize, 16, 31, 33, 64] {
            let error = expect_error(
                recovery.validate_resolved_key(&vec![7u8; length]),
                "a wrong length recovery key must be refused",
            );
            assert!(
                matches!(error, PaymentsConfigError::RecoveryKeyLength { actual, .. } if actual == length),
                "expected {length} bytes to be refused"
            );
        }
    }

    #[test]
    fn every_credential_field_names_a_secret() {
        for path in [
            vec!["challenge_binding_key"],
            vec!["rails", "stripe", "api_key"],
            vec!["rails", "lightning_cln", "rune"],
            vec!["rails", "lightning_lnd", "macaroon"],
        ] {
            let error = expect_error(
                validate_with(&path, "an-inline-credential".into()),
                "an inline credential must be refused",
            );
            assert!(
                matches!(error, PaymentsConfigError::InlineSecret { .. }),
                "expected {} to require a secret reference",
                path.join(".")
            );
        }
    }

    #[test]
    fn the_x402_network_must_be_caip2_and_the_asset_must_be_named() {
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "network"], "base".into()),
                "a short chain name must be refused"
            ),
            PaymentsConfigError::NotCaip2 { .. }
        ));
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "asset"], "".into()),
                "an empty asset must be refused"
            ),
            PaymentsConfigError::Value { .. }
        ));
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "pay_to"], "".into()),
                "an empty recipient must be refused"
            ),
            PaymentsConfigError::Value { .. }
        ));
    }

    #[test]
    fn the_x402_scheme_timeout_and_extra_are_bounded() {
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "scheme"], "upto".into()),
                "an unimplemented scheme must be refused"
            ),
            PaymentsConfigError::Pinned { .. }
        ));
        for seconds in [0u64, 3_601] {
            assert!(
                matches!(
                    expect_error(
                        validate_with(&["rails", "x402", "max_timeout_seconds"], seconds.into()),
                        "an out of range scheme timeout must be refused"
                    ),
                    PaymentsConfigError::OutOfRange { .. }
                ),
                "expected {seconds} seconds to be refused"
            );
        }

        let mut oversized = serde_yaml::Mapping::new();
        oversized.insert(
            serde_yaml::Value::String("blob".to_string()),
            serde_yaml::Value::String("x".repeat(MAX_X402_EXTRA_JCS_BYTES + 1)),
        );
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "extra"], oversized.into()),
                "an oversized extra object must be refused"
            ),
            PaymentsConfigError::ExtraTooLarge { .. }
        ));
    }

    #[test]
    fn the_x402_extra_object_keeps_deterministic_jcs_bytes() {
        // The client echoes this object back and the proxy compares it
        // exactly, so its canonical encoding has to be stable across a
        // reparse and independent of the order the operator wrote it in.
        let config = reference_config();
        let x402 = config.rails.x402.as_ref().expect("the reference has x402");
        let canonical = serde_json_canonicalizer::to_vec(&x402.extra).expect("extra canonicalizes");
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            r#"{"name":"USDC","version":"2"}"#
        );

        let mut reordered = document();
        let mut swapped = serde_yaml::Mapping::new();
        swapped.insert(
            serde_yaml::Value::String("version".to_string()),
            serde_yaml::Value::String("2".to_string()),
        );
        swapped.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String("USDC".to_string()),
        );
        set(&mut reordered, &["rails", "x402", "extra"], swapped.into());
        let reordered = parse(reordered).expect("the reordered document deserializes");
        let other = reordered.rails.x402.as_ref().expect("x402 survives");
        assert_eq!(
            serde_json_canonicalizer::to_vec(&x402.extra).unwrap(),
            serde_json_canonicalizer::to_vec(&other.extra).unwrap()
        );
    }

    #[test]
    fn the_facilitator_root_is_a_root_over_tls_with_no_credentials() {
        for (bad, why) in [
            ("http://facilitator.example", "cleartext"),
            ("https://user:pass@facilitator.example", "userinfo"),
            ("https://facilitator.example/api?v=2", "a query"),
            ("https://facilitator.example/api#frag", "a fragment"),
            (
                "https://facilitator.example/api/verify",
                "an endpoint suffix",
            ),
            (
                "https://facilitator.example/api/settle/",
                "an endpoint suffix",
            ),
        ] {
            let mut candidate = serde_yaml::Mapping::new();
            candidate.insert(
                serde_yaml::Value::String("facilitator_url".to_string()),
                serde_yaml::Value::String(bad.to_string()),
            );
            let error = expect_error(
                validate_with(
                    &["rails", "x402", "facilitators"],
                    serde_yaml::Value::Sequence(vec![candidate.into()]),
                ),
                "an unusable facilitator root must be refused",
            );
            assert!(
                matches!(error, PaymentsConfigError::FacilitatorUrl { .. }),
                "expected {why} to be refused"
            );
        }

        assert!(matches!(
            expect_error(
                validate_with(
                    &["rails", "x402", "facilitators"],
                    serde_yaml::Value::Sequence(Vec::new())
                ),
                "a rail with no facilitator must be refused"
            ),
            PaymentsConfigError::Value { .. }
        ));
    }

    #[test]
    fn the_x402_timeouts_must_fit_the_authorization_budget() {
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "settle_timeout_ms"], 1_500.into()),
                "per-call budgets above the total must be refused"
            ),
            PaymentsConfigError::TimeoutSumExceedsBudget { .. }
        ));
        // The sum may exactly equal the budget.
        let mut exact = document();
        set(
            &mut exact,
            &["rails", "x402", "verify_timeout_ms"],
            800.into(),
        );
        set(
            &mut exact,
            &["rails", "x402", "settle_timeout_ms"],
            1_200.into(),
        );
        parse(exact)
            .expect("the document deserializes")
            .validate()
            .expect("a sum equal to the budget is allowed");
    }

    #[test]
    fn the_breaker_bounds_permit_exactly_one_probe() {
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "breaker", "failure_threshold"], 0.into()),
                "a zero threshold must be refused"
            ),
            PaymentsConfigError::OutOfRange { .. }
        ));
        for open_ms in [99u64, 60_001] {
            assert!(
                matches!(
                    expect_error(
                        validate_with(&["rails", "x402", "breaker", "open_ms"], open_ms.into()),
                        "an out of range open window must be refused"
                    ),
                    PaymentsConfigError::OutOfRange { .. }
                ),
                "expected {open_ms} ms to be refused"
            );
        }
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "x402", "breaker", "half_open_max"], 2.into()),
                "a second concurrent probe must be refused"
            ),
            PaymentsConfigError::OutOfRange { .. }
        ));
    }

    #[test]
    fn the_stripe_currency_decimals_are_checked_against_iso_4217() {
        assert!(matches!(
            expect_error(
                validate_with(&["rails", "stripe", "currency_decimals"], 0.into()),
                "a mis-declared minor unit must be refused"
            ),
            PaymentsConfigError::CurrencyDecimalsMismatch { .. }
        ));
        let mut unknown = document();
        set(
            &mut unknown,
            &["rails", "stripe", "quote_currency"],
            "ZZZ".into(),
        );
        assert!(matches!(
            expect_error(
                parse(unknown).expect("it deserializes").validate(),
                "an unknown currency must be refused"
            ),
            PaymentsConfigError::UnknownCurrency { .. }
        ));
    }

    #[test]
    fn direct_payment_intent_capture_is_manual_only() {
        // Challenge preparation must not capture funds, so an automatic
        // capture PaymentIntent cannot be advertised.
        assert!(matches!(
            expect_error(
                validate_with(
                    &["rails", "stripe", "direct_payment_intent", "capture_method"],
                    "automatic".into()
                ),
                "automatic capture must be refused"
            ),
            PaymentsConfigError::Pinned { .. }
        ));
    }

    #[test]
    fn the_cln_socket_is_absolute_and_the_version_floor_holds() {
        assert!(matches!(
            expect_error(
                validate_with(
                    &["rails", "lightning_cln", "socket_path"],
                    "run/lightning/lightning-rpc".into()
                ),
                "a relative socket path must be refused"
            ),
            PaymentsConfigError::NotAbsolutePath { .. }
        ));
        assert!(matches!(
            expect_error(
                validate_with(
                    &["rails", "lightning_cln", "minimum_version"],
                    "25.12".into()
                ),
                "a version below the adapter floor must be refused"
            ),
            PaymentsConfigError::ClnVersionTooLow { .. }
        ));
        // At or above the floor is fine.
        for version in ["26.06", "26.11", "27.02"] {
            assert!(
                validate_with(
                    &["rails", "lightning_cln", "minimum_version"],
                    version.into()
                )
                .is_ok(),
                "expected {version} to be accepted"
            );
        }
    }

    #[test]
    fn invoice_expiry_is_bounded_on_both_lightning_rails() {
        for backend in ["lightning_cln", "lightning_lnd"] {
            for seconds in [29u64, 86_401] {
                let error = expect_error(
                    validate_with(
                        &["rails", backend, "invoice_expiry_seconds"],
                        seconds.into(),
                    ),
                    "an out of range invoice expiry must be refused",
                );
                assert!(
                    matches!(error, PaymentsConfigError::OutOfRange { .. }),
                    "expected {backend} at {seconds} seconds to be refused"
                );
            }
        }
    }

    #[test]
    fn the_lnd_rail_requires_all_three_connection_inputs() {
        // Discovering any of these missing at first payment would fail a
        // paid request rather than a boot.
        assert!(matches!(
            expect_error(
                validate_with(
                    &["rails", "lightning_lnd", "endpoint"],
                    "lnd.internal:10009".into()
                ),
                "a non-TLS endpoint must be refused"
            ),
            PaymentsConfigError::Value { .. }
        ));
        assert!(matches!(
            expect_error(
                validate_with(
                    &["rails", "lightning_lnd", "tls_certificate_path"],
                    "tls.cert".into()
                ),
                "a relative certificate path must be refused"
            ),
            PaymentsConfigError::NotAbsolutePath { .. }
        ));
        for required in ["endpoint", "tls_certificate_path", "macaroon"] {
            let mut missing = document();
            set(
                &mut missing,
                &["rails", "lightning_lnd", required],
                serde_yaml::Value::Null,
            );
            assert!(
                parse(missing).is_err(),
                "expected a missing {required} to fail to deserialize"
            );
        }
    }

    #[test]
    fn payment_auth_is_pinned_to_one_draft_method_and_intent() {
        for (field, value) in [
            ("draft", "draft-ryan-httpauth-payment-02"),
            ("method", "paypal"),
            ("intent", "subscribe"),
        ] {
            let error = expect_error(
                validate_with(&["protocols", "payment_auth", field], value.into()),
                "an unregistered draft, method, or intent must be refused",
            );
            assert!(
                matches!(error, PaymentsConfigError::Pinned { .. }),
                "expected {field} = {value} to be refused"
            );
        }
        // The realm is quoted verbatim into a header field value and is
        // the first binding slot, so it cannot carry a quote.
        assert!(matches!(
            expect_error(
                validate_with(
                    &["protocols", "payment_auth", "realm"],
                    "api\", x=\"".into()
                ),
                "a realm that could forge a parameter must be refused"
            ),
            PaymentsConfigError::Value { .. }
        ));
    }

    #[test]
    fn payment_auth_and_the_meter_both_require_the_stripe_rail() {
        let mut without_stripe = document();
        set(
            &mut without_stripe,
            &["rails", "stripe"],
            serde_yaml::Value::Null,
        );
        set(
            &mut without_stripe,
            &["usage_reporters", "stripe_meter"],
            serde_yaml::Value::Null,
        );
        assert!(matches!(
            expect_error(
                parse(without_stripe).expect("it deserializes").validate(),
                "Payment Auth without its settlement rail must be refused"
            ),
            PaymentsConfigError::PaymentAuthWithoutStripe
        ));

        let mut meter_only = document();
        set(
            &mut meter_only,
            &["rails", "stripe"],
            serde_yaml::Value::Null,
        );
        set(
            &mut meter_only,
            &["protocols", "payment_auth"],
            serde_yaml::Value::Null,
        );
        assert!(matches!(
            expect_error(
                parse(meter_only).expect("it deserializes").validate(),
                "a meter with no Stripe credentials must be refused"
            ),
            PaymentsConfigError::MeterWithoutStripe
        ));
    }

    #[test]
    fn every_advertised_rail_resolves_to_exactly_one_backend() {
        let config = reference_config();
        // Two backends configured is fine on its own. Advertising the
        // lightning rail with no selector is where it becomes ambiguous.
        assert!(matches!(
            expect_error(
                config.validate_advertised_rails(&[AdvertisedRailName::Lightning]),
                "an ambiguous lightning advertisement must be refused"
            ),
            PaymentsConfigError::AmbiguousLightningBackend
        ));

        let mut selected = document();
        set(&mut selected, &["rails", "lightning_backend"], "cln".into());
        let selected = parse(selected).expect("it deserializes");
        selected.validate().expect("a selector validates");
        assert_eq!(
            selected.lightning_backend().unwrap(),
            Some(LightningBackend::Cln)
        );

        // A selector naming an absent block is always wrong.
        let mut orphan = document();
        set(
            &mut orphan,
            &["rails", "lightning_lnd"],
            serde_yaml::Value::Null,
        );
        set(&mut orphan, &["rails", "lightning_backend"], "lnd".into());
        assert!(matches!(
            expect_error(
                parse(orphan).expect("it deserializes").validate(),
                "a selector naming an absent backend must be refused"
            ),
            PaymentsConfigError::LightningBackendNotConfigured { .. }
        ));
    }

    #[test]
    fn advertising_a_rail_with_no_backend_is_refused() {
        let mut no_x402 = document();
        set(&mut no_x402, &["rails", "x402"], serde_yaml::Value::Null);
        let no_x402 = parse(no_x402).expect("it deserializes");
        no_x402
            .validate()
            .expect("the rest of the document is fine");
        assert!(matches!(
            expect_error(
                no_x402.validate_advertised_rails(&[AdvertisedRailName::X402]),
                "advertising an unconfigured rail must be refused"
            ),
            PaymentsConfigError::RailNotConfigured { .. }
        ));
    }

    #[test]
    fn one_challenge_cannot_mix_quote_currencies() {
        let mut selected = document();
        set(&mut selected, &["rails", "lightning_backend"], "cln".into());
        let config = parse(selected).expect("it deserializes");

        // x402 and Stripe both price in USD, so they can share a
        // challenge.
        config
            .validate_advertised_rails(&[
                AdvertisedRailName::X402,
                AdvertisedRailName::Mpp,
                AdvertisedRailName::Stripe,
            ])
            .expect("one currency across three rails is fine");

        // Lightning prices in BTC, and the proxy performs no
        // foreign-exchange conversion.
        assert!(matches!(
            expect_error(
                config.validate_advertised_rails(&[
                    AdvertisedRailName::X402,
                    AdvertisedRailName::Lightning
                ]),
                "a mixed currency challenge must be refused"
            ),
            PaymentsConfigError::MixedQuoteCurrency { .. }
        ));
    }

    #[test]
    fn a_configured_provider_without_its_feature_fails_startup_by_name() {
        let config = reference_config();
        assert_eq!(
            config.required_features(),
            vec![
                "payments",
                "payment-mpp",
                "payment-x402",
                "payment-stripe",
                "payment-lightning-cln",
                "payment-lightning-lnd",
            ]
        );

        // A binary with everything compiled in starts.
        config
            .check_compiled_features(&config.required_features())
            .expect("a fully featured binary starts");

        // One missing feature names both the block and the feature.
        for missing in config.required_features() {
            let compiled: Vec<&str> = config
                .required_features()
                .into_iter()
                .filter(|feature| *feature != missing)
                .collect();
            let error = expect_error(
                config.check_compiled_features(&compiled),
                "a configured rail with no compiled adapter must fail startup",
            );
            match error {
                PaymentsConfigError::MissingFeature { feature, surface } => {
                    assert_eq!(feature, missing);
                    assert!(
                        surface.starts_with("proxy.payments"),
                        "the failure names the configured block"
                    );
                }
                other => panic!("expected a missing feature error, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_meter_alone_still_needs_the_stripe_feature() {
        // Usage reporting requires the Stripe feature but does not
        // require any route to advertise Stripe.
        let mut meter_only = document();
        set(
            &mut meter_only,
            &["protocols", "payment_auth"],
            serde_yaml::Value::Null,
        );
        set(&mut meter_only, &["rails", "x402"], serde_yaml::Value::Null);
        set(
            &mut meter_only,
            &["rails", "lightning_cln"],
            serde_yaml::Value::Null,
        );
        set(
            &mut meter_only,
            &["rails", "lightning_lnd"],
            serde_yaml::Value::Null,
        );
        let config = parse(meter_only).expect("it deserializes");
        config.validate().expect("a meter plus its rail validates");
        assert_eq!(
            config.required_features(),
            vec!["payments", "payment-stripe"]
        );
    }

    #[test]
    fn an_unknown_key_anywhere_is_refused() {
        // Every block denies unknown fields, so a typo in a key that
        // disables a protection cannot be silently dropped.
        for path in [
            vec!["surprise"],
            vec!["rails", "surprise"],
            vec!["rails", "x402", "surprise"],
            vec!["rails", "stripe", "surprise"],
            vec!["protocols", "payment_auth", "surprise"],
            vec!["worker", "surprise"],
        ] {
            let mut mutated = document();
            set(&mut mutated, &path, true.into());
            assert!(
                parse(mutated).is_err(),
                "expected an unknown key at {} to be refused",
                path.join(".")
            );
        }
    }

    #[test]
    fn the_state_path_must_be_absolute() {
        assert!(matches!(
            expect_error(
                validate_with(&["state_path"], "payments.sqlite3".into()),
                "a relative state path must be refused"
            ),
            PaymentsConfigError::NotAbsolutePath { .. }
        ));
    }

    #[test]
    fn the_worker_cadence_is_bounded() {
        for (field, value) in [
            ("reconcile_interval_ms", 0u64),
            ("reconcile_interval_ms", 300_001),
            ("max_reconcile_batch", 0),
            ("max_reconcile_batch", 2_048),
            ("shutdown_timeout_ms", 0),
            ("shutdown_timeout_ms", 120_001),
        ] {
            let error = expect_error(
                validate_with(&["worker", field], value.into()),
                "an out of range worker setting must be refused",
            );
            assert!(
                matches!(error, PaymentsConfigError::OutOfRange { .. }),
                "expected worker.{field} = {value} to be refused"
            );
        }
    }

    #[test]
    fn the_settlement_conversion_matches_each_configured_rail() {
        let config = reference_config();
        let x402 = config.rails.x402.as_ref().expect("x402 is configured");
        let stripe = config.rails.stripe.as_ref().expect("stripe is configured");
        let cln = config
            .rails
            .lightning_cln
            .as_ref()
            .expect("cln is configured");

        // Ten dollars, quoted in micros, into each rail's own unit.
        assert_eq!(
            settlement_amount(10_000_000, x402.asset_decimals).unwrap(),
            "10000000"
        );
        assert_eq!(
            settlement_amount(10_000_000, stripe.currency_decimals).unwrap(),
            "1000"
        );
        assert_eq!(
            settlement_amount(1_000_000, cln.settlement_decimals).unwrap(),
            "100000000000"
        );

        // A price finer than the rail's unit is refused, never rounded.
        assert!(matches!(
            expect_error(
                settlement_amount(10_000_001, stripe.currency_decimals),
                "a fractional cent must not round"
            ),
            AmountConversionError::Inexact { .. }
        ));
    }
}
