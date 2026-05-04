//! AI Crawl Control policy: emit HTTP 402 challenges and accept payment tokens.
//!
//! Implements the "Pay Per Crawl" pattern: the gateway returns a `402 Payment
//! Required` response with a JSON challenge to AI crawlers that arrive without
//! a valid payment token. The crawler retries with a `Crawler-Payment` header;
//! the policy validates the token through a pluggable [`Ledger`] and allows
//! the request once.
//!
//! The OSS ledger is in-memory: tokens are pre-loaded from config and each
//! token spends exactly once (single-use). When the `http-ledger` feature is
//! enabled, `HttpLedger` talks to a network-callable backend per
//! `docs/adr-http-ledger-protocol.md` (HMAC-signed, idempotent, retried,
//! circuit-broken).
//!
//! When the `tiered-pricing` feature is enabled, [`AiCrawlControlConfig`]
//! accepts a `tiers:` list with per-route pricing, per-shape pricing, a
//! free-preview byte budget, and a paywall position hint per
//! `docs/AIGOVERNANCE-BUILD.md` § G1.2.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// --- Public types ---

/// Outcome of an AI Crawl Control check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiCrawlDecision {
    /// Request is allowed - either it carried a valid payment token or
    /// it does not match the crawler signature.
    Allow,
    /// Request must be charged. The proxy returns 402 with this challenge
    /// body and stamps the configured challenge header. This is the Wave 1
    /// single-rail path that legacy crawlers see when they have not opted
    /// in to multi-rail content negotiation.
    Charge {
        /// JSON body the client receives in the 402 response.
        body: String,
        /// Value to set on the `<challenge_header>` response header.
        challenge: String,
    },
    /// Wave 3 multi-rail challenge. Emitted when the agent opted in via
    /// `Accept-Payment` or one of the multi-rail `Accept` media types
    /// (`application/sbproxy-multi-rail+json`, `application/x402+json`,
    /// `application/mpp+json`). The body is JSON per A3.1 with one rail
    /// entry per offered rail, each carrying its own quote-token JWS.
    MultiRail {
        /// JSON body the client receives in the 402 response.
        body: String,
        /// Content-Type to stamp on the response. Always
        /// `application/sbproxy-multi-rail+json` in Wave 3; pinned
        /// here so the proxy hot path never has to know the literal.
        content_type: &'static str,
    },
    /// Wave 3 multi-rail negotiation produced no overlap between the
    /// agent's `Accept-Payment` list and the route's configured rails.
    /// Per A3.1 the proxy responds `406 Not Acceptable` with the
    /// included body listing the rails the operator does support so
    /// the agent can recover.
    NoAcceptableRail {
        /// JSON body the client receives in the 406 response.
        body: String,
    },
    /// Ledger is temporarily unavailable. The proxy returns 503 with this
    /// JSON body and the indicated `Retry-After` value (seconds). Distinct
    /// from `Charge` so callers can route a transient failure to a
    /// different response code than a deliberate payment challenge.
    LedgerUnavailable {
        /// JSON body returned in the 503 response.
        body: String,
        /// Seconds to put in the `Retry-After` HTTP header.
        retry_after_seconds: u32,
    },
}

/// MIME type for the multi-rail 402 body per A3.1.
pub const MULTI_RAIL_CONTENT_TYPE: &str = "application/sbproxy-multi-rail+json";

/// Closed enum of payment rails the proxy can advertise. Mirrors the
/// `Accept-Payment` token set and the per-tier `rails:` override list.
/// New rails follow the closed-enum amendment rule from
/// `adr-schema-versioning.md` (A1.8). Wave 7 added `Lightning` to mirror
/// the externally-registered rail named `"lightning"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Rail {
    /// x402 v2 (LF stewarded; stablecoin via EIP-3009 transferWithAuthorization).
    X402,
    /// Stripe MPP (`2026-03-04.preview`; multi-method via `payment_intent`).
    Mpp,
    /// Lightning Network rail (Wave 7 A7.4). Settled by an external
    /// BillingRail impl which registers the canonical name `"lightning"`.
    /// The OSS enum carries the variant so policy decisions and
    /// `Accept-Payment` negotiation can reference the rail without
    /// depending on the rail crate.
    Lightning,
}

impl Rail {
    /// Stable string form used in the multi-rail body, the metric label,
    /// and the `Accept-Payment` parser.
    pub fn as_str(self) -> &'static str {
        match self {
            Rail::X402 => "x402",
            Rail::Mpp => "mpp",
            Rail::Lightning => "lightning",
        }
    }

    /// Parse a closed-enum token. Returns `None` for any value outside
    /// the known set; callers translate that to a 406 fallback.
    ///
    /// Named `parse` rather than `from_str` so it does not shadow
    /// [`std::str::FromStr`]; the `Option`-returning shape matches the
    /// `Accept-Payment` parser's "drop unknown tokens" semantics.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "x402" => Some(Rail::X402),
            "mpp" => Some(Rail::Mpp),
            "lightning" => Some(Rail::Lightning),
            _ => None,
        }
    }
}

/// Successful redemption result returned by [`Ledger::redeem`].
///
/// `token_id` is the ledger's own identifier for the redeemed entry
/// (echoes the inbound `token` for `InMemoryLedger`; an opaque
/// `redemption_id` from the ledger backend for `HttpLedger`).
/// `amount_micros` and `currency` describe the price actually charged,
/// drawn from the matched [`Tier`] when tiered pricing is configured or
/// the policy-level price otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemResult {
    /// Stable identifier for this redemption.
    pub token_id: String,
    /// Charged amount in micros of `currency`.
    pub amount_micros: u64,
    /// ISO-4217 currency code (`USD`, `EUR`, ...).
    pub currency: String,
    /// Optional on-chain or off-chain settlement hash from the backend.
    pub txhash: Option<String>,
}

/// Error envelope returned by [`Ledger::redeem`] on any failure.
///
/// `code` is a closed dotted-string set defined in
/// `docs/adr-http-ledger-protocol.md`. `retryable` distinguishes a
/// hard rejection (token already spent, invalid signature) from a
/// transient one (rate limited, ledger unavailable). The policy at
/// the request path maps `retryable=false` to a 402 challenge and
/// `retryable=true` to a 503 with `Retry-After`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("ledger error {code}: {message}")]
pub struct LedgerError {
    /// Machine-readable error code, e.g. `ledger.token_already_spent`.
    pub code: String,
    /// Human-readable description. Safe to log.
    pub message: String,
    /// True when the caller should retry. Mirrors the HTTP envelope.
    pub retryable: bool,
    /// Optional `Retry-After` hint in seconds.
    pub retry_after_seconds: Option<u32>,
}

impl LedgerError {
    /// Build a non-retryable error (the policy should fail closed with 402).
    pub fn hard(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
            retry_after_seconds: None,
        }
    }

    /// Build a retryable error (the policy should emit 503 + Retry-After).
    pub fn transient(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: true,
            retry_after_seconds: None,
        }
    }

    /// Replace this error's `Retry-After` hint.
    pub fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }
}

/// Pluggable validator for `Crawler-Payment` tokens.
///
/// Implementations mark the token spent on success so a single token
/// authorises a single request. See [`InMemoryLedger`] (OSS default) and
/// `HttpLedger` (enabled by the `http-ledger` feature).
pub trait Ledger: Send + Sync + std::fmt::Debug + 'static {
    /// Validate `token` for a request to `(host, path)`.
    ///
    /// Returns [`Ok(RedeemResult)`](RedeemResult) when the token is
    /// well-formed, on the ledger, and not already spent. Returns
    /// [`Err(LedgerError)`](LedgerError) for any failure; the caller
    /// branches on `retryable` to choose between a 402 challenge and a
    /// 503 response.
    ///
    /// `expected_amount_micros` and `expected_currency` come from the
    /// matched [`Tier`] (or the policy-level price). They are advisory
    /// for [`InMemoryLedger`] and authoritative for `HttpLedger`,
    /// which forwards them in the signed `payload`.
    fn redeem(
        &self,
        token: &str,
        host: &str,
        path: &str,
        expected_amount_micros: u64,
        expected_currency: &str,
    ) -> Result<RedeemResult, LedgerError>;
}

/// In-memory ledger backed by a pre-loaded set of valid tokens. Single
/// use: a token that redeems successfully is removed from the set.
#[derive(Debug)]
pub struct InMemoryLedger {
    valid: Mutex<HashSet<String>>,
}

impl InMemoryLedger {
    /// Build a ledger seeded with the given tokens.
    pub fn new(tokens: impl IntoIterator<Item = String>) -> Self {
        Self {
            valid: Mutex::new(tokens.into_iter().collect()),
        }
    }

    /// Number of tokens still available for redemption.
    pub fn remaining(&self) -> usize {
        self.valid.lock().len()
    }
}

impl Ledger for InMemoryLedger {
    fn redeem(
        &self,
        token: &str,
        _host: &str,
        _path: &str,
        expected_amount_micros: u64,
        expected_currency: &str,
    ) -> Result<RedeemResult, LedgerError> {
        let mut set = self.valid.lock();
        if set.remove(token) {
            Ok(RedeemResult {
                token_id: token.to_string(),
                amount_micros: expected_amount_micros,
                currency: expected_currency.to_string(),
                txhash: None,
            })
        } else {
            Err(LedgerError::hard(
                "ledger.token_already_spent",
                "token unknown or already spent",
            ))
        }
    }
}

// --- Tiered pricing types (G1.2) ---

/// Closed enumeration of the content shapes the policy can price for.
///
/// Mirrors the values fixed by `docs/adr-metric-cardinality.md` so the
/// `content_shape` label budget on `sbproxy_requests_total` and the
/// HTTP ledger `payload.content_shape` field share one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentShape {
    /// HTML pages.
    Html,
    /// Markdown documents (often the LLM-friendly projection).
    Markdown,
    /// JSON envelope, including JSON-LD.
    Json,
    /// PDF documents.
    Pdf,
    /// Anything else; intentionally a closed catch-all to keep the
    /// metric label budget bounded.
    Other,
}

impl ContentShape {
    /// Stable string form used in the challenge body, the metric
    /// label, and the HTTP ledger payload.
    pub fn as_str(self) -> &'static str {
        match self {
            ContentShape::Html => "html",
            ContentShape::Markdown => "markdown",
            ContentShape::Json => "json",
            ContentShape::Pdf => "pdf",
            ContentShape::Other => "other",
        }
    }
}

/// Where the paywall sits inside the rendered response. Carried in the
/// challenge body so a cooperative crawler can decide whether to pay
/// for the full document or accept the free-preview prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaywallPosition {
    /// Paywall replaces the entire body. Free preview, if any, is
    /// served as a separate excerpt before the paywall response.
    TopOfPage,
    /// Free preview is served inline, then the paywall HTML / JSON
    /// follows in the same response body.
    Inline,
    /// Paywall is rendered at the bottom of the page, after the full
    /// (or near-full) free preview. Discouraged for high-value content.
    BottomOfPage,
}

/// Currency-aware money amount. Stored in micros (1e-6 of the currency
/// unit) so `f64` rounding never enters the path. `u64` saturates at
/// 18 trillion units which is comfortably above any plausible price.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Money {
    /// Amount in micros of `currency`.
    pub amount_micros: u64,
    /// ISO-4217 currency code (`USD`, `EUR`, ...).
    pub currency: String,
}

impl Money {
    /// Build a money value from a unit amount (e.g. `0.001` USD) and a
    /// currency code. Rounds to micros via `(amount * 1e6).round()`.
    pub fn from_units(amount: f64, currency: impl Into<String>) -> Self {
        let micros = if amount <= 0.0 {
            0
        } else {
            (amount * 1_000_000.0).round() as u64
        };
        Self {
            amount_micros: micros,
            currency: currency.into(),
        }
    }

    /// Render the price as a decimal string in major units, e.g. `0.001000`.
    pub fn to_units_string(&self) -> String {
        let major = (self.amount_micros / 1_000_000) as f64;
        let minor = (self.amount_micros % 1_000_000) as f64 / 1_000_000.0;
        format!("{:.6}", major + minor)
    }
}

/// One pricing tier: a route pattern and the price + shape + preview
/// behaviour it triggers when matched. The first tier whose pattern
/// matches the request path wins; later tiers act as fallbacks.
///
/// `route_pattern` is a Wave 1 prefix matcher. A trailing `*` matches
/// any suffix (e.g. `/articles/*`); an exact pattern matches only that
/// path. Future waves may layer regex / template support without
/// changing the wire shape.
#[derive(Debug, Clone, Deserialize)]
pub struct Tier {
    /// Path matcher. Supports literal paths and a `*` suffix wildcard.
    pub route_pattern: String,
    /// Price for any request this tier matches.
    pub price: Money,
    /// Optional shape selector. When set, the tier only matches if the
    /// request's negotiated content shape (resolved via `Accept` header
    /// in a follow-up wave; for now the policy treats this as advisory)
    /// equals the configured value.
    #[serde(default)]
    pub content_shape: Option<ContentShape>,
    /// Optional agent-id selector. When set, the tier only matches if
    /// the request's resolved `agent_id` (G1.4 resolver chain) equals
    /// the configured value. Supports the reserved sentinels `human`,
    /// `unknown`, `anonymous` (per G1.1 taxonomy) plus any vendor id
    /// the registry feed (G2.1) returns. Empty string = wildcard.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Optional free-preview byte budget. The crawler may read up to
    /// this many bytes of the response without paying. Wired into the
    /// challenge body so cooperative crawlers can decide up front.
    #[serde(default)]
    pub free_preview_bytes: Option<u64>,
    /// Optional paywall position hint surfaced to the crawler.
    #[serde(default)]
    pub paywall_position: Option<PaywallPosition>,
    /// Optional per-tier rail override (G3.4 / A3.1). When set, the tier
    /// offers only the listed rails; when unset, the tier inherits the
    /// policy-level default (every rail configured under
    /// `ai_crawl_control.rails:`). The closed enum is the same set as
    /// the agent's `Accept-Payment` header so adding a third rail goes
    /// through the A1.8 deprecation window.
    #[serde(default)]
    pub rails: Option<Vec<Rail>>,
    /// Per-tier citation requirement (G4.4 + G4.10 closeout). When the
    /// tier resolver matches a request, this flag is written into
    /// `RequestContext::citation_required` so downstream transforms
    /// (`citation_block`, `json_envelope`) can read a single source of
    /// truth instead of carrying their own copies of the flag. Per-tier
    /// so the value can vary by route and shape (e.g. require
    /// attribution on the Markdown projection but not on raw HTML).
    /// Default `false` keeps existing fixtures unchanged.
    #[serde(default)]
    pub citation_required: bool,
}

impl Tier {
    /// Returns true when this tier's `route_pattern` matches `path`.
    pub fn matches_path(&self, path: &str) -> bool {
        if let Some(prefix) = self.route_pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            self.route_pattern == path
        }
    }

    /// Returns true when this tier accepts the supplied `agent_id`.
    /// A `None` selector matches any agent. A `Some("")` selector also
    /// matches any agent (operator-friendly wildcard). Otherwise the
    /// selector must equal `agent_id` exactly.
    pub fn matches_agent(&self, agent_id: &str) -> bool {
        match &self.agent_id {
            None => true,
            Some(s) if s.is_empty() => true,
            Some(s) => s == agent_id,
        }
    }

    /// Returns true when this tier accepts the supplied `Accept` header.
    ///
    /// A `None` `content_shape` selector matches any shape (wildcard).
    /// A `Some(_)` selector must match the shape parsed from the
    /// `Accept` header. When the header is absent or unparseable, the
    /// selector matches any tier without an explicit `content_shape`
    /// and skips tiers that demand a specific shape. This keeps the
    /// hot-path lean: a malformed Accept does not steer routing, it
    /// silently falls through to the path-only catch-all.
    pub fn matches_shape(&self, accept: Option<&str>) -> bool {
        match self.content_shape {
            None => true,
            Some(want) => {
                let Some(accept_str) = accept else {
                    return false;
                };
                ContentShape::from_accept(accept_str)
                    .map(|got| got == want)
                    .unwrap_or(false)
            }
        }
    }
}

impl ContentShape {
    /// Best-effort `Accept` header parser. Returns the first recognised
    /// shape from the comma-separated media-type list. Quality factors
    /// are ignored; the first match wins. Unrecognised values yield
    /// `None`, which the caller treats as "no shape preference".
    ///
    /// The vocabulary is the closed `ContentShape` enum so the parser
    /// stays allocation-free on the hot path: each branch is a static
    /// substring test and there is no fallback to `Other`. Operators
    /// who want to price `Other` can omit `content_shape` on the tier.
    pub fn from_accept(accept: &str) -> Option<Self> {
        for raw in accept.split(',') {
            // Strip parameters (`;q=0.8`, `;charset=utf-8`).
            let media = raw.split(';').next().unwrap_or("").trim();
            // Case-insensitive comparison without allocation: media
            // types are 7-bit ASCII so eq_ignore_ascii_case is safe.
            if media.eq_ignore_ascii_case("text/html")
                || media.eq_ignore_ascii_case("application/xhtml+xml")
            {
                return Some(ContentShape::Html);
            }
            if media.eq_ignore_ascii_case("text/markdown")
                || media.eq_ignore_ascii_case("text/x-markdown")
            {
                return Some(ContentShape::Markdown);
            }
            if media.eq_ignore_ascii_case("application/json")
                || media.eq_ignore_ascii_case("application/ld+json")
            {
                return Some(ContentShape::Json);
            }
            if media.eq_ignore_ascii_case("application/pdf") {
                return Some(ContentShape::Pdf);
            }
        }
        None
    }
}

// --- Content-Signal header value (G4.5) ---

/// Closed enumeration of valid `Content-Signal` response header values.
///
/// Mirrors the value set fixed in
/// `docs/adr-content-negotiation-and-pricing.md` § "Content-Signal
/// response header" (G4.1). The proxy stamps `Content-Signal: <value>`
/// on 200 responses when the origin's `content_signal:` config key is
/// set; the value vocabulary is closed per A1.8 so any unknown value
/// fails config compilation.
///
/// The header is a cooperative signal for standards-compliant crawlers
/// and a mandatory field surfaced by the JSON envelope (A4.2). It is
/// not security-critical; a motivated crawler can ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentSignal {
    /// Content is licensed for AI training (per operator's RSL terms).
    AiTrain,
    /// Content may be indexed for search but not used for training.
    Search,
    /// Content may be used as model input (inference) but not for training.
    AiInput,
}

impl ContentSignal {
    /// Stable wire-form string used in the response header value, the
    /// projection metadata, and the JSON envelope.
    pub fn as_str(self) -> &'static str {
        match self {
            ContentSignal::AiTrain => "ai-train",
            ContentSignal::Search => "search",
            ContentSignal::AiInput => "ai-input",
        }
    }
}

impl std::fmt::Display for ContentSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ContentSignal {
    type Err = ContentSignalParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ai-train" => Ok(ContentSignal::AiTrain),
            "search" => Ok(ContentSignal::Search),
            "ai-input" => Ok(ContentSignal::AiInput),
            other => Err(ContentSignalParseError {
                value: other.to_string(),
            }),
        }
    }
}

impl serde::Serialize for ContentSignal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ContentSignal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse()
            .map_err(|e: ContentSignalParseError| serde::de::Error::custom(e.to_string()))
    }
}

/// Error returned when a string fails to parse into a [`ContentSignal`].
///
/// Carries the offending value so config-load errors point at the
/// exact YAML token. Used by the `RawOriginConfig` content-signal
/// field validator to fail config compilation per A1.8 closed-enum
/// rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentSignalParseError {
    /// The offending value as it appeared in the source YAML.
    pub value: String,
}

impl std::fmt::Display for ContentSignalParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid content_signal value {:?}: must be one of ai-train, search, ai-input",
            self.value
        )
    }
}

impl std::error::Error for ContentSignalParseError {}

// --- Multi-rail challenge body (A3.1) ---

/// One entry in the multi-rail 402 body's `rails` array.
///
/// Common fields (`amount_micros`, `currency`, `expires_at`, `quote_token`)
/// live alongside the rail-specific extension fields under the same JSON
/// shape pinned in `docs/adr-multi-rail-402-challenge.md`. The enum
/// representation uses the closed `kind` discriminator from A1.8 so a future
/// third rail can land without breaking existing parsers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RailChallenge {
    /// x402 v2 challenge entry. Carries the chain, facilitator URL, asset
    /// (USDC, USDT, ...), and the merchant address that the agent's
    /// EIP-3009 signed authorization must pay into.
    X402 {
        /// Wire-protocol version. `"2"` for x402 v2 in Wave 3.
        version: String,
        /// Chain identifier (`base`, `solana`, `eth-l2`, ...).
        chain: String,
        /// Facilitator URL the agent posts the signed authorization to.
        facilitator: String,
        /// Stablecoin asset (`USDC`, `USDT`, ...).
        asset: String,
        /// Price in micros of `currency`.
        amount_micros: u64,
        /// ISO-4217 currency code mirrored across all rail entries.
        currency: String,
        /// Merchant address on `chain`.
        pay_to: String,
        /// RFC 3339 expiry mirroring the quote-token TTL.
        expires_at: String,
        /// Per-rail quote-token JWS (G3.6 / A3.2).
        quote_token: String,
    },
    /// MPP / Stripe challenge entry. Carries the placeholder
    /// `payment_intent` id; real PI creation happens in the worker.
    Mpp {
        /// Wire-protocol version. `"1"` for MPP in Wave 3.
        version: String,
        /// Stripe `pi_*` identifier the agent confirms against. Wave 3
        /// emits a placeholder id; G3.3's worker replaces it with the
        /// real PI on the redeem path.
        stripe_payment_intent: String,
        /// Price in micros of `currency`.
        amount_micros: u64,
        /// ISO-4217 currency code mirrored across all rail entries.
        currency: String,
        /// RFC 3339 expiry mirroring the quote-token TTL.
        expires_at: String,
        /// Per-rail quote-token JWS (G3.6 / A3.2).
        quote_token: String,
    },
}

impl RailChallenge {
    /// Discriminator: the rail this entry belongs to.
    pub fn rail(&self) -> Rail {
        match self {
            RailChallenge::X402 { .. } => Rail::X402,
            RailChallenge::Mpp { .. } => Rail::Mpp,
        }
    }

    /// The quote-token JWS embedded in the entry. Useful for tests that
    /// want to verify each rail entry has a distinct nonce.
    pub fn quote_token(&self) -> &str {
        match self {
            RailChallenge::X402 { quote_token, .. } => quote_token,
            RailChallenge::Mpp { quote_token, .. } => quote_token,
        }
    }
}

/// Top-level multi-rail 402 body per A3.1. Serialised with
/// `Content-Type: application/sbproxy-multi-rail+json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiRailChallenge {
    /// One entry per offered rail. Empty array is invalid; the proxy MUST
    /// emit at least one rail or fall back to the Wave 1 single-rail format.
    pub rails: Vec<RailChallenge>,
    /// Currently always `"header_negotiation"`; reserved for future
    /// `out_of_band` and `wallet_handshake` values.
    pub agent_choice_method: String,
    /// Currently always `"first_match_wins"`; reserved for future
    /// `cheapest_wins` and `operator_choice` values.
    pub policy: String,
}

impl MultiRailChallenge {
    /// Serialise to the wire JSON shape pinned by A3.1.
    pub fn to_json(&self) -> String {
        // serde_json::to_string is sufficient here; the body is small (one
        // entry per rail) and the proxy hot path already allocates a body
        // string for the existing Wave 1 path.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Parsed agent preference set from the `Accept-Payment` header (or the
/// equivalent multi-rail `Accept` MIME types per A3.1's opt-in rules).
///
/// `None` means the agent did not opt in: the proxy serves the Wave 1
/// single-rail format. `Some(set)` means the agent opted in; the proxy
/// filters its configured rails through `set` and emits the multi-rail
/// body. An empty inner set (after parsing a header that listed only
/// unknown tokens) is a 406 fallback; the proxy responds with the rails
/// it does support so the agent can recover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRailPreferences {
    /// Ordered, de-duplicated list of rails the agent will accept. Order
    /// reflects the agent's q-value preference; the proxy uses this to
    /// sort the emitted rail entries.
    pub accepted: Vec<Rail>,
    /// True when at least one closed-enum token in the source header was
    /// outside the Wave 3 set. Distinct from `accepted.is_empty()`
    /// because an empty `accepted` after seeing an unknown rail is the
    /// 406 case, while an absent header is the Wave 1 fallback.
    pub had_unknown: bool,
}

/// Parse the `Accept-Payment` header value into a preference set.
///
/// Returns `None` when the header is absent or empty. The parser follows
/// the Accept-style q-value syntax pinned in A3.1: comma-separated tokens,
/// each optionally followed by `;q=<float>` parameters. Tokens outside
/// the closed `Rail` enum are recorded in `had_unknown` and dropped from
/// `accepted`.
pub fn parse_accept_payment(header: Option<&str>) -> Option<AgentRailPreferences> {
    let raw = header?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut entries: Vec<(Rail, f32, usize)> = Vec::new();
    let mut had_unknown = false;
    for (idx, segment) in trimmed.split(',').enumerate() {
        let mut parts = segment.split(';');
        let rail_token = parts.next().unwrap_or("").trim();
        if rail_token.is_empty() {
            continue;
        }
        let mut q = 1.0f32;
        for param in parts {
            let p = param.trim();
            if let Some(rest) = p.strip_prefix("q=") {
                if let Ok(parsed) = rest.parse::<f32>() {
                    q = parsed.clamp(0.0, 1.0);
                }
            }
        }
        match Rail::parse(rail_token) {
            Some(r) => entries.push((r, q, idx)),
            None => had_unknown = true,
        }
    }
    // Sort: q desc, then declaration order (stable for q ties so operator
    // preference order breaks them in the caller's combined sort).
    entries.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.2.cmp(&b.2))
    });
    let mut seen = std::collections::HashSet::new();
    let mut accepted = Vec::with_capacity(entries.len());
    for (rail, _, _) in entries {
        if seen.insert(rail) {
            accepted.push(rail);
        }
    }
    Some(AgentRailPreferences {
        accepted,
        had_unknown,
    })
}

/// Examine the request `Accept` header(s) and decide whether the agent
/// opted in to the multi-rail body via a content negotiation MIME.
///
/// Per A3.1 any of `application/sbproxy-multi-rail+json`,
/// `application/x402+json`, or `application/mpp+json` counts as an opt-in.
/// The MIME-type opt-in is independent of the `Accept-Payment` header; an
/// agent that sends `Accept: application/x402+json` without
/// `Accept-Payment` still gets the multi-rail body, filtered to only the
/// x402 entry.
pub fn accept_implies_multi_rail(accept: Option<&str>) -> Option<AgentRailPreferences> {
    let raw = accept?;
    let mut accepted = Vec::new();
    let mut any_match = false;
    for segment in raw.split(',') {
        let media = segment.split(';').next().unwrap_or("").trim();
        if media.eq_ignore_ascii_case("application/sbproxy-multi-rail+json") {
            // Multi-rail catch-all: the agent will accept any rail.
            return Some(AgentRailPreferences {
                accepted: vec![Rail::X402, Rail::Mpp],
                had_unknown: false,
            });
        }
        if media.eq_ignore_ascii_case("application/x402+json") {
            if !accepted.contains(&Rail::X402) {
                accepted.push(Rail::X402);
            }
            any_match = true;
        } else if media.eq_ignore_ascii_case("application/mpp+json") {
            if !accepted.contains(&Rail::Mpp) {
                accepted.push(Rail::Mpp);
            }
            any_match = true;
        }
    }
    if any_match {
        Some(AgentRailPreferences {
            accepted,
            had_unknown: false,
        })
    } else {
        None
    }
}

/// Combine `Accept-Payment` and `Accept` MIME-type opt-ins. Returns the
/// merged preference set or `None` when neither header opts the agent in.
/// The merge keeps the order from `Accept-Payment` (which carries
/// q-values) and only adds `Accept`-derived rails that were not already
/// present.
pub fn resolve_agent_preferences(
    accept_payment: Option<&str>,
    accept: Option<&str>,
) -> Option<AgentRailPreferences> {
    let from_ap = parse_accept_payment(accept_payment);
    let from_accept = accept_implies_multi_rail(accept);
    match (from_ap, from_accept) {
        (None, None) => None,
        (Some(ap), None) => Some(ap),
        (None, Some(a)) => Some(a),
        (Some(mut ap), Some(a)) => {
            for r in a.accepted {
                if !ap.accepted.contains(&r) {
                    ap.accepted.push(r);
                }
            }
            ap.had_unknown |= a.had_unknown;
            Some(ap)
        }
    }
}

// --- Config + compiled policy ---

/// Operator-supplied configuration for the x402 rail. Pins the chain,
/// asset, facilitator URL, and merchant `pay_to` address that the proxy
/// stamps into each x402 entry of a multi-rail 402 body.
///
/// Wave 3 ships a single x402 instance per origin; multi-chain support
/// (separate Base + Solana entries in one challenge) is a Wave 4 follow-up
/// that will widen this to a list. The single-instance shape is the right
/// floor: every operator who wants to advertise x402 needs exactly these
/// fields.
#[derive(Debug, Clone, Deserialize)]
pub struct X402RailYamlConfig {
    /// Chain identifier (`base`, `solana`, `eth-l2`).
    pub chain: String,
    /// Facilitator URL the agent posts the signed authorization to.
    pub facilitator: String,
    /// Stablecoin asset (`USDC`, `USDT`, ...).
    #[serde(default = "default_x402_asset")]
    pub asset: String,
    /// Merchant address on `chain` that receives the settled payment.
    pub pay_to: String,
    /// Wire-protocol version. Defaults to `"2"` (x402 v2).
    #[serde(default = "default_x402_version")]
    pub version: String,
}

fn default_x402_asset() -> String {
    "USDC".to_string()
}

fn default_x402_version() -> String {
    "2".to_string()
}

/// Operator-supplied configuration for the MPP rail. Wave 3 just needs
/// the version pin; the actual `pi_*` identifier is generated at redeem
/// time by G3.3's worker. This struct is here so the YAML schema has a
/// stable place to grow into when MPP gains operator-tunable knobs.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MppRailYamlConfig {
    /// Wire-protocol version. Defaults to `"1"`.
    #[serde(default = "default_mpp_version")]
    pub version: String,
}

fn default_mpp_version() -> String {
    "1".to_string()
}

/// Operator config block selecting which rails to advertise plus per-rail
/// settings. Lives under the `ai_crawl_control.rails:` key.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RailsYamlConfig {
    /// Optional x402 configuration. When absent, x402 is not offered.
    #[serde(default)]
    pub x402: Option<X402RailYamlConfig>,
    /// Optional MPP configuration. When absent, MPP is not offered.
    #[serde(default)]
    pub mpp: Option<MppRailYamlConfig>,
}

/// Operator-supplied quote-token signing material. The proxy needs the
/// active key to sign tokens; the JWKS endpoint serves the public half.
#[derive(Debug, Clone, Deserialize)]
pub struct QuoteTokenYamlConfig {
    /// Key id stamped into the JWS header. The verifier looks up the
    /// matching public key in the JWKS by this id.
    pub key_id: String,
    /// 32-byte Ed25519 seed, hex-encoded. Convenient for dev / test;
    /// production deployments use `secret_ref` instead.
    #[serde(default)]
    pub seed_hex: Option<String>,
    /// Reference to an env var that holds the hex-encoded seed.
    #[serde(default)]
    pub secret_ref: Option<LedgerSecretRef>,
    /// Issuer URL stamped into every token's `iss` claim. Defaults to a
    /// generic `sbproxy://` URI when absent so unit tests do not have to
    /// thread the proxy's external base URL.
    #[serde(default = "default_quote_issuer")]
    pub issuer: String,
    /// Default TTL in seconds. Per A3.2 the default is 300 (5 min) and
    /// the verifier ceiling is 3600 (1 h).
    #[serde(default = "default_quote_ttl")]
    pub default_ttl_seconds: u64,
}

fn default_quote_issuer() -> String {
    "sbproxy://local".to_string()
}

fn default_quote_ttl() -> u64 {
    300
}

/// Configuration shape parsed from `policies: - type: ai_crawl_control`.
#[derive(Debug, Deserialize)]
pub struct AiCrawlControlConfig {
    /// Price displayed in the 402 challenge body. Used as the fallback
    /// when no [`Tier`] matches the request path.
    #[serde(default)]
    pub price: Option<f64>,
    /// ISO-4217 currency code for `price`.
    #[serde(default = "default_currency")]
    pub currency: String,
    /// Header the crawler reads from the 402 response and writes to its
    /// retry. Defaults to `crawler-payment`.
    #[serde(default = "default_header")]
    pub header: String,
    /// User-Agent substrings that mark a crawler. The check is a
    /// case-insensitive substring match. When empty, the policy treats
    /// every request as a candidate (recommended only for routes that
    /// are exclusively for crawlers).
    #[serde(default = "default_crawler_uas")]
    pub crawler_user_agents: Vec<String>,
    /// In-memory token list. Populating this enables the bundled
    /// in-memory ledger; leave empty to wire a custom ledger from code.
    #[serde(default)]
    pub valid_tokens: Vec<String>,
    /// Optional list of pricing tiers. Each tier carries its own
    /// price, optional content shape, optional free-preview byte
    /// budget, and optional paywall position. The first tier whose
    /// `route_pattern` matches the request path wins.
    ///
    /// When empty (or when no tier matches), the policy falls back to
    /// the top-level `price` / `currency`.
    #[serde(default)]
    pub tiers: Vec<Tier>,
    /// Optional HTTP ledger configuration (G1.3 wire). When present,
    /// the policy redeems tokens against a network ledger per
    /// `docs/adr-http-ledger-protocol.md` instead of the bundled
    /// in-memory ledger. `valid_tokens` stays valid as a dev-mode
    /// fallback (the in-memory ledger is constructed regardless and
    /// only swapped out when this block parses cleanly).
    ///
    /// Requires the `http-ledger` cargo feature to be on. With the
    /// feature off, the field still deserialises (so YAML written
    /// against the larger schema parses cleanly) but is ignored at
    /// policy construction.
    #[serde(default)]
    pub ledger: Option<LedgerYamlConfig>,
    /// Optional multi-rail challenge configuration (G3.4 / A3.1). When
    /// present and at least one rail is configured, the policy emits a
    /// multi-rail 402 body for opted-in agents and falls back to the
    /// Wave 1 single-rail format for agents that did not opt in. When
    /// absent, the policy emits the Wave 1 single-rail format
    /// unconditionally.
    #[serde(default)]
    pub rails: Option<RailsYamlConfig>,
    /// Optional quote-token signing config (G3.6 / A3.2). When the
    /// `rails:` block is set, this must be present so the proxy can
    /// sign per-rail quote tokens. Construction returns an error if
    /// `rails:` is set but `quote_token:` is missing or malformed.
    #[serde(default)]
    pub quote_token: Option<QuoteTokenYamlConfig>,
}

// --- Ledger YAML shape (G1.3 wire) ---

/// YAML configuration for the HTTP ledger client.
///
/// Mirrors the typed `HttpLedgerConfig` but with operator-friendly
/// field names and a few convenience knobs (env-resolved secret,
/// optional flat retry / breaker subblocks). Field names match the
/// shape documented in `docs/adr-http-ledger-protocol.md` so the
/// schema is reviewable against the ADR.
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerYamlConfig {
    /// Base URL of the ledger. Plain `http://` is rejected at
    /// construction time (per the ADR); operators must use `https://`.
    pub url: String,
    /// HMAC key id (selects which key on the ledger side validates
    /// the signature).
    #[serde(alias = "hmac_key_id", alias = "key-id")]
    pub key_id: String,
    /// HMAC key reference. Resolves an env var that holds the raw key
    /// bytes (hex-encoded, ASCII). When absent, falls back to the
    /// `hmac_key_hex` inline string for dev / test.
    #[serde(default)]
    pub secret_ref: Option<LedgerSecretRef>,
    /// Inline HMAC key (hex-encoded). Only honoured when `secret_ref`
    /// is absent. Convenient for dev configs and unit tests; should
    /// not appear in production sb.yml.
    #[serde(default, alias = "hmac_key_hex")]
    pub key_hex: Option<String>,
    /// Workspace tenant id stamped on the redeem envelope. Defaults
    /// to `default` (matches the OSS resolver default).
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,
    /// Header the proxy uses to carry the per-request idempotency
    /// key. Defaults to `Idempotency-Key`. The proxy always reuses the
    /// same key across retries of one logical request.
    #[serde(default = "default_idempotency_header")]
    pub idempotency_key_header: String,
    /// Per-attempt timeout in milliseconds. Defaults to 5 000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional retry-policy override. Defaults match the ADR
    /// (max 5 attempts, exponential backoff with jitter).
    #[serde(default)]
    pub retry: Option<LedgerRetryConfig>,
    /// Optional circuit-breaker override. Defaults match the ADR
    /// (10 consecutive failures opens; 5 s open duration).
    #[serde(default)]
    pub breaker: Option<LedgerBreakerConfig>,
}

/// Reference to an env var that holds the HMAC key (hex-encoded).
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerSecretRef {
    /// Environment variable name that holds the hex-encoded HMAC key.
    pub env: String,
}

/// Retry-policy override for the HTTP ledger client.
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerRetryConfig {
    /// Maximum retry attempts (1..=5). Hard-clamped by the client.
    #[serde(default = "default_retry_max_attempts")]
    pub max_attempts: u32,
    /// Initial backoff in milliseconds. Default 250.
    #[serde(default = "default_retry_initial_backoff")]
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds. Default 5 000.
    #[serde(default = "default_retry_max_backoff")]
    pub max_backoff_ms: u64,
}

/// Circuit-breaker override for the HTTP ledger client.
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerBreakerConfig {
    /// Consecutive failures that open the breaker. Default 10.
    #[serde(default = "default_breaker_failure_threshold")]
    pub failure_threshold: u32,
    /// Successes in `HalfOpen` to close the breaker. Default 1.
    #[serde(default = "default_breaker_success_threshold")]
    pub success_threshold: u32,
    /// Duration the breaker stays open in milliseconds. Default 5 000.
    #[serde(default = "default_breaker_open_duration")]
    pub open_duration_ms: u64,
}

fn default_workspace_id() -> String {
    "default".to_string()
}

fn default_idempotency_header() -> String {
    "Idempotency-Key".to_string()
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_retry_max_attempts() -> u32 {
    5
}

fn default_retry_initial_backoff() -> u64 {
    250
}

fn default_retry_max_backoff() -> u64 {
    5_000
}

fn default_breaker_failure_threshold() -> u32 {
    10
}

fn default_breaker_success_threshold() -> u32 {
    1
}

fn default_breaker_open_duration() -> u64 {
    5_000
}

fn default_currency() -> String {
    "USD".to_string()
}

fn default_header() -> String {
    "crawler-payment".to_string()
}

fn default_crawler_uas() -> Vec<String> {
    vec![
        "GPTBot".to_string(),
        "ChatGPT-User".to_string(),
        "anthropic-ai".to_string(),
        "ClaudeBot".to_string(),
        "Google-Extended".to_string(),
        "PerplexityBot".to_string(),
        "CCBot".to_string(),
        "FacebookBot".to_string(),
    ]
}

/// Compiled AI crawl control policy.
pub struct AiCrawlControlPolicy {
    price: Option<f64>,
    currency: String,
    header: String,
    crawler_user_agents: Vec<String>,
    tiers: Vec<Tier>,
    ledger: Arc<dyn Ledger>,
    /// Optional multi-rail challenge plan compiled from
    /// `ai_crawl_control.rails:` and `ai_crawl_control.quote_token:`.
    /// `None` means the policy emits the Wave 1 single-rail format
    /// unconditionally; `Some(_)` means the policy emits the multi-rail
    /// body for opted-in agents and falls back to single-rail otherwise.
    multi_rail: Option<Arc<MultiRailPlan>>,
}

/// Compiled multi-rail challenge plan. Holds the operator-configured
/// rails plus the signing material needed to mint per-rail quote tokens.
struct MultiRailPlan {
    /// Operator-configured rails in their declared preference order. The
    /// agent's `Accept-Payment` filter runs over this list to pick the
    /// rail entries actually emitted.
    configured_rails: Vec<ConfiguredRail>,
    /// Signer for the per-rail quote tokens.
    signer: super::quote_token::QuoteTokenSigner,
    /// Nonce store the issuer pre-registers nonces against. The local
    /// ledger consumes from the same store on redeem.
    nonce_store: Arc<dyn super::quote_token::NonceStore>,
}

impl std::fmt::Debug for MultiRailPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiRailPlan")
            .field("rails", &self.configured_rails)
            .field("signer", &self.signer)
            .finish()
    }
}

/// One operator-configured rail, ready to be stamped into a
/// [`RailChallenge`] entry on the hot path.
#[derive(Debug, Clone)]
enum ConfiguredRail {
    X402 {
        /// Wire-protocol version, e.g. `"2"`.
        version: String,
        /// Chain identifier (`base`, `solana`, `eth-l2`).
        chain: String,
        /// Facilitator URL for the chain.
        facilitator: String,
        /// Stablecoin asset (`USDC`, `USDT`, ...).
        asset: String,
        /// Merchant address that receives settled payments.
        pay_to: String,
    },
    Mpp {
        /// Wire-protocol version, e.g. `"1"`.
        version: String,
    },
}

impl ConfiguredRail {
    fn rail(&self) -> Rail {
        match self {
            ConfiguredRail::X402 { .. } => Rail::X402,
            ConfiguredRail::Mpp { .. } => Rail::Mpp,
        }
    }
}

impl std::fmt::Debug for AiCrawlControlPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiCrawlControlPolicy")
            .field("price", &self.price)
            .field("currency", &self.currency)
            .field("header", &self.header)
            .field("crawler_user_agents", &self.crawler_user_agents)
            .field("tiers", &self.tiers)
            .field("ledger", &self.ledger)
            .field("multi_rail", &self.multi_rail.is_some())
            .finish()
    }
}

impl AiCrawlControlPolicy {
    /// Build the policy from JSON config. Uses an in-memory ledger
    /// seeded with `valid_tokens`; embedders can swap in a different
    /// ledger via [`Self::with_ledger`].
    ///
    /// When the YAML carries a `ledger:` block AND the `http-ledger`
    /// cargo feature is enabled, the in-memory ledger is replaced by
    /// an `HttpLedger` talking to the configured backend. The
    /// `valid_tokens` field stays valid as a dev-mode fallback only
    /// when no `ledger:` block is present.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config: AiCrawlControlConfig = serde_json::from_value(value)?;

        // Default to the bundled in-memory ledger so dev configs and
        // tests without a network ledger keep working.
        #[allow(unused_mut)] // mut only used when `http-ledger` feature is on.
        let mut ledger: Arc<dyn Ledger> =
            Arc::new(InMemoryLedger::new(config.valid_tokens.clone()));

        // G1.3 wire: when the operator authored a `ledger:` block and
        // the binary was built with `http-ledger`, swap the in-memory
        // ledger for the real HTTP client. With the feature off the
        // block still deserialises (so YAML written against the
        // larger schema parses cleanly) but the policy stays on the
        // in-memory ledger and a warning is logged.
        if let Some(ledger_yaml) = config.ledger.clone() {
            #[cfg(feature = "http-ledger")]
            {
                let http_ledger = build_http_ledger(ledger_yaml)?;
                ledger = Arc::new(http_ledger);
            }
            #[cfg(not(feature = "http-ledger"))]
            {
                let _ = ledger_yaml;
                tracing::warn!(
                    "ai_crawl_control: `ledger:` block ignored because the \
                     `http-ledger` feature is off; falling back to in-memory ledger"
                );
            }
        }

        // G3.4 multi-rail challenge plan compilation. When the operator
        // authored `rails:` we expect a matching `quote_token:` block so
        // the proxy can sign per-rail tokens. We fail closed at
        // construction time rather than degrade silently to the Wave 1
        // single-rail path; an operator who copy-pasted half the YAML
        // should know about it before traffic hits production.
        let multi_rail = build_multi_rail_plan(config.rails, config.quote_token)?;

        Ok(Self {
            price: config.price,
            currency: config.currency,
            header: config.header,
            crawler_user_agents: config.crawler_user_agents,
            tiers: config.tiers,
            ledger,
            multi_rail,
        })
    }

    /// Replace the policy's ledger. Useful when the embedding binary
    /// wants to talk to a real payments backend.
    pub fn with_ledger(mut self, ledger: Arc<dyn Ledger>) -> Self {
        self.ledger = ledger;
        self
    }

    /// Inject a custom multi-rail plan. Useful for embedders that build
    /// the signer + nonce store outside the YAML schema (typical in
    /// integration tests where the test wants control over the seed).
    #[doc(hidden)]
    pub fn with_multi_rail_for_test(
        mut self,
        configured_rails: Vec<ConfiguredRailForTest>,
        signer: super::quote_token::QuoteTokenSigner,
        nonce_store: Arc<dyn super::quote_token::NonceStore>,
    ) -> Self {
        let configured_rails: Vec<ConfiguredRail> = configured_rails
            .into_iter()
            .map(ConfiguredRailForTest::into_inner)
            .collect();
        self.multi_rail = Some(Arc::new(MultiRailPlan {
            configured_rails,
            signer,
            nonce_store,
        }));
        self
    }

    /// Returns true when the policy has a multi-rail plan configured.
    pub fn has_multi_rail(&self) -> bool {
        self.multi_rail.is_some()
    }

    /// JWKS shape for the active quote-token verifier (matches the
    /// signer's public key). Returns `None` when no multi-rail plan is
    /// configured. The proxy admin server serves this body at
    /// `/.well-known/sbproxy/quote-keys.json`.
    pub fn quote_token_jwks(&self) -> Option<serde_json::Value> {
        let plan = self.multi_rail.as_ref()?;
        let mut keys = std::collections::HashMap::new();
        keys.insert(
            plan.signer.key_id().to_string(),
            plan.signer.verifying_key(),
        );
        // Build a throwaway verifier just for the JWKS shape; the verifier
        // does not need a real nonce store for that purpose.
        let dummy_store: Arc<dyn super::quote_token::NonceStore> =
            Arc::new(super::quote_token::InMemoryNonceStore::new());
        let verifier = super::quote_token::QuoteTokenVerifier::with_keys(keys, dummy_store);
        Some(verifier.jwks_json())
    }

    /// Header the policy reads / writes for the payment token.
    pub fn header_name(&self) -> &str {
        &self.header
    }

    /// Resolve the price the policy will quote for `path`.
    ///
    /// Path-only convenience that treats every request as matching
    /// any agent_id. Wave 2 call sites that have an agent_id resolved
    /// in the request context should call [`Self::resolve_price_for`]
    /// instead so per-vendor tiers can fire.
    pub fn resolve_price(&self, path: &str) -> Money {
        self.resolve_price_for(path, "")
    }

    /// Find the [`Tier`] (if any) that applies to `path`. Path-only
    /// convenience around [`Self::matched_tier_for`].
    pub fn matched_tier(&self, path: &str) -> Option<&Tier> {
        self.matched_tier_for(path, "")
    }

    /// Resolve the price for `(path, agent_id)`. The first tier whose
    /// `route_pattern` matches AND whose `agent_id` selector accepts
    /// the supplied agent wins. An empty `agent_id` is treated as
    /// "any" and matches tiers with `agent_id = None | Some("")`.
    pub fn resolve_price_for(&self, path: &str, agent_id: &str) -> Money {
        self.resolve_price_for_request(path, agent_id, None)
    }

    /// Resolve the price for `(path, agent_id, accept)`. Like
    /// [`Self::resolve_price_for`] but additionally consults the request
    /// `Accept` header to steer per-shape tiers (G1.2 wire). Path-only
    /// callers continue to work via [`Self::resolve_price_for`].
    pub fn resolve_price_for_request(
        &self,
        path: &str,
        agent_id: &str,
        accept: Option<&str>,
    ) -> Money {
        if let Some(tier) = self.matched_tier_for_request(path, agent_id, accept) {
            return tier.price.clone();
        }
        let amount_micros = self
            .price
            .map(|p| (p.max(0.0) * 1_000_000.0).round() as u64)
            .unwrap_or(0);
        Money {
            amount_micros,
            currency: self.currency.clone(),
        }
    }

    /// Find the [`Tier`] (if any) for `(path, agent_id)`. The match
    /// rule is "first tier whose route_pattern matches AND whose
    /// agent_id selector accepts the supplied agent". This means an
    /// operator who wants per-vendor pricing should put more-specific
    /// tiers ahead of catch-all tiers in the config.
    pub fn matched_tier_for(&self, path: &str, agent_id: &str) -> Option<&Tier> {
        self.matched_tier_for_request(path, agent_id, None)
    }

    /// Find the [`Tier`] (if any) for `(path, agent_id, accept)`.
    ///
    /// Adds an `Accept`-header dimension to the existing
    /// `(route_pattern, agent_id)` matcher. The first tier whose path
    /// AND agent AND content-shape selectors all accept the request
    /// wins. Path-only callers continue to work via
    /// [`Self::matched_tier_for`] which supplies `None` for `accept`.
    ///
    /// Wildcard semantics:
    ///
    /// - `agent_id = None | Some("")` matches any agent.
    /// - `content_shape = None` matches any shape.
    /// - `accept = None` (no header) skips tiers that demand a specific
    ///   shape and matches any tier without `content_shape`.
    pub fn matched_tier_for_request(
        &self,
        path: &str,
        agent_id: &str,
        accept: Option<&str>,
    ) -> Option<&Tier> {
        self.tiers
            .iter()
            .find(|t| t.matches_path(path) && t.matches_agent(agent_id) && t.matches_shape(accept))
    }

    /// Inspect the request and decide whether it pays through.
    ///
    /// `agent_id` is the resolved agent identifier from G1.4's resolver
    /// chain (`stamp_request_context`). When `Some`, it threads onto the
    /// quote-token JWS `sub` claim so the wallet redeem path can audit
    /// which agent paid. When `None`, the policy stamps `"unknown"` as
    /// before. Pre-G1.4 callers (and unit tests that do not exercise
    /// agent-class) can pass `None` and behave identically.
    pub fn check(
        &self,
        method: &str,
        host: &str,
        path: &str,
        headers: &http::HeaderMap,
        agent_id: Option<&str>,
    ) -> AiCrawlDecision {
        // Only GET / HEAD are subject to crawl charging - no point
        // 402-ing a POST that already has its own payment semantics.
        if !matches!(method, "GET" | "HEAD") {
            return AiCrawlDecision::Allow;
        }
        // When the policy has no crawler signature configured, every
        // unauthenticated GET / HEAD is in scope.
        let is_crawler = if self.crawler_user_agents.is_empty() {
            true
        } else {
            user_agent_matches(headers, &self.crawler_user_agents)
        };
        if !is_crawler {
            return AiCrawlDecision::Allow;
        }
        // --- G1.2 Accept-aware tier resolution ---
        //
        // Read the `Accept` header once and thread the parsed shape into
        // both the price lookup and the challenge body. A missing or
        // malformed header silently falls through to the path/agent
        // matcher (wildcard tiers still apply).
        let accept = headers
            .get(http::header::ACCEPT)
            .and_then(|v| v.to_str().ok());
        let price = self.resolve_price_for_request(path, "", accept);
        // Pre-resolve the tier so its `rails:` override (and `content_shape`)
        // can flow into the multi-rail emission path below. Cloning is
        // intentional: the tier is already small and we want to drop the
        // borrow before we mutate the response decision.
        let matched_tier = self.matched_tier_for_request(path, "", accept).cloned();
        if let Some(token) = headers
            .get(self.header.as_str())
            .and_then(|v| v.to_str().ok())
        {
            let token = token.trim();
            if !token.is_empty() {
                match self
                    .ledger
                    .redeem(token, host, path, price.amount_micros, &price.currency)
                {
                    Ok(_) => return AiCrawlDecision::Allow,
                    Err(err) if err.retryable => {
                        let body = self.unavailable_body(host, path, &err);
                        let retry_after = err.retry_after_seconds.unwrap_or(5);
                        return AiCrawlDecision::LedgerUnavailable {
                            body,
                            retry_after_seconds: retry_after,
                        };
                    }
                    Err(_) => {
                        // Hard failure (token unknown / already spent /
                        // signature invalid). Fall through and emit the
                        // 402 challenge so the crawler can negotiate.
                    }
                }
            }
        }
        // --- G3.4 multi-rail challenge emission ---
        //
        // When the operator configured a multi-rail plan AND the agent
        // opted in (via Accept-Payment or one of the multi-rail Accept
        // MIME types), emit the multi-rail body. Otherwise fall back to
        // the Wave 1 single-rail format so legacy crawlers keep working.
        if let Some(plan) = self.multi_rail.as_ref() {
            let accept_payment = headers
                .get("accept-payment")
                .or_else(|| headers.get("Accept-Payment"))
                .and_then(|v| v.to_str().ok());
            if let Some(prefs) = resolve_agent_preferences(accept_payment, accept) {
                // Per-tier rail filter: if the matched tier overrides the
                // policy-level rails, the tier's list is the operator
                // floor. Both filters must agree per A3.1.
                let tier_rail_filter: Option<Vec<Rail>> =
                    matched_tier.as_ref().and_then(|t| t.rails.clone());
                return self.emit_multi_rail(
                    plan,
                    host,
                    path,
                    &price,
                    matched_tier.as_ref(),
                    accept,
                    &prefs,
                    tier_rail_filter.as_deref(),
                    agent_id,
                );
            }
        }
        AiCrawlDecision::Charge {
            body: self.challenge_body_with_accept(host, path, &price, accept),
            challenge: self.challenge_header(&price),
        }
    }

    /// Build a [`AiCrawlDecision::MultiRail`] (or [`AiCrawlDecision::NoAcceptableRail`])
    /// per A3.1's filter / sort / emit flow.
    //
    // The argument count is high because the multi-rail emission binds
    // together pieces from three different layers (the request, the
    // matched tier, and the compiled plan). Splitting them into a
    // sub-struct adds ceremony without making the call site clearer.
    #[allow(clippy::too_many_arguments)]
    fn emit_multi_rail(
        &self,
        plan: &MultiRailPlan,
        host: &str,
        path: &str,
        price: &Money,
        matched_tier: Option<&Tier>,
        accept: Option<&str>,
        prefs: &AgentRailPreferences,
        tier_rail_filter: Option<&[Rail]>,
        agent_id: Option<&str>,
    ) -> AiCrawlDecision {
        // 1. Operator filter: optional per-tier override.
        let operator_filter: Vec<Rail> = match tier_rail_filter {
            Some(allowed) => allowed.to_vec(),
            None => plan.configured_rails.iter().map(|r| r.rail()).collect(),
        };
        // 2. Agent filter: keep only rails the agent's Accept-Payment list
        //    accepts, in the agent's q-value order. Operator preference
        //    order breaks q-value ties because the configured_rails list
        //    is the operator's preferred order.
        let mut emitted: Vec<&ConfiguredRail> = Vec::new();
        for agent_pref in &prefs.accepted {
            if !operator_filter.contains(agent_pref) {
                continue;
            }
            if let Some(cfg) = plan
                .configured_rails
                .iter()
                .find(|c| c.rail() == *agent_pref)
            {
                emitted.push(cfg);
            }
        }
        if emitted.is_empty() {
            // 406 fallback per A3.1: agent's preference set has no overlap
            // with the configured rails (after the per-tier filter).
            let supported: Vec<&str> = operator_filter.iter().map(|r| r.as_str()).collect();
            let body = format!(
                "{{\"error\":\"no_acceptable_rail\",\"supported_rails\":[{rails}],\"target\":\"{host}{path}\",\"message\":\"Agent's Accept-Payment list does not overlap with this route's configured rails.\"}}",
                rails = supported
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(","),
                host = host,
                path = path,
            );
            return AiCrawlDecision::NoAcceptableRail { body };
        }

        // 3. Resolve content shape: G3.5 threads the matched tier's
        //    `content_shape` into the quote-token `shape` claim. Tier-less
        //    requests fall back to the parsed Accept header; if that also
        //    yields nothing we use ContentShape::Other.
        let shape = matched_tier
            .and_then(|t| t.content_shape)
            .or_else(|| accept.and_then(ContentShape::from_accept))
            .unwrap_or(ContentShape::Other);

        // 4. Emit one RailChallenge per surviving entry, each carrying its
        //    own quote token (separate nonce per rail per A3.1 + A3.2).
        let mut rail_entries: Vec<RailChallenge> = Vec::with_capacity(emitted.len());
        for cfg in emitted {
            let rail_name = cfg.rail().as_str();
            let facilitator = match cfg {
                ConfiguredRail::X402 { facilitator, .. } => Some(facilitator.clone()),
                ConfiguredRail::Mpp { .. } => None,
            };
            // Sign one quote token per rail entry. Each gets its own nonce
            // and quote_id so the agent can pick exactly one rail and the
            // others can expire on TTL per A3.2.
            // sub claim: G1.4 resolver chain runs in `stamp_request_context`
            // upstream of policy::check. When the caller threaded a resolved
            // agent_id we land it here so the quote-token's `sub` claim is
            // honest about who paid; pre-G1.4 callers (and the OSS-default
            // build that ships without agent-class) pass None and we keep
            // the Wave 1 `"unknown"` fallback so the JWS issue path never
            // signs an empty sub.
            let sub_claim = agent_id.unwrap_or("unknown");
            let issued = match plan.signer.issue(
                sub_claim,
                path,
                shape,
                price.clone(),
                rail_name,
                facilitator.clone(),
                None,
            ) {
                Ok(q) => q,
                Err(_) => {
                    // JWS signing failed; the alternative is to silently
                    // drop the rail entry, which would be surprising.
                    // Skip this rail and continue; if every rail fails we
                    // fall back to the Wave 1 single-rail format below.
                    continue;
                }
            };
            // Pre-register the nonce so the verifier can later distinguish
            // "never seen" from "already consumed". Errors here are
            // logged (best-effort) but do not abort the response.
            let _ = plan.nonce_store.register(&issued.claims.nonce);
            let expires_at = unix_seconds_to_rfc3339(issued.claims.exp);
            match cfg {
                ConfiguredRail::X402 {
                    version,
                    chain,
                    facilitator,
                    asset,
                    pay_to,
                } => rail_entries.push(RailChallenge::X402 {
                    version: version.clone(),
                    chain: chain.clone(),
                    facilitator: facilitator.clone(),
                    asset: asset.clone(),
                    amount_micros: price.amount_micros,
                    currency: price.currency.clone(),
                    pay_to: pay_to.clone(),
                    expires_at,
                    quote_token: issued.token,
                }),
                ConfiguredRail::Mpp { version } => rail_entries.push(RailChallenge::Mpp {
                    version: version.clone(),
                    // Wave 3 placeholder; the real Stripe `pi_*` is created
                    // by the worker (G3.3) on the redeem path.
                    stripe_payment_intent: format!("pi_pending_{}", issued.claims.quote_id),
                    amount_micros: price.amount_micros,
                    currency: price.currency.clone(),
                    expires_at,
                    quote_token: issued.token,
                }),
            }
        }

        if rail_entries.is_empty() {
            // Every rail failed to sign. Fall back to single-rail so the
            // agent at least gets a 402 it can act on.
            return AiCrawlDecision::Charge {
                body: self.challenge_body_with_accept(host, path, price, accept),
                challenge: self.challenge_header(price),
            };
        }

        let body = MultiRailChallenge {
            rails: rail_entries,
            agent_choice_method: "header_negotiation".to_string(),
            policy: "first_match_wins".to_string(),
        }
        .to_json();

        AiCrawlDecision::MultiRail {
            body,
            content_type: MULTI_RAIL_CONTENT_TYPE,
        }
    }

    fn challenge_header(&self, price: &Money) -> String {
        format!(
            "Crawler-Payment realm=\"{}\" currency=\"{}\" price=\"{}\"",
            "ai-crawl",
            price.currency,
            price.to_units_string()
        )
    }

    fn challenge_body_with_accept(
        &self,
        host: &str,
        path: &str,
        price: &Money,
        accept: Option<&str>,
    ) -> String {
        let tier = self.matched_tier_for_request(path, "", accept);
        let shape = tier
            .and_then(|t| t.content_shape)
            .map(|s| format!(",\"content_shape\":\"{}\"", s.as_str()))
            .unwrap_or_default();
        let preview = tier
            .and_then(|t| t.free_preview_bytes)
            .map(|b| format!(",\"free_preview_bytes\":{b}"))
            .unwrap_or_default();
        let position = tier
            .and_then(|t| t.paywall_position)
            .map(|p| format!(",\"paywall_position\":\"{}\"", paywall_position_str(p)))
            .unwrap_or_default();
        format!(
            "{{\"error\":\"payment_required\",\"price\":\"{price_str}\",\"amount_micros\":{micros},\"currency\":\"{currency}\",\"target\":\"{host}{path}\",\"header\":\"{header}\"{shape}{preview}{position}}}",
            price_str = price.to_units_string(),
            micros = price.amount_micros,
            currency = price.currency,
            host = host,
            path = path,
            header = self.header,
        )
    }

    fn unavailable_body(&self, host: &str, path: &str, err: &LedgerError) -> String {
        format!(
            "{{\"error\":\"ledger_unavailable\",\"code\":\"{code}\",\"message\":\"{msg}\",\"target\":\"{host}{path}\"}}",
            code = err.code,
            msg = sanitize_for_json(&err.message),
            host = host,
            path = path,
        )
    }
}

fn paywall_position_str(p: PaywallPosition) -> &'static str {
    match p {
        PaywallPosition::TopOfPage => "top_of_page",
        PaywallPosition::Inline => "inline",
        PaywallPosition::BottomOfPage => "bottom_of_page",
    }
}

fn sanitize_for_json(input: &str) -> String {
    // Conservative escape: drop control characters and escape quotes /
    // backslashes. The error envelope is hand-written rather than
    // serde-serialized to keep this hot path allocation-light.
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn user_agent_matches(headers: &http::HeaderMap, needles: &[String]) -> bool {
    let Some(ua) = headers
        .get("user-agent")
        .or_else(|| headers.get("User-Agent"))
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let lc = ua.to_ascii_lowercase();
    needles.iter().any(|n| lc.contains(&n.to_ascii_lowercase()))
}

// --- Multi-rail plan compilation (G3.4) ---

/// Public test-only wrapper around the private [`ConfiguredRail`] enum.
/// Lets integration tests inject a fully-formed multi-rail plan without
/// going through the YAML schema or the env-var-based key resolver.
#[doc(hidden)]
pub struct ConfiguredRailForTest(ConfiguredRail);

impl ConfiguredRailForTest {
    /// Wrap an x402 rail with the operator-supplied chain / facilitator
    /// / asset / pay_to. The version string defaults to `"2"` to match
    /// the Wave 3 x402 v2 ship.
    pub fn x402(
        chain: impl Into<String>,
        facilitator: impl Into<String>,
        asset: impl Into<String>,
        pay_to: impl Into<String>,
    ) -> Self {
        Self(ConfiguredRail::X402 {
            version: "2".to_string(),
            chain: chain.into(),
            facilitator: facilitator.into(),
            asset: asset.into(),
            pay_to: pay_to.into(),
        })
    }

    /// Wrap an MPP rail. The version string defaults to `"1"`.
    pub fn mpp() -> Self {
        Self(ConfiguredRail::Mpp {
            version: "1".to_string(),
        })
    }

    fn into_inner(self) -> ConfiguredRail {
        self.0
    }
}

/// Compile the YAML `rails:` + `quote_token:` blocks into a runtime plan.
/// Returns `Ok(None)` when neither block is present (the policy stays on
/// the Wave 1 single-rail path); returns `Err` when one block is present
/// without the other or when key resolution fails.
fn build_multi_rail_plan(
    rails_yaml: Option<RailsYamlConfig>,
    quote_token_yaml: Option<QuoteTokenYamlConfig>,
) -> anyhow::Result<Option<Arc<MultiRailPlan>>> {
    let Some(rails) = rails_yaml else {
        if quote_token_yaml.is_some() {
            anyhow::bail!(
                "ai_crawl_control: `quote_token:` block without a matching `rails:` block; \
                 add a `rails:` block (with at least one rail configured) or remove `quote_token:`"
            );
        }
        return Ok(None);
    };
    let qt_yaml = quote_token_yaml.ok_or_else(|| {
        anyhow::anyhow!(
            "ai_crawl_control: `rails:` block requires a `quote_token:` block so the proxy can \
             sign per-rail quote tokens (see docs/adr-quote-token-jws.md)"
        )
    })?;

    // Build the configured rails list in declaration-stable order: x402
    // first when both are configured, mirroring the operator's typical
    // preference (no fees on x402 vs. MPP card-network costs).
    let mut configured_rails: Vec<ConfiguredRail> = Vec::with_capacity(2);
    if let Some(x) = rails.x402 {
        configured_rails.push(ConfiguredRail::X402 {
            version: x.version,
            chain: x.chain,
            facilitator: x.facilitator,
            asset: x.asset,
            pay_to: x.pay_to,
        });
    }
    if let Some(m) = rails.mpp {
        configured_rails.push(ConfiguredRail::Mpp { version: m.version });
    }
    if configured_rails.is_empty() {
        anyhow::bail!("ai_crawl_control.rails: must configure at least one rail (x402 and/or mpp)");
    }

    // --- Quote-token signer ---
    let seed_hex = if let Some(sref) = &qt_yaml.secret_ref {
        std::env::var(&sref.env).map_err(|_| {
            anyhow::anyhow!(
                "ai_crawl_control.quote_token.secret_ref.env: env var '{}' not set",
                sref.env
            )
        })?
    } else if let Some(inline) = &qt_yaml.seed_hex {
        inline.clone()
    } else {
        anyhow::bail!(
            "ai_crawl_control.quote_token requires either secret_ref.env or seed_hex (32-byte ed25519 seed, hex-encoded)"
        );
    };
    let seed_bytes = hex::decode(seed_hex.trim())
        .map_err(|e| anyhow::anyhow!("ai_crawl_control.quote_token seed is not valid hex: {e}"))?;
    if seed_bytes.len() != 32 {
        anyhow::bail!(
            "ai_crawl_control.quote_token seed must be exactly 32 bytes (got {})",
            seed_bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let signer = super::quote_token::QuoteTokenSigner::from_seed_bytes(
        &seed,
        qt_yaml.key_id,
        qt_yaml.issuer,
        std::time::Duration::from_secs(qt_yaml.default_ttl_seconds),
    );
    let nonce_store: Arc<dyn super::quote_token::NonceStore> =
        Arc::new(super::quote_token::InMemoryNonceStore::new());

    Ok(Some(Arc::new(MultiRailPlan {
        configured_rails,
        signer,
        nonce_store,
    })))
}

/// Convert a unix-seconds timestamp to RFC 3339 in UTC. Used for the
/// `expires_at` mirror in each rail entry of the multi-rail body.
fn unix_seconds_to_rfc3339(unix_seconds: u64) -> String {
    let secs = unix_seconds as i64;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

// --- HTTP ledger client (G1.3) ---

#[cfg(feature = "http-ledger")]
pub use http_ledger::{HttpLedger, HttpLedgerConfig};

/// Resolve a [`LedgerYamlConfig`] into a constructed `HttpLedger`.
///
/// Resolution order for the HMAC key:
///
/// 1. `secret_ref.env`: read the named env var, hex-decode the value.
/// 2. `key_hex`: hex-decode the inline string (dev / test convenience).
/// 3. Neither set: error.
///
/// Plain `http://` URLs are rejected up front so the YAML never
/// reaches a `HttpLedger::new` that would also reject them.
#[cfg(feature = "http-ledger")]
fn build_http_ledger(yaml: LedgerYamlConfig) -> anyhow::Result<HttpLedger> {
    use std::time::Duration;

    let key_hex = if let Some(ref sref) = yaml.secret_ref {
        std::env::var(&sref.env).map_err(|_| {
            anyhow::anyhow!(
                "ai_crawl_control.ledger.secret_ref.env: env var '{}' not set",
                sref.env
            )
        })?
    } else if let Some(ref inline) = yaml.key_hex {
        inline.clone()
    } else {
        anyhow::bail!(
            "ai_crawl_control.ledger requires either secret_ref.env or key_hex (hex-encoded HMAC key)"
        );
    };
    let key = hex::decode(key_hex.trim())
        .map_err(|e| anyhow::anyhow!("ai_crawl_control.ledger HMAC key is not valid hex: {e}"))?;

    let retry = yaml.retry.unwrap_or(LedgerRetryConfig {
        max_attempts: default_retry_max_attempts(),
        initial_backoff_ms: default_retry_initial_backoff(),
        max_backoff_ms: default_retry_max_backoff(),
    });
    let breaker = yaml.breaker.unwrap_or(LedgerBreakerConfig {
        failure_threshold: default_breaker_failure_threshold(),
        success_threshold: default_breaker_success_threshold(),
        open_duration_ms: default_breaker_open_duration(),
    });

    let cfg = HttpLedgerConfig {
        endpoint: yaml.url,
        key_id: yaml.key_id,
        key,
        workspace_id: yaml.workspace_id,
        agent_id: "unknown".to_string(),
        agent_vendor: "unknown".to_string(),
        per_attempt_timeout: Duration::from_millis(yaml.timeout_ms),
        // Total timeout is the simple sum of (max_attempts * per-attempt
        // timeout) plus the worst-case sum of backoffs. Operators who
        // need a tighter or looser deadline can pass it via a future
        // top-level field; the ADR keeps the relationship simple.
        total_timeout: Duration::from_millis(
            yaml.timeout_ms.saturating_mul(retry.max_attempts as u64)
                + retry
                    .max_backoff_ms
                    .saturating_mul(retry.max_attempts as u64),
        ),
        max_attempts: retry.max_attempts.clamp(1, 5),
        breaker_failure_threshold: breaker.failure_threshold,
        breaker_success_threshold: breaker.success_threshold,
        breaker_open_duration: Duration::from_millis(breaker.open_duration_ms),
    };

    HttpLedger::new(cfg)
}

#[cfg(feature = "http-ledger")]
mod http_ledger {
    //! HTTP ledger client per `docs/adr-http-ledger-protocol.md`.
    //!
    //! Sync (blocking) by design: the [`Ledger`] trait is sync because
    //! the policy fast-path lives inside Pingora's request filter, which
    //! does not own a tokio runtime handle. We use `reqwest::blocking`
    //! the same way the WAF rule-feed loader does at config-compile.
    //! For high-rps deployments the circuit breaker bounds the cost of
    //! a slow ledger to one round-trip + breaker-open period.
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use std::time::{SystemTime, UNIX_EPOCH};

    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use rand::Rng;
    use sbproxy_platform::CircuitBreaker;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use ulid::Ulid;

    use super::{Ledger, LedgerError, RedeemResult};

    type HmacSha256 = Hmac<Sha256>;

    /// Configuration for `HttpLedger`.
    #[derive(Debug, Clone)]
    pub struct HttpLedgerConfig {
        /// Base URL, e.g. `https://ledger.internal`. The client appends
        /// `/v1/ledger/redeem` (and other verb paths in later waves).
        /// Plain HTTP is rejected at construction time per the ADR.
        pub endpoint: String,
        /// HMAC key id (selects which key on the ledger side validates
        /// the signature).
        pub key_id: String,
        /// HMAC key bytes. Loaded from `SBPROXY_LEDGER_HMAC_KEY_FILE`
        /// in the binary; tests pass raw bytes.
        pub key: Vec<u8>,
        /// Workspace tenant key. `default` in OSS, the customer
        /// workspace id in enterprise.
        pub workspace_id: String,
        /// Agent identifier from the agent-class taxonomy (G1.1). The
        /// Wave 1 caller forwards `unknown` until G1.4 lands; widening
        /// the call site is a follow-up.
        pub agent_id: String,
        /// Convenience copy of the taxonomy `vendor` carried so the
        /// ledger does not need to load the taxonomy.
        pub agent_vendor: String,
        /// Per-attempt deadline; the client aborts the request after
        /// this many milliseconds and counts it as a transient failure.
        pub per_attempt_timeout: Duration,
        /// Total deadline across all retries.
        pub total_timeout: Duration,
        /// Maximum retry attempts. Hard-capped at 5 by the ADR.
        pub max_attempts: u32,
        /// Consecutive failures that open the circuit breaker.
        pub breaker_failure_threshold: u32,
        /// Successes in `HalfOpen` to close the breaker again.
        pub breaker_success_threshold: u32,
        /// Duration the breaker stays open before allowing a probe.
        pub breaker_open_duration: Duration,
    }

    impl HttpLedgerConfig {
        /// Defaults aligned with the ADR (5 attempts, 5 s per attempt,
        /// 30 s total, breaker opens after 10 failures, 5 s open).
        pub fn with_defaults(
            endpoint: impl Into<String>,
            key_id: impl Into<String>,
            key: Vec<u8>,
        ) -> Self {
            Self {
                endpoint: endpoint.into(),
                key_id: key_id.into(),
                key,
                workspace_id: "default".to_string(),
                agent_id: "unknown".to_string(),
                agent_vendor: "unknown".to_string(),
                per_attempt_timeout: Duration::from_secs(5),
                total_timeout: Duration::from_secs(30),
                max_attempts: 5,
                breaker_failure_threshold: 10,
                breaker_success_threshold: 1,
                breaker_open_duration: Duration::from_secs(5),
            }
        }
    }

    /// HTTP ledger client. See `docs/adr-http-ledger-protocol.md`.
    pub struct HttpLedger {
        config: HttpLedgerConfig,
        client: reqwest::blocking::Client,
        breaker: Arc<CircuitBreaker>,
        /// Optional recency probe stamped on every successful redeem.
        /// When wired into `sbproxy_observe::default_registry`, this
        /// is what flips `/readyz` from 503 to 200 once the ledger
        /// answers a real request. Left as `None` for tests and for
        /// configs that do not expose `/readyz`.
        recency: Option<sbproxy_observe::Recency>,
    }

    impl std::fmt::Debug for HttpLedger {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HttpLedger")
                .field("endpoint", &self.config.endpoint)
                .field("key_id", &self.config.key_id)
                .field("workspace_id", &self.config.workspace_id)
                .field("agent_id", &self.config.agent_id)
                .finish()
        }
    }

    impl HttpLedger {
        /// Build a new client. Returns `Err` if `endpoint` is not HTTPS.
        pub fn new(config: HttpLedgerConfig) -> anyhow::Result<Self> {
            // The ADR mandates HTTPS for the ledger endpoint. A plain
            // HTTP target is almost always a misconfiguration, so we
            // refuse to construct the client rather than fail later.
            if !config.endpoint.starts_with("https://") {
                anyhow::bail!(
                    "HttpLedger endpoint must be https://; got '{}'",
                    config.endpoint
                );
            }
            let client = reqwest::blocking::Client::builder()
                .timeout(config.per_attempt_timeout)
                .build()?;
            let breaker = Arc::new(CircuitBreaker::new(
                config.breaker_failure_threshold,
                config.breaker_success_threshold,
                config.breaker_open_duration,
            ));
            Ok(Self {
                config,
                client,
                breaker,
                recency: None,
            })
        }

        /// Inject a custom HTTP client (used by tests to point at a
        /// stub server with a relaxed TLS config).
        pub fn with_client(mut self, client: reqwest::blocking::Client) -> Self {
            self.client = client;
            self
        }

        /// Inject a custom circuit breaker, e.g. one shared across
        /// multiple verbs in a future wave.
        pub fn with_breaker(mut self, breaker: Arc<CircuitBreaker>) -> Self {
            self.breaker = breaker;
            self
        }

        /// Wire a `Recency` clone so every successful redeem stamps
        /// the readiness probe. The same `Recency` should be passed
        /// to `sbproxy_observe::default_registry(...)` at startup so
        /// `/readyz` returns 200 once the ledger answers a real
        /// request and 503 once it has been silent for longer than
        /// the configured staleness window.
        pub fn with_recency(mut self, recency: sbproxy_observe::Recency) -> Self {
            self.recency = Some(recency);
            self
        }

        /// Expose the breaker state for `/readyz` and Grafana dashboards.
        pub fn breaker(&self) -> &CircuitBreaker {
            &self.breaker
        }
    }

    impl Ledger for HttpLedger {
        fn redeem(
            &self,
            token: &str,
            host: &str,
            path: &str,
            expected_amount_micros: u64,
            expected_currency: &str,
        ) -> Result<RedeemResult, LedgerError> {
            // --- Breaker gate ---
            //
            // When open we short-circuit with a synthetic transient
            // error; the policy at the request path then emits 503.
            if !self.breaker.allow_request() {
                return Err(LedgerError::transient(
                    "ledger.unavailable",
                    "circuit breaker open",
                )
                .with_retry_after(
                    self.config.breaker_open_duration.as_secs().max(1) as u32,
                ));
            }

            // --- Request envelope ---
            let request_id = Ulid::new().to_string();
            let idempotency_key = Ulid::new().to_string();
            let nonce = random_nonce_hex();
            let timestamp = rfc3339_millis_now();
            let envelope = RedeemEnvelope {
                v: 1,
                request_id: request_id.clone(),
                timestamp: timestamp.clone(),
                nonce: nonce.clone(),
                agent_id: self.config.agent_id.clone(),
                agent_vendor: self.config.agent_vendor.clone(),
                workspace_id: self.config.workspace_id.clone(),
                payload: RedeemPayload {
                    token: token.to_string(),
                    host: host.to_string(),
                    path: path.to_string(),
                    amount_micros: expected_amount_micros,
                    currency: expected_currency.to_string(),
                    content_shape: None,
                },
            };
            let body_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                LedgerError::hard("ledger.bad_request", format!("envelope encode: {e}"))
            })?;
            let body_hash_hex = sha256_hex(&body_bytes);

            let path_only = "/v1/ledger/redeem";
            let signing_string = canonical_signing_string(
                envelope.v,
                &request_id,
                &timestamp,
                &nonce,
                &self.config.workspace_id,
                "POST",
                path_only,
                &body_hash_hex,
            );
            let signature_hex = hmac_sha256_hex(&self.config.key, signing_string.as_bytes())
                .map_err(|e| LedgerError::hard("ledger.bad_request", format!("hmac init: {e}")))?;
            let signature_header = format!("v1={signature_hex}");

            let url = format!(
                "{}{}",
                self.config.endpoint.trim_end_matches('/'),
                path_only
            );

            // --- Retry loop ---
            //
            // Schedule per ADR: 0 ms, 250 ms, 500 ms, 1 s, 2 s base
            // delay, each with `[0, base)` jitter added. Same Idempotency-Key
            // across retries so the ledger short-circuits on replay.
            let max_attempts = self.config.max_attempts.clamp(1, 5);
            let total_deadline = Instant::now() + self.config.total_timeout;
            let mut last_err: Option<LedgerError> = None;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    let base_ms = match attempt {
                        1 => 250u64,
                        2 => 500,
                        3 => 1000,
                        _ => 2000,
                    };
                    let jitter_ms = rand::thread_rng().gen_range(0..base_ms.max(1));
                    let delay = Duration::from_millis(base_ms + jitter_ms);
                    if Instant::now() + delay >= total_deadline {
                        break;
                    }
                    std::thread::sleep(delay);
                }
                if Instant::now() >= total_deadline {
                    break;
                }
                match self.send_attempt(
                    &url,
                    &body_bytes,
                    &idempotency_key,
                    &request_id,
                    &signature_header,
                ) {
                    Ok(result) => {
                        self.breaker.record_success();
                        if let Some(r) = &self.recency {
                            r.mark_success();
                        }
                        return Ok(result);
                    }
                    Err(err) => {
                        if err.retryable {
                            self.breaker.record_failure();
                            last_err = Some(err);
                            continue;
                        }
                        // Hard failure: do not retry, do not flap the
                        // breaker. The policy will translate to 402.
                        return Err(err);
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| {
                LedgerError::transient("ledger.unavailable", "max retries exhausted")
            }))
        }
    }

    impl HttpLedger {
        fn send_attempt(
            &self,
            url: &str,
            body: &[u8],
            idempotency_key: &str,
            request_id: &str,
            signature_header: &str,
        ) -> Result<RedeemResult, LedgerError> {
            let response = self
                .client
                .post(url)
                .header("content-type", "application/json")
                .header("idempotency-key", idempotency_key)
                .header("x-sb-ledger-signature", signature_header)
                .header("x-sb-ledger-key-id", &self.config.key_id)
                .header("x-sb-request-id", request_id)
                .body(body.to_vec())
                .send();

            let response = match response {
                Ok(r) => r,
                Err(e) => {
                    // Network errors (DNS, TCP RST, TLS, read timeout)
                    // are always retryable.
                    return Err(LedgerError::transient(
                        "ledger.unavailable",
                        format!("network: {e}"),
                    ));
                }
            };

            let status = response.status();
            let retry_after_header = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u32>().ok());
            let body_text = response.text().unwrap_or_default();

            if status.is_success() {
                let envelope: ResponseEnvelope = serde_json::from_str(&body_text).map_err(|e| {
                    LedgerError::transient("ledger.internal", format!("decode response: {e}"))
                })?;
                if let Some(result) = envelope.result {
                    let redeemed = result.redeemed.unwrap_or(false);
                    if !redeemed {
                        return Err(LedgerError::hard(
                            "ledger.token_already_spent",
                            "ledger reported redeemed=false",
                        ));
                    }
                    return Ok(RedeemResult {
                        token_id: result
                            .redemption_id
                            .unwrap_or_else(|| request_id.to_string()),
                        amount_micros: result.amount_micros.unwrap_or(0),
                        currency: result.currency.unwrap_or_default(),
                        txhash: result.txhash,
                    });
                }
                if let Some(err) = envelope.error {
                    return Err(map_envelope_error(err, retry_after_header));
                }
                return Err(LedgerError::transient(
                    "ledger.internal",
                    "response missing result and error",
                ));
            }

            // Non-2xx: try to decode the error envelope, otherwise
            // synthesize one from the HTTP status.
            let envelope: Option<ResponseEnvelope> = serde_json::from_str(&body_text).ok();
            if let Some(err) = envelope.and_then(|e| e.error) {
                return Err(map_envelope_error(err, retry_after_header));
            }
            let code = status.as_u16();
            match code {
                400 => Err(LedgerError::hard(
                    "ledger.bad_request",
                    format!("HTTP {code}"),
                )),
                401 => Err(LedgerError::hard(
                    "ledger.signature_invalid",
                    format!("HTTP {code}"),
                )),
                409 => Err(LedgerError::hard(
                    "ledger.token_already_spent",
                    format!("HTTP {code}"),
                )),
                429 => {
                    let mut e =
                        LedgerError::transient("ledger.rate_limited", format!("HTTP {code}"));
                    if let Some(s) = retry_after_header {
                        e = e.with_retry_after(s);
                    }
                    Err(e)
                }
                502..=504 => {
                    let mut e =
                        LedgerError::transient("ledger.unavailable", format!("HTTP {code}"));
                    if let Some(s) = retry_after_header {
                        e = e.with_retry_after(s);
                    }
                    Err(e)
                }
                _ if (500..600).contains(&code) => Err(LedgerError::transient(
                    "ledger.internal",
                    format!("HTTP {code}"),
                )),
                _ => Err(LedgerError::hard(
                    "ledger.bad_request",
                    format!("HTTP {code}"),
                )),
            }
        }
    }

    fn map_envelope_error(err: ErrorPart, retry_after_header: Option<u32>) -> LedgerError {
        let mut out = LedgerError {
            code: err.code,
            message: err.message,
            retryable: err.retryable,
            retry_after_seconds: err.retry_after_seconds,
        };
        if out.retry_after_seconds.is_none() {
            out.retry_after_seconds = retry_after_header;
        }
        out
    }

    // --- Wire types ---

    #[derive(Debug, Serialize)]
    struct RedeemEnvelope {
        v: u32,
        request_id: String,
        timestamp: String,
        nonce: String,
        agent_id: String,
        agent_vendor: String,
        workspace_id: String,
        payload: RedeemPayload,
    }

    #[derive(Debug, Serialize)]
    struct RedeemPayload {
        token: String,
        host: String,
        path: String,
        amount_micros: u64,
        currency: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        content_shape: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ResponseEnvelope {
        #[serde(default)]
        result: Option<ResultPart>,
        #[serde(default)]
        error: Option<ErrorPart>,
    }

    #[derive(Debug, Deserialize)]
    struct ResultPart {
        #[serde(default)]
        redeemed: Option<bool>,
        #[serde(default)]
        redemption_id: Option<String>,
        #[serde(default)]
        amount_micros: Option<u64>,
        #[serde(default)]
        currency: Option<String>,
        #[serde(default)]
        txhash: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct ErrorPart {
        code: String,
        message: String,
        #[serde(default)]
        retryable: bool,
        #[serde(default)]
        retry_after_seconds: Option<u32>,
    }

    // --- Helpers ---

    #[allow(clippy::too_many_arguments)] // canonical signing string is 8 fields by spec.
    fn canonical_signing_string(
        v: u32,
        request_id: &str,
        timestamp: &str,
        nonce: &str,
        workspace_id: &str,
        method: &str,
        path: &str,
        body_hash_hex: &str,
    ) -> String {
        // Eight lines, \n separated, no trailing newline (per ADR).
        format!(
            "{v}\n{request_id}\n{timestamp}\n{nonce}\n{workspace_id}\n{method}\n{path}\n{body_hash_hex}"
        )
    }

    fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> Result<String, String> {
        let mut mac = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
        mac.update(data);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn random_nonce_hex() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        hex::encode(bytes)
    }

    fn rfc3339_millis_now() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as i64;
        let millis = now.subsec_millis();
        // Manual format avoids pulling chrono::Utc::now() which is
        // already in the dep tree but not used elsewhere on this hot
        // path. RFC 3339 / ISO 8601 form.
        let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, millis * 1_000_000)
            .unwrap_or_default();
        datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn ua_headers(ua: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("user-agent", ua.parse().unwrap());
        h
    }

    fn payment_headers(ua: &str, header: &str, token: &str) -> http::HeaderMap {
        let mut h = ua_headers(ua);
        h.insert(
            http::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            token.parse().unwrap(),
        );
        h
    }

    #[test]
    fn human_browser_ua_passes_without_payment() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "valid_tokens": ["t1"],
        }))
        .unwrap();
        let h = ua_headers("Mozilla/5.0");
        assert_eq!(
            policy.check("GET", "x.com", "/article", &h, None),
            AiCrawlDecision::Allow
        );
    }

    #[test]
    fn known_crawler_without_token_gets_402_challenge() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": ["t1"],
        }))
        .unwrap();
        let h = ua_headers("Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)");
        match policy.check("GET", "x.com", "/article", &h, None) {
            AiCrawlDecision::Charge { body, challenge } => {
                assert!(body.contains("\"price\":\"0.001000\""));
                assert!(body.contains("\"amount_micros\":1000"));
                assert!(challenge.contains("Crawler-Payment"));
            }
            other => panic!("expected Charge, got {:?}", other),
        }
    }

    #[test]
    fn crawler_with_valid_token_passes_once_then_402s() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "valid_tokens": ["good-token"],
        }))
        .unwrap();
        let h1 = payment_headers("GPTBot/1.0", "crawler-payment", "good-token");
        assert_eq!(
            policy.check("GET", "x.com", "/", &h1, None),
            AiCrawlDecision::Allow
        );
        // Same token cannot redeem again - single-use ledger.
        let h2 = payment_headers("GPTBot/1.0", "crawler-payment", "good-token");
        assert!(matches!(
            policy.check("GET", "x.com", "/", &h2, None),
            AiCrawlDecision::Charge { .. }
        ));
    }

    #[test]
    fn crawler_with_unknown_token_gets_402() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "valid_tokens": ["good-token"],
        }))
        .unwrap();
        let h = payment_headers("ClaudeBot/1.0", "crawler-payment", "wrong-token");
        assert!(matches!(
            policy.check("GET", "x.com", "/", &h, None),
            AiCrawlDecision::Charge { .. }
        ));
    }

    #[test]
    fn post_requests_are_not_charged() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "valid_tokens": [],
        }))
        .unwrap();
        let h = ua_headers("GPTBot/1.0");
        assert_eq!(
            policy.check("POST", "x.com", "/", &h, None),
            AiCrawlDecision::Allow
        );
    }

    // --- Tier resolution ---

    #[test]
    fn tier_prefix_pattern_matches_path_subtree() {
        let tier = Tier {
            route_pattern: "/articles/*".to_string(),
            price: Money::from_units(0.01, "USD"),
            content_shape: Some(ContentShape::Markdown),
            agent_id: None,
            free_preview_bytes: Some(2048),
            paywall_position: Some(PaywallPosition::Inline),
            rails: None,
            citation_required: false,
        };
        assert!(tier.matches_path("/articles/foo"));
        assert!(tier.matches_path("/articles/foo/bar"));
        assert!(!tier.matches_path("/blog/post"));
    }

    #[test]
    fn tier_agent_id_selector_filters_per_vendor() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "tiers": [
                {
                    "route_pattern": "/articles/*",
                    "price": { "amount_micros": 50000, "currency": "USD" },
                    "agent_id": "openai-gptbot"
                },
                {
                    "route_pattern": "/articles/*",
                    "price": { "amount_micros": 10000, "currency": "USD" }
                }
            ]
        }))
        .expect("compile policy");
        let openai_price = policy.resolve_price_for("/articles/x", "openai-gptbot");
        assert_eq!(openai_price.amount_micros, 50_000, "vendor tier wins");
        let other_price = policy.resolve_price_for("/articles/x", "anthropic-claudebot");
        assert_eq!(other_price.amount_micros, 10_000, "fallback tier wins");
        let no_agent = policy.resolve_price_for("/articles/x", "");
        assert_eq!(no_agent.amount_micros, 10_000, "wildcard hits fallback");
    }

    #[test]
    fn first_matching_tier_wins() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "tiers": [
                { "route_pattern": "/articles/*",
                  "price": { "amount_micros": 5000, "currency": "USD" } },
                { "route_pattern": "/*",
                  "price": { "amount_micros": 100, "currency": "USD" } }
            ]
        }))
        .unwrap();
        let resolved = policy.resolve_price("/articles/foo");
        assert_eq!(resolved.amount_micros, 5000);
        let fallback = policy.resolve_price("/whatever");
        assert_eq!(fallback.amount_micros, 100);
    }

    #[test]
    fn accept_header_steers_per_shape_tier() {
        // Tiers in order: markdown ($0.005) then html ($0.001). The
        // markdown tier sits first to prove the shape selector (not
        // tier order) is what picks the right price.
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "tiers": [
                {
                    "route_pattern": "/*",
                    "price": { "amount_micros": 5000, "currency": "USD" },
                    "content_shape": "markdown"
                },
                {
                    "route_pattern": "/*",
                    "price": { "amount_micros": 1000, "currency": "USD" },
                    "content_shape": "html"
                }
            ]
        }))
        .unwrap();

        // Markdown Accept selects the markdown tier ($0.005).
        let md = policy.resolve_price_for_request("/article", "", Some("text/markdown"));
        assert_eq!(md.amount_micros, 5000, "markdown Accept => markdown tier");

        // HTML Accept selects the html tier ($0.001) even though it's
        // listed second.
        let html = policy.resolve_price_for_request("/article", "", Some("text/html"));
        assert_eq!(html.amount_micros, 1000, "html Accept => html tier");
    }

    #[test]
    fn missing_accept_falls_through_shape_selector() {
        // When no Accept header is present, neither shape-specific tier
        // matches, so the top-level fallback price applies.
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.0007,
            "valid_tokens": [],
            "tiers": [
                {
                    "route_pattern": "/*",
                    "price": { "amount_micros": 5000, "currency": "USD" },
                    "content_shape": "markdown"
                }
            ]
        }))
        .unwrap();
        let none_accept = policy.resolve_price_for_request("/article", "", None);
        assert_eq!(
            none_accept.amount_micros, 700,
            "no Accept => fallback to top-level price"
        );
    }

    #[test]
    fn malformed_accept_silently_falls_through() {
        // A nonsense Accept value (no recognised media type) doesn't
        // match any shape; tiers without `content_shape` still apply.
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "tiers": [
                {
                    "route_pattern": "/*",
                    "price": { "amount_micros": 9000, "currency": "USD" }
                }
            ]
        }))
        .unwrap();
        let bad = policy.resolve_price_for_request("/article", "", Some("not-a-type;;;"));
        assert_eq!(
            bad.amount_micros, 9000,
            "malformed Accept matches catch-all tier"
        );
    }

    #[test]
    fn content_shape_from_accept_handles_common_types() {
        assert_eq!(
            ContentShape::from_accept("text/html"),
            Some(ContentShape::Html)
        );
        assert_eq!(
            ContentShape::from_accept("application/xhtml+xml"),
            Some(ContentShape::Html)
        );
        assert_eq!(
            ContentShape::from_accept("text/markdown"),
            Some(ContentShape::Markdown)
        );
        assert_eq!(
            ContentShape::from_accept("application/json;charset=utf-8"),
            Some(ContentShape::Json)
        );
        assert_eq!(
            ContentShape::from_accept("application/pdf"),
            Some(ContentShape::Pdf)
        );
        // First match wins across a comma-separated list.
        assert_eq!(
            ContentShape::from_accept("text/markdown, text/html;q=0.5"),
            Some(ContentShape::Markdown)
        );
        // Quality factors do not steer ordering for the simple parser.
        assert_eq!(
            ContentShape::from_accept("application/octet-stream"),
            None,
            "unrecognised types yield None"
        );
        assert_eq!(ContentShape::from_accept(""), None);
    }

    #[test]
    fn no_matching_tier_falls_back_to_top_level_price() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.0005,
            "valid_tokens": [],
            "tiers": [
                { "route_pattern": "/premium/*",
                  "price": { "amount_micros": 5000, "currency": "USD" } }
            ]
        }))
        .unwrap();
        let resolved = policy.resolve_price("/free/post");
        assert_eq!(resolved.amount_micros, 500);
        assert_eq!(resolved.currency, "USD");
    }

    #[test]
    fn challenge_body_includes_tier_metadata() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "tiers": [
                {
                    "route_pattern": "/articles/*",
                    "price": { "amount_micros": 1500, "currency": "USD" },
                    "content_shape": "markdown",
                    "free_preview_bytes": 2048,
                    "paywall_position": "inline"
                }
            ]
        }))
        .unwrap();
        // The tier's `content_shape: markdown` selector now requires the
        // request `Accept` header to negotiate that shape (G1.2 wire).
        let mut h = ua_headers("GPTBot/1.0");
        h.insert(http::header::ACCEPT, "text/markdown".parse().unwrap());
        match policy.check("GET", "x.com", "/articles/foo", &h, None) {
            AiCrawlDecision::Charge { body, .. } => {
                assert!(body.contains("\"amount_micros\":1500"));
                assert!(body.contains("\"content_shape\":\"markdown\""));
                assert!(body.contains("\"free_preview_bytes\":2048"));
                assert!(body.contains("\"paywall_position\":\"inline\""));
            }
            other => panic!("expected Charge, got {:?}", other),
        }
    }

    // --- Ledger trait Result widening ---

    #[derive(Debug)]
    struct AlwaysTransient;
    impl Ledger for AlwaysTransient {
        fn redeem(
            &self,
            _t: &str,
            _h: &str,
            _p: &str,
            _a: u64,
            _c: &str,
        ) -> Result<RedeemResult, LedgerError> {
            Err(LedgerError::transient("ledger.unavailable", "down").with_retry_after(7))
        }
    }

    #[derive(Debug)]
    struct AlwaysHard;
    impl Ledger for AlwaysHard {
        fn redeem(
            &self,
            _t: &str,
            _h: &str,
            _p: &str,
            _a: u64,
            _c: &str,
        ) -> Result<RedeemResult, LedgerError> {
            Err(LedgerError::hard(
                "ledger.token_already_spent",
                "spent already",
            ))
        }
    }

    #[derive(Debug)]
    struct AlwaysHappy;
    impl Ledger for AlwaysHappy {
        fn redeem(
            &self,
            t: &str,
            _h: &str,
            _p: &str,
            a: u64,
            c: &str,
        ) -> Result<RedeemResult, LedgerError> {
            Ok(RedeemResult {
                token_id: t.to_string(),
                amount_micros: a,
                currency: c.to_string(),
                txhash: Some("0xdeadbeef".to_string()),
            })
        }
    }

    #[test]
    fn ledger_transient_error_yields_503_with_retry_after() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
        }))
        .unwrap()
        .with_ledger(Arc::new(AlwaysTransient));
        let h = payment_headers("GPTBot/1.0", "crawler-payment", "any-token");
        match policy.check("GET", "x.com", "/article", &h, None) {
            AiCrawlDecision::LedgerUnavailable {
                retry_after_seconds,
                body,
            } => {
                assert_eq!(retry_after_seconds, 7);
                assert!(body.contains("ledger_unavailable"));
            }
            other => panic!("expected LedgerUnavailable, got {:?}", other),
        }
    }

    #[test]
    fn ledger_hard_error_falls_through_to_402() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
        }))
        .unwrap()
        .with_ledger(Arc::new(AlwaysHard));
        let h = payment_headers("GPTBot/1.0", "crawler-payment", "any-token");
        assert!(matches!(
            policy.check("GET", "x.com", "/article", &h, None),
            AiCrawlDecision::Charge { .. }
        ));
    }

    #[test]
    fn ledger_happy_path_passes_request() {
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
        }))
        .unwrap()
        .with_ledger(Arc::new(AlwaysHappy));
        let h = payment_headers("GPTBot/1.0", "crawler-payment", "tok-abc");
        assert_eq!(
            policy.check("GET", "x.com", "/article", &h, None),
            AiCrawlDecision::Allow
        );
    }

    #[test]
    fn money_from_units_rounds_to_micros() {
        let m = Money::from_units(0.001234567, "USD");
        assert_eq!(m.amount_micros, 1235);
        assert_eq!(m.currency, "USD");
    }

    #[cfg(feature = "http-ledger")]
    #[test]
    fn http_ledger_rejects_plain_http_endpoint() {
        let cfg = HttpLedgerConfig::with_defaults(
            "http://insecure.example.com",
            "k1",
            b"secret-key".to_vec(),
        );
        let err = HttpLedger::new(cfg).unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[cfg(feature = "http-ledger")]
    #[test]
    fn ledger_yaml_block_constructs_http_ledger() {
        // YAML wiring (G1.3): when the operator authors a `ledger:`
        // block on `ai_crawl_control`, `from_config` must swap the
        // bundled InMemoryLedger for an HttpLedger pointing at the
        // configured https endpoint. Plain http:// rejects with the
        // ADR's "must be https://" message.
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "ledger": {
                "url": "https://ledger.internal/v1/ledger",
                "key_id": "test-key-1",
                "key_hex": "0011223344",
                "workspace_id": "default",
                "timeout_ms": 1000,
            }
        }))
        .expect("policy compiles with https ledger");
        // The dyn ledger debug stamp surfaces the configured endpoint.
        let dbg = format!("{:?}", policy);
        assert!(dbg.contains("ledger.internal"), "{dbg}");
    }

    #[cfg(feature = "http-ledger")]
    #[test]
    fn ledger_yaml_block_rejects_plain_http() {
        let err = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "ledger": {
                "url": "http://ledger.internal",
                "key_id": "k1",
                "key_hex": "00",
            }
        }))
        .expect_err("plain http should be rejected");
        assert!(
            err.to_string().contains("https://"),
            "error mentions https requirement: {err}"
        );
    }

    #[cfg(feature = "http-ledger")]
    #[test]
    fn ledger_yaml_block_resolves_secret_ref_env() {
        std::env::set_var("SBPROXY_TEST_LEDGER_HMAC", "deadbeef");
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "ledger": {
                "url": "https://ledger.internal/v1/ledger",
                "key_id": "k2",
                "secret_ref": { "env": "SBPROXY_TEST_LEDGER_HMAC" },
            }
        }))
        .expect("policy compiles with secret_ref.env");
        let dbg = format!("{:?}", policy);
        assert!(dbg.contains("ledger.internal"), "{dbg}");
        std::env::remove_var("SBPROXY_TEST_LEDGER_HMAC");
    }

    // --- G3.4 / G3.5 multi-rail challenge tests ---

    /// Build a multi-rail-enabled policy for tests. Uses a deterministic
    /// 32-byte hex seed so token signatures are reproducible across runs.
    fn multi_rail_policy(price_micros: u64) -> AiCrawlControlPolicy {
        AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": (price_micros as f64) / 1_000_000.0,
            "valid_tokens": [],
            "rails": {
                "x402": {
                    "chain": "base",
                    "facilitator": "https://facilitator-base.x402.org",
                    "asset": "USDC",
                    "pay_to": "0xabc",
                },
                "mpp": {}
            },
            "quote_token": {
                "key_id": "test-kid",
                "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
                "issuer": "https://api.example.com",
                "default_ttl_seconds": 300,
            }
        }))
        .expect("multi-rail policy compiles")
    }

    fn multi_rail_headers(
        ua: &str,
        accept_payment: Option<&str>,
        accept: Option<&str>,
    ) -> http::HeaderMap {
        let mut h = ua_headers(ua);
        if let Some(ap) = accept_payment {
            h.insert("accept-payment", ap.parse().unwrap());
        }
        if let Some(a) = accept {
            h.insert(http::header::ACCEPT, a.parse().unwrap());
        }
        h
    }

    #[test]
    fn multi_rail_challenge_emits_x402_and_mpp_when_accept_matches() {
        let policy = multi_rail_policy(1000);
        let headers =
            multi_rail_headers("GPTBot/1.0", Some("x402;q=1, mpp;q=0.9"), Some("text/html"));
        let decision = policy.check("GET", "x.com", "/articles/foo", &headers, None);
        match decision {
            AiCrawlDecision::MultiRail { body, content_type } => {
                assert_eq!(content_type, MULTI_RAIL_CONTENT_TYPE);
                let parsed: MultiRailChallenge =
                    serde_json::from_str(&body).expect("multi-rail body parses");
                assert_eq!(parsed.rails.len(), 2, "both rails emitted");
                assert_eq!(parsed.rails[0].rail(), Rail::X402);
                assert_eq!(parsed.rails[1].rail(), Rail::Mpp);
                assert_eq!(parsed.agent_choice_method, "header_negotiation");
                assert_eq!(parsed.policy, "first_match_wins");
            }
            other => panic!("expected MultiRail, got {other:?}"),
        }
    }

    #[test]
    fn multi_rail_challenge_falls_back_to_single_rail_for_legacy_agent() {
        // No Accept-Payment header, no multi-rail Accept MIME type -> the
        // policy emits the Wave 1 Crawler-Payment single-rail body even
        // though a multi-rail plan is configured.
        let policy = multi_rail_policy(1000);
        let headers = multi_rail_headers("GPTBot/1.0", None, Some("text/html"));
        let decision = policy.check("GET", "x.com", "/articles/foo", &headers, None);
        match decision {
            AiCrawlDecision::Charge { challenge, body } => {
                assert!(
                    challenge.contains("Crawler-Payment"),
                    "single-rail challenge header"
                );
                assert!(
                    body.contains("\"amount_micros\":1000"),
                    "single-rail body carries price"
                );
            }
            other => panic!("expected single-rail Charge, got {other:?}"),
        }
    }

    #[test]
    fn multi_rail_challenge_each_rail_has_distinct_nonce() {
        let policy = multi_rail_policy(1000);
        let headers = multi_rail_headers("GPTBot/1.0", Some("x402, mpp"), Some("text/html"));
        let AiCrawlDecision::MultiRail { body, .. } =
            policy.check("GET", "x.com", "/articles/foo", &headers, None)
        else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.rails.len(), 2);
        // Each rail's quote token claims should carry a distinct nonce. We
        // re-decode without verifying because verification consumes the
        // nonce; a base64url-decode of the payload segment is enough.
        let nonces: Vec<String> = parsed
            .rails
            .iter()
            .map(|r| extract_nonce_from_token(r.quote_token()))
            .collect();
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1], "each rail has its own nonce");
    }

    #[test]
    fn multi_rail_x402_only_filter_drops_mpp_entry() {
        // Agent only accepts x402; the MPP entry must be filtered.
        let policy = multi_rail_policy(1000);
        let headers = multi_rail_headers("GPTBot/1.0", Some("x402"), None);
        let AiCrawlDecision::MultiRail { body, .. } =
            policy.check("GET", "x.com", "/articles/foo", &headers, None)
        else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.rails.len(), 1);
        assert_eq!(parsed.rails[0].rail(), Rail::X402);
    }

    #[test]
    fn multi_rail_no_acceptable_rail_yields_406() {
        // Agent only accepts a rail the operator does not configure.
        let policy = multi_rail_policy(1000);
        let headers = multi_rail_headers("GPTBot/1.0", Some("lightning"), None);
        let decision = policy.check("GET", "x.com", "/articles/foo", &headers, None);
        match decision {
            AiCrawlDecision::NoAcceptableRail { body } => {
                assert!(body.contains("\"error\":\"no_acceptable_rail\""));
                assert!(body.contains("\"x402\""));
                assert!(body.contains("\"mpp\""));
            }
            other => panic!("expected NoAcceptableRail, got {other:?}"),
        }
    }

    #[test]
    fn multi_rail_accept_application_x402_json_opts_in() {
        // Per A3.1: `Accept: application/x402+json` opts the agent in even
        // without an `Accept-Payment` header. The body is filtered to x402
        // because the Accept-derived preference set lists only x402.
        let policy = multi_rail_policy(1000);
        let headers = multi_rail_headers("GPTBot/1.0", None, Some("application/x402+json"));
        let AiCrawlDecision::MultiRail { body, .. } =
            policy.check("GET", "x.com", "/articles/foo", &headers, None)
        else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.rails.len(), 1);
        assert_eq!(parsed.rails[0].rail(), Rail::X402);
    }

    // --- G3.5 per-shape pricing thread verification ---

    #[test]
    fn per_shape_pricing_threads_shape_claim_into_quote_token() {
        // G3.5 acceptance criterion: the matched tier's `content_shape`
        // must flow end-to-end from the request `Accept` header through
        // tier matching into the quote-token JWS `shape` claim. This
        // test pins the wiring so a future refactor that breaks the
        // thread (e.g. accidentally hard-coding `Other` in
        // `emit_multi_rail`) fails loudly instead of corrupting the
        // audit log.
        //
        // The tier list orders markdown ahead of html so the test
        // proves the shape selector (not declaration order) picks the
        // right tier. The two prices are deliberately distinct so a
        // mistuned matcher would surface as the wrong amount_micros.
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "tiers": [
                {
                    "route_pattern": "/*",
                    "price": { "amount_micros": 5000, "currency": "USD" },
                    "content_shape": "markdown"
                },
                {
                    "route_pattern": "/*",
                    "price": { "amount_micros": 1000, "currency": "USD" },
                    "content_shape": "html"
                }
            ],
            "rails": { "x402": {
                "chain": "base",
                "facilitator": "https://facilitator-base.x402.org",
                "asset": "USDC",
                "pay_to": "0xabc",
            }},
            "quote_token": {
                "key_id": "test-kid",
                "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
                "issuer": "https://api.example.com",
                "default_ttl_seconds": 300,
            }
        }))
        .unwrap();

        // Markdown agent.
        let h_md = multi_rail_headers("GPTBot/1.0", Some("x402"), Some("text/markdown"));
        let AiCrawlDecision::MultiRail { body, .. } =
            policy.check("GET", "x.com", "/article", &h_md, None)
        else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        let claims = decode_token_claims(parsed.rails[0].quote_token());
        assert_eq!(claims.shape, "markdown");
        assert_eq!(claims.price.amount_micros, 5_000);
        assert_eq!(claims.route, "/article");
        assert_eq!(claims.rail, "x402");

        // HTML agent.
        let h_html = multi_rail_headers("GPTBot/1.0", Some("x402"), Some("text/html"));
        let AiCrawlDecision::MultiRail { body, .. } =
            policy.check("GET", "x.com", "/article", &h_html, None)
        else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        let claims = decode_token_claims(parsed.rails[0].quote_token());
        assert_eq!(claims.shape, "html");
        assert_eq!(claims.price.amount_micros, 1_000);
    }

    // --- Wave 3 closeout: G1.4 -> G3.6 agent_id threading ---

    #[test]
    fn check_threads_agent_id_into_quote_token_sub_claim() {
        // Wave 3 closeout: when the caller passes a resolved agent_id
        // (G1.4 stamps it onto RequestContext upstream of the AiCrawl
        // policy), the JWS `sub` claim must be the resolved id, not the
        // Wave 1 `"unknown"` placeholder.
        let policy = multi_rail_policy(1000);
        let headers = multi_rail_headers("GPTBot/1.0", Some("x402"), None);
        let AiCrawlDecision::MultiRail { body, .. } = policy.check(
            "GET",
            "x.com",
            "/articles/foo",
            &headers,
            Some("openai-gptbot"),
        ) else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        let claims = decode_token_claims(parsed.rails[0].quote_token());
        assert_eq!(
            claims.sub, "openai-gptbot",
            "sub claim must carry the resolved agent_id"
        );
    }

    #[test]
    fn check_falls_back_to_unknown_when_agent_id_is_none() {
        // Backward-compat: pre-G1.4 callers (and OSS-default builds that
        // ship without the agent-class feature) pass None and the policy
        // stamps the Wave 1 `"unknown"` placeholder so the JWS issue path
        // never signs an empty sub.
        let policy = multi_rail_policy(1000);
        let headers = multi_rail_headers("GPTBot/1.0", Some("x402"), None);
        let AiCrawlDecision::MultiRail { body, .. } =
            policy.check("GET", "x.com", "/articles/foo", &headers, None)
        else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        let claims = decode_token_claims(parsed.rails[0].quote_token());
        assert_eq!(claims.sub, "unknown");
    }

    #[test]
    fn parse_accept_payment_q_value_ordering() {
        // q-value desc, then declaration order on ties.
        let prefs = parse_accept_payment(Some("mpp;q=0.5, x402;q=0.9")).unwrap();
        assert_eq!(prefs.accepted, vec![Rail::X402, Rail::Mpp]);
        let prefs = parse_accept_payment(Some("x402, mpp")).unwrap();
        assert_eq!(prefs.accepted, vec![Rail::X402, Rail::Mpp]);
        // Wave 7: `lightning` is a known rail and parses; `quux` stands in
        // as the unknown-token guard for the 406 fallback path.
        let prefs = parse_accept_payment(Some("quux, x402")).unwrap();
        assert_eq!(prefs.accepted, vec![Rail::X402]);
        assert!(prefs.had_unknown);
        assert!(parse_accept_payment(None).is_none());
        assert!(parse_accept_payment(Some("")).is_none());
    }

    #[test]
    fn rail_lightning_serde_roundtrips_lowercase_token() {
        // The enterprise-side Lightning BillingRail registers itself as
        // `"lightning"`. The OSS Rail enum's wire form must match exactly
        // so multi-rail negotiation and `Accept-Payment` parsing line up.
        let serialised = serde_json::to_string(&Rail::Lightning).unwrap();
        assert_eq!(serialised, "\"lightning\"");
        let parsed: Rail = serde_json::from_str("\"lightning\"").unwrap();
        assert_eq!(parsed, Rail::Lightning);
        assert_eq!(Rail::Lightning.as_str(), "lightning");
        assert_eq!(Rail::parse("lightning"), Some(Rail::Lightning));
        assert_eq!(Rail::parse("LIGHTNING"), Some(Rail::Lightning));
    }

    #[test]
    fn per_tier_rails_override_filters_emitted_rails() {
        // Tier with `rails: [mpp]` should drop the x402 entry even when
        // the agent and policy both list x402 as acceptable.
        let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "tiers": [
                {
                    "route_pattern": "/preview/*",
                    "price": { "amount_micros": 100, "currency": "USD" },
                    "rails": ["mpp"]
                }
            ],
            "rails": {
                "x402": {
                    "chain": "base",
                    "facilitator": "https://facilitator-base.x402.org",
                    "asset": "USDC",
                    "pay_to": "0xabc",
                },
                "mpp": {}
            },
            "quote_token": {
                "key_id": "test-kid",
                "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
                "issuer": "https://api.example.com",
                "default_ttl_seconds": 300,
            }
        }))
        .unwrap();
        let headers = multi_rail_headers("GPTBot/1.0", Some("x402, mpp"), None);
        let AiCrawlDecision::MultiRail { body, .. } =
            policy.check("GET", "x.com", "/preview/foo", &headers, None)
        else {
            panic!("expected MultiRail");
        };
        let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.rails.len(), 1);
        assert_eq!(parsed.rails[0].rail(), Rail::Mpp);
    }

    #[test]
    fn jwks_endpoint_publishes_active_kid() {
        let policy = multi_rail_policy(1000);
        let jwks = policy.quote_token_jwks().expect("jwks");
        let keys = jwks.get("keys").and_then(|v| v.as_array()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].get("kid").and_then(|v| v.as_str()),
            Some("test-kid")
        );
    }

    #[test]
    fn quote_token_yaml_without_rails_is_a_config_error() {
        let err = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "quote_token": {
                "key_id": "test-kid",
                "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
            }
        }))
        .expect_err("quote_token without rails should fail");
        assert!(err.to_string().contains("rails"), "{err}");
    }

    #[test]
    fn rails_yaml_without_quote_token_is_a_config_error() {
        let err = AiCrawlControlPolicy::from_config(serde_json::json!({
            "price": 0.001,
            "valid_tokens": [],
            "rails": { "mpp": {} }
        }))
        .expect_err("rails without quote_token should fail");
        assert!(err.to_string().contains("quote_token"), "{err}");
    }

    // --- Helpers for the multi-rail tests above ---

    fn decode_token_claims(token: &str) -> crate::policy::quote_token::QuoteClaims {
        use base64::Engine as _;
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("payload b64");
        serde_json::from_slice(&payload).expect("claims decode")
    }

    fn extract_nonce_from_token(token: &str) -> String {
        decode_token_claims(token).nonce
    }
}
