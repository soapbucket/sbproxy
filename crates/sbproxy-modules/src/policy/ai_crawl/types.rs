//! AI Crawl Control types: decisions, rails, tiered pricing, content
//! signals, multi-rail challenges, and the YAML config + ledger shapes.
//!
//! Extracted from the ai_crawl policy module.

use super::*;

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
    /// Multi-rail challenge. Emitted when the agent opted in via
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
    /// Multi-rail negotiation produced no overlap between the
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
    /// The crawler's purpose is governed by a Content Signal the
    /// operator declared as disallowed (`=no`), so the request is
    /// blocked with `403` regardless of any payment it carries. A
    /// training crawler hitting an origin with `ai_train: false` lands
    /// here; a search crawler on the same origin (`search: true`) does
    /// not. `body` is the JSON explanation returned to the client.
    SignalBlocked {
        /// JSON body returned in the 403 response.
        body: String,
    },
}

/// Cloudflare "Content Signals" preference set for an origin's
/// managed `robots.txt`. Each signal is independently optional:
///
/// - `None` -> not declared; omitted from the `robots.txt` directive
///   and never triggers signal-based enforcement.
/// - `Some(true)` -> `=yes` (the use is permitted).
/// - `Some(false)` -> `=no` (the use is disallowed; a crawler whose
///   purpose maps to this signal is blocked).
///
/// `search` covers indexing for search results, `ai_input` covers
/// real-time AI answers and RAG, and `ai_train` covers model
/// training. The directive value uses the hyphenated wire spelling
/// (`ai-input`, `ai-train`) while the config keys stay snake_case to
/// match the rest of the schema. See
/// <https://blog.cloudflare.com/content-signals-policy/>.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentSignals {
    /// Search indexing (appear in search results).
    #[serde(default)]
    pub search: Option<bool>,
    /// Real-time AI input (answers / RAG / assistant fetches).
    #[serde(default)]
    pub ai_input: Option<bool>,
    /// Model training / fine-tuning.
    #[serde(default)]
    pub ai_train: Option<bool>,
}

impl ContentSignals {
    /// True when no signal is declared (the all-absent default). Both
    /// `robots.txt` emission and enforcement skip an empty set.
    pub fn is_empty(&self) -> bool {
        self.search.is_none() && self.ai_input.is_none() && self.ai_train.is_none()
    }

    /// Render the Cloudflare `Content-Signal:` directive value, e.g.
    /// `search=yes, ai-input=no, ai-train=no`. Returns `None` when no
    /// signal is declared. Declared signals are emitted in the fixed
    /// order search, ai-input, ai-train so output is deterministic.
    pub fn directive_value(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut parts: Vec<String> = Vec::with_capacity(3);
        if let Some(v) = self.search {
            parts.push(format!("search={}", yes_no(v)));
        }
        if let Some(v) = self.ai_input {
            parts.push(format!("ai-input={}", yes_no(v)));
        }
        if let Some(v) = self.ai_train {
            parts.push(format!("ai-train={}", yes_no(v)));
        }
        Some(parts.join(", "))
    }

    /// The declared value of the signal that governs `purpose`, if
    /// any. `None` means the signal was left undeclared.
    pub fn signal_for(&self, purpose: CrawlerPurpose) -> Option<bool> {
        match purpose {
            CrawlerPurpose::Train => self.ai_train,
            CrawlerPurpose::Search => self.search,
            CrawlerPurpose::Input => self.ai_input,
        }
    }

    /// Whether a crawler with the given purpose is disallowed by an
    /// explicit `=no` signal. Undeclared and `=yes` signals are not
    /// disallowing.
    pub fn disallows(&self, purpose: CrawlerPurpose) -> bool {
        matches!(self.signal_for(purpose), Some(false))
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Coarse crawl purpose used to map a crawler to the Content Signal
/// that governs it. Deliberately narrower than the agent-class
/// catalogue's `AgentPurpose`: Content Signals only distinguishes
/// model training, search indexing, and real-time AI input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlerPurpose {
    /// Training-data collection (governed by `ai-train`).
    Train,
    /// Search-index population (governed by `search`).
    Search,
    /// Real-time AI input / RAG / assistant fetch (governed by
    /// `ai-input`).
    Input,
}

impl CrawlerPurpose {
    /// The hyphenated wire name of the governing signal.
    pub fn signal_name(self) -> &'static str {
        match self {
            CrawlerPurpose::Train => "ai-train",
            CrawlerPurpose::Search => "search",
            CrawlerPurpose::Input => "ai-input",
        }
    }
}

/// Best-effort purpose classification for the well-known crawlers,
/// used only by Content Signals enforcement. Returns `None` for
/// user-agents we cannot confidently place; those fall through to the
/// normal pricing path rather than being signal-blocked.
///
/// This is intentionally a small, conservative table keyed on the
/// public crawler user-agents that publish a stable purpose. When the
/// `agent-class` feature is on the proxy already resolves a richer
/// agent identity, and a future change can defer to that catalogue's
/// `AgentPurpose` here instead of this list. The training list is
/// checked first so the `-extended` training variants (e.g.
/// `Applebot-Extended`) are not mistaken for their search-bot
/// namesakes (`Applebot`).
pub fn classify_crawler_purpose(user_agent: &str) -> Option<CrawlerPurpose> {
    let ua = user_agent.to_ascii_lowercase();
    const TRAIN: &[&str] = &[
        "gptbot",
        "ccbot",
        "claudebot",
        "anthropic-ai",
        "google-extended",
        "applebot-extended",
        "bytespider",
        "amazonbot",
        "facebookbot",
        "meta-externalagent",
        "diffbot",
        "omgili",
        "timpibot",
        "cohere-ai",
        "perplexitybot",
    ];
    const INPUT: &[&str] = &[
        "chatgpt-user",
        "oai-searchbot",
        "perplexity-user",
        "claude-user",
        "claude-web",
    ];
    const SEARCH: &[&str] = &[
        "googlebot",
        "bingbot",
        "duckduckbot",
        "applebot",
        "yandex",
        "baiduspider",
    ];
    if TRAIN.iter().any(|n| ua.contains(n)) {
        return Some(CrawlerPurpose::Train);
    }
    if INPUT.iter().any(|n| ua.contains(n)) {
        return Some(CrawlerPurpose::Input);
    }
    if SEARCH.iter().any(|n| ua.contains(n)) {
        return Some(CrawlerPurpose::Search);
    }
    None
}

/// Build the JSON body for a [`AiCrawlDecision::SignalBlocked`] 403.
pub(crate) fn signal_blocked_body(purpose: CrawlerPurpose) -> String {
    format!(
        "{{\"error\":\"content_signal_disallowed\",\"signal\":\"{}\",\"detail\":\"this origin's robots.txt Content-Signal disallows {} crawlers\"}}",
        purpose.signal_name(),
        purpose.signal_name()
    )
}

/// MIME type for the multi-rail 402 body per A3.1.
pub const MULTI_RAIL_CONTENT_TYPE: &str = "application/sbproxy-multi-rail+json";

/// Closed enum of payment rails the proxy can advertise. Mirrors the
/// `Accept-Payment` token set and the per-tier `rails:` override list.
/// New rails follow the closed-enum amendment rule. Wave 7 added
/// `Lightning` to mirror the externally-registered rail named
/// `"lightning"`.
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
/// `code` is a closed dotted-string set. `retryable` distinguishes a
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
///
/// This stays a trait rather than an enum: the implementation is selected
/// at runtime from config (in-memory vs HTTP backend) and tests inject
/// their own fakes through `Arc<dyn Ledger>`, so it is genuinely
/// polymorphic.
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

// --- Tiered pricing types ---

/// Closed enumeration of the content shapes the policy can price for.
///
/// The closed value set is shared with the
/// `content_shape` label budget on `sbproxy_requests_total` and the
/// HTTP ledger `payload.content_shape` field so they share one vocabulary.
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
    /// the registry feed returns. Empty string = wildcard.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Optional free-preview byte budget. Zero-price tiers with a
    /// preview budget pass through without payment; paid tiers surface
    /// the budget in the challenge body so cooperative crawlers can
    /// decide up front.
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

    /// Returns true when this tier represents a free-preview lane the
    /// request path can enter without presenting a payment token.
    pub fn allows_free_preview(&self) -> bool {
        self.free_preview_bytes.unwrap_or(0) > 0 && self.price.amount_micros == 0
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

// --- Content-Signal header value ---

/// Closed enumeration of valid `Content-Signal` response header values.
///
/// G4.1: the proxy stamps `Content-Signal: <value>`
/// on 200 responses when the origin's `content_signal:` config key is
/// set; the value vocabulary is closed per A1.8 so any unknown value
/// fails config compilation.
///
/// The header is a cooperative signal for standards-compliant crawlers
/// and a mandatory field surfaced by the JSON envelope. It is
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

// --- Multi-rail challenge body ---

/// One entry in the multi-rail 402 body's `rails` array.
///
/// Common fields (`amount_micros`, `currency`, `expires_at`, `quote_token`)
/// live alongside the rail-specific extension fields under one JSON shape.
/// The enum representation uses a closed `kind` discriminator so a
/// future third rail can land without breaking existing parsers.
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

pub(super) fn default_x402_asset() -> String {
    "USDC".to_string()
}

pub(super) fn default_x402_version() -> String {
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

pub(super) fn default_mpp_version() -> String {
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

pub(super) fn default_quote_issuer() -> String {
    "sbproxy://local".to_string()
}

pub(super) fn default_quote_ttl() -> u64 {
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
    /// the policy redeems tokens against a network ledger instead of
    /// the bundled in-memory ledger. `valid_tokens` stays valid as a
    /// dev-mode
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
    /// Cloudflare Content Signals for the managed `robots.txt`
    /// (`search` / `ai_input` / `ai_train`). When any signal is
    /// declared, the projection emits a `Content-Signal:` directive
    /// and the policy blocks a crawler whose purpose maps to a
    /// disallowed (`=no`) signal. The same set drives the RSL
    /// `<ai-use>` assertions so the two never contradict. Empty (the
    /// default) keeps both behaviours off, so existing configs are
    /// unaffected.
    #[serde(default)]
    pub content_signals: ContentSignals,
}

// --- Ledger YAML shape (G1.3 wire) ---

/// YAML configuration for the HTTP ledger client.
///
/// Mirrors the typed `HttpLedgerConfig` but with operator-friendly
/// field names and a few convenience knobs (env-resolved secret,
/// optional flat retry / breaker subblocks).
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerYamlConfig {
    /// Base URL of the ledger. Plain `http://` is rejected at
    /// construction time; operators must use `https://`.
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
    #[serde(default)]
    pub env: Option<String>,
    /// Logical `secret:<name>` reference resolved through sbproxy-vault.
    #[serde(default)]
    pub secret: Option<String>,
}

pub(super) fn resolve_secret_ref(sref: &LedgerSecretRef, context: &str) -> anyhow::Result<String> {
    if let Some(env) = sref.env.as_deref() {
        return std::env::var(env)
            .map_err(|_| anyhow::anyhow!("{context}.secret_ref.env: env var '{env}' not set"));
    }
    if let Some(secret) = sref.secret.as_deref() {
        let resolver = sbproxy_vault::SecretResolver::new(None, std::collections::HashMap::new())
            .with_fallback(sbproxy_vault::ResolveFallback::Env);
        return resolver
            .resolve(&format!("secret:{secret}"))
            .map_err(|e| anyhow::anyhow!("{context}.secret_ref.secret: {e}"));
    }
    anyhow::bail!("{context}.secret_ref requires either env or secret")
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

pub(super) fn default_workspace_id() -> String {
    "default".to_string()
}

pub(super) fn default_idempotency_header() -> String {
    "Idempotency-Key".to_string()
}

pub(super) fn default_timeout_ms() -> u64 {
    5_000
}

pub(super) fn default_retry_max_attempts() -> u32 {
    5
}

pub(super) fn default_retry_initial_backoff() -> u64 {
    250
}

pub(super) fn default_retry_max_backoff() -> u64 {
    5_000
}

pub(super) fn default_breaker_failure_threshold() -> u32 {
    10
}

pub(super) fn default_breaker_success_threshold() -> u32 {
    1
}

pub(super) fn default_breaker_open_duration() -> u64 {
    5_000
}

pub(super) fn default_currency() -> String {
    "USD".to_string()
}

pub(super) fn default_header() -> String {
    "crawler-payment".to_string()
}

pub(super) fn default_crawler_uas() -> Vec<String> {
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

#[cfg(test)]
mod content_signal_tests {
    use super::*;

    fn signals(
        search: Option<bool>,
        ai_input: Option<bool>,
        ai_train: Option<bool>,
    ) -> ContentSignals {
        ContentSignals {
            search,
            ai_input,
            ai_train,
        }
    }

    #[test]
    fn empty_set_emits_no_directive() {
        let s = ContentSignals::default();
        assert!(s.is_empty());
        assert_eq!(s.directive_value(), None);
    }

    #[test]
    fn directive_value_uses_wire_spelling_and_fixed_order() {
        let s = signals(Some(true), Some(false), Some(false));
        assert_eq!(
            s.directive_value().as_deref(),
            Some("search=yes, ai-input=no, ai-train=no")
        );
    }

    #[test]
    fn directive_value_omits_undeclared_signals() {
        let s = signals(Some(true), None, Some(false));
        assert_eq!(
            s.directive_value().as_deref(),
            Some("search=yes, ai-train=no")
        );
    }

    #[test]
    fn disallows_only_on_explicit_no() {
        let s = signals(Some(true), None, Some(false));
        assert!(s.disallows(CrawlerPurpose::Train)); // ai-train=no
        assert!(!s.disallows(CrawlerPurpose::Search)); // search=yes
        assert!(!s.disallows(CrawlerPurpose::Input)); // undeclared
    }

    #[test]
    fn classify_training_search_and_input_bots() {
        assert_eq!(
            classify_crawler_purpose("Mozilla/5.0 (compatible; GPTBot/1.0)"),
            Some(CrawlerPurpose::Train)
        );
        assert_eq!(
            classify_crawler_purpose("Mozilla/5.0 (compatible; ClaudeBot/1.0)"),
            Some(CrawlerPurpose::Train)
        );
        assert_eq!(
            classify_crawler_purpose("Mozilla/5.0 (compatible; Googlebot/2.1)"),
            Some(CrawlerPurpose::Search)
        );
        assert_eq!(
            classify_crawler_purpose("ChatGPT-User/1.0"),
            Some(CrawlerPurpose::Input)
        );
        assert_eq!(classify_crawler_purpose("Mozilla/5.0 (Macintosh)"), None);
    }

    #[test]
    fn applebot_extended_is_training_not_search() {
        // `Applebot-Extended` (training opt-out signal) must not be
        // mistaken for `Applebot` (search) via substring overlap.
        assert_eq!(
            classify_crawler_purpose("Applebot-Extended/1.0"),
            Some(CrawlerPurpose::Train)
        );
        assert_eq!(
            classify_crawler_purpose("Applebot/0.1"),
            Some(CrawlerPurpose::Search)
        );
    }

    #[test]
    fn signal_blocked_body_names_the_signal() {
        let body = signal_blocked_body(CrawlerPurpose::Train);
        assert!(body.contains("\"signal\":\"ai-train\""));
        assert!(body.contains("content_signal_disallowed"));
    }
}
