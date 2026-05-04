//! Policy module - enum dispatch for built-in policy enforcers.

/// Wave 7 / A7.2 A2A protocol policy module.
pub mod a2a;
/// `Accept-Payment` header parser (Wave 3 / R3.1, A3.1).
pub mod accept_payment;
#[cfg(feature = "agent-class")]
pub mod agent_class;
pub mod ai_crawl;
/// aipref preference signal parser (Wave 4 / G4.9).
pub mod aipref;
pub mod dlp;
pub mod http_framing;
pub mod openapi_validation;
pub mod page_shield;
pub mod prompt_injection_v2;
pub mod quote_token;
pub mod sharded_limiter;
pub mod waf;

pub use a2a::{
    A2APolicy, A2APolicyConfig, A2APolicyDecision, CycleDetection, A2A_HARD_CHAIN_DEPTH_CEILING,
    DEFAULT_MAX_CHAIN_DEPTH,
};
pub use accept_payment::{
    rail_tokens as accept_payment_rail_tokens, AcceptPayment,
    ParseError as AcceptPaymentParseError, RailKind, RailPreference,
};
pub use ai_crawl::{
    accept_implies_multi_rail, parse_accept_payment, resolve_agent_preferences,
    AgentRailPreferences, AiCrawlControlPolicy, AiCrawlDecision, ConfiguredRailForTest,
    ContentShape, ContentSignal, ContentSignalParseError, InMemoryLedger, Ledger as AiCrawlLedger,
    LedgerError, Money, MultiRailChallenge, PaywallPosition, Rail, RailChallenge, RedeemResult,
    Tier, MULTI_RAIL_CONTENT_TYPE,
};
#[cfg(feature = "http-ledger")]
pub use ai_crawl::{HttpLedger, HttpLedgerConfig};
pub use aipref::{parse_aipref, AiprefParseError, AiprefSignal};
pub use dlp::{DlpAction, DlpDirection, DlpPolicy, DlpScanResult};
pub use http_framing::{FramingViolation, HttpFramingPolicy};
pub use openapi_validation::{
    OpenApiValidationMode, OpenApiValidationPolicy, ValidationResult as OpenApiValidationResult,
};
pub use page_shield::{PageShieldMode, PageShieldPolicy, DEFAULT_REPORT_PATH};
pub use prompt_injection_v2::{
    classification_cache_stats, evaluate_body, reset_classification_cache, BodyAwareConfig,
    BodyAwareOutcome, ClassificationCacheStats, DetectionLabel, DetectionResult, Detector,
    OnnxDetector, PromptInjectionAction, PromptInjectionV2Outcome, PromptInjectionV2Policy,
    HEURISTIC_DETECTOR_NAME, ONNX_DETECTOR_NAME,
};
pub use quote_token::{
    InMemoryNonceStore, IssuedQuote, NonceCheck, NonceError, NonceStore, QuoteClaims,
    QuoteTokenSigner, QuoteTokenVerifier, SignError, VerifyError, MAX_IAT_SKEW,
};
pub use waf::{
    shutdown_waf_feed_tasks, FeedRule, FeedRuleAction, FeedRuleSeverity, RuleSet, WafFeedConfig,
    WafFeedSubscriber, WafFeedTransport,
};

use base64::Engine as _;
use ipnetwork::IpNetwork;
use regex::Regex;
use sbproxy_platform::storage::{AsyncKVStore, KVStore};
use sbproxy_plugin::PolicyEnforcer;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
// parking_lot::Mutex is ~2-3x faster than std::sync::Mutex under contention.
// Critical for rate-limit scenarios (P08/P09) where every request at 15k rps
// locks the token bucket. See sbproxy-bench/docs/RUST_OPTIMIZATIONS.md A4.
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;
use tracing;

// --- Policy Enum ---

/// Policy enforcer - enum dispatch for built-in types.
/// Each variant holds its compiled config inline (no Box indirection).
pub enum Policy {
    /// Rate limiting policy.
    RateLimit(RateLimitPolicy),
    /// IP allow/deny filter based on CIDR lists.
    IpFilter(IpFilterPolicy),
    /// Injects security headers into responses.
    SecHeaders(SecHeadersPolicy),
    /// Limits request body size, header count, etc.
    RequestLimit(RequestLimitPolicy),
    /// CSRF token validation.
    Csrf(CsrfPolicy),
    /// DDoS protection with connection tracking.
    Ddos(DdosPolicy),
    /// Subresource Integrity validation.
    Sri(SriPolicy),
    /// CEL expression-based policy. Evaluates a CEL expression against the
    /// request context. If the expression evaluates to false, the request is denied.
    Expression(ExpressionPolicy),
    /// CEL assertion policy for response-time validation. Evaluates a CEL
    /// expression and logs/flags when it returns false.
    Assertion(AssertionPolicy),
    /// Web Application Firewall policy.
    Waf(WafPolicy),
    /// Validates request bodies against a JSON Schema before they
    /// reach the upstream. Rejects malformed or non-conforming
    /// payloads at the edge with a configurable status / body.
    RequestValidator(RequestValidatorPolicy),
    /// Caps in-flight (concurrent) requests per route, per IP, or per
    /// API key. Distinct from RateLimit which throttles RPS.
    ConcurrentLimit(ConcurrentLimitPolicy),
    /// AI Crawl Control: emits HTTP 402 challenges to crawlers that
    /// arrive without a valid `Crawler-Payment` token.
    AiCrawl(AiCrawlControlPolicy),
    /// Detects exposed credentials in inbound requests against a
    /// pre-loaded password list. Tags the upstream request with an
    /// `Exposed-Credential-Check` header or blocks the request, per
    /// the configured action. See [`ExposedCredsPolicy`].
    ExposedCreds(ExposedCredsPolicy),
    /// Page Shield: stamps a CSP header on every response with the
    /// configured directives plus a `report-uri` pointing back to the
    /// proxy intake endpoint.
    PageShield(PageShieldPolicy),
    /// Data Loss Prevention scan over request URI + headers. Matches
    /// against the configured detector catalogue and either tags the
    /// upstream request or blocks the call.
    Dlp(DlpPolicy),
    /// Validates incoming request bodies against a published OpenAPI
    /// 3.0 specification. Operations are indexed at startup; per-path
    /// per-method per-content-type schemas are compiled once.
    OpenApiValidation(OpenApiValidationPolicy),
    /// `prompt_injection_v2`: scoring detector + configurable action.
    /// Holds a swappable [`Detector`] and either tags, blocks, or
    /// logs requests whose prompt scores above the threshold. The OSS
    /// build registers a heuristic detector by default; the trait is
    /// designed so a future ONNX classifier can plug in cleanly.
    PromptInjectionV2(PromptInjectionV2Policy),
    /// HTTP framing policy. Detects request smuggling primitives
    /// (CL.TE, TE.CL, TE.TE, duplicate CL, malformed Transfer-Encoding,
    /// CRLF / NUL injection) and rejects the request with a 400 before
    /// it reaches the upstream. See `policy/http_framing.rs`.
    HttpFraming(HttpFramingPolicy),
    /// Agent-class policy (G1.4 wire). Marker policy that opts an
    /// origin into the agent-class resolver chain. The resolver
    /// itself runs in the request pipeline (`stamp_request_context`);
    /// this policy carries the per-origin knobs (forward-to-upstream
    /// header names, rDNS override). Feature-gated via `agent-class`.
    #[cfg(feature = "agent-class")]
    AgentClass(agent_class::AgentClassPolicy),
    /// A2A (agent-to-agent) policy module (Wave 7 / A7.2). Per-route
    /// chain-depth cap, cycle detection, callee allowlist, caller
    /// denylist. Evaluation reads `RequestContext.a2a` populated by
    /// the request filter. See `docs/adr-a2a-protocol-envelope.md`.
    A2A(a2a::A2APolicy),
    /// Third-party plugin (only case using dynamic dispatch).
    Plugin(Box<dyn PolicyEnforcer>),
}

impl Policy {
    /// Get the type name for this policy.
    pub fn policy_type(&self) -> &str {
        match self {
            Self::RateLimit(_) => "rate_limiting",
            Self::IpFilter(_) => "ip_filter",
            Self::SecHeaders(_) => "security_headers",
            Self::RequestLimit(_) => "request_limit",
            Self::Csrf(_) => "csrf",
            Self::Ddos(_) => "ddos",
            Self::Sri(_) => "sri",
            Self::Expression(_) => "expression",
            Self::Assertion(_) => "assertion",
            Self::Waf(_) => "waf",
            Self::RequestValidator(_) => "request_validator",
            Self::ConcurrentLimit(_) => "concurrent_limit",
            Self::AiCrawl(_) => "ai_crawl_control",
            Self::ExposedCreds(_) => "exposed_credentials",
            Self::PageShield(_) => "page_shield",
            Self::Dlp(_) => "dlp",
            Self::OpenApiValidation(_) => "openapi_validation",
            Self::PromptInjectionV2(_) => "prompt_injection_v2",
            Self::HttpFraming(_) => "http_framing",
            #[cfg(feature = "agent-class")]
            Self::AgentClass(_) => "agent_class",
            Self::A2A(_) => "a2a",
            Self::Plugin(p) => p.policy_type(),
        }
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimit(r) => f.debug_tuple("RateLimit").field(r).finish(),
            Self::IpFilter(r) => f.debug_tuple("IpFilter").field(r).finish(),
            Self::SecHeaders(r) => f.debug_tuple("SecHeaders").field(r).finish(),
            Self::RequestLimit(r) => f.debug_tuple("RequestLimit").field(r).finish(),
            Self::Csrf(r) => f.debug_tuple("Csrf").field(r).finish(),
            Self::Ddos(r) => f.debug_tuple("Ddos").field(r).finish(),
            Self::Sri(r) => f.debug_tuple("Sri").field(r).finish(),
            Self::Expression(r) => f.debug_tuple("Expression").field(r).finish(),
            Self::Assertion(r) => f.debug_tuple("Assertion").field(r).finish(),
            Self::Waf(r) => f.debug_tuple("Waf").field(r).finish(),
            Self::RequestValidator(r) => f.debug_tuple("RequestValidator").field(r).finish(),
            Self::ConcurrentLimit(r) => f.debug_tuple("ConcurrentLimit").field(r).finish(),
            Self::AiCrawl(r) => f.debug_tuple("AiCrawl").field(r).finish(),
            Self::ExposedCreds(r) => f.debug_tuple("ExposedCreds").field(r).finish(),
            Self::PageShield(r) => f.debug_tuple("PageShield").field(r).finish(),
            Self::Dlp(r) => f.debug_tuple("Dlp").field(r).finish(),
            Self::OpenApiValidation(r) => f.debug_tuple("OpenApiValidation").field(r).finish(),
            Self::PromptInjectionV2(r) => f.debug_tuple("PromptInjectionV2").field(r).finish(),
            Self::HttpFraming(r) => f.debug_tuple("HttpFraming").field(r).finish(),
            #[cfg(feature = "agent-class")]
            Self::AgentClass(r) => f.debug_tuple("AgentClass").field(r).finish(),
            Self::A2A(r) => f.debug_tuple("A2A").field(r).finish(),
            Self::Plugin(_) => write!(f, "Plugin(...)"),
        }
    }
}

// --- RateLimitPolicy ---

/// Info returned after a rate limit check, for adding response headers.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Whether the request was allowed.
    pub allowed: bool,
    /// The configured limit (requests per window).
    pub limit: u64,
    /// Remaining requests in the current window.
    pub remaining: u64,
    /// Seconds until the bucket fully refills (delta format).
    pub reset_secs: u64,
    /// Whether rate limit headers should be emitted.
    pub headers_enabled: bool,
    /// Whether to include the Retry-After header on 429 responses.
    pub include_retry_after: bool,
}

/// Rate limit policy using a token bucket algorithm.
///
/// Tokens refill at `requests_per_second` rate, up to `burst` capacity.
/// Each allowed request consumes one token. When the bucket is empty,
/// requests are rejected until tokens refill.
///
/// When an L2 store (Redis) is attached via [`RateLimitPolicy::with_store`], rate limiting
/// switches to a distributed *fixed-window counter* so multiple proxy
/// replicas share state. This is intentionally simpler than the token-bucket
/// algorithm (and not smoothly refilled) but it lets a cluster enforce a
/// single shared limit.
#[derive(Deserialize)]
pub struct RateLimitPolicy {
    /// Per-second token refill rate.
    #[serde(default)]
    pub requests_per_second: Option<f64>,
    /// Per-minute token refill rate (mutually exclusive with `requests_per_second`).
    #[serde(default)]
    pub requests_per_minute: Option<f64>,
    /// Maximum burst capacity. When unset, defaults to the per-second rate.
    #[serde(default)]
    pub burst: Option<u32>,
    /// Algorithm hint (`token_bucket`, `fixed_window`); the runtime picks based on backend.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Header configuration (`X-RateLimit-*`, `Retry-After`).
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    /// Optional list of IPs/CIDRs that are exempt from rate limiting.
    #[serde(default)]
    pub whitelist: Option<Vec<String>>,
    /// Optional CEL expression evaluated against the request context to
    /// derive the bucket key. Common idioms:
    ///
    /// - `connection.remote_ip`: per-IP buckets (default behaviour when
    ///   the field is unset).
    /// - `request.headers["x-api-key"]`: per-API-key buckets.
    /// - `jwt.claims.tenant_id`: per-JWT-claim buckets (the
    ///   "Volumetric Abuse Detection" pattern).
    /// - `jwt.claims.sub + ":" + jwt.claims.tenant_id`: composite keys.
    ///
    /// When evaluation fails or returns empty, the policy falls back to
    /// the default client IP / hostname behaviour. Each distinct key
    /// gets its own token bucket; the cache is bounded so unbounded
    /// key cardinality cannot exhaust memory.
    #[serde(default)]
    pub key: Option<String>,
    /// Maximum number of distinct keys tracked locally. When the cache
    /// is full, the least-recently-used key is evicted. Defaults to
    /// 100k which keeps the bucket map under ~10 MB even with long key
    /// strings.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
    #[serde(skip)]
    buckets: Mutex<Option<lru::LruCache<String, TokenBucket>>>,
    #[serde(skip)]
    template_bucket: Mutex<TokenBucket>,

    // --- Optional L2 (cluster-shared) state ---
    /// Shared counter backend (sync). When `Some`, requests are gated by
    /// a Redis-backed fixed-window counter via `spawn_blocking`. Kept
    /// for callers that have not yet migrated to `async_store`.
    #[serde(skip)]
    store: Option<Arc<dyn KVStore>>,
    /// Shared counter backend (async-native). When `Some`, `allow_with_info_async`
    /// prefers this path over the sync `store`. Uses the `redis` crate's
    /// async client directly, with no `spawn_blocking` overhead per request.
    /// See `AsyncKVStore` + `AsyncRedisKVStore` in `sbproxy-platform`.
    #[serde(skip)]
    async_store: Option<Arc<dyn AsyncKVStore>>,
    /// Optional observer invoked after every successful L2 increment.
    /// Receives the post-increment count so consumers (e.g. the mesh
    /// persistence `SharedState`) can mirror the counter into a CRDT
    /// snapshot without knowing about the underlying store. Called only
    /// on the success path; failures are silent (fail-warn posture).
    #[serde(skip)]
    observer: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    /// Fixed-window length in seconds when `store` is active. Derived from
    /// the configured rate (1 s for `requests_per_second`, 60 s for
    /// `requests_per_minute`).
    #[serde(skip)]
    window_secs: u64,
    /// Pre-computed counter-key prefix so request-hot path does not allocate
    /// more than necessary. Format: `"sbproxy:rl:<origin-id>:"`.
    #[serde(skip)]
    key_prefix: String,
}

// Manual Debug impl because `dyn KVStore` has no `Debug` bound.
impl std::fmt::Debug for RateLimitPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitPolicy")
            .field("requests_per_second", &self.requests_per_second)
            .field("requests_per_minute", &self.requests_per_minute)
            .field("burst", &self.burst)
            .field("algorithm", &self.algorithm)
            .field("headers", &self.headers)
            .field("whitelist", &self.whitelist)
            .field("key", &self.key)
            .field("max_keys", &self.max_keys)
            .field("template_bucket", &self.template_bucket)
            .field("store_attached", &self.store.is_some())
            .field("async_store_attached", &self.async_store.is_some())
            .field("window_secs", &self.window_secs)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

impl RateLimitPolicy {
    /// Get the effective requests per second rate.
    fn effective_rps(&self) -> f64 {
        if let Some(rps) = self.requests_per_second {
            rps
        } else if let Some(rpm) = self.requests_per_minute {
            rpm / 60.0
        } else {
            10.0 // Default: 10 rps
        }
    }
}

/// Internal token bucket state.
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self {
            tokens: 0.0,
            max_tokens: 0.0,
            refill_rate: 0.0,
            last_refill: Instant::now(),
        }
    }
}

fn default_max_keys() -> usize {
    100_000
}

impl RateLimitPolicy {
    /// Build a RateLimitPolicy from a generic JSON config value.
    ///
    /// After deserialization, initializes the token bucket with the
    /// correct capacity and refill rate. When `burst` is not explicitly
    /// set, it defaults to the effective rate (e.g. requests_per_minute)
    /// so the bucket is exhausted after exactly that many requests.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        let rps = policy.effective_rps();

        // Compute effective burst: if not explicitly set, use the rate limit
        // value so the bucket capacity matches the configured limit.
        let effective_burst = policy.burst.unwrap_or_else(|| {
            if let Some(rpm) = policy.requests_per_minute {
                rpm.ceil() as u32
            } else if let Some(rps_val) = policy.requests_per_second {
                rps_val.ceil() as u32
            } else {
                10
            }
        });

        let template = TokenBucket {
            tokens: effective_burst as f64,
            max_tokens: effective_burst as f64,
            refill_rate: rps,
            last_refill: Instant::now(),
        };
        // The template is the seed every per-key bucket clones from. It also
        // backs the legacy single-bucket path used when `key:` is unset.
        policy.template_bucket = Mutex::new(template);
        // Per-key buckets are only allocated when a `key:` expression is
        // configured. Cap defaults to 100k via `default_max_keys`.
        policy.buckets = if policy.key.is_some() {
            let cap = policy.max_keys.max(1);
            let cap = std::num::NonZeroUsize::new(cap).expect("cap is at least 1");
            Mutex::new(Some(lru::LruCache::new(cap)))
        } else {
            Mutex::new(None)
        };

        // Window length in seconds for the Redis-backed counter path. Prefer
        // requests_per_minute when that's how the limit is declared, otherwise
        // use a 1-second window for requests_per_second.
        policy.window_secs = if policy.requests_per_minute.is_some() {
            60
        } else {
            1
        };

        Ok(policy)
    }

    /// Attach a shared L2 store so this policy enforces a cluster-wide
    /// fixed-window counter. The `origin_id` is baked into every Redis
    /// key so different origins don't share counter state.
    ///
    /// When `store` is `None` the policy keeps the in-process token bucket.
    pub fn with_store(mut self, store: Option<Arc<dyn KVStore>>, origin_id: &str) -> Self {
        self.store = store;
        self.key_prefix = format!("sbproxy:rl:{}:", origin_id);
        self
    }

    /// Attach an **async** shared L2 store. Takes precedence over the sync
    /// `store` on the request-hot path: `allow_with_info_async` calls the
    /// async backend directly via `.await` without bridging through
    /// `spawn_blocking`.
    ///
    /// `origin_id` is baked into the counter-key prefix the same way
    /// [`Self::with_store`] does it. Calling this sets the prefix only if
    /// the sync `with_store` hasn't already set it, so both setters can
    /// be chained in either order.
    pub fn with_async_store(
        mut self,
        store: Option<Arc<dyn AsyncKVStore>>,
        origin_id: &str,
    ) -> Self {
        self.async_store = store;
        if self.key_prefix.is_empty() {
            self.key_prefix = format!("sbproxy:rl:{}:", origin_id);
        }
        self
    }

    /// Attach an observer closure called after every successful L2
    /// counter increment (both async and sync paths). Designed for
    /// the mesh persistence `SharedState` pattern: the enterprise
    /// startup hook creates a closure that pushes the post-increment
    /// count into the shared CRDT, so snapshots to Redis reflect
    /// real rate-limit state instead of placeholder empties.
    ///
    /// Pass `None` to clear a previously attached observer. Observer
    /// closures must be cheap, since they run on the request-hot path.
    pub fn with_observer(mut self, observer: Option<Arc<dyn Fn(u64) + Send + Sync>>) -> Self {
        self.observer = observer;
        self
    }

    /// Effective per-window limit used by the Redis-backed fixed-window path.
    fn window_limit(&self) -> u64 {
        if let Some(rpm) = self.requests_per_minute {
            rpm.ceil() as u64
        } else if let Some(rps) = self.requests_per_second {
            rps.ceil() as u64
        } else {
            10
        }
    }

    /// Check whether rate limit headers are enabled in the config.
    fn headers_enabled(&self) -> bool {
        self.headers
            .as_ref()
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Check whether the include_retry_after option is enabled.
    fn include_retry_after(&self) -> bool {
        self.headers
            .as_ref()
            .and_then(|v| v.get("include_retry_after"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Try to consume a token. Returns true if the request is allowed,
    /// false if rate-limited.
    pub fn allow(&self) -> bool {
        self.allow_with_info().allowed
    }

    /// Try to consume a token from the default (single, shared) bucket.
    /// Equivalent to `allow_with_info_for("")`.
    pub fn allow_with_info(&self) -> RateLimitInfo {
        self.allow_with_info_for("")
    }

    /// Try to consume a token from the bucket associated with `key`.
    ///
    /// When the policy has no `key:` expression configured, every call
    /// shares the same template bucket regardless of the argument. When
    /// `key:` is set, each distinct key gets its own bucket via an LRU
    /// cache bounded by `max_keys`.
    ///
    /// This is the local-only path; it does not consult any shared L2
    /// store.
    pub fn allow_with_info_for(&self, key: &str) -> RateLimitInfo {
        let now = Instant::now();
        let headers_enabled = self.headers_enabled();
        let include_retry_after = self.include_retry_after();

        // Resolve which bucket to act on. The per-key path uses the LRU
        // map and may insert a fresh bucket cloned from the template;
        // the legacy path operates on the shared template bucket.
        let mut buckets_guard = self.buckets.lock();
        let mut template_guard;
        let bucket: &mut TokenBucket = if let Some(map) = buckets_guard.as_mut() {
            if !map.contains(key) {
                let template = self.template_bucket.lock().clone();
                map.put(key.to_string(), template);
            }
            map.get_mut(key).expect("inserted just above")
        } else {
            template_guard = self.template_bucket.lock();
            &mut template_guard
        };

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;

        let limit = bucket.max_tokens as u64;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let remaining = bucket.tokens.floor() as u64;
            let deficit = bucket.max_tokens - bucket.tokens;
            let reset_secs = if bucket.refill_rate > 0.0 {
                (deficit / bucket.refill_rate).ceil() as u64
            } else {
                0
            };
            // Drop both guards before the observer call. The observer may
            // grab a separate lock (e.g. mesh SharedState) and we don't
            // want to hold the bucket cache while it runs.
            drop(buckets_guard);
            if let Some(obs) = self.observer.as_ref() {
                obs(1);
            }
            RateLimitInfo {
                allowed: true,
                limit,
                remaining,
                reset_secs,
                headers_enabled,
                include_retry_after,
            }
        } else {
            let full_reset = if bucket.refill_rate > 0.0 {
                (bucket.max_tokens / bucket.refill_rate).ceil() as u64
            } else {
                0
            };
            RateLimitInfo {
                allowed: false,
                limit,
                remaining: 0,
                reset_secs: full_reset,
                headers_enabled,
                include_retry_after,
            }
        }
    }

    /// Async variant of [`RateLimitPolicy::allow_with_info`].
    ///
    /// When a shared L2 store is attached, this enforces a *fixed-window
    /// counter* in Redis (atomic INCR + EXPIRE). The window length is
    /// derived from the rate unit (`requests_per_second` -> 1 s window,
    /// `requests_per_minute` -> 60 s window). Note this is a different
    /// algorithm from the local token bucket: it does not smoothly refill
    /// or admit bursts above the rate limit.
    ///
    /// When no store is attached, this falls back to the sync token-bucket
    /// path (same semantics as [`RateLimitPolicy::allow_with_info`]).
    ///
    /// If the Redis call fails, the request is admitted (fail-open). The
    /// alternative (fail-closed) would turn a Redis hiccup into a
    /// cluster-wide outage. The Go OSS proxy makes the same choice.
    pub async fn allow_with_info_async(&self, client_id: &str) -> RateLimitInfo {
        // Prefer the async store (no spawn_blocking overhead). Fall back
        // to the sync store via spawn_blocking for callers that have not
        // migrated yet. If neither is configured, fall all the way back
        // to the local per-key token bucket.
        if self.async_store.is_none() && self.store.is_none() {
            return self.allow_with_info_for(client_id);
        }

        let window = if self.window_secs > 0 {
            self.window_secs
        } else {
            1
        };
        let limit = self.window_limit();
        let headers_enabled = self.headers_enabled();
        let include_retry_after = self.include_retry_after();

        // Bucket the counter by wall-clock epoch so the window moves
        // forward together across replicas. Each window gets its own key.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = now_secs - (now_secs % window);

        let key = format!("{}{}:{}", self.key_prefix, client_id, window_start);
        let ttl = window + 1;
        let key_bytes = key.into_bytes();

        // Fail-open helper: Redis hiccups should not turn into a
        // cluster-wide outage. Matches the Go OSS proxy's choice.
        let fail_open = || RateLimitInfo {
            allowed: true,
            limit,
            remaining: limit,
            reset_secs: window,
            headers_enabled,
            include_retry_after,
        };

        let incr_result: anyhow::Result<i64> = if let Some(async_store) = self.async_store.as_ref()
        {
            // Async path: native await, no spawn_blocking tax.
            async_store.incr_with_ttl(&key_bytes, ttl).await
        } else {
            let store = self
                .store
                .clone()
                .expect("checked at function entry that at least one store is set");
            // Sync fallback path via spawn_blocking.
            match tokio::task::spawn_blocking({
                let key_bytes = key_bytes.clone();
                move || store.incr_with_ttl(&key_bytes, ttl)
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "l2 rate-limit spawn_blocking join failed");
                    return fail_open();
                }
            }
        };

        let count = match incr_result {
            Ok(n) => n as u64,
            Err(e) => {
                tracing::warn!(error = %e, "l2 rate-limit INCR failed, failing open");
                return fail_open();
            }
        };

        // Push the post-increment count to the observer if one is attached.
        // Cheap (Arc clone + function call); runs outside the fail-open branch.
        if let Some(obs) = self.observer.as_ref() {
            obs(count);
        }

        let remaining = limit.saturating_sub(count);
        let reset_secs = window.saturating_sub(now_secs - window_start);

        RateLimitInfo {
            allowed: count <= limit,
            limit,
            remaining,
            reset_secs,
            headers_enabled,
            include_retry_after,
        }
    }
}

// --- IpFilterPolicy ---

/// IP allow/deny filter based on CIDR lists.
///
/// If `whitelist` is non-empty, the client IP must match at least one
/// entry. If `blacklist` is non-empty, the client IP must NOT match
/// any entry. Both lists can be used together (whitelist is checked first).
#[derive(Debug, Deserialize)]
pub struct IpFilterPolicy {
    /// CIDR ranges that are explicitly permitted. Empty allows everything.
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// CIDR ranges that are explicitly denied.
    #[serde(default)]
    pub blacklist: Vec<String>,
    /// Parsed CIDR networks from whitelist strings.
    #[serde(skip)]
    parsed_whitelist: Vec<IpNetwork>,
    /// Parsed CIDR networks from blacklist strings.
    #[serde(skip)]
    parsed_blacklist: Vec<IpNetwork>,
}

impl IpFilterPolicy {
    /// Build an IpFilterPolicy from a generic JSON config value.
    ///
    /// Parses all CIDR strings into `IpNetwork` values at construction
    /// time so that per-request checks are fast comparisons.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;

        policy.parsed_whitelist = policy
            .whitelist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid whitelist CIDR: {}", e))?;

        policy.parsed_blacklist = policy
            .blacklist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid blacklist CIDR: {}", e))?;

        Ok(policy)
    }

    /// Check whether the given IP address is allowed by this filter.
    ///
    /// Returns true if the IP passes both whitelist and blacklist checks.
    pub fn check_ip(&self, ip: &IpAddr) -> bool {
        // Whitelist check: if non-empty, IP must match at least one entry
        if !self.parsed_whitelist.is_empty()
            && !self.parsed_whitelist.iter().any(|net| net.contains(*ip))
        {
            return false;
        }

        // Blacklist check: IP must not match any entry
        if self.parsed_blacklist.iter().any(|net| net.contains(*ip)) {
            return false;
        }

        true
    }
}

// --- SecHeadersPolicy ---

/// A single security header name/value pair.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityHeader {
    /// The HTTP header name (e.g. `X-Frame-Options`).
    pub name: String,
    /// The HTTP header value (e.g. `DENY`).
    pub value: String,
}

/// Advanced Content-Security-Policy configuration.
///
/// Supports per-request nonce generation and per-URL-prefix route overrides.
/// Use this when a plain CSP header value via the `headers:` array is not
/// enough.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ContentSecurityPolicy {
    /// The CSP policy string (e.g. `default-src 'self'`).
    #[serde(default)]
    pub policy: String,
    /// When true, a per-request nonce is generated and injected into
    /// `script-src` and `style-src` directives of the policy.
    #[serde(default)]
    pub enable_nonce: bool,
    /// When true, emit `Content-Security-Policy-Report-Only` instead of
    /// `Content-Security-Policy`.
    #[serde(default)]
    pub report_only: bool,
    /// Optional CSP violation report URI, appended as `; report-uri <uri>`.
    #[serde(default)]
    pub report_uri: String,
    /// Per-route overrides. Keys are URL path prefixes. On a request, the
    /// longest-matching prefix wins; an exact key match beats prefix match.
    /// If no key matches, the outer policy is used.
    #[serde(default)]
    pub dynamic_routes: HashMap<String, ContentSecurityPolicy>,
}

impl ContentSecurityPolicy {
    /// Resolve the CSP config for a given URL path.
    ///
    /// Exact key match wins; otherwise longest matching path prefix wins;
    /// otherwise falls back to `self`.
    pub fn resolve_for_path<'a>(&'a self, path: &str) -> &'a ContentSecurityPolicy {
        if self.dynamic_routes.is_empty() {
            return self;
        }
        if let Some(route_csp) = self.dynamic_routes.get(path) {
            return route_csp;
        }
        let mut best: Option<(&str, &ContentSecurityPolicy)> = None;
        for (route, route_csp) in &self.dynamic_routes {
            if path.starts_with(route.as_str()) {
                match best {
                    Some((cur, _)) if cur.len() >= route.len() => {}
                    _ => best = Some((route.as_str(), route_csp)),
                }
            }
        }
        best.map(|(_, csp)| csp).unwrap_or(self)
    }
}

/// CSP configuration value. Accepts either a plain policy string (legacy
/// shortcut) or a detailed object with nonce, report-only, dynamic routes.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ContentSecurityPolicySpec {
    /// Shortcut: just a policy string. Equivalent to `{ policy: "<s>" }`.
    Simple(String),
    /// Detailed config supporting per-request nonce and dynamic routes.
    Detailed(ContentSecurityPolicy),
}

impl ContentSecurityPolicySpec {
    /// Returns the policy string for this spec. For detailed specs with an
    /// empty policy field, returns `None`.
    pub fn as_legacy_str(&self) -> Option<&str> {
        match self {
            Self::Simple(s) => Some(s.as_str()),
            Self::Detailed(d) if !d.policy.is_empty() => Some(d.policy.as_str()),
            Self::Detailed(_) => None,
        }
    }

    /// Returns true if this spec requires per-request processing (nonce or
    /// dynamic routes). Simple string specs never require it.
    pub fn requires_per_request_build(&self) -> bool {
        match self {
            Self::Simple(_) => false,
            Self::Detailed(d) => d.enable_nonce || !d.dynamic_routes.is_empty(),
        }
    }
}

/// Generate a base64-encoded 16-byte random nonce for CSP.
pub fn generate_csp_nonce() -> Option<String> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Inject a nonce into `script-src` and `style-src` directives of a CSP
/// policy string. If the directive already contains a nonce, it is left
/// unchanged. Returns the policy unchanged if `nonce` is empty.
fn inject_nonce_into_policy(policy: &str, nonce: &str) -> String {
    if nonce.is_empty() {
        return policy.to_string();
    }
    policy
        .split(';')
        .map(|part| {
            let trimmed = part.trim();
            if (trimmed.starts_with("script-src") || trimmed.starts_with("style-src"))
                && !trimmed.contains("'nonce-")
            {
                format!("{} 'nonce-{}'", trimmed, nonce)
            } else {
                trimmed.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Injects security headers into responses.
///
/// This is a response-phase policy. The proxy applies these headers
/// to outgoing responses before sending them to the client.
///
/// Canonical format uses a `headers` array:
/// ```yaml
/// - type: security_headers
///   headers:
///     - name: X-Frame-Options
///       value: DENY
/// ```
///
/// Legacy flat fields (`x_frame_options`, `x_content_type_options`, etc.) are
/// still accepted for backward compatibility but trigger a deprecation log.
#[derive(Debug, Deserialize)]
pub struct SecHeadersPolicy {
    /// Canonical: list of `{name, value}` header pairs to inject.
    #[serde(default)]
    pub headers: Vec<SecurityHeader>,
    // --- Legacy flat fields (deprecated, kept for backward compatibility) ---
    /// Legacy `X-Frame-Options` value (e.g. `DENY`).
    #[serde(default)]
    pub x_frame_options: Option<String>,
    /// Legacy `X-Content-Type-Options` value (e.g. `nosniff`).
    #[serde(default)]
    pub x_content_type_options: Option<String>,
    /// Legacy `X-XSS-Protection` value.
    #[serde(default)]
    pub x_xss_protection: Option<String>,
    /// Legacy `Referrer-Policy` value.
    #[serde(default)]
    pub referrer_policy: Option<String>,
    /// Content-Security-Policy. Accepts either a plain policy string (legacy
    /// shortcut) or a detailed object with `enable_nonce`, `report_only`,
    /// `report_uri`, and `dynamic_routes`.
    #[serde(default)]
    pub content_security_policy: Option<ContentSecurityPolicySpec>,
    /// Legacy `Permissions-Policy` value.
    #[serde(default)]
    pub permissions_policy: Option<String>,
    /// Legacy `Strict-Transport-Security` value (HSTS shortcut).
    #[serde(default)]
    pub strict_transport_security: Option<String>,
}

impl SecHeadersPolicy {
    /// Build a SecHeadersPolicy from a generic JSON config value.
    ///
    /// Supports three formats:
    /// 1. New array format: `{ "headers": [{"name": "X-Frame-Options", "value": "DENY"}] }`
    /// 2. Flat (legacy): `{ "x_frame_options": "DENY" }`
    /// 3. Nested (Go compat legacy): `{ "x_frame_options": { "enabled": true, "value": "DENY" } }`
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // Check if the new `headers` array key is present.
        let has_headers_array = value
            .get("headers")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);

        if has_headers_array {
            // New canonical format - deserialize directly.
            return serde_json::from_value::<Self>(value)
                .map_err(|e| anyhow::anyhow!("security_headers parse error: {}", e));
        }

        // Try flat legacy format first.
        if let Ok(policy) = serde_json::from_value::<Self>(value.clone()) {
            // Log deprecation warning if any legacy fields are set.
            if policy.x_frame_options.is_some()
                || policy.x_content_type_options.is_some()
                || policy.x_xss_protection.is_some()
                || policy.referrer_policy.is_some()
                || policy.content_security_policy.is_some()
                || policy.permissions_policy.is_some()
                || policy.strict_transport_security.is_some()
            {
                tracing::warn!(
                    "security_headers: flat fields (x_frame_options, x_content_type_options, \
                     etc.) are deprecated. Use `headers: [{{name, value}}]` format instead."
                );
            }
            return Ok(policy);
        }
        // Fall back to Go nested format.
        Self::from_nested_config(&value)
    }

    /// Resolve all headers to inject, merging canonical `headers` array with
    /// legacy flat fields. The `headers` array takes precedence; legacy fields
    /// are appended only when the canonical array is empty.
    ///
    /// This method does not handle CSP nonce generation or dynamic routes.
    /// Callers that need per-request features should use
    /// [`resolved_headers_for_request`](Self::resolved_headers_for_request).
    pub fn resolved_headers(&self) -> Vec<(String, String)> {
        if !self.headers.is_empty() {
            return self
                .headers
                .iter()
                .map(|h| (h.name.to_lowercase(), h.value.clone()))
                .collect();
        }
        // Fall back to legacy flat fields.
        let mut out = Vec::new();
        if let Some(v) = &self.x_frame_options {
            out.push(("x-frame-options".into(), v.clone()));
        }
        if let Some(v) = &self.x_content_type_options {
            out.push(("x-content-type-options".into(), v.clone()));
        }
        if let Some(v) = &self.x_xss_protection {
            out.push(("x-xss-protection".into(), v.clone()));
        }
        if let Some(v) = &self.referrer_policy {
            out.push(("referrer-policy".into(), v.clone()));
        }
        if let Some(spec) = &self.content_security_policy {
            if let Some(v) = spec.as_legacy_str() {
                out.push(("content-security-policy".into(), v.to_string()));
            }
        }
        if let Some(v) = &self.permissions_policy {
            out.push(("permissions-policy".into(), v.clone()));
        }
        if let Some(v) = &self.strict_transport_security {
            out.push(("strict-transport-security".into(), v.clone()));
        }
        out
    }

    /// Resolve headers for a given request path, handling CSP nonce generation
    /// and dynamic routes when the `content_security_policy` field is the
    /// detailed variant.
    ///
    /// Returns the header list and the generated nonce (if any). Callers that
    /// expose the nonce to response templating should forward the nonce to
    /// downstream stages; a common pattern is also to emit an `X-CSP-Nonce`
    /// header so browser-side code can read it.
    pub fn resolved_headers_for_request(
        &self,
        path: &str,
    ) -> (Vec<(String, String)>, Option<String>) {
        // If the CSP spec doesn't need per-request processing, the static
        // resolution is already correct.
        let needs_rich = matches!(
            self.content_security_policy.as_ref(),
            Some(spec) if spec.requires_per_request_build()
        );
        if !needs_rich {
            return (self.resolved_headers(), None);
        }

        // Start from the static list, then remove any CSP header (we'll
        // rebuild it) and append the rich version.
        let mut headers = self.resolved_headers();
        headers.retain(|(n, _)| {
            n != "content-security-policy" && n != "content-security-policy-report-only"
        });

        let spec = match self.content_security_policy.as_ref() {
            Some(ContentSecurityPolicySpec::Detailed(d)) => d,
            _ => return (headers, None),
        };
        let resolved = spec.resolve_for_path(path);

        let nonce = if resolved.enable_nonce {
            generate_csp_nonce()
        } else {
            None
        };

        let mut value = if let Some(n) = &nonce {
            inject_nonce_into_policy(&resolved.policy, n)
        } else {
            resolved.policy.clone()
        };
        if !resolved.report_uri.is_empty() {
            value.push_str("; report-uri ");
            value.push_str(&resolved.report_uri);
        }

        if !value.is_empty() {
            let name = if resolved.report_only {
                "content-security-policy-report-only"
            } else {
                "content-security-policy"
            };
            headers.push((name.to_string(), value));
        }

        (headers, nonce)
    }

    /// Parse Go-style nested security headers config.
    fn from_nested_config(value: &serde_json::Value) -> anyhow::Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("security_headers config must be an object"))?;

        tracing::warn!(
            "security_headers: nested Go-compat format is deprecated. \
             Use `headers: [{{name, value}}]` format instead."
        );

        let x_frame_options = Self::extract_nested_value(obj, "x_frame_options");
        let x_content_type_options = if let Some(sub) = obj.get("x_content_type_options") {
            if let Some(sub_obj) = sub.as_object() {
                let enabled = sub_obj
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let no_sniff = sub_obj
                    .get("no_sniff")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if enabled && no_sniff {
                    Some("nosniff".to_string())
                } else {
                    None
                }
            } else {
                sub.as_str().map(|s| s.to_string())
            }
        } else {
            None
        };

        let referrer_policy = Self::extract_nested_policy(obj, "referrer_policy");
        let content_security_policy = Self::extract_nested_policy(obj, "content_security_policy")
            .map(ContentSecurityPolicySpec::Simple);

        // HSTS from strict_transport_security
        let strict_transport_security = Self::extract_hsts(obj);
        let x_xss_protection = Self::extract_nested_value(obj, "x_xss_protection");
        let permissions_policy = Self::extract_nested_value(obj, "permissions_policy");

        Ok(Self {
            headers: Vec::new(),
            x_frame_options,
            x_content_type_options,
            x_xss_protection,
            referrer_policy,
            content_security_policy,
            permissions_policy,
            strict_transport_security,
        })
    }

    /// Extract a value from a nested `{ "enabled": true, "value": "X" }` object.
    fn extract_nested_value(
        obj: &serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Option<String> {
        let sub = obj.get(key)?;
        if let Some(s) = sub.as_str() {
            return Some(s.to_string());
        }
        let sub_obj = sub.as_object()?;
        let enabled = sub_obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        sub_obj
            .get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract HSTS header value from a nested strict_transport_security config.
    ///
    /// Accepts Go-compat format:
    /// `{ "enabled": true, "max_age": 31536000, "include_subdomains": true }`
    fn extract_hsts(obj: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
        let sub = obj.get("strict_transport_security")?;
        if let Some(s) = sub.as_str() {
            return Some(s.to_string());
        }
        let sub_obj = sub.as_object()?;
        let enabled = sub_obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let max_age = sub_obj
            .get("max_age")
            .and_then(|v| v.as_u64())
            .unwrap_or(31_536_000);
        let include_subdomains = sub_obj
            .get("include_subdomains")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let preload = sub_obj
            .get("preload")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut value = format!("max-age={}", max_age);
        if include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if preload {
            value.push_str("; preload");
        }
        Some(value)
    }

    /// Extract a policy string from a nested `{ "enabled": true, "policy": "X" }` object.
    fn extract_nested_policy(
        obj: &serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Option<String> {
        let sub = obj.get(key)?;
        if let Some(s) = sub.as_str() {
            return Some(s.to_string());
        }
        let sub_obj = sub.as_object()?;
        let enabled = sub_obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        sub_obj
            .get("policy")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

// --- RequestLimitPolicy ---

/// Limits request body size, header count, header value size, and URL length.
///
/// Any limit set to `None` means that dimension is unchecked.
#[derive(Debug, Deserialize)]
pub struct RequestLimitPolicy {
    /// Maximum request body size in bytes.
    #[serde(default)]
    pub max_body_size: Option<usize>,
    /// Maximum number of request headers.
    #[serde(default, alias = "max_headers_count")]
    pub max_header_count: Option<usize>,
    /// Maximum size (in bytes) of a single header value.
    #[serde(default)]
    pub max_header_size: Option<SizeValue>,
    /// Maximum URL length in characters.
    #[serde(default)]
    pub max_url_length: Option<usize>,
    /// Maximum query string length (Go compat).
    #[serde(default)]
    pub max_query_string_length: Option<usize>,
    /// Maximum request size (Go compat).
    #[serde(default)]
    pub max_request_size: Option<SizeValue>,
    /// Go compat: nested size_limits config.
    #[serde(default)]
    pub size_limits: Option<serde_json::Value>,
}

/// A size value that can be either a number or a string like "4KB", "1MB".
#[derive(Debug, Clone)]
pub struct SizeValue(pub usize);

impl<'de> serde::Deserialize<'de> for SizeValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = serde_json::Value::deserialize(deserializer)?;
        match &val {
            serde_json::Value::Number(n) => {
                let size = n
                    .as_u64()
                    .ok_or_else(|| serde::de::Error::custom("invalid size number"))?
                    as usize;
                Ok(SizeValue(size))
            }
            serde_json::Value::String(s) => parse_size_string(s)
                .map(SizeValue)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom("size must be a number or string")),
        }
    }
}

/// Parse size strings like "4KB", "1MB", "1024" into bytes.
fn parse_size_string(s: &str) -> Result<usize, String> {
    let s = s.trim();
    if s.ends_with("KB") || s.ends_with("kb") || s.ends_with("kB") {
        let num: usize = s[..s.len() - 2]
            .trim()
            .parse()
            .map_err(|e| format!("{}", e))?;
        Ok(num * 1024)
    } else if s.ends_with("MB") || s.ends_with("mb") || s.ends_with("mB") {
        let num: usize = s[..s.len() - 2]
            .trim()
            .parse()
            .map_err(|e| format!("{}", e))?;
        Ok(num * 1024 * 1024)
    } else {
        s.parse().map_err(|e| format!("{}", e))
    }
}

impl RequestLimitPolicy {
    /// Build a RequestLimitPolicy from a generic JSON config value.
    ///
    /// Supports two formats:
    /// 1. Flat (Rust native): `{ "max_body_size": 1024, "max_header_count": 50 }`
    /// 2. Nested (Go compat): `{ "size_limits": { "max_url_length": 100, ... } }`
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // If there is a nested size_limits object, merge its fields into the top level.
        if let Some(size_limits) = value.get("size_limits") {
            let mut merged = size_limits.clone();
            // Copy top-level type field for compatibility.
            if let Some(obj) = merged.as_object_mut() {
                if let Some(t) = value.get("type") {
                    obj.insert("type".to_string(), t.clone());
                }
            }
            let policy: Self = serde_json::from_value(merged)?;
            return Ok(policy);
        }
        let policy: Self = serde_json::from_value(value)?;
        Ok(policy)
    }

    /// Check a request against the configured limits.
    ///
    /// Parameters:
    /// - `body_size`: actual body size in bytes (or 0 if unknown)
    /// - `header_count`: number of headers in the request
    /// - `max_header_value_size`: largest single header value in bytes
    /// - `url_length`: length of the request URL in characters
    ///
    /// Returns `Ok(())` if all limits pass, or `Err` with a description
    /// of which limit was exceeded.
    pub fn check_request(
        &self,
        body_size: usize,
        header_count: usize,
        max_header_value_size: usize,
        url_length: usize,
        query_string_length: usize,
    ) -> Result<(), String> {
        if let Some(max) = self.max_body_size {
            if body_size > max {
                return Err(format!("body size {} exceeds limit {}", body_size, max));
            }
        }
        if let Some(max) = self.max_header_count {
            if header_count > max {
                return Err(format!(
                    "header count {} exceeds limit {}",
                    header_count, max
                ));
            }
        }
        if let Some(ref max) = self.max_header_size {
            if max_header_value_size > max.0 {
                return Err(format!(
                    "header value size {} exceeds limit {}",
                    max_header_value_size, max.0
                ));
            }
        }
        if let Some(max) = self.max_url_length {
            if url_length > max {
                return Err(format!("URL length {} exceeds limit {}", url_length, max));
            }
        }
        if let Some(max) = self.max_query_string_length {
            if query_string_length > max {
                return Err(format!(
                    "query string length {} exceeds limit {}",
                    query_string_length, max
                ));
            }
        }
        Ok(())
    }
}

// --- CsrfPolicy ---

fn default_csrf_header() -> String {
    "X-CSRF-Token".to_string()
}

fn default_csrf_cookie() -> String {
    "csrf_token".to_string()
}

fn default_safe_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()]
}

/// CSRF token validation policy.
///
/// Compares the token in the request header against the token in the
/// cookie. Protected methods (POST, PUT, DELETE by default) require a
/// valid CSRF token. All other methods are considered safe.
#[derive(Debug, Deserialize)]
pub struct CsrfPolicy {
    /// HMAC key used to sign CSRF tokens. Go configs use `secret` instead of `secret_key`.
    #[serde(alias = "secret")]
    pub secret_key: String,
    /// Name of the request header carrying the CSRF token.
    #[serde(default = "default_csrf_header")]
    pub header_name: String,
    /// Name of the cookie carrying the canonical CSRF token.
    #[serde(default = "default_csrf_cookie")]
    pub cookie_name: String,
    /// Methods that require CSRF token validation. All other methods are
    /// considered safe and exempt. Default: POST, PUT, DELETE.
    /// Go configs use `methods` for this field.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Legacy: safe_methods (inverse of methods). If set and methods is
    /// empty, protected methods = everything NOT in safe_methods.
    #[serde(default = "default_safe_methods")]
    pub safe_methods: Vec<String>,
    /// Go compat: cookie path.
    #[serde(default)]
    pub cookie_path: Option<String>,
    /// Go compat: cookie SameSite attribute.
    #[serde(default)]
    pub cookie_same_site: Option<String>,
    /// Go compat: paths exempt from CSRF checking.
    #[serde(default)]
    pub exempt_paths: Vec<String>,
}

impl CsrfPolicy {
    /// Build a CsrfPolicy from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let policy: Self = serde_json::from_value(value)?;
        Ok(policy)
    }

    /// Check whether a method is protected (requires CSRF token).
    pub fn is_protected_method(&self, method: &str) -> bool {
        if !self.methods.is_empty() {
            // Explicit protected methods list.
            self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
        } else {
            // Infer from safe_methods: any method not in safe_methods is protected.
            !self
                .safe_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
        }
    }
}

// --- DdosPolicy ---

fn default_ddos_threshold() -> u32 {
    100
}

fn default_ddos_block_duration() -> u64 {
    300
}

fn default_ddos_max_tracked_ips() -> usize {
    100_000
}

/// Outcome of a per-request DDoS check.
#[derive(Debug, PartialEq, Eq)]
pub enum DdosCheckResult {
    /// Request is allowed through; the policy has recorded it.
    Allow,
    /// Request must be rejected. Carries the seconds remaining until the
    /// IP is unblocked, suitable for a `Retry-After` header.
    Block {
        /// Whole seconds until the block expires; always >= 1.
        retry_after_secs: u64,
    },
}

/// Per-IP runtime state: a sliding 1-second window of recent request
/// timestamps, plus the absolute instant the block expires (if any).
#[derive(Debug)]
struct DdosIpState {
    window: std::collections::VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl DdosIpState {
    fn new() -> Self {
        Self {
            window: std::collections::VecDeque::new(),
            blocked_until: None,
        }
    }
}

/// DDoS protection policy with per-IP rate tracking and temporary blocks.
///
/// Tracks per-IP request counts in a sliding one-second window. When an
/// IP exceeds the configured `requests_per_second` threshold, it is
/// blocked for `block_duration_secs`. Whitelisted IPs always pass.
///
/// Memory is bounded by `max_tracked_ips` via LRU eviction so an
/// adversary cannot exhaust memory by cycling source IPs.
#[derive(Deserialize)]
pub struct DdosPolicy {
    /// Per-IP requests-per-second threshold that triggers blocking.
    #[serde(default = "default_ddos_threshold")]
    pub requests_per_second: u32,
    /// Duration in seconds an IP stays blocked once the threshold trips.
    #[serde(default = "default_ddos_block_duration")]
    pub block_duration_secs: u64,
    /// IP addresses or CIDR ranges that bypass DDoS checks.
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// Maximum number of distinct IPs tracked locally. Past this,
    /// least-recently-seen IPs are evicted from the LRU.
    #[serde(default = "default_ddos_max_tracked_ips")]
    pub max_tracked_ips: usize,
    /// Go compat: nested detection config.
    #[serde(default)]
    pub detection: Option<serde_json::Value>,
    /// Go compat: nested mitigation config.
    #[serde(default)]
    pub mitigation: Option<serde_json::Value>,

    /// CIDR forms of `whitelist`, parsed once at construction time.
    #[serde(skip)]
    parsed_whitelist: Vec<IpNetwork>,
    /// Per-IP sliding-window state. Lazily allocated; `None` until the
    /// first request arrives so config-only paths pay nothing.
    #[serde(skip)]
    state: Mutex<Option<lru::LruCache<IpAddr, DdosIpState>>>,
}

impl std::fmt::Debug for DdosPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdosPolicy")
            .field("requests_per_second", &self.requests_per_second)
            .field("block_duration_secs", &self.block_duration_secs)
            .field("whitelist", &self.whitelist)
            .field("max_tracked_ips", &self.max_tracked_ips)
            .finish()
    }
}

impl DdosPolicy {
    /// Build a DdosPolicy from a generic JSON config value.
    ///
    /// Supports two config formats:
    /// 1. Flat (Rust native): `{ "requests_per_second": 100, "block_duration_secs": 300 }`
    /// 2. Nested (Go compat): `{ "detection": { "request_rate_threshold": 10, ... }, "mitigation": { "block_duration": "10s", ... } }`
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;

        // Extract values from Go-style nested detection config.
        if let Some(detection) = &policy.detection {
            if let Some(threshold) = detection
                .get("request_rate_threshold")
                .and_then(|v| v.as_u64())
            {
                policy.requests_per_second = threshold as u32;
            }
        }

        // Extract values from Go-style nested mitigation config.
        if let Some(mitigation) = &policy.mitigation {
            if let Some(duration) = mitigation.get("block_duration").and_then(|v| v.as_str()) {
                // Parse Go duration strings like "10s", "5m".
                if let Some(secs) = parse_go_duration(duration) {
                    policy.block_duration_secs = secs;
                }
            }
        }

        // Parse whitelist entries once. Accept bare IPs (`10.0.0.1`) as
        // well as CIDRs (`10.0.0.0/24`); IpNetwork treats a bare IP as a
        // /32 or /128 host route.
        policy.parsed_whitelist = policy
            .whitelist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid DDoS whitelist entry: {}", e))?;

        Ok(policy)
    }

    /// Decide whether a request from `client_ip` should be allowed or
    /// blocked. The decision is recorded so subsequent calls see it.
    ///
    /// Behaviour:
    /// - Whitelisted IPs always return `Allow` and never accumulate
    ///   counter state.
    /// - If the IP is currently blocked, returns `Block` with the
    ///   remaining seconds.
    /// - Otherwise slides the 1-second request window forward, counts
    ///   the request, and trips a fresh block when the window crosses
    ///   the threshold.
    pub fn check(&self, client_ip: IpAddr) -> DdosCheckResult {
        if self
            .parsed_whitelist
            .iter()
            .any(|net| net.contains(client_ip))
        {
            return DdosCheckResult::Allow;
        }

        let now = Instant::now();
        let window = std::time::Duration::from_secs(1);
        let block_dur = std::time::Duration::from_secs(self.block_duration_secs.max(1));
        let threshold = self.requests_per_second.max(1) as usize;

        let mut guard = self.state.lock();
        let cache = guard.get_or_insert_with(|| {
            let cap = std::num::NonZeroUsize::new(self.max_tracked_ips.max(1))
                .expect("cap is at least 1");
            lru::LruCache::new(cap)
        });

        // get_or_insert_mut promotes the entry on access (LRU-correct).
        let entry = cache.get_or_insert_mut(client_ip, DdosIpState::new);

        // If a previous burst is still being penalised, short-circuit.
        if let Some(until) = entry.blocked_until {
            if now < until {
                let remaining = until.saturating_duration_since(now).as_secs() + 1;
                return DdosCheckResult::Block {
                    retry_after_secs: remaining,
                };
            }
            // Block expired. Clear state and let this request count fresh.
            entry.blocked_until = None;
            entry.window.clear();
        }

        // Slide the window: drop entries older than 1s.
        while let Some(&front) = entry.window.front() {
            if now.duration_since(front) > window {
                entry.window.pop_front();
            } else {
                break;
            }
        }

        // Threshold trip: this request would push count > threshold.
        if entry.window.len() >= threshold {
            entry.blocked_until = Some(now + block_dur);
            return DdosCheckResult::Block {
                retry_after_secs: block_dur.as_secs(),
            };
        }

        entry.window.push_back(now);
        DdosCheckResult::Allow
    }
}

/// Parse a Go-style duration string (e.g., "10s", "5m") into seconds.
fn parse_go_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix('s') {
        num.parse().ok()
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().ok().map(|m| m * 60)
    } else if let Some(num) = s.strip_suffix('h') {
        num.parse::<u64>().ok().map(|h| h * 3600)
    } else {
        s.parse().ok()
    }
}

// --- SriPolicy ---

/// One SRI violation observed on an HTML response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SriViolation {
    /// Tag that triggered the violation (`script` or `link`).
    pub tag: String,
    /// Source URL (`src` for script tags, `href` for link tags).
    pub url: String,
    /// Why the violation fired.
    pub reason: SriViolationReason,
}

/// Why an HTML subresource reference failed the SRI check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SriViolationReason {
    /// No `integrity="..."` attribute was present.
    MissingIntegrity,
    /// The integrity attribute used an algorithm not in `algorithms`.
    DisallowedAlgorithm {
        /// Algorithm prefix that was found (e.g. `sha1`, `md5`).
        found: String,
    },
}

/// Outcome of `SriPolicy::check_html_body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SriCheckResult {
    /// The response is not HTML or the policy is disabled; no inspection done.
    NotApplicable,
    /// HTML was inspected and every external subresource carried a valid
    /// integrity attribute.
    Clean,
    /// One or more subresources failed the check.
    Violations(Vec<SriViolation>),
}

/// Subresource Integrity (SRI) inspection policy.
///
/// When `enforce` is true and a response is `text/html`, the body is
/// scanned for `<script src="..."></script>` and
/// `<link rel="stylesheet" href="...">` tags pointing at external
/// origins (absolute `http://` or `https://` URLs). Each external
/// reference must carry an `integrity="..."` attribute using one of
/// the configured algorithms; references that do not are reported as
/// violations.
///
/// SRI is fundamentally a browser-side mechanism, so this policy is
/// observational by design: it surfaces missing or weak integrity
/// attributes so an operator can fix the upstream HTML, without
/// rewriting the body or blocking the response. Violations are
/// emitted on the response as the `X-SRI-Violations` header by the
/// response-phase wiring in `sbproxy-core`.
#[derive(Debug, Deserialize)]
pub struct SriPolicy {
    /// When true, scan HTML responses and emit the `X-SRI-Violations`
    /// header for any missing or weak integrity attributes. Default
    /// false (no-op).
    #[serde(default)]
    pub enforce: bool,
    /// Integrity hash algorithms to accept. Defaults to
    /// `["sha256", "sha384", "sha512"]` when not set, matching the
    /// algorithms the SRI spec admits for subresource integrity.
    #[serde(default)]
    pub algorithms: Vec<String>,
}

impl SriPolicy {
    /// Build an SriPolicy from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        if policy.algorithms.is_empty() {
            policy.algorithms = vec![
                "sha256".to_string(),
                "sha384".to_string(),
                "sha512".to_string(),
            ];
        }
        Ok(policy)
    }

    /// Inspect an HTML response body for missing or weak SRI attributes.
    ///
    /// Returns `NotApplicable` when the policy is disabled (`enforce =
    /// false`) or when the response is not `text/html`. Returns `Clean`
    /// when every external subresource reference carries an acceptable
    /// `integrity` attribute. Returns `Violations` listing each
    /// problem otherwise.
    pub fn check_html_body(&self, body: &[u8], content_type: &str) -> SriCheckResult {
        if !self.enforce {
            return SriCheckResult::NotApplicable;
        }
        if !content_type
            .split(';')
            .next()
            .map(|s| s.trim().eq_ignore_ascii_case("text/html"))
            .unwrap_or(false)
        {
            return SriCheckResult::NotApplicable;
        }
        let html = match std::str::from_utf8(body) {
            Ok(s) => s,
            // Non-UTF-8 bodies are not text/html in practice; skip rather than panic.
            Err(_) => return SriCheckResult::NotApplicable,
        };

        let violations = scan_html_for_sri(html, &self.algorithms);
        if violations.is_empty() {
            SriCheckResult::Clean
        } else {
            SriCheckResult::Violations(violations)
        }
    }
}

/// Scan an HTML document and return any SRI violations.
///
/// Uses a single regex pass that captures every `<script>` and `<link>`
/// open-tag, then per-tag predicates classify subresource references
/// and check the integrity attribute. Inline scripts (no `src=`) and
/// non-stylesheet `<link>` tags (`preconnect`, `icon`, etc.) are
/// ignored. Same-origin references (relative URLs and protocol-
/// relative `//host/...`) are also ignored because the page itself
/// already vouches for them.
fn scan_html_for_sri(html: &str, allowed_algorithms: &[String]) -> Vec<SriViolation> {
    use regex::Regex;
    use std::sync::OnceLock;

    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let tag_re = TAG_RE.get_or_init(|| {
        // Match the open-tag of every <script ...> and <link ...>.
        // (?is) = case-insensitive, dot matches newline.
        Regex::new(r#"(?is)<(script|link)\b([^>]*)>"#).expect("static SRI tag regex compiles")
    });

    let mut violations = Vec::new();
    for cap in tag_re.captures_iter(html) {
        let tag = cap.get(1).map(|m| m.as_str().to_lowercase());
        let attrs = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let tag = match tag.as_deref() {
            Some("script") => "script",
            Some("link") => "link",
            _ => continue,
        };

        // Pick the URL attribute relevant to the tag and decide if it
        // points at an external origin worth checking.
        let url = if tag == "script" {
            attr_value(attrs, "src")
        } else {
            // Only stylesheet links carry subresources we can validate
            // with SRI today. preconnect, dns-prefetch, icon, etc. are
            // out of scope.
            let rel = attr_value(attrs, "rel").unwrap_or_default();
            if !rel
                .split_ascii_whitespace()
                .any(|r| r.eq_ignore_ascii_case("stylesheet"))
            {
                continue;
            }
            attr_value(attrs, "href")
        };

        let url = match url {
            Some(u) if is_external_url(&u) => u,
            // Inline (no src/href) or same-origin: SRI does not apply.
            _ => continue,
        };

        match attr_value(attrs, "integrity") {
            None => violations.push(SriViolation {
                tag: tag.to_string(),
                url,
                reason: SriViolationReason::MissingIntegrity,
            }),
            Some(integrity) => {
                // Integrity is a space-separated list of hashes; each
                // entry is `<algorithm>-<base64-hash>`. We require at
                // least one entry to use an allowed algorithm.
                let any_allowed = integrity.split_ascii_whitespace().any(|entry| {
                    let alg = entry.split('-').next().unwrap_or("").to_ascii_lowercase();
                    allowed_algorithms
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(&alg))
                });
                if !any_allowed {
                    let found = integrity
                        .split_ascii_whitespace()
                        .filter_map(|entry| entry.split('-').next())
                        .collect::<Vec<_>>()
                        .join(",");
                    violations.push(SriViolation {
                        tag: tag.to_string(),
                        url,
                        reason: SriViolationReason::DisallowedAlgorithm { found },
                    });
                }
            }
        }
    }

    violations
}

/// Pull a single attribute value out of an HTML open-tag attribute string.
///
/// Handles double-quoted, single-quoted, and unquoted values. Returns
/// `None` when the attribute is missing.
fn attr_value(attrs: &str, name: &str) -> Option<String> {
    use regex::Regex;
    // Build the regex at call time. Attribute count is small (a handful
    // per tag) and SRI scanning is response-time, not request-hot-path,
    // so this is acceptable.
    let pattern = format!(
        r#"(?is)\b{}\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))"#,
        regex::escape(name)
    );
    let re = Regex::new(&pattern).ok()?;
    let cap = re.captures(attrs)?;
    cap.get(2)
        .or_else(|| cap.get(3))
        .or_else(|| cap.get(4))
        .map(|m| m.as_str().to_string())
}

/// Heuristic: does this URL point at an external origin?
///
/// Absolute `http://` or `https://` URLs are external. Relative URLs
/// (`/path`, `path`) and protocol-relative URLs (`//host/path`) are
/// treated as same-origin and skipped, matching how browsers exempt
/// same-origin subresources from SRI requirements by default.
fn is_external_url(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

// --- ExpressionPolicy ---

/// CEL expression-based policy.
///
/// Evaluates a CEL expression against the HTTP request context. If the
/// expression evaluates to `false`, the request is denied with the
/// configured status code and message.
#[derive(Debug)]
pub struct ExpressionPolicy {
    /// CEL expression evaluated against the request context.
    pub expression: String,
    /// HTTP status code returned when the expression evaluates to false.
    pub deny_status: u16,
    /// Body returned with the deny status code.
    pub deny_message: String,
}

fn default_deny_status() -> u16 {
    403
}

fn default_deny_msg() -> String {
    "forbidden by policy".to_string()
}

impl ExpressionPolicy {
    /// Build an ExpressionPolicy from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(alias = "cel_expr")]
            expression: String,
            #[serde(default = "default_deny_status", alias = "status_code")]
            deny_status: u16,
            #[serde(default = "default_deny_msg")]
            deny_message: String,
        }

        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            expression: cfg.expression,
            deny_status: cfg.deny_status,
            deny_message: cfg.deny_message,
        })
    }

    /// Evaluate the expression against request data.
    ///
    /// Returns `true` if the request should be allowed, `false` if denied.
    /// Fails closed on evaluation errors (e.g., missing header key) since
    /// the expression could not prove the request is allowed. Fails open
    /// only on compilation errors (misconfiguration).
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
    ) -> bool {
        self.evaluate_with_aipref(method, path, headers, query, client_ip, hostname, None)
    }

    /// Evaluate the expression with an optional [`AiprefSignal`] stamped
    /// into the CEL context under `request.aipref.{train,search,ai_input}`.
    ///
    /// Wave 4 / G4.9 follow-up: the proxy's request enricher parses
    /// the inbound `aipref:` header and threads the result here so
    /// CEL expressions can author route gates like
    /// `request.aipref.train == false` without re-parsing the header.
    /// `None` leaves the namespace at the default-permissive zero
    /// value (every axis `true`) per A4.1's "absence of a signal is
    /// not a signal" rule.
    #[allow(clippy::too_many_arguments)] // Mirrors `evaluate` plus the optional aipref signal; refactoring to a struct argument is a separate cleanup.
    pub fn evaluate_with_aipref(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
        aipref: Option<&AiprefSignal>,
    ) -> bool {
        self.evaluate_with_views(
            method,
            path,
            headers,
            query,
            client_ip,
            hostname,
            ExpressionViews {
                aipref,
                ..Default::default()
            },
        )
    }

    /// Evaluate the expression with the full bundle of Wave 5 / Wave 4
    /// view objects available to the CEL surface.
    ///
    /// New code should call this method directly so the
    /// `request.kya.*` and `request.ml_classification.*` namespaces
    /// are populated alongside `request.aipref.*`. The shorter
    /// `evaluate_with_aipref` wrapper above forwards every other view
    /// as `None` for back-compat with call sites that have not been
    /// updated yet.
    #[allow(clippy::too_many_arguments)] // The view bundle is one struct; the request-shape parameters mirror `evaluate`.
    pub fn evaluate_with_views(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
        views: ExpressionViews<'_>,
    ) -> bool {
        let engine = sbproxy_extension::cel::CelEngine::new();
        let mut ctx = sbproxy_extension::cel::context::build_request_context(
            method, path, headers, query, client_ip, hostname,
        );
        // Translate the `sbproxy-modules` parser type into the
        // dependency-neutral CEL view so `sbproxy-extension` does not
        // need to depend back on `sbproxy-modules`.
        let view = views
            .aipref
            .map(|s| sbproxy_extension::cel::context::AiprefView {
                train: s.train,
                search: s.search,
                ai_input: s.ai_input,
            });
        sbproxy_extension::cel::context::populate_aipref_namespace(&mut ctx, view.as_ref());

        // Wave 5 / G5.1: stamp the KYA verdict whenever the verifier
        // ran. When `views.kya` is `None`, the namespace is not
        // populated; `request.kya.verdict` resolves to the empty
        // string in that case so policy expressions do not need to
        // probe for presence.
        if let Some(kya) = views.kya {
            sbproxy_extension::cel::context::populate_kya_namespace(&mut ctx, &kya);
        }

        // Wave 5 / A5.2: stamp the ML classifier verdict whenever
        // inference produced one.
        if let Some(ml) = views.ml {
            sbproxy_extension::cel::context::populate_ml_namespace(&mut ctx, &ml);
        }

        match engine.compile(&self.expression) {
            Ok(expr) => engine.eval_bool(&expr, &ctx).unwrap_or(false),
            Err(_) => true, // Fail open on compile error only
        }
    }
}

/// Bundle of optional Wave 4 / Wave 5 view objects that an
/// `ExpressionPolicy` (and similar CEL evaluators) can read at
/// evaluation time.
///
/// All fields default to `None`, so callers populate only the views
/// that have a meaningful value for the current request. Adding a new
/// view here is a non-breaking change because `Default` keeps every
/// existing call site compiling.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExpressionViews<'a> {
    /// Wave 4 / G4.9 aipref preference signal.
    pub aipref: Option<&'a AiprefSignal>,
    /// Wave 5 / G5.1 KYA verifier verdict view.
    pub kya: Option<sbproxy_extension::cel::context::KyaVerdictView<'a>>,
    /// Wave 5 / A5.2 ML agent classifier verdict view.
    pub ml: Option<sbproxy_extension::cel::context::MlClassificationView<'a>>,
}

// --- AssertionPolicy ---

/// CEL assertion policy for response-time validation.
///
/// Evaluates a CEL expression as an assertion. Unlike ExpressionPolicy which
/// gates requests, assertions are informational - they log/flag when the
/// expression returns false but do not block traffic.
#[derive(Debug)]
pub struct AssertionPolicy {
    /// CEL expression evaluated for its truth value.
    pub expression: String,
    /// Human-readable name attached to assertion log entries.
    pub name: String,
}

fn default_assertion_name() -> String {
    "assertion".to_string()
}

impl AssertionPolicy {
    /// Build an AssertionPolicy from a generic JSON config value.
    ///
    /// Accepts both:
    /// - Flat format: `{expression: "...", name: "..."}`
    /// - Go-compat format: `{assertions: [{name: "...", cel_expr: "...", action: "..."}]}`
    ///   (uses the first assertion in the list)
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // Try Go-compat format first: assertions list
        if let Some(assertions) = value.get("assertions") {
            if let Some(arr) = assertions.as_array() {
                if let Some(first) = arr.first() {
                    let name = first
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("assertion")
                        .to_string();
                    let expression = first
                        .get("cel_expr")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("assertion missing cel_expr field"))?
                        .trim()
                        .to_string();
                    return Ok(Self { expression, name });
                }
            }
        }

        // Flat format: {expression, name}
        #[derive(Deserialize)]
        struct Config {
            expression: String,
            #[serde(default = "default_assertion_name")]
            name: String,
        }

        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            expression: cfg.expression,
            name: cfg.name,
        })
    }

    /// Evaluate the assertion against response data.
    ///
    /// Returns `true` if the assertion passed, `false` if it failed.
    /// Fails open (returns `true`) on compilation or evaluation errors.
    /// Unlike ExpressionPolicy, assertions are informational - they
    /// log warnings but never block traffic.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        request_headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
        response_status: u16,
        response_headers: &http::HeaderMap,
        body_size: Option<usize>,
    ) -> bool {
        let engine = sbproxy_extension::cel::CelEngine::new();
        let ctx = sbproxy_extension::cel::context::build_response_context(
            method,
            path,
            request_headers,
            query,
            client_ip,
            hostname,
            response_status,
            response_headers,
            body_size,
        );
        match engine.compile(&self.expression) {
            Ok(expr) => engine.eval_bool(&expr, &ctx).unwrap_or(true),
            Err(e) => {
                tracing::warn!(
                    assertion = %self.name,
                    error = %e,
                    "assertion CEL compilation failed, skipping"
                );
                true
            }
        }
    }
}

// --- WafPolicy ---

/// Default paranoia level when none is configured. Mirrors the OWASP CRS
/// convention where 1 is the lowest false-positive setting.
const DEFAULT_PARANOIA: u8 = 1;

/// Maximum supported paranoia level. Matches the OWASP CRS 1-4 range.
const MAX_PARANOIA: u8 = 4;

/// Web Application Firewall policy.
///
/// Provides OWASP CRS-based request filtering, custom rules, and
/// configurable actions on match. Fields are stored as generic values
/// for forward compatibility with the Go implementation.
///
/// The `paranoia` field follows the OWASP CRS convention. Level 1 is the
/// default and runs only the lowest-false-positive rules. Levels 2-4
/// progressively enable stricter rules at the cost of more false
/// positives. Rules without an explicit paranoia attribute default to
/// paranoia=1 and therefore always run.
#[derive(Debug, Deserialize)]
pub struct WafPolicy {
    /// OWASP Core Rule Set configuration.
    #[serde(default)]
    pub owasp_crs: Option<serde_json::Value>,
    /// Action to take when a rule matches (e.g. "block", "log").
    #[serde(default)]
    pub action_on_match: Option<String>,
    /// If true, log matches but do not block.
    #[serde(default)]
    pub test_mode: bool,
    /// If true, allow requests through on WAF engine failure.
    #[serde(default)]
    pub fail_open: bool,
    /// Paranoia level (1-4). Only rules whose paranoia attribute is less
    /// than or equal to this value are evaluated. Defaults to 1 (lowest
    /// false-positive). For backward compatibility, the value can also be
    /// supplied as `owasp_crs.paranoia_level`; the top-level field wins
    /// when both are present.
    #[serde(default)]
    pub paranoia: Option<u8>,
    /// Custom WAF rules.
    #[serde(default)]
    pub custom_rules: Vec<serde_json::Value>,
    /// Optional remote rule-feed subscription. When present and
    /// `enabled: true`, the policy spawns a background subscriber that
    /// hot-loads signed rule bundles from the publisher and merges them
    /// with the static rule corpus on every request. See
    /// [`waf::WafFeedConfig`] for the wire shape and
    /// [`waf::WafFeedSubscriber`] for the runtime behaviour.
    ///
    /// The deserialised config is the *blueprint*; the live
    /// subscriber that owns the background task lives in
    /// [`Self::feed_subscriber`].
    #[serde(default)]
    pub feed: Option<waf::WafFeedConfig>,
    /// Live feed subscriber. Skipped from serde because it owns
    /// runtime state (an [`arc_swap::ArcSwap`] of the current
    /// [`waf::RuleSet`] plus a background task handle). Populated by
    /// [`Self::from_config`] when [`Self::feed`] is `Some(_)` and
    /// `enabled: true`.
    #[serde(skip)]
    pub feed_subscriber: Option<Arc<waf::WafFeedSubscriber>>,
}

/// Result of a WAF check.
pub enum WafResult {
    /// Request is clean - allow it through.
    Clean,
    /// Attack detected - block with a message.
    Blocked(String),
    /// WAF engine error occurred during evaluation.
    Error(String),
}

// --- OWASP-lite built-in patterns ---
//
// Each pattern carries an OWASP CRS-style paranoia tag. Paranoia=1 is the
// always-on baseline (high-confidence signatures). Paranoia>=2 patterns
// only run when the operator explicitly opts into a higher-strictness
// posture via `WafPolicy::paranoia`.

/// Built-in WAF signature with an associated paranoia level.
struct BuiltinPattern {
    name: &'static str,
    paranoia: u8,
    regex: std::sync::LazyLock<Regex>,
}

static SQLI_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "sqli",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|insert\s+into|select\s+.*\s+from|;\s*delete|;\s*update|--\s*$)").unwrap()
    }),
};

static XSS_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "xss",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(<script|javascript:|on\w+\s*=|<img[^>]+onerror|<svg[^>]+onload|alert\s*\(|document\.cookie)").unwrap()
    }),
};

static PATH_TRAVERSAL_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "path_traversal",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(\.\./|\.\.\\|%2e%2e|%252e|etc/passwd|/proc/self|/dev/null)").unwrap()
    }),
};

/// Stricter SQLi signature catching boolean-blind and time-delay edge
/// cases that the paranoia=1 corpus tolerates. Enabled at paranoia>=2.
static SQLI_STRICT_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "sqli_strict",
    paranoia: 2,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(\bwaitfor\s+delay\b|\bbenchmark\s*\(|\bsleep\s*\(\s*\d+\s*\)|\bextractvalue\s*\(|\bload_file\s*\(|\binformation_schema\b|\bxp_cmdshell\b|\bcase\s+when\b.*\bthen\b)").unwrap()
    }),
};

impl WafPolicy {
    /// Build a WafPolicy from a generic JSON config value.
    ///
    /// When the deserialized config carries a `feed` block with
    /// `enabled: true`, a [`waf::WafFeedSubscriber`] is built and its
    /// background task spawned on [`waf::WAF_FEED_TASKS`]. Subscriber
    /// construction errors propagate; rule-feed downloads do *not* (a
    /// flaky publisher must never break config compile).
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        if let Some(feed_cfg) = policy.feed.clone() {
            if feed_cfg.enabled {
                let sub = waf::WafFeedSubscriber::new(feed_cfg)?;
                policy.feed_subscriber = Some(sub);
            }
        }
        Ok(policy)
    }

    /// Check whether OWASP CRS is enabled.
    fn owasp_enabled(&self) -> bool {
        match &self.owasp_crs {
            Some(v) => v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false),
            None => false,
        }
    }

    /// Resolve the effective paranoia level. The top-level `paranoia` field
    /// wins. If unset, fall back to `owasp_crs.paranoia_level` for OWASP
    /// CRS-style configs. Defaults to 1 and is clamped to the 1-4 range.
    fn effective_paranoia(&self) -> u8 {
        let raw = self.paranoia.or_else(|| {
            self.owasp_crs.as_ref().and_then(|v| {
                v.get("paranoia_level")
                    .and_then(|p| p.as_u64())
                    .map(|n| n as u8)
            })
        });
        let level = raw.unwrap_or(DEFAULT_PARANOIA);
        level.clamp(1, MAX_PARANOIA)
    }

    /// Check a request against WAF rules. Returns a WafResult indicating
    /// whether the request is clean, blocked, or if an error occurred.
    ///
    /// Rule selection follows the OWASP CRS paranoia model: only rules
    /// whose paranoia level is less than or equal to the policy's
    /// configured level are evaluated. Custom rules without a paranoia
    /// attribute default to paranoia=1 and therefore always run.
    pub fn check_request(
        &self,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> WafResult {
        let action = self.action_on_match.as_deref().unwrap_or("block");
        let paranoia = self.effective_paranoia();

        // --- OWASP CRS built-in patterns ---
        if self.owasp_enabled() {
            // URL-decode the URI before pattern matching (e.g., %3D -> =, + -> space)
            let decoded_uri = percent_encoding::percent_decode_str(uri)
                .decode_utf8_lossy()
                .replace('+', " ");

            // Collect all text to scan: decoded URI, header values, body.
            let header_text: String = headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");

            let targets = [Some(decoded_uri.as_str()), Some(header_text.as_str()), body];

            // Built-in pattern corpus. Each entry carries an OWASP-style
            // paranoia tag and a human-readable block message.
            let builtins: [(&BuiltinPattern, &str); 4] = [
                (&SQLI_PATTERN, "WAF: SQL injection detected"),
                (&XSS_PATTERN, "WAF: XSS detected"),
                (&PATH_TRAVERSAL_PATTERN, "WAF: path traversal detected"),
                (&SQLI_STRICT_PATTERN, "WAF: SQL injection (strict) detected"),
            ];

            for target in targets.into_iter().flatten() {
                for (rule, block_msg) in builtins.iter() {
                    // Paranoia gate: skip rules above the configured level.
                    if rule.paranoia > paranoia {
                        continue;
                    }
                    if rule.regex.is_match(target) {
                        if action == "log" || self.test_mode {
                            tracing::warn!(
                                pattern = rule.name,
                                paranoia = rule.paranoia,
                                "WAF: pattern detected (log mode)"
                            );
                        } else {
                            return WafResult::Blocked((*block_msg).to_string());
                        }
                    }
                }
            }
        }

        // --- Feed rules (subscribed via WafFeedSubscriber) ---
        //
        // Rules from the remote feed are evaluated alongside the
        // built-in corpus and the inline custom rules. Their paranoia
        // attribute is gated by the policy's `paranoia` setting just
        // like the built-in patterns. A rule from the feed with the
        // same `id` as a built-in or earlier custom rule is the
        // authoritative version; the static corpus does not carry
        // numeric ids today, so override is by-id only and only takes
        // effect against custom_rules below (which we filter
        // accordingly).
        //
        // The subscriber's background task is lazy-spawned on the
        // first request that reaches this branch, since OSS config
        // compile runs before Pingora's Tokio runtime exists. Once
        // started, the call is a no-op (`std::sync::Once`).
        if let Some(sub) = &self.feed_subscriber {
            sub.ensure_started();
        }
        let feed_snapshot = self.feed_subscriber.as_ref().map(|s| s.current_rules());
        let feed_rule_ids: std::collections::HashSet<&str> = match &feed_snapshot {
            Some(snap) => snap.rules.iter().map(|r| r.id.as_str()).collect(),
            None => std::collections::HashSet::new(),
        };
        if let Some(snap) = feed_snapshot.as_ref() {
            // URL-decoded URI plus joined headers, mirroring the
            // built-in scan corpus so feed signatures do not have to
            // re-implement encoding.
            let decoded_uri = percent_encoding::percent_decode_str(uri)
                .decode_utf8_lossy()
                .replace('+', " ");
            let header_text: String = headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");
            let targets = [Some(decoded_uri.as_str()), Some(header_text.as_str()), body];

            for rule in &snap.rules {
                if rule.paranoia > paranoia {
                    continue;
                }
                let mut matched = false;
                for target in targets.into_iter().flatten() {
                    if rule.regex.is_match(target) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    continue;
                }
                let log_only = matches!(rule.action, waf::FeedRuleAction::Log)
                    || action == "log"
                    || self.test_mode;
                if log_only {
                    tracing::warn!(
                        rule_id = rule.id.as_str(),
                        category = rule.category.as_str(),
                        paranoia = rule.paranoia,
                        "WAF feed: rule matched (log mode)"
                    );
                } else {
                    return WafResult::Blocked(format!(
                        "WAF feed: {} matched [rule {}]",
                        rule.category, rule.id
                    ));
                }
            }
        }

        // --- Custom rules ---
        for rule_value in &self.custom_rules {
            // Feed rules with the same `id` shadow inline custom rules.
            // Skip the inline rule when a feed rule of the same id
            // already evaluated above, so operators can override
            // bundled signatures from upstream without redeploying.
            if let Some(id) = rule_value.get("id").and_then(|v| v.as_str()) {
                if feed_rule_ids.contains(id) {
                    continue;
                }
            }
            // Paranoia gate for custom rules. Rules without a `paranoia`
            // attribute default to paranoia=1 (always run).
            let rule_paranoia = rule_value
                .get("paranoia")
                .and_then(|p| p.as_u64())
                .map(|n| (n as u8).clamp(1, MAX_PARANOIA))
                .unwrap_or(DEFAULT_PARANOIA);
            if rule_paranoia > paranoia {
                continue;
            }
            match self.evaluate_custom_rule(rule_value, uri, headers, body) {
                Ok(true) => {
                    // Rule matched.
                    let rule_action = rule_value
                        .get("action")
                        .and_then(|a| a.as_str())
                        .unwrap_or(action);
                    let message = rule_value
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("WAF: custom rule matched");
                    let rule_id = rule_value
                        .get("id")
                        .and_then(|id| id.as_str())
                        .unwrap_or("unknown");

                    if rule_action == "log" || self.test_mode {
                        tracing::warn!(rule_id = rule_id, "WAF: custom rule matched (log mode)");
                    } else {
                        return WafResult::Blocked(format!("{} [rule {}]", message, rule_id));
                    }
                }
                Ok(false) => {} // No match, continue.
                Err(e) => {
                    return WafResult::Error(format!("WAF custom rule error: {}", e));
                }
            }
        }

        WafResult::Clean
    }

    /// Evaluate a single custom rule against the request.
    /// Returns Ok(true) if the rule matched, Ok(false) if not, Err on engine error.
    fn evaluate_custom_rule(
        &self,
        rule: &serde_json::Value,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        // Check for Lua-based custom rules
        if let Some(lua_script) = rule.get("lua_script").and_then(|s| s.as_str()) {
            return self.evaluate_lua_custom_rule(lua_script, uri, headers, body);
        }

        // Check for JavaScript-based custom rules (js_script field, or engine: "javascript")
        let js_script = rule.get("js_script").and_then(|s| s.as_str()).or_else(|| {
            let engine = rule.get("engine").and_then(|e| e.as_str()).unwrap_or("lua");
            if engine == "javascript" {
                rule.get("script").and_then(|s| s.as_str())
            } else {
                None
            }
        });
        if let Some(script) = js_script {
            return self.evaluate_js_custom_rule(script, uri, headers, body);
        }

        let pattern = rule
            .get("pattern")
            .and_then(|p| p.as_str())
            .ok_or_else(|| {
                "custom rule missing 'pattern', 'lua_script', or 'js_script' field".to_string()
            })?;

        let operator = rule
            .get("operator")
            .and_then(|o| o.as_str())
            .unwrap_or("contains");

        let variables = rule
            .get("variables")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // If no variables specified, scan the full URI.
        if variables.is_empty() {
            return self.match_operator(operator, uri, pattern);
        }

        for var in &variables {
            let var_name = var
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("REQUEST_URI");
            let var_key = var.get("key").and_then(|k| k.as_str());

            let target_values = self.resolve_variable(var_name, var_key, uri, headers, body);
            for target in &target_values {
                if self.match_operator(operator, target, pattern)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Evaluate a Lua-based custom WAF rule.
    ///
    /// The script must define a `match(request)` function that receives a
    /// request object with a `header()` method for looking up HTTP headers.
    /// Returns true if the rule matched (request should be blocked).
    fn evaluate_lua_custom_rule(
        &self,
        script: &str,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        use sbproxy_extension::lua::LuaEngine;

        let engine = LuaEngine::new().map_err(|e| format!("Lua engine init error: {}", e))?;

        // Build headers map for the Lua engine
        let mut headers_map = std::collections::HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        engine
            .waf_match(script, uri, &headers_map, body)
            .map_err(|e| format!("Lua WAF script error: {}", e))
    }

    /// Evaluate a JavaScript-based custom WAF rule.
    ///
    /// The script must define a `match(request)` function. The request object
    /// has `uri`, `headers`, `body` fields and a `header(name)` method for
    /// case-insensitive header lookup. Returns true if the rule matched
    /// (request should be blocked).
    ///
    /// Use `js_script` in the rule config, or set `engine: "javascript"` with
    /// a `script` field.
    fn evaluate_js_custom_rule(
        &self,
        script: &str,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        use sbproxy_extension::js::JsEngine;

        let engine = JsEngine::new().map_err(|e| format!("JS engine init error: {}", e))?;

        // Build headers map for the JS engine
        let mut headers_map = std::collections::HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        engine
            .waf_match(script, uri, &headers_map, body)
            .map_err(|e| format!("JS WAF script error: {}", e))
    }

    /// Resolve a WAF variable name to the actual string values to scan.
    fn resolve_variable(
        &self,
        name: &str,
        key: Option<&str>,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Vec<String> {
        match name {
            "REQUEST_URI" => vec![uri.to_string()],
            "REQUEST_HEADERS" => {
                if let Some(header_name) = key {
                    headers
                        .get_all(header_name)
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                        .collect()
                } else {
                    // All header values.
                    headers
                        .iter()
                        .filter_map(|(_, v)| v.to_str().ok())
                        .map(|s| s.to_string())
                        .collect()
                }
            }
            "REQUEST_BODY" => {
                if let Some(b) = body {
                    vec![b.to_string()]
                } else {
                    vec![]
                }
            }
            _ => {
                tracing::debug!(variable = name, "WAF: unknown variable, skipping");
                vec![]
            }
        }
    }

    /// Apply the operator to check if target matches pattern.
    fn match_operator(&self, operator: &str, target: &str, pattern: &str) -> Result<bool, String> {
        match operator {
            "contains" => Ok(target.contains(pattern)),
            "rx" | "regex" => {
                let re = Regex::new(pattern)
                    .map_err(|e| format!("invalid regex '{}': {}", pattern, e))?;
                Ok(re.is_match(target))
            }
            "eq" | "equals" => Ok(target == pattern),
            "starts_with" => Ok(target.starts_with(pattern)),
            "ends_with" => Ok(target.ends_with(pattern)),
            _ => Err(format!("unknown WAF operator: {}", operator)),
        }
    }
}

// --- BotDetection ---

/// Bot detection configuration. Blocks requests based on User-Agent patterns.
///
/// If `deny_list` is non-empty, any User-Agent containing a denied pattern
/// (case-insensitive substring match) is blocked with 403.
/// If `allow_list` is non-empty, a User-Agent matching an allowed pattern
/// is exempted from the deny check.
#[derive(Debug, Deserialize)]
pub struct BotDetection {
    /// Master switch for bot detection on this origin.
    #[serde(default)]
    pub enabled: bool,
    /// Mode of operation (`block`, `log`, etc.).
    #[serde(default)]
    pub mode: Option<String>,
    /// User-Agent substrings (case-insensitive) that are blocked.
    #[serde(default)]
    pub deny_list: Vec<String>,
    /// User-Agent substrings (case-insensitive) that are exempted.
    #[serde(default)]
    pub allow_list: Vec<String>,
}

impl BotDetection {
    /// Build a BotDetection from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check if the given User-Agent should be blocked.
    /// Returns true if the request should be allowed, false if blocked.
    pub fn check_user_agent(&self, user_agent: &str) -> bool {
        if !self.enabled {
            return true;
        }

        let ua_lower = user_agent.to_lowercase();

        // Check allow list first: if the UA matches any allowed pattern, allow.
        for pattern in &self.allow_list {
            if ua_lower.contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        // Check deny list: if the UA matches any denied pattern, block.
        for pattern in &self.deny_list {
            if ua_lower.contains(&pattern.to_lowercase()) {
                return false;
            }
        }

        // Default: allow
        true
    }
}

// --- ThreatProtection ---

/// Threat protection for JSON request bodies. Validates depth, key count,
/// string length, array size, and total body size.
#[derive(Debug, Deserialize)]
pub struct ThreatProtection {
    /// Master switch for body threat checks on this origin.
    #[serde(default)]
    pub enabled: bool,
    /// JSON-specific limits applied when the body is `application/json`.
    #[serde(default)]
    pub json: Option<JsonThreatConfig>,
}

/// JSON-specific threat limits.
#[derive(Debug, Deserialize, Clone)]
pub struct JsonThreatConfig {
    /// Maximum allowed nesting depth.
    #[serde(default)]
    pub max_depth: Option<usize>,
    /// Maximum allowed number of keys across all objects.
    #[serde(default)]
    pub max_keys: Option<usize>,
    /// Maximum allowed length of any single string value.
    #[serde(default)]
    pub max_string_length: Option<usize>,
    /// Maximum allowed length of any single array.
    #[serde(default)]
    pub max_array_size: Option<usize>,
    /// Maximum allowed total body size in bytes.
    #[serde(default)]
    pub max_total_size: Option<usize>,
}

impl ThreatProtection {
    /// Build a ThreatProtection from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check a JSON body against the configured threat limits.
    /// Returns Ok(()) if valid, Err(message) if a limit is exceeded.
    pub fn check_json_body(&self, body: &[u8]) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let json_config = match &self.json {
            Some(c) => c,
            None => return Ok(()),
        };

        // Check total body size.
        if let Some(max_size) = json_config.max_total_size {
            if body.len() > max_size {
                return Err(format!("body size {} exceeds max {}", body.len(), max_size));
            }
        }

        // Parse JSON.
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {}", e))?;

        // Validate recursively.
        Self::validate_value(&value, 0, json_config)
    }

    /// Recursively validate a JSON value against the threat limits.
    fn validate_value(
        value: &serde_json::Value,
        current_depth: usize,
        config: &JsonThreatConfig,
    ) -> Result<(), String> {
        if let Some(max_depth) = config.max_depth {
            if current_depth > max_depth {
                return Err(format!(
                    "JSON depth {} exceeds max {}",
                    current_depth, max_depth
                ));
            }
        }

        match value {
            serde_json::Value::Object(map) => {
                if let Some(max_keys) = config.max_keys {
                    if map.len() > max_keys {
                        return Err(format!("object has {} keys, max {}", map.len(), max_keys));
                    }
                }
                for (_key, val) in map {
                    Self::validate_value(val, current_depth + 1, config)?;
                }
            }
            serde_json::Value::Array(arr) => {
                if let Some(max_size) = config.max_array_size {
                    if arr.len() > max_size {
                        return Err(format!(
                            "array has {} elements, max {}",
                            arr.len(),
                            max_size
                        ));
                    }
                }
                for val in arr {
                    Self::validate_value(val, current_depth + 1, config)?;
                }
            }
            serde_json::Value::String(s) => {
                if let Some(max_len) = config.max_string_length {
                    if s.len() > max_len {
                        return Err(format!("string length {} exceeds max {}", s.len(), max_len));
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }
}

// --- RequestValidatorPolicy ---

/// Validates request bodies against a JSON Schema at the edge.
///
/// Modelled on Kong's request-validator and Envoy's JSON-schema
/// filter: the schema is compiled at config-load time so each request
/// is a cheap dispatch. Remote `$ref` resolution is disabled at the
/// workspace level so a malicious schema cannot become an SSRF
/// primitive.
///
/// The policy applies to requests whose `Content-Type` matches one
/// of the configured `content_types` (default: `application/json`).
/// Requests of any other type are passed through untouched.
pub struct RequestValidatorPolicy {
    /// The raw schema document, kept for diagnostics.
    pub schema: serde_json::Value,
    /// Pre-compiled validator.
    compiled: jsonschema::JSONSchema,
    /// Content-types that trigger validation. Matched
    /// case-insensitively against the leading media type of the
    /// inbound `Content-Type` (parameters like `; charset=utf-8` are
    /// ignored).
    pub content_types: Vec<String>,
    /// HTTP status returned when the body fails validation.
    /// Default 400.
    pub status: u16,
    /// Optional response body to send on rejection. When unset, the
    /// proxy returns a short JSON object describing the failure
    /// location (without echoing the offending payload back to the
    /// caller).
    pub error_body: Option<String>,
    /// `Content-Type` for the rejection body. Default
    /// `application/json`.
    pub error_content_type: String,
}

impl std::fmt::Debug for RequestValidatorPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestValidatorPolicy")
            .field("content_types", &self.content_types)
            .field("status", &self.status)
            .finish()
    }
}

impl RequestValidatorPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            schema: serde_json::Value,
            #[serde(default = "default_content_types")]
            content_types: Vec<String>,
            #[serde(default = "default_status")]
            status: u16,
            #[serde(default)]
            error_body: Option<String>,
            #[serde(default = "default_error_content_type")]
            error_content_type: String,
        }
        fn default_content_types() -> Vec<String> {
            vec!["application/json".to_string()]
        }
        fn default_status() -> u16 {
            400
        }
        fn default_error_content_type() -> String {
            "application/json".to_string()
        }

        let raw: Raw = serde_json::from_value(value)?;
        let compiled = jsonschema::JSONSchema::options()
            .compile(&raw.schema)
            .map_err(|e| anyhow::anyhow!("invalid request_validator schema: {e}"))?;
        Ok(Self {
            schema: raw.schema,
            compiled,
            content_types: raw.content_types,
            status: raw.status,
            error_body: raw.error_body,
            error_content_type: raw.error_content_type,
        })
    }

    /// True when this policy should validate a request with the given
    /// `Content-Type` header value (`None` = absent header).
    pub fn applies_to(&self, content_type: Option<&str>) -> bool {
        let ct = match content_type {
            Some(c) => c,
            None => return false,
        };
        let media = ct.split(';').next().unwrap_or("").trim();
        self.content_types
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(media))
    }

    /// Validate a request body. Returns `Ok(())` when the body
    /// conforms; otherwise an `Err(message)` describing where
    /// validation failed (the location only, since the offending value is
    /// omitted because it is attacker-controlled).
    pub fn validate(&self, body: &[u8]) -> Result<(), String> {
        let instance: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| format!("invalid JSON in request body: {e}"))?;
        if let Err(errors) = self.compiled.validate(&instance) {
            let first = errors
                .into_iter()
                .next()
                .map(|e| format!("{}", e.instance_path))
                .unwrap_or_else(|| "<root>".to_string());
            return Err(format!("request body failed schema validation at {first}"));
        }
        Ok(())
    }
}

// --- ConcurrentLimitPolicy ---

/// Caps in-flight requests per key, returning a configurable status
/// code (default 503) when the limit is reached.
///
/// Distinct from `RateLimitPolicy`, which controls *rate* (RPS).
/// Concurrent limits protect backends with low concurrency budgets:
/// legacy SOAP services, DB-bound endpoints, GPU inference workers.
///
/// Keys are derived per request by `key`:
///   * `origin` (default): one global counter for the whole route;
///   * `ip`: one counter per client IP;
///   * `api_key`: one counter per `X-Api-Key` header value (or
///     `Authorization: Bearer …` when api-key auth is not used).
///
/// Each accepted request takes a permit; the permit is released in
/// the response phase. If acquisition would exceed `max`, the
/// request is rejected immediately.
pub struct ConcurrentLimitPolicy {
    /// Maximum concurrent requests per key.
    pub max: u32,
    /// Key strategy: `origin`, `ip`, or `api_key`.
    pub key: String,
    /// HTTP status returned when the limit is exceeded. Default 503.
    pub status: u16,
    /// Optional response body for rejections.
    pub error_body: Option<String>,
    /// Counters keyed by the resolved key string.
    counters: std::sync::Arc<dashmap::DashMap<String, std::sync::atomic::AtomicU32>>,
}

impl std::fmt::Debug for ConcurrentLimitPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrentLimitPolicy")
            .field("max", &self.max)
            .field("key", &self.key)
            .field("status", &self.status)
            .field("active_keys", &self.counters.len())
            .finish()
    }
}

impl ConcurrentLimitPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            max: u32,
            #[serde(default = "default_key")]
            key: String,
            #[serde(default = "default_status")]
            status: u16,
            #[serde(default)]
            error_body: Option<String>,
        }
        fn default_key() -> String {
            "origin".to_string()
        }
        fn default_status() -> u16 {
            503
        }

        let raw: Raw = serde_json::from_value(value)?;
        anyhow::ensure!(raw.max > 0, "concurrent_limit.max must be > 0");
        match raw.key.as_str() {
            "origin" | "ip" | "api_key" => {}
            other => anyhow::bail!(
                "concurrent_limit.key must be 'origin', 'ip', or 'api_key' (got '{other}')"
            ),
        }
        Ok(Self {
            max: raw.max,
            key: raw.key,
            status: raw.status,
            error_body: raw.error_body,
            counters: std::sync::Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Resolve the bucket key for a request given the client IP and
    /// request headers, plus an origin identifier used as the bucket
    /// when `key = "origin"`.
    pub fn resolve_key(
        &self,
        origin_id: &str,
        client_ip: Option<&str>,
        headers: &http::HeaderMap,
    ) -> String {
        match self.key.as_str() {
            "ip" => client_ip.unwrap_or("0.0.0.0").to_string(),
            "api_key" => {
                if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                    return v.to_string();
                }
                if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
                    return v.trim_start_matches("Bearer ").to_string();
                }
                "anon".to_string()
            }
            _ => origin_id.to_string(),
        }
    }

    /// Try to acquire a permit. Returns `Some(guard)` when the
    /// permit was issued; the caller must keep the guard alive for
    /// the lifetime of the request, since dropping it releases the slot.
    /// Returns `None` when the limit is already saturated; the
    /// caller should reject the request with `self.status`.
    pub fn try_acquire(&self, key: &str) -> Option<ConcurrentLimitGuard> {
        use std::sync::atomic::Ordering;
        let entry = self
            .counters
            .entry(key.to_string())
            .or_insert_with(|| std::sync::atomic::AtomicU32::new(0));
        let prev = entry.value().fetch_add(1, Ordering::AcqRel);
        if prev >= self.max {
            // Roll back the increment.
            entry.value().fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(ConcurrentLimitGuard {
            counters: std::sync::Arc::clone(&self.counters),
            key: key.to_string(),
        })
    }
}

/// RAII handle that releases a concurrent-limit permit when dropped.
pub struct ConcurrentLimitGuard {
    counters: std::sync::Arc<dashmap::DashMap<String, std::sync::atomic::AtomicU32>>,
    key: String,
}

impl Drop for ConcurrentLimitGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if let Some(entry) = self.counters.get(&self.key) {
            entry.value().fetch_sub(1, Ordering::AcqRel);
        }
    }
}

// --- ExposedCredsPolicy ---

/// Outcome of an exposed-credentials check on an inbound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposedCredsResult {
    /// No credentials extracted, or the extracted credentials were
    /// not on the configured exposure list.
    Clean,
    /// Credentials matched the list. The policy's `action` decides
    /// whether to tag the upstream request or block it.
    Hit {
        /// Short reason string emitted as the value of the
        /// `Exposed-Credential-Check` header (`leaked-password` for
        /// the static-list provider).
        reason: &'static str,
    },
}

/// What to do when a request carries an exposed credential.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExposedCredsAction {
    /// Forward the request, but stamp the `Exposed-Credential-Check`
    /// header so the upstream can react (force a step-up auth, page
    /// the SecOps team, etc.). Default.
    #[default]
    Tag,
    /// Reject the request with `403 Forbidden`. Use this once the
    /// upstream is confident the list represents real exposures.
    Block,
}

/// Detects exposed credentials in inbound requests.
///
/// Today the OSS implementation ships the **static** provider:
/// operators supply a list of leaked passwords (or SHA-1 hashes
/// thereof) and the policy hashes inbound credentials with SHA-1
/// before checking the set in constant time. Hash-only lists keep
/// the configured material from leaking through error messages or
/// process dumps.
///
/// Credentials are extracted from `Authorization: Basic <b64>`. The
/// HIBP k-anonymity provider lives behind a separate enterprise
/// adapter (TBD) so the OSS data plane has no outbound dependency.
#[derive(Debug, Deserialize)]
pub struct ExposedCredsPolicy {
    /// Source of the exposure list. Today only `static` is recognised
    /// in OSS; enterprise extends this with `hibp`.
    #[serde(default = "default_exposed_creds_provider")]
    pub provider: String,
    /// Action to take on a match. Default is `tag`.
    #[serde(default)]
    pub action: ExposedCredsAction,
    /// Header name stamped on the upstream request when `action: tag`.
    /// Default `exposed-credential-check`.
    #[serde(default = "default_exposed_creds_header")]
    pub header: String,
    /// Inline plaintext passwords. Hashed at compile time; the source
    /// strings are not retained on the policy.
    #[serde(default)]
    pub passwords: Vec<String>,
    /// Inline SHA-1 hex hashes (uppercase, the HIBP convention).
    /// Useful when distributing pre-hashed exposure lists without
    /// shipping plaintext passwords through the config.
    #[serde(default)]
    pub sha1_hashes: Vec<String>,
    /// File path containing one SHA-1 hex hash per line. Lines
    /// starting with `#` are ignored. Loaded once at config compile.
    #[serde(default)]
    pub sha1_file: Option<String>,
    /// Compiled lookup set (hex SHA-1, uppercase). Built by
    /// [`Self::from_config`] and not deserialised directly.
    #[serde(skip)]
    hash_set: std::collections::HashSet<String>,
}

fn default_exposed_creds_provider() -> String {
    "static".to_string()
}

fn default_exposed_creds_header() -> String {
    "exposed-credential-check".to_string()
}

impl ExposedCredsPolicy {
    /// Build a policy from a JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        if policy.provider != "static" {
            anyhow::bail!(
                "exposed_credentials provider {:?} not recognised in OSS; only `static` is supported (HIBP lives in the enterprise build)",
                policy.provider
            );
        }
        let mut hash_set = std::collections::HashSet::new();
        for password in policy.passwords.drain(..) {
            hash_set.insert(sha1_hex_upper(password.as_bytes()));
        }
        for h in policy.sha1_hashes.drain(..) {
            hash_set.insert(h.trim().to_ascii_uppercase());
        }
        if let Some(path) = policy.sha1_file.as_deref() {
            let body = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("read sha1_file {}: {}", path, e))?;
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                hash_set.insert(line.to_ascii_uppercase());
            }
        }
        if hash_set.is_empty() {
            anyhow::bail!(
                "exposed_credentials requires a non-empty list (passwords, sha1_hashes, or sha1_file)"
            );
        }
        policy.hash_set = hash_set;
        Ok(policy)
    }

    /// Inspect the request headers for exposed credentials. Today this
    /// recognises `Authorization: Basic <base64(user:password)>`.
    pub fn check(&self, headers: &http::HeaderMap) -> ExposedCredsResult {
        let Some(password) = extract_basic_auth_password(headers) else {
            return ExposedCredsResult::Clean;
        };
        let hash = sha1_hex_upper(password.as_bytes());
        if self.hash_set.contains(&hash) {
            ExposedCredsResult::Hit {
                reason: "leaked-password",
            }
        } else {
            ExposedCredsResult::Clean
        }
    }

    /// Header name to stamp on the upstream request when tagging.
    pub fn header_name(&self) -> &str {
        &self.header
    }

    /// Configured action.
    pub fn action(&self) -> ExposedCredsAction {
        self.action
    }
}

/// Extract the password segment of an `Authorization: Basic` header.
fn extract_basic_auth_password(headers: &http::HeaderMap) -> Option<String> {
    let raw = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))?;
    let raw = raw.to_str().ok()?;
    let token = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?
        .trim();
    if token.is_empty() {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let decoded = std::str::from_utf8(&bytes).ok()?;
    let (_user, password) = decoded.split_once(':')?;
    if password.is_empty() {
        None
    } else {
        Some(password.to_string())
    }
}

fn sha1_hex_upper(bytes: &[u8]) -> String {
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
    let d = digest(&SHA1_FOR_LEGACY_USE_ONLY, bytes);
    let mut out = String::with_capacity(40);
    for b in d.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02X}", b);
    }
    out
}

// --- Tests ---

#[cfg(test)]
mod exposed_creds_tests {
    use super::*;

    fn basic_auth_header(user: &str, password: &str) -> http::HeaderMap {
        let raw = format!("{}:{}", user, password);
        let token = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("Basic {token}").parse().unwrap());
        headers
    }

    #[test]
    fn known_password_is_flagged() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let result = policy.check(&basic_auth_header("alice", "password123"));
        assert!(matches!(result, ExposedCredsResult::Hit { .. }));
    }

    #[test]
    fn unknown_password_passes() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let result = policy.check(&basic_auth_header("alice", "this-is-fine"));
        assert_eq!(result, ExposedCredsResult::Clean);
    }

    #[test]
    fn no_basic_auth_is_clean() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let result = policy.check(&http::HeaderMap::new());
        assert_eq!(result, ExposedCredsResult::Clean);
    }

    #[test]
    fn bearer_token_does_not_match_basic_auth_path() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password123"],
        }))
        .unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer password123".parse().unwrap());
        assert_eq!(policy.check(&headers), ExposedCredsResult::Clean);
    }

    #[test]
    fn sha1_hashes_match_lowercase_or_uppercase() {
        // "password" -> SHA1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "sha1_hashes": ["5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"],
        }))
        .unwrap();
        let result = policy.check(&basic_auth_header("alice", "password"));
        assert!(matches!(result, ExposedCredsResult::Hit { .. }));
    }

    #[test]
    fn empty_list_is_rejected_at_config_time() {
        let err = ExposedCredsPolicy::from_config(serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("non-empty list"));
    }

    #[test]
    fn unrecognised_provider_rejected() {
        let err = ExposedCredsPolicy::from_config(serde_json::json!({
            "provider": "hibp",
            "passwords": ["password"],
        }))
        .unwrap_err();
        assert!(err.to_string().contains("hibp"));
    }

    #[test]
    fn block_action_round_trips() {
        let policy = ExposedCredsPolicy::from_config(serde_json::json!({
            "passwords": ["password"],
            "action": "block",
        }))
        .unwrap();
        assert_eq!(policy.action(), ExposedCredsAction::Block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- RateLimitPolicy tests ---

    #[test]
    fn rate_limit_policy_type() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 100.0,
            "burst": 50
        });
        let rl = RateLimitPolicy::from_config(json).unwrap();
        let policy = Policy::RateLimit(rl);
        assert_eq!(policy.policy_type(), "rate_limiting");
    }

    #[test]
    fn policy_debug_rate_limit() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 10.0,
            "burst": 5
        });
        let rl = RateLimitPolicy::from_config(json).unwrap();
        let policy = Policy::RateLimit(rl);
        let debug = format!("{:?}", policy);
        assert!(debug.contains("RateLimit"));
    }

    #[test]
    fn rate_limit_from_config() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 50.0,
            "burst": 20
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert_eq!(policy.requests_per_second, Some(50.0));
        assert_eq!(policy.burst, Some(20));
    }

    #[test]
    fn rate_limit_from_config_default_burst() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 10.0
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert_eq!(policy.burst, None);
    }

    #[test]
    fn rate_limit_from_config_defaults() {
        // Both rps and rpm are optional; defaults to 10 rps
        let json = serde_json::json!({"type": "rate_limiting"});
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert_eq!(policy.effective_rps(), 10.0);
    }

    #[test]
    fn rate_limit_from_config_rpm() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_minute": 60
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert!((policy.effective_rps() - 1.0).abs() < 0.01);
    }

    #[test]
    fn allow_within_burst() {
        let json = serde_json::json!({
            "requests_per_second": 10.0,
            "burst": 5
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();

        for _ in 0..5 {
            assert!(policy.allow());
        }
        assert!(!policy.allow());
    }

    #[test]
    fn allow_refills_over_time() {
        let json = serde_json::json!({
            "requests_per_second": 1000.0,
            "burst": 1
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();

        assert!(policy.allow());
        assert!(!policy.allow());

        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(policy.allow());
    }

    #[test]
    fn allow_does_not_exceed_burst() {
        let json = serde_json::json!({
            "requests_per_second": 1000.0,
            "burst": 3
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();

        for _ in 0..3 {
            assert!(policy.allow());
        }
        assert!(!policy.allow());

        std::thread::sleep(std::time::Duration::from_millis(10));

        let mut allowed = 0;
        for _ in 0..10 {
            if policy.allow() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3, "should not exceed burst capacity");
    }

    // --- IpFilterPolicy tests ---

    #[test]
    fn ip_filter_policy_type() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8"]
        }))
        .unwrap();
        let policy = Policy::IpFilter(policy);
        assert_eq!(policy.policy_type(), "ip_filter");
    }

    #[test]
    fn ip_filter_whitelist_allows_matching() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8", "192.168.1.0/24"]
        }))
        .unwrap();

        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(policy.check_ip(&ip));

        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_whitelist_denies_non_matching() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8"]
        }))
        .unwrap();

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(!policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_blacklist_blocks_matching() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "blacklist": ["192.168.1.0/24"]
        }))
        .unwrap();

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(!policy.check_ip(&ip));

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_empty_lists_allow_all() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({})).unwrap();

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_invalid_cidr_errors() {
        let result = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["not-a-cidr"]
        }));
        assert!(result.is_err());
    }

    #[test]
    fn ip_filter_whitelist_and_blacklist_combined() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8"],
            "blacklist": ["10.0.1.0/24"]
        }))
        .unwrap();

        // In whitelist but also in blacklist - should be denied
        let ip: IpAddr = "10.0.1.5".parse().unwrap();
        assert!(!policy.check_ip(&ip));

        // In whitelist and not in blacklist - should be allowed
        let ip: IpAddr = "10.0.2.5".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_single_ip_cidr() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["192.168.1.1/32"]
        }))
        .unwrap();

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(policy.check_ip(&ip));

        let ip: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(!policy.check_ip(&ip));
    }

    // --- SecHeadersPolicy tests ---

    #[test]
    fn sec_headers_policy_type() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [{"name": "X-Frame-Options", "value": "DENY"}]
        }))
        .unwrap();
        let policy = Policy::SecHeaders(policy);
        assert_eq!(policy.policy_type(), "security_headers");
    }

    #[test]
    fn sec_headers_from_config_new_format() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [
                {"name": "X-Frame-Options", "value": "SAMEORIGIN"},
                {"name": "X-Content-Type-Options", "value": "nosniff"},
                {"name": "Referrer-Policy", "value": "no-referrer"},
                {"name": "Content-Security-Policy", "value": "default-src 'self'"}
            ]
        }))
        .unwrap();

        let resolved = policy.resolved_headers();
        assert_eq!(resolved.len(), 4);
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "x-frame-options" && v == "SAMEORIGIN"));
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "x-content-type-options" && v == "nosniff"));
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "referrer-policy" && v == "no-referrer"));
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "content-security-policy" && v == "default-src 'self'"));
    }

    #[test]
    fn sec_headers_from_config_legacy_flat() {
        // Legacy flat format still works (backward compat).
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "x_frame_options": "SAMEORIGIN",
            "x_content_type_options": "nosniff",
            "referrer_policy": "no-referrer",
            "content_security_policy": "default-src 'self'"
        }))
        .unwrap();

        assert_eq!(policy.x_frame_options.as_deref(), Some("SAMEORIGIN"));
        assert_eq!(policy.x_content_type_options.as_deref(), Some("nosniff"));
        assert_eq!(policy.referrer_policy.as_deref(), Some("no-referrer"));
        assert_eq!(
            policy
                .content_security_policy
                .as_ref()
                .and_then(|s| s.as_legacy_str()),
            Some("default-src 'self'")
        );
        assert!(policy.x_xss_protection.is_none());
        assert!(policy.permissions_policy.is_none());

        let resolved = policy.resolved_headers();
        assert!(resolved.iter().any(|(n, _)| n == "x-frame-options"));
    }

    #[test]
    fn sec_headers_empty_config() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({})).unwrap();
        assert!(policy.headers.is_empty());
        assert!(policy.x_frame_options.is_none());
        assert!(policy.resolved_headers().is_empty());
    }

    #[test]
    fn sec_headers_csp_detailed_with_nonce() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "default-src 'self'; script-src 'self'",
                "enable_nonce": true
            }
        }))
        .unwrap();

        let (headers, nonce) = policy.resolved_headers_for_request("/");
        let nonce = nonce.expect("nonce should be generated when enable_nonce is true");
        assert!(!nonce.is_empty());

        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .expect("CSP header should be set");
        assert!(
            csp.1.contains(&format!("'nonce-{}'", nonce)),
            "nonce should be injected into script-src: {}",
            csp.1
        );
    }

    #[test]
    fn sec_headers_csp_report_only() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "default-src 'self'",
                "report_only": true,
                "report_uri": "/csp-report",
                "enable_nonce": true
            }
        }))
        .unwrap();

        let (headers, _nonce) = policy.resolved_headers_for_request("/");
        let h = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy-report-only")
            .expect("report-only CSP header should be set");
        assert!(h.1.contains("report-uri /csp-report"));
        assert!(
            headers.iter().all(|(n, _)| n != "content-security-policy"),
            "must not emit both enforcing and report-only CSP"
        );
    }

    #[test]
    fn sec_headers_csp_dynamic_routes() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "default-src 'self'",
                "dynamic_routes": {
                    "/admin": { "policy": "default-src 'self' admin.example.com" },
                    "/admin/users": { "policy": "default-src 'self' admin.example.com users.example.com" }
                }
            }
        }))
        .unwrap();

        // Root path uses the outer policy.
        let (headers, _) = policy.resolved_headers_for_request("/");
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(csp.1, "default-src 'self'");

        // `/admin` prefix uses admin policy.
        let (headers, _) = policy.resolved_headers_for_request("/admin/something");
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(csp.1, "default-src 'self' admin.example.com");

        // Longer prefix wins.
        let (headers, _) = policy.resolved_headers_for_request("/admin/users/42");
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(
            csp.1,
            "default-src 'self' admin.example.com users.example.com"
        );
    }

    #[test]
    fn sec_headers_csp_simple_string_still_works() {
        // The plain string form of content_security_policy must still parse
        // and produce a simple CSP header with no nonce or routes.
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": "default-src 'self'"
        }))
        .unwrap();

        let (headers, nonce) = policy.resolved_headers_for_request("/any/path");
        assert!(nonce.is_none());
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(csp.1, "default-src 'self'");
    }

    #[test]
    fn sec_headers_nonce_injection_preserves_existing_nonce() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "script-src 'self' 'nonce-fixed'; style-src 'self'",
                "enable_nonce": true
            }
        }))
        .unwrap();

        let (headers, nonce) = policy.resolved_headers_for_request("/");
        let nonce = nonce.unwrap();
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        // The existing 'nonce-fixed' directive is preserved (no double-injection).
        assert!(csp.1.contains("'nonce-fixed'"));
        // style-src gets the new nonce injected.
        assert!(csp
            .1
            .contains(&format!("style-src 'self' 'nonce-{}'", nonce)));
    }

    // --- RequestLimitPolicy tests ---

    #[test]
    fn request_limit_policy_type() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_body_size": 1024
        }))
        .unwrap();
        let policy = Policy::RequestLimit(policy);
        assert_eq!(policy.policy_type(), "request_limit");
    }

    #[test]
    fn request_limit_check_passes() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_body_size": 1024,
            "max_header_count": 50,
            "max_header_size": 8192,
            "max_url_length": 2048
        }))
        .unwrap();

        assert!(policy.check_request(512, 10, 256, 100, 0).is_ok());
    }

    #[test]
    fn request_limit_body_too_large() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_body_size": 1024
        }))
        .unwrap();

        let result = policy.check_request(2048, 10, 256, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("body size"));
    }

    #[test]
    fn request_limit_too_many_headers() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_header_count": 10
        }))
        .unwrap();

        let result = policy.check_request(0, 20, 256, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("header count"));
    }

    #[test]
    fn request_limit_header_value_too_large() {
        let policy = RequestLimitPolicy {
            max_body_size: None,
            max_header_count: None,
            max_header_size: Some(SizeValue(256)),
            max_url_length: None,
            max_query_string_length: None,
            max_request_size: None,
            size_limits: None,
        };

        let result = policy.check_request(0, 5, 512, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("header value size"));
    }

    #[test]
    fn request_limit_url_too_long() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_url_length": 100
        }))
        .unwrap();

        let result = policy.check_request(0, 5, 50, 200, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("URL length"));
    }

    #[test]
    fn request_limit_no_limits_set() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({})).unwrap();
        assert!(policy.check_request(999999, 999, 999, 9999, 0).is_ok());
    }

    // --- CsrfPolicy tests ---

    #[test]
    fn csrf_policy_type() {
        let policy = CsrfPolicy::from_config(serde_json::json!({
            "secret_key": "test-secret"
        }))
        .unwrap();
        let policy = Policy::Csrf(policy);
        assert_eq!(policy.policy_type(), "csrf");
    }

    #[test]
    fn csrf_from_config_defaults() {
        let policy = CsrfPolicy::from_config(serde_json::json!({
            "secret_key": "my-secret"
        }))
        .unwrap();

        assert_eq!(policy.secret_key, "my-secret");
        assert_eq!(policy.header_name, "X-CSRF-Token");
        assert_eq!(policy.cookie_name, "csrf_token");
        assert_eq!(policy.safe_methods, vec!["GET", "HEAD", "OPTIONS"]);
    }

    #[test]
    fn csrf_from_config_custom() {
        let policy = CsrfPolicy::from_config(serde_json::json!({
            "secret_key": "s3cr3t",
            "header_name": "X-My-Token",
            "cookie_name": "my_csrf",
            "safe_methods": ["GET"]
        }))
        .unwrap();

        assert_eq!(policy.header_name, "X-My-Token");
        assert_eq!(policy.cookie_name, "my_csrf");
        assert_eq!(policy.safe_methods, vec!["GET"]);
    }

    #[test]
    fn csrf_missing_secret_key_errors() {
        let result = CsrfPolicy::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    // --- DdosPolicy tests ---

    #[test]
    fn ddos_policy_type() {
        let policy = DdosPolicy::from_config(serde_json::json!({})).unwrap();
        let policy = Policy::Ddos(policy);
        assert_eq!(policy.policy_type(), "ddos");
    }

    #[test]
    fn ddos_from_config_defaults() {
        let policy = DdosPolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(policy.requests_per_second, 100);
        assert_eq!(policy.block_duration_secs, 300);
        assert!(policy.whitelist.is_empty());
    }

    #[test]
    fn ddos_from_config_custom() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 50,
            "block_duration_secs": 600,
            "whitelist": ["10.0.0.1", "192.168.1.0/24"]
        }))
        .unwrap();

        assert_eq!(policy.requests_per_second, 50);
        assert_eq!(policy.block_duration_secs, 600);
        assert_eq!(policy.whitelist.len(), 2);
    }

    // --- DdosPolicy enforcement ---

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ddos_allows_under_threshold() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 5,
            "block_duration_secs": 1
        }))
        .unwrap();

        let client = ip("10.0.0.1");
        for i in 0..5 {
            assert_eq!(
                policy.check(client),
                DdosCheckResult::Allow,
                "request {i} under threshold should be allowed"
            );
        }
    }

    #[test]
    fn ddos_blocks_at_threshold() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 3,
            "block_duration_secs": 5
        }))
        .unwrap();

        let client = ip("10.0.0.2");

        // First 3 fill the window
        for _ in 0..3 {
            assert_eq!(policy.check(client), DdosCheckResult::Allow);
        }

        // 4th trips the threshold
        match policy.check(client) {
            DdosCheckResult::Block { retry_after_secs } => {
                assert!(
                    retry_after_secs > 0 && retry_after_secs <= 5,
                    "retry_after should be in (0, block_duration]: got {retry_after_secs}"
                );
            }
            DdosCheckResult::Allow => panic!("4th request should have been blocked"),
        }
    }

    #[test]
    fn ddos_subsequent_requests_during_block_are_blocked() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 2,
            "block_duration_secs": 10
        }))
        .unwrap();

        let client = ip("10.0.0.3");

        // Trip the block
        for _ in 0..2 {
            assert_eq!(policy.check(client), DdosCheckResult::Allow);
        }
        let _ = policy.check(client); // trips block

        // Every subsequent request inside the block window stays blocked
        for _ in 0..5 {
            match policy.check(client) {
                DdosCheckResult::Block { .. } => {}
                DdosCheckResult::Allow => panic!("blocked IP should remain blocked"),
            }
        }
    }

    #[test]
    fn ddos_unblocks_after_block_duration() {
        // 1-second block keeps the test fast.
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 2,
            "block_duration_secs": 1
        }))
        .unwrap();

        let client = ip("10.0.0.4");

        // Trip the block
        for _ in 0..2 {
            assert!(matches!(policy.check(client), DdosCheckResult::Allow));
        }
        assert!(matches!(
            policy.check(client),
            DdosCheckResult::Block { .. }
        ));

        // Wait out the block window
        std::thread::sleep(std::time::Duration::from_millis(1100));

        assert_eq!(
            policy.check(client),
            DdosCheckResult::Allow,
            "block should expire after block_duration_secs"
        );
    }

    #[test]
    fn ddos_per_ip_isolation() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 2,
            "block_duration_secs": 5
        }))
        .unwrap();

        let attacker = ip("10.0.0.5");
        let bystander = ip("10.0.0.6");

        // Attacker trips block
        for _ in 0..2 {
            assert!(matches!(policy.check(attacker), DdosCheckResult::Allow));
        }
        assert!(matches!(
            policy.check(attacker),
            DdosCheckResult::Block { .. }
        ));

        // Bystander is unaffected
        for _ in 0..2 {
            assert_eq!(
                policy.check(bystander),
                DdosCheckResult::Allow,
                "bystander IP must not be affected by another IP's block"
            );
        }
    }

    #[test]
    fn ddos_whitelisted_ip_bypasses_check() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 1,
            "block_duration_secs": 10,
            "whitelist": ["10.0.0.7"]
        }))
        .unwrap();

        let trusted = ip("10.0.0.7");

        // Burst well past threshold; whitelist must allow every one
        for i in 0..20 {
            assert_eq!(
                policy.check(trusted),
                DdosCheckResult::Allow,
                "whitelisted IP must always be allowed (request {i})"
            );
        }
    }

    #[test]
    fn ddos_whitelist_supports_cidr() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 1,
            "block_duration_secs": 10,
            "whitelist": ["10.0.0.0/24"]
        }))
        .unwrap();

        let inside_subnet = ip("10.0.0.42");
        let outside_subnet = ip("10.0.1.1");

        // CIDR member is exempt
        for _ in 0..5 {
            assert_eq!(policy.check(inside_subnet), DdosCheckResult::Allow);
        }

        // Non-member trips the threshold normally
        assert_eq!(policy.check(outside_subnet), DdosCheckResult::Allow);
        assert!(matches!(
            policy.check(outside_subnet),
            DdosCheckResult::Block { .. }
        ));
    }

    #[test]
    fn ddos_go_compat_nested_config_enforces_correctly() {
        // The Go-compat nested format is parsed into the same flat fields
        // and must drive the runtime check identically.
        let policy = DdosPolicy::from_config(serde_json::json!({
            "detection": { "request_rate_threshold": 2 },
            "mitigation": { "block_duration": "1s" }
        }))
        .unwrap();

        assert_eq!(policy.requests_per_second, 2);
        assert_eq!(policy.block_duration_secs, 1);

        let client = ip("10.0.0.8");
        for _ in 0..2 {
            assert!(matches!(policy.check(client), DdosCheckResult::Allow));
        }
        assert!(matches!(
            policy.check(client),
            DdosCheckResult::Block { .. }
        ));
    }

    // --- SriPolicy tests ---

    #[test]
    fn sri_policy_type() {
        let policy = SriPolicy::from_config(serde_json::json!({})).unwrap();
        let policy = Policy::Sri(policy);
        assert_eq!(policy.policy_type(), "sri");
    }

    #[test]
    fn sri_from_config_defaults() {
        let policy = SriPolicy::from_config(serde_json::json!({})).unwrap();
        assert!(!policy.enforce);
        // Default to the SRI-spec-approved algorithm set so an enabled
        // policy is useful out of the box without an explicit list.
        assert_eq!(policy.algorithms, vec!["sha256", "sha384", "sha512"]);
    }

    #[test]
    fn sri_from_config_custom() {
        let policy = SriPolicy::from_config(serde_json::json!({
            "enforce": true,
            "algorithms": ["sha256", "sha384", "sha512"]
        }))
        .unwrap();

        assert!(policy.enforce);
        assert_eq!(policy.algorithms, vec!["sha256", "sha384", "sha512"]);
    }

    // --- SriPolicy enforcement ---

    fn enforced_sri() -> SriPolicy {
        SriPolicy::from_config(serde_json::json!({"enforce": true})).unwrap()
    }

    #[test]
    fn sri_disabled_policy_is_noop() {
        let policy = SriPolicy::from_config(serde_json::json!({})).unwrap();
        let result =
            policy.check_html_body(b"<script src=\"https://x/y.js\"></script>", "text/html");
        assert_eq!(result, SriCheckResult::NotApplicable);
    }

    #[test]
    fn sri_skips_non_html_responses() {
        let policy = enforced_sri();
        let body = b"{\"foo\": 1}";
        assert_eq!(
            policy.check_html_body(body, "application/json"),
            SriCheckResult::NotApplicable
        );
        assert_eq!(
            policy.check_html_body(body, "text/plain"),
            SriCheckResult::NotApplicable
        );
    }

    #[test]
    fn sri_html_with_no_subresources_is_clean() {
        let policy = enforced_sri();
        let html = b"<html><body><h1>hello</h1><p>no scripts</p></body></html>";
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_inline_script_is_ignored() {
        let policy = enforced_sri();
        // Inline script (no src attribute) is not a subresource.
        let html = b"<script>console.log('hi')</script>";
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_relative_url_is_treated_as_same_origin() {
        let policy = enforced_sri();
        let html = br#"<script src="/static/app.js"></script>
<link rel="stylesheet" href="theme.css">"#;
        // Relative URLs are same-origin; SRI does not apply.
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_external_script_with_valid_integrity_is_clean() {
        let policy = enforced_sri();
        let html = br#"<script src="https://cdn.example.com/lib.js"
                       integrity="sha384-abc123"
                       crossorigin="anonymous"></script>"#;
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_external_script_missing_integrity_is_violation() {
        let policy = enforced_sri();
        let html = br#"<script src="https://cdn.example.com/lib.js"></script>"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].tag, "script");
                assert_eq!(v[0].url, "https://cdn.example.com/lib.js");
                assert_eq!(v[0].reason, SriViolationReason::MissingIntegrity);
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_external_stylesheet_missing_integrity_is_violation() {
        let policy = enforced_sri();
        let html = br#"<link rel="stylesheet" href="https://cdn.example.com/theme.css">"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].tag, "link");
                assert_eq!(v[0].url, "https://cdn.example.com/theme.css");
                assert_eq!(v[0].reason, SriViolationReason::MissingIntegrity);
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_non_stylesheet_link_is_ignored() {
        let policy = enforced_sri();
        // preconnect, dns-prefetch, icon, etc. are not subresources we
        // can validate via SRI.
        let html = br#"<link rel="preconnect" href="https://cdn.example.com">
<link rel="icon" href="https://cdn.example.com/favicon.ico">"#;
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_weak_algorithm_is_violation() {
        let policy = SriPolicy::from_config(serde_json::json!({
            "enforce": true,
            "algorithms": ["sha384", "sha512"]
        }))
        .unwrap();
        // sha256 hash present but the policy only accepts sha384/sha512.
        let html = br#"<script src="https://cdn.example.com/lib.js"
                       integrity="sha256-abc"></script>"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                assert_eq!(v.len(), 1);
                assert!(matches!(
                    v[0].reason,
                    SriViolationReason::DisallowedAlgorithm { ref found } if found == "sha256"
                ));
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_multiple_violations_reported_individually() {
        let policy = enforced_sri();
        let html = br#"<html>
<link rel="stylesheet" href="https://cdn1.example.com/a.css">
<script src="https://cdn2.example.com/a.js"></script>
<script src="https://cdn3.example.com/b.js" integrity="sha384-OK"></script>
<script src="/local.js"></script>
</html>"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                // 2 external violations (cdn1 stylesheet + cdn2 script).
                // cdn3 is fine; /local.js is same-origin.
                assert_eq!(v.len(), 2, "violations: {v:?}");
                let urls: Vec<&str> = v.iter().map(|x| x.url.as_str()).collect();
                assert!(urls.contains(&"https://cdn1.example.com/a.css"));
                assert!(urls.contains(&"https://cdn2.example.com/a.js"));
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_content_type_with_charset_still_matches_html() {
        let policy = enforced_sri();
        let html = br#"<script src="https://cdn.example.com/lib.js"></script>"#;
        let result = policy.check_html_body(html, "text/html; charset=utf-8");
        assert!(matches!(result, SriCheckResult::Violations(_)));
    }

    // --- ExpressionPolicy tests ---

    #[test]
    fn expression_policy_type() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();
        let policy = Policy::Expression(policy);
        assert_eq!(policy.policy_type(), "expression");
    }

    #[test]
    fn expression_from_config() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.method == \"GET\"",
            "deny_status": 401,
            "deny_message": "unauthorized"
        }))
        .unwrap();

        assert_eq!(policy.expression, "request.method == \"GET\"");
        assert_eq!(policy.deny_status, 401);
        assert_eq!(policy.deny_message, "unauthorized");
    }

    #[test]
    fn expression_from_config_defaults() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();

        assert_eq!(policy.deny_status, 403);
        assert_eq!(policy.deny_message, "forbidden by policy");
    }

    #[test]
    fn expression_from_config_missing_expression_errors() {
        let result = ExpressionPolicy::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn expression_evaluate_simple_true() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.method == \"GET\""
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        assert!(policy.evaluate("GET", "/", &headers, None, None, "example.com"));
    }

    #[test]
    fn expression_evaluate_simple_false() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.method == \"POST\""
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        assert!(!policy.evaluate("GET", "/", &headers, None, None, "example.com"));
    }

    #[test]
    fn expression_evaluate_fail_open_on_bad_expression() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "this is not valid CEL !!!"
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        // Should fail open (return true) on compile error
        assert!(policy.evaluate("GET", "/", &headers, None, None, "example.com"));
    }

    #[test]
    fn expression_evaluate_path_check() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.path.startsWith(\"/api/\")"
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        assert!(policy.evaluate("GET", "/api/v1/users", &headers, None, None, "example.com"));
        assert!(!policy.evaluate("GET", "/health", &headers, None, None, "example.com"));
    }

    // --- AssertionPolicy tests ---

    #[test]
    fn assertion_policy_type() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();
        let policy = Policy::Assertion(policy);
        assert_eq!(policy.policy_type(), "assertion");
    }

    #[test]
    fn assertion_from_config() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status < 500",
            "name": "no-5xx"
        }))
        .unwrap();

        assert_eq!(policy.expression, "response.status < 500");
        assert_eq!(policy.name, "no-5xx");
    }

    #[test]
    fn assertion_from_config_default_name() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();

        assert_eq!(policy.name, "assertion");
    }

    #[test]
    fn assertion_from_config_missing_expression_errors() {
        let result = AssertionPolicy::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    // --- Debug impl tests ---

    #[test]
    fn policy_debug_all_variants() {
        let variants: Vec<Policy> = vec![
            Policy::IpFilter(IpFilterPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::SecHeaders(SecHeadersPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::RequestLimit(RequestLimitPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::Csrf(CsrfPolicy::from_config(serde_json::json!({"secret_key": "s"})).unwrap()),
            Policy::Ddos(DdosPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::Sri(SriPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::Expression(
                ExpressionPolicy::from_config(serde_json::json!({"expression": "true"})).unwrap(),
            ),
            Policy::Assertion(
                AssertionPolicy::from_config(serde_json::json!({"expression": "true"})).unwrap(),
            ),
        ];

        let expected_names = [
            "IpFilter",
            "SecHeaders",
            "RequestLimit",
            "Csrf",
            "Ddos",
            "Sri",
            "Expression",
            "Assertion",
        ];

        for (policy, name) in variants.iter().zip(expected_names.iter()) {
            let debug = format!("{:?}", policy);
            assert!(debug.contains(name), "debug for {} missing", name);
        }
    }

    // --- AssertionPolicy evaluate tests ---

    #[test]
    fn assertion_evaluate_passing() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status == 200",
            "name": "status_ok"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "GET",
            "/api/data",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        assert!(result, "assertion should pass when status is 200");
    }

    #[test]
    fn assertion_evaluate_failing() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status < 400",
            "name": "no_errors"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "GET",
            "/api/data",
            &req_headers,
            None,
            None,
            "example.com",
            500,
            &resp_headers,
            None,
        );
        assert!(!result, "assertion should fail when status is 500");
    }

    #[test]
    fn assertion_evaluate_with_response_headers() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": r#"response.headers["content-type"] == "application/json""#,
            "name": "json_content_type"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let mut resp_headers = http::HeaderMap::new();
        resp_headers.insert("content-type", "application/json".parse().unwrap());
        let result = policy.evaluate(
            "GET",
            "/api/data",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        assert!(result, "assertion should pass with matching content-type");
    }

    #[test]
    fn assertion_evaluate_invalid_expression_fails_open() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "this is not valid CEL !!!",
            "name": "bad_expression"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "GET",
            "/",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        assert!(result, "invalid expression should fail open (return true)");
    }

    #[test]
    fn assertion_evaluate_combined_request_response() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": r#"request.method == "POST" && response.status == 201"#,
            "name": "post_created"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "POST",
            "/api/users",
            &req_headers,
            None,
            None,
            "example.com",
            201,
            &resp_headers,
            None,
        );
        assert!(result, "assertion should pass for POST returning 201");

        // Same assertion but with wrong status
        let result = policy.evaluate(
            "POST",
            "/api/users",
            &req_headers,
            None,
            None,
            "example.com",
            400,
            &resp_headers,
            None,
        );
        assert!(!result, "assertion should fail for POST returning 400");
    }

    // --- BotDetection tests ---

    #[test]
    fn bot_detection_from_config() {
        let json = serde_json::json!({
            "enabled": true,
            "mode": "block",
            "deny_list": ["badcrawler", "evilbot"],
            "allow_list": ["goodbot"]
        });
        let bot = BotDetection::from_config(json).unwrap();
        assert!(bot.enabled);
        assert_eq!(bot.deny_list, vec!["badcrawler", "evilbot"]);
        assert_eq!(bot.allow_list, vec!["goodbot"]);
    }

    #[test]
    fn bot_detection_blocks_denied_ua() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["badcrawler".to_string(), "evilbot".to_string()],
            allow_list: vec![],
        };
        assert!(!bot.check_user_agent("badcrawler/1.0"));
        assert!(!bot.check_user_agent("evilbot/2.0"));
        assert!(!bot.check_user_agent("Mozilla/5.0 badcrawler"));
    }

    #[test]
    fn bot_detection_allows_normal_ua() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["badcrawler".to_string()],
            allow_list: vec![],
        };
        assert!(bot.check_user_agent("Mozilla/5.0"));
        assert!(bot.check_user_agent("curl/7.68.0"));
    }

    #[test]
    fn bot_detection_allow_list_overrides_deny() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["bot".to_string()],
            allow_list: vec!["goodbot".to_string()],
        };
        // "goodbot" matches the allow list, so it passes even though "bot" is denied.
        assert!(bot.check_user_agent("goodbot/1.0"));
        // "badbot" does NOT match the allow list, and "bot" is denied.
        assert!(!bot.check_user_agent("badbot/1.0"));
    }

    #[test]
    fn bot_detection_case_insensitive() {
        let bot = BotDetection {
            enabled: true,
            mode: Some("block".to_string()),
            deny_list: vec!["BadCrawler".to_string()],
            allow_list: vec![],
        };
        assert!(!bot.check_user_agent("BADCRAWLER/1.0"));
        assert!(!bot.check_user_agent("badcrawler/1.0"));
    }

    #[test]
    fn bot_detection_disabled_allows_all() {
        let bot = BotDetection {
            enabled: false,
            mode: None,
            deny_list: vec!["badcrawler".to_string()],
            allow_list: vec![],
        };
        assert!(bot.check_user_agent("badcrawler/1.0"));
    }

    // --- ThreatProtection tests ---

    #[test]
    fn threat_protection_from_config() {
        let json = serde_json::json!({
            "enabled": true,
            "json": {
                "max_depth": 3,
                "max_keys": 5,
                "max_string_length": 50,
                "max_array_size": 3,
                "max_total_size": 512
            }
        });
        let tp = ThreatProtection::from_config(json).unwrap();
        assert!(tp.enabled);
        let jc = tp.json.as_ref().unwrap();
        assert_eq!(jc.max_depth, Some(3));
        assert_eq!(jc.max_keys, Some(5));
    }

    #[test]
    fn threat_protection_passes_normal_json() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: Some(3),
                max_keys: Some(5),
                max_string_length: Some(50),
                max_array_size: Some(3),
                max_total_size: Some(512),
            }),
        };
        let body = br#"{"a": 1, "b": 2}"#;
        assert!(tp.check_json_body(body).is_ok());
    }

    #[test]
    fn threat_protection_blocks_deep_json() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: Some(3),
                max_keys: None,
                max_string_length: None,
                max_array_size: None,
                max_total_size: None,
            }),
        };
        let body = br#"{"a":{"b":{"c":{"d":{"e":"too deep"}}}}}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("depth"));
    }

    #[test]
    fn threat_protection_blocks_too_many_keys() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: Some(5),
                max_string_length: None,
                max_array_size: None,
                max_total_size: None,
            }),
        };
        let body = br#"{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("keys"));
    }

    #[test]
    fn threat_protection_blocks_long_string() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: None,
                max_string_length: Some(10),
                max_array_size: None,
                max_total_size: None,
            }),
        };
        let body = br#"{"msg":"this is a very long string that exceeds the limit"}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("string length"));
    }

    #[test]
    fn threat_protection_blocks_large_array() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: None,
                max_string_length: None,
                max_array_size: Some(2),
                max_total_size: None,
            }),
        };
        let body = br#"{"arr": [1, 2, 3, 4]}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("array"));
    }

    #[test]
    fn threat_protection_blocks_oversized_body() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: None,
                max_string_length: None,
                max_array_size: None,
                max_total_size: Some(10),
            }),
        };
        let body = br#"{"a": 1, "b": 2, "c": 3}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("body size"));
    }

    #[test]
    fn threat_protection_disabled_allows_all() {
        let tp = ThreatProtection {
            enabled: false,
            json: Some(JsonThreatConfig {
                max_depth: Some(1),
                max_keys: Some(1),
                max_string_length: Some(1),
                max_array_size: Some(1),
                max_total_size: Some(1),
            }),
        };
        let body = br#"{"a":{"b":{"c":"deep"}}, "x": [1,2,3]}"#;
        assert!(tp.check_json_body(body).is_ok());
    }

    // --- WafPolicy JS custom rule tests ---

    fn make_header_map(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn waf_js_rule_blocks_malicious_user_agent() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-ua-check",
                    "js_script": r#"
                        function match(request) {
                            const ua = request.header("user-agent") || "";
                            return ua.includes("malicious-bot");
                        }
                    "#,
                    "message": "blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[("user-agent", "malicious-bot/1.0")]);
        let result = policy.check_request("/api", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_allows_safe_user_agent() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-ua-check",
                    "js_script": r#"
                        function match(request) {
                            const ua = request.header("user-agent") || "";
                            return ua.includes("malicious-bot");
                        }
                    "#,
                    "message": "blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[("user-agent", "Mozilla/5.0 (safe browser)")]);
        let result = policy.check_request("/api", &headers, None);
        assert!(matches!(result, WafResult::Clean));
    }

    #[test]
    fn waf_js_rule_via_engine_field_blocks() {
        // Alternative config: engine: "javascript" + script field
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-uri-check",
                    "engine": "javascript",
                    "script": r#"
                        function match(request) {
                            return request.uri.includes("../");
                        }
                    "#,
                    "message": "path traversal blocked by JS"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/etc/../passwd", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_body_check_blocks() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-body-check",
                    "js_script": r#"
                        function match(request) {
                            const body = request.body || "";
                            return body.includes("<script>");
                        }
                    "#,
                    "message": "XSS blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/submit", &headers, Some("<script>alert(1)</script>"));
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_body_check_allows_clean() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-body-check",
                    "js_script": r#"
                        function match(request) {
                            const body = request.body || "";
                            return body.includes("<script>");
                        }
                    "#,
                    "message": "XSS blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/submit", &headers, Some("clean input data"));
        assert!(matches!(result, WafResult::Clean));
    }

    #[test]
    fn waf_lua_and_js_rules_can_coexist() {
        // A WAF policy with one Lua rule and one JS rule
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "lua-check",
                    "lua_script": r#"
                        function match(request)
                            local ua = request:header("user-agent") or ""
                            return ua:find("evilbot") ~= nil
                        end
                    "#,
                    "message": "lua: blocked"
                },
                {
                    "id": "js-check",
                    "js_script": r#"
                        function match(request) {
                            return request.uri.includes("/admin");
                        }
                    "#,
                    "message": "js: blocked admin"
                }
            ]
        }))
        .unwrap();

        // JS rule blocks /admin
        let headers = make_header_map(&[("user-agent", "Mozilla/5.0")]);
        let result = policy.check_request("/admin/panel", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));

        // Neither rule matches for clean request
        let result = policy.check_request("/api/users", &headers, None);
        assert!(matches!(result, WafResult::Clean));
    }

    // --- Paranoia level tests ---

    /// Default paranoia is 1 when no field is set on the policy.
    #[test]
    fn waf_default_paranoia_is_one() {
        let policy = WafPolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(policy.effective_paranoia(), 1);
    }

    /// Top-level `paranoia` overrides the nested CRS field for back-compat.
    #[test]
    fn waf_top_level_paranoia_wins_over_owasp_crs() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 3,
            "owasp_crs": { "enabled": true, "paranoia_level": 1 },
        }))
        .unwrap();
        assert_eq!(policy.effective_paranoia(), 3);
    }

    /// `owasp_crs.paranoia_level` is honored when the top-level field is unset.
    #[test]
    fn waf_owasp_crs_paranoia_level_used_as_fallback() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true, "paranoia_level": 2 },
        }))
        .unwrap();
        assert_eq!(policy.effective_paranoia(), 2);
    }

    /// Out-of-range values clamp into the 1-4 window.
    #[test]
    fn waf_paranoia_clamps_to_valid_range() {
        let high = WafPolicy::from_config(serde_json::json!({ "paranoia": 99 })).unwrap();
        assert_eq!(high.effective_paranoia(), 4);
        let low = WafPolicy::from_config(serde_json::json!({ "paranoia": 0 })).unwrap();
        assert_eq!(low.effective_paranoia(), 1);
    }

    /// Built-in stricter SQLi pattern (paranoia=2) does not fire at paranoia=1.
    #[test]
    fn waf_strict_sqli_pattern_skipped_at_paranoia_one() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true },
            "paranoia": 1,
            "action_on_match": "block",
        }))
        .unwrap();

        // Payload only matches SQLI_STRICT_PATTERN (paranoia=2), not the
        // baseline SQLI_PATTERN, XSS_PATTERN, or PATH_TRAVERSAL_PATTERN.
        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?q=BENCHMARK(1000000,sha1(1))", &headers, None);
        assert!(
            matches!(result, WafResult::Clean),
            "paranoia=1 must skip strict-only signatures, got {:?}",
            std::mem::discriminant(&result)
        );
    }

    /// Same payload triggers when paranoia is raised to 2.
    #[test]
    fn waf_strict_sqli_pattern_fires_at_paranoia_two() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true },
            "paranoia": 2,
            "action_on_match": "block",
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?q=BENCHMARK(1000000,sha1(1))", &headers, None);
        assert!(
            matches!(result, WafResult::Blocked(_)),
            "paranoia=2 must run strict signatures"
        );
    }

    /// Custom rules without a paranoia attribute always run (default=1).
    #[test]
    fn waf_custom_rule_default_paranoia_always_runs() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 1,
            "custom_rules": [
                {
                    "id": "default-paranoia",
                    "operator": "contains",
                    "pattern": "/forbidden",
                    "action": "block",
                    "message": "default paranoia rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/forbidden/path", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    /// Custom rule tagged paranoia=3 is suppressed when policy paranoia=1.
    #[test]
    fn waf_high_paranoia_custom_rule_skipped_at_low_policy_paranoia() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 1,
            "custom_rules": [
                {
                    "id": "noisy-rule",
                    "paranoia": 3,
                    "operator": "contains",
                    "pattern": "edge-case",
                    "action": "block",
                    "message": "edge case"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?x=edge-case", &headers, None);
        assert!(
            matches!(result, WafResult::Clean),
            "paranoia=3 rule must not run at policy paranoia=1"
        );
    }

    /// Same custom rule fires once policy paranoia is raised.
    #[test]
    fn waf_high_paranoia_custom_rule_fires_at_matching_policy_paranoia() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 3,
            "custom_rules": [
                {
                    "id": "noisy-rule",
                    "paranoia": 3,
                    "operator": "contains",
                    "pattern": "edge-case",
                    "action": "block",
                    "message": "edge case"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?x=edge-case", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    // --- ExpressionPolicy with aipref (G4.9) ---

    #[test]
    fn expression_policy_evaluate_with_aipref_train_false() {
        let p = ExpressionPolicy {
            expression: "request.aipref.train == false".to_string(),
            deny_status: 403,
            deny_message: "x".to_string(),
        };
        let signal = AiprefSignal {
            train: false,
            search: true,
            ai_input: true,
        };
        let result = p.evaluate_with_aipref(
            "GET",
            "/",
            &http::HeaderMap::new(),
            None,
            None,
            "h.com",
            Some(&signal),
        );
        assert!(
            result,
            "expression `request.aipref.train == false` must evaluate to true when train=false"
        );
    }

    #[test]
    fn expression_policy_evaluate_with_aipref_default_permissive() {
        let p = ExpressionPolicy {
            expression: "request.aipref.train == true".to_string(),
            deny_status: 403,
            deny_message: "x".to_string(),
        };
        let result = p.evaluate_with_aipref(
            "GET",
            "/",
            &http::HeaderMap::new(),
            None,
            None,
            "h.com",
            None,
        );
        assert!(
            result,
            "absent aipref signal must default-permissive (train == true)"
        );
    }
}
