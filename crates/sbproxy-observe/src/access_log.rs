//! Structured JSON access logs.
//!
//! Emits one JSON line per completed request with configurable fields.
//! Output goes to stdout via the tracing `access_log` target at info level.
//! Secrets in any field are redacted before emission.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::request_event::UserIdSource;

// --- Access log entry ---

/// A single access log record emitted after a request completes.
///
/// Optional fields are omitted from JSON output when `None`, keeping
/// log lines compact for non-AI traffic that has no token/model data.
///
/// Field set is intentionally broad: an off-line ML pipeline trains
/// on these lines for routing, anomaly detection, and abuse models.
/// New fields land here even when they only matter for one workflow,
/// because adding them later means re-mining historical traffic.
#[derive(Debug, Serialize)]
pub struct AccessLogEntry {
    /// RFC 3339 timestamp of when the response was sent.
    pub timestamp: String,
    /// Unique request identifier (UUIDv4 or propagated from upstream).
    pub request_id: String,
    /// Origin hostname that handled the request.
    pub origin: String,
    /// HTTP method (GET, POST, ...).
    pub method: String,
    /// Request path (without query string).
    pub path: String,
    /// HTTP response status code.
    pub status: u16,
    /// End-to-end latency in milliseconds (wall time).
    pub latency_ms: f64,
    /// Bytes received from the client (request body + headers).
    pub bytes_in: u64,
    /// Bytes sent to the client (response body + headers).
    pub bytes_out: u64,
    /// Client IP address (post-forwarding-header resolution).
    pub client_ip: String,
    /// AI provider name when the origin is an AI gateway route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// AI model identifier selected for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Prompt / input tokens consumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_in: Option<u64>,
    /// Completion / output tokens generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_out: Option<u64>,
    /// W3C trace-id for distributed tracing correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Cache result: "hit", "miss", "stale", or "bypass".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_result: Option<String>,

    // --- Wave 8 envelope linkage ---
    /// Wave 8 envelope ULID (`docs/adr-event-envelope.md`). Distinct
    /// from `request_id` (UUIDv4); the ULID feeds the typed envelope
    /// stream and the access log so portal queries can join the two
    /// sources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_request_id: Option<String>,
    /// Resolved end-user identifier (header / JWT `sub` / forward-auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Where `user_id` came from (`header`, `jwt`, `forward_auth`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id_source: Option<UserIdSource>,
    /// Session identifier (caller-supplied or auto-generated for
    /// anonymous traffic per the Wave 8 ADR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Parent session identifier; never auto-generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    /// Caller-supplied custom properties from `X-Sb-Property-*`
    /// headers, after caps and redaction. Empty when capture is off
    /// or no headers were sent.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub properties: BTreeMap<String, String>,

    // --- Routing + behavior ---
    /// Tenant / workspace owner. Stays empty for the OSS single-tenant
    /// default workspace; enterprise multi-tenant deployments stamp
    /// the resolved tenant.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub workspace_id: String,
    /// Authentication scheme that produced the auth decision
    /// (`api_key`, `basic_auth`, `jwt`, `forward_auth`, `oauth`,
    /// `noop`, ...). Absent when no auth was configured for the
    /// origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// True when this request was served from cache (hot or reserve)
    /// without contacting the upstream. Mirrors `cache_result == "hit"`
    /// but distinguishes hit-then-revalidated paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub served_from_cache: Option<bool>,
    /// True when the primary upstream failed and the fallback
    /// path served the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_triggered: Option<bool>,
    /// Number of upstream retries attempted before this terminal
    /// outcome. `0` means the original attempt succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,
    /// Forward rule index that matched the request. `None` when the
    /// origin's primary action handled the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_rule_idx: Option<usize>,

    // --- Geographic + classifier signal ---
    /// ISO-3166-1 alpha-2 country code derived from `client_ip` by
    /// the optional geo-enrichment policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_geo: Option<String>,
    /// Prompt classifier verdict label (e.g. `safe`, `injection`,
    /// `pii`, `toxic`). Stable strings only; raw scores live on the
    /// envelope event, not the access log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classifier_prompt: Option<String>,
    /// Detected intent category (e.g. `coding`, `vision`, `analysis`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classifier_intent: Option<String>,

    // --- Failure classification ---
    /// Compact failure label when the request did not return a 2xx
    /// (e.g. `auth_denied`, `rate_limited`, `waf_blocked`,
    /// `upstream_5xx`, `upstream_timeout`, `validator_failed`).
    /// `None` for successful requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,

    // --- Wave 1 / G1.6 per-agent dimensions ---
    /// Stable agent identifier from the agent-class catalog (e.g.
    /// `openai-gptbot`, `anthropic-claudebot`) or one of the reserved
    /// sentinels (`human`, `anonymous`, `unknown`). `None` when the
    /// resolver has not run for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// `agent_class` from the catalog (e.g. `training`, `search`,
    /// `assistant`) or matching sentinel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_class: Option<String>,
    /// `agent_vendor` from the catalog (e.g. `OpenAI`, `Anthropic`)
    /// or matching sentinel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_vendor: Option<String>,
    /// Closed enum: `none`, `x402`, `mpp_card`, `mpp_stablecoin`,
    /// `stripe_fiat`, `lightning`. `None` when the request did not
    /// hit a payment-rail decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_rail: Option<String>,
    /// Closed enum: `html`, `markdown`, `json`, `pdf`, `other`.
    /// `None` when the response shape was not classified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_shape: Option<String>,

    // --- Wave 6 / G6.2 access log v1 fields ---
    //
    // Per `adr-licensing-cap.md`, `adr-licensing-olp.md`, and the Wave 3
    // quote-token / multi-rail 402 ADRs. These let the access log
    // attribute every request to the tier it matched, the price quoted,
    // the rail that settled (if any), the quote/license/CAP token IDs
    // presented, and the on-chain hash for crypto rails.
    /// Pricing tier the request matched (`free`, `commercial`, `bot`,
    /// or any operator-defined name from the `ai_crawl_control` policy).
    /// `None` when no tier resolver fired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Response shape the body transformer ran (Markdown / JSON / HTML
    /// / PDF / other). Mirrors `RequestContext.content_shape_transform`.
    /// Distinct from `content_shape` which is the pricing-pass shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    /// Quote price in micro-units of `currency` (e.g. `1500` with
    /// `currency = "USD"` is $0.0015). `None` when the request did not
    /// receive a priced quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<u64>,
    /// ISO 4217 fiat currency or rail-specific code (e.g. `"USD"`,
    /// `"USDC"`, `"BTC-msat"`). `None` when no quote was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Billing rail that settled the request (`x402`, `mpp_card`,
    /// `mpp_stablecoin`, `stripe_fiat`, `lightning`). `None` for
    /// unsettled / free traffic. Distinct from `payment_rail` (which
    /// records the rail decision); `rail` records the actual settler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    /// `jti` of the quote token presented and redeemed for this request,
    /// per Wave 3 `adr-quote-token-jws.md` (A3.2). `None` when no quote
    /// token was redeemed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeemed_token_id: Option<String>,
    /// On-chain settlement hash when the rail produced one (x402,
    /// Lightning preimage hash, MPP stablecoin tx). `None` for fiat
    /// rails or unsettled traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txhash: Option<String>,
    /// `jti` of the OLP license token presented per
    /// `adr-licensing-olp.md` (A6.1). `None` when no license token was
    /// presented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_token_id: Option<String>,
    /// `jti` of the CAP token presented per `adr-licensing-cap.md`
    /// (A6.2). `None` when no CAP token was presented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_token_id: Option<String>,
    /// Resolved upstream host the request was proxied to. `None` for
    /// short-circuited requests (auth deny, WAF block, cache hit) that
    /// never contacted an upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_host: Option<String>,

    // --- G6.4 captured headers ---
    /// Request headers captured under the
    /// `access_log.capture_headers.request` allowlist. Names are
    /// lowercased; values are truncated to the configured byte cap and
    /// optionally PII-redacted. Empty (and absent from the JSON line)
    /// when capture is off or no allowlisted headers were present on
    /// the request.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub request_headers: BTreeMap<String, String>,
    /// Response headers captured under the
    /// `access_log.capture_headers.response` allowlist. Same shape and
    /// semantics as [`Self::request_headers`].
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub response_headers: BTreeMap<String, String>,
}

impl AccessLogEntry {
    /// Emit this entry as a JSON line via tracing at INFO level.
    ///
    /// Secrets are redacted before the line is written. The tracing target
    /// `access_log` allows log routers to separate access logs from
    /// application logs.
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            let redacted = crate::redact::redact_secrets(&json);
            tracing::info!(target: "access_log", "{}", redacted);
        }
    }

    /// Start an [`AccessLogEntryBuilder`] for incremental field
    /// stamping as the request flows through the pipeline.
    ///
    /// `request_id`, `method`, `path`, and `origin` are typically known
    /// at request-filter time; later fields (status, latency, token
    /// IDs, settlement metadata) are stamped as they become available.
    /// The actual log write happens at request completion via
    /// [`AccessLogEntryBuilder::emit`] or [`AccessLogEntryBuilder::build`]
    /// + [`AccessLogEntry::emit`].
    pub fn builder() -> AccessLogEntryBuilder {
        AccessLogEntryBuilder::default()
    }
}

// --- Access log entry builder ---

/// Incremental builder for [`AccessLogEntry`].
///
/// Wave 6 / G6.2 surface. Call sites stamp fields as a request flows
/// through the pipeline (request filter, auth, action, response filter)
/// and call [`Self::emit`] once at request completion.
///
/// The builder defaults every field to its zero / `None` value so a
/// caller that only knows part of the request's metadata still produces
/// a valid entry. The required scalar fields (`timestamp`,
/// `request_id`, `method`, `path`, `origin`, `status`, `latency_ms`,
/// `bytes_in`, `bytes_out`, `client_ip`) default to placeholder values
/// (`""` strings, `0` numbers); typical call sites stamp them via
/// [`Self::request_id`], [`Self::method`], etc., before [`Self::emit`].
#[derive(Debug, Default)]
pub struct AccessLogEntryBuilder {
    inner: AccessLogEntry,
}

impl Default for AccessLogEntry {
    fn default() -> Self {
        Self {
            timestamp: String::new(),
            request_id: String::new(),
            origin: String::new(),
            method: String::new(),
            path: String::new(),
            status: 0,
            latency_ms: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            client_ip: String::new(),
            provider: None,
            model: None,
            tokens_in: None,
            tokens_out: None,
            trace_id: None,
            cache_result: None,
            envelope_request_id: None,
            user_id: None,
            user_id_source: None,
            session_id: None,
            parent_session_id: None,
            properties: BTreeMap::new(),
            workspace_id: String::new(),
            auth_type: None,
            served_from_cache: None,
            fallback_triggered: None,
            retry_count: None,
            forward_rule_idx: None,
            request_geo: None,
            classifier_prompt: None,
            classifier_intent: None,
            error_class: None,
            agent_id: None,
            agent_class: None,
            agent_vendor: None,
            payment_rail: None,
            content_shape: None,
            tier: None,
            shape: None,
            price: None,
            currency: None,
            rail: None,
            redeemed_token_id: None,
            txhash: None,
            license_token_id: None,
            cap_token_id: None,
            upstream_host: None,
            request_headers: BTreeMap::new(),
            response_headers: BTreeMap::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
impl AccessLogEntryBuilder {
    // --- Required-shape stampers (request lifecycle) ---

    /// Set the RFC 3339 response timestamp.
    pub fn timestamp(mut self, ts: impl Into<String>) -> Self {
        self.inner.timestamp = ts.into();
        self
    }
    /// Set the request identifier (UUIDv4 or propagated upstream id).
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.inner.request_id = id.into();
        self
    }
    /// Set the origin hostname that handled the request.
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.inner.origin = origin.into();
        self
    }
    /// Set the HTTP method.
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.inner.method = method.into();
        self
    }
    /// Set the request path (without query string).
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.inner.path = path.into();
        self
    }
    /// Set the HTTP response status code.
    pub fn status(mut self, status: u16) -> Self {
        self.inner.status = status;
        self
    }
    /// Set end-to-end latency in milliseconds.
    pub fn latency_ms(mut self, ms: f64) -> Self {
        self.inner.latency_ms = ms;
        self
    }
    /// Set request body bytes received.
    pub fn bytes_in(mut self, bytes: u64) -> Self {
        self.inner.bytes_in = bytes;
        self
    }
    /// Set response body bytes sent.
    pub fn bytes_out(mut self, bytes: u64) -> Self {
        self.inner.bytes_out = bytes;
        self
    }
    /// Set client IP (post-forwarding-header resolution).
    pub fn client_ip(mut self, ip: impl Into<String>) -> Self {
        self.inner.client_ip = ip.into();
        self
    }

    // --- Wave 1 / G1.4 agent-class fields ---

    /// Set the resolved agent identifier from G1.4.
    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.inner.agent_id = Some(agent_id.into());
        self
    }
    /// Set the agent class label.
    pub fn agent_class(mut self, agent_class: impl Into<String>) -> Self {
        self.inner.agent_class = Some(agent_class.into());
        self
    }
    /// Set the agent vendor display name.
    pub fn agent_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.inner.agent_vendor = Some(vendor.into());
        self
    }

    // --- Wave 6 / G6.2 commerce fields ---

    /// Set the matched pricing tier name.
    pub fn tier(mut self, tier: impl Into<String>) -> Self {
        self.inner.tier = Some(tier.into());
        self
    }
    /// Set the response body shape (Markdown / JSON / HTML / PDF / other).
    pub fn shape(mut self, shape: impl Into<String>) -> Self {
        self.inner.shape = Some(shape.into());
        self
    }
    /// Set the quote price in micro-units of `currency`.
    pub fn price(mut self, price: u64) -> Self {
        self.inner.price = Some(price);
        self
    }
    /// Set the quote currency (ISO 4217 or rail-specific code).
    pub fn currency(mut self, currency: impl Into<String>) -> Self {
        self.inner.currency = Some(currency.into());
        self
    }
    /// Set the billing rail that settled the request.
    pub fn rail(mut self, rail: impl Into<String>) -> Self {
        self.inner.rail = Some(rail.into());
        self
    }
    /// Set the redeemed quote-token jti.
    pub fn redeemed_token_id(mut self, jti: impl Into<String>) -> Self {
        self.inner.redeemed_token_id = Some(jti.into());
        self
    }
    /// Set the on-chain settlement hash.
    pub fn txhash(mut self, hash: impl Into<String>) -> Self {
        self.inner.txhash = Some(hash.into());
        self
    }
    /// Set the OLP license-token jti.
    pub fn license_token_id(mut self, jti: impl Into<String>) -> Self {
        self.inner.license_token_id = Some(jti.into());
        self
    }
    /// Set the CAP-token jti.
    pub fn cap_token_id(mut self, jti: impl Into<String>) -> Self {
        self.inner.cap_token_id = Some(jti.into());
        self
    }
    /// Set the resolved upstream host the request was proxied to.
    pub fn upstream_host(mut self, host: impl Into<String>) -> Self {
        self.inner.upstream_host = Some(host.into());
        self
    }

    // --- G6.4 captured headers ---

    /// Set the captured request headers (lowercased keys, truncated
    /// values). Replaces any previously stamped map.
    pub fn request_headers(mut self, headers: BTreeMap<String, String>) -> Self {
        self.inner.request_headers = headers;
        self
    }
    /// Set the captured response headers (lowercased keys, truncated
    /// values). Replaces any previously stamped map.
    pub fn response_headers(mut self, headers: BTreeMap<String, String>) -> Self {
        self.inner.response_headers = headers;
        self
    }

    /// Finalise the builder into an [`AccessLogEntry`] without writing.
    pub fn build(self) -> AccessLogEntry {
        self.inner
    }

    /// Finalise the builder and emit the entry as a JSON line via the
    /// `access_log` tracing target. Equivalent to
    /// [`Self::build`] + [`AccessLogEntry::emit`].
    pub fn emit(self) {
        self.build().emit();
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_entry() -> AccessLogEntry {
        AccessLogEntry {
            timestamp: "2026-04-16T12:00:00Z".to_string(),
            request_id: "abc123".to_string(),
            origin: "api.example.com".to_string(),
            method: "GET".to_string(),
            path: "/health".to_string(),
            status: 200,
            latency_ms: 3.5,
            bytes_in: 128,
            bytes_out: 512,
            client_ip: "10.0.0.1".to_string(),
            provider: None,
            model: None,
            tokens_in: None,
            tokens_out: None,
            trace_id: None,
            cache_result: None,
            envelope_request_id: None,
            user_id: None,
            user_id_source: None,
            session_id: None,
            parent_session_id: None,
            properties: BTreeMap::new(),
            workspace_id: String::new(),
            auth_type: None,
            served_from_cache: None,
            fallback_triggered: None,
            retry_count: None,
            forward_rule_idx: None,
            request_geo: None,
            classifier_prompt: None,
            classifier_intent: None,
            error_class: None,
            agent_id: None,
            agent_class: None,
            agent_vendor: None,
            payment_rail: None,
            content_shape: None,
            tier: None,
            shape: None,
            price: None,
            currency: None,
            rail: None,
            redeemed_token_id: None,
            txhash: None,
            license_token_id: None,
            cap_token_id: None,
            upstream_host: None,
            request_headers: BTreeMap::new(),
            response_headers: BTreeMap::new(),
        }
    }

    #[test]
    fn test_json_serialization_required_fields() {
        let entry = minimal_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["timestamp"], "2026-04-16T12:00:00Z");
        assert_eq!(v["request_id"], "abc123");
        assert_eq!(v["origin"], "api.example.com");
        assert_eq!(v["method"], "GET");
        assert_eq!(v["path"], "/health");
        assert_eq!(v["status"], 200);
        assert_eq!(v["bytes_in"], 128);
        assert_eq!(v["bytes_out"], 512);
        assert_eq!(v["client_ip"], "10.0.0.1");
    }

    #[test]
    fn test_optional_fields_omitted_when_none() {
        let entry = minimal_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(
            v.get("provider").is_none(),
            "provider should be absent when None"
        );
        assert!(v.get("model").is_none(), "model should be absent when None");
        assert!(
            v.get("tokens_in").is_none(),
            "tokens_in should be absent when None"
        );
        assert!(
            v.get("tokens_out").is_none(),
            "tokens_out should be absent when None"
        );
        assert!(
            v.get("trace_id").is_none(),
            "trace_id should be absent when None"
        );
        assert!(
            v.get("cache_result").is_none(),
            "cache_result should be absent when None"
        );
    }

    #[test]
    fn test_optional_fields_present_when_some() {
        let mut entry = minimal_entry();
        entry.provider = Some("openai".to_string());
        entry.model = Some("gpt-4o".to_string());
        entry.tokens_in = Some(100);
        entry.tokens_out = Some(250);
        entry.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string());
        entry.cache_result = Some("miss".to_string());

        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["provider"], "openai");
        assert_eq!(v["model"], "gpt-4o");
        assert_eq!(v["tokens_in"], 100);
        assert_eq!(v["tokens_out"], 250);
        assert_eq!(v["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(v["cache_result"], "miss");
    }

    #[test]
    fn test_latency_ms_precision() {
        let mut entry = minimal_entry();
        entry.latency_ms = 1.23456789;
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let lat = v["latency_ms"].as_f64().unwrap();
        assert!((lat - 1.23456789).abs() < 1e-6);
    }

    #[test]
    fn test_secrets_redacted_in_path() {
        // A path that embeds an API key in a query-like form should be redacted.
        let mut entry = minimal_entry();
        // sk-... key in the path field will be caught by the openai pattern.
        entry.path = "/v1/chat?api_key=sk-abcdefghijklmnopqrstu1234567890".to_string();

        // Serialise and manually redact (mirrors what emit() does internally).
        let json = serde_json::to_string(&entry).unwrap();
        let redacted = crate::redact::redact_secrets(&json);

        assert!(!redacted.contains("sk-abcdefghijklmnopqrstu1234567890"));
        assert!(redacted.contains("sk-[REDACTED]"));
    }

    #[test]
    fn test_bearer_in_client_ip_field_redacted() {
        // Ensure the redaction pass covers every field, not just obvious ones.
        let mut entry = minimal_entry();
        // Contrived but validates that redact_secrets is applied to the full JSON.
        entry.client_ip = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc".to_string();

        let json = serde_json::to_string(&entry).unwrap();
        let redacted = crate::redact::redact_secrets(&json);

        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(redacted.contains("Bearer [REDACTED]"));
    }

    #[test]
    fn test_agent_fields_serialise_when_present() {
        // Wave 1 / G1.6 typed agent fields. Confirm they round-trip
        // and stay absent when None (consistent with the rest of the
        // optional surface).
        let mut entry = minimal_entry();
        entry.agent_id = Some("openai-gptbot".to_string());
        entry.agent_class = Some("training".to_string());
        entry.agent_vendor = Some("openai".to_string());
        entry.payment_rail = Some("x402".to_string());
        entry.content_shape = Some("html".to_string());

        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["agent_id"], "openai-gptbot");
        assert_eq!(v["agent_class"], "training");
        assert_eq!(v["agent_vendor"], "openai");
        assert_eq!(v["payment_rail"], "x402");
        assert_eq!(v["content_shape"], "html");
    }

    #[test]
    fn test_agent_fields_omitted_when_none() {
        let entry = minimal_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("agent_id").is_none());
        assert!(v.get("agent_class").is_none());
        assert!(v.get("agent_vendor").is_none());
        assert!(v.get("payment_rail").is_none());
        assert!(v.get("content_shape").is_none());
    }

    #[test]
    fn test_all_cache_result_values_round_trip() {
        for result in &["hit", "miss", "stale", "bypass"] {
            let mut entry = minimal_entry();
            entry.cache_result = Some(result.to_string());
            let json = serde_json::to_string(&entry).unwrap();
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(v["cache_result"], *result);
        }
    }

    // --- Wave 6 / G6.2 v1 field tests ---

    #[test]
    fn test_g6_2_fields_omitted_when_none() {
        let entry = minimal_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        for field in &[
            "tier",
            "shape",
            "price",
            "currency",
            "rail",
            "redeemed_token_id",
            "txhash",
            "license_token_id",
            "cap_token_id",
            "upstream_host",
        ] {
            assert!(
                v.get(*field).is_none(),
                "expected `{field}` to be absent when None"
            );
        }
    }

    #[test]
    fn test_g6_2_fields_round_trip() {
        let mut entry = minimal_entry();
        entry.tier = Some("commercial".to_string());
        entry.shape = Some("markdown".to_string());
        entry.price = Some(1500);
        entry.currency = Some("USD".to_string());
        entry.rail = Some("x402".to_string());
        entry.redeemed_token_id = Some("01J7HZ8X9R3QUOTE".to_string());
        entry.txhash = Some("0xabc123".to_string());
        entry.license_token_id = Some("01J7HZ8X9R3LIC".to_string());
        entry.cap_token_id = Some("01J7HZ8X9R3CAP".to_string());
        entry.upstream_host = Some("origin.internal:8080".to_string());

        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tier"], "commercial");
        assert_eq!(v["shape"], "markdown");
        assert_eq!(v["price"], 1500);
        assert_eq!(v["currency"], "USD");
        assert_eq!(v["rail"], "x402");
        assert_eq!(v["redeemed_token_id"], "01J7HZ8X9R3QUOTE");
        assert_eq!(v["txhash"], "0xabc123");
        assert_eq!(v["license_token_id"], "01J7HZ8X9R3LIC");
        assert_eq!(v["cap_token_id"], "01J7HZ8X9R3CAP");
        assert_eq!(v["upstream_host"], "origin.internal:8080");
    }

    // --- Builder pattern ---

    #[test]
    fn test_builder_assembles_entry_incrementally() {
        let entry = AccessLogEntry::builder()
            .timestamp("2026-05-02T12:00:00Z")
            .request_id("req-1")
            .method("GET")
            .path("/article/42")
            .origin("api.example.com")
            .status(200)
            .latency_ms(7.25)
            .bytes_in(0)
            .bytes_out(2048)
            .client_ip("203.0.113.10")
            .agent_id("openai-gptbot")
            .agent_class("training")
            .agent_vendor("OpenAI")
            .tier("commercial")
            .shape("markdown")
            .price(1500)
            .currency("USD")
            .rail("x402")
            .redeemed_token_id("quote-1")
            .txhash("0xdeadbeef")
            .license_token_id("license-1")
            .cap_token_id("cap-1")
            .upstream_host("origin.internal:8080")
            .build();
        assert_eq!(entry.request_id, "req-1");
        assert_eq!(entry.tier.as_deref(), Some("commercial"));
        assert_eq!(entry.cap_token_id.as_deref(), Some("cap-1"));
    }

    #[test]
    fn test_builder_default_omits_optional_fields() {
        let entry = AccessLogEntry::builder()
            .timestamp("2026-05-02T12:00:00Z")
            .request_id("req-2")
            .method("GET")
            .path("/")
            .origin("api.example.com")
            .status(200)
            .latency_ms(1.0)
            .bytes_in(0)
            .bytes_out(0)
            .client_ip("203.0.113.10")
            .build();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Required fields present.
        assert_eq!(v["request_id"], "req-2");
        // G6.2 optional fields all absent.
        for field in &[
            "tier",
            "shape",
            "price",
            "currency",
            "rail",
            "redeemed_token_id",
            "txhash",
            "license_token_id",
            "cap_token_id",
            "upstream_host",
            "agent_id",
        ] {
            assert!(
                v.get(*field).is_none(),
                "expected `{field}` to be absent on a default builder"
            );
        }
    }

    // --- Redaction denylist (A1.5) ---

    #[test]
    fn test_a1_5_authorization_header_never_appears_in_emitted_json() {
        // A1.5: Authorization header values must never appear in the
        // emitted access-log line. The redactor catches both Bearer and
        // Basic schemes; any other scheme that happens to be carried
        // here is acceptable as long as the secret material is masked.
        let mut entry = minimal_entry();
        // Stamp a real-looking Bearer token into the path (the same
        // class of leak the redactor must catch even if a caller
        // accidentally includes the header value in a logged field).
        entry.path = "/admin?Authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
            .to_string();
        // And a Basic credential elsewhere.
        entry.upstream_host = Some("Basic dXNlcjpwYXNzd29yZA==".to_string());
        let json = serde_json::to_string(&entry).unwrap();
        let redacted = crate::redact::redact_secrets(&json);
        assert!(
            !redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"),
            "raw bearer token leaked into emitted line"
        );
        assert!(
            !redacted.contains("dXNlcjpwYXNzd29yZA=="),
            "basic credential leaked into emitted line"
        );
        assert!(redacted.contains("Bearer [REDACTED]"));
        assert!(redacted.contains("Basic [REDACTED]"));
    }

    // --- Snapshot: representative G6.2 request shape ---

    #[test]
    fn test_g6_2_snapshot_representative_shape() {
        // Stable JSON shape for a representative paid agent crawl that
        // settled on x402 with a CAP token authorising the route. Field
        // order follows serde's struct order; if we shuffle the struct
        // this test will fail and remind us to update consumers.
        let entry = AccessLogEntry::builder()
            .timestamp("2026-05-02T12:00:00Z")
            .request_id("req-snap-1")
            .origin("api.example.com")
            .method("GET")
            .path("/articles/42")
            .status(200)
            .latency_ms(8.5)
            .bytes_in(0)
            .bytes_out(2048)
            .client_ip("203.0.113.10")
            .agent_id("openai-gptbot")
            .agent_class("training")
            .agent_vendor("OpenAI")
            .tier("commercial")
            .shape("markdown")
            .price(1500)
            .currency("USD")
            .rail("x402")
            .redeemed_token_id("quote-1")
            .txhash("0xdeadbeef")
            .license_token_id("license-1")
            .cap_token_id("cap-1")
            .upstream_host("origin.internal:8080")
            .build();
        let json = serde_json::to_string(&entry).unwrap();
        let expected = "{\"timestamp\":\"2026-05-02T12:00:00Z\",\"request_id\":\"req-snap-1\",\"origin\":\"api.example.com\",\"method\":\"GET\",\"path\":\"/articles/42\",\"status\":200,\"latency_ms\":8.5,\"bytes_in\":0,\"bytes_out\":2048,\"client_ip\":\"203.0.113.10\",\"agent_id\":\"openai-gptbot\",\"agent_class\":\"training\",\"agent_vendor\":\"OpenAI\",\"tier\":\"commercial\",\"shape\":\"markdown\",\"price\":1500,\"currency\":\"USD\",\"rail\":\"x402\",\"redeemed_token_id\":\"quote-1\",\"txhash\":\"0xdeadbeef\",\"license_token_id\":\"license-1\",\"cap_token_id\":\"cap-1\",\"upstream_host\":\"origin.internal:8080\"}";
        assert_eq!(json, expected);
    }

    // --- G6.4 captured-header field tests ---

    #[test]
    fn captured_header_fields_omitted_when_empty() {
        let entry = minimal_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("request_headers").is_none(),
            "request_headers absent when empty"
        );
        assert!(
            v.get("response_headers").is_none(),
            "response_headers absent when empty"
        );
    }

    #[test]
    fn captured_header_fields_serialise_when_populated() {
        let mut req = BTreeMap::new();
        req.insert("user-agent".to_string(), "curl/8.0".to_string());
        req.insert("referer".to_string(), "https://example.com".to_string());
        let mut resp = BTreeMap::new();
        resp.insert("x-cache".to_string(), "HIT".to_string());

        let entry = AccessLogEntry::builder()
            .timestamp("2026-05-04T00:00:00Z")
            .request_id("req-h-1")
            .origin("api.example.com")
            .method("GET")
            .path("/foo")
            .status(200)
            .latency_ms(2.0)
            .bytes_in(0)
            .bytes_out(0)
            .client_ip("1.2.3.4")
            .request_headers(req)
            .response_headers(resp)
            .build();

        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["request_headers"]["user-agent"], "curl/8.0");
        assert_eq!(v["request_headers"]["referer"], "https://example.com");
        assert_eq!(v["response_headers"]["x-cache"], "HIT");
    }
}
