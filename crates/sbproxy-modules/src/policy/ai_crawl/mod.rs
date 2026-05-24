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
//! enabled, `HttpLedger` talks to a network-callable backend (HMAC-signed,
//! idempotent, retried, circuit-broken).
//!
//! When the `tiered-pricing` feature is enabled, [`AiCrawlControlConfig`]
//! accepts a `tiers:` list with per-route pricing, per-shape pricing, a
//! free-preview byte budget, and a paywall position hint per
//! `docs/AIGOVERNANCE-BUILD.md` § G1.2.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

mod types;
pub use types::*;

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
        if matched_tier
            .as_ref()
            .map(|tier| tier.allows_free_preview())
            .unwrap_or(false)
        {
            return AiCrawlDecision::Allow;
        }
        if let Some(token) = headers
            .get(self.header.as_str())
            .and_then(|v| v.to_str().ok())
        {
            let token = token.trim();
            if !token.is_empty() {
                // WOR-75: time the redeem call so the
                // `sbproxy_ledger_redeem_duration_seconds` histogram
                // and its exemplar can land on every code path
                // (success, hard failure, transient failure). The
                // `outcome` label mirrors the three branches below so
                // dashboards can distinguish "slow ledger" from "slow
                // signature check".
                let redeem_started = std::time::Instant::now();
                let result =
                    self.ledger
                        .redeem(token, host, path, price.amount_micros, &price.currency);
                let outcome = match &result {
                    Ok(_) => "success",
                    Err(e) if e.retryable => "transient_failure",
                    Err(_) => "hard_failure",
                };
                sbproxy_observe::metrics::record_ledger_redeem_duration(
                    host,
                    outcome,
                    redeem_started.elapsed().as_secs_f64(),
                );
                match result {
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
            //
            // Thread the real route / rail / currency through; persistence
            // backends (the enterprise Postgres-backed store) stamp these
            // on the `quote_tokens` audit row so a recovery query can group
            // replay attempts by route at the price they were issued at.
            let _ = plan.nonce_store.register_with_context(
                &issued.claims.nonce,
                super::quote_token::NonceContext::new(path, rail_name, &price.currency),
            );
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
             sign per-rail quote tokens"
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
        resolve_secret_ref(sref, "ai_crawl_control.quote_token")?
    } else if let Some(inline) = &qt_yaml.seed_hex {
        inline.clone()
    } else {
        anyhow::bail!(
            "ai_crawl_control.quote_token requires either secret_ref.env, secret_ref.secret, or seed_hex (32-byte ed25519 seed, hex-encoded)"
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
        resolve_secret_ref(sref, "ai_crawl_control.ledger")?
    } else if let Some(ref inline) = yaml.key_hex {
        inline.clone()
    } else {
        anyhow::bail!(
            "ai_crawl_control.ledger requires either secret_ref.env, secret_ref.secret, or key_hex (hex-encoded HMAC key)"
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
mod http_ledger;

#[cfg(test)]
mod tests;
