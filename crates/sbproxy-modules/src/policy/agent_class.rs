//! Agent-class resolver (G1.4) and the OSS policy that wraps it.
//!
//! The resolver chain is:
//!
//! 1. **Web Bot Auth** verified `keyid` matches a catalog entry => highest confidence.
//! 2. **Reverse-DNS** forward-confirms against a catalog entry's expected suffix => strong confidence.
//! 3. **User-Agent** regex matches a catalog entry => advisory.
//! 4. Anonymous Web Bot Auth signature with no matching `keyid` => emit `anonymous`.
//! 5. UA matched a generic crawler heuristic => emit `unknown`.
//! 6. None of the above => emit `human`.
//!
//! See `docs/adr-agent-class-taxonomy.md` for the full ordering rationale.
//!
//! The resolver is split from the `RequestContext` so the same
//! resolution logic feeds the OSS request pipeline, the enterprise
//! webhook envelope, and offline analyses (e.g. log replay).
//!
//! # The `agent_class` policy (G1.4 wire)
//!
//! [`AgentClassPolicy`] is the YAML-addressable policy operators write
//! into `policies: - type: agent_class`. It is intentionally thin: the
//! actual resolver runs earlier in `request_filter` (the
//! `core::agent_class::stamp_request_context` seam) using the
//! [`AgentClassResolver`] the binary builds at startup from the
//! top-level `agent_classes:` block. This policy stamps the resolved
//! verdict onto upstream request headers when `forward_to_upstream`
//! is true.

use std::net::IpAddr;
use std::sync::Arc;

use sbproxy_classifiers::{AgentClass, AgentClassCatalog, AgentId, AgentIdSource, AgentPurpose};
use sbproxy_security::agent_verify::{
    verify_reverse_dns, Resolver, ReverseDnsCache, ReverseDnsVerdict,
};

// --- Public API ---

/// Inputs to the resolver. The resolver is pure: every piece of state
/// it needs is plumbed through here so the same call yields the same
/// answer. Callers populate the inputs at request entry, after auth
/// has produced a verified `keyid` (when present).
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolveInputs<'a> {
    /// Verified Web Bot Auth `keyid` (RFC 9421 `Signature-Input`
    /// `keyid` parameter), already cryptographically verified by
    /// `sbproxy-modules::auth::bot_auth`. Pass `None` when no
    /// signature was present or verification failed.
    pub bot_auth_keyid: Option<&'a str>,
    /// Set to `true` when a Web Bot Auth signature was present and
    /// cryptographically valid but advertised a `keyid` that no
    /// catalog entry recognises. Drives the `anonymous` verdict.
    pub anonymous_bot_auth: bool,
    /// Client IP from the trusted-boundary peer. `None` skips rDNS.
    pub client_ip: Option<IpAddr>,
    /// `User-Agent` header value, untrusted. `None` or empty skips
    /// the UA regex pass and the generic-crawler heuristic.
    pub user_agent: Option<&'a str>,
}

/// Output of [`Resolver`]. `agent_id` is one of the three reserved
/// sentinels (`human`, `anonymous`, `unknown`) or a catalog `id`.
/// The catalog entry, when present, surfaces the vendor display
/// string and bounded purpose enum for downstream consumers.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// Resolved [`AgentId`] (sentinel or catalog `id`).
    pub agent_id: AgentId,
    /// Operator display name. `"unknown"` for sentinels.
    pub vendor: String,
    /// Operator-stated purpose. [`AgentPurpose::Unknown`] for sentinels.
    pub purpose: AgentPurpose,
    /// Diagnostic stamp for which signal in the chain matched.
    pub source: AgentIdSource,
    /// Optional rDNS hostname when [`AgentIdSource::Rdns`] matched.
    pub rdns_hostname: Option<String>,
}

impl Resolved {
    /// Build the `human` fallthrough verdict.
    pub fn human() -> Self {
        Self {
            agent_id: AgentId::human(),
            vendor: "unknown".to_string(),
            purpose: AgentPurpose::Unknown,
            source: AgentIdSource::Fallback,
            rdns_hostname: None,
        }
    }

    /// Build the `anonymous` verdict (Web Bot Auth, no matching keyid).
    pub fn anonymous() -> Self {
        Self {
            agent_id: AgentId::anonymous(),
            vendor: "unknown".to_string(),
            purpose: AgentPurpose::Unknown,
            source: AgentIdSource::AnonymousBotAuth,
            rdns_hostname: None,
        }
    }

    /// Build the `unknown` verdict (looks like a bot but no entry caught it).
    pub fn unknown_bot() -> Self {
        Self {
            agent_id: AgentId::unknown(),
            vendor: "unknown".to_string(),
            purpose: AgentPurpose::Unknown,
            source: AgentIdSource::Fallback,
            rdns_hostname: None,
        }
    }

    /// Build a verdict from a matched catalog entry plus the source
    /// signal that produced it.
    pub fn from_match(
        entry: &AgentClass,
        source: AgentIdSource,
        rdns_hostname: Option<String>,
    ) -> Self {
        Self {
            agent_id: AgentId(entry.id.clone()),
            vendor: entry.vendor.clone(),
            purpose: entry.purpose,
            source,
            rdns_hostname,
        }
    }
}

/// Stateful resolver that owns the catalog, the rDNS verdict cache,
/// and the [`Resolver`] DNS port.
pub struct AgentClassResolver {
    catalog: Arc<AgentClassCatalog>,
    dns_resolver: Arc<dyn Resolver>,
    rdns_cache: ReverseDnsCache,
}

impl AgentClassResolver {
    /// Build a resolver around the supplied catalog and DNS resolver.
    /// `rdns_cache_capacity` caps the per-process verdict cache; pass
    /// 4096 for the OSS default (matches `ReverseDnsCache`'s docs).
    pub fn new(
        catalog: Arc<AgentClassCatalog>,
        dns_resolver: Arc<dyn Resolver>,
        rdns_cache_capacity: usize,
    ) -> Self {
        Self {
            catalog,
            dns_resolver,
            rdns_cache: ReverseDnsCache::new(rdns_cache_capacity),
        }
    }

    /// Borrow the underlying catalog. Useful for callers that want to
    /// surface vendor metadata in dashboards.
    pub fn catalog(&self) -> &AgentClassCatalog {
        &self.catalog
    }

    /// Run the resolver chain against `inputs` and return the verdict.
    ///
    /// Hot-path notes:
    ///
    /// - Bot-auth keyid lookup is `HashMap` O(1).
    /// - rDNS verdicts are cached per-IP; a hot crawler hits the
    ///   cache after the first verified request.
    /// - UA regex is iterative across catalog entries (~10 entries
    ///   in Wave 1; tractable).
    pub fn resolve(&self, inputs: &ResolveInputs<'_>) -> Resolved {
        // --- Step 1: bot-auth keyid match. Highest confidence. ---
        if let Some(keyid) = inputs.bot_auth_keyid {
            if let Some(entry) = self.catalog.lookup_by_keyid(keyid) {
                return Resolved::from_match(entry, AgentIdSource::BotAuth, None);
            }
        }

        // --- Step 2: forward-confirmed reverse DNS. ---
        if let Some(ip) = inputs.client_ip {
            if let Some(ReverseDnsVerdict::Verified(host)) = self.cached_rdns(ip) {
                if let Some(entry) = self.catalog.lookup_by_reverse_dns(&host) {
                    return Resolved::from_match(entry, AgentIdSource::Rdns, Some(host));
                }
            }
        }

        // --- Step 3: User-Agent regex. Advisory. ---
        let ua_present = inputs
            .user_agent
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if let Some(ua) = inputs.user_agent {
            if let Some(entry) = self.catalog.lookup_by_user_agent(ua) {
                return Resolved::from_match(entry, AgentIdSource::UserAgent, None);
            }
        }

        // --- Step 4: anonymous Web Bot Auth. ---
        if inputs.anonymous_bot_auth {
            return Resolved::anonymous();
        }

        // --- Step 5: generic crawler heuristic on the UA string. ---
        if let Some(ua) = inputs.user_agent {
            if ua_present && looks_like_generic_crawler(ua) {
                return Resolved::unknown_bot();
            }
        }

        // --- Step 6: fallthrough. ---
        Resolved::human()
    }

    /// Resolve an rDNS verdict, consulting the cache first and
    /// falling back to a fresh `verify_reverse_dns` call. Cache TTL
    /// for both verified and not-matched results is 5 minutes; DNS
    /// errors are not cached so a transient outage doesn't pin a
    /// false negative.
    fn cached_rdns(&self, ip: IpAddr) -> Option<ReverseDnsVerdict> {
        if let Some(v) = self.rdns_cache.get(ip) {
            return Some(v);
        }
        let suffixes_owned = self.catalog.all_rdns_suffixes();
        if suffixes_owned.is_empty() {
            return None;
        }
        let suffixes_ref: Vec<&str> = suffixes_owned.iter().map(|s| s.as_str()).collect();
        let verdict = verify_reverse_dns(self.dns_resolver.as_ref(), ip, &suffixes_ref);
        match &verdict {
            ReverseDnsVerdict::Verified(_) | ReverseDnsVerdict::NotMatched => {
                self.rdns_cache
                    .insert(ip, verdict.clone(), std::time::Duration::from_secs(300));
            }
            ReverseDnsVerdict::DnsError(_) => {
                // Don't cache DNS errors; resolver tries again next
                // request when the operator may have recovered the
                // upstream resolver.
            }
        }
        Some(verdict)
    }
}

// --- Agent-class policy (G1.4 wire) ---

/// YAML config for the `agent_class` policy module.
///
/// The block is intentionally small: the heavy resolver state lives
/// on the binary-side [`AgentClassResolver`] built from the top-level
/// `agent_classes:` block. The per-origin policy controls only the
/// few knobs an operator might want to vary per route (forward-mode,
/// rDNS toggle override, header names).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AgentClassPolicyConfig {
    /// When `true`, the policy stamps the resolved agent class onto
    /// the upstream request as `X-Forwarded-Agent-Class` (or the
    /// header configured via `header_name`). Defaults to `false`;
    /// most operators want resolution but not header forwarding (the
    /// metric labels on `sbproxy_requests_total` already carry the
    /// dimension; forwarding to the upstream is opt-in to keep
    /// origin servers from accidentally learning an unstable taxonomy).
    #[serde(default)]
    pub forward_to_upstream: bool,
    /// Header name used when `forward_to_upstream` is true. Defaults
    /// to `X-Forwarded-Agent-Class`.
    #[serde(default = "default_forward_header")]
    pub header_name: String,
    /// Header that carries the resolved vendor display string when
    /// `forward_to_upstream` is true. Defaults to
    /// `X-Forwarded-Agent-Vendor`.
    #[serde(default = "default_vendor_header")]
    pub vendor_header_name: String,
    /// Header that carries `true` / `false` to indicate whether the
    /// resolution path was a verified one (bot-auth keyid or rDNS).
    /// Defaults to `X-Forwarded-Agent-Verified`. Empty string disables.
    #[serde(default = "default_verified_header")]
    pub verified_header_name: String,
    /// Operator-level toggle for resolver step 2 (reverse-DNS). The
    /// top-level `agent_classes.resolver.rdns_enabled` is the global
    /// default; this per-policy override lets a single origin opt in
    /// or out without touching the global config. `None` means inherit
    /// the global default.
    ///
    /// Note: enforcement of this toggle requires the binary to consult
    /// the policy block when invoking the resolver. The current Wave
    /// 3 wiring builds one resolver process-wide; per-origin override
    /// is reserved for a follow-up.
    #[serde(default)]
    pub verify_reverse_dns: Option<bool>,
}

fn default_forward_header() -> String {
    "X-Forwarded-Agent-Class".to_string()
}

fn default_vendor_header() -> String {
    "X-Forwarded-Agent-Vendor".to_string()
}

fn default_verified_header() -> String {
    "X-Forwarded-Agent-Verified".to_string()
}

/// Compiled `agent_class` policy. Holds the parsed config and acts
/// as a marker so the request pipeline can find the policy block via
/// the existing policy-enum dispatch (the resolver itself runs in the
/// binary-side [`AgentClassResolver`]; this policy is the seam that
/// surfaces the verdict on the upstream request).
#[derive(Debug, Clone)]
pub struct AgentClassPolicy {
    config: AgentClassPolicyConfig,
}

impl AgentClassPolicy {
    /// Build the policy from a JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config: AgentClassPolicyConfig = serde_json::from_value(value)?;
        Ok(Self { config })
    }

    /// True when the policy should stamp the resolved verdict onto
    /// the upstream request.
    pub fn forward_to_upstream(&self) -> bool {
        self.config.forward_to_upstream
    }

    /// Header name for the resolved agent_id.
    pub fn header_name(&self) -> &str {
        &self.config.header_name
    }

    /// Header name for the resolved vendor display string.
    pub fn vendor_header_name(&self) -> &str {
        &self.config.vendor_header_name
    }

    /// Header name for the verified-flag header. Empty disables.
    pub fn verified_header_name(&self) -> &str {
        &self.config.verified_header_name
    }

    /// Operator-level rDNS override. `None` = inherit global default.
    pub fn verify_reverse_dns(&self) -> Option<bool> {
        self.config.verify_reverse_dns
    }
}

/// Coarse "looks like a bot" heuristic for the step-5 fallback. The
/// catalog catches the well-known names; this catches everything that
/// self-identifies as a crawler / scraper / spider but isn't in our
/// vendor list. Substring matching, case-insensitive.
fn looks_like_generic_crawler(user_agent: &str) -> bool {
    let lower = user_agent.to_ascii_lowercase();
    const BOT_TOKENS: &[&str] = &[
        "bot", "crawl", "spider", "scrape", "fetch", "ai-agent", "ai_agent",
    ];
    BOT_TOKENS.iter().any(|t| lower.contains(t))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_security::agent_verify::StubResolver;
    use std::net::Ipv4Addr;

    fn googlebot_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1))
    }

    fn build_resolver_with_dns(stub: StubResolver) -> AgentClassResolver {
        AgentClassResolver::new(Arc::new(AgentClassCatalog::defaults()), Arc::new(stub), 64)
    }

    #[test]
    fn ua_match_resolves_known_bot() {
        let resolver = build_resolver_with_dns(StubResolver::new());
        let inputs = ResolveInputs {
            user_agent: Some("Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"),
            ..Default::default()
        };
        let r = resolver.resolve(&inputs);
        assert_eq!(r.agent_id.as_str(), "openai-gptbot");
        assert_eq!(r.vendor, "OpenAI");
        assert_eq!(r.purpose, AgentPurpose::Training);
        assert_eq!(r.source, AgentIdSource::UserAgent);
    }

    #[test]
    fn rdns_match_outranks_ua() {
        // Plant a googlebot rDNS entry; UA pretends to be Chrome.
        let ip = googlebot_ip();
        let stub = StubResolver::new()
            .with_ptr(ip, vec!["crawl-66-249-66-1.googlebot.com".to_string()])
            .with_forward("crawl-66-249-66-1.googlebot.com", vec![ip]);
        let resolver = build_resolver_with_dns(stub);
        let inputs = ResolveInputs {
            client_ip: Some(ip),
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
            ),
            ..Default::default()
        };
        let r = resolver.resolve(&inputs);
        assert_eq!(r.agent_id.as_str(), "google-googlebot");
        assert_eq!(r.source, AgentIdSource::Rdns);
        assert_eq!(
            r.rdns_hostname.as_deref(),
            Some("crawl-66-249-66-1.googlebot.com")
        );
    }

    #[test]
    fn anonymous_bot_auth_emits_anonymous_when_no_other_signal() {
        let resolver = build_resolver_with_dns(StubResolver::new());
        let inputs = ResolveInputs {
            anonymous_bot_auth: true,
            ..Default::default()
        };
        let r = resolver.resolve(&inputs);
        assert_eq!(r.agent_id.as_str(), "anonymous");
        assert_eq!(r.source, AgentIdSource::AnonymousBotAuth);
    }

    #[test]
    fn generic_crawler_ua_emits_unknown() {
        let resolver = build_resolver_with_dns(StubResolver::new());
        let inputs = ResolveInputs {
            user_agent: Some("MysteryCrawler/0.9 (+https://example.com/about)"),
            ..Default::default()
        };
        let r = resolver.resolve(&inputs);
        assert_eq!(r.agent_id.as_str(), "unknown");
        assert_eq!(r.source, AgentIdSource::Fallback);
    }

    #[test]
    fn fallthrough_to_human() {
        let resolver = build_resolver_with_dns(StubResolver::new());
        let inputs = ResolveInputs {
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
            ),
            ..Default::default()
        };
        let r = resolver.resolve(&inputs);
        assert_eq!(r.agent_id.as_str(), "human");
        assert_eq!(r.source, AgentIdSource::Fallback);
    }

    #[test]
    fn rdns_cache_is_consulted_on_second_call() {
        let ip = googlebot_ip();
        let stub = StubResolver::new()
            .with_ptr(ip, vec!["crawl-1.googlebot.com".to_string()])
            .with_forward("crawl-1.googlebot.com", vec![ip]);
        let resolver = build_resolver_with_dns(stub);
        let inputs = ResolveInputs {
            client_ip: Some(ip),
            user_agent: Some("any"),
            ..Default::default()
        };
        let first = resolver.resolve(&inputs);
        assert_eq!(first.agent_id.as_str(), "google-googlebot");
        // Second call: even if the resolver were to fail (we can't
        // poke the stub here, but this exercises the cache path), we
        // expect the same verdict.
        let second = resolver.resolve(&inputs);
        assert_eq!(second.agent_id.as_str(), "google-googlebot");
    }

    #[test]
    fn looks_like_generic_crawler_recognises_common_tokens() {
        assert!(looks_like_generic_crawler("PalmCrawler/1.0"));
        assert!(looks_like_generic_crawler("ScrapeBot 0.9"));
        assert!(looks_like_generic_crawler("MySpider"));
        assert!(!looks_like_generic_crawler("Mozilla/5.0 Chrome/123.0"));
    }
}
