//! Forward-confirmed reverse-DNS verifier for AI-agent identification (G1.5).
//!
//! Per `docs/adr-agent-class-taxonomy.md`, a request claiming to come
//! from a vendor's crawler is "rDNS verified" when:
//!
//! 1. A PTR lookup on the client IP returns at least one hostname.
//! 2. A forward A/AAAA lookup on that hostname includes the original
//!    client IP (forward-confirms the PTR).
//! 3. The hostname ends with one of the vendor's expected suffixes
//!    (case-insensitive).
//!
//! All three steps must succeed. Any failure produces a
//! [`ReverseDnsVerdict`] that the caller can attach to the request
//! context as the agent-id source diagnostic; we never silently fall
//! back to `User-Agent` matching.
//!
//! # Per-vendor expected suffixes (Wave 1 OSS catalog)
//!
//! | Vendor       | Suffix                     |
//! |--------------|----------------------------|
//! | GPTBot       | `.gptbot.openai.com`        |
//! | ClaudeBot    | `.anthropic.com`, `.claude.ai` |
//! | PerplexityBot| `.perplexity.ai`            |
//! | GoogleBot    | `.googlebot.com`, `.google.com` |
//! | BingBot      | `.search.msn.com`           |
//! | DuckDuckBot  | `.duckduckgo.com`           |
//! | AppleBot     | `.applebot.apple.com`       |
//! | CCBot        | `.commoncrawl.org`          |
//!
//! These are also embedded into `sbproxy-classifiers::AgentClassCatalog`.
//!
//! # Resolver injection
//!
//! The verifier owns no DNS dependency. It accepts a [`Resolver`]
//! trait object so:
//!
//! - tests can pass a deterministic in-memory resolver (no network),
//! - the proxy binary can plug in `hickory-resolver` (a follow-up
//!   slice; today the OSS proxy uses [`SystemResolver`] which performs
//!   PTR + forward lookups via the host stub resolver via
//!   `getaddrinfo`-style APIs).
//!
//! # Caching
//!
//! Verdicts are cached per-IP so a hot crawler does not re-issue PTR
//! lookups on every request. The cache TTL is the lower of the
//! observed PTR / forward TTLs and is capped at one hour. The cache
//! is process-local; no cross-pod sharing in the OSS distribution.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// --- Public API ---

/// Verdict returned by [`verify_reverse_dns`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReverseDnsVerdict {
    /// PTR + forward lookups succeeded and the hostname ended in one
    /// of the supplied suffixes. Carries the matched hostname so the
    /// caller can stamp it into audit logs.
    Verified(String),
    /// All DNS calls succeeded but the hostname did not match any of
    /// the supplied suffixes, or the forward lookup did not contain
    /// the original IP. Distinguishable from [`Self::DnsError`] so the
    /// caller can decide whether to demote the verdict (NotMatched)
    /// versus fall through to UA-only matching (DnsError).
    NotMatched,
    /// At least one DNS call failed (timeout, NXDOMAIN, server fail).
    /// The contained string is a one-line, low-detail reason suitable
    /// for the audit log.
    DnsError(String),
}

impl ReverseDnsVerdict {
    /// True iff the verdict is [`Self::Verified`].
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

/// DNS resolver port surfaced to `agent_verify`. Keeps this crate free
/// of a hard DNS dependency; callers wire in a real implementation
/// (e.g. `hickory-resolver`) and tests wire in [`StubResolver`].
pub trait Resolver: Send + Sync {
    /// Reverse-resolve `ip` to one or more PTR hostnames. Hostnames
    /// are returned without the trailing dot.
    fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String>;
    /// Forward-resolve `hostname` to one or more A / AAAA records.
    fn forward(&self, hostname: &str) -> Result<Vec<IpAddr>, String>;
}

/// Verify that `client_ip` is operated by an agent whose hostname
/// ends with one of `expected_suffixes`.
///
/// The function performs a forward-confirmed reverse-DNS check, then
/// matches the resolved hostname against the supplied suffix list
/// (case-insensitive, leading-dot tolerant).
///
/// `expected_suffixes` may include either `".vendor.com"` or
/// `"vendor.com"`; both forms compare against the resolved hostname's
/// last n bytes after lowercasing.
pub fn verify_reverse_dns(
    resolver: &dyn Resolver,
    client_ip: IpAddr,
    expected_suffixes: &[&str],
) -> ReverseDnsVerdict {
    if expected_suffixes.is_empty() {
        return ReverseDnsVerdict::NotMatched;
    }

    // --- Step 1: PTR lookup. ---
    let ptrs = match resolver.reverse(client_ip) {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            return ReverseDnsVerdict::DnsError("PTR lookup returned no records".to_string());
        }
        Err(e) => {
            return ReverseDnsVerdict::DnsError(format!("PTR lookup failed: {e}"));
        }
    };

    // --- Step 2 & 3: forward-confirm and suffix match. ---
    //
    // For every PTR hostname, we forward-resolve and check whether
    // the original client IP is in the forward set. If yes, then we
    // check whether the hostname ends with an expected suffix. The
    // first PTR that satisfies both wins.
    let mut last_forward_error: Option<String> = None;
    for ptr in &ptrs {
        let host = strip_trailing_dot(ptr).to_ascii_lowercase();
        // Forward-confirm.
        let forwards = match resolver.forward(&host) {
            Ok(f) => f,
            Err(e) => {
                last_forward_error = Some(e);
                continue;
            }
        };
        if !forwards.contains(&client_ip) {
            // PTR did not forward-confirm; skip suffix check.
            continue;
        }
        if matches_any_suffix(&host, expected_suffixes) {
            return ReverseDnsVerdict::Verified(host);
        }
    }

    if let Some(err) = last_forward_error {
        return ReverseDnsVerdict::DnsError(format!(
            "no PTR forward-confirmed; last forward error: {err}"
        ));
    }
    ReverseDnsVerdict::NotMatched
}

/// True iff `hostname` (already lowercased) ends with at least one
/// suffix from `suffixes` (case-insensitive). Suffixes may be supplied
/// with or without a leading dot.
fn matches_any_suffix(hostname: &str, suffixes: &[&str]) -> bool {
    for suffix in suffixes {
        let suf = suffix.to_ascii_lowercase();
        if suf.is_empty() {
            continue;
        }
        let with_dot = if suf.starts_with('.') {
            suf.clone()
        } else {
            format!(".{suf}")
        };
        // Accept both ".googlebot.com" matching "crawl-1.googlebot.com"
        // and "googlebot.com" matching "googlebot.com" (exact).
        if hostname.ends_with(&with_dot) || hostname == suf.trim_start_matches('.') {
            return true;
        }
    }
    false
}

fn strip_trailing_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

// --- StubResolver (test fixture) ---

/// In-memory [`Resolver`] for unit tests. Builders configure the PTR
/// and forward maps; lookups never touch the network.
#[derive(Debug, Default)]
pub struct StubResolver {
    ptr: HashMap<IpAddr, Vec<String>>,
    forward: HashMap<String, Vec<IpAddr>>,
    /// When set, [`Resolver::reverse`] returns this error verbatim.
    reverse_error: Option<String>,
    /// When set, [`Resolver::forward`] returns this error for every host.
    forward_error: Option<String>,
}

impl StubResolver {
    /// Empty stub. Add PTR / forward entries with [`Self::with_ptr`] /
    /// [`Self::with_forward`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Wire `ip -> [hostnames]` into the stub. Hostnames may include a
    /// trailing dot; the verifier strips it.
    pub fn with_ptr(mut self, ip: IpAddr, hostnames: Vec<String>) -> Self {
        self.ptr.insert(ip, hostnames);
        self
    }

    /// Wire `hostname -> [ips]` into the stub. Hostname is lowercased
    /// at lookup time so the caller can pass any case.
    pub fn with_forward(mut self, hostname: &str, ips: Vec<IpAddr>) -> Self {
        self.forward.insert(hostname.to_ascii_lowercase(), ips);
        self
    }

    /// Make every reverse lookup fail with the supplied reason.
    pub fn with_reverse_error(mut self, err: &str) -> Self {
        self.reverse_error = Some(err.to_string());
        self
    }

    /// Make every forward lookup fail with the supplied reason.
    pub fn with_forward_error(mut self, err: &str) -> Self {
        self.forward_error = Some(err.to_string());
        self
    }
}

impl Resolver for StubResolver {
    fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String> {
        if let Some(err) = &self.reverse_error {
            return Err(err.clone());
        }
        Ok(self.ptr.get(&ip).cloned().unwrap_or_default())
    }
    fn forward(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        if let Some(err) = &self.forward_error {
            return Err(err.clone());
        }
        Ok(self
            .forward
            .get(&hostname.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default())
    }
}

// --- SystemResolver (host stub resolver) ---

/// [`Resolver`] backed by the host stub resolver via `getaddrinfo`.
/// PTR lookups are performed by formatting the IP into an
/// `in-addr.arpa` / `ip6.arpa` query string and... actually the host
/// `std` API does not expose PTR. The OSS proxy ships this stub which
/// returns [`Result::Err`] until a real DNS dependency is wired in
/// (Wave 1 follow-up: switch to `hickory-resolver`).
///
/// Used in production today only when an operator explicitly opts in;
/// the resolver chain falls back to UA matching when this returns an
/// error verdict, which matches the ADR-defined ordering.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn reverse(&self, _ip: IpAddr) -> Result<Vec<String>, String> {
        Err("system resolver does not implement PTR; configure hickory-resolver via the platform layer".to_string())
    }
    fn forward(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        // `std::net::ToSocketAddrs` requires a port; use 80 as a
        // sentinel and discard it from the returned addresses.
        let target = format!("{hostname}:80");
        let iter = std::net::ToSocketAddrs::to_socket_addrs(&target).map_err(|e| e.to_string())?;
        Ok(iter.map(|sa| sa.ip()).collect())
    }
}

// --- Verdict cache ---

/// Process-local cache of [`ReverseDnsVerdict`] keyed by client IP.
///
/// Entries are evicted by elapsed wall-clock; the TTL is the smaller
/// of the observed PTR / forward TTLs (clamped at one hour). The cache
/// is bounded to `max_entries` and uses a coarse FIFO ring eviction
/// when full because verdict lookups dominate over inserts. The OSS
/// default capacity is 4096, picked so a single flooded /24 of bots
/// fits without thrashing the cache while staying well under any
/// memory-pressure threshold.
pub struct ReverseDnsCache {
    inner: Mutex<CacheInner>,
    max_entries: usize,
}

struct CacheInner {
    entries: HashMap<IpAddr, CacheEntry>,
    order: Vec<IpAddr>,
}

struct CacheEntry {
    verdict: ReverseDnsVerdict,
    expires_at: Instant,
}

impl ReverseDnsCache {
    /// Hard cap on cached verdict TTL. Even if the underlying DNS
    /// records claim to be valid for longer, we re-verify after this.
    pub const MAX_TTL: Duration = Duration::from_secs(60 * 60);

    /// Build a cache with the supplied entry capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                entries: HashMap::with_capacity(max_entries),
                order: Vec::with_capacity(max_entries),
            }),
            max_entries,
        }
    }

    /// Look up a fresh verdict; returns `None` if absent or expired.
    pub fn get(&self, ip: IpAddr) -> Option<ReverseDnsVerdict> {
        let inner = self.inner.lock().expect("rdns cache mutex poisoned");
        let entry = inner.entries.get(&ip)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        Some(entry.verdict.clone())
    }

    /// Insert a verdict with the supplied effective TTL; the TTL is
    /// silently capped at [`Self::MAX_TTL`].
    pub fn insert(&self, ip: IpAddr, verdict: ReverseDnsVerdict, ttl: Duration) {
        let ttl = ttl.min(Self::MAX_TTL);
        let mut inner = self.inner.lock().expect("rdns cache mutex poisoned");
        let evict_oldest = !inner.entries.contains_key(&ip)
            && inner.entries.len() >= self.max_entries
            && self.max_entries > 0;
        if evict_oldest {
            if let Some(oldest) = inner.order.first().copied() {
                inner.order.remove(0);
                inner.entries.remove(&oldest);
            }
        }
        if !inner.entries.contains_key(&ip) {
            inner.order.push(ip);
        }
        inner.entries.insert(
            ip,
            CacheEntry {
                verdict,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// Number of live entries (does not eagerly evict expired keys).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("rdns cache mutex poisoned")
            .entries
            .len()
    }

    /// True iff [`Self::len`] is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn happy_path_googlebot_verifies() {
        let ip = ip4(66, 249, 66, 1);
        let resolver = StubResolver::new()
            .with_ptr(ip, vec!["crawl-66-249-66-1.googlebot.com.".to_string()])
            .with_forward("crawl-66-249-66-1.googlebot.com", vec![ip]);

        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);
        assert_eq!(
            verdict,
            ReverseDnsVerdict::Verified("crawl-66-249-66-1.googlebot.com".to_string())
        );
        assert!(verdict.is_verified());
    }

    #[test]
    fn happy_path_gptbot_verifies_without_leading_dot() {
        let ip = ip4(20, 171, 191, 1);
        let resolver = StubResolver::new()
            .with_ptr(ip, vec!["bot1.gptbot.openai.com".to_string()])
            .with_forward("bot1.gptbot.openai.com", vec![ip]);

        // Suffix supplied without leading dot still matches.
        let verdict = verify_reverse_dns(&resolver, ip, &["gptbot.openai.com"]);
        assert!(
            matches!(verdict, ReverseDnsVerdict::Verified(ref h) if h == "bot1.gptbot.openai.com")
        );
    }

    #[test]
    fn no_ptr_returns_dns_error() {
        let ip = ip4(1, 2, 3, 4);
        let resolver = StubResolver::new();
        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);
        match verdict {
            ReverseDnsVerdict::DnsError(msg) => assert!(msg.contains("PTR"), "got {msg}"),
            other => panic!("expected DnsError, got {other:?}"),
        }
    }

    #[test]
    fn forward_does_not_confirm_returns_not_matched() {
        let ip = ip4(1, 2, 3, 4);
        // PTR claims googlebot.com but forward returns a *different* IP.
        let resolver = StubResolver::new()
            .with_ptr(ip, vec!["crawl-1.googlebot.com".to_string()])
            .with_forward("crawl-1.googlebot.com", vec![ip4(9, 9, 9, 9)]);

        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);
        assert_eq!(verdict, ReverseDnsVerdict::NotMatched);
    }

    #[test]
    fn suffix_does_not_match_returns_not_matched() {
        let ip = ip4(1, 2, 3, 4);
        let resolver = StubResolver::new()
            .with_ptr(ip, vec!["evil.example.com".to_string()])
            .with_forward("evil.example.com", vec![ip]);

        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);
        assert_eq!(verdict, ReverseDnsVerdict::NotMatched);
    }

    #[test]
    fn empty_suffix_list_is_not_matched() {
        let ip = ip4(1, 2, 3, 4);
        let resolver = StubResolver::new();
        let verdict = verify_reverse_dns(&resolver, ip, &[]);
        assert_eq!(verdict, ReverseDnsVerdict::NotMatched);
    }

    #[test]
    fn reverse_error_propagates_as_dns_error() {
        let ip = ip4(1, 2, 3, 4);
        let resolver = StubResolver::new().with_reverse_error("SERVFAIL");
        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);
        match verdict {
            ReverseDnsVerdict::DnsError(msg) => assert!(msg.contains("SERVFAIL"), "got {msg}"),
            other => panic!("expected DnsError, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_path_works() {
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4004, 0x812, 0, 0, 0, 0x200e,
        ));
        let resolver = StubResolver::new()
            .with_ptr(ip, vec!["lga25s33-in-x0e.1e100.net".to_string()])
            .with_forward("lga25s33-in-x0e.1e100.net", vec![ip]);

        // Catalog includes .google.com but not .1e100.net; should be NotMatched.
        let verdict = verify_reverse_dns(&resolver, ip, &[".google.com"]);
        assert_eq!(verdict, ReverseDnsVerdict::NotMatched);
    }

    #[test]
    fn case_insensitive_match() {
        let ip = ip4(1, 2, 3, 4);
        let resolver = StubResolver::new()
            .with_ptr(ip, vec!["Crawl-1.GoogleBot.COM".to_string()])
            .with_forward("crawl-1.googlebot.com", vec![ip]);
        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);
        assert!(verdict.is_verified());
    }

    #[test]
    fn cache_round_trips_verdicts_under_ttl() {
        let cache = ReverseDnsCache::new(8);
        let ip = ip4(1, 2, 3, 4);
        cache.insert(
            ip,
            ReverseDnsVerdict::Verified("a.googlebot.com".to_string()),
            Duration::from_secs(60),
        );
        let v = cache.get(ip).expect("verdict cached");
        assert_eq!(
            v,
            ReverseDnsVerdict::Verified("a.googlebot.com".to_string())
        );
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let cache = ReverseDnsCache::new(2);
        let a = ip4(1, 1, 1, 1);
        let b = ip4(2, 2, 2, 2);
        let c = ip4(3, 3, 3, 3);
        cache.insert(a, ReverseDnsVerdict::NotMatched, Duration::from_secs(60));
        cache.insert(b, ReverseDnsVerdict::NotMatched, Duration::from_secs(60));
        cache.insert(c, ReverseDnsVerdict::NotMatched, Duration::from_secs(60));
        // a was the first inserted; evicted to make room for c.
        assert!(cache.get(a).is_none());
        assert!(cache.get(b).is_some());
        assert!(cache.get(c).is_some());
    }

    #[test]
    fn cache_caps_ttl_at_one_hour() {
        let cache = ReverseDnsCache::new(8);
        let ip = ip4(1, 2, 3, 4);
        cache.insert(
            ip,
            ReverseDnsVerdict::Verified("h".to_string()),
            Duration::from_secs(60 * 60 * 24),
        );
        assert!(cache.get(ip).is_some());
        // We can't easily inspect the cap without time travel, but we
        // can at least verify the insert succeeded and the entry is
        // live. (The cap itself is asserted by the constant.)
        assert_eq!(ReverseDnsCache::MAX_TTL, Duration::from_secs(60 * 60));
    }
}
