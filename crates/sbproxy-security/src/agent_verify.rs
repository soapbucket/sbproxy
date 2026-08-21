//! Forward-confirmed reverse-DNS verifier for AI-agent identification.
//!
//! A request claiming to come from a vendor's crawler is "rDNS verified" when:
//!
//! 1. A PTR lookup on the client IP returns at least one hostname.
//! 2. A forward A/AAAA lookup on that hostname includes the original
//!    client IP (forward-confirms the PTR).
//! 3. The hostname ends with one of the vendor's expected suffixes
//!    (case-insensitive).
//!
//! All three steps must succeed. Any failure produces a
//! [`ReverseDnsVerdict`] that the caller attaches to the request
//! context as the agent-id source diagnostic. The verdict does not by
//! itself settle the agent class: the resolver chain in
//! `sbproxy-modules::policy::agent_class` reads anything other than
//! `Verified` as "rDNS did not identify this client" and continues to
//! its `User-Agent` pass, so a `DnsError` or `NotMatched` client can
//! still be classified from its UA header alone. Only a `Verified`
//! verdict is stamped with the `Rdns` agent-id source, which is the
//! distinction a policy should key on.
//!
//! # Per-vendor expected suffixes
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
//! - the proxy binary uses [`SystemResolver`], which performs PTR and
//!   forward lookups via `hickory-resolver` and the host DNS
//!   configuration.
//!
//! # Cost control
//!
//! This runs on the request path, and the client owns the reverse zone
//! that answers step 1. Every bound below exists because the client,
//! not the operator, decides what that zone returns:
//!
//! - A whole verification is capped at four forward lookups
//!   (`MAX_FORWARD_CONFIRMS`). A reverse zone that answers with 50 PTR
//!   names costs the same as one that answers with four.
//! - A whole verification is capped at two seconds of wall clock
//!   (`VERIFY_BUDGET`) measured across the forward-confirm loop and
//!   checked before each forward lookup is issued.
//! - [`SystemResolver`] caps each individual query and runs it on one
//!   shared background runtime with one shared `hickory-resolver`
//!   instance, so a lookup costs neither an OS thread nor a fresh
//!   resolver (and repeat queries hit hickory's own response cache).
//!
//! A run that hits either cap without forward-confirming anything
//! returns [`ReverseDnsVerdict::DnsError`] rather than
//! [`ReverseDnsVerdict::NotMatched`]: we stopped early, so we do not
//! know that the client is unmatched, only that we refused to keep
//! looking.
//!
//! # Caching
//!
//! Verdicts are cached per-IP by the caller so a hot crawler does not
//! re-issue PTR lookups on every request. The [`Resolver`] port carries
//! no record TTL, so the cache TTL is a fixed value the caller picks,
//! not the observed PTR / forward TTL. The production caller
//! (`sbproxy-modules::policy::agent_class`) uses 300 seconds for a
//! `Verified` or `NotMatched` verdict and 30 seconds for a `DnsError`,
//! and [`ReverseDnsCache`] clamps whatever it is handed at one hour.
//! The cache is process-local; no cross-pod sharing in the OSS
//! distribution.

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

/// Ceiling on how many PTR names one reverse zone can make the
/// verifier forward-confirm.
///
/// Step 1 is answered by the client's own reverse zone, so the length
/// of that answer is chosen by the party we are trying to identify.
/// Four is generous: a vendor crawler publishes one PTR per address.
/// Anything past the fourth name is not checked.
const MAX_FORWARD_CONFIRMS: usize = 4;

/// Wall-clock budget for the forward-confirm loop of a single
/// `verify_reverse_dns` call.
///
/// Checked before each forward lookup is issued, so the real ceiling is
/// this budget plus one query timeout. It exists so a zone that answers
/// slowly rather than not at all cannot turn `MAX_FORWARD_CONFIRMS`
/// queries into `MAX_FORWARD_CONFIRMS` times the per-query timeout.
const VERIFY_BUDGET: Duration = Duration::from_secs(2);

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
///
/// The forward-confirm loop is bounded, in count and in wall clock; see
/// the module-level "Cost control" section for why, and for what a run
/// that stops early returns.
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
    //
    // The loop is bounded twice over because `ptrs` came from the
    // client's own reverse zone: a zone that answers with 50 names
    // pointing at black-holed forward zones would otherwise buy 50
    // sequential timeouts on whatever thread called us.
    let started = Instant::now();
    let mut last_forward_error: Option<String> = None;
    let mut stopped_early: Option<&'static str> = None;
    for (checked, ptr) in ptrs.iter().enumerate() {
        if checked >= MAX_FORWARD_CONFIRMS {
            stopped_early = Some("PTR set exceeded the forward-confirm cap");
            break;
        }
        if started.elapsed() >= VERIFY_BUDGET {
            stopped_early = Some("forward-confirm budget exhausted");
            break;
        }
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

    // A truncated run is reported as a DNS error rather than
    // `NotMatched`. `NotMatched` is a statement about the client ("we
    // checked, it is not this vendor") and gets the long cache TTL; we
    // did not check, so we must not make that statement.
    if let Some(reason) = stopped_early {
        return ReverseDnsVerdict::DnsError(match last_forward_error {
            Some(err) => format!("{reason}; last forward error: {err}"),
            None => reason.to_string(),
        });
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

// --- SystemResolver (hickory resolver) ---

/// Ceiling on a single PTR or forward query.
///
/// Deliberately the same 2s as the SSRF module's
/// `DNS_RESOLUTION_TIMEOUT`, and for the same reason: the zone being
/// queried belongs to the party we are trying to identify, so it must
/// not get to decide how long a request-path thread waits. The system
/// default is 5s with 2 retries, which is 15s per query.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Slack on the caller-side wait so the in-task timeout is normally the
/// one that fires and the error string stays specific.
const DNS_QUERY_WAIT_SLACK: Duration = Duration::from_millis(250);

/// [`Resolver`] backed by the host DNS configuration through
/// `hickory-resolver`.
///
/// This is what the proxy binary installs by default: `hickory-resolver`
/// is a non-optional dependency of this crate and
/// `install_agent_class_resolver` runs unconditionally when the
/// `agent-class` feature is on, which it is in the default build. An
/// operator who does not want PTR lookups on the request path sets
/// `agent_classes.resolver.rdns_enabled: false`, which skips step 2
/// entirely.
///
/// Every lookup goes through one shared background runtime and one
/// shared `hickory-resolver` instance, and each query is capped at two
/// seconds. See the module-level "Cost control" section.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String> {
        run_hickory_lookup(move |resolver| async move {
            let lookup = resolver
                .reverse_lookup(ip)
                .await
                .map_err(|e| format!("reverse lookup {ip}: {e}"))?;
            let hosts = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::PTR(ptr) => {
                        Some(ptr.0.to_utf8().trim_end_matches('.').to_string())
                    }
                    _ => None,
                })
                .collect();
            Ok(hosts)
        })
    }

    fn forward(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        let hostname = hostname.to_string();
        run_hickory_lookup(move |resolver| async move {
            let lookup = resolver
                .lookup_ip(hostname.as_str())
                .await
                .map_err(|e| format!("forward lookup {hostname}: {e}"))?;
            Ok(lookup.iter().collect())
        })
    }
}

/// The one background runtime every hickory lookup runs on.
///
/// It is built once. The shape this replaced built a fresh
/// multi-thread `Runtime` (which starts one worker per CPU) inside a
/// freshly spawned OS thread for every single query, so a client IP
/// with no PTR record paid a thread plus a whole runtime on every
/// request, forever, because a `DnsError` verdict is not cached for
/// long. One worker thread is enough here: the work is IO-bound and
/// bounded by `MAX_FORWARD_CONFIRMS`.
fn dns_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RUNTIME: std::sync::OnceLock<Result<tokio::runtime::Runtime, String>> =
        std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("sbproxy-agent-dns")
                .enable_all()
                .build()
                .map_err(|e| format!("DNS runtime init: {e}"))
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// The one process-wide `hickory-resolver` instance.
///
/// Sharing it is not only about construction cost: a `Resolver` owns a
/// TTL-bounded response cache, and rebuilding one per query threw that
/// cache away every time, so even a well-behaved crawler re-queried
/// its own PTR record on every cache-missing request.
fn shared_resolver() -> Result<&'static hickory_resolver::TokioResolver, String> {
    static RESOLVER: std::sync::OnceLock<Result<hickory_resolver::TokioResolver, String>> =
        std::sync::OnceLock::new();
    RESOLVER
        .get_or_init(|| {
            let mut builder = hickory_resolver::Resolver::builder_tokio()
                .map_err(|e| format!("DNS resolver init: {e}"))?;
            let options = builder.options_mut();
            options.timeout = DNS_QUERY_TIMEOUT;
            // One retry, not the default two. The caller retries at a
            // much coarser grain (the next request after the negative
            // cache entry expires), so burning three query timeouts
            // inline buys nothing.
            options.attempts = 1;
            builder
                .build()
                .map_err(|e| format!("DNS resolver build: {e}"))
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// Run one hickory query on the shared runtime and block the caller
/// until it answers or `DNS_QUERY_TIMEOUT` elapses.
///
/// The caller is blocked, not the runtime: `Runtime::block_on` panics
/// when it is called from a thread that is already driving a Tokio
/// runtime, which a Pingora worker is, so the result comes back over a
/// std channel instead. The wait is bounded, which is the property
/// that matters, and the request-path caller
/// (`sbproxy-core::agent_class::stamp_request_context_offloaded`) hands
/// this to `spawn_blocking` so the blocked thread is a blocking-pool
/// thread rather than an async worker.
fn run_hickory_lookup<T, F, Fut>(f: F) -> Result<T, String>
where
    F: FnOnce(&'static hickory_resolver::TokioResolver) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>> + Send + 'static,
    T: Send + 'static,
{
    let runtime = dns_runtime()?;
    let resolver = shared_resolver()?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let outcome = match tokio::time::timeout(DNS_QUERY_TIMEOUT, f(resolver)).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "DNS query exceeded {}s",
                DNS_QUERY_TIMEOUT.as_secs()
            )),
        };
        // A caller that already gave up dropped the receiver. Nothing
        // to report and nothing to leak: the task ends here.
        let _ = tx.send(outcome);
    });
    match rx.recv_timeout(DNS_QUERY_TIMEOUT + DNS_QUERY_WAIT_SLACK) {
        Ok(outcome) => outcome,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err("DNS query timed out".to_string()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("DNS query task ended without a result".to_string())
        }
    }
}

// --- Verdict cache ---

/// Process-local cache of [`ReverseDnsVerdict`] keyed by client IP.
///
/// Entries are evicted by elapsed wall clock. The TTL is whatever the
/// caller passes to [`Self::insert`], clamped at one hour: the
/// [`Resolver`] port returns hostnames and addresses with no record
/// TTL attached, so nothing here can observe the PTR or forward TTL.
/// The production caller (`sbproxy-modules::policy::agent_class`)
/// passes 300 seconds for a resolved verdict and 30 seconds for a
/// `DnsError`.
///
/// The cache is bounded to `max_entries` and uses a coarse FIFO ring
/// eviction when full because verdict lookups dominate over inserts.
/// The OSS default capacity is 4096, picked so a single flooded /24 of
/// bots fits without thrashing the cache while staying well under any
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
    /// Hard cap on cached verdict TTL. Whatever the caller asks for,
    /// we re-verify after this.
    pub(crate) const MAX_TTL: Duration = Duration::from_secs(60 * 60);

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
    /// silently capped at `MAX_TTL`.
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
    fn forward_error_is_reported_as_unverified() {
        // The stub's forward-error branch had no coverage, which is what
        // made its builder look dead. A forward lookup that fails is not
        // the same as one that succeeds and disagrees, and the verdict
        // has to say which happened.
        let ip = ip4(1, 2, 3, 4);
        let resolver = StubResolver::new()
            .with_ptr(ip, vec!["crawl-1.googlebot.com".to_string()])
            .with_forward_error("REFUSED");
        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);
        match verdict {
            ReverseDnsVerdict::DnsError(msg) => assert!(msg.contains("REFUSED"), "got {msg}"),
            other => panic!("expected DnsError from a failed forward lookup, got {other:?}"),
        }
    }

    /// Resolver that counts forward lookups. The cap is a claim about
    /// how many queries a hostile PTR set can buy, and a test that
    /// cannot count queries cannot check that claim.
    struct CountingResolver {
        ptrs: Vec<String>,
        forward_calls: std::sync::atomic::AtomicUsize,
    }

    impl Resolver for CountingResolver {
        fn reverse(&self, _ip: IpAddr) -> Result<Vec<String>, String> {
            Ok(self.ptrs.clone())
        }

        fn forward(&self, _hostname: &str) -> Result<Vec<IpAddr>, String> {
            self.forward_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Never forward-confirms, so the loop runs to whichever
            // bound stops it first.
            Ok(Vec::new())
        }
    }

    #[test]
    fn hostile_ptr_set_stops_at_the_forward_confirm_cap() {
        // Step 1 is answered by the client's own reverse zone, so the
        // client picks how many names come back. Without the cap this
        // bought one sequential forward lookup per name, on the calling
        // thread, on every request (the resulting verdict is only
        // negatively cached for a short window).
        let ip = ip4(203, 0, 113, 7);
        let resolver = CountingResolver {
            ptrs: (0..50).map(|i| format!("h{i}.evil.example")).collect(),
            forward_calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);

        assert_eq!(
            resolver
                .forward_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            MAX_FORWARD_CONFIRMS,
            "the forward-confirm loop must stop at the cap, not at the end of the PTR set"
        );
        match verdict {
            // A truncated run has not established that the client is
            // unmatched, so it must not return the verdict that gets
            // the long positive cache TTL.
            ReverseDnsVerdict::DnsError(msg) => {
                assert!(msg.contains("forward-confirm cap"), "got {msg}")
            }
            other => panic!("expected DnsError from a truncated run, got {other:?}"),
        }
    }

    #[test]
    fn ptr_set_at_the_cap_still_verifies() {
        // The cap must not be narrower than its claim: a zone that
        // answers with exactly the cap's worth of names, the last of
        // which is the real one, still forward-confirms.
        let ip = ip4(66, 249, 66, 2);
        let mut ptrs: Vec<String> = (0..MAX_FORWARD_CONFIRMS - 1)
            .map(|i| format!("decoy{i}.example.net"))
            .collect();
        ptrs.push("crawl-2.googlebot.com".to_string());
        let resolver = StubResolver::new()
            .with_ptr(ip, ptrs)
            .with_forward("crawl-2.googlebot.com", vec![ip]);

        let verdict = verify_reverse_dns(&resolver, ip, &[".googlebot.com"]);

        assert_eq!(
            verdict,
            ReverseDnsVerdict::Verified("crawl-2.googlebot.com".to_string())
        );
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
        assert!(matches!(verdict, ReverseDnsVerdict::Verified(_)));
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
