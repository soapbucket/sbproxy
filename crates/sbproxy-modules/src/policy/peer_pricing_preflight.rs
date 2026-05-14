// SPDX-License-Identifier: BUSL-1.1
//! WOR-188: outbound peer-pricing pre-flight policy.
//!
//! When sbproxy issues an outbound request to a cooperating peer the
//! pre-flight checks the peer's published `llms.txt` for a priced
//! route that matches the outbound path. If the matched price fits
//! the operator's configured budget the call goes through; if it
//! does not the policy short-circuits with a structured 402 to the
//! original agent so the agent can decide whether to top up, switch
//! rails, or back off.
//!
//! The policy is the outbound dual of [`crate::policy::AiCrawlControlPolicy`]:
//!
//! - `ai_crawl_control` advertises a price on inbound crawler
//!   requests.
//! - `peer_pricing_preflight` reads that price on outbound peer
//!   requests.
//!
//! Both speak the same vocabulary
//! ([`crate::policy::ContentShape`], `Money`, tiered routes) so the
//! two ends of a cooperating-agent fetch agree on what was charged.
//!
//! ## Flow
//!
//! 1. First outbound to `peer.example`: side-fetch
//!    `https://peer.example/llms.txt`. Parse with
//!    [`crate::transform::llms_txt::parse`].
//! 2. Cache the parsed result keyed by `peer-host:etag` for
//!    `cache_ttl`. A peer that does not publish a manifest is cached
//!    as a sentinel for `NO_MANIFEST_TTL` so we do not re-probe on
//!    every outbound call.
//! 3. Match the outbound request path against `routes[]`. No match
//!    falls through (no charge advertised, no enforcement applied).
//! 4. Compare `price_micros` against
//!    [`PeerPricingPreflightConfig::max_price_per_request`] and
//!    against the per-day rolling spend captured in
//!    [`PeerPricingPreflightPolicy::spent_today_micros`].
//! 5. Within budget: allow the call and return
//!    [`PreflightDecision::Allow`](crate::policy::peer_pricing_preflight::PreflightDecision::Allow) with the matched route attached
//!    for observability.
//! 6. Over budget: return
//!    [`PreflightDecision::Block`](crate::policy::peer_pricing_preflight::PreflightDecision::Block) carrying a structured 402 body the
//!    caller can write back to the agent verbatim.
//! 7. Tiered choice: when more than one tier matches the path the
//!    cheapest route whose `shape` satisfies the agent's `Accept`
//!    header wins.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::policy::ContentShape;
use crate::transform::llms_pricing::{parse, LlmsTxt, ParseError, PricedRoute};

/// Default TTL applied to a successfully parsed peer manifest when
/// the caller does not configure one explicitly.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// TTL applied to a sentinel "peer has no manifest" cache entry. Kept
/// short on purpose so a peer can publish a manifest mid-day and have
/// it picked up without an operator restart.
pub const NO_MANIFEST_TTL: Duration = Duration::from_secs(5 * 60);

/// Wire-shape config for the pre-flight policy.
///
/// All fields are optional so a minimally-configured policy still
/// behaves usefully: a missing `max_price_per_request` defaults to
/// "no per-request cap" and a missing `daily_budget_micros` defaults
/// to "no daily cap"; both missing means the policy decodes the
/// manifest but never blocks (useful in audit-only deployments).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PeerPricingPreflightConfig {
    /// Hard cap on a single outbound call, expressed in major units
    /// of `currency` (e.g. `0.01` for one USD cent at six-decimal
    /// micros). Anything above this returns a 402 to the agent.
    pub max_price_per_request: Option<f64>,
    /// Rolling 24-hour budget in micros (1e-6 of `currency`). Once
    /// the policy has authorised `daily_budget_micros` of spend
    /// across all peers further calls return a 402 until the rolling
    /// window slides forward.
    pub daily_budget_micros: Option<u64>,
    /// TTL for a successfully parsed manifest. Accepts duration
    /// strings like `1h`, `30m`, `5s`. Defaults to
    /// [`DEFAULT_CACHE_TTL`] when absent.
    #[serde(default)]
    pub cache_ttl: Option<DurationString>,
    /// Behaviour when a peer either returns a non-200 or fails to
    /// publish a parseable manifest. Defaults to
    /// [`OnNoManifest::Allow`] so an outbound to a peer that has not
    /// adopted the spec does not unconditionally fail.
    #[serde(default)]
    pub on_no_manifest: OnNoManifest,
}

/// Thin newtype around the human-friendly duration strings the
/// existing sbproxy YAML accepts (`1h`, `30m`, ...).
#[derive(Debug, Clone)]
pub struct DurationString(Duration);

impl DurationString {
    /// Decoded duration.
    pub fn duration(&self) -> Duration {
        self.0
    }
}

impl<'de> Deserialize<'de> for DurationString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        parse_duration(&raw)
            .map(DurationString)
            .map_err(serde::de::Error::custom)
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num_part, unit_part): (String, String) =
        s.chars().partition(|c| c.is_ascii_digit() || *c == '.');
    if num_part.is_empty() {
        return Err(format!("no digits in duration {s:?}"));
    }
    let n: f64 = num_part.parse().map_err(|e| format!("bad number: {e}"))?;
    let unit = unit_part.trim();
    let secs = match unit {
        "" | "s" => n,
        "ms" => n / 1000.0,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        "d" => n * 86400.0,
        other => return Err(format!("unknown duration unit {other:?}")),
    };
    if secs < 0.0 {
        return Err("negative duration".into());
    }
    Ok(Duration::from_secs_f64(secs))
}

/// What the policy does when a peer has not published a parseable
/// `llms.txt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnNoManifest {
    /// Allow the outbound call. Cooperating-agent deployments default
    /// here because peers that have not opted into the protocol must
    /// still be reachable.
    #[default]
    Allow,
    /// Block the outbound call with a 402 (`reason: no_manifest`).
    /// Useful for closed federations that require every peer to
    /// publish.
    Block,
}

/// Decision the policy returns for a single outbound request.
///
/// The dispatcher uses [`PreflightDecision::Allow`] to continue the
/// outbound and [`PreflightDecision::Block`] to short-circuit with the
/// carried 402 body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightDecision {
    /// Outbound is allowed. `matched_route` is `Some` iff a priced
    /// route in the peer's manifest covered the path; observability
    /// uses it to emit the `sbproxy.outbound.peer_pricing` event with
    /// the price the operator just committed to.
    Allow {
        /// Matched priced route, if any. `None` means the path fell
        /// through with no advertised price.
        matched_route: Option<PricedRoute>,
    },
    /// Outbound is blocked. The caller writes `body` back to the
    /// agent as a 402.
    Block {
        /// Reason classifier suitable for metrics + events.
        reason: BlockReason,
        /// Structured JSON body to return to the agent. Already
        /// shaped per the 402 contract in
        /// `docs/outbound-peer-pricing.md`.
        body: serde_json::Value,
    },
}

/// Why the pre-flight blocked an outbound call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// The matched route's `price_micros` exceeded
    /// `max_price_per_request`.
    OverPerRequestBudget,
    /// Authorising this call would have exceeded
    /// `daily_budget_micros`.
    OverDailyBudget,
    /// The peer published no manifest (or one we could not parse)
    /// and the policy is configured to block in that case.
    NoManifest,
}

impl BlockReason {
    /// Stable string form used in event payloads + the 402 body.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockReason::OverPerRequestBudget => "over_per_request_budget",
            BlockReason::OverDailyBudget => "over_daily_budget",
            BlockReason::NoManifest => "no_manifest",
        }
    }
}

/// Result the fetch hook returns to the policy.
///
/// The pre-flight is fetch-agnostic: production wiring passes a
/// closure backed by the proxy's outbound HTTP client; tests pass a
/// closure backed by a `MockUpstream` peer.
#[derive(Debug, Clone)]
pub enum FetchResult {
    /// The peer returned a 2xx with this body.
    Ok(Vec<u8>),
    /// The peer either returned a non-2xx or the fetch failed.
    /// Treated identically to "no manifest" so we don't have to
    /// surface every transport flavour up to the policy.
    NotPublished,
}

/// Trait used by the policy to fetch the peer's manifest.
///
/// Wrapping the network in a trait keeps the policy synchronously
/// testable: the test passes a deterministic fetcher backed by an
/// in-memory map and never touches the network.
pub trait ManifestFetcher: Send + Sync {
    /// Fetch `https://<peer_host>/llms.txt`. The implementation is
    /// free to honour ETag, conditional GET, or other transport
    /// niceties; the policy only needs the bytes or a not-published
    /// signal.
    fn fetch(&self, peer_host: &str) -> FetchResult;
}

/// Cached parsed manifest with the deadline at which it should be
/// re-fetched. Stored as `Option<LlmsTxt>` so a "peer has no
/// manifest" outcome can also be cached.
#[derive(Debug, Clone)]
struct CachedManifest {
    parsed: Option<LlmsTxt>,
    expires_at: Instant,
}

/// Rolling-window record of one authorised outbound charge.
#[derive(Debug, Clone, Copy)]
struct SpendRecord {
    /// Unix-seconds timestamp captured when the policy authorised
    /// this charge.
    at_unix_secs: u64,
    /// Authorised amount in micros.
    micros: u64,
}

/// Stateful pre-flight policy.
///
/// One instance per origin: the cache and the daily-budget ledger are
/// scoped per policy. Concurrent calls are serialised on the cache
/// lock and the ledger lock, both held only long enough to read or
/// write a single entry, so contention is bounded.
pub struct PeerPricingPreflightPolicy {
    cfg: PeerPricingPreflightConfig,
    max_price_per_request_micros: Option<u64>,
    cache_ttl: Duration,
    cache: RwLock<HashMap<String, CachedManifest>>,
    spent: Mutex<Vec<SpendRecord>>,
}

impl std::fmt::Debug for PeerPricingPreflightPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerPricingPreflightPolicy")
            .field("cfg", &self.cfg)
            .field(
                "max_price_per_request_micros",
                &self.max_price_per_request_micros,
            )
            .field("cache_ttl", &self.cache_ttl)
            .finish()
    }
}

impl PeerPricingPreflightPolicy {
    /// Build a pre-flight policy from a generic JSON config value.
    /// Mirrors the constructor shape every other policy in this
    /// module uses.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: PeerPricingPreflightConfig = serde_json::from_value(value)?;
        Self::with_config(cfg)
    }

    /// Build a pre-flight policy directly from a typed config. The
    /// `from_config` JSON path delegates here so unit tests can keep
    /// the construction call short.
    pub fn with_config(cfg: PeerPricingPreflightConfig) -> anyhow::Result<Self> {
        let max_micros = cfg
            .max_price_per_request
            .map(|amount| (amount.max(0.0) * 1_000_000.0).round() as u64);
        let cache_ttl = cfg
            .cache_ttl
            .as_ref()
            .map(|d| d.duration())
            .unwrap_or(DEFAULT_CACHE_TTL);
        Ok(Self {
            cfg,
            max_price_per_request_micros: max_micros,
            cache_ttl,
            cache: RwLock::new(HashMap::new()),
            spent: Mutex::new(Vec::new()),
        })
    }

    /// Currently configured cache TTL. Exposed so tests can assert
    /// that operator-supplied `cache_ttl` values land on the policy.
    pub fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    /// Authorised spend in the last rolling 24 hours, in micros.
    pub fn spent_today_micros(&self) -> u64 {
        let now = now_unix_secs();
        let cutoff = now.saturating_sub(86_400);
        let guard = match self.spent.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .iter()
            .filter(|r| r.at_unix_secs >= cutoff)
            .map(|r| r.micros)
            .sum()
    }

    /// Evaluate the pre-flight for a single outbound request.
    ///
    /// `peer_host` is the hostname the outbound is targeting (used
    /// for the manifest fetch + cache key); `path` is the outbound
    /// request path; `agent_accept` is the original agent's `Accept`
    /// header, used for tiered tie-breaking; `fetcher` is the hook
    /// the policy uses to side-fetch the peer's `llms.txt`.
    pub fn evaluate<F: ManifestFetcher>(
        &self,
        peer_host: &str,
        path: &str,
        agent_accept: Option<&str>,
        fetcher: &F,
    ) -> PreflightDecision {
        let cached = self.lookup_cache(peer_host);
        let parsed = match cached {
            Some(c) => c,
            None => self.refresh_cache(peer_host, fetcher),
        };

        let manifest = match parsed {
            Some(m) => m,
            None => return self.decide_no_manifest(peer_host, path),
        };

        let matched = pick_matching_route(&manifest, path, agent_accept);
        let Some(route) = matched else {
            // No priced route covered the path; treat as a free
            // pass-through. The outbound still happens, the operator
            // simply has no advertised price to enforce.
            return PreflightDecision::Allow {
                matched_route: None,
            };
        };

        if let Some(max) = self.max_price_per_request_micros {
            if route.price_micros > max {
                let body = build_402_body(
                    peer_host,
                    BlockReason::OverPerRequestBudget,
                    &route,
                    Some(max),
                    self.cfg.daily_budget_micros,
                );
                return PreflightDecision::Block {
                    reason: BlockReason::OverPerRequestBudget,
                    body,
                };
            }
        }

        if let Some(daily) = self.cfg.daily_budget_micros {
            let already = self.spent_today_micros();
            if already.saturating_add(route.price_micros) > daily {
                let body = build_402_body(
                    peer_host,
                    BlockReason::OverDailyBudget,
                    &route,
                    self.max_price_per_request_micros,
                    Some(daily),
                );
                return PreflightDecision::Block {
                    reason: BlockReason::OverDailyBudget,
                    body,
                };
            }
        }

        // Authorise the spend. Recorded before the call returns so
        // concurrent evaluations see the in-flight charge.
        self.record_spend(route.price_micros);

        PreflightDecision::Allow {
            matched_route: Some(route),
        }
    }

    fn decide_no_manifest(&self, peer_host: &str, path: &str) -> PreflightDecision {
        match self.cfg.on_no_manifest {
            OnNoManifest::Allow => PreflightDecision::Allow {
                matched_route: None,
            },
            OnNoManifest::Block => {
                let body = serde_json::json!({
                    "error": "peer_pricing_preflight",
                    "reason": BlockReason::NoManifest.as_str(),
                    "peer_host": peer_host,
                    "path": path,
                });
                PreflightDecision::Block {
                    reason: BlockReason::NoManifest,
                    body,
                }
            }
        }
    }

    fn lookup_cache(&self, peer_host: &str) -> Option<Option<LlmsTxt>> {
        let now = Instant::now();
        let guard = match self.cache.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = guard.get(peer_host) {
            if entry.expires_at > now {
                return Some(entry.parsed.clone());
            }
        }
        None
    }

    fn refresh_cache<F: ManifestFetcher>(&self, peer_host: &str, fetcher: &F) -> Option<LlmsTxt> {
        let (parsed, ttl) = match fetcher.fetch(peer_host) {
            FetchResult::Ok(bytes) => match parse_manifest(&bytes) {
                Ok(m) => (Some(m), self.cache_ttl),
                Err(_) => (None, NO_MANIFEST_TTL),
            },
            FetchResult::NotPublished => (None, NO_MANIFEST_TTL),
        };
        let expires_at = Instant::now() + ttl;
        let mut guard = match self.cache.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(
            peer_host.to_string(),
            CachedManifest {
                parsed: parsed.clone(),
                expires_at,
            },
        );
        parsed
    }

    fn record_spend(&self, micros: u64) {
        if micros == 0 {
            return;
        }
        let now = now_unix_secs();
        let mut guard = match self.spent.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // GC older-than-24h entries while we hold the lock.
        let cutoff = now.saturating_sub(86_400);
        guard.retain(|r| r.at_unix_secs >= cutoff);
        guard.push(SpendRecord {
            at_unix_secs: now,
            micros,
        });
    }
}

/// Parse the raw bytes the fetcher returned. Wrapper kept for
/// readability + so the test suite can assert the parser dependency
/// without re-importing it.
fn parse_manifest(bytes: &[u8]) -> Result<LlmsTxt, ParseError> {
    parse(bytes)
}

/// Pick the priced route that should govern this outbound call.
///
/// The match is two-step:
///
/// 1. Filter the manifest's routes down to those whose
///    `route_pattern` matches `path`.
/// 2. Apply the agent's `Accept` preferences (if any) to select the
///    cheapest tier whose `shape` satisfies the agent.
fn pick_matching_route(
    manifest: &LlmsTxt,
    path: &str,
    agent_accept: Option<&str>,
) -> Option<PricedRoute> {
    let candidates: Vec<&PricedRoute> = manifest
        .routes
        .iter()
        .filter(|r| route_matches(&r.route_pattern, path))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let accepted = parse_accept_shapes(agent_accept);
    // First pass: tiers whose `shape` is in the agent's Accept list.
    let shape_filtered: Vec<&&PricedRoute> = candidates
        .iter()
        .filter(|r| accepted.contains(&r.shape))
        .collect();
    let pool: &[&&PricedRoute] = if !shape_filtered.is_empty() {
        &shape_filtered[..]
    } else {
        // Pre-fall-back: when the agent expressed no preference (or
        // the manifest's tiers don't intersect with what the agent
        // accepts) every candidate stays in the running.
        return candidates
            .into_iter()
            .min_by_key(|r| r.price_micros)
            .cloned();
    };
    pool.iter()
        .min_by_key(|r| r.price_micros)
        .map(|r| (**r).clone())
}

/// Minimal route matcher matching the same prefix-wildcard contract
/// that [`crate::policy::Tier`] uses. Supports literal paths and a
/// trailing `*` suffix wildcard. Anything else falls back to literal
/// equality. Kept private to keep the matcher inside the policy so
/// the public surface stays the policy itself.
fn route_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        pattern == path
    }
}

/// Best-effort parse of the agent's `Accept` header into a set of
/// [`ContentShape`] values. The full HTTP `Accept` grammar (q-values,
/// parameters) is out of scope here; we only need to know which
/// shapes the agent will accept.
fn parse_accept_shapes(accept: Option<&str>) -> Vec<ContentShape> {
    let Some(a) = accept else {
        return Vec::new();
    };
    let mut shapes = Vec::new();
    for raw in a.split(',') {
        let mime = raw.split(';').next().unwrap_or("").trim();
        if mime.is_empty() {
            continue;
        }
        let shape = match mime {
            "text/html" | "application/xhtml+xml" => Some(ContentShape::Html),
            "text/markdown" => Some(ContentShape::Markdown),
            "application/json" | "application/ld+json" => Some(ContentShape::Json),
            "application/pdf" => Some(ContentShape::Pdf),
            "*/*" => None, // wildcard matches everything; expressed as empty list
            _ => None,
        };
        if let Some(s) = shape {
            if !shapes.contains(&s) {
                shapes.push(s);
            }
        }
    }
    shapes
}

/// Build the structured 402 body returned to the agent.
fn build_402_body(
    peer_host: &str,
    reason: BlockReason,
    route: &PricedRoute,
    max_per_request_micros: Option<u64>,
    daily_budget_micros: Option<u64>,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "error": "peer_pricing_preflight",
        "reason": reason.as_str(),
        "peer_host": peer_host,
        "route_pattern": route.route_pattern,
        "price_micros": route.price_micros,
        "currency": route.currency,
        "shape": route.shape.as_str(),
    });
    if let Some(agent) = &route.agent_id {
        body["agent_id"] = serde_json::Value::String(agent.clone());
    }
    if let Some(preview) = route.free_preview_bytes {
        body["free_preview_bytes"] = serde_json::Value::from(preview);
    }
    if let Some(max) = max_per_request_micros {
        body["max_price_per_request_micros"] = serde_json::Value::from(max);
    }
    if let Some(daily) = daily_budget_micros {
        body["daily_budget_micros"] = serde_json::Value::from(daily);
    }
    body
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Recording fetcher backed by a single fixture body so tests can
    /// count how many times the policy hit the peer.
    struct RecordingFetcher {
        body: Option<Vec<u8>>,
        calls: Arc<AtomicUsize>,
    }

    impl RecordingFetcher {
        fn new(body: Option<&str>) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    body: body.map(|s| s.as_bytes().to_vec()),
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl ManifestFetcher for RecordingFetcher {
        fn fetch(&self, _peer_host: &str) -> FetchResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.body {
                Some(b) => FetchResult::Ok(b.clone()),
                None => FetchResult::NotPublished,
            }
        }
    }

    fn fixture_manifest() -> String {
        // Hand-rolled to keep the tests independent of the
        // projections renderer's whitespace quirks.
        "# sitename: peer.example\n\
         # version: 1\n\
         # payment: pay-per-request\n\
         # shapes: html,markdown,json\n\
         \n\
         # peer.example\n\
         \n\
         ## Priced routes\n\
         \n\
         - `/articles/*` - agent `*`, shape `html`, price 0.005000 USD\n\
         - `/articles/*` - agent `*`, shape `markdown`, price 0.002000 USD\n\
         - `/data/*` - agent `*`, shape `json`, price 0.050000 USD\n"
            .to_string()
    }

    #[test]
    fn allows_when_under_budget() {
        let (fetcher, calls) = RecordingFetcher::new(Some(&fixture_manifest()));
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: Some(0.01),
            daily_budget_micros: Some(10_000_000),
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Allow,
        })
        .unwrap();

        let decision = policy.evaluate(
            "peer.example",
            "/articles/intro",
            Some("text/markdown"),
            &fetcher,
        );
        match decision {
            PreflightDecision::Allow {
                matched_route: Some(route),
            } => {
                assert_eq!(route.route_pattern, "/articles/*");
                assert_eq!(route.shape, ContentShape::Markdown);
                assert_eq!(route.price_micros, 2000);
            }
            other => panic!("expected Allow with route, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(policy.spent_today_micros(), 2000);
    }

    #[test]
    fn blocks_when_over_per_request_budget() {
        let (fetcher, _) = RecordingFetcher::new(Some(&fixture_manifest()));
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: Some(0.001), // 1000 micros
            daily_budget_micros: None,
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Allow,
        })
        .unwrap();

        let decision = policy.evaluate(
            "peer.example",
            "/data/users",
            Some("application/json"),
            &fetcher,
        );
        match decision {
            PreflightDecision::Block { reason, body } => {
                assert_eq!(reason, BlockReason::OverPerRequestBudget);
                assert_eq!(body["reason"], "over_per_request_budget");
                assert_eq!(body["peer_host"], "peer.example");
                assert_eq!(body["route_pattern"], "/data/*");
                assert_eq!(body["price_micros"], 50_000);
                assert_eq!(body["shape"], "json");
                assert_eq!(body["currency"], "USD");
            }
            other => panic!("expected Block, got {other:?}"),
        }
        // Blocked calls do not accrue daily spend.
        assert_eq!(policy.spent_today_micros(), 0);
    }

    #[test]
    fn blocks_when_over_daily_budget() {
        let (fetcher, _) = RecordingFetcher::new(Some(&fixture_manifest()));
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: Some(1.0),
            daily_budget_micros: Some(3000), // 0.003 USD
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Allow,
        })
        .unwrap();

        // First call (2000 micros) authorises.
        let d1 = policy.evaluate(
            "peer.example",
            "/articles/one",
            Some("text/markdown"),
            &fetcher,
        );
        assert!(matches!(d1, PreflightDecision::Allow { .. }));

        // Second call (another 2000 micros) tips us over 3000.
        let d2 = policy.evaluate(
            "peer.example",
            "/articles/two",
            Some("text/markdown"),
            &fetcher,
        );
        match d2 {
            PreflightDecision::Block { reason, body } => {
                assert_eq!(reason, BlockReason::OverDailyBudget);
                assert_eq!(body["reason"], "over_daily_budget");
                assert_eq!(body["daily_budget_micros"], 3000);
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn passes_through_when_no_route_matches() {
        let (fetcher, _) = RecordingFetcher::new(Some(&fixture_manifest()));
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: Some(0.001),
            daily_budget_micros: Some(10),
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Allow,
        })
        .unwrap();

        // /other is not in the manifest, so the policy allows without
        // charging.
        let decision = policy.evaluate("peer.example", "/other", None, &fetcher);
        assert!(matches!(
            decision,
            PreflightDecision::Allow {
                matched_route: None
            }
        ));
        assert_eq!(policy.spent_today_micros(), 0);
    }

    #[test]
    fn caches_manifest_within_ttl() {
        let (fetcher, calls) = RecordingFetcher::new(Some(&fixture_manifest()));
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: Some(0.01),
            daily_budget_micros: None,
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Allow,
        })
        .unwrap();

        for _ in 0..5 {
            let _ = policy.evaluate(
                "peer.example",
                "/articles/x",
                Some("text/markdown"),
                &fetcher,
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn caches_no_manifest_with_short_ttl() {
        let (fetcher, calls) = RecordingFetcher::new(None);
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: None,
            daily_budget_micros: None,
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Allow,
        })
        .unwrap();

        for _ in 0..3 {
            let _ = policy.evaluate("peer.example", "/x", None, &fetcher);
        }
        // The sentinel cache means we hit the fetcher exactly once
        // even though the peer publishes no manifest.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn on_no_manifest_block_short_circuits() {
        let (fetcher, _) = RecordingFetcher::new(None);
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: None,
            daily_budget_micros: None,
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Block,
        })
        .unwrap();

        let decision = policy.evaluate("peer.example", "/x", None, &fetcher);
        match decision {
            PreflightDecision::Block { reason, body } => {
                assert_eq!(reason, BlockReason::NoManifest);
                assert_eq!(body["reason"], "no_manifest");
                assert_eq!(body["peer_host"], "peer.example");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn tiered_choice_prefers_cheapest_satisfying_accept() {
        let (fetcher, _) = RecordingFetcher::new(Some(&fixture_manifest()));
        let policy = PeerPricingPreflightPolicy::with_config(PeerPricingPreflightConfig {
            max_price_per_request: Some(0.01),
            daily_budget_micros: None,
            cache_ttl: None,
            on_no_manifest: OnNoManifest::Allow,
        })
        .unwrap();

        // Agent accepts both markdown and html; markdown is cheaper.
        let decision = policy.evaluate(
            "peer.example",
            "/articles/intro",
            Some("text/html,text/markdown;q=0.8"),
            &fetcher,
        );
        match decision {
            PreflightDecision::Allow {
                matched_route: Some(route),
            } => {
                assert_eq!(route.shape, ContentShape::Markdown);
                assert_eq!(route.price_micros, 2000);
            }
            other => panic!("expected markdown allow, got {other:?}"),
        }
    }

    #[test]
    fn cache_ttl_config_parses_human_friendly_form() {
        let cfg: PeerPricingPreflightConfig = serde_json::from_value(serde_json::json!({
            "max_price_per_request": 0.01,
            "daily_budget_micros": 10_000_000u64,
            "cache_ttl": "30m",
            "on_no_manifest": "allow",
        }))
        .unwrap();
        let policy = PeerPricingPreflightPolicy::with_config(cfg).unwrap();
        assert_eq!(policy.cache_ttl(), Duration::from_secs(1800));
    }

    #[test]
    fn from_config_round_trips_yaml_shape() {
        let raw = r#"
max_price_per_request: 0.01
daily_budget_micros: 10000000
cache_ttl: 1h
on_no_manifest: allow
"#;
        let value: serde_json::Value = serde_yaml::from_str(raw).unwrap();
        let policy = PeerPricingPreflightPolicy::from_config(value).unwrap();
        assert_eq!(policy.cache_ttl(), Duration::from_secs(3600));
    }

    #[test]
    fn route_matches_supports_literal_and_wildcard() {
        assert!(route_matches("/a", "/a"));
        assert!(!route_matches("/a", "/a/"));
        assert!(route_matches("/a/*", "/a/"));
        assert!(route_matches("/a/*", "/a/b/c"));
        assert!(!route_matches("/a/*", "/b"));
    }
}
