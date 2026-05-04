//! WAF rule-feed subscriber.
//!
//! Hot-loads signed rule bundles published by the enterprise feed
//! service and exposes the current [`RuleSet`] to the WAF policy
//! evaluator via an [`arc_swap::ArcSwap`] snapshot. In-flight requests
//! see a stable view; updates land atomically.
//!
//! # Protocol contract
//!
//! The publisher is out of scope for this OSS crate; this module only
//! consumes the bundle. Two transports are supported:
//!
//! ## HTTP polling
//!
//! ```text
//! GET https://<feed-host>/waf/rules/<channel>?after=<version>
//! Authorization: Bearer <token>
//! ```
//!
//! Returns one of:
//! - `200 OK` with `X-SBProxy-Feed-Sig: <hex hmac-sha256>` over the raw
//!   body, plus a JSON payload shaped like [`SignedBundle`].
//! - `304 Not Modified` when the publisher has nothing newer than
//!   `after=<version>`.
//!
//! ## Redis Streams
//!
//! ```text
//! XREAD COUNT 10 BLOCK 5000 STREAMS waf:rules:<channel> $
//! ```
//!
//! Each entry's fields are `version`, `bundle` (JSON [`SignedBundle`]
//! payload), and `signature` (hex HMAC-SHA256 over the JSON bundle
//! string).
//!
//! ## Bundle shape
//!
//! ```json
//! {
//!   "version": "2026-04-28T12:00:00Z",
//!   "channel": "owasp-crs-paranoia-4",
//!   "expires_at": "2026-05-28T00:00:00Z",
//!   "rules": [
//!     {
//!       "id": "942100",
//!       "paranoia": 4,
//!       "category": "sqli",
//!       "pattern": "(?i)\\bunion\\s+select\\b",
//!       "action": "block",
//!       "severity": "critical"
//!     }
//!   ]
//! }
//! ```
//!
//! # Failure semantics
//!
//! - Signature failure: log + drop the bundle. Last-good remains live.
//! - Fetch failure (network, HTTP non-2xx, parse error): warn + retain
//!   last-good. When [`WafFeedConfig::fallback_to_static`] is `false`,
//!   a `WafFeedDown` event is emitted and the rule set is cleared.
//! - Bundle older than [`WafFeedConfig::max_age`]: rejected as stale.
//! - Last-good cache: on every successful fetch the raw bundle JSON
//!   plus its signature are persisted to
//!   `<cache_dir>/waf-feed-<channel>.json` so a cold start can hot-load
//!   the previous good corpus when the feed is unreachable.
//!
//! # Lifecycle
//!
//! Background polling / XREAD tasks are spawned on the process-wide
//! [`WAF_FEED_TASKS`] tracker. Graceful shutdown drivers call
//! [`super::shutdown_waf_feed_tasks`] to drain them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
// `KeyInit` provides `new_from_slice`; `Mac` provides `update`, `finalize`,
// and `verify_slice`. Both come from `digest` re-exports in `hmac 0.13`.
use hmac::{Hmac, KeyInit, Mac};
use regex::Regex;
// `Serialize` is enabled for the bundle types so test fixtures (and any
// future internal call site that wants to round-trip a synthetic bundle
// to/from JSON without going through the wire) can rebuild the exact
// byte stream the publisher produced.
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio_util::task::TaskTracker;

/// Process-wide tracker for background WAF feed tasks. Spawn handles on
/// this so the graceful-shutdown driver in
/// [`super::shutdown_waf_feed_tasks`] can drain them on teardown. Lazy
/// so callers that never enable a feed pay no cost.
pub static WAF_FEED_TASKS: std::sync::LazyLock<TaskTracker> =
    std::sync::LazyLock::new(TaskTracker::new);

/// Default HTTP poll interval when none is configured.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Default acceptable bundle age. Bundles whose `version` timestamp is
/// older than this are treated as stale and ignored.
pub const DEFAULT_MAX_AGE_SECS: u64 = 86_400;

/// Default Redis XREAD block window. Five seconds matches the publisher
/// default and keeps the loop responsive to shutdown.
pub const DEFAULT_REDIS_BLOCK_MS: u64 = 5_000;

/// Header name carrying the HMAC-SHA256 signature over the HTTP feed
/// response body.
pub const FEED_SIGNATURE_HEADER: &str = "X-SBProxy-Feed-Sig";

// --- Config ---

/// Feed transport selection.
///
/// The `transport` field on [`WafFeedConfig`] is a string in the YAML
/// schema (`"http"` / `"redis"`) so we deserialize via [`String`] and
/// resolve to this enum at subscribe time. That keeps the config
/// surface stable even if we add a third transport later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafFeedTransport {
    /// Periodic HTTP GETs against the feed URL.
    Http,
    /// Redis Streams `XREAD BLOCK` against the configured stream.
    Redis,
}

/// Subscriber-side configuration. Mirrors the YAML schema documented
/// in `docs/features.md` under the WAF rule-feed section.
#[derive(Debug, Clone, Deserialize)]
pub struct WafFeedConfig {
    /// Master switch. `false` disables the subscriber entirely; the
    /// subscriber is never spawned and [`WafFeedSubscriber::current_rules`]
    /// returns an empty [`RuleSet`].
    #[serde(default)]
    pub enabled: bool,

    /// Transport to use. `"http"` (default) or `"redis"`.
    #[serde(default = "default_transport")]
    pub transport: String,

    /// HTTP feed URL. Required when `transport == "http"`.
    #[serde(default)]
    pub url: Option<String>,

    /// Redis connection URL (e.g. `redis://localhost:6379/0`). Required
    /// when `transport == "redis"`.
    #[serde(default)]
    pub redis_url: Option<String>,

    /// Redis stream name. Required when `transport == "redis"`.
    #[serde(default)]
    pub redis_stream: Option<String>,

    /// Channel identifier. Used for the cache filename and for the
    /// `WafFeedDown` event payload. Required regardless of transport.
    #[serde(default)]
    pub channel: Option<String>,

    /// Environment variable holding the bearer token for HTTP feeds.
    #[serde(default)]
    pub auth_token_env: Option<String>,

    /// Environment variable holding the HMAC signing key. The
    /// publisher and subscriber must share this key out of band.
    /// Required when [`Self::enabled`] is true.
    #[serde(default)]
    pub signature_key_env: Option<String>,

    /// HTTP poll interval in seconds. Ignored when `transport == "redis"`.
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,

    /// Reject bundles whose `version` is older than this many seconds.
    /// `0` disables the staleness gate.
    #[serde(default = "default_max_age")]
    pub max_age: u64,

    /// When `true` (default) and the feed is unreachable, the
    /// subscriber keeps serving the last-good rule set. When `false`,
    /// the rule set is cleared and a `WafFeedDown` event is emitted so
    /// upstream operators know the proxy is running without dynamic
    /// rules.
    #[serde(default = "default_fallback_to_static")]
    pub fallback_to_static: bool,

    /// Last-good cache directory. Defaults to
    /// `~/.cache/sbproxy/` if `None`. The bundle file is named
    /// `waf-feed-<channel>.json` underneath this directory.
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,

    /// Optional override of the cache file path. When set, this wins
    /// over [`Self::cache_dir`] + channel-derived filename. Mostly
    /// useful in tests.
    #[serde(default)]
    pub cache_file: Option<PathBuf>,
}

fn default_transport() -> String {
    "http".to_string()
}
fn default_poll_interval() -> u64 {
    DEFAULT_POLL_INTERVAL_SECS
}
fn default_max_age() -> u64 {
    DEFAULT_MAX_AGE_SECS
}
fn default_fallback_to_static() -> bool {
    true
}

impl WafFeedConfig {
    /// Resolve the configured transport string to a typed variant.
    pub fn transport_kind(&self) -> Result<WafFeedTransport> {
        match self.transport.as_str() {
            "http" => Ok(WafFeedTransport::Http),
            "redis" => Ok(WafFeedTransport::Redis),
            other => anyhow::bail!("unknown waf feed transport: {}", other),
        }
    }

    /// Compute the path the subscriber writes the last-good bundle to
    /// after every successful fetch.
    pub fn cache_path(&self) -> PathBuf {
        if let Some(p) = &self.cache_file {
            return p.clone();
        }
        let dir = self.cache_dir.clone().unwrap_or_else(default_cache_dir);
        let channel = self.channel.as_deref().unwrap_or("default");
        // Replace any path-separator characters in the channel name to
        // keep the filename single-segment.
        let safe = channel.replace(['/', '\\'], "_");
        dir.join(format!("waf-feed-{}.json", safe))
    }
}

fn default_cache_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".cache");
        p.push("sbproxy");
        p
    } else {
        PathBuf::from("/tmp/sbproxy-cache")
    }
}

// --- Bundle types ---

/// Action a rule applies on match. Mirrors the publisher contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedRuleAction {
    /// Block the request with a 403. Default when the publisher omits
    /// the field.
    #[default]
    Block,
    /// Log a warning but pass the request through.
    Log,
}

/// Severity tag from the publisher. Used for log enrichment only;
/// matching/blocking is governed by [`FeedRuleAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedRuleSeverity {
    /// Informational rule, primarily useful in log mode.
    Info,
    /// Low-severity alert.
    Low,
    /// Medium-severity alert. Default when the publisher omits the
    /// field.
    #[default]
    Medium,
    /// High-severity alert.
    High,
    /// Critical attack class.
    Critical,
}

/// One rule in a published bundle.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeedRule {
    /// Stable rule identifier (e.g. `"942100"`).
    pub id: String,
    /// Paranoia level, gated by [`crate::policy::WafPolicy::paranoia`].
    #[serde(default = "default_rule_paranoia")]
    pub paranoia: u8,
    /// Free-form category tag, used for log enrichment.
    #[serde(default)]
    pub category: String,
    /// Regex pattern compiled at parse time.
    pub pattern: String,
    /// What to do when the pattern matches.
    #[serde(default)]
    pub action: FeedRuleAction,
    /// Severity tag for log enrichment.
    #[serde(default)]
    pub severity: FeedRuleSeverity,
}

fn default_rule_paranoia() -> u8 {
    1
}

/// JSON shape of a published bundle. The wire format is the body of an
/// HTTP 200 response or the `bundle` field of a Redis stream entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedBundle {
    /// ISO-8601 (or any RFC 3339) timestamp identifying this revision.
    pub version: String,
    /// Channel identifier the bundle belongs to.
    #[serde(default)]
    pub channel: String,
    /// Optional explicit expiration. Independent of [`WafFeedConfig::max_age`].
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Rules in this bundle.
    #[serde(default)]
    pub rules: Vec<FeedRule>,
}

// --- Compiled rule set ---

/// One compiled rule. Owns a pre-parsed [`Regex`] so the hot path skips
/// per-request regex compilation.
#[derive(Debug)]
pub struct CompiledRule {
    /// Stable rule identifier from the bundle.
    pub id: String,
    /// Paranoia level (1-4).
    pub paranoia: u8,
    /// Category tag.
    pub category: String,
    /// Action on match.
    pub action: FeedRuleAction,
    /// Severity tag.
    pub severity: FeedRuleSeverity,
    /// Compiled regex.
    pub regex: Regex,
}

/// Snapshot of the currently-active rule corpus. [`Arc`]-shared so
/// in-flight requests can hold a stable reference across an update.
#[derive(Debug, Default)]
pub struct RuleSet {
    /// Bundle version string, propagated from [`SignedBundle::version`].
    pub version: String,
    /// Channel name.
    pub channel: String,
    /// Compiled rules, in publisher order.
    pub rules: Vec<CompiledRule>,
}

impl RuleSet {
    /// Build a [`RuleSet`] from a parsed bundle, compiling each rule's
    /// regex. Rules with invalid regexes are dropped with a warning so
    /// a single bad entry does not poison the whole bundle.
    pub fn from_bundle(bundle: SignedBundle) -> Self {
        let mut rules = Vec::with_capacity(bundle.rules.len());
        for r in bundle.rules {
            match Regex::new(&r.pattern) {
                Ok(regex) => rules.push(CompiledRule {
                    id: r.id,
                    paranoia: r.paranoia.clamp(1, 4),
                    category: r.category,
                    action: r.action,
                    severity: r.severity,
                    regex,
                }),
                Err(e) => {
                    tracing::warn!(
                        rule_id = %r.id,
                        pattern = %r.pattern,
                        error = %e,
                        "WAF feed: dropping rule with invalid regex"
                    );
                }
            }
        }
        Self {
            version: bundle.version,
            channel: bundle.channel,
            rules,
        }
    }

    /// Number of compiled rules in the snapshot.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when the rule set carries no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

// --- Subscriber ---

/// Owner of the background fetch task and the live rule snapshot.
///
/// One subscriber is intended per origin per channel; the WAF policy
/// holds an [`Arc`] reference and consults [`Self::current_rules`] on
/// each request.
pub struct WafFeedSubscriber {
    config: WafFeedConfig,
    rules: ArcSwap<RuleSet>,
    /// Shared with the background task so it can also write updates
    /// atomically. Cloned through [`Arc`] to keep the public API
    /// `&self`.
    last_good_version: parking_lot::Mutex<Option<String>>,
    /// Guard that ensures the background poller / XREAD loop is
    /// spawned exactly once. The proxy compiles config in a sync
    /// context (before Pingora's runtime exists), so spawning at
    /// `new()` time would be a no-op. Instead, the first hot-path
    /// request that lands inside a Tokio runtime calls
    /// [`Self::ensure_started`] which performs the spawn behind this
    /// `Once`.
    started: std::sync::Once,
}

impl std::fmt::Debug for WafFeedSubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.rules.load();
        f.debug_struct("WafFeedSubscriber")
            .field("channel", &snap.channel)
            .field("version", &snap.version)
            .field("rule_count", &snap.rules.len())
            .finish()
    }
}

impl WafFeedSubscriber {
    /// Build a subscriber. When the feed is enabled, the constructor
    /// hot-loads the last-good cache (if present) so a cold proxy
    /// start with the publisher unreachable still has a working
    /// corpus. The background fetch task is *not* spawned here; see
    /// [`Self::ensure_started`].
    ///
    /// Spawn-on-construct does not work because config compile runs
    /// before Pingora boots its Tokio runtime. The request hot path
    /// (which always runs inside the runtime) is responsible for
    /// kicking the lazy spawn through [`Self::ensure_started`].
    pub fn new(config: WafFeedConfig) -> Result<Arc<Self>> {
        // Validate the transport up front so misconfiguration fails
        // config compile rather than waiting for the first request.
        if config.enabled {
            let _ = config.transport_kind()?;
        }
        let me = Arc::new(Self {
            config,
            rules: ArcSwap::from_pointee(RuleSet::default()),
            last_good_version: parking_lot::Mutex::new(None),
            started: std::sync::Once::new(),
        });
        if !me.config.enabled {
            return Ok(me);
        }

        // Best-effort hot-load from the last-good cache. A missing or
        // corrupt cache is not fatal; the background task will overwrite
        // it on the next successful fetch.
        if let Err(e) = me.hot_load_cache() {
            tracing::debug!(error = %e, "WAF feed: no usable last-good cache");
        }
        Ok(me)
    }

    /// Spawn the transport-specific background task once a Tokio
    /// runtime is available. Idempotent: subsequent calls are no-ops.
    /// Called lazily from the WAF request path so the task starts
    /// inside Pingora's runtime, since OSS config compile runs in a
    /// sync context where `tokio::spawn` would panic.
    pub fn ensure_started(self: &Arc<Self>) {
        if !self.config.enabled {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        // Snapshot the transport up front so the closure sees a
        // resolved value rather than re-resolving at spawn time.
        let kind = match self.config.transport_kind() {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "WAF feed: invalid transport at spawn time");
                return;
            }
        };
        let me = Arc::clone(self);
        self.started.call_once(|| match kind {
            WafFeedTransport::Http => {
                let handle = me.clone();
                WAF_FEED_TASKS.spawn(async move {
                    handle.run_http_loop().await;
                });
                tracing::info!(
                    channel = me.config.channel.as_deref().unwrap_or(""),
                    "WAF feed: HTTP subscriber started"
                );
            }
            WafFeedTransport::Redis => {
                let handle = me.clone();
                WAF_FEED_TASKS.spawn(async move {
                    handle.run_redis_loop().await;
                });
                tracing::info!(
                    channel = me.config.channel.as_deref().unwrap_or(""),
                    "WAF feed: Redis subscriber started"
                );
            }
        });
    }

    /// Snapshot of the currently active rule set. Cheap (one
    /// `ArcSwap::load`); safe to call on the hot path. Holders see a
    /// stable view even if the subscriber rotates in a new bundle
    /// mid-request.
    pub fn current_rules(&self) -> Arc<RuleSet> {
        self.rules.load_full()
    }

    /// Apply a new rule set. Used by the background loop and by tests
    /// that want to inject a synthetic bundle without going over the
    /// wire.
    pub fn apply_bundle(&self, bundle: SignedBundle, raw: &[u8]) -> Result<()> {
        // Reject stale bundles up front.
        if let Some(age) = self.config_max_age_check_secs() {
            if let Some(age_secs) = bundle_age_secs(&bundle.version) {
                if age_secs > age {
                    anyhow::bail!(
                        "bundle version '{}' is {}s old, exceeds max_age={}",
                        bundle.version,
                        age_secs,
                        age
                    );
                }
            }
        }

        let version = bundle.version.clone();
        let rule_set = RuleSet::from_bundle(bundle);
        let count = rule_set.len();
        self.rules.store(Arc::new(rule_set));
        *self.last_good_version.lock() = Some(version.clone());

        // Persist last-good. Failure here is logged but not fatal: an
        // unwriteable cache directory must not stall a healthy feed.
        if let Err(e) = self.write_cache(raw) {
            tracing::warn!(error = %e, "WAF feed: failed to persist last-good cache");
        }
        tracing::info!(
            version = %version,
            rules = count,
            channel = self.config.channel.as_deref().unwrap_or(""),
            "WAF feed: applied bundle"
        );
        Ok(())
    }

    fn config_max_age_check_secs(&self) -> Option<u64> {
        if self.config.max_age == 0 {
            None
        } else {
            Some(self.config.max_age)
        }
    }

    /// HTTP polling loop. Runs forever until the surrounding tracker is
    /// closed and the task is dropped.
    async fn run_http_loop(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.poll_interval.max(1));
        let url = match self.config.url.as_deref() {
            Some(u) => u.to_string(),
            None => {
                tracing::error!("WAF feed: HTTP transport selected but no URL configured");
                return;
            }
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        loop {
            let after = self.last_good_version.lock().clone();
            match self.fetch_http_once(&client, &url, after.as_deref()).await {
                Ok(FetchOutcome::Updated) => {}
                Ok(FetchOutcome::NotModified) => {
                    tracing::trace!("WAF feed: 304 Not Modified");
                }
                Err(e) => {
                    tracing::warn!(
                        url = %url,
                        error = %e,
                        "WAF feed: HTTP fetch failed; keeping last-good"
                    );
                    if !self.config.fallback_to_static {
                        // Operator opted out of last-good behaviour;
                        // surface the failure by clearing the rule set
                        // and emitting a structured event.
                        self.rules.store(Arc::new(RuleSet::default()));
                        tracing::error!(
                            event = "WafFeedDown",
                            channel = self.config.channel.as_deref().unwrap_or(""),
                            "WAF feed: cleared rule set per fallback_to_static=false"
                        );
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// One HTTP fetch attempt. Returns whether a fresh bundle was
    /// applied.
    async fn fetch_http_once(
        &self,
        client: &reqwest::Client,
        url: &str,
        after: Option<&str>,
    ) -> Result<FetchOutcome> {
        let mut req = client.get(url);
        if let Some(v) = after {
            req = req.query(&[("after", v)]);
        }
        if let Some(env_name) = &self.config.auth_token_env {
            if let Ok(token) = std::env::var(env_name) {
                req = req.header("Authorization", format!("Bearer {}", token));
            }
        }

        let resp = req.send().await.context("WAF feed: HTTP send failed")?;
        if resp.status().as_u16() == 304 {
            return Ok(FetchOutcome::NotModified);
        }
        if !resp.status().is_success() {
            anyhow::bail!("WAF feed: non-2xx status {}", resp.status());
        }

        let signature = resp
            .headers()
            .get(FEED_SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("WAF feed: missing {} header", FEED_SIGNATURE_HEADER))?;
        let body = resp.bytes().await.context("WAF feed: read body failed")?;
        self.verify_and_apply(&body, &signature)?;
        Ok(FetchOutcome::Updated)
    }

    /// Redis Streams loop. Connects lazily and reconnects on error.
    async fn run_redis_loop(self: Arc<Self>) {
        let stream = match self.config.redis_stream.as_deref() {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("WAF feed: Redis transport selected but no stream configured");
                return;
            }
        };
        let url = match self.config.redis_url.as_deref() {
            Some(u) => u.to_string(),
            None => {
                tracing::error!("WAF feed: Redis transport selected but no redis_url configured");
                return;
            }
        };

        // `last_id` advances as new entries arrive. We start at `$` so
        // the consumer only sees entries published *after* the
        // subscriber starts. The static cache feeds the cold-start gap.
        let mut last_id = "$".to_string();
        loop {
            match self.run_redis_iter(&url, &stream, &mut last_id).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(
                        url = %url,
                        stream = %stream,
                        error = %e,
                        "WAF feed: Redis loop error; reconnecting"
                    );
                    if !self.config.fallback_to_static {
                        self.rules.store(Arc::new(RuleSet::default()));
                        tracing::error!(
                            event = "WafFeedDown",
                            channel = self.config.channel.as_deref().unwrap_or(""),
                            "WAF feed: cleared rule set per fallback_to_static=false"
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    async fn run_redis_iter(&self, url: &str, stream: &str, last_id: &mut String) -> Result<()> {
        use redis::AsyncCommands;
        let client = redis::Client::open(url).context("WAF feed: open redis client")?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .context("WAF feed: connect redis")?;

        loop {
            // XREAD COUNT 10 BLOCK 5000 STREAMS <stream> <last_id>
            let opts = redis::streams::StreamReadOptions::default()
                .count(10)
                .block(DEFAULT_REDIS_BLOCK_MS as usize);
            let reply: Option<redis::streams::StreamReadReply> = conn
                .xread_options(&[stream], &[last_id.as_str()], &opts)
                .await
                .context("WAF feed: XREAD failed")?;
            let Some(reply) = reply else {
                // BLOCK timeout, no new entries. Loop to keep waiting.
                continue;
            };
            for key in reply.keys {
                for entry in key.ids {
                    *last_id = entry.id.clone();
                    let bundle_json = bytes_field(&entry.map, "bundle");
                    let signature = bytes_field(&entry.map, "signature");
                    let (Some(bundle_json), Some(signature)) = (bundle_json, signature) else {
                        tracing::warn!(
                            id = %entry.id,
                            "WAF feed: redis entry missing bundle/signature fields"
                        );
                        continue;
                    };
                    let signature_str = match std::str::from_utf8(&signature) {
                        Ok(s) => s,
                        Err(_) => {
                            tracing::warn!(
                                id = %entry.id,
                                "WAF feed: signature field is not UTF-8"
                            );
                            continue;
                        }
                    };
                    if let Err(e) = self.verify_and_apply(&bundle_json, signature_str) {
                        tracing::warn!(
                            id = %entry.id,
                            error = %e,
                            "WAF feed: rejected redis entry"
                        );
                    }
                }
            }
        }
    }

    /// Verify the HMAC over `raw`, parse it as a [`SignedBundle`], and
    /// hot-swap the rule set on success.
    fn verify_and_apply(&self, raw: &[u8], signature_hex: &str) -> Result<()> {
        let key_env = self
            .config
            .signature_key_env
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("signature_key_env not configured"))?;
        let key = std::env::var(key_env)
            .with_context(|| format!("WAF feed: signature key env var '{}' not set", key_env))?;
        verify_signature(raw, signature_hex, key.as_bytes())
            .context("WAF feed: signature verification failed")?;
        let bundle: SignedBundle =
            serde_json::from_slice(raw).context("WAF feed: bundle JSON parse failed")?;
        self.apply_bundle(bundle, raw)
    }

    /// Try to load the last-good bundle from disk. Used at startup so a
    /// proxy reboot during a feed outage still has a working corpus.
    fn hot_load_cache(&self) -> Result<()> {
        let path = self.config.cache_path();
        let raw = std::fs::read(&path).with_context(|| format!("read cache {}", path.display()))?;
        // The cache file stores the *raw* bundle JSON exactly as
        // received over the wire; we re-verify against the configured
        // signing key so a tampered cache cannot smuggle rules in.
        // The signature we check against is stored alongside the
        // bundle in a sidecar `<path>.sig` file written atomically by
        // [`Self::write_cache`].
        let sig_path = path.with_extension("sig");
        let signature = std::fs::read_to_string(&sig_path)
            .with_context(|| format!("read cache sig {}", sig_path.display()))?;
        let signature = signature.trim().to_string();
        self.verify_and_apply(&raw, &signature)
    }

    /// Persist the current bundle (raw JSON + signature sidecar) to the
    /// configured cache directory. Atomic-ish: writes to a `.tmp`
    /// sibling and renames into place.
    fn write_cache(&self, raw: &[u8]) -> Result<()> {
        let path = self.config.cache_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create cache dir {}", parent.display()))?;
        }
        // Recompute the signature so the on-disk artifact is
        // self-contained. Using the same signing key the publisher uses
        // means the next process restart can hot-load it through the
        // standard verify path.
        let key_env = self
            .config
            .signature_key_env
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("signature_key_env not configured"))?;
        let key = std::env::var(key_env)
            .with_context(|| format!("WAF feed: signature key env var '{}' not set", key_env))?;
        let signature = compute_signature(raw, key.as_bytes());

        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, raw).with_context(|| format!("write cache {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("rename cache to {}", path.display()))?;
        let sig_path = path.with_extension("sig");
        std::fs::write(&sig_path, signature)
            .with_context(|| format!("write cache sig {}", sig_path.display()))?;
        Ok(())
    }
}

/// Internal HTTP fetch outcome.
enum FetchOutcome {
    /// A new bundle was fetched, verified, and applied.
    Updated,
    /// The publisher returned 304 Not Modified.
    NotModified,
}

// --- Helpers ---

/// Extract a Redis stream entry field as raw bytes. Stream values
/// arrive as [`redis::Value::Data`] (RESP2 bulk-string) or
/// [`redis::Value::Status`] (inline string); anything else is
/// treated as missing.
fn bytes_field(
    map: &std::collections::HashMap<String, redis::Value>,
    name: &str,
) -> Option<Vec<u8>> {
    match map.get(name)? {
        redis::Value::Data(b) => Some(b.clone()),
        redis::Value::Status(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

// --- Signature primitives ---

type HmacSha256 = Hmac<Sha256>;

/// Compute the hex-encoded HMAC-SHA256 of `body` under `key`.
pub fn compute_signature(body: &[u8], key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, body);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a hex-encoded HMAC-SHA256 signature.
pub fn verify_signature(body: &[u8], signature_hex: &str, key: &[u8]) -> Result<()> {
    let expected = hex::decode(signature_hex)
        .with_context(|| format!("invalid hex signature: {}", signature_hex))?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, body);
    mac.verify_slice(&expected)
        .map_err(|_| anyhow::anyhow!("signature mismatch"))?;
    Ok(())
}

/// Best-effort age-of-bundle calculation. Accepts the RFC 3339 / ISO
/// 8601 timestamps the publisher emits. Returns `None` for inputs we
/// cannot parse rather than rejecting the bundle outright; the
/// staleness gate is a safety net, not the primary defense.
fn bundle_age_secs(version: &str) -> Option<u64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(version).ok()?;
    let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
    let age = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
    age.num_seconds().try_into().ok()
}

/// Resolve a cache file path to a parent directory the test can poke.
/// Exposed for tests; not part of the stable API.
#[doc(hidden)]
pub fn cache_dir_for(config: &WafFeedConfig) -> Option<&Path> {
    config
        .cache_file
        .as_deref()
        .and_then(|p| p.parent())
        .or(config.cache_dir.as_deref())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_bundle(version: &str, rule_id: &str, pattern: &str) -> SignedBundle {
        SignedBundle {
            version: version.to_string(),
            channel: "test".to_string(),
            expires_at: None,
            rules: vec![FeedRule {
                id: rule_id.to_string(),
                paranoia: 1,
                category: "test".to_string(),
                pattern: pattern.to_string(),
                action: FeedRuleAction::Block,
                severity: FeedRuleSeverity::Medium,
            }],
        }
    }

    fn make_subscriber(tmp: &TempDir) -> (Arc<WafFeedSubscriber>, Vec<u8>, String, &'static str) {
        // Use a deterministic env var name per test to avoid races
        // when `cargo test` runs in parallel.
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let key_env: &'static str =
            Box::leak(format!("SBPROXY_FEED_TEST_KEY_{}", n).into_boxed_str());
        std::env::set_var(key_env, "supersecretkey");
        let cache_file = tmp.path().join("cache.json");
        let config = WafFeedConfig {
            enabled: false, // disabled so new() does not spawn background tasks
            transport: "http".to_string(),
            url: Some("http://unused.test/feed".to_string()),
            redis_url: None,
            redis_stream: None,
            channel: Some("test".to_string()),
            auth_token_env: None,
            signature_key_env: Some(key_env.to_string()),
            poll_interval: 60,
            max_age: 0, // disable staleness for unit tests
            fallback_to_static: true,
            cache_dir: None,
            cache_file: Some(cache_file),
        };
        let bundle = make_bundle("2026-04-28T12:00:00Z", "001", r"(?i)union\s+select");
        let raw = serde_json::to_vec(&bundle).unwrap();
        let signature = compute_signature(&raw, b"supersecretkey");
        let sub = WafFeedSubscriber::new(config).expect("subscriber");
        (sub, raw, signature, key_env)
    }

    #[test]
    fn signature_verify_round_trip() {
        let key = b"k";
        let body = b"{\"hello\":\"world\"}";
        let sig = compute_signature(body, key);
        verify_signature(body, &sig, key).expect("good signature");
    }

    #[test]
    fn signature_verify_rejects_tampered_body() {
        let key = b"k";
        let body = b"{\"hello\":\"world\"}";
        let sig = compute_signature(body, key);
        let bad_body = b"{\"hello\":\"WORLD\"}";
        assert!(verify_signature(bad_body, &sig, key).is_err());
    }

    #[test]
    fn signature_verify_rejects_wrong_key() {
        let body = b"payload";
        let sig = compute_signature(body, b"k1");
        assert!(verify_signature(body, &sig, b"k2").is_err());
    }

    #[test]
    fn malformed_bundle_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let (sub, _raw, _sig, _key_env) = make_subscriber(&tmp);
        let bad = b"not json at all";
        let sig = compute_signature(bad, b"supersecretkey");
        let err = sub.verify_and_apply(bad, &sig).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("parse"));
    }

    #[test]
    fn well_formed_bundle_updates_rule_set() {
        let tmp = TempDir::new().unwrap();
        let (sub, raw, sig, _key_env) = make_subscriber(&tmp);
        sub.verify_and_apply(&raw, &sig).expect("apply");
        let snap = sub.current_rules();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.rules[0].id, "001");
        assert!(snap.rules[0].regex.is_match("UNION SELECT secret"));
    }

    #[test]
    fn last_good_persists_across_reload() {
        let tmp = TempDir::new().unwrap();
        // First subscriber writes the cache.
        let (sub, raw, sig, key_env) = make_subscriber(&tmp);
        sub.verify_and_apply(&raw, &sig).expect("apply");
        let cache_file = sub.config.cache_path();
        assert!(cache_file.exists(), "cache file written");
        assert!(
            cache_file.with_extension("sig").exists(),
            "signature sidecar written"
        );

        // Second subscriber points at the same cache file and same env
        // var, with the feed disabled. It should still hot-load the
        // last-good corpus from disk.
        let config = WafFeedConfig {
            enabled: false,
            transport: "http".to_string(),
            url: Some("http://unused.test/feed".to_string()),
            redis_url: None,
            redis_stream: None,
            channel: Some("test".to_string()),
            auth_token_env: None,
            signature_key_env: Some(key_env.to_string()),
            poll_interval: 60,
            max_age: 0,
            fallback_to_static: true,
            cache_dir: None,
            cache_file: Some(cache_file),
        };
        let sub2 = WafFeedSubscriber::new(config).expect("subscriber");
        // hot_load_cache is called on construction even when enabled=false?
        // No: the spawn path is gated on enabled, but hot_load_cache
        // only runs for enabled feeds. To exercise the cold-start
        // path, force-load explicitly.
        sub2.hot_load_cache().expect("hot load");
        let snap = sub2.current_rules();
        assert_eq!(snap.rules.len(), 1);
        assert_eq!(snap.rules[0].id, "001");
    }

    #[test]
    fn stale_bundle_is_rejected_when_max_age_set() {
        let tmp = TempDir::new().unwrap();
        let (sub, _raw, _sig, _key_env) = make_subscriber(&tmp);
        // Construct a bundle with a very old timestamp.
        let old = SignedBundle {
            version: "2000-01-01T00:00:00Z".to_string(),
            channel: "test".to_string(),
            expires_at: None,
            rules: vec![FeedRule {
                id: "old".to_string(),
                paranoia: 1,
                category: "x".to_string(),
                pattern: "x".to_string(),
                action: FeedRuleAction::Block,
                severity: FeedRuleSeverity::Low,
            }],
        };
        let raw = serde_json::to_vec(&old).unwrap();
        // Borrow internals: raise max_age via a freshly built
        // subscriber so we hit the staleness branch.
        let cache_file = tmp.path().join("stale.json");
        let config = WafFeedConfig {
            enabled: false,
            transport: "http".to_string(),
            url: Some("http://unused.test/feed".to_string()),
            redis_url: None,
            redis_stream: None,
            channel: Some("stale".to_string()),
            auth_token_env: None,
            signature_key_env: sub.config.signature_key_env.clone(),
            poll_interval: 60,
            max_age: 60, // 60s; bundle is decades old
            fallback_to_static: true,
            cache_dir: None,
            cache_file: Some(cache_file),
        };
        let sub2 = WafFeedSubscriber::new(config).unwrap();
        let err = sub2.apply_bundle(old, &raw).unwrap_err();
        assert!(err.to_string().contains("max_age"));
    }

    #[test]
    fn invalid_regex_in_rule_is_dropped() {
        let bundle = SignedBundle {
            version: "v".into(),
            channel: "c".into(),
            expires_at: None,
            rules: vec![
                FeedRule {
                    id: "good".into(),
                    paranoia: 1,
                    category: "x".into(),
                    pattern: "ok".into(),
                    action: FeedRuleAction::Block,
                    severity: FeedRuleSeverity::Low,
                },
                FeedRule {
                    id: "bad".into(),
                    paranoia: 1,
                    category: "x".into(),
                    pattern: "(unbalanced".into(),
                    action: FeedRuleAction::Block,
                    severity: FeedRuleSeverity::Low,
                },
            ],
        };
        let rs = RuleSet::from_bundle(bundle);
        assert_eq!(rs.rules.len(), 1, "invalid regex should be dropped");
        assert_eq!(rs.rules[0].id, "good");
    }
}
