//! Persistent, time-boxed WAF block actions.
//!
//! A client whose request is challenged or denied by the WAF accrues a
//! *strike*. Once the strike count crosses a configured threshold inside
//! a sliding window, the client is placed in a time-boxed block: every
//! subsequent request is rejected up front (before the rule engine even
//! runs) until the block window elapses, after which the client is
//! released automatically.
//!
//! Persistence is the point. The block state outlives a single request
//! and, when a shared [`KVStore`] (Redis) is attached, outlives a single
//! replica: every proxy in the fleet sees the same block. This reuses
//! the existing rate-limit storage stack rather than introducing a new
//! one, so operators who already run Redis for distributed rate limiting
//! get distributed WAF blocks for free.
//!
//! Two tiers back the state machine, mirroring how
//! [`crate::policy::RateLimitPolicy`] degrades from an L2 Redis counter
//! to an in-process token bucket:
//!
//! - **L2 (shared)**: when a [`KVStore`] is attached via
//!   [`WafPolicy::with_block_store`](crate::policy::WafPolicy::with_block_store),
//!   strikes use the store's atomic `incr_with_ttl` and the block marker
//!   uses `put_with_ttl`. TTLs do the expiry; no background sweeper is
//!   needed and the state is visible to every replica.
//! - **L1 (local)**: when no store is attached (the single-replica
//!   default) an in-process map keyed by client tracks strike timestamps
//!   and the block-until instant. Expiry is computed lazily on read so
//!   there is still no sweeper task.
//!
//! The L1 map is bounded by an LRU so an attacker spraying distinct keys
//! (one-off IPs, random api keys) cannot exhaust memory, exactly as the
//! rate limiter bounds its per-key bucket map.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sbproxy_platform::storage::KVStore;
use serde::Deserialize;

/// Default number of WAF/challenge denials that trip a persistent block.
const DEFAULT_STRIKES: u32 = 3;

/// Default sliding window (seconds) over which strikes accumulate.
const DEFAULT_WINDOW_SECS: u64 = 60;

/// Default time-boxed block duration in minutes.
const DEFAULT_BLOCK_MINUTES: u64 = 10;

/// Minimum configurable block duration in minutes.
const MIN_BLOCK_MINUTES: u64 = 1;

/// Maximum configurable block duration in minutes.
const MAX_BLOCK_MINUTES: u64 = 60;

/// Maximum number of distinct client keys tracked in the local (L1) map.
/// Bounds memory under a spray of one-off keys; the least-recently-used
/// entry is evicted past this cap.
const DEFAULT_MAX_KEYS: usize = 100_000;

/// Dimension a persistent block is tracked by. Resolved by the enforcer
/// from the configured `track_by` field and stamped onto metrics so the
/// `key_kind` label is a closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKeyKind {
    /// Track by client IP address (default).
    Ip,
    /// Track by the inbound API key header value.
    ApiKey,
    /// Track by a CEL-derived key.
    Cel,
}

impl BlockKeyKind {
    /// Stable metric/label string. Closed set: `ip`, `api_key`, `cel`.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockKeyKind::Ip => "ip",
            BlockKeyKind::ApiKey => "api_key",
            BlockKeyKind::Cel => "cel",
        }
    }
}

/// Configuration for persistent, time-boxed WAF block actions.
///
/// All fields carry serde defaults so existing WAF configs that omit the
/// `persistent_block` block keep deserialising unchanged (the feature is
/// off unless `enabled: true`).
#[derive(Debug, Clone, Deserialize)]
pub struct PersistentBlockConfig {
    /// Master switch. When `false` (the default) no strikes are recorded
    /// and no client is ever auto-blocked.
    #[serde(default)]
    pub enabled: bool,

    /// Number of WAF/challenge denials within [`Self::window_secs`] that
    /// escalate a client to a time-boxed block. Defaults to 3.
    #[serde(default = "default_strikes")]
    pub strikes: u32,

    /// Sliding window, in seconds, over which strikes accumulate.
    /// Defaults to 60.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// Block duration in minutes. Clamped to the 1-60 range. Defaults to
    /// 10.
    #[serde(default = "default_block_minutes")]
    pub block_minutes: u64,

    /// Dimension to track clients by: `ip` (default), `api_key`, or
    /// `cel`. When `cel`, [`Self::key`] must hold the expression.
    #[serde(default = "default_track_by")]
    pub track_by: String,

    /// CEL expression used to derive the tracking key when
    /// `track_by: cel`. Ignored otherwise.
    #[serde(default)]
    pub key: Option<String>,

    /// Maximum number of distinct client keys held in the local (L1)
    /// map. Defaults to 100k. Ignored on the Redis path (TTLs bound it).
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
}

fn default_strikes() -> u32 {
    DEFAULT_STRIKES
}
fn default_window_secs() -> u64 {
    DEFAULT_WINDOW_SECS
}
fn default_block_minutes() -> u64 {
    DEFAULT_BLOCK_MINUTES
}
fn default_track_by() -> String {
    "ip".to_string()
}
fn default_max_keys() -> usize {
    DEFAULT_MAX_KEYS
}

impl PersistentBlockConfig {
    /// Effective block window as a [`Duration`], with `block_minutes`
    /// clamped to the supported 1-60 minute range.
    pub fn block_duration(&self) -> Duration {
        let mins = self
            .block_minutes
            .clamp(MIN_BLOCK_MINUTES, MAX_BLOCK_MINUTES);
        Duration::from_secs(mins * 60)
    }

    /// Resolve the configured `track_by` string to a [`BlockKeyKind`].
    /// Unknown values fall back to [`BlockKeyKind::Ip`] so a typo never
    /// silently disables tracking.
    pub fn key_kind(&self) -> BlockKeyKind {
        match self.track_by.as_str() {
            "api_key" => BlockKeyKind::ApiKey,
            "cel" => BlockKeyKind::Cel,
            _ => BlockKeyKind::Ip,
        }
    }
}

/// Per-client strike record in the local (L1) tier. Holds the recent
/// strike timestamps (pruned to the sliding window) and the instant the
/// active block lifts, if any.
#[derive(Debug, Clone, Default)]
struct LocalEntry {
    /// Timestamps of recent strikes, oldest first.
    strikes: VecDeque<Instant>,
    /// When `Some`, the client is blocked until this instant.
    blocked_until: Option<Instant>,
}

/// Outcome of recording a strike against a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrikeOutcome {
    /// The strike was counted but the threshold was not reached.
    Counted,
    /// The strike crossed the threshold and the client is now blocked.
    Escalated,
}

/// Persistent block state machine.
///
/// One instance is built per WAF policy from a [`PersistentBlockConfig`].
/// The enforcer calls [`Self::is_blocked`] up front and [`Self::record_strike`]
/// after a WAF/challenge deny. When [`Self::with_store`] attached a shared
/// [`KVStore`], both calls round-trip through it so state is shared across
/// replicas; otherwise the in-process LRU map is authoritative.
pub struct PersistentBlockStore {
    config: PersistentBlockConfig,
    /// Local (L1) per-client map. Bounded by an LRU.
    local: Mutex<lru::LruCache<String, LocalEntry>>,
    /// Optional shared (L2) store. When `Some`, strikes and block markers
    /// round-trip through it. Reuses the rate-limit L2 store.
    store: Option<Arc<dyn KVStore>>,
    /// Key prefix baked with the origin id so origins never collide on
    /// shared state. Format: `sbproxy:waf:block:<origin>:`.
    key_prefix: String,
}

impl std::fmt::Debug for PersistentBlockStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentBlockStore")
            .field("config", &self.config)
            .field("store_attached", &self.store.is_some())
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

impl PersistentBlockStore {
    /// Build a store from config. Local-only until [`Self::with_store`]
    /// attaches a shared backend.
    pub fn new(config: PersistentBlockConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_keys.max(1)).expect("cap is at least 1");
        Self {
            config,
            local: Mutex::new(lru::LruCache::new(cap)),
            store: None,
            key_prefix: "sbproxy:waf:block:local:".to_string(),
        }
    }

    /// Attach a shared L2 store so block state is visible across replicas.
    /// The `origin_id` is baked into every key so origins do not share
    /// block state. When `store` is `None` the local map stays
    /// authoritative.
    pub fn with_store(mut self, store: Option<Arc<dyn KVStore>>, origin_id: &str) -> Self {
        self.store = store;
        self.key_prefix = format!("sbproxy:waf:block:{}:", origin_id);
        self
    }

    /// The dimension blocks are tracked by, for the `key_kind` metric label.
    pub fn key_kind(&self) -> BlockKeyKind {
        self.config.key_kind()
    }

    /// Whether persistent blocking is enabled at all.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// The configured CEL key expression when `track_by: cel`, else `None`.
    pub fn cel_key(&self) -> Option<&str> {
        if self.config.key_kind() == BlockKeyKind::Cel {
            self.config.key.as_deref()
        } else {
            None
        }
    }

    /// Redis key for the block marker of `client`.
    fn block_marker_key(&self, client: &str) -> Vec<u8> {
        format!("{}{}:blocked", self.key_prefix, client).into_bytes()
    }

    /// Redis key for the strike counter of `client`.
    fn strike_key(&self, client: &str) -> Vec<u8> {
        format!("{}{}:strikes", self.key_prefix, client).into_bytes()
    }

    /// Return whether `client` is currently inside an active block window.
    ///
    /// On the shared (L2) path a present block-marker key means blocked;
    /// the marker's TTL is the release timer. On the local path the
    /// `blocked_until` instant is compared against now, and an expired
    /// block is cleared in place (lazy release).
    ///
    /// Errors on the L2 path fail *open* (return `false`): a Redis hiccup
    /// must not start blocking every client, mirroring the rate limiter's
    /// fail-open posture.
    pub async fn is_blocked(&self, client: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        if let Some(store) = self.store.clone() {
            let key = self.block_marker_key(client);
            match sbproxy_platform::storage::get_async(store, key).await {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => {
                    tracing::warn!(error = %e, "waf persistent-block L2 read failed, failing open");
                    false
                }
            }
        } else {
            let now = Instant::now();
            let mut guard = self.local.lock();
            if let Some(entry) = guard.get_mut(client) {
                match entry.blocked_until {
                    Some(until) if now < until => true,
                    Some(_) => {
                        // Block window elapsed: release the client.
                        entry.blocked_until = None;
                        false
                    }
                    None => false,
                }
            } else {
                false
            }
        }
    }

    /// Record one strike against `client`. Returns whether the strike
    /// merely counted or crossed the threshold and escalated the client
    /// into a fresh block window.
    ///
    /// On the shared (L2) path the strike counter is an atomic
    /// `incr_with_ttl` scoped to the sliding window; when the
    /// post-increment count reaches the threshold a block marker is
    /// written with the block-window TTL. On the local path the strike
    /// timestamps are pruned to the window before the threshold check.
    ///
    /// L2 errors fail *open* (treated as a plain `Counted`) so storage
    /// flakiness degrades to local-only behaviour rather than dropping
    /// the request.
    pub async fn record_strike(&self, client: &str) -> StrikeOutcome {
        if !self.config.enabled {
            return StrikeOutcome::Counted;
        }
        if let Some(store) = self.store.clone() {
            self.record_strike_l2(store, client).await
        } else {
            self.record_strike_local(client)
        }
    }

    async fn record_strike_l2(&self, store: Arc<dyn KVStore>, client: &str) -> StrikeOutcome {
        let strike_key = self.strike_key(client);
        let count = match sbproxy_platform::storage::incr_with_ttl_async(
            Arc::clone(&store),
            strike_key,
            self.config.window_secs.max(1),
        )
        .await
        {
            Ok(n) => n as u64,
            Err(e) => {
                tracing::warn!(error = %e, "waf persistent-block L2 strike incr failed, failing open");
                return StrikeOutcome::Counted;
            }
        };
        if count >= self.config.strikes as u64 {
            let marker = self.block_marker_key(client);
            let ttl = self.config.block_duration().as_secs().max(1);
            if let Err(e) =
                sbproxy_platform::storage::put_with_ttl_async(store, marker, b"1".to_vec(), ttl)
                    .await
            {
                tracing::warn!(error = %e, "waf persistent-block L2 block-marker write failed");
                return StrikeOutcome::Counted;
            }
            StrikeOutcome::Escalated
        } else {
            StrikeOutcome::Counted
        }
    }

    fn record_strike_local(&self, client: &str) -> StrikeOutcome {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs.max(1));
        let mut guard = self.local.lock();
        if !guard.contains(client) {
            guard.put(client.to_string(), LocalEntry::default());
        }
        let entry = guard.get_mut(client).expect("inserted just above");
        // Prune strikes older than the sliding window.
        while let Some(front) = entry.strikes.front() {
            if now.duration_since(*front) > window {
                entry.strikes.pop_front();
            } else {
                break;
            }
        }
        entry.strikes.push_back(now);
        if entry.strikes.len() as u64 >= self.config.strikes as u64 {
            entry.blocked_until = Some(now + self.config.block_duration());
            // Reset the strike window so the next block requires a fresh
            // round of strikes rather than re-tripping immediately.
            entry.strikes.clear();
            StrikeOutcome::Escalated
        } else {
            StrikeOutcome::Counted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_platform::storage::MemoryKVStore;

    /// Test-only KVStore that honours TTLs and atomic counters with a
    /// manually advanceable clock, so the shared (L2) escalation and
    /// release paths can be exercised deterministically without Redis.
    struct FakeTtlStore {
        // key -> (value, expires_at_offset_secs_from_base)
        data: Mutex<std::collections::HashMap<Vec<u8>, (bytes::Bytes, u64)>>,
        // counters share the same expiry map; integer is stored as text.
        now: Mutex<u64>,
    }

    impl FakeTtlStore {
        fn new() -> Self {
            Self {
                data: Mutex::new(std::collections::HashMap::new()),
                now: Mutex::new(0),
            }
        }
        fn advance(&self, secs: u64) {
            *self.now.lock() += secs;
        }
        fn now(&self) -> u64 {
            *self.now.lock()
        }
    }

    impl KVStore for FakeTtlStore {
        fn get(&self, key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            let now = self.now();
            let mut data = self.data.lock();
            match data.get(key) {
                Some((_, exp)) if now >= *exp => {
                    data.remove(key);
                    Ok(None)
                }
                Some((v, _)) => Ok(Some(v.clone())),
                None => Ok(None),
            }
        }
        fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
            self.data.lock().insert(
                key.to_vec(),
                (bytes::Bytes::copy_from_slice(value), u64::MAX),
            );
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
            self.data.lock().remove(key);
            Ok(())
        }
        fn scan_prefix(&self, _prefix: &[u8]) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            Ok(vec![])
        }
        fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> anyhow::Result<()> {
            let exp = self.now() + ttl_secs;
            self.data
                .lock()
                .insert(key.to_vec(), (bytes::Bytes::copy_from_slice(value), exp));
            Ok(())
        }
        fn incr_with_ttl(&self, key: &[u8], ttl_secs: u64) -> anyhow::Result<i64> {
            let now = self.now();
            let mut data = self.data.lock();
            let current = match data.get(key) {
                Some((_, exp)) if now >= *exp => 0,
                Some((v, _)) => String::from_utf8_lossy(v).parse::<i64>().unwrap_or(0),
                None => 0,
            };
            let next = current + 1;
            let exp = now + ttl_secs;
            data.insert(key.to_vec(), (bytes::Bytes::from(next.to_string()), exp));
            Ok(next)
        }
    }

    fn cfg(strikes: u32, window_secs: u64, block_minutes: u64) -> PersistentBlockConfig {
        PersistentBlockConfig {
            enabled: true,
            strikes,
            window_secs,
            block_minutes,
            track_by: "ip".to_string(),
            key: None,
            max_keys: 100,
        }
    }

    #[test]
    fn block_minutes_clamp_to_supported_range() {
        let mut c = cfg(3, 60, 0);
        assert_eq!(c.block_duration(), Duration::from_secs(60));
        c.block_minutes = 999;
        assert_eq!(c.block_duration(), Duration::from_secs(60 * 60));
        c.block_minutes = 10;
        assert_eq!(c.block_duration(), Duration::from_secs(600));
    }

    #[test]
    fn key_kind_parses_and_defaults() {
        let mut c = cfg(3, 60, 10);
        assert_eq!(c.key_kind(), BlockKeyKind::Ip);
        c.track_by = "api_key".to_string();
        assert_eq!(c.key_kind(), BlockKeyKind::ApiKey);
        c.track_by = "cel".to_string();
        assert_eq!(c.key_kind(), BlockKeyKind::Cel);
        c.track_by = "garbage".to_string();
        assert_eq!(c.key_kind(), BlockKeyKind::Ip);
    }

    #[test]
    fn disabled_store_never_blocks_or_escalates() {
        let mut c = cfg(1, 60, 10);
        c.enabled = false;
        let store = PersistentBlockStore::new(c);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert_eq!(store.record_strike("1.2.3.4").await, StrikeOutcome::Counted);
            assert!(!store.is_blocked("1.2.3.4").await);
        });
    }

    #[test]
    fn local_escalates_after_threshold_then_blocks() {
        let store = PersistentBlockStore::new(cfg(3, 60, 10));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert!(!store.is_blocked("1.2.3.4").await);
            assert_eq!(store.record_strike("1.2.3.4").await, StrikeOutcome::Counted);
            assert_eq!(store.record_strike("1.2.3.4").await, StrikeOutcome::Counted);
            assert_eq!(
                store.record_strike("1.2.3.4").await,
                StrikeOutcome::Escalated
            );
            assert!(store.is_blocked("1.2.3.4").await, "client must be blocked");
        });
    }

    #[test]
    fn local_release_after_window_elapses() {
        // A 1-minute block clamps up from a sub-minute request, so use the
        // raw field manipulation to test the lazy release path: set the
        // block window to the minimum and force an elapsed block.
        let store = PersistentBlockStore::new(cfg(1, 60, 1));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert_eq!(
                store.record_strike("9.9.9.9").await,
                StrikeOutcome::Escalated
            );
            assert!(store.is_blocked("9.9.9.9").await);
            // Force the block to have expired by rewriting the instant.
            {
                let mut guard = store.local.lock();
                if let Some(entry) = guard.get_mut("9.9.9.9") {
                    entry.blocked_until = Some(Instant::now() - std::time::Duration::from_secs(1));
                }
            }
            assert!(
                !store.is_blocked("9.9.9.9").await,
                "block must release after the window elapses"
            );
        });
    }

    #[test]
    fn local_strikes_outside_window_do_not_accumulate() {
        // window of 0 clamps to 1s; strikes spaced beyond the window get
        // pruned so the threshold is never reached. We simulate aging by
        // rewriting the deque timestamps.
        let store = PersistentBlockStore::new(cfg(3, 1, 10));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert_eq!(store.record_strike("8.8.8.8").await, StrikeOutcome::Counted);
            // Age the recorded strike beyond the window.
            {
                let mut guard = store.local.lock();
                if let Some(entry) = guard.get_mut("8.8.8.8") {
                    for ts in entry.strikes.iter_mut() {
                        *ts = Instant::now() - std::time::Duration::from_secs(5);
                    }
                }
            }
            // The aged strike is pruned, so this counts as the first fresh one.
            assert_eq!(store.record_strike("8.8.8.8").await, StrikeOutcome::Counted);
            assert!(!store.is_blocked("8.8.8.8").await);
        });
    }

    #[test]
    fn distinct_clients_tracked_independently() {
        let store = PersistentBlockStore::new(cfg(2, 60, 10));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert_eq!(store.record_strike("a").await, StrikeOutcome::Counted);
            assert_eq!(store.record_strike("b").await, StrikeOutcome::Counted);
            assert_eq!(store.record_strike("a").await, StrikeOutcome::Escalated);
            assert!(store.is_blocked("a").await);
            assert!(!store.is_blocked("b").await, "client b unaffected");
        });
    }

    #[test]
    fn l2_store_persists_strikes_escalates_then_releases() {
        // The shared (Redis-shaped) path: a TTL-aware store accumulates
        // strikes via incr_with_ttl and writes a block marker via
        // put_with_ttl. Advancing the fake clock past the block window
        // releases the client, proving the time-boxed release survives in
        // the shared tier (and, by construction, across replicas).
        let fake = Arc::new(FakeTtlStore::new());
        let store = PersistentBlockStore::new(cfg(3, 60, 1))
            .with_store(Some(fake.clone() as Arc<dyn KVStore>), "origin-x");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert!(!store.is_blocked("c").await);
            assert_eq!(store.record_strike("c").await, StrikeOutcome::Counted);
            assert_eq!(store.record_strike("c").await, StrikeOutcome::Counted);
            assert_eq!(store.record_strike("c").await, StrikeOutcome::Escalated);
            assert!(store.is_blocked("c").await, "client must be blocked in L2");
            // Block window is 1 minute; advance past it.
            fake.advance(61);
            assert!(
                !store.is_blocked("c").await,
                "L2 block must release after its TTL elapses"
            );
        });
    }

    #[test]
    fn l2_store_without_ttl_support_fails_open() {
        // MemoryKVStore lacks TTL/incr support; storage flakiness must
        // degrade safely (never escalate, never block) rather than drop
        // requests.
        let store = PersistentBlockStore::new(cfg(2, 60, 10))
            .with_store(Some(Arc::new(MemoryKVStore::new(0))), "origin-x");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert_eq!(store.record_strike("c").await, StrikeOutcome::Counted);
            assert_eq!(store.record_strike("c").await, StrikeOutcome::Counted);
            assert!(
                !store.is_blocked("c").await,
                "memory store has no TTL/incr support so blocks must fail open"
            );
        });
    }

    #[test]
    fn l2_key_prefix_includes_origin() {
        let store = PersistentBlockStore::new(cfg(2, 60, 10))
            .with_store(Some(Arc::new(MemoryKVStore::new(0))), "api.example.com");
        let marker = String::from_utf8(store.block_marker_key("1.2.3.4")).unwrap();
        assert_eq!(marker, "sbproxy:waf:block:api.example.com:1.2.3.4:blocked");
        let strikes = String::from_utf8(store.strike_key("1.2.3.4")).unwrap();
        assert_eq!(strikes, "sbproxy:waf:block:api.example.com:1.2.3.4:strikes");
    }
}
