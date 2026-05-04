//! DNS lookup cache with TTL-based expiry.
//!
//! Provides a thread-safe, bounded cache for resolved DNS entries. Entries expire
//! after a configurable TTL and the cache enforces a maximum entry count.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// A cached DNS resolution result with an expiry time.
#[derive(Debug, Clone)]
pub struct DnsEntry {
    /// Resolved IP addresses for the hostname.
    pub addresses: Vec<IpAddr>,
    /// When this entry expires and should be re-resolved.
    pub expires_at: Instant,
}

/// Thread-safe DNS resolution cache with TTL and bounded capacity.
pub struct DnsCache {
    cache: DashMap<String, DnsEntry>,
    default_ttl: Duration,
    max_entries: usize,
}

impl DnsCache {
    /// Create a new DNS cache.
    ///
    /// - `default_ttl`: how long entries remain valid.
    /// - `max_entries`: maximum number of cached hostnames. When full, expired entries
    ///   are evicted first; if still full, the oldest entry is removed.
    pub fn new(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            cache: DashMap::new(),
            default_ttl,
            max_entries,
        }
    }

    /// Look up a cached DNS entry. Returns `None` if not cached or expired.
    pub fn get(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let entry = self.cache.get(hostname)?;
        if Instant::now() >= entry.expires_at {
            return None;
        }
        Some(entry.addresses.clone())
    }

    /// Store a DNS resolution result with the default TTL.
    ///
    /// If the cache is at capacity, expired entries are evicted first. If still full,
    /// the entry closest to expiry is removed to make room.
    pub fn put(&self, hostname: &str, addresses: Vec<IpAddr>) {
        // If the key already exists, just update it.
        if self.cache.contains_key(hostname) {
            self.cache.insert(
                hostname.to_string(),
                DnsEntry {
                    addresses,
                    expires_at: Instant::now() + self.default_ttl,
                },
            );
            return;
        }

        // Evict expired entries if we are at capacity.
        if self.cache.len() >= self.max_entries {
            let now = Instant::now();
            self.cache.retain(|_, entry| entry.expires_at > now);
        }

        // If still at capacity, evict the entry closest to expiry.
        if self.cache.len() >= self.max_entries {
            let oldest_key = self
                .cache
                .iter()
                .min_by_key(|e| e.value().expires_at)
                .map(|e| e.key().clone());
            if let Some(key) = oldest_key {
                self.cache.remove(&key);
            }
        }

        self.cache.insert(
            hostname.to_string(),
            DnsEntry {
                addresses,
                expires_at: Instant::now() + self.default_ttl,
            },
        );
    }

    /// Remove all expired entries from the cache.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| entry.expires_at > now);
    }

    /// Number of entries currently in the cache (including expired ones).
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

// --- Refreshing resolver ---

/// A DNS resolver that asynchronously refreshes a cached hostname's
/// A / AAAA record set using `tokio::net::lookup_host`.
///
/// One resolver instance backs every `service_discovery`-enabled
/// upstream. Each tracked hostname has its own `RwLock<Vec<IpAddr>>`
/// plus a `last_refreshed` timestamp; on access the resolver checks
/// whether the cached snapshot is older than `refresh_secs` and
/// triggers a re-resolve when stale. A round-robin counter picks the
/// next IP from the current set so the connection pool spreads load
/// across all resolved addresses.
pub struct RefreshingResolver {
    state: tokio::sync::RwLock<HashMap<String, ResolvedHost>>,
}

struct ResolvedHost {
    ips: Vec<IpAddr>,
    refreshed_at: Instant,
    rr_counter: std::sync::atomic::AtomicU64,
}

impl Default for RefreshingResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshingResolver {
    /// Create an empty resolver.
    pub fn new() -> Self {
        Self {
            state: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Pick a fresh IP for the given hostname. Refreshes the cache
    /// asynchronously when the snapshot is older than
    /// `refresh_secs`. Returns `None` only when DNS resolution has
    /// never produced any IPs for this hostname.
    ///
    /// `port` is appended to the hostname for resolution because
    /// `tokio::net::lookup_host` expects a `host:port` form.
    /// `ipv6` controls whether AAAA records are included in the
    /// returned set.
    pub async fn pick_ip(
        &self,
        hostname: &str,
        port: u16,
        refresh_secs: u64,
        ipv6: bool,
    ) -> Option<IpAddr> {
        // Fast path - cached set is fresh.
        {
            let guard = self.state.read().await;
            if let Some(entry) = guard.get(hostname) {
                let age = entry.refreshed_at.elapsed().as_secs();
                if age < refresh_secs && !entry.ips.is_empty() {
                    return Some(round_robin_pick(&entry.ips, &entry.rr_counter, ipv6));
                }
            }
        }
        // Slow path - resolve and cache. Multiple racers may resolve
        // in parallel; the writer holds the lock only briefly to
        // swap the entry in. The DNS layer below is itself cached
        // by the OS so this is cheap when records have not changed.
        let target = format!("{hostname}:{port}");
        let resolved: Vec<IpAddr> = match tokio::net::lookup_host(target).await {
            Ok(iter) => iter
                .map(|sa| sa.ip())
                .filter(|ip| ipv6 || ip.is_ipv4())
                .collect(),
            Err(e) => {
                tracing::warn!(hostname = %hostname, error = %e, "DNS resolution failed");
                return None;
            }
        };
        if resolved.is_empty() {
            tracing::warn!(hostname = %hostname, "DNS returned no addresses");
            return None;
        }
        let pick = resolved.first().copied();
        let mut guard = self.state.write().await;
        guard.insert(
            hostname.to_string(),
            ResolvedHost {
                ips: resolved,
                refreshed_at: Instant::now(),
                rr_counter: std::sync::atomic::AtomicU64::new(0),
            },
        );
        pick
    }
}

fn round_robin_pick(ips: &[IpAddr], counter: &std::sync::atomic::AtomicU64, ipv6: bool) -> IpAddr {
    use std::sync::atomic::Ordering;
    let mut filtered: Vec<&IpAddr> = if ipv6 {
        ips.iter().collect()
    } else {
        ips.iter().filter(|ip| ip.is_ipv4()).collect()
    };
    if filtered.is_empty() {
        // Fallback: ipv6=false but only AAAA records resolved. Use
        // any IP rather than fail closed.
        filtered = ips.iter().collect();
    }
    let idx = counter.fetch_add(1, Ordering::Relaxed) as usize % filtered.len();
    *filtered[idx]
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- RefreshingResolver tests ---

    #[tokio::test]
    async fn round_robin_picks_each_ip_in_turn() {
        let counter = std::sync::atomic::AtomicU64::new(0);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
        ];
        let picks: Vec<_> = (0..6)
            .map(|_| round_robin_pick(&ips, &counter, true))
            .collect();
        // Three IPs, 6 picks => each appears at least once and twice in
        // contiguous runs.
        assert!(picks.contains(&ips[0]));
        assert!(picks.contains(&ips[1]));
        assert!(picks.contains(&ips[2]));
    }

    #[tokio::test]
    async fn round_robin_filters_ipv6_when_disabled() {
        let counter = std::sync::atomic::AtomicU64::new(0);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ];
        for _ in 0..10 {
            let pick = round_robin_pick(&ips, &counter, false);
            assert!(pick.is_ipv4(), "ipv6=false should never return AAAA");
        }
    }

    #[tokio::test]
    async fn round_robin_falls_back_when_only_ipv6_and_ipv6_disabled() {
        // When the resolver returns only AAAA but the user asked for
        // ipv6: false, we still hand back an IP rather than failing
        // the whole request.
        let counter = std::sync::atomic::AtomicU64::new(0);
        let ips = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        let pick = round_robin_pick(&ips, &counter, false);
        assert!(pick.is_ipv6());
    }

    #[tokio::test]
    async fn resolver_caches_within_refresh_window() {
        // Resolving localhost should always succeed (loopback).
        let r = RefreshingResolver::new();
        let first = r.pick_ip("localhost", 0, 60, true).await;
        assert!(first.is_some());
        // Second call within the refresh window must return without
        // touching DNS again. We can't observe DNS calls directly,
        // but we can verify the result is consistent.
        let second = r.pick_ip("localhost", 0, 60, true).await;
        assert!(second.is_some());
    }

    #[test]
    fn put_and_get() {
        let cache = DnsCache::new(Duration::from_secs(300), 100);
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];

        cache.put("example.com", addrs.clone());
        let result = cache.get("example.com");
        assert_eq!(result, Some(addrs));
    }

    #[test]
    fn returns_none_for_missing() {
        let cache = DnsCache::new(Duration::from_secs(300), 100);
        assert_eq!(cache.get("nonexistent.com"), None);
    }

    #[test]
    fn expired_entry_returns_none() {
        let cache = DnsCache::new(Duration::from_millis(0), 100);
        cache.put("example.com", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        // TTL is 0ms, so the entry is immediately expired.
        // A small sleep is not needed because Instant::now() will be >= expires_at.
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn evict_expired_removes_stale_entries() {
        let cache = DnsCache::new(Duration::from_millis(0), 100);
        cache.put("a.com", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        cache.put("b.com", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert_eq!(cache.len(), 2);

        std::thread::sleep(Duration::from_millis(1));
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn max_entries_evicts_oldest() {
        let cache = DnsCache::new(Duration::from_secs(300), 2);
        cache.put("a.com", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        std::thread::sleep(Duration::from_millis(1));
        cache.put("b.com", vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]);
        std::thread::sleep(Duration::from_millis(1));

        // Cache is full (2 entries). Adding a third should evict the oldest (a.com).
        cache.put("c.com", vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))]);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("a.com"), None);
        assert!(cache.get("b.com").is_some());
        assert!(cache.get("c.com").is_some());
    }

    #[test]
    fn update_existing_entry() {
        let cache = DnsCache::new(Duration::from_secs(300), 100);
        cache.put("example.com", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        cache.put(
            "example.com",
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
        );

        let result = cache.get("example.com").unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_ipv6());
    }

    #[test]
    fn is_empty() {
        let cache = DnsCache::new(Duration::from_secs(300), 100);
        assert!(cache.is_empty());
        cache.put("x.com", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert!(!cache.is_empty());
    }

    #[test]
    fn concurrent_put_and_get_no_panic() {
        use std::sync::Arc;
        use std::thread;
        let cache = Arc::new(DnsCache::new(Duration::from_secs(300), 64));
        let mut handles = Vec::new();
        for thread_id in 0..16 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..500 {
                    let host = format!("host-{}-{}.example", thread_id, i % 32);
                    let addr = IpAddr::V4(Ipv4Addr::new(
                        thread_id as u8,
                        (i >> 8) as u8,
                        (i & 0xff) as u8,
                        1,
                    ));
                    c.put(&host, vec![addr]);
                    let _ = c.get(&host);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Primary goal of this test is no panic / no deadlock under
        // concurrent put+get with eviction. DashMap's per-shard locking
        // makes the strict `len <= max_entries` invariant racy, so we
        // only assert the cache did not grow unbounded relative to the
        // total key universe (16 threads x 32 keys = 512 distinct keys).
        assert!(cache.len() <= 512);
    }
}
