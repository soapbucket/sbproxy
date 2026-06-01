//! WOR-892 follow-up: process-global registry of [`DiscoveryCache`]
//! instances, keyed by issuer.
//!
//! PR #355 shipped the `DiscoveryCache` type that takes a fetcher
//! closure and returns the OIDC discovery document with TTL-bounded
//! caching. Each origin's request path needs to share one cache per
//! issuer so two concurrent requests against the same IdP do not
//! each fire their own `.well-known` fetch. This module owns that
//! shared map.
//!
//! Two deliberate scope choices:
//!
//! 1. **Keyed by issuer, not by origin.** Two origins that point at
//!    the same IdP (the same `issuer`) share one cache and one
//!    fetch round-trip. This is the right thing whether they share
//!    the same auth provider or not: the OIDC discovery document is
//!    an issuer property, not an origin property.
//! 2. **No eviction.** A live IdP entry costs ~1 KB and an issuer
//!    URL is bounded by operator config; there is no untrusted
//!    growth path. The cache itself enforces TTL on the document
//!    inside; this registry simply hands out `Arc` handles.
//!
//! The actual `DiscoveryCache::get_or_fetch` call still requires
//! the caller to supply the fetcher closure (which performs the
//! HTTP I/O against the IdP). This module is the agreed lookup
//! point so every call site reaches the same cache.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::DashMap;

use super::discovery::DiscoveryCache;

/// Look up the shared [`DiscoveryCache`] for `issuer`, constructing
/// one with the supplied `ttl` if this is the first call against
/// that issuer in the current process. Subsequent calls with the
/// same issuer ignore the supplied `ttl` (the TTL is a property of
/// the first construction, not of the lookup).
pub fn get_or_init_discovery_cache(issuer: &str, ttl: Duration) -> Arc<DiscoveryCache> {
    let registry = registry();
    if let Some(existing) = registry.get(issuer) {
        return Arc::clone(existing.value());
    }
    let cache = Arc::new(DiscoveryCache::new(issuer.to_string(), ttl));
    // Race: another thread could have inserted between the get and
    // here. `entry` resolves the race by returning the already-
    // inserted Arc when one exists. We discard our just-constructed
    // cache in that case; the cost is one empty TTL-bounded cache
    // that gets dropped at end of scope.
    let entry = registry
        .entry(issuer.to_string())
        .or_insert_with(|| Arc::clone(&cache));
    Arc::clone(entry.value())
}

/// True when the registry has already constructed a cache for
/// `issuer`. Used by tests to assert reuse; not a public concurrency
/// signal (the result is racy under concurrent inserts).
pub fn has_cache_for(issuer: &str) -> bool {
    registry().contains_key(issuer)
}

/// Drop the cached `DiscoveryCache` for `issuer`. Useful when the
/// operator rotates an IdP behind the same issuer URL and wants the
/// next request to re-discover. The IdP-side discovery document
/// itself is invalidated through `DiscoveryCache::invalidate`; this
/// helper drops the cache wrapper entirely so the next lookup
/// constructs a fresh one with the supplied TTL.
pub fn drop_cache_for(issuer: &str) {
    registry().remove(issuer);
}

fn registry() -> &'static DashMap<String, Arc<DiscoveryCache>> {
    static REGISTRY: OnceLock<DashMap<String, Arc<DiscoveryCache>>> = OnceLock::new();
    REGISTRY.get_or_init(DashMap::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_issuer(label: &str) -> String {
        format!(
            "https://idp-{}-{}-{}.example.com",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn first_lookup_constructs_cache() {
        let issuer = unique_issuer("first");
        assert!(!has_cache_for(&issuer));
        let cache = get_or_init_discovery_cache(&issuer, Duration::from_secs(60));
        assert_eq!(cache.issuer(), issuer);
        assert!(has_cache_for(&issuer));
    }

    #[test]
    fn second_lookup_returns_same_arc() {
        let issuer = unique_issuer("second");
        let a = get_or_init_discovery_cache(&issuer, Duration::from_secs(60));
        let b = get_or_init_discovery_cache(&issuer, Duration::from_secs(99));
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn ttl_on_second_lookup_is_ignored_first_wins() {
        // The TTL is sealed into the cache by the first construction.
        // The second `get_or_init_discovery_cache` call should NOT
        // build a fresh cache with a different TTL; it should hand
        // back the same Arc as before. Asserting Arc::ptr_eq above
        // already proves this, but pinning the intent explicitly so
        // a future refactor cannot quietly change the contract.
        let issuer = unique_issuer("ttl");
        let a = get_or_init_discovery_cache(&issuer, Duration::from_secs(60));
        let b = get_or_init_discovery_cache(&issuer, Duration::from_secs(3600));
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn drop_cache_for_lets_next_lookup_build_fresh() {
        let issuer = unique_issuer("drop");
        let a = get_or_init_discovery_cache(&issuer, Duration::from_secs(60));
        drop_cache_for(&issuer);
        assert!(!has_cache_for(&issuer));
        let b = get_or_init_discovery_cache(&issuer, Duration::from_secs(60));
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn distinct_issuers_get_distinct_caches() {
        let issuer_a = unique_issuer("distinct-A");
        let issuer_b = unique_issuer("distinct-B");
        let a = get_or_init_discovery_cache(&issuer_a, Duration::from_secs(60));
        let b = get_or_init_discovery_cache(&issuer_b, Duration::from_secs(60));
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(a.issuer(), issuer_a);
        assert_eq!(b.issuer(), issuer_b);
    }
}
