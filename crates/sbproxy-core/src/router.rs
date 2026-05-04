//! Host-based and header-based request routing with bloom filter pre-check.
//!
//! `HostRouter` maps incoming hostnames to origin indices in the
//! `CompiledConfig.origins` vec. A bloom filter rejects definitely-unknown
//! hostnames in O(1) without touching the HashMap, reducing lookup cost
//! for attack traffic and misconfigured clients.
//!
//! `HeaderRoute` provides a secondary routing layer that overrides the origin
//! based on specific request header values, enabling advanced traffic splitting
//! without changing the DNS or hostname configuration.

use std::collections::HashMap;

use bloomfilter::Bloom;
use compact_str::CompactString;
use sbproxy_config::CompiledConfig;

/// Routes incoming requests to the correct origin by hostname.
///
/// Uses a bloom filter to fast-reject hostnames that are definitely not
/// configured, avoiding HashMap lookups for unknown hosts. The bloom filter
/// is tuned for a ~1% false positive rate.
pub struct HostRouter {
    host_map: HashMap<CompactString, usize>,
    bloom: Bloom<str>,
}

impl HostRouter {
    /// Build a new router from a compiled config snapshot.
    ///
    /// Constructs a bloom filter sized for the number of configured hostnames
    /// with a ~1% false positive rate, then inserts all hostnames.
    pub fn new(config: &CompiledConfig) -> Self {
        let num_items = config.host_map.len().max(1);
        let bloom = Bloom::new_for_fp_rate(num_items, 0.01);
        let mut router = Self {
            host_map: config.host_map.clone(),
            bloom,
        };
        for hostname in config.host_map.keys() {
            router.bloom.set(hostname.as_str());
        }
        router
    }

    /// Fast check: is this hostname POSSIBLY configured?
    ///
    /// Returns `false` for definitely-unknown hosts (no HashMap lookup needed).
    /// Returns `true` for known hosts and a small fraction (~1%) of unknown hosts.
    pub fn maybe_exists(&self, hostname: &str) -> bool {
        self.bloom.check(hostname)
    }

    /// Look up origin index by hostname.
    ///
    /// Uses bloom filter pre-check to skip HashMap lookup for unknown hosts.
    /// Returns `None` if the hostname is not registered in this config.
    pub fn resolve(&self, hostname: &str) -> Option<usize> {
        if !self.bloom.check(hostname) {
            return None; // Definitely not configured.
        }
        self.host_map.get(hostname).copied()
    }

    /// Returns the number of registered hostnames.
    pub fn len(&self) -> usize {
        self.host_map.len()
    }

    /// Returns true if no hostnames are registered.
    pub fn is_empty(&self) -> bool {
        self.host_map.is_empty()
    }
}

// --- Header-based routing ---

/// A header-based route override.
///
/// After hostname routing resolves an origin, a `HeaderRoute` can override
/// the resolved origin based on a specific request header name/value pair.
/// This enables traffic splitting, tenant routing, and A/B testing without
/// DNS changes.
#[derive(Debug, Clone)]
pub struct HeaderRoute {
    /// The name of the HTTP header to inspect (e.g., `"X-Tenant"`).
    pub header_name: String,
    /// The value to match against the header (exact match).
    pub header_value: String,
    /// The hostname of the origin to route to when the header matches.
    pub origin_hostname: String,
}

/// Collection of header-based route overrides.
///
/// Applied after hostname routing. The first matching rule wins.
#[derive(Debug, Default)]
pub struct HeaderRouter {
    routes: Vec<HeaderRoute>,
}

impl HeaderRouter {
    /// Create a new empty `HeaderRouter`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a header route override.
    pub fn add_route(&mut self, route: HeaderRoute) {
        self.routes.push(route);
    }

    /// Check whether any header route matches the given `HeaderMap`.
    ///
    /// Returns the `origin_hostname` of the first matching rule, or `None`
    /// if no rules match.
    pub fn resolve(&self, headers: &http::HeaderMap) -> Option<&str> {
        for route in &self.routes {
            if let Some(val) = headers.get(route.header_name.as_str()) {
                if val.to_str().unwrap_or("") == route.header_value {
                    return Some(route.origin_hostname.as_str());
                }
            }
        }
        None
    }

    /// Returns true if there are no header routes configured.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns the number of configured header routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(hostnames: &[&str]) -> CompiledConfig {
        let mut host_map = HashMap::new();
        let mut origins = Vec::new();
        for (idx, hostname) in hostnames.iter().enumerate() {
            host_map.insert(CompactString::new(hostname), idx);
            origins.push(sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                workspace_id: CompactString::default(),
                action_config: serde_json::json!({"type": "proxy", "url": "http://127.0.0.1:3000"}),
                auth_config: None,
                policy_configs: Vec::new(),
                transform_configs: Vec::new(),
                cors: None,
                hsts: None,
                compression: None,
                session: None,
                properties: None,
                sessions: None,
                user: None,
                force_ssl: false,
                allowed_methods: smallvec::smallvec![],
                request_modifiers: smallvec::smallvec![],
                response_modifiers: smallvec::smallvec![],
                variables: None,
                forward_rules: Vec::new(),
                fallback_origin: None,
                error_pages: None,
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: std::collections::HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
                rate_limits: None,
                auto_content_negotiate: None,
                content_signal: None,
                token_bytes_ratio: None,
            });
        }
        CompiledConfig {
            origins,
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        }
    }

    #[test]
    fn resolve_existing_host() {
        let config = make_config(&["api.example.com", "web.example.com"]);
        let router = HostRouter::new(&config);

        assert!(router.resolve("api.example.com").is_some());
        assert!(router.resolve("web.example.com").is_some());
        // Indices should be distinct.
        assert_ne!(
            router.resolve("api.example.com"),
            router.resolve("web.example.com")
        );
    }

    #[test]
    fn resolve_missing_host_returns_none() {
        let config = make_config(&["api.example.com"]);
        let router = HostRouter::new(&config);

        assert!(router.resolve("unknown.com").is_none());
        assert!(router.resolve("").is_none());
    }

    #[test]
    fn empty_config_resolves_nothing() {
        let config = make_config(&[]);
        let router = HostRouter::new(&config);

        assert!(router.is_empty());
        assert_eq!(router.len(), 0);
        assert!(router.resolve("anything.com").is_none());
    }

    #[test]
    fn len_matches_host_count() {
        let config = make_config(&["a.com", "b.com", "c.com"]);
        let router = HostRouter::new(&config);

        assert_eq!(router.len(), 3);
        assert!(!router.is_empty());
    }

    #[test]
    fn maybe_exists_true_for_known_hosts() {
        let config = make_config(&["api.example.com", "web.example.com"]);
        let router = HostRouter::new(&config);

        // Bloom filter must return true for all inserted items (no false negatives).
        assert!(router.maybe_exists("api.example.com"));
        assert!(router.maybe_exists("web.example.com"));
    }

    #[test]
    fn maybe_exists_false_for_unknown_hosts() {
        // With only a few items, the bloom filter should reject most unknown hosts.
        let config = make_config(&["api.example.com"]);
        let router = HostRouter::new(&config);

        // Test several unknown hostnames. With a 1% FP rate and a single item,
        // it is extremely unlikely all of these would be false positives.
        let unknowns = [
            "unknown1.com",
            "unknown2.com",
            "unknown3.com",
            "totally-different.org",
            "not-configured.net",
        ];
        let rejected_count = unknowns.iter().filter(|h| !router.maybe_exists(h)).count();
        // At least some should be rejected (overwhelmingly likely all will be).
        assert!(
            rejected_count >= 3,
            "bloom filter should reject most unknown hosts, but only rejected {}/{}",
            rejected_count,
            unknowns.len()
        );
    }

    #[test]
    fn bloom_filter_false_positive_rate_under_threshold() {
        // Insert 1000 hostnames, then test 10000 unknown hostnames.
        // The false positive rate should be under 2% (target is 1%).
        let hostnames: Vec<String> = (0..1000)
            .map(|i| format!("host-{}.example.com", i))
            .collect();
        let hostname_strs: Vec<&str> = hostnames.iter().map(|s| s.as_str()).collect();
        let config = make_config(&hostname_strs);
        let router = HostRouter::new(&config);

        // Verify all inserted hostnames are found.
        for h in &hostnames {
            assert!(
                router.resolve(h).is_some(),
                "inserted hostname {} should resolve",
                h
            );
        }

        // Test unknown hostnames for false positives.
        let test_count = 10_000;
        let false_positives = (0..test_count)
            .filter(|i| router.maybe_exists(&format!("unknown-{}.notreal.xyz", i)))
            .count();

        let fp_rate = false_positives as f64 / test_count as f64;
        assert!(
            fp_rate < 0.02,
            "false positive rate {:.4} exceeds 2% threshold ({} / {})",
            fp_rate,
            false_positives,
            test_count
        );
    }

    // --- HeaderRouter tests ---

    #[test]
    fn header_router_empty_returns_none() {
        let router = HeaderRouter::new();
        let headers = http::HeaderMap::new();
        assert!(router.resolve(&headers).is_none());
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);
    }

    #[test]
    fn header_router_matches_exact_value() {
        let mut router = HeaderRouter::new();
        router.add_route(HeaderRoute {
            header_name: "X-Tenant".to_string(),
            header_value: "acme".to_string(),
            origin_hostname: "acme.internal".to_string(),
        });

        let mut headers = http::HeaderMap::new();
        headers.insert("x-tenant", http::HeaderValue::from_static("acme"));

        assert_eq!(router.resolve(&headers), Some("acme.internal"));
    }

    #[test]
    fn header_router_no_match_returns_none() {
        let mut router = HeaderRouter::new();
        router.add_route(HeaderRoute {
            header_name: "X-Tenant".to_string(),
            header_value: "acme".to_string(),
            origin_hostname: "acme.internal".to_string(),
        });

        let mut headers = http::HeaderMap::new();
        headers.insert("x-tenant", http::HeaderValue::from_static("other"));

        assert!(router.resolve(&headers).is_none());
    }

    #[test]
    fn header_router_first_match_wins() {
        let mut router = HeaderRouter::new();
        router.add_route(HeaderRoute {
            header_name: "X-Env".to_string(),
            header_value: "staging".to_string(),
            origin_hostname: "staging.internal".to_string(),
        });
        router.add_route(HeaderRoute {
            header_name: "X-Env".to_string(),
            header_value: "staging".to_string(),
            origin_hostname: "staging-alt.internal".to_string(),
        });

        let mut headers = http::HeaderMap::new();
        headers.insert("x-env", http::HeaderValue::from_static("staging"));

        // First rule wins.
        assert_eq!(router.resolve(&headers), Some("staging.internal"));
    }

    #[test]
    fn header_router_missing_header_returns_none() {
        let mut router = HeaderRouter::new();
        router.add_route(HeaderRoute {
            header_name: "X-Feature-Flag".to_string(),
            header_value: "beta".to_string(),
            origin_hostname: "beta.internal".to_string(),
        });

        // Header is absent entirely.
        let headers = http::HeaderMap::new();
        assert!(router.resolve(&headers).is_none());
    }

    #[test]
    fn header_router_multiple_routes_correct_match() {
        let mut router = HeaderRouter::new();
        router.add_route(HeaderRoute {
            header_name: "X-Region".to_string(),
            header_value: "us-east".to_string(),
            origin_hostname: "us-east.backend".to_string(),
        });
        router.add_route(HeaderRoute {
            header_name: "X-Region".to_string(),
            header_value: "eu-west".to_string(),
            origin_hostname: "eu-west.backend".to_string(),
        });

        let mut headers_us = http::HeaderMap::new();
        headers_us.insert("x-region", http::HeaderValue::from_static("us-east"));

        let mut headers_eu = http::HeaderMap::new();
        headers_eu.insert("x-region", http::HeaderValue::from_static("eu-west"));

        assert_eq!(router.resolve(&headers_us), Some("us-east.backend"));
        assert_eq!(router.resolve(&headers_eu), Some("eu-west.backend"));
        assert_eq!(router.len(), 2);
    }
}
