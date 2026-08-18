//! Host-based request routing with bloom filter pre-check.
//!
//! `HostRouter` maps incoming hostnames to origin indices in the
//! `CompiledConfig.origins` vec. A bloom filter rejects definitely-unknown
//! hostnames in O(1) without touching the HashMap, reducing lookup cost
//! for attack traffic and misconfigured clients.
//!
//! Origin keys starting with `*.` are wildcard entries. They live in a
//! separate map keyed by the literal suffix after `*.` and are consulted
//! only when the exact lookup misses, walking the inbound hostname one
//! leading label at a time. Exact keys therefore always beat wildcards,
//! and between wildcards the longest matching suffix wins.

use std::collections::HashMap;

use bloomfilter::Bloom;
use compact_str::CompactString;
use sbproxy_config::CompiledConfig;

/// Routes incoming requests to the correct origin by hostname.
///
/// Uses a bloom filter to fast-reject hostnames that are definitely not
/// configured exactly, avoiding HashMap lookups for unknown hosts. The
/// bloom filter is tuned for a ~1% false positive rate and covers exact
/// keys only: a wildcard matches by suffix, so full inbound hostnames
/// cannot be pre-inserted for it. Configs without wildcards keep the
/// original fast-reject behavior; with wildcards present, a miss costs
/// one suffix-map probe per label of the inbound hostname.
pub struct HostRouter {
    host_map: HashMap<CompactString, usize>,
    /// Wildcard origins keyed by the literal suffix after `*.`
    /// (`*.example.com` is stored as `example.com`).
    wildcard_map: HashMap<CompactString, usize>,
    bloom: Bloom<str>,
}

impl HostRouter {
    /// Build a new router from a compiled config snapshot.
    ///
    /// Splits the config's host map into exact entries and wildcard
    /// suffix entries, then constructs a bloom filter sized for the
    /// exact hostnames with a ~1% false positive rate. The literal
    /// `*.suffix` spellings never arrive on the wire, so they stay out
    /// of both the exact map and the bloom filter.
    pub fn new(config: &CompiledConfig) -> Self {
        let mut host_map = HashMap::new();
        let mut wildcard_map = HashMap::new();
        for (hostname, &idx) in &config.host_map {
            match hostname.strip_prefix("*.") {
                Some(suffix) => {
                    wildcard_map.insert(CompactString::new(suffix), idx);
                }
                None => {
                    host_map.insert(hostname.clone(), idx);
                }
            }
        }
        let num_items = host_map.len().max(1);
        let mut bloom = Bloom::new_for_fp_rate(num_items, 0.01);
        for hostname in host_map.keys() {
            bloom.set(hostname.as_str());
        }
        Self {
            host_map,
            wildcard_map,
            bloom,
        }
    }

    /// Fast check: is this hostname POSSIBLY configured?
    ///
    /// Returns `false` for definitely-unknown hosts. Returns `true` for
    /// known hosts and a small fraction (~1%) of unknown hosts. The
    /// bloom filter covers exact keys; wildcard coverage is answered by
    /// the suffix map directly, which has no false positives.
    pub fn maybe_exists(&self, hostname: &str) -> bool {
        self.bloom.check(hostname) || self.resolve_wildcard(hostname).is_some()
    }

    /// Look up origin index by hostname.
    ///
    /// Exact keys are checked first (behind the bloom pre-check), so an
    /// exact origin always beats a wildcard. On a miss the wildcard
    /// suffix map is walked from the most specific suffix, so the
    /// longest matching suffix wins and `*.example.com` matches
    /// `a.example.com` and `a.b.example.com` but never `example.com`
    /// itself. Returns `None` if the hostname is not registered in this
    /// config.
    pub fn resolve(&self, hostname: &str) -> Option<usize> {
        if self.bloom.check(hostname) {
            if let Some(&idx) = self.host_map.get(hostname) {
                return Some(idx);
            }
        }
        self.resolve_wildcard(hostname)
    }

    /// Walk the inbound hostname's label boundaries against the wildcard
    /// suffix map, most specific suffix first.
    fn resolve_wildcard(&self, hostname: &str) -> Option<usize> {
        if self.wildcard_map.is_empty() {
            return None;
        }
        let mut rest = hostname;
        while let Some((label, suffix)) = rest.split_once('.') {
            if label.is_empty() {
                // A hostname with an empty label is malformed; a
                // wildcard matches one or more real labels, never an
                // empty one.
                return None;
            }
            if !suffix.is_empty() {
                if let Some(&idx) = self.wildcard_map.get(suffix) {
                    return Some(idx);
                }
            }
            rest = suffix;
        }
        None
    }

    /// Returns the number of registered hostnames, exact and wildcard.
    pub fn len(&self) -> usize {
        self.host_map.len() + self.wildcard_map.len()
    }

    /// Returns true if no hostnames are registered.
    pub fn is_empty(&self) -> bool {
        self.host_map.is_empty() && self.wildcard_map.is_empty()
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
                cache_config_fingerprint: CompactString::default(),
                workspace_id: CompactString::default(),
                tenant_id: compact_str::CompactString::const_new("__default__"),
                action_config: serde_json::json!({"type": "proxy", "url": "http://127.0.0.1:3000"}),
                auth_config: None,
                policy_configs: Vec::new(),
                transform_configs: Vec::new(),
                filters: Vec::new(),
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
                problem_details: None,
                proxy_status: None,
                message_signatures: None,
                olp: None,
                web_bot_auth_publish: None,
                idempotency: None,
                timeouts: sbproxy_config::UpstreamTimeouts::default(),
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: std::collections::HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
                auto_content_negotiate: None,
                content_signal: None,
                token_bytes_ratio: None,
                agent_skills: Vec::new(),
                agents_md: None,
                ai_txt: None,
                agents_json: None,
                outbound_credential: None,
                outbound_web_bot_auth: false,
                observability: None,
                attestation: None,
                owasp_pack_manifest: None,
            });
        }
        CompiledConfig {
            extension_bundles: Default::default(),
            origins,
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            mesh: None,
            access_log: None,
            decision_audit: Default::default(),
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
            request_events: None,
            events: None,
            flags: Vec::new(),
            egress: Default::default(),
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
        // Bloom filters may return false positives, especially for tiny
        // filters where the implementation rounds internal sizing. The
        // hard contract for unknown hosts is that `resolve` still
        // returns None after the Bloom pre-check falls through.
        let config = make_config(&["api.example.com"]);
        let router = HostRouter::new(&config);

        for host in [
            "unknown1.com",
            "unknown2.com",
            "unknown3.com",
            "totally-different.org",
            "not-configured.net",
        ] {
            assert_eq!(router.resolve(host), None, "unknown host must not resolve");
        }
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

    // --- Wildcard routing tests ---

    #[test]
    fn wildcard_matches_one_or_more_leading_labels() {
        let config = make_config(&["*.example.com"]);
        let router = HostRouter::new(&config);

        assert_eq!(router.resolve("a.example.com"), Some(0));
        assert_eq!(router.resolve("a.b.example.com"), Some(0));
        // The bare suffix is not covered: `*.` requires at least one label.
        assert_eq!(router.resolve("example.com"), None);
    }

    #[test]
    fn exact_match_beats_wildcard() {
        let config = make_config(&["*.example.com", "api.example.com"]);
        let router = HostRouter::new(&config);

        assert_eq!(router.resolve("api.example.com"), Some(1));
        assert_eq!(router.resolve("web.example.com"), Some(0));
    }

    #[test]
    fn longest_wildcard_suffix_wins() {
        let config = make_config(&["*.example.com", "*.b.example.com"]);
        let router = HostRouter::new(&config);

        assert_eq!(router.resolve("a.b.example.com"), Some(1));
        // `b.example.com` itself only matches the broader wildcard.
        assert_eq!(router.resolve("b.example.com"), Some(0));
    }

    #[test]
    fn wildcard_non_matching_host_falls_through() {
        let config = make_config(&["*.example.com"]);
        let router = HostRouter::new(&config);

        assert_eq!(router.resolve("a.example.org"), None);
        assert_eq!(router.resolve("com"), None);
        assert_eq!(router.resolve(""), None);
    }

    #[test]
    fn wildcard_never_matches_an_empty_label() {
        let config = make_config(&["*.example.com"]);
        let router = HostRouter::new(&config);

        assert_eq!(router.resolve(".example.com"), None);
        assert_eq!(router.resolve("a..example.com"), None);
    }

    #[test]
    fn maybe_exists_covers_wildcard_hosts() {
        let config = make_config(&["*.example.com"]);
        let router = HostRouter::new(&config);

        assert!(router.maybe_exists("a.example.com"));
        assert!(router.maybe_exists("a.b.example.com"));
        assert!(!router.maybe_exists("example.org"));
    }

    #[test]
    fn len_counts_exact_and_wildcard_entries() {
        let config = make_config(&["*.example.com", "api.example.com"]);
        let router = HostRouter::new(&config);

        assert_eq!(router.len(), 2);
        assert!(!router.is_empty());
    }
}
