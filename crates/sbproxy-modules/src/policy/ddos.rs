//! DDoS protection policy.
//!
//! Tracks per-IP request counts in a sliding one-second window. When
//! an IP exceeds the configured threshold it is blocked for the
//! configured duration. Whitelisted CIDRs always pass.

use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Instant;

fn default_ddos_threshold() -> u32 {
    100
}

fn default_ddos_block_duration() -> u64 {
    300
}

fn default_ddos_max_tracked_ips() -> usize {
    100_000
}

/// Outcome of a per-request DDoS check.
#[derive(Debug, PartialEq, Eq)]
pub enum DdosCheckResult {
    /// Request is allowed through; the policy has recorded it.
    Allow,
    /// Request must be rejected. Carries the seconds remaining until the
    /// IP is unblocked, suitable for a `Retry-After` header.
    Block {
        /// Whole seconds until the block expires; always >= 1.
        retry_after_secs: u64,
    },
}

/// Per-IP runtime state: a sliding 1-second window of recent request
/// timestamps, plus the absolute instant the block expires (if any).
#[derive(Debug)]
struct DdosIpState {
    window: std::collections::VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl DdosIpState {
    fn new() -> Self {
        Self {
            window: std::collections::VecDeque::new(),
            blocked_until: None,
        }
    }
}

/// DDoS protection policy with per-IP rate tracking and temporary blocks.
///
/// Tracks per-IP request counts in a sliding one-second window. When an
/// IP exceeds the configured `requests_per_second` threshold, it is
/// blocked for `block_duration_secs`. Whitelisted IPs always pass.
///
/// Memory is bounded by `max_tracked_ips` via LRU eviction so an
/// adversary cannot exhaust memory by cycling source IPs.
#[derive(Deserialize)]
pub struct DdosPolicy {
    /// Per-IP requests-per-second threshold that triggers blocking.
    #[serde(default = "default_ddos_threshold")]
    pub requests_per_second: u32,
    /// Duration in seconds an IP stays blocked once the threshold trips.
    #[serde(default = "default_ddos_block_duration")]
    pub block_duration_secs: u64,
    /// IP addresses or CIDR ranges that bypass DDoS checks.
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// Maximum number of distinct IPs tracked locally. Past this,
    /// least-recently-seen IPs are evicted from the LRU.
    #[serde(default = "default_ddos_max_tracked_ips")]
    pub max_tracked_ips: usize,
    /// Go compat: nested detection config.
    #[serde(default)]
    pub detection: Option<serde_json::Value>,
    /// Go compat: nested mitigation config.
    #[serde(default)]
    pub mitigation: Option<serde_json::Value>,

    /// CIDR forms of `whitelist`, parsed once at construction time.
    #[serde(skip)]
    parsed_whitelist: Vec<IpNetwork>,
    /// Per-IP sliding-window state. Lazily allocated; `None` until the
    /// first request arrives so config-only paths pay nothing.
    #[serde(skip)]
    state: Mutex<Option<lru::LruCache<IpAddr, DdosIpState>>>,
}

impl std::fmt::Debug for DdosPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdosPolicy")
            .field("requests_per_second", &self.requests_per_second)
            .field("block_duration_secs", &self.block_duration_secs)
            .field("whitelist", &self.whitelist)
            .field("max_tracked_ips", &self.max_tracked_ips)
            .finish()
    }
}

impl DdosPolicy {
    /// Build a DdosPolicy from a generic JSON config value.
    ///
    /// Supports two config formats:
    /// 1. Flat (Rust native): `{ "requests_per_second": 100, "block_duration_secs": 300 }`
    /// 2. Nested (Go compat): `{ "detection": { "request_rate_threshold": 10, ... }, "mitigation": { "block_duration": "10s", ... } }`
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;

        // Extract values from Go-style nested detection config.
        if let Some(detection) = &policy.detection {
            if let Some(threshold) = detection
                .get("request_rate_threshold")
                .and_then(|v| v.as_u64())
            {
                policy.requests_per_second = threshold as u32;
            }
        }

        // Extract values from Go-style nested mitigation config.
        if let Some(mitigation) = &policy.mitigation {
            if let Some(duration) = mitigation.get("block_duration").and_then(|v| v.as_str()) {
                // Parse Go duration strings like "10s", "5m".
                if let Some(secs) = parse_go_duration(duration) {
                    policy.block_duration_secs = secs;
                }
            }
        }

        // Parse whitelist entries once. Accept bare IPs (`10.0.0.1`) as
        // well as CIDRs (`10.0.0.0/24`); IpNetwork treats a bare IP as a
        // /32 or /128 host route.
        policy.parsed_whitelist = policy
            .whitelist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid DDoS whitelist entry: {}", e))?;

        Ok(policy)
    }

    /// Decide whether a request from `client_ip` should be allowed or
    /// blocked. The decision is recorded so subsequent calls see it.
    ///
    /// Behaviour:
    /// - Whitelisted IPs always return `Allow` and never accumulate
    ///   counter state.
    /// - If the IP is currently blocked, returns `Block` with the
    ///   remaining seconds.
    /// - Otherwise slides the 1-second request window forward, counts
    ///   the request, and trips a fresh block when the window crosses
    ///   the threshold.
    pub fn check(&self, client_ip: IpAddr) -> DdosCheckResult {
        if self
            .parsed_whitelist
            .iter()
            .any(|net| net.contains(client_ip))
        {
            return DdosCheckResult::Allow;
        }

        let now = Instant::now();
        let window = std::time::Duration::from_secs(1);
        let block_dur = std::time::Duration::from_secs(self.block_duration_secs.max(1));
        let threshold = self.requests_per_second.max(1) as usize;

        let mut guard = self.state.lock();
        let cache = guard.get_or_insert_with(|| {
            let cap = std::num::NonZeroUsize::new(self.max_tracked_ips.max(1))
                .expect("cap is at least 1");
            lru::LruCache::new(cap)
        });

        // get_or_insert_mut promotes the entry on access (LRU-correct).
        let entry = cache.get_or_insert_mut(client_ip, DdosIpState::new);

        // If a previous burst is still being penalised, short-circuit.
        if let Some(until) = entry.blocked_until {
            if now < until {
                let remaining = until.saturating_duration_since(now).as_secs() + 1;
                return DdosCheckResult::Block {
                    retry_after_secs: remaining,
                };
            }
            // Block expired. Clear state and let this request count fresh.
            entry.blocked_until = None;
            entry.window.clear();
        }

        // Slide the window: drop entries older than 1s.
        while let Some(&front) = entry.window.front() {
            if now.duration_since(front) > window {
                entry.window.pop_front();
            } else {
                break;
            }
        }

        // Threshold trip: this request would push count > threshold.
        if entry.window.len() >= threshold {
            entry.blocked_until = Some(now + block_dur);
            return DdosCheckResult::Block {
                retry_after_secs: block_dur.as_secs(),
            };
        }

        entry.window.push_back(now);
        DdosCheckResult::Allow
    }
}

/// Parse a Go-style duration string (e.g., "10s", "5m") into seconds.
fn parse_go_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix('s') {
        num.parse().ok()
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>().ok().map(|m| m * 60)
    } else if let Some(num) = s.strip_suffix('h') {
        num.parse::<u64>().ok().map(|h| h * 3600)
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn ddos_policy_type() {
        let policy = DdosPolicy::from_config(serde_json::json!({})).unwrap();
        let policy = Policy::Ddos(policy);
        assert_eq!(policy.policy_type(), "ddos");
    }

    #[test]
    fn ddos_from_config_defaults() {
        let policy = DdosPolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(policy.requests_per_second, 100);
        assert_eq!(policy.block_duration_secs, 300);
        assert!(policy.whitelist.is_empty());
    }

    #[test]
    fn ddos_from_config_custom() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 50,
            "block_duration_secs": 600,
            "whitelist": ["10.0.0.1", "192.168.1.0/24"]
        }))
        .unwrap();

        assert_eq!(policy.requests_per_second, 50);
        assert_eq!(policy.block_duration_secs, 600);
        assert_eq!(policy.whitelist.len(), 2);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ddos_allows_under_threshold() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 5,
            "block_duration_secs": 1
        }))
        .unwrap();

        let client = ip("10.0.0.1");
        for i in 0..5 {
            assert_eq!(
                policy.check(client),
                DdosCheckResult::Allow,
                "request {i} under threshold should be allowed"
            );
        }
    }

    #[test]
    fn ddos_blocks_at_threshold() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 3,
            "block_duration_secs": 5
        }))
        .unwrap();

        let client = ip("10.0.0.2");

        // First 3 fill the window
        for _ in 0..3 {
            assert_eq!(policy.check(client), DdosCheckResult::Allow);
        }

        // 4th trips the threshold
        match policy.check(client) {
            DdosCheckResult::Block { retry_after_secs } => {
                assert!(
                    retry_after_secs > 0 && retry_after_secs <= 5,
                    "retry_after should be in (0, block_duration]: got {retry_after_secs}"
                );
            }
            DdosCheckResult::Allow => panic!("4th request should have been blocked"),
        }
    }

    #[test]
    fn ddos_subsequent_requests_during_block_are_blocked() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 2,
            "block_duration_secs": 10
        }))
        .unwrap();

        let client = ip("10.0.0.3");

        // Trip the block
        for _ in 0..2 {
            assert_eq!(policy.check(client), DdosCheckResult::Allow);
        }
        let _ = policy.check(client); // trips block

        // Every subsequent request inside the block window stays blocked
        for _ in 0..5 {
            match policy.check(client) {
                DdosCheckResult::Block { .. } => {}
                DdosCheckResult::Allow => panic!("blocked IP should remain blocked"),
            }
        }
    }

    #[test]
    fn ddos_unblocks_after_block_duration() {
        // 1-second block keeps the test fast.
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 2,
            "block_duration_secs": 1
        }))
        .unwrap();

        let client = ip("10.0.0.4");

        // Trip the block
        for _ in 0..2 {
            assert!(matches!(policy.check(client), DdosCheckResult::Allow));
        }
        assert!(matches!(
            policy.check(client),
            DdosCheckResult::Block { .. }
        ));

        // Wait out the block window
        std::thread::sleep(std::time::Duration::from_millis(1100));

        assert_eq!(
            policy.check(client),
            DdosCheckResult::Allow,
            "block should expire after block_duration_secs"
        );
    }

    #[test]
    fn ddos_per_ip_isolation() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 2,
            "block_duration_secs": 5
        }))
        .unwrap();

        let attacker = ip("10.0.0.5");
        let bystander = ip("10.0.0.6");

        // Attacker trips block
        for _ in 0..2 {
            assert!(matches!(policy.check(attacker), DdosCheckResult::Allow));
        }
        assert!(matches!(
            policy.check(attacker),
            DdosCheckResult::Block { .. }
        ));

        // Bystander is unaffected
        for _ in 0..2 {
            assert_eq!(
                policy.check(bystander),
                DdosCheckResult::Allow,
                "bystander IP must not be affected by another IP's block"
            );
        }
    }

    #[test]
    fn ddos_whitelisted_ip_bypasses_check() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 1,
            "block_duration_secs": 10,
            "whitelist": ["10.0.0.7"]
        }))
        .unwrap();

        let trusted = ip("10.0.0.7");

        // Burst well past threshold; whitelist must allow every one
        for i in 0..20 {
            assert_eq!(
                policy.check(trusted),
                DdosCheckResult::Allow,
                "whitelisted IP must always be allowed (request {i})"
            );
        }
    }

    #[test]
    fn ddos_whitelist_supports_cidr() {
        let policy = DdosPolicy::from_config(serde_json::json!({
            "requests_per_second": 1,
            "block_duration_secs": 10,
            "whitelist": ["10.0.0.0/24"]
        }))
        .unwrap();

        let inside_subnet = ip("10.0.0.42");
        let outside_subnet = ip("10.0.1.1");

        // CIDR member is exempt
        for _ in 0..5 {
            assert_eq!(policy.check(inside_subnet), DdosCheckResult::Allow);
        }

        // Non-member trips the threshold normally
        assert_eq!(policy.check(outside_subnet), DdosCheckResult::Allow);
        assert!(matches!(
            policy.check(outside_subnet),
            DdosCheckResult::Block { .. }
        ));
    }

    #[test]
    fn ddos_go_compat_nested_config_enforces_correctly() {
        // The Go-compat nested format is parsed into the same flat fields
        // and must drive the runtime check identically.
        let policy = DdosPolicy::from_config(serde_json::json!({
            "detection": { "request_rate_threshold": 2 },
            "mitigation": { "block_duration": "1s" }
        }))
        .unwrap();

        assert_eq!(policy.requests_per_second, 2);
        assert_eq!(policy.block_duration_secs, 1);

        let client = ip("10.0.0.8");
        for _ in 0..2 {
            assert!(matches!(policy.check(client), DdosCheckResult::Allow));
        }
        assert!(matches!(
            policy.check(client),
            DdosCheckResult::Block { .. }
        ));
    }
}
