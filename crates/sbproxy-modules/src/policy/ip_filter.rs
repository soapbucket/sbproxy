//! IP allow/deny filter policy.
//!
//! Matches the client IP against optional whitelist and blacklist CIDR
//! lists. Whitelist (when non-empty) is checked first; blacklist always
//! denies on match.

use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::net::IpAddr;

/// IP allow/deny filter based on CIDR lists.
///
/// If `whitelist` is non-empty, the client IP must match at least one
/// entry. If `blacklist` is non-empty, the client IP must NOT match
/// any entry. Both lists can be used together (whitelist is checked first).
#[derive(Debug, Deserialize)]
pub struct IpFilterPolicy {
    /// CIDR ranges that are explicitly permitted. Empty allows everything.
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// CIDR ranges that are explicitly denied.
    #[serde(default)]
    pub blacklist: Vec<String>,
    /// Parsed CIDR networks from whitelist strings.
    #[serde(skip)]
    parsed_whitelist: Vec<IpNetwork>,
    /// Parsed CIDR networks from blacklist strings.
    #[serde(skip)]
    parsed_blacklist: Vec<IpNetwork>,
}

impl IpFilterPolicy {
    /// Build an IpFilterPolicy from a generic JSON config value.
    ///
    /// Parses all CIDR strings into `IpNetwork` values at construction
    /// time so that per-request checks are fast comparisons.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;

        policy.parsed_whitelist = policy
            .whitelist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid whitelist CIDR: {}", e))?;

        policy.parsed_blacklist = policy
            .blacklist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid blacklist CIDR: {}", e))?;

        Ok(policy)
    }

    /// Check whether the given IP address is allowed by this filter.
    ///
    /// Returns true if the IP passes both whitelist and blacklist checks.
    pub fn check_ip(&self, ip: &IpAddr) -> bool {
        // Whitelist check: if non-empty, IP must match at least one entry
        if !self.parsed_whitelist.is_empty()
            && !self.parsed_whitelist.iter().any(|net| net.contains(*ip))
        {
            return false;
        }

        // Blacklist check: IP must not match any entry
        if self.parsed_blacklist.iter().any(|net| net.contains(*ip)) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn ip_filter_policy_type() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8"]
        }))
        .unwrap();
        let policy = Policy::IpFilter(policy);
        assert_eq!(policy.policy_type(), "ip_filter");
    }

    #[test]
    fn ip_filter_whitelist_allows_matching() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8", "192.168.1.0/24"]
        }))
        .unwrap();

        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(policy.check_ip(&ip));

        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_whitelist_denies_non_matching() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8"]
        }))
        .unwrap();

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(!policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_blacklist_blocks_matching() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "blacklist": ["192.168.1.0/24"]
        }))
        .unwrap();

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(!policy.check_ip(&ip));

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_empty_lists_allow_all() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({})).unwrap();

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_invalid_cidr_errors() {
        let result = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["not-a-cidr"]
        }));
        assert!(result.is_err());
    }

    #[test]
    fn ip_filter_whitelist_and_blacklist_combined() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["10.0.0.0/8"],
            "blacklist": ["10.0.1.0/24"]
        }))
        .unwrap();

        // In whitelist but also in blacklist - should be denied
        let ip: IpAddr = "10.0.1.5".parse().unwrap();
        assert!(!policy.check_ip(&ip));

        // In whitelist and not in blacklist - should be allowed
        let ip: IpAddr = "10.0.2.5".parse().unwrap();
        assert!(policy.check_ip(&ip));
    }

    #[test]
    fn ip_filter_single_ip_cidr() {
        let policy = IpFilterPolicy::from_config(serde_json::json!({
            "whitelist": ["192.168.1.1/32"]
        }))
        .unwrap();

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(policy.check_ip(&ip));

        let ip: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(!policy.check_ip(&ip));
    }
}
