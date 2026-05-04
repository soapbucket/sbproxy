//! IP reputation and CIDR matching utilities.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use tracing::warn;

use crate::ssrf;

/// Check if an IP is in any of the given CIDR ranges.
pub fn ip_in_cidrs(ip: &IpAddr, cidrs: &[IpNetwork]) -> bool {
    cidrs.iter().any(|cidr| cidr.contains(*ip))
}

/// Parse a list of CIDR strings into IpNetwork objects, skipping invalid entries.
///
/// Each unparseable entry is logged at WARN level so that misconfigured
/// allow/deny lists do not silently lose rules. The function still returns
/// only the valid entries; callers that need strict-mode behavior should
/// validate beforehand.
pub fn parse_cidrs(cidrs: &[String]) -> Vec<IpNetwork> {
    cidrs
        .iter()
        .filter_map(|s| match s.parse::<IpNetwork>() {
            Ok(net) => Some(net),
            Err(e) => {
                warn!(
                    cidr = %s,
                    error = %e,
                    "skipping unparseable CIDR entry; rule will be ignored"
                );
                None
            }
        })
        .collect()
}

/// Check if an IP is a private, reserved, or otherwise non-routable address.
///
/// Delegates to the comprehensive [`ssrf::is_private_ip`] check, which
/// covers loopback, RFC 1918 private ranges, link-local, broadcast,
/// unspecified, CGNAT (100.64.0.0/10), documentation ranges, IPv6 ULA
/// (fc00::/7), and IPv6 link-local (fe80::/10). Maintaining a single
/// source of truth keeps IP-filter callers in sync with SSRF blocking,
/// and also handles IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) by
/// inspecting the embedded IPv4 address.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    // IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) must be unwrapped so a
    // request to e.g. `::ffff:169.254.169.254` is treated as the IPv4
    // link-local address it really is, rather than slipping through under
    // the IPv6 path.
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return ssrf::is_private_ip(&IpAddr::V4(v4));
        }
    }
    ssrf::is_private_ip(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_cidrs_match() {
        let cidrs = parse_cidrs(&["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]);
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(ip_in_cidrs(&ip, &cidrs));
    }

    #[test]
    fn test_ip_in_cidrs_no_match() {
        let cidrs = parse_cidrs(&["10.0.0.0/8".to_string()]);
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(!ip_in_cidrs(&ip, &cidrs));
    }

    #[test]
    fn test_parse_cidrs_skips_invalid() {
        let cidrs = parse_cidrs(&[
            "10.0.0.0/8".to_string(),
            "not-a-cidr".to_string(),
            "192.168.1.0/24".to_string(),
        ]);
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_loopback() {
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(!is_private_ip(&"2001:db8::1".parse().unwrap()));
    }

    // --- H1 regression tests ---
    //
    // Before delegating to the comprehensive ssrf::is_private_ip, the
    // public function only covered RFC 1918 private, loopback, IPv4
    // link-local, and IPv6 loopback. The cases below were silently
    // accepted as "public" by IP-filter callers; they must now all be
    // blocked.

    #[test]
    fn test_cgnat_blocked() {
        // 100.64.0.0/10 carrier-grade NAT (RFC 6598).
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_private_ip(&"100.127.255.255".parse().unwrap()));
        assert!(!is_private_ip(&"100.128.0.0".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_ula_blocked() {
        // fc00::/7 unique local addresses (RFC 4193).
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_link_local_blocked() {
        // fe80::/10 IPv6 link-local (RFC 4291).
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::dead:beef".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_metadata_endpoint_blocked() {
        // The cloud-instance metadata endpoint is 169.254.169.254. An
        // attacker who can submit `::ffff:169.254.169.254` (IPv4-mapped
        // IPv6) must not bypass the link-local block.
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_private_ip(&mapped));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_loopback_blocked() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_private_ip(&mapped));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_public_allowed() {
        let mapped: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(&mapped));
    }

    #[test]
    fn test_documentation_ranges_blocked() {
        assert!(is_private_ip(&"192.0.2.1".parse().unwrap()));
        assert!(is_private_ip(&"198.51.100.1".parse().unwrap()));
        assert!(is_private_ip(&"203.0.113.1".parse().unwrap()));
    }
}
