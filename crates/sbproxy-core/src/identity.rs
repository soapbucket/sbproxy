//! Process and config identity used in webhook envelopes, alerts, and logs.
//!
//! These identifiers travel with every webhook the proxy originates so a
//! receiver can attribute the event to a specific process and config.
//! Webhooks set them on the JSON envelope and as `X-Sbproxy-*` headers.

use std::sync::OnceLock;

/// Build version of the running proxy, taken from `Cargo.toml`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Process-wide cache for client certificate metadata captured during
/// the mTLS handshake.
///
/// The cache lives outside any single config because cert digests are
/// stable across hot reloads and rebuilding it on every reload would
/// drop in-flight verification state. The cache is bounded by an LRU
/// so a churning or adversarial client population presenting many
/// distinct certs can't grow it without bound (which would otherwise
/// be a remote OOM vector). The bound is `DEFAULT_MAX_CERT_CACHE_ENTRIES`
/// from `sbproxy_tls::mtls`; per-handshake config does not yet reroute
/// this lazy initializer (the digest-keyed cache is process-wide on
/// purpose, see the type doc for rationale).
pub fn mtls_cert_cache() -> sbproxy_tls::mtls::MtlsCertCacheHandle {
    static CACHE: OnceLock<sbproxy_tls::mtls::MtlsCertCacheHandle> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            sbproxy_tls::mtls::MtlsCertCache::new(sbproxy_tls::mtls::DEFAULT_MAX_CERT_CACHE_ENTRIES)
        })
        .clone()
}

/// Per-process instance identifier.
///
/// Stable for the lifetime of the process. Combines the host name (or
/// pod name when running under Kubernetes) with a short random tag so a
/// receiver can distinguish replicas with the same host name.
///
/// Format: `<host>-<8 hex chars>` (e.g. `sbproxy-7c4d8b9a`).
pub fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let host = hostname()
            .unwrap_or_else(|| "sbproxy".to_string())
            .replace('.', "-");
        let tag: u32 = rand::random();
        format!("{host}-{tag:08x}")
    })
}

fn hostname() -> Option<String> {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return Some(h);
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Generate a fresh request identifier suitable for correlation across
/// the proxy's webhook envelope, response headers, and access logs.
///
/// Uses UUID v4 rendered without hyphens (`hex32`) so it is compact and
/// safe in URLs and header values.
pub fn new_request_id() -> String {
    let mut buf = [0u8; 32];
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let hi = b >> 4;
        let lo = b & 0x0f;
        buf[i * 2] = hex_nibble(hi);
        buf[i * 2 + 1] = hex_nibble(lo);
    }
    String::from_utf8(buf.to_vec()).expect("hex is valid utf8")
}

fn hex_nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10),
        _ => unreachable!(),
    }
}

/// Compute a short `config_revision` tag for a serialized config blob.
///
/// The result is the first 12 hex chars of SHA-256(blob), which is
/// short enough for headers and unique enough to detect any reload.
pub fn config_revision(serialized: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(serialized);
    digest
        .iter()
        .take(6)
        .fold(String::with_capacity(12), |mut acc, b| {
            acc.push(hex_nibble(b >> 4) as char);
            acc.push(hex_nibble(b & 0x0f) as char);
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- IPv6 sanity for the trusted_proxies CIDR primitive ---
    //
    // The actual matching lives in request_filter and uses
    // `ipnetwork::IpNetwork::contains`. These tests guard against the
    // ipnetwork dep ever silently changing its IPv6 semantics.

    #[test]
    fn ipnetwork_v4_cidr_matches_address() {
        let net: ipnetwork::IpNetwork = "10.0.0.0/8".parse().unwrap();
        let ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        assert!(net.contains(ip));
    }

    #[test]
    fn ipnetwork_v6_cidr_matches_address() {
        let net: ipnetwork::IpNetwork = "2001:db8::/32".parse().unwrap();
        let ip: std::net::IpAddr = "2001:db8:abcd::1".parse().unwrap();
        assert!(net.contains(ip));
    }

    #[test]
    fn ipnetwork_v6_loopback_does_not_match_v6_documentation_range() {
        let net: ipnetwork::IpNetwork = "2001:db8::/32".parse().unwrap();
        let ip: std::net::IpAddr = "::1".parse().unwrap();
        assert!(!net.contains(ip));
    }

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }

    #[test]
    fn instance_id_is_stable_within_process() {
        let a = instance_id();
        let b = instance_id();
        assert_eq!(a, b);
    }

    #[test]
    fn new_request_id_is_32_hex_chars() {
        let id = new_request_id();
        assert_eq!(id.len(), 32);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn config_revision_is_12_hex_chars() {
        let rev = config_revision(b"some yaml");
        assert_eq!(rev.len(), 12);
        assert!(rev
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn config_revision_changes_with_input() {
        assert_ne!(config_revision(b"config-a"), config_revision(b"config-b"),);
    }
}
