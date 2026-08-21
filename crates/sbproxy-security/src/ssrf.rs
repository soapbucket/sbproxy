//! SSRF (Server-Side Request Forgery) protection.
//!
//! Validates that upstream URLs don't target private, loopback,
//! or link-local IP addresses. Used to prevent AI tools and
//! proxy actions from accessing internal infrastructure.
//!
//! ## Residual TOCTOU risk and the dial-time re-validation contract
//!
//! `validate_url` and `validate_url_with_allowlist` resolve the URL's
//! hostname to one or more [`SocketAddr`]s and reject the request if any
//! resolved address is private. There is an unavoidable TOCTOU between
//! that resolve and the actual upstream connect: a hostile DNS server can
//! return a public address at validation time and a private address (e.g.
//! 169.254.169.254) when the proxy actually dials. This is classic DNS
//! rebinding.
//!
//! The contract for callers is therefore:
//!
//! 1. Prefer [`validate_url_resolved`], which returns the resolved
//!    [`SocketAddr`] list. Pin the dial to one of those addresses.
//! 2. Re-check the chosen address with [`is_private_ip`] immediately
//!    before the dial.
//! 3. If the dial path is owned by Pingora (or any other component that
//!    re-resolves on its own), emit `tracing::error!` if the dialed peer
//!    address turns out to be private and abort the upstream call.
//!
//! ### Caller status
//!
//! This list exists so a reviewer auditing the contract above can walk
//! every path that needs dial-time re-validation without grepping.
//! Nine call sites across the workspace, split by whether the caller
//! actually pins what it validated.
//!
//! Pinned: the caller takes the [`SocketAddr`]s back and dials those.
//!
//! - `sbproxy-ai::external_guardrail`, `build_prepared`: two call sites
//!   (allowlisted and plain), both feeding `resolve_to_addrs` on the
//!   guardrail's HTTP client.
//! - `sbproxy-rag::http`, provider base URL: also re-checks each
//!   address with [`is_private_ip`] before pinning, so an
//!   `allow_private_url` typo cannot quietly open the private range.
//! - `sbproxy-observe::event_sink`, `deliver_batch`: revalidates on
//!   every batch, not once at startup, and pins the collector.
//!
//! Not pinned. Each is defensible for its own reason, and each is a
//! place the rebinding window is still open:
//!
//! - `sbproxy-core::policy_dispatch`, Confirm webhook target: the OSS
//!   pipeline never dials it. Validation is a fail-closed decision
//!   gate, not a pre-dial check.
//! - `sbproxy-modules::policy::a2a`, `check_push_notification`: the
//!   resolved addresses are discarded because the gateway does not own
//!   that dial; the remote agent does.
//! - `sbproxy-observe::alerting::channels`, `webhook_url_allowed`:
//!   validates with `validate_url` and then POSTs through a shared
//!   `reqwest` client that resolves the hostname again. This is the one
//!   caller whose own dial re-resolves, and the one to fix first.
//! - `sbproxy-ai::provider`, base URL: a config-time refusal; the
//!   provider client dials later on its own.
//! - `sbproxy-observe::event_sink`, `start_webhook_worker`: a startup
//!   refusal via `validate_url_with_allowlist` so a bad `events.url` is
//!   an operator-visible boot failure. The per-batch site above is what
//!   guards the dial.
//!
//! Separately, the Pingora dial path follows the contract above without
//! going through these functions: `guard_upstream` in
//! `sbproxy-core/src/server.rs` re-resolves the upstream host with
//! [`resolve_host_addrs`] and re-checks every resolved address with
//! [`is_private_ip`] immediately before the dial, honoring the
//! operator's `upstream.allow_private_cidrs` allowlist. The RAG Redis
//! backend pins its dial through [`resolve_host_addrs`] the same way.
//!
//! A new caller that uses an in-process HTTP client belongs in the
//! pinned list: pass the pre-resolved `SocketAddr` to the client rather
//! than letting it re-resolve the hostname.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Maximum time to wait for the system resolver. The OS default can be
/// tens of seconds, which lets a hostile DNS server stall request
/// validation and tie up worker threads.
const DNS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(2);

// --- IP range helpers ---

/// Check if an IPv4 address is in the CGNAT range (100.64.0.0/10).
fn is_cgnat(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 100.64.0.0 - 100.127.255.255
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

/// Check if an IPv4 address is in a documentation range.
/// Covers 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24.
fn is_documentation(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

/// Check if an IPv6 address is in the ULA range (fc00::/7).
fn is_ula(ip: &Ipv6Addr) -> bool {
    // ULA: first byte starts with 0b1111_110x -> 0xFC or 0xFD
    let segments = ip.segments();
    (segments[0] & 0xFE00) == 0xFC00
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xFFC0) == 0xFE80
}

/// Check if an IP address is private/internal and should be blocked.
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped before the
/// check so that an attacker cannot bypass the IPv4 link-local /
/// loopback / RFC 1918 blocks by submitting the v6-shaped form.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6: unwrap and re-check as IPv4.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ipv4(&v4);
            }
            v6.is_loopback()           // ::1
            || v6.is_unspecified()     // ::
            || is_ula(v6)              // fc00::/7
            || is_link_local_v6(v6) // fe80::/10
        }
    }
}

/// IPv4-only private/reserved check, factored out so the v6-mapped path
/// can share it.
fn is_private_ipv4(v4: &Ipv4Addr) -> bool {
    v4.is_loopback()          // 127.0.0.0/8
    || v4.is_private()         // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    || v4.is_link_local()      // 169.254.0.0/16
    || v4.is_broadcast()       // 255.255.255.255
    || v4.is_unspecified()     // 0.0.0.0
    || is_cgnat(v4)            // 100.64.0.0/10
    || is_documentation(v4) // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
}

/// A URL that has been validated and (when the host was a hostname)
/// resolved to one or more concrete socket addresses.
///
/// Callers that own the dial path should pass these addresses directly
/// to the connector and re-check each one with [`is_private_ip`] at
/// dial time. See the residual-TOCTOU note in the module-level docs.
#[derive(Debug, Clone)]
pub struct ResolvedUrl {
    /// The URL host as it appeared in the input. May be an IP literal
    /// (in which case `addrs` is a single socket-addr formed from the
    /// literal and the URL port) or a DNS name.
    pub host: String,
    /// Effective port, including the scheme default (80 / 443) when no
    /// port was explicitly present in the URL.
    pub port: u16,
    /// Resolved socket addresses. For an IP-literal URL there is exactly
    /// one entry; for a hostname URL there is at least one and every
    /// entry is guaranteed to be a public IP at validation time. None
    /// of these is guaranteed to remain public by dial time, hence the
    /// dial-time re-validation contract.
    pub addrs: Vec<SocketAddr>,
    /// True when the host matched an entry in the caller-supplied
    /// allowlist. In this mode `addrs` may contain private addresses;
    /// the caller asked for that explicitly.
    pub allowlisted: bool,
}

/// Validate a URL is safe to request (not targeting private infrastructure).
///
/// Returns `Ok(())` if safe, `Err(reason)` if blocked.
/// If the URL host is already an IP address, it is checked directly.
///
/// This is the legacy shape that does not return resolved addresses;
/// new callers should prefer [`validate_url_resolved`] so they can pin
/// the dial to a known-good [`SocketAddr`] and avoid the DNS-rebinding
/// TOCTOU described in the module docs.
pub fn validate_url(url: &str) -> Result<(), String> {
    validate_url_with_allowlist(url, &[])
}

/// Validate a URL with an allowlist of permitted internal hosts or IPs.
///
/// If the host in the URL appears in `allowlist` (exact match), the URL is
/// allowed regardless of whether the address is private.
pub fn validate_url_with_allowlist(url: &str, allowlist: &[String]) -> Result<(), String> {
    validate_url_resolved(url, allowlist).map(|_| ())
}

/// Validate a URL and return the resolved socket addresses on success.
///
/// On success the caller is expected to:
///
/// 1. Pin the dial to one of the returned [`SocketAddr`]s rather than
///    re-resolving the hostname via the OS resolver (which is what
///    enables DNS rebinding).
/// 2. Re-check the chosen address with [`is_private_ip`] immediately
///    before the dial, since the result of validation is not bound to
///    the dial in time.
///
/// Hosts in `allowlist` short-circuit the private-IP block, mirroring
/// [`validate_url_with_allowlist`]. The returned `ResolvedUrl` carries
/// `allowlisted = true` in that case so callers can decide whether to
/// suppress the dial-time `is_private_ip` re-check.
pub fn validate_url_resolved(url: &str, allowlist: &[String]) -> Result<ResolvedUrl, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "blocked scheme '{scheme}': only http/https are permitted"
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?
        .to_string();
    let port = parsed
        .port()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let allowlisted = allowlist.iter().any(|entry| entry == &host);

    // If the host is already an IP address, check it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allowlisted && is_private_ip(&ip) {
            return Err(format!("blocked: IP address {ip} is private/internal"));
        }
        return Ok(ResolvedUrl {
            host,
            port,
            addrs: vec![SocketAddr::new(ip, port)],
            allowlisted,
        });
    }

    if allowlisted {
        // Caller has explicitly allowlisted this hostname. Resolve best-
        // effort so they can still pin the dial to a SocketAddr; if
        // resolution fails we return an empty addrs vec rather than
        // blocking, preserving the original allowlist semantics. This is
        // intentional (WOR-1156): an operator who allowlists an internal
        // host (split-horizon DNS, names only resolvable at dial time)
        // wants the request permitted; the dial-time re-validation
        // contract documented at the module level is the mitigation for
        // the re-resolution TOCTOU, not failing this resolve.
        let addr_str = format!("{host}:{port}");
        let addrs = resolve_with_timeout(&addr_str, DNS_RESOLUTION_TIMEOUT).unwrap_or_default();
        return Ok(ResolvedUrl {
            host,
            port,
            addrs,
            allowlisted: true,
        });
    }

    // For hostnames we use a bounded-time blocking resolve. Two things
    // matter for security:
    //   1. A hostile DNS server could stall resolution; we cap the wait.
    //   2. A resolver error ("dns failed, try again") previously returned
    //      Ok(()) (fail-open), which let an attacker bypass the private-IP
    //      block by pointing at a name that intermittently fails to
    //      resolve. We now fail closed on any resolve error.
    // Note: there is still a TOCTOU between this resolve and the actual
    // connect. The caller is expected to dial one of the returned
    // SocketAddrs and re-validate it with `is_private_ip`.
    let addr_str = format!("{host}:{port}");
    match resolve_with_timeout(&addr_str, DNS_RESOLUTION_TIMEOUT) {
        Ok(addrs) => {
            if addrs.is_empty() {
                return Err(format!(
                    "blocked: hostname '{host}' resolved to no addresses"
                ));
            }
            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(format!(
                        "blocked: hostname '{host}' resolves to private IP {}",
                        addr.ip()
                    ));
                }
            }
            Ok(ResolvedUrl {
                host,
                port,
                addrs,
                allowlisted: false,
            })
        }
        Err(e) => Err(format!("blocked: could not resolve hostname '{host}': {e}")),
    }
}

/// Resolve `addr_str` with the system resolver, giving up after `timeout`.
///
/// Implemented by running the blocking `ToSocketAddrs` call on a background
/// thread and using a `crossbeam`-less `std::sync::mpsc` channel to collect
/// the result. If the thread has not replied by the deadline, we return a
/// timeout error and leak the worker thread (it will exit on its own when
/// the resolver finally returns); this bounds request-path latency without
/// a hard kill.
fn resolve_with_timeout(addr_str: &str, timeout: Duration) -> Result<Vec<SocketAddr>, String> {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();
    let owned = addr_str.to_string();
    std::thread::spawn(move || {
        let result: Result<Vec<SocketAddr>, String> = match owned.to_socket_addrs() {
            Ok(iter) => Ok(iter.collect()),
            Err(e) => Err(e.to_string()),
        };
        // If the main thread has already given up, this send just drops
        // the result, which is fine.
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(inner) => inner,
        Err(mpsc::RecvTimeoutError::Timeout) => Err("dns resolution timed out".to_string()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("dns resolver thread crashed".to_string()),
    }
}

/// Async, non-caching resolve of `host:port` to its full address set,
/// giving up after the `DNS_RESOLUTION_TIMEOUT` (WOR-1689).
///
/// This is the hot-path counterpart to `resolve_with_timeout`: it runs
/// `getaddrinfo` on tokio's shared blocking pool and `await`s it, so a
/// slow or hostile resolver yields the worker instead of pinning it, and
/// no per-request OS thread is spawned. It deliberately does NOT cache:
/// the SSRF verdict must be recomputed on every request so a host that is
/// re-pointed at a private address (DNS rebinding) cannot ride a stale
/// "allowed" verdict. Callers treat any `Err` as fail-closed.
pub async fn resolve_host_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    match tokio::time::timeout(
        DNS_RESOLUTION_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(iter)) => Ok(iter.collect()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("dns resolution timed out".to_string()),
    }
}

// --- Use of std's ToSocketAddrs ---

use std::net::ToSocketAddrs;

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_private_ip: IPv4 ---

    #[test]
    fn loopback_v4_is_private() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn private_class_a_is_private() {
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn private_class_b_is_private() {
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.31.255.255".parse().unwrap()));
    }

    #[test]
    fn private_class_c_is_private() {
        assert!(is_private_ip(&"192.168.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn link_local_v4_is_private() {
        assert!(is_private_ip(&"169.254.0.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn broadcast_is_private() {
        assert!(is_private_ip(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn unspecified_v4_is_private() {
        assert!(is_private_ip(&"0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn cgnat_range_is_private() {
        // 100.64.0.0/10 -> 100.64.0.0 - 100.127.255.255
        assert!(is_private_ip(&"100.64.0.0".parse().unwrap()));
        assert!(is_private_ip(&"100.100.1.2".parse().unwrap()));
        assert!(is_private_ip(&"100.127.255.255".parse().unwrap()));
        // Boundary: 100.128.0.0 is outside CGNAT.
        assert!(!is_private_ip(&"100.128.0.0".parse().unwrap()));
    }

    #[test]
    fn documentation_ranges_are_private() {
        assert!(is_private_ip(&"192.0.2.1".parse().unwrap()));
        assert!(is_private_ip(&"198.51.100.1".parse().unwrap()));
        assert!(is_private_ip(&"203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn public_ipv4_allowed() {
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip(&"93.184.216.34".parse().unwrap()));
    }

    // --- is_private_ip: IPv6 ---

    #[test]
    fn loopback_v6_is_private() {
        assert!(is_private_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn unspecified_v6_is_private() {
        assert!(is_private_ip(&"::".parse().unwrap()));
    }

    #[test]
    fn ula_v6_is_private() {
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fd12:3456:789a::1".parse().unwrap()));
    }

    #[test]
    fn link_local_v6_is_private() {
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::dead:beef".parse().unwrap()));
    }

    #[test]
    fn public_ipv6_allowed() {
        assert!(!is_private_ip(&"2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_private_ip(&"2606:4700:4700::1111".parse().unwrap()));
    }

    // --- validate_url ---

    #[test]
    fn url_with_private_ip_blocked() {
        assert!(validate_url("http://192.168.1.1/api").is_err());
        assert!(validate_url("https://10.0.0.1/secret").is_err());
        assert!(validate_url("http://127.0.0.1:8080/").is_err());
    }

    #[test]
    fn url_with_public_ip_allowed() {
        assert!(validate_url("https://8.8.8.8/dns").is_ok());
        assert!(validate_url("http://1.1.1.1/").is_ok());
    }

    #[test]
    fn url_with_link_local_blocked() {
        assert!(validate_url("http://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn url_with_cgnat_blocked() {
        assert!(validate_url("http://100.64.0.1/").is_err());
    }

    #[test]
    fn invalid_url_returns_error() {
        assert!(validate_url("not a url").is_err());
        assert!(validate_url("").is_err());
    }

    #[test]
    fn non_http_scheme_blocked() {
        assert!(validate_url("ftp://example.com/file").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    // --- validate_url_with_allowlist ---

    #[test]
    fn allowlisted_private_ip_host_is_permitted() {
        let allowlist = vec!["192.168.1.100".to_string()];
        assert!(validate_url_with_allowlist("http://192.168.1.100/api", &allowlist).is_ok());
    }

    #[test]
    fn allowlisted_private_hostname_is_permitted() {
        let allowlist = vec!["internal.corp".to_string()];
        // Hostname doesn't resolve in test, so it passes through anyway;
        // allowlist check ensures it is always permitted regardless.
        assert!(validate_url_with_allowlist("http://internal.corp/api", &allowlist).is_ok());
    }

    #[test]
    fn non_allowlisted_private_ip_still_blocked() {
        let allowlist = vec!["192.168.1.100".to_string()];
        assert!(validate_url_with_allowlist("http://10.0.0.1/api", &allowlist).is_err());
    }

    #[test]
    fn empty_allowlist_same_as_validate_url() {
        assert!(validate_url_with_allowlist("http://127.0.0.1/", &[]).is_err());
        assert!(validate_url_with_allowlist("https://8.8.8.8/", &[]).is_ok());
    }

    // --- is_cgnat boundary ---

    #[test]
    fn cgnat_boundary_100_63_is_public() {
        // 100.63.255.255 is just below CGNAT range.
        assert!(!is_private_ip(&"100.63.255.255".parse().unwrap()));
    }

    #[test]
    fn cgnat_boundary_100_64_is_private() {
        assert!(is_private_ip(&"100.64.0.0".parse().unwrap()));
    }

    // --- IPv4-mapped IPv6 ---

    #[test]
    fn ipv4_mapped_ipv6_loopback_blocked() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_private_ip(&mapped));
    }

    #[test]
    fn ipv4_mapped_ipv6_metadata_blocked() {
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_private_ip(&mapped));
    }

    #[test]
    fn ipv4_mapped_ipv6_public_allowed() {
        let mapped: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(&mapped));
    }

    // --- validate_url_resolved ---

    #[test]
    fn validate_url_resolved_returns_socket_addr_for_public_ip() {
        let resolved =
            validate_url_resolved("http://8.8.8.8:53/", &[]).expect("public IP must resolve");
        assert_eq!(resolved.host, "8.8.8.8");
        assert_eq!(resolved.port, 53);
        assert_eq!(resolved.addrs.len(), 1);
        assert_eq!(resolved.addrs[0].ip(), "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(resolved.addrs[0].port(), 53);
        assert!(!resolved.allowlisted);
    }

    #[test]
    fn validate_url_resolved_default_port_https() {
        let resolved =
            validate_url_resolved("https://1.1.1.1/", &[]).expect("public IP must resolve");
        assert_eq!(resolved.port, 443);
        assert_eq!(resolved.addrs[0].port(), 443);
    }

    #[test]
    fn validate_url_resolved_default_port_http() {
        let resolved =
            validate_url_resolved("http://1.1.1.1/", &[]).expect("public IP must resolve");
        assert_eq!(resolved.port, 80);
    }

    #[test]
    fn validate_url_resolved_blocks_private_ip() {
        assert!(validate_url_resolved("http://10.0.0.1/", &[]).is_err());
    }

    #[test]
    fn validate_url_resolved_allowlist_returns_allowlisted_flag() {
        let allowlist = vec!["192.168.1.100".to_string()];
        let resolved = validate_url_resolved("http://192.168.1.100:8080/api", &allowlist)
            .expect("allowlisted private IP must pass");
        assert!(resolved.allowlisted);
        assert_eq!(resolved.addrs.len(), 1);
        assert_eq!(resolved.addrs[0].port(), 8080);
    }
}

/// Guard for the "Caller status" block in this module's docs.
///
/// That block is not decoration. It is the enumeration a reviewer walks
/// when auditing the dial-time re-validation contract, so a call site
/// missing from it is a call site nobody audits. It went stale exactly
/// that way once: two `sbproxy-observe::event_sink` sites existed while
/// the block still said `validate_url_with_allowlist` had no callers
/// outside this module.
///
/// What it cannot see, and what still needs a human reviewer:
///
/// - A caller that renames the import (`use ... as check;`) or reaches
///   these functions through a macro. It matches on the function name
///   followed by an open paren, nothing cleverer.
/// - Whether a caller listed as pinned actually pins. The pinned /
///   not-pinned split in the block is prose, and only the count and the
///   membership are checked here.
#[cfg(test)]
mod caller_status_guard {
    use std::path::{Path, PathBuf};

    /// Every entry point outside code can call to validate a URL. The
    /// trailing paren is what separates a call from a `use` line or a
    /// doc reference.
    const VALIDATORS: &[&str] = &[
        "validate_url(",
        "validate_url_with_allowlist(",
        "validate_url_resolved(",
    ];

    /// The doc block spells its count as a word, so the guard has to
    /// read one.
    const NUMBER_WORDS: &[&str] = &[
        "Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
        "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen",
    ];

    fn rust_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let skip = path
                        .file_name()
                        .is_some_and(|n| n == "target" || n == "node_modules");
                    if !skip {
                        stack.push(path);
                    }
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        out
    }

    /// `crates/sbproxy-observe/src/alerting/channels.rs` becomes
    /// `sbproxy-observe::alerting::channels`, which is the form the doc
    /// block names callers in.
    fn qualified_name(crates_dir: &Path, file: &Path) -> Option<String> {
        let rel = file.strip_prefix(crates_dir).ok()?;
        let mut parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if parts.len() < 3 || parts[1] != "src" {
            return None;
        }
        let krate = parts[0].clone();
        let mut modules: Vec<String> = parts.drain(2..).collect();
        let leaf = modules.pop()?;
        let leaf = leaf.strip_suffix(".rs")?.to_string();
        if leaf != "mod" && leaf != "lib" {
            modules.push(leaf);
        }
        Some(format!("{krate}::{}", modules.join("::")))
    }

    #[test]
    fn caller_status_block_names_every_call_site() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let crates_dir = manifest.parent().expect("crate lives under crates/");
        assert!(
            crates_dir.join("sbproxy-security").is_dir(),
            "this guard reads the workspace source tree; {} is not it",
            crates_dir.display()
        );

        let this_file = manifest.join("src").join("ssrf.rs");
        let source = std::fs::read_to_string(&this_file).expect("read ssrf.rs");
        let block = source
            .split("//! ### Caller status")
            .nth(1)
            .expect("caller-status block still exists")
            .split("\nuse ")
            .next()
            .expect("block ends where the code starts");

        let mut sites = 0usize;
        let mut unnamed: Vec<String> = Vec::new();
        for file in rust_files(crates_dir) {
            if file == this_file {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let calls = text
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.starts_with("//")
                        && !trimmed.starts_with('*')
                        && VALIDATORS.iter().any(|v| trimmed.contains(*v))
                })
                .count();
            if calls == 0 {
                continue;
            }
            sites += calls;
            match qualified_name(crates_dir, &file) {
                // A call site outside `<crate>/src/` is not something
                // the doc's naming scheme can express, so it is a
                // finding rather than something to skip quietly.
                None => unnamed.push(file.display().to_string()),
                Some(name) => {
                    if !block.contains(&format!("`{name}`")) {
                        unnamed.push(format!("{name} ({calls} call sites)"));
                    }
                }
            }
        }

        assert!(
            unnamed.is_empty(),
            "the caller-status block does not name these SSRF-validating call sites: {unnamed:?}"
        );
        let word = NUMBER_WORDS
            .get(sites)
            .copied()
            .expect("call-site count is within the guard's vocabulary");
        assert!(
            block.contains(&format!("{word} call sites")),
            "the caller-status block claims a count other than {sites} ({word})"
        );
    }
}
