//! HAProxy PROXY protocol v1 parser.
//!
//! Parses the PROXY protocol v1 TCP header that some load balancers prepend to
//! incoming connections to convey the original client IP and port.
//!
//! # Format
//! ```text
//! PROXY <protocol> <src_ip> <dst_ip> <src_port> <dst_port>\r\n
//! ```
//!
//! Supported protocols: `TCP4` (IPv4) and `TCP6` (IPv6).
//!
//! # Reference
//! <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>

use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};

// --- ProxyProtocolHeader ---

/// Decoded PROXY protocol v1 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyProtocolHeader {
    /// Protocol string: `"TCP4"` or `"TCP6"`.
    pub protocol: String,
    /// Source (client) IP address.
    pub src_addr: IpAddr,
    /// Destination (server) IP address.
    pub dst_addr: IpAddr,
    /// Source (client) TCP port.
    pub src_port: u16,
    /// Destination (server) TCP port.
    pub dst_port: u16,
}

// --- Parser ---

/// Parse a PROXY protocol v1 header line.
///
/// The `line` argument should be the first line of the TCP connection, including
/// the trailing `\r\n`.  Lines without the `\r\n` terminator are also accepted
/// for convenience.
///
/// # Errors
/// Returns an error if:
/// - The line does not start with `"PROXY "`.
/// - The protocol is not `TCP4` or `TCP6`.
/// - IP addresses cannot be parsed.
/// - Ports are outside the valid range (1–65535) or cannot be parsed.
/// - The number of fields is not exactly 6.
pub fn parse_proxy_protocol_v1(line: &str) -> Result<ProxyProtocolHeader> {
    // Strip the \r\n terminator (or just \n, or nothing).
    let line = line.trim_end_matches('\n').trim_end_matches('\r');

    // Must start with "PROXY ".
    if !line.starts_with("PROXY ") {
        bail!("not a PROXY protocol header: missing 'PROXY' prefix");
    }

    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() != 6 {
        bail!(
            "PROXY protocol header must have 6 fields, got {}",
            parts.len()
        );
    }

    // parts: ["PROXY", protocol, src_ip, dst_ip, src_port, dst_port]
    let protocol = parts[1];
    let src_ip_str = parts[2];
    let dst_ip_str = parts[3];
    let src_port_str = parts[4];
    let dst_port_str = parts[5];

    // Validate protocol.
    match protocol {
        "TCP4" | "TCP6" => {}
        other => bail!(
            "unsupported PROXY protocol: '{}' (expected TCP4 or TCP6)",
            other
        ),
    }

    // Parse source IP.
    let src_addr = IpAddr::from_str(src_ip_str)
        .map_err(|e| anyhow!("invalid source IP '{}': {}", src_ip_str, e))?;

    // Parse destination IP.
    let dst_addr = IpAddr::from_str(dst_ip_str)
        .map_err(|e| anyhow!("invalid destination IP '{}': {}", dst_ip_str, e))?;

    // Validate IP version matches protocol.
    match protocol {
        "TCP4" if !src_addr.is_ipv4() => bail!("TCP4 header contains IPv6 source address"),
        "TCP4" if !dst_addr.is_ipv4() => bail!("TCP4 header contains IPv6 destination address"),
        "TCP6" if !src_addr.is_ipv6() => bail!("TCP6 header contains IPv4 source address"),
        "TCP6" if !dst_addr.is_ipv6() => bail!("TCP6 header contains IPv4 destination address"),
        _ => {}
    }

    // Parse source port.
    let src_port: u16 = src_port_str
        .parse()
        .map_err(|_| anyhow!("invalid source port '{}'", src_port_str))?;

    // Parse destination port.
    let dst_port: u16 = dst_port_str
        .parse()
        .map_err(|_| anyhow!("invalid destination port '{}'", dst_port_str))?;

    // Ports must be non-zero.
    if src_port == 0 {
        bail!("source port must be non-zero");
    }
    if dst_port == 0 {
        bail!("destination port must be non-zero");
    }

    Ok(ProxyProtocolHeader {
        protocol: protocol.to_string(),
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    })
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- Valid TCP4 ---

    #[test]
    fn parse_tcp4_with_crlf() {
        let header =
            parse_proxy_protocol_v1("PROXY TCP4 192.168.1.1 10.0.0.1 12345 80\r\n").unwrap();
        assert_eq!(header.protocol, "TCP4");
        assert_eq!(header.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(header.dst_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(header.src_port, 12345);
        assert_eq!(header.dst_port, 80);
    }

    #[test]
    fn parse_tcp4_without_crlf() {
        let header = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 1024 443").unwrap();
        assert_eq!(header.protocol, "TCP4");
        assert_eq!(header.src_port, 1024);
        assert_eq!(header.dst_port, 443);
    }

    #[test]
    fn parse_tcp4_loopback() {
        let header =
            parse_proxy_protocol_v1("PROXY TCP4 127.0.0.1 127.0.0.1 50000 8080\r\n").unwrap();
        assert_eq!(header.src_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(header.dst_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    // --- Valid TCP6 ---

    #[test]
    fn parse_tcp6_with_crlf() {
        let header = parse_proxy_protocol_v1("PROXY TCP6 ::1 ::1 12345 80\r\n").unwrap();
        assert_eq!(header.protocol, "TCP6");
        assert_eq!(header.src_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(header.dst_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(header.src_port, 12345);
        assert_eq!(header.dst_port, 80);
    }

    #[test]
    fn parse_tcp6_full_address() {
        let header =
            parse_proxy_protocol_v1("PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\n").unwrap();
        assert_eq!(header.protocol, "TCP6");
        assert_eq!(header.src_addr, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(header.dst_addr, "2001:db8::2".parse::<IpAddr>().unwrap());
    }

    // --- Invalid headers ---

    #[test]
    fn reject_missing_proxy_prefix() {
        let result = parse_proxy_protocol_v1("TCP4 1.2.3.4 5.6.7.8 80 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing 'PROXY' prefix"));
    }

    #[test]
    fn reject_empty_string() {
        let result = parse_proxy_protocol_v1("");
        assert!(result.is_err());
    }

    #[test]
    fn reject_unknown_protocol() {
        let result = parse_proxy_protocol_v1("PROXY UDP4 1.2.3.4 5.6.7.8 80 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unsupported PROXY protocol"));
    }

    #[test]
    fn reject_too_few_fields() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("6 fields"));
    }

    #[test]
    fn reject_too_many_fields() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 80 443 extra\r\n");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_src_ip() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 not.an.ip 5.6.7.8 80 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid source IP"));
    }

    #[test]
    fn reject_invalid_dst_ip() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 not.an.ip 80 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid destination IP"));
    }

    #[test]
    fn reject_invalid_src_port() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 abc 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid source port"));
    }

    #[test]
    fn reject_invalid_dst_port() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 80 xyz\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid destination port"));
    }

    #[test]
    fn reject_zero_src_port() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 0 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("source port must be non-zero"));
    }

    #[test]
    fn reject_zero_dst_port() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 80 0\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("destination port must be non-zero"));
    }

    #[test]
    fn reject_tcp4_with_ipv6_src() {
        let result = parse_proxy_protocol_v1("PROXY TCP4 ::1 1.2.3.4 80 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("TCP4 header contains IPv6 source address"));
    }

    #[test]
    fn reject_tcp6_with_ipv4_src() {
        let result = parse_proxy_protocol_v1("PROXY TCP6 1.2.3.4 ::1 80 443\r\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("TCP6 header contains IPv4 source address"));
    }

    #[test]
    fn port_at_maximum_value() {
        let header = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 65535 65534\r\n").unwrap();
        assert_eq!(header.src_port, 65535);
        assert_eq!(header.dst_port, 65534);
    }

    // --- Equality ---

    #[test]
    fn header_equality() {
        let h1 = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 1000 80\r\n").unwrap();
        let h2 = parse_proxy_protocol_v1("PROXY TCP4 1.2.3.4 5.6.7.8 1000 80\r\n").unwrap();
        assert_eq!(h1, h2);
    }
}
