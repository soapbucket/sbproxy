//! RFC 9209 Proxy-Status header generation.
//!
//! Produces structured `Proxy-Status` header values that downstream clients and
//! intermediaries can use to diagnose forwarding errors.

/// Build an RFC 9209 `Proxy-Status` header value with the default
/// `sbproxy` identity. When an error description is provided it is
/// appended as an `error` parameter.
pub fn build_proxy_status(status: u16, error: Option<&str>) -> String {
    build_proxy_status_with_identity("sbproxy", status, error)
}

/// Build an RFC 9209 `Proxy-Status` header value with an
/// operator-configured proxy identity (e.g. `acme-edge`,
/// `sbproxy-eu-west-1`).
pub fn build_proxy_status_with_identity(
    identity: &str,
    status: u16,
    error: Option<&str>,
) -> String {
    let mut value = format!("{}; received-status={}", identity, status);
    if let Some(err) = error {
        value.push_str(&format!("; error=\"{}\"", err));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_status() {
        let header = build_proxy_status(200, None);
        assert_eq!(header, "sbproxy; received-status=200");
    }

    #[test]
    fn test_error_status() {
        let header = build_proxy_status(502, Some("connection_refused"));
        assert_eq!(
            header,
            "sbproxy; received-status=502; error=\"connection_refused\""
        );
    }

    #[test]
    fn test_custom_identity() {
        let header = build_proxy_status_with_identity("acme-edge", 504, Some("upstream_timeout"));
        assert_eq!(
            header,
            "acme-edge; received-status=504; error=\"upstream_timeout\""
        );
    }

    #[test]
    fn test_custom_identity_no_error() {
        let header = build_proxy_status_with_identity("sbproxy-eu-1", 200, None);
        assert_eq!(header, "sbproxy-eu-1; received-status=200");
    }
}
