//! RFC 9209 Proxy-Status header generation.
//!
//! Produces structured `Proxy-Status` header values that downstream clients and
//! intermediaries can use to diagnose forwarding errors.

/// Build an RFC 9209 `Proxy-Status` header value.
///
/// The proxy token is always `sbproxy`. When an error description is provided it
/// is appended as an `error` parameter.
pub fn build_proxy_status(status: u16, error: Option<&str>) -> String {
    let mut value = format!("sbproxy; received-status={}", status);
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
}
