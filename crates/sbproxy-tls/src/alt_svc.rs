//! Alt-Svc header generation for HTTP/3 advertisement.

/// Build the value for an `Alt-Svc` header that advertises HTTP/3 on the given port.
///
/// The `ma` (max-age) directive is set to 86400 seconds (24 hours).
///
/// # Example
/// ```
/// use sbproxy_tls::alt_svc::h3_alt_svc_value;
/// assert_eq!(h3_alt_svc_value(443), "h3=\":443\"; ma=86400");
/// ```
pub fn h3_alt_svc_value(port: u16) -> String {
    format!("h3=\":{}\"; ma=86400", port)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_https_port() {
        assert_eq!(h3_alt_svc_value(443), "h3=\":443\"; ma=86400");
    }

    #[test]
    fn test_alt_https_port() {
        assert_eq!(h3_alt_svc_value(8443), "h3=\":8443\"; ma=86400");
    }
}
