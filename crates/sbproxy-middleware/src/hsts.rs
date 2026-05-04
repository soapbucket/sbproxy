//! HSTS (HTTP Strict Transport Security) middleware.
//!
//! Builds and applies the `Strict-Transport-Security` header based on [`HstsConfig`].

use http::{HeaderMap, HeaderValue};
use sbproxy_config::HstsConfig;

/// Build the `Strict-Transport-Security` header value string.
pub fn hsts_header_value(config: &HstsConfig) -> String {
    let mut value = format!("max-age={}", config.max_age);
    if config.include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if config.preload {
        value.push_str("; preload");
    }
    value
}

/// Apply the HSTS header to response headers.
pub fn apply_hsts(config: &HstsConfig, response_headers: &mut HeaderMap) {
    let value = hsts_header_value(config);
    if let Ok(v) = HeaderValue::from_str(&value) {
        response_headers.insert("strict-transport-security", v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Header Value Formatting ---

    #[test]
    fn test_hsts_max_age_only() {
        let config = HstsConfig {
            max_age: 86400,
            include_subdomains: false,
            preload: false,
        };
        assert_eq!(hsts_header_value(&config), "max-age=86400");
    }

    #[test]
    fn test_hsts_with_include_subdomains() {
        let config = HstsConfig {
            max_age: 31536000,
            include_subdomains: true,
            preload: false,
        };
        assert_eq!(
            hsts_header_value(&config),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[test]
    fn test_hsts_with_preload() {
        let config = HstsConfig {
            max_age: 31536000,
            include_subdomains: false,
            preload: true,
        };
        assert_eq!(hsts_header_value(&config), "max-age=31536000; preload");
    }

    #[test]
    fn test_hsts_full_options() {
        let config = HstsConfig {
            max_age: 31536000,
            include_subdomains: true,
            preload: true,
        };
        assert_eq!(
            hsts_header_value(&config),
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[test]
    fn test_hsts_zero_max_age() {
        let config = HstsConfig {
            max_age: 0,
            include_subdomains: false,
            preload: false,
        };
        assert_eq!(hsts_header_value(&config), "max-age=0");
    }

    // --- Apply to HeaderMap ---

    #[test]
    fn test_apply_hsts_sets_header() {
        let config = HstsConfig {
            max_age: 31536000,
            include_subdomains: true,
            preload: true,
        };
        let mut headers = HeaderMap::new();
        apply_hsts(&config, &mut headers);

        assert_eq!(
            headers.get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[test]
    fn test_apply_hsts_overwrites_existing() {
        let config = HstsConfig {
            max_age: 600,
            include_subdomains: false,
            preload: false,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=0"),
        );

        apply_hsts(&config, &mut headers);

        assert_eq!(
            headers.get("strict-transport-security").unwrap(),
            "max-age=600"
        );
    }
}
