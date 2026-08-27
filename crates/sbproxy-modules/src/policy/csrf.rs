//! CSRF token validation policy.
//!
//! Compares the token in the request header against the token in the
//! cookie. Protected methods (POST, PUT, DELETE by default) require a
//! valid CSRF token; safe methods (GET, HEAD, OPTIONS) are exempt.

use serde::Deserialize;

fn default_csrf_header() -> String {
    "X-CSRF-Token".to_string()
}

fn default_csrf_cookie() -> String {
    "csrf_token".to_string()
}

fn default_safe_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()]
}

/// CSRF token validation policy.
///
/// Compares the token in the request header against the token in the
/// cookie. Protected methods (POST, PUT, DELETE by default) require a
/// valid CSRF token. All other methods are considered safe.
#[derive(Clone, Deserialize)]
pub struct CsrfPolicy {
    /// HMAC key used to sign CSRF tokens. Go configs use `secret` instead of `secret_key`.
    #[serde(alias = "secret")]
    pub secret_key: String,
    /// Name of the request header carrying the CSRF token.
    #[serde(default = "default_csrf_header")]
    pub header_name: String,
    /// Name of the cookie carrying the canonical CSRF token.
    #[serde(default = "default_csrf_cookie")]
    pub cookie_name: String,
    /// Methods that require CSRF token validation. All other methods are
    /// considered safe and exempt. Default: POST, PUT, DELETE.
    /// Go configs use `methods` for this field.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Legacy: safe_methods (inverse of methods). If set and methods is
    /// empty, protected methods = everything NOT in safe_methods.
    #[serde(default = "default_safe_methods")]
    pub safe_methods: Vec<String>,
    /// Go compat: cookie path.
    #[serde(default)]
    pub cookie_path: Option<String>,
    /// Go compat: cookie SameSite attribute.
    #[serde(default)]
    pub cookie_same_site: Option<String>,
    /// Go compat: paths exempt from CSRF checking.
    #[serde(default)]
    pub exempt_paths: Vec<String>,
}

/// Redacted `Debug` (WOR-2640). `secret_key` is the HMAC key that
/// signs CSRF tokens, so reading it is enough to forge one and defeat
/// the policy entirely. Header, cookie and method configuration stay:
/// they are what an operator debugging a false rejection needs, and
/// none of them is a secret.
impl std::fmt::Debug for CsrfPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrfPolicy")
            .field("secret_key", &"[REDACTED]")
            .field("header_name", &self.header_name)
            .field("cookie_name", &self.cookie_name)
            .field("methods", &self.methods)
            .field("safe_methods", &self.safe_methods)
            .field("cookie_path", &self.cookie_path)
            .field("cookie_same_site", &self.cookie_same_site)
            .field("exempt_paths", &self.exempt_paths)
            .finish()
    }
}

impl CsrfPolicy {
    /// Build a CsrfPolicy from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let policy: Self = serde_json::from_value(value)?;
        Ok(policy)
    }

    /// Check whether a method is protected (requires CSRF token).
    pub fn is_protected_method(&self, method: &str) -> bool {
        if !self.methods.is_empty() {
            // Explicit protected methods list.
            self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
        } else {
            // Infer from safe_methods: any method not in safe_methods is protected.
            !self
                .safe_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn csrf_policy_type() {
        let policy = CsrfPolicy::from_config(serde_json::json!({
            "secret_key": "test-secret"
        }))
        .unwrap();
        let policy = Policy::Csrf(policy);
        assert_eq!(policy.policy_type(), "csrf");
    }

    #[test]
    fn csrf_from_config_defaults() {
        let policy = CsrfPolicy::from_config(serde_json::json!({
            "secret_key": "my-secret"
        }))
        .unwrap();

        assert_eq!(policy.secret_key, "my-secret");
        assert_eq!(policy.header_name, "X-CSRF-Token");
        assert_eq!(policy.cookie_name, "csrf_token");
        assert_eq!(policy.safe_methods, vec!["GET", "HEAD", "OPTIONS"]);
    }

    #[test]
    fn csrf_from_config_custom() {
        let policy = CsrfPolicy::from_config(serde_json::json!({
            "secret_key": "s3cr3t",
            "header_name": "X-My-Token",
            "cookie_name": "my_csrf",
            "safe_methods": ["GET"]
        }))
        .unwrap();

        assert_eq!(policy.header_name, "X-My-Token");
        assert_eq!(policy.cookie_name, "my_csrf");
        assert_eq!(policy.safe_methods, vec!["GET"]);
    }

    #[test]
    fn csrf_missing_secret_key_errors() {
        let result = CsrfPolicy::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    /// WOR-2640: the CSRF signing key is what makes a token
    /// unforgeable, so anything that reads it defeats the policy.
    #[test]
    fn debug_never_renders_the_csrf_signing_key() {
        const SENTINEL: &str = "SENTINEL-SECRET-9f3a";
        let policy = CsrfPolicy {
            secret_key: SENTINEL.to_string(),
            header_name: "x-csrf-token".to_string(),
            cookie_name: "csrf".to_string(),
            methods: vec!["POST".to_string()],
            safe_methods: Vec::new(),
            cookie_path: None,
            cookie_same_site: None,
            exempt_paths: Vec::new(),
        };
        let rendered = format!("{policy:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the CSRF signing key reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("x-csrf-token") && rendered.contains("csrf"),
            "the header and cookie names must survive: {rendered}"
        );
    }
}
