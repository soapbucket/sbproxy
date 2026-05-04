//! Origin-scoped secret isolation and auto-scoping.
//!
//! Secret references follow a dot-free hierarchical naming scheme:
//!
//! - `system:<name>` - proxy infrastructure secrets (not accessible from origin config)
//! - `origin:<hostname>:<name>` - per-origin secrets
//! - `shared:<name>` or bare `<name>` - available to all origins

/// Secret scope determines which contexts may access a secret.
#[derive(Debug, Clone, PartialEq)]
pub enum SecretScope {
    /// `secret:system:name` - proxy infrastructure only.
    System,
    /// `secret:origin:hostname:name` - per-origin, isolated.
    Origin(String),
    /// `secret:name` or `secret:shared:name` - available to all origins.
    Shared,
}

/// Parse a secret reference (without the `secret:` prefix) into its scope and
/// canonical name.
///
/// # Examples
///
/// ```
/// use sbproxy_vault::scope::{parse_scope, SecretScope};
///
/// let (scope, name) = parse_scope("system:db_pass");
/// assert_eq!(scope, SecretScope::System);
/// assert_eq!(name, "db_pass");
///
/// let (scope, name) = parse_scope("origin:api.example.com:key");
/// assert_eq!(scope, SecretScope::Origin("api.example.com".into()));
/// assert_eq!(name, "key");
/// ```
pub fn parse_scope(reference: &str) -> (SecretScope, String) {
    if let Some(rest) = reference.strip_prefix("system:") {
        (SecretScope::System, rest.to_string())
    } else if let Some(rest) = reference.strip_prefix("origin:") {
        // origin:<hostname>:<name>
        if let Some(colon_idx) = rest.find(':') {
            let hostname = &rest[..colon_idx];
            let name = &rest[colon_idx + 1..];
            (SecretScope::Origin(hostname.to_string()), name.to_string())
        } else {
            // Malformed origin reference; treat as shared.
            (SecretScope::Shared, reference.to_string())
        }
    } else if let Some(rest) = reference.strip_prefix("shared:") {
        (SecretScope::Shared, rest.to_string())
    } else {
        (SecretScope::Shared, reference.to_string())
    }
}

/// Auto-scope a bare secret reference within an origin context.
///
/// A bare name (no `shared:`, `system:`, or `origin:` prefix) inside origin
/// config is automatically scoped to that origin.
///
/// `"secret:name"` inside origin `"api.example.com"` becomes
/// `"origin:api.example.com:name"`.
pub fn auto_scope(reference: &str, origin_hostname: &str) -> String {
    let (scope, _) = parse_scope(reference);
    match scope {
        // Only bare names (parsed as Shared without an explicit prefix) get auto-scoped.
        SecretScope::Shared
            if !reference.starts_with("shared:")
                && !reference.starts_with("system:")
                && !reference.starts_with("origin:") =>
        {
            format!("origin:{}:{}", origin_hostname, reference)
        }
        _ => reference.to_string(),
    }
}

/// Validate that a secret reference is accessible from the given context.
///
/// Returns `Err` with a human-readable message if access should be denied.
///
/// - `context_hostname = None` means proxy-level (system) config.
/// - `context_hostname = Some("api.example.com")` means an origin config block.
pub fn validate_access(reference: &str, context_hostname: Option<&str>) -> Result<(), String> {
    let (scope, _) = parse_scope(reference);
    match scope {
        SecretScope::System => {
            if context_hostname.is_some() {
                Err(format!(
                    "system secret '{}' cannot be accessed from origin config",
                    reference
                ))
            } else {
                Ok(())
            }
        }
        SecretScope::Origin(ref hostname) => match context_hostname {
            Some(ctx_host) if ctx_host != hostname => Err(format!(
                "cross-origin secret access denied: origin '{}' cannot access secrets for '{}'",
                ctx_host, hostname
            )),
            None => Ok(()), // proxy-level config may access any origin's secrets
            _ => Ok(()),
        },
        SecretScope::Shared => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_scope ---

    #[test]
    fn parse_system_scope() {
        let (scope, name) = parse_scope("system:db_password");
        assert_eq!(scope, SecretScope::System);
        assert_eq!(name, "db_password");
    }

    #[test]
    fn parse_origin_scope() {
        let (scope, name) = parse_scope("origin:api.example.com:openai_key");
        assert_eq!(scope, SecretScope::Origin("api.example.com".to_string()));
        assert_eq!(name, "openai_key");
    }

    #[test]
    fn parse_shared_scope_explicit() {
        let (scope, name) = parse_scope("shared:global_token");
        assert_eq!(scope, SecretScope::Shared);
        assert_eq!(name, "global_token");
    }

    #[test]
    fn parse_bare_name_is_shared() {
        let (scope, name) = parse_scope("my_api_key");
        assert_eq!(scope, SecretScope::Shared);
        assert_eq!(name, "my_api_key");
    }

    #[test]
    fn parse_origin_missing_name_falls_back_to_shared() {
        // "origin:hostname" with no trailing colon is malformed
        let (scope, _) = parse_scope("origin:hostname-only");
        assert_eq!(scope, SecretScope::Shared);
    }

    // --- auto_scope ---

    #[test]
    fn auto_scope_bare_name_gets_scoped_to_origin() {
        let result = auto_scope("my_secret", "api.example.com");
        assert_eq!(result, "origin:api.example.com:my_secret");
    }

    #[test]
    fn auto_scope_preserves_explicit_shared_prefix() {
        let result = auto_scope("shared:global_key", "api.example.com");
        assert_eq!(result, "shared:global_key");
    }

    #[test]
    fn auto_scope_preserves_explicit_origin_prefix() {
        let result = auto_scope("origin:other.com:key", "api.example.com");
        assert_eq!(result, "origin:other.com:key");
    }

    #[test]
    fn auto_scope_preserves_system_prefix() {
        let result = auto_scope("system:infra_key", "api.example.com");
        assert_eq!(result, "system:infra_key");
    }

    // --- validate_access ---

    #[test]
    fn validate_same_origin_allowed() {
        let result = validate_access("origin:api.example.com:key", Some("api.example.com"));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_cross_origin_rejected() {
        let result = validate_access("origin:other.example.com:key", Some("api.example.com"));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("cross-origin"));
        assert!(msg.contains("api.example.com"));
        assert!(msg.contains("other.example.com"));
    }

    #[test]
    fn validate_system_from_origin_rejected() {
        let result = validate_access("system:db_password", Some("api.example.com"));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("system secret"));
    }

    #[test]
    fn validate_system_from_proxy_allowed() {
        let result = validate_access("system:db_password", None);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_shared_from_any_origin_allowed() {
        let result = validate_access("shared:public_token", Some("api.example.com"));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_origin_secret_from_proxy_level_allowed() {
        // Proxy-level config (None context) may access any origin's secrets.
        let result = validate_access("origin:api.example.com:key", None);
        assert!(result.is_ok());
    }
}
