//! Request and response header modifiers.
//!
//! Applies set, add, and remove operations to HTTP header maps based on
//! [`HeaderModifiers`], [`RequestModifierConfig`], and [`ResponseModifierConfig`].

use std::collections::HashMap;

use http::{header::HeaderName, HeaderMap, HeaderValue};
use sbproxy_config::{HeaderModifiers, RequestModifierConfig, ResponseModifierConfig};

/// Template context for resolving `{{key}}` patterns in header values.
///
/// Contains request metadata and origin variables that can be referenced
/// in modifier header values using Mustache-style `{{key}}` syntax.
///
/// # Environment variable allowlist (security)
///
/// `{{env.X}}` expansion is gated by [`Self::allowed_env_vars`]. In
/// multi-tenant deployments any tenant could otherwise inject a header
/// like `X-Leak: {{env.AWS_SECRET_ACCESS_KEY}}` and exfiltrate secrets
/// to an upstream they control. The default is an empty allowlist,
/// which means no `{{env.X}}` template ever resolves. Operators must
/// explicitly opt in by populating the allowlist with the env var names
/// (without the `env.` prefix) that are safe for header interpolation.
pub struct TemplateContext {
    /// Flat key-value map. Keys like `request.id`, `request.method`,
    /// `request.path`, `vars.app_name`, etc.
    pub values: HashMap<String, String>,
    /// Env var names (without the `env.` prefix) permitted for
    /// `{{env.X}}` interpolation. Defaults to an empty list, which
    /// blocks all env expansion.
    pub allowed_env_vars: Vec<String>,
}

impl TemplateContext {
    /// Create an empty template context with no env vars allowlisted.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            allowed_env_vars: Vec::new(),
        }
    }

    /// Resolve `{{key}}` patterns in a string.
    ///
    /// Supports the following template patterns:
    /// - `{{vars.X}}` - origin-defined variables (looked up in `self.values`)
    /// - `{{request.id}}`, `{{request.method}}`, etc. - request metadata
    /// - `{{env.X}}` - environment variables (only resolved when `X` is in
    ///   [`Self::allowed_env_vars`]; otherwise the template expands to
    ///   the empty string and a `tracing::warn!` is emitted)
    ///
    /// Unresolved non-env patterns are left as-is in the output.
    pub fn resolve(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut rest = input;

        while let Some(start) = rest.find("{{") {
            result.push_str(&rest[..start]);
            let after_open = &rest[start + 2..];
            if let Some(end) = after_open.find("}}") {
                let key = after_open[..end].trim();
                if let Some(val) = self.values.get(key) {
                    result.push_str(val);
                } else if let Some(env_name) = key.strip_prefix("env.") {
                    // Env var expansion is gated by an explicit
                    // operator allowlist. Anything not on the list
                    // resolves to the empty string and is logged.
                    // This blocks template-based exfiltration of
                    // process secrets in multi-tenant deployments
                    // (OPENSOURCE.md H4).
                    if self.allowed_env_vars.iter().any(|n| n == env_name) {
                        match std::env::var(env_name) {
                            Ok(val) => result.push_str(&val),
                            Err(_) => {
                                // Allowlisted but unset: leave the
                                // template literal so config errors
                                // surface as obviously broken headers
                                // rather than silently empty.
                                result.push_str("{{");
                                result.push_str(&after_open[..end]);
                                result.push_str("}}");
                            }
                        }
                    } else {
                        tracing::warn!(
                            env_var = %env_name,
                            "blocked env template: env var not in allowed_env_vars allowlist"
                        );
                        // Resolve to empty string so the secret is not
                        // leaked even if X is set in the process
                        // environment.
                    }
                } else {
                    // Leave unresolved templates as-is.
                    result.push_str("{{");
                    result.push_str(&after_open[..end]);
                    result.push_str("}}");
                }
                rest = &after_open[end + 2..];
            } else {
                // No closing }}, push the rest as-is.
                result.push_str(&rest[start..]);
                rest = "";
                break;
            }
        }
        result.push_str(rest);
        result
    }
}

impl Default for TemplateContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply header modifications (remove, set, add) to a header map.
///
/// Operations are applied in this order:
/// 1. **Remove** - delete headers by name
/// 2. **Set** - insert or overwrite headers
/// 3. **Add** - append additional header values
///
/// This ordering ensures that a set + add for the same key results in both values
/// being present, and that removals do not clobber subsequent sets.
pub fn apply_header_modifiers(modifiers: &HeaderModifiers, headers: &mut HeaderMap) {
    // 1. Remove
    for key in &modifiers.remove {
        headers.remove(key.as_str());
    }

    // 2. Set (overwrite)
    for (key, value) in &modifiers.set {
        if let (Ok(name), Ok(val)) = (key.parse::<HeaderName>(), HeaderValue::from_str(value)) {
            headers.insert(name, val);
        }
    }

    // 3. Add (append)
    for (key, value) in &modifiers.add {
        if let (Ok(name), Ok(val)) = (key.parse::<HeaderName>(), HeaderValue::from_str(value)) {
            headers.append(name, val);
        }
    }
}

/// Apply header modifiers with template variable interpolation.
///
/// Same as [`apply_header_modifiers`] but resolves `{{key}}` patterns in
/// header values using the provided template context before setting them.
pub fn apply_header_modifiers_with_templates(
    modifiers: &HeaderModifiers,
    headers: &mut HeaderMap,
    tmpl: &TemplateContext,
) {
    // 1. Remove
    for key in &modifiers.remove {
        headers.remove(key.as_str());
    }

    // 2. Set (overwrite) - resolve templates in values.
    for (key, value) in &modifiers.set {
        let resolved = tmpl.resolve(value);
        if let (Ok(name), Ok(val)) = (key.parse::<HeaderName>(), HeaderValue::from_str(&resolved)) {
            headers.insert(name, val);
        }
    }

    // 3. Add (append) - resolve templates in values.
    for (key, value) in &modifiers.add {
        let resolved = tmpl.resolve(value);
        if let (Ok(name), Ok(val)) = (key.parse::<HeaderName>(), HeaderValue::from_str(&resolved)) {
            headers.append(name, val);
        }
    }
}

/// Apply a list of request modifiers to request headers.
pub fn apply_request_modifiers(modifiers: &[RequestModifierConfig], headers: &mut HeaderMap) {
    for modifier in modifiers {
        if let Some(hm) = &modifier.headers {
            apply_header_modifiers(hm, headers);
        }
    }
}

/// Apply a list of request modifiers with template variable interpolation.
pub fn apply_request_modifiers_with_templates(
    modifiers: &[RequestModifierConfig],
    headers: &mut HeaderMap,
    tmpl: &TemplateContext,
) {
    for modifier in modifiers {
        if let Some(hm) = &modifier.headers {
            apply_header_modifiers_with_templates(hm, headers, tmpl);
        }
    }
}

/// Apply a list of response modifiers to response headers.
pub fn apply_response_modifiers(modifiers: &[ResponseModifierConfig], headers: &mut HeaderMap) {
    for modifier in modifiers {
        if let Some(hm) = &modifier.headers {
            apply_header_modifiers(hm, headers);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn modifiers_with_set(pairs: Vec<(&str, &str)>) -> HeaderModifiers {
        HeaderModifiers {
            set: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            add: HashMap::new(),
            remove: vec![],
        }
    }

    fn modifiers_with_add(pairs: Vec<(&str, &str)>) -> HeaderModifiers {
        HeaderModifiers {
            set: HashMap::new(),
            add: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            remove: vec![],
        }
    }

    fn modifiers_with_remove(keys: Vec<&str>) -> HeaderModifiers {
        HeaderModifiers {
            set: HashMap::new(),
            add: HashMap::new(),
            remove: keys.into_iter().map(|k| k.into()).collect(),
        }
    }

    // --- Set Operations ---

    #[test]
    fn test_set_inserts_new_header() {
        let mods = modifiers_with_set(vec![("x-custom", "hello")]);
        let mut headers = HeaderMap::new();
        apply_header_modifiers(&mods, &mut headers);

        assert_eq!(headers.get("x-custom").unwrap(), "hello");
    }

    #[test]
    fn test_set_overwrites_existing_header() {
        let mods = modifiers_with_set(vec![("x-custom", "new-value")]);
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("old-value"));

        apply_header_modifiers(&mods, &mut headers);

        assert_eq!(headers.get("x-custom").unwrap(), "new-value");
    }

    // --- Add Operations ---

    #[test]
    fn test_add_appends_to_existing_header() {
        let mods = modifiers_with_add(vec![("x-custom", "second")]);
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("first"));

        apply_header_modifiers(&mods, &mut headers);

        let values: Vec<&HeaderValue> = headers.get_all("x-custom").iter().collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "first");
        assert_eq!(values[1], "second");
    }

    #[test]
    fn test_add_creates_header_if_missing() {
        let mods = modifiers_with_add(vec![("x-new", "value")]);
        let mut headers = HeaderMap::new();

        apply_header_modifiers(&mods, &mut headers);

        assert_eq!(headers.get("x-new").unwrap(), "value");
    }

    // --- Remove Operations ---

    #[test]
    fn test_remove_deletes_header() {
        let mods = modifiers_with_remove(vec!["x-remove-me"]);
        let mut headers = HeaderMap::new();
        headers.insert("x-remove-me", HeaderValue::from_static("gone"));
        headers.insert("x-keep", HeaderValue::from_static("stay"));

        apply_header_modifiers(&mods, &mut headers);

        assert!(headers.get("x-remove-me").is_none());
        assert_eq!(headers.get("x-keep").unwrap(), "stay");
    }

    #[test]
    fn test_remove_nonexistent_header_is_noop() {
        let mods = modifiers_with_remove(vec!["x-does-not-exist"]);
        let mut headers = HeaderMap::new();
        headers.insert("x-keep", HeaderValue::from_static("stay"));

        apply_header_modifiers(&mods, &mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("x-keep").unwrap(), "stay");
    }

    // --- Ordering: remove then set then add ---

    #[test]
    fn test_ordering_remove_before_set() {
        // Remove x-foo, then set x-foo. The set should win.
        let mods = HeaderModifiers {
            remove: vec!["x-foo".into()],
            set: [("x-foo".into(), "new".into())].into_iter().collect(),
            add: HashMap::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-foo", HeaderValue::from_static("old"));

        apply_header_modifiers(&mods, &mut headers);

        assert_eq!(headers.get("x-foo").unwrap(), "new");
    }

    #[test]
    fn test_ordering_set_then_add_same_key() {
        // Set x-foo to "base", then add "extra". Both should be present.
        let mods = HeaderModifiers {
            remove: vec![],
            set: [("x-foo".into(), "base".into())].into_iter().collect(),
            add: [("x-foo".into(), "extra".into())].into_iter().collect(),
        };
        let mut headers = HeaderMap::new();

        apply_header_modifiers(&mods, &mut headers);

        let values: Vec<&HeaderValue> = headers.get_all("x-foo").iter().collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "base");
        assert_eq!(values[1], "extra");
    }

    // --- Request / Response Modifier Wrappers ---

    #[test]
    fn test_apply_request_modifiers() {
        let modifiers = vec![
            RequestModifierConfig {
                headers: Some(modifiers_with_set(vec![("x-injected", "yes")])),
                url: None,
                query: None,
                method: None,
                body: None,
                lua_script: None,
                js_script: None,
            },
            RequestModifierConfig {
                headers: None,
                url: None,
                query: None,
                method: None,
                body: None,
                lua_script: None,
                js_script: None,
            },
            RequestModifierConfig {
                headers: Some(modifiers_with_set(vec![("x-second", "also")])),
                url: None,
                query: None,
                method: None,
                body: None,
                lua_script: None,
                js_script: None,
            },
        ];

        let mut headers = HeaderMap::new();
        apply_request_modifiers(&modifiers, &mut headers);

        assert_eq!(headers.get("x-injected").unwrap(), "yes");
        assert_eq!(headers.get("x-second").unwrap(), "also");
    }

    #[test]
    fn test_apply_response_modifiers() {
        let modifiers = vec![ResponseModifierConfig {
            headers: Some(modifiers_with_remove(vec!["server"])),
            status: None,
            body: None,
            lua_script: None,
            js_script: None,
        }];

        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));

        apply_response_modifiers(&modifiers, &mut headers);

        assert!(headers.get("server").is_none());
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn test_empty_modifiers_is_noop() {
        let mods = HeaderModifiers::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-keep", HeaderValue::from_static("stay"));

        apply_header_modifiers(&mods, &mut headers);

        assert_eq!(headers.len(), 1);
    }

    // --- Invalid header names/values are silently skipped ---

    #[test]
    fn test_invalid_header_value_skipped() {
        // Header values cannot contain certain control characters
        let mods = HeaderModifiers {
            set: [("x-bad".into(), "value\x00with\x01nulls".into())]
                .into_iter()
                .collect(),
            add: HashMap::new(),
            remove: vec![],
        };
        let mut headers = HeaderMap::new();
        apply_header_modifiers(&mods, &mut headers);

        // The invalid value should be skipped, not panic
        assert!(headers.get("x-bad").is_none());
    }

    // --- TemplateContext tests ---

    #[test]
    fn test_template_resolve_vars() {
        let mut tmpl = TemplateContext::new();
        tmpl.values
            .insert("vars.name".to_string(), "my-app".to_string());
        tmpl.values
            .insert("vars.version".to_string(), "1.0".to_string());

        assert_eq!(
            tmpl.resolve("App: {{vars.name}} v{{vars.version}}"),
            "App: my-app v1.0"
        );
    }

    #[test]
    fn test_template_resolve_request_metadata() {
        let mut tmpl = TemplateContext::new();
        tmpl.values
            .insert("request.method".to_string(), "POST".to_string());
        tmpl.values
            .insert("request.path".to_string(), "/api/v1".to_string());

        assert_eq!(
            tmpl.resolve("{{request.method}} {{request.path}}"),
            "POST /api/v1"
        );
    }

    #[test]
    fn test_template_resolve_env_vars() {
        std::env::set_var("SBPROXY_TEST_TMPL_VAR", "from-env");
        let mut tmpl = TemplateContext::new();
        tmpl.allowed_env_vars
            .push("SBPROXY_TEST_TMPL_VAR".to_string());
        assert_eq!(
            tmpl.resolve("Value: {{env.SBPROXY_TEST_TMPL_VAR}}"),
            "Value: from-env"
        );
        std::env::remove_var("SBPROXY_TEST_TMPL_VAR");
    }

    #[test]
    fn test_template_resolve_env_unset_but_allowlisted_left_as_is() {
        let mut tmpl = TemplateContext::new();
        tmpl.allowed_env_vars
            .push("SBPROXY_NONEXISTENT_VAR_XYZ".to_string());
        assert_eq!(
            tmpl.resolve("{{env.SBPROXY_NONEXISTENT_VAR_XYZ}}"),
            "{{env.SBPROXY_NONEXISTENT_VAR_XYZ}}"
        );
    }

    #[test]
    fn test_template_resolve_unresolved_left_as_is() {
        let tmpl = TemplateContext::new();
        assert_eq!(tmpl.resolve("{{vars.unknown}}"), "{{vars.unknown}}");
    }

    #[test]
    fn test_template_resolve_no_templates() {
        let tmpl = TemplateContext::new();
        assert_eq!(tmpl.resolve("plain text"), "plain text");
    }

    #[test]
    fn test_template_resolve_unclosed_braces() {
        let tmpl = TemplateContext::new();
        assert_eq!(tmpl.resolve("{{unclosed"), "{{unclosed");
    }

    #[test]
    fn test_template_with_modifiers() {
        std::env::set_var("SBPROXY_HDR_TEST", "env-value");
        let mut tmpl = TemplateContext::new();
        tmpl.values
            .insert("vars.app".to_string(), "test-app".to_string());
        tmpl.allowed_env_vars.push("SBPROXY_HDR_TEST".to_string());

        let mods = modifiers_with_set(vec![
            ("x-app", "{{vars.app}}"),
            ("x-env", "{{env.SBPROXY_HDR_TEST}}"),
        ]);
        let mut headers = HeaderMap::new();
        apply_header_modifiers_with_templates(&mods, &mut headers, &tmpl);

        assert_eq!(headers.get("x-app").unwrap(), "test-app");
        assert_eq!(headers.get("x-env").unwrap(), "env-value");
        std::env::remove_var("SBPROXY_HDR_TEST");
    }

    // --- H4 regression: env-var template injection (OPENSOURCE.md) ---

    #[test]
    fn test_template_env_blocked_by_default_allowlist_empty() {
        // Regression for OPENSOURCE.md H4. With the default empty
        // allowlist, even a real env var must NOT be resolved.
        std::env::set_var("SBPROXY_H4_TEST_PUBLIC", "leaked");
        let tmpl = TemplateContext::new();
        let out = tmpl.resolve("X={{env.SBPROXY_H4_TEST_PUBLIC}};");
        assert_eq!(out, "X=;");
        std::env::remove_var("SBPROXY_H4_TEST_PUBLIC");
    }

    #[test]
    fn test_template_env_aws_secret_not_resolved_unless_allowlisted() {
        // Canonical "would have been a CVE" case from OPENSOURCE.md
        // H4: a tenant injects {{env.AWS_SECRET_ACCESS_KEY}} into a
        // header and ships it to an upstream they control. With no
        // allowlist entry the template must expand to empty.
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AKIA-pretend-secret");
        let tmpl = TemplateContext::new();
        let out = tmpl.resolve("auth={{env.AWS_SECRET_ACCESS_KEY}}");
        assert_eq!(out, "auth=");
        // Confirm the allowlist is the only switch that lets it
        // through. (We do not actually allowlist AWS_SECRET_ACCESS_KEY
        // in production; this just exercises the gating logic.)
        let mut allowed = TemplateContext::new();
        allowed
            .allowed_env_vars
            .push("AWS_SECRET_ACCESS_KEY".to_string());
        let out = allowed.resolve("auth={{env.AWS_SECRET_ACCESS_KEY}}");
        assert_eq!(out, "auth=AKIA-pretend-secret");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    #[test]
    fn test_template_env_partial_allowlist() {
        // Only the explicitly-named var is resolvable.
        std::env::set_var("SBPROXY_H4_ALLOWED", "ok");
        std::env::set_var("SBPROXY_H4_DENIED", "secret");
        let mut tmpl = TemplateContext::new();
        tmpl.allowed_env_vars.push("SBPROXY_H4_ALLOWED".to_string());
        let out = tmpl.resolve("a={{env.SBPROXY_H4_ALLOWED}};b={{env.SBPROXY_H4_DENIED}}");
        assert_eq!(out, "a=ok;b=");
        std::env::remove_var("SBPROXY_H4_ALLOWED");
        std::env::remove_var("SBPROXY_H4_DENIED");
    }
}
