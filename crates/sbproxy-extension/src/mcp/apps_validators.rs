//! WOR-818 PR3: OpenAI Apps SDK / MCP Apps (SEP-1865) validators.
//!
//! The Apps extension layers a small UI contract on top of base MCP:
//! a tool can advertise a UI template (an HTML resource) under
//! `_meta.mcpApps.template.uri`, the client renders it in a sandboxed
//! iframe, and the rendered widget's button presses round-trip back
//! to the server with `params.audit.cause` so the audit chain can
//! see which UI element triggered which `tools/call`.
//!
//! Whatever sits in front of an Apps-SDK origin (sbproxy, an
//! enterprise extension, a CI gate built on top of `sbproxy-plugin`)
//! needs a small set of typed checks against the SEP-1865 rules:
//! template declared, iframe sandbox safe, CSP present, cache hints
//! present. This module ships those four checks as pure functions
//! over the typed [`super::types::Tool`] / [`super::types::Resource`]
//! shapes so any caller can run them. The mcptest enterprise
//! validation pack consumes the same shapes; this OSS module is the
//! single source of truth for the rule set.
//!
//! Five deliberate choices kept this PR small:
//!
//! 1. **Pure functions.** No trait, no registry, no fluent builder.
//!    Each rule is one `fn(input) -> Vec<Finding>` so callers compose
//!    by appending vectors. Trivially unit-testable.
//! 2. **Typed shapes, not raw JSON.** Validators read
//!    [`super::types::Tool`], [`super::types::Resource`], and an
//!    HTML body `&str`. JSON parsing happens once, upstream of the
//!    validators.
//! 3. **Findings, not bool.** Each check returns
//!    [`Vec<AppsFinding>`] so a caller building a scorecard sees
//!    every issue at once, not just the first.
//! 4. **No HTML AST.** The CSP + sandbox checks scan the raw template
//!    body with substring + regex-free byte logic. A real DOM parser
//!    is a future refinement; the substring checks already catch the
//!    failure mode that SEP-1865 §4 calls out as MUST.
//! 5. **No cross-resource resolution.** The "template declared"
//!    check verifies the URI string is present on the tool AND
//!    that an entry in the resource list shares the URI. Fetching
//!    the resource body and verifying it is reachable belongs to the
//!    caller; this layer is the shape check.

use super::types::{Resource, Tool};

/// One finding from an Apps-SDK validator. The `severity` is a
/// string rather than an enum so callers can grow new severities
/// (warning, info) without breaking the wire shape; the validators
/// in this module emit only `"error"` and `"warning"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppsFinding {
    /// Stable identifier for the rule, suitable for filtering or
    /// suppression. Matches the mcptest enterprise validation pack's
    /// identifiers so reports correlate.
    pub rule: &'static str,
    /// One-line operator-facing description of the violation.
    pub message: String,
    /// `"error"` for a SEP-1865 MUST, `"warning"` for a SHOULD.
    pub severity: &'static str,
}

impl AppsFinding {
    fn error(rule: &'static str, message: impl Into<String>) -> Self {
        Self {
            rule,
            message: message.into(),
            severity: "error",
        }
    }

    fn warning(rule: &'static str, message: impl Into<String>) -> Self {
        Self {
            rule,
            message: message.into(),
            severity: "warning",
        }
    }
}

/// Extract the UI template URI a tool advertises under
/// `_meta.mcpApps.template.uri`, when present. Returns `None` when
/// the tool is a base-MCP tool (no Apps UI). Wrapped as a small
/// helper because three validators read the same path.
pub fn tool_apps_template_uri(tool: &Tool) -> Option<&str> {
    tool.meta
        .as_ref()?
        .get("mcpApps")?
        .get("template")?
        .get("uri")?
        .as_str()
}

/// SEP-1865 §3: a tool advertising an Apps UI MUST point at a
/// declared resource. Emits an error when the tool carries a
/// `_meta.mcpApps.template.uri` but no entry in `resources` has a
/// matching `uri`. Returns an empty vec for tools that do not
/// advertise an Apps UI; those are legal base-MCP tools.
pub fn validate_template_declared(tool: &Tool, resources: &[Resource]) -> Vec<AppsFinding> {
    let Some(uri) = tool_apps_template_uri(tool) else {
        return Vec::new();
    };
    if resources.iter().any(|r| r.uri == uri) {
        return Vec::new();
    }
    vec![AppsFinding::error(
        "apps.template_declared",
        format!(
            "tool {:?} advertises Apps template {uri:?} but no resource with that URI is declared",
            tool.name
        ),
    )]
}

/// SEP-1865 §4: when the rendered template HTML carries an
/// `<iframe>`, the iframe MUST have a `sandbox` attribute, AND
/// MUST NOT combine `allow-same-origin` with `allow-scripts`
/// (which defeats the sandbox). Scans the raw HTML body string;
/// any `<iframe` substring triggers the check.
///
/// A template that does not embed an iframe at all is fine; the
/// rule applies only when one is present.
pub fn validate_iframe_sandbox(template_body: &str) -> Vec<AppsFinding> {
    if !template_body.to_ascii_lowercase().contains("<iframe") {
        return Vec::new();
    }
    let lower = template_body.to_ascii_lowercase();
    let mut out: Vec<AppsFinding> = Vec::new();
    if !lower.contains("sandbox") {
        out.push(AppsFinding::error(
            "apps.iframe_sandbox",
            "<iframe> tag present without a `sandbox` attribute",
        ));
        return out;
    }
    if lower.contains("allow-same-origin") && lower.contains("allow-scripts") {
        out.push(AppsFinding::error(
            "apps.iframe_sandbox",
            "iframe sandbox combines `allow-same-origin` with `allow-scripts`, which defeats isolation",
        ));
    }
    out
}

/// SEP-1865 §4: HTML templates SHOULD declare a
/// Content-Security-Policy meta tag restricting at minimum
/// `script-src` and `object-src` so a compromised template cannot
/// pull arbitrary script. SHOULD-level, so this emits a warning,
/// not an error.
pub fn validate_csp_present(template_body: &str) -> Vec<AppsFinding> {
    let lower = template_body.to_ascii_lowercase();
    let has_csp_meta = lower.contains("http-equiv=\"content-security-policy\"")
        || lower.contains("http-equiv='content-security-policy'");
    if !has_csp_meta {
        return vec![AppsFinding::warning(
            "apps.csp_present",
            "template HTML does not declare a Content-Security-Policy meta tag",
        )];
    }
    if !lower.contains("script-src") {
        return vec![AppsFinding::warning(
            "apps.csp_present",
            "Content-Security-Policy meta tag does not constrain `script-src`",
        )];
    }
    Vec::new()
}

/// SEP-1865 §5: a UI template resource SHOULD carry cache metadata
/// (an `etag`, a `cacheControl`, or a `maxAge`) under `_meta` so
/// the client can avoid re-downloading the template on every tool
/// call. SHOULD-level: emits a warning when absent.
///
/// Reads the resource's `_meta` block (when present) and looks for
/// any of the three keys. Absence of `_meta` is the same as absence
/// of all three.
pub fn validate_cache_metadata(
    resource: &Resource,
    meta: Option<&serde_json::Value>,
) -> Vec<AppsFinding> {
    let Some(m) = meta else {
        return vec![AppsFinding::warning(
            "apps.cache_metadata",
            format!(
                "resource {:?} has no `_meta` block, so the client cannot cache the template",
                resource.uri
            ),
        )];
    };
    let has_hint =
        m.get("etag").is_some() || m.get("cacheControl").is_some() || m.get("maxAge").is_some();
    if has_hint {
        return Vec::new();
    }
    vec![AppsFinding::warning(
        "apps.cache_metadata",
        format!(
            "resource {:?} `_meta` block has no `etag`, `cacheControl`, or `maxAge`",
            resource.uri
        ),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool_with_meta(name: &str, meta: serde_json::Value) -> Tool {
        Tool {
            name: name.to_string(),
            description: None,
            input_schema: json!({}),
            annotations: None,
            meta: Some(meta),
        }
    }

    fn base_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: None,
            input_schema: json!({}),
            annotations: None,
            meta: None,
        }
    }

    fn resource(uri: &str) -> Resource {
        Resource {
            uri: uri.to_string(),
            name: uri.to_string(),
            description: None,
            mime_type: Some("text/html".to_string()),
        }
    }

    // -- tool_apps_template_uri ----------------------------------

    #[test]
    fn template_uri_helper_returns_none_for_base_mcp_tool() {
        assert!(tool_apps_template_uri(&base_tool("echo")).is_none());
    }

    #[test]
    fn template_uri_helper_extracts_nested_string() {
        let tool = tool_with_meta(
            "ui-tool",
            json!({"mcpApps": {"template": {"uri": "mcp://app/widget.html"}}}),
        );
        assert_eq!(tool_apps_template_uri(&tool), Some("mcp://app/widget.html"));
    }

    #[test]
    fn template_uri_helper_returns_none_when_value_is_wrong_type() {
        let tool = tool_with_meta("ui-tool", json!({"mcpApps": {"template": {"uri": 42}}}));
        assert!(tool_apps_template_uri(&tool).is_none());
    }

    // -- validate_template_declared ------------------------------

    #[test]
    fn template_declared_passes_for_base_mcp_tool() {
        assert!(validate_template_declared(&base_tool("echo"), &[]).is_empty());
    }

    #[test]
    fn template_declared_passes_when_resource_present() {
        let tool = tool_with_meta(
            "ui-tool",
            json!({"mcpApps": {"template": {"uri": "mcp://app/widget.html"}}}),
        );
        let resources = vec![resource("mcp://app/widget.html")];
        assert!(validate_template_declared(&tool, &resources).is_empty());
    }

    #[test]
    fn template_declared_errors_when_resource_missing() {
        let tool = tool_with_meta(
            "ui-tool",
            json!({"mcpApps": {"template": {"uri": "mcp://app/widget.html"}}}),
        );
        let findings = validate_template_declared(&tool, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "apps.template_declared");
        assert_eq!(findings[0].severity, "error");
        assert!(findings[0].message.contains("mcp://app/widget.html"));
    }

    // -- validate_iframe_sandbox --------------------------------

    #[test]
    fn iframe_sandbox_passes_when_no_iframe_present() {
        let html = r#"<html><body><h1>hello</h1></body></html>"#;
        assert!(validate_iframe_sandbox(html).is_empty());
    }

    #[test]
    fn iframe_sandbox_passes_when_iframe_carries_sandbox_attr() {
        let html = r#"<iframe src="x" sandbox="allow-scripts"></iframe>"#;
        assert!(validate_iframe_sandbox(html).is_empty());
    }

    #[test]
    fn iframe_sandbox_errors_when_attribute_absent() {
        let html = r#"<iframe src="x"></iframe>"#;
        let findings = validate_iframe_sandbox(html);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "apps.iframe_sandbox");
        assert_eq!(findings[0].severity, "error");
        assert!(findings[0].message.contains("sandbox"));
    }

    #[test]
    fn iframe_sandbox_errors_on_dangerous_same_origin_plus_scripts() {
        let html = r#"<iframe src="x" sandbox="allow-scripts allow-same-origin"></iframe>"#;
        let findings = validate_iframe_sandbox(html);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("allow-same-origin"));
        assert!(findings[0].message.contains("allow-scripts"));
    }

    #[test]
    fn iframe_sandbox_is_case_insensitive() {
        let html = r#"<IFRAME SRC="x"></IFRAME>"#;
        let findings = validate_iframe_sandbox(html);
        assert_eq!(findings.len(), 1);
    }

    // -- validate_csp_present ----------------------------------

    #[test]
    fn csp_present_warns_when_meta_tag_absent() {
        let html = r#"<html><body><h1>hi</h1></body></html>"#;
        let findings = validate_csp_present(html);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "warning");
        assert!(findings[0].message.contains("Content-Security-Policy"));
    }

    #[test]
    fn csp_present_warns_when_script_src_missing() {
        let html = r#"<meta http-equiv="Content-Security-Policy" content="default-src 'self'">"#;
        let findings = validate_csp_present(html);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("script-src"));
    }

    #[test]
    fn csp_present_passes_when_script_src_declared() {
        let html = r#"<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">"#;
        assert!(validate_csp_present(html).is_empty());
    }

    #[test]
    fn csp_present_accepts_single_quoted_meta_tag() {
        let html = r#"<meta http-equiv='Content-Security-Policy' content="script-src 'self'">"#;
        assert!(validate_csp_present(html).is_empty());
    }

    // -- validate_cache_metadata --------------------------------

    #[test]
    fn cache_metadata_warns_when_meta_absent() {
        let r = resource("mcp://app/widget.html");
        let findings = validate_cache_metadata(&r, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "warning");
        assert!(findings[0].message.contains("no `_meta`"));
    }

    #[test]
    fn cache_metadata_warns_when_all_hint_keys_absent() {
        let r = resource("mcp://app/widget.html");
        let meta = json!({ "unrelated": "field" });
        let findings = validate_cache_metadata(&r, Some(&meta));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("etag"));
    }

    #[test]
    fn cache_metadata_passes_with_etag() {
        let r = resource("mcp://app/widget.html");
        let meta = json!({"etag": "v42"});
        assert!(validate_cache_metadata(&r, Some(&meta)).is_empty());
    }

    #[test]
    fn cache_metadata_passes_with_cache_control() {
        let r = resource("mcp://app/widget.html");
        let meta = json!({"cacheControl": "max-age=3600"});
        assert!(validate_cache_metadata(&r, Some(&meta)).is_empty());
    }

    #[test]
    fn cache_metadata_passes_with_max_age() {
        let r = resource("mcp://app/widget.html");
        let meta = json!({"maxAge": 3600});
        assert!(validate_cache_metadata(&r, Some(&meta)).is_empty());
    }
}
