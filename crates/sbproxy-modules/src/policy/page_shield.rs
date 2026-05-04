//! Page Shield: client-side script monitoring via CSP report intake.
//!
//! The policy stamps a Content Security Policy header on every response
//! and points the `report-uri` / `report-to` directive at a proxy-local
//! intake endpoint (`/__sbproxy/csp-report` by default). Browser-emitted
//! violation reports land back at the gateway, which fans them out as
//! `policy_denied` events on the OSS event bus. Enterprise builds layer
//! a connection-monitor analyser on top of the same intake surface
//! (F3.20) without changing the data plane.

use serde::Deserialize;

/// Whether the configured policy is enforced or only reported.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PageShieldMode {
    /// `Content-Security-Policy-Report-Only`. Browsers report violations
    /// but do not block the offending resources. The recommended starting
    /// point: deploy in report-only, watch the events, then flip to
    /// enforce once the policy reflects reality.
    #[default]
    ReportOnly,
    /// `Content-Security-Policy`. Browsers block violations and report.
    Enforce,
}

impl PageShieldMode {
    fn header_name(self) -> &'static str {
        match self {
            Self::ReportOnly => "content-security-policy-report-only",
            Self::Enforce => "content-security-policy",
        }
    }
}

/// Default intake path for browser-emitted CSP reports.
pub const DEFAULT_REPORT_PATH: &str = "/__sbproxy/csp-report";

/// Page Shield policy.
///
/// Configuration mirrors what an operator writes in CSP today: a list
/// of directives (`default-src 'self'`, `script-src 'self' cdn.example`)
/// joined into a single header. The proxy automatically appends a
/// `report-uri` (and a matching `report-to` when an endpoint group is
/// supplied) so reports land at the intake.
#[derive(Debug, Deserialize)]
pub struct PageShieldPolicy {
    /// `report-only` (default) emits `Content-Security-Policy-Report-Only`.
    /// `enforce` emits `Content-Security-Policy`.
    #[serde(default)]
    pub mode: PageShieldMode,
    /// CSP directives to merge. Each string is a complete directive
    /// (`default-src 'self'`); the policy joins them with `; `.
    #[serde(default)]
    pub directives: Vec<String>,
    /// Override the intake path. Defaults to `/__sbproxy/csp-report`.
    #[serde(default)]
    pub report_path: Option<String>,
    /// Optional `Reporting-Endpoints` group name. When set the policy
    /// also emits a `report-to <name>` directive so newer browsers use
    /// the modern Reporting API.
    #[serde(default)]
    pub report_to_group: Option<String>,
    /// When true and an upstream response already carries a CSP header,
    /// the upstream value wins (the policy does nothing). Default
    /// `false`: the policy always writes its header. Use this for
    /// origins where the application emits a tighter CSP it manages
    /// itself but still wants the gateway intake as a fallback.
    #[serde(default)]
    pub respect_upstream: bool,
}

impl PageShieldPolicy {
    /// Build the policy from a JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let policy: Self = serde_json::from_value(value)?;
        if policy.directives.is_empty() {
            anyhow::bail!(
                "page_shield requires at least one directive (e.g. \"default-src 'self'\")"
            );
        }
        Ok(policy)
    }

    /// Path the intake endpoint listens on.
    pub fn report_path(&self) -> &str {
        self.report_path.as_deref().unwrap_or(DEFAULT_REPORT_PATH)
    }

    /// Returns `(header_name, header_value)` to set on the response.
    /// `request_origin` is the value of the request `Host` header so
    /// the report URI can be rendered as a same-origin path.
    pub fn header(&self, _request_origin: &str) -> (&'static str, String) {
        let mut directives = self.directives.clone();
        directives.push(format!("report-uri {}", self.report_path()));
        if let Some(group) = &self.report_to_group {
            directives.push(format!("report-to {}", group));
        }
        let value = directives.join("; ");
        (self.mode.header_name(), value)
    }

    /// True when the policy should bow out because the upstream already
    /// produced a CSP header.
    pub fn yields_to_upstream(&self, upstream_has_csp: bool) -> bool {
        self.respect_upstream && upstream_has_csp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_report_only() {
        let p = PageShieldPolicy::from_config(serde_json::json!({
            "directives": ["default-src 'self'"],
        }))
        .unwrap();
        assert_eq!(p.mode, PageShieldMode::ReportOnly);
        let (name, _) = p.header("example.com");
        assert_eq!(name, "content-security-policy-report-only");
    }

    #[test]
    fn enforce_mode_uses_csp_header() {
        let p = PageShieldPolicy::from_config(serde_json::json!({
            "mode": "enforce",
            "directives": ["default-src 'self'"],
        }))
        .unwrap();
        let (name, _) = p.header("example.com");
        assert_eq!(name, "content-security-policy");
    }

    #[test]
    fn header_appends_report_uri() {
        let p = PageShieldPolicy::from_config(serde_json::json!({
            "directives": ["default-src 'self'", "script-src 'self' cdn.example"],
        }))
        .unwrap();
        let (_, value) = p.header("example.com");
        assert!(value.starts_with("default-src 'self'"));
        assert!(value.contains("script-src 'self' cdn.example"));
        assert!(value.contains("report-uri /__sbproxy/csp-report"));
    }

    #[test]
    fn report_to_directive_emitted_when_group_set() {
        let p = PageShieldPolicy::from_config(serde_json::json!({
            "directives": ["default-src 'self'"],
            "report_to_group": "csp-endpoint",
        }))
        .unwrap();
        let (_, value) = p.header("example.com");
        assert!(value.contains("report-to csp-endpoint"));
    }

    #[test]
    fn custom_report_path_used_in_uri() {
        let p = PageShieldPolicy::from_config(serde_json::json!({
            "directives": ["default-src 'self'"],
            "report_path": "/__shield/csp",
        }))
        .unwrap();
        let (_, value) = p.header("example.com");
        assert!(value.contains("report-uri /__shield/csp"));
    }

    #[test]
    fn empty_directives_rejected() {
        let err = PageShieldPolicy::from_config(serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("at least one directive"));
    }

    #[test]
    fn yields_to_upstream_only_when_flag_set_and_present() {
        let p = PageShieldPolicy::from_config(serde_json::json!({
            "directives": ["default-src 'self'"],
            "respect_upstream": true,
        }))
        .unwrap();
        assert!(p.yields_to_upstream(true));
        assert!(!p.yields_to_upstream(false));
        let p2 = PageShieldPolicy::from_config(serde_json::json!({
            "directives": ["default-src 'self'"],
        }))
        .unwrap();
        assert!(!p2.yields_to_upstream(true));
    }
}
