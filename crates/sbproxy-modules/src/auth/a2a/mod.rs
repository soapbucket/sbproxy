//! A2A protocol envelope (Wave 7 / A7.2).
//!
//! See `docs/adr-a2a-protocol-envelope.md`. The module exposes the
//! shared `A2AContext` populated by the request filter and the
//! detection function that runs before either spec parser. Parsers
//! live behind feature flags so the default OSS build compiles
//! detection only and treats matched requests as plain POSTs.

#[cfg(feature = "a2a-anthropic")]
pub mod anthropic;
#[cfg(feature = "a2a-google")]
pub mod google;

use serde::{Deserialize, Serialize};

/// Closed enum of the A2A specs the proxy understands.
///
/// New variants extend the wire envelope per A1.8 (closed-enum
/// amendment rules). Today both variants carry the `v0` designation
/// because the upstream drafts are unstable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum A2ASpec {
    /// Anthropic A2A draft (`draft-anthropic-a2a-v0`). Modeled as an
    /// MCP method (`agents.invoke`).
    AnthropicV0,
    /// Google A2A draft (`draft-google-a2a-v0`). Dedicated content
    /// type `application/a2a+json`.
    GoogleV0,
}

impl A2ASpec {
    /// Stable label used in metrics and audit events.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::AnthropicV0 => "anthropic-v0",
            Self::GoogleV0 => "google-v0",
        }
    }
}

/// One hop in the A2A call chain. The chain is ordered oldest first
/// so `chain[0]` is the chain root and `chain[chain_depth - 1]` is
/// the immediate caller of this hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHop {
    /// Resolved agent identifier of the hop. The string form mirrors
    /// the catalog `id` values produced by the G1.4 resolver.
    pub agent_id: String,
    /// Per-hop request id (the request id of the hop, not the parent).
    pub request_id: String,
    /// Wall-clock timestamp the hop was observed, in milliseconds since
    /// the unix epoch. Zero when the wire envelope omits it; downstream
    /// pipelines treat zero as `unknown`.
    pub timestamp_ms: u64,
}

/// Per-request A2A envelope, populated once in the request filter.
///
/// Fields use zero / empty defaults when the wire envelope omits them
/// so the policy module can run on partial data; the request filter
/// records an audit event when fields are missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AContext {
    /// Which spec this envelope was decoded under.
    pub spec: A2ASpec,
    /// Resolved agent id of the caller (the agent that initiated the
    /// hop). String form mirrors the G1.4 resolver output.
    pub caller_agent_id: String,
    /// Resolved agent id of the callee, when the parser could
    /// determine it from the envelope. None when the callee is
    /// implied by routing alone.
    pub callee_agent_id: Option<String>,
    /// Opaque caller-assigned task identifier. Joins the audit
    /// pipeline; never used as a metric label.
    pub task_id: String,
    /// Request id of the parent hop (the hop that called this one).
    /// None for the chain root.
    pub parent_request_id: Option<String>,
    /// 1 for the first hop, +1 per nested call. Capped at 32 by the
    /// policy module.
    pub chain_depth: u32,
    /// Full ancestor chain, oldest first. Empty for the chain root.
    pub chain: Vec<ChainHop>,
    /// Free-form spec-version string (e.g. `"anthropic-v0"`,
    /// `"google-v0"`). Surfaced to the audit event verbatim so
    /// reconstructions across spec rev bumps stay debuggable.
    pub raw_envelope_version: String,
}

impl A2AContext {
    /// Build an empty (zero-default) context for the given spec.
    /// Useful when detection succeeded but parsing produced no fields,
    /// so the policy module can still apply route-level limits.
    pub fn empty(spec: A2ASpec) -> Self {
        Self {
            spec,
            caller_agent_id: String::new(),
            callee_agent_id: None,
            task_id: String::new(),
            parent_request_id: None,
            chain_depth: 1,
            chain: Vec::new(),
            raw_envelope_version: spec.as_label().to_string(),
        }
    }
}

/// Detection signal: which spec a request appears to be A2A under.
/// `None` means "not an A2A request, fall through to the regular
/// HTTP path".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedSpec {
    /// Anthropic A2A path (MCP method).
    Anthropic,
    /// Google A2A path (dedicated content type).
    Google,
    /// Operator escape hatch (`a2a.route_glob`); the spec is
    /// indeterminate but the request is still A2A traffic.
    OperatorRoute,
}

impl DetectedSpec {
    /// Map the detection signal back to a spec for context construction.
    /// `OperatorRoute` defaults to `GoogleV0` because the operator
    /// escape hatch is most commonly used for Google-shaped envelopes.
    pub fn to_spec(self) -> A2ASpec {
        match self {
            Self::Anthropic => A2ASpec::AnthropicV0,
            Self::Google | Self::OperatorRoute => A2ASpec::GoogleV0,
        }
    }
}

/// Detect whether a request looks like A2A traffic.
///
/// Runs once per request, before any policy evaluation. Returns the
/// matched detection signal, or `None` for plain HTTP requests. The
/// function does not parse the body; parsing is deferred to the
/// feature-gated parsers.
///
/// Detection cases (per ADR § "Detection"):
///
/// 1. `Content-Type: application/a2a+json` (with optional `; version=*`)
///    triggers Google detection.
/// 2. `MCP-Method: agents.invoke` triggers Anthropic detection.
/// 3. The path matching `route_glob` is the operator escape hatch.
pub fn detect(
    headers: &http::HeaderMap,
    path: &str,
    route_glob: Option<&str>,
) -> Option<DetectedSpec> {
    if let Some(ct) = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        let lower = ct.to_ascii_lowercase();
        // Match on the bare type or `application/a2a+json; version=*`.
        let bare = lower.split(';').next().unwrap_or("").trim();
        if bare == "application/a2a+json" {
            return Some(DetectedSpec::Google);
        }
    }

    if let Some(method) = headers.get("mcp-method").and_then(|v| v.to_str().ok()) {
        if method.trim().eq_ignore_ascii_case("agents.invoke") {
            return Some(DetectedSpec::Anthropic);
        }
    }

    if let Some(glob) = route_glob {
        if glob_matches(glob, path) {
            return Some(DetectedSpec::OperatorRoute);
        }
    }

    None
}

/// Tiny glob matcher supporting `*` (single segment) and `**` (any
/// suffix). Used for the operator route escape hatch and the policy
/// allowlist matcher; standalone so the policy module does not pull
/// a regex dep just for path matching.
pub(crate) fn glob_matches(glob: &str, path: &str) -> bool {
    if glob == "**" || glob == "*" {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = glob.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    glob == path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn detect_returns_none_for_plain_request() {
        let h = headers(&[("content-type", "application/json")]);
        assert_eq!(detect(&h, "/api/x", None), None);
    }

    #[test]
    fn detect_google_via_content_type() {
        let h = headers(&[("content-type", "application/a2a+json")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Google));
    }

    #[test]
    fn detect_google_via_content_type_with_version_param() {
        let h = headers(&[("content-type", "application/a2a+json; version=1")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Google));
    }

    #[test]
    fn detect_google_is_case_insensitive() {
        let h = headers(&[("content-type", "Application/A2A+JSON")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Google));
    }

    #[test]
    fn detect_anthropic_via_mcp_method() {
        let h = headers(&[("mcp-method", "agents.invoke")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Anthropic));
    }

    #[test]
    fn detect_anthropic_other_methods_ignored() {
        let h = headers(&[("mcp-method", "tools.list")]);
        assert_eq!(detect(&h, "/", None), None);
    }

    #[test]
    fn detect_operator_route_glob_matches_prefix() {
        let h = headers(&[]);
        assert_eq!(
            detect(&h, "/agents/invoke", Some("/agents/**")),
            Some(DetectedSpec::OperatorRoute)
        );
    }

    #[test]
    fn detect_content_type_takes_precedence_over_glob() {
        let h = headers(&[("content-type", "application/a2a+json")]);
        assert_eq!(
            detect(&h, "/agents/x", Some("/agents/**")),
            Some(DetectedSpec::Google)
        );
    }

    #[test]
    fn glob_matches_supports_double_star() {
        assert!(glob_matches("/api/**", "/api/v1/x"));
        assert!(glob_matches("/api/**", "/api"));
        assert!(!glob_matches("/api/**", "/other"));
    }

    #[test]
    fn glob_matches_supports_prefix_star() {
        assert!(glob_matches("/foo*", "/foobar"));
        assert!(!glob_matches("/foo*", "/bar"));
    }

    #[test]
    fn glob_matches_exact() {
        assert!(glob_matches("/exact", "/exact"));
        assert!(!glob_matches("/exact", "/exact/x"));
    }

    #[test]
    fn empty_context_uses_sensible_defaults() {
        let ctx = A2AContext::empty(A2ASpec::GoogleV0);
        assert_eq!(ctx.chain_depth, 1);
        assert!(ctx.chain.is_empty());
        assert_eq!(ctx.raw_envelope_version, "google-v0");
    }

    #[test]
    fn spec_label_round_trips() {
        assert_eq!(A2ASpec::AnthropicV0.as_label(), "anthropic-v0");
        assert_eq!(A2ASpec::GoogleV0.as_label(), "google-v0");
    }

    #[test]
    fn detected_spec_maps_to_spec() {
        assert_eq!(DetectedSpec::Anthropic.to_spec(), A2ASpec::AnthropicV0);
        assert_eq!(DetectedSpec::Google.to_spec(), A2ASpec::GoogleV0);
        assert_eq!(DetectedSpec::OperatorRoute.to_spec(), A2ASpec::GoogleV0);
    }
}
