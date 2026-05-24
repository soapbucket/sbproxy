//! A2A agent-card URL rewriter.
//!
//! Rewrites the `url`, `endpoint`, and nested `agent.url` fields on
//! JSON responses served at well-known A2A discovery paths
//! (`/.well-known/agent.json` and `/agent-card.json` by default) so
//! MCP and A2A clients route their subsequent calls through the proxy
//! instead of jumping straight at the upstream.
//!
//! ## Why this exists
//!
//! The A2A discovery flow goes:
//!
//! 1. Client fetches `https://proxy.example.com/.well-known/agent.json`.
//! 2. Proxy forwards to the upstream agent, which returns a body whose
//!    `url` (and friends) point at the upstream's own public hostname.
//! 3. Without rewriting, the client takes that upstream `url` at face
//!    value and bypasses the proxy on every subsequent call. Rate
//!    limits, auth, audit, billing, every other policy the proxy was
//!    placed in front of - all skipped.
//!
//! The rewriter sits in the response-body pipeline, parses the JSON,
//! and substitutes the upstream hostname with the proxy's external
//! hostname. The path and query of each rewritten URL are preserved
//! so deeply-linked A2A endpoints continue to resolve.
//!
//! ## Configuration
//!
//! ```yaml
//! transforms:
//!   - type: a2a_agent_card_rewrite
//!     # Optional. Defaults to the two well-known A2A discovery
//!     # paths. When set, only responses to one of these request
//!     # paths are rewritten.
//!     paths:
//!       - /.well-known/agent.json
//!       - /agent-card.json
//!     # Optional. When unset, the rewriter uses the inbound `Host`
//!     # header so a single deployment behind multiple hostnames
//!     # routes cleanly.
//!     proxy_host: proxy.example.com
//! ```
//!
//! ## Standard pipeline integration
//!
//! The standard transform `apply(body, content_type)` signature does
//! not carry the request path. To avoid silently rewriting JSON
//! responses on unrelated routes, the standard `apply` is a no-op:
//! it only writes through the body when [`A2aAgentCardRewriter::apply_with_path`]
//! is invoked with the live request path. Path-aware wiring lives in
//! the typed-dispatch arm in `sbproxy-core::server::apply_transform_with_ctx`;
//! see the WOR-234 follow-up for the connector.
//!
//! Until that wiring lands, the unit tests below pin the
//! path-and-host substitution logic against fixture JSON bodies.

use bytes::BytesMut;
use serde::Deserialize;
use tracing::debug;

/// Canonical A2A agent-card discovery paths. Used as the default
/// `paths` list when the operator does not override it.
pub const DEFAULT_AGENT_CARD_PATHS: &[&str] = &["/.well-known/agent.json", "/agent-card.json"];

/// YAML configuration shape for the A2A agent-card rewriter.
///
/// Both fields are optional. An empty `paths` list collapses to the
/// canonical defaults so an empty `type: a2a_agent_card_rewrite`
/// block does the right thing for a vanilla A2A deployment.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct A2aAgentCardRewriteConfig {
    /// Request paths the rewriter triggers on. Defaults to
    /// [`DEFAULT_AGENT_CARD_PATHS`].
    #[serde(default)]
    pub paths: Vec<String>,
    /// External hostname (or host:port) to substitute into the
    /// rewritten URLs. When `None`, the call site is expected to
    /// fall back to the inbound `Host` header. Tests can supply this
    /// directly.
    #[serde(default)]
    pub proxy_host: Option<String>,
}

/// Compiled A2A agent-card response rewriter.
#[derive(Debug, Clone)]
pub struct A2aAgentCardRewriter {
    /// Effective list of request paths that trigger the rewrite.
    /// Defaults are applied at construction time.
    pub paths: Vec<String>,
    /// Optional configured proxy host. When unset, callers fall back
    /// to the inbound `Host` header.
    pub proxy_host: Option<String>,
}

impl A2aAgentCardRewriter {
    /// Build a rewriter from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: A2aAgentCardRewriteConfig = serde_json::from_value(value)?;
        Ok(Self::from_parts(cfg.paths, cfg.proxy_host))
    }

    /// Build a rewriter from already-deserialized parts.
    ///
    /// Empty `paths` collapses to [`DEFAULT_AGENT_CARD_PATHS`] so the
    /// vanilla A2A wiring lights up without operator config.
    pub fn from_parts(paths: Vec<String>, proxy_host: Option<String>) -> Self {
        let paths = if paths.is_empty() {
            DEFAULT_AGENT_CARD_PATHS
                .iter()
                .map(|p| (*p).to_string())
                .collect()
        } else {
            paths
        };
        Self { paths, proxy_host }
    }

    /// Standard pipeline `apply`. This is a no-op because the request
    /// path is not threaded through the standard signature; see the
    /// module doc for the wiring story. The body is left untouched so
    /// the rewriter can sit in a pipeline without surprising the
    /// other transforms.
    pub fn apply(&self, _body: &mut BytesMut) -> anyhow::Result<()> {
        Ok(())
    }

    /// Path-aware apply.
    ///
    /// - Returns `Ok(())` and leaves the body untouched when the
    ///   request path is not in the configured list.
    /// - Returns `Ok(())` and leaves the body untouched when the
    ///   content type is not JSON.
    /// - Returns `Ok(())` and leaves the body untouched when the body
    ///   is malformed JSON; the rewriter only logs a debug line. The
    ///   caller is the upstream's contract holder, so a malformed
    ///   body is an upstream bug, not a proxy crash.
    /// - When the body is a JSON object, rewrites the `url`,
    ///   `endpoint`, and nested `agent.url` fields whose hostnames
    ///   differ from `host` to use `host`. Path, query, and scheme
    ///   are preserved.
    ///
    /// `host` is the effective proxy host - usually the configured
    /// `proxy_host` field, otherwise the inbound `Host` header. The
    /// caller resolves the precedence so the rewriter stays focused
    /// on the JSON edits.
    pub fn apply_with_path(
        &self,
        body: &mut BytesMut,
        content_type: Option<&str>,
        request_path: &str,
        host: &str,
    ) -> anyhow::Result<()> {
        if !self.path_matches(request_path) {
            return Ok(());
        }
        if !is_json_content_type(content_type) {
            return Ok(());
        }
        if host.is_empty() {
            debug!("a2a_agent_card_rewrite: empty proxy host, leaving body unchanged");
            return Ok(());
        }
        let mut json: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "a2a_agent_card_rewrite: body is not valid JSON, leaving unchanged");
                return Ok(());
            }
        };
        let mut rewrote = false;
        if let Some(obj) = json.as_object_mut() {
            for field in ["url", "endpoint"] {
                if rewrite_string_field(obj, field, host) {
                    rewrote = true;
                }
            }
            if let Some(agent) = obj.get_mut("agent").and_then(|v| v.as_object_mut()) {
                if rewrite_string_field(agent, "url", host) {
                    rewrote = true;
                }
            }
        }
        if !rewrote {
            return Ok(());
        }
        let serialized = serde_json::to_vec(&json)?;
        body.clear();
        body.extend_from_slice(&serialized);
        Ok(())
    }

    /// Returns `true` when the supplied request path matches one of
    /// the configured trigger paths exactly.
    fn path_matches(&self, request_path: &str) -> bool {
        self.paths.iter().any(|p| p == request_path)
    }
}

/// Rewrite a string-valued field on a JSON object to swap its host
/// for `target_host`. Returns `true` when the field was rewritten;
/// `false` when the field is absent, non-string, malformed, or
/// already pointing at `target_host`.
fn rewrite_string_field(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    target_host: &str,
) -> bool {
    let Some(value) = obj.get(field).and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(rewritten) = swap_host(value, target_host) else {
        return false;
    };
    if rewritten == value {
        return false;
    }
    obj.insert(field.to_string(), serde_json::Value::String(rewritten));
    true
}

/// Replace the host component of `original` with `target_host`,
/// preserving scheme, path, and query.
///
/// Returns `None` for inputs that do not parse as absolute URLs with
/// a host - relative references like `/agents/1` are left alone since
/// the client will still resolve them against the proxy origin.
fn swap_host(original: &str, target_host: &str) -> Option<String> {
    let parsed = url::Url::parse(original).ok()?;
    parsed.host_str()?;
    let scheme = parsed.scheme();
    let path = parsed.path();
    let query = parsed.query();
    let fragment = parsed.fragment();
    let mut out = String::with_capacity(original.len() + target_host.len());
    out.push_str(scheme);
    out.push_str("://");
    out.push_str(target_host);
    out.push_str(path);
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    Some(out)
}

/// Returns `true` when `content_type` looks like JSON. Matches the
/// standard `application/json` plus the `+json` family
/// (`application/agent+json`, `application/ld+json`, etc.).
fn is_json_content_type(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    let main = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if main == "application/json" {
        return true;
    }
    main.starts_with("application/") && main.ends_with("+json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewriter() -> A2aAgentCardRewriter {
        A2aAgentCardRewriter::from_parts(Vec::new(), Some("proxy.test".to_string()))
    }

    #[test]
    fn from_parts_applies_default_paths_when_empty() {
        let r = A2aAgentCardRewriter::from_parts(Vec::new(), None);
        assert_eq!(r.paths.len(), DEFAULT_AGENT_CARD_PATHS.len());
        assert!(r.paths.contains(&"/.well-known/agent.json".to_string()));
        assert!(r.paths.contains(&"/agent-card.json".to_string()));
    }

    #[test]
    fn from_parts_respects_custom_paths() {
        let r = A2aAgentCardRewriter::from_parts(vec!["/custom/card.json".to_string()], None);
        assert_eq!(r.paths, vec!["/custom/card.json".to_string()]);
    }

    #[test]
    fn from_config_round_trip() {
        let r = A2aAgentCardRewriter::from_config(serde_json::json!({
            "paths": ["/.well-known/agent.json"],
            "proxy_host": "proxy.example.com"
        }))
        .unwrap();
        assert_eq!(r.paths, vec!["/.well-known/agent.json".to_string()]);
        assert_eq!(r.proxy_host.as_deref(), Some("proxy.example.com"));
    }

    #[test]
    fn from_config_no_fields_falls_back_to_defaults() {
        let r = A2aAgentCardRewriter::from_config(serde_json::json!({})).unwrap();
        assert!(r.paths.contains(&"/.well-known/agent.json".to_string()));
        assert!(r.paths.contains(&"/agent-card.json".to_string()));
        assert!(r.proxy_host.is_none());
    }

    /// Test 1: JSON body with top-level `url` pointing at the upstream
    /// and a configured proxy host returns a body whose `url` carries
    /// the proxy host with the original path preserved.
    #[test]
    fn rewrites_top_level_url_to_proxy_host() {
        let r = rewriter();
        let mut body =
            BytesMut::from(&br#"{"name":"agent-1","url":"https://test.sbproxy.dev/agents/1"}"#[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["url"], "https://proxy.test/agents/1");
        assert_eq!(parsed["name"], "agent-1");
    }

    /// Test 2: A response that is not JSON leaves the body untouched
    /// even when the path matches.
    #[test]
    fn non_json_content_type_is_untouched() {
        let r = rewriter();
        let original = b"plain text body with url=https://test.sbproxy.dev";
        let mut body = BytesMut::from(&original[..]);
        r.apply_with_path(
            &mut body,
            Some("text/plain"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        assert_eq!(&body[..], &original[..]);
    }

    /// Test 3: A path that is not in the configured list leaves the
    /// body untouched, even when the content type is JSON and the
    /// body has a rewritable `url`.
    #[test]
    fn non_configured_path_is_untouched() {
        let r = rewriter();
        let original = br#"{"url":"https://test.sbproxy.dev/agents/1"}"#;
        let mut body = BytesMut::from(&original[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/api/v1/things",
            "proxy.test",
        )
        .unwrap();
        assert_eq!(&body[..], &original[..]);
    }

    /// Test 4: Malformed JSON does not crash; the body is left
    /// untouched and the rewriter logs a debug line.
    #[test]
    fn malformed_json_is_untouched() {
        let r = rewriter();
        let original = b"{not valid json,";
        let mut body = BytesMut::from(&original[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        assert_eq!(&body[..], &original[..]);
    }

    /// Test 5: A JSON body with no `url` field is left untouched.
    #[test]
    fn missing_url_field_is_untouched() {
        let r = rewriter();
        let original = br#"{"name":"agent-1","version":"1.0"}"#;
        let mut body = BytesMut::from(&original[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        let parsed_before: serde_json::Value = serde_json::from_slice(original).unwrap();
        let parsed_after: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed_before, parsed_after);
    }

    // --- Extra coverage: endpoint, nested agent.url, alt content types ---

    #[test]
    fn rewrites_endpoint_field() {
        let r = rewriter();
        let mut body =
            BytesMut::from(&br#"{"endpoint":"https://test.sbproxy.dev:8443/jsonrpc"}"#[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/agent-card.json",
            "proxy.test",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["endpoint"], "https://proxy.test/jsonrpc");
    }

    #[test]
    fn rewrites_nested_agent_url() {
        let r = rewriter();
        let mut body = BytesMut::from(
            &br#"{"agent":{"name":"a","url":"https://test.sbproxy.dev/a/run"}}"#[..],
        );
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["agent"]["url"], "https://proxy.test/a/run");
        assert_eq!(parsed["agent"]["name"], "a");
    }

    #[test]
    fn accepts_plus_json_content_type() {
        let r = rewriter();
        let mut body = BytesMut::from(&br#"{"url":"https://test.sbproxy.dev/agents/1"}"#[..]);
        r.apply_with_path(
            &mut body,
            Some("application/agent+json; charset=utf-8"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["url"], "https://proxy.test/agents/1");
    }

    #[test]
    fn relative_url_is_left_alone() {
        let r = rewriter();
        // A relative URL is already proxy-relative; rewriting it
        // would invent a hostname out of nowhere.
        let original = br#"{"url":"/agents/1"}"#;
        let mut body = BytesMut::from(&original[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        assert_eq!(&body[..], &original[..]);
    }

    #[test]
    fn url_already_pointing_at_proxy_host_is_unchanged() {
        let r = rewriter();
        // No rewrite needed; the response should still be a no-op.
        // We compare the parsed JSON in case serde reorders keys.
        let original = br#"{"url":"https://proxy.test/agents/1"}"#;
        let mut body = BytesMut::from(&original[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        let parsed_before: serde_json::Value = serde_json::from_slice(original).unwrap();
        let parsed_after: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed_before, parsed_after);
    }

    #[test]
    fn preserves_query_and_fragment() {
        let r = rewriter();
        let mut body =
            BytesMut::from(&br#"{"url":"https://test.sbproxy.dev/agents/1?token=abc#frag"}"#[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "proxy.test",
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["url"], "https://proxy.test/agents/1?token=abc#frag");
    }

    #[test]
    fn empty_host_is_untouched() {
        let r = rewriter();
        let original = br#"{"url":"https://test.sbproxy.dev/agents/1"}"#;
        let mut body = BytesMut::from(&original[..]);
        r.apply_with_path(
            &mut body,
            Some("application/json"),
            "/.well-known/agent.json",
            "",
        )
        .unwrap();
        assert_eq!(&body[..], &original[..]);
    }

    #[test]
    fn standard_apply_is_noop() {
        let r = rewriter();
        let original = br#"{"url":"https://test.sbproxy.dev/agents/1"}"#;
        let mut body = BytesMut::from(&original[..]);
        r.apply(&mut body).unwrap();
        assert_eq!(&body[..], &original[..]);
    }
}
