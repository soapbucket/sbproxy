//! G4.10 citation-block transform: prepends a Markdown citation line
//! to the projection body when the operator requires attribution.
//!
//! When the per-origin `citation_required` flag is true, the transform
//! prepends a single Markdown blockquote line of the form:
//!
//! ```text
//! > Citation required for AI training and inference. Source: <canonical_url>. License: <license>.
//! ```
//!
//! The fields are sourced from `RequestContext::canonical_url` and
//! `RequestContext::rsl_urn` (both stamped earlier in the pipeline by
//! the request enricher and RSL projection). When `canonical_url` is
//! absent or empty the transform writes `Source: unknown`. When
//! `rsl_urn` is absent the transform falls back to `all-rights-reserved`
//! to mirror the JSON envelope's licence-field rule (G4.4).
//!
//! The transform is idempotent on the no-citation path: when the flag is
//! false, the body is unchanged.

use bytes::BytesMut;
use serde::Deserialize;

// --- Config ---

/// YAML configuration shape for the citation-block transform.
///
/// ```yaml
/// transforms:
///   - type: citation_block
///     # optional standalone override; normally the flag is read from
///     # `RequestContext::citation_required` (set by the ai_crawl_control
///     # tier resolver from the matched Tier).
///     force_citation: true
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CitationBlockConfig {
    /// Operator-set fallback for the citation flag. `None` means
    /// "defer to context"; the transform reads
    /// `RequestContext::citation_required` and only falls back when
    /// no tier matched.
    #[serde(default)]
    pub force_citation: Option<bool>,
    /// Legacy alias kept for fixture compat. Pre-centralisation YAML
    /// used `citation_required: bool`. When set without
    /// `force_citation`, it maps onto `force_citation`.
    #[serde(default)]
    pub citation_required: Option<bool>,
}

// --- Transform ---

/// G4.10 citation-block transform. Stateless; reads the citation flag
/// from per-request context (preferred) and falls back to its own
/// optional [`Self::force_citation`] config when no tier matched. See
/// `docs/AIGOVERNANCE.md` § 9 (2026-05-02 entry) for why the flag lives
/// on [`crate::Tier`] / `RequestContext` rather than in two transform
/// configs.
#[derive(Debug, Default, Clone)]
pub struct CitationBlockTransform {
    /// Optional operator-set fallback. `None` means "defer to context";
    /// `Some(_)` only applies when `RequestContext::citation_required`
    /// is `None` (no `ai_crawl_control` tier matched).
    pub force_citation: Option<bool>,
}

impl CitationBlockTransform {
    /// Build a [`CitationBlockTransform`] from a generic JSON value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: CitationBlockConfig = serde_json::from_value(value)?;
        Ok(Self {
            force_citation: cfg.force_citation.or(cfg.citation_required),
        })
    }

    /// Apply the citation-block prefix.
    ///
    /// `body` is the Markdown projection; on success the buffer is
    /// rewritten with the citation line followed by two newlines and
    /// the original body. When the resolved citation flag is `false`
    /// the body is returned unchanged.
    ///
    /// `ctx_citation_required` is the per-request value from
    /// `RequestContext::citation_required`. When `Some`, the tier
    /// resolver matched and the value is authoritative. When `None`,
    /// the transform falls back to [`Self::force_citation`] and finally
    /// to `false`.
    ///
    /// `canonical_url` and `rsl_urn` come from `RequestContext`. Either
    /// being `None` or empty falls back per the rules in the module
    /// docs.
    pub fn apply(
        &self,
        body: &mut BytesMut,
        canonical_url: Option<&str>,
        rsl_urn: Option<&str>,
        ctx_citation_required: Option<bool>,
    ) -> anyhow::Result<()> {
        if !self.resolve_citation_required(ctx_citation_required) {
            return Ok(());
        }

        let url = canonical_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown");
        let license = rsl_urn
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("all-rights-reserved");

        let prefix = format!(
            "> Citation required for AI training and inference. Source: {url}. License: {license}.\n\n"
        );

        // Build a new buffer with prefix + existing body. Avoids
        // shifting the existing bytes which is what
        // `body.extend_from_slice` after `body.clear()` would force.
        let original = body.clone();
        body.clear();
        body.reserve(prefix.len() + original.len());
        body.extend_from_slice(prefix.as_bytes());
        body.extend_from_slice(&original);

        Ok(())
    }

    /// Resolve the effective citation flag for this request.
    ///
    /// `ctx_value` is the per-request value from
    /// `RequestContext::citation_required` (set by the tier
    /// resolver). It wins when present. When `None`, the transform
    /// falls back to its own [`Self::force_citation`] config; when
    /// that is also `None`, the default is `false`.
    fn resolve_citation_required(&self, ctx_value: Option<bool>) -> bool {
        ctx_value.unwrap_or_else(|| self.force_citation.unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_str(b: &BytesMut) -> &str {
        std::str::from_utf8(b).expect("utf8")
    }

    #[test]
    fn citation_required_false_leaves_body_unchanged() {
        let t = CitationBlockTransform {
            force_citation: Some(false),
        };
        let mut body = BytesMut::from(&b"# Title\n\nBody."[..]);
        t.apply(
            &mut body,
            Some("https://example.com/x"),
            Some("urn:rsl:1.0:foo"),
            None,
        )
        .unwrap();
        assert_eq!(body_str(&body), "# Title\n\nBody.");
    }

    #[test]
    fn citation_required_true_with_full_inputs_prepends_line() {
        let t = CitationBlockTransform {
            force_citation: Some(true),
        };
        let mut body = BytesMut::from(&b"# Title\n\nBody."[..]);
        t.apply(
            &mut body,
            Some("https://example.com/x"),
            Some("urn:rsl:1.0:foo"),
            None,
        )
        .unwrap();
        let s = body_str(&body);
        assert!(
            s.starts_with("> Citation required for AI training and inference. Source: https://example.com/x. License: urn:rsl:1.0:foo.\n\n"),
            "got: {s}"
        );
        assert!(s.contains("# Title\n\nBody."));
    }

    #[test]
    fn citation_required_true_without_rsl_urn_uses_all_rights_reserved() {
        let t = CitationBlockTransform {
            force_citation: Some(true),
        };
        let mut body = BytesMut::from(&b"body"[..]);
        t.apply(&mut body, Some("https://example.com/x"), None, None)
            .unwrap();
        let s = body_str(&body);
        assert!(s.contains("License: all-rights-reserved."));
    }

    #[test]
    fn citation_required_true_with_empty_rsl_urn_uses_all_rights_reserved() {
        let t = CitationBlockTransform {
            force_citation: Some(true),
        };
        let mut body = BytesMut::from(&b"body"[..]);
        t.apply(&mut body, Some("https://example.com/x"), Some(""), None)
            .unwrap();
        let s = body_str(&body);
        assert!(s.contains("License: all-rights-reserved."));
    }

    #[test]
    fn citation_required_true_with_empty_canonical_url_uses_unknown() {
        let t = CitationBlockTransform {
            force_citation: Some(true),
        };
        let mut body = BytesMut::from(&b"body"[..]);
        t.apply(&mut body, None, Some("urn:rsl:1.0:foo"), None)
            .unwrap();
        let s = body_str(&body);
        assert!(s.contains("Source: unknown."));
    }

    #[test]
    fn config_parses_force_citation_field() {
        let t = CitationBlockTransform::from_config(serde_json::json!({"force_citation": true}))
            .unwrap();
        assert_eq!(t.force_citation, Some(true));

        let t = CitationBlockTransform::from_config(serde_json::json!({})).unwrap();
        assert!(t.force_citation.is_none());
    }

    #[test]
    fn config_accepts_legacy_citation_required_alias() {
        // Pre-centralisation YAML still parses: `citation_required:
        // true` is mapped onto `force_citation: Some(true)`.
        let t = CitationBlockTransform::from_config(serde_json::json!({"citation_required": true}))
            .unwrap();
        assert_eq!(t.force_citation, Some(true));
    }

    // --- citation_required resolution paths (centralisation closeout) ---

    #[test]
    fn citation_required_reads_from_ctx_when_set() {
        // Force is false; ctx says true. Ctx wins.
        let t = CitationBlockTransform {
            force_citation: Some(false),
        };
        let mut body = BytesMut::from(&b"body"[..]);
        t.apply(
            &mut body,
            Some("https://example.com/x"),
            Some("urn:rsl:1.0:foo"),
            Some(true),
        )
        .unwrap();
        let s = body_str(&body);
        assert!(
            s.starts_with("> Citation required"),
            "ctx-set value wins: {s}"
        );
    }

    #[test]
    fn citation_required_falls_back_to_force_citation_when_ctx_unset() {
        let t = CitationBlockTransform {
            force_citation: Some(true),
        };
        let mut body = BytesMut::from(&b"body"[..]);
        t.apply(
            &mut body,
            Some("https://example.com/x"),
            Some("urn:rsl:1.0:foo"),
            None,
        )
        .unwrap();
        let s = body_str(&body);
        assert!(
            s.starts_with("> Citation required"),
            "force_citation fallback applies: {s}"
        );
    }

    #[test]
    fn citation_required_defaults_false_when_neither_set() {
        let t = CitationBlockTransform::default();
        let mut body = BytesMut::from(&b"body"[..]);
        t.apply(
            &mut body,
            Some("https://example.com/x"),
            Some("urn:rsl:1.0:foo"),
            None,
        )
        .unwrap();
        assert_eq!(body_str(&body), "body", "default false leaves body alone");
    }
}
