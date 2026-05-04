//! G4.4 JSON envelope transform: wraps Markdown projection in the v1 schema.
//!
//! Implements the JSON envelope schema pinned by
//! `docs/adr-json-envelope-schema.md` (A4.2). The envelope is the output
//! shape for the `ContentShape::Json` branch of the content-negotiation
//! pipeline (G4.2). It serialises the Markdown body produced by G4.3
//! together with citation metadata, the page's RSL license URN, and any
//! pass-through JSON-LD extracted from the original HTML.
//!
//! The transform is a no-op unless `ctx.content_shape_transform` is
//! `Some(ContentShape::Json)` and `ctx.markdown_projection` has been
//! populated by an upstream HTML-to-Markdown transform. When either
//! precondition is unmet the transform falls through and the upstream
//! body is unchanged.
//!
//! Wire format:
//!
//! ```json
//! {
//!   "schema_version": "1",
//!   "title": "Article Title",
//!   "url": "https://example.com/articles/foo",
//!   "license": "urn:rsl:1.0:example.com:a3f9d2",
//!   "content_md": "# Article Title\n\nBody...",
//!   "fetched_at": "2026-05-01T12:00:00Z",
//!   "citation_required": true,
//!   "schema_org": { "@context": "https://schema.org" },
//!   "token_estimate": 1420
//! }
//! ```

use bytes::BytesMut;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;

use crate::policy::ContentShape;
use crate::transform::MarkdownProjection;

/// Pinned envelope schema version. Bumped only via the breaking-change
/// ADR window per A1.8 (see `docs/adr-json-envelope-schema.md`).
pub const JSON_ENVELOPE_SCHEMA_VERSION: &str = "1";

/// Profile URL stamped into the response `Content-Type` header so
/// agents that branch on the profile can detect the v1 schema before
/// parsing the body. Tracks the body's `schema_version` field.
pub const JSON_ENVELOPE_PROFILE: &str = "https://sbproxy.dev/schema/json-envelope/v1";

/// Content-Type emitted with the JSON envelope. RFC 6906 profile
/// parameter pinning the v1 schema URL.
pub const JSON_ENVELOPE_CONTENT_TYPE: &str =
    "application/json; profile=\"https://sbproxy.dev/schema/json-envelope/v1\"";

// --- Envelope shape ---

/// JSON envelope body (A4.2 v1 schema).
///
/// Field order matches the ADR's locked shape. `serde` preserves the
/// declaration order in the serialised output so agents that pretty-
/// print or hash the body see a stable byte sequence.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JsonEnvelope {
    /// Always `"1"` in Wave 4. String-typed per A1.8 access-log
    /// convention; bumps to `"2"` only via the deprecation window.
    pub schema_version: &'static str,
    /// Page title. Empty string when the source had no `<title>` and no
    /// H1. Required field.
    pub title: String,
    /// Canonical URL of the resource. Sourced from
    /// `RequestContext::canonical_url`; empty when the request handler
    /// did not stamp one.
    pub url: String,
    /// RSL license URN (per `adr-policy-graph-projections.md`) or
    /// `"all-rights-reserved"` when no RSL policy is configured.
    pub license: String,
    /// Markdown body produced by G4.3's projection. Same content as the
    /// `text/markdown` response for the same request.
    pub content_md: String,
    /// RFC 3339 timestamp at which the proxy fetched the upstream
    /// response. UTC only.
    pub fetched_at: DateTime<Utc>,
    /// Operator-configured citation requirement flag. `true` echoes
    /// upstream attribution requirements to the agent.
    pub citation_required: bool,
    /// Pass-through of the page's first `<script type="application/
    /// ld+json">` block. `None` when no JSON-LD is present or the block
    /// failed to parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_org: Option<serde_json::Value>,
    /// Approximate token count of `content_md`. Same value as the
    /// `x-markdown-tokens` response header. Sourced from
    /// `MarkdownProjection::token_estimate`.
    pub token_estimate: u32,
}

impl JsonEnvelope {
    /// Build an envelope from a [`MarkdownProjection`] and the
    /// surrounding request metadata.
    ///
    /// `original_html` is the upstream response body before the Markdown
    /// projection ran; the envelope extracts the first JSON-LD block
    /// from it (if any) for the `schema_org` field.
    pub fn from_projection(
        projection: &MarkdownProjection,
        canonical_url: Option<&str>,
        rsl_urn: Option<&str>,
        citation_required: bool,
        original_html: Option<&str>,
        fetched_at: DateTime<Utc>,
    ) -> Self {
        let title = projection.title.clone().unwrap_or_default();
        let url = canonical_url.unwrap_or("").to_string();
        let license = rsl_urn
            .filter(|s| !s.is_empty())
            .unwrap_or("all-rights-reserved")
            .to_string();
        let schema_org = original_html.and_then(extract_first_json_ld);
        Self {
            schema_version: JSON_ENVELOPE_SCHEMA_VERSION,
            title,
            url,
            license,
            content_md: projection.body.clone(),
            fetched_at,
            citation_required,
            schema_org,
            token_estimate: projection.token_estimate,
        }
    }

    /// Serialise the envelope to a UTF-8 byte vector. Errors only when
    /// the embedded `schema_org` JSON value is somehow non-serialisable,
    /// which should not happen because it comes from
    /// `serde_json::from_str` which already validates structure.
    pub fn to_vec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

// --- Transform ---

/// G4.4 transform: serialises the in-context [`MarkdownProjection`] as a
/// JSON envelope when the negotiated transformation shape is `Json`.
///
/// The transform is a per-origin singleton; it carries no per-request
/// state. The `apply` method takes the `ctx` fields it needs as
/// explicit parameters so the transform stays usable from the existing
/// pure body-buffer pipeline. Callers thread the values from
/// `RequestContext` (G4.2 stamps `content_shape_transform`,
/// `markdown_projection`, `canonical_url`, `rsl_urn`,
/// `citation_required`).
///
/// The `citation_required` flag now lives on
/// `RequestContext::citation_required`, written there by the
/// `ai_crawl_control` tier resolver from the matched [`crate::Tier`].
/// The transform reads `ctx_citation_required` first and falls back to
/// its own optional [`Self::force_citation`] when no tier matched. See
/// `docs/AIGOVERNANCE.md` § 9 (2026-05-02 entry) for the centralisation
/// rationale.
#[derive(Debug, Default, Clone)]
pub struct JsonEnvelopeTransform {
    /// Operator-set fallback for the `citation_required` body field.
    /// `None` means "no force"; the transform reads the flag from
    /// `RequestContext::citation_required` instead. `Some(true)` /
    /// `Some(false)` only applies when the tier resolver did not write
    /// a value (the standalone case where the operator wires the
    /// transform without an `ai_crawl_control` policy). The legacy YAML
    /// key `citation_required: <bool>` is still honoured (mapped to
    /// `force_citation: Some(<bool>)`) for backwards compat with
    /// fixtures authored before the centralisation.
    pub force_citation: Option<bool>,
}

impl JsonEnvelopeTransform {
    /// Build a [`JsonEnvelopeTransform`] from a generic JSON value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(serde::Deserialize, Default)]
        struct Config {
            /// Optional explicit override (preferred name).
            #[serde(default)]
            force_citation: Option<bool>,
            /// Legacy alias kept for fixture compat. When set without
            /// `force_citation`, it maps onto `force_citation`.
            #[serde(default)]
            citation_required: Option<bool>,
        }
        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            force_citation: cfg.force_citation.or(cfg.citation_required),
        })
    }

    /// Apply the JSON-envelope transform.
    ///
    /// `body` is the upstream HTML response (which doubles as the
    /// `original_html` source for JSON-LD extraction). On success, the
    /// buffer is replaced with the serialised envelope bytes; the
    /// caller stamps `Content-Type: application/json; profile="..."`.
    ///
    /// `ctx_citation_required` is the value from
    /// `RequestContext::citation_required`. When `Some`, the tier
    /// resolver matched and the value is authoritative. When `None`,
    /// the transform falls back to [`Self::force_citation`] and finally
    /// to `false`.
    ///
    /// The transform falls through (returns `Ok(false)` without
    /// touching the buffer) when:
    /// - `transform_shape` is not `Some(ContentShape::Json)`, or
    /// - `projection` is `None` (the upstream was not HTML and no
    ///   Markdown projection was produced).
    pub fn apply(
        &self,
        body: &mut BytesMut,
        transform_shape: Option<ContentShape>,
        projection: Option<&MarkdownProjection>,
        canonical_url: Option<&str>,
        rsl_urn: Option<&str>,
        ctx_citation_required: Option<bool>,
    ) -> anyhow::Result<bool> {
        if transform_shape != Some(ContentShape::Json) {
            return Ok(false);
        }
        let Some(projection) = projection else {
            return Ok(false);
        };

        let citation_required = self.resolve_citation_required(ctx_citation_required);

        // Extract JSON-LD from the original body before we overwrite it.
        let original_html = std::str::from_utf8(body).ok().map(str::to_string);

        let envelope = JsonEnvelope::from_projection(
            projection,
            canonical_url,
            rsl_urn,
            citation_required,
            original_html.as_deref(),
            Utc::now(),
        );

        let bytes = envelope.to_vec()?;
        body.clear();
        body.extend_from_slice(&bytes);
        Ok(true)
    }

    /// Resolve the effective citation flag for this request.
    ///
    /// `ctx_value` is the per-request value from
    /// `RequestContext::citation_required` (set by the tier
    /// resolver). It wins when present. When `None`, the transform
    /// falls back to its own [`Self::force_citation`] config; when that
    /// is also `None`, the default is `false`.
    fn resolve_citation_required(&self, ctx_value: Option<bool>) -> bool {
        ctx_value.unwrap_or_else(|| self.force_citation.unwrap_or(false))
    }
}

// --- JSON-LD extraction ---

/// Extract the first `<script type="application/ld+json">...</script>`
/// block from `html` and parse it as JSON. Returns `None` when no block
/// is present, the script tag has no body, or the body fails to parse.
///
/// The regex is intentionally permissive about whitespace and
/// attribute ordering. A real HTML parser would be more correct but
/// the envelope's `schema_org` field is best-effort pass-through; over-
/// matching is preferable to silently dropping legitimate JSON-LD.
fn extract_first_json_ld(html: &str) -> Option<serde_json::Value> {
    static PATTERN: &str =
        r#"(?is)<script\b[^>]*\btype\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script\s*>"#;
    let re = Regex::new(PATTERN).ok()?;
    let caps = re.captures(html)?;
    let raw = caps.get(1)?.as_str().trim();
    if raw.is_empty() {
        return None;
    }
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection(body: &str, title: Option<&str>, tokens: u32) -> MarkdownProjection {
        MarkdownProjection {
            body: body.to_string(),
            title: title.map(str::to_string),
            token_estimate: tokens,
        }
    }

    // --- Schema lock ---

    #[test]
    fn schema_version_constant_locked_to_v1() {
        assert_eq!(JSON_ENVELOPE_SCHEMA_VERSION, "1");
    }

    #[test]
    fn content_type_constant_carries_profile_url() {
        assert!(JSON_ENVELOPE_CONTENT_TYPE.contains("application/json"));
        assert!(JSON_ENVELOPE_CONTENT_TYPE.contains(JSON_ENVELOPE_PROFILE));
    }

    // --- Round-trip serialisation ---

    #[test]
    fn envelope_serialises_full_shape() {
        let proj = projection("# Hi\n\nBody.", Some("Hi"), 12);
        let envelope = JsonEnvelope::from_projection(
            &proj,
            Some("https://example.com/foo"),
            Some("urn:rsl:1.0:example.com:abc"),
            true,
            None,
            DateTime::parse_from_rfc3339("2026-05-01T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let bytes = envelope.to_vec().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(parsed["schema_version"], "1");
        assert_eq!(parsed["title"], "Hi");
        assert_eq!(parsed["url"], "https://example.com/foo");
        assert_eq!(parsed["license"], "urn:rsl:1.0:example.com:abc");
        assert_eq!(parsed["content_md"], "# Hi\n\nBody.");
        assert_eq!(parsed["citation_required"], true);
        assert_eq!(parsed["token_estimate"], 12);
        assert!(parsed.get("schema_org").is_none(), "no JSON-LD => omitted");
        assert!(parsed["fetched_at"].is_string());
    }

    // --- Field defaults ---

    #[test]
    fn missing_title_serialises_as_empty_string() {
        let proj = projection("Body without heading", None, 4);
        let envelope = JsonEnvelope::from_projection(&proj, None, None, false, None, Utc::now());
        assert_eq!(envelope.title, "");
        let bytes = envelope.to_vec().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["title"], "");
    }

    #[test]
    fn missing_license_falls_back_to_all_rights_reserved() {
        let proj = projection("body", Some("t"), 1);
        let envelope = JsonEnvelope::from_projection(&proj, None, None, false, None, Utc::now());
        assert_eq!(envelope.license, "all-rights-reserved");
    }

    #[test]
    fn empty_string_license_falls_back_to_all_rights_reserved() {
        let proj = projection("body", Some("t"), 1);
        let envelope =
            JsonEnvelope::from_projection(&proj, None, Some(""), false, None, Utc::now());
        assert_eq!(envelope.license, "all-rights-reserved");
    }

    // --- citation_required toggle ---

    #[test]
    fn citation_required_true_in_body() {
        let proj = projection("body", Some("t"), 1);
        let envelope = JsonEnvelope::from_projection(&proj, None, None, true, None, Utc::now());
        assert!(envelope.citation_required);
        let bytes = envelope.to_vec().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["citation_required"], true);
    }

    #[test]
    fn citation_required_false_default() {
        let proj = projection("body", Some("t"), 1);
        let envelope = JsonEnvelope::from_projection(&proj, None, None, false, None, Utc::now());
        let bytes = envelope.to_vec().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["citation_required"], false);
    }

    // --- JSON-LD extraction ---

    #[test]
    fn json_ld_extracted_from_script_block() {
        let html = r#"<html><head>
            <script type="application/ld+json">
            {"@context": "https://schema.org", "@type": "Article", "headline": "Hi"}
            </script>
            </head><body>...</body></html>"#;
        let extracted = extract_first_json_ld(html).expect("JSON-LD parses");
        assert_eq!(extracted["@type"], "Article");
        assert_eq!(extracted["headline"], "Hi");
    }

    #[test]
    fn missing_json_ld_yields_none() {
        let html = "<html><body><p>no jsonld here</p></body></html>";
        assert!(extract_first_json_ld(html).is_none());
    }

    #[test]
    fn invalid_json_ld_yields_none() {
        let html = r#"<script type="application/ld+json">{not valid json</script>"#;
        assert!(extract_first_json_ld(html).is_none());
    }

    // --- Transform fall-through ---

    #[test]
    fn transform_falls_through_when_shape_is_not_json() {
        let t = JsonEnvelopeTransform::default();
        let mut body = BytesMut::from(&b"<p>hi</p>"[..]);
        let proj = projection("hi", None, 1);
        let applied = t
            .apply(
                &mut body,
                Some(ContentShape::Markdown),
                Some(&proj),
                None,
                None,
                None,
            )
            .unwrap();
        assert!(!applied);
        assert_eq!(&body[..], b"<p>hi</p>");
    }

    #[test]
    fn transform_falls_through_when_projection_missing() {
        let t = JsonEnvelopeTransform::default();
        let mut body = BytesMut::from(&b"<p>hi</p>"[..]);
        let applied = t
            .apply(&mut body, Some(ContentShape::Json), None, None, None, None)
            .unwrap();
        assert!(!applied);
        assert_eq!(&body[..], b"<p>hi</p>");
    }

    #[test]
    fn transform_writes_envelope_when_shape_and_projection_set() {
        let t = JsonEnvelopeTransform {
            force_citation: Some(true),
        };
        let mut body = BytesMut::from(
            &b"<html><head><script type=\"application/ld+json\">{\"@type\":\"Thing\"}</script></head><body>x</body></html>"[..],
        );
        let proj = projection("# Hi\n\nBody.", Some("Hi"), 7);
        let applied = t
            .apply(
                &mut body,
                Some(ContentShape::Json),
                Some(&proj),
                Some("https://example.com/foo"),
                Some("urn:rsl:1.0:example.com:abc"),
                None,
            )
            .unwrap();
        assert!(applied);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["schema_version"], "1");
        assert_eq!(parsed["title"], "Hi");
        assert_eq!(parsed["url"], "https://example.com/foo");
        assert_eq!(parsed["license"], "urn:rsl:1.0:example.com:abc");
        assert_eq!(parsed["citation_required"], true);
        assert_eq!(parsed["content_md"], "# Hi\n\nBody.");
        assert_eq!(parsed["token_estimate"], 7);
        assert_eq!(parsed["schema_org"]["@type"], "Thing");
    }

    #[test]
    fn config_parses_force_citation_field() {
        let t = JsonEnvelopeTransform::from_config(serde_json::json!({"force_citation": true}))
            .unwrap();
        assert_eq!(t.force_citation, Some(true));
        let t = JsonEnvelopeTransform::from_config(serde_json::json!({})).unwrap();
        assert!(t.force_citation.is_none());
    }

    #[test]
    fn config_accepts_legacy_citation_required_alias() {
        // Pre-centralisation YAML still parses: `citation_required:
        // true` is mapped onto `force_citation: Some(true)`.
        let t = JsonEnvelopeTransform::from_config(serde_json::json!({"citation_required": true}))
            .unwrap();
        assert_eq!(t.force_citation, Some(true));
    }

    // --- citation_required resolution paths (centralisation closeout) ---

    #[test]
    fn citation_required_reads_from_ctx_when_set() {
        let t = JsonEnvelopeTransform {
            force_citation: Some(false),
        };
        let mut body = BytesMut::from(&b"<p>hi</p>"[..]);
        let proj = projection("# Hi\n\nBody.", Some("Hi"), 1);
        // ctx says true; force_citation says false. Ctx wins.
        let applied = t
            .apply(
                &mut body,
                Some(ContentShape::Json),
                Some(&proj),
                None,
                None,
                Some(true),
            )
            .unwrap();
        assert!(applied);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["citation_required"], true, "ctx-set value wins");
    }

    #[test]
    fn citation_required_falls_back_to_force_citation_when_ctx_unset() {
        let t = JsonEnvelopeTransform {
            force_citation: Some(true),
        };
        let mut body = BytesMut::from(&b"<p>hi</p>"[..]);
        let proj = projection("# Hi\n\nBody.", Some("Hi"), 1);
        let applied = t
            .apply(
                &mut body,
                Some(ContentShape::Json),
                Some(&proj),
                None,
                None,
                None,
            )
            .unwrap();
        assert!(applied);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["citation_required"], true,
            "force_citation fallback applies when ctx is unset"
        );
    }

    #[test]
    fn citation_required_defaults_false_when_neither_set() {
        let t = JsonEnvelopeTransform::default();
        let mut body = BytesMut::from(&b"<p>hi</p>"[..]);
        let proj = projection("# Hi\n\nBody.", Some("Hi"), 1);
        let applied = t
            .apply(
                &mut body,
                Some(ContentShape::Json),
                Some(&proj),
                None,
                None,
                None,
            )
            .unwrap();
        assert!(applied);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["citation_required"], false,
            "default is false when ctx and force_citation are both unset"
        );
    }
}
