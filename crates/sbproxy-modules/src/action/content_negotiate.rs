//! G4.2 content-negotiate action: resolves content shape from `Accept` headers.
//!
//! Implements the two-pass `Accept`-resolution contract from
//! `docs/adr-content-negotiation-and-pricing.md` (G4.1).
//!
//! ## Pass 1: pricing shape
//! Calls [`ContentShape::from_accept`] (declaration-order, q-values stripped)
//! and stores the result in `RequestContext::content_shape_pricing`. This
//! preserves the existing tier-lookup semantics from G3.5.
//!
//! ## Pass 2: transformation shape
//! A q-value-aware scan over the same `Accept` header. Each MIME type is
//! recognised against the canonical preference table (Markdown, Json, Html,
//! Pdf, Other), tagged with its q-value (default 1.0), and the highest-q
//! shape wins. On q-value tie, the canonical preference order from the
//! ADR breaks the tie: Markdown < Json < Html < Pdf < Other.
//!
//! Wildcard (`*/*`) and absent `Accept` headers fall back to the
//! configured `default_content_shape`, then to `Html`.
//!
//! When pass 1 and pass 2 disagree (e.g. agent sends
//! `Accept: text/markdown;q=0.9, text/html;q=1.0`, pass 1 picks Markdown
//! while pass 2 picks Html), the divergence is logged at debug.
//!
//! The action does not touch the response body; it only stamps `ctx`. The
//! downstream pipeline reads `ctx.content_shape_transform` to drive which
//! response transform runs (G4.3 markdown projection vs G4.4 JSON envelope
//! vs HTML pass-through).

use serde::Deserialize;

use crate::policy::ContentShape;

// --- Config ---

/// YAML configuration shape for the content-negotiate action.
///
/// Lives at the action position on an origin:
///
/// ```yaml
/// action:
///   type: content_negotiate
///   default_content_shape: markdown
/// ```
///
/// Both fields are optional. When `default_content_shape` is unset, the
/// wildcard `*/*` (or an absent `Accept` header) resolves to
/// [`ContentShape::Html`] per G4.1.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ContentNegotiateConfig {
    /// Per-origin default shape used when the agent's `Accept` header
    /// is `*/*` or absent. Defaults to [`ContentShape::Html`] when unset.
    #[serde(default)]
    pub default_content_shape: Option<ContentShape>,
}

impl ContentNegotiateConfig {
    /// Build a [`ContentNegotiateConfig`] from a generic JSON value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }
}

// --- Result type ---

/// Output of the two-pass `Accept` resolver.
///
/// Both shapes are returned so the caller can stamp them onto the
/// per-request context (`content_shape_pricing` and
/// `content_shape_transform`). The two values may differ; see
/// [`crate::action::content_negotiate`] module docs and G4.1 for the
/// rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedShapes {
    /// Pass 1 shape (declaration-order, q-values stripped). Drives the
    /// pricing tier lookup.
    pub pricing: ContentShape,
    /// Pass 2 shape (q-value-aware). Drives the response-body
    /// transformer choice.
    pub transform: ContentShape,
}

impl NegotiatedShapes {
    /// Returns true when the two passes disagree. Useful for logging at
    /// debug or for emitting a divergence metric.
    pub fn diverged(&self) -> bool {
        self.pricing != self.transform
    }
}

// --- Resolver ---

/// Resolve both pricing and transformation shapes from an `Accept` header.
///
/// `accept` is the raw header value. `None` is treated the same as
/// `Some("*/*")`: both passes fall back to `default_shape` (or
/// [`ContentShape::Html`] when that is also `None`).
pub fn resolve_shapes(
    accept: Option<&str>,
    default_shape: Option<ContentShape>,
) -> NegotiatedShapes {
    let fallback = default_shape.unwrap_or(ContentShape::Html);

    // No header at all: both passes fall back.
    let Some(raw) = accept else {
        return NegotiatedShapes {
            pricing: fallback,
            transform: fallback,
        };
    };

    // Wildcard-only header: both passes fall back. We check this before
    // running the resolvers so a `*/*` with no other recognised media
    // types does not get misclassified as Other.
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_only_wildcards(trimmed) {
        return NegotiatedShapes {
            pricing: fallback,
            transform: fallback,
        };
    }

    let pricing = ContentShape::from_accept(raw).unwrap_or(fallback);
    let transform = resolve_transform_shape(raw).unwrap_or(fallback);

    if pricing != transform {
        tracing::debug!(
            ?pricing,
            ?transform,
            accept = raw,
            "content_negotiate: pricing and transform shapes diverge"
        );
    }

    NegotiatedShapes { pricing, transform }
}

/// True when `accept` consists only of wildcards (`*/*` and friends),
/// possibly with q-value parameters and whitespace.
fn is_only_wildcards(accept: &str) -> bool {
    for raw in accept.split(',') {
        let media = raw.split(';').next().unwrap_or("").trim();
        if media != "*/*" && !media.is_empty() {
            return false;
        }
    }
    true
}

/// Pass 2 resolver: q-value-aware scan over the `Accept` header.
///
/// Returns `None` when no recognised MIME type is present.
fn resolve_transform_shape(accept: &str) -> Option<ContentShape> {
    let mut best: Option<(ContentShape, f32, u8)> = None;
    for raw in accept.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(';');
        let media = parts.next()?.trim();
        let mut q: f32 = 1.0;
        for param in parts {
            let param = param.trim();
            if let Some(value) = param
                .strip_prefix("q=")
                .or_else(|| param.strip_prefix("Q="))
            {
                // Malformed q-value silently treated as q=1.0 per the
                // task spec. (The task explicitly calls this out so the
                // resolver does not penalise typos.)
                if let Ok(parsed) = value.trim().parse::<f32>() {
                    if parsed.is_finite() && parsed >= 0.0 {
                        q = parsed.clamp(0.0, 1.0);
                    }
                }
            }
        }
        let Some(shape) = recognise_mime(media) else {
            continue;
        };
        let rank = preference_rank(shape);
        let candidate = (shape, q, rank);
        match best {
            None => best = Some(candidate),
            Some((_, best_q, best_rank)) => {
                // Higher q wins; on tie, lower rank wins.
                if q > best_q || (q == best_q && rank < best_rank) {
                    best = Some(candidate);
                }
            }
        }
    }
    best.map(|(shape, _, _)| shape)
}

/// Map a MIME type string to its [`ContentShape`].
///
/// Mirrors the vocabulary in [`ContentShape::from_accept`] but exposes
/// it as a single-MIME helper so the q-value-aware resolver can tag
/// each entry with its rank.
fn recognise_mime(media: &str) -> Option<ContentShape> {
    if media.eq_ignore_ascii_case("text/markdown") || media.eq_ignore_ascii_case("text/x-markdown")
    {
        return Some(ContentShape::Markdown);
    }
    if media.eq_ignore_ascii_case("application/json")
        || media.eq_ignore_ascii_case("application/ld+json")
    {
        return Some(ContentShape::Json);
    }
    if media.eq_ignore_ascii_case("text/html")
        || media.eq_ignore_ascii_case("application/xhtml+xml")
    {
        return Some(ContentShape::Html);
    }
    if media.eq_ignore_ascii_case("application/pdf") {
        return Some(ContentShape::Pdf);
    }
    None
}

/// Canonical preference order from G4.1: Markdown < Json < Html < Pdf
/// < Other. Lower number wins on q-value tie.
fn preference_rank(shape: ContentShape) -> u8 {
    match shape {
        ContentShape::Markdown => 1,
        ContentShape::Json => 2,
        ContentShape::Html => 3,
        ContentShape::Pdf => 4,
        ContentShape::Other => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Config parsing ---

    #[test]
    fn config_parses_default_content_shape() {
        let cfg: ContentNegotiateConfig = serde_json::from_value(serde_json::json!({
            "default_content_shape": "markdown"
        }))
        .unwrap();
        assert_eq!(cfg.default_content_shape, Some(ContentShape::Markdown));
    }

    #[test]
    fn config_parses_empty() {
        let cfg = ContentNegotiateConfig::from_config(serde_json::json!({})).unwrap();
        assert!(cfg.default_content_shape.is_none());
    }

    // --- Two-pass: simple Accept ---

    #[test]
    fn explicit_q_values_pick_highest_q_for_transform() {
        // Accept: text/html;q=1.0, text/markdown;q=0.9
        // Pass 1: declaration order -> Html (first recognised).
        // Pass 2: q-value -> Html (q=1.0 > 0.9).
        let s = resolve_shapes(Some("text/html;q=1.0, text/markdown;q=0.9"), None);
        assert_eq!(s.pricing, ContentShape::Html);
        assert_eq!(s.transform, ContentShape::Html);
        assert!(!s.diverged());
    }

    #[test]
    fn pricing_and_transform_diverge_when_first_match_loses_q() {
        // Pass 1 picks Markdown (first recognised); Pass 2 picks Html (q=1.0 wins).
        let s = resolve_shapes(Some("text/markdown;q=0.9, text/html;q=1.0"), None);
        assert_eq!(s.pricing, ContentShape::Markdown);
        assert_eq!(s.transform, ContentShape::Html);
        assert!(s.diverged());
    }

    // --- Two-pass: q-value tie at equal preference ---

    #[test]
    fn q_value_tie_breaks_with_canonical_order_markdown_first() {
        // Both q=0.9; canonical order: Markdown (1) beats Html (3).
        let s = resolve_shapes(Some("text/markdown;q=0.9, text/html;q=0.9"), None);
        // Pass 1: declaration order -> Markdown.
        assert_eq!(s.pricing, ContentShape::Markdown);
        // Pass 2: tie -> canonical preference -> Markdown.
        assert_eq!(s.transform, ContentShape::Markdown);
    }

    #[test]
    fn q_value_tie_canonical_order_json_beats_html() {
        // Both q=0.7; Json (2) beats Html (3).
        let s = resolve_shapes(Some("text/html;q=0.7, application/json;q=0.7"), None);
        // Pass 1: text/html first.
        assert_eq!(s.pricing, ContentShape::Html);
        // Pass 2: tie at 0.7, Json beats Html.
        assert_eq!(s.transform, ContentShape::Json);
    }

    // --- Wildcard handling ---

    #[test]
    fn wildcard_only_with_default_uses_default() {
        let s = resolve_shapes(Some("*/*"), Some(ContentShape::Markdown));
        assert_eq!(s.pricing, ContentShape::Markdown);
        assert_eq!(s.transform, ContentShape::Markdown);
    }

    #[test]
    fn wildcard_only_without_default_falls_back_to_html() {
        let s = resolve_shapes(Some("*/*"), None);
        assert_eq!(s.pricing, ContentShape::Html);
        assert_eq!(s.transform, ContentShape::Html);
    }

    #[test]
    fn absent_accept_header_uses_default_or_html() {
        let s = resolve_shapes(None, Some(ContentShape::Json));
        assert_eq!(s.pricing, ContentShape::Json);
        assert_eq!(s.transform, ContentShape::Json);

        let s = resolve_shapes(None, None);
        assert_eq!(s.pricing, ContentShape::Html);
        assert_eq!(s.transform, ContentShape::Html);
    }

    #[test]
    fn empty_accept_header_uses_default() {
        let s = resolve_shapes(Some(""), Some(ContentShape::Markdown));
        assert_eq!(s.pricing, ContentShape::Markdown);
    }

    #[test]
    fn wildcard_with_q_value_treated_as_wildcard() {
        // `*/*;q=0.5` carries no recognised shape; fall back.
        let s = resolve_shapes(Some("*/*;q=0.5"), Some(ContentShape::Json));
        assert_eq!(s.pricing, ContentShape::Json);
        assert_eq!(s.transform, ContentShape::Json);
    }

    // --- Malformed q-value handling ---

    #[test]
    fn malformed_q_value_treated_as_q_one() {
        // `q=abc` is not parseable; the resolver treats it as q=1.0 per spec.
        // text/html with malformed q vs text/markdown q=0.5 -> Html wins.
        let s = resolve_shapes(Some("text/html;q=abc, text/markdown;q=0.5"), None);
        assert_eq!(s.transform, ContentShape::Html);
    }

    // --- Asymmetric pricing-vs-transformation ---

    #[test]
    fn asymmetric_shapes_logged_via_diverged_flag() {
        // The G4.1 ADR's worked example: pricing follows declaration
        // order (Markdown), transformation follows q-value (Html).
        let s = resolve_shapes(Some("text/markdown;q=0.9, text/html;q=1.0"), None);
        assert!(s.diverged());
        assert_eq!(s.pricing, ContentShape::Markdown);
        assert_eq!(s.transform, ContentShape::Html);
    }

    // --- Other recognised types ---

    #[test]
    fn json_ld_recognised_as_json() {
        let s = resolve_shapes(Some("application/ld+json"), None);
        assert_eq!(s.pricing, ContentShape::Json);
        assert_eq!(s.transform, ContentShape::Json);
    }

    #[test]
    fn pdf_recognised() {
        let s = resolve_shapes(Some("application/pdf;q=0.8"), None);
        assert_eq!(s.pricing, ContentShape::Pdf);
        assert_eq!(s.transform, ContentShape::Pdf);
    }

    #[test]
    fn unrecognised_mime_falls_back_to_default() {
        // `application/x-custom` is not recognised; fall back to default.
        let s = resolve_shapes(Some("application/x-custom"), Some(ContentShape::Markdown));
        // Pass 1's `from_accept` returns None -> fallback.
        assert_eq!(s.pricing, ContentShape::Markdown);
        // Pass 2 also finds no recognised MIME -> fallback.
        assert_eq!(s.transform, ContentShape::Markdown);
    }
}
