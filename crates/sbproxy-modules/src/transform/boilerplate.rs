//! G4.10 boilerplate-stripping transform.
//!
//! Removes navigation chrome, footers, sidebars, ad blocks, and comment
//! sections from HTML so the downstream Markdown projection (G4.3) sees
//! mainly the article body. This is a Readability-lite stripper, not a
//! perfect content extractor; the goal is to cut obvious nav and
//! footer noise without dragging a full HTML parser into the hot path.
//!
//! The transform records the number of bytes removed so the
//! `RequestMetrics::stripped_bytes` counter can be stamped on the
//! per-request audit log (Q4.14). Callers thread the returned `u64`
//! into `ctx.metrics.stripped_bytes` after `apply` returns.
//!
//! Run order: this transform must run BEFORE `HtmlToMarkdownTransform`
//! (G4.3). Doing it after Markdown projection would have nothing to
//! strip; the projection has already discarded structural tags.
//!
//! ## Stripping rules
//!
//! - `<nav>...</nav>`
//! - `<footer>...</footer>`
//! - `<aside>...</aside>`
//! - `<div class="comments">...</div>` (and `comment`, `comment-section`,
//!   `comment-list`, `comments-section`)
//! - `<div id="comments">...</div>` (and the variants above)
//! - `<div class="ad">...</div>` (and `ads`, `advert`, `advertisement`,
//!   `sidebar`)
//! - `<div id="sidebar">...</div>` and `<div id="ads">...</div>`
//!
//! All matches are case-insensitive. Self-closing or empty variants are
//! handled implicitly because the regexes require a closing tag.

use bytes::BytesMut;
use regex::Regex;
use serde::Deserialize;

// --- Config ---

/// YAML configuration shape for the boilerplate transform. Wave 4 ships
/// no knobs; the field is reserved for a future `extra_selectors`
/// expansion without breaking config compatibility.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BoilerplateConfig {}

// --- Transform ---

/// G4.10 boilerplate-stripping transform.
///
/// Stateless: the regexes are built once per `apply` call. Reasonable
/// for the typical N-transforms-per-origin setup; if profiling shows
/// regex build cost becoming significant we can move them into a
/// `OnceCell` on the struct.
#[derive(Debug, Default, Clone)]
pub struct BoilerplateTransform {}

impl BoilerplateTransform {
    /// Build a [`BoilerplateTransform`] from a generic JSON value.
    pub fn from_config(_value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    /// Strip boilerplate from `body` in-place. Returns the count of
    /// bytes removed so the caller can stamp
    /// `ctx.metrics.stripped_bytes`.
    ///
    /// On non-UTF-8 input the transform falls through (returns
    /// `Ok(0)` without modifying the buffer) so a binary upstream
    /// response cannot cause a hard error.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<u64> {
        let Ok(html) = std::str::from_utf8(body) else {
            return Ok(0);
        };
        let original_len = html.len();
        let stripped = strip_boilerplate(html);
        let new_len = stripped.len();
        if new_len == original_len {
            return Ok(0);
        }
        body.clear();
        body.extend_from_slice(stripped.as_bytes());
        Ok((original_len - new_len) as u64)
    }
}

/// Apply every stripping pass in sequence. Each pass walks the input
/// once and is short-circuit safe (a regex that does not match leaves
/// the string unchanged with one allocation).
fn strip_boilerplate(html: &str) -> String {
    let mut out = html.to_string();

    // Tag-name strippers (case-insensitive, multi-line).
    for tag in &["nav", "footer", "aside"] {
        let pattern = format!(
            r"(?is)<{tag}\b[^>]*>.*?</{tag}\s*>",
            tag = regex::escape(tag)
        );
        if let Ok(re) = Regex::new(&pattern) {
            out = re.replace_all(&out, "").into_owned();
        }
    }

    // class-based div strippers. The class attribute may carry multiple
    // tokens, so the inner check looks for the target token between
    // word boundaries.
    let class_targets = [
        "comments",
        "comment",
        "comment-section",
        "comment-list",
        "comments-section",
        "ad",
        "ads",
        "advert",
        "advertisement",
        "sidebar",
    ];
    for target in &class_targets {
        let pattern = format!(
            r#"(?is)<div\b[^>]*\bclass\s*=\s*["'][^"']*\b{cls}\b[^"']*["'][^>]*>.*?</div\s*>"#,
            cls = regex::escape(target)
        );
        if let Ok(re) = Regex::new(&pattern) {
            out = re.replace_all(&out, "").into_owned();
        }
    }

    // id-based div strippers.
    let id_targets = ["comments", "sidebar", "ads", "advertisement"];
    for target in &id_targets {
        let pattern = format!(
            r#"(?is)<div\b[^>]*\bid\s*=\s*["']{id}["'][^>]*>.*?</div\s*>"#,
            id = regex::escape(target)
        );
        if let Ok(re) = Regex::new(&pattern) {
            out = re.replace_all(&out, "").into_owned();
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_str(b: &BytesMut) -> &str {
        std::str::from_utf8(b).expect("utf8")
    }

    #[test]
    fn nav_block_stripped() {
        let t = BoilerplateTransform::default();
        let mut body = BytesMut::from(
            &b"<html><body><nav>menu</nav><h1>Title</h1><p>Body.</p></body></html>"[..],
        );
        let stripped = t.apply(&mut body).unwrap();
        assert!(stripped > 0);
        let s = body_str(&body);
        assert!(!s.contains("<nav>"), "nav stripped: {s}");
        assert!(!s.contains("menu"), "nav body stripped: {s}");
        assert!(s.contains("<h1>Title</h1>"), "article preserved: {s}");
    }

    #[test]
    fn footer_block_stripped() {
        let t = BoilerplateTransform::default();
        let mut body = BytesMut::from(
            &b"<html><body><h1>Hi</h1><footer>copyright junk</footer></body></html>"[..],
        );
        let stripped = t.apply(&mut body).unwrap();
        assert!(stripped > 0);
        let s = body_str(&body);
        assert!(!s.contains("<footer>"), "footer stripped: {s}");
        assert!(!s.contains("copyright junk"), "footer body stripped: {s}");
    }

    #[test]
    fn aside_block_stripped() {
        let t = BoilerplateTransform::default();
        let mut body =
            BytesMut::from(&b"<article><h1>Hi</h1><aside>related links</aside></article>"[..]);
        let stripped = t.apply(&mut body).unwrap();
        assert!(stripped > 0);
        let s = body_str(&body);
        assert!(!s.contains("<aside>"), "aside stripped: {s}");
    }

    #[test]
    fn comments_div_stripped_by_class_and_id() {
        let t = BoilerplateTransform::default();
        let mut body = BytesMut::from(
            &b"<h1>Title</h1><div class=\"comments\">spam</div><div id=\"comments\">also spam</div><p>Body.</p>"[..],
        );
        let stripped = t.apply(&mut body).unwrap();
        assert!(stripped > 0);
        let s = body_str(&body);
        assert!(!s.contains("comments"), "comments stripped: {s}");
        assert!(!s.contains("spam"), "comments body stripped: {s}");
        assert!(s.contains("<p>Body.</p>"), "article preserved: {s}");
    }

    #[test]
    fn html_without_boilerplate_unchanged() {
        let t = BoilerplateTransform::default();
        let mut body = BytesMut::from(&b"<h1>Hi</h1><p>Body.</p>"[..]);
        let stripped = t.apply(&mut body).unwrap();
        assert_eq!(stripped, 0);
        assert_eq!(body_str(&body), "<h1>Hi</h1><p>Body.</p>");
    }

    #[test]
    fn stripped_byte_count_is_positive() {
        let t = BoilerplateTransform::default();
        let original = b"<nav>SOME LONG NAVIGATION BAR</nav><h1>x</h1>";
        let mut body = BytesMut::from(&original[..]);
        let stripped = t.apply(&mut body).unwrap();
        // Strip count >= the bytes between the nav tags.
        assert!(stripped >= b"SOME LONG NAVIGATION BAR".len() as u64);
        // Body got shorter by exactly that much.
        assert_eq!(body.len() as u64 + stripped, original.len() as u64);
    }

    #[test]
    fn ad_div_stripped_via_class() {
        let t = BoilerplateTransform::default();
        let mut body = BytesMut::from(
            &b"<article><div class=\"ad\">Sponsored content here</div><p>Real body.</p></article>"
                [..],
        );
        t.apply(&mut body).unwrap();
        let s = body_str(&body);
        assert!(!s.contains("Sponsored content here"));
        assert!(s.contains("<p>Real body.</p>"));
    }

    #[test]
    fn sidebar_div_stripped_via_id() {
        let t = BoilerplateTransform::default();
        let mut body =
            BytesMut::from(&b"<main><h1>x</h1></main><div id=\"sidebar\">unrelated nav</div>"[..]);
        t.apply(&mut body).unwrap();
        let s = body_str(&body);
        assert!(!s.contains("unrelated nav"));
        assert!(s.contains("<h1>x</h1>"));
    }

    #[test]
    fn config_parses_empty_object() {
        let _t = BoilerplateTransform::from_config(serde_json::json!({})).unwrap();
    }
}
