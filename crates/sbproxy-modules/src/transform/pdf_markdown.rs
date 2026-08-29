//! PDF-to-Markdown transform.
//!
//! When the upstream origin returns a `Content-Type: application/pdf`
//! body, this transform replaces it with a Markdown projection
//! ([`MarkdownProjection`], the same struct [`HtmlToMarkdownTransform`]
//! produces), so downstream JSON-envelope wrapping and token-estimate
//! headers see the same shape as the HTML-to-Markdown path regardless of
//! which source format the origin served.
//!
//! # Cargo feature
//!
//! This module compiles only under the `transform-pdf` feature. It is
//! off by default: `pdf-extract` (content-stream walking and glyph
//! decoding) and `lopdf` (document-object parsing, plus reading the
//! `/Info /Title` trailer entry `pdf-extract` does not expose) together
//! pull roughly 70 transitive crates, and most deployments never see a
//! PDF response. Enable it with `--features sbproxy-modules/transform-pdf`
//! (or the equivalent on the `sbproxy` binary crate) when a route needs
//! it.
//!
//! # Trade-offs
//!
//! - Table layout is not preserved; cells flatten in reading order.
//! - Image-only (scanned) PDFs yield empty text; there is no OCR
//!   fallback.
//! - Encrypted (password-protected) PDFs fail the decode fast rather
//!   than prompting for a password.
//!
//! # Metrics
//!
//! `sbproxy_transform_pdf_pages_decoded_total` on every successful
//! decode; `sbproxy_transform_pdf_decode_errors_total{error_kind}` on
//! failure. Neither carries an `origin` label:
//! [`Transform::apply`](crate::transform::Transform::apply) is handed
//! no origin, so the version this was ported from labeled every series
//! with the empty string, and a label that only ever holds one value
//! is worse than no label. See
//! `dashboards/grafana/sbproxy-overview.json` for the paired panel.
//!
//! # What a decode failure does not say
//!
//! `error_kind` is a closed enum and [`PdfDecodeError::detail`] is a
//! fixed sentence per kind. The underlying library's error message is
//! deliberately dropped rather than logged: `lopdf::Error` has
//! variants that embed strings taken straight out of the parsed file,
//! and this transform runs against upstream response bodies, so
//! formatting one into a log line would put a slice of a relayed
//! payload into the operator's log store.
//!
//! [`pdf-extract`]: https://crates.io/crates/pdf-extract
//! [`lopdf`]: https://crates.io/crates/lopdf

use bytes::BytesMut;
use serde::Deserialize;
use std::sync::LazyLock;

use super::MarkdownProjection;

// --- Config -----------------------------------------------------------------

/// Per-route configuration for the PDF-to-Markdown transform.
#[derive(Clone, Debug, Deserialize)]
pub struct PdfConfig {
    /// Hard cap on pages walked. Pages past this index are dropped
    /// and a `(... PDF truncated at N pages ...)` note is appended to
    /// the Markdown body, bounding CPU/memory consumption for an
    /// adversarially large upload.
    #[serde(default = "default_max_pages")]
    pub max_pages: u32,

    /// Whether to walk the content stream and emit page text. When
    /// `false` the transform produces an empty body with the title
    /// still resolved.
    #[serde(default = "default_true")]
    pub extract_text: bool,

    /// Reserved. Table-layout reconstruction is not implemented;
    /// setting this to `true` logs a `tracing::warn!` and is
    /// otherwise a no-op.
    #[serde(default)]
    pub extract_tables: bool,

    /// Bytes-per-token ratio used by the token-estimate formula
    /// `(body.len() as f32 * token_bytes_ratio) as u32`, matching
    /// [`super::DEFAULT_TOKEN_BYTES_RATIO`]'s 0.25 default for
    /// English prose. Operators with non-English content can
    /// calibrate per route.
    #[serde(default = "default_token_bytes_ratio")]
    pub token_bytes_ratio: f32,
}

impl Default for PdfConfig {
    fn default() -> Self {
        Self {
            max_pages: default_max_pages(),
            extract_text: true,
            extract_tables: false,
            token_bytes_ratio: default_token_bytes_ratio(),
        }
    }
}

fn default_max_pages() -> u32 {
    50
}

fn default_true() -> bool {
    true
}

fn default_token_bytes_ratio() -> f32 {
    super::DEFAULT_TOKEN_BYTES_RATIO
}

/// Closed set of decode-failure causes used as the `error_kind` label
/// on `sbproxy_transform_pdf_decode_errors_total`, bounding the
/// metric's cardinality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeErrorKind {
    /// `lopdf` could not parse the document trailer, xref table, or
    /// catalog. Almost always a truncated upload or a non-PDF body
    /// that slipped past the `Content-Type` check.
    DocumentParse,
    /// The document parsed but `pdf-extract` failed while walking the
    /// content stream. Usually a corrupt page object or an
    /// unsupported font encoding.
    ContentExtract,
    /// The body is empty. Treated as a decode error rather than a
    /// phantom empty Markdown projection downstream.
    EmptyBody,
}

impl DecodeErrorKind {
    /// Stable string form used in the metric label and the
    /// `x-sbproxy-transform-error` detail.
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeErrorKind::DocumentParse => "document_parse",
            DecodeErrorKind::ContentExtract => "content_extract",
            DecodeErrorKind::EmptyBody => "empty_body",
        }
    }
}

/// Concrete error emitted by [`PdfToMarkdownTransform::decode`] on
/// failure. The response middleware's generic transform-error handling
/// (`docs/transforms.md`) turns this into a `500`/`502` with
/// `x-sbproxy-transform-error: pdf_markdown`; the corrupted PDF is
/// never forwarded.
#[derive(Clone, Debug, thiserror::Error)]
#[error("pdf_decode_failed: {kind}: {detail}", kind = .kind.as_str())]
pub struct PdfDecodeError {
    /// Closed-set classification of the failure.
    pub kind: DecodeErrorKind,
    /// Human-readable detail, and deliberately not the underlying
    /// library's error message.
    ///
    /// `lopdf::Error` has variants that embed strings lifted straight
    /// out of the parsed file: `DictKey(String)`,
    /// `InvalidInlineImage(String)`, `InvalidOutline(String)`, and
    /// `DictType { found: String }` among them. Formatting one of
    /// those into a log line puts a fragment of the response body,
    /// which is an upstream payload this proxy is only relaying, into
    /// the operator's log store. So each `DecodeErrorKind` carries a
    /// fixed sentence naming the stage that failed and nothing else. A
    /// failure is diagnosable by kind and by the document that
    /// produced it, not by a quote from inside it.
    pub detail: String,
}

// --- Metrics ------------------------------------------------------------------

/// Turn a registration result into an `Option`, logging instead of
/// ending the process. Production code in this workspace may not add
/// an unwrap or expect site (`scripts/check-unwrap-ratchet.sh`), and a
/// transform that cannot register a counter still has a body to
/// project.
fn registered<M>(result: prometheus::Result<M>, family: &'static str) -> Option<M> {
    match result {
        Ok(metric) => Some(metric),
        Err(error) => {
            debug_assert!(
                false,
                "metric family {family} must register exactly once: {error}"
            );
            tracing::warn!(
                metric = family,
                %error,
                "metric family did not register; the panel reading it stays flat for this process"
            );
            None
        }
    }
}

/// Pages decoded by the `pdf_markdown` transform.
///
/// Unlabeled on purpose. The obvious label is `origin`, and the
/// version of this transform that was ported here declared one, but
/// `Transform::apply(&self, body, content_type)` is handed no origin
/// and the call site passed the empty string for it: every series
/// landed on `origin=""`. A label that always holds one value is worse
/// than no label, because a dashboard filtering on it silently matches
/// everything. Giving it a real value means threading the origin
/// through the whole `Transform` trait, which is its own change.
static PDF_PAGES_DECODED: LazyLock<Option<prometheus::Counter>> = LazyLock::new(|| {
    registered(
        prometheus::register_counter!(
            "sbproxy_transform_pdf_pages_decoded_total",
            "Pages successfully decoded by the pdf_markdown transform",
        ),
        "sbproxy_transform_pdf_pages_decoded_total",
    )
});

/// Decode failures, by `error_kind`. That label is the closed
/// `DecodeErrorKind` enum, never anything read out of the document.
/// Same reasoning as `PDF_PAGES_DECODED` for why there is no `origin`.
static PDF_DECODE_ERRORS: LazyLock<Option<prometheus::CounterVec>> = LazyLock::new(|| {
    registered(
        prometheus::register_counter_vec!(
            "sbproxy_transform_pdf_decode_errors_total",
            "pdf_markdown transform decode failures by error kind",
            &["error_kind"]
        ),
        "sbproxy_transform_pdf_decode_errors_total",
    )
});

fn record_pdf_pages_decoded(count: u64) {
    if let Some(counter) = PDF_PAGES_DECODED.as_ref() {
        counter.inc_by(count as f64);
    }
}

fn record_pdf_decode_error(kind: DecodeErrorKind) {
    if let Some(counter) = PDF_DECODE_ERRORS.as_ref() {
        counter.with_label_values(&[kind.as_str()]).inc();
    }
}

// --- Transform ------------------------------------------------------------

/// PDF-to-Markdown transform implementation. See module docs for the
/// runtime contract.
#[derive(Debug)]
pub struct PdfToMarkdownTransform {
    config: PdfConfig,
}

impl PdfToMarkdownTransform {
    /// Build a transform from a YAML-shaped JSON config.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config: PdfConfig = serde_json::from_value(value)?;
        Ok(Self { config })
    }

    /// Decode a PDF body into a [`MarkdownProjection`].
    ///
    /// Pure synchronous function, exposed so unit tests can drive the
    /// decoder directly.
    pub fn decode(&self, bytes: &[u8]) -> Result<MarkdownProjection, PdfDecodeError> {
        if bytes.is_empty() {
            return Err(PdfDecodeError {
                kind: DecodeErrorKind::EmptyBody,
                detail: "response body has zero bytes".to_string(),
            });
        }

        if self.config.extract_tables {
            tracing::warn!("pdf_markdown: extract_tables is not implemented; treating as false");
        }

        // Read metadata + page count via lopdf even when `extract_text`
        // is false, so the title is still available.
        let doc = lopdf::Document::load_mem(bytes).map_err(|_| PdfDecodeError {
            kind: DecodeErrorKind::DocumentParse,
            // The library error is dropped rather than formatted in;
            // see `PdfDecodeError::detail`.
            detail: "the response body did not parse as a PDF document".to_string(),
        })?;

        let title_from_metadata = read_title(&doc);

        // Per-page extraction (rather than the whole-document API)
        // does not depend on pdf-extract emitting a form-feed at every
        // page boundary, which many real-world PDFs do but minimal
        // synthetic fixtures do not; page boundaries come from the
        // PDF's own /Pages tree instead.
        let pages_owned: Vec<String> = if self.config.extract_text {
            pdf_extract::extract_text_from_mem_by_pages(bytes).map_err(|_| PdfDecodeError {
                kind: DecodeErrorKind::ContentExtract,
                // Same reasoning as the `load_mem` arm above.
                detail: "the PDF parsed but its text content could not be extracted".to_string(),
            })?
        } else {
            Vec::new()
        };

        // Trim trailing empty pages (pdf-extract can emit empty
        // strings for image-only or content-less pages) and apply the
        // configured `max_pages` cap.
        let pages: Vec<&str> = pages_owned
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();

        let max_pages = self.config.max_pages.max(1) as usize;
        let truncated = pages.len() > max_pages;
        let kept: Vec<&str> = pages.iter().take(max_pages).copied().collect();

        let mut body = kept.join("\n\n---\n\n");
        if truncated {
            body.push_str("\n\n---\n\n");
            body.push_str(&format!("(... PDF truncated at {} pages ...)", max_pages));
        }

        record_pdf_pages_decoded(kept.len() as u64);

        // Title resolution order: `/Info /Title`, then the first
        // heading-like line of the body, then a literal fallback.
        let title = title_from_metadata
            .or_else(|| first_heading_like_line(&body))
            .or_else(|| Some("Untitled PDF".to_string()));

        let ratio = self.config.token_bytes_ratio.clamp(0.0, 4.0);
        let token_estimate = (body.len() as f32 * ratio) as u32;

        tracing::info!(
            pages_decoded = kept.len(),
            truncated = truncated,
            token_estimate = token_estimate,
            "pdf_markdown decode succeeded"
        );

        Ok(MarkdownProjection {
            body,
            title,
            token_estimate,
        })
    }

    /// Apply the transform: replace the body with its Markdown
    /// projection when `content_type` is `application/pdf`, otherwise
    /// pass through unchanged.
    pub fn apply(&self, body: &mut BytesMut, content_type: Option<&str>) -> anyhow::Result<()> {
        let is_pdf = content_type
            .map(|c| {
                c.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/pdf")
            })
            .unwrap_or(false);
        if !is_pdf {
            return Ok(());
        }

        match self.decode(body.as_ref()) {
            Ok(projection) => {
                body.clear();
                body.extend_from_slice(projection.body.as_bytes());
                Ok(())
            }
            Err(err) => {
                record_pdf_decode_error(err.kind);
                tracing::error!(
                    kind = err.kind.as_str(),
                    detail = %err.detail,
                    "pdf_markdown decode failed"
                );
                Err(err.into())
            }
        }
    }
}

// --- Helpers --------------------------------------------------------------

/// Read the `/Info /Title` entry from the trailer. `None` when the
/// Info dictionary is absent or the title field is missing or not a
/// string; a malformed metadata block should not fail the decode.
fn read_title(doc: &lopdf::Document) -> Option<String> {
    let info_obj = doc.trailer.get(b"Info").ok()?;
    let info = match info_obj {
        lopdf::Object::Reference(id) => doc.get_object(*id).ok()?.as_dict().ok()?,
        lopdf::Object::Dictionary(d) => d,
        _ => return None,
    };

    let title_obj = info.get(b"Title").ok()?;
    let bytes = match title_obj {
        lopdf::Object::String(b, _) => b,
        _ => return None,
    };

    // PDF strings are PDFDocEncoding by default; a leading FE FF BOM
    // means UTF-16BE instead.
    let raw = if bytes.starts_with(&[0xFE, 0xFF]) {
        decode_utf16_be(&bytes[2..])
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn decode_utf16_be(bytes: &[u8]) -> String {
    let pairs: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&pairs)
}

/// First non-empty line of `body`, stripped of leading ATX/list
/// markers. Fallback title source when `/Info /Title` is absent.
fn first_heading_like_line(body: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let stripped = trimmed
            .trim_start_matches(|c: char| c == '#' || c == '-' || c == '*' || c.is_whitespace());
        if stripped.is_empty() {
            continue;
        }
        return Some(stripped.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_fixture_pdf(title: &str, lines: &[&str]) -> Vec<u8> {
        use lopdf::{dictionary, Object, Stream};

        let mut doc = lopdf::Document::with_version("1.5");

        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });

        let mut ops = vec![
            lopdf::content::Operation::new("BT", vec![]),
            lopdf::content::Operation::new("Tf", vec!["F1".into(), 12.into()]),
            lopdf::content::Operation::new("Td", vec![72.into(), 720.into()]),
        ];
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                ops.push(lopdf::content::Operation::new(
                    "Td",
                    vec![0.into(), (-14).into()],
                ));
            }
            ops.push(lopdf::content::Operation::new(
                "Tj",
                vec![Object::string_literal(*line)],
            ));
        }
        ops.push(lopdf::content::Operation::new("ET", vec![]));
        let content = lopdf::content::Content { operations: ops };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));

        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        });

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });

        let info_id = doc.add_object(dictionary! {
            "Title" => Object::string_literal(title),
        });

        doc.trailer.set("Root", catalog_id);
        doc.trailer.set("Info", info_id);
        doc.compress();

        let mut buf = Vec::new();
        doc.save_to(&mut buf).expect("encode pdf");
        buf
    }

    fn build_multipage_pdf(title: &str, num_pages: u32) -> Vec<u8> {
        use lopdf::{dictionary, Object, Stream};

        let mut doc = lopdf::Document::with_version("1.5");
        let pages_root_id = doc.new_object_id();

        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });

        let mut page_ids: Vec<Object> = Vec::with_capacity(num_pages as usize);
        for i in 0..num_pages {
            let line = format!("Page number {} body line", i + 1);
            let ops = vec![
                lopdf::content::Operation::new("BT", vec![]),
                lopdf::content::Operation::new("Tf", vec!["F1".into(), 12.into()]),
                lopdf::content::Operation::new("Td", vec![72.into(), 720.into()]),
                lopdf::content::Operation::new("Tj", vec![Object::string_literal(line.as_str())]),
                lopdf::content::Operation::new("ET", vec![]),
            ];
            let content = lopdf::content::Content { operations: ops };
            let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
            let page_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_root_id,
                "Contents" => content_id,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            });
            page_ids.push(page_id.into());
        }

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids,
            "Count" => num_pages as i64,
        };
        doc.objects.insert(pages_root_id, Object::Dictionary(pages));

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_root_id,
        });
        let info_id = doc.add_object(dictionary! {
            "Title" => Object::string_literal(title),
        });
        doc.trailer.set("Root", catalog_id);
        doc.trailer.set("Info", info_id);
        doc.compress();

        let mut buf = Vec::new();
        doc.save_to(&mut buf).expect("encode multi-page pdf");
        buf
    }

    fn default_transform() -> PdfToMarkdownTransform {
        PdfToMarkdownTransform {
            config: PdfConfig::default(),
        }
    }

    #[test]
    fn config_defaults_match_doc() {
        let cfg: PdfConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(cfg.max_pages, 50);
        assert!(cfg.extract_text);
        assert!(!cfg.extract_tables);
        assert!((cfg.token_bytes_ratio - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn config_overrides_propagate() {
        let cfg: PdfConfig = serde_json::from_value(serde_json::json!({
            "max_pages": 12,
            "extract_text": false,
            "extract_tables": true,
            "token_bytes_ratio": 0.5,
        }))
        .unwrap();
        assert_eq!(cfg.max_pages, 12);
        assert!(!cfg.extract_text);
        assert!(cfg.extract_tables);
        assert!((cfg.token_bytes_ratio - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn decode_extracts_title_and_text() {
        let pdf = build_fixture_pdf(
            "Test Document",
            &["Hello agent world.", "This document contains two lines."],
        );
        let t = default_transform();
        let projection = t.decode(&pdf).expect("decode");
        assert_eq!(projection.title.as_deref(), Some("Test Document"));
        assert!(projection.body.contains("Hello agent world"));
        assert!(projection.body.contains("two lines"));
        assert!(projection.token_estimate > 0);
    }

    #[test]
    fn decode_token_estimate_matches_formula() {
        let pdf = build_fixture_pdf("X", &["Hello agent world."]);
        let t = PdfToMarkdownTransform {
            config: PdfConfig {
                token_bytes_ratio: 0.5,
                ..PdfConfig::default()
            },
        };
        let projection = t.decode(&pdf).expect("decode");
        let expected = (projection.body.len() as f32 * 0.5) as u32;
        assert_eq!(projection.token_estimate, expected);
    }

    #[test]
    fn decode_falls_back_to_first_line_when_no_title_metadata() {
        // A PDF with no /Info dictionary at all; the title should fall
        // back to the body's first non-empty line.
        use lopdf::{dictionary, Object, Stream};

        let mut doc = lopdf::Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let ops = vec![
            lopdf::content::Operation::new("BT", vec![]),
            lopdf::content::Operation::new("Tf", vec!["F1".into(), 12.into()]),
            lopdf::content::Operation::new("Td", vec![72.into(), 720.into()]),
            lopdf::content::Operation::new("Tj", vec![Object::string_literal("Body Heading Line")]),
            lopdf::content::Operation::new("ET", vec![]),
        ];
        let content = lopdf::content::Content { operations: ops };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        // Intentionally no Info entry.
        doc.compress();
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let t = default_transform();
        let projection = t.decode(&buf).expect("decode");
        assert_eq!(projection.title.as_deref(), Some("Body Heading Line"));
    }

    #[test]
    fn decode_truncates_at_max_pages_with_note() {
        let pdf = build_multipage_pdf("Truncation Test", 6);
        let t = PdfToMarkdownTransform {
            config: PdfConfig {
                max_pages: 3,
                ..PdfConfig::default()
            },
        };
        let projection = t.decode(&pdf).expect("decode");
        assert!(projection
            .body
            .contains("(... PDF truncated at 3 pages ...)"));
        assert!(projection.body.contains("Page number 1"));
        assert!(projection.body.contains("Page number 3"));
        assert!(!projection.body.contains("Page number 4"));
    }

    #[test]
    fn decode_no_truncation_when_under_cap() {
        let pdf = build_multipage_pdf("Under Cap", 2);
        let t = default_transform();
        let projection = t.decode(&pdf).expect("decode");
        assert!(!projection.body.contains("PDF truncated at"));
    }

    #[test]
    fn decode_corrupted_pdf_returns_error() {
        let t = default_transform();
        let err = t
            .decode(b"this is definitely not a pdf body")
            .expect_err("expected decode failure");
        assert_eq!(err.kind, DecodeErrorKind::DocumentParse);
        assert!(err.to_string().starts_with("pdf_decode_failed:"));
    }

    /// RUSTSEC-2026-0187: `lopdf` before 0.42 parsed nested arrays and
    /// dictionaries with unbounded recursion, so a small file whose
    /// Catalog nests a few thousand arrays deep exhausted the call
    /// stack and killed the process with `SIGABRT`. That is an abort,
    /// not a panic, so nothing upstream of here could have caught it,
    /// and this transform is handed upstream response bodies.
    ///
    /// This test is the reason the dependency is floored at 0.42
    /// rather than the 0.38 the port was written against: on a
    /// vulnerable version the process dies here instead of the
    /// assertion failing. It asserts the ordinary refusal, which is
    /// the whole fix: a bounded parser returns `Err` and the transform
    /// reports `document_parse` like any other malformed body.
    #[test]
    fn a_deeply_nested_pdf_is_refused_rather_than_aborting_the_process() {
        // The advisory's own proof of concept: a Catalog whose /X value
        // is thousands of nested arrays. ~10,000 levels is the depth it
        // names; 12,000 leaves margin without making the fixture large.
        const DEPTH: usize = 12_000;
        let mut body = String::from("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /X ");
        body.push_str(&"[".repeat(DEPTH));
        body.push_str(&"]".repeat(DEPTH));
        body.push_str(" >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");

        let t = default_transform();
        let err = t
            .decode(body.as_bytes())
            .expect_err("a nesting bomb must be refused, not parsed");
        assert_eq!(err.kind, DecodeErrorKind::DocumentParse);
        // And the refusal says nothing about what was inside the file.
        assert_eq!(
            err.detail,
            "the response body did not parse as a PDF document"
        );
    }

    /// The decode error an operator sees must never quote the document.
    /// `lopdf::Error` has variants that embed strings lifted out of the
    /// parsed file, so formatting one into the detail would put a slice
    /// of an upstream payload into the log store.
    #[test]
    fn a_decode_failure_detail_carries_no_bytes_from_the_document() {
        let t = default_transform();
        // A body whose recognizable content is a distinctive marker. If
        // any library error string reached `detail`, a fragment of this
        // is what would show up in it.
        let marker = "SENTINEL-PAYLOAD-b7a41f";
        let body = format!("%PDF-1.7\n1 0 obj\n<< /Title ({marker}) /Broken");
        let err = t
            .decode(body.as_bytes())
            .expect_err("expected decode failure");
        assert!(
            !err.detail.contains(marker) && !err.to_string().contains(marker),
            "decode error leaked document content: {}",
            err.detail
        );
    }

    #[test]
    fn decode_empty_body_returns_error() {
        let t = default_transform();
        let err = t.decode(&[]).expect_err("expected decode failure");
        assert_eq!(err.kind, DecodeErrorKind::EmptyBody);
        assert_eq!(err.kind.as_str(), "empty_body");
    }

    #[test]
    fn apply_replaces_body_with_markdown_when_pdf() {
        let pdf = build_fixture_pdf("Apply Test", &["Hello apply."]);
        let mut body = BytesMut::from(pdf.as_slice());
        let t = default_transform();
        t.apply(&mut body, Some("application/pdf")).expect("apply");
        let out = std::str::from_utf8(&body).expect("utf8");
        assert!(out.contains("Hello apply"));
        assert!(!out.starts_with("%PDF"));
    }

    #[test]
    fn apply_passes_through_when_not_pdf() {
        let original = b"<html><body>Hello HTML</body></html>".to_vec();
        let mut body = BytesMut::from(original.as_slice());
        let t = default_transform();
        t.apply(&mut body, Some("text/html; charset=utf-8"))
            .expect("apply");
        assert_eq!(body.as_ref(), original.as_slice());
    }

    #[test]
    fn apply_returns_error_on_corrupted_pdf() {
        let mut body = BytesMut::from(&b"definitely not a pdf"[..]);
        let t = default_transform();
        let err = t
            .apply(&mut body, Some("application/pdf"))
            .expect_err("expected apply to surface decode error");
        assert!(err.to_string().contains("pdf_decode_failed"));
    }
}
