//! Markup transforms: HTML manipulation, HTML optimization, HTML-to-Markdown
//! conversion, Markdown-to-HTML conversion, and CSS manipulation.

use bytes::BytesMut;
use regex::Regex;
use serde::Deserialize;

// --- Helper ---

fn default_true() -> bool {
    true
}

/// Convert body bytes to a UTF-8 string, returning an error if invalid.
fn body_to_string(body: &BytesMut) -> anyhow::Result<String> {
    String::from_utf8(body.to_vec()).map_err(|e| anyhow::anyhow!("body is not valid UTF-8: {}", e))
}

/// Replace body contents with the given string.
fn replace_body(body: &mut BytesMut, text: &str) {
    body.clear();
    body.extend_from_slice(text.as_bytes());
}

// --- HtmlTransform ---

/// Where to inject HTML content.
#[derive(Debug, Deserialize, Clone)]
pub struct HtmlInjection {
    /// One of: "head_end", "body_start", "body_end".
    pub position: String,
    /// HTML content to inject.
    pub content: String,
}

/// Rewrite an attribute on elements matching a CSS selector.
#[derive(Debug, Deserialize, Clone)]
pub struct AttributeRewrite {
    /// CSS selector (used as a simple tag match for now).
    pub selector: String,
    /// Attribute name to set.
    pub attribute: String,
    /// New attribute value.
    pub value: String,
}

/// Format options for HTML optimization (Go config compatibility).
///
/// These map to OptimizeHtmlTransform behavior:
/// `strip_comments` -> remove HTML comments
/// `strip_newlines` / `strip_space` -> collapse whitespace
/// `lowercase_tags` -> lowercase all tag names
#[derive(Debug, Deserialize, Default, Clone)]
pub struct HtmlFormatOptions {
    /// Remove HTML comments (`<!-- ... -->`).
    #[serde(default)]
    pub strip_comments: bool,
    /// Remove newlines between tags.
    #[serde(default)]
    pub strip_newlines: bool,
    /// Collapse runs of whitespace.
    #[serde(default)]
    pub strip_space: bool,
    /// Lowercase all HTML tag names.
    #[serde(default)]
    pub lowercase_tags: bool,
}

/// Manipulates HTML content: inject elements, remove elements, rewrite attributes.
///
/// Uses basic string operations (no full HTML parser). Injection targets the
/// `</head>`, `<body>`, and `</body>` tags. Removal uses simple regex matching
/// against tag patterns. Attribute rewrites match opening tags by tag name.
///
/// When `format_options` is present, also applies HTML optimization (comment
/// stripping, whitespace collapsing) after the manipulation phase.
#[derive(Debug, Deserialize)]
pub struct HtmlTransform {
    /// CSS selectors to remove from the HTML.
    /// Currently supports simple tag names (e.g. "script", "style") and
    /// id selectors (e.g. "#banner").
    #[serde(default)]
    pub remove_selectors: Vec<String>,
    /// Elements to inject at specific positions.
    #[serde(default)]
    pub inject: Vec<HtmlInjection>,
    /// Attribute rewrites on matching elements.
    #[serde(default)]
    pub rewrite_attributes: Vec<AttributeRewrite>,
    /// HTML optimization options (Go config compatibility).
    #[serde(default)]
    pub format_options: Option<HtmlFormatOptions>,
}

impl HtmlTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply HTML manipulation to the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let mut html = body_to_string(body)?;

        // Remove elements matching selectors.
        for selector in &self.remove_selectors {
            html = self.remove_selector(&html, selector);
        }

        // Inject content at positions.
        for injection in &self.inject {
            html = self.inject_content(&html, injection);
        }

        // Rewrite attributes.
        for rewrite in &self.rewrite_attributes {
            html = self.rewrite_attr(&html, rewrite);
        }

        // Apply format options (HTML optimization) if present.
        if let Some(opts) = &self.format_options {
            if opts.strip_comments {
                if let Ok(re) = Regex::new(r"(?s)<!--.*?-->") {
                    html = re.replace_all(&html, "").into_owned();
                }
            }
            if opts.strip_newlines || opts.strip_space {
                html = collapse_whitespace_preserving_pre(&html);
            }
            if opts.lowercase_tags {
                if let Ok(re) = Regex::new(r"<(/?)([A-Z][A-Za-z0-9]*)") {
                    html = re
                        .replace_all(&html, |caps: &regex::Captures| {
                            format!("<{}{}", &caps[1], caps[2].to_lowercase())
                        })
                        .into_owned();
                }
            }
        }

        replace_body(body, &html);
        Ok(())
    }

    /// Remove elements matching a simple selector.
    /// Supports tag names ("script", "style") and id selectors ("#banner").
    fn remove_selector(&self, html: &str, selector: &str) -> String {
        if let Some(id) = selector.strip_prefix('#') {
            // Remove element with matching id attribute (self-closing or paired).
            let pattern = format!(
                r#"(?is)<\w+[^>]*\bid\s*=\s*["']{id}["'][^>]*/?>(?:.*?</\w+>)?"#,
                id = regex::escape(id)
            );
            if let Ok(re) = Regex::new(&pattern) {
                return re.replace_all(html, "").into_owned();
            }
        } else if let Some(cls) = selector.strip_prefix('.') {
            // Remove elements with matching class.
            let pattern = format!(
                r#"(?is)<(\w+)[^>]*\bclass\s*=\s*["'][^"']*\b{cls}\b[^"']*["'][^>]*>.*?</\1>"#,
                cls = regex::escape(cls)
            );
            if let Ok(re) = Regex::new(&pattern) {
                return re.replace_all(html, "").into_owned();
            }
        } else {
            // Tag name selector: remove both paired and self-closing tags.
            let tag = regex::escape(selector);
            let pattern = format!(
                r"(?is)<{tag}\b[^>]*>.*?</{tag}\s*>|<{tag}\b[^>]*/?>",
                tag = tag
            );
            if let Ok(re) = Regex::new(&pattern) {
                return re.replace_all(html, "").into_owned();
            }
        }
        html.to_string()
    }

    /// Inject HTML content at a specific position.
    fn inject_content(&self, html: &str, injection: &HtmlInjection) -> String {
        match injection.position.as_str() {
            "head_end" => {
                // Insert before </head>.
                if let Some(pos) = html.to_lowercase().find("</head>") {
                    let mut result = String::with_capacity(html.len() + injection.content.len());
                    result.push_str(&html[..pos]);
                    result.push_str(&injection.content);
                    result.push_str(&html[pos..]);
                    return result;
                }
            }
            "body_start" => {
                // Insert after <body> (with optional attributes).
                let re = Regex::new(r"(?i)<body[^>]*>").ok();
                if let Some(re) = re {
                    if let Some(m) = re.find(html) {
                        let mut result =
                            String::with_capacity(html.len() + injection.content.len());
                        result.push_str(&html[..m.end()]);
                        result.push_str(&injection.content);
                        result.push_str(&html[m.end()..]);
                        return result;
                    }
                }
            }
            "body_end" => {
                // Insert before </body>.
                if let Some(pos) = html.to_lowercase().find("</body>") {
                    let mut result = String::with_capacity(html.len() + injection.content.len());
                    result.push_str(&html[..pos]);
                    result.push_str(&injection.content);
                    result.push_str(&html[pos..]);
                    return result;
                }
            }
            _ => {}
        }
        // If the target tag was not found, return unchanged.
        html.to_string()
    }

    /// Rewrite an attribute on tags matching the selector (tag name only).
    fn rewrite_attr(&self, html: &str, rewrite: &AttributeRewrite) -> String {
        let tag = regex::escape(&rewrite.selector);
        let attr = regex::escape(&rewrite.attribute);
        let pattern = format!(
            r#"(?i)(<{tag}\b[^>]*)\b{attr}\s*=\s*["'][^"']*["']"#,
            tag = tag,
            attr = attr
        );

        if let Ok(re) = Regex::new(&pattern) {
            let replacement = format!(r#"${{1}}{}="{}""#, rewrite.attribute, rewrite.value);
            let result = re.replace_all(html, replacement.as_str()).into_owned();
            // If the attribute was replaced at least once, return.
            if result != html {
                return result;
            }
        }

        // If the attribute was not found on any matching tag, add it to the first match.
        let tag_pattern = format!(r"(?i)<{tag}\b", tag = tag);
        if let Ok(re) = Regex::new(&tag_pattern) {
            if let Some(m) = re.find(html) {
                let mut result = String::with_capacity(
                    html.len() + rewrite.attribute.len() + rewrite.value.len() + 5,
                );
                result.push_str(&html[..m.end()]);
                result.push_str(&format!(r#" {}="{}""#, rewrite.attribute, rewrite.value));
                result.push_str(&html[m.end()..]);
                return result;
            }
        }

        html.to_string()
    }
}

// --- OptimizeHtmlTransform ---

/// Minifies HTML by removing comments and collapsing whitespace.
///
/// A lightweight optimization that does not require a full HTML parser.
/// Strips `<!-- -->` comments and collapses runs of whitespace into
/// single spaces while preserving content inside `<pre>` and `<code>` tags.
#[derive(Debug, Deserialize, Default)]
pub struct OptimizeHtmlTransform {
    /// Remove HTML comments (`<!-- ... -->`). Default: true.
    #[serde(default = "default_true")]
    pub remove_comments: bool,
    /// Collapse runs of whitespace to a single space. Default: true.
    #[serde(default = "default_true")]
    pub collapse_whitespace: bool,
    /// Remove certain optional closing tags (experimental). Default: false.
    #[serde(default)]
    pub remove_optional_tags: bool,
}

impl OptimizeHtmlTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply HTML optimization to the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let mut html = body_to_string(body)?;

        if self.remove_comments {
            // Remove HTML comments, including multi-line.
            if let Ok(re) = Regex::new(r"(?s)<!--.*?-->") {
                html = re.replace_all(&html, "").into_owned();
            }
        }

        if self.collapse_whitespace {
            // Collapse runs of whitespace (spaces, tabs, newlines) into a single space,
            // but skip content inside <pre> and <code> tags.
            html = collapse_whitespace_preserving_pre(&html);
        }

        if self.remove_optional_tags {
            // Remove optional closing tags: </li>, </p>, </td>, </th>, </tr>,
            // </thead>, </tbody>, </tfoot>, </dd>, </dt>.
            if let Ok(re) = Regex::new(r"(?i)</(?:li|p|td|th|tr|thead|tbody|tfoot|dd|dt)\s*>") {
                html = re.replace_all(&html, "").into_owned();
            }
        }

        replace_body(body, &html);
        Ok(())
    }
}

/// Collapse whitespace while preserving content inside `<pre>` blocks.
fn collapse_whitespace_preserving_pre(html: &str) -> String {
    // Split on <pre> ... </pre> boundaries.
    let pre_re = Regex::new(r"(?is)(<pre\b[^>]*>.*?</pre\s*>)").unwrap();
    let mut result = String::with_capacity(html.len());
    let mut last_end = 0;

    for m in pre_re.find_iter(html) {
        // Collapse whitespace in the non-pre segment.
        let segment = &html[last_end..m.start()];
        result.push_str(&collapse_ws(segment));
        // Preserve the <pre> block as-is.
        result.push_str(m.as_str());
        last_end = m.end();
    }

    // Handle trailing content after the last <pre> block.
    if last_end < html.len() {
        result.push_str(&collapse_ws(&html[last_end..]));
    }

    result
}

/// Collapse runs of whitespace into single spaces.
fn collapse_ws(text: &str) -> String {
    let ws_re = Regex::new(r"\s+").unwrap();
    ws_re.replace_all(text, " ").into_owned()
}

// --- HtmlToMarkdownTransform ---

/// Default tokens-per-byte ratio for the Markdown token estimator.
///
/// `0.25` is the rough English-prose approximation called out in
/// `docs/adr-json-envelope-schema.md` (A4.2). Operators with non-English
/// or dense technical content can override this on the per-origin
/// `token_bytes_ratio` knob.
pub const DEFAULT_TOKEN_BYTES_RATIO: f32 = 0.25;

fn default_token_bytes_ratio() -> f32 {
    DEFAULT_TOKEN_BYTES_RATIO
}

/// Result of an HTML-to-Markdown projection.
///
/// G4.3 (Markdown response) and G4.4 (JSON envelope) both consume the
/// same projection so the `token_estimate` field never diverges between
/// the body and the `x-markdown-tokens` response header. The `title` is
/// extracted from the first H1 in the produced Markdown body, falling
/// back to the original HTML `<title>` element when no H1 is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownProjection {
    /// Rendered Markdown body. Same content that `HtmlToMarkdownTransform::apply`
    /// would write into the response when the negotiated shape is `Markdown`.
    pub body: String,
    /// Page title. `Some` when an H1 was found in the body or a `<title>`
    /// element was found in the source HTML. `None` is preserved for the
    /// JSON envelope to serialise as an empty string.
    pub title: Option<String>,
    /// Approximate token count of `body`, using
    /// `(body.len() as f32 * token_bytes_ratio) as u32`. Capped by `u32::MAX`
    /// for absurdly large inputs (~17 GiB at the default ratio).
    pub token_estimate: u32,
}

/// Converts HTML to Markdown using regex-based extraction.
///
/// Handles common HTML elements: headings, paragraphs, links, bold, italic,
/// inline code, line breaks, and lists. Not a full parser, so deeply nested
/// or malformed HTML may not convert perfectly.
#[derive(Debug, Deserialize)]
pub struct HtmlToMarkdownTransform {
    /// Heading style: "atx" (# style, default) or "setext" (underline).
    #[serde(default)]
    pub heading_style: Option<String>,
    /// Tokens-per-byte ratio for the projection's `token_estimate` field
    /// (G4.3 / A4.2). Defaults to [`DEFAULT_TOKEN_BYTES_RATIO`]; operators
    /// can override per-origin to calibrate for non-English or dense
    /// technical content.
    #[serde(default = "default_token_bytes_ratio")]
    pub token_bytes_ratio: f32,
}

impl Default for HtmlToMarkdownTransform {
    fn default() -> Self {
        Self {
            heading_style: None,
            token_bytes_ratio: DEFAULT_TOKEN_BYTES_RATIO,
        }
    }
}

impl HtmlToMarkdownTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply HTML-to-Markdown conversion to the body.
    ///
    /// Equivalent to running [`Self::project`] and writing only the body
    /// back into the buffer. Callers that need the title and token
    /// estimate (G4.4 JSON envelope, G4.3 `x-markdown-tokens` header)
    /// should call `project` instead and stash the result in
    /// `RequestContext::markdown_projection`.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let html = body_to_string(body)?;
        let projection = self.project(&html);
        replace_body(body, &projection.body);
        Ok(())
    }

    /// Project HTML into a [`MarkdownProjection`].
    ///
    /// Computes the Markdown body once, then derives the title and
    /// token estimate from the same string so the three outputs are
    /// always internally consistent.
    pub fn project(&self, html: &str) -> MarkdownProjection {
        // Capture the original `<title>` before the regex pipeline strips
        // tags so we can fall back to it when the body has no H1.
        let html_title = extract_html_title(html);
        let body = self.convert(html);
        let title = first_markdown_h1(&body).or(html_title);
        let token_estimate = estimate_tokens(&body, self.token_bytes_ratio);
        MarkdownProjection {
            body,
            title,
            token_estimate,
        }
    }

    /// Convert HTML string to Markdown.
    fn convert(&self, html: &str) -> String {
        let mut text = html.to_string();
        let use_setext = self.heading_style.as_deref() == Some("setext");

        // Strip <head>...</head> wholesale. The `<title>` extraction
        // for the MarkdownProjection.title field happens against the
        // original HTML in `project()` so we don't lose the title;
        // stripping the whole head here keeps the body Markdown
        // free of stray title / meta text that would otherwise prefix
        // the body when no H1 is the literal first element.
        if let Ok(re) = Regex::new(r"(?is)<head\b[^>]*>.*?</head\s*>") {
            text = re.replace_all(&text, "").into_owned();
        }

        // Strip <script> and <style> blocks.
        if let Ok(re) = Regex::new(r"(?is)<script\b[^>]*>.*?</script\s*>") {
            text = re.replace_all(&text, "").into_owned();
        }
        if let Ok(re) = Regex::new(r"(?is)<style\b[^>]*>.*?</style\s*>") {
            text = re.replace_all(&text, "").into_owned();
        }

        // Headings h1-h6.
        for level in 1..=6u8 {
            let pattern = format!(r"(?is)<h{level}\b[^>]*>(.*?)</h{level}\s*>");
            if let Ok(re) = Regex::new(&pattern) {
                if use_setext && level <= 2 {
                    let underline_char = if level == 1 { '=' } else { '-' };
                    text = re
                        .replace_all(&text, |caps: &regex::Captures| {
                            let content = strip_tags(&caps[1]).trim().to_string();
                            let underline = std::iter::repeat_n(underline_char, content.len())
                                .collect::<String>();
                            format!("\n{}\n{}\n", content, underline)
                        })
                        .into_owned();
                } else {
                    let prefix = "#".repeat(level as usize);
                    text = re
                        .replace_all(&text, |caps: &regex::Captures| {
                            let content = strip_tags(&caps[1]).trim().to_string();
                            format!("\n{} {}\n", prefix, content)
                        })
                        .into_owned();
                }
            }
        }

        // Bold: <strong> or <b>.
        if let Ok(re) = Regex::new(r"(?is)<(?:strong|b)\b[^>]*>(.*?)</(?:strong|b)\s*>") {
            text = re.replace_all(&text, "**$1**").into_owned();
        }

        // Italic: <em> or <i>.
        if let Ok(re) = Regex::new(r"(?is)<(?:em|i)\b[^>]*>(.*?)</(?:em|i)\s*>") {
            text = re.replace_all(&text, "*$1*").into_owned();
        }

        // Inline code.
        if let Ok(re) = Regex::new(r"(?is)<code\b[^>]*>(.*?)</code\s*>") {
            text = re.replace_all(&text, "`$1`").into_owned();
        }

        // Links: <a href="url">text</a>.
        if let Ok(re) =
            Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*["']([^"']*)["'][^>]*>(.*?)</a\s*>"#)
        {
            text = re
                .replace_all(&text, |caps: &regex::Captures| {
                    let url = &caps[1];
                    let link_text = strip_tags(&caps[2]);
                    format!("[{}]({})", link_text.trim(), url)
                })
                .into_owned();
        }

        // Images: <img src="url" alt="text" />.
        if let Ok(re) = Regex::new(
            r#"(?is)<img\b[^>]*\bsrc\s*=\s*["']([^"']*)["'][^>]*\balt\s*=\s*["']([^"']*)["'][^>]*/?\s*>"#,
        ) {
            text = re.replace_all(&text, "![$2]($1)").into_owned();
        }
        // Also handle img where alt comes before src.
        if let Ok(re) = Regex::new(
            r#"(?is)<img\b[^>]*\balt\s*=\s*["']([^"']*)["'][^>]*\bsrc\s*=\s*["']([^"']*)["'][^>]*/?\s*>"#,
        ) {
            text = re.replace_all(&text, "![$1]($2)").into_owned();
        }

        // Line breaks.
        if let Ok(re) = Regex::new(r"(?i)<br\s*/?\s*>") {
            text = re.replace_all(&text, "\n").into_owned();
        }

        // Horizontal rules.
        if let Ok(re) = Regex::new(r"(?i)<hr\s*/?\s*>") {
            text = re.replace_all(&text, "\n---\n").into_owned();
        }

        // Unordered list items.
        if let Ok(re) = Regex::new(r"(?is)<li\b[^>]*>(.*?)</li\s*>") {
            text = re
                .replace_all(&text, |caps: &regex::Captures| {
                    let content = strip_tags(&caps[1]).trim().to_string();
                    format!("- {}\n", content)
                })
                .into_owned();
        }

        // Paragraphs.
        if let Ok(re) = Regex::new(r"(?is)<p\b[^>]*>(.*?)</p\s*>") {
            text = re
                .replace_all(&text, |caps: &regex::Captures| {
                    let content = caps[1].trim();
                    format!("\n{}\n", content)
                })
                .into_owned();
        }

        // Blockquotes.
        if let Ok(re) = Regex::new(r"(?is)<blockquote\b[^>]*>(.*?)</blockquote\s*>") {
            text = re
                .replace_all(&text, |caps: &regex::Captures| {
                    let content = strip_tags(&caps[1]).trim().to_string();
                    let quoted: Vec<String> = content.lines().map(|l| format!("> {}", l)).collect();
                    format!("\n{}\n", quoted.join("\n"))
                })
                .into_owned();
        }

        // Strip remaining tags.
        text = strip_tags(&text);

        // Decode common HTML entities.
        text = text
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&nbsp;", " ");

        // Collapse excessive blank lines to at most two newlines.
        if let Ok(re) = Regex::new(r"\n{3,}") {
            text = re.replace_all(&text, "\n\n").into_owned();
        }

        text.trim().to_string()
    }
}

/// Strip all HTML tags from a string.
fn strip_tags(html: &str) -> String {
    let re = Regex::new(r"<[^>]+>").unwrap();
    re.replace_all(html, "").into_owned()
}

/// Extract the contents of the first `<title>...</title>` element.
///
/// Used as the fallback for the Markdown projection's title when the
/// rendered body has no H1. Returns `None` when no title element is
/// found or the captured text is empty after trimming.
fn extract_html_title(html: &str) -> Option<String> {
    let re = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title\s*>").ok()?;
    let caps = re.captures(html)?;
    let raw = caps.get(1)?.as_str();
    let cleaned = strip_tags(raw).trim().to_string();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Pull the first ATX or Setext H1 out of a Markdown body. Used by the
/// projection's title resolution; falls back to the source HTML's
/// `<title>` element when this returns `None`.
fn first_markdown_h1(markdown: &str) -> Option<String> {
    let mut lines = markdown.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        // ATX form: `# Heading` (one `#` only, not `##` or deeper).
        if let Some(rest) = trimmed.strip_prefix("# ") {
            let title = rest.trim().to_string();
            if !title.is_empty() {
                return Some(title);
            }
        }
        // Setext form: text on one line, `===` underline on the next.
        if let Some(next) = lines.peek() {
            let next_trimmed = next.trim();
            if !trimmed.is_empty()
                && !next_trimmed.is_empty()
                && next_trimmed.chars().all(|c| c == '=')
            {
                return Some(trimmed.trim().to_string());
            }
        }
    }
    None
}

/// Estimate token count from a Markdown body length and a per-origin ratio.
///
/// `(body.len() as f32 * ratio).round() as u32`, saturating at `u32::MAX`
/// for inputs larger than ~17 GiB at the default `0.25` ratio. Negative
/// or NaN ratios fall back to [`DEFAULT_TOKEN_BYTES_RATIO`] so a
/// misconfigured origin cannot poison the metric.
fn estimate_tokens(body: &str, ratio: f32) -> u32 {
    let safe_ratio = if ratio.is_finite() && ratio > 0.0 {
        ratio
    } else {
        DEFAULT_TOKEN_BYTES_RATIO
    };
    let estimate = (body.len() as f32 * safe_ratio).round();
    if estimate >= u32::MAX as f32 {
        u32::MAX
    } else if estimate < 0.0 {
        0
    } else {
        estimate as u32
    }
}

// --- MarkdownTransform ---

/// Converts Markdown to HTML using the `pulldown-cmark` crate.
#[derive(Debug, Deserialize, Default)]
pub struct MarkdownTransform {
    /// Enable smart punctuation (curly quotes, em-dashes, etc.).
    #[serde(default)]
    pub smart_punctuation: bool,
    /// Enable GitHub-flavored Markdown tables.
    #[serde(default)]
    pub tables: bool,
    /// Enable strikethrough syntax (`~~text~~`).
    #[serde(default)]
    pub strikethrough: bool,
}

impl MarkdownTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply Markdown-to-HTML conversion to the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let markdown = body_to_string(body)?;

        let mut options = pulldown_cmark::Options::empty();
        if self.tables {
            options.insert(pulldown_cmark::Options::ENABLE_TABLES);
        }
        if self.strikethrough {
            options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
        }
        if self.smart_punctuation {
            options.insert(pulldown_cmark::Options::ENABLE_SMART_PUNCTUATION);
        }

        let parser = pulldown_cmark::Parser::new_ext(&markdown, options);
        let mut html_output = String::new();
        pulldown_cmark::html::push_html(&mut html_output, parser);

        replace_body(body, &html_output);
        Ok(())
    }
}

// --- CssTransform ---

/// Basic CSS manipulation: inject rules, remove selectors, minify.
///
/// Uses string operations for rule injection and removal. Minification
/// strips comments and collapses whitespace. A full CSS parser (e.g.
/// lightningcss) can be added later for more advanced operations.
#[derive(Debug, Deserialize)]
pub struct CssTransform {
    /// CSS rules to append to the stylesheet.
    #[serde(default)]
    pub inject: Vec<String>,
    /// Selectors whose rule blocks should be removed.
    #[serde(default)]
    pub remove_selectors: Vec<String>,
    /// If true, minify the CSS output.
    #[serde(default)]
    pub minify: bool,
}

impl CssTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply CSS manipulation to the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let mut css = body_to_string(body)?;

        // Remove rule blocks for specified selectors.
        for selector in &self.remove_selectors {
            css = self.remove_rule(&css, selector);
        }

        // Append injected rules.
        for rule in &self.inject {
            if !css.is_empty() && !css.ends_with('\n') {
                css.push('\n');
            }
            css.push_str(rule);
            if !rule.ends_with('\n') {
                css.push('\n');
            }
        }

        // Minify if requested.
        if self.minify {
            css = minify_css(&css);
        }

        replace_body(body, &css);
        Ok(())
    }

    /// Remove a CSS rule block by selector.
    fn remove_rule(&self, css: &str, selector: &str) -> String {
        // Match the selector followed by { ... } (handles nested braces one level deep).
        let escaped = regex::escape(selector);
        let pattern = format!(r"(?s){sel}\s*\{{[^{{}}]*\}}", sel = escaped);
        if let Ok(re) = Regex::new(&pattern) {
            return re.replace_all(css, "").into_owned();
        }
        css.to_string()
    }
}

/// Basic CSS minification: remove comments, collapse whitespace, trim.
fn minify_css(css: &str) -> String {
    let mut result = css.to_string();

    // Remove CSS comments.
    if let Ok(re) = Regex::new(r"(?s)/\*.*?\*/") {
        result = re.replace_all(&result, "").into_owned();
    }

    // Collapse whitespace around braces, colons, semicolons.
    if let Ok(re) = Regex::new(r"\s*\{\s*") {
        result = re.replace_all(&result, "{").into_owned();
    }
    if let Ok(re) = Regex::new(r"\s*\}\s*") {
        result = re.replace_all(&result, "}").into_owned();
    }
    if let Ok(re) = Regex::new(r"\s*:\s*") {
        result = re.replace_all(&result, ":").into_owned();
    }
    if let Ok(re) = Regex::new(r"\s*;\s*") {
        result = re.replace_all(&result, ";").into_owned();
    }

    // Collapse remaining runs of whitespace.
    if let Ok(re) = Regex::new(r"\s+") {
        result = re.replace_all(&result, " ").into_owned();
    }

    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- HtmlTransform tests ---

    #[test]
    fn html_from_config() {
        let config = serde_json::json!({
            "remove_selectors": ["script"],
            "inject": [{"position": "body_end", "content": "<p>footer</p>"}],
            "rewrite_attributes": [{"selector": "a", "attribute": "target", "value": "_blank"}]
        });
        let t = HtmlTransform::from_config(config).unwrap();
        assert_eq!(t.remove_selectors, vec!["script"]);
        assert_eq!(t.inject.len(), 1);
        assert_eq!(t.rewrite_attributes.len(), 1);
    }

    #[test]
    fn html_remove_script_tags() {
        let t = HtmlTransform {
            remove_selectors: vec!["script".into()],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: None,
        };
        let mut body = BytesMut::from(
            &b"<html><head><script>alert('x')</script></head><body>hello</body></html>"[..],
        );
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("script"));
        assert!(result.contains("hello"));
    }

    #[test]
    fn html_remove_by_id() {
        let t = HtmlTransform {
            remove_selectors: vec!["#banner".into()],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: None,
        };
        let mut body = BytesMut::from(&b"<div id=\"banner\">ad here</div><div>content</div>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("banner"));
        assert!(result.contains("content"));
    }

    #[test]
    fn html_inject_body_end() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![HtmlInjection {
                position: "body_end".into(),
                content: "<script>analytics()</script>".into(),
            }],
            rewrite_attributes: vec![],
            format_options: None,
        };
        let mut body = BytesMut::from(&b"<html><body><p>hello</p></body></html>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("<script>analytics()</script></body>"));
    }

    #[test]
    fn html_inject_head_end() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![HtmlInjection {
                position: "head_end".into(),
                content: "<link rel=\"stylesheet\" href=\"/style.css\">".into(),
            }],
            rewrite_attributes: vec![],
            format_options: None,
        };
        let mut body =
            BytesMut::from(&b"<html><head><title>Test</title></head><body></body></html>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains(r#"style.css"></head>"#));
    }

    #[test]
    fn html_inject_body_start() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![HtmlInjection {
                position: "body_start".into(),
                content: "<nav>menu</nav>".into(),
            }],
            rewrite_attributes: vec![],
            format_options: None,
        };
        let mut body = BytesMut::from(&b"<html><body><p>content</p></body></html>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("<body><nav>menu</nav><p>content</p>"));
    }

    #[test]
    fn html_rewrite_attribute() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![],
            rewrite_attributes: vec![AttributeRewrite {
                selector: "a".into(),
                attribute: "target".into(),
                value: "_blank".into(),
            }],
            format_options: None,
        };
        let mut body = BytesMut::from(&b"<a href=\"/page\" target=\"_self\">link</a>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains(r#"target="_blank""#));
        assert!(!result.contains("_self"));
    }

    #[test]
    fn html_empty_body() {
        let t = HtmlTransform {
            remove_selectors: vec!["div".into()],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: None,
        };
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    // --- OptimizeHtmlTransform tests ---

    #[test]
    fn optimize_html_from_config() {
        let config = serde_json::json!({});
        let t = OptimizeHtmlTransform::from_config(config).unwrap();
        // Defaults should be true for remove_comments and collapse_whitespace.
        assert!(t.remove_comments);
        assert!(t.collapse_whitespace);
        assert!(!t.remove_optional_tags);
    }

    #[test]
    fn optimize_html_remove_comments() {
        let t = OptimizeHtmlTransform {
            remove_comments: true,
            collapse_whitespace: false,
            remove_optional_tags: false,
        };
        let mut body = BytesMut::from(&b"<p>hello</p><!-- this is a comment --><p>world</p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("<!--"));
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }

    #[test]
    fn optimize_html_collapse_whitespace() {
        let t = OptimizeHtmlTransform {
            remove_comments: false,
            collapse_whitespace: true,
            remove_optional_tags: false,
        };
        let mut body = BytesMut::from(&b"<p>  hello   world  </p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        // Whitespace should be collapsed.
        assert!(result.contains("<p> hello world </p>"));
    }

    #[test]
    fn optimize_html_preserves_pre() {
        let t = OptimizeHtmlTransform {
            remove_comments: false,
            collapse_whitespace: true,
            remove_optional_tags: false,
        };
        let mut body =
            BytesMut::from(&b"<p>  a  b  </p><pre>  keep   spaces  </pre><p>  c  d  </p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("<pre>  keep   spaces  </pre>"));
    }

    #[test]
    fn optimize_html_remove_optional_tags() {
        let t = OptimizeHtmlTransform {
            remove_comments: false,
            collapse_whitespace: false,
            remove_optional_tags: true,
        };
        let mut body = BytesMut::from(&b"<ul><li>one</li><li>two</li></ul>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("</li>"));
        assert!(result.contains("<li>one"));
    }

    #[test]
    fn optimize_html_multiline_comment() {
        let t = OptimizeHtmlTransform {
            remove_comments: true,
            collapse_whitespace: false,
            remove_optional_tags: false,
        };
        let mut body =
            BytesMut::from(&b"<p>before</p><!--\n  multi\n  line\n  comment\n--><p>after</p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("<!--"));
        assert!(result.contains("before"));
        assert!(result.contains("after"));
    }

    // --- HtmlToMarkdownTransform tests ---

    #[test]
    fn html_to_markdown_from_config() {
        let config = serde_json::json!({"heading_style": "setext"});
        let t = HtmlToMarkdownTransform::from_config(config).unwrap();
        assert_eq!(t.heading_style.as_deref(), Some("setext"));
    }

    #[test]
    fn html_to_markdown_headings_atx() {
        let t = HtmlToMarkdownTransform::default();
        let mut body = BytesMut::from(&b"<h1>Title</h1><h2>Subtitle</h2><h3>Section</h3>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("# Title"));
        assert!(result.contains("## Subtitle"));
        assert!(result.contains("### Section"));
    }

    #[test]
    fn html_to_markdown_headings_setext() {
        let t = HtmlToMarkdownTransform {
            heading_style: Some("setext".into()),
            token_bytes_ratio: DEFAULT_TOKEN_BYTES_RATIO,
        };
        let mut body = BytesMut::from(&b"<h1>Title</h1><h2>Subtitle</h2>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("Title\n====="));
        assert!(result.contains("Subtitle\n--------"));
    }

    #[test]
    fn html_to_markdown_links_and_bold() {
        let t = HtmlToMarkdownTransform::default();
        let mut body = BytesMut::from(
            &b"<p>Click <a href=\"https://example.com\">here</a> for <strong>info</strong>.</p>"[..],
        );
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("[here](https://example.com)"));
        assert!(result.contains("**info**"));
    }

    #[test]
    fn html_to_markdown_code_and_em() {
        let t = HtmlToMarkdownTransform::default();
        let mut body =
            BytesMut::from(&b"<p>Use <code>fmt.Println</code> and <em>test</em>.</p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("`fmt.Println`"));
        assert!(result.contains("*test*"));
    }

    #[test]
    fn html_to_markdown_strips_scripts() {
        let t = HtmlToMarkdownTransform::default();
        let mut body = BytesMut::from(&b"<p>hello</p><script>evil()</script><p>world</p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("evil"));
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }

    #[test]
    fn html_to_markdown_entities() {
        let t = HtmlToMarkdownTransform::default();
        let mut body = BytesMut::from(&b"<p>A &amp; B &lt; C &gt; D</p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("A & B < C > D"));
    }

    // --- MarkdownProjection tests (G4.3) ---

    #[test]
    fn projection_title_from_h1_heading() {
        let t = HtmlToMarkdownTransform::default();
        let proj = t.project("<html><head><title>Page Title</title></head><body><h1>Article H1</h1><p>Body text.</p></body></html>");
        // H1 wins over <title>.
        assert_eq!(proj.title.as_deref(), Some("Article H1"));
        assert!(proj.body.contains("# Article H1"));
        assert!(proj.body.contains("Body text."));
    }

    #[test]
    fn projection_title_falls_back_to_html_title() {
        let t = HtmlToMarkdownTransform::default();
        let proj = t.project("<html><head><title>Fallback Title</title></head><body><p>No H1 here.</p></body></html>");
        assert_eq!(proj.title.as_deref(), Some("Fallback Title"));
    }

    #[test]
    fn projection_title_none_when_no_h1_or_title() {
        let t = HtmlToMarkdownTransform::default();
        let proj = t.project("<html><body><p>Just body content.</p></body></html>");
        assert!(proj.title.is_none());
    }

    #[test]
    fn projection_title_setext_h1_recognised() {
        let t = HtmlToMarkdownTransform {
            heading_style: Some("setext".into()),
            token_bytes_ratio: DEFAULT_TOKEN_BYTES_RATIO,
        };
        let proj = t.project("<h1>Setext Form</h1><p>body</p>");
        assert_eq!(proj.title.as_deref(), Some("Setext Form"));
    }

    #[test]
    fn projection_token_estimate_default_ratio() {
        let t = HtmlToMarkdownTransform::default();
        // Body length is deterministic; pick something where we can
        // sanity-check the estimate.
        let proj = t.project("<p>aaaaaaaaaaaaaaaa</p>"); // 16 'a's after stripping.
                                                         // Output Markdown is roughly the same length (paragraph wrapping
                                                         // adds whitespace). Estimate must be a small positive number.
        assert!(proj.token_estimate > 0);
        // Sanity: roughly body.len() * 0.25.
        let expected = (proj.body.len() as f32 * 0.25).round() as u32;
        assert_eq!(proj.token_estimate, expected);
    }

    #[test]
    fn projection_token_estimate_overridden_ratio() {
        let t = HtmlToMarkdownTransform {
            heading_style: None,
            token_bytes_ratio: 0.5,
        };
        let proj = t.project("<p>hello world</p>");
        let expected = (proj.body.len() as f32 * 0.5).round() as u32;
        assert_eq!(proj.token_estimate, expected);
    }

    #[test]
    fn projection_token_estimate_invalid_ratio_uses_default() {
        let t = HtmlToMarkdownTransform {
            heading_style: None,
            token_bytes_ratio: f32::NAN,
        };
        let proj = t.project("<p>hello world</p>");
        // Falls back to the default 0.25 ratio.
        let expected = (proj.body.len() as f32 * DEFAULT_TOKEN_BYTES_RATIO).round() as u32;
        assert_eq!(proj.token_estimate, expected);
    }

    #[test]
    fn projection_default_token_bytes_ratio() {
        let t = HtmlToMarkdownTransform::default();
        assert!((t.token_bytes_ratio - DEFAULT_TOKEN_BYTES_RATIO).abs() < f32::EPSILON);
    }

    #[test]
    fn projection_apply_writes_body_only() {
        // The Transform::apply path stays byte-compatible: body buffer
        // contains exactly the rendered Markdown, no envelope.
        let t = HtmlToMarkdownTransform::default();
        let mut body = BytesMut::from(&b"<h1>Hi</h1><p>Hello.</p>"[..]);
        t.apply(&mut body).unwrap();
        let written = std::str::from_utf8(&body).unwrap();
        assert!(written.contains("# Hi"));
        assert!(written.contains("Hello."));
    }

    #[test]
    fn projection_title_skips_empty_html_title() {
        let t = HtmlToMarkdownTransform::default();
        let proj = t.project("<html><head><title>   </title></head><body><p>x</p></body></html>");
        assert!(proj.title.is_none());
    }

    // --- MarkdownTransform tests ---

    #[test]
    fn markdown_from_config() {
        let config = serde_json::json!({
            "tables": true,
            "strikethrough": true,
            "smart_punctuation": false
        });
        let t = MarkdownTransform::from_config(config).unwrap();
        assert!(t.tables);
        assert!(t.strikethrough);
        assert!(!t.smart_punctuation);
    }

    #[test]
    fn markdown_basic_conversion() {
        let t = MarkdownTransform::default();
        let mut body = BytesMut::from(&b"# Hello\n\nThis is **bold** and *italic*."[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("<h1>Hello</h1>"));
        assert!(result.contains("<strong>bold</strong>"));
        assert!(result.contains("<em>italic</em>"));
    }

    #[test]
    fn markdown_with_link() {
        let t = MarkdownTransform::default();
        let mut body = BytesMut::from(&b"Visit [example](https://example.com)."[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains(r#"<a href="https://example.com">example</a>"#));
    }

    #[test]
    fn markdown_with_tables() {
        let t = MarkdownTransform {
            tables: true,
            ..Default::default()
        };
        let md = "| A | B |\n|---|---|\n| 1 | 2 |\n";
        let mut body = BytesMut::from(md.as_bytes());
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("<table>"));
        assert!(result.contains("<td>1</td>"));
    }

    #[test]
    fn markdown_with_strikethrough() {
        let t = MarkdownTransform {
            strikethrough: true,
            ..Default::default()
        };
        let mut body = BytesMut::from(&b"This is ~~deleted~~ text."[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("<del>deleted</del>"));
    }

    #[test]
    fn markdown_empty_body() {
        let t = MarkdownTransform::default();
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    // --- CssTransform tests ---

    #[test]
    fn css_from_config() {
        let config = serde_json::json!({
            "inject": ["body { margin: 0; }"],
            "remove_selectors": [".ad"],
            "minify": true
        });
        let t = CssTransform::from_config(config).unwrap();
        assert_eq!(t.inject, vec!["body { margin: 0; }"]);
        assert_eq!(t.remove_selectors, vec![".ad"]);
        assert!(t.minify);
    }

    #[test]
    fn css_inject_rules() {
        let t = CssTransform {
            inject: vec!["body { margin: 0; }".into(), "p { color: red; }".into()],
            remove_selectors: vec![],
            minify: false,
        };
        let mut body = BytesMut::from(&b"h1 { font-size: 2em; }"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("h1 { font-size: 2em; }"));
        assert!(result.contains("body { margin: 0; }"));
        assert!(result.contains("p { color: red; }"));
    }

    #[test]
    fn css_remove_selectors() {
        let t = CssTransform {
            inject: vec![],
            remove_selectors: vec![".ad".into()],
            minify: false,
        };
        let mut body =
            BytesMut::from(&b"h1 { color: blue; }\n.ad { display: block; }\np { margin: 0; }"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains(".ad"));
        assert!(result.contains("h1"));
        assert!(result.contains("p { margin: 0; }"));
    }

    #[test]
    fn css_minify() {
        let t = CssTransform {
            inject: vec![],
            remove_selectors: vec![],
            minify: true,
        };
        let mut body =
            BytesMut::from(&b"/* comment */\nh1 {\n  color: blue;\n  font-size: 2em;\n}\n"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("/* comment */"));
        assert!(!result.contains('\n'));
        assert!(result.contains("color:blue"));
    }

    #[test]
    fn css_empty_body() {
        let t = CssTransform {
            inject: vec!["body { margin: 0; }".into()],
            remove_selectors: vec![],
            minify: false,
        };
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("body { margin: 0; }"));
    }

    #[test]
    fn css_minify_removes_comments() {
        let css =
            "/* header styles */\nh1 { color: red; }\n/* footer */\n.footer { padding: 10px; }";
        let result = minify_css(css);
        assert!(!result.contains("header styles"));
        assert!(!result.contains("footer */"));
    }

    // --- HtmlTransform format_options tests ---

    #[test]
    fn html_format_options_strip_comments() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: Some(HtmlFormatOptions {
                strip_comments: true,
                strip_newlines: false,
                strip_space: false,
                lowercase_tags: false,
            }),
        };
        let mut body = BytesMut::from(&b"<p>hello</p><!-- this is a comment --><p>world</p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("<!--"), "comment should be stripped");
        assert!(result.contains("<p>hello</p>"));
        assert!(result.contains("<p>world</p>"));
    }

    #[test]
    fn html_format_options_strip_multiline_comments() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: Some(HtmlFormatOptions {
                strip_comments: true,
                strip_newlines: false,
                strip_space: false,
                lowercase_tags: false,
            }),
        };
        let mut body =
            BytesMut::from(&b"<p>before</p><!--\n  multi\n  line\n  comment\n--><p>after</p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("<!--"));
        assert!(result.contains("<p>before</p><p>after</p>"));
    }

    #[test]
    fn html_format_options_strip_space() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: Some(HtmlFormatOptions {
                strip_comments: false,
                strip_newlines: false,
                strip_space: true,
                lowercase_tags: false,
            }),
        };
        let mut body = BytesMut::from(&b"<p>  hello   world  </p>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("<p> hello world </p>"));
    }

    #[test]
    fn html_format_options_lowercase_tags() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: Some(HtmlFormatOptions {
                strip_comments: false,
                strip_newlines: false,
                strip_space: false,
                lowercase_tags: true,
            }),
        };
        let mut body = BytesMut::from(&b"<DIV><P>hello</P></DIV>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(
            result.contains("<div>"),
            "DIV should be lowercase: {}",
            result
        );
        assert!(result.contains("<p>"), "P should be lowercase: {}", result);
        assert!(
            result.contains("</p>"),
            "closing P should be lowercase: {}",
            result
        );
        assert!(
            result.contains("</div>"),
            "closing DIV should be lowercase: {}",
            result
        );
    }

    #[test]
    fn html_format_options_all_combined() {
        let t = HtmlTransform {
            remove_selectors: vec![],
            inject: vec![],
            rewrite_attributes: vec![],
            format_options: Some(HtmlFormatOptions {
                strip_comments: true,
                strip_newlines: true,
                strip_space: true,
                lowercase_tags: true,
            }),
        };
        let mut body =
            BytesMut::from(&b"<DIV>\n  <!-- comment -->\n  <P>  hello  </P>\n</DIV>"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(!result.contains("<!--"), "comment stripped");
        assert!(result.contains("<div>"), "lowercase tags");
        assert!(result.contains("hello"), "content preserved");
    }
}
