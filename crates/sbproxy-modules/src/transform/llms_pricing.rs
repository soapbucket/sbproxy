//! WOR-188: parser for the priced-route flavour of `llms.txt`.
//!
//! This module is the input dual of
//! [`crate::projections::llms::render`]: it takes the bytes that
//! `render` emits and decodes them back into a structured
//! [`LlmsTxt`]. The pre-flight policy in
//! [`crate::policy::peer_pricing_preflight`] uses this parser to read
//! the `llms.txt` document a peer publishes, match the outbound
//! request path against the priced-route list, and decide whether the
//! call fits the configured budget.
//!
//! The on-the-wire shape this parser accepts is the YAML-like header
//! block followed by a Markdown body emitted by
//! `projections::llms::render`:
//!
//! ```text
//! # sitename: shop.example.com
//! # version: 42
//! # payment: pay-per-request
//! # shapes: html,markdown
//!
//! # shop.example.com
//!
//! ## Priced routes
//!
//! - `/articles/*` - agent `GPTBot`, shape `html`, price 0.002000 USD (free preview: 256 bytes)
//! - `/api/*` - agent `*`, shape `json`, price 0.000500 USD
//! ```
//!
//! Parsing is lenient: unknown header lines are ignored, blank lines
//! are skipped, and badly shaped bullet lines are dropped rather than
//! raising. The only hard error is non-UTF-8 input.
//!
//! ## Round-trip with `projections::llms::render`
//!
//! `render` produces the bytes that `parse` consumes. The
//! `round_trip_render_into_parse` unit test pins the contract that the
//! parser recovers the route list `render` emitted for a given
//! `ai_crawl_control` configuration.
//!
//! ## Fuzzing contract
//!
//! `parse` must never panic on arbitrary bytes. The
//! `parse_never_panics_on_arbitrary_input` property test in this file
//! drives ~256 KiB of random bytes through the parser; a future
//! cargo-fuzz target can do the same in a long-running harness.

use std::fmt;

use crate::policy::ContentShape;

/// A parsed `llms.txt` document in the priced-route flavour produced
/// by [`crate::projections::llms::render`].
///
/// Every field is optional in the sense that the parser tolerates
/// documents that omit individual lines. A document with no
/// `# payment:` header still parses; the corresponding
/// [`Payment`] is then [`Payment::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmsTxt {
    /// `# sitename:` header value, if present.
    pub sitename: Option<String>,
    /// `# version:` header value, if present. Carried as a string so
    /// the parser does not have to commit to a numeric type; the
    /// renderer emits the config version hash as a decimal integer.
    pub version: Option<String>,
    /// `# payment:` header value, decoded into a typed
    /// [`Payment`]. [`Payment::Unknown`] is the parsed shape for
    /// documents that simply do not carry the line.
    pub payment: Payment,
    /// `# shapes:` header value, decoded into the set of advertised
    /// shapes in declaration order. Empty when the line is absent.
    pub shapes: Vec<ContentShape>,
    /// One entry per `- ...` line under `## Priced routes`, in
    /// document order. The pre-flight policy iterates this list
    /// looking for a route pattern that matches the outbound request
    /// path.
    pub routes: Vec<PricedRoute>,
}

/// Payment summary from the `# payment:` header line.
///
/// `render` emits one of three shapes:
///
/// - `# payment: free` -> [`Payment::Free`]
/// - `# payment: 0.005000 EUR` -> [`Payment::Flat`] (top-level price)
/// - `# payment: pay-per-request` -> [`Payment::PayPerRequest`]
///   (tiered pricing follows in the route list)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Payment {
    /// The header line was absent (the parser saw no `# payment:`).
    #[default]
    Unknown,
    /// `# payment: free`.
    Free,
    /// `# payment: <amount> <currency>`. Amount is carried in micros
    /// (1e-6 of `currency`) so the parser never relies on `f64`
    /// equality.
    Flat {
        /// Price in micros of `currency`.
        price_micros: u64,
        /// ISO-4217 currency code, e.g. `USD`.
        currency: String,
    },
    /// `# payment: pay-per-request`. The actual per-route prices live
    /// in [`LlmsTxt::routes`].
    PayPerRequest,
}

/// A single priced-route line under `## Priced routes`.
///
/// Mirrors the per-tier output shape of
/// [`crate::projections::llms::render`]; the field names are chosen
/// to line up with [`crate::policy::Tier`] so the pre-flight policy
/// can compare matched routes against the operator's budget without a
/// translation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedRoute {
    /// Path matcher copied from the renderer. Supports literal paths
    /// and a trailing `*` suffix wildcard.
    pub route_pattern: String,
    /// `agent_id` filter, or `None` if the rendered bullet used the
    /// wildcard form (`agent `*``).
    pub agent_id: Option<String>,
    /// Content shape the priced route applies to.
    pub shape: ContentShape,
    /// Price in micros of `currency`.
    pub price_micros: u64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Free preview byte budget if the renderer emitted the
    /// `(free preview: N bytes)` suffix.
    pub free_preview_bytes: Option<u64>,
}

/// Errors surfaced by [`parse`].
///
/// The parser intentionally tolerates every shape of malformed line
/// short of non-UTF-8 input; bullet lines that the parser cannot
/// decode are skipped rather than rejected. This keeps the fuzz
/// contract simple: `parse(bytes)` either returns `Ok(LlmsTxt)` or
/// `Err(ParseError::NotUtf8)` for any byte sequence, and never panics.
#[derive(Debug)]
pub enum ParseError {
    /// The input was not valid UTF-8.
    NotUtf8(std::str::Utf8Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::NotUtf8(e) => write!(f, "llms.txt input is not valid UTF-8: {e}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::NotUtf8(e) => Some(e),
        }
    }
}

impl From<std::str::Utf8Error> for ParseError {
    fn from(e: std::str::Utf8Error) -> Self {
        ParseError::NotUtf8(e)
    }
}

/// Parse a `llms.txt` document in the priced-route flavour into
/// a [`LlmsTxt`].
///
/// Bullet lines whose shape the parser cannot decode are dropped
/// without raising; the only error path is non-UTF-8 input. See the
/// module-level doc for the supported on-the-wire shape.
pub fn parse(bytes: &[u8]) -> Result<LlmsTxt, ParseError> {
    let text = std::str::from_utf8(bytes)?;
    Ok(parse_str(text))
}

/// Internal entry point used by both [`parse`] and the unit tests so
/// the public API can stay byte-shaped without forcing callers to
/// build a `&[u8]` for round-trip tests.
fn parse_str(text: &str) -> LlmsTxt {
    let mut out = LlmsTxt {
        sitename: None,
        version: None,
        payment: Payment::Unknown,
        shapes: Vec::new(),
        routes: Vec::new(),
    };

    let mut in_routes_section = false;
    for raw in text.lines() {
        let line = raw.trim_end();

        // Section selector: `## Priced routes` flips the bullet
        // parser on. Any other `## ...` heading turns it off.
        if let Some(rest) = line.strip_prefix("## ") {
            in_routes_section = rest.trim().eq_ignore_ascii_case("priced routes");
            continue;
        }

        if let Some(rest) = line.strip_prefix("# ") {
            // Header lines all live at the very top of the document
            // but we accept them anywhere to stay lenient on the
            // fuzz surface.
            parse_header_line(rest, &mut out);
            continue;
        }

        if in_routes_section {
            if let Some(stripped) = line.strip_prefix("- ") {
                if let Some(route) = parse_route_bullet(stripped) {
                    out.routes.push(route);
                }
            }
        }
    }

    out
}

/// Decode a single header line (everything after `# `).
///
/// Unknown header keys are ignored. The line is `key: value`; missing
/// `:` is treated as a no-op.
fn parse_header_line(rest: &str, out: &mut LlmsTxt) {
    let Some((key, value)) = rest.split_once(':') else {
        return;
    };
    let key = key.trim().to_ascii_lowercase();
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    match key.as_str() {
        "sitename" => out.sitename = Some(value.to_string()),
        "version" => out.version = Some(value.to_string()),
        "payment" => out.payment = parse_payment(value),
        "shapes" => out.shapes = parse_shapes(value),
        _ => {}
    }
}

/// Decode the `# payment:` value.
fn parse_payment(value: &str) -> Payment {
    let v = value.trim();
    if v.eq_ignore_ascii_case("free") {
        return Payment::Free;
    }
    if v.eq_ignore_ascii_case("pay-per-request") {
        return Payment::PayPerRequest;
    }
    // Flat form: `<amount> <currency>` where amount is a decimal in
    // major units. The renderer emits `0.005000 EUR`-shaped values.
    let mut parts = v.split_whitespace();
    if let (Some(amount), Some(currency)) = (parts.next(), parts.next()) {
        if let Some(micros) = parse_micros_from_units(amount) {
            return Payment::Flat {
                price_micros: micros,
                currency: currency.to_string(),
            };
        }
    }
    Payment::Unknown
}

/// Decode the `# shapes:` value. Tokens that don't match a known
/// [`ContentShape`] string drop without erroring so the parser stays
/// lenient.
fn parse_shapes(value: &str) -> Vec<ContentShape> {
    value
        .split(',')
        .filter_map(|s| match s.trim() {
            "html" => Some(ContentShape::Html),
            "markdown" => Some(ContentShape::Markdown),
            "json" => Some(ContentShape::Json),
            "pdf" => Some(ContentShape::Pdf),
            "other" => Some(ContentShape::Other),
            _ => None,
        })
        .collect()
}

/// Decode one `- ` bullet line under `## Priced routes`.
///
/// Returns `None` for a line that does not match the renderer's shape
/// so the parser stays lenient against arbitrary bytes.
fn parse_route_bullet(line: &str) -> Option<PricedRoute> {
    // Shape: `` `/articles/*` - agent `GPTBot`, shape `html`, price 0.002000 USD (free preview: 256 bytes) ``
    let route_pattern = extract_backticked(line, 0)?.to_string();
    let after_pattern = position_after_nth_backtick(line, 2)?;
    let tail = line[after_pattern..].trim_start_matches([' ', '-']);

    // Pull the three labelled fields. Each is `label `value``.
    let agent = extract_labelled(tail, "agent")?;
    let shape_str = extract_labelled(tail, "shape")?;

    // Price: `price <amount> <currency>` (no backticks).
    let price_segment = find_segment(tail, "price ")?;
    let after_price = &tail[price_segment + "price ".len()..];
    let mut price_parts = after_price.split_whitespace();
    let amount = price_parts.next()?;
    let currency = price_parts.next()?;
    let price_micros = parse_micros_from_units(amount)?;
    let currency = currency.trim_end_matches(',').to_string();

    // Optional `(free preview: N bytes)` suffix.
    let free_preview_bytes = if let Some(idx) = tail.find("(free preview:") {
        let rest = &tail[idx + "(free preview:".len()..];
        rest.split_whitespace()
            .next()
            .and_then(|n| n.parse::<u64>().ok())
    } else {
        None
    };

    let agent_id = if agent == "*" {
        None
    } else {
        Some(agent.to_string())
    };

    Some(PricedRoute {
        route_pattern,
        agent_id,
        shape: parse_content_shape(shape_str),
        price_micros,
        currency,
        free_preview_bytes,
    })
}

/// Map a shape token to [`ContentShape`], defaulting to
/// [`ContentShape::Other`] for unrecognised values so the parser
/// stays lenient.
fn parse_content_shape(s: &str) -> ContentShape {
    match s {
        "html" => ContentShape::Html,
        "markdown" => ContentShape::Markdown,
        "json" => ContentShape::Json,
        "pdf" => ContentShape::Pdf,
        _ => ContentShape::Other,
    }
}

/// Find `label `value`` inside a string and return `value`.
fn extract_labelled<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let idx = text.find(label)?;
    let after = &text[idx + label.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix('`')?;
    let end = after.find('`')?;
    Some(&after[..end])
}

/// Return the substring inside the `n`th pair of backticks (0-indexed).
fn extract_backticked(text: &str, n: usize) -> Option<&str> {
    let mut cursor = 0usize;
    let mut pair = 0usize;
    while cursor < text.len() {
        let rest = &text[cursor..];
        let open = rest.find('`')?;
        let after_open = cursor + open + 1;
        if after_open > text.len() {
            return None;
        }
        let close_rel = text[after_open..].find('`')?;
        let close = after_open + close_rel;
        if pair == n {
            return Some(&text[after_open..close]);
        }
        pair += 1;
        cursor = close + 1;
    }
    None
}

/// Return the byte offset directly after the `n`th backtick (1-indexed).
fn position_after_nth_backtick(text: &str, n: usize) -> Option<usize> {
    let mut count = 0usize;
    for (i, b) in text.bytes().enumerate() {
        if b == b'`' {
            count += 1;
            if count == n {
                return Some(i + 1);
            }
        }
    }
    None
}

/// Locate the first occurrence of `needle` in `haystack`. Tiny
/// wrapper kept for readability at the call site.
fn find_segment(haystack: &str, needle: &str) -> Option<usize> {
    haystack.find(needle)
}

/// Parse a decimal amount string (e.g. `0.002000`) into micros.
///
/// Returns `None` for negative amounts, non-numeric text, or amounts
/// that overflow `u64` after scaling. Used by both the header and the
/// bullet parser so the wire form stays consistent.
fn parse_micros_from_units(amount: &str) -> Option<u64> {
    let s = amount.trim();
    if s.is_empty() {
        return None;
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let int: u64 = int_part.parse().ok()?;
    let int_micros = int.checked_mul(1_000_000)?;
    let frac_micros: u64 = if frac_part.is_empty() {
        0
    } else {
        // Truncate / pad to six fractional digits so `0.5` and
        // `0.500000` both come back as 500_000.
        let mut padded = String::from(frac_part);
        if padded.len() < 6 {
            padded.extend(std::iter::repeat_n('0', 6 - padded.len()));
        } else {
            padded.truncate(6);
        }
        padded.parse().ok()?
    };
    int_micros.checked_add(frac_micros)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projections::llms::render;
    use proptest::prelude::*;

    /// `parse` accepts the bytes `projections::llms::render` emits and
    /// recovers every priced route.
    #[test]
    fn round_trip_render_into_parse() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [
                {
                    "route_pattern": "/articles/*",
                    "price": {"amount_micros": 2000, "currency": "USD"},
                    "agent_id": "GPTBot",
                    "content_shape": "html",
                    "free_preview_bytes": 256,
                },
                {
                    "route_pattern": "/api/*",
                    "price": {"amount_micros": 500, "currency": "USD"},
                    "content_shape": "json",
                },
            ],
        });
        let (_summary, full) = render("shop.example.com", &cfg, 42);
        let parsed = parse(full.as_bytes()).expect("parse must accept rendered output");

        assert_eq!(parsed.sitename.as_deref(), Some("shop.example.com"));
        assert_eq!(parsed.version.as_deref(), Some("42"));
        assert_eq!(parsed.payment, Payment::PayPerRequest);
        assert!(parsed.shapes.contains(&ContentShape::Html));
        assert!(parsed.shapes.contains(&ContentShape::Json));

        assert_eq!(parsed.routes.len(), 2);
        let first = &parsed.routes[0];
        assert_eq!(first.route_pattern, "/articles/*");
        assert_eq!(first.agent_id.as_deref(), Some("GPTBot"));
        assert_eq!(first.shape, ContentShape::Html);
        assert_eq!(first.price_micros, 2000);
        assert_eq!(first.currency, "USD");
        assert_eq!(first.free_preview_bytes, Some(256));

        let second = &parsed.routes[1];
        assert_eq!(second.route_pattern, "/api/*");
        assert!(second.agent_id.is_none());
        assert_eq!(second.shape, ContentShape::Json);
        assert_eq!(second.price_micros, 500);
        assert_eq!(second.currency, "USD");
        assert!(second.free_preview_bytes.is_none());
    }

    #[test]
    fn parse_flat_payment_header() {
        let doc = "# sitename: example.com\n# payment: 0.005000 EUR\n";
        let parsed = parse(doc.as_bytes()).unwrap();
        assert_eq!(
            parsed.payment,
            Payment::Flat {
                price_micros: 5000,
                currency: "EUR".to_string()
            }
        );
    }

    #[test]
    fn parse_free_payment_header() {
        let doc = "# payment: free\n";
        let parsed = parse(doc.as_bytes()).unwrap();
        assert_eq!(parsed.payment, Payment::Free);
    }

    #[test]
    fn parse_missing_payment_is_unknown() {
        let doc = "# sitename: x\n";
        let parsed = parse(doc.as_bytes()).unwrap();
        assert_eq!(parsed.payment, Payment::Unknown);
    }

    #[test]
    fn parse_ignores_unknown_header_keys() {
        let doc = "# sitename: x\n# whatever: please-ignore\n";
        let parsed = parse(doc.as_bytes()).unwrap();
        assert_eq!(parsed.sitename.as_deref(), Some("x"));
    }

    #[test]
    fn parse_ignores_malformed_bullet_lines() {
        let doc = "## Priced routes\n- not a real bullet\n- ` /broken\n";
        let parsed = parse(doc.as_bytes()).unwrap();
        assert!(parsed.routes.is_empty());
    }

    #[test]
    fn parse_non_utf8_input_errors() {
        let bytes = [0xFFu8, 0xFE, 0xFD];
        assert!(matches!(parse(&bytes), Err(ParseError::NotUtf8(_))));
    }

    #[test]
    fn parse_micros_handles_short_and_long_fractions() {
        assert_eq!(parse_micros_from_units("0.5"), Some(500_000));
        assert_eq!(parse_micros_from_units("0.500000"), Some(500_000));
        // Trailing digits beyond six are truncated.
        assert_eq!(parse_micros_from_units("0.0000001"), Some(0));
        assert_eq!(parse_micros_from_units("1"), Some(1_000_000));
    }

    #[test]
    fn parse_micros_rejects_negatives_and_non_numeric() {
        assert_eq!(parse_micros_from_units("-1.0"), None);
        assert_eq!(parse_micros_from_units("abc"), None);
        assert_eq!(parse_micros_from_units(""), None);
    }

    proptest! {
        /// Arbitrary bytes must never panic the parser and must
        /// either succeed or surface `NotUtf8`. No third state is
        /// allowed.
        #[test]
        fn parse_never_panics_on_arbitrary_input(input in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = parse(&input);
        }

        /// Arbitrary UTF-8 strings must produce `Ok(LlmsTxt)`; the
        /// only error path is non-UTF-8 input.
        #[test]
        fn parse_ok_on_arbitrary_utf8(input in ".{0,2048}") {
            let bytes = input.as_bytes();
            let parsed = parse(bytes).unwrap();
            // No assertions on the shape: arbitrary text should
            // collapse to mostly-empty `LlmsTxt`. The point of the
            // test is the absence of panics.
            let _ = parsed;
        }
    }
}
