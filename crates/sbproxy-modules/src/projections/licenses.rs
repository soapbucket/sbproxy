//! G4.7: `/licenses.xml` projection per RSL 1.0.
//!
//! One `<license>` element per origin-level `Content-Signal` value.
//! The URN is `urn:rsl:1.0:<origin_hostname>:<config_version_hash>`.
//!
//! Mapping table from `docs/adr-policy-graph-projections.md`:
//!
//! | `Content-Signal` value | RSL `<ai-use>` assertion |
//! |---|---|
//! | `ai-train` | `<ai-use type="training" licensed="true" />` |
//! | `ai-input` | `<ai-use type="inference" licensed="true" />` |
//! | `search` | `<ai-use type="search-index" licensed="true" />` |
//! | absent | `<ai-use type="training" licensed="false" />` |
//!
//! ## Internal contract: `RequestContext.rsl_urn`
//!
//! The data-plane handler that serves this projection stamps the URN
//! returned by `render` onto `RequestContext.rsl_urn` so the Wave 4
//! JSON envelope (rust-A's G4.4) can read it for the `license` field
//! without re-parsing the projection body. Any caller that wants to
//! emit an RSL-aware response on the same hostname should consult
//! `current_projections().rsl_urns` for the URN; the URN equals
//! `urn:rsl:1.0:<hostname>:<config_version>` so it is also derivable
//! without the cache when needed.

/// Render `(licenses_xml, urn)` for a single origin.
///
/// `content_signal` is the parsed value of the origin's
/// `extensions["content_signal"]` slot (None when absent). Returns the
/// canonical RSL 1.0 document and the URN that identifies it; the URN
/// is the same value the response middleware stamps on
/// `RequestContext.rsl_urn`.
pub fn render(
    hostname: &str,
    content_signal: Option<&str>,
    config_version: u64,
) -> (String, String) {
    let urn = format!("urn:rsl:1.0:{hostname}:{config_version}");

    // RSL 1.0 mapping. Absent signal asserts default-deny (training,
    // licensed="false").
    let (ai_type, licensed) = match content_signal {
        Some("ai-train") => ("training", "true"),
        Some("ai-input") => ("inference", "true"),
        Some("search") => ("search-index", "true"),
        _ => ("training", "false"),
    };

    // Quick-xml is not pulled into sbproxy-modules directly: the
    // document shape is small enough that hand-rolled emission with
    // strict escaping is cleaner than wiring a writer for one
    // element. The escape helper handles the five XML predefined
    // entities; URNs and hostnames pass through unchanged because RSL
    // restricts them to URI-safe characters.
    let mut xml = String::with_capacity(512);
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push('\n');
    xml.push_str(r#"<rsl xmlns="https://rsl.ai/spec/1.0" version="1.0">"#);
    xml.push('\n');
    xml.push_str(&format!("  <license urn=\"{}\">\n", escape_xml_attr(&urn)));
    xml.push_str(&format!(
        "    <origin hostname=\"{}\" />\n",
        escape_xml_attr(hostname)
    ));
    xml.push_str(&format!(
        "    <ai-use type=\"{ai_type}\" licensed=\"{licensed}\" />\n"
    ));
    if let Some(signal) = content_signal {
        xml.push_str(&format!(
            "    <content-signal>{}</content-signal>\n",
            escape_xml_text(signal)
        ));
    }
    xml.push_str("  </license>\n");
    xml.push_str("</rsl>\n");

    (xml, urn)
}

fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_xml_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urn_format_matches_spec() {
        let (_xml, urn) = render("shop.example.com", Some("ai-train"), 42);
        assert_eq!(urn, "urn:rsl:1.0:shop.example.com:42");
    }

    #[test]
    fn ai_train_maps_to_training_licensed_true() {
        let (xml, _) = render("h", Some("ai-train"), 1);
        assert!(xml.contains(r#"<ai-use type="training" licensed="true" />"#));
        assert!(xml.contains("<content-signal>ai-train</content-signal>"));
    }

    #[test]
    fn ai_input_maps_to_inference_licensed_true() {
        let (xml, _) = render("h", Some("ai-input"), 1);
        assert!(xml.contains(r#"<ai-use type="inference" licensed="true" />"#));
    }

    #[test]
    fn search_maps_to_search_index_licensed_true() {
        let (xml, _) = render("h", Some("search"), 1);
        assert!(xml.contains(r#"<ai-use type="search-index" licensed="true" />"#));
    }

    #[test]
    fn absent_signal_maps_to_default_deny() {
        let (xml, _) = render("h", None, 1);
        assert!(xml.contains(r#"<ai-use type="training" licensed="false" />"#));
        // No content-signal element when the signal is absent.
        assert!(!xml.contains("<content-signal>"));
    }

    #[test]
    fn unknown_signal_falls_back_to_default_deny() {
        let (xml, _) = render("h", Some("custom-future-value"), 1);
        // Falls into the catch-all branch (default-deny).
        assert!(xml.contains(r#"<ai-use type="training" licensed="false" />"#));
        // We still echo the signal text (escaped) for forensics so
        // the operator can see what value reached the projection.
        assert!(xml.contains("<content-signal>custom-future-value</content-signal>"));
    }

    #[test]
    fn xml_namespace_and_version_present() {
        let (xml, _) = render("h", Some("ai-train"), 1);
        assert!(xml.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(xml.contains(r#"<rsl xmlns="https://rsl.ai/spec/1.0" version="1.0">"#));
    }

    #[test]
    fn hostname_with_special_chars_is_escaped_in_attr() {
        // Constructed (not realistic) hostname to verify the attribute
        // escaper is wired even though DNS hostnames cannot legally
        // contain `&`.
        let (xml, _) = render("a&b", Some("ai-train"), 1);
        assert!(xml.contains("hostname=\"a&amp;b\""));
    }

    #[test]
    fn deterministic_output() {
        let (a, _) = render("h", Some("ai-train"), 1);
        let (b, _) = render("h", Some("ai-train"), 1);
        assert_eq!(a, b);
    }
}
