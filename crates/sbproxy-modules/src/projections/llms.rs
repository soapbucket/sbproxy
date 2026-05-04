//! G4.6: `llms.txt` and `llms-full.txt` projections.
//!
//! Format follows the Anthropic / Mistral convention referenced in
//! `docs/adr-policy-graph-projections.md` § "llms.txt and
//! llms-full.txt": a YAML-like header followed by a Markdown body.
//! `llms.txt` is the concise summary (header only); `llms-full.txt`
//! includes the full priced-route listing.
//!
//! Header fields:
//!
//! - `# sitename:` from the origin hostname
//! - `# version:` from the config version hash
//! - `# payment:` the top-level price (or "pay-per-request" for
//!   complex tier sets)
//! - `# shapes:` comma-separated list of offered `ContentShape` values

use std::collections::BTreeSet;

use serde_json::Value;

/// Render `(llms.txt, llms-full.txt)` for a single origin.
pub fn render(hostname: &str, ai_crawl: &Value, config_version: u64) -> (String, String) {
    let header = render_header(hostname, ai_crawl, config_version);

    // Concise summary: header-only with a one-line Markdown body.
    let mut llms = String::with_capacity(header.len() + 256);
    llms.push_str(&header);
    llms.push('\n');
    llms.push_str(&format!("# {hostname}\n\n"));
    llms.push_str(&format!(
        "Crawler pricing for `{hostname}` is enforced by SBproxy. \
         Cooperative agents should fetch `/llms-full.txt` for the full \
         priced-route listing, or `/.well-known/tdmrep.json` for the \
         machine-readable text-and-data-mining policy.\n"
    ));

    // Full listing: header + per-tier Markdown body.
    let mut full = String::with_capacity(header.len() + 1024);
    full.push_str(&header);
    full.push('\n');
    full.push_str(&format!("# {hostname}\n\n"));
    full.push_str("## Priced routes\n\n");

    let mut any_tiers = false;
    if let Some(tiers) = ai_crawl.get("tiers").and_then(|v| v.as_array()) {
        for tier in tiers {
            let route = tier
                .get("route_pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("/");
            let micros = tier_price_micros(tier);
            let currency = tier
                .get("price")
                .and_then(|p| p.get("currency"))
                .and_then(|v| v.as_str())
                .unwrap_or("USD");
            let shape = tier
                .get("content_shape")
                .and_then(|v| v.as_str())
                .unwrap_or("any");
            let agent = tier
                .get("agent_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("*");
            let preview = tier
                .get("free_preview_bytes")
                .and_then(|v| v.as_u64())
                .map(|n| format!(" (free preview: {n} bytes)"))
                .unwrap_or_default();
            full.push_str(&format!(
                "- `{route}` - agent `{agent}`, shape `{shape}`, price {} {currency}{preview}\n",
                format_units(micros)
            ));
            any_tiers = true;
        }
    }
    if !any_tiers {
        full.push_str(
            "_No tiered pricing configured; the top-level price applies to every route._\n",
        );
    }

    (llms, full)
}

fn render_header(hostname: &str, ai_crawl: &Value, config_version: u64) -> String {
    let mut header = String::with_capacity(256);
    header.push_str(&format!("# sitename: {hostname}\n"));
    header.push_str(&format!("# version: {config_version}\n"));

    // Payment summary: the top-level catch-all price, or
    // "pay-per-request" when tiers are configured.
    let tiers_present = ai_crawl
        .get("tiers")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if tiers_present {
        header.push_str("# payment: pay-per-request\n");
    } else {
        let top_price = ai_crawl
            .get("price")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let currency = ai_crawl
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("USD");
        if top_price > 0.0 {
            header.push_str(&format!("# payment: {top_price:.6} {currency}\n"));
        } else {
            header.push_str("# payment: free\n");
        }
    }

    // Shape inventory: every `content_shape` we see across tiers,
    // alphabetised. Empty when no tiers carry a shape.
    let mut shapes: BTreeSet<String> = BTreeSet::new();
    if let Some(tiers) = ai_crawl.get("tiers").and_then(|v| v.as_array()) {
        for tier in tiers {
            if let Some(s) = tier.get("content_shape").and_then(|v| v.as_str()) {
                shapes.insert(s.to_string());
            }
        }
    }
    if !shapes.is_empty() {
        let joined: Vec<String> = shapes.into_iter().collect();
        header.push_str(&format!("# shapes: {}\n", joined.join(",")));
    }

    header
}

fn tier_price_micros(tier: &Value) -> u64 {
    tier.get("price")
        .and_then(|p| p.get("amount_micros"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            tier.get("price")
                .and_then(|v| v.as_f64())
                .map(|f| (f.max(0.0) * 1_000_000.0).round() as u64)
        })
        .unwrap_or(0)
}

fn format_units(micros: u64) -> String {
    let major = micros / 1_000_000;
    let minor = micros % 1_000_000;
    format!("{major}.{minor:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_carries_sitename_and_version() {
        let cfg = serde_json::json!({"type": "ai_crawl_control", "price": 0.001});
        let (llms, _full) = render("shop.example.com", &cfg, 7);
        assert!(llms.contains("# sitename: shop.example.com"));
        assert!(llms.contains("# version: 7"));
    }

    #[test]
    fn payment_line_falls_back_to_free_when_no_price() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let (llms, _) = render("h", &cfg, 1);
        assert!(llms.contains("# payment: free"));
    }

    #[test]
    fn payment_line_summarises_top_level_price() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "price": 0.005,
            "currency": "EUR",
        });
        let (llms, _) = render("h", &cfg, 1);
        assert!(llms.contains("# payment: 0.005000 EUR"));
    }

    #[test]
    fn payment_line_says_pay_per_request_when_tiers_present() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [{"route_pattern": "/x", "price": {"amount_micros": 1000, "currency": "USD"}}],
        });
        let (llms, _) = render("h", &cfg, 1);
        assert!(llms.contains("# payment: pay-per-request"));
    }

    #[test]
    fn shapes_line_joins_offered_shapes_alphabetically() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [
                {"route_pattern": "/a", "price": {"amount_micros": 1, "currency": "USD"}, "content_shape": "markdown"},
                {"route_pattern": "/b", "price": {"amount_micros": 1, "currency": "USD"}, "content_shape": "html"},
            ],
        });
        let (llms, _) = render("h", &cfg, 1);
        assert!(llms.contains("# shapes: html,markdown"));
    }

    #[test]
    fn full_lists_each_tier() {
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
            ],
        });
        let (_, full) = render("h", &cfg, 1);
        assert!(full.contains("## Priced routes"));
        assert!(full.contains("`/articles/*`"));
        assert!(full.contains("agent `GPTBot`"));
        assert!(full.contains("shape `html`"));
        assert!(full.contains("0.002000 USD"));
        assert!(full.contains("free preview: 256 bytes"));
    }

    #[test]
    fn full_explains_when_no_tiers_configured() {
        let cfg = serde_json::json!({"type": "ai_crawl_control", "price": 0.001});
        let (_, full) = render("h", &cfg, 1);
        assert!(full.contains("No tiered pricing configured"));
    }

    #[test]
    fn deterministic_for_same_input() {
        let cfg = serde_json::json!({"type": "ai_crawl_control", "price": 0.001});
        let (a1, b1) = render("h", &cfg, 1);
        let (a2, b2) = render("h", &cfg, 1);
        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
    }
}
