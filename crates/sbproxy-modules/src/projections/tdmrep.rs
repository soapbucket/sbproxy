//! G4.8: `/.well-known/tdmrep.json` projection per W3C TDMRep.
//!
//! JSON document with one `policies[]` entry per priced route. Mapping
//! per `docs/adr-policy-graph-projections.md`:
//!
//! - `ai-train` -> `"right": "train"`
//! - `ai-input` or `search` -> `"right": "research"`
//! - absent -> no entry (no right asserted = right reserved per the
//!   EU DSM Directive Article 4 default)
//!
//! The accompanying `TDM-Reservation: 1` response header is not
//! emitted from this module; see `current_projections().content_signals`
//! for the per-hostname signal value the response middleware reads
//! before stamping the header. The middleware lives in
//! `sbproxy-core::server` close to the other response-shaping code.

use serde_json::{json, Value};

/// Render the `/.well-known/tdmrep.json` body for a single origin.
pub fn render(_hostname: &str, ai_crawl: &Value, content_signal: Option<&str>) -> String {
    let right = match content_signal {
        Some("ai-train") => Some("train"),
        Some("ai-input") | Some("search") => Some("research"),
        _ => None,
    };

    let now = current_rfc3339();
    let mut policies: Vec<Value> = Vec::new();

    if let Some(right_value) = right {
        if let Some(tiers) = ai_crawl.get("tiers").and_then(|v| v.as_array()) {
            for tier in tiers {
                let route = tier
                    .get("route_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");
                // `mine-type` per W3C TDMRep: machine-readable hint
                // to the agent about the document shape. We surface
                // the configured `content_shape` mapped to a short
                // MIME list, defaulting to text/html when unset.
                let mime = mine_type_from_shape(tier.get("content_shape").and_then(|v| v.as_str()));
                policies.push(json!({
                    "location": route,
                    "mine-type": mime,
                    "right": right_value,
                }));
            }
            // No tiered routes? Emit a single catch-all entry so the
            // agent at least sees the origin-level position.
            if policies.is_empty() {
                policies.push(json!({
                    "location": "/",
                    "mine-type": ["text/html"],
                    "right": right_value,
                }));
            }
        } else {
            policies.push(json!({
                "location": "/",
                "mine-type": ["text/html"],
                "right": right_value,
            }));
        }
    }

    let doc = json!({
        "version": "1.0",
        "generated": now,
        "policies": policies,
    });

    // Pretty-print with two-space indent for readability; the file is
    // typically fetched once per agent and parsed, so the bytes-on-the-wire
    // cost is negligible.
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

fn mine_type_from_shape(shape: Option<&str>) -> Vec<&'static str> {
    match shape {
        Some("html") => vec!["text/html"],
        Some("markdown") => vec!["text/markdown", "text/html"],
        Some("json") => vec!["application/json", "application/ld+json"],
        Some("pdf") => vec!["application/pdf"],
        Some("other") | Some(_) => vec!["application/octet-stream"],
        None => vec!["text/html"],
    }
}

fn current_rfc3339() -> String {
    // chrono is already a workspace dep used elsewhere in
    // sbproxy-modules. We deliberately stamp a fresh timestamp on
    // each render so reload-driven regenerations record their wall
    // clock. The byte-for-byte equality cited in A4.1 § "Operator
    // preview via CLI" therefore holds across the same process
    // wall-clock second; rendering twice within the same second is
    // exactly the same body. For snapshot tests we substitute a
    // fixed clock when needed.
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_train_maps_to_train_right() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [{"route_pattern": "/x", "price": {"amount_micros": 1000, "currency": "USD"}}],
        });
        let body = render("h", &cfg, Some("ai-train"));
        let v: Value = serde_json::from_str(&body).unwrap();
        let policies = v["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0]["right"], "train");
    }

    #[test]
    fn ai_input_maps_to_research_right() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("ai-input"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["policies"][0]["right"], "research");
    }

    #[test]
    fn search_maps_to_research_right() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("search"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["policies"][0]["right"], "research");
    }

    #[test]
    fn absent_signal_emits_empty_policies() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [{"route_pattern": "/x", "price": {"amount_micros": 1000, "currency": "USD"}}],
        });
        let body = render("h", &cfg, None);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["policies"].as_array().unwrap().is_empty(),
            "absent Content-Signal must not assert any TDMRep right (right reserved)"
        );
    }

    #[test]
    fn one_policy_entry_per_priced_tier() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [
                {"route_pattern": "/articles/*", "price": {"amount_micros": 1000, "currency": "USD"}, "content_shape": "html"},
                {"route_pattern": "/data/*", "price": {"amount_micros": 5000, "currency": "USD"}, "content_shape": "json"},
            ],
        });
        let body = render("h", &cfg, Some("ai-train"));
        let v: Value = serde_json::from_str(&body).unwrap();
        let policies = v["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0]["location"], "/articles/*");
        assert_eq!(policies[1]["location"], "/data/*");
        assert_eq!(policies[0]["mine-type"][0], "text/html");
        assert_eq!(policies[1]["mine-type"][0], "application/json");
    }

    #[test]
    fn catch_all_when_signal_present_but_no_tiers() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("ai-train"));
        let v: Value = serde_json::from_str(&body).unwrap();
        let policies = v["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0]["location"], "/");
        assert_eq!(policies[0]["right"], "train");
    }

    #[test]
    fn version_and_generated_fields_present() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("ai-train"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["version"], "1.0");
        let generated = v["generated"].as_str().unwrap();
        // RFC 3339 'YYYY-MM-DDTHH:MM:SSZ' or with offset.
        assert!(generated.contains('T'));
        assert!(generated.ends_with('Z') || generated.contains('+') || generated.contains('-'));
    }
}
