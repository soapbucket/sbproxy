//! `/.well-known/tdmrep.json` projection per W3C TDMRep
//! CG-FINAL-tdmrep-20240510.
//!
//! The W3C TDMRep spec mandates a bare JSON array at the document
//! root, where each entry is an object with three fields:
//!
//! - `location` (string, URL): the resource the policy applies to.
//! - `tdm-reservation` (integer 0 or 1): 1 reserves TDM rights, 0
//!   waives them.
//! - `tdm-policy` (string, URL): URL of the policy document the
//!   agent can fetch to negotiate access. Optional per spec when
//!   `tdm-reservation` is 0; this projection always emits it
//!   alongside a reservation of 1 because the proxy ships the
//!   companion `/licenses.xml` document on every origin that has an
//!   `ai_crawl_control` policy attached.
//!
//! Mapping table (origin-level `Content-Signal` to TDMRep entry):
//!
//! - `ai-train`, `ai-input`, `search` -> entry emitted with
//!   `tdm-reservation: 1` and `tdm-policy` pointing at the
//!   companion `/licenses.xml` document on the same origin.
//! - absent -> no entry emitted (the EU DSM Article 4 default
//!   already treats absence as reservation; the accompanying
//!   `TDM-Reservation: 1` response header is stamped by the
//!   response middleware via `current_projections().content_signals`,
//!   not from this body).
//!
//! The accompanying `TDM-Reservation: 1` response header is not
//! emitted from this module; see `current_projections().content_signals`
//! for the per-hostname signal value the response middleware reads
//! before stamping the header. The middleware lives in
//! `sbproxy-core::server` close to the other response-shaping code.

use serde::Serialize;
use serde_json::Value;

/// One entry in the TDMRep JSON array.
///
/// Field names match the W3C TDMRep CG-FINAL spec exactly: `location`,
/// `tdm-reservation`, `tdm-policy`. The Rust field names are
/// snake_case-with-rename so we land the hyphenated names on
/// serialisation without forcing every caller to deal with
/// hyphens-in-keys.
#[derive(Debug, Serialize)]
struct TdmRepEntry<'a> {
    location: &'a str,
    #[serde(rename = "tdm-reservation")]
    tdm_reservation: u8,
    #[serde(rename = "tdm-policy")]
    tdm_policy: String,
}

/// Render the `/.well-known/tdmrep.json` body for a single origin.
///
/// Per the W3C TDMRep spec, the document is a bare JSON array at the
/// root (no envelope object). When the origin asserts no
/// `Content-Signal`, the array is empty and the response middleware
/// instead stamps a `TDM-Reservation: 1` header on every response
/// (reservation-by-default).
pub fn render(hostname: &str, ai_crawl: &Value, content_signal: Option<&str>) -> String {
    // Wave 4 emits a non-empty array only when the origin asserts a
    // recognised signal. Absent / unrecognised signals fall back to
    // the empty-array case so the response middleware can stamp the
    // catch-all `TDM-Reservation: 1` header without contradicting the
    // body.
    let emit_entries = matches!(
        content_signal,
        Some("ai-train") | Some("ai-input") | Some("search")
    );

    let mut entries: Vec<TdmRepEntry<'_>> = Vec::new();

    if emit_entries {
        let policy_url = format!("https://{hostname}/licenses.xml");

        if let Some(tiers) = ai_crawl.get("tiers").and_then(|v| v.as_array()) {
            for tier in tiers {
                let route = tier
                    .get("route_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");
                entries.push(TdmRepEntry {
                    location: route,
                    tdm_reservation: 1,
                    tdm_policy: policy_url.clone(),
                });
            }
        }

        // No tiered routes? Emit a single catch-all entry so the
        // agent at least sees the origin-level position.
        if entries.is_empty() {
            entries.push(TdmRepEntry {
                location: "/",
                tdm_reservation: 1,
                tdm_policy: policy_url,
            });
        }
    }

    // Pretty-print with two-space indent for readability; the file is
    // typically fetched once per agent and parsed, so the bytes-on-the-wire
    // cost is negligible.
    serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_array(body: &str) -> Vec<Value> {
        let v: Value = serde_json::from_str(body).expect("body must be valid JSON");
        v.as_array()
            .expect("TDMRep document must be a bare JSON array at the root")
            .clone()
    }

    #[test]
    fn ai_train_emits_entry_with_reservation_one() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [{"route_pattern": "/x", "price": {"amount_micros": 1000, "currency": "USD"}}],
        });
        let body = render("blog.example.com", &cfg, Some("ai-train"));
        let arr = parse_array(&body);
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["location"], "/x");
        assert_eq!(arr[0]["tdm-reservation"], 1);
        assert_eq!(
            arr[0]["tdm-policy"],
            "https://blog.example.com/licenses.xml"
        );
    }

    #[test]
    fn ai_input_emits_entry_with_reservation_one() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("ai-input"));
        let arr = parse_array(&body);
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["tdm-reservation"], 1);
    }

    #[test]
    fn search_emits_entry_with_reservation_one() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("search"));
        let arr = parse_array(&body);
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["tdm-reservation"], 1);
    }

    #[test]
    fn absent_signal_emits_empty_array() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [{"route_pattern": "/x", "price": {"amount_micros": 1000, "currency": "USD"}}],
        });
        let body = render("h", &cfg, None);
        let arr = parse_array(&body);
        assert!(
            arr.is_empty(),
            "absent Content-Signal must not assert any TDMRep entry (right reserved via header)"
        );
    }

    #[test]
    fn one_entry_per_priced_tier() {
        let cfg = serde_json::json!({
            "type": "ai_crawl_control",
            "tiers": [
                {"route_pattern": "/articles/*", "price": {"amount_micros": 1000, "currency": "USD"}, "content_shape": "html"},
                {"route_pattern": "/data/*", "price": {"amount_micros": 5000, "currency": "USD"}, "content_shape": "json"},
            ],
        });
        let body = render("h", &cfg, Some("ai-train"));
        let arr = parse_array(&body);
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["location"], "/articles/*");
        assert_eq!(arr[1]["location"], "/data/*");
        assert_eq!(arr[0]["tdm-reservation"], 1);
        assert_eq!(arr[1]["tdm-reservation"], 1);
    }

    #[test]
    fn catch_all_when_signal_present_but_no_tiers() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("ai-train"));
        let arr = parse_array(&body);
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["location"], "/");
        assert_eq!(arr[0]["tdm-reservation"], 1);
    }

    #[test]
    fn document_root_is_bare_array_no_envelope() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("ai-train"));
        // Spec compliance: the root must be an array, not an object.
        let v: Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(
            v.is_array(),
            "TDMRep root must be a bare JSON array per W3C CG-FINAL; got {body}"
        );
        // No legacy envelope keys.
        assert!(!body.contains("\"policies\""));
        assert!(!body.contains("\"version\""));
        assert!(!body.contains("\"generated\""));
    }

    #[test]
    fn entry_uses_dashed_field_names() {
        let cfg = serde_json::json!({"type": "ai_crawl_control"});
        let body = render("h", &cfg, Some("ai-train"));
        // Spec mandates `tdm-reservation` and `tdm-policy` (hyphenated).
        assert!(
            body.contains("\"tdm-reservation\""),
            "must use canonical key tdm-reservation; got {body}"
        );
        assert!(
            body.contains("\"tdm-policy\""),
            "must use canonical key tdm-policy; got {body}"
        );
        // Snake-case variants must not leak through serde.
        assert!(!body.contains("tdm_reservation"));
        assert!(!body.contains("tdm_policy"));
    }
}
