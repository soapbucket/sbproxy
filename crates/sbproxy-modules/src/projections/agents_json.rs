//! agents.json projection (WOR-820).
//!
//! Emits the Wildcard agents.json v0.1 manifest that sits alongside an
//! OpenAPI document and describes how to chain operations into
//! outcome-based flows for agents. The proxy assembles the spec
//! envelope (`agentsJson`, `info`, `sources`, `flows`, optional
//! `overrides`) from per-origin config; `sources` defaults to the
//! origin's emitted `/.well-known/openapi.json`. Flows are
//! operator-authored and emitted verbatim, so a correctly-authored
//! config produces a schema-valid document.
//!
//! Spec: <https://github.com/wild-card-ai/agents-json>.

use sbproxy_config::AgentsJsonConfig;

/// agents.json spec version this projection emits.
const AGENTS_JSON_VERSION: &str = "0.1.0";

/// Render the agents.json manifest body for `hostname` from `cfg`.
///
/// When `cfg.sources` is omitted, a single source is synthesized
/// pointing at the origin's OpenAPI document.
pub fn render(hostname: &str, cfg: &AgentsJsonConfig) -> String {
    let sources = cfg.sources.clone().unwrap_or_else(|| {
        vec![serde_json::json!({
            "id": "openapi",
            "path": format!("https://{hostname}/.well-known/openapi.json"),
        })]
    });

    let mut doc = serde_json::json!({
        "agentsJson": AGENTS_JSON_VERSION,
        "info": {
            "title": cfg.info.title,
            "version": cfg.info.version,
            "description": cfg.info.description,
        },
        "sources": sources,
        "flows": cfg.flows,
    });
    if let (Some(overrides), Some(obj)) = (cfg.overrides.as_ref(), doc.as_object_mut()) {
        obj.insert(
            "overrides".to_string(),
            serde_json::Value::Array(overrides.clone()),
        );
    }
    serde_json::to_string(&doc).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::AgentsJsonInfo;

    fn cfg() -> AgentsJsonConfig {
        AgentsJsonConfig {
            info: AgentsJsonInfo {
                title: "Shop API".to_string(),
                version: "1.0.0".to_string(),
                description: "Order flows".to_string(),
            },
            sources: None,
            flows: vec![serde_json::json!({
                "id": "place_order",
                "title": "Place an order",
                "description": "Create then confirm an order",
                "actions": [{"id": "create", "sourceId": "openapi", "operationId": "createOrder"}],
                "fields": {"parameters": [], "responses": {}}
            })],
            overrides: None,
        }
    }

    #[test]
    fn envelope_has_required_top_level_fields() {
        let body = render("api.example.com", &cfg());
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["agentsJson"], "0.1.0");
        assert_eq!(v["info"]["title"], "Shop API");
        assert_eq!(v["info"]["version"], "1.0.0");
        assert!(v["info"]["description"].is_string());
        assert!(v["sources"].is_array());
        assert!(v["flows"].is_array());
    }

    #[test]
    fn sources_default_to_origin_openapi() {
        let v: serde_json::Value =
            serde_json::from_str(&render("api.example.com", &cfg())).unwrap();
        assert_eq!(v["sources"][0]["id"], "openapi");
        assert_eq!(
            v["sources"][0]["path"],
            "https://api.example.com/.well-known/openapi.json"
        );
    }

    #[test]
    fn operator_flow_is_emitted_verbatim() {
        let v: serde_json::Value = serde_json::from_str(&render("h", &cfg())).unwrap();
        assert_eq!(v["flows"][0]["id"], "place_order");
        assert_eq!(v["flows"][0]["actions"][0]["operationId"], "createOrder");
    }

    #[test]
    fn explicit_sources_override_default() {
        let mut c = cfg();
        c.sources = Some(vec![
            serde_json::json!({"id": "custom", "path": "https://x/openapi.yaml"}),
        ]);
        let v: serde_json::Value = serde_json::from_str(&render("h", &c)).unwrap();
        assert_eq!(v["sources"][0]["id"], "custom");
        assert_eq!(v["sources"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn overrides_emitted_only_when_present() {
        let without: serde_json::Value = serde_json::from_str(&render("h", &cfg())).unwrap();
        assert!(without.get("overrides").is_none());

        let mut c = cfg();
        c.overrides = Some(vec![serde_json::json!({
            "sourceId": "openapi", "operationId": "createOrder",
            "fieldPath": "$.x", "value": 1
        })]);
        let with: serde_json::Value = serde_json::from_str(&render("h", &c)).unwrap();
        assert!(with["overrides"].is_array());
    }
}
