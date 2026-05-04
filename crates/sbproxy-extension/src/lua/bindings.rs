//! Request/response Lua table builders.
//!
//! Converts HTTP request and response data into `serde_json::Value` structures
//! suitable for passing into the Lua engine as global tables.

use std::collections::HashMap;

// --- Request Table Builder ---

/// Build a Lua-friendly request table from HTTP request data.
///
/// Returns a `serde_json::Value::Object` with fields: method, path, headers,
/// and optionally query and body.
pub fn build_request_table(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    query: Option<&str>,
    body: Option<&str>,
) -> serde_json::Value {
    let mut req = serde_json::Map::new();
    req.insert(
        "method".to_string(),
        serde_json::Value::String(method.to_string()),
    );
    req.insert(
        "path".to_string(),
        serde_json::Value::String(path.to_string()),
    );
    req.insert("headers".to_string(), serde_json::json!(headers));
    if let Some(q) = query {
        req.insert(
            "query".to_string(),
            serde_json::Value::String(q.to_string()),
        );
    }
    if let Some(b) = body {
        req.insert("body".to_string(), serde_json::Value::String(b.to_string()));
    }
    serde_json::Value::Object(req)
}

/// Splice the agent-class fields into an existing request table built
/// by [`build_request_table`]. Mirrors the CEL helper which adds
/// `request.agent_id` / `request.agent_class` etc., so scripts in
/// either engine see the same surface.
pub fn enrich_request_table_with_agent_class(
    request: &mut serde_json::Value,
    agent_id: Option<&str>,
    agent_vendor: Option<&str>,
    agent_purpose: Option<&str>,
    agent_id_source: Option<&str>,
    agent_rdns_hostname: Option<&str>,
) {
    if let Some(map) = request.as_object_mut() {
        let id = agent_id.unwrap_or("");
        map.insert(
            "agent_id".to_string(),
            serde_json::Value::String(id.to_string()),
        );
        map.insert(
            "agent_class".to_string(),
            serde_json::Value::String(id.to_string()),
        );
        map.insert(
            "agent_vendor".to_string(),
            serde_json::Value::String(agent_vendor.unwrap_or("").to_string()),
        );
        map.insert(
            "agent_purpose".to_string(),
            serde_json::Value::String(agent_purpose.unwrap_or("").to_string()),
        );
        map.insert(
            "agent_id_source".to_string(),
            serde_json::Value::String(agent_id_source.unwrap_or("").to_string()),
        );
        map.insert(
            "agent_rdns_hostname".to_string(),
            serde_json::Value::String(agent_rdns_hostname.unwrap_or("").to_string()),
        );
    }
}

/// Build the agent-class table for Lua scripts (G1.4). Mirrors the
/// `agent` / `request.agent_*` namespace exposed to CEL
/// ([`crate::cel::context::populate_agent_class_namespace`]) so scripts
/// written in either engine see the same surface.
///
/// All fields are present every call. Unset values render as empty
/// strings so a Lua script can branch on `string.len(agent.id) > 0`
/// without first probing for `nil`.
pub fn build_agent_class_table(
    agent_id: Option<&str>,
    agent_vendor: Option<&str>,
    agent_purpose: Option<&str>,
    agent_id_source: Option<&str>,
    agent_rdns_hostname: Option<&str>,
) -> serde_json::Value {
    let mut t = serde_json::Map::new();
    let id = agent_id.unwrap_or("");
    t.insert("id".to_string(), serde_json::Value::String(id.to_string()));
    // `class` is an alias for `id`. Catalog id is the agent class.
    t.insert(
        "class".to_string(),
        serde_json::Value::String(id.to_string()),
    );
    t.insert(
        "vendor".to_string(),
        serde_json::Value::String(agent_vendor.unwrap_or("").to_string()),
    );
    t.insert(
        "purpose".to_string(),
        serde_json::Value::String(agent_purpose.unwrap_or("").to_string()),
    );
    t.insert(
        "source".to_string(),
        serde_json::Value::String(agent_id_source.unwrap_or("").to_string()),
    );
    t.insert(
        "rdns_hostname".to_string(),
        serde_json::Value::String(agent_rdns_hostname.unwrap_or("").to_string()),
    );
    serde_json::Value::Object(t)
}

/// Splice the Wave 5 / G5.3 TLS fingerprint into an existing request
/// table built by [`build_request_table`]. Adds a nested `tls`
/// sub-table with `ja3`, `ja4`, `ja4h`, and `trustworthy` keys so
/// Lua / JS / WASM scripts read `request.tls.ja4` exactly like the
/// CEL surface (`crate::cel::context::populate_tls_namespace`).
pub fn enrich_request_table_with_tls_fingerprint(
    request: &mut serde_json::Value,
    ja3: Option<&str>,
    ja4: Option<&str>,
    ja4h: Option<&str>,
    trustworthy: bool,
) {
    if let Some(map) = request.as_object_mut() {
        let mut tls = serde_json::Map::new();
        tls.insert(
            "ja3".to_string(),
            serde_json::Value::String(ja3.unwrap_or("").to_string()),
        );
        tls.insert(
            "ja4".to_string(),
            serde_json::Value::String(ja4.unwrap_or("").to_string()),
        );
        tls.insert(
            "ja4h".to_string(),
            serde_json::Value::String(ja4h.unwrap_or("").to_string()),
        );
        tls.insert(
            "trustworthy".to_string(),
            serde_json::Value::Bool(trustworthy),
        );
        map.insert("tls".to_string(), serde_json::Value::Object(tls));
    }
}

/// Build the Wave 8 envelope table for Lua scripts. Mirrors the
/// `envelope` namespace exposed to CEL ([`crate::cel::context`]) so
/// scripts written in either engine see the same dimension surface.
///
/// All fields are present every call. Unset dimensions render as
/// empty strings (and `properties` as an empty table) so a Lua script
/// can branch on `string.len(envelope.user_id) > 0` without first
/// probing for `nil`.
pub fn build_envelope_table(
    user_id: Option<&str>,
    user_id_source: Option<&str>,
    session_id: Option<&str>,
    parent_session_id: Option<&str>,
    workspace_id: Option<&str>,
    properties: &HashMap<String, String>,
) -> serde_json::Value {
    let mut env = serde_json::Map::new();
    env.insert(
        "user_id".to_string(),
        serde_json::Value::String(user_id.unwrap_or("").to_string()),
    );
    env.insert(
        "user_id_source".to_string(),
        serde_json::Value::String(user_id_source.unwrap_or("").to_string()),
    );
    env.insert(
        "session_id".to_string(),
        serde_json::Value::String(session_id.unwrap_or("").to_string()),
    );
    env.insert(
        "parent_session_id".to_string(),
        serde_json::Value::String(parent_session_id.unwrap_or("").to_string()),
    );
    env.insert(
        "workspace_id".to_string(),
        serde_json::Value::String(workspace_id.unwrap_or("").to_string()),
    );
    env.insert("properties".to_string(), serde_json::json!(properties));
    serde_json::Value::Object(env)
}

/// Splice the Wave 5 / G5.1 KYA verifier verdict into an existing
/// request table built by [`build_request_table`]. Adds a nested
/// `kya` sub-table mirroring the CEL surface
/// (`crate::cel::context::populate_kya_namespace`) so Lua / JS / WASM
/// scripts read `request.kya.verdict` exactly the same way CEL does.
///
/// All fields render as the empty string (or `0` for `kyab_balance`)
/// when the verifier did not run, so a script can branch on
/// `request.kya.verdict == "missing"` without first probing for
/// `nil`.
pub fn enrich_request_table_with_kya(
    request: &mut serde_json::Value,
    verdict: Option<&str>,
    agent_id: Option<&str>,
    vendor: Option<&str>,
    kya_version: Option<&str>,
    kyab_balance: Option<u64>,
) {
    if let Some(map) = request.as_object_mut() {
        let mut kya = serde_json::Map::new();
        kya.insert(
            "verdict".to_string(),
            serde_json::Value::String(verdict.unwrap_or("").to_string()),
        );
        kya.insert(
            "agent_id".to_string(),
            serde_json::Value::String(agent_id.unwrap_or("").to_string()),
        );
        kya.insert(
            "vendor".to_string(),
            serde_json::Value::String(vendor.unwrap_or("").to_string()),
        );
        kya.insert(
            "kya_version".to_string(),
            serde_json::Value::String(kya_version.unwrap_or("").to_string()),
        );
        let mut balance = serde_json::Map::new();
        balance.insert(
            "amount".to_string(),
            serde_json::Value::Number(serde_json::Number::from(kyab_balance.unwrap_or(0))),
        );
        kya.insert(
            "kyab_balance".to_string(),
            serde_json::Value::Object(balance),
        );
        map.insert("kya".to_string(), serde_json::Value::Object(kya));
    }
}

/// Splice the Wave 5 / A5.2 ML agent classifier verdict into an
/// existing request table built by [`build_request_table`]. Adds a
/// nested `ml_classification` sub-table mirroring the CEL surface
/// (`crate::cel::context::populate_ml_namespace`).
///
/// Fields default to the zero value when the classifier did not run.
pub fn enrich_request_table_with_ml(
    request: &mut serde_json::Value,
    class: Option<&str>,
    confidence: Option<f32>,
    model_version: Option<&str>,
    feature_schema_version: Option<u32>,
) {
    if let Some(map) = request.as_object_mut() {
        let mut ml = serde_json::Map::new();
        ml.insert(
            "class".to_string(),
            serde_json::Value::String(class.unwrap_or("").to_string()),
        );
        ml.insert(
            "confidence".to_string(),
            serde_json::Number::from_f64(confidence.unwrap_or(0.0) as f64)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
        );
        ml.insert(
            "model_version".to_string(),
            serde_json::Value::String(model_version.unwrap_or("").to_string()),
        );
        ml.insert(
            "feature_schema_version".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                feature_schema_version.unwrap_or(0),
            )),
        );
        map.insert(
            "ml_classification".to_string(),
            serde_json::Value::Object(ml),
        );
    }
}

// --- Response Table Builder ---

/// Build a Lua-friendly response table from HTTP response data.
///
/// Returns a `serde_json::Value::Object` with fields: status, headers,
/// and optionally body.
pub fn build_response_table(
    status: u16,
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> serde_json::Value {
    let mut resp = serde_json::Map::new();
    resp.insert(
        "status".to_string(),
        serde_json::Value::Number(serde_json::Number::from(status)),
    );
    resp.insert("headers".to_string(), serde_json::json!(headers));
    if let Some(b) = body {
        resp.insert("body".to_string(), serde_json::Value::String(b.to_string()));
    }
    serde_json::Value::Object(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_table_full() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-api-key".to_string(), "secret123".to_string());

        let req = build_request_table(
            "POST",
            "/api/v1/users",
            &headers,
            Some("page=1&limit=10"),
            Some(r#"{"name":"test"}"#),
        );

        assert_eq!(req["method"], "POST");
        assert_eq!(req["path"], "/api/v1/users");
        assert_eq!(req["query"], "page=1&limit=10");
        assert_eq!(req["body"], r#"{"name":"test"}"#);
        assert_eq!(req["headers"]["content-type"], "application/json");
        assert_eq!(req["headers"]["x-api-key"], "secret123");
    }

    #[test]
    fn test_build_request_table_minimal() {
        let headers = HashMap::new();
        let req = build_request_table("GET", "/health", &headers, None, None);

        assert_eq!(req["method"], "GET");
        assert_eq!(req["path"], "/health");
        assert!(req.get("query").is_none());
        assert!(req.get("body").is_none());
    }

    #[test]
    fn test_build_response_table() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());

        let resp = build_response_table(200, &headers, Some("<html></html>"));

        assert_eq!(resp["status"], 200);
        assert_eq!(resp["headers"]["content-type"], "text/html");
        assert_eq!(resp["body"], "<html></html>");
    }

    #[test]
    fn test_build_response_table_no_body() {
        let headers = HashMap::new();
        let resp = build_response_table(204, &headers, None);

        assert_eq!(resp["status"], 204);
        assert!(resp.get("body").is_none());
    }

    #[test]
    fn envelope_table_round_trips_supplied_dimensions() {
        let mut props = HashMap::new();
        props.insert("environment".to_string(), "prod".to_string());
        let env = build_envelope_table(
            Some("user_42"),
            Some("header"),
            Some("01H..."),
            None,
            Some("ws_a"),
            &props,
        );
        assert_eq!(env["user_id"], "user_42");
        assert_eq!(env["user_id_source"], "header");
        assert_eq!(env["session_id"], "01H...");
        assert_eq!(env["parent_session_id"], "");
        assert_eq!(env["workspace_id"], "ws_a");
        assert_eq!(env["properties"]["environment"], "prod");
    }

    #[test]
    fn envelope_table_defaults_to_empty_strings() {
        let props = HashMap::new();
        let env = build_envelope_table(None, None, None, None, None, &props);
        assert_eq!(env["user_id"], "");
        assert_eq!(env["user_id_source"], "");
        assert_eq!(env["session_id"], "");
        assert_eq!(env["parent_session_id"], "");
        assert_eq!(env["workspace_id"], "");
        // properties is always a (possibly empty) table.
        assert!(env["properties"].is_object());
    }

    // --- Agent class table (G1.4) tests ---

    #[test]
    fn agent_class_table_round_trips_supplied_fields() {
        let t = build_agent_class_table(
            Some("openai-gptbot"),
            Some("OpenAI"),
            Some("training"),
            Some("user_agent"),
            Some("crawl-1.gptbot.openai.com"),
        );
        assert_eq!(t["id"], "openai-gptbot");
        assert_eq!(t["class"], "openai-gptbot");
        assert_eq!(t["vendor"], "OpenAI");
        assert_eq!(t["purpose"], "training");
        assert_eq!(t["source"], "user_agent");
        assert_eq!(t["rdns_hostname"], "crawl-1.gptbot.openai.com");
    }

    #[test]
    fn agent_class_table_defaults_to_empty_strings() {
        let t = build_agent_class_table(None, None, None, None, None);
        assert_eq!(t["id"], "");
        assert_eq!(t["vendor"], "");
        assert_eq!(t["purpose"], "");
    }

    // --- Wave 5 / G5.1 KYA tests ---

    #[test]
    fn enrich_request_table_adds_kya_subtable_for_verified_token() {
        let headers = HashMap::new();
        let mut req = build_request_table("GET", "/", &headers, None, None);
        enrich_request_table_with_kya(
            &mut req,
            Some("verified"),
            Some("openai-gptbot"),
            Some("skyfire"),
            Some("v1"),
            Some(1000),
        );
        assert_eq!(req["kya"]["verdict"], "verified");
        assert_eq!(req["kya"]["agent_id"], "openai-gptbot");
        assert_eq!(req["kya"]["vendor"], "skyfire");
        assert_eq!(req["kya"]["kya_version"], "v1");
        assert_eq!(req["kya"]["kyab_balance"]["amount"], 1000);
    }

    #[test]
    fn enrich_request_table_adds_kya_subtable_for_missing_verdict() {
        let headers = HashMap::new();
        let mut req = build_request_table("GET", "/", &headers, None, None);
        enrich_request_table_with_kya(&mut req, Some("missing"), None, None, None, None);
        assert_eq!(req["kya"]["verdict"], "missing");
        assert_eq!(req["kya"]["agent_id"], "");
        assert_eq!(req["kya"]["kyab_balance"]["amount"], 0);
    }

    // --- Wave 5 / A5.2 ML classifier tests ---

    #[test]
    fn enrich_request_table_adds_ml_classification_subtable_for_human_verdict() {
        let headers = HashMap::new();
        let mut req = build_request_table("GET", "/", &headers, None, None);
        enrich_request_table_with_ml(
            &mut req,
            Some("human"),
            Some(0.97),
            Some("ml-agent-v1"),
            Some(1),
        );
        assert_eq!(req["ml_classification"]["class"], "human");
        // serde_json normalises 0.97 to a Number; we assert via the
        // f64 round-trip rather than a direct equality on f32.
        let conf = req["ml_classification"]["confidence"].as_f64().unwrap();
        assert!((conf - 0.97).abs() < 0.001);
        assert_eq!(req["ml_classification"]["model_version"], "ml-agent-v1");
        assert_eq!(req["ml_classification"]["feature_schema_version"], 1);
    }

    #[test]
    fn enrich_request_table_adds_ml_classification_subtable_with_defaults() {
        let headers = HashMap::new();
        let mut req = build_request_table("GET", "/", &headers, None, None);
        enrich_request_table_with_ml(&mut req, None, None, None, None);
        assert_eq!(req["ml_classification"]["class"], "");
        assert_eq!(
            req["ml_classification"]["confidence"].as_f64().unwrap(),
            0.0
        );
        assert_eq!(req["ml_classification"]["feature_schema_version"], 0);
    }

    #[test]
    fn enrich_request_table_adds_agent_keys() {
        let headers = HashMap::new();
        let mut req = build_request_table("GET", "/", &headers, None, None);
        enrich_request_table_with_agent_class(
            &mut req,
            Some("anthropic-claudebot"),
            Some("Anthropic"),
            Some("training"),
            Some("rdns"),
            Some("a.anthropic.com"),
        );
        assert_eq!(req["method"], "GET");
        assert_eq!(req["agent_id"], "anthropic-claudebot");
        assert_eq!(req["agent_class"], "anthropic-claudebot");
        assert_eq!(req["agent_vendor"], "Anthropic");
        assert_eq!(req["agent_id_source"], "rdns");
    }
}
