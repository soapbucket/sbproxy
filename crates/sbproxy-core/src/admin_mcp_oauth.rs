// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! MCP OAuth broker and federated MCP runtime operator surfaces
//! (`GET /admin/mcp-oauth`, `GET /admin/mcp-runtime`).
//!
//! `sbproxy-mcp-gateway` ships its own `GET {base_path}/admin/status`
//! for a host that embeds the crate's axum router. sbproxy is not that
//! host, and deliberately does not mount it: in process the broker's
//! whole route tree is dispatched on the **public** MCP origin, ahead
//! of the resource-server check, and the OAuth routes have to stay
//! unauthenticated for the flow to work at all. Mounting a route that
//! answers "which security controls are off" there would publish it to
//! anyone who asked.
//!
//! So a colocated operator had no way to see what the broker has wired
//! in, short of reading the config back. This is the same JSON under
//! the proxy's own authenticated admin API, one entry per configured
//! `mcp` action, which is what makes the broker half consistent with
//! the federation half's `GET /admin/federation`.
//!
//! `GET /admin/mcp-runtime` is the WOR-2110 surface: each federated
//! server's discriminated runtime state (`starting` / `ready` /
//! `authRequired` / `error` / `stopped`) plus in-flight tool-call
//! step-up challenges, distinct from operator enable/disable intent.
//! A console page for both is separate scope, under the admin console
//! epic; `docs/admin-api-reference.md` says so beside the routes.

use serde_json::json;

/// Response tuple shared by the admin dispatchers.
type Resp = (u16, &'static str, String);

/// Dispatch `/admin/mcp-oauth`. Returns `None` for paths this module
/// does not own so the caller falls through to the next dispatcher.
pub fn dispatch(method: &str, path: &str) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        "/admin/mcp-oauth" if method.eq_ignore_ascii_case("GET") => Some(status()),
        "/admin/mcp-oauth" => Some((
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        )),
        "/admin/mcp-runtime" if method.eq_ignore_ascii_case("GET") => Some(runtime()),
        "/admin/mcp-runtime" => Some((
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        )),
        _ => None,
    }
}

/// `GET /admin/mcp-oauth`: every colocated OAuth broker this proxy
/// runs, and what each has wired in.
fn status() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let mut brokers = Vec::new();
    for action in &pipeline.actions {
        let sbproxy_modules::action::Action::Mcp(mcp) = action else {
            continue;
        };
        let Some(broker) = mcp.oauth_broker.as_ref() else {
            continue;
        };
        let mut entry = broker.status_json();
        // The resource server is the other half an operator asks
        // about, and its absence is the interesting case: a broker
        // with no verifier mints tokens nothing on this proxy checks.
        if let Some(object) = entry.as_object_mut() {
            object.insert(
                "resource_server_configured".to_string(),
                json!(mcp.resource_server.is_some()),
            );
        }
        brokers.push(entry);
    }
    if brokers.is_empty() {
        // `{"enabled": false}` rather than 404, matching
        // `/admin/federation`, so a poll can tell "no broker
        // configured" from "typo in the path".
        return (
            200,
            "application/json",
            json!({ "enabled": false }).to_string(),
        );
    }
    (
        200,
        "application/json",
        json!({ "enabled": true, "brokers": brokers }).to_string(),
    )
}

/// `GET /admin/mcp-runtime`: discriminated server runtime state and
/// in-flight tool-call auth challenges (WOR-2110). A console page is
/// separate scope, under the admin console epic.
fn runtime() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let mut federations = Vec::new();
    for action in &pipeline.actions {
        let sbproxy_modules::action::Action::Mcp(mcp) = action else {
            continue;
        };
        federations.push(mcp.federation.runtime_status_json());
    }
    if federations.is_empty() {
        return (
            200,
            "application/json",
            json!({ "enabled": false }).to_string(),
        );
    }
    (
        200,
        "application/json",
        json!({ "enabled": true, "federations": federations }).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_this_module_does_not_own_fall_through() {
        assert!(dispatch("GET", "/admin/federation").is_none());
        assert!(dispatch("GET", "/admin/cache").is_none());
        assert!(dispatch("GET", "/admin/mcp-oauth/extra").is_none());
    }

    #[test]
    fn a_non_get_is_answered_405_rather_than_falling_through() {
        let (status, _, body) = dispatch("POST", "/admin/mcp-oauth").expect("claimed");
        assert_eq!(status, 405);
        assert!(body.contains("method not allowed"));
    }

    #[test]
    fn a_query_string_does_not_stop_the_route_matching() {
        assert!(dispatch("GET", "/admin/mcp-oauth?pretty=1").is_some());
        assert!(dispatch("GET", "/admin/mcp-runtime?pretty=1").is_some());
    }

    #[test]
    fn mcp_runtime_without_federation_reports_disabled_rather_than_404() {
        let (status, content_type, body) = runtime();
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(value["enabled"], false);
    }

    #[test]
    fn mcp_runtime_rejects_non_get() {
        let (status, _, body) = dispatch("POST", "/admin/mcp-runtime").expect("claimed");
        assert_eq!(status, 405);
        assert!(body.contains("method not allowed"));
    }

    #[test]
    fn no_broker_configured_reports_disabled_rather_than_404() {
        let (status, content_type, body) = status_for_test();
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(value["enabled"], false);
    }

    /// The default test pipeline has no `mcp` action, so this exercises
    /// the empty branch without standing a broker up.
    fn status_for_test() -> Resp {
        status()
    }
}
