//! Dispatch-side glue for the MCP tool rollout plane.
//!
//! The pure resolution ladder lives in
//! `sbproxy_extension::mcp::rollout`. This module turns its decisions
//! into dispatch actions: which catalogue entries to hide from
//! `tools/list`, what to advertise instead, how a `tools/call` on a
//! managed tool rewrites onto a concrete federated server, adapter
//! execution, and the `_meta` stamped on results.
//!
//! Everything here is synchronous and free of federation locks so it
//! unit-tests without a server harness; `action_dispatch` supplies
//! the catalogue snapshot and runs the actual upstream call.

use std::collections::{HashMap, HashSet};

use sbproxy_extension::js::JsEngine;
use sbproxy_extension::mcp::rollout::{
    ResolutionInput, ResolveError, RolloutPlan, META_AVAILABLE_KEY, META_SUNSET_KEY,
    META_VERSION_KEY,
};
use sbproxy_plugin::Principal;

/// JSON-RPC error code for rollout rejections (`-32000..=-32099` is
/// the implementation-defined server-error range; `-32098` sits next
/// to the quota lane's `-32099`).
pub const ROLLOUT_ERROR_CODE: i64 = -32098;

/// What `tools/call` should do for a given tool name.
#[derive(Debug)]
pub enum CallPlan {
    /// Not a managed tool: dispatch exactly as before.
    Unmanaged,
    /// Managed: dispatch the base tool on this server, through these
    /// adapters.
    Routed(Box<RoutedCall>),
    /// Managed but the call must fail with this JSON-RPC error.
    Reject {
        /// JSON-RPC error code.
        code: i64,
        /// Human-readable detail.
        message: String,
    },
}

/// A managed call, resolved onto a concrete route.
#[derive(Debug, Clone)]
pub struct RoutedCall {
    /// Base (unversioned) tool name; the upstream knows it by this.
    pub base: String,
    /// Federated server that serves the chosen version.
    pub server: String,
    /// Chosen version, rendered for labels and `_meta`.
    pub version: String,
    /// Ladder rung that chose it (metric label).
    pub via: &'static str,
    /// `js:` request-adapter reference, when translating.
    pub request_adapter: Option<String>,
    /// `js:` response-adapter reference, when translating.
    pub response_adapter: Option<String>,
    /// `(sunset date ISO, past_sunset)` when the version carries one.
    pub deprecation: Option<(String, bool)>,
}

/// Resolve one `tools/call` name against the plan.
///
/// `session_reqs` comes from the session store (declared at
/// `initialize`), `call_req` from the request `_meta`.
pub fn plan_call(
    plan: &RolloutPlan,
    name: &str,
    call_req: Option<&str>,
    session_reqs: Option<&HashMap<String, String>>,
    principal: Option<&Principal>,
    today: chrono::NaiveDate,
) -> CallPlan {
    let input = ResolutionInput {
        call_req,
        session_reqs,
        principal,
        today,
    };
    let resolved = match plan.resolve(name, &input) {
        None => return CallPlan::Unmanaged,
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            let message = match e {
                ResolveError::InvalidRequirement {
                    requirement,
                    detail,
                } => format!(
                    "tool '{name}': version requirement '{requirement}' is not a \
                     semver range: {detail}"
                ),
                ResolveError::NoMatchingVersion { requirement } => {
                    format!("tool '{name}': no published version satisfies '{requirement}'")
                }
                ResolveError::SunsetBlocked { version, sunset } => format!(
                    "tool '{name}' version {version} was sunset on {sunset} and is \
                     no longer served; migrate to a newer version"
                ),
            };
            return CallPlan::Reject {
                code: ROLLOUT_ERROR_CODE,
                message,
            };
        }
    };

    // A version without its own server dispatches to the tool's
    // default version's server (the adapter case).
    let server = match &resolved.entry.server {
        Some(s) => s.clone(),
        None => {
            let default_input = ResolutionInput {
                call_req: None,
                session_reqs: None,
                principal: None,
                today,
            };
            let fallback = plan
                .resolve(resolved.base, &default_input)
                .and_then(|r| r.ok())
                .and_then(|r| r.entry.server.clone());
            match fallback {
                Some(s) => s,
                None => {
                    return CallPlan::Reject {
                        code: ROLLOUT_ERROR_CODE,
                        message: format!(
                            "tool '{name}' version {} has no route: neither it nor \
                             the default version names a federated server",
                            resolved.entry.version
                        ),
                    }
                }
            }
        }
    };

    let (request_adapter, response_adapter) = resolved
        .entry
        .adapter
        .as_ref()
        .map(|a| (a.request.clone(), a.response.clone()))
        .unwrap_or((None, None));

    CallPlan::Routed(Box::new(RoutedCall {
        base: resolved.base.to_string(),
        server,
        version: resolved.entry.version.to_string(),
        via: resolved.via.label(),
        request_adapter,
        response_adapter,
        deprecation: resolved
            .deprecation
            .map(|d| (d.sunset.format("%Y-%m-%d").to_string(), d.past_sunset)),
    }))
}

/// Map a `(server, base tool)` pair onto the catalogue name the
/// federation actually advertises: the server-qualified name when the
/// registry holds it for that server, else the bare name when the
/// bare entry belongs to that server.
pub fn catalogue_name_for(
    server_of: impl Fn(&str) -> Option<String>,
    server: &str,
    base: &str,
) -> Option<String> {
    let qualified = format!("{server}.{base}");
    if server_of(&qualified).as_deref() == Some(server) {
        return Some(qualified);
    }
    if server_of(base).as_deref() == Some(server) {
        return Some(base.to_string());
    }
    None
}

/// One catalogue entry the rollout view consumes: the advertised
/// name, the owning server, and the pre-serialized tool JSON.
pub struct CatalogueEntry<'a> {
    /// Advertised (possibly server-prefixed) name.
    pub name: &'a str,
    /// Owning federated server.
    pub server: &'a str,
    /// The entry's serialized tool object.
    pub json: &'a str,
}

/// The rollout view over a catalogue snapshot: which advertised
/// names to hide, and the synthesized entries to append.
pub struct ViewPatch {
    /// Advertised names the managed tools replace.
    pub hidden: HashSet<String>,
    /// Replacement entries (base names and aliases), serialized.
    pub synthesized: Vec<serde_json::Value>,
}

/// Build the per-consumer rollout patch for `tools/list`.
///
/// Every catalogue entry that advertises a managed tool (on any of
/// its version servers, bare or prefixed) is hidden; one entry per
/// managed tool (the consumer's chosen version) plus one per alias is
/// synthesized in its place. Schemas come from the inline `contract`
/// when configured, else from the live entry of the version's server,
/// else from any live entry of the base tool.
pub fn synthesize_view(
    plan: &RolloutPlan,
    entries: &[CatalogueEntry<'_>],
    session_reqs: Option<&HashMap<String, String>>,
    principal: Option<&Principal>,
    today: chrono::NaiveDate,
) -> ViewPatch {
    let input = ResolutionInput {
        call_req: None,
        session_reqs,
        principal,
        today,
    };

    // (server, base) -> parsed live tool JSON, and the hidden set.
    let mut live: HashMap<(String, String), serde_json::Value> = HashMap::new();
    let mut hidden = HashSet::new();
    for entry in entries {
        let base = entry
            .name
            .strip_prefix(&format!("{}.", entry.server))
            .unwrap_or(entry.name);
        if !plan.manages(base) {
            continue;
        }
        hidden.insert(entry.name.to_string());
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(entry.json) {
            live.insert((entry.server.to_string(), base.to_string()), v);
        }
    }

    let mut synthesized = Vec::new();
    for decision in plan.view(&input) {
        let available = decision.meta[META_AVAILABLE_KEY].clone();
        let mut emit = |name: &str, entry: &sbproxy_extension::mcp::rollout::VersionEntry| {
            let schema = entry.contract.clone().or_else(|| {
                entry
                    .server
                    .as_ref()
                    .and_then(|s| live.get(&(s.clone(), decision.base.to_string())).cloned())
                    .or_else(|| {
                        live.iter()
                            .find(|((_, b), _)| b == decision.base)
                            .map(|(_, v)| v.clone())
                    })
            });
            let Some(mut tool) = schema else {
                // Nothing to advertise for this version: no inline
                // contract and no live upstream entry. Skip it rather
                // than advertise a wrong schema.
                return;
            };
            tool["name"] = serde_json::Value::String(name.to_string());
            let mut meta = serde_json::Map::new();
            meta.insert(
                META_VERSION_KEY.to_string(),
                entry.version.to_string().into(),
            );
            meta.insert(META_AVAILABLE_KEY.to_string(), available.clone());
            if let Some(sunset) = entry.sunset {
                let iso = sunset.format("%Y-%m-%d").to_string();
                meta.insert(META_SUNSET_KEY.to_string(), iso.clone().into());
                let suffix = format!(" [deprecated; sunset {iso}]");
                match tool.get_mut("description") {
                    Some(serde_json::Value::String(d)) if !d.ends_with(&suffix) => {
                        d.push_str(&suffix);
                    }
                    _ => {
                        tool["description"] = serde_json::Value::String(suffix.trim().to_string());
                    }
                }
            }
            match tool.get_mut("_meta") {
                Some(serde_json::Value::Object(existing)) => {
                    existing.extend(meta);
                }
                _ => {
                    tool["_meta"] = serde_json::Value::Object(meta);
                }
            }
            synthesized.push(tool);
        };

        emit(decision.base, decision.chosen);
        for (alias, entry) in &decision.aliases {
            emit(alias, entry);
        }
    }

    ViewPatch {
        hidden,
        synthesized,
    }
}

/// Run one `js:` adapter function over a JSON value. The reference is
/// `js:<path>`; the file must define the named function
/// (`request(args)` or `response(result)`) and return the transformed
/// value. The file is read per call so operator edits take effect
/// without a reload; MCP tool calls are far from the proxy hot path.
pub fn run_adapter(
    js_ref: &str,
    func: &str,
    value: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let path = js_ref
        .strip_prefix("js:")
        .ok_or_else(|| anyhow::anyhow!("adapter '{js_ref}' is not a js: reference"))?;
    let source = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("adapter '{js_ref}': cannot read script: {e}"))?;
    let executor =
        JsEngine::new().map_err(|e| anyhow::anyhow!("adapter '{js_ref}': engine: {e}"))?;
    executor
        .call_function(&source, func, vec![value])
        .map_err(|e| anyhow::anyhow!("adapter '{js_ref}': {func}: {e}"))
}

/// Finish a managed call's result: run the response adapter when the
/// route has one, then stamp the rollout `_meta`. `Err` carries a
/// human-readable message for a JSON-RPC error (the adapter failed;
/// returning the untranslated v-new shape to a v-old caller would be
/// a silent contract break).
pub fn finish_response(
    route: Option<&RoutedCall>,
    value: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let Some(route) = route else {
        return Ok(value);
    };
    let mut value = match &route.response_adapter {
        Some(js_ref) => run_adapter(js_ref, "response", value)
            .map_err(|e| format!("response adapter failed: {e}"))?,
        None => value,
    };
    inject_result_meta(&mut value, &route.version, route.deprecation.as_ref());
    Ok(value)
}

/// Stamp the rollout `_meta` onto a `tools/call` result: the version
/// that served the call and, for deprecated versions, the sunset.
pub fn inject_result_meta(
    result: &mut serde_json::Value,
    version: &str,
    deprecation: Option<&(String, bool)>,
) {
    if !result.is_object() {
        return;
    }
    let mut meta = serde_json::Map::new();
    meta.insert(META_VERSION_KEY.to_string(), version.into());
    if let Some((sunset, _)) = deprecation {
        meta.insert(META_SUNSET_KEY.to_string(), sunset.as_str().into());
    }
    match result.get_mut("_meta") {
        Some(serde_json::Value::Object(existing)) => existing.extend(meta),
        _ => {
            result["_meta"] = serde_json::Value::Object(meta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_extension::mcp::access_control::McpPrincipalSelector;
    use sbproxy_extension::mcp::rollout::{
        AdapterPair, PinSpec, RolloutSpec, SunsetBehavior, ToolRolloutSpec, VersionSpec,
    };
    use sbproxy_plugin::{PrincipalAttrs, PrincipalSource, TenantId};

    fn day(s: &str) -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn principal(team: &str) -> Principal {
        Principal {
            tenant_id: TenantId::from("acme"),
            sub: "dev-1".to_string(),
            source: PrincipalSource::Bearer,
            virtual_key: None,
            attrs: PrincipalAttrs {
                team: Some(team.to_string()),
                ..PrincipalAttrs::default()
            },
        }
    }

    fn plan() -> RolloutPlan {
        let mut tools = HashMap::new();
        tools.insert(
            "search".to_string(),
            ToolRolloutSpec {
                versions: vec![
                    VersionSpec {
                        version: "1.4.0".into(),
                        server: Some("legacy-api".into()),
                        sunset: Some("2026-01-01".into()),
                        ..VersionSpec::default()
                    },
                    VersionSpec {
                        version: "2.0.0".into(),
                        server: Some("new-api".into()),
                        ..VersionSpec::default()
                    },
                ],
                default: None,
                aliases: true,
            },
        );
        let plan = RolloutSpec {
            tools,
            pins: vec![PinSpec {
                selector: McpPrincipalSelector {
                    team: Some("checkout".into()),
                    ..McpPrincipalSelector::default()
                },
                requirements: HashMap::from([("search".to_string(), "^1".to_string())]),
            }],
        };
        RolloutPlan::compile(&plan).unwrap()
    }

    fn adapter_plan() -> RolloutPlan {
        let mut tools = HashMap::new();
        tools.insert(
            "search".to_string(),
            ToolRolloutSpec {
                versions: vec![
                    VersionSpec {
                        version: "1.4.0".into(),
                        adapter: Some(AdapterPair {
                            request: Some("js:req.js".into()),
                            response: Some("js:res.js".into()),
                        }),
                        contract: Some(serde_json::json!({
                            "name": "search",
                            "description": "v1 search",
                            "inputSchema": {"type": "object",
                                "properties": {"q": {"type": "string"}}}
                        })),
                        ..VersionSpec::default()
                    },
                    VersionSpec {
                        version: "2.0.0".into(),
                        server: Some("new-api".into()),
                        ..VersionSpec::default()
                    },
                ],
                default: None,
                aliases: true,
            },
        );
        RolloutPlan::compile(&RolloutSpec {
            tools,
            pins: vec![],
        })
        .unwrap()
    }

    const TODAY: &str = "2026-07-13";

    #[test]
    fn plan_call_unmanaged_passes_through() {
        let p = plan();
        assert!(matches!(
            plan_call(&p, "weather", None, None, None, day(TODAY)),
            CallPlan::Unmanaged
        ));
    }

    #[test]
    fn plan_call_routes_default_version() {
        let p = plan();
        match plan_call(&p, "search", None, None, None, day(TODAY)) {
            CallPlan::Routed(r) => {
                assert_eq!(r.base, "search");
                assert_eq!(r.server, "new-api");
                assert_eq!(r.version, "2.0.0");
                assert_eq!(r.via, "default");
                assert!(r.deprecation.is_none());
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    #[test]
    fn plan_call_pin_routes_old_version_with_deprecation() {
        let p = plan();
        let caller = principal("checkout");
        match plan_call(&p, "search", None, None, Some(&caller), day(TODAY)) {
            CallPlan::Routed(r) => {
                assert_eq!(r.server, "legacy-api");
                assert_eq!(r.version, "1.4.0");
                assert_eq!(r.via, "pin");
                let (sunset, past) = r.deprecation.expect("deprecated");
                assert_eq!(sunset, "2026-01-01");
                assert!(past);
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    #[test]
    fn plan_call_meta_requirement_wins() {
        let p = plan();
        let caller = principal("checkout");
        match plan_call(&p, "search", Some("^2"), None, Some(&caller), day(TODAY)) {
            CallPlan::Routed(r) => {
                assert_eq!(r.version, "2.0.0");
                assert_eq!(r.via, "meta");
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    #[test]
    fn plan_call_alias_routes_major() {
        let p = plan();
        match plan_call(&p, "search_v1", None, None, None, day(TODAY)) {
            CallPlan::Routed(r) => {
                assert_eq!(r.version, "1.4.0");
                assert_eq!(r.via, "alias");
                assert_eq!(r.base, "search");
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    #[test]
    fn plan_call_invalid_requirement_rejects() {
        let p = plan();
        match plan_call(&p, "search", Some("not a req"), None, None, day(TODAY)) {
            CallPlan::Reject { code, message } => {
                assert_eq!(code, ROLLOUT_ERROR_CODE);
                assert!(message.contains("semver range"), "{message}");
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn plan_call_sunset_block_rejects() {
        let mut tools = HashMap::new();
        tools.insert(
            "search".to_string(),
            ToolRolloutSpec {
                versions: vec![
                    VersionSpec {
                        version: "1.4.0".into(),
                        server: Some("legacy-api".into()),
                        sunset: Some("2026-01-01".into()),
                        after_sunset: SunsetBehavior::Block,
                        ..VersionSpec::default()
                    },
                    VersionSpec {
                        version: "2.0.0".into(),
                        server: Some("new-api".into()),
                        ..VersionSpec::default()
                    },
                ],
                default: None,
                aliases: true,
            },
        );
        let p = RolloutPlan::compile(&RolloutSpec {
            tools,
            pins: vec![],
        })
        .unwrap();
        match plan_call(&p, "search", Some("^1"), None, None, day(TODAY)) {
            CallPlan::Reject { message, .. } => {
                assert!(message.contains("sunset"), "{message}");
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn plan_call_adapter_version_falls_back_to_default_server() {
        let p = adapter_plan();
        match plan_call(&p, "search", Some("^1"), None, None, day(TODAY)) {
            CallPlan::Routed(r) => {
                assert_eq!(r.server, "new-api");
                assert_eq!(r.version, "1.4.0");
                assert_eq!(r.request_adapter.as_deref(), Some("js:req.js"));
                assert_eq!(r.response_adapter.as_deref(), Some("js:res.js"));
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    #[test]
    fn catalogue_name_prefers_qualified_then_bare() {
        let lookup = |name: &str| -> Option<String> {
            match name {
                "legacy-api.search" => Some("legacy-api".to_string()),
                "search" => Some("new-api".to_string()),
                _ => None,
            }
        };
        assert_eq!(
            catalogue_name_for(lookup, "legacy-api", "search").as_deref(),
            Some("legacy-api.search")
        );
        assert_eq!(
            catalogue_name_for(lookup, "new-api", "search").as_deref(),
            Some("search")
        );
        assert!(catalogue_name_for(lookup, "gone-api", "search").is_none());
    }

    fn entry<'a>(name: &'a str, server: &'a str, json: &'a str) -> CatalogueEntry<'a> {
        CatalogueEntry { name, server, json }
    }

    #[test]
    fn view_hides_managed_entries_and_synthesizes_versions() {
        let p = plan();
        let legacy = r#"{"name":"legacy-api.search","description":"old","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}"#;
        let newer = r#"{"name":"search","description":"new","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}"#;
        let other = r#"{"name":"weather","description":"w","inputSchema":{}}"#;
        let entries = [
            entry("legacy-api.search", "legacy-api", legacy),
            entry("search", "new-api", newer),
            entry("weather", "other-api", other),
        ];
        let patch = synthesize_view(&p, &entries, None, None, day(TODAY));
        assert!(patch.hidden.contains("legacy-api.search"));
        assert!(patch.hidden.contains("search"));
        assert!(!patch.hidden.contains("weather"));

        let names: Vec<&str> = patch
            .synthesized
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"search"));
        assert!(names.contains(&"search_v1"));
        assert!(names.contains(&"search_v2"));

        let base = patch
            .synthesized
            .iter()
            .find(|t| t["name"] == "search")
            .unwrap();
        // Default consumer sees v2's schema under the base name.
        assert_eq!(base["_meta"][META_VERSION_KEY], "2.0.0");
        assert!(base["inputSchema"]["properties"]["query"].is_object());

        let v1 = patch
            .synthesized
            .iter()
            .find(|t| t["name"] == "search_v1")
            .unwrap();
        assert_eq!(v1["_meta"][META_VERSION_KEY], "1.4.0");
        assert!(v1["inputSchema"]["properties"]["q"].is_object());
        // Deprecated version carries the sunset in _meta and the
        // description suffix.
        assert_eq!(v1["_meta"][META_SUNSET_KEY], "2026-01-01");
        assert!(v1["description"]
            .as_str()
            .unwrap()
            .contains("sunset 2026-01-01"));
    }

    #[test]
    fn view_pinned_consumer_sees_old_schema_under_base_name() {
        let p = plan();
        let legacy = r#"{"name":"legacy-api.search","description":"old","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}"#;
        let newer = r#"{"name":"search","description":"new","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}"#;
        let entries = [
            entry("legacy-api.search", "legacy-api", legacy),
            entry("search", "new-api", newer),
        ];
        let caller = principal("checkout");
        let patch = synthesize_view(&p, &entries, None, Some(&caller), day(TODAY));
        let base = patch
            .synthesized
            .iter()
            .find(|t| t["name"] == "search")
            .unwrap();
        assert_eq!(base["_meta"][META_VERSION_KEY], "1.4.0");
        assert!(base["inputSchema"]["properties"]["q"].is_object());
    }

    #[test]
    fn view_uses_inline_contract_for_adapter_version() {
        let p = adapter_plan();
        let newer = r#"{"name":"search","description":"new","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}}"#;
        let entries = [entry("search", "new-api", newer)];
        let patch = synthesize_view(&p, &entries, None, None, day(TODAY));
        let v1 = patch
            .synthesized
            .iter()
            .find(|t| t["name"] == "search_v1")
            .unwrap();
        assert_eq!(v1["description"], "v1 search");
        assert!(v1["inputSchema"]["properties"]["q"].is_object());
    }

    #[test]
    fn run_adapter_executes_named_functions() {
        let dir = std::env::temp_dir().join(format!(
            "sbproxy-rollout-adapter-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v1.js");
        std::fs::write(
            &path,
            r#"
function request(args) {
    return { query: args.q, limit: args.limit === undefined ? 10 : args.limit };
}
function response(result) {
    result.adapted = true;
    return result;
}
"#,
        )
        .unwrap();
        let js_ref = format!("js:{}", path.display());

        let adapted = run_adapter(&js_ref, "request", serde_json::json!({"q": "rust"})).unwrap();
        assert_eq!(adapted, serde_json::json!({"query": "rust", "limit": 10}));

        let out = run_adapter(&js_ref, "response", serde_json::json!({"content": []})).unwrap();
        assert_eq!(out["adapted"], true);

        let err = run_adapter("js:/no/such/file.js", "request", serde_json::json!({}))
            .expect_err("missing file");
        assert!(err.to_string().contains("cannot read script"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finish_response_adapts_then_stamps_meta() {
        let dir = std::env::temp_dir().join(format!(
            "sbproxy-rollout-finish-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("res.js");
        std::fs::write(
            &path,
            "function response(result) { result.shape = \"v1\"; return result; }",
        )
        .unwrap();
        let route = RoutedCall {
            base: "search".into(),
            server: "new-api".into(),
            version: "1.4.0".into(),
            via: "pin",
            request_adapter: None,
            response_adapter: Some(format!("js:{}", path.display())),
            deprecation: Some(("2026-01-01".into(), true)),
        };
        let out = finish_response(Some(&route), serde_json::json!({"content": []})).unwrap();
        assert_eq!(out["shape"], "v1");
        assert_eq!(out["_meta"][META_VERSION_KEY], "1.4.0");
        assert_eq!(out["_meta"][META_SUNSET_KEY], "2026-01-01");

        // No route: value passes through untouched.
        let plain = finish_response(None, serde_json::json!({"a": 1})).unwrap();
        assert_eq!(plain, serde_json::json!({"a": 1}));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inject_result_meta_stamps_version_and_sunset() {
        let mut result = serde_json::json!({"content": [{"type": "text", "text": "ok"}]});
        inject_result_meta(
            &mut result,
            "1.4.0",
            Some(&("2026-01-01".to_string(), true)),
        );
        assert_eq!(result["_meta"][META_VERSION_KEY], "1.4.0");
        assert_eq!(result["_meta"][META_SUNSET_KEY], "2026-01-01");

        let mut plain = serde_json::json!({"content": []});
        inject_result_meta(&mut plain, "2.0.0", None);
        assert_eq!(plain["_meta"][META_VERSION_KEY], "2.0.0");
        assert!(plain["_meta"].get(META_SUNSET_KEY).is_none());
    }
}
