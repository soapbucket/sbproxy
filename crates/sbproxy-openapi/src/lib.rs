//! Emit an OpenAPI 3.0 document describing the routes a gateway config exposes.
//!
//! Walks a [`sbproxy_config::CompiledConfig`] snapshot and produces an
//! OpenAPI 3.0 JSON document covering paths, methods, parameters, security
//! schemes, response codes, CORS, and cache directives. Buyers consume the
//! emitted spec with standard tooling (Postman, Swagger UI, ReadMe.io,
//! Stainless, etc.).
//!
//! # Mapping
//!
//! | Source                                        | OpenAPI target                                |
//! |-----------------------------------------------|-----------------------------------------------|
//! | `CompiledOrigin.hostname`                     | `servers[].url`                               |
//! | Forward rule `template` matcher               | `paths` key (template syntax verbatim)        |
//! | Forward rule `exact` matcher                  | `paths` key                                   |
//! | Forward rule `prefix` matcher                 | `paths` key + `x-sbproxy-prefix-match: true`  |
//! | Forward rule `regex` matcher                  | `x-sbproxy-regex-path` extension only         |
//! | `CompiledOrigin.allowed_methods`              | `Operation` per method                        |
//! | Rule-level `parameters`                       | `parameters[]` per operation                  |
//! | `CompiledOrigin.auth_config`                  | `securitySchemes` + `security`                |
//! | `CompiledOrigin.response_cache.*_status`      | `responses` keys                              |
//! | `CompiledOrigin.error_pages`                  | `responses` keys                              |
//! | `CompiledOrigin.cors`                         | `x-sbproxy-cors` extension                    |
//!
//! Plugin-extensible auth types we don't recognise round-trip into an
//! `x-sbproxy-auth-type` extension and skip the `security` requirement so
//! the doc still validates.

#![warn(missing_docs)]

use sbproxy_config::{CompiledConfig, RawForwardRule};
use serde_json::{json, Map, Value};

/// Build an OpenAPI 3.0 document from a compiled config snapshot.
///
/// When `host_filter` is `Some(host)`, only origins whose hostname matches
/// the filter are emitted - used by the per-host `/.well-known/openapi.json`
/// endpoint. When `None`, every configured origin is included.
pub fn build(snapshot: &CompiledConfig, host_filter: Option<&str>) -> Value {
    // --- Top-level info ---
    let mut spec = Map::new();
    spec.insert("openapi".to_string(), Value::String("3.0.3".to_string()));
    spec.insert(
        "info".to_string(),
        json!({
            "title": "SoapBucket Gateway",
            "description": "Routes exposed by this SoapBucket gateway, derived from its live configuration. \
                Coverage is bounded by what the gateway config knows: path templates, methods, declared \
                parameters, auth schemes, and known response codes. Upstream request/response bodies are \
                not described here unless declared explicitly.",
            "version": snapshot_version(snapshot),
        }),
    );

    // --- Servers ---
    let servers: Vec<Value> = snapshot
        .origins
        .iter()
        .filter(|o| host_filter.is_none_or(|h| h == o.hostname.as_str()))
        .map(|o| {
            json!({
                "url": format!("https://{}", o.hostname),
                "description": format!("Origin {}", o.origin_id),
            })
        })
        .collect();
    if !servers.is_empty() {
        spec.insert("servers".to_string(), Value::Array(servers));
    }

    // --- Paths + per-origin securitySchemes ---
    let mut paths = Map::new();
    let mut security_schemes = Map::new();

    for origin in &snapshot.origins {
        if let Some(h) = host_filter {
            if h != origin.hostname.as_str() {
                continue;
            }
        }

        // Auth scheme for this origin (if any), keyed by scheme name we
        // synthesize from the origin id so distinct origins can declare
        // distinct auth without collisions.
        let security_requirement = origin.auth_config.as_ref().and_then(|auth| {
            let scheme_name = format!("{}_auth", origin.origin_id);
            map_auth(auth, &scheme_name).map(|scheme| {
                security_schemes.insert(scheme_name.clone(), scheme);
                let mut req = Map::new();
                req.insert(scheme_name, Value::Array(Vec::new()));
                Value::Array(vec![Value::Object(req)])
            })
        });

        // Methods to emit per path. Empty allowlist = every standard verb.
        let methods: Vec<&str> = if origin.allowed_methods.is_empty() {
            vec!["get", "post", "put", "patch", "delete", "head", "options"]
        } else {
            origin
                .allowed_methods
                .iter()
                .map(|m| http_method_to_lowercase(m))
                .collect()
        };

        // Walk forward rules. Each rule's matchers become path keys; the
        // rule's parameters apply to every operation under those paths.
        for rule_json in &origin.forward_rules {
            let rule: RawForwardRule = match serde_json::from_value(rule_json.clone()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping malformed forward rule during OpenAPI emission");
                    continue;
                }
            };

            for matcher in &rule.rules {
                let (path_key, extensions) = match path_key_for_matcher(matcher) {
                    Some(v) => v,
                    None => continue,
                };
                let path_item = paths
                    .entry(path_key)
                    .or_insert_with(|| Value::Object(Map::new()));
                let path_obj = path_item.as_object_mut().expect("path item is object");
                for (k, v) in extensions {
                    path_obj.insert(k, v);
                }

                for method in &methods {
                    let mut op = Map::new();
                    op.insert(
                        "summary".to_string(),
                        Value::String(format!(
                            "{} via forward rule on {}",
                            method.to_uppercase(),
                            origin.hostname
                        )),
                    );
                    op.insert(
                        "operationId".to_string(),
                        Value::String(operation_id(
                            origin.origin_id.as_str(),
                            method,
                            &rule.origin.id,
                        )),
                    );
                    if !rule.parameters.is_empty() {
                        op.insert(
                            "parameters".to_string(),
                            serde_json::to_value(&rule.parameters).unwrap_or(Value::Array(vec![])),
                        );
                    }
                    op.insert("responses".to_string(), build_responses(origin));
                    if let Some(sec) = &security_requirement {
                        op.insert("security".to_string(), sec.clone());
                    }
                    path_obj.insert((*method).to_string(), Value::Object(op));
                }
            }
        }

        // CORS captured as an extension since OpenAPI 3.0 has no native
        // vocabulary for it.
        if let Some(cors) = &origin.cors {
            spec.entry("x-sbproxy-cors")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(obj) = spec
                .get_mut("x-sbproxy-cors")
                .and_then(|v| v.as_object_mut())
            {
                obj.insert(
                    origin.hostname.to_string(),
                    serde_json::to_value(cors).unwrap_or(Value::Null),
                );
            }
        }
    }

    spec.insert("paths".to_string(), Value::Object(paths));
    if !security_schemes.is_empty() {
        let mut components = Map::new();
        components.insert(
            "securitySchemes".to_string(),
            Value::Object(security_schemes),
        );
        spec.insert("components".to_string(), Value::Object(components));
    }

    Value::Object(spec)
}

/// Render a built spec as pretty-printed JSON.
pub fn render_json(spec: &Value) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(spec)?)
}

/// Render a built spec as YAML.
pub fn render_yaml(spec: &Value) -> anyhow::Result<String> {
    Ok(serde_yaml::to_string(spec)?)
}

// --- Helpers ---

fn snapshot_version(_snapshot: &CompiledConfig) -> String {
    // Origin set fingerprint would belong here, but the compiled config
    // itself does not carry the runtime config_revision (that lives on
    // CompiledPipeline). Callers who want to surface the live revision
    // can override this field after building the spec.
    "1.0.0".to_string()
}

fn http_method_to_lowercase(method: &http::Method) -> &'static str {
    match *method {
        http::Method::GET => "get",
        http::Method::POST => "post",
        http::Method::PUT => "put",
        http::Method::PATCH => "patch",
        http::Method::DELETE => "delete",
        http::Method::HEAD => "head",
        http::Method::OPTIONS => "options",
        http::Method::TRACE => "trace",
        // Unknown verb: fall through to GET so the doc stays valid; the
        // operationId still encodes the origin/rule for traceability.
        _ => "get",
    }
}

fn operation_id(origin_id: &str, method: &str, rule_origin_id: &Option<String>) -> String {
    let suffix = rule_origin_id.as_deref().unwrap_or("default");
    format!(
        "{}_{}_{}",
        origin_id.replace([':', '/', ' '], "_"),
        method,
        suffix.replace([':', '/', ' '], "_")
    )
}

/// Convert a forward-rule matcher into an OpenAPI `paths` key plus any
/// path-level extensions to attach. Returns `None` for matchers that do
/// not yield a meaningful path entry (e.g. shorthand `match:` is treated
/// as a prefix here too).
fn path_key_for_matcher(
    matcher: &sbproxy_config::ForwardRuleMatcher,
) -> Option<(String, Vec<(String, Value)>)> {
    if let Some(path) = &matcher.path {
        if let Some(template) = &path.template {
            return Some((template.clone(), Vec::new()));
        }
        if let Some(regex) = &path.regex {
            // Regex matchers cannot map to a standard OpenAPI paths key.
            // Surface them under a synthetic path keyed on the pattern so
            // the doc remains valid, plus an extension flagging the source.
            return Some((
                format!("/__regex__/{}", regex.replace('/', "_")),
                vec![(
                    "x-sbproxy-regex-path".to_string(),
                    Value::String(regex.clone()),
                )],
            ));
        }
        if let Some(exact) = &path.exact {
            return Some((exact.clone(), Vec::new()));
        }
        if let Some(prefix) = &path.prefix {
            return Some((
                prefix.clone(),
                vec![("x-sbproxy-prefix-match".to_string(), Value::Bool(true))],
            ));
        }
    }
    if let Some(prefix) = &matcher.match_prefix {
        return Some((
            prefix.clone(),
            vec![("x-sbproxy-prefix-match".to_string(), Value::Bool(true))],
        ));
    }
    None
}

/// Build the `responses` map for an operation from origin-level signals.
///
/// We have three signals that hint at known status codes: cacheable status
/// codes from `response_cache`, status codes referenced by `error_pages`,
/// and a default `200`. We always emit `200` and `default` so the spec is
/// usable even when no signals are present.
fn build_responses(origin: &sbproxy_config::CompiledOrigin) -> Value {
    let mut responses = Map::new();
    responses.insert(
        "200".to_string(),
        json!({ "description": "Successful response" }),
    );

    if let Some(rc) = &origin.response_cache {
        for code in &rc.cacheable_status {
            let key = code.to_string();
            responses
                .entry(key)
                .or_insert_with(|| json!({ "description": format!("HTTP {}", code) }));
        }
    }

    if let Some(pages) = &origin.error_pages {
        if let Some(obj) = pages.as_object() {
            for code in obj.keys() {
                responses
                    .entry(code.clone())
                    .or_insert_with(|| json!({ "description": format!("HTTP {}", code) }));
            }
        }
    }

    responses
        .entry("default".to_string())
        .or_insert_with(|| json!({ "description": "Unexpected error" }));

    Value::Object(responses)
}

/// A pluggable mapper from a gateway auth config to an OpenAPI 3.0
/// SecurityScheme.
///
/// OSS ships baseline mappers for the auth types the open-source proxy
/// implements (api_keys, basic_auth, oauth_client_creds). Enterprise
/// crates register richer mappers via [`inventory::submit!`] for
/// enterprise-only auth types (SAML, biscuit, oauth_introspection,
/// ext_authz) and may override OSS mappers when they want to publish
/// fuller metadata.
///
/// Registration is link-time: any crate compiled into the final binary
/// that submits an entry contributes its mapping. Resolution iterates
/// registered mappers in inventory order; enterprise crates that
/// deliberately want last-word semantics should pick a unique
/// `auth_type` rather than relying on registration order.
pub struct AuthSchemeMapper {
    /// The auth `type:` value this mapper handles (e.g. `"saml"`).
    pub auth_type: &'static str,
    /// Build the SecurityScheme JSON. The closure receives the raw auth
    /// config block and the synthesized scheme name (so it can reference
    /// itself in `x-sbproxy-*` extensions if needed).
    pub map: fn(auth: &Value, scheme_name: &str) -> Value,
}

inventory::collect!(AuthSchemeMapper);

/// Map a gateway auth config to an OpenAPI 3.0 SecurityScheme.
///
/// Resolution order:
/// 1. Registered [`AuthSchemeMapper`] entries with a matching
///    `auth_type` (enterprise override path).
/// 2. OSS built-in mappers for the auth types the open-source proxy
///    implements directly.
/// 3. Generic fallback: `apiKey` placeholder + `x-sbproxy-auth-type`
///    extension so the doc still validates and operators see the
///    original type.
fn map_auth(auth: &Value, scheme_name: &str) -> Option<Value> {
    let auth_type = auth.get("type")?.as_str()?;

    // Registered out-of-tree mappers first.
    for entry in inventory::iter::<AuthSchemeMapper> {
        if entry.auth_type == auth_type {
            return Some((entry.map)(auth, scheme_name));
        }
    }

    // OSS built-ins. These are intentionally minimal; richer mappings
    // for additional auth types (SAML, biscuit, oauth_introspection,
    // ext_authz, full OAuth authorization-code flow) are provided by
    // out-of-tree mappers registered through the inventory hook above.
    Some(match auth_type {
        "oauth_client_creds" => {
            let token_url = auth
                .get("token_url")
                .and_then(|v| v.as_str())
                .unwrap_or("https://example.com/token");
            json!({
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": token_url,
                        "scopes": {},
                    }
                },
                "x-sbproxy-auth-type": auth_type,
            })
        }
        "api_keys" => {
            let header = auth
                .get("header")
                .and_then(|v| v.as_str())
                .unwrap_or("X-API-Key");
            json!({
                "type": "apiKey",
                "in": "header",
                "name": header,
                "x-sbproxy-auth-type": auth_type,
            })
        }
        "basic_auth" => json!({
            "type": "http",
            "scheme": "basic",
            "x-sbproxy-auth-type": auth_type,
        }),
        // Unknown auth types: emit a placeholder so the doc validates
        // and surface the original type as an extension. When an
        // out-of-tree mapper is linked in, the registered mapper above
        // kicks in instead.
        _ => json!({
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "x-sbproxy-auth-type": auth_type,
            "description": format!(
                "Auth handled by the gateway-side plugin '{}'; richer SecurityScheme metadata is available in the enterprise build (see docs/enterprise.md).",
                auth_type
            ),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_snapshot() -> CompiledConfig {
        let mut host_map = std::collections::HashMap::new();
        host_map.insert(compact_str::CompactString::new("api.example.com"), 0);
        let mut origin = empty_origin("api.example.com", "api");
        origin.allowed_methods = smallvec::smallvec![http::Method::GET, http::Method::POST];
        origin.forward_rules = vec![serde_json::json!({
            "rules": [
                { "path": { "template": "/users/{id}" } },
                { "path": { "exact": "/health" } }
            ],
            "parameters": [
                {
                    "name": "id",
                    "in": "path",
                    "required": true,
                    "schema": { "type": "integer" }
                }
            ],
            "origin": {
                "id": "users-api",
                "action": { "type": "proxy", "url": "http://127.0.0.1/" }
            }
        })];
        CompiledConfig {
            origins: vec![origin],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        }
    }

    fn empty_origin(host: &str, id: &str) -> sbproxy_config::CompiledOrigin {
        sbproxy_config::CompiledOrigin {
            hostname: compact_str::CompactString::new(host),
            origin_id: compact_str::CompactString::new(id),
            workspace_id: compact_str::CompactString::default(),
            action_config: serde_json::json!({"type": "proxy", "url": "http://127.0.0.1/"}),
            auth_config: None,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec::smallvec![],
            request_modifiers: smallvec::smallvec![],
            response_modifiers: smallvec::smallvec![],
            variables: None,
            forward_rules: Vec::new(),
            fallback_origin: None,
            error_pages: None,
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: std::collections::HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            rate_limits: None,
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
        }
    }

    #[test]
    fn build_emits_valid_top_level_shape() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        assert_eq!(spec["openapi"], "3.0.3");
        assert!(spec["info"].is_object());
        assert!(spec["paths"].is_object());
        assert!(spec["servers"].is_array());
    }

    #[test]
    fn build_includes_template_path() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let paths = spec["paths"].as_object().unwrap();
        assert!(paths.contains_key("/users/{id}"));
        assert!(paths.contains_key("/health"));
    }

    #[test]
    fn build_emits_methods_per_path() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let path = &spec["paths"]["/users/{id}"];
        assert!(path["get"].is_object());
        assert!(path["post"].is_object());
        // Allowed methods only: PUT/PATCH/DELETE not in allowed_methods.
        assert!(path.get("put").is_none());
    }

    #[test]
    fn build_propagates_parameters() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let params = spec["paths"]["/users/{id}"]["get"]["parameters"]
            .as_array()
            .expect("parameters array");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0]["name"], "id");
        assert_eq!(params[0]["in"], "path");
        assert_eq!(params[0]["required"], true);
        assert_eq!(params[0]["schema"]["type"], "integer");
    }

    #[test]
    fn build_filters_by_host() {
        let mut snap = make_minimal_snapshot();
        let mut other = empty_origin("web.example.com", "web");
        other.allowed_methods = smallvec::smallvec![http::Method::GET];
        other.forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "exact": "/login" } }],
            "origin": { "id": "web-login", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        snap.host_map
            .insert(compact_str::CompactString::new("web.example.com"), 1);
        snap.origins.push(other);

        let spec = build(&snap, Some("web.example.com"));
        let paths = spec["paths"].as_object().unwrap();
        assert!(paths.contains_key("/login"));
        assert!(!paths.contains_key("/users/{id}"));
    }

    #[test]
    fn build_emits_security_scheme_for_oauth() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "oauth_client_creds",
            "token_url": "https://auth.example.com/token"
        }));
        let spec = build(&snap, None);
        let schemes = spec["components"]["securitySchemes"]
            .as_object()
            .expect("securitySchemes object");
        let scheme = schemes.values().next().expect("at least one scheme");
        assert_eq!(scheme["type"], "oauth2");
        assert_eq!(
            scheme["flows"]["clientCredentials"]["tokenUrl"],
            "https://auth.example.com/token"
        );
    }

    #[test]
    fn build_unknown_auth_type_falls_through_with_extension() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].auth_config = Some(serde_json::json!({
            "type": "custom_enterprise_auth"
        }));
        let spec = build(&snap, None);
        let schemes = spec["components"]["securitySchemes"]
            .as_object()
            .expect("securitySchemes object");
        let scheme = schemes.values().next().unwrap();
        assert_eq!(scheme["x-sbproxy-auth-type"], "custom_enterprise_auth");
    }

    #[test]
    fn build_marks_prefix_path_with_extension() {
        let mut snap = make_minimal_snapshot();
        snap.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [{ "path": { "prefix": "/api/" } }],
            "origin": { "id": "api", "action": { "type": "proxy", "url": "http://127.0.0.1/" } }
        })];
        let spec = build(&snap, None);
        assert_eq!(
            spec["paths"]["/api/"]["x-sbproxy-prefix-match"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn render_json_round_trips() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let rendered = render_json(&spec).unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["openapi"], "3.0.3");
    }

    #[test]
    fn render_yaml_round_trips() {
        let snap = make_minimal_snapshot();
        let spec = build(&snap, None);
        let yaml = render_yaml(&spec).unwrap();
        assert!(yaml.contains("openapi"));
        assert!(yaml.contains("3.0.3"));
    }
}
