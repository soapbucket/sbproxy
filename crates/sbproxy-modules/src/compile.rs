//! Config-to-module compilation.
//!
//! Bridges `sbproxy-config` (JSON values) to typed module enums by
//! reading the `type` discriminator and deserializing into the
//! appropriate variant.

use anyhow::{Context, Result};
use sbproxy_config::extract_type;

use crate::action::{
    A2aAction, Action, AiProxyAction, BeaconAction, EchoAction, GraphQLAction, GrpcAction,
    LoadBalancerAction, McpAction, MockAction, ProxyAction, RedirectAction, StaticAction,
    StorageAction, WebSocketAction,
};
use crate::auth::{
    ApiKeyAuth, Auth, BasicAuthProvider, BearerAuth, BotAuthProvider, DigestAuth,
    ForwardAuthProvider, JwtAuth,
};
use crate::policy::{
    AssertionPolicy, CsrfPolicy, DdosPolicy, ExpressionPolicy, IpFilterPolicy, Policy,
    RateLimitPolicy, RequestLimitPolicy, SecHeadersPolicy, SriPolicy, WafPolicy,
};
use crate::transform::{
    BoilerplateTransform, CelScriptTransform, CitationBlockTransform, CssTransform,
    DiscardTransform, EncodingTransform, FormatConvertTransform, HtmlToMarkdownTransform,
    HtmlTransform, JavaScriptTransform, JsJsonTransform, JsonEnvelopeTransform,
    JsonProjectionTransform, JsonSchemaTransform, JsonTransform, LuaJsonTransform,
    MarkdownTransform, NormalizeTransform, OptimizeHtmlTransform, PayloadLimitTransform,
    ReplaceStringsTransform, SseChunkingTransform, TemplateTransform, Transform, WasmTransform,
};

/// Compile a JSON action config into an Action enum variant.
pub fn compile_action(config: &serde_json::Value) -> Result<Action> {
    let type_name = extract_type(config)?;
    match type_name.as_str() {
        "proxy" => Ok(Action::Proxy(ProxyAction::from_config(config.clone())?)),
        "redirect" => Ok(Action::Redirect(RedirectAction::from_config(
            config.clone(),
        )?)),
        "static" => Ok(Action::Static(StaticAction::from_config(config.clone())?)),
        "echo" => Ok(Action::Echo(EchoAction::from_config(config.clone())?)),
        "mock" => Ok(Action::Mock(MockAction::from_config(config.clone())?)),
        "beacon" => Ok(Action::Beacon(BeaconAction::from_config(config.clone())?)),
        "load_balancer" => Ok(Action::LoadBalancer(std::sync::Arc::new(
            LoadBalancerAction::from_config(config.clone())?,
        ))),
        "ai_proxy" => Ok(Action::AiProxy(Box::new(AiProxyAction::from_config(
            config.clone(),
        )?))),
        "websocket" => Ok(Action::WebSocket(WebSocketAction::from_config(
            config.clone(),
        )?)),
        "grpc" => Ok(Action::Grpc(GrpcAction::from_config(config.clone())?)),
        "graphql" => Ok(Action::GraphQL(GraphQLAction::from_config(config.clone())?)),
        "storage" => Ok(Action::Storage(
            StorageAction::from_config(config.clone())?.build()?,
        )),
        "a2a" => Ok(Action::A2a(A2aAction::from_config(config.clone())?)),
        "mcp" => Ok(Action::Mcp(Box::new(McpAction::from_config(
            config.clone(),
        )?))),
        "noop" => Ok(Action::Noop),
        _ => anyhow::bail!("unknown action type: {}", type_name),
    }
}

/// Compile a JSON auth config into an Auth enum variant.
///
/// Built-in auth types match through the explicit arms below. Anything
/// that doesn't match a built-in falls through to the inventory-based
/// auth plugin registry, so enterprise auth types (`saml`, `biscuit`,
/// `oauth`, `oauth_introspection`, `ext_authz`, ...) work transparently
/// when their crates are linked into the binary.
pub fn compile_auth(config: &serde_json::Value) -> Result<Auth> {
    let type_name = extract_type(config)?;
    match type_name.as_str() {
        "api_key" => Ok(Auth::ApiKey(ApiKeyAuth::from_config(config.clone())?)),
        "basic_auth" => Ok(Auth::BasicAuth(BasicAuthProvider::from_config(
            config.clone(),
        )?)),
        "bearer" | "bearer_token" => Ok(Auth::Bearer(BearerAuth::from_config(config.clone())?)),
        "jwt" => Ok(Auth::Jwt(JwtAuth::from_config(config.clone())?)),
        "digest" => Ok(Auth::Digest(DigestAuth::from_config(config.clone())?)),
        "forward_auth" | "forward" => Ok(Auth::ForwardAuth(ForwardAuthProvider::from_config(
            config.clone(),
        )?)),
        "bot_auth" | "web_bot_auth" => {
            Ok(Auth::BotAuth(BotAuthProvider::from_config(config.clone())?))
        }
        "cap" => Ok(Auth::Cap(crate::auth::cap::CapVerifier::from_config(
            config.clone(),
        )?)),
        "noop" => Ok(Auth::Noop),
        other => {
            if let Some(result) = sbproxy_plugin::build_auth_plugin(other, config.clone()) {
                let provider =
                    result.with_context(|| format!("auth plugin {other:?} factory failed"))?;
                Ok(Auth::Plugin(provider))
            } else {
                anyhow::bail!("unknown auth type: {}", other)
            }
        }
    }
}

/// Compile a single JSON policy config into a Policy enum variant.
pub fn compile_policy(config: &serde_json::Value) -> Result<Policy> {
    let type_name = extract_type(config)?;
    match type_name.as_str() {
        "rate_limiting" => Ok(Policy::RateLimit(RateLimitPolicy::from_config(
            config.clone(),
        )?)),
        "ip_filter" | "ip_filtering" => Ok(Policy::IpFilter(IpFilterPolicy::from_config(
            config.clone(),
        )?)),
        "security_headers" => Ok(Policy::SecHeaders(SecHeadersPolicy::from_config(
            config.clone(),
        )?)),
        "request_limit" | "request_limiting" => Ok(Policy::RequestLimit(
            RequestLimitPolicy::from_config(config.clone())?,
        )),
        "csrf" => Ok(Policy::Csrf(CsrfPolicy::from_config(config.clone())?)),
        "ddos" | "ddos_protection" => Ok(Policy::Ddos(DdosPolicy::from_config(config.clone())?)),
        "waf" => Ok(Policy::Waf(WafPolicy::from_config(config.clone())?)),
        "sri" => Ok(Policy::Sri(SriPolicy::from_config(config.clone())?)),
        "expression" => Ok(Policy::Expression(ExpressionPolicy::from_config(
            config.clone(),
        )?)),
        "assertion" | "response_assertion" => Ok(Policy::Assertion(AssertionPolicy::from_config(
            config.clone(),
        )?)),
        "request_validator" => Ok(Policy::RequestValidator(
            crate::policy::RequestValidatorPolicy::from_config(config.clone())?,
        )),
        "concurrent_limit" | "concurrent_limiting" => Ok(Policy::ConcurrentLimit(
            crate::policy::ConcurrentLimitPolicy::from_config(config.clone())?,
        )),
        "ai_crawl_control" | "pay_per_crawl" => Ok(Policy::AiCrawl(
            crate::policy::AiCrawlControlPolicy::from_config(config.clone())?,
        )),
        "exposed_credentials" | "leaked_credentials" => Ok(Policy::ExposedCreds(
            crate::policy::ExposedCredsPolicy::from_config(config.clone())?,
        )),
        "page_shield" => Ok(Policy::PageShield(
            crate::policy::PageShieldPolicy::from_config(config.clone())?,
        )),
        "dlp" => Ok(Policy::Dlp(crate::policy::DlpPolicy::from_config(
            config.clone(),
        )?)),
        "openapi_validation" => Ok(Policy::OpenApiValidation(
            crate::policy::OpenApiValidationPolicy::from_config(config.clone())?,
        )),
        "prompt_injection_v2" => Ok(Policy::PromptInjectionV2(
            crate::policy::PromptInjectionV2Policy::from_config(config.clone())?,
        )),
        "http_framing" => Ok(Policy::HttpFraming(
            crate::policy::HttpFramingPolicy::from_config(config.clone())?,
        )),
        // G1.4 wire: the `agent_class` policy is the YAML seam for the
        // agent-class resolver. The policy itself is thin (per-origin
        // header-forwarding knobs); the resolver state lives in the
        // binary-side `AgentClassResolver` built from the top-level
        // `agent_classes:` block.
        #[cfg(feature = "agent-class")]
        "agent_class" => Ok(Policy::AgentClass(
            crate::policy::agent_class::AgentClassPolicy::from_config(config.clone())?,
        )),
        // Wave 7 / A7.2 A2A protocol policy. Always compiled into the
        // OSS build (the parser surface is feature-gated, but the
        // policy module enforces route-level limits regardless of
        // whether parsing produced a populated context).
        "a2a" => Ok(Policy::A2A(crate::policy::a2a::A2APolicy::from_config(
            config.clone(),
        )?)),
        _ => anyhow::bail!("unknown policy type: {}", type_name),
    }
}

/// Compile a JSON transform config into a Transform enum variant.
pub fn compile_transform(config: &serde_json::Value) -> Result<Transform> {
    let type_name = extract_type(config)?;
    match type_name.as_str() {
        "json" => Ok(Transform::Json(JsonTransform::from_config(config.clone())?)),
        "json_projection" => Ok(Transform::JsonProjection(
            JsonProjectionTransform::from_config(config.clone())?,
        )),
        "json_schema" => Ok(Transform::JsonSchema(JsonSchemaTransform::from_config(
            config.clone(),
        )?)),
        "template" => Ok(Transform::Template(TemplateTransform::from_config(
            config.clone(),
        )?)),
        "replace_strings" => Ok(Transform::ReplaceStrings(
            ReplaceStringsTransform::from_config(config.clone())?,
        )),
        "normalize" => Ok(Transform::Normalize(NormalizeTransform::from_config(
            config.clone(),
        )?)),
        "encoding" => Ok(Transform::Encoding(EncodingTransform::from_config(
            config.clone(),
        )?)),
        "format_convert" => Ok(Transform::FormatConvert(
            FormatConvertTransform::from_config(config.clone())?,
        )),
        "payload_limit" => Ok(Transform::PayloadLimit(PayloadLimitTransform::from_config(
            config.clone(),
        )?)),
        "discard" => Ok(Transform::Discard(DiscardTransform::from_config(
            config.clone(),
        )?)),
        "sse_chunking" => Ok(Transform::SseChunking(SseChunkingTransform::from_config(
            config.clone(),
        )?)),
        "html" => Ok(Transform::Html(HtmlTransform::from_config(config.clone())?)),
        "optimize_html" => Ok(Transform::OptimizeHtml(OptimizeHtmlTransform::from_config(
            config.clone(),
        )?)),
        "html_to_markdown" => Ok(Transform::HtmlToMarkdown(
            HtmlToMarkdownTransform::from_config(config.clone())?,
        )),
        "markdown" => Ok(Transform::Markdown(MarkdownTransform::from_config(
            config.clone(),
        )?)),
        "css" => Ok(Transform::Css(CssTransform::from_config(config.clone())?)),
        "lua_json" => Ok(Transform::LuaJson(LuaJsonTransform::from_config(
            config.clone(),
        )?)),
        "javascript" => Ok(Transform::JavaScript(JavaScriptTransform::from_config(
            config.clone(),
        )?)),
        "js_json" => Ok(Transform::JsJson(JsJsonTransform::from_config(
            config.clone(),
        )?)),
        "wasm" => Ok(Transform::Wasm(WasmTransform::from_config(config.clone())?)),
        // --- Wave 4 content-shaping transforms (G4.10 / G4.4) ---
        //
        // These three accept their YAML configs here so the schema
        // sweep passes; the actual response-filter wiring that calls
        // the typed `apply` (with ctx fields) lands in day-5.
        "boilerplate" => Ok(Transform::Boilerplate(BoilerplateTransform::from_config(
            config.clone(),
        )?)),
        "citation_block" => Ok(Transform::CitationBlock(
            CitationBlockTransform::from_config(config.clone())?,
        )),
        "json_envelope" => Ok(Transform::JsonEnvelope(JsonEnvelopeTransform::from_config(
            config.clone(),
        )?)),
        // Wave 5 day-5 / Q5.x: CEL response-body transform. Used by
        // the e2e tests to stamp `request.tls.ja4` /
        // `request.kya.verdict` back into the response body. See
        // `crates/sbproxy-modules/src/transform/cel_script.rs`.
        "cel" => Ok(Transform::CelScript(CelScriptTransform::from_config(
            config.clone(),
        )?)),
        "noop" => Ok(Transform::Noop),
        _ => anyhow::bail!("unknown transform type: {}", type_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- compile_action tests ---

    #[test]
    fn compile_action_proxy() {
        let json = serde_json::json!({
            "type": "proxy",
            "url": "http://localhost:3000",
            "strip_base_path": true
        });
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "proxy");

        if let Action::Proxy(p) = action {
            assert_eq!(p.url, "http://localhost:3000");
            assert!(p.strip_base_path);
        } else {
            panic!("expected Action::Proxy");
        }
    }

    #[test]
    fn compile_action_noop() {
        let json = serde_json::json!({"type": "noop"});
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "noop");
    }

    #[test]
    fn compile_action_redirect() {
        let json = serde_json::json!({
            "type": "redirect",
            "url": "https://new-site.com",
            "status": 301
        });
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "redirect");

        if let Action::Redirect(r) = action {
            assert_eq!(r.url, "https://new-site.com");
            assert_eq!(r.status, 301);
        } else {
            panic!("expected Action::Redirect");
        }
    }

    #[test]
    fn compile_action_static() {
        let json = serde_json::json!({
            "type": "static",
            "body": "Hello, world!",
            "content_type": "text/plain"
        });
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "static");

        if let Action::Static(s) = action {
            assert_eq!(s.body, "Hello, world!");
            assert_eq!(s.status, 200);
        } else {
            panic!("expected Action::Static");
        }
    }

    #[test]
    fn compile_action_echo() {
        let json = serde_json::json!({"type": "echo"});
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "echo");
    }

    #[test]
    fn compile_action_mock() {
        let json = serde_json::json!({
            "type": "mock",
            "status": 201,
            "body": {"created": true},
            "delay_ms": 100
        });
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "mock");

        if let Action::Mock(m) = action {
            assert_eq!(m.status, 201);
            assert_eq!(m.delay_ms, Some(100));
        } else {
            panic!("expected Action::Mock");
        }
    }

    #[test]
    fn compile_action_beacon() {
        let json = serde_json::json!({"type": "beacon"});
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "beacon");
    }

    #[test]
    fn compile_action_load_balancer() {
        let json = serde_json::json!({
            "type": "load_balancer",
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080", "weight": 3}
            ],
            "algorithm": "round_robin"
        });
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "load_balancer");

        if let Action::LoadBalancer(lb) = action {
            assert_eq!(lb.targets.len(), 2);
            assert_eq!(lb.targets[1].weight, 3);
        } else {
            panic!("expected Action::LoadBalancer");
        }
    }

    #[test]
    fn compile_action_unknown_type() {
        let json = serde_json::json!({"type": "unknown_thing"});
        assert!(compile_action(&json).is_err());
    }

    #[test]
    fn compile_action_mcp() {
        // Note: WOR-42 makes per-server `rbac` and `timeout` hard
        // config errors until the federation dispatcher actually
        // enforces them. Restore the fields here once that wiring
        // lands (see sbproxy-modules/src/action/mcp.rs).
        let json = serde_json::json!({
            "type": "mcp",
            "mode": "gateway",
            "server_info": {"name": "test", "version": "1.0.0"},
            "federated_servers": [
                {
                    "origin": "github.example.com",
                    "prefix": "gh"
                }
            ],
            "guardrails": [
                {"type": "tool_allowlist", "allow": ["gh.search_repos"]}
            ]
        });
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "mcp");
        if let Action::Mcp(m) = action {
            assert_eq!(m.server_name, "test");
            assert_eq!(m.prefixes.len(), 1);
            assert!(m.is_tool_allowed("gh.search_repos"));
            assert!(!m.is_tool_allowed("gh.delete_repo"));
        } else {
            panic!("expected Action::Mcp");
        }
    }

    #[test]
    fn compile_action_mcp_requires_servers() {
        let json = serde_json::json!({
            "type": "mcp",
            "federated_servers": []
        });
        assert!(compile_action(&json).is_err());
    }

    #[test]
    fn compile_action_missing_type() {
        let json = serde_json::json!({"url": "http://example.com"});
        assert!(compile_action(&json).is_err());
    }

    // --- compile_auth tests ---

    #[test]
    fn compile_auth_api_key() {
        let json = serde_json::json!({
            "type": "api_key",
            "api_keys": ["key1", "key2"],
            "header_name": "Authorization"
        });
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "api_key");
    }

    #[test]
    fn compile_auth_noop() {
        let json = serde_json::json!({"type": "noop"});
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "noop");
    }

    #[test]
    fn compile_auth_basic_auth() {
        let json = serde_json::json!({
            "type": "basic_auth",
            "users": [{"username": "admin", "password": "pass"}]
        });
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "basic_auth");
    }

    #[test]
    fn compile_auth_bearer() {
        let json = serde_json::json!({
            "type": "bearer",
            "tokens": ["tok-1"]
        });
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "bearer");
    }

    #[test]
    fn compile_auth_jwt() {
        let json = serde_json::json!({
            "type": "jwt",
            "secret": "hmac-secret"
        });
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "jwt");
    }

    #[test]
    fn compile_auth_digest() {
        let json = serde_json::json!({
            "type": "digest",
            "realm": "Restricted",
            "users": [{"username": "u", "password": "p"}]
        });
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "digest");
    }

    #[test]
    fn compile_auth_forward_auth() {
        let json = serde_json::json!({
            "type": "forward_auth",
            "url": "http://auth-svc/check"
        });
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "forward_auth");
    }

    #[test]
    fn compile_auth_unknown_type() {
        let json = serde_json::json!({"type": "oauth2"});
        assert!(compile_auth(&json).is_err());
    }

    // --- compile_policy tests ---

    #[test]
    fn compile_policy_rate_limiting() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 100.0,
            "burst": 50
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "rate_limiting");
    }

    #[test]
    fn compile_policy_unknown_type() {
        let json = serde_json::json!({"type": "nonexistent_policy"});
        assert!(compile_policy(&json).is_err());
    }

    #[test]
    fn compile_policy_rate_limit_defaults() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "burst": 10
        });
        // requests_per_second is optional (defaults to 10 rps)
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "rate_limiting");
    }

    #[test]
    fn compile_policy_ip_filter() {
        let json = serde_json::json!({
            "type": "ip_filter",
            "whitelist": ["10.0.0.0/8"],
            "blacklist": ["10.0.1.0/24"]
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "ip_filter");
    }

    #[test]
    fn compile_policy_security_headers() {
        // New canonical format.
        let json = serde_json::json!({
            "type": "security_headers",
            "headers": [
                {"name": "X-Frame-Options", "value": "DENY"},
                {"name": "X-Content-Type-Options", "value": "nosniff"}
            ]
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "security_headers");
        if let Policy::SecHeaders(sec) = policy {
            let resolved = sec.resolved_headers();
            assert!(resolved
                .iter()
                .any(|(n, v)| n == "x-frame-options" && v == "DENY"));
            assert!(resolved
                .iter()
                .any(|(n, v)| n == "x-content-type-options" && v == "nosniff"));
        } else {
            panic!("expected Policy::SecHeaders");
        }
    }

    #[test]
    fn compile_policy_security_headers_legacy_flat() {
        // Legacy flat format still compiles (backward compat).
        let json = serde_json::json!({
            "type": "security_headers",
            "x_frame_options": "DENY",
            "x_content_type_options": "nosniff"
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "security_headers");
    }

    #[test]
    fn compile_policy_request_limit() {
        let json = serde_json::json!({
            "type": "request_limit",
            "max_body_size": 1048576,
            "max_header_count": 100
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "request_limit");
    }

    #[test]
    fn compile_policy_csrf() {
        let json = serde_json::json!({
            "type": "csrf",
            "secret_key": "test-secret-key"
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "csrf");
    }

    #[test]
    fn compile_policy_ddos() {
        let json = serde_json::json!({
            "type": "ddos",
            "requests_per_second": 200,
            "block_duration_secs": 600
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "ddos");
    }

    #[test]
    fn compile_policy_sri() {
        let json = serde_json::json!({
            "type": "sri",
            "enforce": true,
            "algorithms": ["sha256", "sha384"]
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "sri");
    }

    // --- compile_transform tests ---

    #[test]
    fn compile_transform_json() {
        let json = serde_json::json!({
            "type": "json",
            "set": {"added": true},
            "remove": ["secret"]
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "json");
    }

    #[test]
    fn compile_transform_json_projection() {
        let json = serde_json::json!({
            "type": "json_projection",
            "fields": ["id", "name"],
            "exclude": false
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "json_projection");
    }

    #[test]
    fn compile_transform_json_schema() {
        let json = serde_json::json!({
            "type": "json_schema",
            "schema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"}
                }
            }
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "json_schema");
    }

    #[test]
    fn compile_transform_noop() {
        let json = serde_json::json!({"type": "noop"});
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "noop");
    }

    #[test]
    fn compile_transform_cel_script() {
        // Wave 5 day-5: pin the new `cel` transform compiles through
        // the standard dispatch path.
        let json = serde_json::json!({
            "type": "cel",
            "on_response": r#""hello-from-cel""#,
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "cel");
    }

    #[test]
    fn compile_transform_cel_script_via_expression_alias() {
        // The `expression:` alias mirrors the policy-side CEL field.
        let json = serde_json::json!({
            "type": "cel",
            "expression": r#""hello-from-cel""#,
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "cel");
    }

    #[test]
    fn compile_transform_cel_script_missing_expression_fails() {
        // Without `on_response` (or alias), the compiler must reject
        // the block so a misconfigured `type: cel` does not silently
        // become a no-op.
        let json = serde_json::json!({"type": "cel"});
        assert!(compile_transform(&json).is_err());
    }

    #[test]
    fn compile_transform_template() {
        let json = serde_json::json!({
            "type": "template",
            "template": "Hello, {{ name }}!"
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "template");
    }

    #[test]
    fn compile_transform_replace_strings() {
        let json = serde_json::json!({
            "type": "replace_strings",
            "replacements": [{"find": "foo", "replace": "bar"}]
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "replace_strings");
    }

    #[test]
    fn compile_transform_normalize() {
        let json = serde_json::json!({
            "type": "normalize",
            "trim": true,
            "collapse_whitespace": true
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "normalize");
    }

    #[test]
    fn compile_transform_encoding() {
        let json = serde_json::json!({
            "type": "encoding",
            "encoding": "base64_encode"
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "encoding");
    }

    #[test]
    fn compile_transform_format_convert() {
        let json = serde_json::json!({
            "type": "format_convert",
            "from": "json",
            "to": "yaml"
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "format_convert");
    }

    #[test]
    fn compile_transform_payload_limit() {
        let json = serde_json::json!({
            "type": "payload_limit",
            "max_size": 1024,
            "truncate": true
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "payload_limit");
    }

    #[test]
    fn compile_transform_discard() {
        let json = serde_json::json!({"type": "discard"});
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "discard");
    }

    #[test]
    fn compile_transform_sse_chunking() {
        let json = serde_json::json!({"type": "sse_chunking"});
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "sse_chunking");
    }

    #[test]
    fn compile_transform_lua_json() {
        let json = serde_json::json!({
            "type": "lua_json",
            "script": "body.extra = true\nreturn body"
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "lua_json");
    }

    #[test]
    fn compile_transform_javascript() {
        let json = serde_json::json!({
            "type": "javascript",
            "script": "function transform(body) { return body.toUpperCase(); }"
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "javascript");
    }

    #[test]
    fn compile_transform_js_json() {
        let json = serde_json::json!({
            "type": "js_json",
            "script": "function modify_json(data) { data.processed = true; return data; }"
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "js_json");
    }

    #[test]
    fn compile_policy_expression() {
        let json = serde_json::json!({
            "type": "expression",
            "expression": "request.method == \"GET\"",
            "deny_status": 403,
            "deny_message": "not allowed"
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "expression");
    }

    #[test]
    fn compile_policy_assertion() {
        let json = serde_json::json!({
            "type": "assertion",
            "expression": "response.status < 500",
            "name": "no-server-errors"
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "assertion");
    }

    #[test]
    fn compile_transform_unknown_type() {
        let json = serde_json::json!({"type": "xml_magic"});
        assert!(compile_transform(&json).is_err());
    }

    #[test]
    fn compile_transform_missing_type() {
        let json = serde_json::json!({"fields": ["id"]});
        assert!(compile_transform(&json).is_err());
    }

    // --- Go config compatibility tests ---

    #[test]
    fn compile_action_static_with_json_body() {
        let json = serde_json::json!({
            "type": "static",
            "status_code": 200,
            "content_type": "application/json",
            "json_body": {
                "message": "Hello from static",
                "version": "1.0"
            }
        });
        let action = compile_action(&json).unwrap();
        assert_eq!(action.action_type(), "static");

        if let Action::Static(s) = action {
            assert_eq!(s.status, 200);
            assert!(s.body.contains("Hello from static"));
            assert_eq!(s.content_type.as_deref(), Some("application/json"));
        } else {
            panic!("expected Action::Static");
        }
    }

    #[test]
    fn compile_action_static_json_body_defaults_content_type() {
        let json = serde_json::json!({
            "type": "static",
            "json_body": {"ok": true}
        });
        let action = compile_action(&json).unwrap();
        if let Action::Static(s) = action {
            assert_eq!(s.content_type.as_deref(), Some("application/json"));
            assert_eq!(s.body, r#"{"ok":true}"#);
        } else {
            panic!("expected Action::Static");
        }
    }

    #[test]
    fn compile_action_redirect_with_status_code() {
        let json = serde_json::json!({
            "type": "redirect",
            "url": "https://example.com",
            "status_code": 301
        });
        let action = compile_action(&json).unwrap();
        if let Action::Redirect(r) = action {
            assert_eq!(r.status, 301);
        } else {
            panic!("expected Action::Redirect");
        }
    }

    #[test]
    fn compile_auth_bearer_token_alias() {
        let json = serde_json::json!({
            "type": "bearer_token",
            "tokens": ["tok-1"]
        });
        let auth = compile_auth(&json).unwrap();
        assert_eq!(auth.auth_type(), "bearer");
    }

    #[test]
    fn compile_policy_ip_filtering_alias() {
        let json = serde_json::json!({
            "type": "ip_filtering",
            "whitelist": ["10.0.0.0/8"]
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "ip_filter");
    }

    #[test]
    fn compile_policy_security_headers_nested_format() {
        // Legacy Go nested format still compiles (backward compat).
        let json = serde_json::json!({
            "type": "security_headers",
            "x_frame_options": {
                "enabled": true,
                "value": "DENY"
            },
            "x_content_type_options": {
                "enabled": true,
                "no_sniff": true
            },
            "content_security_policy": {
                "enabled": true,
                "policy": "default-src 'self'"
            },
            "referrer_policy": {
                "enabled": true,
                "policy": "strict-origin-when-cross-origin"
            }
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "security_headers");

        if let Policy::SecHeaders(sec) = policy {
            assert_eq!(sec.x_frame_options.as_deref(), Some("DENY"));
            assert_eq!(sec.x_content_type_options.as_deref(), Some("nosniff"));
            assert_eq!(
                sec.content_security_policy
                    .as_ref()
                    .and_then(|s| s.as_legacy_str()),
                Some("default-src 'self'")
            );
            assert_eq!(
                sec.referrer_policy.as_deref(),
                Some("strict-origin-when-cross-origin")
            );
            // resolved_headers should still work via legacy fallback.
            let resolved = sec.resolved_headers();
            assert!(resolved.iter().any(|(n, _)| n == "x-frame-options"));
        } else {
            panic!("expected Policy::SecHeaders");
        }
    }
}
