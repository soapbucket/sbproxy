//! Config-to-module compilation.
//!
//! Bridges `sbproxy-config` (JSON values) to typed module enums by
//! reading the `type` discriminator and deserializing into the
//! appropriate variant.

use anyhow::{Context, Result};
use sbproxy_config::extract_type;
use sbproxy_extension::bundle::{
    build_javascript_action, build_javascript_policy, build_javascript_transform,
    build_wasm_action, build_wasm_policy, build_wasm_transform, BundleRegistry, LoadedBundleHook,
};

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
    RateLimitPolicy, RequestLimitPolicy, SecHeadersPolicy, SemanticConstraintPolicy, SriPolicy,
    WafPolicy,
};
use crate::transform::{
    A2aAgentCardRewriter, BoilerplateTransform, CelScriptTransform, CitationBlockTransform,
    CssTransform, DiscardTransform, EncodingTransform, FormatConvertTransform,
    HtmlToMarkdownTransform, HtmlTransform, JavaScriptTransform, JsJsonTransform,
    JsonEnvelopeTransform, JsonProjectionTransform, JsonSchemaTransform, JsonTransform,
    LuaJsonTransform, MarkdownTransform, NormalizeTransform, OptimizeHtmlTransform,
    PayloadLimitTransform, ReplaceStringsTransform, SseChunkingTransform, TemplateTransform,
    Transform, WasmTransform,
};

/// Compile a JSON action config into an Action enum variant.
pub fn compile_action(config: &serde_json::Value) -> Result<Action> {
    compile_action_for_origin_with_runtime(config, "", true, None)
}

/// Compile an action with dynamic bundle lookup after built-ins and linked plugins.
pub fn compile_action_with_registry(
    config: &serde_json::Value,
    registry: &dyn BundleRegistry,
) -> Result<Action> {
    let type_name = extract_type(config)?;
    if registry.action(&type_name).is_none() {
        return compile_action(config);
    }
    compile_action_for_origin_with_runtime(config, "", true, Some(registry))
}

/// Compile a JSON action for validation without constructing runtime clients.
pub fn compile_action_for_validation(config: &serde_json::Value) -> Result<Action> {
    compile_action_for_origin_with_runtime(config, "", false, None)
}

/// Compile an action with the stable identity of its owning origin.
pub fn compile_action_for_origin(config: &serde_json::Value, origin_id: &str) -> Result<Action> {
    compile_action_for_origin_with_runtime(config, origin_id, true, None)
}

/// Compile an origin action with dynamic bundle lookup after built-ins and linked plugins.
pub fn compile_action_for_origin_with_registry(
    config: &serde_json::Value,
    origin_id: &str,
    registry: &dyn BundleRegistry,
) -> Result<Action> {
    let type_name = extract_type(config)?;
    if registry.action(&type_name).is_none() {
        return compile_action_for_origin(config, origin_id);
    }
    compile_action_for_origin_with_runtime(config, origin_id, true, Some(registry))
}

/// Compile an origin action for validation without constructing runtime clients.
pub fn compile_action_for_origin_for_validation(
    config: &serde_json::Value,
    origin_id: &str,
) -> Result<Action> {
    compile_action_for_origin_with_runtime(config, origin_id, false, None)
}

fn compile_action_for_origin_with_runtime(
    config: &serde_json::Value,
    origin_id: &str,
    prepare_runtime: bool,
    registry: Option<&dyn BundleRegistry>,
) -> Result<Action> {
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
            LoadBalancerAction::from_config_for_origin(config.clone(), origin_id)?,
        ))),
        "ai_proxy" => {
            let action = if prepare_runtime {
                AiProxyAction::from_config(config.clone())?
            } else {
                AiProxyAction::from_config_for_validation(config.clone())?
            };
            Ok(Action::AiProxy(Box::new(action)))
        }
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
        other => match sbproxy_plugin::build_action_plugin(other, config.clone()) {
            Some(Ok(handler)) => Ok(Action::Plugin(crate::PluginAction::linked(handler))),
            Some(Err(error)) => {
                Err(error).with_context(|| format!("action plugin {other:?} factory failed"))
            }
            None => match registry.and_then(|registry| registry.action(other)) {
                Some(hook) => compile_bundle_action(hook, attachment_config(config, &[]))
                    .with_context(|| format!("action bundle {other:?} initialization failed")),
                None => anyhow::bail!("unknown action type: {}", other),
            },
        },
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
        "oidc" => Ok(Auth::Oidc(Box::new(
            crate::auth::oidc::OidcAuth::from_config(config.clone())?,
        ))),
        "noop" => Ok(Auth::Noop),
        other => {
            // Time + emit the factory invocation so operators can spot
            // panics or config-invalid plugins at config-compile time
            // (before traffic flows). The metric only fires when the
            // plugin name is one a registered factory recognises;
            // unknown names short-circuit with the existing bail.
            let start = std::time::Instant::now();
            let outcome = sbproxy_plugin::build_auth_plugin(other, config.clone());
            let elapsed = start.elapsed().as_secs_f64();
            match outcome {
                Some(Ok(provider)) => {
                    sbproxy_observe::metrics::record_plugin_init("auth", other, "ok", elapsed);
                    Ok(Auth::Plugin(provider))
                }
                Some(Err(e)) => {
                    sbproxy_observe::metrics::record_plugin_init(
                        "auth",
                        other,
                        "config_invalid",
                        elapsed,
                    );
                    Err(e).with_context(|| format!("auth plugin {other:?} factory failed"))
                }
                None => anyhow::bail!("unknown auth type: {}", other),
            }
        }
    }
}

/// Compile a single JSON policy config into a Policy enum variant.
pub fn compile_policy(config: &serde_json::Value) -> Result<Policy> {
    compile_policy_with_optional_registry(config, None)
}

/// Compile a policy with dynamic bundle lookup after built-ins and linked plugins.
pub fn compile_policy_with_registry(
    config: &serde_json::Value,
    registry: &dyn BundleRegistry,
) -> Result<Policy> {
    let type_name = extract_type(config)?;
    if registry.policy(&type_name).is_none() {
        return compile_policy(config);
    }
    compile_policy_with_optional_registry(config, Some(registry))
}

fn compile_policy_with_optional_registry(
    config: &serde_json::Value,
    registry: Option<&dyn BundleRegistry>,
) -> Result<Policy> {
    let type_name = extract_type(config)?;
    match type_name.as_str() {
        "rate_limit_budget" => Ok(Policy::RateLimitBudget(
            crate::policy::rate_limit_budget::RateLimitBudgetPolicy::from_config(config.clone())?,
        )),
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
        "rego" => Ok(Policy::Rego(
            crate::policy::rego::RegoPolicy::from_config(config.clone())
                .context("invalid `rego` policy")?,
        )),
        "expression" => Ok(Policy::Expression(ExpressionPolicy::from_config(
            config.clone(),
        )?)),
        "assertion" | "response_assertion" => Ok(Policy::Assertion(AssertionPolicy::from_config(
            config.clone(),
        )?)),
        "request_validator" => Ok(Policy::RequestValidator(
            crate::policy::RequestValidatorPolicy::from_config(config.clone())?,
        )),
        "content_digest" => Ok(Policy::ContentDigest(
            crate::policy::ContentDigestPolicy::from_config(config.clone())?,
        )),
        "concurrent_limit" | "concurrent_limiting" => Ok(Policy::ConcurrentLimit(
            crate::policy::ConcurrentLimitPolicy::from_config(config.clone())?,
        )),
        "ai_crawl_control" | "pay_per_crawl" => Ok(Policy::AiCrawl(
            crate::policy::AiCrawlControlPolicy::from_config(config.clone())?,
        )),
        "object_authz" | "bola" => Ok(Policy::ObjectAuthz(
            crate::policy::ObjectAuthzPolicy::from_config(config.clone())?,
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
        // WOR-203 PR 3b: NL-as-a-policy. The policy module wraps a
        // configured `JudgeClient` and routes each request through
        // the configured prompt template. See
        // `policy/semantic_constraint.rs` and
        // `docs/adr-policy-compilation.md`.
        "semantic_constraint" => Ok(Policy::SemanticConstraint(
            SemanticConstraintPolicy::from_config(config.clone())?,
        )),
        // WOR-506: per-`agent_id` semantic rate limit. The policy is
        // wrapped in `Arc` so the enforcer wrapper in `sbproxy-core`
        // can share the bucket state across the compiled chain
        // without cloning the LRU caches.
        "agent_budget" => Ok(Policy::AgentBudget(std::sync::Arc::new(
            crate::policy::AgentBudgetPolicy::from_config(config.clone())?,
        ))),
        other => match sbproxy_plugin::build_policy_plugin(other, config.clone()) {
            Some(Ok(enforcer)) => Ok(Policy::Plugin(crate::PluginPolicy::linked(enforcer))),
            Some(Err(error)) => {
                Err(error).with_context(|| format!("policy plugin {other:?} factory failed"))
            }
            None => match registry.and_then(|registry| registry.policy(other)) {
                Some(hook) => compile_bundle_policy(hook, attachment_config(config, &[]))
                    .with_context(|| format!("policy bundle {other:?} initialization failed")),
                None => anyhow::bail!("unknown policy type: {}", other),
            },
        },
    }
}

/// Compile a JSON transform config into a Transform enum variant.
pub fn compile_transform(config: &serde_json::Value) -> Result<Transform> {
    compile_transform_with_optional_registry(config, None)
}

/// Compile a transform with dynamic bundle lookup after built-ins and linked plugins.
pub fn compile_transform_with_registry(
    config: &serde_json::Value,
    registry: &dyn BundleRegistry,
) -> Result<Transform> {
    let type_name = extract_type(config)?;
    if registry.transform(&type_name).is_none() {
        return compile_transform(config);
    }
    compile_transform_with_optional_registry(config, Some(registry))
}

fn compile_transform_with_optional_registry(
    config: &serde_json::Value,
    registry: Option<&dyn BundleRegistry>,
) -> Result<Transform> {
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
        // WOR-234: A2A agent-card URL rewriter. The path-aware
        // dispatch wiring lives in `sbproxy-core::server`; this
        // arm only constructs the rewriter from operator config.
        "a2a_agent_card_rewrite" => Ok(Transform::A2aAgentCardRewrite(
            A2aAgentCardRewriter::from_config(config.clone())?,
        )),
        "noop" => Ok(Transform::Noop),
        other => match sbproxy_plugin::build_transform_plugin(other, config.clone()) {
            Some(Ok(handler)) => Ok(Transform::Plugin(crate::PluginTransform::linked(handler))),
            Some(Err(error)) => {
                Err(error).with_context(|| format!("transform plugin {other:?} factory failed"))
            }
            None => match registry.and_then(|registry| registry.transform(other)) {
                Some(hook) => compile_bundle_transform(
                    hook,
                    attachment_config(
                        config,
                        &[
                            "content_types",
                            "fail_on_error",
                            "failure_posture",
                            "max_body_size",
                            "disabled",
                        ],
                    ),
                )
                .with_context(|| format!("transform bundle {other:?} initialization failed")),
                None => anyhow::bail!("unknown transform type: {}", other),
            },
        },
    }
}

fn attachment_config(config: &serde_json::Value, wrapper_fields: &[&str]) -> serde_json::Value {
    let mut attachment = config.clone();
    if let Some(object) = attachment.as_object_mut() {
        object.remove("type");
        for field in wrapper_fields {
            object.remove(*field);
        }
    }
    attachment
}

fn compile_bundle_policy(hook: &LoadedBundleHook, config: serde_json::Value) -> Result<Policy> {
    let handler: Box<dyn sbproxy_plugin::PolicyEnforcer> = match hook.manifest().runtime {
        sbproxy_config::BundleRuntime::Javascript => {
            Box::new(build_javascript_policy(hook, config)?)
        }
        sbproxy_config::BundleRuntime::Wasm => Box::new(build_wasm_policy(hook, config)?),
        sbproxy_config::BundleRuntime::ProxyWasm => {
            anyhow::bail!("Proxy-Wasm bundles cannot provide policy hooks")
        }
    };
    Ok(Policy::Plugin(crate::PluginPolicy::dynamic(
        handler,
        dynamic_hook_metadata(hook)?,
    )))
}

fn compile_bundle_transform(
    hook: &LoadedBundleHook,
    config: serde_json::Value,
) -> Result<Transform> {
    let handler: Box<dyn sbproxy_plugin::TransformHandler> = match hook.manifest().runtime {
        sbproxy_config::BundleRuntime::Javascript => {
            Box::new(build_javascript_transform(hook, config)?)
        }
        sbproxy_config::BundleRuntime::Wasm => Box::new(build_wasm_transform(hook, config)?),
        sbproxy_config::BundleRuntime::ProxyWasm => {
            anyhow::bail!("Proxy-Wasm bundles cannot provide transform hooks")
        }
    };
    Ok(Transform::Plugin(crate::PluginTransform::dynamic(
        handler,
        dynamic_hook_metadata(hook)?,
    )))
}

fn compile_bundle_action(hook: &LoadedBundleHook, config: serde_json::Value) -> Result<Action> {
    let handler: Box<dyn sbproxy_plugin::ActionHandler> = match hook.manifest().runtime {
        sbproxy_config::BundleRuntime::Javascript => {
            Box::new(build_javascript_action(hook, config)?)
        }
        sbproxy_config::BundleRuntime::Wasm => Box::new(build_wasm_action(hook, config)?),
        sbproxy_config::BundleRuntime::ProxyWasm => {
            anyhow::bail!("Proxy-Wasm bundles cannot provide action hooks")
        }
    };
    Ok(Action::Plugin(crate::PluginAction::dynamic(
        handler,
        dynamic_hook_metadata(hook)?,
    )))
}

fn dynamic_hook_metadata(hook: &LoadedBundleHook) -> Result<crate::DynamicHookMetadata> {
    let maximum = usize::try_from(hook.manifest().sandbox.max_buffer_bytes)
        .context("bundle sandbox max_buffer_bytes does not fit this platform")?;
    Ok(crate::DynamicHookMetadata::new(
        hook.manifest().name.clone(),
        hook.hook().type_name.clone(),
        hook.manifest().runtime,
        hook.hook().execution.body_mode,
        maximum,
        hook.manifest().failure_posture,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use bytes::{Bytes, BytesMut};
    use sbproxy_config::{BundleBodyMode, ExtensionBundlesConfig, FailureMode};
    use sbproxy_extension::bundle::DynamicBundleRegistry;
    use sbproxy_plugin::{
        ActionHandler, ActionOutcome, ActionPluginRegistration, PluginResult, PolicyDecision,
        PolicyEnforcer, PolicyPluginRegistration, TransformContext, TransformHandler,
        TransformPluginRegistration,
    };
    use tempfile::TempDir;

    use super::*;

    struct CompileFixturePolicy;

    impl PolicyEnforcer for CompileFixturePolicy {
        fn policy_type(&self) -> &str {
            "compile_fixture_policy"
        }

        fn enforce(
            &self,
            _req: &http::Request<Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = PluginResult<PolicyDecision>> + Send + '_>> {
            Box::pin(async { Ok(PolicyDecision::Allow) })
        }
    }

    struct CompileFixtureTransform;

    impl TransformHandler for CompileFixtureTransform {
        fn transform_type(&self) -> &str {
            "compile_fixture_transform"
        }

        fn apply<'a>(
            &'a self,
            body: &'a mut BytesMut,
            _content_type: Option<&'a str>,
            _ctx: &'a TransformContext<'a>,
        ) -> Pin<Box<dyn Future<Output = PluginResult<()>> + Send + 'a>> {
            Box::pin(async move {
                body.clear();
                body.extend_from_slice(b"typed transform ran");
                Ok(())
            })
        }
    }

    struct CompileFixtureAction;

    impl ActionHandler for CompileFixtureAction {
        fn handler_type(&self) -> &str {
            "compile_fixture_action"
        }

        fn handle(
            &self,
            _req: &mut http::Request<Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> Pin<Box<dyn Future<Output = PluginResult<ActionOutcome>> + Send + '_>> {
            Box::pin(async {
                Ok(ActionOutcome::Response {
                    status: 204,
                    headers: Vec::new(),
                    body: Bytes::new(),
                })
            })
        }
    }

    inventory::submit! {
        PolicyPluginRegistration {
            name: "compile_fixture_policy",
            factory: |_config| Ok(Box::new(CompileFixturePolicy)),
        }
    }

    inventory::submit! {
        TransformPluginRegistration {
            name: "compile_fixture_transform",
            factory: |_config| Ok(Box::new(CompileFixtureTransform)),
        }
    }

    inventory::submit! {
        ActionPluginRegistration {
            name: "compile_fixture_action",
            factory: |_config| Ok(Box::new(CompileFixtureAction)),
        }
    }

    struct DynamicCompileFixture {
        _directory: TempDir,
        registry: Arc<DynamicBundleRegistry>,
    }

    fn dynamic_compile_fixture() -> DynamicCompileFixture {
        let directory = TempDir::new().expect("temporary bundle directory");
        let bundle = directory.path().join("compile-fixture");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        std::fs::write(
            bundle.join("entry.js"),
            r#"
                export function policy() {
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
                export function denyPolicy() {
                    return { version: "sbproxy-envelope/v1", decision: "deny", status: 403 };
                }
                export function transform() {
                    return { version: "sbproxy-envelope/v1", body_base64: "cmV3cml0dGVu" };
                }
                export function action(input) {
                    return {
                        version: "sbproxy-envelope/v1",
                        outcome: "response",
                        status: input.config.status,
                        headers: [],
                        body_base64: "ZHluYW1pYyBhY3Rpb24="
                    };
                }
            "#,
        )
        .expect("write JavaScript entry");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: compile-fixture
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: dynamic_compile_policy
    export: policy
  - kind: policy
    type: compile_fixture_policy
    export: denyPolicy
  - kind: transform
    type: dynamic_compile_transform
    export: transform
  - kind: action
    type: dynamic_compile_action
    export: action
    config_schema:
      type: object
      additionalProperties: false
      required: [status]
      properties:
        status:
          type: integer
          default: 207
  - kind: action
    type: noop
    export: action
"#,
        )
        .expect("write bundle manifest");
        let config = ExtensionBundlesConfig {
            bundles_dir: Some(directory.path().display().to_string()),
            sources: Vec::new(),
        };
        let registry = DynamicBundleRegistry::load(&config, directory.path(), &BTreeSet::new())
            .expect("load dynamic compile fixture");
        DynamicCompileFixture {
            _directory: directory,
            registry,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn extension_registry_compiles_dynamic_policy_transform_and_action() {
        let fixture = dynamic_compile_fixture();

        let policy = compile_policy_with_registry(
            &serde_json::json!({"type": "dynamic_compile_policy"}),
            fixture.registry.as_ref(),
        )
        .expect("dynamic policy should compile");
        let Policy::Plugin(policy) = policy else {
            panic!("dynamic policy should use plugin dispatch");
        };
        let (policy, policy_metadata) = policy.into_parts();
        let policy_metadata = policy_metadata
            .as_ref()
            .expect("dynamic policy should retain bundle execution metadata");
        assert_eq!(policy_metadata.bundle_id(), "compile-fixture");
        assert_eq!(policy_metadata.hook_type(), "dynamic_compile_policy");
        assert_eq!(policy_metadata.body_mode(), BundleBodyMode::Buffered);
        assert_eq!(policy_metadata.max_buffer_bytes(), 1_048_576);
        assert_eq!(policy_metadata.failure_posture(), FailureMode::Closed);
        let decision = policy
            .enforce(&http::Request::new(Bytes::new()), &mut ())
            .await
            .expect("dynamic policy should run");
        assert_eq!(decision, PolicyDecision::Allow);

        let transform = compile_transform_with_registry(
            &serde_json::json!({"type": "dynamic_compile_transform"}),
            fixture.registry.as_ref(),
        )
        .expect("dynamic transform should compile");
        let Transform::Plugin(transform) = transform else {
            panic!("dynamic transform should use plugin dispatch");
        };
        let mut body = BytesMut::from(&b"original"[..]);
        transform
            .handler()
            .apply(
                &mut body,
                Some("text/plain"),
                &TransformContext::new("fixture.example"),
            )
            .await
            .expect("dynamic transform should run");
        assert_eq!(&body[..], b"rewritten");

        let action = compile_action_with_registry(
            &serde_json::json!({"type": "dynamic_compile_action"}),
            fixture.registry.as_ref(),
        )
        .expect("dynamic action should compile with its schema default");
        let Action::Plugin(action) = action else {
            panic!("dynamic action should use plugin dispatch");
        };
        let action_metadata = action
            .dynamic_hook()
            .expect("dynamic action should retain bundle execution metadata");
        assert_eq!(action_metadata.bundle_id(), "compile-fixture");
        assert_eq!(action_metadata.hook_type(), "dynamic_compile_action");
        assert_eq!(action_metadata.body_mode(), BundleBodyMode::Buffered);
        assert_eq!(action_metadata.max_buffer_bytes(), 1_048_576);
        assert_eq!(action_metadata.failure_posture(), FailureMode::Closed);
        let mut request = http::Request::new(Bytes::new());
        let outcome = action
            .handler()
            .handle(&mut request, &mut ())
            .await
            .expect("dynamic action should run");
        assert_eq!(
            outcome,
            ActionOutcome::Response {
                status: 207,
                headers: Vec::new(),
                body: Bytes::from_static(b"dynamic action"),
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn extension_registry_keeps_builtin_and_static_precedence() {
        let fixture = dynamic_compile_fixture();

        let builtin = compile_action_with_registry(
            &serde_json::json!({"type": "noop"}),
            fixture.registry.as_ref(),
        )
        .expect("built-in action should compile");
        assert!(matches!(builtin, Action::Noop));

        let static_policy = compile_policy_with_registry(
            &serde_json::json!({"type": "compile_fixture_policy"}),
            fixture.registry.as_ref(),
        )
        .expect("linked static policy should compile");
        let Policy::Plugin(static_policy) = static_policy else {
            panic!("linked policy should use plugin dispatch");
        };
        let (static_policy, static_metadata) = static_policy.into_parts();
        assert!(
            static_metadata.is_none(),
            "linked policy should retain legacy body handling"
        );
        let decision = static_policy
            .enforce(&http::Request::new(Bytes::new()), &mut ())
            .await
            .expect("linked static policy should run");
        assert_eq!(decision, PolicyDecision::Allow);
    }

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
    fn compile_action_load_balancer_rejects_unknown_strategy_by_name() {
        let json = serde_json::json!({
            "type": "load_balancer",
            "strategy": "unknown-picker",
            "targets": [{"url": "http://one"}]
        });

        let error = compile_action(&json).expect_err("unknown strategy must fail");

        assert!(
            error.to_string().contains("unknown-picker"),
            "error should name the invalid strategy: {error}"
        );
    }

    #[test]
    fn compile_action_load_balancer_accepts_registered_strategy() {
        let json = serde_json::json!({
            "type": "load_balancer",
            "algorithm": "least_connections",
            "lb_method": "plugin",
            "strategy": "first-healthy",
            "strategy_config": {},
            "targets": [
                {
                    "url": "http://one",
                    "metadata": {"gpu_utilization": 0.8}
                },
                {
                    "url": "http://two",
                    "metadata": {"gpu_utilization": 0.2}
                }
            ]
        });

        let action = compile_action(&json).expect("registered strategy should compile");

        assert_eq!(action.action_type(), "load_balancer");
        let Action::LoadBalancer(load_balancer) = action else {
            panic!("expected load balancer action");
        };
        assert_eq!(
            load_balancer.targets[0].metadata["gpu_utilization"],
            serde_json::json!(0.8)
        );
    }

    #[test]
    fn compile_action_load_balancer_rejects_plugin_method_without_strategy() {
        let json = serde_json::json!({
            "type": "load_balancer",
            "lb_method": "plugin",
            "targets": [{"url": "http://one"}]
        });

        let error = compile_action(&json).expect_err("plugin method requires a strategy");

        assert!(
            error.to_string().contains("strategy"),
            "error should explain the missing strategy: {error}"
        );
    }

    #[test]
    fn compile_action_load_balancer_rejects_non_object_strategy_config() {
        let json = serde_json::json!({
            "type": "load_balancer",
            "strategy": "first-healthy",
            "strategy_config": ["not", "an", "object"],
            "targets": [{"url": "http://one"}]
        });

        let error = compile_action(&json).expect_err("strategy config must be an object");

        assert!(
            error.to_string().contains("strategy_config"),
            "error should identify strategy_config: {error}"
        );
    }

    #[test]
    fn compile_action_load_balancer_rejects_more_than_64_metadata_entries() {
        let metadata: serde_json::Map<String, serde_json::Value> = (0..65)
            .map(|index| (format!("key-{index}"), serde_json::json!(index)))
            .collect();
        let json = serde_json::json!({
            "type": "load_balancer",
            "targets": [{
                "url": "http://one",
                "metadata": metadata
            }]
        });

        let error = compile_action(&json).expect_err("metadata entry count must be bounded");

        assert!(
            error.to_string().contains("metadata"),
            "error should identify target metadata: {error}"
        );
    }

    #[test]
    fn compile_action_load_balancer_rejects_metadata_keys_over_64_bytes() {
        let json = serde_json::json!({
            "type": "load_balancer",
            "targets": [{
                "url": "http://one",
                "metadata": {
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": true
                }
            }]
        });

        let error = compile_action(&json).expect_err("metadata keys must be bounded");

        assert!(
            error.to_string().contains("64 bytes"),
            "error should explain the metadata key bound: {error}"
        );
    }

    #[test]
    fn compile_action_for_origin_builds_registered_strategy() {
        let json = serde_json::json!({
            "type": "load_balancer",
            "strategy": "bandit",
            "strategy_config": {"epsilon": 0.0},
            "targets": [
                {"url": "http://one"},
                {"url": "http://two"}
            ]
        });

        let action = compile_action_for_origin(&json, "origin-alpha")
            .expect("origin-aware action should compile");

        assert_eq!(action.action_type(), "load_balancer");
    }

    #[test]
    fn compile_action_unknown_type() {
        let json = serde_json::json!({"type": "unknown_thing"});
        assert!(compile_action(&json).is_err());
    }

    #[test]
    fn compile_action_builds_typed_static_plugin() {
        let action = compile_action(&serde_json::json!({"type": "compile_fixture_action"}))
            .expect("typed action registration must be reachable from config");

        assert_eq!(action.action_type(), "compile_fixture_action");
        assert!(matches!(action, Action::Plugin(_)));
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
    fn compile_policy_builds_typed_static_plugin() {
        let policy = compile_policy(&serde_json::json!({"type": "compile_fixture_policy"}))
            .expect("typed policy registration must be reachable from config");

        assert_eq!(policy.policy_type(), "compile_fixture_policy");
        assert!(matches!(policy, Policy::Plugin(_)));
    }

    #[test]
    fn compile_policy_rejects_removed_peer_pricing_preflight() {
        let json = serde_json::json!({"type": "peer_pricing_preflight"});
        let err = compile_policy(&json).expect_err("removed policy must not compile");
        assert!(err.to_string().contains("unknown policy type"));
    }

    #[test]
    fn compile_policy_accepts_live_semantic_constraint_shape() {
        let json = serde_json::json!({
            "type": "semantic_constraint",
            "prompt_template": "classify {{ request.path }}",
            "judge": {
                "endpoint": "http://127.0.0.1:1/",
                "api_key_env": "SBPROXY_SC_TEST_KEY"
            }
        });
        let policy = compile_policy(&json).expect("live semantic_constraint must compile");
        assert_eq!(policy.policy_type(), "semantic_constraint");
    }

    #[test]
    fn compile_policy_rejects_removed_semantic_constraint_policy_id() {
        let json = serde_json::json!({
            "type": "semantic_constraint",
            "prompt_template": "classify {{ request.path }}",
            "policy_id": "legacy-compiled-policy",
            "judge": {
                "endpoint": "http://127.0.0.1:1/",
                "api_key_env": "SBPROXY_SC_TEST_KEY"
            }
        });
        let err = compile_policy(&json).expect_err("removed policy_id must not compile");
        assert!(err.to_string().contains("policy_id"));
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

    #[test]
    fn compile_policy_agent_budget() {
        let json = serde_json::json!({
            "type": "agent_budget",
            "requests_per_minute": 60,
            "tokens_per_hour": 100000,
            "burst": 10,
            "on_exceed": "deny"
        });
        let policy = compile_policy(&json).unwrap();
        assert_eq!(policy.policy_type(), "agent_budget");
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
    fn compile_transform_builds_and_runs_typed_static_plugin() {
        let transform =
            compile_transform(&serde_json::json!({"type": "compile_fixture_transform"}))
                .expect("typed transform registration must be reachable from config");
        let mut body = BytesMut::from(&b"original"[..]);

        transform
            .apply(&mut body, Some("text/plain"))
            .expect("compiled typed transform must run without generic registration");

        assert_eq!(transform.transform_type(), "compile_fixture_transform");
        assert_eq!(&body[..], b"typed transform ran");
    }

    #[test]
    fn compile_transform_cel_script() {
        // Wave 5 day-5: pin the `cel` transform compiles through the
        // standard dispatch path. WOR-2362 moved the surface from a
        // body expression to header rules.
        let json = serde_json::json!({
            "type": "cel",
            "headers": [{"op": "set", "name": "x-hello", "value_expr": r#""hello-from-cel""#}],
        });
        let transform = compile_transform(&json).unwrap();
        assert_eq!(transform.transform_type(), "cel");
    }

    #[test]
    fn compile_transform_cel_script_body_expression_is_refused() {
        // WOR-2362: `on_response:` and its `expression:` alias both
        // replaced the whole response body with one scalar. Refused at
        // the compiler, not silently ignored.
        for key in ["on_response", "expression"] {
            let json = serde_json::json!({"type": "cel", key: r#""hello-from-cel""#});
            let err = compile_transform(&json)
                .expect_err("a body-replacing cel transform must not compile");
            assert!(
                err.to_string().contains(key),
                "the compiler error must name the key the operator wrote: {err}"
            );
        }
    }

    #[test]
    fn compile_transform_cel_script_missing_headers_fails() {
        // Without `headers:`, the compiler must reject the block so a
        // misconfigured `type: cel` does not silently become a no-op.
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
