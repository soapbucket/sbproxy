// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Reviewed exceptions to the build-time configuration-reader scan.
//!
//! Most schema keys need no entry: the reader guard finds their non-test Rust
//! field access. An entry exists only when the serialized name differs from the
//! Rust field or serde consumes it indirectly, or when the key is deliberately
//! retained without live behavior.
//!
//! Keep this list reviewed and small. Every stable exception names the concrete
//! consumer the scanner cannot infer. Every `ConfigOnly` exception tells an
//! operator exactly what does not happen and names the tracking issue.

use sbproxy_capability::{ConfigKeyCapability, SupportLevel};

const fn stable(path: &'static str, consumer: &'static str) -> ConfigKeyCapability {
    ConfigKeyCapability {
        path,
        support: SupportLevel::Stable,
        consumer: Some(consumer),
        note: None,
    }
}

const fn config_only(path: &'static str, note: &'static str) -> ConfigKeyCapability {
    ConfigKeyCapability {
        path,
        support: SupportLevel::ConfigOnly,
        consumer: None,
        note: Some(note),
    }
}

/// A key the compiler refuses outright.
///
/// Distinct from [`config_only`], which describes a key that is accepted and
/// quietly inert. An `Unsupported` key never reaches a running proxy at all:
/// `compile_config` rejects the whole document and says why. The note here is
/// the reviewer-facing record; the operator-facing text is the compile error.
const fn unsupported(path: &'static str, note: &'static str) -> ConfigKeyCapability {
    ConfigKeyCapability {
        path,
        support: SupportLevel::Unsupported,
        consumer: None,
        note: Some(note),
    }
}

const OUTBOUND_CREDENTIAL_CONSUMER: &str =
    "sbproxy_core::pipeline::parse_outbound_credential_config";

const AI_RESILIENCE_CONSUMER: &str = "sbproxy_ai::handler::AiHandlerConfig::router";

const LB_ZONE_NOTE: &str =
    "Target selection is not locality aware. The `locality_filter` that would read this label \
     has no production caller and no key turns it on, so the value only ever appears in the \
     admin targets view. Tracked by WOR-2246.";

/// Keys whose reader is indirect, plus deliberately inert compatibility keys.
///
/// Every override names one exact schema leaf. Parent entries never suppress
/// reader checks for children added later.
pub const CONFIG_KEY_OVERRIDES: &[ConfigKeyCapability] = &[
    stable(
        "access_log.capture_headers.max_value_bytes",
        "sbproxy_core::server::access_log::emit_access_log",
    ),
    stable(
        "access_log.capture_headers.redact_pii",
        "sbproxy_core::server::access_log::emit_access_log",
    ),
    stable(
        "access_log.output.type",
        "sbproxy_core::server::access_log::emit_access_log",
    ),
    config_only(
        "agent_classes.hosted_feed.bootstrap_keys[]",
        "The OSS resolver does not fetch hosted agent-class feeds; builtin and inline catalogs \
         remain live. Retained for compatibility and tracked by WOR-1976.",
    ),
    config_only(
        "agent_classes.hosted_feed.url",
        "The OSS resolver does not fetch hosted agent-class feeds; builtin and inline catalogs \
         remain live. Retained for compatibility and tracked by WOR-1976.",
    ),
    config_only(
        "audit.sink",
        "The OSS admin-action audit path always retains its bounded in-memory ring and mirrors \
         rows to tracing; this selector is not installed. Classified under WOR-1976.",
    ),
    // The eight entries below are the first from the module and AI-gateway
    // surface, which the generated schema cannot describe and which
    // `MODULE_CONFIG_ROOTS` now walks instead.
    //
    // Each of the five WOR-2245 audit findings is now accounted for, and
    // only one of them is still pinned. The two resilience blocks are wired,
    // so they are `stable` below: they were pinned config-only earlier on
    // this branch, against a main where the AI router was built without
    // breakers or a detector because the only installing path had no
    // callers. The handler calls `with_circuit_breakers` and
    // `with_outlier_detection` when the config asks now, so pinning them
    // would report working features as inert. Sticky sessions are the load
    // balancer's own warning. `routing.strategy: token_rate` is refused by
    // `compile_config` rather than pinned, which is the better answer and
    // the only available one: the key is `routing`, the key is read, and it
    // was one accepted *value* of it that did nothing, a shape no
    // reader-based check can see. Target zones are the remaining pin.
    stable(
        "origins.*.action.resilience.circuit_breaker.failure_threshold",
        AI_RESILIENCE_CONSUMER,
    ),
    stable(
        "origins.*.action.resilience.circuit_breaker.open_duration_secs",
        AI_RESILIENCE_CONSUMER,
    ),
    stable(
        "origins.*.action.resilience.circuit_breaker.success_threshold",
        AI_RESILIENCE_CONSUMER,
    ),
    stable(
        "origins.*.action.resilience.outlier_detection.ejection_duration_secs",
        AI_RESILIENCE_CONSUMER,
    ),
    stable(
        "origins.*.action.resilience.outlier_detection.min_requests",
        AI_RESILIENCE_CONSUMER,
    ),
    stable(
        "origins.*.action.resilience.outlier_detection.threshold",
        AI_RESILIENCE_CONSUMER,
    ),
    stable(
        "origins.*.action.resilience.outlier_detection.window_secs",
        AI_RESILIENCE_CONSUMER,
    ),
    // `origins.*.action.sticky.*` is deliberately absent. The load balancer
    // warns for it itself through `LoadBalancerAction::config_only_keys`,
    // using this registry's own message shape, so an entry here would be a
    // second competing classification of one field and two boot warnings for
    // it.
    config_only("origins.*.action.targets[].zone", LB_ZONE_NOTE),
    config_only(
        "origins.*.agent_skills[].max_clock_skew_secs",
        "Agent Skills responses do not yet carry the signed freshness headers this limit would \
         verify. Reserved under WOR-1976.",
    ),
    stable(
        "origins.*.agent_skills[].type",
        "sbproxy_config::compiler::compile_origin",
    ),
    stable(
        "origins.*.agents_json.flows[]",
        "sbproxy_modules::projections::agents_json::render",
    ),
    stable(
        "origins.*.agents_json.info.description",
        "sbproxy_modules::projections::agents_json::render",
    ),
    stable(
        "origins.*.agents_json.info.title",
        "sbproxy_modules::projections::agents_json::render",
    ),
    stable(
        "origins.*.agents_json.info.version",
        "sbproxy_modules::projections::agents_json::render",
    ),
    config_only(
        "origins.*.compression.level",
        "The OSS compressors use their library defaults; this compatibility value is not \
         applied. Classified under WOR-1976.",
    ),
    stable(
        "origins.*.compression.min_size",
        "sbproxy_config::compiler::compile_origin",
    ),
    config_only(
        "origins.*.connection_pool.idle_timeout_secs",
        "Pingora owns upstream connection pooling; these per-origin limits are not applied by \
         the OSS runtime. Classified under WOR-1976.",
    ),
    config_only(
        "origins.*.connection_pool.max_connections",
        "Pingora owns upstream connection pooling; these per-origin limits are not applied by \
         the OSS runtime. Classified under WOR-1976.",
    ),
    config_only(
        "origins.*.connection_pool.max_lifetime_secs",
        "Pingora owns upstream connection pooling; these per-origin limits are not applied by \
         the OSS runtime. Classified under WOR-1976.",
    ),
    config_only(
        "origins.*.cors.enable",
        "The presence of the cors block enables CORS; the legacy enable/enabled value itself is \
         ignored, including false. Classified under WOR-1976.",
    ),
    stable(
        "origins.*.credentials[].policies[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "origins.*.credentials[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    config_only(
        "origins.*.credentials[].attrs.budget.reset",
        "Credential lowering carries token and cost caps but does not install or enforce this \
         reset window. Reserved under WOR-1976.",
    ),
    stable(
        "origins.*.credentials[].attrs.tags[]",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    config_only(
        "origins.*.credentials[].attrs.team",
        "Credential lowering does not copy this attribution value into the virtual-key principal; \
         project, user, tags, metadata, and cost_center remain live. Reserved under WOR-1976.",
    ),
    config_only(
        "origins.*.forward_rules[].origin.hostname",
        "The inline forward origin runtime consumes its action and modifiers but does not expose \
         this informational hostname. Classified under WOR-1976.",
    ),
    stable(
        "origins.*.forward_rules[].origin.request_modifiers[].js_script",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    stable(
        "origins.*.forward_rules[].origin.request_modifiers[].lua_script",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    config_only(
        "origins.*.forward_rules[].origin.version",
        "The inline forward origin runtime consumes its action and modifiers but does not expose \
         this informational version. Classified under WOR-1976.",
    ),
    config_only(
        "origins.*.forward_rules[].origin.workspace_id",
        "The inline forward origin runtime consumes its action and modifiers but does not apply \
         this informational workspace identifier. Classified under WOR-1976.",
    ),
    stable(
        "origins.*.forward_rules[].parameters[].description",
        "sbproxy_openapi::build",
    ),
    stable(
        "origins.*.forward_rules[].parameters[].in",
        "sbproxy_openapi::build",
    ),
    stable(
        "origins.*.forward_rules[].parameters[].name",
        "sbproxy_openapi::build",
    ),
    stable(
        "origins.*.forward_rules[].parameters[].required",
        "sbproxy_openapi::build",
    ),
    stable(
        "origins.*.forward_rules[].parameters[].schema",
        "sbproxy_openapi::build",
    ),
    // The body matcher is compiled from the untyped `serde_json::Value` the
    // forward rule carries, so `compile_body_matcher` reads `pointer`,
    // `value`, `prefix`, and `max_bytes` off the JSON object rather than off
    // a typed `BodyMatcher`. The scanner looks for a read of the config
    // struct's field and cannot follow that hop, which is why these four are
    // pinned by hand rather than resolved automatically. The reads are at
    // `sbproxy_core::pipeline::compile_body_matcher`; `max_bytes` is read a
    // second time by `forward_rule_body_cap` to decide whether to buffer.
    stable(
        "origins.*.forward_rules[].rules[].body.max_bytes",
        "sbproxy_core::pipeline::compile_body_matcher",
    ),
    stable(
        "origins.*.forward_rules[].rules[].body.pointer",
        "sbproxy_core::pipeline::compile_body_matcher",
    ),
    stable(
        "origins.*.forward_rules[].rules[].body.prefix",
        "sbproxy_core::pipeline::compile_body_matcher",
    ),
    stable(
        "origins.*.forward_rules[].rules[].body.value",
        "sbproxy_core::pipeline::compile_body_matcher",
    ),
    stable(
        "origins.*.forward_rules[].rules[].header.name",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    stable(
        "origins.*.forward_rules[].rules[].header.prefix",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    stable(
        "origins.*.forward_rules[].rules[].header.value",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    stable(
        "origins.*.forward_rules[].rules[].match",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    stable(
        "origins.*.forward_rules[].rules[].query.name",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    stable(
        "origins.*.forward_rules[].rules[].query.value",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    stable(
        "origins.*.hsts.max_age",
        "sbproxy_config::compiler::compile_origin",
    ),
    stable(
        "origins.*.observability.log.redact.disable[]",
        "sbproxy_core::server::lifecycle::install_op_redact_state",
    ),
    stable(
        "origins.*.observability.log.redact.fields[]",
        "sbproxy_core::server::lifecycle::install_op_redact_state",
    ),
    stable(
        "origins.*.observability.log.sinks[].output.type",
        "sbproxy_core::server::lifecycle::compile_one_sink",
    ),
    stable(
        "origins.*.outbound_credential.act_depth_cap",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.allowed_audiences[]",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.audience",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.client_id",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.client_secret",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.dpop.alg",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.dpop.jwk",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.dpop.key",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.header",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.scheme",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.scope",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.secret",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.subject_token_issuers[]",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.token_endpoint",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.outbound_credential.type",
        OUTBOUND_CREDENTIAL_CONSUMER,
    ),
    stable(
        "origins.*.olp.introspect.auth.mode",
        "sbproxy_core::server::request_phase::handle_olp_introspect_or_revoke",
    ),
    stable(
        "origins.*.olp.introspect.realm",
        "sbproxy_core::server::request_phase::handle_olp_introspect_or_revoke",
    ),
    stable(
        "origins.*.olp.introspect.revocation_store.backend",
        "sbproxy_core::server::request_phase::handle_olp_introspect_or_revoke",
    ),
    stable(
        "origins.*.proxy_status.enabled",
        "sbproxy_config::compiler::compile_origin",
    ),
    stable(
        "origins.*.proxy_status.identity",
        "sbproxy_config::compiler::compile_origin",
    ),
    config_only(
        "origins.*.rate_limit_headers",
        "The OSS runtime does not consume the origin-level block; configure headers on the live \
         rate-limit policy instead. Classified under WOR-1976.",
    ),
    stable(
        "origins.*.request_modifiers[].js_script",
        "sbproxy_config::compiler::compile_origin",
    ),
    stable(
        "origins.*.request_modifiers[].lua_script",
        "sbproxy_config::compiler::compile_origin",
    ),
    config_only(
        "origins.*.response_modifiers[].status.text",
        "The response path applies the configured status code but does not emit this optional \
         reason text. Classified under WOR-1976.",
    ),
    config_only(
        "origins.*.sessions.ttl_seconds",
        "Session capture does not expire its in-process request-ring entries from this value; it \
         is a reserved retention hint under WOR-1976.",
    ),
    stable(
        "origins.*.sessions.budget.max_per_window",
        "sbproxy_observe::capture::budget_admits",
    ),
    stable(
        "origins.*.sessions.budget.window_seconds",
        "sbproxy_observe::capture::budget_admits",
    ),
    config_only(
        "origins.*.traffic_capture",
        "The OSS runtime has no traffic-capture consumer; use the live mirror block or an \
         out-of-tree extension. Classified under WOR-1976.",
    ),
    stable(
        "origins.*.user.budget.max_per_window",
        "sbproxy_observe::capture::budget_admits",
    ),
    stable(
        "origins.*.user.budget.window_seconds",
        "sbproxy_observe::capture::budget_admits",
    ),
    stable(
        "proxy.alerting.channels[].type",
        "sbproxy::map_alert_channel",
    ),
    stable(
        "proxy.cache_reserve.backend.type",
        "sbproxy_core::pipeline::build_cache_reserve",
    ),
    stable(
        "proxy.acme.challenge_types[]",
        "sbproxy_core::server::lifecycle::run",
    ),
    stable(
        "proxy.acme.directory_url",
        "sbproxy_core::server::lifecycle::run",
    ),
    stable("proxy.acme.email", "sbproxy_core::server::lifecycle::run"),
    stable(
        "proxy.acme.renew_before_days",
        "sbproxy_core::server::lifecycle::run",
    ),
    stable(
        "proxy.admin.tls.cert",
        "sbproxy_core::server::lifecycle::run",
    ),
    stable(
        "proxy.admin.tls.key",
        "sbproxy_core::server::lifecycle::run",
    ),
    stable(
        "proxy.correlation_id.echo_response",
        "sbproxy_core::server::lifecycle::run",
    ),
    config_only(
        "proxy.credentials[].attrs.budget.reset",
        "Credential lowering carries token and cost caps but does not install or enforce this \
         reset window. Reserved under WOR-1976.",
    ),
    stable(
        "proxy.credentials[].attrs.tags[]",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    config_only(
        "proxy.credentials[].attrs.team",
        "Credential lowering does not copy this attribution value into the virtual-key principal; \
         project, user, tags, metadata, and cost_center remain live. Reserved under WOR-1976.",
    ),
    stable(
        "proxy.credentials[].policies[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "proxy.credentials[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    config_only(
        "proxy.device_parser_file",
        "The current pure-Rust device parser does not load an operator regex catalog. Reserved \
         for the parser swap tracked under WOR-1976.",
    ),
    config_only(
        "proxy.http3.enabled",
        "This build does not serve HTTP/3; enabled=true fails config compilation. Native HTTP/3 \
         support is tracked in WOR-1969.",
    ),
    config_only(
        "proxy.http3.idle_timeout_secs",
        "This build does not serve HTTP/3, so the QUIC idle timeout is not installed. Native \
         HTTP/3 support is tracked in WOR-1969.",
    ),
    config_only(
        "proxy.http3.max_streams",
        "This build does not serve HTTP/3, so the QUIC stream limit is not installed. Native \
         HTTP/3 support is tracked in WOR-1969.",
    ),
    stable(
        "proxy.http_client_timeouts.bot_auth_directory_client_secs",
        "sbproxy_core::server::bot_auth_directory_client",
    ),
    stable(
        "proxy.http_client_timeouts.callback_client_secs",
        "sbproxy_core::server::callbacks::callback_client",
    ),
    stable(
        "proxy.http_client_timeouts.forward_auth_client_secs",
        "sbproxy_core::server::forward_auth_client",
    ),
    stable(
        "proxy.http_client_timeouts.forward_auth_request_secs",
        "sbproxy_core::server::check_forward_auth",
    ),
    stable(
        "proxy.http_client_timeouts.swr_client_secs",
        "sbproxy_core::server::swr_client",
    ),
    stable(
        "proxy.key_management.governance.backend.type",
        "sbproxy_core::key_plane::build_governance_store",
    ),
    // Both `failure_mode` keys below are read only through the
    // `failure_posture()` accessor on their owning config struct, so the
    // scanner sees a method call rather than a field read at the site that
    // acts on the value. WOR-2121.
    stable(
        "proxy.key_management.governance.failure_mode",
        "sbproxy_core::server::ai_dispatch::handle_ai_proxy",
    ),
    stable(
        "proxy.key_management.governance.failure_posture",
        "sbproxy_core::server::ai_dispatch::handle_ai_proxy",
    ),
    stable(
        "proxy.key_management.failure_posture",
        "sbproxy_core::key_plane::prepare_key_plane",
    ),
    config_only(
        "proxy.key_management.governance.key_introspection",
        "The caller-only key-introspection route is not installed by the OSS runtime. Retained \
         for compatibility and classified under WOR-1976.",
    ),
    stable(
        "proxy.key_management.governance.missing_rate",
        "sbproxy_core::server::ai_dispatch::handle_ai_proxy",
    ),
    stable(
        "proxy.key_management.governance.require_governed_key",
        "sbproxy_core::server::ai_dispatch::handle_ai_proxy",
    ),
    config_only(
        "proxy.key_management.store.redis_source_of_truth",
        "Selecting the Redis store already makes Redis authoritative; this legacy boolean does \
         not alter runtime behavior. Classified under WOR-1976.",
    ),
    unsupported(
        "proxy.messenger_settings.driver",
        "WOR-2166: the shared message bus has no runtime consumer. Nothing subscribes to a topic \
         and nothing publishes on one, so a configured bus moved no events between replicas. \
         `compile_config` rejects the whole block and points at `proxy.config_authority` for \
         config distribution and `POST /admin/cache/purge` for cache invalidation.",
    ),
    unsupported(
        "proxy.messenger_settings.params.*",
        "WOR-2166: driver parameters for the shared message bus, which has no runtime consumer. \
         Never read: `compile_config` rejects the block before any driver is constructed.",
    ),
    stable(
        "proxy.model_host.cache.budget_gib",
        "sbproxy_core::server::model_host::compile_runtime_candidate",
    ),
    stable(
        "proxy.model_host.engines.*.acceleration",
        "sbproxy_core::server::model_host::compile_runtime_candidate",
    ),
    stable(
        "proxy.model_host.engines.*.path",
        "sbproxy_core::server::model_host::compile_runtime_candidate",
    ),
    stable(
        "proxy.model_host.engines.*.shm_size_gib",
        "sbproxy_core::server::model_host::compile_runtime_candidate",
    ),
    config_only(
        "proxy.observability.log.level",
        "The active tracing filter is selected by CLI/environment precedence, not this YAML \
         value. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.observability.log.format",
        "The active tracing format is selected by CLI/environment precedence, not this YAML \
         value. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.observability.log.sampling.debug",
        "The process logger currently uses its fixed sampling defaults; these YAML rates are not \
         installed. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.observability.log.sampling.info",
        "The process logger currently uses its fixed sampling defaults; these YAML rates are not \
         installed. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.observability.log.sampling.trace",
        "The process logger currently uses its fixed sampling defaults; these YAML rates are not \
         installed. Classified under WOR-1976.",
    ),
    stable(
        "proxy.observability.log.sinks[].output.type",
        "sbproxy_core::server::lifecycle::compile_one_sink",
    ),
    config_only(
        "proxy.scripting.javascript.sandbox.budget_ms",
        "QuickJS engines currently use their built-in sandbox defaults; this YAML block is not \
         installed into JsEngine::new. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.scripting.javascript.sandbox.memory_mb",
        "QuickJS engines currently use their built-in sandbox defaults; this YAML block is not \
         installed into JsEngine::new. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.scripting.javascript.sandbox.stack_kb",
        "QuickJS engines currently use their built-in sandbox defaults; this YAML block is not \
         installed into JsEngine::new. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.secrets.backend",
        "The legacy single-backend selector is not consulted; declare named entries under \
         proxy.secrets.backends. Classified under WOR-1976.",
    ),
    stable(
        "proxy.secrets.backends[].auth.access_key_id",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.external_id",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.external_account_file.path",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.jwt_path",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.mount",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.role",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.role_arn",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.role_id",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.secret_access_key",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.secret_id",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.service_account_key_file.path",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.service_account_key_json.json",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.service_principal.authority",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.service_principal.client_id",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.service_principal.client_secret",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.service_principal.tenant_id",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.session_name",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.session_token",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.token",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.type",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].auth.user_assigned_identity.client_id",
        "sbproxy::install_secret_resolver",
    ),
    stable(
        "proxy.secrets.backends[].type",
        "sbproxy::install_secret_resolver",
    ),
    config_only(
        "proxy.secrets.fallback",
        "The named-backend resolver fails unresolved provider URIs loudly and does not consult \
         this legacy fallback selector. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.secrets.hashicorp.addr",
        "The legacy HashiCorp block is not installed; configure a hashicorp entry under \
         proxy.secrets.backends. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.secrets.hashicorp.mount",
        "The legacy HashiCorp block is not installed; configure a hashicorp entry under \
         proxy.secrets.backends. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.secrets.hashicorp.token",
        "The legacy HashiCorp block is not installed; configure a hashicorp entry under \
         proxy.secrets.backends. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.secrets.map.*",
        "The secret:<name> form was removed; use secret://<backend>/<name>. Retained for \
         compatibility and tracked by WOR-1976.",
    ),
    config_only(
        "proxy.secrets.rotation.grace_period_secs",
        "The OSS process resolver does not schedule re-resolution or a dual-value grace window \
         from this block. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.secrets.rotation.re_resolve_interval_secs",
        "The OSS process resolver does not schedule re-resolution or a dual-value grace window \
         from this block. Classified under WOR-1976.",
    ),
    config_only(
        "proxy.tenants[].credentials[].attrs.budget.reset",
        "Credential lowering carries token and cost caps but does not install or enforce this \
         reset window. Reserved under WOR-1976.",
    ),
    stable(
        "proxy.tenants[].credentials[].attrs.tags[]",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    config_only(
        "proxy.tenants[].credentials[].attrs.team",
        "Credential lowering does not copy this attribution value into the virtual-key principal; \
         project, user, tags, metadata, and cost_center remain live. Reserved under WOR-1976.",
    ),
    stable(
        "proxy.tenants[].credentials[].policies[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "proxy.tenants[].credentials[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "proxy.tenants[].observability.log.redact.disable[]",
        "sbproxy_core::server::lifecycle::install_op_redact_state",
    ),
    stable(
        "proxy.tenants[].observability.log.redact.fields[]",
        "sbproxy_core::server::lifecycle::install_op_redact_state",
    ),
    stable(
        "proxy.tenants[].observability.log.sinks[].output.type",
        "sbproxy_core::server::lifecycle::compile_one_sink",
    ),
    stable("source.kind", "sbproxy_config::source::load_with_depth"),
];

// --- Module and AI-gateway surface (WOR-2245) ---
//
// Everything below drives the build-time guard and has no runtime consumer,
// so it is compiled only for tests. `CONFIG_KEY_OVERRIDES` above is the
// opposite: it is production data because the boot warning reads it.
//
// The guard walks the generated `ConfigFile` schema, and `ConfigFile` types
// `action`, `authentication`, `policies` and `transforms` as
// `serde_json::Value` on purpose, because modules are pluggable and this
// crate must not need to name their types. The consequence is that no key
// below any of them reaches the schema: `schemas/sb-config.schema.json` is
// 419KB and contains no occurrence of `resilience`, `circuit_breaker`,
// `outlier_detection` or `load_balancer`. Every confirmed-dead config
// finding from the WOR-2245 audit sat in that hole.
//
// A root closes the hole for one subtree by naming the Rust type the
// subtree deserializes into, which the scan walks with the same `syn` index
// it already uses to prove reads.

#[cfg(test)]
use sbproxy_capability::config_scan::{
    ModuleConfigRoot, ModuleCoverage, ModuleCoverageState, ModuleDispatch, ModuleRootEnforcement,
};

#[cfg(test)]
const MODULE_TRIAGE_NOTE: &str = "not yet walked; classified under WOR-2245";

#[cfg(test)]
const fn deferred(kind: &'static str, name: &'static str) -> ModuleCoverage {
    ModuleCoverage {
        kind,
        name,
        state: ModuleCoverageState::Deferred(MODULE_TRIAGE_NOTE),
    }
}

#[cfg(test)]
const fn rooted(kind: &'static str, name: &'static str) -> ModuleCoverage {
    ModuleCoverage {
        kind,
        name,
        state: ModuleCoverageState::Rooted,
    }
}

/// Configuration subtrees the generated schema cannot reach.
///
/// Both entries are `ReportOnly` for now. Their findings print, they do not
/// fail the build, and the ones already traced by hand are pinned in
/// `CONFIG_KEY_OVERRIDES` so an operator who sets them is warned at boot.
/// Turning a root `Enforced` is a separate, deliberate step: it means
/// somebody has read every finding under it and either wired the key or
/// pinned it. Doing that on the same change that widened the scan would
/// fail the build on five pre-existing dead keys, and a check that does
/// that gets reverted rather than fixed.
#[cfg(test)]
const MODULE_CONFIG_ROOTS: &[ModuleConfigRoot] = &[
    ModuleConfigRoot {
        path: "origins.*.action",
        rust_type: "sbproxy_modules::action::loadbalancer::LoadBalancerConfig",
        enforcement: ModuleRootEnforcement::ReportOnly(
            "target zones are dead here and are pinned above, and the load balancer warns for \
             sticky itself; the rest of the load_balancer surface has not been triaged. \
             WOR-2246.",
        ),
    },
    // Rooted at the subtree rather than at `AiHandlerConfig`, deliberately.
    // The whole AI action is several hundred keys and nobody has triaged
    // them; `resilience` is where the confirmed-dead ones are. A root is a
    // path and a type, so coverage can grow a subtree at a time instead of
    // waiting for one very large review.
    ModuleConfigRoot {
        path: "origins.*.action.resilience",
        rust_type: "sbproxy_ai::handler::AiResilienceConfig",
        enforcement: ModuleRootEnforcement::ReportOnly(
            "the circuit-breaker and outlier-detection blocks are wired and are pinned stable \
             above; retry_policy and llm_aware have not been triaged. WOR-2233.",
        ),
    },
];

/// Where the config compiler turns an operator's `type:` string into a
/// module.
#[cfg(test)]
const MODULE_DISPATCHES: &[ModuleDispatch] = &[
    ModuleDispatch {
        kind: "action",
        source: "crates/sbproxy-modules/src/compile.rs",
        function: "compile_action_for_origin_with_runtime",
    },
    ModuleDispatch {
        kind: "auth",
        source: "crates/sbproxy-modules/src/compile.rs",
        function: "compile_auth",
    },
    // Both name the private `_with_optional_registry` function rather
    // than the `pub` wrapper. Bundle support turned the wrapper into a
    // one-line delegation, so the `type:` table lives one level down.
    ModuleDispatch {
        kind: "policy",
        source: "crates/sbproxy-modules/src/compile.rs",
        function: "compile_policy_with_optional_registry",
    },
    ModuleDispatch {
        kind: "transform",
        source: "crates/sbproxy-modules/src/compile.rs",
        function: "compile_transform_with_optional_registry",
    },
];

/// Every module an operator can name, and whether its config is walked.
///
/// This is what makes forgetting impossible rather than merely unlikely. A
/// registry of roots alone covers the modules somebody remembered; a module
/// added next month would go unguarded until the next audit noticed. Here
/// the guard reads the dispatch tables themselves, so a new `type:` string
/// that reaches operators without an entry below fails the build on the day
/// it lands. Deferring is a legitimate answer and costs one line: the point
/// is that the decision gets recorded instead of skipped.
///
/// Aliases are separate entries because an operator can write either
/// spelling. Checked in both directions, so a removed module cannot leave a
/// stale classification behind.
#[cfg(test)]
const MODULE_COVERAGE: &[ModuleCoverage] = &[
    rooted("action", "load_balancer"),
    // Only the `resilience` subtree of the AI action has a root today.
    deferred("action", "ai_proxy"),
    deferred("action", "a2a"),
    deferred("action", "beacon"),
    deferred("action", "echo"),
    deferred("action", "graphql"),
    deferred("action", "grpc"),
    deferred("action", "mcp"),
    deferred("action", "mock"),
    deferred("action", "noop"),
    deferred("action", "proxy"),
    deferred("action", "redirect"),
    deferred("action", "static"),
    deferred("action", "storage"),
    deferred("action", "websocket"),
    deferred("auth", "api_key"),
    deferred("auth", "basic_auth"),
    deferred("auth", "bearer"),
    deferred("auth", "bearer_token"),
    deferred("auth", "bot_auth"),
    deferred("auth", "cap"),
    deferred("auth", "digest"),
    deferred("auth", "forward"),
    deferred("auth", "forward_auth"),
    deferred("auth", "jwt"),
    deferred("auth", "noop"),
    deferred("auth", "oidc"),
    deferred("auth", "web_bot_auth"),
    deferred("policy", "a2a"),
    deferred("policy", "agent_budget"),
    deferred("policy", "agent_class"),
    deferred("policy", "ai_crawl_control"),
    deferred("policy", "assertion"),
    deferred("policy", "bola"),
    deferred("policy", "concurrent_limit"),
    deferred("policy", "concurrent_limiting"),
    deferred("policy", "content_digest"),
    deferred("policy", "csrf"),
    deferred("policy", "ddos"),
    deferred("policy", "ddos_protection"),
    deferred("policy", "dlp"),
    deferred("policy", "exposed_credentials"),
    deferred("policy", "expression"),
    deferred("policy", "http_framing"),
    deferred("policy", "ip_filter"),
    deferred("policy", "ip_filtering"),
    deferred("policy", "leaked_credentials"),
    deferred("policy", "object_authz"),
    deferred("policy", "openapi_validation"),
    deferred("policy", "page_shield"),
    deferred("policy", "pay_per_crawl"),
    deferred("policy", "prompt_injection_v2"),
    deferred("policy", "rate_limit_budget"),
    deferred("policy", "rate_limiting"),
    deferred("policy", "request_limit"),
    deferred("policy", "request_limiting"),
    deferred("policy", "request_validator"),
    deferred("policy", "response_assertion"),
    deferred("policy", "security_headers"),
    deferred("policy", "semantic_constraint"),
    deferred("policy", "sri"),
    deferred("policy", "waf"),
    deferred("transform", "a2a_agent_card_rewrite"),
    deferred("transform", "boilerplate"),
    deferred("transform", "cel"),
    deferred("transform", "citation_block"),
    deferred("transform", "css"),
    deferred("transform", "discard"),
    deferred("transform", "encoding"),
    deferred("transform", "format_convert"),
    deferred("transform", "html"),
    deferred("transform", "html_to_markdown"),
    deferred("transform", "javascript"),
    deferred("transform", "js_json"),
    deferred("transform", "json"),
    deferred("transform", "json_envelope"),
    deferred("transform", "json_projection"),
    deferred("transform", "json_schema"),
    deferred("transform", "lua_json"),
    deferred("transform", "markdown"),
    deferred("transform", "noop"),
    deferred("transform", "normalize"),
    deferred("transform", "optimize_html"),
    deferred("transform", "payload_limit"),
    deferred("transform", "replace_strings"),
    deferred("transform", "sse_chunking"),
    deferred("transform", "template"),
    deferred("transform", "wasm"),
];

const CONFIG_KEY_ALIASES: &[(&str, &str)] = &[
    (
        "agent_classes.hosted_feed.bootstrap_keys",
        "agent_classes.hosted_feed.bootstrap_keys[]",
    ),
    ("origins.*.cors.enabled", "origins.*.cors.enable"),
    ("proxy.secrets.map", "proxy.secrets.map.*"),
];

/// Return the config-only registry entries explicitly present in raw YAML.
///
/// This walks the operator-authored value rather than a deserialized
/// [`crate::types::ConfigFile`], so serde defaults do not produce warnings for
/// omitted keys. Registry `*` segments match map values and `[]` segments match
/// array elements.
pub(crate) fn configured_config_only_keys(
    yaml: &serde_yaml::Value,
) -> Vec<&'static ConfigKeyCapability> {
    CONFIG_KEY_OVERRIDES
        .iter()
        .filter(|entry| entry.support == SupportLevel::ConfigOnly)
        .filter(|entry| {
            std::iter::once(entry.path)
                .chain(
                    CONFIG_KEY_ALIASES.iter().filter_map(|(alias, canonical)| {
                        (*canonical == entry.path).then_some(*alias)
                    }),
                )
                .any(|path| {
                    let segments: Vec<&str> = path.split('.').collect();
                    yaml_path_exists(yaml, &segments)
                })
        })
        .collect()
}

fn yaml_path_exists(value: &serde_yaml::Value, segments: &[&str]) -> bool {
    let Some((segment, rest)) = segments.split_first() else {
        return true;
    };

    if *segment == "*" {
        return value
            .as_mapping()
            .is_some_and(|map| map.values().any(|child| yaml_path_exists(child, rest)));
    }

    if let Some(name) = segment.strip_suffix("[]") {
        return value
            .get(name)
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|items| items.iter().any(|child| yaml_path_exists(child, rest)));
    }

    value
        .get(*segment)
        .is_some_and(|child| yaml_path_exists(child, rest))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use sbproxy_capability::config_scan::{
        schema_key_paths, verify_config_readers_with_modules, verify_module_dispatch_coverage,
    };
    use sbproxy_capability::scan::rust_sources;

    #[test]
    fn every_config_only_key_names_its_tracking_issue() {
        for key in CONFIG_KEY_OVERRIDES
            .iter()
            .filter(|key| key.support == SupportLevel::ConfigOnly)
        {
            let note = key.note.unwrap_or("");
            assert!(
                note.contains("WOR-"),
                "config-only key {} must explain itself and point at the work that tracks \
                 it: '{note}'",
                key.path
            );
        }
    }

    #[test]
    fn alerting_is_wired_and_no_longer_classified_inert() {
        assert!(!CONFIG_KEY_OVERRIDES
            .iter()
            .any(|key| key.path == "proxy.alerting"));
    }

    #[test]
    fn configured_config_only_keys_follow_maps_and_arrays_without_defaults() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
proxy:
  observability:
    log:
      sampling: { info: 0.5 }
origins:
  api.example:
    agent_skills:
      - type: skill-md
        name: deploy
        description: deploy
        url: /deploy.md
        max_clock_skew_secs: 30
    action: { type: static, status_code: 200 }
"#,
        )
        .expect("fixture parses");

        let configured = configured_config_only_keys(&yaml);
        let paths: Vec<&str> = configured.iter().map(|key| key.path).collect();

        assert_eq!(
            paths,
            [
                "origins.*.agent_skills[].max_clock_skew_secs",
                "proxy.observability.log.sampling.info",
            ]
        );
        assert!(!paths.contains(&"origins.*.agent_skills[].type"));
        assert!(!paths.contains(&"proxy.http3"));
    }

    #[test]
    fn credential_team_warns_at_every_supported_scope() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
proxy:
  credentials:
    - attrs: { team: global }
  tenants:
    - credentials:
        - attrs: { team: tenant }
origins:
  api.example:
    credentials:
      - attrs: { team: origin }
"#,
        )
        .expect("fixture parses");

        let paths: Vec<&str> = configured_config_only_keys(&yaml)
            .iter()
            .map(|key| key.path)
            .collect();

        assert_eq!(
            paths,
            [
                "origins.*.credentials[].attrs.team",
                "proxy.credentials[].attrs.team",
                "proxy.tenants[].credentials[].attrs.team",
            ]
        );
    }

    #[test]
    fn empty_config_only_collections_still_warn_when_explicitly_authored() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
agent_classes:
  hosted_feed:
    bootstrap_keys: []
proxy:
  secrets:
    map: {}
"#,
        )
        .expect("fixture parses");

        let paths: Vec<&str> = configured_config_only_keys(&yaml)
            .iter()
            .map(|key| key.path)
            .collect();

        assert_eq!(
            paths,
            [
                "agent_classes.hosted_feed.bootstrap_keys[]",
                "proxy.secrets.map.*",
            ]
        );
    }

    #[test]
    fn cors_enable_alias_emits_the_canonical_config_only_warning() {
        for spelling in ["enable", "enabled"] {
            let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
                r#"
origins:
  api.example:
    cors:
      {spelling}: false
    action: {{ type: static, status_code: 200 }}
"#
            ))
            .expect("fixture parses");

            let configured = configured_config_only_keys(&yaml);
            let paths: Vec<&str> = configured.iter().map(|key| key.path).collect();

            assert_eq!(
                paths,
                ["origins.*.cors.enable"],
                "raw YAML spelling {spelling} must produce the same warning"
            );
        }
    }

    #[test]
    fn every_deferred_module_names_its_tracking_issue() {
        for entry in MODULE_COVERAGE {
            let ModuleCoverageState::Deferred(note) = entry.state else {
                continue;
            };
            assert!(
                note.contains("WOR-"),
                "deferred module {}:{} must point at the work that tracks it: '{note}'",
                entry.kind,
                entry.name
            );
        }
    }

    #[test]
    fn every_schema_key_has_a_production_reader_or_reviewed_override() {
        let schema = serde_json::to_value(schemars::schema_for!(crate::types::ConfigFile))
            .expect("config schema serializes");
        let keys = schema_key_paths(&schema);
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("sbproxy-config crate lives under crates/");
        let sources = rust_sources(repo_root);

        let report = verify_config_readers_with_modules(
            &keys,
            MODULE_CONFIG_ROOTS,
            CONFIG_KEY_OVERRIDES,
            sources,
        );

        // Findings under a `ReportOnly` root are printed, never asserted on.
        // They are pre-existing debt: WOR-2233 and WOR-2246 decide whether
        // each one gets wired or removed, and failing here would only mean
        // this guard gets reverted before either lands.
        if !report.reported.is_empty() {
            println!(
                "module-surface keys with no production reader ({} of {} walked keys). These do \
                 not fail the build yet; see MODULE_CONFIG_ROOTS:\n{}",
                report.reported.len(),
                report.module_keys.len(),
                report
                    .reported
                    .iter()
                    .map(|finding| format!("  - {finding}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }

        assert!(
            report.errors.is_empty(),
            "configuration keys without production readers:\n{}",
            report
                .errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn every_dispatchable_module_declares_whether_its_config_is_guarded() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("sbproxy-config crate lives under crates/");
        let sources = rust_sources(repo_root);

        let errors = verify_module_dispatch_coverage(MODULE_DISPATCHES, MODULE_COVERAGE, sources);

        assert!(
            errors.is_empty(),
            "module coverage registry is out of step with the config dispatch tables:\n{}",
            errors
                .iter()
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
