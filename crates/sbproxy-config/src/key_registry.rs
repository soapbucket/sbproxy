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

/// Boot- and reload-path installer for `proxy.scripting.javascript.sandbox:`.
/// It hands the block to the extension crate's process-wide handle, which
/// every `JsEngine::new()` then reads (WOR-2319).
const JS_SANDBOX_CONSUMER: &str = "sbproxy_core::server::lifecycle::install_js_sandbox_limits";

const LB_ZONE_NOTE: &str =
    "Target selection is not locality aware. This label has exactly one reader in the \
     workspace, the admin target-health view behind `GET /api/health/targets`, so zoning your \
     targets renders a column and does not make the proxy prefer a same-zone target. Tracked \
     by WOR-2328.";

/// Where the load balancer parses and validates its own config block.
const LB_CONFIG_CONSUMER: &str =
    "sbproxy_modules::action::loadbalancer::LoadBalancerAction::from_config_for_origin";

/// Per-request target selection, which is where priority ordering applies.
const LB_SELECT_CONSUMER: &str =
    "sbproxy_modules::action::loadbalancer::LoadBalancerAction::select_target_for_request";

/// The forwarding-header controls are read a crate away, on a local
/// `forwarding` binding rather than as a field access on
/// `ForwardingHeaderControls`, so the reader scan cannot attribute them.
/// All seven are read in the same function, each gating one header.
const FORWARDING_CONSUMER: &str = "sbproxy_core::server::proxy_http::apply_forwarding_headers";

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
    // Read cross-crate: `compile_single_forward_rule` in sbproxy-core
    // pulls it off the serde_json value rather than off the typed
    // struct, which is the shape this guard cannot see.
    stable(
        "origins.*.forward_rules[].rules[].when",
        "sbproxy_core::pipeline::compile_single_forward_rule",
    ),
    config_only(
        "agent_classes.hosted_feed.bootstrap_keys[]",
        "No fetcher exists for a hosted agent-class feed, and no signature check is installed \
         for one either, so these trust anchors verify nothing. Use `catalog: builtin` or \
         `catalog: inline`, the two the resolver serves. WOR-2329.",
    ),
    config_only(
        "agent_classes.hosted_feed.url",
        "The agent-class resolver serves `catalog: builtin` and `catalog: inline`. Selecting \
         `hosted-feed` or `merged` logs a warning and falls back to the built-in defaults, and \
         nothing in the tree ever requests this URL. WOR-2329.",
    ),
    // `audit.sink`, `audit.path`, and `audit.sign_with` deliberately have
    // no entry here. `audit.sink` was pinned `config_only` while the key
    // selected nothing; it now selects whether the security audit trail is
    // hash-chained and signed, and `compiler::validate_audit` plus
    // `sbproxy_core::server::lifecycle::install_audit_chain` read all three
    // off a typed `&AuditConfig`, which is the shape the reader guard
    // resolves on its own (WOR-2318).
    //
    // The six `events.*` keys are absent for the same reason and are worth
    // naming, because "no entry" is indistinguishable from "nobody looked".
    // `compiler::validate_events` and
    // `sbproxy_core::server::lifecycle::build_event_egress` read `sink`,
    // `path`, `url`, `signing_secret`, `types`, and `queue_capacity` off a
    // typed `&EventsConfig`. None of them is inert: an option that belongs
    // to a sink other than the selected one is refused at compile rather
    // than pinned here, which is the same call `audit.path` under
    // `sink: memory` took.
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
    // would report working features as inert. Sticky sessions were removed
    // outright (WOR-2311): the load balancer refuses an authored `sticky:`
    // at config compile and points at the `ring_hash` algorithm.
    // `routing.strategy: token_rate` is refused by
    // `compile_config` rather than pinned, which is the better answer and
    // the only available one: the key is `routing`, the key is read, and it
    // was one accepted *value* of it that did nothing, a shape no
    // reader-based check can see. Target zones are the remaining pin.
    //
    // Two more keys took the refusal route for the same reason (WOR-2319).
    // Both live under `origins.*.transforms[]`, which `ConfigFile` types as
    // `serde_json::Value` and no root walks, so the schema cannot see them
    // and no entry here could pin them even if pinning were the answer:
    //
    //   * `type: wasm`, key `allowed_hosts`. Parsed and never enforced.
    //     Modules get no sockets at all today, so there is nothing to
    //     enforce it against, and an allowlist that describes a boundary
    //     nothing checks is worse than no key. `WasmTransform::from_config`
    //     refuses it and says why.
    //   * `type: cel`, key `on_request`. Compiled at config load and never
    //     evaluated. Transforms in this repo are response-side: the dispatch
    //     signature is `(body, content_type)` and it runs off the response
    //     body buffer, so there is no request phase for the expression to
    //     run in. `CelScriptTransform::from_config` refuses it and points at
    //     the request-phase surfaces that do exist.
    //   * `type: cel`, keys `on_response` and its `expression` alias
    //     (WOR-2362). Alive but unauthored: the expression replaced the
    //     entire response body with whatever scalar it evaluated to, which
    //     is producing output rather than deciding. Body rewriting belongs
    //     to the `javascript`, `lua_json`, and WASM transforms, which can
    //     parse a body, edit part of it, and re-emit.
    //     `CelScriptTransform::from_config` refuses both and names them.
    //
    // Deleting any of these fields on its own would have been silent: none
    // of the config structs set `deny_unknown_fields`, so an operator's key
    // would have gone from inert-and-documented to inert-and-ignored.
    // WOR-2330: the eleven entries below are what flipping
    // `origins.*.action` to `Enforced` surfaced. Every one has a real
    // production reader; the scan cannot attribute them because the read
    // happens on a local binding, inside a validation, or a crate away
    // from the type that declares the field. They are `stable` with a
    // named consumer rather than `config_only`, because each key does
    // change behaviour.
    stable("origins.*.action.lb_method", LB_CONFIG_CONSUMER),
    stable("origins.*.action.strategy_config", LB_CONFIG_CONSUMER),
    stable("origins.*.action.targets[].priority", LB_SELECT_CONSUMER),
    stable(
        "origins.*.action.targets[].health_check.path",
        "sbproxy_modules::action::loadbalancer::LoadBalancerAction::spawn_health_probes_on",
    ),
    stable(
        "origins.*.action.targets[].disable_forwarded_for_header",
        FORWARDING_CONSUMER,
    ),
    stable(
        "origins.*.action.targets[].disable_forwarded_header",
        FORWARDING_CONSUMER,
    ),
    stable(
        "origins.*.action.targets[].disable_forwarded_host_header",
        FORWARDING_CONSUMER,
    ),
    stable(
        "origins.*.action.targets[].disable_forwarded_port_header",
        FORWARDING_CONSUMER,
    ),
    stable(
        "origins.*.action.targets[].disable_forwarded_proto_header",
        FORWARDING_CONSUMER,
    ),
    stable(
        "origins.*.action.targets[].disable_real_ip_header",
        FORWARDING_CONSUMER,
    ),
    stable(
        "origins.*.action.targets[].disable_via_header",
        FORWARDING_CONSUMER,
    ),
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
    // `origins.*.action.sticky.*` is deliberately absent. The key was
    // removed (WOR-2311): `LoadBalancerAction::from_config_for_origin`
    // refuses an authored block at config compile with a message naming
    // `algorithm: ring_hash` as the replacement, so an entry here would
    // classify a field that no longer parses.
    config_only("origins.*.action.targets[].zone", LB_ZONE_NOTE),
    config_only(
        "origins.*.agent_skills[].max_clock_skew_secs",
        "Nothing signs an Agent Skills response, so there is no freshness header for this \
         tolerance to check; skill artifacts are verified by SHA-256 digest only. The one \
         signature freshness check in the tree is inbound RFC 9421 verification, which reads \
         its own `clock_skew_seconds`. WOR-2315.",
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
    stable(
        "origins.*.compression.level",
        "sbproxy_config::compiler::compile_origin",
    ),
    stable(
        "origins.*.compression.min_size",
        "sbproxy_config::compiler::compile_origin",
    ),
    // Promoted from config_only when the per-origin `timeouts` block landed:
    // the legacy idle spelling now feeds the resolved upstream idle deadline.
    stable(
        "origins.*.connection_pool.idle_timeout_secs",
        "sbproxy_config::compiler::resolve_upstream_timeouts",
    ),
    // Refused at compile since WOR-2310. Neither has a Pingora primitive
    // to be wired into, so they are not waiting on plumbing work.
    // `PeerOptions`, the per-peer struct `proxy_http.rs` already tunes,
    // has no pool-size and no maximum-lifetime field; the only pool sizing
    // in the vendored fork is `ConnectorOptions::keepalive_pool_size`,
    // which is set once per connector and cannot carry a per-origin value;
    // and `pingora-pool` has no age-based eviction at all.
    unsupported(
        "origins.*.connection_pool.max_connections",
        "Pingora sizes the upstream keepalive pool per connector, not per origin, so this never \
         capped anything. The compile error points at a `concurrent_limit` policy. WOR-2310.",
    ),
    unsupported(
        "origins.*.connection_pool.max_lifetime_secs",
        "Pingora's connection pool has no age-based eviction, so no pooled connection was ever \
         retired for being old. The compile error points at `timeouts.idle_ms`. WOR-2310.",
    ),
    unsupported(
        "origins.*.cors.enable",
        "The presence of the cors block is what turns CORS on, and neither entry point reads \
         this flag, so `enable: false` left CORS fully active while reading like a kill switch. \
         WOR-2325 refuses `false` at compile for that reason and leaves `true` accepted, since \
         `true` agrees with what the block already does. The `enabled` spelling is a serde \
         alias of the same field, so one check covers both. Delete the cors block to turn CORS \
         off.",
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
        "Credential lowering copies `max_tokens` and `max_cost_usd` and nothing else, and no \
         per-credential budget shape downstream carries a window, so the cap is cumulative and \
         never resets. For a resetting cap today, use the AI action's `budget.limits[]`, which \
         does take a `period`. WOR-2312.",
    ),
    stable(
        "origins.*.credentials[].attrs.tags[]",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "origins.*.credentials[].attrs.team",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    unsupported(
        "origins.*.forward_rules[].origin.hostname",
        "The request has already been matched to the parent origin by the time a forward rule \
         fires, so this tag selected no upstream and changed no header. Of the inline origin's \
         metadata only `id` is read, by OpenAPI emission. Refused at compile since WOR-2325; \
         put the target host in the rule's own `origin.action.url`.",
    ),
    stable(
        "origins.*.forward_rules[].origin.request_modifiers[].js_script",
        "sbproxy_core::server::js_request_modifier",
    ),
    stable(
        "origins.*.forward_rules[].origin.request_modifiers[].lua_script",
        "sbproxy_core::server::lua_request_modifier",
    ),
    unsupported(
        "origins.*.forward_rules[].origin.version",
        "The compiled child origin carries no version label, so the value reached neither \
         routing, logs, metrics, nor the emitted OpenAPI document. Refused at compile since \
         WOR-2325; match the version in the rule's path, or fold it into `origin.id`, which is \
         read.",
    ),
    unsupported(
        "origins.*.forward_rules[].origin.workspace_id",
        "The compiled child origin has no workspace field, so nothing scoped, attributed, or \
         logged a request by this value. Refused at compile since WOR-2325; multi-tenant \
         attribution is `origins.*.tenant_id` naming a declared `proxy.tenants[].id`.",
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
    // Like the body matcher above, the method matcher is compiled from the
    // untyped JSON the forward rule carries: `compile_single_forward_rule`
    // reads `method` off the JSON object and hands it to
    // `compile_method_matcher`, a hop the scanner cannot follow from the
    // typed `MethodSpec` field.
    stable(
        "origins.*.forward_rules[].rules[].method[]",
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
    stable(
        "origins.*.request_modifiers[].js_script",
        "sbproxy_core::server::js_request_modifier",
    ),
    stable(
        "origins.*.request_modifiers[].lua_script",
        "sbproxy_core::server::lua_request_modifier",
    ),
    stable(
        "origins.*.response_modifiers[].status.text",
        "sbproxy_core::server::action_dispatch::apply_plugin_action_response_modifiers",
    ),
    unsupported(
        "origins.*.sessions.ttl_seconds",
        "There is no sessions index to retain. The admin recent-request ring bounds itself by \
         entry count and evicts the oldest entry when full, so a session aged out on request \
         volume and never on this deadline. The compile error points at `sessions.budget`. \
         WOR-2310.",
    ),
    stable(
        "origins.*.sessions.budget.max_per_window",
        "sbproxy_observe::capture::budget_admits",
    ),
    stable(
        "origins.*.sessions.budget.window_seconds",
        "sbproxy_observe::capture::budget_admits",
    ),
    unsupported(
        "origins.*.traffic_capture",
        "No traffic-capture consumer exists, and the block was accepted as an untyped value, so \
         nothing validated its contents either. The compile error points at `mirror`. WOR-2310.",
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
        "Credential lowering copies `max_tokens` and `max_cost_usd` and nothing else, and no \
         per-credential budget shape downstream carries a window, so the cap is cumulative and \
         never resets. For a resetting cap today, use the AI action's `budget.limits[]`, which \
         does take a `period`. WOR-2312.",
    ),
    stable(
        "proxy.credentials[].attrs.tags[]",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "proxy.credentials[].attrs.team",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "proxy.credentials[].policies[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "proxy.credentials[].type",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    unsupported(
        "proxy.device_parser_file",
        "The device parser matches on compiled-in rules and has no code path that opens a \
         catalog file, so a maintained catalog and a missing one behaved identically. The \
         compile error points at `proxy.ai_providers_file` as the override that does work. \
         WOR-2310.",
    ),
    // Repointed from WOR-1969, which was canceled on 2026-08-01 along with
    // its only HTTP/3 child. The three keys below are not unreachable: the
    // block compiles with `enabled: false`, and the two tuning leaves still
    // move an `sbproxy plan` from Reload to Restart.
    config_only(
        "proxy.http3.enabled",
        "This build does not serve HTTP/3. `enabled: true` is refused at config compile, so \
         `false` is the only value that starts the proxy. WOR-2310.",
    ),
    config_only(
        "proxy.http3.idle_timeout_secs",
        "Settable in a config that compiles, next to `enabled: false`, and it installs no QUIC \
         idle timeout because no QUIC listener is ever started. Its one live effect is on \
         `sbproxy plan`: `proxy.http3.**` carries a Restart blast radius, so editing this turns \
         a reload into a restart. WOR-2310.",
    ),
    config_only(
        "proxy.http3.max_streams",
        "Settable in a config that compiles, next to `enabled: false`, and it caps no QUIC \
         streams because no QUIC listener is ever started. Like `idle_timeout_secs`, its one \
         live effect is to turn an `sbproxy plan` reload into a restart. WOR-2310.",
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
    unsupported(
        "proxy.key_management.governance.key_introspection",
        "No build installs the caller-facing key-introspection route, so `true` added no \
         endpoint and a caller asking about its own key got the same 404 either way. WOR-2325 \
         refuses `true` at compile and leaves `false` accepted, since `false` is the default \
         and is what the build does. Read a key's policy and usage through the admin API \
         instead.",
    ),
    stable(
        "proxy.key_management.governance.missing_rate",
        "sbproxy_core::server::ai_dispatch::handle_ai_proxy",
    ),
    stable(
        "proxy.key_management.governance.require_governed_key",
        "sbproxy_core::server::ai_dispatch::handle_ai_proxy",
    ),
    unsupported(
        "proxy.key_management.store.redis_source_of_truth",
        "The key plane picks its system of record from `store.backend` and from nothing else, \
         so this boolean offered a choice that does not exist: it could neither promote Redis \
         under another backend nor demote it under its own. WOR-2325 refuses `true` at compile \
         and leaves `false` accepted, since `false` is the default. Select the store with \
         `proxy.key_management.store.backend`.",
    ),
    unsupported(
        "proxy.messenger_settings.driver",
        "WOR-2166: the shared message bus has no runtime consumer. Nothing subscribes to a topic \
         and nothing publishes on one, so a configured bus moved no events between replicas. \
         `compile_config` rejects the whole block and points at `proxy.config_authority` for \
         config distribution and `POST /admin/cache/purge` for cache invalidation. WOR-2310 \
         deleted the backend implementations, so no driver name can ever be honored.",
    ),
    unsupported(
        "proxy.messenger_settings.params.*",
        "WOR-2166: driver parameters for the shared message bus, which has no runtime consumer. \
         Never read: `compile_config` rejects the block, and since WOR-2310 there is no driver \
         left to construct from them.",
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
    // WOR-2325: `level` and `format` were pinned config-only because the
    // binary resolved the startup filter from the CLI and `RUST_LOG` alone
    // and never opened the file. They are now the rank below `RUST_LOG` in
    // one documented chain, so they are `stable` and name the resolver that
    // reads them. `level` picks up a config reload as well, through
    // `sbproxy_core::server::lifecycle::install_config_log_level`; the
    // registry names one consumer per key, and boot is the one that decides
    // what the process starts with.
    //
    // The three `sampling.*` leaves below are a different finding and stay
    // pinned. Their note used to say the process logger runs "fixed
    // defaults", which reads as though a rate is applied. None is:
    // `sbproxy_observe::logging::emit` has no sampling call site, so
    // `should_sample` is dead on the emit path and every level ships at
    // 100% whatever the YAML asks for. Installing the rates would not
    // change that; the emitter has to learn to sample first.
    stable(
        "proxy.observability.log.level",
        "sbproxy::resolve_log_filter",
    ),
    stable(
        "proxy.observability.log.format",
        "sbproxy::resolve_log_format",
    ),
    config_only(
        "proxy.observability.log.sampling.debug",
        "The process logger has no sampling call site, so no rate is applied at any level and \
         this one drops nothing. Throttle request logs with access_log.sample_rate instead. \
         Tracked by WOR-2318.",
    ),
    config_only(
        "proxy.observability.log.sampling.info",
        "The process logger has no sampling call site, so no rate is applied at any level and \
         this one drops nothing. Throttle request logs with access_log.sample_rate instead. \
         Tracked by WOR-2318.",
    ),
    config_only(
        "proxy.observability.log.sampling.trace",
        "The process logger has no sampling call site, so no rate is applied at any level and \
         this one drops nothing. Throttle request logs with access_log.sample_rate instead. \
         Tracked by WOR-2318.",
    ),
    stable(
        "proxy.observability.log.sinks[].output.type",
        "sbproxy_core::server::lifecycle::compile_one_sink",
    ),
    // WOR-2319: these three were pinned config-only because the boot path
    // never installed them and every QuickJS engine ran the built-in
    // defaults. They reach the engine now, through the same process-wide
    // handle the Lua half has used since WOR-594, so they are `stable` and
    // name the installer. The read itself happens in `sbproxy-extension`,
    // one indirection past the handle, which is what the entry stands in
    // for.
    stable(
        "proxy.scripting.javascript.sandbox.budget_ms",
        JS_SANDBOX_CONSUMER,
    ),
    stable(
        "proxy.scripting.javascript.sandbox.memory_mb",
        JS_SANDBOX_CONSUMER,
    ),
    stable(
        "proxy.scripting.javascript.sandbox.stack_kb",
        JS_SANDBOX_CONSUMER,
    ),
    unsupported(
        "proxy.secrets.backend",
        "The legacy single-backend selector was never consulted. The resolver is built only \
         from the named entries under `proxy.secrets.backends`, so a provider named here \
         selected nothing and every `secret://` reference resolved as if it were absent. \
         Refused at compile since WOR-2325.",
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
    unsupported(
        "proxy.secrets.fallback",
        "The named-backend resolver fails an unresolvable `secret://` reference loudly and \
         never consulted this legacy selector, so no lookup ever fell through to it. Refused at \
         compile since WOR-2325; declare every backend you want consulted under \
         `proxy.secrets.backends`.",
    ),
    unsupported(
        "proxy.secrets.hashicorp.addr",
        "The legacy top-level HashiCorp block is never installed: nothing builds a Vault client \
         from it, so this address was contacted by nobody. Refused at compile since WOR-2325; \
         declare a `hashicorp` entry under `proxy.secrets.backends` instead.",
    ),
    unsupported(
        "proxy.secrets.hashicorp.mount",
        "The legacy top-level HashiCorp block is never installed: nothing builds a Vault client \
         from it, so this mount path scoped no lookup. Refused at compile since WOR-2325; \
         declare a `hashicorp` entry under `proxy.secrets.backends` instead.",
    ),
    unsupported(
        "proxy.secrets.hashicorp.token",
        "The legacy top-level HashiCorp block is never installed: nothing builds a Vault client \
         from it, so this token authenticated nothing and sat in the config for no purpose. \
         Refused at compile since WOR-2325; declare a `hashicorp` entry under \
         `proxy.secrets.backends` instead.",
    ),
    // Not a resolution source, and still live. The `secret:<name>` colon
    // form was removed (WOR-1785) and `install_secret_resolver` warns that
    // the map's values resolve nothing, which is why this sat here as
    // config-only. Two readers make that wrong. A non-empty map clears the
    // `backends.is_empty() && map.is_empty()` early return, so the process
    // resolver gets installed and four call sites that branch on
    // `sbproxy_vault::process_resolver()` take their other arm. And
    // `validate::validate` builds its known-secret set from the map's keys,
    // so an undeclared `secret:<name>` becomes a `missing-vault-key` error
    // that exits `sbproxy plan` with 3. Warning that a key which changes a
    // plan's exit code does nothing is the wrong answer.
    stable("proxy.secrets.map.*", "sbproxy::install_secret_resolver"),
    // WOR-2191: read inside the ACME renewal task on a local
    // `acme_config` binding, a crate away from the type that declares the
    // field, so the reader scan cannot attribute it. The key is live: it
    // supplies the trusted root for the ACME directory endpoint.
    stable(
        "proxy.acme.ca_root",
        "sbproxy_tls::TlsState::start_acme_renewal_task",
    ),
    stable(
        "proxy.secrets.rotation.grace_period_secs",
        "sbproxy_core::key_plane::KeyPlane::resolve_credential_secret",
    ),
    stable(
        "proxy.secrets.rotation.re_resolve_interval_secs",
        "sbproxy_core::key_plane::KeyPlane::resolve_credential_secret",
    ),
    config_only(
        "proxy.tenants[].credentials[].attrs.budget.reset",
        "Credential lowering copies `max_tokens` and `max_cost_usd` and nothing else, and no \
         per-credential budget shape downstream carries a window, so the cap is cumulative and \
         never resets. For a resetting cap today, use the AI action's `budget.limits[]`, which \
         does take a `period`. WOR-2312.",
    ),
    stable(
        "proxy.tenants[].credentials[].attrs.tags[]",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
    ),
    stable(
        "proxy.tenants[].credentials[].attrs.team",
        "sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys",
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
/// Both entries are `Enforced` as of WOR-2330: somebody has read every key
/// under each and either confirmed a reader or pinned it above. A dead key
/// added under either root now fails the build rather than printing a line
/// nobody reads.
///
/// `ReportOnly` remains the honest state for a subtree nobody has walked
/// yet, and it is how both of these started. It is meant to be temporary,
/// because a `ReportOnly` root prevents no regressions and quietly
/// accumulates whatever is added under it. Widening the scan and flipping
/// the flag are still two separate changes: doing both at once fails the
/// build on pre-existing dead keys, and a check that does that gets
/// reverted rather than fixed.
///
/// What the WOR-2330 walk found, recorded so the next person does not
/// re-derive it:
///
/// * `origins.*.action`: every key had a live reader except `targets[].zone`,
///   which stays pinned above under WOR-2328. Two looked dead and are not.
///   `targets[].host_override` reads in `sbproxy_core`'s upstream-host
///   selection rather than in the load balancer, so a search scoped to
///   `loadbalancer.rs` misses it. `lb_method` is read only by the
///   `lb_method: plugin requires strategy` validation and selects nothing,
///   which is exactly what it is documented to be.
/// * `origins.*.action.resilience`: `retry_policy` and `llm_aware` were the
///   untriaged pair and both are live, in the failover loop's per-error
///   retry classification and in the handler's LLM-aware action lookup.
///
/// Growing coverage a subtree at a time is the intended pattern. The AI
/// action is several hundred keys, so `resilience` is rooted at the
/// subtree rather than at `AiHandlerConfig`; more narrow roots are the
/// right shape for the rest, not one wide one.
#[cfg(test)]
const MODULE_CONFIG_ROOTS: &[ModuleConfigRoot] = &[
    ModuleConfigRoot {
        path: "origins.*.action",
        rust_type: "sbproxy_modules::action::loadbalancer::LoadBalancerConfig",
        enforcement: ModuleRootEnforcement::Enforced,
    },
    // Rooted at the subtree rather than at `AiHandlerConfig`, deliberately.
    // The whole AI action is several hundred keys and nobody has triaged
    // them; `resilience` is where the confirmed-dead ones were. A root is a
    // path and a type, so coverage can grow a subtree at a time instead of
    // waiting for one very large review.
    ModuleConfigRoot {
        path: "origins.*.action.resilience",
        rust_type: "sbproxy_ai::handler::AiResilienceConfig",
        enforcement: ModuleRootEnforcement::Enforced,
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

// `origins.*.cors.enabled` was listed here so the boot warning fired for
// both spellings. It is gone because `cors.enable` is `Unsupported` now:
// `enabled` is a serde alias of `enable`, so both spellings deserialize onto
// the same field and hit the same compile refusal, and an alias whose
// canonical entry can never be `ConfigOnly` again could never fire.
const CONFIG_KEY_ALIASES: &[(&str, &str)] = &[
    (
        "agent_classes.hosted_feed.bootstrap_keys",
        "agent_classes.hosted_feed.bootstrap_keys[]",
    ),
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

    /// `attrs.team` is lowered onto the virtual key at all three
    /// credential scopes, so authoring it is no longer inert and must
    /// not warn. The registry has to agree with the compiler here or an
    /// operator is told a live key does nothing.
    #[test]
    fn credential_team_is_stable_at_every_supported_scope() {
        const TEAM_KEYS: [&str; 3] = [
            "origins.*.credentials[].attrs.team",
            "proxy.credentials[].attrs.team",
            "proxy.tenants[].credentials[].attrs.team",
        ];

        for path in TEAM_KEYS {
            let entry = CONFIG_KEY_OVERRIDES
                .iter()
                .find(|key| key.path == path)
                .unwrap_or_else(|| panic!("{path} is registered"));
            assert_eq!(
                entry.support,
                SupportLevel::Stable,
                "{path} lowers into the virtual key and must not be classified inert"
            );
            assert_eq!(
                entry.consumer,
                Some("sbproxy_config::compiler::lower_credentials_into_origin_virtual_keys"),
                "{path} must name the lowering site that reads it"
            );
        }

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

        assert!(
            paths.is_empty(),
            "authoring a credential team must emit no config-only warning: {paths:?}"
        );
    }

    /// The `map: {}` half is the negative case and is the point of keeping
    /// it in the fixture: `proxy.secrets.map` is `stable` now, so authoring
    /// it must produce no warning even though the empty-collection walk
    /// still reaches it.
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

        assert_eq!(paths, ["agent_classes.hosted_feed.bootstrap_keys[]"]);
    }

    /// `proxy.secrets.map` gates whether the process secret resolver is
    /// installed and which `secret:<name>` references `sbproxy plan`
    /// accepts, so it is `stable` and must never warn. It was `config_only`
    /// until WOR-2325, which told operators a live key was inert.
    #[test]
    fn secrets_map_is_stable_and_never_warns() {
        let entry = CONFIG_KEY_OVERRIDES
            .iter()
            .find(|key| key.path == "proxy.secrets.map.*")
            .expect("proxy.secrets.map.* is registered");
        assert_eq!(entry.support, SupportLevel::Stable);
        assert_eq!(entry.consumer, Some("sbproxy::install_secret_resolver"));

        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
proxy:
  secrets:
    map:
      upstream_key: env:UPSTREAM_KEY
"#,
        )
        .expect("fixture parses");

        let paths: Vec<&str> = configured_config_only_keys(&yaml)
            .iter()
            .map(|key| key.path)
            .collect();
        assert!(paths.is_empty(), "a stable key must not warn: {paths:?}");
    }

    /// Both spellings of the legacy CORS switch are refused at compile now,
    /// so neither may reach the boot warning. `enabled` is a serde alias of
    /// `enable`, which is why the registry no longer carries an alias row
    /// for it: one classification covers both.
    #[test]
    fn cors_enable_is_unsupported_in_both_spellings() {
        let entry = CONFIG_KEY_OVERRIDES
            .iter()
            .find(|key| key.path == "origins.*.cors.enable")
            .expect("origins.*.cors.enable is registered");
        assert_eq!(entry.support, SupportLevel::Unsupported);

        assert!(
            !CONFIG_KEY_ALIASES
                .iter()
                .any(|(alias, _)| *alias == "origins.*.cors.enabled"),
            "an alias onto a non-ConfigOnly key can never fire and must not linger"
        );

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

            let paths: Vec<&str> = configured_config_only_keys(&yaml)
                .iter()
                .map(|key| key.path)
                .collect();

            assert!(
                paths.is_empty(),
                "spelling {spelling} is refused at compile and must not also warn: {paths:?}"
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
        // They are pre-existing debt, and each root's note says who owns it
        // and what is still untriaged under it. Failing here instead would
        // only mean this guard gets reverted before the wiring lands.
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
